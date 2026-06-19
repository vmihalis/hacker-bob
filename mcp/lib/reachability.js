"use strict";

const fs = require("fs");
const path = require("path");
const {
  NATIVE_SOURCE_EXTENSIONS,
} = require("./native-extensions.js");

const NETWORK_CONTENT_RE = /\b(accept4|recvfrom|recvmsg|WSAStartup|getaddrinfo|svc_run|svc_register|svc_create|xdr_[a-z0-9_]+|clnt_create|rpcb_set|MHD_start_daemon|evhttp_[a-z0-9_]+|uv_tcp_[a-z0-9_]+|SSL_accept|gnutls_handshake|bindresvport)\s*\(/;
const NETWORK_SOCKET_RE = /(?<![\w.>])(socket|listen)\s*\(/;
const NETWORK_TOKEN_RE = /\b(INADDR_ANY|SOCK_STREAM|SOCK_DGRAM|AF_INET6?|sockaddr_in6?|htons|in_port_t)\b/;
const NON_SHIPPING_DIR_RE = /(^|\/)(tests?|examples?|samples?|demos?|fuzz|fuzzing|benchmarks?|contrib|third[_-]?party|3rdparty|fixtures?|testdata)\//i;
const SERVICE_UNIT_RE = /(^|\/)[^/]+\.(service|socket)$/;
const SERVER_PATH_RE = /(^|\/)(daemon|daemons|server|servers|httpd|net|rpc|proto|protocol|listener|ipc)\//i;
const SERVER_FILE_RE = /(^|\/)[^/]*(server|daemon|listener|socket|httpd|rpcsvc)[^/]*\.(c|cc|cpp|cxx|h|hpp)$/i;
const ENTRYPOINT_FILE_RE = /(^|\/)(main|app|service|net|socket|server|daemon|rpc|http|listen)\w*\.(c|cc|cpp|cxx)$/i;
const DOCKERFILE_RE = /(^|\/)Dockerfile([.-][\w.-]+)?$/;
const NETWORK_SCAN_LIMIT = 50;
const NETWORK_FALLBACK_LIMIT = 80;
const REACHABILITY_READ_LIMIT_BYTES = 150 * 1024;
const SIGNAL_LIMIT = 14;
const PATH_HINT_SIGNAL_LIMIT = Math.floor(SIGNAL_LIMIT / 2);
const ATTRIBUTION_LIMIT = 20;
const NETWORK_SEMANTIC_TOP_LEVEL_DIR_RE = /^(server|servers|httpd|net|network|rpc|proto|protocol|listener|listeners|ipc|service|services)$/i;
const HEADER_EXTENSIONS = Object.freeze(new Set([".h", ".hh", ".hpp"]));

const CEILING_RANK = Object.freeze({
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  none: 0,
});

function maxCeiling(a, b) {
  return (CEILING_RANK[b] || 0) > (CEILING_RANK[a] || 0) ? b : a;
}

function safeReadText(repoRoot, rel, maxBytes = REACHABILITY_READ_LIMIT_BYTES) {
  try {
    if (path.isAbsolute(rel)) return null;
    const rootReal = fs.realpathSync(repoRoot);
    const absPath = path.resolve(repoRoot, rel);
    const realPath = fs.realpathSync(absPath);
    const relativeToRoot = path.relative(rootReal, realPath);
    if (relativeToRoot.startsWith("..") || path.isAbsolute(relativeToRoot)) return null;
    const fd = fs.openSync(realPath, "r");
    try {
      const buffer = Buffer.alloc(maxBytes);
      const bytesRead = fs.readSync(fd, buffer, 0, maxBytes, 0);
      const slice = buffer.subarray(0, bytesRead);
      if (slice.includes(0)) return null;
      return slice.toString("utf8");
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return null;
  }
}

function severityCeilingForSurface(surfaceType, networkReachable) {
  switch (surfaceType) {
    case "oss_native_code":
      return networkReachable ? "critical" : "medium";
    case "oss_api_schema":
    case "oss_authz":
      return networkReachable ? "high" : "medium";
    case "oss_dependency":
    case "oss_ci_cd":
    case "oss_secrets_config":
      return "medium";
    case "oss_docs_behavior":
      return "low";
    default:
      return "medium";
  }
}

function attackVectorForSurface(surfaceType, networkReachable) {
  if (surfaceType === "oss_dependency" || surfaceType === "oss_ci_cd") return "supply_chain";
  if (surfaceType === "oss_native_code" || surfaceType === "oss_api_schema" || surfaceType === "oss_authz") {
    return networkReachable ? "network" : "local";
  }
  return "local";
}

function unique(values, limit = null) {
  const out = [];
  const seen = new Set();
  for (const value of values) {
    if (typeof value !== "string") continue;
    const trimmed = value.trim();
    if (!trimmed || seen.has(trimmed)) continue;
    seen.add(trimmed);
    out.push(trimmed);
    if (limit != null && out.length >= limit) break;
  }
  return out;
}

function hasNetworkContent(file, text) {
  if (NETWORK_CONTENT_RE.test(text) || NETWORK_SOCKET_RE.test(text)) return true;
  if (HEADER_EXTENSIONS.has(path.extname(file).toLowerCase())) return false;
  return NETWORK_TOKEN_RE.test(text);
}

const REACH_ANCHOR_PREFIXES = ["net_call:", "server_path:", "systemd_unit:", "expose:"];

function dirPrefixesAtDepth(files, maxDepth, cap, minDirectoryDepth = 1) {
  const dirs = new Set();
  for (const file of files) {
    if (!file.includes("/")) continue;
    const parts = file.split("/");
    const directoryDepth = parts.length - 1;
    if (directoryDepth < minDirectoryDepth) continue;
    dirs.add(parts.slice(0, Math.min(maxDepth, parts.length - 1)).join("/"));
    if (dirs.size >= cap) break;
  }
  return Array.from(dirs);
}

function reachableDirPrefixes(files, maxDepth, cap) {
  const dirs = new Set();
  for (const file of files) {
    if (!file.includes("/")) continue;
    const parts = file.split("/");
    const directoryDepth = parts.length - 1;
    if (directoryDepth === 1 && !NETWORK_SEMANTIC_TOP_LEVEL_DIR_RE.test(parts[0])) continue;
    dirs.add(parts.slice(0, Math.min(maxDepth, directoryDepth)).join("/"));
    if (dirs.size >= cap) break;
  }
  return Array.from(dirs);
}

function reachabilityAttribution(signals, nativeFiles) {
  const anchors = [];
  for (const signal of signals) {
    const prefix = REACH_ANCHOR_PREFIXES.find((p) => signal.startsWith(p));
    if (prefix) anchors.push(signal.slice(prefix.length));
  }
  const anchorFiles = unique(anchors, ATTRIBUTION_LIMIT);
  const anchorDirs = dirPrefixesAtDepth(anchorFiles, 2, ATTRIBUTION_LIMIT, 1);
  const reachableDirs = reachableDirPrefixes(anchorFiles, 2, ATTRIBUTION_LIMIT);
  const localDirs = dirPrefixesAtDepth(nativeFiles, 2, 200).filter(
    (dir) => !anchorDirs.some((rd) => (
      dir === rd || dir.startsWith(`${rd}/`) || rd.startsWith(`${dir}/`)
    )),
  ).slice(0, ATTRIBUTION_LIMIT);
  return {
    network_reachable_anchors: anchorFiles,
    network_reachable_dirs: reachableDirs,
    local_only_candidate_dirs: localDirs,
  };
}

function detectNetworkReachability(repoRoot, files) {
  const signals = [];
  const shippingFiles = files.filter((file) => !NON_SHIPPING_DIR_RE.test(file));
  const nativeFiles = shippingFiles.filter((file) => NATIVE_SOURCE_EXTENSIONS.has(path.extname(file).toLowerCase()));

  for (const file of shippingFiles) {
    if (SERVICE_UNIT_RE.test(file)) signals.push(`systemd_unit:${file}`);
  }

  const priority = nativeFiles.filter((file) => SERVER_PATH_RE.test(file) || SERVER_FILE_RE.test(file));
  signals.push(...unique(priority.map((file) => `server_path:${file}`), PATH_HINT_SIGNAL_LIMIT));

  const dockerfiles = shippingFiles.filter((file) => DOCKERFILE_RE.test(file));
  const scanList = unique([
    ...priority,
    ...nativeFiles.filter((file) => ENTRYPOINT_FILE_RE.test(file)),
    ...dockerfiles,
  ], NETWORK_SCAN_LIMIT);

  let netHit = false;
  let contentSignalCount = 0;
  for (const file of scanList) {
    const text = safeReadText(repoRoot, file);
    if (!text) continue;
    if (DOCKERFILE_RE.test(file)) {
      if (/\bEXPOSE\s+\d/.test(text)) {
        signals.push(`expose:${file}`);
        contentSignalCount += 1;
        netHit = true;
      }
      continue;
    }
    if (hasNetworkContent(file, text)) {
      signals.push(`net_call:${file}`);
      contentSignalCount += 1;
      netHit = true;
      if (contentSignalCount >= SIGNAL_LIMIT) break;
    }
  }

  if (!netHit) {
    for (const file of nativeFiles.slice(0, NETWORK_FALLBACK_LIMIT)) {
      const text = safeReadText(repoRoot, file);
      if (!text) continue;
      if (NETWORK_CONTENT_RE.test(text) || NETWORK_SOCKET_RE.test(text)) {
        signals.push(`net_call:${file}`);
        netHit = true;
        break;
      }
    }
  }

  const signalsOut = unique(signals, SIGNAL_LIMIT);
  const networkReachable = netHit || signalsOut.some((signal) => signal.startsWith("systemd_unit:"));
  return {
    network_reachable: networkReachable,
    signals: signalsOut,
    attribution: networkReachable ? reachabilityAttribution(signalsOut, nativeFiles) : null,
  };
}

function relDir(rel) {
  return rel.includes("/") ? rel.split("/").slice(0, -1).join("/") : "";
}

function relIsInDirs(rel, dirs) {
  const dir = relDir(rel);
  return dirs.some((candidate) => (
    candidate === dir || (candidate && dir.startsWith(`${candidate}/`))
  ));
}

function surfaceReachableForRel(rel, reach) {
  if (!reach.network_reachable) return false;
  const attribution = reach.attribution || {};
  const anchors = attribution.network_reachable_anchors || [];
  const dirs = attribution.network_reachable_dirs || [];
  if (anchors.length === 0 && dirs.length === 0) return false;
  return anchors.includes(rel) || relIsInDirs(rel, dirs);
}

function classifyRepoReachability({
  repoRoot,
  files,
  projection = {},
  surfaceIdForRel = (rel) => rel,
} = {}) {
  const normalizedFiles = Array.isArray(files) ? files.slice().sort() : [];
  const modules = Array.isArray(projection.modules) ? projection.modules : [];
  const nativeModules = modules.filter((mod) => mod && (mod.nativeSource || mod.nativeBuild) && typeof mod.rel === "string");
  const reach = detectNetworkReachability(repoRoot, normalizedFiles);
  const perSurface = new Map();
  let max = nativeModules.length > 0 ? "medium" : "none";

  for (const mod of nativeModules) {
    const networkReachable = surfaceReachableForRel(mod.rel, reach);
    const surfaceType = "oss_native_code";
    const severityCeiling = severityCeilingForSurface(surfaceType, networkReachable);
    max = maxCeiling(max, severityCeiling);
    const attribution = reach.attribution || {};
    perSurface.set(mod.rel, {
      network_reachable: networkReachable,
      attack_vector: attackVectorForSurface(surfaceType, networkReachable),
      severity_ceiling: severityCeiling,
      network_reachable_anchors: networkReachable ? attribution.network_reachable_anchors || [] : [],
      network_reachable_dirs: networkReachable ? attribution.network_reachable_dirs || [] : [],
      local_only_candidate_dirs: attribution.local_only_candidate_dirs || [],
    });
  }

  const surfaceCeilings = nativeModules.map((mod) => {
    const stamp = perSurface.get(mod.rel);
    return {
      id: surfaceIdForRel(mod.rel),
      file_path: mod.rel,
      severity_ceiling: stamp.severity_ceiling,
      attack_vector: stamp.attack_vector,
      network_reachable: stamp.network_reachable,
    };
  });

  return {
    reachability: {
      max_credible_severity_ceiling: max,
      network_reachable: reach.network_reachable,
      network_reachable_surface_ids: surfaceCeilings
        .filter((surface) => surface.network_reachable)
        .map((surface) => surface.id),
      surface_ceilings: surfaceCeilings,
      signals: reach.signals,
      native_attack_vector_map: reach.attribution,
    },
    perSurface,
  };
}

module.exports = {
  NETWORK_SCAN_LIMIT,
  NETWORK_FALLBACK_LIMIT,
  REACHABILITY_READ_LIMIT_BYTES,
  attackVectorForSurface,
  classifyRepoReachability,
  detectNetworkReachability,
  maxCeiling,
  safeReadText,
  severityCeilingForSurface,
};
