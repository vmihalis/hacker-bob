"use strict";

const fs = require("fs");
const path = require("path");
const {
  readAttackSurfaceStrict,
} = require("./attack-surface.js");
const {
  sessionDir,
  scopeWarningsPath,
} = require("./paths.js");
const {
  hostnameFromUrl,
  hostnamesForSurface,
  safeUrlObject,
} = require("./url-surface.js");

const PUBLIC_INTEL_ALLOWED_HOSTS = Object.freeze([
  "web.archive.org",
  "otx.alienvault.com",
  "crt.sh",
  "api.github.com",
  "raw.githubusercontent.com",
]);

function normalizeScopeExclusionToken(token) {
  if (typeof token !== "string") {
    return null;
  }

  const trimmed = token.trim().replace(/^["']+|["']+$/g, "");
  if (!trimmed) {
    return null;
  }

  try {
    const parsed = new URL(trimmed);
    if (parsed.hostname) {
      return parsed.hostname.trim().toLowerCase();
    }
  } catch {}

  const hostCandidate = trimmed
    .split(/[/?#]/, 1)[0]
    .split(":", 1)[0]
    .trim()
    .replace(/\.+$/, "");
  if (/^[A-Za-z0-9][A-Za-z0-9._-]*\.[A-Za-z]{2,63}$/.test(hostCandidate)) {
    return hostCandidate.toLowerCase();
  }

  return trimmed;
}

function readScopeExclusions(domain) {
  const logPath = scopeWarningsPath(domain);
  if (!fs.existsSync(logPath)) {
    return [];
  }

  let raw;
  try {
    raw = fs.readFileSync(logPath, "utf8");
  } catch {
    return [];
  }

  const exclusions = [];
  const seen = new Set();
  for (const line of raw.split("\n")) {
    const match = line.match(/OUT-OF-SCOPE(?: \(http_scan\))?:\s*(.+?)\s*\((?:command|url):/);
    if (!match) continue;
    const normalized = normalizeScopeExclusionToken(match[1]);
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    exclusions.push(normalized);
  }

  return exclusions;
}

function normalizeHostToken(token) {
  const normalized = normalizeScopeExclusionToken(token);
  if (!normalized || typeof normalized !== "string") return null;
  return normalized.toLowerCase().replace(/\.+$/, "");
}

function hostMatchesScope(hostname, allowedHosts) {
  if (!hostname) return false;
  const host = hostname.toLowerCase().replace(/\.+$/, "");
  return Array.from(allowedHosts || []).some((allowedHost) => {
    const allowed = String(allowedHost || "").toLowerCase().replace(/\.+$/, "");
    return allowed && (host === allowed || host.endsWith(`.${allowed}`));
  });
}

function readDenyListHosts(domain) {
  const denyListPath = path.join(sessionDir(domain), "deny-list.txt");
  if (!fs.existsSync(denyListPath)) {
    return [];
  }

  try {
    return fs.readFileSync(denyListPath, "utf8")
      .split("\n")
      .map((line) => normalizeHostToken(line))
      .filter(Boolean);
  } catch {
    return [];
  }
}

function readSessionTargetHosts(domain) {
  const hosts = new Set([domain.toLowerCase().replace(/\.+$/, "")]);
  const statePath = path.join(sessionDir(domain), "state.json");
  if (!fs.existsSync(statePath)) {
    return hosts;
  }

  try {
    const state = JSON.parse(fs.readFileSync(statePath, "utf8"));
    const target = normalizeHostToken(state && state.target);
    if (target) hosts.add(target);
    const targetUrlHost = hostnameFromUrl(state && state.target_url);
    if (targetUrlHost) hosts.add(targetUrlHost.toLowerCase().replace(/\.+$/, ""));
  } catch {}

  return hosts;
}

function readAttackSurfaceHosts(domain) {
  try {
    const attackSurface = readAttackSurfaceStrict(domain);
    const hosts = new Set();
    for (const surface of attackSurface.document.surfaces) {
      for (const host of hostnamesForSurface(surface)) {
        hosts.add(host);
      }
    }
    return hosts;
  } catch {
    return new Set();
  }
}

function readAllowedScanHosts(domain) {
  return new Set([
    ...readSessionTargetHosts(domain),
    ...readAttackSurfaceHosts(domain),
  ]);
}

function resolveHttpScanTargetDomain(url, explicitTargetDomain = null) {
  if (explicitTargetDomain) {
    return String(explicitTargetDomain).toLowerCase().replace(/\.+$/, "");
  }

  return null;
}

function targetAppearsInPublicIntelUrl(url, targetDomain) {
  if (!targetDomain) return false;
  const parsed = safeUrlObject(url);
  if (!parsed) return false;
  const target = targetDomain.toLowerCase().replace(/\.+$/, "");
  const raw = `${parsed.pathname}${parsed.search}`.toLowerCase();
  let decoded = raw;
  try {
    decoded = decodeURIComponent(raw);
  } catch {}
  return raw.includes(target) || decoded.includes(target);
}

function isPublicIntelScanAllowed(url, host, targetDomain) {
  return hostMatchesScope(host, PUBLIC_INTEL_ALLOWED_HOSTS) &&
    targetAppearsInPublicIntelUrl(url, targetDomain);
}

function makeScopeBlockedError(message) {
  const error = new Error(message);
  error.scope_decision = "blocked";
  return error;
}

function validateHttpScanScope(url, targetDomain) {
  const parsed = safeUrlObject(url);
  if (!parsed) {
    throw makeScopeBlockedError("Invalid URL");
  }
  const host = parsed.hostname.toLowerCase().replace(/\.+$/, "");
  const domain = String(targetDomain || "").toLowerCase().replace(/\.+$/, "");
  if (!domain) {
    throw makeScopeBlockedError("target_domain is required for scoped HTTP scans");
  }

  const denyListHosts = readDenyListHosts(domain);
  if (hostMatchesScope(host, denyListHosts)) {
    throw makeScopeBlockedError(`Blocked deny-listed host: ${host}`);
  }

  const allowedHosts = new Set([
    ...readAllowedScanHosts(domain),
  ]);
  if (hostMatchesScope(host, allowedHosts)) {
    return {
      allowed: true,
      scope_decision: "allowed",
      reason: "first_party",
      host,
      allowed_hosts: Array.from(allowedHosts).sort(),
    };
  }

  if (isPublicIntelScanAllowed(url, host, domain)) {
    return {
      allowed: true,
      scope_decision: "allowed",
      reason: "public_intel",
      host,
      allowed_hosts: PUBLIC_INTEL_ALLOWED_HOSTS.slice(),
    };
  }

  throw makeScopeBlockedError(`Blocked out-of-scope host: ${host} is not in scope for ${domain}`);
}

function filterExclusionsByHosts(entries, hosts, cap = 100) {
  if (!entries || entries.length === 0) {
    return { filtered: [], total: 0, omitted: 0 };
  }
  const hostnames = (hosts || []).map((h) => {
    try {
      return new URL(h).hostname;
    } catch {
      return h.replace(/^https?:\/\//, "");
    }
  });
  const surfaceRelevant = [];
  const generic = [];
  for (const entry of entries) {
    const firstToken = entry.split(/[\s\-\/]/)[0];
    const looksLikeHost = firstToken.includes(".") &&
      /^[a-zA-Z0-9][a-zA-Z0-9.\-]*\.[a-zA-Z]{2,}$/.test(firstToken);
    if (looksLikeHost) {
      if (hostnames.some((h) => firstToken === h || firstToken.endsWith("." + h))) {
        surfaceRelevant.push(entry);
      }
    } else {
      generic.push(entry);
    }
  }
  const combined = [...surfaceRelevant, ...generic];
  const filtered = combined.slice(0, cap);
  return { filtered, total: entries.length, omitted: Math.max(0, combined.length - filtered.length) };
}

module.exports = {
  filterExclusionsByHosts,
  hostMatchesScope,
  isPublicIntelScanAllowed,
  normalizeScopeExclusionToken,
  readScopeExclusions,
  resolveHttpScanTargetDomain,
  validateHttpScanScope,
};
