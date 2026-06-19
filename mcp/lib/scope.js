"use strict";

const fs = require("fs");
const net = require("net");
const { domainToASCII } = require("node:url");
const psl = require("psl");
const {
  assertSafeDomain,
  scopeWarningsPath,
} = require("./paths.js");
const {
  readFileUtf8,
} = require("./storage.js");
const {
  isBlockedInternalHost,
  isFirstPartyHost,
  safeUrlObject,
} = require("./url-surface.js");
const {
  labTargetEligibleHost,
  labTargetPermitted,
  labAuthorizationForTarget,
} = require("./lab-target-attest.js");

const PSL_OVERLAY_FILE_ENV = "BOB_PSL_OVERLAY_FILE";
let publicSuffixOverlayCache = {
  path: undefined,
  statKey: null,
  overlay: null,
};

function normalizeDnsHostToAscii(value, fieldName) {
  const raw = String(value || "").trim().replace(/\.+$/, "");
  if (!raw) throw new Error(`${fieldName} is required`);
  const ascii = domainToASCII(raw);
  if (!ascii) throw new Error(`${fieldName} is not a valid DNS hostname: ${value}`);
  const host = ascii.toLowerCase().replace(/\.+$/, "");
  const labels = host.split(".");
  for (const label of labels) {
    if (
      label.length < 1 ||
      label.length > 63 ||
      !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
    ) {
      throw new Error(`${fieldName} contains an invalid DNS label: ${value}`);
    }
  }
  return host;
}

function readPublicSuffixOverlay() {
  const overlayPath = process.env[PSL_OVERLAY_FILE_ENV];
  if (!overlayPath) {
    publicSuffixOverlayCache = { path: null, statKey: null, overlay: { path: null, suffixes: [] } };
    return publicSuffixOverlayCache.overlay;
  }

  let raw;
  let statKey;
  try {
    const stat = fs.statSync(overlayPath);
    statKey = `${stat.dev}:${stat.ino}:${stat.size}:${stat.mtimeMs}`;
    if (
      publicSuffixOverlayCache.path === overlayPath &&
      publicSuffixOverlayCache.statKey === statKey &&
      publicSuffixOverlayCache.overlay
    ) {
      return publicSuffixOverlayCache.overlay;
    }
    raw = readFileUtf8(overlayPath, { label: "PSL overlay file" });
  } catch (error) {
    throw new Error(`PSL overlay file is not readable: ${error.message || String(error)}`);
  }

  const suffixes = [];
  const seen = new Set();
  for (const rawLine of raw.split(/\r?\n/)) {
    const trimmed = rawLine.replace(/\s+#.*$/, "").trim().replace(/^\./, "").replace(/\.+$/, "");
    if (!trimmed || trimmed.startsWith("#")) continue;
    const suffix = normalizeDnsHostToAscii(trimmed, "PSL overlay suffix");
    if (!seen.has(suffix)) {
      seen.add(suffix);
      suffixes.push(suffix);
    }
  }
  suffixes.sort((a, b) => b.length - a.length || a.localeCompare(b));
  const overlay = { path: overlayPath, suffixes };
  publicSuffixOverlayCache = { path: overlayPath, statKey, overlay };
  return overlay;
}

function overlaySuffixForHost(host, overlay) {
  for (const suffix of overlay.suffixes) {
    if (host === suffix || host.endsWith(`.${suffix}`)) return suffix;
  }
  return null;
}

function publicSuffixInfoForHost(host) {
  const normalizedHost = normalizeDnsHostToAscii(host, "host");
  const overlay = readPublicSuffixOverlay();
  const overlaySuffix = overlaySuffixForHost(normalizedHost, overlay);
  if (overlaySuffix) {
    if (normalizedHost === overlaySuffix) {
      return {
        registrable_domain: null,
        public_suffix: overlaySuffix,
        public_suffix_source: "operator_overlay",
        psl_overlay_file: overlay.path,
      };
    }
    const prefix = normalizedHost.slice(0, -(overlaySuffix.length + 1));
    const registrableLabel = prefix.split(".").at(-1);
    return {
      registrable_domain: `${registrableLabel}.${overlaySuffix}`,
      public_suffix: overlaySuffix,
      public_suffix_source: "operator_overlay",
      psl_overlay_file: overlay.path,
    };
  }

  const parsed = psl.parse(normalizedHost);
  if (parsed.error) {
    throw new Error(`target_domain is not a valid public DNS domain: ${host}`);
  }
  return {
    registrable_domain: parsed.domain || null,
    public_suffix: parsed.tld || null,
    public_suffix_source: parsed.listed ? "psl" : "psl_unlisted",
    psl_overlay_file: overlay.path,
  };
}

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
    raw = readFileUtf8(logPath, { label: "scope-warnings.log" });
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

function makeScopeBlockedError(message, details = {}) {
  const error = new Error(message);
  error.code = "SCOPE_BLOCKED";
  error.scope_decision = "blocked";
  error.details = {
    scope_decision: "blocked",
    ...details,
  };
  return error;
}

function assertHttpScopeDomain(targetDomain, opts = {}) {
  const raw = assertSafeDomain(targetDomain);
  let host;
  try {
    host = normalizeDnsHostToAscii(raw, "target_domain");
  } catch (error) {
    throw new Error(`target_domain is not a valid HTTP scope domain: ${targetDomain}`);
  }

  const address = host.replace(/^\[|\]$/g, "");
  if (host.includes(":") || net.isIP(address) || isBlockedInternalHost(host)) {
    // Operator-attested lab/private-target escape (OFF by default, fail-closed).
    // A loopback/RFC1918 IPv4 host whose session carries a valid operator
    // attestation bypasses the public-DNS requirement. Cloud metadata,
    // link-local, IPv6, and .internal/.local names are NOT eligible even under
    // attestation. The attestation is supplied explicitly (opts.labAuthorization,
    // the init bootstrap before state is persisted) or read from the persisted
    // audit-graded session artifact. See lab-target-attest.js.
    if (labTargetEligibleHost(host)) {
      const authorization = opts.labAuthorization != null
        ? opts.labAuthorization
        : labAuthorizationForTarget(host);
      if (labTargetPermitted(host, { authorization })) {
        return host;
      }
    }
    throw new Error(`target_domain is not a public DNS domain: ${targetDomain}`);
  }

  const suffixInfo = publicSuffixInfoForHost(host);
  if (!suffixInfo.registrable_domain) {
    throw new Error(`target_domain must include a registrable domain, not only a public suffix: ${targetDomain}`);
  }

  return host;
}

function validateHttpScanScope(url, targetDomain, opts = {}) {
  const parsed = safeUrlObject(url);
  if (!parsed) {
    throw makeScopeBlockedError("Invalid URL");
  }
  let host;
  try {
    host = normalizeDnsHostToAscii(parsed.hostname, "url host");
  } catch {
    throw makeScopeBlockedError("Invalid URL host");
  }
  let domain;
  try {
    domain = assertHttpScopeDomain(targetDomain, opts);
  } catch (error) {
    throw makeScopeBlockedError(error.message || String(error));
  }
  if (!domain) {
    throw makeScopeBlockedError("target_domain is required for scoped HTTP scans");
  }

  // Lab-attested private target: scope is pinned to the EXACT attested host.
  // Reaching here with a lab-eligible domain means assertHttpScopeDomain already
  // confirmed a valid attestation (else it threw). A private host has no
  // registrable domain / public suffix, so first-party == exact host match —
  // this prevents an attested 192.168.1.53 session from pivoting to any other
  // private host (e.g. 169.254.169.254 or a neighbor on the LAN).
  if (labTargetEligibleHost(domain)) {
    if (host !== domain) {
      throw makeScopeBlockedError(
        `URL host ${host} is outside attested lab target ${domain}`,
        { host, target_domain: domain },
      );
    }
    return {
      allowed: true,
      scope_decision: "allowed",
      reason: "lab_attested_private_target",
      host,
      target_domain: domain,
      registrable_domain: null,
      public_suffix: null,
      public_suffix_source: "lab_attested_private_target",
      psl_overlay_file: null,
    };
  }

  if (!isFirstPartyHost(host, domain)) {
    const domainSuffixInfo = publicSuffixInfoForHost(domain);
    throw makeScopeBlockedError(
      `URL host ${host} is outside target_domain ${domain}`,
      {
        host,
        target_domain: domain,
        registrable_domain: domainSuffixInfo.registrable_domain,
        public_suffix: domainSuffixInfo.public_suffix,
        public_suffix_source: domainSuffixInfo.public_suffix_source,
        psl_overlay_file: domainSuffixInfo.psl_overlay_file,
      },
    );
  }

  const suffixInfo = publicSuffixInfoForHost(domain);
  return {
    allowed: true,
    scope_decision: "allowed",
    reason: "first_party_host",
    host,
    target_domain: domain,
    registrable_domain: suffixInfo.registrable_domain,
    public_suffix: suffixInfo.public_suffix,
    public_suffix_source: suffixInfo.public_suffix_source,
    psl_overlay_file: suffixInfo.psl_overlay_file,
  };
}

function resolveHttpScanTargetDomain(url, explicitTargetDomain = null) {
  if (explicitTargetDomain) {
    return assertHttpScopeDomain(explicitTargetDomain);
  }

  return null;
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
  assertHttpScopeDomain,
  filterExclusionsByHosts,
  normalizeScopeExclusionToken,
  publicSuffixInfoForHost,
  readScopeExclusions,
  resolveHttpScanTargetDomain,
  validateHttpScanScope,
};
