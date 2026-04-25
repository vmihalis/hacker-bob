"use strict";

const fs = require("fs");
const {
  scopeWarningsPath,
} = require("./paths.js");
const {
  safeUrlObject,
} = require("./url-surface.js");

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

  return {
    allowed: true,
    scope_decision: "allowed",
    reason: "permissive",
    host,
    target_domain: domain,
  };
}

function resolveHttpScanTargetDomain(url, explicitTargetDomain = null) {
  if (explicitTargetDomain) {
    return String(explicitTargetDomain).toLowerCase().replace(/\.+$/, "");
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
  filterExclusionsByHosts,
  normalizeScopeExclusionToken,
  readScopeExclusions,
  resolveHttpScanTargetDomain,
  validateHttpScanScope,
};
