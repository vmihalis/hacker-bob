"use strict";

const fs = require("fs");
const {
  computeResponseSignature,
  diffResponseSignatures,
} = require("./auth-differential.js");
const {
  assertSafeDomain,
  authDifferentialResultsPath,
  sessionDir,
} = require("./paths.js");
const {
  readFileUtf8,
} = require("./storage.js");
const { hashCanonicalJson } = require("./verification-contracts.js");
const { appendFrontierEvent } = require("./frontier-events.js");
const { scheduleMaterialization } = require("./frontier-materialize-debounce.js");

const DEFAULT_ENDPOINT_LIMIT = 200;

function ensureSessionDir(domain) {
  const dir = sessionDir(domain);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  return dir;
}

function joinUrl(baseUrl, endpointPath) {
  if (typeof baseUrl !== "string" || baseUrl.length === 0) {
    throw new Error("base_url must be a non-empty string");
  }
  if (typeof endpointPath !== "string" || endpointPath.length === 0) {
    throw new Error("endpoint must be a non-empty string");
  }
  const trimmedBase = baseUrl.replace(/\/+$/, "");
  const normalizedPath = endpointPath.startsWith("/") ? endpointPath : `/${endpointPath}`;
  return `${trimmedBase}${normalizedPath}`;
}

function normalizeEndpoints(rawEndpoints) {
  if (!Array.isArray(rawEndpoints)) {
    throw new Error("endpoints must be an array");
  }
  const result = [];
  for (const entry of rawEndpoints) {
    if (typeof entry === "string" && entry.length > 0) {
      result.push({ endpoint: entry, method: "GET" });
      continue;
    }
    if (entry != null && typeof entry === "object" && typeof entry.endpoint === "string") {
      const method = typeof entry.method === "string" && entry.method.length > 0
        ? entry.method.toUpperCase()
        : "GET";
      result.push({ endpoint: entry.endpoint, method });
    }
  }
  result.sort((a, b) => {
    const byEndpoint = a.endpoint.localeCompare(b.endpoint);
    if (byEndpoint !== 0) return byEndpoint;
    return a.method.localeCompare(b.method);
  });
  return result;
}

function normalizeProfiles(rawProfiles) {
  if (!Array.isArray(rawProfiles)) {
    throw new Error("auth_profiles must be an array");
  }
  const seen = new Set();
  const result = [];
  for (const entry of rawProfiles) {
    if (typeof entry !== "string" || entry.length === 0) continue;
    if (seen.has(entry)) continue;
    seen.add(entry);
    result.push(entry);
  }
  if (result.length < 2) {
    throw new Error("auth_profiles must contain at least two distinct entries");
  }
  return result;
}

function persistResults(domain, payload) {
  ensureSessionDir(domain);
  const filePath = authDifferentialResultsPath(domain);
  fs.writeFileSync(filePath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
}

function readResults(domain) {
  const filePath = authDifferentialResultsPath(domain);
  if (!fs.existsSync(filePath)) return null;
  const raw = readFileUtf8(filePath, { label: "auth-differential-results.json" });
  try {
    return JSON.parse(raw);
  } catch (err) {
    throw new Error(`Malformed auth-differential-results.json: ${err.message || String(err)}`);
  }
}

function countByType(perEndpoint) {
  const counts = {};
  for (const entry of perEndpoint) {
    for (const divergence of entry.divergences) {
      counts[divergence.type] = (counts[divergence.type] || 0) + 1;
    }
  }
  return counts;
}

function countBySeverity(perEndpoint) {
  const counts = {};
  for (const entry of perEndpoint) {
    for (const divergence of entry.divergences) {
      counts[divergence.severity_class] = (counts[divergence.severity_class] || 0) + 1;
    }
  }
  return counts;
}

async function runAuthDifferential({
  target_domain,
  base_url,
  endpoints,
  auth_profiles,
  fetch_fn,
  profile_metadata,
  run_id,
  limit,
}) {
  const domain = assertSafeDomain(target_domain);
  if (typeof base_url !== "string" || base_url.length === 0) {
    throw new Error("base_url must be a non-empty string");
  }
  if (typeof fetch_fn !== "function") {
    throw new Error("fetch_fn must be a function");
  }
  const normalizedEndpoints = normalizeEndpoints(endpoints);
  const profileList = normalizeProfiles(auth_profiles);
  const effectiveLimit = Number.isInteger(limit) && limit > 0 ? limit : DEFAULT_ENDPOINT_LIMIT;
  const cappedEndpoints = normalizedEndpoints.slice(0, effectiveLimit);
  const startedAt = new Date().toISOString();
  const perEndpoint = [];
  let fetchErrorCount = 0;
  let fetchTotal = 0;
  for (const { endpoint, method } of cappedEndpoints) {
    const url = joinUrl(base_url, endpoint);
    const signaturesByProfile = {};
    const fetchErrorsByProfile = {};
    for (const profile of profileList) {
      fetchTotal += 1;
      let observed;
      try {
        observed = await fetch_fn({ url, method, auth_profile: profile, endpoint });
      } catch (err) {
        fetchErrorsByProfile[profile] = err.message || String(err);
        fetchErrorCount += 1;
        continue;
      }
      if (observed == null || typeof observed !== "object") {
        fetchErrorsByProfile[profile] = "fetch_fn returned non-object";
        fetchErrorCount += 1;
        continue;
      }
      signaturesByProfile[profile] = computeResponseSignature(observed);
    }
    const divergences = Object.keys(signaturesByProfile).length >= 2
      ? diffResponseSignatures({
        signatures_by_profile: signaturesByProfile,
        profile_metadata: profile_metadata || null,
      })
      : [];
    perEndpoint.push({
      endpoint,
      method,
      signatures_by_profile: signaturesByProfile,
      divergences,
      fetch_errors_by_profile: fetchErrorsByProfile,
    });
  }
  perEndpoint.sort((a, b) => {
    const byEndpoint = a.endpoint.localeCompare(b.endpoint);
    if (byEndpoint !== 0) return byEndpoint;
    return a.method.localeCompare(b.method);
  });
  const summary = {
    target_domain: domain,
    base_url,
    started_at: startedAt,
    finished_at: new Date().toISOString(),
    run_id: typeof run_id === "string" && run_id.length > 0 ? run_id : null,
    auth_profiles: profileList,
    endpoints_tested: cappedEndpoints.length,
    endpoints_skipped_by_limit: normalizedEndpoints.length - cappedEndpoints.length,
    profiles_tested: profileList.length,
    fetches_total: fetchTotal,
    fetch_errors: fetchErrorCount,
    divergences_total: perEndpoint.reduce((acc, entry) => acc + entry.divergences.length, 0),
    divergences_by_type: countByType(perEndpoint),
    divergences_by_severity: countBySeverity(perEndpoint),
  };
  const payload = {
    schema_version: 1,
    summary,
    per_endpoint: perEndpoint,
  };
  payload.results_hash = hashCanonicalJson({
    summary: { ...summary, started_at: null, finished_at: null },
    per_endpoint: perEndpoint,
  });
  // LEGACY: removed in Plane D — auth-differential-results.json remains during
  // the dual-write window so capability-eval and report-writer keep working;
  // frontier-events.jsonl carries the authoritative observation signal.
  persistResults(domain, payload);

  // Dual-write per Pact P2: each auth-differential run produces a per-endpoint
  // observation about how a surface responds across auth profiles. Emit one
  // observation.recorded event per tested endpoint so the frontier projection
  // can fold them by surface; the runner does not know the surface mapping for
  // endpoints, so observations are surfaced by url-derived surface_ref via
  // payload — downstream readers can join on the same key.
  for (const entry of perEndpoint) {
    try {
      appendFrontierEvent({
        target_domain: domain,
        kind: "observation.recorded",
        payload: {
          observation_kind: "auth_redirect",
          endpoint: entry.endpoint,
          method: entry.method,
          profiles: profileList,
          divergence_count: entry.divergences.length,
          divergence_types: Array.from(new Set(entry.divergences.map((d) => d.type))).sort(),
          divergence_severities: Array.from(new Set(entry.divergences.map((d) => d.severity_class))).sort(),
          run_id: summary.run_id,
          results_hash: payload.results_hash,
        },
        source: {
          artifact: "auth-differential-results.json",
          tool: "bob_run_auth_differential",
          ref: payload.results_hash,
        },
      });
    } catch {
      // Frontier ledger is dual-write best-effort during the deprecation window.
    }
  }
  try {
    scheduleMaterialization(domain);
  } catch {}
  return payload;
}

module.exports = {
  runAuthDifferential,
  readResults,
  joinUrl,
  normalizeEndpoints,
  normalizeProfiles,
};
