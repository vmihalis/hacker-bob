"use strict";

// Auth-differential is a LEAD sweep: divergences are frontier OBSERVATIONS, never signed
// findings. Function-level / privilege-escalation authorization is endpoint-specific policy
// with no synthetic-control equivalent to the IDOR canary (a producer-minted object whose
// cross-tenant leak is cryptographically provable), so a divergence CANNOT be auto-signed
// without agent-supplied policy judgment — which false-positives on legitimate tiered access
// (an endpoint intentionally serving role-scoped fields produces the same divergence as a
// breach). Object-id IDOR is the one mechanically-confirmable class and is signed by
// bob_http_idor_confirm. Confirm a suspected BFLA via a targeted manual flip, not an
// auto-producer over these observations.

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

function rowUpsertKey(row) {
  const sid = row && typeof row.surface_id === "string" ? row.surface_id : "";
  const ep = row && typeof row.endpoint === "string" ? row.endpoint : "";
  const m = row && typeof row.method === "string" ? row.method : "";
  return `${sid}\t${ep}\t${m}`;
}

// ACCUMULATE across sweeps: each bob_run_auth_differential upserts its rows by
// (surface_id, endpoint, method) into the existing file rather than overwriting it,
// so a run that sweeps surface B does not clobber surface A's coverage — both id-bearing
// surfaces retain their sweep row for the grade-time gate. Returns the merged payload.
function persistResults(domain, payload) {
  ensureSessionDir(domain);
  const filePath = authDifferentialResultsPath(domain);
  let priorRows = [];
  if (fs.existsSync(filePath)) {
    try {
      const prior = JSON.parse(readFileUtf8(filePath, { label: "auth-differential-results.json" }));
      if (prior && Array.isArray(prior.per_endpoint)) priorRows = prior.per_endpoint;
    } catch {
      priorRows = [];
    }
  }
  const newRows = Array.isArray(payload.per_endpoint) ? payload.per_endpoint : [];
  const newKeys = new Set(newRows.map(rowUpsertKey));
  const merged = priorRows.filter((row) => !newKeys.has(rowUpsertKey(row))).concat(newRows);
  merged.sort((a, b) => rowUpsertKey(a).localeCompare(rowUpsertKey(b)));
  const summary = {
    ...payload.summary,
    divergences_total: merged.reduce((acc, e) => acc + (Array.isArray(e.divergences) ? e.divergences.length : 0), 0),
    divergences_by_type: countByType(merged),
    divergences_by_severity: countBySeverity(merged),
  };
  const mergedPayload = {
    ...payload,
    summary,
    per_endpoint: merged,
    results_hash: hashCanonicalJson({
      summary: { ...summary, started_at: null, finished_at: null },
      per_endpoint: merged,
    }),
  };
  fs.writeFileSync(filePath, `${JSON.stringify(mergedPayload, null, 2)}\n`, "utf8");
  return mergedPayload;
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

// A per_endpoint row counts as an EXECUTED cross-tenant differential only if the
// sweep actually exercised access: at least one swept principal got a non-error
// (2xx) response — a real account reached the collection — OR the negative control
// FLIPPED (a recorded divergence). Two fabricated credentials that both get denied
// (401/403, no divergence) minted distinct fingerprints but never tested isolation,
// so they do not earn completion. Single-source for both completion gates.
function signatureIsNonError(sig) {
  return !!(sig && typeof sig === "object"
    && ((typeof sig.status === "number" && sig.status >= 200 && sig.status < 300)
      || sig.status_class === "2xx"
      || sig.response_class === "ok"));
}

function rowShowsExecutedDifferential(row) {
  const signatures = row && row.signatures_by_profile;
  if (!(signatures && typeof signatures === "object" && !Array.isArray(signatures))) return false;
  // Require REAL authenticated access: at least one swept principal got a non-error (2xx)
  // response, proving a real account reached the collection. A sweep where every principal
  // is DENIED (401/403 — even with a status_class divergence BETWEEN two denial codes)
  // never accessed the resource and never tested cross-tenant isolation.
  return Object.values(signatures).some(signatureIsNonError);
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
  surface_id,
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
  const rowFingerprintSets = [];
  // A fingerprint is a VALIDATED principal only if it produced a non-error (2xx) response
  // somewhere in the sweep — a real authenticated session. A junk/expired credential that
  // only ever 4xx'd is distinct MATERIAL but not a validated principal, so it must not
  // count toward distinct_principal_count (else [real, junk] forges a 2-principal test).
  const validatedFingerprints = new Set();
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
    // Collect this row's fingerprints (by MCP-owned auth fingerprint, so two profile NAMES
    // bound to the same session collapse to one) and mark those that AUTHENTICATED (2xx)
    // anywhere as validated principals; distinct_principal_count is finalized post-loop.
    const rowFps = new Set();
    for (const profile of Object.keys(signaturesByProfile)) {
      const meta = profile_metadata && typeof profile_metadata === "object" ? profile_metadata[profile] : null;
      const fp = meta && typeof meta === "object" ? meta.principal_fingerprint : null;
      if (typeof fp !== "string" || !fp) continue;
      rowFps.add(fp);
      if (signatureIsNonError(signaturesByProfile[profile])) validatedFingerprints.add(fp);
    }
    perEndpoint.push({
      // The surface this sweep was run for (passed by the caller). NOTE: the ADVERSARIAL
      // binding is the gate's endpoint-membership check against this surface's materialized
      // id-bearing endpoints; surface_id only scopes which surface the row may credit.
      surface_id: typeof surface_id === "string" && surface_id ? surface_id : null,
      endpoint,
      method,
      signatures_by_profile: signaturesByProfile,
      divergences,
      distinct_principal_count: 0,
      fetch_errors_by_profile: fetchErrorsByProfile,
    });
    rowFingerprintSets.push(rowFps);
  }
  // Finalize distinct_principal_count over VALIDATED principals only (>=1 2xx in the sweep).
  perEndpoint.forEach((row, i) => {
    let n = 0;
    for (const fp of rowFingerprintSets[i]) if (validatedFingerprints.has(fp)) n += 1;
    row.distinct_principal_count = n;
  });
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
  const persisted = persistResults(domain, payload);

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
          results_hash: persisted.results_hash,
        },
        source: {
          artifact: "auth-differential-results.json",
          tool: "bob_run_auth_differential",
          ref: persisted.results_hash,
        },
      });
    } catch {
      // Frontier ledger is dual-write best-effort during the deprecation window.
    }
  }
  try {
    scheduleMaterialization(domain);
  } catch {}
  return persisted;
}

module.exports = {
  runAuthDifferential,
  readResults,
  rowShowsExecutedDifferential,
  joinUrl,
  normalizeEndpoints,
  normalizeProfiles,
};
