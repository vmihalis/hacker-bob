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
} = require("./io/paths.js");
const {
  readFileUtf8,
  withSessionLock,
  writeFileAtomic,
} = require("./io/storage.js");
const { hashCanonicalJson } = require("./verification/verification-contracts.js");
const { appendFrontierEvent } = require("./frontier/frontier-events.js");
const { scheduleMaterialization } = require("./frontier/frontier-materialize-debounce.js");
// Cycle B: KEY each auth-differential per_endpoint row with a domain-separated ed25519
// signature so a Bash-forged cross-tenant-flip row needs the signing key, not just a
// well-formed shape. Signed at WRITE inside persistResults' session lock; verified at the
// consume-time crediting sites (claims.js authDifferentialCovered, agent-run-completion.js
// hasAuthDifferentialSweepForSurface). Reuses signRowWithMac/verifyRowWithMac (NOT a new MAC).
// Does NOT close the same-uid signer residual — the private key is still 0600 at the agent
// uid; the enforced delta is that an unsigned/content-tampered forged row no longer clears
// the id-bearing gate. row_mac is EXCLUDED from results_hash so the hash stays byte-stable.
const { AUTH_DIFFERENTIAL_ROW_MAC_CONTEXT } = require("./ledger-integrity/index.js");
const { signRowViaIsolatedSignerOrLocal } = require("./ledger-integrity/index.js");

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

// results_hash covers the SUBSTANTIVE row content only; row_mac is EXCLUDED from its
// canonical preimage (mirroring invariantFoundryResultHash's container_isolated exclusion).
// The MAC is a keyed signature OVER the row-minus-row_mac, so binding it back into the hash
// would be circular and — more importantly — would make results_hash non-deterministic across
// re-signs. Excluding it keeps results_hash byte-stable/deterministic so the frontier
// observation `ref` and the existing determinism test are unchanged, while the row_mac itself
// still binds every substantive field (flipping any of them invalidates the signature).
function stripRowMacForHash(rows) {
  return rows.map((row) => {
    if (row && typeof row === "object" && !Array.isArray(row)
      && Object.prototype.hasOwnProperty.call(row, "row_mac")) {
      const { row_mac, ...rest } = row;
      return rest;
    }
    return row;
  });
}

// ACCUMULATE across sweeps: each bob_run_auth_differential upserts its rows by
// (surface_id, endpoint, method) into the existing file rather than overwriting it,
// so a run that sweeps surface B does not clobber surface A's coverage — both id-bearing
// surfaces retain their sweep row for the grade-time gate. Returns the merged payload.
function persistResults(domain, payload) {
  ensureSessionDir(domain);
  const filePath = authDifferentialResultsPath(domain);
  // The accumulate/upsert is a read-modify-write on the shared results ledger: read prior,
  // merge this run's rows, write the union. Run it under the reentrant session lock so a
  // concurrent same-domain sweep cannot interleave a lost update, and persist through the
  // atomic write helper (temp + rename) so a crash/failed write leaves the prior ledger
  // byte-intact rather than truncated. The lock is reentrant, so this is a no-op nesting
  // when a caller already holds it. Serialization stays 2-space-indent + trailing newline
  // so on-disk bytes and results_hash are byte-identical to the pre-lock writeFileSync path.
  return withSessionLock(domain, () => {
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
    // SIGN each NEW row (in place) under the auth-differential context through the single
    // signing seam BEFORE the merge/upsert — we already hold the session lock the seam's
    // contract requires. Prior rows on disk retain their existing row_mac (never re-signed,
    // never legitimized). A row already carrying a row_mac is left untouched (signRowWithMac
    // rejects a pre-assigned envelope). The seam isolates the secret when the server runs
    // under a dedicated signer uid; on the same-uid box it degrades to a local sign and the
    // verdict-level attestation gate carries the trust consequence.
    for (const row of newRows) {
      if (row && typeof row === "object" && !Array.isArray(row) && row.row_mac == null) {
        signRowViaIsolatedSignerOrLocal(domain, AUTH_DIFFERENTIAL_ROW_MAC_CONTEXT, row);
      }
    }
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
        per_endpoint: stripRowMacForHash(merged),
      }),
    };
    writeFileAtomic(filePath, `${JSON.stringify(mergedPayload, null, 2)}\n`);
    return mergedPayload;
  });
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
// A completion-earning cross-tenant flip must be observed on a SAFE (idempotent read) method.
// A state-changing method's "denial" is forgeable: one principal DELETEs/POSTs the object and a
// second request (even the SAME account in another session) then sees 404/409 — a STATE artifact,
// not an authorization boundary. Isolation-completion is proven by a READ differential (a distinct
// principal cannot READ the object); a write-isolation break is a FINDING recorded through the
// confirm producers, not a completion flip.
const SAFE_DIFFERENTIAL_METHODS = new Set(["GET", "HEAD"]);

function signatureIsNonError(sig) {
  return !!(sig && typeof sig === "object"
    && ((typeof sig.status === "number" && sig.status >= 200 && sig.status < 300)
      || sig.status_class === "2xx"
      || sig.response_class === "ok"));
}

// A genuine AUTHORIZATION denial (401/403, or existence-hiding 404) — the "negative control
// held" half of a cross-tenant flip. A transient/throttle code (408/425/429) or a generic 400
// is NOT a denial: it must not let a rate-limit on principal B masquerade as an access-control
// boundary. The denied side must also be VALIDATED (a 2xx somewhere) so a junk credential's
// 401 is never a flip. status_class "4xx" is intentionally NOT accepted (too coarse — it would
// re-admit 429).
function signatureIsDenied(sig) {
  return !!(sig && typeof sig === "object"
    && ((typeof sig.status === "number" && (sig.status === 401 || sig.status === 403 || sig.status === 404))
      || sig.response_class === "forbidden"
      || sig.response_class === "unauthorized"));
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
  id_bearing_templates,
  deadline_ms,
}) {
  const domain = assertSafeDomain(target_domain);
  if (typeof base_url !== "string" || base_url.length === 0) {
    throw new Error("base_url must be a non-empty string");
  }
  if (typeof fetch_fn !== "function") {
    throw new Error("fetch_fn must be a function");
  }
  // Reuse the SAME templatizer + route-frozen id-bearing set the grade-time gate uses
  // (claims.js:1972/1986) so the runner's "validated principal" definition cannot drift from
  // the gate's. Required in-function to mirror the gate's require pattern (avoids pulling the
  // large producer module at load, and any require cycle). id_bearing_templates is the caller-
  // resolved, route-frozen {id}-template set for surface_id; an empty/unresolvable set FAILS
  // CLOSED (validates no principal for the flip arm) rather than admitting a public-endpoint 2xx.
  const { templatizeIdBearingEndpoint } = require("./frontier/id-bearing-endpoints.js");
  const idBearingTemplateSet = new Set(
    Array.isArray(id_bearing_templates)
      ? id_bearing_templates.filter((t) => typeof t === "string" && t)
      : [],
  );
  const normalizedEndpoints = normalizeEndpoints(endpoints);
  const profileList = normalizeProfiles(auth_profiles);
  const effectiveLimit = Number.isInteger(limit) && limit > 0 ? limit : DEFAULT_ENDPOINT_LIMIT;
  const cappedEndpoints = normalizedEndpoints.slice(0, effectiveLimit);
  const startedAt = new Date().toISOString();
  const perEndpoint = [];
  const rowFpSignatures = [];
  // A fingerprint is a VALIDATED principal only if it produced a non-error (2xx) response
  // somewhere in the sweep — a real authenticated session. A junk/expired credential that
  // only ever 4xx'd is distinct MATERIAL but not a validated principal, so it must not
  // count toward distinct_principal_count (else [real, junk] forges a 2-principal test).
  const validatedFingerprints = new Set();
  // A STRICTER validated set for the cross_tenant_flip denied-arm gate: a fingerprint qualifies
  // only if its 2xx landed on one of THIS surface's frozen id-bearing endpoints AND that row is
  // GATED (at least one swept principal was genuinely denied there) — not on an arbitrary/public
  // swept endpoint (e.g. /health) and not on a PUBLIC id-bearing endpoint everyone 2xx's. This
  // closes the junk-authenticated forge: a non-anon junk credential that only 2xx's a public (or
  // an ungated, universally-2xx id-bearing) endpoint and 401s the gated id-bearing row is NOT a
  // validated-denied tenant, so it mints no false flip. An empty idBearingTemplateSet leaves this
  // set empty -> no row can flip (fail closed).
  const idBearingValidatedFingerprints = new Set();
  // A fingerprint whose profile metadata explicitly declares an UNAUTHENTICATED request
  // (sent_with_auth === false) is an anon/public arm, never a real DENIED tenant. Such an
  // arm 2xx'ing a public endpoint must not mint a false cross_tenant_flip on a protected row.
  // Only strict === false excludes; absent/undefined sent_with_auth stays eligible so the
  // genuine owner-in/attacker-out two-tenant case still flips.
  const anonFingerprints = new Set();
  let fetchErrorCount = 0;
  let fetchTotal = 0;
  // Sweep-wide wall-clock deadline: an ADDITIVE total-runtime guard layered on top of the
  // per-request timeout_ms hung-arm bound (which is unchanged). When the budget elapses we STOP
  // issuing further arms and leave the remaining endpoints UN-RUN — no row is pushed for them, so
  // they can never mint a divergence or a cross_tenant_flip. An honest partial (a severed link
  // recorded as such), never a forced/false flip. Default OFF: an omitted/invalid deadline_ms
  // leaves the loop and the persisted bytes byte-identical to today.
  const deadlineConfigured = Number.isInteger(deadline_ms) && deadline_ms > 0;
  const sweepStartMs = Date.now();
  let deadlineReached = false;
  let endpointsRun = 0;
  for (let endpointIndex = 0; endpointIndex < cappedEndpoints.length; endpointIndex += 1) {
    if (deadlineConfigured && Date.now() - sweepStartMs >= deadline_ms) {
      deadlineReached = true;
      break;
    }
    const { endpoint, method } = cappedEndpoints[endpointIndex];
    const url = joinUrl(base_url, endpoint);
    const signaturesByProfile = {};
    const fetchErrorsByProfile = {};
    // AB/BA counterbalancing: alternate which arm is fetched FIRST per endpoint so no single
    // profile is systematically the second (later) request and therefore systematically the
    // one exposed to a mid-sweep deploy/WAF/cache shift — averaging that drift across arms
    // instead of attributing it to the principal. Exactly one request per (endpoint, profile)
    // (N=1), so there is no request-budget/http-audit/circuit-breaker regression. Only the
    // wall-clock fetch order changes: results are re-keyed into canonical profileList order
    // below, so signatures_by_profile bytes, divergences (diffResponseSignatures sorts
    // profiles), distinct_principal_count, cross_tenant_flip, and results_hash are all
    // order-invariant.
    const armOrder = endpointIndex % 2 === 0 ? profileList : profileList.slice().reverse();
    const signatureByProfile = new Map();
    const errorByProfile = new Map();
    for (const profile of armOrder) {
      fetchTotal += 1;
      let observed;
      try {
        observed = await fetch_fn({ url, method, auth_profile: profile, endpoint });
      } catch (err) {
        errorByProfile.set(profile, err.message || String(err));
        fetchErrorCount += 1;
        continue;
      }
      if (observed == null || typeof observed !== "object") {
        errorByProfile.set(profile, "fetch_fn returned non-object");
        fetchErrorCount += 1;
        continue;
      }
      signatureByProfile.set(profile, computeResponseSignature(observed));
    }
    // Re-key both result maps in canonical profileList order so the persisted key order
    // (and the serialized bytes) is independent of the AB/BA fetch order.
    for (const profile of profileList) {
      if (signatureByProfile.has(profile)) signaturesByProfile[profile] = signatureByProfile.get(profile);
      if (errorByProfile.has(profile)) fetchErrorsByProfile[profile] = errorByProfile.get(profile);
    }
    const divergences = Object.keys(signaturesByProfile).length >= 2
      ? diffResponseSignatures({
        signatures_by_profile: signaturesByProfile,
        profile_metadata: profile_metadata || null,
      })
      : [];
    // "Gated" for THIS row = at least one swept principal got a genuine authorization denial
    // (401/403/404, not a throttle) on this endpoint. All of this endpoint's signatures are
    // already collected in signaturesByProfile, so gatedness is a row-level property computed
    // once, before the per-fingerprint loop, reusing the existing signatureIsDenied helper.
    const rowGated = Object.values(signaturesByProfile).some(signatureIsDenied);
    // Map this row's fingerprints (MCP-owned, so two profile NAMES of one session collapse)
    // to their signature, and mark any that AUTHENTICATED (2xx) anywhere as validated
    // principals. distinct_principal_count and cross_tenant_flip are finalized post-loop.
    const rowFpSig = new Map();
    for (const profile of Object.keys(signaturesByProfile)) {
      const meta = profile_metadata && typeof profile_metadata === "object" ? profile_metadata[profile] : null;
      const fp = meta && typeof meta === "object" ? meta.principal_fingerprint : null;
      if (typeof fp !== "string" || !fp) continue;
      rowFpSig.set(fp, signaturesByProfile[profile]);
      if (signatureIsNonError(signaturesByProfile[profile])) {
        validatedFingerprints.add(fp);
        // Additionally record this principal as validated-for-flip only when its 2xx landed on a
        // row that is BOTH id-bearing AND gated: one of THIS surface's frozen id-bearing endpoints
        // (endpoint is this row's own path, in scope) AND a row where >=1 swept principal was
        // genuinely denied (rowGated). templatizeIdBearingEndpoint returns null for a non-id-bearing
        // path (e.g. /health) and Set.has(null) is false, so a public 2xx never qualifies; rowGated
        // additionally rejects a PUBLIC id-bearing endpoint everyone 2xx's — it validates NO ONE.
        if (rowGated && idBearingTemplateSet.has(templatizeIdBearingEndpoint(endpoint))) idBearingValidatedFingerprints.add(fp);
      }
      if (meta && typeof meta === "object" && meta.sent_with_auth === false) anonFingerprints.add(fp);
    }
    perEndpoint.push({
      // The surface this sweep was run for (passed by the caller). NOTE: the ADVERSARIAL
      // binding is the gate's endpoint-membership check against this surface's materialized
      // id-bearing endpoints; surface_id only scopes which surface the row may credit.
      surface_id: typeof surface_id === "string" && surface_id ? surface_id : null,
      endpoint,
      method,
      // The ACTUAL joined URL this arm was fetched against (joinUrl(base_url, endpoint), the same
      // `url` used for the fetch_fn call above). Persisting it binds the SIGNED endpoint to the
      // TESTED endpoint: without it, a row carries only endpoint+method, so a real flip observed on
      // an easy same-host path under a benign base_url (e.g. /safe-prefix) could be signed and later
      // credited as the crown surface's path. effective_url enters the row_mac preimage (it is a
      // substantive, non-row_mac field), so tampering with the tested URL invalidates the signature.
      // It is a pure derivation of endpoint+base_url, both already order-determining the row sort, so
      // results_hash stays deterministic and order-invariant.
      effective_url: url,
      signatures_by_profile: signaturesByProfile,
      divergences,
      distinct_principal_count: 0,
      cross_tenant_flip: false,
      fetch_errors_by_profile: fetchErrorsByProfile,
    });
    rowFpSignatures.push(rowFpSig);
    endpointsRun += 1;
  }
  // Finalize per row: distinct_principal_count over VALIDATED principals, and cross_tenant_flip
  // = a VALIDATED principal ACCESSED this object (2xx) while a DISTINCT VALIDATED principal was
  // DENIED it (4xx) — the negative control flipped. Same-account-twice (both 2xx, no denial) and
  // [real, junk] (junk not validated) both fail to produce a flip.
  perEndpoint.forEach((row, i) => {
    const fpSig = rowFpSignatures[i];
    const accessors = new Set();
    const deniedValidated = new Set();
    let distinct = 0;
    for (const [fp, sig] of fpSig) {
      if (validatedFingerprints.has(fp)) distinct += 1;
      if (signatureIsNonError(sig)) accessors.add(fp);
      // A denied arm must be a real tenant that PROVED authenticated access to a GATED (id-bearing)
      // resource: `idBearingValidatedFingerprints.has(fp)` requires this principal to have 2xx'd one
      // of THIS surface's frozen id-bearing endpoints somewhere in the sweep. That membership check
      // is the load-bearing gate — its ABSENCE is exactly the forge U1b closes: a non-anon junk
      // credential that only 2xx's a public endpoint (/health) and 401s this id-bearing row would
      // otherwise be admitted as the "validated denied" tenant and mint a false cross_tenant_flip
      // with no real 2-tenant test. `signatureIsDenied(sig)` requires a genuine 401/403/404 (not a
      // throttle) on this row; `!anonFingerprints.has(fp)` is retained as U1 defense-in-depth.
      else if (signatureIsDenied(sig) && idBearingValidatedFingerprints.has(fp) && !anonFingerprints.has(fp)) deniedValidated.add(fp);
    }
    row.distinct_principal_count = distinct;
    // Only a SAFE-method row earns the completion flip (a state-changing "denial" is a forgeable
    // state artifact, not authorization). Non-safe rows still carry signatures/divergences for lead
    // value but never set cross_tenant_flip, so they cannot clear an id-bearing surface.
    const rowMethodSafe = SAFE_DIFFERENTIAL_METHODS.has(String(row.method || "GET").toUpperCase());
    row.cross_tenant_flip = rowMethodSafe
      && [...accessors].some((a) => [...deniedValidated].some((b) => a !== b));
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
    // endpoints_tested is the ACTUAL number of endpoints run (== cappedEndpoints.length unless a
    // deadline cut the sweep short), so coverage is never over-reported. endpoints_skipped_by_limit
    // is the count trimmed by the endpoint cap. The deadline keys are emitted ONLY when a deadline
    // was configured, so an un-deadlined run's summary bytes/results_hash are unchanged from today.
    endpoints_tested: endpointsRun,
    endpoints_skipped_by_limit: normalizedEndpoints.length - cappedEndpoints.length,
    ...(deadlineConfigured
      ? {
        endpoints_skipped_by_deadline: cappedEndpoints.length - endpointsRun,
        deadline_reached: deadlineReached,
      }
      : {}),
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
    per_endpoint: stripRowMacForHash(perEndpoint),
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
