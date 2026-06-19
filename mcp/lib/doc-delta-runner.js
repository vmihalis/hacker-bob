"use strict";

const fs = require("fs");
const { detectDivergences } = require("./contract-divergence.js");
const { querySchemaContracts } = require("./schema-contracts-store.js");
const {
  assertSafeDomain,
  docDeltaResultsPath,
  sessionDir,
} = require("./paths.js");
const {
  readFileUtf8,
} = require("./storage.js");
const { hashCanonicalJson } = require("./verification-contracts.js");
const { appendFrontierEvent } = require("./frontier-events.js");
const { scheduleMaterialization } = require("./frontier-materialize-debounce.js");

const DEFAULT_LIMIT = 200;
const MAX_LIMIT = 1000;

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

function summariseObserved(observed) {
  return {
    status: typeof observed.status === "number" ? observed.status : null,
    content_type: typeof observed.content_type === "string" ? observed.content_type : null,
    sent_with_auth: observed.sent_with_auth === true,
  };
}

function countByType(perContract) {
  const counts = {};
  for (const entry of perContract) {
    for (const divergence of entry.divergences) {
      counts[divergence.type] = (counts[divergence.type] || 0) + 1;
    }
  }
  return counts;
}

function countBySeverity(perContract) {
  const counts = {};
  for (const entry of perContract) {
    for (const divergence of entry.divergences) {
      counts[divergence.severity_class] = (counts[divergence.severity_class] || 0) + 1;
    }
  }
  return counts;
}

function persistResults(domain, payload) {
  ensureSessionDir(domain);
  const filePath = docDeltaResultsPath(domain);
  fs.writeFileSync(filePath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
}

function readResults(domain) {
  const filePath = docDeltaResultsPath(domain);
  if (!fs.existsSync(filePath)) return null;
  const raw = readFileUtf8(filePath, { label: "doc-delta-results.json" });
  try {
    return JSON.parse(raw);
  } catch (err) {
    throw new Error(`Malformed doc-delta-results.json: ${err.message || String(err)}`);
  }
}

async function runDocDelta({
  target_domain,
  base_url,
  fetch_fn,
  endpoint_pattern,
  method,
  limit,
  run_id,
}) {
  const domain = assertSafeDomain(target_domain);
  if (typeof base_url !== "string" || base_url.length === 0) {
    throw new Error("base_url must be a non-empty string");
  }
  if (typeof fetch_fn !== "function") {
    throw new Error("fetch_fn must be a function");
  }
  const effectiveLimit = Number.isInteger(limit) && limit > 0
    ? Math.min(limit, MAX_LIMIT)
    : DEFAULT_LIMIT;
  const queryResult = querySchemaContracts({
    target_domain: domain,
    endpoint_pattern,
    method,
    limit: effectiveLimit,
  });
  const contracts = queryResult.contracts;
  const startedAt = new Date().toISOString();
  const perContract = [];
  for (const contract of contracts) {
    const url = joinUrl(base_url, contract.endpoint);
    let observed;
    try {
      observed = await fetch_fn({ url, method: contract.method, contract });
    } catch (err) {
      perContract.push({
        contract_hash: contract.contract_hash,
        endpoint: contract.endpoint,
        method: contract.method,
        observed: null,
        divergences: [],
        fetch_error: err.message || String(err),
      });
      continue;
    }
    if (observed == null || typeof observed !== "object") {
      perContract.push({
        contract_hash: contract.contract_hash,
        endpoint: contract.endpoint,
        method: contract.method,
        observed: null,
        divergences: [],
        fetch_error: "fetch_fn returned non-object",
      });
      continue;
    }
    const divergences = detectDivergences(contract, observed);
    perContract.push({
      contract_hash: contract.contract_hash,
      endpoint: contract.endpoint,
      method: contract.method,
      observed: summariseObserved(observed),
      divergences,
    });
  }
  perContract.sort((a, b) => a.contract_hash.localeCompare(b.contract_hash));
  const summary = {
    target_domain: domain,
    base_url,
    started_at: startedAt,
    finished_at: new Date().toISOString(),
    run_id: typeof run_id === "string" && run_id.length > 0 ? run_id : null,
    contracts_tested: contracts.length,
    contracts_in_corpus: queryResult.total_in_corpus,
    contracts_skipped_by_filter: queryResult.total_in_corpus - contracts.length,
    fetch_errors: perContract.filter((entry) => entry.fetch_error != null).length,
    divergences_total: perContract.reduce((acc, entry) => acc + entry.divergences.length, 0),
    divergences_by_type: countByType(perContract),
    divergences_by_severity: countBySeverity(perContract),
  };
  const payload = {
    schema_version: 1,
    summary,
    per_contract: perContract,
  };
  payload.results_hash = hashCanonicalJson({ summary: { ...summary, started_at: null, finished_at: null }, per_contract: perContract });
  // LEGACY: removed in Plane D — doc-delta-results.json remains during the
  // dual-write window so capability-eval and report-writer keep working;
  // frontier-events.jsonl carries the authoritative observation signal.
  persistResults(domain, payload);

  // Dual-write per Pact P2: each doc-delta contract probe is an observation
  // that compares a documented contract to live behavior. Emit one
  // observation.recorded per contract so the frontier projection can fold
  // them onto whichever surface the contract maps to downstream.
  for (const entry of perContract) {
    try {
      appendFrontierEvent({
        target_domain: domain,
        kind: "observation.recorded",
        payload: {
          observation_kind: "doc_delta",
          endpoint: entry.endpoint,
          method: entry.method,
          contract_hash: entry.contract_hash,
          divergence_count: entry.divergences.length,
          divergence_types: Array.from(new Set(entry.divergences.map((d) => d.type))).sort(),
          divergence_severities: Array.from(new Set(entry.divergences.map((d) => d.severity_class))).sort(),
          fetch_error: entry.fetch_error || null,
          run_id: summary.run_id,
          results_hash: payload.results_hash,
        },
        source: {
          artifact: "doc-delta-results.json",
          tool: "bob_run_doc_delta",
          ref: entry.contract_hash,
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
  runDocDelta,
  readResults,
  joinUrl,
  MAX_LIMIT,
};
