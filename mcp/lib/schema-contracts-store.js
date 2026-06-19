"use strict";

const fs = require("fs");
const { parseSchemaDoc } = require("./schema-contracts.js");
const {
  assertSafeDomain,
  schemaContractsJsonlPath,
  sessionDir,
} = require("./paths.js");
const {
  readFileUtf8,
  withSessionLock,
  writeFileAtomic,
} = require("./storage.js");
const { appendFrontierEvent } = require("./frontier-events.js");
const { scheduleMaterialization } = require("./frontier-materialize-debounce.js");

function ensureSessionDir(domain) {
  const dir = sessionDir(domain);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  return dir;
}

function readJsonlContracts(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const raw = readFileUtf8(filePath, { label: "schema-contracts.jsonl" });
  const lines = raw.split(/\r?\n/).filter((line) => line.trim().length > 0);
  const records = [];
  for (let i = 0; i < lines.length; i++) {
    try {
      records.push(JSON.parse(lines[i]));
    } catch (err) {
      throw new Error(
        `Malformed schema-contracts.jsonl at line ${i + 1}: ${err.message || String(err)}`,
      );
    }
  }
  return records;
}

function writeJsonlContracts(filePath, records) {
  const sorted = records.slice().sort((a, b) => {
    const aHash = typeof a.contract_hash === "string" ? a.contract_hash : "";
    const bHash = typeof b.contract_hash === "string" ? b.contract_hash : "";
    if (aHash < bHash) return -1;
    if (aHash > bHash) return 1;
    return 0;
  });
  const body = sorted.map((record) => JSON.stringify(record)).join("\n");
  writeFileAtomic(filePath, body.length > 0 ? body + "\n" : "");
}

function ingestSchemaDoc({ target_domain, raw_doc, source_uri }) {
  const domain = assertSafeDomain(target_domain);
  if (typeof raw_doc !== "string" || raw_doc.length === 0) {
    throw new Error("raw_doc must be a non-empty string");
  }
  const sourceUri = typeof source_uri === "string" && source_uri.length > 0 ? source_uri : null;
  const ingestedAt = new Date().toISOString();
  const parsed = parseSchemaDoc(raw_doc);
  if (!parsed.schema_format) {
    return {
      schema_format: null,
      contract_count: 0,
      new_count: 0,
      replaced_count: 0,
      source_doc_hash: parsed.source_doc_hash,
      source_uri: sourceUri,
      total_in_corpus: 0,
      parser_warnings: parsed.parser_warnings,
    };
  }
  return withSessionLock(domain, () => {
    ensureSessionDir(domain);
    const filePath = schemaContractsJsonlPath(domain);
    const existing = readJsonlContracts(filePath);
    const byHash = new Map();
    for (const record of existing) {
      if (record && typeof record.contract_hash === "string") {
        byHash.set(record.contract_hash, record);
      }
    }
    let newCount = 0;
    let replacedCount = 0;
    for (const contract of parsed.contracts) {
      const record = {
        ...contract,
        schema_format: parsed.schema_format,
        source_doc_hash: parsed.source_doc_hash,
        source_uri: sourceUri,
        ingested_at: ingestedAt,
      };
      if (byHash.has(contract.contract_hash)) {
        replacedCount += 1;
      } else {
        newCount += 1;
      }
      byHash.set(contract.contract_hash, record);
    }
    const records = Array.from(byHash.values());
    // LEGACY: removed in Plane D — schema-contracts.jsonl remains during the
    // dual-write window so doc-delta and query-schema-contracts keep working;
    // frontier-events.jsonl carries the authoritative observation signal.
    writeJsonlContracts(filePath, records);
    // Dual-write per Pact P2: each ingested schema contract is a static schema
    // observation. Emit one observation.recorded per contract so the frontier
    // projection sees the schema_field surface signal alongside the legacy
    // contract corpus.
    for (const contract of parsed.contracts) {
      try {
        appendFrontierEvent({
          target_domain: domain,
          kind: "observation.recorded",
          payload: {
            observation_kind: "schema_field",
            endpoint: typeof contract.endpoint === "string" ? contract.endpoint : null,
            method: typeof contract.method === "string" ? contract.method : null,
            contract_hash: typeof contract.contract_hash === "string" ? contract.contract_hash : null,
            schema_format: parsed.schema_format,
            source_doc_hash: parsed.source_doc_hash,
            source_uri: sourceUri,
            claimed_auth_schemes: contract.claimed_auth && Array.isArray(contract.claimed_auth.schemes)
              ? contract.claimed_auth.schemes
              : [],
            param_count: Array.isArray(contract.claimed_params) ? contract.claimed_params.length : 0,
            documented_status_codes: Object.keys(contract.claimed_response_shape || {}).sort(),
          },
          source: {
            artifact: "schema-contracts.jsonl",
            tool: "bob_ingest_schema_doc",
            ref: typeof contract.contract_hash === "string" ? contract.contract_hash : null,
          },
        });
      } catch {
        // Frontier ledger is dual-write best-effort during the deprecation window.
      }
    }
    try {
      scheduleMaterialization(domain);
    } catch {}
    return {
      schema_format: parsed.schema_format,
      contract_count: parsed.contracts.length,
      new_count: newCount,
      replaced_count: replacedCount,
      source_doc_hash: parsed.source_doc_hash,
      source_uri: sourceUri,
      total_in_corpus: records.length,
      parser_warnings: parsed.parser_warnings,
    };
  });
}

function querySchemaContracts({ target_domain, endpoint_pattern, method, limit }) {
  const domain = assertSafeDomain(target_domain);
  const filePath = schemaContractsJsonlPath(domain);
  if (!fs.existsSync(filePath)) {
    return { contracts: [], total_matched: 0, source_count: 0, total_in_corpus: 0 };
  }
  const records = readJsonlContracts(filePath);
  const methodFilter = typeof method === "string" && method.length > 0
    ? method.toUpperCase()
    : null;
  const patternFilter = typeof endpoint_pattern === "string" && endpoint_pattern.length > 0
    ? endpoint_pattern
    : null;
  const matched = [];
  const sourceSet = new Set();
  for (const record of records) {
    if (record == null || typeof record !== "object") continue;
    if (typeof record.source_doc_hash === "string") {
      sourceSet.add(record.source_doc_hash);
    }
    if (methodFilter && record.method !== methodFilter) continue;
    if (patternFilter
      && (typeof record.endpoint !== "string" || !record.endpoint.includes(patternFilter))) {
      continue;
    }
    matched.push(record);
  }
  const cap = Number.isInteger(limit) && limit > 0 ? limit : matched.length;
  return {
    contracts: matched.slice(0, cap),
    total_matched: matched.length,
    source_count: sourceSet.size,
    total_in_corpus: records.length,
  };
}

const SCHEMA_SLICE_DEFAULT_LIMIT = 5;
const SCHEMA_SLICE_MAX_LIMIT = 25;

function compactContractForSlice(contract) {
  if (contract == null || typeof contract !== "object") return null;
  const auth = contract.claimed_auth || {};
  return {
    endpoint: typeof contract.endpoint === "string" ? contract.endpoint : null,
    method: typeof contract.method === "string" ? contract.method : null,
    claimed_auth_schemes: Array.isArray(auth.schemes) ? auth.schemes : [],
    none_allowed: auth.none_allowed === true,
    param_count: Array.isArray(contract.claimed_params) ? contract.claimed_params.length : 0,
    documented_status_codes: Object.keys(contract.claimed_response_shape || {}).sort(),
    contract_hash: typeof contract.contract_hash === "string" ? contract.contract_hash.slice(0, 16) : null,
    schema_format: typeof contract.schema_format === "string" ? contract.schema_format : null,
  };
}

function summarizeSchemaSliceForSurface(domain, surfaceObj, options) {
  const opts = options || {};
  const requestedLimit = Number.isInteger(opts.limit) && opts.limit > 0 ? opts.limit : SCHEMA_SLICE_DEFAULT_LIMIT;
  const limit = Math.min(requestedLimit, SCHEMA_SLICE_MAX_LIMIT);
  let queryResult;
  try {
    queryResult = querySchemaContracts({ target_domain: domain });
  } catch (_err) {
    return null;
  }
  if (queryResult.total_in_corpus === 0) return null;
  const candidateHints = [];
  if (surfaceObj && typeof surfaceObj === "object") {
    if (typeof surfaceObj.endpoint_pattern === "string" && surfaceObj.endpoint_pattern.length > 0) {
      candidateHints.push(surfaceObj.endpoint_pattern);
    }
    if (Array.isArray(surfaceObj.endpoints)) {
      for (const endpoint of surfaceObj.endpoints) {
        if (typeof endpoint === "string" && endpoint.length > 0) {
          candidateHints.push(endpoint);
        }
      }
    }
  }
  let matchedHint = null;
  let contracts = queryResult.contracts;
  for (const hint of candidateHints) {
    const filtered = contracts.filter((contract) =>
      typeof contract.endpoint === "string" && contract.endpoint.includes(hint));
    if (filtered.length > 0) {
      contracts = filtered;
      matchedHint = hint;
      break;
    }
  }
  const sliced = contracts.slice(0, limit)
    .map(compactContractForSlice)
    .filter((entry) => entry != null);
  return {
    total_in_corpus: queryResult.total_in_corpus,
    matched_to_surface: contracts.length,
    contracts: sliced,
    truncated: contracts.length > limit,
    hint_applied: matchedHint,
    limit,
  };
}

module.exports = {
  ingestSchemaDoc,
  querySchemaContracts,
  summarizeSchemaSliceForSurface,
};
