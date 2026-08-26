"use strict";

// Per-session registry of advisory candidate mechanism templates. This is the
// runtime, target_domain-keyed, MCP-owned store the frozen module-level corpus
// (invariant-template-corpus.js) cannot carry: MECHANISM_TEMPLATES is frozen at
// require time, so a live open-vocab feed needs a mutable session ledger that the
// loader merge reads from. The store mirrors the audit-report / schema-contract
// ingest shape: a per-session JSONL, idempotent by candidateDedupKey, read back
// by the corpus merge.
//
// Every persisted candidate is TIER-3 advisory: it ranks/seeds attention but can
// never mint a verdict, closure, or claim. It carries claim_authority:false and
// candidate:true so a reader cannot mistake it for a confirmed corpus template;
// the only writer that can flip a record's tier to 2 is the promotion gate
// (mechanism-promotion-gate.js) with its all-three executed bar. Registering a
// candidate self-confirms NOTHING — it RESOLVES only via an executed differential
// elsewhere.

const fs = require("fs");
const {
  assertSafeDomain,
  mechanismCandidatesJsonlPath,
  sessionDir,
} = require("../io/paths.js");
const {
  readFileUtf8,
  withSessionLock,
  writeFileAtomic,
} = require("../io/storage.js");
const {
  normalizeMechanismTemplate,
} = require("./invariant-template-corpus.js");
const {
  candidateDedupKey,
} = require("./mechanism-template-ingest.js");
const {
  validateNoSensitiveMaterial,
} = require("../redaction/index.js");

// The advisory tier a registered candidate carries. A corpus template is tier-2
// (confirmed, validated, trusted reuse); a registered candidate is tier-3 and
// stays distinguishable from confirmed.
const CANDIDATE_TIER = 3;

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function ensureSessionDir(domain) {
  const dir = sessionDir(domain);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  return dir;
}

function readJsonlRecords(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const raw = readFileUtf8(filePath, { label: "mechanism-candidates.jsonl" });
  const lines = raw.split(/\r?\n/).filter((line) => line.trim().length > 0);
  const records = [];
  for (let i = 0; i < lines.length; i++) {
    try {
      records.push(JSON.parse(lines[i]));
    } catch (err) {
      throw new Error(
        `Malformed mechanism-candidates.jsonl at line ${i + 1}: ${err.message || String(err)}`,
      );
    }
  }
  return records;
}

function writeJsonlRecords(filePath, records) {
  const sorted = records.slice().sort((a, b) => {
    const aKey = typeof a.dedup_key === "string" ? a.dedup_key : "";
    const bKey = typeof b.dedup_key === "string" ? b.dedup_key : "";
    if (aKey < bKey) return -1;
    if (aKey > bKey) return 1;
    return 0;
  });
  const body = sorted.map((record) => JSON.stringify(record)).join("\n");
  writeFileAtomic(filePath, body.length > 0 ? body + "\n" : "");
}

// Build the persisted record from a caller-supplied candidate template. The
// loader-validated subset (the 10 shape keys) comes from normalizeMechanismTemplate
// so a malformed candidate is REFUSED here, exactly as the loader refuses it; the
// advisory tier metadata (tier:3, candidate:true, claim_authority:false,
// source_tier, advisory_evidence) is preserved alongside so a downstream reader
// keeps the merely-believed marker. The dedup_key is the registry's idempotency
// key, mirroring candidateDedupKey.
function buildRegistryRecord(candidate) {
  if (!isPlainObject(candidate)) {
    return { record: null, warnings: ["candidate must be an object"] };
  }
  const normalized = normalizeMechanismTemplate(candidate);
  if (!normalized.template) {
    return { record: null, warnings: normalized.warnings };
  }
  const dedupKey = candidateDedupKey(candidate);
  if (typeof dedupKey !== "string" || !dedupKey) {
    return { record: null, warnings: ["candidate dedup key could not be derived"] };
  }
  const record = {
    ...normalized.template,
    // A registered candidate is tier-3 advisory and distinguishable from a
    // confirmed corpus template. The promotion gate is the only writer that can
    // flip tier to 2; registration never does.
    tier: CANDIDATE_TIER,
    candidate: true,
    claim_authority: false,
    source_tier: typeof candidate.source_tier === "string" ? candidate.source_tier : "registered",
    dedup_key: dedupKey,
  };
  // The merely-believed marker travels with the record so a reader inspecting a
  // single field cannot lose it. executed_proof:false is explicit — registration
  // carries no executed differential.
  if (isPlainObject(candidate.advisory_evidence)) {
    record.advisory_evidence = candidate.advisory_evidence;
  } else {
    record.advisory_evidence = Object.freeze({
      tier: CANDIDATE_TIER,
      claim_authority: false,
      executed_proof: false,
      verified: false,
    });
  }
  return { record, warnings: [] };
}

// Register a batch of candidate templates into the per-session registry. Idempotent
// by dedup_key: re-registering a candidate with the same key REPLACES it (last
// writer wins) rather than appending a duplicate, mirroring the audit-report
// source_doc_hash / schema-contract contract_hash idempotency. Dedup collapses
// CWE-639 == cwe-639 style duplicates so the registry never holds two records for
// the same mechanism; it NEVER drops a distinct mechanism (rank, don't bound).
function registerMechanismCandidates({ target_domain, candidates }) {
  const domain = assertSafeDomain(target_domain);
  const input = Array.isArray(candidates) ? candidates : [];
  if (input.length === 0) {
    throw new Error("candidates must be a non-empty array");
  }
  const registeredAt = new Date().toISOString();
  return withSessionLock(domain, () => {
    ensureSessionDir(domain);
    const filePath = mechanismCandidatesJsonlPath(domain);
    const existing = readJsonlRecords(filePath);
    const byKey = new Map();
    for (const record of existing) {
      if (isPlainObject(record) && typeof record.dedup_key === "string") {
        byKey.set(record.dedup_key, record);
      }
    }
    const warnings = [];
    let newCount = 0;
    let replacedCount = 0;
    const accepted = [];
    for (const [index, candidate] of input.entries()) {
      const built = buildRegistryRecord(candidate);
      if (!built.record) {
        warnings.push({ index, warnings: built.warnings });
        continue;
      }
      const record = { ...built.record, registered_at: registeredAt };
      // The candidate registry holds advisory data only; a sensitive value
      // smuggled into a candidate field is rejected before it lands on disk.
      validateNoSensitiveMaterial(record, "mechanism_candidate");
      if (byKey.has(record.dedup_key)) {
        replacedCount += 1;
      } else {
        newCount += 1;
      }
      byKey.set(record.dedup_key, record);
      accepted.push({ id: record.id, dedup_key: record.dedup_key, tier: record.tier });
    }
    const records = Array.from(byKey.values());
    writeJsonlRecords(filePath, records);
    return {
      target_domain: domain,
      registered_count: accepted.length,
      new_count: newCount,
      replaced_count: replacedCount,
      total_in_registry: records.length,
      accepted,
      warnings,
      writes_artifacts: true,
    };
  });
}

// Read every registered candidate for a domain. Returns frozen records so a
// consumer cannot mutate the registry through a read. The merge in
// invariant-template-corpus.js layers these tier-3 candidates over the frozen
// tier-2 corpus base, never conflating the two.
function readMechanismCandidates(target_domain) {
  const domain = assertSafeDomain(target_domain);
  const filePath = mechanismCandidatesJsonlPath(domain);
  if (!fs.existsSync(filePath)) return Object.freeze([]);
  const records = readJsonlRecords(filePath);
  const out = [];
  for (const record of records) {
    if (!isPlainObject(record)) continue;
    out.push(Object.freeze({ ...record }));
  }
  return Object.freeze(out);
}

module.exports = {
  CANDIDATE_TIER,
  buildRegistryRecord,
  registerMechanismCandidates,
  readMechanismCandidates,
};
