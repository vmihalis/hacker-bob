"use strict";

const {
  normalizeKnowledgeBatch,
} = require("../core/mechanism/mechanism-template-ingest.js");
const {
  instantiateFamily,
  toCorpusRecord,
} = require("../core/authorization-differential-family.js");
const {
  registerMechanismCandidates,
} = require("../core/mechanism/mechanism-candidate-store.js");

// Build the candidate template list to register from the tool args. Three input
// channels, any combination of which may be supplied:
//   - knowledge_batch: { kind, record, options } envelopes (or bare records with
//     a top-level kind) run through the mechanism-template-ingest normalizer.
//   - include_authz_family: lift the authorization-differential family
//     (object-auth + the four other authz instances) into corpus records — the
//     faithful object-auth lift flows in here.
//   - candidates: pre-normalized candidate template records (loader-shaped) for
//     callers that already hold a corpus record.
// Every produced candidate is tier-3 advisory; the store stamps tier/candidate/
// claim_authority and refuses a malformed shape. The family lift's advisory tier
// metadata (claim_authority:false) is preserved through toCorpusRecord +
// store-side stamping.
function collectCandidates(args) {
  const candidates = [];
  const warnings = [];

  if (Array.isArray(args.knowledge_batch) && args.knowledge_batch.length > 0) {
    const normalized = normalizeKnowledgeBatch(args.knowledge_batch, {
      kind: typeof args.kind === "string" ? args.kind : undefined,
    });
    for (const candidate of normalized.candidates) candidates.push(candidate);
    for (const warning of normalized.warnings) warnings.push(warning);
  }

  if (args.include_authz_family === true) {
    for (const template of instantiateFamily()) {
      const corpusRecord = toCorpusRecord(template);
      // Carry the family's advisory markers onto the record so the store keeps it
      // tier-3 advisory and distinguishable from a confirmed corpus template.
      corpusRecord.tier = template.tier;
      corpusRecord.candidate = true;
      corpusRecord.claim_authority = template.claim_authority;
      corpusRecord.source_tier = "authz_family_lift";
      candidates.push(corpusRecord);
    }
  }

  if (Array.isArray(args.candidates) && args.candidates.length > 0) {
    for (const candidate of args.candidates) candidates.push(candidate);
  }

  return { candidates, warnings };
}

function registerMechanismTemplateHandler(args) {
  const collected = collectCandidates(args || {});
  if (collected.candidates.length === 0) {
    return {
      target_domain: args && args.target_domain,
      registered_count: 0,
      new_count: 0,
      replaced_count: 0,
      total_in_registry: 0,
      accepted: [],
      warnings: collected.warnings,
      note: "no candidate templates resolved from knowledge_batch / include_authz_family / candidates",
      writes_artifacts: false,
    };
  }
  const result = registerMechanismCandidates({
    target_domain: args.target_domain,
    candidates: collected.candidates,
  });
  return {
    ...result,
    warnings: collected.warnings.concat(result.warnings || []),
  };
}

module.exports = Object.freeze({
  name: "bob_register_mechanism_template",
  description:
    "Register advisory tier-3 candidate mechanism templates into the per-session mechanism-candidates.jsonl registry (the open-vocab layer over the frozen corpus). Accepts normalizer knowledge batches (cwe_catalog / audit_finding / schema_contract), the authorization-differential family lift (include_authz_family), and/or pre-normalized candidate records. Idempotent by candidate dedup key. A registered candidate is advisory only: it ranks/seeds attention and RESOLVES only via an executed differential — it never mints a verdict, closure, or claim, and stays distinguishable from a confirmed corpus template (tier:3, candidate:true, claim_authority:false).",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      knowledge_batch: {
        type: "array",
        description:
          "Knowledge records to normalize into candidates. Each item is either { kind, record, options } or a bare record (with a top-level `kind`). kind is one of cwe_catalog / audit_finding / schema_contract.",
        items: { type: "object" },
      },
      kind: {
        type: "string",
        description: "Default kind for bare knowledge_batch records (cwe_catalog / audit_finding / schema_contract).",
      },
      include_authz_family: {
        type: "boolean",
        description:
          "When true, lift the authorization-differential family (object authorization + function-level access control + privilege escalation + business-logic authz + SSRF-as-authz) into tier-3 candidates. The object-auth lift reproduces the hardcoded template field-for-field.",
      },
      candidates: {
        type: "array",
        description: "Pre-normalized candidate template records in the loader-validated shape.",
        items: { type: "object" },
      },
    },
    required: ["target_domain"],
  },
  handler: registerMechanismTemplateHandler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["mechanism-candidates.jsonl"],
});
