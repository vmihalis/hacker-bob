"use strict";

const fs = require("fs");
const { StringDecoder } = require("string_decoder");
const {
  ERROR_CODES,
  ToolError,
} = require("../envelope.js");
const {
  assertNonEmptyString,
  parseAgentId,
  parseWaveId,
} = require("../validation.js");
const {
  claimsJsonlPath,
} = require("../paths.js");
const {
  withSessionLock,
} = require("../storage.js");
const {
  validateNoSensitiveMaterial,
  redactTextSensitiveValues,
} = require("../sensitive-material.js");
const {
  validateAssignedWaveAgentSurface,
} = require("../assignments.js");
const {
  safeAppendPipelineEventDirect,
} = require("../pipeline-events.js");
const {
  safeGovernanceContextForDomain,
} = require("../governance-context.js");
const {
  computeFindingDedupeKey,
  normalizeFindingRecord,
} = require("../finding-contracts.js");
const {
  appendCandidateClaim,
  normalizeEvidenceReferenceShape,
  normalizeExploitOutcome,
  readCandidateClaims,
} = require("../claims.js");
const { appendFrontierEvent } = require("../frontier-events.js");
const { scheduleMaterialization } = require("../frontier-materialize-debounce.js");
const { hashCanonicalJson } = require("../verification-contracts.js");
const { isKnownCwe } = require("../cwe-catalog.js");
const { CVSS_INPUT_KEYS, CVSS_INPUT_ENUMS, deriveCvss31 } = require("../cvss31.js");

// Registry-driven schema for the optional structured CVSS v3.1 base inputs. The
// enum values are sourced from cvss31.js so the schema and the server-side
// normalizer cannot drift; only the keys the caller asserts are persisted, and
// the vector is derived server-side at report time (never stored on the
// hashed finding).
const CVSS_INPUTS_SCHEMA = Object.freeze({
  type: "object",
  additionalProperties: false,
  description:
    "Optional structured CVSS v3.1 base-metric inputs. The MCP derives the CVSS v3.1 vector and base score server-side at report time and renders them as an INFORMATIONAL annotation; the grade verdict severity stays authoritative. Supply these for reportable findings instead of hand-authoring a vector. Unknown keys or values are rejected. attack_vector and privileges_required plus at least one of confidentiality/integrity/availability are needed for a derivable vector; otherwise the report shows an explicit insufficient-verified-facts marker.",
  properties: CVSS_INPUT_KEYS.reduce((acc, key) => {
    acc[key] = { type: "string", enum: [...CVSS_INPUT_ENUMS[key]] };
    return acc;
  }, {}),
});

// Example catalog CWEs surfaced in the missing-CWE remediation, keyed by the
// finding class so the operator sees relevant ids. The validator is the source
// of truth; these are illustrative hints only.
const EXAMPLE_CWES_BY_CLASS = Object.freeze({
  smart_contract: "CWE-841 (reentrancy), CWE-284 (access-control bypass), CWE-682 (incorrect calculation), CWE-294 (signature replay)",
  web: "CWE-79 (XSS), CWE-639 (IDOR), CWE-352 (CSRF), CWE-918 (SSRF), CWE-200 (info exposure)",
});

// CandidateClaim recording. Every candidate claim lands in claims.jsonl with
// an embedded finding-shaped payload referenced via evidence_refs[kind="finding"].
// The finding_id identifier is preserved as the stable handle for verification
// and grade rounds; it is minted by scanning the existing claims ledger.

// Y.0 hotfix 1 (O2): field evidence showed bob_record_candidate_claim returning
// INTERNAL_ERROR ~71% of the time because field-observed payloads exceeded the
// per-field text caps and triggered the sensitive-material validator on benign
// matches (e.g. a victim_token surfaced inside a proof-of-concept narrative).
// The caps are raised here and a per-call secret_detection_bypass list lets the
// caller declare specific fields as benign with a recorded rationale; the live
// values below are the single source of truth — tests import this constant
// (no duplicated literals) so any future cap change is caught immediately.
const CLAIM_TEXT_LIMITS = Object.freeze({
  title: 300,
  cwe: 120,
  endpoint: 2000,
  description: 16000,
  proof_of_concept: 16000,
  response_evidence: 16000,
  impact: 8000,
  auth_profile: 200,
  reachability_assertion_call_path: 4000,
  reachability_assertion_justification: 2000,
});

const SECRET_DETECTION_BYPASS_FIELDS = Object.freeze(new Set([
  "description",
  "proof_of_concept",
  "response_evidence",
  "impact",
]));
const SECRET_DETECTION_BYPASS_RATIONALE_MAX = 512;
const SECRET_DETECTION_BYPASS_MAX_ENTRIES = SECRET_DETECTION_BYPASS_FIELDS.size;

function normalizeSecretDetectionBypass(raw) {
  if (raw == null) return new Map();
  const entries = Array.isArray(raw) ? raw : [raw];
  if (entries.length > SECRET_DETECTION_BYPASS_MAX_ENTRIES) {
    throw new Error(
      `secret_detection_bypass must contain at most ${SECRET_DETECTION_BYPASS_MAX_ENTRIES} entries`,
    );
  }
  const bypass = new Map();
  for (const entry of entries) {
    if (entry == null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error("secret_detection_bypass entries must be objects with {field, rationale}");
    }
    const field = assertNonEmptyString(entry.field, "secret_detection_bypass.field");
    if (!SECRET_DETECTION_BYPASS_FIELDS.has(field)) {
      throw new Error(
        `secret_detection_bypass.field must be one of: ${Array.from(SECRET_DETECTION_BYPASS_FIELDS).sort().join(", ")}`,
      );
    }
    const rationale = assertNonEmptyString(entry.rationale, "secret_detection_bypass.rationale");
    if (rationale.length > SECRET_DETECTION_BYPASS_RATIONALE_MAX) {
      throw new Error(
        `secret_detection_bypass.rationale must be at most ${SECRET_DETECTION_BYPASS_RATIONALE_MAX} chars`,
      );
    }
    // The rationale is audit free-text that explains WHY the secret-shaped
    // evidence is benign (e.g. "the reflected Authorization header is the CORS
    // proof"). It is persisted into claims.jsonl under
    // payload.secret_evidence_bypass and is NOT covered by the finding-field
    // value scan, so an evaluator could smuggle the raw secret VALUE into it.
    // Scrub any token-shaped material out of the rationale before it is stored
    // (the same free-text redactor Plane O JSONL writers use): a real
    // `Authorization: Bearer <token>` / JWT / key value is replaced with
    // REDACTED, while descriptive prose ("a bearer token surfaced in the
    // narrative") is left intact — so the bypass metadata can never become a
    // covert channel for secrets, without rejecting legitimate rationales.
    const safeRationale = redactTextSensitiveValues(rationale);
    if (bypass.has(field)) {
      throw new Error(`secret_detection_bypass.field ${field} listed twice`);
    }
    bypass.set(field, safeRationale);
  }
  return bypass;
}

function findingIdNumber(findingId) {
  const match = typeof findingId === "string" ? findingId.match(/^F-([1-9]\d*)$/) : null;
  return match ? Number(match[1]) : 0;
}

function findingEvidenceRefs(claim) {
  if (!claim || !Array.isArray(claim.evidence_refs)) return [];
  return claim.evidence_refs.filter((ref) => (
    ref && typeof ref === "object" && ref.kind === "finding" && typeof ref.finding_id === "string"
  ));
}

function scanExistingFindingFootprint(domain) {
  // The finding-id mint and dedupe-key match are both derived from the live
  // claims ledger now. A pre-D.2 session whose findings.jsonl already carried
  // F-N rows continues to influence the mint because the C.2 dual-write
  // mirrored every finding into a CandidateClaim with the same finding_id.
  let maxNumber = 0;
  let total = 0;
  const dedupeIndex = new Map();
  for (const claim of readCandidateClaims(domain)) {
    total += 1;
    for (const ref of findingEvidenceRefs(claim)) {
      const n = findingIdNumber(ref.finding_id);
      if (n > maxNumber) maxNumber = n;
    }
    const dedupeKey = claim && claim.payload && typeof claim.payload.dedupe_key === "string"
      ? claim.payload.dedupe_key
      : null;
    if (dedupeKey && !dedupeIndex.has(dedupeKey)) {
      const findingRefs = findingEvidenceRefs(claim);
      dedupeIndex.set(dedupeKey, {
        claim,
        finding_id: findingRefs.length > 0 ? findingRefs[0].finding_id : null,
      });
    }
  }
  return { maxNumber, total, dedupeIndex };
}

function validateClaimForPersistence(finding, secretBypass = new Map()) {
  for (const [field, maxTextChars] of Object.entries(CLAIM_TEXT_LIMITS)) {
    if (finding[field] == null) continue;
    if (secretBypass.has(field)) {
      // Caller asserted this field is a benign match (e.g. a victim token
      // surfaced inside a PoC narrative). Cap is still enforced; sensitive-
      // material structural detection is skipped for this field only.
      if (typeof finding[field] === "string" && finding[field].length > maxTextChars) {
        throw new Error(`${field} is too large; do not persist raw large response bodies`);
      }
      continue;
    }
    validateNoSensitiveMaterial(finding[field], field, { maxTextChars });
  }
  if (finding.reachability_assertion) {
    validateNoSensitiveMaterial(
      finding.reachability_assertion.call_path,
      "reachability_assertion.call_path",
      { maxTextChars: CLAIM_TEXT_LIMITS.reachability_assertion_call_path },
    );
    if (finding.reachability_assertion.justification != null) {
      validateNoSensitiveMaterial(
        finding.reachability_assertion.justification,
        "reachability_assertion.justification",
        { maxTextChars: CLAIM_TEXT_LIMITS.reachability_assertion_justification },
      );
    }
  }
}

function assertReportableCweOnWrite(args, surfaceType) {
  const severity = args && args.severity;
  if (severity !== "critical" && severity !== "high" && severity !== "medium") return;
  const cweEmpty = args.cwe == null || (typeof args.cwe === "string" && !args.cwe.trim());
  if (cweEmpty) {
    const examples = EXAMPLE_CWES_BY_CLASS[surfaceType] || EXAMPLE_CWES_BY_CLASS.web;
    throw new Error(
      `cwe is required for ${severity} findings and must be a catalog id from mcp/lib/cwe-catalog.js (examples: ${examples})`,
    );
  }
  if (!isKnownCwe(args.cwe)) {
    const examples = EXAMPLE_CWES_BY_CLASS[surfaceType] || EXAMPLE_CWES_BY_CLASS.web;
    throw new Error(
      `cwe ${JSON.stringify(args.cwe)} is not in the curated CWE catalog (mcp/lib/cwe-catalog.js); use a catalog id (examples: ${examples})`,
    );
  }
}

// Names the CVSS v3.1 base metrics still missing from a finding's cvss_inputs so
// the remediation tells the operator exactly what to supply. attack_complexity,
// user_interaction, and scope have spec defaults and are never listed; only
// attack_vector, privileges_required, and the impact triad gate derivability.
function missingCvssBaseMetrics(inputs) {
  const facts = inputs && typeof inputs === "object" && !Array.isArray(inputs) ? inputs : {};
  const missing = [];
  if (facts.attack_vector == null) missing.push("attack_vector");
  if (facts.privileges_required == null) missing.push("privileges_required");
  if (facts.confidentiality == null && facts.integrity == null && facts.availability == null) {
    missing.push("at least one of confidentiality/integrity/availability");
  }
  return missing;
}

// Reportable findings (critical/high/medium) must carry cvss_inputs sufficient
// for a DERIVABLE CVSS v3.1 vector, mirroring how the CWE gate requires a
// catalog id. This is evaluated on the BUILT/normalized finding so the OSS
// reachability attack_vector fallback (network/local -> AV) has already run; an
// OSS finding that asserts reachability + PR + impact but no explicit
// attack_vector still passes. The insufficient-verified-facts marker still
// renders for legacy read-back rows and low/info findings, which never reach
// this assert.
function assertReportableCvssInputsOnWrite(finding) {
  const severity = finding && finding.severity;
  if (severity !== "critical" && severity !== "high" && severity !== "medium") return;
  const derived = deriveCvss31(finding.cvss_inputs);
  // A derivable AND non-zero vector satisfies the gate. A "none"-banded vector
  // (base_score 0.0) is derivable but means all of confidentiality/integrity/
  // availability are "none" — it cannot back a medium+ severity claim, so it is
  // rejected below alongside the insufficient case.
  if (!derived.insufficient && derived.base_score > 0) return;
  // The reachability_assertion fallback exists ONLY for the oss_native_code pack
  // (assertReachabilityAssertionScope rejects it on web/SC), so only surface that
  // guidance for OSS findings — pointing a web evaluator at reachability_assertion
  // would direct them to a field their write will reject.
  const ossHint = finding && finding.capability_pack === "oss_native_code"
    ? " For routed oss_native_code findings, attack_vector is auto-derived from reachability_assertion (network -> AV:N, local -> AV:L), so supply reachability_assertion instead of attack_vector."
    : "";
  if (!derived.insufficient && derived.base_score === 0) {
    throw new Error(
      `cvss_inputs for ${severity} findings must describe real impact: confidentiality, integrity, and availability are all "none", which derives a CVSS v3.1 base score of 0.0 (band "none") and contradicts the claimed severity. Set at least one impact metric to low or high.`,
    );
  }
  const missing = missingCvssBaseMetrics(finding.cvss_inputs);
  const missingList = missing.length ? missing.join(", ") : "attack_vector, privileges_required, at least one of confidentiality/integrity/availability";
  throw new Error(
    `cvss_inputs is required for ${severity} findings and must be sufficient to derive a CVSS v3.1 base vector; supply the missing base metrics (${missingList}) as enums on cvss_inputs.${ossHint}`,
  );
}

function buildFindingPayloadRecord(args, context, findingId, { requireCwe = false } = {}) {
  return normalizeFindingRecord({
    id: findingId,
    target_domain: context.domain,
    title: args.title,
    severity: args.severity,
    cwe: args.cwe,
    endpoint: args.endpoint,
    // OSS-mode locator fields. The validators in finding-contracts.js cap
    // length and reject empty strings; recorders that omit them keep the
    // legacy web-shaped finding payload unchanged.
    file_path: args.file_path,
    symbol: args.symbol,
    manifest: args.manifest,
    affected_package: args.affected_package,
    affected_version_range: args.affected_version_range,
    repro_command: args.repro_command,
    description: args.description,
    proof_of_concept: args.proof_of_concept,
    response_evidence: args.response_evidence,
    impact: args.impact,
    validated: args.validated,
    wave: context.wave,
    agent: context.agent,
    surface_id: context.surfaceId,
    surface_type: context.surfaceType,
    capability_pack: context.capabilityPack,
    evaluator_agent: context.evaluatorAgent,
    brief_profile: context.briefProfile,
    sc_evidence: args.sc_evidence,
    reachability_assertion: args.reachability_assertion,
    cvss_inputs: args.cvss_inputs,
    dedupe_key: args.dedupe_key,
    auth_profile: args.auth_profile,
    force_record: args.force_record === true,
  }, { expectedDomain: context.domain, requireCwe });
}

function deriveSubjectId(finding) {
  if (finding && finding.sc_evidence && typeof finding.sc_evidence.contract_address === "string") {
    return finding.sc_evidence.contract_address;
  }
  if (finding && typeof finding.endpoint === "string" && finding.endpoint.trim()) {
    return finding.endpoint;
  }
  return null;
}

function deriveAttackClass(finding) {
  if (!finding) return null;
  if (typeof finding.attack_class === "string" && finding.attack_class.trim()) {
    return finding.attack_class;
  }
  if (typeof finding.cwe === "string" && finding.cwe.trim()) {
    return finding.cwe;
  }
  return null;
}

function severityForClaim(severity) {
  if (severity === "info") return "informational";
  return severity;
}

// Expands a single secret_detection_bypass field into the deep value-path(s)
// the claims-layer validator will see for that field. The embedded finding
// lives at payload.finding.<field>; the top-level summary is sourced from
// description, so a description-level bypass also covers the top-level summary;
// impact is mirrored to claim.impact. Shared by the write path (persist the
// rows + build the transient bypass Set) and reconstructed on read in claims.js
// from the persisted `path` field, so the two stay in lock-step.
function secretEvidenceBypassValuePaths(field) {
  const paths = [`payload.finding.${field}`];
  if (field === "description") paths.push("summary");
  if (field === "impact") paths.push("impact");
  return paths;
}

function buildSecretEvidenceBypassRows(secretBypass) {
  const rows = [];
  for (const [field, rationale] of secretBypass.entries()) {
    for (const path of secretEvidenceBypassValuePaths(field)) {
      rows.push({ field, rationale, path });
    }
  }
  return rows;
}

function normalizeExploitRunEvidenceRefs(rawRefs) {
  if (rawRefs == null) return [];
  if (!Array.isArray(rawRefs)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "evidence_refs must be an array when provided", { code: "evidence_refs_not_array" });
  }
  return rawRefs.map((ref, index) => {
    if (ref == null || typeof ref !== "object" || Array.isArray(ref)) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `evidence_refs[${index}] must be an object`, { code: "evidence_ref_not_object" });
    }
    if (ref.kind !== "exploit_run") {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `evidence_refs[${index}].kind must be exploit_run`, { code: "evidence_ref_kind_invalid" });
    }
    // normalizeEvidenceReferenceShape does the DEEP shape checks (e.g. absolute
    // target URL); it throws a bare Error, which would surface as INTERNAL_ERROR.
    // Rethrow as INVALID_ARGUMENTS so malformed caller input is a client fault.
    try {
      return normalizeEvidenceReferenceShape({ ...ref }, `evidence_refs[${index}]`);
    } catch (error) {
      if (error instanceof ToolError) throw error;
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message || `evidence_refs[${index}] is invalid`, { code: "evidence_ref_invalid_shape" });
    }
  });
}

function buildClaimPayloadFromFinding(finding, findingContentHash, args, secretBypass = new Map()) {
  const payload = {};
  const subjectId = deriveSubjectId(finding);
  if (subjectId) payload.subject_id = subjectId;
  const attackClass = deriveAttackClass(finding);
  if (attackClass) payload.attack_class = attackClass;
  if (typeof finding.auth_profile === "string" && finding.auth_profile.trim()) {
    payload.auth_profile_ref = finding.auth_profile;
  }
  if (typeof finding.surface_id === "string" && finding.surface_id.trim()) {
    payload.surface_ref = finding.surface_id;
  }
  // Preserve the legacy dedupe key on the claim payload so subsequent
  // record-candidate-claim calls can detect duplicates without re-scanning a
  // separate findings ledger.
  if (typeof finding.dedupe_key === "string" && finding.dedupe_key) {
    payload.dedupe_key = finding.dedupe_key;
  }
  // Carry the inline finding-shaped payload so consumers that still address
  // findings by their familiar fields (title, severity, endpoint, description,
  // proof_of_concept, sc_evidence, wave/agent, capability routing) can read
  // them directly off the claim without resolving a separate artifact. This is
  // the post-D.2 replacement for the old findings.jsonl row.
  const findingPayload = {};
  for (const key of [
    "id",
    "target_domain",
    "title",
    "severity",
    "cwe",
    "endpoint",
    "file_path",
    "symbol",
    "manifest",
    "affected_package",
    "affected_version_range",
    "repro_command",
    "description",
    "proof_of_concept",
    "response_evidence",
    "impact",
    "validated",
    "wave",
    "agent",
    "surface_id",
    "surface_type",
    "capability_pack",
    "evaluator_agent",
    "brief_profile",
    "sc_evidence",
    "reachability_assertion",
    "cvss_inputs",
    "auth_profile",
    "dedupe_key",
    "force_record",
  ]) {
    if (finding[key] != null) findingPayload[key] = finding[key];
  }
  payload.finding = findingPayload;

  // Persist the operator-approved secret-evidence bypass onto the claim so the
  // read-time re-scan (readCandidateClaims -> normalizeCandidateClaim) can
  // re-honor exactly the paths approved at write. Each row carries the field,
  // the auditable rationale (already required at write), and the resolved deep
  // value-path. Without this, the value-scan re-fires on the persisted PoC and
  // throws on every read of a legitimately secret-shaped finding (the stuck-
  // session jam). Structural SENSITIVE_KEY_RE and the maxTextChars cap still
  // fire everywhere; only these listed value-paths skip the regex value scan.
  const secretBypassRows = buildSecretEvidenceBypassRows(secretBypass);
  if (secretBypassRows.length > 0) {
    payload.secret_evidence_bypass = secretBypassRows;
  }

  const evidenceRefs = [{
    kind: "finding",
    finding_id: finding.id,
    content_hash: findingContentHash,
  }];
  evidenceRefs.push(...normalizeExploitRunEvidenceRefs(args.evidence_refs));

  const claim = {
    target_domain: finding.target_domain,
    title: finding.title,
    summary: typeof finding.description === "string" && finding.description.trim()
      ? finding.description
      : finding.title,
    severity: severityForClaim(finding.severity),
    status: "candidate",
    created_at: typeof args.created_at === "string" && args.created_at.trim()
      ? args.created_at
      : new Date().toISOString(),
    evidence_refs: evidenceRefs,
  };
  // normalizeExploitOutcome throws a bare Error (e.g. exploited_safely without
  // safe_oracle); rethrow as INVALID_ARGUMENTS so it is not surfaced as a fault.
  let exploitOutcome;
  try {
    exploitOutcome = normalizeExploitOutcome(args.exploit_outcome);
  } catch (error) {
    if (error instanceof ToolError) throw error;
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message || "exploit_outcome is invalid", { code: "exploit_outcome_invalid" });
  }
  if (exploitOutcome) claim.exploit_outcome = exploitOutcome;
  if (typeof finding.surface_id === "string" && finding.surface_id.trim()) {
    claim.surface_ids = [finding.surface_id];
  }
  if (typeof finding.impact === "string" && finding.impact.trim()) {
    claim.impact = finding.impact;
  }
  claim.payload = payload;
  return claim;
}

function recordCandidateClaimHandler(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const hasWave = args.wave != null;
  const hasAgent = args.agent != null;
  if (hasWave !== hasAgent) {
    throw new Error("wave and agent must either both be provided or both be omitted");
  }

  let wave = null;
  let agent = null;
  let surfaceId = null;
  let surfaceType = null;
  let capabilityPack = null;
  let evaluatorAgent = null;
  let briefProfile = null;
  if (hasWave) {
    wave = parseWaveId(args.wave);
    agent = parseAgentId(args.agent);
    surfaceId = assertNonEmptyString(args.surface_id, "surface_id");
    const assignment = validateAssignedWaveAgentSurface(domain, wave, agent, surfaceId);
    const rawSurfaceType = assignment && assignment.surface_type ? assignment.surface_type : null;
    surfaceType = rawSurfaceType === "smart_contract" ? "smart_contract" : "web";
    capabilityPack = assignment.capability_pack || null;
    evaluatorAgent = assignment.evaluator_agent || null;
    briefProfile = assignment.brief_profile || null;
  } else {
    surfaceId = args.surface_id == null ? null : assertNonEmptyString(args.surface_id, "surface_id");
    if (args.sc_evidence != null) {
      throw new Error("sc_evidence findings must be recorded with wave and agent so the routed capability pack is captured from the assignment");
    }
    surfaceType = "web";
    capabilityPack = "web";
    evaluatorAgent = "evaluator-agent";
    briefProfile = "web";
  }

  return withSessionLock(domain, () => {
    const context = {
      domain,
      wave,
      agent,
      surfaceId,
      surfaceType,
      capabilityPack,
      evaluatorAgent,
      briefProfile,
    };
    const secretBypass = normalizeSecretDetectionBypass(args.secret_detection_bypass);
    const preliminary = buildFindingPayloadRecord(args, context, "F-1");
    validateClaimForPersistence(preliminary, secretBypass);

    const scan = scanExistingFindingFootprint(domain);
    const existing = scan.dedupeIndex.get(preliminary.dedupe_key) || null;
    if (existing && args.force_record !== true) {
      return JSON.stringify({
        recorded: false,
        duplicate: true,
        finding_id: existing.finding_id,
        existing_finding_id: existing.finding_id,
        dedupe_key: preliminary.dedupe_key,
        total: scan.total,
        written_jsonl: claimsJsonlPath(domain),
        claim_id: existing.claim ? existing.claim.claim_id : null,
      });
    }

    const counter = scan.maxNumber + 1;
    assertReportableCweOnWrite(args, surfaceType);
    const finding = buildFindingPayloadRecord(args, context, `F-${counter}`, { requireCwe: true });
    assertReportableCvssInputsOnWrite(finding);
    validateClaimForPersistence(finding, secretBypass);

    const findingContentHash = hashCanonicalJson(finding);
    const claimInput = buildClaimPayloadFromFinding(finding, findingContentHash, args || {}, secretBypass);
    // Y.0 hotfix 1 (O2): expand the per-field bypass into the exact deep paths
    // the claims-layer validator will see, via the same helper that builds the
    // persisted secret_evidence_bypass rows so write-time and read-time honor
    // identical paths. The embedded finding lives at payload.finding.<field>;
    // the top-level summary is sourced from description; impact is mirrored to
    // claim.impact.
    const payloadBypassValuePaths = new Set();
    for (const field of secretBypass.keys()) {
      for (const path of secretEvidenceBypassValuePaths(field)) {
        payloadBypassValuePaths.add(path);
      }
    }
    const claim = appendCandidateClaim(claimInput, {
      payloadBypassValuePaths: payloadBypassValuePaths.size > 0 ? payloadBypassValuePaths : null,
    });

    appendFrontierEvent({
      target_domain: domain,
      kind: "claim.candidate.linked",
      payload: {
        claim_id: claim.claim_id,
        finding_id: finding.id,
        surface_id: finding.surface_id || null,
      },
      surface_id: finding.surface_id || null,
      claim_id: claim.claim_id,
      source: { artifact: "claims.jsonl", tool: "bob_record_candidate_claim" },
    });
    scheduleMaterialization(domain);

    const response = {
      recorded: true,
      finding_id: finding.id,
      claim_id: claim.claim_id,
      total: scan.total + 1,
      finding_sequence: counter,
      dedupe_key: finding.dedupe_key,
      written_jsonl: claimsJsonlPath(domain),
    };
    if (finding.force_record) {
      response.force_record = true;
    }

    const governanceContext = safeGovernanceContextForDomain(domain);
    safeAppendPipelineEventDirect(domain, "finding_recorded", {
      wave,
      agent,
      surface_id: surfaceId,
      status: finding.severity,
      source: "bob_record_candidate_claim",
      counts: {
        findings: scan.total + 1,
        validated: finding.validated ? 1 : 0,
      },
    }, governanceContext);

    return JSON.stringify(response);
  });
}

function findingPayloadsFromClaims(domain) {
  return readCandidateClaims(domain)
    .map((claim) => {
      const payload = claim && claim.payload && typeof claim.payload === "object" ? claim.payload : {};
      const finding = payload.finding && typeof payload.finding === "object" ? payload.finding : null;
      if (!finding) return null;
      try {
        return normalizeFindingRecord({ ...finding, target_domain: claim.target_domain }, {
          expectedDomain: domain,
        });
      } catch {
        return null;
      }
    })
    .filter((entry) => entry != null);
}

module.exports = Object.freeze({
  name: "bob_record_candidate_claim",
  aliases: ["bob_record_finding", "bounty_record_finding"],
  description:
    "Record a validated candidate claim to claims.jsonl with an embedded finding-shaped payload, plus a claim.candidate.linked frontier event. Survives context rotation.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "title": {
        "type": "string"
      },
      "severity": {
        "type": "string",
        "enum": [
          "critical",
          "high",
          "medium",
          "low",
          "info"
        ]
      },
      "cwe": {
        "type": "string"
      },
      "endpoint": {
        "type": "string"
      },
      "file_path": {
        "type": "string",
        "description": "OSS mode: repo-relative primary file path for the finding."
      },
      "symbol": {
        "type": "string",
        "description": "OSS mode: affected function, class, route, workflow, or config key."
      },
      "manifest": {
        "type": "string",
        "description": "OSS mode: affected manifest or lockfile."
      },
      "affected_package": {
        "type": "string",
        "description": "OSS mode: affected package/dependency name."
      },
      "affected_version_range": {
        "type": "string",
        "description": "OSS mode: affected package version range."
      },
      "repro_command": {
        "type": "string",
        "description": "OSS mode: bounded local command that reproduces or verifies the issue when known. High/critical native-code claims must additionally cite the run as an evidence_refs[] entry of kind \"repo_command_run\" backed by a non-dry-run row in repo-command-runs.jsonl."
      },
      "description": {
        "type": "string"
      },
      "proof_of_concept": {
        "type": "string"
      },
      "response_evidence": {
        "type": "string"
      },
      "impact": {
        "type": "string"
      },
      "auth_profile": {
        "type": "string"
      },
      "exploit_outcome": {
        "type": "object",
        "description": "Optional safe exploit outcome. outcome=\"exploited_safely\" requires safe_oracle.kind and at least one evidence_refs[] item with kind=\"exploit_run\" backed by a MAC-signed offensive-runs.jsonl row.",
        "properties": {
          "outcome": {
            "type": "string",
            "enum": ["exploited_safely", "blocked_by_defense", "blocked_by_infra"]
          },
          "safe_oracle": {
            "type": "object",
            "properties": {
              "kind": {
                "type": "string",
                "enum": [
                  "out_of_band_interaction",
                  "reflected_canary",
                  "differential_response",
                  "benign_state_change",
                  "blind_boolean_timing",
                  "benign_command_marker"
                ]
              }
            },
            "required": ["kind"],
            "additionalProperties": false
          }
        },
        "required": ["outcome"],
        "additionalProperties": false
      },
      "evidence_refs": {
        "type": "array",
        "description": "Optional exploit proof references. bob_record_candidate_claim only accepts kind=\"exploit_run\" here; it always adds the finding ref itself.",
        "items": {
          "type": "object",
          "properties": {
            "kind": { "type": "string", "enum": ["exploit_run"] },
            "run_id": { "type": "string" },
            "tool_id": { "type": "string" },
            "target": { "type": "string" },
            "offensive_outcome": { "type": "string", "enum": ["exploited_safely", "blocked_by_defense", "blocked_by_infra"] },
            "command_hash": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
            "exit_code": { "type": ["integer", "null"] },
            "stdout_hash": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
            "stderr_hash": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
            "source_run_id": { "type": "string" }
          },
          "required": ["kind", "run_id", "tool_id", "target", "offensive_outcome", "command_hash", "exit_code", "stdout_hash", "stderr_hash"],
          "additionalProperties": false
        }
      },
      "surface_id": {
        "type": "string"
      },
      "validated": {
        "type": "boolean"
      },
      "wave": {
        "type": "string",
        "pattern": "^w[1-9][0-9]*$"
      },
      "agent": {
        "type": "string",
        "pattern": "^a[1-9][0-9]*$"
      },
      "force_record": {
        "type": "boolean",
        "description": "Intentionally record a duplicate candidate claim instead of returning the existing finding ID."
      },
      "secret_detection_bypass": {
        "type": "array",
        "maxItems": 4,
        "description": "Y.0 hotfix 1 (O2): list of {field, rationale} entries declaring that a specific finding text field carries a benign match the sensitive-material validator should skip (e.g. a victim_token surfaced inline in a PoC narrative). Length cap on the field is still enforced; the rationale is required for audit. Allowed fields: description, proof_of_concept, response_evidence, impact.",
        "items": {
          "type": "object",
          "properties": {
            "field": {
              "type": "string",
              "enum": ["description", "proof_of_concept", "response_evidence", "impact"]
            },
            "rationale": {
              "type": "string",
              "minLength": 1,
              "maxLength": 512
            }
          },
          "required": ["field", "rationale"],
          "additionalProperties": false
        }
      },
      "reachability_assertion": {
        "type": "object",
        "description": "Optional evaluator-asserted finding reachability. Only allowed for routed oss_native_code findings. Cite the entrypoint-to-sink path the evaluator verified; this evaluator-authored assertion is trusted grading provenance at grade time and overrides the repo-inventory attack-vector/network-reachability classification. An existing inventory/heuristic severity ceiling still constrains the asserted class ceiling, while assertion-only grading derives the ceiling from the asserted class and records an audit note. It is not independently verifier-reviewed and does not self-certify reachability defensibility. Frozen conflict policy is first distinct attack_vector/network_reachable assertion wins by claim time; same-classification call_path refinements are not conflicts and update the rendered call path; corrections to attack_vector/network_reachable require operator amendment/re-freeze rather than another conflicting claim.",
        "properties": {
          "attack_vector": {
            "type": "string",
            "enum": ["network", "local"],
            "description": "Evaluator-classified attack vector for the finding-level call path."
          },
          "network_reachable": {
            "type": "boolean",
            "description": "True only when the cited call path is reachable from network-controlled input."
          },
          "call_path": {
            "type": "string",
            "minLength": 7,
            "maxLength": 4000,
            "pattern": "^(?!.*[\\n\\r])(?!\\s*->)(?!.*->\\s*(?:->|$))[^\\n\\r]*->[^\\n\\r]*->[^\\n\\r]*$",
            "description": "Cited entrypoint-to-sink path with at least two hops, for example: UDP-161 SNMP SET -> write_vacmAccessStatus -> access_parse_oid."
          },
          "justification": {
            "type": "string",
            "maxLength": 2000,
            "description": "Short rationale for why this path is network or local reachable."
          }
        },
        "required": ["attack_vector", "network_reachable", "call_path"],
        "additionalProperties": false
      },
      "cvss_inputs": CVSS_INPUTS_SCHEMA,
      "sc_evidence": {
        "type": "object",
        "description": "Structured re-run handle for smart-contract candidate claims. Required when the assigned surface is a smart contract; rejected otherwise so the verifier can re-run via bob_foundry_run (EVM) or bob_anchor_run (SVM) with no string-parsing of the prose PoC.",
        "properties": {
          "chain_family": {
            "type": "string",
            "enum": ["evm", "svm", "aptos", "sui", "substrate", "cosmwasm"],
            "description": "Discriminator for cross-family validation. Defaults to 'evm' when omitted for back-compat with legacy candidate claims."
          },
          "chain_id": {
            "oneOf": [
              { "type": "integer", "minimum": 1, "maximum": 9007199254740991 },
              { "type": "string", "minLength": 1, "maxLength": 64 }
            ],
            "description": "EVM: positive integer chain ID (e.g., 1, 137). SVM: cluster string from {mainnet-beta, devnet, testnet}. Aptos: network string from {mainnet, testnet, devnet}. Sui: network string from {mainnet, testnet, devnet, localnet}. Substrate: network string from {polkadot, kusama, astar, shiden, rococo, westend, localnet}. CosmWasm: network string from {osmosis, juno, neutron, archway, sei, stargaze, terra, kava, localnet}."
          },
          "contract_address": {
            "type": "string",
            "minLength": 1,
            "maxLength": 90,
            "description": "EVM: 0x-prefixed 40-hex address. SVM: base58 32-44 char Solana program ID. Aptos: 0x-prefixed hex module address (1-64 hex chars, normalized to 64). Sui: 0x-prefixed hex package ID (1-64 hex chars, normalized to 64). Substrate: SS58-encoded base58 address (45-52 chars). CosmWasm: bech32 with chain HRP (e.g., osmo1..., juno1...). Validated against chain_family."
          },
          "harness_path": {
            "type": "string",
            "description": "Foundry/Anchor project root for the recorded test. Must live under the user's home directory at re-run time."
          },
          "match_test": {
            "type": "string",
            "minLength": 1,
            "maxLength": 200,
            "description": "Test function selector passed to forge --match-test (EVM) or anchor's mocha grep (SVM). Convention: a passing test asserts the bug exists, so PASS=reproduced."
          },
          "match_contract": {
            "type": "string",
            "minLength": 1,
            "maxLength": 200,
            "description": "Optional contract / program selector. EVM uses --match-contract; SVM ignores this and uses the anchor program directory layout."
          },
          "fork_block": {
            "type": "integer",
            "minimum": 0,
            "maximum": 9007199254740991,
            "description": "Pinned chain reference at recording time. EVM: block number. SVM: slot. Aptos: ledger version. Sui: checkpoint sequence number. Substrate: block number. CosmWasm: block height. Verifiers re-run WITHOUT pinning to confirm the bug still reproduces on current state."
          },
          "function_signature": {
            "type": "string",
            "minLength": 1,
            "maxLength": 200,
            "description": "Affected function / instruction signature (e.g., borrow(uint256), Deposit{amount: u64}). Optional; surfaces in the report header."
          }
        },
        "required": ["chain_id", "contract_address", "harness_path", "match_test"]
      }
    },
    "required": [
      "target_domain",
      "title",
      "severity",
      "endpoint",
      "description",
      "proof_of_concept",
      "validated"
    ]
  },
  handler: recordCandidateClaimHandler,
  role_bundles: ["evaluator-shared", "orchestrator"],
  mutating: true,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["claims.jsonl","frontier-events.jsonl"],
  findingPayloadsFromClaims,
  computeFindingDedupeKey,
  CLAIM_TEXT_LIMITS,
  SECRET_DETECTION_BYPASS_FIELDS,
});
