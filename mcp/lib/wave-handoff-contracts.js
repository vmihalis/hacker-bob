"use strict";

const crypto = require("crypto");
const {
  assertNonEmptyString,
  compareAgentLabels,
  normalizeStringArray,
  parseAgentId,
  parseSurfaceStatus,
  parseWaveId,
} = require("./validation.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  validateNoSensitiveMaterial,
} = require("./sensitive-material.js");
const {
  canonicalJson,
  hashCanonicalJson,
} = require("./verification-contracts.js");

const WAVE_HANDOFF_CONTENT_MAX_CHARS = 120000;
const HANDOFF_PROVENANCE_MODEL = "session_file_hmac_v1";
const HANDOFF_PROVENANCE_SIGNATURE_VERSION = 1;
const HANDOFF_PROVENANCE_SIGNATURE_ALGORITHM = "hmac-sha256";
const HANDOFF_PROVENANCE_SIGNATURE_CONTEXT = "hacker-bob:wave-handoff:session-file-hmac:v1";

function sha256Hex(value) {
  return crypto.createHash("sha256").update(String(value), "utf8").digest("hex");
}

function generateHandoffToken() {
  return crypto.randomBytes(24).toString("base64url");
}

function assignmentRequiresToken(assignment) {
  return !!(assignment && (assignment.handoff_token_required === true || assignment.handoff_token_sha256));
}

function validateHandoffToken(assignment, token) {
  // Tokenized assignments store only `handoff_token_sha256` on disk. The raw
  // token is handed to the assigned agent and checked only at write time.
  // Assignments without token metadata are rejected — the v1.3.5 legacy
  // downgrade path was removed in v1.3.6 so the assignment-file-downgrade
  // attack documented in R1-HIGH-#1 cannot be reached.
  if (!assignmentRequiresToken(assignment)) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      "wave assignment is missing handoff token metadata; signed handoffs are required. The assignment file may have been tampered, or this is a pre-v1.3.5 session that needs re-init.",
    );
  }
  if (typeof assignment.handoff_token_sha256 !== "string" || !assignment.handoff_token_sha256.trim()) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "wave assignment requires a handoff token but is missing handoff_token_sha256");
  }
  if (typeof token !== "string" || !token.trim()) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff_token is required for this wave assignment");
  }
  if (sha256Hex(token.trim()) !== assignment.handoff_token_sha256) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff_token does not match this wave assignment");
  }
  return "verified";
}

function handoffSignaturePayload(payload) {
  const copy = { ...payload };
  delete copy.provenance_signature;
  return canonicalJson(copy);
}

function computeHandoffProvenanceDigest(payload, signingKey) {
  if (!Buffer.isBuffer(signingKey) || signingKey.length === 0) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "handoff signing key is required for verified provenance");
  }
  return crypto
    .createHmac("sha256", signingKey)
    .update(HANDOFF_PROVENANCE_SIGNATURE_CONTEXT)
    .update("\n")
    .update(handoffSignaturePayload(payload))
    .digest("hex");
}

function handoffAssignmentProvenancePayload(assignment) {
  if (!assignment || typeof assignment !== "object" || Array.isArray(assignment)) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "wave assignment is required for handoff provenance");
  }
  return {
    agent: assignment.agent || null,
    surface_id: assignment.surface_id || null,
    surface_type: assignment.surface_type || null,
    capability_pack: assignment.capability_pack || null,
    capability_pack_version: assignment.capability_pack_version || null,
    evaluator_agent: assignment.evaluator_agent || null,
    brief_profile: assignment.brief_profile || null,
    context_budget: assignment.context_budget || null,
    task_lens: assignment.task_lens || null,
    budget: assignment.budget || null,
    handoff_token_required: assignmentRequiresToken(assignment),
    handoff_token_sha256: assignment.handoff_token_sha256 || null,
  };
}

function computeHandoffAssignmentHash(assignment) {
  if (assignmentRequiresToken(assignment) && !assignment.handoff_token_sha256) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "wave assignment requires a handoff token but is missing handoff_token_sha256");
  }
  return hashCanonicalJson(handoffAssignmentProvenancePayload(assignment));
}

function normalizeHandoffProvenanceSignature(signature) {
  if (signature == null || typeof signature !== "object" || Array.isArray(signature)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff provenance signature is required for this tokenized assignment");
  }
  if (signature.version !== HANDOFF_PROVENANCE_SIGNATURE_VERSION) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff provenance signature version is unsupported");
  }
  if (signature.algorithm !== HANDOFF_PROVENANCE_SIGNATURE_ALGORITHM) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff provenance signature algorithm is unsupported");
  }
  if (typeof signature.digest !== "string" || !/^[0-9a-f]{64}$/.test(signature.digest)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff provenance signature digest is malformed");
  }
  return signature.digest;
}

function signHandoffProvenance(payload, signingKey, { assignment } = {}) {
  if (payload.provenance_model != null || payload.provenance_signature != null || payload.provenance_assignment_hash != null) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff provenance fields must be assigned by the signer");
  }
  const signedPayload = {
    ...payload,
    provenance_model: HANDOFF_PROVENANCE_MODEL,
    provenance_assignment_hash: computeHandoffAssignmentHash(assignment),
  };
  return {
    ...signedPayload,
    provenance_signature: {
      version: HANDOFF_PROVENANCE_SIGNATURE_VERSION,
      algorithm: HANDOFF_PROVENANCE_SIGNATURE_ALGORITHM,
      digest: computeHandoffProvenanceDigest(signedPayload, signingKey),
    },
  };
}

function verifyHandoffProvenanceSignature(payload, signingKey, { assignment } = {}) {
  if (payload.provenance_model !== HANDOFF_PROVENANCE_MODEL) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff provenance model is missing or unsupported");
  }
  const expectedAssignmentHash = computeHandoffAssignmentHash(assignment);
  if (payload.provenance_assignment_hash !== expectedAssignmentHash) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff provenance assignment hash does not match the current wave assignment");
  }
  const actualDigest = normalizeHandoffProvenanceSignature(payload.provenance_signature);
  const expectedDigest = computeHandoffProvenanceDigest(payload, signingKey);
  const actual = Buffer.from(actualDigest, "hex");
  const expected = Buffer.from(expectedDigest, "hex");
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff provenance signature does not match the handoff payload");
  }
}

function validateHandoffProvenance(payload, assignment, { signingKey = null } = {}) {
  // Tokenized handoffs are signed with a session-local MCP key after the raw
  // token is checked at write time. This verifies the persisted artifact
  // without storing raw tokens. It does not defend against a local actor with
  // direct read access to Bob's private session key.
  //
  // The v1.3.5 legacy downgrade path was removed in v1.3.6 — assignments
  // without token metadata are rejected outright, closing the assignment-
  // file-downgrade attack documented in R1-HIGH-#1.
  if (!assignmentRequiresToken(assignment)) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      "handoff provenance is required but the assignment lacks token metadata; the assignment file may have been tampered, or this is a pre-v1.3.5 handoff that needs re-init.",
    );
  }
  if (payload.provenance !== "verified") {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff provenance is not verified for this tokenized assignment");
  }
  verifyHandoffProvenanceSignature(payload, signingKey, { assignment });
  normalizeHandoffSummary(payload, { requireStructuredSummary: true });
  return "verified";
}

function normalizeHandoffSummary(payload, { requireStructuredSummary = false } = {}) {
  if (payload.summary == null && !requireStructuredSummary) {
    return null;
  }
  const summary = assertNonEmptyString(payload.summary, "summary");
  if (summary.length > 2000) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "summary must be at most 2000 characters");
  }
  return summary;
}

function normalizeChainNotes(value) {
  const notes = normalizeStringArray(value, "chain_notes");
  if (notes.length > 20) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "chain_notes must contain at most 20 entries");
  }
  for (const note of notes) {
    if (note.length > 300) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "chain_notes entries must be at most 300 characters");
    }
  }
  return notes;
}

// Runtime mirror of the bob_write_wave_handoff JSON schema enum and the
// renderer's BLOCKED_HARNESS_RUN_KINDS constant. Mismatch here would cause
// SVM/Move/Substrate/CosmWasm evaluators to fail finalization even though the
// schema accepted their handoff. test/prompt-contracts.test.js enforces the
// schema, renderer, and runtime invariant.
const BLOCKED_HARNESS_KIND_VALUES = Object.freeze([
  "foundry_fork",
  "anchor_fork",
  "aptos_fork",
  "sui_fork",
  "substrate_fork",
  "cosmwasm_fork",
  "rpc_endpoint",
  "fuzzer",
  "symbolic_solver",
  "mock_dependency",
  "external_api",
  "docker_unavailable",
  "sanitizer_unavailable",
  "static_analyzer_unavailable",
  "cve_feed_stale",
  "other",
]);

// Mirror of capability-packs-rendering.js BLOCKED_PREREQ_KINDS and the
// bob_write_wave_handoff schema enum for blocked_prereqs[].kind. Like
// BLOCKED_HARNESS_KIND_VALUES this is a runtime guard that throws on unknown
// kinds before the JSON schema would even check; mismatch with the renderer
// constant or schema enum is caught by the parity test in
// test/prompt-contracts.test.js.
const BLOCKED_PREREQ_KIND_VALUES = Object.freeze([
  "auth_missing",
  "egress_unreachable",
  "funded_wallet_missing",
  "key_material_missing",
  "external_credential_missing",
]);

const BLOCKED_PREREQ_IDENTIFIER_HINT_PATTERN = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
const BLOCKED_PREREQ_IDENTIFIER_HINT_LONG_HEX_PATTERN = /^[0-9a-f]{32,}$/;

const BYPASS_ATTEMPT_OUTCOME_VALUES = Object.freeze([
  "no_finding",
  "partial_evidence",
  "finding_recorded",
  "blocked",
]);

function normalizeBlockedHarnessRuns(value) {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "blocked_harness_runs must be an array");
  }
  if (value.length > 20) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "blocked_harness_runs must contain at most 20 entries");
  }
  return value.map((entry, index) => {
    if (entry == null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `blocked_harness_runs[${index}] must be an object`);
    }
    const kind = assertNonEmptyString(entry.kind, `blocked_harness_runs[${index}].kind`);
    if (!BLOCKED_HARNESS_KIND_VALUES.includes(kind)) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `blocked_harness_runs[${index}].kind must be one of ${BLOCKED_HARNESS_KIND_VALUES.join(", ")}`);
    }
    const harness = assertNonEmptyString(entry.harness, `blocked_harness_runs[${index}].harness`);
    const reason = assertNonEmptyString(entry.reason, `blocked_harness_runs[${index}].reason`);
    if (harness.length > 120) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `blocked_harness_runs[${index}].harness must be at most 120 characters`);
    }
    if (reason.length > 240) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `blocked_harness_runs[${index}].reason must be at most 240 characters`);
    }
    const normalized = { kind, harness, reason };
    if (entry.needed_for != null) {
      const neededFor = assertNonEmptyString(entry.needed_for, `blocked_harness_runs[${index}].needed_for`);
      if (neededFor.length > 200) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `blocked_harness_runs[${index}].needed_for must be at most 200 characters`);
      }
      normalized.needed_for = neededFor;
    }
    return normalized;
  });
}

function normalizeBlockedPrereqs(value) {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "blocked_prereqs must be an array");
  }
  if (value.length > 20) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "blocked_prereqs must contain at most 20 entries");
  }
  return value.map((entry, index) => {
    if (entry == null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `blocked_prereqs[${index}] must be an object`);
    }
    const kind = assertNonEmptyString(entry.kind, `blocked_prereqs[${index}].kind`);
    if (!BLOCKED_PREREQ_KIND_VALUES.includes(kind)) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `blocked_prereqs[${index}].kind must be one of ${BLOCKED_PREREQ_KIND_VALUES.join(", ")}`);
    }
    const reason = assertNonEmptyString(entry.reason, `blocked_prereqs[${index}].reason`);
    if (reason.length > 240) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `blocked_prereqs[${index}].reason must be at most 240 characters`);
    }
    try {
      validateNoSensitiveMaterial(reason, `blocked_prereqs[${index}].reason`);
    } catch (error) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message);
    }
    const normalized = { kind, reason };
    if (entry.identifier_hint != null) {
      const identifierHint = assertNonEmptyString(entry.identifier_hint, `blocked_prereqs[${index}].identifier_hint`);
      if (identifierHint.length > 64) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `blocked_prereqs[${index}].identifier_hint must be at most 64 characters`);
      }
      if (!BLOCKED_PREREQ_IDENTIFIER_HINT_PATTERN.test(identifierHint)) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `blocked_prereqs[${index}].identifier_hint must match /^[a-z0-9][a-z0-9_.-]{0,63}$/ - use a lowercase registry handle, not a credential or token value`);
      }
      if (BLOCKED_PREREQ_IDENTIFIER_HINT_LONG_HEX_PATTERN.test(identifierHint)) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `blocked_prereqs[${index}].identifier_hint looks like a hex private key, address, or hash; use a human-readable registry handle instead`);
      }
      try {
        validateNoSensitiveMaterial(identifierHint, `blocked_prereqs[${index}].identifier_hint`);
      } catch (error) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message);
      }
      normalized.identifier_hint = identifierHint;
    }
    if (entry.evidence_summary != null) {
      const evidenceSummary = assertNonEmptyString(entry.evidence_summary, `blocked_prereqs[${index}].evidence_summary`);
      if (evidenceSummary.length > 300) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `blocked_prereqs[${index}].evidence_summary must be at most 300 characters`);
      }
      try {
        validateNoSensitiveMaterial(evidenceSummary, `blocked_prereqs[${index}].evidence_summary`);
      } catch (error) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message);
      }
      normalized.evidence_summary = evidenceSummary;
    }
    if (entry.needed_for != null) {
      const neededFor = assertNonEmptyString(entry.needed_for, `blocked_prereqs[${index}].needed_for`);
      if (neededFor.length > 200) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `blocked_prereqs[${index}].needed_for must be at most 200 characters`);
      }
      try {
        validateNoSensitiveMaterial(neededFor, `blocked_prereqs[${index}].needed_for`);
      } catch (error) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message);
      }
      normalized.needed_for = neededFor;
    }
    return normalized;
  });
}

const BYPASS_ATTEMPT_CONDITION_MIN_CHARS = 4;
const BYPASS_ATTEMPT_SUMMARY_MIN_CHARS = 30;

function normalizeBypassAttempts(value, { findingIds = null } = {}) {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "bypass_attempts must be an array");
  }
  if (value.length > 30) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "bypass_attempts must contain at most 30 entries");
  }
  return value.map((entry, index) => {
    if (entry == null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `bypass_attempts[${index}] must be an object`);
    }
    const condition = assertNonEmptyString(entry.condition, `bypass_attempts[${index}].condition`);
    if (condition.length < BYPASS_ATTEMPT_CONDITION_MIN_CHARS) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `bypass_attempts[${index}].condition must be at least ${BYPASS_ATTEMPT_CONDITION_MIN_CHARS} characters`);
    }
    if (condition.length > 120) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `bypass_attempts[${index}].condition must be at most 120 characters`);
    }
    const attemptSummary = assertNonEmptyString(entry.attempt_summary, `bypass_attempts[${index}].attempt_summary`);
    if (attemptSummary.length < BYPASS_ATTEMPT_SUMMARY_MIN_CHARS) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `bypass_attempts[${index}].attempt_summary must be at least ${BYPASS_ATTEMPT_SUMMARY_MIN_CHARS} characters; describe the concrete state machine or payload you exercised`);
    }
    if (attemptSummary.length > 500) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `bypass_attempts[${index}].attempt_summary must be at most 500 characters`);
    }
    const outcome = assertNonEmptyString(entry.outcome, `bypass_attempts[${index}].outcome`);
    if (!BYPASS_ATTEMPT_OUTCOME_VALUES.includes(outcome)) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `bypass_attempts[${index}].outcome must be one of ${BYPASS_ATTEMPT_OUTCOME_VALUES.join(", ")}`);
    }
    const normalized = { condition, attempt_summary: attemptSummary, outcome };
    if (entry.finding_id != null) {
      const findingId = assertNonEmptyString(entry.finding_id, `bypass_attempts[${index}].finding_id`);
      if (!/^F-([1-9]\d*)$/.test(findingId)) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `bypass_attempts[${index}].finding_id must match F-N pattern`);
      }
      if (findingIds && !findingIds.has(findingId)) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `bypass_attempts[${index}].finding_id ${findingId} does not match any recorded finding for this run`);
      }
      normalized.finding_id = findingId;
    }
    if (outcome === "finding_recorded" && !normalized.finding_id) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `bypass_attempts[${index}].finding_id is required when outcome is "finding_recorded"`);
    }
    return normalized;
  });
}

function assertBlockedHarnessConsistency(surfaceStatus, blockedHarnessRuns) {
  if (surfaceStatus === "complete" && blockedHarnessRuns.length > 0) {
    // Plane O O.7: the gate must surface a stable, machine-checkable code so
    // operators and reviewers can detect "surface marked complete despite
    // blocked harnesses" without string-matching the message. The structured
    // `details.code` reaches the MCP envelope as
    // `{error: {code: "surface_complete_with_blocked_harness", ...}}`.
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "surface_status cannot be 'complete' when blocked_harness_runs is non-empty; set surface_status to 'partial' or resolve the blocked harnesses first",
      {
        code: "surface_complete_with_blocked_harness",
        surface_status: surfaceStatus,
        blocked_harness_kinds: blockedHarnessRuns.map((entry) => entry.kind),
      },
    );
  }
}

function assertBlockedPrereqConsistency(surfaceStatus, blockedPrereqs) {
  if (surfaceStatus === "complete" && blockedPrereqs.length > 0) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "surface_status cannot be 'complete' when blocked_prereqs is non-empty; set surface_status to 'partial' or resolve the missing prerequisites first",
    );
  }
}

function assertSmartContractCompletionEvidence({
  surfaceType,
  surfaceStatus,
  bypassAttempts,
  findingCount,
}) {
  if (surfaceType !== "smart_contract") return;
  if (surfaceStatus !== "complete") return;
  if (findingCount > 0) return;
  if (bypassAttempts.length > 0) return;
  throw new ToolError(
    ERROR_CODES.INVALID_ARGUMENTS,
    "smart_contract surfaces cannot be marked 'complete' without evidence of attempted invariant breaks: record at least one finding for this surface, or supply at least one bypass_attempts entry citing a trust_assumptions[*].bypass_conditions condition that was tested. Set surface_status to 'partial' if no attempt was made.",
  );
}

function validateWaveHandoffPayload(payload, {
  targetDomain,
  wave,
  agent,
  surfaceId,
  effectiveSurfaceType,
  findingsForRun,
}) {
  if (payload == null || typeof payload !== "object" || Array.isArray(payload)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff payload must be an object");
  }

  if (payload.target_domain != null && assertNonEmptyString(payload.target_domain, "target_domain") !== targetDomain) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff target_domain does not match merge target");
  }

  const payloadWave = parseWaveId(payload.wave);
  const payloadAgent = parseAgentId(payload.agent);
  const payloadSurfaceId = assertNonEmptyString(payload.surface_id, "surface_id");
  const surfaceStatus = parseSurfaceStatus(payload.surface_status);

  if (payloadWave !== wave) throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff wave does not match assignment wave");
  if (payloadAgent !== agent) throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff agent does not match assignment");
  if (payloadSurfaceId !== surfaceId) throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff surface_id does not match assignment");
  if (!Array.isArray(findingsForRun)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "findingsForRun must be provided as an array");
  }

  const findingIdSet = new Set(findingsForRun.map((finding) => finding.id));

  const blockedHarnessRuns = normalizeBlockedHarnessRuns(payload.blocked_harness_runs);
  const blockedPrereqs = normalizeBlockedPrereqs(payload.blocked_prereqs);
  const bypassAttempts = normalizeBypassAttempts(payload.bypass_attempts, { findingIds: findingIdSet });
  assertBlockedHarnessConsistency(surfaceStatus, blockedHarnessRuns);
  assertBlockedPrereqConsistency(surfaceStatus, blockedPrereqs);

  const surfaceTypeFallback = typeof payload.surface_type === "string" && payload.surface_type.trim() !== ""
    ? payload.surface_type.trim()
    : null;
  const surfaceType = effectiveSurfaceType !== undefined
    ? effectiveSurfaceType
    : surfaceTypeFallback;
  assertSmartContractCompletionEvidence({
    surfaceType,
    surfaceStatus,
    bypassAttempts,
    findingCount: findingsForRun.length,
  });

  return {
    surface_type: surfaceType,
    summary: normalizeHandoffSummary(payload),
    chain_notes: normalizeChainNotes(payload.chain_notes),
    blocked_harness_runs: blockedHarnessRuns,
    blocked_prereqs: blockedPrereqs,
    bypass_attempts: bypassAttempts,
    dead_ends: normalizeStringArray(payload.dead_ends, "dead_ends"),
    waf_blocked_endpoints: normalizeStringArray(payload.waf_blocked_endpoints, "waf_blocked_endpoints"),
    lead_surface_ids: normalizeStringArray(payload.lead_surface_ids, "lead_surface_ids"),
    surface_lead_ids: normalizeStringArray(payload.surface_lead_ids, "surface_lead_ids"),
    surface_status: surfaceStatus,
  };
}

function attachHandoffOrigin(entries, { agent, surfaceId }) {
  if (!Array.isArray(entries)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "handoff entries must be an array");
  }
  return entries.map((entry) => ({
    ...entry,
    agent,
    surface_id: surfaceId,
  }));
}

function groupByOrigin(entries, { keyFor, seedFor, fields }) {
  const groups = new Map();
  for (const entry of entries) {
    const key = keyFor(entry);
    if (!groups.has(key)) {
      groups.set(key, {
        ...seedFor(entry),
        count: 0,
        agents: new Set(),
        surface_ids: new Set(),
      });
    }
    const group = groups.get(key);
    group.count += 1;
    if (entry.agent) group.agents.add(entry.agent);
    if (entry.surface_id) group.surface_ids.add(entry.surface_id);
  }
  return Array.from(groups.values()).map((group) => {
    const result = {};
    for (const field of fields) {
      result[field] = group[field];
    }
    return {
      ...result,
      count: group.count,
      agents: Array.from(group.agents).sort(compareAgentLabels),
      surface_ids: Array.from(group.surface_ids).sort(),
    };
  });
}

function groupBlockedHarnessRuns(entries) {
  return groupByOrigin(entries, {
    keyFor: (entry) => `${entry.kind}\u0000${entry.harness}`,
    seedFor: (entry) => ({ kind: entry.kind, harness: entry.harness }),
    fields: ["kind", "harness"],
  });
}

function groupBlockedPrereqs(entries) {
  return groupByOrigin(entries, {
    keyFor: (entry) => `${entry.kind}\t${entry.identifier_hint || ""}`,
    seedFor: (entry) => ({
      kind: entry.kind,
      identifier_hint: entry.identifier_hint || null,
    }),
    fields: ["kind", "identifier_hint"],
  });
}

function groupBypassAttempts(entries) {
  return groupByOrigin(entries, {
    keyFor: (entry) => `${entry.condition}\u0000${entry.outcome}`,
    seedFor: (entry) => ({ condition: entry.condition, outcome: entry.outcome }),
    fields: ["condition", "outcome"],
  });
}

module.exports = {
  BLOCKED_HARNESS_KIND_VALUES,
  BLOCKED_PREREQ_IDENTIFIER_HINT_LONG_HEX_PATTERN,
  BLOCKED_PREREQ_IDENTIFIER_HINT_PATTERN,
  BLOCKED_PREREQ_KIND_VALUES,
  BYPASS_ATTEMPT_CONDITION_MIN_CHARS,
  BYPASS_ATTEMPT_OUTCOME_VALUES,
  BYPASS_ATTEMPT_SUMMARY_MIN_CHARS,
  WAVE_HANDOFF_CONTENT_MAX_CHARS,
  HANDOFF_PROVENANCE_MODEL,
  HANDOFF_PROVENANCE_SIGNATURE_ALGORITHM,
  HANDOFF_PROVENANCE_SIGNATURE_CONTEXT,
  HANDOFF_PROVENANCE_SIGNATURE_VERSION,
  assertBlockedHarnessConsistency,
  assertBlockedPrereqConsistency,
  assertSmartContractCompletionEvidence,
  assignmentRequiresToken,
  attachHandoffOrigin,
  computeHandoffAssignmentHash,
  computeHandoffProvenanceDigest,
  generateHandoffToken,
  groupBlockedHarnessRuns,
  groupBlockedPrereqs,
  groupBypassAttempts,
  handoffAssignmentProvenancePayload,
  handoffSignaturePayload,
  normalizeBlockedHarnessRuns,
  normalizeBlockedPrereqs,
  normalizeBypassAttempts,
  normalizeChainNotes,
  normalizeHandoffSummary,
  normalizeHandoffProvenanceSignature,
  sha256Hex,
  signHandoffProvenance,
  validateHandoffProvenance,
  validateHandoffToken,
  validateWaveHandoffPayload,
  verifyHandoffProvenanceSignature,
};
