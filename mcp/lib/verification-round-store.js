"use strict";

const {
  SEVERITY_VALUES,
  VERIFICATION_CONFIDENCE_REASON_VALUES,
  VERIFICATION_CONFIDENCE_VALUES,
  VERIFICATION_DISPOSITION_VALUES,
  VERIFICATION_ROUND_VALUES,
} = require("./constants.js");
const {
  assertBoolean,
  assertEnumValue,
  assertInteger,
  assertNonEmptyString,
  assertRequiredText,
  normalizeOptionalText,
  parseFindingId,
} = require("./validation.js");
const {
  verificationRoundPaths,
} = require("./paths.js");
const {
  loadJsonDocumentStrict,
  withSessionLock,
  writeFileAtomic,
  writeMarkdownMirror,
} = require("./storage.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  safeAppendPipelineEventDirect,
} = require("./pipeline-events.js");
const {
  safeGovernanceContextForDomain,
} = require("./governance-context.js");
const {
  finalVerificationHash,
} = require("./verification-contracts.js");
const {
  findingIdSetForVerificationContext,
} = require("./verification-finding-id-adapter.js");

function verificationLib() {
  return require("./verification.js");
}

function normalizeStringEnumArray(value, fieldName, allowedValues, { required = false } = {}) {
  if (value == null) {
    if (required) throw new Error(`${fieldName} must be an array`);
    return [];
  }
  if (!Array.isArray(value)) {
    throw new Error(`${fieldName} must be an array`);
  }
  const seen = new Set();
  const normalized = [];
  for (const item of value) {
    const text = assertEnumValue(item, allowedValues, fieldName);
    if (!seen.has(text)) {
      seen.add(text);
      normalized.push(text);
    }
  }
  normalized.sort();
  return normalized;
}

const VERIFICATION_ARTIFACT_HASH_KEY_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/;
// Y.0 hotfix 2 (O3): field evidence showed verification rounds that recorded
// artifact hashes from third-party tooling (HTTP digest headers, vendor
// scanner outputs) where md5 — not sha256 — was the only hash the upstream
// emitted. The validator previously rejected those rounds; the regex now
// accepts both md5 (32 lowercase hex) and sha256 (64 lowercase hex). The
// 64-hex sha256 path is the back-compat default; md5 is the additive widening.
const VERIFICATION_ARTIFACT_HASH_VALUE_RE = /^(?:[a-f0-9]{32}|[a-f0-9]{64})$/;
const VERIFICATION_ARTIFACT_HASH_MAX_ENTRIES = 20;
const VERIFICATION_ARTIFACT_HASH_SECRET_KEY_RE = /(?:authorization|cookie|token|secret|password|passwd|api[_-]?key|credential|session)/i;

function normalizeArtifactHashes(value, fieldName = "artifact_hashes") {
  if (value == null) return {};
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${fieldName} must be an object`);
  }
  const entries = Object.entries(value);
  if (entries.length > VERIFICATION_ARTIFACT_HASH_MAX_ENTRIES) {
    throw new Error(`${fieldName} must contain at most ${VERIFICATION_ARTIFACT_HASH_MAX_ENTRIES} entries`);
  }
  const normalized = {};
  for (const [key, hash] of entries.sort(([a], [b]) => a.localeCompare(b))) {
    const safeKey = assertNonEmptyString(key, `${fieldName} key`);
    if (!VERIFICATION_ARTIFACT_HASH_KEY_RE.test(safeKey)) {
      throw new Error(`${fieldName} key must use only letters, numbers, dot, underscore, colon, or hyphen and be at most 80 chars`);
    }
    if (VERIFICATION_ARTIFACT_HASH_SECRET_KEY_RE.test(safeKey)) {
      throw new Error(`${fieldName} key must be metadata-only and must not name secrets or credentials`);
    }
    const normalizedHash = assertNonEmptyString(hash, `${fieldName}.${safeKey}`);
    if (!VERIFICATION_ARTIFACT_HASH_VALUE_RE.test(normalizedHash)) {
      throw new Error(`${fieldName}.${safeKey} must be a lower-case md5 (32 hex) or sha256 (64 hex) hash`);
    }
    normalized[safeKey] = normalizedHash;
  }
  return normalized;
}

function normalizeVerificationResult(result, findingIdSet, { schemaVersion = 1 } = {}) {
  if (result == null || typeof result !== "object" || Array.isArray(result)) {
    throw new Error("results entries must be objects");
  }

  const findingId = parseFindingId(result.finding_id);
  if (!findingIdSet.has(findingId)) {
    throw new Error(`Unknown finding_id: ${findingId}`);
  }

  const normalized = {
    finding_id: findingId,
    disposition: assertEnumValue(result.disposition, VERIFICATION_DISPOSITION_VALUES, "disposition"),
    severity: result.severity == null ? null : assertEnumValue(result.severity, SEVERITY_VALUES, "severity"),
    reportable: assertBoolean(result.reportable, "reportable"),
    reasoning: assertRequiredText(result.reasoning, "reasoning"),
  };

  if (schemaVersion === 2) {
    normalized.confidence = assertEnumValue(result.confidence, VERIFICATION_CONFIDENCE_VALUES, "confidence");
    normalized.confidence_reasons = normalizeStringEnumArray(
      result.confidence_reasons,
      "confidence_reasons",
      VERIFICATION_CONFIDENCE_REASON_VALUES,
      { required: true },
    ).sort((a, b) => a.localeCompare(b));
    normalized.state_sensitive = assertBoolean(result.state_sensitive, "state_sensitive");
    normalized.artifact_hashes = normalizeArtifactHashes(result.artifact_hashes);
    normalized.inherited_confidence_reasons = normalizeStringEnumArray(
      result.inherited_confidence_reasons,
      "inherited_confidence_reasons",
      VERIFICATION_CONFIDENCE_REASON_VALUES,
    ).sort((a, b) => a.localeCompare(b));
    normalized.resolved_confidence_reasons = normalizeStringEnumArray(
      result.resolved_confidence_reasons,
      "resolved_confidence_reasons",
      VERIFICATION_CONFIDENCE_REASON_VALUES,
    ).sort((a, b) => a.localeCompare(b));
  }

  return normalized;
}

function sortVerificationResultsByFindingIds(results, findingIds) {
  const order = new Map(findingIds.map((id, index) => [id, index]));
  return results.slice().sort((a, b) => (
    (order.get(a.finding_id) ?? Number.MAX_SAFE_INTEGER)
    - (order.get(b.finding_id) ?? Number.MAX_SAFE_INTEGER)
    || a.finding_id.localeCompare(b.finding_id)
  ));
}

function normalizeVerificationRoundDocument(document, { expectedDomain, expectedRound, findingIdSet = null } = {}) {
  if (document == null || typeof document !== "object" || Array.isArray(document)) {
    throw new Error("verification round document must be an object");
  }

  const round = assertEnumValue(document.round, VERIFICATION_ROUND_VALUES, "round");
  const version = assertInteger(document.version, "version", { min: 1, max: 2 });
  const normalized = {
    version,
    target_domain: assertNonEmptyString(document.target_domain, "target_domain"),
    round,
    notes: normalizeOptionalText(document.notes, "notes"),
    results: [],
  };

  if (version === 2) {
    if (document.plan_hash != null) {
      throw new Error("plan_hash is not supported; use adjudication_plan_hash");
    }
    normalized.verification_attempt_id = assertNonEmptyString(document.verification_attempt_id, "verification_attempt_id");
    normalized.verification_snapshot_hash = assertNonEmptyString(document.verification_snapshot_hash, "verification_snapshot_hash");
    normalized.round_profile = assertRequiredText(document.round_profile, "round_profile");
    if (round === "final") {
      normalized.adjudication_plan_hash = assertNonEmptyString(document.adjudication_plan_hash, "adjudication_plan_hash");
      normalized.final_verification_hash = normalizeOptionalText(document.final_verification_hash, "final_verification_hash");
    }
  }

  if (!Array.isArray(document.results)) {
    throw new Error("results must be an array");
  }

  const seenIds = new Set();
  for (const result of document.results) {
    const normalizedResult = normalizeVerificationResult(
      result,
      findingIdSet ?? new Set([parseFindingId(result.finding_id)]),
      { schemaVersion: version },
    );
    if (seenIds.has(normalizedResult.finding_id)) {
      throw new Error(`Duplicate finding_id in results: ${normalizedResult.finding_id}`);
    }
    seenIds.add(normalizedResult.finding_id);
    normalized.results.push(normalizedResult);
  }
  if (version === 2) {
    normalized.results.sort((a, b) => a.finding_id.localeCompare(b.finding_id));
  }

  if (expectedDomain != null && normalized.target_domain !== expectedDomain) {
    throw new Error(`verification round target_domain mismatch: expected ${expectedDomain}`);
  }
  if (expectedRound != null && normalized.round !== expectedRound) {
    throw new Error(`verification round mismatch: expected ${expectedRound}`);
  }

  return normalized;
}

function requirePriorVerificationRound(domain, round, findingIdSet) {
  const priorRoundByRound = { balanced: "brutalist", final: "balanced" };
  const priorRound = priorRoundByRound[round];
  if (!priorRound) return null;

  const priorPaths = verificationRoundPaths(domain, priorRound);
  const priorDocument = loadJsonDocumentStrict(priorPaths.json, `${priorRound} verification round JSON`);
  return normalizeVerificationRoundDocument(priorDocument, {
    expectedDomain: domain,
    expectedRound: priorRound,
    findingIdSet,
  });
}

function renderVerificationRoundMarkdown(document) {
  const lines = [
    `# Verification Round: ${document.round}`,
    `- Target: ${document.target_domain}`,
    ...(document.version === 2
      ? [
        "- Schema: v2",
        `- Attempt: ${document.verification_attempt_id}`,
        `- Snapshot: ${document.verification_snapshot_hash}`,
        ...(document.adjudication_plan_hash ? [`- Adjudication Plan: ${document.adjudication_plan_hash}`] : []),
        ...(document.final_verification_hash ? [`- Final Verification Hash: ${document.final_verification_hash}`] : []),
      ]
      : []),
    `- Notes: ${document.notes || "N/A"}`,
    `- Results: ${document.results.length}`,
    "",
  ];

  if (document.results.length === 0) {
    lines.push("No verification results recorded.");
    lines.push("");
    return `${lines.join("\n")}\n`;
  }

  for (const result of document.results) {
    lines.push(`## ${result.finding_id}`);
    lines.push(`- Disposition: ${result.disposition}`);
    lines.push(`- Severity: ${result.severity || "none"}`);
    lines.push(`- Reportable: ${result.reportable ? "YES" : "NO"}`);
    if (document.version === 2) {
      lines.push(`- Confidence: ${result.confidence}`);
      lines.push(`- Confidence Reasons: ${result.confidence_reasons.length ? result.confidence_reasons.join(", ") : "N/A"}`);
      lines.push(`- State Sensitive: ${result.state_sensitive ? "YES" : "NO"}`);
    }
    lines.push(`- Reasoning: ${result.reasoning}`);
    lines.push("");
  }

  return `${lines.join("\n")}\n`;
}

function writeVerificationRound(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  return withSessionLock(domain, () => {
  const round = assertEnumValue(args.round, VERIFICATION_ROUND_VALUES, "round");
  const notes = normalizeOptionalText(args.notes, "notes");
  if (!Array.isArray(args.results)) {
    throw new Error("results must be an array");
  }

  const schemaVersion = verificationLib().selectVerificationWriteSchemaVersion(domain);
  let v2State = null;
  let v2Snapshot = null;
  let v2Adjudication = null;
  if (schemaVersion === 2) {
    const current = verificationLib().currentV2RoundInput(domain, args);
    v2State = current.state;
    v2Snapshot = current.snapshot;
  }

  const findingIdSet = schemaVersion === 2
    ? new Set(v2Snapshot.finding_ids)
    : findingIdSetForVerificationContext({ domain });
  const seenIds = new Set();
  let results = args.results.map((result) => {
    const normalizedResult = normalizeVerificationResult(result, findingIdSet, { schemaVersion });
    if (seenIds.has(normalizedResult.finding_id)) {
      throw new Error(`Duplicate finding_id in results: ${normalizedResult.finding_id}`);
    }
    seenIds.add(normalizedResult.finding_id);
    return normalizedResult;
  });
  if (schemaVersion === 2) {
    results.sort((a, b) => a.finding_id.localeCompare(b.finding_id));
  }

  if (schemaVersion === 1) {
    const priorDocument = requirePriorVerificationRound(domain, round, findingIdSet);
    if (priorDocument) {
      const priorIds = new Set(priorDocument.results.map((result) => result.finding_id));
      const currentIds = new Set(results.map((result) => result.finding_id));
      const missing = [...priorIds].filter((id) => !currentIds.has(id));
      if (missing.length > 0) {
        throw new Error(
          `${round} round is missing ${missing.length} finding(s) from ${priorDocument.round} round: ${missing.join(", ")}. ` +
          "Include ALL findings from the prior round - pass through unchanged findings you did not re-test."
        );
      }
    }
  } else {
    if (args.plan_hash != null) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "plan_hash is not supported; use adjudication_plan_hash");
    }
    verificationLib().assertExactFindingCoverage(results, v2Snapshot.finding_ids, round);
    results = sortVerificationResultsByFindingIds(results, v2Snapshot.finding_ids);
    if (round === "final") {
      let adjudicationPlanHash;
      try {
        adjudicationPlanHash = assertNonEmptyString(args.adjudication_plan_hash, "adjudication_plan_hash");
      } catch (error) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message || String(error));
      }
      v2Adjudication = verificationLib().requireCurrentAdjudication(domain, {
        adjudicationPlanHash,
        state: v2State,
        snapshot: v2Snapshot,
      });
    } else if (args.adjudication_plan_hash != null) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "adjudication_plan_hash is only allowed for final v2 verification");
    }
  }

  const document = {
    version: schemaVersion,
    target_domain: domain,
    round,
    notes,
    results,
  };
  if (schemaVersion === 2) {
    document.verification_attempt_id = v2State.verification_attempt_id;
    document.verification_snapshot_hash = v2State.verification_snapshot_hash;
    document.round_profile = args.round_profile == null
      ? round
      : assertRequiredText(args.round_profile, "round_profile");
    if (round === "final") {
      document.adjudication_plan_hash = v2Adjudication.adjudication_plan_hash;
      document.final_verification_hash = finalVerificationHash(document);
      verificationLib().validateFinalAgainstAdjudication(domain, document, v2Adjudication);
    }
  }

  const paths = verificationRoundPaths(domain, round);
  writeFileAtomic(paths.json, JSON.stringify(document, null, 2) + "\n");

  const response = {
    round,
    schema_version: schemaVersion,
    results_count: results.length,
    written_json: paths.json,
  };
  if (schemaVersion === 2) {
    response.verification_attempt_id = v2State.verification_attempt_id;
    response.verification_snapshot_hash = v2State.verification_snapshot_hash;
    if (document.adjudication_plan_hash) response.adjudication_plan_hash = document.adjudication_plan_hash;
    if (document.final_verification_hash) response.final_verification_hash = document.final_verification_hash;
  }
  writeMarkdownMirror(paths.markdown, renderVerificationRoundMarkdown(document), response);
  safeAppendPipelineEventDirect(domain, "verification_written", {
    phase: "VERIFY",
    status: round,
    source: "bob_write_verification_round",
    verification_attempt_id: schemaVersion === 2 ? v2State.verification_attempt_id : undefined,
    verification_snapshot_hash: schemaVersion === 2 ? v2State.verification_snapshot_hash : undefined,
    adjudication_plan_hash: schemaVersion === 2 && round === "final" ? document.adjudication_plan_hash : undefined,
    final_verification_hash: schemaVersion === 2 && round === "final" ? document.final_verification_hash : undefined,
    counts: {
      results: results.length,
      reportable: results.filter((result) => result.reportable).length,
      confirmed: results.filter((result) => result.disposition === "confirmed").length,
    },
  }, safeGovernanceContextForDomain(domain));
  if (schemaVersion === 2) verificationLib().refreshVerificationManifest(domain, { throw_on_error: true });
  return JSON.stringify(response);
  });
}

function readVerificationRound(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const paths = verificationRoundPaths(domain, args.round);
  const document = loadJsonDocumentStrict(paths.json, `${paths.round} verification round JSON`);
  const findingIdSet = document && document.version === 2
    ? null
    : findingIdSetForVerificationContext({ domain });
  const normalized = normalizeVerificationRoundDocument(document, {
    expectedDomain: domain,
    expectedRound: paths.round,
    findingIdSet,
  });
  return JSON.stringify(verificationLib().decorateVerificationRoundRead(domain, normalized));
}

module.exports = {
  normalizeArtifactHashes,
  normalizeVerificationResult,
  normalizeVerificationRoundDocument,
  readVerificationRound,
  renderVerificationRoundMarkdown,
  requirePriorVerificationRound,
  sortVerificationResultsByFindingIds,
  writeVerificationRound,
};
