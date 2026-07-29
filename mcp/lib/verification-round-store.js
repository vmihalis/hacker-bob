"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
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
  statePath,
  verificationRoundPaths,
  verificationRoundPartialDir,
} = require("./paths.js");
const {
  loadJsonDocumentStrict,
  readJsonFile,
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
const {
  readCurrentClaimFreeze,
} = require("./claim-freeze.js");
const {
  readOffensiveRunRecords,
  offensiveRunRowSatisfiesEvidence,
  OFFENSIVE_TOOL_DEMONSTRATED_CEILING,
} = require("./claims.js");
const {
  resolveRowVerifierSafely,
} = require("./handoff-signing-key.js");
const {
  sessionNucleusFromState,
} = require("./governance-contracts.js");
const {
  readSessionStateStrict,
} = require("./session-state-store.js");

function verificationLib() {
  return require("./verification.js");
}

const VERIFY_SEVERITY_RANK = Object.freeze({
  info: 1,
  informational: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
});

function verifySeverityRank(severity) {
  return (typeof severity === "string" && VERIFY_SEVERITY_RANK[severity.toLowerCase()]) || 0;
}

function toRoundSeverity(claimSeverity) {
  return claimSeverity === "informational" ? "info" : claimSeverity;
}

const VERIFY_SEVERITY_BY_RANK = Object.freeze({
  1: "info",
  2: "low",
  3: "medium",
  4: "high",
  5: "critical",
});

function severityForVerifyRank(rank) {
  return VERIFY_SEVERITY_BY_RANK[rank] || null;
}

function rowAttemptFreshForState(row, sessionState) {
  return row.verification_attempt_id == null
    || (
      row.verification_attempt_id === sessionState.verification_attempt_id
      && (
        row.verification_snapshot_hash == null
        || row.verification_snapshot_hash === sessionState.verification_snapshot_hash
      )
    );
}

// The three v2 result fields that can carry confidence reasons. An unvalidated
// `exploit_replay_confirmed` proof claim must be stripped from all of them.
const REASON_ARRAY_FIELDS = Object.freeze([
  "confidence_reasons",
  "inherited_confidence_reasons",
  "resolved_confidence_reasons",
]);

// MUTATES `results` in place: lowers `result.severity` for each unproven
// severity rise, and strips a `exploit_replay_confirmed` reason that did not
// back a validated rise. Returns the list of clamps applied:
// [{ finding_id, from, to }]. The in-place mutation is load-bearing — the same
// array is serialized into the persisted round document by the caller (hence
// the explicit "InPlace" name).
//
// SCOPE: this is an anti-inflation guard applied to EVERY scope (web sessions
// with scope_policy.target_url AND repo/smart-contract sessions with
// scope_policy.target_repo), uniformly to every finding in the session. We
// deliberately do NOT carve out smart-contract findings. The web/smart_contract
// axis is per-finding, but every per-finding and per-session SC signal available
// before VERIFY is agent-influenced — claim surface_ids / payload
// (agent-recorded), and even surface routes (an evaluator can inject a synthetic
// smart-contract surface.observed via bob_append_frontier_event that routing then
// classifies). A spoofable SC exemption is strictly worse than none: it is an
// inflation bypass. The only trusted, non-agent signal is the init-time session
// scope. Consequence: a smart-contract finding is held to its FROZEN
// (evaluator-recorded) severity — the evaluator's assessment is the trusted
// baseline, and an unproven verification-time raise above it is clamped.
//
// The exploit-row allow-path (the only way a rise above baseline survives) is
// WEB-ONLY. It validates a rise to a SPECIFIC asserted rank against a
// MAC-covered, tiered demonstrated_severity carried on an offensive run row.
// The smart-contract executed-evidence ledger (invariant-verified.jsonl, read by
// readInvariantVerifiedSummary) is BOOLEAN per finding (VERIFIED_PASS / not) with
// no demonstrated-severity tier, so it cannot answer "was a rise to critical
// SPECIFICALLY proven?". Wiring it in as a boolean "rise unlocked" switch would
// be unsound — a verified-low FV pass would unlock a critical rise — so it is
// deliberately NOT consulted in the rise decision. A repo/SC rise therefore has
// no allow-path and ALWAYS clamps to the frozen baseline: a genuinely-critical SC
// finding must be FROZEN critical at record time, never raised at VERIFY,
// consistent with the discipline that severity follows demonstrated impact at
// claim time. (A session is exactly one of web/repo — normalizeScopePolicy keeps
// target_url and target_repo mutually exclusive — so a cross-stack web+SC session
// is a web session whose SC-typed findings clamp uniformly today, unchanged.)
// reclampSeveritiesAgainstFreeze — the PURE, read-safe core of the severity
// clamp. Returns a Map<finding_id, { severity, provenRise }> where `severity` is
// the WITHIN-BAND clamped target for each result: the frozen-claim baseline when a
// result's on-disk severity rises above the baseline WITHOUT a MAC-demonstrated
// proven rise, otherwise the result's own on-disk severity (this only LOWERS an
// above-baseline-unproven severity; it never raises). `provenRise` records whether
// the rise was MAC-validated (so the write-time wrapper can keep / strip the
// exploit-proof reason). It performs NO mutation and NO reason stripping.
//
// READ-TIME RE-CLAMP (Y): the same baseline+proven-rise logic the write path
// applies is re-applied at the compose + grade READ sites against a result set
// parsed from the on-disk final round, so a runtime-indirection rewrite of
// verification-final.json that bumps a finding above its demonstrated baseline
// re-reads as the baseline. Forging an inflated public/grade severity then requires
// re-forging the audit-graded, agent-Write-blocked claim-freeze.json baseline (or a
// MAC-valid demonstrated-severity offensive row), not just the keyless final round.
//
// FAIL-CLOSED identically to the in-place mutator: a corrupt session state or a
// corrupt freeze throws STATE_CONFLICT; a missing freeze / non-web-or-repo scope
// returns an empty Map (no clamp), matching today's pass-through.
function reclampSeveritiesAgainstFreeze(domain, results) {
  const out = new Map();
  let nucleus;
  let sessionState;
  try {
    sessionState = readSessionStateStrict(domain).state;
    nucleus = sessionNucleusFromState(sessionState);
  } catch (error) {
    if (fs.existsSync(statePath(domain))) {
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        `severity-rise guard could not read session state: ${error.message || String(error)}`,
      );
    }
    return out;
  }
  if (!nucleus || nucleus.scope_policy == null) return out;
  const isWebScope = nucleus.scope_policy.target_url != null;
  const isRepoScope = nucleus.scope_policy.target_repo != null;
  if (!isWebScope && !isRepoScope) return out;

  let freeze;
  try {
    freeze = readCurrentClaimFreeze(domain);
  } catch (error) {
    // readCurrentClaimFreeze now RE-THROWS on a present-but-INVALID freeze_mac (a
    // tampered/forged/cross-context freeze). Converting that throw into a
    // STATE_CONFLICT halt is the MEDIUM-A close: a tampered freeze HALTS the severity
    // clamp instead of returning an empty Map that would silently un-clamp inflated
    // severities. A genuinely-absent freeze (or a torn/corrupt one) returns null below,
    // never reaching this catch.
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `severity-rise guard could not read claim freeze: ${error.message || String(error)}`,
    );
  }
  if (!freeze || !Array.isArray(freeze.claims)) return out;

  const exploitRunClaimIds = new Map();
  for (const claim of freeze.claims) {
    if (!claim || typeof claim !== "object") continue;
    const refs = Array.isArray(claim.evidence_refs) ? claim.evidence_refs : [];
    const claimKey = typeof claim.claim_id === "string" && claim.claim_id
      ? claim.claim_id
      : JSON.stringify(refs.filter((ref) => ref && ref.kind === "finding"));
    for (const ref of refs) {
      if (!ref || ref.kind !== "exploit_run" || typeof ref.run_id !== "string") continue;
      const set = exploitRunClaimIds.get(ref.run_id) || new Set();
      set.add(claimKey);
      exploitRunClaimIds.set(ref.run_id, set);
    }
  }
  const duplicateExploitRunIds = new Set(
    Array.from(exploitRunClaimIds.entries())
      .filter(([, claimIds]) => claimIds.size > 1)
      .map(([runId]) => runId),
  );

  const byFinding = new Map();
  for (const claim of freeze.claims) {
    if (!claim || typeof claim !== "object") continue;
    const rank = verifySeverityRank(claim.severity);
    const refs = Array.isArray(claim.evidence_refs) ? claim.evidence_refs : [];
    const findingIds = refs
      .filter((ref) => ref && ref.kind === "finding" && typeof ref.finding_id === "string")
      .map((ref) => ref.finding_id);
    const claimSurfaceIds = Array.isArray(claim.surface_ids) ? claim.surface_ids : [];
    const rawClaimSurfaceId = claimSurfaceIds.length === 1 ? claimSurfaceIds[0] : null;
    const claimSurfaceId = typeof rawClaimSurfaceId === "string" && rawClaimSurfaceId.trim() !== ""
      ? rawClaimSurfaceId.trim()
      : null;
    const exploitRunRefs = findingIds.length === 1
      ? refs
        .filter((ref) => (
          ref
          && ref.kind === "exploit_run"
          && typeof ref.run_id === "string"
          && !duplicateExploitRunIds.has(ref.run_id)
        ))
        .map((ref) => ({ ref, surfaceId: claimSurfaceId }))
      : [];
    for (const findingId of findingIds) {
      const current = byFinding.get(findingId)
        || { maxRank: 0, maxSeverity: null, exploitRunRefs: [] };
      if (rank > current.maxRank) {
        current.maxRank = rank;
        current.maxSeverity = claim.severity;
      }
      for (const entry of exploitRunRefs) current.exploitRunRefs.push(entry);
      byFinding.set(findingId, current);
    }
  }

  let runRows = null;
  let verifier = null;
  for (const result of results) {
    if (!result || typeof result.severity !== "string") continue;

    const hasExploitReplaySignal = Array.isArray(result.confidence_reasons)
      && result.confidence_reasons.includes("exploit_replay_confirmed");
    let provenRise = false;

    const base = byFinding.get(result.finding_id);
    let maxDemonstratedRank = 0;
    if (isWebScope && base && base.exploitRunRefs.length > 0) {
      if (runRows === null) runRows = readOffensiveRunRecords(domain);
      if (runRows.length > 0) {
        if (verifier === null) verifier = resolveRowVerifierSafely(domain);
        for (const { ref, surfaceId } of base.exploitRunRefs) {
          for (const row of runRows) {
            if (
              offensiveRunRowSatisfiesEvidence(row, ref, domain, verifier)
              && rowAttemptFreshForState(row, sessionState)
              && surfaceId !== null
              && typeof row.surface_id === "string"
              && row.surface_id.trim() === surfaceId
            ) {
              const toolCeilRank = verifySeverityRank(
                OFFENSIVE_TOOL_DEMONSTRATED_CEILING[row.tool_id] ?? "info",
              );
              const cappedRowRank = Math.min(verifySeverityRank(row.demonstrated_severity), toolCeilRank);
              maxDemonstratedRank = Math.max(maxDemonstratedRank, cappedRowRank);
            }
          }
        }
      }
    }
    let clampedSeverity = result.severity;
    if (base && base.maxRank > 0 && verifySeverityRank(result.severity) > base.maxRank) {
      const assertedRank = verifySeverityRank(result.severity);
      if (hasExploitReplaySignal && base.exploitRunRefs.length > 0) {
        provenRise = maxDemonstratedRank >= assertedRank;
      }
      if (!provenRise) {
        const to = toRoundSeverity(base.maxSeverity);
        if (to !== result.severity) clampedSeverity = to;
      }
    }
    out.set(result.finding_id, { severity: clampedSeverity, provenRise });
  }
  return out;
}

function clampResultSeveritiesInPlace(domain, results) {
  // Delegate the baseline + proven-rise computation to the pure helper, then apply
  // the WRITE-TIME side effects: mutate result.severity DOWN to the clamped target
  // and strip the exploit-proof reason on an unproven/non rise. The read-time
  // re-clamp at compose/grade reuses the SAME helper, so write and read agree by
  // construction.
  const decisions = reclampSeveritiesAgainstFreeze(domain, results);
  const clamps = [];
  for (const result of results) {
    if (!result || typeof result.severity !== "string") continue;
    const decision = decisions.get(result.finding_id);
    if (!decision) continue;
    if (decision.severity !== result.severity) {
      const from = result.severity;
      result.severity = decision.severity;
      clamps.push({ finding_id: result.finding_id, from, to: decision.severity });
    }
    // `exploit_replay_confirmed` is a proof claim. Keep it ONLY when it backed a
    // validated severity rise; on a non-rise, an unproven (clamped) rise, or a
    // finding with no frozen baseline, strip it from ALL THREE persisted reason
    // arrays (confidence_reasons + the inherited_/resolved_ provenance arrays,
    // which the tool schema also permits to carry it) so the content-hashed round
    // artifact never carries a false exploit-proof audit signal — in any field.
    const exploitReasonAnywhere = REASON_ARRAY_FIELDS.some((field) => (
      Array.isArray(result[field]) && result[field].includes("exploit_replay_confirmed")
    ));
    if (exploitReasonAnywhere && !decision.provenRise) {
      for (const field of REASON_ARRAY_FIELDS) {
        if (Array.isArray(result[field])) {
          result[field] = result[field].filter((reason) => reason !== "exploit_replay_confirmed");
        }
      }
    }
  }
  return clamps;
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

  // Durable clamp audit. Preserved with the exact {finding_id, from, to} shape it
  // was written with so the v2 final_verification_hash recomputes consistently on
  // read; from/to are enum-validated so a tampered artifact cannot inject bogus
  // severity transitions.
  if (document.severity_clamps != null) {
    if (!Array.isArray(document.severity_clamps)) {
      throw new Error("severity_clamps must be an array");
    }
    normalized.severity_clamps = document.severity_clamps.map((clamp, index) => {
      if (clamp == null || typeof clamp !== "object" || Array.isArray(clamp)) {
        throw new Error(`severity_clamps[${index}] must be an object`);
      }
      return {
        finding_id: parseFindingId(clamp.finding_id),
        from: assertEnumValue(clamp.from, SEVERITY_VALUES, `severity_clamps[${index}].from`),
        to: assertEnumValue(clamp.to, SEVERITY_VALUES, `severity_clamps[${index}].to`),
      };
    });
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
  // Union-commit signal: a v2 round writer invoked WITHOUT a `results` array
  // commits the staged per-finding partials. The orchestrator triggers this once
  // every per-finding worker has staged its result; the server reads the
  // fresh-bound partials, unions them in snapshot order, and routes the SAME
  // finalize (exact-coverage assert + severity clamp + final hash + adjudication)
  // so the committed round is byte-identical to a single-shot write over the same
  // union. The legacy single-attempt batch path (a `results` array is supplied)
  // is untouched, and commitVerificationRoundFromPartials always supplies
  // `results`, so this routing never recurses.
  if (args.results === undefined) {
    const schemaVersion = verificationLib().selectVerificationWriteSchemaVersion(domain);
    if (schemaVersion !== 2) {
      throw new Error("results must be an array");
    }
    return commitVerificationRoundFromPartials(args);
  }
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

  const severityClamps = clampResultSeveritiesInPlace(domain, results);

  const document = {
    version: schemaVersion,
    target_domain: domain,
    round,
    notes,
    results,
  };
  // Durable, authoritative clamp audit: record every {finding_id, from, to} in
  // the persisted (content-hashed, for v2) round document so a runtime clamp is
  // reconstructable from the artifact itself — not only the ephemeral response
  // or the best-effort pipeline event. Omitted when nothing was clamped.
  if (severityClamps.length > 0) document.severity_clamps = severityClamps;
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
  // Audit signal: surface the clamp so an operator (and the agent that
  // submitted the higher severity) can tell a verifier's choice from a runtime
  // clamp. Without this the persisted severity differs silently from the
  // submitted one.
  if (severityClamps.length > 0) response.severity_clamps = severityClamps;
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
  if (severityClamps.length > 0) {
    // Lightweight signal only: the authoritative, per-finding clamp audit lives
    // in the persisted round document's `severity_clamps`. counts.clamped is the
    // exact (uncapped) count, so this event never diverges from the record.
    safeAppendPipelineEventDirect(domain, "severity_clamped", {
      status: round,
      source: "bob_write_verification_round",
      counts: { clamped: severityClamps.length },
    }, safeGovernanceContextForDomain(domain));
  }
  if (schemaVersion === 2) verificationLib().refreshVerificationManifest(domain, { throw_on_error: true });
  return JSON.stringify(response);
  });
}

// ---------------------------------------------------------------------------
// Finding-keyed verification-round partials.
//
// Per-finding verification workers each produce a PARTIAL round covering ONE
// finding_id. A worker submits its single result to the staging area below; the
// SERVER unions all staged partials into ONE round document at commit time and
// runs the unchanged writeVerificationRound finalization (exact-coverage assert,
// deterministic sort, anti-inflation severity clamp, v2 final hash, adjudication
// binding). This is faithful to the single-document-per-round schema:
// final_verification_hash, adjudication.input_round_hashes, evidence binding,
// and loadCurrentV2Round all assume exactly one artifact per round. Per-finding
// round documents would shatter every one of those bindings, so partials are
// UNIONED into the existing round artifact rather than persisted per-finding.
//
// Non-forgeability is preserved: no worker writes a round document or a verdict;
// each worker stages one finding's submission, and the exact-coverage gate
// asserts the UNION covers EXACTLY snapshot.finding_ids at commit. A worker that
// over-reports (an extra finding_id) is rejected by the same `extra` leg, and a
// missing finding stops-and-names the coverage gap (the union never silently
// drops a finding). The committed round is the ONLY audit-graded artifact.
// ---------------------------------------------------------------------------

function partialFileName(round, findingId) {
  return `${crypto.createHash("sha256").update(`${round}:${findingId}`).digest("hex")}.json`;
}

function partialFilePath(domain, round, findingId) {
  return path.join(verificationRoundPartialDir(domain, round), partialFileName(round, findingId));
}

function readVerificationRoundPartial(filePath) {
  try {
    return readJsonFile(filePath, { label: path.basename(filePath) });
  } catch {
    return null;
  }
}

// List the staged partials for a round whose binding matches the CURRENT v2
// VERIFY attempt/snapshot. Stale-bound partials (a prior attempt or a superseded
// snapshot) are pruned so they can never leak into a fresh round's union.
function listCurrentRoundPartials(domain, round, { state }) {
  const dir = verificationRoundPartialDir(domain, round);
  if (!fs.existsSync(dir)) return [];
  const partials = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
    const filePath = path.join(dir, entry.name);
    const partial = readVerificationRoundPartial(filePath);
    const fresh = partial
      && partial.round === round
      && partial.verification_attempt_id === state.verification_attempt_id
      && partial.verification_snapshot_hash === state.verification_snapshot_hash
      && partial.result
      && typeof partial.result === "object"
      && !Array.isArray(partial.result);
    if (!fresh) {
      try { fs.rmSync(filePath, { force: true }); } catch {}
      continue;
    }
    partials.push({ filePath, partial });
  }
  return partials;
}

// Stage ONE finding's verification result for a round. Called by a per-finding
// worker. Validates the v2 VERIFY binding and that finding_id ∈ snapshot, then
// validates the single result through the SAME normalizer the round writer uses
// (so an invalid submission is rejected here, not at commit). The RAW result is
// persisted (repro_steps/evidence_refs and the other write-tool inputSchema
// fields are carried through unchanged) so the committed round is byte-identical
// to a single-shot writeVerificationRound over the same union. Re-staging the
// same finding_id overwrites (idempotent worker retry).
function stageVerificationRoundPartial(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  return withSessionLock(domain, () => {
    const round = assertEnumValue(args.round, VERIFICATION_ROUND_VALUES, "round");
    const schemaVersion = verificationLib().selectVerificationWriteSchemaVersion(domain);
    if (schemaVersion !== 2) {
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        "per-finding verification partials require a v2 VERIFY attempt",
      );
    }
    const { state, snapshot } = verificationLib().currentV2RoundInput(domain, args);
    if (args.result == null || typeof args.result !== "object" || Array.isArray(args.result)) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "result must be a single verification result object");
    }
    const findingIdSet = new Set(snapshot.finding_ids);
    // Normalize for validation only (and to learn the canonical finding_id); the
    // RAW result is what we persist so the union round is byte-identical to a
    // single-shot write. Anti-inflation clamping is applied by the round writer
    // at commit (uniformly across the union), never here.
    const normalized = normalizeVerificationResult(args.result, findingIdSet, { schemaVersion });
    const findingId = normalized.finding_id;
    const notesFragment = normalizeOptionalText(args.notes, "notes");

    const dir = verificationRoundPartialDir(domain, round);
    fs.mkdirSync(dir, { recursive: true });
    const filePath = partialFilePath(domain, round, findingId);
    const document = {
      version: 1,
      target_domain: domain,
      round,
      verification_attempt_id: state.verification_attempt_id,
      verification_snapshot_hash: state.verification_snapshot_hash,
      finding_id: findingId,
      result: args.result,
      notes_fragment: notesFragment,
      staged_at: new Date().toISOString(),
    };
    writeFileAtomic(filePath, `${JSON.stringify(document, null, 2)}\n`);

    const staged = new Set(
      listCurrentRoundPartials(domain, round, { state }).map(({ partial }) => partial.finding_id),
    );
    const remaining = snapshot.finding_ids.filter((id) => !staged.has(id));
    safeAppendPipelineEventDirect(domain, "verification_partial_staged", {
      phase: "VERIFY",
      status: round,
      source: "verification_round_partial",
      verification_attempt_id: state.verification_attempt_id,
      verification_snapshot_hash: state.verification_snapshot_hash,
      counts: {
        snapshot_findings: snapshot.finding_ids.length,
        staged: staged.size,
        remaining: remaining.length,
      },
    }, safeGovernanceContextForDomain(domain));

    return JSON.stringify({
      round,
      finding_id: findingId,
      verification_attempt_id: state.verification_attempt_id,
      verification_snapshot_hash: state.verification_snapshot_hash,
      staged_count: staged.size,
      snapshot_findings: snapshot.finding_ids.length,
      remaining_finding_ids: remaining,
      ready_to_commit: remaining.length === 0,
    });
  });
}

// Commit the staged partials for a round into the single round document. The
// SERVER reads every fresh-bound partial, unions the raw results in snapshot
// order, and routes through the unchanged writeVerificationRound — so the
// exact-coverage assertion is the COMMIT gate. A missing finding fails with the
// existing "must cover exactly the current VERIFY snapshot finding IDs (missing:
// ...)" error, naming the coverage gap rather than silently dropping it. On
// success the staged partials are cleared (the committed round is authoritative).
function commitVerificationRoundFromPartials(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  return withSessionLock(domain, () => {
    const round = assertEnumValue(args.round, VERIFICATION_ROUND_VALUES, "round");
    const schemaVersion = verificationLib().selectVerificationWriteSchemaVersion(domain);
    if (schemaVersion !== 2) {
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        "per-finding verification partial commit requires a v2 VERIFY attempt",
      );
    }
    const { state, snapshot } = verificationLib().currentV2RoundInput(domain, args);
    const partials = listCurrentRoundPartials(domain, round, { state });
    const byFinding = new Map(partials.map(({ partial }) => [partial.finding_id, partial]));
    // Union in snapshot order. The exact-coverage gate inside writeVerificationRound
    // re-asserts membership; assembling in snapshot order keeps the union
    // deterministic and replayable independent of filesystem iteration order.
    const results = snapshot.finding_ids
      .filter((id) => byFinding.has(id))
      .map((id) => byFinding.get(id).result);
    const noteFragments = partials
      .map(({ partial }) => (typeof partial.notes_fragment === "string" ? partial.notes_fragment.trim() : ""))
      .filter((fragment) => fragment.length > 0);

    const writeArgs = {
      target_domain: domain,
      round,
      notes: args.notes != null
        ? args.notes
        : (noteFragments.length > 0 ? noteFragments.join("\n") : null),
      verification_attempt_id: state.verification_attempt_id,
      verification_snapshot_hash: state.verification_snapshot_hash,
      round_profile: args.round_profile != null ? args.round_profile : round,
      results,
    };
    if (args.adjudication_plan_hash != null) writeArgs.adjudication_plan_hash = args.adjudication_plan_hash;

    // writeVerificationRound re-takes the session lock; withSessionLock is
    // re-entrant per the storage contract, so the union commit is atomic against
    // concurrent stages. The exact-coverage assertion here is the only commit
    // gate — a missing finding throws before any round document is written.
    const response = JSON.parse(writeVerificationRound(writeArgs));

    // The committed round document is now authoritative; clear the staging area
    // so a subsequent attempt/snapshot starts clean. Best-effort: the freshness
    // filter in listCurrentRoundPartials already excludes stale-bound files.
    for (const { filePath } of partials) {
      try { fs.rmSync(filePath, { force: true }); } catch {}
    }
    safeAppendPipelineEventDirect(domain, "verification_partials_committed", {
      phase: "VERIFY",
      status: round,
      source: "verification_round_partial",
      verification_attempt_id: state.verification_attempt_id,
      verification_snapshot_hash: state.verification_snapshot_hash,
      counts: {
        snapshot_findings: snapshot.finding_ids.length,
        committed_results: results.length,
      },
    }, safeGovernanceContextForDomain(domain));

    return JSON.stringify({
      ...response,
      committed_from_partials: true,
      committed_finding_count: results.length,
    });
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
  clampResultSeveritiesInPlace,
  reclampSeveritiesAgainstFreeze,
  commitVerificationRoundFromPartials,
  listCurrentRoundPartials,
  normalizeArtifactHashes,
  normalizeVerificationResult,
  normalizeVerificationRoundDocument,
  readVerificationRound,
  renderVerificationRoundMarkdown,
  requirePriorVerificationRound,
  sortVerificationResultsByFindingIds,
  stageVerificationRoundPartial,
  verifySeverityRank,
  writeVerificationRound,
};
