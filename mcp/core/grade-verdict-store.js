"use strict";

const fs = require("fs");
const {
  GRADE_HOLD_MIN_SCORE,
  GRADE_SUBMIT_MIN_SCORE,
  GRADE_VERDICT_VALUES,
} = require("./grading-vocabulary.js");
const {
  SEVERITY_VALUES,
} = require("./constants/shared-vocabulary.js");
const {
  assertEnumValue,
  assertInteger,
  assertNonEmptyString,
  normalizeOptionalText,
  parseFindingId,
} = require("./io/validation.js");
const {
  gradeArtifactPaths,
  verificationRoundPaths,
} = require("./io/paths.js");
const {
  loadJsonDocumentStrict,
  withSessionLock,
  writeFileAtomic,
  writeMarkdownMirror,
} = require("./io/storage.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./io/envelope.js");
const {
  safeAppendPipelineEventDirect,
} = require("./telemetry/pipeline-events.js");
const {
  safeGovernanceContextForDomain,
} = require("./governance/governance-context.js");
const {
  readCurrentClaimFreeze,
} = require("./claims/claim-freeze.js");
const {
  claimIdSetFromFindingIds,
  findingIdSetForVerificationContext,
} = require("./verification/verification-finding-id-adapter.js");
const {
  normalizeVerificationRoundDocument,
  reclampSeveritiesAgainstFreeze,
} = require("./verification/verification-round-store.js");
const {
  finalSeverityByFinding,
  missingReachabilityStampsForReportableFindings,
  normalizeReachabilityDispositionStamp,
  reachabilityDispositionForFinding,
} = require("./frontier/reachability-ceiling.js");
const {
  computeDefenderDisposition,
  DEFENDER_DISPOSITION_VALUES,
} = require("./defender-disposition.js");
const {
  writeGradeFreezeBundleSync,
} = require("./grade-freeze-store.js");
const {
  canonicalJson,
} = require("./verification/verification-contracts.js");

function verificationLib() {
  return require("./verification/verification.js");
}

// Cycle C.6: project the finding_id set from the frozen CandidateClaim batch.
// Each CandidateClaim in the freeze carries evidence_refs[] entries with
// kind="finding" + finding_id; folding those produces the set of finding ids
// the grade pipeline must cover. The frozen set is authoritative — mutations
// to findings.jsonl AFTER the freeze must not change the grade work-set.
function readFrozenGradeFindingIdSet(domain) {
  const freeze = readCurrentClaimFreeze(domain);
  if (!freeze || !Array.isArray(freeze.claims)) return new Set();
  const ids = new Set();
  for (const claim of freeze.claims) {
    if (!claim || !Array.isArray(claim.evidence_refs)) continue;
    for (const ref of claim.evidence_refs) {
      if (ref && typeof ref === "object" && ref.kind === "finding" && typeof ref.finding_id === "string") {
        ids.add(ref.finding_id);
      }
    }
  }
  return ids;
}

// Resolve the grade work-set's finding_id membership. Frozen claims[] are
// authoritative when a freeze exists on disk. Sessions that have recorded
// claims but not yet materialized a freeze (legacy v1 verification, tests that
// drive grade directly) fall through to the live claim ledger so the
// finding_id projection stays consistent without a findings.jsonl reader.
function readGradeFindingIdSet(domain) {
  const frozen = readFrozenGradeFindingIdSet(domain);
  if (frozen.size > 0) return frozen;
  return findingIdSetForVerificationContext({ domain });
}

// LEGACY: removed in Plane D — accepts the older `{ finding_ids: [...] }`
// shape from callers that have not migrated to the snapshot/freeze projection.
// Routes the raw id array through the finding-id adapter so the grade
// pipeline still surfaces an authoritative finding-id set without the adapter
// dependency leaking past this function.
function resolveGradeFindingIdSet(domain, { findingIdSet = null, finding_ids = null } = {}) {
  if (findingIdSet instanceof Set) return findingIdSet;
  if (Array.isArray(findingIdSet)) return new Set(findingIdSet);
  if (Array.isArray(finding_ids)) {
    // LEGACY: removed in Plane D
    claimIdSetFromFindingIds(domain, finding_ids); // touches the adapter so the contract is exercised
    return new Set(finding_ids);
  }
  return readGradeFindingIdSet(domain);
}

function normalizeGradeFinding(result, findingIdSet) {
  if (result == null || typeof result !== "object" || Array.isArray(result)) {
    throw new Error("findings entries must be objects");
  }

  const findingId = parseFindingId(result.finding_id);
  if (!findingIdSet.has(findingId)) {
    throw new Error(`Unknown finding_id: ${findingId}`);
  }

  const normalized = {
    finding_id: findingId,
    impact: assertInteger(result.impact, "impact", { min: 0, max: 30 }),
    proof_quality: assertInteger(result.proof_quality, "proof_quality", { min: 0, max: 25 }),
    severity_accuracy: assertInteger(result.severity_accuracy, "severity_accuracy", { min: 0, max: 15 }),
    chain_potential: assertInteger(result.chain_potential, "chain_potential", { min: 0, max: 15 }),
    report_quality: assertInteger(result.report_quality, "report_quality", { min: 0, max: 15 }),
    total_score: assertInteger(result.total_score, "total_score", { min: 0 }),
    feedback: normalizeOptionalText(result.feedback, "feedback"),
  };
  if (result.reachability != null) {
    normalized.reachability = normalizeReachabilityDispositionStamp(result.reachability, "reachability");
  }
  // The graded-on severity for a finding whose reachability was silent (no cap).
  // Carried through read-back so a downstream reader has the display severity;
  // validated as a severity band. Absent when a reachability stamp is present (the
  // severity lives there) or on legacy verdicts, whose shape stays byte-identical.
  if (result.graded_severity != null) {
    normalized.graded_severity = assertEnumValue(
      result.graded_severity,
      ["critical", "high", "medium", "low", "info"],
      "graded_severity",
    );
  }
  // Additive server-derived defender relens (customer /r surface speaks defender,
  // not SUBMIT/HOLD/SKIP). Carried through read-back like reachability; never
  // enters the score/verdict math. Present on grades written after this wiring;
  // absent on legacy verdicts, whose shape stays byte-identical.
  if (result.defender_disposition != null) {
    normalized.defender_disposition = assertEnumValue(
      result.defender_disposition,
      DEFENDER_DISPOSITION_VALUES,
      "defender_disposition",
    );
  }

  const expectedTotal = normalized.impact
    + normalized.proof_quality
    + normalized.severity_accuracy
    + normalized.chain_potential
    + normalized.report_quality;
  if (normalized.total_score !== expectedTotal) {
    throw new Error(`finding ${findingId} total_score must equal the sum of rubric scores`);
  }

  return normalized;
}

// Optional, server-derived coverage-closure annotation (covered / total
// reachable cells + uncovered remainder). A pure stat: it never participates in
// the grade decision math, and is carried through read-back so a machine
// consumer sees the same numbers grade.md renders.
function normalizeCoverageClosure(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("coverage_closure must be an object");
  }
  return {
    cell_floor_active: value.cell_floor_active === true,
    covered_cells: assertInteger(value.covered_cells, "coverage_closure.covered_cells", { min: 0 }),
    total_reachable_cells: assertInteger(value.total_reachable_cells, "coverage_closure.total_reachable_cells", { min: 0 }),
    uncovered_reachable_cells: assertInteger(value.uncovered_reachable_cells, "coverage_closure.uncovered_reachable_cells", { min: 0 }),
  };
}

// Durable advisory-trust annotation stamped on a grade recorded under the
// sandbox-isolation degrade path. A pure trust marker: it never enters
// enforceGradeVerdictConsistency (the score/verdict math is unchanged), and is
// carried through read-back so a machine consumer sees the recorded verdict is
// advisory-trust, not production-trust.
function normalizeSandboxDowngrade(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("sandbox_downgrade must be an object");
  }
  if (value.downgraded !== true) {
    throw new Error("sandbox_downgrade.downgraded must be true");
  }
  const ids = Array.isArray(value.reportable_finding_ids)
    ? value.reportable_finding_ids.map((id) => assertNonEmptyString(id, "sandbox_downgrade.reportable_finding_ids[]"))
    : [];
  return {
    downgraded: true,
    reason: assertNonEmptyString(value.reason, "sandbox_downgrade.reason"),
    reportable_finding_ids: ids,
    warning: assertNonEmptyString(value.warning, "sandbox_downgrade.warning"),
  };
}

function normalizeGradeVerdictDocument(document, { expectedDomain = null, findingIdSet = null } = {}) {
  if (document == null || typeof document !== "object" || Array.isArray(document)) {
    throw new Error("grade verdict document must be an object");
  }

  const normalized = {
    version: assertInteger(document.version, "version", { min: 1, max: 1 }),
    target_domain: assertNonEmptyString(document.target_domain, "target_domain"),
    verdict: assertEnumValue(document.verdict, GRADE_VERDICT_VALUES, "verdict"),
    total_score: assertInteger(document.total_score, "total_score", { min: 0 }),
    findings: [],
    feedback: normalizeOptionalText(document.feedback, "feedback"),
    // Cycle C.6: optional claim freeze binding. Null preserves backwards
    // compatibility with legacy grade verdicts written before the binding was
    // introduced; new writers populate it whenever a freeze exists.
    claim_freeze_id: document.claim_freeze_id == null
      ? null
      : assertNonEmptyString(document.claim_freeze_id, "claim_freeze_id"),
  };

  // Present only on grade verdicts written after a cell floor exists; absent for
  // legacy/surface-only sessions, so their persisted shape is byte-identical.
  if (document.coverage_closure != null) {
    normalized.coverage_closure = normalizeCoverageClosure(document.coverage_closure);
  }

  // Present only on grade verdicts recorded under the sandbox-isolation degrade
  // path; absent for clean/enforce-allowed grades, so their shape is byte-
  // identical. Carried through read-back so a downstream grader/finalizer sees
  // the recorded verdict is advisory-trust, not production-trust.
  if (document.sandbox_downgrade != null) {
    normalized.sandbox_downgrade = normalizeSandboxDowngrade(document.sandbox_downgrade);
  }

  if (document.capability_pack_bindings != null) {
    if (expectedDomain == null) {
      throw new Error("capability_pack_bindings require an expected target domain");
    }
    if (!Array.isArray(document.capability_pack_bindings)) {
      throw new Error("capability_pack_bindings must be an array");
    }
    const bindingFindingIds = document.capability_pack_bindings.map((binding, index) => {
      if (binding == null || typeof binding !== "object" || Array.isArray(binding)) {
        throw new Error(`capability_pack_bindings[${index}] must be an object`);
      }
      return parseFindingId(binding.finding_id, `capability_pack_bindings[${index}].finding_id`);
    });
    const expected = require("./capability/capability-pack-grade-adapters.js")
      .buildCapabilityPackGradeBindings(expectedDomain, bindingFindingIds);
    if (expected.legacy_finding_ids.length > 0
        || canonicalJson(expected.bindings) !== canonicalJson(document.capability_pack_bindings)) {
      throw new Error("capability_pack_bindings do not match live pack adapter projections");
    }
    normalized.capability_pack_bindings = expected.bindings;
  }

  if (!Array.isArray(document.findings)) {
    throw new Error("findings must be an array");
  }

  const seenIds = new Set();
  for (const finding of document.findings) {
    const normalizedFinding = normalizeGradeFinding(
      finding,
      findingIdSet ?? new Set([parseFindingId(finding.finding_id)]),
    );
    if (seenIds.has(normalizedFinding.finding_id)) {
      throw new Error(`Duplicate finding_id in findings: ${normalizedFinding.finding_id}`);
    }
    seenIds.add(normalizedFinding.finding_id);
    normalized.findings.push(normalizedFinding);
  }

  if (expectedDomain != null && normalized.target_domain !== expectedDomain) {
    throw new Error(`grade verdict target_domain mismatch: expected ${expectedDomain}`);
  }

  enforceGradeVerdictConsistency(normalized, {
    finalReportableSeveritySet: expectedDomain == null ? null : requireFinalReportableSeveritySet(expectedDomain, findingIdSet),
  });

  return normalized;
}

function isMediumOrHigher(severity) {
  return ["medium", "high", "critical"].includes(severity);
}

// Cycle C.6: derive the reportable-severity set from the verification round
// bound to the frozen snapshot's claim freeze. For V2 attempts, requireV2State
// loads the freshness-checked snapshot (its claim_freeze_id is integrity-bound
// to the current claim-freeze.json by assertSnapshotMatchesFreeze) and the
// V2 final round is bound to that snapshot via verification_snapshot_hash, so
// the chain is round -> snapshot -> freeze. For V1 the snapshot/binding does
// not exist; we fall back to the live final round but still project the
// finding_id set from the frozen claim batch when one is available.
function requireFinalReportableSeveritySet(domain, findingIdSet) {
  const paths = verificationRoundPaths(domain, "final");
  let normalized;
  try {
    const document = loadJsonDocumentStrict(paths.json, "final verification round JSON");
    let effectiveFindingIdSet = findingIdSet;
    let v2Current = null;
    if (document && document.version === 2) {
      // requireV2State asserts the snapshot's claim_freeze_id and
      // claim_freeze_hash agree with the persisted claim-freeze.json; the
      // V2 verification round is then bound to that snapshot via the
      // verification_snapshot_hash equality enforced by
      // assertCurrentV2RoundDocument. The grade verdict therefore reads its
      // reportable-severity set from a final round that is transitively
      // bound to the frozen claim batch.
      v2Current = verificationLib().requireV2State(domain);
      effectiveFindingIdSet = new Set(v2Current.snapshot.finding_ids);
    }
    normalized = normalizeVerificationRoundDocument(document, {
      expectedDomain: domain,
      expectedRound: "final",
      findingIdSet: effectiveFindingIdSet,
    });
    if (normalized.version === 2) {
      verificationLib().assertCurrentV2RoundDocument(domain, normalized, {
        expectedRound: "final",
        state: v2Current.state,
        snapshot: v2Current.snapshot,
      });
    }
  } catch (error) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `Final verification must exist and be valid before grading: ${error.message || String(error)}`,
    );
  }
  // READ-TIME RE-CLAMP: re-apply the frozen-baseline severity clamp before
  // projecting the reportable medium+ set, so a runtime-indirection rewrite of
  // verification-final.json that inflates a finding above its demonstrated baseline
  // re-reads as the baseline here too — keeping this grade-side projection in lockstep
  // with finalSeverityByFinding / finalReportableFindingSeverities and the compose
  // medium+ set. Only LOWERS an above-baseline unproven severity; a MAC-armed proven
  // rise keeps its higher value. Fail-closed identically (a corrupt freeze throws).
  const decisions = reclampSeveritiesAgainstFreeze(domain, normalized.results);
  for (const result of normalized.results) {
    if (!result || typeof result.finding_id !== "string") continue;
    const decision = decisions.get(result.finding_id);
    if (decision && SEVERITY_VALUES.includes(decision.severity)) {
      result.severity = decision.severity;
    }
  }
  return new Set(
    normalized.results
      .filter((result) => result.reportable && isMediumOrHigher(result.severity))
      .map((result) => result.finding_id),
  );
}

// Cycle C.6: project the active claim_freeze_id for the session. Used to
// record the freeze binding on the grade verdict document so a grader can
// later prove which frozen claim batch was scored. Returns null when no
// freeze exists yet (legacy/pre-claim sessions).
function currentClaimFreezeId(domain) {
  const freeze = readCurrentClaimFreeze(domain);
  if (!freeze) return null;
  return typeof freeze.freeze_id === "string" && freeze.freeze_id ? freeze.freeze_id : null;
}

function requireEvidencePacksForGrading(domain, findingIdSet) {
  const {
    requireValidEvidencePacksForFinalReportableFindings,
  } = require("./evidence.js");
  return requireValidEvidencePacksForFinalReportableFindings(domain, { findingIdSet });
}

function enforceGradeVerdictConsistency(document, { finalReportableSeveritySet: reportableSet = null } = {}) {
  const maxFindingScore = document.findings.reduce(
    (maxScore, finding) => Math.max(maxScore, finding.total_score),
    0,
  );
  if (document.total_score !== maxFindingScore) {
    throw new Error(`grade total_score must equal the maximum per-finding score (${maxFindingScore})`);
  }

  const hasReportableMedium = reportableSet == null
    ? document.findings.length > 0
    : document.findings.some((finding) => reportableSet.has(finding.finding_id));

  let expectedVerdict;
  if (!hasReportableMedium || document.total_score < GRADE_HOLD_MIN_SCORE) {
    expectedVerdict = "SKIP";
  } else if (document.total_score < GRADE_SUBMIT_MIN_SCORE) {
    expectedVerdict = "HOLD";
  } else {
    expectedVerdict = "SUBMIT";
  }

  if (document.verdict !== expectedVerdict) {
    throw new Error(
      `grade verdict ${document.verdict} does not match total_score ${document.total_score} and reportable findings; expected ${expectedVerdict}`,
    );
  }
}

function renderGradeVerdictMarkdown(document) {
  const lines = [
    "# Grade Verdict",
    `- Target: ${document.target_domain}`,
    `- Verdict: ${document.verdict}`,
    `- Total Score: ${document.total_score}`,
    `- Feedback: ${document.feedback || "N/A"}`,
  ];
  const closure = document.coverage_closure;
  if (closure && closure.cell_floor_active === true) {
    lines.push(
      `- Coverage closure (informational): ${closure.covered_cells}/${closure.total_reachable_cells} `
      + `reachable cells covered (${closure.uncovered_reachable_cells} uncovered)`,
    );
  }
  lines.push("");

  if (document.findings.length === 0) {
    lines.push("No graded findings.");
    lines.push("");
    return `${lines.join("\n")}\n`;
  }

  for (const finding of document.findings) {
    lines.push(`## ${finding.finding_id}`);
    lines.push(`- Impact: ${finding.impact}`);
    lines.push(`- Proof Quality: ${finding.proof_quality}`);
    lines.push(`- Severity Accuracy: ${finding.severity_accuracy}`);
    lines.push(`- Chain Potential: ${finding.chain_potential}`);
    lines.push(`- Report Quality: ${finding.report_quality}`);
    lines.push(`- Total Score: ${finding.total_score}`);
    if (finding.reachability) {
      lines.push(`- Graded Severity: ${finding.reachability.graded_severity}`);
      lines.push(`- Attack Vector: ${finding.reachability.attack_vector}`);
      lines.push(`- Reachability Disposition: ${finding.reachability.disposition}`);
      lines.push(`- Reachability Source: ${finding.reachability.reachability_source}`);
      if (finding.reachability.call_path) {
        lines.push(`- Reachability Call Path: ${finding.reachability.call_path}`);
      }
      if (finding.reachability.reachability_divergence) {
        lines.push(`- Reachability Divergence: ${finding.reachability.reachability_divergence}`);
      }
      lines.push(`- Reachability Defensible: ${finding.reachability.defensible ? "yes" : "no"}`);
    }
    lines.push(`- Feedback: ${finding.feedback || "N/A"}`);
    lines.push("");
  }

  return `${lines.join("\n")}\n`;
}

function writeGradeVerdict(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  return withSessionLock(domain, () => {
  const verdict = assertEnumValue(args.verdict, GRADE_VERDICT_VALUES, "verdict");
  const totalScore = assertInteger(args.total_score, "total_score", { min: 0 });
  const feedback = normalizeOptionalText(args.feedback, "feedback");
  if (!Array.isArray(args.findings)) {
    throw new Error("findings must be an array");
  }

  // Cycle C.6: the grade work-set is the frozen claim batch enumeration.
  // resolveGradeFindingIdSet honors a caller-supplied legacy { finding_ids[] }
  // shape via the verification-finding-id-adapter; otherwise the frozen
  // claims[] projection wins, falling back to the live ledger only when no
  // freeze exists yet.
  const findingIdSet = resolveGradeFindingIdSet(domain, args);
  const seenIds = new Set();
  const normalizedFindings = args.findings.map((finding) => {
    const normalizedFinding = normalizeGradeFinding(finding, findingIdSet);
    if (seenIds.has(normalizedFinding.finding_id)) {
      throw new Error(`Duplicate finding_id in findings: ${normalizedFinding.finding_id}`);
    }
    seenIds.add(normalizedFinding.finding_id);
    return normalizedFinding;
  });

  const finalReportableSeveritySet = requireFinalReportableSeveritySet(domain, findingIdSet);
  // PH-C10 pack-owned grade gates. The dispatch is manifest-driven: a pack
  // with a declared grade adapter must produce its live binding now; packs
  // without one remain on the legacy web/OSS/SC gates below. Include every
  // graded finding plus every final-reportable finding so omitting a physical
  // reportable result from args cannot bypass its adapter.
  const packGradeFindingIds = Array.from(new Set([
    ...seenIds,
    ...finalReportableSeveritySet,
  ])).sort();
  let capabilityPackGradeProjection;
  try {
    capabilityPackGradeProjection = require("./capability/capability-pack-grade-adapters.js")
      .buildCapabilityPackGradeBindings(domain, packGradeFindingIds);
  } catch (error) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `Capability-pack grade adapter rejected the finding set: ${error.message || String(error)}`,
      { code: "capability_pack_grade_adapter_rejected" },
    );
  }
  const packHandledFindingIds = new Set(
    capabilityPackGradeProjection.handled_finding_ids,
  );
  const omittedPackReportable = [...finalReportableSeveritySet]
    .filter((findingId) => packHandledFindingIds.has(findingId) && !seenIds.has(findingId));
  if (omittedPackReportable.length > 0) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `Pack-owned reportable finding(s) are missing from the grade input: ${omittedPackReportable.join(", ")}`,
      { code: "capability_pack_reportable_grade_omitted", finding_ids: omittedPackReportable },
    );
  }
  const legacyReportableSeveritySet = new Set(
    [...finalReportableSeveritySet].filter((findingId) => !packHandledFindingIds.has(findingId)),
  );
  // Verdict-level sandbox-isolation gate (the ALL-sessions write-level door
  // closing the web/SC uniformity gap the repo-only lifecycle gateVerifyToGrade
  // misses). When a reportable medium+ finding draws on one of the four keyed
  // verdict ledgers and the LIVE re-probe cannot prove the signer key is isolated
  // (or a legacy/v1-HMAC row backs a NEW claim): enforce -> refuse to write the
  // grade (the analog of the compose door's report.md refusal); degrade ->
  // record the grade but stamp a durable downgrade annotation + emit a loud
  // warning so the SUBMIT-as-reportable verdict is not trusted as production
  // grade. Reuses the SAME decision module both verdict seams consume (no logic
  // fork) and the live probe inside it (never the stored sandbox-isolation.json
  // flag). A clean / advisory-only / no-verdict-ledger grade is inert
  // (decision:allow) and writes byte-identically — RANK != BOUND. The gate is
  // verdict-LEVEL O(1) (one evaluateVerdictSandboxGate per write), never per row.
  const sandboxGate = require("./ledger-integrity/index.js");
  let sandboxDecision;
  try {
    sandboxDecision = sandboxGate.evaluateVerdictSandboxGate(domain);
  } catch (error) {
    // Fail CLOSED: refuse to record a trusted grade whose isolation could not be
    // evaluated rather than launder an unevaluable verdict.
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `Refusing to write grade verdict: sandbox-isolation gate evaluation failed (failing closed): ${error.message || String(error)}`,
      { code: "grade_sandbox_isolation_unattested_unevaluable" },
      { remediation: sandboxGate.SANDBOX_REMEDIATION },
    );
  }
  let sandboxDowngrade = null;
  if (sandboxDecision.applies && sandboxDecision.decision === "block") {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      "Refusing to write grade verdict: "
        + `${sandboxDecision.reportable_finding_ids.length} reportable medium+ finding(s) draw on a keyed verdict `
        + `ledger but the signing key is not isolated (mode=enforce, reason=${sandboxDecision.reason}); a same-uid `
        + "agent could forge the backing MAC so a SUBMIT-reportable verdict cannot be trusted",
      {
        code: "grade_sandbox_isolation_unattested",
        reason: sandboxDecision.reason,
        reportable_finding_ids: sandboxDecision.reportable_finding_ids,
      },
      { remediation: sandboxGate.SANDBOX_REMEDIATION },
    );
  } else if (sandboxDecision.applies && sandboxDecision.decision === "downgrade") {
    // degrade: never silent (CONSTRAINT 5). Emit the loud warning AND fold a
    // durable downgrade annotation into the grade document so a downstream
    // grader/finalizer sees the recorded verdict is advisory-trust, not
    // production-trust. The verdict/score math (enforceGradeVerdictConsistency)
    // is untouched; only the TRUST stamp changes, analogous to the compose
    // door annotating bob_verified -> external_research provenance.
    const warning = sandboxGate.emitSandboxDowngradeWarning(sandboxDecision, "bob_write_grade_verdict:");
    sandboxDowngrade = {
      downgraded: true,
      reason: sandboxDecision.reason,
      reportable_finding_ids: sandboxDecision.reportable_finding_ids,
      warning,
    };
  }
  // Fail-closed trust gate: refuse to bind a trust-degraded (unsigned) finding
  // into the grade verdict at all. Any finding bound into grade.json (seenIds)
  // can drive total_score and the SUBMIT verdict regardless of its reportable
  // severity, so the gate keys on the actually-bound set, not the narrower
  // reportable-severity set. Inert for signed/unmarked findings because
  // degradedReportableFindingIds is empty for them.
  const { degradedReportableFindingIds } = require("../tools/record-candidate-claim.js");
  const degraded = degradedReportableFindingIds(domain);
  if (degraded.size > 0) {
    const offending = [...seenIds].filter((id) => degraded.has(id));
    if (offending.length > 0) {
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        `Refusing to grade trust-degraded (unsigned) finding(s): ${offending.join(", ")}`,
        { degraded_finding_ids: offending },
        {
          remediation:
            "Re-verify the source of the named finding(s) and clear the unsigned signature_verification_status marker, or exclude the finding(s) from the grade verdict, before writing it.",
        },
      );
    }
  }
  const missingReachability = missingReachabilityStampsForReportableFindings(domain);
  if (missingReachability.missing.length > 0) {
    const prefix = missingReachability.inventory_absent === true
      ? "Reachability inventory is required before grading final reportable repo module findings: "
      : "Reachability stamps are required for final reportable repo module findings before grading: ";
    throw new Error(
      prefix + missingReachability.missing.join(", "),
    );
  }
  const finalSeverities = finalSeverityByFinding(domain);
  // O-P4 differential-reproduction proof gate. A final-reportable high/critical
  // native-code finding must be backed by a verified_pass in repro-verified.jsonl
  // bound (by command_hash) to its declared repro_command_argv. The single
  // repo_command_run the claim cited is forgeable; only the verifier's differential
  // re-run mints the verified_pass, and that ledger is MCP-write-only. Fail closed:
  // an unbacked native high/critical finding cannot be graded (mirrors the
  // reachability-stamp gate above).
  const { reproVerifiedGapForNativeReportableFindings } = require("./claims/claims.js");
  const reproGap = reproVerifiedGapForNativeReportableFindings(domain, {
    reportableFindingIds: legacyReportableSeveritySet,
    finalSeverities,
  });
  if (reproGap.missing.length > 0) {
    const detail = reproGap.missing.map((m) => `${m.finding_id} (${m.reason})`).join(", ");
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `Differential reproduction verified_pass is required for final reportable high/critical native-code finding(s) before grading: ${detail}.`,
      { code: "O_P4_missing_repro_verified_pass", missing: reproGap.missing },
      {
        remediation:
          "Run bob_verify_repro_reproduction with command = the finding's repro_command_argv and control_ref = the upstream-fix commit; it mints a verified_pass only on a genuine sanitizer flip. Or lower the finding's severity below high / exclude it from the reportable set.",
      },
    );
  }
  // Standalone-finding differential proof gate. The symmetric sibling of the O-P4 gate
  // above, for the residual standalone non-oracle classes (auth-bypass-not-via-IDOR,
  // manual IDOR, SSRF, business-logic, info-disclosure, races). A final-reportable
  // medium+ finding NOT covered by an existing executed producer (native repro, FV
  // invariant-verified, or an exploit_run-backed exploited_safely claim) must be backed
  // by a verified_pass in finding-differential-verified.jsonl bound to the finding_id —
  // and that ledger is MCP-write-only (agent-Write-blocked). normalizeVerificationResult
  // only type-validates the round result; the executed flip is required HERE so a
  // merely-claimed standalone finding cannot be graded SUBMIT (MINT != CONFIRM). Fail
  // closed: an unbacked standalone medium+ finding caps to advisory (the RANK != BOUND
  // outcome — excluded from the reportable set, applied per finding, never a class bound).
  const { findingDifferentialGapForStandaloneReportableFindings } = require("./claims/claims.js");
  const findingDifferentialGap = findingDifferentialGapForStandaloneReportableFindings(domain, {
    reportableFindingIds: legacyReportableSeveritySet,
    finalSeverities,
  });
  if (findingDifferentialGap.missing.length > 0) {
    const detail = findingDifferentialGap.missing.map((m) => `${m.finding_id} (${m.reason})`).join(", ");
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `Finding-differential verified_pass is required for final reportable medium+ standalone finding(s) before grading: ${detail}.`,
      { code: "missing_finding_differential_verified_pass", missing: findingDifferentialGap.missing },
      {
        remediation:
          "Run bob_verify_finding_differential binding the executed positive run and its blocked control for THIS finding's surface (finding_differential_surface_mismatch = the verified flip is bound to a different surface; finding_differential_severity_below_finding = the executed flip's demonstrated severity is below the finding's severity), or lower its severity below medium / exclude it from the reportable set.",
      },
    );
  }
  // Cross-stack composition-path proof gate. The single-surface finding-differential
  // gate above runs FIRST and is unchanged; THIS gate only adds coverage for the
  // residual CROSS-STACK finding (surfaces span >=2 stacks OR a composition_path
  // ref). A final-reportable medium+ cross-stack finding whose proof IS a
  // composition path must carry that path_hash in the audit-graded
  // composition-verified.jsonl verified_path_hashes[] (re-resolved at read time —
  // bind rows RE-MAC-verified, the flip RE-adjudicated). Reasoning-only / unbound
  // proof caps to advisory (the RANK != BOUND outcome — excluded from the
  // reportable set, applied per finding, never a class bound, never dropped). A
  // single-surface finding fails the cross-stack predicate and is untouched here.
  const { crossStackPathGapForReportableFindings } = require("./claims/claims.js");
  const crossStackGap = crossStackPathGapForReportableFindings(domain, {
    reportableFindingIds: legacyReportableSeveritySet,
    finalSeverities,
  });
  if (crossStackGap.missing.length > 0) {
    const detail = crossStackGap.missing.map((m) => `${m.finding_id} (${m.reason})`).join(", ");
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `Cross-stack composition path verified_pass is required for final reportable medium+ cross-stack finding(s) before grading: ${detail}.`,
      { code: "missing_cross_stack_path_verified_pass", missing: crossStackGap.missing },
      {
        remediation:
          "Run bob_verify_composition_path binding the positive executed row (stack A) and its flipping control (stack B) for this finding's composition path, then cite the minted path_hash on the claim as an evidence_refs[] item of kind \"composition_path\" (cross_stack_path_unbound = no composition_path ref on the claim; cross_stack_path_not_verified = the cited path_hash is not a member of the audit-graded cross-stack verified set, e.g. it is a guard-only or same-stack-family verified_pass; cross_stack_path_surface_mismatch = the bound verified_pass is for a different finding's surfaces); or lower its severity below medium / exclude it from the reportable set.",
      },
    );
  }
  // Completion-depth gate. Sibling of the three report-side proof gates above, but it
  // guards a different invariant: a surface marked surface_status:complete (exhausted)
  // must bind to REAL work — a re-derived executed differential for one of its findings,
  // OR documented honest exhaustion (a coverage row / substantive bypass_attempt) — not
  // finding EXISTENCE alone. The report gates make a REPORTED finding real; this makes a
  // CLAIMED-EXHAUSTED surface real, closing the surface-completion masquerade (false
  // exhaustion feeding coverage_closure + the report's "surface tested" prose). Grade is
  // the right home: post-verification, the verifier-owned verified rows exist; an
  // evaluation-time gate would deadlock (evaluators cannot mint verified rows). Fail
  // closed — applies to ALL complete surfaces, not only the reportable set.
  const { completionDepthGapForCompleteSurfaces } = require("./claims/claims.js");
  const completionGap = completionDepthGapForCompleteSurfaces(domain, {
    packExecutedFindingIds: new Set(
      capabilityPackGradeProjection.completion_depth_finding_ids,
    ),
  });
  if (completionGap.missing.length > 0) {
    const detail = completionGap.missing
      .map((entry) => `${entry.surface_id} (${entry.reason})`)
      .join(", ");
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `Surfaces marked complete must bind to an executed differential or documented exhaustion before grading: ${detail}.`,
      { code: "missing_completion_depth", missing: completionGap.missing },
      {
        remediation:
          "For each named surface: run the relevant bob_verify_* for one of its findings (the executed differential is verifier-owned, minted downstream), OR reconcile it to surface_status: partial. IMPORTANT: for a surface whose reason is complete_idbearing_surface_no_differential (an id-bearing / BOLA surface), a coverage row or a bypass_attempt narrative does NOT clear it — it requires an executed cross-tenant flip (needs >=2 distinct principals) or a verified finding; with <2 principals, reconcile to partial (an honest 'needs a 2nd principal to test cross-tenant' block). Only for a NON-id-bearing surface (complete_surface_no_evidence) are concrete coverage rows / a substantive bypass_attempt also accepted; complete_surface_finding_not_executed = a recorded finding was never executed into a differential. complete_surface_routes_unverifiable = the surface-routes.json that establishes which surfaces are id-bearing is present but unreadable, so id-bearing status cannot be verified for this surface — it clears only on an executed / verified finding (never a bypass_attempt narrative); investigate the corrupt routes file or reconcile to partial.",
      },
    );
  }
  const findings = normalizedFindings.map((finding) => {
    const recordedSeverity = finalSeverities.get(finding.finding_id);
    // A finding not carried into the final verification round has no graded
    // severity; it is not a customer-facing result, so it gets NO defender word
    // (absent — never a fabricated "held" that a consumer cannot tell apart from a
    // genuinely held finding). Mirrors reachability, which is stamped only when it
    // has spoken.
    if (!recordedSeverity) return finding;
    const stamp = reachabilityDispositionForFinding({
      domain,
      findingId: finding.finding_id,
      recordedSeverity,
    });
    const reachability = stamp.disposition !== "unknown" ? stamp : null;
    // Deterministic defender relens of the SAME verdict numbers (final severity ×
    // reachability × per-finding score × reportable → fix_now/worth_fixing/watch/
    // held). Additive and non-gating — it never enters enforceGradeVerdictConsistency
    // or the score math. The graded-on severity is authoritative when reachability
    // has spoken; otherwise the recorded final severity.
    const defender_disposition = computeDefenderDisposition({
      finalSeverity: recordedSeverity,
      graded_severity: reachability ? reachability.graded_severity : null,
      disposition: reachability ? reachability.disposition : null,
      total_score: finding.total_score,
      reportable: finalReportableSeveritySet.has(finding.finding_id),
    });
    const stamped = { ...finding, defender_disposition };
    if (reachability) {
      // The graded-on severity lives on the reachability stamp when it spoke.
      stamped.reachability = reachability;
    } else {
      // Reachability was silent (unknown) — which is every web/SC finding. The
      // graded severity then equals the recorded final severity (nothing capped it).
      // Carry it explicitly so a downstream reader (e.g. the hosted witness) has the
      // finding's severity for display weight WITHOUT a reachability stamp — the
      // recorded severity is otherwise in hand at grade time and lost on write.
      stamped.graded_severity = recordedSeverity;
    }
    return stamped;
  });

  const claimFreezeId = currentClaimFreezeId(domain);
  const document = {
    version: 1,
    target_domain: domain,
    verdict,
    total_score: totalScore,
    findings,
    feedback,
    // Cycle C.6: record the frozen claim batch the grade verdict is scoring.
    // null is preserved for legacy/pre-claim sessions where no freeze exists.
    claim_freeze_id: claimFreezeId,
  };
  if (capabilityPackGradeProjection.bindings.length > 0) {
    document.capability_pack_bindings = capabilityPackGradeProjection.bindings;
  }
  enforceGradeVerdictConsistency(document, {
    finalReportableSeveritySet,
  });
  verificationLib().requireVerificationCompleteForGrade(domain, { findingIdSet });

  // Pure, non-gating coverage-closure annotation. Computed AFTER the verdict
  // math (it never enters enforceGradeVerdictConsistency) and attached only when
  // a cell floor exists, so legacy/surface-only grade verdicts stay byte-
  // identical. Fail-soft: a read error simply omits the annotation.
  try {
    const closure = require("./frontier/coverage-closure.js").coverageClosureStat(domain);
    if (closure && closure.cell_floor_active === true) {
      document.coverage_closure = closure;
    }
  } catch {}

  // degrade-mode durable trust annotation. Carried through normalizeGradeVerdict
  // Document read-back (like coverage_closure) so a downstream consumer sees the
  // recorded grade is advisory-trust. Absent on a clean/enforce-allowed grade, so
  // those documents stay byte-identical.
  if (sandboxDowngrade != null) {
    document.sandbox_downgrade = sandboxDowngrade;
  }

  const paths = gradeArtifactPaths(domain);
  writeFileAtomic(paths.json, JSON.stringify(document, null, 2) + "\n");

  // ARCHITECTURAL FIX (Eric-approved): additive, best-effort WORM freeze of
  // the just-written grade verdict, taken HERE (at GRADE time, before any
  // human approval exists) and keyed by grade_verdict_hash. See
  // mcp/lib/grade-freeze-store.js's module header for the full rationale.
  // No-ops when no bucket is configured (every non-AWS-branch session);
  // never throws; never blocks this write.
  {
    const { findingPayloadsFromClaims } = require("../tools/record-candidate-claim.js");
    writeGradeFreezeBundleSync({
      domain,
      document,
      findingPayloads: findingPayloadsFromClaims(domain),
      reportableFindingIds: finalReportableSeveritySet,
    });
  }

  const response = {
    verdict,
    findings_count: findings.length,
    written_json: paths.json,
    claim_freeze_id: claimFreezeId,
  };
  if (sandboxDowngrade != null) {
    response.sandbox_downgrade = sandboxDowngrade;
  }
  writeMarkdownMirror(paths.markdown, renderGradeVerdictMarkdown(document), response);
  safeAppendPipelineEventDirect(domain, "grade_written", {
    phase: "GRADE",
    status: verdict,
    source: "bob_write_grade_verdict",
    claim_freeze_id: claimFreezeId,
    counts: {
      findings: findings.length,
      total_score: totalScore,
    },
  }, safeGovernanceContextForDomain(domain));
  return JSON.stringify(response);
  });
}

function readGradeVerdict(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const paths = gradeArtifactPaths(domain);
  const document = loadJsonDocumentStrict(paths.json, "grade verdict JSON");
  // Cycle C.6: read the work-set from the frozen claim batch.
  const findingIdSet = readGradeFindingIdSet(domain);
  const normalized = normalizeGradeVerdictDocument(document, {
    expectedDomain: domain,
    findingIdSet,
  });
  requireEvidencePacksForGrading(domain, findingIdSet);
  return JSON.stringify(normalized);
}

function fileMtimeIso(filePath) {
  try {
    return new Date(fs.statSync(filePath).mtimeMs).toISOString();
  } catch {
    return null;
  }
}

function summarizeGradeVerdictArtifact(targetDomain) {
  const domain = assertNonEmptyString(targetDomain, "target_domain");
  const paths = gradeArtifactPaths(domain);
  const summary = {
    exists: fs.existsSync(paths.json),
    valid: false,
    legacy_summary: false,
    verdict: null,
    total_score: null,
    findings_count: 0,
    error: null,
    mtime: fileMtimeIso(paths.json),
  };
  if (!summary.exists) return summary;

  let document = null;
  try {
    document = loadJsonDocumentStrict(paths.json, "grade verdict JSON");
    if (document && typeof document === "object" && !Array.isArray(document)) {
      summary.verdict = typeof document.verdict === "string" ? document.verdict.slice(0, 40) : null;
      summary.total_score = Number.isFinite(document.total_score) ? Math.trunc(document.total_score) : null;
      summary.findings_count = Array.isArray(document.findings) ? document.findings.length : 0;
    }
    const normalized = JSON.parse(readGradeVerdict({ target_domain: domain }));
    summary.valid = true;
    summary.legacy_summary = false;
    summary.verdict = normalized.verdict;
    summary.total_score = normalized.total_score;
    summary.findings_count = normalized.findings.length;
  } catch (error) {
    if (isLegacyGradeSummaryDocument(document, domain)) {
      summary.valid = true;
      summary.legacy_summary = true;
      summary.error = null;
    } else {
      summary.valid = false;
      summary.error = error.message || String(error);
    }
  }
  return summary;
}

function isLegacyGradeSummaryDocument(document, domain) {
  if (document == null || typeof document !== "object" || Array.isArray(document)) return false;
  if (document.target_domain !== domain) return false;
  if (!GRADE_VERDICT_VALUES.includes(document.verdict)) return false;
  if (!Number.isInteger(document.total_score) || document.total_score < 0) return false;
  if (!Array.isArray(document.findings)) return false;
  return document.findings.every((finding) => {
    if (finding == null || typeof finding !== "object" || Array.isArray(finding)) return false;
    try {
      parseFindingId(finding.finding_id);
    } catch {
      return false;
    }
    if (!Number.isInteger(finding.total_score) || finding.total_score < 0) return false;
    return (
      finding.impact == null &&
      finding.proof_quality == null &&
      finding.severity_accuracy == null &&
      finding.chain_potential == null &&
      finding.report_quality == null
    );
  });
}

module.exports = {
  enforceGradeVerdictConsistency,
  normalizeGradeFinding,
  normalizeGradeVerdictDocument,
  readGradeVerdict,
  renderGradeVerdictMarkdown,
  requireFinalReportableSeveritySet,
  summarizeGradeVerdictArtifact,
  writeGradeVerdict,
};
