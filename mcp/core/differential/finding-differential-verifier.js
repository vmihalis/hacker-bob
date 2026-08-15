"use strict";

const fs = require("fs");

// Web-standalone finding-differential verifier — the execution-graded, differential
// gate that makes a standalone non-oracle finding (auth-bypass-not-via-IDOR, manual
// IDOR, SSRF, business-logic, info-disclosure, races) non-fabricatable at REPORT time.
// Mirrors repro-replay-verifier.js (native) and invariant-runner.js's FV-confirm:
// producer-independence is enforced at the INTEGRITY boundary, not by the producer's
// good behavior.
//
// THE FORGERY IT DEFEATS: normalizeVerificationResult only type-validates a round
// result's disposition/reportable/severity. A standalone web finding could be written
// confirmed+reportable+medium with NO executed binding at all — a forged report verdict.
// The existing per-finding executed binders (exploit_run, invariant-verified, repro-
// verified) cover only their own classes; the residual standalone classes had no
// per-finding executed producer.
//
// THE DEFENSE: a DIFFERENTIAL bound to the finding_id. Unlike the native/SC gates this
// verifier does NOT re-execute (the web standalone classes have no two-tree docker
// model — their executed evidence is HTTP rows that ALREADY exist as MAC-signed,
// run_id-single-use offensive-runs.jsonl rows). It BINDS two such executed rows for ONE
// finding_id, faithful to resolveSynthesizedDifferentialVerdict (binds an executed
// verified_pass it does not run) and to the O-P4 repro gate (matches a finding to its
// repro row by hash). It mints a verified_pass ONLY when a negative control FLIPS
// against the executed positive on the SAME surface: the positive demonstrates the
// issue (exploited_safely) and the control does NOT (blocked_by_defense). A single
// declared row, a hash-identical control, or a non-discriminating control (same
// outcome) shows NO FLIP and is REFUSED — exactly adjudicateDifferential's no-flip
// branch generalized to finding_id, mechanism-agnostically. The verdict is written
// ONLY to the MCP-write-only, agent-Write-blocked finding-differential-verified.jsonl
// the grade-time gate grades on.

const {
  findingDifferentialVerifiedJsonlPath,
  assertSafeDomain,
} = require("../io/paths.js");
const {
  appendJsonlLine,
  withSessionLock,
} = require("../io/storage.js");
const {
  hashCanonicalJson,
} = require("../verification/verification-contracts.js");
const {
  readOffensiveRunRecords,
} = require("../claims/claims.js");
const {
  verifyRowWithMac,
  OFFENSIVE_ROW_MAC_CONTEXT,
} = require("../ledger-integrity/offensive-row-mac.js");
const {
  resolveOffensiveRowVerifier,
} = require("../ledger-integrity/handoff-signing-key.js");

const FINDING_DIFFERENTIAL_VERIFIED_VERSION = 1;
const FINDING_DIFFERENTIAL_VERIFIED_MAX_RECORDS = 2000;

const RESULT_VERIFIED_PASS = "verified_pass";
const RESULT_REFUTED = "refuted";
const RESULT_INCONCLUSIVE = "inconclusive";

// First-cut executed source: offensive-runs.jsonl only. It is the MAC-signed,
// audit-graded, run_id-single-use executed HTTP ledger; binding any of its rows
// trusts a non-forgeable artifact. The auth_differential source named in the design
// is DEFERRED until its row is promoted to an audit-graded ledger (its results file
// is MCP-owned but not audit-graded today), so a row from a forgeable artifact can
// never back a verdict here.
const SUPPORTED_LEDGER_OFFENSIVE_RUNS = "offensive_runs";
const SUPPORTED_LEDGERS = Object.freeze(new Set([SUPPORTED_LEDGER_OFFENSIVE_RUNS]));

// The positive must DEMONSTRATE the issue; the control must be an affirmative DEFENSE
// block (blocked_by_defense); blocked_by_infra is transport/infra noise (egress
// unsupported, browser unavailable, baseline-not-auth-challenge, synthetic-id-not-
// provable), not a safe-variant denial — accepting it would let a transport hiccup
// mint a false control. The flip is mechanism-agnostic: the verdict words come from the
// executed row's offensive_outcome, never a crash-specific spelling.
const POSITIVE_OUTCOME = "exploited_safely";
const CONTROL_BLOCKED_OUTCOMES = Object.freeze(new Set(["blocked_by_defense"]));

// The MAC-covered oracle_kind stamped on an out-of-band (OOB) offensive row (oob-collector
// ORACLE_KIND_VALUES[0] / offensive-capture-writer OFFENSIVE_ROW_ORACLE_KINDS). The OOB
// attribution gate below keys on it so it caps ONLY OOB positives, never a non-OOB differential.
const OOB_ORACLE_KIND = "out_of_band_interaction";

// Hash the parts of an offensive row that constitute its executed identity, so two
// rows that are byte-identical in their proof material (same target/command/outcome/
// captures) collapse to the same row_hash and a hash-identical control is REFUSED.
// row_mac is excluded (it is the signature envelope, not the executed content), and
// run_id is excluded so a control that merely re-runs the identical request under a
// fresh run_id still collides — a true safe-variant control must differ in its
// command_hash/target/outcome, not just its id.
function offensiveRowHash(row) {
  return hashCanonicalJson({
    target_domain: row.target_domain,
    tool_id: row.tool_id,
    target: row.target,
    offensive_outcome: row.offensive_outcome,
    command_hash: row.command_hash,
    exit_code: row.exit_code,
    stdout_hash: row.stdout_hash,
    stderr_hash: row.stderr_hash,
    demonstrated_severity: row.demonstrated_severity,
    surface_id: row.surface_id,
  });
}

// Resolve an EXECUTED row from a {ledger,row_id} ref. Only offensive-runs is supported
// (first cut). The row must verify its MAC against the session signing key (so an
// agent-authored/tampered/wrong-key row is rejected before any field check), and must
// affirmatively assert a completed, non-dry-run, non-timed-out execution — mirroring
// offensiveRunRowSatisfiesEvidence's integrity preconditions. Returns the row or throws.
function resolveExecutedRow(domain, ref, verifier, label) {
  if (ref == null || typeof ref !== "object") {
    throw new Error(`${label}_run_ref must be an object { ledger, row_id }`);
  }
  if (!SUPPORTED_LEDGERS.has(ref.ledger)) {
    throw new Error(
      `${label}_run_ref.ledger must be one of [${[...SUPPORTED_LEDGERS].join(", ")}] (the audit-graded executed HTTP ledger); got ${ref.ledger}`,
    );
  }
  if (typeof ref.row_id !== "string" || !ref.row_id) {
    throw new Error(`${label}_run_ref.row_id (the executed offensive-runs run_id) is required`);
  }
  const rows = readOffensiveRunRecords(domain);
  const matches = rows.filter((r) => r && r.run_id === ref.row_id);
  if (matches.length === 0) {
    throw new Error(`${label}_run_ref.row_id does not match any offensive-runs row: ${ref.row_id}`);
  }
  if (matches.length > 1) {
    // The producer enforces run_id single-use; a duplicate means a corrupt/tampered
    // ledger, so fail closed rather than pick a row.
    throw new Error(`${label}_run_ref.row_id matches more than one offensive-runs row (corrupt ledger): ${ref.row_id}`);
  }
  const row = matches[0];
  // INTEGRITY boundary: the row must be MAC-signed by the trusted producer. New rows
  // are ed25519 (verified with the public key); legacy rows are symmetric HMAC. The
  // verifier bundle carries both and verifyRowWithMac dispatches per row on the row's
  // declared scheme. Same threat-model boundary as offensiveRunRowSatisfiesEvidence:
  // the verifier holds no secret, but the ed25519 private key is still 0600 at the
  // agent uid, so this split is the foundation, not the close.
  if (!verifyRowWithMac(OFFENSIVE_ROW_MAC_CONTEXT, row, verifier)) {
    throw new Error(`${label}_run_ref.row_id is not a validly MAC-signed offensive-runs row: ${ref.row_id}`);
  }
  if (row.dry_run !== false) {
    throw new Error(`${label}_run_ref.row_id is a dry-run row (a single declared row never mints verified): ${ref.row_id}`);
  }
  if (row.timed_out !== false) {
    throw new Error(`${label}_run_ref.row_id timed out (no trustworthy executed bytes): ${ref.row_id}`);
  }
  return row;
}

// The FLIP CONTRACT — generalizes adjudicateDifferential (repro-replay-verifier.js) to
// finding_id, mechanism-agnostically. Given the executed positive + control rows already
// bound to THIS finding's surface, derive the verdict:
//   * BOTH rows must bind to THIS finding's surface_id (mirror the #111 surface-binding
//     gate). A row produced for another surface can never back this finding.
//   * The positive must DEMONSTRATE the issue (offensive_outcome === exploited_safely).
//   * A hash-identical control (positive_row_hash === control_row_hash) is REFUSED — it
//     cannot discriminate (the non-forgeability spine; mirrors
//     adjudicateInvariantDifferential's control-hash gate).
//   * A non-discriminating control (same offensive_outcome as the positive) is REFUSED —
//     no flip (adjudicateDifferential's controlVerdict.crashed branch generalized).
//   * The control must be a TRUE safe-variant on the SAME surface: a blocked_by_*
//     outcome. Anything else is no flip.
// Only a genuine flip (positive exploited, control blocked, same surface, distinct hash)
// mints verified_pass.
function adjudicateFindingDifferential({ surfaceId, positiveRow, controlRow }) {
  const positiveSurface = typeof positiveRow.surface_id === "string" ? positiveRow.surface_id.trim() : "";
  const controlSurface = typeof controlRow.surface_id === "string" ? controlRow.surface_id.trim() : "";
  const boundSurface = typeof surfaceId === "string" ? surfaceId.trim() : "";

  // Surface binding (issue #111 generalized): both rows must bind to THIS finding's
  // single surface, so a higher-impact row produced for surface B can never resolve a
  // finding on surface A.
  if (!boundSurface) {
    return { result: RESULT_INCONCLUSIVE, reason: "finding has no single bound surface_id (cannot bind the differential)" };
  }
  if (positiveSurface !== boundSurface) {
    return { result: RESULT_INCONCLUSIVE, reason: `positive row surface_id (${positiveSurface || "<empty>"}) does not equal the finding surface (${boundSurface})` };
  }
  if (controlSurface !== boundSurface) {
    return { result: RESULT_INCONCLUSIVE, reason: `control row surface_id (${controlSurface || "<empty>"}) does not equal the finding surface (${boundSurface})` };
  }

  const positiveHash = offensiveRowHash(positiveRow);
  const controlHash = offensiveRowHash(controlRow);

  // The positive must demonstrate the issue. A positive that is itself blocked/declared
  // proves nothing (a single non-demonstrating run never mints verified).
  if (positiveRow.offensive_outcome !== POSITIVE_OUTCOME) {
    return {
      result: RESULT_REFUTED,
      reason: `positive run did not demonstrate the issue (offensive_outcome=${positiveRow.offensive_outcome}, expected ${POSITIVE_OUTCOME})`,
      positiveHash,
      controlHash,
    };
  }

  // Hash-identical control cannot discriminate (the non-forgeability spine).
  if (positiveHash === controlHash) {
    return {
      result: RESULT_REFUTED,
      reason: "control row is hash-identical to the positive (a non-discriminating control cannot flip)",
      positiveHash,
      controlHash,
    };
  }

  // Non-discriminating control: same offensive_outcome as the positive -> no flip
  // (the control also demonstrates, or fails the same way). Refuted, exactly
  // adjudicateDifferential's "control also crashes" branch generalized.
  if (controlRow.offensive_outcome === positiveRow.offensive_outcome) {
    return {
      result: RESULT_REFUTED,
      reason: `no differential flip: the control demonstrates the same outcome as the positive (${controlRow.offensive_outcome})`,
      positiveHash,
      controlHash,
    };
  }

  // The control must be a true safe-variant: blocked. Any other (non-blocked,
  // non-exploited) outcome is not a discriminating control.
  if (!CONTROL_BLOCKED_OUTCOMES.has(controlRow.offensive_outcome)) {
    return {
      result: RESULT_REFUTED,
      reason: `control row is not a blocked safe-variant (offensive_outcome=${controlRow.offensive_outcome}); the control must be blocked on the same surface to flip`,
      positiveHash,
      controlHash,
    };
  }

  // ATTRIBUTION GATE (OOB). An OOB positive earns a clean reportable verified_pass ONLY when the
  // sink interaction is PROVABLY target-caused: an HTTP callback whose source IP is VERIFIED
  // distinct from the configured session egress (oob-collector sets the MAC-covered
  // source_attribution_established:true only then). Everything else is attribution-UNESTABLISHED
  // and caps to a lead: a DNS callback (source = the target's recursive resolver, so it is
  // self-hittable — the agent can self-resolve the token), an HTTP callback when no session-egress
  // IP is configured (source distinctness is unverifiable, so the agent could self-request the OOB
  // URL), and a legacy/buggy OOB row missing the field (undefined !== true → fail-closed). The
  // decoy-silent flip proves token-SPECIFICITY (the sink fired for the injected token, not a random
  // decoy) but NOT target-CAUSATION, so an unestablished OOB stays INCONCLUSIVE (not refuted — the
  // flip is real, just insufficient). The gate is keyed on the MAC-covered oracle_kind, so it fires
  // for OOB positives ONLY — a non-OOB positive (IDOR/XSS/repro/...) has no oracle_kind and is
  // unaffected. Re-adjudicated at read time, so a verified row minted before this gate is dropped.
  if (positiveRow.oracle_kind === OOB_ORACLE_KIND && positiveRow.source_attribution_established !== true) {
    return {
      result: RESULT_INCONCLUSIVE,
      reason: "OOB positive attribution is UNESTABLISHED: the sink interaction is not provably target-caused (a DNS callback from the target's recursive resolver, an HTTP callback with no configured session-egress IP to prove source distinctness, or a row predating attribution). The decoy-silent flip proves token-specificity, not target-causation — re-confirm with an HTTP OOB hit whose source IP is distinct from the configured session egress (set BOB_OOB_SELF_EGRESS_IP).",
      positiveHash,
      controlHash,
    };
  }

  // Genuine flip: positive demonstrates the issue, control is blocked, on the SAME
  // surface, with distinct executed identities.
  return {
    result: RESULT_VERIFIED_PASS,
    reason: "executed_finding_differential_flip",
    positiveHash,
    controlHash,
  };
}

// verifyFindingDifferential — bind two executed offensive-runs rows for ONE finding_id,
// adjudicate the flip, and mint a verdict ONLY on a genuine flip.
//
// input: { target_domain, finding_id, surface_id, positive_run_ref, control_run_ref }
//   surface_id is the finding's single surface; both rows must bind to it.
//   each *_run_ref is { ledger: "offensive_runs", row_id: <run_id> } pointing at an
//   EXECUTED, MAC-signed, MCP-write-only row the session already produced.
function verifyFindingDifferential(input) {
  if (input == null || typeof input !== "object") {
    throw new TypeError("input must be { target_domain, finding_id, surface_id, positive_run_ref, control_run_ref }");
  }
  const targetDomain = assertSafeDomain(input.target_domain);
  const findingId = typeof input.finding_id === "string" ? input.finding_id : null;
  if (!findingId) throw new Error("finding_id is required");
  const surfaceId = typeof input.surface_id === "string" ? input.surface_id.trim() : "";
  if (!surfaceId) throw new Error("surface_id (the finding's single bound surface) is required");

  return withSessionLock(targetDomain, () => {
    const verifier = resolveOffensiveRowVerifier(targetDomain);
    const positiveRow = resolveExecutedRow(targetDomain, input.positive_run_ref, verifier, "positive");
    const controlRow = resolveExecutedRow(targetDomain, input.control_run_ref, verifier, "control");

    // run_id single-use: a row already bound to a finding-differential verdict cannot
    // bind another (mirror duplicateExploitRunIds / the offensive run_id single-use
    // guard). Read the ledger under the lock so the check-then-append is race-safe.
    const priorBoundRunIds = readBoundRunIds(targetDomain);
    if (priorBoundRunIds.has(positiveRow.run_id)) {
      throw new Error(`positive_run_ref.row_id is already bound to a finding-differential verdict (run_id single-use): ${positiveRow.run_id}`);
    }
    if (priorBoundRunIds.has(controlRow.run_id)) {
      throw new Error(`control_run_ref.row_id is already bound to a finding-differential verdict (run_id single-use): ${controlRow.run_id}`);
    }
    if (positiveRow.run_id === controlRow.run_id) {
      throw new Error("positive and control must be DIFFERENT executed rows (a single run never mints verified)");
    }

    const { result, reason, positiveHash, controlHash } = adjudicateFindingDifferential({
      surfaceId, positiveRow, controlRow,
    });

    return mintFindingDifferentialRecord({
      targetDomain,
      findingId,
      surfaceId,
      result,
      reason,
      positiveRunId: positiveRow.run_id,
      positiveRowHash: positiveHash || offensiveRowHash(positiveRow),
      controlRunId: controlRow.run_id,
      controlRowHash: controlHash || offensiveRowHash(controlRow),
      source: SUPPORTED_LEDGER_OFFENSIVE_RUNS,
    });
  });
}

// The set of offensive run_ids already bound to a finding-differential verdict
// (verified_pass OR refuted/inconclusive — a row is consumed by its first binding so it
// cannot be re-bound to launder a different verdict). Read off the ledger only.
function readBoundRunIds(domain) {
  const ids = new Set();
  for (const record of readRecords(domain)) {
    if (typeof record.positive_run_id === "string") ids.add(record.positive_run_id);
    if (typeof record.control_run_id === "string") ids.add(record.control_run_id);
  }
  return ids;
}

function readRecords(domain) {
  let records = [];
  try {
    const raw = fs.readFileSync(findingDifferentialVerifiedJsonlPath(domain), "utf8");
    records = raw
      .split("\n")
      .filter((line) => line.trim())
      .map((line) => { try { return JSON.parse(line); } catch { return null; } })
      .filter(Boolean);
  } catch {
    records = [];
  }
  return records;
}

// Mint the adjudicated verdict to the MCP-write-only, agent-Write-blocked
// finding-differential-verified.jsonl, keyed by finding_id and bound to BOTH executed
// run ids + hashes. Mirrors mintInvariantVerifiedRecord / mintDifferentialRecord. MUST
// be called under withSessionLock (verifyFindingDifferential holds it).
function mintFindingDifferentialRecord({
  targetDomain, findingId, surfaceId, result, reason,
  positiveRunId, positiveRowHash, controlRunId, controlRowHash, source,
}) {
  const body = {
    version: FINDING_DIFFERENTIAL_VERIFIED_VERSION,
    target_domain: targetDomain,
    ts: new Date().toISOString(),
    finding_id: findingId,
    result,
    reason,
    surface_id: surfaceId,
    source,
    positive_run_id: positiveRunId,
    positive_row_hash: positiveRowHash,
    control_run_id: controlRunId,
    control_row_hash: controlRowHash,
  };
  const record = { ...body, results_hash: hashCanonicalJson(body) };
  appendJsonlLine(findingDifferentialVerifiedJsonlPath(targetDomain), record, {
    maxRecords: FINDING_DIFFERENTIAL_VERIFIED_MAX_RECORDS,
  });
  return {
    target_domain: targetDomain,
    finding_id: findingId,
    result,
    reason,
    surface_id: surfaceId,
    positive_run_id: positiveRunId,
    positive_row_hash: positiveRowHash,
    control_run_id: controlRunId,
    control_row_hash: controlRowHash,
    results_hash: record.results_hash,
  };
}

// reverifyFindingDifferentialRecord — READ-TIME INTEGRITY. Do NOT trust the verdict
// row's stored result / surface_id / demonstrated_severity (results_hash is an UNKEYED
// self-hash, so a same-UID `node -e` can write a bare forged verified_pass line whose
// run_ids point at nothing). RE-RESOLVE positive_run_id + control_run_id against the
// MAC-verified offensive-runs rows and RE-RUN adjudicateFindingDifferential, deriving
// surface_id + demonstrated_severity FROM THE MAC-COVERED POSITIVE ROW. This reuses the
// source-row MAC (offensive-row-mac.js via resolveExecutedRow) — no new key surface.
//
// A forged verdict whose run_ids don't resolve to two MAC-valid rows that ACTUALLY FLIP
// on the bound surface fails here (any throw → ok:false). Forging the source rows still
// needs the 0600 signing key, the same residual the whole offensive stack documents as
// the sandbox-PR boundary; it is NOT widened here.
//
// FAIL-CLOSED on a rotated/truncated ledger: a verdict whose offensive-runs rows were
// legitimately minted then later removed reads as unverified. The source evidence IS the
// asset — if it is gone, the verdict is no longer provable.
//
// Runs under NO lock (read-only, like the summary reader). Returns
// { ok, surface_id, demonstrated_severity, container_isolated } — surface_id +
// demonstrated_severity + container_isolated are taken from the RE-RESOLVED POSITIVE
// ROW, never the verdict record's stored fields. container_isolated mirrors the
// invariant leg's HIGH-1 re-resolution (readInvariantVerifiedSummary): the verdict gate
// treats an SC finding-differential-backed reportable whose positive offensive row was
// NOT containerized as un-isolated. Offensive-runs rows do not carry container_isolated
// today, so this re-resolves to false for every existing finding-differential row — the
// CORRECT fail-closed posture (no containerization proof => un-isolated).
function reverifyFindingDifferentialRecord(domain, record) {
  const targetDomain = assertSafeDomain(domain);
  if (record == null || typeof record !== "object") return { ok: false, surface_id: null, demonstrated_severity: null, container_isolated: false };
  try {
    // Read-time re-derivation (CONSTRAINT 6): the MAC is re-checked here at read time,
    // in-memory, no disk re-check beyond reading the verifier bundle once. Scheme
    // dispatch is per row, so the verdict flips identically for ed25519 and legacy rows.
    const verifier = resolveOffensiveRowVerifier(targetDomain);
    const positiveRow = resolveExecutedRow(
      targetDomain,
      { ledger: SUPPORTED_LEDGER_OFFENSIVE_RUNS, row_id: record.positive_run_id },
      verifier,
      "positive",
    );
    const controlRow = resolveExecutedRow(
      targetDomain,
      { ledger: SUPPORTED_LEDGER_OFFENSIVE_RUNS, row_id: record.control_run_id },
      verifier,
      "control",
    );
    if (positiveRow.run_id === controlRow.run_id) {
      // A single run never flips against itself.
      return { ok: false, surface_id: null, demonstrated_severity: null };
    }
    // Bind the differential to the POSITIVE ROW's own surface — derived from signed
    // bytes, not from the verdict record. adjudicateFindingDifferential additionally
    // requires the control row to share it, so a forged record cannot relabel the surface.
    const boundSurface = typeof positiveRow.surface_id === "string" ? positiveRow.surface_id.trim() : "";
    const { result } = adjudicateFindingDifferential({
      surfaceId: boundSurface,
      positiveRow,
      controlRow,
    });
    return {
      ok: result === RESULT_VERIFIED_PASS,
      surface_id: boundSurface || null,
      demonstrated_severity: typeof positiveRow.demonstrated_severity === "string"
        ? positiveRow.demonstrated_severity
        : null,
      // Whether the RE-RESOLVED positive offensive row was executed in a
      // filesystem-namespace container. Re-resolved from the MAC-covered positive row;
      // absence reads false (fail-closed un-isolated at the verdict gate). HIGH-1
      // belt-and-suspenders: an SC finding-differential-backed reportable whose backing
      // run was not containerized must not be trusted on an isolated box.
      container_isolated: positiveRow.container_isolated === true,
    };
  } catch {
    // Missing / duplicate / foreign-MAC / dry-run / timed-out row, or an absent key →
    // the flip is not re-derivable from signed bytes. Fail closed.
    return { ok: false, surface_id: null, demonstrated_severity: null, container_isolated: false };
  }
}

// readFindingDifferentialVerifiedSummary — the AUTHORITATIVE standalone-class confirm
// signal, mirroring readReproVerifiedSummary / readInvariantVerifiedSummary. Reads the
// MCP-write-only, audit-graded finding-differential-verified.jsonl from disk only; a
// verified_pass cannot be hand-forged (the path is agent-Write-blocked) — only
// verifyFindingDifferential mints it. The grade-time gate reads verified_by_finding.
//
// READ-TIME RE-DERIVATION (A1): each verified_pass record is RE-RESOLVED + RE-ADJUDICATED
// from the MAC-covered offensive-runs rows it cites (reverifyFindingDifferentialRecord).
// A finding is included in verified_by_finding ONLY when ok===true, and its surface_id +
// demonstrated_severity come FROM THE RE-RESOLVED POSITIVE ROW (signed source data), not
// the verdict record's self-hashed fields. This closes the direct-disk forge: a bare
// forged verdict line whose run_ids don't resolve to two MAC-valid flipping rows is
// excluded here, before the grade-time surface-bind + severity-ceiling read it.
function readFindingDifferentialVerifiedSummary(domain) {
  const targetDomain = assertSafeDomain(domain);
  const records = readRecords(targetDomain);
  const verified = records.filter((r) => r.result === RESULT_VERIFIED_PASS);
  const verifiedByFinding = {};
  for (const r of verified) {
    const rederived = reverifyFindingDifferentialRecord(targetDomain, r);
    if (!rederived.ok) continue;
    verifiedByFinding[r.finding_id] = {
      positive_row_hash: r.positive_row_hash,
      control_row_hash: r.control_row_hash,
      // From the MAC-covered positive row, NOT the verdict record's stored fields.
      surface_id: rederived.surface_id,
      demonstrated_severity: rederived.demonstrated_severity,
      // Whether the RE-RESOLVED positive offensive row was containerized, mirroring
      // readInvariantVerifiedSummary. The verdict gate's SC-containerization consult
      // (sandbox-isolation-gate.js scBackingUnIsolatedFindingIds) treats a
      // finding-differential-backed SC reportable whose backing run was NOT
      // containerized as un-isolated. False on every existing offensive row (the field
      // is not minted there yet) — the correct fail-closed posture.
      container_isolated: rederived.container_isolated === true,
    };
  }
  return {
    total_runs: records.length,
    verified_pass_count: verified.length,
    refuted_count: records.filter((r) => r.result === RESULT_REFUTED).length,
    inconclusive_count: records.filter((r) => r.result === RESULT_INCONCLUSIVE).length,
    // finding_id -> the RE-DERIVED bound surface + demonstrated_severity + run hashes,
    // for the grade-time gate to require a verified_pass bound to THIS finding
    // (LEDGER-BY-ID) AND to enforce the surface bind + severity ceiling off MAC source.
    verified_by_finding: verifiedByFinding,
  };
}

module.exports = {
  FINDING_DIFFERENTIAL_VERIFIED_VERSION,
  FINDING_DIFFERENTIAL_VERIFIED_MAX_RECORDS,
  RESULT_VERIFIED_PASS,
  RESULT_REFUTED,
  RESULT_INCONCLUSIVE,
  offensiveRowHash,
  adjudicateFindingDifferential,
  verifyFindingDifferential,
  reverifyFindingDifferentialRecord,
  readFindingDifferentialVerifiedSummary,
};
