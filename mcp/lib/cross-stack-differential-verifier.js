"use strict";

// Cross-stack differential bind-path — the SECOND verification kind alongside the
// object-auth guard RE-EXECUTE path. A bind leaf carries positive_run_ref +
// control_run_ref (BOTH invariant_runs rows: the EFFECT stack) AND a required
// cause_run_ref (an offensive_runs row: the stack-A CAUSE), pointing at ALREADY-
// EXECUTED, MAC-signed rows. This verifier BINDS those rows — it does NOT re-execute
// them — generalizing the single-surface invariant-differential to a cross-SURFACE
// CAUSE/EFFECT differential.
//
// THE CAUSAL MODEL — the CONSUMED-ARTIFACT is the controlled variable. A cross-stack vuln
// is causal: a CAUSE on stack A (a web offensive run that exploited_safely) produces an
// EFFECT on stack B (an EVM invariant violation). The non-forgeable witness is the EFFECT
// measured under TWO conditions that differ ONLY in the controlled variable — the PRESENCE
// of the web-captured artifact, ON THE SAME TREE — PLUS the CAUSE bound to the violated arm:
//   * positive arm = an invariant_runs row, VIOLATED, on the target tree, that CONSUMED the
//                    web-captured artifact (consumed_artifact_hash non-null, bound to the
//                    cause).
//   * control arm  = the SAME invariant test (template_id, contract_name, function_name,
//                    execution_context_hash, slot_values ALL MATCH — ported byte-for-byte
//                    from verifyInvariantDifferential) on the SAME tree/checkout, HELD,
//                    that ran ARTIFACT-ABSENT (consumed_artifact_hash null). The ONLY
//                    difference between the two arms is the consumed artifact, so the
//                    violation is provably CONTINGENT on consuming it.
//   * the CAUSE    = an offensive_runs row that exploited_safely on stack A, carried in
//                    cause_run_ref and NAMED by the violated arm's MAC-covered
//                    cause_run_id (the causal link).
// The cross-stack-ness is the bound CAUSE resolving on a DIFFERENT stack than the
// effect arms: surface_refs = [effect-arm surface, cause surface], is_cross_stack iff
// those are distinct. A tree-only flip (different trees, no artifact differential) is NOT
// a cross-stack mint — it is a single-surface invariant differential
// (verifyInvariantDifferential's job) and is REFUSED on the cross-stack/bind path.
//
// THE FORGERY THIS DEFEATS (the F1 model bug). The prior adjudicator accepted a
// verified_pass from {positive demonstrates, control outcome differs, control isBlocked}
// over EITHER ledger, with the two arms NEVER bound to the same mechanism. So a real
// web IDOR (offensive exploited_safely) + a trivial passing invariant on an UNRELATED
// contract minted a "cross-stack flip" — a web outcome vs an unrelated EVM outcome,
// which is not a differential at all. The corrected model REFUSES that: both flip arms
// must be the SAME invariant test (violated vs held), and the web exploit is the bound
// CAUSE, never an arm.
//
// THE DEFENSE (the non-forgeability spine, every leg preserved):
//   BIND-DON'T-RE-EXECUTE   — every leg resolves to an already-executed MAC-signed row;
//                             agent prose is never trusted.
//   SAME-TEST EFFECT FLIP   — positive and control are the SAME invariant test on the SAME
//                             tree (5 same-test fields MATCH, tree/checkout MATCH); positive
//                             VIOLATED, control HELD. The consumed ARTIFACT presence is the
//                             controlled variable, NOT the tree. An unrelated control, a
//                             hash-identical control, or a DIFFERENT-tree flip is REFUSED — a
//                             tree-only flip is a single-surface invariant differential, not
//                             cross-stack causation, and routes to verifyInvariantDifferential.
//   BOUND CAUSE             — a flip is cross-stack-attributable ONLY when an offensive
//                             exploited_safely row is bound, the violated arm NAMES it
//                             (MAC-covered cause_run_id — necessary), AND the violated arm
//                             CONSUMED its captured artifact (the violated arm's MAC-
//                             covered consumed_artifact_hash == the cause's MAC-covered
//                             consumed_artifact_hash, with the control arm cause-free). The
//                             NAME is forgeable-by-coincidence; the CONSUMED-ARTIFACT
//                             binding is the sufficient proof that the EVM violation
//                             consumed the WEB capture, not merely named the run. A
//                             missing/non-demonstrating cause, a broken name link, or a
//                             missing/mismatched consumed-artifact binding -> REFUSED.
//   REAL CROSS-STACK SPAN   — verified_pass is GATED on is_cross_stack: the EFFECT
//                             (smart_contract invariant arm) and the route-resolved CAUSE
//                             stack family must be DIFFERENT KNOWN families. A same-family
//                             or unresolved-family flip is a single-surface differential,
//                             not a cross-stack causative flip -> REFUSED.
//   DISTINCT ROW-HASHES     — the effect arms have distinct executed-identity hashes.
//   STRICT MAC ON EVERY ROW — every resolved row verifies its ledger's keyed MAC under a
//                             STRICT gate (assertRowMac — an unsigned/legacy row is
//                             REJECTED, never accepted-with-warning) before any field is
//                             read.
//   FLIP FROM EXECUTED NAMES— the flip is adjudicated from the EXECUTED outcome names
//                             each ledger records (classifyFoundryViolation,
//                             offensive_outcome), never a hardcoded predicate.
//   OPEN-VOCAB EDGE_TYPE    — edge_type is shape-validated only (any non-empty string);
//                             it annotates the bind, it never gates it.
//   LEDGER-BY-ID            — the verified_pass is appended ONLY to the MCP-write-only,
//                             audit-graded composition-verified.jsonl keyed by the
//                             EXECUTION-keyed identity; no frontier event is emitted.
//   READ-TIME RE-VERIFY     — at read time all THREE rows are RE-RESOLVED (MAC-verified)
//                             and the flip + causal link are RE-ADJUDICATED from signed
//                             source bytes; the path_hash enters verified_path_hashes[]
//                             only when ok.

const {
  hashCanonicalJson,
} = require("./verification-contracts.js");
const {
  verifyRowWithMac,
  assertRowMac,
  OFFENSIVE_ROW_MAC_CONTEXT,
  INVARIANT_RUN_MAC_CONTEXT,
} = require("./offensive-row-mac.js");
const {
  resolveOffensiveRowVerifier,
  resolveRowVerifierSafely,
} = require("./handoff-signing-key.js");
const {
  readOffensiveRunRecords,
} = require("./claims.js");
const {
  offensiveRowHash,
} = require("./finding-differential-verifier.js");
const {
  readInvariantRunCorpus,
  readInvariantRunRowForVerification,
  classifyFoundryViolation,
} = require("./invariant-runner.js");

// A 64-hex content hash gate (the shape consumed_artifact_hash / stdout_hash carry,
// identical to the runner's injection-side gate). Returns the lowercased hex or null.
function hex64OrNull(value) {
  if (typeof value !== "string") return null;
  const v = value.trim().toLowerCase();
  return /^[0-9a-f]{64}$/.test(v) ? v : null;
}

function nonEmptyTrim(value) {
  if (typeof value !== "string") return null;
  const v = value.trim();
  return v ? v : null;
}

// The set of executed-row ledgers a bind leaf may cite. The schema enum on the tool
// is a convenience; THIS resolver table is the real authority. offensive_runs and
// invariant_runs are the two supported ledgers — web (offensive HTTP) and the EVM /
// SC-FV invariant arm — so the cross-stack bind is not web-only. repo_command_runs
// (native repro) is a re-execute model whose flip lives in its verdict, not a per-row
// disposition field; binding it is a documented later follow-up, so an unsupported
// ledger string resolves to no entry (REFUSED), never a silent pass.
const LEDGER_OFFENSIVE_RUNS = "offensive_runs";
const LEDGER_INVARIANT_RUNS = "invariant_runs";

// The positive must DEMONSTRATE the mechanism; the control must be a non-demonstrating
// (blocked / held) row. blocked_by_infra is transport/infra noise, NOT a safe-variant
// denial, so it is excluded — a transport hiccup must never mint a false control.
const OFFENSIVE_POSITIVE_OUTCOME = "exploited_safely";
const OFFENSIVE_CONTROL_BLOCKED_OUTCOMES = Object.freeze(new Set(["blocked_by_defense"]));
// The cross-stack consuming template id. Both flip arms (and the decoy arm) must be
// runs of this audited consuming template — the only corpus template whose body binds
// a captured cause. Asserting it on the read side mirrors the runner's mint-side guard.
const CROSS_STACK_CONSUME_TEMPLATE_ID = "INV-CROSS-STACK-AUTH-REPLAY-001";
// Invariant disposition: classifyFoundryViolation maps the executed Foundry outcome to
// violated / held / degraded. The positive must be "violated"; the control must be
// "held". "degraded" carries no signal (fork blocked / missing harness) -> inconclusive.
const INVARIANT_POSITIVE_DISPOSITION = "violated";
const INVARIANT_CONTROL_HELD_DISPOSITION = "held";

// A leaf is a BIND leaf iff it carries BOTH positive_run_ref AND control_run_ref
// (each a { ledger, row_id }). This shape is the dispatch key, not edge_type.
function isBindLeaf(leaf) {
  return (
    leaf != null &&
    typeof leaf === "object" &&
    leaf.positive_run_ref != null &&
    typeof leaf.positive_run_ref === "object" &&
    leaf.control_run_ref != null &&
    typeof leaf.control_run_ref === "object"
  );
}

function isShapeValidEdgeType(value) {
  return typeof value === "string" && value.length > 0;
}

// --- per-ledger resolver table -------------------------------------------------------
//
// Each entry exposes a UNIFORM { resolveRow, identityHash, demonstrates, isBlocked,
// surfaceRef, severity } so the cross-stack adjudicator is ledger-polymorphic and
// mechanism-agnostic. resolveRow MAC-verifies the row (throws on a missing / present-
// but-invalid / dry-run / timed-out / degraded row); identityHash is the distinct-
// identity hash; demonstrates/isBlocked read the EXECUTED disposition (never a
// predicate name); surfaceRef yields the row's cross-stack surface binding.

function resolveOffensiveBindRow(domain, rowId, ctx) {
  if (typeof rowId !== "string" || !rowId) {
    throw new Error("offensive_runs row_id (the executed run_id) is required");
  }
  const rows = ctx.offensiveRows || readOffensiveRunRecords(domain);
  const matches = rows.filter((r) => r && r.run_id === rowId);
  if (matches.length === 0) throw new Error(`offensive_runs row_id does not resolve: ${rowId}`);
  if (matches.length > 1) throw new Error(`offensive_runs row_id matches more than one row (corrupt ledger): ${rowId}`);
  const row = matches[0];
  const verifier = ctx.offensiveVerifier || resolveOffensiveRowVerifier(domain);
  // STRICT MAC (F2): reject an unsigned row, never accept-with-warning. An offensive
  // row feeding a verified_pass (positive OR cause arm) MUST carry a real signature.
  // verifyRowWithMac already returns false for an absent envelope, so this is the
  // same guarantee the offensive arm always had; assertRowMac makes the unsigned-vs-
  // present-but-bad distinction explicit and parallel to the invariant arm below.
  if (!verifyRowWithMac(OFFENSIVE_ROW_MAC_CONTEXT, row, verifier)) {
    throw new Error(`offensive_runs row_id is not a validly MAC-signed row: ${rowId}`);
  }
  if (row.dry_run !== false) throw new Error(`offensive_runs row_id is a dry-run row: ${rowId}`);
  if (row.timed_out !== false) throw new Error(`offensive_runs row_id timed out: ${rowId}`);
  return row;
}

const OFFENSIVE_LEDGER_ENTRY = Object.freeze({
  ledger: LEDGER_OFFENSIVE_RUNS,
  resolveRow: resolveOffensiveBindRow,
  identityHash: (row) => offensiveRowHash(row),
  demonstrates: (row) => row.offensive_outcome === OFFENSIVE_POSITIVE_OUTCOME,
  isBlocked: (row) => OFFENSIVE_CONTROL_BLOCKED_OUTCOMES.has(row.offensive_outcome),
  outcomeName: (row) => (typeof row.offensive_outcome === "string" ? row.offensive_outcome : null),
  // Offensive rows carry surface_id directly; the cross-stack surface ref is that id.
  surfaceRef: (row) => (typeof row.surface_id === "string" && row.surface_id.trim() ? `offensive:${row.surface_id.trim()}` : null),
  severity: (row) => (typeof row.demonstrated_severity === "string" ? row.demonstrated_severity : null),
  containerIsolated: (row) => row.container_isolated === true,
  rowKey: (row) => row.run_id,
  // The MAC-covered consumable-artifact binding (O-A): sha256 of the bytes the on-chain
  // side will consume, or null for a web-only finding that captured no consumable. It is
  // INSIDE the row_mac (offensive-capture-writer.js RESERVED_ROW_KEYS), so reading it off
  // a STRICT-MAC-verified row is reading a signed value. The cross-stack adjudicator binds
  // the violated invariant arm's consumed_artifact_hash to THIS hash (the consumed-artifact
  // binding that proves the EVM violation actually consumed the web capture, not merely
  // named the run).
  consumedArtifactHash: (row) => hex64OrNull(row.consumed_artifact_hash),
  // The MAC-covered DECOY marker (a sibling of consumed_artifact_hash). A decoy capture
  // carries is_decoy:true + random consumed bytes + a blocked_by_defense outcome, so it
  // is never the positive cause leg but is the random-bytes arm the cross-stack
  // adjudicator requires to HOLD. Reading it off the STRICT-MAC-verified row is reading
  // a signed value; absence reads false (a genuine cause is not a decoy).
  isDecoy: (row) => row.is_decoy === true,
});

function resolveInvariantBindRow(domain, rowId, ctx) {
  if (typeof rowId !== "string" || !rowId) {
    throw new Error("invariant_runs row_id (the executed run_hash) is required");
  }
  const corpus = ctx.invariantCorpus || readInvariantRunCorpus({ target_domain: domain });
  const rows = Array.isArray(corpus.runs) ? corpus.runs : [];
  // Resolve the candidate row first to recover its OWN finding_id, so the bind is
  // path-keyed not finding-keyed: readInvariantRunRowForVerification asserts the row's
  // finding_id equals the expected one, so we feed it the row's own finding_id (a
  // findingId-agnostic resolution that still runs the full content-hash + MAC re-check).
  const candidate = rows.filter((r) => r && typeof r.run_hash === "string" && r.run_hash.toLowerCase() === rowId.toLowerCase());
  if (candidate.length === 0) throw new Error(`invariant_runs row_id does not resolve: ${rowId}`);
  const ownFindingId = candidate[0].finding_id;
  if (ownFindingId == null) throw new Error(`invariant_runs row_id has no finding_id: ${rowId}`);
  const verifier = ctx.invariantVerifier !== undefined ? ctx.invariantVerifier : resolveRowVerifierSafely(domain);
  // readInvariantRunRowForVerification re-derives computeInvariantRunHash, re-binds the
  // foundry_result hash + outcome, and asserts the keyed MAC (assertRowMacOrLegacy under
  // INVARIANT_RUN_MAC_CONTEXT). A present-but-invalid MAC, a content-hash mismatch, or a
  // dry-run row throws -> the bind REFUSES this leg.
  const row = readInvariantRunRowForVerification(rows, rowId, "invariant_run_ref", ownFindingId, verifier);
  // STRICT MAC (F2a): readInvariantRunRowForVerification accepts an UNSIGNED row with a
  // warning (assertRowMacOrLegacy -> {legacy:true}) because invariant-runs.jsonl was for a
  // window only best-effort hook-blocked, so a same-uid agent could append an unsigned row.
  // A row feeding a NON-FORGEABLE cross-stack verified_pass cannot be legacy: re-assert
  // STRICTLY here (a SECOND gate, on top of the content-hash re-derivation), so an
  // unsigned/legacy invariant row is REFUSED at the cross-stack bind even though it stays
  // accept-with-warning at the general FV read sites.
  assertRowMac(INVARIANT_RUN_MAC_CONTEXT, row, verifier);
  return row;
}

const INVARIANT_LEDGER_ENTRY = Object.freeze({
  ledger: LEDGER_INVARIANT_RUNS,
  resolveRow: resolveInvariantBindRow,
  // run_hash IS the distinct executed identity (binds the 12 hash-covered fields incl.
  // tree_ref). Two rows on different trees have different run_hash; a control hash-
  // identical to the positive is REFUSED on this hash.
  identityHash: (row) => row.run_hash,
  demonstrates: (row) => classifyFoundryViolation(row.foundry_result) === INVARIANT_POSITIVE_DISPOSITION,
  isBlocked: (row) => classifyFoundryViolation(row.foundry_result) === INVARIANT_CONTROL_HELD_DISPOSITION,
  outcomeName: (row) => classifyFoundryViolation(row.foundry_result),
  // The invariant arm has no surface_id; its cross-stack surface ref is the finding +
  // contract binding (the surface the invariant arm proves on).
  surfaceRef: (row) => {
    const finding = row.finding_id != null ? String(row.finding_id) : null;
    const contract = typeof row.contract_name === "string" && row.contract_name ? row.contract_name : null;
    if (!finding && !contract) return null;
    return `invariant:${finding || "?"}:${contract || "?"}`;
  },
  severity: () => null,
  containerIsolated: (row) => row.container_isolated === true,
  rowKey: (row) => row.run_hash,
  // The MAC-covered causal link: the offensive run_id whose state the violated arm
  // executed against (null on a held control / a cause-free run). Read by the
  // adjudicator's causal-link check; it is INSIDE the row_mac (a sibling of
  // container_isolated), so an agent cannot re-point the violated arm at a different
  // cause without invalidating the row's signature.
  causeRunId: (row) => (typeof row.cause_run_id === "string" && row.cause_run_id.trim() ? row.cause_run_id.trim() : null),
  // The MAC-covered CONSUMED-ARTIFACT binding (O-A): sha256 of the bytes THIS invariant
  // run actually consumed (injected as BOB_CONSUMED_ARTIFACT), or null on a cause-free
  // control. It is a top-level SIBLING outside computeInvariantRunHash but INSIDE the
  // row_mac, so reading it off a STRICT-MAC-verified row is reading a signed value. The
  // O-B consumed-artifact binding requires the VIOLATED arm's consumed_artifact_hash to
  // equal the named cause offensive row's consumed_artifact_hash (proven-not-named).
  consumedArtifactHash: (row) => hex64OrNull(row.consumed_artifact_hash),
  // An invariant arm is never a decoy CAPTURE (the decoy is an offensive-runs row);
  // false keeps resolveBindRef uniform across ledgers.
  isDecoy: () => false,
});

const LEDGER_TABLE = Object.freeze(new Map([
  [LEDGER_OFFENSIVE_RUNS, OFFENSIVE_LEDGER_ENTRY],
  [LEDGER_INVARIANT_RUNS, INVARIANT_LEDGER_ENTRY],
]));

function lookupLedgerEntry(ledger) {
  if (typeof ledger !== "string" || !ledger) return null;
  return LEDGER_TABLE.get(ledger) || null;
}

// Resolve one { ledger, row_id } ref to its { entry, row, identity, outcome, surfaceRef,
// severity, containerIsolated }. Throws on an unsupported ledger / unresolvable / MAC-
// failing / non-executed row (the caller maps the throw to a refusal).
function resolveBindRef(domain, ref, ctx, label) {
  if (ref == null || typeof ref !== "object") {
    throw new Error(`${label}_run_ref must be an object { ledger, row_id }`);
  }
  const entry = lookupLedgerEntry(ref.ledger);
  if (!entry) {
    throw new Error(
      `${label}_run_ref.ledger must be one of [${[...LEDGER_TABLE.keys()].join(", ")}]; got ${ref.ledger}`,
    );
  }
  const row = entry.resolveRow(domain, ref.row_id, ctx);
  return {
    entry,
    row,
    identity: entry.identityHash(row),
    outcome: entry.outcomeName(row),
    surfaceRef: entry.surfaceRef(row),
    severity: entry.severity(row),
    containerIsolated: entry.containerIsolated(row),
    rowKey: entry.rowKey(row),
    // The MAC-covered consumed-artifact hash (signed, re-derived off the STRICT-MAC row).
    // On an offensive cause leg it is what the capture pinned; on an invariant arm it is
    // what that run actually consumed. The adjudicator binds these (O-B sufficient proof).
    consumedArtifactHash: typeof entry.consumedArtifactHash === "function" ? entry.consumedArtifactHash(row) : null,
    // The MAC-covered decoy marker (offensive cause/decoy leg only; false elsewhere).
    isDecoy: typeof entry.isDecoy === "function" ? entry.isDecoy(row) : false,
  };
}

// The SAME-TEST fields a cross-stack effect flip's positive and control arms must MATCH
// (ported from verifyInvariantDifferential's binding): a control that differs on any of
// these is provably a DIFFERENT invariant test, not the SAME test with the artifact removed,
// so it is refused. finding_id is restored at the head (MEDIUM-1): the two flip arms
// must be the SAME finding — a "control" arm from an unrelated finding that happens to
// share template/contract/function/exec-ctx is no longer a valid negative control.
const SAME_TEST_SCALAR_FIELDS = Object.freeze([
  "finding_id",
  "template_id",
  "contract_name",
  "function_name",
  "execution_context_hash",
]);

// The violated (positive) effect arm must NAME the bound cause. cause_run_id is the
// MAC-covered sibling on the invariant row (set only on a violated, cause-consuming
// run); the cause leg's offensive run_id is the row's run_id. The NAME link is NECESSARY
// (no name => no causal link) but NOT SUFFICIENT — naming is forgeable-by-coincidence (an
// EVM author can set cause_run_id to a real web run without that run's bytes ever entering
// the foundry subprocess). The CONSUMED-ARTIFACT binding below is the sufficient proof.
function violatedArmNamesCause(violatedRow, causeRow) {
  const named = nonEmptyTrim(violatedRow.cause_run_id);
  const causeId = causeRow && typeof causeRow.run_id === "string" ? causeRow.run_id : null;
  return named != null && causeId != null && named === causeId;
}

// The CONSUMED-ARTIFACT BINDING — the O-B sufficient proof that the EVM violation actually
// CONSUMED the web-captured artifact, replacing the name-only string equality. Cross-stack
// causation is NAMED-not-PROVEN by the name check alone: a real web exploit + a real same-
// test EVM flip on an UNRELATED contract that merely NAMES the web run would falsely chain
// (and survives Mechanism A — all three rows are genuinely signed). The binding closes it.
//
// REFUSE-FIRST, all four conditions over the resolved legs:
//   (precondition) the violated arm NAMES this exact cause (kept — necessary).
//   (a) the violated arm's consumed_artifact_hash is NON-NULL — it actually consumed bytes.
//   (c) the named cause offensive row HAS a captured artifact (consumed_artifact_hash non-
//       null), re-derived from the MAC-VERIFIED cause row.
//   (b) the violated arm's consumed_artifact_hash EQUALS the cause's captured-artifact hash
//       (the EVM violation consumed the EXACT bytes the web attack captured).
//   (d) the CONTROL arm did NOT consume it (consumed_artifact_hash null) — it ran cause-
//       free, so the artifact PRESENCE is the controlled variable.
// All three rows reach this function already STRICT-MAC-verified (resolveOffensiveBindRow /
// resolveInvariantBindRow), so reading their consumed_artifact_hash is reading SIGNED
// values; a forger cannot set the invariant row's consumed_artifact_hash to the cause's
// without invalidating its MAC (only the runner's injection path mints it, by re-hashing
// the on-disk bytes). leg objects are { row, consumedArtifactHash, ... }.
//
// opts.refetchCause (read-time only): also re-fetch the cause's stored bytes and assert
// they STILL hash to the cause row's signed consumed_artifact_hash. The mint path leaves
// this off (the two signed hashes already reconcile — byte-cheap); the reverify path sets
// it true so a post-mint swap of the .consumed leaf is caught at read time.
function violatedArmConsumedCause(violatedLeg, controlLeg, causeLeg, opts = {}) {
  const violatedRow = violatedLeg.row;
  const controlRow = controlLeg.row;
  const causeRow = causeLeg.row;
  // (precondition) NAME link — necessary, never sufficient.
  if (!violatedArmNamesCause(violatedRow, causeRow)) {
    return { ok: false, reason: "the violated invariant run does not bind this cause run (no causal link)" };
  }
  // (a) the violated arm consumed SOMETHING.
  const consumed = violatedLeg.consumedArtifactHash;
  if (consumed == null) {
    return { ok: false, reason: "the violated invariant run consumed no artifact (consumed_artifact_hash null) — the named cause's bytes never entered the effect run" };
  }
  // (c) the cause CAPTURED a consumable artifact (re-derived from the MAC-verified row).
  const causeHash = causeLeg.consumedArtifactHash;
  if (causeHash == null) {
    return { ok: false, reason: "the named cause captured no consumable artifact (consumed_artifact_hash null) — there is nothing to consume" };
  }
  // (b) the violated arm consumed the EXACT bytes the cause captured.
  if (consumed !== causeHash) {
    return { ok: false, reason: "the violated arm consumed a different artifact than the cause captured (consumed_artifact_hash mismatch) — named but not consumed" };
  }
  // (d) the control arm ran cause-free.
  const controlConsumed = controlLeg.consumedArtifactHash;
  if (controlConsumed != null) {
    return { ok: false, reason: "the control arm also consumed an artifact (consumed_artifact_hash non-null) — it did not run cause-free, so the artifact is not the controlled variable" };
  }
  // (read-time) re-fetch the cause bytes and re-confirm they still hash to the signed
  // cause hash (catches a post-mint swap of the .consumed leaf). The byte-reader applies
  // the same realpath/O_NOFOLLOW/nlink discipline as the runner's injection-side fetch.
  if (opts.refetchCause === true) {
    const runId = causeRow && typeof causeRow.run_id === "string" ? causeRow.run_id : null;
    if (runId == null) {
      return { ok: false, reason: "cannot re-fetch cause bytes: cause row has no run_id" };
    }
    let fetched = null;
    try {
      // eslint-disable-next-line global-require
      const { readOffensiveCaptureBytesSecure } = require("./claim-freeze.js");
      fetched = readOffensiveCaptureBytesSecure(opts.domain, runId, "consumed");
    } catch {
      fetched = null;
    }
    if (fetched == null || hex64OrNull(fetched.sha256) !== causeHash) {
      return { ok: false, reason: "the cause's stored consumable bytes no longer hash to its MAC-covered consumed_artifact_hash (read-time integrity failure)" };
    }
  }
  return { ok: true };
}

// The DECOY-ARM CONSUMED-DECOY BINDING — the artifact-RELEVANCE proof. The positive/
// control differential proves the gate reacts to SOMETHING present, not that it validates
// THESE bytes: a gate `require(auth.length>0)` passes present->violate / absent->hold while
// the artifact is irrelevant. The decoy arm closes that. The decoy is a DISTINCT MAC-bound
// capture of RANDOM bytes (is_decoy:true, NOT the real cause), injected into the SAME test
// on the SAME tree. A gate that validates the SPECIFIC credential bytes REJECTS the random
// decoy -> the decoy arm HOLDS. A tautological / any-non-empty gate ACCEPTS the decoy ->
// the decoy arm VIOLATES -> no flip -> REFUSED. So requiring decoy->HOLD structurally
// forces the gate to validate the specific bytes = the artifact is the REAL causal input.
//
// REFUSE-FIRST over the resolved legs (decoyArmLeg = the invariant arm run with the decoy
// bytes; decoyCaptureLeg = the offensive is_decoy capture row):
//   (precondition) the decoy CAPTURE is a real signed offensive row marked is_decoy:true
//       (so it is provably NOT the real cause and cannot stand in for it).
//   (precondition) the decoy ARM NAMES the decoy capture (cause_run_id == decoy run_id).
//   (a) the decoy arm CONSUMED something (consumed_artifact_hash non-null).
//   (c) the decoy capture HAS captured bytes (consumed_artifact_hash non-null).
//   (b) the decoy arm consumed the EXACT decoy bytes (hashes equal).
//   (d) the decoy bytes are DISTINCT from the real cause's bytes (the decoy is not the
//       cause re-labeled) — different consumed_artifact_hash than the violated arm.
//   (SHAPE PARITY) the decoy capture bytes have the SAME byte length as the cause capture
//       bytes (always) AND the SAME encoding class when one is derivable (raw/hex/base64/
//       json/jwt). A gate that flips the decoy to HOLD by rejecting "wrong length / wrong
//       shape" can no longer distinguish it from the cause — to hold the decoy it MUST
//       validate the byte CONTENT. The decoy and cause bytes are read off the SIGNED rows'
//       MAC-covered hashes (each fetched-and-re-hashed), so the shape an agent presents is
//       the shape it captured. A wrong-shape decoy (e.g. 32 random bytes against a 900-byte
//       JSON cause) is REFUSED here.
//   (HOLD) the decoy ARM is BLOCKED (the gate rejected the random bytes) — enforced by the
//       adjudicator's isBlocked check on the decoy arm; this function binds the bytes.
// All rows reach this already STRICT-MAC-verified, so reading their fields is reading SIGNED
// values. The shape-parity binding fetches BOTH the decoy capture's and the cause's stored
// bytes (re-hashing each to its signed hash). opts.refetchCause additionally re-confirms the
// decoy capture bytes hash to the signed decoy capture hash. causeLeg is the resolved
// offensive CAUSE leg (its run_id names the cause capture whose shape the decoy must match).
function decoyArmConsumedDecoy(decoyArmLeg, decoyCaptureLeg, violatedLeg, causeLeg, opts = {}) {
  const decoyArmRow = decoyArmLeg.row;
  const decoyCaptureRow = decoyCaptureLeg.row;
  // (precondition) the capture is a REAL decoy, never the cause re-pointed.
  if (decoyCaptureLeg.isDecoy !== true) {
    return { ok: false, reason: "the bound decoy capture is not marked is_decoy (a decoy must be a distinct random-bytes capture, never the real cause)" };
  }
  // (precondition) the decoy arm NAMES the decoy capture.
  const named = nonEmptyTrim(decoyArmRow.cause_run_id);
  const decoyId = decoyCaptureRow && typeof decoyCaptureRow.run_id === "string" ? decoyCaptureRow.run_id : null;
  if (named == null || decoyId == null || named !== decoyId) {
    return { ok: false, reason: "the decoy invariant arm does not bind the decoy capture (no decoy causal link)" };
  }
  // (a) the decoy arm consumed SOMETHING.
  const armConsumed = decoyArmLeg.consumedArtifactHash;
  if (armConsumed == null) {
    return { ok: false, reason: "the decoy invariant arm consumed no artifact (consumed_artifact_hash null) — the decoy bytes never entered the decoy run" };
  }
  // (c) the decoy capture CAPTURED bytes.
  const decoyHash = decoyCaptureLeg.consumedArtifactHash;
  if (decoyHash == null) {
    return { ok: false, reason: "the decoy capture has no consumable bytes (consumed_artifact_hash null)" };
  }
  // (b) the decoy arm consumed the EXACT decoy bytes.
  if (armConsumed !== decoyHash) {
    return { ok: false, reason: "the decoy arm consumed a different artifact than the decoy captured (consumed_artifact_hash mismatch)" };
  }
  // (d) the decoy bytes are DISTINCT from the real cause's bytes.
  const causeConsumed = violatedLeg.consumedArtifactHash;
  if (causeConsumed != null && armConsumed === causeConsumed) {
    return { ok: false, reason: "the decoy bytes are identical to the real cause bytes (a decoy must be RANDOM bytes distinct from the captured credential)" };
  }
  // (read-time) re-fetch the decoy capture bytes and re-confirm they still hash.
  if (opts.refetchCause === true) {
    const runId = decoyCaptureRow && typeof decoyCaptureRow.run_id === "string" ? decoyCaptureRow.run_id : null;
    if (runId == null) {
      return { ok: false, reason: "cannot re-fetch decoy bytes: decoy capture row has no run_id" };
    }
    let fetched = null;
    try {
      // eslint-disable-next-line global-require
      const { readOffensiveCaptureBytesSecure } = require("./claim-freeze.js");
      fetched = readOffensiveCaptureBytesSecure(opts.domain, runId, "consumed");
    } catch {
      fetched = null;
    }
    if (fetched == null || hex64OrNull(fetched.sha256) !== decoyHash) {
      return { ok: false, reason: "the decoy capture's stored bytes no longer hash to its MAC-covered consumed_artifact_hash (read-time integrity failure)" };
    }
  }
  // (SHAPE PARITY) the decoy must be the SAME SHAPE as the cause (byte length always;
  // encoding class when derivable), random content. This forecloses the shape-distinguishing
  // gate: a contract that flips the decoy to HOLD by rejecting "wrong length / not-JWT-shaped"
  // can no longer tell the decoy from the cause, so holding it REQUIRES validating content.
  // Bind off the SIGNED rows' captures: fetch the decoy capture bytes and the real cause
  // capture bytes, re-hash each to its MAC-covered consumed_artifact_hash, and compare shape.
  const shapeParity = decoyShapeMatchesCause(decoyCaptureLeg, causeLeg, opts);
  if (!shapeParity.ok) {
    return shapeParity;
  }
  return { ok: true };
}

// decoyShapeMatchesCause — bind the decoy capture's SHAPE to the cause capture's SHAPE off
// the SIGNED rows. Reads BOTH .consumed leaves under the secure byte reader, re-hashes each
// to its row's MAC-covered consumed_artifact_hash (so the bytes are the ones the signed row
// captured, not a swapped leaf), then asserts SAME byte length (always) and SAME encoding
// class when one is derivable (raw -> length-only). A null/unreadable/hash-mismatched
// capture fails closed (no parity = no verified_pass). domain is read from opts (the byte
// reader is domain-scoped).
function decoyShapeMatchesCause(decoyCaptureLeg, causeLeg, opts = {}) {
  const decoyRow = decoyCaptureLeg && decoyCaptureLeg.row;
  const causeRow = causeLeg && causeLeg.row;
  const decoyRunId = decoyRow && typeof decoyRow.run_id === "string" ? decoyRow.run_id : null;
  const causeRunId = causeRow && typeof causeRow.run_id === "string" ? causeRow.run_id : null;
  const decoySignedHash = decoyCaptureLeg && decoyCaptureLeg.consumedArtifactHash;
  const causeSignedHash = causeLeg && causeLeg.consumedArtifactHash;
  if (decoyRunId == null || causeRunId == null || decoySignedHash == null || causeSignedHash == null) {
    return { ok: false, reason: "decoy shape-parity: cannot resolve the decoy/cause capture identities (missing run_id or signed consumed_artifact_hash)" };
  }
  let readBytes;
  let classify;
  try {
    // eslint-disable-next-line global-require
    ({ readOffensiveCaptureBytesSecure: readBytes } = require("./claim-freeze.js"));
    // eslint-disable-next-line global-require
    ({ classifyConsumableShape: classify } = require("./consumable-shape.js"));
  } catch {
    return { ok: false, reason: "decoy shape-parity: shape classifier unavailable" };
  }
  const decoyFetched = readBytes(opts.domain, decoyRunId, "consumed");
  if (decoyFetched == null || hex64OrNull(decoyFetched.sha256) !== decoySignedHash) {
    return { ok: false, reason: "decoy shape-parity: the decoy capture bytes do not hash to its MAC-covered consumed_artifact_hash" };
  }
  const causeFetched = readBytes(opts.domain, causeRunId, "consumed");
  if (causeFetched == null || hex64OrNull(causeFetched.sha256) !== causeSignedHash) {
    return { ok: false, reason: "decoy shape-parity: the cause capture bytes do not hash to its MAC-covered consumed_artifact_hash" };
  }
  if (decoyFetched.bytes.length !== causeFetched.bytes.length) {
    return { ok: false, reason: `decoy shape-parity: the decoy is ${decoyFetched.bytes.length} bytes but the cause is ${causeFetched.bytes.length} bytes — a shape-distinguishing gate could reject the decoy by length WITHOUT validating content; the decoy must be minted from the cause (same length, random content)` };
  }
  const decoyClass = classify(decoyFetched.bytes);
  const causeClass = classify(causeFetched.bytes);
  // Encoding-class binding when the cause has a derivable structured class. For a raw cause
  // (no derivable structure) the byte-length check above is the binding ("at minimum byte-
  // length; encoding-class if derivable").
  if (causeClass !== "raw" && decoyClass !== causeClass) {
    return { ok: false, reason: `decoy shape-parity: the cause is encoding-class '${causeClass}' but the decoy is '${decoyClass}' — a shape-distinguishing gate could reject the decoy by shape WITHOUT validating content; the decoy must match the cause's encoding class` };
  }
  return { ok: true };
}

// Cause finding-scoping. The cause is resolved from ALL offensive rows by run_id, so a
// cross-finding cause whose captured bytes coincidentally hash the same could still bind.
// Scope the cause to the SAME finding as the effect: the effect finding_id is on the
// invariant positive row; the cause's surface_id must belong to that finding's claim
// surface set. This catches an ACCIDENTAL cross-finding bind (a cause from an unrelated
// finding), NOT an adversary: the agent authors the claim whose surface_ids this checks
// against, so a determined forger can list the cause surface in its own claim and satisfy
// it. The non-forgeable proof is the consumed-artifact + decoy + container-isolation legs;
// this is hygiene, adding no forgery resistance. This RESOLVER stays a pure predicate
// returning { available, inFinding };
// the INTERPRETATION lives at the adjudicator's verified_pass gate, which now HARD-FAILS
// CLOSED — a cross-stack reportable mint requires available && inFinding, so an
// indeterminate map (no claim, empty surface_ids, unreadable, or null finding/cause
// surface) refuses rather than falling back. Resolved lazily from claims.js (already
// required at top level for readOffensiveRunRecords — no new cycle).
function causeWithinEffectFinding(effectFindingId, causeSurfaceId, domain) {
  if (effectFindingId == null || causeSurfaceId == null) return { available: false, inFinding: false };
  let claims;
  try {
    // eslint-disable-next-line global-require
    const { readCandidateClaims } = require("./claims.js");
    claims = readCandidateClaims(domain);
  } catch {
    return { available: false, inFinding: false };
  }
  if (!Array.isArray(claims) || claims.length === 0) return { available: false, inFinding: false };
  // Find the claim for THIS finding (payload.finding.id, else a finding evidence_ref),
  // mirroring crossStackPathGapForReportableFindings' dual-index.
  const targetFinding = String(effectFindingId);
  const surfaceSet = new Set();
  let resolvedClaim = false;
  for (const claim of claims) {
    const payload = claim && claim.payload && typeof claim.payload === "object" && !Array.isArray(claim.payload)
      ? claim.payload
      : null;
    const findingId = payload && payload.finding && typeof payload.finding === "object" ? payload.finding.id : null;
    let isThisFinding = typeof findingId === "string" && String(findingId) === targetFinding;
    if (!isThisFinding) {
      const refs = Array.isArray(claim && claim.evidence_refs) ? claim.evidence_refs : [];
      for (const ref of refs) {
        if (ref && ref.kind === "finding" && typeof ref.finding_id === "string" && String(ref.finding_id) === targetFinding) {
          isThisFinding = true;
          break;
        }
      }
    }
    if (!isThisFinding) continue;
    resolvedClaim = true;
    const ids = Array.isArray(claim.surface_ids) ? claim.surface_ids : [];
    for (const id of ids) {
      if (typeof id === "string" && id) surfaceSet.add(id);
    }
  }
  // No claim for this finding, or a claim with no surface_ids -> map unavailable (soft).
  if (!resolvedClaim || surfaceSet.size === 0) return { available: false, inFinding: false };
  return { available: true, inFinding: surfaceSet.has(causeSurfaceId) };
}

// REAL stack-family resolution for is_cross_stack (HIGH-1). The prior is_cross_stack
// (surface_refs.length >= 2) was a label-shape tautology: the positive arm is ALWAYS
// invariant: and the cause is ALWAYS offensive:, so the two refs always carry distinct
// prefixes and length is always 2. That asserted nothing about STACK families and gated
// nothing. This resolves the CAUSE's real stack family from surface-routes.json (the SAME
// route metadata finalize-node.js consults) and treats the EFFECT (invariant) arm as the
// structurally smart_contract stack. A real cross-stack flip's effect (smart_contract) and
// cause (web/code_module) must be DIFFERENT, KNOWN families.
//
// The route map is resolved through surface-router.js's readSurfaceRoutesStrict (a leaf-ish
// module already required by context-budget/technique-packs), inlining the same
// { surface_id -> surface_type } projection finalize-node.js's safeSurfaceRouteMap does —
// NOT requiring finalize-node.js (the finalize TOOL requires this verification stack, so a
// reverse require would cycle). Cached on ctx so a per-leaf / whole-ledger reverify pass
// reads routes once.
function resolveSurfaceFamilyMap(domain) {
  let result;
  try {
    // eslint-disable-next-line global-require
    const { readSurfaceRoutesStrict } = require("./surface-router.js");
    result = readSurfaceRoutesStrict(domain);
  } catch {
    return {};
  }
  const map = {};
  const doc = result && result.document;
  if (!doc || !Array.isArray(doc.routes)) return map;
  for (const route of doc.routes) {
    if (!route || typeof route !== "object") continue;
    const surfaceId = typeof route.surface_id === "string" ? route.surface_id : null;
    if (!surfaceId) continue;
    map[surfaceId] = typeof route.surface_type === "string" ? route.surface_type.trim() : null;
  }
  return map;
}

// Memoize the route-family map on ctx (the verifier runs per-leaf and the reverify pass
// runs over the whole ledger).
function surfaceFamilyMapForCtx(domain, ctx) {
  if (ctx && ctx.surfaceFamilyById != null) return ctx.surfaceFamilyById;
  const map = resolveSurfaceFamilyMap(domain);
  if (ctx) ctx.surfaceFamilyById = map;
  return map;
}

// web / smart_contract / code_module are the known stack families; anything else (or an
// absent route) collapses to null (NOT a third family), mirroring surfaceStackFamily in
// finalize-node.js. A null family CANNOT be proven distinct, so it fails is_cross_stack.
function knownStackFamily(surfaceType) {
  if (surfaceType === "web" || surfaceType === "smart_contract" || surfaceType === "code_module") {
    return surfaceType;
  }
  return null;
}

// crossStackFamilies — resolve the effect (invariant) and cause (offensive) stack families
// and decide is_cross_stack = BOTH known AND DISTINCT (fail-closed: an unknown cause family
// is NOT proven cross-stack). The effect arm is structurally smart_contract (an
// invariant_runs Foundry execution against a contract). The cause family is route-resolved
// from its offensive surface_id (the surfaceRef is `offensive:<surface_id>`).
function crossStackFamilies(causeLeg, surfaceFamilyById) {
  const effectFamily = "smart_contract";
  let causeFamily = null;
  const causeRef = causeLeg && typeof causeLeg.surfaceRef === "string" ? causeLeg.surfaceRef : null;
  if (causeRef && causeRef.startsWith("offensive:")) {
    const surfaceId = causeRef.slice("offensive:".length);
    const surfaceType = surfaceFamilyById ? surfaceFamilyById[surfaceId] : null;
    causeFamily = knownStackFamily(surfaceType);
  }
  const isCrossStack = effectFamily != null && causeFamily != null && effectFamily !== causeFamily;
  return { effectFamily, causeFamily, isCrossStack };
}

// Adjudicate the cross-stack CAUSE/EFFECT differential from the resolved legs. The flip
// is read from EXECUTED outcome names via each leg's ledger entry, never a hardcoded
// predicate. REFUSE-FIRST:
//   * BOTH flip arms (and the decoy arm) MUST be invariant_runs (the effect stack). The
//     stack-A attack is the bound CAUSE, not an arm — an offensive positive is refused.
//   * SAME-TEST binding (ported from verifyInvariantDifferential): positive, control AND
//     decoy must be the SAME invariant test (template_id, contract_name, function_name,
//     execution_context_hash, slot_values, generated_source_hash MATCH) on the SAME tree.
//   * consume-template id: every arm is a run of the audited cross-stack consuming
//     template (the only template whose body binds a captured artifact as the auth arg).
//   * positive VIOLATED, control HELD, DECOY HELD (the THREE-arm relevance differential).
//   * a bound CAUSE: an offensive exploited_safely row the violated arm NAMES + CONSUMED
//     (consumed_artifact_hash binding), control ARTIFACT-ABSENT.
//   * a bound DECOY: a DISTINCT is_decoy:true capture of RANDOM bytes the decoy arm NAMED +
//     CONSUMED, whose bytes are distinct from the real cause, and which the gate REJECTS
//     (decoy arm HOLDS). A tautological / any-non-empty gate ACCEPTS the decoy -> the
//     decoy arm VIOLATES -> no flip -> REFUSED. This forces the gate to validate the
//     SPECIFIC credential bytes (the artifact-relevance closer).
//   * ISOLATION PARITY: the positive, control AND decoy arms must each be
//     container_isolated === true (mirrors the single-surface scBackingUnIsolatedFindingIds
//     posture) — a degraded host-as-signer SC run can read the key and forge both arms.
//   * REAL cross-stack span (HIGH-1): the EFFECT (smart_contract) and CAUSE families must
//     be DIFFERENT KNOWN stack families; verified_pass is GATED on is_cross_stack === true.
// ctx carries { target_domain, surfaceFamilyById? } (the cached route-family map), an
// optional refetchCause flag (read-time), and an optional `enforce` flag (default true)
// for the isolation gate. Returns { result, reason, positive_identity, control_identity,
// cause_identity, decoy_identity, surface_refs, is_cross_stack, positive_outcome,
// control_outcome, cause_outcome, decoy_outcome }.
function adjudicateCrossStackFlip(positiveLeg, controlLeg, causeLeg, decoyArmLeg, decoyCaptureLeg, ctx = {}) {
  const positiveIdentity = positiveLeg.identity;
  const controlIdentity = controlLeg.identity;
  const base = {
    positive_identity: positiveIdentity,
    control_identity: controlIdentity,
    cause_identity: causeLeg ? causeLeg.identity : null,
    decoy_identity: decoyArmLeg ? decoyArmLeg.identity : null,
    surface_refs: [],
    is_cross_stack: false,
    positive_outcome: positiveLeg.outcome,
    control_outcome: controlLeg.outcome,
    cause_outcome: causeLeg ? causeLeg.outcome : null,
    decoy_outcome: decoyArmLeg ? decoyArmLeg.outcome : null,
  };
  const refuse = (reason) => ({ result: "refuted", reason, ...base });

  // Both flip arms (and the decoy arm) MUST be invariant_runs (the EFFECT stack). An
  // offensive positive is never an arm — the stack-A attack is the bound cause.
  if (positiveLeg.entry.ledger !== LEDGER_INVARIANT_RUNS || controlLeg.entry.ledger !== LEDGER_INVARIANT_RUNS) {
    return refuse("cross-stack flip arms must BOTH be invariant_runs (the effect stack); the stack-A attack is the bound cause, not an arm");
  }
  if (decoyArmLeg == null) {
    return refuse("cross-stack flip requires a decoy_run_ref (the random-bytes arm that must HOLD — the artifact-relevance proof)");
  }
  if (decoyArmLeg.entry.ledger !== LEDGER_INVARIANT_RUNS) {
    return refuse("the decoy arm must be an invariant_runs row (the SAME test on the SAME tree, run with random decoy bytes)");
  }
  const p = positiveLeg.row;
  const c = controlLeg.row;
  const d = decoyArmLeg.row;

  // CONSUME-TEMPLATE id — every arm must be a run of the audited cross-stack consuming
  // template (the only corpus template whose body binds a captured artifact as the auth
  // argument). This mirrors the runner's mint-side guard so an arbitrary slot-controlled
  // template can never reach a cross-stack verified_pass.
  if (p.template_id !== CROSS_STACK_CONSUME_TEMPLATE_ID) {
    return refuse(`cross-stack flip arms must run template ${CROSS_STACK_CONSUME_TEMPLATE_ID} (the audited consuming template); positive template_id=${p.template_id}`);
  }

  // SAME-TEST binding — ported byte-for-byte from verifyInvariantDifferential, extended to
  // the decoy arm: positive, control AND decoy must be the SAME generated test (same
  // template/contract/function/exec-ctx/slot_values/generated_source_hash). On the cross-
  // stack/bind path it is also the SAME tree (see below), so the THREE arms are byte-
  // identical generated tests on the byte-identical tree and the ONLY permitted difference
  // is the injected consumed artifact (real cause / random decoy / none).
  for (const field of SAME_TEST_SCALAR_FIELDS) {
    if ((p[field] || null) !== (c[field] || null)) {
      return refuse(`control must be the SAME test on the same tree (${field} differs)`);
    }
    if ((p[field] || null) !== (d[field] || null)) {
      return refuse(`decoy must be the SAME test on the same tree (${field} differs)`);
    }
  }
  if (hashCanonicalJson(p.slot_values || null) !== hashCanonicalJson(c.slot_values || null)) {
    return refuse("control slot_values must match the positive (same test, same tree, artifact-absent)");
  }
  if (hashCanonicalJson(p.slot_values || null) !== hashCanonicalJson(d.slot_values || null)) {
    return refuse("decoy slot_values must match the positive (same test, same tree, random-bytes arm)");
  }
  // The pinned SOURCE hash must match across all three arms — a shadowed/overridden test
  // body on any arm changes generated_source_hash and is refused here.
  if ((p.generated_source_hash || null) !== (c.generated_source_hash || null)) {
    return refuse("control generated_source_hash must match the positive (the SAME pinned test source)");
  }
  if ((p.generated_source_hash || null) !== (d.generated_source_hash || null)) {
    return refuse("decoy generated_source_hash must match the positive (the SAME pinned test source)");
  }

  // SAME-TREE artifact-presence differential — the cross-stack/bind path's controlled
  // variable is the CONSUMED ARTIFACT, not the tree. positive, control AND decoy must
  // reference the SAME tree/checkout so the only thing that can flip the outcome is which
  // bytes (real cause / random decoy / none) the env carried. A DIFFERENT-tree flip is a
  // single-surface invariant differential (verifyInvariantDifferential's job), NOT a cross-
  // stack causative flip — refuse it here so it routes to the right verifier (RANK != BOUND:
  // this refuses a mis-classified flip, it does not bound coverage).
  if ((p.tree_ref || null) !== (c.tree_ref || null) || p.checkout_kind !== c.checkout_kind) {
    return refuse("cross-stack control must reference the SAME tree/checkout as the positive run (the artifact PRESENCE, not the tree, is the controlled variable); a different-tree flip is a single-surface invariant differential, not cross-stack causation");
  }
  if ((p.tree_ref || null) !== (d.tree_ref || null) || p.checkout_kind !== d.checkout_kind) {
    return refuse("the decoy arm must reference the SAME tree/checkout as the positive run (the consumed bytes, not the tree, are the controlled variable)");
  }

  // CROSS-STACK TARGET BINDING — the executed EVM "effect" must run against the REAL audited
  // on-chain contract, not an agent-deployed/vm.etch'd target. Without this, an agent who
  // writes the harness setUp deploys a MaliciousTarget that reverts iff bytes != capturedAuth
  // and satisfies positive=VIOLATED/control=HELD/decoy=HELD legitimately, minting a forged
  // verified_pass. Each arm carries (outside run_hash, inside row_mac): target_code_sha256
  // (the executed runtime-bytecode sha256 the PINNED template emitted, exactly once) and
  // target_onchain_code_sha256 (sha256 of eth_getCode at the SAME address+fork_block, fetched
  // by the runner over the trusted fork endpoints — the agent controls the executed value but
  // NOT the on-chain one). They MUST be equal: a fake-deployed or vm.etch'd target has a
  // different runtime bytecode than the chain carried at fork_block. REQUIRED on all three
  // arms; a row minted BEFORE this binding (no target fields) is REFUSED (fail-closed
  // migration), never accepted-with-warning.
  for (const [armName, row] of [["positive", p], ["control", c], ["decoy", d]]) {
    const executedBound = typeof row.target_address === "string" && typeof row.target_code_sha256 === "string";
    if (!executedBound) {
      // address+code absent: the row predates target binding entirely (pre-binding migration).
      return refuse(`${armName} arm missing cross-stack target binding (target_address / target_code_sha256) — a cross-stack invariant must bind its EVM target to the audited on-chain bytecode; a row minted before target binding is REFUSED`);
    }
    if (typeof row.target_onchain_code_sha256 !== "string") {
      // Executed binding present but the runner's on-chain cross-check was UNAVAILABLE (all
      // trusted endpoints failed/timed-out, or the real-code responders disagreed). This is a
      // transient/operational state, NOT proof of a fake target. Refuse (the row does not bind),
      // but signal it is RE-RUNNABLE: re-running the invariant when the RPC ladder is healthy
      // mints a resolved row that supersedes this one at the SAME run_hash (the target siblings
      // are outside run_hash). Distinguishing this from a mismatch is what stops a transient RPC
      // blip from masquerading as a forgery and permanently blocking grading.
      return refuse(`${armName} arm: on-chain target bytecode lookup was UNAVAILABLE (target_onchain_code_sha256 null) — the runner could not cross-check the executed target against the chain at fork_block (transient RPC failure or endpoint disagreement). This is NOT a forgery; RE-RUN the invariant when the trusted RPC ladder is healthy to re-attempt the target cross-check.`);
    }
    if (row.target_code_sha256 !== row.target_onchain_code_sha256) {
      return refuse(`${armName} arm: executed target bytecode sha256 (${row.target_code_sha256}) does not equal the on-chain bytecode at fork_block (${row.target_onchain_code_sha256}) — a fake-deployed or vm.etch'd target is REFUSED`);
    }
  }
  if (p.target_address !== c.target_address || p.target_address !== d.target_address) {
    return refuse("cross-stack arms must reference the SAME target address (the same test on the same tree)");
  }
  if (p.target_onchain_code_sha256 !== c.target_onchain_code_sha256 || p.target_onchain_code_sha256 !== d.target_onchain_code_sha256) {
    return refuse("cross-stack arms must execute against the SAME on-chain target bytecode (an intermediate upgrade/swap between arms is REFUSED)");
  }

  // Distinct executed identity (the non-forgeability spine). The arms share a tree but flip
  // outcome (violated vs held), so their foundry_result_hash differs -> run_hash differs
  // (consumed_artifact_hash is OUTSIDE computeInvariantRunHash). An identical run_hash would
  // mean identical outcomes -> no flip; refuse it as a non-discriminating control.
  if (positiveIdentity != null && positiveIdentity === controlIdentity) {
    return refuse("control run_hash is identical to the positive (a non-discriminating control cannot flip)");
  }

  // FLIP — positive VIOLATED, control HELD, DECOY HELD (executed outcome names, never a
  // predicate). The decoy-HOLD is the artifact-relevance closer: a gate that accepts any
  // non-empty bytes accepts the random decoy too -> the decoy VIOLATES -> this refuses.
  if (!positiveLeg.entry.demonstrates(p)) {
    return refuse(`positive invariant did not VIOLATE (outcome=${positiveLeg.outcome})`);
  }
  if (!controlLeg.entry.isBlocked(c)) {
    return refuse(`control invariant is not HELD (outcome=${controlLeg.outcome}); the control must hold on the fixed tree`);
  }
  if (!decoyArmLeg.entry.isBlocked(d)) {
    return refuse(`decoy invariant is not HELD (outcome=${decoyArmLeg.outcome}); a gate that accepts the RANDOM decoy bytes does not validate the SPECIFIC credential — the artifact is not the real causal input`);
  }

  // CAUSE — a stack-A offensive run that exploited_safely, bound to the violated arm.
  if (causeLeg == null) {
    return refuse("cross-stack flip requires a bound cause_run_ref (the stack-A attack that produced the effect)");
  }
  if (causeLeg.entry.ledger !== LEDGER_OFFENSIVE_RUNS || !causeLeg.entry.demonstrates(causeLeg.row)) {
    return refuse(`cause must be an offensive_runs row that exploited_safely (outcome=${causeLeg.outcome})`);
  }
  // CAUSAL LINK + CONSUMED-ARTIFACT BINDING (O-B). The violated arm must NAME this cause
  // (necessary) AND have CONSUMED its captured artifact (the sufficient proof): the
  // violated arm's consumed_artifact_hash is non-null and equals the cause's MAC-covered
  // consumed_artifact_hash, and the control arm ran cause-free. A merely-named flip whose
  // violated arm never consumed the cause bytes is NOT a cross-stack causative flip.
  const consumedLink = violatedArmConsumedCause(positiveLeg, controlLeg, causeLeg, {
    domain: ctx.target_domain,
    refetchCause: ctx.refetchCause === true,
  });
  if (!consumedLink.ok) {
    return refuse(consumedLink.reason);
  }

  // DECOY — a DISTINCT is_decoy:true capture of RANDOM bytes, bound to the decoy arm.
  if (decoyCaptureLeg == null) {
    return refuse("cross-stack flip requires a bound decoy capture (the random-bytes capture the decoy arm consumes)");
  }
  if (decoyCaptureLeg.entry.ledger !== LEDGER_OFFENSIVE_RUNS || decoyCaptureLeg.isDecoy !== true) {
    return refuse("the decoy capture must be an offensive_runs row marked is_decoy:true (a distinct random-bytes capture, never the real cause)");
  }
  // The decoy capture must be DISTINCT from the real cause (a separate run_id), so the
  // decoy is provably not the cause re-used.
  if (decoyCaptureLeg.rowKey != null && causeLeg.rowKey != null && decoyCaptureLeg.rowKey === causeLeg.rowKey) {
    return refuse("the decoy capture and the cause are the same run (a decoy must be a DISTINCT random-bytes capture)");
  }
  // DECOY-ARM CONSUMED-DECOY BINDING — the decoy arm NAMED + CONSUMED the decoy capture's
  // random bytes (distinct from the real cause bytes). Combined with the decoy-HOLD flip
  // check above, this is the artifact-relevance proof.
  const decoyLink = decoyArmConsumedDecoy(decoyArmLeg, decoyCaptureLeg, positiveLeg, causeLeg, {
    domain: ctx.target_domain,
    refetchCause: ctx.refetchCause === true,
  });
  if (!decoyLink.ok) {
    return refuse(decoyLink.reason);
  }

  // ISOLATION PARITY — every invariant arm (positive, control, decoy) must have run
  // container_isolated === true. On an isolated-signer box where the SC toolchain degrades
  // to host-as-signer, agent Solidity runs as the signer uid and can read the 0400 key to
  // hand-mint MAC-valid rows -> forge any arm. This mirrors the single-surface
  // scBackingUnIsolatedFindingIds posture (which flags a positive whose container_isolated
  // !== true). container_isolated is read off the STRICT-MAC-verified row, so an agent on a
  // degraded box cannot flip it without invalidating the row_mac. Under ctx.enforce (the
  // default) this REFUSES; the membership/verdict-gate leg is a second line at report time.
  const enforceIsolation = ctx.enforce !== false;
  if (enforceIsolation) {
    if (positiveLeg.containerIsolated !== true) {
      return refuse("cross-stack positive arm ran host-as-signer (container_isolated !== true); a degraded SC toolchain can read the signing key and forge both arms");
    }
    if (controlLeg.containerIsolated !== true) {
      return refuse("cross-stack control arm ran host-as-signer (container_isolated !== true); a degraded SC toolchain can read the signing key and forge both arms");
    }
    if (decoyArmLeg.containerIsolated !== true) {
      return refuse("cross-stack decoy arm ran host-as-signer (container_isolated !== true); a degraded SC toolchain can read the signing key and forge both arms");
    }
  }

  // surface_refs = [effect-arm surface, cause surface]. is_cross_stack is the REAL stack-
  // family check (HIGH-1): the effect (smart_contract) and the route-resolved cause family
  // must be DIFFERENT KNOWN families — not the prior length>=2 label-shape tautology. This
  // CLASSIFICATION ("is this a cross-stack flip at all") runs BEFORE the finding-scope
  // soundness gate below: a same-family/unresolved-family flip is not a cross-stack flip, so
  // it never reaches the cross-stack-only finding-scope requirement.
  const surfaceRefs = [];
  for (const ref of [positiveLeg.surfaceRef, causeLeg.surfaceRef]) {
    if (typeof ref === "string" && ref && !surfaceRefs.includes(ref)) surfaceRefs.push(ref);
  }
  const surfaceFamilyById = surfaceFamilyMapForCtx(ctx.target_domain, ctx);
  const { effectFamily, causeFamily, isCrossStack } = crossStackFamilies(causeLeg, surfaceFamilyById);
  // GATE verified_pass on a PROVEN-distinct cross-stack span. A same-family or unresolved-
  // family flip is a single-surface invariant differential (verifyInvariantDifferential's
  // job), NOT a cross-stack causative flip — refuse here so it routes to the right verifier
  // (RANK != BOUND: this refuses a mis-classified flip, it does not bound coverage).
  if (!isCrossStack) {
    return refuse(
      `flip arms and cause do not span distinct stack families (effect=${effectFamily || "unknown"}, cause=${causeFamily || "unknown"}); a same-stack or unresolved-stack flip is not a cross-stack causative flip`,
    );
  }

  // FAIL-CLOSED FINDING-SCOPE — for a cross-stack REPORTABLE mint the cause must be
  // PROVABLY within the effect finding's surface set. "The cause is within the effect
  // finding" is a soundness requirement, not defense-in-depth: a cause whose finding-scope
  // cannot be established must not produce verified_pass. The cross-stack adjudicator runs
  // at reportable-mint time inside a repo session where the claim and its surface_ids
  // exist, so an INDETERMINATE scope (no claim map, empty surface_ids, unreadable claims,
  // null finding_id / cause surface) is an anomaly, not a benign non-repo case — it HARD-
  // FAILS CLOSED rather than falling back to the consumed-artifact binding. This runs AFTER
  // the is_cross_stack classification: only a flip already proven cross-stack is subject to
  // the cross-stack-only finding-scope requirement. require available && inFinding (was:
  // refuse only when available && !inFinding).
  const causeSurfaceId = typeof causeLeg.surfaceRef === "string" && causeLeg.surfaceRef.startsWith("offensive:")
    ? causeLeg.surfaceRef.slice("offensive:".length)
    : null;
  const findingScope = causeWithinEffectFinding(p.finding_id != null ? String(p.finding_id) : null, causeSurfaceId, ctx.target_domain);
  if (!(findingScope.available && findingScope.inFinding)) {
    return refuse("cross-stack reportable mint requires the cause to be PROVABLY within the effect finding's surface set; an indeterminate finding<->surface map (no claim, empty surface_ids, unreadable, or null finding/cause surface) fails closed");
  }

  return {
    result: "verified_pass",
    reason: "executed_cross_stack_cause_effect_differential",
    ...base,
    surface_refs: surfaceRefs,
    is_cross_stack: true,
  };
}

// The EXECUTION-keyed identity of a verified_pass (F4). Membership in verified_path_hashes
// keys on the EXECUTED row-identity tuple (the four re-derived row hashes — positive,
// control, cause, AND the decoy arm), NOT the agent-supplied path/evidence annotation. So
// one real flipping {positive, control, decoy, cause} tuple called N times with different
// evidence_ref / edge_type spellings collapses to ONE claim, and the decoy is part of the
// non-forgeable identity. Computed from the adjudicated verdict's identities, never the
// leaf's annotation.
function executionKeyForVerdict(verdict) {
  return hashCanonicalJson({
    positive_identity: verdict.positive_identity,
    control_identity: verdict.control_identity,
    cause_identity: verdict.cause_identity,
    decoy_identity: verdict.decoy_identity,
  });
}

// resolveBoundDifferentialLeaf — the bind-path leaf verifier the dispatcher calls for a
// bind leaf (one carrying positive_run_ref + control_run_ref). It resolves the two effect
// arms AND the bound cause (each STRICT-MAC-verified), confirms the same-test effect flip +
// the causal link, accepts open-vocab edge_type by shape, and returns a per-leaf record
// { leaf_status, execution_key, ... }. Never throws on a probe failure (any throw ->
// inconclusive leaf record), mirroring the guard-path verifyLeaf.
//
// ctx: { target_domain } (+ optional cached readers/verifiers for batching).
function resolveBoundDifferentialLeaf(leaf, ctx) {
  const domain = ctx.target_domain;
  const edgeType = leaf && typeof leaf.edge_type === "string" ? leaf.edge_type : null;
  const base = {
    edge_id: leaf && typeof leaf.edge_id === "string" ? leaf.edge_id : null,
    evidence_ref: leaf && typeof leaf.evidence_ref === "string" ? leaf.evidence_ref : null,
    edge_type: edgeType,
    bind: true,
  };

  // Open-vocab edge_type: SHAPE-gate only (annotate-don't-gate). A bind leaf must still
  // carry SOME non-empty mechanism label so the verdict record is attributable, but its
  // spelling is never matched against an enum.
  if (!isShapeValidEdgeType(edgeType)) {
    return { ...base, leaf_status: "inconclusive", reason: "bind leaf edge_type must be a non-empty string (open-vocab, shape-validated)" };
  }

  const pRef = leaf.positive_run_ref;
  const cRef = leaf.control_run_ref;
  // A cross-stack flip REQUIRES a bound cause_run_ref (the stack-A attack). Without it the
  // flip is not cross-stack-attributable.
  const causeRef = leaf.cause_run_ref;
  if (causeRef == null || typeof causeRef !== "object") {
    return { ...base, leaf_status: "refuted", reason: "cross-stack bind leaf requires a cause_run_ref { ledger, row_id } (the stack-A attack that produced the effect)" };
  }
  // A cross-stack flip REQUIRES the decoy arm (the invariant run on the same test/tree that
  // consumed the random decoy bytes) AND the decoy capture (the is_decoy offensive row).
  const decoyArmRef = leaf.decoy_run_ref;
  const decoyCaptureRef = leaf.decoy_cause_run_ref;
  if (decoyArmRef == null || typeof decoyArmRef !== "object") {
    return { ...base, leaf_status: "refuted", reason: "cross-stack bind leaf requires a decoy_run_ref { ledger, row_id } (the SAME test on the SAME tree run with random decoy bytes — must HOLD)" };
  }
  if (decoyCaptureRef == null || typeof decoyCaptureRef !== "object") {
    return { ...base, leaf_status: "refuted", reason: "cross-stack bind leaf requires a decoy_cause_run_ref { ledger, row_id } (the is_decoy random-bytes capture the decoy arm consumes)" };
  }

  // The effect arms (positive, control, decoy) must be distinct invariant rows (a single
  // run never mints). A same {ledger,row_id} between any two is rejected before resolution.
  const sameRef = (a, b) => a && b && typeof a === "object" && typeof b === "object"
    && a.ledger === b.ledger && a.row_id === b.row_id;
  if (sameRef(pRef, cRef) || sameRef(pRef, decoyArmRef) || sameRef(cRef, decoyArmRef)) {
    return { ...base, leaf_status: "refuted", reason: "positive, control and decoy must be DIFFERENT executed rows (a single run never mints verified)" };
  }

  let positiveLeg;
  let controlLeg;
  let causeLeg;
  let decoyArmLeg;
  let decoyCaptureLeg;
  try {
    positiveLeg = resolveBindRef(domain, pRef, ctx, "positive");
    controlLeg = resolveBindRef(domain, cRef, ctx, "control");
    causeLeg = resolveBindRef(domain, causeRef, ctx, "cause");
    decoyArmLeg = resolveBindRef(domain, decoyArmRef, ctx, "decoy");
    decoyCaptureLeg = resolveBindRef(domain, decoyCaptureRef, ctx, "decoy_cause");
  } catch (err) {
    return { ...base, leaf_status: "inconclusive", reason: `bind resolution error: ${err && err.message ? err.message : String(err)}` };
  }

  const verdict = adjudicateCrossStackFlip(positiveLeg, controlLeg, causeLeg, decoyArmLeg, decoyCaptureLeg, ctx);
  const leafRecord = {
    ...base,
    positive_ref: { ledger: pRef.ledger, row_id: pRef.row_id },
    control_ref: { ledger: cRef.ledger, row_id: cRef.row_id },
    cause_ref: { ledger: causeRef.ledger, row_id: causeRef.row_id },
    decoy_ref: { ledger: decoyArmRef.ledger, row_id: decoyArmRef.row_id },
    decoy_cause_ref: { ledger: decoyCaptureRef.ledger, row_id: decoyCaptureRef.row_id },
    positive_row_hash: verdict.positive_identity,
    control_row_hash: verdict.control_identity,
    cause_row_hash: verdict.cause_identity,
    decoy_row_hash: verdict.decoy_identity,
    surface_refs: verdict.surface_refs,
    is_cross_stack: verdict.is_cross_stack,
    positive_outcome: verdict.positive_outcome,
    control_outcome: verdict.control_outcome,
    cause_outcome: verdict.cause_outcome,
    decoy_outcome: verdict.decoy_outcome,
    // container_isolated / severity come from the VIOLATED INVARIANT positive arm (the
    // effect-stack producer), never the cause.
    container_isolated: positiveLeg.containerIsolated === true,
    demonstrated_severity: positiveLeg.severity,
    // The execution-keyed identity (F4): one execution = one membership key, independent
    // of the agent-supplied evidence_ref / edge_type annotation.
    execution_key: executionKeyForVerdict(verdict),
  };
  if (verdict.result === "verified_pass") {
    return { ...leafRecord, leaf_status: "verified", reason: verdict.reason };
  }
  return { ...leafRecord, leaf_status: "refuted", reason: verdict.reason };
}

// reverifyCrossStackLeaf — READ-TIME INTEGRITY for a persisted bind leaf record. Do NOT
// trust the verdict record's stored result / surface_refs / execution_key
// (composition-verified.jsonl's results_hash is an UNKEYED self-hash). RE-RESOLVE all
// THREE run refs (STRICT-MAC-verified) and RE-ADJUDICATE the flip + causal link from
// signed source bytes. surface_refs / severity / container_isolated / execution_key are
// re-derived FROM THE RE-RESOLVED ROWS, never the record's self-hashed fields. Any throw
// -> ok:false (fail-closed on a rotated / truncated source ledger, or a stored leaf whose
// cause no longer re-resolves). Returns { ok, surface_refs, is_cross_stack,
// demonstrated_severity, container_isolated, execution_key }.
function reverifyCrossStackLeaf(domain, leafRecord, ctx = {}) {
  const FAIL = { ok: false, surface_refs: [], is_cross_stack: false, demonstrated_severity: null, container_isolated: false, execution_key: null };
  if (leafRecord == null || typeof leafRecord !== "object") {
    return { ...FAIL };
  }
  try {
    const pRef = leafRecord.positive_ref;
    const cRef = leafRecord.control_ref;
    const causeRef = leafRecord.cause_ref;
    const decoyArmRef = leafRecord.decoy_ref;
    const decoyCaptureRef = leafRecord.decoy_cause_ref;
    if (pRef == null || cRef == null) throw new Error("bind leaf record missing positive_ref / control_ref");
    if (causeRef == null) throw new Error("bind leaf record missing cause_ref (no causal link to re-resolve)");
    if (decoyArmRef == null || decoyCaptureRef == null) {
      throw new Error("bind leaf record missing decoy_ref / decoy_cause_ref (no decoy relevance arm to re-resolve)");
    }
    if (pRef.ledger === cRef.ledger && pRef.row_id === cRef.row_id) {
      throw new Error("a single run never flips against itself");
    }
    const positiveLeg = resolveBindRef(domain, pRef, ctx, "positive");
    const controlLeg = resolveBindRef(domain, cRef, ctx, "control");
    const causeLeg = resolveBindRef(domain, causeRef, ctx, "cause");
    const decoyArmLeg = resolveBindRef(domain, decoyArmRef, ctx, "decoy");
    const decoyCaptureLeg = resolveBindRef(domain, decoyCaptureRef, ctx, "decoy_cause");
    // READ-TIME: re-adjudicate from the re-resolved (STRICT-MAC) rows with the consumed-
    // artifact + decoy bindings re-derived AND the cause/decoy bytes re-fetched
    // (refetchCause), so a post-mint swap of either .consumed leaf or a stale stack-family
    // routing drops the row.
    const adjudicateCtx = { target_domain: domain, refetchCause: true, surfaceFamilyById: ctx.surfaceFamilyById };
    const verdict = adjudicateCrossStackFlip(positiveLeg, controlLeg, causeLeg, decoyArmLeg, decoyCaptureLeg, adjudicateCtx);
    return {
      ok: verdict.result === "verified_pass",
      surface_refs: verdict.surface_refs,
      is_cross_stack: verdict.is_cross_stack,
      // From the MAC-covered positive (effect) row, never the verdict record's fields.
      demonstrated_severity: positiveLeg.severity,
      container_isolated: positiveLeg.containerIsolated === true,
      // Re-derived from the RE-RESOLVED rows (not the stored field), so a forged
      // execution_key cannot survive read-time re-verification.
      execution_key: executionKeyForVerdict(verdict),
    };
  } catch {
    return { ...FAIL };
  }
}

module.exports = {
  LEDGER_OFFENSIVE_RUNS,
  LEDGER_INVARIANT_RUNS,
  isBindLeaf,
  isShapeValidEdgeType,
  lookupLedgerEntry,
  resolveBindRef,
  adjudicateCrossStackFlip,
  resolveBoundDifferentialLeaf,
  reverifyCrossStackLeaf,
  executionKeyForVerdict,
  violatedArmNamesCause,
  violatedArmConsumedCause,
  decoyArmConsumedDecoy,
  crossStackFamilies,
  CROSS_STACK_CONSUME_TEMPLATE_ID,
};
