"use strict";

// Verdict-level sandbox-isolation gate (Mechanism A, N5).
//
// The four keyed verdict ledgers (offensive-runs.jsonl, invariant-runs.jsonl,
// repo-command-runs.jsonl, claim-freeze.json) are signed with the ed25519
// private key. That key is born owner-only in the session tree; the genuine
// close to F3 (a same-uid agent reading the key and forging a MAC) is the
// OPERATOR running the MCP server under a dedicated signer uid so the agent uid
// gets EACCES on the key (and cannot raw-write the audit-graded ledgers either).
// scripts/launch-bob-signer.sh is the operator launcher; the in-process sign
// shim (handoff-signing-key.js signRowViaIsolatedSignerOrLocal) keeps minting
// rows even on an unisolated box so in-flight sessions never crash. The TRUST
// consequence is decided HERE, at the verdict boundary, not on the fast in-lock
// sign path.
//
// This module is the SINGLE source of truth both verdict seams consume:
//   * lifecycle-gates.js gateVerifyToGrade — pushes a STATE_CONFLICT blocker
//     (enforce) or stamps a downgrade directive (degrade);
//   * tools/compose-report.js — throws STATE_CONFLICT (enforce) or downgrades
//     the verdict-ledger-backed reportable medium+ sections to advisory
//     (degrade).
//
// CONSTRAINT 1 (fast per-row read): everything here is verdict-LEVEL, evaluated
// ONCE per gate (one lstat probe + an early-exiting ledger scheme scan + a
// once-per-call claims/summary/freeze read for the per-finding backing set), NEVER
// on the per-row MAC re-derivation hot path. The ledger scheme scan early-exits as
// soon as it knows present + hasLegacyOrV1, and the per-finding backing read runs
// only when the reportable set is non-empty. CONSTRAINT 6 (read-time re-derivation
// untouched): this layer sits ABOVE verifyRowWithMac/reverify* and protects their
// trust root; it never re-derives a row's content hash.
//
// FORWARD-NOTE ii (never trust the self-asserted file): the gate consumes a LIVE
// probe (probeVerdictLedgerKeyIsolation) at gate time. It NEVER reads the stored
// sandbox-isolation.json `attested` flag for the trust decision — a same-uid
// agent can rewrite that artifact via runtime indirection; only the live
// structural facts (the key's owner-only mode + the running uid == the key owner
// == the declared signer + a distinct declared agent uid + not root) are the
// truth, and the agent can fake none of them.
//
// WHERE THE GATE'S INTEGRITY ACTUALLY RESTS (stated plainly). This is an
// IN-PROCESS gate: a SAME-UID actor can monkeypatch evaluateVerdictSandboxGate,
// the live probe's lstat/getuid, or the probe's inputs (the suite's
// withIsolatedSigner / withStructuralIsolatedKey helpers are constructive proofs
// of exactly that). So the gate is meaningful ONLY under Mechanism A, where the
// agent runs at a DISTINCT uid and therefore cannot inject into the server
// process at all. On a same-uid box there is no in-process tamper-resistance to
// rely on — which is the whole point of fail-closing: the live probe returns
// isolated:false there (the agent uid is not distinct from the signer), so the
// gate blocks (enforce) or downgrades (degrade) rather than trusting an integrity
// it does not have. The gate does not claim same-uid tamper-resistance; it claims
// cross-uid exclusion under Mechanism A and fail-closed advisory everywhere else.
//
// RANK != BOUND (the gate never bounds coverage), applied PER FINDING: only the
// reportable medium+ findings whose OWN evidence cites an EXECUTED keyed verdict-ledger
// row (an exploit_run / repo_command_run ref, or an invariant/finding-differential
// verified_pass) are ever blocked/downgraded. The claim-freeze is NOT a per-finding
// backing leg — it freezes EVERY candidate claim, so counting freeze membership would
// re-gate a pure-OSINT reportable finding downstream of VERIFY. A pure-OSINT reportable
// finding is UNAFFECTED even when an UNRELATED finding wrote a ledger row AND a freeze
// containing its claim exists — `present` (any ledger row) is NOT the per-finding
// predicate; findingsBackedByKeyedLedger intersects the reportable set with the
// actually-executed-backed findings. Advisory / low / info / operator_osint /
// external_research surfaces are never touched.

const fs = require("fs");
const {
  resolveSandboxAttestationMode,
  probeVerdictLedgerKeyIsolation,
  evaluateSandboxIsolation,
} = require("./sandbox-isolation-attest.js");

const MEDIUM_OR_HIGHER_SEVERITIES = Object.freeze(new Set(["medium", "high", "critical"]));

const SANDBOX_ISOLATION_BLOCKER_CODE = "sandbox_isolation_unattested";

const SANDBOX_REMEDIATION =
  "run the MCP server under a dedicated signer OS uid (scripts/launch-bob-signer.sh: "
  + "the agent uid then gets EACCES on the ed25519 verdict-ledger private key and cannot "
  + "raw-write the audit-graded ledgers) and set BOB_SANDBOX_ATTESTATION_MODE=enforce + "
  + "the operator ack/uid env; or re-run the verdict producer once the signer is isolated";

// Read the four keyed verdict-ledger files RAW and enumerate each row's MAC
// envelope class WITHOUT verifying it. Verification stays on the per-row read
// path (verifyRowWithMac); here we only classify the declared scheme so the
// enforce-mode legacy/v1-HMAC block can refuse a row that would launder a
// symmetric-key forgery minted while the key was still readable. Classes:
//   * "unsigned" — no MAC envelope (an old in-flight row, or a stripped MAC);
//   * "v1_hmac"  — version 1 OR scheme "hmac-sha256" (symmetric-key MAC);
//   * "ed25519"  — version 2 scheme "ed25519" (the post-split asymmetric MAC).
// A row whose class is unsigned or v1_hmac cannot back a NEW reportable claim
// under enforce; it remains READABLE for forensics (this classifier never
// mutates or deletes anything).
function classifyMacEnvelope(env) {
  if (env == null || typeof env !== "object" || Array.isArray(env)) return "unsigned";
  if (env.version === 1) return "v1_hmac";
  if (env.version === 2) {
    if (env.scheme === "ed25519") return "ed25519";
    if (env.scheme === "hmac-sha256") return "v1_hmac";
    return "unsigned";
  }
  // Unknown/forward envelope shapes are treated as unsigned (fail closed for a
  // NEW claim; still readable for forensics).
  return "unsigned";
}

function readJsonlRowsRaw(filePath) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch {
    return [];
  }
  const rows = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      rows.push(JSON.parse(line));
    } catch {
      // A malformed line is forensic noise here; the strict per-row readers own
      // the hard failure. Skip it for the verdict-level scheme scan.
    }
  }
  return rows;
}

// Scan the four keyed verdict ledgers for the two facts the gate decision needs:
//   present       — at least one ledger row exists (this session draws on a keyed
//                   verdict ledger at all);
//   hasLegacyOrV1 — at least one row is unsigned or v1-HMAC (the laundering-risk
//                   class that forces block/downgrade independent of isolation).
// The gate only ever consumes those two booleans (the old classes Set was read
// solely as has("unsigned")||has("v1_hmac")), so this drops the full Set and
// EARLY-EXITS: once BOTH present and hasLegacyOrV1 are true, no further file/row is
// classified — the laundering-risk case (which dominates the decision) short-circuits.
// The common all-ed25519 ledger still scans fully (hasLegacyOrV1 never trips), but
// that is the case where the early-exit would not have helped anyway. CONSTRAINT 1:
// verdict-LEVEL; the per-row classifyMacEnvelope is an envelope-SHAPE check, never a
// per-row MAC re-derivation (CONSTRAINT 6 untouched).
function verdictLedgerMacClasses(domain) {
  const {
    offensiveRunsJsonlPath,
    invariantRunsJsonlPath,
    repoCommandRunsJsonlPath,
    claimFreezePath,
    compositionVerifiedJsonlPath,
  } = require("../io/paths.js");
  let present = false;
  let hasLegacyOrV1 = false;

  for (const filePath of [
    offensiveRunsJsonlPath(domain),
    invariantRunsJsonlPath(domain),
    repoCommandRunsJsonlPath(domain),
  ]) {
    for (const row of readJsonlRowsRaw(filePath)) {
      present = true;
      const cls = classifyMacEnvelope(row && row.row_mac);
      if (cls === "unsigned" || cls === "v1_hmac") hasLegacyOrV1 = true;
      if (present && hasLegacyOrV1) return { present, hasLegacyOrV1 };
    }
  }

  // composition-verified.jsonl (cross-stack bind / object-auth guard verified_pass rows)
  // makes the session DRAW on a keyed verdict ledger: a live cross-stack flip exists, so
  // an indeterminate cross-stack reportable claim must fail closed (ledgerPresent true).
  // These rows carry no row_mac envelope (they are re-resolved bind/guard verdicts, not
  // MAC-keyed leaves), so they only contribute `present`, never hasLegacyOrV1 — a
  // re-resolved bind row's trust rests on its source rows' MACs, not a row_mac on the
  // composition row itself.
  for (const row of readJsonlRowsRaw(compositionVerifiedJsonlPath(domain))) {
    if (row && row.result === "verified_pass") {
      present = true;
      break;
    }
  }

  // claim-freeze.json is a single JSON object carrying freeze_mac (not JSONL).
  try {
    const text = fs.readFileSync(claimFreezePath(domain), "utf8");
    const doc = JSON.parse(text);
    if (doc != null && typeof doc === "object" && !Array.isArray(doc)) {
      present = true;
      const cls = classifyMacEnvelope(doc.freeze_mac);
      if (cls === "unsigned" || cls === "v1_hmac") hasLegacyOrV1 = true;
    }
  } catch {
    // absent/malformed freeze: no contribution.
  }

  return { present, hasLegacyOrV1 };
}

// The reportable medium+ finding set, read through the SAME final-verification
// projection the executed-flip gates use (reclamped severity, not agent-bumped).
// Returns a Set of finding ids. Empty when there is no final round or no
// reportable medium+ finding — the gate is then inert.
function reportableMediumPlusFindingIds(domain) {
  const ids = new Set();
  let finalByFinding;
  try {
    // record-candidate-claim.js owns readFinalVerificationByFinding indirectly
    // via compose-report; read the final round directly to avoid a require cycle
    // into the composer. The shape is the reclamped {reportable, severity} map.
    finalByFinding = readFinalVerificationByFinding(domain);
  } catch {
    return ids;
  }
  for (const [findingId, entry] of finalByFinding) {
    if (!entry || entry.reportable !== true) continue;
    if (!entry.severity || !MEDIUM_OR_HIGHER_SEVERITIES.has(entry.severity)) continue;
    ids.add(findingId);
  }
  return ids;
}

// Reclamped final-verification projection, keyed by finding_id. Reuses the SAME
// reclampSeveritiesAgainstFreeze helper the composer's readFinalVerificationByFinding
// uses (single source of truth), so the gate's reportable medium+ set matches the
// executed-flip gates exactly: a hand-bumped low->critical re-reads as its frozen
// baseline. Lives here (not via the composer) so verify->grade — which has no
// composer in scope — shares the projection without a require cycle into
// tools/compose-report.js. A missing/malformed final round yields an empty map
// (the gate is then inert).
function readFinalVerificationByFinding(domain) {
  const { verificationRoundPaths } = require("../io/paths.js");
  const { SEVERITY_VALUES } = require("../../lib/constants.js");
  const out = new Map();
  let paths;
  try {
    paths = verificationRoundPaths(domain, "final");
  } catch {
    return out;
  }
  if (!fs.existsSync(paths.json)) return out;
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(paths.json, "utf8"));
  } catch {
    return out;
  }
  const results = Array.isArray(doc && doc.results) ? doc.results : [];
  const { reclampSeveritiesAgainstFreeze } = require("../verification/verification-round-store.js");
  const reclamped = reclampSeveritiesAgainstFreeze(domain, results);
  for (const result of results) {
    if (!result || typeof result !== "object") continue;
    const id = typeof result.finding_id === "string" ? result.finding_id : null;
    if (!id || !id.trim()) continue;
    const rawSeverity = SEVERITY_VALUES.includes(result.severity) ? result.severity : null;
    const decision = reclamped.get(id);
    const clampedSeverity = decision && SEVERITY_VALUES.includes(decision.severity)
      ? decision.severity
      : rawSeverity;
    out.set(id, {
      reportable: result.reportable === true,
      severity: clampedSeverity,
    });
  }
  return out;
}

// RANK != BOUND, applied PER FINDING. `present` (verdictLedgerMacClasses) is true
// iff ANY of the four ledgers carries ANY row — but a row written by an UNRELATED
// finding must not bound a DIFFERENT reportable finding. This helper computes the
// SUBSET of finding ids whose OWN evidence actually cites a keyed verdict-ledger row,
// so only those are ever blocked/downgraded; a pure-OSINT reportable finding (its
// claim cites only finding/http_audit/verification_round refs) is never gated merely
// because some other finding wrote an offensive/invariant/repo/freeze row.
//
// A finding is keyed-ledger-backed (gated) iff it cites an EXECUTED verdict-ledger
// row OR its backing cannot be determined (indeterminate => fail CLOSED). The
// EXECUTED-row legs are ANY of:
//   * its claim's evidence_refs[] carries an exploit_run ref (an offensive-runs.jsonl
//     row, hash-bound to a signed MAC) OR a repo_command_run ref (a
//     repo-command-runs.jsonl row);
//   * the finding is in finding-differential-verified.jsonl's verified_by_finding —
//     a verified_pass RE-RESOLVED from MAC-covered offensive-runs rows;
//   * the finding is in invariant-verified.jsonl's verified_by_finding — a
//     verified_pass re-adjudicated from invariant-runs rows.
// The claim-freeze is DELIBERATELY NOT a backing leg here. buildClaimFreeze freezes
// EVERY candidate claim (readCandidateClaims, no reportability/backing filter), so by
// grade/compose time a freeze contains ~every reportable finding's claim. Counting
// freeze membership as backing would collapse the per-finding intersection back to ~the
// full reportable set, re-gating a pure-OSINT reportable finding downstream of VERIFY —
// the exact RANK != BOUND violation this gate exists to avoid. The freeze is the
// severity-baseline + class source (read by reclampSeveritiesAgainstFreeze and the
// laundering-risk scan in verdictLedgerMacClasses), NOT a per-finding executed-verdict
// backing.
// INDETERMINATE BACKING fails CLOSED when a keyed ledger is present: a reportable
// medium+ finding whose claim cannot be resolved in EITHER index is added to
// `backed` (gated/requires isolation) IFF the session ACTUALLY DRAWS on a keyed
// verdict ledger (ledgerPresent — any offensive/invariant/repo/freeze row exists).
// That matches the not-isolated and laundering-risk fail-closed posture: an
// unresolvable claim over a LIVE keyed ledger has unknown (possibly keyed) backing.
// When NO keyed ledger row exists in the session (ledgerPresent false), an
// unresolvable-claim finding is verification-round-only / pure-OSINT — nothing to
// launder — so it stays UNGATED (the gate's no_verdict_ledger_backing inert case),
// identical to today's pass-through. A pure-OSINT finding that DOES resolve a claim
// (finding/http_audit refs only) is always unaffected.
// Claims are resolved by payload.finding.id OR a kind:"finding" evidence_ref's
// finding_id — the SAME dual index claims.js's claimByFinding loop uses — so a
// dual-write tool-path finding is not under-counted (which would UNDER-gate).
//
// Verdict-LEVEL (CONSTRAINT 1): reads claims once + the two verified summaries once;
// never per-row MAC re-derivation. Called ONLY when the reportable set is non-empty
// (the caller early-returns before touching claims otherwise).
function findingsBackedByKeyedLedger(domain, reportableIds, { ledgerPresent = false, compositionSummary = null } = {}) {
  const backed = new Set();
  if (!(reportableIds instanceof Set) || reportableIds.size === 0) return backed;

  // Resolve each finding id -> its CandidateClaim (dual index: payload.finding.id and a
  // kind:"finding" evidence_ref finding_id), mirroring claims.js's claimByFinding loop.
  const claimByFinding = new Map();
  let claims = [];
  try {
    const { readCandidateClaims } = require("../claims/claims.js");
    claims = readCandidateClaims(domain);
  } catch {
    claims = [];
  }
  for (const claim of claims) {
    if (!claim || typeof claim !== "object") continue;
    const payloadFinding = claim.payload && typeof claim.payload === "object" && !Array.isArray(claim.payload)
      ? claim.payload.finding
      : null;
    const payloadFindingId = payloadFinding && typeof payloadFinding === "object" ? payloadFinding.id : null;
    if (typeof payloadFindingId === "string" && !claimByFinding.has(payloadFindingId)) {
      claimByFinding.set(payloadFindingId, claim);
    }
    const refs = Array.isArray(claim.evidence_refs) ? claim.evidence_refs : [];
    for (const ref of refs) {
      if (ref && ref.kind === "finding" && typeof ref.finding_id === "string" && !claimByFinding.has(ref.finding_id)) {
        claimByFinding.set(ref.finding_id, claim);
      }
    }
  }

  // The invariant / finding-differential confirm signals (verified_by_finding maps).
  let differentialVerified = {};
  try {
    const { readFindingDifferentialVerifiedSummary } = require("../differential/finding-differential-verifier.js");
    differentialVerified = readFindingDifferentialVerifiedSummary(domain).verified_by_finding || {};
  } catch {
    differentialVerified = {};
  }
  let invariantVerified = {};
  try {
    const { readInvariantVerifiedSummary } = require("../invariant-runner.js");
    invariantVerified = readInvariantVerifiedSummary(domain).verified_by_finding || {};
  } catch {
    invariantVerified = {};
  }

  // The cross-stack composition_path backing leg. A cross-stack finding is backed ONLY by
  // a composition_path evidence_ref whose path_hash is a RE-RESOLVED member of
  // composition-verified.jsonl's verified_path_hashes (bind rows re-MAC-verified at read
  // time, so a forged ledger line does not count). Without this leg the enforce gate is
  // INERT on a cross-stack finding (hasKeyedRowRef only matches exploit_run /
  // repo_command_run). Read once (verdict-LEVEL).
  let verifiedCompositionPathHashes = new Set();
  try {
    // Reuse the caller-precomputed read-time summary when threaded (the gate computes it ONCE
    // per evaluation and shares it across this gate and scBackingUnIsolatedFindingIds, each of
    // which would otherwise re-resolve every bind leaf). Falls back to a fresh re-derivation
    // when called standalone — same authoritative read, never a cached/stale one.
    const summary = compositionSummary
      || require("../differential/composition-live-verifier.js").readCompositionVerifiedSummary(domain);
    if (Array.isArray(summary.verified_path_hashes)) {
      verifiedCompositionPathHashes = new Set(summary.verified_path_hashes);
    }
  } catch {
    verifiedCompositionPathHashes = new Set();
  }

  for (const findingId of reportableIds) {
    if (Object.prototype.hasOwnProperty.call(differentialVerified, findingId)
      || Object.prototype.hasOwnProperty.call(invariantVerified, findingId)) {
      backed.add(findingId);
      continue;
    }
    const claim = claimByFinding.get(findingId);
    if (!claim) {
      // INDETERMINATE BACKING. A reportable medium+ finding reached the
      // final-verification projection but its claim cannot be resolved in either
      // claim index. Whether this is a laundering risk depends on whether the
      // session ACTUALLY DRAWS on a keyed verdict ledger:
      //   * ledgerPresent === true: a keyed verdict-ledger row exists in this
      //     session, so an unresolvable-claim reportable finding has UNKNOWN
      //     (possibly keyed) backing -> FAIL CLOSED (gate it), matching the
      //     not-isolated and legacy/v1 laundering fail-closed posture. The only
      //     safe stance for an indeterminate case over a live keyed ledger is to
      //     require isolation rather than let it escape.
      //   * ledgerPresent === false: NO keyed verdict-ledger row exists anywhere
      //     in the session, so there is nothing to launder — a verification-round
      //     -only / pure-OSINT reportable finding with no claim is NOT
      //     verdict-ledger-backed (the gate's whole premise, reason
      //     no_verdict_ledger_backing). Excluding it here keeps the gate inert on
      //     a clean session, identical to today's pass-through.
      // This never over-gates a genuinely pure-OSINT finding that DID resolve a
      // claim (only finding/http_audit refs, no exploit_run/repo_command_run
      // ref): that finding is excluded by the hasKeyedRowRef branch below.
      if (ledgerPresent) backed.add(findingId);
      continue;
    }
    const refs = Array.isArray(claim.evidence_refs) ? claim.evidence_refs : [];
    const hasKeyedRowRef = refs.some((ref) => (
      ref && (ref.kind === "exploit_run" || ref.kind === "repo_command_run")
    ));
    // The cross-stack composition_path leg: a claim citing a composition_path ref whose
    // path_hash RE-RESOLVES into composition-verified.jsonl's verified_path_hashes is
    // backed by a cross-stack executed verified_pass — gate it like any executed-row
    // backing. A composition_path ref whose path_hash is NOT a re-resolved member does NOT
    // back the finding here (it is a separate cross-stack-gap concern in claims.js).
    const hasVerifiedCompositionPath = refs.some((ref) => (
      ref && ref.kind === "composition_path"
      && typeof ref.path_hash === "string"
      && verifiedCompositionPathHashes.has(ref.path_hash)
    ));
    if (hasKeyedRowRef || hasVerifiedCompositionPath) {
      backed.add(findingId);
    }
    // No claim-freeze leg: freeze membership is NOT a per-finding executed-verdict
    // backing (see the function-level note above). A pure-OSINT reportable finding
    // (no exploit_run/repo_command_run ref, not in either verified summary) is excluded
    // from `backed` even when a freeze containing its claim exists.
  }
  return backed;
}

// Resolve a surface_id's observed kind from the frontier surface.observed events,
// returning the kind string (e.g. "smart_contract") or null. Used to SC-SCOPE the
// finding-differential containerization consult so HTTP differential findings are not
// over-gated. Reads the same payload.kind source the seedScBackedFinding test writes.
// Verdict-LEVEL: one frontier-events read per gate (not per row); any read failure
// resolves null (the differential leg then leaves the finding ungated — HTTP-safe).
function resolveSurfaceKind(domain, surfaceId) {
  if (typeof surfaceId !== "string" || !surfaceId.trim()) return null;
  let events = [];
  try {
    const { readFrontierEvents } = require("../frontier/frontier-events.js");
    events = readFrontierEvents(domain);
  } catch {
    return null;
  }
  let kind = null;
  for (const event of events) {
    if (!event || event.kind !== "surface.observed" || event.surface_id !== surfaceId) continue;
    const payload = event.payload && typeof event.payload === "object" && !Array.isArray(event.payload)
      ? event.payload
      : null;
    if (payload && typeof payload.kind === "string" && payload.kind.trim()) {
      kind = payload.kind.trim();
    }
  }
  return kind;
}

// HIGH-1 PER-FINDING CONTAINERIZATION CONSULT. A smart-contract verdict reaches the
// gate via the invariantVerified leg (readInvariantVerifiedSummary's verified_by_finding)
// OR the finding-differential leg (readFindingDifferentialVerifiedSummary's
// verified_by_finding — offensive rows). The live signer-key probe
// (probeVerdictLedgerKeyIsolation) only measures whether the AGENT-uid process can read
// the key — it stays true on an isolated-signer box. But the SC seam DEGRADES to a host
// spawn AS THE SIGNER when no toolchain image is available, so agent-authored
// Solidity/Move/Rust in the SC test/build runs as the signer and CAN read the 0400 key to
// forge a MAC-valid verdict-ledger row — while the probe still says isolated. So the gate
// must ALSO consult, per finding, whether the backing POSITIVE row was containerized. This
// returns the subset of `findingIds` whose backing positive row is NOT
// container_isolated:true (a degrade-host SC run, or a legacy row predating the field).
// Those findings are treated as un-isolated regardless of the process-level probe:
// blocked under enforce, downgraded under degrade.
//
// TWO LEGS:
//   * INVARIANT leg — every invariantVerified finding is SC by construction (invariant
//     runs are forge/halmos), so it is gated whenever its positive run is not
//     containerized (unchanged behavior).
//   * FINDING-DIFFERENTIAL leg — predominantly HTTP/offensive (cors/idor/nuclei/reflect/
//     xss). Gating EVERY differential-backed finding on container_isolated would wrongly
//     downgrade legit HTTP reportables (RANK != BOUND violation). So this leg is
//     SC-SCOPED: a differential-backed finding is consulted ONLY when it is NOT also
//     invariant-backed (already handled) AND its bound surface resolves to kind
//     smart_contract. An HTTP differential finding (non-SC surface) is left ungated.
//
// Verdict-LEVEL (CONSTRAINT 1): reads the two verified summaries once (already read by
// findingsBackedByKeyedLedger) + one frontier-events read for SC-scoping; never per-row
// MAC re-derivation (CONSTRAINT 6 untouched — container_isolated is a recorded MAC-covered
// field, re-resolved from the positive row).
function scBackingUnIsolatedFindingIds(domain, findingIds, { compositionSummary = null } = {}) {
  const unIsolated = new Set();
  if (!(findingIds instanceof Set) || findingIds.size === 0) return unIsolated;
  let invariantVerified = {};
  try {
    const { readInvariantVerifiedSummary } = require("../invariant-runner.js");
    invariantVerified = readInvariantVerifiedSummary(domain).verified_by_finding || {};
  } catch {
    invariantVerified = {};
  }
  let differentialVerified = {};
  try {
    const { readFindingDifferentialVerifiedSummary } = require("../differential/finding-differential-verifier.js");
    differentialVerified = readFindingDifferentialVerifiedSummary(domain).verified_by_finding || {};
  } catch {
    differentialVerified = {};
  }
  // The cross-stack composition_path isolation map: a re-resolved cross-stack path is
  // trusted-isolated iff EVERY backing invariant arm (positive/control/decoy) ran
  // container_isolated. Read once (verdict-LEVEL). A cross-stack finding whose backing
  // path is NOT in this map (or maps false) is treated as un-isolated, mirroring the
  // single-surface invariant posture — the cross-stack mint wrote a third ledger
  // (composition-verified.jsonl) the SC isolation consult previously never read.
  let crossStackVerifiedHashes = new Set();
  let crossStackContainerIsolated = {};
  let claims = [];
  try {
    // Reuse the caller-precomputed read-time summary when threaded (shared with
    // findingsBackedByKeyedLedger in one gate evaluation); fall back to a fresh re-derivation
    // when called standalone — same authoritative read, never a cached/stale one.
    const summary = compositionSummary
      || require("../differential/composition-live-verifier.js").readCompositionVerifiedSummary(domain);
    if (Array.isArray(summary.verified_cross_stack_path_hashes)) {
      crossStackVerifiedHashes = new Set(summary.verified_cross_stack_path_hashes);
    }
    if (summary.verified_cross_stack_path_container_isolated
      && typeof summary.verified_cross_stack_path_container_isolated === "object") {
      crossStackContainerIsolated = summary.verified_cross_stack_path_container_isolated;
    }
  } catch {
    crossStackVerifiedHashes = new Set();
    crossStackContainerIsolated = {};
  }
  try {
    const { readCandidateClaims } = require("../claims/claims.js");
    claims = readCandidateClaims(domain);
  } catch {
    claims = [];
  }
  // Resolve each finding -> the composition_path evidence_refs on its claim (dual index by
  // payload.finding.id and a kind:"finding" evidence_ref), so a cross-stack finding's
  // backing path_hash is recoverable for the isolation consult.
  const compositionPathHashesByFinding = new Map();
  for (const claim of claims) {
    if (!claim || typeof claim !== "object") continue;
    const refs = Array.isArray(claim.evidence_refs) ? claim.evidence_refs : [];
    const pathHashes = refs
      .filter((ref) => ref && ref.kind === "composition_path" && typeof ref.path_hash === "string" && ref.path_hash)
      .map((ref) => ref.path_hash);
    if (pathHashes.length === 0) continue;
    const payloadFinding = claim.payload && typeof claim.payload === "object" && !Array.isArray(claim.payload)
      ? claim.payload.finding : null;
    const payloadFindingId = payloadFinding && typeof payloadFinding === "object" ? payloadFinding.id : null;
    if (typeof payloadFindingId === "string") {
      const set = compositionPathHashesByFinding.get(payloadFindingId) || new Set();
      for (const h of pathHashes) set.add(h);
      compositionPathHashesByFinding.set(payloadFindingId, set);
    }
    for (const ref of refs) {
      if (ref && ref.kind === "finding" && typeof ref.finding_id === "string") {
        const set = compositionPathHashesByFinding.get(ref.finding_id) || new Set();
        for (const h of pathHashes) set.add(h);
        compositionPathHashesByFinding.set(ref.finding_id, set);
      }
    }
  }
  for (const findingId of findingIds) {
    // INVARIANT leg: every invariant verdict is an SC run; gate on containerization.
    if (Object.prototype.hasOwnProperty.call(invariantVerified, findingId)) {
      const entry = invariantVerified[findingId];
      // A backing SC verdict whose re-resolved positive run was NOT containerized
      // (degrade-host-as-signer, or a legacy row) cannot be trusted. Fail closed:
      // absence of container_isolated:true => un-isolated.
      if (!entry || entry.container_isolated !== true) {
        unIsolated.add(findingId);
      }
      continue;
    }
    // COMPOSITION-PATH leg (cross-stack): a finding backed by a cross-stack composition_path
    // whose backing arms degraded (host-as-signer) is un-isolated. This mirrors the single-
    // surface invariant posture for the cross-stack path the mint-side adjudicator now
    // refuses, so a row admitted under degrade is still treated as un-isolated at report
    // time. Consult ONLY a path that re-resolves into the cross-stack verified set.
    const pathHashes = compositionPathHashesByFinding.get(findingId);
    if (pathHashes && pathHashes.size > 0) {
      let consultedCrossStack = false;
      let anyUnIsolated = false;
      for (const h of pathHashes) {
        if (!crossStackVerifiedHashes.has(h)) continue;
        consultedCrossStack = true;
        if (crossStackContainerIsolated[h] !== true) anyUnIsolated = true;
      }
      if (consultedCrossStack) {
        if (anyUnIsolated) unIsolated.add(findingId);
        continue;
      }
    }
    // FINDING-DIFFERENTIAL leg (belt-and-suspenders): SC-SCOPED so HTTP differential
    // findings are unaffected. Consult ONLY when the finding's bound surface is a
    // smart_contract surface; otherwise leave it ungated (RANK != BOUND preserved).
    if (Object.prototype.hasOwnProperty.call(differentialVerified, findingId)) {
      const entry = differentialVerified[findingId];
      const boundSurface = entry && typeof entry.surface_id === "string" ? entry.surface_id : null;
      const surfaceKind = resolveSurfaceKind(domain, boundSurface);
      if (surfaceKind !== "smart_contract") continue;
      // An SC finding-differential-backed reportable whose backing positive offensive
      // run was NOT containerized cannot be trusted. Fail closed (offensive rows do not
      // carry container_isolated today, so this re-resolves false — un-isolated).
      if (!entry || entry.container_isolated !== true) {
        unIsolated.add(findingId);
      }
    }
  }
  return unIsolated;
}

// THE verdict-level decision both seams consume. Pure of any throw/write so the
// callers shape the consequence (blocker vs ToolError vs section downgrade).
//
// Returns a frozen object:
//   applies            : the gate is active (a reportable medium+ finding exists
//                        AND the session draws on a keyed verdict ledger).
//   mode               : "enforce" | "degrade" (resolved, platform-aware).
//   mode_defaulted     : the mode came from the platform default (no explicit env).
//   isolated           : the LIVE probe proved signer isolation (the load-bearing
//                        leg). false on the same-uid box.
//   attested           : isolated AND the operator env ack/uid bind (stricter; for
//                        forensics/telemetry — the gate decision keys off isolated).
//   has_legacy_or_v1   : at least one verdict-ledger row is unsigned or v1-HMAC
//                        (the laundering-risk class).
//   sc_backing_not_containerized : at least one gated finding's SC backing positive
//                        row was NOT containerized (a degrade-host-as-signer SC run).
//                        Consults BOTH the invariantVerified leg (every invariant run is
//                        SC) AND the finding-differential leg SC-SCOPED to smart_contract
//                        surfaces (HTTP differential findings unaffected). Forces
//                        block/downgrade even when the live signer probe says isolated
//                        (HIGH-1).
//   reportable_finding_ids : the reportable medium+ findings INTERSECTED with the
//                        per-finding keyed-ledger-backed set (RANK != BOUND — only
//                        these are ever blocked/downgraded; a pure-OSINT reportable
//                        finding is excluded even when an unrelated ledger row exists).
//   decision           : "allow" | "block" | "downgrade".
//   reason             : a legible machine code for the decision.
//   probe              : the raw live probe record (forensic).
function evaluateVerdictSandboxGate(domain, env = process.env, platform = process.platform) {
  const reportable = reportableMediumPlusFindingIds(domain);
  const ledger = verdictLedgerMacClasses(domain);
  const { mode, defaulted } = resolveSandboxAttestationMode(env, platform);

  // RANK != BOUND, PER FINDING: only findings whose OWN evidence cites a keyed
  // verdict-ledger row are ever gated. A pure-OSINT reportable finding is UNAFFECTED
  // even when an UNRELATED finding wrote an offensive/invariant/repo/freeze row.
  // findingsBackedByKeyedLedger reads claims/summaries/freeze ONCE, only when the
  // reportable set is non-empty (it early-returns an empty set otherwise, so a clean
  // session never touches claims).
  //
  // Compute the read-time cross-stack summary ONCE for this evaluation and share it across
  // BOTH consulting gates (here + scBackingUnIsolatedFindingIds). Each compute re-resolves
  // every bind leaf's refs and re-hashes cause/decoy bytes (O(rows × refs)), so a single
  // synchronous pass should derive it once, not per gate. Sharing one instance within this
  // pass is sound — no ledger is written mid-gate, so a re-derivation would return the same
  // result. Guarded on reportable.size>0 (the exact condition under which the gates read it),
  // so a clean/empty session still skips the derivation entirely.
  let compositionSummary = null;
  if (reportable.size > 0) {
    try {
      compositionSummary = require("../differential/composition-live-verifier.js").readCompositionVerifiedSummary(domain);
    } catch {
      compositionSummary = null;
    }
  }
  const backed = findingsBackedByKeyedLedger(domain, reportable, { ledgerPresent: ledger.present, compositionSummary });
  const gatedIds = new Set([...reportable].filter((id) => backed.has(id)));

  // Inert: no reportable medium+ finding, OR none of the reportable findings is
  // backed by a keyed verdict-ledger row. A clean / pure-OSINT / advisory-only
  // session passes untouched.
  if (gatedIds.size === 0) {
    return Object.freeze({
      applies: false,
      mode,
      mode_defaulted: defaulted,
      isolated: null,
      attested: null,
      has_legacy_or_v1: ledger.hasLegacyOrV1,
      sc_backing_not_containerized: false,
      reportable_finding_ids: [],
      decision: "allow",
      reason: reportable.size === 0 ? "no_reportable_medium_plus" : "no_verdict_ledger_backing",
      probe: null,
    });
  }

  // The LIVE re-probe — never the stored file flag (forward-note ii).
  const probe = probeVerdictLedgerKeyIsolation(domain);
  // evaluateSandboxIsolation binds the operator env (ack + declared uid). It
  // probes the SYMMETRIC key today; we recompute attested off the LIVE ed25519
  // probe so the forensic `attested` matches the gated secret. The decision keys
  // off probe.isolated (the load-bearing leg), with the env bind as the strict
  // reading of attestation for telemetry.
  let envEval = null;
  try {
    envEval = evaluateSandboxIsolation(domain);
  } catch {
    envEval = null;
  }
  const operatorAck = !!(envEval && envEval.operator && envEval.operator.ack_present);
  const declaredUid = envEval && envEval.operator ? envEval.operator.declared_signer_uid : null;
  const attested = Boolean(
    probe.isolated && operatorAck && declaredUid != null && probe.owner_uid === declaredUid,
  );
  const hasLegacyOrV1 = ledger.hasLegacyOrV1;

  // HIGH-1: per-finding containerization consult. Even when the live signer-key
  // probe says isolated, an SC verdict backed by a NON-containerized (degrade-host
  // -as-signer) positive row cannot be trusted — agent-authored Solidity/Move/Rust ran
  // AS THE SIGNER and could forge a MAC-valid row. Any gated finding whose SC backing
  // positive row is not container_isolated:true makes the gate behave as un-isolated for
  // that finding (block/downgrade). Consults BOTH legs: the invariantVerified leg (every
  // invariant run is SC) and the finding-differential leg SC-SCOPED to smart_contract
  // surfaces (HTTP differential findings unaffected — belt-and-suspenders to the seam
  // refuse, which once all seven runners thread targetDomain prevents the unsafe run
  // entirely on an isolated box).
  const scUnIsolated = scBackingUnIsolatedFindingIds(domain, gatedIds, { compositionSummary });
  const scBackingNotContainerized = scUnIsolated.size > 0;

  // Isolated AND no laundering-risk row AND every SC backing row is containerized
  // => allow. The signer is genuinely out-of-uid, every backing row is an
  // asymmetric ed25519 MAC, and no SC verdict rests on a host-as-signer run.
  if (probe.isolated && !hasLegacyOrV1 && !scBackingNotContainerized) {
    return Object.freeze({
      applies: true,
      mode,
      mode_defaulted: defaulted,
      isolated: true,
      attested,
      has_legacy_or_v1: false,
      sc_backing_not_containerized: false,
      reportable_finding_ids: [...gatedIds],
      decision: "allow",
      reason: "isolated_signer_ed25519_only",
      probe,
    });
  }

  // Not isolated, OR a legacy/v1-HMAC row is among the backing rows, OR an SC
  // verdict rests on a non-containerized (degrade-host-as-signer) backing row.
  // Under enforce we BLOCK the verdict-ledger-backed reportable medium+ claim;
  // under degrade we DOWNGRADE it to advisory + warn loudly. Never silent either
  // way. Reason precedence: an un-isolated signer dominates (the broadest failure),
  // then a laundering-risk row, then the SC-containerization failure (which can fire
  // even with an isolated signer and all-ed25519 rows).
  const reason = !probe.isolated
    ? "signer_not_isolated"
    : (hasLegacyOrV1
      ? "legacy_or_v1_hmac_row_backs_new_claim"
      : "sc_backing_not_containerized");
  return Object.freeze({
    applies: true,
    mode,
    mode_defaulted: defaulted,
    isolated: probe.isolated,
    attested,
    has_legacy_or_v1: hasLegacyOrV1,
    sc_backing_not_containerized: scBackingNotContainerized,
    reportable_finding_ids: [...gatedIds],
    decision: mode === "enforce" ? "block" : "downgrade",
    reason,
    probe,
  });
}

// Build the loud, legible warning string for the degrade path. CONSTRAINT 5:
// degrade is NEVER silent. The string is emitted to stderr here AND returned in
// the gate-result the callers fold into their own audit-graded output (the grade
// verdict's blockers/notes and the bob_compose_report result), so a stripped /
// headless harness that discards stderr still sees the downgrade in the
// structured result. No new pipeline-event type is introduced (no registry
// churn): the durable channels are stderr + the caller's existing artifacts.
function sandboxDowngradeWarning(decision, context) {
  return (
    `SANDBOX ISOLATION ${decision.reason === "signer_not_isolated" ? "UNATTESTED" : "DEGRADED"}: `
    + `${context} downgrading ${decision.reportable_finding_ids.length} verdict-ledger-backed `
    + `reportable medium+ finding(s) to advisory (mode=degrade, reason=${decision.reason}). `
    + SANDBOX_REMEDIATION
  );
}

// Emit the degrade warning loudly to stderr (best-effort; never throws). Returns
// the message so the caller can ALSO fold it into its structured result.
function emitSandboxDowngradeWarning(decision, context) {
  const message = sandboxDowngradeWarning(decision, context);
  try {
    process.stderr.write(`${message}\n`);
  } catch {
    // stderr unavailable; the returned message is folded into the structured
    // result by the caller, which is the durable channel.
  }
  return message;
}

module.exports = {
  SANDBOX_ISOLATION_BLOCKER_CODE,
  SANDBOX_REMEDIATION,
  MEDIUM_OR_HIGHER_SEVERITIES,
  classifyMacEnvelope,
  verdictLedgerMacClasses,
  reportableMediumPlusFindingIds,
  findingsBackedByKeyedLedger,
  readFinalVerificationByFinding,
  evaluateVerdictSandboxGate,
  sandboxDowngradeWarning,
  emitSandboxDowngradeWarning,
};
