"use strict";

const fs = require("fs");

// Composition LIVE verifier — SC1 confirm-half, mechanism-agnostic dispatcher.
//
// The offline composition harness (composition-experiment-harness.js) is a SHAPE
// gate: it confirms a path's leaves are replay-shaped, discriminating, and
// tamper-evident, and carries that as `verification_required: true`. It executes
// nothing, so a self-consistent counterfeit observation passes it. This module is
// the semantic half: a DISPATCHER that resolves each leaf to a registered verifier
// template by edge_type (mechanism-template-registry.js), RE-EXECUTES that
// mechanism's control battery live, re-derives its deterministic verdict, and only
// mints a `verified_pass` when the verdict reproduces and AGREES with the leaf's
// offline claim. A counterfeit flip dies here because the negative control is
// actually re-run and must classify to the opposite reached state. The dispatcher
// is mechanism-blind: it reads the executed verdict's disposition, never a
// predicate name, to adjudicate the flip.
//
// Producer-independence is structural, enforced at the INTEGRITY boundary, not by
// the producer's good behavior:
//   1. This is the only writer of composition-verified.jsonl, which is audit-graded
//      (paths.js AUDIT_GRADED_BASENAMES) — agents cannot Write-forge it.
//   2. It emits NO frontier event — adding observation.recorded events is the exact
//      laundering surface the offline gate cannot defend, so the verified record
//      lives ONLY in the protected ledger that SC1 grades on (LV-3 telemetry).
//   3. The leaf's live re-execution inputs (primary + control_plan) are re-issued
//      by the resolved template; the verdict is re-derived from the bytes it
//      captured, not from the producer's claimed request/response.
//
// Open-vocab scope: an edge_type with a registered template is live-verifiable; the
// object-auth `guard` edge is the registered template today. Every edge_type with
// NO registered template, and any leaf lacking that mechanism's re-execution
// inputs, returns `inconclusive` — never a producer-string fallback, never a
// verified_pass. A new mechanism is added by registering its template, not by
// editing this dispatcher.
//
// TWO verification kinds share this dispatcher and the same composition-verified.jsonl
// ledger keyed by path_hash:
//   1. RE-EXECUTE (guard): the registered-template path above re-runs the mechanism's
//      control battery live (object-auth today).
//   2. BIND (cross-stack): a leaf carrying positive_run_ref + control_run_ref BINDS two
//      ALREADY-EXECUTED MAC-signed rows (offensive-runs web / invariant-runs EVM-SC),
//      possibly on different surfaces/stacks, and confirms the executed flip WITHOUT
//      re-executing (cross-stack-differential-verifier.js). The bind branch is shape-
//      routed (presence of both refs) BEFORE the edge_type template lookup, so the
//      object-auth guard re-execution path is untouched/byte-identical. A bind leaf's
//      edge_type is open-vocab and purely annotational (shape-validated, not a dispatch
//      key).

const {
  runPathCompositionExperiment,
  resolveSynthesizedDifferentialVerdict,
} = require("./composition-experiment-harness.js");
const {
  readFrontierEvents,
} = require("./frontier-events.js");
const {
  lookupVerifierTemplate,
} = require("./mechanism-template-registry.js");
const {
  makePerCallHttpScanFetcher,
} = require("./http-scan-adapter.js");
const {
  validateHttpScanScope,
} = require("./scope.js");
const {
  assertSafeDomain,
  compositionVerifiedJsonlPath,
} = require("./paths.js");
const {
  appendJsonlLine,
  withSessionLock,
} = require("./storage.js");
const {
  hashCanonicalJson,
} = require("./verification-contracts.js");
const {
  emitVerifiedInterventionSignal,
} = require("./belief/outcome-bridge.js");
const {
  isBindLeaf,
  resolveBoundDifferentialLeaf,
  reverifyCrossStackLeaf,
} = require("./cross-stack-differential-verifier.js");

// F4 — execution-keyed membership identity. For a bind-bearing path the binding key is
// derived from the SORTED set of its bind leaves' execution_keys (each keyed on the
// executed (positive, control, cause) row-hash tuple), NOT the agent-supplied evidence_ref
// / edge_type annotation. So one real flipping triple called N times with different
// annotations collapses to ONE membership entry -> ONE claim. A guard-only path keeps its
// annotational hash byte-identical (it has no bind leaf), so the object-auth re-execute
// path's path_hash is unchanged.
function pathMembershipHash(fullHash, leaves) {
  const hasBind = Array.isArray(leaves) && leaves.some((l) => l && l.bind === true);
  if (!hasBind) return fullHash; // guard-only: unchanged annotational hash.
  const tokens = leaves.map((l) => (l && l.bind === true
    ? { exec: l.execution_key ?? null }
    : { ev: (l && typeof l.evidence_ref === "string" ? l.evidence_ref : null) }));
  // Canonical-sorted set so leaf ORDER and annotation never perturb the membership key.
  const sorted = tokens
    .map((t) => hashCanonicalJson(t))
    .sort()
    .map((h) => ({ leaf: h }));
  return hashCanonicalJson(sorted);
}

const COMPOSITION_VERIFIED_VERSION = 1;
const COMPOSITION_VERIFIED_MAX_RECORDS = 2000;
const EVIDENCE_REF_PREFIX = "frontier_event:";

// Path-level outcomes.
const RESULT_VERIFIED_PASS = "verified_pass";
const RESULT_REFUTED = "refuted";
const RESULT_INCONCLUSIVE = "inconclusive";
const RESULT_OFFLINE_REFUSED = "offline_refused";

// Per-leaf outcomes.
const LEAF_VERIFIED = "verified";
const LEAF_REFUTED = "refuted";
const LEAF_INCONCLUSIVE = "inconclusive";

function indexEventsById(events) {
  const index = new Map();
  for (const event of events) {
    if (event && typeof event.event_id === "string") index.set(event.event_id, event);
  }
  return index;
}

function leafEventId(leaf) {
  const ref = leaf && typeof leaf === "object" ? leaf.evidence_ref : null;
  if (typeof ref !== "string" || !ref.startsWith(EVIDENCE_REF_PREFIX)) return null;
  return ref.slice(EVIDENCE_REF_PREFIX.length);
}

// Verify one leaf by dispatching to its edge_type's registered verifier template
// and re-executing that mechanism's control battery. `offlineEvent` is the resolved
// observation.recorded the offline gate already accepted. Returns a per-leaf record;
// never throws on a probe failure (that becomes inconclusive).
async function verifyLeaf(leaf, offlineEvent, ctx) {
  const base = {
    edge_id: leaf && typeof leaf.edge_id === "string" ? leaf.edge_id : null,
    evidence_ref: leaf && typeof leaf.evidence_ref === "string" ? leaf.evidence_ref : null,
  };
  const payload = offlineEvent && offlineEvent.payload && typeof offlineEvent.payload === "object"
    ? offlineEvent.payload
    : {};
  const edgeType = typeof payload.edge_type === "string" ? payload.edge_type : null;
  const claimedVerdict = typeof payload.verdict === "string" ? payload.verdict : null;
  base.edge_type = edgeType;
  base.claimed_verdict = claimedVerdict;

  // Dispatch by edge_type to a registered verifier template (open-vocab; the lookup
  // is the rail, not a hardcoded edge_type). No template for an edge_type =>
  // inconclusive (annotate-don't-gate), NOT a producer-string fallback.
  const template = lookupVerifierTemplate(edgeType);
  if (!template) {
    return { ...base, leaf_status: LEAF_INCONCLUSIVE, reason: `edge_type '${edgeType}' has no registered verifier template; register a mechanism template, or for a cross-stack mechanism supply positive_run_ref+control_run_ref executed-row evidence` };
  }
  // The template owns this leaf only when it carries the mechanism's live
  // re-execution inputs (for object-auth: primary + control_plan).
  if (!template.discriminator_predicate(leaf)) {
    return { ...base, leaf_status: LEAF_INCONCLUSIVE, reason: "guard leaf lacks live re-execution inputs (primary + control_plan)" };
  }

  // Bind the live re-execution to the offline leaf via the template's geometry: the
  // battery must be a genuine cross-principal SAME-object differential aimed at the
  // object the offline observation names, on the same origin. Otherwise the verifier
  // would prove a DIFFERENT predicate than the leaf claims — refuse, never mint.
  const planViolations = template.plan_validator(payload.request, ctx.base_url, leaf.primary, leaf.control_plan);
  if (planViolations.length > 0) {
    return { ...base, leaf_status: LEAF_INCONCLUSIVE, reason: `control plan is not a cross-principal same-object battery bound to the leaf: ${planViolations.join("; ")}` };
  }

  let probe;
  try {
    probe = await template.live_verifier(ctx, leaf);
  } catch (err) {
    return { ...base, leaf_status: LEAF_INCONCLUSIVE, reason: `probe error: ${err && err.message ? err.message : String(err)}` };
  }

  const verdict = template.differential_evaluator(probe);
  const leafRecord = {
    ...base,
    disposition: verdict.disposition,
    live_verdict_hash: verdict.verdict_hash,
    degraded_controls: probe.degraded_controls,
    primary_reached: probe.primary_effect.reached === true,
    primary_body_match: probe.primary_effect.body_match,
  };

  // A leaf is verified ONLY when the live re-derivation is confirmed AND it agrees
  // with the leaf's offline claim. Live-denied contradicts the claim -> refuted.
  // Live-inconclusive (missing/degraded controls) -> inconclusive.
  if (verdict.disposition === "confirmed") {
    if (claimedVerdict === "confirmed") {
      return { ...leafRecord, leaf_status: LEAF_VERIFIED };
    }
    return { ...leafRecord, leaf_status: LEAF_REFUTED, reason: `live confirmed but leaf claimed '${claimedVerdict}'` };
  }
  if (verdict.disposition === "denied") {
    return { ...leafRecord, leaf_status: LEAF_REFUTED, reason: `live re-execution denied: ${verdict.reason}` };
  }
  return { ...leafRecord, leaf_status: LEAF_INCONCLUSIVE, reason: `live re-execution inconclusive: ${verdict.reason}` };
}

// The path_hash for the full ordered path, computed with the SAME formula
// runPathCompositionExperiment uses (hashCanonicalJson over the ordered evidence_ref
// sequence, null for a missing ref). For a guard-only path it equals the offline
// run's path_hash byte-for-byte; for a path carrying bind leaves (which need no
// guard observation) it remains stable and ordered.
function fullPathHash(path) {
  return hashCanonicalJson(
    path.map((leaf) => (leaf && typeof leaf === "object" ? leaf.evidence_ref ?? null : null)),
  );
}

// verifyCompositionPath — verify a composition path and mint a verified_pass only when
// every leaf resolves. Two leaf kinds compose in one path:
//   * a GUARD leaf is RE-EXECUTED (the offline shape gate is its hard precondition, then
//     its registered template re-runs the control battery live);
//   * a BIND leaf (positive_run_ref + control_run_ref) BINDS two already-executed MAC-
//     signed rows and confirms the cross-stack flip without re-executing — it bypasses
//     the offline shape gate (it has no guard observation to shape-check) and the HTTP
//     fetcher.
//
// input: { target_domain, base_url, path: [ { evidence_ref, edge_id, primary, control_plan }
//          | { positive_run_ref, control_run_ref, edge_type } ], block_internal_hosts?,
//          egress_profile? }
// deps:  { httpScanFn }  (injected so tests run without a network)
async function verifyCompositionPath(input, deps = {}) {
  if (input == null || typeof input !== "object") {
    throw new TypeError("input must be { target_domain, base_url, path }");
  }
  const targetDomain = assertSafeDomain(input.target_domain);
  if (!Array.isArray(input.path) || input.path.length === 0) {
    throw new Error("path must contain at least one leaf edge");
  }
  if (typeof deps.httpScanFn !== "function") {
    throw new TypeError("deps.httpScanFn must be a function");
  }

  // Partition leaves: bind leaves (cross-stack, resolve already-executed rows) bypass the
  // offline shape gate and the HTTP fetcher; guard leaves keep the byte-identical
  // re-execute path. A guard-only path has NO bind leaves, so the offline gate runs over
  // the full path exactly as before.
  const guardLeaves = input.path.filter((leaf) => !isBindLeaf(leaf));
  const hasBindLeaf = guardLeaves.length < input.path.length;

  // Step 1: the offline shape gate is a hard precondition FOR THE GUARD LEAVES. A guard
  // leaf that is not even replay-shaped cannot be live-verified — there is nothing
  // trustworthy to re-run. Bind leaves are excluded (they have no guard observation; the
  // executed rows they bind are the trust source). A path of only bind leaves skips the
  // offline gate; its offline_result is recorded as "bind".
  const offline = guardLeaves.length > 0
    ? runPathCompositionExperiment(targetDomain, {
        path: guardLeaves.map((leaf) => ({
          evidence_ref: leaf && leaf.evidence_ref,
          edge_id: leaf && leaf.edge_id,
        })),
      })
    : { result: "bind", path_hash: null };

  const pathHash = fullPathHash(input.path);

  const fetch_fn = makePerCallHttpScanFetcher({
    httpScanFn: deps.httpScanFn,
    target_domain: targetDomain,
    block_internal_hosts: input.block_internal_hosts,
    egress_profile: input.egress_profile,
  });
  const ctx = {
    target_domain: targetDomain,
    base_url: input.base_url,
    fetch_fn,
    validate_scope_fn: (url, td) => validateHttpScanScope(url, td || targetDomain),
  };
  const bindCtx = { target_domain: targetDomain };

  const index = indexEventsById(readFrontierEvents(targetDomain));
  const leaves = [];
  let result;

  if (guardLeaves.length > 0 && offline.result !== "pass") {
    // The offline gate refused a guard leaf; record the refusal without re-executing or
    // binding anything (a malformed guard leaf taints the whole path).
    result = RESULT_OFFLINE_REFUSED;
  } else {
    for (const leaf of input.path) {
      if (isBindLeaf(leaf)) {
        // BIND: resolve two already-executed MAC-signed rows and confirm the cross-stack
        // flip. No HTTP fetch, no offline observation.
        leaves.push(resolveBoundDifferentialLeaf(leaf, bindCtx));
        continue;
      }
      const eventId = leafEventId(leaf);
      const offlineEvent = eventId ? index.get(eventId) : null;
      // The offline gate already proved every guard leaf resolves to a typed observation,
      // so offlineEvent is present; guard defensively regardless.
      // eslint-disable-next-line no-await-in-loop
      const leafRecord = await verifyLeaf(leaf, offlineEvent, ctx);
      leaves.push(leafRecord);
    }
    const anyRefuted = leaves.some((l) => l.leaf_status === LEAF_REFUTED);
    const allVerified = leaves.every((l) => l.leaf_status === LEAF_VERIFIED);
    if (anyRefuted) result = RESULT_REFUTED;
    else if (allVerified) result = RESULT_VERIFIED_PASS;
    else result = RESULT_INCONCLUSIVE;
  }

  const verifiedLeafCount = leaves.filter((l) => l.leaf_status === LEAF_VERIFIED).length;
  // F4 — the BINDING key is the execution-keyed membership hash for a bind-bearing path
  // (independent of the agent-supplied evidence_ref / edge_type annotation), and the
  // unchanged annotational hash for a guard-only path. `path_hash` (the field consumers
  // bind on, returned to the caller, and declared by the agent on the Contract /
  // composition_path ref) is THIS key. The annotational hash is retained verbatim under
  // annotation_path_hash for human readability, but binding is on the execution key only.
  const membershipHash = pathMembershipHash(pathHash, leaves);
  const body = {
    version: COMPOSITION_VERIFIED_VERSION,
    target_domain: targetDomain,
    ts: new Date().toISOString(),
    result,
    offline_result: offline.result,
    path_hash: membershipHash,
    leaf_count: input.path.length,
    verified_leaf_count: verifiedLeafCount,
    leaves,
  };
  // A guard-only path's record is byte-identical to before (no bind annotation, and
  // membershipHash === pathHash so path_hash is unchanged). Only a path that actually
  // carries a cross-stack bind leaf adds has_bind_leaf + annotation_path_hash, so the
  // re-execute path's records and results_hash are unchanged.
  if (hasBindLeaf) {
    body.has_bind_leaf = true;
    body.annotation_path_hash = pathHash;
  }
  const record = { ...body, results_hash: hashCanonicalJson(body) };

  withSessionLock(targetDomain, () => {
    appendJsonlLine(compositionVerifiedJsonlPath(targetDomain), record, {
      maxRecords: COMPOSITION_VERIFIED_MAX_RECORDS,
    });
  });

  // Outcome-bridge: ONE-WAY executed-reality -> belief, advisory only. This runs
  // strictly AFTER the audit-graded append and is internally try/catch-swallowed, so
  // a belief write failure can never alter `result` or composition-verified.jsonl.
  // Only a verified_pass with LEAF_VERIFIED leaves emits anything; each emitted
  // record is tagged with this row's results_hash and sharpens exactly the matching
  // request_equivalence latent. NO frontier event, NO grade/claim write (NO GATING).
  if (result === RESULT_VERIFIED_PASS) {
    emitVerifiedInterventionSignal({
      target_domain: targetDomain,
      base_url: input.base_url,
      path: input.path,
      leaves: leaves.map((leaf) => ({ ...leaf, results_hash: record.results_hash })),
      event_index: index,
      leaf_verified_status: LEAF_VERIFIED,
    });
  }

  return {
    target_domain: targetDomain,
    result,
    offline_result: offline.result,
    // The BINDING key (F4): membership hash for a bind path, annotational hash for a
    // guard-only path. The agent declares THIS on the Contract / composition_path ref.
    path_hash: membershipHash,
    leaf_count: input.path.length,
    verified_leaf_count: verifiedLeafCount,
    results_hash: record.results_hash,
    leaves,
  };
}

// Summarize the verified_pass ledger for SC1 grading. This is the AUTHORITATIVE
// SC1 confirm-half signal — it reads the MCP-write-only composition-verified.jsonl
// (audit-graded), never a frontier event, so the count cannot be hand-forged.
function readCompositionVerifiedSummary(domain) {
  const targetDomain = assertSafeDomain(domain);
  let records = [];
  try {
    const raw = fs.readFileSync(compositionVerifiedJsonlPath(targetDomain), "utf8");
    records = raw
      .split("\n")
      .filter((line) => line.trim())
      .map((line) => { try { return JSON.parse(line); } catch { return null; } })
      .filter(Boolean);
  } catch {
    records = [];
  }
  const verified = records.filter((r) => r.result === RESULT_VERIFIED_PASS);
  // READ-TIME RE-VERIFICATION (bind rows only). A guard verified_pass row keeps its
  // existing path — it was minted by a live re-execution that cannot be replayed here.
  // A BIND verified_pass row (has_bind_leaf) is NOT trusted on its stored result:
  // composition-verified.jsonl's results_hash is an UNKEYED self-hash, so a same-uid
  // direct-disk write could append a bare forged bind verified_pass line whose run refs
  // point at nothing. Each bind leaf is RE-RESOLVED (MAC-verified) and the flip is
  // RE-ADJUDICATED from the signed source rows; the record's path_hash enters the
  // membership set ONLY when EVERY bind leaf re-verifies ok. Fail-closed on a rotated /
  // truncated source ledger.
  // Re-verify a record's bind leaves AND re-derive its EXECUTION-keyed membership hash
  // from the RE-RESOLVED rows (F4). Returns the membership hash to admit into the binding
  // set, or null to EXCLUDE the row. A guard-only row admits its stored path_hash
  // unchanged. A bind row admits the membership hash recomputed from the re-resolved
  // execution_keys — NOT the stored path_hash — so a direct-appended row whose claimed
  // path_hash does not match its executed rows can never enter the binding set.
  // Returns { hash, crossStack, surfaceRefs } where `hash` is the membership hash to admit
  // (or null to EXCLUDE the row), `crossStack` is true iff the row has a bind leaf AND at
  // least one re-verified bind leaf is is_cross_stack (HIGH-3 — a guard-only row or a same-
  // family bind row is NOT cross-stack), and `surfaceRefs` is the UNION of the re-resolved
  // bind leaves' surface_refs (HIGH-2 — used to reconcile the bound path against the
  // consuming claim/node surfaces). A guard-only row admits its stored path_hash with
  // crossStack:false and no surface_refs.
  const recordBindMembership = (record) => {
    if (record.has_bind_leaf !== true) {
      const h = typeof record.path_hash === "string" && record.path_hash ? record.path_hash : null;
      return { hash: h, crossStack: false, surfaceRefs: [], containerIsolated: true };
    }
    const leaves = Array.isArray(record.leaves) ? record.leaves : [];
    const bindLeaves = leaves.filter((l) => l && l.bind === true);
    if (bindLeaves.length === 0) return { hash: null, crossStack: false, surfaceRefs: [], containerIsolated: false }; // claims bind but carries none: fail closed
    const reLeaves = [];
    let anyCrossStack = false;
    // Every re-verified bind leaf's positive arm must be container_isolated for the path to
    // be trusted-isolated. Default true (no bind leaf flips it false), then AND each leg.
    let allContainerIsolated = true;
    const surfaceRefSet = new Set();
    for (const leaf of leaves) {
      if (leaf && leaf.bind === true) {
        const re = reverifyCrossStackLeaf(targetDomain, leaf);
        if (!re.ok) return { hash: null, crossStack: false, surfaceRefs: [], containerIsolated: false }; // any bind leaf fails -> exclude the whole row
        reLeaves.push({ bind: true, execution_key: re.execution_key });
        if (re.is_cross_stack === true) anyCrossStack = true;
        if (re.container_isolated !== true) allContainerIsolated = false;
        if (Array.isArray(re.surface_refs)) {
          for (const ref of re.surface_refs) {
            if (typeof ref === "string" && ref) surfaceRefSet.add(ref);
          }
        }
      } else {
        // A guard leaf inside a bind-bearing path contributes its annotation verbatim,
        // mirroring pathMembershipHash so a mixed path re-derives identically.
        reLeaves.push({ bind: false, evidence_ref: leaf && typeof leaf.evidence_ref === "string" ? leaf.evidence_ref : null });
      }
    }
    // Recompute the membership hash from the re-resolved leaves (fullHash unused for a
    // bind-bearing path, so a placeholder is harmless — pathMembershipHash branches on
    // hasBind and never reads it).
    return { hash: pathMembershipHash(null, reLeaves), crossStack: anyCrossStack, surfaceRefs: Array.from(surfaceRefSet), containerIsolated: allContainerIsolated };
  };
  // The full set of EXECUTION-keyed membership hashes of EVERY executed verified_pass row
  // for the domain whose bind leaves (if any) re-verify. The consumer binds a verdict iff
  // THIS execution key is a member, so binding is execution-precise: a different verified
  // path no longer satisfies the binding, and N annotational variants of ONE execution
  // collapse to ONE key.
  const boundMembership = [];
  const verifiedBound = [];
  // HIGH-3: cross-stack-only membership — admitted ONLY from rows that have a bind leaf AND
  // at least one re-verified bind leaf is is_cross_stack:true. A guard-only row's path_hash
  // (which backs SC1/object-auth) is INELIGIBLE to satisfy a CROSS-STACK gate, and a same-
  // family bind row (is_cross_stack:false after HIGH-1) is excluded too.
  const crossStackMembership = [];
  // HIGH-2: membershipHash -> union of the row's re-resolved bind surface_refs, used by the
  // cross-stack consumers to reconcile the bound path against the consuming surfaces.
  const surfaceRefsByHash = {};
  // ISOLATION PARITY (belt-and-suspenders): membershipHash -> whether EVERY re-verified bind
  // leg ran container_isolated. The verdict-level isolation gate consults this so a cross-
  // stack reportable whose backing arms degraded is treated as un-isolated at report time —
  // a second line below the adjudicator's mint-side refusal.
  const containerIsolatedByHash = {};
  for (const r of verified) {
    const m = recordBindMembership(r);
    if (typeof m.hash === "string" && m.hash) {
      boundMembership.push(m.hash);
      verifiedBound.push(r);
      if (m.crossStack === true) {
        crossStackMembership.push(m.hash);
        const existing = surfaceRefsByHash[m.hash] || [];
        surfaceRefsByHash[m.hash] = Array.from(new Set([...existing, ...m.surfaceRefs]));
        // A path is isolated iff EVERY contributing row's arms were all isolated. Default
        // true on first sight; once any row for the hash degrades, it stays false.
        const prior = Object.prototype.hasOwnProperty.call(containerIsolatedByHash, m.hash)
          ? containerIsolatedByHash[m.hash] : true;
        containerIsolatedByHash[m.hash] = prior && m.containerIsolated === true;
      }
    }
  }
  const lastVerified = verifiedBound.length > 0 ? verifiedBound[verifiedBound.length - 1] : null;
  const verifiedPathHashes = Array.from(new Set(boundMembership));
  return {
    total_runs: records.length,
    verified_pass_count: verified.length,
    refuted_count: records.filter((r) => r.result === RESULT_REFUTED).length,
    inconclusive_count: records.filter((r) => r.result === RESULT_INCONCLUSIVE).length,
    offline_refused_count: records.filter((r) => r.result === RESULT_OFFLINE_REFUSED).length,
    // Authoritative per-path membership set for verdict binding (bind rows re-verified).
    // Kept for the SC1/guard consumers (object-auth confirm-half) and back-compat.
    verified_path_hashes: verifiedPathHashes,
    // HIGH-3 — the cross-stack-only membership set: rows with has_bind_leaf AND a re-
    // verified is_cross_stack:true bind leaf. The cross-stack gates (finalize-node /
    // crossStackPathGapForReportableFindings) bind on THIS set, so a guard-only or same-
    // family verified_pass can never satisfy a cross-stack gate by plain membership.
    verified_cross_stack_path_hashes: Array.from(new Set(crossStackMembership)),
    // HIGH-2 — per-cross-stack-path bound surface_refs (union of the bind leaves' re-
    // resolved surface_refs), so the cross-stack consumers can reconcile the bound path
    // against the consuming claim/node surfaces (not just check set membership).
    verified_cross_stack_path_surface_refs: surfaceRefsByHash,
    // ISOLATION PARITY — per-cross-stack-path whether EVERY backing arm ran
    // container_isolated. The verdict-level isolation gate treats a cross-stack reportable
    // whose path is NOT isolated as un-isolated (block under enforce / downgrade under
    // degrade), mirroring the single-surface invariant posture.
    verified_cross_stack_path_container_isolated: containerIsolatedByHash,
    // Retained for back-compat; the array above is authoritative for binding.
    last_verified_path_hash: lastVerified ? lastVerified.path_hash : null,
    // SC1's confirm-half is satisfied ONLY by at least one live verified_pass.
    sc1_confirm_half_satisfied: verified.length > 0,
  };
}

// resolveCompositionPathSynthVerdict — the open-vocab MINT->CONFIRM boundary, wired.
// resolveSynthesizedDifferentialVerdict (composition-experiment-harness.js) is the
// dormant resolver: an agent's open-vocab mechanism assertion (a shaped observation)
// resolves to SYNTH_VERIFIED IFF an EXECUTED verified_pass binds it by path_hash. This
// seam injects readCompositionVerifiedSummary as that executed ledger — which, after the
// read-time-reverify extension above, returns verified_path_hashes[] INCLUDING re-
// resolved cross-stack bind verified_pass rows. So a minted cross-stack mechanism
// resolves SYNTH_VERIFIED only when bound to a real cross-stack flip's path_hash; a
// declared-only verdict is not_executed and a cross-path binding is binding_mismatch.
//
// The dep is injected (not required across modules) so the harness keeps its no-cycle
// discipline: it requires nothing of this module, this module wires the reader in.
function resolveCompositionPathSynthVerdict(targetDomain, observation, pathHash) {
  const domain = assertSafeDomain(targetDomain);
  return resolveSynthesizedDifferentialVerdict(
    { observation, path_hash: pathHash },
    { readExecutedVerifiedSummary: () => readCompositionVerifiedSummary(domain) },
  );
}

module.exports = {
  COMPOSITION_VERIFIED_MAX_RECORDS,
  COMPOSITION_VERIFIED_VERSION,
  readCompositionVerifiedSummary,
  resolveCompositionPathSynthVerdict,
  RESULT_VERIFIED_PASS,
  RESULT_REFUTED,
  RESULT_INCONCLUSIVE,
  RESULT_OFFLINE_REFUSED,
  LEAF_VERIFIED,
  LEAF_REFUTED,
  LEAF_INCONCLUSIVE,
  verifyCompositionPath,
};
