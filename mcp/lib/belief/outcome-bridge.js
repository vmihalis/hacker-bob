"use strict";

// Outcome-bridge — the one-way executed-reality -> belief edge.
//
// A live composition verifier mints a verified_pass ONLY after re-executing an
// object-auth guard leaf's cross-principal same-object battery and reproducing the
// flip (composition-live-verifier.js). That executed outcome is ground truth about
// one latent: the attacker-principal request reached the SAME victim object the
// victim authorized request reaches, so the two requests are access-EQUIVALENT.
//
// This module turns that audit-graded outcome into an ADVISORY belief signal that
// sharpens the matching request_equivalence latent's posterior toward `equivalent`.
// It is strictly one-way and non-gating:
//   - It runs AFTER the audit-graded composition-verified.jsonl append, never before,
//     and the whole emit is wrapped by the caller so a belief failure cannot alter
//     the verified record (NO GATING).
//   - It writes only advisory belief-scratch via writeBeliefSignalScratch; it emits
//     NO frontier event (the no-laundering rule) and touches no grade/claim path.
//   - dispatch_authority:false is stamped on every payload.
//   - It keys by CONSTRUCTION: the signal's latent_id is recomputed with the SAME
//     stableId + scope normalization the belief window mints for that observation,
//     so a verified_pass moves exactly the matching latent and nothing else.
//   - A non-pass path emits nothing (caller guards on verified_pass); a non-verified
//     leaf emits nothing (filtered here on LEAF_VERIFIED).

// authority is required as a module object (not destructured) so the single
// audit-graded boundary stays patchable in tests that force a belief write failure
// to prove the emit cannot alter the audit-graded composition-verified.jsonl row.
const authority = require("./authority.js");
const {
  stableId,
  requestEquivalenceScope,
} = require("./belief-window.js");

const EVIDENCE_REF_PREFIX = "frontier_event:";

// Bounded same-bug_class sibling propagation is intentionally NOT done here. A
// sibling-raise must raise sibling priors ONLY through the existing surface_graph
// factor path, weight-capped, and must never resolve a sibling or alone cross a
// band. The direct-keying edge here deliberately sharpens exactly ONE latent by
// exact id; a sibling-raise belongs in the factor graph, not in this exact-id
// producer, so it is excluded here to keep the KEYING/COMPLETENESS invariants exact.

// The sharpen target: a verified object-auth flip is strong-but-not-certain evidence
// of request equivalence. ~0.9 with the residual mass split over the other two
// canonical request_equivalence states is a Bayesian sharpen, not a hard 1.0.
const VERIFIED_EQUIVALENT_DISTRIBUTION = Object.freeze({
  equivalent: 0.9,
  distinct: 0.05,
  unknown: 0.05,
});

function leafEventId(leaf) {
  const ref = leaf && typeof leaf === "object" ? leaf.evidence_ref : null;
  if (typeof ref !== "string" || !ref.startsWith(EVIDENCE_REF_PREFIX)) return null;
  return ref.slice(EVIDENCE_REF_PREFIX.length);
}

// Emit one verified_intervention belief signal per LEAF_VERIFIED leaf of a
// verified_pass path. Returns the count emitted (0 when nothing matched). NEVER
// throws: any failure is swallowed so the advisory edge can never affect the
// audit-graded result. `leaves` are the per-leaf records from verifyCompositionPath;
// `path` is the same-ordered input leaves carrying evidence_ref; `eventIndex` is the
// offline frontier-event index (event_id -> event).
function emitVerifiedInterventionSignal({
  target_domain,
  base_url,
  path,
  leaves,
  event_index,
  leaf_verified_status,
}) {
  let emitted = 0;
  try {
    if (!Array.isArray(path) || !Array.isArray(leaves)) return 0;
    const verifiedStatus = leaf_verified_status;
    for (let i = 0; i < path.length; i += 1) {
      const leaf = path[i];
      const record = leaves[i];
      if (!record || record.leaf_status !== verifiedStatus) continue;
      const eventId = leafEventId(leaf);
      if (!eventId) continue;
      const offlineEvent = event_index && typeof event_index.get === "function"
        ? event_index.get(eventId)
        : null;
      const payload = offlineEvent && offlineEvent.payload && typeof offlineEvent.payload === "object"
        ? offlineEvent.payload
        : null;
      const req = payload && payload.request && typeof payload.request === "object"
        ? payload.request
        : null;
      if (!payload || !req || typeof req.url !== "string" || !req.url) continue;

      // Recompute the IDENTICAL scope the belief window mints for this observation
      // (requestEquivalenceScope is the shared normalizer), then the IDENTICAL
      // variable_id (shared stableId). This is exact-id keying by construction.
      const scope = requestEquivalenceScope(payload, eventId, base_url);
      const variableId = stableId("BV", { type: "request_equivalence", scope });

      authority.writeBeliefSignalScratch({
        target_domain,
        kind: "belief_signal",
        source: "composition-live-verifier",
        provenance: "verified_intervention",
        role: "evidence",
        artifact_ref: `composition_verified:${record && record.results_hash ? record.results_hash : ""}`,
        payload: {
          latent_id: variableId,
          type: "request_equivalence",
          scope,
          verified_state: "equivalent",
          distribution: { ...VERIFIED_EQUIVALENT_DISTRIBUTION },
          results_hash: record && record.results_hash ? record.results_hash : null,
          edge_id: record && record.edge_id ? record.edge_id : null,
          dispatch_authority: false,
        },
      });
      emitted += 1;
    }
  } catch {
    // advisory: a belief write failure must never alter the audit-graded result.
  }
  return emitted;
}

module.exports = {
  VERIFIED_EQUIVALENT_DISTRIBUTION,
  emitVerifiedInterventionSignal,
};
