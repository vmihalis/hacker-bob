"use strict";

// phaseFanoutPlan — the general per-phase fan-out-plan emitter.
//
// Cross-role fan-out in this system is ORCHESTRATOR-MEDIATED: the brain emits a
// per-phase PLAN (a deterministic list of dispatch items), and the orchestrator's
// single-spawner muscle spawns one background worker per item. Each phase has its
// OWN authority emitter for that list; this module is a thin, pure DISPATCHER
// that delegates to the right authority emitter for the requested phase. It does
// ZERO plan computation of its own — every phase plan is reproduced by
// construction (identity dispatch), so the shipped plans are byte/structure-for-
// structure identical to calling the authority emitter directly.
//
// The shared CONTRACT (not a shared data type — the per-phase shapes are
// genuinely heterogeneous) is:
//   (a) a deterministic, replayable enumeration of a coverage space into a list
//       of dispatch items;
//   (b) a per-item brief/budget;
//   (c) a host/governor-aware degrade that collapses parallelism WITHOUT
//       dropping coverage (RANK != BOUND);
//   (d) a union/coverage guarantee that the single-spawner orchestrator drains.
//
// SEPARATE module, like recon-angle-plan.js: this is NEVER imported by the
// cell-floor derivation. Importing deriveChildFanoutPlan here does not relocate
// or modify the guarded pure body in capability-pack-derivation.js, so the
// monotone cell-floor fixpoint and its purity lint stay unpolluted. The live
// call sites (bob_plan_recon_angles, bob_materialize_cell_floor /
// bob_schedule_graph_nodes, bob_stage_verification_round_partial) keep calling
// their authority emitters DIRECTLY; this wrapper is a brain-internal seam for a
// future fan-out phase, wired to a tool only when that phase is built.
//
// Everything here is PURE (no clock, random, env, or I/O): each phase takes its
// inputs via args, and the dispatcher is a switch with no hidden state.

const { deriveChildFanoutPlan } = require("./capability/capability-pack-derivation.js");
const { deriveReconAnglePlan } = require("./frontier/recon-angle-plan.js");

// The phases that have an authority emitter today. A new phase plugs a new
// authority emitter into the switch instead of inventing a fourth ad-hoc call
// path.
const PHASE = Object.freeze({
  CELL: "cell",
  RECON: "recon",
  VERIFICATION: "verification",
});

// phaseFanoutPlan(phase, args) — pure dispatcher.
//
//   phase "cell": args = { parent_surface_id, surface_metadata, options }.
//     Returns deriveChildFanoutPlan(parent_surface_id, surface_metadata, options)
//     VERBATIM (the same frozen object the cell emitter returns). The "list" =
//     (bug_class x auth_role [x mechanism]) cells; RANK != BOUND is realized via
//     budget_pruned_count spill re-emitted by the cell-floor to fixpoint.
//
//   phase "recon": args = { options }.
//     Returns deriveReconAnglePlan(options) VERBATIM. The "list" = the four
//     coverage-disjoint angles (always all four); degrade collapses parallelism
//     to a single sequential agent that still runs every angle's steps.
//
//   phase "verification": args = { finding_ids }.
//     PROJECTION ONLY of the already-frozen snapshot list — no re-derivation, no
//     I/O. Returns a frozen { phase, items } where items is a copy (.slice()) of
//     finding_ids in snapshot order. The orchestrator spawns exactly one verifier
//     worker per id; assertExactFindingCoverage remains the real commit-time
//     union gate.
function phaseFanoutPlan(phase, args = {}) {
  switch (phase) {
    case PHASE.CELL:
      return deriveChildFanoutPlan(
        args.parent_surface_id,
        args.surface_metadata,
        args.options,
      );
    case PHASE.RECON:
      return deriveReconAnglePlan(args.options || {});
    case PHASE.VERIFICATION: {
      const ids = Array.isArray(args.finding_ids) ? args.finding_ids.slice() : [];
      return Object.freeze({
        phase: PHASE.VERIFICATION,
        items: Object.freeze(ids),
      });
    }
    default:
      throw new Error(`phaseFanoutPlan: unknown phase ${phase}`);
  }
}

module.exports = Object.freeze({ PHASE, phaseFanoutPlan });
