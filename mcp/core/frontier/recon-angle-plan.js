"use strict";

// Recon multi-modal sweep — the deterministic recon-angle emitter.
//
// SEPARATE from deriveChildFanoutPlan (capability-pack-derivation.js): this
// module is NEVER imported by the cell-floor derivation, so the monotone
// cell-floor fixpoint stays unpolluted. It emits a FLAT (depth-0, not nested)
// fan-out plan for the SETUP recon phase only. The orchestrator's proven
// single-spawner muscle (the same one that drives wave evaluators, cell-floor
// closure, and one-chain-verifier-per-path) spawns one background worker per
// emitted angle; recon agents stay Task-less and never self-fan-out.
//
// Everything here is PURE (no clock, random, env, or I/O) so it is trivially
// testable, deterministic, and replayable: the same input yields a deep-equal
// plan across calls. Host resolution, governor budget, and deep-mode are read
// by the thin tool wrapper and passed in.
//
// Default behavior (no governor, a host that self-manages its subagent pool)
// fans out all four angles. A finite-pool / non-self-managing / unknown host
// degrades to a single sequential agent that still runs all four angles' steps
// in order (today's byte-identical 7-step path). The governor, when its
// remaining lifetime budget is below the angle count, ALSO degrades to that
// single sequential agent — but NEVER drops an angle: the single agent still
// runs every angle's steps (the exhaustive union), the cap only collapses the
// parallelism. RANK != BOUND: a width ceiling, when hit, STOPS the parallel
// spread and REPORTS which angles would not be covered as parallel; coverage
// is never silently reduced.

// The four coverage-DISJOINT angles, read off surface-discovery.md's 7 steps.
// Each angle worker first re-runs step 1 (the idempotent binary check) and then
// runs only its slice. The assembly worker (run once after the angle workers
// drain) builds attack_surface.json as the UNION of all angle scratch — lossless
// because the angles write disjoint scratch files. The order is STATIC and
// deterministic; deep_mode enriches the urls angle (more crawl depth) but never
// adds a fifth angle.
const RECON_ANGLES = Object.freeze([
  Object.freeze({
    id: "host_family",
    steps: Object.freeze([2, 3, 4]),
    description:
      "subdomain enumeration -> live-host probe -> first-party family discovery " +
      "(sequential WITHIN the angle: httpx -l subdomains.txt consumes the subdomain step)",
  }),
  Object.freeze({
    id: "urls",
    steps: Object.freeze([5]),
    description: "archived-URL (CDX/Wayback) + Katana crawl URL discovery",
  }),
  Object.freeze({
    id: "nuclei",
    steps: Object.freeze([6]),
    description: "the bounded nuclei pass (the long pole, isolated for wall-clock overlap)",
  }),
  Object.freeze({
    id: "js_jwt",
    steps: Object.freeze([7]),
    description: "JS endpoint / secret-shape / JWT-candidate extraction",
  }),
]);

// A host self-manages its subagent pool (and can therefore drain a flat
// background fan-out) only when it advertises an unbounded concurrent-subagent
// pool. nested-spawn.js encodes this as max_concurrent_subagents:null for
// claude/codex; finite-pool hosts (kimi/generic-mcp:1) and the unknown
// fail-closed fallback cannot drain extra concurrent workers, so recon degrades
// to the single sequential agent. Recon is FLAT (depth-0), so this deliberately
// does NOT consult effectiveSpawnDepth (that clamp governs NESTED depth, a
// different axis).
const { hostPoolCeiling } = require("../session/nested-spawn.js");

function deepEnrichedAngles(deepMode) {
  if (!deepMode) return RECON_ANGLES;
  // Deep mode enriches the urls angle (broader crawl roots / depth) without
  // adding a fifth angle. The enrichment is a flag the angle worker reads; the
  // angle SET and order are invariant so the union stays the same four angles.
  return Object.freeze(
    RECON_ANGLES.map((angle) =>
      angle.id === "urls" ? Object.freeze({ ...angle, deep: true }) : angle,
    ),
  );
}

// deriveReconAnglePlan — the pure emitter.
//
// Input:
//   deep_mode: boolean (enriches the urls angle, never adds an angle)
//   host_id:   string  (runtimeClient(): "claude" | "codex" | "kimi" |
//                        "generic-mcp" | "unknown" | ...)
//   governor:  null | { max_total_spawned_agents: integer|null,
//                       total_spawned: integer } — the lifetime operator-cost
//              ceiling and the spawn-ledger total already handed out.
//
// Output (deterministic, replayable):
//   { mode: "fanout" | "sequential",
//     angles: [ { id, steps, description, deep? }, ... ] (ALL four, always),
//     degrade_reason?: "host_pool_finite",
//     governor_gap?:   { ... } }   // present only on governor-forced sequential
function deriveReconAnglePlan({ deep_mode = false, host_id = "unknown", governor = null } = {}) {
  const deepMode = deep_mode === true;
  const angles = deepEnrichedAngles(deepMode);
  const angleCount = angles.length;

  // 1. Host-fail-closed degradation. A finite host pool (kimi/generic/unknown)
  //    cannot drain extra concurrent workers -> single sequential agent =
  //    today's byte-identical 7-step path. A self-managing pool (null ceiling:
  //    claude/codex) can drain the flat fan-out.
  const ceiling = hostPoolCeiling(host_id);
  if (ceiling != null) {
    return Object.freeze({
      mode: "sequential",
      angles,
      degrade_reason: "host_pool_finite",
    });
  }

  // 2. Governor (lifetime operator-cost ceiling). RANK != BOUND: when the
  //    remaining lifetime budget is below the angle count, the parallel spread
  //    would overshoot the ceiling, so we STOP the parallel spread and REPORT
  //    the angles that would not be covered as parallel — but the single
  //    sequential agent STILL runs ALL angles' steps (the exhaustive union).
  //    No angle is ever dropped; only the parallelism collapses.
  if (governor && typeof governor === "object") {
    const maxTotal = Number.isInteger(governor.max_total_spawned_agents)
      ? governor.max_total_spawned_agents
      : null;
    const totalSpawned = Number.isInteger(governor.total_spawned) ? governor.total_spawned : 0;
    if (maxTotal != null) {
      const remaining = maxTotal - totalSpawned;
      // One worker per angle PLUS one assembly worker is the parallel cost.
      const parallelCost = angleCount + 1;
      if (remaining < parallelCost) {
        // How many angle-workers the remaining budget could still admit (the
        // assembly worker always runs, so reserve one slot for it).
        const admissible = Math.max(0, remaining - 1);
        const uncovered = angles.slice(admissible).map((angle) => angle.id);
        return Object.freeze({
          mode: "sequential",
          angles,
          governor_gap: Object.freeze({
            max_total_spawned_agents: maxTotal,
            total_spawned: totalSpawned,
            remaining,
            required_for_parallel: parallelCost,
            uncovered_as_parallel: Object.freeze(uncovered),
          }),
        });
      }
    }
  }

  // 3. Default: self-managing host, no binding governor -> full fan-out.
  return Object.freeze({
    mode: "fanout",
    angles,
  });
}

module.exports = {
  RECON_ANGLES,
  deriveReconAnglePlan,
};
