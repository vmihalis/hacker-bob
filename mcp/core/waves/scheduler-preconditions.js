"use strict";

// Y.10 (Y-D12 / Y-P12) — scheduler-precondition registry.
//
// Each scheduler precondition is a closed-enum name that maps to a check
// function returning `{satisfied: boolean, blocked_surface_ids?: string[]}`.
// The runtime gate at bob_advance_session consults these checks before
// allowing OPEN_FRONTIER -> CLAIM_FREEZE; the CI marker scan at
// scripts/check-skill-scheduler-coherence.js consumes the closed enum to
// assert that committed skill / role markdown carries the `@precondition:`
// directive on the relevant state-block.
//
// The set is intentionally narrow: only conditions the runtime gate
// mechanically enforces appear here. New preconditions extend the enum
// AND register a check function in PRECONDITION_CHECKS at the same time
// (paired safety enforcement — see test/scheduler-preconditions-shape.test.js).

const {
  getLatestMergedWavePartialSurfaceIds,
} = require("./wave-handoff-store.js");
const {
  readSessionStateStrict,
  sessionStateMissing,
} = require("../session/session-state-store.js");

// Classifies a throw from the seed_surfaces_present materialize/route pipeline.
// Returns true ONLY for the expected "surface input is not present yet" signals:
// a fresh SETUP session whose producers have not materialized any surface. Those
// are legitimately non-terminal (reported_gap -> the SETUP gate passes). Every
// OTHER throw — corrupt surface-index.json / attack_surface.json (a JSON.parse
// SyntaxError or a "Malformed ... JSON" wrap), a read-cap breach, a disk or lock
// failure — is a materialization ERROR: the surface input exists but could not be
// read/routed, so the seed gate must BLOCK rather than read it as "no surfaces".
function isSeedInputNotYetMaterialized(error) {
  if (!error) return false;
  // A missing expected file (surface-index.json / attack_surface.json) surfaces
  // as ENOENT: the input has not been seeded yet.
  if (error.code === "ENOENT") return true;
  const message = typeof error.message === "string" ? error.message : "";
  // buildSurfaceRoutesDocument's canonical "no surface input has been seeded yet"
  // throw (currentSurfaces returned source: "missing"). NOT the "Malformed attack
  // surface JSON:" wrap, which is a corruption error and must NOT match here.
  if (/^Missing attack surface JSON:/.test(message)) return true;
  return false;
}

const SCHEDULER_PRECONDITION_VALUES = Object.freeze([
  "partial_surfaces_drained",
  "chain_work_terminal",
  "uncovered_reachable_cells",
  "seed_producers_drained",
  "blocked_prereqs_capability_clear",
  "seed_surfaces_present",
  "unscanned_bodies_drained",
]);

function historyBySurfaceFromBlockedPrereqs(history) {
  const historyBySurface = new Map();
  for (const entry of Array.isArray(history) ? history : []) {
    if (!entry || typeof entry.surface_id !== "string" || !entry.surface_id) continue;
    if (!historyBySurface.has(entry.surface_id)) historyBySurface.set(entry.surface_id, []);
    historyBySurface.get(entry.surface_id).push(entry);
  }
  return historyBySurface;
}

function latestBlockedPrereqWave(history) {
  let latest = 0;
  for (const entry of Array.isArray(history) ? history : []) {
    if (entry && Number.isInteger(entry.wave) && entry.wave > latest) latest = entry.wave;
  }
  return latest;
}

function evaluateBlockedPrereqsCapabilityClear(targetDomain) {
  if (typeof targetDomain !== "string" || targetDomain.length === 0) {
    throw new Error("blocked_prereqs_capability_clear: target_domain is required");
  }
  let state;
  try {
    ({ state } = readSessionStateStrict(targetDomain));
  } catch (error) {
    if (sessionStateMissing(error)) {
      return { satisfied: true, capability_clear_active: false, blocked_surface_ids: [] };
    }
    throw error;
  }
  const history = Array.isArray(state.blocked_prereq_history) ? state.blocked_prereq_history : [];
  if (history.length === 0) {
    return { satisfied: true, capability_clear_active: false, blocked_surface_ids: [] };
  }
  const currentWave = Number.isInteger(state.evaluation_wave) && state.evaluation_wave > 0
    ? state.evaluation_wave
    : latestBlockedPrereqWave(history);
  if (!currentWave) {
    return { satisfied: true, capability_clear_active: false, blocked_surface_ids: [] };
  }
  const historyBySurface = historyBySurfaceFromBlockedPrereqs(history);
  const {
    computeCapabilityClearedPremiseSurfaceIds,
  } = require("./wave-promotion-detector.js");
  const blockedSurfaceIds = Array.from(computeCapabilityClearedPremiseSurfaceIds({
    historyBySurface,
    currentWave,
    target_domain: targetDomain,
  }));
  return {
    satisfied: blockedSurfaceIds.length === 0,
    capability_clear_active: blockedSurfaceIds.length > 0,
    blocked_surface_ids: blockedSurfaceIds,
  };
}

function resolveWebOnchainRefProducerIds() {
  const { PRODUCER_PACKS } = require("../dispatch/producer-packs.js");
  const ids = new Set();
  for (const pack of Object.values(PRODUCER_PACKS || {})) {
    const trigger = pack && pack.trigger;
    if (!pack || pack.advisory === true || !trigger || trigger.kind !== "derived") continue;
    const consumes = Array.isArray(trigger.consumes) ? trigger.consumes : [];
    const produces = Array.isArray(pack.produces) ? pack.produces : [];
    if (consumes.includes("http_bodies") && produces.includes("chain_address_set")) {
      ids.add(pack.producer_id);
    }
  }
  return ids;
}

// Each check receives `{target_domain}` and returns an object with at minimum
// `{satisfied: boolean}`. When unsatisfied, the check MAY return additional
// structured context (e.g., `blocked_surface_ids`) that the gate surfaces in
// the STATE_CONFLICT payload.
const PRECONDITION_CHECKS = Object.freeze({
  partial_surfaces_drained(context) {
    const targetDomain = context && context.target_domain;
    if (typeof targetDomain !== "string" || targetDomain.length === 0) {
      throw new Error("partial_surfaces_drained: target_domain is required");
    }
    const capabilityClear = evaluateBlockedPrereqsCapabilityClear(targetDomain);
    if (!capabilityClear.satisfied) {
      return {
        satisfied: false,
        blocked_surface_ids: capabilityClear.blocked_surface_ids,
        blocked_prereqs_capability_clear: capabilityClear,
      };
    }
    const blockedSurfaceIds = getLatestMergedWavePartialSurfaceIds(targetDomain);
    return {
      satisfied: blockedSurfaceIds.length === 0,
      blocked_surface_ids: blockedSurfaceIds,
    };
  },
  // Chain work that is recorded must produce a terminal structured chain
  // attempt before CLAIM_FREEZE. The required-work signal is the same one
  // pipeline-analytics surfaces as `chain_phase_no_attempts`
  // (findings.total >= 2 OR handoff chain_notes_count > 0); the precondition
  // reads it from the canonical session-artifact summary rather than
  // recomputing it, and is satisfied when no chain work is required or a
  // terminal attempt already exists.
  chain_work_terminal(context) {
    const targetDomain = context && context.target_domain;
    if (typeof targetDomain !== "string" || targetDomain.length === 0) {
      throw new Error("chain_work_terminal: target_domain is required");
    }
    const {
      readSessionArtifactSummary,
      chainWorkRequired,
    } = require("../telemetry/pipeline-session-artifacts.js");
    const summary = readSessionArtifactSummary(targetDomain);
    const findingsTotal = summary && summary.findings && Number.isInteger(summary.findings.total)
      ? summary.findings.total
      : 0;
    const chainNotesCount = summary && summary.chain_handoffs
      && Number.isInteger(summary.chain_handoffs.chain_notes_count)
      ? summary.chain_handoffs.chain_notes_count
      : 0;
    const terminalTotal = summary && summary.chain_attempts
      && Number.isInteger(summary.chain_attempts.terminal_total)
      ? summary.chain_attempts.terminal_total
      : 0;
    const required = chainWorkRequired(summary);
    return {
      satisfied: !required || terminalTotal > 0,
      chain_work_required: required,
      findings_total: findingsTotal,
      chain_notes_count: chainNotesCount,
      terminal_total: terminalTotal,
    };
  },
  // Closure teeth: a frontier cannot freeze while reachable coverage cells
  // remain uncovered. SELF-ACTIVATING — a session that never materialized a
  // cell floor has no cell-coverage obligation and is vacuously satisfied, so
  // legacy/surface-only runs are unaffected; the gate only bites once the
  // orchestrator commits to cell coverage (cell nodes exist in the graph). The
  // uncovered count is the floor enumeration MINUS already-covered cells (the
  // same coverage-pruned planCellsForSurface the producer dispatches), so a cell
  // counts as covered exactly when bob_finalize_node reconciled a verified probe.
  uncovered_reachable_cells(context) {
    const targetDomain = context && context.target_domain;
    if (typeof targetDomain !== "string" || targetDomain.length === 0) {
      throw new Error("uncovered_reachable_cells: target_domain is required");
    }
    const { materializeTaskGraph } = require("./task-graph-materializer.js");
    const doc = materializeTaskGraph(targetDomain, { write: false }).document;
    const hasCellFloor = doc.nodes.some((node) => node.kind === "cell");
    if (!hasCellFloor) {
      return { satisfied: true, cell_floor_active: false, uncovered_count: 0 };
    }
    const { currentSurfaces } = require("../frontier/frontier-projections.js");
    const { buildCoverageSummaryForSurface, readCoverageRecordsFromJsonl } = require("../frontier/coverage.js");
    const { planCellsForSurface } = require("../session/assignment-brief.js");
    const { loadQueuePolicy } = require("../io/queue-policy.js");
    const policy = loadQueuePolicy(targetDomain);
    const surfaces = currentSurfaces(targetDomain).surfaces || [];
    const coverageRecords = readCoverageRecordsFromJsonl(targetDomain);
    let uncovered = 0;
    const uncoveredSurfaceIds = [];
    for (const surfaceObj of surfaces) {
      const surfaceId = surfaceObj && surfaceObj.id;
      if (typeof surfaceId !== "string" || !surfaceId) continue;
      const coverageSummary = buildCoverageSummaryForSurface(coverageRecords, surfaceId);
      const plan = planCellsForSurface({
        domain: targetDomain,
        surfaceObj,
        surfaceId,
        coverageSummary,
        remainingDepth: 1,
        maxChildren: policy.max_spawn_children,
      });
      const remaining = plan && Array.isArray(plan.children) ? plan.children.length : 0;
      if (remaining > 0) {
        uncovered += remaining;
        uncoveredSurfaceIds.push(surfaceId);
      }
    }
    // Transition-cell floor (A2): cross-surface invariants on edges are closure
    // obligations too. An unprobed (edge x bug_class) cell must block freeze, or
    // a cross-surface invariant (L1->L2 replay, deposit->distribute) would
    // evaporate between two surface evaluators.
    const { enumerateTransitionCellFloor } = require("../session/assignment-brief.js");
    for (const edge of enumerateTransitionCellFloor({
      domain: targetDomain,
      coverageRecords,
      maxChildren: policy.max_spawn_children,
    })) {
      const remaining = edge.plan && Array.isArray(edge.plan.children) ? edge.plan.children.length : 0;
      if (remaining > 0) {
        uncovered += remaining;
        uncoveredSurfaceIds.push(edge.edge_token);
      }
    }
    return {
      satisfied: uncovered === 0,
      cell_floor_active: true,
      uncovered_count: uncovered,
      uncovered_surface_ids: uncoveredSurfaceIds.slice(0, 50),
    };
  },
  // Producer-floor teeth: a frontier cannot freeze while the deterministic
  // recon-producer floor is not at its fixpoint — a READY non-advisory producer
  // remains OR a per-instance sc-expander is still pending. The drain verdict runs
  // the SAME buildProducerFloorPlan the dispatch handler uses (the whole PLAN, not
  // merely the isProducerFloorAtFixpoint predicate), so the gate and the dispatcher
  // can never disagree on what "drained" means: they feed planProducerFloor the
  // IDENTICAL policy-derived caps, so a depth-capped sc-expander the dispatcher will
  // never propose is never counted pending here. A plan rebuilt WITHOUT those caps
  // would fall back to the hardcoded depthCap default of 3 and, at a non-default
  // linked_contract_depth (0/1), freeze the frontier forever waiting on an expander
  // the dispatcher is permanently depth-capped from proposing. The suppressed bare
  // sc_address_expander rides in plan.sc_expander_instances, which plan.ready does
  // not represent, so a verdict read off plan.ready alone would freeze ahead of a
  // pending SC linked-contract expansion. SELF-ACTIVATING — a session that never
  // materialized a producer floor has no producer node in the graph and is
  // vacuously satisfied, so recon-angle-only / legacy / surface-only runs are
  // unaffected. RANK != BOUND: derived producers whose upstream input is absent are
  // surfaced in producer_gaps[] (sliced for display only) but NEVER block — gaps
  // satisfy-and-report. Read-only: materializeTaskGraph runs with {write:false} and
  // buildProducerFloorPlan only reads state + the producer_run ledger + SC surfaces
  // and runs the pure planProducerFloor, exactly mirroring uncovered_reachable_cells
  // (the sibling above).
  seed_producers_drained(context) {
    const targetDomain = context && context.target_domain;
    if (typeof targetDomain !== "string" || targetDomain.length === 0) {
      throw new Error("seed_producers_drained: target_domain is required");
    }
    const { materializeTaskGraph } = require("./task-graph-materializer.js");
    const { PRODUCER_NODE_KIND } = require("../../lib/constants.js");
    const doc = materializeTaskGraph(targetDomain, { write: false }).document;
    const hasProducerFloor = doc.nodes.some((node) => node.kind === PRODUCER_NODE_KIND);
    if (!hasProducerFloor) {
      return { satisfied: true, producer_floor_active: false, ready_count: 0, producer_gaps: [] };
    }
    // Single-sourced with the dispatch handler: buildProducerFloorPlan assembles the
    // IDENTICAL plan inputs — the policy-derived caps (linked_contract_depth + the
    // OD1 seed governors), the live SC surface inventory, the terminal producer_run
    // set, and availableArtifactKinds (root seeds UNION every terminal producer's
    // produces[]) — and runs the same pure planProducerFloor. Reusing the whole
    // builder (not just the fixpoint predicate) keeps the caps single-sourced too:
    // the gate's depth governor is the operator's persisted linked_contract_depth,
    // never a hardcoded depthCap default, so a depth-capped sc-expander the
    // dispatcher will never propose cannot keep this gate blocked forever. Read-only:
    // buildProducerFloorPlan only reads state + the producer_run ledger + SC surfaces
    // and runs the pure planner.
    const {
      buildProducerFloorPlan,
      isProducerFloorAtFixpoint,
    } = require("../../tools/materialize-producer-floor.js");
    const { plan } = buildProducerFloorPlan(targetDomain);
    // Same null-guard the fixpoint predicate uses (isProducerFloorAtFixpoint):
    // plan.ready never holds null, so this is a consistency guard only.
    const readyNonAdvisory = plan.ready.filter((p) => p && p.advisory !== true);
    const scExpanderInstances = Array.isArray(plan.sc_expander_instances)
      ? plan.sc_expander_instances
      : [];
    return {
      // Single-sourced fixpoint predicate over a single-sourced plan: the floor is
      // drained only when NO ready non-advisory producer remains AND NO per-instance
      // sc-expander is pending. Because buildProducerFloorPlan fed planProducerFloor
      // the SAME caps the dispatch handler uses, the gate and the dispatcher agree on
      // which sc-expander instances are depth-admissible — the caps can never drift.
      satisfied: isProducerFloorAtFixpoint(plan),
      producer_floor_active: true,
      ready_count: readyNonAdvisory.length,
      ready_producer_ids: readyNonAdvisory.map((p) => p.producer_id).slice(0, 50),
      sc_expander_instance_count: scExpanderInstances.length,
      sc_expander_instance_keys: scExpanderInstances.map((i) => i.producer_key).slice(0, 50),
      producer_gaps: plan.gaps.slice(0, 50),
    };
  },
  // PRD-5
  // An unscanned http_bodies artifact blocks the OPEN_FRONTIER -> CLAIM_FREEZE
  // drain when the web_onchain_ref producer remains READY with no terminal
  // producer_run row, so the unrouted on-chain ref is a recorded MCP-owned
  // obligation. The verdict is single-sourced with the dispatcher through
  // buildProducerFloorPlan. RANK != BOUND: absent-input gaps satisfy-and-report.
  unscanned_bodies_drained(context) {
    const targetDomain = context && context.target_domain;
    if (typeof targetDomain !== "string" || targetDomain.length === 0) {
      throw new Error("unscanned_bodies_drained: target_domain is required");
    }
    const { materializeTaskGraph } = require("./task-graph-materializer.js");
    const { PRODUCER_NODE_KIND } = require("../../lib/constants.js");
    const doc = materializeTaskGraph(targetDomain, { write: false }).document;
    const hasProducerFloor = doc.nodes.some((node) => node.kind === PRODUCER_NODE_KIND);
    if (!hasProducerFloor) {
      return {
        satisfied: true,
        obligation_active: false,
        unscanned_body_present: false,
        ready_web_onchain_ref_count: 0,
        ready_web_onchain_ref_ids: [],
        obligation_gaps: [],
      };
    }
    const { buildProducerFloorPlan } = require("../../tools/materialize-producer-floor.js");
    const { plan } = buildProducerFloorPlan(targetDomain);
    const refIds = resolveWebOnchainRefProducerIds();
    const readyRefProducers = plan.ready.filter((p) => p && p.advisory !== true && refIds.has(p.producer_id));
    const unscanned_body_present = readyRefProducers.length > 0;
    return {
      satisfied: unscanned_body_present === false,
      obligation_active: true,
      unscanned_body_present,
      ready_web_onchain_ref_count: readyRefProducers.length,
      ready_web_onchain_ref_ids: readyRefProducers.map((p) => p.producer_id).slice(0, 50),
      obligation_gaps: Array.isArray(plan.gaps) ? plan.gaps.slice(0, 50) : [],
    };
  },
  blocked_prereqs_capability_clear(context) {
    const targetDomain = context && context.target_domain;
    return evaluateBlockedPrereqsCapabilityClear(targetDomain);
  },
  // Seed teeth: a frontier with zero routed seed surfaces has nothing to
  // schedule. materializeFrontier(domain, {write:true}) FORCES synchronous
  // surface-index.json materialization (its write path wraps the reentrant
  // session lock, so this stays safe to call later from inside an
  // already-held lock at a gate), and buildSurfaceRoutesDocument then derives
  // the routed seed surfaces; satisfied when at least one route exists.
  //
  // A throw is triaged by its cause. An "input not seeded yet" throw (a fresh
  // session that has neither surface-index.json nor attack_surface.json, where
  // buildSurfaceRoutesDocument throws "Missing attack surface JSON: <path>", or an
  // ENOENT on an expected file) is a REPORTED gap, not a confirmed-empty frontier:
  // map it to {satisfied:false, reported_gap:true, reason} so a downstream gate
  // never reads a not-yet-materialized frontier as "no surfaces exist". An
  // UNEXPECTED throw — corrupt surface-index.json / attack_surface.json, a read-cap
  // breach, a disk or lock failure — is a materialization ERROR: the input exists
  // but could not be read/routed, so it maps to {satisfied:false,
  // materialization_error:true, error_code:"seed_surfaces_materialization_error",
  // reason} and the SETUP gate BLOCKS rather than advancing on broken state. The
  // only permitted bare satisfied:false is a successful route build whose routes
  // array is genuinely empty. The reason string has any absolute filesystem path
  // redacted to a basename so it never leaks the local session/home path.
  seed_surfaces_present(context) {
    const targetDomain = context && context.target_domain;
    if (typeof targetDomain !== "string" || targetDomain.length === 0) {
      throw new Error("seed_surfaces_present: target_domain is required");
    }
    try {
      const { materializeFrontier } = require("../frontier/frontier-materializer.js");
      const { buildSurfaceRoutesDocument } = require("../frontier/surface-router.js");
      materializeFrontier(targetDomain, { write: true });
      const routes = buildSurfaceRoutesDocument(targetDomain).routes;
      return { satisfied: routes.length >= 1, seed_surface_count: routes.length };
    } catch (error) {
      const path = require("path");
      const rawReason = error && error.message ? error.message : String(error);
      const reason = rawReason.replace(/\/[^\s]+/g, (match) => path.basename(match));
      if (isSeedInputNotYetMaterialized(error)) {
        return { satisfied: false, reported_gap: true, reason };
      }
      return {
        satisfied: false,
        materialization_error: true,
        error_code: "seed_surfaces_materialization_error",
        reason,
      };
    }
  },
});

function evaluateSchedulerPrecondition(name, context) {
  if (!SCHEDULER_PRECONDITION_VALUES.includes(name)) {
    throw new Error(`unknown scheduler precondition: ${name}`);
  }
  const check = PRECONDITION_CHECKS[name];
  if (typeof check !== "function") {
    throw new Error(`scheduler precondition ${name} has no check function`);
  }
  return check(context || {});
}

module.exports = {
  SCHEDULER_PRECONDITION_VALUES,
  PRECONDITION_CHECKS,
  evaluateSchedulerPrecondition,
};
