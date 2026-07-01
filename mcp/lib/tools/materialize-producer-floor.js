"use strict";

// bob_materialize_producer_floor — the producer-floor producer. Sweeps the recon
// producer DAG (PRODUCER_PACKS) and emits one producer_proposed
// observation.recorded event per producer that is READY (its input clause holds)
// and NOT already terminal in the producer_run ledger. The materializer folds each
// emitted event into a schedulable 'producer' TaskGraph node. A root producer
// draws its input from the session seeds (the web 'target' seed / the chain
// 'chain_address_set' seed); a derived producer draws from an upstream artifact
// kind already produced. The floor is a monotone fixpoint: each materialize->drain
// pass shrinks the ready set until no producer remains
// (producer_floor_at_fixpoint). Single-spawner: the orchestrator appends, no
// worker spawn. Mirrors the cell-floor's pure-planner + impure-wrapper split.

const { assertNonEmptyString } = require("../validation.js");
const { currentSurfaces } = require("../frontier-projections.js");
const { appendFrontierEvent, readFrontierEvents } = require("../frontier-events.js");
const { PRODUCER_PACKS, isProducerReady } = require("../producer-packs.js");
const { producerRunSet, recordProducerRun } = require("../producer-run-ledger.js");
const { materializeTaskGraph, producerNodeId } = require("../task-graph-materializer.js");
const { loadQueuePolicy } = require("../queue-policy.js");
const { statePath } = require("../paths.js");
const { readJsonFile } = require("../storage.js");
const { scheduleMaterialization } = require("../frontier-materialize-debounce.js");
const {
  PRODUCER_NODE_KIND,
  DEFAULT_SEED_PRODUCER_PER_PASS_CAP,
  DEFAULT_PER_EXPANDER_LINKED_ADDRESS_CAP,
  DEFAULT_MAX_TOTAL_SEED_PRODUCERS,
} = require("../constants.js");

// Orphan-executed reconciler bounds. A producer node stuck 'executed' with NO
// terminal producer_run row (produced | blocked) lost its finalize across the
// turn barrier — the floor would otherwise never re-propose it. One materialize
// pass of grace covers a legitimate in-flight finalize; from the K-th consecutive
// unreconciled pass the orphan is converted to a STRUCTURAL strike so the existing
// strike tally auto-blocks it at the threshold and the floor moves on. A pass with
// an orphan index below K emits a non-striking TRANSIENT audit tick instead.
const ORPHAN_EXECUTED_RECONCILE_PASS_THRESHOLD = 2;
const ORPHAN_TICK_REASON = "orphan_executed_pending";
const ORPHAN_STRIKE_REASON = "orphan_executed_unreconciled";

// Stale-dispatch reconciler bounds. A producer node stuck 'proposed' (never
// scheduled) or 'dispatched' (a worker that never returned an executed
// transition) makes no forward progress, so without a strike path the floor
// re-proposes it forever and the drain precondition never converges. A
// dispatched producer is legitimately mid-run for longer than a lost finalize,
// so the grace window here is wider than the orphan-executed one: passes below
// the threshold emit a non-striking transient tick and passes at/above it emit a
// STRUCTURAL strike, feeding the SAME strike tally so the producer auto-blocks at
// STUCK_PRODUCER_DISPATCH_THRESHOLD and the floor moves on.
const STALE_DISPATCH_RECONCILE_PASS_THRESHOLD = 3;
const STALE_DISPATCH_TICK_REASON = "stale_dispatch_pending";
const STALE_DISPATCH_STRIKE_REASON = "stale_dispatch_unreconciled";
// The node states that have not yet reached 'executed' — a producer in either is
// not making progress toward a terminal producer_run and is reconciled here.
const STALE_DISPATCH_NODE_STATES = Object.freeze(["proposed", "dispatched"]);

// The base producer_id of the identity-keyed sc-expander self-edge. The bare
// node (no chain identity) collides on the per-instance address-keyed scratch
// dirs, so it is suppressed whenever address-keyed instances exist; the per-pass
// instance keys embed the on-chain identity after this prefix.
const SC_ADDRESS_EXPANDER_PRODUCER_ID = "sc_address_expander";

// Pure planner: given the producer packs, the terminal producer_run set, and the
// set of currently-available artifact kinds (root seeds UNION upstream-produced
// kinds), classify every non-terminal producer as ready (its input clause holds)
// or, for a derived producer, a gap (no available kind intersects its consumes).
// Deterministic, side-effect-free — mirrors the cell-floor planner's purity.
//
// The emergent sc_address_expander recursion is BOUND+GATED here additively: the
// optional scSurfaces[] (each {chain_family, chain_id, address, depth,
// provenance?}) is the live smart_contract surface inventory the expander
// re-consumes, and caps{} carries the queue-policy governors. The per-instance
// expander proposals land in sc_expander_instances[] and the kinded over-cap /
// over-depth / unprovenanced reports in sc_recursion_gaps[]; the legacy
// ready/gaps/uncovered_input_types shapes are UNCHANGED so existing consumers
// keep working byte-identically when no sc input is supplied.
function planProducerFloor({
  packs,
  producerRunSet: runSet,
  availableArtifactKinds,
  scSurfaces,
  caps,
}) {
  const available = availableArtifactKinds instanceof Set
    ? availableArtifactKinds
    : new Set(Array.isArray(availableArtifactKinds) ? availableArtifactKinds : []);
  const runs = runSet instanceof Set ? runSet : new Set(runSet || []);
  // When live SC surfaces exist, the per-instance address-keyed expanders below
  // cover the chain recursion, so the bare sc_address_expander is suppressed to
  // avoid a write-after-write collision on the shared address-keyed scratch dirs.
  const hasScSurfaces = Array.isArray(scSurfaces) && scSurfaces.length > 0;
  const ready = [];
  const gaps = [];
  const uncovered = new Set();
  for (const pack of Object.values(packs || {})) {
    if (!pack || typeof pack !== "object") continue;
    const producerId = pack.producer_id;
    if (typeof producerId !== "string" || !producerId) continue;
    // Already terminal — never re-propose. Keeps the materialize->drain loop
    // monotone and convergent to the fixpoint.
    if (runs.has(producerId)) continue;
    const trigger = pack.trigger || {};
    if (trigger.kind === "root") {
      // A root producer's input clause is the presence of its target_class seed:
      // a web root needs the 'target' seed, a chain root the 'chain_address_set'
      // seed. A root with no matching seed is not this session's target class
      // (e.g. a web root in a contracts session) — not ready, but not a gap to
      // fill, so it is simply omitted.
      const rootSeed = trigger.target_class === "web" ? "target" : "chain_address_set";
      if (available.has(rootSeed)) ready.push(pack);
      continue;
    }
    if (trigger.kind === "derived") {
      // The bare sc-expander does no useful work alone — it carries no
      // chain_family/chain_id/address — so suppress it entirely (never ready,
      // never a gap) once address-keyed instances cover the recursion.
      if (producerId === SC_ADDRESS_EXPANDER_PRODUCER_ID && hasScSurfaces) continue;
      const consumes = Array.isArray(trigger.consumes) ? trigger.consumes : [];
      // ONE readiness source (isProducerReady). The default 'all' mode is a JOIN:
      // a multi-input producer (web_assembly's eight kinds) is ready only when
      // EVERY consumed kind is available, never on a partial input set. A pack
      // may opt into 'any' (e.g. sc_address_expander) via trigger.input_mode.
      if (isProducerReady(consumes, available, trigger.input_mode)) {
        ready.push(pack);
      } else {
        const missing = consumes.filter((kind) => !available.has(kind));
        // PRD-2 RANK != BOUND: every not-ready derived producer is REPORTED at
        // construction — pushed onto gaps[] in full, never dropped, capped, or
        // truncated here. Any later display ceiling is an external read-time
        // concern, not a fabric decision at this construction site.
        gaps.push({ producer_id: producerId, missing_input_types: missing });
        for (const kind of missing) uncovered.add(kind);
      }
    }
  }
  const sc = planScExpanderRecursion({ scSurfaces, runs, caps });
  return {
    ready,
    gaps,
    uncovered_input_types: Array.from(uncovered),
    sc_expander_instances: sc.instances,
    sc_recursion_gaps: sc.gaps,
  };
}

// Shared producer-floor fixpoint predicate: the floor is at its fixpoint when a
// plan leaves NO ready non-advisory producer AND NO pending per-instance
// sc-expander. The bare sc_address_expander is suppressed once address-keyed
// instances cover the SC recursion, so the live SC frontier rides in
// plan.sc_expander_instances, which plan.ready no longer represents; a fixpoint
// read off plan.ready alone would report DRAINED while a per-instance expander is
// still pending. Single-sourced so the dispatch handler's
// producer_floor_at_fixpoint and the seed_producers_drained precondition apply the
// identical predicate and can never drift.
function isProducerFloorAtFixpoint(plan) {
  const ready = Array.isArray(plan && plan.ready) ? plan.ready : [];
  const readyNonAdvisory = ready.filter((p) => p && p.advisory !== true);
  const scInstances = Array.isArray(plan && plan.sc_expander_instances)
    ? plan.sc_expander_instances
    : [];
  return readyNonAdvisory.length === 0 && scInstances.length === 0;
}

// Pure: BOUND+GATE the emergent sc-expander recursion. Each scSurface re-proposes
// one per-instance sc_address_expander keyed by its on-chain identity
// (chain_family, chain_id, address.toLowerCase()) at proposed_depth = source
// depth + 1. The bounds are applied in order — DEDUP, OD4 depth cap, OD1 per-pass
// + per-expander cap, OD1 lifetime backstop, OD3 provenance — and every contract
// that is NOT proposed is REPORTED by name in a kinded gap (RANK != BOUND: a cap
// ranks, it never silently drops). The per-pass and per-expander caps are the
// REAL fan-out bounds; the lifetime ceiling is only a backstop.
function planScExpanderRecursion({ scSurfaces, runs, caps }) {
  const instances = [];
  const recursionGaps = [];
  if (!Array.isArray(scSurfaces) || scSurfaces.length === 0) {
    return { instances, gaps: recursionGaps };
  }
  const runSet = runs instanceof Set ? runs : new Set(runs || []);
  const c = (caps && typeof caps === "object") ? caps : {};
  // A missing count cap defaults to the bounded governor normalizeQueuePolicy
  // would produce (the sole caller supplies normalized integers, so this fallback
  // is a bounded safety floor, never unbounded); over-cap contracts are still
  // REPORTED by name (RANK != BOUND). A missing depth cap mirrors the queue-policy
  // default of 3 so the recursion still terminates.
  const depthCap = Number.isInteger(c.linked_contract_depth) ? c.linked_contract_depth : 3;
  const perPassCap = Number.isInteger(c.seed_producer_per_pass_cap) ? c.seed_producer_per_pass_cap : DEFAULT_SEED_PRODUCER_PER_PASS_CAP;
  const perExpanderCap = Number.isInteger(c.per_expander_linked_address_cap) ? c.per_expander_linked_address_cap : DEFAULT_PER_EXPANDER_LINKED_ADDRESS_CAP;
  const lifetimeCeiling = Number.isInteger(c.max_total_seed_producers) ? c.max_total_seed_producers : DEFAULT_MAX_TOTAL_SEED_PRODUCERS;

  // Normalize each source surface to its on-chain identity tuple. A surface
  // missing any of (chain_family, chain_id, address) is not an expander source
  // and is simply skipped (it is not a smart_contract recon source — no gap).
  const sources = [];
  for (const s of scSurfaces) {
    if (!s || typeof s !== "object") continue;
    const chainFamily = typeof s.chain_family === "string" ? s.chain_family.trim() : "";
    const chainId = s.chain_id == null ? "" : String(s.chain_id).trim();
    const rawAddress = typeof s.address === "string"
      ? s.address
      : (typeof s.contract_address === "string" ? s.contract_address : "");
    const address = rawAddress ? rawAddress.trim().toLowerCase() : "";
    if (!chainFamily || !chainId || !address) continue;
    const depth = Number.isInteger(s.depth) ? s.depth : 1;
    const provenance = typeof s.provenance === "string" ? s.provenance.trim() : "";
    sources.push({ chainFamily, chainId, address, depth, provenance });
  }

  // OD3 bound set: the (family:chain_id) pairs and exact addresses carried by
  // SEED (depth <= 1) surfaces. A deeper child on a bound chain at a DIFFERENT
  // address is a linked contract that needs a verified-source provenance marker
  // to be admissible — mirroring authorizeChainScope's provenanced same-chain
  // membership path WITHOUT widening the chain-scope authority gate.
  const boundChains = new Set();
  const boundAddresses = new Set();
  for (const src of sources) {
    if (src.depth <= 1) {
      boundChains.add(`${src.chainFamily}:${src.chainId}`);
      boundAddresses.add(`${src.chainFamily}:${src.chainId}:${src.address}`);
    }
  }

  // Distinct expander contracts already terminal in the run ledger count against
  // the lifetime backstop so the ceiling binds ACROSS passes, not just within one.
  let lifetimeCount = 0;
  for (const key of runSet) {
    if (typeof key === "string" && key.startsWith(`${SC_ADDRESS_EXPANDER_PRODUCER_ID}:`)) lifetimeCount += 1;
  }

  let perPassProposed = 0;
  const perChainProposed = new Map();
  const seenIdentities = new Set();
  const perPassDeferred = [];
  const lifetimeDeferred = [];

  for (const src of sources) {
    const identity = `${src.chainFamily}:${src.chainId}:${src.address}`;
    const producerKey = `${SC_ADDRESS_EXPANDER_PRODUCER_ID}:${identity}`;
    const proposedDepth = src.depth + 1;
    const named = {
      producer_key: producerKey,
      chain_family: src.chainFamily,
      chain_id: src.chainId,
      address: src.address,
    };

    // (1) DEDUP — terminal in the run ledger OR an identity seen earlier in this
    // pass. The same (family, chain_id, address) never re-proposes / re-expands.
    if (runSet.has(producerKey) || seenIdentities.has(identity)) {
      seenIdentities.add(identity);
      continue;
    }
    seenIdentities.add(identity);

    // (2) OD4 DEPTH cap — a producer_key reached past the lineage depth governor
    // is not proposed and is REPORTED by name (non-blocking).
    if (proposedDepth > depthCap) {
      recursionGaps.push({
        kind: "linked_contract_depth_capped",
        producer_key: producerKey,
        chain_family: src.chainFamily,
        chain_id: src.chainId,
        address: src.address,
        depth: proposedDepth,
      });
      continue;
    }

    // (3) OD1 PER-PASS + per-expander caps — the REAL fan-out bounds. At most
    // seed_producer_per_pass_cap instances mint per pass, and at most
    // per_expander_linked_address_cap linked addresses per (family:chain_id)
    // chain-expander. Over-cap instances are deferred and named below.
    const chainKey = `${src.chainFamily}:${src.chainId}`;
    const chainCount = perChainProposed.get(chainKey) || 0;
    if (perPassProposed >= perPassCap || chainCount >= perExpanderCap) {
      perPassDeferred.push(named);
      continue;
    }

    // (4) OD1 LIFETIME ceiling backstop — distinct expanded contracts across the
    // session's lifetime stay under the 1024 ceiling; over-ceiling named below.
    if (lifetimeCount >= lifetimeCeiling) {
      lifetimeDeferred.push(named);
      continue;
    }

    // (5) OD3 PROVENANCE — a same-chain linked child (bound chain, different
    // address) lacking a verified-source provenance marker is not proposed and
    // is REPORTED; an exact seed/bound contract and a provenanced child pass.
    const isSameChainLink = boundChains.has(chainKey) && !boundAddresses.has(identity);
    if (isSameChainLink && !src.provenance) {
      recursionGaps.push({
        kind: "sc_unprovenanced_link",
        producer_key: producerKey,
        chain_family: src.chainFamily,
        chain_id: src.chainId,
        address: src.address,
        depth: proposedDepth,
      });
      continue;
    }
    // A source on a chain NO seed bound (cross-chain / unbound) is outside OD3's
    // same-chain provenance decision, so an unprovenanced one is admitted here
    // WITHOUT a provenance verdict. That admission is unchanged — M3
    // authorizeChainScope still gates every off-authority read and OD1 still
    // bounds fan-out — but the skipped provenance check is REPORTED rather than
    // silently passed (report-gaps: a skip is observable, never silent).
    if (!boundChains.has(chainKey) && !src.provenance) {
      recursionGaps.push({
        kind: "sc_cross_chain_provenance_skipped",
        producer_key: producerKey,
        chain_family: src.chainFamily,
        chain_id: src.chainId,
        address: src.address,
        depth: proposedDepth,
      });
    }

    instances.push({
      producer_key: producerKey,
      chain_family: src.chainFamily,
      chain_id: src.chainId,
      address: src.address,
      depth: proposedDepth,
    });
    perPassProposed += 1;
    perChainProposed.set(chainKey, chainCount + 1);
    lifetimeCount += 1;
  }

  // RANK != BOUND: the per-pass/per-expander and lifetime deferrals are reported
  // as kinded gaps that NAME every deferred contract — never a silent truncation.
  if (perPassDeferred.length > 0) {
    recursionGaps.push({
      kind: "sc_linked_address_capped",
      deferred_contracts: perPassDeferred,
      cap: Number.isFinite(perPassCap) ? perPassCap : null,
    });
  }
  if (lifetimeDeferred.length > 0) {
    recursionGaps.push({
      kind: "sc_lifetime_ceiling",
      deferred_contracts: lifetimeDeferred,
      ceiling: Number.isFinite(lifetimeCeiling) ? lifetimeCeiling : null,
    });
  }
  return { instances, gaps: recursionGaps };
}

// Pure planner: classify every executed producer node whose producer_key carries
// NO terminal producer_run row as either a non-striking transient tick (its
// running orphan index is below passThreshold — one pass of grace for an in-flight
// finalize) or a structural strike (index at/above passThreshold). Deterministic
// and side-effect-free; dedups by producer_key because producerNodeId folds at
// most one executed node per key. A finalized/verified/failed node, or any node
// whose key is already terminal, is never ticked or struck.
function planOrphanReconcile({
  producerNodes,
  nodeIdToProducerKey,
  terminalRunSet,
  orphanCountsByKey,
  passThreshold,
}) {
  const map = nodeIdToProducerKey instanceof Map ? nodeIdToProducerKey : new Map();
  const runs = terminalRunSet instanceof Set ? terminalRunSet : new Set(terminalRunSet || []);
  const counts = orphanCountsByKey instanceof Map ? orphanCountsByKey : new Map();
  const threshold = Number.isInteger(passThreshold) && passThreshold > 0
    ? passThreshold
    : ORPHAN_EXECUTED_RECONCILE_PASS_THRESHOLD;
  const ticks = [];
  const strikes = [];
  const seen = new Set();
  for (const node of Array.isArray(producerNodes) ? producerNodes : []) {
    if (!node || node.kind !== PRODUCER_NODE_KIND) continue;
    if (node.state !== "executed") continue;
    const producerKey = map.get(node.node_id);
    if (typeof producerKey !== "string" || !producerKey) continue;
    // The orphan condition: an executed producer node with no terminal
    // producer_run row. A key already terminal is done — never reconciled.
    if (runs.has(producerKey)) continue;
    if (seen.has(producerKey)) continue;
    seen.add(producerKey);
    const thisPassIndex = (counts.get(producerKey) || 0) + 1;
    if (thisPassIndex < threshold) {
      ticks.push({ producer_key: producerKey, node_id: node.node_id });
    } else {
      strikes.push({ producer_key: producerKey, node_id: node.node_id });
    }
  }
  return { ticks, strikes };
}

// Pure planner: classify every producer node stuck in a pre-executed state
// (proposed | dispatched) whose producer_key carries NO terminal producer_run
// row as either a non-striking transient tick (its running stale index is below
// passThreshold — grace for a producer still legitimately mid-dispatch) or a
// structural strike (index at/above passThreshold). Deterministic and
// side-effect-free; dedups by producer_key. A node that has reached 'executed'
// (handled by the orphan-executed reconciler), any terminal node, or any node
// whose key is already terminal, is never ticked or struck here.
function planStaleDispatchReconcile({
  producerNodes,
  nodeIdToProducerKey,
  terminalRunSet,
  staleCountsByKey,
  passThreshold,
}) {
  const map = nodeIdToProducerKey instanceof Map ? nodeIdToProducerKey : new Map();
  const runs = terminalRunSet instanceof Set ? terminalRunSet : new Set(terminalRunSet || []);
  const counts = staleCountsByKey instanceof Map ? staleCountsByKey : new Map();
  const threshold = Number.isInteger(passThreshold) && passThreshold > 0
    ? passThreshold
    : STALE_DISPATCH_RECONCILE_PASS_THRESHOLD;
  const ticks = [];
  const strikes = [];
  const seen = new Set();
  for (const node of Array.isArray(producerNodes) ? producerNodes : []) {
    if (!node || node.kind !== PRODUCER_NODE_KIND) continue;
    if (!STALE_DISPATCH_NODE_STATES.includes(node.state)) continue;
    const producerKey = map.get(node.node_id);
    if (typeof producerKey !== "string" || !producerKey) continue;
    if (runs.has(producerKey)) continue;
    if (seen.has(producerKey)) continue;
    seen.add(producerKey);
    const thisPassIndex = (counts.get(producerKey) || 0) + 1;
    if (thisPassIndex < threshold) {
      ticks.push({ producer_key: producerKey, node_id: node.node_id });
    } else {
      strikes.push({ producer_key: producerKey, node_id: node.node_id });
    }
  }
  return { ticks, strikes };
}

// Build the freshest reconcile inputs live: the read-only producer graph nodes
// plus the node_id -> producer_key map recovered from the producer_proposed
// events (the same scan the seed-producer scheduler uses). Shared by both the
// orphan-executed and stale-dispatch reconcilers so they read identical state.
function buildLiveProducerReconcileInputs(domain) {
  const live = materializeTaskGraph(domain, { write: false });
  const producerNodes = Array.isArray(live.document.nodes) ? live.document.nodes : [];
  const map = new Map();
  for (const event of readFrontierEvents(domain)) {
    if (!event || event.kind !== "observation.recorded") continue;
    const payload = event.payload;
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) continue;
    const obsKind = (typeof payload.observation_kind === "string" && payload.observation_kind.trim())
      ? payload.observation_kind.trim()
      : (typeof payload.kind === "string" ? payload.kind.trim() : "");
    if (obsKind !== "producer_proposed") continue;
    const producerKey = (typeof payload.producer_key === "string" && payload.producer_key)
      ? payload.producer_key
      : (typeof payload.producer_id === "string" ? payload.producer_id : null);
    if (!producerKey) continue;
    map.set(producerNodeId({ producerKey }), producerKey);
  }
  return { producerNodes, nodeIdToProducerKey: map };
}

// The running reconcile index per producer_key = how many prior tick/strike rows
// carrying one of `reasons` it already accrued. Recomputed over the append-only
// ledger so the K-grace debounce is monotone across passes.
function countReconcileRowsByKey(domain, reasons) {
  const reasonSet = reasons instanceof Set ? reasons : new Set(Array.isArray(reasons) ? reasons : [reasons]);
  const counts = new Map();
  for (const event of readFrontierEvents(domain)) {
    if (!event || event.kind !== "observation.recorded") continue;
    const payload = event.payload;
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) continue;
    if (payload.observation_kind !== "producer_run") continue;
    if (payload.status !== "failed_retryable") continue;
    if (!reasonSet.has(payload.reason)) continue;
    const key = typeof payload.producer_key === "string" ? payload.producer_key : null;
    if (!key) continue;
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return counts;
}

// Impure executor: reconcile every executed-orphan producer node against the
// producer_run ledger. Reuses recordProducerRun/producerRunSet only — no new
// observation subtype, no new ledger file; ticks vs strikes are distinguished by
// reason tag and failure_class, and every write lands in frontier-events.jsonl.
// When nodes/map are omitted the freshest state is built live: read-only graph
// nodes plus the node_id -> producer_key map from the producer_proposed events
// (the same scan the seed-producer scheduler uses). The third structural strike
// auto-writes a single terminal blocked row, after which the key is terminal and
// both the floor and the reconciler skip it — bounded.
function reconcileOrphanExecutedProducers(domain, { nodes, nodeIdToProducerKey } = {}) {
  let producerNodes = nodes;
  let map = nodeIdToProducerKey;
  if (!Array.isArray(producerNodes) || !(map instanceof Map)) {
    ({ producerNodes, nodeIdToProducerKey: map } = buildLiveProducerReconcileInputs(domain));
  }

  const terminalRunSet = producerRunSet(domain);
  const orphanCountsByKey = countReconcileRowsByKey(domain, [ORPHAN_TICK_REASON, ORPHAN_STRIKE_REASON]);

  const plan = planOrphanReconcile({
    producerNodes,
    nodeIdToProducerKey: map,
    terminalRunSet,
    orphanCountsByKey,
    passThreshold: ORPHAN_EXECUTED_RECONCILE_PASS_THRESHOLD,
  });

  const ticked = [];
  const struck = [];
  const autoBlocked = [];
  for (const tick of plan.ticks) {
    recordProducerRun(domain, {
      producer_key: tick.producer_key,
      status: "failed_retryable",
      failure_class: "transient",
      reason: ORPHAN_TICK_REASON,
    });
    ticked.push(tick.producer_key);
  }
  for (const strike of plan.strikes) {
    const result = recordProducerRun(domain, {
      producer_key: strike.producer_key,
      status: "failed_retryable",
      failure_class: "structural",
      reason: ORPHAN_STRIKE_REASON,
    });
    struck.push(strike.producer_key);
    if (result && result.auto_blocked) autoBlocked.push(strike.producer_key);
  }
  return { ticked, struck, auto_blocked: autoBlocked };
}

// Impure executor: reconcile every stale-dispatch producer node (stuck
// 'proposed'/'dispatched' with no terminal producer_run row) against the
// producer_run ledger. Mirrors reconcileOrphanExecutedProducers exactly — same
// recordProducerRun strike path, same shared live-state + count helpers — but
// over the pre-executed node states with the wider stale-dispatch grace window.
// The structural strikes feed the SAME strike tally, so a producer that never
// progresses past dispatch auto-blocks at STUCK_PRODUCER_DISPATCH_THRESHOLD and
// the floor stops re-proposing it — the drain precondition then converges.
function reconcileStaleDispatchProducers(domain, { nodes, nodeIdToProducerKey } = {}) {
  let producerNodes = nodes;
  let map = nodeIdToProducerKey;
  if (!Array.isArray(producerNodes) || !(map instanceof Map)) {
    ({ producerNodes, nodeIdToProducerKey: map } = buildLiveProducerReconcileInputs(domain));
  }

  const terminalRunSet = producerRunSet(domain);
  const staleCountsByKey = countReconcileRowsByKey(domain, [STALE_DISPATCH_TICK_REASON, STALE_DISPATCH_STRIKE_REASON]);

  const plan = planStaleDispatchReconcile({
    producerNodes,
    nodeIdToProducerKey: map,
    terminalRunSet,
    staleCountsByKey,
    passThreshold: STALE_DISPATCH_RECONCILE_PASS_THRESHOLD,
  });

  const ticked = [];
  const struck = [];
  const autoBlocked = [];
  for (const tick of plan.ticks) {
    recordProducerRun(domain, {
      producer_key: tick.producer_key,
      status: "failed_retryable",
      failure_class: "transient",
      reason: STALE_DISPATCH_TICK_REASON,
    });
    ticked.push(tick.producer_key);
  }
  for (const strike of plan.strikes) {
    const result = recordProducerRun(domain, {
      producer_key: strike.producer_key,
      status: "failed_retryable",
      failure_class: "structural",
      reason: STALE_DISPATCH_STRIKE_REASON,
    });
    struck.push(strike.producer_key);
    if (result && result.auto_blocked) autoBlocked.push(strike.producer_key);
  }
  return { ticked, struck, auto_blocked: autoBlocked };
}

// Read the live smart_contract surface inventory as the sc-expander recursion
// sources. Each surface carrying full chain identity (chain_family, chain_id,
// contract_address) is one recon source the per-instance expander re-consumes.
// SHARED by the producer-floor handler and the seed_producers_drained
// precondition so both see the same scSurfaces and suppress the bare expander
// identically — the suppression can never desync between dispatch and the drain
// gate. Tolerant of an empty surface set.
function readScExpanderSurfaces(domain) {
  const surfaceRead = currentSurfaces(domain);
  const surfaceRows = Array.isArray(surfaceRead && surfaceRead.surfaces) ? surfaceRead.surfaces : [];
  const scSurfaces = [];
  for (const surface of surfaceRows) {
    if (!surface || typeof surface !== "object") continue;
    if (surface.surface_type !== "smart_contract") continue;
    const chainFamily = typeof surface.chain_family === "string" ? surface.chain_family.trim() : "";
    const chainId = surface.chain_id == null ? "" : String(surface.chain_id).trim();
    const address = typeof surface.contract_address === "string" ? surface.contract_address.trim() : "";
    if (!chainFamily || !chainId || !address) continue;
    const depth = Number.isInteger(surface.depth) ? surface.depth : 1;
    const provenance = typeof surface.provenance === "string" ? surface.provenance.trim() : "";
    scSurfaces.push({ chain_family: chainFamily, chain_id: chainId, address, depth, provenance });
  }
  return scSurfaces;
}

// Single-sourced producer-floor PLAN builder. Assembles the EXACT inputs the
// dispatch handler feeds planProducerFloor — the policy-derived caps
// (linked_contract_depth + the OD1 seed governors), the live smart_contract
// surface inventory, the terminal producer_run set, and the available artifact
// kinds (root seeds UNION every terminal producer's produces[]) — and returns the
// resulting plan alongside those inputs. SHARED by the bob_materialize_producer_
// floor handler and the seed_producers_drained scheduler precondition so the whole
// PLAN (not merely the isProducerFloorAtFixpoint predicate) is single-sourced: the
// SAME persisted linked_contract_depth, scSurfaces, and availableArtifactKinds feed
// BOTH, so the caps that govern the sc-expander recursion depth cannot drift. A
// gate that rebuilt the plan WITHOUT these caps would fall back to the hardcoded
// planScExpanderRecursion depthCap default of 3 and, at a non-default
// linked_contract_depth (0/1), wait forever for a depth-capped expander the
// dispatcher will never propose — freezing the frontier. Read-only: loadQueuePolicy
// / producerRunSet / readScExpanderSurfaces / readJsonFile are all reads and
// planProducerFloor is pure, so it is safe to call from the read-only drain gate.
function buildProducerFloorPlan(domain) {
  assertNonEmptyString(domain, "target_domain");
  // Load the queue policy on the same governor surface as the sibling cell floor;
  // it also fails loud on a malformed persisted policy before any emission.
  const policy = loadQueuePolicy(domain);
  const caps = {
    linked_contract_depth: policy.linked_contract_depth,
    seed_producer_per_pass_cap: policy.seed_producer_per_pass_cap,
    per_expander_linked_address_cap: policy.per_expander_linked_address_cap,
    max_total_seed_producers: policy.max_total_seed_producers,
  };
  const runSet = producerRunSet(domain);
  // The live smart_contract surface inventory is the sc-expander recursion's recon
  // sources (and, when non-empty, suppresses the bare expander).
  const scSurfaces = readScExpanderSurfaces(domain);
  let state = {};
  try {
    state = readJsonFile(statePath(domain), { label: "state.json" }) || {};
  } catch {
    state = {};
  }
  // availableArtifactKinds = root seeds UNION the produces[] of every producer
  // already terminal in the run ledger. A web session seeds 'target'; a chain
  // session seeds 'chain_address_set'; each produced upstream producer unlocks its
  // produces[] kinds for the derived producers downstream.
  const availableArtifactKinds = new Set();
  if (typeof state.target_url === "string" && state.target_url) {
    availableArtifactKinds.add("target");
  }
  if (Array.isArray(state.target_contracts) && state.target_contracts.length > 0) {
    availableArtifactKinds.add("chain_address_set");
  }
  for (const producerKey of runSet) {
    const pack = PRODUCER_PACKS[producerKey];
    if (pack && Array.isArray(pack.produces)) {
      for (const kind of pack.produces) availableArtifactKinds.add(kind);
    }
  }
  const plan = planProducerFloor({
    packs: PRODUCER_PACKS,
    producerRunSet: runSet,
    availableArtifactKinds,
    scSurfaces,
    caps,
  });
  return { plan, policy, caps, runSet, scSurfaces, availableArtifactKinds };
}

function handler(args) {
  const domain = assertNonEmptyString((args || {}).target_domain, "target_domain");
  // Single-sourced with the seed_producers_drained precondition: buildProducerFloorPlan
  // loads the queue policy, derives the OD1/OD4 caps, reads the live SC surface
  // inventory + the terminal producer_run set, assembles availableArtifactKinds, and
  // runs the pure planProducerFloor. The web/derived producer emission is unbounded
  // (every ready producer is enumerated — RANK != BOUND); the OD1/OD4 caps bound only
  // the emergent sc-expander recursion. The drain gate calls the SAME builder, so the
  // caps that govern the sc-expander recursion depth cannot drift between dispatch and
  // the freeze precondition.
  const { plan } = buildProducerFloorPlan(domain);

  // Fold each ready producer into a producer node by emitting a producer_proposed
  // observation.recorded event; the materializer's producer_proposed branch turns
  // it into a kind-'producer' node via producerNodeId. No contract is attached —
  // contract wiring + dispatch is the seed-producer scheduler's job.
  let tier1ProducersEmitted = 0;
  for (const pack of plan.ready) {
    appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      payload: {
        observation_kind: "producer_proposed",
        producer_key: pack.producer_id,
        producer_id: pack.producer_id,
      },
      actor: "orchestrator",
    });
    // The Tier-1 fixpoint count excludes advisory producers; every current pack
    // is advisory:false, so this equals the total emitted today.
    if (pack.advisory !== true) tier1ProducersEmitted += 1;
  }

  // Fold each bounded sc-expander instance into its own producer node. The
  // per-instance producer_key embeds the on-chain identity; the depth + chain
  // identity ride on the payload so finalize-node can recover them, mint the
  // identity-keyed child surface, and record the instance terminal (dedup).
  for (const instance of plan.sc_expander_instances) {
    appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      payload: {
        observation_kind: "producer_proposed",
        producer_key: instance.producer_key,
        producer_id: instance.producer_key,
        chain_family: instance.chain_family,
        chain_id: instance.chain_id,
        contract_address: instance.address,
        depth: instance.depth,
      },
      actor: "orchestrator",
    });
  }

  if (plan.ready.length > 0 || plan.sc_expander_instances.length > 0) {
    // Materialize so the freshly-emitted producer nodes exist before a later
    // scheduler pass reads them.
    materializeTaskGraph(domain, { write: true });
    try {
      scheduleMaterialization(domain);
    } catch {
      // Materialization debounce is best-effort; never regress the appends.
    }
  }

  // Reconcile executed-orphan producer nodes against the freshest graph state
  // (read AFTER the emission + materialize above, so a freshly-proposed producer
  // sits in 'proposed' and is never reconciled). A node stuck 'executed' with no
  // terminal producer_run row lost its finalize across the turn barrier; the
  // reconciler converts it to a strike so the floor re-proposes it and it
  // auto-blocks at the threshold. Best-effort: never regress the floor emission.
  let orphanReconciled = { ticked: [], struck: [], auto_blocked: [] };
  try {
    orphanReconciled = reconcileOrphanExecutedProducers(domain);
  } catch {
    orphanReconciled = { ticked: [], struck: [], auto_blocked: [] };
  }

  // Reconcile stale-dispatch producer nodes against the same freshest graph
  // state. A node stuck 'proposed' (never scheduled) or 'dispatched' (a worker
  // that never returned executed) makes no progress; the reconciler grants the
  // stale-dispatch grace window, then strikes it structurally so it auto-blocks
  // at the threshold and the floor stops re-proposing it. A freshly-proposed
  // producer accrues only the grace tick and clears the moment it advances or
  // turns terminal. Best-effort: never regress the floor emission.
  let staleDispatchReconciled = { ticked: [], struck: [], auto_blocked: [] };
  try {
    staleDispatchReconciled = reconcileStaleDispatchProducers(domain);
  } catch {
    staleDispatchReconciled = { ticked: [], struck: [], auto_blocked: [] };
  }

  return JSON.stringify({
    version: 1,
    target_domain: domain,
    tier1_producers_emitted: tier1ProducersEmitted,
    // The producer floor is at its fixpoint once a full drain emits no new
    // non-advisory producer AND no new sc-expander instance: the reachable
    // producer set is finite, the run ledger is monotone, and the sc recursion is
    // depth/identity bounded, so emissions strictly decrease to 0 — a real fixpoint.
    producer_floor_at_fixpoint: isProducerFloorAtFixpoint(plan),
    // RANK != BOUND: not-ready derived producers are reported, never dropped.
    producer_gaps: plan.gaps.slice(0, 100),
    uncovered_input_types: plan.uncovered_input_types,
    // RANK != BOUND: every depth-capped / over-cap / unprovenanced linked
    // contract is reported by name, never silently dropped.
    sc_recursion_gaps: plan.sc_recursion_gaps.slice(0, 100),
    // RANK != BOUND: executed-orphan producers whose finalize was lost across the
    // turn barrier are reported (ticked grace / structural strikes / auto-blocked
    // keys), never silently abandoned. Empty when no executed-orphan node exists.
    orphan_executed_reconciled: orphanReconciled,
    // RANK != BOUND: stale-dispatch producers stuck pre-executed are reported the
    // same way, never silently abandoned. Empty when no stale-dispatch node exists.
    stale_dispatch_reconciled: staleDispatchReconciled,
  });
}

module.exports = Object.freeze({
  name: "bob_materialize_producer_floor",
  description:
    "Materialize the deterministic recon-producer FLOOR: sweep the PRODUCER_PACKS "
    + "DAG and emit one producer_proposed observation.recorded event per producer "
    + "that is ready (root seed present / an available upstream artifact kind "
    + "intersects its consumes) and not already terminal in the producer_run "
    + "ledger, which the materializer folds into schedulable 'producer' TaskGraph "
    + "nodes. Drains to producer_floor_at_fixpoint (no new non-advisory producer). "
    + "Not-ready derived producers are reported in producer_gaps[] / "
    + "uncovered_input_types[], never dropped. Single-spawner: the orchestrator "
    + "appends, no worker spawn.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
    },
    required: ["target_domain"],
  },
  handler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["frontier-events.jsonl"],
  // The pure planner is exported as an inert extra key on the tool descriptor so
  // the seed_producers_drained scheduler precondition reuses the same ready/gaps
  // logic instead of duplicating it. defineTool (tool-registry.js) consumes only
  // the known descriptor fields, so registration ignores this key. The reconciler
  // helpers and the shared surface reader ride the same inert-key precedent for
  // the termination tests and the precondition's suppression parity.
  planProducerFloor,
  buildProducerFloorPlan,
  isProducerFloorAtFixpoint,
  planOrphanReconcile,
  planStaleDispatchReconcile,
  reconcileOrphanExecutedProducers,
  reconcileStaleDispatchProducers,
  readScExpanderSurfaces,
  ORPHAN_EXECUTED_RECONCILE_PASS_THRESHOLD,
  STALE_DISPATCH_RECONCILE_PASS_THRESHOLD,
});
