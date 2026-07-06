"use strict";

const crypto = require("crypto");
const fs = require("fs");

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
const { CASE_FOLD_SAFE_CHAIN_FAMILIES, contractIdentityKey } = require("../chain-authority.js");
const {
  producerRunSet,
  recordProducerRun,
  buildProducerRunLedgerCache,
  isProducerRunLedgerCache,
} = require("../producer-run-ledger.js");
const { materializeTaskGraph, producerNodeId } = require("../task-graph-materializer.js");
const { loadQueuePolicy, CLAMP_CEILING } = require("../queue-policy.js");
const { httpAuditJsonlPath, statePath, trafficJsonlPath } = require("../paths.js");
const { readFileUtf8, readJsonFile, withSessionLock } = require("../storage.js");
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
// re-proposes it forever and the drain precondition never converges. Non-progress
// is judged by the WALL-CLOCK age of the node's most recent transition (ts_last),
// NEVER by how many times the sibling floor tool ran: dispatch
// (bob_schedule_seed_producers) is a SEPARATE tool with no guaranteed
// interleaving, so a per-floor-pass strike would auto-block a healthy in-flight
// producer after a handful of rapid floor calls even while its worker is still
// progressing. A node whose last transition is within STALE_DISPATCH_GRACE_MS is
// still legitimately in-flight — its PENDING state already rides its live graph
// transition, so a within-grace observation is REPORTED but persists NO
// producer_run row (persisting one transient tick per floor pass across the
// 15-minute grace window would grow the append-only ledger unboundedly, one
// row/pass, toward the refuse ceiling). Only a node aged past the window (or
// carrying no observable timestamp) writes a row: a STRUCTURAL strike feeding the
// strike tally, so a genuinely non-progressing producer still auto-blocks at
// STUCK_PRODUCER_DISPATCH_THRESHOLD (a bounded ≤ threshold rows) and the floor
// moves on. producer_run reconcile rows carry no node_id, so they never touch
// ts_last — the clock advances only on a real node transition, never on reconcile
// activity.
const STALE_DISPATCH_GRACE_MS = 15 * 60 * 1000;
const STALE_DISPATCH_STRIKE_REASON = "stale_dispatch_unreconciled";
// The node states that have not yet reached 'executed' — a producer in either is
// not making progress toward a terminal producer_run and is reconciled here.
const STALE_DISPATCH_NODE_STATES = Object.freeze(["proposed", "dispatched"]);

// The base producer_id of the identity-keyed sc-expander self-edge. The bare
// node (no chain identity) collides on the per-instance address-keyed scratch
// dirs, so it is suppressed whenever address-keyed instances exist; the per-pass
// instance keys embed the on-chain identity after this prefix.
const SC_ADDRESS_EXPANDER_PRODUCER_ID = "sc_address_expander";
const WEB_HTTP_BODIES_PRODUCER_ID = "web_http_bodies";
const WEB_ONCHAIN_REF_PRODUCER_ID = "web_onchain_ref";
const COMPOSITION_TRANSITION_KIND = "identity_propagation";

function compositionTransitionSurfaceId(payload, eventId) {
  const proposalId = typeof payload.proposal_id === "string" ? payload.proposal_id.trim() : "";
  if (proposalId) return `transition:${proposalId}`;
  const from = typeof payload.from_surface === "string" ? payload.from_surface.trim() : "";
  const to = typeof payload.to_surface === "string" ? payload.to_surface.trim() : "";
  const kind = typeof payload.transition_kind === "string" ? payload.transition_kind.trim() : "";
  if (from && to && kind) return `transition:${from}::${to}::${kind}`;
  return `transition:event:${eventId}`;
}

function loadTransitionSurfaceId() {
  const { transitionSurfaceId } = require("../frontier-materializer.js");
  return typeof transitionSurfaceId === "function"
    ? transitionSurfaceId
    : compositionTransitionSurfaceId;
}

// Case-folding an on-chain address is only safe where the address encoding is
// case-INSENSITIVE: EVM hex and the hex Move families (aptos, sui). Solana (svm)
// base58, Substrate SS58, and Cosmos bech32 are case-SENSITIVE — lowercasing them
// corrupts the pubkey (a dedup collision plus a wrong on-chain fetch). Keyed on
// chain_family so the identity tuple / per-instance producer_key / dedup sets stay
// faithful, and consistent with readScExpanderSurfaces which never lowercases.
// CASE_FOLD_SAFE_CHAIN_FAMILIES is imported from chain-authority.js (single-sourced),
// so this planner and the authority normalizer key address case-folding identically.

// Clamp a caps knob into a sane [lo, hi] range. Number.isInteger ALONE lets a
// negative, zero, or absurdly-large override through; the planner is a pure
// function reachable from tests and future callers, so it clamps here rather than
// trusting its sole live caller (buildProducerFloorPlan, which feeds normalized
// policy caps) to pre-normalize. The count-cap ceiling matches queue-policy.js's
// CLAMP_CEILING width governor; a non-integer falls back to the bounded default.
function clampCap(value, { lo, hi, fallback }) {
  if (!Number.isInteger(value)) return fallback;
  if (value < lo) return lo;
  if (value > hi) return hi;
  return value;
}

function planCompositionFloor({
  leakedIdentifierFacts,
  surfaceIds,
  existingTransitionKeys,
  transitionKeyOf,
  transitionKindValues,
}) {
  const kindValues = transitionKindValues || require("../task-graph-events.js").TRANSITION_KIND_VALUES;
  if (!Array.isArray(kindValues)
    || !kindValues.includes(COMPOSITION_TRANSITION_KIND)) {
    return {
      propose: [],
      blocked_prereqs: [{
        kind: "missing_transition_kind",
        transition_kind: COMPOSITION_TRANSITION_KIND,
      }],
    };
  }
  if (typeof transitionKeyOf !== "function") {
    throw new Error("transitionKeyOf must be a function");
  }

  const eligibleSurfaceIds = surfaceIds instanceof Set ? surfaceIds : null;
  const shouldFilterSurfaces = !!(eligibleSurfaceIds && eligibleSurfaceIds.size > 0);
  const existingKeys = existingTransitionKeys instanceof Set
    ? existingTransitionKeys
    : new Set(existingTransitionKeys || []);
  const groups = new Map();
  const facts = Array.isArray(leakedIdentifierFacts) ? leakedIdentifierFacts : [];

  for (const fact of facts) {
    const payload = fact && fact.payload && typeof fact.payload === "object" ? fact.payload : fact;
    if (!payload || typeof payload !== "object") continue;
    const identifierClass = typeof payload.identifier_class === "string"
      ? payload.identifier_class.trim()
      : "";
    const identifierFingerprint = typeof payload.identifier_fingerprint === "string"
      ? payload.identifier_fingerprint.trim()
      : "";
    const surfaceId = typeof payload.surface_id === "string" ? payload.surface_id.trim() : "";
    if (!identifierClass || !identifierFingerprint || !surfaceId) continue;
    if (shouldFilterSurfaces && !eligibleSurfaceIds.has(surfaceId)) continue;

    const groupKey = `${identifierClass}${identifierFingerprint}`;
    if (!groups.has(groupKey)) {
      groups.set(groupKey, {
        identifier_class: identifierClass,
        surfaces: new Map(),
      });
    }
    const group = groups.get(groupKey);
    if (!group.surfaces.has(surfaceId)) group.surfaces.set(surfaceId, []);
    if (payload.claim_id != null) {
      const claimId = String(payload.claim_id).trim();
      if (claimId && !group.surfaces.get(surfaceId).includes(claimId)) {
        group.surfaces.get(surfaceId).push(claimId);
      }
    }
  }

  const propose = [];
  // Within-pass dedup: M distinct shared identifiers across the SAME surface pair {A,B}
  // must emit ONE (A,B) transition, not M identical ones (write-amplification on an
  // identifier-rich, attacker-influenceable body). existingKeys dedups vs prior passes;
  // this set dedups vs THIS pass.
  const proposedKeys = new Set();
  for (const key of Array.from(groups.keys()).sort()) {
    const group = groups.get(key);
    const surfaces = Array.from(group.surfaces.keys()).sort();
    if (surfaces.length < 2) continue;
    for (let i = 0; i < surfaces.length; i += 1) {
      for (let j = i + 1; j < surfaces.length; j += 1) {
        const from = surfaces[i];
        const to = surfaces[j];
        const forwardKey = transitionKeyOf({ from, to });
        const reverseKey = transitionKeyOf({ from: to, to: from });
        if (existingKeys.has(forwardKey) || existingKeys.has(reverseKey)) continue;
        if (proposedKeys.has(forwardKey) || proposedKeys.has(reverseKey)) continue;
        proposedKeys.add(forwardKey);

        const evidenceRefs = [];
        const fromClaim = group.surfaces.get(from)[0];
        const toClaim = group.surfaces.get(to)[0];
        if (fromClaim) evidenceRefs.push(String(fromClaim));
        if (toClaim && toClaim !== fromClaim) evidenceRefs.push(String(toClaim));
        propose.push({
          from_surface: from,
          to_surface: to,
          kind: COMPOSITION_TRANSITION_KIND,
          trust_assumption:
            `identity_propagation: an ${group.identifier_class} leaked on surface ${from} `
            + `also indexes surface ${to}; untested cross-collection identity handoff`,
          evidence_refs: evidenceRefs,
        });
      }
    }
  }

  return { propose, blocked_prereqs: [] };
}

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
      if (producerId === WEB_HTTP_BODIES_PRODUCER_ID && !available.has("http_bodies")) continue;
      if (available.has(rootSeed)) ready.push(pack);
      continue;
    }
    if (trigger.kind === "derived") {
      // The bare sc-expander does no useful work alone — it carries no
      // chain_family/chain_id/address — so suppress it entirely (never ready,
      // never a gap) once address-keyed instances cover the recursion.
      if (producerId === SC_ADDRESS_EXPANDER_PRODUCER_ID && hasScSurfaces) continue;
      const consumes = Array.isArray(trigger.consumes) ? trigger.consumes : [];
      const produces = Array.isArray(pack.produces) ? pack.produces : [];
      // ONE readiness source (isProducerReady). The default 'all' mode is a JOIN:
      // a multi-input producer (web_assembly's eight kinds) is ready only when
      // EVERY consumed kind is available, never on a partial input set. A pack
      // may opt into 'any' (e.g. sc_address_expander) via trigger.input_mode.
      // pack.produces is passed so a self-edge kind (sc_surface, which the expander
      // both consumes AND produces) is excluded from readiness: a self-produced kind
      // is permanently available once minted and would make the producer "ready
      // forever", so readiness rests on the external inputs and the self-recursion's
      // termination is carried structurally by the per-instance dedup below (an
      // instance is proposed iff its on-chain identity is un-expanded).
      if (isProducerReady(consumes, available, trigger.input_mode, produces)) {
        ready.push(pack);
      } else {
        // Report only the EXTERNAL (non-self-produced) inputs as missing — a
        // self-edge kind is never a readiness input, so it is never "missing".
        const selfProduced = new Set(produces);
        const missing = consumes.filter((kind) => !selfProduced.has(kind) && !available.has(kind));
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
  // Every cap is CLAMPED, not merely defaulted: a Number.isInteger guard alone
  // admits a negative, zero, or absurdly-large override, all of which corrupt the
  // fan-out bound. A missing/non-integer cap falls back to the bounded governor
  // normalizeQueuePolicy would produce; a present one is clamped into the same sane
  // range queue-policy.js enforces (depth [0..32], counts [1..CLAMP_CEILING]).
  // Over-cap contracts are still REPORTED by name (RANK != BOUND).
  const depthCap = clampCap(c.linked_contract_depth, { lo: 0, hi: 32, fallback: 3 });
  const perPassCap = clampCap(c.seed_producer_per_pass_cap, { lo: 1, hi: CLAMP_CEILING, fallback: DEFAULT_SEED_PRODUCER_PER_PASS_CAP });
  const perExpanderCap = clampCap(c.per_expander_linked_address_cap, { lo: 1, hi: CLAMP_CEILING, fallback: DEFAULT_PER_EXPANDER_LINKED_ADDRESS_CAP });
  const lifetimeCeiling = clampCap(c.max_total_seed_producers, { lo: 1, hi: CLAMP_CEILING, fallback: DEFAULT_MAX_TOTAL_SEED_PRODUCERS });

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
    // Case-fold ONLY where the address encoding is case-insensitive (EVM hex, hex
    // Move). svm base58 / substrate SS58 / cosmwasm bech32 are case-sensitive, so
    // their addresses ride verbatim — lowercasing would corrupt the pubkey.
    const trimmedAddress = rawAddress ? rawAddress.trim() : "";
    const address = CASE_FOLD_SAFE_CHAIN_FAMILIES.has(chainFamily.toLowerCase())
      ? trimmedAddress.toLowerCase()
      : trimmedAddress;
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

// Parse a producer node's most-recent transition timestamp (ts_last, falling
// back to ts_first) into epoch ms, or null when absent/unparseable. This is the
// non-progress clock the stale-dispatch reconciler reads: it advances ONLY when
// the node genuinely transitions, and producer_run reconcile rows carry no
// node_id so they never touch it — the clock can never be inflated by the
// reconciler's own writes.
function nodeProgressMs(node) {
  const raw = (node && typeof node.ts_last === "string" && node.ts_last)
    ? node.ts_last
    : (node && typeof node.ts_first === "string" ? node.ts_first : "");
  const ms = Date.parse(raw);
  return Number.isFinite(ms) ? ms : null;
}

// Pure planner: classify every producer node stuck in a pre-executed state
// (proposed | dispatched) whose producer_key carries NO terminal producer_run row
// as either a within-grace tick (its most recent transition is within graceMs of
// nowMs — the producer is still legitimately mid-dispatch) or a structural strike
// (aged past the grace window, or carrying no observable timestamp — no forward
// progress). The clock is WALL-CLOCK node age, never a floor-pass count, so a
// healthy in-flight producer is never struck by repeated floor calls, while a
// genuinely non-progressing one still accrues one strike per past-grace pass and
// converges to a terminal auto-block. The executor REPORTS ticks (the pending
// state rides the node's live graph transition) but persists only strikes, so
// within-grace passes add no ledger rows. Deterministic and side-effect-free;
// dedups by producer_key. A node that has reached 'executed' (handled by the
// orphan-executed reconciler), any terminal node, or any node whose key is already
// terminal, is never ticked or struck here.
function planStaleDispatchReconcile({
  producerNodes,
  nodeIdToProducerKey,
  terminalRunSet,
  nowMs,
  graceMs,
}) {
  const map = nodeIdToProducerKey instanceof Map ? nodeIdToProducerKey : new Map();
  const runs = terminalRunSet instanceof Set ? terminalRunSet : new Set(terminalRunSet || []);
  const now = Number.isFinite(nowMs) ? nowMs : Date.now();
  const grace = Number.isFinite(graceMs) && graceMs >= 0 ? graceMs : STALE_DISPATCH_GRACE_MS;
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
    // Non-progress evidence: the wall-clock age of the node's last transition.
    // Within the grace window the producer is still legitimately mid-dispatch, no
    // matter how many floor passes ran; past it (or with no timestamp to read) it
    // has made no observable progress and strikes toward the auto-block threshold.
    const lastProgressMs = nodeProgressMs(node);
    const stale = lastProgressMs == null || (now - lastProgressMs) >= grace;
    if (stale) {
      strikes.push({ producer_key: producerKey, node_id: node.node_id });
    } else {
      ticks.push({ producer_key: producerKey, node_id: node.node_id });
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
function reconcileOrphanExecutedProducers(domain, { nodes, nodeIdToProducerKey, terminalRunSet, ledgerCache } = {}) {
  let producerNodes = nodes;
  let map = nodeIdToProducerKey;
  if (!Array.isArray(producerNodes) || !(map instanceof Map)) {
    ({ producerNodes, nodeIdToProducerKey: map } = buildLiveProducerReconcileInputs(domain));
  }

  // Reuse a threaded ledger cache when the handler already built one this pass; the
  // orphan and stale reconcilers key on disjoint node states, so one shared cache
  // is faithful for both. Direct callers (tests) omit it and it is built live. The
  // cache's terminal-key set doubles as the terminalRunSet when none was threaded.
  const cache = isProducerRunLedgerCache(ledgerCache) ? ledgerCache : buildProducerRunLedgerCache(domain);
  const runSet = terminalRunSet instanceof Set ? terminalRunSet : cache.terminalKeys;
  const orphanCountsByKey = countReconcileRowsByKey(domain, [ORPHAN_TICK_REASON, ORPHAN_STRIKE_REASON]);

  const plan = planOrphanReconcile({
    producerNodes,
    nodeIdToProducerKey: map,
    terminalRunSet: runSet,
    orphanCountsByKey,
    passThreshold: ORPHAN_EXECUTED_RECONCILE_PASS_THRESHOLD,
  });

  const ticked = [];
  const struck = [];
  const autoBlocked = [];
  for (const tick of plan.ticks) {
    // The orphan tick is count-gated (planOrphanReconcile emits at most K-1 ticks
    // per key before switching to strikes), so this transient row stays bounded; it
    // never touches the strike tally, so it needs no ledger cache.
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
    }, cache);
    struck.push(strike.producer_key);
    if (result && result.auto_blocked) autoBlocked.push(strike.producer_key);
  }
  return { ticked, struck, auto_blocked: autoBlocked };
}

// Impure executor: reconcile every stale-dispatch producer node (stuck
// 'proposed'/'dispatched' with no terminal producer_run row) against the
// producer_run ledger. Classifies tick vs strike on the WALL-CLOCK age of the
// node's last transition (nowMs - node.ts_last vs STALE_DISPATCH_GRACE_MS) instead
// of a floor-pass count — a healthy in-flight producer whose worker is progressing
// is never struck by repeated floor calls.
//
// A within-grace producer is still legitimately in-flight; its PENDING state is
// already carried by its live graph transition, so a grace observation is REPORTED
// in `ticked` but persists NO producer_run row. Persisting one transient tick per
// floor pass across the 15-minute grace window is precisely what grew the
// append-only ledger one-row-per-pass toward the refuse ceiling; the wall-clock
// strike path never counts ticks, so no ledger row is needed to observe 'still
// pending'. Only a node aged past the grace window (or with no timestamp) writes a
// row — a STRUCTURAL strike feeding the SAME strike tally — so a producer with no
// forward progress auto-blocks at STUCK_PRODUCER_DISPATCH_THRESHOLD (a bounded ≤
// threshold rows) and the floor stops re-proposing it; the drain precondition then
// converges. A threaded ledgerCache carries the strike tally + terminal set in
// memory so the strike loop never re-scans the whole event log per write.
// nowMs/graceMs are injectable for deterministic tests; live calls read Date.now()
// and the constant.
function reconcileStaleDispatchProducers(
  domain,
  { nodes, nodeIdToProducerKey, terminalRunSet, ledgerCache, nowMs, graceMs } = {},
) {
  let producerNodes = nodes;
  let map = nodeIdToProducerKey;
  if (!Array.isArray(producerNodes) || !(map instanceof Map)) {
    ({ producerNodes, nodeIdToProducerKey: map } = buildLiveProducerReconcileInputs(domain));
  }

  const cache = isProducerRunLedgerCache(ledgerCache) ? ledgerCache : buildProducerRunLedgerCache(domain);
  const runSet = terminalRunSet instanceof Set ? terminalRunSet : cache.terminalKeys;

  const plan = planStaleDispatchReconcile({
    producerNodes,
    nodeIdToProducerKey: map,
    terminalRunSet: runSet,
    nowMs,
    graceMs,
  });

  // Within-grace producers are REPORTED (their pending state rides the live graph
  // node), never persisted — no transient tick row is written.
  const ticked = plan.ticks.map((tick) => tick.producer_key);
  const struck = [];
  const autoBlocked = [];
  for (const strike of plan.strikes) {
    const result = recordProducerRun(domain, {
      producer_key: strike.producer_key,
      status: "failed_retryable",
      failure_class: "structural",
      reason: STALE_DISPATCH_STRIKE_REASON,
    }, cache);
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

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function readJsonlObjectsFailSoft(filePath) {
  if (!fs.existsSync(filePath)) return [];
  let content;
  try {
    content = readFileUtf8(filePath, { label: filePath });
  } catch {
    return [];
  }
  if (!content.trim()) return [];
  const rows = [];
  for (const line of content.split("\n")) {
    if (!line.trim()) continue;
    try {
      const parsed = JSON.parse(line);
      if (isPlainObject(parsed)) rows.push(parsed);
    } catch {
      continue;
    }
  }
  return rows;
}

function stringifyBodyValue(value) {
  if (typeof value === "string") return value;
  if (Buffer.isBuffer(value)) return value.toString("utf8");
  if (isPlainObject(value) || Array.isArray(value)) {
    try {
      return JSON.stringify(value);
    } catch {
      return "";
    }
  }
  return "";
}

function bodyTextFromRecord(record) {
  if (!isPlainObject(record)) return "";
  const directFields = [
    "body",
    "response_body",
    "responseBody",
    "text",
    "html",
    "content",
    "_content",
  ];
  for (const field of directFields) {
    const text = stringifyBodyValue(record[field]);
    if (text.trim()) return text;
  }
  if (isPlainObject(record.response)) {
    const responseFields = ["body", "response_body", "text", "html", "_content"];
    for (const field of responseFields) {
      const text = stringifyBodyValue(record.response[field]);
      if (text.trim()) return text;
    }
    if (isPlainObject(record.response.content)) {
      const text = stringifyBodyValue(record.response.content.text || record.response.content.body);
      if (text.trim()) return text;
    }
  }
  return "";
}

function readHttpBodyCorpus(domain) {
  const rows = [];
  for (const source of [
    { artifact: "http-audit.jsonl", filePath: httpAuditJsonlPath(domain) },
    { artifact: "traffic.jsonl", filePath: trafficJsonlPath(domain) },
  ]) {
    const records = readJsonlObjectsFailSoft(source.filePath);
    for (let i = 0; i < records.length; i += 1) {
      const body = bodyTextFromRecord(records[i]);
      if (!body.trim()) continue;
      rows.push({
        artifact: source.artifact,
        line: i + 1,
        record: records[i],
        body,
      });
    }
  }
  return rows;
}

function hasMaterializedHttpBodyCorpus(domain) {
  return readHttpBodyCorpus(domain).length > 0;
}

function scanStringFields(value, out = []) {
  if (typeof value === "string") {
    out.push(value);
    return out;
  }
  if (Array.isArray(value)) {
    for (const item of value) scanStringFields(item, out);
    return out;
  }
  if (isPlainObject(value)) {
    for (const item of Object.values(value)) scanStringFields(item, out);
  }
  return out;
}

function parseBodyJson(body) {
  try {
    const parsed = JSON.parse(body);
    return isPlainObject(parsed) || Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function chainIdFromHintText(text) {
  const normalized = typeof text === "string" ? text.trim().toLowerCase() : "";
  if (!normalized) return null;
  const eip155 = normalized.match(/\beip155[:_-](\d{1,10})\b/);
  if (eip155) return eip155[1];
  const chainId = normalized.match(/\bchain[_-]?id["'\s:=]+(\d{1,10})\b/);
  if (chainId) return chainId[1];
  // Fail closed on ambiguous common words in UNTRUSTED response bodies: require a
  // chain-SPECIFIC disambiguator, never a bare 'base' ("base fee"/"base url") or bare
  // 'mainnet' (matches "avalanche mainnet" etc.). Mirrors lead-intake resolveChainContext.
  if (/\bbase[-_\s]?(?:mainnet|sepolia|goerli)\b/.test(normalized)) return "8453";
  // Bare \bethereum\b matches "Ethereum-compatible"/"EVM"/"Ethereum-based" for essentially
  // every EVM L2 — require a mainnet-SPECIFIC disambiguator so a non-mainnet L2 contract is
  // never silently stamped chain 1 (Y-D22 fail-closed).
  if (/\bethereum[-_\s]?mainnet\b|\beip155[:_-]?1\b/.test(normalized)) return "1";
  if (/\barbitrum[-_\s]?one\b|\barbitrum[-_\s]?mainnet\b/.test(normalized)) return "42161";
  if (/\boptimism[-_\s]?mainnet\b|\bop[-_\s]?mainnet\b/.test(normalized)) return "10";
  if (/\bpolygon[-_\s]?mainnet\b/.test(normalized)) return "137";
  return null;
}

function collectChainHintTexts(record, parsedBody, body) {
  const texts = [];
  scanStringFields(record, texts);
  if (parsedBody) scanStringFields(parsedBody, texts);
  const compact = typeof body === "string" ? body.slice(0, 200000) : "";
  if (compact) texts.push(compact);
  return texts;
}

function resolveChainFamilyForHit(hit) {
  // depends: S4-resolver
  if (!hit || typeof hit.address !== "string") return null;
  const address = hit.address.trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) return null;
  const chainId = hit.chain_id == null ? "" : String(hit.chain_id).trim();
  if (!chainId) return null;
  return { chain_family: "evm", chain_id: chainId, address };
}

function extractOnchainReferenceHits(row) {
  const parsedBody = parseBodyJson(row.body);
  const hintTexts = collectChainHintTexts(row.record, parsedBody, row.body);
  let chainId = null;
  for (const text of hintTexts) {
    chainId = chainIdFromHintText(text);
    if (chainId) break;
  }

  const addressSet = new Set();
  // Boundary-anchored so a 64-hex tx/keccak/slot value (0x + 64 hex) is NOT truncated to
  // its first 40 hex and mis-read as a contract address (which would mint a bogus surface).
  const addressRe = /(?<![0-9a-fA-F])0x[0-9a-fA-F]{40}(?![0-9a-fA-F])/g;
  const bodyMatches = row.body.match(addressRe) || [];
  for (const address of bodyMatches) addressSet.add(address);
  if (parsedBody) {
    const jsonText = JSON.stringify(parsedBody);
    for (const address of jsonText.match(addressRe) || []) addressSet.add(address);
  }

  return Array.from(addressSet).map((address) => ({
    address,
    chain_id: chainId,
    artifact: row.artifact,
    line: row.line,
  }));
}

function blockedPrereqId(hit) {
  return "web-onchain-ref-" + crypto.createHash("sha256")
    .update(JSON.stringify([hit.artifact, hit.line, hit.address]))
    .digest("hex")
    .slice(0, 16);
}

function recordUnresolvedOnchainReference(domain, hit) {
  appendFrontierEvent({
    target_domain: domain,
    kind: "frontier.enqueued",
    payload: {
      lead_id: blockedPrereqId(hit),
      surface_ref: null,
      score: 0,
      priority: "medium",
      confidence: "low",
      blocked_prereqs: [{
        kind: "chain_family_unresolved",
        identifier_hint: hit.address,
        reason: "on-chain address reference was found in a captured response body without resolvable chain context",
        next_step: "Record the chain context for this response or add a resolver hint that maps the address to a chain_family and chain_id.",
      }],
      provenance: {
        source: WEB_ONCHAIN_REF_PRODUCER_ID,
        artifact: hit.artifact,
        line: hit.line,
      },
    },
    source: { artifact: hit.artifact, tool: WEB_ONCHAIN_REF_PRODUCER_ID },
    actor: "orchestrator",
  });
}

function recordInlineProducerProduced(domain, producerKey, inputItemCount) {
  appendFrontierEvent({
    target_domain: domain,
    kind: "observation.recorded",
    payload: {
      observation_kind: "producer_run",
      producer_key: producerKey,
      status: "produced",
      reason: "input_consumed",
      input_consumed: { input_item_count: inputItemCount },
    },
    source: { tool: "bob_materialize_producer_floor" },
    actor: "orchestrator",
  });
}

function executeWebHttpBodiesProducer(domain, { runSet = null } = {}) {
  const runs = runSet instanceof Set ? runSet : producerRunSet(domain);
  if (runs.has(WEB_HTTP_BODIES_PRODUCER_ID)) return { executed: false, input_item_count: 0 };
  const rows = readHttpBodyCorpus(domain);
  if (rows.length === 0) return { executed: false, input_item_count: 0 };
  recordInlineProducerProduced(domain, WEB_HTTP_BODIES_PRODUCER_ID, rows.length);
  return { executed: true, input_item_count: rows.length };
}

function recordOverCapOnchainReference(domain, tuple) {
  appendFrontierEvent({
    target_domain: domain,
    kind: "frontier.enqueued",
    payload: {
      lead_id: blockedPrereqId({ address: tuple && tuple.address ? tuple.address : contractIdentityKey(tuple) }),
      surface_ref: null,
      score: 0,
      priority: "low",
      confidence: "low",
      blocked_prereqs: [{
        kind: "onchain_ref_over_cap",
        identifier_hint: tuple && tuple.address ? tuple.address : contractIdentityKey(tuple),
        reason: "on-chain address reference from a captured response body exceeded the per-pass seed cap and was not auto-bound",
        next_step: "Confirm this address is in program scope and record it as an authorized contract target before it is analyzed.",
      }],
      provenance: { source: WEB_ONCHAIN_REF_PRODUCER_ID, artifact: "http_body_corpus", line: null },
    },
    source: { artifact: "http_body_corpus", tool: WEB_ONCHAIN_REF_PRODUCER_ID },
    actor: "orchestrator",
  });
}

function executeWebOnchainRefProducer(domain, state, { runSet = null } = {}) {
  const runs = runSet instanceof Set ? runSet : producerRunSet(domain);
  if (runs.has(WEB_ONCHAIN_REF_PRODUCER_ID)) {
    return { executed: false, input_item_count: 0, resolved: 0, unresolved: 0 };
  }
  const rows = readHttpBodyCorpus(domain);
  if (rows.length === 0) return { executed: false, input_item_count: 0, resolved: 0, unresolved: 0 };

  const tuples = [];
  const tupleKeys = new Set();
  let unresolved = 0;
  for (const row of rows) {
    for (const hit of extractOnchainReferenceHits(row)) {
      const resolved = resolveChainFamilyForHit(hit);
      if (!resolved) {
        unresolved += 1;
        recordUnresolvedOnchainReference(domain, hit);
        continue;
      }
      const key = contractIdentityKey(resolved);
      if (tupleKeys.has(key)) continue;
      tupleKeys.add(key);
      tuples.push(resolved);
    }
  }

  // PRD-4: the materialized HTTP body corpus is consumed by this producer-run
  // ledger row; any resolved contract is seeded only through the shared
  // bindAndSeedContracts funnel, and unresolved chain context is recorded as a
  // blocked prerequisite instead of defaulted.
  // OD1-parity cap: an attacker-influenceable response body can carry an unbounded number of
  // 0x-addresses; cap the tuples SEEDED so untrusted body content cannot mint an unbounded
  // set of smart_contract obligations (a DoS on frontier convergence). This producer is
  // one-shot (the runs.has short-circuit above), so the per-pass cap is also the lifetime
  // bound. Over-cap refs are REPORTED as blocked prerequisites, never silently dropped.
  const policy = loadQueuePolicy(domain);
  const perPassCap = clampCap(policy && policy.seed_producer_per_pass_cap, {
    lo: 1, hi: CLAMP_CEILING, fallback: DEFAULT_SEED_PRODUCER_PER_PASS_CAP,
  });
  const seededTuples = tuples.slice(0, perPassCap);
  const overCapTuples = tuples.slice(perPassCap);
  if (seededTuples.length > 0) {
    require("../contract-target.js").bindAndSeedContracts(state, seededTuples);
  }
  for (const tuple of overCapTuples) recordOverCapOnchainReference(domain, tuple);
  recordInlineProducerProduced(domain, WEB_ONCHAIN_REF_PRODUCER_ID, rows.length);
  return {
    executed: true,
    input_item_count: rows.length,
    resolved: seededTuples.length,
    unresolved,
    over_cap: overCapTuples.length,
  };
}

function executeInlineProducerWorkers(domain, plan, state, runSet) {
  const readyIds = new Set((Array.isArray(plan && plan.ready) ? plan.ready : [])
    .map((pack) => pack && pack.producer_id)
    .filter(Boolean));
  const executed = [];
  if (readyIds.has(WEB_HTTP_BODIES_PRODUCER_ID)) {
    const result = executeWebHttpBodiesProducer(domain, { runSet });
    if (result.executed) executed.push({ producer_id: WEB_HTTP_BODIES_PRODUCER_ID, ...result });
  }
  if (readyIds.has(WEB_ONCHAIN_REF_PRODUCER_ID)) {
    const stateForContracts = { ...(state || {}), target_domain: domain, target: domain };
    const result = executeWebOnchainRefProducer(domain, stateForContracts, { runSet });
    if (result.executed) executed.push({ producer_id: WEB_ONCHAIN_REF_PRODUCER_ID, ...result });
  }
  return executed;
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
  const hasWebTarget = typeof state.target_url === "string" && state.target_url;
  if (hasWebTarget) {
    availableArtifactKinds.add("target");
  }
  if (Array.isArray(state.target_contracts) && state.target_contracts.length > 0) {
    availableArtifactKinds.add("chain_address_set");
  }
  if (hasWebTarget && hasMaterializedHttpBodyCorpus(domain)) {
    availableArtifactKinds.add("http_bodies");
  }
  for (const producerKey of runSet) {
    const pack = PRODUCER_PACKS[producerKey];
    if (pack && Array.isArray(pack.produces)) {
      if (producerKey === WEB_ONCHAIN_REF_PRODUCER_ID && scSurfaces.length === 0) continue;
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
  return { plan, policy, caps, runSet, scSurfaces, availableArtifactKinds, state };
}

function isLedgerPressureRefusal(err) {
  return !!(err && err.code === "ledger_pressure_refusal");
}

// Fail-SOFT ledger-pressure envelope. materializeTaskGraph refuses (throws) once
// the frontier log crosses LEDGER_PRESSURE_REFUSE_THRESHOLD; rather than let that
// throw disable the whole floor, the handler returns this structured result so the
// caller can see the refusal, rotate/split the session, and keep every other
// surface running. The idempotent emission below is what keeps the ledger from
// growing into this wall in the first place.
function ledgerPressureResult(domain, err) {
  const details = (err && err.details && typeof err.details === "object") ? err.details : {};
  const num = (value) => (Number.isFinite(value) ? value : null);
  return JSON.stringify({
    version: 1,
    target_domain: domain,
    ledger_pressure_refusal: true,
    tier1_producers_emitted: 0,
    producer_floor_at_fixpoint: false,
    producer_gaps: [],
    uncovered_input_types: [],
    sc_recursion_gaps: [],
    orphan_executed_reconciled: { ticked: [], struck: [], auto_blocked: [] },
    stale_dispatch_reconciled: { ticked: [], struck: [], auto_blocked: [] },
    ledger_pressure: {
      code: "ledger_pressure_refusal",
      message: err && err.message ? String(err.message) : "ledger_pressure_refusal",
      event_count: num(details.event_count),
      refuse_threshold: num(details.refuse_threshold),
      warn_threshold: num(details.warn_threshold),
    },
  });
}

function handler(args) {
  const domain = assertNonEmptyString((args || {}).target_domain, "target_domain");
  // Serialize the whole read -> plan -> append -> reconcile sequence under the
  // session lock. Without it two concurrent floor invocations read the SAME graph,
  // identify the same un-proposed producers, and append DUPLICATE producer_proposed
  // events; or one reads stale state just before a node finalizes and strikes a
  // healthy active producer. The lock is reentrant, so the nested buildProducerFloorPlan
  // reads plus the appendFrontierEvent / materializeTaskGraph / recordProducerRun locks
  // compose without deadlock. Mirrors the seed-producer scheduler, which wraps its
  // select -> reserve -> dispatch sequence identically.
  return withSessionLock(domain, () => {
  // Single-sourced with the seed_producers_drained precondition: buildProducerFloorPlan
  // loads the queue policy, derives the OD1/OD4 caps, reads the live SC surface
  // inventory + the terminal producer_run set, assembles availableArtifactKinds, and
  // runs the pure planProducerFloor. The web/derived producer emission is unbounded
  // (every ready producer is enumerated — RANK != BOUND); the OD1/OD4 caps bound only
  // the emergent sc-expander recursion. The drain gate calls the SAME builder, so the
  // caps that govern the sc-expander recursion depth cannot drift between dispatch and
  // the freeze precondition.
  let built = buildProducerFloorPlan(domain);
  let { plan } = built;
  const inlineProducerRuns = executeInlineProducerWorkers(domain, plan, built.state, built.runSet);
  if (inlineProducerRuns.length > 0) {
    built = buildProducerFloorPlan(domain);
    plan = built.plan;
  }

  // Read the live producer graph ONCE up front (fail SOFT on ledger pressure). It
  // serves the idempotent-emission dedupe below AND, when nothing new is emitted,
  // is reused by the reconcilers instead of re-materializing — one graph fold, not
  // three.
  let liveInputs;
  try {
    liveInputs = buildLiveProducerReconcileInputs(domain);
  } catch (err) {
    if (isLedgerPressureRefusal(err)) return ledgerPressureResult(domain, err);
    throw err;
  }
  const existingProducerNodeIds = new Set();
  for (const node of liveInputs.producerNodes) {
    if (node && node.kind === PRODUCER_NODE_KIND && typeof node.node_id === "string") {
      existingProducerNodeIds.add(node.node_id);
    }
  }

  // Fold each ready producer into a producer node by emitting a producer_proposed
  // observation.recorded event; the materializer's producer_proposed branch turns
  // it into a kind-'producer' node via producerNodeId. No contract is attached —
  // contract wiring + dispatch is the seed-producer scheduler's job. IDEMPOTENT: a
  // producer whose node already exists is skipped — the materializer already
  // dedupes the NODE, but a re-append would grow the append-only event log by one
  // row per floor pass for every non-terminal-but-proposed producer. plan.ready
  // excludes only TERMINAL producers, so this dedupe (not the run ledger) is what
  // stops a proposed-but-unfinished producer from re-emitting every pass.
  let tier1ProducersEmitted = 0;
  let emittedAny = false;
  for (const pack of plan.ready) {
    if (existingProducerNodeIds.has(producerNodeId({ producerKey: pack.producer_id }))) continue;
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
    emittedAny = true;
    // The Tier-1 fixpoint count excludes advisory producers; every current pack
    // is advisory:false, so this equals the total emitted today.
    if (pack.advisory !== true) tier1ProducersEmitted += 1;
  }

  // Fold each bounded sc-expander instance into its own producer node. The
  // per-instance producer_key embeds the on-chain identity; the depth + chain
  // identity ride on the payload so finalize-node can recover them, mint the
  // identity-keyed child surface, and record the instance terminal (dedup). Same
  // idempotent skip: an instance whose node already exists is not re-appended.
  for (const instance of plan.sc_expander_instances) {
    if (existingProducerNodeIds.has(producerNodeId({ producerKey: instance.producer_key }))) continue;
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
    emittedAny = true;
  }

  // PRD-6: leaked-identifier composition floor. Turn cross-surface shared
  // identifiers into deduped identity_propagation transition proposals; the
  // existing transition-cell floor (enumerateTransitionCellFloor + emitOrAutoBlock)
  // fans and converges them. Strictly monotone: each edge proposed at most once
  // (dedup on transitionSurfaceId), so the reachable edge set stays finite and a
  // repeat pass with no new leaked-identifier facts proposes zero new edges,
  // preserving the transition-floor convergence proof's finiteness precondition.
  const {
    appendTransitionProposal,
    readTransitionProposals,
    TRANSITION_KIND_VALUES,
  } = require("../task-graph-events.js");
  const transitionSurfaceId = loadTransitionSurfaceId();
  const leakedIdentifierFacts = readFrontierEvents(domain).filter((event) => (
    event
    && event.kind === "observation.recorded"
    && event.payload
    && event.payload.observation_kind === "leaked_identifier"
  ));
  const existingTransitionKeys = new Set(
    readTransitionProposals(domain).map((event) => transitionSurfaceId(event.payload, event.event_id)),
  );
  const surfaceIds = new Set(
    ((currentSurfaces(domain).surfaces || []))
      .map((surface) => surface && surface.id)
      .filter(Boolean),
  );
  const transitionKeyOf = ({ from, to }) => transitionSurfaceId({
    from_surface: from,
    to_surface: to,
    transition_kind: COMPOSITION_TRANSITION_KIND,
  }, null);
  const composition = planCompositionFloor({
    leakedIdentifierFacts,
    surfaceIds,
    existingTransitionKeys,
    transitionKeyOf,
    transitionKindValues: TRANSITION_KIND_VALUES,
  });
  for (const proposal of composition.propose) {
    appendTransitionProposal({
      target_domain: domain,
      from_surface: proposal.from_surface,
      to_surface: proposal.to_surface,
      kind: COMPOSITION_TRANSITION_KIND,
      trust_assumption: proposal.trust_assumption,
      evidence_refs: proposal.evidence_refs,
      actor: "orchestrator",
    });
    emittedAny = true;
  }

  // When nothing new was emitted the pre-emission graph read is still current and
  // the reconcilers reuse it. When something was emitted, materialize (fail SOFT on
  // ledger pressure) and re-read so the reconcilers see the freshly-proposed
  // producer nodes — a freshly-proposed node carries a just-now ts_last and sits
  // inside the stale-dispatch grace window, so it is never struck on sight.
  let reconcileInputs = liveInputs;
  if (emittedAny) {
    try {
      materializeTaskGraph(domain, { write: true });
      reconcileInputs = buildLiveProducerReconcileInputs(domain);
    } catch (err) {
      if (isLedgerPressureRefusal(err)) return ledgerPressureResult(domain, err);
      throw err;
    }
    try {
      scheduleMaterialization(domain);
    } catch {
      // Materialization debounce is best-effort; never regress the appends.
    }
  }

  // One producer_run ledger snapshot (strike tally + terminal-key set) + one graph
  // read threaded through BOTH reconcilers. They key on disjoint node states
  // (executed vs proposed/dispatched) and producerNodeId folds at most one node per
  // key, so the two never touch the same producer_key — the shared cache is faithful
  // for both, avoids a per-stage re-fold of the frontier log, and lets each strike's
  // auto-block decision read the tally from memory instead of re-scanning per write.
  const ledgerCache = buildProducerRunLedgerCache(domain);
  const reconcileOpts = {
    nodes: reconcileInputs.producerNodes,
    nodeIdToProducerKey: reconcileInputs.nodeIdToProducerKey,
    terminalRunSet: ledgerCache.terminalKeys,
    ledgerCache,
  };

  // Reconcile executed-orphan producer nodes. A node stuck 'executed' with no
  // terminal producer_run row lost its finalize across the turn barrier; the
  // reconciler grants a one-pass grace then converts it to a strike so it
  // auto-blocks at the threshold. Best-effort: never regress the floor emission.
  let orphanReconciled = { ticked: [], struck: [], auto_blocked: [] };
  try {
    orphanReconciled = reconcileOrphanExecutedProducers(domain, reconcileOpts);
  } catch {
    orphanReconciled = { ticked: [], struck: [], auto_blocked: [] };
  }

  // Reconcile stale-dispatch producer nodes. A node stuck 'proposed' (never
  // scheduled) or 'dispatched' (a worker that never returned executed) makes no
  // progress; the reconciler ticks it while it is within the wall-clock grace
  // window, then strikes it structurally once it ages past the window so it
  // auto-blocks and the floor stops re-proposing it. A healthy in-flight producer
  // whose ts_last is recent is never struck by repeated floor calls. Best-effort.
  let staleDispatchReconciled = { ticked: [], struck: [], auto_blocked: [] };
  try {
    staleDispatchReconciled = reconcileStaleDispatchProducers(domain, reconcileOpts);
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
    inline_producer_runs: inlineProducerRuns,
  });
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
  planCompositionFloor,
  buildProducerFloorPlan,
  isProducerFloorAtFixpoint,
  planOrphanReconcile,
  planStaleDispatchReconcile,
  reconcileOrphanExecutedProducers,
  reconcileStaleDispatchProducers,
  executeWebHttpBodiesProducer,
  executeWebOnchainRefProducer,
  hasMaterializedHttpBodyCorpus,
  readHttpBodyCorpus,
  readScExpanderSurfaces,
  ORPHAN_EXECUTED_RECONCILE_PASS_THRESHOLD,
  STALE_DISPATCH_GRACE_MS,
});
