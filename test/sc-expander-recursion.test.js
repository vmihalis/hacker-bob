"use strict";

// The emergent sc_address_expander recursion is BOUND+GATED by the pure producer
// floor planner. A chain_address_set seed makes the root expander ready; each
// minted smart_contract surface re-proposes a per-instance expander keyed by its
// on-chain identity at proposed_depth = source depth + 1. The bounds are the OD4
// linked-contract depth cap, the OD1 per-pass / per-expander caps, and dedup via
// the producer-run ledger. RANK != BOUND: every contract that is not proposed is
// REPORTED by name in a kinded gap — never a silent drop. These assertions hang
// on planProducerFloor + an in-memory producer-run set (the same pure surface the
// race-freedom test drives), so no session I/O is needed.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const producerFloorTool = require("../mcp/lib/tools/materialize-producer-floor.js");
const { planProducerFloor } = producerFloorTool;
const { PRODUCER_PACKS } = require("../mcp/lib/producer-packs.js");
const { appendFrontierEvent } = require("../mcp/lib/frontier-events.js");
const { materializeFrontier } = require("../mcp/lib/frontier-materializer.js");
const initContractSessionTool = require("../mcp/lib/tools/init-contract-session.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-sc-recursion-"));
  process.env.HOME = tempHome;
  try {
    return fn(tempHome);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
}

// finalize-node-shaped child emission: a smart_contract surface.observed carrying
// the OD4 recursion depth + the OD3 provenance marker, riding the SAME payload
// shape + funnel as emitProducerObservedSurfaces (finalize-node.js). Its
// surface_id is the on-chain identity key so the materializer folds it to ONE
// surface.
function emitScSurface(domain, { address, chainFamily = "evm", chainId = "1", depth, provenance }) {
  const surfaceId = `${chainFamily}:${chainId}:${address.toLowerCase()}`;
  const payload = {
    surface_type: "smart_contract",
    chain_family: chainFamily,
    chain_id: String(chainId),
    contract_address: address,
    surface_id: surfaceId,
  };
  if (depth != null) payload.depth = depth;
  if (provenance != null) payload.provenance = provenance;
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    surface_id: surfaceId,
    payload,
    source: { tool: "bob_finalize_node" },
  });
  return surfaceId;
}

const WIDE_CAPS = Object.freeze({
  linked_contract_depth: 3,
  seed_producer_per_pass_cap: 32,
  per_expander_linked_address_cap: 16,
  max_total_seed_producers: 1024,
});

function readyIds(plan) {
  return plan.ready.map((pack) => pack.producer_id).sort();
}

function instanceKeys(plan) {
  return plan.sc_expander_instances.map((i) => i.producer_key).sort();
}

function gapsOfKind(plan, kind) {
  return plan.sc_recursion_gaps.filter((g) => g.kind === kind);
}

test("a chain_address_set seed makes the sc_address_expander ready (the depth-1 root expansion)", () => {
  const plan = planProducerFloor({
    packs: PRODUCER_PACKS,
    producerRunSet: new Set(),
    availableArtifactKinds: ["chain_address_set"],
  });
  assert.ok(readyIds(plan).includes("sc_address_expander"),
    "the chain_address_set seed makes the root sc_address_expander ready");
  // No sc surface inventory was supplied, so the additive recursion fields are
  // empty and the legacy shapes are untouched (backward compatibility).
  assert.deepEqual(plan.sc_expander_instances, []);
  assert.deepEqual(plan.sc_recursion_gaps, []);
  assert.ok(Array.isArray(plan.gaps));
  assert.ok(Array.isArray(plan.uncovered_input_types));
});

test("a minted sc_surface at depth 1 re-proposes a per-instance expander on its identity at depth 2", () => {
  const plan = planProducerFloor({
    packs: PRODUCER_PACKS,
    producerRunSet: new Set(),
    availableArtifactKinds: ["chain_address_set"],
    scSurfaces: [{ chain_family: "evm", chain_id: "1", address: "0xAbC", depth: 1 }],
    caps: WIDE_CAPS,
  });
  assert.equal(plan.sc_expander_instances.length, 1,
    "the depth-1 surface mints exactly one per-instance expander");
  const instance = plan.sc_expander_instances[0];
  assert.equal(instance.producer_key, "sc_address_expander:evm:1:0xabc",
    "the per-instance producer_key embeds the lowercased on-chain identity");
  assert.equal(instance.depth, 2,
    "proposed_depth = source depth + 1");
  assert.deepEqual(plan.sc_recursion_gaps, [],
    "an in-bounds, seed-bound surface yields no recursion gap");
});

test("recursion stops past linked_contract_depth: an over-depth source is reported, not proposed", () => {
  const plan = planProducerFloor({
    packs: PRODUCER_PACKS,
    producerRunSet: new Set(),
    availableArtifactKinds: ["chain_address_set"],
    // depth 3 -> proposed_depth 4 > linked_contract_depth 3.
    scSurfaces: [{ chain_family: "evm", chain_id: "1", address: "0xDEEP", depth: 3 }],
    caps: WIDE_CAPS,
  });
  assert.deepEqual(plan.sc_expander_instances, [],
    "no expander is proposed past the depth governor");
  const depthGaps = gapsOfKind(plan, "linked_contract_depth_capped");
  assert.equal(depthGaps.length, 1,
    "the over-depth contract is reported in exactly one depth-capped gap");
  assert.equal(depthGaps[0].address, "0xdeep",
    "RANK != BOUND: the deferred contract is named, never silently dropped");
  assert.equal(depthGaps[0].depth, 4);
  assert.equal(depthGaps[0].producer_key, "sc_address_expander:evm:1:0xdeep");
});

test("dedup: a (family,chain_id,address) terminal in the run ledger or duplicated in-pass never re-proposes", () => {
  const plan = planProducerFloor({
    packs: PRODUCER_PACKS,
    producerRunSet: new Set(["sc_address_expander:evm:1:0xter"]),
    availableArtifactKinds: ["chain_address_set"],
    scSurfaces: [
      { chain_family: "evm", chain_id: "1", address: "0xTER", depth: 1 },
      { chain_family: "evm", chain_id: "1", address: "0xDUP", depth: 1 },
      { chain_family: "evm", chain_id: "1", address: "0xDUP", depth: 1 },
    ],
    caps: WIDE_CAPS,
  });
  assert.deepEqual(instanceKeys(plan), ["sc_address_expander:evm:1:0xdup"],
    "the terminal contract is skipped and the in-pass duplicate is folded to one proposal");
  assert.equal(
    plan.sc_expander_instances.filter((i) => i.address === "0xter").length,
    0,
    "a contract already terminal in the run ledger never re-expands");
});

test("over the per-pass cap, the deferred contracts are reported by name (RANK != BOUND)", () => {
  const plan = planProducerFloor({
    packs: PRODUCER_PACKS,
    producerRunSet: new Set(),
    availableArtifactKinds: ["chain_address_set"],
    scSurfaces: [
      { chain_family: "evm", chain_id: "1", address: "0xA", depth: 1 },
      { chain_family: "evm", chain_id: "1", address: "0xB", depth: 1 },
      { chain_family: "evm", chain_id: "1", address: "0xC", depth: 1 },
    ],
    caps: { ...WIDE_CAPS, seed_producer_per_pass_cap: 1 },
  });
  assert.equal(plan.sc_expander_instances.length, 1,
    "the per-pass cap admits exactly one expander this pass");
  const cappedGaps = gapsOfKind(plan, "sc_linked_address_capped");
  assert.equal(cappedGaps.length, 1,
    "the over-cap contracts are reported in one sc_linked_address_capped gap");
  const deferred = cappedGaps[0].deferred_contracts.map((d) => d.address).sort();
  assert.deepEqual(deferred, ["0xb", "0xc"],
    "RANK != BOUND: every over-cap contract is named, none silently absent");
  assert.equal(cappedGaps[0].cap, 1);
});

test("supplying no sc surfaces keeps the legacy ready/gaps shapes byte-stable", () => {
  // Mirrors the race-freedom web call shape: with only the root seed and no sc
  // inventory, the additive recursion fields stay empty and the web ready set is
  // exactly the root host-family producer.
  const plan = planProducerFloor({
    packs: PRODUCER_PACKS,
    producerRunSet: new Set(),
    availableArtifactKinds: ["target"],
  });
  assert.deepEqual(readyIds(plan), ["web_host_family"]);
  assert.deepEqual(plan.sc_expander_instances, []);
  assert.deepEqual(plan.sc_recursion_gaps, []);
});

test("a missing count cap defaults to the bounded queue-policy governor, never unbounded", () => {
  // buildProducerFloorPlan always supplies normalized integer caps, so this
  // caps-missing path is unreachable in prod; the assertion is that its FALLBACK
  // is a bounded governor (the DEFAULT_QUEUE_POLICY per-expander cap of 16), not
  // Infinity. Twenty depth-1 seeds on one chain, with the count caps omitted.
  const scSurfaces = [];
  for (let i = 0; i < 20; i += 1) {
    scSurfaces.push({
      chain_family: "evm",
      chain_id: "1",
      address: `0x${String(i).padStart(40, "0")}`,
      depth: 1,
    });
  }
  const plan = planProducerFloor({
    packs: PRODUCER_PACKS,
    producerRunSet: new Set(),
    availableArtifactKinds: ["chain_address_set"],
    scSurfaces,
    caps: {}, // no caps supplied -> the bounded defaults apply, not Infinity
  });
  assert.equal(plan.sc_expander_instances.length, 16,
    "the missing per-expander cap defaults to the bounded 16, not an unbounded admit");
  const cappedGaps = gapsOfKind(plan, "sc_linked_address_capped");
  assert.equal(cappedGaps.length, 1,
    "the four over-cap contracts are reported, never silently dropped (RANK != BOUND)");
  assert.equal(cappedGaps[0].deferred_contracts.length, 4);
  // Pre-fix the missing per-pass cap was Infinity and this reported cap was null;
  // the bounded default reports the finite governor value.
  assert.equal(cappedGaps[0].cap, 32,
    "the reported cap is the finite default per-pass governor, not null (was Infinity pre-fix)");
});

test("isProducerFloorAtFixpoint null-guards plan.ready (the guard the drain-gate reporting filter mirrors)", () => {
  // NIT 5 consistency: the seed_producers_drained reporting filter now uses the
  // SAME `(p) => p && p.advisory !== true` null-guard as this predicate. A null in
  // ready is filtered out, not dereferenced. (plan.ready never holds null in prod.)
  assert.doesNotThrow(() =>
    producerFloorTool.isProducerFloorAtFixpoint({ ready: [null], sc_expander_instances: [] }));
  assert.equal(
    producerFloorTool.isProducerFloorAtFixpoint({ ready: [null], sc_expander_instances: [] }),
    true,
    "a null ready entry is skipped, so a ready:[null] plan reads as drained");
  // The reporting filter expression itself tolerates the same null identically.
  const readyNonAdvisory = [null, { advisory: false }, { advisory: true }].filter((p) => p && p.advisory !== true);
  assert.equal(readyNonAdvisory.length, 1,
    "the null-guarded filter drops null and advisory entries, keeping one real producer");
});

// END-TO-END through the persisted path. The pure-planner tests above hand
// planProducerFloor a synthetic scSurfaces[] with depth already set. This one
// drives the REAL round-trip: a finalize-node-shaped surface.observed at depth 2
// -> materialize -> project -> readScExpanderSurfaces -> buildProducerFloorPlan.
// Pre-fix the materializer scalar allowlist and projectMaterializedSurface both
// STRIPPED depth, so readScExpanderSurfaces read the depth-1 default, proposed_depth
// stayed at 2, and OD4 depth-capping NEVER fired on the persisted path.
test("OD4 depth cap fires THROUGH materialization: a depth-2 surface at cap does NOT propose a depth-3 expander", () => {
  withTempHome(() => {
    const rootAddress = "0xaaa1000000000000000000000000000000000000";
    const childAddress = "0xbbb2000000000000000000000000000000000000";
    // Persist linked_contract_depth = 2 into the queue policy that
    // buildProducerFloorPlan reads. The seeded root is a depth-1 surface on evm:1.
    const init = JSON.parse(initContractSessionTool.handler({
      contracts: [{ chain_family: "evm", chain_id: "1", address: rootAddress }],
      linked_contract_depth: 2,
    }));
    const domain = init.target_domain;

    // A depth-2 linked child carrying a verified-source provenance marker, so ONLY
    // the OD4 depth cap (not OD3) can withhold it.
    emitScSurface(domain, { address: childAddress, depth: 2, provenance: "verified_source" });

    // Fold the ledger into surface-index.json (materialize + project).
    materializeFrontier(domain, { write: true });

    // ROUND-TRIP: readScExpanderSurfaces recovers the true depth (2, a NUMBER) and
    // provenance. Pre-fix both were stripped -> depth read back as the depth-1
    // default and provenance as "".
    const scSurfaces = producerFloorTool.readScExpanderSurfaces(domain);
    const child = scSurfaces.find((s) => s.address === childAddress.toLowerCase());
    assert.ok(child, "the materialized+projected depth-2 child is visible to readScExpanderSurfaces");
    assert.equal(child.depth, 2,
      "the OD4 depth threads through materialize+project as 2, not the depth-1 default");
    assert.equal(Number.isInteger(child.depth), true,
      "depth round-trips as a NUMBER, not a numeric string");
    assert.equal(child.provenance, "verified_source",
      "the OD3 provenance marker survives materialize+project");

    // GATE: buildProducerFloorPlan reads the SAME persisted linked_contract_depth=2
    // cap and the SAME scSurfaces the readScExpanderSurfaces above returned (no
    // desync). depth-2 -> proposed_depth 3 > 2 -> depth-capped: NOT proposed,
    // REPORTED by name (RANK != BOUND).
    const { plan } = producerFloorTool.buildProducerFloorPlan(domain);
    const childKey = `sc_address_expander:evm:1:${childAddress.toLowerCase()}`;
    assert.equal(
      plan.sc_expander_instances.filter((i) => i.producer_key === childKey).length,
      0,
      "the depth-2 child at cap does NOT propose a depth-3 expander instance");
    const depthGaps = plan.sc_recursion_gaps.filter(
      (g) => g.kind === "linked_contract_depth_capped" && g.address === childAddress.toLowerCase());
    assert.equal(depthGaps.length, 1,
      "the depth-capped child is reported in exactly one linked_contract_depth_capped gap");
    assert.equal(depthGaps[0].depth, 3, "proposed_depth = source depth + 1 = 3");
    assert.equal(depthGaps[0].producer_key, childKey);
  });
});

// A surface's materialized depth is MONOTONIC: server-stamped depth only grows
// (producing-run depth + 1), so a later, SHALLOWER surface.observed for the same
// on-chain identity must never lower the recorded depth. Without the guard the
// last write would win and a stale shallow re-observation could pull a depth-3
// contract back to depth 2, un-capping recursion the deeper stamp had settled.
test("a later shallower surface.observed does NOT lower a recorded depth (monotonic depth)", () => {
  withTempHome(() => {
    const rootAddress = "0xaaa4000000000000000000000000000000000000";
    const linkedAddress = "0xbbb5000000000000000000000000000000000000";
    const init = JSON.parse(initContractSessionTool.handler({
      contracts: [{ chain_family: "evm", chain_id: "1", address: rootAddress }],
    }));
    const domain = init.target_domain;

    // Same on-chain identity, observed DEEP (3) first, then SHALLOW (2).
    emitScSurface(domain, { address: linkedAddress, depth: 3, provenance: "verified_source" });
    emitScSurface(domain, { address: linkedAddress, depth: 2, provenance: "verified_source" });
    materializeFrontier(domain, { write: true });

    const scSurfaces = producerFloorTool.readScExpanderSurfaces(domain);
    const linked = scSurfaces.find((s) => s.address === linkedAddress.toLowerCase());
    assert.ok(linked, "the materialized+projected linked surface is visible");
    assert.equal(linked.depth, 3,
      "the deeper stamp wins: the later shallower write does not lower the recorded depth");
    assert.equal(Number.isInteger(linked.depth), true, "depth stays a NUMBER");
  });
});

// The normal monotone-INCREASING path is byte-identical to last-write-wins: an
// increasing re-stamp still lands the higher depth, so the guard only bites the
// shallow-regression case above.
test("a later deeper surface.observed still raises the recorded depth (monotone-up unchanged)", () => {
  withTempHome(() => {
    const rootAddress = "0xaaa6000000000000000000000000000000000000";
    const linkedAddress = "0xbbb7000000000000000000000000000000000000";
    const init = JSON.parse(initContractSessionTool.handler({
      contracts: [{ chain_family: "evm", chain_id: "1", address: rootAddress }],
    }));
    const domain = init.target_domain;

    emitScSurface(domain, { address: linkedAddress, depth: 2, provenance: "verified_source" });
    emitScSurface(domain, { address: linkedAddress, depth: 3, provenance: "verified_source" });
    materializeFrontier(domain, { write: true });

    const scSurfaces = producerFloorTool.readScExpanderSurfaces(domain);
    const linked = scSurfaces.find((s) => s.address === linkedAddress.toLowerCase());
    assert.ok(linked, "the materialized+projected linked surface is visible");
    assert.equal(linked.depth, 3, "the later deeper stamp raises the recorded depth to 3");
  });
});
