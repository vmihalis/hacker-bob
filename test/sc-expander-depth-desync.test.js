"use strict";

// CASE3 depth-desync characterization. frontier-materializer folds a re-observed
// surface's depth DOWN to the shortest path (Math.min), but the per-instance
// sc_address_expander is keyed by a DEPTH-INDEPENDENT producer_key
// (`sc_address_expander:<family>:<chain_id>:<address>`) that is the run-ledger
// terminal-dedup key. So a contract fully expanded DEEP (its producer_key terminal
// 'produced'), then re-reached SHALLOW, folds its surface depth down (correct) yet
// does NOT re-expand — its now-in-budget deeper links stay undiscovered. These
// assertions PIN that current bounded behavior (graceful under-exploration) and its
// bound (depth-1-safe provenance withholds same-chain links regardless, so the
// desync can never affect same-chain lineage). The structural fix — depth-keying the
// expander producer_key — lives in the sibling-owned planScExpanderRecursion, not at
// the fold; documenting it here keeps the boundary honest without perturbing the
// producer-floor termination fixpoint.

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
const { recordProducerRun, producerRunSet } = require("../mcp/lib/producer-run-ledger.js");
const initContractSessionTool = require("../mcp/lib/tools/init-contract-session.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-sc-desync-"));
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

// finalize-node-shaped child emission (mirrors emitProducerObservedSurfaces): a
// smart_contract surface.observed carrying the OD4 recursion depth + the OD3
// provenance marker, keyed on the on-chain identity so the materializer folds it to
// ONE surface.
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

// CASE3 through the persisted path: a contract expanded DEEP (terminal in the run
// ledger) then folded SHALLOW does NOT re-expand — the depth-independent producer_key
// is already terminal, so the fold updates the surface but never re-fires the
// expander. Pins the graceful under-exploration.
test("CASE3: a folded-shallow contract already TERMINAL in the run ledger does NOT re-expand", () => {
  withTempHome(() => {
    const rootAddress = "0xaaa1000000000000000000000000000000000000";
    const cAddress = "0xccc1000000000000000000000000000000000000";
    // linked_contract_depth = 2: a depth-1 source proposes a depth-2 expander (in
    // budget); a depth-3 source proposes a depth-4 expander (over the cap).
    const init = JSON.parse(initContractSessionTool.handler({
      contracts: [{ chain_family: "evm", chain_id: "1", address: rootAddress }],
      linked_contract_depth: 2,
    }));
    const domain = init.target_domain;

    // C is recorded DEEP (3) first, then RE-REACHED SHALLOW (1) — the surface folds
    // to depth 1 (Math.min).
    emitScSurface(domain, { address: cAddress, depth: 3, provenance: "verified_source" });
    emitScSurface(domain, { address: cAddress, depth: 1, provenance: "verified_source" });
    materializeFrontier(domain, { write: true });

    const linked = producerFloorTool.readScExpanderSurfaces(domain)
      .find((s) => s.address === cAddress.toLowerCase());
    assert.ok(linked, "the materialized+projected linked surface is visible");
    assert.equal(linked.depth, 1,
      "the shorter path folds the recorded surface depth down from 3 to 1 (Math.min, correct)");

    // C's per-instance expander is TERMINAL 'produced' in the run ledger (it fully
    // expanded when first discovered deep). The producer_key carries NO depth.
    const cKey = `sc_address_expander:evm:1:${cAddress.toLowerCase()}`;
    recordProducerRun(domain, { producer_key: cKey, status: "produced" });
    assert.equal(producerRunSet(domain).has(cKey), true, "C is terminal in the run ledger");

    // Even though the folded depth (1) puts C's proposed_depth (2) back inside the
    // cap, the depth-independent terminal dedup skips it: C does NOT re-expand.
    const { plan } = producerFloorTool.buildProducerFloorPlan(domain);
    assert.equal(
      plan.sc_expander_instances.filter((i) => i.producer_key === cKey).length,
      0,
      "CASE3 desync: the already-terminal expander is not re-proposed despite the downward fold");
    // It is skipped by the run-ledger dedup (step 1 `continue`), NOT reported as a
    // depth-capped gap — the fold made it in-budget, the dedup is what withholds it.
    const cGaps = plan.sc_recursion_gaps.filter(
      (g) => g.address === cAddress.toLowerCase());
    assert.deepEqual(cGaps, [],
      "the terminal contract is silently deduped, not reported as a depth/provenance gap");
  });
});

// The terminal-dedup is the ONLY difference between CASE3 (no re-expand) and the
// already-correct CASE2 (a folded-shallow contract that was never expanded DOES
// re-expand). Same fold, same folded depth, same cap — only the run-ledger terminal
// state differs.
test("contrast: the SAME folded-shallow contract, NOT terminal, DOES re-expand (CASE2 is correct)", () => {
  withTempHome(() => {
    const rootAddress = "0xaaa2000000000000000000000000000000000000";
    const cAddress = "0xccc2000000000000000000000000000000000000";
    const init = JSON.parse(initContractSessionTool.handler({
      contracts: [{ chain_family: "evm", chain_id: "1", address: rootAddress }],
      linked_contract_depth: 2,
    }));
    const domain = init.target_domain;

    emitScSurface(domain, { address: cAddress, depth: 3, provenance: "verified_source" });
    emitScSurface(domain, { address: cAddress, depth: 1, provenance: "verified_source" });
    materializeFrontier(domain, { write: true });

    // No terminal producer_run row this time — the ONLY difference from CASE3.
    const cKey = `sc_address_expander:evm:1:${cAddress.toLowerCase()}`;
    assert.equal(producerRunSet(domain).has(cKey), false, "C is NOT terminal in the run ledger");

    const { plan } = producerFloorTool.buildProducerFloorPlan(domain);
    const proposed = plan.sc_expander_instances.filter((i) => i.producer_key === cKey);
    assert.equal(proposed.length, 1,
      "a non-terminal folded-shallow contract re-expands: exactly one instance is proposed");
    assert.equal(proposed[0].depth, 2, "proposed_depth = folded depth 1 + 1 = 2, within the cap");
  });
});

// The BOUND: depth-1-safe provenance withholds EVERY unprovenanced same-chain linked
// child (a bound chain, a different address) REGARDLESS of the expander's terminal
// state — so a re-firing expander could not expand a deep same-chain grandchild
// anyway. The CASE3 desync therefore can never worsen same-chain coverage; its only
// residual is cross-chain lineage. Pure planner, no session I/O.
test("bound: an unprovenanced same-chain deep link is withheld regardless (depth-1-safe provenance)", () => {
  // A depth-1 seed on evm:1 binds the chain and its exact address; a depth-2 child
  // at a DIFFERENT same-chain address without provenance is an sc_unprovenanced_link.
  const plan = planProducerFloor({
    packs: PRODUCER_PACKS,
    producerRunSet: new Set(),
    availableArtifactKinds: ["chain_address_set"],
    scSurfaces: [
      { chain_family: "evm", chain_id: "1", address: "0xSEED", depth: 1, provenance: "verified_source" },
      // No provenance on the deeper same-chain child.
      { chain_family: "evm", chain_id: "1", address: "0xCHILD", depth: 2 },
    ],
    caps: WIDE_CAPS,
  });
  const childKey = "sc_address_expander:evm:1:0xchild";
  assert.equal(
    plan.sc_expander_instances.filter((i) => i.producer_key === childKey).length,
    0,
    "the unprovenanced same-chain deep child is not proposed (OD3 withholds it)");
  const provGaps = plan.sc_recursion_gaps.filter(
    (g) => g.kind === "sc_unprovenanced_link" && g.address === "0xchild");
  assert.equal(provGaps.length, 1,
    "RANK != BOUND: the withheld same-chain child is reported by name, never silently dropped");
});
