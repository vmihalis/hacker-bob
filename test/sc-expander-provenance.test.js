"use strict";

// OD3 same-chain linked-contract provenance gate in the pure producer-floor
// planner. A child surface on a chain ALREADY BOUND by a seed (depth <= 1) at a
// DIFFERENT address than any seed/bound contract is a linked contract. Without a
// verified-source provenance marker it is NOT proposed as an expander instance —
// it is REPORTED by name in an sc_unprovenanced_link recursion gap (RANK !=
// BOUND). The SAME linked surface WITH a provenance marker is admitted as an
// expander instance. These assertions hang on planProducerFloor over an in-memory
// producer-run set (the same pure surface the recursion test drives), so no
// session I/O is needed; they fail if the OD3 provenance branch is removed — the
// unprovenanced child would then be proposed and the gap would vanish.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const producerFloorTool = require("../mcp/lib/tools/materialize-producer-floor.js");
const { planProducerFloor } = producerFloorTool;
const { PRODUCER_PACKS } = require("../mcp/lib/producer-packs.js");
const { appendFrontierEvent, readFrontierEvents } = require("../mcp/lib/frontier-events.js");
const { materializeFrontier } = require("../mcp/lib/frontier-materializer.js");
const initContractSessionTool = require("../mcp/lib/tools/init-contract-session.js");
const finalizeNodeTool = require("../mcp/lib/tools/finalize-node.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-sc-provenance-"));
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
// the OD4 recursion depth + (optionally) the OD3 provenance marker, riding the
// SAME payload shape + funnel as emitProducerObservedSurfaces (finalize-node.js).
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

// A depth-1 seed binds (chain_family:chain_id) AND its exact lowercased address.
// The linked child rides on the SAME bound chain at a DIFFERENT address and a
// deeper lineage depth (so it is not itself a seed-bound address and is therefore
// a same-chain link, not an exact bound contract).
const SEED = Object.freeze({ chain_family: "evm", chain_id: "1", address: "0xSEED", depth: 1 });

function instanceAddresses(plan) {
  return plan.sc_expander_instances.map((i) => i.address).sort();
}

function unprovenancedGaps(plan) {
  return plan.sc_recursion_gaps.filter((g) => g.kind === "sc_unprovenanced_link");
}

test("a same-chain linked child WITHOUT a provenance marker is reported as sc_unprovenanced_link, not proposed (OD3)", () => {
  const plan = planProducerFloor({
    packs: PRODUCER_PACKS,
    producerRunSet: new Set(),
    availableArtifactKinds: ["chain_address_set"],
    scSurfaces: [
      SEED,
      // bound chain evm:1, DIFFERENT address, deeper depth, NO provenance marker.
      { chain_family: "evm", chain_id: "1", address: "0xLINK", depth: 2 },
    ],
    caps: WIDE_CAPS,
  });

  // The seed itself is the bound contract (not a same-chain link) and is proposed;
  // the unprovenanced linked child is withheld.
  assert.ok(instanceAddresses(plan).includes("0xseed"),
    "the seed-bound contract is admitted as an expander instance");
  assert.equal(
    plan.sc_expander_instances.filter((i) => i.address === "0xlink").length,
    0,
    "the unprovenanced same-chain linked child is NOT proposed as an expander instance");

  const gaps = unprovenancedGaps(plan);
  assert.equal(gaps.length, 1,
    "the unprovenanced linked child is reported in exactly one sc_unprovenanced_link gap");
  assert.equal(gaps[0].address, "0xlink",
    "RANK != BOUND: the withheld linked contract is named, never silently dropped");
  assert.equal(gaps[0].chain_family, "evm");
  assert.equal(gaps[0].chain_id, "1");
  assert.equal(gaps[0].depth, 3, "proposed_depth = source depth + 1");
  assert.equal(gaps[0].producer_key, "sc_address_expander:evm:1:0xlink");
});

test("a cross-chain / unbound expander source reports a provenance-skip gap instead of silently skipping OD3", () => {
  const plan = planProducerFloor({
    packs: PRODUCER_PACKS,
    producerRunSet: new Set(),
    availableArtifactKinds: ["chain_address_set"],
    scSurfaces: [
      SEED,
      // A source on a DIFFERENT, unbound chain (evm:137) at a deeper lineage depth
      // with NO provenance marker. Its chain carries no seed, so OD3's same-chain
      // provenance gate never examines it — it is admitted regardless of provenance.
      { chain_family: "evm", chain_id: "137", address: "0xCROSS", depth: 2 },
    ],
    caps: WIDE_CAPS,
  });

  // Admission is UNCHANGED: the cross-chain source is still proposed as an
  // instance (M3 authorizeChainScope + OD1 remain the real bounds).
  assert.ok(instanceAddresses(plan).includes("0xcross"),
    "the cross-chain unbound source is still admitted — the admit/block decision is unchanged");
  // The seed itself is still admitted and is NOT a cross-chain skip (its chain is bound).
  assert.ok(instanceAddresses(plan).includes("0xseed"),
    "the seed-bound contract is still admitted and yields no cross-chain skip gap");

  // The previously-silent OD3 skip is now OBSERVABLE as a kinded gap.
  const skipGaps = plan.sc_recursion_gaps.filter((g) => g.kind === "sc_cross_chain_provenance_skipped");
  assert.equal(skipGaps.length, 1,
    "the skipped OD3 provenance check on the cross-chain source is reported, never silent");
  assert.equal(skipGaps[0].address, "0xcross",
    "report-gaps: the cross-chain source is named");
  assert.equal(skipGaps[0].chain_family, "evm");
  assert.equal(skipGaps[0].chain_id, "137");
  assert.equal(skipGaps[0].depth, 3, "proposed_depth = source depth + 1");
  assert.equal(skipGaps[0].producer_key, "sc_address_expander:evm:137:0xcross");
  // A same-chain unprovenanced link would be sc_unprovenanced_link and WITHHELD;
  // the cross-chain skip is a distinct kind and is NOT withheld.
  assert.equal(unprovenancedGaps(plan).length, 0,
    "the cross-chain skip is a report, not an sc_unprovenanced_link withholding");
});

test("a cross-chain source WITH a provenance marker is admitted and yields no provenance-skip gap", () => {
  const plan = planProducerFloor({
    packs: PRODUCER_PACKS,
    producerRunSet: new Set(),
    availableArtifactKinds: ["chain_address_set"],
    scSurfaces: [
      SEED,
      // Same cross-chain source, now carrying a provenance marker: nothing is
      // skipped, so no skip gap is reported.
      { chain_family: "evm", chain_id: "137", address: "0xCROSS", depth: 2, provenance: "verified_source" },
    ],
    caps: WIDE_CAPS,
  });
  assert.ok(instanceAddresses(plan).includes("0xcross"),
    "a provenanced cross-chain source is admitted");
  assert.equal(
    plan.sc_recursion_gaps.filter((g) => g.kind === "sc_cross_chain_provenance_skipped").length,
    0,
    "a provenanced cross-chain source has nothing skipped, so no skip gap is reported");
});

test("the SAME same-chain linked child WITH a provenance marker is admitted as an expander instance (OD3)", () => {
  const plan = planProducerFloor({
    packs: PRODUCER_PACKS,
    producerRunSet: new Set(),
    availableArtifactKinds: ["chain_address_set"],
    scSurfaces: [
      SEED,
      // identical linked child, now carrying a verified-source provenance marker.
      { chain_family: "evm", chain_id: "1", address: "0xLINK", depth: 2, provenance: "immutable" },
    ],
    caps: WIDE_CAPS,
  });

  assert.ok(instanceAddresses(plan).includes("0xlink"),
    "a provenanced same-chain linked child IS admitted as an expander instance");
  const instance = plan.sc_expander_instances.find((i) => i.address === "0xlink");
  assert.equal(instance.producer_key, "sc_address_expander:evm:1:0xlink",
    "the admitted instance's producer_key embeds the lowercased on-chain identity");
  assert.equal(instance.depth, 3, "proposed_depth = source depth + 1");
  assert.equal(unprovenancedGaps(plan).length, 0,
    "a provenanced linked child yields NO sc_unprovenanced_link gap");
});

// END-TO-END through the persisted path. The pure-planner tests above hand
// planProducerFloor a synthetic scSurfaces[] with provenance + depth already set.
// This one drives the REAL round-trip: two finalize-node-shaped depth-2 children
// (one WITH a provenance marker, one WITHOUT) -> materialize -> project ->
// readScExpanderSurfaces -> buildProducerFloorPlan. Pre-fix the materializer scalar
// allowlist and projectMaterializedSurface both STRIPPED provenance AND depth, so
// readScExpanderSurfaces read provenance="" and depth=1; at depth 1 the children
// were misclassified as SEEDS (depth <= 1) that bind their own addresses, so OD3
// never treated them as same-chain links and never fired on the persisted path.
test("provenance survives materialize+project and drives the OD3 gate", () => {
  withTempHome(() => {
    const rootAddress = "0xaaa1000000000000000000000000000000000000";
    const unprovenancedAddress = "0xbbb2000000000000000000000000000000000000";
    const provenancedAddress = "0xccc3000000000000000000000000000000000000";
    // Default linked_contract_depth (3): the depth-2 children are NOT depth-capped
    // (proposed_depth 3 <= 3), so OD3 is the only gate under test. The seeded root
    // is a depth-1 surface that binds evm:1.
    const init = JSON.parse(initContractSessionTool.handler({
      contracts: [{ chain_family: "evm", chain_id: "1", address: rootAddress }],
    }));
    const domain = init.target_domain;

    // Two depth-2 same-chain linked children at DIFFERENT addresses: one without a
    // provenance marker, one with.
    emitScSurface(domain, { address: unprovenancedAddress, depth: 2 });
    emitScSurface(domain, { address: provenancedAddress, depth: 2, provenance: "immutable" });

    materializeFrontier(domain, { write: true });

    // ROUND-TRIP: provenance survives on the provenanced child and is genuinely
    // absent on the other; BOTH keep the true depth 2 (so OD3 sees same-chain
    // LINKS, not depth-1 seeds).
    const scSurfaces = producerFloorTool.readScExpanderSurfaces(domain);
    const unprov = scSurfaces.find((s) => s.address === unprovenancedAddress.toLowerCase());
    const prov = scSurfaces.find((s) => s.address === provenancedAddress.toLowerCase());
    assert.ok(unprov && prov, "both materialized+projected depth-2 children are visible");
    assert.equal(unprov.depth, 2, "the unprovenanced child's depth threads through as 2, not the depth-1 default");
    assert.equal(prov.depth, 2, "the provenanced child's depth threads through as 2, not the depth-1 default");
    assert.equal(unprov.provenance, "", "the unprovenanced child carries no provenance marker");
    assert.equal(prov.provenance, "immutable", "the provenanced child's marker survives materialize+project");

    // GATE: OD3 same-chain linked-contract provenance, over the SAME persisted
    // scSurfaces. Unprovenanced -> withheld + reported; provenanced -> admitted.
    const { plan } = producerFloorTool.buildProducerFloorPlan(domain);
    const unprovKey = `sc_address_expander:evm:1:${unprovenancedAddress.toLowerCase()}`;
    const provKey = `sc_address_expander:evm:1:${provenancedAddress.toLowerCase()}`;

    assert.equal(
      plan.sc_expander_instances.filter((i) => i.producer_key === unprovKey).length,
      0,
      "the unprovenanced same-chain linked child is NOT proposed as an expander instance");
    const unprovGaps = plan.sc_recursion_gaps.filter(
      (g) => g.kind === "sc_unprovenanced_link" && g.address === unprovenancedAddress.toLowerCase());
    assert.equal(unprovGaps.length, 1,
      "the unprovenanced child is reported in exactly one sc_unprovenanced_link gap (OD3 fires on the persisted path)");
    assert.equal(unprovGaps[0].depth, 3, "proposed_depth = source depth + 1 = 3");
    assert.equal(unprovGaps[0].producer_key, unprovKey);

    assert.equal(
      plan.sc_expander_instances.filter((i) => i.producer_key === provKey).length,
      1,
      "the provenanced same-chain linked child IS admitted as an expander instance");
    assert.equal(
      plan.sc_recursion_gaps.filter(
        (g) => g.kind === "sc_unprovenanced_link" && g.address === provenancedAddress.toLowerCase()).length,
      0,
      "the provenanced child yields NO sc_unprovenanced_link gap");
  });
});

// THE FIX, at its source. The tests above hand the OD3 gate scSurfaces whose
// provenance is already set. These drive the REAL server stamp
// (finalize-node.js emitProducerObservedSurfaces): the expander attests a
// per-surface provenance kind, and the server stamps the verified-source marker
// ONLY for a PROVEN on-chain kind, leaving it ABSENT otherwise. The prior
// hard-stamped constant made EVERY producer-discovered surface look provenanced,
// which auto-admitted comment-only / attacker-directed same-chain pivots.
test("emitProducerObservedSurfaces stamps verified_source ONLY for a PROVEN attested provenance kind, never a constant", () => {
  withTempHome(() => {
    const init = JSON.parse(initContractSessionTool.handler({
      contracts: [{ chain_family: "evm", chain_id: "1", address: "0xaaa1000000000000000000000000000000000000" }],
    }));
    const domain = init.target_domain;
    const provenAddr = "0x1111000000000000000000000000000000000000";
    const commentAddr = "0x2222000000000000000000000000000000000000";
    const absentAddr = "0x3333000000000000000000000000000000000000";

    finalizeNodeTool.emitProducerObservedSurfaces({
      domain,
      pack: PRODUCER_PACKS.sc_address_expander,
      run: {
        surfaces_observed: [
          { surface_type: "smart_contract", chain_family: "evm", chain_id: "1", contract_address: provenAddr, provenance: "immutable" },
          { surface_type: "smart_contract", chain_family: "evm", chain_id: "1", contract_address: commentAddr, provenance: "comment_only" },
          { surface_type: "smart_contract", chain_family: "evm", chain_id: "1", contract_address: absentAddr },
        ],
      },
      producerId: "sc_address_expander:evm:1:0xparent",
      sourceDepth: 2,
    });

    const emitted = readFrontierEvents(domain).filter(
      (ev) => ev && ev.kind === "surface.observed"
        && ev.payload && ev.payload.surface_type === "smart_contract");
    const byAddr = (addr) => emitted.find((ev) => ev.payload.contract_address === addr.toLowerCase());
    const proven = byAddr(provenAddr);
    const comment = byAddr(commentAddr);
    const absent = byAddr(absentAddr);

    assert.ok(proven && comment && absent, "all three producer-discovered surfaces are emitted");
    assert.equal(proven.payload.provenance, "verified_source",
      "a PROVEN attested kind (immutable) is stamped verified_source");
    assert.equal(comment.payload.provenance, undefined,
      "a comment_only attestation is NOT stamped — payload.provenance is absent so OD3 withholds it");
    assert.equal(absent.payload.provenance, undefined,
      "a surface with no attested provenance is NOT stamped — no constant, so OD3 withholds it");
  });
});

test("through the real server stamp: a PROVEN-attested same-chain child expands (OD3) while a comment_only-attested one is WITHHELD as sc_unprovenanced_link", () => {
  withTempHome(() => {
    const rootAddress = "0xaaa1000000000000000000000000000000000000";
    const provenAddress = "0xccc3000000000000000000000000000000000000";
    const commentAddress = "0xbbb2000000000000000000000000000000000000";
    const init = JSON.parse(initContractSessionTool.handler({
      contracts: [{ chain_family: "evm", chain_id: "1", address: rootAddress }],
    }));
    const domain = init.target_domain;

    // Two same-chain (evm:1) depth-2 children at DIFFERENT addresses than the seed,
    // emitted through the REAL server stamp: one attested with a PROVEN on-chain kind
    // (diamond_facet), one attested comment_only.
    finalizeNodeTool.emitProducerObservedSurfaces({
      domain,
      pack: PRODUCER_PACKS.sc_address_expander,
      run: {
        surfaces_observed: [
          { surface_type: "smart_contract", chain_family: "evm", chain_id: "1", contract_address: provenAddress, provenance: "diamond_facet" },
          { surface_type: "smart_contract", chain_family: "evm", chain_id: "1", contract_address: commentAddress, provenance: "comment_only" },
        ],
      },
      producerId: "sc_address_expander:evm:1:root",
      sourceDepth: 2,
    });

    materializeFrontier(domain, { write: true });

    const { plan } = producerFloorTool.buildProducerFloorPlan(domain);
    const provKey = `sc_address_expander:evm:1:${provenAddress.toLowerCase()}`;
    const commentKey = `sc_address_expander:evm:1:${commentAddress.toLowerCase()}`;

    assert.equal(
      plan.sc_expander_instances.filter((i) => i.producer_key === provKey).length,
      1,
      "the PROVEN-attested (diamond_facet) same-chain child is admitted as an expander instance (OD3 passes)");
    assert.equal(
      plan.sc_recursion_gaps.filter((g) => g.kind === "sc_unprovenanced_link" && g.producer_key === provKey).length,
      0,
      "the proven child yields NO sc_unprovenanced_link gap");

    assert.equal(
      plan.sc_expander_instances.filter((i) => i.producer_key === commentKey).length,
      0,
      "the comment_only-attested same-chain child is NOT proposed — the server left its provenance absent");
    const commentGaps = plan.sc_recursion_gaps.filter(
      (g) => g.kind === "sc_unprovenanced_link" && g.producer_key === commentKey);
    assert.equal(commentGaps.length, 1,
      "the comment_only child is WITHHELD and reported as sc_unprovenanced_link (the fix: no hard-stamped constant)");
    assert.equal(commentGaps[0].address, commentAddress.toLowerCase(),
      "RANK != BOUND: the withheld comment-only contract is named");
  });
});
