"use strict";

// The SC producer plane: a smart_contract surface/lead routes by chain_family to
// the sc_address_expander producer (run by the sc-recon-expander agent), and a
// missing or unsupported chain_family fails CLOSED to a named producer gap —
// never a web fallback. The expander's sc_surface consume+produce is the single
// whitelisted identity self-edge, and the chain_address_set it consumes is
// produced by the chain-front-door root, so the coherence legs stay green.

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  PRODUCER_PACKS,
  classifyScProducer,
} = require("../mcp/lib/producer-packs.js");
const { CHAIN_FAMILY_VALUES } = require("../mcp/lib/constants.js");
const {
  checkLegB,
  checkLegC,
} = require("../scripts/check-producer-coherence.js");

test("every supported chain_family routes to sc_address_expander / sc-recon-expander", () => {
  for (const family of CHAIN_FAMILY_VALUES) {
    const result = classifyScProducer({ chain_family: family });
    assert.equal(
      result.producer_id,
      "sc_address_expander",
      `${family} must route to the sc_address_expander producer`,
    );
    assert.equal(
      result.producer_agent,
      "sc-recon-expander",
      `${family} must be run by the sc-recon-expander agent`,
    );
    assert.equal(
      result.producer_gap,
      undefined,
      `${family} is supported, so it yields no producer gap`,
    );
  }
});

test("case/whitespace-insensitive routing for a supported chain_family", () => {
  const result = classifyScProducer({ chain_family: "  EVM  " });
  assert.equal(result.producer_id, "sc_address_expander");
  assert.equal(result.producer_agent, "sc-recon-expander");
});

test("an unsupported or missing chain_family fails closed to a named gap, never a web producer", () => {
  const cases = [
    { chain_family: "bitcoin" },
    { chain_family: "unknown_chain" },
    { chain_family: null },
    { chain_family: "" },
    {},
    undefined,
  ];
  for (const input of cases) {
    const result = classifyScProducer(input);
    assert.equal(
      result.producer_gap.kind,
      "sc_chain_family_unsupported",
      `${JSON.stringify(input)} must yield the named sc_chain_family_unsupported gap`,
    );
    assert.equal(
      result.producer_id,
      undefined,
      `${JSON.stringify(input)} must not resolve to any producer`,
    );
    assert.notEqual(
      result.producer_id,
      "web_host_family",
      `${JSON.stringify(input)} must never fall back to a web producer`,
    );
  }
});

test("the only artifact kind a single producer both consumes and produces is sc_surface", () => {
  const selfEdgeKinds = new Set();
  for (const pack of Object.values(PRODUCER_PACKS)) {
    const consumes = new Set(pack.trigger.consumes || []);
    for (const produced of pack.produces || []) {
      if (consumes.has(produced)) selfEdgeKinds.add(produced);
    }
  }
  assert.deepEqual(
    [...selfEdgeKinds].sort(),
    ["sc_surface"],
    "sc_surface is the single whitelisted identity self-edge across PRODUCER_PACKS",
  );
});

test("the chain_address_set consume is non-orphan and the producer graph stays acyclic with the SC packs present", () => {
  // checkLegB returns the violations array directly; checkLegC returns
  // { violations, nodeCount }.
  assert.deepEqual(
    checkLegB(),
    [],
    "leg b: every consumed kind (incl. chain_address_set) is produced by some producer",
  );
  assert.deepEqual(
    checkLegC().violations,
    [],
    "leg c: the only cycle is the single whitelisted sc_surface identity self-edge",
  );
});
