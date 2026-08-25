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
  ARTIFACT_KIND_VALUES,
  PRODUCER_PACKS,
  classifyScProducer,
} = require("../mcp/core/dispatch/producer-packs.js");
const { CHAIN_FAMILY_VALUES } = require("../mcp/core/constants/shared-vocabulary.js");
const { planProducerFloor } = require("../mcp/tools/materialize-producer-floor.js");
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

test("an svm (base58) address is NOT lowercased in the identity / producer_key, while evm hex IS case-folded", () => {
  // svm base58 is case-SENSITIVE — lowercasing corrupts the pubkey (a dedup
  // collision plus a wrong on-chain fetch). The per-instance identity tuple and
  // producer_key must carry the address verbatim for svm, and consistently with
  // readScExpanderSurfaces which never lowercases.
  const svmAddress = "So11111111111111111111111111111111111111112"; // mixed-case base58
  const svmPlan = planProducerFloor({
    packs: PRODUCER_PACKS,
    producerRunSet: new Set(["sc_chain_root"]),
    availableArtifactKinds: ["chain_address_set", "sc_surface"],
    scSurfaces: [{
      chain_family: "svm", chain_id: "mainnet-beta", address: svmAddress, depth: 1, provenance: "seed",
    }],
    caps: {},
  });
  assert.equal(svmPlan.sc_expander_instances.length, 1, "the svm seed contract mints one instance");
  const svmInstance = svmPlan.sc_expander_instances[0];
  assert.equal(svmInstance.address, svmAddress, "the svm base58 address rides verbatim, never lowercased");
  assert.notEqual(svmInstance.address, svmAddress.toLowerCase(),
    "a lowercased svm pubkey would be a different (wrong) address");
  assert.equal(svmInstance.producer_key, `sc_address_expander:svm:mainnet-beta:${svmAddress}`,
    "the per-instance producer_key embeds the case-preserved svm identity");

  // EVM hex is case-INSENSITIVE, so it IS folded to lowercase for stable dedup.
  const evmMixed = "0xABCdef0000000000000000000000000000000001";
  const evmPlan = planProducerFloor({
    packs: PRODUCER_PACKS,
    producerRunSet: new Set(["sc_chain_root"]),
    availableArtifactKinds: ["chain_address_set", "sc_surface"],
    scSurfaces: [{
      chain_family: "evm", chain_id: "1", address: evmMixed, depth: 1, provenance: "seed",
    }],
    caps: {},
  });
  assert.equal(evmPlan.sc_expander_instances[0].address, evmMixed.toLowerCase(),
    "evm hex is case-folded to lowercase (case-insensitive encoding)");
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

test("web_onchain_ref consumes the http_bodies artifact and emits smart_contract chain seeds", () => {
  assert.equal(ARTIFACT_KIND_VALUES.includes("http_bodies"), true,
    "http_bodies must be in the closed artifact vocabulary");

  const bodyRoot = PRODUCER_PACKS.web_http_bodies;
  assert.equal(bodyRoot.producer_id, "web_http_bodies");
  assert.equal(bodyRoot.producer_agent, "surface-discovery-agent");
  assert.deepEqual(bodyRoot.trigger, {
    kind: "root",
    target_class: "web",
    consumes: [],
  });
  assert.deepEqual(bodyRoot.produces, ["http_bodies"]);
  assert.deepEqual(bodyRoot.emits_surface_types, []);

  const refProducer = PRODUCER_PACKS.web_onchain_ref;
  assert.equal(refProducer.producer_id, "web_onchain_ref");
  assert.equal(refProducer.producer_agent, "surface-discovery-agent");
  assert.deepEqual(refProducer.trigger, {
    kind: "derived",
    target_class: "web",
    consumes: ["http_bodies"],
  });
  assert.deepEqual(refProducer.produces, ["chain_address_set"]);
  assert.deepEqual(refProducer.emits_surface_types, ["smart_contract"]);
  assert.equal(Object.prototype.hasOwnProperty.call(refProducer.trigger, "input_mode"), false,
    "web_onchain_ref uses the default all-of input mode");
});
