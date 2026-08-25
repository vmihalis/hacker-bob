"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { classifySurfaceCapability, deriveConfidenceAdjustment } = require("../mcp/core/capability/capability-packs.js");

const CONFIDENCE_LADDER = ["high", "medium", "low"];

test("EVM smart_contract surface routes to smart_contract_evm with chain_family", () => {
  const result = classifySurfaceCapability({
    id: "sc1",
    surface_type: "smart_contract",
    chain_family: "evm",
  });
  assert.equal(result.chain_family, "evm");
  assert.equal(result.routable, true);
  assert.equal(result.capability_pack, "smart_contract_evm");
  assert.equal(typeof result.confidence, "string");
  assert.ok(result.confidence.length > 0);
});

test("unknown chain_family smart_contract is unroutable and does not throw", () => {
  // Called directly (not via assert.throws) — the contract is that an
  // ambiguous SC returns a structured unroutable result instead of throwing.
  const result = classifySurfaceCapability({
    id: "sc2",
    surface_type: "smart_contract",
    chain_family: "cardano",
  });
  assert.equal(result.routable, false);
  assert.equal(result.capability_pack, null);
  assert.equal(typeof result.unroutable_reason, "string");
  assert.ok(result.unroutable_reason.length > 0);
  assert.equal(typeof result.confidence, "string");
  assert.ok(result.confidence.length > 0);
});

test("missing chain_family smart_contract is unroutable and does not throw", () => {
  const result = classifySurfaceCapability({
    id: "sc3",
    surface_type: "smart_contract",
  });
  assert.equal(result.routable, false);
  assert.equal(result.capability_pack, null);
  assert.equal(typeof result.unroutable_reason, "string");
  assert.ok(result.unroutable_reason.length > 0);
});

test("web surface routes to the web pack with null chain_family", () => {
  const result = classifySurfaceCapability({ id: "w1", surface_type: "api" });
  assert.equal(result.routable, true);
  assert.equal(result.chain_family, null);
  assert.equal(result.capability_pack, "web");
  assert.equal(typeof result.confidence, "string");
  assert.ok(result.confidence.length > 0);
});

test("confidence is a non-empty string on every classification path", () => {
  const surfaces = [
    { id: "sc1", surface_type: "smart_contract", chain_family: "evm" },
    { id: "sc2", surface_type: "smart_contract", chain_family: "cardano" },
    { id: "w1", surface_type: "api" },
  ];
  for (const surface of surfaces) {
    const result = classifySurfaceCapability(surface);
    assert.equal(typeof result.confidence, "string");
    assert.ok(result.confidence.length > 0);
  }
});

test("deriveConfidenceAdjustment: heavy friction demotes high -> medium (one threshold = one step)", () => {
  assert.equal(deriveConfidenceAdjustment("high", { tool_inadequate_count: 3 }), "medium");
});

test("deriveConfidenceAdjustment: very heavy friction demotes high -> low and clamps at low", () => {
  assert.equal(deriveConfidenceAdjustment("high", { tool_inadequate_count: 99 }), "low");
  assert.equal(deriveConfidenceAdjustment("low", { tool_inadequate_count: 99 }), "low");
});

test("deriveConfidenceAdjustment: no / absent friction leaves confidence unchanged", () => {
  assert.equal(deriveConfidenceAdjustment("high", { tool_inadequate_count: 0 }), "high");
  assert.equal(deriveConfidenceAdjustment("high", null), "high");
  assert.equal(deriveConfidenceAdjustment("medium", undefined), "medium");
});

test("deriveConfidenceAdjustment: never promotes (result ladder index >= base index) over base x count sweep", () => {
  for (const base of CONFIDENCE_LADDER) {
    const baseIdx = CONFIDENCE_LADDER.indexOf(base);
    for (const count of [0, 3, 6, 99]) {
      const out = deriveConfidenceAdjustment(base, { tool_inadequate_count: count });
      const outIdx = CONFIDENCE_LADDER.indexOf(out);
      assert.ok(outIdx >= baseIdx, `promoted ${base} -> ${out} at count=${count}`);
    }
  }
});

test("deriveConfidenceAdjustment: deterministic / pure — three identical calls are bit-identical", () => {
  const a = deriveConfidenceAdjustment("high", { tool_inadequate_count: 4 });
  const b = deriveConfidenceAdjustment("high", { tool_inadequate_count: 4 });
  const c = deriveConfidenceAdjustment("high", { tool_inadequate_count: 4 });
  assert.equal(a, b);
  assert.equal(b, c);
});

test("deriveConfidenceAdjustment: unrecognised base is returned unchanged", () => {
  assert.equal(deriveConfidenceAdjustment("bogus", { tool_inadequate_count: 99 }), "bogus");
});
