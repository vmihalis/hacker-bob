"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  FIXTURES,
  evaluateAllFixtures,
  evaluateOneFixture,
} = require("../mcp/core/capability/capability-eval-harness.js");
const {
  capabilityToolMapFromRegistry,
} = require("../mcp/tools/tool-registry.js");

test("FIXTURES capabilities are backed by registry capability metadata", () => {
  const capabilityMap = capabilityToolMapFromRegistry();
  for (const [name, spec] of Object.entries(FIXTURES)) {
    assert.ok(capabilityMap[spec.capability], `${name} capability ${spec.capability} is registry-backed`);
  }
});

test("evaluateAllFixtures runs every fixture and reports passed/failed counts", async () => {
  const result = await evaluateAllFixtures();
  assert.equal(result.summary.total, Object.keys(FIXTURES).length);
  assert.equal(result.summary.failed, 0, `expected 0 failed, got ${result.summary.failed}: ${JSON.stringify(result.results.filter((r) => r.status === "failed"))}`);
  assert.equal(result.summary.passed, Object.keys(FIXTURES).length);
  for (const fixtureResult of result.results) {
    assert.ok(typeof fixtureResult.duration_ms === "number");
    assert.ok(fixtureResult.duration_ms >= 0);
  }
});

test("evaluateOneFixture executes a single named fixture", async () => {
  const result = await evaluateOneFixture("c2_doc_delta_auth_bypass");
  assert.equal(result.status, "passed");
  assert.equal(result.fixture, "c2_doc_delta_auth_bypass");
  assert.equal(result.capability, "C2_doc_vs_behavior");
  assert.ok(result.detail);
});

test("evaluateOneFixture rejects unknown fixture names", async () => {
  await assert.rejects(
    () => evaluateOneFixture("not-a-real-fixture"),
    /Unknown capability fixture/,
  );
});

test("each fixture has a non-empty description and a runner function", () => {
  for (const [name, spec] of Object.entries(FIXTURES)) {
    assert.ok(typeof spec.capability === "string" && spec.capability.length > 0, `${name} has capability`);
    assert.ok(typeof spec.description === "string" && spec.description.length > 0, `${name} has description`);
    assert.ok(typeof spec.run === "function", `${name} has run function`);
  }
});

test("a fixture failure surfaces as status: failed with an error message", async () => {
  // Inject a fixture that throws on purpose by patching FIXTURES temporarily.
  const original = FIXTURES.c2_doc_delta_auth_bypass.run;
  // FIXTURES is frozen, so patch the inner run via Object.defineProperty.
  Object.defineProperty(FIXTURES.c2_doc_delta_auth_bypass, "run", {
    value: async () => { throw new Error("synthetic failure"); },
    configurable: true,
    writable: true,
  });
  try {
    const result = await evaluateOneFixture("c2_doc_delta_auth_bypass");
    assert.equal(result.status, "failed");
    assert.match(result.error, /synthetic failure/);
  } finally {
    Object.defineProperty(FIXTURES.c2_doc_delta_auth_bypass, "run", {
      value: original,
      configurable: true,
      writable: true,
    });
  }
});
