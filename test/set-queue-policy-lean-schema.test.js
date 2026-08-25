"use strict";

// LEAN_PROFILE reachability through bob_set_queue_policy. The normalizer already
// handles an explicit null governor / in-flight cap correctly; the only block was the
// TOOL SCHEMA boundary, which declared these two fields as type "integer" and rejected
// null before the normalizer ran. They are now type ["integer","null"], so an operator
// can send the literal LEAN_PROFILE (or any null subset) through the tool — and the
// width-at-baseline LEAN profile stays governor-null (RANK != BOUND preserved). A PARTIAL
// lean (null governor + raised wave caps) still arms the 512 auto-fill governor.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const setQueuePolicy = require("../mcp/tools/set-queue-policy.js");
const { validateAgainstSchema } = require("../mcp/core/dispatch/tool-validation.js");
const {
  LEAN_PROFILE,
  DEFAULT_NESTING_SPAWN_BUDGET,
  normalizeQueuePolicy,
} = require("../mcp/core/io/queue-policy.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-lean-schema-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

const POLICY_PROPS = setQueuePolicy.inputSchema.properties.policy.properties;

test("the bob_set_queue_policy inputSchema declares the governor fields as type ['integer','null']", () => {
  assert.deepEqual(POLICY_PROPS.max_concurrent_evaluators.type, ["integer", "null"]);
  assert.deepEqual(POLICY_PROPS.max_total_spawned_agents.type, ["integer", "null"]);
});

test("passing null for the governor fields no longer throws at the schema validation boundary", () => {
  // This is the boundary that previously rejected null (type "integer").
  assert.doesNotThrow(() => validateAgainstSchema(
    { target_domain: "lean.example.test", policy: { max_concurrent_evaluators: null, max_total_spawned_agents: null } },
    setQueuePolicy.inputSchema,
    [],
  ));
  // An integer still validates; a non-integer/non-null is still rejected.
  assert.doesNotThrow(() => validateAgainstSchema(
    { target_domain: "lean.example.test", policy: { max_concurrent_evaluators: 8, max_total_spawned_agents: 256 } },
    setQueuePolicy.inputSchema, [],
  ));
  assert.throws(() => validateAgainstSchema(
    { target_domain: "lean.example.test", policy: { max_concurrent_evaluators: "x" } },
    setQueuePolicy.inputSchema, [],
  ));
});

test("bob_set_queue_policy accepts the FULL LEAN_PROFILE through the validator and persists governor null + in-flight cap null", () => withTempHome(() => {
  const domain = "lean-full.example.test";
  const args = { target_domain: domain, policy: { ...LEAN_PROFILE } };
  // The schema boundary accepts the full lean profile (all knobs lowered together,
  // both governor fields null).
  assert.doesNotThrow(() => validateAgainstSchema(args, setQueuePolicy.inputSchema, []));
  const persisted = JSON.parse(setQueuePolicy.handler(args)).queue_policy;
  // The at-baseline LEAN profile keeps BOTH null — no auto-fill governor (the
  // conservative single-recon / flat-evaluator profile, RANK != BOUND).
  assert.equal(persisted.max_concurrent_evaluators, null, "in-flight cap stays null");
  assert.equal(persisted.max_total_spawned_agents, null, "the lifetime governor stays null (width is at/below baseline)");
  assert.equal(persisted.max_spawn_depth, 1, "depth 1 (no nesting)");
}));

test("a PARTIAL lean (null governor + raised wave caps) still arms the 512 auto-fill governor", () => withTempHome(() => {
  // Lowering ONLY the governor while leaving raised width is the SAFE direction: the
  // auto-fill re-arms the 512 budget so a lifted width is never unbounded.
  const partial = normalizeQueuePolicy({
    max_total_spawned_agents: null,
    max_concurrent_evaluators: null,
    standard_wave_max: 128, // raised ABOVE the conservative baseline
  });
  assert.equal(partial.max_total_spawned_agents, DEFAULT_NESTING_SPAWN_BUDGET,
    "a raised-width partial lean re-arms the safety governor");
}));
