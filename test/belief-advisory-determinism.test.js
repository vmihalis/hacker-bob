"use strict";

// Belief-ordered dispatch is DETERMINISTIC.
//
// With belief ON, a fixed (seed, fed-signals) pair must produce a byte-identical
// dispatch order across repeated runs. The belief rank builders
// (buildCellBeliefRank / buildBeliefSchedulerHints) must be seed-deterministic with
// NO unseeded RNG (Math.random / randomBytes / Date.now) leaking into dispatch
// order. If one existed, that itself would be a finding — so this file also asserts,
// at the source, that the dispatch-order belief modules contain no unseeded RNG.
//
// Belief is driven ON LOCALLY (injected surfaces + seed); NO production default is
// changed.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const REPO_ROOT = path.join(__dirname, "..");

const {
  buildCellBeliefRank,
} = require("../mcp/lib/belief/cell-scheduler-priority.js");
const {
  buildBeliefSchedulerHints,
} = require("../mcp/lib/belief/scheduler-priority.js");
const { appendEdges } = require("../mcp/lib/surface-graph.js");
const { sessionDir } = require("../mcp/lib/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-belief-determinism-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function seedGraph(domain) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  appendEdges({
    target_domain: domain,
    edges: [
      { source: { type: "principal", id: "principal:attacker" }, target: { type: "policy_gate", id: "policy_gate:owner" }, edge_type: "tests_gate" },
      { source: { type: "policy_gate", id: "policy_gate:owner" }, target: { type: "effect", id: "effect:unauth_succeeds_where_auth_blocked:victim" }, edge_type: "permits_effect" },
    ],
  });
}

const SURFACES = (domain) => [
  { id: "surface:idor-victim", title: "victim object access", hosts: [domain], bug_class_hints: ["unauth_succeeds_where_auth_blocked"], high_value_flows: ["attacker reads owner victim object"] },
  { id: "surface:cold", title: "static assets", hosts: [domain] },
];

const CANDIDATES = [
  { node_id: "TG-cell-hot", kind: "cell", priority: "medium", tier: 1, severity_floor: "low", surface_refs: ["surface:idor-victim"] },
  { node_id: "TG-cell-cold", kind: "cell", priority: "medium", tier: 1, severity_floor: "low", surface_refs: ["surface:cold"] },
];

test("buildCellBeliefRank is byte-identical across two runs with the same (seed, signals)", () => {
  withTempHome(() => {
    const domain = "belief-cell-determinism.example.com";
    seedGraph(domain);
    const document = { nodes: CANDIDATES };
    const run = () => buildCellBeliefRank({
      target_domain: domain,
      document,
      candidates: CANDIDATES,
      surfaces: SURFACES(domain),
      seed: "belief-scheduler-priority",
    });
    const first = run();
    const second = run();

    // NON-VACUITY GUARD: the rank must be non-empty, else "identical" is trivial.
    assert.ok(first.size >= 1, `belief rank must be non-empty (got ${first.size}) — else determinism is vacuous`);

    // Byte-identical: same keys, same scores, same insertion order.
    assert.deepEqual([...first.entries()], [...second.entries()], "same (seed, signals) => byte-identical cell belief rank");
  });
});

test("buildBeliefSchedulerHints order + scores are byte-identical across two runs (same seed, same fed-signals)", () => {
  withTempHome(() => {
    const domain = "belief-hints-determinism.example.com";
    seedGraph(domain);
    const run = () => buildBeliefSchedulerHints({
      target_domain: domain,
      surfaces: SURFACES(domain),
      seed: "belief-scheduler-priority",
    });
    const first = run();
    const second = run();
    assert.equal(first.applied, true, "non-vacuity: belief hints applied");
    assert.ok(first.hints.length >= 1, "non-vacuity: at least one hint");

    // Order + scores are byte-identical.
    assert.deepEqual(
      first.hints.map((h) => [h.surface_id, h.score]),
      second.hints.map((h) => [h.surface_id, h.score]),
      "same (seed, fed-signals) => byte-identical hint order and scores",
    );
    // The replay pin (fed-signal hashes) is byte-identical too — the determinism is
    // recorded and auditable, not incidental.
    assert.deepEqual(first.belief_replay, second.belief_replay, "belief_replay pin is byte-identical across runs");
    assert.equal(first.calculus_hash, second.calculus_hash);
    assert.equal(first.window_hash, second.window_hash);
  });
});

test("a DIFFERENT seed is still internally deterministic (re-running the SAME different seed reproduces it)", () => {
  withTempHome(() => {
    const domain = "belief-seed-determinism.example.com";
    seedGraph(domain);
    const runWith = (seed) => buildBeliefSchedulerHints({ target_domain: domain, surfaces: SURFACES(domain), seed }).hints.map((h) => [h.surface_id, h.score]);
    // Same (seed, signals) reproduces, for two distinct seeds — confirms the order is
    // a pure function of (seed, signals), with no run-to-run RNG drift.
    assert.deepEqual(runWith("seed-A"), runWith("seed-A"), "seed-A reproduces");
    assert.deepEqual(runWith("seed-B"), runWith("seed-B"), "seed-B reproduces");
  });
});

test("the dispatch-order belief modules contain NO unseeded RNG (no Math.random / randomBytes / Date.now leak into order)", () => {
  // A standing source guard: an unseeded RNG anywhere on the belief dispatch-order
  // path would silently break replayability (and is itself a finding). Assert the
  // order-bearing modules are RNG-free at the source.
  const UNSEEDED_RNG = /Math\.random\s*\(|randomBytes\s*\(|randomUUID\s*\(|Date\.now\s*\(/;
  const ORDER_MODULES = [
    "mcp/lib/belief/cell-scheduler-priority.js",
    "mcp/lib/belief/scheduler-priority.js",
    "mcp/lib/belief/intervention-calculus.js",
    "mcp/lib/graph-scheduler.js",
  ];
  for (const rel of ORDER_MODULES) {
    const src = fs.readFileSync(path.join(REPO_ROOT, rel), "utf8");
    assert.ok(
      !UNSEEDED_RNG.test(src),
      `${rel} contains an unseeded RNG / wall-clock call on the dispatch-order path — replayability leak (a finding)`,
    );
  }
});

test("positive control: the unseeded-RNG guard BITES a module that uses Math.random", () => {
  // Prove the RNG guard is non-vacuous: a synthetic source string with Math.random
  // MUST be flagged by the same regex.
  const UNSEEDED_RNG = /Math\.random\s*\(|randomBytes\s*\(|randomUUID\s*\(|Date\.now\s*\(/;
  assert.ok(UNSEEDED_RNG.test("const x = Math.random();"), "the RNG guard must flag Math.random (else vacuous)");
  assert.ok(UNSEEDED_RNG.test("const t = Date.now();"), "the RNG guard must flag Date.now");
});
