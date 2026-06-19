"use strict";

// Evidence-bound path-composition experiment harness + the two orchestrator-
// only composition tools.
//
// The harness invariant: a composed cross-surface path is confirmed (pass)
// ONLY when every ordered leaf PROVES exploitability. A leaf is refused when its
// evidence_ref (a) is malformed (not a frontier_event:<id> ref), (b) resolves to
// no real event_id, or (c) resolves to an event that is not a typed-replay
// observation — its payload must carry the decisive request/response + verdict,
// a negative control whose verdict flips, and a recomputing replay_hash. Binding
// to a real-but-untyped payload, a non-flipping (benign) control, or a tampered
// hash is refused. Any refused leaf makes the whole path "fail": a path whose
// leaves are not bound to a replayable, control-flipping observation cannot be
// confirmed.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  appendFrontierEvent,
} = require("../mcp/lib/frontier-events.js");
const {
  COMPOSITION_EXPERIMENT_RESULT_KINDS,
  EVIDENCE_BINDING_REF_PATTERN,
} = require("../mcp/lib/task-graph-events.js");
const {
  COMPOSITION_RESULTS_MAX_RECORDS,
  REFUSAL_INVALID_PAYLOAD,
  REFUSAL_MALFORMED_REF,
  REFUSAL_NO_DECISIVE_FLIP,
  REFUSAL_NONDISCRIMINATING_CONTROL,
  REFUSAL_REPLAY_MISMATCH,
  REFUSAL_UNRESOLVED_EVENT,
  runPathCompositionExperiment,
} = require("../mcp/lib/composition-experiment-harness.js");
const {
  compositionResultsJsonlPath,
} = require("../mcp/lib/paths.js");
const { hashCanonicalJson } = require("../mcp/lib/verification-contracts.js");
const { TOOL_MANIFEST, TOOL_HANDLERS } = require("../mcp/lib/tool-registry.js");

const DOMAIN = "composition-experiment.test";

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-composition-exp-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

// Seed a real frontier observation and return its event_id so a leaf can bind
// to it via the frontier_event:<event_id> ref.
function seedRealEvent(domain, payload = { title: "obs" }) {
  const event = appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts: "2026-06-01T00:00:00.000Z",
    surface_id: "surface:billing",
    payload,
  });
  return event.event_id;
}

// Seed a frontier observation that carries the typed-replay predicate: the
// decisive request/response + verdict, a negative control whose verdict flips,
// and a replay_hash over the canonical {edge_type, request, response}. This is
// what a leaf must bind to in order to confirm (prove exploitability), not merely
// bind. opts.flip=false makes the negative-control verdict match (benign-but-
// bound); opts.tamperHash=true breaks the replay hash.
function seedReplayEvent(domain, edgeType, opts = {}) {
  const request = { method: "GET", url: `/api/${edgeType}/1`, principal: "attacker" };
  const response = { status: 200, body: `${edgeType}-leaked` };
  // A discriminating control is a DIFFERENT input; opts.nondiscriminating makes
  // it byte-identical to the positive (an impossible flip).
  const negative_control = {
    request: opts.nondiscriminating === true ? { ...request } : { ...request, principal: "owner" },
    response: opts.nondiscriminating === true ? { ...response } : { status: 403, body: "forbidden" },
    verdict: opts.flip === false ? "confirmed" : "denied",
  };
  const decisive = { edge_type: edgeType, request, response, verdict: "confirmed", negative_control };
  const payload = {
    ...decisive,
    replay_hash: opts.tamperHash === true ? "0".repeat(64) : hashCanonicalJson(decisive),
  };
  const event = appendFrontierEvent({
    target_domain: domain,
    kind: opts.kind || "observation.recorded",
    ts: "2026-06-01T00:00:00.000Z",
    surface_id: `surface:${edgeType}`,
    payload,
  });
  return event.event_id;
}

function refFor(eventId) {
  return `frontier_event:${eventId}`;
}

function readResultLedger(domain) {
  const filePath = compositionResultsJsonlPath(domain);
  if (!fs.existsSync(filePath)) return [];
  return fs
    .readFileSync(filePath, "utf8")
    .split("\n")
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line));
}

// ─── Vocabulary is frozen + binary ───────────────────────────────────────

test("COMPOSITION_EXPERIMENT_RESULT_KINDS is the frozen binary pass/fail vocab", () => {
  assert.deepEqual(COMPOSITION_EXPERIMENT_RESULT_KINDS, ["pass", "fail"]);
  assert.equal(Object.isFrozen(COMPOSITION_EXPERIMENT_RESULT_KINDS), true);
});

test("EVIDENCE_BINDING_REF_PATTERN matches frontier_event refs and rejects bare evidence", () => {
  assert.match("frontier_event:FE-abc123", EVIDENCE_BINDING_REF_PATTERN);
  assert.doesNotMatch("FE-abc123", EVIDENCE_BINDING_REF_PATTERN);
  assert.doesNotMatch("frontier_event:", EVIDENCE_BINDING_REF_PATTERN);
  assert.doesNotMatch("frontier_event:has space", EVIDENCE_BINDING_REF_PATTERN);
  assert.doesNotMatch("https://example.test/evidence/1", EVIDENCE_BINDING_REF_PATTERN);
});

// ─── PASS: every leaf resolves to a real validated observation ───────────

test("PASS when every leaf binds to a typed-replay observation whose decisive control flips", () => {
  withTempHome(() => {
    const a = seedReplayEvent(DOMAIN, "reachability");
    const b = seedReplayEvent(DOMAIN, "guard");
    const out = runPathCompositionExperiment(DOMAIN, {
      path: [
        { edge_id: "e1", evidence_ref: refFor(a) },
        { edge_id: "e2", evidence_ref: refFor(b) },
      ],
    });
    assert.equal(out.result, "pass");
    // A pass is an offline precondition, not a verified exploit.
    assert.equal(out.verification_required, true);
    assert.equal(out.refused_leaf_count, 0);
    assert.equal(out.bound_leaf_count, 2);
    assert.ok(!("refused_leaves" in out));
    assert.deepEqual(out.bound_event_ids, [a, b]);
  });
});

// ─── REFUSE: bound but does not PROVE exploitability (binds != exploits) ──

test("REFUSE a leaf bound to the right kind but an untyped payload — binding is not exploitation", () => {
  withTempHome(() => {
    // Right kind (observation.recorded) but the payload is not a typed-replay
    // observation: it binds (resolves) but proves nothing about a guard failing.
    const event = appendFrontierEvent({
      target_domain: DOMAIN,
      kind: "observation.recorded",
      ts: "2026-06-01T00:00:00.000Z",
      surface_id: "surface:billing",
      payload: { title: "auth-surface" },
    });
    const out = runPathCompositionExperiment(DOMAIN, {
      path: [{ edge_id: "e1", evidence_ref: refFor(event.event_id) }],
    });
    assert.equal(out.result, "fail");
    assert.equal(out.refused_leaves[0].reason, REFUSAL_INVALID_PAYLOAD);
  });
});

test("REFUSE a benign-but-bound leaf whose decisive control does not flip the verdict", () => {
  withTempHome(() => {
    const benign = seedReplayEvent(DOMAIN, "guard", { flip: false });
    const out = runPathCompositionExperiment(DOMAIN, {
      path: [{ edge_id: "e1", evidence_ref: refFor(benign) }],
    });
    assert.equal(out.result, "fail");
    assert.equal(out.refused_leaves[0].reason, REFUSAL_NO_DECISIVE_FLIP);
  });
});

test("REFUSE a leaf whose replay_hash does not recompute (unreplayable evidence)", () => {
  withTempHome(() => {
    const tampered = seedReplayEvent(DOMAIN, "sink", { tamperHash: true });
    const out = runPathCompositionExperiment(DOMAIN, {
      path: [{ edge_id: "e1", evidence_ref: refFor(tampered) }],
    });
    assert.equal(out.result, "fail");
    assert.equal(out.refused_leaves[0].reason, REFUSAL_REPLAY_MISMATCH);
  });
});

test("REFUSE a fabricated impossible flip — identical control input with the verdict relabelled", () => {
  withTempHome(() => {
    // negative_control byte-identical to the positive, only the verdict flipped:
    // the same input cannot yield opposite outcomes, so the flip is fabricated.
    const fake = seedReplayEvent(DOMAIN, "guard", { nondiscriminating: true });
    const out = runPathCompositionExperiment(DOMAIN, {
      path: [{ edge_id: "e1", evidence_ref: refFor(fake) }],
    });
    assert.equal(out.result, "fail");
    assert.equal(out.refused_leaves[0].reason, REFUSAL_NONDISCRIMINATING_CONTROL);
  });
});

test("REFUSE an exploit-shaped payload carried on a non-observation kind (no laundering)", () => {
  withTempHome(() => {
    // A perfect typed-replay payload on surface.observed must not confirm: only
    // the canonical observation.recorded kind may carry replay evidence.
    const wrongKind = seedReplayEvent(DOMAIN, "guard", { kind: "surface.observed" });
    const out = runPathCompositionExperiment(DOMAIN, {
      path: [{ edge_id: "e1", evidence_ref: refFor(wrongKind) }],
    });
    assert.equal(out.result, "fail");
    assert.equal(out.refused_leaves[0].reason, REFUSAL_INVALID_PAYLOAD);
  });
});

// ─── REFUSE (a): malformed ref ───────────────────────────────────────────

test("REFUSE a path with a malformed evidence_ref", () => {
  withTempHome(() => {
    const a = seedReplayEvent(DOMAIN, "guard");
    const out = runPathCompositionExperiment(DOMAIN, {
      path: [
        { edge_id: "e1", evidence_ref: refFor(a) },
        { edge_id: "e2", evidence_ref: "not-a-frontier-event-ref" },
      ],
    });
    assert.equal(out.result, "fail");
    assert.equal(out.refused_leaf_count, 1);
    assert.equal(out.refused_leaves[0].index, 1);
    assert.equal(out.refused_leaves[0].reason, REFUSAL_MALFORMED_REF);
  });
});

// ─── REFUSE (b): ref to a non-existent event_id ──────────────────────────

test("REFUSE a path whose ref resolves to no real event_id", () => {
  withTempHome(() => {
    const a = seedReplayEvent(DOMAIN, "guard");
    const out = runPathCompositionExperiment(DOMAIN, {
      path: [
        { edge_id: "e1", evidence_ref: refFor(a) },
        { edge_id: "e2", evidence_ref: refFor("FE-does-not-exist") },
      ],
    });
    assert.equal(out.result, "fail");
    assert.equal(out.refused_leaf_count, 1);
    assert.equal(out.refused_leaves[0].reason, REFUSAL_UNRESOLVED_EVENT);
    assert.equal(out.refused_leaves[0].resolved_event_id, "FE-does-not-exist");
  });
});

// ─── REFUSE (c): ref to an empty/invalid-payload event ───────────────────

test("REFUSE a path whose ref resolves to a bare/empty-payload event", () => {
  withTempHome(() => {
    // An event with an empty payload normalizes to payload: {} — a bare
    // observation with nothing to replay. The harness refuses it even though
    // the event_id resolves.
    const empty = appendFrontierEvent({
      target_domain: DOMAIN,
      kind: "surface.observed",
      ts: "2026-06-01T00:00:00.000Z",
      surface_id: "surface:bare",
      payload: {},
    });
    const out = runPathCompositionExperiment(DOMAIN, {
      path: [{ edge_id: "e1", evidence_ref: refFor(empty.event_id) }],
    });
    assert.equal(out.result, "fail");
    assert.equal(out.refused_leaf_count, 1);
    assert.equal(out.refused_leaves[0].reason, REFUSAL_INVALID_PAYLOAD);
    assert.equal(out.refused_leaves[0].resolved_event_id, empty.event_id);
  });
});

// ─── Binding resolves real events, not just regex shape ──────────────────

test("a well-formed ref to a never-recorded event is still refused (resolution, not regex)", () => {
  withTempHome(() => {
    // No events seeded: the ref is syntactically valid but binds to nothing.
    const out = runPathCompositionExperiment(DOMAIN, {
      path: [{ evidence_ref: "frontier_event:FE-syntactically-valid" }],
    });
    assert.equal(out.result, "fail");
    assert.equal(out.refused_leaves[0].reason, REFUSAL_UNRESOLVED_EVENT);
  });
});

// ─── Every refusal family is reported when a path mixes them ─────────────

test("a path mixing all three refusal families reports each unbound leaf", () => {
  withTempHome(() => {
    const good = seedReplayEvent(DOMAIN, "guard");
    const out = runPathCompositionExperiment(DOMAIN, {
      path: [
        { evidence_ref: refFor(good) },
        { evidence_ref: "bare-string" },
        { evidence_ref: refFor("FE-missing") },
      ],
    });
    assert.equal(out.result, "fail");
    assert.equal(out.bound_leaf_count, 1);
    const reasons = out.refused_leaves.map((leaf) => leaf.reason).sort();
    assert.deepEqual(reasons, [REFUSAL_MALFORMED_REF, REFUSAL_UNRESOLVED_EVENT].sort());
  });
});

// ─── Empty / invalid path inputs ─────────────────────────────────────────

test("an empty path is rejected — nothing to compose", () => {
  withTempHome(() => {
    assert.throws(() => runPathCompositionExperiment(DOMAIN, { path: [] }), /at least one leaf/);
  });
});

test("a non-array path is rejected", () => {
  withTempHome(() => {
    assert.throws(() => runPathCompositionExperiment(DOMAIN, { path: "nope" }), /must be an array/);
  });
});

// ─── Ledger is appended + capped ─────────────────────────────────────────

test("each run appends one record to the composition-results ledger", () => {
  withTempHome(() => {
    const a = seedReplayEvent(DOMAIN, "guard");
    runPathCompositionExperiment(DOMAIN, { path: [{ evidence_ref: refFor(a) }] });
    runPathCompositionExperiment(DOMAIN, { path: [{ evidence_ref: "bad" }] });
    const ledger = readResultLedger(DOMAIN);
    assert.equal(ledger.length, 2);
    assert.equal(ledger[0].result, "pass");
    assert.equal(ledger[1].result, "fail");
    assert.equal(ledger[1].refused_leaves.length, 1);
  });
});

test("the composition-results ledger is capped at COMPOSITION_RESULTS_MAX_RECORDS", () => {
  withTempHome(() => {
    const a = seedReplayEvent(DOMAIN, "guard");
    const filePath = compositionResultsJsonlPath(DOMAIN);
    // Pre-fill the ledger above the cap, then one real run trims it.
    const overflow = COMPOSITION_RESULTS_MAX_RECORDS + 5;
    const lines = [];
    for (let i = 0; i < overflow; i += 1) {
      lines.push(JSON.stringify({ version: 1, target_domain: DOMAIN, ts: "2026-06-01T00:00:00.000Z", result: "fail", seq: i }));
    }
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, `${lines.join("\n")}\n`, "utf8");
    runPathCompositionExperiment(DOMAIN, { path: [{ evidence_ref: refFor(a) }] });
    const ledger = readResultLedger(DOMAIN);
    assert.equal(ledger.length, COMPOSITION_RESULTS_MAX_RECORDS);
    // The newest record (our real run) survives; the oldest overflow lines are
    // trimmed.
    assert.equal(ledger[ledger.length - 1].result, "pass");
  });
});

// ─── Both tools are discoverable, orchestrator-only, valid shape ─────────

test("bob_run_path_composition_experiment is orchestrator-only and mutating", () => {
  const meta = TOOL_MANIFEST.bob_run_path_composition_experiment;
  assert.ok(meta, "tool is registered");
  assert.deepEqual(meta.role_bundles, ["orchestrator"]);
  assert.equal(meta.mutating, true);
  assert.equal(meta.network_access, false);
  assert.deepEqual(meta.session_artifacts_written, ["composition-results.jsonl"]);
  assert.equal(typeof TOOL_HANDLERS.bob_run_path_composition_experiment, "function");
});

test("bob_read_composition_telemetry is orchestrator-only and read-only", () => {
  const meta = TOOL_MANIFEST.bob_read_composition_telemetry;
  assert.ok(meta, "tool is registered");
  assert.deepEqual(meta.role_bundles, ["orchestrator"]);
  assert.equal(meta.mutating, false);
  assert.equal(meta.network_access, false);
  assert.deepEqual(meta.session_artifacts_written, []);
  assert.equal(typeof TOOL_HANDLERS.bob_read_composition_telemetry, "function");
});

test("bob_run_path_composition_experiment handler wraps the harness end to end", () => {
  withTempHome(() => {
    const a = seedReplayEvent(DOMAIN, "guard");
    const out = TOOL_HANDLERS.bob_run_path_composition_experiment({
      target_domain: DOMAIN,
      path: [{ evidence_ref: refFor(a) }],
    });
    assert.equal(out.result, "pass");
  });
});

test("bob_read_composition_telemetry handler returns the composition object", () => {
  withTempHome(() => {
    seedRealEvent(DOMAIN);
    const telemetry = TOOL_HANDLERS.bob_read_composition_telemetry({ target_domain: DOMAIN });
    assert.ok(telemetry && typeof telemetry === "object");
    for (const key of [
      "surfaces",
      "hypotheses",
      "transitions",
      "claims",
      "edges",
      "hypotheses_per_surface",
      "transitions_per_hypothesis",
      "composed",
    ]) {
      assert.ok(key in telemetry, `composition telemetry has ${key}`);
    }
  });
});
