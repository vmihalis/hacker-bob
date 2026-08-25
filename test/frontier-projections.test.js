"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  appendClosureRecordedEvent,
  appendFrontierEvent,
} = require("../mcp/core/frontier/frontier-events.js");
const {
  currentBlockers,
  currentClosures,
  observationsForSurface,
} = require("../mcp/core/frontier/frontier-projections.js");
const {
  attackSurfacePath,
  sessionDir,
} = require("../mcp/core/io/paths.js");
const {
  secondorderMint,
  secondorderReread,
  resolveBinding,
  ORACLE_KIND_VALUES,
} = require("../mcp/domains/web/offensive-secondorder-producer.js");
const {
  verifyFindingDifferential,
} = require("../mcp/core/differential/index.js");
const {
  initSession,
} = require("../mcp/core/session/session-state.js");
const {
  routeSurfaces,
} = require("../mcp/core/frontier/surface-router.js");
const {
  ensureHandoffSigningKey,
} = require("../mcp/core/ledger-integrity/index.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/core/frontier/frontier-materialize-debounce.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-frontier-projections-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function withTempHomeAsync(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-frontier-projections-"));
  process.env.HOME = home;
  return Promise.resolve()
    .then(() => fn(home))
    .finally(() => {
      process.env.HOME = previousHome;
      resetMaterializationDebounce();
      fs.rmSync(home, { recursive: true, force: true });
    });
}

function ensureSessionDir(domain) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
}

const SECONDORDER_SURFACE_ID = "surface:stored";

function seedSecondorderSession(domain) {
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  fs.mkdirSync(path.dirname(attackSurfacePath(domain)), { recursive: true });
  fs.writeFileSync(attackSurfacePath(domain), `${JSON.stringify({
    surfaces: [{
      id: SECONDORDER_SURFACE_ID,
      title: "Synthetic stored-effect surface",
      surface_type: "web",
      hosts: [domain],
      endpoints: [`https://${domain}/api/inject`, `https://${domain}/api/read`],
      priority: "HIGH",
    }],
  }, null, 2)}\n`, "utf8");
  JSON.parse(routeSurfaces({ target_domain: domain }));
  ensureHandoffSigningKey(domain);
}

function secondorderCanaryFor(domain, handle) {
  const { binding } = resolveBinding(domain, handle);
  return binding ? binding.canary : null;
}

function jsonSource(obj, { status = 200 } = {}) {
  return () => ({ status, bodyBytes: Buffer.from(JSON.stringify(obj), "utf8") });
}

async function seedSecondorderCanaryProof(domain, findingId) {
  const positiveMint = await secondorderMint({
    target_domain: domain,
    surface_id: SECONDORDER_SURFACE_ID,
    oracle_kind: ORACLE_KIND_VALUES[0],
  });
  const canary = secondorderCanaryFor(domain, positiveMint.token_handle);
  const positive = await secondorderReread(
    { target_domain: domain, token_handle: positiveMint.token_handle, expect: "interaction" },
    { observation_source: jsonSource({ data: { body: canary } }) },
  );
  const controlMint = await secondorderMint({
    target_domain: domain,
    surface_id: SECONDORDER_SURFACE_ID,
    oracle_kind: ORACLE_KIND_VALUES[0],
  });
  const control = await secondorderReread(
    { target_domain: domain, token_handle: controlMint.token_handle, expect: "silence" },
    { observation_source: jsonSource({ data: { body: "unrelated" } }) },
  );
  return verifyFindingDifferential({
    target_domain: domain,
    finding_id: findingId,
    surface_id: SECONDORDER_SURFACE_ID,
    positive_run_ref: { ledger: "offensive_runs", row_id: positive.run_id },
    control_run_ref: { ledger: "offensive_runs", row_id: control.run_id },
  });
}

test("currentBlockers reflects a blocker.asserted event without touching state.terminally_blocked", () => {
  withTempHome(() => {
    const domain = "blocker-projection.example.com";
    ensureSessionDir(domain);
    // No state.json — state.terminally_blocked is implicit empty.
    appendFrontierEvent({
      target_domain: domain,
      kind: "blocker.asserted",
      ts: "2026-05-27T10:00:00.000Z",
      surface_id: "surface:billing",
      payload: {
        terminally_blocked: true,
        kind: "auth_missing",
      },
      source: { artifact: "wave-merge", tool: "bob_apply_wave_merge" },
    });
    const projected = currentBlockers(domain);
    assert.equal(projected.length, 1);
    assert.equal(projected[0].surface_id, "surface:billing");
    assert.ok(projected[0].source_event_id.startsWith("FE-"));
  });
});

test("currentBlockers folds latest event per surface_id", () => {
  withTempHome(() => {
    const domain = "blocker-fold.example.com";
    ensureSessionDir(domain);
    appendFrontierEvent({
      target_domain: domain,
      kind: "blocker.asserted",
      ts: "2026-05-27T10:00:00.000Z",
      surface_id: "surface:alpha",
      payload: { terminally_blocked: true, kind: "auth_missing", reason: "first" },
    });
    appendFrontierEvent({
      target_domain: domain,
      kind: "blocker.asserted",
      ts: "2026-05-27T10:01:00.000Z",
      surface_id: "surface:alpha",
      payload: { terminally_blocked: true, kind: "egress_unreachable", reason: "second" },
    });
    appendFrontierEvent({
      target_domain: domain,
      kind: "blocker.asserted",
      ts: "2026-05-27T10:02:00.000Z",
      surface_id: "surface:beta",
      payload: { terminally_blocked: true, kind: "auth_missing", reason: "beta-first" },
    });
    const projected = currentBlockers(domain);
    assert.equal(projected.length, 2);
    const byId = new Map(projected.map((entry) => [entry.surface_id, entry]));
    assert.equal(byId.get("surface:alpha").reason, "second");
    assert.equal(byId.get("surface:beta").reason, "beta-first");
  });
});

test("currentClosures refuses proof_record forgeries while preserving plain exhaustion closures", () => {
  withTempHome(() => {
    const domain = "closure-projection.example.com";
    ensureSessionDir(domain);
    // A logCoverage-style closure event must not be treated as a surface
    // closure — these capture endpoint-batch coverage, not surface state.
    appendClosureRecordedEvent({
      target_domain: domain,
      kind: "closure.recorded",
      ts: "2026-05-27T10:00:00.000Z",
      surface_id: "surface:coverage-batch",
      payload: { records: 1, statuses: { requeue: 1 } },
      source: { artifact: "coverage.jsonl", tool: "bob_log_coverage" },
    });
    // Soft/unknown proof_record rows are not proof. They must hold open even
    // when wave-merge-sourced.
    appendClosureRecordedEvent({
      target_domain: domain,
      kind: "closure.recorded",
      ts: "2026-05-27T10:01:00.000Z",
      surface_id: "surface:explored",
      payload: {
        surface_fully_explored: true,
        reason: "complete handoff",
        proof_record: { proof_mode: "soft_llm_verdict", result: "closed" },
      },
      source: { artifact: "wave-merge", tool: "bob_apply_wave_merge" },
    });
    assert.deepEqual(currentClosures(domain), []);

    // Plain surface exhaustion carries no proof claim and remains governed by
    // the existing earned-done/exhaustion path.
    appendClosureRecordedEvent({
      target_domain: domain,
      kind: "closure.recorded",
      ts: "2026-05-27T10:02:00.000Z",
      surface_id: "surface:plain-exhaustion",
      payload: { surface_fully_explored: true, reason: "surface_completed" },
      source: { artifact: "wave-merge", tool: "bob_apply_wave_merge" },
    });
    const projected = currentClosures(domain);
    assert.equal(projected.length, 1);
    assert.equal(projected[0].surface_id, "surface:plain-exhaustion");
    assert.equal(projected[0].reason, "surface_completed");
  });
});

test("currentClosures requires a proof_record claim to match a re-derived canary proof", () => {
  return withTempHomeAsync(async () => {
    const domain = "closure-canary-proof.example.com";
    seedSecondorderSession(domain);
    const verdict = await seedSecondorderCanaryProof(domain, "F-CANARY-CLOSURE");
    assert.equal(verdict.result, "verified_pass");
    assert.equal(verdict.proof_record.proof_mode, "observed_invariant_canary_v1");

    appendClosureRecordedEvent({
      target_domain: domain,
      kind: "closure.recorded",
      ts: "2026-05-27T10:00:00.000Z",
      surface_id: SECONDORDER_SURFACE_ID,
      payload: {
        surface_fully_explored: true,
        proof_mode: "observed_invariant_canary_v1",
        reason: "raw canary closure without proof",
      },
      source: { artifact: "wave-merge", tool: "bob_apply_wave_merge" },
    });
    assert.deepEqual(currentClosures(domain), [], "raw canary closure rows without a proof_record hold open");

    appendClosureRecordedEvent({
      target_domain: domain,
      kind: "closure.recorded",
      ts: "2026-05-27T10:01:00.000Z",
      surface_id: SECONDORDER_SURFACE_ID,
      payload: {
        surface_fully_explored: true,
        reason: "forged proof hash",
        proof_record: { ...verdict.proof_record, proof_hash: "0".repeat(64) },
      },
      source: { artifact: "wave-merge", tool: "bob_apply_wave_merge" },
    });
    assert.deepEqual(currentClosures(domain), [], "mismatched proof_record holds the surface open");

    appendClosureRecordedEvent({
      target_domain: domain,
      kind: "closure.recorded",
      ts: "2026-05-27T10:02:00.000Z",
      surface_id: SECONDORDER_SURFACE_ID,
      payload: {
        surface_fully_explored: true,
        reason: "matched canary proof",
        proof_record: verdict.proof_record,
      },
      source: { artifact: "wave-merge", tool: "bob_apply_wave_merge" },
    });
    const projected = currentClosures(domain);
    assert.equal(projected.length, 1);
    assert.equal(projected[0].surface_id, SECONDORDER_SURFACE_ID);
    assert.equal(projected[0].reason, "matched canary proof");

    appendClosureRecordedEvent({
      target_domain: domain,
      kind: "closure.recorded",
      ts: "2026-05-27T10:03:00.000Z",
      surface_id: SECONDORDER_SURFACE_ID,
      payload: {
        surface_fully_explored: true,
        reason: "later forged soft proof",
        proof_record: { proof_mode: "soft_llm_verdict", result: "closed" },
      },
      source: { artifact: "wave-merge", tool: "bob_apply_wave_merge" },
    });
    assert.deepEqual(currentClosures(domain), [], "a later forged proof claim supersedes the earlier closure and holds open");
  });
});

test("currentClosures ignores non-qualifying batch coverage events (no fallback after D.3)", () => {
  withTempHome(() => {
    const domain = "no-fallback-closures.example.com";
    ensureSessionDir(domain);
    // logCoverage-style events do not satisfy isSurfaceClosureEvent because
    // they lack surface_fully_explored AND are not wave-merge-sourced. After
    // D.3 the state.explored fallback is gone — the projection returns
    // an empty array rather than back-reading state.json.
    appendClosureRecordedEvent({
      target_domain: domain,
      kind: "closure.recorded",
      ts: "2026-05-27T10:00:00.000Z",
      surface_id: "surface:coverage-batch",
      payload: { records: 1, statuses: { requeue: 1 } },
      source: { artifact: "coverage.jsonl", tool: "bob_log_coverage" },
    });
    const projected = currentClosures(domain);
    assert.deepEqual(projected, []);
  });
});

test("currentBlockers ignores non-qualifying dead-end batch events (no fallback after D.3)", () => {
  withTempHome(() => {
    const domain = "no-fallback-blockers.example.com";
    ensureSessionDir(domain);
    // logDeadEnds-style events do not satisfy isSurfaceBlockerEvent because
    // they lack terminally_blocked AND are not wave-merge-sourced. After
    // D.3 the state.terminally_blocked fallback is gone.
    appendFrontierEvent({
      target_domain: domain,
      kind: "blocker.asserted",
      ts: "2026-05-27T10:00:00.000Z",
      surface_id: "surface:dead-end-batch",
      payload: {
        dead_ends: ["GET /foo"],
        waf_blocked_endpoints: [],
        dead_end_count: 1,
        waf_blocked_count: 0,
      },
      source: { artifact: "live-dead-ends.jsonl", tool: "bob_log_dead_ends" },
    });
    const projected = currentBlockers(domain);
    assert.deepEqual(projected, []);
  });
});

test("currentBlockers excludes surfaces whose latest event is an unblock clear", () => {
  withTempHome(() => {
    const domain = "clear-supersedes-blocker.example.com";
    ensureSessionDir(domain);
    appendFrontierEvent({
      target_domain: domain,
      kind: "blocker.asserted",
      ts: "2026-05-27T10:00:00.000Z",
      surface_id: "surface:transient",
      payload: { terminally_blocked: true, kind: "auth_missing" },
      source: { artifact: "wave-merge", tool: "bob_apply_wave_merge" },
    });
    appendClosureRecordedEvent({
      target_domain: domain,
      kind: "closure.recorded",
      ts: "2026-05-27T10:01:00.000Z",
      surface_id: "surface:transient",
      payload: { surface_unblocked: true, reason: "operator_cleared_terminal_block" },
      source: { artifact: "wave-merge", tool: "bob_apply_wave_merge" },
    });
    assert.deepEqual(currentBlockers(domain), []);
    assert.equal(currentClosures(domain).length, 0);
  });
});

test("currentClosures and currentBlockers return empty arrays when neither state nor ledger has surface state", () => {
  withTempHome(() => {
    const domain = "pristine.example.com";
    ensureSessionDir(domain);
    assert.deepEqual(currentClosures(domain), []);
    assert.deepEqual(currentBlockers(domain), []);
  });
});

test("observationsForSurface returns observation events for the requested surface in timestamp order", () => {
  withTempHome(() => {
    const domain = "observations.example.com";
    ensureSessionDir(domain);
    appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      ts: "2026-05-27T10:02:00.000Z",
      surface_id: "surface:gamma",
      payload: { note: "second" },
    });
    appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      ts: "2026-05-27T10:01:00.000Z",
      surface_id: "surface:gamma",
      payload: { note: "first" },
    });
    appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      ts: "2026-05-27T10:03:00.000Z",
      surface_id: "surface:other",
      payload: { note: "different surface" },
    });
    const ordered = observationsForSurface(domain, "surface:gamma");
    assert.equal(ordered.length, 2);
    assert.equal(ordered[0].payload.note, "first");
    assert.equal(ordered[1].payload.note, "second");
  });
});

test("observationsForSurface returns empty array when no events exist for the surface", () => {
  withTempHome(() => {
    const domain = "empty-observations.example.com";
    ensureSessionDir(domain);
    assert.deepEqual(observationsForSurface(domain, "surface:absent"), []);
  });
});

test("observationsForSurface rejects empty surface_id", () => {
  withTempHome(() => {
    const domain = "observation-validation.example.com";
    ensureSessionDir(domain);
    assert.throws(
      () => observationsForSurface(domain, ""),
      /surface_id/,
    );
  });
});
