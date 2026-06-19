"use strict";

// Cycle Y.2 — bob_emit_runtime_drift (Y-D13).
//
// Asserts:
//   * Tool is orchestrator-only at the role-bundle layer (Y-D13).
//     The Y.3 _write-base.js auto-emit path will route through a
//     mcp_server_internal synthetic caller bundle that is NOT exported
//     by mcp/lib/role-bundles.js — but THIS cycle ships only the
//     orchestrator entry; we assert that NO non-orchestrator role bundle
//     resolves the tool name (a CI guard in Y.8 will additionally assert
//     mcp_server_internal absence from role-bundle exports).
//   * detected_by is FORCED to "mcp_runtime_auto_emit" even if callers
//     pass another value (Y-P7 — runtime channel cannot spoof voluntary).
//   * The closed runtime-emit drift-signature set is enforced: signatures
//     legal for CI-emitted bob_log_protocol_drift but not for runtime
//     emission (e.g. lifecycle_transition_invalid) are REJECTED.
//   * Y-R20 idempotency: (run_id, drift_signature, details.tool) silently
//     de-dupes; same triple with different rationale → second call is
//     idempotent. Different details.tool → second call appends.
//   * Y-D14 / D11 enrichment shape end-to-end: the details payload shape
//     {tool, session_mode, run_id} round-trips through the appended event.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const emitRuntimeDriftTool = require("../mcp/lib/tools/emit-runtime-drift.js");
const {
  TOOL_REGISTRY,
  toolNamesForRoleBundle,
  VALID_ROLE_BUNDLES,
} = require("../mcp/lib/tool-registry.js");
const {
  readFrontierEvents,
} = require("../mcp/lib/frontier-events.js");
const {
  sessionDir,
} = require("../mcp/lib/paths.js");
const {
  DETECTED_BY_VALUES,
} = require("../mcp/lib/capability-observations.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-y2-runtime-drift-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function ensureSessionDir(domain) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
}

function driftEventsFromLedger(domain) {
  return readFrontierEvents(domain)
    .filter((event) => event.kind === "observation.recorded"
      && event.payload
      && event.payload.observation_kind === "protocol_drift_observed");
}

// ── Y-D13: orchestrator-only at the role-bundle layer ───────────────────────

test("bob_emit_runtime_drift is granted ONLY to the orchestrator role bundle (Y-D13)", () => {
  assert.deepEqual(emitRuntimeDriftTool.role_bundles, ["orchestrator"]);

  // Sweep every other bundle to confirm the tool name does NOT appear.
  const offendingBundles = [];
  for (const bundle of VALID_ROLE_BUNDLES) {
    if (bundle === "orchestrator") continue;
    if (toolNamesForRoleBundle(bundle).includes("bob_emit_runtime_drift")) {
      offendingBundles.push(bundle);
    }
  }
  assert.deepEqual(
    offendingBundles,
    [],
    `bob_emit_runtime_drift leaked into non-orchestrator bundles: ${offendingBundles.join(", ")}`,
  );

  // Cross-check against the materialized registry entry.
  const entry = TOOL_REGISTRY.find((t) => t.name === "bob_emit_runtime_drift");
  assert.ok(entry, "bob_emit_runtime_drift must be registered");
  assert.deepEqual(entry.role_bundles, ["orchestrator"]);
});

test("the Y-D13 runtime-emit drift signature set is a subset of DRIFT_SIGNATURE_VALUES", () => {
  const { RUNTIME_EMIT_DRIFT_SIGNATURES } = emitRuntimeDriftTool;
  assert.ok(Array.isArray(RUNTIME_EMIT_DRIFT_SIGNATURES));
  assert.ok(Object.isFrozen(RUNTIME_EMIT_DRIFT_SIGNATURES));
  assert.deepEqual(
    RUNTIME_EMIT_DRIFT_SIGNATURES.slice().sort(),
    [
      "hook_denial",
      "partial_advance_acknowledged",
      "write_arg_schema_mismatch_recovered",
      "wrong_mode_tool_call",
    ],
  );
  // mcp_runtime_auto_emit must remain a closed-enum DETECTED_BY value.
  assert.ok(DETECTED_BY_VALUES.includes("mcp_runtime_auto_emit"));
});

// ── runtime-only contract ───────────────────────────────────────────────────

test("CI-only drift_signature (lifecycle_transition_invalid) is REJECTED at the runtime entry", () => {
  withTempHome(() => {
    const domain = "runtime-drift-ci-only.example.com";
    ensureSessionDir(domain);
    assert.throws(
      () => emitRuntimeDriftTool.handler({
        target_domain: domain,
        run_id: "run-1",
        drift_signature: "lifecycle_transition_invalid",
        rationale: "should reject — CI gates emit these via bob_log_protocol_drift.",
      }),
      /drift_signature must be one of/,
    );
    assert.equal(driftEventsFromLedger(domain).length, 0);
  });
});

test("runtime emit stamps detected_by=mcp_runtime_auto_emit even if caller passes another value", () => {
  withTempHome(() => {
    const domain = "runtime-drift-force-detected-by.example.com";
    ensureSessionDir(domain);
    const response = JSON.parse(emitRuntimeDriftTool.handler({
      target_domain: domain,
      run_id: "run-1",
      // Callers cannot spoof voluntary — the handler builds the payload itself.
      // Pass a junk value to prove it is ignored. (The schema does not list
      // detected_by, so passing it should be a no-op anyway.)
      detected_by: "agent_self_report",
      drift_signature: "wrong_mode_tool_call",
      rationale: "Verifier invoked bob_repo_check on a web-mode session.",
      details: { tool: "bob_repo_check", session_mode: "web", run_id: "run-1" },
    }));
    assert.equal(response.appended, true);
    assert.equal(response.observation_kind, "protocol_drift_observed");

    const events = driftEventsFromLedger(domain);
    assert.equal(events.length, 1);
    assert.equal(events[0].payload.detected_by, "mcp_runtime_auto_emit");
    assert.equal(events[0].payload.drift_signature, "wrong_mode_tool_call");
    assert.deepEqual(events[0].payload.details, {
      tool: "bob_repo_check",
      session_mode: "web",
      run_id: "run-1",
    });
  });
});

// ── Y-R20 idempotency ───────────────────────────────────────────────────────

test("Y-R20: idempotent on (run_id, drift_signature, details.tool)", () => {
  withTempHome(() => {
    const domain = "runtime-drift-idempotent.example.com";
    ensureSessionDir(domain);
    const first = JSON.parse(emitRuntimeDriftTool.handler({
      target_domain: domain,
      run_id: "run-1",
      drift_signature: "write_arg_schema_mismatch_recovered",
      rationale: "AJV missing repro_steps on first attempt; retry succeeded.",
      details: { tool: "bob_write_verification_round", attempts: 2 },
    }));
    assert.equal(first.appended, true);

    const second = JSON.parse(emitRuntimeDriftTool.handler({
      target_domain: domain,
      run_id: "run-1",
      drift_signature: "write_arg_schema_mismatch_recovered",
      rationale: "Different rationale — should still de-dupe on (run_id, sig, tool).",
      details: { tool: "bob_write_verification_round", attempts: 3 },
    }));
    assert.equal(second.appended, false);
    assert.equal(second.idempotent, true);
    assert.equal(second.event_id, first.event_id);

    // Different details.tool resolves to a NEW key.
    const third = JSON.parse(emitRuntimeDriftTool.handler({
      target_domain: domain,
      run_id: "run-1",
      drift_signature: "write_arg_schema_mismatch_recovered",
      rationale: "Different tool — different key.",
      details: { tool: "bob_write_evidence_packs", attempts: 2 },
    }));
    assert.equal(third.appended, true);
    assert.notEqual(third.event_id, first.event_id);

    assert.equal(driftEventsFromLedger(domain).length, 2);
  });
});

// ── argument validation ─────────────────────────────────────────────────────

test("rationale > 512 chars is REJECTED", () => {
  withTempHome(() => {
    const domain = "runtime-drift-rationale.example.com";
    ensureSessionDir(domain);
    assert.throws(
      () => emitRuntimeDriftTool.handler({
        target_domain: domain,
        run_id: "run-1",
        drift_signature: "hook_denial",
        rationale: "x".repeat(513),
      }),
      /rationale must be <= 512/,
    );
  });
});

test("non-object args are REJECTED", () => {
  assert.throws(
    () => emitRuntimeDriftTool.handler(null),
    /must be a plain object/,
  );
  assert.throws(
    () => emitRuntimeDriftTool.handler("string"),
    /must be a plain object/,
  );
  assert.throws(
    () => emitRuntimeDriftTool.handler([1, 2, 3]),
    /must be a plain object/,
  );
});
