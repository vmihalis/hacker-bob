"use strict";

// Cycle Y.2 — bob_log_capability_friction + bob_log_protocol_drift
// integration tests. Asserts:
//   * Y-P3 5-tuple idempotency: second emission with the same
//     (run_id, node_id, wanted_tool, purpose, detected_by) tuple silently
//     short-circuits (no duplicate append).
//   * Same 4-tuple with a DIFFERENT purpose appends TWO events (operator
//     scrutiny path per Y-P11 coexistence signal).
//   * Voluntary tool_inadequate + adversarial-scan synthetic on the same
//     wanted_tool COEXIST (different detected_by → different 5-tuple key).
//   * The validator IS invoked through the tool (Y-P2 shape rejection
//     happens at the wrapper, not just on isolated validator calls).
//   * Y-P10 witness existence + tool match is verified end-to-end using a
//     real frontier event the test seeds itself.
//   * frontier-events.jsonl receives an observation.recorded event whose
//     payload carries observation_kind: "capability_friction_observed"
//     (Y-P1 — siblings of OSS kinds, ZERO new top-level kinds).
//
// Protocol drift assertions cover the (run_id, skill_path, drift_signature)
// idempotency key + runtime-emit drifts coexisting under a <runtime>
// sentinel skill_path.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const logCapabilityFrictionTool = require("../mcp/lib/tools/log-capability-friction.js");
const logProtocolDriftTool = require("../mcp/lib/tools/log-protocol-drift.js");
const {
  appendFrontierEvent,
  readFrontierEvents,
  FRONTIER_EVENT_KINDS,
} = require("../mcp/lib/frontier-events.js");
const {
  sessionDir,
} = require("../mcp/lib/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-y2-friction-"));
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

function baseFrictionArgs(domain, overrides = {}) {
  return {
    target_domain: domain,
    run_id: "run-A",
    node_id: "N-1",
    wanted_tool: "bob_http_scan",
    purpose: "http_probe",
    fallback_used: "bash_curl",
    friction_kind: "tool_absent",
    detected_by: "agent_self_report",
    rationale: "Pack omitted bob_http_scan; reached for curl as fallback.",
    ...overrides,
  };
}

function baseDriftArgs(domain, overrides = {}) {
  return {
    target_domain: domain,
    run_id: "run-B",
    drift_signature: "wrong_mode_tool_call",
    detected_by: "mcp_runtime_auto_emit",
    rationale: "Verifier invoked bob_repo_check on a web-mode session.",
    ...overrides,
  };
}

function frictionPayloadsFromLedger(domain) {
  return readFrontierEvents(domain)
    .filter((event) => event.kind === "observation.recorded"
      && event.payload
      && event.payload.observation_kind === "capability_friction_observed")
    .map((event) => ({ event_id: event.event_id, payload: event.payload }));
}

function driftPayloadsFromLedger(domain) {
  return readFrontierEvents(domain)
    .filter((event) => event.kind === "observation.recorded"
      && event.payload
      && event.payload.observation_kind === "protocol_drift_observed")
    .map((event) => ({ event_id: event.event_id, payload: event.payload }));
}

// ── tool registration + frontmatter contract ────────────────────────────────

test("bob_log_capability_friction is registered with the expected role bundles + capability_id", () => {
  assert.equal(logCapabilityFrictionTool.name, "bob_log_capability_friction");
  assert.equal(logCapabilityFrictionTool.capability_id, "Y_self_reporting");
  assert.ok(logCapabilityFrictionTool.role_bundles.includes("evaluator-shared"));
  assert.ok(logCapabilityFrictionTool.role_bundles.includes("orchestrator"));
  assert.ok(logCapabilityFrictionTool.role_bundles.includes("surface-discovery"));
  assert.ok(logCapabilityFrictionTool.role_bundles.includes("chain"));
  assert.ok(logCapabilityFrictionTool.role_bundles.includes("evaluator-spawn"));
  assert.deepEqual(
    logCapabilityFrictionTool.session_artifacts_written,
    ["frontier-events.jsonl"],
  );
});

test("bob_log_protocol_drift is registered with broad voluntary-emission role bundles", () => {
  assert.equal(logProtocolDriftTool.name, "bob_log_protocol_drift");
  assert.equal(logProtocolDriftTool.capability_id, "Y_self_reporting");
  assert.ok(logProtocolDriftTool.role_bundles.includes("orchestrator"));
  assert.ok(logProtocolDriftTool.role_bundles.includes("evaluator-shared"));
});

test("the two log tools ride observation.recorded — no new top-level FRONTIER_EVENT_KIND", () => {
  assert.ok(FRONTIER_EVENT_KINDS.includes("observation.recorded"));
  assert.equal(FRONTIER_EVENT_KINDS.includes("capability_friction_observed"), false);
  assert.equal(FRONTIER_EVENT_KINDS.includes("protocol_drift_observed"), false);
});

// ── shape validation delegation ─────────────────────────────────────────────

test("invalid payload (unknown purpose) is REJECTED by the wrapper", () => {
  withTempHome(() => {
    const domain = "shape-reject.example.com";
    ensureSessionDir(domain);
    assert.throws(
      () => logCapabilityFrictionTool.handler(baseFrictionArgs(domain, {
        purpose: "not_a_purpose",
      })),
      /purpose must be one of/,
    );
    assert.equal(frictionPayloadsFromLedger(domain).length, 0);
  });
});

test("unregistered wanted_tool is REJECTED by the wrapper", () => {
  withTempHome(() => {
    const domain = "wanted-tool-reject.example.com";
    ensureSessionDir(domain);
    assert.throws(
      () => logCapabilityFrictionTool.handler(baseFrictionArgs(domain, {
        wanted_tool: "bob_not_a_real_tool",
      })),
      /wanted_tool must exist in TOOL_REGISTRY/,
    );
    assert.equal(frictionPayloadsFromLedger(domain).length, 0);
  });
});

test("rationale > 512 chars is REJECTED by the wrapper", () => {
  withTempHome(() => {
    const domain = "rationale-reject.example.com";
    ensureSessionDir(domain);
    assert.throws(
      () => logCapabilityFrictionTool.handler(baseFrictionArgs(domain, {
        rationale: "x".repeat(513),
      })),
      /rationale must be <= 512/,
    );
    assert.equal(frictionPayloadsFromLedger(domain).length, 0);
  });
});

// ── Y-P1 / Y-P2 happy path: friction event lands on observation.recorded ────

test("tool_absent friction APPENDS an observation.recorded event with payload.observation_kind set", () => {
  withTempHome(() => {
    const domain = "friction-append.example.com";
    ensureSessionDir(domain);

    const response = JSON.parse(logCapabilityFrictionTool.handler(baseFrictionArgs(domain, {
      surface_id: "surface:billing-admin",
    })));
    assert.equal(response.appended, true);
    assert.equal(response.idempotent, false);
    assert.equal(response.observation_kind, "capability_friction_observed");
    assert.equal(typeof response.event_id, "string");
    assert.equal(typeof response.event_hash, "string");

    const ledger = frictionPayloadsFromLedger(domain);
    assert.equal(ledger.length, 1);
    const [{ payload }] = ledger;
    assert.equal(payload.observation_kind, "capability_friction_observed");
    assert.equal(payload.run_id, "run-A");
    assert.equal(payload.node_id, "N-1");
    assert.equal(payload.wanted_tool, "bob_http_scan");
    assert.equal(payload.purpose, "http_probe");
    assert.equal(payload.friction_kind, "tool_absent");
    assert.equal(payload.detected_by, "agent_self_report");
    assert.equal(payload.surface_id, "surface:billing-admin");
    assert.equal(Object.prototype.hasOwnProperty.call(payload, "inadequacy_mode"), false);
    assert.equal(Object.prototype.hasOwnProperty.call(payload, "inadequate_invocation_ref"), false);
  });
});

// ── Y-P3 5-tuple idempotency ────────────────────────────────────────────────

test("second emission with the SAME 5-tuple is silently de-duped (Y-P3)", () => {
  withTempHome(() => {
    const domain = "friction-idempotent.example.com";
    ensureSessionDir(domain);

    const first = JSON.parse(logCapabilityFrictionTool.handler(baseFrictionArgs(domain)));
    assert.equal(first.appended, true);
    assert.equal(first.idempotent, false);

    const second = JSON.parse(logCapabilityFrictionTool.handler(baseFrictionArgs(domain, {
      // Change rationale + surface_id to prove these fields are NOT in the
      // 5-tuple; the de-dupe must still fire because the 5-tuple is identical.
      rationale: "Different rationale — should still de-dupe on 5-tuple match.",
      surface_id: "surface:NEW",
    })));
    assert.equal(second.appended, false);
    assert.equal(second.idempotent, true);
    assert.equal(second.event_id, first.event_id);
    assert.equal(second.event_hash, first.event_hash);

    assert.equal(frictionPayloadsFromLedger(domain).length, 1);
  });
});

test("same 4-tuple but DIFFERENT purpose appends TWO events (operator scrutiny)", () => {
  withTempHome(() => {
    const domain = "friction-purpose-distinct.example.com";
    ensureSessionDir(domain);

    const first = JSON.parse(logCapabilityFrictionTool.handler(baseFrictionArgs(domain, {
      purpose: "http_probe",
    })));
    const second = JSON.parse(logCapabilityFrictionTool.handler(baseFrictionArgs(domain, {
      purpose: "schema_fetch",
    })));
    assert.equal(first.appended, true);
    assert.equal(second.appended, true);
    assert.notEqual(first.event_id, second.event_id);

    const ledger = frictionPayloadsFromLedger(domain);
    assert.equal(ledger.length, 2);
    const purposes = ledger.map(({ payload }) => payload.purpose).sort();
    assert.deepEqual(purposes, ["http_probe", "schema_fetch"]);
  });
});

test("voluntary tool_inadequate + adversarial-scan synthetic on SAME wanted_tool coexist (Y-P11)", () => {
  withTempHome(() => {
    const domain = "friction-coexistence.example.com";
    ensureSessionDir(domain);

    // First seed a recorded MCP invocation event the witness can resolve to
    // (Y-P10 mechanical witness verifier requires the referenced event to
    // exist in the same run_id and reference the same tool).
    const witness = appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      payload: {
        observation_kind: "tool_invocation_recorded",
        tool: "bob_http_scan",
        run_id: "run-A",
        outcome: "non_success",
      },
    });
    const witnessRef = `frontier_event:${witness.event_id}`;

    // Voluntary tool_inadequate with mechanical witness.
    const voluntary = JSON.parse(logCapabilityFrictionTool.handler(baseFrictionArgs(domain, {
      friction_kind: "tool_inadequate",
      inadequacy_mode: "body_truncated",
      inadequate_invocation_ref: witnessRef,
      detected_by: "agent_self_report",
    })));
    assert.equal(voluntary.appended, true);

    // Synthetic adversarial-scan record for the SAME wanted_tool / purpose /
    // node — must NOT de-dupe because detected_by is different.
    const synthetic = JSON.parse(logCapabilityFrictionTool.handler(baseFrictionArgs(domain, {
      friction_kind: "tool_absent",
      detected_by: "adversarial_transcript_scan",
      fallback_used: "bash_curl",
    })));
    assert.equal(synthetic.appended, true);
    assert.notEqual(synthetic.event_id, voluntary.event_id);

    const ledger = frictionPayloadsFromLedger(domain);
    assert.equal(ledger.length, 2);
    const kinds = ledger.map(({ payload }) => `${payload.friction_kind}/${payload.detected_by}`).sort();
    assert.deepEqual(kinds, [
      "tool_absent/adversarial_transcript_scan",
      "tool_inadequate/agent_self_report",
    ]);
  });
});

// ── Y-P10 witness verification end-to-end through the wrapper ───────────────

test("tool_inadequate witness pointing at a NON-MATCHING run_id is REJECTED end-to-end", () => {
  withTempHome(() => {
    const domain = "friction-witness-run.example.com";
    ensureSessionDir(domain);

    // Seed a witness whose run_id is OTHER than the friction record's run_id.
    const witness = appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      payload: {
        observation_kind: "tool_invocation_recorded",
        tool: "bob_http_scan",
        run_id: "run-OTHER",
        outcome: "non_success",
      },
    });
    const witnessRef = `frontier_event:${witness.event_id}`;

    assert.throws(
      () => logCapabilityFrictionTool.handler(baseFrictionArgs(domain, {
        friction_kind: "tool_inadequate",
        inadequacy_mode: "body_truncated",
        inadequate_invocation_ref: witnessRef,
        run_id: "run-A",
      })),
      /run_id .* does not match record run_id/,
    );
  });
});

test("tool_inadequate witness pointing at a different TOOL is REJECTED end-to-end", () => {
  withTempHome(() => {
    const domain = "friction-witness-tool.example.com";
    ensureSessionDir(domain);

    const witness = appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      payload: {
        observation_kind: "tool_invocation_recorded",
        tool: "bob_extract_routes",
        run_id: "run-A",
        outcome: "non_success",
      },
    });
    const witnessRef = `frontier_event:${witness.event_id}`;

    assert.throws(
      () => logCapabilityFrictionTool.handler(baseFrictionArgs(domain, {
        friction_kind: "tool_inadequate",
        inadequacy_mode: "body_truncated",
        inadequate_invocation_ref: witnessRef,
        wanted_tool: "bob_http_scan",
      })),
      /does not match wanted_tool/,
    );
  });
});

test("tool_inadequate witness pointing at a MISSING event_id is REJECTED end-to-end", () => {
  withTempHome(() => {
    const domain = "friction-witness-missing.example.com";
    ensureSessionDir(domain);
    assert.throws(
      () => logCapabilityFrictionTool.handler(baseFrictionArgs(domain, {
        friction_kind: "tool_inadequate",
        inadequacy_mode: "body_truncated",
        inadequate_invocation_ref: "frontier_event:FE-does-not-exist",
      })),
      /not found in session frontier events/,
    );
  });
});

// ── bob_log_protocol_drift idempotency ──────────────────────────────────────

test("protocol drift APPENDS an observation.recorded event with payload.observation_kind set", () => {
  withTempHome(() => {
    const domain = "drift-append.example.com";
    ensureSessionDir(domain);
    const response = JSON.parse(logProtocolDriftTool.handler(baseDriftArgs(domain, {
      skill_path: "prompts/roles/verifier.md",
      details: { tool: "bob_repo_check", session_mode: "web" },
    })));
    assert.equal(response.appended, true);
    assert.equal(response.observation_kind, "protocol_drift_observed");

    const ledger = driftPayloadsFromLedger(domain);
    assert.equal(ledger.length, 1);
    const [{ payload }] = ledger;
    assert.equal(payload.drift_signature, "wrong_mode_tool_call");
    assert.equal(payload.skill_path, "prompts/roles/verifier.md");
    assert.deepEqual(payload.details, { tool: "bob_repo_check", session_mode: "web" });
  });
});

test("drift idempotency on (run_id, skill_path, drift_signature) silently de-dupes", () => {
  withTempHome(() => {
    const domain = "drift-idempotent.example.com";
    ensureSessionDir(domain);
    const first = JSON.parse(logProtocolDriftTool.handler(baseDriftArgs(domain, {
      skill_path: "prompts/roles/verifier.md",
    })));
    const second = JSON.parse(logProtocolDriftTool.handler(baseDriftArgs(domain, {
      skill_path: "prompts/roles/verifier.md",
      rationale: "Different rationale — same triple → idempotent.",
    })));
    assert.equal(first.appended, true);
    assert.equal(second.appended, false);
    assert.equal(second.idempotent, true);
    assert.equal(second.event_id, first.event_id);
    assert.equal(driftPayloadsFromLedger(domain).length, 1);
  });
});

test("drift idempotency: same drift_signature on DIFFERENT skill_path appends TWO events", () => {
  withTempHome(() => {
    const domain = "drift-distinct-skill.example.com";
    ensureSessionDir(domain);
    const a = JSON.parse(logProtocolDriftTool.handler(baseDriftArgs(domain, {
      skill_path: "prompts/roles/verifier.md",
    })));
    const b = JSON.parse(logProtocolDriftTool.handler(baseDriftArgs(domain, {
      skill_path: "prompts/roles/evaluator.md",
    })));
    assert.equal(a.appended, true);
    assert.equal(b.appended, true);
    assert.notEqual(a.event_id, b.event_id);
    assert.equal(driftPayloadsFromLedger(domain).length, 2);
  });
});

test("drift idempotency: runtime-emit (no skill_path) collapses onto <runtime> sentinel", () => {
  withTempHome(() => {
    const domain = "drift-runtime-sentinel.example.com";
    ensureSessionDir(domain);

    // Two runtime-emit calls (no skill_path) with the same drift_signature
    // and run_id must de-dupe to a single event under the sentinel.
    const a = JSON.parse(logProtocolDriftTool.handler(baseDriftArgs(domain)));
    const b = JSON.parse(logProtocolDriftTool.handler(baseDriftArgs(domain, {
      rationale: "Second attempt; should de-dupe under <runtime>.",
    })));
    assert.equal(a.appended, true);
    assert.equal(b.appended, false);
    assert.equal(b.idempotent, true);

    // A third call with an explicit skill_path resolves to a DIFFERENT key
    // and appends a second event.
    const c = JSON.parse(logProtocolDriftTool.handler(baseDriftArgs(domain, {
      skill_path: "prompts/roles/verifier.md",
    })));
    assert.equal(c.appended, true);
    assert.notEqual(c.event_id, a.event_id);

    assert.equal(driftPayloadsFromLedger(domain).length, 2);
  });
});
