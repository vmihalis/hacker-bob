"use strict";

// CR-3 / I4 — bob_apply_wave_merge mechanizes the friction loop server-side.
//
// Closes the CLASS "friction loop fires only when an agent reads orchestrator
// prose". The PRIMARY test drives a real merge through applyWaveMerge (no
// orchestrator, no prose) and asserts the promotion + the result block. The
// remaining tests pin the invariants at the helper boundary.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  attackSurfacePath,
  sessionDir,
} = require("../mcp/lib/paths.js");
const {
  settleAgentRunFromHandoff,
} = require("../mcp/lib/agent-runs.js");
const {
  loadWaveArtifacts,
} = require("../mcp/lib/wave-handoff-store.js");
const {
  startWave,
  applyWaveMerge,
  writeWaveHandoff,
} = require("../mcp/lib/waves.js");
const {
  initSession,
  advanceSession,
} = require("../mcp/lib/session-state.js");
const {
  writeFileAtomic,
} = require("../mcp/lib/storage.js");

const {
  mechanizeWaveFriction,
  frictionIdempotencyKey,
  forwardFrictionSynthetics,
  buildScannerList,
  SERVER_WITNESSABLE_SCANNER_KINDS,
} = require("../mcp/lib/friction-mechanization.js");
const logCapabilityFrictionTool = require("../mcp/lib/tools/log-capability-friction.js");
const { readFrontierEvents } = require("../mcp/lib/frontier-events.js");
const { writeQueuePolicy } = require("../mcp/lib/queue-policy.js");
const { DEFAULT_SCANNERS, SYNTHESIZERS } = require("../mcp/lib/friction-scanners.js");
const { loadWaveAssignments } = require("../mcp/lib/assignments.js");
const { readHandoffSigningKey } = require("../mcp/lib/handoff-signing-key.js");

void frictionIdempotencyKey;

// seedAttackSurfaces is a LOCAL helper in test/agent-run-merge-gate.test.js:57
// (NOT an importable module) — body copied verbatim.
function seedAttackSurfaces(domain, surfaces) {
  writeFileAtomic(attackSurfacePath(domain), `${JSON.stringify({ surfaces }, null, 2)}\n`);
}

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-t6-friction-"));
  process.env.HOME = home;
  try { return fn(home); }
  finally { process.env.HOME = previousHome; fs.rmSync(home, { recursive: true, force: true }); }
}

function ensureSession(domain) { fs.mkdirSync(sessionDir(domain), { recursive: true }); }

// Append N tool_absent voluntary frictions for distinct runs so a (wanted_tool,
// surface_id) group reaches threshold. Uses the real log tool so the events are
// shaped exactly as the server reads them.
function seedAbsentGroup(domain, wantedTool, surfaceId, count) {
  for (let i = 0; i < count; i += 1) {
    logCapabilityFrictionTool.handler({
      target_domain: domain,
      run_id: `run-${i}`,
      node_id: `N-${i}`,
      wanted_tool: wantedTool,
      purpose: "http_probe",
      fallback_used: "bash_curl",
      friction_kind: "tool_absent",
      detected_by: "agent_self_report",
      rationale: "Pack omitted the tool; reached for curl.",
      surface_id: surfaceId,
    });
  }
}

function hypothesisProposals(domain, surfaceId) {
  return readFrontierEvents(domain).filter((e) =>
    e && e.kind === "observation.recorded"
    && e.payload && e.payload.kind === "hypothesis_proposed"
    && e.payload.suggested_contract
    && e.payload.suggested_contract.promotion_marker
    && e.payload.suggested_contract.promotion_marker.friction_kind === "tool_absent"
    && e.payload.suggested_contract.promotion_marker.surface_id === surfaceId);
}

// ── PRIMARY: end-to-end through applyWaveMerge (closes F1 + F5) ──────────────
test("CR-3 E2E: a real merge auto-proposes a tool_absent group with NO agent action", () => {
  withTempHome(() => {
    const domain = "t6-e2e.example.com";
    const surfaceId = "surface-a";

    JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));
    seedAttackSurfaces(domain, [{ id: surfaceId, hosts: [`https://${domain}`], priority: "HIGH" }]);
    JSON.parse(advanceSession({ target_domain: domain, to_state: "OPEN_FRONTIER" }));
    writeQueuePolicy(domain, { friction_promotion_threshold: 2 });

    // Seed a tool_absent group at threshold (run coords are irrelevant to the
    // promotion grouping: it groups by wanted_tool/surface_id).
    seedAbsentGroup(domain, "bob_http_scan", surfaceId, 2);

    const start = JSON.parse(startWave({
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: surfaceId }],
    }));
    const handoffToken = start.assignments[0].handoff_token;

    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: surfaceId,
      surface_status: "complete",
      handoff_token: handoffToken,
      summary: "surface fully covered",
      chain_notes: ["nothing else worth pivoting to"],
      content: "# Handoff\n\nFinal handoff body",
    });

    // Settle through the merge gate exactly as the SubagentStop hook does.
    const assignments = loadWaveAssignments(domain, 1);
    const assignment = assignments.assignmentByAgent.get("a1");
    const handoffJson = JSON.parse(fs.readFileSync(path.join(sessionDir(domain), "handoff-w1-a1.json"), "utf8"));
    settleAgentRunFromHandoff({
      target_domain: domain, wave: "w1", agent: "a1", surface_id: surfaceId,
      assignment, handoff: handoffJson, signing_key: readHandoffSigningKey(domain),
    }, { write: true });

    const before = hypothesisProposals(domain, surfaceId);
    assert.equal(before.length, 0, "precondition: no promotion before the merge");

    // THE merge — no bob_propose_friction_promotion / bob_scan_transcript_for_friction
    // is called anywhere in this test body.
    const merge = JSON.parse(applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }));
    assert.equal(merge.status, "merged");

    // F5: the mechanization ran and did NOT swallow a bug.
    assert.ok(merge.friction_mechanization, "friction_mechanization block present");
    assert.ok(!merge.friction_mechanization.error,
      `friction_mechanization must be non-error, got ${JSON.stringify(merge.friction_mechanization)}`);
    assert.equal(merge.friction_mechanization.promotions_proposed, 1,
      "the merge auto-proposed exactly one tool_absent group");

    // F1: a hypothesis_proposed event exists purely because the SERVER merged —
    // no agent in the loop. Deleting the mechanizeWaveFriction call site fails here
    // (the load-bearing CR-3 invariant). run_contexts is NOT exercised by this
    // assertion: the promotion path reads frontier events directly, while
    // run_contexts only feeds the advisory handoff_ledger_diff scanner.
    const after = hypothesisProposals(domain, surfaceId);
    assert.equal(after.length, 1, "a hypothesis_proposed event fired with NO agent call");
  });
});

// ── Y-P11: server never auto-promotes tool_inadequate ───────────────────────
test("Y-P11: server NEVER auto-promotes tool_inadequate", () => {
  withTempHome(() => {
    const domain = "t6-inadequate.example.com";
    ensureSession(domain);
    writeQueuePolicy(domain, { friction_promotion_threshold: 2 });

    const { appendFrontierEvent } = require("../mcp/lib/frontier-events.js");
    for (let i = 0; i < 2; i += 1) {
      const witness = appendFrontierEvent({
        target_domain: domain,
        kind: "observation.recorded",
        payload: { observation_kind: "mcp_invocation_recorded", run_id: `run-${i}`, tool: "bob_resolve_body", outcome: "error" },
        source: { artifact: "frontier-events.jsonl", tool: "test" },
      });
      logCapabilityFrictionTool.handler({
        target_domain: domain, run_id: `run-${i}`, node_id: `N-${i}`,
        wanted_tool: "bob_resolve_body", purpose: "body_resolve", fallback_used: "none",
        friction_kind: "tool_inadequate", inadequacy_mode: "output_format_unsuitable",
        inadequate_invocation_ref: `frontier_event:${witness.event_id}`,
        detected_by: "agent_self_report", rationale: "Tool returned an unusable body shape.",
        surface_id: "surface:api",
      });
    }

    const result = mechanizeWaveFriction(domain, []);
    assert.equal(result.promotions_proposed, 0, "tool_inadequate is operator-gated; server proposes nothing");
    const inadequate = readFrontierEvents(domain).filter((e) =>
      e && e.payload && e.payload.kind === "hypothesis_proposed"
      && e.payload.suggested_contract && e.payload.suggested_contract.promotion_marker
      && e.payload.suggested_contract.promotion_marker.friction_kind === "tool_inadequate");
    assert.equal(inadequate.length, 0, "no tool_inadequate hypothesis created server-side");
  });
});

// ── Y-P3 (per-detected_by): a synthetic and a verbatim re-forward collapse;
//    a voluntary report COEXISTS (intentional) ────────────────────────────────
test("Y-P3 per-detected_by: verbatim re-forward collapses; voluntary report coexists", () => {
  withTempHome(() => {
    const domain = "t6-idem.example.com";
    ensureSession(domain);

    const synthetic = {
      kind: "friction",
      scanner: "large_response_body_unimported",
      payload: {
        target_domain: domain, run_id: "run-X", node_id: "N-X",
        wanted_tool: "bob_import_http_traffic", purpose: "evidence_pull",
        fallback_used: "bash_other", friction_kind: "tool_absent",
        detected_by: "adversarial_transcript_scan", surface_id: "surface:evidence",
        rationale: "synthetic — oversized evidence body with no binding handle.",
      },
    };

    const first = forwardFrictionSynthetics(domain, [synthetic]);
    assert.equal(first.length, 1, "first forward appends one synthetic");

    // Verbatim re-forward (same detected_by) — Y-P3 collapse.
    const second = forwardFrictionSynthetics(domain, [synthetic]);
    assert.equal(second.length, 0, "verbatim re-forward de-dupes — no double-fire");

    // An explicit log with the SAME 5-tuple (same detected_by) is also a no-op.
    const sameKind = JSON.parse(logCapabilityFrictionTool.handler({
      target_domain: domain, run_id: "run-X", node_id: "N-X",
      wanted_tool: "bob_import_http_traffic", purpose: "evidence_pull",
      fallback_used: "bash_other", friction_kind: "tool_absent",
      detected_by: "adversarial_transcript_scan",
      rationale: "re-report of the same synthetic", surface_id: "surface:evidence",
    }));
    assert.equal(sameKind.appended, false);
    assert.equal(sameKind.idempotent, true);

    // A VOLUNTARY report (different detected_by) for the same logical friction
    // COEXISTS by design (Y-P11) — it is NOT a double-fire and must persist.
    const voluntary = JSON.parse(logCapabilityFrictionTool.handler({
      target_domain: domain, run_id: "run-X", node_id: "N-X",
      wanted_tool: "bob_import_http_traffic", purpose: "evidence_pull",
      fallback_used: "bash_other", friction_kind: "tool_absent",
      detected_by: "agent_self_report",
      rationale: "agent independently noticed the same gap", surface_id: "surface:evidence",
    }));
    assert.equal(voluntary.appended, true, "voluntary report with distinct detected_by coexists (Y-P11)");

    const frictionEvents = readFrontierEvents(domain).filter((e) =>
      e && e.payload && e.payload.observation_kind === "capability_friction_observed"
      && e.payload.run_id === "run-X" && e.payload.wanted_tool === "bob_import_http_traffic");
    assert.equal(frictionEvents.length, 2,
      "exactly two events: one synthetic + one voluntary (distinct detected_by, intentional coexistence)");
  });
});

// ── Y-P6: a second merge does not double-propose the same tool_absent group ──
test("Y-P6: a second merge does not double-propose the same tool_absent group", () => {
  withTempHome(() => {
    const domain = "t6-remerge.example.com";
    ensureSession(domain);
    writeQueuePolicy(domain, { friction_promotion_threshold: 2 });
    seedAbsentGroup(domain, "bob_http_scan", "surface:s1", 2);

    const r1 = mechanizeWaveFriction(domain, []);
    assert.equal(r1.promotions_proposed, 1);

    const r2 = mechanizeWaveFriction(domain, []);
    assert.equal(r2.promotions_proposed, 0, "re-merge re-proposes nothing");
    assert.ok(r2.promotions.some((p) => p.idempotent === true), "re-merge short-circuits idempotent (Y-P6)");
    assert.equal(hypothesisProposals(domain, "surface:s1").length, 1, "still exactly one hypothesis after two merges");
  });
});

// ── SERVER_WITNESSABLE_SCANNER_KINDS closure (closes F4 / R5) ────────────────
test("closure: every server-witnessable kind is reachable, and no invocation-needing kind leaks in", () => {
  // 1) Every kind declared witnessable is actually a real DEFAULT_SCANNERS kind
  //    and is reachable via buildScannerList (no orphan allow-list entry).
  const defaultKinds = new Set(DEFAULT_SCANNERS.map((s) => s.kind));
  for (const kind of SERVER_WITNESSABLE_SCANNER_KINDS) {
    assert.ok(defaultKinds.has(kind), `witnessable kind ${kind} must exist in DEFAULT_SCANNERS`);
  }
  const reachableKinds = new Set(buildScannerList([]).map((s) => s.kind));
  for (const kind of SERVER_WITNESSABLE_SCANNER_KINDS) {
    assert.ok(reachableKinds.has(kind), `witnessable kind ${kind} must be reachable via buildScannerList`);
  }
  assert.deepEqual(reachableKinds, new Set(SERVER_WITNESSABLE_SCANNER_KINDS),
    "buildScannerList must return exactly the witnessable kinds for the default scanner set");

  // 2) Tripwire: any NEW DEFAULT_SCANNERS kind forces a conscious decision —
  //    it must be classified as either a synthesizer-only kind that is KNOWN to
  //    need a transcript/invocation stream, OR added to the witnessable set.
  //    The invocation/transcript-requiring kinds are explicitly NOT witnessable.
  const INVOCATION_OR_TRANSCRIPT_REQUIRING = new Set([
    "regex", "regex_with_context", "invocation_failure",
    "evidence_size", "handoff_invocation_diff",
  ]);
  for (const kind of defaultKinds) {
    const classified = SERVER_WITNESSABLE_SCANNER_KINDS.has(kind)
      || INVOCATION_OR_TRANSCRIPT_REQUIRING.has(kind);
    assert.ok(classified,
      `DEFAULT_SCANNERS kind "${kind}" is unclassified: add it to SERVER_WITNESSABLE_SCANNER_KINDS `
      + "(if it needs no transcript/invocation stream at merge time) or to the "
      + "INVOCATION_OR_TRANSCRIPT_REQUIRING exclusion in this test, with cause.");
  }
  // And every synthesizer key the registry exposes is one of those two buckets.
  for (const kind of Object.keys(SYNTHESIZERS)) {
    assert.ok(SERVER_WITNESSABLE_SCANNER_KINDS.has(kind) || INVOCATION_OR_TRANSCRIPT_REQUIRING.has(kind),
      `SYNTHESIZERS key "${kind}" must be classified witnessable or invocation/transcript-requiring`);
  }
});
