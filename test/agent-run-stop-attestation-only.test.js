"use strict";

// NS-7 live SubagentStop coverage: an evaluator-fanout child is accepted only
// when its host-owned spawn transcript, MCP-issued cell identity, and terminal
// coverage agree. Acceptance must not settle or terminally mutate the shared
// wave-root AgentRun. A root marker always wins over an echoed child marker.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const HOOK = path.join(ROOT, ".claude", "hooks", "agent-run-stop.js");

const { attackSurfacePath, pipelineEventsJsonlPath, sessionDir } = require("../mcp/core/io/paths.js");
const { writeFileAtomic } = require("../mcp/core/io/storage.js");
const { initSession, advanceSession } = require("../mcp/core/session/session-state.js");
const { startWave } = require("../mcp/core/waves/waves.js");
const { DEFAULT_QUEUE_POLICY, normalizeQueuePolicy, writeQueuePolicy } = require("../mcp/core/io/queue-policy.js");
const { buildChildFanoutPlanForSurface } = require("../mcp/core/session/assignment-brief.js");
const { logCoverage } = require("../mcp/core/frontier/coverage.js");
const { readAgentRuns } = require("../mcp/core/session/agent-runs.js");
const { toolInvocationTelemetryPath } = require("../mcp/core/telemetry/tool-telemetry.js");
const { FANOUT_ROLE_REGISTRY } = require("../mcp/core/session/nested-spawn.js");

function readJsonl(file) {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, "utf8").split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
}

function withClaudeHome(fn) {
  const previousHome = process.env.HOME;
  const previousClient = process.env.BOB_CLIENT;
  const previousAgentTeams = process.env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-child-stop-"));
  process.env.HOME = home;
  process.env.BOB_CLIENT = "claude";
  process.env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS = "1";
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME; else process.env.HOME = previousHome;
    if (previousClient === undefined) delete process.env.BOB_CLIENT; else process.env.BOB_CLIENT = previousClient;
    if (previousAgentTeams === undefined) {
      delete process.env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS;
    } else {
      process.env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS = previousAgentTeams;
    }
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function bootstrap(domain) {
  const surface = {
    id: "surface-api-users",
    uri: `https://${domain}/api/users/123`,
    hosts: [`https://${domain}`],
    priority: "HIGH",
    endpoints: ["/api/users/123"],
    interesting_params: ["id"],
    bug_class_hints: ["idor"],
    high_value_flows: ["user data lookup by object id"],
  };
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));
  writeFileAtomic(attackSurfacePath(domain), `${JSON.stringify({ surfaces: [surface] }, null, 2)}\n`);
  JSON.parse(advanceSession({ target_domain: domain, to_state: "OPEN_FRONTIER" }));
  writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, max_spawn_depth: 3 }));
  const started = JSON.parse(startWave({
    target_domain: domain,
    wave_number: 1,
    assignments: [{ agent: "a1", surface_id: surface.id }],
  }));
  assert.equal(started.assignments[0].evaluator_agent, "evaluator-fanout");
  const plan = buildChildFanoutPlanForSurface({
    domain,
    surfaceObj: surface,
    surfaceId: surface.id,
    coverageSummary: {},
    wave: "w1",
  });
  assert.ok(plan && plan.remaining_depth === 1);
  const child = plan.children.find((entry) => entry.bug_class === "idor");
  assert.ok(child && child.remaining_depth === 0);
  return { surface, child };
}

function markerFor(domain, child) {
  return {
    target_domain: domain,
    wave: "w1",
    agent: "a1",
    surface_id: child.surface_id,
    cell_key: child.cell_key,
    planning_key: child.planning_key,
    bug_class: child.bug_class,
    auth_profile: child.auth_profile || "",
    coverage_status: "tested",
  };
}

function spawnPrompt(marker, overrides = {}) {
  const values = { ...marker, ...overrides };
  return [
    "Nested child: true",
    `Domain: ${values.target_domain}`,
    `Wave: ${values.wave}`,
    `Agent: ${values.agent}`,
    `surface_id: ${values.surface_id}`,
    `cell_key: ${values.cell_key}`,
    `planning_key: ${values.planning_key}`,
    `bug_class: ${values.bug_class}`,
    `auth_profile: ${values.auth_profile || '\"\"'}`,
    `remaining_depth: ${values.remaining_depth == null ? 0 : values.remaining_depth}`,
  ].join("\n");
}

function writeTranscript(home, prompt) {
  const transcript = path.join(home, `child-${Math.random().toString(16).slice(2)}.jsonl`);
  fs.writeFileSync(transcript, `${JSON.stringify({ message: { role: "user", content: prompt } })}\n`, "utf8");
  return transcript;
}

function runHook(home, message, prompt, { agentType = FANOUT_ROLE_REGISTRY.child.subagent_type } = {}) {
  const transcript = writeTranscript(home, prompt);
  return spawnSync(process.execPath, [HOOK], {
    input: JSON.stringify({
      last_assistant_message: message,
      agent_transcript_path: transcript,
      agent_type: agentType,
    }),
    encoding: "utf8",
    env: {
      ...process.env,
      HOME: home,
      BOB_CLIENT: "claude",
      BOB_PROJECT_DIR: ROOT,
      CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS: "1",
    },
  });
}

function rootPrompt(marker) {
  return [
    `Domain: ${marker.target_domain}`,
    `Wave: ${marker.wave}`,
    `Agent: ${marker.agent}`,
    `Handoff token: ${"a".repeat(64)}`,
    "First action: call bob_read_assignment_brief for this wave root.",
  ].join("\n");
}

function runPreToolHook(home, toolName, prompt, {
  agentType = FANOUT_ROLE_REGISTRY.child.subagent_type,
  toolInput = {},
} = {}) {
  const transcript = writeTranscript(home, prompt);
  return spawnSync(process.execPath, [HOOK], {
    input: JSON.stringify({
      hook_event_name: "PreToolUse",
      tool_name: toolName,
      tool_input: toolInput,
      agent_type: agentType,
      agent_id: "agent-test",
      transcript_path: transcript,
    }),
    encoding: "utf8",
    env: {
      ...process.env,
      HOME: home,
      BOB_CLIENT: "claude",
      BOB_PROJECT_DIR: ROOT,
      CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS: "1",
    },
  });
}

function preToolDeniedReason(result) {
  assert.equal(result.status, 0, `PreToolUse denial must use the documented stdout decision: ${result.stderr}`);
  const payload = JSON.parse(result.stdout.trim());
  assert.equal(payload.hookSpecificOutput.hookEventName, "PreToolUse");
  assert.equal(payload.hookSpecificOutput.permissionDecision, "deny");
  assert.equal(typeof payload.hookSpecificOutput.permissionDecisionReason, "string");
  return payload.hookSpecificOutput.permissionDecisionReason;
}

function recordTerminalCoverage(domain, child) {
  JSON.parse(logCoverage({
    target_domain: domain,
    wave: "w1",
    agent: "a1",
    surface_id: child.surface_id,
    entries: [{
      endpoint: "/api/users/123",
      method: "GET",
      bug_class: child.bug_class,
      auth_profile: child.auth_profile || undefined,
      status: "tested",
      evidence_summary: "Anonymous object-id probe completed with a terminal authorization differential.",
    }],
  }));
}

test("NS-7: a transcript-bound issued child with terminal coverage exits cleanly without settling the root", () => {
  withClaudeHome((home) => {
    const domain = "child-stop-valid.example.com";
    const { child } = bootstrap(domain);
    recordTerminalCoverage(domain, child);
    const marker = markerFor(domain, child);
    const runsBefore = readAgentRuns(domain);
    const stoppedBefore = readJsonl(pipelineEventsJsonlPath(domain))
      .filter((row) => row.type === "evaluator_stopped").length;

    const result = runHook(
      home,
      `cell complete\nBOB_CHILD_CELL_DONE ${JSON.stringify(marker)}`,
      spawnPrompt(marker),
    );

    assert.equal(result.status, 0, `stdout=${result.stdout}\nstderr=${result.stderr}`);
    assert.match(result.stdout, /Nested child cell/);
    assert.deepEqual(readAgentRuns(domain), runsBefore, "child stop must not mutate the shared wave AgentRun");
    const childTelemetry = readJsonl(toolInvocationTelemetryPath(process.env))
      .filter((row) => row.run_type === "fanout_child" && row.target_domain === domain);
    assert.equal(childTelemetry.length, 1, "accepted child writes one distinct fanout_child telemetry row");
    assert.equal(childTelemetry[0].status, "allowed");
    const stoppedAfter = readJsonl(pipelineEventsJsonlPath(domain))
      .filter((row) => row.type === "evaluator_stopped").length;
    assert.equal(stoppedAfter, stoppedBefore, "child completion must not emit the root evaluator_stopped event");
    assert.equal(
      fs.existsSync(path.join(sessionDir(domain), "handoff-w1-a1.json")),
      false,
      "child acceptance must not synthesize the root handoff",
    );
  });
});
test("NS-7: an issued transcript-bound child without terminal coverage is blocked without mutating the root", () => {
  withClaudeHome((home) => {
    const domain = "child-stop-no-coverage.example.com";
    const { child } = bootstrap(domain);
    const marker = markerFor(domain, child);
    const runsBefore = readAgentRuns(domain);

    const result = runHook(
      home,
      `BOB_CHILD_CELL_DONE ${JSON.stringify(marker)}`,
      spawnPrompt(marker),
    );

    assert.equal(result.status, 2, `stdout=${result.stdout}\nstderr=${result.stderr}`);
    assert.match(result.stderr, /no terminal current-run coverage/i);
    assert.deepEqual(readAgentRuns(domain), runsBefore, "coverage failure must not fail or settle the root");
  });
});

test("NS-7: a valid marker from the wrong child transcript is blocked without mutating the root", () => {
  withClaudeHome((home) => {
    const domain = "child-stop-context.example.com";
    const { child } = bootstrap(domain);
    recordTerminalCoverage(domain, child);
    const marker = markerFor(domain, child);
    const runsBefore = readAgentRuns(domain);

    const result = runHook(
      home,
      `BOB_CHILD_CELL_DONE ${JSON.stringify(marker)}`,
      spawnPrompt(marker, { planning_key: '["ssrf",""]' }),
    );

    assert.equal(result.status, 2, `stdout=${result.stdout}\nstderr=${result.stderr}`);
    assert.match(result.stderr, /spawn context/i);
    assert.deepEqual(readAgentRuns(domain), runsBefore, "rejected child stop must not fail or settle the root");
  });
});

test("NS-7: malformed child marker remediation never delegates root-owned settlement", () => {
  withClaudeHome((home) => {
    const domain = "child-stop-malformed.example.com";
    const { child } = bootstrap(domain);
    const marker = markerFor(domain, child);
    const runsBefore = readAgentRuns(domain);

    const result = runHook(
      home,
      'BOB_CHILD_CELL_DONE {"target_domain":}',
      spawnPrompt(marker),
    );

    assert.equal(result.status, 2, `stdout=${result.stdout}\nstderr=${result.stderr}`);
    assert.match(result.stderr, /re-emit valid BOB_CHILD_CELL_DONE/);
    assert.match(result.stderr, /Do not write a wave handoff/);
    assert.match(result.stderr, /do not .*bob_finalize_agent_run/i);
    assert.doesNotMatch(result.stderr, /write the wave handoff with bob_write_wave_handoff/i);
    assert.deepEqual(readAgentRuns(domain), runsBefore, "malformed child stop must not fail or settle the root");
  });
});

test("NS-7: missing child marker remediation never delegates root-owned settlement", () => {
  withClaudeHome((home) => {
    const domain = "child-stop-missing.example.com";
    const { child } = bootstrap(domain);
    const marker = markerFor(domain, child);
    const runsBefore = readAgentRuns(domain);

    const result = runHook(
      home,
      "Cell work is complete, but the marker was omitted.",
      spawnPrompt(marker),
    );

    assert.equal(result.status, 2, `stdout=${result.stdout}\nstderr=${result.stderr}`);
    assert.match(result.stderr, /emit BOB_CHILD_CELL_DONE/);
    assert.match(result.stderr, /Do not write a wave handoff/);
    assert.match(result.stderr, /do not .*bob_finalize_agent_run/i);
    assert.doesNotMatch(result.stderr, /write the wave handoff with bob_write_wave_handoff/i);
    assert.deepEqual(readAgentRuns(domain), runsBefore, "missing child stop must not fail or settle the root");
  });
});

test("NS-7: malformed child text in a root context keeps root-owned remediation", () => {
  withClaudeHome((home) => {
    const domain = "child-stop-root-malformed-echo.example.com";
    const { child } = bootstrap(domain);
    const marker = markerFor(domain, child);

    const result = runHook(
      home,
      'absorbed child text: BOB_CHILD_CELL_DONE {"target_domain":}',
      spawnPrompt(marker).replace("Nested child: true", "Wave root: true"),
      { agentType: FANOUT_ROLE_REGISTRY.root.subagent_type },
    );

    assert.equal(result.status, 2, `stdout=${result.stdout}\nstderr=${result.stderr}`);
    assert.match(result.stderr, /write the wave handoff with bob_write_wave_handoff/i);
    assert.doesNotMatch(result.stderr, /Nested child stop blocked/);
  });
});

test("NS-7: a root marker from nested child context cannot mutate the shared root run", () => {
  withClaudeHome((home) => {
    const domain = "child-stop-forbidden-root-marker.example.com";
    const { child } = bootstrap(domain);
    const childMarker = markerFor(domain, child);
    const rootMarker = {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: child.surface_id,
    };
    const runsBefore = readAgentRuns(domain);

    const result = runHook(
      home,
      `BOB_AGENT_RUN_DONE ${JSON.stringify(rootMarker)}`,
      spawnPrompt(childMarker),
    );

    assert.equal(result.status, 2, `stdout=${result.stdout}\nstderr=${result.stderr}`);
    assert.match(result.stderr, /Nested child must not emit BOB_AGENT_RUN_DONE/);
    assert.match(result.stderr, /emit only BOB_CHILD_CELL_DONE/);
    assert.deepEqual(readAgentRuns(domain), runsBefore, "child root-marker error must not fail or settle the root");
  });
});

test("NS-7: a root marker wins when root final text also echoes a valid child marker", () => {
  withClaudeHome((home) => {
    const domain = "child-stop-root-priority.example.com";
    const { child } = bootstrap(domain);
    recordTerminalCoverage(domain, child);
    const childMarker = markerFor(domain, child);
    const rootMarker = {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: child.surface_id,
    };
    const result = runHook(
      home,
      [
        `absorbed pointer: BOB_CHILD_CELL_DONE ${JSON.stringify(childMarker)}`,
        `BOB_AGENT_RUN_DONE ${JSON.stringify(rootMarker)}`,
      ].join("\n"),
      spawnPrompt(childMarker).replace("Nested child: true", "Wave root: true"),
      { agentType: FANOUT_ROLE_REGISTRY.root.subagent_type },
    );

    assert.equal(result.status, 2, "root marker must take the normal finalize gate, not the child escape path");
    assert.doesNotMatch(result.stdout, /Nested child cell/);
    assert.ok(readAgentRuns(domain).some((row) => row.agent_id === "a1" && row.status === "failed"));
  });
});

test("NS-7: PreToolUse denies child spawn/settlement tools and preserves the wave root", () => {
  withClaudeHome((home) => {
    const domain = "child-pretool-boundary.example.com";
    const { child } = bootstrap(domain);
    const marker = markerFor(domain, child);
    const runsBefore = readAgentRuns(domain);
    const forbiddenTools = [
      "Agent",
      "Task",
      "mcp__hacker-bob__bob_write_wave_handoff",
      "mcp__hacker-bob__bob_finalize_agent_run",
    ];

    for (const toolName of forbiddenTools) {
      const denied = runPreToolHook(home, toolName, spawnPrompt(marker));
      assert.match(preToolDeniedReason(denied), /Nested evaluator-fanout-child cannot call root-owned tool/);
    }
    const safe = runPreToolHook(home, "mcp__hacker-bob__bob_log_coverage", spawnPrompt(marker));
    assert.equal(safe.status, 0, "child durable-coverage tools remain available");
    assert.deepEqual(readAgentRuns(domain), runsBefore, "PreToolUse denials must not mutate the shared AgentRun");
  });
});

test("NS-7: PreToolUse permits attested root tools and denies unreadable fanout scope", () => {
  withClaudeHome((home) => {
    const domain = "root-pretool-boundary.example.com";
    const { child } = bootstrap(domain);
    const marker = markerFor(domain, child);
    for (const toolName of ["mcp__hacker-bob__bob_write_wave_handoff", "mcp__hacker-bob__bob_finalize_agent_run"]) {
      const allowed = runPreToolHook(home, toolName, rootPrompt(marker), {
        agentType: FANOUT_ROLE_REGISTRY.root.subagent_type,
      });
      assert.equal(allowed.status, 0, `${toolName} remains available to the attested wave root`);
    }
    const allowedChild = runPreToolHook(home, "Agent", rootPrompt(marker), {
      agentType: FANOUT_ROLE_REGISTRY.root.subagent_type,
      toolInput: {
        subagent_type: FANOUT_ROLE_REGISTRY.child.subagent_type,
        run_in_background: false,
        prompt: spawnPrompt(marker),
      },
    });
    assert.equal(allowedChild.status, 0, "root may spawn the exact anonymous synchronous child role");
    const unknown = runPreToolHook(home, "mcp__hacker-bob__bob_finalize_agent_run", "unrecognized prompt", {
      agentType: FANOUT_ROLE_REGISTRY.root.subagent_type,
    });
    assert.match(preToolDeniedReason(unknown), /scope could not be attested/);
  });
});

test("NS-7: PreToolUse denies foreign, named, and background root fanout calls", () => {
  withClaudeHome((home) => {
    const domain = "root-pretool-shape.example.com";
    const { child } = bootstrap(domain);
    const marker = markerFor(domain, child);
    const root = rootPrompt(marker);
    const invalid = [
      [{}, /only evaluator-fanout-child/],
      [{ subagent_type: "evaluator-agent" }, /only evaluator-fanout-child/],
      [{ subagent_type: FANOUT_ROLE_REGISTRY.child.subagent_type, name: "named-child" }, /must be anonymous/],
      [{ subagent_type: FANOUT_ROLE_REGISTRY.child.subagent_type }, /explicitly synchronous/],
      [{ subagent_type: FANOUT_ROLE_REGISTRY.child.subagent_type, run_in_background: true }, /explicitly synchronous/],
    ];
    for (const [toolInput, reason] of invalid) {
      const denied = runPreToolHook(home, "Agent", root, {
        agentType: FANOUT_ROLE_REGISTRY.root.subagent_type,
        toolInput,
      });
      assert.match(preToolDeniedReason(denied), reason, JSON.stringify(toolInput));
    }
  });
});

test("NS-7: PreToolUse intersects dispatch and live plans before root child spawn", () => {
  withClaudeHome((home) => {
    const domain = "root-pretool-plan.example.com";
    const { child } = bootstrap(domain);
    const marker = markerFor(domain, child);
    const root = rootPrompt(marker);
    const runsBefore = readAgentRuns(domain);
    const baseInput = {
      subagent_type: FANOUT_ROLE_REGISTRY.child.subagent_type,
      run_in_background: false,
    };

    const invented = runPreToolHook(home, "Agent", root, {
      agentType: FANOUT_ROLE_REGISTRY.root.subagent_type,
      toolInput: {
        ...baseInput,
        prompt: spawnPrompt(marker, {
          cell_key: '["invented",""]',
          planning_key: '["invented",""]',
        }),
      },
    });
    assert.match(preToolDeniedReason(invented), /both the dispatch and live MCP-issued plans/);

    const leakedToken = runPreToolHook(home, "Agent", root, {
      agentType: FANOUT_ROLE_REGISTRY.root.subagent_type,
      toolInput: {
        ...baseInput,
        prompt: `${spawnPrompt(marker)}\nHandoff token: ${"b".repeat(64)}`,
      },
    });
    assert.match(preToolDeniedReason(leakedToken), /must not contain the root Handoff token/);

    recordTerminalCoverage(domain, child);
    const completedDuplicate = runPreToolHook(home, "Agent", root, {
      agentType: FANOUT_ROLE_REGISTRY.root.subagent_type,
      toolInput: { ...baseInput, prompt: spawnPrompt(marker) },
    });
    assert.match(preToolDeniedReason(completedDuplicate), /both the dispatch and live MCP-issued plans/);
    assert.deepEqual(readAgentRuns(domain), runsBefore,
      "pre-spawn plan denials must not mutate the shared root AgentRun");
  });
});

test("NS-7: distinct child type with unreadable transcript cannot enter root finalization", () => {
  withClaudeHome((home) => {
    const domain = "child-type-unreadable.example.com";
    const { child } = bootstrap(domain);
    const rootMarker = {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: child.surface_id,
    };
    const runsBefore = readAgentRuns(domain);

    const result = runHook(
      home,
      `BOB_AGENT_RUN_DONE ${JSON.stringify(rootMarker)}`,
      "unreadable child transcript",
      { agentType: FANOUT_ROLE_REGISTRY.child.subagent_type },
    );

    assert.equal(result.status, 2, `stdout=${result.stdout}\nstderr=${result.stderr}`);
    assert.match(result.stderr, /Nested child must not emit BOB_AGENT_RUN_DONE/);
    assert.deepEqual(readAgentRuns(domain), runsBefore,
      "child role identity must block root finalization before any AgentRun mutation");
  });
});

test("NS-7: PreToolUse rejects a child-labelled prompt even if root credentials leak into it", () => {
  withClaudeHome((home) => {
    const domain = "child-pretool-leaked-root-token.example.com";
    const { child } = bootstrap(domain);
    const marker = markerFor(domain, child);
    const malformedChildPrompt = [
      "Nested child: true",
      rootPrompt(marker),
      // Deliberately omit remaining_depth to prove the independent child label
      // keeps leaked root credentials from satisfying root attestation.
    ].join("\n");

    const denied = runPreToolHook(
      home,
      "mcp__hacker-bob__bob_finalize_agent_run",
      malformedChildPrompt,
    );
    assert.match(preToolDeniedReason(denied), /scope could not be attested/);
  });
});

// The SubagentStop attestation hook settles only attested agent-run state. It
// must never become a producer for lifecycle, wave, finding, or frontier state.
test("the SubagentStop hook never advances lifecycle/wave/finding state or emits frontier events", () => {
  const source = fs.readFileSync(HOOK, "utf8");
  const forbidden = [
    "advanceSession",
    "appendFrontierEvent",
    "materializeFrontier",
    "writeSessionStateDocument",
    "appendCandidateClaim",
  ];
  for (const symbol of forbidden) {
    assert.equal(
      source.includes(symbol),
      false,
      `agent-run-stop is attestation-only; found a forbidden state-producing reference: ${symbol}`,
    );
  }
});
