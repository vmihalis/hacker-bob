"use strict";

// Plane Y Cycle Y.5 (rev 4 O5) — Wave brief target_class threading.
//
// Pact: when queue-policy carries `target_class_default: "phishing_fraud"`,
// the wave brief's derivation MUST UNION the four phishing auxiliaries
// (bob_public_intel + 3 browser tools) into allowed_tools_for_node[] via
// the pure deriveAuxiliaryToolsForTargetClass path. When the target_class
// is web_application the auxiliaries MUST NOT auto-include
// phishing-specific tools.
//
// Y-D9 (rev 4) introduces `target_class_default` on queue-policy. Y.6 lands
// the schema-side validator; until Y.6 ships the caller-side resolver in
// wave-brief-derivation.js falls back to plain assignment unless the field
// is set by writing the queue-policy JSON directly. This test seeds the
// policy file directly because the schema-side writer rejects the new field
// pre-Y.6 — once Y.6 lands the writer would also accept it.

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  attackSurfacePath,
  queuePolicyPath,
  sessionDir,
  statePath,
} = require("../mcp/lib/paths.js");
const {
  readAssignmentBrief,
  buildWaveBriefDerivation,
} = require("../mcp/lib/assignment-brief.js");
const {
  startWave,
} = require("../mcp/lib/waves.js");
const {
  writeFileAtomic,
} = require("../mcp/lib/storage.js");

const PHISHING_AUX_TOOLS = [
  "bob_public_intel",
  "bob_browser_evaluate",
  "bob_browser_take_screenshot",
  "bob_browser_console_messages",
];

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-y5-tc-"));
  process.env.HOME = tempHome;
  try {
    return fn(tempHome);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
}

function uniqueDomain(prefix) {
  return `${prefix}-${crypto.randomBytes(4).toString("hex")}.example`;
}

function seedSessionState(domain) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  writeFileAtomic(statePath(domain), `${JSON.stringify({
    target: domain,
    target_url: `https://${domain}`,
    deep_mode: false,
    phase: "EVALUATE",
    evaluation_wave: 0,
    pending_wave: null,
    total_findings: 0,
    explored: [],
    terminally_blocked: [],
    prereq_registry_snapshots: [],
    blocked_prereq_history: [],
    terminal_block_clear_history: [],
    dead_ends: [],
    waf_blocked_endpoints: [],
    lead_surface_ids: [],
    scope_exclusions: [],
    hold_count: 0,
    auth_status: "pending",
    operator_note: null,
    verification_schema_version: null,
    verification_attempt_id: null,
    verification_snapshot_hash: null,
  }, null, 2)}\n`);
}

function seedAttackSurface(domain, surfaces) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  writeFileAtomic(attackSurfacePath(domain), `${JSON.stringify({ surfaces }, null, 2)}\n`);
}

// Seed queue-policy directly — Y.5 reads it gracefully, Y.6 will land the
// schema-level validator and the bob_set_queue_policy writer for the new
// field. Writing the JSON file lets the Y.5 caller-side resolver see the
// value without depending on the (future) writer surface.
function seedQueuePolicyWithTargetClass(domain, targetClass) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  writeFileAtomic(queuePolicyPath(domain), `${JSON.stringify({
    version: 1,
    max_parallel_tasks: 4,
    priority_order: ["critical", "high", "medium", "low"],
    stale_after_ms: 86400000,
    close_blocked_on_freeze: false,
    standard_wave_target: 4,
    standard_wave_max: 6,
    deep_wave_target: 6,
    deep_wave_max: 8,
    default_wave_task_lens: "surface_scout",
    default_wave_task_budget: { max_steps: 6, max_context_tokens: 24000 },
    friction_scanners: [],
    target_class_default: targetClass,
  }, null, 2)}\n`);
}

function startSingleSurfaceWave(domain, surfaceId) {
  return JSON.parse(startWave({
    target_domain: domain,
    wave_number: 1,
    assignments: [{ agent: "a1", surface_id: surfaceId }],
  }));
}

test("target_class_default=phishing_fraud surfaces all four auxiliary tools in wave_brief_derivation.allowed_tools_for_node[] (O5)", () => {
  withTempHome(() => {
    const domain = uniqueDomain("y5-phish");
    const surfaceId = "phish-kit";
    seedSessionState(domain);
    seedAttackSurface(domain, [{
      id: surfaceId,
      surface_type: "api",
      hosts: [`https://kit.${domain}`],
      title: "Phishing kit landing",
      tech_stack: ["Express"],
      endpoints: ["/login", "/verify"],
    }]);
    seedQueuePolicyWithTargetClass(domain, "phishing_fraud");
    startSingleSurfaceWave(domain, surfaceId);

    const brief = JSON.parse(readAssignmentBrief({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      egress_profile: "default",
      block_internal_hosts: false,
    }));

    assert.ok(brief.wave_brief_derivation);
    assert.equal(brief.wave_brief_derivation.target_class, "phishing_fraud");

    const auxTools = brief.wave_brief_derivation.target_class_auxiliary_tools;
    const addedTools = brief.wave_brief_derivation.added_tools;
    for (const tool of PHISHING_AUX_TOOLS) {
      assert.ok(
        auxTools.includes(tool),
        `phishing_fraud target_class MUST surface ${tool} in target_class_auxiliary_tools[] (saw: ${auxTools.join(", ")})`,
      );
      assert.ok(
        addedTools.includes(tool),
        `phishing_fraud target_class MUST surface ${tool} in added_tools[] (saw: ${addedTools.join(", ")})`,
      );
    }
  });
});

test("target_class_default=web_application does NOT auto-include phishing-specific tools (O5)", () => {
  withTempHome(() => {
    const domain = uniqueDomain("y5-web");
    const surfaceId = "web-api";
    seedSessionState(domain);
    seedAttackSurface(domain, [{
      id: surfaceId,
      surface_type: "api",
      hosts: [`https://api.${domain}`],
      title: "Plain web API",
      tech_stack: ["Express"],
      endpoints: ["/api/users"],
    }]);
    seedQueuePolicyWithTargetClass(domain, "web_application");
    startSingleSurfaceWave(domain, surfaceId);

    const brief = JSON.parse(readAssignmentBrief({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      egress_profile: "default",
      block_internal_hosts: false,
    }));

    assert.ok(brief.wave_brief_derivation);
    assert.equal(brief.wave_brief_derivation.target_class, "web_application");

    const auxTools = brief.wave_brief_derivation.target_class_auxiliary_tools;
    const addedTools = brief.wave_brief_derivation.added_tools;
    for (const tool of PHISHING_AUX_TOOLS) {
      assert.equal(
        auxTools.includes(tool),
        false,
        `web_application target_class MUST NOT auto-include phishing-specific ${tool}`,
      );
      assert.equal(
        addedTools.includes(tool),
        false,
        `web_application target_class MUST NOT auto-include phishing-specific ${tool} in added_tools[]`,
      );
    }
  });
});

test("unknown target_class on queue-policy is ignored (graceful — stale operator hand-edit MUST not abort brief)", () => {
  withTempHome(() => {
    const domain = uniqueDomain("y5-unknown");
    const surfaceId = "web-api";
    seedSessionState(domain);
    seedAttackSurface(domain, [{
      id: surfaceId,
      surface_type: "api",
      hosts: [`https://api.${domain}`],
      title: "Plain web API",
      tech_stack: ["Express"],
      endpoints: ["/api/users"],
    }]);
    // Write a queue-policy directly with an unknown target_class. The
    // caller-side resolver MUST skip it rather than throw.
    seedQueuePolicyWithTargetClass(domain, "not_a_real_target_class");
    startSingleSurfaceWave(domain, surfaceId);

    const brief = JSON.parse(readAssignmentBrief({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      egress_profile: "default",
      block_internal_hosts: false,
    }));

    assert.ok(brief.wave_brief_derivation);
    assert.equal(brief.wave_brief_derivation.target_class, null);
  });
});

test("buildWaveBriefDerivation rejects an explicit unknown target_class (closed-enum contract)", () => {
  assert.throws(
    () => buildWaveBriefDerivation({
      surfaceObj: { id: "s1", surface_type: "api" },
      surfaceId: "s1",
      waveNumber: 1,
      frontierEvents: [],
      queuePolicy: null,
      explicitTargetClass: "definitely_not_in_enum",
      includeInadequacy: false,
    }),
    /target_class/,
  );
});
