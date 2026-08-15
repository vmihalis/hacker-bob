"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  derivePhysicalAssignmentContextDigest,
} = require("../mcp/domains/physical/physical-capability-consumers.js");
const {
  claimsJsonlPath,
} = require("../mcp/core/io/paths.js");
const {
  getRegisteredTool,
} = require("../mcp/tools/tool-registry.js");
const {
  classForTool,
} = require("../mcp/core/session/session-authority.js");
const {
  validateToolArguments,
} = require("../mcp/core/dispatch/tool-validation.js");

function assignmentFixture() {
  const assignment = {
    version: 1,
    capability_pack: "physical",
    capability_pack_version: 1,
    evaluator_agent: "evaluator-physical-agent",
    brief_profile: "physical",
    surface_id: "surface:door-reader",
    surface_type: "control_point",
    surface_class: "physical",
    session_nucleus_hash: "d".repeat(64),
    asset_locator: "physical-asset:door-reader",
    campaign_ref: "physical-campaign:campaign-1",
    physical_resource_bundle_ref: "physical-resource-bundle:bundle-1",
    lifecycle_precondition: "no_active_effects",
    effect_authority: "broker_admission_required",
  };
  assignment.assignment_context_digest = derivePhysicalAssignmentContextDigest(assignment);
  return assignment;
}

function argsFixture() {
  return {
    target_domain: "physical-session-1",
    assignment: assignmentFixture(),
    verified_verdict_ref: "physical-claim-verdict:verdict-1",
    title: "Credential representation crosses the restricted-zone control",
    severity: "high",
    cwe: "CWE-284",
    description: "An independent observer recorded the differential control transition.",
    impact: "An unauthorized bearer could reach the bounded restricted zone.",
  };
}

test("bob_record_physical_candidate_claim is a physical-only effectless claim writer", () => {
  const tool = getRegisteredTool("bob_record_physical_candidate_claim");
  assert.ok(tool);
  assert.deepEqual(tool.role_bundles, ["evaluator-physical"]);
  assert.deepEqual(tool.required_session_axes, ["physical"]);
  assert.equal(tool.mutating, true);
  assert.equal(tool.network_access, false);
  assert.equal(tool.browser_access, false);
  assert.deepEqual(tool.effect_surface, []);
  assert.equal(classForTool(tool.name), "initialized_session_mutation");
  assert.equal(Object.prototype.hasOwnProperty.call(tool.inputSchema.properties, "endpoint"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(tool.inputSchema.properties, "proof_of_concept"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(tool.inputSchema.properties, "response_evidence"), false);
});

test("physical claim schema accepts only the closed assignment and opaque verdict inputs", () => {
  const args = argsFixture();
  assert.doesNotThrow(() => validateToolArguments("bob_record_physical_candidate_claim", args));
  assert.throws(
    () => validateToolArguments("bob_record_physical_candidate_claim", {
      ...args,
      endpoint: "https://invalid.example/door",
    }),
    /endpoint is not allowed/,
  );
  assert.throws(
    () => validateToolArguments("bob_record_physical_candidate_claim", {
      ...args,
      assignment: { ...args.assignment, effect_authority: "agent_allowed" },
    }),
    /must be one of broker_admission_required/,
  );
});

test("physical claim writer fails before persistence without a verified physical session", () => {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-physical-claim-"));
  process.env.HOME = home;
  try {
    const tool = getRegisteredTool("bob_record_physical_candidate_claim");
    assert.throws(
      () => tool.handler(argsFixture()),
      (error) => error && error.code === "STATE_CONFLICT"
        && /verified physical session nucleus is unavailable/.test(error.message),
    );
    assert.equal(fs.existsSync(claimsJsonlPath("physical-session-1")), false);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});
