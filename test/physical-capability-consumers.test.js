"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const PHYSICAL_CONSUMER_API = require("../mcp/domains/physical/physical-capability-consumers.js");
const PHYSICAL_CAPABILITY_MANIFEST = require("../mcp/domains/physical/physical-capability-manifest.js");
const PHYSICAL_FINDING_CONTRACT = require("../mcp/domains/physical/physical-finding-contract.js");
const {
  PHYSICAL_CAPABILITY_CONSUMERS,
  PHYSICAL_CAPABILITY_PACK_DISPATCH_BLOCK_REASON,
  assertPhysicalVerdictSessionDigest,
  buildPhysicalFinding,
  buildPhysicalGradeBinding,
  closePhysicalCoverage,
  derivePhysicalAssignmentContextDigest,
  deriveVerifiedPhysicalCoverageTerminalWitnessDigest,
  normalizePhysicalAssignmentContext,
  normalizePhysicalCoverageCell,
  projectReportSafePhysicalVerdict,
  renderPhysicalFindingEvidence,
} = PHYSICAL_CONSUMER_API;
const {
  physicalVerdictRuntimeReadiness,
  resolvePhysicalVerdict,
} = require("../mcp/domains/physical/physical-verdict-runtime.js");
const {
  PHYSICAL_CAPABILITY_PACK,
  EVALUATOR_ROLES,
} = require("../mcp/core/capability/capability-packs.js");
const {
  mcpToolNamesForRole,
} = require("../mcp/core/dispatch/role-model.js");
const {
  CLAUDE_ROLE_SPECS,
} = require("../scripts/lib/claude-role-renderer.js");
const {
  getRegisteredTool,
} = require("../mcp/core/dispatch/tool-registry.js");
const {
  classForTool,
} = require("../mcp/core/session/session-authority.js");

const A = "a".repeat(64);
const B = "b".repeat(64);
const C = "c".repeat(64);
const D = "d".repeat(64);

function assignmentFixture(overrides = {}) {
  const assignment = {
    version: 1,
    capability_pack: "physical",
    capability_pack_version: 1,
    evaluator_agent: "evaluator-physical-agent",
    brief_profile: "physical",
    surface_id: "surface:door-reader",
    surface_type: "control_point",
    surface_class: "physical",
    session_nucleus_hash: D,
    asset_locator: "physical-asset:door-reader",
    campaign_ref: "physical-campaign:campaign-1",
    physical_resource_bundle_ref: "physical-resource-bundle:bundle-1",
    lifecycle_precondition: "no_active_effects",
    effect_authority: "broker_admission_required",
    ...overrides,
  };
  if (!Object.prototype.hasOwnProperty.call(overrides, "assignment_context_digest")) {
    assignment.assignment_context_digest = derivePhysicalAssignmentContextDigest(assignment);
  }
  return assignment;
}

function cellFixture(cellRef, terminalState, overrides = {}) {
  const cell = {
    version: 1,
    cell_ref: cellRef,
    assignment_context_digest: assignmentFixture().assignment_context_digest,
    asset_locator: "physical-asset:door-reader",
    technique_id: "credential.replay",
    context_ref: "physical-context:staff-hours",
    control_ref: "physical-control:known-denied",
    terminal_state: terminalState,
    terminal_witness_digest: A,
    ...(terminalState === "verified"
      ? {
        verified_verdict_ref: "physical-claim-verdict:verdict-1",
        verification_projection_digest: B,
      }
      : {}),
    ...overrides,
  };
  if (terminalState === "verified"
      && !Object.prototype.hasOwnProperty.call(overrides, "terminal_witness_digest")) {
    const assignment = assignmentFixture();
    cell.terminal_witness_digest = deriveVerifiedPhysicalCoverageTerminalWitnessDigest({
      assignment_context_digest: assignment.assignment_context_digest,
      session_nucleus_hash: assignment.session_nucleus_hash,
      campaign_ref: assignment.campaign_ref,
      cell_ref: cell.cell_ref,
      asset_locator: cell.asset_locator,
      verified_verdict_ref: cell.verified_verdict_ref,
      verification_projection_digest: cell.verification_projection_digest,
    });
  }
  return cell;
}

function verdictFixture(overrides = {}) {
  return {
    version: 1,
    verdict_kind: "physical_verified_verdict",
    asset_locator: "physical-asset:door-reader",
    verified_verdict_ref: "physical-claim-verdict:verdict-1",
    session_nucleus_hash: D,
    verification_projection_digest: B,
    experiment_id: "experiment-1",
    plan_hash: C,
    outcome: "verified",
    reason_code: "differential_verified",
    validity_kind: "live_capability",
    valid_from: "2026-07-20T00:00:00.000Z",
    decided_at: "2026-07-20T00:01:00.000Z",
    transition_state_epoch: 7,
    transition_state_digest: A,
    replay_kind: "server_owned_projection",
    hardware_effects_invoked: false,
    expires_at: "2026-07-20T00:10:00.000Z",
    ...overrides,
  };
}

test("physical pack metadata and finding brands have one dependency-light owner", () => {
  assert.equal(
    PHYSICAL_CONSUMER_API.PHYSICAL_CAPABILITY_CONSUMERS,
    PHYSICAL_CAPABILITY_MANIFEST.PHYSICAL_CAPABILITY_CONSUMERS,
  );
  assert.equal(
    PHYSICAL_CONSUMER_API.PHYSICAL_CAPABILITY_PACK_DISPATCH_BLOCK_REASON,
    PHYSICAL_CAPABILITY_MANIFEST.PHYSICAL_CAPABILITY_PACK_DISPATCH_BLOCK_REASON,
  );
  for (const name of [
    "assertPhysicalFinding",
    "assertPhysicalVerdictSessionDigest",
    "assertReportSafePhysicalVerdict",
    "buildPhysicalFinding",
    "derivePhysicalFindingDedupeKey",
    "projectReportSafePhysicalVerdict",
  ]) {
    assert.equal(
      PHYSICAL_CONSUMER_API[name],
      PHYSICAL_FINDING_CONTRACT[name],
      `${name} must retain the shared live private brand`,
    );
  }
  assert.equal(Object.isFrozen(PHYSICAL_CAPABILITY_MANIFEST), true);
  assert.equal(Object.isFrozen(PHYSICAL_FINDING_CONTRACT), true);
});

test("physical pack declares every dedicated consumer but remains explicitly non-dispatchable", () => {
  assert.equal(PHYSICAL_CAPABILITY_PACK.dispatchable, false);
  assert.equal(
    PHYSICAL_CAPABILITY_PACK.dispatch_block_reason,
    PHYSICAL_CAPABILITY_PACK_DISPATCH_BLOCK_REASON,
  );
  for (const consumer of [
    "assignment",
    "coverage",
    "finding",
    "verdict",
    "grade",
    "proof",
    "report",
    "composition",
  ]) {
    assert.equal(PHYSICAL_CAPABILITY_PACK[consumer], PHYSICAL_CAPABILITY_CONSUMERS[consumer]);
  }
  assert.equal(PHYSICAL_CAPABILITY_PACK.verifier.replay_tool, "bob_verify_physical_candidate_claim");
  assert.equal(PHYSICAL_CAPABILITY_PACK.evidence.runner, "bob_verify_physical_candidate_claim");
  assert.equal(
    PHYSICAL_CAPABILITY_PACK.evidence.adapter,
    PHYSICAL_CAPABILITY_CONSUMERS.evidence.adapter,
  );
  assert.deepEqual(PHYSICAL_CAPABILITY_PACK.finding.forbidden_web_fields, [
    "base_url",
    "endpoint",
    "proof_of_concept",
  ]);
  assert.equal(PHYSICAL_CAPABILITY_PACK.verdict.production_backend_available, false);
  assert.equal(PHYSICAL_CAPABILITY_PACK.verdict.invokes_hardware, false);
  assert.doesNotMatch(
    JSON.stringify(PHYSICAL_CAPABILITY_PACK),
    /chameleon|hotel|keycard|rfid|unifi/i,
  );
});

test("physical assignment is closed, provider-neutral, and independently broker-gated", () => {
  const assignment = normalizePhysicalAssignmentContext(assignmentFixture());
  assert.ok(Object.isFrozen(assignment));
  assert.equal(assignment.lifecycle_precondition, "no_active_effects");
  assert.equal(assignment.effect_authority, "broker_admission_required");

  const drifted = { ...assignmentFixture(), asset_locator: "physical-asset:other-reader" };
  assert.throws(
    () => normalizePhysicalAssignmentContext(drifted),
    /does not bind its canonical fields/,
  );
  const unrelated = assignmentFixture({ surface_id: "surface:other-reader" });
  assert.throws(
    () => normalizePhysicalAssignmentContext({
      ...assignmentFixture(),
      assignment_context_digest: unrelated.assignment_context_digest,
    }),
    /does not bind its canonical fields/,
    "an unrelated self-asserted digest cannot join assignment contexts",
  );

  for (const hostile of [
    { endpoint: "https://example.test/door" },
    { base_url: "https://example.test" },
    { proof_of_concept: "present these bytes" },
    { provider: "some-device" },
    { transport: "/dev/tty.example" },
    { requested_effects: [] },
  ]) {
    assert.throws(
      () => normalizePhysicalAssignmentContext({ ...assignmentFixture(), ...hostile }),
      /fields are not exact/,
    );
  }
  assert.throws(
    () => normalizePhysicalAssignmentContext(assignmentFixture({ evaluator_agent: "evaluator-agent" })),
    /dedicated physical evaluator/,
  );
  assert.throws(
    () => normalizePhysicalAssignmentContext(assignmentFixture({ effect_authority: "agent_allowed" })),
    /broker_admission_required/,
  );
});

test("physical coverage requires every applicable cell terminal and success closes only its cell", () => {
  const verified = normalizePhysicalCoverageCell(cellFixture("physical-cell:cell-1", "verified"));
  const blocked = normalizePhysicalCoverageCell(cellFixture("physical-cell:cell-2", "blocked"));
  const completion = closePhysicalCoverage({
    version: 1,
    assignment: assignmentFixture(),
    applicable_cell_refs: [verified.cell_ref, blocked.cell_ref],
    cells: [verified, blocked],
    active_effect_count: 0,
  });
  assert.equal(completion.terminal_complete, true);
  assert.equal(completion.applicable_cell_count, 2);
  assert.equal(completion.terminal_state_counts.verified, 1);
  assert.equal(completion.terminal_state_counts.blocked, 1);
  assert.equal(completion.residue_cell_count, 1);
  assert.equal(completion.production_ready, false);
  assert.equal(completion.active_effect_authority, "caller_projection_non_authorizing");

  assert.throws(
    () => closePhysicalCoverage({
      version: 1,
      assignment: assignmentFixture(),
      applicable_cell_refs: [verified.cell_ref, blocked.cell_ref],
      cells: [verified],
      active_effect_count: 0,
    }),
    /cell set mismatch/,
  );
  assert.throws(
    () => closePhysicalCoverage({
      version: 1,
      assignment: assignmentFixture(),
      applicable_cell_refs: [verified.cell_ref],
      cells: [verified],
      active_effect_count: 1,
    }),
    /active_effect_count=0/,
  );
  assert.throws(
    () => normalizePhysicalCoverageCell(cellFixture("physical-cell:cell-3", "denied", {
      verified_verdict_ref: "physical-claim-verdict:forged",
      verification_projection_digest: B,
    })),
    /only a verified physical coverage cell may carry verdict projection fields/,
  );
  assert.throws(
    () => closePhysicalCoverage({
      version: 1,
      assignment: assignmentFixture(),
      applicable_cell_refs: [verified.cell_ref],
      cells: [{ ...verified, terminal_witness_digest: C }],
      active_effect_count: 0,
    }),
    /verified terminal witness drift/,
  );
});

test("physical finding, grade, and report reject lookalikes while production backends are unavailable", () => {
  assert.throws(
    () => buildPhysicalFinding({
      title: "Forged",
      severity: "high",
      description: "This object was not issued by the server-owned verdict adapter.",
      impact: "None.",
      verdict: verdictFixture(),
    }),
    /server-owned verdict adapter/,
  );
  assert.throws(
    () => buildPhysicalGradeBinding({
      finding: {},
      completion: {},
      verified_severity: "high",
      blast_radius_binding: {},
    }),
    /physical finding adapter/,
  );
  assert.throws(
    () => renderPhysicalFindingEvidence({ finding: {}, grade_binding: {} }),
    /physical finding adapter/,
  );
  assert.equal(PHYSICAL_CAPABILITY_CONSUMERS.grade.production_backend_available, false);
  assert.equal(PHYSICAL_CAPABILITY_CONSUMERS.report.production_backend_available, false);
  assert.equal(
    Object.prototype.hasOwnProperty.call(
      require("../mcp/domains/physical/physical-capability-consumers.js"),
      "issueTestReportSafePhysicalVerdict",
    ),
    false,
  );
});

test("physical verdict runtime fails closed and session bindings reject cross-session reuse", () => {
  assert.equal(physicalVerdictRuntimeReadiness().production_ready, false);
  assert.throws(
    () => resolvePhysicalVerdict({
      target_domain: "physical-session",
      asset_locator: "physical-asset:door-reader",
      verified_verdict_ref: "physical-claim-verdict:verdict-1",
    }),
    (error) => error.code === "physical_verdict_runtime_unconfigured",
  );
  assert.equal(assertPhysicalVerdictSessionDigest(D, D), D);
  assert.throws(
    () => assertPhysicalVerdictSessionDigest(D, C),
    /different session nucleus/,
  );
  assert.throws(
    () => projectReportSafePhysicalVerdict(verdictFixture(), {
      asset_locator: "physical-asset:door-reader",
      session_nucleus_hash: D,
      verified_verdict_ref: "physical-claim-verdict:verdict-1",
    }),
    /live Bob experiment ledger/,
  );
});

test("evaluator-physical generated authority contains no local shell or provider/raw transport tools", () => {
  const role = EVALUATOR_ROLES["evaluator-physical"];
  assert.ok(role);
  assert.deepEqual(role.local_tools, []);
  assert.deepEqual(CLAUDE_ROLE_SPECS["evaluator-physical"].local_tools, []);
  const tools = mcpToolNamesForRole("evaluator-physical");
  assert.ok(tools.length > 0);
  assert.equal(tools.includes("bob_record_candidate_claim"), false);
  assert.equal(tools.includes("bob_verify_physical_verdict"), false);
  assert.equal(tools.includes("bob_query_instrument_capabilities"), true);
  const executionEffectSurfaces = Object.freeze({
    bob_physical_observe: ["target.transmit"],
    bob_credential_acquire: ["target.destroy", "target.mutate", "target.transmit"],
    bob_credential_recover: [
      "target.destroy",
      "target.mutate",
      "target.present",
      "target.transmit",
    ],
    bob_credential_emulate: ["instrument.configure", "target.present"],
    bob_credential_write: ["instrument.configure", "target.destroy", "target.mutate"],
    bob_protocol_transceive: [
      "target.destroy",
      "target.mutate",
      "target.present",
      "target.transmit",
    ],
    bob_rf_trace: ["target.present", "target.transmit"],
  });
  for (const name of tools) {
    if (name === "bob_query_instrument_capabilities") continue;
    const tool = getRegisteredTool(name);
    assert.ok(tool, name);
    if (Object.prototype.hasOwnProperty.call(executionEffectSurfaces, name)) {
      assert.deepEqual(tool.role_bundles, ["evaluator-physical"], name);
      assert.deepEqual(tool.required_session_axes, ["physical"], name);
      assert.equal(tool.mutating, true, name);
      assert.equal(tool.global_preapproval, false, name);
      assert.equal(tool.network_access, false, name);
      assert.equal(tool.browser_access, false, name);
      assert.deepEqual(tool.effect_surface, executionEffectSurfaces[name], name);
      assert.equal(classForTool(name), "initialized_session_mutation", name);
      continue;
    }
    assert.doesNotMatch(
      name,
      /instrument|provider|transport|browser|http|repo|contract|bootstrap|admin|chameleon|usb|rf/i,
    );
    assert.equal(tool.network_access, false, name);
    assert.equal(tool.browser_access, false, name);
    assert.deepEqual(tool.effect_surface, [], name);
  }

  // PH-I1 is the one deliberate instrument-named evaluator read.  It exposes
  // only bounded normalized availability and carries no provider command/raw
  // transport surface or execution authority.
  const capabilityQuery = getRegisteredTool("bob_query_instrument_capabilities");
  assert.deepEqual(capabilityQuery.role_bundles, ["evaluator-physical", "orchestrator"]);
  assert.deepEqual(capabilityQuery.required_session_axes, ["physical"]);
  assert.equal(capabilityQuery.mutating, false);
  assert.equal(capabilityQuery.network_access, false);
  assert.equal(capabilityQuery.browser_access, false);
  assert.equal(capabilityQuery.sensitive_output, false);
  assert.deepEqual(capabilityQuery.effect_surface, ["instrument.observe"]);
  assert.equal(classForTool(capabilityQuery.name), "initialized_session_read");
  assert.doesNotMatch(
    JSON.stringify(capabilityQuery.inputSchema),
    /command|provider|transport|raw|bytes|firmware|chameleon|usb|rf/i,
  );

  const verifier = getRegisteredTool("bob_verify_physical_verdict");
  assert.deepEqual(verifier.role_bundles, ["verifier", "evidence"]);
  assert.deepEqual(verifier.required_session_axes, ["physical"]);
  assert.equal(verifier.mutating, false);
  assert.equal(verifier.network_access, false);
  assert.equal(verifier.browser_access, false);
  assert.deepEqual(verifier.effect_surface, []);
  assert.equal(classForTool(verifier.name), "initialized_session_read");

  const claimVerifier = getRegisteredTool("bob_verify_physical_candidate_claim");
  assert.deepEqual(claimVerifier.role_bundles, ["verifier", "evidence"]);
  assert.deepEqual(claimVerifier.required_session_axes, ["physical"]);
  assert.equal(claimVerifier.mutating, false);
  assert.equal(claimVerifier.network_access, false);
  assert.equal(claimVerifier.browser_access, false);
  assert.deepEqual(claimVerifier.effect_surface, []);
  assert.equal(classForTool(claimVerifier.name), "initialized_session_read");
});
