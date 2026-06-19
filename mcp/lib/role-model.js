"use strict";

const path = require("path");
const {
  TOOL_MANIFEST,
  toolNamesForRoleBundle,
} = require("./tool-registry.js");
const { evaluatorRoleSpecs } = require("./capability-packs.js");

const ROLE_PROMPT_DIR = path.join("prompts", "roles");

const READ_ONLY_STATUS_TOOLS = Object.freeze([
  "bob_read_pipeline_analytics",
  "bob_read_session_summary",
  "bob_read_state_summary",
  "bob_wave_status",
  "bob_read_wave_handoffs",
  "bob_read_candidate_claims",
  "bob_read_verification_context",
  "bob_read_verification_round",
  "bob_read_evidence_packs",
  "bob_read_grade_verdict",
]);

const READ_ONLY_DEBUG_TOOLS = Object.freeze([
  "bob_read_pipeline_analytics",
  "bob_read_tool_telemetry",
  "bob_read_session_summary",
  "bob_read_state_summary",
  "bob_wave_status",
  "bob_read_wave_handoffs",
  "bob_read_candidate_claims",
  "bob_read_verification_context",
  "bob_read_verification_round",
  "bob_diff_verification_attempts",
  "bob_read_evidence_packs",
  "bob_read_grade_verdict",
]);

const ROLE_DEFINITIONS = Object.freeze({
  orchestrator: Object.freeze({
    id: "orchestrator",
    prompt_body: path.join(ROLE_PROMPT_DIR, "orchestrator.md"),
    mcp_role_bundles: Object.freeze(["orchestrator", "auth"]),
  }),
  "surface-discovery": Object.freeze({
    id: "surface-discovery",
    prompt_body: path.join(ROLE_PROMPT_DIR, "surface-discovery.md"),
    mcp_role_bundles: Object.freeze(["surface-discovery"]),
    mcp_tools: Object.freeze(["bob_read_session_nucleus"]),
  }),
  "deep-surface-discovery": Object.freeze({
    id: "deep-surface-discovery",
    prompt_body: path.join(ROLE_PROMPT_DIR, "deep-surface-discovery.md"),
    mcp_role_bundles: Object.freeze(["deep-surface-discovery"]),
    mcp_tools: Object.freeze(["bob_read_session_nucleus"]),
  }),
  "surface-router": Object.freeze({
    id: "surface-router",
    prompt_body: path.join(ROLE_PROMPT_DIR, "surface-router.md"),
    mcp_role_bundles: Object.freeze(["router"]),
  }),
  evaluator: Object.freeze({
    id: "evaluator",
    prompt_body: path.join(ROLE_PROMPT_DIR, "evaluator.md"),
    mcp_role_bundles: Object.freeze(["evaluator-shared", "evaluator-web"]),
  }),
  // Per-chain evaluator role definitions are generated below from EVALUATOR_ROLES
  // in capability-packs.js. The static `evaluator` (web) role above stays
  // hand-coded because it is not chain-specific.
  ...Object.fromEntries(
    evaluatorRoleSpecs().map((role) => [
      role.role_id,
      Object.freeze({
        id: role.role_id,
        family: "evaluator",
        prompt_body: path.join(ROLE_PROMPT_DIR, role.prompt_body_filename),
        mcp_role_bundles: role.role_bundles,
      }),
    ]),
  ),
  // Plane X Cycle X.10 — generic TaskGraph evaluator shell. UNION of the
  // shared evaluator + web + every chain-specific evaluator bundle so a
  // single agent shell can execute Transition and Hypothesis nodes that
  // span arbitrary tool combinations not knowable at build time. Per X-P7
  // this is an ergonomics trade (preventive→detective control swap):
  // mechanical verifier (X.6) catches out-of-band tool invocations via
  // the `tool_constraint_violation` failure_reason emitted from
  // bob_finalize_node when agent_output.tool_invocations[] contains a
  // tool outside the dispatched node's allowed_tools_for_node[] set.
  "evaluator-spawn": Object.freeze({
    id: "evaluator-spawn",
    family: "evaluator",
    prompt_body: path.join(ROLE_PROMPT_DIR, "evaluator-spawn.md"),
    mcp_role_bundles: Object.freeze([
      "evaluator-shared",
      "evaluator-spawn",
      "evaluator-web",
      ...evaluatorRoleSpecs().flatMap((role) => role.role_bundles.filter((b) => b !== "evaluator-shared")),
    ]),
  }),
  chain: Object.freeze({
    id: "chain",
    prompt_body: path.join(ROLE_PROMPT_DIR, "chain.md"),
    mcp_role_bundles: Object.freeze(["chain"]),
  }),
  "brutalist-verifier": Object.freeze({
    id: "brutalist-verifier",
    family: "verifier",
    prompt_body: path.join(ROLE_PROMPT_DIR, "brutalist-verifier.md"),
    mcp_role_bundles: Object.freeze(["verifier"]),
  }),
  "balanced-verifier": Object.freeze({
    id: "balanced-verifier",
    family: "verifier",
    prompt_body: path.join(ROLE_PROMPT_DIR, "balanced-verifier.md"),
    mcp_role_bundles: Object.freeze(["verifier"]),
  }),
  "final-verifier": Object.freeze({
    id: "final-verifier",
    family: "verifier",
    prompt_body: path.join(ROLE_PROMPT_DIR, "final-verifier.md"),
    mcp_role_bundles: Object.freeze(["verifier"]),
    mcp_tools: Object.freeze(["bob_write_proof_bundle"]),
  }),
  evidence: Object.freeze({
    id: "evidence",
    prompt_body: path.join(ROLE_PROMPT_DIR, "evidence.md"),
    mcp_role_bundles: Object.freeze(["evidence"]),
  }),
  grader: Object.freeze({
    id: "grader",
    prompt_body: path.join(ROLE_PROMPT_DIR, "grader.md"),
    mcp_role_bundles: Object.freeze(["grader"]),
  }),
  reporter: Object.freeze({
    id: "reporter",
    prompt_body: path.join(ROLE_PROMPT_DIR, "reporter.md"),
    mcp_role_bundles: Object.freeze(["reporter"]),
  }),
  status: Object.freeze({
    id: "status",
    prompt_body: path.join(ROLE_PROMPT_DIR, "status.md"),
    mcp_role_bundles: Object.freeze([]),
    mcp_tools: READ_ONLY_STATUS_TOOLS,
  }),
  debug: Object.freeze({
    id: "debug",
    prompt_body: path.join(ROLE_PROMPT_DIR, "debug.md"),
    mcp_role_bundles: Object.freeze([]),
    mcp_tools: READ_ONLY_DEBUG_TOOLS,
  }),
});

function uniqueStrings(values) {
  return Array.from(new Set(values.filter((value) => typeof value === "string" && value.trim())));
}

function roleDefinition(roleId) {
  const role = ROLE_DEFINITIONS[roleId];
  if (!role) throw new Error(`Unknown Bob role: ${roleId}`);
  return role;
}

function allRoleDefinitions() {
  return Object.values(ROLE_DEFINITIONS);
}

function mcpToolNamesForRole(roleId) {
  const role = roleDefinition(roleId);
  return uniqueStrings([
    ...role.mcp_role_bundles.flatMap((roleBundle) => toolNamesForRoleBundle(roleBundle)),
    ...(role.mcp_tools || []),
  ]);
}

function assertRoleModel() {
  for (const role of allRoleDefinitions()) {
    for (const toolName of mcpToolNamesForRole(role.id)) {
      if (!TOOL_MANIFEST[toolName]) {
        throw new Error(`Role ${role.id} references unknown MCP tool ${toolName}`);
      }
    }
  }
}

assertRoleModel();

module.exports = {
  READ_ONLY_DEBUG_TOOLS,
  READ_ONLY_STATUS_TOOLS,
  ROLE_DEFINITIONS,
  ROLE_PROMPT_DIR,
  allRoleDefinitions,
  mcpToolNamesForRole,
  roleDefinition,
};
