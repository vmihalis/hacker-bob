"use strict";

const path = require("path");
const {
  TOOL_MANIFEST,
  toolNamesForRoleBundle,
} = require("./tool-registry.js");

const ROLE_PROMPT_DIR = path.join("prompts", "roles");

const READ_ONLY_STATUS_TOOLS = Object.freeze([
  "bounty_read_pipeline_analytics",
  "bounty_read_state_summary",
  "bounty_wave_status",
  "bounty_read_wave_handoffs",
  "bounty_read_findings",
  "bounty_read_verification_round",
  "bounty_read_grade_verdict",
]);

const READ_ONLY_DEBUG_TOOLS = Object.freeze([
  "bounty_read_pipeline_analytics",
  "bounty_read_tool_telemetry",
  "bounty_read_state_summary",
  "bounty_wave_status",
  "bounty_read_wave_handoffs",
  "bounty_read_findings",
  "bounty_read_verification_round",
  "bounty_read_grade_verdict",
]);

const ROLE_DEFINITIONS = Object.freeze({
  orchestrator: Object.freeze({
    id: "orchestrator",
    prompt_body: path.join(ROLE_PROMPT_DIR, "orchestrator.md"),
    mcp_role_bundles: Object.freeze(["orchestrator", "auth"]),
  }),
  recon: Object.freeze({
    id: "recon",
    prompt_body: path.join(ROLE_PROMPT_DIR, "recon.md"),
    mcp_role_bundles: Object.freeze([]),
  }),
  hunter: Object.freeze({
    id: "hunter",
    prompt_body: path.join(ROLE_PROMPT_DIR, "hunter.md"),
    mcp_role_bundles: Object.freeze(["hunter"]),
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
