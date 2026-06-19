"use strict";

const {
  TOOL_MANIFEST,
  TOOLS,
  toolNamesForRoleBundle,
} = require("../../mcp/lib/tool-registry.js");
const {
  mcpToolNamesForRole,
} = require("../../mcp/lib/role-model.js");
const {
  evaluatorAgentNamesForCapabilityPacks,
} = require("../../mcp/lib/capability-packs.js");

const BASE_PERMISSIONS = Object.freeze([
  "Bash(mkdir *)",
  "Bash(test *)",
  "Bash(cat *)",
  "Bash(ls *)",
  "Bash(sort *)",
  "Bash(wc *)",
  "Bash(head *)",
  "Bash(tail *)",
  "Bash(jq *)",
  "Bash(printf *)",
  "Bash(echo *)",
  "Read",
  "Glob",
  "Grep",
]);

const PROJECT_DIR_EXPR = "${CLAUDE_PROJECT_DIR:-$PWD}";

function mcpPermissionForTool(toolName) {
  return `mcp__hacker-bob__${toolName}`;
}

function permissionsForAllTools() {
  // Aliases (Cycle P.1) are not surfaced as permissions; the primary bob_*
  // entry covers both names because the registry routes aliases to the same
  // handler.
  return TOOLS
    .filter((tool) => !TOOL_MANIFEST[tool.name].alias_of)
    .map((tool) => mcpPermissionForTool(tool.name));
}

function permissionsForRoleBundle(roleBundle) {
  return toolNamesForRoleBundle(roleBundle).map(mcpPermissionForTool);
}

function permissionsForRoleBundles(roleBundles) {
  return uniqueStrings(roleBundles.flatMap((roleBundle) => permissionsForRoleBundle(roleBundle)));
}

function permissionsForRole(roleId) {
  return mcpToolNamesForRole(roleId).map(mcpPermissionForTool);
}

function uniqueStrings(values) {
  return Array.from(new Set(values.filter((value) => typeof value === "string" && value.trim())));
}

function isOrchestratorOnlyMutator(toolName) {
  const metadata = TOOL_MANIFEST[toolName];
  return !!metadata &&
    metadata.mutating === true &&
    metadata.role_bundles.length === 1 &&
    metadata.role_bundles[0] === "orchestrator";
}

function defaultGlobalMcpPermissions() {
  // Aliases (Cycle P.1 deprecation entries) inherit global_preapproval from
  // their primary but must not be re-emitted as a separate permission line.
  // Generated settings carry the canonical bob_* entry; calls through a
  // bounty_* alias still resolve through the registry alias mapping.
  return TOOLS
    .map((tool) => tool.name)
    .filter((toolName) => {
      const meta = TOOL_MANIFEST[toolName];
      return meta.global_preapproval === true && !meta.alias_of;
    })
    .map(mcpPermissionForTool);
}

function defaultPreToolUseHooks() {
  return [
    {
      matcher: "Bash",
      hooks: [
        {
          type: "command",
          command: `bash "${PROJECT_DIR_EXPR}/.claude/hooks/session-write-guard.sh"`,
          timeout: 5,
        },
        {
          type: "command",
          command: `bash "${PROJECT_DIR_EXPR}/.claude/hooks/session-read-guard.sh"`,
          timeout: 5,
        },
      ],
    },
    {
      matcher: "Read",
      hooks: [
        {
          type: "command",
          command: `bash "${PROJECT_DIR_EXPR}/.claude/hooks/session-read-guard.sh"`,
          timeout: 5,
        },
      ],
    },
    {
      matcher: "Write",
      hooks: [
        {
          type: "command",
          command: `bash "${PROJECT_DIR_EXPR}/.claude/hooks/session-write-guard.sh"`,
          timeout: 5,
        },
      ],
    },
  ];
}

function defaultSubagentStopHooks() {
  return evaluatorAgentNamesForCapabilityPacks().map((evaluatorAgent) => (
    {
      matcher: evaluatorAgent,
      hooks: [
        {
          type: "command",
          command: `node "${PROJECT_DIR_EXPR}/.claude/hooks/agent-run-stop.js"`,
          timeout: 10,
        },
      ],
    }
  ));
}

function defaultSubagentStartHooks() {
  // Cycle S.5: mark the AgentRun ledger row `running` when the evaluator
  // subagent starts. Best-effort and never blocks the agent's start; the
  // file-presence fallback (Pact P2) covers misses during the deprecation
  // window.
  return evaluatorAgentNamesForCapabilityPacks().map((evaluatorAgent) => (
    {
      matcher: evaluatorAgent,
      hooks: [
        {
          type: "command",
          command: `node "${PROJECT_DIR_EXPR}/.claude/hooks/agent-run-start.js"`,
          timeout: 5,
        },
      ],
    }
  ));
}

function defaultSessionStartHooks() {
  return [
    {
      matcher: "startup",
      hooks: [
        {
          type: "command",
          command: `node "${PROJECT_DIR_EXPR}/.claude/hooks/bob-check-update.js" "${PROJECT_DIR_EXPR}"`,
          timeout: 2,
        },
      ],
    },
  ];
}

function hackerBobSkillAllowedTools() {
  return uniqueStrings([
    "Task",
    "Read",
    ...permissionsForRole("orchestrator"),
  ]);
}

function defaultClaudeSettings() {
  return {
    permissions: {
      allow: uniqueStrings([
        ...defaultGlobalMcpPermissions(),
        ...BASE_PERMISSIONS,
      ]),
    },
    hooks: {
      PreToolUse: defaultPreToolUseHooks(),
      SessionStart: defaultSessionStartHooks(),
      SubagentStart: defaultSubagentStartHooks(),
      SubagentStop: defaultSubagentStopHooks(),
    },
    statusLine: {
      type: "command",
      command: `node "${PROJECT_DIR_EXPR}/.claude/hooks/bob-statusline.js"`,
    },
  };
}

module.exports = {
  BASE_PERMISSIONS,
  hackerBobSkillAllowedTools,
  defaultClaudeSettings,
  defaultGlobalMcpPermissions,
  defaultPreToolUseHooks,
  defaultSessionStartHooks,
  defaultSubagentStartHooks,
  defaultSubagentStopHooks,
  isOrchestratorOnlyMutator,
  mcpPermissionForTool,
  permissionsForAllTools,
  permissionsForRole,
  permissionsForRoleBundle,
  permissionsForRoleBundles,
};
