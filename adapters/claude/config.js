"use strict";

const {
  TOOL_MANIFEST,
  TOOLS,
  toolNamesForRoleBundle,
} = require("../../mcp/lib/tool-registry.js");
const {
  mcpToolNamesForRole,
} = require("../../mcp/lib/role-model.js");

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

function mcpPermissionForTool(toolName) {
  return `mcp__bountyagent__${toolName}`;
}

function permissionsForAllTools() {
  return TOOLS.map((tool) => mcpPermissionForTool(tool.name));
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
  return TOOLS
    .map((tool) => tool.name)
    .filter((toolName) => TOOL_MANIFEST[toolName].global_preapproval === true)
    .map(mcpPermissionForTool);
}

function scopeMcpHookMatcher(toolName) {
  return {
    matcher: mcpPermissionForTool(toolName),
    hooks: [{
      type: "command",
      command: "bash \"$CLAUDE_PROJECT_DIR/.claude/hooks/scope-guard-mcp.sh\"",
      timeout: 5,
    }],
  };
}

function defaultPreToolUseHooks() {
  const hookRequired = Object.entries(TOOL_MANIFEST)
    .filter(([, metadata]) => metadata.hook_required)
    .map(([toolName]) => scopeMcpHookMatcher(toolName));

  return [
    {
      matcher: "Bash",
      hooks: [
        {
          type: "command",
          command: "bash \"$CLAUDE_PROJECT_DIR/.claude/hooks/scope-guard.sh\"",
          timeout: 5,
        },
        {
          type: "command",
          command: "bash \"$CLAUDE_PROJECT_DIR/.claude/hooks/session-write-guard.sh\"",
          timeout: 5,
        },
      ],
    },
    {
      matcher: "Write",
      hooks: [
        {
          type: "command",
          command: "bash \"$CLAUDE_PROJECT_DIR/.claude/hooks/session-write-guard.sh\"",
          timeout: 5,
        },
      ],
    },
    ...hookRequired,
  ];
}

function defaultSubagentStopHooks() {
  return [
    {
      matcher: "hunter-agent",
      hooks: [
        {
          type: "command",
          command: "node \"$CLAUDE_PROJECT_DIR/.claude/hooks/hunter-subagent-stop.js\"",
          timeout: 10,
        },
      ],
    },
  ];
}

function defaultSessionStartHooks() {
  return [
    {
      matcher: "startup",
      hooks: [
        {
          type: "command",
          command: "node \"$CLAUDE_PROJECT_DIR/.claude/hooks/bob-check-update.js\" \"$CLAUDE_PROJECT_DIR\"",
          timeout: 2,
        },
      ],
    },
  ];
}

function bountyagentSkillAllowedTools() {
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
      SubagentStop: defaultSubagentStopHooks(),
    },
    statusLine: {
      type: "command",
      command: "node \"$CLAUDE_PROJECT_DIR/.claude/hooks/bounty-statusline.js\"",
    },
  };
}

module.exports = {
  BASE_PERMISSIONS,
  bountyagentSkillAllowedTools,
  defaultClaudeSettings,
  defaultGlobalMcpPermissions,
  defaultPreToolUseHooks,
  defaultSessionStartHooks,
  defaultSubagentStopHooks,
  isOrchestratorOnlyMutator,
  mcpPermissionForTool,
  permissionsForAllTools,
  permissionsForRole,
  permissionsForRoleBundle,
  permissionsForRoleBundles,
};
