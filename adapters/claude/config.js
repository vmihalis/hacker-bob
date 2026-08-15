"use strict";

const {
  TOOL_MANIFEST,
  TOOLS,
  toolNamesForRoleBundle,
} = require("../../mcp/core/dispatch/tool-registry.js");
const {
  mcpToolNamesForRole,
} = require("../../mcp/core/dispatch/role-model.js");
const {
  evaluatorAgentNamesForCapabilityPacks,
} = require("../../mcp/core/capability/capability-packs.js");

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
const FANOUT_CHILD_SCOPE_GUARD_MATCHER = [
  "mcp__hacker-bob__bob_write_wave_handoff",
  "mcp__hacker-bob__bob_finalize_agent_run",
  "Agent",
  "Task",
].join("|");

function fanoutChildScopeGuardHookEntry() {
  return {
    matcher: FANOUT_CHILD_SCOPE_GUARD_MATCHER,
    hooks: [
      {
        type: "command",
        command: `node "${PROJECT_DIR_EXPR}/.claude/hooks/agent-run-stop.js"`,
        timeout: 5,
      },
    ],
  };
}

function mcpPermissionForTool(toolName) {
  return `mcp__hacker-bob__${toolName}`;
}

function permissionsForAllTools() {
  // Every registered tool is its own canonical bob_* primary, so every entry
  // in TOOLS surfaces one permission line.
  return TOOLS
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
  // Every registered tool is its own canonical bob_* primary; emit a
  // global-preapproval permission line for each one whose manifest opts in.
  return TOOLS
    .map((tool) => tool.name)
    .filter((toolName) => {
      const meta = TOOL_MANIFEST[toolName];
      return meta.global_preapproval === true;
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
      // Grep is a content-read surface too: without this, an agent could Grep the raw-PII
      // massread-evidence/ capture (or any blocked dir) the Read/Bash guards otherwise protect.
      matcher: "Grep",
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
    {
      // Edit/MultiEdit carry tool_input.file_path just like Write, so the
      // write guard's file_path branch classifies them unchanged. Without this
      // matcher Edit is an UNGUARDED write path to MCP-owned/audit-graded
      // session artifacts (the Write matcher alone does not cover Edit).
      matcher: "Edit|MultiEdit",
      hooks: [
        {
          type: "command",
          command: `bash "${PROJECT_DIR_EXPR}/.claude/hooks/session-write-guard.sh"`,
          timeout: 5,
        },
      ],
    },
    {
      // Opt-in "ask before writing" gate: INERT unless BOB_HTTP_WRITE_CONFIRM is truthy, then a
      // bob_http_scan call with a mutating method (POST/PUT/PATCH/DELETE) returns
      // permissionDecision:"ask" so the operator confirms before Bob writes to the target. Read
      // probes pass through. Ships everywhere (autonomous default preserved by the flag default-off).
      matcher: "mcp__hacker-bob__bob_http_scan",
      hooks: [
        {
          type: "command",
          command: `bash "${PROJECT_DIR_EXPR}/.claude/hooks/bob-http-write-confirm.sh"`,
          timeout: 5,
        },
      ],
    },
    // NS-7 defense in depth: the distinct child role already omits Agent/Task,
    // handoff, and finalize from generated frontmatter. The tracked hook also
    // attests the host-owned initial prompt and denies those calls if ambient
    // host permission inheritance ever presents one anyway. Root scope remains
    // usable only with its injected handoff-token prompt.
    fanoutChildScopeGuardHookEntry(),
  ];
}

// Every wave evaluator that writes a wave handoff + the BOB_AGENT_RUN_DONE marker
// gets the agent-run lifecycle hooks: the routed capability-pack evaluators PLUS
// the spawn-capable evaluator-fanout (CN Step B), which is dispatched per-surface
// in waves and finalizes the same way. spawnCapableAgentNames() is lazy-required
// from the (build-time-only) renderer to avoid a load-time cycle: the renderer
// already requires this config module at top level.
function subagentLifecycleAgentNames() {
  const { spawnCapableAgentNames } = require("../../scripts/lib/claude-role-renderer.js");
  return uniqueStrings([
    ...evaluatorAgentNamesForCapabilityPacks(),
    ...spawnCapableAgentNames(),
  ]);
}

// NS-7 — child completion is transcript-attested by SubagentStop, but the
// child must never receive SubagentStart: that hook writes the shared root's
// AgentRun identity. Keep the start set root-only and extend only the stop set.
function subagentStopAttestedAgentNames() {
  const { fanoutChildAgentNames } = require("../../scripts/lib/claude-role-renderer.js");
  return uniqueStrings([
    ...subagentLifecycleAgentNames(),
    ...fanoutChildAgentNames(),
  ]);
}

function defaultSubagentStopHooks() {
  return subagentStopAttestedAgentNames().map((evaluatorAgent) => (
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
  return subagentLifecycleAgentNames().map((evaluatorAgent) => (
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
  FANOUT_CHILD_SCOPE_GUARD_MATCHER,
  fanoutChildScopeGuardHookEntry,
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
