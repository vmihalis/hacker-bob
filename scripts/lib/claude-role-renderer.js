"use strict";

const fs = require("fs");
const path = require("path");
const {
  mcpPermissionForTool,
} = require("../../adapters/claude/config.js");
const {
  mcpToolNamesForRole,
  roleDefinition,
} = require("../../mcp/lib/role-model.js");

const DEFAULT_ROOT = path.join(__dirname, "..", "..");

const CLAUDE_ROLE_SPECS = Object.freeze({
  orchestrator: Object.freeze({
    role_id: "orchestrator",
    kind: "skill",
    output_path: path.join(".claude", "skills", "bountyagent", "SKILL.md"),
    name: "bob-hunt",
    disable_model_invocation: true,
    argument_hint: "[target-url | resume <domain> [force-merge]]",
    local_tools: Object.freeze(["Task", "Read"]),
  }),
  status: Object.freeze({
    role_id: "status",
    kind: "skill",
    output_path: path.join(".claude", "skills", "bountyagentstatus", "SKILL.md"),
    name: "bob-status",
    disable_model_invocation: true,
    argument_hint: "[--last | <target_domain>]",
    local_tools: Object.freeze([
      "Read",
      "Glob",
      "Bash(find *)",
      "Bash(ls *)",
      "Bash(node *)",
      "Bash(stat *)",
      "Bash(test *)",
    ]),
  }),
  debug: Object.freeze({
    role_id: "debug",
    kind: "skill",
    output_path: path.join(".claude", "skills", "bountyagentdebug", "SKILL.md"),
    name: "bob-debug",
    disable_model_invocation: true,
    argument_hint: "[--last | <target_domain>] [--deep]",
    local_tools: Object.freeze([
      "Read",
      "Glob",
      "Grep",
      "Bash(find *)",
      "Bash(ls *)",
      "Bash(stat *)",
      "Bash(test *)",
    ]),
  }),
  recon: Object.freeze({
    role_id: "recon",
    kind: "agent",
    output_path: path.join(".claude", "agents", "recon-agent.md"),
    name: "recon-agent",
    description: "Runs full recon pipeline \u2014 subdomain enum, live hosts, archived URLs, nuclei, JS extraction \u2014 and produces attack_surface.json",
    model: "opus",
    color: "cyan",
    local_tools: Object.freeze(["Bash", "Read", "Write", "Glob", "Grep"]),
  }),
  hunter: Object.freeze({
    role_id: "hunter",
    kind: "agent",
    output_path: path.join(".claude", "agents", "hunter-agent.md"),
    name: "hunter-agent",
    description: "Tests one attack surface for vulnerabilities \u2014 spawned per-surface with injected context from the orchestrator",
    model: "opus",
    color: "yellow",
    max_turns: 200,
    background: true,
    mcp_server: true,
    local_tools: Object.freeze(["Bash", "Read", "Grep", "Glob"]),
  }),
  chain: Object.freeze({
    role_id: "chain",
    kind: "agent",
    output_path: path.join(".claude", "agents", "chain-builder.md"),
    name: "chain-builder",
    description: "Analyzes proven findings for credible exploit chains that elevate severity",
    model: "opus",
    color: "purple",
    mcp_server: true,
    local_tools: Object.freeze(["Write"]),
  }),
  "brutalist-verifier": Object.freeze({
    role_id: "brutalist-verifier",
    kind: "agent",
    output_path: path.join(".claude", "agents", "brutalist-verifier.md"),
    name: "brutalist-verifier",
    description: "Round 1 verification \u2014 re-runs PoCs with maximum skepticism, checks severity inflation, filters non-bugs",
    model: "sonnet",
    color: "red",
    mcp_server: true,
    local_tools: Object.freeze(["Bash", "Read"]),
  }),
  "balanced-verifier": Object.freeze({
    role_id: "balanced-verifier",
    kind: "agent",
    output_path: path.join(".claude", "agents", "balanced-verifier.md"),
    name: "balanced-verifier",
    description: "Round 2 verification \u2014 reviews brutalist decisions for false negatives and severity over-corrections",
    model: "opus",
    color: "blue",
    mcp_server: true,
    local_tools: Object.freeze(["Bash", "Read"]),
  }),
  "final-verifier": Object.freeze({
    role_id: "final-verifier",
    kind: "agent",
    output_path: path.join(".claude", "agents", "final-verifier.md"),
    name: "final-verifier",
    description: "Round 3 verification \u2014 re-runs only REPORTABLE findings with fresh requests as final confirmation",
    model: "sonnet",
    color: "green",
    mcp_server: true,
    local_tools: Object.freeze(["Bash"]),
  }),
  grader: Object.freeze({
    role_id: "grader",
    kind: "agent",
    output_path: path.join(".claude", "agents", "grader.md"),
    name: "grader",
    description: "Scores verified findings on 5 axes and issues SUBMIT/HOLD/SKIP verdict",
    model: "sonnet",
    color: "orange",
    mcp_server: true,
    local_tools: Object.freeze([]),
  }),
  reporter: Object.freeze({
    role_id: "reporter",
    kind: "agent",
    output_path: path.join(".claude", "agents", "report-writer.md"),
    name: "report-writer",
    description: "Generates submission-ready bug bounty report from verified and graded findings",
    model: "sonnet",
    color: "green",
    mcp_server: true,
    local_tools: Object.freeze(["Write"]),
  }),
});

function uniqueStrings(values) {
  return Array.from(new Set(values.filter((value) => typeof value === "string" && value.trim())));
}

function claudeMcpToolsForRole(roleId) {
  return mcpToolNamesForRole(roleId).map(mcpPermissionForTool);
}

function claudeAllowedToolsForRole(roleId) {
  const spec = CLAUDE_ROLE_SPECS[roleId];
  if (!spec) throw new Error(`Missing Claude role spec for ${roleId}`);
  return uniqueStrings([
    ...(spec.local_tools || []),
    ...claudeMcpToolsForRole(roleId),
  ]);
}

function renderSkillFrontmatter(spec) {
  const allowedTools = claudeAllowedToolsForRole(spec.role_id);
  return [
    "---",
    `name: ${spec.name}`,
    `disable-model-invocation: ${spec.disable_model_invocation ? "true" : "false"}`,
    `argument-hint: ${JSON.stringify(spec.argument_hint)}`,
    "allowed-tools:",
    ...allowedTools.map((tool) => `  - ${tool}`),
    "---",
  ].join("\n");
}

function renderAgentFrontmatter(spec) {
  const lines = [
    "---",
    `name: ${spec.name}`,
    `description: ${spec.description}`,
    `tools: ${claudeAllowedToolsForRole(spec.role_id).join(", ")}`,
    `model: ${spec.model}`,
    `color: ${spec.color}`,
  ];
  if (spec.max_turns) lines.push(`maxTurns: ${spec.max_turns}`);
  if (spec.background) lines.push("background: true");
  if (spec.mcp_server) {
    lines.push(
      "mcpServers:",
      "  - bountyagent",
      "requiredMcpServers:",
      "  - bountyagent",
    );
  }
  lines.push("---");
  return lines.join("\n");
}

function roleBody(roleId, { root = DEFAULT_ROOT } = {}) {
  const role = roleDefinition(roleId);
  const body = fs.readFileSync(path.join(root, role.prompt_body), "utf8").replace(/^\n+/, "");
  return renderClaudePromptBody(roleId, body);
}

function renderClaudePromptBody(roleId, body) {
  if (roleId !== "status") return body;
  return body.replace(
    "{{STATUS_UPDATE_CACHE_COMMAND}}",
    'node "$CLAUDE_PROJECT_DIR/.claude/hooks/bob-update.js" status "$CLAUDE_PROJECT_DIR" --json',
  );
}

function renderClaudeRole(roleId, options = {}) {
  const spec = CLAUDE_ROLE_SPECS[roleId];
  if (!spec) throw new Error(`Missing Claude role spec for ${roleId}`);
  const frontmatter = spec.kind === "skill"
    ? renderSkillFrontmatter(spec)
    : renderAgentFrontmatter(spec);
  const separator = spec.kind === "agent" ? "\n\n" : "\n";
  return `${frontmatter}${separator}${roleBody(roleId, options)}`;
}

function claudeRoleOutputPath(roleId, { root = DEFAULT_ROOT } = {}) {
  const spec = CLAUDE_ROLE_SPECS[roleId];
  if (!spec) throw new Error(`Missing Claude role spec for ${roleId}`);
  return path.join(root, spec.output_path);
}

function updateClaudeRoleFile(roleId, { check = false, root = DEFAULT_ROOT } = {}) {
  const filePath = claudeRoleOutputPath(roleId, { root });
  const document = fs.readFileSync(filePath, "utf8");
  const nextDocument = renderClaudeRole(roleId, { root });
  if (document === nextDocument) return false;
  if (check) {
    throw new Error(`${path.relative(root, filePath)} is stale; run node scripts/generate-claude-roles.js`);
  }
  fs.writeFileSync(filePath, nextDocument, "utf8");
  return true;
}

function updateClaudeRoleFiles({ check = false, root = DEFAULT_ROOT, roleIds = Object.keys(CLAUDE_ROLE_SPECS) } = {}) {
  let changed = false;
  for (const roleId of roleIds) {
    changed = updateClaudeRoleFile(roleId, { check, root }) || changed;
  }
  return changed;
}

module.exports = {
  CLAUDE_ROLE_SPECS,
  claudeAllowedToolsForRole,
  claudeMcpToolsForRole,
  claudeRoleOutputPath,
  renderClaudePromptBody,
  renderClaudeRole,
  updateClaudeRoleFile,
  updateClaudeRoleFiles,
};
