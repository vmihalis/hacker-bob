"use strict";

const fs = require("fs");
const path = require("path");
const {
  roleDefinition,
} = require("../../mcp/lib/role-model.js");

const DEFAULT_ROOT = path.join(__dirname, "..", "..");

const CODEX_SKILL_SPECS = Object.freeze({
  hunt: Object.freeze({
    role_id: "orchestrator",
    output_path: path.join("adapters", "codex", "hacker-bob", "skills", "hunt", "SKILL.md"),
    name: "hunt",
    description: "Run or resume a Hacker Bob bug bounty hunt in Codex using the shared MCP runtime.",
  }),
  status: Object.freeze({
    role_id: "status",
    output_path: path.join("adapters", "codex", "hacker-bob", "skills", "status", "SKILL.md"),
    name: "status",
    description: "Read Hacker Bob session state, wave status, findings, verification, and grade summaries in Codex.",
  }),
  debug: Object.freeze({
    role_id: "debug",
    output_path: path.join("adapters", "codex", "hacker-bob", "skills", "debug", "SKILL.md"),
    name: "debug",
    description: "Debug Hacker Bob sessions in Codex using MCP telemetry and local session artifacts.",
  }),
  update: Object.freeze({
    output_path: path.join("adapters", "codex", "hacker-bob", "skills", "update", "SKILL.md"),
    name: "update",
    description: "Check for Hacker Bob package updates and guide project-local update installation from Codex.",
  }),
});

function renderFrontmatter(spec) {
  return [
    "---",
    `name: ${spec.name}`,
    `description: ${spec.description}`,
    "---",
  ].join("\n");
}

function roleBody(roleId, { root = DEFAULT_ROOT } = {}) {
  const role = roleDefinition(roleId);
  return fs.readFileSync(path.join(root, role.prompt_body), "utf8").replace(/^\n+/, "");
}

function renderCodexPromptBody(roleId, body) {
  return body
    .replace(
      "{{STATUS_UPDATE_CACHE_COMMAND}}",
      "node -e \"const update=require('./mcp/lib/update-check.js'); console.log(JSON.stringify(update.readUpdateCache(process.cwd()) || null, null, 2));\"",
    )
    .replace(/Claude `SubagentStop` is only an adapter guardrail/g, "Host stop hooks are only adapter guardrails")
    .replace(/Claude Code enforces `maxTurns` as a turn budget, not a raw tool-call budget\./g, "The host may enforce turn budgets differently from raw tool-call budgets.")
    .replace(/Paste in Claude Code\./g, "Paste in the current Codex session.")
    .replace(/for Claude compatibility/g, "for host compatibility")
    .replace(/Claude transcript windows/g, "Codex session log windows")
    .replace(/Claude transcripts/g, "Codex session logs")
    .replace(/Claude transcript JSONL files/g, "Codex session log files")
    .replace(/Claude project JSONL files/g, "Codex session log files")
    .replace(/Claude Code/g, "Codex")
    .replace(/\/bob-hunt/g, "$hacker-bob:hunt")
    .replace(/\/bob-status/g, "$hacker-bob:status")
    .replace(/\/bob-debug/g, "$hacker-bob:debug")
    .replace(/\/bob-update/g, "$hacker-bob:update")
    .replace(/\/bob:hunt/g, "$hacker-bob:hunt")
    .replace(/\/bob:status/g, "$hacker-bob:status")
    .replace(/\/bob:debug/g, "$hacker-bob:debug")
    .replace(/\/bob:update/g, "$hacker-bob:update");
}

function renderUpdateSkill() {
  return [
    "# Hacker Bob Update",
    "",
    "Use this when the operator asks to check, plan, or apply Hacker Bob updates from Codex.",
    "",
    "## Read Cache",
    "Read the passive local cache without network access:",
    "```bash",
    "node -e \"const update=require('./mcp/lib/update-check.js'); console.log(JSON.stringify(update.readUpdateCache(process.cwd()) || null, null, 2));\"",
    "```",
    "",
    "## Check Latest",
    "Run this only when the operator explicitly asks to check for updates:",
    "```bash",
    "node -e \"const update=require('./mcp/lib/update-check.js'); update.checkForUpdate(process.cwd(), { includeChangelog: true }).then((result) => console.log(update.renderUpdatePlan(result))).catch((error) => { console.error(error.message || String(error)); process.exit(1); });\"",
    "```",
    "",
    "## Apply Update",
    "Ask before updating. When confirmed, run from the project root:",
    "```bash",
    "npx -y hacker-bob@latest install \"$PWD\"",
    "```",
    "",
    "After installation, tell the operator to restart Codex in this project before continuing.",
    "",
  ].join("\n");
}

function renderCodexSkill(skillId, options = {}) {
  const spec = CODEX_SKILL_SPECS[skillId];
  if (!spec) throw new Error(`Missing Codex skill spec for ${skillId}`);
  const body = spec.role_id
    ? renderCodexPromptBody(spec.role_id, roleBody(spec.role_id, options))
    : renderUpdateSkill();
  return `${renderFrontmatter(spec)}\n\n${body}`;
}

function codexSkillOutputPath(skillId, { root = DEFAULT_ROOT } = {}) {
  const spec = CODEX_SKILL_SPECS[skillId];
  if (!spec) throw new Error(`Missing Codex skill spec for ${skillId}`);
  return path.join(root, spec.output_path);
}

function updateCodexSkillFile(skillId, { check = false, root = DEFAULT_ROOT } = {}) {
  const filePath = codexSkillOutputPath(skillId, { root });
  const nextDocument = renderCodexSkill(skillId, { root });
  const document = fs.existsSync(filePath) ? fs.readFileSync(filePath, "utf8") : null;
  if (document === nextDocument) return false;
  if (check) {
    throw new Error(`${path.relative(root, filePath)} is stale; run node scripts/generate-codex-skills.js`);
  }
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, nextDocument, "utf8");
  return true;
}

function updateCodexSkillFiles({ check = false, root = DEFAULT_ROOT, skillIds = Object.keys(CODEX_SKILL_SPECS) } = {}) {
  let changed = false;
  for (const skillId of skillIds) {
    changed = updateCodexSkillFile(skillId, { check, root }) || changed;
  }
  return changed;
}

module.exports = {
  CODEX_SKILL_SPECS,
  codexSkillOutputPath,
  renderCodexPromptBody,
  renderCodexSkill,
  updateCodexSkillFile,
  updateCodexSkillFiles,
};
