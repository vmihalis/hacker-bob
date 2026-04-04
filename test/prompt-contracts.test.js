const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");

function readFile(relativePath) {
  return fs.readFileSync(path.join(ROOT, relativePath), "utf8");
}

function parseFrontmatter(document, fileLabel) {
  const match = document.match(/^---\n([\s\S]*?)\n---\n/);
  assert.ok(match, `${fileLabel} is missing YAML frontmatter`);

  const frontmatter = {};
  for (const line of match[1].split("\n")) {
    const parsed = line.match(/^([A-Za-z0-9_]+):\s*(.*)$/);
    if (!parsed) continue;
    frontmatter[parsed[1]] = parsed[2];
  }
  return frontmatter;
}

test("hunter frontmatter excludes Write and still exposes wave handoff MCP tools", () => {
  const document = readFile(".claude/agents/hunter-agent.md");
  const frontmatter = parseFrontmatter(document, "hunter-agent.md");
  const tools = frontmatter.tools.split(/\s*,\s*/).filter(Boolean);

  assert.ok(!tools.includes("Write"));
  assert.ok(tools.includes("Bash"));
  assert.ok(tools.includes("mcp__bountyagent__bounty_write_wave_handoff"));
  assert.ok(tools.includes("mcp__bountyagent__bounty_record_finding"));
});

test("hunter and orchestrator prompts keep the structured handoff contract explicit", () => {
  const hunterPrompt = readFile(".claude/agents/hunter-agent.md");
  const orchestratorPrompt = readFile(".claude/commands/bountyagent.md");

  assert.match(hunterPrompt, /Do not manually create orchestrator-consumed handoff files\./);
  assert.match(hunterPrompt, /Durable hunt state must flow only through MCP tools\./);
  assert.match(orchestratorPrompt, /MCP-owned JSON artifacts are authoritative for orchestration\./);
  assert.match(orchestratorPrompt, /must never call `bounty_write_wave_handoff`/);
  assert.match(orchestratorPrompt, /must never synthesize or repair authoritative handoff JSON from markdown or `SESSION_HANDOFF\.md`/);
  assert.match(orchestratorPrompt, /Missing structured handoffs resolve only through `pending` or explicit `force-merge`\./);
});
