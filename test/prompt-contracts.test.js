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

test("chain-builder and report-writer declare requiredMcpServers bountyagent", () => {
  for (const agent of ["chain-builder", "report-writer"]) {
    const document = readFile(`.claude/agents/${agent}.md`);
    assert.match(
      document,
      /requiredMcpServers:\s*\n\s*-\s*bountyagent/,
      `${agent}.md missing requiredMcpServers: bountyagent`
    );
  }
});

test("all MCP-writing agents declare requiredMcpServers bountyagent", () => {
  const agents = [
    "hunter-agent",
    "brutalist-verifier",
    "balanced-verifier",
    "final-verifier",
    "grader",
  ];
  for (const agent of agents) {
    const document = readFile(`.claude/agents/${agent}.md`);
    assert.match(
      document,
      /requiredMcpServers:\s*\n\s*-\s*bountyagent/,
      `${agent}.md missing requiredMcpServers: bountyagent`
    );
  }
});

test("orchestrator validates brutalist and balanced rounds before proceeding", () => {
  const orchestrator = readFile(".claude/commands/bountyagent.md");
  assert.match(
    orchestrator,
    /After the brutalist agent completes, validate/,
    "Missing post-brutalist validation"
  );
  assert.match(
    orchestrator,
    /bounty_read_verification_round.*round.*brutalist/,
    "Missing brutalist read-back validation call"
  );
  assert.match(
    orchestrator,
    /After the balanced agent completes, validate/,
    "Missing post-balanced validation"
  );
  assert.match(
    orchestrator,
    /bounty_read_verification_round.*round.*balanced/,
    "Missing balanced read-back validation call"
  );
});

test("settings.json registers session-write-guard for Bash and Write", () => {
  const settings = JSON.parse(readFile(".claude/settings.json"));
  const preToolUse = settings.hooks.PreToolUse;

  const bashEntry = preToolUse.find((e) => e.matcher === "Bash");
  assert.ok(bashEntry, "No Bash matcher in PreToolUse");
  assert.ok(
    bashEntry.hooks.some((h) => h.command.includes("session-write-guard.sh")),
    "session-write-guard.sh not registered for Bash"
  );

  const writeEntry = preToolUse.find((e) => e.matcher === "Write");
  assert.ok(writeEntry, "No Write matcher in PreToolUse");
  assert.ok(
    writeEntry.hooks.some((h) => h.command.includes("session-write-guard.sh")),
    "session-write-guard.sh not registered for Write"
  );
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
