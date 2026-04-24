const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { TOOLS, TOOL_MANIFEST } = require("../mcp/server.js");
const {
  bountyagentSkillAllowedTools,
  defaultClaudeSettings,
  defaultGlobalMcpPermissions,
  isOrchestratorOnlyMutator,
  permissionsForRoleBundles,
} = require("../mcp/lib/claude-config.js");

const ROOT = path.join(__dirname, "..");

function readFile(relativePath) {
  return fs.readFileSync(path.join(ROOT, relativePath), "utf8");
}

function lineCount(relativePath) {
  return readFile(relativePath).trimEnd().split(/\r?\n/).length;
}

function sourceAllowedMcpTools() {
  const settings = JSON.parse(readFile(".claude/settings.json"));
  return new Set(
    settings.permissions.allow
      .filter((tool) => tool.startsWith("mcp__bountyagent__"))
      .map((tool) => tool.replace(/^mcp__bountyagent__/, "")),
  );
}

function scriptAllowedMcpTools(relativePath) {
  return new Set(
    Array.from(readFile(relativePath).matchAll(/"mcp__bountyagent__(bounty_[A-Za-z0-9_]+)"/g))
      .map((match) => match[1]),
  );
}

function generatedAllowedMcpTools() {
  return new Set(
    defaultClaudeSettings().permissions.allow
      .filter((tool) => tool.startsWith("mcp__bountyagent__"))
      .map((tool) => tool.replace(/^mcp__bountyagent__/, "")),
  );
}

function orchestratorReferencedMcpTools() {
  return new Set(
    Array.from(readFile(".claude/skills/bountyagent/SKILL.md").matchAll(/\b(bounty_[A-Za-z0-9_]+)\b/g))
      .map((match) => match[1]),
  );
}

function allMarkdown(relativeDir) {
  return fs.readdirSync(path.join(ROOT, relativeDir))
    .filter((name) => name.endsWith(".md"))
    .map((name) => path.join(relativeDir, name));
}

function settingsHookMatchers() {
  const settings = JSON.parse(readFile(".claude/settings.json"));
  return new Set((settings.hooks.PreToolUse || []).map((entry) => entry.matcher));
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

function parseYamlListFrontmatter(document, key, fileLabel) {
  const match = document.match(/^---\n([\s\S]*?)\n---\n/);
  assert.ok(match, `${fileLabel} is missing YAML frontmatter`);
  const lines = match[1].split("\n");
  const start = lines.findIndex((line) => line === `${key}:`);
  assert.notEqual(start, -1, `${fileLabel} is missing ${key}`);
  const values = [];
  for (let index = start + 1; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.startsWith("  - ")) break;
    values.push(line.slice(4));
  }
  return values;
}

test("hunter frontmatter excludes Write and still exposes wave handoff MCP tools", () => {
  const document = readFile(".claude/agents/hunter-agent.md");
  const frontmatter = parseFrontmatter(document, "hunter-agent.md");
  const tools = frontmatter.tools.split(/\s*,\s*/).filter(Boolean);

  assert.ok(!tools.includes("Write"));
  assert.ok(tools.includes("Bash"));
  assert.ok(tools.includes("mcp__bountyagent__bounty_write_wave_handoff"));
  assert.ok(tools.includes("mcp__bountyagent__bounty_record_finding"));
  assert.ok(tools.includes("mcp__bountyagent__bounty_list_auth_profiles"));
  assert.ok(tools.includes("mcp__bountyagent__bounty_log_coverage"));
  assert.ok(tools.includes("mcp__bountyagent__bounty_read_http_audit"));
  assert.ok(tools.includes("mcp__bountyagent__bounty_import_static_artifact"));
  assert.ok(tools.includes("mcp__bountyagent__bounty_static_scan"));
  assert.ok(!tools.includes("mcp__bountyagent__bounty_import_http_traffic"));
  assert.ok(!tools.includes("mcp__bountyagent__bounty_public_intel"));
  assert.ok(!tools.includes("mcp__bountyagent__bounty_auth_manual"));
  assert.ok(!tools.includes("mcp__bountyagent__bounty_read_handoff"));
});

test("manifest, settings, and generated Claude config keep global MCP permissions narrowed", () => {
  const manifestTools = new Set(Object.keys(TOOL_MANIFEST));
  const registeredTools = new Set(TOOLS.map((tool) => tool.name));
  const sourceAllowed = sourceAllowedMcpTools();
  const generatedAllowed = generatedAllowedMcpTools();
  const expectedGlobalAllowed = new Set(
    defaultGlobalMcpPermissions().map((tool) => tool.replace(/^mcp__bountyagent__/, "")),
  );

  assert.deepEqual([...manifestTools].sort(), [...registeredTools].sort());
  assert.deepEqual([...sourceAllowed].sort(), [...expectedGlobalAllowed].sort());
  assert.deepEqual([...generatedAllowed].sort(), [...expectedGlobalAllowed].sort());

  for (const [toolName, metadata] of Object.entries(TOOL_MANIFEST)) {
    assert.equal(typeof metadata.global_preapproval, "boolean", `${toolName} missing global_preapproval`);
    assert.equal(
      sourceAllowed.has(toolName),
      metadata.global_preapproval,
      `${toolName} source global preapproval mismatch`,
    );
    assert.equal(
      generatedAllowed.has(toolName),
      metadata.global_preapproval,
      `${toolName} generated global preapproval mismatch`,
    );
    if (isOrchestratorOnlyMutator(toolName)) {
      assert.ok(!sourceAllowed.has(toolName), `${toolName} should not be globally pre-approved`);
    }
  }
  assert.equal(TOOL_MANIFEST.bounty_merge_wave_handoffs.global_preapproval, false);
  assert.equal(TOOL_MANIFEST.bounty_merge_wave_handoffs.mutating, false);
  assert.ok(!sourceAllowed.has("bounty_merge_wave_handoffs"));
  assert.ok(!generatedAllowed.has("bounty_merge_wave_handoffs"));
  assert.ok(sourceAllowed.has("bounty_wave_handoff_status"));

  const hookMatchers = settingsHookMatchers();
  for (const [toolName, metadata] of Object.entries(TOOL_MANIFEST)) {
    if (!metadata.hook_required) continue;
    assert.ok(hookMatchers.has(`mcp__bountyagent__${toolName}`), `${toolName} requires a scope hook`);
  }
});

test("MCP-dependent agents declare official mcpServers bountyagent metadata", () => {
  const agents = [
    "hunter-agent",
    "brutalist-verifier",
    "balanced-verifier",
    "final-verifier",
    "grader",
    "chain-builder",
    "report-writer",
  ];
  for (const agent of agents) {
    const document = readFile(`.claude/agents/${agent}.md`);
    assert.match(
      document,
      /mcpServers:\s*\n\s*-\s*bountyagent/,
      `${agent}.md missing mcpServers: bountyagent`
    );
  }
});

test("recon-agent remains MCP-free", () => {
  const document = readFile(".claude/agents/recon-agent.md");
  assert.doesNotMatch(document, /mcpServers:/);
  assert.doesNotMatch(document, /requiredMcpServers:/);
  assert.doesNotMatch(document, /mcp__/i);
});

test("global rules stay small and keep scope plus MCP-owned artifact guardrails", () => {
  for (const ruleFile of [".claude/rules/hunting.md", ".claude/rules/reporting.md"]) {
    const document = readFile(ruleFile);
    assert.ok(lineCount(ruleFile) <= 60, `${ruleFile} is too large for always-active context`);
    assert.match(document, /scope/i, `${ruleFile} must mention scope`);
    assert.match(document, /MCP-owned artifacts/i, `${ruleFile} must mention MCP-owned artifacts`);
  }
});

test("bountyagent skill stays orchestration-sized and preserves FSM shape", () => {
  const orchestrator = readFile(".claude/skills/bountyagent/SKILL.md");
  assert.ok(lineCount(".claude/skills/bountyagent/SKILL.md") <= 240, "bountyagent skill is too large");
  assert.match(orchestrator, /RECON\s*→\s*AUTH\s*→\s*HUNT\s*→\s*CHAIN\s*→\s*VERIFY\s*→\s*GRADE\s*→\s*REPORT/);
  for (const phase of ["RECON", "AUTH", "HUNT", "CHAIN", "VERIFY", "GRADE", "REPORT", "EXPLORE"]) {
    assert.match(orchestrator, new RegExp(`PHASE [0-9]+: ${phase}|${phase}`), `missing ${phase}`);
  }
  assert.match(orchestrator, /must never call `bounty_write_wave_handoff`/);
  assert.match(orchestrator, /must never write handoff JSON directly/);
});

test("orchestrator validates brutalist and balanced rounds before proceeding", () => {
  const orchestrator = readFile(".claude/skills/bountyagent/SKILL.md");
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

test("prompts do not tell agents to read auth.json directly", () => {
  for (const relativePath of [
    ".claude/commands/bountyagent.md",
    ".claude/skills/bountyagent/SKILL.md",
    ...allMarkdown(".claude/agents"),
  ]) {
    const document = readFile(relativePath);
    assert.doesNotMatch(document, /auth\.json/i, `${relativePath} should use auth MCP tools`);
  }
});

test("chain-builder uses structured handoffs without Bash or markdown dependency", () => {
  const document = readFile(".claude/agents/chain-builder.md");
  const frontmatter = parseFrontmatter(document, "chain-builder.md");
  const tools = frontmatter.tools.split(/\s*,\s*/).filter(Boolean);

  assert.ok(!tools.includes("Bash"));
  assert.ok(tools.includes("mcp__bountyagent__bounty_read_wave_handoffs"));
  assert.match(document, /bounty_read_wave_handoffs/);
  assert.doesNotMatch(document, /handoff-w\*\.md/);
});

test("orchestrator has no blanket bypassPermissions rule", () => {
  const orchestrator = readFile(".claude/skills/bountyagent/SKILL.md");
  assert.doesNotMatch(orchestrator, /Every Agent tool call MUST use `mode: "bypassPermissions"`/);
  assert.doesNotMatch(orchestrator, /mode:\s*"bypassPermissions"/);
});

test("bountyagent skill allowed-tools match orchestrator and auth bundles", () => {
  const skill = readFile(".claude/skills/bountyagent/SKILL.md");
  const allowedTools = parseYamlListFrontmatter(skill, "allowed-tools", "bountyagent/SKILL.md");
  const expectedTools = bountyagentSkillAllowedTools();
  assert.deepEqual(allowedTools.sort(), expectedTools.slice().sort());
  assert.deepEqual(
    allowedTools.filter((tool) => tool.startsWith("mcp__bountyagent__")).sort(),
    permissionsForRoleBundles(["orchestrator", "auth"]).sort(),
  );
  assert.ok(allowedTools.includes("Task"));
  assert.ok(allowedTools.includes("Read"));
  assert.ok(allowedTools.includes("mcp__bountyagent__bounty_merge_wave_handoffs"));
  assert.ok(!allowedTools.includes("mcp__bountyagent__bounty_write_wave_handoff"));
});

test("root-orchestrator MCP calls are covered by skill allowed-tools", () => {
  const allowedTools = new Set(parseYamlListFrontmatter(
    readFile(".claude/skills/bountyagent/SKILL.md"),
    "allowed-tools",
    "bountyagent/SKILL.md",
  ).filter((tool) => tool.startsWith("mcp__bountyagent__"))
    .map((tool) => tool.replace(/^mcp__bountyagent__/, "")));

  for (const tool of orchestratorReferencedMcpTools()) {
    const metadata = TOOL_MANIFEST[tool];
    if (!metadata || (!metadata.role_bundles.includes("orchestrator") && !metadata.role_bundles.includes("auth"))) {
      continue;
    }
    assert.ok(allowedTools.has(tool), `${tool} missing from bountyagent skill allowed-tools`);
  }
});

test("recon agent preserves exactly seven Bash collection calls", () => {
  const reconPrompt = readFile(".claude/agents/recon-agent.md");
  const bashBlocks = Array.from(reconPrompt.matchAll(/```bash\n/g));

  assert.equal(bashBlocks.length, 7);
  assert.match(reconPrompt, /Use exactly the 7 Bash calls below, in order/);
  assert.match(reconPrompt, /Do not make any additional Bash calls/);
});

test("recon attack_surface schema keeps required fields and adds optional enrichment", () => {
  const reconPrompt = readFile(".claude/agents/recon-agent.md");

  for (const field of [
    "id",
    "hosts",
    "tech_stack",
    "endpoints",
    "interesting_params",
    "nuclei_hits",
    "priority",
  ]) {
    assert.match(reconPrompt, new RegExp(`"${field}"`), `missing required field ${field}`);
  }

  for (const field of [
    "surface_type",
    "bug_class_hints",
    "high_value_flows",
    "evidence",
    "ranking",
  ]) {
    assert.match(reconPrompt, new RegExp(`"${field}"`), `missing optional field ${field}`);
  }

  assert.match(reconPrompt, /Required per-surface fields remain/);
  assert.match(reconPrompt, /Optional enrichment fields are additive/);
});

test("recon prompt remains enrichment-only without new commands or imported toolsets", () => {
  const reconPrompt = readFile(".claude/agents/recon-agent.md");

  assert.doesNotMatch(reconPrompt, /\/bountyagent/);
  assert.doesNotMatch(reconPrompt, /slash commands?/i);
  assert.doesNotMatch(reconPrompt, /claude-bug-bounty/i);
  assert.doesNotMatch(reconPrompt, /scripts\/|tools\//i);
  assert.doesNotMatch(reconPrompt, /mcp__/i);
});

test("installer and dev-sync copy and configure session-write-guard", () => {
  const install = readFile("install.sh");
  const devSync = readFile("dev-sync.sh");

  assert.match(install, /cp "\$SCRIPT_DIR\/\.claude\/hooks\/session-write-guard\.sh"/);
  assert.match(devSync, /cp "\$SCRIPT_DIR\/\.claude\/hooks\/session-write-guard\.sh"/);
  assert.match(install, /cp "\$SCRIPT_DIR\/\.claude\/hooks\/hunter-subagent-stop\.js"/);
  assert.match(devSync, /cp "\$SCRIPT_DIR\/\.claude\/hooks\/hunter-subagent-stop\.js"/);
  assert.match(install, /\.claude\/skills\/bountyagent\/SKILL\.md/);
  assert.match(devSync, /\.claude\/skills\/bountyagent\/SKILL\.md/);
  assert.match(install, /mcp\/lib\/tools/);
  assert.match(devSync, /mcp\/lib\/tools/);
  assert.match(install, /merge-claude-config\.js/);
  assert.match(devSync, /merge-claude-config\.js/);

  const hookText = JSON.stringify(defaultClaudeSettings().hooks.PreToolUse);
  assert.match(hookText, /"matcher":"Bash"[\s\S]*session-write-guard\.sh/);
  assert.match(hookText, /"matcher":"Write"[\s\S]*session-write-guard\.sh/);
  assert.match(JSON.stringify(defaultClaudeSettings().hooks.SubagentStop), /hunter-subagent-stop\.js/);
});

test("verifier and grader examples use F-N finding IDs", () => {
  for (const agent of ["brutalist-verifier", "balanced-verifier", "final-verifier", "grader"]) {
    const document = readFile(`.claude/agents/${agent}.md`);
    assert.doesNotMatch(document, /\bw\d+-a\d+-\d+\b/, `${agent}.md contains stale wave-agent finding IDs`);
    assert.match(document, /finding_id:\s*"F-\d+"/, `${agent}.md missing F-N finding_id example`);
  }
});

test("verifiers can read request audit summaries without direct file access", () => {
  for (const agent of ["brutalist-verifier", "balanced-verifier", "final-verifier"]) {
    const document = readFile(`.claude/agents/${agent}.md`);
    const frontmatter = parseFrontmatter(document, `${agent}.md`);
    assert.match(frontmatter.tools, /mcp__bountyagent__bounty_read_http_audit/);
    assert.match(document, /bounty_read_http_audit/);
    assert.doesNotMatch(document, /http-audit\.jsonl/);
  }
});

test("orchestrator documents --no-auth flag and skips AUTH when set", () => {
  const orchestrator = readFile(".claude/skills/bountyagent/SKILL.md");
  assert.match(
    orchestrator,
    /--no-auth/,
    "Missing --no-auth flag documentation"
  );
  assert.match(
    orchestrator,
    /--no-auth.*skip/is,
    "Missing --no-auth skip behavior"
  );
  assert.match(
    orchestrator,
    /auth_status.*unauthenticated/,
    "Missing unauthenticated transition when --no-auth is set"
  );
});

test("orchestrator documents checkpoint modes and MCP-owned traffic/audit/intel/static state", () => {
  const orchestrator = readFile(".claude/skills/bountyagent/SKILL.md");

  assert.match(orchestrator, /--paranoid/);
  assert.match(orchestrator, /--normal/);
  assert.match(orchestrator, /--yolo/);
  assert.match(orchestrator, /If no checkpoint flag is supplied, use `--normal`/);
  assert.match(orchestrator, /bounty_import_http_traffic[\s\S]*traffic\.jsonl/);
  assert.match(orchestrator, /bounty_http_scan[\s\S]*http-audit\.jsonl/);
  assert.match(orchestrator, /bounty_public_intel[\s\S]*public-intel\.json/);
  assert.match(orchestrator, /bounty_import_static_artifact[\s\S]*static-imports/);
  assert.match(orchestrator, /bounty_static_scan[\s\S]*static-scan-results\.jsonl/);
});

test("hunter and orchestrator prompts keep the structured handoff contract explicit", () => {
  const hunterPrompt = readFile(".claude/agents/hunter-agent.md");
  const orchestratorPrompt = readFile(".claude/skills/bountyagent/SKILL.md");

  assert.match(hunterPrompt, /surface_type[\s\S]*bug_class_hints[\s\S]*high_value_flows/);
  assert.match(orchestratorPrompt, /surface_type[\s\S]*bug_class_hints[\s\S]*high_value_flows/);
  assert.match(hunterPrompt, /traffic_summary[\s\S]*audit_summary[\s\S]*circuit_breaker_summary[\s\S]*ranking_summary[\s\S]*intel_hints[\s\S]*static_scan_hints/);
  assert.match(hunterPrompt, /Prefer real observed authenticated endpoints from `traffic_summary`/);
  assert.match(hunterPrompt, /Log coverage before switching away from a promising traffic-derived endpoint|log coverage before switching away from promising traffic-derived endpoints/i);
  assert.match(orchestratorPrompt, /traffic_summary[\s\S]*audit_summary[\s\S]*circuit_breaker_summary[\s\S]*ranking_summary[\s\S]*intel_hints[\s\S]*static_scan_hints/);
  assert.match(hunterPrompt, /bounty_import_static_artifact[\s\S]*bounty_static_scan/);
  assert.match(hunterPrompt, /never pass or scan arbitrary filesystem paths/i);
  assert.match(hunterPrompt, /Do not manually create orchestrator-consumed handoff files\./);
  assert.match(hunterPrompt, /BOB_HUNTER_DONE/);
  assert.match(orchestratorPrompt, /BOB_HUNTER_DONE/);
  assert.match(hunterPrompt, /Durable hunt state must flow only through MCP tools\./);
  assert.match(hunterPrompt, /bounty_log_coverage/);
  assert.match(hunterPrompt, /never write `coverage\.jsonl` through Bash/);
  assert.match(hunterPrompt, /Never create or backfill[\s\S]*http-audit\.jsonl[\s\S]*traffic\.jsonl[\s\S]*public-intel\.json[\s\S]*static-artifacts\.jsonl[\s\S]*static-scan-results\.jsonl/);
  assert.match(hunterPrompt, /status` \(`tested`, `blocked`, `promising`, `needs_auth`, or `requeue`\)/);
  assert.match(orchestratorPrompt, /MCP-owned JSON artifacts are authoritative for orchestration\./);
  assert.match(orchestratorPrompt, /must never call `bounty_write_wave_handoff`/);
  assert.match(orchestratorPrompt, /must never synthesize or repair authoritative handoff JSON from markdown or `SESSION_HANDOFF\.md`/);
  assert.match(orchestratorPrompt, /Missing structured handoffs resolve only through `pending` or explicit `force-merge`\./);
  assert.match(orchestratorPrompt, /bounty_log_coverage/);
  assert.match(orchestratorPrompt, /never write `coverage\.jsonl` through Bash/);
});
