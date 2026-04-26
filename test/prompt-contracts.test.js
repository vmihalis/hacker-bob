const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { TOOLS, TOOL_MANIFEST } = require("../mcp/server.js");
const {
  ADAPTERS,
  getAdapter,
} = require("../adapters/index.js");
const {
  bountyagentSkillAllowedTools,
  defaultClaudeSettings,
  defaultGlobalMcpPermissions,
  isOrchestratorOnlyMutator,
  permissionsForRoleBundles,
} = require("../adapters/claude/config.js");
const {
  allRoleDefinitions,
  mcpToolNamesForRole,
} = require("../mcp/lib/role-model.js");
const {
  CLAUDE_ROLE_SPECS,
  renderClaudeRole,
} = require("../scripts/lib/claude-role-renderer.js");
const {
  CODEX_SKILL_SPECS,
  renderCodexSkill,
} = require("../scripts/lib/codex-role-renderer.js");

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
    Array.from(readFile(".claude/skills/bob-hunt/SKILL.md").matchAll(/\b(bounty_[A-Za-z0-9_]+)\b/g))
      .map((match) => match[1]),
  );
}

function allMarkdown(relativeDir) {
  return fs.readdirSync(path.join(ROOT, relativeDir))
    .filter((name) => name.endsWith(".md"))
    .map((name) => path.join(relativeDir, name));
}

function allJsFiles(relativeDir) {
  const rootDir = path.join(ROOT, relativeDir);
  const files = [];
  const visit = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        visit(full);
      } else if (entry.isFile() && entry.name.endsWith(".js")) {
        files.push(path.relative(ROOT, full));
      }
    }
  };
  visit(rootDir);
  return files.sort();
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

function roleMcpToolsFromClaudeOutput(roleId) {
  const spec = CLAUDE_ROLE_SPECS[roleId];
  assert.ok(spec, `${roleId} missing Claude role spec`);
  const document = readFile(spec.output_path);
  const tools = spec.kind === "skill"
    ? parseYamlListFrontmatter(document, "allowed-tools", spec.output_path)
    : parseFrontmatter(document, spec.output_path).tools.split(/\s*,\s*/).filter(Boolean);
  return tools
    .filter((tool) => tool.startsWith("mcp__bountyagent__"))
    .map((tool) => tool.replace(/^mcp__bountyagent__/, ""))
    .sort();
}

test("Claude roles render exactly from the shared role model", () => {
  for (const [roleId, spec] of Object.entries(CLAUDE_ROLE_SPECS)) {
    assert.equal(
      readFile(spec.output_path),
      renderClaudeRole(roleId),
      `${spec.output_path} is not generated from ${roleId}`,
    );
  }
});

test("Claude slash commands render from adapter-owned command specs", () => {
  const claudeAdapter = getAdapter("claude");
  for (const [commandId, spec] of Object.entries(claudeAdapter.COMMAND_SPECS)) {
    const relativePath = path.relative(ROOT, claudeAdapter.commandOutputPath(commandId));
    assert.equal(
      readFile(relativePath),
      claudeAdapter.renderCommand(commandId),
      `${spec.file} is not generated from ${commandId}`,
    );
  }
});

test("Codex skills render exactly from the shared role model", () => {
  for (const [skillId, spec] of Object.entries(CODEX_SKILL_SPECS)) {
    assert.equal(
      readFile(spec.output_path),
      renderCodexSkill(skillId),
      `${spec.output_path} is not generated from ${skillId}`,
    );
  }
});

test("adapter registry exposes the shared lifecycle surface", () => {
  assert.deepEqual(Object.keys(ADAPTERS).sort(), ["claude", "codex", "generic-mcp"].sort());
  for (const id of Object.keys(ADAPTERS)) {
    const adapter = getAdapter(id);
    assert.equal(adapter.id, id);
    for (const method of ["install", "doctor", "uninstall", "render", "managedFiles", "mergeConfig"]) {
      assert.equal(typeof adapter[method], "function", `${id}.${method} must be a function`);
    }
  }
});

test("Codex plugin manifest and skills expose portable Bob contracts", () => {
  const codex = getAdapter("codex");
  const manifest = JSON.parse(readFile("adapters/codex/hacker-bob/.codex-plugin/plugin.json"));
  assert.equal(manifest.name, "hacker-bob");
  assert.equal(manifest.skills, "./skills/");
  assert.equal(manifest.mcpServers, "./.mcp.json");
  assert.doesNotMatch(JSON.stringify(manifest), /TODO/);

  const mcp = JSON.parse(readFile("adapters/codex/hacker-bob/.mcp.json"));
  assert.equal(mcp.mcpServers.bountyagent.command, "node");
  assert.match(mcp.mcpServers.bountyagent.args[0], /mcp\/server\.js$/);

  const hunt = readFile("adapters/codex/hacker-bob/skills/hunt/SKILL.md");
  const status = readFile("adapters/codex/hacker-bob/skills/status/SKILL.md");
  const debug = readFile("adapters/codex/hacker-bob/skills/debug/SKILL.md");
  assert.match(hunt, /bounty_finalize_hunter_run/);
  assert.doesNotMatch(hunt + status + debug, /CLAUDE_PROJECT_DIR|mcp__bountyagent__|\/bob:/);
  assert.match(status, /mcp\/lib\/update-check\.js/);

  for (const commandId of codex.commandIds()) {
    const command = codex.renderCommand(commandId);
    assert.match(command, new RegExp(`\\$hacker-bob:${commandId}`));
    assert.match(command, /\$ARGUMENTS/);
    assert.doesNotMatch(command, /CLAUDE_PROJECT_DIR|mcp__bountyagent__/);
  }
});

test("Generic MCP prompt docs describe manual host mode without host-native files", () => {
  const doc = readFile("adapters/generic-mcp/prompts/hacker-bob.md");
  assert.match(doc, /bounty_finalize_hunter_run/);
  assert.match(doc, /Generic MCP mode does not provide host-native background agents/);
  assert.doesNotMatch(doc, /CLAUDE_PROJECT_DIR|mcp__bountyagent__|\.claude|\.codex/);
});

test("Claude lifecycle routes host-specific doctor and uninstall through the adapter", () => {
  const adapter = readFile("adapters/claude/index.js");
  const lifecycle = readFile("scripts/lifecycle.js");
  assert.match(lifecycle, /adapter\.doctor\(\{/);
  assert.match(lifecycle, /adapter\.uninstall\(\{/);
  assert.match(lifecycle, /adapterId === "claude"/);
  assert.doesNotMatch(adapter, /not implemented|orchestrated by scripts\/lifecycle/);
  assert.doesNotMatch(lifecycle, /BOB_COMMAND_FILES|HOOK_FILES|settingsHasHookEntries|settingsMissingPermissions/);
});

test("Claude config lives under the Claude adapter outside the MCP runtime", () => {
  assert.equal(fs.existsSync(path.join(ROOT, "mcp", "lib", "claude-config.js")), false);
  for (const relativePath of allJsFiles("mcp")) {
    const document = readFile(relativePath);
    assert.doesNotMatch(document, /claude-config|adapters\/claude/, `${relativePath} imports Claude adapter config`);
  }
});

test("Claude project env syntax stays adapter-scoped or compatibility-scoped", () => {
  const expected = new Set([
    path.join("mcp", "lib", "runtime-resources.js"),
    path.join("scripts", "lib", "claude-role-renderer.js"),
  ]);
  for (const root of ["mcp", "scripts", "bin"]) {
    for (const relativePath of allJsFiles(root)) {
      const document = readFile(relativePath);
      if (expected.has(relativePath)) continue;
      assert.doesNotMatch(document, /CLAUDE_PROJECT_DIR/, `${relativePath} contains Claude project env syntax`);
    }
  }
});

test("Claude role MCP tool contracts match neutral roles", () => {
  for (const roleId of Object.keys(CLAUDE_ROLE_SPECS)) {
    assert.deepEqual(
      roleMcpToolsFromClaudeOutput(roleId),
      mcpToolNamesForRole(roleId).slice().sort(),
      `${roleId} Claude MCP tools drifted from neutral role model`,
    );
  }
});

test("neutral role prompt bodies do not contain host-specific MCP permission syntax", () => {
  for (const role of allRoleDefinitions()) {
    const body = readFile(role.prompt_body);
    assert.doesNotMatch(body, /mcp__bountyagent__/, `${role.prompt_body} contains Claude MCP permission syntax`);
    assert.doesNotMatch(body, /CLAUDE_PROJECT_DIR/, `${role.prompt_body} contains Claude project env syntax`);
    assert.doesNotMatch(body, /^allowed-tools:|^tools:/m, `${role.prompt_body} contains adapter frontmatter`);
  }
});

test("hunter frontmatter excludes Write and still exposes wave handoff MCP tools", () => {
  const document = readFile(".claude/agents/hunter-agent.md");
  const frontmatter = parseFrontmatter(document, "hunter-agent.md");
  const tools = frontmatter.tools.split(/\s*,\s*/).filter(Boolean);

  assert.ok(!tools.includes("Write"));
  assert.ok(tools.includes("Bash"));
  assert.ok(tools.includes("mcp__bountyagent__bounty_write_wave_handoff"));
  assert.ok(tools.includes("mcp__bountyagent__bounty_finalize_hunter_run"));
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
  assert.deepEqual(TOOL_MANIFEST.bounty_read_tool_telemetry.role_bundles, ["orchestrator"]);
  assert.equal(TOOL_MANIFEST.bounty_read_tool_telemetry.global_preapproval, false);
  assert.equal(TOOL_MANIFEST.bounty_read_tool_telemetry.mutating, false);
  assert.deepEqual(TOOL_MANIFEST.bounty_read_pipeline_analytics.role_bundles, ["orchestrator"]);
  assert.equal(TOOL_MANIFEST.bounty_read_pipeline_analytics.global_preapproval, false);
  assert.equal(TOOL_MANIFEST.bounty_read_pipeline_analytics.mutating, false);
  assert.ok(!sourceAllowed.has("bounty_merge_wave_handoffs"));
  assert.ok(!sourceAllowed.has("bounty_read_tool_telemetry"));
  assert.ok(!sourceAllowed.has("bounty_read_pipeline_analytics"));
  assert.ok(!generatedAllowed.has("bounty_merge_wave_handoffs"));
  assert.ok(!generatedAllowed.has("bounty_read_tool_telemetry"));
  assert.ok(!generatedAllowed.has("bounty_read_pipeline_analytics"));
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
  const orchestrator = readFile(".claude/skills/bob-hunt/SKILL.md");
  assert.ok(lineCount(".claude/skills/bob-hunt/SKILL.md") <= 240, "bountyagent skill is too large");
  assert.match(orchestrator, /RECON\s*→\s*AUTH\s*→\s*HUNT\s*→\s*CHAIN\s*→\s*VERIFY\s*→\s*GRADE\s*→\s*REPORT/);
  for (const phase of ["RECON", "AUTH", "HUNT", "CHAIN", "VERIFY", "GRADE", "REPORT", "EXPLORE"]) {
    assert.match(orchestrator, new RegExp(`PHASE [0-9]+: ${phase}|${phase}`), `missing ${phase}`);
  }
  assert.match(orchestrator, /must never call `bounty_write_wave_handoff`/);
  assert.match(orchestrator, /must never write handoff JSON directly/);
});

test("orchestrator validates brutalist and balanced rounds before proceeding", () => {
  const orchestrator = readFile(".claude/skills/bob-hunt/SKILL.md");
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
    ".claude/commands/bob-update.md",
    ".claude/skills/bob-hunt/SKILL.md",
    ".claude/skills/bob-status/SKILL.md",
    ".claude/skills/bob-debug/SKILL.md",
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
  const orchestrator = readFile(".claude/skills/bob-hunt/SKILL.md");
  assert.doesNotMatch(orchestrator, /Every Agent tool call MUST use `mode: "bypassPermissions"`/);
  assert.doesNotMatch(orchestrator, /mode:\s*"bypassPermissions"/);
});

test("bountyagent skill allowed-tools match orchestrator and auth bundles", () => {
  const skill = readFile(".claude/skills/bob-hunt/SKILL.md");
  const allowedTools = parseYamlListFrontmatter(skill, "allowed-tools", "bob-hunt/SKILL.md");
  const expectedTools = bountyagentSkillAllowedTools();
  assert.deepEqual(allowedTools.sort(), expectedTools.slice().sort());
  assert.deepEqual(
    allowedTools.filter((tool) => tool.startsWith("mcp__bountyagent__")).sort(),
    permissionsForRoleBundles(["orchestrator", "auth"]).sort(),
  );
  assert.ok(allowedTools.includes("Task"));
  assert.ok(allowedTools.includes("Read"));
  assert.ok(allowedTools.includes("mcp__bountyagent__bounty_merge_wave_handoffs"));
  assert.ok(allowedTools.includes("mcp__bountyagent__bounty_read_tool_telemetry"));
  assert.ok(allowedTools.includes("mcp__bountyagent__bounty_read_pipeline_analytics"));
  assert.ok(!allowedTools.includes("mcp__bountyagent__bounty_write_wave_handoff"));
});

test("Claude ships only the bob-update command shim", () => {
  const claudeAdapter = getAdapter("claude");
  const updateCommand = readFile(".claude/commands/bob-update.md");

  assert.deepEqual(Object.keys(claudeAdapter.COMMAND_SPECS), ["update"]);
  assert.equal(updateCommand, claudeAdapter.renderCommand("update"));
  assert.equal(fs.existsSync(path.join(ROOT, ".claude", "commands", "bob", "hunt.md")), false);
  assert.equal(fs.existsSync(path.join(ROOT, ".claude", "commands", "bob", "status.md")), false);
  assert.equal(fs.existsSync(path.join(ROOT, ".claude", "commands", "bob", "debug.md")), false);
  assert.equal(fs.existsSync(path.join(ROOT, ".claude", "commands", "bob", "update.md")), false);
  assert.match(updateCommand, /hacker-bob@latest install/);
  assert.match(updateCommand, /Update now\?/);
  assert.match(updateCommand, /fully restart Claude Code/);
  assert.deepEqual(
    parseYamlListFrontmatter(updateCommand, "allowed-tools", "bob-update.md").sort(),
    ["AskUserQuestion", "Bash"].sort(),
  );
});

test("bountyagentstatus skill is compact, read-only, and points to next commands", () => {
  const skill = readFile(".claude/skills/bob-status/SKILL.md");
  const allowedTools = parseYamlListFrontmatter(skill, "allowed-tools", "bob-status/SKILL.md");
  const forbiddenTools = [
    "Task",
    "Write",
    "Grep",
    "mcp__bountyagent__bounty_start_wave",
    "mcp__bountyagent__bounty_apply_wave_merge",
    "mcp__bountyagent__bounty_merge_wave_handoffs",
    "mcp__bountyagent__bounty_transition_phase",
    "mcp__bountyagent__bounty_auth_store",
    "mcp__bountyagent__bounty_write_handoff",
    "mcp__bountyagent__bounty_write_wave_handoff",
    "mcp__bountyagent__bounty_finalize_hunter_run",
    "mcp__bountyagent__bounty_write_verification_round",
    "mcp__bountyagent__bounty_write_grade_verdict",
    "mcp__bountyagent__bounty_record_finding",
    "mcp__bountyagent__bounty_http_scan",
    "mcp__bountyagent__bounty_import_http_traffic",
    "mcp__bountyagent__bounty_public_intel",
    "mcp__bountyagent__bounty_import_static_artifact",
    "mcp__bountyagent__bounty_static_scan",
    "mcp__bountyagent__bounty_auto_signup",
    "mcp__bountyagent__bounty_temp_email",
    "mcp__bountyagent__bounty_signup_detect",
    "mcp__bountyagent__bounty_log_coverage",
    "mcp__bountyagent__bounty_log_dead_ends",
    "mcp__bountyagent__bounty_read_tool_telemetry",
  ];

  assert.match(skill, /not a debug review/i);
  assert.match(skill, /No args or `--last`/);
  assert.match(skill, /bounty_read_pipeline_analytics\(\{ target_domain, include_events: false, limit: 20 \}\)/);
  assert.match(skill, /bounty_read_state_summary\(\{ target_domain \}\)/);
  assert.match(skill, /bounty_wave_status\(\{ target_domain \}\)/);
  assert.match(skill, /\/bob-hunt resume <target_domain>/);
  assert.match(skill, /\/bob-debug --deep <target_domain>/);
  for (const tool of forbiddenTools) {
    assert.ok(!allowedTools.includes(tool), `${tool} must not be allowed in bountyagentstatus`);
  }
  for (const tool of allowedTools.filter((entry) => entry.startsWith("mcp__bountyagent__"))) {
    const toolName = tool.replace(/^mcp__bountyagent__/, "");
    assert.equal(TOOL_MANIFEST[toolName].mutating, false, `${toolName} must be read-only`);
    assert.equal(TOOL_MANIFEST[toolName].network_access, false, `${toolName} must not touch the network`);
  }
});

test("bountyagentdebug skill is telemetry-first and supports latest, explicit, and deep modes", () => {
  const skill = readFile(".claude/skills/bob-debug/SKILL.md");

  assert.match(skill, /bounty_read_pipeline_analytics\(\{ target_domain, include_events: true, limit: 100 \}\)/);
  assert.match(skill, /bounty_read_tool_telemetry\(\{ target_domain, include_agent_runs: true, limit: 100 \}\)/);
  assert.match(skill, /No args or `--last`/);
  assert.match(skill, /`<target_domain>`/);
  assert.match(skill, /`--deep`/);
  assert.match(skill, /pipeline-events\.jsonl[\s\S]*state\.json[\s\S]*grade\.json[\s\S]*report\.md[\s\S]*directory mtime/);
  assert.match(skill, /Artifact fallback mode: telemetry MCP unavailable or incomplete\./);
});

test("bountyagentdebug skill allowed-tools are read-only and exclude mutators", () => {
  const skill = readFile(".claude/skills/bob-debug/SKILL.md");
  const allowedTools = parseYamlListFrontmatter(skill, "allowed-tools", "bob-debug/SKILL.md");
  const expectedReadOnlyMcpTools = [
    "mcp__bountyagent__bounty_read_pipeline_analytics",
    "mcp__bountyagent__bounty_read_tool_telemetry",
    "mcp__bountyagent__bounty_read_state_summary",
    "mcp__bountyagent__bounty_wave_status",
    "mcp__bountyagent__bounty_read_wave_handoffs",
    "mcp__bountyagent__bounty_read_findings",
    "mcp__bountyagent__bounty_read_verification_round",
    "mcp__bountyagent__bounty_read_grade_verdict",
  ];
  const forbiddenTools = [
    "Task",
    "Write",
    "mcp__bountyagent__bounty_start_wave",
    "mcp__bountyagent__bounty_apply_wave_merge",
    "mcp__bountyagent__bounty_merge_wave_handoffs",
    "mcp__bountyagent__bounty_transition_phase",
    "mcp__bountyagent__bounty_auth_store",
    "mcp__bountyagent__bounty_write_handoff",
    "mcp__bountyagent__bounty_write_wave_handoff",
    "mcp__bountyagent__bounty_finalize_hunter_run",
    "mcp__bountyagent__bounty_write_verification_round",
    "mcp__bountyagent__bounty_write_grade_verdict",
    "mcp__bountyagent__bounty_record_finding",
    "mcp__bountyagent__bounty_http_scan",
    "mcp__bountyagent__bounty_import_http_traffic",
    "mcp__bountyagent__bounty_public_intel",
    "mcp__bountyagent__bounty_import_static_artifact",
    "mcp__bountyagent__bounty_static_scan",
    "mcp__bountyagent__bounty_auto_signup",
    "mcp__bountyagent__bounty_temp_email",
    "mcp__bountyagent__bounty_signup_detect",
    "mcp__bountyagent__bounty_log_coverage",
    "mcp__bountyagent__bounty_log_dead_ends",
  ];

  assert.ok(allowedTools.includes("Read"));
  assert.ok(allowedTools.includes("Glob"));
  assert.ok(allowedTools.includes("Grep"));
  for (const tool of expectedReadOnlyMcpTools) {
    assert.ok(allowedTools.includes(tool), `${tool} missing from bountyagentdebug allowed-tools`);
  }
  for (const tool of forbiddenTools) {
    assert.ok(!allowedTools.includes(tool), `${tool} must not be allowed in bountyagentdebug`);
  }
  for (const tool of allowedTools.filter((entry) => entry.startsWith("mcp__bountyagent__"))) {
    const toolName = tool.replace(/^mcp__bountyagent__/, "");
    assert.equal(TOOL_MANIFEST[toolName].mutating, false, `${toolName} must be read-only`);
    assert.equal(TOOL_MANIFEST[toolName].network_access, false, `${toolName} must not touch the network`);
  }
});

test("installer and dev-sync ship Claude hyphen skills and prune legacy slash paths", () => {
  const install = readFile("install.sh");
  const installer = readFile("scripts/install.js");
  const claudeAdapter = readFile("adapters/claude/index.js");
  const devSync = readFile("dev-sync.sh");

  assert.match(install, /bin\/hacker-bob\.js/);
  assert.match(claudeAdapter, /bob-update\.md/);
  assert.match(claudeAdapter, /bob-hunt/);
  assert.match(claudeAdapter, /bob-status/);
  assert.match(claudeAdapter, /bob-debug/);
  assert.match(claudeAdapter, /hunt\.md/);
  assert.match(claudeAdapter, /status\.md/);
  assert.match(claudeAdapter, /debug\.md/);
  assert.match(claudeAdapter, /update\.md/);
  assert.match(installer, /\.hacker-bob/);
  assert.match(devSync, /\.hacker-bob\/knowledge/);
  assert.match(devSync, /\.hacker-bob\/bypass-tables/);
  assert.match(devSync, /\.claude\/commands\/bob-update\.md/);
  assert.match(devSync, /rm -f "\$CLAUDE_DIR\/commands\/bob\/hunt\.md"/);
  assert.match(devSync, /"\$CLAUDE_DIR\/commands\/bob\/update\.md"/);
  assert.match(claudeAdapter, /bountyagentstatus/);
  assert.match(devSync, /\.claude\/skills\/bob-status\/SKILL\.md/);
  assert.match(claudeAdapter, /bountyagentdebug/);
  assert.match(devSync, /\.claude\/skills\/bob-debug\/SKILL\.md/);
  assert.match(devSync, /\.claude\/skills\/bob-hunt\/SKILL\.md/);
});

test("dev-sync accepts adapters and gates Claude-specific sync paths", () => {
  const devSync = readFile("dev-sync.sh");

  assert.match(devSync, /--adapter claude\|codex\|generic-mcp\|all/);
  assert.match(devSync, /ADAPTER="claude"/);
  assert.match(devSync, /"\$SCRIPT_DIR\/install\.sh" "\$TARGET_ABS" --adapter "\$ADAPTER"/);
  assert.match(devSync, /function sync_claude_adapter\(\)|sync_claude_adapter\(\) \{/);
  assert.match(devSync, /if adapter_includes "claude"; then\s+sync_claude_adapter/s);
  assert.match(devSync, /\$hacker-bob:status skill/);
  assert.match(devSync, /generic-mcp\/hacker-bob\.md/);
});

test("root-orchestrator MCP calls are covered by skill allowed-tools", () => {
  const allowedTools = new Set(parseYamlListFrontmatter(
    readFile(".claude/skills/bob-hunt/SKILL.md"),
    "allowed-tools",
    "bob-hunt/SKILL.md",
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

  assert.doesNotMatch(reconPrompt, /\/bob-hunt/);
  assert.doesNotMatch(reconPrompt, /slash commands?/i);
  assert.doesNotMatch(reconPrompt, /claude-bug-bounty/i);
  assert.doesNotMatch(reconPrompt, /scripts\/|tools\//i);
  assert.doesNotMatch(reconPrompt, /mcp__/i);
});

test("installer and dev-sync copy and configure session-write-guard", () => {
  const install = readFile("scripts/install.js");
  const claudeAdapter = readFile("adapters/claude/index.js");
  const devSync = readFile("dev-sync.sh");

  assert.match(claudeAdapter, /session-write-guard\.sh/);
  assert.match(devSync, /cp "\$SCRIPT_DIR\/\.claude\/hooks\/session-write-guard\.sh"/);
  assert.match(claudeAdapter, /hunter-subagent-stop\.js/);
  assert.match(devSync, /cp "\$SCRIPT_DIR\/\.claude\/hooks\/hunter-subagent-stop\.js"/);
  assert.match(claudeAdapter, /bountyagent/);
  assert.match(devSync, /\.claude\/skills\/bob-hunt\/SKILL\.md/);
  assert.match(claudeAdapter, /hunt\.md/);
  assert.match(devSync, /\.claude\/commands\/bob-update\.md/);
  assert.match(install, /"mcp", "lib", "tools"/);
  assert.match(devSync, /mcp\/lib\/tools/);
  assert.match(claudeAdapter, /merge-claude-config\.js/);
  assert.match(devSync, /merge-claude-config\.js/);

  const hookText = JSON.stringify(defaultClaudeSettings().hooks.PreToolUse);
  assert.match(hookText, /"matcher":"Bash"[\s\S]*session-write-guard\.sh/);
  assert.match(hookText, /"matcher":"Write"[\s\S]*session-write-guard\.sh/);
  assert.match(JSON.stringify(defaultClaudeSettings().hooks.SubagentStop), /hunter-subagent-stop\.js/);
  assert.match(JSON.stringify(defaultClaudeSettings().hooks.SessionStart), /bob-check-update\.js/);
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
  const orchestrator = readFile(".claude/skills/bob-hunt/SKILL.md");
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
  const orchestrator = readFile(".claude/skills/bob-hunt/SKILL.md");

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

test("orchestrator handles auto-signup manual fallback through data fallback fields", () => {
  const orchestrator = readFile(".claude/skills/bob-hunt/SKILL.md");

  assert.match(orchestrator, /bounty_auto_signup/);
  assert.match(orchestrator, /result\.data\.fallback === "manual"/);
  assert.match(orchestrator, /result\.data\.reason[\s\S]*result\.data\.message/);
});

test("README describes MCP ranking as runtime prioritization, not persistent rewrites", () => {
  const readme = readFile("README.md");

  assert.match(readme, /MCP ranking computes runtime priority/);
  assert.match(readme, /Imports and public-intel fetches do not rewrite `attack_surface\.json`/);
  assert.doesNotMatch(readme, /MCP ranking can raise priority and add reasons/);
});

test("production CI runs npm test on supported Node versions without browser installs", () => {
  const workflow = readFile(".github/workflows/ci.yml");

  assert.match(workflow, /pull_request:/);
  assert.match(workflow, /push:/);
  assert.match(workflow, /node-version: \[20, 22\]/);
  assert.match(workflow, /npm ci/);
  assert.match(workflow, /npm test/);
  assert.doesNotMatch(workflow, /patchright install|install-browser/);
});

test("bounty_http_scan prompt contracts require target_domain on every call", () => {
  const hunterPrompt = readFile(".claude/agents/hunter-agent.md");
  const orchestratorPrompt = readFile(".claude/skills/bob-hunt/SKILL.md");
  const verifierPrompts = [
    readFile(".claude/agents/brutalist-verifier.md"),
    readFile(".claude/agents/balanced-verifier.md"),
    readFile(".claude/agents/final-verifier.md"),
  ];

  assert.match(hunterPrompt, /Every `bounty_http_scan` call must include `target_domain`/);
  assert.match(hunterPrompt, /`bounty_http_scan` with `target_domain`/);
  assert.doesNotMatch(hunterPrompt, /different domain than the target[\s\S]{0,160}target_domain/i);
  assert.doesNotMatch(hunterPrompt, /cross-domain[\s\S]{0,160}target_domain/i);

  assert.match(orchestratorPrompt, /bounty_http_scan\(\{ target_domain/);
  assert.match(orchestratorPrompt, /`bounty_http_scan` with `target_domain`/);
  assert.match(orchestratorPrompt, /bounty_http_scan with target_domain/);
  assert.doesNotMatch(orchestratorPrompt, /cross-domain[\s\S]{0,160}target_domain/i);

  for (const verifierPrompt of verifierPrompts) {
    assert.match(verifierPrompt, /`bounty_http_scan` with `target_domain` and the appropriate `auth_profile`/);
    assert.doesNotMatch(verifierPrompt, /cross-domain[\s\S]{0,160}target_domain/i);
  }
});

test("hunter and orchestrator prompts keep the structured handoff contract explicit", () => {
  const hunterPrompt = readFile(".claude/agents/hunter-agent.md");
  const orchestratorPrompt = readFile(".claude/skills/bob-hunt/SKILL.md");

  assert.match(hunterPrompt, /surface_type[\s\S]*bug_class_hints[\s\S]*high_value_flows/);
  assert.match(orchestratorPrompt, /surface_type[\s\S]*bug_class_hints[\s\S]*high_value_flows/);
  assert.match(hunterPrompt, /traffic_summary[\s\S]*audit_summary[\s\S]*circuit_breaker_summary[\s\S]*ranking_summary[\s\S]*intel_hints[\s\S]*static_scan_hints/);
  assert.match(hunterPrompt, /Prefer real observed authenticated endpoints from `traffic_summary`/);
  assert.match(hunterPrompt, /Log coverage before switching away from a promising traffic-derived endpoint|log coverage before switching away from promising traffic-derived endpoints/i);
  assert.match(orchestratorPrompt, /traffic_summary[\s\S]*audit_summary[\s\S]*circuit_breaker_summary[\s\S]*ranking_summary[\s\S]*intel_hints[\s\S]*static_scan_hints/);
  assert.match(hunterPrompt, /bounty_import_static_artifact[\s\S]*bounty_static_scan/);
  assert.match(hunterPrompt, /never pass or scan arbitrary filesystem paths/i);
  assert.match(hunterPrompt, /Do not manually create orchestrator-consumed handoff files\./);
  assert.match(hunterPrompt, /bounty_finalize_hunter_run/);
  assert.match(hunterPrompt, /BOB_HUNTER_DONE/);
  assert.match(orchestratorPrompt, /bounty_finalize_hunter_run/);
  assert.match(orchestratorPrompt, /Claude `SubagentStop` is only an adapter guardrail/);
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
