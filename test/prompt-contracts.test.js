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
  roleDefinition,
} = require("../mcp/lib/role-model.js");
const {
  CLAUDE_ROLE_SPECS,
  renderClaudeRole,
} = require("../scripts/lib/claude-role-renderer.js");
const {
  CODEX_SKILL_SPECS,
  renderCodexSkill,
} = require("../scripts/lib/codex-role-renderer.js");
const {
  CODEX_ROLE_SPECS,
} = require("../adapters/codex/role-specs.js");
const {
  AGENT_TOOL_SPECS,
  toolsForSpec,
} = require("../scripts/generate-agent-tools.js");
const {
  CAPABILITY_PACKS,
  DEFAULT_CONTEXT_BUDGET,
  hunterAgentNamesForCapabilityPacks,
  SMART_CONTRACT_CONTEXT_BUDGET,
} = require("../mcp/lib/capability-packs.js");

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

test("public copy uses Hacker Bob naming instead of retired product phrasing", () => {
  const publicFiles = [
    "mcp/server.js",
    "site/index.html",
    "site/src/App.tsx",
  ];
  const retiredNamePattern = new RegExp("\\bBounty " + "Agent\\b|\\bbounty " + "agent\\b", "i");

  for (const file of publicFiles) {
    assert.doesNotMatch(
      readFile(file),
      retiredNamePattern,
      `${file} should use Hacker Bob or Bob naming`,
    );
  }
});

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

test("Codex plugin manifest and direct skills expose portable Bob contracts", () => {
  const codex = getAdapter("codex");
  const manifest = JSON.parse(readFile("adapters/codex/hacker-bob/.codex-plugin/plugin.json"));
  assert.equal(manifest.name, "hacker-bob");
  assert.equal(manifest.mcpServers, "./.mcp.json");
  assert.equal(Object.prototype.hasOwnProperty.call(manifest, "skills"), false);
  assert.doesNotMatch(JSON.stringify(manifest), /TODO/);

  const mcp = JSON.parse(readFile("adapters/codex/hacker-bob/.mcp.json"));
  assert.equal(mcp.mcpServers.bountyagent.command, "node");
  assert.match(mcp.mcpServers.bountyagent.args[0], /mcp\/server\.js$/);

  const hunt = readFile("adapters/codex/skills/bob-hunt/SKILL.md");
  const status = readFile("adapters/codex/skills/bob-status/SKILL.md");
  const debug = readFile("adapters/codex/skills/bob-debug/SKILL.md");
  assert.equal(parseFrontmatter(hunt, "adapters/codex/skills/bob-hunt/SKILL.md").name, "bob-hunt");
  assert.equal(parseFrontmatter(status, "adapters/codex/skills/bob-status/SKILL.md").name, "bob-status");
  assert.equal(parseFrontmatter(debug, "adapters/codex/skills/bob-debug/SKILL.md").name, "bob-debug");
  assert.match(hunt, /bounty_finalize_hunter_run/);
  assert.match(hunt, /Codex Agent Mapping/);
  assert.match(hunt, /Codex Worker Role Contracts/);
  assert.match(hunt, /BEGIN recon CONTRACT/);
  assert.match(hunt, /BEGIN hunter CONTRACT/);
  assert.match(hunt, /spawn_agent/);
  assert.match(hunt, /agent_type: "worker"/);
  assert.match(hunt, /bounty_read_hunter_brief\(\{ target_domain:[\s\S]*egress_profile:[\s\S]*block_internal_hosts: \[block_internal_hosts\]/);
  assert.match(hunt, /wait_agent/);
  assert.match(hunt, /close_agent/);
  assert.match(hunt, /host_agent_id -> w\[wave\]\/a\[agent\]\/surface_id/);
  assert.doesNotMatch(hunt + status + debug, /CLAUDE_PROJECT_DIR|mcp__bountyagent__|\/bob:|\bClaude\b|Agent\(subagent_type|subagent_type|run_in_background|\bTask\b|SubagentStop/);
  assert.match(status, /mcp\/lib\/update-check\.js/);

  for (const [roleId, spec] of Object.entries(CODEX_ROLE_SPECS)) {
    assert.equal(spec.agent_type, "worker", `${roleId} must map to a Codex worker`);
    assert.ok(spec.bob_role, `${roleId} must keep a Bob logical role name`);
  }

  for (const commandId of codex.commandIds()) {
    const command = codex.renderCommand(commandId);
    assert.match(command, new RegExp(`\\$bob-${commandId}`));
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
    // bin/hacker-bob.js is the cross-adapter CLI; its help text documents
    // host-specific env markers (CLAUDE_PROJECT_DIR, CODEX_HOME) as detection
    // signals. The mention is documentation, not runtime coupling.
    path.join("bin", "hacker-bob.js"),
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

test("shared orchestrator keeps launch mechanics adapter-owned", () => {
  const body = readFile("prompts/roles/orchestrator.md");
  for (const placeholder of [
    "{{SPAWN_RECON_AGENT}}",
    "{{SPAWN_HUNTER_AGENT}}",
    "{{SPAWN_CHAIN_AGENT}}",
    "{{SPAWN_BRUTALIST_VERIFIER}}",
    "{{SPAWN_BALANCED_VERIFIER}}",
    "{{SPAWN_FINAL_VERIFIER}}",
    "{{SPAWN_GRADER_AGENT}}",
    "{{SPAWN_REPORTER_AGENT}}",
  ]) {
    assert.match(body, new RegExp(placeholder.replace(/[{}]/g, "\\$&")));
  }
  assert.doesNotMatch(body, /Agent\(subagent_type|subagent_type|run_in_background|SubagentStop|Claude Code/);
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
  assert.ok(tools.includes("mcp__bountyagent__bounty_record_surface_leads"));
  assert.ok(tools.includes("mcp__bountyagent__bounty_read_surface_leads"));
  assert.ok(tools.includes("mcp__bountyagent__bounty_get_context_budget"));
  assert.ok(tools.includes("mcp__bountyagent__bounty_select_technique_packs"));
  assert.ok(tools.includes("mcp__bountyagent__bounty_read_technique_pack"));
  assert.ok(tools.includes("mcp__bountyagent__bounty_log_technique_attempt"));
  assert.ok(!tools.includes("mcp__bountyagent__bounty_import_http_traffic"));
  assert.ok(!tools.includes("mcp__bountyagent__bounty_public_intel"));
  assert.ok(!tools.includes("mcp__bountyagent__bounty_auth_manual"));
  assert.ok(!tools.includes("mcp__bountyagent__bounty_read_handoff"));
});

test("surface-router-agent is thin and cannot hunt or write directly", () => {
  const document = readFile(".claude/agents/surface-router-agent.md");
  const frontmatter = parseFrontmatter(document, "surface-router-agent.md");
  const tools = frontmatter.tools.split(/\s*,\s*/).filter(Boolean);

  assert.deepEqual(tools, [
    "Read",
    "mcp__bountyagent__bounty_route_surfaces",
  ]);
  assert.match(document, /mcpServers:\s*\n\s*-\s*bountyagent/);
  assert.match(document, /bounty_route_surfaces/);
  assert.match(document, /surface-routes\.json/);
  assert.doesNotMatch(frontmatter.tools, /Bash|Write|bounty_http_scan|curl|browser/i);
  assert.match(document, /Do not do recon, hunting, auth, HTTP requests, browser work, Bash, or direct file writes/);
});

test("generated hunter-agent tools come from the hunter-shared and hunter-web bundles only", () => {
  const spec = AGENT_TOOL_SPECS["hunter-agent.md"];
  assert.deepEqual(spec.roleBundles, ["hunter-shared", "hunter-web"]);
  assert.deepEqual(
    toolsForSpec(spec).filter((tool) => tool.startsWith("mcp__bountyagent__")).sort(),
    permissionsForRoleBundles(["hunter-shared", "hunter-web"]).sort(),
  );
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
  assert.deepEqual(TOOL_MANIFEST.bounty_route_surfaces.role_bundles, ["orchestrator", "router"]);
  assert.equal(TOOL_MANIFEST.bounty_route_surfaces.global_preapproval, false);
  assert.equal(TOOL_MANIFEST.bounty_route_surfaces.mutating, true);
  assert.deepEqual(TOOL_MANIFEST.bounty_record_surface_leads.role_bundles, ["hunter-web", "orchestrator"]);
  assert.equal(TOOL_MANIFEST.bounty_record_surface_leads.global_preapproval, true);
  assert.equal(TOOL_MANIFEST.bounty_read_surface_leads.global_preapproval, true);
  assert.equal(TOOL_MANIFEST.bounty_promote_surface_leads.global_preapproval, false);
  assert.equal(TOOL_MANIFEST.bounty_promote_surface_leads.mutating, true);
  assert.deepEqual(TOOL_MANIFEST.bounty_get_context_budget.role_bundles, ["hunter-shared", "orchestrator"]);
  assert.deepEqual(TOOL_MANIFEST.bounty_select_technique_packs.role_bundles, ["hunter-web", "orchestrator"]);
  assert.deepEqual(TOOL_MANIFEST.bounty_read_technique_pack.role_bundles, ["hunter-web", "orchestrator"]);
  assert.deepEqual(TOOL_MANIFEST.bounty_log_technique_attempt.role_bundles, ["hunter-web", "orchestrator"]);
  assert.equal(TOOL_MANIFEST.bounty_get_context_budget.mutating, false);
  assert.equal(TOOL_MANIFEST.bounty_select_technique_packs.mutating, false);
  assert.equal(TOOL_MANIFEST.bounty_read_technique_pack.mutating, true);
  assert.equal(TOOL_MANIFEST.bounty_log_technique_attempt.mutating, true);
  assert.deepEqual(TOOL_MANIFEST.bounty_read_technique_pack.session_artifacts_written, ["technique-pack-reads.jsonl"]);
  assert.deepEqual(TOOL_MANIFEST.bounty_log_technique_attempt.session_artifacts_written, ["technique-attempts.jsonl"]);
  assert.deepEqual(TOOL_MANIFEST.bounty_write_evidence_packs.role_bundles, ["evidence"]);
  assert.deepEqual(TOOL_MANIFEST.bounty_read_evidence_packs.role_bundles, ["evidence", "grader", "reporter", "orchestrator"]);
  assert.ok(!sourceAllowed.has("bounty_merge_wave_handoffs"));
  assert.ok(!sourceAllowed.has("bounty_read_tool_telemetry"));
  assert.ok(!sourceAllowed.has("bounty_read_pipeline_analytics"));
  assert.ok(!sourceAllowed.has("bounty_route_surfaces"));
  assert.ok(!generatedAllowed.has("bounty_merge_wave_handoffs"));
  assert.ok(!generatedAllowed.has("bounty_read_tool_telemetry"));
  assert.ok(!generatedAllowed.has("bounty_read_pipeline_analytics"));
  assert.ok(!generatedAllowed.has("bounty_route_surfaces"));
  assert.ok(!sourceAllowed.has("bounty_promote_surface_leads"));
  assert.ok(sourceAllowed.has("bounty_record_surface_leads"));
  assert.ok(sourceAllowed.has("bounty_read_surface_leads"));
  assert.ok(sourceAllowed.has("bounty_get_context_budget"));
  assert.ok(sourceAllowed.has("bounty_select_technique_packs"));
  assert.ok(sourceAllowed.has("bounty_read_technique_pack"));
  assert.ok(sourceAllowed.has("bounty_log_technique_attempt"));
  assert.ok(sourceAllowed.has("bounty_wave_handoff_status"));

  const hookMatchers = settingsHookMatchers();
  for (const [toolName, metadata] of Object.entries(TOOL_MANIFEST)) {
    if (!metadata.hook_required) continue;
    assert.ok(hookMatchers.has(`mcp__bountyagent__${toolName}`), `${toolName} requires a scope hook`);
  }
});

test("standard hook test script runs both write and read guards", () => {
  const packageJson = JSON.parse(readFile("package.json"));
  assert.match(packageJson.scripts["test:hooks"], /test-write-guard\.py/);
  assert.match(packageJson.scripts["test:hooks"], /test-read-guard\.py/);
});

test("MCP-dependent agents declare official mcpServers bountyagent metadata", () => {
  const agents = [
    "surface-router-agent",
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

test("recon agents remain MCP-free", () => {
  for (const agent of ["recon-agent", "deep-recon-agent"]) {
    const document = readFile(`.claude/agents/${agent}.md`);
    assert.doesNotMatch(document, /mcpServers:/, `${agent} should not declare MCP servers`);
    assert.doesNotMatch(document, /requiredMcpServers:/, `${agent} should not require MCP servers`);
    assert.doesNotMatch(document, /mcp__/i, `${agent} should not expose MCP tools`);
  }
});

test("global rules stay small and keep scope plus MCP-owned artifact guardrails", () => {
  for (const ruleFile of [".claude/rules/hunting.md", ".claude/rules/reporting.md"]) {
    const document = readFile(ruleFile);
    assert.ok(lineCount(ruleFile) <= 60, `${ruleFile} is too large for always-active context`);
    assert.match(document, /scope/i, `${ruleFile} must mention scope`);
    assert.match(document, /MCP-owned artifacts/i, `${ruleFile} must mention MCP-owned artifacts`);
  }
});

test("hunter-evm-agent ships with the EVM tool surface and SC anti-stop rule", () => {
  const document = readFile(".claude/agents/hunter-evm-agent.md");
  const frontmatter = parseFrontmatter(document, "hunter-evm-agent.md");
  const tools = frontmatter.tools.split(/\s*,\s*/).filter(Boolean);

  assert.ok(tools.includes("Bash"));
  assert.ok(tools.includes("Read"));
  assert.ok(tools.includes("Write"), "hunter-evm needs Write to scaffold Foundry tests");
  assert.ok(tools.includes("mcp__bountyagent__bounty_evm_call"));
  assert.ok(tools.includes("mcp__bountyagent__bounty_evm_storage_read"));
  assert.ok(tools.includes("mcp__bountyagent__bounty_evm_fetch_source"));
  assert.ok(tools.includes("mcp__bountyagent__bounty_evm_role_table"));
  assert.ok(tools.includes("mcp__bountyagent__bounty_foundry_run"));
  assert.ok(tools.includes("mcp__bountyagent__bounty_write_wave_handoff"));
  assert.ok(tools.includes("mcp__bountyagent__bounty_finalize_hunter_run"));
  assert.ok(tools.includes("mcp__bountyagent__bounty_record_finding"));

  assert.match(document, /surface_type[^\n]*smart_contract/i);
  assert.match(document, /bounty_evm_fetch_source/);
  assert.match(document, /bounty_foundry_run/);
  assert.match(document, /bypass_attempts/);
  assert.match(document, /blocked_harness_runs/);
  assert.match(document, /BOB_HUNTER_DONE/);
});

test("hunting rules and hunter prompt encode the smart_contract anti-stop rule", () => {
  const huntingRules = readFile(".claude/rules/hunting.md");
  assert.match(huntingRules, /smart_contract/i, "hunting.md missing smart_contract rule");
  assert.match(huntingRules, /bypass_attempts/i, "hunting.md missing bypass_attempts requirement");

  const hunterPrompt = readFile(".claude/agents/hunter-agent.md");
  assert.match(hunterPrompt, /surface_type: smart_contract/, "hunter prompt missing smart_contract surface_type reference");
  assert.match(hunterPrompt, /bypass_attempts/, "hunter prompt missing bypass_attempts reference");
  assert.match(hunterPrompt, /blocked_harness_runs/, "hunter prompt missing blocked_harness_runs reference");
  assert.match(
    hunterPrompt,
    /MCP server (also )?rejects `surface_status: complete`/i,
    "hunter prompt missing server-side rejection guidance",
  );
});

test("hunter prompt teaches the blocked_prereqs[] policy and orchestrator handles terminally_blocked surfaces", () => {
  const hunterPrompt = readFile(".claude/agents/hunter-agent.md");
  assert.match(hunterPrompt, /blocked_prereqs/, "hunter prompt missing blocked_prereqs policy");
  assert.match(hunterPrompt, /auth_missing/, "hunter prompt missing auth_missing kind reference");
  assert.match(hunterPrompt, /egress_unreachable/, "hunter prompt missing egress_unreachable kind reference");
  assert.match(hunterPrompt, /bounty_clear_terminal_block/, "hunter prompt missing bounty_clear_terminal_block reference");

  const orchestratorPrompt = readFile("prompts/roles/orchestrator.md");
  assert.match(orchestratorPrompt, /terminally_blocked/, "orchestrator prompt missing terminally_blocked exclusion guidance");
  assert.match(orchestratorPrompt, /bounty_clear_terminal_block/, "orchestrator prompt missing clear-block tool reference");
  assert.match(
    orchestratorPrompt,
    /override_reason` is rejected outside/,
    "orchestrator prompt missing override_reason scope warning",
  );

  const reporterPrompt = readFile("prompts/roles/reporter.md");
  assert.match(reporterPrompt, /Blocked by missing prerequisites/, "reporter prompt missing blocked-prereqs section guidance");
  assert.match(reporterPrompt, /bounty_report_written/, "reporter prompt missing bounty_report_written call");
});

test("bob-spec loader is wired into the hunter brief", () => {
  const briefSource = readFile("mcp/lib/hunter-brief.js");
  assert.match(
    briefSource,
    /require\(['"]\.\/bob-spec(\.js)?['"]\)/,
    "hunter-brief.js must import the bob-spec loader",
  );
  assert.match(briefSource, /summarizeBobSpecForBrief\(loadBobSpec\(domain\)/);

  const { loadBobSpec, summarizeBobSpecForBrief } = require("../mcp/lib/bob-spec.js");
  assert.equal(typeof loadBobSpec, "function");
  assert.equal(typeof summarizeBobSpecForBrief, "function");

  // Empty-state shape — when no bob-spec.json exists in a fresh domain, the
  // brief still surfaces a present:false summary so the hunter prompt can
  // branch instead of crashing.
  const summary = summarizeBobSpecForBrief({ present: false, reason: "missing" }, "surface-a");
  assert.equal(summary.present, false);
  assert.equal(summary.reason, "missing");
  assert.match(summary.message, /smart_contract/i);
  assert.doesNotMatch(
    summary.message,
    /free-text condition string|use any string|fabricate/i,
    "empty-state message must not invite freeform fabrication",
  );
});

test("bountyagent skill stays orchestration-sized and preserves FSM shape", () => {
  const orchestrator = readFile(".claude/skills/bob-hunt/SKILL.md");
  // Line cap is 340: web orchestration plus the EVM/SVM/Move/Substrate/
  // CosmWasm spawn templates fit, but no future chain pack may bump this cap.
  // Instead, extract per-family spawn details to separate skill files
  // (e.g., bob-spawn-substrate.md, bob-spawn-cosmwasm.md) and reference them
  // from this orchestrator skill via @-includes or short cross-links.
  assert.ok(lineCount(".claude/skills/bob-hunt/SKILL.md") <= 340, "bountyagent skill is too large");
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

test("evidence-agent exists, is MCP-only, and cannot mutate unrelated artifacts", () => {
  const document = readFile(".claude/agents/evidence-agent.md");
  const frontmatter = parseFrontmatter(document, "evidence-agent.md");
  const tools = frontmatter.tools.split(/\s*,\s*/).filter(Boolean);
  // The evidence role bundle includes HTTP tools (bounty_http_scan, audit, etc.)
  // plus the smart-contract family runners (since v1.2.0) so evidence-agent can
  // collect representative samples for SC findings via bounty_*_run dispatch.
  // We assert the required-core tools are present rather than locking the full
  // list, since SC tools are added through role_bundles in each tool module.
  const requiredCore = [
    "mcp__bountyagent__bounty_http_scan",
    "mcp__bountyagent__bounty_read_http_audit",
    "mcp__bountyagent__bounty_read_findings",
    "mcp__bountyagent__bounty_read_verification_round",
    "mcp__bountyagent__bounty_write_evidence_packs",
    "mcp__bountyagent__bounty_read_evidence_packs",
    "mcp__bountyagent__bounty_list_auth_profiles",
  ];

  assert.deepEqual(AGENT_TOOL_SPECS["evidence-agent.md"], {
    roleBundles: ["evidence"],
    extras: [],
  });
  for (const tool of requiredCore) {
    assert.ok(tools.includes(tool), `evidence-agent.md tools must include ${tool}`);
  }
  assert.match(document, /final reportable findings only/);
  assert.match(document, /bounty_write_evidence_packs/);
  assert.doesNotMatch(frontmatter.tools, /Bash|Write|bounty_record_finding|bounty_write_wave_handoff|bounty_write_grade_verdict/);
  assert.doesNotMatch(frontmatter.tools, /bounty_write_chain_attempt|bounty_transition_phase/);
});

test("bob-hunt spawns evidence before grade and validates evidence packs", () => {
  const orchestrator = readFile(".claude/skills/bob-hunt/SKILL.md");
  const evidenceIndex = orchestrator.indexOf('subagent_type: "evidence-agent"');
  const gradeTransitionIndex = orchestrator.indexOf('to_phase: "GRADE"');
  const graderIndex = orchestrator.indexOf('subagent_type: "grader"');

  assert.ok(evidenceIndex > 0, "missing evidence-agent spawn");
  assert.ok(gradeTransitionIndex > evidenceIndex, "GRADE transition must happen after evidence-agent");
  assert.ok(graderIndex > gradeTransitionIndex, "grader must spawn after GRADE transition");
  assert.match(orchestrator, /bounty_read_evidence_packs\(\{ target_domain: "\[domain\]" \}\)/);
  assert.match(orchestrator, /write only through bounty_write_evidence_packs/);
});

test("bob-hunt closes no-finding verification through SKIP grade and report", () => {
  const orchestrator = readFile(".claude/skills/bob-hunt/SKILL.md");
  const grader = readFile(".claude/agents/grader.md");
  const reporter = readFile(".claude/agents/report-writer.md");

  assert.doesNotMatch(orchestrator, /If no result has `reportable: true`, report `No reportable vulnerabilities`[\s\S]{0,80}stop/);
  assert.match(orchestrator, /no result has `reportable: true`[\s\S]*continue through GRADE and REPORT/);
  assert.match(orchestrator, /On `SUBMIT` or `SKIP`, transition to REPORT/);
  assert.match(grader, /terminal SKIP verdict with `total_score: 0`, `findings: \[\]`/);
  assert.match(reporter, /no-findings closeout/);
});

test("settings.json registers session guards for Bash, Read, and Write", () => {
  const settings = JSON.parse(readFile(".claude/settings.json"));
  const preToolUse = settings.hooks.PreToolUse;

  const bashEntry = preToolUse.find((e) => e.matcher === "Bash");
  assert.ok(bashEntry, "No Bash matcher in PreToolUse");
  assert.ok(
    bashEntry.hooks.some((h) => h.command.includes("session-write-guard.sh")),
    "session-write-guard.sh not registered for Bash"
  );
  assert.ok(
    bashEntry.hooks.some((h) => h.command.includes("session-read-guard.sh")),
    "session-read-guard.sh not registered for Bash"
  );

  const readEntry = preToolUse.find((e) => e.matcher === "Read");
  assert.ok(readEntry, "No Read matcher in PreToolUse");
  assert.ok(
    readEntry.hooks.some((h) => h.command.includes("session-read-guard.sh")),
    "session-read-guard.sh not registered for Read"
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
  assert.ok(allowedTools.includes("mcp__bountyagent__bounty_route_surfaces"));
  assert.ok(allowedTools.includes("mcp__bountyagent__bounty_read_session_summary"));
  assert.ok(allowedTools.includes("mcp__bountyagent__bounty_set_operator_note"));
  assert.ok(allowedTools.includes("mcp__bountyagent__bounty_clear_operator_note"));
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
  assert.match(skill, /bounty_read_session_summary\(\{ target_domain \}\)/);
  assert.match(skill, /bounty_read_state_summary\(\{ target_domain \}\)/);
  assert.match(skill, /bounty_wave_status\(\{ target_domain \}\)/);
  assert.ok(allowedTools.includes("mcp__bountyagent__bounty_read_evidence_packs"));
  assert.ok(allowedTools.includes("mcp__bountyagent__bounty_read_session_summary"));
  assert.match(skill, /evidence status/);
  assert.match(skill, /bounty_read_pipeline_analytics\.data\.sessions\[0\]\.evidence/);
  assert.match(skill, /bounty_read_evidence_packs\(\{ target_domain \}\)/);
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
  assert.match(skill, /bounty_read_session_summary\(\{ target_domain \}\)/);
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
    "mcp__bountyagent__bounty_read_session_summary",
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
  assert.match(devSync, /\$bob-status skill/);
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

test("normal recon agent is single-purpose and has no deep-only contract", () => {
  const reconPrompt = readFile(".claude/agents/recon-agent.md");

  assert.doesNotMatch(reconPrompt, /\[MODE\]|MODE=/);
  assert.doesNotMatch(reconPrompt, /amass/);
  assert.doesNotMatch(reconPrompt, /assetfinder/);
  assert.doesNotMatch(reconPrompt, /chaos/);
  assert.doesNotMatch(reconPrompt, /dnsx/);
  assert.doesNotMatch(reconPrompt, /tlsx/);
  assert.doesNotMatch(reconPrompt, /subzy/);
  assert.doesNotMatch(reconPrompt, /surface-leads\.json/);
  assert.doesNotMatch(reconPrompt, /deep-summary\.json/);
});

test("recon agents include optional Katana crawl and JWT candidate artifacts", () => {
  for (const agent of ["recon-agent", "deep-recon-agent"]) {
    const reconPrompt = readFile(`.claude/agents/${agent}.md`);

    assert.match(reconPrompt, /OK:katana/);
    assert.match(reconPrompt, /MISSING:katana/);
    assert.match(reconPrompt, /katana_urls\.txt/);
    assert.match(reconPrompt, /OK:jwt_tool/);
    assert.match(reconPrompt, /MISSING:jwt_tool/);
    assert.match(reconPrompt, /jwt_candidates\.txt/);
    assert.match(reconPrompt, /JWT-shaped candidates|jwt_candidates/);
  }
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

test("deep recon agent preserves exactly seven Bash collection calls", () => {
  const deepReconPrompt = readFile(".claude/agents/deep-recon-agent.md");
  const bashBlocks = Array.from(deepReconPrompt.matchAll(/```bash\n/g));

  assert.equal(bashBlocks.length, 7);
  assert.match(deepReconPrompt, /Use exactly the 7 Bash calls below, in order/);
  assert.match(deepReconPrompt, /Do not make any additional Bash calls/);
});

test("deep recon stays bounded, broad, and writes compact ranked lead artifacts", () => {
  const deepReconPrompt = readFile(".claude/agents/deep-recon-agent.md");

  assert.match(deepReconPrompt, /Passive subdomain and CT aggregation/i);
  assert.match(deepReconPrompt, /crt\.sh/);
  assert.match(deepReconPrompt, /amass/);
  assert.match(deepReconPrompt, /assetfinder/);
  assert.match(deepReconPrompt, /chaos/);
  assert.match(deepReconPrompt, /dnsx/);
  assert.match(deepReconPrompt, /tlsx/);
  assert.match(deepReconPrompt, /katana/);
  assert.match(deepReconPrompt, /subzy/);
  assert.match(deepReconPrompt, /subzy_takeovers\.txt/);
  assert.match(deepReconPrompt, /tlsx_sans\.txt/);
  assert.match(deepReconPrompt, /CDX\/Wayback/);
  assert.match(deepReconPrompt, /JS extraction/i);
  assert.match(deepReconPrompt, /JWT and OIDC token review candidates/);
  assert.match(deepReconPrompt, /takeover_candidates/);
  assert.match(deepReconPrompt, /tech\/CVE hints/);
  assert.match(deepReconPrompt, /sibling-domain-candidates\.txt/);
  assert.match(deepReconPrompt, /brand-sibling-probe-candidates\.txt/);
  assert.match(deepReconPrompt, /Brand-linked sibling properties lightly probed/);
  assert.match(deepReconPrompt, /Sibling domain candidates recorded for review/);
  assert.match(deepReconPrompt, /deep-summary\.json/);
  assert.match(deepReconPrompt, /surface-leads\.json/);
  assert.match(deepReconPrompt, /Do not duplicate every URL/);
  assert.match(deepReconPrompt, /Do not dump raw URLs, JavaScript bodies, or scanner output into prose/);
  assert.match(deepReconPrompt, /Do not copy raw secrets, bearer values, or JWT-looking strings/);
  assert.match(deepReconPrompt, /record counts and local artifact names only/);
});

test("deep recon target family probing stays bounded and sibling liveness is gated", () => {
  const deepReconPrompt = readFile(".claude/agents/deep-recon-agent.md");
  const familyStart = deepReconPrompt.indexOf("4. First-party family discovery");
  const familyEnd = deepReconPrompt.indexOf("5. Archived URLs with CDX/Wayback");
  const cdxEnd = deepReconPrompt.indexOf("6. JS extraction and endpoint clustering");
  const step7Start = deepReconPrompt.indexOf("7. Compact summaries, ranked leads, and attack surface");
  assert.ok(familyStart >= 0 && familyEnd > familyStart, "missing deep recon family discovery section");
  assert.ok(step7Start > cdxEnd, "missing deep recon compact summary section");
  const familySection = deepReconPrompt.slice(familyStart, familyEnd);
  const cdxSection = deepReconPrompt.slice(familyEnd, cdxEnd);
  const jsSection = deepReconPrompt.slice(cdxEnd, step7Start);
  const step7Section = deepReconPrompt.slice(step7Start);
  const liveUrlsEnd = step7Section.indexOf(': > "$SESSION/nuclei_results.txt"');
  assert.ok(liveUrlsEnd > 0, "missing deep recon live_urls builder");
  const liveUrlsBuilder = step7Section.slice(0, liveUrlsEnd);

  assert.match(familySection, /Target-domain family probing remains bounded/i);
  assert.match(familySection, /do not probe the broad `sibling-domain-candidates\.txt` set/i);
  assert.match(familySection, /host == domain or host\.endswith\("\." \+ domain\)/);
  assert.match(familySection, /sibling-domain-candidates\.txt/);
  assert.match(familySection, /brand-sibling-probe-candidates\.txt/);
  assert.match(familySection, /same-TLD-only repeat evidence stays record-only/i);
  assert.match(familySection, /label\.startswith\(target_label\)/);
  assert.match(familySection, /if brand_related:\n\s+brand_siblings\.append\(host\)/);
  assert.match(familySection, /-l "\$SESSION\/brand-sibling-probe-candidates\.txt"/);
  assert.match(step7Section, /def add_lead\([\s\S]*promote=None\)/);
  assert.match(step7Section, /Brand-linked sibling properties lightly probed[\s\S]*\*brand_sibling_live\[:5\][\s\S]*55, promote=True/);
  assert.doesNotMatch(step7Section, /Brand-linked sibling properties queued for review[\s\S]{0,300}promote=True/);
  assert.doesNotMatch(familySection, /httpx[\s\S]*sibling-domain-candidates\.txt/i);
  assert.doesNotMatch(familySection, /-l "\$SESSION\/sibling-domain-candidates\.txt"/);
  assert.doesNotMatch(cdxSection, /sibling-domain-candidates\.txt/);
  for (const needle of ["brand-sibling-probe-candidates.txt", "brand_sibling_live.txt"]) {
    const escapedNeedle = needle.replace(/\./g, "\\.");
    assert.doesNotMatch(cdxSection, new RegExp(escapedNeedle));
    assert.doesNotMatch(jsSection, new RegExp(escapedNeedle));
    assert.doesNotMatch(liveUrlsBuilder, new RegExp(escapedNeedle));
  }
});

test("recon prompts remain enrichment-only without new commands or imported toolsets", () => {
  for (const agent of ["recon-agent", "deep-recon-agent"]) {
    const reconPrompt = readFile(`.claude/agents/${agent}.md`);

    assert.doesNotMatch(reconPrompt, /\/bob-hunt/, `${agent} should not mention slash commands`);
    assert.doesNotMatch(reconPrompt, /slash commands?/i, `${agent} should not mention slash commands`);
    assert.doesNotMatch(reconPrompt, /claude-bug-bounty/i, `${agent} should not import external prompts`);
    assert.doesNotMatch(reconPrompt, /scripts\/|tools\//i, `${agent} should not require repo scripts or tools`);
    assert.doesNotMatch(reconPrompt, /mcp__/i, `${agent} should not use MCP tools`);
  }
});

test("installer and dev-sync copy and configure session guards", () => {
  const install = readFile("scripts/install.js");
  const claudeAdapter = readFile("adapters/claude/index.js");
  const devSync = readFile("dev-sync.sh");

  assert.match(claudeAdapter, /session-write-guard\.sh/);
  assert.match(claudeAdapter, /session-read-guard\.sh/);
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
  assert.match(hookText, /"matcher":"Bash"[\s\S]*session-read-guard\.sh/);
  assert.match(hookText, /"matcher":"Read"[\s\S]*session-read-guard\.sh/);
  assert.match(hookText, /"matcher":"Write"[\s\S]*session-write-guard\.sh/);
  assert.match(JSON.stringify(defaultClaudeSettings().hooks.SubagentStop), /hunter-subagent-stop\.js/);
  assert.match(JSON.stringify(defaultClaudeSettings().hooks.SessionStart), /bob-check-update\.js/);
});

test("SubagentStop hooks cover every routed capability-pack hunter agent", () => {
  const expectedHunters = hunterAgentNamesForCapabilityPacks().sort();
  const configuredHunters = (defaultClaudeSettings().hooks.SubagentStop || [])
    .filter((entry) => (entry.hooks || []).some((hook) => /hunter-subagent-stop\.js/.test(hook.command)))
    .map((entry) => entry.matcher)
    .sort();

  assert.deepEqual(configuredHunters, expectedHunters);
});

test("capability packs expose versioned context budgets for routed hunters", () => {
  for (const pack of Object.values(CAPABILITY_PACKS)) {
    assert.equal(pack.capability_pack_version, 1);
    assert.ok(pack.hunter_agent);
    assert.ok(pack.brief_profile);
    assert.deepEqual(
      Object.keys(pack.context_budget).sort(),
      ["attempt_log_required", "candidate_pack_limit", "full_pack_read_limit"].sort(),
    );
    if (pack.brief_profile === "web") {
      assert.deepEqual(pack.context_budget, DEFAULT_CONTEXT_BUDGET);
    } else {
      assert.deepEqual(pack.context_budget, SMART_CONTRACT_CONTEXT_BUDGET);
    }
  }
});

test("no rendered prompt artifact leaks an unsubstituted {{...}} placeholder (renderer parity)", () => {
  // The {{CAPABILITY_PACK_VERIFIER_TABLE}} substitution lives in a
  // renderer-agnostic helper so both the Claude and Codex renderers run it.
  // This test guards renderer parity: every checked-in generated prompt
  // artifact (Claude agents, Codex skills, Bob skills) must contain zero
  // literal `{{...}}` placeholders.
  const generatedFiles = [
    ...fs.readdirSync(path.join(ROOT, ".claude/agents"))
      .filter((name) => name.endsWith(".md"))
      .map((name) => `.claude/agents/${name}`),
    ".claude/skills/bob-hunt/SKILL.md",
    "adapters/codex/skills/bob-hunt/SKILL.md",
    "adapters/codex/skills/bob-status/SKILL.md",
    "adapters/codex/skills/bob-debug/SKILL.md",
  ];
  for (const relativePath of generatedFiles) {
    const document = readFile(relativePath);
    const matches = document.match(/\{\{[A-Z][A-Z0-9_]+\}\}/g) || [];
    assert.deepEqual(
      matches,
      [],
      `${relativePath} contains unsubstituted placeholders: ${matches.join(", ")}`,
    );
  }
});

test("hunter prompt sources do not hand-code handoff field limits", () => {
  // Limits for fields written by bounty_write_wave_handoff are owned by its
  // JSON schema and rendered into hunter prompts via {{HANDOFF_FIELD_LIMITS}}.
  // Hand-coded character counts on these specific fields would drift
  // independently of schema bumps. Other character bounds (e.g. on
  // match_test or chain-specific contract_address shapes) are owned by
  // their respective tools, not by bounty_write_wave_handoff, so they stay
  // hand-coded here.
  // Derive the prompt-source list from HUNTER_ROLES (per-chain hunters)
  // plus the generic web hunter, so adding a 7th chain pack auto-extends
  // this guard without an edit here.
  const { HUNTER_ROLES } = require("../mcp/lib/capability-packs.js");
  const hunterPromptFiles = [
    "prompts/roles/hunter.md",
    ...Object.values(HUNTER_ROLES).map((role) => `prompts/roles/${role.prompt_body_filename}`),
  ];
  const HANDOFF_FIELD_NAMES = [
    "summary",
    "chain_notes",
    "blocked_harness_runs",
    "bypass_attempts",
    "attempt_summary",
    "condition",
  ];
  // Trip when a handoff field name and a char-count assertion sit on the
  // same line or in adjacent text — that's a duplicate of the schema-rendered
  // table.
  for (const relativePath of hunterPromptFiles) {
    const body = readFile(relativePath);
    for (const line of body.split(/\r?\n/)) {
      const hasFieldName = HANDOFF_FIELD_NAMES.some((name) => line.includes(`\`${name}\``) || line.includes(name));
      if (!hasFieldName) continue;
      const charLimitMatch = line.match(/(?:≥|≤|<=|>=|max(?:imum)?|at most|at least|min(?:imum)?)\s*\d+(?:[\s-]*char)/i)
        || line.match(/\d+\s*-\s*char\s*\b(?:summary|condition|attempt|chain_notes|blocked_harness)/i);
      if (charLimitMatch) {
        assert.fail(
          `${relativePath} hand-codes a handoff field limit: "${charLimitMatch[0].trim()}" in line: ${line.trim()}; remove the literal — the {{HANDOFF_FIELD_LIMITS}} placeholder is the single source of truth.`,
        );
      }
    }
  }
});

test("rendered hunter prompts include the schema-derived handoff field limits", () => {
  // The renderer reads the live schema in mcp/lib/tools/write-wave-handoff.js
  // and emits one block per hunter prompt. Any hunter agent must see the
  // limits before submission, not from rejection messages.
  const renderedHunterAgents = fs.readdirSync(path.join(ROOT, ".claude/agents"))
    .filter((name) => name.startsWith("hunter") && name.endsWith(".md"))
    .map((name) => `.claude/agents/${name}`);
  for (const relativePath of renderedHunterAgents) {
    const body = readFile(relativePath);
    assert.match(
      body,
      /Handoff field limits \(enforced by `bounty_write_wave_handoff`/,
      `${relativePath} is missing the rendered handoff field limits block`,
    );
    assert.match(body, /`summary`:/);
    assert.match(body, /`chain_notes\[\]`:/);
    assert.match(body, /`blocked_harness_runs\[\]\.harness`:/);
  }
});

test("checked-in .claude/settings.json SubagentStop matches every capability-pack hunter agent", () => {
  // The repo-local settings.json is what direct-from-repo Claude usage reads
  // (e.g., when developing the framework itself or running ./dev-sync.sh).
  // It must stay in lock-step with defaultClaudeSettings() — otherwise SC
  // hunter stop hooks silently fail to fire in repo-local runs.
  const checkedInSettings = JSON.parse(readFile(".claude/settings.json"));
  const expectedHunters = hunterAgentNamesForCapabilityPacks().sort();
  const checkedInHunters = (checkedInSettings.hooks.SubagentStop || [])
    .filter((entry) => (entry.hooks || []).some((hook) => /hunter-subagent-stop\.js/.test(hook.command)))
    .map((entry) => entry.matcher)
    .sort();

  assert.deepEqual(checkedInHunters, expectedHunters);
});

test("each capability pack's role_bundles match the routed Claude role's mcp_role_bundles", () => {
  // pack -> role drift would silently misroute or drop tools at spawn time.
  // Build agent_name -> role_id from CLAUDE_ROLE_SPECS and assert lock-step.
  const agentNameToRoleId = {};
  for (const [roleId, spec] of Object.entries(CLAUDE_ROLE_SPECS)) {
    if (spec.kind === "agent" && typeof spec.output_path === "string") {
      const agentName = path.basename(spec.output_path).replace(/\.md$/, "");
      agentNameToRoleId[agentName] = roleId;
    }
  }
  for (const pack of Object.values(CAPABILITY_PACKS)) {
    const roleId = agentNameToRoleId[pack.hunter_agent];
    assert.ok(
      roleId,
      `capability pack ${pack.id} hunter_agent ${pack.hunter_agent} has no Claude role spec`,
    );
    const role = roleDefinition(roleId);
    const packBundles = Array.from(pack.role_bundles).sort();
    const roleBundles = Array.from(role.mcp_role_bundles).sort();
    assert.deepEqual(
      packBundles,
      roleBundles,
      `capability pack ${pack.id}.role_bundles (${packBundles.join(",")}) must equal role ${roleId}.mcp_role_bundles (${roleBundles.join(",")})`,
    );
  }
});

test("every SC pack ships a complete spawn block consumed by the catalogue renderer", () => {
  // The orchestrator skill embeds {{HUNTER_PACK_CATALOGUE}}; the renderer
  // calls assertSpawnField() for every pack, so a missing or non-string
  // spawn field will throw at render time. This test catches missing fields
  // in the source registry without waiting for the renderer to throw.
  const { BLOCKED_HARNESS_RUN_KINDS } = require("../mcp/lib/capability-packs-rendering.js");
  for (const pack of Object.values(CAPABILITY_PACKS)) {
    assert.ok(pack.spawn, `pack ${pack.id} must declare a spawn block`);
    assert.ok(typeof pack.spawn.profile === "string", `pack ${pack.id} spawn.profile must be a string`);
    if (pack.spawn.profile === "smart_contract") {
      for (const field of ["chain_family", "hunter_name_prefix", "chain_id_description", "workflow_summary", "cli_dependency", "blocked_harness_kind_options"]) {
        assert.ok(
          typeof pack.spawn[field] === "string" && pack.spawn[field].trim(),
          `SC pack ${pack.id} spawn.${field} must be a non-empty string`,
        );
      }
      // Every kind in blocked_harness_kind_options must be in the
      // bounty_write_wave_handoff schema enum, otherwise hunters that
      // follow the catalogue will fail finalization.
      const kinds = pack.spawn.blocked_harness_kind_options.split(/\s+or\s+/).map((t) => t.trim()).filter(Boolean);
      for (const kind of kinds) {
        assert.ok(
          BLOCKED_HARNESS_RUN_KINDS.includes(kind),
          `SC pack ${pack.id} blocked_harness_kind_options token "${kind}" must be in the bounty_write_wave_handoff schema enum`,
        );
      }
    }
  }
});

test("BLOCKED_HARNESS_RUN_KINDS, schema enum, and waves.js normalizer all stay in sync", () => {
  // Three-way mirror: the renderer constant, the JSON schema enum, and
  // the runtime normalizer in waves.js (which throws on unknown kinds
  // before the schema check would even run). If any of the three
  // diverges, hunters following the catalogue will fail finalization.
  const { BLOCKED_HARNESS_RUN_KINDS } = require("../mcp/lib/capability-packs-rendering.js");
  const schema = require("../mcp/lib/tools/write-wave-handoff.js").inputSchema;
  const enumFromSchema = schema.properties.blocked_harness_runs.items.properties.kind.enum;
  // Read the runtime list from waves.js source — it is not exported but
  // pinning the literal string ensures the runtime stays in lock-step.
  const wavesSource = readFile("mcp/lib/waves.js");
  const wavesEnumMatch = wavesSource.match(/BLOCKED_HARNESS_KIND_VALUES = Object\.freeze\(\[([^\]]+)\]\)/);
  assert.ok(wavesEnumMatch, "could not locate BLOCKED_HARNESS_KIND_VALUES literal in waves.js");
  const wavesKinds = Array.from(wavesEnumMatch[1].matchAll(/"([a-z_]+)"/g)).map((m) => m[1]);
  const sorted = (arr) => [...arr].sort();
  assert.deepEqual(sorted(BLOCKED_HARNESS_RUN_KINDS), sorted(enumFromSchema),
    "BLOCKED_HARNESS_RUN_KINDS must mirror the write-wave-handoff schema enum");
  assert.deepEqual(sorted(BLOCKED_HARNESS_RUN_KINDS), sorted(wavesKinds),
    "waves.js BLOCKED_HARNESS_KIND_VALUES must mirror BLOCKED_HARNESS_RUN_KINDS — runtime normalizer rejects schema-accepted kinds otherwise");
});

test("BLOCKED_PREREQ_KINDS, schema enum, and waves.js normalizer all stay in sync", () => {
  // Same three-way mirror invariant as BLOCKED_HARNESS_RUN_KINDS. Adding a
  // new prereq kind requires updating all three sites, otherwise hunters
  // either get rejected by the schema or fail finalization in the runtime
  // normalizer.
  const { BLOCKED_PREREQ_KINDS } = require("../mcp/lib/capability-packs-rendering.js");
  const schema = require("../mcp/lib/tools/write-wave-handoff.js").inputSchema;
  const enumFromSchema = schema.properties.blocked_prereqs.items.properties.kind.enum;
  const wavesSource = readFile("mcp/lib/waves.js");
  const wavesEnumMatch = wavesSource.match(/BLOCKED_PREREQ_KIND_VALUES = Object\.freeze\(\[([^\]]+)\]\)/);
  assert.ok(wavesEnumMatch, "could not locate BLOCKED_PREREQ_KIND_VALUES literal in waves.js");
  const wavesKinds = Array.from(wavesEnumMatch[1].matchAll(/"([a-z_]+)"/g)).map((m) => m[1]);
  const sorted = (arr) => [...arr].sort();
  assert.deepEqual(sorted(BLOCKED_PREREQ_KINDS), sorted(enumFromSchema),
    "BLOCKED_PREREQ_KINDS must mirror the write-wave-handoff schema enum");
  assert.deepEqual(sorted(BLOCKED_PREREQ_KINDS), sorted(wavesKinds),
    "waves.js BLOCKED_PREREQ_KIND_VALUES must mirror BLOCKED_PREREQ_KINDS — runtime normalizer rejects schema-accepted kinds otherwise");
});

test("blocked_prereqs identifier_hint pattern matches between schema and runtime normalizer", () => {
  // The schema regex and the runtime normalizer must reject the same
  // strings, otherwise hunters can submit secret-shaped values that pass
  // one check and fail the other (or worse, leak through).
  const schema = require("../mcp/lib/tools/write-wave-handoff.js").inputSchema;
  const schemaPattern = schema.properties.blocked_prereqs.items.properties.identifier_hint.pattern;
  const wavesSource = readFile("mcp/lib/waves.js");
  const runtimeMatch = wavesSource.match(/BLOCKED_PREREQ_IDENTIFIER_HINT_PATTERN = (\/[^\n]+\/)/);
  assert.ok(runtimeMatch, "could not locate BLOCKED_PREREQ_IDENTIFIER_HINT_PATTERN literal in waves.js");
  // Strip leading and trailing /; runtime pattern is a JS regex literal,
  // schema pattern is a JSON-schema string.
  const runtimePattern = runtimeMatch[1].slice(1, -1);
  assert.equal(runtimePattern, schemaPattern,
    "blocked_prereqs[].identifier_hint pattern must be identical between the JSON schema and the waves.js runtime normalizer");
});

test("rendered hunter prompts include blocked_prereqs handoff field limits", () => {
  // The placeholder substitution in capability-packs-rendering.js writes
  // limits for blocked_prereqs[] into every hunter prompt. Without this,
  // hunters learn the constraints by rejection.
  const { renderHandoffFieldLimits, BLOCKED_PREREQ_KINDS } = require("../mcp/lib/capability-packs-rendering.js");
  const limits = renderHandoffFieldLimits();
  assert.match(limits, /blocked_prereqs\[\]\.kind/,
    "renderHandoffFieldLimits must surface blocked_prereqs[].kind for hunter prompts");
  for (const kind of BLOCKED_PREREQ_KINDS) {
    assert.ok(limits.includes(kind),
      `renderHandoffFieldLimits must list every BLOCKED_PREREQ_KIND in the rendered limits — missing ${kind}`);
  }
  assert.match(limits, /blocked_prereqs\[\]\.identifier_hint/,
    "renderHandoffFieldLimits must surface blocked_prereqs[].identifier_hint with its lowercase-handle constraint");
  assert.match(limits, /no secrets/,
    "renderHandoffFieldLimits must remind hunters that identifier_hint cannot hold secret-shaped values");
});

test("rendered orchestrator catalogue lists every smart-contract pack exactly once", () => {
  // Adding a new SC pack auto-extends the catalogue. The test enforces the
  // 1:1 pack -> catalogue line invariant so a renderer regression that
  // double-renders or skips a pack is caught immediately. Catalogue is
  // keyed by capability_pack (the value bounty_start_wave actually returns
  // on each assignment), not chain_family.
  const rendered = readFile(".claude/skills/bob-hunt/SKILL.md");
  for (const pack of Object.values(CAPABILITY_PACKS)) {
    if (pack.spawn.profile !== "smart_contract") continue;
    const escaped = pack.id.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const lineRegex = new RegExp(`- \`capability_pack: "${escaped}"\` \\(chain_family \`[^\`]+\`\\) -> hunter_agent \`${pack.hunter_agent}\``, "g");
    const matches = rendered.match(lineRegex) || [];
    assert.equal(
      matches.length,
      1,
      `rendered orchestrator catalogue must list pack ${pack.id} exactly once (found ${matches.length})`,
    );
  }
});

test("adding a chain pack costs the documented number of files (registry consolidation gate)", () => {
  // HUNTER_ROLES + CAPABILITY_PACKS in mcp/lib/capability-packs.js are the
  // source of truth for hunter routing. role-model.js,
  // claude-role-renderer.js, codex/role-specs.js, and tool-registry.js all
  // derive their hunter role specs / chain bundles from the registry instead
  // of carrying parallel hand-coded entries.
  //
  // This test asserts that no chain-specific identifiers leak into the four
  // consumer files outside the cross-cutting bundles. If a future maintainer
  // adds a chain literal back ("hunter-evm" / "hunter-svm" / etc.) outside
  // the canonical registry, this test fails — forcing the maintainer either
  // to remove the duplication or to update this gate's known-allowed list.
  const chainBundles = ["hunter-evm", "hunter-svm", "hunter-move", "hunter-substrate", "hunter-cosmwasm"];
  const consumers = [
    "mcp/lib/role-model.js",
    "mcp/lib/tool-registry.js",
    "scripts/lib/claude-role-renderer.js",
    "scripts/lib/codex-role-renderer.js",
    "adapters/codex/role-specs.js",
  ];
  for (const consumer of consumers) {
    const body = readFile(consumer);
    for (const bundle of chainBundles) {
      const matches = body.match(new RegExp(`\\b${bundle.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "g")) || [];
      assert.equal(
        matches.length,
        0,
        `${consumer} hardcodes "${bundle}" — chain-specific identifiers must come from HUNTER_ROLES in capability-packs.js, not be repeated in consumer files`,
      );
    }
  }

  // Also pin the file-cost: enumerate the files that must change to add a
  // 7th chain pack today. This is the abstraction's promise.
  // - mcp/lib/capability-packs.js: define HUNTER_ROLES + CAPABILITY_PACKS entries
  // - mcp/lib/findings.js: chain_id + address validation (irreducible per chain)
  // - prompts/roles/hunter-X.md: hunter prompt body (irreducible)
  // - prompts/roles/chain.md: pivot patterns (irreducible)
  const KNOWN_PACK_TOUCH_FILES = [
    "mcp/lib/capability-packs.js",
    "mcp/lib/findings.js",
    "prompts/roles/chain.md",
    "prompts/roles/hunter-NEW_CHAIN.md (new file)",
  ];
  // Anchor the count so a maintainer adding a new chain coupling outside
  // the registry has to either fix the abstraction or extend this list.
  assert.ok(
    KNOWN_PACK_TOUCH_FILES.length <= 4,
    `Adding a chain pack must touch ≤4 files; currently documented as ${KNOWN_PACK_TOUCH_FILES.length}: ${KNOWN_PACK_TOUCH_FILES.join(", ")}`,
  );
});

test("HUNTER_ROLES is the single source of truth for hunter role specs across consumers", () => {
  // role-model.js, claude-role-renderer.js, codex/role-specs.js all
  // generate their hunter entries from HUNTER_ROLES at module load. This
  // test asserts cross-consumer consistency: every HUNTER_ROLES entry
  // surfaces in each consumer with matching name and bundle list.
  const { HUNTER_ROLES } = require("../mcp/lib/capability-packs.js");
  const { ROLE_DEFINITIONS } = require("../mcp/lib/role-model.js");

  for (const role of Object.values(HUNTER_ROLES)) {
    const claudeSpec = CLAUDE_ROLE_SPECS[role.role_id];
    const codexSpec = CODEX_ROLE_SPECS[role.role_id];
    const roleDef = ROLE_DEFINITIONS[role.role_id];

    assert.ok(claudeSpec, `HUNTER_ROLES.${role.role_id} missing CLAUDE_ROLE_SPECS entry`);
    assert.ok(codexSpec, `HUNTER_ROLES.${role.role_id} missing CODEX_ROLE_SPECS entry`);
    assert.ok(roleDef, `HUNTER_ROLES.${role.role_id} missing ROLE_DEFINITIONS entry`);

    assert.equal(claudeSpec.name, role.name, `Claude spec name mismatch for ${role.role_id}`);
    assert.equal(claudeSpec.color, role.color, `Claude spec color mismatch for ${role.role_id}`);
    assert.equal(claudeSpec.description, role.description, `Claude spec description mismatch for ${role.role_id}`);
    assert.equal(codexSpec.bob_role, role.name, `Codex spec bob_role mismatch for ${role.role_id}`);
    assert.deepEqual(
      [...roleDef.mcp_role_bundles].sort(),
      [...role.role_bundles].sort(),
      `role-model.js mcp_role_bundles drifted from HUNTER_ROLES for ${role.role_id}`,
    );
  }
});

test("renderer source files contain no per-chain workflow strings (pack.spawn is the only source)", () => {
  // Anti-cruft: per-chain workflow strings must live in pack.spawn, not in
  // the renderer source. Catching `bounty_evm_fetch_source -> read sources`
  // (workflow head) or chain-family-specific cli dependencies in the
  // renderer source means duplication is creeping back in. This test pins
  // that the renderers stay registry-driven.
  const claudeRenderer = readFile("scripts/lib/claude-role-renderer.js");
  const codexRenderer = readFile("scripts/lib/codex-role-renderer.js");
  const forbiddenWorkflowFragments = [
    "bounty_evm_fetch_source -> read sources",
    "bounty_svm_fetch_program (confirm",
    "bounty_aptos_fetch_module (enumerate",
    "bounty_sui_fetch_package (enumerate",
    "bounty_substrate_fetch_runtime (confirm",
    "bounty_cosmwasm_fetch_contract (confirm",
  ];
  for (const fragment of forbiddenWorkflowFragments) {
    assert.ok(
      !claudeRenderer.includes(fragment),
      `claude-role-renderer.js must not inline workflow fragment "${fragment}" — move it to pack.spawn`,
    );
    assert.ok(
      !codexRenderer.includes(fragment),
      `codex-role-renderer.js must not inline workflow fragment "${fragment}" — move it to pack.spawn`,
    );
  }
  // Also pin: no SPAWN_HUNTER_*_AGENT placeholder per-chain bodies in the
  // renderer constants — pack.spawn is the only source.
  assert.doesNotMatch(claudeRenderer, /SPAWN_HUNTER_EVM_AGENT|SPAWN_HUNTER_SVM_AGENT|SPAWN_HUNTER_MOVE_AGENT|SPAWN_HUNTER_SUBSTRATE_AGENT|SPAWN_HUNTER_COSMWASM_AGENT/);
  assert.doesNotMatch(codexRenderer, /SPAWN_HUNTER_EVM_AGENT|SPAWN_HUNTER_SVM_AGENT|SPAWN_HUNTER_MOVE_AGENT|SPAWN_HUNTER_SUBSTRATE_AGENT|SPAWN_HUNTER_COSMWASM_AGENT/);
});

test("hunter agent tool counts stay bounded under capability packs (anti-cruft budget)", () => {
  // Cap routed hunters tightly. The web hunter has explicit web-only technique
  // pack tools; smart-contract hunters stay on the stricter pack budget.
  const HUNTER_MCP_TOOL_BUDGET = 16;
  const agentNameToRoleId = {};
  for (const [roleId, spec] of Object.entries(CLAUDE_ROLE_SPECS)) {
    if (spec.kind === "agent" && typeof spec.output_path === "string") {
      const agentName = path.basename(spec.output_path).replace(/\.md$/, "");
      agentNameToRoleId[agentName] = roleId;
    }
  }
  for (const pack of Object.values(CAPABILITY_PACKS)) {
    const roleId = agentNameToRoleId[pack.hunter_agent];
    const tools = mcpToolNamesForRole(roleId);
    const budget = pack.brief_profile === "web" ? 18 : HUNTER_MCP_TOOL_BUDGET;
    assert.ok(
      tools.length <= budget,
      `pack ${pack.id} hunter ${pack.hunter_agent} has ${tools.length} MCP tools (budget ${budget}); justify or split before raising the cap`,
    );
  }
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

test("verifier role bundle has only one documented mutating tool (evm-fetch-source) and no orchestration mutators", () => {
  // The role-bundle expansion that gave verifiers SC re-run primitives also
  // included bounty_evm_fetch_source, which writes to the per-session
  // contracts cache (mutating:true). That one is an intentional, documented
  // exception. NO mutator that advances orchestration (recordFinding,
  // write_wave_handoff, finalize_hunter_run, log_coverage, log_dead_ends,
  // write_grade_verdict) may slip into the verifier bundle.
  const verifierBundleTools = TOOLS.filter((tool) => {
    const meta = TOOL_MANIFEST[tool.name];
    return meta && Array.isArray(meta.role_bundles) && meta.role_bundles.includes("verifier");
  });
  const mutatingInVerifier = verifierBundleTools.filter((tool) => TOOL_MANIFEST[tool.name].mutating === true);
  assert.deepEqual(
    mutatingInVerifier.map((tool) => tool.name).sort(),
    [
      "bounty_evm_fetch_source",       // SC source-cache populate during re-run
      "bounty_http_scan",              // web PoC replay (existing baseline)
      "bounty_write_verification_round" // the verifier's own write path
    ].sort(),
    "Only evm-fetch-source, http_scan, and write-verification-round may be mutating in the verifier bundle. New mutating tools must be reviewed before joining verifier role.",
  );
  const forbidden = ["bounty_record_finding", "bounty_write_wave_handoff", "bounty_finalize_hunter_run", "bounty_log_coverage", "bounty_log_dead_ends", "bounty_write_grade_verdict", "bounty_apply_wave_merge"];
  for (const tool of forbidden) {
    const meta = TOOL_MANIFEST[tool];
    if (!meta) continue;
    assert.ok(
      !meta.role_bundles.includes("verifier"),
      `${tool} must NOT be in the verifier role bundle — orchestration mutators stay hunter/orchestrator-only.`,
    );
  }
});

test("verifier agents expose EVM read-side and PoC-replay tools for SC findings", () => {
  // SC findings need bounty_foundry_run for re-run plus the read-side
  // primitives (evm_call/storage/source/role_table/halmos) for trust-map
  // checks. All six tools must appear in the rendered tools list.
  const requiredTools = [
    "bounty_foundry_run",
    "bounty_halmos_run",
    "bounty_evm_call",
    "bounty_evm_storage_read",
    "bounty_evm_fetch_source",
    "bounty_evm_role_table",
  ];
  for (const agent of ["brutalist-verifier", "balanced-verifier", "final-verifier"]) {
    const document = readFile(`.claude/agents/${agent}.md`);
    const frontmatter = parseFrontmatter(document, `${agent}.md`);
    for (const tool of requiredTools) {
      assert.match(
        frontmatter.tools,
        new RegExp(`mcp__bountyagent__${tool}\\b`),
        `${agent}.md frontmatter is missing ${tool}`,
      );
    }
  }
});

test("chain-builder prompt enforces severity ladder, finding-id citations, and surface-match", () => {
  const prompt = readFile("prompts/roles/chain.md");
  // Disambiguation by surface_type
  assert.match(prompt, /surface_type/, "chain.md must branch on surface_type");
  assert.match(prompt, /smart_contract/, "chain.md must mention smart_contract");
  // SC patterns
  for (const pattern of ["oracle_manipulation", "governance_bypass", "signature_replay", "role_compromise", "flash_loan_callable_entry", "hook_callback_abuse"]) {
    assert.match(prompt, new RegExp(pattern), `chain.md missing SC pattern: ${pattern}`);
  }
  // Cross-family chain reasoning
  assert.match(prompt, /Cross-family/i, "chain.md must mention cross-family chains");
  assert.match(prompt, /subdomain_takeover/, "chain.md missing canonical web→SC pivot");
  // SEVERITY LADDER: enforce no jumping rungs and no LOW+LOW elevation.
  // "LOW+LOW concatenation forbidden" alone left a LOW+LOW→MEDIUM loophole;
  // test the ladder explicitly so the loophole stays closed.
  assert.match(prompt, /LOW\s*\+\s*LOW.*at most LOW/i, "chain.md must cap LOW+LOW at LOW");
  assert.match(prompt, /LOW\s*\+\s*MEDIUM.*at most MEDIUM/i, "chain.md must cap LOW+MEDIUM at MEDIUM");
  assert.match(prompt, /severity-elevation rationale/i, "chain.md must require an explicit elevation rationale for any composition that claims a higher severity than the worst input link");
  assert.match(prompt, /jump-the-rung|jump the rung/i, "chain.md must forbid jump-the-rung escalations");
  // PROOF: chain_notes is hint, not proof. Every link MUST cite a finding_id.
  assert.match(prompt, /finding_id.*MUST|MUST cite a `finding_id`|MUST cite.*finding_id/i, "chain.md must require finding_id citation per link");
  assert.match(prompt, /chain_notes.*hint|hint.*chain_notes|chain_notes.*not proof/i, "chain.md must clarify chain_notes is hint, not proof");
  // SURFACE MATCH: SC link must cite surface_type=smart_contract finding with sc_evidence
  assert.match(prompt, /surface_type:\s*"smart_contract"/, "chain.md must require SC link to cite surface_type=smart_contract finding");
  assert.match(prompt, /sc_evidence/, "chain.md must reference sc_evidence requirement on SC link");
});

test("report-writer prompt gates on reportable, never invents blocks, and severity-DESC executive summary", () => {
  const prompt = readFile("prompts/roles/reporter.md");
  // Surface routing
  assert.match(prompt, /surface_type/, "reporter.md must branch on surface_type");
  assert.match(prompt, /smart_contract/, "reporter.md must mention smart_contract");
  // SC section anatomy
  for (const required of ["Chain \\+ Address", "Affected Function", "On-chain effect", "Verified at", "Remediation"]) {
    assert.match(prompt, new RegExp(required), `reporter.md missing SC section: ${required}`);
  }
  // REPORTABILITY GATE: only render reportable: true findings
  assert.match(prompt, /reportable.*true|REPORTABILITY GATE/i, "reporter.md must gate rendering on final-verifier reportable: true");
  assert.match(prompt, /\bskip\b/i, "reporter.md must say to skip non-reportable findings");
  // BLOCK FABRICATION: polarity flipped — render block ONLY when reasoning has
  // the literal substring; default is "block reference unavailable"
  assert.match(prompt, /block reference unavailable/, "reporter.md must teach the never-invent-a-block convention");
  assert.match(prompt, /Never derive.*sc_evidence\.fork_block|never derive.*fork_block|do NOT.*sc_evidence\.fork_block/i, "reporter.md must forbid deriving verification block from sc_evidence.fork_block");
  // SEVERITY-DESC executive summary
  assert.match(prompt, /severity DESC|severity DESCENDING|sorted by severity/i, "reporter.md must specify severity-DESC executive summary across families");
  // CWE map corrections
  assert.match(prompt, /CWE-294/, "reporter.md must use CWE-294 for signature replay (not CWE-352)");
  assert.match(prompt, /CWE-1284|CWE-829/, "reporter.md must use CWE-1284/CWE-829 for oracle staleness (not CWE-672)");
  // TVL fail-soft mirrors block fail-soft
  assert.match(prompt, /TVL context unavailable/, "reporter.md must declare TVL fail-soft text");
  assert.match(prompt, /Never infer dollar impact/i, "reporter.md must forbid TVL inference from PoC content");
  // Severity precedence: final-verifier authoritative; grader is verdict-only
  assert.match(prompt, /grader.*verdict|verdict.*grader|grader.*not.*severity/i, "reporter.md must clarify grader is verdict-only, not severity");
  // Chain reading
  assert.match(prompt, /chains\.md/, "reporter.md must declare chains.md as a read input");
});

test("report-writer agent has Read tool exposure for chains.md", () => {
  const document = readFile(".claude/agents/report-writer.md");
  const frontmatter = parseFrontmatter(document, "report-writer.md");
  assert.match(frontmatter.tools, /\bRead\b/, "report-writer must expose Read tool to consume chains.md");
});

test("verifier prompt sources instruct pack-driven dispatch and embed the capability pack verifier table", () => {
  // SC dispatch lives in the capability-pack manifest, not in each verifier
  // prompt body. Sources must instruct lookup via finding.capability_pack
  // and embed the {{CAPABILITY_PACK_VERIFIER_TABLE}} placeholder so the
  // renderer drops the per-pack reference table at the bottom of each
  // rendered agent. The polarity convention and SC fail-mode language stay
  // in every source prompt so a polarity bug can't slip in.
  for (const role of ["brutalist-verifier", "balanced-verifier", "final-verifier"]) {
    const prompt = readFile(`prompts/roles/${role}.md`);
    assert.match(prompt, /sc_evidence/, `${role}.md does not mention sc_evidence`);
    assert.match(prompt, /finding\.capability_pack/, `${role}.md must instruct lookup via finding.capability_pack`);
    assert.match(prompt, /\{\{CAPABILITY_PACK_VERIFIER_TABLE\}\}/, `${role}.md must embed the capability pack verifier table placeholder`);
    assert.match(prompt, /smart_contract|smart-contract/i, `${role}.md does not branch on smart_contract`);
    assert.match(
      prompt,
      /Pass.*reproduce|reproduce.*Pass|assert(s|ed)?\s+the\s+bug|exploit harness|exploit-test/i,
      `${role}.md does not document the test-pass = bug-reproduced convention`,
    );
    assert.match(
      prompt,
      /not_in_path|fork-blocked|cannot re-run|cannot finalize/i,
      `${role}.md does not document SC fail-closed behavior`,
    );
  }
});

test("rendered verifier agents carry every capability pack runner via the rendered pack table", () => {
  // The rendered .claude/agents/*-verifier.md files must contain the
  // capability-pack verifier table with every pack's runner, fail-mode
  // codes, and disambiguation tool. Adding a new pack to capability-packs.js
  // updates these at next regeneration without touching prompt sources.
  for (const role of ["brutalist-verifier", "balanced-verifier", "final-verifier"]) {
    const rendered = readFile(`.claude/agents/${role}.md`);
    assert.match(rendered, /Capability pack verifier table/, `${role}.md must render the capability pack table`);
    for (const runner of [
      "bounty_http_scan",
      "bounty_foundry_run",
      "bounty_anchor_run",
      "bounty_aptos_run",
      "bounty_sui_run",
      "bounty_substrate_run",
      "bounty_cosmwasm_run",
    ]) {
      assert.match(rendered, new RegExp(runner), `${role}.md rendered table must list ${runner}`);
    }
  }
});

test("capability pack registry exposes a verifier replay tool for every pack", () => {
  // The pack manifest is the dispatch source of truth. Every pack must
  // declare a replay_tool that resolves to a registered MCP tool and a
  // sample_type for evidence labels. SC packs must also declare a
  // disambiguation read; web is allowed to omit it.
  const { CAPABILITY_PACKS } = require("../mcp/lib/capability-packs.js");
  const toolNames = new Set(Object.keys(TOOL_MANIFEST));
  for (const pack of Object.values(CAPABILITY_PACKS)) {
    const v = pack.verifier;
    assert.ok(v, `pack ${pack.id} must declare a verifier block`);
    assert.ok(typeof v.replay_tool === "string" && v.replay_tool.length > 0,
      `pack ${pack.id} verifier.replay_tool must be a non-empty string`);
    assert.ok(toolNames.has(v.replay_tool),
      `pack ${pack.id} verifier.replay_tool ${v.replay_tool} is not a registered MCP tool`);
    assert.ok(typeof v.sample_type === "string" && v.sample_type.length > 0,
      `pack ${pack.id} verifier.sample_type must be a non-empty string`);
    if (pack.id !== "web") {
      // Same-shape addresses across networks (Aptos↔Sui 0x+64hex, SS58
      // polkadot↔kusama, bech32 osmo↔juno) cannot be distinguished by the
      // runner alone. Every SC pack must declare the disambiguation read
      // tool. Newcomer packs that genuinely don't need one (e.g. EVM —
      // chain_id alone fixes the fork) are allowed to set null explicitly.
      assert.ok(v.disambiguation === null || (v.disambiguation && toolNames.has(v.disambiguation.tool)),
        `pack ${pack.id} verifier.disambiguation.tool must be null or a registered MCP tool`);
    }
  }
});

test("capability pack registry exposes an evidence runner for every pack", () => {
  const { CAPABILITY_PACKS } = require("../mcp/lib/capability-packs.js");
  const toolNames = new Set(Object.keys(TOOL_MANIFEST));
  for (const pack of Object.values(CAPABILITY_PACKS)) {
    const e = pack.evidence;
    assert.ok(e, `pack ${pack.id} must declare an evidence block`);
    assert.ok(toolNames.has(e.runner),
      `pack ${pack.id} evidence.runner ${e.runner} is not a registered MCP tool`);
    assert.equal(typeof e.sample_type, "string");
  }
});

test("verifier prompt sources stay below the chain_family branching budget (anti-cruft)", () => {
  // The source prompt instructs pack-driven dispatch once; the renderer
  // drops the per-pack table. Crossing 2 chain_family references in a
  // verifier source means the prompt is creeping back to per-chain
  // branching (which the pack manifest is meant to absorb).
  for (const role of ["brutalist-verifier", "balanced-verifier", "final-verifier", "evidence"]) {
    const prompt = readFile(`prompts/roles/${role}.md`);
    const matches = prompt.match(/chain_family/g) || [];
    assert.ok(
      matches.length <= 2,
      `${role}.md has ${matches.length} chain_family references; cap is 2 (the dispatch lives in the pack manifest)`,
    );
  }
});

test("hunter-svm-agent ships with the SVM tool surface", () => {
  const document = readFile(".claude/agents/hunter-svm-agent.md");
  const frontmatter = parseFrontmatter(document, "hunter-svm-agent.md");
  const tools = frontmatter.tools.split(",").map((tool) => tool.trim());
  assert.ok(tools.includes("mcp__bountyagent__bounty_svm_fetch_account"), "hunter-svm needs svm_fetch_account");
  assert.ok(tools.includes("mcp__bountyagent__bounty_svm_fetch_program"), "hunter-svm needs svm_fetch_program for upgrade authority");
  assert.ok(tools.includes("mcp__bountyagent__bounty_anchor_run"), "hunter-svm needs anchor_run for PoCs");
  assert.ok(tools.includes("mcp__bountyagent__bounty_record_finding"), "hunter-svm needs record_finding");
  assert.ok(tools.includes("Write"), "hunter-svm needs Write to scaffold Anchor tests");
});

test("hunter-svm prompt encodes the chain_family=svm anti-stop rule and sc_evidence shape", () => {
  const prompt = readFile("prompts/roles/hunter-svm.md");
  // Chain-family confirmation pattern
  assert.match(prompt, /chain_family.*svm|svm.*chain_family/i, "hunter-svm must confirm chain_family is svm");
  // sc_evidence shape — must teach the SVM-specific contract_address (program_id) + cluster
  assert.match(prompt, /chain_family.*"svm"/i, "hunter-svm must instruct chain_family: svm in sc_evidence");
  assert.match(prompt, /base58/i, "hunter-svm must teach base58 program_id encoding");
  assert.match(prompt, /cluster/i, "hunter-svm must teach cluster as chain_id");
  // Anchor harness primitive
  assert.match(prompt, /bounty_anchor_run/, "hunter-svm must document bounty_anchor_run");
});

test("orchestrator dispatches by chain_family to hunter-evm or hunter-svm via pack catalogue", () => {
  // Per-chain SPAWN_HUNTER_*_AGENT placeholders are absent. The orchestrator
  // embeds a single {{HUNTER_PACK_CATALOGUE}} that the renderer fills from
  // the pack registry; the rendered skill must list every SC pack's
  // chain_family + hunter_agent in the catalogue lines.
  const source = readFile("prompts/roles/orchestrator.md");
  assert.match(source, /\{\{HUNTER_PACK_CATALOGUE\}\}/, "orchestrator source must embed the HUNTER_PACK_CATALOGUE placeholder");
  assert.doesNotMatch(source, /SPAWN_HUNTER_EVM_AGENT|SPAWN_HUNTER_SVM_AGENT|SPAWN_HUNTER_MOVE_AGENT|SPAWN_HUNTER_SUBSTRATE_AGENT|SPAWN_HUNTER_COSMWASM_AGENT/, "orchestrator source must not contain per-chain spawn placeholders");

  assert.equal(CAPABILITY_PACKS.smart_contract_evm.spawn.chain_family, "evm");
  assert.equal(CAPABILITY_PACKS.smart_contract_evm.hunter_agent, "hunter-evm-agent");
  assert.equal(CAPABILITY_PACKS.smart_contract_svm.spawn.chain_family, "svm");
  assert.equal(CAPABILITY_PACKS.smart_contract_svm.hunter_agent, "hunter-svm-agent");

  const rendered = readFile(".claude/skills/bob-hunt/SKILL.md");
  assert.match(rendered, /capability_pack: "smart_contract_evm".*hunter-evm-agent/, "rendered orchestrator must list smart_contract_evm -> hunter-evm-agent in catalogue");
  assert.match(rendered, /capability_pack: "smart_contract_svm".*hunter-svm-agent/, "rendered orchestrator must list smart_contract_svm -> hunter-svm-agent in catalogue");
});

test("chain-builder prompt enumerates SVM patterns and enforces svm-cite-finding", () => {
  const prompt = readFile("prompts/roles/chain.md");
  assert.match(prompt, /SC SVM patterns|chain_family.*svm/i, "chain.md must enumerate SVM patterns");
  assert.match(prompt, /missing_signer|cpi_privilege_escalation|upgrade_authority_compromise/, "chain.md must list SVM bug-class pivots");
  assert.match(prompt, /chain_family.*evm|evm.*chain_family/, "chain.md must enforce evm-side cite");
  assert.match(prompt, /chain_family.*svm|svm.*chain_family/, "chain.md must enforce svm-side cite");
});

test("report-writer prompt renders SVM cluster + program_id + cwe map", () => {
  const prompt = readFile("prompts/roles/reporter.md");
  // SVM Chain + Address line
  assert.match(prompt, /cluster.*program_id|program_id.*cluster/, "reporter.md must render SVM cluster + program_id");
  // SVM CWE map entries
  assert.match(prompt, /CWE-862/, "reporter.md must map missing_signer to CWE-862");
  assert.match(prompt, /CWE-345/, "reporter.md must map account validation/sysvar to CWE-345");
  // cpi_privilege_escalation maps to CWE-863 (incorrect authorization).
  // CWE-269 is privilege management; signer extension via CPI is an
  // authorization-decision bug.
  assert.match(prompt, /CWE-863/, "reporter.md must map cpi_privilege_escalation to CWE-863");
  assert.doesNotMatch(prompt, /cpi_privilege_escalation.*CWE-269/, "reporter.md must NOT map cpi_privilege_escalation to CWE-269");
  // SVM remediation
  assert.match(prompt, /Anchor|#\[account\(signer\)\]|require_keys_eq/, "reporter.md must offer Anchor remediation snippets");
  // Gas-render fence: gas only for EVM, never for SVM
  assert.match(prompt, /Gas cost.*EVM only|never render a gas line for SVM/i, "reporter.md must restrict gas rendering to EVM");
  // SVM block-reference rendering uses Solana vocabulary. The verifier
  // matcher stays uniform, but the reporter branches by chain_family.
  assert.match(prompt, /slot .*<N>.*on cluster .*<X>/i, "reporter.md must render 'slot N on cluster X' for SVM findings");
  assert.match(prompt, /slot reference unavailable/i, "reporter.md must use 'slot reference unavailable' for SVM");
});

test("verifier prompts document the SC tooling fail-mode taxonomy at least once", () => {
  // anchor_not_in_path only fires on ENOENT for the anchor binary itself.
  // When cargo / solana / solana-test-validator / yarn / jest / ts-mocha
  // cause the failure, we surface anchor_dependency_missing or
  // anchor_test_runner_unknown. The taxonomy is generic across runners:
  // <runner>_not_in_path, <runner>_dependency_missing,
  // <runner>_test_runner_unknown, move_compile_failed, cargo_compile_failed,
  // rpc_unreachable. Each verifier source must mention the canonical pattern
  // so the prompt tells the agent how to interpret runner failures.
  for (const role of ["brutalist-verifier", "balanced-verifier", "final-verifier"]) {
    const prompt = readFile(`prompts/roles/${role}.md`);
    assert.match(prompt, /not_in_path/, `${role}.md must reference the <runner>_not_in_path family of fail-modes`);
    assert.match(prompt, /dependency_missing/, `${role}.md must reference the <runner>_dependency_missing family`);
  }
});

// ----------------------------------------------------------------------
// Move (Aptos + Sui) prompt contracts
// ----------------------------------------------------------------------

test("Aptos and Sui packs route to the correct Move runners", () => {
  // smart_contract_aptos and smart_contract_sui are separate packs so
  // verifier dispatch is one runner per pack. Both still use
  // hunter-move-agent (the agent's tool list covers both).
  const { CAPABILITY_PACKS } = require("../mcp/lib/capability-packs.js");
  assert.equal(CAPABILITY_PACKS.smart_contract_aptos.verifier.replay_tool, "bounty_aptos_run");
  assert.equal(CAPABILITY_PACKS.smart_contract_aptos.hunter_agent, "hunter-move-agent");
  assert.equal(CAPABILITY_PACKS.smart_contract_sui.verifier.replay_tool, "bounty_sui_run");
  assert.equal(CAPABILITY_PACKS.smart_contract_sui.hunter_agent, "hunter-move-agent");
  // Move compile fail-mode must be documented in at least one verifier source
  // (it's shared by aptos+sui and applies in the rendered table footer).
  for (const role of ["brutalist-verifier", "balanced-verifier", "final-verifier"]) {
    const prompt = readFile(`prompts/roles/${role}.md`);
    assert.match(prompt, /move_compile_failed/, `${role}.md must reference move_compile_failed in the SC fail-mode taxonomy`);
  }
});

test("hunter-move-agent ships with the Move tool surface", () => {
  const document = readFile(".claude/agents/hunter-move-agent.md");
  const frontmatter = parseFrontmatter(document, "hunter-move-agent.md");
  const tools = frontmatter.tools.split(",").map((tool) => tool.trim());
  assert.ok(tools.includes("mcp__bountyagent__bounty_aptos_fetch_resource"), "hunter-move needs aptos_fetch_resource");
  assert.ok(tools.includes("mcp__bountyagent__bounty_aptos_fetch_module"), "hunter-move needs aptos_fetch_module");
  assert.ok(tools.includes("mcp__bountyagent__bounty_aptos_run"), "hunter-move needs aptos_run for PoCs");
  assert.ok(tools.includes("mcp__bountyagent__bounty_sui_fetch_object"), "hunter-move needs sui_fetch_object");
  assert.ok(tools.includes("mcp__bountyagent__bounty_sui_fetch_package"), "hunter-move needs sui_fetch_package");
  assert.ok(tools.includes("mcp__bountyagent__bounty_sui_run"), "hunter-move needs sui_run for PoCs");
  assert.ok(tools.includes("mcp__bountyagent__bounty_record_finding"), "hunter-move needs record_finding");
  assert.ok(tools.includes("Write"), "hunter-move needs Write to scaffold Move tests");
});

test("hunter-move prompt encodes the chain_family={aptos,sui} branching and sc_evidence shape", () => {
  const prompt = readFile("prompts/roles/hunter-move.md");
  // Family confirmation pattern — both aptos and sui must be named
  assert.match(prompt, /chain_family.*aptos|aptos.*chain_family/i, "hunter-move must confirm chain_family aptos");
  assert.match(prompt, /chain_family.*sui|sui.*chain_family/i, "hunter-move must confirm chain_family sui");
  // sc_evidence shape: chain_family enum
  assert.match(prompt, /chain_family.*"aptos"/i, "hunter-move must instruct chain_family: aptos in sc_evidence");
  assert.match(prompt, /chain_family.*"sui"/i, "hunter-move must instruct chain_family: sui in sc_evidence");
  // Move test primitives
  assert.match(prompt, /bounty_aptos_run/, "hunter-move must document bounty_aptos_run");
  assert.match(prompt, /bounty_sui_run/, "hunter-move must document bounty_sui_run");
  // Bug class catalog
  assert.match(prompt, /capability_leakage/, "hunter-move must list capability_leakage bug class");
  assert.match(prompt, /object_ownership_violation/, "hunter-move must list Sui object_ownership_violation bug class");
  assert.match(prompt, /package_upgrade_authority/, "hunter-move must list package_upgrade_authority bug class");
});

test("orchestrator dispatches by chain_family to hunter-move for aptos and sui packs", () => {
  // smart_contract_aptos and smart_contract_sui are separate packs (one
  // verifier runner per pack), both routing to hunter-move-agent. The pack
  // catalogue renders one entry per pack.
  assert.equal(CAPABILITY_PACKS.smart_contract_aptos.spawn.chain_family, "aptos");
  assert.equal(CAPABILITY_PACKS.smart_contract_aptos.hunter_agent, "hunter-move-agent");
  assert.equal(CAPABILITY_PACKS.smart_contract_sui.spawn.chain_family, "sui");
  assert.equal(CAPABILITY_PACKS.smart_contract_sui.hunter_agent, "hunter-move-agent");

  const rendered = readFile(".claude/skills/bob-hunt/SKILL.md");
  assert.match(rendered, /capability_pack: "smart_contract_aptos".*hunter-move-agent/, "rendered orchestrator must list smart_contract_aptos -> hunter-move-agent");
  assert.match(rendered, /capability_pack: "smart_contract_sui".*hunter-move-agent/, "rendered orchestrator must list smart_contract_sui -> hunter-move-agent");
});

test("chain-builder prompt enumerates Aptos + Sui patterns and enforces aptos/sui-cite-finding", () => {
  const prompt = readFile("prompts/roles/chain.md");
  assert.match(prompt, /SC Aptos patterns|chain_family.*aptos/i, "chain.md must enumerate Aptos patterns");
  assert.match(prompt, /SC Sui patterns|chain_family.*sui/i, "chain.md must enumerate Sui patterns");
  assert.match(prompt, /capability_leakage|signer_capability_leak/, "chain.md must list Move capability bug-class pivots");
  assert.match(prompt, /object_ownership_violation|dynamic_field_unauthorized_remove/, "chain.md must list Sui-specific bug-class pivots");
  assert.match(prompt, /chain_family.*aptos|aptos.*chain_family/, "chain.md must enforce aptos-side cite");
  assert.match(prompt, /chain_family.*sui|sui.*chain_family/, "chain.md must enforce sui-side cite");
});

test("Aptos and Sui packs declare the address-disambiguation read tool", () => {
  // Aptos and Sui share 0x+64-hex address space. A hunter could record
  // chain_family=aptos with a Sui package_id (or vice versa); the runner
  // alone cannot detect this. The disambiguation requirement lives in the
  // pack manifest's verifier block, not in prompt prose.
  const { CAPABILITY_PACKS } = require("../mcp/lib/capability-packs.js");
  const aptos = CAPABILITY_PACKS.smart_contract_aptos.verifier.disambiguation;
  assert.ok(aptos, "smart_contract_aptos must declare a disambiguation read");
  assert.equal(aptos.tool, "bounty_aptos_fetch_module");
  assert.match(aptos.fail_reason, /Aptos|chain_family\/chain_id mismatch/i);
  const sui = CAPABILITY_PACKS.smart_contract_sui.verifier.disambiguation;
  assert.ok(sui, "smart_contract_sui must declare a disambiguation read");
  assert.equal(sui.tool, "bounty_sui_fetch_package");
  assert.match(sui.fail_reason, /Sui|chain_family\/chain_id mismatch/i);
  // Brutalist prompt source must require running the disambiguation when
  // the pack declares one — keeps the contract honest at the call site.
  const brutalist = readFile("prompts/roles/brutalist-verifier.md");
  assert.match(brutalist, /pack's `verifier\.disambiguation` is set/i,
    "brutalist must instruct running pack.verifier.disambiguation when present");
  // The chain_family/chain_id mismatch language lives in pack.disambiguation.fail_reason
  // — surfaced in the rendered brutalist via the verifier table.
  const brutalistRendered = readFile(".claude/agents/brutalist-verifier.md");
  assert.match(brutalistRendered, /chain_family\/chain_id mismatch/i,
    "rendered brutalist must surface chain_family/chain_id mismatch via the pack table");
});

test("balanced-verifier carries Move severity heuristics", () => {
  const balanced = readFile("prompts/roles/balanced-verifier.md");
  assert.match(balanced, /Move severity heuristics/i, "balanced must include Move severity heuristics block");
  assert.match(balanced, /TreasuryCap.*MintCap.*BurnCap.*UpgradeCap|TreasuryCap.*HIGH/i, "balanced must enumerate financial caps as HIGH");
  assert.match(balanced, /read-only.*LOW|configuration-only.*LOW/i, "balanced must classify read-only caps as LOW");
});

test("report-writer prompt renders Aptos network + module_address + Sui network + package_id + Move CWE map", () => {
  const prompt = readFile("prompts/roles/reporter.md");
  // Aptos Chain + Address line
  assert.match(prompt, /network.*module_address|module_address.*network/, "reporter.md must render Aptos network + module_address");
  // Sui Chain + Address line
  assert.match(prompt, /network.*package_id|package_id.*network/, "reporter.md must render Sui network + package_id");
  // Move CWE map entries
  assert.match(prompt, /signer_capability_leak.*CWE-862|CWE-862.*signer_capability_leak/, "reporter.md must map Aptos signer_capability_leak to CWE-862");
  assert.match(prompt, /capability_leakage.*CWE-863|CWE-863.*capability_leakage/, "reporter.md must map Move capability_leakage to CWE-863");
  assert.match(prompt, /generic_type_confusion.*CWE-843|CWE-843.*generic_type_confusion/i, "reporter.md must map generic_type_confusion to CWE-843");
  // Aptos remediation
  assert.match(prompt, /Aptos.*Move|move_to|signer::address_of/i, "reporter.md must offer Aptos Move remediation snippets");
  // Sui remediation
  assert.match(prompt, /Sui.*Move|tx_context::sender|object::owner|UpgradeCap/i, "reporter.md must offer Sui Move remediation snippets");
  // Aptos verified-at vocabulary: version on network
  assert.match(prompt, /version .*<N>.*on network .*<X>/i, "reporter.md must render 'version N on network X' for Aptos findings");
  assert.match(prompt, /version reference unavailable/i, "reporter.md must use 'version reference unavailable' for Aptos");
  // Sui verified-at vocabulary: checkpoint on network
  assert.match(prompt, /checkpoint .*<N>.*on network .*<X>/i, "reporter.md must render 'checkpoint N on network X' for Sui findings");
  assert.match(prompt, /checkpoint reference unavailable/i, "reporter.md must use 'checkpoint reference unavailable' for Sui");
  // Gas-render fence: never for Move (deterministic VM, no realistic mainnet gas)
  assert.match(prompt, /never render a gas line for (Aptos|Sui|Move)/i, "reporter.md must restrict gas rendering away from Move families");
  // CWE entries for Move-specific bug classes
  assert.match(prompt, /key_drop_resource_theft.*CWE-664|CWE-664.*key_drop_resource_theft/i, "reporter.md must map key_drop_resource_theft to CWE-664");
  assert.match(prompt, /store_phantom_drop.*CWE-664|CWE-664.*store_phantom_drop/i, "reporter.md must map store_phantom_drop to CWE-664");
  assert.match(prompt, /key_rotation_replay.*CWE-294|CWE-294.*key_rotation_replay/i, "reporter.md must map key_rotation_replay to CWE-294");
  // Sui owner field shape rendering rule
  assert.match(prompt, /Sui owner-field rendering|AddressOwner\(0x/i, "reporter.md must specify how to flatten Sui owner JSON shapes into prose");
});

test("hunter-substrate-agent ships with the Substrate / ink! tool surface", () => {
  const document = readFile(".claude/agents/hunter-substrate-agent.md");
  const frontmatter = parseFrontmatter(document, "hunter-substrate-agent.md");
  const tools = frontmatter.tools.split(",").map((tool) => tool.trim());
  assert.ok(tools.includes("mcp__bountyagent__bounty_substrate_run"), "hunter-substrate needs substrate_run for PoCs");
  assert.ok(tools.includes("mcp__bountyagent__bounty_substrate_fetch_storage"), "hunter-substrate needs substrate_fetch_storage");
  assert.ok(tools.includes("mcp__bountyagent__bounty_substrate_fetch_runtime"), "hunter-substrate needs substrate_fetch_runtime");
  assert.ok(tools.includes("mcp__bountyagent__bounty_record_finding"), "hunter-substrate needs record_finding");
  assert.ok(tools.includes("Write"), "hunter-substrate needs Write to scaffold ink! tests");
});

test("hunter-cosmwasm-agent ships with the CosmWasm tool surface", () => {
  const document = readFile(".claude/agents/hunter-cosmwasm-agent.md");
  const frontmatter = parseFrontmatter(document, "hunter-cosmwasm-agent.md");
  const tools = frontmatter.tools.split(",").map((tool) => tool.trim());
  assert.ok(tools.includes("mcp__bountyagent__bounty_cosmwasm_run"), "hunter-cosmwasm needs cosmwasm_run for PoCs");
  assert.ok(tools.includes("mcp__bountyagent__bounty_cosmwasm_fetch_contract"), "hunter-cosmwasm needs cosmwasm_fetch_contract");
  assert.ok(tools.includes("mcp__bountyagent__bounty_cosmwasm_smart_query"), "hunter-cosmwasm needs cosmwasm_smart_query");
  assert.ok(tools.includes("mcp__bountyagent__bounty_record_finding"), "hunter-cosmwasm needs record_finding");
  assert.ok(tools.includes("Write"), "hunter-cosmwasm needs Write to scaffold cw-multi-test integration tests");
});

test("hunter-substrate prompt encodes chain_family=substrate branching, sc_evidence shape, and bug class catalog", () => {
  const prompt = readFile("prompts/roles/hunter-substrate.md");
  assert.match(prompt, /chain_family.*"substrate"|chain_family.*: substrate|substrate.*chain_family/i, "hunter-substrate must reference chain_family substrate");
  assert.match(prompt, /chain_family: "substrate"/, "hunter-substrate must instruct chain_family: \"substrate\" in sc_evidence");
  assert.match(prompt, /bounty_substrate_run/, "hunter-substrate must document bounty_substrate_run");
  assert.match(prompt, /bounty_substrate_fetch_storage/, "hunter-substrate must document bounty_substrate_fetch_storage");
  // Bug class catalog
  assert.match(prompt, /set_code_hash_unauthorized/, "hunter-substrate must list set_code_hash_unauthorized");
  assert.match(prompt, /caller_spoof/, "hunter-substrate must list caller_spoof");
  assert.match(prompt, /reentrancy_cross_contract/, "hunter-substrate must list reentrancy_cross_contract");
  assert.match(prompt, /SS58/, "hunter-substrate must reference SS58 address format");
});

test("hunter-cosmwasm prompt encodes chain_family=cosmwasm branching, sc_evidence shape, and bug class catalog", () => {
  const prompt = readFile("prompts/roles/hunter-cosmwasm.md");
  assert.match(prompt, /chain_family.*"cosmwasm"|chain_family.*: cosmwasm|cosmwasm.*chain_family/i, "hunter-cosmwasm must reference chain_family cosmwasm");
  assert.match(prompt, /chain_family: "cosmwasm"/, "hunter-cosmwasm must instruct chain_family: \"cosmwasm\" in sc_evidence");
  assert.match(prompt, /bounty_cosmwasm_run/, "hunter-cosmwasm must document bounty_cosmwasm_run");
  assert.match(prompt, /bounty_cosmwasm_fetch_contract/, "hunter-cosmwasm must document bounty_cosmwasm_fetch_contract");
  assert.match(prompt, /bounty_cosmwasm_smart_query/, "hunter-cosmwasm must document bounty_cosmwasm_smart_query");
  // Bug class catalog
  assert.match(prompt, /migrate_msg_open|migrate.*open/i, "hunter-cosmwasm must list migrate_msg_open");
  assert.match(prompt, /submessage_reply_misuse/, "hunter-cosmwasm must list submessage_reply_misuse");
  assert.match(prompt, /non_payable_check_missing|non_payable/i, "hunter-cosmwasm must list non_payable_check_missing");
  assert.match(prompt, /bech32/i, "hunter-cosmwasm must reference bech32 address format");
});

test("orchestrator dispatches by chain_family to hunter-substrate and hunter-cosmwasm via pack catalogue", () => {
  assert.equal(CAPABILITY_PACKS.smart_contract_substrate.spawn.chain_family, "substrate");
  assert.equal(CAPABILITY_PACKS.smart_contract_substrate.hunter_agent, "hunter-substrate-agent");
  assert.equal(CAPABILITY_PACKS.smart_contract_cosmwasm.spawn.chain_family, "cosmwasm");
  assert.equal(CAPABILITY_PACKS.smart_contract_cosmwasm.hunter_agent, "hunter-cosmwasm-agent");

  const rendered = readFile(".claude/skills/bob-hunt/SKILL.md");
  assert.match(rendered, /capability_pack: "smart_contract_substrate".*hunter-substrate-agent/, "rendered orchestrator must list smart_contract_substrate -> hunter-substrate-agent");
  assert.match(rendered, /capability_pack: "smart_contract_cosmwasm".*hunter-cosmwasm-agent/, "rendered orchestrator must list smart_contract_cosmwasm -> hunter-cosmwasm-agent");
});

test("Substrate and CosmWasm packs declare disambiguation reads", () => {
  // Per-chain dispatch lives in the pack manifest. SS58 prefix bytes are not
  // BLAKE2b-checked (cost), so a Kusama SS58 against chain_id="polkadot"
  // must be caught by an on-chain read; bech32 HRPs similarly need a
  // network-resolving call to detect a wrong-network record.
  const { CAPABILITY_PACKS } = require("../mcp/lib/capability-packs.js");
  const sub = CAPABILITY_PACKS.smart_contract_substrate.verifier;
  assert.equal(sub.replay_tool, "bounty_substrate_run");
  assert.ok(sub.disambiguation, "substrate pack must declare disambiguation read");
  assert.equal(sub.disambiguation.tool, "bounty_substrate_fetch_storage");
  assert.match(sub.disambiguation.fail_reason, /Substrate/);
  const cw = CAPABILITY_PACKS.smart_contract_cosmwasm.verifier;
  assert.equal(cw.replay_tool, "bounty_cosmwasm_run");
  assert.ok(cw.disambiguation, "cosmwasm pack must declare disambiguation read");
  assert.equal(cw.disambiguation.tool, "bounty_cosmwasm_fetch_contract");
  assert.match(cw.disambiguation.fail_reason, /CosmWasm/);
  // Rendered brutalist must list these tools via the rendered pack table.
  const brutalistRendered = readFile(".claude/agents/brutalist-verifier.md");
  assert.match(brutalistRendered, /bounty_substrate_fetch_storage/);
  assert.match(brutalistRendered, /bounty_cosmwasm_fetch_contract/);
});

test("balanced-verifier carries Substrate + CosmWasm severity heuristics", () => {
  const balanced = readFile("prompts/roles/balanced-verifier.md");
  assert.match(balanced, /Substrate.*severity heuristics/i, "balanced must include Substrate severity heuristics block");
  assert.match(balanced, /set_code_hash_unauthorized.*HIGH|HIGH.*set_code_hash_unauthorized/i, "balanced must classify set_code_hash_unauthorized as HIGH/CRITICAL");
  assert.match(balanced, /CosmWasm severity heuristics/i, "balanced must include CosmWasm severity heuristics block");
  assert.match(balanced, /migrate_msg_open.*CRITICAL|CRITICAL.*migrate_msg_open/i, "balanced must classify migrate_msg_open as CRITICAL");
  assert.match(balanced, /cw_multi_test_only_passes/i, "balanced must caveat cw-multi-test-only findings");
});

test("rendered final-verifier carries Substrate + CosmWasm runners and block-reference fields via the pack table", () => {
  const final = readFile(".claude/agents/final-verifier.md");
  assert.match(final, /bounty_substrate_run/, "rendered final must mention bounty_substrate_run via the pack table");
  assert.match(final, /bounty_cosmwasm_run/, "rendered final must mention bounty_cosmwasm_run via the pack table");
  // Both packs use fork_block_used for the resolved block reference.
  assert.match(final, /fork_block_used/);
  // Source prompt instructs pack-driven dispatch; the per-chain branches are
  // gone from the source.
  const finalSource = readFile("prompts/roles/final-verifier.md");
  assert.match(finalSource, /finding\.capability_pack/, "final-verifier source must instruct lookup via finding.capability_pack");
});

test("chain-builder enumerates Substrate + CosmWasm patterns and enforces family-cite", () => {
  const prompt = readFile("prompts/roles/chain.md");
  assert.match(prompt, /SC Substrate patterns|chain_family.*substrate/i, "chain.md must enumerate Substrate patterns");
  assert.match(prompt, /SC CosmWasm patterns|chain_family.*cosmwasm/i, "chain.md must enumerate CosmWasm patterns");
  assert.match(prompt, /set_code_hash_unauthorized.*contract_takeover|migrate_msg_open.*contract_takeover/i, "chain.md must list takeover-pattern pivots for the new families");
  assert.match(prompt, /Substrate-family SC pattern MUST cite.*"substrate"/, "chain.md must enforce substrate-family cite");
  assert.match(prompt, /CosmWasm-family SC pattern MUST cite.*"cosmwasm"/, "chain.md must enforce cosmwasm-family cite");
});

test("report-writer renders Substrate + CosmWasm address shape, CWE map, and verified-at lines", () => {
  const prompt = readFile("prompts/roles/reporter.md");
  // Substrate Chain + Address line
  assert.match(prompt, /Substrate.*ss58_address|ss58_address.*network/i, "reporter.md must render Substrate network + ss58_address");
  // CosmWasm Chain + Address line
  assert.match(prompt, /CosmWasm.*contract_address|contract_address.*network/i, "reporter.md must render CosmWasm network + contract_address");
  // Substrate verified-at
  assert.match(prompt, /Substrate.*block <N>.*on network <X>/i, "reporter.md must render 'block N on network X' for Substrate findings");
  // CosmWasm verified-at
  assert.match(prompt, /CosmWasm.*block <N>.*on chain <X>/i, "reporter.md must render 'block N on chain X' for CosmWasm findings");
  // CWE map entries
  assert.match(prompt, /set_code_hash_unauthorized.*CWE-284|CWE-284.*set_code_hash_unauthorized/i, "reporter.md must map set_code_hash_unauthorized to CWE-284");
  assert.match(prompt, /migrate_msg_open.*CWE-284|CWE-284.*migrate_msg_open/i, "reporter.md must map migrate_msg_open to CWE-284");
  assert.match(prompt, /reentrancy_cross_contract.*CWE-841|CWE-841.*reentrancy_cross_contract/i, "reporter.md must map reentrancy_cross_contract to CWE-841");
  assert.match(prompt, /submessage_reply_misuse.*CWE-841|CWE-841.*submessage_reply_misuse/i, "reporter.md must map submessage_reply_misuse to CWE-841");
  // Substrate remediation
  assert.match(prompt, /Substrate.*ink|set_code_hash|CallFlags::default|self\.admin/i, "reporter.md must offer Substrate / ink! remediation snippets");
  // CosmWasm remediation
  assert.match(prompt, /CosmWasm.*Migrate|nonpayable|info\.funds|cw_utils/i, "reporter.md must offer CosmWasm remediation snippets");
  // Gas-render fence covers Substrate + CosmWasm
  assert.match(prompt, /never render a gas line for.*Substrate.*CosmWasm|never render a gas line for.*CosmWasm/i, "reporter.md must restrict gas rendering away from Substrate / CosmWasm");
});

test("bounty_record_finding inputSchema requires sc_evidence sub-fields for SC findings", () => {
  // The schema is the contract verifiers depend on. Missing or optional
  // required sub-fields would force verifiers to free-text-parse the PoC,
  // which is exactly the failure mode the structured field exists to
  // prevent.
  const tool = TOOLS.find((entry) => entry.name === "bounty_record_finding");
  assert.ok(tool, "bounty_record_finding tool not registered");
  const sc = tool.inputSchema.properties.sc_evidence;
  assert.equal(sc.type, "object", "sc_evidence must be an object schema");
  assert.deepEqual(
    [...sc.required].sort(),
    ["chain_id", "contract_address", "harness_path", "match_test"].sort(),
    "sc_evidence required sub-fields drifted from contract",
  );
  // chain_family enumerates evm, svm, aptos, sui, substrate, cosmwasm.
  assert.deepEqual(
    [...sc.properties.chain_family.enum].sort(),
    ["aptos", "cosmwasm", "evm", "substrate", "sui", "svm"],
    "chain_family must enumerate supported families",
  );
  // chain_id is polymorphic (integer for EVM, string cluster for SVM). Validate
  // the schema enumerates both shapes via oneOf.
  assert.ok(
    Array.isArray(sc.properties.chain_id.oneOf) && sc.properties.chain_id.oneOf.length === 2,
    "chain_id must be polymorphic via oneOf",
  );
  assert.equal(sc.properties.chain_id.oneOf[0].type, "integer");
  assert.equal(sc.properties.chain_id.oneOf[1].type, "string");
  // contract_address polymorphism: free string with length cap. Family-specific
  // regex enforcement runs at normalizeScEvidence time, not in JSON schema.
  assert.equal(sc.properties.contract_address.type, "string");
  assert.equal(sc.properties.match_test.type, "string");
});

test("REPORT phase uses compact session summary instead of root reading report markdown", () => {
  const orchestrator = readFile(".claude/skills/bob-hunt/SKILL.md");

  assert.match(orchestrator, /After the report writer finishes[\s\S]*bounty_read_session_summary/);
  assert.match(orchestrator, /result\.data\.summary\.report\.path/);
  assert.match(orchestrator, /Do not read `report\.md` in the root orchestrator/);
});

test("resume instructions continue from MCP summaries and do not reconstruct from markdown", () => {
  const orchestrator = readFile(".claude/skills/bob-hunt/SKILL.md");

  assert.match(orchestrator, /First call `bounty_read_state_summary\(\{ target_domain \}\)`/);
  assert.match(orchestrator, /do not reconstruct resume state from markdown/i);
  assert.match(orchestrator, /handoff markdown/);
});

test("non-hunter agents require compact final markers and forbid raw final payloads", () => {
  const expectations = {
    "chain-builder": "BOB_CHAIN_DONE",
    "brutalist-verifier": "BOB_VERIFY_DONE",
    "balanced-verifier": "BOB_VERIFY_DONE",
    "final-verifier": "BOB_VERIFY_DONE",
    "evidence-agent": "BOB_EVIDENCE_DONE",
    "grader": "BOB_GRADE_DONE",
    "report-writer": "BOB_REPORT_DONE",
  };

  for (const [agent, marker] of Object.entries(expectations)) {
    const document = readFile(`.claude/agents/${agent}.md`);
    assert.match(document, new RegExp(marker), `${agent} missing ${marker}`);
    assert.match(document, /compact summary-only|compact and end/i, `${agent} must require compact final text`);
    assert.match(document, /raw requests[\s\S]*raw responses[\s\S]*(cookies|tokens|authorization headers)/i, `${agent} must forbid raw final payloads`);
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

test("orchestrator documents deep mode persistence, recon mode, and lead debt", () => {
  const orchestrator = readFile(".claude/skills/bob-hunt/SKILL.md");

  assert.match(orchestrator, /argument-hint: .*--deep/);
  assert.match(orchestrator, /`--deep` enables broader script-heavy recon/);
  assert.match(orchestrator, /bounty_init_session\(\{ target_domain, target_url, deep_mode \}\)/);
  assert.match(orchestrator, /persisted `state\.deep_mode` keeps deep behavior/);
  assert.match(orchestrator, /deep_mode false: Agent\(subagent_type: "recon-agent"/);
  assert.match(orchestrator, /deep_mode true: Agent\(subagent_type: "deep-recon-agent"/);
  assert.doesNotMatch(orchestrator, /MODE=\[normal\|deep\]/);
  assert.match(orchestrator, /bounty_promote_surface_leads\(\{ target_domain, limit: 8, min_score: 60 \}\)/);
  assert.match(orchestrator, /bounty_read_surface_leads\(\{ target_domain, limit: 20 \}\)/);
  assert.match(orchestrator, /maximum 8/);
  assert.match(orchestrator, /high-confidence unpromoted leads/);
  assert.match(orchestrator, /surface_leads/);
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
    // The contract is that every bounty_http_scan call from a verifier
    // carries target_domain and the captured auth_profile — the exact
    // wording can vary.
    assert.match(verifierPrompt, /`bounty_http_scan`[^\n]*`target_domain`[^\n]*`auth_profile`/);
    assert.doesNotMatch(verifierPrompt, /cross-domain[\s\S]{0,160}target_domain/i);
  }
});

test("hunter and orchestrator prompts keep the structured handoff contract explicit", () => {
  const hunterPrompt = readFile(".claude/agents/hunter-agent.md");
  const orchestratorPrompt = readFile(".claude/skills/bob-hunt/SKILL.md");

  assert.match(hunterPrompt, /surface_type[\s\S]*bug_class_hints[\s\S]*high_value_flows/);
  assert.match(orchestratorPrompt, /surface_type[\s\S]*bug_class_hints[\s\S]*high_value_flows/);
  assert.match(hunterPrompt, /traffic_summary[\s\S]*audit_summary[\s\S]*circuit_breaker_summary[\s\S]*ranking_summary[\s\S]*intel_hints[\s\S]*static_scan_hints/);
  assert.match(hunterPrompt, /run_context/);
  assert.match(hunterPrompt, /run_context\.context_budget/);
  assert.match(hunterPrompt, /technique_packs\.selected/);
  assert.match(hunterPrompt, /technique_packs\.selected` as the primary technique context/);
  assert.match(hunterPrompt, /top-level `techniques` and `payload_hints` fields are smaller legacy compatibility summaries/);
  assert.match(hunterPrompt, /bounty_read_technique_pack/);
  assert.match(hunterPrompt, /full_pack_read_limit/);
  assert.match(hunterPrompt, /bounty_log_technique_attempt/);
  assert.match(hunterPrompt, /Every call requires a valid `status` and non-empty `evidence`; include `outcome` when the attempt has a concrete result/);
  assert.match(hunterPrompt, /technique-pack-reads\.jsonl/);
  assert.match(hunterPrompt, /never write `technique-attempts\.jsonl` or `technique-pack-reads\.jsonl` through Bash/);
  assert.match(orchestratorPrompt, /bounty_read_hunter_brief\(\{ target_domain:[\s\S]*egress_profile:[\s\S]*block_internal_hosts/);
  assert.match(orchestratorPrompt, /block_internal_hosts: \[block_internal_hosts\]/);
  assert.doesNotMatch(orchestratorPrompt, /block_internal_hosts: false/);
  assert.match(orchestratorPrompt, /Egress profile: \[egress_profile\]\. Block internal hosts: \[block_internal_hosts\]/);
  assert.match(orchestratorPrompt, /Context budget: \[assignment\.context_budget\]/);
  assert.match(orchestratorPrompt, /technique_packs\.selected/);
  assert.match(orchestratorPrompt, /registry warnings, and small legacy technique summaries/);
  assert.match(orchestratorPrompt, /bounty_read_technique_pack[\s\S]*bounty_log_technique_attempt/);
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
  assert.match(hunterPrompt, /bounty_record_surface_leads/);
  assert.match(hunterPrompt, /surface_leads/);
  assert.match(hunterPrompt, /surface-leads\.json/);
  assert.match(hunterPrompt, /bounty_log_coverage/);
  assert.match(hunterPrompt, /never write `coverage\.jsonl` through Bash/);
  assert.match(hunterPrompt, /Never create or backfill[\s\S]*technique-attempts\.jsonl[\s\S]*technique-pack-reads\.jsonl[\s\S]*http-audit\.jsonl[\s\S]*traffic\.jsonl[\s\S]*public-intel\.json[\s\S]*static-artifacts\.jsonl[\s\S]*static-scan-results\.jsonl/);
  assert.match(hunterPrompt, /status` \(`tested`, `blocked`, `promising`, `needs_auth`, or `requeue`\)/);
  assert.match(orchestratorPrompt, /MCP-owned JSON artifacts are authoritative for orchestration\./);
  assert.match(orchestratorPrompt, /must never call `bounty_write_wave_handoff`/);
  assert.match(orchestratorPrompt, /must never synthesize or repair authoritative handoff JSON from markdown or `SESSION_HANDOFF\.md`/);
  assert.match(orchestratorPrompt, /Missing structured handoffs resolve only through `pending` or explicit `force-merge`\./);
  assert.match(orchestratorPrompt, /bounty_log_coverage/);
  assert.match(orchestratorPrompt, /never write `coverage\.jsonl` through Bash/);
  assert.match(orchestratorPrompt, /technique-pack-reads\.jsonl/);
});

test("replay prompts preserve technique-pack priority and MCP-owned artifact prohibitions", () => {
  const replayPrompts = [
    "scripts/replay-prompts/00-baseline.md",
    "scripts/replay-prompts/01-scope-anchor.md",
    "testing/policy-replay/prompts/00-baseline.md",
    "testing/policy-replay/prompts/01-scope-anchor.md",
  ];

  for (const promptPath of replayPrompts) {
    const prompt = readFile(promptPath);
    assert.match(prompt, /technique_packs\.selected/);
    assert.match(prompt, /Prefer `technique_packs\.selected` as the primary technique context/);
    assert.match(prompt, /top-level `techniques` and `payload_hints` fields are smaller legacy compatibility summaries/);
    assert.match(prompt, /Never create or backfill[\s\S]*technique-attempts\.jsonl[\s\S]*technique-pack-reads\.jsonl/);
  }
});

test("context scaling architecture doc is durable and matches enforced budget contract", () => {
  assert.equal(fs.existsSync(path.join(ROOT, "docs/context-scaling-and-platform-adapters.md")), false);
  const doc = readFile("docs/context-scaling-architecture.md");

  assert.match(doc, /^# Context Scaling Architecture/m);
  assert.match(doc, /candidate_pack_limit/);
  assert.match(doc, /full_pack_read_limit/);
  assert.match(doc, /attempt_log_required/);
  assert.match(doc, /technique_packs\.selected` is the canonical web-hunter context/);
  assert.match(doc, /Smart-contract hunters currently set `attempt_log_required: false`/);
  assert.doesNotMatch(doc, /Eric['’]s agent/i);
  assert.doesNotMatch(doc, /rebase/i);
  assert.doesNotMatch(doc, /brief_max_tokens|team_escalation_allowed/);
});

// ----------------------------------------------------------------------
// Merge integration: SC × main mechanisms (chain attempts, evidence packs)
// ----------------------------------------------------------------------

test("bob-hunt routes surfaces after recon and spawns returned hunter agents", () => {
  const orchestratorPrompt = readFile(".claude/skills/bob-hunt/SKILL.md");
  const reconSection = orchestratorPrompt.match(/## PHASE 1: RECON([\s\S]*?)## PHASE 2: AUTH/)[1];

  assert.match(
    reconSection,
    /Agent\(subagent_type: "surface-router-agent", name: "surface-router", prompt: "/,
  );
  assert.match(reconSection, /Domain: \[domain\]\. Session: ~\/bounty-agent-sessions\/\[domain\]\./);
  assert.match(reconSection, /bounty_route_surfaces\(\{ target_domain: '\[domain\]' \}\) and use \.data/);
  assert.match(reconSection, /If routing fails or returns zero surfaces, report the error and stop/);
  assert.match(
    reconSection,
    /only after successful routing call `bounty_transition_phase\(\{ target_domain, to_phase: "AUTH" \}\)`/,
  );
  assert.match(orchestratorPrompt, /assignments\[\]\.hunter_agent/);
  assert.match(orchestratorPrompt, /subagent_type: "\[assignment\.hunter_agent\]"/);
  assert.match(orchestratorPrompt, /Capability pack: \[assignment\.capability_pack\]\. Brief profile: \[assignment\.brief_profile\]/);
  assert.match(orchestratorPrompt, /Context budget: \[assignment\.context_budget\]/);
});

test("post-report evidence hunters are explicit and do not masquerade as wave handoffs", () => {
  const hunterPrompt = readFile(".claude/agents/hunter-agent.md");
  const orchestratorPrompt = readFile(".claude/skills/bob-hunt/SKILL.md");

  assert.match(orchestratorPrompt, /Post-REPORT user intent stays flexible/);
  assert.match(orchestratorPrompt, /transition `REPORT -> EXPLORE`/);
  assert.match(orchestratorPrompt, /post-report evidence mode without transitioning to EXPLORE/);
  assert.match(orchestratorPrompt, /BOB_HUNTER_DONE \{"target_domain":"\[domain\]","mode":"evidence"/);
  assert.match(hunterPrompt, /Post-report evidence mode is different/);
  assert.match(hunterPrompt, /Do not call `bounty_read_hunter_brief`/);
  assert.match(hunterPrompt, /Do not call `bounty_record_finding`, `bounty_write_wave_handoff`/);
  assert.match(hunterPrompt, /"mode":"evidence"/);
});

test("chain.md instructs bounty_write_chain_attempt for every SC pivot with terminal outcomes", () => {
  const prompt = readFile("prompts/roles/chain.md");
  assert.match(prompt, /bounty_write_chain_attempt/, "chain.md must reference bounty_write_chain_attempt");
  assert.match(prompt, /Terminal chain attempts/i, "chain.md must explain terminal-attempt convention");
  for (const outcome of ["confirmed", "denied", "blocked", "inconclusive", "not_applicable"]) {
    assert.match(prompt, new RegExp(`\`${outcome}\``), `chain.md must enumerate ${outcome} outcome`);
  }
  assert.match(prompt, /CHAIN -> VERIFY/, "chain.md must reference the gate it satisfies");
  assert.match(prompt, /No credible chains[\s\S]*not_applicable/, "chain.md must instruct writing not_applicable when no chain exists, to clear the gate");
  assert.match(prompt, /SC pivots specifically.*proof_reference.*MUST cite/, "chain.md must require sc_evidence-anchored proof_reference for SC pivots");
});

test("evidence-agent dispatches by capability_pack with pack-driven runner workflow", () => {
  // evidence-agent looks up finding.capability_pack in the pack manifest
  // and uses the pack's evidence.runner. The agent's allowlist still
  // carries every runner so polymorphic dispatch works in a single run.
  const document = readFile(".claude/agents/evidence-agent.md");
  const frontmatter = parseFrontmatter(document, "evidence-agent.md");
  const tools = frontmatter.tools.split(",").map((tool) => tool.trim());
  for (const required of [
    "mcp__bountyagent__bounty_foundry_run",
    "mcp__bountyagent__bounty_anchor_run",
    "mcp__bountyagent__bounty_aptos_run",
    "mcp__bountyagent__bounty_sui_run",
    "mcp__bountyagent__bounty_substrate_run",
    "mcp__bountyagent__bounty_cosmwasm_run",
  ]) {
    assert.ok(tools.includes(required), `evidence-agent must include ${required}`);
  }
  assert.ok(tools.includes("mcp__bountyagent__bounty_http_scan"), "evidence-agent must keep bounty_http_scan for web findings");

  // Source body instructs pack-driven dispatch and embeds the placeholder.
  const source = readFile("prompts/roles/evidence.md");
  assert.match(source, /Dispatch by `finding\.capability_pack`/i, "evidence source must document capability_pack dispatch");
  assert.match(source, /\{\{CAPABILITY_PACK_VERIFIER_TABLE\}\}/, "evidence source must embed the capability pack table placeholder");
  // The capability pack registry is the runtime source of truth.
  const { CAPABILITY_PACKS } = require("../mcp/lib/capability-packs.js");
  const familyRunners = {
    smart_contract_evm: "bounty_foundry_run",
    smart_contract_svm: "bounty_anchor_run",
    smart_contract_aptos: "bounty_aptos_run",
    smart_contract_sui: "bounty_sui_run",
    smart_contract_substrate: "bounty_substrate_run",
    smart_contract_cosmwasm: "bounty_cosmwasm_run",
  };
  for (const [packId, runner] of Object.entries(familyRunners)) {
    assert.equal(CAPABILITY_PACKS[packId].evidence.runner, runner, `pack ${packId} must route to ${runner}`);
  }
  // Rendered evidence agent contains every runner via the pack table.
  for (const runner of Object.values(familyRunners)) {
    assert.match(document, new RegExp(runner), `evidence-agent rendered prompt must list ${runner} via the pack table`);
  }
  // Tooling-blocker fallback survives the prompt rewrite.
  assert.match(source, /tooling-blocker reason[^\n]*evidence pack still gets written/i, "evidence source must describe tooling-blocker fallback so gate clears");
});

test("hunter-completion.js exports evidence-mode helpers (post-merge refactor)", () => {
  const completion = require("../mcp/lib/hunter-completion.js");
  for (const fn of ["isEvidenceMarker", "evidenceMarkerValidationError", "evaluateEvidenceCompletion", "evidenceTelemetryInput", "EVIDENCE_MODE", "markerMode"]) {
    assert.ok(completion[fn] !== undefined, `hunter-completion must export ${fn}`);
  }
  assert.equal(completion.EVIDENCE_MODE, "evidence");
  // isEvidenceMarker on a wave-mode marker returns false; on a mode='evidence' marker returns true.
  assert.equal(completion.isEvidenceMarker({ wave: "w1", agent: "a1", target_domain: "x", surface_id: "s" }), false);
  assert.equal(completion.isEvidenceMarker({ target_domain: "x", surface_id: "F-1", mode: "evidence" }), true);
});

test("SC tools register evidence role bundle so evidence-agent can re-run family runners", () => {
  const expected = [
    "bounty_foundry_run",
    "bounty_halmos_run",
    "bounty_anchor_run",
    "bounty_aptos_run",
    "bounty_sui_run",
    "bounty_substrate_run",
    "bounty_cosmwasm_run",
    "bounty_evm_call",
    "bounty_evm_storage_read",
    "bounty_evm_fetch_source",
    "bounty_evm_role_table",
    "bounty_svm_fetch_account",
    "bounty_svm_fetch_program",
    "bounty_aptos_fetch_resource",
    "bounty_aptos_fetch_module",
    "bounty_sui_fetch_object",
    "bounty_sui_fetch_package",
    "bounty_substrate_fetch_storage",
    "bounty_substrate_fetch_runtime",
    "bounty_cosmwasm_fetch_contract",
    "bounty_cosmwasm_smart_query",
  ];
  for (const name of expected) {
    const meta = TOOL_MANIFEST[name];
    assert.ok(meta, `${name} is in TOOL_MANIFEST`);
    assert.ok(meta.role_bundles.includes("evidence"), `${name} must include evidence role bundle`);
  }
});

test("brutalist-verifier wires the @brutalist/mcp roast layer with graceful fallback (no debate)", () => {
  for (const filePath of [
    "prompts/roles/brutalist-verifier.md",
    ".claude/agents/brutalist-verifier.md",
    "adapters/codex/skills/bob-hunt/SKILL.md",
  ]) {
    const body = readFile(filePath);
    assert.match(body, /mcp__brutalist__roast\b/, `${filePath} must reference mcp__brutalist__roast`);
    assert.match(body, /brutalist roast unavailable/i, `${filePath} must include the graceful-fallback wording`);
    // The debate orchestrator is too time-expensive for a per-finding loop.
    // The prompt should explicitly forbid it; the only allowed mention is the
    // negative instruction (do NOT call mcp__brutalist__roast_cli_debate).
    const debateMentions = body.match(/mcp__brutalist__roast_cli_debate/g) || [];
    assert.ok(debateMentions.length <= 1, `${filePath} mentions roast_cli_debate ${debateMentions.length} times; expected at most 1 (the explicit prohibition)`);
    if (debateMentions.length === 1) {
      const debateContext = body.slice(Math.max(0, body.indexOf("roast_cli_debate") - 80), body.indexOf("roast_cli_debate") + 80);
      assert.match(debateContext, /do NOT call|too time-expensive/i, `${filePath} mentions roast_cli_debate without the explicit prohibition context`);
    }
  }
});

test("Claude brutalist-verifier agent registers @brutalist/mcp tools but only requires bountyagent", () => {
  const body = readFile(".claude/agents/brutalist-verifier.md");
  // Inspect the tools: frontmatter line specifically — the prompt body will mention
  // roast_cli_debate once in the explicit prohibition, but the tools allowlist must not.
  const toolsLine = body.match(/^tools: (.+)$/m);
  assert.ok(toolsLine, "brutalist-verifier frontmatter missing tools: line");
  const toolsList = toolsLine[1];
  for (const tool of ["mcp__brutalist__roast", "mcp__brutalist__brutalist_discover", "mcp__brutalist__cli_agent_roster"]) {
    assert.ok(toolsList.includes(tool), `brutalist-verifier tools: must include ${tool}`);
  }
  assert.ok(!toolsList.includes("mcp__brutalist__roast_cli_debate"), "brutalist-verifier tools: must NOT include roast_cli_debate");
  // mcpServers should list both bountyagent and brutalist; requiredMcpServers should be bountyagent-only.
  const mcpServersBlock = body.match(/mcpServers:\n((?:  - .+\n)+)/);
  assert.ok(mcpServersBlock, "brutalist-verifier frontmatter missing mcpServers list");
  assert.match(mcpServersBlock[1], /  - bountyagent\n/);
  assert.match(mcpServersBlock[1], /  - brutalist\n/);
  const requiredBlock = body.match(/requiredMcpServers:\n((?:  - .+\n)+)/);
  assert.ok(requiredBlock, "brutalist-verifier frontmatter missing requiredMcpServers list");
  assert.match(requiredBlock[1], /  - bountyagent\n/);
  assert.doesNotMatch(requiredBlock[1], /  - brutalist\n/, "brutalist must remain optional (graceful fallback)");
});

test("Codex bundled .mcp.json registers both bountyagent and the optional brutalist server", () => {
  const mcp = JSON.parse(readFile("adapters/codex/hacker-bob/.mcp.json"));
  assert.ok(mcp.mcpServers && mcp.mcpServers.bountyagent, "Codex .mcp.json must keep bountyagent");
  assert.ok(mcp.mcpServers.brutalist, "Codex .mcp.json must register the brutalist server");
  assert.equal(mcp.mcpServers.brutalist.command, "npx");
  assert.deepEqual(mcp.mcpServers.brutalist.args, ["-y", "@brutalist/mcp@latest"]);
});
