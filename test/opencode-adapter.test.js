"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const opencode = require("../adapters/opencode/index.js");

const ROOT = path.join(__dirname, "..");

function makeWorkspace() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "bob-opencode-adapter-"));
}

function installInto(workspace) {
  return opencode.install({
    sourceRoot: ROOT,
    targetAbs: workspace,
    serverPath: path.join(workspace, "mcp", "server.js"),
    manifest: { version: "9.9.9", name: "hacker-bob" },
    installedAt: "2026-01-01T00:00:00.000Z",
    installerSource: "test",
    commitSha: "deadbeef",
    packageName: "hacker-bob",
  });
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

test("opencode install writes the OpenCode-shaped MCP entry and command/subagent surface", () => {
  const workspace = makeWorkspace();
  try {
    installInto(workspace);

    const cfg = readJson(path.join(workspace, "opencode.json"));
    assert.equal(cfg.$schema, "https://opencode.ai/config.json");
    // OpenCode local stdio shape — NOT the mcpServers { command, args } shape.
    assert.deepEqual(cfg.mcp["hacker-bob"], {
      type: "local",
      command: ["node", path.join(workspace, "mcp", "server.js")],
      enabled: true,
    });
    assert.equal(cfg.mcp.brutalist.type, "local");
    // Pinned to the same reviewed version the Claude/Codex/Kimi/generic adapters
    // share via BRUTALIST_MCP_SERVER — never the floating @latest tag.
    assert.deepEqual(cfg.mcp.brutalist.command, ["npx", "-y", "@brutalist/mcp@1.14.7"]);

    // All six slash commands are rendered.
    for (const commandId of opencode.commandIds()) {
      const file = path.join(workspace, ".opencode", "commands", opencode.commandSpec(commandId).file);
      assert.ok(fs.existsSync(file), `expected command file ${file}`);
    }
    // All 20 per-role subagents are installed under .opencode/agents/ (18 worker
    // roles + the read-only bob-status / bob-debug command-bound subagents).
    assert.equal(opencode.agentTargetFiles().length, 20);
    for (const relative of opencode.agentTargetFiles()) {
      assert.ok(fs.existsSync(path.join(workspace, relative)), `expected agent file ${relative}`);
    }
    assert.ok(fs.existsSync(path.join(workspace, ".opencode", "agents", "bob-orchestrator.md")));

    const meta = readJson(path.join(workspace, ".opencode", "bob", "install.json"));
    assert.equal(meta.bob_version, "9.9.9");
    assert.equal(meta.install_target, workspace);
    assert.equal(meta.commit_sha, "deadbeef");
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test("opencode renders the task-tool spawn seam (not @mention/Agent) and routes /bob-evaluate to bob-orchestrator", () => {
  const workspace = makeWorkspace();
  try {
    installInto(workspace);

    const orchestrator = fs.readFileSync(path.join(workspace, ".opencode", "agents", "bob-orchestrator.md"), "utf8");
    // The orchestrator dispatches named subagents through the task tool —
    // OpenCode's @mention path is manual operator invocation only and a
    // literal @bob-* assistant message would never spawn a sub-session.
    assert.match(orchestrator, /task\(subagent_type: "bob-brutalist-verifier"/);
    assert.match(orchestrator, /task\(subagent_type: "bob-grader"/);
    assert.match(orchestrator, /task\(subagent_type: "bob-\[assignment\.evaluator_agent\]"/);
    // Neither the Claude Agent(subagent_type:) form nor a concrete @bob-<role>
    // mention dispatch may leak into the rendered spawn seam. The only allowed
    // @bob reference is the generic `@bob-<role>` manual-path note.
    assert.doesNotMatch(orchestrator, /Agent\(subagent_type:/);
    assert.doesNotMatch(orchestrator, /@bob-[a-z]/);
    // No leftover spawn placeholders.
    assert.doesNotMatch(orchestrator, /\{\{[A-Z0-9_]+\}\}/);

    // Orchestrator frontmatter: mode: primary, task enabled, BYOK (no model line).
    const ofm = orchestrator.match(/^---\n([\s\S]*?)\n---\n/)[1];
    assert.match(ofm, /^mode: primary$/m);
    assert.match(ofm, /^  task: true$/m);
    assert.doesNotMatch(ofm, /^model:/m);

    // A subagent carries mode: subagent and no model.
    const verifier = fs.readFileSync(path.join(workspace, ".opencode", "agents", "bob-brutalist-verifier.md"), "utf8");
    const vfm = verifier.match(/^---\n([\s\S]*?)\n---\n/)[1];
    assert.match(vfm, /^mode: subagent$/m);
    assert.doesNotMatch(vfm, /^model:/m);

    // /bob-evaluate routes to the bob-orchestrator primary agent.
    const evalCmd = fs.readFileSync(path.join(workspace, ".opencode", "commands", "bob-evaluate.md"), "utf8");
    assert.match(evalCmd, /^agent: bob-orchestrator$/m);

    // Utility commands call the shared mcp/lib helpers directly (no hooks dir),
    // and bind to the built-in bash-capable `build` primary so their node/npx
    // snippets run even when the active agent is bash-restricted (e.g.
    // bob-orchestrator after /bob-evaluate). `build` is a primary, not a `bob-*`
    // Task subagent, so it stays out of the orchestrator's Task allow-list.
    const egressCmd = fs.readFileSync(path.join(workspace, ".opencode", "commands", "bob-egress.md"), "utf8");
    assert.match(egressCmd, /mcp\/lib\/egress-cli\.js/);
    assert.match(egressCmd, /^agent: build$/m);
    const updateCmd = fs.readFileSync(path.join(workspace, ".opencode", "commands", "bob-update.md"), "utf8");
    assert.match(updateCmd, /mcp\/lib\/update-check\.js/);
    assert.match(updateCmd, /^agent: build$/m);
    const exportCmd = fs.readFileSync(path.join(workspace, ".opencode", "commands", "bob-export.md"), "utf8");
    assert.match(exportCmd, /^agent: build$/m);
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test("opencode subagent frontmatter gates MCP tools to each role's registry bundle", () => {
  const workspace = makeWorkspace();
  try {
    installInto(workspace);

    const frontmatterOf = (agentFile) => {
      const document = fs.readFileSync(path.join(workspace, ".opencode", "agents", agentFile), "utf8");
      return document.match(/^---\n([\s\S]*?)\n---\n/)[1];
    };

    // Every agent denies the whole hacker-bob server, then re-allows exactly
    // its role bundle (specific keys beat the glob — OpenCode's Wildcard.all
    // gives the longest matching pattern precedence).
    const grader = frontmatterOf("bob-grader.md");
    assert.match(grader, /^  "hacker-bob_\*": false$/m);
    assert.match(grader, /^  hacker-bob_bob_write_grade_verdict: true$/m);
    // Out-of-role mutators must NOT be re-allowed for the grader: lifecycle
    // advancement and report finalization stay orchestrator/reporter-only.
    assert.doesNotMatch(grader, /hacker-bob_bob_advance_session/);
    assert.doesNotMatch(grader, /hacker-bob_bob_finalize_report/);
    assert.doesNotMatch(grader, /hacker-bob_bob_write_wave_handoff/);

    // The external @brutalist/mcp server is open only for the brutalist verifier.
    assert.match(frontmatterOf("bob-brutalist-verifier.md"), /^  "brutalist_\*": true$/m);
    assert.match(grader, /^  "brutalist_\*": false$/m);
    assert.match(frontmatterOf("bob-orchestrator.md"), /^  "brutalist_\*": false$/m);

    // The orchestrator never writes evaluator handoffs.
    const orchestrator = frontmatterOf("bob-orchestrator.md");
    assert.match(orchestrator, /^  "hacker-bob_\*": false$/m);
    assert.doesNotMatch(orchestrator, /hacker-bob_bob_write_wave_handoff/);
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test("opencode frontmatter denies tools by default and locks down orchestrator + status/debug", () => {
  const workspace = makeWorkspace();
  try {
    installInto(workspace);
    const frontmatterOf = (agentFile) =>
      fs.readFileSync(path.join(workspace, ".opencode", "agents", agentFile), "utf8")
        .match(/^---\n([\s\S]*?)\n---\n/)[1];

    // Deny-all baseline: OpenCode's tools map is an override map (unlisted tools
    // stay enabled), so every role must emit `"*": false` to actually close
    // webfetch/websearch/list/etc. unless explicitly re-allowed.
    for (const file of ["bob-orchestrator.md", "bob-grader.md", "bob-evaluator-agent.md", "bob-status.md"]) {
      assert.match(frontmatterOf(file), /^  "\*": false$/m, `${file} missing deny-all baseline`);
    }

    // The root orchestrator is the lifecycle authority: NO bash, and Task
    // dispatch allow-listed to EXACTLY Bob's generated subagents by name —
    // deny-all FIRST, then one exact `bob-<role>` allow per mode:subagent. A
    // `bob-*` glob is forbidden: OpenCode never filters its merged global+
    // project+generated agent registry by provenance, so a glob would expose any
    // operator/global agent whose name merely starts with `bob-`.
    const orchestrator = frontmatterOf("bob-orchestrator.md");
    assert.match(orchestrator, /^  bash: false$/m);
    assert.match(orchestrator, /^permission:\n  task:\n    "\*": deny$/m);
    assert.doesNotMatch(orchestrator, /"bob-\*": allow/, "no bob-* glob — exact names only");
    assert.match(orchestrator, /^    "bob-grader": allow$/m);
    assert.match(orchestrator, /^    "bob-evaluator-agent": allow$/m);
    assert.match(orchestrator, /^    "bob-brutalist-verifier": allow$/m);
    // The primary orchestrator is never a Task target and must not allow itself.
    assert.doesNotMatch(orchestrator, /^    "bob-orchestrator": allow$/m);

    // status/debug are read-only subagents: no write/edit/task, no mutating Bob
    // tools, and bash scoped deny-by-default via permission.bash.
    for (const file of ["bob-status.md", "bob-debug.md"]) {
      const fm = frontmatterOf(file);
      assert.match(fm, /^mode: subagent$/m, `${file} must be a subagent`);
      assert.doesNotMatch(fm, /^  (write|edit|task): true$/m, `${file} must not enable write/edit/task`);
      assert.doesNotMatch(fm, /hacker-bob_bob_advance_session/, `${file} must not allow lifecycle mutators`);
      assert.doesNotMatch(
        fm,
        /hacker-bob_bob_(write|compose|finalize|amend|record|apply|advance|start|merge)_/,
        `${file} must not allow any Bob write/lifecycle tool`,
      );
      assert.match(fm, /^permission:\n  bash:\n    "\*": deny$/m, `${file} must scope bash deny-by-default`);
    }

    // /bob-status's bash allow-list is pinned to the exact passive update-cache
    // command, not a broad `node *` that would permit arbitrary `node -e ...`
    // (file writes / network) from an agent that reads target-influenced data.
    const status = frontmatterOf("bob-status.md");
    assert.doesNotMatch(status, /"node \*": allow/, "status must not allow broad node *");
    assert.match(
      status,
      /^    "node -e \\"const update=require\('\.\/mcp\/lib\/update-check\.js'\); console\.log\(JSON\.stringify\(update\.readUpdateCache\(process\.cwd\(\)\) \|\| null, null, 2\)\);\\"": allow$/m,
      "status must pin the exact update-cache command",
    );

    // The /bob-status and /bob-debug commands route to those read-only agents
    // (commands cannot self-restrict tools, so the agent binding is the gate).
    assert.match(
      fs.readFileSync(path.join(workspace, ".opencode", "commands", "bob-status.md"), "utf8"),
      /^agent: bob-status$/m,
    );
    assert.match(
      fs.readFileSync(path.join(workspace, ".opencode", "commands", "bob-debug.md"), "utf8"),
      /^agent: bob-debug$/m,
    );

    // Agent-suite roles re-allow grep/glob under the deny-all; read-only roles
    // and the verifiers do not.
    const evaluator = frontmatterOf("bob-evaluator-agent.md");
    assert.match(evaluator, /^  grep: true$/m);
    assert.match(evaluator, /^  glob: true$/m);
    for (const file of ["bob-grader.md", "bob-brutalist-verifier.md", "bob-orchestrator.md"]) {
      assert.doesNotMatch(frontmatterOf(file), /^  (grep|glob): true$/m, `${file} must not re-allow grep/glob`);
    }
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test("opencode install preserves operator-configured opencode.json keys and servers", () => {
  const workspace = makeWorkspace();
  try {
    fs.writeFileSync(path.join(workspace, "opencode.json"), `${JSON.stringify({
      $schema: "https://opencode.ai/config.json",
      theme: "tokyonight",
      model: "anthropic/claude-opus-4-8",
      mcp: {
        "my-own-server": { type: "local", command: ["node", "myserver.js"], enabled: true },
      },
    }, null, 2)}\n`, "utf8");

    installInto(workspace);

    const cfg = readJson(path.join(workspace, "opencode.json"));
    assert.equal(cfg.theme, "tokyonight");
    assert.equal(cfg.model, "anthropic/claude-opus-4-8");
    assert.deepEqual(cfg.mcp["my-own-server"].command, ["node", "myserver.js"]);
    assert.ok(cfg.mcp["hacker-bob"], "bob server entry should be merged in");
    assert.ok(cfg.mcp.brutalist, "brutalist server entry should be merged in");
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test("opencode install never overwrites an operator-owned brutalist MCP server", () => {
  const workspace = makeWorkspace();
  try {
    const operatorBrutalist = { type: "local", command: ["node", "my-own-brutalist.js"], enabled: true };
    fs.writeFileSync(path.join(workspace, "opencode.json"), `${JSON.stringify({
      $schema: "https://opencode.ai/config.json",
      mcp: { brutalist: operatorBrutalist },
    }, null, 2)}\n`, "utf8");

    installInto(workspace);

    const cfg = readJson(path.join(workspace, "opencode.json"));
    assert.deepEqual(cfg.mcp.brutalist, operatorBrutalist, "operator brutalist entry must be preserved");
    assert.ok(cfg.mcp["hacker-bob"], "bob server entry should still be merged in");

    // Uninstall must also leave the foreign brutalist entry alone.
    opencode.uninstall({ targetAbs: workspace, dryRun: false });
    const after = readJson(path.join(workspace, "opencode.json"));
    assert.deepEqual(after.mcp.brutalist, operatorBrutalist, "operator brutalist entry must survive uninstall");
    assert.ok(!after.mcp["hacker-bob"], "bob server entry should be removed");
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test("opencode install refreshes a stale Bob-managed brutalist pin and preserves the operator's enabled toggle", () => {
  const workspace = makeWorkspace();
  try {
    // A prior Bob install wrote an OLDER @brutalist/mcp pin; the operator then
    // disabled it. A reinstall must refresh the command to the current reviewed
    // pin (so a security bump takes effect) without re-enabling a server the
    // operator turned off.
    fs.writeFileSync(path.join(workspace, "opencode.json"), `${JSON.stringify({
      $schema: "https://opencode.ai/config.json",
      mcp: { brutalist: { type: "local", command: ["npx", "-y", "@brutalist/mcp@1.0.0"], enabled: false } },
    }, null, 2)}\n`, "utf8");

    installInto(workspace);

    const cfg = readJson(path.join(workspace, "opencode.json"));
    assert.deepEqual(cfg.mcp.brutalist.command, opencode.BRUTALIST_COMMAND, "stale Bob pin must be refreshed to the current reviewed command");
    assert.equal(cfg.mcp.brutalist.enabled, false, "the operator's disabled toggle must be preserved");
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test("opencode doctor passes on a fresh install", () => {
  const workspace = makeWorkspace();
  try {
    fs.mkdirSync(path.join(workspace, "mcp"), { recursive: true });
    fs.writeFileSync(path.join(workspace, "mcp", "server.js"), "module.exports = {};\n", "utf8");
    installInto(workspace);

    const report = opencode.doctor({ targetAbs: workspace });
    assert.equal(report.adapter, "opencode");
    assert.equal(report.ok, true, `doctor errors: ${JSON.stringify(report.checks.filter((c) => c.status === "error"))}`);
    const ids = new Set(report.checks.map((c) => c.id));
    assert.ok(ids.has("opencode_config"));
    assert.ok(ids.has("opencode_commands"));
    assert.ok(ids.has("opencode_agents"));
    assert.ok(ids.has("opencode_install_metadata"));
    assert.equal(report.checks.find((c) => c.id === "opencode_auth").status, "info");
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test("opencode uninstall strips only Bob-managed entries and keeps operator config", () => {
  const workspace = makeWorkspace();
  try {
    fs.writeFileSync(path.join(workspace, "opencode.json"), `${JSON.stringify({
      $schema: "https://opencode.ai/config.json",
      theme: "tokyonight",
      mcp: {
        "my-own-server": { type: "local", command: ["node", "myserver.js"], enabled: true },
      },
    }, null, 2)}\n`, "utf8");
    installInto(workspace);

    const result = opencode.uninstall({ targetAbs: workspace, dryRun: false });
    assert.equal(result.ok, true);

    const cfg = readJson(path.join(workspace, "opencode.json"));
    assert.equal(cfg.theme, "tokyonight");
    assert.deepEqual(cfg.mcp["my-own-server"].command, ["node", "myserver.js"]);
    assert.ok(!cfg.mcp["hacker-bob"], "bob server entry should be removed");
    assert.ok(!cfg.mcp.brutalist, "brutalist server entry should be removed");

    // All Bob-managed files removed.
    assert.ok(!fs.existsSync(path.join(workspace, ".opencode", "commands", "bob-evaluate.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".opencode", "bob", "install.json")));
    assert.ok(!fs.existsSync(path.join(workspace, ".opencode", "agents", "bob-orchestrator.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".opencode", "agents")), "the agents dir is swept when empty");
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test("opencode uninstall removes a Bob-only opencode.json entirely", () => {
  const workspace = makeWorkspace();
  try {
    installInto(workspace);
    assert.ok(fs.existsSync(path.join(workspace, "opencode.json")));

    opencode.uninstall({ targetAbs: workspace, dryRun: false });
    assert.ok(!fs.existsSync(path.join(workspace, "opencode.json")), "Bob-only opencode.json should be removed");
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test("opencode uninstall refuses to rewrite a symlinked opencode.json", () => {
  const workspace = makeWorkspace();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "bob-opencode-outside-"));
  try {
    // A config symlinked to a file outside the install target must never be
    // followed: rewriting through it would modify an arbitrary user-owned file.
    const realConfig = path.join(outside, "user-config.json");
    fs.writeFileSync(realConfig, `${JSON.stringify({
      $schema: "https://opencode.ai/config.json",
      theme: "tokyonight",
      mcp: {
        "hacker-bob": { type: "local", command: ["node", path.join(workspace, "mcp", "server.js")], enabled: true },
      },
    }, null, 2)}\n`, "utf8");
    const before = fs.readFileSync(realConfig, "utf8");
    fs.symlinkSync(realConfig, path.join(workspace, "opencode.json"));

    const result = opencode.uninstall({ targetAbs: workspace, dryRun: false });
    assert.ok(
      result.skipped.some((s) => s.path === "opencode.json" && /symlink/.test(s.reason)),
      `expected a symlink skip entry, got ${JSON.stringify(result.skipped)}`,
    );
    assert.equal(fs.readFileSync(realConfig, "utf8"), before, "symlink target must not be rewritten");
    assert.ok(fs.existsSync(realConfig), "symlink target must not be removed");
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

test("opencode uninstall refuses to remove Bob files through a symlinked .opencode/agents parent", () => {
  const workspace = makeWorkspace();
  const shared = fs.mkdtempSync(path.join(os.tmpdir(), "bob-opencode-shared-agents-"));
  try {
    installInto(workspace);
    // Operator aliased .opencode/agents at a SHARED agents dir (e.g.
    // ~/.config/opencode/agents) that holds a same-named operator file. Replacing
    // the in-target dir with a symlink to it simulates that aliasing. Uninstall
    // must not traverse the symlinked parent and delete Bob-named files in the
    // link target — that target is outside the install scope.
    const realAgents = path.join(workspace, ".opencode", "agents");
    const sharedOrchestrator = path.join(shared, "bob-orchestrator.md");
    fs.writeFileSync(sharedOrchestrator, "shared agent owned by the operator\n", "utf8");
    fs.rmSync(realAgents, { recursive: true, force: true });
    fs.symlinkSync(shared, realAgents);

    const result = opencode.uninstall({ targetAbs: workspace, dryRun: false });
    assert.equal(result.ok, true);
    // The symlinked parent (and the leaf files reached through it) are skipped.
    assert.ok(
      result.skipped.some((s) => /symlink/.test(s.reason) && /agents/.test(s.path)),
      `expected a symlinked-parent skip entry, got ${JSON.stringify(result.skipped)}`,
    );
    assert.ok(fs.existsSync(sharedOrchestrator), "shared symlink-target file must survive uninstall");
    assert.equal(
      fs.readFileSync(sharedOrchestrator, "utf8"),
      "shared agent owned by the operator\n",
      "shared symlink-target file must not be rewritten",
    );
    // The symlink itself must be left in place (never rmdir'd through).
    assert.ok(fs.existsSync(realAgents), "the .opencode/agents symlink must be left in place");
    assert.ok(fs.lstatSync(realAgents).isSymbolicLink(), "the parent must remain a symlink, not be replaced");
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
    fs.rmSync(shared, { recursive: true, force: true });
  }
});

test("opencode uninstall preserves a non-Bob-managed hacker-bob entry", () => {
  const workspace = makeWorkspace();
  try {
    // Operator hand-rolled a hacker-bob entry that does not match Bob's expected
    // shape (different server path). Uninstall must not touch it.
    fs.writeFileSync(path.join(workspace, "opencode.json"), `${JSON.stringify({
      $schema: "https://opencode.ai/config.json",
      mcp: {
        "hacker-bob": { type: "local", command: ["node", "/somewhere/else/server.js"], enabled: true },
      },
    }, null, 2)}\n`, "utf8");

    const result = opencode.uninstall({ targetAbs: workspace, dryRun: false });
    const cfg = readJson(path.join(workspace, "opencode.json"));
    assert.deepEqual(cfg.mcp["hacker-bob"].command, ["node", "/somewhere/else/server.js"]);
    assert.ok(result.skipped.some((s) => s.path === "opencode.json"));
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test("opencode uninstall removes a Bob-managed brutalist even when the hacker-bob entry was repointed", () => {
  const workspace = makeWorkspace();
  try {
    // Operator repointed hacker-bob at a dev checkout (so it is NOT Bob-managed)
    // but kept Bob's brutalist entry from a prior install. Uninstall must
    // preserve the custom hacker-bob (record the skip) yet still strip the
    // Bob-managed brutalist — leaving it would keep an external npx-spawned MCP
    // server wired after Bob is gone.
    fs.writeFileSync(path.join(workspace, "opencode.json"), `${JSON.stringify({
      $schema: "https://opencode.ai/config.json",
      mcp: {
        "hacker-bob": { type: "local", command: ["node", "/somewhere/else/server.js"], enabled: true },
        brutalist: { type: "local", command: opencode.BRUTALIST_COMMAND, enabled: true },
      },
    }, null, 2)}\n`, "utf8");

    const result = opencode.uninstall({ targetAbs: workspace, dryRun: false });
    const cfg = readJson(path.join(workspace, "opencode.json"));
    assert.deepEqual(cfg.mcp["hacker-bob"].command, ["node", "/somewhere/else/server.js"], "custom hacker-bob must be preserved");
    assert.ok(result.skipped.some((s) => s.path === "opencode.json"), "custom hacker-bob skip must be recorded");
    assert.ok(!cfg.mcp.brutalist, "Bob-managed brutalist must be removed even alongside a custom hacker-bob");
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test("opencode uninstall also strips a stale-pinned Bob-managed brutalist", () => {
  const workspace = makeWorkspace();
  try {
    // A brutalist entry Bob wrote under an EARLIER pin is still Bob-managed and
    // must be removed on uninstall (version-agnostic recognizer), not mistaken
    // for an operator-owned server.
    installInto(workspace);
    const cfgPath = path.join(workspace, "opencode.json");
    const cfg = readJson(cfgPath);
    cfg.mcp.brutalist.command = ["npx", "-y", "@brutalist/mcp@1.0.0"];
    fs.writeFileSync(cfgPath, `${JSON.stringify(cfg, null, 2)}\n`, "utf8");

    opencode.uninstall({ targetAbs: workspace, dryRun: false });
    assert.ok(!fs.existsSync(cfgPath), "Bob-only config with a stale brutalist pin should be fully removed");
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test("opencode frontmatter emits the hacker-bob_* deny BEFORE the per-tool allows (load-bearing for last-match-wins)", () => {
  const workspace = makeWorkspace();
  try {
    installInto(workspace);
    // OpenCode resolves per-agent tool permissions last-matching-rule-wins, so
    // the wildcard deny MUST precede the specific allows for the allow-list to
    // take effect. The other tests assert presence/absence of keys but not this
    // ordering — the actual invariant the whole MCP gating depends on.
    const fm = fs.readFileSync(path.join(workspace, ".opencode", "agents", "bob-grader.md"), "utf8")
      .match(/^---\n([\s\S]*?)\n---\n/)[1];
    const denyIdx = fm.indexOf('"hacker-bob_*": false');
    const firstAllowIdx = fm.search(/^  hacker-bob_\w+: true$/m);
    assert.ok(denyIdx >= 0, "expected the hacker-bob_* wildcard deny");
    assert.ok(firstAllowIdx >= 0, "expected at least one per-tool allow");
    assert.ok(denyIdx < firstAllowIdx, "wildcard deny must precede the specific allows (OpenCode is last-match-wins)");
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});
