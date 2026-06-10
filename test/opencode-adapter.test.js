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
    assert.deepEqual(cfg.mcp.brutalist.command, ["npx", "-y", "@brutalist/mcp@latest"]);

    // All six slash commands are rendered.
    for (const commandId of opencode.commandIds()) {
      const file = path.join(workspace, ".opencode", "commands", opencode.commandSpec(commandId).file);
      assert.ok(fs.existsSync(file), `expected command file ${file}`);
    }
    // All 18 per-role subagents are installed under .opencode/agents/.
    assert.equal(opencode.agentTargetFiles().length, 18);
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

    // Utility commands call the shared mcp/lib helpers directly (no hooks dir).
    const egressCmd = fs.readFileSync(path.join(workspace, ".opencode", "commands", "bob-egress.md"), "utf8");
    assert.match(egressCmd, /mcp\/lib\/egress-cli\.js/);
    const updateCmd = fs.readFileSync(path.join(workspace, ".opencode", "commands", "bob-update.md"), "utf8");
    assert.match(updateCmd, /mcp\/lib\/update-check\.js/);
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
