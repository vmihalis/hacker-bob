const test = require("node:test");
const assert = require("node:assert/strict");
const { execFile, execFileSync, spawnSync } = require("node:child_process");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const { promisify } = require("node:util");

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "bin", "hacker-bob.js");
const PACKAGE_VERSION = require("../package.json").version;
const execFileAsync = promisify(execFile);

test("CLI help explains per-project installs and global CLI behavior", () => {
  const output = execFileSync(process.execPath, [CLI, "--help"], {
    cwd: ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  for (const command of ["install", "update", "check-update", "doctor", "uninstall"]) {
    assert.match(output, new RegExp(`hacker-bob ${command}`));
  }
  assert.match(output, /Bob auto-selects/);
  assert.match(output, /default host adapter is Claude/);
  assert.match(output, /\$CLAUDE_PROJECT_DIR/);
  assert.match(output, /\$CODEX_HOME/);
  assert.match(output, /--adapter claude\|codex\|generic-mcp\|kimi\|all/);
  assert.match(output, /Global npm install only adds this CLI to PATH/);
  assert.match(output, /Uninstall defaults to dry-run/);
});

test("CLI installs into a workspace", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-install-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    execFileSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });

    assert.equal(fs.readFileSync(path.join(workspace, ".claude", "bob", "VERSION"), "utf8").trim(), PACKAGE_VERSION);
    assert.equal(fs.readFileSync(path.join(workspace, ".hacker-bob", "VERSION"), "utf8").trim(), PACKAGE_VERSION);
    const installMeta = JSON.parse(fs.readFileSync(path.join(workspace, ".hacker-bob", "install.json"), "utf8"));
    assert.deepEqual(installMeta.installed_adapters, ["claude"]);
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-update.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-egress.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-export.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-evaluate-runner", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bob-hunt", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "update.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-check-update.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-egress.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-export.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "bob", "egress-profiles.json")));

    // .mcp.json must register both hacker-bob (required) and brutalist (optional roast layer).
    const mcp = JSON.parse(fs.readFileSync(path.join(workspace, ".mcp.json"), "utf8"));
    assert.ok(mcp.mcpServers["hacker-bob"]);
    assert.ok(!mcp.mcpServers.bountyagent, "v2.0+ installs must not emit the legacy bountyagent server key");
    assert.ok(mcp.mcpServers.brutalist, "Claude install must register the optional brutalist MCP server");
    assert.equal(mcp.mcpServers.brutalist.command, "npx");
    assert.deepEqual(mcp.mcpServers.brutalist.args, ["-y", "@brutalist/mcp@latest"]);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("CLI installs and doctors the Codex adapter without Claude files", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-codex-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    execFileSync(process.execPath, [CLI, "install", "--adapter", "codex", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });

    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".codex-plugin", "plugin.json")));
    // Plugin .mcp.json must register both hacker-bob and the optional brutalist server.
    // The bundled source file ships both; this assertion catches mergeConfig regressions
    // that would silently overwrite the bundled file with a hacker-bob-only template
    // during install.
    const codexMcp = JSON.parse(fs.readFileSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".mcp.json"), "utf8"));
    assert.ok(codexMcp.mcpServers["hacker-bob"], "Codex plugin .mcp.json must keep hacker-bob");
    assert.ok(codexMcp.mcpServers.brutalist, "Codex plugin .mcp.json must register the optional brutalist MCP server post-install");
    assert.deepEqual(codexMcp.mcpServers.brutalist.args, ["-y", "@brutalist/mcp@latest"]);
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-status", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-debug", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-update", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-export", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-egress", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "skills", "evaluate", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "skills", "hacker-bob-evaluate", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-evaluate.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-status.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-debug.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-update.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-export.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-egress.md")));
    const marketplace = JSON.parse(fs.readFileSync(path.join(workspace, ".agents", "plugins", "marketplace.json"), "utf8"));
    const marketplaceEntry = marketplace.plugins.find((plugin) => plugin.name === "hacker-bob");
    assert.equal(marketplaceEntry.source.path, "./.codex/plugins/hacker-bob");
    assert.equal(marketplaceEntry.policy.installation, "INSTALLED_BY_DEFAULT");
    assert.ok(fs.existsSync(path.join(
      tempHome,
      ".codex",
      "plugins",
      "cache",
      "hacker-bob-local",
      "hacker-bob",
      PACKAGE_VERSION,
      "commands",
      "bob-evaluate.md",
    )));
    assert.ok(!fs.existsSync(path.join(
      tempHome,
      ".codex",
      "plugins",
      "cache",
      "hacker-bob-local",
      "hacker-bob",
      PACKAGE_VERSION,
      "skills",
    )));
    const codexConfig = fs.readFileSync(path.join(tempHome, ".codex", "config.toml"), "utf8");
    assert.match(codexConfig, /\[plugins\."hacker-bob@hacker-bob-local"\]/);
    assert.match(codexConfig, /\[marketplaces\.hacker-bob-local\]/);
    assert.ok(codexConfig.includes(`source = "${workspace.replace(/\\/g, "\\\\").replace(/"/g, "\\\"")}"`));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude")));
    const installMeta = JSON.parse(fs.readFileSync(path.join(workspace, ".hacker-bob", "install.json"), "utf8"));
    assert.deepEqual(installMeta.installed_adapters, ["codex"]);

    const output = execFileSync(process.execPath, [CLI, "doctor", workspace, "--adapter", "codex", "--json"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const result = JSON.parse(output);
    assert.equal(result.ok, true);
    assert.deepEqual(result.adapters, ["codex"]);
    assert.ok(result.checks.some((check) => check.id === "codex_plugin_manifest" && check.status === "ok"));
    assert.ok(result.checks.some((check) => check.id === "codex_global_skills" && check.status === "ok"));
    assert.ok(result.checks.some((check) => check.id === "codex_plugin_skills_clean" && check.status === "ok"));
    assert.ok(result.checks.some((check) => check.id === "codex_plugin_commands" && check.status === "ok"));
    assert.ok(result.checks.some((check) => check.id === "codex_plugin_marketplace" && check.status === "ok"));
    assert.ok(!result.checks.some((check) => check.id.startsWith("claude_")));

    const egressOutput = execFileSync(process.execPath, [
      path.join(workspace, "mcp", "lib", "egress-cli.js"),
      workspace,
      "add",
      "operator",
      "--proxy-env",
      "BOB_EGRESS_OPERATOR_PROXY",
      "--region",
      "EU",
      "--json",
    ], {
      cwd: workspace,
      env: { ...process.env, HOME: tempHome },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    assert.equal(JSON.parse(egressOutput).profile.name, "operator");
    const egressList = JSON.parse(execFileSync(process.execPath, [
      path.join(workspace, "mcp", "lib", "egress-cli.js"),
      workspace,
      "list",
      "--json",
    ], {
      cwd: workspace,
      env: { ...process.env, HOME: tempHome },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }));
    assert.ok(egressList.profiles.some((profile) => profile.name === "operator" && profile.proxy_configured));
    assert.doesNotMatch(JSON.stringify(egressList), /BOB_EGRESS_OPERATOR_PROXY|proxy\.example|secret/);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("CLI installs and doctors the Kimi adapter without Claude or Codex files", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-kimi-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    execFileSync(process.execPath, [CLI, "install", "--adapter", "kimi", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });

    for (const skill of ["bob-evaluate", "bob-status", "bob-debug", "bob-update", "bob-export", "bob-egress"]) {
      assert.ok(fs.existsSync(path.join(workspace, ".kimi", "skills", skill, "SKILL.md")), `${skill} missing`);
    }
    assert.ok(fs.existsSync(path.join(workspace, ".kimi", "bob", "VERSION")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex")));

    // .kimi/mcp.json must register the canonical v2.0 `hacker-bob` server key,
    // never the legacy `bountyagent` key (CHANGELOG v2.0 + TROUBLESHOOTING.md).
    const mcp = JSON.parse(fs.readFileSync(path.join(workspace, ".kimi", "mcp.json"), "utf8"));
    assert.ok(mcp.mcpServers["hacker-bob"], "Kimi install must register the hacker-bob server key");
    assert.ok(!mcp.mcpServers.bountyagent, "v2.0+ Kimi installs must not emit the legacy bountyagent server key");
    assert.equal(mcp.mcpServers["hacker-bob"].command, "node");
    assert.ok(mcp.mcpServers["hacker-bob"].args.some((arg) => arg.endsWith(path.join("mcp", "server.js"))));

    const installMeta = JSON.parse(fs.readFileSync(path.join(workspace, ".hacker-bob", "install.json"), "utf8"));
    assert.deepEqual(installMeta.installed_adapters, ["kimi"]);

    const output = execFileSync(process.execPath, [CLI, "doctor", workspace, "--adapter", "kimi", "--json"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const result = JSON.parse(output);
    assert.equal(result.ok, true);
    assert.deepEqual(result.adapters, ["kimi"]);
    assert.ok(result.checks.some((check) => check.id === "kimi_skills" && check.status === "ok"));
    assert.ok(result.checks.some((check) => check.id === "kimi_mcp_server_config" && check.status === "ok"));
    assert.ok(!result.checks.some((check) => check.id.startsWith("claude_") || check.id.startsWith("codex_")));

    const uninstall = JSON.parse(execFileSync(process.execPath, [CLI, "uninstall", workspace, "--adapter", "kimi", "--yes", "--json"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }));
    assert.equal(uninstall.dry_run, false);
    assert.deepEqual(uninstall.adapters, ["kimi"]);
    assert.equal(uninstall.remove_shared, true);
    assert.ok(!fs.existsSync(path.join(workspace, ".kimi", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".kimi", "mcp.json")));
    assert.ok(!fs.existsSync(path.join(workspace, "mcp", "server.js")));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("CLI auto-selects kimi when project has .kimi/ and no --adapter flag", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-detect-kimi-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(path.join(workspace, ".kimi"), { recursive: true });
  const cleanEnv = { ...process.env, HOME: tempHome };
  delete cleanEnv.CLAUDE_PROJECT_DIR;
  delete cleanEnv.CODEX_HOME;
  delete cleanEnv.KIMI_PROJECT_DIR;

  try {
    const result = spawnSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: cleanEnv,
      encoding: "utf8",
    });
    assert.equal(result.status, 0, `install failed: ${result.stderr}`);
    assert.match(result.stderr, /auto-selected adapter kimi/);
    assert.match(result.stderr, /reason: project_dot_kimi/);
    const installMeta = JSON.parse(fs.readFileSync(path.join(workspace, ".hacker-bob", "install.json"), "utf8"));
    assert.deepEqual(installMeta.installed_adapters, ["kimi"]);
    assert.ok(fs.existsSync(path.join(workspace, ".kimi", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "settings.json")));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("CLI reinstall with no --adapter preserves a kimi-only install (does not flip to claude)", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-kimi-reinstall-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    execFileSync(process.execPath, [CLI, "install", "--adapter", "kimi", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    const initialMeta = JSON.parse(fs.readFileSync(path.join(workspace, ".hacker-bob", "install.json"), "utf8"));
    assert.deepEqual(initialMeta.installed_adapters, ["kimi"]);

    const cleanEnv = { ...process.env, HOME: tempHome };
    delete cleanEnv.CLAUDE_PROJECT_DIR;
    delete cleanEnv.CODEX_HOME;
    delete cleanEnv.KIMI_PROJECT_DIR;
    const reinstall = spawnSync(process.execPath, [CLI, "update", workspace], {
      cwd: ROOT,
      env: cleanEnv,
      encoding: "utf8",
    });
    assert.equal(reinstall.status, 0, `update failed: ${reinstall.stderr}`);
    assert.match(reinstall.stderr, /reason: reinstall_metadata/);
    const finalMeta = JSON.parse(fs.readFileSync(path.join(workspace, ".hacker-bob", "install.json"), "utf8"));
    assert.deepEqual(finalMeta.installed_adapters, ["kimi"]);
    assert.ok(fs.existsSync(path.join(workspace, ".kimi", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bob-evaluate-runner", "SKILL.md")));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("CLI generic MCP adapter install and uninstall preserve unrelated MCP config", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-generic-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    fs.writeFileSync(path.join(workspace, ".mcp.json"), `${JSON.stringify({
      mcpServers: {
        existing: { command: "node", args: ["existing.js"] },
      },
    }, null, 2)}\n`);

    execFileSync(process.execPath, [CLI, "install", workspace, "--adapter=generic-mcp"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    assert.ok(fs.existsSync(path.join(workspace, ".hacker-bob", "generic-mcp", "hacker-bob.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex")));

    // .mcp.json must keep the operator's existing entry, register hacker-bob,
    // and additionally register the optional brutalist server.
    const installedMcp = JSON.parse(fs.readFileSync(path.join(workspace, ".mcp.json"), "utf8"));
    assert.ok(installedMcp.mcpServers.existing, "generic-mcp install must preserve unrelated MCP servers");
    assert.ok(installedMcp.mcpServers["hacker-bob"]);
    assert.ok(!installedMcp.mcpServers.bountyagent);
    assert.ok(installedMcp.mcpServers.brutalist, "generic-mcp install must register the optional brutalist MCP server");
    assert.deepEqual(installedMcp.mcpServers.brutalist.args, ["-y", "@brutalist/mcp@latest"]);

    const output = execFileSync(process.execPath, [CLI, "uninstall", workspace, "--adapter", "generic-mcp", "--yes", "--json"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const result = JSON.parse(output);
    assert.equal(result.dry_run, false);
    assert.deepEqual(result.adapters, ["generic-mcp"]);
    assert.equal(result.remove_shared, true);
    assert.ok(!fs.existsSync(path.join(workspace, ".hacker-bob", "generic-mcp", "hacker-bob.md")));
    assert.ok(!fs.existsSync(path.join(workspace, "mcp", "server.js")));

    const mcp = JSON.parse(fs.readFileSync(path.join(workspace, ".mcp.json"), "utf8"));
    assert.ok(mcp.mcpServers.existing);
    assert.ok(!mcp.mcpServers["hacker-bob"]);
    assert.ok(!mcp.mcpServers.bountyagent);
    assert.ok(!mcp.mcpServers.brutalist, "uninstall must also remove the Bob-managed brutalist server");
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("CLI uninstall of one adapter preserves remaining adapters and shared runtime", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-all-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    execFileSync(process.execPath, [CLI, "install", workspace, "--adapter", "all"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });

    const output = execFileSync(process.execPath, [CLI, "uninstall", workspace, "--adapter", "codex", "--yes", "--json"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const result = JSON.parse(output);
    assert.equal(result.dry_run, false);
    assert.deepEqual(result.remaining_adapters, ["claude", "generic-mcp", "kimi"]);
    assert.equal(result.remove_shared, false);
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".mcp.json")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-evaluate.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-egress.md")));
    assert.ok(!fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-export", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-egress", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".agents", "plugins", "marketplace.json")));
    assert.ok(!fs.existsSync(path.join(tempHome, ".codex", "plugins", "cache", "hacker-bob-local", "hacker-bob")));
    assert.ok(!fs.existsSync(path.join(tempHome, ".codex", "config.toml")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-update.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-evaluate-runner", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".hacker-bob", "generic-mcp", "hacker-bob.md")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "server.js")));

    const installMeta = JSON.parse(fs.readFileSync(path.join(workspace, ".hacker-bob", "install.json"), "utf8"));
    assert.deepEqual(installMeta.installed_adapters, ["claude", "generic-mcp", "kimi"]);

    const claudeOutput = execFileSync(process.execPath, [CLI, "uninstall", workspace, "--adapter", "claude", "--yes", "--json"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const claudeResult = JSON.parse(claudeOutput);
    assert.deepEqual(claudeResult.remaining_adapters, ["generic-mcp", "kimi"]);
    assert.equal(claudeResult.remove_shared, false);
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob-update.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob-export.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bob-evaluate-runner", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".hacker-bob", "generic-mcp", "hacker-bob.md")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "server.js")));
    const mcp = JSON.parse(fs.readFileSync(path.join(workspace, ".mcp.json"), "utf8"));
    assert.ok(mcp.mcpServers["hacker-bob"]);
    const finalMeta = JSON.parse(fs.readFileSync(path.join(workspace, ".hacker-bob", "install.json"), "utf8"));
    assert.deepEqual(finalMeta.installed_adapters, ["generic-mcp", "kimi"]);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("CLI auto-selects claude (default fallback) on a fresh install with no --adapter and logs the reason", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-detect-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });
  const cleanEnv = { ...process.env, HOME: tempHome };
  delete cleanEnv.CLAUDE_PROJECT_DIR;
  delete cleanEnv.CODEX_HOME;
  // Strip PATH so the CLI-on-PATH detection layer sees neither claude nor codex.
  cleanEnv.PATH = "/usr/bin:/bin";

  try {
    const result = spawnSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: cleanEnv,
      encoding: "utf8",
    });
    assert.equal(result.status, 0, `install failed: ${result.stderr}`);
    assert.match(result.stderr, /auto-selected adapter claude/, `stderr should mention auto-select; got: ${result.stderr}`);
    assert.match(result.stderr, /reason: default_fallback/);
    const installMeta = JSON.parse(fs.readFileSync(path.join(workspace, ".hacker-bob", "install.json"), "utf8"));
    assert.deepEqual(installMeta.installed_adapters, ["claude"]);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("CLI generic-mcp install writes mcpServers['hacker-bob'] into .mcp.json", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-generic-presence-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    execFileSync(process.execPath, [CLI, "install", workspace, "--adapter", "generic-mcp"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    const mcp = JSON.parse(fs.readFileSync(path.join(workspace, ".mcp.json"), "utf8"));
    assert.ok(mcp.mcpServers && mcp.mcpServers["hacker-bob"], "mcpServers['hacker-bob'] should be present after generic-mcp install");
    assert.ok(!mcp.mcpServers.bountyagent, "v2.0+ installs must not emit the legacy bountyagent server key");
    assert.equal(mcp.mcpServers["hacker-bob"].command, "node");
    assert.ok(
      Array.isArray(mcp.mcpServers["hacker-bob"].args)
        && mcp.mcpServers["hacker-bob"].args.some((arg) => arg.endsWith(path.join("mcp", "server.js"))),
      `mcpServers['hacker-bob'].args should reference mcp/server.js; got: ${JSON.stringify(mcp.mcpServers["hacker-bob"].args)}`,
    );
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("CLI no-flag uninstall on multi-adapter install removes everything that was installed", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-uninstall-multi-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    execFileSync(process.execPath, [CLI, "install", workspace, "--adapter", "all"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    const installed = JSON.parse(fs.readFileSync(path.join(workspace, ".hacker-bob", "install.json"), "utf8"));
    assert.deepEqual(installed.installed_adapters, ["claude", "codex", "generic-mcp", "kimi"]);

    const cleanEnv = { ...process.env, HOME: tempHome };
    delete cleanEnv.CLAUDE_PROJECT_DIR;
    delete cleanEnv.CODEX_HOME;
    const result = spawnSync(process.execPath, [CLI, "uninstall", workspace, "--yes", "--json"], {
      cwd: ROOT,
      env: cleanEnv,
      encoding: "utf8",
    });
    assert.equal(result.status, 0, `uninstall failed: ${result.stderr}`);
    assert.match(result.stderr, /reason: installed_adapters/);
    const parsed = JSON.parse(result.stdout);
    assert.deepEqual(parsed.adapters.sort(), ["claude", "codex", "generic-mcp", "kimi"]);
    assert.deepEqual(parsed.remaining_adapters, []);
    assert.equal(parsed.remove_shared, true);
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bob-evaluate-runner", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".hacker-bob", "generic-mcp", "hacker-bob.md")));
    assert.ok(!fs.existsSync(path.join(workspace, "mcp", "server.js")));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("CLI no-flag doctor on multi-adapter install runs checks for every installed adapter", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-doctor-multi-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    execFileSync(process.execPath, [CLI, "install", workspace, "--adapter", "all"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });

    const cleanEnv = { ...process.env, HOME: tempHome };
    delete cleanEnv.CLAUDE_PROJECT_DIR;
    delete cleanEnv.CODEX_HOME;
    const result = spawnSync(process.execPath, [CLI, "doctor", workspace, "--json"], {
      cwd: ROOT,
      env: cleanEnv,
      encoding: "utf8",
    });
    assert.equal(result.status, 0, `doctor failed: ${result.stderr}`);
    assert.match(result.stderr, /reason: installed_adapters/);
    const parsed = JSON.parse(result.stdout);
    assert.deepEqual(parsed.adapters.sort(), ["claude", "codex", "generic-mcp", "kimi"]);
    const checkIds = new Set(parsed.checks.map((check) => check.id));
    // Each adapter should contribute at least one check id with its own prefix.
    assert.ok([...checkIds].some((id) => id.startsWith("claude_")), "expected at least one claude_* check");
    assert.ok([...checkIds].some((id) => id.startsWith("codex_")), "expected at least one codex_* check");
    assert.ok([...checkIds].some((id) => id.startsWith("generic_mcp_") || id.includes("generic")), "expected at least one generic-mcp check");
    assert.ok([...checkIds].some((id) => id.startsWith("kimi_")), "expected at least one kimi_* check");
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("CLI no-flag update on a previously-installed codex project keeps codex (does not flip to claude)", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-update-preserve-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    execFileSync(process.execPath, [CLI, "install", workspace, "--adapter", "codex"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });

    const cleanEnv = { ...process.env, HOME: tempHome };
    delete cleanEnv.CLAUDE_PROJECT_DIR;
    delete cleanEnv.CODEX_HOME;
    const result = spawnSync(process.execPath, [CLI, "update", workspace], {
      cwd: ROOT,
      env: cleanEnv,
      encoding: "utf8",
    });
    assert.equal(result.status, 0, `update failed: ${result.stderr}`);
    assert.match(result.stderr, /reason: reinstall_metadata/);
    const meta = JSON.parse(fs.readFileSync(path.join(workspace, ".hacker-bob", "install.json"), "utf8"));
    assert.deepEqual(meta.installed_adapters, ["codex"]);
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bob-evaluate-runner", "SKILL.md")));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("CLI auto-selects codex when project has .codex/plugins/ and no --adapter flag", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-detect-codex-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(path.join(workspace, ".codex", "plugins"), { recursive: true });
  const cleanEnv = { ...process.env, HOME: tempHome };
  delete cleanEnv.CLAUDE_PROJECT_DIR;
  delete cleanEnv.CODEX_HOME;

  try {
    execFileSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: cleanEnv,
      stdio: "pipe",
    });
    const installMeta = JSON.parse(fs.readFileSync(path.join(workspace, ".hacker-bob", "install.json"), "utf8"));
    assert.deepEqual(installMeta.installed_adapters, ["codex"]);
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".codex-plugin", "plugin.json")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "settings.json")));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("CLI reinstall with no --adapter preserves previously-installed adapter mix", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-detect-reinstall-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    execFileSync(process.execPath, [CLI, "install", workspace, "--adapter", "codex"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    const initialMeta = JSON.parse(fs.readFileSync(path.join(workspace, ".hacker-bob", "install.json"), "utf8"));
    assert.deepEqual(initialMeta.installed_adapters, ["codex"]);

    // Reinstall without --adapter; the installer must keep codex (and not silently flip to claude).
    const cleanEnv = { ...process.env, HOME: tempHome };
    delete cleanEnv.CLAUDE_PROJECT_DIR;
    delete cleanEnv.CODEX_HOME;
    const reinstall = spawnSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: cleanEnv,
      encoding: "utf8",
    });
    assert.equal(reinstall.status, 0, `reinstall failed: ${reinstall.stderr}`);
    assert.match(reinstall.stderr, /reason: reinstall_metadata/);
    const finalMeta = JSON.parse(fs.readFileSync(path.join(workspace, ".hacker-bob", "install.json"), "utf8"));
    assert.deepEqual(finalMeta.installed_adapters, ["codex"]);
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bob-evaluate-runner", "SKILL.md")));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("CLI check-update emits JSON with mocked registry and changelog URLs", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-update-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(path.join(workspace, ".claude", "bob"), { recursive: true });
  fs.writeFileSync(path.join(workspace, ".claude", "bob", "VERSION"), "1.0.0\n");

  const registryPath = path.join(tempRoot, "registry.json");
  const changelogPath = path.join(tempRoot, "CHANGELOG.md");
  fs.writeFileSync(registryPath, JSON.stringify({ "dist-tags": { latest: "1.1.0" } }));
  fs.writeFileSync(changelogPath, "## [1.1.0] - 2026-04-26\n\n- update\n");

  try {
    const output = execFileSync(process.execPath, [CLI, "check-update", workspace, "--json"], {
      cwd: ROOT,
      env: {
        ...process.env,
        HOME: tempHome,
        HACKER_BOB_REGISTRY_METADATA_URL: pathToFileURL(registryPath).href,
        HACKER_BOB_CHANGELOG_URL: pathToFileURL(changelogPath).href,
      },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const result = JSON.parse(output);
    assert.equal(result.installed_version, "1.0.0");
    assert.equal(result.latest_version, "1.1.0");
    assert.equal(result.update_available, true);
    assert.match(result.changelog, /update/);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("CLI doctor passes on a freshly installed workspace", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-doctor-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    execFileSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });

    const output = execFileSync(process.execPath, [CLI, "doctor", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    assert.match(output, /No required problems found/);
    assert.match(output, /OK: mcp_server_loadable/);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("CLI doctor --json returns stable machine-readable checks", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-doctor-json-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    execFileSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });

    const output = execFileSync(process.execPath, [CLI, "doctor", workspace, "--json"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const result = JSON.parse(output);
    assert.equal(result.ok, true);
    assert.equal(result.target, workspace);
    assert.equal(
      result.checks.find((check) => check.id === "claude_mcp_dependency_proxy_agent").status,
      "ok",
    );
    for (const id of [
      "node_version",
      "target_directory",
      "install_version",
      "install_metadata",
      "install_metadata_json",
      "claude_installed_version",
      "claude_install_metadata",
      "claude_commands",
      "claude_hook_files",
      "claude_mcp_server_config",
      "claude_settings_hooks",
      "claude_settings_statusline",
      "claude_egress_profiles_example",
      "claude_egress_profiles_config",
      "claude_mcp_dependency_proxy_agent",
      "claude_policy_replay_harness",
      "mcp_server_loadable",
      "resource_knowledge",
      "resource_bypass_tables",
    ]) {
      assert.ok(result.checks.some((check) => check.id === id), `${id} missing`);
    }
    assert.ok(result.checks.every((check) => ["ok", "warn"].includes(check.status)));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("CLI doctor exits 1 when required install state is missing", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-doctor-fail-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    execFileSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    fs.rmSync(path.join(workspace, ".claude", "bob", "VERSION"), { force: true });

    assert.throws(() => {
      execFileSync(process.execPath, [CLI, "doctor", workspace, "--json"], {
        cwd: ROOT,
        env: { ...process.env, HOME: tempHome },
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      });
    }, (error) => {
      assert.equal(error.status, 1);
      const result = JSON.parse(error.stdout.toString("utf8"));
      assert.equal(result.ok, false);
      assert.ok(result.checks.some((check) => check.id === "claude_installed_version" && check.status === "error"));
      return true;
    });
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("CLI uninstall dry-run changes nothing", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-uninstall-dry-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    execFileSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    const versionBefore = fs.readFileSync(path.join(workspace, ".claude", "bob", "VERSION"), "utf8");
    const mcpBefore = fs.readFileSync(path.join(workspace, ".mcp.json"), "utf8");
    const settingsBefore = fs.readFileSync(path.join(workspace, ".claude", "settings.json"), "utf8");

    const output = execFileSync(process.execPath, [CLI, "uninstall", workspace, "--dry-run", "--json"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const result = JSON.parse(output);
    assert.equal(result.dry_run, true);
    assert.ok(result.actions.length > 0);
    assert.equal(fs.readFileSync(path.join(workspace, ".claude", "bob", "VERSION"), "utf8"), versionBefore);
    assert.equal(fs.readFileSync(path.join(workspace, ".mcp.json"), "utf8"), mcpBefore);
    assert.equal(fs.readFileSync(path.join(workspace, ".claude", "settings.json"), "utf8"), settingsBefore);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("CLI uninstall --yes removes Bob-managed files and preserves unrelated config", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-uninstall-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(path.join(workspace, ".claude"), { recursive: true });

  try {
    fs.writeFileSync(path.join(workspace, ".mcp.json"), `${JSON.stringify({
      mcpServers: {
        existing: { command: "node", args: ["existing.js"] },
      },
    }, null, 2)}\n`);
    fs.writeFileSync(path.join(workspace, ".claude", "settings.json"), `${JSON.stringify({
      permissions: {
        allow: ["custom-tool", "mcp__hacker-bob__custom_user_tool"],
      },
      hooks: {
        PreToolUse: [{
          matcher: "Bash",
          hooks: [{ type: "command", command: "echo existing", timeout: 1 }],
        }],
      },
      customSetting: true,
    }, null, 2)}\n`);

    execFileSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    fs.writeFileSync(path.join(workspace, ".claude", "bob", "egress-profiles.json"), `${JSON.stringify({
      version: 1,
      profiles: [
        { name: "default", proxy_url: null, region: null, description: "Direct", enabled: true },
        { name: "operator", proxy_url: "${BOB_EGRESS_OPERATOR_PROXY}", region: "EU", description: "Operator-owned", enabled: true },
      ],
    }, null, 2)}\n`);
    fs.writeFileSync(path.join(tempHome, "hacker-bob-sessions", "keep.txt"), "keep\n");

    const output = execFileSync(process.execPath, [CLI, "uninstall", workspace, "--yes", "--json"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const result = JSON.parse(output);
    assert.equal(result.dry_run, false);
    assert.ok(result.actions.some((action) => action.path === path.join(".claude", "bob", "VERSION")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob-update.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob-export.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-check-update.js")));
    assert.ok(!fs.existsSync(path.join(workspace, ".hacker-bob", "knowledge", "evaluator-techniques.json")));
    assert.ok(!fs.existsSync(path.join(workspace, ".hacker-bob", "bypass-tables", "rest-api.txt")));
    assert.ok(!fs.existsSync(path.join(workspace, "mcp", "server.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "bob", "egress-profiles.json")));
    assert.ok(result.skipped.some((item) => item.path === path.join(".claude", "bob", "egress-profiles.json")));

    const mcp = JSON.parse(fs.readFileSync(path.join(workspace, ".mcp.json"), "utf8"));
    assert.ok(mcp.mcpServers.existing);
    assert.ok(!mcp.mcpServers["hacker-bob"]);
    assert.ok(!mcp.mcpServers.bountyagent);

    const settings = JSON.parse(fs.readFileSync(path.join(workspace, ".claude", "settings.json"), "utf8"));
    assert.equal(settings.customSetting, true);
    assert.ok(settings.permissions.allow.includes("custom-tool"));
    assert.ok(settings.permissions.allow.includes("mcp__hacker-bob__custom_user_tool"));
    assert.ok(!settings.permissions.allow.includes("mcp__hacker-bob__bob_http_scan"));
    assert.ok(!settings.permissions.allow.includes("mcp__bountyagent__bob_http_scan"));
    assert.ok(!settings.statusLine);
    assert.ok(settings.hooks.PreToolUse.some((entry) => (
      entry.matcher === "Bash" &&
      entry.hooks.some((hook) => hook.command === "echo existing")
    )));
    assert.ok(!settings.hooks.PreToolUse.some((entry) => (
      entry.hooks &&
      entry.hooks.some((hook) => /scope-guard\.sh|session-write-guard\.sh/.test(hook.command))
    )));
    assert.ok(fs.existsSync(path.join(tempHome, "hacker-bob-sessions", "keep.txt")));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("installed bob-egress helper manages profiles and redacts credentials", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-egress-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    execFileSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    const helper = path.join(workspace, ".claude", "hooks", "bob-egress.js");
    const run = (args, env = {}) => execFileSync(process.execPath, [helper, workspace, ...args], {
      cwd: workspace,
      env: { ...process.env, HOME: tempHome, ...env },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });

    let listed = JSON.parse(run(["list", "--json"]));
    assert.equal(listed.profiles.length, 1);
    assert.equal(listed.profiles[0].name, "default");

    run(["add", "operator", "--proxy-env", "BOB_EGRESS_OPERATOR_PROXY", "--region", "EU", "--description", "Operator profile", "--json"]);
    listed = JSON.parse(run(["list", "--json"]));
    const operator = listed.profiles.find((profile) => profile.name === "operator");
    assert.equal(operator.enabled, true);
    assert.equal(operator.proxy_configured, true);
    assert.doesNotMatch(JSON.stringify(listed), /BOB_EGRESS_OPERATOR_PROXY|secret|proxy\.example/);

    run(["disable", "operator", "--json"]);
    listed = JSON.parse(run(["list", "--json"]));
    assert.equal(listed.profiles.find((profile) => profile.name === "operator").enabled, false);

    run(["enable", "operator", "--json"]);
    listed = JSON.parse(run(["list", "--json"]));
    assert.equal(listed.profiles.find((profile) => profile.name === "operator").enabled, true);

    run(["remove", "operator", "--yes", "--json"]);
    listed = JSON.parse(run(["list", "--json"]));
    assert.equal(listed.profiles.some((profile) => profile.name === "operator"), false);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("installed bob-egress test handles default egress against a safe local endpoint", async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-egress-test-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cli-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });
  const localServer = http.createServer((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ip: "127.0.0.1" }));
  });

  try {
    await new Promise((resolve) => localServer.listen(0, "127.0.0.1", resolve));
    const port = localServer.address().port;
    execFileSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    const { stdout } = await execFileAsync(process.execPath, [
      path.join(workspace, ".claude", "hooks", "bob-egress.js"),
      workspace,
      "test",
      "default",
      "--url",
      `http://127.0.0.1:${port}/ip`,
      "--json",
    ], {
      cwd: workspace,
      env: { ...process.env, HOME: tempHome },
      encoding: "utf8",
    });
    const result = JSON.parse(stdout);
    assert.equal(result.profile.name, "default");
    assert.equal(result.profile.proxy_configured, false);
    assert.equal(result.observed.status, 200);
    assert.equal(result.observed.ip, "127.0.0.1");
  } finally {
    await new Promise((resolve) => localServer.close(resolve));
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});
