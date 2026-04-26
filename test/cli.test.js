const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "bin", "hacker-bob.js");
const PACKAGE_VERSION = require("../package.json").version;

test("CLI help explains per-project installs and global CLI behavior", () => {
  const output = execFileSync(process.execPath, [CLI, "--help"], {
    cwd: ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  for (const command of ["install", "update", "check-update", "doctor", "uninstall"]) {
    assert.match(output, new RegExp(`hacker-bob ${command}`));
  }
  assert.match(output, /default host adapter is Claude/);
  assert.match(output, /--adapter claude\|codex\|generic-mcp\|all/);
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
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-hunt", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "update.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-check-update.js")));
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
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "skills", "hunt", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "skills", "hacker-bob-hunt", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "hunt.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "status.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "debug.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "update.md")));
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
      "hunt.md",
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
    assert.ok(result.checks.some((check) => check.id === "codex_plugin_commands" && check.status === "ok"));
    assert.ok(result.checks.some((check) => check.id === "codex_plugin_marketplace" && check.status === "ok"));
    assert.ok(!result.checks.some((check) => check.id.startsWith("claude_")));
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
    assert.ok(!mcp.mcpServers.bountyagent);
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
    assert.deepEqual(result.remaining_adapters, ["claude", "generic-mcp"]);
    assert.equal(result.remove_shared, false);
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".mcp.json")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "hunt.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".agents", "plugins", "marketplace.json")));
    assert.ok(!fs.existsSync(path.join(tempHome, ".codex", "plugins", "cache", "hacker-bob-local", "hacker-bob")));
    assert.ok(!fs.existsSync(path.join(tempHome, ".codex", "config.toml")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-update.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-hunt", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".hacker-bob", "generic-mcp", "hacker-bob.md")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "server.js")));

    const installMeta = JSON.parse(fs.readFileSync(path.join(workspace, ".hacker-bob", "install.json"), "utf8"));
    assert.deepEqual(installMeta.installed_adapters, ["claude", "generic-mcp"]);

    const claudeOutput = execFileSync(process.execPath, [CLI, "uninstall", workspace, "--adapter", "claude", "--yes", "--json"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const claudeResult = JSON.parse(claudeOutput);
    assert.deepEqual(claudeResult.remaining_adapters, ["generic-mcp"]);
    assert.equal(claudeResult.remove_shared, false);
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob-update.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bob-hunt", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".hacker-bob", "generic-mcp", "hacker-bob.md")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "server.js")));
    const mcp = JSON.parse(fs.readFileSync(path.join(workspace, ".mcp.json"), "utf8"));
    assert.ok(mcp.mcpServers.bountyagent);
    const finalMeta = JSON.parse(fs.readFileSync(path.join(workspace, ".hacker-bob", "install.json"), "utf8"));
    assert.deepEqual(finalMeta.installed_adapters, ["generic-mcp"]);
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
        allow: ["custom-tool", "mcp__bountyagent__custom_user_tool"],
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
    fs.writeFileSync(path.join(tempHome, "bounty-agent-sessions", "keep.txt"), "keep\n");

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
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-check-update.js")));
    assert.ok(!fs.existsSync(path.join(workspace, ".hacker-bob", "knowledge", "hunter-techniques.json")));
    assert.ok(!fs.existsSync(path.join(workspace, ".hacker-bob", "bypass-tables", "rest-api.txt")));
    assert.ok(!fs.existsSync(path.join(workspace, "mcp", "server.js")));

    const mcp = JSON.parse(fs.readFileSync(path.join(workspace, ".mcp.json"), "utf8"));
    assert.ok(mcp.mcpServers.existing);
    assert.ok(!mcp.mcpServers.bountyagent);

    const settings = JSON.parse(fs.readFileSync(path.join(workspace, ".claude", "settings.json"), "utf8"));
    assert.equal(settings.customSetting, true);
    assert.ok(settings.permissions.allow.includes("custom-tool"));
    assert.ok(settings.permissions.allow.includes("mcp__bountyagent__custom_user_tool"));
    assert.ok(!settings.permissions.allow.includes("mcp__bountyagent__bounty_http_scan"));
    assert.ok(!settings.statusLine);
    assert.ok(settings.hooks.PreToolUse.some((entry) => (
      entry.matcher === "Bash" &&
      entry.hooks.some((hook) => hook.command === "echo existing")
    )));
    assert.ok(!settings.hooks.PreToolUse.some((entry) => (
      entry.hooks &&
      entry.hooks.some((hook) => /scope-guard\.sh|session-write-guard\.sh/.test(hook.command))
    )));
    assert.ok(fs.existsSync(path.join(tempHome, "bounty-agent-sessions", "keep.txt")));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});
