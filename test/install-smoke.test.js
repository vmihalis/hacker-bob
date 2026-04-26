const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { getAdapter } = require("../adapters/index.js");

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "bin", "hacker-bob.js");
const PACKAGE_VERSION = require("../package.json").version;
const CODEX_ADAPTER = getAdapter("codex");
const GENERIC_MCP_ADAPTER = getAdapter("generic-mcp");

test("installer copies a require-able complete MCP runtime", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-install-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    execFileSync(path.join(ROOT, "install.sh"), [workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });

    const installedServer = path.join(workspace, "mcp", "server.js");
    assert.ok(fs.existsSync(installedServer));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "redaction.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "lib", "dispatch.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "lib", "tools", "index.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "hunt.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "status.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "debug.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "update.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bountyagent.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bountyagentdebug.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagent", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagentstatus", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagentdebug", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "hunter-subagent-stop.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-update.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-check-update.js")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-update-lib.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "lib", "update-check.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".hacker-bob", "knowledge", "hunter-techniques.json")));
    assert.ok(fs.existsSync(path.join(workspace, ".hacker-bob", "bypass-tables", "rest-api.txt")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "knowledge")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "bypass-tables")));
    assert.equal(fs.readFileSync(path.join(workspace, ".hacker-bob", "VERSION"), "utf8").trim(), PACKAGE_VERSION);
    const neutralInstallMeta = JSON.parse(fs.readFileSync(path.join(workspace, ".hacker-bob", "install.json"), "utf8"));
    assert.equal(neutralInstallMeta.schema_version, 2);
    assert.equal(neutralInstallMeta.bob_version, PACKAGE_VERSION);
    assert.equal(neutralInstallMeta.package_name, "hacker-bob");
    assert.equal(neutralInstallMeta.install_target, workspace);
    assert.deepEqual(neutralInstallMeta.installed_adapters, ["claude"]);
    assert.equal(fs.readFileSync(path.join(workspace, ".claude", "bob", "VERSION"), "utf8").trim(), PACKAGE_VERSION);
    const installMeta = JSON.parse(fs.readFileSync(path.join(workspace, ".claude", "bob", "install.json"), "utf8"));
    assert.equal(installMeta.schema_version, 1);
    assert.equal(installMeta.bob_version, PACKAGE_VERSION);
    assert.equal(installMeta.package_name, "hacker-bob");
    assert.equal(installMeta.install_target, workspace);

    execFileSync(process.execPath, [
      "-e",
      [
        "const server = require(process.argv[1]);",
        "if (!Array.isArray(server.TOOLS) || server.TOOLS.length !== 36) process.exit(2);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_list_auth_profiles')) process.exit(3);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_read_tool_telemetry')) process.exit(6);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_read_pipeline_analytics')) process.exit(7);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_finalize_hunter_run')) process.exit(8);",
        "Promise.resolve(server.executeTool('bounty_list_auth_profiles', { target_domain: 'example.com' }))",
        "  .then((result) => { if (!result.ok || result.data.target_domain !== 'example.com') process.exit(4); })",
        "  .catch(() => process.exit(5));",
      ].join(" "),
      installedServer,
    ], { env: { ...process.env, HOME: tempHome }, stdio: "pipe" });
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("doctor accepts legacy-only resources and uninstall removes legacy resource copies", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-legacy-resources-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    execFileSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });

    fs.mkdirSync(path.join(workspace, ".claude"), { recursive: true });
    fs.renameSync(
      path.join(workspace, ".hacker-bob", "knowledge"),
      path.join(workspace, ".claude", "knowledge"),
    );
    fs.renameSync(
      path.join(workspace, ".hacker-bob", "bypass-tables"),
      path.join(workspace, ".claude", "bypass-tables"),
    );
    fs.rmSync(path.join(workspace, ".hacker-bob"), { recursive: true, force: true });

    const doctorOutput = execFileSync(process.execPath, [CLI, "doctor", workspace, "--json"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const doctor = JSON.parse(doctorOutput);
    assert.equal(doctor.ok, true);
    assert.equal(doctor.checks.find((check) => check.id === "resource_knowledge").status, "warn");
    assert.equal(doctor.checks.find((check) => check.id === "resource_bypass_tables").status, "warn");

    const uninstallOutput = execFileSync(process.execPath, [CLI, "uninstall", workspace, "--yes", "--json"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const uninstall = JSON.parse(uninstallOutput);
    assert.equal(uninstall.dry_run, false);
    assert.ok(uninstall.actions.some((action) => action.path === path.join(".claude", "knowledge", "hunter-techniques.json")));
    assert.ok(uninstall.actions.some((action) => action.path === path.join(".claude", "bypass-tables", "rest-api.txt")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "knowledge", "hunter-techniques.json")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "bypass-tables", "rest-api.txt")));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("installer merges existing MCP/settings config idempotently", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-install-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(path.join(workspace, ".claude", "knowledge"), { recursive: true });
  fs.mkdirSync(path.join(workspace, ".claude", "bypass-tables"), { recursive: true });
  fs.mkdirSync(path.join(workspace, ".claude", "hooks"), { recursive: true });

  try {
    fs.writeFileSync(path.join(workspace, ".claude", "knowledge", "hunter-techniques.json"), "{}\n");
    fs.writeFileSync(path.join(workspace, ".claude", "knowledge", "custom.json"), "{}\n");
    fs.writeFileSync(path.join(workspace, ".claude", "bypass-tables", "rest-api.txt"), "old\n");
    fs.writeFileSync(path.join(workspace, ".claude", "bypass-tables", "custom.txt"), "custom\n");
    fs.writeFileSync(path.join(workspace, ".claude", "hooks", "bob-update-lib.js"), "old\n");
    fs.writeFileSync(path.join(workspace, ".mcp.json"), `${JSON.stringify({
      mcpServers: {
        existing: { command: "node", args: ["existing.js"] },
      },
    }, null, 2)}\n`);
    fs.writeFileSync(path.join(workspace, ".claude", "settings.json"), `${JSON.stringify({
      permissions: {
        allow: [
          "Read",
          "custom-tool",
          "mcp__bountyagent__bounty_merge_wave_handoffs",
          "mcp__bountyagent__custom_user_tool",
        ],
      },
      hooks: {
        SessionStart: [{
          matcher: "startup",
          hooks: [{ type: "command", command: "echo existing session", timeout: 1 }],
        }],
        PreToolUse: [{
          matcher: "Bash",
          hooks: [{ type: "command", command: "echo existing", timeout: 1 }],
        }],
        SubagentStop: [{
          matcher: "hunter-agent",
          hooks: [{ type: "command", command: "echo existing stop", timeout: 1 }],
        }],
      },
      customSetting: true,
    }, null, 2)}\n`);

    for (let index = 0; index < 2; index += 1) {
      execFileSync(path.join(ROOT, "install.sh"), [workspace], {
        cwd: ROOT,
        env: { ...process.env, HOME: tempHome },
        stdio: "pipe",
      });
    }

    const mcp = JSON.parse(fs.readFileSync(path.join(workspace, ".mcp.json"), "utf8"));
    assert.ok(mcp.mcpServers.existing);
    assert.ok(mcp.mcpServers.bountyagent);
    assert.equal(Object.keys(mcp.mcpServers).filter((name) => name === "bountyagent").length, 1);

    const settings = JSON.parse(fs.readFileSync(path.join(workspace, ".claude", "settings.json"), "utf8"));
    assert.equal(settings.customSetting, true);
    assert.equal(settings.permissions.allow.length, new Set(settings.permissions.allow).size);
    assert.ok(settings.permissions.allow.includes("custom-tool"));
    assert.ok(settings.permissions.allow.includes("mcp__bountyagent__custom_user_tool"));
    assert.ok(settings.permissions.allow.includes("mcp__bountyagent__bounty_http_scan"));
    assert.ok(!settings.permissions.allow.includes("mcp__bountyagent__bounty_merge_wave_handoffs"));

    const bashEntry = settings.hooks.PreToolUse.find((entry) => entry.matcher === "Bash");
    assert.ok(bashEntry);
    assert.ok(bashEntry.hooks.some((hook) => hook.command === "echo existing"));
    assert.equal(
      bashEntry.hooks.filter((hook) => /session-write-guard\.sh/.test(hook.command)).length,
      1,
    );
    assert.equal(
      settings.hooks.PreToolUse.filter((entry) => entry.matcher === "mcp__bountyagent__bounty_http_scan").length,
      1,
    );
    const stopEntry = settings.hooks.SubagentStop.find((entry) => entry.matcher === "hunter-agent");
    assert.ok(stopEntry);
    assert.ok(stopEntry.hooks.some((hook) => hook.command === "echo existing stop"));
    assert.equal(
      stopEntry.hooks.filter((hook) => /hunter-subagent-stop\.js/.test(hook.command)).length,
      1,
    );
    const sessionEntry = settings.hooks.SessionStart.find((entry) => entry.matcher === "startup");
    assert.ok(sessionEntry);
    assert.ok(sessionEntry.hooks.some((hook) => hook.command === "echo existing session"));
    assert.equal(
      sessionEntry.hooks.filter((hook) => /bob-check-update\.js/.test(hook.command)).length,
      1,
    );
    assert.ok(fs.existsSync(path.join(workspace, ".hacker-bob", "knowledge", "hunter-techniques.json")));
    assert.ok(fs.existsSync(path.join(workspace, ".hacker-bob", "bypass-tables", "rest-api.txt")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "knowledge", "hunter-techniques.json")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "bypass-tables", "rest-api.txt")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-update-lib.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "knowledge", "custom.json")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "bypass-tables", "custom.txt")));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("install doctor uninstall dry-run uninstall and reinstall workflow works", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-lifecycle-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    execFileSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    execFileSync(process.execPath, [CLI, "doctor", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    execFileSync(process.execPath, [CLI, "uninstall", workspace, "--dry-run"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "hunt.md")));

    execFileSync(process.execPath, [CLI, "uninstall", workspace, "--yes"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "hunt.md")));

    execFileSync(process.execPath, [CLI, "uninstall", workspace, "--yes"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });

    execFileSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    execFileSync(process.execPath, [CLI, "doctor", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("codex adapter installs plugin skills and doctor checks MCP wiring", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-codex-adapter-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    execFileSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });

    const install = CODEX_ADAPTER.install({
      sourceRoot: ROOT,
      targetAbs: workspace,
      serverPath: path.join(workspace, "mcp", "server.js"),
    });
    assert.equal(install.skills, 4);
    assert.equal(install.commands, 4);
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".codex-plugin", "plugin.json")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "skills", "hunt", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "skills", "hacker-bob-hunt", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "hunt.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".agents", "plugins", "marketplace.json")));

    const mcp = JSON.parse(fs.readFileSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".mcp.json"), "utf8"));
    assert.deepEqual(mcp.mcpServers.bountyagent, {
      command: "node",
      args: [path.join(workspace, "mcp", "server.js")],
    });

    const doctor = CODEX_ADAPTER.doctor({ targetAbs: workspace });
    assert.equal(doctor.ok, true);
    assert.ok(doctor.checks.some((check) => check.id === "codex_plugin_manifest" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "codex_plugin_mcp" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "codex_plugin_commands" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "codex_plugin_marketplace" && check.status === "ok"));

    const dryRun = CODEX_ADAPTER.uninstall({ sourceRoot: ROOT, targetAbs: workspace, dryRun: true });
    assert.equal(dryRun.dry_run, true);
    assert.ok(dryRun.actions.some((action) => action.path === path.join(".codex", "plugins", "hacker-bob", ".mcp.json")));
    assert.ok(dryRun.actions.some((action) => action.path === path.join(".agents", "plugins", "marketplace.json")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".mcp.json")));

    const removed = CODEX_ADAPTER.uninstall({ sourceRoot: ROOT, targetAbs: workspace, dryRun: false });
    assert.equal(removed.dry_run, false);
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".mcp.json")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "hunt.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".agents", "plugins", "marketplace.json")));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("generic MCP adapter installs only MCP config and prompt docs", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-generic-mcp-adapter-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    execFileSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    fs.rmSync(path.join(workspace, ".claude"), { recursive: true, force: true });
    fs.writeFileSync(path.join(workspace, ".mcp.json"), `${JSON.stringify({
      mcpServers: {
        existing: { command: "node", args: ["existing.js"] },
      },
    }, null, 2)}\n`);

    GENERIC_MCP_ADAPTER.install({
      sourceRoot: ROOT,
      targetAbs: workspace,
      serverPath: path.join(workspace, "mcp", "server.js"),
    });

    assert.ok(!fs.existsSync(path.join(workspace, ".claude")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex")));
    assert.ok(fs.existsSync(path.join(workspace, ".hacker-bob", "generic-mcp", "hacker-bob.md")));

    const mcp = JSON.parse(fs.readFileSync(path.join(workspace, ".mcp.json"), "utf8"));
    assert.ok(mcp.mcpServers.existing);
    assert.deepEqual(mcp.mcpServers.bountyagent, {
      command: "node",
      args: [path.join(workspace, "mcp", "server.js")],
    });

    const doctor = GENERIC_MCP_ADAPTER.doctor({ targetAbs: workspace });
    assert.equal(doctor.ok, true);
    assert.ok(doctor.checks.some((check) => check.id === "generic_mcp_server" && check.status === "ok"));

    const removed = GENERIC_MCP_ADAPTER.uninstall({ targetAbs: workspace, dryRun: false });
    assert.equal(removed.dry_run, false);
    assert.ok(!fs.existsSync(path.join(workspace, ".hacker-bob", "generic-mcp", "hacker-bob.md")));
    const after = JSON.parse(fs.readFileSync(path.join(workspace, ".mcp.json"), "utf8"));
    assert.ok(after.mcpServers.existing);
    assert.ok(!after.mcpServers.bountyagent);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});
