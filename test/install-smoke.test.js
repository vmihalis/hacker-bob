const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync, spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { getAdapter } = require("../adapters/index.js");
const update = require("../mcp/lib/update-check.js");
const { createSafeInstallFs } = require("../scripts/lib/install-fs.js");

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "bin", "hacker-bob.js");
const PACKAGE_VERSION = require("../package.json").version;
const CODEX_ADAPTER = getAdapter("codex");
const GENERIC_MCP_ADAPTER = getAdapter("generic-mcp");
const KIMI_ADAPTER = getAdapter("kimi");

function assertRegularFile(filePath) {
  assert.equal(fs.lstatSync(filePath).isFile(), true);
}

test("installer copies a require-able complete MCP runtime", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-install-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    update.writeUpdateCache(workspace, {
      schema_version: 1,
      package_name: "hacker-bob",
      install_target: workspace,
      installed_version: "1.0.0",
      latest_version: "1.3.0",
      update_available: true,
      legacy_install: false,
      checked_at: new Date(1000).toISOString(),
      checked_at_ms: 1000,
      error: null,
    }, { homeDir: tempHome });

    execFileSync(path.join(ROOT, "install.sh"), [workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    assert.equal(update.readUpdateCache(workspace, { homeDir: tempHome }), null);

    const installedServer = path.join(workspace, "mcp", "server.js");
    assert.ok(fs.existsSync(installedServer));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "redaction.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "lib", "dispatch.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "lib", "tools", "index.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "lib", "egress-profiles.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "node_modules", "psl", "dist", "psl.cjs")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "node_modules", "proxy-agent", "dist", "index.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "node_modules", "punycode", "punycode.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-update.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-egress.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-export.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "hunt.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "status.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "debug.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "update.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bountyagent.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bountyagentdebug.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-hunt", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-oss", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-status", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-debug", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagent", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagentstatus", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagentdebug", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "hunter-subagent-stop.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-egress.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-export.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-update.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-check-update.js")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-update-lib.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "lib", "update-check.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "lib", "bob-export.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".hacker-bob", "knowledge", "hunter-techniques.json")));
    assert.ok(fs.existsSync(path.join(workspace, ".hacker-bob", "bypass-tables", "rest-api.txt")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "knowledge")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "bypass-tables")));
    assert.ok(fs.existsSync(path.join(workspace, "testing", "policy-replay", "replay.mjs")));
    assert.ok(fs.existsSync(path.join(workspace, "testing", "policy-replay", "tune.mjs")));
    assert.ok(fs.existsSync(path.join(workspace, "testing", "policy-replay", "cases", "sample-hunter-refusal.json")));
    assert.ok(!fs.existsSync(path.join(workspace, "testing", "policy-replay", "node_modules")));

    const { createRequire } = require("node:module");
    const installedRequire = createRequire(installedServer);
    assert.ok(
      installedRequire.resolve("@anthropic-ai/claude-agent-sdk"),
      "Claude Agent SDK must resolve from <workspace>/mcp/server.js so policy-replay's fallback can find it",
    );

    const sourceSdkManifestPath = path.join(ROOT, "node_modules", "@anthropic-ai", "claude-agent-sdk", "package.json");
    if (fs.existsSync(sourceSdkManifestPath)) {
      const sdkOptionalDeps = JSON.parse(fs.readFileSync(sourceSdkManifestPath, "utf8")).optionalDependencies || {};
      const platformKey = `${process.platform}-${process.arch}`;
      const currentPlatformPackages = Object.keys(sdkOptionalDeps).filter((name) => name.includes(platformKey));
      for (const platformPackage of currentPlatformPackages) {
        const sourcePackageDir = path.join(ROOT, "node_modules", ...platformPackage.split("/"));
        if (!fs.existsSync(sourcePackageDir)) continue;
        const targetPackageDir = path.join(workspace, "mcp", "node_modules", ...platformPackage.split("/"));
        assert.ok(
          fs.existsSync(targetPackageDir),
          `Source has ${platformPackage}; copyRuntimeNodeDependencies must propagate it into <workspace>/mcp/node_modules so live replay can invoke the SDK`,
        );
      }
    }
    assert.equal(fs.readFileSync(path.join(workspace, ".hacker-bob", "VERSION"), "utf8").trim(), PACKAGE_VERSION);
    const neutralInstallMeta = JSON.parse(fs.readFileSync(path.join(workspace, ".hacker-bob", "install.json"), "utf8"));
    assert.equal(neutralInstallMeta.schema_version, 2);
    assert.equal(neutralInstallMeta.bob_version, PACKAGE_VERSION);
    assert.equal(neutralInstallMeta.package_name, "hacker-bob");
    assert.equal(neutralInstallMeta.install_target, workspace);
    assert.deepEqual(neutralInstallMeta.installed_adapters, ["claude"]);
    assert.equal(fs.readFileSync(path.join(workspace, ".claude", "bob", "VERSION"), "utf8").trim(), PACKAGE_VERSION);
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "bob", "egress-profiles.example.json")));
    const egressConfig = JSON.parse(fs.readFileSync(path.join(workspace, ".claude", "bob", "egress-profiles.json"), "utf8"));
    assert.equal(egressConfig.profiles.find((profile) => profile.name === "default").proxy_url, null);
    const settings = JSON.parse(fs.readFileSync(path.join(workspace, ".claude", "settings.json"), "utf8"));
    const settingsText = JSON.stringify(settings);
    assert.match(settingsText, /\$\{CLAUDE_PROJECT_DIR:-\$PWD\}/);
    assert.doesNotMatch(settingsText, /\$CLAUDE_PROJECT_DIR(?!:-)/);
    const installMeta = JSON.parse(fs.readFileSync(path.join(workspace, ".claude", "bob", "install.json"), "utf8"));
    assert.equal(installMeta.schema_version, 1);
    assert.equal(installMeta.bob_version, PACKAGE_VERSION);
    assert.equal(installMeta.package_name, "hacker-bob");
    assert.equal(installMeta.install_target, workspace);

    const statuslinePath = path.join(workspace, ".claude", "hooks", "bounty-statusline.js");
    const nestedWorkspaceDir = path.join(workspace, "nested");
    fs.mkdirSync(nestedWorkspaceDir, { recursive: true });
    const runStatusline = () => execFileSync(process.execPath, [statuslinePath], {
      cwd: nestedWorkspaceDir,
      env: { ...process.env, HOME: tempHome, CLAUDE_PROJECT_DIR: workspace },
      input: JSON.stringify({
        model: { display_name: "Claude" },
        workspace: { current_dir: nestedWorkspaceDir },
      }),
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    });

    update.writeUpdateCache(workspace, {
      schema_version: 1,
      package_name: "hacker-bob",
      install_target: workspace,
      installed_version: "1.0.0",
      latest_version: "1.3.0",
      update_available: true,
      legacy_install: false,
      checked_at: new Date().toISOString(),
      checked_at_ms: Date.now(),
      error: null,
    }, { homeDir: tempHome });
    assert.doesNotMatch(runStatusline(), /Bob 1\.3\.0|Update Bob|bob-update/);

    update.writeUpdateCache(workspace, {
      schema_version: 1,
      package_name: "hacker-bob",
      install_target: workspace,
      installed_version: PACKAGE_VERSION,
      latest_version: "99.0.0",
      update_available: true,
      legacy_install: false,
      checked_at: new Date().toISOString(),
      checked_at_ms: Date.now(),
      error: null,
    }, { homeDir: tempHome });
    assert.match(runStatusline(), /Update Bob to 99\.0\.0: \/bob-update/);

    execFileSync(process.execPath, [
      "-e",
      [
        "const server = require(process.argv[1]);",
        "if (!Array.isArray(server.TOOLS) || server.TOOLS.length !== 109) process.exit(2);",
        "const installedRequire = require('module').createRequire(process.argv[1]);",
        "installedRequire('psl');",
        "installedRequire('proxy-agent');",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_list_auth_profiles')) process.exit(3);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_read_tool_telemetry')) process.exit(6);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_read_pipeline_analytics')) process.exit(7);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_finalize_hunter_run')) process.exit(8);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_write_evidence_packs')) process.exit(9);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_read_evidence_packs')) process.exit(10);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_promote_surface_leads')) process.exit(11);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_read_session_summary')) process.exit(12);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_set_operator_note')) process.exit(13);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_clear_operator_note')) process.exit(14);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_route_surfaces')) process.exit(15);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_read_surface_routes')) process.exit(16);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_start_next_wave')) process.exit(17);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_select_technique_packs')) process.exit(18);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_read_technique_pack')) process.exit(19);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_log_technique_attempt')) process.exit(20);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_get_context_budget')) process.exit(21);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_read_verification_context')) process.exit(22);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_build_verification_adjudication')) process.exit(23);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_init_repo_session')) process.exit(24);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_repo_inventory')) process.exit(25);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_repo_prepare_env')) process.exit(26);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_repo_docker_run')) process.exit(27);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bounty_repo_check')) process.exit(28);",
        "Promise.resolve(server.executeTool('bounty_init_session', { target_domain: 'example.com', target_url: 'https://example.com/' }))",
        "  .then((init) => { if (!init.ok) process.exit(29); return server.executeTool('bounty_list_auth_profiles', { target_domain: 'example.com' }); })",
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

test("installer replaces symlinked generated runtime leaves without following them", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-install-symlink-runtime-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-home-"));
  const workspace = path.join(tempRoot, "workspace");
  const victim = path.join(tempRoot, "victim-server.js");
  fs.mkdirSync(path.join(workspace, "mcp"), { recursive: true });
  fs.writeFileSync(victim, "victim stays\n", "utf8");
  fs.symlinkSync(victim, path.join(workspace, "mcp", "server.js"));

  try {
    execFileSync(process.execPath, [CLI, "install", workspace, "--adapter", "claude"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });

    assert.equal(fs.readFileSync(victim, "utf8"), "victim stays\n");
    assertRegularFile(path.join(workspace, "mcp", "server.js"));
    assert.match(fs.readFileSync(path.join(workspace, "mcp", "server.js"), "utf8"), /startStdioServer/);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("installer replaces symlinked adapter-owned generated leaves without following them", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-install-symlink-adapter-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-home-"));
  const workspace = path.join(tempRoot, "workspace");
  const victim = path.join(tempRoot, "victim-command.md");
  const commandPath = path.join(workspace, ".claude", "commands", "bob-egress.md");
  fs.mkdirSync(path.dirname(commandPath), { recursive: true });
  fs.writeFileSync(victim, "victim stays\n", "utf8");
  fs.symlinkSync(victim, commandPath);

  try {
    execFileSync(process.execPath, [CLI, "install", workspace, "--adapter", "claude"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });

    assert.equal(fs.readFileSync(victim, "utf8"), "victim stays\n");
    assertRegularFile(commandPath);
    assert.match(fs.readFileSync(commandPath, "utf8"), /bob-egress/);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("installer rejects symlinked generated parent directories without writing through them", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-install-symlink-parent-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-home-"));
  const workspace = path.join(tempRoot, "workspace");
  const outsideKnowledge = path.join(tempRoot, "outside-knowledge");
  fs.mkdirSync(path.join(workspace, ".hacker-bob"), { recursive: true });
  fs.mkdirSync(outsideKnowledge, { recursive: true });
  fs.writeFileSync(path.join(outsideKnowledge, "hunter-techniques.json"), "victim stays\n", "utf8");
  fs.symlinkSync(outsideKnowledge, path.join(workspace, ".hacker-bob", "knowledge"));

  try {
    const result = spawnSync(process.execPath, [CLI, "install", workspace, "--adapter", "claude"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      encoding: "utf8",
    });

    assert.notEqual(result.status, 0, `install unexpectedly succeeded: ${result.stdout}`);
    assert.match(result.stderr, /symlinked parent directory|symlinked directory/);
    assert.equal(fs.readFileSync(path.join(outsideKnowledge, "hunter-techniques.json"), "utf8"), "victim stays\n");
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("installer rejects symlinked merged config without writing through it", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-install-symlink-config-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-home-"));
  const workspace = path.join(tempRoot, "workspace");
  const victim = path.join(tempRoot, "victim-mcp.json");
  fs.mkdirSync(workspace, { recursive: true });
  fs.writeFileSync(victim, `${JSON.stringify({ mcpServers: { outside: { command: "node" } } }, null, 2)}\n`, "utf8");
  fs.symlinkSync(victim, path.join(workspace, ".mcp.json"));

  try {
    const result = spawnSync(process.execPath, [CLI, "install", workspace, "--adapter", "claude"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      encoding: "utf8",
    });

    assert.notEqual(result.status, 0, `install unexpectedly succeeded: ${result.stdout}`);
    assert.match(result.stderr, /symlinked .*\.mcp\.json/);
    const outside = JSON.parse(fs.readFileSync(victim, "utf8"));
    assert.deepEqual(outside, { mcpServers: { outside: { command: "node" } } });
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("codex installer replaces symlinked direct skill leaves under CODEX_HOME", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-install-symlink-codex-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-home-"));
  const workspace = path.join(tempRoot, "workspace");
  const codexHome = path.join(tempHome, ".codex");
  const victim = path.join(tempRoot, "victim-skill.md");
  const skillPath = path.join(codexHome, "skills", "bob-hunt", "SKILL.md");
  fs.mkdirSync(workspace, { recursive: true });
  fs.mkdirSync(path.dirname(skillPath), { recursive: true });
  fs.writeFileSync(victim, "victim stays\n", "utf8");
  fs.symlinkSync(victim, skillPath);

  try {
    execFileSync(process.execPath, [CLI, "install", workspace, "--adapter", "codex"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome, CODEX_HOME: codexHome },
      stdio: "pipe",
    });

    assert.equal(fs.readFileSync(victim, "utf8"), "victim stays\n");
    assertRegularFile(skillPath);
    assert.match(fs.readFileSync(skillPath, "utf8"), /bob-hunt/);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("install filesystem recursive copies return nested relative paths", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-install-fs-copy-"));
  const source = path.join(tempRoot, "source");
  const destination = path.join(tempRoot, "destination");
  fs.mkdirSync(path.join(source, "sub"), { recursive: true });
  fs.writeFileSync(path.join(source, "top.txt"), "top\n", "utf8");
  fs.writeFileSync(path.join(source, "sub", "nested.txt"), "nested\n", "utf8");

  try {
    const installFs = createSafeInstallFs(tempRoot, { label: "test install root" });
    const copied = installFs.copyDirRecursive(source, destination);

    assert.deepEqual(copied.sort(), ["sub/nested.txt", "top.txt"]);
    assert.equal(fs.readFileSync(path.join(destination, "sub", "nested.txt"), "utf8"), "nested\n");
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
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
  fs.mkdirSync(path.join(workspace, ".claude", "commands", "bob"), { recursive: true });
  fs.mkdirSync(path.join(workspace, ".claude", "skills", "bountyagent"), { recursive: true });
  fs.mkdirSync(path.join(workspace, ".claude", "skills", "bountyagentstatus"), { recursive: true });
  fs.mkdirSync(path.join(workspace, ".claude", "skills", "bountyagentdebug"), { recursive: true });

  try {
    fs.writeFileSync(path.join(workspace, ".claude", "knowledge", "hunter-techniques.json"), "{}\n");
    fs.writeFileSync(path.join(workspace, ".claude", "knowledge", "custom.json"), "{}\n");
    fs.writeFileSync(path.join(workspace, ".claude", "bypass-tables", "rest-api.txt"), "old\n");
    fs.writeFileSync(path.join(workspace, ".claude", "bypass-tables", "custom.txt"), "custom\n");
    fs.writeFileSync(path.join(workspace, ".claude", "hooks", "bob-update-lib.js"), "old\n");
    fs.writeFileSync(path.join(workspace, ".claude", "commands", "bob", "hunt.md"), "old\n");
    fs.writeFileSync(path.join(workspace, ".claude", "commands", "bob", "status.md"), "old\n");
    fs.writeFileSync(path.join(workspace, ".claude", "commands", "bob", "debug.md"), "old\n");
    fs.writeFileSync(path.join(workspace, ".claude", "commands", "bob", "update.md"), "old\n");
    fs.writeFileSync(path.join(workspace, ".claude", "skills", "bountyagent", "SKILL.md"), "old\n");
    fs.writeFileSync(path.join(workspace, ".claude", "skills", "bountyagentstatus", "SKILL.md"), "old\n");
    fs.writeFileSync(path.join(workspace, ".claude", "skills", "bountyagentdebug", "SKILL.md"), "old\n");
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
          hooks: [
            { type: "command", command: "echo existing session", timeout: 1 },
            { type: "command", command: "node \"$CLAUDE_PROJECT_DIR/.claude/hooks/bob-check-update.js\" \"$CLAUDE_PROJECT_DIR\"", timeout: 2 },
          ],
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
      statusLine: {
        type: "command",
        command: "node \"$CLAUDE_PROJECT_DIR/.claude/hooks/bounty-statusline.js\"",
      },
      customSetting: true,
    }, null, 2)}\n`);

    for (let index = 0; index < 2; index += 1) {
      execFileSync(path.join(ROOT, "install.sh"), [workspace], {
        cwd: ROOT,
        env: { ...process.env, HOME: tempHome },
        stdio: "pipe",
      });
      if (index === 0) {
        fs.writeFileSync(path.join(workspace, ".claude", "bob", "egress-profiles.json"), `${JSON.stringify({
          version: 1,
          profiles: [
            { name: "default", proxy_url: null, region: null, description: "Direct", enabled: true },
            { name: "operator", proxy_url: "${BOB_EGRESS_OPERATOR_PROXY}", region: "EU", description: "Operator-owned", enabled: true },
          ],
        }, null, 2)}\n`);
      }
    }

    const mcp = JSON.parse(fs.readFileSync(path.join(workspace, ".mcp.json"), "utf8"));
    assert.ok(mcp.mcpServers.existing);
    assert.ok(mcp.mcpServers.bountyagent);
    assert.equal(Object.keys(mcp.mcpServers).filter((name) => name === "bountyagent").length, 1);

    const settings = JSON.parse(fs.readFileSync(path.join(workspace, ".claude", "settings.json"), "utf8"));
    const settingsText = JSON.stringify(settings);
    assert.match(settingsText, /\$\{CLAUDE_PROJECT_DIR:-\$PWD\}/);
    assert.doesNotMatch(settingsText, /\$CLAUDE_PROJECT_DIR(?!:-)/);
    assert.equal(settings.customSetting, true);
    assert.equal(settings.permissions.allow.length, new Set(settings.permissions.allow).size);
    assert.ok(settings.permissions.allow.includes("custom-tool"));
    assert.ok(settings.permissions.allow.includes("mcp__bountyagent__custom_user_tool"));
    assert.ok(settings.permissions.allow.includes("mcp__bountyagent__bounty_http_scan"));
    assert.ok(!settings.permissions.allow.includes("mcp__bountyagent__bounty_merge_wave_handoffs"));
    assert.match(settings.statusLine.command, /\$\{CLAUDE_PROJECT_DIR:-\$PWD\}/);

    const bashEntry = settings.hooks.PreToolUse.find((entry) => entry.matcher === "Bash");
    assert.ok(bashEntry);
    assert.ok(bashEntry.hooks.some((hook) => hook.command === "echo existing"));
    assert.equal(
      bashEntry.hooks.filter((hook) => /session-write-guard\.sh/.test(hook.command)).length,
      1,
    );
    assert.equal(
      settings.hooks.PreToolUse.filter((entry) => entry.matcher === "mcp__bountyagent__bounty_http_scan").length,
      0,
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
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-update.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-export.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "hunt.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "status.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "debug.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "update.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagent", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagentstatus", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagentdebug", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-hunt", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-status", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-debug", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "knowledge", "custom.json")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "bypass-tables", "custom.txt")));
    assert.match(sessionEntry.hooks.find((hook) => /bob-check-update\.js/.test(hook.command)).command, /\$\{CLAUDE_PROJECT_DIR:-\$PWD\}/);
    const egressConfig = JSON.parse(fs.readFileSync(path.join(workspace, ".claude", "bob", "egress-profiles.json"), "utf8"));
    assert.ok(egressConfig.profiles.some((profile) => profile.name === "operator"));
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
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-update.md")));

    execFileSync(process.execPath, [CLI, "uninstall", workspace, "--yes"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob-update.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bob-hunt", "SKILL.md")));

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

test("codex adapter installs direct skills and doctor checks MCP wiring", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-codex-adapter-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-home-"));
  const workspace = path.join(tempRoot, "workspace");
  const originalCodexHome = process.env.CODEX_HOME;
  fs.mkdirSync(workspace, { recursive: true });
  process.env.CODEX_HOME = path.join(tempHome, ".codex");

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
    assert.equal(install.skills, 7);
    assert.equal(install.commands, 7);
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".codex-plugin", "plugin.json")));
    const manifest = JSON.parse(fs.readFileSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".codex-plugin", "plugin.json"), "utf8"));
    assert.equal(Object.prototype.hasOwnProperty.call(manifest, "skills"), false);
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-hunt", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-oss", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-status", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-debug", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-update", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-export", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-egress", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "skills", "hunt", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "skills", "bob-hunt", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "skills", "hacker-bob-hunt", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(tempHome, ".codex", "skills", "hacker-bob-hunt", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-hunt.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-oss.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-export.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-egress.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".agents", "plugins", "marketplace.json")));

    const mcp = JSON.parse(fs.readFileSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".mcp.json"), "utf8"));
    assert.deepEqual(mcp.mcpServers.bountyagent, {
      command: "node",
      args: [path.join(workspace, "mcp", "server.js")],
    });

    const doctor = CODEX_ADAPTER.doctor({ targetAbs: workspace });
    assert.equal(doctor.ok, true);
    assert.ok(doctor.checks.some((check) => check.id === "codex_plugin_manifest" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "codex_global_skills" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "codex_global_skills_fresh" && check.status === "warn"));
    fs.cpSync(path.join(ROOT, "adapters", "codex", "skills"), path.join(workspace, "adapters", "codex", "skills"), { recursive: true });
    const sourceBackedDoctor = CODEX_ADAPTER.doctor({ targetAbs: workspace });
    assert.equal(sourceBackedDoctor.ok, true);
    assert.ok(sourceBackedDoctor.checks.some((check) => check.id === "codex_global_skills_fresh" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "codex_plugin_skills_clean" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "codex_plugin_mcp" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "codex_plugin_commands" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "codex_plugin_marketplace" && check.status === "ok"));

    fs.appendFileSync(path.join(tempHome, ".codex", "skills", "bob-oss", "SKILL.md"), "\n# stale local edit\n", "utf8");
    const staleDoctor = CODEX_ADAPTER.doctor({ targetAbs: workspace });
    assert.equal(staleDoctor.ok, false);
    const freshness = staleDoctor.checks.find((check) => check.id === "codex_global_skills_fresh");
    assert.equal(freshness.status, "error");
    assert.equal(freshness.detail.stale.some((item) => item.skill === "bob-oss" && item.reason === "content_mismatch"), true);
    assert.equal(freshness.detail.reinstall, "node bin/hacker-bob.js install . --adapter codex");

    const readErrorPath = path.join(tempHome, ".codex", "skills", "bob-status", "SKILL.md");
    const originalReadFileSync = fs.readFileSync;
    try {
      fs.readFileSync = function patchedReadFileSync(filePath, ...args) {
        if (path.resolve(String(filePath)) === path.resolve(readErrorPath)) {
          throw new Error("simulated read failure");
        }
        return originalReadFileSync.call(this, filePath, ...args);
      };
      const readErrorFreshness = CODEX_ADAPTER.directSkillFreshness(workspace);
      assert.equal(
        readErrorFreshness.stale.some((item) => (
          item.skill === "bob-status" &&
          item.reason === "read_error" &&
          /simulated read failure/.test(item.error)
        )),
        true,
      );
    } finally {
      fs.readFileSync = originalReadFileSync;
    }

    const dryRun = CODEX_ADAPTER.uninstall({ sourceRoot: ROOT, targetAbs: workspace, dryRun: true });
    assert.equal(dryRun.dry_run, true);
    assert.ok(dryRun.actions.some((action) => action.path === path.join(tempHome, ".codex", "skills", "bob-hunt", "SKILL.md")));
    assert.ok(dryRun.actions.some((action) => action.path === path.join(".codex", "plugins", "hacker-bob", ".mcp.json")));
    assert.ok(dryRun.actions.some((action) => action.path === path.join(".agents", "plugins", "marketplace.json")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".mcp.json")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-hunt", "SKILL.md")));

    const removed = CODEX_ADAPTER.uninstall({ sourceRoot: ROOT, targetAbs: workspace, dryRun: false });
    assert.equal(removed.dry_run, false);
    assert.ok(!fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-hunt", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-export", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-egress", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".mcp.json")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-hunt.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-export.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-egress.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".agents", "plugins", "marketplace.json")));
  } finally {
    if (originalCodexHome === undefined) {
      delete process.env.CODEX_HOME;
    } else {
      process.env.CODEX_HOME = originalCodexHome;
    }
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("kimi adapter installs skills and MCP config", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-kimi-adapter-"));
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

    const install = KIMI_ADAPTER.install({
      sourceRoot: ROOT,
      targetAbs: workspace,
      serverPath: path.join(workspace, "mcp", "server.js"),
    });
    assert.equal(install.skills, 6);
    assert.ok(fs.existsSync(path.join(workspace, ".kimi", "skills", "bob-hunt", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".kimi", "skills", "bob-status", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".kimi", "skills", "bob-debug", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".kimi", "skills", "bob-update", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".kimi", "skills", "bob-export", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".kimi", "skills", "bob-egress", "SKILL.md")));
    // Kimi adapter does NOT install hooks (see adapters/kimi/config.js header):
    // the ~/.kimi/config.toml PreToolUse registration syntax is undocumented,
    // so shipping the .sh scripts would be a security control that never runs.
    assert.ok(!fs.existsSync(path.join(workspace, ".kimi", "hooks")), "kimi adapter must not install .kimi/hooks");

    const mcp = JSON.parse(fs.readFileSync(path.join(workspace, ".kimi", "mcp.json"), "utf8"));
    assert.deepEqual(mcp.mcpServers.bountyagent, {
      command: "node",
      args: [path.join(workspace, "mcp", "server.js")],
    });
    assert.ok(mcp.mcpServers.brutalist, "kimi install must register the optional brutalist MCP server");
    assert.deepEqual(mcp.mcpServers.brutalist.args, ["-y", "@brutalist/mcp@latest"]);

    const doctor = KIMI_ADAPTER.doctor({ targetAbs: workspace });
    assert.equal(doctor.ok, true);
    assert.ok(doctor.checks.some((check) => check.id === "kimi_skills" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "kimi_mcp_server_config" && check.status === "ok"));

    const dryRun = KIMI_ADAPTER.uninstall({ sourceRoot: ROOT, targetAbs: workspace, dryRun: true });
    assert.equal(dryRun.dry_run, true);
    assert.ok(dryRun.actions.some((action) => action.path === path.join(".kimi", "skills", "bob-hunt", "SKILL.md")));
    assert.ok(dryRun.actions.some((action) => action.path === path.join(".kimi", "mcp.json")));
    assert.ok(fs.existsSync(path.join(workspace, ".kimi", "skills", "bob-hunt", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".kimi", "mcp.json")));

    const removed = KIMI_ADAPTER.uninstall({ sourceRoot: ROOT, targetAbs: workspace, dryRun: false });
    assert.equal(removed.dry_run, false);
    assert.ok(!fs.existsSync(path.join(workspace, ".kimi", "skills", "bob-hunt", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".kimi", "skills", "bob-export", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".kimi", "skills", "bob-egress", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".kimi", "mcp.json")));
    // Regression: managedDirs() must enumerate all six skill directories so
    // uninstall removes them — earlier revisions only listed bob-hunt,
    // bob-status, bob-debug and left bob-update/bob-export/bob-egress on disk.
    for (const skill of ["bob-hunt", "bob-status", "bob-debug", "bob-update", "bob-export", "bob-egress"]) {
      assert.ok(
        !fs.existsSync(path.join(workspace, ".kimi", "skills", skill)),
        `kimi uninstall must remove the ${skill} skill directory`,
      );
    }
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
