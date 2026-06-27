const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { getAdapter } = require("../adapters/index.js");
const { installProject } = require("../scripts/install.js");
const update = require("../mcp/lib/update-check.js");

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "bin", "hacker-bob.js");
const PACKAGE_VERSION = require("../package.json").version;
const CODEX_ADAPTER = getAdapter("codex");
const KIMI_ADAPTER = getAdapter("kimi");
const GENERIC_MCP_ADAPTER = getAdapter("generic-mcp");

test("PRE-FLIGHT atomicity: a stale bounty_* permission with no canonical twin aborts BEFORE any file is copied", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-preflight-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(path.join(workspace, ".claude"), { recursive: true });
  // An operator's existing settings pinning a REMOVED bounty_* tool (no bob_* twin). The legacy
  // permission migration THROWS during the settings merge — which runs AFTER the runtime/agents/
  // hooks are copied. The pre-flight must catch it BEFORE the first mutation, leaving the target
  // untouched (no half-upgraded project).
  const settingsPath = path.join(workspace, ".claude", "settings.json");
  const original = `${JSON.stringify({
    permissions: { allow: ["mcp__hacker-bob__bounty_report_written", "Read"] },
    customSetting: true,
  }, null, 2)}\n`;
  fs.writeFileSync(settingsPath, original, "utf8");
  try {
    assert.throws(
      () => installProject(workspace, { adapter: "claude", sourceRoot: ROOT, onAdapterResolution: () => {} }),
      /stale MCP permission|no canonical replacement|bounty_\* tool alias/i,
    );
    // ATOMICITY: nothing Bob-owned was created — the doomed install never touched the target.
    assert.ok(!fs.existsSync(path.join(workspace, "mcp", "server.js")), "no MCP runtime copied");
    assert.ok(!fs.existsSync(path.join(workspace, ".hacker-bob")), "no .hacker-bob resources");
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "bob")), "no .claude/bob metadata");
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills")), "no skills copied");
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "agents")), "no agents copied");
    // The operator's settings.json is left EXACTLY as it was (not migrated/overwritten).
    assert.equal(fs.readFileSync(settingsPath, "utf8"), original);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("installer copies a require-able complete MCP runtime", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-install-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-home-"));
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
    // The installer ships an EXPLICIT manifest of top-level mcp/ runtime files (deny-by-default).
    // Guard BOTH regressions the manifest-vs-glob review raised:
    //  (1) the manifest EQUALS the real source top-level mcp/*.js — a NEW runtime file (as
    //      browser-driver.js, the DRIVER_SCRIPT_PATH server.js spawns, once was) or a DELETION makes
    //      manifest != source and fails here, closing the silent-drift gap that broke authed_fetch (#155);
    //  (2) the INSTALLED top-level mcp/*.js EQUALS the manifest — a dropped OR a stray file fails too.
    const { MCP_TOP_LEVEL_RUNTIME_FILES } = require("../scripts/install.js");
    const topLevelJs = (dir) => fs.readdirSync(dir)
      .filter((name) => name.endsWith(".js") && fs.statSync(path.join(dir, name)).isFile())
      .sort();
    const manifest = [...MCP_TOP_LEVEL_RUNTIME_FILES].sort();
    // Drift guard: the manifest must list exactly the real top-level mcp/*.js, so a NEW runtime file
    // (as browser-driver.js once was) or a deletion forces a manifest update instead of silently
    // shipping the wrong set — the drift that froze the operational driver.
    assert.deepEqual(topLevelJs(path.join(ROOT, "mcp")), manifest,
      "MCP_TOP_LEVEL_RUNTIME_FILES must equal the real top-level mcp/*.js — update the manifest when a runtime file is added/removed");
    // Ship guard: every manifest runtime file is installed. A SUPERSET check, not equality — the
    // installer never deletes target files it did not place, so it must not assert the target holds
    // ONLY these (a user's own top-level mcp/*.js is legitimately preserved).
    for (const name of manifest) {
      assert.ok(fs.existsSync(path.join(workspace, "mcp", name)), `installer must copy top-level mcp/${name}`);
    }
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "lib", "dispatch.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "lib", "tools", "index.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "lib", "egress-profiles.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "node_modules", "psl", "dist", "psl.cjs")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "node_modules", "proxy-agent", "dist", "index.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "node_modules", "punycode", "punycode.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-update.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-egress.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-export.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-evaluate.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "evaluate.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "status.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "debug.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "update.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bountyagent.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bountyagentdebug.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-evaluate-runner", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-status", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-debug", "SKILL.md")));
    // Legacy skill dirs must not be present — they would surface as duplicate
    // /bob-evaluate slash-picker entries with orchestrator-prose descriptions.
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bob-hunt", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagent", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagentstatus", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagentdebug", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "agent-run-stop.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-egress.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-export.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-update.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-check-update.js")));
    // CR-2: the write-guard classification manifest must be installed beside the
    // hook, or the hook's fail-closed branch blocks every session write.
    assert.ok(
      fs.existsSync(path.join(workspace, ".claude", "hooks", "write-guard-tables.json")),
      "write-guard-tables.json must be installed beside session-write-guard.sh",
    );
    // And it must NOT be executable (it is hook DATA, not a hook).
    {
      const m = fs.statSync(path.join(workspace, ".claude", "hooks", "write-guard-tables.json")).mode;
      assert.equal(m & 0o111, 0, "write-guard-tables.json must not be executable");
    }
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-update-lib.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "lib", "update-check.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "lib", "bob-export.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".hacker-bob", "knowledge", "evaluator-techniques.json")));
    assert.ok(fs.existsSync(path.join(workspace, ".hacker-bob", "bypass-tables", "rest-api.txt")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "knowledge")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "bypass-tables")));
    assert.ok(fs.existsSync(path.join(workspace, "testing", "policy-replay", "replay.mjs")));
    assert.ok(fs.existsSync(path.join(workspace, "testing", "policy-replay", "tune.mjs")));
    assert.ok(fs.existsSync(path.join(workspace, "testing", "policy-replay", "cases", "sample-evaluator-refusal.json")));
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
    // Y.10 (Y-D12 / D6 + D14) — install provisions the operator session-cap
    // nonce at $HOME/.bob/session-cap (mode 0600) so partial-surface
    // acknowledgement attestation_tokens have an authoritative nonce to
    // match against. Without this, the OPEN_FRONTIER -> CLAIM_FREEZE gate
    // would accept any non-empty token as authority.
    const sessionCapFile = path.join(tempHome, ".bob", "session-cap");
    assert.ok(fs.existsSync(sessionCapFile), "install must provision ~/.bob/session-cap nonce");
    const sessionCapStat = fs.statSync(sessionCapFile);
    assert.equal(sessionCapStat.mode & 0o777, 0o600, "session-cap file mode must be 0600");
    const sessionCapValue = fs.readFileSync(sessionCapFile, "utf8").trim();
    assert.match(sessionCapValue, /^[0-9a-f]{64}$/, "session-cap nonce must be 64-char hex");

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

    const statuslinePath = path.join(workspace, ".claude", "hooks", "bob-statusline.js");
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
        "const installedRequire = require('module').createRequire(process.argv[1]);",
        "installedRequire('psl');",
        "installedRequire('proxy-agent');",
        "if (!Array.isArray(server.TOOLS) || server.TOOLS.length !== 182) process.exit(2);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_stage_verification_round_partial')) process.exit(53);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_plan_recon_angles')) process.exit(52);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_register_mechanism_template')) process.exit(51);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_http_confirm')) process.exit(42);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_http_cors_confirm')) process.exit(49);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_http_idor_confirm')) process.exit(43);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_http_xss_reflect')) process.exit(44);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_http_xss_confirm')) process.exit(45);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_oob_mint')) process.exit(46);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_oob_poll')) process.exit(47);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_nuclei_scan')) process.exit(48);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_import_harness')) process.exit(50);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_ingest_sarif')) process.exit(40);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_read_static_analysis_index')) process.exit(41);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_list_auth_profiles')) process.exit(3);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_materialize_task_graph')) process.exit(33);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_read_task_graph')) process.exit(34);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_attach_contract')) process.exit(35);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_prepare_node')) process.exit(36);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_finalize_node')) process.exit(37);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_schedule_graph_nodes')) process.exit(38);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_repo_inventory')) process.exit(29);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_repo_prepare_env')) process.exit(30);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_repo_docker_run')) process.exit(31);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_repo_check')) process.exit(32);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_finalize_report')) process.exit(25);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_read_tool_telemetry')) process.exit(6);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_read_pipeline_analytics')) process.exit(7);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_finalize_agent_run')) process.exit(8);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_write_evidence_packs')) process.exit(9);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_read_evidence_packs')) process.exit(10);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_write_proof_bundle')) process.exit(39);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_promote_surface_leads')) process.exit(11);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_read_session_summary')) process.exit(12);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_set_operator_note')) process.exit(13);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_clear_operator_note')) process.exit(14);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_route_surfaces')) process.exit(15);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_read_surface_routes')) process.exit(16);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_start_next_wave')) process.exit(17);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_select_technique_packs')) process.exit(18);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_read_technique_pack')) process.exit(19);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_log_technique_attempt')) process.exit(20);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_get_context_budget')) process.exit(21);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_read_verification_context')) process.exit(22);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_build_verification_adjudication')) process.exit(23);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_browser_session_start')) process.exit(26);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_browser_evaluate')) process.exit(27);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_browser_session_close')) process.exit(28);",
        "Promise.resolve(server.executeTool('bob_init_session', { target_domain: 'example.com', target_url: 'https://example.com/' }))",
        "  .then((init) => { if (!init.ok) process.exit(24); return server.executeTool('bob_list_auth_profiles', { target_domain: 'example.com' }); })",
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
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-legacy-resources-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-home-"));
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
    assert.ok(uninstall.actions.some((action) => action.path === path.join(".claude", "knowledge", "evaluator-techniques.json")));
    assert.ok(uninstall.actions.some((action) => action.path === path.join(".claude", "bypass-tables", "rest-api.txt")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "knowledge", "evaluator-techniques.json")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "bypass-tables", "rest-api.txt")));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("installer merges existing MCP/settings config idempotently", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-install-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(path.join(workspace, ".claude", "knowledge"), { recursive: true });
  fs.mkdirSync(path.join(workspace, ".claude", "bypass-tables"), { recursive: true });
  fs.mkdirSync(path.join(workspace, ".claude", "hooks"), { recursive: true });
  fs.mkdirSync(path.join(workspace, ".claude", "commands", "bob"), { recursive: true });
  fs.mkdirSync(path.join(workspace, ".claude", "skills", "bountyagent"), { recursive: true });
  fs.mkdirSync(path.join(workspace, ".claude", "skills", "bountyagentstatus"), { recursive: true });
  fs.mkdirSync(path.join(workspace, ".claude", "skills", "bountyagentdebug"), { recursive: true });

  try {
    fs.writeFileSync(path.join(workspace, ".claude", "knowledge", "evaluator-techniques.json"), "{}\n");
    fs.writeFileSync(path.join(workspace, ".claude", "knowledge", "custom.json"), "{}\n");
    fs.writeFileSync(path.join(workspace, ".claude", "bypass-tables", "rest-api.txt"), "old\n");
    fs.writeFileSync(path.join(workspace, ".claude", "bypass-tables", "custom.txt"), "custom\n");
    fs.writeFileSync(path.join(workspace, ".claude", "hooks", "bob-update-lib.js"), "old\n");
    fs.writeFileSync(path.join(workspace, ".claude", "commands", "bob", "evaluate.md"), "old\n");
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
          "mcp__bountyagent__bob_merge_wave_handoffs",
          "mcp__bountyagent__custom_user_tool",
          "mcp__hacker-bob__pre_migration_custom",
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
          matcher: "evaluator-agent",
          hooks: [{ type: "command", command: "echo existing stop", timeout: 1 }],
        }],
      },
      statusLine: {
        type: "command",
        command: "node \"$CLAUDE_PROJECT_DIR/.claude/hooks/bob-statusline.js\"",
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
    // Migration shim rewrites the legacy `bountyagent` key to `hacker-bob`.
    assert.ok(mcp.mcpServers["hacker-bob"]);
    assert.ok(!mcp.mcpServers.bountyagent, "migration shim must remove legacy bountyagent server key");

    const settings = JSON.parse(fs.readFileSync(path.join(workspace, ".claude", "settings.json"), "utf8"));
    const settingsText = JSON.stringify(settings);
    assert.match(settingsText, /\$\{CLAUDE_PROJECT_DIR:-\$PWD\}/);
    assert.doesNotMatch(settingsText, /\$CLAUDE_PROJECT_DIR(?!:-)/);
    assert.equal(settings.customSetting, true);
    assert.equal(settings.permissions.allow.length, new Set(settings.permissions.allow).size);
    assert.ok(settings.permissions.allow.includes("custom-tool"));
    // Migration shim rewrites mcp__bountyagent__* permission strings to mcp__hacker-bob__*.
    assert.ok(settings.permissions.allow.includes("mcp__hacker-bob__custom_user_tool"));
    assert.ok(!settings.permissions.allow.includes("mcp__bountyagent__custom_user_tool"));
    assert.ok(settings.permissions.allow.includes("mcp__hacker-bob__bob_http_scan"));
    // The pre-migration custom permission is idempotently preserved.
    assert.ok(settings.permissions.allow.includes("mcp__hacker-bob__pre_migration_custom"));
    // Stale legacy permission strings are dropped (both forms).
    assert.ok(!settings.permissions.allow.includes("mcp__bountyagent__bob_merge_wave_handoffs"));
    assert.ok(!settings.permissions.allow.includes("mcp__hacker-bob__bob_merge_wave_handoffs"));
    assert.match(settings.statusLine.command, /\$\{CLAUDE_PROJECT_DIR:-\$PWD\}/);

    const bashEntry = settings.hooks.PreToolUse.find((entry) => entry.matcher === "Bash");
    assert.ok(bashEntry);
    assert.ok(bashEntry.hooks.some((hook) => hook.command === "echo existing"));
    assert.equal(
      bashEntry.hooks.filter((hook) => /session-write-guard\.sh/.test(hook.command)).length,
      1,
    );
    // Edit/MultiEdit must route through the write guard too — otherwise Edit is
    // an unguarded write path to MCP-owned/audit-graded session artifacts.
    const editEntry = settings.hooks.PreToolUse.find((entry) => entry.matcher === "Edit|MultiEdit");
    assert.ok(editEntry, "Edit|MultiEdit guard matcher must survive the merge");
    assert.equal(
      editEntry.hooks.filter((hook) => /session-write-guard\.sh/.test(hook.command)).length,
      1,
    );
    // The write-confirm gate matcher ships in the canonical source settings and merges into an
    // existing target exactly once (deduped), pointing at the bob-http-write-confirm.sh hook.
    const scanEntries = settings.hooks.PreToolUse.filter((entry) => entry.matcher === "mcp__hacker-bob__bob_http_scan");
    assert.equal(scanEntries.length, 1);
    assert.equal(
      scanEntries[0].hooks.filter((hook) => /bob-http-write-confirm\.sh/.test(hook.command)).length,
      1,
    );
    const stopEntry = settings.hooks.SubagentStop.find((entry) => entry.matcher === "evaluator-agent");
    assert.ok(stopEntry);
    assert.ok(stopEntry.hooks.some((hook) => hook.command === "echo existing stop"));
    assert.equal(
      stopEntry.hooks.filter((hook) => /agent-run-stop\.js/.test(hook.command)).length,
      1,
    );
    const sessionEntry = settings.hooks.SessionStart.find((entry) => entry.matcher === "startup");
    assert.ok(sessionEntry);
    assert.ok(sessionEntry.hooks.some((hook) => hook.command === "echo existing session"));
    assert.equal(
      sessionEntry.hooks.filter((hook) => /bob-check-update\.js/.test(hook.command)).length,
      1,
    );
    assert.ok(fs.existsSync(path.join(workspace, ".hacker-bob", "knowledge", "evaluator-techniques.json")));
    assert.ok(fs.existsSync(path.join(workspace, ".hacker-bob", "bypass-tables", "rest-api.txt")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "knowledge", "evaluator-techniques.json")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "bypass-tables", "rest-api.txt")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-update-lib.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-update.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-export.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-evaluate.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "evaluate.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "status.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "debug.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "update.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagent", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagentstatus", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagentdebug", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bob-hunt", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-evaluate-runner", "SKILL.md")));
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
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-lifecycle-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-home-"));
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
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bob-evaluate-runner", "SKILL.md")));

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

test("reinstall REFRESHES a stale Bob runtime file but preserves user-owned mcp/ files", () => {
  // Two contracts at once:
  //  - REFRESH (CodeRabbit/glm round-5): the actual bug was a FROZEN browser-driver.js. copyFile
  //    overwrites, so a reinstall must replace a stale driver with the current source — assert the
  //    seeded-stale content is gone, not just that the file exists.
  //  - PRESERVE (Codex/glm round-4): the installer must NEVER delete a top-level mcp/*.js it did not
  //    place — the target is the user's project. (An earlier "converge to the manifest" cleanup deleted
  //    by negation, which would destroy user files; reverted.)
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-userfile-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });
  const install = () => execFileSync(process.execPath, [CLI, "install", workspace], {
    cwd: ROOT,
    env: { ...process.env, HOME: tempHome },
    stdio: "pipe",
  });
  try {
    install();
    const userFile = path.join(workspace, "mcp", "my-own-mcp-thing.js");
    fs.writeFileSync(userFile, "// a file the user placed in their own mcp/ dir\n");
    const driver = path.join(workspace, "mcp", "browser-driver.js");
    const staleMarker = "// STALE driver from an older install — must be overwritten on reinstall\n";
    fs.writeFileSync(driver, staleMarker);
    install(); // reinstall over the existing workspace
    assert.ok(fs.existsSync(userFile), "reinstall must NOT delete a top-level mcp/ file Bob did not place");
    const refreshed = fs.readFileSync(driver, "utf8");
    assert.notEqual(refreshed, staleMarker, "reinstall must overwrite a stale browser-driver.js (the frozen-driver bug)");
    assert.equal(refreshed, fs.readFileSync(path.join(ROOT, "mcp", "browser-driver.js"), "utf8"),
      "reinstall must refresh browser-driver.js to the current source version");
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("dev-sync.sh copies every top-level mcp/ runtime file in the manifest", () => {
  // agy round-5: dev-sync.sh's explicit cp list can drift from MCP_TOP_LEVEL_RUNTIME_FILES. Rather than
  // couple dev-sync to the install.js require-graph at runtime (reverted in round 4 — fragile + a
  // single-quote-path hazard), pin the two with a TEST: every manifest runtime file must appear as a
  // dev-sync cp target, so adding a runtime file to the manifest without updating dev-sync fails CI.
  const { MCP_TOP_LEVEL_RUNTIME_FILES } = require("../scripts/install.js");
  const devSync = fs.readFileSync(path.join(ROOT, "dev-sync.sh"), "utf8");
  for (const name of MCP_TOP_LEVEL_RUNTIME_FILES) {
    assert.ok(devSync.includes(`mcp/${name}`),
      `dev-sync.sh must copy top-level mcp/${name} (keep its cp list in step with MCP_TOP_LEVEL_RUNTIME_FILES)`);
  }
});

test("codex adapter installs direct skills and doctor checks MCP wiring", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-codex-adapter-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-home-"));
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
    assert.equal(install.skills, 6);
    assert.equal(install.commands, 6);
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".codex-plugin", "plugin.json")));
    const manifest = JSON.parse(fs.readFileSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".codex-plugin", "plugin.json"), "utf8"));
    assert.equal(Object.prototype.hasOwnProperty.call(manifest, "skills"), false);
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-status", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-debug", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-update", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-export", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-egress", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "skills", "evaluate", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "skills", "hacker-bob-evaluate", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(tempHome, ".codex", "skills", "hacker-bob-evaluate", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-evaluate.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-export.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-egress.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".agents", "plugins", "marketplace.json")));

    const mcp = JSON.parse(fs.readFileSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".mcp.json"), "utf8"));
    assert.deepEqual(mcp.mcpServers["hacker-bob"], {
      command: "node",
      args: [path.join(workspace, "mcp", "server.js")],
    });
    assert.ok(!mcp.mcpServers.bountyagent);

    const doctor = CODEX_ADAPTER.doctor({ targetAbs: workspace });
    assert.equal(doctor.ok, true);
    assert.ok(doctor.checks.some((check) => check.id === "codex_plugin_manifest" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "codex_global_skills" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "codex_plugin_skills_clean" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "codex_plugin_mcp" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "codex_plugin_commands" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "codex_plugin_marketplace" && check.status === "ok"));

    const dryRun = CODEX_ADAPTER.uninstall({ sourceRoot: ROOT, targetAbs: workspace, dryRun: true });
    assert.equal(dryRun.dry_run, true);
    assert.ok(dryRun.actions.some((action) => action.path === path.join(tempHome, ".codex", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(dryRun.actions.some((action) => action.path === path.join(".codex", "plugins", "hacker-bob", ".mcp.json")));
    assert.ok(dryRun.actions.some((action) => action.path === path.join(".agents", "plugins", "marketplace.json")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".mcp.json")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-evaluate", "SKILL.md")));

    const removed = CODEX_ADAPTER.uninstall({ sourceRoot: ROOT, targetAbs: workspace, dryRun: false });
    assert.equal(removed.dry_run, false);
    assert.ok(!fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-export", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-egress", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".mcp.json")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-evaluate.md")));
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

test("kimi adapter installs skills, registers the hacker-bob MCP key, and doctor/uninstall round-trip", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-kimi-adapter-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });
  const serverPath = path.join(workspace, "mcp", "server.js");
  // Redirect the Kimi home (config.toml) into the temp dir so the install never
  // mutates the developer's real ~/.kimi — mirrors the Codex CODEX_HOME override.
  const originalKimiShare = process.env.KIMI_SHARE_DIR;
  process.env.KIMI_SHARE_DIR = path.join(tempHome, ".kimi");
  const cfgPath = path.join(tempHome, ".kimi", "config.toml");

  try {
    // Base install lays down the shared runtime (mcp/server.js); then exercise
    // the Kimi adapter methods directly, mirroring the Codex adapter test.
    execFileSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });

    const install = KIMI_ADAPTER.install({
      sourceRoot: ROOT,
      targetAbs: workspace,
      serverPath,
      manifest: { version: PACKAGE_VERSION, name: "hacker-bob" },
    });
    assert.equal(install.skills, 6);
    assert.equal(install.hooks, 2);
    assert.ok(install.kimiDir);

    // PreToolUse guard scripts copied + executable; scope-guard.sh (no-op) swept.
    for (const hook of ["session-write-guard.sh", "session-read-guard.sh"]) {
      const hp = path.join(workspace, ".kimi", "hooks", hook);
      assert.ok(fs.existsSync(hp), `${hook} must be installed`);
      assert.ok((fs.statSync(hp).mode & 0o111) !== 0, `${hook} must be executable`);
    }
    assert.ok(!fs.existsSync(path.join(workspace, ".kimi", "hooks", "scope-guard.sh")),
      "no-op scope-guard.sh must not be installed");

    // The generated allow/deny manifest lands beside the guards (non-executable).
    const manifestPath = path.join(workspace, ".kimi", "hooks", "write-guard-tables.json");
    assert.ok(fs.existsSync(manifestPath), "write-guard-tables.json must be copied beside the guards");
    assert.equal(fs.statSync(manifestPath).mode & 0o111, 0, "manifest must not be executable");

    // ~/.kimi/config.toml registered, one Bob block, points at THIS project.
    assert.ok(fs.existsSync(cfgPath), "kimi config.toml must be created/updated");
    let cfg = fs.readFileSync(cfgPath, "utf8");
    assert.match(cfg, /\[\[hooks\]\]/);
    assert.match(cfg, /event = "PreToolUse"/);
    assert.ok(cfg.includes(path.join(workspace, ".kimi", "hooks", "session-write-guard.sh")));
    assert.ok(cfg.includes(path.join(workspace, ".kimi", "hooks", "session-read-guard.sh")));
    assert.equal((cfg.match(/# >>> hacker-bob managed hooks/g) || []).length, 1,
      "exactly one Bob hook block");

    // Idempotent + merge-not-clobber: seed an operator hook, reinstall, assert
    // preserved & no duplicate Bob block.
    fs.writeFileSync(cfgPath, `[[hooks]]\nevent = "Stop"\ncommand = "echo operator"\n\n${cfg}`);
    KIMI_ADAPTER.install({ sourceRoot: ROOT, targetAbs: workspace, serverPath, manifest: { version: PACKAGE_VERSION, name: "hacker-bob" } });
    cfg = fs.readFileSync(cfgPath, "utf8");
    assert.ok(cfg.includes('command = "echo operator"'), "operator hook preserved across reinstall");
    assert.equal((cfg.match(/# >>> hacker-bob managed hooks/g) || []).length, 1,
      "reinstall must not duplicate the Bob block");
    for (const skill of ["bob-evaluate", "bob-status", "bob-debug", "bob-update", "bob-export", "bob-egress"]) {
      assert.ok(fs.existsSync(path.join(workspace, ".kimi", "skills", skill, "SKILL.md")), `${skill} SKILL.md missing`);
    }
    assert.ok(fs.existsSync(path.join(workspace, ".kimi", "bob", "VERSION")));
    assert.ok(fs.existsSync(path.join(workspace, ".kimi", "bob", "install.json")));

    // v2.0 server key: must be the canonical `hacker-bob`, never the legacy
    // `bountyagent` (CHANGELOG v2.0 + docs/TROUBLESHOOTING.md).
    const mcp = JSON.parse(fs.readFileSync(path.join(workspace, ".kimi", "mcp.json"), "utf8"));
    assert.deepEqual(mcp.mcpServers["hacker-bob"], { command: "node", args: [serverPath] });
    assert.ok(!mcp.mcpServers.bountyagent, "fresh Kimi install must not emit the legacy bountyagent key");
    assert.ok(mcp.mcpServers.brutalist, "Kimi install registers the optional brutalist server");

    const doctor = KIMI_ADAPTER.doctor({ targetAbs: workspace });
    assert.equal(doctor.ok, true);
    assert.ok(doctor.checks.some((check) => check.id === "kimi_installed_version" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "kimi_install_metadata" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "kimi_skills" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "kimi_mcp_server_config" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "kimi_mcp_brutalist_optional"));
    assert.ok(doctor.checks.some((check) => check.id === "kimi_cli_on_path"));
    assert.ok(doctor.checks.some((check) => check.id === "kimi_hook_files" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "kimi_hook_modes" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "kimi_hook_manifest" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "kimi_hook_registration" && check.status === "ok"));
    // The best-effort caveat must always surface (warn never fails doctor).
    assert.ok(doctor.checks.some((check) => check.id === "kimi_hook_best_effort" && check.status === "warn"));
    // No cross-adapter check leakage.
    assert.ok(!doctor.checks.some((check) => check.id.startsWith("claude_") || check.id.startsWith("codex_")));

    // Legacy migration: a Bob-managed v1.x `bountyagent` entry is rewritten to
    // `hacker-bob` on reinstall, preserving operator-owned sibling servers.
    fs.writeFileSync(path.join(workspace, ".kimi", "mcp.json"), `${JSON.stringify({
      mcpServers: {
        bountyagent: { command: "node", args: [serverPath] },
        operator: { command: "node", args: ["sibling.js"] },
      },
    }, null, 2)}\n`);
    // Seed stale skill dirs from a prior build (bob-hunt v1, bob-evaluate-runner
    // interim misname). A normal reinstall/update must sweep them so old prompts
    // and tool names are never left exposed beside the current bob-evaluate
    // skill — parity with the Codex and Claude install-time legacy sweep.
    for (const legacySkill of ["bob-evaluate-runner", "bob-hunt"]) {
      fs.mkdirSync(path.join(workspace, ".kimi", "skills", legacySkill), { recursive: true });
      fs.writeFileSync(path.join(workspace, ".kimi", "skills", legacySkill, "SKILL.md"), `# stale ${legacySkill}\n`);
    }
    KIMI_ADAPTER.install({ sourceRoot: ROOT, targetAbs: workspace, serverPath, manifest: { version: PACKAGE_VERSION, name: "hacker-bob" } });
    const migrated = JSON.parse(fs.readFileSync(path.join(workspace, ".kimi", "mcp.json"), "utf8"));
    assert.ok(migrated.mcpServers["hacker-bob"], "migration must add the hacker-bob key");
    assert.ok(!migrated.mcpServers.bountyagent, "migration must drop the legacy bountyagent key");
    assert.ok(migrated.mcpServers.operator, "migration must preserve operator-owned sibling servers");
    // The reinstall swept the legacy skill dirs while keeping current skills.
    for (const legacySkill of ["bob-evaluate-runner", "bob-hunt"]) {
      assert.ok(
        !fs.existsSync(path.join(workspace, ".kimi", "skills", legacySkill, "SKILL.md")),
        `${legacySkill} legacy skill must be swept on reinstall`,
      );
    }
    assert.ok(
      fs.existsSync(path.join(workspace, ".kimi", "skills", "bob-evaluate", "SKILL.md")),
      "current bob-evaluate skill must survive the legacy sweep",
    );

    const dryRun = KIMI_ADAPTER.uninstall({ sourceRoot: ROOT, targetAbs: workspace, dryRun: true });
    assert.equal(dryRun.dry_run, true);
    assert.ok(dryRun.actions.some((action) => action.path === path.join(".kimi", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(dryRun.actions.some((action) => action.path === path.join(".kimi", "mcp.json")));
    assert.ok(fs.existsSync(path.join(workspace, ".kimi", "skills", "bob-evaluate", "SKILL.md")));

    const removed = KIMI_ADAPTER.uninstall({ sourceRoot: ROOT, targetAbs: workspace, dryRun: false });
    assert.equal(removed.dry_run, false);
    for (const skill of ["bob-evaluate", "bob-export", "bob-egress"]) {
      assert.ok(!fs.existsSync(path.join(workspace, ".kimi", "skills", skill, "SKILL.md")), `${skill} should be removed`);
    }
    // `.kimi/` is a Bob-owned directory (it is created by the Kimi install and
    // listed in managedFiles), so uninstall removes the whole `.kimi/mcp.json`.
    assert.ok(!fs.existsSync(path.join(workspace, ".kimi", "mcp.json")), ".kimi/mcp.json should be removed on uninstall");

    // Hook isolation: uninstall removed the Bob block (config preserved because
    // the operator hook keeps it non-empty) and the copied guard scripts.
    const afterConfig = fs.readFileSync(cfgPath, "utf8");
    assert.ok(!afterConfig.includes("# >>> hacker-bob managed hooks"), "Bob hook block removed on uninstall");
    assert.ok(afterConfig.includes('command = "echo operator"'), "operator hook survives uninstall");
    assert.ok(!fs.existsSync(path.join(workspace, ".kimi", "hooks", "session-write-guard.sh")), "guard removed on uninstall");
  } finally {
    if (originalKimiShare === undefined) delete process.env.KIMI_SHARE_DIR;
    else process.env.KIMI_SHARE_DIR = originalKimiShare;
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("kimi hook registration is shell-injection-safe and uninstall is install-scoped", () => {
  // #2: the generated PreToolUse `command` is run as a shell command, so the
  // hook path must be single-quoted (shell-inert) — $(), backticks, $VAR in the
  // install path must NOT expand at hook runtime.
  const malicious = "/tmp/proj-$(touch /tmp/PWNED)-`id`-$HOME";
  const block = KIMI_ADAPTER.renderKimiHookBlock(malicious);
  const writePath = path.join(malicious, ".kimi", "hooks", "session-write-guard.sh");
  assert.ok(block.includes(`'${writePath}'`),
    "hook path must be single-quoted in the command so the shell cannot expand it");
  // shellSingleQuote escapes an embedded single quote as '\'' (close/escape/reopen).
  assert.equal(KIMI_ADAPTER.shellSingleQuote("a'b"), "'a'\\''b'");

  // #7a: kimiHookBlockMatchesTarget identifies the OWNING install only.
  const blockA = KIMI_ADAPTER.renderKimiHookBlock("/tmp/projA");
  assert.equal(KIMI_ADAPTER.kimiHookBlockMatchesTarget(blockA, "/tmp/projA"), true);
  assert.equal(KIMI_ADAPTER.kimiHookBlockMatchesTarget(blockA, "/tmp/projB"), false);

  const originalKimiShare = process.env.KIMI_SHARE_DIR;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-kimi-uninstall-"));
  try {
    // #7b: uninstalling project A must NOT remove a global Bob block owned by B.
    const kimiDir = path.join(tempHome, ".kimi");
    fs.mkdirSync(kimiDir, { recursive: true });
    process.env.KIMI_SHARE_DIR = kimiDir;
    const cfgPath = path.join(kimiDir, "config.toml");
    fs.writeFileSync(cfgPath, `${KIMI_ADAPTER.renderKimiHookBlock("/tmp/projB")}\n`);

    const rA = KIMI_ADAPTER.uninstall({ sourceRoot: ROOT, targetAbs: "/tmp/projA", dryRun: false });
    assert.ok(fs.readFileSync(cfgPath, "utf8").includes("# >>> hacker-bob managed hooks"),
      "B's global hook block must survive A's uninstall");
    assert.ok(rA.skipped.some((s) => /different project/.test(s.reason || "")),
      "uninstall must report skipping a block owned by a different project");

    // #7c: a symlinked config must not be followed/rewritten on uninstall.
    const realCfg = path.join(tempHome, "real-config.toml");
    fs.writeFileSync(realCfg, `${KIMI_ADAPTER.renderKimiHookBlock("/tmp/projB")}\n`);
    const symHome = path.join(tempHome, "symhome", ".kimi");
    fs.mkdirSync(symHome, { recursive: true });
    fs.symlinkSync(realCfg, path.join(symHome, "config.toml"));
    process.env.KIMI_SHARE_DIR = symHome;
    const rSym = KIMI_ADAPTER.uninstall({ sourceRoot: ROOT, targetAbs: "/tmp/projB", dryRun: false });
    assert.ok(fs.readFileSync(realCfg, "utf8").includes("# >>> hacker-bob managed hooks"),
      "symlinked config target must be left intact");
    assert.ok(rSym.skipped.some((s) => /symlink/.test(s.reason || "")),
      "uninstall must report refusing to rewrite a symlinked config");
  } finally {
    if (originalKimiShare === undefined) delete process.env.KIMI_SHARE_DIR;
    else process.env.KIMI_SHARE_DIR = originalKimiShare;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("detectInstalledAdapterIds recognizes an installed kimi layout (claude/codex parity)", () => {
  // Locks the fix for reinstall/update/uninstall auto-detection: a project that
  // has a kimi install but no neutral install.json metadata must still resolve
  // to the kimi adapter via filesystem detection, exactly like claude and codex.
  const { detectInstalledAdapterIds } = require("../scripts/install.js");
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-detect-adapters-"));
  try {
    const viaVersion = path.join(tempRoot, "kimi-version");
    fs.mkdirSync(path.join(viaVersion, ".kimi", "bob"), { recursive: true });
    fs.writeFileSync(path.join(viaVersion, ".kimi", "bob", "VERSION"), `${PACKAGE_VERSION}\n`);
    assert.deepEqual(detectInstalledAdapterIds(viaVersion), ["kimi"]);

    const viaSkill = path.join(tempRoot, "kimi-skill");
    fs.mkdirSync(path.join(viaSkill, ".kimi", "skills", "bob-evaluate"), { recursive: true });
    fs.writeFileSync(path.join(viaSkill, ".kimi", "skills", "bob-evaluate", "SKILL.md"), "x\n");
    assert.deepEqual(detectInstalledAdapterIds(viaSkill), ["kimi"]);

    const codexLayout = path.join(tempRoot, "codex");
    fs.mkdirSync(path.join(codexLayout, ".codex", "plugins", "hacker-bob"), { recursive: true });
    assert.deepEqual(detectInstalledAdapterIds(codexLayout), ["codex"]);

    const claudeLayout = path.join(tempRoot, "claude");
    fs.mkdirSync(path.join(claudeLayout, ".claude", "bob"), { recursive: true });
    fs.writeFileSync(path.join(claudeLayout, ".claude", "bob", "VERSION"), `${PACKAGE_VERSION}\n`);
    assert.deepEqual(detectInstalledAdapterIds(claudeLayout), ["claude"]);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("generic MCP adapter installs only MCP config and prompt docs", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-generic-mcp-adapter-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-home-"));
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
    assert.deepEqual(mcp.mcpServers["hacker-bob"], {
      command: "node",
      args: [path.join(workspace, "mcp", "server.js")],
    });
    assert.ok(!mcp.mcpServers.bountyagent);

    const doctor = GENERIC_MCP_ADAPTER.doctor({ targetAbs: workspace });
    assert.equal(doctor.ok, true);
    assert.ok(doctor.checks.some((check) => check.id === "generic_mcp_server" && check.status === "ok"));

    const removed = GENERIC_MCP_ADAPTER.uninstall({ targetAbs: workspace, dryRun: false });
    assert.equal(removed.dry_run, false);
    assert.ok(!fs.existsSync(path.join(workspace, ".hacker-bob", "generic-mcp", "hacker-bob.md")));
    const after = JSON.parse(fs.readFileSync(path.join(workspace, ".mcp.json"), "utf8"));
    assert.ok(after.mcpServers.existing);
    assert.ok(!after.mcpServers["hacker-bob"]);
    assert.ok(!after.mcpServers.bountyagent);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("migration shim rewrites v1.x bountyagent server key + permission strings to hacker-bob", () => {
  // The shim in scripts/merge-claude-config.js powers the v2.0.0 rename for
  // existing installs. This test exercises it directly (unit-level), then
  // re-runs it on the rewritten output to prove idempotency.
  const {
    migrateLegacyMcp,
    migrateLegacySettings,
    migrateLegacyServerKey,
    rewriteLegacyPermissionString,
  } = require("../scripts/merge-claude-config.js");

  // Sanity: prefix rewriter handles legacy/canonical/unknown strings.
  assert.equal(
    rewriteLegacyPermissionString("mcp__bountyagent__bob_http_scan"),
    "mcp__hacker-bob__bob_http_scan",
  );
  assert.equal(
    rewriteLegacyPermissionString("mcp__hacker-bob__bob_http_scan"),
    "mcp__hacker-bob__bob_http_scan",
  );
  assert.equal(rewriteLegacyPermissionString("custom-tool"), "custom-tool");
  assert.equal(rewriteLegacyPermissionString(undefined), undefined);

  // Pure .mcp.json migration: legacy key is renamed and operator entries
  // unrelated to the rename are preserved.
  const v1Mcp = {
    mcpServers: {
      bountyagent: {
        command: "node",
        args: ["/legacy/path/mcp/server.js"],
      },
      operator: { command: "node", args: ["op.js"] },
    },
  };
  const mcpResult = migrateLegacyMcp(v1Mcp);
  assert.equal(mcpResult.migrated, true);
  assert.deepEqual(mcpResult.value.mcpServers["hacker-bob"], {
    command: "node",
    args: ["/legacy/path/mcp/server.js"],
  });
  assert.ok(!("bountyagent" in mcpResult.value.mcpServers));
  assert.deepEqual(mcpResult.value.mcpServers.operator, { command: "node", args: ["op.js"] });

  // Idempotency: re-running migration on already-migrated input is a no-op.
  const idempotentMcp = migrateLegacyMcp(mcpResult.value);
  assert.equal(idempotentMcp.migrated, false);
  assert.deepEqual(idempotentMcp.value, mcpResult.value);

  // Both keys present: legacy is dropped, canonical is preserved untouched.
  const dualKeyMcp = {
    mcpServers: {
      bountyagent: { command: "node", args: ["legacy.js"] },
      "hacker-bob": { command: "node", args: ["canonical.js"] },
    },
  };
  const dualResult = migrateLegacyMcp(dualKeyMcp);
  assert.equal(dualResult.migrated, true);
  assert.deepEqual(dualResult.value.mcpServers["hacker-bob"], { command: "node", args: ["canonical.js"] });
  assert.ok(!("bountyagent" in dualResult.value.mcpServers));

  // Pure settings.json migration: legacy permission strings rewritten, others
  // preserved.
  const v1Settings = {
    permissions: {
      allow: [
        "mcp__bountyagent__bob_http_scan",
        "mcp__bountyagent__custom_user_tool",
        "Read",
        "mcp__hacker-bob__pre_migration_custom",
      ],
    },
    customSetting: true,
  };
  const settingsResult = migrateLegacySettings(v1Settings);
  assert.equal(settingsResult.migrated, true);
  assert.ok(settingsResult.value.permissions.allow.includes("mcp__hacker-bob__bob_http_scan"));
  assert.ok(settingsResult.value.permissions.allow.includes("mcp__hacker-bob__custom_user_tool"));
  assert.ok(settingsResult.value.permissions.allow.includes("Read"));
  // Idempotency: pre-existing canonical permission survives without duplication.
  assert.ok(settingsResult.value.permissions.allow.includes("mcp__hacker-bob__pre_migration_custom"));
  assert.equal(
    settingsResult.value.permissions.allow.length,
    new Set(settingsResult.value.permissions.allow).size,
    "migration must dedupe permission strings",
  );
  assert.equal(settingsResult.value.customSetting, true, "unrelated settings preserved");
  assert.ok(!settingsResult.value.permissions.allow.some((p) => p.startsWith("mcp__bountyagent__")));

  // Idempotency: re-migration is a no-op.
  const idempotentSettings = migrateLegacySettings(settingsResult.value);
  assert.equal(idempotentSettings.migrated, false);
  assert.deepEqual(idempotentSettings.value, settingsResult.value);

  // No-op cases.
  assert.equal(migrateLegacyMcp({}).migrated, false);
  assert.equal(migrateLegacyMcp({ mcpServers: { other: {} } }).migrated, false);
  assert.equal(migrateLegacySettings({}).migrated, false);
  assert.equal(migrateLegacySettings({ permissions: { allow: ["Read"] } }).migrated, false);

  // Combined entry point logs and reports overall migration status.
  const captured = [];
  const combined = migrateLegacyServerKey({
    mcp: v1Mcp,
    settings: v1Settings,
    logger: (msg) => captured.push(msg),
  });
  assert.equal(combined.migrated, true);
  assert.equal(captured.length, 1);
  assert.match(captured[0], /bountyagent\s*->\s*hacker-bob/);
  assert.match(captured[0], /\.mcp\.json/);
  assert.match(captured[0], /\.claude\/settings\.json/);
});

test("merge-claude-config CLI auto-migrates a v1.x .mcp.json + settings.json layout", () => {
  // Round-trip the migration shim through the CLI entrypoint. This exercises
  // the same code path install/update uses on existing v1.x workspaces.
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-migration-shim-"));
  const workspace = path.join(tempRoot, "v1-install");
  fs.mkdirSync(path.join(workspace, ".claude"), { recursive: true });

  try {
    const legacyServerPath = path.join(workspace, "mcp", "server.js");
    fs.writeFileSync(path.join(workspace, ".mcp.json"), `${JSON.stringify({
      mcpServers: {
        bountyagent: { command: "node", args: [legacyServerPath] },
        operatorService: { command: "node", args: ["sidecar.js"] },
      },
    }, null, 2)}\n`);
    fs.writeFileSync(path.join(workspace, ".claude", "settings.json"), `${JSON.stringify({
      permissions: {
        allow: [
          "mcp__bountyagent__bob_http_scan",
          "mcp__bountyagent__custom_user_tool",
          "custom-allowlisted",
        ],
      },
      customSetting: true,
    }, null, 2)}\n`);

    const merge = require("../scripts/merge-claude-config.js");
    const mcp = JSON.parse(fs.readFileSync(path.join(workspace, ".mcp.json"), "utf8"));
    const settings = JSON.parse(fs.readFileSync(path.join(workspace, ".claude", "settings.json"), "utf8"));
    const migrated = merge.migrateLegacyServerKey({ mcp, settings });
    assert.equal(migrated.migrated, true);

    // The merge step then runs over the migrated config (idempotent for the
    // rename surfaces).
    const finalMcp = merge.mergeMcp(migrated.mcp, legacyServerPath);
    assert.ok(finalMcp.mcpServers["hacker-bob"]);
    assert.ok(!finalMcp.mcpServers.bountyagent);
    assert.deepEqual(finalMcp.mcpServers.operatorService, { command: "node", args: ["sidecar.js"] });
    assert.ok(finalMcp.mcpServers.brutalist);

    const finalSettings = merge.mergeSettings(migrated.settings, {
      permissions: { allow: ["mcp__hacker-bob__bob_record_candidate_claim"] },
      hooks: {},
    });
    assert.ok(finalSettings.permissions.allow.includes("mcp__hacker-bob__bob_http_scan"));
    assert.ok(finalSettings.permissions.allow.includes("mcp__hacker-bob__custom_user_tool"));
    assert.ok(finalSettings.permissions.allow.includes("mcp__hacker-bob__bob_record_candidate_claim"));
    assert.ok(finalSettings.permissions.allow.includes("custom-allowlisted"));
    assert.equal(finalSettings.customSetting, true);
    assert.ok(!finalSettings.permissions.allow.some((p) => p.startsWith("mcp__bountyagent__")));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});
