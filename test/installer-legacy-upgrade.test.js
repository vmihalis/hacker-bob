"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  LEGACY_AGENT_FILES,
  LEGACY_HOOK_COMMAND_REWRITES,
  LEGACY_HOOK_FILES,
} = require("../adapters/claude/index.js");
const {
  migrateLegacyHookCommands,
  rewriteLegacyHookCommand,
} = require("../scripts/merge-claude-config.js");

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "bin", "hacker-bob.js");

const PROJECT_DIR_EXPR = "${CLAUDE_PROJECT_DIR:-$PWD}";

function buildV1Settings() {
  // A representative v1.x settings.json: SubagentStop hooks point at the
  // pre-rename `hunter-subagent-stop.js`, statusLine.command points at the
  // pre-rename `bounty-statusline.js`, custom operator entries are present.
  return {
    permissions: {
      allow: [
        "Read",
        "Bash(echo *)",
        "mcp__bountyagent__bob_http_scan",
        "mcp__bountyagent__custom_user_tool",
      ],
    },
    hooks: {
      PreToolUse: [
        {
          matcher: "Bash",
          hooks: [
            { type: "command", command: "echo existing bash", timeout: 1 },
          ],
        },
      ],
      SubagentStop: [
        {
          matcher: "evaluator-agent",
          hooks: [
            {
              type: "command",
              command: `node "${PROJECT_DIR_EXPR}/.claude/hooks/hunter-subagent-stop.js"`,
              timeout: 10,
            },
          ],
        },
        {
          matcher: "evaluator-evm-agent",
          hooks: [
            {
              type: "command",
              command: `node "${PROJECT_DIR_EXPR}/.claude/hooks/hunter-subagent-stop.js"`,
              timeout: 10,
            },
          ],
        },
      ],
    },
    statusLine: {
      type: "command",
      command: `node "${PROJECT_DIR_EXPR}/.claude/hooks/bounty-statusline.js"`,
    },
    customSetting: true,
  };
}

function setupV1Workspace(workspace) {
  fs.mkdirSync(path.join(workspace, ".claude", "agents"), { recursive: true });
  fs.mkdirSync(path.join(workspace, ".claude", "hooks"), { recursive: true });
  // 8 legacy agent files
  for (const legacyAgent of LEGACY_AGENT_FILES) {
    fs.writeFileSync(path.join(workspace, ".claude", "agents", legacyAgent), `# legacy ${legacyAgent}\n`);
  }
  // 2 legacy hook files
  for (const legacyHook of LEGACY_HOOK_FILES) {
    fs.writeFileSync(path.join(workspace, ".claude", "hooks", legacyHook), "// legacy\n");
  }
  // Legacy .mcp.json (covered by existing migration but included for completeness)
  fs.writeFileSync(path.join(workspace, ".mcp.json"), `${JSON.stringify({
    mcpServers: {
      bountyagent: {
        command: "node",
        args: [path.join(workspace, "mcp", "server.js")],
      },
    },
  }, null, 2)}\n`);
  // Legacy settings.json with stale hook command references
  fs.writeFileSync(
    path.join(workspace, ".claude", "settings.json"),
    `${JSON.stringify(buildV1Settings(), null, 2)}\n`,
  );
}

function readSettings(workspace) {
  return JSON.parse(fs.readFileSync(path.join(workspace, ".claude", "settings.json"), "utf8"));
}

function readMcp(workspace) {
  return JSON.parse(fs.readFileSync(path.join(workspace, ".mcp.json"), "utf8"));
}

function runInstall(workspace, tempHome) {
  execFileSync(process.execPath, [CLI, "install", workspace], {
    cwd: ROOT,
    env: { ...process.env, HOME: tempHome },
    stdio: "pipe",
  });
}

test("rewriteLegacyHookCommand swaps embedded hook filenames and is idempotent", () => {
  // hunter-subagent-stop.js -> agent-run-stop.js
  const v1Stop = `node "${PROJECT_DIR_EXPR}/.claude/hooks/hunter-subagent-stop.js"`;
  const rewrittenStop = rewriteLegacyHookCommand(v1Stop);
  assert.equal(rewrittenStop, `node "${PROJECT_DIR_EXPR}/.claude/hooks/agent-run-stop.js"`);
  assert.equal(rewriteLegacyHookCommand(rewrittenStop), rewrittenStop, "idempotent");

  // bounty-statusline.js -> bob-statusline.js
  const v1Status = `node "${PROJECT_DIR_EXPR}/.claude/hooks/bounty-statusline.js"`;
  const rewrittenStatus = rewriteLegacyHookCommand(v1Status);
  assert.equal(rewrittenStatus, `node "${PROJECT_DIR_EXPR}/.claude/hooks/bob-statusline.js"`);
  assert.equal(rewriteLegacyHookCommand(rewrittenStatus), rewrittenStatus, "idempotent");

  // No-op on canonical names.
  assert.equal(
    rewriteLegacyHookCommand("echo unrelated"),
    "echo unrelated",
  );
  assert.equal(rewriteLegacyHookCommand(undefined), undefined);
});

test("migrateLegacyHookCommands dedupes when legacy and canonical entries coexist", () => {
  // If both a legacy-pointing and a canonical-pointing hook for the same
  // trigger are present, the rewrite + dedupe step collapses to a single
  // canonical entry.
  const input = {
    hooks: {
      SubagentStop: [
        {
          matcher: "evaluator-agent",
          hooks: [
            {
              type: "command",
              command: `node "${PROJECT_DIR_EXPR}/.claude/hooks/hunter-subagent-stop.js"`,
              timeout: 10,
            },
            {
              type: "command",
              command: `node "${PROJECT_DIR_EXPR}/.claude/hooks/agent-run-stop.js"`,
              timeout: 10,
            },
          ],
        },
      ],
    },
  };
  const result = migrateLegacyHookCommands(input);
  assert.equal(result.migrated, true);
  const hooks = result.value.hooks.SubagentStop[0].hooks;
  assert.equal(hooks.length, 1, "duplicate canonical/legacy entries collapse to one");
  assert.match(hooks[0].command, /agent-run-stop\.js/);
});

test("migrateLegacyHookCommands is a no-op when no legacy filenames are present", () => {
  const clean = {
    hooks: {
      SubagentStop: [
        {
          matcher: "evaluator-agent",
          hooks: [
            { type: "command", command: `node "${PROJECT_DIR_EXPR}/.claude/hooks/agent-run-stop.js"`, timeout: 10 },
          ],
        },
      ],
    },
    statusLine: {
      type: "command",
      command: `node "${PROJECT_DIR_EXPR}/.claude/hooks/bob-statusline.js"`,
    },
  };
  const result = migrateLegacyHookCommands(clean);
  assert.equal(result.migrated, false);
  assert.deepEqual(result.value, clean);
});

test("LEGACY_HOOK_COMMAND_REWRITES exposes the same surface from both modules", () => {
  // The list lives in both the adapter (for documentation / external
  // inspection) and the merge shim (for the actual rewrite). They must stay
  // in lockstep.
  const fromMerge = require("../scripts/merge-claude-config.js").LEGACY_HOOK_COMMAND_REWRITES;
  assert.deepEqual(
    LEGACY_HOOK_COMMAND_REWRITES.map((entry) => ({ from: entry.from, to: entry.to })),
    fromMerge.map((entry) => ({ from: entry.from, to: entry.to })),
  );
  assert.ok(LEGACY_HOOK_COMMAND_REWRITES.some((entry) => entry.from === "hunter-subagent-stop.js"));
  assert.ok(LEGACY_HOOK_COMMAND_REWRITES.some((entry) => entry.from === "bounty-statusline.js"));
});

test("installer sweeps v1.x legacy agent/hook files and rewrites stale hook references", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-legacy-upgrade-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-home-"));
  const workspace = path.join(tempRoot, "v1-workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    setupV1Workspace(workspace);

    // Sanity: legacy artifacts exist pre-install.
    for (const legacyAgent of LEGACY_AGENT_FILES) {
      assert.ok(fs.existsSync(path.join(workspace, ".claude", "agents", legacyAgent)), `pre-install ${legacyAgent} fixture`);
    }
    for (const legacyHook of LEGACY_HOOK_FILES) {
      assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", legacyHook)), `pre-install ${legacyHook} fixture`);
    }
    const preMcp = readMcp(workspace);
    assert.ok(preMcp.mcpServers.bountyagent, "pre-install legacy mcp key");

    runInstall(workspace, tempHome);

    // All 8 legacy agent files are gone.
    for (const legacyAgent of LEGACY_AGENT_FILES) {
      assert.ok(
        !fs.existsSync(path.join(workspace, ".claude", "agents", legacyAgent)),
        `${legacyAgent} should be removed`,
      );
    }
    // Both legacy hook files are gone.
    for (const legacyHook of LEGACY_HOOK_FILES) {
      assert.ok(
        !fs.existsSync(path.join(workspace, ".claude", "hooks", legacyHook)),
        `${legacyHook} should be removed`,
      );
    }

    // SubagentStop hook command points at agent-run-stop.js, not the legacy
    // hunter-subagent-stop.js.
    const settings = readSettings(workspace);
    const settingsText = JSON.stringify(settings);
    assert.doesNotMatch(settingsText, /hunter-subagent-stop\.js/, "stale subagent-stop reference rewritten");
    assert.doesNotMatch(settingsText, /bounty-statusline\.js/, "stale statusline reference rewritten");

    const stopEntry = settings.hooks.SubagentStop.find((entry) => entry.matcher === "evaluator-agent");
    assert.ok(stopEntry, "SubagentStop entry for evaluator-agent preserved");
    assert.ok(
      stopEntry.hooks.some((hook) => /agent-run-stop\.js/.test(hook.command)),
      "stale SubagentStop hook rewritten to canonical agent-run-stop.js",
    );

    // statusLine rewritten to bob-statusline.js.
    assert.match(settings.statusLine.command, /bob-statusline\.js/);

    // .mcp.json server key migrated to hacker-bob.
    const mcp = readMcp(workspace);
    assert.ok(mcp.mcpServers["hacker-bob"], "canonical mcp server key present");
    assert.ok(!mcp.mcpServers.bountyagent, "legacy bountyagent server key removed");

    // Operator-customized state outside the migration surface survives.
    assert.equal(settings.customSetting, true, "unrelated operator settings preserved");
    const bashEntry = settings.hooks.PreToolUse.find((entry) => entry.matcher === "Bash");
    assert.ok(bashEntry, "operator PreToolUse Bash entry preserved");
    assert.ok(
      bashEntry.hooks.some((hook) => hook.command === "echo existing bash"),
      "operator-authored hook command preserved verbatim",
    );

    // Idempotency: re-running install on the post-install state introduces no
    // new churn. Capture relevant artifacts before and after and assert that
    // legacy artifacts remain absent and stale references remain absent.
    runInstall(workspace, tempHome);

    for (const legacyAgent of LEGACY_AGENT_FILES) {
      assert.ok(!fs.existsSync(path.join(workspace, ".claude", "agents", legacyAgent)));
    }
    for (const legacyHook of LEGACY_HOOK_FILES) {
      assert.ok(!fs.existsSync(path.join(workspace, ".claude", "hooks", legacyHook)));
    }
    const settingsAfter = readSettings(workspace);
    const settingsAfterText = JSON.stringify(settingsAfter);
    assert.doesNotMatch(settingsAfterText, /hunter-subagent-stop\.js/);
    assert.doesNotMatch(settingsAfterText, /bounty-statusline\.js/);
    const mcpAfter = readMcp(workspace);
    assert.ok(mcpAfter.mcpServers["hacker-bob"]);
    assert.ok(!mcpAfter.mcpServers.bountyagent);

    // Verify the canonical surfaces shipped during install are still in place
    // (sweep must not collateral-damage current hooks/agents).
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "agent-run-stop.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-statusline.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "agents", "evaluator-agent.md")));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});
