const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const ALIAS_ROOT = path.join(ROOT, "packages", "hacker-bob");
const PACKAGE_VERSION = require("../package.json").version;
const ALIAS_VERSION = require("../packages/hacker-bob/package.json").version;

test("npm package contains runtime surfaces and excludes test/cache artifacts", () => {
  const npmCache = fs.mkdtempSync(path.join(os.tmpdir(), "bob-npm-cache-"));
  try {
    const output = execFileSync("npm", ["pack", "--dry-run", "--json"], {
      cwd: ROOT,
      env: { ...process.env, npm_config_cache: npmCache },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const [pack] = JSON.parse(output);
    const files = new Set(pack.files.map((file) => file.path));

    for (const expected of [
      "package.json",
      "README.md",
      "LICENSE",
      "NOTICE",
      "CHANGELOG.md",
      "install.sh",
      "bin/hacker-bob.js",
      "docs/hacker-bob.png",
      "docs/TROUBLESHOOTING.md",
      "docs/releases/v1.1.0.md",
      ".claude/commands/bob-update.md",
      ".claude/hooks/bob-update.js",
      ".claude/hooks/bob-check-update.js",
      "mcp/server.js",
      "mcp/lib/tools/index.js",
      "scripts/install.js",
      "scripts/lifecycle.js",
      "scripts/merge-claude-config.js",
      "testing/policy-replay/replay.mjs",
      "testing/policy-replay/tune.mjs",
      "testing/policy-replay/cases/sample-hunter-refusal.json",
    ]) {
      assert.ok(files.has(expected), `${expected} missing from npm pack output`);
    }

    assert.ok(pack.size < 1500000, `npm pack size ${pack.size} exceeds 1.5 MB threshold`);

    for (const file of files) {
      assert.ok(!file.startsWith("test/"), `${file} should not be packed`);
      if (file.startsWith("testing/")) {
        assert.ok(
          file.startsWith("testing/policy-replay/"),
          `${file} should not be packed`,
        );
        assert.ok(!file.includes("node_modules"), `${file} should not include node_modules`);
      }
      assert.ok(!file.startsWith(".github/"), `${file} should not be packed`);
      assert.ok(!file.startsWith("packages/"), `${file} should not be packed in canonical package`);
      assert.ok(!file.includes("bounty-agent-sessions"), `${file} should not be packed`);
      assert.ok(!file.includes(".cache/"), `${file} should not be packed`);
    }
  } finally {
    fs.rmSync(npmCache, { recursive: true, force: true });
  }
});

test("alias package version matches canonical package", () => {
  assert.equal(ALIAS_VERSION, PACKAGE_VERSION);
});

test("alias package packs only wrapper and manifest", () => {
  const npmCache = fs.mkdtempSync(path.join(os.tmpdir(), "bob-alias-npm-cache-"));
  try {
    const output = execFileSync("npm", ["pack", "--dry-run", "--json"], {
      cwd: ALIAS_ROOT,
      env: { ...process.env, npm_config_cache: npmCache },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const [pack] = JSON.parse(output);
    assert.equal(pack.name, "hacker-bob");
    assert.equal(pack.version, PACKAGE_VERSION);
    assert.deepEqual(
      pack.files.map((file) => file.path).sort(),
      ["bin/hacker-bob.js", "package.json"],
    );
    assert.ok(pack.size < 3000, `alias pack size ${pack.size} exceeds 3 KB threshold`);
  } finally {
    fs.rmSync(npmCache, { recursive: true, force: true });
  }
});
