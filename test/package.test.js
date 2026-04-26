const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");

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
      ".claude/commands/bob/update.md",
      ".claude/hooks/bob-update.js",
      ".claude/hooks/bob-check-update.js",
      "mcp/server.js",
      "mcp/lib/tools/index.js",
      "scripts/install.js",
      "scripts/merge-claude-config.js",
    ]) {
      assert.ok(files.has(expected), `${expected} missing from npm pack output`);
    }

    for (const file of files) {
      assert.ok(!file.startsWith("test/"), `${file} should not be packed`);
      assert.ok(!file.startsWith(".github/"), `${file} should not be packed`);
      assert.ok(!file.includes("bounty-agent-sessions"), `${file} should not be packed`);
      assert.ok(!file.includes(".cache/"), `${file} should not be packed`);
    }
  } finally {
    fs.rmSync(npmCache, { recursive: true, force: true });
  }
});
