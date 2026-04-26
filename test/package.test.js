const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const COMPAT_ROOT = path.join(ROOT, "packages", "hacker-bob-cc");
const PACKAGE_VERSION = require("../package.json").version;
const COMPAT_VERSION = require("../packages/hacker-bob-cc/package.json").version;

function sourceTreeFiles(relativeDir) {
  const root = path.join(ROOT, relativeDir);
  if (!fs.existsSync(root)) return [];
  const files = [];
  const visit = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        visit(full);
      } else if (entry.isFile()) {
        files.push(path.relative(ROOT, full).split(path.sep).join("/"));
      }
    }
  };
  visit(root);
  return files.sort();
}

function expectedCanonicalFiles() {
  return Array.from(new Set([
    "package.json",
    "README.md",
    "LICENSE",
    "NOTICE",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "DISCLAIMER.md",
    "SECURITY.md",
    "install.sh",
    ...sourceTreeFiles(".hacker-bob"),
    ...sourceTreeFiles(".claude"),
    ...sourceTreeFiles("adapters"),
    ...sourceTreeFiles("bin"),
    ...sourceTreeFiles("docs"),
    ...sourceTreeFiles("mcp"),
    ...sourceTreeFiles("prompts"),
    ...sourceTreeFiles("scripts"),
  ])).sort();
}

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

    assert.equal(pack.name, "hacker-bob");
    assert.equal(pack.version, PACKAGE_VERSION);
    for (const expected of expectedCanonicalFiles()) {
      assert.ok(files.has(expected), `${expected} missing from npm pack output`);
    }

    assert.ok(pack.size < 1500000, `npm pack size ${pack.size} exceeds 1.5 MB threshold`);

    for (const file of files) {
      assert.ok(!file.startsWith("test/"), `${file} should not be packed`);
      assert.ok(!file.startsWith(".github/"), `${file} should not be packed`);
      assert.ok(!file.startsWith("packages/"), `${file} should not be packed in canonical package`);
      assert.notEqual(file, ".claude/hooks/bob-update-lib.js", "hook-local update library should not be packed");
      assert.ok(!file.includes("bounty-agent-sessions"), `${file} should not be packed`);
      assert.ok(!file.includes(".cache/"), `${file} should not be packed`);
    }
  } finally {
    fs.rmSync(npmCache, { recursive: true, force: true });
  }
});

test("compatibility package version matches canonical package", () => {
  assert.equal(COMPAT_VERSION, PACKAGE_VERSION);
});

test("compatibility package packs only wrapper and manifest", () => {
  const npmCache = fs.mkdtempSync(path.join(os.tmpdir(), "bob-compat-npm-cache-"));
  try {
    const output = execFileSync("npm", ["pack", "--dry-run", "--json"], {
      cwd: COMPAT_ROOT,
      env: { ...process.env, npm_config_cache: npmCache },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const [pack] = JSON.parse(output);
    assert.equal(pack.name, "hacker-bob-cc");
    assert.equal(pack.version, PACKAGE_VERSION);
    assert.deepEqual(
      pack.files.map((file) => file.path).sort(),
      ["bin/hacker-bob.js", "package.json"],
    );
    assert.ok(pack.size < 3000, `compatibility pack size ${pack.size} exceeds 3 KB threshold`);
  } finally {
    fs.rmSync(npmCache, { recursive: true, force: true });
  }
});
