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
  assert.match(output, /one Claude Code project directory per command/);
  assert.match(output, /Global npm install only adds this CLI to PATH/);
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
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "update.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-check-update.js")));
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
