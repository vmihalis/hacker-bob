const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");

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

    execFileSync(process.execPath, [
      "-e",
      "const server = require(process.argv[1]); if (!Array.isArray(server.TOOLS)) process.exit(2);",
      installedServer,
    ], { stdio: "pipe" });
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});
