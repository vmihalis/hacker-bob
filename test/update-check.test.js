const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const update = require("../mcp/lib/update-check.js");

function tempWorkspace() {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-update-test-"));
  const workspace = path.join(tempRoot, "workspace");
  const homeDir = path.join(tempRoot, "home");
  fs.mkdirSync(path.join(workspace, ".claude", "bob"), { recursive: true });
  fs.mkdirSync(homeDir, { recursive: true });
  return { tempRoot, workspace, homeDir };
}

function response(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => body,
  };
}

function registryAndChangelogFetch({ latest = "1.2.0", changelog = "" } = {}) {
  return async (url) => {
    if (String(url).includes("registry")) {
      return response(JSON.stringify({ "dist-tags": { latest } }));
    }
    return response(changelog);
  };
}

test("semver comparison handles releases and prereleases", () => {
  assert.equal(update.compareSemver("1.2.0", "1.1.9"), 1);
  assert.equal(update.compareSemver("v1.2.0", "1.2.0"), 0);
  assert.equal(update.compareSemver("1.2.0-beta.2", "1.2.0-beta.10"), -1);
  assert.equal(update.compareSemver("1.2.0", "1.2.0-beta.10"), 1);
});

test("changelog extraction returns versions newer than installed through latest", () => {
  const changelog = [
    "# Changelog",
    "",
    "## [1.3.0] - 2026-05-01",
    "- future",
    "",
    "## [1.2.0] - 2026-04-26",
    "- two",
    "",
    "## [1.1.0] - 2026-04-20",
    "- one",
    "",
    "## [1.0.0] - 2026-04-01",
    "- initial",
  ].join("\n");

  const extracted = update.extractChangelogEntries(changelog, "1.0.0", "1.2.0");
  assert.match(extracted, /1\.2\.0/);
  assert.match(extracted, /1\.1\.0/);
  assert.doesNotMatch(extracted, /1\.3\.0/);
  assert.doesNotMatch(extracted, /1\.0\.0/);
});

test("missing installed version is treated as a legacy install", async () => {
  const { tempRoot, workspace } = tempWorkspace();
  try {
    const result = await update.checkForUpdate(workspace, {
      fetchImpl: registryAndChangelogFetch({
        latest: "1.2.0",
        changelog: "## [1.2.0] - 2026-04-26\n\n- latest\n",
      }),
    });
    assert.equal(result.installed_version, null);
    assert.equal(result.legacy_install, true);
    assert.equal(result.latest_version, "1.2.0");
    assert.equal(result.update_available, true);
    assert.match(result.changelog, /latest/);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("neutral install version takes precedence over legacy Claude fallback", () => {
  const { tempRoot, workspace } = tempWorkspace();
  try {
    fs.mkdirSync(path.join(workspace, ".hacker-bob"), { recursive: true });
    fs.writeFileSync(path.join(workspace, ".hacker-bob", "VERSION"), "2.0.0\n");
    fs.writeFileSync(path.join(workspace, ".claude", "bob", "VERSION"), "1.0.0\n");
    assert.equal(update.readInstalledVersion(workspace), "2.0.0");
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("cache refresh respects the 24 hour TTL", async () => {
  const { tempRoot, workspace, homeDir } = tempWorkspace();
  try {
    fs.writeFileSync(path.join(workspace, ".claude", "bob", "VERSION"), "1.0.0\n");
    update.writeUpdateCache(workspace, {
      schema_version: 1,
      checked_at_ms: 1000,
      checked_at: new Date(1000).toISOString(),
      installed_version: "1.0.0",
      latest_version: "1.0.0",
      update_available: false,
    }, { homeDir });

    let fetches = 0;
    const fresh = await update.refreshUpdateCache(workspace, {
      homeDir,
      nowMs: 1000 + update.CACHE_TTL_MS - 1,
      fetchImpl: async () => {
        fetches += 1;
        throw new Error("should not fetch");
      },
    });
    assert.equal(fresh.refreshed, false);
    assert.equal(fetches, 0);

    const stale = await update.refreshUpdateCache(workspace, {
      homeDir,
      nowMs: 1000 + update.CACHE_TTL_MS + 1,
      fetchImpl: async () => {
        fetches += 1;
        return response(JSON.stringify({ "dist-tags": { latest: "1.1.0" } }));
      },
    });
    assert.equal(stale.refreshed, true);
    assert.equal(fetches, 1);
    assert.equal(stale.cache.update_available, true);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("offline registry failures produce a clean cacheable error state", async () => {
  const { tempRoot, workspace, homeDir } = tempWorkspace();
  try {
    fs.writeFileSync(path.join(workspace, ".claude", "bob", "VERSION"), "1.0.0\n");
    const refreshed = await update.refreshUpdateCache(workspace, {
      homeDir,
      force: true,
      fetchImpl: async () => {
        throw new Error("network down");
      },
    });
    assert.equal(refreshed.cache.update_available, false);
    assert.equal(refreshed.cache.error.type, "registry");
    assert.match(refreshed.cache.error.message, /network down/);

    const cached = update.readUpdateCache(workspace, { homeDir });
    assert.equal(cached.error.type, "registry");
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("changelog fetch failures keep version update results", async () => {
  const { tempRoot, workspace } = tempWorkspace();
  try {
    fs.writeFileSync(path.join(workspace, ".claude", "bob", "VERSION"), "1.0.0\n");
    const result = await update.checkForUpdate(workspace, {
      fetchImpl: async (url) => {
        if (String(url).includes("registry")) {
          return response(JSON.stringify({ "dist-tags": { latest: "1.1.0" } }));
        }
        throw new Error("changelog offline");
      },
    });
    assert.equal(result.update_available, true);
    assert.equal(result.latest_version, "1.1.0");
    assert.match(result.changelog_error, /changelog offline/);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("neutral update rendering uses project path unless an adapter overrides the command", () => {
  const { tempRoot, workspace } = tempWorkspace();
  try {
    const result = {
      schema_version: 1,
      package_name: "hacker-bob",
      install_target: workspace,
      installed_version: "1.0.0",
      latest_version: "1.2.0",
      update_available: true,
      legacy_install: false,
      error: null,
    };
    const neutral = update.renderUpdatePlan(result);
    assert.match(neutral, new RegExp(`npx -y hacker-bob@latest install ${JSON.stringify(workspace).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
    assert.doesNotMatch(neutral, /CLAUDE_PROJECT_DIR/);

    const adapter = update.renderUpdatePlan(result, { installCommand: 'npx -y hacker-bob@latest install "$CLAUDE_PROJECT_DIR"' });
    assert.match(adapter, /CLAUDE_PROJECT_DIR/);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});
