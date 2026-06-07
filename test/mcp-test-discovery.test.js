const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const MANIFEST_PATH = path.join(ROOT, "test", "mcp-test-manifest.json");
const PACKAGE_JSON_PATH = path.join(ROOT, "package.json");

const MODULE_GUARD_TESTS = Object.freeze([
  Object.freeze({
    module: "mcp/lib/reachability.js",
    guards: Object.freeze([
      "test/reachability.test.js",
      "test/repo-target.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/reachability-ceiling.js",
    guards: Object.freeze([
      "test/reachability.test.js",
      "test/grade-from-frozen-payload.test.js",
      "test/lifecycle-advance.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/repo-target.js",
    guards: Object.freeze([
      "test/repo-target-binding.test.js",
      "test/repo-inventory.test.js",
      "test/repo-target.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/stigmergic-consumers.js",
    guards: Object.freeze([
      "test/stigmergic-consumers-shape.test.js",
      "test/stigmergy-coherence.test.js",
    ]),
  }),
]);

function readManifest() {
  const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"));
  assert.ok(Array.isArray(manifest), "mcp-test-manifest.json must be an array");
  return manifest;
}

function discoveredMcpTests() {
  return fs.readdirSync(path.join(ROOT, "test"))
    .filter((name) => /^mcp-.*\.test\.js$/.test(name))
    .map((name) => `test/${name}`)
    .sort();
}

function onDiskTestFiles() {
  return fs.readdirSync(path.join(ROOT, "test"))
    .filter((name) => /\.test\.js$/.test(name))
    .map((name) => `test/${name}`)
    .sort();
}

function packageScriptTests() {
  const pkg = JSON.parse(fs.readFileSync(PACKAGE_JSON_PATH, "utf8"));
  const scriptText = Object.values(pkg.scripts || {}).join("\n");
  return Array.from(scriptText.matchAll(/test\/[\w.-]+\.test\.js/g))
    .map((match) => match[0])
    .sort();
}

function runnableTestSet() {
  return new Set([
    ...readManifest(),
    ...packageScriptTests(),
  ]);
}

test("test:mcp manifest keeps mcp-prefixed test discovery in sync", () => {
  const manifest = readManifest();
  const manifestMcpTests = manifest.filter((file) => path.basename(file).startsWith("mcp-")).sort();

  assert.equal(new Set(manifest).size, manifest.length, "mcp-test-manifest.json contains duplicate entries");
  for (const file of manifest) {
    assert.ok(fs.existsSync(path.join(ROOT, file)), `${file} does not exist`);
  }

  assert.deepEqual(manifestMcpTests, discoveredMcpTests());
  assert.ok(manifest.includes("test/mcp-server.test.js"));
  assert.ok(manifest.includes("test/mcp-test-discovery.test.js"));
});

test("critical modules have explicit runnable guard tests", () => {
  const runnable = runnableTestSet();

  for (const entry of MODULE_GUARD_TESTS) {
    assert.ok(fs.existsSync(path.join(ROOT, entry.module)), `${entry.module} does not exist`);
    assert.ok(entry.guards.length > 0, `${entry.module} must name at least one guard test`);
    for (const guard of entry.guards) {
      assert.ok(fs.existsSync(path.join(ROOT, guard)), `${guard} does not exist`);
      assert.ok(
        runnable.has(guard),
        `${entry.module} guard ${guard} is not in mcp-test-manifest.json or a package.json test script`,
      );
    }
  }
});

test("every on-disk test file is executed by a declared runner", () => {
  const runnable = runnableTestSet();
  const unrunnable = onDiskTestFiles().filter((file) => !runnable.has(file));
  assert.deepEqual(unrunnable, []);
});
