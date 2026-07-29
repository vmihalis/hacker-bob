const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const MANIFEST_PATH = path.join(ROOT, "test", "mcp-test-manifest.json");
const PACKAGE_JSON_PATH = path.join(ROOT, "package.json");

const MODULE_GUARD_TESTS = Object.freeze([
  Object.freeze({
    module: "mcp/lib/physical-quantities.js",
    guards: Object.freeze([
      "test/physical-effects-contract.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/requested-effects.js",
    guards: Object.freeze([
      "test/physical-effects-contract.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/physical-authority.js",
    guards: Object.freeze([
      "test/physical-authority-contract.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/physical-dispatch-authority.js",
    guards: Object.freeze([
      "test/physical-dispatch-authority.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/physical-trusted-clock.js",
    guards: Object.freeze([
      "test/physical-trusted-clock.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/physical-trusted-clock-store.js",
    guards: Object.freeze([
      "test/physical-trusted-clock-store.test.js",
      "test/physical-experiment-contract.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/physical-inventory-checkpoint.js",
    guards: Object.freeze([
      "test/physical-inventory-checkpoint.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/physical-resource-arbiter.js",
    guards: Object.freeze([
      "test/physical-resource-arbiter.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/physical-resource-graph-coordinator.js",
    guards: Object.freeze([
      "test/physical-resource-graph-coordinator.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/physical-provider-authoring.js",
    guards: Object.freeze([
      "test/physical-provider-authoring.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/physical-campaign-anchor.js",
    guards: Object.freeze([
      "test/physical-campaign-coordinator.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/physical-campaign-closure.js",
    guards: Object.freeze([
      "test/physical-campaign-closure.test.js",
      "test/physical-campaign-coordinator.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/physical-campaign-coordinator.js",
    guards: Object.freeze([
      "test/physical-campaign-coordinator.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/physical-lifecycle-capstone.js",
    guards: Object.freeze([
      "test/physical-lifecycle-capstone.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/plane-physical-gate-evidence.js",
    guards: Object.freeze([
      "test/plane-physical-gate-evidence.test.js",
      "test/plane-physical-release-readiness.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/plane-physical-release-contracts.js",
    guards: Object.freeze([
      "test/plane-physical-release-readiness.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/plane-physical-release-readiness.js",
    guards: Object.freeze([
      "test/plane-physical-release-readiness.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/plane-physical-release-snapshot.js",
    guards: Object.freeze([
      "test/plane-physical-release-readiness.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/instrument-provider-contract.js",
    guards: Object.freeze([
      "test/instrument-provider-contract.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/instrument-bootstrap-contract.js",
    guards: Object.freeze([
      "test/instrument-bootstrap-contract.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/instrument-bootstrap-store.js",
    guards: Object.freeze([
      "test/instrument-bootstrap-store.test.js",
      "test/instrument-bootstrap-async-observation.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-instrument-deterministic/lib/provider.js",
    guards: Object.freeze([
      "test/deterministic-instrument-provider.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-instrument-deterministic/lib/fixtures.js",
    guards: Object.freeze([
      "test/deterministic-instrument-provider.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-instrument-broker/lib/authenticated-durable-exchange.js",
    guards: Object.freeze([
      "test/instrument-broker.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-instrument-broker/lib/broker.js",
    guards: Object.freeze([
      "test/instrument-broker.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-instrument-broker/lib/bootstrap-broker.js",
    guards: Object.freeze([
      "test/instrument-broker.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-instrument-broker/lib/ipc-contract.js",
    guards: Object.freeze([
      "test/instrument-broker.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-instrument-broker/lib/ipc.js",
    guards: Object.freeze([
      "test/instrument-broker.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-instrument-broker/lib/ipc-native-peer-credentials.js",
    guards: Object.freeze([
      "test/instrument-broker.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-instrument-broker/lib/provider-contract.js",
    guards: Object.freeze([
      "test/instrument-broker.test.js",
      "test/instrument-provider-contract.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-instrument-broker/lib/physical-provider-dispatch.js",
    guards: Object.freeze([
      "test/instrument-broker.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-instrument-broker/lib/resource-reservations.js",
    guards: Object.freeze([
      "test/instrument-broker.test.js",
      "test/physical-resource-arbiter-admission.test.js",
      "test/physical-resource-graph-coordinator.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-instrument-broker/lib/resource-request-registry.js",
    guards: Object.freeze([
      "test/instrument-broker.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-instrument-broker/lib/resource-arbiter-admission.js",
    guards: Object.freeze([
      "test/physical-resource-arbiter-admission.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-instrument-broker/lib/resource-arbiter-store.js",
    guards: Object.freeze([
      "test/physical-resource-arbiter-store.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-instrument-chameleon/lib/bootstrap-operations.js",
    guards: Object.freeze([
      "test/chameleon-bootstrap-operations.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-instrument-chameleon/lib/bootstrap-response-payloads.js",
    guards: Object.freeze([
      "test/chameleon-bootstrap-response-payloads.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-instrument-chameleon/lib/ble.js",
    guards: Object.freeze([
      "test/chameleon-ble-nus.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-instrument-chameleon/lib/operations.js",
    guards: Object.freeze([
      "test/chameleon-operation-manifest.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-instrument-chameleon/lib/codec.js",
    guards: Object.freeze([
      "test/chameleon-frame-codec.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-instrument-chameleon/lib/usb-cdc-custody.js",
    guards: Object.freeze([
      "test/chameleon-usb-cdc-custody.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-instrument-chameleon/lib/state-stewardship.js",
    guards: Object.freeze([
      "test/chameleon-state-stewardship.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-instrument-chameleon/lib/manual-actions.js",
    guards: Object.freeze([
      "test/chameleon-manual-actions.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-instrument-chameleon/lib/failure-matrix-engineering.js",
    guards: Object.freeze([
      "test/chameleon-failure-matrix-engineering.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/executed-evidence-registry.js",
    guards: Object.freeze([
      "test/executed-evidence-registry.test.js",
      "test/physical-surface-graph-ph-s8-acceptance.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/instrument-capabilities.js",
    guards: Object.freeze([
      "test/instrument-capabilities.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/instrument-capabilities-chameleon.js",
    guards: Object.freeze([
      "test/instrument-capabilities.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/tools/query-instrument-capabilities.js",
    guards: Object.freeze([
      "test/instrument-capabilities.test.js",
      "test/mcp-server.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/physical-scope.js",
    guards: Object.freeze([
      "test/physical-scope-contract.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/physical-experiment-contract.js",
    guards: Object.freeze([
      "test/physical-experiment-contract.test.js",
      "test/physical-surface-graph-ph-s8-acceptance.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/instrument-lease-contract.js",
    guards: Object.freeze([
      "test/instrument-lease-contract.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/instrument-lease-store.js",
    guards: Object.freeze([
      "test/instrument-lease-store.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-instrument-broker/lib/instrument-lease-store.js",
    guards: Object.freeze([
      "test/instrument-lease-store.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/instrument-safety-supervisor.js",
    guards: Object.freeze([
      "test/instrument-safety-supervisor.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-artifact-vault/lib/vault.js",
    guards: Object.freeze([
      "test/physical-artifact-vault.test.js",
      "test/transform-attempt-claims.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-artifact-vault/lib/transform-worker.js",
    guards: Object.freeze([
      "test/physical-artifact-vault.test.js",
      "test/transform-registry-loader.test.js",
      "test/transform-attempt-claims.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-artifact-vault/lib/transform-policy.js",
    guards: Object.freeze([
      "test/physical-artifact-vault.test.js",
      "test/transform-registry-loader.test.js",
      "test/transform-attempt-claims.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-artifact-vault/lib/contracts.js",
    guards: Object.freeze([
      "test/physical-artifact-vault.test.js",
      "test/transform-attempt-claims.test.js",
    ]),
  }),
  Object.freeze({
    module: "packages/bob-artifact-vault/lib/operator-export-channel.js",
    guards: Object.freeze([
      "test/physical-artifact-vault.test.js",
      "test/transform-attempt-claims.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/surface-graph.js",
    guards: Object.freeze([
      "test/surface-graph.test.js",
      "test/physical-surface-graph.test.js",
      "test/physical-surface-graph-ph-s8-acceptance.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/physical-surface-transition.js",
    guards: Object.freeze([
      "test/physical-surface-graph.test.js",
      "test/physical-surface-graph-ph-s8-acceptance.test.js",
    ]),
  }),
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
  Object.freeze({
    module: "mcp/lib/belief/authority.js",
    guards: Object.freeze([
      "test/belief-authority.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/belief/frontier-facts.js",
    guards: Object.freeze([
      "test/belief-frontier-facts.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/belief/belief-window.js",
    guards: Object.freeze([
      "test/belief-window.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/belief/factor-graph.js",
    guards: Object.freeze([
      "test/belief-factor-graph.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/belief/residual.js",
    guards: Object.freeze([
      "test/belief-residual.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/belief/intervention-calculus.js",
    guards: Object.freeze([
      "test/belief-intervention-calculus.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/belief/experiment-loop.js",
    guards: Object.freeze([
      "test/belief-experiment-loop.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/belief/scheduler-priority.js",
    guards: Object.freeze([
      "test/wave-planner.test.js",
    ]),
  }),
  Object.freeze({
    module: "mcp/lib/belief/model.js",
    guards: Object.freeze([
      "test/belief-model.test.js",
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
