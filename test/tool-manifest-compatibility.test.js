"use strict";

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const REPO_ROOT = path.resolve(__dirname, "..");

const MANIFEST_CONTRACTS = Object.freeze([
  Object.freeze({
    file: "mcp/tools/manifests/discovery.js",
    length: 32,
    segments: Object.freeze([
      Object.freeze({ name: "discoveryBeforePhysicalClaimTools", length: 30 }),
      Object.freeze({ name: "discoveryAfterPhysicalClaimTools", length: 2 }),
    ]),
  }),
  Object.freeze({
    file: "mcp/tools/manifests/session-waves.js",
    length: 32,
    segments: Object.freeze([
      Object.freeze({ name: "sessionInitializerTools", length: 2 }),
      Object.freeze({ name: "sessionAfterSpecializedSessionTools", length: 30 }),
    ]),
  }),
  Object.freeze({
    file: "mcp/tools/manifests/reporting-capabilities.js",
    length: 20,
    segments: Object.freeze([
      Object.freeze({ name: "reportingBeforeBlockchainInvariantTools", length: 17 }),
      Object.freeze({ name: "surfaceAnalysisTools", length: 3 }),
    ]),
  }),
  Object.freeze({
    file: "mcp/tools/manifests/task-graph.js",
    length: 38,
    segments: Object.freeze([
      Object.freeze({ name: "taskReproVerificationTools", length: 10 }),
      Object.freeze({ name: "findingVerificationTools", length: 1 }),
      Object.freeze({ name: "taskGraphExecutionTools", length: 11 }),
      Object.freeze({ name: "browserSessionExecutionTools", length: 15 }),
      Object.freeze({ name: "packTelemetryTools", length: 1 }),
    ]),
  }),
]);

const COMPOSITION_SOURCE_FILES = Object.freeze([
  "mcp/tools/index.js",
  ...MANIFEST_CONTRACTS.map((contract) => contract.file),
]);

const FORBIDDEN_CATCHALL_NAMES = Object.freeze([
  "discoveryClaimRecordingTools",
  "sessionWaveLifecycleTools",
  "reportingCapabilityTools",
  "taskBrowserExecutionTools",
]);

function requireFromRoot(root, relativePath) {
  return require(path.join(root, relativePath));
}

function assertUniqueValues(values, label) {
  assert.equal(new Set(values).size, values.length, `${label} must not contain duplicates`);
}

function toolNames(tools) {
  return tools.map((tool) => tool.name);
}

function assertArrayDefaultContract(manifest, contract, label) {
  assert.equal(Array.isArray(manifest), true, `${label} must export an Array`);
  assert.equal(Object.isFrozen(manifest), true, `${label} default export must be frozen`);
  assert.equal(manifest.length, contract.length, `${label} length drifted`);
  assert.deepEqual([...manifest], manifest, `${label} iteration must match numeric array order`);
  assert.deepEqual(
    Object.keys(manifest),
    Array.from({ length: contract.length }, (_, index) => String(index)),
    `${label} Object.keys must expose only numeric indexes`,
  );
  assertUniqueValues(manifest, `${label} module identities`);
  assertUniqueValues(toolNames(manifest), `${label} tool names`);
}

function assertSegmentContract(manifest, contract, label) {
  const flattened = [];
  for (const segment of contract.segments) {
    const descriptor = Object.getOwnPropertyDescriptor(manifest, segment.name);
    assert.ok(descriptor, `${label} missing segment ${segment.name}`);
    assert.equal(descriptor.enumerable, false, `${label}.${segment.name} must be non-enumerable`);
    assert.equal(descriptor.writable, false, `${label}.${segment.name} must be read-only`);
    assert.equal(descriptor.configurable, false, `${label}.${segment.name} must be non-configurable`);

    const { [segment.name]: destructured } = manifest;
    assert.equal(destructured, descriptor.value, `${label}.${segment.name} must destructure to descriptor value`);
    assert.equal(Array.isArray(destructured), true, `${label}.${segment.name} must be an Array`);
    assert.equal(Object.isFrozen(destructured), true, `${label}.${segment.name} must be frozen`);
    assert.equal(destructured.length, segment.length, `${label}.${segment.name} length drifted`);
    assertUniqueValues(destructured, `${label}.${segment.name} module identities`);
    flattened.push(...destructured);
  }

  assert.deepEqual(flattened, manifest, `${label} named segments must flatten to the default export`);
}

function manifestContractSummary(root) {
  return MANIFEST_CONTRACTS.map((contract) => {
    const manifest = requireFromRoot(root, contract.file);
    const label = `${root}:${contract.file}`;
    assertArrayDefaultContract(manifest, contract, label);
    assertSegmentContract(manifest, contract, label);
    return {
      file: contract.file,
      names: toolNames(manifest),
      segments: Object.fromEntries(contract.segments.map((segment) => [
        segment.name,
        toolNames(manifest[segment.name]),
      ])),
    };
  });
}

function expectedToolModules(root) {
  const {
    discoveryBeforePhysicalClaimTools,
    discoveryAfterPhysicalClaimTools,
  } = requireFromRoot(root, "mcp/tools/manifests/discovery.js");
  const {
    sessionInitializerTools,
    sessionAfterSpecializedSessionTools,
  } = requireFromRoot(root, "mcp/tools/manifests/session-waves.js");
  const {
    reportingBeforeBlockchainInvariantTools,
    surfaceAnalysisTools,
  } = requireFromRoot(root, "mcp/tools/manifests/reporting-capabilities.js");
  const {
    taskReproVerificationTools,
    findingVerificationTools,
    taskGraphExecutionTools,
    browserSessionExecutionTools,
    packTelemetryTools,
  } = requireFromRoot(root, "mcp/tools/manifests/task-graph.js");

  const physicalClaimTools = Object.freeze([
    requireFromRoot(root, "mcp/tools/physical/record-physical-candidate-claim.js"),
  ]);
  const specializedSessionTools = Object.freeze([
    requireFromRoot(root, "mcp/tools/blockchain/init-contract-session.js"),
    requireFromRoot(root, "mcp/tools/physical/init-physical-session.js"),
    requireFromRoot(root, "mcp/tools/physical/query-instrument-capabilities.js"),
  ]);
  const blockchainInvariantReportingTools = Object.freeze([
    requireFromRoot(root, "mcp/tools/blockchain/suggest-invariants.js"),
    requireFromRoot(root, "mcp/tools/blockchain/run-invariant-for-finding.js"),
    requireFromRoot(root, "mcp/tools/blockchain/read-invariant-runs.js"),
  ]);
  const blockchainRuntimeTools = Object.freeze([
    requireFromRoot(root, "mcp/tools/blockchain/evm-call.js"),
    requireFromRoot(root, "mcp/tools/blockchain/evm-storage-read.js"),
    requireFromRoot(root, "mcp/tools/blockchain/evm-fetch-source.js"),
    requireFromRoot(root, "mcp/tools/blockchain/evm-role-table.js"),
    requireFromRoot(root, "mcp/tools/blockchain/foundry-run.js"),
    requireFromRoot(root, "mcp/tools/blockchain/halmos-run.js"),
    requireFromRoot(root, "mcp/tools/blockchain/svm-fetch-account.js"),
    requireFromRoot(root, "mcp/tools/blockchain/svm-fetch-program.js"),
    requireFromRoot(root, "mcp/tools/blockchain/anchor-run.js"),
    requireFromRoot(root, "mcp/tools/blockchain/aptos-fetch-resource.js"),
    requireFromRoot(root, "mcp/tools/blockchain/aptos-fetch-module.js"),
    requireFromRoot(root, "mcp/tools/blockchain/aptos-run.js"),
    requireFromRoot(root, "mcp/tools/blockchain/sui-fetch-object.js"),
    requireFromRoot(root, "mcp/tools/blockchain/sui-fetch-package.js"),
    requireFromRoot(root, "mcp/tools/blockchain/sui-run.js"),
    requireFromRoot(root, "mcp/tools/blockchain/substrate-run.js"),
    requireFromRoot(root, "mcp/tools/blockchain/substrate-fetch-storage.js"),
    requireFromRoot(root, "mcp/tools/blockchain/substrate-fetch-runtime.js"),
    requireFromRoot(root, "mcp/tools/blockchain/cosmwasm-run.js"),
    requireFromRoot(root, "mcp/tools/blockchain/cosmwasm-fetch-contract.js"),
    requireFromRoot(root, "mcp/tools/blockchain/cosmwasm-smart-query.js"),
  ]);
  const blockchainVerificationTools = Object.freeze([
    requireFromRoot(root, "mcp/tools/blockchain/verify-invariant-differential.js"),
  ]);
  const physicalVerificationInstrumentTools = Object.freeze([
    requireFromRoot(root, "mcp/tools/physical/verify-physical-verdict.js"),
    requireFromRoot(root, "mcp/tools/physical/verify-physical-candidate-claim.js"),
    requireFromRoot(root, "mcp/tools/physical/physical-observe.js"),
    requireFromRoot(root, "mcp/tools/physical/credential-acquire.js"),
    requireFromRoot(root, "mcp/tools/physical/credential-recover.js"),
    requireFromRoot(root, "mcp/tools/physical/credential-emulate.js"),
    requireFromRoot(root, "mcp/tools/physical/credential-write.js"),
    requireFromRoot(root, "mcp/tools/physical/protocol-transceive.js"),
    requireFromRoot(root, "mcp/tools/physical/rf-trace.js"),
  ]);

  return [
    ...discoveryBeforePhysicalClaimTools,
    ...physicalClaimTools,
    ...discoveryAfterPhysicalClaimTools,
    ...requireFromRoot(root, "mcp/tools/manifests/chain.js"),
    ...requireFromRoot(root, "mcp/tools/manifests/verification.js"),
    ...sessionInitializerTools,
    ...specializedSessionTools,
    ...sessionAfterSpecializedSessionTools,
    ...reportingBeforeBlockchainInvariantTools,
    ...blockchainInvariantReportingTools,
    ...surfaceAnalysisTools,
    ...blockchainRuntimeTools,
    ...requireFromRoot(root, "mcp/tools/manifests/frontier-belief.js"),
    ...taskReproVerificationTools,
    ...blockchainVerificationTools,
    ...findingVerificationTools,
    ...physicalVerificationInstrumentTools,
    ...taskGraphExecutionTools,
    ...browserSessionExecutionTools,
    ...packTelemetryTools,
    ...requireFromRoot(root, "mcp/tools/manifests/friction.js"),
  ];
}

function assertToolModulesComposition(root) {
  const { TOOL_MODULES } = requireFromRoot(root, "mcp/tools/index.js");
  const expected = expectedToolModules(root);
  assert.equal(Object.isFrozen(TOOL_MODULES), true, `${root}: TOOL_MODULES must be frozen`);
  assertUniqueValues(TOOL_MODULES, `${root}: TOOL_MODULES module identities`);
  assertUniqueValues(toolNames(TOOL_MODULES), `${root}: TOOL_MODULES tool names`);
  assert.deepEqual(TOOL_MODULES, expected, `${root}: TOOL_MODULES must match explicit segment composition`);
  return toolNames(TOOL_MODULES);
}

function readCompositionSources(root) {
  return Object.fromEntries(COMPOSITION_SOURCE_FILES.map((relativePath) => [
    relativePath,
    fs.readFileSync(path.join(root, relativePath), "utf8"),
  ]));
}

function assertNoForbiddenComposition(sourceByPath, label) {
  for (const [relativePath, source] of Object.entries(sourceByPath)) {
    for (const forbiddenName of FORBIDDEN_CATCHALL_NAMES) {
      assert.equal(
        source.includes(forbiddenName),
        false,
        `${label}:${relativePath} must not retain ${forbiddenName}`,
      );
    }
    assert.equal(
      /(?:^|[^\w$])(?:slice|splice)\s*\(/u.test(source) || /\.(?:slice|splice)\s*\(/u.test(source),
      false,
      `${label}:${relativePath} must not compose manifests with slice/splice`,
    );
    assert.equal(
      /\[[0-9]+\]/u.test(source) || /\.at\s*\(\s*[0-9]/u.test(source),
      false,
      `${label}:${relativePath} must not compose manifests with numeric index coordinates`,
    );
  }
}

function staticallyRequiredCompositionPaths(root) {
  const required = new Set(COMPOSITION_SOURCE_FILES);
  const requirePattern = /require\("([^"]+)"\)/gu;
  for (const relativePath of COMPOSITION_SOURCE_FILES) {
    const source = fs.readFileSync(path.join(root, relativePath), "utf8");
    const directory = path.dirname(relativePath);
    for (const match of source.matchAll(requirePattern)) {
      const specifier = match[1];
      if (!specifier.startsWith(".")) continue;
      const resolved = path.normalize(path.join(directory, specifier));
      const resolvedWithExtension = path.extname(resolved) ? resolved : `${resolved}.js`;
      assert.ok(
        fs.existsSync(path.join(root, resolvedWithExtension)),
        `${relativePath} requires missing path ${specifier}`,
      );
      required.add(resolvedWithExtension);
    }
  }
  return [...required].sort();
}

function packRepository() {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-tool-manifest-pack-"));
  const packDirectory = path.join(tempRoot, "pack");
  const extractDirectory = path.join(tempRoot, "extract");
  const cacheDirectory = path.join(tempRoot, "npm-cache");
  fs.mkdirSync(packDirectory);
  fs.mkdirSync(extractDirectory);
  fs.mkdirSync(cacheDirectory);

  try {
    const stdout = execFileSync(
      "npm",
      ["pack", "--ignore-scripts", "--pack-destination", packDirectory],
      {
        cwd: REPO_ROOT,
        encoding: "utf8",
        env: {
          ...process.env,
          npm_config_cache: cacheDirectory,
          npm_config_update_notifier: "false",
        },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    const tarballName = stdout.trim().split(/\r?\n/u).filter(Boolean).pop();
    assert.ok(tarballName, "npm pack did not report a tarball name");
    const tarballPath = path.join(packDirectory, tarballName);
    const tarballEntries = execFileSync("tar", ["-tzf", tarballPath], { encoding: "utf8" })
      .trim()
      .split(/\r?\n/u)
      .filter(Boolean);
    execFileSync("tar", ["-xzf", tarballPath, "-C", extractDirectory], { stdio: "ignore" });
    const packageRoot = path.join(extractDirectory, "package");
    const sourceNodeModules = path.join(REPO_ROOT, "node_modules");
    if (fs.existsSync(sourceNodeModules)) {
      fs.symlinkSync(sourceNodeModules, path.join(packageRoot, "node_modules"), "dir");
    }
    return {
      tempRoot,
      packageRoot,
      tarballEntries: new Set(tarballEntries),
    };
  } catch (error) {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    throw error;
  }
}

test("manifest arrays expose hidden immutable segments without breaking default-array callers", () => {
  const sourceSummary = manifestContractSummary(REPO_ROOT);
  const toolModuleNames = assertToolModulesComposition(REPO_ROOT);
  assertNoForbiddenComposition(readCompositionSources(REPO_ROOT), "source");

  const packed = packRepository();
  try {
    for (const relativePath of staticallyRequiredCompositionPaths(REPO_ROOT)) {
      assert.ok(
        packed.tarballEntries.has(`package/${relativePath}`),
        `npm pack must include ${relativePath}`,
      );
    }

    assertNoForbiddenComposition(readCompositionSources(packed.packageRoot), "packed");
    assert.deepEqual(manifestContractSummary(packed.packageRoot), sourceSummary);
    assert.deepEqual(assertToolModulesComposition(packed.packageRoot), toolModuleNames);
  } finally {
    fs.rmSync(packed.tempRoot, { recursive: true, force: true });
  }
});
