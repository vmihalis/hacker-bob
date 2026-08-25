const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  installLifecycleCustodianTestDouble,
  lifecycleCustodianTestDoubleSupported,
} = require("./fixtures/lifecycle-custodian-test-port.js");

// Darwin/arm64-only native fixture. Elsewhere leave the real wrapper in place —
// it reports the custodian unavailable, which is the path the installer takes
// on those hosts, so these cases still exercise a real install.
if (lifecycleCustodianTestDoubleSupported()) installLifecycleCustodianTestDouble();

const { getAdapter } = require("../adapters/index.js");
const {
  copyRuntimeNodeDependencies,
  installProject,
  isInstallableMcpRuntimeTreeFile,
} = require("../scripts/install.js");
const { doctorProject } = require("../scripts/lifecycle.js");
const update = require("../mcp/core/update-check.js");
const { FANOUT_ROLE_REGISTRY } = require("../mcp/core/session/nested-spawn.js");
const {
  CANONICAL_RUNTIME_PACKAGE_ROOTS,
  canonicalInstalledRuntimeFiles,
  isCanonicalRuntimePackageFile,
  sourceTreeFiles,
} = require("../scripts/lib/package-policy.js");
const {
  declaredRuntimeEntrypoints,
  loadCanonicalRuntimeEntrypoints,
} = require("./helpers/canonical-runtime-entrypoints.js");

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "bin", "hacker-bob.js");
const PACKAGE_VERSION = require("../package.json").version;
const CODEX_ADAPTER = getAdapter("codex");
const KIMI_ADAPTER = getAdapter("kimi");
const GENERIC_MCP_ADAPTER = getAdapter("generic-mcp");
const LIFECYCLE_CUSTODIAN_TEST_PRELOAD = path.join(
  __dirname,
  "fixtures",
  "lifecycle-custodian-test-preload.js",
);
const ORIGINAL_NODE_OPTIONS = process.env.NODE_OPTIONS;
process.env.NODE_OPTIONS = [
  `--require=${LIFECYCLE_CUSTODIAN_TEST_PRELOAD}`,
  ORIGINAL_NODE_OPTIONS,
].filter(Boolean).join(" ");

test("installer runtime subtree predicate is exactly package-policy scoped", () => {
  assert.equal(isInstallableMcpRuntimeTreeFile("core", "nested/runtime.js"), true);
  assert.equal(isInstallableMcpRuntimeTreeFile("fuzz", "bob-multitu-build.sh"), true);
  assert.equal(isInstallableMcpRuntimeTreeFile("fuzz", "future-builder.sh"), false);
  assert.equal(isInstallableMcpRuntimeTreeFile("fuzz", "nested/bob-multitu-build.sh"), false);
  assert.equal(isInstallableMcpRuntimeTreeFile("core", "offensive-image.json"), false);
  assert.equal(isInstallableMcpRuntimeTreeFile("other", "runtime.js"), false);
  assert.equal(isInstallableMcpRuntimeTreeFile("core", "../fuzz/bob-multitu-build.sh"), false);
});
test.after(() => {
  if (ORIGINAL_NODE_OPTIONS === undefined) delete process.env.NODE_OPTIONS;
  else process.env.NODE_OPTIONS = ORIGINAL_NODE_OPTIONS;
});

function installWithTestHome(workspace, tempHome) {
  const previousHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    return installProject(workspace, {
      sourceRoot: ROOT,
      installerSource: "install.sh",
    });
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
  }
}

function writeRuntimeFixturePackage(packageRoot, manifest, files = {}) {
  fs.mkdirSync(packageRoot, { recursive: true });
  fs.writeFileSync(
    path.join(packageRoot, "package.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
    "utf8",
  );
  for (const [relativePath, contents] of Object.entries(files)) {
    const filePath = path.join(packageRoot, ...relativePath.split("/"));
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, contents, "utf8");
  }
}

test("packed npm layout resolves hoisted runtime dependencies without executing them", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-packed-dependency-"));
  const dependencyRoot = path.join(tempRoot, "dependency");
  const packageRoot = path.join(tempRoot, "package");
  const installRoot = path.join(tempRoot, "install");
  const targetMcp = path.join(tempRoot, "target", "mcp");
  const sentinel = path.join(tempRoot, "dependency-executed");
  const dependencyName = "bob-runtime-layout-proof-dependency";
  const packageName = "bob-runtime-layout-proof-package";

  const pack = (root) => {
    const output = execFileSync("npm", ["pack", "--json", "--ignore-scripts"], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    return path.join(root, JSON.parse(output)[0].filename);
  };

  try {
    fs.mkdirSync(dependencyRoot, { recursive: true });
    fs.writeFileSync(path.join(dependencyRoot, "package.json"), `${JSON.stringify({
      name: dependencyName,
      version: "1.0.0",
      main: "index.js",
    })}\n`, "utf8");
    fs.writeFileSync(
      path.join(dependencyRoot, "index.js"),
      `require("node:fs").writeFileSync(${JSON.stringify(sentinel)}, "executed");\nmodule.exports = {};\n`,
      "utf8",
    );
    const dependencyTarball = pack(dependencyRoot);

    fs.mkdirSync(packageRoot, { recursive: true });
    fs.writeFileSync(path.join(packageRoot, "package.json"), `${JSON.stringify({
      name: packageName,
      version: "1.0.0",
      main: "index.js",
      dependencies: {
        [dependencyName]: `file:${dependencyTarball}`,
      },
    })}\n`, "utf8");
    fs.writeFileSync(path.join(packageRoot, "index.js"), "module.exports = {};\n", "utf8");
    const packageTarball = pack(packageRoot);

    execFileSync("npm", [
      "install",
      "--offline",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--package-lock=false",
      "--prefix",
      installRoot,
      packageTarball,
    ], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });

    const installedPackage = path.join(installRoot, "node_modules", packageName);
    const hoistedDependency = path.join(installRoot, "node_modules", dependencyName);
    assert.ok(fs.existsSync(hoistedDependency));
    assert.ok(!fs.existsSync(path.join(installedPackage, "node_modules", dependencyName)));
    assert.ok(!fs.existsSync(sentinel), "packing and installing must not execute dependency code");

    const foreignSentinel = path.join(
      targetMcp,
      "node_modules",
      "foreign-package",
      "sentinel.txt",
    );
    const foreignBin = path.join(targetMcp, "node_modules", ".bin", "user-tool");
    fs.mkdirSync(path.dirname(foreignSentinel), { recursive: true });
    fs.mkdirSync(path.dirname(foreignBin), { recursive: true });
    fs.writeFileSync(foreignSentinel, "foreign\n", "utf8");
    fs.writeFileSync(foreignBin, "user-bin\n", "utf8");
    const copied = copyRuntimeNodeDependencies(installedPackage, targetMcp);
    assert.ok(copied.includes(path.join(dependencyName, "package.json")));
    assert.ok(copied.includes(path.join(dependencyName, "index.js")));
    assert.equal(
      JSON.parse(fs.readFileSync(path.join(
        targetMcp,
        "node_modules",
        dependencyName,
        "package.json",
      ), "utf8")).name,
      dependencyName,
    );
    assert.ok(!fs.existsSync(sentinel), "static dependency copying must not execute package code");
    assert.equal(fs.readFileSync(foreignSentinel, "utf8"), "foreign\n");
    assert.equal(fs.readFileSync(foreignBin, "utf8"), "user-bin\n");

    const installedDependencyIndex = path.join(
      targetMcp,
      "node_modules",
      dependencyName,
      "index.js",
    );
    fs.writeFileSync(installedDependencyIndex, "previous-complete-package\n", "utf8");
    const sourceDependencyIndex = path.join(hoistedDependency, "index.js");
    const originalOpenSync = fs.openSync;
    const originalReadSync = fs.readSync;
    let shortReadDescriptor = null;
    let forcedShortRead = false;
    fs.openSync = (filePath, ...args) => {
      const descriptor = Reflect.apply(originalOpenSync, fs, [filePath, ...args]);
      if (path.resolve(String(filePath)) === path.resolve(sourceDependencyIndex)) {
        shortReadDescriptor = descriptor;
      }
      return descriptor;
    };
    fs.readSync = (descriptor, ...args) => {
      if (!forcedShortRead && descriptor === shortReadDescriptor) {
        forcedShortRead = true;
        return 0;
      }
      return Reflect.apply(originalReadSync, fs, [descriptor, ...args]);
    };
    try {
      let shortReadError;
      try {
        copyRuntimeNodeDependencies(installedPackage, targetMcp);
      } catch (error) {
        shortReadError = error;
      }
      assert.ok(shortReadError,
        "a source short read during direct copy must fail with explicit source substitution");
      assert.equal(shortReadError.code, "runtime_dependency_source_rejected");
      assert.equal(shortReadError.reason_code, "package_file_substituted");
    } finally {
      fs.openSync = originalOpenSync;
      fs.readSync = originalReadSync;
    }
    assert.ok(
      !fs.existsSync(installedDependencyIndex),
      "direct dependency replacement is explicitly non-atomic after source preflight",
    );
    assert.ok(!fs.readdirSync(path.join(targetMcp, "node_modules"))
      .some((name) => name.startsWith(".bob-runtime-dependency-")));
    assert.equal(fs.readFileSync(foreignSentinel, "utf8"), "foreign\n");
    assert.equal(fs.readFileSync(foreignBin, "utf8"), "user-bin\n");

    const linkedTargetMcp = path.join(tempRoot, "linked-target-mcp");
    const foreignNodeModules = path.join(tempRoot, "foreign-node-modules");
    fs.mkdirSync(linkedTargetMcp, { recursive: true });
    fs.mkdirSync(foreignNodeModules, { recursive: true });
    fs.symlinkSync(foreignNodeModules, path.join(linkedTargetMcp, "node_modules"), "dir");
    assert.throws(
      () => copyRuntimeNodeDependencies(installedPackage, linkedTargetMcp),
      (error) => error && error.code === "runtime_dependency_target_rejected"
        && error.reason_code === "target_ancestry_unowned_or_nonregular",
      "a symlinked target node_modules ancestry must fail before any package mutation",
    );
    assert.deepEqual(fs.readdirSync(foreignNodeModules), []);

    const unownedRoot = path.join(tempRoot, "unowned-layout");
    const unownedPackage = path.join(unownedRoot, "package");
    const unownedDependency = path.join(unownedRoot, "node_modules", dependencyName);
    fs.mkdirSync(unownedPackage, { recursive: true });
    fs.cpSync(hoistedDependency, unownedDependency, { recursive: true });
    fs.writeFileSync(path.join(unownedPackage, "package.json"), `${JSON.stringify({
      name: packageName,
      version: "1.0.0",
      dependencies: { [dependencyName]: "1.0.0" },
    })}\n`, "utf8");
    const unownedTarget = path.join(tempRoot, "unowned-target");
    fs.mkdirSync(unownedTarget, { recursive: true });
    assert.throws(
      () => copyRuntimeNodeDependencies(unownedPackage, unownedTarget),
      /Runtime dependency .* is missing/,
      "resolution must not walk to an ancestor node_modules outside the package's owned layout",
    );

    const linkedRoot = path.join(tempRoot, "linked-layout", "node_modules");
    const linkedPackage = path.join(linkedRoot, packageName);
    fs.mkdirSync(linkedPackage, { recursive: true });
    fs.writeFileSync(path.join(linkedPackage, "package.json"), `${JSON.stringify({
      name: packageName,
      version: "1.0.0",
      dependencies: { [dependencyName]: "1.0.0" },
    })}\n`, "utf8");
    fs.symlinkSync(hoistedDependency, path.join(linkedRoot, dependencyName), "dir");
    const linkedSourceTarget = path.join(tempRoot, "linked-source-target");
    fs.mkdirSync(linkedSourceTarget, { recursive: true });
    assert.throws(
      () => copyRuntimeNodeDependencies(linkedPackage, linkedSourceTarget),
      (error) => error && error.code === "runtime_dependency_source_rejected"
        && error.reason_code === "source_ancestry_unowned_or_nonregular",
      "symlinked dependency ancestry must fail closed",
    );
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("runtime dependency graph preserves ancestor hoists and nested package versions", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-dependency-graph-"));
  const installRoot = path.join(tempRoot, "install");
  const outerModules = path.join(installRoot, "node_modules");
  const hostModules = path.join(outerModules, "fixture-host", "node_modules");
  const sourceRoot = path.join(hostModules, "fixture-root");
  const alpha = path.join(hostModules, "fixture-alpha");
  const consumer = path.join(outerModules, "fixture-consumer");
  const outerShared = path.join(outerModules, "fixture-shared");
  const nestedShared = path.join(alpha, "node_modules", "fixture-shared");
  const targetMcp = path.join(tempRoot, "target", "mcp");

  try {
    writeRuntimeFixturePackage(sourceRoot, {
      name: "fixture-root",
      version: "1.0.0",
      dependencies: {
        "fixture-alpha": "1.0.0",
        "fixture-consumer": "1.0.0",
      },
    });
    writeRuntimeFixturePackage(alpha, {
      name: "fixture-alpha",
      version: "1.0.0",
      dependencies: { "fixture-shared": "2.0.0" },
    }, { "index.js": "module.exports = 'alpha';\n" });
    writeRuntimeFixturePackage(consumer, {
      name: "fixture-consumer",
      version: "1.0.0",
      dependencies: { "fixture-shared": "1.0.0" },
    }, { "index.js": "module.exports = 'consumer';\n" });
    writeRuntimeFixturePackage(outerShared, {
      name: "fixture-shared",
      version: "1.0.0",
    }, { "version.txt": "outer-v1\n" });
    writeRuntimeFixturePackage(nestedShared, {
      name: "fixture-shared",
      version: "2.0.0",
    }, { "version.txt": "nested-v2\n" });
    fs.mkdirSync(targetMcp, { recursive: true });

    const copied = copyRuntimeNodeDependencies(sourceRoot, targetMcp);
    assert.ok(copied.includes(path.join("fixture-alpha", "package.json")));
    assert.ok(copied.includes(path.join(
      "fixture-alpha",
      "node_modules",
      "fixture-shared",
      "package.json",
    )));
    assert.equal(fs.readFileSync(path.join(
      targetMcp,
      "node_modules",
      "fixture-shared",
      "version.txt",
    ), "utf8"), "outer-v1\n");
    assert.equal(fs.readFileSync(path.join(
      targetMcp,
      "node_modules",
      "fixture-alpha",
      "node_modules",
      "fixture-shared",
      "version.txt",
    ), "utf8"), "nested-v2\n");
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("runtime dependency graph copies required peers and honors optional peer metadata", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-dependency-peers-"));
  const modulesRoot = path.join(tempRoot, "install", "node_modules");
  const sourceRoot = path.join(modulesRoot, "fixture-root");
  const plugin = path.join(modulesRoot, "fixture-plugin");
  const peer = path.join(modulesRoot, "fixture-peer");
  const targetMcp = path.join(tempRoot, "target", "mcp");

  try {
    writeRuntimeFixturePackage(sourceRoot, {
      name: "fixture-root",
      version: "1.0.0",
      dependencies: { "fixture-plugin": "1.0.0" },
    });
    writeRuntimeFixturePackage(plugin, {
      name: "fixture-plugin",
      version: "1.0.0",
      peerDependencies: {
        "fixture-optional-peer": "^1.0.0",
        "fixture-peer": "^1.0.0",
      },
      peerDependenciesMeta: {
        "fixture-optional-peer": { optional: true },
        "fixture-retired-peer": { optional: true },
      },
    }, { "index.js": "module.exports = require('fixture-peer');\n" });
    writeRuntimeFixturePackage(peer, {
      name: "fixture-peer",
      version: "1.0.0",
    }, { "index.js": "module.exports = 'peer';\n" });
    fs.mkdirSync(targetMcp, { recursive: true });

    const copied = copyRuntimeNodeDependencies(sourceRoot, targetMcp);
    assert.ok(copied.includes(path.join("fixture-peer", "package.json")));
    assert.ok(!fs.existsSync(path.join(
      targetMcp,
      "node_modules",
      "fixture-optional-peer",
    )));

    fs.rmSync(peer, { recursive: true, force: true });
    const sentinel = path.join(targetMcp, "node_modules", "sentinel.txt");
    fs.writeFileSync(sentinel, "unchanged\n", "utf8");
    assert.throws(
      () => copyRuntimeNodeDependencies(sourceRoot, targetMcp),
      (error) => error && error.code === "runtime_dependency_source_rejected"
        && error.reason_code === "required_peer_dependency_missing",
    );
    assert.equal(fs.readFileSync(sentinel, "utf8"), "unchanged\n");
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("manifest substitution after graph construction fails before target mutation", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-dependency-manifest-"));
  const modulesRoot = path.join(tempRoot, "install", "node_modules");
  const sourceRoot = path.join(modulesRoot, "fixture-root");
  const dependency = path.join(modulesRoot, "fixture-dependency");
  const dependencyManifest = path.join(dependency, "package.json");
  const targetMcp = path.join(tempRoot, "target", "mcp");

  try {
    writeRuntimeFixturePackage(sourceRoot, {
      name: "fixture-root",
      version: "1.0.0",
      dependencies: { "fixture-dependency": "1.0.0" },
    });
    writeRuntimeFixturePackage(dependency, {
      name: "fixture-dependency",
      version: "1.0.0",
    }, { "index.js": "module.exports = true;\n" });
    const sentinel = path.join(targetMcp, "node_modules", "sentinel.txt");
    fs.mkdirSync(path.dirname(sentinel), { recursive: true });
    fs.writeFileSync(sentinel, "untouched\n", "utf8");

    const originalOpenSync = fs.openSync;
    let manifestOpenCount = 0;
    fs.openSync = (filePath, ...args) => {
      if (path.resolve(String(filePath)) === path.resolve(dependencyManifest)) {
        manifestOpenCount += 1;
        if (manifestOpenCount === 2) {
          fs.writeFileSync(dependencyManifest, `${JSON.stringify({
            name: "fixture-dependency",
            version: "2.0.0",
          })}\n`, "utf8");
        }
      }
      return Reflect.apply(originalOpenSync, fs, [filePath, ...args]);
    };
    try {
      assert.throws(
        () => copyRuntimeNodeDependencies(sourceRoot, targetMcp),
        (error) => error && error.code === "runtime_dependency_source_rejected"
          && error.reason_code === "package_manifest_substituted",
      );
    } finally {
      fs.openSync = originalOpenSync;
    }
    assert.equal(manifestOpenCount, 2);
    assert.equal(fs.readFileSync(sentinel, "utf8"), "untouched\n");
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("source and target dependency-tree overlap is rejected before mutation", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-dependency-overlap-"));
  const sourceRoot = path.join(tempRoot, "install", "node_modules", "fixture-root");
  const dependency = path.join(tempRoot, "install", "node_modules", "fixture-dependency");
  const targetMcp = path.join(tempRoot, "install");

  try {
    writeRuntimeFixturePackage(sourceRoot, {
      name: "fixture-root",
      version: "1.0.0",
      dependencies: { "fixture-dependency": "1.0.0" },
    });
    writeRuntimeFixturePackage(dependency, {
      name: "fixture-dependency",
      version: "1.0.0",
    }, { "index.js": "module.exports = true;\n" });
    const originalManifest = fs.readFileSync(path.join(dependency, "package.json"), "utf8");

    assert.throws(
      () => copyRuntimeNodeDependencies(sourceRoot, targetMcp),
      (error) => error && error.code === "runtime_dependency_target_rejected"
        && error.reason_code === "source_target_overlap",
    );
    assert.equal(
      fs.readFileSync(path.join(dependency, "package.json"), "utf8"),
      originalManifest,
    );
    assert.ok(fs.existsSync(sourceRoot));

    const validProject = path.join(tempRoot, "valid-project");
    const validModules = path.join(validProject, "node_modules");
    const validSource = path.join(validModules, "fixture-valid-root");
    const validDependency = path.join(validModules, "fixture-valid-dependency");
    const validTargetMcp = path.join(validProject, "mcp");
    writeRuntimeFixturePackage(validSource, {
      name: "fixture-valid-root",
      version: "1.0.0",
      dependencies: { "fixture-valid-dependency": "1.0.0" },
    });
    writeRuntimeFixturePackage(validDependency, {
      name: "fixture-valid-dependency",
      version: "1.0.0",
    }, { "index.js": "module.exports = 'valid';\n" });
    fs.mkdirSync(validTargetMcp, { recursive: true });
    assert.doesNotThrow(() => copyRuntimeNodeDependencies(validSource, validTargetMcp));
    assert.ok(fs.existsSync(path.join(
      validTargetMcp,
      "node_modules",
      "fixture-valid-dependency",
      "index.js",
    )));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("installProject rejects an invalid dependency graph before any target mutation", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-install-preflight-"));
  const sourceRoot = path.join(tempRoot, "source");
  const plugin = path.join(sourceRoot, "node_modules", "fixture-plugin");
  const workspace = path.join(tempRoot, "workspace");
  const sentinel = path.join(workspace, "mcp", "server.js");

  try {
    writeRuntimeFixturePackage(sourceRoot, {
      name: "fixture-root",
      version: "1.0.0",
      dependencies: { "fixture-plugin": "1.0.0" },
    });
    writeRuntimeFixturePackage(plugin, {
      name: "fixture-plugin",
      version: "1.0.0",
      peerDependencies: { "fixture-required-peer": "1.0.0" },
    });
    fs.mkdirSync(path.dirname(sentinel), { recursive: true });
    fs.writeFileSync(sentinel, "operator-owned-before\n", "utf8");

    assert.throws(
      () => installProject(workspace, {
        adapter: "generic-mcp",
        sourceRoot,
        onAdapterResolution: () => {},
      }),
      (error) => error && error.code === "runtime_dependency_source_rejected"
        && error.reason_code === "required_peer_dependency_missing",
    );
    assert.equal(fs.readFileSync(sentinel, "utf8"), "operator-owned-before\n");
    assert.deepEqual(fs.readdirSync(workspace).sort(), ["mcp"]);
    assert.deepEqual(fs.readdirSync(path.join(workspace, "mcp")).sort(), ["server.js"]);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("dependency preflight bounds empty-directory fanout before target mutation", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-directory-bound-"));
  const modulesRoot = path.join(tempRoot, "install", "node_modules");
  const sourceRoot = path.join(modulesRoot, "fixture-root");
  const dependency = path.join(modulesRoot, "fixture-wide-dependency");
  const targetMcp = path.join(tempRoot, "target", "mcp");
  const sentinel = path.join(targetMcp, "node_modules", "foreign", "sentinel.txt");

  try {
    writeRuntimeFixturePackage(sourceRoot, {
      name: "fixture-root",
      version: "1.0.0",
      dependencies: { "fixture-wide-dependency": "1.0.0" },
    });
    writeRuntimeFixturePackage(dependency, {
      name: "fixture-wide-dependency",
      version: "1.0.0",
    });
    for (let index = 0; index < 4097; index += 1) {
      fs.mkdirSync(path.join(dependency, `empty-${String(index).padStart(4, "0")}`));
    }
    fs.mkdirSync(path.dirname(sentinel), { recursive: true });
    fs.writeFileSync(sentinel, "untouched\n", "utf8");

    assert.throws(
      () => copyRuntimeNodeDependencies(sourceRoot, targetMcp),
      (error) => error && error.code === "runtime_dependency_source_rejected"
        && error.reason_code === "package_tree_directory_bound_exceeded",
    );
    assert.equal(fs.readFileSync(sentinel, "utf8"), "untouched\n");
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("core installer and packed runtime start without a lifecycle-custodian preload", () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "bob-core-install-no-custodian-"));
  const workspace = path.join(base, "workspace");
  const tempHome = path.join(base, "home");
  fs.mkdirSync(workspace);
  fs.mkdirSync(tempHome);
  try {
    const output = execFileSync(process.execPath, [
      "-e",
      [
        "const path = require('node:path');",
        "const root = process.argv[1];",
        "const target = process.argv[2];",
        "const custodian = require(path.join(root, 'scripts/lib/lifecycle-custodian.js'));",
        "if (custodian.lifecycleCustodianStatus().available !== false) process.exit(61);",
        "const result = require(path.join(root, 'scripts/install.js')).installProject(target, { sourceRoot: root, adapter: 'generic-mcp', onAdapterResolution() {} });",
        "const server = require(path.join(target, 'mcp/server.js'));",
        "const registry = require(path.join(target, 'mcp/tools/tool-registry.js'));",
        "if (!Array.isArray(server.TOOLS) || server.TOOLS.length < 1) process.exit(62);",
        "if (JSON.stringify(server.TOOLS.map((tool) => tool.name)) !== JSON.stringify(registry.TOOLS.map((tool) => tool.name))) process.exit(63);",
        "const removed = require(path.join(root, 'scripts/lifecycle.js')).uninstallProject(target, { sourceRoot: root, adapter: 'generic-mcp', dryRun: false, onAdapterResolution() {} });",
        "if (!removed.ok || require('node:fs').existsSync(path.join(target, 'mcp/server.js'))) process.exit(64);",
        "process.stdout.write(JSON.stringify({ version: result.version, tool_count: server.TOOLS.length, uninstalled: true }));",
      ].join("\n"),
      ROOT,
      workspace,
    ], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome, NODE_OPTIONS: "" },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const result = JSON.parse(output);
    assert.equal(result.version, PACKAGE_VERSION);
    assert.ok(result.tool_count > 0);
    assert.equal(result.uninstalled, true);
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
});

test("direct streaming aborts an append beyond the preflight size before writing it", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-stream-bound-"));
  const modulesRoot = path.join(tempRoot, "install", "node_modules");
  const sourceRoot = path.join(modulesRoot, "fixture-root");
  const dependency = path.join(modulesRoot, "fixture-stream-dependency");
  const payload = path.join(dependency, "a.bin");
  const targetMcp = path.join(tempRoot, "target", "mcp");
  const foreign = path.join(targetMcp, "node_modules", "foreign", "sentinel.txt");

  try {
    writeRuntimeFixturePackage(sourceRoot, {
      name: "fixture-root",
      version: "1.0.0",
      dependencies: { "fixture-stream-dependency": "1.0.0" },
    });
    writeRuntimeFixturePackage(dependency, {
      name: "fixture-stream-dependency",
      version: "1.0.0",
    }, { "a.bin": "ABCD" });
    fs.mkdirSync(path.dirname(foreign), { recursive: true });
    fs.writeFileSync(foreign, "foreign\n", "utf8");

    const originalOpenSync = fs.openSync;
    const originalReadSync = fs.readSync;
    let payloadDescriptor = null;
    let payloadReads = 0;
    fs.openSync = (filePath, ...args) => {
      const descriptor = Reflect.apply(originalOpenSync, fs, [filePath, ...args]);
      if (path.resolve(String(filePath)) === path.resolve(payload)) {
        payloadDescriptor = descriptor;
      }
      return descriptor;
    };
    fs.readSync = (descriptor, ...args) => {
      if (descriptor === payloadDescriptor) {
        payloadReads += 1;
        if (payloadReads === 2) fs.appendFileSync(payload, "X", "utf8");
      }
      return Reflect.apply(originalReadSync, fs, [descriptor, ...args]);
    };
    try {
      assert.throws(
        () => copyRuntimeNodeDependencies(sourceRoot, targetMcp),
        (error) => error && error.code === "runtime_dependency_source_rejected"
          && error.reason_code === "package_file_bound_exceeded",
      );
    } finally {
      fs.openSync = originalOpenSync;
      fs.readSync = originalReadSync;
    }
    assert.equal(payloadReads, 2);
    assert.ok(!fs.existsSync(path.join(
      targetMcp,
      "node_modules",
      "fixture-stream-dependency",
      "a.bin",
    )));
    assert.equal(fs.readFileSync(foreign, "utf8"), "foreign\n");
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("all dependency destinations are validated before the first direct removal", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-target-preflight-"));
  const modulesRoot = path.join(tempRoot, "install", "node_modules");
  const sourceRoot = path.join(modulesRoot, "fixture-root");
  const alpha = path.join(modulesRoot, "fixture-alpha");
  const beta = path.join(modulesRoot, "fixture-beta");
  const targetMcp = path.join(tempRoot, "target", "mcp");
  const installedAlpha = path.join(targetMcp, "node_modules", "fixture-alpha");
  const installedBeta = path.join(targetMcp, "node_modules", "fixture-beta");
  const alphaSentinel = path.join(installedAlpha, "sentinel.txt");
  const foreign = path.join(tempRoot, "foreign-beta");

  try {
    writeRuntimeFixturePackage(sourceRoot, {
      name: "fixture-root",
      version: "1.0.0",
      dependencies: {
        "fixture-alpha": "1.0.0",
        "fixture-beta": "1.0.0",
      },
    });
    writeRuntimeFixturePackage(alpha, {
      name: "fixture-alpha",
      version: "1.0.0",
    });
    writeRuntimeFixturePackage(beta, {
      name: "fixture-beta",
      version: "1.0.0",
    });
    fs.mkdirSync(installedAlpha, { recursive: true });
    fs.writeFileSync(alphaSentinel, "must-survive\n", "utf8");
    fs.mkdirSync(foreign, { recursive: true });
    fs.symlinkSync(foreign, installedBeta, "dir");

    assert.throws(
      () => copyRuntimeNodeDependencies(sourceRoot, targetMcp),
      (error) => error && error.code === "runtime_dependency_target_rejected"
        && error.reason_code === "target_destination_nonregular",
    );
    assert.equal(fs.readFileSync(alphaSentinel, "utf8"), "must-survive\n");
    assert.deepEqual(fs.readdirSync(foreign), []);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("PRE-FLIGHT atomicity: a stale bounty_* permission with no canonical twin aborts BEFORE any file is copied", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-preflight-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(path.join(workspace, ".claude"), { recursive: true });
  // An operator's existing settings pinning a REMOVED bounty_* tool (no bob_* twin). The legacy
  // permission migration THROWS during the settings merge — which runs AFTER the runtime/agents/
  // hooks are copied. The pre-flight must catch it BEFORE the first mutation, leaving the target
  // untouched (no half-upgraded project).
  const settingsPath = path.join(workspace, ".claude", "settings.json");
  const original = `${JSON.stringify({
    permissions: { allow: ["mcp__hacker-bob__bounty_report_written", "Read"] },
    customSetting: true,
  }, null, 2)}\n`;
  fs.writeFileSync(settingsPath, original, "utf8");
  try {
    assert.throws(
      () => installProject(workspace, { adapter: "claude", sourceRoot: ROOT, onAdapterResolution: () => {} }),
      /stale MCP permission|no canonical replacement|bounty_\* tool alias/i,
    );
    // ATOMICITY: nothing Bob-owned was created — the doomed install never touched the target.
    assert.ok(!fs.existsSync(path.join(workspace, "mcp", "server.js")), "no MCP runtime copied");
    assert.ok(!fs.existsSync(path.join(workspace, ".hacker-bob")), "no .hacker-bob resources");
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "bob")), "no .claude/bob metadata");
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills")), "no skills copied");
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "agents")), "no agents copied");
    // The operator's settings.json is left EXACTLY as it was (not migrated/overwritten).
    assert.equal(fs.readFileSync(settingsPath, "utf8"), original);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("installer copies a require-able complete MCP runtime", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-install-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    update.writeUpdateCache(workspace, {
      schema_version: 1,
      package_name: "hacker-bob",
      install_target: workspace,
      installed_version: "1.0.0",
      latest_version: "1.3.0",
      update_available: true,
      legacy_install: false,
      checked_at: new Date(1000).toISOString(),
      checked_at_ms: 1000,
      error: null,
    }, { homeDir: tempHome });

    installWithTestHome(workspace, tempHome);
    assert.equal(update.readUpdateCache(workspace, { homeDir: tempHome }), null);

    const installedServer = path.join(workspace, "mcp", "server.js");
    assert.ok(fs.existsSync(installedServer));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "redaction.js")));
    // The installer ships an EXPLICIT manifest of top-level mcp/ runtime files (deny-by-default).
    // Guard BOTH regressions the manifest-vs-glob review raised:
    //  (1) the manifest EQUALS the real source top-level mcp/*.js — a NEW runtime file (as
    //      browser-driver.js, the DRIVER_SCRIPT_PATH server.js spawns, once was) or a DELETION makes
    //      manifest != source and fails here, closing the silent-drift gap that broke authed_fetch (#155);
    //  (2) the INSTALLED top-level mcp/*.js EQUALS the manifest — a dropped OR a stray file fails too.
    const { MCP_TOP_LEVEL_RUNTIME_FILES } = require("../scripts/install.js");
    const topLevelJs = (dir) => fs.readdirSync(dir)
      .filter((name) => name.endsWith(".js") && fs.statSync(path.join(dir, name)).isFile())
      .sort();
    const manifest = [...MCP_TOP_LEVEL_RUNTIME_FILES].sort();
    // Drift guard: the manifest must list exactly the real top-level mcp/*.js, so a NEW runtime file
    // (as browser-driver.js once was) or a deletion forces a manifest update instead of silently
    // shipping the wrong set — the drift that froze the operational driver.
    assert.deepEqual(topLevelJs(path.join(ROOT, "mcp")), manifest,
      "MCP_TOP_LEVEL_RUNTIME_FILES must equal the real top-level mcp/*.js — update the manifest when a runtime file is added/removed");
    // Ship guard: every manifest runtime file is installed. A SUPERSET check, not equality — the
    // installer never deletes target files it did not place, so it must not assert the target holds
    // ONLY these (a user's own top-level mcp/*.js is legitimately preserved).
    for (const name of manifest) {
      assert.ok(fs.existsSync(path.join(workspace, "mcp", name)), `installer must copy top-level mcp/${name}`);
    }
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "core", "dispatch", "dispatch.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "tools", "index.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "core", "egress-profiles.js")));
    for (const relativeRoot of CANONICAL_RUNTIME_PACKAGE_ROOTS) {
      const expected = sourceTreeFiles(ROOT, relativeRoot)
        .filter(isCanonicalRuntimePackageFile)
        .map((file) => file.slice(relativeRoot.length + 1));
      const installed = sourceTreeFiles(workspace, relativeRoot)
        .map((file) => file.slice(relativeRoot.length + 1));
      assert.deepEqual(
        installed,
        expected,
        `${relativeRoot} install surface must exactly mirror the canonical packaged runtime`,
      );
    }
    assert.ok(
      !fs.existsSync(path.join(workspace, ".hacker-bob", "optional-providers")),
      "ordinary install must not auto-install or stage optional provider packages",
    );
    assert.ok(fs.existsSync(path.join(
      workspace,
      "packages",
      "bob-instrument-broker",
      "lib",
      "resource-reservations.js",
    )));
    assert.ok(!fs.existsSync(path.join(
      workspace,
      "packages",
      "bob-instrument-broker",
      "test",
    )));
    const runtimeDoctorCheck = () => doctorProject(workspace, {
      adapter: "claude",
      onAdapterResolution: () => {},
      sourceRoot: ROOT,
    }).checks.find((check) => check.id === "bob_owned_runtime_integrity");
    const brokerRuntime = path.join(
      workspace,
      "packages",
      "bob-instrument-broker",
      "lib",
      "broker.js",
    );
    const sourceBrokerRuntime = path.join(
      ROOT,
      "packages",
      "bob-instrument-broker",
      "lib",
      "broker.js",
    );
    const originalBrokerBytes = fs.readFileSync(brokerRuntime);
    const originalBrokerMode = fs.statSync(brokerRuntime).mode & 0o777;
    let runtimeCheck = runtimeDoctorCheck();
    assert.equal(runtimeCheck.status, "ok");
    assert.equal(runtimeCheck.detail.coverage, "bob_owned_runtime_only");
    const installedCompatibilityStore = path.join(workspace, "mcp", "domains", "physical", "instrument-lease-store.js");
    const installedCanonicalStore = path.join(
      workspace,
      "packages",
      "bob-instrument-broker",
      "lib",
      "instrument-lease-store.js",
    );
    assert.equal(require(installedCompatibilityStore), require(installedCanonicalStore));
    assert.ok(fs.statSync(installedCompatibilityStore).size < 256);
    assert.ok(fs.statSync(installedCanonicalStore).size > 200_000);
    const expectedInstalledEntrypoints = declaredRuntimeEntrypoints(
      workspace,
      CANONICAL_RUNTIME_PACKAGE_ROOTS,
    );
    assert.equal(
      expectedInstalledEntrypoints.length,
      57,
      "project-local install must retain every canonical physical package entrypoint",
    );
    const installedEntrypoints = loadCanonicalRuntimeEntrypoints({
      runtimeRoot: workspace,
      relativeRoots: CANONICAL_RUNTIME_PACKAGE_ROOTS,
      isolatedHome: path.join(tempHome, "canonical-entrypoint-loader"),
    });
    assert.deepEqual(installedEntrypoints.loaded, expectedInstalledEntrypoints);
    for (const entry of expectedInstalledEntrypoints) {
      assert.ok(
        installedEntrypoints.resolved_modules.includes(entry.entrypoint),
        `${entry.entrypoint} must load from the doctor-qualified project-local runtime`,
      );
    }

    fs.writeFileSync(brokerRuntime, "\"use strict\";\nmodule.exports = {};\n", "utf8");
    runtimeCheck = runtimeDoctorCheck();
    assert.equal(runtimeCheck.status, "error");
    assert.ok(runtimeCheck.detail.diagnostics.digest_mismatch.includes(
      "packages/bob-instrument-broker/lib/broker.js"));
    fs.writeFileSync(brokerRuntime, originalBrokerBytes);
    fs.chmodSync(brokerRuntime, originalBrokerMode);

    fs.rmSync(brokerRuntime);
    runtimeCheck = runtimeDoctorCheck();
    assert.equal(runtimeCheck.status, "error");
    assert.ok(runtimeCheck.detail.diagnostics.missing.includes(
      "packages/bob-instrument-broker/lib/broker.js"));
    fs.writeFileSync(brokerRuntime, originalBrokerBytes);
    fs.chmodSync(brokerRuntime, originalBrokerMode);

    const extraRuntime = path.join(path.dirname(brokerRuntime), "undeclared-runtime.js");
    fs.writeFileSync(extraRuntime, "module.exports = {};\n", "utf8");
    runtimeCheck = runtimeDoctorCheck();
    assert.equal(runtimeCheck.status, "error");
    assert.ok(runtimeCheck.detail.diagnostics.extra.includes(
      "packages/bob-instrument-broker/lib/undeclared-runtime.js"));
    fs.rmSync(extraRuntime);

    fs.rmSync(brokerRuntime);
    fs.symlinkSync(sourceBrokerRuntime, brokerRuntime);
    runtimeCheck = runtimeDoctorCheck();
    assert.equal(runtimeCheck.status, "error");
    assert.ok(runtimeCheck.detail.diagnostics.non_regular.some((issue) => (
      issue.path === "packages/bob-instrument-broker/lib/broker.js"
      && issue.observed_type === "symlink"
    )));
    fs.rmSync(brokerRuntime);
    fs.writeFileSync(brokerRuntime, originalBrokerBytes);
    fs.chmodSync(brokerRuntime, originalBrokerMode);

    fs.chmodSync(brokerRuntime, originalBrokerMode === 0o600 ? 0o644 : 0o600);
    runtimeCheck = runtimeDoctorCheck();
    assert.equal(runtimeCheck.status, "error");
    assert.ok(runtimeCheck.detail.diagnostics.mode_mismatch.some((issue) => (
      issue.path === "packages/bob-instrument-broker/lib/broker.js"
    )));
    fs.chmodSync(brokerRuntime, originalBrokerMode);
    assert.equal(runtimeDoctorCheck().status, "ok");
    const dependencyCustodyCheck = doctorProject(workspace, {
      adapter: "claude",
      onAdapterResolution: () => {},
      sourceRoot: ROOT,
    }).checks.find((check) => check.id === "runtime_dependency_custody");
    assert.equal(dependencyCustodyCheck.status, "warn");
    assert.deepEqual(dependencyCustodyCheck.detail, {
      coverage: "unverified_transitive_dependencies",
      integrity_verified: false,
      same_uid_race_qualified: false,
      crash_atomic: false,
      descriptor_relative_custody: false,
      stale_dependency_pruning: false,
      foreign_package_pruning: false,
      npm_bin_shims_generated: false,
    });
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "node_modules", "psl", "dist", "psl.cjs")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "node_modules", "proxy-agent", "dist", "index.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "node_modules", "punycode", "punycode.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-update.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-egress.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-export.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-evaluate.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "evaluate.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "status.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "debug.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "update.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bountyagent.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bountyagentdebug.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-evaluate-runner", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-status", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-debug", "SKILL.md")));
    // Legacy skill dirs must not be present — they would surface as duplicate
    // /bob-evaluate slash-picker entries with orchestrator-prose descriptions.
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bob-hunt", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagent", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagentstatus", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagentdebug", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "agent-run-stop.js")));
    assert.ok(
      fs.existsSync(path.join(workspace, ".claude", "agents", `${FANOUT_ROLE_REGISTRY.child.subagent_type}.md`)),
      "installer must ship the distinct fanout child role",
    );
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-egress.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-export.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-update.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-check-update.js")));
    // CR-2: the write-guard classification manifest must be installed beside the
    // hook, or the hook's fail-closed branch blocks every session write.
    assert.ok(
      fs.existsSync(path.join(workspace, ".claude", "hooks", "write-guard-tables.json")),
      "write-guard-tables.json must be installed beside session-write-guard.sh",
    );
    // And it must NOT be executable (it is hook DATA, not a hook).
    {
      const m = fs.statSync(path.join(workspace, ".claude", "hooks", "write-guard-tables.json")).mode;
      assert.equal(m & 0o111, 0, "write-guard-tables.json must not be executable");
    }
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-update-lib.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "core", "update-check.js")));
    assert.ok(fs.existsSync(path.join(workspace, "mcp", "core", "bob-export.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".hacker-bob", "knowledge", "evaluator-techniques.json")));
    assert.ok(fs.existsSync(path.join(workspace, ".hacker-bob", "bypass-tables", "rest-api.txt")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "knowledge")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "bypass-tables")));
    assert.ok(fs.existsSync(path.join(workspace, "testing", "policy-replay", "replay.mjs")));
    assert.ok(fs.existsSync(path.join(workspace, "testing", "policy-replay", "tune.mjs")));
    assert.ok(fs.existsSync(path.join(workspace, "testing", "policy-replay", "cases", "sample-evaluator-refusal.json")));
    assert.ok(!fs.existsSync(path.join(workspace, "testing", "policy-replay", "node_modules")));

    const { createRequire } = require("node:module");
    const installedRequire = createRequire(installedServer);
    assert.ok(
      installedRequire.resolve("@anthropic-ai/claude-agent-sdk"),
      "Claude Agent SDK must resolve from <workspace>/mcp/server.js so policy-replay's fallback can find it",
    );
    for (const requiredRuntime of [
      "@anthropic-ai/sdk",
      "@modelcontextprotocol/sdk/client",
      "@modelcontextprotocol/sdk/server",
      "zod",
      "quickjs-wasi",
    ]) {
      assert.ok(
        installedRequire.resolve(requiredRuntime),
        `${requiredRuntime} must resolve from the installed MCP runtime dependency graph`,
      );
    }

    const sourceSdkManifestPath = path.join(ROOT, "node_modules", "@anthropic-ai", "claude-agent-sdk", "package.json");
    if (fs.existsSync(sourceSdkManifestPath)) {
      const sdkOptionalDeps = JSON.parse(fs.readFileSync(sourceSdkManifestPath, "utf8")).optionalDependencies || {};
      const platformKey = `${process.platform}-${process.arch}`;
      const currentPlatformPackages = Object.keys(sdkOptionalDeps).filter((name) => name.includes(platformKey));
      for (const platformPackage of currentPlatformPackages) {
        const sourcePackageDir = path.join(ROOT, "node_modules", ...platformPackage.split("/"));
        if (!fs.existsSync(sourcePackageDir)) continue;
        const targetPackageDir = path.join(workspace, "mcp", "node_modules", ...platformPackage.split("/"));
        assert.ok(
          fs.existsSync(targetPackageDir),
          `Source has ${platformPackage}; copyRuntimeNodeDependencies must propagate it into <workspace>/mcp/node_modules so live replay can invoke the SDK`,
        );
      }
    }
    assert.equal(fs.readFileSync(path.join(workspace, ".hacker-bob", "VERSION"), "utf8").trim(), PACKAGE_VERSION);
    const neutralInstallMeta = JSON.parse(fs.readFileSync(path.join(workspace, ".hacker-bob", "install.json"), "utf8"));
    assert.equal(neutralInstallMeta.schema_version, 2);
    assert.equal(neutralInstallMeta.bob_version, PACKAGE_VERSION);
    assert.equal(neutralInstallMeta.package_name, "hacker-bob");
    assert.equal(neutralInstallMeta.install_target, workspace);
    assert.deepEqual(neutralInstallMeta.installed_adapters, ["claude"]);
    // Y.10 (Y-D12 / D6 + D14) — install provisions the operator session-cap
    // nonce at $HOME/.bob/session-cap (mode 0600) so partial-surface
    // acknowledgement attestation_tokens have an authoritative nonce to
    // match against. Without this, the OPEN_FRONTIER -> CLAIM_FREEZE gate
    // would accept any non-empty token as authority.
    const sessionCapFile = path.join(tempHome, ".bob", "session-cap");
    assert.ok(fs.existsSync(sessionCapFile), "install must provision ~/.bob/session-cap nonce");
    const sessionCapStat = fs.statSync(sessionCapFile);
    assert.equal(sessionCapStat.mode & 0o777, 0o600, "session-cap file mode must be 0600");
    const sessionCapValue = fs.readFileSync(sessionCapFile, "utf8").trim();
    assert.match(sessionCapValue, /^[0-9a-f]{64}$/, "session-cap nonce must be 64-char hex");

    assert.equal(fs.readFileSync(path.join(workspace, ".claude", "bob", "VERSION"), "utf8").trim(), PACKAGE_VERSION);
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "bob", "egress-profiles.example.json")));
    const egressConfig = JSON.parse(fs.readFileSync(path.join(workspace, ".claude", "bob", "egress-profiles.json"), "utf8"));
    assert.equal(egressConfig.profiles.find((profile) => profile.name === "default").proxy_url, null);
    const settings = JSON.parse(fs.readFileSync(path.join(workspace, ".claude", "settings.json"), "utf8"));
    const settingsText = JSON.stringify(settings);
    assert.match(settingsText, /\$\{CLAUDE_PROJECT_DIR:-\$PWD\}/);
    assert.doesNotMatch(settingsText, /\$CLAUDE_PROJECT_DIR(?!:-)/);
    const childStop = (settings.hooks.SubagentStop || []).filter((entry) => (
      entry.matcher === FANOUT_ROLE_REGISTRY.child.subagent_type
      && (entry.hooks || []).some((hook) => /agent-run-stop\.js/.test(hook.command))
    ));
    assert.equal(childStop.length, 1, "installed child must be transcript-attested by exactly one SubagentStop hook");
    assert.equal(
      (settings.hooks.SubagentStart || []).some((entry) => entry.matcher === FANOUT_ROLE_REGISTRY.child.subagent_type),
      false,
      "installed child must never receive the shared-root AgentRun start hook",
    );
    const installMeta = JSON.parse(fs.readFileSync(path.join(workspace, ".claude", "bob", "install.json"), "utf8"));
    assert.equal(installMeta.schema_version, 1);
    assert.equal(installMeta.bob_version, PACKAGE_VERSION);
    assert.equal(installMeta.package_name, "hacker-bob");
    assert.equal(installMeta.install_target, workspace);

    const statuslinePath = path.join(workspace, ".claude", "hooks", "bob-statusline.js");
    const nestedWorkspaceDir = path.join(workspace, "nested");
    fs.mkdirSync(nestedWorkspaceDir, { recursive: true });
    const runStatusline = () => execFileSync(process.execPath, [statuslinePath], {
      cwd: nestedWorkspaceDir,
      env: { ...process.env, HOME: tempHome, CLAUDE_PROJECT_DIR: workspace },
      input: JSON.stringify({
        model: { display_name: "Claude" },
        workspace: { current_dir: nestedWorkspaceDir },
      }),
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    });

    update.writeUpdateCache(workspace, {
      schema_version: 1,
      package_name: "hacker-bob",
      install_target: workspace,
      installed_version: "1.0.0",
      latest_version: "1.3.0",
      update_available: true,
      legacy_install: false,
      checked_at: new Date().toISOString(),
      checked_at_ms: Date.now(),
      error: null,
    }, { homeDir: tempHome });
    assert.doesNotMatch(runStatusline(), /Bob 1\.3\.0|Update Bob|bob-update/);

    update.writeUpdateCache(workspace, {
      schema_version: 1,
      package_name: "hacker-bob",
      install_target: workspace,
      installed_version: PACKAGE_VERSION,
      latest_version: "99.0.0",
      update_available: true,
      legacy_install: false,
      checked_at: new Date().toISOString(),
      checked_at_ms: Date.now(),
      error: null,
    }, { homeDir: tempHome });
    assert.match(runStatusline(), /Update Bob to 99\.0\.0: \/bob-update/);

    execFileSync(process.execPath, [
      "-e",
      [
        "const server = require(process.argv[1]);",
        "const installedRequire = require('module').createRequire(process.argv[1]);",
        "const installedRegistry = installedRequire('./tools/tool-registry.js');",
        "installedRequire('psl');",
        "installedRequire('proxy-agent');",
        "if (!Array.isArray(server.TOOLS) || server.TOOLS.length < 1) process.exit(2);",
        "if (JSON.stringify(server.TOOLS.map((tool) => tool.name)) !== JSON.stringify(installedRegistry.TOOLS.map((tool) => tool.name))) process.exit(55);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_init_physical_session')) process.exit(54);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_stage_verification_round_partial')) process.exit(53);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_plan_recon_angles')) process.exit(52);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_register_mechanism_template')) process.exit(51);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_http_confirm')) process.exit(42);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_http_cors_confirm')) process.exit(49);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_http_massread_confirm')) process.exit(50);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_http_idor_confirm')) process.exit(43);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_http_xss_reflect')) process.exit(44);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_http_xss_confirm')) process.exit(45);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_oob_mint')) process.exit(46);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_oob_poll')) process.exit(47);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_nuclei_scan')) process.exit(48);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_import_harness')) process.exit(50);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_ingest_sarif')) process.exit(40);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_read_static_analysis_index')) process.exit(41);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_list_auth_profiles')) process.exit(3);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_materialize_task_graph')) process.exit(33);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_read_task_graph')) process.exit(34);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_attach_contract')) process.exit(35);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_prepare_node')) process.exit(36);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_finalize_node')) process.exit(37);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_schedule_graph_nodes')) process.exit(38);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_repo_inventory')) process.exit(29);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_repo_prepare_env')) process.exit(30);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_repo_docker_run')) process.exit(31);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_repo_check')) process.exit(32);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_finalize_report')) process.exit(25);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_read_tool_telemetry')) process.exit(6);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_read_pipeline_analytics')) process.exit(7);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_finalize_agent_run')) process.exit(8);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_write_evidence_packs')) process.exit(9);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_read_evidence_packs')) process.exit(10);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_write_proof_bundle')) process.exit(39);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_promote_surface_leads')) process.exit(11);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_read_session_summary')) process.exit(12);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_set_operator_note')) process.exit(13);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_clear_operator_note')) process.exit(14);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_route_surfaces')) process.exit(15);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_read_surface_routes')) process.exit(16);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_start_next_wave')) process.exit(17);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_select_technique_packs')) process.exit(18);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_read_technique_pack')) process.exit(19);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_log_technique_attempt')) process.exit(20);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_get_context_budget')) process.exit(21);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_read_verification_context')) process.exit(22);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_build_verification_adjudication')) process.exit(23);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_browser_session_start')) process.exit(26);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_browser_evaluate')) process.exit(27);",
        "if (!server.TOOLS.some((tool) => tool.name === 'bob_browser_session_close')) process.exit(28);",
        "Promise.resolve(server.executeTool('bob_init_session', { target_domain: 'example.com', target_url: 'https://example.com/' }))",
        "  .then((init) => { if (!init.ok) process.exit(24); return server.executeTool('bob_list_auth_profiles', { target_domain: 'example.com' }); })",
        "  .then((result) => { if (!result.ok || result.data.target_domain !== 'example.com') process.exit(4); })",
        "  .catch(() => process.exit(5));",
      ].join(" "),
      installedServer,
    ], { env: { ...process.env, HOME: tempHome }, stdio: "pipe" });
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("doctor accepts legacy-only resources and uninstall removes legacy resource copies", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-legacy-resources-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    execFileSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });

    fs.mkdirSync(path.join(workspace, ".claude"), { recursive: true });
    fs.renameSync(
      path.join(workspace, ".hacker-bob", "knowledge"),
      path.join(workspace, ".claude", "knowledge"),
    );
    fs.renameSync(
      path.join(workspace, ".hacker-bob", "bypass-tables"),
      path.join(workspace, ".claude", "bypass-tables"),
    );

    let doctorOutput;
    try {
      doctorOutput = execFileSync(process.execPath, [CLI, "doctor", workspace, "--json"], {
        cwd: ROOT,
        env: { ...process.env, HOME: tempHome },
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (error) {
      const stdout = typeof error.stdout === "string" ? error.stdout : "";
      const stderr = typeof error.stderr === "string" ? error.stderr : "";
      assert.fail(`legacy-resource doctor failed\nstdout:\n${stdout}\nstderr:\n${stderr}`);
    }
    const doctor = JSON.parse(doctorOutput);
    assert.equal(doctor.ok, true);
    assert.equal(doctor.checks.find((check) => check.id === "resource_knowledge").status, "warn");
    assert.equal(doctor.checks.find((check) => check.id === "resource_bypass_tables").status, "warn");

    const foreignDependency = path.join(
      workspace,
      "mcp",
      "node_modules",
      "operator-foreign-package",
      "sentinel.txt",
    );
    const operatorBin = path.join(
      workspace,
      "mcp",
      "node_modules",
      ".bin",
      "operator-tool",
    );
    const installedTransitive = path.join(
      workspace,
      "mcp",
      "node_modules",
      "psl",
      "package.json",
    );
    fs.mkdirSync(path.dirname(foreignDependency), { recursive: true });
    fs.mkdirSync(path.dirname(operatorBin), { recursive: true });
    fs.writeFileSync(foreignDependency, "foreign\n", "utf8");
    fs.writeFileSync(operatorBin, "operator-bin\n", "utf8");
    assert.ok(fs.existsSync(installedTransitive));

    const uninstallOutput = execFileSync(process.execPath, [CLI, "uninstall", workspace, "--yes", "--json"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const uninstall = JSON.parse(uninstallOutput);
    assert.equal(uninstall.dry_run, false);
    assert.ok(uninstall.actions.some((action) => action.path === path.join(".claude", "knowledge", "evaluator-techniques.json")));
    assert.ok(uninstall.actions.some((action) => action.path === path.join(".claude", "bypass-tables", "rest-api.txt")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "knowledge", "evaluator-techniques.json")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "bypass-tables", "rest-api.txt")));
    assert.equal(fs.readFileSync(foreignDependency, "utf8"), "foreign\n");
    assert.equal(fs.readFileSync(operatorBin, "utf8"), "operator-bin\n");
    assert.ok(fs.existsSync(installedTransitive));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("installer merges existing MCP/settings config idempotently", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-install-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(path.join(workspace, ".claude", "knowledge"), { recursive: true });
  fs.mkdirSync(path.join(workspace, ".claude", "bypass-tables"), { recursive: true });
  fs.mkdirSync(path.join(workspace, ".claude", "hooks"), { recursive: true });
  fs.mkdirSync(path.join(workspace, ".claude", "commands", "bob"), { recursive: true });
  fs.mkdirSync(path.join(workspace, ".claude", "skills", "bountyagent"), { recursive: true });
  fs.mkdirSync(path.join(workspace, ".claude", "skills", "bountyagentstatus"), { recursive: true });
  fs.mkdirSync(path.join(workspace, ".claude", "skills", "bountyagentdebug"), { recursive: true });

  try {
    fs.writeFileSync(path.join(workspace, ".claude", "knowledge", "evaluator-techniques.json"), "{}\n");
    fs.writeFileSync(path.join(workspace, ".claude", "knowledge", "custom.json"), "{}\n");
    fs.writeFileSync(path.join(workspace, ".claude", "bypass-tables", "rest-api.txt"), "old\n");
    fs.writeFileSync(path.join(workspace, ".claude", "bypass-tables", "custom.txt"), "custom\n");
    fs.writeFileSync(path.join(workspace, ".claude", "hooks", "bob-update-lib.js"), "old\n");
    fs.writeFileSync(path.join(workspace, ".claude", "commands", "bob", "evaluate.md"), "old\n");
    fs.writeFileSync(path.join(workspace, ".claude", "commands", "bob", "status.md"), "old\n");
    fs.writeFileSync(path.join(workspace, ".claude", "commands", "bob", "debug.md"), "old\n");
    fs.writeFileSync(path.join(workspace, ".claude", "commands", "bob", "update.md"), "old\n");
    fs.writeFileSync(path.join(workspace, ".claude", "skills", "bountyagent", "SKILL.md"), "old\n");
    fs.writeFileSync(path.join(workspace, ".claude", "skills", "bountyagentstatus", "SKILL.md"), "old\n");
    fs.writeFileSync(path.join(workspace, ".claude", "skills", "bountyagentdebug", "SKILL.md"), "old\n");
    fs.writeFileSync(path.join(workspace, ".mcp.json"), `${JSON.stringify({
      mcpServers: {
        existing: { command: "node", args: ["existing.js"] },
      },
    }, null, 2)}\n`);
    fs.writeFileSync(path.join(workspace, ".claude", "settings.json"), `${JSON.stringify({
      permissions: {
        allow: [
          "Read",
          "custom-tool",
          "mcp__bountyagent__bob_merge_wave_handoffs",
          "mcp__bountyagent__custom_user_tool",
          "mcp__hacker-bob__pre_migration_custom",
        ],
      },
      hooks: {
        SessionStart: [{
          matcher: "startup",
          hooks: [
            { type: "command", command: "echo existing session", timeout: 1 },
            { type: "command", command: "node \"$CLAUDE_PROJECT_DIR/.claude/hooks/bob-check-update.js\" \"$CLAUDE_PROJECT_DIR\"", timeout: 2 },
          ],
        }],
        PreToolUse: [{
          matcher: "Bash",
          hooks: [{ type: "command", command: "echo existing", timeout: 1 }],
        }],
        SubagentStop: [{
          matcher: "evaluator-agent",
          hooks: [{ type: "command", command: "echo existing stop", timeout: 1 }],
        }],
      },
      statusLine: {
        type: "command",
        command: "node \"$CLAUDE_PROJECT_DIR/.claude/hooks/bob-statusline.js\"",
      },
      customSetting: true,
    }, null, 2)}\n`);

    for (let index = 0; index < 2; index += 1) {
      installWithTestHome(workspace, tempHome);
      if (index === 0) {
        fs.writeFileSync(path.join(workspace, ".claude", "bob", "egress-profiles.json"), `${JSON.stringify({
          version: 1,
          profiles: [
            { name: "default", proxy_url: null, region: null, description: "Direct", enabled: true },
            { name: "operator", proxy_url: "${BOB_EGRESS_OPERATOR_PROXY}", region: "EU", description: "Operator-owned", enabled: true },
          ],
        }, null, 2)}\n`);
      }
    }

    const mcp = JSON.parse(fs.readFileSync(path.join(workspace, ".mcp.json"), "utf8"));
    assert.ok(mcp.mcpServers.existing);
    // Migration shim rewrites the legacy `bountyagent` key to `hacker-bob`.
    assert.ok(mcp.mcpServers["hacker-bob"]);
    assert.ok(!mcp.mcpServers.bountyagent, "migration shim must remove legacy bountyagent server key");

    const settings = JSON.parse(fs.readFileSync(path.join(workspace, ".claude", "settings.json"), "utf8"));
    const settingsText = JSON.stringify(settings);
    assert.match(settingsText, /\$\{CLAUDE_PROJECT_DIR:-\$PWD\}/);
    assert.doesNotMatch(settingsText, /\$CLAUDE_PROJECT_DIR(?!:-)/);
    assert.equal(settings.customSetting, true);
    assert.equal(settings.permissions.allow.length, new Set(settings.permissions.allow).size);
    assert.ok(settings.permissions.allow.includes("custom-tool"));
    // Migration shim rewrites mcp__bountyagent__* permission strings to mcp__hacker-bob__*.
    assert.ok(settings.permissions.allow.includes("mcp__hacker-bob__custom_user_tool"));
    assert.ok(!settings.permissions.allow.includes("mcp__bountyagent__custom_user_tool"));
    assert.ok(settings.permissions.allow.includes("mcp__hacker-bob__bob_http_scan"));
    // The pre-migration custom permission is idempotently preserved.
    assert.ok(settings.permissions.allow.includes("mcp__hacker-bob__pre_migration_custom"));
    // Stale legacy permission strings are dropped (both forms).
    assert.ok(!settings.permissions.allow.includes("mcp__bountyagent__bob_merge_wave_handoffs"));
    assert.ok(!settings.permissions.allow.includes("mcp__hacker-bob__bob_merge_wave_handoffs"));
    assert.match(settings.statusLine.command, /\$\{CLAUDE_PROJECT_DIR:-\$PWD\}/);

    const bashEntry = settings.hooks.PreToolUse.find((entry) => entry.matcher === "Bash");
    assert.ok(bashEntry);
    assert.ok(bashEntry.hooks.some((hook) => hook.command === "echo existing"));
    assert.equal(
      bashEntry.hooks.filter((hook) => /session-write-guard\.sh/.test(hook.command)).length,
      1,
    );
    // Edit/MultiEdit must route through the write guard too — otherwise Edit is
    // an unguarded write path to MCP-owned/audit-graded session artifacts.
    const editEntry = settings.hooks.PreToolUse.find((entry) => entry.matcher === "Edit|MultiEdit");
    assert.ok(editEntry, "Edit|MultiEdit guard matcher must survive the merge");
    assert.equal(
      editEntry.hooks.filter((hook) => /session-write-guard\.sh/.test(hook.command)).length,
      1,
    );
    // The write-confirm gate matcher ships in the canonical source settings and merges into an
    // existing target exactly once (deduped), pointing at the bob-http-write-confirm.sh hook.
    const scanEntries = settings.hooks.PreToolUse.filter((entry) => entry.matcher === "mcp__hacker-bob__bob_http_scan");
    assert.equal(scanEntries.length, 1);
    assert.equal(
      scanEntries[0].hooks.filter((hook) => /bob-http-write-confirm\.sh/.test(hook.command)).length,
      1,
    );
    const stopEntry = settings.hooks.SubagentStop.find((entry) => entry.matcher === "evaluator-agent");
    assert.ok(stopEntry);
    assert.ok(stopEntry.hooks.some((hook) => hook.command === "echo existing stop"));
    assert.equal(
      stopEntry.hooks.filter((hook) => /agent-run-stop\.js/.test(hook.command)).length,
      1,
    );
    const sessionEntry = settings.hooks.SessionStart.find((entry) => entry.matcher === "startup");
    assert.ok(sessionEntry);
    assert.ok(sessionEntry.hooks.some((hook) => hook.command === "echo existing session"));
    assert.equal(
      sessionEntry.hooks.filter((hook) => /bob-check-update\.js/.test(hook.command)).length,
      1,
    );
    assert.ok(fs.existsSync(path.join(workspace, ".hacker-bob", "knowledge", "evaluator-techniques.json")));
    assert.ok(fs.existsSync(path.join(workspace, ".hacker-bob", "bypass-tables", "rest-api.txt")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "knowledge", "evaluator-techniques.json")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "bypass-tables", "rest-api.txt")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "hooks", "bob-update-lib.js")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-update.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-export.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-evaluate.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "evaluate.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "status.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "debug.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob", "update.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagent", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagentstatus", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bountyagentdebug", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bob-hunt", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-evaluate-runner", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-status", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "skills", "bob-debug", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "knowledge", "custom.json")));
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "bypass-tables", "custom.txt")));
    assert.match(sessionEntry.hooks.find((hook) => /bob-check-update\.js/.test(hook.command)).command, /\$\{CLAUDE_PROJECT_DIR:-\$PWD\}/);
    const egressConfig = JSON.parse(fs.readFileSync(path.join(workspace, ".claude", "bob", "egress-profiles.json"), "utf8"));
    assert.ok(egressConfig.profiles.some((profile) => profile.name === "operator"));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("install doctor uninstall dry-run uninstall and reinstall workflow works", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-lifecycle-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    execFileSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    for (const authoringSurface of [
      "mcp/domains/physical/physical-provider-authoring.js",
      "packages/bob-instrument-deterministic/lib/orthogonal-fixture.js",
      ".hacker-bob/docs/provider-authoring.md",
    ]) {
      assert.ok(
        fs.existsSync(path.join(workspace, authoringSurface)),
        `PH-X4 authoring surface ${authoringSurface} must install before doctor`,
      );
    }
    const installedAuthoringGuide = path.join(
      workspace,
      ".hacker-bob",
      "docs",
      "provider-authoring.md",
    );
    fs.writeFileSync(installedAuthoringGuide, "substituted provider guide\n", "utf8");
    let staleGuideDoctorError = null;
    try {
      execFileSync(process.execPath, [CLI, "doctor", workspace], {
        cwd: ROOT,
        env: { ...process.env, HOME: tempHome },
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (error) {
      staleGuideDoctorError = error;
    }
    assert.ok(staleGuideDoctorError, "doctor must reject a substituted installed authoring guide");
    assert.match(
      `${staleGuideDoctorError.stdout || ""}\n${staleGuideDoctorError.stderr || ""}`,
      /install_support_physical_provider_authoring|missing, substituted, or stale/,
    );
    execFileSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    assert.equal(
      fs.readFileSync(installedAuthoringGuide, "utf8"),
      fs.readFileSync(path.join(ROOT, "docs", "provider-authoring.md"), "utf8"),
      "reinstall must restore the exact packaged authoring guide",
    );
    execFileSync(process.execPath, [CLI, "doctor", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    execFileSync(process.execPath, [CLI, "uninstall", workspace, "--dry-run"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    assert.ok(fs.existsSync(path.join(workspace, ".claude", "commands", "bob-update.md")));

    execFileSync(process.execPath, [CLI, "uninstall", workspace, "--yes"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "commands", "bob-update.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".claude", "skills", "bob-evaluate-runner", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, "mcp", "domains", "physical", "physical-provider-authoring.js")));
    assert.ok(!fs.existsSync(path.join(
      workspace,
      "packages",
      "bob-instrument-deterministic",
      "lib",
      "orthogonal-fixture.js",
    )));
    assert.ok(!fs.existsSync(path.join(
      workspace,
      ".hacker-bob",
      "docs",
      "provider-authoring.md",
    )));
    for (const relativeRoot of CANONICAL_RUNTIME_PACKAGE_ROOTS) {
      assert.ok(
        !fs.existsSync(path.join(workspace, relativeRoot)),
        `full uninstall must remove Bob-owned nested runtime root ${relativeRoot}`,
      );
    }

    execFileSync(process.execPath, [CLI, "uninstall", workspace, "--yes"], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });

    execFileSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    execFileSync(process.execPath, [CLI, "doctor", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("reinstall converges Bob-owned MCP surfaces while preserving mixed-ownership siblings", () => {
  // Four contracts at once:
  //  - REFRESH (CodeRabbit/glm round-5): the actual bug was a FROZEN browser-driver.js. copyFile
  //    overwrites, so a reinstall must replace a stale driver with the current source — assert the
  //    seeded-stale content is gone, not just that the file exists.
  //  - PRESERVE (Codex/glm round-4): the installer must NEVER delete a top-level mcp/*.js it did not
  //    place — the target is the user's project. (An earlier "converge to the manifest" cleanup deleted
  //    by negation, which would destroy user files; reverted.)
  //  - CONVERGE: mcp/{core,domains,tools,fuzz,lib} are wholly Bob-owned. Removed
  //    runtime files and nested directories must not survive an upgrade.
  //  - SHARE: mcp/node_modules has separate direct-copy ownership semantics, so a
  //    foreign dependency remains untouched while Bob's dependency graph refreshes.
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-userfile-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });
  const install = () => execFileSync(process.execPath, [CLI, "install", workspace], {
    cwd: ROOT,
    env: { ...process.env, HOME: tempHome },
    stdio: "pipe",
  });
  try {
    install();
    const userFile = path.join(workspace, "mcp", "my-own-mcp-thing.js");
    fs.writeFileSync(userFile, "// a file the user placed in their own mcp/ dir\n");
    const ownershipMetadataPath = path.join(workspace, ".hacker-bob", "install.json");
    const ownershipMetadata = JSON.parse(fs.readFileSync(ownershipMetadataPath, "utf8"));
    const retiredBobTopLevel = path.join(workspace, "mcp", "retired-bob-runtime.js");
    const retiredBobBytes = "module.exports = 'retired Bob runtime';\n";
    fs.writeFileSync(retiredBobTopLevel, retiredBobBytes, "utf8");
    const modifiedFormerBobTopLevel = path.join(
      workspace,
      "mcp",
      "retired-runtime-with-local-edits.js",
    );
    const preEditBobBytes = "module.exports = 'former Bob bytes';\n";
    fs.writeFileSync(
      modifiedFormerBobTopLevel,
      "module.exports = 'operator-owned local replacement';\n",
      "utf8",
    );
    ownershipMetadata.mcp_top_level_runtime_ownership.files.push(
      {
        name: path.basename(retiredBobTopLevel),
        byte_size: Buffer.byteLength(retiredBobBytes),
        sha256: crypto.createHash("sha256").update(retiredBobBytes).digest("hex"),
      },
      {
        name: path.basename(modifiedFormerBobTopLevel),
        byte_size: Buffer.byteLength(preEditBobBytes),
        sha256: crypto.createHash("sha256").update(preEditBobBytes).digest("hex"),
      },
    );
    fs.writeFileSync(
      ownershipMetadataPath,
      `${JSON.stringify(ownershipMetadata, null, 2)}\n`,
      "utf8",
    );
    const driver = path.join(workspace, "mcp", "browser-driver.js");
    const staleMarker = "// STALE driver from an older install — must be overwritten on reinstall\n";
    fs.writeFileSync(driver, staleMarker);
    const retiredV201Modules = [
      "session-root-migration.js",
      "telemetry-migration.js",
    ].map((name) => path.join(workspace, "mcp", "core", name));
    for (const retired of retiredV201Modules) {
      fs.writeFileSync(retired, "module.exports = { stale_v201_runtime: true };\n", "utf8");
    }
    const removedDirectoryFile = path.join(
      workspace,
      "mcp",
      "core",
      "removed-whole-directory",
      "stale-runtime.js",
    );
    fs.mkdirSync(path.dirname(removedDirectoryFile), { recursive: true });
    fs.writeFileSync(removedDirectoryFile, "module.exports = 'stale';\n", "utf8");
    const foreignDependency = path.join(
      workspace,
      "mcp",
      "node_modules",
      "operator-foreign-package",
      "sentinel.txt",
    );
    fs.mkdirSync(path.dirname(foreignDependency), { recursive: true });
    fs.writeFileSync(foreignDependency, "preserve-foreign-dependency\n", "utf8");
    install(); // reinstall over the existing workspace
    assert.ok(fs.existsSync(userFile), "reinstall must NOT delete a top-level mcp/ file Bob did not place");
    assert.equal(
      fs.existsSync(retiredBobTopLevel),
      false,
      "a retired top-level runtime with an exact prior Bob ownership receipt must be pruned",
    );
    assert.equal(
      fs.readFileSync(modifiedFormerBobTopLevel, "utf8"),
      "module.exports = 'operator-owned local replacement';\n",
      "a locally modified former Bob runtime must be preserved when its receipt digest no longer matches",
    );
    const refreshed = fs.readFileSync(driver, "utf8");
    assert.notEqual(refreshed, staleMarker, "reinstall must overwrite a stale browser-driver.js (the frozen-driver bug)");
    assert.equal(refreshed, fs.readFileSync(path.join(ROOT, "mcp", "browser-driver.js"), "utf8"),
      "reinstall must refresh browser-driver.js to the current source version");
    for (const retired of retiredV201Modules) {
      assert.equal(fs.existsSync(retired), false, `${path.basename(retired)} must be pruned on upgrade`);
    }
    assert.equal(
      fs.existsSync(removedDirectoryFile),
      false,
      "a whole Bob-owned directory removed from the source must be pruned on upgrade",
    );
    assert.equal(
      fs.readFileSync(foreignDependency, "utf8"),
      "preserve-foreign-dependency\n",
      "reinstall must preserve foreign mcp/node_modules entries",
    );
    for (const runtimeTree of ["core", "domains", "tools", "fuzz", "lib"]) {
      assert.deepEqual(
        sourceTreeFiles(workspace, path.join("mcp", runtimeTree)),
        sourceTreeFiles(ROOT, path.join("mcp", runtimeTree)),
        `installed Bob-owned mcp/${runtimeTree} must exactly match the source tree`,
      );
    }
    const refreshedOwnership = JSON.parse(fs.readFileSync(ownershipMetadataPath, "utf8"))
      .mcp_top_level_runtime_ownership;
    assert.equal(refreshedOwnership.version, 1);
    assert.deepEqual(
      refreshedOwnership.files.map((file) => file.name),
      [...require("../scripts/install.js").MCP_TOP_LEVEL_RUNTIME_FILES],
      "the next ownership receipt must contain only the current top-level Bob runtime manifest",
    );
    for (const file of refreshedOwnership.files) {
      assert.equal(
        file.byte_size,
        fs.statSync(path.join(ROOT, "mcp", file.name)).size,
        `ownership receipt size must bind current source mcp/${file.name}`,
      );
      assert.equal(
        file.sha256,
        crypto.createHash("sha256")
          .update(fs.readFileSync(path.join(ROOT, "mcp", file.name)))
          .digest("hex"),
        `ownership receipt digest must bind current source mcp/${file.name}`,
      );
    }
    const runtimeIntegrity = doctorProject(workspace, {
      adapter: "claude",
      onAdapterResolution: () => {},
      sourceRoot: ROOT,
    }).checks.find((check) => check.id === "bob_owned_runtime_integrity");
    assert.equal(runtimeIntegrity.status, "ok");
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("dev-sync.sh copies every top-level mcp/ runtime file in the manifest", () => {
  // agy round-5: dev-sync.sh's explicit cp list can drift from MCP_TOP_LEVEL_RUNTIME_FILES. Rather than
  // couple dev-sync to the install.js require-graph at runtime (reverted in round 4 — fragile + a
  // single-quote-path hazard), pin the two with a TEST: every manifest runtime file must appear as a
  // dev-sync cp target, so adding a runtime file to the manifest without updating dev-sync fails CI.
  const { MCP_TOP_LEVEL_RUNTIME_FILES } = require("../scripts/install.js");
  const devSync = fs.readFileSync(path.join(ROOT, "dev-sync.sh"), "utf8");
  for (const name of MCP_TOP_LEVEL_RUNTIME_FILES) {
    assert.ok(devSync.includes(`mcp/${name}`),
      `dev-sync.sh must copy top-level mcp/${name} (keep its cp list in step with MCP_TOP_LEVEL_RUNTIME_FILES)`);
  }
});

test("codex adapter installs direct skills and doctor checks MCP wiring", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-codex-adapter-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-home-"));
  const workspace = path.join(tempRoot, "workspace");
  const originalCodexHome = process.env.CODEX_HOME;
  fs.mkdirSync(workspace, { recursive: true });
  process.env.CODEX_HOME = path.join(tempHome, ".codex");

  try {
    execFileSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });

    const install = CODEX_ADAPTER.install({
      sourceRoot: ROOT,
      targetAbs: workspace,
      serverPath: path.join(workspace, "mcp", "server.js"),
    });
    assert.equal(install.skills, 6);
    assert.equal(install.commands, 6);
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".codex-plugin", "plugin.json")));
    const manifest = JSON.parse(fs.readFileSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".codex-plugin", "plugin.json"), "utf8"));
    assert.equal(Object.prototype.hasOwnProperty.call(manifest, "skills"), false);
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-status", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-debug", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-update", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-export", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-egress", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "skills", "evaluate", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "skills", "hacker-bob-evaluate", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(tempHome, ".codex", "skills", "hacker-bob-evaluate", "SKILL.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-evaluate.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-export.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-egress.md")));
    assert.ok(fs.existsSync(path.join(workspace, ".agents", "plugins", "marketplace.json")));

    const mcp = JSON.parse(fs.readFileSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".mcp.json"), "utf8"));
    assert.deepEqual(mcp.mcpServers["hacker-bob"], {
      command: "node",
      args: [path.join(workspace, "mcp", "server.js")],
    });
    assert.ok(!mcp.mcpServers.bountyagent);

    const doctor = CODEX_ADAPTER.doctor({ targetAbs: workspace });
    assert.equal(doctor.ok, true);
    assert.ok(doctor.checks.some((check) => check.id === "codex_plugin_manifest" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "codex_global_skills" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "codex_plugin_skills_clean" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "codex_plugin_mcp" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "codex_plugin_commands" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "codex_plugin_marketplace" && check.status === "ok"));

    const dryRun = CODEX_ADAPTER.uninstall({ sourceRoot: ROOT, targetAbs: workspace, dryRun: true });
    assert.equal(dryRun.dry_run, true);
    assert.ok(dryRun.actions.some((action) => action.path === path.join(tempHome, ".codex", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(dryRun.actions.some((action) => action.path === path.join(".codex", "plugins", "hacker-bob", ".mcp.json")));
    assert.ok(dryRun.actions.some((action) => action.path === path.join(".agents", "plugins", "marketplace.json")));
    assert.ok(fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".mcp.json")));
    assert.ok(fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-evaluate", "SKILL.md")));

    const removed = CODEX_ADAPTER.uninstall({ sourceRoot: ROOT, targetAbs: workspace, dryRun: false });
    assert.equal(removed.dry_run, false);
    assert.ok(!fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-export", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(tempHome, ".codex", "skills", "bob-egress", "SKILL.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", ".mcp.json")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-evaluate.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-export.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex", "plugins", "hacker-bob", "commands", "bob-egress.md")));
    assert.ok(!fs.existsSync(path.join(workspace, ".agents", "plugins", "marketplace.json")));
  } finally {
    if (originalCodexHome === undefined) {
      delete process.env.CODEX_HOME;
    } else {
      process.env.CODEX_HOME = originalCodexHome;
    }
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("kimi adapter installs skills, registers the hacker-bob MCP key, and doctor/uninstall round-trip", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-kimi-adapter-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });
  const serverPath = path.join(workspace, "mcp", "server.js");
  // Redirect the Kimi home (config.toml) into the temp dir so the install never
  // mutates the developer's real ~/.kimi — mirrors the Codex CODEX_HOME override.
  const originalKimiShare = process.env.KIMI_SHARE_DIR;
  process.env.KIMI_SHARE_DIR = path.join(tempHome, ".kimi");
  const cfgPath = path.join(tempHome, ".kimi", "config.toml");

  try {
    // Base install lays down the shared runtime (mcp/server.js); then exercise
    // the Kimi adapter methods directly, mirroring the Codex adapter test.
    execFileSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });

    const install = KIMI_ADAPTER.install({
      sourceRoot: ROOT,
      targetAbs: workspace,
      serverPath,
      manifest: { version: PACKAGE_VERSION, name: "hacker-bob" },
    });
    assert.equal(install.skills, 6);
    assert.equal(install.hooks, 2);
    assert.ok(install.kimiDir);

    // PreToolUse guard scripts copied + executable; scope-guard.sh (no-op) swept.
    for (const hook of ["session-write-guard.sh", "session-read-guard.sh"]) {
      const hp = path.join(workspace, ".kimi", "hooks", hook);
      assert.ok(fs.existsSync(hp), `${hook} must be installed`);
      assert.ok((fs.statSync(hp).mode & 0o111) !== 0, `${hook} must be executable`);
    }
    assert.ok(!fs.existsSync(path.join(workspace, ".kimi", "hooks", "scope-guard.sh")),
      "no-op scope-guard.sh must not be installed");

    // The generated allow/deny manifest lands beside the guards (non-executable).
    const manifestPath = path.join(workspace, ".kimi", "hooks", "write-guard-tables.json");
    assert.ok(fs.existsSync(manifestPath), "write-guard-tables.json must be copied beside the guards");
    assert.equal(fs.statSync(manifestPath).mode & 0o111, 0, "manifest must not be executable");

    // ~/.kimi/config.toml registered, one Bob block, points at THIS project.
    assert.ok(fs.existsSync(cfgPath), "kimi config.toml must be created/updated");
    let cfg = fs.readFileSync(cfgPath, "utf8");
    assert.match(cfg, /\[\[hooks\]\]/);
    assert.match(cfg, /event = "PreToolUse"/);
    assert.ok(cfg.includes(path.join(workspace, ".kimi", "hooks", "session-write-guard.sh")));
    assert.ok(cfg.includes(path.join(workspace, ".kimi", "hooks", "session-read-guard.sh")));
    assert.equal((cfg.match(/# >>> hacker-bob managed hooks/g) || []).length, 1,
      "exactly one Bob hook block");

    // Idempotent + merge-not-clobber: seed an operator hook, reinstall, assert
    // preserved & no duplicate Bob block.
    fs.writeFileSync(cfgPath, `[[hooks]]\nevent = "Stop"\ncommand = "echo operator"\n\n${cfg}`);
    KIMI_ADAPTER.install({ sourceRoot: ROOT, targetAbs: workspace, serverPath, manifest: { version: PACKAGE_VERSION, name: "hacker-bob" } });
    cfg = fs.readFileSync(cfgPath, "utf8");
    assert.ok(cfg.includes('command = "echo operator"'), "operator hook preserved across reinstall");
    assert.equal((cfg.match(/# >>> hacker-bob managed hooks/g) || []).length, 1,
      "reinstall must not duplicate the Bob block");
    for (const skill of ["bob-evaluate", "bob-status", "bob-debug", "bob-update", "bob-export", "bob-egress"]) {
      assert.ok(fs.existsSync(path.join(workspace, ".kimi", "skills", skill, "SKILL.md")), `${skill} SKILL.md missing`);
    }
    assert.ok(fs.existsSync(path.join(workspace, ".kimi", "bob", "VERSION")));
    assert.ok(fs.existsSync(path.join(workspace, ".kimi", "bob", "install.json")));

    // v2.0 server key: must be the canonical `hacker-bob`, never the legacy
    // `bountyagent` (CHANGELOG v2.0 + docs/TROUBLESHOOTING.md).
    const mcp = JSON.parse(fs.readFileSync(path.join(workspace, ".kimi", "mcp.json"), "utf8"));
    assert.deepEqual(mcp.mcpServers["hacker-bob"], { command: "node", args: [serverPath] });
    assert.ok(!mcp.mcpServers.bountyagent, "fresh Kimi install must not emit the legacy bountyagent key");
    assert.ok(mcp.mcpServers.brutalist, "Kimi install registers the optional brutalist server");

    const doctor = KIMI_ADAPTER.doctor({ targetAbs: workspace });
    assert.equal(doctor.ok, true);
    assert.ok(doctor.checks.some((check) => check.id === "kimi_installed_version" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "kimi_install_metadata" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "kimi_skills" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "kimi_mcp_server_config" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "kimi_mcp_brutalist_optional"));
    assert.ok(doctor.checks.some((check) => check.id === "kimi_cli_on_path"));
    assert.ok(doctor.checks.some((check) => check.id === "kimi_hook_files" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "kimi_hook_modes" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "kimi_hook_manifest" && check.status === "ok"));
    assert.ok(doctor.checks.some((check) => check.id === "kimi_hook_registration" && check.status === "ok"));
    // The best-effort caveat must always surface (warn never fails doctor).
    assert.ok(doctor.checks.some((check) => check.id === "kimi_hook_best_effort" && check.status === "warn"));
    // No cross-adapter check leakage.
    assert.ok(!doctor.checks.some((check) => check.id.startsWith("claude_") || check.id.startsWith("codex_")));

    // Legacy migration: a Bob-managed v1.x `bountyagent` entry is rewritten to
    // `hacker-bob` on reinstall, preserving operator-owned sibling servers.
    fs.writeFileSync(path.join(workspace, ".kimi", "mcp.json"), `${JSON.stringify({
      mcpServers: {
        bountyagent: { command: "node", args: [serverPath] },
        operator: { command: "node", args: ["sibling.js"] },
      },
    }, null, 2)}\n`);
    // Seed stale skill dirs from a prior build (bob-hunt v1, bob-evaluate-runner
    // interim misname). A normal reinstall/update must sweep them so old prompts
    // and tool names are never left exposed beside the current bob-evaluate
    // skill — parity with the Codex and Claude install-time legacy sweep.
    for (const legacySkill of ["bob-evaluate-runner", "bob-hunt"]) {
      fs.mkdirSync(path.join(workspace, ".kimi", "skills", legacySkill), { recursive: true });
      fs.writeFileSync(path.join(workspace, ".kimi", "skills", legacySkill, "SKILL.md"), `# stale ${legacySkill}\n`);
    }
    KIMI_ADAPTER.install({ sourceRoot: ROOT, targetAbs: workspace, serverPath, manifest: { version: PACKAGE_VERSION, name: "hacker-bob" } });
    const migrated = JSON.parse(fs.readFileSync(path.join(workspace, ".kimi", "mcp.json"), "utf8"));
    assert.ok(migrated.mcpServers["hacker-bob"], "migration must add the hacker-bob key");
    assert.ok(!migrated.mcpServers.bountyagent, "migration must drop the legacy bountyagent key");
    assert.ok(migrated.mcpServers.operator, "migration must preserve operator-owned sibling servers");
    // The reinstall swept the legacy skill dirs while keeping current skills.
    for (const legacySkill of ["bob-evaluate-runner", "bob-hunt"]) {
      assert.ok(
        !fs.existsSync(path.join(workspace, ".kimi", "skills", legacySkill, "SKILL.md")),
        `${legacySkill} legacy skill must be swept on reinstall`,
      );
    }
    assert.ok(
      fs.existsSync(path.join(workspace, ".kimi", "skills", "bob-evaluate", "SKILL.md")),
      "current bob-evaluate skill must survive the legacy sweep",
    );

    const dryRun = KIMI_ADAPTER.uninstall({ sourceRoot: ROOT, targetAbs: workspace, dryRun: true });
    assert.equal(dryRun.dry_run, true);
    assert.ok(dryRun.actions.some((action) => action.path === path.join(".kimi", "skills", "bob-evaluate", "SKILL.md")));
    assert.ok(dryRun.actions.some((action) => action.path === path.join(".kimi", "mcp.json")));
    assert.ok(fs.existsSync(path.join(workspace, ".kimi", "skills", "bob-evaluate", "SKILL.md")));

    const removed = KIMI_ADAPTER.uninstall({ sourceRoot: ROOT, targetAbs: workspace, dryRun: false });
    assert.equal(removed.dry_run, false);
    for (const skill of ["bob-evaluate", "bob-export", "bob-egress"]) {
      assert.ok(!fs.existsSync(path.join(workspace, ".kimi", "skills", skill, "SKILL.md")), `${skill} should be removed`);
    }
    // `.kimi/` is a Bob-owned directory (it is created by the Kimi install and
    // listed in managedFiles), so uninstall removes the whole `.kimi/mcp.json`.
    assert.ok(!fs.existsSync(path.join(workspace, ".kimi", "mcp.json")), ".kimi/mcp.json should be removed on uninstall");

    // Hook isolation: uninstall removed the Bob block (config preserved because
    // the operator hook keeps it non-empty) and the copied guard scripts.
    const afterConfig = fs.readFileSync(cfgPath, "utf8");
    assert.ok(!afterConfig.includes("# >>> hacker-bob managed hooks"), "Bob hook block removed on uninstall");
    assert.ok(afterConfig.includes('command = "echo operator"'), "operator hook survives uninstall");
    assert.ok(!fs.existsSync(path.join(workspace, ".kimi", "hooks", "session-write-guard.sh")), "guard removed on uninstall");
  } finally {
    if (originalKimiShare === undefined) delete process.env.KIMI_SHARE_DIR;
    else process.env.KIMI_SHARE_DIR = originalKimiShare;
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("kimi hook registration is shell-injection-safe and uninstall is install-scoped", () => {
  // #2: the generated PreToolUse `command` is run as a shell command, so the
  // hook path must be single-quoted (shell-inert) — $(), backticks, $VAR in the
  // install path must NOT expand at hook runtime.
  const malicious = "/tmp/proj-$(touch /tmp/PWNED)-`id`-$HOME";
  const block = KIMI_ADAPTER.renderKimiHookBlock(malicious);
  const writePath = path.join(malicious, ".kimi", "hooks", "session-write-guard.sh");
  assert.ok(block.includes(`'${writePath}'`),
    "hook path must be single-quoted in the command so the shell cannot expand it");
  // shellSingleQuote escapes an embedded single quote as '\'' (close/escape/reopen).
  assert.equal(KIMI_ADAPTER.shellSingleQuote("a'b"), "'a'\\''b'");

  // #7a: kimiHookBlockMatchesTarget identifies the OWNING install only.
  const blockA = KIMI_ADAPTER.renderKimiHookBlock("/tmp/projA");
  assert.equal(KIMI_ADAPTER.kimiHookBlockMatchesTarget(blockA, "/tmp/projA"), true);
  assert.equal(KIMI_ADAPTER.kimiHookBlockMatchesTarget(blockA, "/tmp/projB"), false);

  const originalKimiShare = process.env.KIMI_SHARE_DIR;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-kimi-uninstall-"));
  try {
    // #7b: uninstalling project A must NOT remove a global Bob block owned by B.
    const kimiDir = path.join(tempHome, ".kimi");
    fs.mkdirSync(kimiDir, { recursive: true });
    process.env.KIMI_SHARE_DIR = kimiDir;
    const cfgPath = path.join(kimiDir, "config.toml");
    fs.writeFileSync(cfgPath, `${KIMI_ADAPTER.renderKimiHookBlock("/tmp/projB")}\n`);

    const rA = KIMI_ADAPTER.uninstall({ sourceRoot: ROOT, targetAbs: "/tmp/projA", dryRun: false });
    assert.ok(fs.readFileSync(cfgPath, "utf8").includes("# >>> hacker-bob managed hooks"),
      "B's global hook block must survive A's uninstall");
    assert.ok(rA.skipped.some((s) => /different project/.test(s.reason || "")),
      "uninstall must report skipping a block owned by a different project");

    // #7c: a symlinked config must not be followed/rewritten on uninstall.
    const realCfg = path.join(tempHome, "real-config.toml");
    fs.writeFileSync(realCfg, `${KIMI_ADAPTER.renderKimiHookBlock("/tmp/projB")}\n`);
    const symHome = path.join(tempHome, "symhome", ".kimi");
    fs.mkdirSync(symHome, { recursive: true });
    fs.symlinkSync(realCfg, path.join(symHome, "config.toml"));
    process.env.KIMI_SHARE_DIR = symHome;
    const rSym = KIMI_ADAPTER.uninstall({ sourceRoot: ROOT, targetAbs: "/tmp/projB", dryRun: false });
    assert.ok(fs.readFileSync(realCfg, "utf8").includes("# >>> hacker-bob managed hooks"),
      "symlinked config target must be left intact");
    assert.ok(rSym.skipped.some((s) => /symlink/.test(s.reason || "")),
      "uninstall must report refusing to rewrite a symlinked config");
  } finally {
    if (originalKimiShare === undefined) delete process.env.KIMI_SHARE_DIR;
    else process.env.KIMI_SHARE_DIR = originalKimiShare;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("detectInstalledAdapterIds recognizes an installed kimi layout (claude/codex parity)", () => {
  // Locks the fix for reinstall/update/uninstall auto-detection: a project that
  // has a kimi install but no neutral install.json metadata must still resolve
  // to the kimi adapter via filesystem detection, exactly like claude and codex.
  const { detectInstalledAdapterIds } = require("../scripts/install.js");
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-detect-adapters-"));
  try {
    const viaVersion = path.join(tempRoot, "kimi-version");
    fs.mkdirSync(path.join(viaVersion, ".kimi", "bob"), { recursive: true });
    fs.writeFileSync(path.join(viaVersion, ".kimi", "bob", "VERSION"), `${PACKAGE_VERSION}\n`);
    assert.deepEqual(detectInstalledAdapterIds(viaVersion), ["kimi"]);

    const viaSkill = path.join(tempRoot, "kimi-skill");
    fs.mkdirSync(path.join(viaSkill, ".kimi", "skills", "bob-evaluate"), { recursive: true });
    fs.writeFileSync(path.join(viaSkill, ".kimi", "skills", "bob-evaluate", "SKILL.md"), "x\n");
    assert.deepEqual(detectInstalledAdapterIds(viaSkill), ["kimi"]);

    const codexLayout = path.join(tempRoot, "codex");
    fs.mkdirSync(path.join(codexLayout, ".codex", "plugins", "hacker-bob"), { recursive: true });
    assert.deepEqual(detectInstalledAdapterIds(codexLayout), ["codex"]);

    const claudeLayout = path.join(tempRoot, "claude");
    fs.mkdirSync(path.join(claudeLayout, ".claude", "bob"), { recursive: true });
    fs.writeFileSync(path.join(claudeLayout, ".claude", "bob", "VERSION"), `${PACKAGE_VERSION}\n`);
    assert.deepEqual(detectInstalledAdapterIds(claudeLayout), ["claude"]);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("generic MCP adapter installs only MCP config and prompt docs", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-generic-mcp-adapter-"));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-home-"));
  const workspace = path.join(tempRoot, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  try {
    execFileSync(process.execPath, [CLI, "install", workspace], {
      cwd: ROOT,
      env: { ...process.env, HOME: tempHome },
      stdio: "pipe",
    });
    fs.rmSync(path.join(workspace, ".claude"), { recursive: true, force: true });
    fs.writeFileSync(path.join(workspace, ".mcp.json"), `${JSON.stringify({
      mcpServers: {
        existing: { command: "node", args: ["existing.js"] },
      },
    }, null, 2)}\n`);

    GENERIC_MCP_ADAPTER.install({
      sourceRoot: ROOT,
      targetAbs: workspace,
      serverPath: path.join(workspace, "mcp", "server.js"),
    });

    assert.ok(!fs.existsSync(path.join(workspace, ".claude")));
    assert.ok(!fs.existsSync(path.join(workspace, ".codex")));
    assert.ok(fs.existsSync(path.join(workspace, ".hacker-bob", "generic-mcp", "hacker-bob.md")));

    const mcp = JSON.parse(fs.readFileSync(path.join(workspace, ".mcp.json"), "utf8"));
    assert.ok(mcp.mcpServers.existing);
    assert.deepEqual(mcp.mcpServers["hacker-bob"], {
      command: "node",
      args: [path.join(workspace, "mcp", "server.js")],
    });
    assert.ok(!mcp.mcpServers.bountyagent);

    const doctor = GENERIC_MCP_ADAPTER.doctor({ targetAbs: workspace });
    assert.equal(doctor.ok, true);
    assert.ok(doctor.checks.some((check) => check.id === "generic_mcp_server" && check.status === "ok"));

    const removed = GENERIC_MCP_ADAPTER.uninstall({ targetAbs: workspace, dryRun: false });
    assert.equal(removed.dry_run, false);
    assert.ok(!fs.existsSync(path.join(workspace, ".hacker-bob", "generic-mcp", "hacker-bob.md")));
    const after = JSON.parse(fs.readFileSync(path.join(workspace, ".mcp.json"), "utf8"));
    assert.ok(after.mcpServers.existing);
    assert.ok(!after.mcpServers["hacker-bob"]);
    assert.ok(!after.mcpServers.bountyagent);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("migration shim rewrites v1.x bountyagent server key + permission strings to hacker-bob", () => {
  // The shim in scripts/merge-claude-config.js powers the v2.0.0 rename for
  // existing installs. This test exercises it directly (unit-level), then
  // re-runs it on the rewritten output to prove idempotency.
  const {
    migrateLegacyMcp,
    migrateLegacySettings,
    migrateLegacyServerKey,
    rewriteLegacyPermissionString,
  } = require("../scripts/merge-claude-config.js");

  // Sanity: prefix rewriter handles legacy/canonical/unknown strings.
  assert.equal(
    rewriteLegacyPermissionString("mcp__bountyagent__bob_http_scan"),
    "mcp__hacker-bob__bob_http_scan",
  );
  assert.equal(
    rewriteLegacyPermissionString("mcp__hacker-bob__bob_http_scan"),
    "mcp__hacker-bob__bob_http_scan",
  );
  assert.equal(rewriteLegacyPermissionString("custom-tool"), "custom-tool");
  assert.equal(rewriteLegacyPermissionString(undefined), undefined);

  // Pure .mcp.json migration: legacy key is renamed and operator entries
  // unrelated to the rename are preserved.
  const v1Mcp = {
    mcpServers: {
      bountyagent: {
        command: "node",
        args: ["/legacy/path/mcp/server.js"],
      },
      operator: { command: "node", args: ["op.js"] },
    },
  };
  const mcpResult = migrateLegacyMcp(v1Mcp);
  assert.equal(mcpResult.migrated, true);
  assert.deepEqual(mcpResult.value.mcpServers["hacker-bob"], {
    command: "node",
    args: ["/legacy/path/mcp/server.js"],
  });
  assert.ok(!("bountyagent" in mcpResult.value.mcpServers));
  assert.deepEqual(mcpResult.value.mcpServers.operator, { command: "node", args: ["op.js"] });

  // Idempotency: re-running migration on already-migrated input is a no-op.
  const idempotentMcp = migrateLegacyMcp(mcpResult.value);
  assert.equal(idempotentMcp.migrated, false);
  assert.deepEqual(idempotentMcp.value, mcpResult.value);

  // Both keys present: legacy is dropped, canonical is preserved untouched.
  const dualKeyMcp = {
    mcpServers: {
      bountyagent: { command: "node", args: ["legacy.js"] },
      "hacker-bob": { command: "node", args: ["canonical.js"] },
    },
  };
  const dualResult = migrateLegacyMcp(dualKeyMcp);
  assert.equal(dualResult.migrated, true);
  assert.deepEqual(dualResult.value.mcpServers["hacker-bob"], { command: "node", args: ["canonical.js"] });
  assert.ok(!("bountyagent" in dualResult.value.mcpServers));

  // Pure settings.json migration: legacy permission strings rewritten, others
  // preserved.
  const v1Settings = {
    permissions: {
      allow: [
        "mcp__bountyagent__bob_http_scan",
        "mcp__bountyagent__custom_user_tool",
        "Read",
        "mcp__hacker-bob__pre_migration_custom",
      ],
    },
    customSetting: true,
  };
  const settingsResult = migrateLegacySettings(v1Settings);
  assert.equal(settingsResult.migrated, true);
  assert.ok(settingsResult.value.permissions.allow.includes("mcp__hacker-bob__bob_http_scan"));
  assert.ok(settingsResult.value.permissions.allow.includes("mcp__hacker-bob__custom_user_tool"));
  assert.ok(settingsResult.value.permissions.allow.includes("Read"));
  // Idempotency: pre-existing canonical permission survives without duplication.
  assert.ok(settingsResult.value.permissions.allow.includes("mcp__hacker-bob__pre_migration_custom"));
  assert.equal(
    settingsResult.value.permissions.allow.length,
    new Set(settingsResult.value.permissions.allow).size,
    "migration must dedupe permission strings",
  );
  assert.equal(settingsResult.value.customSetting, true, "unrelated settings preserved");
  assert.ok(!settingsResult.value.permissions.allow.some((p) => p.startsWith("mcp__bountyagent__")));

  // Idempotency: re-migration is a no-op.
  const idempotentSettings = migrateLegacySettings(settingsResult.value);
  assert.equal(idempotentSettings.migrated, false);
  assert.deepEqual(idempotentSettings.value, settingsResult.value);

  // No-op cases.
  assert.equal(migrateLegacyMcp({}).migrated, false);
  assert.equal(migrateLegacyMcp({ mcpServers: { other: {} } }).migrated, false);
  assert.equal(migrateLegacySettings({}).migrated, false);
  assert.equal(migrateLegacySettings({ permissions: { allow: ["Read"] } }).migrated, false);

  // Combined entry point logs and reports overall migration status.
  const captured = [];
  const combined = migrateLegacyServerKey({
    mcp: v1Mcp,
    settings: v1Settings,
    logger: (msg) => captured.push(msg),
  });
  assert.equal(combined.migrated, true);
  assert.equal(captured.length, 1);
  assert.match(captured[0], /bountyagent\s*->\s*hacker-bob/);
  assert.match(captured[0], /\.mcp\.json/);
  assert.match(captured[0], /\.claude\/settings\.json/);
});

test("merge-claude-config CLI auto-migrates a v1.x .mcp.json + settings.json layout", () => {
  // Round-trip the migration shim through the CLI entrypoint. This exercises
  // the same code path install/update uses on existing v1.x workspaces.
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-migration-shim-"));
  const workspace = path.join(tempRoot, "v1-install");
  fs.mkdirSync(path.join(workspace, ".claude"), { recursive: true });

  try {
    const legacyServerPath = path.join(workspace, "mcp", "server.js");
    fs.writeFileSync(path.join(workspace, ".mcp.json"), `${JSON.stringify({
      mcpServers: {
        bountyagent: { command: "node", args: [legacyServerPath] },
        operatorService: { command: "node", args: ["sidecar.js"] },
      },
    }, null, 2)}\n`);
    fs.writeFileSync(path.join(workspace, ".claude", "settings.json"), `${JSON.stringify({
      permissions: {
        allow: [
          "mcp__bountyagent__bob_http_scan",
          "mcp__bountyagent__custom_user_tool",
          "custom-allowlisted",
        ],
      },
      customSetting: true,
    }, null, 2)}\n`);

    const merge = require("../scripts/merge-claude-config.js");
    const mcp = JSON.parse(fs.readFileSync(path.join(workspace, ".mcp.json"), "utf8"));
    const settings = JSON.parse(fs.readFileSync(path.join(workspace, ".claude", "settings.json"), "utf8"));
    const migrated = merge.migrateLegacyServerKey({ mcp, settings });
    assert.equal(migrated.migrated, true);

    // The merge step then runs over the migrated config (idempotent for the
    // rename surfaces).
    const finalMcp = merge.mergeMcp(migrated.mcp, legacyServerPath);
    assert.ok(finalMcp.mcpServers["hacker-bob"]);
    assert.ok(!finalMcp.mcpServers.bountyagent);
    assert.deepEqual(finalMcp.mcpServers.operatorService, { command: "node", args: ["sidecar.js"] });
    assert.ok(finalMcp.mcpServers.brutalist);

    const finalSettings = merge.mergeSettings(migrated.settings, {
      permissions: { allow: ["mcp__hacker-bob__bob_record_candidate_claim"] },
      hooks: {},
    });
    assert.ok(finalSettings.permissions.allow.includes("mcp__hacker-bob__bob_http_scan"));
    assert.ok(finalSettings.permissions.allow.includes("mcp__hacker-bob__custom_user_tool"));
    assert.ok(finalSettings.permissions.allow.includes("mcp__hacker-bob__bob_record_candidate_claim"));
    assert.ok(finalSettings.permissions.allow.includes("custom-allowlisted"));
    assert.equal(finalSettings.customSetting, true);
    assert.ok(!finalSettings.permissions.allow.some((p) => p.startsWith("mcp__bountyagent__")));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});
