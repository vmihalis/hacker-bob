const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  CANONICAL_RUNTIME_PACKAGE_ROOTS,
  CANONICAL_PACKAGE_MAX_BYTES,
  DISALLOWED_PACKED_FILE_PATTERNS,
  DISALLOWED_PACKED_TEXT_PATTERNS,
  EXCLUDED_CANONICAL_PACKAGE_FILES,
  LOCAL_INSTALL_METADATA_FILES,
  OPTIONAL_PROVIDER_EXCLUDED_PACKAGE_ROOTS,
  REQUIRED_SUPPORT_SURFACES,
  STALE_HOOK_SCRIPT_NAMES,
  expectedCanonicalFiles,
  isExcludedCanonicalPackageFile,
  isInternalPlaneBeliefRoadmapDoc,
  isInternalPlaneDeltaDetailDoc,
  isInternalPlaneDeltaVerificationDoc,
  isInternalPlanePhysicalDoc,
  isInternalPolicyReplayPlanningDoc,
  isCanonicalRuntimePackageFile,
  isInternalRefactorDoc,
  isInternalRefactorScratch,
  isPackableBin,
  isPackableBobResource,
  isPackableMcpRuntimeFile,
  isPackableScript,
  isPackedTextFile,
  sourceTreeFiles,
  wrapperPackages,
} = require("../scripts/lib/package-policy.js");

const ROOT = path.join(__dirname, "..");
const PACKAGE_VERSION = require("../package.json").version;
const WRAPPER_PACKAGES = wrapperPackages(ROOT);
const {
  DARWIN_ARM64_PHYSICAL_PACKAGE_ROOTS,
  PORTABLE_PHYSICAL_PACKAGE_ROOTS,
  darwinArm64Applicability,
  portablePackageApplicability,
} = require("../scripts/lib/physical-package-test-matrix.js");
const {
  declaredRuntimeEntrypoints,
  loadCanonicalRuntimeEntrypoints,
} = require("./helpers/canonical-runtime-entrypoints.js");

function withDependencyFreshnessFixture(metadata, fn) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-dependency-freshness-"));
  try {
    const fixturePath = path.join(root, "metadata.json");
    fs.writeFileSync(fixturePath, `${JSON.stringify(metadata)}\n`, "utf8");
    return fn(fixturePath);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

test("cache-bob-workspace action links bob-diff-review into Claude skill discovery", () => {
  const action = fs.readFileSync(path.join(ROOT, ".github/actions/cache-bob-workspace/action.yml"), "utf8");
  assert.match(action, /\$INSTALL_TARGET\/\.claude\/skills\/bob-diff-review/);
  assert.match(action, /\$HOME\/\.claude\/skills\/bob-diff-review/);
  assert.match(action, /ln -s "\$SKILL_SRC" "\$SKILL_DEST"/);
  assert.match(action, /\[\[ ! -f "\$SKILL_DEST\/SKILL\.md" \]\]/);
});

test("canonical package declares PSL as a runtime dependency without vendoring it", () => {
  const packageJson = require("../package.json");
  const packageLock = require("../package-lock.json");
  assert.equal(packageJson.dependencies.psl, "^1.15.0");
  assert.equal(packageLock.packages[""].dependencies.psl, "^1.15.0");
  assert.equal(packageLock.packages["node_modules/psl"].version, "1.15.0");
  assert.equal(packageLock.packages["node_modules/psl"].dependencies.punycode, "^2.3.1");
  assert.equal(packageLock.packages["node_modules/punycode"].version, "2.3.1");
});

test("durable instrument store has one broker-owned implementation and an exact MCP alias", () => {
  const compatibilityPath = path.join(ROOT, "mcp", "lib", "instrument-lease-store.js");
  const canonicalPath = path.join(
    ROOT,
    "packages",
    "bob-instrument-broker",
    "lib",
    "instrument-lease-store.js",
  );
  const manifest = require("../packages/bob-instrument-broker/package.json");
  assert.equal(
    manifest.exports["./instrument-lease-store"],
    "./lib/instrument-lease-store.js",
  );
  assert.ok(fs.statSync(canonicalPath).size > 200_000, "canonical store implementation is missing");
  assert.ok(fs.statSync(compatibilityPath).size < 256, "MCP store alias must remain tiny");
  assert.equal(require(compatibilityPath), require(canonicalPath));
});

test("dependency freshness check warns on stale but current PSL metadata", () => {
  const output = withDependencyFreshnessFixture({
    version: "1.15.0",
    "dist-tags": { latest: "1.15.0" },
    time: { "1.15.0": "2024-12-02T10:16:04.251Z" },
  }, (fixturePath) => execFileSync(process.execPath, [
    "scripts/dependency-freshness.js",
    "--metadata-file",
    fixturePath,
    "--now",
    "2026-05-17T00:00:00.000Z",
  ], {
    cwd: ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }));

  assert.match(output, /OK PSL overlay escape hatch remains implemented without runtime network refresh/);
  assert.match(output, /OK psl lockfile version matches npm latest 1\.15\.0/);
  assert.match(output, /WARN psl@1\.15\.0 latest publish age \d+\.\d days exceeds warning threshold 180 days/);
  assert.match(output, /Dependency freshness check passed with 1 warning\(s\)\./);
});

test("dependency freshness check fails when PSL lockfile is behind latest", () => {
  assert.throws(() => withDependencyFreshnessFixture({
    version: "1.16.0",
    "dist-tags": { latest: "1.16.0" },
    time: { "1.16.0": "2026-05-01T00:00:00.000Z" },
  }, (fixturePath) => execFileSync(process.execPath, [
    "scripts/dependency-freshness.js",
    "--metadata-file",
    fixturePath,
    "--now",
    "2026-05-17T00:00:00.000Z",
  ], {
    cwd: ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  })), (error) => {
    assert.match(String(error.stdout), /FAIL psl lockfile version 1\.15\.0 is behind npm latest 1\.16\.0/);
    return true;
  });
});

test("canonical package lists shipped Claude hooks explicitly", () => {
  const packageJson = require("../package.json");
  assert.ok(!packageJson.files.includes(".claude/hooks/**/*"));
  for (const staleName of STALE_HOOK_SCRIPT_NAMES) {
    assert.ok(!packageJson.files.includes(`.claude/hooks/${staleName}`));
  }
  for (const hookName of [
    "bob-check-update-worker.js",
    "bob-check-update.js",
    "bob-egress.js",
    "bob-export.js",
    "bob-update.js",
    "bob-statusline.js",
    "agent-run-start.js",
    "agent-run-stop.js",
    "bob-http-write-confirm.sh",
    "bob-http-write-confirm-impl.py",
    "session-read-guard.sh",
    "session-write-guard.sh",
  ]) {
    assert.ok(packageJson.files.includes(`.claude/hooks/${hookName}`), `${hookName} should be explicitly packed`);
  }
});

test("canonical package declares the MCP runtime through a deny-by-default file surface", () => {
  const packageJson = require("../package.json");
  assert.ok(!packageJson.files.includes("mcp/**/*"));
  for (const expected of [
    "mcp/server.js",
    "mcp/auto-signup.js",
    "mcp/redaction.js",
    "mcp/browser-driver.js",
    "mcp/lib/**/*.js",
    "mcp/lib/fuzz/bob-multitu-build.sh",
    "mcp/lib/offensive-image.json",
  ]) {
    assert.ok(packageJson.files.includes(expected), `${expected} should be explicitly packed`);
  }
  assert.equal(isPackedTextFile(".claude/hooks/bob-approval-gate-impl.py"), true);
  assert.equal(isPackedTextFile("docker/offensive.Dockerfile"), true);
});

test("root release gates separate portable coverage from required Darwin arm64 qualification", () => {
  assert.deepEqual(PORTABLE_PHYSICAL_PACKAGE_ROOTS, [
    "packages/bob-artifact-vault",
    "packages/bob-instrument-broker",
    "packages/bob-instrument-contracts",
    "packages/bob-instrument-chameleon",
    "packages/bob-instrument-chameleon-worker",
    "packages/bob-instrument-chameleon-worker-runtime",
    "packages/bob-instrument-deterministic",
    "packages/bob-instrument-native-prebuild-trust",
    "packages/bob-instrument-principal-acl-darwin",
  ]);
  assert.deepEqual(DARWIN_ARM64_PHYSICAL_PACKAGE_ROOTS, [
    "packages/bob-instrument-chameleon-native-darwin",
    "packages/bob-instrument-native-darwin",
    "packages/bob-instrument-trusted-clock-native-darwin",
    "packages/bob-instrument-launcher-native-darwin",
    "packages/bob-instrument-safety-native-darwin",
  ]);
  for (const relativeRoot of [
    ...PORTABLE_PHYSICAL_PACKAGE_ROOTS,
    ...DARWIN_ARM64_PHYSICAL_PACKAGE_ROOTS,
  ]) {
    const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, relativeRoot, "package.json"), "utf8"));
    assert.equal(typeof manifest.scripts.test, "string", `${relativeRoot} has no enumerated test`);
  }
  const packageJson = require("../package.json");
  assert.equal(packageJson.scripts["test:physical-packages"],
    "node scripts/run-physical-package-tests.js --portable");
  assert.equal(packageJson.scripts["test:physical-native-darwin"],
    "node scripts/run-physical-package-tests.js --native-darwin");
  assert.equal(packageJson.scripts["test:physical-native-darwin:required"],
    "node scripts/run-physical-package-tests.js --native-darwin-required");
  assert.equal(packageJson.scripts.test, "npm run test:portable");
  assert.match(packageJson.scripts["test:portable"], /npm run test:physical-packages/u);
  assert.doesNotMatch(packageJson.scripts["test:portable"], /native-darwin/u);
  assert.doesNotMatch(packageJson.scripts["test:portable"], /test:lifecycle-custodian-native/u);
  assert.match(packageJson.scripts["test:portable"], /npm run test:install/u);
  assert.match(packageJson.scripts["test:portable"], /npm run test:cli/u);
  assert.match(packageJson.scripts["test:native-darwin"],
    /npm run test:physical-native-darwin:required/u);
  assert.match(packageJson.scripts["test:native-darwin"],
    /npm run test:lifecycle-custodian-native/u);
  assert.doesNotMatch(packageJson.scripts["test:native-darwin"], /test:install|test:cli/u);
  assert.doesNotMatch(packageJson.scripts["test:install"], /test:lifecycle-custodian-native/u);
  assert.doesNotMatch(packageJson.scripts["test:cli"], /test:lifecycle-custodian-native/u);

  // What this job requires is an Apple-silicon runner, not one specific image:
  // macos-13 and earlier are Intel, macos-14 and later are arm64. Pinning the
  // exact label made a necessary image bump look like a policy violation — the
  // SDK the natives compile against is a property of the image, so it has to be
  // free to move forward while the arm64 guarantee stays asserted.
  const ARM64_DARWIN_RUNNER =
    /native-darwin-qualification:[\s\S]{0,800}?runs-on: macos-(?:1[4-9]|[2-9]\d)\b/u;
  const ciWorkflow = fs.readFileSync(path.join(ROOT, ".github", "workflows", "ci.yml"), "utf8");
  assert.match(ciWorkflow, ARM64_DARWIN_RUNNER);
  assert.match(ciWorkflow, /run: npm run test:native-darwin/u);
  const releaseWorkflow = fs.readFileSync(
    path.join(ROOT, ".github", "workflows", "release.yml"),
    "utf8",
  );
  assert.match(releaseWorkflow, ARM64_DARWIN_RUNNER);
  assert.match(releaseWorkflow, /publish:\n\s+needs: native-darwin-qualification/u);
  assert.match(releaseWorkflow, /run: npm run test:native-darwin/u);
  assert.deepEqual(
    darwinArm64Applicability({ platform: "linux", architecture: "x64", node_version: "20.1.0" }),
    {
      applicable: false,
      reason_code: "host_not_darwin_arm64",
      platform: "linux",
      architecture: "x64",
      node_major: 20,
    },
  );
  assert.equal(darwinArm64Applicability({
    platform: "darwin",
    architecture: "arm64",
    node_version: "21.0.0",
  }).supported, false);
  assert.deepEqual(portablePackageApplicability({ node_version: "20.19.4" }), {
    applicable: true,
    supported: true,
    reason_code: "node20",
    node_major: 20,
  });
  assert.deepEqual(portablePackageApplicability({ node_version: "22.17.1" }), {
    applicable: false,
    reason_code: "node_major_not_20",
    node_major: 22,
  });
});

test("worker closure packages have reproducible root workspace and lock ownership", () => {
  const packageJson = require("../package.json");
  const lock = require("../package-lock.json");
  const workspaceRoots = [
    "packages/bob-instrument-contracts",
    "packages/bob-instrument-chameleon-worker-runtime",
    "packages/bob-instrument-chameleon-worker",
  ];
  for (const workspaceRoot of workspaceRoots) {
    assert.ok(packageJson.workspaces.includes(workspaceRoot), workspaceRoot);
    assert.ok(lock.packages[workspaceRoot], `${workspaceRoot} missing from lock`);
    const manifest = require(path.join(ROOT, workspaceRoot, "package.json"));
    const link = lock.packages[`node_modules/${manifest.name}`];
    assert.deepEqual(link, { resolved: workspaceRoot, link: true });
  }
  assert.deepEqual(
    lock.packages["packages/bob-instrument-chameleon-worker"].dependencies,
    { "@hacker-bob/instrument-chameleon-worker-runtime": "0.0.0-development" },
  );
  assert.deepEqual(
    lock.packages["packages/bob-instrument-chameleon-worker-runtime"].dependencies,
    undefined,
  );
  assert.equal(packageJson.dependencies["@babel/parser"], "^7.29.7");
  assert.equal(lock.packages[""].dependencies["@babel/parser"], "^7.29.7");
});

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
    const expectedFiles = expectedCanonicalFiles(ROOT);
    for (const expected of expectedFiles) {
      assert.ok(files.has(expected), `${expected} missing from npm pack output`);
    }
    for (const expected of REQUIRED_SUPPORT_SURFACES) {
      assert.ok(files.has(expected), `${expected} should be intentionally packed`);
    }
    assert.ok(
      files.has("testing/policy-replay/README.md"),
      "installed policy-replay usage documentation must remain packed",
    );
    for (const supportDoc of [
      "docs/plane-delta/capability-hypergraph-delta.md",
      "docs/plane-delta/nodes.json",
      "docs/plane-delta/hyperedges.json",
    ]) {
      assert.ok(files.has(supportDoc), `${supportDoc} high-level topology should remain packed`);
    }
    for (const excludedRoot of OPTIONAL_PROVIDER_EXCLUDED_PACKAGE_ROOTS) {
      assert.ok(
        ![...files].some((file) => file === excludedRoot || file.startsWith(`${excludedRoot}/`)),
        `${excludedRoot} optional implementation package must not be in canonical Bob`,
      );
    }
    for (const pureContractRoot of [
      "packages/bob-instrument-native-prebuild-trust",
      "packages/bob-instrument-principal-acl-darwin",
    ]) {
      assert.ok(files.has(`${pureContractRoot}/package.json`));
      assert.ok(
        [...files].some((file) => file.startsWith(`${pureContractRoot}/lib/`) && file.endsWith(".js")),
        `${pureContractRoot} must ship its pure contract sources`,
      );
    }
    for (const excluded of EXCLUDED_CANONICAL_PACKAGE_FILES) {
      assert.ok(!files.has(excluded), `${excluded} should not be packed`);
      assert.ok(!expectedFiles.includes(excluded), `${excluded} should not be expected`);
      assert.equal(isExcludedCanonicalPackageFile(excluded), true, `${excluded} should be denied by policy`);
    }

    // README-relative media must stay in the tarball so npm consumers receive
    // a complete document. The shared ceiling still catches accidental assets
    // and vendored dependencies.
    assert.ok(
      pack.size < CANONICAL_PACKAGE_MAX_BYTES,
      `npm pack size ${pack.size} exceeds ${CANONICAL_PACKAGE_MAX_BYTES}-byte ceiling`,
    );

    for (const file of files) {
      assert.ok(!file.startsWith("node_modules/"), `${file} should not vendor runtime dependencies`);
      assert.ok(!file.startsWith("test/"), `${file} should not be packed`);
      assert.ok(!isInternalRefactorDoc(file), `${file} should not be packed`);
      assert.ok(!isInternalPlaneBeliefRoadmapDoc(file), `${file} should not be packed`);
      assert.ok(!isInternalPlaneDeltaDetailDoc(file), `${file} should not be packed`);
      assert.ok(!isInternalPlaneDeltaVerificationDoc(file), `${file} should not be packed`);
      assert.ok(!isInternalPlanePhysicalDoc(file), `${file} should not be packed`);
      assert.ok(!isInternalPolicyReplayPlanningDoc(file), `${file} should not be packed`);
      assert.ok(!isInternalRefactorScratch(file), `${file} should not be packed`);
      assert.ok(!file.startsWith("scripts/replay-prompts/"), `${file} should not be packed`);
      assert.ok(!DISALLOWED_PACKED_FILE_PATTERNS.some((pattern) => pattern.test(file)), `${file} should not be packed`);
      if (file.startsWith("scripts/")) {
        assert.ok(isPackableScript(file), `${file} should not be packed from scripts/`);
      }
      if (file.startsWith("bin/")) {
        assert.ok(isPackableBin(file), `${file} should not be packed from bin/`);
      }
      if (file.startsWith(".hacker-bob/")) {
        assert.ok(isPackableBobResource(file), `${file} should not be packed from .hacker-bob/`);
      }
      if (file.startsWith("testing/")) {
        assert.ok(
          file.startsWith("testing/policy-replay/"),
          `${file} should not be packed`,
        );
        assert.ok(!file.includes("node_modules"), `${file} should not include node_modules`);
      }
      if (file.startsWith("mcp/")) {
        assert.ok(isPackableMcpRuntimeFile(file), `${file} is not an admitted MCP runtime file`);
      }
      assert.ok(!file.startsWith(".github/"), `${file} should not be packed`);
      if (file.startsWith("packages/")) {
        assert.ok(
          isCanonicalRuntimePackageFile(file),
          `${file} is not an allowlisted nested physical runtime file`,
        );
      }
      assert.notEqual(file, ".claude/hooks/bob-update-lib.js", "hook-local update library should not be packed");
      assert.ok(!LOCAL_INSTALL_METADATA_FILES.has(file), `${file} should not be packed`);
      assert.ok(!file.includes("bounty-agent-sessions"), `${file} should not be packed`);
      assert.ok(!file.includes("hacker-bob-sessions"), `${file} should not be packed`);
      assert.ok(!file.includes(".cache/"), `${file} should not be packed`);
      assert.ok(!file.endsWith("/.bob-optional-package.json"), `${file} is local install metadata`);
      assert.ok(!file.includes("/.staging-"), `${file} is local transaction state`);
      assert.ok(!file.includes("/.backup-"), `${file} is local transaction state`);
      assert.ok(!file.includes("/.transaction-"), `${file} is local transaction state`);
      assert.ok(!/(?:^|\/)(?:release-envelope|trust-policy|hil-evidence)\.json$/u.test(file),
        `${file} must not ship a real trust root or local qualification evidence`);
      if (isPackedTextFile(file)) {
        const sourcePath = path.join(ROOT, file);
        if (fs.existsSync(sourcePath)) {
          const content = fs.readFileSync(sourcePath, "utf8");
          for (const pattern of DISALLOWED_PACKED_TEXT_PATTERNS) {
            assert.doesNotMatch(content, pattern, `${file} should not include local absolute paths`);
          }
          assert.doesNotMatch(
            content,
            /-----BEGIN (?:OPENSSH |EC |RSA )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]{40,}\r?\n-----END (?:OPENSSH |EC |RSA )?PRIVATE KEY-----/u,
            `${file} must not include a private key`,
          );
        }
      }
    }
  } finally {
    fs.rmSync(npmCache, { recursive: true, force: true });
  }
});

test("lifecycle custodian source package never packs its compiled test helper", () => {
  const packageRoot = path.join(ROOT, "packages", "bob-lifecycle-custodian-native-darwin");
  const npmCache = fs.mkdtempSync(path.join(os.tmpdir(), "bob-custodian-npm-cache-"));
  try {
    const output = execFileSync("npm", ["pack", "--dry-run", "--json"], {
      cwd: packageRoot,
      env: { ...process.env, npm_config_cache: npmCache },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const [pack] = JSON.parse(output);
    const files = pack.files.map((file) => file.path).sort();
    assert.deepEqual(files, [
      "README.md",
      "native/lifecycle_custodian.c",
      "package.json",
      "scripts/build-test-fixture.js",
      "scripts/check-source.js",
      "test/source-contract.test.js",
    ].sort());
    assert.ok(!files.some((file) => file.startsWith("dist/")));
  } finally {
    fs.rmSync(npmCache, { recursive: true, force: true });
  }
});

test("canonical package excludes internal design docs and scratch topology", () => {
  const output = execFileSync("npm", ["pack", "--dry-run", "--json"], {
    cwd: ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  const [pack] = JSON.parse(output);
  const files = new Set(pack.files.map((file) => file.path));
  for (const file of files) {
    assert.ok(!isInternalRefactorDoc(file), `${file} should not be packed`);
    assert.ok(!isInternalPlaneBeliefRoadmapDoc(file), `${file} should not be packed`);
    assert.ok(!isInternalPlaneDeltaDetailDoc(file), `${file} should not be packed`);
    assert.ok(!isInternalPlaneDeltaVerificationDoc(file), `${file} should not be packed`);
    assert.ok(!isInternalPlanePhysicalDoc(file), `${file} should not be packed`);
    assert.ok(!isInternalPolicyReplayPlanningDoc(file), `${file} should not be packed`);
    assert.ok(!isInternalRefactorScratch(file), `${file} should not be packed`);
  }
  for (const entrypoint of [
    "packages/bob-artifact-vault/index.js",
    "packages/bob-artifact-vault/worker.js",
    "packages/bob-artifact-vault/operator.js",
    "mcp/lib/physical-provider-authoring.js",
    "packages/bob-instrument-deterministic/lib/orthogonal-fixture.js",
    "docs/provider-authoring.md",
  ]) {
    assert.ok(files.has(entrypoint), `${entrypoint} must be packed for its declared export`);
  }
});

test("nested physical runtime packages pack only declared runtime sources", () => {
  const packageSpecs = [
    {
      root: "packages/bob-artifact-vault",
      files: ["index.js", "worker.js", "operator.js", "lib/**/*.js"],
      rootEntrypoints: ["index.js", "worker.js", "operator.js"],
    },
    {
      root: "packages/bob-instrument-broker",
      files: ["lib/**/*.js"],
      rootEntrypoints: [],
    },
    {
      root: "packages/bob-instrument-contracts",
      files: ["lib/**/*.js"],
      rootEntrypoints: [],
    },
    {
      root: "packages/bob-instrument-chameleon",
      files: ["lib/**/*.js"],
      rootEntrypoints: [],
    },
    {
      root: "packages/bob-instrument-chameleon-worker-runtime",
      files: ["lib/**/*.js"],
      rootEntrypoints: [],
    },
    {
      root: "packages/bob-instrument-deterministic",
      files: ["lib/**/*.js"],
      rootEntrypoints: [],
    },
  ];

  for (const spec of packageSpecs) {
    const relativeRoot = spec.root;
    const packageRoot = path.join(ROOT, relativeRoot);
    const packageJson = JSON.parse(fs.readFileSync(path.join(packageRoot, "package.json"), "utf8"));
    assert.deepEqual(packageJson.files, spec.files);

    const npmCache = fs.mkdtempSync(path.join(os.tmpdir(), "bob-nested-package-cache-"));
    try {
      const output = execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
        cwd: packageRoot,
        env: { ...process.env, npm_config_cache: npmCache },
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      });
      const [pack] = JSON.parse(output);
      const files = pack.files.map((file) => file.path).sort();
      const expected = fs.readdirSync(path.join(packageRoot, "lib"))
        .filter((name) => name.endsWith(".js"))
        .map((name) => `lib/${name}`)
        .concat(spec.rootEntrypoints)
        .concat("package.json")
        .sort();
      assert.deepEqual(files, expected, `${relativeRoot} packed undeclared files`);
      assert.ok(!files.some((file) => file.startsWith("test/")),
        `${relativeRoot} must not pack tests or fixtures`);
      const declaredEntrypoints = [
        packageJson.main,
        ...Object.values(packageJson.exports || {}),
      ].filter(Boolean).map((file) => file.replace(/^\.\//u, ""));
      for (const entrypoint of declaredEntrypoints) {
        assert.ok(files.includes(entrypoint),
          `${relativeRoot} declared entrypoint ${entrypoint} is missing from its pack`);
      }
    } finally {
      fs.rmSync(npmCache, { recursive: true, force: true });
    }
  }
});

test("real canonical tarball has a closed all-export physical runtime dependency graph", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-canonical-closure-"));
  const npmCache = path.join(tempRoot, "npm-cache");
  const extractedRoot = path.join(tempRoot, "extracted");
  const isolatedHome = path.join(tempRoot, "home");
  try {
    fs.mkdirSync(extractedRoot, { recursive: true });
    const output = execFileSync("npm", [
      "pack",
      "--json",
      "--ignore-scripts",
      "--pack-destination",
      tempRoot,
    ], {
      cwd: ROOT,
      env: { ...process.env, npm_config_cache: npmCache },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const packs = JSON.parse(output);
    assert.equal(packs.length, 1);
    const tarball = path.join(tempRoot, packs[0].filename);
    assert.ok(fs.statSync(tarball).isFile(), "npm pack must emit a real tarball");
    execFileSync("tar", ["-xzf", tarball, "-C", extractedRoot], {
      cwd: tempRoot,
      stdio: ["ignore", "pipe", "pipe"],
    });

    const runtimeRoot = path.join(extractedRoot, "package");
    assert.equal(
      JSON.parse(fs.readFileSync(path.join(runtimeRoot, "package.json"), "utf8")).name,
      "hacker-bob",
    );
    const extractedCompatibilityStore = path.join(
      runtimeRoot,
      "mcp",
      "lib",
      "instrument-lease-store.js",
    );
    const extractedCanonicalStore = path.join(
      runtimeRoot,
      "packages",
      "bob-instrument-broker",
      "lib",
      "instrument-lease-store.js",
    );
    assert.equal(require(extractedCompatibilityStore), require(extractedCanonicalStore));
    assert.ok(fs.statSync(extractedCompatibilityStore).size < 256);
    assert.ok(fs.statSync(extractedCanonicalStore).size > 200_000);
    const expected = declaredRuntimeEntrypoints(runtimeRoot, CANONICAL_RUNTIME_PACKAGE_ROOTS);
    assert.equal(expected.length, 57, "canonical physical packages must retain all 57 declared entrypoints");

    const loaded = loadCanonicalRuntimeEntrypoints({
      runtimeRoot,
      relativeRoots: CANONICAL_RUNTIME_PACKAGE_ROOTS,
      isolatedHome,
      requireNoNodeModules: true,
    });
    assert.deepEqual(loaded.loaded, expected);
    for (const entry of expected) {
      assert.ok(
        loaded.resolved_modules.includes(entry.entrypoint),
        `${entry.entrypoint} was declared but not resolved from the extracted tarball`,
      );
    }

    const embeddedPackageNames = CANONICAL_RUNTIME_PACKAGE_ROOTS.map((relativeRoot) => {
      const manifest = JSON.parse(fs.readFileSync(
        path.join(runtimeRoot, relativeRoot, "package.json"),
        "utf8",
      ));
      assert.equal(manifest.private, true, `${relativeRoot} must remain embedded and private`);
      return manifest.name;
    });
    for (const relativeRoot of CANONICAL_RUNTIME_PACKAGE_ROOTS) {
      for (const file of sourceTreeFiles(runtimeRoot, relativeRoot).filter((entry) => (
        entry.endsWith(".js")
      ))) {
        const source = fs.readFileSync(path.join(runtimeRoot, file), "utf8");
        for (const packageName of embeddedPackageNames) {
          const escapedName = packageName.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
          assert.doesNotMatch(
            source,
            new RegExp(`\\brequire\\(\\s*["']${escapedName}(?:/[^"']*)?["']\\s*\\)`, "u"),
            `${file} must bind embedded private packages by static sibling path, not ${packageName}`,
          );
        }
      }
    }
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("package policy excludes denied files even if they exist in the source tree", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-package-policy-"));
  try {
    fs.mkdirSync(path.join(root, "docs"), { recursive: true });
    fs.mkdirSync(path.join(root, "docs", "plane-belief", "detail"), { recursive: true });
    fs.mkdirSync(path.join(root, "docs", "plane-delta", "detail"), { recursive: true });
    fs.mkdirSync(path.join(root, "docs", "plane-delta", "verification"), { recursive: true });
    fs.mkdirSync(path.join(root, "docs", "plane-physical"), { recursive: true });
    fs.mkdirSync(path.join(root, "mcp", "lib", "fuzz"), { recursive: true });
    fs.mkdirSync(path.join(root, ".claude", "hooks"), { recursive: true });
    fs.mkdirSync(path.join(root, "scripts", "replay-prompts"), { recursive: true });
    fs.mkdirSync(path.join(root, "testing", "policy-replay"), { recursive: true });
    fs.writeFileSync(path.join(root, ".claude", "hooks", "scope-guard.sh"), "stale\n");
    fs.writeFileSync(path.join(root, ".claude", "hooks", "scope-guard-mcp.sh"), "stale\n");
    fs.writeFileSync(path.join(root, "docs", "hacker-bob-offline-guide.pdf"), "stale\n");
    fs.writeFileSync(path.join(root, "docs", "causal-belief-hypergraph.md"), "internal\n");
    fs.writeFileSync(path.join(root, "docs", "plane-belief", "nodes.json"), "{}\n");
    fs.writeFileSync(path.join(root, "docs", "plane-belief", "detail", "CB-1.md"), "internal\n");
    fs.writeFileSync(path.join(root, "docs", "plane-delta", "README.md"), "internal\n");
    fs.writeFileSync(path.join(root, "docs", "plane-delta", "detail", "S14.md"), "internal\n");
    fs.writeFileSync(path.join(root, "docs", "plane-delta", "verification", "WEAVE.md"), "internal\n");
    fs.writeFileSync(path.join(root, "docs", "plane-physical", "nodes.json"), "{}\n");
    fs.writeFileSync(path.join(root, "mcp", "server.js"), "module.exports = {};\n");
    fs.writeFileSync(path.join(root, "mcp", "lib", "runtime.js"), "module.exports = {};\n");
    fs.writeFileSync(path.join(root, "mcp", "lib", "fuzz", "bob-multitu-build.sh"), "exit 0\n");
    fs.writeFileSync(path.join(root, "mcp", "lib", "hil-evidence.json"), "{}\n");
    fs.writeFileSync(path.join(root, "mcp", "lib", "operator-private.pem"), "secret\n");
    fs.writeFileSync(path.join(root, "scripts", "replay-refusal.js"), "stale\n");
    fs.writeFileSync(path.join(root, "scripts", "replay-prompts", "00-baseline.md"), "stale\n");
    fs.writeFileSync(path.join(root, "scripts", "keep.js"), "keep\n");
    fs.writeFileSync(path.join(root, "testing", "policy-replay", "README.md"), "keep\n");
    fs.writeFileSync(path.join(root, "testing", "policy-replay", "LIVE_SMOKE_DESIGN.md"), "internal\n");

    const expectedFiles = expectedCanonicalFiles(root);
    assert.ok(expectedFiles.includes("scripts/keep.js"));
    assert.ok(expectedFiles.includes("testing/policy-replay/README.md"));
    assert.ok(!expectedFiles.includes("docs/causal-belief-hypergraph.md"));
    assert.ok(!expectedFiles.includes("docs/plane-belief/nodes.json"));
    assert.ok(!expectedFiles.includes("docs/plane-belief/detail/CB-1.md"));
    assert.ok(!expectedFiles.includes("docs/plane-delta/README.md"));
    assert.ok(!expectedFiles.includes("docs/plane-delta/detail/S14.md"));
    assert.ok(!expectedFiles.includes("docs/plane-delta/verification/WEAVE.md"));
    assert.ok(!expectedFiles.includes("docs/plane-physical/nodes.json"));
    assert.ok(!expectedFiles.includes("testing/policy-replay/LIVE_SMOKE_DESIGN.md"));
    assert.ok(expectedFiles.includes("mcp/server.js"));
    assert.ok(expectedFiles.includes("mcp/lib/runtime.js"));
    assert.ok(expectedFiles.includes("mcp/lib/fuzz/bob-multitu-build.sh"));
    assert.ok(!expectedFiles.includes("mcp/lib/hil-evidence.json"));
    assert.ok(!expectedFiles.includes("mcp/lib/operator-private.pem"));
    for (const excluded of EXCLUDED_CANONICAL_PACKAGE_FILES) {
      assert.ok(!expectedFiles.includes(excluded), `${excluded} should not be expected`);
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

for (const wrapper of WRAPPER_PACKAGES) {
  test(`${wrapper.name} package version matches canonical package`, () => {
    const wrapperVersion = require(path.join(wrapper.root, "package.json")).version;
    assert.equal(wrapperVersion, PACKAGE_VERSION);
  });

  test(`${wrapper.name} package declares bin ${wrapper.name} -> ${wrapper.bin}`, () => {
    const wrapperPackage = require(path.join(wrapper.root, "package.json"));
    assert.deepEqual(wrapperPackage.bin, { [wrapper.name]: wrapper.bin });
    assert.deepEqual(wrapperPackage.files, [wrapper.bin, "README.md"]);
    assert.equal(wrapperPackage.dependencies && wrapperPackage.dependencies["hacker-bob"], PACKAGE_VERSION);
  });

  test(`${wrapper.name} bin script pins --adapter ${wrapper.adapter} when none is supplied`, () => {
    const binSource = fs.readFileSync(path.join(wrapper.root, wrapper.bin), "utf8");
    assert.match(binSource, /process\.argv\.push\(\s*"--adapter"\s*,/);
    assert.match(binSource, new RegExp(`"${wrapper.adapter}"`));
    // Explicit --adapter must be respected: the wrapper only injects when
    // the operator has not already supplied one. Catches a regression that
    // would force every install through the wrapper's pinned adapter.
    assert.match(binSource, /arg === "--adapter" \|\| arg\.startsWith\("--adapter="\)/);
    assert.match(binSource, /require\("hacker-bob\/bin\/hacker-bob\.js"\)/);
  });

  test(`${wrapper.name} package packs only wrapper and manifest`, () => {
    const npmCache = fs.mkdtempSync(path.join(os.tmpdir(), `bob-${wrapper.name}-npm-cache-`));
    try {
      const output = execFileSync("npm", ["pack", "--dry-run", "--json"], {
        cwd: wrapper.root,
        env: { ...process.env, npm_config_cache: npmCache },
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      });
      const [pack] = JSON.parse(output);
      assert.equal(pack.name, wrapper.name);
      assert.equal(pack.version, PACKAGE_VERSION);
      assert.deepEqual(
        pack.files.map((file) => file.path).sort(),
        [wrapper.bin, "README.md", "package.json"].sort(),
      );
      assert.ok(pack.size < 5000, `${wrapper.name} pack size ${pack.size} exceeds 5 KB threshold`);
    } finally {
      fs.rmSync(npmCache, { recursive: true, force: true });
    }
  });
}
