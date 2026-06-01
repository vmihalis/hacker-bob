const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  DISALLOWED_PACKED_FILE_PATTERNS,
  DISALLOWED_PACKED_TEXT_PATTERNS,
  EXCLUDED_CANONICAL_PACKAGE_FILES,
  LOCAL_INSTALL_METADATA_FILES,
  REQUIRED_SUPPORT_SURFACES,
  STALE_HOOK_SCRIPT_NAMES,
  expectedCanonicalFiles,
  isExcludedCanonicalPackageFile,
  isInternalRefactorDoc,
  isInternalRefactorScratch,
  isPackableBin,
  isPackableBobResource,
  isPackableScript,
  isPackedTextFile,
  wrapperPackages,
} = require("../scripts/lib/package-policy.js");

const ROOT = path.join(__dirname, "..");
const PACKAGE_VERSION = require("../package.json").version;
const WRAPPER_PACKAGES = wrapperPackages(ROOT);

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

test("canonical package declares PSL as a runtime dependency without vendoring it", () => {
  const packageJson = require("../package.json");
  const packageLock = require("../package-lock.json");
  assert.equal(packageJson.dependencies.psl, "^1.15.0");
  assert.equal(packageLock.packages[""].dependencies.psl, "^1.15.0");
  assert.equal(packageLock.packages["node_modules/psl"].version, "1.15.0");
  assert.equal(packageLock.packages["node_modules/psl"].dependencies.punycode, "^2.3.1");
  assert.equal(packageLock.packages["node_modules/punycode"].version, "2.3.1");
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
    "2026-06-10T00:00:00.000Z",
  ], {
    cwd: ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }));

  assert.match(output, /OK PSL overlay escape hatch remains implemented without runtime network refresh/);
  assert.match(output, /OK psl lockfile version matches npm latest 1\.15\.0/);
  assert.match(output, /WARN psl@1\.15\.0 latest publish age \d+\.\d days exceeds warning threshold 180 days; lockfile is still npm latest/);
  assert.match(output, /INFO psl freshness owner: Public Suffix List scope ownership/);
  assert.match(output, /Dependency freshness check passed with 1 warning\(s\)\./);
});

test("dependency freshness check fails when PSL is behind latest", () => {
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
    "bounty-statusline.js",
    "hunter-subagent-stop.js",
    "session-read-guard.sh",
    "session-write-guard.sh",
  ]) {
    assert.ok(packageJson.files.includes(`.claude/hooks/${hookName}`), `${hookName} should be explicitly packed`);
  }
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
    for (const excluded of EXCLUDED_CANONICAL_PACKAGE_FILES) {
      assert.ok(!files.has(excluded), `${excluded} should not be packed`);
      assert.ok(!expectedFiles.includes(excluded), `${excluded} should not be expected`);
      assert.equal(isExcludedCanonicalPackageFile(excluded), true, `${excluded} should be denied by policy`);
    }

    // Backstop against accidental bloat (a stray node_modules, cache, or test
    // fixture would add megabytes); the real exclusions are asserted per-file
    // below. Raised 2.5 MB -> 3 MB after shipped docs/prompts grew the canonical
    // package past the old ceiling (packed ~2.51 MB at v1.3.4, all intended to
    // ship per the docs/** files glob and expectedCanonicalFiles()).
    assert.ok(pack.size < 3000000, `npm pack size ${pack.size} exceeds 3 MB threshold`);

    for (const file of files) {
      assert.ok(!file.startsWith("node_modules/"), `${file} should not vendor runtime dependencies`);
      assert.ok(!file.startsWith("test/"), `${file} should not be packed`);
      assert.ok(!isInternalRefactorDoc(file), `${file} should not be packed`);
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
      assert.ok(!file.startsWith(".github/"), `${file} should not be packed`);
      assert.ok(!file.startsWith("packages/"), `${file} should not be packed in canonical package`);
      assert.notEqual(file, ".claude/hooks/bob-update-lib.js", "hook-local update library should not be packed");
      assert.ok(!LOCAL_INSTALL_METADATA_FILES.has(file), `${file} should not be packed`);
      assert.ok(!file.includes("bounty-agent-sessions"), `${file} should not be packed`);
      assert.ok(!file.includes(".cache/"), `${file} should not be packed`);
      if (isPackedTextFile(file)) {
        const sourcePath = path.join(ROOT, file);
        if (fs.existsSync(sourcePath)) {
          const content = fs.readFileSync(sourcePath, "utf8");
          for (const pattern of DISALLOWED_PACKED_TEXT_PATTERNS) {
            assert.doesNotMatch(content, pattern, `${file} should not include local absolute paths`);
          }
        }
      }
    }
  } finally {
    fs.rmSync(npmCache, { recursive: true, force: true });
  }
});

test("canonical package excludes internal refactor docs and scratch topology", () => {
  const output = execFileSync("npm", ["pack", "--dry-run", "--json"], {
    cwd: ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  const [pack] = JSON.parse(output);
  const files = new Set(pack.files.map((file) => file.path));
  for (const file of files) {
    assert.ok(!isInternalRefactorDoc(file), `${file} should not be packed`);
    assert.ok(!isInternalRefactorScratch(file), `${file} should not be packed`);
  }
});

test("package policy excludes denied files even if they exist in the source tree", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-package-policy-"));
  try {
    fs.mkdirSync(path.join(root, "docs"), { recursive: true });
    fs.mkdirSync(path.join(root, ".claude", "hooks"), { recursive: true });
    fs.mkdirSync(path.join(root, "scripts", "replay-prompts"), { recursive: true });
    fs.writeFileSync(path.join(root, ".claude", "hooks", "scope-guard.sh"), "stale\n");
    fs.writeFileSync(path.join(root, ".claude", "hooks", "scope-guard-mcp.sh"), "stale\n");
    fs.writeFileSync(path.join(root, "docs", "hacker-bob-offline-guide.pdf"), "stale\n");
    fs.writeFileSync(path.join(root, "scripts", "replay-refusal.js"), "stale\n");
    fs.writeFileSync(path.join(root, "scripts", "replay-prompts", "00-baseline.md"), "stale\n");
    fs.writeFileSync(path.join(root, "scripts", "keep.js"), "keep\n");

    const expectedFiles = expectedCanonicalFiles(root);
    assert.ok(expectedFiles.includes("scripts/keep.js"));
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
