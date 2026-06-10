"use strict";

// Cycle O.3 — repo-env preparation + Dockerfile.bob tests.
//
// Coverage:
// - Language detection map for Node/Python/Go/Rust/Ruby/PHP/Java/C/default.
// - NFS/XDR shape special case forwards from O.2 inventory.
// - dry_run is default and writes Dockerfile.bob + repo-env.json without
//   exec'ing docker.
// - Generated Dockerfile carries `ARG SESSION_ID=<target_domain>` (O-D6),
//   `USER 1000:1000` (O-P3), `--ignore-scripts` in node recipes.
// - build_image: true threads the egress proxy via `--build-arg` and the
//   constructed docker build argv carries `--network` + `--build-arg`
//   + the per-session image tag (positive assertion per flag).
// - Image tag binds to the SessionNucleus-pinned repo_hash.
// - `ENV` secret leakage check refuses any generated Dockerfile that bakes
//   a proxy/secret into image layers.
// - Docker absent + build_image: true → structured `docker_unavailable`.
// - Tool wrapper is orchestrator-only and declares the right artefacts.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  initRepoSession,
  buildRepoInventory,
  SEED_CORPUS_SUMMARY_LIMIT,
} = require("../mcp/lib/repo-target.js");
const {
  prepareRepoEnv,
  buildDockerfileBob,
  buildDockerBuildArgv,
  buildImageTag,
  detectLanguageProfile,
  recommendedCommandsFor,
  parseFuzzStats,
  assertNoEnvSecretLeak,
  dockerfileBobPath,
  repoEnvJsonPath,
  loadNativeFuzzShape,
  C_DEFAULT_APT_PACKAGES,
  NFS_EXTRA_APT_PACKAGES,
  NATIVE_FUZZ_EXTRA_APT_PACKAGES,
  ENV_SECRET_LEAK_RE,
  RECOMMENDED_COMMAND_ROLES,
} = require("../mcp/lib/repo-env.js");
const {
  validateNoSensitiveMaterial,
} = require("../mcp/lib/sensitive-material.js");
const repoPrepareEnvTool = require("../mcp/lib/tools/repo-prepare-env.js");
const {
  EXPLICIT_AUTHORITY_CLASS_BY_TOOL,
} = require("../mcp/lib/session-authority.js");

// Async-aware temp HOME wrapper. The OSS prepare-env path is async because
// it may exec docker build; we must hold HOME / cleanup until that promise
// resolves, otherwise the OS temp dir vanishes before the test assertions
// run against it.
async function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-repo-env-"));
  process.env.HOME = home;
  try {
    return await fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function makeTempRepoDir(prefix = "bob-repo-env-fixture-") {
  const raw = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  return fs.realpathSync.native ? fs.realpathSync.native(raw) : fs.realpathSync(raw);
}

function write(repoRoot, rel, content = "") {
  const abs = path.join(repoRoot, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content, "utf8");
}

// Helper: synthesize a one-marker repo so detectLanguageProfile resolves to a
// deterministic language. Tests use this for the language-detection matrix.
function makeMarkerRepo(marker, content = "{}") {
  const root = makeTempRepoDir();
  write(root, marker, content);
  return root;
}

// ---------- Language detection map ----------

test("detectLanguageProfile resolves Node from package.json → node:20", () => {
  const root = makeMarkerRepo("package.json");
  const result = detectLanguageProfile(root);
  assert.equal(result.language, "node");
  assert.equal(result.base_image, "node:20");
  assert.equal(result.marker, "package.json");
});

test("detectLanguageProfile resolves Python from pyproject.toml → python:3.12", () => {
  const root = makeMarkerRepo("pyproject.toml", "[project]\nname=\"x\"\n");
  const result = detectLanguageProfile(root);
  assert.equal(result.language, "python");
  assert.equal(result.base_image, "python:3.12");
});

test("detectLanguageProfile resolves Python from requirements.txt", () => {
  const root = makeMarkerRepo("requirements.txt", "");
  const result = detectLanguageProfile(root);
  assert.equal(result.language, "python");
});

test("detectLanguageProfile resolves Python from setup.py", () => {
  const root = makeMarkerRepo("setup.py", "");
  const result = detectLanguageProfile(root);
  assert.equal(result.language, "python");
});

test("detectLanguageProfile resolves Go from go.mod → golang:1.22", () => {
  const root = makeMarkerRepo("go.mod", "module x\n");
  const result = detectLanguageProfile(root);
  assert.equal(result.language, "go");
  assert.equal(result.base_image, "golang:1.22");
});

test("detectLanguageProfile resolves Rust from Cargo.toml → rust:1.79", () => {
  const root = makeMarkerRepo("Cargo.toml", "[package]\nname=\"x\"\n");
  const result = detectLanguageProfile(root);
  assert.equal(result.language, "rust");
  assert.equal(result.base_image, "rust:1.79");
});

test("detectLanguageProfile resolves Ruby from Gemfile → ruby:3.3", () => {
  const root = makeMarkerRepo("Gemfile", "source 'https://rubygems.org'\n");
  const result = detectLanguageProfile(root);
  assert.equal(result.language, "ruby");
  assert.equal(result.base_image, "ruby:3.3");
});

test("detectLanguageProfile resolves PHP from composer.json → php:8.3-cli", () => {
  const root = makeMarkerRepo("composer.json", "{}");
  const result = detectLanguageProfile(root);
  assert.equal(result.language, "php");
  assert.equal(result.base_image, "php:8.3-cli");
});

test("detectLanguageProfile resolves Java from pom.xml → eclipse-temurin:21-jdk", () => {
  const root = makeMarkerRepo("pom.xml", "<project/>\n");
  const result = detectLanguageProfile(root);
  assert.equal(result.language, "java");
  assert.equal(result.base_image, "eclipse-temurin:21-jdk");
});

test("detectLanguageProfile resolves Java from build.gradle", () => {
  const root = makeMarkerRepo("build.gradle", "plugins { id 'java' }\n");
  const result = detectLanguageProfile(root);
  assert.equal(result.language, "java");
});

test("detectLanguageProfile resolves Java from build.gradle.kts", () => {
  const root = makeMarkerRepo("build.gradle.kts", "plugins { java }\n");
  const result = detectLanguageProfile(root);
  assert.equal(result.language, "java");
});

test("detectLanguageProfile resolves C from CMakeLists.txt → ubuntu:24.04", () => {
  const root = makeMarkerRepo("CMakeLists.txt", "project(x)\n");
  const result = detectLanguageProfile(root);
  assert.equal(result.language, "c");
  assert.equal(result.base_image, "ubuntu:24.04");
});

test("detectLanguageProfile resolves C from Makefile", () => {
  const root = makeMarkerRepo("Makefile", "all:\n\techo hi\n");
  const result = detectLanguageProfile(root);
  assert.equal(result.language, "c");
});

test("detectLanguageProfile defaults to ubuntu:24.04 when no markers present", () => {
  const root = makeTempRepoDir();
  write(root, "README.md", "# nothing here\n");
  const result = detectLanguageProfile(root);
  assert.equal(result.language, "default");
  assert.equal(result.base_image, "ubuntu:24.04");
  assert.equal(result.marker, null);
});

// ---------- Recommended commands ----------

test("recommendedCommandsFor node uses npm ci --ignore-scripts (security carry-back)", () => {
  const commands = recommendedCommandsFor("node");
  const install = commands.find((c) => c.id === "install");
  assert.ok(install, "node profile should expose an install command");
  assert.deepEqual(install.command, ["npm", "ci", "--ignore-scripts"]);
  assert.equal(install.role, "build");
});

test("recommendedCommandsFor python uses --no-build-isolation (static-friendly install)", () => {
  const commands = recommendedCommandsFor("python");
  const install = commands.find((c) => c.id === "install");
  assert.ok(install, "python profile should expose an install command");
  assert.ok(install.command.includes("--no-build-isolation"));
  assert.ok(install.command.includes("pip"));
  assert.equal(install.role, "build");
});

test("recommendedCommandsFor c uses compose role with sh -lc staging recipe", () => {
  const commands = recommendedCommandsFor("c");
  assert.equal(commands.length, 1);
  const compose = commands[0];
  assert.equal(compose.role, "compose");
  assert.equal(compose.command[0], "sh");
  assert.equal(compose.command[1], "-lc");
  // The compose recipe must stage /src into /work/repo (read-only mount
  // wisdom from MVP).
  assert.match(compose.command[2], /cp\s+-a\s+\/src/);
  assert.match(compose.command[2], /\/work\/repo/);
  assert.match(compose.command[2], /cmake/);
});

test("recommendedCommandsFor c surfaces NFS/XDR note when shape detected", () => {
  const commands = recommendedCommandsFor("c", { nfsXdrShape: true });
  assert.match(commands[0].description, /NFS\/XDR/);
});

test("recommendedCommandsFor c emits one fuzz seed command when seed corpus is present", () => {
  const commands = recommendedCommandsFor("c", {
    seedCorpus: [{ rel_path: "fuzz/corpus", file_count: 2 }],
  });
  const fuzzCommands = commands.filter((command) => command.role === "fuzz");
  assert.equal(fuzzCommands.length, 1);
  assert.equal(fuzzCommands[0].id, "fuzz_seed_probe");
  assert.equal(fuzzCommands[0].seed_path, "fuzz/corpus");
  assert.match(fuzzCommands[0].description, /fuzz\/corpus/);
  assert.match(fuzzCommands[0].command[2], /find -- 'fuzz\/corpus'/);
});

test("recommendedCommandsFor c emits real ASAN+UBSAN libFuzzer recipe when native fuzz shape is present", () => {
  const commands = recommendedCommandsFor("c", {
    nativeFuzzShape: true,
    seedCorpus: [{ rel_path: "fuzz/corpus", file_count: 2 }],
  });
  const fuzzCommands = commands.filter((command) => command.role === "fuzz");
  assert.equal(fuzzCommands.length, 1);
  const fuzz = fuzzCommands[0];
  assert.equal(fuzz.id, "fuzz_asan_ubsan");
  assert.equal(fuzz.seed_path, "fuzz/corpus");
  assert.match(fuzz.command[2], /LLVMFuzzerTestOneInput/);
  assert.match(fuzz.command[2], /find \. -type f/);
  assert.match(fuzz.command[2], /\*_fuzzer\.c/);
  assert.match(fuzz.command[2], /perl -0ne/);
  assert.match(fuzz.command[2], /find \. -type f .*'\*\.cpp'/);
  assert.match(fuzz.command[2], /LLVMFuzzerTestOneInput\\s\*/);
  assert.doesNotMatch(fuzz.command[2], /grep -RIl/);
  assert.match(fuzz.command[2], /clang(?:\+\+)?-18/);
  assert.match(fuzz.command[2], /-fsanitize=address,undefined,fuzzer/);
  assert.match(fuzz.command[2], /-o \/work\/out\/h -- "\$HARNESS"/);
  assert.match(fuzz.command[2], /-Iinclude/);
  assert.match(fuzz.command[2], /-max_total_time=240/);
  assert.ok(fuzz.command[2].length <= 2048, "native fuzz recipe token must stay within docker-run limit");
  assert.equal(commands.some((command) => command.id === "fuzz_seed_probe"), false);
});

test("recommendedCommandsFor c can emit only the native fuzz recipe for promoted polyglot repos", () => {
  const commands = recommendedCommandsFor("c", {
    nativeFuzzShape: true,
    nativeFuzzOnly: true,
  });
  assert.equal(commands.some((command) => command.id === "build_and_test"), false);
  assert.deepEqual(
    commands.map((command) => command.id),
    ["fuzz_asan_ubsan"],
  );
});

test("recommendedCommandsFor c ignores unsafe seed corpus paths before shell emission", () => {
  const commands = recommendedCommandsFor("c", {
    nativeFuzzShape: true,
    seedCorpus: [
      { rel_path: "/tmp/outside" },
      { rel_path: "../outside" },
      { rel_path: "safe corpus" },
    ],
  });
  const fuzz = commands.find((command) => command.id === "fuzz_asan_ubsan");
  assert.equal(fuzz.seed_path, "safe corpus");
  assert.doesNotMatch(fuzz.command[2], /\/tmp\/outside|\.\.\/outside/);
  assert.match(fuzz.command[2], /SEED='\.\/safe corpus'/);
  assert.match(fuzz.command[2], /realpath -m -- "\$SEED"/);
  assert.match(fuzz.command[2], /cp -a -- "\$SEED_REAL"\/\./);
});

test("recommendedCommandsFor c unpacks OSS-Fuzz zip seed corpora before fuzzing", () => {
  const commands = recommendedCommandsFor("c", {
    nativeFuzzShape: true,
    seedCorpus: [{ rel_path: "parser_seed_corpus.zip", has_zip: true }],
  });
  const fuzz = commands.find((command) => command.id === "fuzz_asan_ubsan");
  assert.equal(fuzz.seed_path, "parser_seed_corpus.zip");
  assert.match(fuzz.command[2], /SEED_IS_ZIP=1/);
  assert.match(fuzz.command[2], /ZIP_MAX_BYTES=16777216/);
  assert.match(fuzz.command[2], /ZIP_MAX_FILES=4096/);
  assert.match(fuzz.command[2], /unzip -Z -1 "\$SEED_REAL" > "\$ZIP_LIST"/);
  assert.match(fuzz.command[2], /test "\$ZIP_TOTAL" -le "\$ZIP_MAX_BYTES"/);
  assert.match(fuzz.command[2], /unzip -qq -o -j -- "\$SEED_REAL" -d \/work\/out\/corpus/);
  assert.match(fuzz.command[2], /\(\^\|\\\/\)\\\.\\\.\(\$\|\\\/\)/);
});

test("recommendedCommandsFor c guards dash-prefixed seed corpus paths", () => {
  const commands = recommendedCommandsFor("c", {
    nativeFuzzShape: true,
    seedCorpus: [{ rel_path: "-corpus" }],
  });
  const fuzz = commands.find((command) => command.id === "fuzz_asan_ubsan");
  assert.equal(fuzz.seed_path, "-corpus");
  assert.match(fuzz.command[2], /SEED='\.\/-corpus'/);
  assert.match(fuzz.command[2], /cp -a --/);
});

test("recommendedCommandsFor c drops overlong seed setup to keep native fuzz recipe executable", () => {
  const commands = recommendedCommandsFor("c", {
    nativeFuzzShape: true,
    seedCorpus: [{ rel_path: `${"deep/".repeat(40)}corpus` }],
  });
  const fuzz = commands.find((command) => command.id === "fuzz_asan_ubsan");
  assert.equal(fuzz.seed_path, undefined);
  assert.ok(fuzz.command[2].length <= 2048, "native fuzz recipe token must stay within docker-run limit");
  assert.doesNotMatch(fuzz.command[2], /SEED=/);
});

test("every recommended_commands[].role is in RECOMMENDED_COMMAND_ROLES", () => {
  for (const lang of ["node", "python", "go", "rust", "ruby", "php", "java", "c"]) {
    const commands = recommendedCommandsFor(lang);
    for (const c of commands) {
      assert.ok(
        RECOMMENDED_COMMAND_ROLES.includes(c.role),
        `${lang} command ${c.id} has unknown role ${c.role}`,
      );
    }
  }
});

// ---------- Dockerfile.bob shape ----------

test("buildDockerfileBob places ARG SESSION_ID as the FIRST instruction (O-D6 cache-bust)", () => {
  const content = buildDockerfileBob({
    language: "node",
    baseImage: "node:20",
    targetDomain: "repo-fixture-deadbeef",
    nfsXdrShape: false,
    allowNetwork: false,
  });
  // Strip comments + blank lines, then assert ARG SESSION_ID is the first
  // real instruction.
  const firstInstruction = content
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))[0];
  assert.match(firstInstruction, /^ARG SESSION_ID=repo-fixture-deadbeef$/);
});

test("buildDockerfileBob emits USER 1000:1000 (O-P3 non-root)", () => {
  const content = buildDockerfileBob({
    language: "c",
    baseImage: "ubuntu:24.04",
    targetDomain: "repo-fixture-aa11bb22",
    nfsXdrShape: false,
    allowNetwork: false,
  });
  assert.match(content, /^USER 1000:1000$/m);
});

test("buildDockerfileBob refuses to bake ENV proxy/credentials into the image (O-P3)", () => {
  // Generated dockerfile content must not contain `ENV.*PROXY` etc. Even
  // with allow_network true we only emit ARG (build-time only) lines.
  for (const allowNetwork of [false, true]) {
    const content = buildDockerfileBob({
      language: "c",
      baseImage: "ubuntu:24.04",
      targetDomain: "repo-fixture-cc33dd44",
      nfsXdrShape: false,
      allowNetwork,
    });
    assert.equal(
      ENV_SECRET_LEAK_RE.test(content),
      false,
      `generated Dockerfile (allow_network=${allowNetwork}) must not bake ENV PROXY: ${content}`,
    );
    assert.doesNotThrow(() => assertNoEnvSecretLeak(content));
    if (allowNetwork) {
      // Build-time ARG declarations are expected; ENV remains absent.
      assert.match(content, /^ARG HTTP_PROXY=/m);
      assert.match(content, /^ARG HTTPS_PROXY=/m);
    }
  }
});

test("assertNoEnvSecretLeak throws when ENV proxy is present", () => {
  const bad = "FROM scratch\nENV HTTP_PROXY=http://leak/\nUSER 1000:1000\n";
  assert.throws(() => assertNoEnvSecretLeak(bad), /O-P3/);
});

test("assertNoEnvSecretLeak throws for ENV SECRET, ENV TOKEN, ENV API_KEY", () => {
  for (const env of ["ENV SECRET=foo", "ENV API_KEY=bar", "ENV PASSWORD=baz", "ENV TOKEN=qux"]) {
    assert.throws(() => assertNoEnvSecretLeak(`FROM scratch\n${env}\n`), /O-P3/);
  }
});

test("buildDockerfileBob skips apt-get install when allow_network=false (so --network none builds)", () => {
  const content = buildDockerfileBob({
    language: "c",
    baseImage: "ubuntu:24.04",
    targetDomain: "repo-fixture-ee55ff66",
    nfsXdrShape: false,
    allowNetwork: false,
  });
  assert.equal(
    /^RUN\s+apt-get update/m.test(content),
    false,
    "apt-get install must not appear when allow_network=false",
  );
  // The skipped-package note documents what would be installed when network
  // is opened so reviewers can see the intent inline.
  assert.match(content, /apt-get install skipped/);
});

test("buildDockerfileBob emits NFS extras when nfsXdrShape true (and allow_network)", () => {
  const content = buildDockerfileBob({
    language: "c",
    baseImage: "ubuntu:24.04",
    targetDomain: "repo-fixture-77ab8899",
    nfsXdrShape: true,
    allowNetwork: true,
  });
  for (const pkg of NFS_EXTRA_APT_PACKAGES) {
    assert.match(content, new RegExp(`\\b${pkg.replace(/[-]/g, "\\-")}\\b`),
      `NFS extra package ${pkg} missing`);
  }
  for (const pkg of C_DEFAULT_APT_PACKAGES) {
    assert.match(content, new RegExp(`\\b${pkg.replace(/[-]/g, "\\-")}\\b`),
      `default C package ${pkg} missing`);
  }
});

test("buildDockerfileBob emits compiler-rt parser deps only when nativeFuzzShape true", () => {
  const withoutFuzz = buildDockerfileBob({
    language: "c",
    baseImage: "ubuntu:24.04",
    targetDomain: "repo-fixture-no-fuzz",
    nfsXdrShape: false,
    nativeFuzzShape: false,
    allowNetwork: true,
  });
  assert.doesNotMatch(withoutFuzz, /\blibclang-rt-18-dev\b/);

  const withFuzz = buildDockerfileBob({
    language: "c",
    baseImage: "ubuntu:24.04",
    targetDomain: "repo-fixture-with-fuzz",
    nfsXdrShape: false,
    nativeFuzzShape: true,
    allowNetwork: true,
  });
  assert.match(
    withFuzz,
    /apt-get install -y --no-install-recommends [^\n]*\bclang clang-18\b/,
    "C images must keep the unversioned clang wrapper while pinning clang-18 for the fuzz recipe",
  );
  for (const pkg of NATIVE_FUZZ_EXTRA_APT_PACKAGES) {
    assert.match(withFuzz, new RegExp(`\\b${pkg.replace(/[-]/g, "\\-")}\\b`),
      `native fuzz package ${pkg} missing`);
  }
});

test("parseFuzzStats returns bounded integer scalars for libFuzzer stdout", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-fuzz-stats-"));
  try {
    const stdoutPath = path.join(dir, "run.stdout");
    fs.writeFileSync(
      stdoutPath,
      [
        "#12 INITED cov: 4 ft: 5 corp: 1/2b exec/s: 10 rss: 30Mb",
        "#99 NEW cov: 10 ft: 20 corp: 3/128b lim: 4096 exec/s: 123 rss: 31Mb",
      ].join("\n"),
      "utf8",
    );
    assert.deepEqual(parseFuzzStats(stdoutPath), {
      cov: 10,
      ft: 20,
      exec_per_s: 123,
      corpus_size: 3,
      crashes: 0,
    });

    fs.writeFileSync(
      stdoutPath,
      "#1 INITED cov: 1 ft: 2 corp: 1/1b exec/s: 3\n==123==ERROR: AddressSanitizer: heap-buffer-overflow\n",
      "utf8",
    );
    assert.deepEqual(parseFuzzStats(stdoutPath), {
      cov: 1,
      ft: 2,
      exec_per_s: 3,
      corpus_size: 1,
      crashes: 1,
    });

    fs.writeFileSync(
      stdoutPath,
      "#2 DONE cov: 2 ft: 3 corp: 1/1b exec/s: 4\nartifact_prefix='/work/out/crash-archive/'\n",
      "utf8",
    );
    assert.deepEqual(parseFuzzStats(stdoutPath), {
      cov: 2,
      ft: 3,
      exec_per_s: 4,
      corpus_size: 1,
      crashes: 0,
    });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("parseFuzzStats reads libFuzzer progress and crashes from stderr", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-fuzz-stats-stderr-"));
  try {
    const stdoutPath = path.join(dir, "run.stdout");
    const stderrPath = path.join(dir, "run.stderr");
    fs.writeFileSync(stdoutPath, "build output\n", "utf8");
    fs.writeFileSync(
      stderrPath,
      "#77 NEW cov: 31 ft: 44 corp: 5/512b exec/s: 900 rss: 40Mb\nERROR: libFuzzer: deadly signal\n",
      "utf8",
    );
    assert.deepEqual(parseFuzzStats(stdoutPath, stderrPath), {
      cov: 31,
      ft: 44,
      exec_per_s: 900,
      corpus_size: 5,
      crashes: 1,
    });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("parseFuzzStats never throws on empty malformed or non-libFuzzer stdout", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-fuzz-stats-empty-"));
  try {
    for (const [name, content] of [
      ["empty", ""],
      ["malformed", "#ABC cov: nope ft: nope exec/s: nope"],
      ["partial", "#12 NEW cov: 7"],
      ["afl", "cycles done : 1\npaths total : 8\n"],
    ]) {
      const stdoutPath = path.join(dir, `${name}.stdout`);
      fs.writeFileSync(stdoutPath, content, "utf8");
      let stats;
      assert.doesNotThrow(() => {
        stats = parseFuzzStats(stdoutPath);
      });
      for (const field of ["cov", "ft", "exec_per_s", "corpus_size", "crashes"]) {
        assert.ok(
          stats[field] == null || Number.isInteger(stats[field]),
          `${name}.${field} must be integer-or-null`,
        );
      }
    }
    assert.deepEqual(parseFuzzStats(path.join(dir, "missing.stdout")), {
      cov: null,
      ft: null,
      exec_per_s: null,
      corpus_size: null,
      crashes: null,
    });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------- buildDockerBuildArgv (per-flag positive assertions, O-P3) ----------

test("buildDockerBuildArgv carries --network none when allow_network=false", () => {
  const argv = buildDockerBuildArgv({
    dockerfilePath: "/tmp/Dockerfile.bob",
    contextPath: "/tmp/repo",
    imageTag: "bob-oss-repo-x:abc",
    allowNetwork: false,
    targetDomain: "repo-x-12345678",
    egressProfile: null,
  });
  assert.equal(argv.command, "docker");
  // Per-flag positive assertions: locate each flag individually so a
  // regression that drops one shows up as a single specific failure.
  assert.equal(argv.args[0], "build");
  const netIndex = argv.args.indexOf("--network");
  assert.ok(netIndex >= 0, "--network flag missing");
  assert.equal(argv.args[netIndex + 1], "none");
});

test("buildDockerBuildArgv carries --network default + --build-arg HTTP_PROXY when allow_network=true", () => {
  const argv = buildDockerBuildArgv({
    dockerfilePath: "/tmp/Dockerfile.bob",
    contextPath: "/tmp/repo",
    imageTag: "bob-oss-repo-x:abc",
    allowNetwork: true,
    targetDomain: "repo-x-12345678",
    egressProfile: { proxy_url: "http://proxy.invalid:3128/", proxy_configured: true },
  });
  const netIndex = argv.args.indexOf("--network");
  assert.equal(argv.args[netIndex + 1], "default");
  // Per-flag: HTTP_PROXY routed via --build-arg, NEVER baked into ENV.
  const buildArgFlags = argv.args
    .map((value, index) => ({ value, index }))
    .filter((entry) => entry.value === "--build-arg")
    .map((entry) => argv.args[entry.index + 1]);
  assert.ok(
    buildArgFlags.some((pair) => /^SESSION_ID=repo-x-12345678$/.test(pair)),
    "SESSION_ID build-arg missing",
  );
  assert.ok(
    buildArgFlags.some((pair) => /^HTTP_PROXY=http:\/\/proxy\.invalid:3128\/$/.test(pair)),
    "HTTP_PROXY build-arg missing",
  );
  assert.ok(
    buildArgFlags.some((pair) => /^HTTPS_PROXY=http:\/\/proxy\.invalid:3128\/$/.test(pair)),
    "HTTPS_PROXY build-arg missing",
  );
});

test("buildDockerBuildArgv tags with --tag <image_tag> and supplies --file <dockerfile>", () => {
  const argv = buildDockerBuildArgv({
    dockerfilePath: "/tmp/Dockerfile.bob",
    contextPath: "/tmp/repo",
    imageTag: "bob-oss-repo-y:f00dface",
    allowNetwork: false,
    targetDomain: "repo-y-deadbeef",
    egressProfile: null,
  });
  const tagIndex = argv.args.indexOf("--tag");
  assert.ok(tagIndex >= 0, "--tag flag missing");
  assert.equal(argv.args[tagIndex + 1], "bob-oss-repo-y:f00dface");
  const fileIndex = argv.args.indexOf("--file");
  assert.ok(fileIndex >= 0, "--file flag missing");
  assert.equal(argv.args[fileIndex + 1], "/tmp/Dockerfile.bob");
  // Context path is the last positional after --file <path>.
  assert.equal(argv.args[argv.args.length - 1], "/tmp/repo");
});

test("buildDockerBuildArgv does NOT thread proxy creds via process env (avoiding ENV in image)", () => {
  // Tests the contract: proxy routing is exclusively via --build-arg. The
  // returned env table is empty so a runtime executor cannot accidentally
  // leak host process env into the build.
  const argv = buildDockerBuildArgv({
    dockerfilePath: "/tmp/Dockerfile.bob",
    contextPath: "/tmp/repo",
    imageTag: "bob-oss-repo-z:cafef00d",
    allowNetwork: true,
    targetDomain: "repo-z-12345678",
    egressProfile: { proxy_url: "http://proxy.invalid:3128/", proxy_configured: true },
  });
  assert.deepEqual(argv.env, {}, "buildDockerBuildArgv must not pre-populate env table");
});

// ---------- buildImageTag binds to nucleus-pinned repo_hash ----------

test("buildImageTag binds to target_domain + pinned repo_hash", () => {
  // 16 hex chars of the repo hash so we stay under docker's 128-char tag limit.
  const tag = buildImageTag("repo-fixture-deadbeef", "abcdef1234567890abcdef1234567890abcdef12");
  assert.equal(tag, "bob-oss-repo-fixture-deadbeef:abcdef1234567890");
});

// ---------- prepareRepoEnv end-to-end ----------

test("prepareRepoEnv dry_run=true writes Dockerfile.bob + repo-env.json without docker exec", async () => {
  await withTempHome(async () => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "package.json", JSON.stringify({ name: "x" }));
    const init = initRepoSession({ repo_path: repoRoot });

    // Stub runtime: any call to execFile fails. The dry-run path must NOT
    // invoke docker.
    let dockerInvoked = false;
    const runtime = {
      execFile: async () => {
        dockerInvoked = true;
        throw new Error("execFile must not be called in dry_run mode");
      },
    };
    const result = await prepareRepoEnv({
      target_domain: init.target_domain,
      runtime,
    });
    assert.equal(dockerInvoked, false, "docker must not be invoked in dry_run");
    assert.equal(result.dry_run, true);
    assert.equal(result.build_image, false);
    assert.equal(result.allow_network, false);
    assert.equal(result.language, "node");
    assert.equal(result.base_image, "node:20");
    assert.equal(result.image_tag, `bob-oss-${init.target_domain}:${init.repo_hash.slice(0, 16)}`);
    assert.match(result.repo_env_hash, /^[0-9a-f]{64}$/);

    const dockerfilePath = dockerfileBobPath(init.target_domain);
    assert.ok(fs.existsSync(dockerfilePath));
    const dockerfile = fs.readFileSync(dockerfilePath, "utf8");
    assert.match(dockerfile, /^ARG SESSION_ID=/m);
    assert.match(dockerfile, /^FROM node:20$/m);
    assert.match(dockerfile, /^USER 1000:1000$/m);

    const repoEnvPath = repoEnvJsonPath(init.target_domain);
    assert.ok(fs.existsSync(repoEnvPath));
    const repoEnv = JSON.parse(fs.readFileSync(repoEnvPath, "utf8"));
    assert.equal(repoEnv.version, 1);
    assert.equal(repoEnv.target_domain, init.target_domain);
    assert.equal(repoEnv.base_image, "node:20");
    assert.equal(repoEnv.dry_run, true);
    assert.equal(repoEnv.allow_network, false);
    assert.ok(Array.isArray(repoEnv.recommended_commands));
    const install = repoEnv.recommended_commands.find((c) => c.id === "install");
    assert.ok(install);
    assert.deepEqual(install.command, ["npm", "ci", "--ignore-scripts"]);
  });
});

test("prepareRepoEnv image_tag binds to the SessionNucleus-pinned repo_hash", async () => {
  await withTempHome(async () => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "Cargo.toml", "[package]\nname=\"x\"\n");
    const init = initRepoSession({ repo_path: repoRoot });
    const result = await prepareRepoEnv({ target_domain: init.target_domain });
    // The image tag MUST reuse the nucleus-pinned repo_hash so the same
    // session lifetime always lands on the same image identity.
    assert.ok(result.image_tag.startsWith(`bob-oss-${init.target_domain}:`));
    assert.ok(result.image_tag.endsWith(init.repo_hash.slice(0, 16)));
  });
});

test("prepareRepoEnv build_image=true with stubbed docker reaches docker exec with all flags", async () => {
  await withTempHome(async () => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "package.json", JSON.stringify({ name: "x" }));
    const init = initRepoSession({ repo_path: repoRoot });

    const calls = [];
    const runtime = {
      execFile: async (command, args) => {
        calls.push({ command, args });
        if (command === "docker" && args[0] === "--version") {
          return { stdout: "Docker version 25.0", stderr: "" };
        }
        if (command === "docker" && args[0] === "build") {
          // Successful build — return empty.
          return { stdout: "", stderr: "" };
        }
        throw new Error(`unexpected call: ${command} ${args.join(" ")}`);
      },
    };

    const result = await prepareRepoEnv({
      target_domain: init.target_domain,
      dry_run: false,
      build_image: true,
      allow_network: false,
      runtime,
    });
    assert.equal(result.build_image, true);
    assert.equal(result.dry_run, false);

    // Per-flag positive assertions on the docker build call.
    const buildCall = calls.find((c) => c.command === "docker" && c.args[0] === "build");
    assert.ok(buildCall, "expected a docker build invocation");
    const args = buildCall.args;
    const netIndex = args.indexOf("--network");
    assert.ok(netIndex >= 0, "--network flag missing");
    assert.equal(args[netIndex + 1], "none");
    const tagIndex = args.indexOf("--tag");
    assert.ok(tagIndex >= 0, "--tag flag missing");
    assert.equal(args[tagIndex + 1], result.image_tag);
    const fileIndex = args.indexOf("--file");
    assert.ok(fileIndex >= 0, "--file flag missing");
    assert.equal(args[fileIndex + 1], dockerfileBobPath(init.target_domain));
    const sessionArgs = args
      .map((value, index) => ({ value, index }))
      .filter((entry) => entry.value === "--build-arg");
    assert.ok(
      sessionArgs.some((entry) => args[entry.index + 1] === `SESSION_ID=${init.target_domain}`),
      "SESSION_ID build-arg missing",
    );
  });
});

test("prepareRepoEnv build_image=true returns docker_unavailable when docker is missing", async () => {
  await withTempHome(async () => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "package.json", JSON.stringify({ name: "x" }));
    const init = initRepoSession({ repo_path: repoRoot });

    const runtime = {
      execFile: async (command) => {
        if (command === "docker") {
          const err = new Error("ENOENT");
          err.code = "ENOENT";
          throw err;
        }
        throw new Error(`unexpected command: ${command}`);
      },
    };

    let caught;
    try {
      await prepareRepoEnv({
        target_domain: init.target_domain,
        dry_run: false,
        build_image: true,
        runtime,
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "expected docker_unavailable error");
    assert.equal(caught.details && caught.details.repo_error_code, "docker_unavailable");

    // Even though build_image failed, dry_run-shaped artefacts should still
    // have been written so the operator can fall back to dry-run inspection.
    assert.ok(fs.existsSync(dockerfileBobPath(init.target_domain)));
    assert.ok(fs.existsSync(repoEnvJsonPath(init.target_domain)));
  });
});

test("prepareRepoEnv reads nfs_xdr_shape from repo-inventory.json when present", async () => {
  await withTempHome(async () => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "CMakeLists.txt", "find_package(libtirpc)\n");
    write(repoRoot, "src/main.c", "#include <rpc/xdr.h>\nint main(){return 0;}\n");
    const init = initRepoSession({ repo_path: repoRoot });
    // Run inventory first so prepare_env can read its NFS detection flag.
    buildRepoInventory({ target_domain: init.target_domain });

    const result = await prepareRepoEnv({ target_domain: init.target_domain });
    assert.equal(result.language, "c");
    assert.equal(result.nfs_xdr_shape, true);

    const repoEnv = JSON.parse(fs.readFileSync(repoEnvJsonPath(init.target_domain), "utf8"));
    assert.equal(repoEnv.detection.nfs_xdr_shape, true);
    // The C compose recipe surfaces the NFS note in its description.
    assert.match(repoEnv.recommended_commands[0].description, /NFS\/XDR/);
  });
});

test("prepareRepoEnv reads native_fuzz_shape from repo-inventory.json and emits real fuzz command", async () => {
  await withTempHome(async () => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(fuzz CXX)\n");
    write(repoRoot, "fuzzing/native_fuzzer.cc", "extern \"C\" int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size){return size > 0 && data[0] == 0xff;}\n");
    write(repoRoot, "fuzz/corpus/minimal.bin", "AAAA");
    const init = initRepoSession({ repo_path: repoRoot });
    buildRepoInventory({ target_domain: init.target_domain });

    assert.equal(loadNativeFuzzShape(init.target_domain), true);
    const result = await prepareRepoEnv({ target_domain: init.target_domain });
    assert.equal(result.language, "c");
    assert.equal(result.native_fuzz_shape, true);

    const repoEnv = JSON.parse(fs.readFileSync(repoEnvJsonPath(init.target_domain), "utf8"));
    assert.equal(repoEnv.detection.native_fuzz_shape, true);
    const fuzzCommands = repoEnv.recommended_commands.filter((command) => command.role === "fuzz");
    assert.equal(fuzzCommands.length, 1);
    assert.equal(fuzzCommands[0].id, "fuzz_asan_ubsan");
    assert.match(fuzzCommands[0].command[2], /-fsanitize=address,undefined,fuzzer/);
  });
});

test("prepareRepoEnv promotes polyglot native fuzz repos to the C fuzz profile", async () => {
  await withTempHome(async () => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "package.json", "{\"scripts\":{\"test\":\"node --test\"}}\n");
    write(repoRoot, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(polyglot_fuzz CXX)\n");
    write(repoRoot, "fuzzing/native_fuzzer.cc", "extern \"C\" int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size){return size > 0 && data[0] == 0xff;}\n");
    const init = initRepoSession({ repo_path: repoRoot });
    buildRepoInventory({ target_domain: init.target_domain });

    assert.equal(detectLanguageProfile(repoRoot).language, "node");
    assert.equal(loadNativeFuzzShape(init.target_domain), true);
    const result = await prepareRepoEnv({ target_domain: init.target_domain });
    assert.equal(result.language, "c");
    assert.equal(result.base_image, "ubuntu:24.04");
    assert.equal(result.native_fuzz_shape, true);

    const repoEnv = JSON.parse(fs.readFileSync(repoEnvJsonPath(init.target_domain), "utf8"));
    assert.equal(repoEnv.detection.language, "c");
    assert.equal(repoEnv.detection.marker, "native_fuzz_shape");
    assert.ok(repoEnv.recommended_commands.some((command) => command.id === "fuzz_asan_ubsan"));
    assert.equal(repoEnv.recommended_commands.some((command) => command.id === "build_and_test"), false);
    const dockerfile = fs.readFileSync(dockerfileBobPath(init.target_domain), "utf8");
    assert.match(dockerfile, /\blibclang-rt-18-dev\b/);
  });
});

test("prepareRepoEnv threads seed_corpus from repo-inventory into C/C++ fuzz command", async () => {
  await withTempHome(async () => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(seed C)\n");
    write(repoRoot, "src/main.c", "int main(){return 0;}\n");
    write(repoRoot, "fuzz/corpus/minimal.bin", "AAAA");
    const init = initRepoSession({ repo_path: repoRoot });
    buildRepoInventory({ target_domain: init.target_domain });

    const result = await prepareRepoEnv({ target_domain: init.target_domain });
    assert.equal(result.language, "c");
    assert.equal(result.seed_corpus.length, 1);
    assert.ok(result.recommended_commands.some((command) => command.role === "fuzz"));

    const repoEnv = JSON.parse(fs.readFileSync(repoEnvJsonPath(init.target_domain), "utf8"));
    assert.equal(repoEnv.detection.seed_corpus_count, 1);
    assert.equal(repoEnv.seed_corpus[0].rel_path, "fuzz/corpus");
    assert.ok(repoEnv.recommended_commands.some((command) => command.id === "fuzz_seed_probe"));
  });
});

test("prepareRepoEnv uses inventory counts for capped seed corpus summaries", async () => {
  await withTempHome(async () => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(seed_count C)\n");
    write(repoRoot, "src/main.c", "int main(){return 0;}\n");
    const corpusCount = SEED_CORPUS_SUMMARY_LIMIT + 2;
    for (let index = 0; index < corpusCount; index += 1) {
      write(repoRoot, `sample_${String(index).padStart(2, "0")}_seed_corpus/input.bin`, `seed-${index}`);
    }
    const init = initRepoSession({ repo_path: repoRoot });
    buildRepoInventory({ target_domain: init.target_domain });

    const result = await prepareRepoEnv({ target_domain: init.target_domain });
    assert.equal(result.seed_corpus.length, SEED_CORPUS_SUMMARY_LIMIT);
    assert.equal(result.seed_corpus_count, corpusCount);

    const repoEnv = JSON.parse(fs.readFileSync(repoEnvJsonPath(init.target_domain), "utf8"));
    assert.equal(repoEnv.seed_corpus.length, SEED_CORPUS_SUMMARY_LIMIT);
    assert.equal(repoEnv.detection.seed_corpus_count, corpusCount);
  });
});

test("prepareRepoEnv refuses dry_run + build_image together", async () => {
  await withTempHome(async () => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "package.json", JSON.stringify({ name: "x" }));
    const init = initRepoSession({ repo_path: repoRoot });
    let caught;
    try {
      await prepareRepoEnv({
        target_domain: init.target_domain,
        dry_run: true,
        build_image: true,
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "expected mutually-exclusive error");
    assert.match(caught.message, /mutually exclusive/);
  });
});

test("prepareRepoEnv allow_network=true injects egress proxy via --build-arg (not ENV)", async () => {
  // We monkey-patch the egress profile to expose a synthetic proxy_url so we
  // can assert the proxy flows through --build-arg and never lands in the
  // resulting Dockerfile.
  await withTempHome(async () => {
    const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-repo-env-project-"));
    const previousProjectDir = process.env.BOB_PROJECT_DIR;
    process.env.BOB_PROJECT_DIR = projectRoot;

    const repoRoot = makeTempRepoDir();
    write(repoRoot, "package.json", JSON.stringify({ name: "x" }));

    const calls = [];
    const runtime = {
      execFile: async (command, args) => {
        calls.push({ command, args });
        if (command === "docker" && args[0] === "--version") {
          return { stdout: "Docker version 25.0", stderr: "" };
        }
        if (command === "docker" && args[0] === "build") {
          return { stdout: "", stderr: "" };
        }
        throw new Error(`unexpected: ${command} ${args.join(" ")}`);
      },
    };

    // Inject a synthetic proxy via the egress profile by writing the
    // proxy URL into the resolved egress profile through the env var hook.
    // Use an isolated BOB_PROJECT_DIR so this test never mutates the shared
    // repo-root egress-profiles.json consumed by the full MCP test manifest.
    const egressPath = path.join(projectRoot, ".claude", "bob", "egress-profiles.json");
    fs.mkdirSync(path.dirname(egressPath), { recursive: true });
    fs.writeFileSync(
      egressPath,
      JSON.stringify(
        {
          version: 1,
          profiles: [
            {
              name: "default",
              region: null,
              description: null,
              proxy_url: null,
              enabled: true,
            },
            {
              name: "synthetic_proxy",
              region: "test",
              description: null,
              proxy_url: "${BOB_TEST_PROXY_URL}",
              enabled: true,
            },
          ],
        },
        null,
        2,
      ),
    );
    const originalProxyEnv = process.env.BOB_TEST_PROXY_URL;
    process.env.BOB_TEST_PROXY_URL = "http://proxy.invalid:3128/";
    try {
      const init = initRepoSession({ repo_path: repoRoot });
      await prepareRepoEnv({
        target_domain: init.target_domain,
        dry_run: false,
        build_image: true,
        allow_network: true,
        egress_profile: "synthetic_proxy",
        runtime,
      });
      const buildCall = calls.find((c) => c.command === "docker" && c.args[0] === "build");
      assert.ok(buildCall, "expected docker build call");
      // Proxy MUST appear as a --build-arg.
      const args = buildCall.args;
      const buildArgs = args
        .map((value, index) => ({ value, index }))
        .filter((entry) => entry.value === "--build-arg")
        .map((entry) => args[entry.index + 1]);
      assert.ok(
        buildArgs.some((p) => p === "HTTP_PROXY=http://proxy.invalid:3128/"),
        `expected HTTP_PROXY build-arg, got ${buildArgs.join(", ")}`,
      );
      assert.ok(
        buildArgs.some((p) => p === "HTTPS_PROXY=http://proxy.invalid:3128/"),
        `expected HTTPS_PROXY build-arg, got ${buildArgs.join(", ")}`,
      );
      // And the generated Dockerfile must NOT contain ENV HTTP_PROXY.
      const dockerfile = fs.readFileSync(dockerfileBobPath(init.target_domain), "utf8");
      assert.equal(
        ENV_SECRET_LEAK_RE.test(dockerfile),
        false,
        "Dockerfile must not bake ENV HTTP_PROXY",
      );
    } finally {
      if (originalProxyEnv === undefined) delete process.env.BOB_TEST_PROXY_URL;
      else process.env.BOB_TEST_PROXY_URL = originalProxyEnv;
      if (previousProjectDir === undefined) delete process.env.BOB_PROJECT_DIR;
      else process.env.BOB_PROJECT_DIR = previousProjectDir;
      fs.rmSync(projectRoot, { recursive: true, force: true });
    }
  });
});

test("prepareRepoEnv throws when target_domain is not a repo session", async () => {
  await withTempHome(async () => {
    let caught;
    try {
      await prepareRepoEnv({ target_domain: "repo-not-real-12345678" });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "expected error for non-repo session");
    assert.match(caught.message, /is not a repo session|Missing session state/);
  });
});

// ---------- Persistence guarantees (O-P7 regression) ----------

test("prepareRepoEnv routes repo-env.json through validateNoSensitiveMaterial", async () => {
  await withTempHome(async () => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "go.mod", "module x\n");
    const init = initRepoSession({ repo_path: repoRoot });
    await prepareRepoEnv({ target_domain: init.target_domain });
    const repoEnv = JSON.parse(fs.readFileSync(repoEnvJsonPath(init.target_domain), "utf8"));
    // The persisted document must re-validate without raising — if a future
    // producer regression sneaks a secret-shaped field in, this fires.
    validateNoSensitiveMaterial(repoEnv, "repo_env");
  });
});

// ---------- Tool wrapper contract ----------

test("bob_repo_prepare_env tool handler returns a JSON envelope", async () => {
  await withTempHome(async () => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "package.json", JSON.stringify({ name: "x" }));
    const init = initRepoSession({ repo_path: repoRoot });
    const payload = JSON.parse(await repoPrepareEnvTool.handler({ target_domain: init.target_domain }));
    assert.equal(payload.version, 1);
    assert.equal(payload.created, true);
    assert.equal(payload.target_domain, init.target_domain);
    assert.equal(payload.dry_run, true);
    assert.ok(payload.image_tag.startsWith("bob-oss-"));
    assert.match(payload.repo_env_hash, /^[0-9a-f]{64}$/);
  });
});

test("bob_repo_prepare_env is orchestrator-only and declares the right artefacts", () => {
  assert.deepEqual(repoPrepareEnvTool.role_bundles, ["orchestrator"]);
  assert.equal(repoPrepareEnvTool.network_access, false);
  assert.equal(repoPrepareEnvTool.browser_access, false);
  assert.equal(repoPrepareEnvTool.mutating, true);
  assert.ok(
    repoPrepareEnvTool.session_artifacts_written.includes("Dockerfile.bob"),
    "session_artifacts_written must declare Dockerfile.bob",
  );
  assert.ok(
    repoPrepareEnvTool.session_artifacts_written.includes("repo-env.json"),
    "session_artifacts_written must declare repo-env.json",
  );
});

test("bob_repo_prepare_env authority class is registered as initialized_session_mutation", () => {
  assert.equal(EXPLICIT_AUTHORITY_CLASS_BY_TOOL.bob_repo_prepare_env, "initialized_session_mutation");
});
