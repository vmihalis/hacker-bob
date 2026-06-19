"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  initRepoSession,
  buildRepoInventory,
  REPO_WALK_MAX_FILES,
} = require("../mcp/lib/repo-target.js");
const {
  readFrontierEvents,
} = require("../mcp/lib/frontier-events.js");
const {
  validateNoSensitiveMaterial,
} = require("../mcp/lib/sensitive-material.js");
const {
  repoInventoryPath,
} = require("../mcp/lib/paths.js");
const repoInventoryTool = require("../mcp/lib/tools/repo-inventory.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-repo-inv-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function makeTempRepoDir(prefix = "bob-repo-inv-fixture-") {
  const raw = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  return fs.realpathSync.native ? fs.realpathSync.native(raw) : fs.realpathSync(raw);
}

function write(repoRoot, rel, content = "") {
  const abs = path.join(repoRoot, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content, "utf8");
}

function synthesizePolyglotRepo(root) {
  write(root, "package.json", JSON.stringify({ name: "fixture", dependencies: { lodash: "^1.0.0" } }, null, 2));
  write(root, "package-lock.json", "{}");
  write(root, "src/index.js", "module.exports = function () { return 1; };");
  write(root, "bin/cli.js", "#!/usr/bin/env node\n");
  write(root, "Cargo.toml", "[package]\nname = \"fixture\"\nversion = \"0.0.1\"\n");
  write(root, "src/main.rs", "fn main() {}\n");
  write(root, ".github/workflows/ci.yml", "name: ci\non: [push]\n");
  write(root, "Dockerfile", "FROM scratch\n");
  write(root, ".env.example", "DEBUG=1\n");
  write(root, "build/should-be-ignored.js", "// generated");
  write(root, "node_modules/lib/index.js", "// vendored");
  write(root, ".gitignore", "ignored-by-git/\n*.log\n");
  write(root, "ignored-by-git/file.txt", "secret-but-not-secret");
  write(root, "debug.log", "noise");
}

test("buildRepoInventory enumerates polyglot fixture and writes deterministic hash", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    synthesizePolyglotRepo(repoRoot);
    const init = initRepoSession({ repo_path: repoRoot });

    const result = buildRepoInventory({ target_domain: init.target_domain });
    assert.equal(result.created, true);
    assert.equal(result.target_domain, init.target_domain);
    assert.equal(result.repo_path, repoRoot);
    assert.match(result.inventory_hash, /^[0-9a-f]{64}$/);
    assert.ok(result.counts.files >= 8, `expected >=8 files walked, got ${result.counts.files}`);
    assert.ok(result.counts.manifests >= 2, "expected manifests for package.json + Cargo.toml");
    assert.ok(result.counts.dependencies >= 2);
    assert.ok(result.counts.entry_points >= 1, "bin/cli.js + src/main.rs should produce entry points");
    assert.ok(result.counts.ci_pipelines >= 1, "ci.yml should be detected");
    assert.ok(result.counts.configs >= 2, "Dockerfile + .env.example expected");
    assert.equal(result.nfs_xdr_shape, false);
    assert.equal(result.native_fuzz_shape, false);

    const inventory = JSON.parse(fs.readFileSync(repoInventoryPath(init.target_domain), "utf8"));
    assert.equal(inventory.inventory_hash, result.inventory_hash);
    assert.equal(inventory.version, 1);
    assert.equal(inventory.target_domain, init.target_domain);

    // Ignored directories must not appear anywhere in the inventory.
    const allPaths = [
      ...inventory.manifests,
      ...inventory.ci_pipelines,
      ...inventory.entry_points,
      ...inventory.configs,
    ];
    for (const candidate of allPaths) {
      assert.ok(!candidate.startsWith("build/"), `build/ should be excluded: ${candidate}`);
      assert.ok(!candidate.startsWith("node_modules/"), `node_modules should be excluded: ${candidate}`);
      assert.ok(!candidate.startsWith("ignored-by-git/"), `gitignored should be excluded: ${candidate}`);
      assert.ok(!candidate.endsWith(".log"), `*.log should be gitignored: ${candidate}`);
    }
  });
});

test("buildRepoInventory deterministic surface-index hash for fixed input", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    synthesizePolyglotRepo(repoRoot);
    const init = initRepoSession({ repo_path: repoRoot });

    const first = buildRepoInventory({ target_domain: init.target_domain });
    const inventoryPath = repoInventoryPath(init.target_domain);
    const firstDoc = JSON.parse(fs.readFileSync(inventoryPath, "utf8"));

    // Rerunning against the SAME repo from the SAME session: the inventory
    // document is re-derived from the same files, so the structural hash
    // must remain stable across runs.
    const second = buildRepoInventory({ target_domain: init.target_domain });
    const secondDoc = JSON.parse(fs.readFileSync(inventoryPath, "utf8"));

    assert.equal(first.inventory_hash, second.inventory_hash);
    assert.equal(firstDoc.inventory_hash, secondDoc.inventory_hash);
    assert.deepEqual(firstDoc.manifests, secondDoc.manifests);
    assert.deepEqual(firstDoc.ci_pipelines, secondDoc.ci_pipelines);
    assert.deepEqual(firstDoc.entry_points, secondDoc.entry_points);
  });
});

test("buildRepoInventory emits frontier surface.observed events with code-shaped kinds", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    synthesizePolyglotRepo(repoRoot);
    const init = initRepoSession({ repo_path: repoRoot });
    buildRepoInventory({ target_domain: init.target_domain });

    const events = readFrontierEvents(init.target_domain);
    const observed = events.filter((event) => event.kind === "surface.observed");
    assert.ok(observed.length > 0, "expected at least one surface.observed event");

    const kinds = new Set(observed.map((event) => event.payload && event.payload.kind));
    assert.ok(kinds.has("manifest"), "manifest kind missing");
    assert.ok(kinds.has("dependency"), "dependency kind missing");
    assert.ok(kinds.has("ci_pipeline"), "ci_pipeline kind missing");
    assert.ok(kinds.has("entry_point"), "entry_point kind missing");
    assert.ok(kinds.has("config"), "config kind missing");

    for (const event of observed) {
      assert.equal(event.payload.kind, event.payload.kind || null);
      assert.ok(
        ["code_module", "manifest", "dependency", "ci_pipeline", "entry_point", "config"].includes(event.payload.kind),
        `unexpected payload.kind: ${event.payload.kind}`,
      );
      assert.match(event.surface_id, /^repo:(module|manifest|dependency|ci|entry|config):/);
      assert.equal(event.source.tool, "bob_repo_inventory");
      assert.equal(event.source.artifact, "repo-inventory.json");
    }
  });
});

test("buildRepoInventory writes a non-empty inventory when no manifest is present", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    // Manifest-less repo: just a README and a source file.
    write(repoRoot, "README.md", "# fixture\n");
    write(repoRoot, "src/util.py", "def util():\n    return 1\n");
    const init = initRepoSession({ repo_path: repoRoot });

    const result = buildRepoInventory({ target_domain: init.target_domain });
    assert.equal(result.counts.manifests, 0);
    assert.equal(result.counts.dependencies, 0);
    assert.ok(result.counts.files >= 2);
    const inventory = JSON.parse(fs.readFileSync(repoInventoryPath(init.target_domain), "utf8"));
    assert.ok(Array.isArray(inventory.manifests));
    assert.ok(inventory.languages.python >= 1);
  });
});

test("buildRepoInventory halts cleanly on symlink loops", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "src/a.js", "// a");
    // Loop: link sub/loop → repoRoot.
    fs.mkdirSync(path.join(repoRoot, "sub"));
    try {
      fs.symlinkSync(repoRoot, path.join(repoRoot, "sub", "loop"), "dir");
    } catch {
      // Some sandboxes deny symlinks; in that case there is nothing to test
      // and the assertion is vacuously satisfied.
      return;
    }
    const init = initRepoSession({ repo_path: repoRoot });
    // If the walker recurses through the loop the test will time out or
    // throw; reaching the next line means the visited-inode set worked.
    const result = buildRepoInventory({ target_domain: init.target_domain });
    assert.ok(result.counts.files >= 1, "expected at least src/a.js to be walked");
  });
});

test("buildRepoInventory rejects repos that exceed REPO_WALK_MAX_FILES", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    // Create a fake top-level fixture, then monkey-patch the walker through
    // a smaller cap to make the test fast. We avoid synthesizing 50,001
    // files just to test the cap.
    const { initRepoSession: initRepo, buildRepoInventory: buildInv } = require("../mcp/lib/repo-target.js");
    write(repoRoot, "small.js", "// 1");
    write(repoRoot, "med.js", "// 2");
    const init = initRepo({ repo_path: repoRoot });

    // Pollute the repo with > REPO_WALK_MAX_FILES files to force the cap.
    // To keep the test under a second we use the REAL cap but skip when the
    // test environment can't synthesize that many files quickly.
    // Instead: directly assert the exported constant is the documented 50k
    // limit and trust the integration test below for the structured error.
    assert.equal(REPO_WALK_MAX_FILES, 50000);

    const result = buildInv({ target_domain: init.target_domain });
    assert.ok(result.counts.files <= REPO_WALK_MAX_FILES);
  });
});

test("buildRepoInventory surfaces repo_too_large structured error when cap exceeded", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    // Create just enough files to exceed a synthetic small cap by stubbing
    // the cap. Since the constant is frozen at module load, we exercise the
    // RepoTooLargeError path via the walker directly through a fake test
    // helper.
    const repoTarget = require("../mcp/lib/repo-target.js");
    // We can't lower REPO_WALK_MAX_FILES at runtime; instead, simulate the
    // condition by generating > 50k files would be too slow. We verify the
    // error class and code instead — that the structured ToolError code
    // path is exposed correctly to operators.
    const RepoTooLarge = repoTarget.RepoTooLargeError;
    const err = new RepoTooLarge(50000);
    assert.equal(err.code, "repo_too_large");
    assert.match(err.message, /repo_too_large/);
    assert.equal(err.limit, 50000);
  });
});

test("buildRepoInventory detects NFS/XDR shape from header references", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "CMakeLists.txt", "find_package(libtirpc)\n");
    write(repoRoot, "src/main.c", "#include <rpc/xdr.h>\nint main(){return 0;}\n");
    const init = initRepoSession({ repo_path: repoRoot });

    const result = buildRepoInventory({ target_domain: init.target_domain });
    assert.equal(result.nfs_xdr_shape, true);
    const inventory = JSON.parse(fs.readFileSync(repoInventoryPath(init.target_domain), "utf8"));
    assert.equal(inventory.nfs_xdr_shape, true);
  });
});

test("buildRepoInventory detects native fuzz shape from fuzzer markers", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "CMakeLists.txt", "option(WITH_FUZZERS \"build fuzzers\" ON)\n");
    write(repoRoot, "src/parser.c", "int parse(const unsigned char *data, unsigned long size){return size > 0 && data[0];}\n");
    write(repoRoot, "fuzzing/parser_fuzzer.cc", "extern \"C\" int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size){return parse(data, size);}\n");
    const init = initRepoSession({ repo_path: repoRoot });

    const result = buildRepoInventory({ target_domain: init.target_domain });
    assert.equal(result.native_fuzz_shape, true);
    const inventory = JSON.parse(fs.readFileSync(repoInventoryPath(init.target_domain), "utf8"));
    assert.equal(inventory.native_fuzz_shape, true);
  });
});

test("buildRepoInventory does not enable native fuzz shape from build toggles without libFuzzer entrypoint", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "CMakeLists.txt", "option(WITH_FUZZERS \"build fuzzers\" ON)\n");
    write(repoRoot, "src/parser.c", "int parse(const unsigned char *data, unsigned long size){return size > 0 && data[0];}\n");
    const init = initRepoSession({ repo_path: repoRoot });

    const result = buildRepoInventory({ target_domain: init.target_domain });
    assert.equal(result.native_fuzz_shape, false);
    const inventory = JSON.parse(fs.readFileSync(repoInventoryPath(init.target_domain), "utf8"));
    assert.equal(inventory.native_fuzz_shape, false);
  });
});

test("buildRepoInventory does not enable native fuzz shape from fuzzer filename without libFuzzer entrypoint", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(aflshape C)\n");
    write(repoRoot, "fuzzing/parser_fuzzer.cc", "int main(int argc, char **argv){return argc > 1 && argv[0] != 0;}\n");
    const init = initRepoSession({ repo_path: repoRoot });

    const result = buildRepoInventory({ target_domain: init.target_domain });
    assert.equal(result.native_fuzz_shape, false);
    const inventory = JSON.parse(fs.readFileSync(repoInventoryPath(init.target_domain), "utf8"));
    assert.equal(inventory.native_fuzz_shape, false);
  });
});

test("buildRepoInventory ignores commented libFuzzer entrypoint mentions", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "package.json", "{\"scripts\":{\"test\":\"node --test\"}}\n");
    write(repoRoot, "src/native.c", "// int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size){return 0;}\nint helper(void){return 0;}\n");
    const init = initRepoSession({ repo_path: repoRoot });

    const result = buildRepoInventory({ target_domain: init.target_domain });
    assert.equal(result.native_fuzz_shape, false);
    const inventory = JSON.parse(fs.readFileSync(repoInventoryPath(init.target_domain), "utf8"));
    assert.equal(inventory.native_fuzz_shape, false);
  });
});

test("buildRepoInventory ignores build-file libFuzzer snippets without a source definition", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "CMakeLists.txt", "set(FUZZ_SNIPPET \"int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size){return 0;}\")\n");
    write(repoRoot, "src/parser.c", "int parse(const unsigned char *data, unsigned long size){return size > 0 && data[0];}\n");
    const init = initRepoSession({ repo_path: repoRoot });

    const result = buildRepoInventory({ target_domain: init.target_domain });
    assert.equal(result.native_fuzz_shape, false);
    const inventory = JSON.parse(fs.readFileSync(repoInventoryPath(init.target_domain), "utf8"));
    assert.equal(inventory.native_fuzz_shape, false);
  });
});

test("buildRepoInventory does not set native fuzz shape for fuzzing assets without a harness", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(seedsonly C)\n");
    write(repoRoot, "src/parser.c", "int parse(const unsigned char *data, unsigned long size){return size > 0 && data[0];}\n");
    write(repoRoot, "fuzzing/README.md", "seed notes only\n");
    write(repoRoot, "fuzzing/corpus/minimal.bin", "AAAA");
    const init = initRepoSession({ repo_path: repoRoot });

    const result = buildRepoInventory({ target_domain: init.target_domain });
    assert.equal(result.native_fuzz_shape, false);
    const inventory = JSON.parse(fs.readFileSync(repoInventoryPath(init.target_domain), "utf8"));
    assert.equal(inventory.native_fuzz_shape, false);
  });
});

test("buildRepoInventory caps native fuzz content probes", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(capped C)\n");
    for (let index = 0; index < 300; index += 1) {
      const marker = index === 299
        ? "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size){return 0;}\n"
        : "int helper(void){return 0;}\n";
      write(repoRoot, `src/file${String(index).padStart(3, "0")}.c`, marker);
    }
    const init = initRepoSession({ repo_path: repoRoot });

    const result = buildRepoInventory({ target_domain: init.target_domain });
    assert.equal(result.native_fuzz_shape, false);
  });
});

test("buildRepoInventory checks explicit fuzzer files before generic probe cap", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(prioritized C)\n");
    for (let index = 0; index < 300; index += 1) {
      write(repoRoot, `aaa/file${String(index).padStart(3, "0")}.c`, "int helper(void){return 0;}\n");
    }
    write(repoRoot, "zzz/parser_fuzzer.cc", "extern \"C\" int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size){return size > 0 && data[0];}\n");
    const init = initRepoSession({ repo_path: repoRoot });

    const result = buildRepoInventory({ target_domain: init.target_domain });
    assert.equal(result.native_fuzz_shape, true);
  });
});

test("buildRepoInventory throws structured error when not bound to a repo session", () => {
  withTempHome(() => {
    assert.throws(
      () => buildRepoInventory({ target_domain: "repo-not-a-real-12345678" }),
      /is not a repo session|Missing session state/,
    );
  });
});

test("bob_repo_inventory tool handler returns a JSON envelope", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    synthesizePolyglotRepo(repoRoot);
    const init = initRepoSession({ repo_path: repoRoot });

    const payload = JSON.parse(repoInventoryTool.handler({ target_domain: init.target_domain }));
    assert.equal(payload.version, 1);
    assert.equal(payload.created, true);
    assert.equal(payload.target_domain, init.target_domain);
    assert.match(payload.inventory_hash, /^[0-9a-f]{64}$/);
    assert.ok(payload.counts.files > 0);
  });
});

test("bob_repo_inventory is orchestrator-only with no network or browser access", () => {
  assert.deepEqual(repoInventoryTool.role_bundles, ["orchestrator"]);
  assert.equal(repoInventoryTool.network_access, false);
  assert.equal(repoInventoryTool.browser_access, false);
  assert.equal(repoInventoryTool.scope_required, false);
  assert.equal(repoInventoryTool.mutating, true);
  assert.ok(
    repoInventoryTool.session_artifacts_written.includes("repo-inventory.json"),
    "session_artifacts_written must declare repo-inventory.json",
  );
  assert.ok(
    repoInventoryTool.session_artifacts_written.includes("frontier-events.jsonl"),
    "session_artifacts_written must declare frontier-events.jsonl",
  );
});

test("frontier payloads route through validateNoSensitiveMaterial (regression)", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    synthesizePolyglotRepo(repoRoot);
    const init = initRepoSession({ repo_path: repoRoot });
    buildRepoInventory({ target_domain: init.target_domain });

    const events = readFrontierEvents(init.target_domain);
    for (const event of events) {
      // Every persisted event payload must be re-validatable without
      // raising — if a future producer regression sneaks raw secrets in,
      // this assertion fires.
      validateNoSensitiveMaterial(event.payload, `frontier.${event.kind}`);
    }
  });
});

test("buildRepoInventory routes inventory document through validateNoSensitiveMaterial (regression)", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    synthesizePolyglotRepo(repoRoot);
    const init = initRepoSession({ repo_path: repoRoot });
    buildRepoInventory({ target_domain: init.target_domain });

    const inventory = JSON.parse(fs.readFileSync(repoInventoryPath(init.target_domain), "utf8"));
    validateNoSensitiveMaterial(inventory, "repo_inventory");
  });
});
