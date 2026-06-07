const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  attackSurfacePath,
  repoCommandRunsJsonlPath,
  repoDockerfilePath,
  repoEnvPath,
  repoInventoryPath,
  surfaceRoutesPath,
} = require("../mcp/lib/paths.js");
const {
  buildRepoInventory,
  initRepoSession,
  repoCheck,
  SEED_CORPUS_SUMMARY_LIMIT,
} = require("../mcp/lib/repo-target.js");
const {
  prepareRepoEnv,
  repoDockerRun,
} = require("../mcp/lib/repo-env.js");
const {
  finalizeAgentRun,
} = require("../mcp/lib/agent-run-completion.js");
const {
  appendCandidateClaim,
} = require("../mcp/lib/claims.js");
const {
  logCoverage,
} = require("../mcp/lib/coverage.js");
const {
  logTechniqueAttempt,
} = require("../mcp/lib/technique-packs.js");
const recordFinding = require("../mcp/lib/tools/record-candidate-claim.js").handler;
const {
  routeSurfaces,
} = require("../mcp/lib/surface-router.js");
const {
  advanceSession,
  readSessionState,
} = require("../mcp/lib/session-state.js");
const {
  startWave,
  writeWaveHandoff,
} = require("../mcp/lib/waves.js");
const {
  materializeFrontier,
} = require("../mcp/lib/frontier-materializer.js");
const {
  currentSurfaces,
} = require("../mcp/lib/frontier-projections.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-oss-test-"));
  process.env.HOME = tempHome;
  const cleanup = () => {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(tempHome, { recursive: true, force: true });
  };
  try {
    const result = fn(tempHome);
    if (result && typeof result.then === "function") {
      return result.finally(cleanup);
    }
    cleanup();
    return result;
  } catch (error) {
    cleanup();
    throw error;
  }
}

function writeFile(root, relativePath, content) {
  const filePath = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content, "utf8");
}

function parseResult(value) {
  return typeof value === "string" ? JSON.parse(value) : value;
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function repoSurfaces(domain) {
  materializeFrontier(domain, { write: true });
  return currentSurfaces(domain).surfaces;
}

function surfaceByTitle(domain, title) {
  return repoSurfaces(domain).find((surface) => surface.title === title);
}

function createNativeRepoSession(home, targetDomain = "repo-native-proof-test") {
  const repo = path.join(home, targetDomain);
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(native_proof C)\n");
  writeFile(repo, "src/parser.c", "int parse_packet(const char *buf, int len) { return len > 0 ? buf[0] : 0; }\n");

  const init = parseResult(initRepoSession({ repo_path: repo, target_domain: targetDomain }));
  parseResult(buildRepoInventory({ target_domain: init.target_domain }));
  parseResult(routeSurfaces({ target_domain: init.target_domain }));
  const nativeSurface = surfaceByTitle(init.target_domain, "src/parser.c");
  assert.ok(nativeSurface, "expected src/parser.c surface");
  parseResult(advanceSession({ target_domain: init.target_domain, to_state: "OPEN_FRONTIER" }));

  const wave = parseResult(startWave({
    target_domain: init.target_domain,
    wave_number: 1,
    assignments: [{
      agent: "a1",
      surface_id: nativeSurface.id,
      task_lens: "code_surface_scout",
    }],
  }));
  const assignment = wave.assignments.find((item) => item.surface_id === nativeSurface.id);
  assert.ok(assignment, `expected ${nativeSurface.id} assignment`);
  assert.equal(assignment.capability_pack, "oss_native_code");

  return {
    targetDomain: init.target_domain,
    repo,
    wave: `w${wave.wave_number}`,
    surface: nativeSurface,
    assignment,
  };
}

function appendRepoDockerRun(domain, command, overrides = {}) {
  const runId = overrides.run_id || `run-${sha256Hex(JSON.stringify(command)).slice(0, 12)}`;
  const commandHash = sha256Hex(JSON.stringify(command));
  fs.appendFileSync(repoCommandRunsJsonlPath(domain), `${JSON.stringify({
    version: 1,
    ts: new Date().toISOString(),
    target_domain: domain,
    runner: "docker",
    run_id: runId,
    dry_run: false,
    status: "ok",
    exit_code: 0,
    command_hash: commandHash,
    stdout_hash: "0".repeat(64),
    stderr_hash: "0".repeat(64),
    command,
    timed_out: false,
    ...overrides,
  })}\n`);
  return {
    run_id: runId,
    command_hash: commandHash,
    stdout_hash: "0".repeat(64),
    stderr_hash: "0".repeat(64),
    exit_code: overrides.exit_code == null ? 0 : overrides.exit_code,
    ...overrides,
  };
}

function nativeFindingInput(context, overrides = {}) {
  return {
    target_domain: context.targetDomain,
    wave: context.wave,
    agent: context.assignment.agent,
    surface_id: context.assignment.surface_id,
    title: "Out-of-bounds read in packet parser",
    severity: "high",
    cwe: "CWE-125",
    endpoint: "src/parser.c",
    file_path: "src/parser.c",
    symbol: "parse_packet",
    repro_command: "/work/repro.sh",
    description: "The packet parser reads attacker-controlled packet bytes past the available buffer.",
    proof_of_concept: "Compile the ASAN harness and run /work/repro.sh against the crafted packet.",
    response_evidence: "AddressSanitizer: heap-buffer-overflow in parse_packet",
    impact: "Remote input can crash the process and may disclose adjacent memory.",
    validated: true,
    ...overrides,
  };
}

function nativeRepoFileEvidence() {
  return {
    kind: "repo_file",
    file_path: "src/parser.c",
    content_hash: "a".repeat(64),
  };
}

function repoCommandRunEvidence(row) {
  return {
    kind: "repo_command_run",
    run_id: row.run_id,
    command_hash: row.command_hash,
    exit_code: row.exit_code,
    stdout_hash: row.stdout_hash || "0".repeat(64),
    stderr_hash: row.stderr_hash || "0".repeat(64),
  };
}

function nativeClaimInput(context, evidenceRefs, overrides = {}) {
  return {
    target_domain: context.targetDomain,
    title: "Out-of-bounds read in packet parser",
    summary: "The packet parser reads attacker-controlled packet bytes past the available buffer.",
    severity: "high",
    surface_ids: [context.assignment.surface_id],
    evidence_refs: evidenceRefs,
    impact: "Remote input can crash the process and may disclose adjacent memory.",
    ...overrides,
  };
}

test("repo session inventory emits OSS surfaces and routes to OSS packs", () => withTempHome((home) => {
  const repo = path.join(home, "sample-project");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "package.json", JSON.stringify({
    name: "sample-project",
    scripts: { test: "node --test", release: "npm publish" },
    dependencies: { express: "^4.18.0", jsonwebtoken: "^9.0.0" },
  }, null, 2));
  writeFile(repo, "package-lock.json", "{}\n");
  writeFile(repo, "src/routes/users.ts", "router.get('/api/users/:id', requireAuth, users.show)\n");
  writeFile(repo, "src/auth/middleware.ts", "export function requireAuth(req, res, next) { next() }\n");
  writeFile(repo, ".github/workflows/ci.yml", "on: [pull_request]\npermissions: write-all\n");
  writeFile(repo, ".env.example", "JWT_SECRET=\nDATABASE_URL=\n");
  writeFile(repo, "README.md", "# Sample\n\nSecurity notes.\n");

  const init = parseResult(initRepoSession({ repo_path: repo }));
  assert.match(init.target_domain, /^repo-sample-project-[a-f0-9]{8}$/);

  const state = parseResult(readSessionState({ target_domain: init.target_domain })).state;
  assert.equal(state.target_repo.root_path, fs.realpathSync(repo));

  const inventory = parseResult(buildRepoInventory({ target_domain: init.target_domain }));
  assert.equal(inventory.counts.files, 7);
  assert.equal(inventory.counts.manifests, 1);
  assert.equal(inventory.counts.dependencies, 1);
  assert.equal(inventory.counts.ci_pipelines, 1);
  assert.equal(inventory.counts.configs, 1);
  const surfaces = repoSurfaces(init.target_domain);
  assert.ok(surfaces.some((surface) => surface.surface_type === "oss_dependency"));
  assert.ok(surfaces.some((surface) => surface.surface_type === "oss_ci_cd"));
  assert.ok(surfaces.some((surface) => surface.surface_type === "oss_secrets_config"));

  const routed = parseResult(routeSurfaces({ target_domain: init.target_domain }));
  assert.equal(routed.counts.oss_dependency, 2);
  assert.equal(routed.counts.oss_ci_cd, 1);

  const routes = JSON.parse(fs.readFileSync(surfaceRoutesPath(init.target_domain), "utf8"));
  assert.ok(routes.routes.some((route) => route.capability_pack === "oss_secrets_config"));

  const check = parseResult(repoCheck({
    target_domain: init.target_domain,
    file_path: "package.json",
    check_type: "file_contains",
    pattern: "release",
  }));
  assert.equal(check.matched, true);
  assert.equal(check.check_type, "file_contains");
}));

test("repo inventory stays bound to the initialized repo root", () => withTempHome((home) => {
  const repo = path.join(home, "sample-project");
  const serviceRepo = path.join(repo, "packages", "service");
  const otherRepo = path.join(home, "other-project");
  fs.mkdirSync(repo, { recursive: true });
  fs.mkdirSync(serviceRepo, { recursive: true });
  fs.mkdirSync(otherRepo, { recursive: true });
  writeFile(repo, "package.json", JSON.stringify({ name: "sample-project" }, null, 2));
  writeFile(serviceRepo, "package.json", JSON.stringify({ name: "service" }, null, 2));
  writeFile(otherRepo, "package.json", JSON.stringify({ name: "other-project" }, null, 2));

  const init = parseResult(initRepoSession({ repo_path: repo, target_domain: "repo-sample-project" }));
  const inventory = parseResult(buildRepoInventory({ target_domain: init.target_domain, repo_path: repo }));
  assert.equal(inventory.target_domain, init.target_domain);
  const scopedInventory = parseResult(buildRepoInventory({ target_domain: init.target_domain, repo_path: serviceRepo }));
  assert.equal(scopedInventory.repo_path, fs.realpathSync(serviceRepo));
  assert.equal(scopedInventory.counts.files, 1);
  const scopedDocument = JSON.parse(fs.readFileSync(repoInventoryPath(init.target_domain), "utf8"));
  assert.deepEqual(scopedDocument.manifests, ["packages/service/package.json"]);
  assert.ok(
    repoSurfaces(init.target_domain).some((surface) => (
      surface.title === "packages/service/package.json"
      && surface.file_path === "packages/service/package.json"
    )),
    "scoped inventory must emit a session-root-relative manifest file_path",
  );

  assert.throws(
    () => buildRepoInventory({ target_domain: init.target_domain, repo_path: otherRepo }),
    /repo_path must stay within the initialized repo session root/,
  );
}));

test("repo check rejects invalid regex with a structured ToolError", () => withTempHome((home) => {
  const repo = path.join(home, "regex-project");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "package.json", JSON.stringify({ name: "regex-project" }, null, 2));

  const init = parseResult(initRepoSession({ repo_path: repo, target_domain: "repo-regex-project" }));
  assert.throws(
    () => repoCheck({
      target_domain: init.target_domain,
      file_path: "package.json",
      check_type: "regex_match",
      regex: "[",
    }),
    /regex pattern is invalid/,
  );
}));

test("reachability classifier stamps a MEDIUM ceiling and down-ranks a local-only native parser", () => withTempHome((home) => {
  const repo = path.join(home, "local-parser");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(local_parser C)\n");
  writeFile(repo, "src/decode.c", "int decode(const unsigned char *buf, int len){ return len > 0 ? buf[0] : 0; }\n");

  const init = parseResult(initRepoSession({ repo_path: repo, target_domain: "repo-local-parser" }));
  const inventory = parseResult(buildRepoInventory({ target_domain: init.target_domain }));
  assert.equal(inventory.reachability.network_reachable, false);
  assert.equal(inventory.reachability.max_credible_severity_ceiling, "medium");

  const native = surfaceByTitle(init.target_domain, "src/decode.c");
  assert.ok(native, "expected native source surface");
  assert.equal(native.network_reachable, false);
  assert.equal(native.attack_vector, "local");
  assert.equal(native.severity_ceiling, "medium");
  assert.equal(native.surface_type, "oss_native_code");
}));

test("reachability classifier promotes a network-reachable native daemon to a CRITICAL ceiling", () => withTempHome((home) => {
  const repo = path.join(home, "net-daemon");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(net_daemon C)\n");
  writeFile(repo, "daemon/server.c", [
    "#include <sys/socket.h>",
    "#include <netinet/in.h>",
    "int serve(void){",
    "  int fd = socket(AF_INET, SOCK_STREAM, 0);",
    "  struct sockaddr_in a; a.sin_addr.s_addr = INADDR_ANY;",
    "  listen(fd, 16);",
    "  return fd;",
    "}",
    "",
  ].join("\n"));
  writeFile(repo, "src/proto.c", "int parse(const char *b, int n){ return n > 0 ? b[0] : 0; }\n");

  const init = parseResult(initRepoSession({ repo_path: repo, target_domain: "repo-net-daemon" }));
  const inventory = parseResult(buildRepoInventory({ target_domain: init.target_domain }));
  assert.equal(inventory.reachability.network_reachable, true);
  assert.equal(inventory.reachability.max_credible_severity_ceiling, "critical");
  assert.ok(inventory.reachability.network_reachable_surface_ids.includes("repo:module:daemon-server.c"));

  const native = surfaceByTitle(init.target_domain, "daemon/server.c");
  assert.equal(native.network_reachable, true);
  assert.equal(native.attack_vector, "network");
  assert.equal(native.severity_ceiling, "critical");
}));

test("project metadata files (AUTHORS) do not create a false OSS-AUTHZ surface", () => withTempHome((home) => {
  const repo = path.join(home, "authors-only");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "package.json", JSON.stringify({ name: "authors-only" }, null, 2));
  writeFile(repo, "AUTHORS.md", "# Authors\n- Jane Doe\n");

  const init = parseResult(initRepoSession({ repo_path: repo, target_domain: "repo-authors-only" }));
  const inventory = parseResult(buildRepoInventory({ target_domain: init.target_domain }));
  assert.ok(!repoSurfaces(init.target_domain).some((surface) => surface.surface_type === "oss_authz"), "AUTHORS must not trigger OSS-AUTHZ");
}));

test("residual hunting seeds recently-patched security fixes into repo inventory", () => withTempHome((home) => {
  const repo = path.join(home, "residual-parser");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(residual C)\n");
  writeFile(repo, "src/decode.c", "int decode(const unsigned char *b, int n){ return n > 0 ? b[0] : 0; }\n");
  writeFile(repo, "CHANGELOG.md", [
    "# Changelog",
    "",
    "## 2.4.4",
    "- Fix heap buffer overflow in decode_chunk() when len is attacker-controlled (CVE-2026-12345)",
    "- Improve documentation wording",
    "",
    "## 2.4.3",
    "- Minor performance refactor",
    "",
  ].join("\n"));

  const init = parseResult(initRepoSession({ repo_path: repo, target_domain: "repo-residual-parser" }));
  const inventory = parseResult(buildRepoInventory({ target_domain: init.target_domain }));
  assert.ok(inventory.counts.residual_hunt_targets >= 1, "expected at least one residual target");
  assert.ok(
    inventory.residual_hunt_targets.some((target) => /CVE-2026-12345|decode_chunk|overflow/i.test(target)),
    "residual targets must capture the patched security fix",
  );
  // A non-security changelog line must not be picked up as a residual lead.
  assert.ok(
    !inventory.residual_hunt_targets.some((target) => /performance refactor/i.test(target)),
    "non-security changelog lines must be ignored",
  );

  const native = surfaceByTitle(init.target_domain, "src/decode.c");
  assert.ok(
    !Object.prototype.hasOwnProperty.call(native, "residual_hunt_targets"),
    "repo-wide residual_hunt_targets must not be repeated on every native surface",
  );
}));

test("residual hunting caps long changelog excerpts before inventory validation", () => withTempHome((home) => {
  const repo = path.join(home, "residual-long-changelog");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(residual_long C)\n");
  writeFile(repo, "src/decode.c", "int decode(const unsigned char *b, int n){ return len > 0 ? b[0] : 0; }\n");
  writeFile(repo, "CHANGELOG.md", `- CVE-2026-99999 fixed in decode_chunk ${"A".repeat(5000)}\n`);

  const init = parseResult(initRepoSession({ repo_path: repo, target_domain: "repo-residual-long-changelog" }));
  const inventory = parseResult(buildRepoInventory({ target_domain: init.target_domain }));
  assert.equal(inventory.counts.residual_hunt_targets, 1);
  const [target] = inventory.residual_hunt_targets;
  assert.ok(target.startsWith("CHANGELOG.md: CVE-2026-99999"));
  assert.ok(target.endsWith("…"), "long residual excerpts must be visibly truncated");
  assert.ok(target.length <= "CHANGELOG.md: ".length + 1025);
}));

test("repo inventory aggregates fuzz seed corpora without reading file contents", () => withTempHome((home) => {
  const repo = path.join(home, "seeded-parser");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(seeded C)\n");
  writeFile(repo, "src/decode.c", "int decode(const unsigned char *b, int n){ return n > 0 ? b[0] : 0; }\n");
  writeFile(repo, "fuzz/corpus/packet-a.bin", "AAAA");
  writeFile(repo, "fuzz/corpus/packet-b.bin", "BBBBBB");
  writeFile(repo, "seeds/minimal.dat", "seed");
  writeFile(repo, "parser_seed_corpus.zip", "zip-bytes");

  const init = parseResult(initRepoSession({ repo_path: repo, target_domain: "repo-seeded-parser" }));
  const inventory = parseResult(buildRepoInventory({ target_domain: init.target_domain }));
  assert.equal(inventory.counts.seed_corpus, 3);
  assert.match(inventory.seed_corpus_hash, /^[a-f0-9]{64}$/);

  const byPath = new Map(inventory.seed_corpus.map((entry) => [entry.rel_path, entry]));
  const fuzzCorpus = byPath.get("fuzz/corpus");
  assert.ok(fuzzCorpus, "expected fuzz/corpus seed aggregate");
  assert.equal(fuzzCorpus.file_count, 2);
  assert.equal(fuzzCorpus.total_bytes, 10);
  assert.equal(fuzzCorpus.has_zip, false);
  assert.deepEqual(fuzzCorpus.sample_rels, ["fuzz/corpus/packet-a.bin", "fuzz/corpus/packet-b.bin"]);
  assert.match(fuzzCorpus.manifest_hash, /^[a-f0-9]{64}$/);

  const zipCorpus = byPath.get("parser_seed_corpus.zip");
  assert.ok(zipCorpus, "expected OSS-Fuzz *_seed_corpus.zip aggregate");
  assert.equal(zipCorpus.file_count, 1);
  assert.equal(zipCorpus.has_zip, true);
}));

test("repo inventory seed corpus count is not capped by the summary list", () => withTempHome((home) => {
  const repo = path.join(home, "many-seeds");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(many_seeds C)\n");
  writeFile(repo, "src/decode.c", "int decode(const unsigned char *b, int n){ return n > 0 ? b[0] : 0; }\n");
  const corpusCount = SEED_CORPUS_SUMMARY_LIMIT + 3;
  for (let index = 0; index < corpusCount; index += 1) {
    writeFile(repo, `case_${String(index).padStart(2, "0")}_seed_corpus/input.bin`, `seed-${index}`);
  }

  const init = parseResult(initRepoSession({ repo_path: repo, target_domain: "repo-many-seeds" }));
  const inventory = parseResult(buildRepoInventory({ target_domain: init.target_domain }));
  assert.equal(inventory.counts.seed_corpus, corpusCount);
  assert.equal(inventory.seed_corpus.length, SEED_CORPUS_SUMMARY_LIMIT);
}));

test("seed corpus aggregation ignores symlinked files outside the repo root", () => withTempHome((home) => {
  const repo = path.join(home, "seed-symlink");
  const outside = path.join(home, "outside-seeds");
  fs.mkdirSync(repo, { recursive: true });
  fs.mkdirSync(outside, { recursive: true });
  writeFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(seed_symlink C)\n");
  writeFile(outside, "case.bin", "outside");
  fs.symlinkSync(outside, path.join(repo, "seeds"), "dir");

  const init = parseResult(initRepoSession({ repo_path: repo, target_domain: "repo-seed-symlink" }));
  const inventory = parseResult(buildRepoInventory({ target_domain: init.target_domain }));
  assert.deepEqual(inventory.seed_corpus, []);
  assert.match(inventory.seed_corpus_hash, /^[a-f0-9]{64}$/);
  assert.equal(inventory.counts.seed_corpus, 0);
}));

test("repo inventory walk does not traverse symlinked directories outside the repo root", () => withTempHome((home) => {
  const repo = path.join(home, "walk-symlink");
  const outside = path.join(home, "outside-walk");
  fs.mkdirSync(repo, { recursive: true });
  fs.mkdirSync(outside, { recursive: true });
  writeFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(walk_symlink C)\n");
  writeFile(outside, "package.json", JSON.stringify({ name: "outside-package" }, null, 2));
  writeFile(outside, "src/escape.c", "int escape(void){ return 1; }\n");
  try {
    fs.symlinkSync(outside, path.join(repo, "vendor"), "dir");
  } catch {
    return;
  }

  const init = parseResult(initRepoSession({ repo_path: repo, target_domain: "repo-walk-symlink" }));
  const inventory = parseResult(buildRepoInventory({ target_domain: init.target_domain }));
  assert.equal(inventory.counts.files, 1);
  assert.equal(inventory.counts.manifests, 0);
  const document = JSON.parse(fs.readFileSync(repoInventoryPath(init.target_domain), "utf8"));
  assert.deepEqual(document.manifests, []);
}));

test("repo Docker environment plan and dry-run command stay session-scoped", () => withTempHome(async (home) => {
  const repo = path.join(home, "libnfs-like");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(libnfs_like C)\nfind_package(libtirpc)\n");
  writeFile(repo, "libnfs.pc.in", "Name: libnfs-like\n");
  writeFile(repo, "src/client.c", "int main(void) { return 0; }\n");

  const init = parseResult(initRepoSession({ repo_path: repo, target_domain: "repo-docker-test" }));
  const inventory = parseResult(buildRepoInventory({ target_domain: init.target_domain }));
  assert.equal(inventory.counts.native_source_files, 1);
  assert.equal(inventory.counts.native_build_files, 1);
  const native = surfaceByTitle(init.target_domain, "src/client.c");
  assert.equal(native.surface_type, "oss_native_code");
  const routed = parseResult(routeSurfaces({ target_domain: init.target_domain }));
  assert.equal(routed.counts.oss_native_code, 2);

  const env = parseResult(await prepareRepoEnv({
    target_domain: init.target_domain,
    dry_run: true,
  }));
  assert.equal(env.dry_run, true);
  assert.equal(env.build_image, false);
  assert.ok(fs.existsSync(repoEnvPath(init.target_domain)));
  assert.ok(fs.existsSync(repoDockerfilePath(init.target_domain)));
  const dockerfile = fs.readFileSync(repoDockerfilePath(init.target_domain), "utf8");
  assert.match(dockerfile, /FROM ubuntu:24\.04/);
  assert.match(dockerfile, /cmake/);
  assert.match(dockerfile, /libkrb5-dev/);
  assert.ok(!dockerfile.includes("libpcap-dev"), "libnfs-like project must not pull libpcap-dev");
  assert.ok(env.recommended_commands.some((command) => command.id === "build_and_test"));

  const run = parseResult(await repoDockerRun({
    target_domain: init.target_domain,
    command: ["sh", "-lc", "cmake --version"],
    dry_run: true,
  }));
  assert.equal(run.dry_run, true);
  assert.equal(run.mount_mode, "read_only");
  assert.ok(run.planned_argv.includes("--network"));
  assert.ok(run.planned_argv.includes("none"));
  assert.ok(run.planned_argv.some((arg) => arg.endsWith(":/src:ro")));
  assert.ok(fs.existsSync(repoCommandRunsJsonlPath(init.target_domain)));
  const log = fs.readFileSync(repoCommandRunsJsonlPath(init.target_domain), "utf8");
  assert.match(log, /"dry_run":true/);
}));

test("high severity OSS native claims require matching non-dry-run repo replay", () => withTempHome((home) => {
  const context = createNativeRepoSession(home);

  assert.throws(
    () => recordFinding(nativeFindingInput(context)),
    /high\/critical native-code claims must include at least one evidence_refs\[\] entry with kind: "repo_command_run"/,
    "legacy recordFinding cannot persist a static-only high native claim",
  );

  const dryRun = appendRepoDockerRun(context.targetDomain, ["sh", "-lc", "/work/repro.sh"], {
    run_id: "run-dry",
    dry_run: true,
  });
  assert.throws(
    () => appendCandidateClaim(nativeClaimInput(context, [
      nativeRepoFileEvidence(),
      repoCommandRunEvidence(dryRun),
    ])),
    /repo_command_run evidence_ref backed by a matching non-dry-run repo-command-runs\.jsonl row/,
  );

  const liveRun = appendRepoDockerRun(context.targetDomain, ["sh", "-lc", "/work/repro.sh"], {
    run_id: "run-live",
  });
  const claim = appendCandidateClaim(nativeClaimInput(context, [
    nativeRepoFileEvidence(),
    repoCommandRunEvidence(liveRun),
  ]));
  assert.equal(claim.severity, "high");
  assert.equal(claim.surface_ids[0], context.assignment.surface_id);
}));

test("OSS dynamic-proof gate rejects Docker startup failure as proof", () => withTempHome((home) => {
  const context = createNativeRepoSession(home, "repo-docker-startup-failure");
  const row = appendRepoDockerRun(context.targetDomain, ["sh", "-lc", "/work/repro.sh"], {
    run_id: "run-docker-startup-failure",
    status: "failed",
    exit_code: 125,
  });

  assert.throws(
    () => appendCandidateClaim(nativeClaimInput(context, [
      nativeRepoFileEvidence(),
      repoCommandRunEvidence(row),
    ])),
    /repo_command_run evidence_ref backed by a matching non-dry-run repo-command-runs\.jsonl row/,
  );
}));

test("OSS dynamic-proof gate rejects container command-start failures as proof", () => withTempHome((home) => {
  for (const exitCode of [126, 127]) {
    const context = createNativeRepoSession(home, `repo-command-start-${exitCode}`);
    const row = appendRepoDockerRun(context.targetDomain, ["sh", "-lc", "/work/repro.sh"], {
      run_id: `run-command-start-${exitCode}`,
      status: "failed",
      exit_code: exitCode,
    });

    assert.throws(
      () => appendCandidateClaim(nativeClaimInput(context, [
        nativeRepoFileEvidence(),
        repoCommandRunEvidence(row),
      ])),
      /repo_command_run evidence_ref backed by a matching non-dry-run repo-command-runs\.jsonl row/,
    );
  }
}));

test("OSS dynamic-proof gate accepts intentional crash and test-failure exits as proof", () => withTempHome((home) => {
  for (const exitCode of [139, 1]) {
    const context = createNativeRepoSession(home, `repo-intentional-failure-${exitCode}`);
    const row = appendRepoDockerRun(context.targetDomain, ["sh", "-lc", "/work/repro.sh"], {
      status: "failed",
      exit_code: exitCode,
    });

    const claim = appendCandidateClaim(nativeClaimInput(context, [
      nativeRepoFileEvidence(),
      repoCommandRunEvidence(row),
    ]));
    assert.equal(claim.severity, "high");
  }
}));

test("OSS dynamic-proof gate fails closed on oversized repo command run logs", () => withTempHome((home) => {
  const context = createNativeRepoSession(home, "repo-oversized-run-log");
  const row = appendRepoDockerRun(context.targetDomain, "/work/repro.sh");
  const runLogPath = repoCommandRunsJsonlPath(context.targetDomain);
  const originalStatSync = fs.statSync;
  try {
    fs.statSync = function patchedStatSync(filePath, ...args) {
      const stats = originalStatSync.call(this, filePath, ...args);
      if (path.resolve(String(filePath)) !== path.resolve(runLogPath)) {
        return stats;
      }
      return Object.create(stats, {
        size: {
          value: 17 * 1024 * 1024,
          enumerable: true,
        },
      });
    };
    assert.throws(
      () => appendCandidateClaim(nativeClaimInput(context, [
        nativeRepoFileEvidence(),
        repoCommandRunEvidence(row),
      ])),
      /repo-command-runs\.jsonl exceeds read cap/,
    );
  } finally {
    fs.statSync = originalStatSync;
  }
}));

test("OSS hunters cannot finalize complete surfaces with zero coverage and zero findings", () => withTempHome((home) => {
  const context = createNativeRepoSession(home, "repo-native-coverage-test");
  fs.writeFileSync(attackSurfacePath(context.targetDomain), `${JSON.stringify({
    version: 1,
    surfaces: [{
      id: context.assignment.surface_id,
      title: "src/parser.c",
      surface_type: "oss_native_code",
    }],
  }, null, 2)}\n`);

  parseResult(logTechniqueAttempt({
    target_domain: context.targetDomain,
    wave: context.wave,
    agent: context.assignment.agent,
    surface_id: context.assignment.surface_id,
    pack_id: "oss-native-code-protocol-memory",
    status: "attempted",
    evidence: "Reviewed parser.c and planned ASAN replay, but no concrete coverage was logged yet.",
    outcome: "No issue recorded",
  }));

  parseResult(writeWaveHandoff({
    target_domain: context.targetDomain,
    wave: context.wave,
    agent: context.assignment.agent,
    surface_id: context.assignment.surface_id,
    handoff_token: context.assignment.handoff_token,
    surface_status: "complete",
    summary: "Static pass only.",
    content: "# Static pass only\n",
  }));

  assert.throws(
    () => finalizeAgentRun({
      target_domain: context.targetDomain,
      wave: context.wave,
      agent: context.assignment.agent,
      surface_id: context.assignment.surface_id,
    }),
    new RegExp(`cannot mark OSS surface ${context.assignment.surface_id.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} complete with zero coverage rows and zero findings`),
  );

  parseResult(logCoverage({
    target_domain: context.targetDomain,
    wave: context.wave,
    agent: context.assignment.agent,
    surface_id: context.assignment.surface_id,
    entries: [{
      endpoint: "src/parser.c",
      bug_class: "memory_safety",
      status: "blocked",
      evidence_summary: "ASAN replay command identified, but harness build was blocked by missing Docker runtime in the test fixture.",
      next_step: "Run /work/repro.sh in the prepared repo Docker image.",
    }],
  }));
  const finalized = parseResult(finalizeAgentRun({
    target_domain: context.targetDomain,
    wave: context.wave,
    agent: context.assignment.agent,
    surface_id: context.assignment.surface_id,
  }));

  assert.equal(finalized.status, "allowed");
  assert.equal(finalized.handoff.surface_status, "complete");
}));

test("reachability classifier flips network_reachable on XDR/RPC stub calls (no raw socket tokens)", () => withTempHome((home) => {
  // An autogenerated RPC stub whose ONLY network evidence is multi-letter
  // xdr_*() calls — no socket()/listen()/htons/sockaddr_in. The content regex's
  // xdr_/evhttp_/uv_tcp_ prefix families must match real calls or this daemon is
  // mis-stamped AV:L / MEDIUM instead of AV:N / CRITICAL.
  const repo = path.join(home, "rpc-stub");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(rpc_stub C)\n");
  writeFile(repo, "src/nfs_xdr.c", [
    "#include <rpc/xdr.h>",
    "int xdr_nfs_arg(XDR *xdrs, struct nfs_arg *p){",
    "  if (!xdr_u_int(xdrs, &p->count)) return 0;",
    "  if (!xdr_bytes(xdrs, &p->data, &p->len, 65536)) return 0;",
    "  if (!xdr_string(xdrs, &p->name, 256)) return 0;",
    "  return 1;",
    "}",
    "",
  ].join("\n"));

  const init = parseResult(initRepoSession({ repo_path: repo, target_domain: "repo-rpc-stub" }));
  const inventory = parseResult(buildRepoInventory({ target_domain: init.target_domain }));
  assert.equal(inventory.reachability.network_reachable, true, "xdr_*() calls must flip network_reachable");
  assert.equal(inventory.reachability.max_credible_severity_ceiling, "critical");

  const native = surfaceByTitle(init.target_domain, "src/nfs_xdr.c");
  assert.equal(native.attack_vector, "network");
  assert.equal(native.severity_ceiling, "critical");
}));

test("residual file probe ignores symlinked files outside the repo root", () => withTempHome((home) => {
  const repo = path.join(home, "residual-symlink");
  const outside = path.join(home, "outside-residuals");
  fs.mkdirSync(repo, { recursive: true });
  fs.mkdirSync(outside, { recursive: true });
  writeFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(residual_symlink C)\n");
  writeFile(repo, "src/decode.c", "int decode(const unsigned char *b, int n){ return n > 0 ? b[0] : 0; }\n");
  writeFile(outside, "SECURITY.md", "Fix heap buffer overflow in outside parser (CVE-2026-77777)\n");
  fs.symlinkSync(outside, path.join(repo, "linked-security"), "dir");

  const init = parseResult(initRepoSession({ repo_path: repo, target_domain: "repo-residual-symlink" }));
  const inventory = parseResult(buildRepoInventory({ target_domain: init.target_domain }));
  assert.deepEqual(inventory.residual_hunt_targets, []);
  assert.equal(inventory.counts.residual_hunt_targets, 0);
}));

test("OSS dynamic-proof gate rejects a repro that claims more than the recorded run executed", () => withTempHome((home) => {
  const context = createNativeRepoSession(home);
  // Only a benign build actually ran...
  const buildOnly = appendRepoDockerRun(context.targetDomain, ["sh", "-lc", "cmake --build /work/build"], {
    run_id: "run-build-only",
  });
  const crashCommand = ["sh", "-lc", "cmake --build /work/build && /work/build/fuzzer crash-001.bin"];
  // ...but the evidence ref claims a different command hash whose crash step never ran.
  assert.throws(
    () => appendCandidateClaim(nativeClaimInput(context, [
      nativeRepoFileEvidence(),
      repoCommandRunEvidence({
        ...buildOnly,
        command_hash: sha256Hex(JSON.stringify(crashCommand)),
      }),
    ])),
    /repo_command_run evidence_ref backed by a matching non-dry-run repo-command-runs\.jsonl row/,
  );
  // The honest case — the executed run's hash matches the claimed repro — passes.
  const crashRun = appendRepoDockerRun(context.targetDomain, crashCommand, {
    run_id: "run-crash",
    exit_code: 139,
  });
  const claim = appendCandidateClaim(nativeClaimInput(context, [
    nativeRepoFileEvidence(),
    repoCommandRunEvidence(crashRun),
  ], { title: "Out-of-bounds read in packet parser after crash replay" }));
  assert.equal(claim.severity, "high");
}));

test("recordFinding duplicate handling still short-circuits before static native proof checks", () => withTempHome((home) => {
  const context = createNativeRepoSession(home);
  const first = parseResult(recordFinding(nativeFindingInput(context, { severity: "medium" })));
  assert.equal(first.recorded, true);

  // Re-recording the same finding (dedupe_key ignores repro_command) with a
  // high severity must return the duplicate, not throw — the proof gate runs
  // only for records that will be written, after dedup.
  const again = parseResult(recordFinding(nativeFindingInput(context, {
    severity: "high",
    repro_command: "/work/never-invoked.sh",
  })));
  assert.equal(again.duplicate, true);
  assert.equal(again.recorded, false);
}));

test("reachability ignores socket/server code that lives only in non-shipping dirs", () => withTempHome((home) => {
  const repo = path.join(home, "parser-with-demo-server");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(parser C)\n");
  writeFile(repo, "src/decode.c", "int decode(const unsigned char *b, int n){ return n > 0 ? b[0] : 0; }\n");
  // A demo TCP server shipped under examples/ must NOT make the library look
  // network-reachable — it is not part of the shipping parser (AV:L stays MEDIUM).
  writeFile(repo, "examples/echo_server.c", [
    "#include <sys/socket.h>",
    "#include <netinet/in.h>",
    "int main(void){",
    "  int fd = socket(AF_INET, SOCK_STREAM, 0);",
    "  struct sockaddr_in a; a.sin_addr.s_addr = INADDR_ANY;",
    "  listen(fd, 16);",
    "  return fd;",
    "}",
    "",
  ].join("\n"));

  const init = parseResult(initRepoSession({ repo_path: repo, target_domain: "repo-parser-demo-server" }));
  const inventory = parseResult(buildRepoInventory({ target_domain: init.target_domain }));
  assert.equal(inventory.reachability.network_reachable, false, "demo server in examples/ must not flip reachability");
  assert.equal(inventory.reachability.max_credible_severity_ceiling, "medium");
}));

test("reachability does not treat C++ method calls (bus.listen) as a socket listener", () => withTempHome((home) => {
  const repo = path.join(home, "event-parser");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(events CXX)\n");
  writeFile(repo, "src/decode.cpp", "int decode(const unsigned char *b, int n){ return n > 0 ? b[0] : 0; }\n");
  // Only member-access .listen()/->socket() — never a bare listen(/socket(.
  writeFile(repo, "src/events.cpp", "void wire(Bus &bus, Bus *p){ bus.listen(nullptr); p->socket(0); }\n");

  const init = parseResult(initRepoSession({ repo_path: repo, target_domain: "repo-event-parser" }));
  const inventory = parseResult(buildRepoInventory({ target_domain: init.target_domain }));
  assert.equal(inventory.reachability.network_reachable, false, "method-call .listen()/->socket() must not flip reachability");
  assert.equal(inventory.reachability.max_credible_severity_ceiling, "medium");
}));

test("reachability detects digit-typed XDR primitives (xdr_uint32_t / xdr_int64_t)", () => withTempHome((home) => {
  const repo = path.join(home, "rpc-fixedwidth");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(rpc C)\n");
  writeFile(repo, "src/proto_xdr.c", [
    "#include <rpc/xdr.h>",
    "int xdr_msg(XDR *xdrs, struct msg *m){",
    "  if (!xdr_uint32_t(xdrs, &m->id)) return 0;",
    "  if (!xdr_int64_t(xdrs, &m->ts)) return 0;",
    "  return 1;",
    "}",
    "",
  ].join("\n"));

  const init = parseResult(initRepoSession({ repo_path: repo, target_domain: "repo-rpc-fixedwidth" }));
  const inventory = parseResult(buildRepoInventory({ target_domain: init.target_domain }));
  assert.equal(inventory.reachability.network_reachable, true, "xdr_uint32_t/xdr_int64_t must flip reachability");
  assert.equal(inventory.reachability.max_credible_severity_ceiling, "critical");
}));

test("reachability attributes per-path anchors (AV:N) and local-only dirs (AV:L) within one native surface", () => withTempHome((home) => {
  // A repo that is BOTH a daemon AND a local-file parser: the surface ceiling
  // stays best-case (CRITICAL), but the per-path map tells the hunter the daemon
  // dir is the AV:N target and the parser dir is an AV:L candidate (#7).
  const repo = path.join(home, "daemon-plus-parser");
  fs.mkdirSync(repo, { recursive: true });
  writeFile(repo, "CMakeLists.txt", "cmake_minimum_required(VERSION 3.22)\nproject(mixed C)\n");
  writeFile(repo, "daemon/server.c", [
    "#include <sys/socket.h>",
    "#include <netinet/in.h>",
    "int serve(void){",
    "  int fd = socket(AF_INET, SOCK_STREAM, 0);",
    "  struct sockaddr_in a; a.sin_addr.s_addr = INADDR_ANY;",
    "  listen(fd, 16);",
    "  return fd;",
    "}",
    "",
  ].join("\n"));
  writeFile(repo, "parsers/conf.c", "int parse_conf(const char *b, int n){ return n > 0 ? b[0] : 0; }\n");

  const init = parseResult(initRepoSession({ repo_path: repo, target_domain: "repo-daemon-plus-parser" }));
  const inventory = parseResult(buildRepoInventory({ target_domain: init.target_domain }));
  assert.equal(inventory.reachability.network_reachable, true);
  assert.equal(inventory.reachability.max_credible_severity_ceiling, "critical");
  assert.ok(inventory.reachability.native_attack_vector_map, "inventory exposes the per-path map");

  const daemon = surfaceByTitle(init.target_domain, "daemon/server.c");
  const parser = surfaceByTitle(init.target_domain, "parsers/conf.c");
  assert.equal(daemon.severity_ceiling, "critical", "daemon module carries the best-case ceiling");
  assert.equal(daemon.network_reachable, true);
  assert.ok(daemon.network_reachable_anchors.includes("daemon/server.c"), "daemon file is a network anchor");
  assert.ok(!(daemon.network_reachable_dirs || []).includes("daemon"), "top-level daemon dir is not promoted wholesale");
  assert.equal(parser.severity_ceiling, "medium", "parser module stays local-only");
  assert.equal(parser.network_reachable, false);
  assert.ok(parser.local_only_candidate_dirs.includes("parsers"), "parser dir flagged AV:L candidate");
  assert.ok(!parser.local_only_candidate_dirs.includes("daemon"), "daemon dir is not a local-only candidate");
}));
