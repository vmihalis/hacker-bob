"use strict";

// Cycle O.4 — sandboxed docker execution via bob_repo_docker_run.
//
// Coverage:
// - dry_run is the default; the planned argv is recorded but docker
//   is never invoked.
// - live mode (stubbed runtime) constructs argv with EVERY O-P3
//   sandbox flag present. Per-flag positive assertions, not aggregate.
// - image_tag mismatch is refused with O-D6 structured error.
// - egress env-vars threaded via --env (NOT ENV in the image).
// - JSONL row never carries raw stdout/stderr.
// - sensitive-material scan catches secret-shaped tokens in planned_argv.
// - tool wrapper is evaluator-shared/verifier/evidence — NOT orchestrator.
// - authority class registered.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

const {
  initRepoSession,
} = require("../mcp/lib/repo-target.js");
const {
  buildDifferentialCheckoutCommand,
  prepareRepoEnv,
  repoDockerRun,
  buildDockerRunArgv,
  buildImageTag,
  DIFFERENTIAL_CHECKOUT_KIND_VALUES,
  REPO_DOCKER_RUN_DEFAULT_TIMEOUT_MS,
  REPO_DOCKER_RUN_MAX_TIMEOUT_MS,
  REPO_DOCKER_RUN_MAX_OUTPUT_BYTES,
  REPO_MOUNT_MODE_VALUES,
} = require("../mcp/lib/repo-env.js");
const {
  validateNoSensitiveMaterial,
} = require("../mcp/lib/sensitive-material.js");
const {
  repoCommandRunsJsonlPath,
  repoRunsDir,
  repoWorkDir,
  sessionDir,
} = require("../mcp/lib/paths.js");
const repoDockerRunTool = require("../mcp/lib/tools/repo-docker-run.js");
const {
  EXPLICIT_AUTHORITY_CLASS_BY_TOOL,
} = require("../mcp/lib/session-authority.js");

async function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-repo-docker-run-"));
  process.env.HOME = home;
  try {
    return await fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function makeTempRepoDir(prefix = "bob-docker-run-fixture-") {
  const raw = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  return fs.realpathSync.native ? fs.realpathSync.native(raw) : fs.realpathSync(raw);
}

function write(repoRoot, rel, content = "") {
  const abs = path.join(repoRoot, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content, "utf8");
}

function readJsonl(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const raw = fs.readFileSync(filePath, "utf8");
  return raw.split(/\r?\n/).filter((line) => line.trim().length > 0).map((line) => JSON.parse(line));
}

function indexOfFlag(args, flag) {
  return args.indexOf(flag);
}

function valueAfterFlag(args, flag) {
  const i = indexOfFlag(args, flag);
  return i >= 0 ? args[i + 1] : undefined;
}

function git(repoRoot, args) {
  return execFileSync("git", ["-C", repoRoot, ...args], {
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: "Bob Test",
      GIT_AUTHOR_EMAIL: "bob-test@example.invalid",
      GIT_COMMITTER_NAME: "Bob Test",
      GIT_COMMITTER_EMAIL: "bob-test@example.invalid",
    },
  }).trim();
}

function makeGitRepo(prefix = "bob-differential-repo-") {
  const repoRoot = makeTempRepoDir(prefix);
  git(repoRoot, ["init", "-q"]);
  write(repoRoot, "package.json", JSON.stringify({ name: "x" }));
  git(repoRoot, ["add", "package.json"]);
  git(repoRoot, ["commit", "-q", "-m", "initial"]);
  const first = git(repoRoot, ["rev-parse", "HEAD"]);
  write(repoRoot, "index.js", "module.exports = 1;\n");
  git(repoRoot, ["add", "index.js"]);
  git(repoRoot, ["commit", "-q", "-m", "second"]);
  const second = git(repoRoot, ["rev-parse", "HEAD"]);
  return { repoRoot, first, second };
}

// ---------- buildDockerRunArgv (pure) per-flag assertions ----------

test("buildDockerRunArgv emits --network none by default (O-P3)", () => {
  const argv = buildDockerRunArgv({
    repoRoot: "/tmp/repo",
    workDir: "/tmp/work",
    imageTag: "bob-oss-repo-x:abc",
    command: ["echo", "hi"],
    allowNetwork: false,
    repoMountMode: "read_only",
    egressProfile: null,
  });
  assert.equal(argv.command, "docker");
  assert.equal(argv.args[0], "run");
  assert.equal(argv.args[1], "--rm");
  assert.equal(valueAfterFlag(argv.args, "--network"), "none");
});

test("buildDockerRunArgv emits --network bridge + --dns 1.1.1.1 when allow_network=true", () => {
  const argv = buildDockerRunArgv({
    repoRoot: "/tmp/repo",
    workDir: "/tmp/work",
    imageTag: "bob-oss-repo-x:abc",
    command: ["echo", "hi"],
    allowNetwork: true,
    repoMountMode: "read_only",
    egressProfile: null,
  });
  assert.equal(valueAfterFlag(argv.args, "--network"), "bridge");
  assert.equal(valueAfterFlag(argv.args, "--dns"), "1.1.1.1");
});

test("buildDockerRunArgv emits --cap-drop ALL (O-P3)", () => {
  const argv = buildDockerRunArgv({
    repoRoot: "/r", workDir: "/w", imageTag: "img:t", command: ["x"],
    allowNetwork: false, repoMountMode: "read_only", egressProfile: null,
  });
  assert.equal(valueAfterFlag(argv.args, "--cap-drop"), "ALL");
});

test("buildDockerRunArgv emits --security-opt no-new-privileges (O-P3)", () => {
  const argv = buildDockerRunArgv({
    repoRoot: "/r", workDir: "/w", imageTag: "img:t", command: ["x"],
    allowNetwork: false, repoMountMode: "read_only", egressProfile: null,
  });
  assert.equal(valueAfterFlag(argv.args, "--security-opt"), "no-new-privileges");
});

test("buildDockerRunArgv emits --user 1000:1000 (O-P3)", () => {
  const argv = buildDockerRunArgv({
    repoRoot: "/r", workDir: "/w", imageTag: "img:t", command: ["x"],
    allowNetwork: false, repoMountMode: "read_only", egressProfile: null,
  });
  assert.equal(valueAfterFlag(argv.args, "--user"), "1000:1000");
});

test("buildDockerRunArgv emits --cpus 2 (O-P3)", () => {
  const argv = buildDockerRunArgv({
    repoRoot: "/r", workDir: "/w", imageTag: "img:t", command: ["x"],
    allowNetwork: false, repoMountMode: "read_only", egressProfile: null,
  });
  assert.equal(valueAfterFlag(argv.args, "--cpus"), "2");
});

test("buildDockerRunArgv emits --memory 4g (O-P3)", () => {
  const argv = buildDockerRunArgv({
    repoRoot: "/r", workDir: "/w", imageTag: "img:t", command: ["x"],
    allowNetwork: false, repoMountMode: "read_only", egressProfile: null,
  });
  assert.equal(valueAfterFlag(argv.args, "--memory"), "4g");
});

test("buildDockerRunArgv emits --pids-limit 1024 (O-P3)", () => {
  const argv = buildDockerRunArgv({
    repoRoot: "/r", workDir: "/w", imageTag: "img:t", command: ["x"],
    allowNetwork: false, repoMountMode: "read_only", egressProfile: null,
  });
  assert.equal(valueAfterFlag(argv.args, "--pids-limit"), "1024");
});

test("buildDockerRunArgv emits --read-only (O-P3)", () => {
  const argv = buildDockerRunArgv({
    repoRoot: "/r", workDir: "/w", imageTag: "img:t", command: ["x"],
    allowNetwork: false, repoMountMode: "read_only", egressProfile: null,
  });
  assert.ok(argv.args.includes("--read-only"), "expected --read-only flag");
});

test("buildDockerRunArgv emits --tmpfs /tmp:size=512m (O-P3)", () => {
  const argv = buildDockerRunArgv({
    repoRoot: "/r", workDir: "/w", imageTag: "img:t", command: ["x"],
    allowNetwork: false, repoMountMode: "read_only", egressProfile: null,
  });
  assert.equal(valueAfterFlag(argv.args, "--tmpfs"), "/tmp:size=512m");
});

test("buildDockerRunArgv mounts /src read-only by default and /work read-write", () => {
  const argv = buildDockerRunArgv({
    repoRoot: "/path/to/repo",
    workDir: "/path/to/work",
    imageTag: "img:t",
    command: ["echo"],
    allowNetwork: false,
    repoMountMode: "read_only",
    egressProfile: null,
  });
  const mounts = argv.args
    .map((value, index) => ({ value, index }))
    .filter((entry) => entry.value === "-v")
    .map((entry) => argv.args[entry.index + 1]);
  assert.ok(
    mounts.some((m) => m === "/path/to/repo:/src:ro"),
    `expected /src read-only mount; got mounts=${mounts.join(", ")}`,
  );
  assert.ok(
    mounts.some((m) => m === "/path/to/work:/work:rw"),
    `expected /work read-write mount; got mounts=${mounts.join(", ")}`,
  );
});

test("buildDockerRunArgv mounts /src read-write when repo_mount_mode=read_write", () => {
  const argv = buildDockerRunArgv({
    repoRoot: "/r",
    workDir: "/w",
    imageTag: "img:t",
    command: ["x"],
    allowNetwork: false,
    repoMountMode: "read_write",
    egressProfile: null,
  });
  const mounts = argv.args
    .map((value, index) => ({ value, index }))
    .filter((entry) => entry.value === "-v")
    .map((entry) => argv.args[entry.index + 1]);
  assert.ok(mounts.some((m) => m === "/r:/src:rw"), `mounts=${mounts.join(", ")}`);
});

test("buildDockerRunArgv places the image tag immediately before the command tokens", () => {
  const argv = buildDockerRunArgv({
    repoRoot: "/r",
    workDir: "/w",
    imageTag: "bob-oss-repo-z:f00d",
    command: ["sh", "-lc", "echo hi"],
    allowNetwork: false,
    repoMountMode: "read_only",
    egressProfile: null,
  });
  const imageIndex = argv.args.indexOf("bob-oss-repo-z:f00d");
  assert.ok(imageIndex >= 0, "image tag missing from argv");
  // Image tag must precede the command tokens — docker run requires positional ordering.
  assert.equal(argv.args[imageIndex + 1], "sh");
  assert.equal(argv.args[imageIndex + 2], "-lc");
  assert.equal(argv.args[imageIndex + 3], "echo hi");
});

test("buildDockerRunArgv threads HTTP_PROXY via --env when allow_network=true (NOT ENV)", () => {
  const argv = buildDockerRunArgv({
    repoRoot: "/r",
    workDir: "/w",
    imageTag: "img:t",
    command: ["x"],
    allowNetwork: true,
    repoMountMode: "read_only",
    egressProfile: { proxy_url: "http://proxy.invalid:3128/", proxy_configured: true },
  });
  const envFlags = argv.args
    .map((value, index) => ({ value, index }))
    .filter((entry) => entry.value === "--env")
    .map((entry) => argv.args[entry.index + 1]);
  assert.ok(
    envFlags.some((e) => e === "HTTP_PROXY=http://proxy.invalid:3128/"),
    `HTTP_PROXY --env missing; got ${envFlags.join(", ")}`,
  );
  assert.ok(
    envFlags.some((e) => e === "HTTPS_PROXY=http://proxy.invalid:3128/"),
    `HTTPS_PROXY --env missing; got ${envFlags.join(", ")}`,
  );
});

test("buildDockerRunArgv does NOT thread proxy when allow_network=false", () => {
  const argv = buildDockerRunArgv({
    repoRoot: "/r",
    workDir: "/w",
    imageTag: "img:t",
    command: ["x"],
    allowNetwork: false,
    repoMountMode: "read_only",
    egressProfile: { proxy_url: "http://proxy.invalid:3128/", proxy_configured: true },
  });
  // No --env flag should appear when network is closed: a proxy is meaningless and would leak intent.
  assert.equal(argv.args.indexOf("--env"), -1, "--env should not appear under --network none");
});

// ---------- S14 differential checkout builder (pure) ----------

test("buildDifferentialCheckoutCommand emits archive materialization for each checkout_kind", () => {
  const ref = "abcdef1234567890";
  for (const kind of DIFFERENTIAL_CHECKOUT_KIND_VALUES) {
    const command = buildDifferentialCheckoutCommand({
      checkout_ref: ref,
      checkout_kind: kind,
    });
    assert.deepEqual(command.slice(0, 2), ["sh", "-lc"]);
    assert.ok(command[2].length <= 2048, `${kind} command token exceeded cap`);
    assert.match(command[2], /rm -rf '\/work\/repo'/);
    assert.match(command[2], /mkdir -p '\/work\/repo'/);
    assert.match(command[2], /git -C \/src cat-file -e/);
    assert.match(command[2], /git -C \/src archive --format=tar/);
    assert.match(command[2], /tar -x -f \/work\/checkout\.tar -C '\/work\/repo'/);
    if (kind === "self_patch") {
      assert.match(command[2], /cat-file -e 'HEAD\^\{commit\}'/);
      assert.match(command[2], /archive --format=tar 'HEAD'/);
      assert.match(command[2], /test -f \/work\/patch\.diff/);
      assert.match(command[2], /git -C '\/work\/repo' apply \/work\/patch\.diff/);
    } else {
      assert.match(command[2], new RegExp(`cat-file -e '${ref}\\^\\{commit\\}'`));
      assert.match(command[2], new RegExp(`archive --format=tar '${ref}'`));
      assert.doesNotMatch(command[2], /patch\.diff/);
    }
  }
});

test("buildDifferentialCheckoutCommand refuses destinations outside /work", () => {
  assert.throws(
    () => buildDifferentialCheckoutCommand({
      checkout_ref: "abcdef1",
      checkout_kind: "upstream_fix",
      dest: "/src/repo",
    }),
    /dest must be a safe path under \/work/,
  );
});

// ---------- repoDockerRun (dry-run) ----------

test("repoDockerRun dry_run records plan to repo-command-runs.jsonl without docker exec", async () => {
  await withTempHome(async () => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "package.json", JSON.stringify({ name: "x" }));
    const init = initRepoSession({ repo_path: repoRoot });

    let dockerInvoked = false;
    const runtime = {
      run: async () => { dockerInvoked = true; throw new Error("must not exec in dry_run"); },
      execFile: async () => { dockerInvoked = true; throw new Error("must not probe in dry_run"); },
    };
    const result = await repoDockerRun({
      target_domain: init.target_domain,
      command: ["echo", "hi"],
      runtime,
    });
    assert.equal(dockerInvoked, false, "docker runtime must not be invoked in dry_run");
    assert.equal(result.dry_run, true);
    assert.equal(result.network_mode, "none");
    assert.equal(result.mount_mode, "read_only");
    assert.equal(Object.prototype.hasOwnProperty.call(result, "checkout_ref"), false);
    assert.equal(Object.prototype.hasOwnProperty.call(result, "checkout_kind"), false);
    assert.equal(result.image_tag, `bob-oss-${init.target_domain}:${init.repo_hash.slice(0, 16)}`);
    assert.equal(result.exit_code, null);
    assert.equal(result.stdout_hash, null);
    assert.equal(result.stderr_hash, null);
    assert.equal(result.stdout_path, null, "dry-run should not allocate stdout file");
    assert.ok(Array.isArray(result.planned_argv));
    assert.ok(result.planned_argv.includes("--cap-drop"));
    assert.ok(result.planned_argv.includes("--user"));
    // run_id is unique-ish per invocation.
    assert.match(result.run_id, /^run-[0-9a-f]+-[0-9a-f]+$/);

    // Plan row was persisted.
    const rows = readJsonl(repoCommandRunsJsonlPath(init.target_domain));
    assert.equal(rows.length, 1);
    assert.equal(rows[0].dry_run, true);
    assert.equal(rows[0].run_id, result.run_id);
    assert.equal(rows[0].image_tag, result.image_tag);
    assert.equal(rows[0].network_mode, "none");
    assert.equal(rows[0].mount_mode, "read_only");
    assert.equal(Object.prototype.hasOwnProperty.call(rows[0], "checkout_ref"), false);
    assert.equal(Object.prototype.hasOwnProperty.call(rows[0], "checkout_kind"), false);
    assert.ok(typeof rows[0].command_hash === "string" && /^[0-9a-f]{64}$/.test(rows[0].command_hash));
  });
});

test("repoDockerRun dry_run injects S14 checkout command and records provenance", async () => {
  await withTempHome(async () => {
    const { repoRoot, first } = makeGitRepo();
    const init = initRepoSession({ repo_path: repoRoot });

    const result = await repoDockerRun({
      target_domain: init.target_domain,
      checkout: { ref: first, kind: "pre_introduction" },
    });
    assert.equal(result.dry_run, true);
    assert.equal(result.checkout_ref, first);
    assert.equal(result.checkout_kind, "pre_introduction");
    assert.equal(result.network_mode, "none");
    assert.equal(result.mount_mode, "read_only");
    assert.ok(result.planned_argv.some((arg) => arg === `${repoRoot}:/src:ro`), "differential run must keep /src read-only");
    const script = result.planned_argv[result.planned_argv.length - 1];
    assert.match(script, /git -C \/src cat-file -e/);
    assert.match(script, /git -C \/src archive --format=tar/);
    assert.match(script, /tar -x -f \/work\/checkout\.tar -C '\/work\/repo'/);

    const rows = readJsonl(repoCommandRunsJsonlPath(init.target_domain));
    assert.equal(rows.length, 1);
    assert.equal(rows[0].checkout_ref, first);
    assert.equal(rows[0].checkout_kind, "pre_introduction");
    assert.equal(rows[0].network_mode, "none");
    assert.equal(rows[0].mount_mode, "read_only");
  });
});

test("repoDockerRun checkout provenance is scrub-validated before persistence", async () => {
  await withTempHome(async () => {
    const { repoRoot, first } = makeGitRepo();
    const init = initRepoSession({ repo_path: repoRoot });
    await assert.rejects(
      () => repoDockerRun({
        target_domain: init.target_domain,
        checkout: { ref: first, kind: "upstream_fix" },
        command: ["echo", "eyJhbGciOiJxxx.aabbccddeexxxxx.aabbccddeexxxxx"],
      }),
      /secrets|secret|tokens|cookies/i,
    );
    const rows = readJsonl(repoCommandRunsJsonlPath(init.target_domain));
    assert.equal(rows.length, 0, "no checkout provenance row should land when scrub fails");
  });
});

// ---------- repoDockerRun (live mode, stubbed runtime) ----------

test("repoDockerRun live mode constructs argv with every O-P3 sandbox flag (per-flag positive)", async () => {
  await withTempHome(async () => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "package.json", JSON.stringify({ name: "x" }));
    const init = initRepoSession({ repo_path: repoRoot });

    let capturedArgs = null;
    const runtime = {
      execFile: async (command) => {
        if (command === "docker") return { stdout: "Docker version 25.0", stderr: "" };
        throw new Error(`unexpected execFile call: ${command}`);
      },
      run: async ({ command, args, stdoutPath, stderrPath }) => {
        capturedArgs = args;
        assert.equal(command, "docker");
        // Write deterministic capture content so the hashes are stable.
        fs.writeFileSync(stdoutPath, "hello from sandbox\n");
        fs.writeFileSync(stderrPath, "");
        return {
          exit_code: 0,
          signal: null,
          duration_ms: 42,
          timed_out: false,
          stdout_bytes: 19,
          stderr_bytes: 0,
          stdout_truncated: false,
          stderr_truncated: false,
        };
      },
    };

    const result = await repoDockerRun({
      target_domain: init.target_domain,
      command: ["echo", "hello"],
      dry_run: false,
      runtime,
    });
    assert.ok(capturedArgs, "runtime.run must have been called");
    assert.equal(result.exit_code, 0);
    assert.equal(result.dry_run, false);
    assert.equal(result.duration_ms, 42);

    // Per-flag positive assertions on the captured argv.
    assert.equal(capturedArgs[0], "run");
    assert.equal(capturedArgs[1], "--rm");
    assert.equal(valueAfterFlag(capturedArgs, "--network"), "none");
    assert.equal(valueAfterFlag(capturedArgs, "--cap-drop"), "ALL");
    assert.equal(valueAfterFlag(capturedArgs, "--security-opt"), "no-new-privileges");
    assert.equal(valueAfterFlag(capturedArgs, "--user"), "1000:1000");
    assert.equal(valueAfterFlag(capturedArgs, "--cpus"), "2");
    assert.equal(valueAfterFlag(capturedArgs, "--memory"), "4g");
    assert.equal(valueAfterFlag(capturedArgs, "--pids-limit"), "1024");
    assert.ok(capturedArgs.includes("--read-only"));
    assert.equal(valueAfterFlag(capturedArgs, "--tmpfs"), "/tmp:size=512m");

    // Mounts: /src read-only, /work writable.
    const mounts = capturedArgs
      .map((v, i) => ({ v, i }))
      .filter((e) => e.v === "-v")
      .map((e) => capturedArgs[e.i + 1]);
    assert.ok(mounts.some((m) => m === `${repoRoot}:/src:ro`));
    assert.ok(mounts.some((m) => m === `${repoWorkDir(init.target_domain)}:/work:rw`));
  });
});

test("repoDockerRun records exit code, duration, network mode, mount mode, image tag in JSONL", async () => {
  await withTempHome(async () => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "package.json", JSON.stringify({ name: "x" }));
    const init = initRepoSession({ repo_path: repoRoot });

    const runtime = {
      execFile: async () => ({ stdout: "Docker version 25.0", stderr: "" }),
      run: async ({ stdoutPath, stderrPath }) => {
        fs.writeFileSync(stdoutPath, "abc");
        fs.writeFileSync(stderrPath, "");
        return {
          exit_code: 7,
          signal: null,
          duration_ms: 123,
          timed_out: false,
          stdout_bytes: 3,
          stderr_bytes: 0,
        };
      },
    };

    const result = await repoDockerRun({
      target_domain: init.target_domain,
      command: ["false"],
      dry_run: false,
      runtime,
    });
    const rows = readJsonl(repoCommandRunsJsonlPath(init.target_domain));
    assert.equal(rows.length, 1);
    assert.equal(rows[0].dry_run, false);
    assert.equal(rows[0].exit_code, 7);
    assert.equal(rows[0].duration_ms, 123);
    assert.equal(rows[0].network_mode, "none");
    assert.equal(rows[0].mount_mode, "read_only");
    assert.equal(rows[0].image_tag, result.image_tag);
    assert.equal(rows[0].run_id, result.run_id);
    // JSONL row must include the hash of stdout/stderr; NOT raw bytes.
    assert.match(rows[0].stdout_hash, /^[0-9a-f]{64}$/);
    assert.match(rows[0].stderr_hash, /^[0-9a-f]{64}$/);
    assert.equal(Object.prototype.hasOwnProperty.call(rows[0], "stdout"), false,
      "JSONL row must NOT carry raw stdout bytes");
    assert.equal(Object.prototype.hasOwnProperty.call(rows[0], "stderr"), false,
      "JSONL row must NOT carry raw stderr bytes");
  });
});

test("repoDockerRun image_tag mismatch is rejected with O-D6 structured error", async () => {
  await withTempHome(async () => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "package.json", JSON.stringify({ name: "x" }));
    const init = initRepoSession({ repo_path: repoRoot });

    let caught;
    try {
      await repoDockerRun({
        target_domain: init.target_domain,
        command: ["echo"],
        image_tag: "bob-oss-different-repo:cafebabe00000000",
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "expected image_tag_mismatch error");
    assert.equal(caught.details && caught.details.repo_error_code, "image_tag_mismatch");
    assert.equal(caught.details && caught.details.violated_invariant, "O-D6");
    assert.equal(caught.details && caught.details.expected_image_tag,
      `bob-oss-${init.target_domain}:${init.repo_hash.slice(0, 16)}`);
  });
});

test("repoDockerRun accepts an explicit image_tag that matches the session-derived tag", async () => {
  await withTempHome(async () => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "package.json", JSON.stringify({ name: "x" }));
    const init = initRepoSession({ repo_path: repoRoot });
    const expected = buildImageTag(init.target_domain, init.repo_hash);
    const result = await repoDockerRun({
      target_domain: init.target_domain,
      command: ["echo"],
      image_tag: expected,
    });
    assert.equal(result.image_tag, expected);
  });
});

test("repoDockerRun threads egress proxy via --env (NOT ENV in image)", async () => {
  await withTempHome(async () => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "package.json", JSON.stringify({ name: "x" }));
    const init = initRepoSession({ repo_path: repoRoot });

    let capturedArgs = null;
    const runtime = {
      execFile: async () => ({ stdout: "Docker version 25.0", stderr: "" }),
      run: async ({ args, stdoutPath, stderrPath }) => {
        capturedArgs = args;
        fs.writeFileSync(stdoutPath, "");
        fs.writeFileSync(stderrPath, "");
        return { exit_code: 0, signal: null, duration_ms: 1, timed_out: false, stdout_bytes: 0, stderr_bytes: 0 };
      },
    };

    // Provision a synthetic egress profile with a proxy URL.
    const projectRoot = path.dirname(__dirname);
    const egressPath = path.join(projectRoot, ".claude", "bob", "egress-profiles.json");
    const originalEgress = fs.existsSync(egressPath) ? fs.readFileSync(egressPath, "utf8") : null;
    fs.mkdirSync(path.dirname(egressPath), { recursive: true });
    fs.writeFileSync(
      egressPath,
      JSON.stringify(
        {
          version: 1,
          profiles: [
            { name: "default", region: null, description: null, proxy_url: null, enabled: true },
            { name: "synthetic_proxy", region: "test", description: null, proxy_url: "${BOB_TEST_PROXY_URL}", enabled: true },
          ],
        },
        null,
        2,
      ),
    );
    const originalProxyEnv = process.env.BOB_TEST_PROXY_URL;
    process.env.BOB_TEST_PROXY_URL = "http://proxy.invalid:3128/";
    try {
      await repoDockerRun({
        target_domain: init.target_domain,
        command: ["echo"],
        dry_run: false,
        allow_network: true,
        egress_profile: "synthetic_proxy",
        runtime,
      });
      assert.ok(capturedArgs, "runtime.run must have been called");
      // --env HTTP_PROXY=... and --env HTTPS_PROXY=... must appear.
      const envValues = capturedArgs
        .map((v, i) => ({ v, i }))
        .filter((e) => e.v === "--env")
        .map((e) => capturedArgs[e.i + 1]);
      assert.ok(envValues.some((v) => v === "HTTP_PROXY=http://proxy.invalid:3128/"),
        `HTTP_PROXY --env missing; got ${envValues.join(", ")}`);
      assert.ok(envValues.some((v) => v === "HTTPS_PROXY=http://proxy.invalid:3128/"),
        `HTTPS_PROXY --env missing; got ${envValues.join(", ")}`);
      // No ENV-prefixed token shape should appear in argv.
      assert.equal(capturedArgs.some((token) => /^ENV\s/i.test(token)), false,
        "docker run argv must not carry ENV ... pseudo-flags");
      // --dns 1.1.1.1 pinned to neutralize host DNS leak.
      assert.equal(valueAfterFlag(capturedArgs, "--dns"), "1.1.1.1");
    } finally {
      if (originalProxyEnv === undefined) delete process.env.BOB_TEST_PROXY_URL;
      else process.env.BOB_TEST_PROXY_URL = originalProxyEnv;
      if (originalEgress != null) fs.writeFileSync(egressPath, originalEgress);
      else fs.rmSync(egressPath, { force: true });
    }
  });
});

test("repoDockerRun JSONL is pre-flighted through validateNoSensitiveMaterial (O-P7)", async () => {
  await withTempHome(async () => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "package.json", JSON.stringify({ name: "x" }));
    const init = initRepoSession({ repo_path: repoRoot });

    // Smuggle a JWT-shaped token into the command. validateNoSensitiveMaterial
    // should fire because SENSITIVE_VALUE_RE matches the eyJ... pattern (the
    // JWT regex demands at least 10 base64url chars per segment).
    let caught;
    try {
      await repoDockerRun({
        target_domain: init.target_domain,
        command: ["echo", "eyJhbGciOiJxxx.aabbccddeexxxxx.aabbccddeexxxxx"],
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "expected sensitive-material validation to fire");
    assert.match(String(caught.message || caught), /secrets|secret|tokens|cookies/i);

    // Confirm the JSONL was not written.
    const rows = readJsonl(repoCommandRunsJsonlPath(init.target_domain));
    assert.equal(rows.length, 0, "no row should land when scrub-validate fails");
  });
});

test("repoDockerRun docker_unavailable when docker CLI is missing in live mode", async () => {
  await withTempHome(async () => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "package.json", JSON.stringify({ name: "x" }));
    const init = initRepoSession({ repo_path: repoRoot });

    const runtime = {
      execFile: async () => {
        const err = new Error("ENOENT");
        err.code = "ENOENT";
        throw err;
      },
      run: async () => { throw new Error("must not run when docker is unavailable"); },
    };

    let caught;
    try {
      await repoDockerRun({
        target_domain: init.target_domain,
        command: ["echo"],
        dry_run: false,
        runtime,
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "expected docker_unavailable error");
    assert.equal(caught.details && caught.details.repo_error_code, "docker_unavailable");
  });
});

test("repoDockerRun rejects empty command array", async () => {
  await withTempHome(async () => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "package.json", JSON.stringify({ name: "x" }));
    const init = initRepoSession({ repo_path: repoRoot });

    await assert.rejects(
      () => repoDockerRun({ target_domain: init.target_domain, command: [] }),
      /non-empty array/,
    );
    await assert.rejects(
      () => repoDockerRun({ target_domain: init.target_domain, command: "echo" }),
      /non-empty array/,
    );
  });
});

test("repoDockerRun rejects timeout_ms above the 600_000 cap", async () => {
  await withTempHome(async () => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "package.json", JSON.stringify({ name: "x" }));
    const init = initRepoSession({ repo_path: repoRoot });

    await assert.rejects(
      () => repoDockerRun({
        target_domain: init.target_domain,
        command: ["echo"],
        timeout_ms: 999999999,
      }),
      /timeout_ms/i,
    );
  });
});

test("repoDockerRun rejects unknown repo_mount_mode", async () => {
  await withTempHome(async () => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "package.json", JSON.stringify({ name: "x" }));
    const init = initRepoSession({ repo_path: repoRoot });

    await assert.rejects(
      () => repoDockerRun({
        target_domain: init.target_domain,
        command: ["echo"],
        repo_mount_mode: "shared",
      }),
      /repo_mount_mode/i,
    );
  });
});

test("repoDockerRun records replay_context when provided", async () => {
  await withTempHome(async () => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "package.json", JSON.stringify({ name: "x" }));
    const init = initRepoSession({ repo_path: repoRoot });
    const result = await repoDockerRun({
      target_domain: init.target_domain,
      command: ["echo"],
      replay_context: { wave: "w1", agent: "a1", surface_id: "repo:module:src-x" },
    });
    assert.deepEqual(result.replay_context, {
      wave: "w1",
      agent: "a1",
      surface_id: "repo:module:src-x",
    });
    const rows = readJsonl(repoCommandRunsJsonlPath(init.target_domain));
    assert.deepEqual(rows[0].replay_context, {
      wave: "w1",
      agent: "a1",
      surface_id: "repo:module:src-x",
    });
  });
});

test("repoDockerRun records blocked_harness_run_id when provided", async () => {
  await withTempHome(async () => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "package.json", JSON.stringify({ name: "x" }));
    const init = initRepoSession({ repo_path: repoRoot });
    const result = await repoDockerRun({
      target_domain: init.target_domain,
      command: ["echo"],
      blocked_harness_run_id: "bh-w1-a1-001",
    });
    assert.equal(result.blocked_harness_run_id, "bh-w1-a1-001");
    const rows = readJsonl(repoCommandRunsJsonlPath(init.target_domain));
    assert.equal(rows[0].blocked_harness_run_id, "bh-w1-a1-001");
  });
});

test("repoDockerRun captures stdout/stderr to <session>/repo-runs/<run_id>.{stdout,stderr}", async () => {
  await withTempHome(async () => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "package.json", JSON.stringify({ name: "x" }));
    const init = initRepoSession({ repo_path: repoRoot });

    const runtime = {
      execFile: async () => ({ stdout: "Docker version 25.0", stderr: "" }),
      run: async ({ stdoutPath, stderrPath }) => {
        fs.writeFileSync(stdoutPath, "captured stdout\n");
        fs.writeFileSync(stderrPath, "captured stderr\n");
        return { exit_code: 0, signal: null, duration_ms: 5, timed_out: false, stdout_bytes: 16, stderr_bytes: 16 };
      },
    };

    const result = await repoDockerRun({
      target_domain: init.target_domain,
      command: ["echo"],
      dry_run: false,
      runtime,
    });
    const expectedDir = repoRunsDir(init.target_domain);
    const expectedStdout = path.join(expectedDir, `${result.run_id}.stdout`);
    const expectedStderr = path.join(expectedDir, `${result.run_id}.stderr`);
    assert.equal(result.stdout_path, expectedStdout);
    assert.equal(result.stderr_path, expectedStderr);
    assert.equal(fs.readFileSync(expectedStdout, "utf8"), "captured stdout\n");
    assert.equal(fs.readFileSync(expectedStderr, "utf8"), "captured stderr\n");
    // stdout/stderr files live under sessionDir but NOT in the JSONL row body.
    const rows = readJsonl(repoCommandRunsJsonlPath(init.target_domain));
    assert.equal(rows[0].stdout_path, expectedStdout);
    assert.equal(rows[0].stderr_path, expectedStderr);
  });
});

test("repoDockerRun throws when target_domain is not a repo session", async () => {
  await withTempHome(async () => {
    await assert.rejects(
      () => repoDockerRun({ target_domain: "repo-missing-12345678", command: ["echo"] }),
      /is not a repo session|Missing session state/,
    );
  });
});

// ---------- Tool wrapper contract ----------

test("bob_repo_docker_run is NOT in the orchestrator role bundle (O.4 §9)", () => {
  assert.equal(
    repoDockerRunTool.role_bundles.includes("orchestrator"),
    false,
    "orchestrator must NOT execute docker; only dispatch",
  );
});

test("bob_repo_docker_run is exposed to evaluator-shared, verifier, evidence", () => {
  assert.deepEqual(repoDockerRunTool.role_bundles.slice().sort(),
    ["evaluator-shared", "evidence", "verifier"]);
});

test("bob_repo_docker_run authority class is initialized_session_mutation", () => {
  assert.equal(EXPLICIT_AUTHORITY_CLASS_BY_TOOL.bob_repo_docker_run, "initialized_session_mutation");
});

test("bob_repo_docker_run declares the right artefacts (JSONL + repo-runs/ + repo-work/)", () => {
  assert.ok(repoDockerRunTool.session_artifacts_written.includes("repo-command-runs.jsonl"));
  assert.ok(repoDockerRunTool.session_artifacts_written.includes("repo-runs/"));
  assert.ok(repoDockerRunTool.session_artifacts_written.includes("repo-work/"));
});

test("bob_repo_docker_run is mutating and declares no network/browser access", () => {
  assert.equal(repoDockerRunTool.mutating, true);
  assert.equal(repoDockerRunTool.network_access, false);
  assert.equal(repoDockerRunTool.browser_access, false);
  assert.equal(repoDockerRunTool.scope_required, false);
  assert.equal(repoDockerRunTool.sensitive_output, false);
});

test("bob_repo_docker_run tool handler returns a JSON envelope (dry-run)", async () => {
  await withTempHome(async () => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "package.json", JSON.stringify({ name: "x" }));
    const init = initRepoSession({ repo_path: repoRoot });
    const payload = JSON.parse(await repoDockerRunTool.handler({
      target_domain: init.target_domain,
      command: ["echo", "hi"],
    }));
    assert.equal(payload.version, 1);
    assert.equal(payload.created, true);
    assert.equal(payload.dry_run, true);
    assert.equal(payload.target_domain, init.target_domain);
    assert.match(payload.run_id, /^run-[0-9a-f]+-[0-9a-f]+$/);
  });
});

test("repo-command-runs.jsonl path lives under the session dir", () => {
  // Sanity-check the path helper so an accidental sessionsRoot relocation can't
  // silently move the run ledger.
  const filePath = repoCommandRunsJsonlPath("repo-x-abcdef01");
  assert.match(filePath, /repo-command-runs\.jsonl$/);
  assert.ok(filePath.includes(path.basename(sessionDir("repo-x-abcdef01"))));
});

test("REPO_DOCKER_RUN constants expose the documented defaults", () => {
  assert.equal(REPO_DOCKER_RUN_DEFAULT_TIMEOUT_MS, 300_000);
  assert.equal(REPO_DOCKER_RUN_MAX_TIMEOUT_MS, 600_000);
  assert.equal(REPO_DOCKER_RUN_MAX_OUTPUT_BYTES, 16 * 1024 * 1024);
  assert.deepEqual(REPO_MOUNT_MODE_VALUES.slice().sort(), ["read_only", "read_write"]);
});
