"use strict";

// A8R: repo host filesystem identity binding + revalidation.
//
// Coverage:
// - root/intermediate/leaf symlink swaps rejected before a byte is read.
// - hardlinked files rejected by openContainedFile's fd-fstat-match.
// - a case/Unicode-normalization-mismatched (non-symlinked) path succeeds
//   (regression guard against the raw realpath-string-inequality false
//   positive).
// - walkRepo dequeue-time revalidation rejects a directory swapped to an
//   outside symlink before it is dequeued (the common TOCTOU case), and the
//   outside subtree's filenames never surface in the inventory.
// - byte content of a swapped/outside path is refused independent of
//   whatever the enumeration layer did.
// - a repo_path override subtree gets its own pinned identity that rejects
//   a swap even after the outer session identity already validated fine.
// - loadGitignore falls back to no patterns (fail-closed) rather than
//   reading through a swapped .gitignore symlink.
// - repoDockerRun's non-checkout live-run path revalidates immediately
//   before the run spawn, not only the docker --version probe.
// - pinned-commit lowercase repo_hash===commit vs path-hash fallback
//   semantics both resolve through bindRepoHostIdentity.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  bindRepoHostIdentity,
  captureRepoHostIdentity,
  openContainedFile,
  pinOverrideIdentity,
  readContainedFile,
  resolveContainedPath,
  revalidateRepoHostIdentity,
} = require("../mcp/domains/repo/repo-host-boundary.js");
const {
  initRepoSession,
  readRepoSession,
  buildRepoInventory,
  repoCheck,
} = require("../mcp/domains/repo/repo-target.js");
const {
  prepareRepoEnv,
  repoDockerRun,
} = require("../mcp/domains/repo/repo-env.js");
const {
  repoInventoryPath,
} = require("../mcp/core/io/paths.js");

async function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-repo-host-boundary-"));
  process.env.HOME = home;
  try {
    return await fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function makeTempRepoDir(prefix = "bob-repo-host-boundary-fixture-") {
  const raw = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  return fs.realpathSync.native ? fs.realpathSync.native(raw) : fs.realpathSync(raw);
}

function write(root, rel, content = "") {
  const abs = path.join(root, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content, "utf8");
}

function errorCode(error) {
  return error && error.details && error.details.repo_error_code;
}

test("bindRepoHostIdentity captures a {realpath,dev,ino} triple and revalidateRepoHostIdentity rejects a root swap", () => withTempHome(() => {
  const repo = makeTempRepoDir();
  write(repo, "keep.txt", "keep");
  const init = initRepoSession({ repo_path: repo });
  const identity = bindRepoHostIdentity(init.target_domain);
  assert.equal(identity.realpath, repo);
  revalidateRepoHostIdentity(identity); // no throw: unswapped

  const outside = makeTempRepoDir("bob-repo-host-boundary-outside-");
  fs.rmSync(repo, { recursive: true, force: true });
  fs.symlinkSync(outside, repo);
  assert.throws(
    () => revalidateRepoHostIdentity(identity),
    (error) => errorCode(error) === "repo_host_root_identity_mismatch",
  );
}));

test("resolveContainedPath rejects a swapped intermediate directory (symlink outside root)", () => withTempHome(() => {
  const repo = makeTempRepoDir();
  write(repo, "a/b/file.txt", "inside");
  const outside = makeTempRepoDir("bob-repo-host-boundary-outside-");
  write(outside, "b/file.txt", "outside-bytes");
  const init = initRepoSession({ repo_path: repo });
  const identity = bindRepoHostIdentity(init.target_domain);

  fs.rmSync(path.join(repo, "a"), { recursive: true, force: true });
  fs.symlinkSync(outside, path.join(repo, "a"));

  assert.throws(
    () => resolveContainedPath(identity, "a/b/file.txt"),
    (error) => errorCode(error) === "repo_host_traversal_rejected",
  );
}));

test("openContainedFile rejects a leaf swapped to a symlink between resolve and open (O_NOFOLLOW)", () => withTempHome(() => {
  const repo = makeTempRepoDir();
  write(repo, "leaf.txt", "legit");
  const outsideFile = path.join(makeTempRepoDir("bob-repo-host-boundary-outside-"), "secret.txt");
  fs.writeFileSync(outsideFile, "outside-bytes", "utf8");
  const init = initRepoSession({ repo_path: repo });
  const identity = bindRepoHostIdentity(init.target_domain);
  const leafPath = path.join(repo, "leaf.txt");

  const originalOpenSync = fs.openSync;
  let sawLeak = false;
  fs.openSync = function patchedOpenSync(targetPath, ...rest) {
    if (targetPath === leafPath) {
      fs.unlinkSync(leafPath);
      fs.symlinkSync(outsideFile, leafPath);
    }
    try {
      return originalOpenSync.call(fs, targetPath, ...rest);
    } catch (error) {
      if (error && error.code === "ELOOP") throw error;
      throw error;
    }
  };
  try {
    assert.throws(
      () => {
        const fd = openContainedFile(identity, "leaf.txt");
        // If this line is ever reached the swap was followed -- prove it by
        // checking the bytes are NOT the outside content before failing loud.
        const buf = Buffer.alloc(64);
        const n = fs.readSync(fd, buf, 0, 64, 0);
        fs.closeSync(fd);
        sawLeak = buf.subarray(0, n).toString("utf8").includes("outside-bytes");
      },
      (error) => errorCode(error) === "repo_host_open_rejected",
    );
  } finally {
    fs.openSync = originalOpenSync;
  }
  assert.equal(sawLeak, false, "outside bytes must never be read through a swapped leaf");
}));

test("openContainedFile rejects a hardlinked file (nlink > 1) even with no symlink involved", () => withTempHome(() => {
  const repo = makeTempRepoDir();
  write(repo, "original.txt", "original-bytes");
  fs.linkSync(path.join(repo, "original.txt"), path.join(repo, "hardlinked.txt"));
  const init = initRepoSession({ repo_path: repo });
  const identity = bindRepoHostIdentity(init.target_domain);

  assert.throws(
    () => openContainedFile(identity, "hardlinked.txt"),
    (error) => errorCode(error) === "repo_host_hardlink_rejected",
  );
}));

test("resolveContainedPath rejects a directory passed where a file is expected (nonregular-for-read guard)", () => withTempHome(() => {
  const repo = makeTempRepoDir();
  fs.mkdirSync(path.join(repo, "adir"));
  const init = initRepoSession({ repo_path: repo });
  const identity = bindRepoHostIdentity(init.target_domain);

  assert.throws(
    () => openContainedFile(identity, "adir"),
    (error) => errorCode(error) === "repo_host_not_a_file",
  );
}));

test("a case/Unicode-normalization-mismatched non-symlinked path succeeds (no false-positive traversal rejection)", () => withTempHome(() => {
  const repo = makeTempRepoDir();
  write(repo, "README.md", "hello");
  const init = initRepoSession({ repo_path: repo });
  const identity = bindRepoHostIdentity(init.target_domain);

  const caseInsensitive = fs.existsSync(path.join(repo, "readme.md"));
  if (!caseInsensitive) {
    // This filesystem is case-sensitive (e.g. Linux ext4) -- the regression
    // this test guards against cannot manifest here. Skip rather than fail.
    return;
  }
  const resolved = resolveContainedPath(identity, "readme.md");
  assert.equal(resolved.isFile, true);
  const { buffer } = readContainedFile(identity, "readme.md");
  assert.equal(buffer.toString("utf8"), "hello");
}));

test("walkRepo dequeue-time revalidation rejects a plain directory swapped to an outside symlink before it is dequeued", () => withTempHome(() => {
  const repo = makeTempRepoDir();
  write(repo, "keep.txt", "keep");
  fs.mkdirSync(path.join(repo, "victim"));
  write(repo, "victim/secret.txt", "leak-me");
  const outside = makeTempRepoDir("bob-repo-host-boundary-outside-");
  write(outside, "outside-secret.txt", "outside-bytes");

  const init = initRepoSession({ repo_path: repo });

  const originalReaddirSync = fs.readdirSync;
  let swapped = false;
  fs.readdirSync = function patchedReaddirSync(dirPath, options) {
    const result = originalReaddirSync.call(fs, dirPath, options);
    if (!swapped && dirPath === repo) {
      // The root listing (first dequeue) fires before "victim" -- queued as
      // a plain directory entry from THIS readdir -- is ever dequeued. Swap
      // it here to land the race squarely in the dequeue-to-readdir window.
      swapped = true;
      fs.rmSync(path.join(repo, "victim"), { recursive: true, force: true });
      fs.symlinkSync(outside, path.join(repo, "victim"));
    }
    return result;
  };
  let result;
  try {
    result = buildRepoInventory({ target_domain: init.target_domain });
  } finally {
    fs.readdirSync = originalReaddirSync;
  }
  assert.ok(swapped, "test setup must actually trigger the swap");
  const doc = JSON.parse(fs.readFileSync(repoInventoryPath(init.target_domain), "utf8"));
  const serialized = JSON.stringify(doc);
  assert.doesNotMatch(serialized, /outside-secret/, "the outside subtree's filenames must never surface");
  assert.doesNotMatch(serialized, /victim\/secret\.txt/, "the swapped-away original content must not surface either");
  assert.ok(result.counts.files >= 1, "the walk must still complete and enumerate the untouched files");
}));

test("repo_path override gets its own pinned identity: a swap after the outer session identity is bound is still rejected", () => withTempHome(() => {
  const repo = makeTempRepoDir();
  fs.mkdirSync(path.join(repo, "scoped"));
  write(repo, "scoped/inside.txt", "inside-bytes");
  const outside = makeTempRepoDir("bob-repo-host-boundary-outside-");
  write(outside, "outside-secret.txt", "outside-bytes");

  const init = initRepoSession({ repo_path: repo });
  const sessionIdentity = bindRepoHostIdentity(init.target_domain);

  // Sanity: pinning succeeds while "scoped" is a real subdirectory.
  const firstPin = pinOverrideIdentity(sessionIdentity, "scoped");
  assert.equal(firstPin.realpath, path.join(repo, "scoped"));

  // Now swap it -- simulating a race that lands strictly AFTER the outer
  // session identity was already validated/bound.
  fs.rmSync(path.join(repo, "scoped"), { recursive: true, force: true });
  fs.symlinkSync(outside, path.join(repo, "scoped"));

  assert.throws(
    () => pinOverrideIdentity(sessionIdentity, "scoped"),
    (error) => errorCode(error) === "repo_host_traversal_rejected",
  );

  // End-to-end: buildRepoInventory with the swapped override must refuse
  // too, and no outside content may land in the persisted inventory.
  assert.throws(
    () => buildRepoInventory({ target_domain: init.target_domain, repo_path: path.join(repo, "scoped") }),
  );
  if (fs.existsSync(repoInventoryPath(init.target_domain))) {
    const raw = fs.readFileSync(repoInventoryPath(init.target_domain), "utf8");
    assert.doesNotMatch(raw, /outside-secret/);
  }
}));

test("a swapped .gitignore symlink is rejected: buildRepoInventory falls back to no ignore patterns rather than reading through it", () => withTempHome(() => {
  const repo = makeTempRepoDir();
  write(repo, "keep.txt", "keep");
  const outside = makeTempRepoDir("bob-repo-host-boundary-outside-");
  // A malicious ignore-everything pattern: if this were read through the
  // symlink, "keep.txt" would silently disappear from the inventory.
  fs.writeFileSync(path.join(outside, ".gitignore-payload"), "*\n", "utf8");
  const init = initRepoSession({ repo_path: repo });
  fs.symlinkSync(path.join(outside, ".gitignore-payload"), path.join(repo, ".gitignore"));

  const result = buildRepoInventory({ target_domain: init.target_domain });
  assert.ok(result.counts.files >= 1, "keep.txt must still be enumerated -- the malicious ignore-all pattern must never be applied");
}));

test("repoCheck rejects a file_path swapped to a symlink pointing outside the repo root", () => withTempHome(() => {
  const repo = makeTempRepoDir();
  write(repo, "target.txt", "inside-bytes");
  const outside = makeTempRepoDir("bob-repo-host-boundary-outside-");
  write(outside, "secret.txt", "outside-bytes");
  const init = initRepoSession({ repo_path: repo });

  fs.unlinkSync(path.join(repo, "target.txt"));
  fs.symlinkSync(path.join(outside, "secret.txt"), path.join(repo, "target.txt"));

  assert.throws(
    () => repoCheck({ target_domain: init.target_domain, check_type: "file_exists", file_path: "target.txt" }),
    (error) => {
      const code = errorCode(error);
      return code === "file_stat_failed" || code === "file_path_not_a_file";
    },
  );
}));

test("bindRepoHostIdentity resolves pinned-commit lowercase repo_hash===commit vs path-hash fallback semantics", () => withTempHome(() => {
  const pathHashRepo = makeTempRepoDir();
  write(pathHashRepo, "keep.txt", "keep");
  const pathHashInit = initRepoSession({ repo_path: pathHashRepo });
  const pathHashSession = readRepoSession(pathHashInit.target_domain);
  const pathHashIdentity = bindRepoHostIdentity(pathHashInit.target_domain);
  assert.equal(pathHashIdentity.repo_hash, pathHashSession.repo_hash);
  assert.equal(pathHashIdentity.commit, null);

  const commitRepo = makeTempRepoDir();
  write(commitRepo, "keep.txt", "keep");
  const commitValue = "ABCDEF1234567890ABCDEF1234567890ABCDEF";
  const commitInit = initRepoSession({ repo_path: commitRepo, commit: commitValue });
  const commitIdentity = bindRepoHostIdentity(commitInit.target_domain);
  assert.equal(commitIdentity.commit, commitValue.toLowerCase());
  assert.equal(commitIdentity.repo_hash, commitValue.toLowerCase());
}));

test("prepareRepoEnv binds and revalidates a repo host identity without changing dry-run output", () => withTempHome(async () => {
  const repo = makeTempRepoDir();
  write(repo, "package.json", JSON.stringify({ name: "fixture" }));
  const init = initRepoSession({ repo_path: repo });
  const result = await prepareRepoEnv({ target_domain: init.target_domain, dry_run: true });
  assert.equal(result.dry_run, true);
  assert.equal(result.repo_path, repo);
}));

test("repoDockerRun non-checkout live-run path revalidates immediately before the run spawn, not only the docker --version probe", () => withTempHome(async () => {
  const repo = makeTempRepoDir();
  write(repo, "keep.txt", "keep");
  const init = initRepoSession({ repo_path: repo });
  const outside = makeTempRepoDir("bob-repo-host-boundary-outside-");

  let runInvoked = false;
  const runtime = {
    // The docker --version probe fires first; swap the repo root here so
    // the swap lands strictly BEFORE the run-spawn revalidation, not just
    // before the probe -- proving the fix isn't gated on the probe alone.
    execFile: async () => {
      fs.rmSync(repo, { recursive: true, force: true });
      fs.symlinkSync(outside, repo);
      return { stdout: "Docker version 25.0", stderr: "" };
    },
    run: async () => {
      runInvoked = true;
      throw new Error("must not run against a swapped repo root");
    },
  };

  await assert.rejects(
    () => repoDockerRun({
      target_domain: init.target_domain,
      command: ["true"],
      dry_run: false,
      runtime,
    }),
    (error) => errorCode(error) === "repo_host_root_identity_mismatch",
  );
  assert.equal(runInvoked, false, "the docker run spawn must never fire against a swapped root");
}));

test("captureRepoHostIdentity refuses a symlink root", () => withTempHome(() => {
  const repo = makeTempRepoDir();
  const outside = makeTempRepoDir("bob-repo-host-boundary-outside-");
  const linkPath = path.join(repo, "link");
  fs.symlinkSync(outside, linkPath);
  assert.throws(
    () => captureRepoHostIdentity(linkPath),
    (error) => errorCode(error) === "repo_host_root_is_symlink",
  );
}));
