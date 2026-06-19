"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  buildDockerRunArgv,
  REPO_MOUNT_MODE_VALUES,
} = require("../mcp/lib/repo-env.js");
const {
  assertRepoRootPath,
} = require("../mcp/lib/governance-contracts.js");
const initRepoSessionTool = require("../mcp/lib/tools/init-repo-session.js");
const repoPrepareEnvTool = require("../mcp/lib/tools/repo-prepare-env.js");
const repoDockerRunTool = require("../mcp/lib/tools/repo-docker-run.js");

function valueAfterFlag(args, flag) {
  const index = args.indexOf(flag);
  return index >= 0 ? args[index + 1] : undefined;
}

function volumeMounts(args) {
  return args
    .map((value, index) => ({ value, index }))
    .filter((entry) => entry.value === "-v")
    .map((entry) => args[entry.index + 1]);
}

test("S15 pins the OSS-container substrate invariants", () => {
  assert.equal(initRepoSessionTool.name, "bob_init_repo_session");
  assert.equal(repoPrepareEnvTool.name, "bob_repo_prepare_env");
  assert.equal(repoDockerRunTool.name, "bob_repo_docker_run");

  assert.equal(initRepoSessionTool.network_access, false);
  assert.equal(repoPrepareEnvTool.network_access, false);
  assert.equal(repoDockerRunTool.network_access, false);

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "bob-s15-root-"));
  try {
    assert.throws(
      () => assertRepoRootPath(path.join(tmp, "missing-repo")),
      (error) => error && error.code === "repo_path_not_found",
    );
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }

  const argv = buildDockerRunArgv({
    repoRoot: "/s15/repo",
    workDir: "/s15/work",
    imageTag: "bob-oss-s15:fixture",
    command: ["true"],
    allowNetwork: false,
    repoMountMode: "read_only",
    egressProfile: null,
  });
  assert.equal(argv.command, "docker");
  assert.equal(valueAfterFlag(argv.args, "--network"), "none");

  const mounts = volumeMounts(argv.args);
  assert.ok(mounts.includes("/s15/repo:/src:ro"), `mounts=${mounts.join(", ")}`);
  assert.ok(mounts.includes("/s15/work:/work:rw"), `mounts=${mounts.join(", ")}`);

  assert.deepEqual([...REPO_MOUNT_MODE_VALUES], ["read_only", "read_write"]);

  assert.deepEqual(initRepoSessionTool.role_bundles, ["orchestrator"]);
  assert.deepEqual(repoPrepareEnvTool.role_bundles, ["orchestrator"]);
  assert.equal(repoDockerRunTool.role_bundles.includes("orchestrator"), false);
  assert.deepEqual(repoDockerRunTool.role_bundles, ["evaluator-shared", "verifier", "evidence"]);
});
