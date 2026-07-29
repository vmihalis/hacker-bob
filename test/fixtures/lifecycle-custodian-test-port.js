"use strict";

const fs = require("node:fs");
const crypto = require("node:crypto");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const {
  encodeLifecycleCustodianRequest,
  normalizeLifecycleCustodianMutation,
  parseLifecycleCustodianResult,
} = require("../../scripts/lib/lifecycle-custodian-contract.js");

const ROOT = path.resolve(__dirname, "..", "..");
const WRAPPER_PATH = require.resolve("../../scripts/lib/lifecycle-custodian.js");
const TEST_BINARY = path.join(
  ROOT,
  "packages",
  "bob-lifecycle-custodian-native-darwin",
  "dist",
  "lifecycle-custodian-test",
);
const TEST_ARGUMENT = "--test-only-lifecycle-custodian-v1";
const PHASES = Object.freeze({
  building: 1,
  prepared: 2,
  backup_renamed: 3,
  installed: 4,
  committed: 5,
  after_staging_create: 6,
  after_backup_rename: 7,
  after_install_rename: 8,
  after_recovery: 9,
});

function fixtureError(reasonCode, detail = null) {
  const error = new Error(detail == null
    ? "Lifecycle custodian test fixture was rejected"
    : `Lifecycle custodian test fixture was rejected: ${detail}`);
  error.code = "lifecycle_custodian_test_fixture_rejected";
  error.reason_code = reasonCode;
  if (detail != null) error.detail = detail;
  return error;
}

function writePreparedFile(root, file) {
  const destination = path.join(root, ...file.path.split("/"));
  fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o755 });
  fs.chmodSync(path.dirname(destination), 0o755);
  const descriptor = fs.openSync(
    destination,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL
      | (fs.constants.O_NOFOLLOW || 0),
    file.mode,
  );
  try {
    fs.writeFileSync(descriptor, file.contents);
    fs.fchmodSync(descriptor, file.mode);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function syncDirectory(directory) {
  const descriptor = fs.openSync(
    directory,
    fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0)
      | (fs.constants.O_NOFOLLOW || 0),
  );
  try {
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function prepareSource(normalized, root) {
  fs.chmodSync(root, 0o755);
  for (const file of normalized.files) writePreparedFile(root, file);
  const directories = new Set([root]);
  for (const file of normalized.files) {
    let current = path.dirname(path.join(root, ...file.path.split("/")));
    while (current.startsWith(`${root}${path.sep}`)) {
      directories.add(current);
      current = path.dirname(current);
    }
  }
  for (const directory of [...directories].sort((left, right) => right.length - left.length)) {
    fs.chmodSync(directory, 0o755);
    syncDirectory(directory);
  }
}

function openDirectory(directory) {
  return fs.openSync(
    directory,
    fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0)
      | (fs.constants.O_NOFOLLOW || 0),
  );
}

function sameFilesystemIdentity(left, right) {
  return left != null && right != null && left.dev === right.dev && left.ino === right.ino;
}

function openStableTargetDirectory(directory) {
  let descriptor;
  try {
    const before = fs.lstatSync(directory);
    if (!before.isDirectory() || before.isSymbolicLink()) {
      throw fixtureError("target_authority_rejected");
    }
    descriptor = openDirectory(directory);
    const opened = fs.fstatSync(descriptor);
    const after = fs.lstatSync(directory);
    if (!opened.isDirectory() || !after.isDirectory() || after.isSymbolicLink()
        || !sameFilesystemIdentity(before, opened)
        || !sameFilesystemIdentity(opened, after)) {
      throw fixtureError("target_authority_rejected");
    }
    const retained = Object.freeze({
      descriptor,
      target_abs: path.resolve(directory),
      dev: opened.dev,
      ino: opened.ino,
    });
    descriptor = undefined;
    return retained;
  } catch (error) {
    if (error && error.code === "lifecycle_custodian_test_fixture_rejected") throw error;
    throw fixtureError("target_authority_rejected");
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

// The double drives a Darwin/arm64-only native fixture. Hosts that cannot run
// it are reported here rather than discovered as a raw ENOENT partway through
// enrollment. Deliberately keyed on platform/arch ALONE and not on whether the
// binary is present: on a supported host a missing fixture must stay a loud,
// actionable failure ("run npm run build:test"), never a silent downgrade to
// the unavailable-custodian path that would make the double's tests vacuous.
function lifecycleCustodianTestDoubleSupported() {
  return process.platform === "darwin" && process.arch === "arm64";
}

function readTestBinaryIdentity() {
  let atPath;
  try {
    atPath = fs.lstatSync(TEST_BINARY);
  } catch {
    throw fixtureError("test_binary_unavailable", TEST_BINARY);
  }
  if (!atPath.isFile() || atPath.isSymbolicLink() || atPath.nlink !== 1
      || (atPath.mode & 0o777) !== 0o755) throw fixtureError("test_binary_unavailable");
  const descriptor = fs.openSync(
    TEST_BINARY,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
  );
  try {
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== atPath.dev
        || opened.ino !== atPath.ino || opened.size !== atPath.size
        || (opened.mode & 0o777) !== 0o755) throw fixtureError("test_binary_unavailable");
    return Object.freeze({
      dev: opened.dev,
      ino: opened.ino,
      size: opened.size,
      sha256: crypto.createHash("sha256").update(fs.readFileSync(descriptor)).digest("hex"),
    });
  } finally {
    fs.closeSync(descriptor);
  }
}

function installLifecycleCustodianTestDouble() {
  const enrolledBinary = readTestBinaryIdentity();
  const targetAuthorities = new WeakMap();
  const assertTestBinaryAvailable = () => {
    const current = readTestBinaryIdentity();
    if (current.dev !== enrolledBinary.dev || current.ino !== enrolledBinary.ino
        || current.size !== enrolledBinary.size || current.sha256 !== enrolledBinary.sha256) {
      throw fixtureError("test_binary_unavailable");
    }
    return Object.freeze({ available: true, test_only: true });
  };
  const state = {
    crashPhase: 0,
    beforeNative: null,
    resultDescriptor: null,
    targetOpenCount: 0,
  };
  const controller = Object.freeze({
    crashNextAt(phase) {
      const value = typeof phase === "string" ? PHASES[phase] : phase;
      if (!Number.isInteger(value) || value < 1 || value > 9) {
        throw fixtureError("crash_phase_invalid");
      }
      state.crashPhase = value;
    },
    beforeNextNative(callback) {
      if (typeof callback !== "function") throw fixtureError("native_hook_invalid");
      state.beforeNative = callback;
    },
    useNextResultDescriptor(descriptor) {
      if (!Number.isInteger(descriptor) || descriptor < 0 || state.resultDescriptor != null) {
        throw fixtureError("result_descriptor_invalid");
      }
      state.resultDescriptor = descriptor;
    },
    targetOpenCount() {
      return state.targetOpenCount;
    },
    test_binary: TEST_BINARY,
  });

  const authorityRecord = (authority) => {
    const record = authority != null && typeof authority === "object"
      ? targetAuthorities.get(authority)
      : null;
    if (!record || record.active !== true) throw fixtureError("target_authority_rejected");
    return record;
  };

  const withLifecycleCustodianTarget = (targetAbs, callback) => {
    if (process.platform !== "darwin" || process.arch !== "arm64") {
      throw fixtureError("test_host_unsupported");
    }
    assertTestBinaryAvailable();
    if (typeof targetAbs !== "string" || targetAbs.length === 0 || typeof callback !== "function") {
      throw fixtureError("target_authority_rejected");
    }
    const retained = openStableTargetDirectory(path.resolve(targetAbs));
    state.targetOpenCount += 1;
    const authority = Object.freeze(Object.create(null));
    const record = {
      active: true,
      descriptor: retained.descriptor,
      target_abs: retained.target_abs,
      dev: retained.dev,
      ino: retained.ino,
    };
    targetAuthorities.set(authority, record);
    try {
      return callback(authority);
    } finally {
      record.active = false;
      targetAuthorities.delete(authority);
      try { fs.closeSync(record.descriptor); } catch { /* best-effort authority cleanup */ }
    }
  };

  const lifecycleCustodianTargetSnapshot = (authority) => {
    const record = authorityRecord(authority);
    return Object.freeze({
      target_abs: record.target_abs,
      dev: record.dev,
      ino: record.ino,
    });
  };

  const executeLifecycleMutation = (authority, input) => {
    const normalized = normalizeLifecycleCustodianMutation(input);
    const targetAuthority = authorityRecord(authority);
    if (process.platform !== "darwin" || process.arch !== "arm64") {
      throw fixtureError("test_host_unsupported");
    }
    assertTestBinaryAvailable();
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hb-lifecycle-custodian-"));
    const sourceRoot = path.join(temporaryRoot, "prepared-source");
    const requestPath = path.join(temporaryRoot, "request.bin");
    fs.mkdirSync(sourceRoot, { mode: 0o755 });
    let sourceFd;
    let requestFd;
    try {
      prepareSource(normalized, sourceRoot);
      const request = encodeLifecycleCustodianRequest(normalized);
      if (state.crashPhase !== 0) request.writeUInt32BE(state.crashPhase, 24);
      fs.writeFileSync(requestPath, request, { flag: "wx", mode: 0o444 });
      fs.chmodSync(requestPath, 0o444);
      syncDirectory(temporaryRoot);
      sourceFd = openDirectory(sourceRoot);
      requestFd = fs.openSync(
        requestPath,
        fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
      );
      const beforeNative = state.beforeNative;
      state.beforeNative = null;
      if (beforeNative) {
        beforeNative(Object.freeze({
          request_path: requestPath,
          source_root: sourceRoot,
          target_abs: targetAuthority.target_abs,
        }));
      }
      const resultDescriptor = state.resultDescriptor;
      state.resultDescriptor = null;
      const child = spawnSync(TEST_BINARY, [TEST_ARGUMENT], {
        env: Object.freeze({ PATH: "/usr/bin:/bin" }),
        stdio: [
          "ignore",
          "ignore",
          "pipe",
          targetAuthority.descriptor,
          sourceFd,
          requestFd,
          resultDescriptor == null ? "pipe" : resultDescriptor,
        ],
        timeout: 30_000,
      });
      const crashPhase = state.crashPhase;
      state.crashPhase = 0;
      if (child.error) throw fixtureError("native_spawn_failed", child.error.message);
      if (crashPhase !== 0 && child.status === 90 + crashPhase) {
        throw fixtureError("injected_native_crash", String(crashPhase));
      }
      if (resultDescriptor != null) {
        throw fixtureError(
          child.status === 0
            ? "invalid_result_descriptor_accepted"
            : "native_mutation_rejected",
          `exit=${child.status}; stderr=${child.stderr.toString("utf8")}`,
        );
      }
      const result = parseLifecycleCustodianResult(child.output[6]);
      if (child.status !== 0 || result.status === "rejected") {
        throw fixtureError(
          "native_mutation_rejected",
          `exit=${child.status}; result=${result.status}; stderr=${child.stderr.toString("utf8")}`,
        );
      }
      return Object.freeze({
        changed: result.status === "changed",
        status: result.status,
        production_ready: false,
        mutation_authorized: true,
        test_only: true,
      });
    } finally {
      state.crashPhase = 0;
      state.resultDescriptor = null;
      for (const descriptor of [requestFd, sourceFd]) {
        if (descriptor !== undefined) {
          try { fs.closeSync(descriptor); } catch { /* best-effort fixture cleanup */ }
        }
      }
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  };

  require.cache[WRAPPER_PATH] = {
    id: WRAPPER_PATH,
    filename: WRAPPER_PATH,
    loaded: true,
    exports: Object.freeze({
      assertLifecycleCustodianAvailable() {
        return assertTestBinaryAvailable();
      },
      executeLifecycleMutation,
      lifecycleCustodianTargetSnapshot,
      lifecycleCustodianStatus() {
        return Object.freeze({
          available: true,
          qualified: false,
          mutation_authorized: true,
          production_ready: false,
          blocker: null,
          test_only: true,
        });
      },
      withLifecycleCustodianTarget,
    }),
    children: [],
    paths: [],
  };
  return controller;
}

module.exports = {
  installLifecycleCustodianTestDouble,
  lifecycleCustodianTestDoubleSupported,
};
