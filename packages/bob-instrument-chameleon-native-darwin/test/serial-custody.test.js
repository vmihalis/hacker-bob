"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const readline = require("node:readline");
const { spawn, spawnSync } = require("node:child_process");
const { once } = require("node:events");

const MODULE_PATH = path.join(__dirname, "..", "lib", "serial-custody.js");
const BINDING_PATH = path.join(
  __dirname,
  "..",
  "build",
  "Release",
  "serial_custody.node",
);
const DIGEST = "a".repeat(64);

process.env.BOB_CHAMELEON_DARWIN_PTY_FIXTURE = "1";

function nonce() {
  return crypto.randomBytes(16).toString("base64url");
}

function lrc(bytes) {
  let sum = 0;
  for (const byte of bytes) sum = (sum + byte) & 0xff;
  return (-sum) & 0xff;
}

function frame(command, data = Buffer.alloc(0), status = 0) {
  const output = Buffer.alloc(10 + data.length);
  output[0] = 0x11;
  output[1] = 0xef;
  output.writeUInt16BE(command, 2);
  output.writeUInt16BE(status, 4);
  output.writeUInt16BE(data.length, 6);
  output[8] = lrc(output.subarray(2, 8));
  data.copy(output, 9);
  output[output.length - 1] = lrc(data);
  return output;
}

function statProjection(value, device = false) {
  const output = {
    ctime_ns: value.ctimeNs.toString(),
    dev: value.dev.toString(),
    gid: value.gid.toString(),
    ino: value.ino.toString(),
    mode: value.mode.toString(),
    nlink: value.nlink.toString(),
    uid: value.uid.toString(),
  };
  if (device) output.rdev = value.rdev.toString();
  return output;
}

function fixtureInput(devicePath) {
  const api = require(MODULE_PATH);
  const directoryPath = path.dirname(devicePath);
  const aclProfileBytes = Buffer.alloc(0);
  const aclProfileDigest = api.deriveDarwinSerialAclProfileDigest({
    state: "absent",
    bytes: aclProfileBytes,
  });
  const workerIdentityDigest = api.deriveDarwinSerialWorkerIdentityDigest({
    worker_uid: process.getuid(),
    worker_gid: process.getgid(),
    acl_profile_digest: aclProfileDigest,
  });
  return {
    version: 1,
    custody_id: "darwin_pty_custody",
    enrollment_id: "operator_enrolled_chameleon",
    operator_device_identity_digest: crypto.createHash("sha256")
      .update("operator-enrolled-private-identity", "utf8")
      .digest("hex"),
    directory_path: directoryPath,
    device_name: path.basename(devicePath),
    expected_directory: statProjection(fs.lstatSync(directoryPath, { bigint: true })),
    expected_device: statProjection(fs.lstatSync(devicePath, { bigint: true }), true),
    worker_uid: process.getuid(),
    worker_gid: process.getgid(),
    worker_identity_digest: workerIdentityDigest,
    acl_profile_state: "absent",
    acl_profile_bytes: aclProfileBytes,
    acl_profile_digest: aclProfileDigest,
  };
}

function nativeConfigFromInput(input, generation = 1) {
  return {
    version: 1,
    fixture_only: true,
    directory_path: input.directory_path,
    final_component: input.device_name,
    expected_directory: input.expected_directory,
    expected_device: input.expected_device,
    directory_stat_digest: DIGEST,
    device_stat_digest: DIGEST,
    operator_device_identity_digest: input.operator_device_identity_digest,
    worker_uid: input.worker_uid,
    worker_gid: input.worker_gid,
    worker_identity_digest: input.worker_identity_digest,
    acl_profile_state: input.acl_profile_state,
    acl_profile_bytes: Buffer.from(input.acl_profile_bytes),
    acl_profile_digest: input.acl_profile_digest,
    connection_generation: generation,
  };
}

async function ptyFixture(t) {
  const source = String.raw`
import errno, os, pty, sys, time
master, slave = pty.openpty()
print(os.ttyname(slave), flush=True)
os.close(slave)
pending = b""

def checksum(value):
    return (-sum(value)) & 0xff

def response(command, payload=b""):
    header = command.to_bytes(2, "big") + (0).to_bytes(2, "big") + len(payload).to_bytes(2, "big")
    return bytes([0x11, 0xef]) + header + bytes([checksum(header)]) + payload + bytes([checksum(payload)])

while True:
    try:
        chunk = os.read(master, 4096)
    except OSError as error:
        if error.errno == errno.EIO:
            time.sleep(0.01)
            continue
        break
    if not chunk:
        time.sleep(0.01)
        continue
    pending += chunk
    while len(pending) >= 9:
        expected = int.from_bytes(pending[6:8], "big") + 10
        if len(pending) < expected:
            break
        request, pending = pending[:expected], pending[expected:]
        command = int.from_bytes(request[2:4], "big")
        encoded = response(command, b"fixture")
        if command == 1033:
            continue
        if command == 1035:
            os.write(master, encoded + encoded)
            continue
        if command == 1017:
            os.write(master, encoded[:3])
            time.sleep(0.01)
            os.write(master, encoded[3:])
            continue
        os.write(master, encoded)
`;
  const child = spawn("/usr/bin/python3", ["-u", "-c", source], {
    stdio: ["ignore", "pipe", "ignore"],
  });
  const lines = readline.createInterface({ input: child.stdout });
  const [devicePath] = await once(lines, "line");
  if (typeof devicePath !== "string" || !devicePath.startsWith("/dev/ttys")) {
    child.kill("SIGKILL");
    throw new Error("Darwin pseudo-terminal fixture did not yield an exact slave path");
  }
  t.after(async () => {
    lines.close();
    child.kill("SIGKILL");
    await Promise.race([
      once(child, "exit"),
      new Promise((resolve) => setTimeout(resolve, 1000)),
    ]);
  });
  return devicePath;
}

function openFixture(api, input, generation = 1) {
  const port = api.createDarwinSerialPtyFixtureCustodyPort({ ...input });
  const grant = api.createDarwinSerialOpenGeneration(port, {
    version: 1,
    connection_generation: generation,
    open_nonce: nonce(),
  });
  const handle = api.openDarwinSerialGeneration(port, grant);
  return { port, grant, handle };
}

function assertSafeError(error, code = "darwin_native_serial_custody_rejected") {
  assert.equal(error?.code, code);
  assert.equal(error?.message, "Darwin native serial custody was rejected");
  assert.equal(Object.hasOwn(error, "path"), false);
  assert.equal(Object.hasOwn(error, "fd"), false);
  return true;
}

test("import is inert and exposes the fail-closed DTR-history assurance", () => {
  const originalDlopen = process.dlopen;
  const originalReaddir = fs.readdirSync;
  let nativeLoads = 0;
  let enumerations = 0;
  process.dlopen = () => {
    nativeLoads += 1;
    throw new Error("native code loaded during import");
  };
  fs.readdirSync = () => {
    enumerations += 1;
    throw new Error("device enumeration during import");
  };
  try {
    delete require.cache[require.resolve(MODULE_PATH)];
    const api = require(MODULE_PATH);
    assert.equal(nativeLoads, 0);
    assert.equal(enumerations, 0);
    assert.equal(api.DARWIN_SERIAL_CUSTODY_ASSURANCE.production_ready, false);
    assert.equal(api.DARWIN_SERIAL_CUSTODY_ASSURANCE.real_device_open_enabled, false);
    assert.equal(api.DARWIN_SERIAL_CUSTODY_ASSURANCE.device_enumeration_exposed, false);
    assert.equal(
      api.DARWIN_SERIAL_PREOPEN_DTR_BLOCKER,
      "darwin_tty_preopen_dtr_history_unprovable",
    );
  } finally {
    process.dlopen = originalDlopen;
    fs.readdirSync = originalReaddir;
    // The import captured a deliberately replaced process primitive. Do not
    // reuse that fail-closed module instance after restoring the host.
    delete require.cache[require.resolve(MODULE_PATH)];
  }
});

test("construction is inert and a real-device port refuses before native load/open", async (t) => {
  const api = require(MODULE_PATH);
  const devicePath = await ptyFixture(t);
  const input = fixtureInput(devicePath);
  let nativeLoads = 0;
  let filesystemOpens = 0;
  const originalDlopen = process.dlopen;
  const originalOpen = fs.openSync;
  process.dlopen = () => {
    nativeLoads += 1;
    throw new Error("real port tried to load native code");
  };
  fs.openSync = () => {
    filesystemOpens += 1;
    throw new Error("real port tried to open a path");
  };
  try {
    const port = api.createDarwinSerialCustodyPort({ ...input });
    assert.equal(api.assertDarwinSerialCustodyPort(port), port);
    assert.equal(nativeLoads, 0);
    assert.equal(filesystemOpens, 0);
    const grant = api.createDarwinSerialOpenGeneration(port, {
      version: 1,
      connection_generation: 1,
      open_nonce: nonce(),
    });
    assert.throws(
      () => api.openDarwinSerialGeneration(port, grant),
      (error) => assertSafeError(error, api.DARWIN_SERIAL_PREOPEN_DTR_BLOCKER),
    );
    assert.equal(nativeLoads, 0);
    assert.equal(filesystemOpens, 0);
    assert.throws(
      () => api.openDarwinSerialGeneration(port, grant),
      assertSafeError,
      "a consumed open generation cannot be replayed",
    );
    assert.throws(
      () => api.createDarwinSerialOpenGeneration(port, {
        version: 1,
        connection_generation: 2,
        open_nonce: nonce(),
      }),
      assertSafeError,
      "a refused real-device open must terminally destroy its port",
    );
  } finally {
    process.dlopen = originalDlopen;
    fs.openSync = originalOpen;
  }
});

test("regular, TCP-shaped, traversal, and symlink candidates are rejected without discovery", async (t) => {
  const api = require(MODULE_PATH);
  const devicePath = await ptyFixture(t);
  const input = fixtureInput(devicePath);
  const socket = new net.Socket();
  t.after(() => socket.destroy());
  assert.throws(
    () => api.createDarwinSerialPtyFixtureCustodyPort({
      ...input,
      device_name: socket,
    }),
    assertSafeError,
  );
  assert.throws(
    () => api.createDarwinSerialPtyFixtureCustodyPort({
      ...input,
      device_name: "../ttys000",
    }),
    assertSafeError,
  );

  // Seed the only legitimate native load through the measured wrapper. A raw
  // require is accepted only after the wrapper has branded and frozen its
  // exact cache record.
  const seeded = openFixture(api, input);
  api.closeDarwinSerialGeneration(seeded.handle);
  const binding = require(BINDING_PATH);
  assert.throws(
    () => binding.openExact({
      ...nativeConfigFromInput(input),
      fixture_only: false,
      directory_path: "/this-path-must-never-be-opened",
      final_component: "not-a-device",
    }),
    (error) => error?.code === "darwin_tty_preopen_dtr_history_unprovable",
    "the raw native boundary must refuse real-device mode before path parsing/open",
  );
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "bob-darwin-serial-"));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const regularPath = path.join(temporary, "ttys-regular");
  fs.writeFileSync(regularPath, "not a tty", { mode: 0o600 });
  const regularInput = {
    ...input,
    directory_path: temporary,
    device_name: path.basename(regularPath),
    expected_directory: statProjection(fs.lstatSync(temporary, { bigint: true })),
    expected_device: statProjection(fs.lstatSync(regularPath, { bigint: true }), true),
  };
  assert.throws(
    () => binding.openExact(nativeConfigFromInput(regularInput)),
    (error) => error?.code === "darwin_native_serial_open_rejected",
  );

  const symlinkPath = path.join(temporary, "ttys-link");
  fs.symlinkSync(devicePath, symlinkPath);
  const symlinkInput = {
    ...input,
    directory_path: temporary,
    device_name: path.basename(symlinkPath),
    expected_directory: statProjection(fs.lstatSync(temporary, { bigint: true })),
  };
  assert.throws(
    () => binding.openExact(nativeConfigFromInput(symlinkInput)),
    (error) => error?.code === "darwin_native_serial_open_rejected",
  );
});

test("an unbranded require-cache Module with bound JavaScript functions is rejected", async (t) => {
  const devicePath = await ptyFixture(t);
  const source = String.raw`
const crypto = require("node:crypto");
const fs = require("node:fs");
const Module = require("node:module");
const path = require("node:path");
const [modulePath, bindingPath, devicePath] = process.argv.slice(1);
const api = require(modulePath);

function project(value, device = false) {
  const output = {
    ctime_ns: value.ctimeNs.toString(),
    dev: value.dev.toString(),
    gid: value.gid.toString(),
    ino: value.ino.toString(),
    mode: value.mode.toString(),
    nlink: value.nlink.toString(),
    uid: value.uid.toString(),
  };
  if (device) output.rdev = value.rdev.toString();
  return output;
}

const directoryPath = path.dirname(devicePath);
const aclProfileBytes = Buffer.alloc(0);
const aclProfileDigest = api.deriveDarwinSerialAclProfileDigest({
  state: "absent",
  bytes: aclProfileBytes,
});
const workerIdentityDigest = api.deriveDarwinSerialWorkerIdentityDigest({
  worker_uid: process.getuid(),
  worker_gid: process.getgid(),
  acl_profile_digest: aclProfileDigest,
});
const port = api.createDarwinSerialPtyFixtureCustodyPort({
  version: 1,
  custody_id: "darwin_cache_forgery",
  enrollment_id: "operator_enrolled_chameleon",
  operator_device_identity_digest: "a".repeat(64),
  directory_path: directoryPath,
  device_name: path.basename(devicePath),
  expected_directory: project(fs.lstatSync(directoryPath, { bigint: true })),
  expected_device: project(fs.lstatSync(devicePath, { bigint: true }), true),
  worker_uid: process.getuid(),
  worker_gid: process.getgid(),
  worker_identity_digest: workerIdentityDigest,
  acl_profile_state: "absent",
  acl_profile_bytes: aclProfileBytes,
  acl_profile_digest: aclProfileDigest,
});
const grant = api.createDarwinSerialOpenGeneration(port, {
  version: 1,
  connection_generation: 1,
  open_nonce: crypto.randomBytes(16).toString("base64url"),
});

let forgedCalls = 0;
function forgedNativeBoundary() {
  forgedCalls += 1;
  throw new Error("forged native boundary was invoked");
}
const bound = forgedNativeBoundary.bind(null);
const resolved = require.resolve(bindingPath);
const forgedModule = new Module(resolved);
forgedModule.filename = resolved;
forgedModule.loaded = true;
forgedModule.exports = {
  openExact: bound,
  transactExact: bound,
  abortExact: bound,
  closeExact: bound,
};
require.cache[resolved] = forgedModule;

let openError;
try {
  api.openDarwinSerialGeneration(port, grant);
} catch (error) {
  openError = error;
}
if (openError?.code !== "darwin_native_serial_binding_rejected"
    || openError?.message !== "Darwin native serial custody was rejected"
    || forgedCalls !== 0) {
  throw new Error("forged cached binding was not rejected before invocation");
}
let remintError;
try {
  api.createDarwinSerialOpenGeneration(port, {
    version: 1,
    connection_generation: 2,
    open_nonce: crypto.randomBytes(16).toString("base64url"),
  });
} catch (error) {
  remintError = error;
}
if (remintError?.code !== "darwin_native_serial_custody_rejected") {
  throw new Error("failed open did not terminally destroy the port");
}
`;
  const result = spawnSync(
    process.execPath,
    ["-e", source, MODULE_PATH, BINDING_PATH, devicePath],
    {
      encoding: "utf8",
      env: { ...process.env, BOB_CHAMELEON_DARWIN_PTY_FIXTURE: "1" },
      timeout: 5000,
    },
  );
  assert.equal(result.status, 0, result.stderr || result.stdout || result.error?.message);
});

test("a forged .node extension hook cannot supply native custody functions", async (t) => {
  const devicePath = await ptyFixture(t);
  const source = String.raw`
const crypto = require("node:crypto");
const fs = require("node:fs");
const Module = require("node:module");
const path = require("node:path");
const [modulePath, bindingPath, devicePath] = process.argv.slice(1);
const api = require(modulePath);

function project(value, device = false) {
  const output = {
    ctime_ns: value.ctimeNs.toString(),
    dev: value.dev.toString(),
    gid: value.gid.toString(),
    ino: value.ino.toString(),
    mode: value.mode.toString(),
    nlink: value.nlink.toString(),
    uid: value.uid.toString(),
  };
  if (device) output.rdev = value.rdev.toString();
  return output;
}

const directoryPath = path.dirname(devicePath);
const aclProfileBytes = Buffer.alloc(0);
const aclProfileDigest = api.deriveDarwinSerialAclProfileDigest({
  state: "absent",
  bytes: aclProfileBytes,
});
const workerIdentityDigest = api.deriveDarwinSerialWorkerIdentityDigest({
  worker_uid: process.getuid(),
  worker_gid: process.getgid(),
  acl_profile_digest: aclProfileDigest,
});
const port = api.createDarwinSerialPtyFixtureCustodyPort({
  version: 1,
  custody_id: "darwin_extension_hook_forgery",
  enrollment_id: "operator_enrolled_chameleon",
  operator_device_identity_digest: "a".repeat(64),
  directory_path: directoryPath,
  device_name: path.basename(devicePath),
  expected_directory: project(fs.lstatSync(directoryPath, { bigint: true })),
  expected_device: project(fs.lstatSync(devicePath, { bigint: true }), true),
  worker_uid: process.getuid(),
  worker_gid: process.getgid(),
  worker_identity_digest: workerIdentityDigest,
  acl_profile_state: "absent",
  acl_profile_bytes: aclProfileBytes,
  acl_profile_digest: aclProfileDigest,
});
const grant = api.createDarwinSerialOpenGeneration(port, {
  version: 1,
  connection_generation: 1,
  open_nonce: crypto.randomBytes(16).toString("base64url"),
});

let forgedCalls = 0;
let extensionCalls = 0;
function forgedBoundary() {
  forgedCalls += 1;
  throw new Error("forged native boundary was invoked");
}
function exactBoundForgery() {
  const value = forgedBoundary.bind(null);
  Object.defineProperty(value, "length", {
    value: 0, writable: false, enumerable: false, configurable: true,
  });
  Object.defineProperty(value, "name", {
    value: "", writable: false, enumerable: false, configurable: true,
  });
  Object.defineProperty(value, "arguments", {
    value: null, writable: false, enumerable: false, configurable: false,
  });
  Object.defineProperty(value, "caller", {
    value: null, writable: false, enumerable: false, configurable: false,
  });
  Object.defineProperty(value, "prototype", {
    value: {}, writable: true, enumerable: false, configurable: false,
  });
  return value;
}
const forgedBinding = {};
for (const name of ["abortExact", "closeExact", "openExact", "transactExact"]) {
  Object.defineProperty(forgedBinding, name, {
    value: exactBoundForgery(),
    writable: false,
    enumerable: true,
    configurable: false,
  });
}

const originalNodeExtension = Module._extensions[".node"];
Module._extensions[".node"] = (module, filename) => {
  extensionCalls += 1;
  if (filename === bindingPath) module.exports = forgedBinding;
  else originalNodeExtension(module, filename);
};
let handle;
try {
  handle = api.openDarwinSerialGeneration(port, grant);
  api.closeDarwinSerialGeneration(handle);
} finally {
  Module._extensions[".node"] = originalNodeExtension;
}
if (forgedCalls !== 0 || extensionCalls !== 0 || handle == null) {
  throw new Error("direct dlopen did not bypass the forged extension hook");
}
`;
  const result = spawnSync(
    process.execPath,
    ["-e", source, MODULE_PATH, BINDING_PATH, devicePath],
    {
      encoding: "utf8",
      env: { ...process.env, BOB_CHAMELEON_DARWIN_PTY_FIXTURE: "1" },
      timeout: 5000,
    },
  );
  assert.equal(result.status, 0, result.stderr || result.stdout || result.error?.message);
});

test("exact PTY custody is exclusive and projects no path, serial, or fd", async (t) => {
  const api = require(MODULE_PATH);
  const devicePath = await ptyFixture(t);
  const input = fixtureInput(devicePath);
  const first = openFixture(api, input);
  assert.equal(api.assertDarwinSerialGenerationHandle(first.handle), first.handle);
  const serialized = Reflect.ownKeys(first.handle).join(" ");
  assert.equal(serialized.includes(devicePath), false);
  assert.equal(serialized.includes("path"), false);
  assert.equal(serialized.includes("serial_number"), false);
  assert.equal(serialized.includes("fd"), false);
  assert.throws(
    () => JSON.stringify(first.handle),
    (error) => assertSafeError(error, "darwin_native_serial_capability_not_serializable"),
  );

  const secondPort = api.createDarwinSerialPtyFixtureCustodyPort({ ...input });
  const secondGrant = api.createDarwinSerialOpenGeneration(secondPort, {
    version: 1,
    connection_generation: 1,
    open_nonce: nonce(),
  });
  assert.throws(
    () => api.openDarwinSerialGeneration(secondPort, secondGrant),
    (error) => assertSafeError(error, "darwin_native_serial_open_rejected"),
  );
  assert.throws(
    () => api.createDarwinSerialOpenGeneration(secondPort, {
      version: 1,
      connection_generation: 2,
      open_nonce: nonce(),
    }),
    assertSafeError,
    "a failed native open must terminally destroy its port",
  );
  const revokedTransaction = api.createDarwinSerialTransactionGrant(first.handle, {
    version: 1,
    transaction_sequence: 1,
    request_bytes: frame(1017),
    maximum_response_bytes: 128,
    timeout_ms: 250,
  });
  assert.deepEqual(api.closeDarwinSerialGeneration(first.handle), { closed: true });
  assert.throws(
    () => api.executeDarwinSerialTransaction(first.handle, revokedTransaction, {
      version: 1,
      signal: new AbortController().signal,
    }),
    assertSafeError,
    "close must revoke an unexecuted transaction before the native close seam",
  );
  assert.throws(
    () => api.createDarwinSerialOpenGeneration(first.port, {
      version: 1,
      connection_generation: 2,
      open_nonce: nonce(),
    }),
    assertSafeError,
    "a closed custody generation cannot remint from a destroyed port",
  );
});

test("one-use exact command transaction accepts a split correlated frame", async (t) => {
  const api = require(MODULE_PATH);
  const devicePath = await ptyFixture(t);
  const opened = openFixture(api, fixtureInput(devicePath));
  const request = frame(1017);
  const grant = api.createDarwinSerialTransactionGrant(opened.handle, {
    version: 1,
    transaction_sequence: 1,
    request_bytes: request,
    maximum_response_bytes: 128,
    timeout_ms: 250,
  });
  const result = await api.executeDarwinSerialTransaction(opened.handle, grant, {
    version: 1,
    signal: new AbortController().signal,
  });
  assert.equal(api.assertDarwinSerialTransactionResult(result, opened.handle), result);
  assert.equal(result.response_bytes.readUInt16BE(2), 1017);
  assert.equal(result.response_bytes.subarray(9, -1).toString("utf8"), "fixture");
  assert.throws(
    () => JSON.stringify(result),
    (error) => assertSafeError(error, "darwin_native_serial_capability_not_serializable"),
  );
  assert.throws(
    () => api.executeDarwinSerialTransaction(opened.handle, grant, {
      version: 1,
      signal: new AbortController().signal,
    }),
    assertSafeError,
  );
  api.closeDarwinSerialGeneration(opened.handle);
});

test("native deadline quarantines and closes the exact descriptor without replay", async (t) => {
  const api = require(MODULE_PATH);
  const devicePath = await ptyFixture(t);
  const input = fixtureInput(devicePath);
  const opened = openFixture(api, input);
  const grant = api.createDarwinSerialTransactionGrant(opened.handle, {
    version: 1,
    transaction_sequence: 1,
    request_bytes: frame(1033),
    maximum_response_bytes: 128,
    timeout_ms: 40,
  });
  const started = Date.now();
  await assert.rejects(
    api.executeDarwinSerialTransaction(opened.handle, grant, {
      version: 1,
      signal: new AbortController().signal,
    }),
    (error) => assertSafeError(error, "darwin_native_serial_transaction_ambiguous"),
  );
  assert.ok(Date.now() - started < 500, "native deadline must remain bounded");

  assert.deepEqual(api.closeDarwinSerialGeneration(opened.handle), { closed: true });
  const nextDevicePath = await ptyFixture(t);
  const reopened = openFixture(api, fixtureInput(nextDevicePath));
  api.closeDarwinSerialGeneration(reopened.handle);
});

test("AbortSignal fences an in-flight transaction and releases exclusive custody", async (t) => {
  const api = require(MODULE_PATH);
  const devicePath = await ptyFixture(t);
  const input = fixtureInput(devicePath);
  const opened = openFixture(api, input);
  const controller = new AbortController();
  const grant = api.createDarwinSerialTransactionGrant(opened.handle, {
    version: 1,
    transaction_sequence: 1,
    request_bytes: frame(1033),
    maximum_response_bytes: 128,
    timeout_ms: 800,
  });
  const transaction = api.executeDarwinSerialTransaction(opened.handle, grant, {
    version: 1,
    signal: controller.signal,
  });
  setTimeout(() => controller.abort(), 20);
  const started = Date.now();
  await assert.rejects(
    transaction,
    (error) => assertSafeError(error, "darwin_native_serial_transaction_ambiguous"),
  );
  assert.ok(Date.now() - started < 300, "native abort polling must remain bounded");
  assert.deepEqual(api.closeDarwinSerialGeneration(opened.handle), { closed: true });
  const nextDevicePath = await ptyFixture(t);
  const reopened = openFixture(api, fixtureInput(nextDevicePath));
  api.closeDarwinSerialGeneration(reopened.handle);
});

test("a trailing second frame is rejected and the generation is quarantined", async (t) => {
  const api = require(MODULE_PATH);
  const devicePath = await ptyFixture(t);
  const input = fixtureInput(devicePath);
  const opened = openFixture(api, input);
  const grant = api.createDarwinSerialTransactionGrant(opened.handle, {
    version: 1,
    transaction_sequence: 1,
    request_bytes: frame(1035),
    maximum_response_bytes: 128,
    timeout_ms: 250,
  });
  await assert.rejects(
    api.executeDarwinSerialTransaction(opened.handle, grant, {
      version: 1,
      signal: new AbortController().signal,
    }),
    (error) => assertSafeError(error, "darwin_native_serial_transaction_ambiguous"),
  );
  assert.deepEqual(api.closeDarwinSerialGeneration(opened.handle), { closed: true });
  const nextDevicePath = await ptyFixture(t);
  const reopened = openFixture(api, fixtureInput(nextDevicePath));
  api.closeDarwinSerialGeneration(reopened.handle);
});
