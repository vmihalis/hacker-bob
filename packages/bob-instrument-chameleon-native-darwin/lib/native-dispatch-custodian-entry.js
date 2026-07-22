"use strict";

// Fixture-only process entry for the zero-argument native dispatch custodian.
// Authority values arrive only on fixed inherited descriptors; argv and env
// contain no path, FD, key, ticket, device, or operation selector.

const crypto = require("node:crypto");
const fs = require("node:fs");
const hostProcess = require("node:process");
const path = require("node:path");

const HostBuffer = Buffer;
const bufferFill = HostBuffer.prototype.fill;
const cryptoCreateHash = crypto.createHash;
const fsLstatSync = fs.lstatSync;
const fsReadFileSync = fs.readFileSync;
const fsRealpathNative = fs.realpathSync.native;
const functionToString = Function.prototype.toString;
const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectPrototype = Object.prototype;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const stringIncludes = String.prototype.includes;
const stringStartsWith = String.prototype.startsWith;
const hostProcessDlopen = hostProcess.dlopen;
const processGetuid = hostProcess.getuid;
const pathJoin = path.join;

const EXPECTED_FLAG = "--fixture-native-dispatch-custodian-v1";
const MAXIMUM_BINDING_BYTES = 16 * 1024 * 1024;

const hashProbe = reflectApply(cryptoCreateHash, crypto, ["sha256"]);
const hashPrototype = objectGetPrototypeOf(hashProbe);
const hashUpdate = hashPrototype.update;
const hashDigest = hashPrototype.digest;
reflectApply(hashDigest, hashProbe, []);

function terminalFailure() {
  hostProcess.exitCode = 70;
}

function sameStat(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode
    && left.nlink === right.nlink && left.uid === right.uid && left.gid === right.gid
    && left.size === right.size && left.ctimeMs === right.ctimeMs;
}

function measureBinding(candidate) {
  const resolved = fsRealpathNative(candidate);
  if (resolved !== candidate) throw new Error("binding path is not canonical");
  const before = fsLstatSync(resolved);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
      || before.uid !== reflectApply(processGetuid, hostProcess, [])
      || (before.mode & 0o022) !== 0 || before.size < 1
      || before.size > MAXIMUM_BINDING_BYTES) throw new Error("binding identity rejected");
  const bytes = fsReadFileSync(resolved);
  try {
    const hash = reflectApply(cryptoCreateHash, crypto, ["sha256"]);
    reflectApply(hashUpdate, hash, [bytes]);
    return {
      resolved,
      stat: before,
      digest: reflectApply(hashDigest, hash, ["hex"]),
    };
  } finally {
    reflectApply(bufferFill, bytes, [0]);
  }
}

function loadMeasuredBinding() {
  const candidate = pathJoin(__dirname, "..", "build", "Release",
    "native_dispatch_custodian.node");
  const before = measureBinding(candidate);
  if (objectGetOwnPropertyDescriptor(require.cache, before.resolved) != null) {
    throw new Error("preloaded native binding rejected");
  }
  const moduleRecord = objectCreate(null);
  moduleRecord.exports = objectCreate(objectPrototype);
  reflectApply(hostProcessDlopen, hostProcess, [moduleRecord, before.resolved]);
  const binding = moduleRecord.exports;
  const keys = reflectOwnKeys(binding);
  if (binding == null || objectGetPrototypeOf(binding) !== objectPrototype
      || keys.length !== 1 || keys[0] !== "dispatchFixtureExact") {
    throw new Error("native binding shape rejected");
  }
  const descriptor = objectGetOwnPropertyDescriptor(binding, "dispatchFixtureExact");
  if (descriptor == null || !objectHasOwn(descriptor, "value")
      || typeof descriptor.value !== "function" || descriptor.enumerable !== true
      || !reflectApply(stringIncludes,
        reflectApply(functionToString, descriptor.value, []), ["[native code]"])) {
    throw new Error("native dispatch function rejected");
  }
  const after = measureBinding(candidate);
  if (!sameStat(before.stat, after.stat) || before.digest !== after.digest) {
    throw new Error("native binding changed during load");
  }
  objectFreeze(descriptor.value.prototype);
  objectFreeze(descriptor.value);
  objectFreeze(binding);
  objectDefineProperty(require.cache, before.resolved, {
    value: objectFreeze(objectCreate(null)),
    writable: false,
    enumerable: true,
    configurable: false,
  });
  return descriptor.value;
}

async function main() {
  if (hostProcess.platform !== "darwin" || hostProcess.arch !== "arm64"
      || !reflectApply(stringStartsWith, hostProcess.versions.node, ["20."])
      || hostProcess.argv.length !== 3 || hostProcess.argv[2] !== EXPECTED_FLAG
      || hostProcess.env.BOB_CHAMELEON_DARWIN_NATIVE_DISPATCH_FIXTURE !== "1") {
    terminalFailure();
    return;
  }
  try {
    const dispatch = loadMeasuredBinding();
    await reflectApply(dispatch, undefined, []);
  } catch {
    terminalFailure();
  }
}

main();
