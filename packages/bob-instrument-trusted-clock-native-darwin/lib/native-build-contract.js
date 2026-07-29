"use strict";

// This is a local source-build receipt, not a release signature or native
// attestation. The loader uses it to reject source/artifact drift before
// direct dlopen. A future immutable prebuild must use a separate signed
// release envelope and operator-pinned trust root.

const crypto = require("node:crypto");
const fs = require("node:fs");
const hostProcess = require("node:process");
const path = require("node:path");
const { types: utilTypes } = require("node:util");

const SafeError = Error;
const SafeBigInt = BigInt;
const SafeString = String;
const arrayJoin = Array.prototype.join;
const arrayPush = Array.prototype.push;
const arraySort = Array.prototype.sort;
const arrayIsArray = Array.isArray;
const bufferAlloc = Buffer.alloc;
const bufferFill = Buffer.prototype.fill;
const bufferFrom = Buffer.from;
const bufferToString = Buffer.prototype.toString;
const bufferWriteBigUInt64BE = Buffer.prototype.writeBigUInt64BE;
const cryptoCreateHash = crypto.createHash;
const fsCloseSync = fs.closeSync;
const fsFstatSync = fs.fstatSync;
const fsLstatSync = fs.lstatSync;
const fsOpenSync = fs.openSync;
const fsReadFileSync = fs.readFileSync;
const fsRealpathNative = fs.realpathSync.native;
const fsOpenCloseOnExec = fs.constants.O_CLOEXEC || 0;
const fsOpenNoFollow = fs.constants.O_NOFOLLOW || 0;
const fsOpenReadOnly = fs.constants.O_RDONLY;
const jsonParse = JSON.parse;
const jsonStringify = JSON.stringify;
const numberIsSafeInteger = Number.isSafeInteger;
const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectKeys = Object.keys;
const pathJoin = path.join;
const pathResolve = path.resolve;
const processGeteuid = hostProcess.geteuid;
const reflectApply = Reflect.apply;
const regExpTest = RegExp.prototype.test;
const utilTypesIsProxy = utilTypes.isProxy;

const OBJECT_PROTOTYPE = Object.prototype;
const HASH_PROTOTYPE = objectGetPrototypeOf(cryptoCreateHash("sha256"));
const HASH_UPDATE = objectGetOwnPropertyDescriptor(HASH_PROTOTYPE, "update").value;
const HASH_DIGEST = objectGetOwnPropertyDescriptor(HASH_PROTOTYPE, "digest").value;
const PACKAGE_ROOT = pathResolve(__dirname, "..");
const LOCAL_BUILD_RECEIPT_RELATIVE_PATH =
  "build/Release/trusted_clock_local_build_receipt.json";
const LOCAL_BUILD_RECEIPT_VERSION = 1;
const LOCAL_BUILD_RECEIPT_KIND = "darwin_trusted_clock_local_source_build";
const LOCAL_BUILD_ASSURANCE = "local_source_build_receipt_non_authorizing";
const LOCAL_BUILD_TARGET = objectFreeze({
  platform: "darwin",
  arch: "arm64",
  node_major: 20,
  napi: 9,
  deployment_target: "13.0",
  configuration: "Release",
  build_system: "node-gyp",
});
const LOCAL_BUILD_SOURCE_PATHS = objectFreeze([
  "binding.gyp",
  "lib/native-binding-loader.js",
  "lib/native-build-contract.js",
  "lib/native-client.js",
  "lib/source-contract.js",
  "native/trusted_clock_client.cc",
  "native/trusted_clock_node.cc",
  "native/trusted_clock_protocol.h",
  "native/trusted_clock_service.cc",
  "package.json",
  "scripts/write-build-receipt.js",
]);
const LOCAL_BUILD_ARTIFACTS = objectFreeze([
  objectFreeze({
    role: "trusted_clock_node_api_client",
    kind: "node_api_bundle",
    path: "build/Release/trusted_clock_client.node",
  }),
  objectFreeze({
    role: "trusted_clock_service",
    kind: "standalone_executable",
    path: "build/Release/trusted_clock_service",
  }),
]);
const LOCAL_BUILD_BLOCKERS = objectFreeze([
  "trusted_clock_local_source_build_not_release_authenticated",
  "trusted_clock_native_release_envelope_v3_or_separate_missing",
  "trusted_clock_node_api_loaded_image_attestation_missing",
  "trusted_clock_immutable_root_owned_installation_missing",
  "trusted_clock_same_process_preimport_runtime_integrity_unproven",
  "trusted_clock_native_client_same_process_capability_custody_not_isolated",
  "trusted_clock_dedicated_principal_and_socket_acl_unproven",
  "trusted_clock_signer_custody_unproven",
  "trusted_clock_restart_sleep_reboot_hil_missing",
]);
const MAX_SOURCE_BYTES = 4 * 1024 * 1024;
const MAX_ARTIFACT_BYTES = 64 * 1024 * 1024;
const MAX_RECEIPT_BYTES = 64 * 1024;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]{0,19})$/u;
const SOURCE_SET_DOMAIN = bufferFrom(
  "hacker-bob/darwin-trusted-clock-local-source-set/v1\0",
  "utf8",
);

function buildContractError(reasonCode = "trusted_clock_local_build_rejected") {
  const error = new SafeError("Darwin trusted-clock local build was rejected");
  objectDefineProperty(error, "code", {
    value: "darwin_trusted_clock_local_build_rejected",
    enumerable: false,
    writable: false,
    configurable: false,
  });
  objectDefineProperty(error, "reason_code", {
    value: reasonCode,
    enumerable: false,
    writable: false,
    configurable: false,
  });
  return error;
}

function reject(reasonCode) {
  throw buildContractError(reasonCode);
}

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || arrayIsArray(value)
      || utilTypesIsProxy(value)) return false;
  const prototype = objectGetPrototypeOf(value);
  return prototype === OBJECT_PROTOTYPE || prototype === null;
}

function own(value, field, reasonCode) {
  const descriptor = objectGetOwnPropertyDescriptor(value, field);
  if (descriptor == null || !objectHasOwn(descriptor, "value")
      || descriptor.enumerable !== true) reject(reasonCode);
  return descriptor.value;
}

function assertExactObject(value, fields, reasonCode) {
  if (!isPlainObject(value)) reject(reasonCode);
  const keys = objectKeys(value);
  if (keys.length !== fields.length) reject(reasonCode);
  for (let index = 0; index < fields.length; index += 1) {
    if (!objectHasOwn(value, fields[index])) reject(reasonCode);
  }
  return value;
}

function canonicalJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return reflectApply(jsonStringify, undefined, [value]);
  }
  if (typeof value === "number") {
    if (!numberIsSafeInteger(value)) reject("receipt_canonical_json_invalid");
    return SafeString(value);
  }
  if (arrayIsArray(value)) {
    const items = [];
    for (let index = 0; index < value.length; index += 1) {
      items[index] = canonicalJson(value[index]);
    }
    return `[${reflectApply(arrayJoin, items, [","])}]`;
  }
  if (!isPlainObject(value)) reject("receipt_canonical_json_invalid");
  const keys = objectKeys(value);
  reflectApply(arraySort, keys, [(left, right) => {
    if (left < right) return -1;
    if (left > right) return 1;
    return 0;
  }]);
  const items = [];
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    items[index] = `${reflectApply(jsonStringify, undefined, [key])}:${canonicalJson(
      own(value, key, "receipt_canonical_json_invalid"),
    )}`;
  }
  return `{${reflectApply(arrayJoin, items, [","])}}`;
}

function hashParts(parts) {
  const hash = cryptoCreateHash("sha256");
  for (let index = 0; index < parts.length; index += 1) {
    reflectApply(HASH_UPDATE, hash, [parts[index]]);
  }
  return reflectApply(HASH_DIGEST, hash, ["hex"]);
}

function sha256(bytes) {
  return hashParts([bytes]);
}

function encodeLength(value) {
  const output = bufferAlloc(8);
  reflectApply(bufferWriteBigUInt64BE, output, [SafeBigInt(value), 0]);
  return output;
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino
    && left.mode === right.mode && left.uid === right.uid
    && left.gid === right.gid && left.nlink === right.nlink
    && left.size === right.size && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function assertCanonicalRoot(rootInput) {
  if (typeof rootInput !== "string") reject("build_root_invalid");
  const absolute = pathResolve(rootInput);
  let canonical;
  let status;
  try {
    canonical = fsRealpathNative(absolute);
    status = fsLstatSync(canonical, { bigint: true });
  } catch {
    reject("build_root_invalid");
  }
  if (absolute !== canonical || !status.isDirectory()
      || status.uid !== SafeBigInt(reflectApply(processGeteuid, hostProcess, []))
      || (status.mode & 0o022n) !== 0n) reject("build_root_invalid");
  return canonical;
}

function readMeasuredFile(
  root,
  relativePath,
  maximumBytes,
  executableRequired,
  retainBytes = false,
) {
  const candidate = pathJoin(root, relativePath);
  let canonical;
  let fd = -1;
  try {
    canonical = fsRealpathNative(candidate);
    if (canonical !== candidate) reject("build_file_path_invalid");
    fd = fsOpenSync(
      canonical,
      fsOpenReadOnly | fsOpenNoFollow | fsOpenCloseOnExec,
    );
    const before = fsFstatSync(fd, { bigint: true });
    const pathStatus = fsLstatSync(canonical, { bigint: true });
    if (!before.isFile() || !pathStatus.isFile()
        || !sameFileIdentity(before, pathStatus) || before.nlink !== 1n
        || before.uid !== SafeBigInt(reflectApply(processGeteuid, hostProcess, []))
        || (before.mode & 0o022n) !== 0n || before.size < 1n
        || before.size > SafeBigInt(maximumBytes)
        || (executableRequired && (before.mode & 0o111n) === 0n)) {
      reject("build_file_identity_invalid");
    }
    const bytes = fsReadFileSync(fd);
    try {
      const after = fsFstatSync(fd, { bigint: true });
      if (!sameFileIdentity(before, after)
          || SafeBigInt(bytes.length) !== before.size) {
        reject("build_file_changed_during_read");
      }
      const output = {
        path: relativePath,
        size: SafeString(before.size),
        sha256: sha256(bytes),
        mode: SafeString(before.mode & 0o777n),
      };
      if (retainBytes) output.bytes = bufferFrom(bytes);
      return objectFreeze(output);
    } finally {
      reflectApply(bufferFill, bytes, [0]);
    }
  } catch (error) {
    if (error?.code === "darwin_trusted_clock_local_build_rejected") throw error;
    reject("build_file_unavailable");
  } finally {
    if (fd >= 0) fsCloseSync(fd);
  }
}

function measureSources(root) {
  const rows = [];
  const framed = [SOURCE_SET_DOMAIN];
  for (let index = 0; index < LOCAL_BUILD_SOURCE_PATHS.length; index += 1) {
    const row = readMeasuredFile(
      root,
      LOCAL_BUILD_SOURCE_PATHS[index],
      MAX_SOURCE_BYTES,
      false,
    );
    rows[index] = objectFreeze({
      path: row.path,
      size: row.size,
      sha256: row.sha256,
    });
    const pathBytes = bufferFrom(row.path, "utf8");
    const digestBytes = bufferFrom(row.sha256, "hex");
    reflectApply(arrayPush, framed, [encodeLength(pathBytes.length), pathBytes]);
    reflectApply(arrayPush, framed, [encodeLength(row.size), digestBytes]);
  }
  return objectFreeze({
    rows: objectFreeze(rows),
    digest: hashParts(framed),
  });
}

function measureArtifacts(root) {
  const rows = [];
  for (let index = 0; index < LOCAL_BUILD_ARTIFACTS.length; index += 1) {
    const expected = LOCAL_BUILD_ARTIFACTS[index];
    const measured = readMeasuredFile(
      root,
      expected.path,
      MAX_ARTIFACT_BYTES,
      true,
    );
    rows[index] = objectFreeze({
      role: expected.role,
      kind: expected.kind,
      path: expected.path,
      size: measured.size,
      sha256: measured.sha256,
      mode: measured.mode,
    });
  }
  return objectFreeze(rows);
}

function createDarwinTrustedClockLocalBuildReceipt(rootInput = PACKAGE_ROOT) {
  if (arguments.length > 1) reject("build_receipt_argument_shape_invalid");
  const root = assertCanonicalRoot(rootInput);
  const sources = measureSources(root);
  const artifacts = measureArtifacts(root);
  return objectFreeze({
    version: LOCAL_BUILD_RECEIPT_VERSION,
    kind: LOCAL_BUILD_RECEIPT_KIND,
    assurance: LOCAL_BUILD_ASSURANCE,
    target: LOCAL_BUILD_TARGET,
    source_set_sha256: sources.digest,
    sources: sources.rows,
    artifacts,
    signed_release_verified: false,
    native_loaded_image_attested: false,
    immutable_installation_verified: false,
    provisioning_verified: false,
    hil_verified: false,
    production_ready: false,
    production_blockers: LOCAL_BUILD_BLOCKERS,
  });
}

function assertDigest(value, reasonCode) {
  if (typeof value !== "string"
      || !reflectApply(regExpTest, DIGEST_PATTERN, [value])) reject(reasonCode);
  return value;
}

function assertDecimal(value, reasonCode) {
  if (typeof value !== "string"
      || !reflectApply(regExpTest, DECIMAL_PATTERN, [value])) reject(reasonCode);
  return value;
}

function validateReceiptShape(receipt) {
  assertExactObject(receipt, [
    "version", "kind", "assurance", "target", "source_set_sha256", "sources",
    "artifacts", "signed_release_verified", "native_loaded_image_attested",
    "immutable_installation_verified", "provisioning_verified", "hil_verified",
    "production_ready", "production_blockers",
  ], "build_receipt_shape_invalid");
  if (own(receipt, "version", "build_receipt_shape_invalid")
        !== LOCAL_BUILD_RECEIPT_VERSION
      || own(receipt, "kind", "build_receipt_shape_invalid")
        !== LOCAL_BUILD_RECEIPT_KIND
      || own(receipt, "assurance", "build_receipt_shape_invalid")
        !== LOCAL_BUILD_ASSURANCE) reject("build_receipt_identity_invalid");
  const target = own(receipt, "target", "build_receipt_shape_invalid");
  assertExactObject(target, objectKeys(LOCAL_BUILD_TARGET), "build_target_shape_invalid");
  const targetFields = objectKeys(LOCAL_BUILD_TARGET);
  for (let index = 0; index < targetFields.length; index += 1) {
    const field = targetFields[index];
    if (own(target, field, "build_target_shape_invalid") !== LOCAL_BUILD_TARGET[field]) {
      reject("build_target_invalid");
    }
  }
  assertDigest(own(receipt, "source_set_sha256", "build_receipt_shape_invalid"),
    "build_source_set_digest_invalid");
  const sources = own(receipt, "sources", "build_receipt_shape_invalid");
  if (!arrayIsArray(sources) || sources.length !== LOCAL_BUILD_SOURCE_PATHS.length) {
    reject("build_sources_shape_invalid");
  }
  for (let index = 0; index < sources.length; index += 1) {
    const row = sources[index];
    assertExactObject(row, ["path", "size", "sha256"], "build_source_shape_invalid");
    if (own(row, "path", "build_source_shape_invalid")
        !== LOCAL_BUILD_SOURCE_PATHS[index]) reject("build_source_path_invalid");
    assertDecimal(own(row, "size", "build_source_shape_invalid"),
      "build_source_size_invalid");
    assertDigest(own(row, "sha256", "build_source_shape_invalid"),
      "build_source_digest_invalid");
  }
  const artifacts = own(receipt, "artifacts", "build_receipt_shape_invalid");
  if (!arrayIsArray(artifacts) || artifacts.length !== LOCAL_BUILD_ARTIFACTS.length) {
    reject("build_artifacts_shape_invalid");
  }
  for (let index = 0; index < artifacts.length; index += 1) {
    const row = artifacts[index];
    const expected = LOCAL_BUILD_ARTIFACTS[index];
    assertExactObject(row, ["role", "kind", "path", "size", "sha256", "mode"],
      "build_artifact_shape_invalid");
    if (own(row, "role", "build_artifact_shape_invalid") !== expected.role
        || own(row, "kind", "build_artifact_shape_invalid") !== expected.kind
        || own(row, "path", "build_artifact_shape_invalid") !== expected.path) {
      reject("build_artifact_identity_invalid");
    }
    assertDecimal(own(row, "size", "build_artifact_shape_invalid"),
      "build_artifact_size_invalid");
    assertDecimal(own(row, "mode", "build_artifact_shape_invalid"),
      "build_artifact_mode_invalid");
    assertDigest(own(row, "sha256", "build_artifact_shape_invalid"),
      "build_artifact_digest_invalid");
  }
  const authorityFields = [
    "signed_release_verified", "native_loaded_image_attested",
    "immutable_installation_verified", "provisioning_verified", "hil_verified",
    "production_ready",
  ];
  for (let index = 0; index < authorityFields.length; index += 1) {
    const field = authorityFields[index];
    if (own(receipt, field, "build_receipt_shape_invalid") !== false) {
      reject("build_receipt_authority_claim_invalid");
    }
  }
  const blockers = own(receipt, "production_blockers", "build_receipt_shape_invalid");
  if (!arrayIsArray(blockers) || blockers.length !== LOCAL_BUILD_BLOCKERS.length) {
    reject("build_receipt_blockers_invalid");
  }
  for (let index = 0; index < blockers.length; index += 1) {
    if (blockers[index] !== LOCAL_BUILD_BLOCKERS[index]) {
      reject("build_receipt_blockers_invalid");
    }
  }
  return receipt;
}

function readReceipt(root) {
  const measured = readMeasuredFile(
    root,
    LOCAL_BUILD_RECEIPT_RELATIVE_PATH,
    MAX_RECEIPT_BYTES,
    false,
    true,
  );
  let parsed;
  let encoded;
  try {
    encoded = reflectApply(bufferToString, measured.bytes, ["utf8"]);
    parsed = reflectApply(jsonParse, undefined, [
      encoded,
    ]);
  } catch {
    reject("build_receipt_parse_invalid");
  } finally {
    reflectApply(bufferFill, measured.bytes, [0]);
  }
  validateReceiptShape(parsed);
  const canonical = `${canonicalJson(parsed)}\n`;
  if (encoded !== canonical) reject("build_receipt_not_canonical");
  return objectFreeze({ receipt: parsed, digest: measured.sha256 });
}

function sameRows(left, right, fields, reasonCode) {
  if (left.length !== right.length) reject(reasonCode);
  for (let index = 0; index < left.length; index += 1) {
    for (let fieldIndex = 0; fieldIndex < fields.length; fieldIndex += 1) {
      const field = fields[fieldIndex];
      if (left[index][field] !== right[index][field]) reject(reasonCode);
    }
  }
}

function verifyDarwinTrustedClockLocalBuild(rootInput = PACKAGE_ROOT) {
  if (arguments.length > 1) reject("build_verify_argument_shape_invalid");
  const root = assertCanonicalRoot(rootInput);
  const stored = readReceipt(root);
  const expected = createDarwinTrustedClockLocalBuildReceipt(root);
  if (stored.receipt.source_set_sha256 !== expected.source_set_sha256) {
    reject("build_source_set_drift");
  }
  sameRows(stored.receipt.sources, expected.sources, ["path", "size", "sha256"],
    "build_source_drift");
  sameRows(stored.receipt.artifacts, expected.artifacts,
    ["role", "kind", "path", "size", "sha256", "mode"],
    "build_artifact_drift");
  const nodeArtifact = expected.artifacts[0];
  const serviceArtifact = expected.artifacts[1];
  return objectFreeze({
    version: LOCAL_BUILD_RECEIPT_VERSION,
    kind: "verified_darwin_trusted_clock_local_source_build",
    assurance: LOCAL_BUILD_ASSURANCE,
    receipt_sha256: stored.digest,
    source_set_sha256: expected.source_set_sha256,
    node_api_client_path: pathJoin(root, nodeArtifact.path),
    node_api_client_sha256: nodeArtifact.sha256,
    node_api_client_size: nodeArtifact.size,
    service_path: pathJoin(root, serviceArtifact.path),
    service_sha256: serviceArtifact.sha256,
    service_size: serviceArtifact.size,
    signed_release_verified: false,
    native_loaded_image_attested: false,
    immutable_installation_verified: false,
    provisioning_verified: false,
    hil_verified: false,
    production_ready: false,
    production_blockers: LOCAL_BUILD_BLOCKERS,
  });
}

module.exports = objectFreeze({
  DARWIN_TRUSTED_CLOCK_LOCAL_BUILD_ARTIFACTS: LOCAL_BUILD_ARTIFACTS,
  DARWIN_TRUSTED_CLOCK_LOCAL_BUILD_ASSURANCE: LOCAL_BUILD_ASSURANCE,
  DARWIN_TRUSTED_CLOCK_LOCAL_BUILD_BLOCKERS: LOCAL_BUILD_BLOCKERS,
  DARWIN_TRUSTED_CLOCK_LOCAL_BUILD_RECEIPT_PATH: LOCAL_BUILD_RECEIPT_RELATIVE_PATH,
  DARWIN_TRUSTED_CLOCK_LOCAL_BUILD_SOURCE_PATHS: LOCAL_BUILD_SOURCE_PATHS,
  DARWIN_TRUSTED_CLOCK_LOCAL_BUILD_TARGET: LOCAL_BUILD_TARGET,
  DARWIN_TRUSTED_CLOCK_LOCAL_BUILD_VERSION: LOCAL_BUILD_RECEIPT_VERSION,
  createDarwinTrustedClockLocalBuildReceipt,
  verifyDarwinTrustedClockLocalBuild,
  _canonicalJsonForBuildReceipt: canonicalJson,
});
