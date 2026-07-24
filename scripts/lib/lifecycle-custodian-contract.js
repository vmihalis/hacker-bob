"use strict";

const crypto = require("node:crypto");

const REQUEST_MAGIC = Buffer.from("HBLCRQ01", "ascii");
const RESULT_MAGIC = Buffer.from("HBLCRS01", "ascii");
const REQUEST_VERSION = 1;
const REQUEST_HEADER_BYTES = 64;
const RECORD_HEADER_BYTES = 44;
const RESULT_BYTES = 16;
const MAX_FILES = 128;
const MAX_TOTAL_BYTES = 512 * 1024 * 1024;
const MAX_PATH_BYTES = 512;
const MAX_REQUEST_BYTES = 128 * 1024;
const COMPONENT_PATTERN = /^[A-Za-z0-9._@+-]{1,128}$/u;

const LIFECYCLE_CUSTODIAN_SELECTIONS = Object.freeze({
  "optional:chameleon_ultra:worker_source": 1,
  "optional:chameleon_ultra:darwin_arm64_native_prebuild": 2,
  "canonical:packages/bob-artifact-vault": 100,
  "canonical:packages/bob-instrument-broker": 101,
  "canonical:packages/bob-instrument-chameleon": 102,
  "canonical:packages/bob-instrument-deterministic": 103,
  "canonical:packages/bob-instrument-native-prebuild-trust": 104,
  "canonical:packages/bob-instrument-principal-acl-darwin": 105,
  "canonical:packages/bob-instrument-contracts": 106,
  "canonical:packages/bob-instrument-chameleon-worker-runtime": 107,
});

const RESULT_NAMES = Object.freeze(["changed", "absent", "rejected"]);

function contractError(reasonCode) {
  const error = new Error("Lifecycle custodian contract was rejected");
  error.code = "lifecycle_custodian_contract_rejected";
  error.reason_code = reasonCode;
  return error;
}

function reject(reasonCode) {
  throw contractError(reasonCode);
}

function selectionCode(selection) {
  if (typeof selection !== "string"
      || !Object.prototype.hasOwnProperty.call(LIFECYCLE_CUSTODIAN_SELECTIONS, selection)) {
    reject("selection_not_enrolled");
  }
  return LIFECYCLE_CUSTODIAN_SELECTIONS[selection];
}

function normalizeRelativePath(value) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\\")
      || value.startsWith("/") || value.endsWith("/") || value.includes("//")
      || value.includes("\0") || Buffer.byteLength(value, "utf8") > MAX_PATH_BYTES) {
    reject("file_path_invalid");
  }
  const components = value.split("/");
  if (components.length > 16
      || components.some((component) => component === "." || component === ".."
        || !COMPONENT_PATTERN.test(component))) reject("file_path_invalid");
  return components.join("/");
}

function allowedMode(selection, mode) {
  if (selection === "optional:chameleon_ultra:worker_source") return mode === 0o444;
  if (selection === "optional:chameleon_ultra:darwin_arm64_native_prebuild") {
    return mode === 0o444 || mode === 0o555;
  }
  return mode === 0o644;
}

function normalizeFiles(operation, selection, files) {
  if (!Array.isArray(files) || files.length > MAX_FILES
      || (operation === "replace" && files.length === 0)
      || (operation === "remove" && files.length !== 0)) reject("file_set_invalid");
  const normalized = files.map((file) => {
    if (file == null || typeof file !== "object" || Array.isArray(file)
        || Object.keys(file).length !== 3
        || !Object.prototype.hasOwnProperty.call(file, "path")
        || !Object.prototype.hasOwnProperty.call(file, "contents")
        || !Object.prototype.hasOwnProperty.call(file, "mode")) reject("file_record_invalid");
    const relativePath = normalizeRelativePath(file.path);
    if (!Buffer.isBuffer(file.contents) || !Number.isSafeInteger(file.mode)
        || !allowedMode(selection, file.mode)) reject("file_record_invalid");
    return Object.freeze({
      path: relativePath,
      contents: Buffer.from(file.contents),
      mode: file.mode,
      byte_size: file.contents.length,
      sha256: crypto.createHash("sha256").update(file.contents).digest(),
    });
  }).sort((left, right) => (left.path < right.path ? -1 : (left.path > right.path ? 1 : 0)));
  for (let index = 1; index < normalized.length; index += 1) {
    if (normalized[index - 1].path === normalized[index].path) reject("file_path_duplicate");
  }
  if (normalized.reduce((total, file) => total + file.byte_size, 0) > MAX_TOTAL_BYTES) {
    reject("file_set_too_large");
  }
  return Object.freeze(normalized);
}

function normalizeLifecycleCustodianMutation(input) {
  if (input == null || typeof input !== "object" || Array.isArray(input)
      || Object.keys(input).length !== 3
      || !Object.prototype.hasOwnProperty.call(input, "operation")
      || !Object.prototype.hasOwnProperty.call(input, "selection")
      || !Object.prototype.hasOwnProperty.call(input, "files")) reject("mutation_input_invalid");
  if (input.operation !== "replace" && input.operation !== "remove") {
    reject("mutation_input_invalid");
  }
  const code = selectionCode(input.selection);
  return Object.freeze({
    operation: input.operation,
    operation_code: input.operation === "replace" ? 1 : 2,
    selection: input.selection,
    selection_code: code,
    files: normalizeFiles(input.operation, input.selection, input.files),
  });
}

function encodeLifecycleCustodianRequest(normalized) {
  if (normalized == null || typeof normalized !== "object"
      || !Number.isInteger(normalized.operation_code)
      || !Number.isInteger(normalized.selection_code)
      || !Array.isArray(normalized.files)) reject("normalized_mutation_invalid");
  const records = normalized.files.map((file) => {
    const pathBytes = Buffer.from(file.path, "utf8");
    const record = Buffer.alloc(RECORD_HEADER_BYTES + pathBytes.length);
    record.writeUInt16BE(pathBytes.length, 0);
    record.writeUInt16BE(file.mode, 2);
    record.writeBigUInt64BE(BigInt(file.byte_size), 4);
    file.sha256.copy(record, 12);
    pathBytes.copy(record, RECORD_HEADER_BYTES);
    return record;
  });
  const recordBytes = Buffer.concat(records);
  if (REQUEST_HEADER_BYTES + recordBytes.length > MAX_REQUEST_BYTES) {
    reject("request_too_large");
  }
  const request = Buffer.alloc(REQUEST_HEADER_BYTES + recordBytes.length);
  REQUEST_MAGIC.copy(request, 0);
  request.writeUInt32BE(REQUEST_VERSION, 8);
  request.writeUInt32BE(normalized.operation_code, 12);
  request.writeUInt32BE(normalized.selection_code, 16);
  request.writeUInt32BE(normalized.files.length, 20);
  crypto.createHash("sha256").update(recordBytes).digest().copy(request, 32);
  recordBytes.copy(request, REQUEST_HEADER_BYTES);
  return request;
}

function parseLifecycleCustodianResult(value) {
  if (!Buffer.isBuffer(value) || value.length !== RESULT_BYTES
      || !value.subarray(0, 8).equals(RESULT_MAGIC)
      || value.readUInt32BE(8) !== REQUEST_VERSION) reject("result_invalid");
  const code = value.readUInt32BE(12);
  if (code >= RESULT_NAMES.length) reject("result_invalid");
  return Object.freeze({ code, status: RESULT_NAMES[code] });
}

module.exports = {
  LIFECYCLE_CUSTODIAN_SELECTIONS,
  encodeLifecycleCustodianRequest,
  normalizeLifecycleCustodianMutation,
  parseLifecycleCustodianResult,
  selectionCode,
};
