"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const {
  ARTIFACT_DATA_CLASSES,
  ARTIFACT_VAULT_SCHEMA_VERSION,
  PUBLIC_ARTIFACT_HANDLE_RE,
  PUBLIC_RESERVATION_HANDLE_RE,
  assertClosedObject,
  assertIdentifier,
  assertOpaqueRef,
} = require("./contracts.js");
const {
  claimTransformAttemptForWorker,
  failTransformAttemptForWorker,
  hasVaultWorkerAccess,
  ingestTransformBatchForWorker,
  inspectTransformAttemptForWorker,
  materializeForWorker,
} = require("./vault.js");
const {
  resolveOperatorTransformPolicy,
} = require("./transform-policy.js");

const TRANSFORM_REGISTRY_ENTRIES = new WeakMap();
const SHA256_RE = /^[a-f0-9]{64}$/;
const PARAMETER_KINDS = Object.freeze(["boolean", "enum", "integer", "number"]);
const MAX_IMPLEMENTATION_BYTES = 8 * 1024 * 1024;
const MAX_PROGRAM_EXPRESSION_DEPTH = 16;
const MAX_PROGRAM_EXPRESSION_NODES = 4096;
const MAX_PROGRAM_CONCAT_VALUES = 64;
const MAX_TRANSFORM_DATA_BYTES = 128 * 1024 * 1024;
const MAX_TRANSFORM_ALLOCATION_BYTES = 256 * 1024 * 1024;
const MAX_TRANSFORM_WORK_BYTES = 512 * 1024 * 1024;
const BASE64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const MEDIA_TYPE_RE = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$/;

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value != null && typeof value === "object") {
    const output = Object.create(null);
    for (const key of Object.keys(value).sort()) {
      if (value[key] !== undefined) output[key] = canonicalize(value[key]);
    }
    return output;
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function manifestDigest(manifest) {
  return crypto.createHash("sha256").update(canonicalJson(manifest)).digest("hex");
}

function normalizeStringSet(value, label, { allowed = null, allowEmpty = false } = {}) {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0)) {
    throw new Error(`${label} must be ${allowEmpty ? "an" : "a non-empty"} array`);
  }
  const normalized = value.map((item, index) => {
    if (typeof item !== "string" || !item.length) throw new Error(`${label}[${index}] must be a string`);
    if (allowed && !allowed.includes(item)) throw new Error(`${label}[${index}] is not registered`);
    return item;
  });
  const sorted = [...new Set(normalized)].sort();
  if (sorted.length !== normalized.length) throw new Error(`${label} must not contain duplicates`);
  return Object.freeze(sorted);
}

function normalizeManifest(input, label) {
  assertClosedObject(
    input,
    label,
    [
      "version",
      "tool_id",
      "tool_version",
      "implementation_digest",
      "handler_export",
      "input_data_classes",
      "output_data_classes",
      "parameters",
      "max_input_handles",
      "max_input_bytes",
      "max_output_artifacts",
      "max_output_bytes",
    ],
  );
  if (input.version !== ARTIFACT_VAULT_SCHEMA_VERSION) throw new Error(`${label}.version must be 1`);
  for (const [field, minimum] of [
    ["max_input_handles", 1],
    ["max_input_bytes", 1],
    ["max_output_artifacts", 1],
    ["max_output_bytes", 1],
  ]) {
    if (!Number.isSafeInteger(input[field]) || input[field] < minimum) {
      throw new Error(`${label}.${field} must be a positive safe integer`);
    }
  }
  for (const field of ["max_input_bytes", "max_output_bytes"]) {
    if (input[field] > MAX_TRANSFORM_DATA_BYTES) {
      throw new Error(`${label}.${field} exceeds the artifact-vault data ceiling`);
    }
  }
  for (const field of ["max_input_handles", "max_output_artifacts"]) {
    if (input[field] > 64) {
      throw new Error(`${label}.${field} exceeds the vault transform batch count ceiling`);
    }
  }
  if (typeof input.implementation_digest !== "string" || !SHA256_RE.test(input.implementation_digest)) {
    throw new Error(`${label}.implementation_digest must be a lowercase SHA-256 digest`);
  }
  if (input.parameters == null || typeof input.parameters !== "object" || Array.isArray(input.parameters)) {
    throw new Error(`${label}.parameters must be an object`);
  }
  const parameters = {};
  for (const parameterId of Object.keys(input.parameters).sort()) {
    assertIdentifier(parameterId, `${label}.parameters field`);
    const contract = input.parameters[parameterId];
    assertClosedObject(contract, `${label}.parameters.${parameterId}`, ["kind", "required"], ["values", "min", "max"]);
    if (!PARAMETER_KINDS.includes(contract.kind)) {
      throw new Error(`${label}.parameters.${parameterId}.kind is not registered`);
    }
    if (typeof contract.required !== "boolean") {
      throw new Error(`${label}.parameters.${parameterId}.required must be a boolean`);
    }
    const normalized = { kind: contract.kind, required: contract.required };
    if (contract.kind === "enum") {
      const wrong = Object.keys(contract).filter((field) => !["kind", "required", "values"].includes(field));
      if (wrong.length > 0) throw new Error(`${label}.parameters.${parameterId} has fields invalid for enum`);
      normalized.values = normalizeStringSet(
        contract.values,
        `${label}.parameters.${parameterId}.values`,
        { allowEmpty: false },
      );
      normalized.values.forEach((value, index) => assertIdentifier(
        value,
        `${label}.parameters.${parameterId}.values[${index}]`,
      ));
    } else if (contract.kind === "integer" || contract.kind === "number") {
      const wrong = Object.keys(contract).filter((field) => !["kind", "required", "min", "max"].includes(field));
      if (wrong.length > 0) throw new Error(`${label}.parameters.${parameterId} has invalid numeric fields`);
      if (typeof contract.min !== "number" || !Number.isFinite(contract.min)
        || typeof contract.max !== "number" || !Number.isFinite(contract.max)
        || contract.min > contract.max
        || (contract.kind === "integer" && (!Number.isSafeInteger(contract.min) || !Number.isSafeInteger(contract.max)))) {
        throw new Error(`${label}.parameters.${parameterId} requires finite coherent min/max bounds`);
      }
      normalized.min = contract.min;
      normalized.max = contract.max;
    } else {
      const wrong = Object.keys(contract).filter((field) => !["kind", "required"].includes(field));
      if (wrong.length > 0) throw new Error(`${label}.parameters.${parameterId} has fields invalid for boolean`);
    }
    parameters[parameterId] = Object.freeze(normalized);
  }
  return Object.freeze({
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    tool_id: assertIdentifier(input.tool_id, `${label}.tool_id`),
    tool_version: assertIdentifier(input.tool_version, `${label}.tool_version`),
    implementation_digest: input.implementation_digest,
    handler_export: assertIdentifier(input.handler_export, `${label}.handler_export`),
    input_data_classes: normalizeStringSet(
      input.input_data_classes,
      `${label}.input_data_classes`,
      { allowed: ARTIFACT_DATA_CLASSES },
    ),
    output_data_classes: normalizeStringSet(
      input.output_data_classes,
      `${label}.output_data_classes`,
      { allowed: ARTIFACT_DATA_CLASSES },
    ),
    parameters: Object.freeze(parameters),
    max_input_handles: input.max_input_handles,
    max_input_bytes: input.max_input_bytes,
    max_output_artifacts: input.max_output_artifacts,
    max_output_bytes: input.max_output_bytes,
  });
}

function normalizeImplementationModule(value, label) {
  if (typeof value !== "string" || value.length < 1 || value.length > 512 || value.includes("\0")) {
    throw new Error(`${label} must be a bounded relative CommonJS module path`);
  }
  if (path.isAbsolute(value) || value.includes("\\")) {
    throw new Error(`${label} must be a relative slash-delimited module path`);
  }
  const segments = value.split("/");
  if (segments.some((segment) => segment.length === 0 || segment === "." || segment === "..")) {
    throw new Error(`${label} must not contain empty or traversal segments`);
  }
  if (!value.endsWith(".transform.json")) {
    throw new Error(`${label} must name a .transform.json program bundle`);
  }
  return value;
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function assertPrivateImplementationFile(stats, label) {
  if (!stats.isFile() || stats.nlink !== 1) {
    throw new Error(`${label} must be a single-link regular file`);
  }
  if ((stats.mode & 0o077) !== 0) {
    throw new Error(`${label} must not grant group or other permissions`);
  }
  if (typeof process.geteuid === "function" && stats.uid !== process.geteuid()) {
    throw new Error(`${label} must be owned by the effective worker user`);
  }
  if (!Number.isSafeInteger(stats.size) || stats.size < 1 || stats.size > MAX_IMPLEMENTATION_BYTES) {
    throw new Error(`${label} must be between 1 byte and ${MAX_IMPLEMENTATION_BYTES} bytes`);
  }
}

function realpathNative(filePath) {
  return fs.realpathSync.native ? fs.realpathSync.native(filePath) : fs.realpathSync(filePath);
}

function readTrustedImplementation(rootRealPath, implementationModule, label) {
  const lexicalPath = path.resolve(rootRealPath, implementationModule);
  const lexicalRelative = path.relative(rootRealPath, lexicalPath);
  if (lexicalRelative.length === 0 || lexicalRelative.startsWith(`..${path.sep}`)
    || lexicalRelative === ".." || path.isAbsolute(lexicalRelative)) {
    throw new Error(`${label} escapes trusted_implementation_root`);
  }

  let resolvedPath;
  try {
    resolvedPath = realpathNative(lexicalPath);
  } catch (error) {
    throw new Error(`${label} cannot be resolved beneath trusted_implementation_root`, { cause: error });
  }
  const resolvedRelative = path.relative(rootRealPath, resolvedPath);
  if (resolvedRelative.length === 0 || resolvedRelative.startsWith(`..${path.sep}`)
    || resolvedRelative === ".." || path.isAbsolute(resolvedRelative)) {
    throw new Error(`${label} resolves outside trusted_implementation_root`);
  }
  if (resolvedPath !== lexicalPath) {
    throw new Error(`${label} must not traverse symbolic links or non-canonical path aliases`);
  }

  let expected;
  try {
    expected = fs.lstatSync(lexicalPath);
  } catch (error) {
    throw new Error(`${label} cannot be inspected`, { cause: error });
  }
  assertPrivateImplementationFile(expected, label);

  if (typeof fs.constants.O_NOFOLLOW !== "number") {
    throw new Error("transform implementation loading requires O_NOFOLLOW support");
  }
  let descriptor;
  try {
    descriptor = fs.openSync(lexicalPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const before = fs.fstatSync(descriptor);
    assertPrivateImplementationFile(before, label);
    if (!sameFileIdentity(expected, before)) {
      throw new Error(`${label} changed while it was being opened`);
    }
    const sourceBytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    assertPrivateImplementationFile(after, label);
    if (!sameFileIdentity(before, after) || before.size !== after.size
      || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs
      || sourceBytes.length !== after.size) {
      throw new Error(`${label} changed while it was being read`);
    }
    const finalPathState = fs.lstatSync(lexicalPath);
    assertPrivateImplementationFile(finalPathState, label);
    if (!sameFileIdentity(after, finalPathState) || realpathNative(lexicalPath) !== resolvedPath) {
      throw new Error(`${label} changed before verification completed`);
    }
    return Object.freeze({
      digest: crypto.createHash("sha256").update(sourceBytes).digest("hex"),
      resolved_path: resolvedPath,
      source_bytes: sourceBytes,
    });
  } catch (error) {
    if (error && error.code === "ELOOP") {
      throw new Error(`${label} must not be a symbolic link`, { cause: error });
    }
    throw error;
  } finally {
    if (descriptor != null) fs.closeSync(descriptor);
  }
}

function normalizeProgramInputIndex(value, label, manifest) {
  if (!Number.isSafeInteger(value) || value < 0 || value >= manifest.max_input_handles) {
    throw new Error(`${label} must reference a manifest-bounded input index`);
  }
  return value;
}

function normalizeByteExpression(input, label, manifest, state, depth = 0) {
  if (depth > MAX_PROGRAM_EXPRESSION_DEPTH) {
    throw new Error(`${label} exceeds the transform expression depth bound`);
  }
  state.nodes += 1;
  if (state.nodes > MAX_PROGRAM_EXPRESSION_NODES) {
    throw new Error(`${label} exceeds the transform expression node bound`);
  }
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error(`${label} must be a byte expression object`);
  }
  if (input.op === "input_bytes") {
    assertClosedObject(input, label, ["op", "input_index"]);
    return Object.freeze({
      op: "input_bytes",
      input_index: normalizeProgramInputIndex(input.input_index, `${label}.input_index`, manifest),
    });
  }
  if (input.op === "literal_base64") {
    assertClosedObject(input, label, ["op", "value"]);
    if (typeof input.value !== "string" || input.value.length > MAX_IMPLEMENTATION_BYTES * 2
      || !BASE64_RE.test(input.value)
      || Buffer.from(input.value, "base64").toString("base64") !== input.value) {
      throw new Error(`${label}.value must be canonical bounded base64`);
    }
    return Object.freeze({ op: "literal_base64", value: input.value });
  }
  if (input.op === "reverse" || input.op === "sha256") {
    assertClosedObject(input, label, ["op", "value"]);
    return Object.freeze({
      op: input.op,
      value: normalizeByteExpression(input.value, `${label}.value`, manifest, state, depth + 1),
    });
  }
  if (input.op === "slice") {
    assertClosedObject(input, label, ["op", "value", "start", "end"]);
    if (!Number.isSafeInteger(input.start) || input.start < 0
      || !Number.isSafeInteger(input.end) || input.end < input.start) {
      throw new Error(`${label} requires coherent non-negative slice bounds`);
    }
    return Object.freeze({
      op: "slice",
      value: normalizeByteExpression(input.value, `${label}.value`, manifest, state, depth + 1),
      start: input.start,
      end: input.end,
    });
  }
  if (input.op === "concat") {
    assertClosedObject(input, label, ["op", "values"]);
    if (!Array.isArray(input.values) || input.values.length < 1
      || input.values.length > MAX_PROGRAM_CONCAT_VALUES) {
      throw new Error(`${label}.values must be a bounded non-empty array`);
    }
    return Object.freeze({
      op: "concat",
      values: Object.freeze(input.values.map((value, index) => normalizeByteExpression(
        value,
        `${label}.values[${index}]`,
        manifest,
        state,
        depth + 1,
      ))),
    });
  }
  throw new Error(`${label}.op is not a registered transform byte operation`);
}

function normalizeOutputAttribute(input, label, manifest, kind) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error(`${label} must be an output attribute expression`);
  }
  const inputOperation = kind === "data_class" ? "input_data_class" : "input_media_type";
  if (input.op === inputOperation) {
    assertClosedObject(input, label, ["op", "input_index"]);
    return Object.freeze({
      op: inputOperation,
      input_index: normalizeProgramInputIndex(input.input_index, `${label}.input_index`, manifest),
    });
  }
  if (input.op === "literal") {
    assertClosedObject(input, label, ["op", "value"]);
    if (kind === "data_class" && !ARTIFACT_DATA_CLASSES.includes(input.value)) {
      throw new Error(`${label}.value is not a registered artifact data class`);
    }
    if (kind === "media_type" && (typeof input.value !== "string" || !MEDIA_TYPE_RE.test(input.value))) {
      throw new Error(`${label}.value must be a lowercase media type`);
    }
    return Object.freeze({ op: "literal", value: input.value });
  }
  throw new Error(`${label}.op is not registered for ${kind}`);
}

function parseTransformProgram(verified, handlerExport, manifest, label) {
  let bundle;
  try {
    bundle = JSON.parse(verified.source_bytes.toString("utf8"));
  } catch (error) {
    throw new Error(`${label} must contain JSON data, not executable module code`, { cause: error });
  }
  assertClosedObject(bundle, label, ["version", "programs"]);
  if (bundle.version !== 1) throw new Error(`${label}.version must be 1`);
  if (bundle.programs == null || typeof bundle.programs !== "object" || Array.isArray(bundle.programs)) {
    throw new Error(`${label}.programs must be an object`);
  }
  const programIds = Object.keys(bundle.programs).sort();
  if (programIds.length < 1 || programIds.length > 1024) {
    throw new Error(`${label}.programs must contain between 1 and 1024 programs`);
  }
  for (const programId of programIds) assertIdentifier(programId, `${label}.programs field`);
  if (!Object.prototype.hasOwnProperty.call(bundle.programs, handlerExport)) {
    throw new Error(`${label}.${handlerExport} must name an owned declarative transform program`);
  }
  const input = bundle.programs[handlerExport];
  assertClosedObject(input, `${label}.programs.${handlerExport}`, ["version", "outputs"]);
  if (input.version !== 1) throw new Error(`${label}.programs.${handlerExport}.version must be 1`);
  if (!Array.isArray(input.outputs) || input.outputs.length < 1
    || input.outputs.length > manifest.max_output_artifacts) {
    throw new Error(`${label}.programs.${handlerExport}.outputs must fit the manifest output bound`);
  }
  const state = { nodes: 0 };
  return Object.freeze({
    version: 1,
    outputs: Object.freeze(input.outputs.map((output, index) => {
      const outputLabel = `${label}.programs.${handlerExport}.outputs[${index}]`;
      assertClosedObject(output, outputLabel, ["plaintext", "data_class", "media_type"]);
      return Object.freeze({
        plaintext: normalizeByteExpression(output.plaintext, `${outputLabel}.plaintext`, manifest, state),
        data_class: normalizeOutputAttribute(output.data_class, `${outputLabel}.data_class`, manifest, "data_class"),
        media_type: normalizeOutputAttribute(output.media_type, `${outputLabel}.media_type`, manifest, "media_type"),
      });
    })),
  });
}

function evaluateByteExpression(expression, inputs) {
  if (expression.op === "input_bytes") {
    const input = inputs[expression.input_index];
    if (!input) throw new Error("transform program referenced an absent input");
    return Buffer.from(input.bytes);
  }
  if (expression.op === "literal_base64") return Buffer.from(expression.value, "base64");
  if (expression.op === "reverse") return evaluateByteExpression(expression.value, inputs).reverse();
  if (expression.op === "sha256") {
    const value = evaluateByteExpression(expression.value, inputs);
    try {
      return crypto.createHash("sha256").update(value).digest();
    } finally {
      value.fill(0);
    }
  }
  if (expression.op === "slice") {
    const value = evaluateByteExpression(expression.value, inputs);
    try {
      if (expression.end > value.length) throw new Error("transform program slice exceeds its value");
      return Buffer.from(value.subarray(expression.start, expression.end));
    } finally {
      value.fill(0);
    }
  }
  const values = [];
  try {
    for (const value of expression.values) values.push(evaluateByteExpression(value, inputs));
    return Buffer.concat(values);
  } finally {
    for (const value of values) value.fill(0);
  }
}

function evaluateOutputAttribute(expression, inputs, field) {
  if (expression.op === "literal") return expression.value;
  const input = inputs[expression.input_index];
  if (!input) throw new Error("transform program referenced an absent input attribute");
  return input[field];
}

function checkedAdd(left, right, label) {
  if (!Number.isSafeInteger(left) || !Number.isSafeInteger(right) || left < 0 || right < 0
    || left > Number.MAX_SAFE_INTEGER - right) {
    throw new Error(`${label} exceeds safe integer accounting`);
  }
  return left + right;
}

function checkedScale(value, factor, ceiling) {
  if (value === 0) return 0;
  if (value > Math.floor(ceiling / factor)) return ceiling;
  return value * factor;
}

function analyzeByteExpression(expression, inputs) {
  if (expression.op === "input_bytes") {
    const input = inputs[expression.input_index];
    if (!input) throw new Error("transform program referenced an absent input");
    return { length: input.bytes.length, allocation: input.bytes.length, work: input.bytes.length };
  }
  if (expression.op === "literal_base64") {
    const length = Buffer.byteLength(expression.value, "base64");
    return { length, allocation: length, work: length };
  }
  if (expression.op === "reverse") {
    const child = analyzeByteExpression(expression.value, inputs);
    return {
      length: child.length,
      allocation: child.allocation,
      work: checkedAdd(child.work, child.length, "transform expression work"),
    };
  }
  if (expression.op === "sha256") {
    const child = analyzeByteExpression(expression.value, inputs);
    return {
      length: 32,
      allocation: checkedAdd(child.allocation, 32, "transform expression allocation"),
      work: checkedAdd(child.work, child.length, "transform expression work"),
    };
  }
  if (expression.op === "slice") {
    const child = analyzeByteExpression(expression.value, inputs);
    if (expression.end > child.length) throw new Error("transform program slice exceeds its value");
    const length = expression.end - expression.start;
    return {
      length,
      allocation: checkedAdd(child.allocation, length, "transform expression allocation"),
      work: checkedAdd(child.work, length, "transform expression work"),
    };
  }
  let length = 0;
  let allocation = 0;
  let work = 0;
  for (const value of expression.values) {
    const child = analyzeByteExpression(value, inputs);
    length = checkedAdd(length, child.length, "transform expression output length");
    allocation = checkedAdd(allocation, child.allocation, "transform expression allocation");
    work = checkedAdd(work, child.work, "transform expression work");
  }
  return {
    length,
    allocation: checkedAdd(allocation, length, "transform expression allocation"),
    work: checkedAdd(work, length, "transform expression work"),
  };
}

function preflightProgram(program, manifest, inputs) {
  let inputBytes = 0;
  for (const input of inputs) {
    inputBytes = checkedAdd(inputBytes, input.bytes.length, "transform input accounting");
  }
  let outputBytes = 0;
  let allocation = 0;
  let work = 0;
  for (const output of program.outputs) {
    const analysis = analyzeByteExpression(output.plaintext, inputs);
    outputBytes = checkedAdd(outputBytes, analysis.length, "transform output accounting");
    allocation = checkedAdd(allocation, analysis.allocation, "transform allocation accounting");
    work = checkedAdd(work, analysis.work, "transform work accounting");
  }
  if (outputBytes > manifest.max_output_bytes) {
    throw new Error("transform program output exceeds the manifest byte ceiling before execution");
  }
  const liveDataBytes = checkedAdd(inputBytes, outputBytes, "transform live-data accounting");
  const allocationBudget = checkedScale(liveDataBytes, 4, MAX_TRANSFORM_ALLOCATION_BYTES);
  const workBudget = checkedScale(liveDataBytes, 8, MAX_TRANSFORM_WORK_BYTES);
  if (allocation > allocationBudget) {
    throw new Error("transform program exceeds its preflight allocation budget");
  }
  if (work > workBudget) {
    throw new Error("transform program exceeds its preflight work budget");
  }
}

function createProgramHandler(program, manifest) {
  return function runDeclarativeTransform({ inputs }) {
    preflightProgram(program, manifest, inputs);
    const outputs = [];
    try {
      for (const output of program.outputs) {
        let plaintext = evaluateByteExpression(output.plaintext, inputs);
        try {
          outputs.push({
            plaintext,
            data_class: evaluateOutputAttribute(output.data_class, inputs, "data_class"),
            media_type: evaluateOutputAttribute(output.media_type, inputs, "media_type"),
          });
          plaintext = null;
        } finally {
          if (plaintext) plaintext.fill(0);
        }
      }
      return { outputs };
    } catch (error) {
      for (const output of outputs) output.plaintext.fill(0);
      throw error;
    }
  };
}

function attachRollbackFailures(error, failures) {
  let target = error instanceof Error ? error : new Error(String(error), { cause: error });
  try {
    Object.defineProperty(target, "rollback_failures", {
      value: Object.freeze([...failures]),
      enumerable: false,
    });
  } catch (attachmentError) {
    target = new Error(target.message, { cause: target });
    Object.defineProperty(target, "rollback_failures", {
      value: Object.freeze([...failures, attachmentError.message || String(attachmentError)]),
      enumerable: false,
    });
  }
  return target;
}

function createTransformRegistry(definitions, transformPolicy) {
  const policyState = resolveOperatorTransformPolicy(transformPolicy);
  if (!Array.isArray(definitions) || definitions.length > 1024) {
    throw new Error("transform definitions must be an array with at most 1024 entries");
  }
  const rootRealPath = policyState.root_identity.real_path;
  const trustedDigests = policyState.trusted_implementation_digests;
  const trusted = new Set(trustedDigests);
  const entries = new Map();
  for (let index = 0; index < definitions.length; index += 1) {
    const definition = definitions[index];
    assertClosedObject(
      definition,
      `transform_definitions[${index}]`,
      ["manifest", "implementation_module"],
    );
    const baseManifest = normalizeManifest(definition.manifest, `transform_definitions[${index}].manifest`);
    if (Object.keys(baseManifest.parameters).length > 0) {
      throw new Error(
        `transform_definitions[${index}].manifest.parameters must be empty until declarative parameter operations exist`,
      );
    }
    const implementationModule = normalizeImplementationModule(
      definition.implementation_module,
      `transform_definitions[${index}].implementation_module`,
    );
    const verified = readTrustedImplementation(
      rootRealPath,
      implementationModule,
      `transform_definitions[${index}].implementation_module`,
    );
    if (verified.digest !== baseManifest.implementation_digest
      || !trusted.has(verified.digest)) {
      throw new Error(`transform_definitions[${index}] implementation bytes are not digest-allowlisted`);
    }
    const program = parseTransformProgram(
      verified,
      baseManifest.handler_export,
      baseManifest,
      `transform_definitions[${index}].implementation_module`,
    );
    const handler = createProgramHandler(program, baseManifest);
    if (entries.has(baseManifest.tool_id)) throw new Error(`duplicate transform tool ID ${baseManifest.tool_id}`);
    entries.set(baseManifest.tool_id, Object.freeze({
      manifest: Object.freeze({
        ...baseManifest,
        tool_digest: manifestDigest(baseManifest),
      }),
      handler,
    }));
  }
  const ids = Object.freeze([...entries.keys()].sort());
  const orderedManifests = ids.map((id) => entries.get(id).manifest);
  const registryDigest = manifestDigest({
    version: 1,
    transform_policy_authority_id: policyState.public_basis.policy_authority_id,
    transform_policy_authority_digest: policyState.public_basis.policy_authority_digest,
    transform_policy_id: policyState.public_basis.policy_id,
    transform_policy_epoch: policyState.public_basis.policy_epoch,
    transform_policy_digest: policyState.policy_digest,
    manifests: orderedManifests,
  });
  const registry = Object.freeze({
    version: 1,
    registry_digest: registryDigest,
    transform_policy_authority_id: policyState.public_basis.policy_authority_id,
    transform_policy_authority_digest: policyState.public_basis.policy_authority_digest,
    transform_policy_id: policyState.public_basis.policy_id,
    transform_policy_epoch: policyState.public_basis.policy_epoch,
    transform_policy_digest: policyState.policy_digest,
    ids() { return ids; },
    manifest(toolId) {
      const entry = entries.get(toolId);
      return entry ? entry.manifest : null;
    },
  });
  TRANSFORM_REGISTRY_ENTRIES.set(registry, Object.freeze({
    entries,
    policy: transformPolicy,
    policy_authority_id: policyState.public_basis.policy_authority_id,
    policy_authority_digest: policyState.public_basis.policy_authority_digest,
    policy_id: policyState.public_basis.policy_id,
    policy_epoch: policyState.public_basis.policy_epoch,
    policy_digest: policyState.policy_digest,
  }));
  return registry;
}

function normalizeParameters(parameters, manifest) {
  if (parameters == null) parameters = {};
  if (typeof parameters !== "object" || Array.isArray(parameters)) {
    throw new Error("transform parameters must be an object");
  }
  const allowed = new Set(Object.keys(manifest.parameters));
  const unknown = Object.keys(parameters).filter((key) => !allowed.has(key)).sort();
  if (unknown.length > 0) throw new Error(`transform parameters have unknown keys: ${unknown.join(", ")}`);
  const missing = Object.entries(manifest.parameters)
    .filter(([, contract]) => contract.required)
    .map(([key]) => key)
    .filter((key) => !Object.prototype.hasOwnProperty.call(parameters, key));
  if (missing.length > 0) throw new Error(`transform parameters are missing: ${missing.sort().join(", ")}`);
  const normalized = {};
  for (const [key, value] of Object.entries(parameters)) {
    const contract = manifest.parameters[key];
    if (contract.kind === "boolean") {
      if (typeof value !== "boolean") throw new Error(`transform parameter ${key} must be boolean`);
    } else if (contract.kind === "enum") {
      if (typeof value !== "string" || !contract.values.includes(value)) {
        throw new Error(`transform parameter ${key} must be a registered enum value`);
      }
    } else if (typeof value !== "number" || !Number.isFinite(value)
      || value < contract.min || value > contract.max
      || (contract.kind === "integer" && !Number.isSafeInteger(value))) {
      throw new Error(`transform parameter ${key} exceeds its numeric contract`);
    }
    normalized[key] = value;
  }
  if (Buffer.byteLength(canonicalJson(parameters), "utf8") > 4096) {
    throw new Error("transform parameters exceed the public bound");
  }
  return Object.freeze(normalized);
}

function runTransform({
  registry,
  registry_digest: registryDigest,
  vault,
  transform_attempt_ref: transformAttemptRef,
  tool_id: toolId,
  tool_digest: toolDigest,
  input_handles: inputHandles,
  outputs: outputBindings,
  parameters = {},
}) {
  const registryState = registry && TRANSFORM_REGISTRY_ENTRIES.get(registry);
  if (!registryState) {
    throw new Error("registry is not a transform registry");
  }
  const currentPolicy = resolveOperatorTransformPolicy(registryState.policy);
  if (currentPolicy.public_basis.policy_authority_id !== registryState.policy_authority_id
    || currentPolicy.public_basis.policy_authority_digest !== registryState.policy_authority_digest
    || currentPolicy.public_basis.policy_id !== registryState.policy_id
    || currentPolicy.public_basis.policy_epoch !== registryState.policy_epoch
    || currentPolicy.policy_digest !== registryState.policy_digest
    || registry.transform_policy_authority_id !== registryState.policy_authority_id
    || registry.transform_policy_authority_digest !== registryState.policy_authority_digest
    || registry.transform_policy_id !== registryState.policy_id
    || registry.transform_policy_epoch !== registryState.policy_epoch
    || registry.transform_policy_digest !== registryState.policy_digest) {
    throw new Error("transform registry policy drifted after operator enrollment");
  }
  const registryEntries = registryState.entries;
  if (typeof registryDigest !== "string" || !SHA256_RE.test(registryDigest)
    || registryDigest !== registry.registry_digest) {
    throw new Error("transform registry digest is absent or drifted");
  }
  const entry = registryEntries.get(toolId);
  if (!entry) throw new Error(`transform tool is not allowlisted: ${toolId}`);
  const manifest = entry.manifest;
  if (typeof toolDigest !== "string" || !SHA256_RE.test(toolDigest) || toolDigest !== manifest.tool_digest) {
    throw new Error("transform tool digest is absent or drifted");
  }
  if (!hasVaultWorkerAccess(vault)) throw new Error("vault lacks worker-only access");
  if (!Array.isArray(inputHandles) || inputHandles.length < 1
    || inputHandles.length > manifest.max_input_handles) {
    throw new Error("transform input handle count is outside the manifest bound");
  }
  if (new Set(inputHandles).size !== inputHandles.length
    || inputHandles.some((handle) => typeof handle !== "string" || !PUBLIC_ARTIFACT_HANDLE_RE.test(handle))) {
    throw new Error("transform input handles must be unique opaque vault handles");
  }
  if (!Array.isArray(outputBindings) || outputBindings.length < 1
    || outputBindings.length > manifest.max_output_artifacts) {
    throw new Error("transform output binding count is outside the manifest bound");
  }
  for (const [index, output] of outputBindings.entries()) {
    assertClosedObject(output, `outputs[${index}]`, ["reservation_handle", "metadata"]);
    if (typeof output.reservation_handle !== "string"
      || !PUBLIC_RESERVATION_HANDLE_RE.test(output.reservation_handle)) {
      throw new Error(`outputs[${index}].reservation_handle is invalid`);
    }
  }
  const normalizedParameters = normalizeParameters(parameters, manifest);
  const normalizedTransformAttemptRef = assertOpaqueRef(
    transformAttemptRef,
    "transform_attempt_ref",
  );
  const batchRef = `transform-batch:v1:${manifestDigest({
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    transform_attempt_ref: normalizedTransformAttemptRef,
  })}`;
  const bindingDigest = manifestDigest({
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    transform_attempt_ref: normalizedTransformAttemptRef,
    registry_digest: registryDigest,
    tool_id: manifest.tool_id,
    tool_digest: manifest.tool_digest,
    input_handles: inputHandles,
    output_bindings: outputBindings,
    parameters: normalizedParameters,
  });

  function completedResult(outputs) {
    return Object.freeze({
      tool_id: manifest.tool_id,
      tool_version: manifest.tool_version,
      tool_digest: manifest.tool_digest,
      status: "completed",
      input_handle_count: inputHandles.length,
      output_handle_count: outputs.length,
      outputs: Object.freeze(outputs),
    });
  }

  const inputHandlesDigest = manifestDigest({
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    input_handles: inputHandles,
  });
  const claimedOutputBindings = outputBindings.map((binding) => Object.freeze({
    reservation_handle: binding.reservation_handle,
    metadata: Object.freeze({
      ...binding.metadata,
      transform_provenance: {
        tool_id: manifest.tool_id,
        tool_version: manifest.tool_version,
        tool_digest: manifest.tool_digest,
        input_handle_count: inputHandles.length,
        batch_ref: batchRef,
        input_handles_digest: inputHandlesDigest,
      },
    }),
  }));

  const claim = claimTransformAttemptForWorker(vault, {
    batch_ref: batchRef,
    binding_digest: bindingDigest,
    input_handles: inputHandles,
    outputs: claimedOutputBindings,
  });
  if (claim.status === "committed") {
    if (!claim.outputs_retained || !claim.outputs) {
      throw new Error("transform attempt is committed and fenced but its outputs are no longer retained");
    }
    return completedResult(claim.outputs);
  }
  if (claim.status !== "claimed" || typeof claim.claim_token !== "string") {
    throw new Error("transform attempt claim did not yield an executable claim token");
  }
  const claimToken = claim.claim_token;

  const inputs = [];
  const handlerOutputBuffers = [];
  let totalInputBytes = 0;
  try {
    for (const handle of inputHandles) {
      const materialized = materializeForWorker(vault, handle);
      if (!manifest.input_data_classes.includes(materialized.metadata.data_class)) {
        materialized.plaintext.fill(0);
        throw new Error(`transform tool does not accept ${materialized.metadata.data_class} inputs`);
      }
      totalInputBytes += materialized.plaintext.length;
      if (totalInputBytes > manifest.max_input_bytes) {
        materialized.plaintext.fill(0);
        throw new Error("transform inputs exceed the manifest byte ceiling");
      }
      inputs.push(materialized);
    }

    const handlerResult = entry.handler(Object.freeze({
      inputs: Object.freeze(inputs.map((item) => Object.freeze({
        bytes: item.plaintext,
        data_class: item.metadata.data_class,
        media_type: item.metadata.media_type,
      }))),
      parameters: normalizedParameters,
    }));
    if (!handlerResult || typeof handlerResult !== "object" || Array.isArray(handlerResult)
      || Object.keys(handlerResult).some((key) => key !== "outputs")
      || !Array.isArray(handlerResult.outputs)) {
      throw new Error("transform handler must return only an outputs array");
    }
    for (const output of handlerResult.outputs) {
      if (output && Buffer.isBuffer(output.plaintext)) handlerOutputBuffers.push(output.plaintext);
    }
    if (handlerResult.outputs.length !== outputBindings.length
      || handlerResult.outputs.length > manifest.max_output_artifacts) {
      throw new Error("transform handler output count does not match reserved bindings");
    }
    let totalOutputBytes = 0;
    const batchEntries = [];
    for (let index = 0; index < handlerResult.outputs.length; index += 1) {
      const output = handlerResult.outputs[index];
      assertClosedObject(output, `handler.outputs[${index}]`, ["plaintext", "data_class", "media_type"]);
      if (!Buffer.isBuffer(output.plaintext)) throw new Error(`handler.outputs[${index}].plaintext must be a Buffer`);
      if (!manifest.output_data_classes.includes(output.data_class)) {
        output.plaintext.fill(0);
        throw new Error(`transform tool cannot emit ${output.data_class}`);
      }
      totalOutputBytes += output.plaintext.length;
      if (totalOutputBytes > manifest.max_output_bytes) {
        output.plaintext.fill(0);
        throw new Error("transform outputs exceed the manifest byte ceiling");
      }
      const binding = claimedOutputBindings[index];
      if (binding.metadata.data_class !== output.data_class || binding.metadata.media_type !== output.media_type) {
        output.plaintext.fill(0);
        throw new Error("transform output content type does not match its reserved metadata");
      }
      batchEntries.push({
        reservation_handle: binding.reservation_handle,
        metadata: binding.metadata,
        plaintext: output.plaintext,
      });
    }
    const committed = ingestTransformBatchForWorker(vault, {
      batch_ref: batchRef,
      binding_digest: bindingDigest,
      claim_token: claimToken,
      entries: batchEntries,
    });
    return completedResult(committed.outputs);
  } catch (error) {
    const rollbackFailures = [];
    // A durable claim already fenced this attempt before plaintext execution.
    // Reconcile it before terminalizing or compensating any reservations.
    let attempt;
    try {
      attempt = inspectTransformAttemptForWorker(vault, batchRef, bindingDigest);
    } catch (reconcileError) {
      rollbackFailures.push(reconcileError.message || String(reconcileError));
      throw attachRollbackFailures(error, rollbackFailures);
    }
    if (!attempt) {
      rollbackFailures.push("durable transform attempt claim disappeared during reconciliation");
      throw attachRollbackFailures(error, rollbackFailures);
    }
    if (attempt.status === "committed") {
      if (attempt.outputs_retained && attempt.outputs) return completedResult(attempt.outputs);
      rollbackFailures.push("transform committed but its output descriptors are no longer retained");
      throw attachRollbackFailures(error, rollbackFailures);
    }
    if (attempt.status === "claimed") {
      const failureDigest = manifestDigest({
        version: ARTIFACT_VAULT_SCHEMA_VERSION,
        error_name: error && error.name ? String(error.name).slice(0, 128) : "Error",
        error_message: error && error.message ? String(error.message).slice(0, 1024) : String(error).slice(0, 1024),
      });
      try {
        attempt = failTransformAttemptForWorker(vault, {
          batch_ref: batchRef,
          binding_digest: bindingDigest,
          claim_token: claimToken,
          failure_digest: failureDigest,
          failure_kind: "precommit_failure",
        });
      } catch (terminalError) {
        rollbackFailures.push(terminalError.message || String(terminalError));
        throw attachRollbackFailures(error, rollbackFailures);
      }
      if (attempt.status === "committed") {
        if (attempt.outputs_retained && attempt.outputs) return completedResult(attempt.outputs);
        rollbackFailures.push("transform committed during terminal reconciliation but outputs are unavailable");
        throw attachRollbackFailures(error, rollbackFailures);
      }
    }
    if (attempt.status !== "failed") {
      rollbackFailures.push(`transform attempt reconciliation returned unexpected state ${attempt.status}`);
      throw attachRollbackFailures(error, rollbackFailures);
    }
    // Failure publication and claimed-output release are one durable vault
    // mutation. There is no separate compensation window here: the vault
    // deletes any preallocated ciphertext only after that mutation commits.
    throw error;
  } finally {
    for (const input of inputs) input.plaintext.fill(0);
    for (const output of handlerOutputBuffers) output.fill(0);
  }
}

module.exports = {
  createTransformRegistry,
  runTransform,
};
