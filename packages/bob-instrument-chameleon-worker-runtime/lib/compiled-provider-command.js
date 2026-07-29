"use strict";

// Package-private one-shot command capabilities. A compiler owns one channel;
// only that channel can mint, validate, consume, or invalidate its commands.
// Raw request bytes live solely in the channel's sealed WeakMap state and are
// copied exactly once across the enrolled native-driver boundary.

const crypto = require("node:crypto");
const {
  isPromise,
  isProxy,
} = require("node:util").types;

const {
  hashCanonicalJson,
} = require("./closed-runtime-contracts.js");

const COMPILED_PROVIDER_COMMAND_VERSION = 1;
const COMPILED_PROVIDER_COMMAND_KIND = "compiled_provider_command_capability";
const REQUEST_DIGEST_DOMAIN =
  "hacker-bob/compiled-provider-command-private-request/v1";
const CHANNEL_BINDING_FIELDS = Object.freeze([
  "version",
  "provider_id",
  "compiler_id",
  "compiler_manifest_digest",
  "compiler_registry_digest",
  "source_profile_digest",
  "operation_id",
  "capability_id",
  "runtime_availability",
]);
const COMMAND_INPUT_FIELDS = Object.freeze([
  "schema_id",
  "variant_id",
  "parameter_selector_id",
  "canonical_command_digest",
  "compiled_operation_digest",
  "request_bytes",
  "maximum_response_bytes",
  "timeout_ms",
]);
const COMMAND_PUBLIC_FIELDS = Object.freeze([
  "version",
  "kind",
  "compiled_command_id",
  "provider_id",
  "compiler_id",
  "compiler_manifest_digest",
  "compiler_registry_digest",
  "source_profile_digest",
  "schema_id",
  "operation_id",
  "capability_id",
  "variant_id",
  "parameter_selector_id",
  "canonical_command_digest",
  "compiled_operation_digest",
  "compiled_command_capability_digest",
  "runtime_availability",
  "execution_authority",
  "production_ready",
  "toJSON",
]);
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;

function commandError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || isProxy(value) || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertClosedDataObject(value, label, required) {
  if (!isPlainObject(value)) throw new Error(`${label} must be a plain data object`);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some((field) => typeof field !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const unknown = keys.filter((field) => !required.includes(field)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = required.filter((field) => !Object.prototype.hasOwnProperty.call(descriptors, field));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  for (const field of keys) {
    const descriptor = descriptors[field];
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || !descriptor.enumerable) {
      throw new Error(`${label}.${field} must be an enumerable data field`);
    }
  }
  return descriptors;
}

function assertBoundedString(value, label) {
  if (typeof value !== "string" || value.length < 1
      || Buffer.byteLength(value, "utf8") > 256) {
    throw new Error(`${label} must be a non-empty bounded string`);
  }
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !DIGEST_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertPositiveInteger(value, label, maximum) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new Error(`${label} must be a positive bounded integer`);
  }
  return value;
}

function requestDigest(bytes) {
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(bytes.length, 0);
  try {
    return crypto.createHash("sha256")
      .update(REQUEST_DIGEST_DOMAIN, "utf8")
      .update(Buffer.from([0]))
      .update(length)
      .update(bytes)
      .digest("hex");
  } finally {
    length.fill(0);
  }
}

function rejectSerialization() {
  throw commandError("compiled_provider_command_not_serializable");
}

function isAsyncCommandForm(value) {
  if (isPromise(value)) return true;
  if (value == null || (typeof value !== "object" && typeof value !== "function")) return false;
  const descriptor = Object.getOwnPropertyDescriptor(value, "then");
  return descriptor != null;
}

function createCompiledProviderCommandChannel(bindingInput) {
  if (arguments.length !== 1) {
    throw new Error("compiled provider command channel requires one binding");
  }
  const bindingDescriptors = assertClosedDataObject(
    bindingInput,
    "compiled_provider_command_channel_binding",
    CHANNEL_BINDING_FIELDS,
  );
  if (bindingDescriptors.version.value !== COMPILED_PROVIDER_COMMAND_VERSION) {
    throw new Error(
      `compiled_provider_command_channel_binding.version must be ${COMPILED_PROVIDER_COMMAND_VERSION}`,
    );
  }
  const channelBinding = Object.freeze({
    version: COMPILED_PROVIDER_COMMAND_VERSION,
    provider_id: assertBoundedString(bindingDescriptors.provider_id.value, "provider_id"),
    compiler_id: assertBoundedString(bindingDescriptors.compiler_id.value, "compiler_id"),
    compiler_manifest_digest: assertDigest(
      bindingDescriptors.compiler_manifest_digest.value,
      "compiler_manifest_digest",
    ),
    compiler_registry_digest: assertDigest(
      bindingDescriptors.compiler_registry_digest.value,
      "compiler_registry_digest",
    ),
    source_profile_digest: assertDigest(
      bindingDescriptors.source_profile_digest.value,
      "source_profile_digest",
    ),
    operation_id: assertBoundedString(bindingDescriptors.operation_id.value, "operation_id"),
    capability_id: assertBoundedString(bindingDescriptors.capability_id.value, "capability_id"),
    runtime_availability: assertBoundedString(
      bindingDescriptors.runtime_availability.value,
      "runtime_availability",
    ),
  });
  const commands = new WeakSet();
  const commandState = new WeakMap();

  function untrustedCommandError(value) {
    if (isProxy(value)) return commandError("compiled_provider_command_proxy");
    if (isAsyncCommandForm(value)) return commandError("compiled_provider_command_async");
    if (value != null && typeof value === "object") {
      const descriptor = Object.getOwnPropertyDescriptor(value, "compiler_manifest_digest");
      if (descriptor && Object.prototype.hasOwnProperty.call(descriptor, "value")
          && typeof descriptor.value === "string"
          && descriptor.value !== channelBinding.compiler_manifest_digest) {
        return commandError("compiled_provider_command_cross_manifest");
      }
    }
    return commandError("compiled_provider_command_untrusted");
  }

  function validateBrandedCommand(value) {
    if (isProxy(value) || isAsyncCommandForm(value)) throw untrustedCommandError(value);
    const state = value == null ? null : commandState.get(value);
    if (!value || !state || !commands.has(value)) throw untrustedCommandError(value);
    if (!Object.isFrozen(value)) throw commandError("compiled_provider_command_corrupt");
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== COMMAND_PUBLIC_FIELDS.length
        || keys.some((field) => typeof field !== "string" || !COMMAND_PUBLIC_FIELDS.includes(field))) {
      throw commandError("compiled_provider_command_corrupt");
    }
    for (const field of COMMAND_PUBLIC_FIELDS) {
      const descriptor = descriptors[field];
      if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
          || !descriptor.enumerable || descriptor.writable || descriptor.configurable
          || descriptor.value !== state.public_projection[field]) {
        throw commandError("compiled_provider_command_corrupt");
      }
    }
    if (state.status === "consumed") throw commandError("compiled_provider_command_replayed");
    if (state.status === "stale") throw commandError("compiled_provider_command_stale");
    if (state.status !== "active" || !Buffer.isBuffer(state.request_bytes)
        || state.request_bytes.length !== state.private_basis.request_byte_length
        || requestDigest(state.request_bytes) !== state.private_basis.provider_request_digest
        || hashCanonicalJson(state.private_basis)
          !== state.public_projection.compiled_command_capability_digest) {
      throw commandError("compiled_provider_command_corrupt");
    }
    return state;
  }

  function mint(input) {
    if (arguments.length !== 1) {
      throw new Error("compiled provider command minting requires one closed command");
    }
    const descriptors = assertClosedDataObject(
      input,
      "compiled_provider_command_input",
      COMMAND_INPUT_FIELDS,
    );
    const suppliedBytes = descriptors.request_bytes.value;
    if (!Buffer.isBuffer(suppliedBytes) || suppliedBytes.length < 1
        || suppliedBytes.length > 16 * 1024) {
      throw new Error("compiled_provider_command_input.request_bytes must be bounded private bytes");
    }
    const sealedBytes = Buffer.from(suppliedBytes);
    try {
      // The opaque-reference contract requires the value after `:` to start
      // with an alphanumeric character.  Raw base64url can begin with `-` or
      // `_`, making command minting fail nondeterministically.  A fixed,
      // versioned alphanumeric prefix preserves all 144 random bits while
      // making every generated identifier valid by construction.
      const compiledCommandId =
        `compiled-command:v1-${crypto.randomBytes(18).toString("base64url")}`;
      const privateBasis = Object.freeze({
        ...channelBinding,
        compiled_command_id: compiledCommandId,
        schema_id: assertBoundedString(descriptors.schema_id.value, "schema_id"),
        variant_id: assertBoundedString(descriptors.variant_id.value, "variant_id"),
        parameter_selector_id: assertBoundedString(
          descriptors.parameter_selector_id.value,
          "parameter_selector_id",
        ),
        canonical_command_digest: assertDigest(
          descriptors.canonical_command_digest.value,
          "canonical_command_digest",
        ),
        compiled_operation_digest: assertDigest(
          descriptors.compiled_operation_digest.value,
          "compiled_operation_digest",
        ),
        provider_request_digest: requestDigest(sealedBytes),
        request_byte_length: sealedBytes.length,
        maximum_response_bytes: assertPositiveInteger(
          descriptors.maximum_response_bytes.value,
          "maximum_response_bytes",
          16 * 1024,
        ),
        timeout_ms: assertPositiveInteger(descriptors.timeout_ms.value, "timeout_ms", 60_000),
      });
      const publicProjection = Object.freeze({
        version: privateBasis.version,
        kind: COMPILED_PROVIDER_COMMAND_KIND,
        compiled_command_id: privateBasis.compiled_command_id,
        provider_id: privateBasis.provider_id,
        compiler_id: privateBasis.compiler_id,
        compiler_manifest_digest: privateBasis.compiler_manifest_digest,
        compiler_registry_digest: privateBasis.compiler_registry_digest,
        source_profile_digest: privateBasis.source_profile_digest,
        schema_id: privateBasis.schema_id,
        operation_id: privateBasis.operation_id,
        capability_id: privateBasis.capability_id,
        variant_id: privateBasis.variant_id,
        parameter_selector_id: privateBasis.parameter_selector_id,
        canonical_command_digest: privateBasis.canonical_command_digest,
        compiled_operation_digest: privateBasis.compiled_operation_digest,
        compiled_command_capability_digest: hashCanonicalJson(privateBasis),
        runtime_availability: privateBasis.runtime_availability,
        execution_authority: false,
        production_ready: false,
        toJSON: rejectSerialization,
      });
      const state = Object.seal({
        status: "active",
        private_basis: privateBasis,
        public_projection: publicProjection,
        request_bytes: sealedBytes,
      });
      commands.add(publicProjection);
      commandState.set(publicProjection, state);
      return publicProjection;
    } catch (error) {
      sealedBytes.fill(0);
      throw error;
    }
  }

  function assertCommand(value) {
    if (arguments.length !== 1) {
      throw new Error("compiled provider command assertion requires one command");
    }
    validateBrandedCommand(value);
    return value;
  }

  function claim(value) {
    if (arguments.length !== 1) {
      throw new Error("compiled provider command claim requires one command");
    }
    const state = validateBrandedCommand(value);
    const requestBytes = Buffer.from(state.request_bytes);
    state.request_bytes.fill(0);
    state.request_bytes = null;
    state.status = "consumed";
    return Object.seal({
      ...state.private_basis,
      compiled_command_capability_digest:
        state.public_projection.compiled_command_capability_digest,
      request_bytes: requestBytes,
    });
  }

  function invalidate(value) {
    if (arguments.length !== 1) {
      throw new Error("compiled provider command invalidation requires one command");
    }
    if (isProxy(value) || isAsyncCommandForm(value)) throw untrustedCommandError(value);
    const state = value == null ? null : commandState.get(value);
    if (!value || !state || !commands.has(value)) throw untrustedCommandError(value);
    if (state.status !== "active") return false;
    state.request_bytes.fill(0);
    state.request_bytes = null;
    state.status = "stale";
    return true;
  }

  return Object.freeze({ assertCommand, claim, invalidate, mint });
}

module.exports = {
  createCompiledProviderCommandChannel,
};
