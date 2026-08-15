"use strict";

// Private in-process resolver port for PH-IP1. The MCP schema never carries a
// raw scope envelope, verifier, effect registry, signature, or file path. A
// host integration may install this resolver before dispatch; the default is a
// hard failure before any session write.

const {
  normalizePhysicalScopeImportRef,
} = require("../../lib/physical-session-identity.js");
const { types: utilTypes } = require("node:util");

const REQUIRED_RESULT_FIELDS = Object.freeze([
  "effect_template_registry",
  "envelope",
  "session_namespace",
  "verifier",
]);

let installedResolver = null;
let resolverInFlight = false;

function runtimeError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function installPhysicalSessionBootstrapResolver(resolver) {
  if (typeof resolver !== "function") {
    throw new Error("physical session bootstrap resolver must be a function");
  }
  if (installedResolver != null) {
    throw new Error("physical session bootstrap resolver is already installed");
  }
  installedResolver = resolver;
  let active = true;
  return function uninstallPhysicalSessionBootstrapResolver() {
    if (active && installedResolver === resolver) {
      installedResolver = null;
      active = false;
    }
  };
}

function normalizeResolverResult(result) {
  // Reflection against a Proxy can execute resolver-controlled traps (for
  // example getPrototypeOf/ownKeys) whose exception may contain private
  // provider diagnostics. Detect and reject proxies before any reflective
  // validation. A bootstrap result is an exact data transfer object, so a
  // proxy has no valid use at this boundary.
  if (result == null || typeof result !== "object" || utilTypes.isProxy(result)
      || Array.isArray(result)
      || Object.getPrototypeOf(result) !== Object.prototype
      || Object.isFrozen(result) !== true) {
    throw runtimeError(
      "physical session bootstrap resolver must return an immutable plain data object",
      "physical_bootstrap_runtime_contract_invalid",
    );
  }
  const ownKeys = Reflect.ownKeys(result);
  if (ownKeys.some((key) => typeof key !== "string")) {
    throw runtimeError(
      "physical session bootstrap resolver result must not carry symbol fields",
      "physical_bootstrap_runtime_contract_invalid",
    );
  }
  const sorted = ownKeys.slice().sort();
  if (sorted.length !== REQUIRED_RESULT_FIELDS.length
      || sorted.some((field, index) => field !== REQUIRED_RESULT_FIELDS[index])) {
    throw runtimeError(
      `physical session bootstrap resolver result must carry exactly ${REQUIRED_RESULT_FIELDS.join(", ")}`,
      "physical_bootstrap_runtime_contract_invalid",
    );
  }
  const descriptors = Object.getOwnPropertyDescriptors(result);
  const values = Object.create(null);
  for (const field of REQUIRED_RESULT_FIELDS) {
    const descriptor = descriptors[field];
    if (!descriptor || descriptor.enumerable !== true
        || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw runtimeError(
        `physical session bootstrap resolver result ${field} must be an enumerable data property`,
        "physical_bootstrap_runtime_contract_invalid",
      );
    }
    values[field] = descriptor.value;
  }
  return Object.freeze({
    effect_template_registry: values.effect_template_registry,
    envelope: values.envelope,
    session_namespace: values.session_namespace,
    verifier: values.verifier,
  });
}

function resolvePhysicalSessionBootstrapImport(physicalScopeImportRef) {
  const ref = normalizePhysicalScopeImportRef(physicalScopeImportRef);
  if (installedResolver == null) {
    throw runtimeError(
      "physical session bootstrap resolver is not configured",
      "physical_bootstrap_runtime_unconfigured",
    );
  }
  if (resolverInFlight) {
    throw runtimeError(
      "physical session bootstrap resolver invocation is already in progress",
      "physical_bootstrap_runtime_reentrant",
    );
  }
  resolverInFlight = true;
  try {
    let result;
    try {
      result = installedResolver(ref);
    } catch {
      // The resolver is a private integration boundary. Its exception may
      // carry a device path, raw policy material, or provider diagnostics;
      // none of that is safe to reflect through the public MCP tool.
      throw runtimeError(
        "physical session bootstrap resolver is unavailable",
        "physical_bootstrap_runtime_unavailable",
      );
    }
    // Do not probe result.then: an accessor is executable resolver-controlled
    // code and its exception could leak through this boundary. Native promises
    // are detected without property access. Every other thenable shape is
    // rejected by normalizeResolverResult's immutable-plain-data contract.
    if (utilTypes.isPromise(result)) {
      // Prevent an async resolver rejection from becoming an unhandled
      // rejection after the synchronous boundary has already failed closed.
      Promise.prototype.then.call(result, undefined, () => {});
      throw runtimeError(
        "physical session bootstrap resolver must be synchronous",
        "physical_bootstrap_runtime_contract_invalid",
      );
    }
    return normalizeResolverResult(result);
  } finally {
    resolverInFlight = false;
  }
}

module.exports = {
  installPhysicalSessionBootstrapResolver,
  resolvePhysicalSessionBootstrapImport,
};
