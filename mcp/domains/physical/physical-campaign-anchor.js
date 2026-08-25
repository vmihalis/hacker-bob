"use strict";

// Private runtime boundary for PH-S12's externally retained monotonic head.
//
// Branding proves only that Bob constructed the synchronous CAS adapter in
// this process.  It deliberately does not claim that the host callbacks are
// remote, independently administered, or backed by a particular durability
// technology.  The coordinator reports that distinction to callers.

const { types: utilTypes } = require("node:util");

const {
  assertSafeDomain,
} = require("../../core/io/paths.js");

const PHYSICAL_CAMPAIGN_ANCHOR_PORT_VERSION = 1;
const PHYSICAL_CAMPAIGN_ANCHOR_NAMESPACE = "hacker-bob/physical-campaign-anchor/v1";
const HASH_PATTERN = /^[a-f0-9]{64}$/u;
const ANCHOR_PORTS = new WeakSet();
const ANCHOR_PORT_STATE = new WeakMap();

let installedResolver = null;

function anchorRuntimeError(code, message, cause = null) {
  const error = new Error(`${code}: ${message}`);
  error.code = code;
  if (cause != null) Object.defineProperty(error, "cause", { value: cause });
  return error;
}

function assertDataRecord(value, label, fields) {
  if (value != null && typeof value === "object" && utilTypes.isProxy(value)) {
    throw anchorRuntimeError(
      "physical_campaign_anchor_contract_invalid",
      `${label} cannot be a Proxy`,
    );
  }
  if (value == null || typeof value !== "object" || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype) {
    throw anchorRuntimeError(
      "physical_campaign_anchor_contract_invalid",
      `${label} must be a plain object`,
    );
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) {
    throw anchorRuntimeError(
      "physical_campaign_anchor_contract_invalid",
      `${label} cannot carry symbol fields`,
    );
  }
  const expected = fields.slice().sort();
  const actual = keys.slice().sort();
  if (actual.length !== expected.length
      || actual.some((field, index) => field !== expected[index])) {
    throw anchorRuntimeError(
      "physical_campaign_anchor_contract_invalid",
      `${label} fields are not exact`,
    );
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const values = Object.create(null);
  for (const field of fields) {
    const descriptor = descriptors[field];
    if (!descriptor || descriptor.enumerable !== true
        || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw anchorRuntimeError(
        "physical_campaign_anchor_contract_invalid",
        `${label}.${field} must be an enumerable data property`,
      );
    }
    values[field] = descriptor.value;
  }
  return values;
}

function copyJsonData(value, label, depth = 0) {
  if (depth > 24) {
    throw anchorRuntimeError(
      "physical_campaign_anchor_contract_invalid",
      `${label} nesting is too deep`,
    );
  }
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) {
    if (utilTypes.isProxy(value)) {
      throw anchorRuntimeError(
        "physical_campaign_anchor_contract_invalid",
        `${label} cannot be a Proxy`,
      );
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const output = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || descriptor.enumerable !== true
          || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
        throw anchorRuntimeError(
          "physical_campaign_anchor_contract_invalid",
          `${label}[${index}] must be an enumerable data property`,
        );
      }
      output.push(copyJsonData(descriptor.value, `${label}[${index}]`, depth + 1));
    }
    const extras = Reflect.ownKeys(descriptors).filter((key) => (
      key !== "length" && (typeof key !== "string" || !/^(0|[1-9][0-9]*)$/u.test(key)
        || Number(key) >= value.length)
    ));
    if (extras.length > 0) {
      throw anchorRuntimeError(
        "physical_campaign_anchor_contract_invalid",
        `${label} has extra properties`,
      );
    }
    return output;
  }
  if (value != null && typeof value === "object" && utilTypes.isProxy(value)) {
    throw anchorRuntimeError(
      "physical_campaign_anchor_contract_invalid",
      `${label} cannot be a Proxy`,
    );
  }
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    throw anchorRuntimeError(
      "physical_campaign_anchor_contract_invalid",
      `${label} must contain JSON data only`,
    );
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw anchorRuntimeError(
      "physical_campaign_anchor_contract_invalid",
      `${label} must contain plain JSON objects only`,
    );
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const output = {};
  for (const key of Reflect.ownKeys(descriptors)) {
    if (typeof key !== "string") {
      throw anchorRuntimeError(
        "physical_campaign_anchor_contract_invalid",
        `${label} cannot carry symbol fields`,
      );
    }
    const descriptor = descriptors[key];
    if (!descriptor || descriptor.enumerable !== true
        || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw anchorRuntimeError(
        "physical_campaign_anchor_contract_invalid",
        `${label}.${key} must be an enumerable data property`,
      );
    }
    output[key] = copyJsonData(descriptor.value, `${label}.${key}`, depth + 1);
  }
  return output;
}

function deepFreeze(value) {
  if (value == null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const entry of Object.values(value)) deepFreeze(entry);
  return Object.freeze(value);
}

function invokeSynchronous(callback, argument, label, code) {
  let result;
  try {
    result = callback(deepFreeze(copyJsonData(argument, `${label} input`)));
  } catch (cause) {
    throw anchorRuntimeError(code, `${label} failed`, cause);
  }
  if (utilTypes.isPromise(result)) {
    throw anchorRuntimeError(code, `${label} must be synchronous`);
  }
  return result;
}

function rejectPortSerialization() {
  throw anchorRuntimeError(
    "physical_campaign_anchor_capability_serialization_refused",
    "physical campaign anchor ports are process-local capabilities",
  );
}

function createPhysicalCampaignAnchorPort(input) {
  const values = assertDataRecord(
    input,
    "physical campaign anchor port input",
    ["anchorSlotDigest", "compareAndSet", "readState"],
  );
  if (typeof values.anchorSlotDigest !== "string" || !HASH_PATTERN.test(values.anchorSlotDigest)) {
    throw anchorRuntimeError(
      "physical_campaign_anchor_contract_invalid",
      "physical campaign anchor port anchorSlotDigest must be a SHA-256 digest",
    );
  }
  if (typeof values.readState !== "function" || typeof values.compareAndSet !== "function") {
    throw anchorRuntimeError(
      "physical_campaign_anchor_contract_invalid",
      "physical campaign anchor port requires readState and compareAndSet functions",
    );
  }
  const port = Object.create(null);
  Object.defineProperties(port, {
    version: { value: PHYSICAL_CAMPAIGN_ANCHOR_PORT_VERSION, enumerable: true },
    kind: { value: "physical_campaign_external_anchor_port", enumerable: true },
    anchor_slot_digest: { value: values.anchorSlotDigest, enumerable: true },
    toJSON: { value: rejectPortSerialization },
  });
  Object.freeze(port);
  ANCHOR_PORTS.add(port);
  ANCHOR_PORT_STATE.set(port, Object.freeze({
    anchorSlotDigest: values.anchorSlotDigest,
    compareAndSet: values.compareAndSet,
    readState: values.readState,
  }));
  return port;
}

function productionOwnerBoundary() {
  // Lazy to keep the callback-only conformance adapter independent of the
  // filesystem-backed production owner at module initialization time.
  return require("./physical-campaign-closure-owner.js");
}

function assertPhysicalCampaignAnchorPort(port) {
  const conformance = port != null && ANCHOR_PORTS.has(port) && Object.isFrozen(port)
    && ANCHOR_PORT_STATE.get(port) != null;
  const productionOwner = port != null
    && productionOwnerBoundary().isProductionPhysicalCampaignAnchorPort(port);
  if (!conformance && !productionOwner) {
    throw anchorRuntimeError(
      "physical_campaign_anchor_port_untrusted",
      "a privately branded physical campaign anchor port is required",
    );
  }
  return port;
}

function installPhysicalCampaignAnchorResolver(resolver) {
  if (typeof resolver !== "function") {
    throw new Error("physical campaign anchor resolver must be a function");
  }
  if (installedResolver != null) {
    throw new Error("physical campaign anchor resolver is already installed");
  }
  installedResolver = resolver;
  let active = true;
  return function uninstallPhysicalCampaignAnchorResolver() {
    if (active && installedResolver === resolver) {
      installedResolver = null;
      active = false;
    }
  };
}

function resolvePort(targetDomain, sessionNucleusHash, { optional }) {
  const domain = assertSafeDomain(targetDomain);
  if (typeof sessionNucleusHash !== "string" || !HASH_PATTERN.test(sessionNucleusHash)) {
    throw anchorRuntimeError(
      "physical_campaign_anchor_runtime_contract_invalid",
      "physical campaign anchor resolver requires a verified session nucleus hash",
    );
  }
  if (installedResolver == null) {
    if (optional) return null;
    throw anchorRuntimeError(
      "physical_campaign_anchor_runtime_unconfigured",
      "physical campaign external anchor resolver is not configured",
    );
  }
  let port;
  try {
    port = installedResolver(Object.freeze({
      version: PHYSICAL_CAMPAIGN_ANCHOR_PORT_VERSION,
      purpose: "physical_campaign_checkpoint_anchor",
      session_nucleus_hash: sessionNucleusHash,
      target_domain: domain,
    }));
  } catch (cause) {
    throw anchorRuntimeError(
      "physical_campaign_anchor_runtime_unavailable",
      "physical campaign external anchor resolver failed",
      cause,
    );
  }
  if (utilTypes.isPromise(port)) {
    throw anchorRuntimeError(
      "physical_campaign_anchor_runtime_contract_invalid",
      "physical campaign external anchor resolver must be synchronous",
    );
  }
  if (port == null && optional) return null;
  if (port == null) {
    throw anchorRuntimeError(
      "physical_campaign_anchor_slot_unenrolled",
      "no host-enrolled external campaign anchor slot is available for this session",
    );
  }
  return assertPhysicalCampaignAnchorPort(port);
}

function resolvePhysicalCampaignAnchorPort(targetDomain, sessionNucleusHash) {
  return resolvePort(targetDomain, sessionNucleusHash, { optional: false });
}

function probePhysicalCampaignAnchorPort(targetDomain, sessionNucleusHash) {
  return resolvePort(targetDomain, sessionNucleusHash, { optional: true });
}

function isPhysicalCampaignAnchorResolverInstalled() {
  return installedResolver != null;
}

function normalizeContext(input) {
  const values = assertDataRecord(
    input,
    "physical campaign anchor context",
    [
      "anchor_namespace",
      "target_domain",
      "version",
    ],
  );
  if (values.version !== PHYSICAL_CAMPAIGN_ANCHOR_PORT_VERSION) {
    throw anchorRuntimeError(
      "physical_campaign_anchor_contract_invalid",
      "physical campaign anchor context version is unsupported",
    );
  }
  const targetDomain = assertSafeDomain(values.target_domain);
  if (values.anchor_namespace !== PHYSICAL_CAMPAIGN_ANCHOR_NAMESPACE) {
    throw anchorRuntimeError(
      "physical_campaign_anchor_contract_invalid",
      "physical campaign anchor context namespace is invalid",
    );
  }
  return Object.freeze({
    version: PHYSICAL_CAMPAIGN_ANCHOR_PORT_VERSION,
    anchor_namespace: PHYSICAL_CAMPAIGN_ANCHOR_NAMESPACE,
    target_domain: targetDomain,
  });
}

function readPhysicalCampaignAnchor(port, contextInput) {
  assertPhysicalCampaignAnchorPort(port);
  const context = normalizeContext(contextInput);
  if (productionOwnerBoundary().isProductionPhysicalCampaignAnchorPort(port)) {
    return productionOwnerBoundary().readProductionPhysicalCampaignAnchor(
      port,
      { ...context, anchor_slot_digest: port.anchor_slot_digest },
    );
  }
  const state = ANCHOR_PORT_STATE.get(port);
  const result = invokeSynchronous(
    state.readState,
    { ...context, anchor_slot_digest: state.anchorSlotDigest },
    "physical campaign external anchor read",
    "physical_campaign_anchor_read_failed",
  );
  if (result == null) return null;
  return deepFreeze(copyJsonData(result, "physical campaign external anchor state"));
}

function compareAndSetPhysicalCampaignAnchor(port, contextInput, expectedState, nextState) {
  assertPhysicalCampaignAnchorPort(port);
  const context = normalizeContext(contextInput);
  if (productionOwnerBoundary().isProductionPhysicalCampaignAnchorPort(port)) {
    return productionOwnerBoundary().compareAndSetProductionPhysicalCampaignAnchor(
      port,
      { ...context, anchor_slot_digest: port.anchor_slot_digest },
      expectedState == null
        ? null
        : copyJsonData(expectedState, "physical campaign expected external anchor"),
      copyJsonData(nextState, "physical campaign next external anchor"),
    );
  }
  const state = ANCHOR_PORT_STATE.get(port);
  const result = invokeSynchronous(
    state.compareAndSet,
    {
      context: { ...context, anchor_slot_digest: state.anchorSlotDigest },
      expected_state: expectedState == null
        ? null
        : copyJsonData(expectedState, "physical campaign expected external anchor"),
      next_state: copyJsonData(nextState, "physical campaign next external anchor"),
    },
    "physical campaign external anchor compareAndSet",
    "physical_campaign_anchor_cas_failed",
  );
  if (typeof result !== "boolean") {
    throw anchorRuntimeError(
      "physical_campaign_anchor_contract_invalid",
      "physical campaign external anchor compareAndSet must return a boolean",
    );
  }
  return result;
}

function physicalCampaignAnchorPortAssurance(port, contextInput = null) {
  assertPhysicalCampaignAnchorPort(port);
  if (productionOwnerBoundary().isProductionPhysicalCampaignAnchorPort(port)) {
    return productionOwnerBoundary().productionPhysicalCampaignAnchorAssurance(
      port,
      contextInput,
    );
  }
  return Object.freeze({
    anchor_assurance: "caller_asserted_monotonic_cas_callback_unattested",
    anchor_externality_attested: false,
    anchor_attestation_digest: null,
    campaign_obligation_server_issued: false,
    campaign_obligation_digest: null,
    physical_nucleus_authority_attested: false,
    physical_nucleus_authority_digest: null,
    closure_signer_production_enrolled: false,
    closure_signer_enrollment_digest: null,
    terminal_witnesses_production_attested: false,
    terminal_witness_attestation_digest: null,
    no_active_effects_durably_attested: false,
    no_active_effects_attestation_digest: null,
    production_ready: false,
    anchor_slot_digest: ANCHOR_PORT_STATE.get(port).anchorSlotDigest,
    local_anchor_role: "crash_journal_only",
  });
}

module.exports = {
  PHYSICAL_CAMPAIGN_ANCHOR_NAMESPACE,
  PHYSICAL_CAMPAIGN_ANCHOR_PORT_VERSION,
  compareAndSetPhysicalCampaignAnchor,
  createPhysicalCampaignAnchorPort,
  isPhysicalCampaignAnchorResolverInstalled,
  installPhysicalCampaignAnchorResolver,
  physicalCampaignAnchorPortAssurance,
  probePhysicalCampaignAnchorPort,
  readPhysicalCampaignAnchor,
  resolvePhysicalCampaignAnchorPort,
};
