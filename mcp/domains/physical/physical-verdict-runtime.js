"use strict";

// Private, synchronous resolver seam for the public physical-verdict adapter.
// The model supplies only opaque, report-safe references.  A host integration
// resolves those references to a live PhysicalExperimentLedger projection; the
// consumer adapter then rechecks its private brand and exact reference binding.

const { types: utilTypes } = require("node:util");

const {
  projectReportSafePhysicalVerdict,
} = require("./physical-capability-consumers.js");
const {
  assertProductionPhysicalExperimentLedger,
  describeProductionPhysicalExperimentLedger,
} = require("./physical-experiment-contract.js");
const {
  readVerifiedSessionNucleus,
} = require("../../core/governance/index.js");

const RESOLVER_REQUEST_FIELDS = Object.freeze([
  "asset_locator",
  "target_domain",
  "verified_verdict_ref",
]);

let installedResolver = null;
let resolverInFlight = false;
const PRODUCTION_RESOLVER_PORTS = new WeakSet();
const PRODUCTION_RESOLVER_PORT_STATE = new WeakMap();
const TEST_RESOLVER_PORTS = new WeakSet();
const TEST_RESOLVER_PORT_STATE = new WeakMap();

function runtimeError(code, message) {
  const error = new Error(`${code}: ${message}`);
  error.code = code;
  return error;
}

function assertBoundedText(value, label, maximum = 255) {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum
      || value !== value.trim() || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw runtimeError("physical_verdict_request_invalid", `${label} is invalid`);
  }
  return value;
}

function normalizeResolverRequest(input) {
  if (input == null || typeof input !== "object" || Array.isArray(input)
      || utilTypes.isProxy(input) || Object.getPrototypeOf(input) !== Object.prototype) {
    throw runtimeError("physical_verdict_request_invalid", "request must be a plain data object");
  }
  const keys = Reflect.ownKeys(input);
  if (keys.some((key) => typeof key !== "string")) {
    throw runtimeError("physical_verdict_request_invalid", "request cannot contain symbol fields");
  }
  const sorted = keys.slice().sort();
  if (sorted.length !== RESOLVER_REQUEST_FIELDS.length
      || sorted.some((field, index) => field !== RESOLVER_REQUEST_FIELDS[index])) {
    throw runtimeError(
      "physical_verdict_request_invalid",
      `request must carry exactly ${RESOLVER_REQUEST_FIELDS.join(", ")}`,
    );
  }
  const descriptors = Object.getOwnPropertyDescriptors(input);
  for (const field of RESOLVER_REQUEST_FIELDS) {
    const descriptor = descriptors[field];
    if (!descriptor || descriptor.enumerable !== true
        || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw runtimeError(
        "physical_verdict_request_invalid",
        `request.${field} must be an enumerable data property`,
      );
    }
  }
  return Object.freeze({
    asset_locator: assertBoundedText(input.asset_locator, "asset_locator"),
    target_domain: assertBoundedText(input.target_domain, "target_domain"),
    verified_verdict_ref: assertBoundedText(input.verified_verdict_ref, "verified_verdict_ref"),
  });
}

function readExactDataFields(input, label, fields) {
  if (input == null || typeof input !== "object" || Array.isArray(input)
      || utilTypes.isProxy(input) || Object.getPrototypeOf(input) !== Object.prototype) {
    throw new Error(`${label} must be an exact plain data object`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const keys = Reflect.ownKeys(input);
  if (keys.some((key) => typeof key !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const sorted = keys.slice().sort();
  const expected = fields.slice().sort();
  if (sorted.length !== expected.length
      || sorted.some((field, index) => field !== expected[index])) {
    throw new Error(`${label} must carry exactly ${fields.join(", ")}`);
  }
  const values = {};
  for (const field of fields) {
    const descriptor = descriptors[field];
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || descriptor.enumerable !== true) {
      throw new Error(`${label}.${field} must be an enumerable data property`);
    }
    values[field] = descriptor.value;
  }
  return values;
}

function createProductionPhysicalVerdictResolverPort(input) {
  const fields = readExactDataFields(
    input,
    "production physical verdict resolver port",
    ["version", "ledgers"],
  );
  if (fields.version !== 1) {
    throw new Error("production physical verdict resolver port.version must be 1");
  }
  if (!Array.isArray(fields.ledgers) || utilTypes.isProxy(fields.ledgers)
      || fields.ledgers.length < 1 || fields.ledgers.length > 1024) {
    throw new Error("production physical verdict resolver port.ledgers must contain 1..1024 live ledgers");
  }
  const descriptors = Object.getOwnPropertyDescriptors(fields.ledgers);
  const ledgerList = [];
  const identities = new Set();
  for (let index = 0; index < fields.ledgers.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || descriptor.enumerable !== true) {
      throw new Error(`production physical verdict resolver port.ledgers[${index}] must be an enumerable data property`);
    }
    const ledger = assertProductionPhysicalExperimentLedger(descriptor.value);
    const identity = describeProductionPhysicalExperimentLedger(ledger);
    const key = `${identity.target_domain}:${identity.plan_hash}`;
    if (identities.has(key)) {
      throw new Error(`production physical verdict resolver port contains duplicate ledger ${key}`);
    }
    identities.add(key);
    ledgerList.push(ledger);
  }
  for (const key of Reflect.ownKeys(fields.ledgers)) {
    if (key === "length") continue;
    if (typeof key !== "string" || !/^(0|[1-9][0-9]*)$/u.test(key)) {
      throw new Error("production physical verdict resolver port.ledgers contains a non-index field");
    }
  }
  const frozenLedgers = Object.freeze([...ledgerList]);
  const resolve = (request) => {
    const matching = [];
    for (const ledger of frozenLedgers) {
      const identity = describeProductionPhysicalExperimentLedger(ledger);
      if (identity.target_domain !== request.target_domain
          || ledger.plan.target_asset_ref !== request.asset_locator) continue;
      const claimRows = ledger.rows().filter((row) => row.row_kind === "claim_verdict");
      if (claimRows.length === 0) continue;
      if (claimRows.length !== 1) {
        throw new Error("production physical verdict ledger contains multiple claim verdict rows");
      }
      if (claimRows[0].row_ref !== request.verified_verdict_ref) continue;
      const projection = ledger.projectVerifiedClaim();
      if (projection.claim_verdict_ref !== request.verified_verdict_ref) {
        throw new Error("production physical verdict ledger projection reference drift");
      }
      matching.push(projection);
    }
    if (matching.length !== 1) {
      throw new Error(
        matching.length === 0
          ? "production physical verdict was not found in the bound ledger set"
          : "production physical verdict reference is ambiguous across bound ledgers",
      );
    }
    return matching[0];
  };
  const port = Object.freeze({
    version: 1,
    production_ready: true,
    resolver_assurance: "bob_owned_live_production_experiment_ledger_set",
    ledger_count: frozenLedgers.length,
  });
  PRODUCTION_RESOLVER_PORTS.add(port);
  PRODUCTION_RESOLVER_PORT_STATE.set(port, resolve);
  return port;
}

function createTestPhysicalVerdictResolverPort(input) {
  const fields = readExactDataFields(
    input,
    "test physical verdict resolver port",
    ["test_only", "resolve"],
  );
  if (fields.test_only !== true || typeof fields.resolve !== "function") {
    throw new Error("test physical verdict resolver port requires test_only and resolve");
  }
  const port = Object.freeze({
    version: 1,
    production_ready: false,
    resolver_assurance: "test_only_in_process_callback_non_authorizing",
  });
  TEST_RESOLVER_PORTS.add(port);
  TEST_RESOLVER_PORT_STATE.set(port, fields.resolve);
  return port;
}

function installResolverPort(port, ports, states, label) {
  if (!port || !ports.has(port) || !states.has(port)) {
    throw new Error(`physical verdict resolver requires a branded ${label} port`);
  }
  if (installedResolver != null) {
    throw new Error("physical verdict resolver is already installed");
  }
  installedResolver = Object.freeze({ port, resolve: states.get(port) });
  let active = true;
  return function uninstallPhysicalVerdictResolver() {
    if (active && installedResolver?.port === port) {
      installedResolver = null;
      active = false;
    }
  };
}

function installPhysicalVerdictResolver(port) {
  if (!port || !PRODUCTION_RESOLVER_PORTS.has(port)
      || !PRODUCTION_RESOLVER_PORT_STATE.has(port)
      || port.production_ready !== true) {
    throw new Error("physical verdict resolver requires a production-qualified resolver port");
  }
  return installResolverPort(
    port,
    PRODUCTION_RESOLVER_PORTS,
    PRODUCTION_RESOLVER_PORT_STATE,
    "production-qualified resolver",
  );
}

function installTestPhysicalVerdictResolver(port) {
  return installResolverPort(port, TEST_RESOLVER_PORTS, TEST_RESOLVER_PORT_STATE, "test resolver");
}

function resolvePhysicalVerdict(input) {
  const request = normalizeResolverRequest(input);
  if (installedResolver == null
      || !PRODUCTION_RESOLVER_PORTS.has(installedResolver.port)
      || !PRODUCTION_RESOLVER_PORT_STATE.has(installedResolver.port)) {
    throw runtimeError(
      "physical_verdict_runtime_unconfigured",
      "production physical verdict resolver is not configured",
    );
  }
  if (resolverInFlight) {
    throw runtimeError(
      "physical_verdict_runtime_reentrant",
      "physical verdict resolver invocation is already in progress",
    );
  }
  let nucleusBefore;
  try {
    nucleusBefore = readVerifiedSessionNucleus(request.target_domain);
  } catch {
    throw runtimeError(
      "physical_verdict_session_binding_invalid",
      "current verified physical session nucleus is unavailable",
    );
  }
  if (!nucleusBefore.physical_scope) {
    throw runtimeError(
      "physical_verdict_session_binding_invalid",
      "current verified session nucleus has no physical authority axis",
    );
  }
  resolverInFlight = true;
  try {
    let projection;
    try {
      projection = installedResolver.resolve(request);
    } catch (error) {
      if (error && error.code === "physical_verdict_runtime_reentrant") throw error;
      throw runtimeError(
        "physical_verdict_runtime_unavailable",
        "physical verdict resolver is unavailable",
      );
    }
    if (utilTypes.isPromise(projection)) {
      Promise.prototype.then.call(projection, undefined, () => {});
      throw runtimeError(
        "physical_verdict_runtime_contract_invalid",
        "physical verdict resolver must be synchronous",
      );
    }
    let nucleusAfter;
    try {
      nucleusAfter = readVerifiedSessionNucleus(request.target_domain);
    } catch {
      throw runtimeError(
        "physical_verdict_session_binding_changed",
        "verified physical session nucleus changed during verdict resolution",
      );
    }
    if (nucleusAfter.nucleus_hash !== nucleusBefore.nucleus_hash) {
      throw runtimeError(
        "physical_verdict_session_binding_changed",
        "verified physical session nucleus changed during verdict resolution",
      );
    }
    let verdict;
    try {
      verdict = projectReportSafePhysicalVerdict(projection, {
        asset_locator: request.asset_locator,
        session_nucleus_hash: nucleusBefore.nucleus_hash,
        verified_verdict_ref: request.verified_verdict_ref,
      });
    } catch {
      // Never reflect a resolver/projection diagnostic.
      throw runtimeError(
        "physical_verdict_runtime_contract_invalid",
        "physical verdict resolver did not return a matching live ledger projection",
      );
    }
    let nucleusFinal;
    try {
      nucleusFinal = readVerifiedSessionNucleus(request.target_domain);
    } catch {
      throw runtimeError(
        "physical_verdict_session_binding_changed",
        "verified physical session nucleus changed during verdict resolution",
      );
    }
    if (nucleusFinal.nucleus_hash !== nucleusBefore.nucleus_hash) {
      throw runtimeError(
        "physical_verdict_session_binding_changed",
        "verified physical session nucleus changed during verdict resolution",
      );
    }
    return verdict;
  } finally {
    resolverInFlight = false;
  }
}

function physicalVerdictRuntimeReadiness() {
  const productionReady = installedResolver?.port.production_ready === true
    && PRODUCTION_RESOLVER_PORTS.has(installedResolver.port);
  return Object.freeze({
    version: 1,
    production_ready: productionReady,
    resolver_installed: installedResolver != null,
    resolver_production_ready: productionReady,
    reason: productionReady ? null : "production_physical_verdict_resolver_not_installed",
  });
}

module.exports = Object.freeze({
  createProductionPhysicalVerdictResolverPort,
  createTestPhysicalVerdictResolverPort,
  installPhysicalVerdictResolver,
  installTestPhysicalVerdictResolver,
  normalizeResolverRequest,
  physicalVerdictRuntimeReadiness,
  resolvePhysicalVerdict,
});
