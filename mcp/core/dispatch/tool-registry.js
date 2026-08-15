"use strict";

const { TOOL_MODULES } = require("../../tools/index.js");
const { chainSpecificEvaluatorBundles } = require("../capability/capability-packs.js");
const { normalizeEffectSurfaceMetadata } = require("../requested-effects.js");

// Cross-cutting role bundles: orchestration, auth, verifier, evidence, etc.
// — not chain-specific. The per-chain evaluator bundles are derived from
// EVALUATOR_ROLES in capability-packs.js so adding a 7th evaluator role extends
// VALID_ROLE_BUNDLES automatically without editing this file.
const CROSS_CUTTING_ROLE_BUNDLES = Object.freeze([
  "auth",
  "chain",
  "deep-surface-discovery",
  "evidence",
  "grader",
  "evaluator-shared",
  "evaluator-spawn",
  "evaluator-web",
  "orchestrator",
  "reporter",
  "router",
  "sc-recon",
  "surface-discovery",
  "verifier",
]);

const VALID_ROLE_BUNDLES = Object.freeze([
  ...CROSS_CUTTING_ROLE_BUNDLES,
  ...chainSpecificEvaluatorBundles(),
]);
const CAPABILITY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SESSION_AXIS_VALUES = Object.freeze(["url", "repo", "contracts", "physical"]);
const REMOVED_TOOL_FIELDS = Object.freeze([
  ["hook", "required"].join("_"),
]);
const REQUIRED_FIELDS = Object.freeze([
  "name",
  "description",
  "inputSchema",
  "handler",
  "role_bundles",
  "mutating",
  "global_preapproval",
  "network_access",
  "browser_access",
  "scope_required",
  "sensitive_output",
  "session_artifacts_written",
]);

function assertBooleanField(entry, field) {
  if (typeof entry[field] !== "boolean") {
    throw new Error(`tool registry entry for ${entry.name} has invalid ${field}`);
  }
}

function assertStringArrayField(entry, field, { allowEmpty = true, validValues = null } = {}) {
  const value = entry[field];
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0)) {
    throw new Error(`tool registry entry for ${entry.name} has invalid ${field}`);
  }
  for (const item of value) {
    if (typeof item !== "string" || !item.trim()) {
      throw new Error(`tool registry entry for ${entry.name} has invalid ${field}`);
    }
    if (validValues && !validValues.includes(item)) {
      throw new Error(`tool registry entry for ${entry.name} has unknown role bundle ${item}`);
    }
  }
}

function cloneJsonCompatible(value) {
  if (Array.isArray(value)) {
    return value.map(cloneJsonCompatible);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, cloneJsonCompatible(child)]));
  }
  return value;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  for (const child of Object.values(value)) {
    deepFreeze(child);
  }
  return Object.freeze(value);
}

function frozenStringArray(value) {
  return Object.freeze(value.slice());
}

function normalizeCapabilityId(entry) {
  if (!Object.prototype.hasOwnProperty.call(entry, "capability_id")) {
    return null;
  }
  if (typeof entry.capability_id !== "string" || !CAPABILITY_ID_PATTERN.test(entry.capability_id)) {
    throw new Error(`tool registry entry for ${entry.name} has invalid capability_id`);
  }
  return entry.capability_id;
}

function normalizeScopeUrlFields(entry) {
  if (!Object.prototype.hasOwnProperty.call(entry, "scope_url_fields")) {
    return [];
  }
  assertStringArrayField(entry, "scope_url_fields");
  const properties = entry.inputSchema && entry.inputSchema.properties && typeof entry.inputSchema.properties === "object"
    ? entry.inputSchema.properties
    : {};
  for (const field of entry.scope_url_fields) {
    if (!Object.prototype.hasOwnProperty.call(properties, field)) {
      throw new Error(`tool registry entry for ${entry.name} has unknown scope_url_fields item ${field}`);
    }
  }
  if (entry.scope_url_fields.length > 0 && entry.scope_required !== true) {
    throw new Error(`tool registry entry for ${entry.name} declares scope_url_fields without scope_required`);
  }
  return Object.freeze(entry.scope_url_fields.slice());
}

function normalizeRequiredSessionAxes(entry) {
  if (!Object.prototype.hasOwnProperty.call(entry, "required_session_axes")) {
    return Object.freeze([]);
  }
  assertStringArrayField(entry, "required_session_axes", {
    allowEmpty: false,
  });
  const unique = [...new Set(entry.required_session_axes)];
  if (unique.length !== entry.required_session_axes.length
      || unique.some((axis) => !SESSION_AXIS_VALUES.includes(axis))) {
    throw new Error(`tool registry entry for ${entry.name} has invalid required_session_axes`);
  }
  // This field is conjunctive: a multi-axis declaration requires every axis.
  // Session authority owns the corresponding runtime membership check.
  return Object.freeze(unique);
}

function defineTool(entry) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
    throw new Error("tool registry entry must be an object");
  }
  for (const field of REMOVED_TOOL_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(entry, field)) {
      throw new Error(`tool registry entry for ${entry.name || "<unknown>"} declares removed hook authority metadata`);
    }
  }
  for (const field of REQUIRED_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(entry, field)) {
      throw new Error(`tool registry entry for ${entry.name || "<unknown>"} missing ${field}`);
    }
  }
  if (typeof entry.name !== "string" || !entry.name.trim()) {
    throw new Error("tool registry entry has invalid name");
  }
  if (typeof entry.description !== "string" || !entry.description.trim()) {
    throw new Error(`tool registry entry for ${entry.name} has invalid description`);
  }
  if (!entry.inputSchema || typeof entry.inputSchema !== "object" || Array.isArray(entry.inputSchema)) {
    throw new Error(`tool registry entry for ${entry.name} has invalid inputSchema`);
  }
  if (typeof entry.handler !== "function") {
    throw new Error(`tool registry entry for ${entry.name} has no handler`);
  }
  assertStringArrayField(entry, "role_bundles", { allowEmpty: false, validValues: VALID_ROLE_BUNDLES });
  assertBooleanField(entry, "mutating");
  assertBooleanField(entry, "global_preapproval");
  assertBooleanField(entry, "network_access");
  assertBooleanField(entry, "browser_access");
  assertBooleanField(entry, "scope_required");
  assertBooleanField(entry, "sensitive_output");
  const externalAccess = entry.network_access || entry.browser_access;
  if (entry.global_preapproval && externalAccess) {
    throw new Error(
      `tool registry entry for ${entry.name} cannot globally preapprove network or browser access`,
    );
  }
  const requiredSessionAxes = normalizeRequiredSessionAxes(entry);
  if (externalAccess && requiredSessionAxes.length === 0) {
    throw new Error(
      `tool registry entry for ${entry.name} must bind network or browser access to a session axis`,
    );
  }
  if (externalAccess && (
    !Array.isArray(entry.inputSchema.required)
    || !entry.inputSchema.required.includes("target_domain")
  )) {
    throw new Error(
      `tool registry entry for ${entry.name} must require target_domain for network or browser access`,
    );
  }
  assertStringArrayField(entry, "session_artifacts_written");
  const effectSurface = normalizeEffectSurfaceMetadata(
    Object.prototype.hasOwnProperty.call(entry, "effect_surface") ? entry.effect_surface : [],
    `tool registry entry for ${entry.name} effect_surface`,
  );
  if (effectSurface.some((surface) => !surface.endsWith(".observe")) && entry.mutating !== true) {
    throw new Error(`tool registry entry for ${entry.name} declares an effectful surface without mutating`);
  }
  return Object.freeze({
    ...entry,
    inputSchema: deepFreeze(cloneJsonCompatible(entry.inputSchema)),
    role_bundles: frozenStringArray(entry.role_bundles),
    session_artifacts_written: frozenStringArray(entry.session_artifacts_written),
    capability_id: normalizeCapabilityId(entry),
    scope_url_fields: normalizeScopeUrlFields(entry),
    required_session_axes: requiredSessionAxes,
    effect_surface: effectSurface,
  });
}

function buildToolRegistry({
  toolModules = TOOL_MODULES,
} = {}) {
  const seenNames = new Set();
  const entries = [];
  for (const entry of toolModules) {
    const tool = defineTool(entry);
    if (seenNames.has(tool.name)) {
      throw new Error(`Duplicate tool name in registry: ${tool.name}`);
    }
    seenNames.add(tool.name);
    entries.push(tool);
  }
  return Object.freeze(entries);
}

const TOOL_REGISTRY = buildToolRegistry();

const TOOL_BY_NAME = new Map(TOOL_REGISTRY.map((tool) => [tool.name, tool]));

function getRegisteredTool(name) {
  return TOOL_BY_NAME.get(name) || null;
}

// The public tools/list catalog advertises every registered tool under its
// canonical bob_* name.
const TOOLS = Object.freeze(TOOL_REGISTRY
  .map((tool) => Object.freeze({
    name: tool.name,
    description: tool.description,
    inputSchema: tool.inputSchema,
  })));

const TOOL_MANIFEST = Object.freeze(TOOL_REGISTRY.reduce((manifest, tool) => {
  const base = {
    role_bundles: frozenStringArray(tool.role_bundles),
    mutating: tool.mutating,
    global_preapproval: tool.global_preapproval,
    network_access: tool.network_access,
    browser_access: tool.browser_access,
    scope_required: tool.scope_required,
    sensitive_output: tool.sensitive_output,
    session_artifacts_written: frozenStringArray(tool.session_artifacts_written),
    capability_id: tool.capability_id,
    scope_url_fields: frozenStringArray(tool.scope_url_fields),
    required_session_axes: frozenStringArray(tool.required_session_axes),
    effect_surface: frozenStringArray(tool.effect_surface),
  };
  manifest[tool.name] = Object.freeze(base);
  return manifest;
}, {}));

const TOOL_HANDLERS = Object.freeze(TOOL_REGISTRY.reduce((handlers, tool) => {
  handlers[tool.name] = tool.handler;
  return handlers;
}, {}));

function toolNamesForRoleBundle(roleBundle) {
  return TOOL_REGISTRY
    .filter((tool) => tool.role_bundles.includes(roleBundle))
    .map((tool) => tool.name);
}

// A role bundle is "usable" iff it is a declared member of VALID_ROLE_BUNDLES
// AND at least one tool surfaces it. A bundle that passes the first check but
// not the second is a dead bundle: derivation maps a capability pack onto it
// and silently yields an empty tool set. Conformance tests (and any
// pack->bundle source-of-truth introduced later) import this single predicate
// rather than re-deriving the conjunction, so "what makes a bundle usable"
// stays single-sourced in the registry.
function roleBundleResolvesToTools(roleBundle) {
  return (
    VALID_ROLE_BUNDLES.includes(roleBundle) &&
    toolNamesForRoleBundle(roleBundle).length > 0
  );
}

// Every registered tool is its own primary; the v2.1.0 break removed the
// bounty_* alias layer, so these query helpers report the trivial mapping.
// Callers (session-authority class resolution, prompt-contract conformance)
// import them rather than re-deriving the registry shape.
function isAliasName(toolName) {
  return false;
}

function aliasNamesForTool(toolName) {
  return [];
}

function primaryToolName(toolName) {
  const tool = TOOL_BY_NAME.get(toolName);
  return tool ? tool.name : null;
}

function capabilityToolMapFromRegistry(registry = TOOL_REGISTRY) {
  const map = {};
  for (const tool of registry) {
    if (tool.capability_id == null) continue;
    if (!Object.prototype.hasOwnProperty.call(map, tool.capability_id)) {
      map[tool.capability_id] = [];
    }
    map[tool.capability_id].push(tool.name);
  }
  for (const capabilityId of Object.keys(map)) {
    map[capabilityId] = Object.freeze(map[capabilityId].slice());
  }
  return Object.freeze(map);
}

module.exports = {
  TOOL_HANDLERS,
  TOOL_MANIFEST,
  TOOL_REGISTRY,
  TOOLS,
  VALID_ROLE_BUNDLES,
  aliasNamesForTool,
  buildToolRegistry,
  capabilityToolMapFromRegistry,
  defineTool,
  getRegisteredTool,
  isAliasName,
  primaryToolName,
  roleBundleResolvesToTools,
  toolNamesForRoleBundle,
};
