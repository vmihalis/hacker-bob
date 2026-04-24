"use strict";

const { TOOLS: TOOL_DEFINITIONS } = require("./tool-definitions.js");
const { TOOL_MANIFEST: TOOL_METADATA } = require("./tool-manifest.js");
const { RAW_TOOL_HANDLERS } = require("./tool-handlers.js");
const { TOOL_MODULES } = require("./tools/index.js");

const VALID_ROLE_BUNDLES = Object.freeze([
  "auth",
  "chain",
  "grader",
  "hunter",
  "orchestrator",
  "reporter",
  "verifier",
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
  "hook_required",
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

function defineTool(entry) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
    throw new Error("tool registry entry must be an object");
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
  assertStringArrayField(entry, "session_artifacts_written");
  assertBooleanField(entry, "hook_required");
  return Object.freeze({ ...entry });
}

function legacyToolEntries(toolDefinitions, toolMetadata, toolHandlers) {
  return toolDefinitions.map((tool) => {
    const metadata = toolMetadata[tool.name];
    const handler = toolHandlers[tool.name];
    if (!metadata) {
      throw new Error(`Missing tool manifest metadata for ${tool.name}`);
    }
    return {
      ...tool,
      ...metadata,
      handler,
    };
  });
}

function buildToolRegistry({
  toolModules = TOOL_MODULES,
  toolDefinitions = TOOL_DEFINITIONS,
  toolMetadata = TOOL_METADATA,
  toolHandlers = RAW_TOOL_HANDLERS,
} = {}) {
  const rawEntries = [
    ...toolModules,
    ...legacyToolEntries(toolDefinitions, toolMetadata, toolHandlers),
  ];
  const seenNames = new Set();
  return Object.freeze(rawEntries.map((entry) => {
    const tool = defineTool(entry);
    if (seenNames.has(tool.name)) {
      throw new Error(`Duplicate tool name in registry: ${tool.name}`);
    }
    seenNames.add(tool.name);
    return tool;
  }));
}

const TOOL_REGISTRY = buildToolRegistry();

const TOOL_BY_NAME = new Map(TOOL_REGISTRY.map((tool) => [tool.name, tool]));

function getRegisteredTool(name) {
  return TOOL_BY_NAME.get(name) || null;
}

const TOOLS = Object.freeze(TOOL_REGISTRY.map((tool) => Object.freeze({
  name: tool.name,
  description: tool.description,
  inputSchema: tool.inputSchema,
})));

const TOOL_MANIFEST = Object.freeze(TOOL_REGISTRY.reduce((manifest, tool) => {
  manifest[tool.name] = Object.freeze({
    role_bundles: tool.role_bundles.slice(),
    mutating: tool.mutating,
    global_preapproval: tool.global_preapproval,
    network_access: tool.network_access,
    browser_access: tool.browser_access,
    scope_required: tool.scope_required,
    sensitive_output: tool.sensitive_output,
    session_artifacts_written: tool.session_artifacts_written.slice(),
    hook_required: tool.hook_required,
  });
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

module.exports = {
  TOOL_HANDLERS,
  TOOL_MANIFEST,
  TOOL_REGISTRY,
  TOOLS,
  VALID_ROLE_BUNDLES,
  buildToolRegistry,
  defineTool,
  getRegisteredTool,
  toolNamesForRoleBundle,
};
