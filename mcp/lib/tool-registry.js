"use strict";

const { TOOLS: TOOL_DEFINITIONS } = require("./tool-definitions.js");
const { TOOL_MANIFEST: TOOL_METADATA } = require("./tool-manifest.js");
const { RAW_TOOL_HANDLERS } = require("./tool-handlers.js");

function defineTool(entry) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
    throw new Error("tool registry entry must be an object");
  }
  const requiredFields = [
    "name",
    "description",
    "inputSchema",
    "handler",
    "role_bundles",
    "mutating",
    "network_access",
    "browser_access",
    "scope_required",
    "sensitive_output",
    "session_artifacts_written",
    "hook_required",
  ];
  for (const field of requiredFields) {
    if (!Object.prototype.hasOwnProperty.call(entry, field)) {
      throw new Error(`tool registry entry for ${entry.name || "<unknown>"} missing ${field}`);
    }
  }
  if (typeof entry.handler !== "function") {
    throw new Error(`tool registry entry for ${entry.name} has no handler`);
  }
  return Object.freeze({ ...entry });
}

const TOOL_REGISTRY = Object.freeze(TOOL_DEFINITIONS.map((tool) => {
  const metadata = TOOL_METADATA[tool.name];
  const handler = RAW_TOOL_HANDLERS[tool.name];
  if (!metadata) {
    throw new Error(`Missing tool manifest metadata for ${tool.name}`);
  }
  return defineTool({
    ...tool,
    ...metadata,
    handler,
  });
}));

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
  defineTool,
  getRegisteredTool,
  toolNamesForRoleBundle,
};
