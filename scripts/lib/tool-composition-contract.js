"use strict";

const assert = require("node:assert/strict");
const { TOOL_MODULES } = require("../../mcp/tools/index.js");
const { defineTool, TOOLS, TOOL_REGISTRY, TOOL_MANIFEST } = require("../../mcp/tools/tool-registry.js");
const { allRoleDefinitions, mcpToolNamesForRole } = require("../../mcp/core/dispatch/role-model.js");

const REGISTRY_SEMANTIC_FIELDS = Object.freeze([
  "role_bundles", "mutating", "global_preapproval", "network_access",
  "browser_access", "scope_required", "sensitive_output", "session_artifacts_written",
  "capability_id", "scope_url_fields", "required_session_axes", "effect_surface",
  "proof_mode", "design_hash",
]);

function assertUniqueNames(names, label) {
  const seen = new Set();
  const duplicates = [];
  for (const name of names) {
    if (seen.has(name)) duplicates.push(name);
    seen.add(name);
  }
  assert.deepEqual([...new Set(duplicates)], [], `${label} must not contain duplicate tool names`);
}

function cloneJsonValue(value, breadcrumb = "snapshot") {
  if (value == null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    assert.equal(Number.isFinite(value), true, `${breadcrumb} must be a finite JSON number`);
    return value;
  }
  if (Array.isArray(value)) return value.map((item, index) => cloneJsonValue(item, `${breadcrumb}[${index}]`));
  if (typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [
      key,
      cloneJsonValue(child, `${breadcrumb}.${key}`),
    ]));
  }
  throw new Error(`${breadcrumb} is not JSON-compatible`);
}

function registrySnapshotForTool(tool) {
  const snapshot = { name: tool.name, description: tool.description, inputSchema: tool.inputSchema };
  for (const field of REGISTRY_SEMANTIC_FIELDS) {
    assert.equal(Object.prototype.hasOwnProperty.call(tool, field), true, `${tool.name} missing registry field ${field}`);
    snapshot[field] = tool[field];
  }
  return cloneJsonValue(snapshot, `tool_registry.${tool.name}`);
}

function buildToolCompositionSnapshot() {
  const toolModuleNames = TOOL_MODULES.map((tool) => defineTool(tool).name);
  const toolNames = TOOLS.map((tool) => tool.name);
  const registryNames = TOOL_REGISTRY.map((tool) => tool.name);
  const manifestNames = Object.keys(TOOL_MANIFEST);
  assert.deepEqual(toolNames, toolModuleNames, "TOOLS order must match TOOL_MODULES");
  assert.deepEqual(registryNames, toolModuleNames, "TOOL_REGISTRY order must match TOOL_MODULES");
  assert.deepEqual(manifestNames, toolModuleNames, "TOOL_MANIFEST order must match TOOL_MODULES");
  assertUniqueNames(toolModuleNames, "TOOL_MODULES");
  assertUniqueNames(toolNames, "TOOLS");
  assertUniqueNames(registryNames, "TOOL_REGISTRY");
  return {
    ordered_names: {
      tool_modules: toolModuleNames,
      tools: toolNames,
      tool_registry: registryNames,
      tool_manifest: manifestNames,
    },
    tools: cloneJsonValue(TOOLS, "tools"),
    tool_registry: TOOL_REGISTRY.map(registrySnapshotForTool),
    tool_manifest: registryNames.map((name) => [name, cloneJsonValue(TOOL_MANIFEST[name], `tool_manifest.${name}`)]),
    role_grants: allRoleDefinitions().map((role) => [
      role.id,
      cloneJsonValue(mcpToolNamesForRole(role.id), `role_grants.${role.id}`),
    ]),
  };
}

module.exports = { buildToolCompositionSnapshot };
