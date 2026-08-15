"use strict";

// Flat cross-cutting tools are grouped by operational archetype. Each factory
// owns the authority metadata that is normal for its family; a declaration
// supplies only genuine exceptions and per-tool artifact writes.

const LOCAL_ONLY = Object.freeze({
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
});

function defineArchetypeTool(family, defaults, spec) {
  if (!spec || typeof spec !== "object" || Array.isArray(spec)) {
    throw new TypeError(`define${family}Tool requires a tool descriptor`);
  }
  return Object.freeze({
    ...defaults,
    ...LOCAL_ONLY,
    ...spec,
  });
}

function defineReadTool(spec) {
  return defineArchetypeTool("Read", {
    mutating: false,
    global_preapproval: true,
    session_artifacts_written: [],
  }, spec);
}

function defineWriteTool(spec) {
  return defineArchetypeTool("Write", {
    mutating: true,
    global_preapproval: true,
  }, spec);
}

function defineQueryTool(spec) {
  return defineArchetypeTool("Query", {
    mutating: false,
    global_preapproval: false,
    session_artifacts_written: [],
  }, spec);
}

function defineLogTool(spec) {
  return defineArchetypeTool("Log", {
    mutating: true,
    global_preapproval: true,
  }, spec);
}

function defineSetTool(spec) {
  return defineArchetypeTool("Set", {
    mutating: true,
    global_preapproval: false,
  }, spec);
}

module.exports = Object.freeze({
  defineLogTool,
  defineQueryTool,
  defineReadTool,
  defineSetTool,
  defineWriteTool,
});
