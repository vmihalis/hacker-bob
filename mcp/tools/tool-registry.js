"use strict";

// Composition root: tools provide the concrete module list to the core registry
// builder. Core owns validation and lookup abstractions without importing tools.
const { TOOL_MODULES } = require("./index.js");
const registry = require("../core/dispatch/tool-registry.js");

module.exports = registry.installToolRegistry(TOOL_MODULES);
