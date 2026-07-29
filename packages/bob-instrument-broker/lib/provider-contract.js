"use strict";

// Temporary compatibility location for the provider-neutral ABI. The
// canonical implementation still lives in core while Plane-PH is assembled;
// moving it here and leaving an MCP compatibility shim is the release step.
module.exports = require("../../../mcp/lib/instrument-provider-contract.js");
