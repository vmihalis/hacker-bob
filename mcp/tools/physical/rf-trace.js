"use strict";

const { definePhysicalTechniqueTool } = require("./physical-technique-tool.js");

module.exports = definePhysicalTechniqueTool("rf_trace");

// The main tree folds the physical tool barrel into tools/index.js. Loading the
// final physical descriptor is therefore the equivalent composition point for
// the plane-owned capability adapter wiring.
require("../../domains/physical/capability-pack-runtime-wiring.js");
