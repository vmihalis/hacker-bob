"use strict";

// Aggregator shim for the legacy surface-leads.js entry. The original module
// was split into lead-intake / lead-scoring / lead-promotion in F.6; D.3
// deleted the surface-mutator shim (attack_surface.json is no longer
// written). External consumers still import from "./surface-leads.js", so
// this file re-exports the union of the three remaining modules.

module.exports = {
  ...require("./lead-intake.js"),
  ...require("./lead-scoring.js"),
  ...require("./lead-promotion.js"),
};
