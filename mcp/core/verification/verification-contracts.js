"use strict";

// This compatibility surface is part of the root hacker-bob package, whose
// packed/installed layout owns both mcp/ and packages/.  Resolve inside that
// root package so an installed project never depends on workspace node_modules.
// Signed provider packages use the declared package export instead.
module.exports = require(
  "../../../packages/bob-instrument-contracts/lib/verification-contracts.js"
);
