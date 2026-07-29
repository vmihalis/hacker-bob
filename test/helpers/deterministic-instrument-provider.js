"use strict";

// Preserve the original test-helper import while the deterministic provider is
// exercised as an independently packaged, broker-free ABI implementation.
module.exports = require(
  "../../packages/bob-instrument-deterministic/lib/provider.js"
);
