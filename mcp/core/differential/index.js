"use strict";

// Public boundary for executed-differential verification. The concrete verifiers
// and harness generators remain private implementation modules; consumers enter
// through this index so strategies can move without widening core-to-core edges.
const composition = require("./composition-live-verifier.js");
const finding = require("./finding-differential-verifier.js");
const crossStack = require("./cross-stack-differential-verifier.js");
const compositionHarness = require("./composition-experiment-harness.js");
const sealedHarness = require("./sealed-cross-stack-harness.js");

module.exports = {
  ...composition,
  ...finding,
  ...crossStack,
  ...compositionHarness,
  ...sealedHarness,
};
