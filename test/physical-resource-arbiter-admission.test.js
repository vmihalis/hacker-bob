"use strict";

// Keep the independently runnable broker package test visible to Bob's
// explicit repository test manifest.
require("../packages/bob-instrument-broker/test/resource-arbiter-admission.test.js");
