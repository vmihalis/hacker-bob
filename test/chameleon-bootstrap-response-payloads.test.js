"use strict";

// Keep the optional provider's package-local pure payload suite in the root
// security-test manifest until the provider becomes an independent workspace.
// The suite uses only signed fixtures and parser-produced in-memory frames.
require("../packages/bob-instrument-chameleon/test/bootstrap-response-payloads.test.js");
