"use strict";

// Keep the independently runnable package suite visible to the repository's
// explicit MCP test manifest.
require("../packages/bob-instrument-broker/test/authenticated-durable-exchange.test.js");
require("../packages/bob-instrument-broker/test/bootstrap-broker.test.js");
require("../packages/bob-instrument-broker/test/broker.test.js");
require("../packages/bob-instrument-broker/test/ipc.test.js");
require("../packages/bob-instrument-broker/test/ipc-native-peer-credentials.test.js");
require("../packages/bob-instrument-broker/test/physical-provider-dispatch.test.js");
require("../packages/bob-instrument-broker/test/resource-request-registry.test.js");
require("../packages/bob-instrument-broker/test/resource-reservations.test.js");
