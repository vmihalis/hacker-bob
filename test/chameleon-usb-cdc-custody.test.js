"use strict";

// The optional provider is not a workspace yet, so root test discovery owns
// this fake-driver-only custody suite. It performs no native USB enumeration.
require("../packages/bob-instrument-chameleon/test/usb-cdc-custody.test.js");
