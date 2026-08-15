"use strict";

// The single public entry for signed-ledger integrity. The implementation
// modules remain sibling-private so signing, custody, row authenticity, and
// isolation enforcement evolve behind one bounded seam.
module.exports = {
  ...require("./offensive-row-mac.js"),
  ...require("./handoff-signing-key.js"),
  ...require("./signing-key-custody.js"),
  ...require("./sandbox-isolation-attest.js"),
  ...require("./sandbox-isolation-gate.js"),
};
