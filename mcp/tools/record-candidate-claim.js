"use strict";

// Thin MCP composition wrapper. Candidate-claim recording and projections live
// in core so core consumers never depend on the tools composition root.
module.exports = require("../core/claims/candidate-claim-recorder.js");
