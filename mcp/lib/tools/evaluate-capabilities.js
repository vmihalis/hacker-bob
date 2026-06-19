"use strict";

async function evaluateCapabilitiesHandler(args) {
  const {
    evaluateAllFixtures,
    evaluateOneFixture,
  } = require("../capability-eval-harness.js");
  if (args && typeof args.fixture === "string" && args.fixture.length > 0) {
    return evaluateOneFixture(args.fixture);
  }
  return evaluateAllFixtures();
}

module.exports = Object.freeze({
  name: "bob_evaluate_capabilities",
  aliases: ["bounty_evaluate_capabilities"],
  description:
    "Run the built-in capability evaluation harness. Each fixture exercises a specific capability against synthetic inputs and asserts the expected outcome (security-class divergence emitted, top-K finding ranked correctly, frontier branched, etc.). Call without args to run every fixture; pass `fixture: '<name>'` to run one. Use to catch capability regressions before parishioner review.",
  inputSchema: {
    type: "object",
    properties: {
      fixture: { type: "string", description: "Optional. Run only the named fixture; omit to run all." },
    },
  },
  handler: evaluateCapabilitiesHandler,
  role_bundles: ["orchestrator"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
