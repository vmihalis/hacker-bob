"use strict";

const {
  assertNonEmptyString,
} = require("../validation.js");
const {
  loadQueuePolicy,
} = require("../queue-policy.js");

function handler(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const policy = loadQueuePolicy(domain);
  return JSON.stringify({
    version: 1,
    target_domain: domain,
    queue_policy: policy,
  });
}

module.exports = Object.freeze({
  name: "bob_read_queue_policy",
  description:
    "Read the persisted QueuePolicy for a target_domain. Returns the normalized policy " +
    "from ~/hacker-bob-sessions/<domain>/queue-policy.json, falling back to " +
    "DEFAULT_QUEUE_POLICY when the file is absent. Carries max_parallel_tasks, " +
    "priority_order, stale_after_ms, close_blocked_on_freeze, and the wave " +
    "targets/budgets/lens consumed by the wave planner.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: {
        type: "string",
      },
    },
    required: ["target_domain"],
  },
  handler,
  role_bundles: ["orchestrator"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
