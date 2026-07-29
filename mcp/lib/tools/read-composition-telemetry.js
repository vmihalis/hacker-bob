"use strict";

const {
  summarizeTaskGraph,
} = require("../task-graph-materializer.js");
const {
  readCompositionVerifiedSummary,
} = require("../composition-live-verifier.js");
const {
  assertSafeDomain,
} = require("../paths.js");

module.exports = Object.freeze({
  name: "bob_read_composition_telemetry",
  description:
    "Read composition telemetry for a session: surface/hypothesis/transition/claim counts, edge count, hypotheses-per-surface and transitions-per-hypothesis rates, and whether the graph has composed past flat surface enumeration. Also reports live_verification — the SC1 confirm-half split (verified_pass_count from the MCP-write-only composition-verified.jsonl ledger vs the offline shape-pass), since SC1 is graded on verified_pass, never on shape-pass. Summary-only; derived from the materialized task graph + the verified ledger, never written.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
    },
    required: ["target_domain"],
  },
  handler: ({ target_domain } = {}) => {
    const targetDomain = assertSafeDomain(target_domain);
    return {
      ...summarizeTaskGraph(targetDomain).composition,
      // SC1 confirm-half: graded on the live verified_pass count, kept SEPARATE
      // from the offline shape-pass composition telemetry above.
      live_verification: readCompositionVerifiedSummary(targetDomain),
    };
  },
  role_bundles: ["orchestrator"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
