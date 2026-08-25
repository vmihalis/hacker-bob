"use strict";

const { assertNonEmptyString } = require("../core/io/validation.js");
const { findingPayloadsFromClaims } = require("./record-candidate-claim.js");

function listCandidateClaims(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const findings = findingPayloadsFromClaims(domain).map((finding) => {
    const row = {
      id: finding.id,
      severity: finding.severity,
      title: finding.title,
      endpoint: finding.endpoint,
    };
    // Surface the trust-degradation marker on degraded (unsigned) rows only,
    // sharing the predicate with degraded_count; signed/unmarked rows stay
    // unchanged so existing list output is byte-stable.
    if (finding.signature_verification_status === "unsigned") {
      row.signature_verification_status = finding.signature_verification_status;
    }
    return row;
  });
  const result = { count: findings.length, findings };
  // Present only when non-zero so an all-signed response stays byte-stable.
  const degradedCount = findings.filter((row) => row.signature_verification_status === "unsigned").length;
  if (degradedCount > 0) result.degraded_count = degradedCount;
  return JSON.stringify(result);
}

module.exports = Object.freeze({
  name: "bob_list_candidate_claims",
  description:
    "List all recorded candidate claims for a target. Each row is projected from the claim's inline finding payload.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      }
    },
    "required": [
      "target_domain"
    ]
  },
  handler: listCandidateClaims,
  role_bundles: ["evaluator-shared","orchestrator"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
