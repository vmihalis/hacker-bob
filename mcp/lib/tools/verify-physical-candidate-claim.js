"use strict";

const {
  projectPhysicalCandidateVerification,
  resolvePhysicalCandidateClaim,
} = require("../physical-claim-lifecycle-adapter.js");

function verifyPhysicalCandidateClaim(args) {
  const resolved = resolvePhysicalCandidateClaim(args.target_domain, args.finding_id);
  return JSON.stringify({
    version: 1,
    verification: projectPhysicalCandidateVerification(resolved),
  });
}

module.exports = Object.freeze({
  name: "bob_verify_physical_candidate_claim",
  description:
    "Revalidate a persisted physical CandidateClaim against its exact assignment, claim hash, finding evidence reference, current session nucleus, and Bob-owned production experiment ledger. No hardware is invoked and no raw evidence is returned.",
  inputSchema: {
    type: "object",
    additionalProperties: false,
    properties: {
      target_domain: {
        type: "string",
        minLength: 1,
        maxLength: 255,
        description: "Initialized physical session authority key.",
      },
      finding_id: {
        type: "string",
        pattern: "^F-[1-9][0-9]*$",
        description: "CandidateClaim finding identifier to revalidate.",
      },
    },
    required: ["target_domain", "finding_id"],
  },
  handler: verifyPhysicalCandidateClaim,
  role_bundles: ["verifier", "evidence"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
  required_session_axes: ["physical"],
  effect_surface: [],
});
