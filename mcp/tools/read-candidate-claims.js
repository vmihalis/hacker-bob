"use strict";

const { defineReadTool } = require("./_archetypes.js");

const { assertNonEmptyString } = require("../core/io/validation.js");
const { findingPayloadsFromClaims } = require("./record-candidate-claim.js");
const { deriveCvss31 } = require("../core/scoring/cvss31.js");

// Attach a server-derived CVSS v3.1 base summary to each finding in the read
// response. This is read-only and additive: the band is computed at read time
// from the finding's persisted cvss_inputs and placed on a fresh per-finding
// copy, so the hashed finding projected by findingPayloadsFromClaims is never
// mutated and other consumers of that shared projection are unaffected. The
// band is an informational sanity signal for the grader; it never gates or
// scores anything. Findings with absent/incomplete inputs carry the explicit
// insufficient marker that deriveCvss31 returns instead of a fabricated vector.
function withDerivedCvss(finding) {
  if (!finding || typeof finding !== "object") return finding;
  return { ...finding, cvss: deriveCvss31(finding.cvss_inputs) };
}

function readCandidateClaimsTool(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const findings = findingPayloadsFromClaims(domain).map(withDerivedCvss);
  const result = { version: 1, target_domain: domain, findings };
  // Surface how many findings carry the trust-degradation marker so a reader
  // can see that some findings came from a source that could not be
  // signature-verified. Present only when non-zero so an all-signed response
  // stays byte-stable; the marker itself rides on each degraded finding.
  const degradedCount = findings.filter(
    (finding) => finding && finding.signature_verification_status === "unsigned",
  ).length;
  if (degradedCount > 0) result.degraded_count = degradedCount;
  return JSON.stringify(result);
}

module.exports = defineReadTool({
  name: "bob_read_candidate_claims",
  description:
    "Read all recorded candidate claims for a target. Returns the embedded finding payloads projected off claims.jsonl.",
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
  handler: readCandidateClaimsTool,
  role_bundles: ["chain","verifier","grader","reporter","evidence"],
});
