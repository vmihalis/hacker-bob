"use strict";

// Field-observed payload retained from the Y.0 hotfix 1 (O2) ticket: a PoC
// narrative whose realistic length exceeded the legacy 4000-char description
// cap AND which inlined a `bearer ...` reproduction string the
// sensitive-material validator flagged as a secret carrier. Shared between
// the Y.0 hotfix regression test and the Y.1 extension regression test so
// both read the same payload from a single source (no duplicated literals).

function fieldObservedPayload(domain) {
  const longNarrative = [
    "Step 1: Authenticate as victim tenant using the captured browser session.",
    "Step 2: Issue GET /api/v2/accounts/me; observe `Authorization: bearer abcdefghij1234567890` echoed back.",
    "Step 3: Replay the same Authorization bearer abcdefghij1234567890 against /api/v2/accounts/<other-tenant>; observe cross-tenant disclosure.",
    "Step 4: Repeat with a refreshed token; the same cross-tenant path remains exploitable.",
    "Discussion: the surfaced `bearer` token is the VICTIM's own bearer, used only to demonstrate the IDOR. The bypass rationale records this so the validator does not flag the narrative as exfiltrating a Bob-side credential.",
    // pad to comfortably exceed the legacy 4000-char cap.
    "Repro paragraph: ".concat("A".repeat(5000)),
  ].join("\n\n");

  return {
    target_domain: domain,
    title: "Cross-tenant IDOR on /api/v2/accounts/<id>",
    severity: "high",
    cwe: "CWE-639",
    endpoint: "https://victim.example/api/v2/accounts/123",
    description: longNarrative,
    proof_of_concept: longNarrative,
    response_evidence: "200 OK; body included other tenant's email + plan tier (~6KB sample retained out-of-band)",
    impact: "Any authenticated tenant can read any other tenant's account record.",
    validated: true,
    // Cross-tenant IDOR: network-reachable, low-privilege authenticated tenant,
    // confidentiality impact (reads any other tenant's account record).
    cvss_inputs: {
      attack_vector: "network",
      privileges_required: "low",
      confidentiality: "high",
    },
  };
}

module.exports = Object.freeze({
  fieldObservedPayload,
});
