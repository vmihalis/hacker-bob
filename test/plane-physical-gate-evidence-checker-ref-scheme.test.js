"use strict";

// Locks the Plane-PH package-safe graph checker to the single production
// gate-evidence reference scheme. The committed nodes.json carries empty
// evidence-ref arrays, so migrating the checker's EVIDENCE_REF_PATTERN turns no
// existing assertion red; this suite feeds refs directly to the exported
// validators so the one-scheme contract is enforced by test, not only by a
// hardcoded regex. Any versioned reference (bob-evidence:v1:/v2:) is a legacy
// artifact and must be rejected as graph-tracked production evidence, matching
// the runtime rejection in plane-physical-release-readiness.js
// (evidence_ref_invalid).

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  validateNodes,
  validateGateTracking,
} = require("../scripts/check-plane-physical.js");
const { DISALLOWED_PACKED_TEXT_PATTERNS } = require("../scripts/lib/package-policy.js");
const nodesDocument = require("../docs/plane-physical/nodes.json");

const HEX64 = "a".repeat(64);
const VALID_REF = `bob-evidence:sha256:${HEX64}`;
const V2_REF = `bob-evidence:v2:sha256:${HEX64}`;
const V1_REF = `bob-evidence:v1:sha256:${HEX64}`;

function clone() {
  return structuredClone(nodesDocument);
}

function gateTrackingErrors(document) {
  const errors = [];
  const { nodes, nodeById } = validateNodes(document, errors);
  validateGateTracking(document, nodes, nodeById, errors);
  return errors;
}

function nodeErrors(document) {
  const errors = [];
  validateNodes(document, errors);
  return errors;
}

function hasSchemeError(errors, field) {
  return errors.some(
    (message) => message.includes(field) && message.includes("expected bob-evidence:"),
  );
}

test("the committed graph passes both validators with no scheme errors", () => {
  const errors = gateTrackingErrors(clone());
  assert.equal(
    errors.some((message) => message.includes("expected bob-evidence:")),
    false,
    `committed graph produced scheme errors: ${JSON.stringify(errors)}`,
  );
});

test("gate_tracking engineering_evidence_refs accept the production scheme", () => {
  const document = clone();
  document.gate_tracking["PH-S1"].engineering_evidence_refs = [VALID_REF];
  assert.equal(
    hasSchemeError(gateTrackingErrors(document), "engineering_evidence_refs"),
    false,
  );
});

test("gate_tracking engineering_evidence_refs reject a versioned scheme", () => {
  for (const badRef of [V1_REF, V2_REF]) {
    const document = clone();
    document.gate_tracking["PH-S1"].engineering_evidence_refs = [badRef];
    const errors = gateTrackingErrors(document);
    assert.equal(hasSchemeError(errors, "engineering_evidence_refs"), true);
    assert.ok(
      errors.some((message) => message.includes("expected bob-evidence:sha256:")),
      `expected an unversioned scheme message, got: ${JSON.stringify(errors)}`,
    );
  }
});

test("gate_tracking hil_evidence_refs accept the scheme and reject versioned", () => {
  // PH-S3 carries a real HIL gate (hil_state: pending), so hil_evidence_refs
  // are permitted (not_required nodes must keep them empty).
  const accept = clone();
  accept.gate_tracking["PH-S3"].hil_evidence_refs = [VALID_REF];
  assert.equal(hasSchemeError(gateTrackingErrors(accept), "hil_evidence_refs"), false);

  for (const badRef of [V1_REF, V2_REF]) {
    const reject = clone();
    reject.gate_tracking["PH-S3"].hil_evidence_refs = [badRef];
    assert.equal(hasSchemeError(gateTrackingErrors(reject), "hil_evidence_refs"), true);
  }
});

test("node review_evidence accepts the scheme and rejects versioned", () => {
  const accept = clone();
  accept.nodes.find((node) => node.id === "PH-S1").review_evidence = [VALID_REF];
  assert.equal(hasSchemeError(nodeErrors(accept), "review_evidence"), false);

  for (const badRef of [V1_REF, V2_REF]) {
    const reject = clone();
    reject.nodes.find((node) => node.id === "PH-S1").review_evidence = [badRef];
    assert.equal(hasSchemeError(nodeErrors(reject), "review_evidence"), true);
  }
});

test("the package text scrubber redacts the production evidence scheme", () => {
  const scrubs = (value) =>
    DISALLOWED_PACKED_TEXT_PATTERNS.some((pattern) => pattern.test(value));
  // The migration must not open a leak: real signed digests must still be
  // caught by the 'no live evidence refs in the tarball' guarantee.
  assert.equal(scrubs(VALID_REF), true, "evidence ref must be scrubbed from packed text");
});
