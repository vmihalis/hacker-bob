"use strict";

// Operator-armed cross-host roam (BOB_HTTP_ROAM_AUTHORIZED=<target_domain>). Proves the scope kernel's
// default-OFF, target-bound relaxation: when armed for THIS session's target, a cross-host URL is allowed
// (reason operator_armed_roam); otherwise the public first-party gate is UNCHANGED. The lab-attested
// private-target path is NOT relaxed (no 169.254 pivot from a lab session), and block_internal_hosts is a
// separate DNS-layer policy this never touches.

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  ROAM_AUTHORIZED_ENV,
  roamAuthorizedForTarget,
  validateHttpScanScope,
} = require("../mcp/lib/scope.js");
const {
  LAB_TARGET_ACK_TOKEN,
  LAB_TARGET_ACK_ENV,
  LAB_TARGET_HOST_ENV,
} = require("../mcp/lib/lab-target-attest.js");

const TARGET = "vu.nl";
const CROSS_HOST_URL = "https://attacker.example.org/x"; // host outside vu.nl; registrable example.org
const FIRST_PARTY_URL = "https://www.vu.nl/en/research"; // subdomain of the target

function withRoamEnv(value, fn) {
  const prev = process.env[ROAM_AUTHORIZED_ENV];
  if (value === null) delete process.env[ROAM_AUTHORIZED_ENV];
  else process.env[ROAM_AUTHORIZED_ENV] = value;
  try {
    return fn();
  } finally {
    if (prev === undefined) delete process.env[ROAM_AUTHORIZED_ENV];
    else process.env[ROAM_AUTHORIZED_ENV] = prev;
  }
}

test("default (roam OFF): a cross-host URL is blocked", () => {
  withRoamEnv(null, () => {
    assert.throws(() => validateHttpScanScope(CROSS_HOST_URL, TARGET), /outside target_domain/);
  });
});

test("roam ARMED for this target: a cross-host URL is allowed with reason operator_armed_roam", () => {
  withRoamEnv(TARGET, () => {
    const result = validateHttpScanScope(CROSS_HOST_URL, TARGET);
    assert.equal(result.allowed, true);
    assert.equal(result.scope_decision, "allowed");
    assert.equal(result.reason, "operator_armed_roam");
    assert.equal(result.host, "attacker.example.org");
    assert.equal(result.target_domain, TARGET);
    // The roamed host is described from ITS OWN public-suffix info, so the audit shows where it went.
    assert.equal(result.registrable_domain, "example.org");
  });
});

test("roam armed for a DIFFERENT target does not relax this session", () => {
  withRoamEnv("some-other-engagement.com", () => {
    assert.throws(() => validateHttpScanScope(CROSS_HOST_URL, TARGET), /outside target_domain/);
  });
});

test("roam matches the WHOLE target (trim + case-insensitive), not a suffix", () => {
  withRoamEnv(`  ${TARGET.toUpperCase()}  `, () => {
    assert.equal(validateHttpScanScope(CROSS_HOST_URL, TARGET).reason, "operator_armed_roam");
  });
  withRoamEnv("nl", () => {
    // A public-suffix fragment of the target must NOT authorize roam.
    assert.throws(() => validateHttpScanScope(CROSS_HOST_URL, TARGET), /outside target_domain/);
  });
});

test("roam ON: a FIRST-PARTY URL still resolves via the normal first_party_host path", () => {
  withRoamEnv(TARGET, () => {
    const result = validateHttpScanScope(FIRST_PARTY_URL, TARGET);
    assert.equal(result.allowed, true);
    assert.equal(result.reason, "first_party_host"); // not operator_armed_roam — roam only fires off-apex
  });
});

test("CRITICAL: an attested LAB target is NOT roamed off even with roam armed (no 169.254 pivot)", () => {
  const prevAck = process.env[LAB_TARGET_ACK_ENV];
  const prevHost = process.env[LAB_TARGET_HOST_ENV];
  process.env[LAB_TARGET_ACK_ENV] = LAB_TARGET_ACK_TOKEN;
  process.env[LAB_TARGET_HOST_ENV] = "127.0.0.1";
  try {
    withRoamEnv("127.0.0.1", () => {
      const labOpts = { labAuthorization: { private_targets: true } };
      // Same attested host: allowed via the lab path.
      assert.equal(
        validateHttpScanScope("http://127.0.0.1/api", "127.0.0.1", labOpts).reason,
        "lab_attested_private_target",
      );
      // Cross-host (cloud metadata IP) stays BLOCKED despite roam being armed for the lab target — the lab
      // path returns/throws before the roam check, so a lab session can never pivot off the attested host.
      assert.throws(
        () => validateHttpScanScope("http://169.254.169.254/latest/meta-data/", "127.0.0.1", labOpts),
        /outside attested lab target/,
      );
    });
  } finally {
    if (prevAck === undefined) delete process.env[LAB_TARGET_ACK_ENV];
    else process.env[LAB_TARGET_ACK_ENV] = prevAck;
    if (prevHost === undefined) delete process.env[LAB_TARGET_HOST_ENV];
    else process.env[LAB_TARGET_HOST_ENV] = prevHost;
  }
});

test("roamAuthorizedForTarget unit: empty/whitespace/mismatch false; exact (trim/case) true", () => {
  withRoamEnv(null, () => assert.equal(roamAuthorizedForTarget(TARGET), false));
  withRoamEnv("   ", () => assert.equal(roamAuthorizedForTarget(TARGET), false));
  withRoamEnv("other.com", () => assert.equal(roamAuthorizedForTarget(TARGET), false));
  withRoamEnv(TARGET, () => assert.equal(roamAuthorizedForTarget(TARGET), true));
  withRoamEnv(`  ${TARGET.toUpperCase()} `, () => assert.equal(roamAuthorizedForTarget(TARGET), true));
  withRoamEnv(TARGET, () => assert.equal(roamAuthorizedForTarget(""), false)); // empty target never roams
});
