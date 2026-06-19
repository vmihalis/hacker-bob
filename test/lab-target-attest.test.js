"use strict";

// Operator-attested lab/private-target authorization. Proves the scope kernel's
// public-DNS gate stays intact by default, and that the ONLY way past it for a
// loopback/RFC1918 target is a valid, exact-token operator attestation —
// fail-closed, narrow, host-pinned, and audit-graded against agent forgery.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  LAB_TARGET_ACK_TOKEN,
  labTargetEligibleHost,
  parseLabAuthorization,
  labTargetPermitted,
  labAuthorizationForTarget,
} = require("../mcp/lib/lab-target-attest.js");
const { assertHttpScopeDomain, validateHttpScanScope } = require("../mcp/lib/scope.js");
const { isAuditGradedPath, labAuthorizationPath, sessionDir } = require("../mcp/lib/paths.js");

const GOOD = Object.freeze({ private_targets: true, ack: LAB_TARGET_ACK_TOKEN });

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-lab-attest-"));
  process.env.HOME = tempHome;
  try {
    return fn(tempHome);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
  }
}

test("eligibility is narrow: loopback + RFC1918 IPv4 only", () => {
  for (const host of ["192.168.1.53", "127.0.0.1", "127.255.255.254", "10.5.5.5", "172.16.0.1", "172.31.255.255"]) {
    assert.equal(labTargetEligibleHost(host), true, `${host} should be eligible`);
  }
  // Excluded even though "private-ish": link-local/cloud-metadata, 172.32 (out of
  // RFC1918), public IPs, IPv6, and hostnames (incl. localhost / .internal).
  for (const host of ["169.254.169.254", "172.32.0.1", "8.8.8.8", "1.1.1.1", "::1", "localhost", "metadata.google.internal", "foo.internal", "example.com"]) {
    assert.equal(labTargetEligibleHost(host), false, `${host} should NOT be eligible`);
  }
});

test("parseLabAuthorization is fail-closed", () => {
  assert.ok(parseLabAuthorization(GOOD));
  assert.equal(parseLabAuthorization(GOOD).scope, "rfc1918_loopback_ipv4");
  // Anything that is not an exact match returns null.
  assert.equal(parseLabAuthorization({ private_targets: true, ack: "yes" }), null);
  assert.equal(parseLabAuthorization({ private_targets: true, ack: `${LAB_TARGET_ACK_TOKEN} ` }), null);
  assert.equal(parseLabAuthorization({ private_targets: false, ack: LAB_TARGET_ACK_TOKEN }), null);
  assert.equal(parseLabAuthorization({ ack: LAB_TARGET_ACK_TOKEN }), null);
  assert.equal(parseLabAuthorization({ private_targets: true }), null);
  assert.equal(parseLabAuthorization(null), null);
  assert.equal(parseLabAuthorization("i-own-it"), null);
  assert.equal(parseLabAuthorization([GOOD]), null);
});

test("labTargetPermitted requires eligibility AND a valid attestation", () => {
  assert.equal(labTargetPermitted("192.168.1.53", { authorization: GOOD }), true);
  assert.equal(labTargetPermitted("192.168.1.53", { authorization: { private_targets: true, ack: "no" } }), false);
  assert.equal(labTargetPermitted("192.168.1.53", {}), false);
  // Eligible host but no attestation, or valid attestation but ineligible host.
  assert.equal(labTargetPermitted("169.254.169.254", { authorization: GOOD }), false);
  assert.equal(labTargetPermitted("8.8.8.8", { authorization: GOOD }), false);
});

test("default public-DNS gate is UNCHANGED without an attestation", () => {
  withTempHome(() => {
    for (const host of ["192.168.1.53", "127.0.0.1", "10.0.0.1", "169.254.169.254", "localhost", "foo.internal"]) {
      assert.throws(() => assertHttpScopeDomain(host), /not a public DNS domain/, `${host} must reject by default`);
    }
    // Public registrable domains still pass.
    assert.equal(assertHttpScopeDomain("example.com"), "example.com");
  });
});

test("opts-supplied attestation permits only eligible hosts (init bootstrap path)", () => {
  withTempHome(() => {
    assert.equal(assertHttpScopeDomain("192.168.1.53", { labAuthorization: GOOD }), "192.168.1.53");
    assert.equal(assertHttpScopeDomain("127.0.0.1", { labAuthorization: GOOD }), "127.0.0.1");
    // Not eligible: blocked even WITH a valid attestation.
    assert.throws(() => assertHttpScopeDomain("169.254.169.254", { labAuthorization: GOOD }), /not a public DNS domain/);
    assert.throws(() => assertHttpScopeDomain("8.8.8.8", { labAuthorization: GOOD }), /not a public DNS domain/);
    // Eligible host but invalid attestation: still rejected.
    assert.throws(() => assertHttpScopeDomain("192.168.1.53", { labAuthorization: { private_targets: true, ack: "x" } }), /not a public DNS domain/);
  });
});

test("validateHttpScanScope pins scope to the exact attested host", () => {
  withTempHome(() => {
    const decision = validateHttpScanScope("http://192.168.1.53:8080/admin", "192.168.1.53", { labAuthorization: GOOD });
    assert.equal(decision.scope_decision, "allowed");
    assert.equal(decision.reason, "lab_attested_private_target");
    assert.equal(decision.target_domain, "192.168.1.53");
    assert.equal(decision.registrable_domain, null);
    // An attested 192.168.1.53 session cannot pivot to any other private host.
    assert.throws(
      () => validateHttpScanScope("http://10.0.0.9/x", "192.168.1.53", { labAuthorization: GOOD }),
      /outside attested lab target/,
    );
    assert.throws(
      () => validateHttpScanScope("http://169.254.169.254/latest/meta-data/", "192.168.1.53", { labAuthorization: GOOD }),
      /outside attested lab target/,
    );
  });
});

test("attestation persists to an audit-graded artifact and is read back without opts", () => {
  withTempHome((home) => {
    // Lazy-require so initSession resolves the temp HOME for its session root.
    const { initSession } = require("../mcp/lib/session-state.js");
    const result = JSON.parse(initSession({
      target_domain: "192.168.1.53",
      target_url: "http://192.168.1.53/",
      lab_authorization: GOOD,
    }));
    assert.equal(result.created, true);
    // Lab authorization implies allow_internal_hosts (layer-2 egress off-block).
    assert.equal(result.state.block_internal_hosts, false);

    const sidecar = path.join(home, "hacker-bob-sessions", "192.168.1.53", "lab-authorization.json");
    assert.equal(fs.existsSync(sidecar), true);
    assert.equal(labAuthorizationPath("192.168.1.53"), sidecar);

    // The scope kernel reads the persisted attestation with NO opts (the scan path).
    assert.equal(assertHttpScopeDomain("192.168.1.53"), "192.168.1.53");
    assert.ok(labAuthorizationForTarget("192.168.1.53"));

    // The artifact is audit-graded → the PreToolUse write-guard blocks agent Write,
    // so a prompt-injected agent cannot forge it to self-authorize.
    assert.equal(isAuditGradedPath(sidecar, "192.168.1.53"), true);
  });
});

test("labAuthorizationForTarget fails closed for a missing or forged sidecar", () => {
  withTempHome(() => {
    // No session at all.
    assert.equal(labAuthorizationForTarget("192.168.1.53"), null);
    // Forged sidecar with a bad token → parsed to null.
    const dir = sessionDir("10.1.2.3");
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(labAuthorizationPath("10.1.2.3"), JSON.stringify({ private_targets: true, ack: "forged" }));
    assert.equal(labAuthorizationForTarget("10.1.2.3"), null);
    assert.throws(() => assertHttpScopeDomain("10.1.2.3"), /not a public DNS domain/);
  });
});

test("lab_authorization cannot be combined with block_internal_hosts", () => {
  withTempHome(() => {
    const { initSession } = require("../mcp/lib/session-state.js");
    assert.throws(
      () => initSession({
        target_domain: "192.168.1.53",
        target_url: "http://192.168.1.53/",
        lab_authorization: GOOD,
        block_internal_hosts: true,
      }),
      /cannot be combined with block_internal_hosts/,
    );
  });
});
