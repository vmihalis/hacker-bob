"use strict";

// Operator-attested lab/private-target authorization. Proves the scope kernel's
// public-DNS gate stays intact by default, and that the ONLY way past it for a
// loopback/RFC1918 target is an OPERATOR env attestation (BOB_LAB_TARGET_ACK)
// PLUS a private_targets intent — fail-closed, narrow, host-pinned, and
// audit-graded against agent forgery. The ack is an env var the model cannot
// supply, so a prompt-injected evaluator cannot self-authorize a private target.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  LAB_TARGET_ACK_TOKEN,
  LAB_TARGET_ACK_ENV,
  operatorLabAckPresent,
  labTargetEligibleHost,
  parseLabAuthorization,
  labTargetPermitted,
  labAuthorizationForTarget,
} = require("../mcp/lib/lab-target-attest.js");
const { assertHttpScopeDomain, validateHttpScanScope } = require("../mcp/lib/scope.js");
const { isAuditGradedPath, labAuthorizationPath, sessionDir } = require("../mcp/lib/paths.js");

// The model-suppliable INTENT — NO secret. Authorization comes from the operator
// env ack, never from this object (the legacy `ack` field is ignored).
const INTENT = Object.freeze({ private_targets: true });

function withLabAck(fn) {
  const prev = process.env[LAB_TARGET_ACK_ENV];
  process.env[LAB_TARGET_ACK_ENV] = LAB_TARGET_ACK_TOKEN;
  try {
    return fn();
  } finally {
    if (prev === undefined) delete process.env[LAB_TARGET_ACK_ENV];
    else process.env[LAB_TARGET_ACK_ENV] = prev;
  }
}

function withoutLabAck(fn) {
  const prev = process.env[LAB_TARGET_ACK_ENV];
  delete process.env[LAB_TARGET_ACK_ENV];
  try {
    return fn();
  } finally {
    if (prev !== undefined) process.env[LAB_TARGET_ACK_ENV] = prev;
  }
}

// Lab-escape context: a temp HOME for the session root, and (by default) the
// operator env ack set. Pass { ack: false } to exercise the no-operator path.
function withTempHome(fn, { ack = true } = {}) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-lab-attest-"));
  process.env.HOME = tempHome;
  const wrapper = ack ? withLabAck : withoutLabAck;
  try {
    return wrapper(() => fn(tempHome));
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

test("parseLabAuthorization requires the operator env ack and is fail-closed", () => {
  // THE STANDOUT: without the operator env, NO model-supplied input authorizes —
  // not the intent alone, and not even the (formerly published) token passed as
  // an argument. A model that can call bob_init_session cannot self-authorize.
  withoutLabAck(() => {
    assert.equal(operatorLabAckPresent(), false);
    assert.equal(parseLabAuthorization(INTENT), null);
    assert.equal(parseLabAuthorization({ private_targets: true, ack: LAB_TARGET_ACK_TOKEN }), null);
  });
  // With the operator env, the (non-secret) intent is honored and normalized.
  withLabAck(() => {
    assert.equal(operatorLabAckPresent(), true);
    const parsed = parseLabAuthorization(INTENT);
    assert.ok(parsed);
    assert.equal(parsed.scope, "rfc1918_loopback_ipv4");
    assert.equal(parsed.ack_source, "operator_env");
    assert.equal(parsed.ack, undefined, "normalized authorization must not carry a token");
    // Still fail-closed on bad shape even WITH the env set.
    assert.equal(parseLabAuthorization({ private_targets: false }), null);
    assert.equal(parseLabAuthorization({}), null);
    assert.equal(parseLabAuthorization(null), null);
    assert.equal(parseLabAuthorization("i-own-it"), null);
    assert.equal(parseLabAuthorization([INTENT]), null);
  });
  // A wrong env value (typo/truncation) fails closed — exact match required.
  const prev = process.env[LAB_TARGET_ACK_ENV];
  process.env[LAB_TARGET_ACK_ENV] = `${LAB_TARGET_ACK_TOKEN} `;
  try {
    assert.equal(operatorLabAckPresent(), false);
    assert.equal(parseLabAuthorization(INTENT), null);
  } finally {
    if (prev === undefined) delete process.env[LAB_TARGET_ACK_ENV];
    else process.env[LAB_TARGET_ACK_ENV] = prev;
  }
});

test("parseLabAuthorization checks the operator env BEFORE reading attacker input", () => {
  // A hostile object whose private_targets getter tries to self-enable the env
  // var as a read side-effect must NOT succeed: the env is read first and we
  // return before the getter ever runs.
  withoutLabAck(() => {
    let getterFired = false;
    const hostile = {
      get private_targets() {
        getterFired = true;
        process.env[LAB_TARGET_ACK_ENV] = LAB_TARGET_ACK_TOKEN;
        return true;
      },
    };
    try {
      assert.equal(parseLabAuthorization(hostile), null);
      assert.equal(getterFired, false, "env must be checked before reading attacker input");
    } finally {
      delete process.env[LAB_TARGET_ACK_ENV];
    }
  });
});

test("labTargetPermitted requires eligibility AND the operator env ack", () => {
  withLabAck(() => {
    assert.equal(labTargetPermitted("192.168.1.53", { authorization: INTENT }), true);
    assert.equal(labTargetPermitted("192.168.1.53", {}), false);
    // Eligible host but ineligible scope: blocked even with the env + intent.
    assert.equal(labTargetPermitted("169.254.169.254", { authorization: INTENT }), false);
    assert.equal(labTargetPermitted("8.8.8.8", { authorization: INTENT }), false);
  });
  // Without the operator env, an eligible host + intent is still refused.
  withoutLabAck(() => {
    assert.equal(labTargetPermitted("192.168.1.53", { authorization: INTENT }), false);
  });
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
    assert.equal(assertHttpScopeDomain("192.168.1.53", { labAuthorization: INTENT }), "192.168.1.53");
    assert.equal(assertHttpScopeDomain("127.0.0.1", { labAuthorization: INTENT }), "127.0.0.1");
    // Not eligible: blocked even WITH a valid attestation.
    assert.throws(() => assertHttpScopeDomain("169.254.169.254", { labAuthorization: INTENT }), /not a public DNS domain/);
    assert.throws(() => assertHttpScopeDomain("8.8.8.8", { labAuthorization: INTENT }), /not a public DNS domain/);
    // Eligible host but intent not asserted: still rejected.
    assert.throws(() => assertHttpScopeDomain("192.168.1.53", { labAuthorization: { private_targets: false } }), /not a public DNS domain/);
  });
  // THE STANDOUT, end-to-end: without the operator env, the SAME intent — and
  // even the old published token passed as an argument — cannot scope a private
  // host. A self-authorizing model is rejected by the public-DNS gate.
  withTempHome(() => {
    assert.throws(() => assertHttpScopeDomain("192.168.1.53", { labAuthorization: INTENT }), /not a public DNS domain/);
    assert.throws(
      () => assertHttpScopeDomain("192.168.1.53", { labAuthorization: { private_targets: true, ack: LAB_TARGET_ACK_TOKEN } }),
      /not a public DNS domain/,
    );
  }, { ack: false });
});

test("validateHttpScanScope pins scope to the exact attested host", () => {
  withTempHome(() => {
    const decision = validateHttpScanScope("http://192.168.1.53:8080/admin", "192.168.1.53", { labAuthorization: INTENT });
    assert.equal(decision.scope_decision, "allowed");
    assert.equal(decision.reason, "lab_attested_private_target");
    assert.equal(decision.target_domain, "192.168.1.53");
    assert.equal(decision.registrable_domain, null);
    // An attested 192.168.1.53 session cannot pivot to any other private host.
    assert.throws(
      () => validateHttpScanScope("http://10.0.0.9/x", "192.168.1.53", { labAuthorization: INTENT }),
      /outside attested lab target/,
    );
    assert.throws(
      () => validateHttpScanScope("http://169.254.169.254/latest/meta-data/", "192.168.1.53", { labAuthorization: INTENT }),
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
      lab_authorization: INTENT,
    }));
    assert.equal(result.created, true);
    // Lab authorization implies allow_internal_hosts (layer-2 egress off-block).
    assert.equal(result.state.block_internal_hosts, false);

    const sidecar = path.join(home, "hacker-bob-sessions", "192.168.1.53", "lab-authorization.json");
    assert.equal(fs.existsSync(sidecar), true);
    assert.equal(labAuthorizationPath("192.168.1.53"), sidecar);
    // The persisted artifact records the env attestation, NOT a token.
    const persisted = JSON.parse(fs.readFileSync(sidecar, "utf8"));
    assert.equal(persisted.ack_source, "operator_env");
    assert.equal(persisted.ack, undefined);

    // The scope kernel reads the persisted attestation with NO opts (the scan path).
    assert.equal(assertHttpScopeDomain("192.168.1.53"), "192.168.1.53");
    assert.ok(labAuthorizationForTarget("192.168.1.53"));

    // The artifact is audit-graded → the PreToolUse write-guard blocks agent Write,
    // so a prompt-injected agent cannot forge it to self-authorize.
    assert.equal(isAuditGradedPath(sidecar, "192.168.1.53"), true);
  });
});

test("labAuthorizationForTarget fails closed for a missing sidecar or absent operator env", () => {
  // No session at all → null (even with the operator env).
  withTempHome(() => {
    assert.equal(labAuthorizationForTarget("192.168.1.53"), null);
  });
  // A present sidecar is NOT honored unless the operator env ack is set — the
  // persisted file is an audit record, not a standalone grant. (Forgery of the
  // file itself is separately prevented by the audit-graded write-guard.)
  withTempHome(() => {
    const dir = sessionDir("10.1.2.3");
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(labAuthorizationPath("10.1.2.3"), JSON.stringify({ private_targets: true, scope: "rfc1918_loopback_ipv4", ack_source: "operator_env" }));
    // With the operator env set, the persisted attestation is honored…
    assert.ok(labAuthorizationForTarget("10.1.2.3"));
    assert.equal(assertHttpScopeDomain("10.1.2.3"), "10.1.2.3");
  });
  withTempHome(() => {
    const dir = sessionDir("10.1.2.3");
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(labAuthorizationPath("10.1.2.3"), JSON.stringify({ private_targets: true, scope: "rfc1918_loopback_ipv4", ack_source: "operator_env" }));
    // …but WITHOUT it, the same file grants nothing.
    assert.equal(labAuthorizationForTarget("10.1.2.3"), null);
    assert.throws(() => assertHttpScopeDomain("10.1.2.3"), /not a public DNS domain/);
  }, { ack: false });
});

test("lab_authorization cannot be combined with block_internal_hosts", () => {
  withTempHome(() => {
    const { initSession } = require("../mcp/lib/session-state.js");
    assert.throws(
      () => initSession({
        target_domain: "192.168.1.53",
        target_url: "http://192.168.1.53/",
        lab_authorization: INTENT,
        block_internal_hosts: true,
      }),
      /cannot be combined with block_internal_hosts/,
    );
  });
});

test("lab_authorization requires the default (direct) egress profile, not a proxy", () => {
  withTempHome(() => {
    const { initSession } = require("../mcp/lib/session-state.js");
    // A proxy-backed egress would scan the attested private target from the
    // proxy's network rather than the operator's lab network — reject it.
    assert.throws(
      () => initSession({
        target_domain: "192.168.1.53",
        target_url: "http://192.168.1.53/",
        lab_authorization: INTENT,
        egress_profile: "some-proxy",
      }),
      /requires the default \(direct\) egress profile/,
    );
    // The explicit default profile is fine (direct egress from the lab network).
    const ok = initSession({
      target_domain: "192.168.1.54",
      target_url: "http://192.168.1.54/",
      lab_authorization: INTENT,
      egress_profile: "default",
    });
    assert.equal(JSON.parse(ok).created, true);
  });
});
