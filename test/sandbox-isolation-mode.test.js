"use strict";

// resolveSandboxAttestationMode — verdict-level mode resolution. A pure function
// of {env, platform}, testable without a real second uid: explicit
// BOB_SANDBOX_ATTESTATION_MODE wins on any platform; unset/malformed defaults to
// DEGRADE on EVERY platform (degrade-default, enforce opt-in). Degrade is a LOUD
// advisory downgrade — never a silent disable — and enforce is the operator's
// deliberate opt-in for a configured isolated-signer deployment (the launcher sets
// it explicitly). The common fleet box is same-uid (probe isolated:false), so a
// degrade default keeps producing findings as a loud downgrade instead of a
// fleet-wide hard block.

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  resolveSandboxAttestationMode,
  SANDBOX_ATTESTATION_MODE_ENV,
} = require("../mcp/core/ledger-integrity/sandbox-isolation-attest.js");

test("explicit enforce is honored on darwin (operator opt-in)", () => {
  const r = resolveSandboxAttestationMode({ [SANDBOX_ATTESTATION_MODE_ENV]: "enforce" }, "darwin");
  assert.equal(r.mode, "enforce");
  assert.equal(r.defaulted, false);
  assert.equal(r.platform, "darwin");
});

test("explicit enforce is honored on linux (operator opt-in)", () => {
  const r = resolveSandboxAttestationMode({ [SANDBOX_ATTESTATION_MODE_ENV]: "enforce" }, "linux");
  assert.equal(r.mode, "enforce");
  assert.equal(r.defaulted, false);
  assert.equal(r.platform, "linux");
});

test("explicit degrade is honored on linux", () => {
  const r = resolveSandboxAttestationMode({ [SANDBOX_ATTESTATION_MODE_ENV]: "degrade" }, "linux");
  assert.equal(r.mode, "degrade");
  assert.equal(r.defaulted, false);
});

test("unset defaults to DEGRADE on linux (degrade-default, NOT a fleet-wide block)", () => {
  // The default flipped from enforce to degrade: a stock same-uid linux box keeps
  // producing findings as a loud advisory downgrade rather than hard-blocking every
  // verdict-ledger-backed medium+ finding.
  const r = resolveSandboxAttestationMode({}, "linux");
  assert.equal(r.mode, "degrade");
  assert.equal(r.defaulted, true);
});

test("unset defaults to DEGRADE on darwin (dev box)", () => {
  const r = resolveSandboxAttestationMode({}, "darwin");
  assert.equal(r.mode, "degrade");
  assert.equal(r.defaulted, true);
});

test("an unknown/malformed value defaults to DEGRADE (loud advisory, never a silent disable)", () => {
  // Degrade-default everywhere: an unknown value resolves to degrade on every
  // platform. Degrade is NOT the weaker silent posture — it is the loud advisory
  // downgrade (the no-rubber-stamp stance); enforce is the explicit opt-in.
  assert.equal(resolveSandboxAttestationMode({ [SANDBOX_ATTESTATION_MODE_ENV]: "loose" }, "linux").mode, "degrade");
  assert.equal(resolveSandboxAttestationMode({ [SANDBOX_ATTESTATION_MODE_ENV]: "loose" }, "darwin").mode, "degrade");
  // The empty string and whitespace are not the exact tokens => default (degrade).
  assert.equal(resolveSandboxAttestationMode({ [SANDBOX_ATTESTATION_MODE_ENV]: "" }, "linux").mode, "degrade");
  assert.equal(resolveSandboxAttestationMode({ [SANDBOX_ATTESTATION_MODE_ENV]: "enforce " }, "linux").defaulted, true);
  assert.equal(resolveSandboxAttestationMode({ [SANDBOX_ATTESTATION_MODE_ENV]: "enforce " }, "linux").mode, "degrade");
});

test("every platform defaults to degrade (no platform special-case)", () => {
  for (const platform of ["linux", "darwin", "win32", "freebsd"]) {
    const r = resolveSandboxAttestationMode({}, platform);
    assert.equal(r.mode, "degrade", `${platform} unset => degrade-default`);
    assert.equal(r.defaulted, true);
  }
});
