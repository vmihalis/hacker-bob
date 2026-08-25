"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

const {
  CONTROL_VALIDITY_ROW_MAC_CONTEXT,
  CONTROL_VALIDITY_CERTIFICATE_MAC_CONTEXT,
  CONTROL_VALIDITY_CLASS_OBJECT_AUTH,
  DISPOSITION_CERTIFIED,
  DISPOSITION_HOLD,
  buildControlValidityCertificate,
  verifyControlValidityCertificate,
} = require("../mcp/core/validity/index.js");
const {
  signRowWithMac,
  verifyRowWithMac,
  MAC_SCHEME_ED25519,
} = require("../mcp/core/ledger-integrity/index.js");

const CONTEXT = Object.freeze({
  session_nucleus: "SN-control-validity-test",
  surface: "GET /api/objects/:id",
  target_domain: "cvk.example.test",
});

function signedRows(overrides = {}, keys = crypto.generateKeyPairSync("ed25519")) {
  const common = {
    class_id: CONTROL_VALIDITY_CLASS_OBJECT_AUTH,
    attempt_id: "attempt-1",
    episode_id: "episode-1",
    session_nucleus: CONTEXT.session_nucleus,
    surface: CONTEXT.surface,
    target_domain: CONTEXT.target_domain,
    source_plane: "executed",
    channel_validity: true,
  };
  const rows = [
    { ...common, control: "__primary__", reached: true, status: 200, response_class: "ok", failure_mode: "none" },
    { ...common, control: "attacker_owned_control", reached: true, status: 200, response_class: "ok", failure_mode: "none" },
    { ...common, control: "victim_auth_same_object", reached: true, status: 200, response_class: "ok", failure_mode: "none" },
    { ...common, control: "no_auth_same_object", reached: false, status: 403, response_class: "forbidden", failure_mode: "unauthorized_existing" },
    { ...common, control: "public_object_check", reached: false, status: 403, response_class: "forbidden", failure_mode: "unauthorized_existing" },
    { ...common, control: "nonexistent_object", reached: false, status: 404, response_class: "not_found", failure_mode: "nonexistent" },
    { ...common, control: "stale_session_check", reached: false, status: 401, response_class: "auth_required", failure_mode: "stale" },
    { ...common, control: "cache_nonce_check", reached: true, status: 200, response_class: "ok", failure_mode: "none" },
  ].map((row) => ({ ...row, ...(overrides[row.control] || {}) }));

  for (const row of rows) {
    signRowWithMac(
      CONTROL_VALIDITY_ROW_MAC_CONTEXT,
      row,
      { scheme: MAC_SCHEME_ED25519, privateKey: keys.privateKey },
    );
  }
  return { rows, keys };
}

function certificateFor(rows, keys, options = {}) {
  return buildControlValidityCertificate({
    class_id: options.class_id || CONTROL_VALIDITY_CLASS_OBJECT_AUTH,
    context: CONTEXT,
    rows,
    row_verifier(row) {
      return verifyRowWithMac(CONTROL_VALIDITY_ROW_MAC_CONTEXT, row, { publicKey: keys.publicKey });
    },
    certificate_signer: options.certificate_signer,
  });
}

test("object-auth right-reason controls mint a deterministic signed ControlValidityCertificate", () => {
  const certKeys = crypto.generateKeyPairSync("ed25519");
  const { rows, keys } = signedRows();

  const a = certificateFor(rows, keys, { certificate_signer: { scheme: MAC_SCHEME_ED25519, privateKey: certKeys.privateKey } });
  const b = certificateFor(rows, keys);

  assert.equal(a.disposition, DISPOSITION_CERTIFIED);
  assert.equal(a.certifies, true);
  assert.equal(b.disposition, DISPOSITION_CERTIFIED);
  assert.equal(b.certificate_hash, a.certificate_hash);
  assert.equal(a.attempt_id, "attempt-1");
  assert.equal(a.episode_id, "episode-1");
  assert.equal(a.discriminators.no_auth_same_object, "unauthorized_existing");
  assert.ok(a.existence_witnesses.includes("victim_auth_same_object"));
  assert.ok(a.positive_boundary_witnesses.includes("attacker_owned_control"));
  assert.equal(
    verifyControlValidityCertificate(a, { publicKey: certKeys.publicKey }),
    true,
    "certificate MAC and read-time hash both verify",
  );
});

test("wrong-reason denials hold instead of certifying", () => {
  const { rows, keys } = signedRows({
    no_auth_same_object: {
      status: 400,
      response_class: "client_error",
      failure_mode: "malformed",
      body: { error: "malformed body" },
    },
  });

  const cert = certificateFor(rows, keys);
  assert.equal(cert.disposition, DISPOSITION_HOLD);
  assert.equal(cert.certifies, false);
  assert.match(cert.hold_reasons.join("\n"), /no_auth_same_object denied for malformed/);
});

test("signed labels cannot override the read-time failure-mode extractor", () => {
  const { rows, keys } = signedRows({
    no_auth_same_object: {
      status: 400,
      response_class: "client_error",
      failure_mode: "unauthorized_existing",
      body: { error: "malformed body" },
    },
  });

  const cert = certificateFor(rows, keys);
  assert.equal(cert.disposition, DISPOSITION_HOLD);
  assert.equal(cert.discriminators.no_auth_same_object, "malformed");
  assert.match(cert.hold_reasons.join("\n"), /no_auth_same_object denied for malformed/);
});

test("forged, soft, and unknown-class inputs fail closed", () => {
  const signed = signedRows();

  const forged = signed.rows.map((row) => ({ ...row }));
  const forgedNoAuth = forged.find((row) => row.control === "no_auth_same_object");
  forgedNoAuth.failure_mode = "malformed";
  const forgedCert = certificateFor(forged, signed.keys);
  assert.equal(forgedCert.disposition, DISPOSITION_HOLD);
  assert.match(forgedCert.reason, /unsigned or unverifiable/);

  const soft = signedRows({ no_auth_same_object: { generated_hypothesis: true } });
  const softCert = certificateFor(soft.rows, soft.keys);
  assert.equal(softCert.disposition, DISPOSITION_HOLD);
  assert.match(softCert.reason, /soft or generated/);

  const unknown = certificateFor(signed.rows, signed.keys, { class_id: "autonomous_new_class" });
  assert.equal(unknown.disposition, DISPOSITION_HOLD);
  assert.match(unknown.reason, /unknown control-validity class/);
});

test("attempt and episode arm splicing refuses closure", () => {
  const { rows, keys } = signedRows({
    public_object_check: { attempt_id: "attempt-2", episode_id: "episode-2" },
  });

  const cert = certificateFor(rows, keys);
  assert.equal(cert.disposition, DISPOSITION_HOLD);
  assert.match(cert.hold_reasons.join("\n"), /attempt_id/);
  assert.match(cert.hold_reasons.join("\n"), /episode_id/);
});
