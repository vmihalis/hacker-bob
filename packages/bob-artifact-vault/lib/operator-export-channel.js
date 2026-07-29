"use strict";

const crypto = require("node:crypto");
const {
  ARTIFACT_VAULT_SCHEMA_VERSION,
  PUBLIC_ARTIFACT_HANDLE_RE,
  assertCanonicalTimestamp,
  assertClosedObject,
  assertOpaqueRef,
} = require("./contracts.js");
const {
  adjudicateTransformAttemptForOperator,
  hasVaultWorkerAccess,
  inspectTransformAttemptForOperator,
  materializeForWorker,
} = require("./vault.js");

const EXPORT_NONCE_RE = /^export-nonce:v1:[A-Za-z0-9_-]{43}$/;
const EXPORT_MAC_RE = /^[a-f0-9]{64}$/;
const TRANSFORM_BATCH_REF_RE = /^transform-batch:v1:[a-f0-9]{64}$/;
const SHA256_RE = /^[a-f0-9]{64}$/;

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value != null && typeof value === "object") {
    const output = Object.create(null);
    for (const key of Object.keys(value).sort()) {
      if (value[key] !== undefined) output[key] = canonicalize(value[key]);
    }
    return output;
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function normalizeUnsignedRequest(input, label = "operator_export_request") {
  assertClosedObject(
    input,
    label,
    [
      "version",
      "artifact_handle",
      "audience",
      "purpose_ref",
      "requester_principal_id",
      "nonce",
      "not_before",
      "expires_at",
    ],
    ["request_mac"],
  );
  if (input.version !== ARTIFACT_VAULT_SCHEMA_VERSION) throw new Error(`${label}.version must be 1`);
  if (typeof input.artifact_handle !== "string" || !PUBLIC_ARTIFACT_HANDLE_RE.test(input.artifact_handle)) {
    throw new Error(`${label}.artifact_handle is invalid`);
  }
  if (typeof input.audience !== "string" || !/^[a-z][a-z0-9._:-]{0,127}$/.test(input.audience)) {
    throw new Error(`${label}.audience must be a bounded identifier`);
  }
  if (typeof input.nonce !== "string" || !EXPORT_NONCE_RE.test(input.nonce)) {
    throw new Error(`${label}.nonce must be a random export nonce`);
  }
  const normalized = {
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    artifact_handle: input.artifact_handle,
    audience: input.audience,
    purpose_ref: assertOpaqueRef(input.purpose_ref, `${label}.purpose_ref`),
    requester_principal_id: assertOpaqueRef(
      input.requester_principal_id,
      `${label}.requester_principal_id`,
    ),
    nonce: input.nonce,
    not_before: assertCanonicalTimestamp(input.not_before, `${label}.not_before`),
    expires_at: assertCanonicalTimestamp(input.expires_at, `${label}.expires_at`),
  };
  if (Date.parse(normalized.expires_at) <= Date.parse(normalized.not_before)) {
    throw new Error(`${label}.expires_at must be after not_before`);
  }
  return Object.freeze(normalized);
}

function exportRequestMac(unsignedRequest, exportKey) {
  return crypto.createHmac("sha256", exportKey).update(canonicalJson(unsignedRequest)).digest("hex");
}

function signOperatorExportRequest(input, exportKey) {
  if (!Buffer.isBuffer(exportKey) || exportKey.length !== 32) {
    throw new Error("operator export key must be a 32-byte Buffer");
  }
  const normalized = normalizeUnsignedRequest(input);
  return Object.freeze({ ...normalized, request_mac: exportRequestMac(normalized, exportKey) });
}

function normalizeUnsignedTransformRequest(input, label = "operator_transform_request") {
  assertClosedObject(input, label, [
    "version",
    "action",
    "batch_ref",
    "binding_digest",
    "audience",
    "purpose_ref",
    "requester_principal_id",
    "nonce",
    "not_before",
    "expires_at",
  ], ["expected_claimed_at", "evidence_ref", "verdict", "request_mac"]);
  if (input.version !== ARTIFACT_VAULT_SCHEMA_VERSION) throw new Error(`${label}.version must be 1`);
  if (!["inspect", "adjudicate_terminal_failed"].includes(input.action)) {
    throw new Error(`${label}.action is not registered`);
  }
  if (typeof input.batch_ref !== "string" || !TRANSFORM_BATCH_REF_RE.test(input.batch_ref)
    || typeof input.binding_digest !== "string" || !SHA256_RE.test(input.binding_digest)) {
    throw new Error(`${label} transform identity is invalid`);
  }
  if (typeof input.audience !== "string" || !/^[a-z][a-z0-9._:-]{0,127}$/.test(input.audience)) {
    throw new Error(`${label}.audience must be a bounded identifier`);
  }
  if (typeof input.nonce !== "string" || !EXPORT_NONCE_RE.test(input.nonce)) {
    throw new Error(`${label}.nonce must be a random operator nonce`);
  }
  const normalized = {
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    action: input.action,
    batch_ref: input.batch_ref,
    binding_digest: input.binding_digest,
    audience: input.audience,
    purpose_ref: assertOpaqueRef(input.purpose_ref, `${label}.purpose_ref`),
    requester_principal_id: assertOpaqueRef(
      input.requester_principal_id,
      `${label}.requester_principal_id`,
    ),
    nonce: input.nonce,
    not_before: assertCanonicalTimestamp(input.not_before, `${label}.not_before`),
    expires_at: assertCanonicalTimestamp(input.expires_at, `${label}.expires_at`),
  };
  if (Date.parse(normalized.expires_at) <= Date.parse(normalized.not_before)) {
    throw new Error(`${label}.expires_at must be after not_before`);
  }
  if (input.action === "inspect") {
    if (input.expected_claimed_at != null || input.evidence_ref != null || input.verdict != null) {
      throw new Error(`${label} inspect action has unexpected adjudication fields`);
    }
  } else {
    if (input.verdict !== "terminal_failed") {
      throw new Error(`${label}.verdict must be terminal_failed`);
    }
    normalized.expected_claimed_at = assertCanonicalTimestamp(
      input.expected_claimed_at,
      `${label}.expected_claimed_at`,
    );
    normalized.evidence_ref = assertOpaqueRef(input.evidence_ref, `${label}.evidence_ref`);
    normalized.verdict = "terminal_failed";
  }
  return Object.freeze(normalized);
}

function transformRequestMac(unsignedRequest, exportKey) {
  return crypto.createHmac("sha256", exportKey)
    .update("hacker-bob/operator-transform/v1\0")
    .update(canonicalJson(unsignedRequest))
    .digest("hex");
}

function signOperatorTransformRequest(input, exportKey) {
  if (!Buffer.isBuffer(exportKey) || exportKey.length !== 32) {
    throw new Error("operator transform key must be a 32-byte Buffer");
  }
  const normalized = normalizeUnsignedTransformRequest(input);
  return Object.freeze({ ...normalized, request_mac: transformRequestMac(normalized, exportKey) });
}

function createOperatorExportChannel({
  vault,
  exportKey,
  audience,
  consumeNonce,
  maxWindowMs = 60_000,
  now = () => new Date(),
} = {}) {
  if (!hasVaultWorkerAccess(vault)) throw new Error("export channel requires worker-only vault access");
  if (!Buffer.isBuffer(exportKey) || exportKey.length !== 32) {
    throw new Error("operator export key must be a 32-byte Buffer unavailable to the MCP principal");
  }
  if (typeof audience !== "string" || !/^[a-z][a-z0-9._:-]{0,127}$/.test(audience)) {
    throw new Error("export audience must be a bounded identifier");
  }
  if (typeof consumeNonce !== "function") {
    throw new Error("export channel requires a durable one-use nonce consumer");
  }
  if (!Number.isSafeInteger(maxWindowMs) || maxWindowMs < 1 || maxWindowMs > 300_000) {
    throw new Error("maxWindowMs must be between 1 and 300000");
  }
  if (typeof now !== "function") throw new Error("now must be a function");
  const channelKey = Buffer.from(exportKey);
  let destroyed = false;

  function exportArtifact(input) {
    if (destroyed) throw new Error("operator export channel is destroyed");
    const normalized = normalizeUnsignedRequest(input);
    if (typeof input.request_mac !== "string" || !EXPORT_MAC_RE.test(input.request_mac)) {
      throw new Error("operator export request MAC is absent or malformed");
    }
    const expectedMac = exportRequestMac(normalized, channelKey);
    const supplied = Buffer.from(input.request_mac, "hex");
    const expected = Buffer.from(expectedMac, "hex");
    if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
      throw new Error("operator export request authentication failed");
    }
    if (normalized.audience !== audience) throw new Error("operator export audience does not match this channel");
    const timestamp = now();
    if (!(timestamp instanceof Date) || Number.isNaN(timestamp.getTime())) throw new Error("now returned an invalid Date");
    const timestampMs = timestamp.getTime();
    const notBeforeMs = Date.parse(normalized.not_before);
    const expiresAtMs = Date.parse(normalized.expires_at);
    if (expiresAtMs - notBeforeMs > maxWindowMs) throw new Error("operator export validity window is too broad");
    if (timestampMs < notBeforeMs || timestampMs >= expiresAtMs) {
      throw new Error("operator export request is not currently valid");
    }
    if (consumeNonce(normalized.nonce, normalized.expires_at) !== true) {
      throw new Error("operator export nonce was replayed or could not be durably consumed");
    }
    const materialized = materializeForWorker(vault, normalized.artifact_handle);
    const receiptPayload = {
      version: ARTIFACT_VAULT_SCHEMA_VERSION,
      artifact_handle: normalized.artifact_handle,
      audience,
      purpose_ref: normalized.purpose_ref,
      requester_principal_id: normalized.requester_principal_id,
      nonce: normalized.nonce,
      exported_at: timestamp.toISOString(),
      byte_length: materialized.plaintext.length,
    };
    return Object.freeze({
      plaintext: materialized.plaintext,
      media_type: materialized.metadata.media_type,
      data_class: materialized.metadata.data_class,
      receipt: Object.freeze({
        ...receiptPayload,
        receipt_mac: crypto.createHmac("sha256", channelKey)
          .update(canonicalJson(receiptPayload))
          .digest("hex"),
      }),
    });
  }

  function authenticateTransformRequest(input, expectedAction) {
    if (destroyed) throw new Error("operator export channel is destroyed");
    const normalized = normalizeUnsignedTransformRequest(input);
    if (normalized.action !== expectedAction) throw new Error("operator transform action does not match this method");
    if (typeof input.request_mac !== "string" || !EXPORT_MAC_RE.test(input.request_mac)) {
      throw new Error("operator transform request MAC is absent or malformed");
    }
    const expectedMac = transformRequestMac(normalized, channelKey);
    const supplied = Buffer.from(input.request_mac, "hex");
    const expected = Buffer.from(expectedMac, "hex");
    if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
      throw new Error("operator transform request authentication failed");
    }
    if (normalized.audience !== audience) throw new Error("operator transform audience does not match this channel");
    const timestamp = now();
    if (!(timestamp instanceof Date) || Number.isNaN(timestamp.getTime())) throw new Error("now returned an invalid Date");
    const timestampMs = timestamp.getTime();
    const notBeforeMs = Date.parse(normalized.not_before);
    const expiresAtMs = Date.parse(normalized.expires_at);
    if (expiresAtMs - notBeforeMs > maxWindowMs) throw new Error("operator transform validity window is too broad");
    if (timestampMs < notBeforeMs || timestampMs >= expiresAtMs) {
      throw new Error("operator transform request is not currently valid");
    }
    if (consumeNonce(normalized.nonce, normalized.expires_at) !== true) {
      throw new Error("operator transform nonce was replayed or could not be durably consumed");
    }
    return normalized;
  }

  function inspectTransformAttempt(input) {
    const normalized = authenticateTransformRequest(input, "inspect");
    return inspectTransformAttemptForOperator(
      vault,
      normalized.batch_ref,
      normalized.binding_digest,
    );
  }

  function adjudicateTransformAttempt(input) {
    const normalized = authenticateTransformRequest(input, "adjudicate_terminal_failed");
    return adjudicateTransformAttemptForOperator(vault, {
      batch_ref: normalized.batch_ref,
      binding_digest: normalized.binding_digest,
      expected_claimed_at: normalized.expected_claimed_at,
      evidence_ref: normalized.evidence_ref,
      verdict: normalized.verdict,
    });
  }

  function destroy() {
    if (destroyed) return;
    destroyed = true;
    channelKey.fill(0);
  }

  return Object.freeze({
    adjudicateTransformAttempt,
    destroy,
    exportArtifact,
    inspectTransformAttempt,
  });
}

module.exports = {
  EXPORT_NONCE_RE,
  createOperatorExportChannel,
  signOperatorExportRequest,
  signOperatorTransformRequest,
};
