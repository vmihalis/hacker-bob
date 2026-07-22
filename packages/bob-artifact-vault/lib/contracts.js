"use strict";

const ARTIFACT_VAULT_SCHEMA_VERSION = 1;
const ARTIFACT_DATA_CLASSES = Object.freeze([
  "metadata",
  "linkable",
  "credential_secret",
  "regulated",
]);
const ARTIFACT_DATA_CLASS_SET = new Set(ARTIFACT_DATA_CLASSES);
const PUBLIC_ARTIFACT_HANDLE_RE = /^artifact:v1:[A-Za-z0-9_-]{43}$/;
const PUBLIC_RESERVATION_HANDLE_RE = /^vault-reservation:v1:[A-Za-z0-9_-]{43}$/;
const TRANSFORM_BATCH_REF_RE = /^transform-batch:v1:[a-f0-9]{64}$/;
const SHA256_RE = /^[a-f0-9]{64}$/;
const OPAQUE_REF_RE = /^[a-z][a-z0-9._-]{0,63}:[A-Za-z0-9][A-Za-z0-9._:-]{0,190}$/;
const IDENTIFIER_RE = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,190}$/;
const MEDIA_TYPE_RE = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$/;

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertClosedObject(value, label, requiredFields, optionalFields = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const allowed = new Set([...requiredFields, ...optionalFields]);
  const unknown = Object.keys(value).filter((field) => !allowed.has(field)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = requiredFields.filter((field) => !Object.prototype.hasOwnProperty.call(value, field));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  return value;
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_RE.test(value)) {
    throw new Error(`${label} must be a bounded identifier`);
  }
  return value;
}

function assertOpaqueRef(value, label) {
  if (typeof value !== "string" || !OPAQUE_REF_RE.test(value)) {
    throw new Error(`${label} must be a namespaced opaque reference`);
  }
  return value;
}

function assertCanonicalTimestamp(value, label) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) {
    throw new Error(`${label} must be an ISO-8601 timestamp`);
  }
  if (new Date(value).toISOString() !== value) {
    throw new Error(`${label} must use canonical UTC ISO-8601 form`);
  }
  return value;
}

function normalizeArtifactMetadata(input, label = "artifact_metadata") {
  assertClosedObject(
    input,
    label,
    [
      "version",
      "session_nucleus_hash",
      "task_id",
      "attempt_id",
      "data_class",
      "media_type",
      "source_ref",
      "retention_expires_at",
    ],
    ["transform_provenance"],
  );
  if (input.version !== ARTIFACT_VAULT_SCHEMA_VERSION) {
    throw new Error(`${label}.version must be ${ARTIFACT_VAULT_SCHEMA_VERSION}`);
  }
  if (typeof input.session_nucleus_hash !== "string" || !SHA256_RE.test(input.session_nucleus_hash)) {
    throw new Error(`${label}.session_nucleus_hash must be a lowercase SHA-256 digest`);
  }
  if (!ARTIFACT_DATA_CLASS_SET.has(input.data_class)) {
    throw new Error(`${label}.data_class must be one of ${ARTIFACT_DATA_CLASSES.join(", ")}`);
  }
  if (typeof input.media_type !== "string" || !MEDIA_TYPE_RE.test(input.media_type)) {
    throw new Error(`${label}.media_type must be a lowercase media type`);
  }
  const normalized = {
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    session_nucleus_hash: input.session_nucleus_hash,
    task_id: assertIdentifier(input.task_id, `${label}.task_id`),
    attempt_id: assertIdentifier(input.attempt_id, `${label}.attempt_id`),
    data_class: input.data_class,
    media_type: input.media_type,
    source_ref: assertOpaqueRef(input.source_ref, `${label}.source_ref`),
    retention_expires_at: assertCanonicalTimestamp(
      input.retention_expires_at,
      `${label}.retention_expires_at`,
    ),
  };
  if (input.transform_provenance != null) {
    assertClosedObject(
      input.transform_provenance,
      `${label}.transform_provenance`,
      [
        "tool_id",
        "tool_version",
        "tool_digest",
        "input_handle_count",
        "batch_ref",
        "input_handles_digest",
      ],
    );
    if (!SHA256_RE.test(input.transform_provenance.tool_digest || "")) {
      throw new Error(`${label}.transform_provenance.tool_digest must be a lowercase SHA-256 digest`);
    }
    if (!Number.isSafeInteger(input.transform_provenance.input_handle_count)
      || input.transform_provenance.input_handle_count < 1
      || input.transform_provenance.input_handle_count > 64) {
      throw new Error(`${label}.transform_provenance.input_handle_count must be between 1 and 64`);
    }
    if (typeof input.transform_provenance.batch_ref !== "string"
      || !TRANSFORM_BATCH_REF_RE.test(input.transform_provenance.batch_ref)) {
      throw new Error(`${label}.transform_provenance.batch_ref is invalid`);
    }
    if (typeof input.transform_provenance.input_handles_digest !== "string"
      || !SHA256_RE.test(input.transform_provenance.input_handles_digest)) {
      throw new Error(`${label}.transform_provenance.input_handles_digest must be a lowercase SHA-256 digest`);
    }
    normalized.transform_provenance = Object.freeze({
      tool_id: assertIdentifier(
        input.transform_provenance.tool_id,
        `${label}.transform_provenance.tool_id`,
      ),
      tool_version: assertIdentifier(
        input.transform_provenance.tool_version,
        `${label}.transform_provenance.tool_version`,
      ),
      tool_digest: input.transform_provenance.tool_digest,
      input_handle_count: input.transform_provenance.input_handle_count,
      batch_ref: input.transform_provenance.batch_ref,
      input_handles_digest: input.transform_provenance.input_handles_digest,
    });
  }
  return Object.freeze(normalized);
}

function normalizeReservationRequest(input, label = "reservation_request") {
  assertClosedObject(
    input,
    label,
    [
      "version",
      "session_nucleus_hash",
      "task_id",
      "attempt_id",
      "reservation_ref",
      "purpose_ref",
      "byte_ceiling",
      "expires_at",
    ],
  );
  if (input.version !== ARTIFACT_VAULT_SCHEMA_VERSION) {
    throw new Error(`${label}.version must be ${ARTIFACT_VAULT_SCHEMA_VERSION}`);
  }
  if (typeof input.session_nucleus_hash !== "string" || !SHA256_RE.test(input.session_nucleus_hash)) {
    throw new Error(`${label}.session_nucleus_hash must be a lowercase SHA-256 digest`);
  }
  if (!Number.isSafeInteger(input.byte_ceiling) || input.byte_ceiling < 1) {
    throw new Error(`${label}.byte_ceiling must be a positive safe integer`);
  }
  const expiresAt = assertCanonicalTimestamp(input.expires_at, `${label}.expires_at`);
  return Object.freeze({
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    session_nucleus_hash: input.session_nucleus_hash,
    task_id: assertIdentifier(input.task_id, `${label}.task_id`),
    attempt_id: assertIdentifier(input.attempt_id, `${label}.attempt_id`),
    reservation_ref: assertOpaqueRef(input.reservation_ref, `${label}.reservation_ref`),
    purpose_ref: assertOpaqueRef(input.purpose_ref, `${label}.purpose_ref`),
    byte_ceiling: input.byte_ceiling,
    expires_at: expiresAt,
  });
}

module.exports = {
  ARTIFACT_DATA_CLASSES,
  ARTIFACT_VAULT_SCHEMA_VERSION,
  PUBLIC_ARTIFACT_HANDLE_RE,
  PUBLIC_RESERVATION_HANDLE_RE,
  assertCanonicalTimestamp,
  assertClosedObject,
  assertIdentifier,
  assertOpaqueRef,
  isPlainObject,
  normalizeArtifactMetadata,
  normalizeReservationRequest,
};
