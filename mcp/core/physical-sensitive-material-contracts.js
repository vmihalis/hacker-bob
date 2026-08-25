"use strict";

// Plane-PH public-output redaction and rejection boundary.
//
// Physical evidence is handle-only outside the vault/worker trust domains.  A
// card UID, credential dump, APDU transcript, RF trace, device serial/path, or
// payment-track value can be identifying or directly reusable even when it is
// not shaped like a conventional web secret.  Keep this module dependency-free
// so telemetry, report, and contract code can apply the same classifier without
// creating a storage or provider import path.

const { types: utilTypes } = require("node:util");

const defineProperty = Object.defineProperty;

const PHYSICAL_REDACTED_VALUE = "[physical-sensitive-redacted]";
const PHYSICAL_BINARY_REDACTED_VALUE = "[physical-binary-redacted]";
const DEFAULT_MAX_PHYSICAL_TEXT_CHARS = 4000;
const DEFAULT_MAX_PHYSICAL_DEPTH = 24;
const DEFAULT_MAX_PHYSICAL_ITEMS = 512;
const PHYSICAL_OUTPUT_BUDGET_VERSION = 1;
const PHYSICAL_PUBLIC_OUTPUT_PROFILES = Object.freeze({
  telemetry: Object.freeze({
    max_depth: 4,
    max_items_per_container: 24,
    max_text_chars: 200,
    max_total_bytes: 4096,
  }),
  brief: Object.freeze({
    max_depth: 8,
    max_items_per_container: 96,
    max_text_chars: 512,
    max_total_bytes: 32 * 1024,
  }),
  report: Object.freeze({
    max_depth: 12,
    max_items_per_container: 256,
    max_text_chars: 1000,
    max_total_bytes: 128 * 1024,
  }),
});

const SAFE_META_SUFFIX_RE = /(?:^|[_-])(?:assurance|available|byte[_-]?length|class|count|digest|disposition|fingerprint|handle|hash|kind|length|masked|present|ref|redacted|scheme|sha256|status|type|verified|version)$/i;

// These are value-bearing names.  Safe metadata such as card_uid_digest,
// artifact_ref, or apdu_status is explicitly exempted above.
const PHYSICAL_SENSITIVE_FIELD_RE = /(?:^|[_-])(?:access[_-]log|acoustic[_-](?:capture|samples|trace)|apdu(?:[_-](?:bytes|command|request|response|transcript))?|artifact[_-]path|atqa|ats|audio(?:[_-](?:bytes|capture|data|recording))?|ble[_-]address|bluetooth[_-]address|bssid|card[_-](?:data|id|number|uid)|cardholder(?:[_-]name)?|cctv[_-](?:frame|image|recording|video)|command[_-]bytes|credential(?:[_-](?:bytes|dump|key|material|secret|value))?|device[_-](?:address|path|serial)|door[_-](?:id|number)|dump(?:[_-](?:bytes|data|hex))?|facility[_-](?:id|number)|hf[_-](?:data|id|uid)|image(?:[_-](?:bytes|data|payload))?|key[_-]material|lf[_-](?:data|id|uid)|mac[_-]address|memory[_-]dump|ndef[_-](?:bytes|payload|record)|optical[_-](?:capture|samples|trace)|pan|photo(?:[_-](?:bytes|data))?|raw[_-](?:capture|frame|response|trace)|reader[_-](?:id|serial)|response[_-]bytes|rf[_-](?:capture|samples|trace)|room[_-](?:id|number)|sak|sector[_-](?:data|dump|key)|serial[_-]number|ssid|tag[_-](?:data|id|uid)|track[_-]?2|uid|usb[_-]serial|vault[_-]plaintext|video(?:[_-](?:bytes|data|recording))?)(?:$|[_-])/i;

const LABELED_PHYSICAL_VALUE_PATTERNS = Object.freeze([
  /\b(?:card|tag|hf|lf)[ _-]?(?:uid|id)\s*[:=]\s*(?:0x)?[0-9a-f][0-9a-f:\- ]{5,}\b/i,
  /\b(?:mifare[ _-]?)?(?:sector[ _-]?)?key(?:[ _-]?[ab])?\s*[:=]\s*[0-9a-f]{12,64}\b/i,
  /\b(?:credential|sector|memory|card|tag|rf)[ _-]?(?:dump|trace|capture|bytes|data)\s*[:=]/i,
  /\b(?:apdu|ndef)[ _-]?(?:command|request|response|transcript|payload|bytes)\s*[:=]/i,
  /\b(?:device[ _-]?(?:serial|path)|serial[ _-]?(?:device|number))\s*[:=]\s*[^\s,;)}]+/i,
  /\b(?:pan|card[ _-]?number)\s*[:=]\s*[0-9][0-9 -]{10,24}\b/i,
  /\b(?:uid|atqa|sak|ats|ssid|bssid|(?:ble|bluetooth|mac)[ _-]?address|(?:door|room|facility|reader)[ _-]?(?:id|number|serial))\s*[:=]\s*[^\s,;)}]+/i,
  /\b(?:access[ _-]?log|cctv[ _-]?(?:frame|image|recording|video)|(?:image|photo|audio|video)[ _-]?(?:bytes|capture|data|payload|recording)?)\s*[:=]/i,
  /\btrack[ _-]?2\s*[:=]\s*;?[0-9]{12,19}[=dD][0-9]{4,}[^\s,;)}]*/i,
  /;[0-9]{12,19}=[0-9]{4,}[^?\s]{0,80}\?/,
  /(?:^|[\s"'])\/dev\/(?:cu|tty)\.[^\s"'<>]+/i,
  /(?:^|[\s"'])\/(?:Users\/[A-Za-z0-9._-]+|tmp|private\/(?:tmp|var)|var\/folders)\/(?:[^\s"'<>]+\/)*[^\s"'<>]*/,
]);

const LABELED_ASSIGNMENT_RE = /\b((?:card|tag|hf|lf)[ _-]?(?:uid|id)|(?:mifare[ _-]?)?(?:sector[ _-]?)?key(?:[ _-]?[ab])?|(?:credential|sector|memory|card|tag|rf)[ _-]?(?:dump|trace|capture|bytes|data)|(?:apdu|ndef)[ _-]?(?:command|request|response|transcript|payload|bytes)|device[ _-]?(?:serial|path)|serial[ _-]?(?:device|number)|pan|card[ _-]?number|track[ _-]?2|uid|atqa|sak|ats|ssid|bssid|(?:ble|bluetooth|mac)[ _-]?address|(?:door|room|facility|reader)[ _-]?(?:id|number|serial)|access[ _-]?log|cctv[ _-]?(?:frame|image|recording|video)|(?:image|photo|audio|video)[ _-]?(?:bytes|capture|data|payload|recording)?)(\s*[:=]\s*)[^\r\n]*/gi;
const TRACK_TWO_RE = /;[0-9]{12,19}=[0-9]{4,}[^?\s]{0,80}\?/g;
const DEVICE_PATH_RE = /\/dev\/(?:cu|tty)\.[^\s"'<>]+/gi;
const LOCAL_PATH_RE = /\/(?:Users\/[A-Za-z0-9._-]+|tmp|private\/(?:tmp|var)|var\/folders)\/(?:[^\s"'<>]+\/)*[^\s"'<>]*/g;
const PACKAGE_UNSAFE_LOCAL_PATH_RE = /^(?:\/Users\/|\/tmp\/|\/private\/(?:tmp|var)\/|\/dev\/(?:cu|tty)\.)/i;
const LIVE_OVERLAY_REFERENCE_RE = /^(?:artifact|execution-receipt|gate-evidence|hil-evidence|inventory-observation|physical-observation|session-nucleus|vault):(?:v[0-9]+:)?[A-Za-z0-9_-]{16,}$/;
const DESIGN_EMPTY_ARRAY_FIELDS = new Set([
  "engineering_evidence_refs",
  "hil_evidence_refs",
  "review_evidence",
]);
const DESIGN_NULL_FIELDS = new Set(["hil_waiver_ref"]);
const DESIGN_RAW_FIELD_NAMES = new Set([
  "apdu_bytes",
  "apdu_command",
  "apdu_request",
  "apdu_response",
  "apdu_transcript",
  "artifact_path",
  "card_id",
  "card_number",
  "card_uid",
  "command_bytes",
  "credential_bytes",
  "credential_dump",
  "credential_key",
  "credential_material",
  "credential_secret",
  "credential_value",
  "device_path",
  "device_serial",
  "dump_bytes",
  "hf_uid",
  "key_material",
  "lf_uid",
  "memory_dump",
  "ndef_payload",
  "pan",
  "raw_capture",
  "raw_frame",
  "raw_response",
  "raw_trace",
  "response_bytes",
  "rf_capture",
  "rf_samples",
  "rf_trace",
  "sector_data",
  "sector_dump",
  "sector_key",
  "tag_id",
  "tag_uid",
  "track2",
  "track_2",
  "vault_plaintext",
]);

function isPlainDataObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)
      || utilTypes.isProxy(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function defineArrayValue(array, index, value) {
  defineProperty(array, `${index}`, {
    value,
    enumerable: true,
    configurable: false,
    writable: false,
  });
}

function normalizePhysicalFieldName(fieldName) {
  return String(fieldName || "")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[^A-Za-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .toLowerCase();
}

function isSafePhysicalMetadataField(fieldName) {
  const normalized = normalizePhysicalFieldName(fieldName);
  return normalized === "apdu_status_word" || SAFE_META_SUFFIX_RE.test(normalized);
}

function isPhysicalSensitiveField(fieldName) {
  const normalized = normalizePhysicalFieldName(fieldName);
  if (!normalized || isSafePhysicalMetadataField(normalized)) return false;
  return PHYSICAL_SENSITIVE_FIELD_RE.test(normalized);
}

function containsPhysicalSensitiveText(value) {
  if (typeof value !== "string") return false;
  // Comparing against the canonical redactor keeps detection and masking in
  // one grammar.  It also makes the operation idempotent: a value that already
  // carries only the redaction marker is not rejected as though the marker
  // itself were credential material.
  return redactPhysicalSensitiveValues(value) !== value;
}

function redactPhysicalSensitiveValues(value) {
  if (typeof value !== "string") return value;
  return value
    .replace(LABELED_ASSIGNMENT_RE, (_match, label, separator) => (
      `${label}${separator}${PHYSICAL_REDACTED_VALUE}`
    ))
    .replace(TRACK_TWO_RE, PHYSICAL_REDACTED_VALUE)
    .replace(DEVICE_PATH_RE, "[physical-device-path-redacted]")
    .replace(LOCAL_PATH_RE, "[local-path-redacted]");
}

function physicalSensitiveError(path) {
  const error = new Error(`${path} appears to contain raw physical credential or device material`);
  Object.defineProperty(error, "code", {
    value: "physical_sensitive_material_rejected",
    enumerable: false,
    configurable: false,
    writable: false,
  });
  return error;
}

function visitData(value, path, options, onLeaf) {
  if (typeof value === "string") {
    if (value.length > options.maxTextChars) throw physicalSensitiveError(path);
    return onLeaf(value, path, null);
  }
  if (value === null || typeof value === "boolean") return onLeaf(value, path, null);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw physicalSensitiveError(path);
    return onLeaf(value, path, null);
  }
  if (typeof value !== "object") throw physicalSensitiveError(path);
  if (Buffer.isBuffer(value) || utilTypes.isUint8Array(value)) {
    return onLeaf(value, path, null);
  }
  if (options.depth >= options.maxDepth) throw physicalSensitiveError(path);
  if (utilTypes.isProxy(value)) throw physicalSensitiveError(path);
  if (Array.isArray(value)) {
    if (value.length > options.maxItems) throw physicalSensitiveError(path);
    const keys = Reflect.ownKeys(value);
    if (keys.length !== value.length + 1 || keys[keys.length - 1] !== "length") {
      throw physicalSensitiveError(path);
    }
    const output = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, `${index}`);
      if (!descriptor || !Object.hasOwn(descriptor, "value") || descriptor.enumerable !== true) {
        throw physicalSensitiveError(`${path}[${index}]`);
      }
      defineArrayValue(output, index, visitData(descriptor.value, `${path}[${index}]`, {
        ...options,
        depth: options.depth + 1,
      }, onLeaf));
    }
    return output;
  }
  if (!isPlainDataObject(value)) throw physicalSensitiveError(path);
  const keys = Reflect.ownKeys(value);
  if (keys.length > options.maxItems || keys.some((key) => typeof key !== "string")) {
    throw physicalSensitiveError(path);
  }
  const output = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, "value") || descriptor.enumerable !== true) {
      throw physicalSensitiveError(`${path}.${key}`);
    }
    if (isPhysicalSensitiveField(key)) {
      output[key] = onLeaf(descriptor.value, `${path}.${key}`, key);
      continue;
    }
    output[key] = visitData(descriptor.value, `${path}.${key}`, {
      ...options,
      depth: options.depth + 1,
    }, onLeaf);
  }
  return output;
}

function normalizedOptions(options = {}) {
  const maxTextChars = Number.isSafeInteger(options.maxTextChars)
    && options.maxTextChars > 0 ? options.maxTextChars : DEFAULT_MAX_PHYSICAL_TEXT_CHARS;
  const maxDepth = Number.isSafeInteger(options.maxDepth)
    && options.maxDepth > 0 ? options.maxDepth : DEFAULT_MAX_PHYSICAL_DEPTH;
  const maxItems = Number.isSafeInteger(options.maxItems)
    && options.maxItems > 0 ? options.maxItems : DEFAULT_MAX_PHYSICAL_ITEMS;
  return { maxTextChars, maxDepth, maxItems, depth: 0 };
}

function validateNoPhysicalSensitiveMaterial(value, fieldName = "physical_output", options = {}) {
  visitData(value, fieldName, normalizedOptions(options), (leaf, path, sensitiveKey) => {
    if ((sensitiveKey != null && leaf !== PHYSICAL_REDACTED_VALUE)
        || Buffer.isBuffer(leaf) || utilTypes.isUint8Array(leaf)
        || containsPhysicalSensitiveText(leaf)) {
      throw physicalSensitiveError(path);
    }
    return leaf;
  });
}

function redactPhysicalStructuredOutput(value, options = {}) {
  const output = visitData(value, "physical_output", normalizedOptions(options), (
    leaf,
    _path,
    sensitiveKey,
  ) => {
    if (sensitiveKey != null) return PHYSICAL_REDACTED_VALUE;
    if (Buffer.isBuffer(leaf) || utilTypes.isUint8Array(leaf)) {
      return PHYSICAL_BINARY_REDACTED_VALUE;
    }
    return typeof leaf === "string" ? redactPhysicalSensitiveValues(leaf) : leaf;
  });
  return deepFreezeData(output);
}

function assertPackageSafePhysicalDesignDocument(value, label = "physical_design") {
  function visit(item, path, depth) {
    if (depth > DEFAULT_MAX_PHYSICAL_DEPTH) throw physicalSensitiveError(path);
    if (typeof item === "string") {
      if (item.length > DEFAULT_MAX_PHYSICAL_TEXT_CHARS
          || PACKAGE_UNSAFE_LOCAL_PATH_RE.test(item)
          || LIVE_OVERLAY_REFERENCE_RE.test(item)
          || containsPhysicalSensitiveText(item)) {
        throw physicalSensitiveError(path);
      }
      return item;
    }
    if (item == null || typeof item === "boolean"
        || (typeof item === "number" && Number.isSafeInteger(item))) return item;
    if (Buffer.isBuffer(item) || utilTypes.isUint8Array(item) || utilTypes.isProxy(item)) {
      throw physicalSensitiveError(path);
    }
    if (Array.isArray(item)) {
      if (item.length > DEFAULT_MAX_PHYSICAL_ITEMS) throw physicalSensitiveError(path);
      const keys = Reflect.ownKeys(item);
      if (keys.length !== item.length + 1 || keys[keys.length - 1] !== "length") {
        throw physicalSensitiveError(path);
      }
      const output = [];
      for (let index = 0; index < item.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(item, `${index}`);
        if (!descriptor || !Object.hasOwn(descriptor, "value")
            || descriptor.enumerable !== true) {
          throw physicalSensitiveError(`${path}[${index}]`);
        }
        defineArrayValue(output, index,
          visit(descriptor.value, `${path}[${index}]`, depth + 1));
      }
      return Object.freeze(output);
    }
    if (!isPlainDataObject(item)) throw physicalSensitiveError(path);
    const keys = Reflect.ownKeys(item);
    if (keys.length > DEFAULT_MAX_PHYSICAL_ITEMS
        || keys.some((key) => typeof key !== "string")) {
      throw physicalSensitiveError(path);
    }
    const output = Object.create(null);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(item, key);
      if (!descriptor || !Object.hasOwn(descriptor, "value")
          || descriptor.enumerable !== true) {
        throw physicalSensitiveError(`${path}.${key}`);
      }
      const child = descriptor.value;
      if (DESIGN_EMPTY_ARRAY_FIELDS.has(key)
          && (!Array.isArray(child) || child.length !== 0)) {
        throw physicalSensitiveError(`${path}.${key}`);
      }
      if (DESIGN_NULL_FIELDS.has(key) && child !== null) {
        throw physicalSensitiveError(`${path}.${key}`);
      }
      // Registry maps legitimately use capability IDs such as
      // CU-HF-ISO14443-4-APDU as object keys.  Only data-field-shaped keys are
      // interpreted as possible raw value carriers here.
      if (DESIGN_RAW_FIELD_NAMES.has(key)) {
        throw physicalSensitiveError(`${path}.${key}`);
      }
      output[key] = visit(child, `${path}.${key}`, depth + 1);
    }
    return Object.freeze(output);
  }
  return visit(value, label, 0);
}

function deepFreezeData(value) {
  if (value == null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const key of Reflect.ownKeys(value)) deepFreezeData(value[key]);
  return Object.freeze(value);
}

function budgetPhysicalPublicOutput(value, profileId = "brief") {
  const profile = PHYSICAL_PUBLIC_OUTPUT_PROFILES[profileId];
  if (!profile) throw physicalSensitiveError("physical_output.profile");
  const sanitized = redactPhysicalStructuredOutput(value, {
    maxDepth: DEFAULT_MAX_PHYSICAL_DEPTH,
    maxItems: DEFAULT_MAX_PHYSICAL_ITEMS,
    maxTextChars: Math.max(profile.max_total_bytes, profile.max_text_chars),
  });
  const state = {
    truncated: false,
    omitted_items: 0,
    truncated_strings: 0,
  };

  function project(item, depth) {
    if (typeof item === "string") {
      if (item.length <= profile.max_text_chars) return item;
      state.truncated = true;
      state.truncated_strings += 1;
      const marker = "[truncated]";
      return `${item.slice(0, Math.max(0, profile.max_text_chars - marker.length))}${marker}`;
    }
    if (item == null || typeof item === "boolean" || typeof item === "number") return item;
    if (depth >= profile.max_depth) {
      state.truncated = true;
      state.omitted_items += 1;
      return "[depth-budget-exhausted]";
    }
    if (Array.isArray(item)) {
      const limit = Math.min(item.length, profile.max_items_per_container);
      const output = [];
      for (let index = 0; index < limit; index += 1) {
        defineArrayValue(output, index, project(item[index], depth + 1));
      }
      if (limit < item.length) {
        state.truncated = true;
        state.omitted_items += item.length - limit;
      }
      return output;
    }
    const keys = Object.keys(item).sort();
    const limit = Math.min(keys.length, profile.max_items_per_container);
    const output = Object.create(null);
    for (let index = 0; index < limit; index += 1) {
      output[keys[index]] = project(item[keys[index]], depth + 1);
    }
    if (limit < keys.length) {
      state.truncated = true;
      state.omitted_items += keys.length - limit;
    }
    return output;
  }

  let data = project(sanitized, 0);
  let dataBytes = Buffer.byteLength(JSON.stringify(data), "utf8");
  if (dataBytes > profile.max_total_bytes) {
    state.truncated = true;
    state.omitted_items += 1;
    data = "[total-byte-budget-exhausted]";
    dataBytes = Buffer.byteLength(JSON.stringify(data), "utf8");
  }
  const output = {
    version: PHYSICAL_OUTPUT_BUDGET_VERSION,
    profile: profileId,
    data,
    budget: {
      max_depth: profile.max_depth,
      max_items_per_container: profile.max_items_per_container,
      max_text_chars: profile.max_text_chars,
      max_total_bytes: profile.max_total_bytes,
      emitted_data_bytes: dataBytes,
      truncated: state.truncated,
      omitted_items: state.omitted_items,
      truncated_strings: state.truncated_strings,
    },
  };
  validateNoPhysicalSensitiveMaterial(output, "physical_public_output", {
    maxDepth: profile.max_depth + 4,
    maxItems: profile.max_items_per_container + 16,
    maxTextChars: profile.max_text_chars + 64,
  });
  return deepFreezeData(output);
}

module.exports = Object.freeze({
  DEFAULT_MAX_PHYSICAL_DEPTH,
  DEFAULT_MAX_PHYSICAL_ITEMS,
  DEFAULT_MAX_PHYSICAL_TEXT_CHARS,
  LABELED_PHYSICAL_VALUE_PATTERNS,
  PHYSICAL_BINARY_REDACTED_VALUE,
  PHYSICAL_OUTPUT_BUDGET_VERSION,
  PHYSICAL_PUBLIC_OUTPUT_PROFILES,
  PHYSICAL_REDACTED_VALUE,
  PHYSICAL_SENSITIVE_FIELD_RE,
  assertPackageSafePhysicalDesignDocument,
  budgetPhysicalPublicOutput,
  containsPhysicalSensitiveText,
  isPhysicalSensitiveField,
  normalizePhysicalFieldName,
  redactPhysicalSensitiveValues,
  redactPhysicalStructuredOutput,
  validateNoPhysicalSensitiveMaterial,
});
