"use strict";

const { hashCanonicalJson } = require("./verification/verification-contracts.js");

const SENSITIVE_FIELD_PATTERNS = [
  /password/i,
  /secret/i,
  /token/i,
  /api[_-]?key/i,
  /private[_-]?key/i,
  /ssn|social[_-]?security/i,
  /tax[_-]?id/i,
  /salary|compensation/i,
  /credit[_-]?card|cc[_-]?num/i,
  /^email$/i,
  /^phone$/i,
  /^address$/i,
  /date[_-]?of[_-]?birth|^dob$/i,
  /internal[_-]?id/i,
  /admin/i,
];

const SEVERITY_SECURITY = "security";
const SEVERITY_INFO_LEAK = "info_leak_potential";
const SEVERITY_DOC_OR_INFRA = "doc_or_infra";

const DIVERGENCE_TYPES = Object.freeze([
  "status_class_differs",
  "response_class_differs",
  "body_hash_differs",
  "body_length_bucket_differs",
  "sensitive_field_count_differs",
  "unauth_succeeds_where_auth_blocked",
]);

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function statusClass(status) {
  if (typeof status !== "number") return "unknown";
  if (status >= 200 && status < 300) return "2xx";
  if (status >= 300 && status < 400) return "3xx";
  if (status === 401) return "401";
  if (status === 403) return "403";
  if (status === 404) return "404";
  if (status >= 400 && status < 500) return "4xx";
  if (status >= 500) return "5xx";
  return "unknown";
}

function classifyResponse(status) {
  if (typeof status !== "number") return "unknown";
  if (status >= 200 && status < 300) return "ok";
  if (status >= 300 && status < 400) return "redirect";
  if (status === 401) return "auth_required";
  if (status === 403) return "forbidden";
  if (status === 404) return "not_found";
  if (status >= 400 && status < 500) return "client_error";
  if (status >= 500) return "server_error";
  return "unknown";
}

function bodyLengthBucket(body) {
  let length = 0;
  if (typeof body === "string") {
    length = body.length;
  } else if (body != null && typeof body === "object") {
    length = JSON.stringify(body).length;
  }
  if (length === 0) return "empty";
  if (length < 256) return "small";
  if (length < 4096) return "medium";
  if (length < 65536) return "large";
  return "huge";
}

function inferBodyShape(body) {
  if (Array.isArray(body)) {
    return {
      type: "array",
      length: body.length,
      element_keys: body.length > 0 && isPlainObject(body[0])
        ? Object.keys(body[0]).sort()
        : null,
    };
  }
  if (isPlainObject(body)) {
    return {
      type: "object",
      property_keys: Object.keys(body).sort(),
    };
  }
  if (typeof body === "string") return { type: "string" };
  if (typeof body === "number") return { type: "number" };
  if (typeof body === "boolean") return { type: "boolean" };
  if (body === null) return { type: "null" };
  return null;
}

function collectFieldKeys(body, accumulator, depth) {
  if (depth > 3) return;
  if (Array.isArray(body)) {
    for (let i = 0; i < Math.min(body.length, 5); i++) {
      collectFieldKeys(body[i], accumulator, depth + 1);
    }
    return;
  }
  if (!isPlainObject(body)) return;
  for (const [key, value] of Object.entries(body)) {
    accumulator.push(key);
    collectFieldKeys(value, accumulator, depth + 1);
  }
}

function countSensitiveFields(body) {
  if (body == null || typeof body !== "object") return 0;
  const keys = [];
  collectFieldKeys(body, keys, 0);
  let count = 0;
  for (const key of keys) {
    if (typeof key !== "string") continue;
    if (SENSITIVE_FIELD_PATTERNS.some((pattern) => pattern.test(key))) {
      count += 1;
    }
  }
  return count;
}

function computeResponseSignature(observed) {
  if (!isPlainObject(observed)) {
    throw new TypeError("observed must be an object");
  }
  const shape = inferBodyShape(observed.body);
  const bodyHash = observed.body === undefined ? null : hashCanonicalJson(observed.body);
  return {
    status: typeof observed.status === "number" ? observed.status : null,
    status_class: statusClass(observed.status),
    response_class: classifyResponse(observed.status),
    body_shape: shape,
    body_hash: bodyHash,
    body_length_bucket: bodyLengthBucket(observed.body),
    sensitive_field_count: countSensitiveFields(observed.body),
    sent_with_auth: observed.sent_with_auth === true,
  };
}

function pickUniqueValues(profiles, getter) {
  const set = new Set();
  for (const profile of profiles) set.add(getter(profile));
  return set;
}

function summarizeProfileValues(profiles, signaturesByProfile, getter) {
  return profiles.map((profile) => `${profile}=${getter(signaturesByProfile[profile])}`).join(", ");
}

function detectUnauthSuccessWhileAuthBlocked(profiles, signaturesByProfile, profileMetadata) {
  if (!isPlainObject(profileMetadata)) return null;
  const unauthOk = [];
  const authBlocked = [];
  for (const profile of profiles) {
    const signature = signaturesByProfile[profile];
    const meta = profileMetadata[profile];
    if (!isPlainObject(signature) || !isPlainObject(meta)) continue;
    if (meta.sent_with_auth === false && signature.response_class === "ok") {
      unauthOk.push(profile);
    }
    if (meta.sent_with_auth === true
      && (signature.response_class === "auth_required" || signature.response_class === "forbidden")) {
      authBlocked.push(profile);
    }
  }
  if (unauthOk.length === 0 || authBlocked.length === 0) return null;
  return {
    type: "unauth_succeeds_where_auth_blocked",
    severity_class: SEVERITY_SECURITY,
    evidence_summary: `unauth_ok=[${unauthOk.join(",")}]; auth_blocked=[${authBlocked.join(",")}]`,
  };
}

function diffResponseSignatures(input) {
  if (!isPlainObject(input)) {
    throw new TypeError("input must be { signatures_by_profile, profile_metadata? }");
  }
  const signaturesByProfile = input.signatures_by_profile;
  if (!isPlainObject(signaturesByProfile)) {
    throw new TypeError("signatures_by_profile must be an object");
  }
  const profiles = Object.keys(signaturesByProfile).sort();
  if (profiles.length < 2) return [];
  for (const profile of profiles) {
    if (!isPlainObject(signaturesByProfile[profile])) {
      throw new TypeError(`signature for profile "${profile}" must be an object`);
    }
  }
  const profileMetadata = isPlainObject(input.profile_metadata) ? input.profile_metadata : null;
  const divergences = [];
  const statusClasses = pickUniqueValues(profiles,
    (p) => signaturesByProfile[p].status_class || "unknown");
  if (statusClasses.size > 1) {
    divergences.push({
      type: "status_class_differs",
      severity_class: SEVERITY_DOC_OR_INFRA,
      evidence_summary: summarizeProfileValues(profiles, signaturesByProfile,
        (s) => s.status_class || "unknown"),
    });
  }
  const responseClasses = pickUniqueValues(profiles,
    (p) => signaturesByProfile[p].response_class || "unknown");
  if (responseClasses.size > 1) {
    divergences.push({
      type: "response_class_differs",
      severity_class: SEVERITY_DOC_OR_INFRA,
      evidence_summary: summarizeProfileValues(profiles, signaturesByProfile,
        (s) => s.response_class || "unknown"),
    });
  }
  const bodyHashes = pickUniqueValues(profiles,
    (p) => signaturesByProfile[p].body_hash || "null");
  if (bodyHashes.size > 1) {
    divergences.push({
      type: "body_hash_differs",
      severity_class: SEVERITY_DOC_OR_INFRA,
      evidence_summary: summarizeProfileValues(profiles, signaturesByProfile,
        (s) => (s.body_hash ? s.body_hash.slice(0, 8) : "null")),
    });
  }
  const lengthBuckets = pickUniqueValues(profiles,
    (p) => signaturesByProfile[p].body_length_bucket || "empty");
  if (lengthBuckets.size > 1) {
    divergences.push({
      type: "body_length_bucket_differs",
      severity_class: SEVERITY_DOC_OR_INFRA,
      evidence_summary: summarizeProfileValues(profiles, signaturesByProfile,
        (s) => s.body_length_bucket || "empty"),
    });
  }
  const sensitiveCounts = profiles.map((p) => signaturesByProfile[p].sensitive_field_count || 0);
  const minSensitive = Math.min(...sensitiveCounts);
  const maxSensitive = Math.max(...sensitiveCounts);
  if (maxSensitive > minSensitive) {
    divergences.push({
      type: "sensitive_field_count_differs",
      severity_class: SEVERITY_INFO_LEAK,
      evidence_summary: summarizeProfileValues(profiles, signaturesByProfile,
        (s) => String(s.sensitive_field_count || 0)),
    });
  }
  const unauthSecurity = detectUnauthSuccessWhileAuthBlocked(profiles, signaturesByProfile, profileMetadata);
  if (unauthSecurity) divergences.push(unauthSecurity);
  divergences.sort((a, b) => a.type.localeCompare(b.type));
  return divergences;
}

module.exports = {
  computeResponseSignature,
  diffResponseSignatures,
  DIVERGENCE_TYPES,
  SEVERITY_SECURITY,
  SEVERITY_INFO_LEAK,
  SEVERITY_DOC_OR_INFRA,
};
