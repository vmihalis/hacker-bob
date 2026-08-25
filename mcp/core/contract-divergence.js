"use strict";

const SEVERITY_SECURITY = "security";
const SEVERITY_INFO_LEAK = "info_leak_potential";
const SEVERITY_DOC_OR_INFRA = "doc_or_infra";

const DIVERGENCE_TYPES = Object.freeze([
  "auth_required_but_succeeded_without",
  "auth_required_but_returned_unauthenticated_class",
  "documented_endpoint_unreachable",
  "claimed_status_not_observed",
  "undocumented_field_in_response",
  "required_field_missing_in_response",
  "content_type_mismatch",
]);

const EVIDENCE_FIELD_LIMIT = 5;

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function statusKey(status) {
  return typeof status === "number" ? String(status) : null;
}

function summariseList(items, limit = EVIDENCE_FIELD_LIMIT) {
  const truncated = items.slice(0, limit);
  return truncated.length === items.length
    ? truncated.join(",")
    : `${truncated.join(",")},...`;
}

function detectAuthDivergence(contract, observed) {
  const auth = contract.claimed_auth;
  if (!isPlainObject(auth)) return [];
  const schemes = Array.isArray(auth.schemes) ? auth.schemes : [];
  if (schemes.length === 0 || auth.none_allowed === true) return [];
  if (typeof observed.status !== "number") return [];
  if (observed.status >= 200 && observed.status < 300 && observed.sent_with_auth === false) {
    return [{
      type: "auth_required_but_succeeded_without",
      severity_class: SEVERITY_SECURITY,
      evidence_summary: `claimed schemes [${schemes.join(",")}]; observed ${observed.status} without auth`,
    }];
  }
  if ((observed.status === 401 || observed.status === 403)
    && observed.sent_with_auth === true) {
    return [{
      type: "auth_required_but_returned_unauthenticated_class",
      severity_class: SEVERITY_DOC_OR_INFRA,
      evidence_summary: `claimed schemes [${schemes.join(",")}]; observed ${observed.status} with auth`,
    }];
  }
  return [];
}

function detectStatusDivergence(contract, observed) {
  const responseShape = isPlainObject(contract.claimed_response_shape)
    ? contract.claimed_response_shape
    : {};
  const claimedStatuses = Object.keys(responseShape);
  if (claimedStatuses.length === 0) return [];
  const observedStatusKey = statusKey(observed.status);
  if (observedStatusKey == null) return [];
  if (observedStatusKey === "404") {
    return [{
      type: "documented_endpoint_unreachable",
      severity_class: SEVERITY_DOC_OR_INFRA,
      evidence_summary: `claimed responses [${claimedStatuses.join(",")}]; observed 404`,
    }];
  }
  if (claimedStatuses.includes(observedStatusKey)) return [];
  return [{
    type: "claimed_status_not_observed",
    severity_class: SEVERITY_DOC_OR_INFRA,
    evidence_summary: `claimed [${claimedStatuses.join(",")}]; observed ${observedStatusKey}`,
  }];
}

function detectShapeDivergence(contract, observed) {
  if (typeof observed.status !== "number") return [];
  const responseShape = isPlainObject(contract.claimed_response_shape)
    ? contract.claimed_response_shape
    : {};
  const claimedForStatus = responseShape[String(observed.status)];
  if (!isPlainObject(claimedForStatus)) return [];
  const divergences = [];
  if (typeof claimedForStatus.content_type === "string"
    && typeof observed.content_type === "string"
    && claimedForStatus.content_type.toLowerCase() !== observed.content_type.toLowerCase()) {
    divergences.push({
      type: "content_type_mismatch",
      severity_class: SEVERITY_DOC_OR_INFRA,
      evidence_summary: `claimed ${claimedForStatus.content_type}; observed ${observed.content_type}`,
    });
  }
  const expectedShape = isPlainObject(claimedForStatus.shape) ? claimedForStatus.shape : null;
  if (!expectedShape) return divergences;
  if (expectedShape.type !== "object") return divergences;
  if (!isPlainObject(observed.body)) return divergences;
  const claimedProperties = isPlainObject(expectedShape.properties)
    ? Object.keys(expectedShape.properties)
    : [];
  const observedProperties = Object.keys(observed.body);
  if (claimedProperties.length > 0) {
    const claimedSet = new Set(claimedProperties);
    const undocumented = observedProperties.filter((key) => !claimedSet.has(key)).sort();
    if (undocumented.length > 0) {
      divergences.push({
        type: "undocumented_field_in_response",
        severity_class: SEVERITY_INFO_LEAK,
        evidence_summary: `undocumented [${summariseList(undocumented)}]`,
      });
    }
  }
  if (Array.isArray(expectedShape.required) && expectedShape.required.length > 0) {
    const observedSet = new Set(observedProperties);
    const missing = expectedShape.required.filter((key) => !observedSet.has(key)).sort();
    if (missing.length > 0) {
      divergences.push({
        type: "required_field_missing_in_response",
        severity_class: SEVERITY_DOC_OR_INFRA,
        evidence_summary: `missing required [${summariseList(missing)}]`,
      });
    }
  }
  return divergences;
}

function detectDivergences(contract, observed) {
  if (!isPlainObject(contract)) {
    throw new TypeError("contract must be an object");
  }
  if (!isPlainObject(observed)) {
    throw new TypeError("observed must be an object");
  }
  const divergences = [];
  divergences.push(...detectAuthDivergence(contract, observed));
  divergences.push(...detectStatusDivergence(contract, observed));
  divergences.push(...detectShapeDivergence(contract, observed));
  divergences.sort((a, b) => a.type.localeCompare(b.type));
  return divergences;
}

module.exports = {
  detectDivergences,
  DIVERGENCE_TYPES,
  SEVERITY_SECURITY,
  SEVERITY_INFO_LEAK,
  SEVERITY_DOC_OR_INFRA,
};
