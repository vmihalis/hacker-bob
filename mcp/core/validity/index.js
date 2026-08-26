"use strict";

const {
  signRowWithMac,
  verifyRowWithMac,
} = require("../ledger-integrity/index.js");
const {
  hashCanonicalJson,
} = require("../verification/verification-contracts.js");
const {
  CONTROL_SEMANTICS,
  evaluateObjectAuthDifferential,
} = require("../belief/differential-tester.js");
const {
  CONTROL_VALIDITY_CLASS_OBJECT_AUTH,
  OBJECT_AUTH_CLASS_ALIASES,
} = require("./class-ids.js");

const CONTROL_VALIDITY_KERNEL_VERSION = "control-validity-kernel.v1";
const CONTROL_VALIDITY_ROW_MAC_CONTEXT = "hacker-bob:control-validity-row:v1";
const CONTROL_VALIDITY_CERTIFICATE_MAC_CONTEXT = "hacker-bob:control-validity-certificate:v1";

const DISPOSITION_CERTIFIED = "certified";
const DISPOSITION_HOLD = "hold";

const FAILURE_MODE_VALUES = Object.freeze([
  "none",
  "malformed",
  "nonexistent",
  "unauth",
  "unauthorized_existing",
  "ratelimited",
  "waf",
  "stale",
  "unknown",
]);
const FAILURE_MODE_SET = new Set(FAILURE_MODE_VALUES);

const SOFT_SOURCE_VALUES = new Set([
  "belief",
  "posterior",
  "llm",
  "model",
  "generated",
  "hypothesis",
]);

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

function uniqueSorted(values) {
  return Array.from(new Set(values)).sort();
}

function normalizeClassId(classId) {
  if (OBJECT_AUTH_CLASS_ALIASES.has(classId)) return CONTROL_VALIDITY_CLASS_OBJECT_AUTH;
  return isNonEmptyString(classId) ? classId : null;
}

function rowDigest(row) {
  return hashCanonicalJson(row);
}

function unsignedProjection(row) {
  const out = {};
  for (const key of Object.keys(row).sort()) {
    if (key === "row_mac") continue;
    out[key] = row[key];
  }
  return out;
}

function certificateHashPreimage(certificate) {
  const out = {};
  for (const key of Object.keys(certificate).sort()) {
    if (key === "row_mac" || key === "certificate_hash") continue;
    out[key] = certificate[key];
  }
  return out;
}

function hasVerifiedRowMac(row, verifier) {
  if (!isPlainObject(row) || !isPlainObject(row.row_mac)) return false;
  if (typeof verifier === "function") return verifier(row) === true;
  return verifyRowWithMac(CONTROL_VALIDITY_ROW_MAC_CONTEXT, row, verifier);
}

function certifyBody(input) {
  const body = {
    kernel_version: CONTROL_VALIDITY_KERNEL_VERSION,
    class_id: input.class_id || null,
    disposition: input.disposition,
    certifies: input.disposition === DISPOSITION_CERTIFIED,
    reason: input.reason,
    context: isPlainObject(input.context) ? { ...input.context } : {},
    attempt_id: input.attempt_id || null,
    episode_id: input.episode_id || null,
    row_digests: Array.isArray(input.row_digests) ? input.row_digests.slice().sort() : [],
    positive_boundary_witnesses: Array.isArray(input.positive_boundary_witnesses)
      ? input.positive_boundary_witnesses.slice().sort()
      : [],
    existence_witnesses: Array.isArray(input.existence_witnesses)
      ? input.existence_witnesses.slice().sort()
      : [],
    discriminators: isPlainObject(input.discriminators) ? { ...input.discriminators } : {},
    alternative_explanations_tested: Array.isArray(input.alternative_explanations_tested)
      ? input.alternative_explanations_tested.slice().sort()
      : [],
    hold_reasons: Array.isArray(input.hold_reasons) ? input.hold_reasons.slice().sort() : [],
  };
  const certificate = Object.freeze({
    ...body,
    certificate_hash: hashCanonicalJson(body),
  });
  if (!input.certificate_signer) return certificate;
  const signed = { ...certificate };
  signRowWithMac(CONTROL_VALIDITY_CERTIFICATE_MAC_CONTEXT, signed, input.certificate_signer);
  return Object.freeze(signed);
}

function holdCertificate(reason, input = {}) {
  return certifyBody({
    class_id: normalizeClassId(input.class_id),
    disposition: DISPOSITION_HOLD,
    reason,
    context: input.context,
    row_digests: input.row_digests,
    hold_reasons: [reason].concat(input.hold_reasons || []),
    certificate_signer: input.certificate_signer,
  });
}

function rowSoftReason(row) {
  if (!isPlainObject(row)) return "row is not an object";
  if (row.soft === true || row.advisory === true || row.generated_hypothesis === true) {
    return "soft or generated row is not closure input";
  }
  const source = isNonEmptyString(row.source_plane) ? row.source_plane : row.source;
  if (SOFT_SOURCE_VALUES.has(source)) return `soft source ${source} is not closure input`;
  return null;
}

function verifySignedRows(rows, verifier) {
  if (!Array.isArray(rows) || rows.length === 0) {
    return { ok: false, reason: "no signed control rows supplied", rows: [] };
  }
  const verified = [];
  for (const row of rows) {
    const soft = rowSoftReason(row);
    if (soft) return { ok: false, reason: soft, rows: verified };
    if (!hasVerifiedRowMac(row, verifier)) {
      return { ok: false, reason: "unsigned or unverifiable control row", rows: verified };
    }
    verified.push(Object.freeze(unsignedProjection(row)));
  }
  return { ok: true, rows: verified };
}

function responseText(row) {
  if (!isPlainObject(row)) return "";
  const pieces = [];
  for (const key of ["body", "error", "reason", "response_body"]) {
    const value = row[key];
    if (typeof value === "string") pieces.push(value);
    else if (isPlainObject(value) || Array.isArray(value)) pieces.push(JSON.stringify(value));
  }
  return pieces.join(" ").toLowerCase();
}

function inferFailureMode(row) {
  if (!isPlainObject(row)) return "unknown";
  if (row.reached === true) return "none";

  const status = typeof row.status === "number" ? row.status : null;
  const klass = isNonEmptyString(row.response_class) ? row.response_class : "";
  const text = responseText(row);

  if (status === 429 || /rate.?limit|too many requests/.test(text)) return "ratelimited";
  if (/waf|cloudflare|captcha|bot|security policy|blocked by/.test(text)) return "waf";
  if (status === 400 || status === 422 || /malformed|invalid request|bad request|parse/.test(text)) return "malformed";
  if (status === 404 || klass === "not_found" || /not found|missing id|missing object|unknown object/.test(text)) {
    return "nonexistent";
  }
  if (row.control === "stale_session_check" && (status === 401 || status === 403)) return "stale";
  if (status === 401 || klass === "auth_required") return "unauth";
  if (status === 403 || klass === "forbidden") return "unauthorized_existing";
  if (FAILURE_MODE_SET.has(row.failure_mode)) return row.failure_mode;
  return "unknown";
}

function sameNonEmptyField(rows, field) {
  const values = uniqueSorted(rows.map((row) => row[field]).filter(isNonEmptyString));
  if (values.length !== 1) return null;
  return values[0];
}

function rowsByControl(rows) {
  const byControl = new Map();
  for (const row of rows) {
    if (!isNonEmptyString(row.control)) continue;
    if (!byControl.has(row.control)) byControl.set(row.control, []);
    byControl.get(row.control).push(row);
  }
  return byControl;
}

function objectAuthExpectedFailureModes(control) {
  if (control === "nonexistent_object") return new Set(["nonexistent"]);
  if (control === "stale_session_check") return new Set(["stale", "unauthorized_existing"]);
  return new Set(["unauthorized_existing"]);
}

function evaluateObjectAuthControlValidity({ rows, class_id, context, certificate_signer }) {
  const holdReasons = [];
  const rowDigests = rows.map(rowDigest);
  const attemptId = sameNonEmptyField(rows, "attempt_id");
  const episodeId = sameNonEmptyField(rows, "episode_id");
  if (!attemptId) holdReasons.push("control rows do not share one non-empty attempt_id");
  if (!episodeId) holdReasons.push("control rows do not share one non-empty episode_id");

  const byControl = rowsByControl(rows);
  const requiredControls = Object.keys(CONTROL_SEMANTICS).sort();
  const primary = byControl.get("__primary__") && byControl.get("__primary__")[0];
  if (!primary || primary.reached !== true) holdReasons.push("primary treatment did not reach the victim object");

  const controls = {};
  const discriminators = {};
  const positiveBoundaryWitnesses = [];
  const existenceWitnesses = [];

  for (const name of requiredControls) {
    const matches = byControl.get(name) || [];
    if (matches.length !== 1) {
      holdReasons.push(`${name} must have exactly one signed row`);
      continue;
    }
    const row = matches[0];
    const sem = CONTROL_SEMANTICS[name];
    const reached = row.reached === true;
    const mode = inferFailureMode(row);
    controls[name] = {
      reached,
      ...(isNonEmptyString(row.evidence_ref) ? { evidence_ref: row.evidence_ref } : {}),
    };
    discriminators[name] = mode;

    if (row.channel_validity === false || row.channel_validity === "compromised") {
      holdReasons.push(`${name} channel validity is compromised`);
    }

    if (sem.kind === "positive") {
      if (reached !== true) holdReasons.push(`${name} positive boundary witness did not reach`);
      else positiveBoundaryWitnesses.push(name);
      if (name === "victim_auth_same_object" && reached === true) existenceWitnesses.push(name);
      continue;
    }

    if (reached !== sem.safe_reached) continue;
    if (sem.safe_reached === true) {
      positiveBoundaryWitnesses.push(name);
      continue;
    }
    const allowedModes = objectAuthExpectedFailureModes(name);
    if (!allowedModes.has(mode)) {
      holdReasons.push(`${name} denied for ${mode}, not ${Array.from(allowedModes).sort().join("/")}`);
    }
  }

  const verdict = evaluateObjectAuthDifferential({
    primary_effect: { reached: primary && primary.reached === true },
    controls,
  });
  if (verdict.disposition !== "confirmed") {
    holdReasons.push(`object-auth differential is ${verdict.disposition}: ${verdict.reason}`);
  }

  if (holdReasons.length > 0) {
    return certifyBody({
      class_id,
      disposition: DISPOSITION_HOLD,
      reason: "control validity refused",
      context,
      attempt_id: attemptId,
      episode_id: episodeId,
      row_digests: rowDigests,
      positive_boundary_witnesses: positiveBoundaryWitnesses,
      existence_witnesses: existenceWitnesses,
      discriminators,
      alternative_explanations_tested: verdict.confounders_ruled_out,
      hold_reasons: holdReasons,
      certificate_signer,
    });
  }

  return certifyBody({
    class_id,
    disposition: DISPOSITION_CERTIFIED,
    reason: "object authorization controls deny for the registered right reasons",
    context,
    attempt_id: attemptId,
    episode_id: episodeId,
    row_digests: rowDigests,
    positive_boundary_witnesses: positiveBoundaryWitnesses,
    existence_witnesses: existenceWitnesses,
    discriminators,
    alternative_explanations_tested: verdict.confounders_ruled_out,
    certificate_signer,
  });
}

function buildControlValidityCertificate(input) {
  if (!isPlainObject(input)) {
    throw new TypeError("input must be a control-validity certificate request");
  }
  const classId = normalizeClassId(input.class_id || input.validity_class_id || input.bug_class);
  if (classId !== CONTROL_VALIDITY_CLASS_OBJECT_AUTH) {
    return holdCertificate("unknown control-validity class", {
      class_id: classId,
      context: input.context,
      certificate_signer: input.certificate_signer,
    });
  }
  const verified = verifySignedRows(input.rows || input.signed_rows, input.row_verifier);
  if (!verified.ok) {
    return holdCertificate(verified.reason, {
      class_id: classId,
      context: input.context,
      row_digests: (input.rows || input.signed_rows || []).filter(isPlainObject).map(rowDigest),
      certificate_signer: input.certificate_signer,
    });
  }
  return evaluateObjectAuthControlValidity({
    rows: verified.rows,
    class_id: classId,
    context: input.context,
    certificate_signer: input.certificate_signer,
  });
}

function verifyControlValidityCertificate(certificate, verifier) {
  if (!isPlainObject(certificate)) return false;
  if (certificate.certificate_hash !== hashCanonicalJson(certificateHashPreimage(certificate))) return false;
  if (!isPlainObject(certificate.row_mac)) return true;
  return verifyRowWithMac(CONTROL_VALIDITY_CERTIFICATE_MAC_CONTEXT, certificate, verifier);
}

function objectAuthControlValidityRowsFromProbe(probe, context = {}) {
  if (!isPlainObject(probe)) return [];
  const common = {
    class_id: CONTROL_VALIDITY_CLASS_OBJECT_AUTH,
    attempt_id: context.attempt_id || null,
    episode_id: context.episode_id || null,
    session_nucleus: context.session_nucleus || null,
    surface: context.surface || null,
    target_domain: context.target_domain || null,
  };
  const rows = [];
  if (isPlainObject(probe.primary_effect)) {
    rows.push({
      ...common,
      control: "__primary__",
      reached: probe.primary_effect.reached === true,
      response_class: probe.primary_effect.response_class || null,
      failure_mode: probe.primary_effect.reached === true ? "none" : "unknown",
      body_match: probe.primary_effect.body_match ?? null,
    });
  }
  const controls = isPlainObject(probe.controls) ? probe.controls : {};
  for (const name of Object.keys(controls).sort()) {
    const entry = controls[name];
    if (!isPlainObject(entry)) continue;
    rows.push({
      ...common,
      control: name,
      reached: entry.reached === true,
      status: typeof entry.status === "number" ? entry.status : null,
      response_class: entry.response_class || null,
      failure_mode: inferFailureMode({ ...entry, control: name }),
      ...(isNonEmptyString(entry.evidence_ref) ? { evidence_ref: entry.evidence_ref } : {}),
    });
  }
  return rows;
}

module.exports = {
  CONTROL_VALIDITY_KERNEL_VERSION,
  CONTROL_VALIDITY_ROW_MAC_CONTEXT,
  CONTROL_VALIDITY_CERTIFICATE_MAC_CONTEXT,
  CONTROL_VALIDITY_CLASS_OBJECT_AUTH,
  OBJECT_AUTH_CLASS_ALIASES,
  FAILURE_MODE_VALUES,
  DISPOSITION_CERTIFIED,
  DISPOSITION_HOLD,
  buildControlValidityCertificate,
  verifyControlValidityCertificate,
  inferFailureMode,
  objectAuthControlValidityRowsFromProbe,
};
