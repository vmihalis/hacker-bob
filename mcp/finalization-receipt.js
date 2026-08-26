"use strict";

const crypto = require("crypto");
const fs = require("fs");

const {
  CHAIN_FAMILY_VALUES,
} = require("./core/constants/shared-vocabulary.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./core/io/envelope.js");
const {
  finalizationReceiptPath,
  finalizationReceiptSidecarPath,
} = require("./core/io/paths.js");
const {
  readFileUtf8,
  withSessionLock,
  writeFileExclusiveAtomic,
} = require("./core/io/storage.js");

const RECEIPT_SCHEMA_VERSION = 1;
const CONSOLE_REPORT_SCHEMA_VERSION = 1;
const RECEIPT_MAX_BYTES = 4 * 1024 * 1024;
const SHA256_RE = /^[0-9a-f]{64}$/;
const HEX24_RE = /^[0-9a-f]{24}$/;
const CONTROL_CHARACTER_RE = /[\u0000-\u001f\u007f-\u009f]/;
const ENCODED_CONTROL_CHARACTER_RE = /%(?:0[0-9a-f]|1[0-9a-f]|7f|8[0-9a-f]|9[0-9a-f])/i;
const DISPLAY_MARKUP_RE = /[<>]/;
const SEVERITY_VALUES = Object.freeze(["critical", "high", "medium", "low"]);
const DISPOSITION_VALUES = Object.freeze(["fix-now", "worth-fixing", "watch", "held"]);
const SURFACE_TYPE_VALUES = Object.freeze(["web", "smart_contract"]);
const RECEIPT_BASENAME = "finalization-receipt.json";
const SIDECAR_BASENAME = "finalization-receipt.sha256";

function receiptError(message, context = {}) {
  return new ToolError(ERROR_CODES.STATE_CONFLICT, message, context);
}

function assertExactObject(value, label, requiredKeys, optionalKeys = []) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    throw receiptError(`${label} must be an object`);
  }
  const allowedKeys = [...requiredKeys, ...optionalKeys];
  for (const key of Object.keys(value)) {
    if (!allowedKeys.includes(key)) {
      throw receiptError(`${label} contains unsupported field: ${key}`);
    }
  }
  for (const key of requiredKeys) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) {
      throw receiptError(`${label}.${key} is required`);
    }
  }
  return value;
}

function assertText(value, label, maxLength, { displaySafe = false } = {}) {
  if (typeof value !== "string") throw receiptError(`${label} must be a string`);
  const normalized = value.trim();
  if (!normalized) throw receiptError(`${label} is required`);
  if (normalized.length > maxLength) {
    throw receiptError(`${label} must be ${maxLength} characters or fewer`);
  }
  if (CONTROL_CHARACTER_RE.test(normalized)) {
    throw receiptError(`${label} must not contain control characters`);
  }
  if (displaySafe && DISPLAY_MARKUP_RE.test(normalized)) {
    throw receiptError(`${label} must not contain markup delimiters`);
  }
  return normalized;
}

function assertEnum(value, allowed, label) {
  if (typeof value !== "string" || !allowed.includes(value)) {
    throw receiptError(`${label} must be one of: ${allowed.join(", ")}`);
  }
  return value;
}

function assertBoolean(value, label) {
  if (typeof value !== "boolean") throw receiptError(`${label} must be a boolean`);
  return value;
}

function assertNonNegativeInteger(value, label) {
  if (!Number.isInteger(value) || value < 0) {
    throw receiptError(`${label} must be a non-negative integer`);
  }
  return value;
}

function assertFiniteNumber(value, label) {
  if (!Number.isFinite(value)) throw receiptError(`${label} must be a finite number`);
  return value;
}

function assertSha256(value, label) {
  if (typeof value !== "string" || !SHA256_RE.test(value)) {
    throw receiptError(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertIsoTimestamp(value, label) {
  const text = assertText(value, label, 64);
  let canonical;
  try {
    canonical = new Date(text).toISOString();
  } catch {
    throw receiptError(`${label} must be an ISO-8601 timestamp`);
  }
  if (canonical !== text) throw receiptError(`${label} must be a canonical ISO-8601 timestamp`);
  return text;
}

function normalizeEndpointTemplate(value, label) {
  const endpoint = assertText(value, label, 512, { displaySafe: true });
  if (ENCODED_CONTROL_CHARACTER_RE.test(endpoint)) {
    throw receiptError(`${label} must not contain encoded control characters`);
  }
  if (endpoint.includes("#")) throw receiptError(`${label} must not contain a fragment`);
  const withoutScheme = endpoint.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  const authority = withoutScheme.split(/[/?]/, 1)[0];
  if (authority.includes("@") || /%40/i.test(authority)) {
    throw receiptError(`${label} must not contain URI userinfo`);
  }
  const queryIndex = endpoint.indexOf("?");
  if (queryIndex >= 0) {
    const query = endpoint.slice(queryIndex + 1);
    const pairs = query.split("&");
    if (!query || pairs.some((pair) => !/^[^=&?#]+=\*$/.test(pair))) {
      throw receiptError(`${label} query values must use key=* placeholders`);
    }
  }
  return endpoint;
}

function normalizeScoreAxes(value, label) {
  const axes = assertExactObject(
    value,
    label,
    ["impact", "proof", "severityAccuracy", "chain", "report"],
  );
  return {
    impact: assertFiniteNumber(axes.impact, `${label}.impact`),
    proof: assertFiniteNumber(axes.proof, `${label}.proof`),
    severityAccuracy: assertFiniteNumber(axes.severityAccuracy, `${label}.severityAccuracy`),
    chain: assertFiniteNumber(axes.chain, `${label}.chain`),
    report: assertFiniteNumber(axes.report, `${label}.report`),
  };
}

function normalizeCwe(value, label) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 16) {
    throw receiptError(`${label} must contain 1..16 structured CWE rows`);
  }
  return value.map((raw, index) => {
    const rowLabel = `${label}[${index}]`;
    const row = assertExactObject(raw, rowLabel, ["id", "name"], ["read"]);
    const normalized = {
      id: assertText(row.id, `${rowLabel}.id`, 32, { displaySafe: true }),
      name: assertText(row.name, `${rowLabel}.name`, 200, { displaySafe: true }),
    };
    if (row.read !== undefined) {
      normalized.read = assertText(row.read, `${rowLabel}.read`, 500, { displaySafe: true });
    }
    return normalized;
  });
}

function normalizeScEvidence(value, label) {
  const evidence = assertExactObject(
    value,
    label,
    ["chainId", "contractIdentity", "functionSignature"],
  );
  return {
    chainId: assertText(evidence.chainId, `${label}.chainId`, 128, { displaySafe: true }),
    contractIdentity: assertText(
      evidence.contractIdentity,
      `${label}.contractIdentity`,
      256,
      { displaySafe: true },
    ),
    functionSignature: assertText(
      evidence.functionSignature,
      `${label}.functionSignature`,
      200,
      { displaySafe: true },
    ),
  };
}

function normalizeSafeProjectedFinding(value, index) {
  const label = `consoleReport.findings[${index}]`;
  const required = [
    "fingerprint",
    "fingerprintVersion",
    "refId",
    "dedupeKey",
    "title",
    "plainRead",
    "severity",
    "disposition",
    "reproduced",
    "reachable",
    "reportable",
    "score",
    "scoreAxes",
    "cwe",
    "surfaceType",
    "evidenceHash",
    "snapshotHash",
    "open",
  ];
  const optional = [
    "verifierPassed",
    "cvssVector",
    "cvssScore",
    "cvssVersion",
    "chainFamily",
    "scEvidence",
    "endpoint",
    "tags",
  ];
  const finding = assertExactObject(value, label, required, optional);
  if (finding.fingerprintVersion !== 1) {
    throw receiptError(`${label}.fingerprintVersion must equal 1`);
  }
  if (typeof finding.fingerprint !== "string" || !SHA256_RE.test(finding.fingerprint)) {
    throw receiptError(`${label}.fingerprint must be a lowercase SHA-256 digest`);
  }
  if (typeof finding.dedupeKey !== "string" || !HEX24_RE.test(finding.dedupeKey)) {
    throw receiptError(`${label}.dedupeKey must be a 24-character lowercase hex digest`);
  }
  const normalized = {
    fingerprint: finding.fingerprint,
    fingerprintVersion: 1,
    refId: assertText(finding.refId, `${label}.refId`, 64, { displaySafe: true }),
    dedupeKey: finding.dedupeKey,
    title: assertText(finding.title, `${label}.title`, 200, { displaySafe: true }),
    plainRead: assertText(finding.plainRead, `${label}.plainRead`, 2000, { displaySafe: true }),
    severity: assertEnum(finding.severity, SEVERITY_VALUES, `${label}.severity`),
    disposition: assertEnum(finding.disposition, DISPOSITION_VALUES, `${label}.disposition`),
    reproduced: assertBoolean(finding.reproduced, `${label}.reproduced`),
    reachable: assertBoolean(finding.reachable, `${label}.reachable`),
    reportable: assertBoolean(finding.reportable, `${label}.reportable`),
    score: assertFiniteNumber(finding.score, `${label}.score`),
    scoreAxes: normalizeScoreAxes(finding.scoreAxes, `${label}.scoreAxes`),
    cwe: normalizeCwe(finding.cwe, `${label}.cwe`),
    surfaceType: assertEnum(finding.surfaceType, SURFACE_TYPE_VALUES, `${label}.surfaceType`),
    evidenceHash: assertSha256(finding.evidenceHash, `${label}.evidenceHash`),
    snapshotHash: assertSha256(finding.snapshotHash, `${label}.snapshotHash`),
    open: assertBoolean(finding.open, `${label}.open`),
  };
  if (normalized.reportable !== true) {
    throw receiptError(`${label}.reportable must be true`);
  }
  if (finding.verifierPassed !== undefined) {
    normalized.verifierPassed = assertBoolean(finding.verifierPassed, `${label}.verifierPassed`);
  }
  for (const [key, maxLength] of [
    ["cvssVector", 256],
    ["cvssScore", 32],
    ["cvssVersion", 32],
  ]) {
    if (finding[key] !== undefined) {
      normalized[key] = assertText(finding[key], `${label}.${key}`, maxLength, { displaySafe: true });
    }
  }
  if (finding.tags !== undefined) {
    if (!Array.isArray(finding.tags) || finding.tags.length > 32) {
      throw receiptError(`${label}.tags must contain at most 32 strings`);
    }
    normalized.tags = finding.tags.map((tag, tagIndex) => (
      assertText(tag, `${label}.tags[${tagIndex}]`, 64, { displaySafe: true })
    ));
  }
  if (normalized.surfaceType === "web") {
    if (finding.chainFamily !== undefined || finding.scEvidence !== undefined) {
      throw receiptError(`${label} web surface must not include smart-contract evidence`);
    }
    normalized.endpoint = normalizeEndpointTemplate(finding.endpoint, `${label}.endpoint`);
  } else {
    if (finding.endpoint !== undefined) {
      throw receiptError(`${label} smart-contract surface must not include a web endpoint`);
    }
    normalized.chainFamily = assertEnum(
      finding.chainFamily,
      CHAIN_FAMILY_VALUES,
      `${label}.chainFamily`,
    );
    normalized.scEvidence = normalizeScEvidence(finding.scEvidence, `${label}.scEvidence`);
  }
  return normalized;
}

function normalizeArtifact(value) {
  const artifact = assertExactObject(
    value,
    "artifact",
    ["emitted", "sha256", "findingCount"],
  );
  const emitted = assertBoolean(artifact.emitted, "artifact.emitted");
  const findingCount = assertNonNegativeInteger(artifact.findingCount, "artifact.findingCount");
  if (emitted) {
    if (artifact.sha256 == null) throw receiptError("artifact.sha256 is required when artifact.emitted is true");
    if (findingCount < 1) throw receiptError("artifact.findingCount must be positive when artifact.emitted is true");
  } else {
    if (artifact.sha256 !== null) throw receiptError("artifact.sha256 must be null when artifact.emitted is false");
    if (findingCount !== 0) throw receiptError("artifact.findingCount must be zero when artifact.emitted is false");
  }
  return {
    emitted,
    sha256: emitted ? assertSha256(artifact.sha256, "artifact.sha256") : null,
    findingCount,
  };
}

function normalizeProjection(value) {
  const projection = assertExactObject(
    value,
    "projection",
    ["required", "succeeded", "duplicate", "projected", "reopened", "closed"],
  );
  const normalized = {
    required: assertBoolean(projection.required, "projection.required"),
    succeeded: assertBoolean(projection.succeeded, "projection.succeeded"),
    duplicate: assertBoolean(projection.duplicate, "projection.duplicate"),
    projected: assertNonNegativeInteger(projection.projected, "projection.projected"),
    reopened: assertNonNegativeInteger(projection.reopened, "projection.reopened"),
    closed: assertNonNegativeInteger(projection.closed, "projection.closed"),
  };
  if (normalized.required && !normalized.succeeded) {
    throw receiptError("a required projection must succeed before a receipt is written");
  }
  if (!normalized.required && (
    normalized.succeeded
    || normalized.duplicate
    || normalized.projected !== 0
    || normalized.reopened !== 0
    || normalized.closed !== 0
  )) {
    throw receiptError("a non-required projection must use the not-attempted zero result");
  }
  if (normalized.duplicate && !normalized.succeeded) {
    throw receiptError("a duplicate projection result must be successful");
  }
  return normalized;
}

function normalizeConsoleReport(value, targetDomain) {
  const report = assertExactObject(value, "consoleReport", ["schemaVersion", "domain", "findings"]);
  if (report.schemaVersion !== CONSOLE_REPORT_SCHEMA_VERSION) {
    throw receiptError(`consoleReport.schemaVersion must equal ${CONSOLE_REPORT_SCHEMA_VERSION}`);
  }
  const domain = assertText(report.domain, "consoleReport.domain", 512, { displaySafe: true });
  if (domain !== targetDomain) throw receiptError("consoleReport.domain must equal targetDomain");
  if (!Array.isArray(report.findings) || report.findings.length > 10_000) {
    throw receiptError("consoleReport.findings must be an array of at most 10000 rows");
  }
  return {
    schemaVersion: CONSOLE_REPORT_SCHEMA_VERSION,
    domain,
    findings: report.findings.map(normalizeSafeProjectedFinding),
  };
}

function normalizeFinalizationReceipt(value) {
  const receipt = assertExactObject(
    value,
    "finalization receipt",
    [
      "schemaVersion",
      "runSlug",
      "targetDomain",
      "reportSlug",
      "completedAt",
      "freezeHash",
      "snapshotHash",
      "evidenceHash",
      "reportContentHash",
      "artifact",
      "projection",
      "consoleReport",
    ],
  );
  if (receipt.schemaVersion !== RECEIPT_SCHEMA_VERSION) {
    throw receiptError(`schemaVersion must equal ${RECEIPT_SCHEMA_VERSION}`);
  }
  const targetDomain = assertText(receipt.targetDomain, "targetDomain", 512, { displaySafe: true });
  const normalized = {
    schemaVersion: RECEIPT_SCHEMA_VERSION,
    runSlug: assertText(receipt.runSlug, "runSlug", 256, { displaySafe: true }),
    targetDomain,
    reportSlug: assertText(receipt.reportSlug, "reportSlug", 256, { displaySafe: true }),
    completedAt: assertIsoTimestamp(receipt.completedAt, "completedAt"),
    freezeHash: assertSha256(receipt.freezeHash, "freezeHash"),
    snapshotHash: assertSha256(receipt.snapshotHash, "snapshotHash"),
    evidenceHash: assertSha256(receipt.evidenceHash, "evidenceHash"),
    reportContentHash: assertSha256(receipt.reportContentHash, "reportContentHash"),
    artifact: normalizeArtifact(receipt.artifact),
    projection: normalizeProjection(receipt.projection),
    consoleReport: normalizeConsoleReport(receipt.consoleReport, targetDomain),
  };
  return normalized;
}

function receiptContent(receipt) {
  return `${JSON.stringify(receipt, null, 2)}\n`;
}

function receiptDigest(content) {
  return crypto.createHash("sha256").update(content, "utf8").digest("hex");
}

function readFinalizationReceipt(domain, { required = true } = {}) {
  const jsonPath = finalizationReceiptPath(domain);
  const sidecarPath = finalizationReceiptSidecarPath(domain);
  const hasJson = fs.existsSync(jsonPath);
  const hasSidecar = fs.existsSync(sidecarPath);
  if (!hasJson && !hasSidecar) {
    if (!required) return null;
    throw receiptError("finalization receipt is not present", { missing_artifact: RECEIPT_BASENAME });
  }
  if (!hasJson || !hasSidecar) {
    if (!required) return null;
    throw receiptError("finalization receipt and sidecar must either both exist or both be absent", {
      receipt_present: hasJson,
      sidecar_present: hasSidecar,
    });
  }

  let content;
  let parsed;
  try {
    content = readFileUtf8(jsonPath, { label: RECEIPT_BASENAME, maxBytes: RECEIPT_MAX_BYTES });
    parsed = JSON.parse(content);
  } catch (error) {
    if (error instanceof ToolError) throw error;
    throw receiptError(`failed to read ${RECEIPT_BASENAME}: ${error.message || String(error)}`);
  }
  const receipt = normalizeFinalizationReceipt(parsed);
  const sidecar = readFileUtf8(sidecarPath, { label: SIDECAR_BASENAME, maxBytes: 256 }).trim();
  const match = /^([0-9a-f]{64})  finalization-receipt\.json$/.exec(sidecar);
  if (!match) throw receiptError(`${SIDECAR_BASENAME} has an invalid format`);
  const actual = receiptDigest(content);
  if (match[1] !== actual) {
    throw receiptError("finalization receipt sidecar digest does not match the receipt", {
      expected_sha256: match[1],
      actual_sha256: actual,
    });
  }
  return { receipt, sha256: actual };
}

function writeFinalizationReceipt(domain, value) {
  const receipt = normalizeFinalizationReceipt(value);
  const sameCompletion = (left, right) => {
    const { completedAt: _leftCompletedAt, ...leftStable } = left;
    const { completedAt: _rightCompletedAt, ...rightStable } = right;
    return JSON.stringify(leftStable) === JSON.stringify(rightStable);
  };
  return withSessionLock(domain, () => {
    const jsonPath = finalizationReceiptPath(domain);
    const sidecarPath = finalizationReceiptSidecarPath(domain);
    if (fs.existsSync(jsonPath) !== fs.existsSync(sidecarPath)) {
      try { fs.unlinkSync(jsonPath); } catch {}
      try { fs.unlinkSync(sidecarPath); } catch {}
    }
    const existing = readFinalizationReceipt(domain, { required: false });
    if (existing) {
      if (sameCompletion(existing.receipt, receipt)) {
        return { ...existing, written: false };
      }
      throw receiptError("completed finalization receipt conflicts with the requested receipt");
    }

    const content = receiptContent(receipt);
    const sha256 = receiptDigest(content);
    const wroteJson = writeFileExclusiveAtomic(jsonPath, content, { mode: 0o600 });
    if (!wroteJson) {
      const raced = readFinalizationReceipt(domain);
      if (sameCompletion(raced.receipt, receipt)) {
        return { ...raced, written: false };
      }
      throw receiptError("completed finalization receipt conflicts with the requested receipt");
    }

    let wroteSidecar = false;
    try {
      wroteSidecar = writeFileExclusiveAtomic(
        sidecarPath,
        `${sha256}  ${RECEIPT_BASENAME}\n`,
        { mode: 0o600 },
      );
      if (!wroteSidecar) throw receiptError("finalization receipt sidecar already exists");
      const stored = readFinalizationReceipt(domain);
      return { ...stored, written: true };
    } catch (error) {
      if (wroteSidecar) {
        try { fs.unlinkSync(sidecarPath); } catch {}
      }
      try { fs.unlinkSync(jsonPath); } catch {}
      throw error;
    }
  });
}

module.exports = {
  CONSOLE_REPORT_SCHEMA_VERSION,
  RECEIPT_SCHEMA_VERSION,
  normalizeFinalizationReceipt,
  normalizeSafeProjectedFinding,
  readFinalizationReceipt,
  receiptContent,
  receiptDigest,
  writeFinalizationReceipt,
};
