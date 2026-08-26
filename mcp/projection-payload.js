"use strict";

// runner-wiring: the www projection payload builder.
//
// Maps the sealed finding artifact back into the www projectedFinding shape
// (fingerprint, severity, disposition, open, ...) that POST /api/findings
// accepts. ADR-002's continuity fingerprint is computed here from STABLE
// parts only — asset key, generalized route template, primary CWE, auth
// profile, surface type — so evidence drift updates one row and never forks
// it. The per-run capability (projectionKey) and scope (kind/retestOf) are
// supplied by the runner environment, never derived from findings.

const crypto = require("crypto");

const {
  assembleFindingArtifact,
} = require("./finding-artifact.js");
const {
  computeFindingDedupeKey,
  findingUsesWebContinuity,
  normalizeEndpointForDedupe,
} = require("./core/finding-contracts.js");
const {
  normalizeSafeProjectedFinding,
} = require("./finalization-receipt.js");
const {
  assertValidCwe,
  cweTitle,
} = require("./core/scoring/cwe-catalog.js");
const {
  loadFinalVerificationDocument,
} = require("./core/report-finalize.js");
const {
  loadJsonDocumentStrict,
} = require("./core/io/storage.js");
const {
  gradeArtifactPaths,
} = require("./core/io/paths.js");
const {
  CHAIN_FAMILY_VALUES,
} = require("./core/constants/shared-vocabulary.js");
const {
  detectPiiShapes,
} = require("./core/pii-detector.js");

const FINGERPRINT_VERSION = 1;
const SHA256_RE = /^[0-9a-f]{64}$/;
const CONSOLE_REPORT_MAX_BYTES = 900000;
const CONSOLE_REPORT_MAX_FINDINGS = 10000;

// Core findings have a narrower technology classification than www. Preserve
// those two values exactly and fail closed if a malformed artifact reaches this
// boundary.

// www findings.ts severity union. "info"-graded findings are not reportable
// medium+ and are excluded from projection (mapped to null here).
function projectionSeverity(severity) {
  if (severity === "critical" || severity === "high" || severity === "medium" || severity === "low") {
    return severity;
  }
  return null;
}

// Core DEFENDER_DISPOSITION_VALUES (fix_now/worth_fixing/watch/held) map to
// the www disposition union. Grading is authoritative; projection never
// fabricates a disposition for absent or unknown grade facts.
function projectionDisposition(defenderDisposition, findingId = "unknown") {
  switch (defenderDisposition) {
    case "fix_now": return "fix-now";
    case "worth_fixing": return "worth-fixing";
    case "watch": return "watch";
    case "held": return "held";
    default:
      throw new Error(
        `finding ${findingId} has missing or unsupported defender_disposition: ${String(defenderDisposition)}`,
      );
  }
}

function projectionSurfaceType(surfaceType) {
  if (surfaceType === "web") return "web";
  if (surfaceType === "smart_contract") return "smart_contract";
  throw new Error(`unsupported projection surface_type: ${String(surfaceType)}`);
}

function assertProjectionContinuity(finding, findingId) {
  if (!findingUsesWebContinuity(finding)) return;
  const missingWeb = [];
  if (typeof finding.request_method !== "string" || !finding.request_method.trim()) {
    missingWeb.push("request_method");
  }
  if (typeof finding.injection_point !== "string" || !finding.injection_point.trim()) {
    missingWeb.push("injection_point");
  }
  if (missingWeb.length > 0) {
    throw new Error(`finding ${findingId} lacks dispatched web continuity fields: ${missingWeb.join(", ")}`);
  }

  const sourceSurfaceType = typeof finding.source_surface_type === "string"
    ? finding.source_surface_type.trim().toLowerCase()
    : "";
  const isGraphql = sourceSurfaceType === "graphql"
    || finding.graphql_operation != null
    || finding.graphql_resolver != null;
  if (!isGraphql) return;
  const missingGraphql = [];
  if (typeof finding.graphql_operation !== "string" || !finding.graphql_operation.trim()) {
    missingGraphql.push("graphql_operation");
  }
  if (typeof finding.graphql_resolver !== "string" || !finding.graphql_resolver.trim()) {
    missingGraphql.push("graphql_resolver");
  }
  if (missingGraphql.length > 0) {
    throw new Error(`finding ${findingId} lacks dispatched GraphQL continuity fields: ${missingGraphql.join(", ")}`);
  }
}

function projectionCwe(cwe, findingId = "unknown") {
  let id;
  try {
    id = assertValidCwe(cwe);
  } catch {
    throw new Error(`finding ${findingId} has missing or unsupported CWE: ${String(cwe)}`);
  }
  const name = cweTitle(id);
  if (!name) throw new Error(`finding ${findingId} has missing or unsupported CWE: ${id}`);
  return [{ id, name }];
}

function projectionDisplayFields(cweRow, surfaceType, sourceSurfaceType) {
  const source = typeof sourceSurfaceType === "string" ? sourceSurfaceType.trim().toLowerCase() : "";
  const surfaceLabel = surfaceType === "smart_contract"
    ? "Smart contract"
    : (source === "graphql" ? "GraphQL" : (source === "api" ? "Web API" : "Web"));
  return {
    title: `${cweRow.name} — ${surfaceLabel}`,
    plainRead: `${surfaceLabel} finding classified as ${cweRow.id}: ${cweRow.name}.`,
  };
}

function projectionGradeFields(gradeEntry, findingId) {
  for (const field of [
    "total_score",
    "impact",
    "proof_quality",
    "severity_accuracy",
    "chain_potential",
    "report_quality",
  ]) {
    if (!Number.isFinite(gradeEntry[field])) {
      throw new Error(`finding ${findingId} lacks valid grade field: ${field}`);
    }
  }
  return {
    score: gradeEntry.total_score,
    scoreAxes: {
      impact: gradeEntry.impact,
      proof: gradeEntry.proof_quality,
      severityAccuracy: gradeEntry.severity_accuracy,
      chain: gradeEntry.chain_potential,
      report: gradeEntry.report_quality,
    },
  };
}

function projectionSurfaceFields(finding, findingId, surfaceType) {
  if (surfaceType === "web") {
    return { endpoint: safeRouteTemplate(finding.endpoint) };
  }
  const evidence = finding.sc_evidence;
  if (evidence == null || typeof evidence !== "object" || Array.isArray(evidence)) {
    throw new Error(`finding ${findingId} lacks normalized smart-contract evidence`);
  }
  const chainFamily = typeof evidence.chain_family === "string"
    ? evidence.chain_family.trim().toLowerCase()
    : "";
  if (!CHAIN_FAMILY_VALUES.includes(chainFamily)) {
    throw new Error(`finding ${findingId} has unsupported smart-contract chain family`);
  }
  const chainId = typeof evidence.chain_id === "number"
    ? String(evidence.chain_id)
    : (typeof evidence.chain_id === "string" ? evidence.chain_id.trim() : "");
  const contractIdentity = typeof evidence.contract_address === "string"
    ? evidence.contract_address.trim()
    : "";
  const functionSignature = typeof evidence.function_signature === "string"
    ? evidence.function_signature.trim()
    : "";
  if (!chainId || !contractIdentity || !functionSignature) {
    throw new Error(`finding ${findingId} lacks normalized smart-contract identity fields`);
  }
  return {
    chainFamily,
    scEvidence: {
      chainId,
      contractIdentity,
      functionSignature,
    },
  };
}

const DYNAMIC_IDENTITY_PREDECESSOR_RE = /^(?:account|accounts|email|emails|member|members|profile|profiles|user|users)$/i;
const SECRET_PREDECESSOR_RE = /^(?:api|api[_-]?key|auth|credential|key|keys|project|projects|rpc|secret|session|token|tokens)$/i;

function safeDecodeRouteSegment(segment) {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

function isSensitiveRouteSegment(segment, index, segments) {
  const decoded = safeDecodeRouteSegment(segment || "").trim();
  if (!decoded) return false;
  if (/^\d+$/.test(decoded)) return true;
  if (/^[0-9a-f]{8,64}$/i.test(decoded)) return true;
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(decoded)) return true;
  if (detectPiiShapes(decoded).length > 0) return true;
  if (/^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/.test(decoded)) return true;
  if (/^(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{16,}|sk-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{10,})$/.test(decoded)) return true;
  const previous = safeDecodeRouteSegment(segments[index - 1] || "");
  if (DYNAMIC_IDENTITY_PREDECESSOR_RE.test(previous)) return true;
  const mixedAlphaNumeric = /[A-Za-z]/.test(decoded) && /[0-9]/.test(decoded);
  if (SECRET_PREDECESSOR_RE.test(previous) && (decoded.length >= 8 || (decoded.length >= 6 && mixedAlphaNumeric))) {
    return true;
  }
  if (decoded.length >= 24 && mixedAlphaNumeric && /^[A-Za-z0-9._~%-]+$/.test(segment)) return true;
  return decoded.length >= 6 && mixedAlphaNumeric && /(?:auth|credential|secret|token)/i.test(decoded);
}

// Generalize an endpoint to a browser-safe route template. Besides common ID
// shapes, identity-bearing and credential-shaped path segments become
// {param}; query values are discarded while sorted key placeholders remain.
function safeRouteTemplate(endpoint) {
  const normalized = normalizeEndpointForDedupe(endpoint);
  if (!normalized) return "";
  let hostPath = normalized;
  let query = "";
  try {
    const parsed = new URL(normalized);
    // The continuity asset key is the canonical target domain, not a socket.
    // Dropping an explicit port here prevents domain/host mismatches from
    // prefixing the domain twice in fingerprintRouteTemplate.
    hostPath = `${parsed.hostname}${parsed.pathname}`;
    query = parsed.search;
  } catch {
    const queryIndex = normalized.indexOf("?");
    if (queryIndex >= 0) {
      hostPath = normalized.slice(0, queryIndex);
      query = normalized.slice(queryIndex);
    }
  }
  const segments = hostPath.split("/");
  const route = segments
    .map((segment, index) => (isSensitiveRouteSegment(segment, index, segments) ? "{param}" : segment))
    .join("/");
  return `${route}${query}`;
}

function fingerprintRouteTemplate(endpoint, domain) {
  const route = safeRouteTemplate(endpoint);
  const canonicalDomain = requiredFingerprintText(domain, "domain", "unknown").toLowerCase();
  if (route === canonicalDomain || route.startsWith(`${canonicalDomain}/`)) return route;
  return route.startsWith("/") ? `${canonicalDomain}${route}` : `${canonicalDomain}/${route}`;
}

function requiredFingerprintText(value, fieldName, findingId) {
  const text = typeof value === "number" ? String(value) : (typeof value === "string" ? value.trim() : "");
  if (!text) {
    throw new Error(`finding ${findingId} lacks fingerprint input: ${fieldName}`);
  }
  return text;
}

// ADR-002 fingerprint v1: sha256 over the canonical JSON of the continuity
// tuple. The PR is not merged, so version 1 is replaced rather than migrated.
function fingerprintV1({
  findingId,
  domain,
  endpoint,
  requestMethod,
  injectionPoint,
  graphqlOperation,
  graphqlResolver,
  cwe,
  authProfile,
  capabilityPack,
  surfaceType,
  sourceSurfaceType,
  scEvidence,
}) {
  const id = requiredFingerprintText(findingId, "finding_id", "unknown");
  const primaryCwe = requiredFingerprintText(cwe, "primary_cwe", id).toUpperCase();
  let parts;
  if (surfaceType === "smart_contract") {
    if (scEvidence == null || typeof scEvidence !== "object" || Array.isArray(scEvidence)) {
      throw new Error(`finding ${id} lacks fingerprint input: sc_evidence`);
    }
    const chainFamily = requiredFingerprintText(
      scEvidence.chain_family,
      "sc_evidence.chain_family",
      id,
    ).toLowerCase();
    const chainId = requiredFingerprintText(scEvidence.chain_id, "sc_evidence.chain_id", id);
    const rawAddress = requiredFingerprintText(
      scEvidence.contract_address,
      "sc_evidence.contract_address",
      id,
    );
    const contractAddress = ["evm", "aptos", "sui", "cosmwasm"].includes(chainFamily)
      ? rawAddress.toLowerCase()
      : rawAddress;
    const functionSignature = requiredFingerprintText(
      scEvidence.function_signature,
      "sc_evidence.function_signature",
      id,
    );
    parts = [
      chainFamily,
      [chainId, contractAddress],
      functionSignature,
      primaryCwe,
      "smart_contract",
    ];
  } else if (capabilityPack != null && !findingUsesWebContinuity({
    surface_type: surfaceType,
    capability_pack: capabilityPack,
  })) {
    parts = [
      requiredFingerprintText(domain, "domain", id).toLowerCase(),
      requiredFingerprintText(fingerprintRouteTemplate(endpoint, domain), "safe_route_template", id),
      primaryCwe,
      requiredFingerprintText(capabilityPack, "capability_pack", id),
    ];
  } else {
    const canonicalDomain = requiredFingerprintText(domain, "domain", id).toLowerCase();
    const injection = requiredFingerprintText(injectionPoint, "injection_point", id);
    const auth = requiredFingerprintText(authProfile, "auth_profile", id);
    const source = typeof sourceSurfaceType === "string" ? sourceSurfaceType.trim().toLowerCase() : "";
    const isGraphql = source === "graphql" || graphqlOperation != null || graphqlResolver != null;
    if (isGraphql) {
      parts = [
        canonicalDomain,
        requiredFingerprintText(graphqlOperation, "graphql_operation", id),
        requiredFingerprintText(graphqlResolver, "graphql_resolver", id),
        injection,
        primaryCwe,
        auth,
        "graphql",
      ];
    } else {
      parts = [
        canonicalDomain,
        requiredFingerprintText(requestMethod, "request_method", id).toUpperCase(),
        requiredFingerprintText(
          fingerprintRouteTemplate(endpoint, canonicalDomain),
          "safe_route_template",
          id,
        ),
        injection,
        primaryCwe,
        auth,
        requiredFingerprintText(surfaceType, "surface_type", id),
      ];
    }
  }
  return crypto.createHash("sha256").update(JSON.stringify(parts)).digest("hex");
}

function assertConsoleReportBounds(domain, findings) {
  if (findings.length > CONSOLE_REPORT_MAX_FINDINGS) {
    throw new Error(`console report must contain at most ${CONSOLE_REPORT_MAX_FINDINGS} findings`);
  }
  const modelJson = JSON.stringify({
    schemaVersion: 1,
    domain,
    findings,
  });
  if (Buffer.byteLength(modelJson, "utf8") > CONSOLE_REPORT_MAX_BYTES) {
    throw new Error(`console report must be ${CONSOLE_REPORT_MAX_BYTES} bytes or fewer`);
  }
}
// Build the www projectedFinding rows from the assembled artifact. Each row
// is display-safe: no repro steps, no raw evidence — only the verified
// summary fields the retained ledger admits. The defender disposition and
// per-finding scores come from the grade document, the verification facts
// from the final round.
function buildProjectionFindings(domain, document, bundle, findings, gradeDocument) {
  const round = loadFinalVerificationDocument(domain);
  const resultsById = new Map(
    (Array.isArray(round.results) ? round.results : [])
      .map((result) => [result.finding_id, result]),
  );
  const findingsById = new Map();
  for (const finding of findings) {
    if (finding && finding.id) findingsById.set(finding.id, finding);
  }
  const gradesById = new Map();
  const gradeFindings = Array.isArray(gradeDocument.findings) ? gradeDocument.findings : [];
  for (const entry of gradeFindings) {
    if (entry && entry.finding_id) gradesById.set(entry.finding_id, entry);
  }
  const rows = [];
  const rowIndexesByFingerprint = new Map();
  for (const artifactFinding of document.findings) {
    const result = resultsById.get(artifactFinding.id);
    const finding = findingsById.get(artifactFinding.id) || {};
    const gradeEntry = gradesById.get(artifactFinding.id) || {};
    const severity = projectionSeverity(artifactFinding.severity);
    if (!severity) continue; // info-graded findings never enter the retained ledger
    const surfaceType = projectionSurfaceType(finding.surface_type);
    assertProjectionContinuity(finding, artifactFinding.id);
    const projectedCwe = projectionCwe(finding.cwe, artifactFinding.id);
    const display = projectionDisplayFields(
      projectedCwe[0],
      surfaceType,
      finding.source_surface_type,
    );
    const gradeFields = projectionGradeFields(gradeEntry, artifactFinding.id);
    const surfaceFields = projectionSurfaceFields(finding, artifactFinding.id, surfaceType);
    const fingerprint = fingerprintV1({
      findingId: artifactFinding.id,
      domain,
      endpoint: finding.endpoint,
      requestMethod: finding.request_method,
      injectionPoint: finding.injection_point,
      graphqlOperation: finding.graphql_operation,
      graphqlResolver: finding.graphql_resolver,
      cwe: finding.cwe,
      authProfile: finding.auth_profile,
      capabilityPack: finding.capability_pack,
      surfaceType,
      sourceSurfaceType: finding.source_surface_type,
      scEvidence: finding.sc_evidence,
    });
    const row = {
      fingerprint,
      fingerprintVersion: FINGERPRINT_VERSION,
      refId: artifactFinding.id,
      dedupeKey: computeFindingDedupeKey({
        endpoint: finding.endpoint,
        title: finding.title,
        cwe: finding.cwe,
        severity: finding.severity,
        auth_profile: finding.auth_profile,
        response_evidence: finding.response_evidence,
        proof_of_concept: finding.proof_of_concept,
      }),
      title: display.title,
      plainRead: display.plainRead,
      severity,
      disposition: projectionDisposition(gradeEntry.defender_disposition, artifactFinding.id),
      ...gradeFields,
      reproduced: result ? result.disposition === "confirmed" : false,
      reachable: result ? result.reportable === true : false,
      reportable: true,
      cwe: projectedCwe,
      surfaceType,
      ...surfaceFields,
      evidenceHash: bundle.evidence_hash,
      snapshotHash: bundle.final_verification_hash,
      open: true,
    };
    const priorIndex = rowIndexesByFingerprint.get(fingerprint);
    if (priorIndex === undefined) {
      rowIndexesByFingerprint.set(fingerprint, rows.length);
      rows.push(row);
    } else {
      const prior = rows[priorIndex];
      const severityRank = { critical: 4, high: 3, medium: 2, low: 1 };
      const preferCurrent = severityRank[row.severity] > severityRank[prior.severity]
        || (severityRank[row.severity] === severityRank[prior.severity] && row.score > prior.score)
        || (
          severityRank[row.severity] === severityRank[prior.severity]
          && row.score === prior.score
          && row.refId.localeCompare(prior.refId) < 0
        );
      if (preferCurrent) rows[priorIndex] = row;
    }
  }
  return rows.map((row, index) => normalizeSafeProjectedFinding(row, index));
}

// Assemble the full www projection POST body for a dispatched run. kind is
// the dispatch-level kind ("assessment" | "retest"), translated to the
// projection-level vocabulary ("scan" | "retest").
function buildProjectionPayload(targetDomain, {
  runSlug,
  projectionKey,
  reportSlug = null,
  kind = "assessment",
  retestOf = [],
  findings = null,
  assembledArtifact = null,
} = {}) {
  if (kind !== "assessment" && kind !== "retest") {
    throw new Error(`unsupported dispatch kind: ${String(kind)}`);
  }
  if (
    !Array.isArray(retestOf) ||
    retestOf.length > 100 ||
    retestOf.some((fingerprint) => typeof fingerprint !== "string" || !SHA256_RE.test(fingerprint)) ||
    new Set(retestOf).size !== retestOf.length
  ) {
    throw new Error("retestOf must contain at most 100 unique lowercase SHA-256 fingerprints");
  }
  if (
    (kind === "assessment" && retestOf.length !== 0) ||
    (kind === "retest" && retestOf.length === 0)
  ) {
    throw new Error("dispatch kind and retestOf do not match");
  }

  const domain = targetDomain;
  const assembled = assembledArtifact || assembleFindingArtifact(domain, { findings });
  if (
    assembledArtifact
    && (
      !assembled.bundle
      || assembled.bundle.target_domain !== domain
      || (assembled.emitted && !Array.isArray(assembled.findings))
    )
  ) {
    throw new Error("assembledArtifact does not belong to the requested target domain");
  }
  const gradeDocument = loadJsonDocumentStrict(
    gradeArtifactPaths(domain).json,
    "grade verdict JSON",
  );
  const projectedFindings = assembled.emitted
    ? buildProjectionFindings(domain, assembled.document, assembled.bundle, assembled.findings, gradeDocument)
    : [];
  assertConsoleReportBounds(domain, projectedFindings);
  const reproducedFingerprints = new Set(projectedFindings.map((finding) => finding.fingerprint));
  const closureMarkers = kind === "retest"
    ? retestOf
      .filter((fingerprint) => !reproducedFingerprints.has(fingerprint))
      .map((fingerprint) => ({ fingerprint, open: false }))
    : [];
  const payload = {
    runSlug,
    projectionKey,
    freezeHash: assembled.bundle.claim_freeze_hash,
    snapshotHash: assembled.bundle.final_verification_hash,
    kind: kind === "retest" ? "retest" : "scan",
    findings: [...projectedFindings, ...closureMarkers],
  };
  if (reportSlug) payload.reportSlug = reportSlug;
  if (retestOf.length > 0) payload.retestOf = retestOf;
  return { payload, assembled };
}

module.exports = {
  CONSOLE_REPORT_MAX_BYTES,
  CONSOLE_REPORT_MAX_FINDINGS,
  FINGERPRINT_VERSION,
  assertConsoleReportBounds,
  buildProjectionFindings,
  buildProjectionPayload,
  fingerprintV1,
  fingerprintRouteTemplate,
  projectionCwe,
  projectionDisposition,
  projectionSeverity,
  projectionSurfaceType,
  safeRouteTemplate,
};
