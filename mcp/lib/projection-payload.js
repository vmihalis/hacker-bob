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
} = require("./finding-contracts.js");
const {
  loadFinalVerificationDocument,
} = require("./report-finalize.js");
const {
  loadJsonDocumentStrict,
} = require("./storage.js");
const {
  gradeArtifactPaths,
} = require("./paths.js");

const FINGERPRINT_VERSION = 1;

// www/convex/lib/validators.ts surfaceType union. The engine's surface_type
// vocabulary is close but not identical; unknown values map to "api" rather
// than failing the projection.
const PROJECTION_SURFACE_TYPES = new Set([
  "admin",
  "api",
  "auth",
  "billing",
  "ci_cd",
  "cms",
  "graphql",
  "js_endpoint",
  "mobile_api",
  "secrets",
  "static",
  "upload",
  "smart_contract",
]);

// www findings.ts severity union. "info"-graded findings are not reportable
// medium+ and are excluded from projection (mapped to null here).
function projectionSeverity(severity) {
  if (severity === "critical" || severity === "high" || severity === "medium" || severity === "low") {
    return severity;
  }
  return null;
}

// Core DEFENDER_DISPOSITION_VALUES (fix_now/worth_fixing/watch/held) ->
// www disposition union (fix-now/worth-fixing/watch/held). Absent on legacy
// verdicts; fall back to worth-fixing rather than inventing a held state.
function projectionDisposition(defenderDisposition) {
  switch (defenderDisposition) {
    case "fix_now": return "fix-now";
    case "worth_fixing": return "worth-fixing";
    case "watch": return "watch";
    case "held": return "held";
    default: return "worth-fixing";
  }
}

function projectionSurfaceType(surfaceType) {
  const normalized = String(surfaceType || "").trim().toLowerCase().replace(/[\s-]+/g, "_");
  return PROJECTION_SURFACE_TYPES.has(normalized) ? normalized : "api";
}

const CWE_NAMES = {
  "CWE-862": "Missing Authorization",
  "CWE-863": "Incorrect Authorization",
  "CWE-284": "Improper Access Control",
  "CWE-306": "Missing Authentication for Critical Function",
  "CWE-918": "Server-Side Request Forgery",
  "CWE-89": "SQL Injection",
  "CWE-79": "Cross-site Scripting",
  "CWE-352": "Cross-Site Request Forgery",
  "CWE-287": "Improper Authentication",
  "CWE-200": "Exposure of Sensitive Information",
  "CWE-269": "Improper Privilege Management",
  "CWE-639": "Authorization Bypass Through User-Controlled Key",
  "CWE-601": "Open Redirect",
  "CWE-22": "Path Traversal",
  "CWE-611": "XML External Entity",
  "CWE-502": "Insecure Deserialization",
};

function projectionCwe(cwe) {
  const id = String(cwe || "").trim();
  if (!id) return [];
  return [{ id, name: CWE_NAMES[id] || id }];
}

// Generalize an endpoint to its route template: numeric, uuid-shaped, and
// long-hex segments become {param}; the query string is dropped. Stable
// across concrete ids so retests correlate to the same fingerprint.
function templateEndpoint(endpoint) {
  const raw = String(endpoint || "").trim();
  if (!raw) return "";
  let hostPath = raw;
  try {
    const parsed = new URL(raw);
    hostPath = `${parsed.host}${parsed.pathname}`;
  } catch {
    hostPath = raw.split("?")[0];
  }
  return hostPath
    .split("/")
    .map((segment) => {
      if (/^\d+$/.test(segment)) return "{param}";
      if (/^[0-9a-f]{8,64}$/i.test(segment)) return "{param}";
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(segment)) {
        return "{param}";
      }
      return segment;
    })
    .join("/");
}

// ADR-002 fingerprint v1: sha256 over the canonical JSON of the stable parts.
function fingerprintV1({ domain, endpoint, cwe, authProfile, surfaceType }) {
  return crypto
    .createHash("sha256")
    .update(JSON.stringify([
      domain,
      templateEndpoint(endpoint),
      cwe || "",
      authProfile || "",
      surfaceType,
    ]))
    .digest("hex");
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
  for (const artifactFinding of document.findings) {
    const result = resultsById.get(artifactFinding.id);
    const finding = findingsById.get(artifactFinding.id) || {};
    const gradeEntry = gradesById.get(artifactFinding.id) || {};
    const severity = projectionSeverity(artifactFinding.severity);
    if (!severity) continue; // info-graded findings never enter the retained ledger
    const surfaceType = projectionSurfaceType(finding.surface_type);
    const row = {
      fingerprint: fingerprintV1({
        domain,
        endpoint: finding.endpoint,
        cwe: finding.cwe,
        authProfile: finding.auth_profile,
        surfaceType,
      }),
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
      title: artifactFinding.title,
      plainRead: artifactFinding.what_it_is || artifactFinding.title,
      severity,
      disposition: projectionDisposition(gradeEntry.defender_disposition),
      reproduced: result ? result.disposition === "confirmed" : false,
      reachable: result ? result.reportable === true : false,
      reportable: true,
      cwe: projectionCwe(finding.cwe),
      surfaceType,
      endpoint: finding.endpoint ? String(finding.endpoint) : undefined,
      remediation: finding.remediation ? String(finding.remediation) : undefined,
      evidenceHash: bundle.evidence_hash,
      snapshotHash: bundle.final_verification_hash,
      open: true,
    };
    rows.push(row);
  }
  return rows;
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
} = {}) {
  const domain = targetDomain;
  const assembled = assembleFindingArtifact(domain, { findings });
  const gradeDocument = loadJsonDocumentStrict(
    gradeArtifactPaths(domain).json,
    "grade verdict JSON",
  );
  const projectedFindings = assembled.emitted
    ? buildProjectionFindings(domain, assembled.document, assembled.bundle, assembled.findings, gradeDocument)
    : [];
  const payload = {
    runSlug,
    projectionKey,
    freezeHash: assembled.bundle.claim_freeze_hash,
    snapshotHash: assembled.bundle.final_verification_hash,
    kind: kind === "retest" ? "retest" : "scan",
    findings: projectedFindings,
  };
  if (reportSlug) payload.reportSlug = reportSlug;
  if (Array.isArray(retestOf) && retestOf.length > 0) payload.retestOf = retestOf;
  return { payload, assembled };
}

module.exports = {
  FINGERPRINT_VERSION,
  buildProjectionFindings,
  buildProjectionPayload,
  fingerprintV1,
  projectionCwe,
  projectionDisposition,
  projectionSeverity,
  projectionSurfaceType,
  templateEndpoint,
};
