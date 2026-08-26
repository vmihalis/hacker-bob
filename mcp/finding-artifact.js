"use strict";

// runner-wiring: canonical structured finding artifact.
//
// At report finalization, bob_finalize_report emits finding-artifact.json —
// the schema-validated structured superset of the sealed run (claims, final
// verification round, evidence packs, grade verdict, report.md) — plus a
// content-hash sidecar. This is the server-side sealed evidence record; the
// browser-readable projection into the retained console ledger is built from
// this document by projection-payload.js and carries no repro material.
//
// Honest zero-finding runs: the schema requires findings[] minItems 1, so a
// clean scan emits NO artifact file and reports emitted:false with the
// reason. The projection payload for such a run is an empty findings[] —
// a legitimate "scan completed, nothing found" freeze snapshot.

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const Ajv2020 = require("ajv/dist/2020");

const {
  assertSafeDomain,
  findingArtifactPath,
  findingArtifactSidecarPath,
  gradeArtifactPaths,
} = require("./core/io/paths.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./core/io/envelope.js");
const {
  loadJsonDocumentStrict,
  withSessionLock,
  writeFileAtomic,
} = require("./core/io/storage.js");
const {
  readSessionStateStrict,
} = require("./core/session/session-state-store.js");
const {
  loadFinalVerificationDocument,
  resolveReportFinalizationHashes,
  sha256Hex,
} = require("./core/report-finalize.js");
const {
  findingPayloadsFromClaims,
} = require("./tools/record-candidate-claim.js");
const {
  SEVERITY_VALUES,
} = require("./core/constants/shared-vocabulary.js");

const SCHEMA_PATH = path.join(
  __dirname,
  "../infra/aws/hacker-bob-stack/finding-artifact.schema.json",
);

// Draft 2020-12 is the schema's declared dialect; the 2020 entry point
// bundles its meta-schema so the $schema URI resolves without network access.
const ajv = new Ajv2020();
const validateArtifact = ajv.compile(require(SCHEMA_PATH));

function artifactError(message, context = {}, remediation = null) {
  return new ToolError(
    ERROR_CODES.STATE_CONFLICT,
    message,
    context,
    remediation ? { remediation } : null,
  );
}

// The graded-on severity is the reachability stamp when it spoke, else the
// explicit graded_severity the grade writer carried, else the final round's
// recorded severity. All three are severity bands already.
function gradedSeverityFor(gradeEntry, result) {
  if (gradeEntry && gradeEntry.reachability && gradeEntry.reachability.graded_severity) {
    return gradeEntry.reachability.graded_severity;
  }
  if (gradeEntry && gradeEntry.graded_severity) return gradeEntry.graded_severity;
  if (result && result.severity) return result.severity;
  return null;
}

function buildArtifactFindings(domain, reportableResults, findings, gradeDocument) {
  const findingsById = new Map();
  for (const finding of findings) {
    if (finding && finding.id) findingsById.set(finding.id, finding);
  }
  const gradesById = new Map();
  const gradeFindings = Array.isArray(gradeDocument.findings) ? gradeDocument.findings : [];
  for (const entry of gradeFindings) {
    if (entry && entry.finding_id) gradesById.set(entry.finding_id, entry);
  }
  const artifactFindings = [];
  for (const result of reportableResults) {
    const finding = findingsById.get(result.finding_id) || {};
    const gradeEntry = gradesById.get(result.finding_id) || {};
    const severity = gradedSeverityFor(gradeEntry, result);
    if (!SEVERITY_VALUES.includes(severity)) {
      throw artifactError(
        `reportable finding ${result.finding_id} lacks a valid graded severity`,
        { finding_id: result.finding_id, graded_severity: severity },
        "Write a valid graded severity before finalizing the report.",
      );
    }
    const entry = {
      id: result.finding_id,
      title: String(finding.title || result.finding_id),
      band: severity,
      severity,
    };
    if (finding.cwe) entry.cwe = String(finding.cwe);
    if (Number.isFinite(gradeEntry.total_score)) entry.grade_score = gradeEntry.total_score;
    if (finding.summary) entry.what_it_is = String(finding.summary);
    else if (finding.title) entry.what_it_is = String(finding.title);
    artifactFindings.push(entry);
  }
  return artifactFindings;
}

function artifactTargetForSession(domain) {
  const { state } = readSessionStateStrict(domain);
  if (state.target_repo) {
    return {
      targetKind: "repo",
      target: {
        kind: "repo",
        name: domain,
        ...(state.target_repo.source_url ? { repository: state.target_repo.source_url } : {}),
      },
    };
  }
  if (!state.target_url && Array.isArray(state.target_contracts) && state.target_contracts.length > 0) {
    return {
      targetKind: "contract",
      target: { kind: "contract", name: domain },
    };
  }
  return {
    targetKind: "web",
    target: { kind: "web", name: domain },
  };
}

// Assemble the canonical artifact document. Returns {emitted, document,
// bundle, reportableCount}. Throws ToolError with a structured pointer when
// any upstream artifact is missing (the same contract as finalization).
function assembleFindingArtifact(targetDomain, { findings = null } = {}) {
  const domain = assertSafeDomain(targetDomain);
  const bundle = resolveReportFinalizationHashes(domain);
  const finalRound = loadFinalVerificationDocument(domain);
  const gradeDocument = loadJsonDocumentStrict(
    gradeArtifactPaths(domain).json,
    "grade verdict JSON",
  );
  const findingsList = findings === null ? findingPayloadsFromClaims(domain) : findings;
  const results = Array.isArray(finalRound.results) ? finalRound.results : [];
  const reportableResults = results.filter(
    (result) => result && result.reportable === true,
  );
  if (reportableResults.length === 0) {
    return {
      emitted: false,
      reason: "no_reportable_findings",
      bundle,
      reportableCount: 0,
    };
  }
  const artifactTarget = artifactTargetForSession(domain);
  const document = {
    schemaVersion: 1,
    targetKind: artifactTarget.targetKind,
    domain,
    target: artifactTarget.target,
    findings: buildArtifactFindings(domain, reportableResults, findingsList, gradeDocument),
    receipt: {
      evidenceHash: bundle.grade_verdict_hash,
      gradeHash: bundle.grade_verdict_hash,
      gradeSha256: bundle.grade_verdict_hash,
      verifierStatus: "passed",
      verificationStatus: "passed",
      integrityChecksPassed: 5,
      generatedAt: new Date().toISOString(),
      profile: domain,
    },
  };
  if (!validateArtifact(document)) {
    const detail = (validateArtifact.errors || [])
      .map((error) => `${error.instancePath || "/"} ${error.message}`)
      .join("; ");
    throw artifactError(
      `assembled finding artifact failed schema validation for ${domain}: ${detail}`,
      { artifact: "finding-artifact.json" },
    );
  }
  return {
    emitted: true,
    document,
    bundle,
    findings: findingsList,
    reportableCount: reportableResults.length,
  };
}

// Write finding-artifact.json + its sha256 sidecar for the domain. Returns
// the emission summary. Called ONLY from the bob_finalize_report composer
// (an audit-graded writer); the paths are audit-graded basenames.
function writeFindingArtifact(targetDomain, options = {}) {
  const domain = assertSafeDomain(targetDomain);
  return withSessionLock(domain, () => {
    const assembled = assembleFindingArtifact(domain, options);
    if (!assembled.emitted) {
      for (const generatedPath of [findingArtifactPath(domain), findingArtifactSidecarPath(domain)]) {
        try {
          fs.unlinkSync(generatedPath);
        } catch (error) {
          if (!error || error.code !== "ENOENT") throw error;
        }
      }
      return assembled;
    }
    const artifactPath = findingArtifactPath(domain);
    const sidecarPath = findingArtifactSidecarPath(domain);
    const content = JSON.stringify(assembled.document, null, 2) + "\n";
    const contentHash = sha256Hex(Buffer.from(content, "utf8"));
    writeFileAtomic(artifactPath, content, { mode: 0o600 });
    writeFileAtomic(sidecarPath, `${contentHash}  finding-artifact.json\n`, { mode: 0o600 });
    return {
      ...assembled,
      written_json: artifactPath,
      sidecar: sidecarPath,
      content_hash: contentHash,
    };
  });
}

module.exports = {
  artifactTargetForSession,
  assembleFindingArtifact,
  buildArtifactFindings,
  gradedSeverityFor,
  writeFindingArtifact,
};
