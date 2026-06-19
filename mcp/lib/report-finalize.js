"use strict";

// Cycle C.7 of the frontier-topology realization hypergraph. Concentrates the
// four-hash binding logic that ReportSnapshot finalization depends on into a
// single helper so both bob_finalize_report (the new primary tool) and the
// legacy bounty_report_written shim can dual-write the same hash-bound
// snapshot. The four upstream hashes are:
//
//   1. claim_freeze_hash       — from readCurrentClaimFreeze (Cycle C.3+C.4 chain).
//   2. final_verification_hash — from the V2 final verification round bound to
//                                 the freeze (the round writer persists this as
//                                 document.final_verification_hash during the
//                                 V2 final-round write; only V2 final rounds
//                                 carry it).
//   3. evidence_hash           — digest over the canonical JSON of the evidence
//                                 packs document's packs[] manifest. The packs
//                                 document is itself bound to the V2 final
//                                 round via verification_attempt_id +
//                                 verification_snapshot_hash equality, so the
//                                 evidence_hash transitively binds to the
//                                 freeze.
//   4. grade_verdict_hash      — sha256 over the canonical JSON of the grade
//                                 verdict document. The grade verdict already
//                                 carries claim_freeze_id and is gate-bound to
//                                 the final verification, so the hash projects
//                                 the freeze + V2 final binding into a single
//                                 scalar.
//
// In addition the helper computes a fifth hash — the sha256 of the report.md
// file content — so a later consumer can prove the snapshot was finalized over
// an exact report.md file (a mutation invalidates the binding and a re-finalize
// will produce a new snapshot row with a new report_content_hash).
//
// C14 adds an optional sixth hash: if the rendered report cites a
// `proof_bundle:` evidence ref, finalization also binds proof-bundles.json.
//
// Invariant: a fresh report cannot be finalized unless all four upstream
// hashes resolve. Each missing hash is surfaced as a structured ToolError so
// callers see the precise upstream that is missing (no freeze / no final
// verification / no grade verdict / no evidence pack). The report.md file
// must also exist; the legacy report_written check remains the first gate.

const crypto = require("crypto");
const fs = require("fs");

const {
  evidencePackPaths,
  proofBundlePaths,
  reportMarkdownPath,
  verificationRoundPaths,
  gradeArtifactPaths,
  assertSafeDomain,
} = require("./paths.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  readCurrentClaimFreeze,
} = require("./claim-freeze.js");
const {
  hashCanonicalJson,
} = require("./verification-contracts.js");
const {
  loadJsonDocumentStrict,
} = require("./storage.js");
const {
  parseFindingId,
} = require("./validation.js");
const {
  normalizeProofBundlesDocument,
} = require("./proof-bundle.js");

const HASH_HEX_RE = /^[0-9a-f]{64}$/i;

function readReportFileContent(domain) {
  const reportPath = reportMarkdownPath(domain);
  if (!fs.existsSync(reportPath)) {
    // Y.10 (Y-D12 / D15) — STATE_CONFLICT remediation backfill #2 of 6:
    // report.md is the audit-graded markdown rendered by bob_compose_report
    // (Y-P13). If it is missing the operator must compose the report
    // server-side before attempting to bind the 5-hash chain.
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `report.md is not present at ${reportPath}; call bob_finalize_report only after writing the report`,
      { missing_artifact: "report.md", report_path: reportPath },
      { remediation: "call bob_compose_report with sections[] and severity_summary to render report.md, then re-invoke bob_finalize_report" },
    );
  }
  return {
    report_path: reportPath,
    content_buffer: fs.readFileSync(reportPath),
  };
}

function sha256Hex(input) {
  return crypto
    .createHash("sha256")
    .update(input)
    .digest("hex");
}

function loadClaimFreezeHash(domain) {
  const freeze = readCurrentClaimFreeze(domain);
  if (!freeze || typeof freeze !== "object") {
    // Y.10 (Y-D12 / D15) — STATE_CONFLICT remediation backfill #3 of 6:
    // claim-freeze.json is the freeze artifact produced when the session
    // transitions OPEN_FRONTIER -> CLAIM_FREEZE. Without it the 5-hash
    // chain cannot bind. Direct callers to bob_advance_session.
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `no claim-freeze.json for ${domain}; advance to CLAIM_FREEZE and freeze the claim batch before finalizing the report`,
      { missing_artifact: "claim-freeze.json" },
      { remediation: "call bob_advance_session({target_domain, to_state: \"CLAIM_FREEZE\"}) to freeze the claim batch, then re-invoke bob_finalize_report" },
    );
  }
  const hash = typeof freeze.freeze_hash === "string" ? freeze.freeze_hash : null;
  if (!hash || !HASH_HEX_RE.test(hash)) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `claim-freeze.json for ${domain} is missing freeze_hash; the freeze must be a hash-bound artifact before finalization`,
      { missing_field: "freeze_hash", freeze_id: freeze.freeze_id || null },
    );
  }
  return {
    claim_freeze_id: typeof freeze.freeze_id === "string" ? freeze.freeze_id : null,
    claim_freeze_hash: hash.toLowerCase(),
    claim_ids: Array.isArray(freeze.claims)
      ? freeze.claims
          .map((claim) => claim && typeof claim.claim_id === "string" ? claim.claim_id : null)
          .filter((id) => id != null)
      : [],
  };
}

function loadFinalVerificationDocument(domain) {
  const paths = verificationRoundPaths(domain, "final");
  if (!fs.existsSync(paths.json)) {
    // Y.10 (Y-D12 / D15) — STATE_CONFLICT remediation backfill #4 of 6:
    // the final V2 verification round binds the freeze to the evidence.
    // Direct callers to bob_write_verification_round with round: "final".
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `final verification round is not present at ${paths.json}; write a V2 final verification round before finalizing the report`,
      { missing_artifact: "verification round (final)" },
      { remediation: "call bob_write_verification_round({target_domain, round: \"final\", ...}) bound to the current claim freeze before re-invoking bob_finalize_report" },
    );
  }
  let document;
  try {
    document = loadJsonDocumentStrict(paths.json, "final verification round JSON");
  } catch (error) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `final verification round at ${paths.json} could not be loaded: ${error.message || String(error)}`,
      { missing_artifact: "verification round (final)" },
    );
  }
  // Only V2 final rounds carry the final_verification_hash field. C.7 requires
  // a freeze-bound V2 final round; a V1 round is allowed during the
  // deprecation window for legacy tests but the finalize path refuses it.
  const hash = document && typeof document.final_verification_hash === "string"
    ? document.final_verification_hash
    : null;
  if (!hash || !HASH_HEX_RE.test(hash)) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `final verification round at ${paths.json} is missing final_verification_hash; the final round must be V2 and bound to the claim freeze before report finalization`,
      {
        missing_field: "final_verification_hash",
        round: "final",
        schema_version: document && document.version != null ? document.version : null,
      },
    );
  }
  document.final_verification_hash = hash.toLowerCase();
  return document;
}

function loadFinalVerificationHash(domain) {
  return loadFinalVerificationDocument(domain).final_verification_hash;
}

function loadEvidencePackHash(domain) {
  const paths = evidencePackPaths(domain);
  if (!fs.existsSync(paths.json)) {
    // Y.10 (Y-D12 / D15) — STATE_CONFLICT remediation backfill #5 of 6:
    // evidence packs are the content layer of the 5-hash binding; their
    // hash is computed over the canonical JSON of packs[]. Direct callers
    // to bob_write_evidence_packs.
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `evidence packs are not present at ${paths.json}; write evidence packs before finalizing the report`,
      { missing_artifact: "evidence-packs.json" },
      { remediation: "call bob_write_evidence_packs({target_domain, packs: [...]}) bound to the current V2 final verification round before re-invoking bob_finalize_report" },
    );
  }
  let document;
  try {
    document = loadJsonDocumentStrict(paths.json, "evidence packs JSON");
  } catch (error) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `evidence packs at ${paths.json} could not be loaded: ${error.message || String(error)}`,
      { missing_artifact: "evidence-packs.json" },
    );
  }
  if (!document || !Array.isArray(document.packs)) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `evidence packs at ${paths.json} are malformed (no packs[] array); rewrite the evidence packs before finalization`,
      { missing_field: "packs" },
    );
  }
  // The evidence_hash is computed over the canonical JSON of the packs[]
  // manifest. Including only packs[] makes the binding stable across
  // verification-attempt-id renames or schema-version bumps that touch only
  // top-level metadata; what we are binding the report to is the actual
  // evidence content captured for each reportable claim.
  return hashCanonicalJson(document.packs);
}

function reportContentCitesProofBundle(contentBuffer) {
  return /\bproof_bundle:F-\d+\b/.test(contentBuffer.toString("utf8"));
}

function proofBundleRefsFromReportContent(contentBuffer) {
  const text = contentBuffer.toString("utf8");
  const refs = new Set();
  for (const match of text.matchAll(/\bproof_bundle:(F-\d+)\b/g)) {
    refs.add(parseFindingId(match[1], "proof_bundle ref"));
  }
  return refs;
}

function findingSetsFromFinalRound(finalRound) {
  const findingIdSet = new Set();
  const finalReportableIdSet = new Set();
  const results = Array.isArray(finalRound && finalRound.results) ? finalRound.results : [];
  for (const result of results) {
    if (!result || typeof result.finding_id !== "string" || !result.finding_id.trim()) continue;
    findingIdSet.add(result.finding_id);
    if (result.reportable === true) finalReportableIdSet.add(result.finding_id);
  }
  return { findingIdSet, finalReportableIdSet };
}

function proofBundleBindingFromFinalRound(finalRound) {
  const bindingFields = ["verification_attempt_id", "verification_snapshot_hash", "final_verification_hash"];
  const finalHasBinding = bindingFields.some((field) => finalRound && finalRound[field] != null);
  if (!((finalRound && finalRound.version === 2) || finalHasBinding)) return null;
  const binding = {};
  for (const field of bindingFields) {
    if (typeof finalRound[field] !== "string" || !finalRound[field].trim()) {
      throw new Error(`current final verification is missing ${field}`);
    }
    binding[field] = finalRound[field];
  }
  return binding;
}

function loadProofBundleHash(domain, { citedFindingIds = null, finalRound = null } = {}) {
  const paths = proofBundlePaths(domain);
  if (!fs.existsSync(paths.json)) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `proof bundles are not present at ${paths.json}; the report cites proof_bundle refs but no proof bundle artifact is available`,
      { missing_artifact: "proof-bundles.json" },
      { remediation: "call bob_write_proof_bundle({target_domain, packs: [...]}) for the cited final-reportable findings, then re-invoke bob_finalize_report" },
    );
  }
  let document;
  try {
    document = loadJsonDocumentStrict(paths.json, "proof bundles JSON");
  } catch (error) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `proof bundles at ${paths.json} could not be loaded: ${error.message || String(error)}`,
      { missing_artifact: "proof-bundles.json" },
    );
  }
  if (!document || !Array.isArray(document.packs)) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `proof bundles at ${paths.json} are malformed (no packs[] array); rewrite proof bundles before finalization`,
      { missing_field: "packs" },
    );
  }
  if (!finalRound || !(citedFindingIds instanceof Set)) {
    return hashCanonicalJson(document);
  }
  if (citedFindingIds.size === 0) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      "report.md contains proof_bundle: text but no proof_bundle:F-N refs could be parsed",
      { missing_ref: "proof_bundle:F-N" },
    );
  }
  let normalized;
  try {
    const verificationBinding = proofBundleBindingFromFinalRound(finalRound);
    normalized = normalizeProofBundlesDocument(document, {
      expectedDomain: domain,
      ...findingSetsFromFinalRound(finalRound),
      verificationBinding,
    });
  } catch (error) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `proof bundles at ${paths.json} do not validate against the current final verification: ${error.message || String(error)}`,
      { missing_artifact: "proof-bundles.json" },
      { remediation: "call bob_write_proof_bundle({target_domain, packs: [...]}) for the current final reportable findings, then re-invoke bob_finalize_report" },
    );
  }
  const normalizedIds = new Set(normalized.packs.map((pack) => pack.finding_id));
  for (const findingId of citedFindingIds) {
    if (!normalizedIds.has(findingId)) {
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        `proof_bundle:${findingId} does not resolve to a current validated proof bundle; rewrite proof bundles before finalization`,
        { ref: `proof_bundle:${findingId}`, missing_artifact: "proof-bundles.json" },
        { remediation: "call bob_write_proof_bundle({target_domain, packs: [...]}) with a pack for the cited final-reportable finding, then re-invoke bob_finalize_report" },
      );
    }
  }
  const normalizedHash = hashCanonicalJson(normalized);
  if (hashCanonicalJson(document) !== normalizedHash) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `proof bundles at ${paths.json} do not match the normalized proof bundle artifact; rewrite proof bundles before finalization`,
      { missing_artifact: "proof-bundles.json" },
      { remediation: "call bob_write_proof_bundle({target_domain, packs: [...]}) so proof-bundles.json contains only validated proof bundle fields, then re-invoke bob_finalize_report" },
    );
  }
  return normalizedHash;
}

function loadGradeVerdictHash(domain) {
  const paths = gradeArtifactPaths(domain);
  if (!fs.existsSync(paths.json)) {
    // Y.10 (Y-D12 / D15) — STATE_CONFLICT remediation backfill #6 of 6:
    // the grade verdict carries the severity decision; its canonical-JSON
    // hash is the last upstream that bob_finalize_report binds.
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `grade verdict is not present at ${paths.json}; write the grade verdict before finalizing the report`,
      { missing_artifact: "grade.json" },
      { remediation: "call bob_write_grade_verdict({target_domain, finding_grades: [...]}) gate-bound to the final verification round, then re-invoke bob_finalize_report" },
    );
  }
  let document;
  try {
    document = loadJsonDocumentStrict(paths.json, "grade verdict JSON");
  } catch (error) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `grade verdict at ${paths.json} could not be loaded: ${error.message || String(error)}`,
      { missing_artifact: "grade.json" },
    );
  }
  return hashCanonicalJson(document);
}

// Resolve the four upstream hashes + the report.md content hash for the
// given target_domain. Throws ToolError with a precise upstream pointer on
// any missing artifact. The returned bundle is the input shape that the
// ReportSnapshot append operation expects, plus convenience fields.
function resolveReportFinalizationHashes(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  const reportFile = readReportFileContent(domain);
  const claimFreeze = loadClaimFreezeHash(domain);
  const finalVerification = loadFinalVerificationDocument(domain);
  const finalVerificationHash = finalVerification.final_verification_hash;
  const evidenceHash = loadEvidencePackHash(domain);
  const gradeVerdictHash = loadGradeVerdictHash(domain);
  const reportContentHash = sha256Hex(reportFile.content_buffer);
  const proofBundleHash = reportContentCitesProofBundle(reportFile.content_buffer)
    ? loadProofBundleHash(domain, {
      citedFindingIds: proofBundleRefsFromReportContent(reportFile.content_buffer),
      finalRound: finalVerification,
    })
    : null;
  const bundle = {
    target_domain: domain,
    report_path: reportFile.report_path,
    report_size_bytes: reportFile.content_buffer.length,
    claim_freeze_id: claimFreeze.claim_freeze_id,
    claim_freeze_hash: claimFreeze.claim_freeze_hash,
    claim_ids: claimFreeze.claim_ids,
    final_verification_hash: finalVerificationHash,
    evidence_hash: evidenceHash,
    grade_verdict_hash: gradeVerdictHash,
    report_content_hash: reportContentHash,
  };
  if (proofBundleHash) bundle.proof_bundle_hash = proofBundleHash;
  return bundle;
}

// Same as resolveReportFinalizationHashes but never throws: returns null when
// any upstream hash cannot be resolved. Used by the legacy report_written
// shim so its dual-write path stays best-effort and never regresses the
// existing pipeline-event emission.
function tryResolveReportFinalizationHashes(targetDomain) {
  try {
    return resolveReportFinalizationHashes(targetDomain);
  } catch {
    return null;
  }
}

module.exports = {
  HASH_HEX_RE,
  loadClaimFreezeHash,
  loadEvidencePackHash,
  loadFinalVerificationDocument,
  loadFinalVerificationHash,
  loadGradeVerdictHash,
  loadProofBundleHash,
  proofBundleRefsFromReportContent,
  readReportFileContent,
  reportContentCitesProofBundle,
  resolveReportFinalizationHashes,
  sha256Hex,
  tryResolveReportFinalizationHashes,
};
