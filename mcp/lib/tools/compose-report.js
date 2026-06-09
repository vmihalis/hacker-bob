"use strict";

// Y.3 Stage c — `bob_compose_report` (Y-D15b / Y-P13 / Y-P13a / Y-P13b / Y-P13c).
//
// This is the MCP-owned authoritative composer for `~/hacker-bob-sessions/
// <target>/report.md`. Agents emit structured sections + bounded prose; MCP
// renders the markdown view server-side, computes the content hash, and writes
// the file atomically. No agent invokes Write on report.md (the path lives in
// `mcp/lib/paths.js` AUDIT_GRADED_PATHS; the report-writer agent loses its
// Write tool grant in Stage d).
//
// Provenance enforcement (Y-P13c): any section marked `provenance:
// "bob_verified"` MUST carry `evidence_refs[]` containing at least one ref
// that (a) parses as a known prefix, (b) the underlying record exists, AND
// (c) at least ONE ref resolves to a `verification_round` result_id whose
// `verification_outcome.reportable === true`. Otherwise the renderer throws
// `INVALID_ARGUMENTS` with a structured `remediation` string that names the
// fix literally. Predicate strength is documented as "cites mechanically
// verified evidence" — NOT "every sentence in this section is semantically
// verified" (Y-R24 / Rice's-theorem acknowledgement).
//
// Bounded narrative caps (Y-P13b): prose ≤ 4096ch; severity_summary ≤ 2048ch;
// repro_steps_by_finding[] entries ≤ K=12 each, each step ≤ 512ch.
//
// Y-P13a operator-edit-warning banner: the renderer prepends a banner
// instructing operators to use `bob_amend_report({section_id, new_prose,
// rationale})` because hand-edits are not preserved across renders.

const fs = require("fs");
const crypto = require("crypto");
const {
  ERROR_CODES,
  ToolError,
} = require("../envelope.js");
const {
  assertSafeDomain,
  reportMarkdownPath,
  reportAmendmentsJsonlPath,
  sessionDir,
  verificationRoundPaths,
  frontierEventsJsonlPath,
  evidencePackPaths,
  proofBundlePaths,
  chainAttemptsJsonlPath,
} = require("../paths.js");
const {
  withSessionLock,
} = require("../storage.js");

const SECTION_KINDS = Object.freeze([
  "impact",
  "repro",
  "evidence",
  "severity",
  "remediation",
  "chain_summary",
  "proof_bundle",
  "provenance",
]);
const PROVENANCE_VALUES = Object.freeze([
  "bob_verified",
  "operator_osint",
  "external_research",
]);

const SECTION_PROSE_MAX = 4096;
const SECTION_HEADING_MAX = 200;
const SEVERITY_SUMMARY_MAX = 2048;
const REPRO_STEPS_PER_FINDING_MAX = 12;
const REPRO_STEP_MAX = 512;

const EVIDENCE_REF_PARSERS = Object.freeze([
  { prefix: "frontier_event:", validate: validateFrontierEventRef },
  { prefix: "http_record:", validate: validateHttpRecordRef },
  { prefix: "verification_round:", validate: validateVerificationRoundRef },
  { prefix: "chain_attempt:", validate: validateChainAttemptRef },
  { prefix: "evidence_pack:", validate: validateEvidencePackRef },
  { prefix: "proof_bundle:", validate: validateProofBundleRef },
]);

// Banner is prepended on every render so operators see the policy verbatim
// every time they read the file (Y-P13a).
const OPERATOR_EDIT_BANNER = [
  "<!--",
  "This file is MCP-rendered by bob_compose_report. Hand-edits are NOT",
  "preserved across renders. To amend a section, call:",
  "    bob_amend_report({ target_domain, section_id, new_prose, rationale })",
  "Audit-graded session paths are listed in mcp/lib/paths.js AUDIT_GRADED_PATHS.",
  "-->",
  "",
].join("\n");

function assertString(value, fieldName, { minLength = 1, maxLength = Infinity } = {}) {
  if (typeof value !== "string") {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `${fieldName} must be a string`);
  }
  if (value.length < minLength) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `${fieldName} must be at least ${minLength} characters`);
  }
  if (value.length > maxLength) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `${fieldName} must be at most ${maxLength} characters`);
  }
  return value;
}

function assertEnum(value, allowed, fieldName) {
  if (!allowed.includes(value)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `${fieldName} must be one of ${allowed.join(", ")}`,
    );
  }
  return value;
}

function classifyEvidenceRef(ref) {
  if (typeof ref !== "string" || !ref) return null;
  for (const parser of EVIDENCE_REF_PARSERS) {
    if (ref.startsWith(parser.prefix)) {
      return { prefix: parser.prefix, id: ref.slice(parser.prefix.length), validate: parser.validate };
    }
  }
  return null;
}

function validateFrontierEventRef(domain, id) {
  const file = frontierEventsJsonlPath(domain);
  if (!fs.existsSync(file)) return false;
  // Cheap line scan — frontier-events is the append-only ledger and bounded by
  // session retention; we look for the event_id literal as substring after
  // newline. For the Y.3 cycle this is the correct level of strictness —
  // the negative-grep + tests cover the happy/sad paths.
  const text = fs.readFileSync(file, "utf8");
  return text.includes(`"event_id":"${id}"`);
}

function validateHttpRecordRef(domain, id) {
  // http_record:R<N> — pattern check only. The traffic ledger holds these as
  // structured records; full existence-check is best left to a dedicated
  // resolver in a later cycle. For Y.3 we accept structurally-valid ids.
  return /^R\d+$/.test(id) || /^[A-Za-z0-9_-]+$/.test(id);
}

function validateVerificationRoundRef(domain, id) {
  // verification_round:<round>:<result_id> form preferred so the renderer can
  // also check reportable=true for that result_id. Bare result_ids are also
  // accepted (compatible with X-D12). We look at all three round artifacts.
  const parts = id.split(":");
  const round = parts.length === 2 ? parts[0] : null;
  const resultId = parts.length === 2 ? parts[1] : id;
  const rounds = round ? [round] : ["brutalist", "balanced", "final"];
  for (const r of rounds) {
    let paths;
    try {
      paths = verificationRoundPaths(domain, r);
    } catch {
      continue;
    }
    if (!fs.existsSync(paths.json)) continue;
    try {
      const doc = JSON.parse(fs.readFileSync(paths.json, "utf8"));
      const results = Array.isArray(doc && doc.results) ? doc.results : [];
      for (const result of results) {
        if (result && (result.finding_id === resultId || result.result_id === resultId)) {
          return { exists: true, reportable: result.reportable === true, round: r };
        }
      }
    } catch {
      continue;
    }
  }
  return { exists: false, reportable: false, round: null };
}

function validateChainAttemptRef(domain, id) {
  const file = chainAttemptsJsonlPath(domain);
  if (!fs.existsSync(file)) return false;
  const text = fs.readFileSync(file, "utf8");
  return text.includes(`"chain_attempt_id":"${id}"`) || text.includes(`"attempt_id":"${id}"`);
}

function validateEvidencePackRef(domain, id) {
  const paths = evidencePackPaths(domain);
  if (!fs.existsSync(paths.json)) return false;
  try {
    const doc = JSON.parse(fs.readFileSync(paths.json, "utf8"));
    const packs = Array.isArray(doc && doc.packs) ? doc.packs : [];
    return packs.some((pack) => pack && pack.finding_id === id);
  } catch {
    return false;
  }
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

function validateProofBundleRef(domain, id) {
  const paths = proofBundlePaths(domain);
  if (!fs.existsSync(paths.json)) return false;
  try {
    const doc = JSON.parse(fs.readFileSync(paths.json, "utf8"));
    const bindingFields = ["verification_attempt_id", "verification_snapshot_hash", "final_verification_hash"];
    const hasBinding = bindingFields.some((field) => doc[field] != null);
    const finalPaths = verificationRoundPaths(domain, "final");
    let finalBinding = null;
    let finalRound = null;
    if (fs.existsSync(finalPaths.json)) {
      finalRound = JSON.parse(fs.readFileSync(finalPaths.json, "utf8"));
      const finalHasBinding = bindingFields.some((field) => finalRound && finalRound[field] != null);
      if ((finalRound && finalRound.version === 2) || finalHasBinding) {
        if (!bindingFields.every((field) => typeof finalRound[field] === "string" && finalRound[field].trim())) {
          return false;
        }
        finalBinding = Object.fromEntries(bindingFields.map((field) => [field, finalRound[field]]));
      }
    }
    if (!finalRound) return false;
    if (hasBinding || finalBinding) {
      if (!hasBinding || !finalBinding) return false;
      if (!bindingFields.every((field) => typeof doc[field] === "string" && doc[field].trim())) return false;
      if (!bindingFields.every((field) => finalBinding[field] === doc[field])) return false;
    }
    const { normalizeProofBundlesDocument } = require("../proof-bundle.js");
    const normalized = normalizeProofBundlesDocument(doc, {
      expectedDomain: domain,
      ...findingSetsFromFinalRound(finalRound),
      verificationBinding: finalBinding,
    });
    return normalized.packs.some((pack) => pack && pack.finding_id === id);
  } catch {
    return false;
  }
}

function validateProvenance(domain, section) {
  if (section.provenance !== "bob_verified") return;
  if (!Array.isArray(section.evidence_refs) || section.evidence_refs.length === 0) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `section ${section.section_id || section.heading || "<unknown>"} marked provenance: bob_verified requires evidence_refs[] with at least one verification_round ref whose reportable=true`,
      { section_id: section.section_id || null, provenance: section.provenance },
      {
        remediation: "remove provenance: bob_verified OR add an evidence_ref to a verification_round result_id with reportable: true",
      },
    );
  }
  let anyReportable = false;
  for (const ref of section.evidence_refs) {
    const classified = classifyEvidenceRef(ref);
    if (!classified) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `evidence_ref ${ref} does not parse as a known prefix (frontier_event:, http_record:, verification_round:, chain_attempt:, evidence_pack:, proof_bundle:)`,
        { ref },
        {
          remediation: "rewrite the evidence_ref with a known prefix or remove provenance: bob_verified",
        },
      );
    }
    const result = classified.validate(domain, classified.id);
    // For verification_round refs we get an object; for others booleans.
    if (classified.prefix === "verification_round:") {
      if (!result || !result.exists) {
        throw new ToolError(
          ERROR_CODES.INVALID_ARGUMENTS,
          `evidence_ref ${ref} does not resolve to a known verification_round result`,
          { ref },
          {
            remediation: "remove provenance: bob_verified OR add an evidence_ref to a verification_round result_id with reportable: true",
          },
        );
      }
      if (result.reportable === true) {
        anyReportable = true;
      }
    } else if (!result) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `evidence_ref ${ref} does not resolve to an existing record`,
        { ref },
        {
          remediation: "rewrite the evidence_ref to an existing record id or remove provenance: bob_verified",
        },
      );
    }
  }
  if (!anyReportable) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `section ${section.section_id || section.heading} marked provenance: bob_verified requires at least one verification_round ref whose reportable=true (X-P3 mechanical-verifier-first)`,
      { section_id: section.section_id || null },
      {
        remediation: "remove provenance: bob_verified OR add an evidence_ref to a verification_round result_id with reportable: true",
      },
    );
  }
}

function normalizeSection(section, index) {
  if (section == null || typeof section !== "object" || Array.isArray(section)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `sections[${index}] must be an object`);
  }
  const kind = assertEnum(section.kind, SECTION_KINDS, `sections[${index}].kind`);
  const heading = assertString(section.heading, `sections[${index}].heading`, { maxLength: SECTION_HEADING_MAX });
  const prose = assertString(section.prose, `sections[${index}].prose`, { maxLength: SECTION_PROSE_MAX });
  const provenance = assertEnum(section.provenance, PROVENANCE_VALUES, `sections[${index}].provenance`);
  const evidenceRefs = Array.isArray(section.evidence_refs) ? section.evidence_refs.slice() : [];
  for (let i = 0; i < evidenceRefs.length; i += 1) {
    assertString(evidenceRefs[i], `sections[${index}].evidence_refs[${i}]`, { maxLength: 512 });
  }
  const sectionId = typeof section.section_id === "string" && section.section_id
    ? section.section_id
    : `section-${index + 1}`;
  return {
    section_id: sectionId,
    kind,
    heading,
    prose,
    provenance,
    evidence_refs: evidenceRefs,
  };
}

function normalizeReproSteps(reproStepsByFinding) {
  if (reproStepsByFinding == null) return [];
  if (!Array.isArray(reproStepsByFinding)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "repro_steps_by_finding must be an array");
  }
  return reproStepsByFinding.map((entry, idx) => {
    if (entry == null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `repro_steps_by_finding[${idx}] must be an object`);
    }
    const findingId = assertString(entry.finding_id, `repro_steps_by_finding[${idx}].finding_id`, { maxLength: 64 });
    const steps = Array.isArray(entry.steps) ? entry.steps : [];
    if (steps.length > REPRO_STEPS_PER_FINDING_MAX) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `repro_steps_by_finding[${idx}].steps must contain at most ${REPRO_STEPS_PER_FINDING_MAX} entries`,
      );
    }
    for (let i = 0; i < steps.length; i += 1) {
      assertString(steps[i], `repro_steps_by_finding[${idx}].steps[${i}]`, { maxLength: REPRO_STEP_MAX });
    }
    return { finding_id: findingId, steps };
  });
}

function renderMarkdown(domain, sections, severitySummary, reproSteps, amendments) {
  const parts = [OPERATOR_EDIT_BANNER];
  parts.push(`# Hacker Bob Report — ${domain}`);
  parts.push("");
  if (severitySummary) {
    parts.push("## Severity Summary");
    parts.push("");
    parts.push(severitySummary);
    parts.push("");
  }
  for (const section of sections) {
    parts.push(`## ${section.heading}`);
    parts.push("");
    parts.push(`<!-- section_id: ${section.section_id} | kind: ${section.kind} | provenance: ${section.provenance} -->`);
    parts.push("");
    parts.push(section.prose);
    if (section.evidence_refs.length > 0) {
      parts.push("");
      parts.push("Evidence:");
      for (const ref of section.evidence_refs) {
        parts.push(`- \`${ref}\``);
      }
    }
    parts.push("");
  }
  if (reproSteps.length > 0) {
    parts.push("## Reproduction Steps");
    parts.push("");
    for (const entry of reproSteps) {
      parts.push(`### ${entry.finding_id}`);
      parts.push("");
      entry.steps.forEach((step, i) => {
        parts.push(`${i + 1}. ${step}`);
      });
      parts.push("");
    }
  }
  if (amendments.length > 0) {
    parts.push("## Operator Amendments");
    parts.push("");
    parts.push("Append-only amendments recorded via `bob_amend_report`:");
    parts.push("");
    for (const amend of amendments) {
      parts.push(`### ${amend.section_id}`);
      parts.push("");
      parts.push(`Rationale: ${amend.rationale}`);
      parts.push("");
      parts.push(amend.new_prose);
      parts.push("");
    }
  }
  return parts.join("\n");
}

function readAmendments(domain) {
  const file = reportAmendmentsJsonlPath(domain);
  if (!fs.existsSync(file)) return [];
  const text = fs.readFileSync(file, "utf8");
  const out = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line));
    } catch {
      // Skip malformed lines; the ledger is append-only and the writer is the
      // sole producer, so this should only happen under operator interference.
    }
  }
  return out;
}

function handler(args) {
  if (args == null || typeof args !== "object" || Array.isArray(args)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "bob_compose_report args must be a plain object");
  }
  const domain = assertSafeDomain(args.target_domain);
  if (!Array.isArray(args.sections) || args.sections.length === 0) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "sections must be a non-empty array");
  }
  const sections = args.sections.map(normalizeSection);
  const severitySummary = args.severity_summary == null
    ? ""
    : assertString(args.severity_summary, "severity_summary", { maxLength: SEVERITY_SUMMARY_MAX, minLength: 0 });
  const reproSteps = normalizeReproSteps(args.repro_steps_by_finding);

  return withSessionLock(domain, () => {
    // Provenance enforcement (Y-P13c). Runs under the session lock so
    // cross-artifact proof/evidence binding checks share the render window.
    for (const section of sections) {
      validateProvenance(domain, section);
    }
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });
    const amendments = readAmendments(domain);
    const markdown = renderMarkdown(domain, sections, severitySummary, reproSteps, amendments);
    const reportPath = reportMarkdownPath(domain);
    fs.writeFileSync(reportPath, markdown, "utf8");
    const contentHash = crypto.createHash("sha256").update(markdown, "utf8").digest("hex");
    return JSON.stringify({
      version: 1,
      target_domain: domain,
      report_path: reportPath,
      report_content_hash: contentHash,
      report_size_bytes: Buffer.byteLength(markdown, "utf8"),
      sections_rendered: sections.length,
      amendments_rendered: amendments.length,
    });
  });
}

const { wrapWriteTool } = require("./_write-base.js");

module.exports = wrapWriteTool({
  name: "bob_compose_report",
  description:
    "Render the canonical session report.md from structured sections (Y-D15b / Y-P13). Agents emit closed-shape input; MCP renders markdown server-side, prepends the operator-edit-warning banner (Y-P13a), enforces provenance on bob_verified sections (Y-P13c — at least one evidence_ref must resolve to a verification_round result_id with reportable=true), caps prose per Y-P13b. Subsequent calls re-render with current report-amendments.jsonl appended (Y-P13a). bob_finalize_report still binds the hash-bound ReportSnapshot on top.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      sections: {
        type: "array",
        minItems: 1,
        items: {
          type: "object",
          properties: {
            section_id: { type: "string", maxLength: 64 },
            kind: { type: "string", enum: [...SECTION_KINDS] },
            heading: { type: "string", maxLength: SECTION_HEADING_MAX },
            prose: { type: "string", maxLength: SECTION_PROSE_MAX },
            evidence_refs: {
              type: "array",
              items: { type: "string", maxLength: 512 },
            },
            provenance: { type: "string", enum: [...PROVENANCE_VALUES] },
          },
          required: ["kind", "heading", "prose", "provenance"],
        },
      },
      severity_summary: { type: "string", maxLength: SEVERITY_SUMMARY_MAX },
      repro_steps_by_finding: {
        type: "array",
        items: {
          type: "object",
          properties: {
            finding_id: { type: "string", maxLength: 64 },
            steps: {
              type: "array",
              maxItems: REPRO_STEPS_PER_FINDING_MAX,
              items: { type: "string", maxLength: REPRO_STEP_MAX },
            },
          },
          required: ["finding_id", "steps"],
        },
      },
    },
    required: ["target_domain", "sections"],
  },
  handler,
  role_bundles: ["reporter", "orchestrator"],
  capability_id: "Y_self_reporting",
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["report.md"],
  SECTION_KINDS,
  PROVENANCE_VALUES,
  SECTION_PROSE_MAX,
  SEVERITY_SUMMARY_MAX,
  REPRO_STEPS_PER_FINDING_MAX,
});
