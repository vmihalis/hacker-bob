"use strict";

// Y.3 Stage c — `bob_amend_report` (Y-D15b / Y-P13a).
//
// Operator amendment path on `report.md`. CLAUDE.md previously sanctioned
// hand-edits; rev 3 supersedes (policy choice A — hand-edit unsupported).
// Amendments are append-only to `report-amendments.jsonl`; subsequent calls
// to `bob_compose_report` (or this tool's re-render side-effect) include the
// amendment block at the bottom of the rendered file.
//
// The append-only ledger means: amendments are AUDITABLE. No silent
// rewriting; the rationale is required and stored verbatim.

const fs = require("fs");
const path = require("path");
const {
  ERROR_CODES,
  ToolError,
} = require("../core/io/envelope.js");
const {
  assertSafeDomain,
  reportAmendmentsJsonlPath,
  reportMarkdownPath,
  sessionDir,
} = require("../core/io/paths.js");
const {
  withSessionLock,
} = require("../core/io/storage.js");

const MAX_SECTION_ID = 64;
const MAX_NEW_PROSE = 4096;
const MAX_RATIONALE = 512;

function assertString(value, fieldName, { maxLength }) {
  if (typeof value !== "string" || !value) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `${fieldName} must be a non-empty string`);
  }
  if (value.length > maxLength) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `${fieldName} must be at most ${maxLength} characters`);
  }
  return value;
}

function handler(args) {
  if (args == null || typeof args !== "object" || Array.isArray(args)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "bob_amend_report args must be a plain object");
  }
  const domain = assertSafeDomain(args.target_domain);
  const sectionId = assertString(args.section_id, "section_id", { maxLength: MAX_SECTION_ID });
  const newProse = assertString(args.new_prose, "new_prose", { maxLength: MAX_NEW_PROSE });
  const rationale = assertString(args.rationale, "rationale", { maxLength: MAX_RATIONALE });

  return withSessionLock(domain, () => {
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });
    const ledgerPath = reportAmendmentsJsonlPath(domain);
    // Refuse to amend when no rendered report.md exists yet; the renderer
    // (bob_compose_report) is the authoritative producer and operators must
    // call it before they can amend.
    if (!fs.existsSync(reportMarkdownPath(domain))) {
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        `report.md does not exist for ${domain}; call bob_compose_report first to render the initial report`,
        { target_domain: domain },
        {
          remediation: "call bob_compose_report({ target_domain, sections, ... }) before bob_amend_report",
        },
      );
    }
    const record = {
      version: 1,
      target_domain: domain,
      section_id: sectionId,
      new_prose: newProse,
      rationale,
      appended_at: new Date().toISOString(),
    };
    fs.appendFileSync(ledgerPath, `${JSON.stringify(record)}\n`, "utf8");
    return JSON.stringify({
      version: 1,
      appended: true,
      target_domain: domain,
      section_id: sectionId,
      ledger_path: ledgerPath,
      // Operators rerun bob_compose_report to fold the amendment in. This
      // tool deliberately does NOT trigger an automatic re-render: the
      // composer is the authoritative renderer and re-rendering requires the
      // structured `sections[]` from the caller, which we do not store.
      note: "amendment recorded append-only; call bob_compose_report to re-render report.md with the amendment block",
    });
  });
}

const { wrapWriteTool } = require("./_write-base.js");

module.exports = wrapWriteTool({
  name: "bob_amend_report",
  writes_audit_graded: true,
  description:
    "Operator-amendment path on report.md (Y-P13a). Appends to report-amendments.jsonl; re-render via bob_compose_report folds the amendment block into the rendered markdown. Hand-edits to report.md are not preserved across renders.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      section_id: { type: "string", maxLength: MAX_SECTION_ID },
      new_prose: { type: "string", maxLength: MAX_NEW_PROSE },
      rationale: { type: "string", maxLength: MAX_RATIONALE },
    },
    required: ["target_domain", "section_id", "new_prose", "rationale"],
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
  session_artifacts_written: ["report-amendments.jsonl"],
});
