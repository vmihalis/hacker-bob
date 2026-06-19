"use strict";

// Y.3 Stage c — bob_amend_report (Y-D15b / Y-P13a). Asserts:
//   * Append-only append to report-amendments.jsonl
//   * Re-render via bob_compose_report includes the amendment block
//   * Calling amend before any compose throws STATE_CONFLICT with structured
//     remediation pointing at bob_compose_report
//   * Bounded caps on section_id (64ch), new_prose (4096ch), rationale (512ch)

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const amendReportTool = require("../mcp/lib/tools/amend-report.js");
const composeReportTool = require("../mcp/lib/tools/compose-report.js");
const { ERROR_CODES } = require("../mcp/lib/envelope.js");
const {
  reportAmendmentsJsonlPath,
  reportMarkdownPath,
} = require("../mcp/lib/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-amend-report-"));
  process.env.HOME = home;
  try {
    const result = fn(home);
    if (result && typeof result.then === "function") {
      throw new Error("withTempHome callers must be synchronous; use awaiting wrapper for async callers");
    }
    return result;
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

function callTool(tool, args) {
  const response = tool.handler(args);
  return typeof response === "string" ? JSON.parse(response) : response;
}

test("bob_amend_report refuses when no report.md exists yet (structured remediation)", () => {
  withTempHome(() => {
    const domain = "no-report-yet.example.com";
    let err;
    try {
      amendReportTool.handler({
        target_domain: domain,
        section_id: "section-1",
        new_prose: "amended prose",
        rationale: "fixing typo",
      });
    } catch (e) { err = e; }
    assert.ok(err);
    assert.equal(err.code, ERROR_CODES.STATE_CONFLICT);
    assert.match(err.remediation, /bob_compose_report/);
  });
});

test("bob_amend_report appends to report-amendments.jsonl (append-only)", () => {
  withTempHome(() => {
    const domain = "amend.example.com";
    // Compose first so report.md exists.
    callTool(composeReportTool, {
      target_domain: domain,
      sections: [{
        kind: "impact",
        heading: "Impact",
        prose: "Initial prose.",
        provenance: "external_research",
      }],
    });
    // First amendment.
    callTool(amendReportTool, {
      target_domain: domain,
      section_id: "section-1",
      new_prose: "Amended prose (round 1).",
      rationale: "fixing wording per operator review",
    });
    // Second amendment to same section.
    callTool(amendReportTool, {
      target_domain: domain,
      section_id: "section-1",
      new_prose: "Amended prose (round 2).",
      rationale: "additional clarification",
    });

    const ledger = fs.readFileSync(reportAmendmentsJsonlPath(domain), "utf8");
    const lines = ledger.trim().split("\n");
    assert.equal(lines.length, 2);
    const first = JSON.parse(lines[0]);
    const second = JSON.parse(lines[1]);
    assert.equal(first.new_prose, "Amended prose (round 1).");
    assert.equal(second.new_prose, "Amended prose (round 2).");
    assert.equal(first.section_id, "section-1");
  });
});

test("re-render via bob_compose_report includes the amendment block", () => {
  withTempHome(() => {
    const domain = "rerender.example.com";
    callTool(composeReportTool, {
      target_domain: domain,
      sections: [{
        kind: "impact",
        heading: "Impact",
        prose: "Initial.",
        provenance: "external_research",
      }],
    });
    callTool(amendReportTool, {
      target_domain: domain,
      section_id: "section-1",
      new_prose: "Amended impact summary text.",
      rationale: "more accurate phrasing",
    });
    // Re-compose.
    callTool(composeReportTool, {
      target_domain: domain,
      sections: [{
        kind: "impact",
        heading: "Impact",
        prose: "Initial.",
        provenance: "external_research",
      }],
    });
    const rendered = fs.readFileSync(reportMarkdownPath(domain), "utf8");
    assert.match(rendered, /Operator Amendments/);
    assert.match(rendered, /Amended impact summary text/);
    assert.match(rendered, /more accurate phrasing/);
  });
});

test("bob_amend_report caps new_prose at 4096 chars and rationale at 512 chars", () => {
  withTempHome(() => {
    const domain = "caps.example.com";
    callTool(composeReportTool, {
      target_domain: domain,
      sections: [{
        kind: "impact",
        heading: "Impact",
        prose: "x",
        provenance: "external_research",
      }],
    });
    let err1;
    try {
      amendReportTool.handler({
        target_domain: domain,
        section_id: "section-1",
        new_prose: "x".repeat(4097),
        rationale: "ok",
      });
    } catch (e) { err1 = e; }
    assert.equal(err1 && err1.code, ERROR_CODES.INVALID_ARGUMENTS);
    let err2;
    try {
      amendReportTool.handler({
        target_domain: domain,
        section_id: "section-1",
        new_prose: "ok",
        rationale: "x".repeat(513),
      });
    } catch (e) { err2 = e; }
    assert.equal(err2 && err2.code, ERROR_CODES.INVALID_ARGUMENTS);
  });
});

test("bob_amend_report tool spec carries Y_self_reporting capability + orchestrator bundle", () => {
  assert.equal(amendReportTool.name, "bob_amend_report");
  assert.equal(amendReportTool.capability_id, "Y_self_reporting");
  assert.ok(amendReportTool.role_bundles.includes("orchestrator"));
  // Append-only ledger — session_artifacts_written must name the JSONL ledger.
  assert.ok(amendReportTool.session_artifacts_written.includes("report-amendments.jsonl"));
});
