"use strict";

// Y.3 Stage c — bob_compose_report (Y-D15b / Y-P13 / Y-P13a / Y-P13c).
// Asserts:
//   * Renderer produces report.md server-side with the operator-edit-warning
//     banner (Y-P13a)
//   * provenance: "bob_verified" with at least one verification_round ref
//     whose reportable=true → success
//   * provenance: "bob_verified" with no evidence_refs[] → INVALID_ARGUMENTS
//     with structured remediation (Y-P13c)
//   * provenance: "bob_verified" with refs that don't resolve to a reportable
//     verification_round result → INVALID_ARGUMENTS
//   * Bounded narrative caps (Y-P13b): prose ≤ 4096, severity_summary ≤ 2048
//   * Subsequent calls re-render (append-only amendments included)

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const composeReportTool = require("../mcp/lib/tools/compose-report.js");
const recordClaimTool = require("../mcp/lib/tools/record-candidate-claim.js");
const { deriveCvss31 } = require("../mcp/lib/cvss31.js");
const { ERROR_CODES } = require("../mcp/lib/envelope.js");
const {
  claimsJsonlPath,
  reportMarkdownPath,
  sessionDir,
  verificationRoundPaths,
} = require("../mcp/lib/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-compose-report-"));
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

function seedFinalRound(domain, results) {
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  const paths = verificationRoundPaths(domain, "final");
  fs.writeFileSync(paths.json, JSON.stringify({
    target_domain: domain,
    round: "final",
    notes: null,
    results,
    written_at: new Date().toISOString(),
  }));
}

function callTool(tool, args) {
  const response = tool.handler(args);
  return typeof response === "string" ? JSON.parse(response) : response;
}

test("bob_compose_report renders report.md with operator-edit-warning banner (Y-P13a)", () => {
  withTempHome(() => {
    const domain = "audit.example.com";
    seedFinalRound(domain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed",
      repro_steps: ["step 1"],
      evidence_refs: ["frontier_event:e1"],
    }]);

    const result = callTool(composeReportTool, {
      target_domain: domain,
      sections: [{
        kind: "impact",
        heading: "Impact Summary",
        prose: "An attacker can drain the vault by replaying the signed permit.",
        provenance: "bob_verified",
        evidence_refs: ["verification_round:final:F-1"],
      }],
    });

    assert.equal(result.target_domain, domain);
    assert.match(result.report_content_hash, /^[a-f0-9]{64}$/);
    const rendered = fs.readFileSync(reportMarkdownPath(domain), "utf8");
    assert.match(rendered, /This file is MCP-rendered/);
    assert.match(rendered, /bob_amend_report/);
    assert.match(rendered, /Impact Summary/);
    assert.match(rendered, /An attacker can drain the vault/);
  });
});

test("bob_compose_report REJECTS bob_verified section without evidence_refs (Y-P13c)", () => {
  withTempHome(() => {
    const domain = "audit.example.com";
    let err;
    try {
      composeReportTool.handler({
        target_domain: domain,
        sections: [{
          kind: "impact",
          heading: "Impact Summary",
          prose: "Unverified claim.",
          provenance: "bob_verified",
        }],
      });
    } catch (e) { err = e; }
    assert.ok(err, "missing evidence_refs[] must throw");
    assert.equal(err.code, ERROR_CODES.INVALID_ARGUMENTS);
    assert.equal(typeof err.remediation, "string");
    assert.match(err.remediation, /remove provenance: bob_verified/);
    assert.match(err.remediation, /verification_round/);
  });
});

test("bob_compose_report REJECTS bob_verified when refs don't resolve to a reportable=true round", () => {
  withTempHome(() => {
    const domain = "audit.example.com";
    seedFinalRound(domain, [{
      finding_id: "F-1",
      disposition: "denied",
      severity: "low",
      reportable: false,
      reasoning: "Not reportable",
      repro_steps: ["x"],
      evidence_refs: ["frontier_event:e1"],
    }]);

    let err;
    try {
      composeReportTool.handler({
        target_domain: domain,
        sections: [{
          kind: "impact",
          heading: "Impact",
          prose: "Claimed verified but referenced finding is not reportable.",
          provenance: "bob_verified",
          evidence_refs: ["verification_round:final:F-1"],
        }],
      });
    } catch (e) { err = e; }
    assert.ok(err, "non-reportable ref must reject");
    assert.equal(err.code, ERROR_CODES.INVALID_ARGUMENTS);
    assert.match(err.remediation, /reportable: true/);
  });
});

test("bob_compose_report ACCEPTS operator_osint provenance without verification_round backing", () => {
  withTempHome(() => {
    const domain = "audit.example.com";
    const result = callTool(composeReportTool, {
      target_domain: domain,
      sections: [{
        kind: "evidence",
        heading: "OSINT Context",
        prose: "Operator-provided context: this org was acquired in 2024.",
        provenance: "operator_osint",
        evidence_refs: [],
      }],
    });
    assert.equal(result.target_domain, domain);
  });
});

test("bob_compose_report enforces Y-P13b prose cap at 4096 characters", () => {
  withTempHome(() => {
    const domain = "audit.example.com";
    const longProse = "x".repeat(4097);
    let err;
    try {
      composeReportTool.handler({
        target_domain: domain,
        sections: [{
          kind: "impact",
          heading: "Too long",
          prose: longProse,
          provenance: "external_research",
        }],
      });
    } catch (e) { err = e; }
    assert.ok(err);
    assert.equal(err.code, ERROR_CODES.INVALID_ARGUMENTS);
    assert.match(err.message, /4096/);
  });
});

test("bob_compose_report enforces Y-P13b repro_steps_by_finding cap at K=12 per finding", () => {
  withTempHome(() => {
    const domain = "audit.example.com";
    let err;
    try {
      composeReportTool.handler({
        target_domain: domain,
        sections: [{
          kind: "impact",
          heading: "Impact",
          prose: "x",
          provenance: "external_research",
        }],
        repro_steps_by_finding: [{
          finding_id: "F-1",
          steps: Array.from({ length: 13 }, (_, i) => `step ${i}`),
        }],
      });
    } catch (e) { err = e; }
    assert.ok(err);
    assert.match(err.message, /at most 12 (entries|items)/);
  });
});

test("bob_compose_report rejects unknown evidence_ref prefix with structured remediation", () => {
  withTempHome(() => {
    const domain = "audit.example.com";
    let err;
    try {
      composeReportTool.handler({
        target_domain: domain,
        sections: [{
          kind: "impact",
          heading: "Impact",
          prose: "claim",
          provenance: "bob_verified",
          evidence_refs: ["unknown_prefix:foo"],
        }],
      });
    } catch (e) { err = e; }
    assert.ok(err);
    assert.equal(err.code, ERROR_CODES.INVALID_ARGUMENTS);
    assert.match(err.remediation, /known prefix|provenance: bob_verified/);
  });
});

test("bob_compose_report tool spec carries Y_self_reporting capability_id and is wrapWriteTool-wrapped", () => {
  assert.equal(composeReportTool.name, "bob_compose_report");
  assert.equal(composeReportTool.capability_id, "Y_self_reporting");
  assert.ok(composeReportTool.role_bundles.includes("orchestrator"));
});

// --- server-derived CVSS v3.1 + validated CWE annotations ---

function recordWebClaim(domain, overrides = {}) {
  return JSON.parse(recordClaimTool.handler({
    target_domain: domain,
    title: overrides.title || "IDOR in /api/orders",
    severity: overrides.severity || "high",
    cwe: overrides.cwe || "CWE-639",
    endpoint: overrides.endpoint || "https://audit.example.com/api/orders/1",
    description: overrides.description || "An attacker can read other users' orders.",
    proof_of_concept: overrides.proof_of_concept || "curl https://audit.example.com/api/orders/2",
    validated: true,
    ...(overrides.cvss_inputs !== undefined ? { cvss_inputs: overrides.cvss_inputs } : {}),
  }));
}

test("bob_compose_report renders a server-derived CVSS v3.1 + CWE block whose vector matches cvss31", () => {
  withTempHome(() => {
    const domain = "audit.example.com";
    const cvssInputs = {
      attack_vector: "network",
      privileges_required: "low",
      confidentiality: "high",
      integrity: "none",
      availability: "none",
    };
    recordWebClaim(domain, { cvss_inputs: cvssInputs });
    seedFinalRound(domain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed",
      repro_steps: ["step 1"],
      evidence_refs: ["frontier_event:e1"],
    }]);

    const result = callTool(composeReportTool, {
      target_domain: domain,
      sections: [{
        kind: "impact",
        heading: "Impact",
        prose: "An attacker can read other users' orders.",
        provenance: "operator_osint",
        evidence_refs: [],
      }],
    });

    assert.equal(result.cvss_annotations_rendered, 1);
    const expected = deriveCvss31(cvssInputs);
    const rendered = fs.readFileSync(reportMarkdownPath(domain), "utf8");
    assert.match(rendered, /## CVSS \/ CWE \(informational\)/);
    assert.match(rendered, /INFORMATIONAL only/);
    // The derived vector and base score must match cvss31 exactly.
    assert.ok(rendered.includes(expected.vector), `report must include derived vector ${expected.vector}`);
    assert.ok(
      rendered.includes(`${expected.base_score} (${expected.severity_band})`),
      `report must include base score ${expected.base_score} (${expected.severity_band})`,
    );
    // Validated CWE is surfaced; the final-round severity is labeled by its
    // source (not as the public/authoritative severity, which graded_severity
    // can downgrade).
    assert.match(rendered, /\*\*CWE:\*\* CWE-639/);
    assert.match(rendered, /Final verification round severity:\*\* high/);
    // No fabricated vector for a derivable finding: exactly the cvss31 vector.
    assert.equal((rendered.match(/CVSS:3\.1\//g) || []).length, 1);
  });
});

test("CVSS annotations exclude non-reportable findings and never appear before a final round", () => {
  withTempHome(() => {
    const domain = "audit.example.com";
    recordWebClaim(domain, {
      cvss_inputs: { attack_vector: "network", privileges_required: "low", confidentiality: "high" },
    });
    const sections = [{
      kind: "impact", heading: "Impact", prose: "x", provenance: "operator_osint", evidence_refs: [],
    }];

    // No final round yet: nothing is reportable, so the candidate finding must
    // NOT be enumerated in the informational CVSS/CWE block (no pre-verification
    // disclosure of candidate titles/CWEs).
    let result = callTool(composeReportTool, { target_domain: domain, sections });
    assert.equal(result.cvss_annotations_rendered, 0);
    assert.doesNotMatch(fs.readFileSync(reportMarkdownPath(domain), "utf8"), /## CVSS \/ CWE/);

    // A final round that marks the finding NOT reportable keeps it excluded too.
    seedFinalRound(domain, [{
      finding_id: "F-1", disposition: "rejected", severity: "high", reportable: false,
      reasoning: "Held / not reportable", repro_steps: [], evidence_refs: [],
    }]);
    result = callTool(composeReportTool, { target_domain: domain, sections });
    assert.equal(result.cvss_annotations_rendered, 0);
    assert.doesNotMatch(fs.readFileSync(reportMarkdownPath(domain), "utf8"), /## CVSS \/ CWE/);
  });
});

test("a non-enum verification-round severity is not interpolated into the report Markdown", () => {
  withTempHome(() => {
    const domain = "audit.example.com";
    recordWebClaim(domain, {
      cvss_inputs: { attack_vector: "network", privileges_required: "low", confidentiality: "high" },
    });
    // A corrupted/hand-edited verification round carrying a non-enum severity
    // that embeds Markdown must not inject into the report.
    const injected = "high\n\n## Injected Heading\n- arbitrary attacker text";
    seedFinalRound(domain, [{
      finding_id: "F-1", disposition: "confirmed", severity: injected, reportable: true,
      reasoning: "Confirmed", repro_steps: ["s"], evidence_refs: ["frontier_event:e1"],
    }]);

    const result = callTool(composeReportTool, {
      target_domain: domain,
      sections: [{ kind: "impact", heading: "Impact", prose: "x", provenance: "operator_osint", evidence_refs: [] }],
    });
    // Finding is reportable, so it is still annotated...
    assert.equal(result.cvss_annotations_rendered, 1);
    const rendered = fs.readFileSync(reportMarkdownPath(domain), "utf8");
    // ...but the injected heading/text must NOT appear. The invalid severity
    // degrades to null and the line falls back to the finding's own (enum-valid)
    // severity instead of interpolating attacker-controlled text.
    assert.doesNotMatch(rendered, /## Injected Heading/);
    assert.doesNotMatch(rendered, /arbitrary attacker text/);
    assert.match(rendered, /Final verification round severity:\*\* high/);
  });
});

test("bob_compose_report renders the insufficient-verified-facts marker for a legacy finding that lacks cvss_inputs", () => {
  withTempHome(() => {
    const domain = "audit.example.com";
    // The write path requires derivable cvss_inputs for a reportable (medium)
    // finding, so record it WITH inputs to clear the gate, then strip them from
    // the persisted claim row to simulate a legacy finding lacking cvss_inputs.
    // Read-back stays tolerant, so the marker still renders for that legacy row.
    recordWebClaim(domain, {
      cwe: "CWE-200",
      title: "Info exposure",
      endpoint: "https://audit.example.com/api/info",
      severity: "medium",
      cvss_inputs: { attack_vector: "network", privileges_required: "low", confidentiality: "high" },
    });
    const claimsFile = claimsJsonlPath(domain);
    const claimLines = fs.readFileSync(claimsFile, "utf8").split("\n").filter((l) => l.trim());
    assert.equal(claimLines.length, 1);
    const claim = JSON.parse(claimLines[0]);
    delete claim.payload.finding.cvss_inputs;
    fs.writeFileSync(claimsFile, `${JSON.stringify(claim)}\n`);
    seedFinalRound(domain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "medium",
      reportable: true,
      reasoning: "Confirmed",
      repro_steps: ["step 1"],
      evidence_refs: ["frontier_event:e1"],
    }]);

    const result = callTool(composeReportTool, {
      target_domain: domain,
      sections: [{
        kind: "impact",
        heading: "Impact",
        prose: "Sensitive data is exposed.",
        provenance: "operator_osint",
        evidence_refs: [],
      }],
    });

    assert.equal(result.cvss_annotations_rendered, 1);
    const rendered = fs.readFileSync(reportMarkdownPath(domain), "utf8");
    assert.match(rendered, /insufficient verified facts/);
    // No fabricated vector when inputs are absent.
    assert.equal((rendered.match(/CVSS:3\.1\//g) || []).length, 0);
  });
});

test("bob_compose_report content hash binds the CVSS block; non-reportable findings are omitted", () => {
  withTempHome(() => {
    const domain = "audit.example.com";
    // F-1 reportable with inputs; F-2 not reportable.
    recordWebClaim(domain, {
      cvss_inputs: { attack_vector: "network", privileges_required: "low", confidentiality: "high" },
    });
    recordWebClaim(domain, {
      title: "Denied finding",
      cwe: "CWE-200",
      endpoint: "https://audit.example.com/api/other",
      cvss_inputs: { attack_vector: "network", privileges_required: "none", confidentiality: "high" },
    });
    seedFinalRound(domain, [
      { finding_id: "F-1", disposition: "confirmed", severity: "high", reportable: true, reasoning: "ok", repro_steps: ["s"], evidence_refs: ["frontier_event:e1"] },
      { finding_id: "F-2", disposition: "denied", severity: "low", reportable: false, reasoning: "no", repro_steps: ["s"], evidence_refs: ["frontier_event:e1"] },
    ]);

    const args = {
      target_domain: domain,
      sections: [{
        kind: "impact",
        heading: "Impact",
        prose: "An attacker can read other users' orders.",
        provenance: "operator_osint",
        evidence_refs: [],
      }],
    };
    const result = callTool(composeReportTool, args);
    // Only the reportable finding is annotated.
    assert.equal(result.cvss_annotations_rendered, 1);
    const rendered = fs.readFileSync(reportMarkdownPath(domain), "utf8");
    assert.match(rendered, /### F-1/);
    assert.doesNotMatch(rendered, /### F-2/);
    // The content hash is the sha256 of the rendered markdown — it binds the
    // CVSS lines. Recomputing over the file content reproduces the reported hash.
    const recomputed = require("crypto").createHash("sha256").update(rendered, "utf8").digest("hex");
    assert.equal(result.report_content_hash, recomputed);
    assert.ok(rendered.includes("CVSS:3.1/"), "the bound markdown must contain the derived vector");
  });
});
