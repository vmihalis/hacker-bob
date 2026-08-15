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

const composeReportTool = require("../mcp/tools/compose-report.js");
const recordClaimTool = require("../mcp/tools/record-candidate-claim.js");
const { withIsolatedSigner } = require("./helpers/sandbox-isolated-signer.js");
const { deriveCvss31 } = require("../mcp/core/scoring/cvss31.js");
const { ERROR_CODES } = require("../mcp/core/io/envelope.js");
const { appendJsonlLine } = require("../mcp/core/io/storage.js");
const { canonicalizeExploitTarget } = require("../mcp/core/claims/claims.js");
const { ensureHandoffSigningKey } = require("../mcp/core/ledger-integrity/index.js");
const { signOffensiveRunRow } = require("../mcp/core/ledger-integrity/index.js");
const { initSession } = require("../mcp/core/session/session-state.js");
const {
  readSessionStateStrict,
  writeSessionStateDocument,
} = require("../mcp/core/session/session-state-store.js");
const { appendFrontierEvent } = require("../mcp/core/frontier/frontier-events.js");
const { offensiveRowHash } = require("../mcp/core/differential/index.js");
const {
  claimsJsonlPath,
  findingDifferentialVerifiedJsonlPath,
  offensiveRunsJsonlPath,
  reportMarkdownPath,
  sessionDir,
  verificationRoundPaths,
} = require("../mcp/core/io/paths.js");

// The web surface the CVSS-render tests bind their reportable medium+ finding to, so a
// matching executed-flip arm satisfies the C1 report gate while the CVSS block renders.
const CVSS_WEB_SURFACE = "surface:orders";

// Seed a genuine, re-derivable finding-differential verified_pass arm (a real MAC-signed
// exploited_safely positive + blocked_by_defense control on CVSS_WEB_SURFACE + the verdict
// line that binds them) so bob_compose_report's executed-flip report-door gate is satisfied for a
// final-reportable medium+ web finding. positiveSeverity must be >= the finding severity.
function seedComposeExecutedArm(domain, findingId, { positiveSeverity = "high" } = {}) {
  const mkRow = (over) => {
    const row = {
      version: 1, target_domain: domain, run_id: over.run_id, tool_id: "bob_http_idor_confirm",
      target: canonicalizeExploitTarget(`https://${domain}/api/orders/1`),
      offensive_outcome: over.offensive_outcome, dry_run: false, timed_out: false,
      command_hash: over.command_hash, exit_code: 0, stdout_hash: "b".repeat(64), stderr_hash: "c".repeat(64),
      demonstrated_severity: positiveSeverity, surface_id: CVSS_WEB_SURFACE,
    };
    signOffensiveRunRow(row, ensureHandoffSigningKey(domain));
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
    return row;
  };
  const positive = mkRow({ run_id: "fd-positive-1", offensive_outcome: "exploited_safely", command_hash: "1".repeat(64) });
  const control = mkRow({ run_id: "fd-control-1", offensive_outcome: "blocked_by_defense", command_hash: "2".repeat(64) });
  appendJsonlLine(findingDifferentialVerifiedJsonlPath(domain), {
    version: 1, target_domain: domain, finding_id: findingId, result: "verified_pass",
    reason: "executed_finding_differential_flip", surface_id: CVSS_WEB_SURFACE, source: "offensive_runs",
    positive_run_id: "fd-positive-1", positive_row_hash: offensiveRowHash(positive),
    control_run_id: "fd-control-1", control_row_hash: offensiveRowHash(control),
  });
}

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
    // Bind to a known surface so the executed-flip report-door gate can match a seeded arm; tests
    // that intentionally leave a finding surfaceless pass surface_id: null.
    ...(overrides.surface_id !== undefined ? { surface_id: overrides.surface_id } : { surface_id: CVSS_WEB_SURFACE }),
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
    // The executed-flip report-door gate requires a binding for a final-reportable medium+
    // finding; seed a genuine high-severity arm so the CVSS render path is reached.
    seedComposeExecutedArm(domain, "F-1", { positiveSeverity: "high" });

    const result = withIsolatedSigner(() => callTool(composeReportTool, {
      target_domain: domain,
      sections: [{
        kind: "impact",
        heading: "Impact",
        prose: "An attacker can read other users' orders.",
        provenance: "operator_osint",
        evidence_refs: [],
      }],
    }));

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
    // The executed-flip report-door gate requires a binding for the reportable medium
    // finding; a medium-severity arm satisfies the ceiling while inputs are absent.
    seedComposeExecutedArm(domain, "F-1", { positiveSeverity: "medium" });

    const result = withIsolatedSigner(() => callTool(composeReportTool, {
      target_domain: domain,
      sections: [{
        kind: "impact",
        heading: "Impact",
        prose: "Sensitive data is exposed.",
        provenance: "operator_osint",
        evidence_refs: [],
      }],
    }));

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
      surface_id: "surface:other",
      cvss_inputs: { attack_vector: "network", privileges_required: "none", confidentiality: "high" },
    });
    seedFinalRound(domain, [
      { finding_id: "F-1", disposition: "confirmed", severity: "high", reportable: true, reasoning: "ok", repro_steps: ["s"], evidence_refs: ["frontier_event:e1"] },
      { finding_id: "F-2", disposition: "denied", severity: "low", reportable: false, reasoning: "no", repro_steps: ["s"], evidence_refs: ["frontier_event:e1"] },
    ]);
    // Only F-1 is reportable medium+; seed its executed-flip arm so the report-door gate passes.
    // F-2 is not reportable, so it never reaches the gate.
    seedComposeExecutedArm(domain, "F-1", { positiveSeverity: "high" });

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
    const result = withIsolatedSigner(() => callTool(composeReportTool, args));
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

// --- H2: "surfaces we could not test, and why" (blocked prerequisites) ---

// Seed a currently-blocked surface: a blocked_prereq_history entry AND a
// matching frontier blocker.asserted event so summarizeBlockedPrereqs's
// currentBlockers ∩ blocked_prereq_history projection returns the surface.
function seedBlockedSurface(domain, { surfaceId, kind, identifierHint, reason, wave = 1 }) {
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  const { raw, state } = readSessionStateStrict(domain);
  const historyEntry = { wave, surface_id: surfaceId, kind, reason };
  if (identifierHint) historyEntry.identifier_hint = identifierHint;
  writeSessionStateDocument(domain, raw, {
    ...state,
    blocked_prereq_history: [historyEntry],
  });
  appendFrontierEvent({
    target_domain: domain,
    kind: "blocker.asserted",
    surface_id: surfaceId,
    payload: { terminally_blocked: true, wave, kind, identifier_hint: identifierHint, reason },
    source: { artifact: "wave-merge", tool: "bob_apply_wave_merge" },
  });
}

test("bob_compose_report renders a 'surfaces we could not test' section for a currently-blocked surface", () => {
  withTempHome(() => {
    const domain = "audit.example.com";
    seedBlockedSurface(domain, {
      surfaceId: "surface-admin",
      kind: "auth_missing",
      identifierHint: "attacker",
      reason: "no attacker auth profile registered",
    });

    const result = callTool(composeReportTool, {
      target_domain: domain,
      sections: [{
        kind: "impact",
        heading: "Recon summary",
        prose: "Recon-only summary; no exploitable finding recorded.",
        provenance: "operator_osint",
        evidence_refs: [],
      }],
    });

    assert.equal(result.blocked_surfaces_rendered, true);
    const rendered = fs.readFileSync(reportMarkdownPath(domain), "utf8");
    // Distinct first-class section heading + informational disclaimer.
    assert.match(rendered, /## Surfaces Not Tested \(blocked prerequisites\)/);
    assert.match(rendered, /surfaces we could not test, and why/);
    // Human label + identifier hint for the kind.
    assert.match(rendered, /### Authentication profile missing \(attacker\)/);
    // The affected surface id.
    assert.match(rendered, /surface-admin/);
    // The typed reason ("not tested because ...").
    assert.match(rendered, /Not tested because:\*\* no attacker auth profile registered/);
    // The concrete per-kind next step.
    assert.match(rendered, /Next step:\*\* Register an auth profile/);
    // The section bytes are covered by the single report_content_hash.
    const recomputed = require("crypto").createHash("sha256").update(rendered, "utf8").digest("hex");
    assert.equal(result.report_content_hash, recomputed);
  });
});

test("bob_compose_report omits the blocked-surfaces section when no surface is blocked", () => {
  withTempHome(() => {
    const domain = "audit.example.com";
    // A real session with no blocked_prereq_history / blocker events.
    JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));

    const result = callTool(composeReportTool, {
      target_domain: domain,
      sections: [{
        kind: "impact",
        heading: "Recon summary",
        prose: "Recon-only summary; no exploitable finding recorded.",
        provenance: "operator_osint",
        evidence_refs: [],
      }],
    });

    assert.equal(result.blocked_surfaces_rendered, false);
    const rendered = fs.readFileSync(reportMarkdownPath(domain), "utf8");
    // Drop-empty: no heading, no empty scaffold.
    assert.doesNotMatch(rendered, /## Surfaces Not Tested/);
  });
});
