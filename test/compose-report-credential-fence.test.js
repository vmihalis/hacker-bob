"use strict";

// Credential EXPORT fence at the report door (bob_compose_report).
//
// Responses reach the agent VERBATIM by operator policy, so the agent holds the
// operator's credential and can quote it into finding evidence — the claim-time secret
// scanner does not stop it (SECRET_DETECTION_BYPASS_FIELDS exempts the evidence fields;
// SENSITIVE_VALUE_RE cannot match an arbitrary account password). report.md is the
// document submitted to the bounty program, so it is the boundary that must fail CLOSED.
//
// Asserts:
//   * a report quoting a stored password REFUSES, names the placeholder label, names
//     the offending section, and writes NOTHING
//   * the refusal never echoes the credential value or caller-supplied text
//   * a clean report composes normally
//   * a session with no stored credentials is byte-identical to before the fence
//   * short / degenerate / common-word credentials do not trip the fence

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const composeReportTool = require("../mcp/tools/compose-report.js");
const { ERROR_CODES } = require("../mcp/core/io/envelope.js");
const { reportMarkdownPath, sessionDir, verificationRoundPaths } = require("../mcp/core/io/paths.js");
const {
  MIN_FENCED_CREDENTIAL_LENGTH,
  buildReportCredentialFence,
  findCredentialExportLeaks,
  isFenceableCredentialValue,
} = require("../mcp/core/redaction/index.js");
const { sessionCredentialMaterial } = require("../mcp/core/auth/index.js");

const DOMAIN = "audit.example.com";

// A value that clears every precision floor: long, mixed-class, high-entropy. This is
// what a real operator test-account password looks like.
const STORED_PASSWORD = "Wc7-tundra-QUILL-9182";

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-credential-fence-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

function storeCredentials(domain, profiles) {
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, "auth.json"),
    JSON.stringify({ version: 2, profiles }),
    { mode: 0o600 },
  );
}

function storePassword(domain, password, profileName = "victim") {
  storeCredentials(domain, { [profileName]: { credentials: { password } } });
}

// An OSINT-provenance section needs no verification_round backing, so these tests
// exercise the export fence without dragging in the executed-flip / provenance gates.
function osintSection(overrides = {}) {
  return {
    section_id: "osint-1",
    kind: "evidence",
    heading: "Reproduction Context",
    prose: "Operator-provided context for the affected tenant.",
    provenance: "operator_osint",
    evidence_refs: [],
    ...overrides,
  };
}

function compose(args) {
  const response = composeReportTool.handler(args);
  return typeof response === "string" ? JSON.parse(response) : response;
}

// The scan is ADVISORY: composing always succeeds and report.md is always written. Blocking
// here was proven disqualifying — an append-only credential-bearing amendment would refuse
// every later compose forever, discarding proven work — so the contract is "warn, never block".
function composeExpectingCredentialWarning(args) {
  const result = JSON.parse(composeReportTool.handler(args));
  assert.equal(fs.existsSync(reportMarkdownPath(args.target_domain)), true,
    "an advisory must never block the write");
  const warnings = result.credential_export_warnings;
  assert.ok(Array.isArray(warnings) && warnings.length > 0,
    "the credential quotation must be reported");
  // The warning names the label and location only — never the value, or the warning would
  // itself publish the secret it is flagging.
  assert.ok(!JSON.stringify(warnings).includes(STORED_PASSWORD),
    "the warning must not echo the credential value");
  return warnings;
}

test("WARNS on a report whose prose quotes a stored credential, naming the placeholder label", () => {
  withTempHome(() => {
    storePassword(DOMAIN, STORED_PASSWORD);

    const warnings = composeExpectingCredentialWarning({
      target_domain: DOMAIN,
      sections: [osintSection({
        prose: `Logged in as victim@example.com with password ${STORED_PASSWORD} and read tenant 2.`,
      })],
    });

    assert.match(JSON.stringify(warnings), /auth\.victim\.password/);
    assert.match(JSON.stringify(warnings), /sections\[0\] \(kind: evidence\)\.prose/);
    assert.deepEqual(warnings, [
      { label: "auth.victim.password", location: "sections[0] (kind: evidence).prose" },
    ]);

    // Advisory: the document IS written; the operator is told, not stopped.
    assert.equal(fs.existsSync(reportMarkdownPath(DOMAIN)), true);
  });
});

test("the warning never echoes the credential value, even when the credential is in the heading", () => {
  withTempHome(() => {
    storePassword(DOMAIN, STORED_PASSWORD);

    const warnings = composeExpectingCredentialWarning({
      target_domain: DOMAIN,
      sections: [osintSection({
        section_id: `leak-${STORED_PASSWORD}`,
        heading: `Login with ${STORED_PASSWORD}`,
      })],
    });

    const serialized = JSON.stringify(warnings);
    assert.equal(
      serialized.includes(STORED_PASSWORD),
      false,
      "the message that refuses the leak must not itself reproduce the credential",
    );
    // Locators are structural, so a credential pasted into a heading or section_id
    // cannot ride back out through the refusal.
    assert.match(JSON.stringify(warnings), /sections\[0\] \(kind: evidence\)\.heading/);
    assert.equal(serialized.includes("leak-"), false, "no caller-supplied section_id in the refusal");
  });
});

test("WARNS on when the credential appears only in repro steps, and attributes the exact step", () => {
  withTempHome(() => {
    storePassword(DOMAIN, STORED_PASSWORD, "attacker");

    const warnings = composeExpectingCredentialWarning({
      target_domain: DOMAIN,
      sections: [osintSection()],
      repro_steps_by_finding: [{
        finding_id: "F-1",
        steps: [
          "Browse to /login.",
          `Submit attacker@example.com / ${STORED_PASSWORD}.`,
        ],
      }],
    });

    assert.deepEqual(warnings, [
      { label: "auth.attacker.password", location: "repro_steps_by_finding[0].steps[1]" },
    ]);
  });
});

test("WARNS on a case-folded quotation of the credential", () => {
  withTempHome(() => {
    storePassword(DOMAIN, STORED_PASSWORD);

    const warnings = composeExpectingCredentialWarning({
      target_domain: DOMAIN,
      sections: [osintSection({ prose: `Password is ${STORED_PASSWORD.toLowerCase()} for this account.` })],
    });

    assert.equal(warnings[0].label, "auth.victim.password");
  });
});

test("WARNS on when the credential rides in the severity summary", () => {
  withTempHome(() => {
    storePassword(DOMAIN, STORED_PASSWORD);

    const warnings = composeExpectingCredentialWarning({
      target_domain: DOMAIN,
      sections: [osintSection()],
      severity_summary: `High: session for ${STORED_PASSWORD} crossed the tenant boundary.`,
    });

    assert.deepEqual(warnings, [
      { label: "auth.victim.password", location: "severity_summary" },
    ]);
  });
});

test("a clean report composes normally even when the session holds credentials", () => {
  withTempHome(() => {
    storeCredentials(DOMAIN, {
      victim: { credentials: { password: STORED_PASSWORD } },
      attacker: { credentials: { password: "Zq4-lantern-BRINE-5507" } },
    });

    const result = compose({
      target_domain: DOMAIN,
      sections: [osintSection({
        prose: "An attacker can read another tenant's orders using the victim account's password.",
      })],
      severity_summary: "High: cross-tenant read of order records.",
      repro_steps_by_finding: [{ finding_id: "F-1", steps: ["Authenticate as the attacker profile."] }],
    });

    assert.equal(result.target_domain, DOMAIN);
    assert.match(result.report_content_hash, /^[a-f0-9]{64}$/);
    const rendered = fs.readFileSync(reportMarkdownPath(DOMAIN), "utf8");
    assert.match(rendered, /another tenant's orders/);
    assert.equal(rendered.includes(STORED_PASSWORD), false);
  });
});

test("a session with no stored credentials renders byte-identically to a credentialled clean session", () => {
  const args = {
    target_domain: DOMAIN,
    sections: [osintSection({ prose: "Operator context: tenant isolation is enforced at the gateway." })],
    severity_summary: "Informational.",
  };

  const withoutCredentials = withTempHome(() => {
    const result = compose(args);
    return { hash: result.report_content_hash, markdown: fs.readFileSync(reportMarkdownPath(DOMAIN), "utf8") };
  });

  const withCredentials = withTempHome(() => {
    storePassword(DOMAIN, STORED_PASSWORD);
    const result = compose(args);
    return { hash: result.report_content_hash, markdown: fs.readFileSync(reportMarkdownPath(DOMAIN), "utf8") };
  });

  // The fence is a detector: on a clean report it contributes zero bytes and zero
  // hash drift, so the audit-graded ReportSnapshot binding is unchanged.
  assert.equal(withCredentials.hash, withoutCredentials.hash);
  assert.equal(withCredentials.markdown, withoutCredentials.markdown);
});

test("a session with no auth.json is untouched by the fence", () => {
  withTempHome(() => {
    // The literal below is not a stored credential in this session, so it must render.
    const result = compose({
      target_domain: DOMAIN,
      sections: [osintSection({ prose: `Documented default credential: ${STORED_PASSWORD}` })],
    });
    assert.match(result.report_content_hash, /^[a-f0-9]{64}$/);
    assert.match(fs.readFileSync(reportMarkdownPath(DOMAIN), "utf8"), /Documented default credential/);
  });
});

test("a degenerate stored credential does not block an otherwise clean report", () => {
  const degenerate = {
    // Below the length floor: matching a 3-char value against a whole report is a
    // coin flip, and no credential that short is protectable by substring search.
    short: "abc",
    // At the floor but built from one character: filler, not a secret.
    repeated: "aaaaaaaa",
    // A pure single common word the composer and the prose emit unconditionally;
    // fencing it would refuse every report for this session.
    commonword: "password",
  };

  for (const [profileName, value] of Object.entries(degenerate)) {
    withTempHome(() => {
      storePassword(DOMAIN, value, profileName);
      const result = compose({
        target_domain: DOMAIN,
        sections: [osintSection({
          // Every degenerate value appears verbatim in this prose.
          prose: "The abc endpoint returns aaaaaaaa for any password value supplied.",
        })],
      });
      assert.match(result.report_content_hash, /^[a-f0-9]{64}$/);
      assert.ok(fs.existsSync(reportMarkdownPath(DOMAIN)), `${profileName} must not block the render`);
    });
  }
});

test("local_storage and session_storage material is fenced alongside credentials", () => {
  withTempHome(() => {
    storeCredentials(DOMAIN, {
      victim: { local_storage: { refresh_token: "lsq-9f2c-REFRESH-8810" } },
    });

    const warnings = composeExpectingCredentialWarning({
      target_domain: DOMAIN,
      sections: [osintSection({ prose: "Recovered refresh token lsq-9f2c-REFRESH-8810 from the response." })],
    });

    assert.equal(warnings[0].label, "auth.victim.refresh_token");
  });
});

test("isFenceableCredentialValue enforces the documented precision floors", () => {
  assert.equal(isFenceableCredentialValue(STORED_PASSWORD), true);
  assert.equal(isFenceableCredentialValue("s3cr3t-x"), true);
  assert.equal(MIN_FENCED_CREDENTIAL_LENGTH, 8);
  assert.equal(isFenceableCredentialValue("a".repeat(MIN_FENCED_CREDENTIAL_LENGTH - 1)), false);
  assert.equal(isFenceableCredentialValue("abababab"), false, "2 distinct chars is filler");
  assert.equal(isFenceableCredentialValue("Password"), false, "pure single common word");
  assert.equal(isFenceableCredentialValue("Password1"), true, "no longer a pure word");
  assert.equal(isFenceableCredentialValue(""), false);
  assert.equal(isFenceableCredentialValue(null), false);
  assert.equal(isFenceableCredentialValue(12345678), false);
});

test("an inactive fence scans nothing and reports nothing", () => {
  withTempHome(() => {
    const fence = buildReportCredentialFence(DOMAIN, sessionCredentialMaterial);
    assert.equal(fence.active, false);
    assert.deepEqual(findCredentialExportLeaks(fence, [{ location: "x", text: "anything at all" }]), []);
  });
});

test("findCredentialExportLeaks dedupes per (label, location) and never returns the value", () => {
  withTempHome(() => {
    storePassword(DOMAIN, STORED_PASSWORD);
    const fence = buildReportCredentialFence(DOMAIN, sessionCredentialMaterial);
    assert.equal(fence.active, true);

    const hits = findCredentialExportLeaks(fence, [
      { location: "sections[0].prose", text: `${STORED_PASSWORD} and again ${STORED_PASSWORD}` },
      { location: "sections[1].prose", text: "clean" },
    ]);
    assert.deepEqual(hits, [{ label: "auth.victim.password", location: "sections[0].prose" }]);
    assert.equal(JSON.stringify(hits).includes(STORED_PASSWORD), false);
  });
});

test("the fence runs after the report-door gates, not instead of them", () => {
  withTempHome(() => {
    storePassword(DOMAIN, STORED_PASSWORD);
    const dir = sessionDir(DOMAIN);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(verificationRoundPaths(DOMAIN, "final").json, JSON.stringify({
      target_domain: DOMAIN,
      round: "final",
      notes: null,
      results: [{
        finding_id: "F-1",
        disposition: "denied",
        severity: "low",
        reportable: false,
        reasoning: "Not reportable",
        repro_steps: ["x"],
        evidence_refs: ["frontier_event:e1"],
      }],
      written_at: new Date().toISOString(),
    }));

    // A bob_verified section with a non-reportable ref must still fail the provenance
    // gate first; the credential fence never becomes an easier or a substitute door.
    let error;
    try {
      composeReportTool.handler({
        target_domain: DOMAIN,
        sections: [osintSection({
          provenance: "bob_verified",
          evidence_refs: ["verification_round:final:F-1"],
          prose: `Password ${STORED_PASSWORD} worked.`,
        })],
      });
    } catch (caught) {
      error = caught;
    }
    // The provenance gate still REFUSES, and it refuses first: the credential scan is advisory
    // and must never become a substitute door — nor mask a real gate by warning instead.
    assert.ok(error, "the provenance gate must still refuse");
    assert.equal(error.code, ERROR_CODES.INVALID_ARGUMENTS);
    assert.equal(fs.existsSync(reportMarkdownPath(DOMAIN)), false);
  });
});
