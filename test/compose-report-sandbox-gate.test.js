"use strict";

// Verdict-level sandbox-isolation gate at the report door
// (compose-report.js assertComposedVerdictSectionsAreSandboxAttested). Mirrors
// the verify->grade gate via the SAME decision module:
//   * enforce + same-uid probe (not isolated) + a verdict-ledger-backed
//     reportable medium+ finding -> THROW STATE_CONFLICT, report.md NOT written;
//   * degrade + not isolated -> downgrade the bob_verified section to advisory
//     (provenance flips, loud warning), render report.md, surface the downgrade
//     in the structured result; advisory/osint sections untouched;
//   * MOCKED isolated:true + ed25519-only backing + enforce -> render bob_verified
//     normally (the allow path, no 2nd uid);
//   * a clean / osint-only session -> unaffected regardless of mode/probe.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const composeReportTool = require("../mcp/tools/compose-report.js");
const recordFindingTool = require("../mcp/tools/record-candidate-claim.js");
const { buildClaimFreeze } = require("../mcp/core/claims/claim-freeze.js");
const { writeVerificationRound } = require("../mcp/core/verification/verification-round-store.js");
const { writeEvidencePacks } = require("../mcp/core/evidence.js");
const { appendJsonlLine } = require("../mcp/core/io/storage.js");
const { appendCandidateClaim } = require("../mcp/core/claims/claims.js");
const { ensureHandoffSigningKey, signRowViaIsolatedSignerOrLocal } = require("../mcp/core/ledger-integrity/handoff-signing-key.js");
const { offensiveRowHash } = require("../mcp/core/differential/finding-differential-verifier.js");
const { OFFENSIVE_ROW_MAC_CONTEXT } = require("../mcp/core/ledger-integrity/offensive-row-mac.js");
const {
  findingDifferentialVerifiedJsonlPath,
  offensiveRunsJsonlPath,
  handoffSigningPrivateKeyPath,
  reportMarkdownPath,
  sessionDir,
} = require("../mcp/core/io/paths.js");
const { SANDBOX_ATTESTATION_MODE_ENV } = require("../mcp/core/ledger-integrity/sandbox-isolation-attest.js");
const { resetForTests: resetMaterializationDebounce } = require("../mcp/core/frontier/frontier-materialize-debounce.js");

function hex(char) { return char.repeat(64); }
const WEB_SURFACE = "surface:billing-profile";

function withTempHome(fn, mode) {
  const previousHome = process.env.HOME;
  const previousMode = process.env[SANDBOX_ATTESTATION_MODE_ENV];
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-compose-sandbox-"));
  process.env.HOME = home;
  if (mode != null) process.env[SANDBOX_ATTESTATION_MODE_ENV] = mode;
  else delete process.env[SANDBOX_ATTESTATION_MODE_ENV];
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    if (previousMode === undefined) delete process.env[SANDBOX_ATTESTATION_MODE_ENV];
    else process.env[SANDBOX_ATTESTATION_MODE_ENV] = previousMode;
    resetMaterializationDebounce();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function verificationResult(findingId, overrides = {}) {
  return {
    finding_id: findingId, disposition: "confirmed", severity: "high", reportable: true,
    reasoning: "Fresh replay confirmed the finding against the current target state.",
    ...overrides,
  };
}

function evidencePack(findingId) {
  return {
    finding_id: findingId, sample_type: "cross-account replay", sample_count: 1,
    aggregate_counts: { affected_objects_sampled: 1 },
    representative_samples: [{
      request_ref: "http-audit:1", endpoint: "/api/billing/1", auth_profile: "attacker",
      status: 200, observed_fields: ["billing_profile_id"], redacted_object_id: "acct_...002",
    }],
    sensitive_clusters: ["billing metadata"],
    replay_summary: "Fresh replay returned another tenant's private billing metadata.",
    redaction_notes: "Object IDs redacted.",
    report_snippet: "An attacker can retrieve another tenant's private billing metadata.",
  };
}

function seedStandaloneWebFinding(domain, { severity = "high" } = {}) {
  // Production initSession ensures the symmetric key alongside the ed25519 pair
  // (session-state.js); resolveOffensiveRowVerifier reads it for legacy-row
  // verification. Mirror that here so the executed-flip re-derivation resolves.
  ensureHandoffSigningKey(domain);
  recordFindingTool.handler({
    target_domain: domain, title: "IDOR on billing profile", severity, cwe: "CWE-639",
    endpoint: "https://victim.example/api/billing/1", description: "Tenant boundary allows cross-account view",
    proof_of_concept: "GET /api/billing/1 returns another tenant payload",
    response_evidence: "Cross-tenant billing payload", impact: "Cross-tenant billing disclosure",
    validated: true, auth_profile: "attacker", surface_id: WEB_SURFACE,
    cvss_inputs: { attack_vector: "network", privileges_required: "low", confidentiality: "high" },
  });
  buildClaimFreeze(domain, { write: true, now: new Date("2026-05-27T01:00:00.000Z") });
  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({
      target_domain: domain, round, notes: null,
      results: [verificationResult("F-1", { severity })],
    });
  }
  writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1")] });
}

// ed25519 offensive row via the single sign shim (v2 asymmetric MAC).
function seedEd25519OffensiveRow(domain, runId, overrides = {}) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  const row = {
    version: 1, target_domain: domain, run_id: runId, tool_id: "bob_http_idor_confirm",
    target: `https://${domain}/api/billing/1`, offensive_outcome: overrides.offensive_outcome || "exploited_safely",
    dry_run: false, timed_out: false, command_hash: overrides.command_hash || hex("1"), exit_code: 0,
    stdout_hash: hex("b"), stderr_hash: hex("c"), demonstrated_severity: "high", surface_id: WEB_SURFACE,
  };
  signRowViaIsolatedSignerOrLocal(domain, OFFENSIVE_ROW_MAC_CONTEXT, row);
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
  return row;
}

// A genuine, re-derivable executed-flip arm so the EXISTING executed-flip gate
// passes — isolating the sandbox gate as the sole new closer. Uses ed25519 rows.
function seedFindingDifferentialArm(domain, findingId) {
  const positive = seedEd25519OffensiveRow(domain, "fd-positive-1", { offensive_outcome: "exploited_safely", command_hash: hex("1") });
  const control = seedEd25519OffensiveRow(domain, "fd-control-1", { offensive_outcome: "blocked_by_defense", command_hash: hex("2") });
  appendJsonlLine(findingDifferentialVerifiedJsonlPath(domain), {
    version: 1, target_domain: domain, finding_id: findingId, result: "verified_pass",
    reason: "executed_finding_differential_flip", surface_id: WEB_SURFACE, source: "offensive_runs",
    positive_run_id: "fd-positive-1", positive_row_hash: offensiveRowHash(positive),
    control_run_id: "fd-control-1", control_row_hash: offensiveRowHash(control),
  });
}

function verifiedSections() {
  return [{
    kind: "impact", heading: "Impact",
    prose: "An attacker can read another tenant's billing profile.",
    provenance: "bob_verified", evidence_refs: ["verification_round:final:F-1"],
  }];
}

function osintSections() {
  return [{
    kind: "impact", heading: "Background", prose: "Public OSINT note.",
    provenance: "operator_osint", evidence_refs: [],
  }];
}

// Stub the STRUCTURAL Mechanism-A isolated layout on the ed25519 private key: an
// owner-only (0400) key owned by the signer uid, the running process owning it
// AND declaring as the signer, a distinct declared agent uid, and not root. No
// openSync stub (the readability test is gone — the server reads its own key).
function withStubbedIsolatedEd25519Key(domain, ownerUid, fn) {
  const realLstat = fs.lstatSync;
  const realGetuid = process.getuid;
  const prevSigner = process.env.BOB_SANDBOX_SIGNER_UID;
  const prevAgent = process.env.BOB_SANDBOX_AGENT_UID;
  const keyPath = handoffSigningPrivateKeyPath(domain);
  fs.lstatSync = function stubLstat(p) {
    if (p === keyPath) return { uid: ownerUid, mode: 0o400, isFile: () => true };
    return realLstat.apply(fs, arguments);
  };
  process.getuid = () => ownerUid;
  process.env.BOB_SANDBOX_SIGNER_UID = String(ownerUid);
  process.env.BOB_SANDBOX_AGENT_UID = String(ownerUid + 1);
  try { return fn(); } finally {
    fs.lstatSync = realLstat;
    process.getuid = realGetuid;
    if (prevSigner === undefined) delete process.env.BOB_SANDBOX_SIGNER_UID;
    else process.env.BOB_SANDBOX_SIGNER_UID = prevSigner;
    if (prevAgent === undefined) delete process.env.BOB_SANDBOX_AGENT_UID;
    else process.env.BOB_SANDBOX_AGENT_UID = prevAgent;
  }
}

test("enforce + same-uid (not isolated) + verdict-backed bob_verified -> THROW, report.md NOT written", () => withTempHome(() => {
  const domain = "compose-sandbox-enforce-block.example.com";
  seedStandaloneWebFinding(domain);
  seedFindingDifferentialArm(domain, "F-1");
  assert.throws(
    () => composeReportTool.handler({ target_domain: domain, sections: verifiedSections() }),
    (err) => {
      assert.equal(err.code, "STATE_CONFLICT");
      assert.match(String(err.message), /not isolated|same-uid agent could forge/);
      return true;
    },
  );
  assert.equal(fs.existsSync(reportMarkdownPath(domain)), false, "report.md must not be written under an enforce block");
}, "enforce"));

test("degrade + not isolated -> downgrades bob_verified to advisory, renders, surfaces the downgrade", () => withTempHome(() => {
  const domain = "compose-sandbox-degrade.example.com";
  seedStandaloneWebFinding(domain);
  seedFindingDifferentialArm(domain, "F-1");
  const out = JSON.parse(composeReportTool.handler({ target_domain: domain, sections: verifiedSections() }));
  assert.equal(out.sections_rendered, 1, "the section still renders (downgraded, not dropped)");
  assert.ok(out.sandbox_isolation_downgrade, "the downgrade is surfaced in the structured result");
  assert.equal(out.sandbox_isolation_downgrade.sections_downgraded_to_advisory, 1);
  assert.match(String(out.sandbox_isolation_downgrade.warning), /downgrading 1 verdict-ledger-backed/);
  // The rendered report.md must carry the advisory banner and NOT a bob_verified provenance comment.
  const md = fs.readFileSync(reportMarkdownPath(domain), "utf8");
  assert.match(md, /ADVISORY — sandbox isolation unattested/);
  assert.doesNotMatch(md, /provenance: bob_verified/, "the section is no longer rendered as bob_verified");
}, "degrade"));

test("degrade + osint-only session (no reportable medium+ finding) -> NO downgrade (RANK != BOUND)", () => withTempHome(() => {
  const domain = "compose-sandbox-osint.example.com";
  // A below-medium finding + a verdict-ledger row: no reportable medium+ claim exists,
  // so the sandbox gate is inert and the osint section renders untouched even under
  // degrade. (The medium+ block/downgrade paths are covered by the tests above.)
  seedStandaloneWebFinding(domain, { severity: "low" });
  seedEd25519OffensiveRow(domain, "row-low-1");
  const out = JSON.parse(composeReportTool.handler({ target_domain: domain, sections: osintSections() }));
  assert.equal(out.sections_rendered, 1);
  assert.ok(!out.sandbox_isolation_downgrade, "a session with no reportable medium+ finding is unaffected");
}, "degrade"));

test("MOCKED isolated:true + ed25519-only backing + enforce -> renders bob_verified normally (allow path)", () => withTempHome(() => {
  const domain = "compose-sandbox-enforce-allow.example.com";
  seedStandaloneWebFinding(domain);
  seedFindingDifferentialArm(domain, "F-1");
  withStubbedIsolatedEd25519Key(domain, 424242, () => {
    const out = JSON.parse(composeReportTool.handler({ target_domain: domain, sections: verifiedSections() }));
    assert.equal(out.sections_rendered, 1);
    assert.ok(!out.sandbox_isolation_downgrade, "an isolated signer renders the verdict without downgrade");
  });
  const md = fs.readFileSync(reportMarkdownPath(domain), "utf8");
  assert.match(md, /provenance: bob_verified/, "the bob_verified section renders as-is on an isolated signer");
}, "enforce"));

test("enforce + isolated probe but a low-severity finding -> renders (gate inert below medium+)", () => withTempHome(() => {
  const domain = "compose-sandbox-low.example.com";
  seedStandaloneWebFinding(domain, { severity: "low" });
  seedEd25519OffensiveRow(domain, "row-low-1");
  const out = JSON.parse(composeReportTool.handler({ target_domain: domain, sections: osintSections() }));
  assert.equal(out.sections_rendered, 1);
  assert.ok(!out.sandbox_isolation_downgrade);
}, "enforce"));

// ---- LOW 3: degrade-mode downgrade scoped to decision.reportable_finding_ids ----
//
// The downgrade is now scoped: only bob_verified sections whose verification_round
// evidence_ref resolves to a GATED finding (decision.reportable_finding_ids) are
// downgraded; a section tied to a NON-gated finding renders unchanged, and a section
// whose finding linkage cannot be resolved fails CLOSED (downgrade).
//
// NOTE on reachability: an END-TO-END bob_verified section tied to a NON-gated finding is
// unreachable through the handler, because the executed-flip gate
// (assertComposedVerifiedSectionsAreExecuted) makes EVERY renderable bob_verified medium+
// section keyed-ledger-backed-and-thus-gated. So the scoping is defense-in-depth against a
// future provenance/backing-set divergence; it is unit-tested directly here against an
// on-disk final round, and the end-to-end degrade path (the gated section downgrades, a
// non-bob_verified section is untouched) is covered by the degrade test above.

const { sectionTargetsGatedFinding } = composeReportTool;

function seedFinalRoundForScoping(domain) {
  // ensureHandoffSigningKey + a recorded finding so writeVerificationRound's finding-id
  // context resolves both F-1 and F-2.
  ensureHandoffSigningKey(domain);
  for (const fid of ["F-1", "F-2"]) {
    appendCandidateClaim({
      target_domain: domain,
      title: `Fixture ${fid}`,
      summary: "Fixture summary.",
      severity: "high",
      surface_ids: [WEB_SURFACE],
      evidence_refs: [{ kind: "finding", finding_id: fid, content_hash: "0".repeat(64) }],
      impact: "Fixture impact.",
    });
  }
  buildClaimFreeze(domain, { write: true, now: new Date("2026-05-27T01:00:00.000Z") });
  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({
      target_domain: domain, round, notes: null,
      results: [verificationResult("F-1", { severity: "high" }), verificationResult("F-2", { severity: "high" })],
    });
  }
}

function bobVerifiedSectionCiting(ref) {
  return { kind: "impact", heading: "Impact", prose: "x", provenance: "bob_verified", evidence_refs: [ref] };
}

test("LOW 3 unit: a section tied to a GATED finding -> downgrade; tied to a NON-gated finding -> skip", () => withTempHome(() => {
  const domain = "compose-sandbox-scope-unit.example.com";
  seedFinalRoundForScoping(domain);
  // F-1 is gated, F-2 is not.
  const gated = new Set(["F-1"]);
  assert.equal(
    sectionTargetsGatedFinding(domain, bobVerifiedSectionCiting("verification_round:final:F-1"), gated),
    true, "a section whose verification_round ref resolves to a gated finding is selected for downgrade",
  );
  assert.equal(
    sectionTargetsGatedFinding(domain, bobVerifiedSectionCiting("verification_round:final:F-2"), gated),
    false, "a section whose verification_round ref resolves ONLY to a non-gated finding is NOT downgraded",
  );
  // A bare result-id ref (no round prefix) still resolves across rounds.
  assert.equal(
    sectionTargetsGatedFinding(domain, bobVerifiedSectionCiting("verification_round:F-2"), gated),
    false, "a bare-id ref to a non-gated finding is not downgraded",
  );
}, "degrade"));

test("LOW 3 unit: a section with NO resolvable finding linkage fails CLOSED (downgrade)", () => withTempHome(() => {
  const domain = "compose-sandbox-scope-failclosed.example.com";
  seedFinalRoundForScoping(domain);
  const gated = new Set(["F-1"]);
  // A verification_round ref that resolves to NO finding (unknown result id) -> fail closed.
  assert.equal(
    sectionTargetsGatedFinding(domain, bobVerifiedSectionCiting("verification_round:final:UNKNOWN-XYZ"), gated),
    true, "an unresolvable verification_round linkage fails CLOSED (downgrade), never silently skipped",
  );
  // A section carrying ONLY a non-verification_round ref (no finding linkage at all) ->
  // fail closed.
  const noLinkage = { kind: "impact", heading: "Impact", prose: "x", provenance: "bob_verified", evidence_refs: ["evidence_pack:F-1"] };
  assert.equal(
    sectionTargetsGatedFinding(domain, noLinkage, gated),
    true, "a section with no verification_round finding linkage fails CLOSED (downgrade)",
  );
}, "degrade"));
