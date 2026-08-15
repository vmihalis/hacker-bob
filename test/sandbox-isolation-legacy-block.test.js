"use strict";

// FORWARD-NOTE iii — under enforce, a legacy/unsigned row and a v1-HMAC row
// cannot back a NEW reportable medium+ claim (blocked-for-new-claims), because a
// v1 symmetric MAC could have been forged while the symmetric key was still
// agent-readable pre-isolation. Old rows stay READABLE for forensics (the
// per-row read path is untouched). Under degrade those rows downgrade to
// advisory + warning, never silent.
//
// The classification leg is exercised here against the verdict-level gate
// decision (evaluateVerdictSandboxGate), which is what both seams consume.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const recordFindingTool = require("../mcp/tools/record-candidate-claim.js");
const { buildClaimFreeze } = require("../mcp/core/claims/claim-freeze.js");
const { writeVerificationRound } = require("../mcp/core/verification/verification-round-store.js");
const { writeEvidencePacks } = require("../mcp/core/evidence.js");
const { ensureHandoffSigningKey, signRowViaIsolatedSignerOrLocal } = require("../mcp/core/ledger-integrity/index.js");
const { signOffensiveRunRow, verifyOffensiveRunRowMac } = require("../mcp/core/ledger-integrity/index.js");
const { OFFENSIVE_ROW_MAC_CONTEXT } = require("../mcp/core/ledger-integrity/index.js");
const { evaluateVerdictSandboxGate } = require("../mcp/core/ledger-integrity/index.js");
const {
  offensiveRunsJsonlPath,
  handoffSigningPrivateKeyPath,
  sessionDir,
} = require("../mcp/core/io/paths.js");
const { SANDBOX_ATTESTATION_MODE_ENV } = require("../mcp/core/ledger-integrity/index.js");

function hex(char) { return char.repeat(64); }
const WEB_SURFACE = "surface:billing-profile";

function withTempHome(fn, mode) {
  const previousHome = process.env.HOME;
  const previousMode = process.env[SANDBOX_ATTESTATION_MODE_ENV];
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-sandbox-legacy-"));
  process.env.HOME = home;
  if (mode != null) process.env[SANDBOX_ATTESTATION_MODE_ENV] = mode;
  else delete process.env[SANDBOX_ATTESTATION_MODE_ENV];
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    if (previousMode === undefined) delete process.env[SANDBOX_ATTESTATION_MODE_ENV];
    else process.env[SANDBOX_ATTESTATION_MODE_ENV] = previousMode;
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

// The finding CITES the backing row via an exploit_run evidence_ref (so it is genuinely
// keyed-ledger-backed per the gate's per-finding predicate, not freeze membership). The
// caller seeds the backing row FIRST and passes its ref; severity is MEDIUM to match the
// bob_http_idor_confirm tool ceiling. A v1-HMAC row still MAC-verifies and an unsigned row
// is accepted-with-warning, so both can back the claim's exploit_run proof — exactly the
// laundering-risk path this file exercises.
function seedReportableFinding(domain, { exploitRunRef } = {}) {
  ensureHandoffSigningKey(domain);
  recordFindingTool.handler({
    target_domain: domain, title: "IDOR on billing profile", severity: "medium", cwe: "CWE-639",
    endpoint: "https://victim.example/api/billing/1", description: "Tenant boundary allows cross-account view",
    proof_of_concept: "GET /api/billing/1 returns another tenant payload",
    response_evidence: "Cross-tenant billing payload", impact: "Cross-tenant billing disclosure",
    validated: true, auth_profile: "attacker", surface_id: WEB_SURFACE,
    cvss_inputs: { attack_vector: "network", privileges_required: "low", confidentiality: "high" },
    exploit_outcome: { outcome: "exploited_safely", safe_oracle: { kind: "differential_response" } },
    evidence_refs: [exploitRunRef],
  });
  buildClaimFreeze(domain, { write: true, now: new Date("2026-05-27T01:00:00.000Z") });
  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({ target_domain: domain, round, notes: null, results: [verificationResult("F-1", { severity: "medium" })] });
  }
  writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1")] });
}

function exploitRunRefFor(row) {
  return {
    kind: "exploit_run", run_id: row.run_id, tool_id: row.tool_id, target: row.target,
    offensive_outcome: row.offensive_outcome, command_hash: row.command_hash,
    exit_code: row.exit_code, stdout_hash: row.stdout_hash, stderr_hash: row.stderr_hash,
  };
}

// A v1-HMAC (legacy symmetric) offensive row — the laundering-risk class. demonstrated
// severity is MEDIUM (the bob_http_idor_confirm ceiling) so it can back the finding's proof.
function seedV1HmacOffensiveRow(domain, runId) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  const row = {
    version: 1, target_domain: domain, run_id: runId, tool_id: "bob_http_idor_confirm",
    target: `https://${domain}/api/billing/1`, offensive_outcome: "exploited_safely",
    dry_run: false, timed_out: false, command_hash: hex("1"), exit_code: 0,
    stdout_hash: hex("b"), stderr_hash: hex("c"), demonstrated_severity: "medium", surface_id: WEB_SURFACE,
  };
  signOffensiveRunRow(row, ensureHandoffSigningKey(domain)); // v1 hmac envelope
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
  return row;
}

// Stub the STRUCTURAL Mechanism-A isolated layout on the ed25519 private key: an
// owner-only (0400) key owned by the signer uid, the running process owning it
// AND declaring as the signer, a distinct declared agent uid, and not root. The
// probe is lstat/getuid STRUCTURAL (legs a-e); it performs NO open()/read of the
// key, so there is no openSync to stub.
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

test("enforce + MOCKED isolated:true but a v1-HMAC backing row -> BLOCK (blocked-for-new-claims)", () => withTempHome(() => {
  const domain = "legacy-block-v1.example.com";
  const row = seedV1HmacOffensiveRow(domain, "row-v1-1");
  seedReportableFinding(domain, { exploitRunRef: exploitRunRefFor(row) });
  withStubbedIsolatedEd25519Key(domain, 424242, () => {
    const decision = evaluateVerdictSandboxGate(domain);
    assert.equal(decision.applies, true);
    assert.equal(decision.isolated, true, "the signer is (mocked) isolated...");
    assert.equal(decision.has_legacy_or_v1, true, "...but a v1-HMAC row backs the claim");
    assert.equal(decision.decision, "block", "a v1-HMAC row cannot back a NEW claim even on an isolated signer");
    assert.equal(decision.reason, "legacy_or_v1_hmac_row_backs_new_claim");
  });
  // The row is still READABLE for forensics — the per-row verify path is untouched.
  assert.equal(verifyOffensiveRunRowMac(row, ensureHandoffSigningKey(domain)), true,
    "the v1-HMAC row remains MAC-valid and readable for forensics");
}, "enforce"));

test("enforce + MOCKED isolated:true but an UNSIGNED (MAC-stripped) backing row -> BLOCK", () => withTempHome(() => {
  const domain = "legacy-block-unsigned.example.com";
  ensureHandoffSigningKey(domain);
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  // The finding is genuinely backed by a VALID ed25519 row it cites (an unsigned row
  // cannot back an exploit_run proof — the record-time proof gate re-verifies the MAC).
  const ed25519 = {
    version: 1, target_domain: domain, run_id: "row-ed-backing-1", tool_id: "bob_http_idor_confirm",
    target: `https://${domain}/api/billing/1`, offensive_outcome: "exploited_safely",
    dry_run: false, timed_out: false, command_hash: hex("1"), exit_code: 0,
    stdout_hash: hex("b"), stderr_hash: hex("c"), demonstrated_severity: "medium", surface_id: WEB_SURFACE,
  };
  signRowViaIsolatedSignerOrLocal(domain, OFFENSIVE_ROW_MAC_CONTEXT, ed25519);
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(ed25519)}\n`);
  seedReportableFinding(domain, { exploitRunRef: exploitRunRefFor(ed25519) });
  // PLUS an old in-flight row with no MAC envelope at all (the accept-with-warning compat
  // window): it is the laundering-risk class verdictLedgerMacClasses flags, so even though
  // the finding's OWN backing is a valid ed25519 row, the session's unsigned row forces a
  // block for a NEW reportable claim under enforce.
  const unsigned = {
    version: 1, target_domain: domain, run_id: "row-unsigned-1", tool_id: "bob_http_idor_confirm",
    target: `https://${domain}/api/billing/1`, offensive_outcome: "exploited_safely",
    dry_run: false, timed_out: false, command_hash: hex("2"), exit_code: 0,
    stdout_hash: hex("b"), stderr_hash: hex("c"), demonstrated_severity: "medium", surface_id: WEB_SURFACE,
  };
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(unsigned)}\n`);
  withStubbedIsolatedEd25519Key(domain, 424242, () => {
    const decision = evaluateVerdictSandboxGate(domain);
    assert.equal(decision.decision, "block");
    assert.equal(decision.has_legacy_or_v1, true);
  });
}, "enforce"));

test("degrade + a v1-HMAC backing row -> DOWNGRADE (advisory + warning), never silent", () => withTempHome(() => {
  const domain = "legacy-downgrade-v1.example.com";
  const row = seedV1HmacOffensiveRow(domain, "row-v1-1");
  seedReportableFinding(domain, { exploitRunRef: exploitRunRefFor(row) });
  withStubbedIsolatedEd25519Key(domain, 424242, () => {
    const decision = evaluateVerdictSandboxGate(domain);
    assert.equal(decision.decision, "downgrade", "degrade downgrades a v1-HMAC-backed claim, never silently accepts it");
    assert.equal(decision.reason, "legacy_or_v1_hmac_row_backs_new_claim");
  });
}, "degrade"));

test("enforce + MOCKED isolated:true + ed25519-ONLY backing -> ALLOW (the clean post-split case)", () => withTempHome(() => {
  const domain = "legacy-allow-ed25519.example.com";
  // ed25519 rows only (signed through the single shim).
  ensureHandoffSigningKey(domain);
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  const row = {
    version: 1, target_domain: domain, run_id: "row-ed-1", tool_id: "bob_http_idor_confirm",
    target: `https://${domain}/api/billing/1`, offensive_outcome: "exploited_safely",
    dry_run: false, timed_out: false, command_hash: hex("1"), exit_code: 0,
    stdout_hash: hex("b"), stderr_hash: hex("c"), demonstrated_severity: "medium", surface_id: WEB_SURFACE,
  };
  signRowViaIsolatedSignerOrLocal(domain, OFFENSIVE_ROW_MAC_CONTEXT, row);
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
  seedReportableFinding(domain, { exploitRunRef: exploitRunRefFor(row) });
  withStubbedIsolatedEd25519Key(domain, 424242, () => {
    const decision = evaluateVerdictSandboxGate(domain);
    assert.equal(decision.has_legacy_or_v1, false);
    assert.equal(decision.decision, "allow");
    assert.equal(decision.reason, "isolated_signer_ed25519_only");
  });
}, "enforce"));
