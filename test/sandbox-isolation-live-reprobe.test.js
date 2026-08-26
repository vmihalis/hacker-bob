"use strict";

// FORWARD-NOTE ii — the verdict gate consumes a LIVE re-probe at gate time, NEVER
// the self-asserted sandbox-isolation.json `attested` flag. A same-uid agent can
// rewrite that artifact via runtime indirection before the audit-graded guard, so
// it is forensic only; the load-bearing truth is the live lstat/getuid STRUCTURAL
// probe (legs a-e: owner-only mode, process owns + is the declared signer,
// distinct declared agent uid, not root) on the real key — no open()/read of the
// key is performed. This test forges sandbox-isolation.json{attested:true} on the
// same-uid box and asserts the enforce gate STILL blocks (the live probe
// dominates), and that the file flag has no influence on the decision.

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
const { OFFENSIVE_ROW_MAC_CONTEXT } = require("../mcp/core/ledger-integrity/index.js");
const { evaluateVerdictSandboxGate } = require("../mcp/core/verdict-sandbox-gate.js");
const {
  sandboxIsolationBlockersForReportableVerdictClaims,
} = require("../mcp/core/session/lifecycle-gates.js");
const {
  offensiveRunsJsonlPath,
  sandboxIsolationPath,
  sessionDir,
} = require("../mcp/core/io/paths.js");
const {
  SANDBOX_ATTESTATION_MODE_ENV,
  SANDBOX_ISOLATION_SCHEMA_VERSION,
  readSandboxIsolationAttestation,
} = require("../mcp/core/ledger-integrity/index.js");

function hex(char) { return char.repeat(64); }
const WEB_SURFACE = "surface:billing-profile";

function withTempHome(fn, mode) {
  const previousHome = process.env.HOME;
  const previousMode = process.env[SANDBOX_ATTESTATION_MODE_ENV];
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-sandbox-reprobe-"));
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

// The finding CITES an ed25519 offensive row via an exploit_run ref (so it is genuinely
// keyed-ledger-backed per the gate's per-finding predicate, not freeze membership). The
// row is seeded FIRST; severity is MEDIUM (the bob_http_idor_confirm tool ceiling) so only
// the isolation leg (not the legacy leg) is at issue.
function seedVerdictBackedFinding(domain) {
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
  recordFindingTool.handler({
    target_domain: domain, title: "IDOR on billing profile", severity: "medium", cwe: "CWE-639",
    endpoint: "https://victim.example/api/billing/1", request_method: "GET", injection_point: "path:billing_id", description: "Tenant boundary allows cross-account view",
    proof_of_concept: "GET /api/billing/1 returns another tenant payload",
    response_evidence: "Cross-tenant billing payload", impact: "Cross-tenant billing disclosure",
    validated: true, auth_profile: "attacker", surface_id: WEB_SURFACE,
    cvss_inputs: { attack_vector: "network", privileges_required: "low", confidentiality: "high" },
    exploit_outcome: { outcome: "exploited_safely", safe_oracle: { kind: "differential_response" } },
    evidence_refs: [{
      kind: "exploit_run", run_id: row.run_id, tool_id: row.tool_id, target: row.target,
      offensive_outcome: row.offensive_outcome, command_hash: row.command_hash,
      exit_code: row.exit_code, stdout_hash: row.stdout_hash, stderr_hash: row.stderr_hash,
    }],
  });
  buildClaimFreeze(domain, { write: true, now: new Date("2026-05-27T01:00:00.000Z") });
  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({ target_domain: domain, round, notes: null, results: [verificationResult("F-1", { severity: "medium" })] });
  }
  writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1")] });
}

// Forge sandbox-isolation.json{attested:true} directly (simulating a same-uid
// agent rewriting it via runtime indirection). The reader would normally read
// this back as attested:true — the test proves the GATE ignores it.
function forgeAttestedFlag(domain) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  const forged = {
    schema_version: SANDBOX_ISOLATION_SCHEMA_VERSION,
    target_domain: domain,
    attested: true,
    recorded_at: new Date().toISOString(),
    probe: {
      key_present: true, owner_only_mode: true, owner_uid: 424242, process_uid: 424242,
      process_owns_key: true, process_is_signer: true, declared_signer_uid: 424242,
      declared_agent_uid: 1000, agent_distinct: true, not_root: true, isolated: true,
    },
    operator: { ack_present: true, declared_signer_uid: 424242 },
    platform: process.platform,
  };
  fs.writeFileSync(sandboxIsolationPath(domain), `${JSON.stringify(forged, null, 2)}\n`);
}

test("a forged sandbox-isolation.json{attested:true} does NOT satisfy the enforce gate (live syscall is the truth)", () => withTempHome(() => {
  const domain = "reprobe-forged-flag.example.com";
  seedVerdictBackedFinding(domain);
  forgeAttestedFlag(domain);
  // Sanity: the stored-flag reader DOES read it back as attested (the artifact is
  // forensic, and on this temp box the forged file passes the reader's shape check).
  assert.equal(readSandboxIsolationAttestation(domain).attested, true,
    "the forged file reads back as attested via the forensic reader...");
  // ...but the gate consults the LIVE probe (same-uid box -> not isolated) and blocks.
  const decision = evaluateVerdictSandboxGate(domain);
  assert.equal(decision.isolated, false, "the live probe is the truth: same-uid box is not isolated");
  assert.equal(decision.decision, "block", "the forged file flag is ignored; enforce blocks on the live probe");
  assert.equal(decision.reason, "signer_not_isolated");
  // And the production verify->grade producer blocks too.
  const blockers = sandboxIsolationBlockersForReportableVerdictClaims(domain);
  assert.equal(blockers.length, 1);
  assert.equal(blockers[0].code, "sandbox_isolation_unattested");
}, "enforce"));

test("the forged flag does not even read back when its shape is broken (fail-closed reader)", () => withTempHome(() => {
  const domain = "reprobe-broken-flag.example.com";
  seedVerdictBackedFinding(domain);
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  // A wrong-schema forged file: the reader fails closed regardless, but the gate
  // already never consults it — assert both: reader closed AND gate still blocks.
  fs.writeFileSync(sandboxIsolationPath(domain), JSON.stringify({ attested: true }));
  assert.equal(readSandboxIsolationAttestation(domain).attested, false, "reader fails closed on a broken-shape forgery");
  const decision = evaluateVerdictSandboxGate(domain);
  assert.equal(decision.decision, "block", "the gate blocks on the live probe independent of the file");
}, "enforce"));
