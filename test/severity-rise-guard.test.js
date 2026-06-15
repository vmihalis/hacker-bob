"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  buildClaimFreeze,
  readCurrentClaimFreeze,
} = require("../mcp/lib/claim-freeze.js");
const {
  appendCandidateClaim,
  canonicalizeExploitTarget,
  normalizeCandidateClaim,
} = require("../mcp/lib/claims.js");
const {
  VERIFICATION_CONFIDENCE_REASON_VALUES,
} = require("../mcp/lib/constants.js");
const {
  ensureHandoffSigningKey,
} = require("../mcp/lib/handoff-signing-key.js");
const {
  claimsJsonlPath,
  offensiveRunsJsonlPath,
  sessionNucleusPath,
  statePath,
  verificationRoundPaths,
} = require("../mcp/lib/paths.js");
const {
  SEVERITY_VALUES,
} = require("../mcp/lib/constants.js");
const {
  signOffensiveRunRow,
} = require("../mcp/lib/offensive-row-mac.js");
const {
  initRepoSession,
} = require("../mcp/lib/repo-target.js");
const {
  initSession,
} = require("../mcp/lib/session-state.js");
const {
  readSessionStateStrict,
} = require("../mcp/lib/session-state-store.js");
const {
  writeFileAtomic,
} = require("../mcp/lib/storage.js");
const {
  buildVerificationAdjudication,
  prepareVerificationEntry,
} = require("../mcp/lib/verification.js");
const {
  writeVerificationRound,
} = require("../mcp/lib/verification-round-store.js");
const writeVerificationRoundTool = require("../mcp/lib/tools/write-verification-round.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-severity-rise-guard-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    resetMaterializationDebounce();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function hex(char) {
  return char.repeat(64);
}

function initWebSession(domain) {
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
}

function initRepoOnlySession(home, domain) {
  const repoRoot = path.join(home, domain);
  fs.mkdirSync(repoRoot, { recursive: true });
  fs.writeFileSync(path.join(repoRoot, "README.md"), "repo fixture\n", "utf8");
  return initRepoSession({ repo_path: repoRoot, target_domain: domain }).target_domain;
}

function findingRef(findingId = "F-1", overrides = {}) {
  return {
    kind: "finding",
    finding_id: findingId,
    content_hash: hex("0"),
    ...overrides,
  };
}

function exploitRef(domain, overrides = {}) {
  return {
    kind: "exploit_run",
    run_id: "run-exploit-1",
    tool_id: "bob_http_confirm_reflected_canary",
    target: canonicalizeExploitTarget(`https://${domain}/proof`),
    offensive_outcome: "exploited_safely",
    command_hash: hex("a"),
    exit_code: 0,
    stdout_hash: hex("b"),
    stderr_hash: hex("c"),
    ...overrides,
  };
}

function offensiveRunRow(domain, ref = exploitRef(domain), overrides = {}) {
  return {
    version: 1,
    target_domain: domain,
    run_id: ref.run_id,
    tool_id: ref.tool_id,
    target: ref.target,
    offensive_outcome: "exploited_safely",
    dry_run: false,
    timed_out: false,
    command_hash: ref.command_hash,
    exit_code: ref.exit_code,
    stdout_hash: ref.stdout_hash,
    stderr_hash: ref.stderr_hash,
    // The impact tier the safe exploit demonstrated (MAC-covered). The guard
    // requires this to meet/exceed the asserted severity before allowing a rise.
    demonstrated_severity: "critical",
    ...overrides,
  };
}

function writeOffensiveRunRows(domain, rows) {
  const filePath = offensiveRunsJsonlPath(domain);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, rows.map((row) => JSON.stringify(row)).join("\n") + "\n", "utf8");
}

function appendRawClaim(domain, claimInput) {
  const claim = normalizeCandidateClaim({ target_domain: domain, ...claimInput });
  const filePath = claimsJsonlPath(domain);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.appendFileSync(filePath, `${JSON.stringify(claim)}\n`, "utf8");
  return claim;
}

function signedOffensiveRow(domain, ref = exploitRef(domain), overrides = {}) {
  const row = offensiveRunRow(domain, ref, overrides);
  signOffensiveRunRow(row, ensureHandoffSigningKey(domain));
  return row;
}

function seedSignedOffensiveRow(domain, ref = exploitRef(domain), overrides = {}) {
  const row = signedOffensiveRow(domain, ref, overrides);
  writeOffensiveRunRows(domain, [row]);
  return row;
}

function appendFrozenFindingClaim(domain, {
  findingId = "F-1",
  severity = "low",
  evidenceRefs = null,
  exploitOutcome = null,
  title = null,
  payload = null,
  surfaceIds = null,
} = {}) {
  const claim = {
    target_domain: domain,
    title: title || `Frozen claim for ${findingId}`,
    summary: "Frozen baseline for verification severity guard tests.",
    severity,
    status: "candidate",
    evidence_refs: evidenceRefs || [findingRef(findingId)],
    impact: "Bounded fixture impact.",
  };
  if (exploitOutcome) claim.exploit_outcome = exploitOutcome;
  if (payload) claim.payload = payload;
  if (surfaceIds) claim.surface_ids = surfaceIds;
  return appendCandidateClaim(claim);
}

function freezeClaims(domain) {
  buildClaimFreeze(domain, {
    write: true,
    now: new Date("2026-06-01T00:00:00.000Z"),
  });
  const freeze = readCurrentClaimFreeze(domain);
  assert.ok(freeze, "claim-freeze.json must exist");
  assert.ok(Array.isArray(freeze.claims), "claim-freeze.json must carry claims[]");
  return freeze;
}

function verificationResult(findingId = "F-1", overrides = {}) {
  return {
    finding_id: findingId,
    disposition: "confirmed",
    severity: "critical",
    reportable: true,
    reasoning: "Verifier attempted to raise severity.",
    ...overrides,
  };
}

function v2VerificationResult(findingId = "F-1", overrides = {}) {
  return {
    ...verificationResult(findingId),
    confidence: "high",
    confidence_reasons: ["fresh_replay_passed"],
    state_sensitive: false,
    artifact_hashes: {},
    ...overrides,
  };
}

function persistedSeverity(domain, round = "brutalist", findingId = "F-1") {
  const document = JSON.parse(fs.readFileSync(verificationRoundPaths(domain, round).json, "utf8"));
  const result = document.results.find((entry) => entry.finding_id === findingId);
  assert.ok(result, `persisted ${round} result must include ${findingId}`);
  return result.severity;
}

function writeV1Round(domain, result, round = "brutalist") {
  writeVerificationRound({
    target_domain: domain,
    round,
    notes: null,
    results: [result],
  });
  return persistedSeverity(domain, round, result.finding_id);
}

function enterVerifyV2(domain) {
  const { raw, state } = readSessionStateStrict(domain);
  const entry = prepareVerificationEntry(domain, state, {
    now: new Date("2026-06-01T00:00:00.000Z"),
  });
  const nextState = {
    ...raw,
    phase: "VERIFY",
    lifecycle_state: "VERIFY",
    ...entry.state_fields,
  };
  writeFileAtomic(statePath(domain), `${JSON.stringify(nextState, null, 2)}\n`);
  return entry.state_fields;
}

function writeV2Round(domain, context, round, results, extra = {}) {
  return JSON.parse(writeVerificationRound({
    target_domain: domain,
    round,
    notes: null,
    verification_attempt_id: context.verification_attempt_id,
    verification_snapshot_hash: context.verification_snapshot_hash,
    round_profile: round,
    results,
    ...extra,
  }));
}

test("web v1 unproven severity rises are clamped to the frozen claim severity", () => withTempHome(() => {
  const domain = "severity-rise-clamp.example";
  initWebSession(domain);
  appendFrozenFindingClaim(domain, { severity: "low" });
  freezeClaims(domain);

  assert.equal(
    writeV1Round(domain, verificationResult("F-1", { severity: "critical" })),
    "low",
  );
}));

test("web guard uses the max frozen severity across claims for the same finding", () => withTempHome(() => {
  const domain = "severity-rise-max-claim.example";
  initWebSession(domain);
  appendFrozenFindingClaim(domain, { severity: "low", title: "Low duplicate claim" });
  appendFrozenFindingClaim(domain, { severity: "high", title: "High duplicate claim" });
  freezeClaims(domain);

  assert.equal(
    writeV1Round(domain, verificationResult("F-1", { severity: "critical" })),
    "high",
  );
}));

test("web v2 exploit proof plus exploit_replay_confirmed allows a severity rise", () => withTempHome(() => {
  const domain = "severity-rise-proof.example";
  initWebSession(domain);
  const ref = exploitRef(domain);
  seedSignedOffensiveRow(domain, ref);
  appendFrozenFindingClaim(domain, {
    severity: "low",
    evidenceRefs: [findingRef("F-1"), ref],
    exploitOutcome: {
      outcome: "exploited_safely",
      safe_oracle: { kind: "reflected_canary" },
    },
  });
  freezeClaims(domain);
  const context = enterVerifyV2(domain);

  writeV2Round(domain, context, "brutalist", [
    v2VerificationResult("F-1", {
      severity: "critical",
      confidence_reasons: ["exploit_replay_confirmed"],
    }),
  ]);

  assert.equal(persistedSeverity(domain), "critical");
}));

test("web v2 low demonstrated row without finding_id unlocks only an info to low rise", () => withTempHome(() => {
  const domain = "severity-rise-low-confirm.example";
  initWebSession(domain);
  const ref = exploitRef(domain);
  const row = seedSignedOffensiveRow(domain, ref, { demonstrated_severity: "low" });
  assert.equal(row.finding_id, undefined);
  appendFrozenFindingClaim(domain, {
    severity: "informational",
    evidenceRefs: [findingRef("F-1"), ref],
    exploitOutcome: {
      outcome: "exploited_safely",
      safe_oracle: { kind: "differential_response" },
    },
  });
  freezeClaims(domain);
  const context = enterVerifyV2(domain);

  writeV2Round(domain, context, "brutalist", [
    v2VerificationResult("F-1", {
      severity: "low",
      confidence_reasons: ["exploit_replay_confirmed"],
    }),
  ]);

  const document = JSON.parse(fs.readFileSync(verificationRoundPaths(domain, "brutalist").json, "utf8"));
  assert.equal(document.results[0].severity, "low");
  assert.ok(document.results[0].confidence_reasons.includes("exploit_replay_confirmed"));
}));

test("web v2 exploit proof is bound by the frozen finding's cited run_id", () => withTempHome(() => {
  const domain = "severity-rise-per-finding-run.example";
  initWebSession(domain);
  const ref = exploitRef(domain);
  seedSignedOffensiveRow(domain, ref, { demonstrated_severity: "low" });
  appendFrozenFindingClaim(domain, {
    findingId: "F-1",
    severity: "informational",
    evidenceRefs: [findingRef("F-1"), ref],
    exploitOutcome: {
      outcome: "exploited_safely",
      safe_oracle: { kind: "differential_response" },
    },
  });
  appendFrozenFindingClaim(domain, {
    findingId: "F-2",
    severity: "informational",
    evidenceRefs: [findingRef("F-2")],
  });
  freezeClaims(domain);
  const context = enterVerifyV2(domain);

  writeV2Round(domain, context, "brutalist", [
    v2VerificationResult("F-1", {
      severity: "low",
      confidence_reasons: ["exploit_replay_confirmed"],
    }),
    v2VerificationResult("F-2", {
      severity: "low",
      confidence_reasons: ["exploit_replay_confirmed"],
    }),
  ]);

  const document = JSON.parse(fs.readFileSync(verificationRoundPaths(domain, "brutalist").json, "utf8"));
  const f1 = document.results.find((result) => result.finding_id === "F-1");
  const f2 = document.results.find((result) => result.finding_id === "F-2");
  assert.equal(f1.severity, "low");
  assert.ok(f1.confidence_reasons.includes("exploit_replay_confirmed"));
  assert.equal(f2.severity, "info");
  assert.ok(!f2.confidence_reasons.includes("exploit_replay_confirmed"));
}));

test("duplicate frozen run_id references are dropped from every claim as defense in depth", () => withTempHome(() => {
  const domain = "severity-rise-duplicate-run-drop.example";
  initWebSession(domain);
  const ref = exploitRef(domain);
  seedSignedOffensiveRow(domain, ref, { demonstrated_severity: "low" });
  appendRawClaim(domain, {
    title: "Forged first frozen claim",
    summary: "Bypasses the record gate for a duplicate-run verification fixture.",
    severity: "informational",
    evidence_refs: [findingRef("F-1"), ref],
    exploit_outcome: { outcome: "exploited_safely", safe_oracle: { kind: "differential_response" } },
  });
  appendRawClaim(domain, {
    title: "Forged second frozen claim",
    summary: "Cites the same run id from a different claim.",
    severity: "informational",
    evidence_refs: [findingRef("F-2"), ref],
    exploit_outcome: { outcome: "exploited_safely", safe_oracle: { kind: "differential_response" } },
  });
  freezeClaims(domain);
  const context = enterVerifyV2(domain);

  writeV2Round(domain, context, "brutalist", [
    v2VerificationResult("F-1", { severity: "low", confidence_reasons: ["exploit_replay_confirmed"] }),
    v2VerificationResult("F-2", { severity: "low", confidence_reasons: ["exploit_replay_confirmed"] }),
  ]);

  assert.equal(persistedSeverity(domain, "brutalist", "F-1"), "info");
  assert.equal(persistedSeverity(domain, "brutalist", "F-2"), "info");
}));

test("web v2 severity rises require both the confidence reason and a satisfying exploit row", () => withTempHome(() => {
  const domainWithRow = "severity-rise-row-no-reason.example";
  initWebSession(domainWithRow);
  const refWithRow = exploitRef(domainWithRow);
  seedSignedOffensiveRow(domainWithRow, refWithRow);
  appendFrozenFindingClaim(domainWithRow, {
    severity: "low",
    evidenceRefs: [findingRef("F-1"), refWithRow],
    exploitOutcome: {
      outcome: "exploited_safely",
      safe_oracle: { kind: "reflected_canary" },
    },
  });
  freezeClaims(domainWithRow);
  let context = enterVerifyV2(domainWithRow);
  writeV2Round(domainWithRow, context, "brutalist", [
    v2VerificationResult("F-1", {
      severity: "critical",
      confidence_reasons: ["fresh_replay_passed"],
    }),
  ]);
  assert.equal(persistedSeverity(domainWithRow), "low");

  const domainWithReason = "severity-rise-reason-no-row.example";
  initWebSession(domainWithReason);
  const refWithReason = exploitRef(domainWithReason);
  seedSignedOffensiveRow(domainWithReason, refWithReason);
  appendFrozenFindingClaim(domainWithReason, {
    severity: "low",
    evidenceRefs: [findingRef("F-1"), refWithReason],
    exploitOutcome: {
      outcome: "exploited_safely",
      safe_oracle: { kind: "reflected_canary" },
    },
  });
  freezeClaims(domainWithReason);
  const dryRunRow = signedOffensiveRow(domainWithReason, refWithReason, { dry_run: true });
  writeOffensiveRunRows(domainWithReason, [dryRunRow]);
  context = enterVerifyV2(domainWithReason);
  writeV2Round(domainWithReason, context, "brutalist", [
    v2VerificationResult("F-1", {
      severity: "critical",
      confidence_reasons: ["exploit_replay_confirmed"],
    }),
  ]);
  assert.equal(persistedSeverity(domainWithReason), "low");
}));

test("the clamp applies uniformly: a finding with smart-contract-looking signals is still clamped", () => withTempHome(() => {
  const domain = "severity-rise-uniform.example";
  initWebSession(domain);
  // No trusted, non-agent SC signal exists before VERIFY (surface_ids, payload,
  // and even routes are agent-influenced), so the guard does NOT exempt
  // smart-contract findings — it applies to every finding in a web-scoped
  // session. A claim stuffed with SC-looking signals is still clamped.
  appendFrozenFindingClaim(domain, {
    findingId: "F-1",
    severity: "low",
    surfaceIds: ["surface-claims-to-be-sc"],
    payload: { finding: { surface_type: "smart_contract", capability_pack: "smart_contract_evm", sc_evidence: { contract_address: "0xfeed" } } },
  });
  freezeClaims(domain);

  assert.equal(writeV1Round(domain, verificationResult("F-1", { severity: "critical" })), "low");
}));

test("a multi-finding claim's exploit row cannot prove a sibling finding's rise", () => withTempHome(() => {
  const domain = "severity-rise-multi-finding.example";
  initWebSession(domain);
  const ref = exploitRef(domain);
  seedSignedOffensiveRow(domain, ref, { demonstrated_severity: "critical" });
  // One claim references BOTH F-1 and F-2 plus a single exploit_run ref. The
  // guard refuses to propagate that row to either finding (cross-finding
  // spillover guard), so an exploit_replay_confirmed rise on F-2 is clamped.
  appendFrozenFindingClaim(domain, {
    severity: "low",
    evidenceRefs: [findingRef("F-1"), findingRef("F-2"), ref],
    exploitOutcome: { outcome: "exploited_safely", safe_oracle: { kind: "reflected_canary" } },
  });
  freezeClaims(domain);
  const context = enterVerifyV2(domain);

  writeV2Round(domain, context, "brutalist", [
    v2VerificationResult("F-1", { severity: "low", confidence_reasons: ["fresh_replay_passed"] }),
    v2VerificationResult("F-2", { severity: "critical", confidence_reasons: ["exploit_replay_confirmed"] }),
  ]);
  assert.equal(persistedSeverity(domain, "brutalist", "F-2"), "low");
}));

test("the clamp is recorded in the persisted round document", () => withTempHome(() => {
  const domain = "severity-rise-doc-audit.example";
  initWebSession(domain);
  appendFrozenFindingClaim(domain, { findingId: "F-1", severity: "low" });
  freezeClaims(domain);

  writeV1Round(domain, verificationResult("F-1", { severity: "critical" }));
  const document = JSON.parse(fs.readFileSync(verificationRoundPaths(domain, "brutalist").json, "utf8"));
  assert.deepEqual(document.severity_clamps, [{ finding_id: "F-1", from: "critical", to: "low" }]);
}));

test("scope is derived from validated state, so a drifted nucleus file cannot disable the guard", () => withTempHome(() => {
  const domain = "severity-rise-nucleus-drift.example";
  initWebSession(domain);
  appendFrozenFindingClaim(domain, { findingId: "F-1", severity: "low" });
  freezeClaims(domain);
  // Tamper the (non-write-guarded) nucleus file to look non-web. The guard reads
  // scope from the validated state, so the web clamp still fires.
  fs.writeFileSync(sessionNucleusPath(domain), `${JSON.stringify({ scope_policy: { target_repo: "x/y" } })}\n`, "utf8");

  assert.equal(writeV1Round(domain, verificationResult("F-1", { severity: "critical" })), "low");
}));

test("an exploit row that demonstrates a lower severity does not unlock a higher rise", () => withTempHome(() => {
  const domain = "severity-rise-impact-binding.example";
  initWebSession(domain);
  const ref = exploitRef(domain);
  // A valid, signed row — but it only demonstrated "low" impact.
  seedSignedOffensiveRow(domain, ref, { demonstrated_severity: "low" });
  appendFrozenFindingClaim(domain, {
    severity: "low",
    evidenceRefs: [findingRef("F-1"), ref],
    exploitOutcome: { outcome: "exploited_safely", safe_oracle: { kind: "reflected_canary" } },
  });
  freezeClaims(domain);
  const context = enterVerifyV2(domain);

  writeV2Round(domain, context, "brutalist", [
    v2VerificationResult("F-1", { severity: "critical", confidence_reasons: ["exploit_replay_confirmed"] }),
  ]);
  assert.equal(persistedSeverity(domain), "low", "low-impact row cannot prove a critical rise");
}));

test("stale non-null verification attempt rows do not unlock verify-time rises", () => withTempHome(() => {
  const domain = "severity-rise-stale-attempt.example";
  initWebSession(domain);
  const ref = exploitRef(domain);
  seedSignedOffensiveRow(domain, ref, {
    demonstrated_severity: "low",
    verification_attempt_id: "verify-old-attempt",
    verification_snapshot_hash: "0".repeat(64),
  });
  appendFrozenFindingClaim(domain, {
    severity: "informational",
    evidenceRefs: [findingRef("F-1"), ref],
    exploitOutcome: { outcome: "exploited_safely", safe_oracle: { kind: "differential_response" } },
  });
  freezeClaims(domain);
  const context = enterVerifyV2(domain);

  writeV2Round(domain, context, "brutalist", [
    v2VerificationResult("F-1", {
      severity: "low",
      confidence_reasons: ["exploit_replay_confirmed"],
    }),
  ]);

  const document = JSON.parse(fs.readFileSync(verificationRoundPaths(domain, "brutalist").json, "utf8"));
  assert.equal(document.results[0].severity, "info");
  assert.ok(!document.results[0].confidence_reasons.includes("exploit_replay_confirmed"));
}));

test("a low exploit row does not cap a finding whose higher baseline is a separate non-exploit claim", () => withTempHome(() => {
  // Regression guard: the demonstrated-severity ceiling must apply ONLY to the
  // exploit-backed rise it validates, never as an unconditional cap. F-1 here has
  // a MEDIUM non-exploit claim (e.g. static analysis) alongside a LOW
  // exploited_safely confirmer claim; a verifier re-asserting medium (no rise)
  // must keep medium — the low exploit row must not drag it down.
  const domain = "severity-rise-no-overcap.example";
  initWebSession(domain);
  const ref = exploitRef(domain);
  // The low exploited_safely claim needs its backing row to pass the record gate.
  seedSignedOffensiveRow(domain, ref, { demonstrated_severity: "low" });
  appendFrozenFindingClaim(domain, {
    severity: "medium",
    evidenceRefs: [findingRef("F-1")],
  });
  appendFrozenFindingClaim(domain, {
    severity: "low",
    evidenceRefs: [findingRef("F-1"), ref],
    exploitOutcome: { outcome: "exploited_safely", safe_oracle: { kind: "differential_response" } },
  });
  freezeClaims(domain);
  writeOffensiveRunRows(domain, [signedOffensiveRow(domain, ref, { demonstrated_severity: "low" })]);
  const context = enterVerifyV2(domain);

  const response = writeV2Round(domain, context, "brutalist", [
    v2VerificationResult("F-1", {
      severity: "medium",
      confidence_reasons: ["fresh_replay_passed"],
    }),
  ]);

  assert.equal(persistedSeverity(domain), "medium");
  assert.ok(
    !response.severity_clamps || response.severity_clamps.length === 0,
    "the low exploit row must not clamp the medium baseline",
  );
}));

test("exploit_replay_confirmed is stripped from a result that did not back a validated rise", () => withTempHome(() => {
  const domain = "severity-rise-strip-reason.example";
  initWebSession(domain);
  // No offensive row exists, so the proof can never validate. A verifier asserts
  // exploit_replay_confirmed on (a) a clamped rise and (b) a non-rise. Both must
  // have the unproven proof-claim stripped from the persisted artifact.
  appendFrozenFindingClaim(domain, { findingId: "F-1", severity: "low" });
  appendFrozenFindingClaim(domain, { findingId: "F-2", severity: "high" });
  freezeClaims(domain);
  const context = enterVerifyV2(domain);

  writeV2Round(domain, context, "brutalist", [
    v2VerificationResult("F-1", { severity: "critical", confidence_reasons: ["exploit_replay_confirmed"] }),
    v2VerificationResult("F-2", {
      severity: "high",
      confidence_reasons: ["fresh_replay_passed"],
      // The proof claim hidden in the provenance arrays must also be stripped.
      inherited_confidence_reasons: ["exploit_replay_confirmed"],
      resolved_confidence_reasons: ["exploit_replay_confirmed"],
    }),
  ]);

  const document = JSON.parse(fs.readFileSync(verificationRoundPaths(domain, "brutalist").json, "utf8"));
  const f1 = document.results.find((r) => r.finding_id === "F-1");
  const f2 = document.results.find((r) => r.finding_id === "F-2");
  assert.equal(f1.severity, "low", "unproven rise is clamped");
  assert.ok(!f1.confidence_reasons.includes("exploit_replay_confirmed"), "stripped on the clamped rise");
  assert.ok(!f2.confidence_reasons.includes("exploit_replay_confirmed"), "stripped on the non-rise");
  assert.ok(!f2.inherited_confidence_reasons.includes("exploit_replay_confirmed"), "stripped from inherited_");
  assert.ok(!f2.resolved_confidence_reasons.includes("exploit_replay_confirmed"), "stripped from resolved_");
  assert.ok(f2.confidence_reasons.includes("fresh_replay_passed"), "other reasons are preserved");
}));

test("clamps are surfaced in the tool response", () => withTempHome(() => {
  const domain = "severity-rise-response-signal.example";
  initWebSession(domain);
  appendFrozenFindingClaim(domain, { findingId: "F-1", severity: "low" });
  freezeClaims(domain);

  const response = JSON.parse(writeVerificationRound({
    target_domain: domain,
    round: "brutalist",
    notes: null,
    results: [verificationResult("F-1", { severity: "critical" })],
  }));

  assert.ok(Array.isArray(response.severity_clamps), "response carries severity_clamps");
  assert.deepEqual(response.severity_clamps, [{ finding_id: "F-1", from: "critical", to: "low" }]);
}));

test("every severity enum value maps to a non-zero VERIFY_SEVERITY_RANK", () => {
  const { verifySeverityRank } = require("../mcp/lib/verification-round-store.js");
  for (const severity of SEVERITY_VALUES) {
    assert.ok(verifySeverityRank(severity) > 0, `${severity} must have a non-zero rank`);
  }
  // The claim enum uses "informational" where the round enum uses "info".
  assert.ok(verifySeverityRank("informational") > 0, "informational must have a non-zero rank");
});

test("non-web repo sessions are not clamped", () => withTempHome((home) => {
  const domain = initRepoOnlySession(home, "severity-rise-repo.example");
  appendFrozenFindingClaim(domain, { severity: "medium" });
  freezeClaims(domain);

  assert.equal(
    writeV1Round(domain, verificationResult("F-1", { severity: "high" })),
    "high",
  );
}));

test("web equality, lowering, info/informational, null severity, and no-freeze paths pass through", () => withTempHome(() => {
  const equalityDomain = "severity-rise-equality.example";
  initWebSession(equalityDomain);
  appendFrozenFindingClaim(equalityDomain, { severity: "high" });
  freezeClaims(equalityDomain);
  assert.equal(writeV1Round(equalityDomain, verificationResult("F-1", { severity: "high" })), "high");

  const loweringDomain = "severity-rise-lowering.example";
  initWebSession(loweringDomain);
  appendFrozenFindingClaim(loweringDomain, { severity: "high" });
  freezeClaims(loweringDomain);
  assert.equal(writeV1Round(loweringDomain, verificationResult("F-1", { severity: "low" })), "low");

  const infoDomain = "severity-rise-info.example";
  initWebSession(infoDomain);
  appendFrozenFindingClaim(infoDomain, { severity: "informational" });
  freezeClaims(infoDomain);
  assert.equal(writeV1Round(infoDomain, verificationResult("F-1", { severity: "info" })), "info");

  const nullDomain = "severity-rise-null.example";
  initWebSession(nullDomain);
  appendFrozenFindingClaim(nullDomain, { severity: "low" });
  freezeClaims(nullDomain);
  assert.equal(writeV1Round(nullDomain, verificationResult("F-1", {
    disposition: "denied",
    severity: null,
    reportable: false,
  })), null);

  const legacyDomain = "severity-rise-no-freeze.example";
  initWebSession(legacyDomain);
  appendFrozenFindingClaim(legacyDomain, { severity: "low" });
  assert.equal(writeV1Round(legacyDomain, verificationResult("F-1", { severity: "critical" })), "critical");
}));

test("corrupt offensive ledger fails closed for exploit-backed ceiling checks", () => withTempHome(() => {
  const domain = "severity-rise-corrupt-ledger.example";
  initWebSession(domain);
  const ref = exploitRef(domain);
  seedSignedOffensiveRow(domain, ref);
  appendFrozenFindingClaim(domain, {
    severity: "low",
    evidenceRefs: [findingRef("F-1"), ref],
    exploitOutcome: {
      outcome: "exploited_safely",
      safe_oracle: { kind: "reflected_canary" },
    },
  });
  freezeClaims(domain);
  const context = enterVerifyV2(domain);

  fs.writeFileSync(offensiveRunsJsonlPath(domain), "{not-json}\n", "utf8");
  assert.throws(
    () => writeV2Round(domain, context, "brutalist", [
      v2VerificationResult("F-1", {
        severity: "low",
        confidence_reasons: ["exploit_replay_confirmed"],
      }),
    ]),
    (error) => error && error.code === "STATE_CONFLICT" && /malformed row/.test(error.message),
  );
}));

test("v2 final write and adjudication consume already-clamped rounds", () => withTempHome(() => {
  const domain = "severity-rise-v2-final.example";
  initWebSession(domain);
  appendFrozenFindingClaim(domain, { severity: "low" });
  freezeClaims(domain);
  const context = enterVerifyV2(domain);
  const raised = v2VerificationResult("F-1", {
    severity: "critical",
    confidence_reasons: ["fresh_replay_passed"],
  });

  writeV2Round(domain, context, "brutalist", [raised]);
  writeV2Round(domain, context, "balanced", [raised]);
  assert.equal(persistedSeverity(domain, "brutalist"), "low");
  assert.equal(persistedSeverity(domain, "balanced"), "low");

  const adjudication = JSON.parse(buildVerificationAdjudication({ target_domain: domain }));
  const final = writeV2Round(domain, context, "final", [raised], {
    adjudication_plan_hash: adjudication.adjudication_plan_hash,
  });

  assert.match(final.final_verification_hash, /^[a-f0-9]{64}$/);
  assert.equal(persistedSeverity(domain, "final"), "low");
}));

test("exploit_replay_confirmed is exposed by constants and every write schema confidence-reason enum", () => {
  assert.ok(VERIFICATION_CONFIDENCE_REASON_VALUES.includes("exploit_replay_confirmed"));

  const resultProperties = writeVerificationRoundTool.inputSchema
    .properties.results.items.properties;
  for (const field of [
    "confidence_reasons",
    "inherited_confidence_reasons",
    "resolved_confidence_reasons",
  ]) {
    assert.ok(
      resultProperties[field].items.enum.includes("exploit_replay_confirmed"),
      `${field} enum must include exploit_replay_confirmed`,
    );
  }
});
