"use strict";

// The per-finding verification round commit routes through the EXISTING round
// writer: bob_write_verification_round invoked WITHOUT a `results` array on a v2
// attempt with staged partials present commits the union, instead of requiring a
// distinct commit tool. These tests pin that routing at the writer boundary:
//   - empty-results commit equals a single-shot write over the same union
//     (byte-identical finding-bearing body; the SAME finalize runs);
//   - the legacy single-shot path (a `results` array is supplied) is unchanged;
//   - an empty-results invocation on a v1 session still demands a results array
//     (no behavior flip for legacy sessions);
//   - the exact-coverage gate is the commit gate: a missing finding stops and
//     names the gap rather than committing a partial union;
//   - commitVerificationRoundFromPartials always supplies results, so the
//     routing never recurses (the union commit produces a real round document).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  buildClaimFreeze,
} = require("../mcp/lib/claim-freeze.js");
const {
  appendCandidateClaim,
} = require("../mcp/lib/claims.js");
const {
  statePath,
  verificationRoundPaths,
} = require("../mcp/lib/paths.js");
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
  prepareVerificationEntry,
} = require("../mcp/lib/verification.js");
const {
  stageVerificationRoundPartial,
  writeVerificationRound,
} = require("../mcp/lib/verification-round-store.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-verification-commit-routing-"));
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

function initWebSession(domain) {
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
}

function appendFrozenFindingClaim(domain, { findingId, severity = "high" } = {}) {
  return appendCandidateClaim({
    target_domain: domain,
    title: `Frozen claim for ${findingId}`,
    summary: "Frozen baseline for per-finding round commit routing.",
    severity,
    status: "candidate",
    evidence_refs: [{ kind: "finding", finding_id: findingId, content_hash: "0".repeat(64) }],
    impact: "Bounded fixture impact.",
  });
}

function freezeClaims(domain) {
  buildClaimFreeze(domain, { write: true, now: new Date("2026-06-01T00:00:00.000Z") });
}

function enterVerifyV2(domain) {
  const { raw, state } = readSessionStateStrict(domain);
  const entry = prepareVerificationEntry(domain, state, { now: new Date("2026-06-01T00:00:00.000Z") });
  const nextState = {
    ...raw,
    phase: "VERIFY",
    lifecycle_state: "VERIFY",
    ...entry.state_fields,
  };
  writeFileAtomic(statePath(domain), `${JSON.stringify(nextState, null, 2)}\n`);
  return entry.state_fields;
}

function v2Result(findingId, overrides = {}) {
  return {
    finding_id: findingId,
    disposition: "confirmed",
    severity: "high",
    reportable: true,
    reasoning: `Per-finding worker verdict for ${findingId}.`,
    repro_steps: [`Step for ${findingId}`],
    evidence_refs: [],
    confidence: "high",
    confidence_reasons: ["fresh_replay_passed"],
    state_sensitive: false,
    artifact_hashes: {},
    ...overrides,
  };
}

function setupTwoFindingVerify(domain) {
  initWebSession(domain);
  appendFrozenFindingClaim(domain, { findingId: "F-1", severity: "high" });
  appendFrozenFindingClaim(domain, { findingId: "F-2", severity: "high" });
  freezeClaims(domain);
  return enterVerifyV2(domain);
}

function roundDoc(domain, round) {
  return JSON.parse(fs.readFileSync(verificationRoundPaths(domain, round).json, "utf8"));
}

test("an empty-results round write commits the staged partials and equals a single-shot write", () => withTempHome(() => {
  const unionDomain = "commit-routing-union.example";
  const singleDomain = "commit-routing-single.example";

  const unionCtx = setupTwoFindingVerify(unionDomain);
  for (const findingId of ["F-2", "F-1"]) {
    stageVerificationRoundPartial({
      target_domain: unionDomain,
      round: "brutalist",
      verification_attempt_id: unionCtx.verification_attempt_id,
      verification_snapshot_hash: unionCtx.verification_snapshot_hash,
      result: v2Result(findingId),
    });
  }

  // No `results` array: the writer routes to the union commit.
  const commitResp = JSON.parse(writeVerificationRound({
    target_domain: unionDomain,
    round: "brutalist",
    notes: null,
    verification_attempt_id: unionCtx.verification_attempt_id,
    verification_snapshot_hash: unionCtx.verification_snapshot_hash,
  }));
  assert.equal(commitResp.committed_from_partials, true);
  assert.equal(commitResp.committed_finding_count, 2);

  const singleCtx = setupTwoFindingVerify(singleDomain);
  writeVerificationRound({
    target_domain: singleDomain,
    round: "brutalist",
    notes: null,
    verification_attempt_id: singleCtx.verification_attempt_id,
    verification_snapshot_hash: singleCtx.verification_snapshot_hash,
    round_profile: "brutalist",
    results: [v2Result("F-1"), v2Result("F-2")],
  });

  assert.deepEqual(roundDoc(unionDomain, "brutalist").results, roundDoc(singleDomain, "brutalist").results);
}));

test("an empty-results commit stops and names a missing finding rather than committing a partial union", () => withTempHome(() => {
  const domain = "commit-routing-missing.example";
  const ctx = setupTwoFindingVerify(domain);
  stageVerificationRoundPartial({
    target_domain: domain,
    round: "brutalist",
    verification_attempt_id: ctx.verification_attempt_id,
    verification_snapshot_hash: ctx.verification_snapshot_hash,
    result: v2Result("F-1"),
  });

  assert.throws(
    () => writeVerificationRound({
      target_domain: domain,
      round: "brutalist",
      notes: null,
      verification_attempt_id: ctx.verification_attempt_id,
      verification_snapshot_hash: ctx.verification_snapshot_hash,
    }),
    /must cover exactly the current VERIFY snapshot finding IDs.*missing: F-2/,
  );
  assert.equal(fs.existsSync(verificationRoundPaths(domain, "brutalist").json), false);
}));

test("the legacy single-shot path is unchanged when a results array is supplied", () => withTempHome(() => {
  const domain = "commit-routing-legacy.example";
  const ctx = setupTwoFindingVerify(domain);

  // A results array NEVER routes to the union commit; it writes the round directly.
  const resp = JSON.parse(writeVerificationRound({
    target_domain: domain,
    round: "brutalist",
    notes: null,
    verification_attempt_id: ctx.verification_attempt_id,
    verification_snapshot_hash: ctx.verification_snapshot_hash,
    round_profile: "brutalist",
    results: [v2Result("F-1"), v2Result("F-2")],
  }));
  assert.notEqual(resp.committed_from_partials, true);
  assert.equal(roundDoc(domain, "brutalist").results.length, 2);
}));

test("an empty-results write on a v1 session still demands a results array (no legacy flip)", () => withTempHome(() => {
  const domain = "commit-routing-v1.example";
  // A bare web session with no v2 VERIFY entry resolves a v1 write schema; the
  // empty-results commit signal must not apply, so the unchanged contract holds.
  initWebSession(domain);
  assert.throws(
    () => writeVerificationRound({
      target_domain: domain,
      round: "brutalist",
      notes: null,
    }),
    /results must be an array/,
  );
}));
