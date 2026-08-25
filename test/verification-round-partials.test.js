"use strict";

// Per-finding verification fan-out at the store/brain level: each per-finding
// worker stages ONE finding's verification result via
// stageVerificationRoundPartial; the server UNIONS the staged partials into the
// single round document via commitVerificationRoundFromPartials, where the
// existing exact-coverage gate is the commit gate. These tests pin:
//   - union equivalence: a partials commit produces the same round document as a
//     single-shot writeVerificationRound over the same results (non-forgeability
//     and the v2 final/adjudication bindings are unaffected because the SAME
//     writer runs);
//   - exact coverage on the union: a missing finding stops-and-names the gap (no
//     silent drop); an extra/unknown finding is rejected at stage time;
//   - the anti-inflation severity clamp stays per-finding-correct on the union;
//   - the finding-scoped replay-lease opt-in narrows attempt_pack -> finding so
//     disjoint findings serialize independently while the same finding serializes.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  buildClaimFreeze,
} = require("../mcp/core/claims/claim-freeze.js");
const {
  appendCandidateClaim,
} = require("../mcp/core/claims/claims.js");
const {
  statePath,
  verificationRoundPaths,
  verificationRoundPartialDir,
} = require("../mcp/core/io/paths.js");
const {
  initSession,
} = require("../mcp/core/session/session-state.js");
const {
  readSessionStateStrict,
} = require("../mcp/core/session/session-state-store.js");
const {
  writeFileAtomic,
} = require("../mcp/core/io/storage.js");
const {
  prepareVerificationEntry,
} = require("../mcp/core/verification/verification.js");
const {
  commitVerificationRoundFromPartials,
  listCurrentRoundPartials,
  stageVerificationRoundPartial,
  writeVerificationRound,
} = require("../mcp/core/verification/verification-round-store.js");
const {
  resolveEffectiveLeaseScope,
  normalizeReplayContext,
  replayExecutionPolicy,
  replayLeaseKey,
} = require("../mcp/core/verification/verification-replay-safety.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/core/frontier/frontier-materialize-debounce.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-verification-round-partials-"));
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

function appendFrozenFindingClaim(domain, { findingId, severity = "high", title = null } = {}) {
  return appendCandidateClaim({
    target_domain: domain,
    title: title || `Frozen claim for ${findingId}`,
    summary: "Frozen baseline for per-finding verification fan-out tests.",
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

test("staging one finding reports the coverage gap and is not yet ready to commit", () => withTempHome(() => {
  const domain = "partials-stage-progress.example";
  const ctx = setupTwoFindingVerify(domain);

  const first = JSON.parse(stageVerificationRoundPartial({
    target_domain: domain,
    round: "brutalist",
    verification_attempt_id: ctx.verification_attempt_id,
    verification_snapshot_hash: ctx.verification_snapshot_hash,
    result: v2Result("F-1"),
  }));
  assert.equal(first.staged_count, 1);
  assert.equal(first.snapshot_findings, 2);
  assert.deepEqual(first.remaining_finding_ids, ["F-2"]);
  assert.equal(first.ready_to_commit, false);

  // No round document exists yet — staging never writes the audit-graded artifact.
  assert.equal(fs.existsSync(verificationRoundPaths(domain, "brutalist").json), false);
}));

test("committing before all findings are staged stops and names the missing finding", () => withTempHome(() => {
  const domain = "partials-missing-stops.example";
  const ctx = setupTwoFindingVerify(domain);

  stageVerificationRoundPartial({
    target_domain: domain,
    round: "brutalist",
    verification_attempt_id: ctx.verification_attempt_id,
    verification_snapshot_hash: ctx.verification_snapshot_hash,
    result: v2Result("F-1"),
  });

  assert.throws(
    () => commitVerificationRoundFromPartials({
      target_domain: domain,
      round: "brutalist",
      verification_attempt_id: ctx.verification_attempt_id,
      verification_snapshot_hash: ctx.verification_snapshot_hash,
    }),
    /must cover exactly the current VERIFY snapshot finding IDs.*missing: F-2/,
  );
  // The partial gap never produced a round document.
  assert.equal(fs.existsSync(verificationRoundPaths(domain, "brutalist").json), false);
}));

test("staging an unknown finding_id is rejected at stage time", () => withTempHome(() => {
  const domain = "partials-extra-rejected.example";
  const ctx = setupTwoFindingVerify(domain);

  assert.throws(
    () => stageVerificationRoundPartial({
      target_domain: domain,
      round: "brutalist",
      verification_attempt_id: ctx.verification_attempt_id,
      verification_snapshot_hash: ctx.verification_snapshot_hash,
      result: v2Result("F-99"),
    }),
    /Unknown finding_id: F-99/,
  );
}));

test("a partials commit produces the same round document as a single-shot write", () => withTempHome(() => {
  const unionDomain = "partials-union.example";
  const singleDomain = "partials-single.example";

  // Union path: stage each finding via a separate worker, then commit.
  const unionCtx = setupTwoFindingVerify(unionDomain);
  for (const findingId of ["F-2", "F-1"]) { // out of snapshot order on purpose
    stageVerificationRoundPartial({
      target_domain: unionDomain,
      round: "brutalist",
      verification_attempt_id: unionCtx.verification_attempt_id,
      verification_snapshot_hash: unionCtx.verification_snapshot_hash,
      result: v2Result(findingId),
    });
  }
  const commitResp = JSON.parse(commitVerificationRoundFromPartials({
    target_domain: unionDomain,
    round: "brutalist",
    verification_attempt_id: unionCtx.verification_attempt_id,
    verification_snapshot_hash: unionCtx.verification_snapshot_hash,
  }));
  assert.equal(commitResp.committed_from_partials, true);
  assert.equal(commitResp.committed_finding_count, 2);

  // Single-shot path on a sibling session with identical findings.
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

  // The two round documents are structurally identical apart from the
  // attempt/snapshot binding (different sessions). Compare the finding-bearing
  // body, which is what the v2 final hash and adjudication bind over.
  const unionBody = roundDoc(unionDomain, "brutalist").results;
  const singleBody = roundDoc(singleDomain, "brutalist").results;
  assert.deepEqual(unionBody, singleBody);

  // Staging area cleared after commit.
  assert.equal(
    fs.existsSync(verificationRoundPartialDir(unionDomain, "brutalist"))
      ? fs.readdirSync(verificationRoundPartialDir(unionDomain, "brutalist")).length
      : 0,
    0,
  );
}));

test("the anti-inflation severity clamp stays per-finding-correct on the union", () => withTempHome(() => {
  const domain = "partials-clamp.example";
  initWebSession(domain);
  // F-1 frozen low (an unproven verify-time rise to critical must clamp to low);
  // F-2 frozen high (a high verdict is at baseline, no clamp).
  appendFrozenFindingClaim(domain, { findingId: "F-1", severity: "low" });
  appendFrozenFindingClaim(domain, { findingId: "F-2", severity: "high" });
  freezeClaims(domain);
  const ctx = enterVerifyV2(domain);

  stageVerificationRoundPartial({
    target_domain: domain,
    round: "brutalist",
    verification_attempt_id: ctx.verification_attempt_id,
    verification_snapshot_hash: ctx.verification_snapshot_hash,
    result: v2Result("F-1", { severity: "critical" }),
  });
  stageVerificationRoundPartial({
    target_domain: domain,
    round: "brutalist",
    verification_attempt_id: ctx.verification_attempt_id,
    verification_snapshot_hash: ctx.verification_snapshot_hash,
    result: v2Result("F-2", { severity: "high" }),
  });
  commitVerificationRoundFromPartials({
    target_domain: domain,
    round: "brutalist",
    verification_attempt_id: ctx.verification_attempt_id,
    verification_snapshot_hash: ctx.verification_snapshot_hash,
  });

  const doc = roundDoc(domain, "brutalist");
  const f1 = doc.results.find((r) => r.finding_id === "F-1");
  const f2 = doc.results.find((r) => r.finding_id === "F-2");
  assert.equal(f1.severity, "low", "unproven F-1 rise is clamped to frozen low on the union");
  assert.equal(f2.severity, "high", "F-2 at baseline is unchanged");
  assert.deepEqual(doc.severity_clamps, [{ finding_id: "F-1", from: "critical", to: "low" }]);
}));

test("re-staging a finding overwrites the prior submission (idempotent worker retry)", () => withTempHome(() => {
  const domain = "partials-restage.example";
  const ctx = setupTwoFindingVerify(domain);

  stageVerificationRoundPartial({
    target_domain: domain,
    round: "brutalist",
    verification_attempt_id: ctx.verification_attempt_id,
    verification_snapshot_hash: ctx.verification_snapshot_hash,
    result: v2Result("F-1", { disposition: "denied", reportable: false }),
  });
  const second = JSON.parse(stageVerificationRoundPartial({
    target_domain: domain,
    round: "brutalist",
    verification_attempt_id: ctx.verification_attempt_id,
    verification_snapshot_hash: ctx.verification_snapshot_hash,
    result: v2Result("F-1", { disposition: "confirmed", reportable: true }),
  }));
  assert.equal(second.staged_count, 1, "re-staging F-1 does not double-count");

  const partials = listCurrentRoundPartials(domain, "brutalist", { state: ctx });
  const f1 = partials.find(({ partial }) => partial.finding_id === "F-1");
  assert.equal(f1.partial.result.disposition, "confirmed", "the latest submission wins");
}));

test("a partial bound to a stale snapshot is pruned and never leaks into the union", () => withTempHome(() => {
  const domain = "partials-stale-binding.example";
  const ctx = setupTwoFindingVerify(domain);

  // Stage F-1 honestly.
  stageVerificationRoundPartial({
    target_domain: domain,
    round: "brutalist",
    verification_attempt_id: ctx.verification_attempt_id,
    verification_snapshot_hash: ctx.verification_snapshot_hash,
    result: v2Result("F-1"),
  });
  // Plant a forged partial for F-2 bound to a DIFFERENT snapshot hash. It must be
  // pruned by the freshness filter, so the commit still stops on missing F-2.
  const dir = verificationRoundPartialDir(domain, "brutalist");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, "forged-stale.json"),
    `${JSON.stringify({
      version: 1,
      target_domain: domain,
      round: "brutalist",
      verification_attempt_id: ctx.verification_attempt_id,
      verification_snapshot_hash: "f".repeat(64),
      finding_id: "F-2",
      result: v2Result("F-2"),
      staged_at: new Date().toISOString(),
    })}\n`,
    "utf8",
  );

  assert.throws(
    () => commitVerificationRoundFromPartials({
      target_domain: domain,
      round: "brutalist",
      verification_attempt_id: ctx.verification_attempt_id,
      verification_snapshot_hash: ctx.verification_snapshot_hash,
    }),
    /missing: F-2/,
  );
}));

test("a worker cannot land a reportable verdict for a finding it did not execute", () => withTempHome(() => {
  const domain = "partials-non-forgeable.example";
  const ctx = setupTwoFindingVerify(domain);

  // Honest worker stages F-1. A second worker forges a reportable critical
  // verdict for F-2 but binds it to a different attempt (it never ran the
  // current VERIFY attempt for F-2). The freshness filter excludes the forged
  // partial, so the commit stops-and-names F-2 rather than committing the
  // forged verdict — a worker can never inject a verdict for a finding it did
  // not legitimately execute under the current attempt+snapshot.
  stageVerificationRoundPartial({
    target_domain: domain,
    round: "brutalist",
    verification_attempt_id: ctx.verification_attempt_id,
    verification_snapshot_hash: ctx.verification_snapshot_hash,
    result: v2Result("F-1"),
  });
  const dir = verificationRoundPartialDir(domain, "brutalist");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, "forged-attempt.json"),
    `${JSON.stringify({
      version: 1,
      target_domain: domain,
      round: "brutalist",
      verification_attempt_id: "forged-attempt-id",
      verification_snapshot_hash: ctx.verification_snapshot_hash,
      finding_id: "F-2",
      result: v2Result("F-2", { severity: "critical", reportable: true }),
      staged_at: new Date().toISOString(),
    })}\n`,
    "utf8",
  );

  assert.throws(
    () => commitVerificationRoundFromPartials({
      target_domain: domain,
      round: "brutalist",
      verification_attempt_id: ctx.verification_attempt_id,
      verification_snapshot_hash: ctx.verification_snapshot_hash,
    }),
    /missing: F-2/,
  );
  // No round document — the forged reportable verdict never reached the
  // audit-graded artifact.
  assert.equal(fs.existsSync(verificationRoundPaths(domain, "brutalist").json), false);
}));

test("a finding-scoped pack can run rounds concurrently while the attempt_pack default cannot", () => withTempHome(() => {
  const domain = "partials-concurrency-policy.example";
  initWebSession(domain);
  const policy = replayExecutionPolicy(domain);
  // Every pack's default lease scope is exposed; can_run_rounds_concurrently is
  // true exactly when the scope is finding (or the mode is parallel_safe). The
  // shipped web default is serialized/attempt_pack -> NOT concurrent, which is
  // why per-finding workers must opt in to the finding scope to fan out.
  for (const pack of policy) {
    const expected = pack.mode === "parallel_safe" || pack.lease_scope === "finding";
    assert.equal(pack.can_run_rounds_concurrently, expected);
  }
  const webPack = policy.find((p) => p.capability_pack === "web");
  assert.equal(webPack.lease_scope, "attempt_pack");
  assert.equal(webPack.can_run_rounds_concurrently, false);
}));

test("the finding-scope lease opt-in narrows attempt_pack and disjoint findings get disjoint keys", () => {
  const ctxF1 = normalizeReplayContext({
    purpose: "verification_replay",
    verification_attempt_id: "attempt-1",
    verification_snapshot_hash: "h",
    finding_id: "F-1",
    lease_scope: "finding",
  });
  const ctxF2 = normalizeReplayContext({
    purpose: "verification_replay",
    verification_attempt_id: "attempt-1",
    verification_snapshot_hash: "h",
    finding_id: "F-2",
    lease_scope: "finding",
  });

  // The opt-in narrows the pack default attempt_pack -> finding.
  assert.equal(resolveEffectiveLeaseScope("attempt_pack", ctxF1), "finding");

  // Disjoint findings -> disjoint keys (run concurrently).
  const keyF1 = replayLeaseKey({ targetDomain: "d", capabilityPack: "p", leaseScope: "finding", context: ctxF1 });
  const keyF2 = replayLeaseKey({ targetDomain: "d", capabilityPack: "p", leaseScope: "finding", context: ctxF2 });
  assert.notEqual(keyF1, keyF2);

  // Same finding -> same key (serializes within-finding).
  const keyF1b = replayLeaseKey({ targetDomain: "d", capabilityPack: "p", leaseScope: "finding", context: ctxF1 });
  assert.equal(keyF1, keyF1b);
});

test("the object-state lease opt-in narrows attempt_pack by surface and state key", () => {
  const ctxCouponA = normalizeReplayContext({
    purpose: "verification_replay",
    verification_attempt_id: "attempt-1",
    verification_snapshot_hash: "h",
    lease_scope: "object_state",
    surface_id: "POST /api/coupons/redeem",
    object_state_key: "coupon:A",
  });
  const ctxCouponB = normalizeReplayContext({
    purpose: "verification_replay",
    verification_attempt_id: "attempt-1",
    verification_snapshot_hash: "h",
    lease_scope: "object_state",
    surface_id: "POST /api/coupons/redeem",
    object_state_key: "coupon:B",
  });

  assert.equal(resolveEffectiveLeaseScope("attempt_pack", ctxCouponA), "object_state");

  const keyA = replayLeaseKey({ targetDomain: "d", capabilityPack: "web", leaseScope: "object_state", context: ctxCouponA });
  const keyB = replayLeaseKey({ targetDomain: "d", capabilityPack: "web", leaseScope: "object_state", context: ctxCouponB });
  assert.notEqual(keyA, keyB);
  assert.equal(
    keyA,
    replayLeaseKey({ targetDomain: "d", capabilityPack: "web", leaseScope: "object_state", context: ctxCouponA }),
  );
});

test("without the opt-in the lease scope is the unchanged pack default (no default flip)", () => {
  const ctx = normalizeReplayContext({
    purpose: "verification_replay",
    verification_attempt_id: "attempt-1",
    verification_snapshot_hash: "h",
    finding_id: "F-1",
  });
  // No replay_context.lease_scope opt-in: behavior is byte-identical to today.
  assert.equal(ctx.lease_scope_opt_in, null);
  assert.equal(resolveEffectiveLeaseScope("attempt_pack", ctx), "attempt_pack");
  // The opt-in with no finding_id also cannot narrow (a finding lease needs an id).
  const ctxNoFinding = normalizeReplayContext({
    purpose: "verification_replay",
    verification_attempt_id: "attempt-1",
    verification_snapshot_hash: "h",
    lease_scope: "finding",
  });
  assert.equal(resolveEffectiveLeaseScope("attempt_pack", ctxNoFinding), "attempt_pack");
});

test("an unsupported lease_scope opt-in value is rejected", () => {
  assert.throws(
    () => normalizeReplayContext({
      purpose: "verification_replay",
      verification_attempt_id: "attempt-1",
      verification_snapshot_hash: "h",
      finding_id: "F-1",
      lease_scope: "attempt_pack",
    }),
    /lease_scope opt-in supports only "finding" or "object_state"/,
  );
});

test("the object-state lease opt-in requires a surface and object-state key", () => {
  assert.throws(
    () => normalizeReplayContext({
      purpose: "verification_replay",
      verification_attempt_id: "attempt-1",
      verification_snapshot_hash: "h",
      lease_scope: "object_state",
      surface_id: "POST /api/coupons/redeem",
    }),
    /replay_context\.object_state_key/,
  );
});

// The VERIFY round dispatch defaults to per-finding fan-out. These pin the
// orchestrator prose (and its rendered host skill) so the dispatch DEFAULT is
// one verifier worker per snapshot finding (each opting into the finding-scoped
// replay lease), while the single-worker whole-round path stays documented as
// the explicit LEAN fallback. The lease-layer tests above (the pack default is
// still attempt_pack/serialized; the opt-in narrows; no opt-in is unchanged)
// prove the flip is dispatch-only and the serialized floor is one explicit
// fallback away.
const REPO_ROOT = path.join(__dirname, "..");
function readRepoText(rel) {
  return fs.readFileSync(path.join(REPO_ROOT, rel), "utf8");
}

for (const surface of [
  "prompts/roles/orchestrator.md",
  ".claude/skills/bob-evaluate-runner/SKILL.md",
]) {
  test(`${surface}: per-finding round fan-out is the DEFAULT verify dispatch`, () => {
    const text = readRepoText(surface);

    // The default-dispatch header (not "optional, default-off").
    assert.match(text, /Per-finding round fan-out \(default dispatch\)/);
    assert.doesNotMatch(text, /default-off/);
    assert.doesNotMatch(text, /\(optional, default-off\)/);

    // The default path spawns one worker per snapshot finding, each opting into
    // the finding-scoped lease (which makes the round concurrent-safe).
    assert.match(text, /by default with one worker per frozen finding/);
    assert.match(text, /By default: read the frozen finding IDs/);
    assert.match(text, /replay_context\.lease_scope: "finding"/);
    assert.match(text, /concurrent-safe for those leases/);

    // can_run_rounds_concurrently is no longer the precondition; it describes
    // the LEAN fallback.
    assert.match(text, /not a precondition for this default path/);

    // RANK != BOUND: exactly one worker per snapshot finding ID, never a subset,
    // and the union covers exactly the snapshot finding IDs.
    assert.match(text, /exactly one worker per snapshot finding ID — never a top-K subset/);
    assert.match(text, /union must cover exactly the snapshot finding IDs/);

    // Non-forgeability: a worker never writes a round document or its own verdict;
    // the server unions the staged partials and runs the identical finalize.
    assert.match(text, /a worker never writes a round document or its own verdict/);
    assert.match(text, /the server unions the staged partials and runs the identical finalize/);
    assert.match(text, /byte-identical to a single-shot write/);

    // Within-finding serialization stays intact; the residual (disjoint findings
    // now replay concurrently by default) is named honestly.
    assert.match(text, /within-finding lock is intact/);
    assert.match(text, /disjoint findings now replay concurrently/);
    assert.match(text, /no-ungoverned-concurrent-live-request guarantee holds per finding/);

    // LEAN fallback is reachable, single-worker whole-round, serialized across
    // findings via the attempt_pack lease, written in one shot with a results array.
    assert.match(text, /LEAN fallback \(single-worker whole round\)/);
    assert.match(text, /serialized across findings/);
    assert.match(text, /pack default `attempt_pack`/);
    assert.match(text, /results.*array.*finalize|carrying the full `results` array/);
    assert.match(text, /non-idempotent or share a fixture/);

    // Host-agnostic spawn wording in the fan-out stanza itself.
    assert.match(text, /host's asynchronous\/background worker mechanism/);

    // Extract just the per-finding fan-out + LEAN fallback region. The
    // host-rendered Claude skill legitimately uses host-coupled spawn syntax
    // (Agent(... run_in_background ...)) in OTHER stanzas, so the host-agnostic
    // invariant is asserted against THIS stanza's prose only.
    const stanzaStart = text.indexOf("Per-finding round fan-out (default dispatch)");
    assert.ok(stanzaStart >= 0, `${surface}: per-finding fan-out stanza not found`);
    const afterStanza = text.indexOf("\n{{SPAWN_BRUTALIST_VERIFIER}}", stanzaStart);
    const brutalistMarker = text.indexOf("brutalist and balanced verifier", stanzaStart);
    const stanzaEnd = afterStanza >= 0
      ? afterStanza
      : (brutalistMarker >= 0 ? brutalistMarker : stanzaStart + 4000);
    const stanza = text.slice(stanzaStart, stanzaEnd);
    assert.doesNotMatch(stanza, /run_in_background/);
    assert.doesNotMatch(stanza, /CLAUDE_PROJECT_DIR/);
    assert.doesNotMatch(stanza, /\bTask\(/);

    // No phase-narrative / arc node-id tokens leaked into the stanza prose.
    assert.doesNotMatch(stanza, /UF-D1|UF-D1-verify|\bUF-\d|\bOW-\d/);
  });
}
