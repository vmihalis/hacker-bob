"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  appendCandidateClaim,
  canonicalizeExploitTarget,
} = require("../mcp/lib/claims.js");
const {
  buildClaimFreeze,
  projectCodeBoundObservedRefs,
  projectExploitRunObservedRef,
  assertCompletenessAgainstFreeze,
  readCurrentClaimFreeze,
} = require("../mcp/lib/claim-freeze.js");
const {
  claimFreezePath,
  handoffSigningKeyPath,
  isAuditGradedPath,
  offensiveRunsDir,
  offensiveRunsJsonlPath,
  sessionDir,
  sessionsRoot,
} = require("../mcp/lib/paths.js");
const {
  evaluateLifecycleTransition,
} = require("../mcp/lib/lifecycle-gates.js");
const {
  advanceSession,
  initSession,
} = require("../mcp/lib/session-state.js");
const {
  readSessionNucleus,
} = require("../mcp/lib/governance-store.js");
const {
  ensureHandoffSigningKey,
} = require("../mcp/lib/handoff-signing-key.js");
const {
  signOffensiveRunRow,
} = require("../mcp/lib/offensive-row-mac.js");

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-offensive-proof-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function hex(char) {
  return char.repeat(64);
}

// The cited target host must be in scope for the claim domain (Codex P1 binding),
// so the ref/row target is derived from the domain unless a test overrides it.
function exploitRef(domain = "example.com", overrides = {}) {
  return {
    kind: "exploit_run",
    run_id: "run-exploit-1",
    tool_id: "bob_http_idor_confirm",
    target: `https://${domain}/search?q=BOB_CANARY_1`,
    offensive_outcome: "exploited_safely",
    command_hash: hex("a"),
    exit_code: 0,
    stdout_hash: hex("b"),
    stderr_hash: hex("c"),
    ...overrides,
  };
}

// issue #111: an exploited_safely claim must carry exactly one surface_id that
// matches its backed row's surface_id. Default both helpers to the same value so
// the positive record path passes; binding tests override one side.
const DEFAULT_SURFACE_ID = "surface-proof-default";

function exploitedClaim(domain, overrides = {}) {
  return {
    target_domain: domain,
    title: "Reflected canary was exploited safely",
    summary: "A benign canary was reflected in the target response.",
    severity: "low",
    exploit_outcome: {
      outcome: "exploited_safely",
      safe_oracle: { kind: "reflected_canary" },
    },
    evidence_refs: [exploitRef(domain)],
    surface_ids: [DEFAULT_SURFACE_ID],
    ...overrides,
  };
}

function buildOffensiveRunRow(domain, overrides = {}) {
  const ref = exploitRef(domain);
  const row = {
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
    demonstrated_severity: "low",
    // issue #111: surface the safe exploit ran against (MAC-covered); must equal
    // the citing claim's single surface_id.
    surface_id: DEFAULT_SURFACE_ID,
    ...overrides,
  };
  // The runner records the same canonical (redacted) target the claim ref carries
  // so the row and ref stay byte-identical for the proof binding.
  row.target = canonicalizeExploitTarget(row.target);
  return row;
}

function writeOffensiveRunRow(domain, row) {
  fs.mkdirSync(path.dirname(offensiveRunsJsonlPath(domain)), { recursive: true });
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
  return row;
}

function appendOffensiveRunRow(domain, overrides = {}) {
  const row = buildOffensiveRunRow(domain, overrides);
  signOffensiveRunRow(row, ensureHandoffSigningKey(domain));
  return writeOffensiveRunRow(domain, row);
}

function advance(domain, toState) {
  return JSON.parse(advanceSession({ target_domain: domain, to_state: toState }));
}

function evaluateFreezeToVerify(domain) {
  return evaluateLifecycleTransition({
    target_domain: domain,
    from_state: "CLAIM_FREEZE",
    to_state: "VERIFY",
    nucleus: readSessionNucleus(domain),
  });
}

function captureThrow(fn) {
  let captured = null;
  try {
    fn();
  } catch (error) {
    captured = error;
  }
  assert.ok(captured, "expected function to throw");
  return captured;
}

test("#freeze-verify-gate: non-exploit frozen claims do not require a signing key", () => withTempHome(() => {
  const domain = "freeze-verify-no-brick.example";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  advance(domain, "OPEN_FRONTIER");
  appendCandidateClaim({
    target_domain: domain,
    title: "Plain reflected behavior",
    summary: "A non-offensive finding fixture.",
    severity: "low",
    evidence_refs: [{
      kind: "finding",
      finding_id: "F-plain",
      content_hash: hex("0"),
    }],
  });
  advance(domain, "CLAIM_FREEZE");
  buildClaimFreeze(domain, { write: true, now: new Date("2026-06-16T00:00:00.000Z") });

  assert.equal(fs.existsSync(handoffSigningKeyPath(domain)), false);
  assert.deepEqual(evaluateFreezeToVerify(domain).blockers, []);

  const envelope = advance(domain, "VERIFY");
  assert.equal(envelope.to_state, "VERIFY");
  assert.equal(envelope.advanced, true);
}));

test("#freeze-verify-gate: vanished offensive row blocks CLAIM_FREEZE -> VERIFY", () => withTempHome(() => {
  const domain = "freeze-verify-missing-row.example";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  advance(domain, "OPEN_FRONTIER");
  appendOffensiveRunRow(domain);
  appendCandidateClaim(exploitedClaim(domain));
  advance(domain, "CLAIM_FREEZE");
  buildClaimFreeze(domain, { write: true, now: new Date("2026-06-16T00:00:00.000Z") });

  fs.rmSync(offensiveRunsJsonlPath(domain), { force: true });
  const blockers = evaluateFreezeToVerify(domain).blockers;
  assert.equal(blockers.length, 1);
  assert.equal(blockers[0].code, "exploited_claim_proof_unbacked_at_freeze");
  assert.equal(blockers[0].underlying_code, "exploit_proof_unbacked_exploit_run_evidence");

  const error = captureThrow(() => advanceSession({ target_domain: domain, to_state: "VERIFY" }));
  assert.equal(error.code, "STATE_CONFLICT");
  assert.equal(error.details && error.details.code, "exploited_claim_proof_unbacked_at_freeze");
}));

test("#freeze-verify-gate: backed exploited claim advances without single-use false positive", () => withTempHome(() => {
  const domain = "freeze-verify-backed.example";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  advance(domain, "OPEN_FRONTIER");
  appendOffensiveRunRow(domain);
  appendCandidateClaim(exploitedClaim(domain));
  advance(domain, "CLAIM_FREEZE");
  buildClaimFreeze(domain, { write: true, now: new Date("2026-06-16T00:00:00.000Z") });

  assert.deepEqual(evaluateFreezeToVerify(domain).blockers, []);
  const envelope = advance(domain, "VERIFY");
  assert.equal(envelope.to_state, "VERIFY");
  assert.equal(envelope.advanced, true);
}));

test("#freeze-verify-gate: a tampered freeze with a ref-less exploited_safely claim is blocked (fail-closed)", () => withTempHome(() => {
  const domain = "freeze-verify-tampered-refless.example";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  advance(domain, "OPEN_FRONTIER");
  appendCandidateClaim({
    target_domain: domain,
    title: "Plain reflected behavior",
    summary: "A non-offensive finding fixture.",
    severity: "low",
    evidence_refs: [{ kind: "finding", finding_id: "F-plain", content_hash: hex("0") }],
  });
  advance(domain, "CLAIM_FREEZE");
  buildClaimFreeze(domain, { write: true, now: new Date("2026-06-16T00:00:00.000Z") });

  // Simulate claim-freeze.json tampering: inject an exploited_safely claim that carries NO
  // exploit_run ref. The record gate would have rejected it, so only direct tampering produces it;
  // the gate must NOT silently skip it (fail-closed), it must block.
  const freeze = readCurrentClaimFreeze(domain);
  freeze.claims.push({
    claim_id: "C-tampered",
    target_domain: domain,
    severity: "critical",
    exploit_outcome: { outcome: "exploited_safely", safe_oracle: { kind: "differential_response" } },
    evidence_refs: [{ kind: "finding", finding_id: "F-x", content_hash: hex("1") }],
  });
  fs.writeFileSync(claimFreezePath(domain), JSON.stringify(freeze));

  const blockers = evaluateFreezeToVerify(domain).blockers;
  assert.equal(blockers.length, 1);
  assert.equal(blockers[0].code, "exploited_claim_proof_unbacked_at_freeze");
  assert.equal(blockers[0].underlying_code, "exploit_proof_missing_exploit_run_evidence");
  assert.equal(blockers[0].claim_id, "C-tampered");
}));

test("#freeze-verify-gate: a freeze whose claims[] is not an array is blocked (fail-closed)", () => withTempHome(() => {
  const domain = "freeze-verify-malformed-shape.example";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  advance(domain, "OPEN_FRONTIER");
  advance(domain, "CLAIM_FREEZE");
  buildClaimFreeze(domain, { write: true, now: new Date("2026-06-16T00:00:00.000Z") });

  const freeze = readCurrentClaimFreeze(domain);
  freeze.claims = "not-an-array";
  fs.writeFileSync(claimFreezePath(domain), JSON.stringify(freeze));

  const blockers = evaluateFreezeToVerify(domain).blockers;
  assert.equal(blockers.length, 1);
  assert.equal(blockers[0].code, "claim_freeze_invalid_shape");
}));

test("#freeze-completeness: projectExploitRunObservedRef re-hashes the on-disk capture file", () => withTempHome(() => {
  const domain = "exploit-proj-match.example";
  const runId = "run-proj-match-1";
  const content = "BOB_SYNTH_CANARY_match synthetic cross-tenant body\n";
  fs.mkdirSync(offensiveRunsDir(domain), { recursive: true });
  fs.writeFileSync(path.join(offensiveRunsDir(domain), `${runId}.stdout`), content);

  const frozenRef = { kind: "exploit_run", run_id: runId, stdout_hash: sha256Hex(content) };
  const obs = projectExploitRunObservedRef(domain, frozenRef);
  assert.ok(obs, "must project an observed ref when the capture file exists");
  assert.equal(obs.kind, "exploit_run");
  assert.equal(obs.stdout_hash, sha256Hex(content), "observed hash is the file's recomputed sha256");
}));

test("#freeze-completeness: projectExploitRunObservedRef returns null when the capture file is missing", () => withTempHome(() => {
  const domain = "exploit-proj-missing.example";
  const frozenRef = { kind: "exploit_run", run_id: "run-absent", stdout_hash: sha256Hex("x") };
  assert.equal(projectExploitRunObservedRef(domain, frozenRef), null);
}));

test("#freeze-completeness: projectExploitRunObservedRef projects the TAMPERED sha when the file changed", () => withTempHome(() => {
  const domain = "exploit-proj-mismatch.example";
  const runId = "run-proj-mismatch-1";
  const original = "ORIGINAL synthetic body\n";
  const tampered = "TAMPERED synthetic body\n";
  fs.mkdirSync(offensiveRunsDir(domain), { recursive: true });
  fs.writeFileSync(path.join(offensiveRunsDir(domain), `${runId}.stdout`), tampered);

  const frozenRef = { kind: "exploit_run", run_id: runId, stdout_hash: sha256Hex(original) };
  const obs = projectExploitRunObservedRef(domain, frozenRef);
  assert.ok(obs);
  assert.equal(obs.stdout_hash, sha256Hex(tampered), "projects the actual on-disk sha (a mismatch the gate will catch)");
  assert.notEqual(obs.stdout_hash, frozenRef.stdout_hash);
}));

test("#freeze-completeness: projectExploitRunObservedRef ignores non-exploit_run refs", () => withTempHome(() => {
  assert.equal(
    projectExploitRunObservedRef("k.example", { kind: "repo_command_run", run_id: "x", stdout_hash: "y" }),
    null,
  );
  assert.equal(projectExploitRunObservedRef("k.example", { kind: "exploit_run" }), null, "no run_id → null");
}));

test("#freeze-completeness: offensive-runs capture dir is audit-graded", () => withTempHome(() => {
  const domain = "exploit-audit.example";
  const capture = path.join(offensiveRunsDir(domain), "run-x.stdout");
  assert.equal(isAuditGradedPath(capture, domain), true, "offensive-runs/<run_id>.stdout must be audit-graded");
}));

test("#freeze-completeness: a recorded exploited_safely claim freezes and projects its exploit_run capture", () => withTempHome(() => {
  const domain = "exploit-freeze-e2e.example";
  const runId = "run-e2e-1";
  const captureContent = "BOB_SYNTH_CANARY_e2e synthetic cross-tenant body\n";
  const stdoutHash = sha256Hex(captureContent);

  // 1. Seed a signed offensive-runs row (run_id + stdout_hash overridden so the
  //    capture file will hash to the same value). appendOffensiveRunRow signs + writes it.
  appendOffensiveRunRow(domain, { run_id: runId, stdout_hash: stdoutHash });

  // 2. Write the capture file at offensive-runs/<run_id>.stdout (sha256 == stdoutHash).
  fs.mkdirSync(offensiveRunsDir(domain), { recursive: true });
  fs.writeFileSync(path.join(offensiveRunsDir(domain), `${runId}.stdout`), captureContent);

  // 3. Record the exploited_safely claim citing a ref with the SAME run_id + stdout_hash.
  //    (exploitedClaim defaults the surface to DEFAULT_SURFACE_ID, which the seeded row also
  //    carries, so the record-time proof gate passes.)
  appendCandidateClaim(exploitedClaim(domain, {
    evidence_refs: [exploitRef(domain, { run_id: runId, stdout_hash: stdoutHash })],
  }));

  // 4. Freeze.
  const freeze = buildClaimFreeze(domain, { write: true, now: new Date("2026-06-16T00:00:00.000Z") });
  assert.equal(freeze.claim_count, 1);

  // 5. Project from disk — the exploit_run observed ref MUST now be included (this is the bug fix).
  const projected = projectCodeBoundObservedRefs(domain, freeze);
  const exploitObs = projected.find((r) => r.kind === "exploit_run");
  assert.ok(exploitObs, "projectCodeBoundObservedRefs must now include the exploit_run observed ref");
  assert.equal(exploitObs.stdout_hash, stdoutHash, "projected hash matches the frozen ref → completeness will pass");

  // 6. The completeness gate passes when supplied the projected observed refs.
  const verdict = assertCompletenessAgainstFreeze(freeze, projected);
  assert.equal(verdict.complete, true, `expected complete; got ${JSON.stringify(verdict)}`);
}));

// Negative end-to-end: the WHOLE point of exploit_run being a content-bound
// kind is tamper-evidence. If the on-disk capture is altered after freeze, the
// re-projected sha no longer matches the frozen stdout_hash and the completeness
// gate MUST report complete:false with an exploit_run mismatch — blocking the
// lifecycle. This exercises the hash-differs branch (claim-freeze.js:287) through
// the real record→freeze→project path.
test("#freeze-completeness: a TAMPERED exploit_run capture drives completeness to false (not silently complete)", () => withTempHome(() => {
  const domain = "exploit-freeze-tamper.example";
  const runId = "run-tamper-1";
  const originalContent = "BOB_SYNTH_CANARY_orig synthetic cross-tenant body\n";
  const stdoutHash = sha256Hex(originalContent);

  // Seed a signed row + claim whose frozen stdout_hash == sha256(originalContent).
  appendOffensiveRunRow(domain, { run_id: runId, stdout_hash: stdoutHash });
  appendCandidateClaim(exploitedClaim(domain, {
    evidence_refs: [exploitRef(domain, { run_id: runId, stdout_hash: stdoutHash })],
  }));

  // Write a TAMPERED capture file at offensive-runs/<run_id>.stdout (sha != frozen stdout_hash).
  fs.mkdirSync(offensiveRunsDir(domain), { recursive: true });
  fs.writeFileSync(
    path.join(offensiveRunsDir(domain), `${runId}.stdout`),
    "TAMPERED synthetic body — altered after freeze\n",
  );

  const freeze = buildClaimFreeze(domain, { write: true, now: new Date("2026-06-16T00:00:00.000Z") });
  const projected = projectCodeBoundObservedRefs(domain, freeze);
  // The projection still emits an exploit_run observed ref (the file exists), but
  // carrying the TAMPERED sha — so the gate must flag a mismatch, not satisfy.
  const verdict = assertCompletenessAgainstFreeze(freeze, projected);
  assert.equal(verdict.complete, false, "a tampered capture must NOT satisfy completeness");
  assert.ok(
    verdict.mismatched.some((m) => m.kind === "exploit_run"),
    `the gate must report the exploit_run ref as mismatched; got ${JSON.stringify(verdict.mismatched)}`,
  );
}));

// Focused unit coverage for the exploit_run-specific anti-silent-satisfy guard
// (claim-freeze.js:277): an observed exploit_run ref that is present by key but
// omits its stdout_hash must count as a mismatch, NOT a key-presence satisfy.
// Without this guard a verifier could satisfy the freeze without ever proving the
// capture's content identity.
test("#freeze-completeness: an exploit_run observed ref missing its stdout_hash is a mismatch, never a silent satisfy", () => withTempHome(() => {
  const domain = "exploit-null-hash.example";
  const runId = "run-nullhash-1";
  const stdoutHash = sha256Hex("BOB_SYNTH_CANARY_nullhash body\n");

  appendOffensiveRunRow(domain, { run_id: runId, stdout_hash: stdoutHash });
  appendCandidateClaim(exploitedClaim(domain, {
    evidence_refs: [exploitRef(domain, { run_id: runId, stdout_hash: stdoutHash })],
  }));
  const freeze = buildClaimFreeze(domain, { write: true, now: new Date("2026-06-16T00:00:00.000Z") });

  // Supply an observed exploit_run ref that matches the frozen key (run_id) but
  // carries no stdout_hash — the gate must NOT treat key-presence as satisfaction.
  const observedWithoutHash = [{ kind: "exploit_run", run_id: runId }];
  const verdict = assertCompletenessAgainstFreeze(freeze, observedWithoutHash);
  assert.equal(verdict.complete, false, "key-present-but-hash-null must not satisfy the freeze");
  assert.ok(
    verdict.mismatched.some((m) => m.kind === "exploit_run" && m.observed_hash === null),
    `the null-observed-hash guard must flag a mismatch; got ${JSON.stringify(verdict.mismatched)}`,
  );
}));

// Defense-in-depth (issue #114): a crafted run_id must never let the projection
// read a file OUTSIDE offensive-runs/. Plant a real file one level up that a
// "../" run_id would resolve to; without the containment guard the projection
// would read it and return its sha (an arbitrary <path>.stdout read-oracle). With
// the guard the resolved path escapes offensiveRunsDir → null.
test("#freeze-completeness: projectExploitRunObservedRef refuses a traversal run_id even when the target file exists", () => withTempHome(() => {
  const domain = "exploit-traversal.example";
  // offensiveRunsDir(domain)/../OUTSIDE.stdout — a real file just outside the capture dir.
  const outsidePath = path.join(offensiveRunsDir(domain), "..", "OUTSIDE.stdout");
  fs.mkdirSync(path.dirname(outsidePath), { recursive: true });
  fs.writeFileSync(outsidePath, "secret body outside the capture dir\n");

  const obs = projectExploitRunObservedRef(domain, {
    kind: "exploit_run",
    run_id: "../OUTSIDE",
    stdout_hash: hex("a"),
  });
  assert.equal(obs, null, "a traversal run_id must NOT read a file outside offensive-runs/, even if it exists");
}));

// Defense-in-depth (issue #114 / Codex P2): a run_id that NORMALIZES back inside
// the dir (e.g. "subdir/../victim") would otherwise resolve to victim.stdout and
// pass the dirname guard, aliasing a DIFFERENT capture. Reject raw separators →
// null, fail-closed.
test("#freeze-completeness: projectExploitRunObservedRef refuses a normalizing run_id that aliases another capture", () => withTempHome(() => {
  const domain = "exploit-alias.example";
  fs.mkdirSync(offensiveRunsDir(domain), { recursive: true });
  // A real capture for run "victim" that the aliasing run_id would resolve to.
  fs.writeFileSync(path.join(offensiveRunsDir(domain), "victim.stdout"), "victim capture body\n");

  const obs = projectExploitRunObservedRef(domain, {
    kind: "exploit_run",
    run_id: "subdir/../victim",
    stdout_hash: hex("a"),
  });
  assert.equal(obs, null, "a run_id with separators/normalization must project null, not alias victim's capture");
}));

// Defense-in-depth (issue #114 / Codex P1): the lexical containment guard does
// not stop a SYMLINKED capture leaf — bare sha256File would follow the link and
// hash an attacker-chosen inode (a content read-oracle). The secure read must
// reject a symlinked leaf (O_NOFOLLOW / lstat) → null.
test("#freeze-completeness: projectExploitRunObservedRef refuses a SYMLINKED capture leaf (no hash oracle)", () => withTempHome(() => {
  const domain = "exploit-symlink-leaf.example";
  const runId = "run-symlink-leaf-1";
  fs.mkdirSync(offensiveRunsDir(domain), { recursive: true });
  // A real secret file outside the capture dir.
  const secretPath = path.join(offensiveRunsDir(domain), "..", "SECRET.txt");
  fs.writeFileSync(secretPath, "out-of-dir secret body the oracle must not hash\n");
  // Plant a symlink at offensive-runs/<run_id>.stdout -> the secret file.
  fs.symlinkSync(secretPath, path.join(offensiveRunsDir(domain), `${runId}.stdout`));

  const obs = projectExploitRunObservedRef(domain, {
    kind: "exploit_run",
    run_id: runId,
    stdout_hash: hex("a"),
  });
  assert.equal(obs, null, "a symlinked capture leaf must project null, never hash the link target");
}));

// Defense-in-depth (issue #114): a symlinked offensive-runs/ DIRECTORY also
// bypasses an O_NOFOLLOW-on-the-leaf-only check. The realpath parent check must
// reject a capture dir that does not resolve to <session>/offensive-runs → null.
test("#freeze-completeness: projectExploitRunObservedRef refuses a SYMLINKED capture directory", () => withTempHome(() => {
  const domain = "exploit-symlink-dir.example";
  const runId = "run-symlink-dir-1";
  // Build a real attacker dir holding a real <run_id>.stdout, then point the
  // session's offensive-runs/ at it via a directory symlink.
  const sessDir = sessionDir(domain);
  fs.mkdirSync(sessDir, { recursive: true });
  const evilDir = path.join(sessDir, "evil-capture-store");
  fs.mkdirSync(evilDir, { recursive: true });
  fs.writeFileSync(path.join(evilDir, `${runId}.stdout`), "planted body via symlinked dir\n");
  fs.symlinkSync(evilDir, offensiveRunsDir(domain));

  const obs = projectExploitRunObservedRef(domain, {
    kind: "exploit_run",
    run_id: runId,
    stdout_hash: hex("a"),
  });
  assert.equal(obs, null, "a symlinked offensive-runs/ dir must project null, never hash through the link");
}));

// Defense-in-depth (issue #114 / Codex high): a symlinked SESSION directory must
// also be rejected. The secure read must anchor the expected capture dir to the
// real sessions root + safe domain (like resolveOffensiveRunsFilePathSecure),
// NOT to realpath(sessionDir) — which would resolve the session symlink and
// silently accept attacker-substituted capture bytes.
test("#freeze-completeness: projectExploitRunObservedRef refuses a SYMLINKED session directory", () => withTempHome(() => {
  const domain = "exploit-symlink-sess.example";
  const runId = "run-symlink-sess-1";
  // A real attacker tree OUTSIDE the sessions root, holding a real capture leaf.
  const attacker = path.join(process.env.HOME, "attacker-evil");
  fs.mkdirSync(path.join(attacker, "offensive-runs"), { recursive: true });
  fs.writeFileSync(path.join(attacker, "offensive-runs", `${runId}.stdout`), "planted body via session symlink\n");
  // Point the whole session dir at the attacker tree via a symlink.
  fs.mkdirSync(sessionsRoot(), { recursive: true });
  fs.symlinkSync(attacker, sessionDir(domain));

  const obs = projectExploitRunObservedRef(domain, {
    kind: "exploit_run",
    run_id: runId,
    stdout_hash: hex("a"),
  });
  assert.equal(obs, null, "a symlinked session dir must project null, never hash attacker-substituted bytes");
}));
