"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  EVIDENCE_REFERENCE_KIND_VALUES,
  OFFENSIVE_OUTCOME_VALUES,
  SAFE_ORACLE_KINDS,
  appendCandidateClaim,
  canonicalizeExploitTarget,
  evidenceReferenceLookupKey,
  normalizeCandidateClaim,
  normalizeEvidenceReferenceShape,
  readCandidateClaims,
} = require("../mcp/lib/claims.js");
const {
  buildClaimFreeze,
  projectCodeBoundObservedRefs,
  projectExploitRunObservedRef,
  assertCompletenessAgainstFreeze,
} = require("../mcp/lib/claim-freeze.js");
const {
  claimsJsonlPath,
  isAuditGradedPath,
  offensiveRunsDir,
  offensiveRunsJsonlPath,
  repoCommandRunsJsonlPath,
} = require("../mcp/lib/paths.js");
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
    tool_id: "bob_http_confirm_reflected_canary",
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
