"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// OSS native-code reproduction verifier — the execution-graded, differential gate
// that makes a memory-safety finding non-fabricatable. Mirrors composition-live-
// verifier.js (the SC1 confirm-half): producer-independence is enforced at the
// INTEGRITY boundary, not by the producer's good behavior.
//
// THE FORGERY IT DEFEATS: bob_repo_docker_run runs an evaluator-CHOSEN free-form
// command and captures whatever it printed. A banner-scanning gate is therefore
// forgeable — `printf '==1==ERROR: AddressSanitizer: heap-buffer-overflow ...'`
// produces a real, hash-backed row whose output "contains a crash". A single run
// proves nothing.
//
// THE DEFENSE: a DIFFERENTIAL. The verifier re-runs the SAME command in TWO fresh
// containers it controls — the vulnerable tree, and the upstream-fix tree (via the
// O-P3 differential checkout) — and parses the bytes IT captured (sanitizer-report.js,
// never a self-reported field). A genuine memory-safety bug CRASHES on the vuln tree
// and is QUIET on the fix tree (the flip). A printf'd banner fires identically on
// BOTH trees -> no flip -> refuted. A crash that fires on both (over-broad PoC, env
// crash) -> no flip -> refuted. Only a real, attributable, flipping crash mints a
// verified_pass, written ONLY to the audit-graded (agent-Write-blocked)
// repro-verified.jsonl that the O-P4 claim gate grades on.

const {
  reproVerifiedJsonlPath,
  repoCommandRunsJsonlPath,
  repoRunsDir,
  assertSafeDomain,
} = require("./paths.js");
const {
  parseSanitizerReport,
} = require("./sanitizer-report.js");
const {
  appendJsonlLine,
  withSessionLock,
} = require("./storage.js");
const {
  hashCanonicalJson,
} = require("./verification-contracts.js");
// Cycle B: verify the keyed repo-command-run row_mac at the read-time re-resolution,
// AFTER the existing dry_run/timed_out checks and BEFORE the capture re-hash. A present-
// but-invalid MAC throws inside resolveRepoRunRow → reverifyReproRecord catch → ok:false;
// an old unsigned row is accepted-with-warning (still re-resolved + capture-re-checked).
// Reuses Cycle A's verify path; does NOT close F3 (key still agent-readable; F2 → F3).
const {
  assertRowMacOrLegacy,
  REPO_COMMAND_RUN_MAC_CONTEXT,
} = require("./offensive-row-mac.js");
const {
  resolveRowVerifierSafely,
} = require("./handoff-signing-key.js");

const REPRO_VERIFIED_VERSION = 1;
const REPRO_VERIFIED_MAX_RECORDS = 2000;
const DEFAULT_CONTROL_KIND = "upstream_fix";

const RESULT_VERIFIED_PASS = "verified_pass";
const RESULT_REFUTED = "refuted";
const RESULT_INCONCLUSIVE = "inconclusive";

// A repoDockerRunFn run result is degraded (run did not produce trustworthy bytes)
// when there is no concrete exit code or the runner reported an error / timeout.
function runDegradation(run) {
  if (run == null || typeof run !== "object") return "no_result";
  if (typeof run.error === "string" && run.error) return "run_error";
  if (run.timed_out === true) return "timed_out";
  if (typeof run.exit_code !== "number" && run.exit_code !== null) return "no_exit_code";
  return null;
}

function verdictFromRun(run) {
  // Parse the bytes the verifier's OWN re-run captured. stdout_text/stderr_text are
  // supplied by the caller (A4 reads repo-runs/<run_id>.{stdout,stderr}); a fake
  // fetcher supplies them directly in tests.
  return parseSanitizerReport(run && run.stderr_text, run && run.stdout_text);
}

// Shared differential adjudication for both the repro gate and the OE4 oracle
// differential. Given the verifier's OWN two re-runs — the tree on which the
// invariant must FAIL (vuln) and the tree on which it must HOLD (control/fix) —
// derive the verdict. This is the single sound differential rule both gates use:
// the invariant FAILS on the vuln tree (an attributable memory-safety crash with
// a /src frame) and HOLDS on the control tree (clean, zero-exit). Anything that
// fires identically on both trees (a printf-forged banner, an over-broad PoC, an
// env crash) shows NO FLIP and is refuted; a degraded run or a false-quiet control
// is inconclusive. controlLabel only changes the human-facing reason text so the
// repro gate ("upstream-fix tree") and the oracle gate ("oracle-fix tree") read
// correctly; the rule is byte-identical.
function adjudicateDifferential({ vulnRun, controlRun, controlLabel = "upstream-fix" }) {
  const vulnDegraded = runDegradation(vulnRun);
  const controlDegraded = runDegradation(controlRun);
  const vulnVerdict = verdictFromRun(vulnRun);
  const controlVerdict = verdictFromRun(controlRun);

  let result;
  let reason;
  if (vulnDegraded || controlDegraded) {
    result = RESULT_INCONCLUSIVE;
    reason = `degraded re-execution (vuln:${vulnDegraded || "ok"}, control:${controlDegraded || "ok"})`;
  } else if (!vulnVerdict.crashed) {
    // The claimed PoC does not reproduce on independent re-execution.
    result = RESULT_REFUTED;
    reason = "vuln-tree re-execution did not crash (claimed reproduction not reproduced)";
  } else if (!vulnVerdict.src_frame) {
    // A crash with no /src-resolved root-cause frame is not attributable to the repo.
    result = RESULT_REFUTED;
    reason = "vuln-tree crash has no /src-resolved root-cause frame (unattributable)";
  } else if (controlVerdict.crashed) {
    // No flip: the same command crashes the FIXED tree too. A printf-forged banner
    // fires identically on both trees and dies exactly here; so does an env/always-crash.
    result = RESULT_REFUTED;
    reason = `no differential flip: the command also crashes the ${controlLabel} tree (forged/over-broad/non-attributable)`;
  } else if (controlRun.exit_code !== 0) {
    // The fix tree neither crashed NOR completed cleanly (non-zero exit, no crash
    // banner). The most likely cause is that the command FAILED TO BUILD/RUN the
    // harness on the fixed source (e.g. the fix changed an API the harness calls),
    // so the absence of a crash proves nothing — the bug may simply never have been
    // exercised. Treat as inconclusive rather than minting a verified_pass off a
    // false-quiet control. (The reproduction idiom is: crash -> non-zero + banner;
    // clean -> exit 0. A clean control MUST be a zero-exit completion.)
    result = RESULT_INCONCLUSIVE;
    reason = `control (${controlLabel}) tree did not crash but exited ${controlRun.exit_code} with no sanitizer banner — cannot distinguish a genuine fix from a failed build/run; differential inconclusive`;
  } else {
    // Real, attributable, flipping crash: vuln crashes with a /src frame; fix builds,
    // runs the harness, and is quiet (exit 0).
    result = RESULT_VERIFIED_PASS;
    reason = `differential reproduction: crashes the vulnerable tree, quiet on the ${controlLabel} tree`;
  }
  return { result, reason, vulnVerdict, controlVerdict };
}

// verifyReproReproduction — re-run the PoC command on the vuln + fix trees, derive a
// differential crash verdict, and mint a verified_pass only on a real flip.
//
// input: { target_domain, finding_id, command (argv[]), control_ref (fix commit),
//          control_kind?, image_tag?, allow_network? }
// deps:  { repoDockerRunFn }  async ({command, checkout?, ...}) ->
//          { run_id, exit_code, stdout_text, stderr_text, timed_out?, error? }
async function verifyReproReproduction(input, deps = {}) {
  if (input == null || typeof input !== "object") {
    throw new TypeError("input must be { target_domain, finding_id, command, control_ref }");
  }
  const targetDomain = assertSafeDomain(input.target_domain);
  const findingId = typeof input.finding_id === "string" ? input.finding_id : null;
  if (!findingId) throw new Error("finding_id is required");
  if (!Array.isArray(input.command) || input.command.length === 0) {
    throw new Error("command must be a non-empty argv array");
  }
  if (typeof input.control_ref !== "string" || !input.control_ref) {
    throw new Error("control_ref (the upstream-fix commit) is required for the differential");
  }
  if (typeof deps.repoDockerRunFn !== "function") {
    throw new TypeError("deps.repoDockerRunFn must be a function");
  }
  const controlKind = typeof input.control_kind === "string" && input.control_kind
    ? input.control_kind : DEFAULT_CONTROL_KIND;
  const baseArgs = {
    target_domain: targetDomain,
    command: input.command,
    dry_run: false,
    allow_network: input.allow_network === true,
  };
  if (typeof input.image_tag === "string" && input.image_tag) baseArgs.image_tag = input.image_tag;

  // Vuln tree (no checkout) + control/fix tree (differential checkout). The verifier
  // owns both executions; the evaluator cannot pre-bake the outputs.
  const vulnRun = await deps.repoDockerRunFn({ ...baseArgs });
  const controlRun = await deps.repoDockerRunFn({ ...baseArgs, checkout: { ref: input.control_ref, kind: controlKind } });

  const { result, reason, vulnVerdict, controlVerdict } = adjudicateDifferential({
    vulnRun, controlRun, controlLabel: "upstream-fix",
  });

  return mintDifferentialRecord({
    targetDomain, findingId, command: input.command, result, reason,
    vulnRun, controlRun, vulnVerdict, controlVerdict,
    extra: { control_ref: input.control_ref, control_kind: controlKind },
  });
}

// Mint the audit-graded record on the SAME ledger with the SAME hash-binding both
// gates share: a stable body is hashed (command_hash over the argv, results_hash
// over the body) and appended under the session lock to the MCP-write-only,
// agent-Write-blocked repro-verified.jsonl. The O-P4 claim gate grades off this
// ledger and cannot tell — nor need it — which mode minted a verified_pass; both
// are sound differentials. extra carries the mode-specific provenance fields.
function mintDifferentialRecord({
  targetDomain, findingId, command, result, reason,
  vulnRun, controlRun, vulnVerdict, controlVerdict, extra = {},
}) {
  const body = {
    version: REPRO_VERIFIED_VERSION,
    target_domain: targetDomain,
    ts: new Date().toISOString(),
    finding_id: findingId,
    result,
    reason,
    command_hash: hashCanonicalJson(command),
    ...extra,
    vuln_run_id: (vulnRun && vulnRun.run_id) || null,
    control_run_id: (controlRun && controlRun.run_id) || null,
    crash_class: vulnVerdict.crash_class,
    sanitizer: vulnVerdict.sanitizer,
    src_frame: vulnVerdict.src_frame,
    vuln_crashed: vulnVerdict.crashed,
    control_crashed: controlVerdict.crashed,
    control_exit_code: typeof controlRun.exit_code === "number" ? controlRun.exit_code : null,
  };
  const record = { ...body, results_hash: hashCanonicalJson(body) };

  withSessionLock(targetDomain, () => {
    appendJsonlLine(reproVerifiedJsonlPath(targetDomain), record, {
      maxRecords: REPRO_VERIFIED_MAX_RECORDS,
    });
  });

  return {
    target_domain: targetDomain,
    finding_id: findingId,
    result,
    reason,
    command_hash: record.command_hash,
    crash_class: record.crash_class,
    results_hash: record.results_hash,
  };
}

// verifyOracleDifferential (OE4) — the SOUND oracle differential. Where
// verifyReproReproduction re-runs the claimed PoC on the vuln tree (no checkout)
// vs. the upstream-fix ref, this re-runs the SAME command across two EXPLICITLY
// patched trees so the invariant's flip is observed against a precise pair:
//
//   oracle-vuln = checkout {kind:"self_patch", checkout_patch: vuln_patch}
//                 -> the bug-bearing source -> the command must FAULT with a /src frame.
//   oracle-fix  = checkout {ref: fix_ref, kind:"upstream_fix", checkout_patch: fix_patch}
//                 -> the fixed source -> the command must be CLEAN (exit 0, no banner).
//
// The verdict rule and the ledger/hash-binding are byte-identical to the repro gate
// (adjudicateDifferential + mintDifferentialRecord), so a verified_pass minted here
// is indistinguishable to — and as sound as — the existing gate's: the invariant
// FAILS on the vuln tree and HOLDS on the fix tree. oracle-vuln clean -> refuted;
// both fault or a fix-build-degraded/false-quiet -> inconclusive.
//
// input: { target_domain, finding_id, command (argv[]), vuln_patch (unified diff),
//          fix_ref (fix commit), fix_patch (unified diff), vuln_ref?, vuln_kind?,
//          fix_kind?, image_tag?, allow_network? }
// deps:  { repoDockerRunFn }  (same contract as verifyReproReproduction)
async function verifyOracleDifferential(input, deps = {}) {
  if (input == null || typeof input !== "object") {
    throw new TypeError("input must be { target_domain, finding_id, command, vuln_patch, fix_ref, fix_patch }");
  }
  const targetDomain = assertSafeDomain(input.target_domain);
  const findingId = typeof input.finding_id === "string" ? input.finding_id : null;
  if (!findingId) throw new Error("finding_id is required");
  if (!Array.isArray(input.command) || input.command.length === 0) {
    throw new Error("command must be a non-empty argv array");
  }
  if (typeof input.vuln_patch !== "string" || !input.vuln_patch.trim()) {
    throw new Error("vuln_patch (the unified diff that materializes the vulnerable tree) is required");
  }
  if (typeof input.fix_ref !== "string" || !input.fix_ref) {
    throw new Error("fix_ref (the upstream-fix commit) is required for the oracle differential");
  }
  if (typeof input.fix_patch !== "string" || !input.fix_patch.trim()) {
    throw new Error("fix_patch (the unified diff that materializes the fixed tree) is required");
  }
  if (typeof deps.repoDockerRunFn !== "function") {
    throw new TypeError("deps.repoDockerRunFn must be a function");
  }
  // self_patch applies vuln_patch onto a base ref; default that base to fix_ref so
  // the vuln tree is the precise inverse of the fix tree (apply the bug-bearing diff
  // to the fixed source). An operator may override with vuln_ref/vuln_kind.
  const vulnKind = typeof input.vuln_kind === "string" && input.vuln_kind ? input.vuln_kind : "self_patch";
  const fixKind = typeof input.fix_kind === "string" && input.fix_kind ? input.fix_kind : DEFAULT_CONTROL_KIND;
  const vulnRef = typeof input.vuln_ref === "string" && input.vuln_ref ? input.vuln_ref : input.fix_ref;
  const baseArgs = {
    target_domain: targetDomain,
    command: input.command,
    dry_run: false,
    allow_network: input.allow_network === true,
  };
  if (typeof input.image_tag === "string" && input.image_tag) baseArgs.image_tag = input.image_tag;

  // The verifier owns both executions; the evaluator cannot pre-bake the outputs.
  const vulnRun = await deps.repoDockerRunFn({
    ...baseArgs,
    checkout: { ref: vulnRef, kind: vulnKind },
    checkout_patch: input.vuln_patch,
  });
  const controlRun = await deps.repoDockerRunFn({
    ...baseArgs,
    checkout: { ref: input.fix_ref, kind: fixKind },
    checkout_patch: input.fix_patch,
  });

  const { result, reason, vulnVerdict, controlVerdict } = adjudicateDifferential({
    vulnRun, controlRun, controlLabel: "oracle-fix",
  });

  return mintDifferentialRecord({
    targetDomain, findingId, command: input.command, result, reason,
    vulnRun, controlRun, vulnVerdict, controlVerdict,
    extra: {
      mode: "oracle_differential",
      control_ref: input.fix_ref,
      control_kind: fixKind,
      vuln_ref: vulnRef,
      vuln_kind: vulnKind,
      vuln_patch_hash: hashCanonicalJson(input.vuln_patch),
      fix_patch_hash: hashCanonicalJson(input.fix_patch),
    },
  });
}

// Read the content-hashed repo-command-runs.jsonl rows once (the same parse evidence.js
// readRepoCommandRunRows uses): a missing file or a malformed line throws so the caller
// fails closed rather than silently admitting a verdict whose source ledger is gone.
function readRepoCommandRunRows(domain) {
  const filePath = repoCommandRunsJsonlPath(domain);
  const raw = fs.readFileSync(filePath, "utf8");
  const rows = [];
  let lineNumber = 0;
  for (const line of raw.split(/\r?\n/)) {
    lineNumber += 1;
    const trimmed = line.trim();
    if (!trimmed) continue;
    const parsed = JSON.parse(trimmed);
    if (parsed == null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error(`repo-command-runs.jsonl row ${lineNumber} is not an object`);
    }
    rows.push(parsed);
  }
  return rows;
}

// Re-resolve a single repo-command-runs row by run_id (mirror evidence.js
// readRepoCommandRunRow): missing → throw; ambiguous content-divergent duplicates →
// throw. A dry-run / timed-out row is not a real execution.
function resolveRepoRunRow(rows, runId, verifier = null) {
  if (typeof runId !== "string" || !runId) throw new Error("run_id must be a non-empty string");
  const matching = rows.filter((row) => row && row.run_id === runId);
  if (matching.length === 0) throw new Error(`run_id ${runId} does not resolve to a repo-command-runs row`);
  if (matching.length > 1) {
    const hashes = new Set(matching.map((row) => hashCanonicalJson(row)));
    if (hashes.size > 1) throw new Error(`run_id ${runId} has ambiguous duplicate repo-command-runs rows`);
  }
  const row = matching[0];
  if (row.dry_run !== false) throw new Error(`run_id ${runId} must reference a live non-dry-run repo docker run`);
  if (row.timed_out === true) throw new Error(`run_id ${runId} must reference a completed repo docker run, not a timed-out run`);
  // Cycle B keyed layer: AFTER the dry_run/timed_out checks, assert the keyed row_mac.
  // A present-but-invalid (forged/tampered/cross-context) row_mac throws → the caller's
  // catch (reverifyReproRecord) maps it to ok:false; an absent row_mac is accepted-with-
  // warning (legacy in-flight row; the capture re-hash in runFromRow still binds it).
  assertRowMacOrLegacy(REPO_COMMAND_RUN_MAC_CONTEXT, row, verifier);
  return row;
}

function sha256File(filePath) {
  const data = fs.readFileSync(filePath);
  return crypto.createHash("sha256").update(data).digest("hex");
}

// Build the run-shaped object adjudicateDifferential consumes from a re-resolved row +
// its on-disk captures. CONTENT-HASH integrity: recompute sha256 of each capture file
// and require it to equal the row's stdout_hash/stderr_hash (the same bind repo-env.js
// minted), so the bytes we re-classify are exactly the bytes the run produced. A missing
// capture file or a hash mismatch throws → the caller fails closed.
function runFromRow(domain, row) {
  const runId = row.run_id;
  const stdoutPath = path.join(repoRunsDir(domain), `${runId}.stdout`);
  const stderrPath = path.join(repoRunsDir(domain), `${runId}.stderr`);
  const stdoutText = fs.readFileSync(stdoutPath, "utf8");
  const stderrText = fs.readFileSync(stderrPath, "utf8");
  if (typeof row.stdout_hash !== "string" || sha256File(stdoutPath) !== row.stdout_hash) {
    throw new Error(`run_id ${runId} stdout capture does not match the row stdout_hash`);
  }
  if (typeof row.stderr_hash !== "string" || sha256File(stderrPath) !== row.stderr_hash) {
    throw new Error(`run_id ${runId} stderr capture does not match the row stderr_hash`);
  }
  return {
    exit_code: typeof row.exit_code === "number" ? row.exit_code : null,
    timed_out: row.timed_out === true,
    error: undefined,
    stdout_text: stdoutText,
    stderr_text: stderrText,
  };
}

// reverifyReproRecord — READ-TIME INTEGRITY. Do NOT trust the verdict row's stored
// command_hash / control_ref / crash_class (results_hash is an UNKEYED self-hash, so a
// runtime-indirection write can append a bare forged verified_pass line whose
// vuln_run_id/control_run_id point at nothing). RE-RESOLVE both run ids against the
// content-hashed repo-command-runs.jsonl rows, RE-CHECK each cited capture file's bytes
// against the row's stdout_hash/stderr_hash, and RE-ADJUDICATE the flip exactly as the
// mint path (adjudicateDifferential) does. A forged verdict whose runs don't resolve to a
// consistent flipping pair fails here (any throw → ok:false).
//
// command_hash RE-BIND: for a repro-mode record the vuln run has NO checkout, so its
// repo-command-runs row command_hash = sha256(JSON.stringify(argv)) is byte-equal to the
// mint's hashCanonicalJson(command); the control run is checkout-wrapped
// (buildDifferentialCheckoutCommand) so its command_hash legitimately differs and is NOT
// the bind target. We assert record.command_hash equals the VULN row's command_hash, so a
// forged command_hash that does not match the actual run is rejected. For an oracle record
// (mode === "oracle_differential") the vuln run IS a patched/checkout-wrapped run, so its
// row command_hash is wrapped and the equality assert does not apply; the flip + capture
// integrity still bind it, and command_hash is carried from the record (no oracle consumer
// uses it as a bind — the O-P4 :1045 bind only ever runs against repro-mode records).
//
// FAIL-CLOSED on a rotated/truncated ledger: a verdict whose repo-command-runs rows were
// legitimately minted then later removed reads as unverified. The source run rows + capture
// bytes ARE the asset — if they are gone, the verdict is no longer re-derivable.
//
// Runs under NO lock (read-only, like the summary reader). Returns
// { ok, command_hash, control_ref, crash_class } — command_hash + crash_class are
// RE-DERIVED from the re-resolved source row/bytes; control_ref is provenance metadata
// carried from the record (not part of the differential and not used by the O-P4 bind).
function reverifyReproRecord(domain, record) {
  const targetDomain = assertSafeDomain(domain);
  if (record == null || typeof record !== "object") {
    return { ok: false, command_hash: null, control_ref: null, crash_class: null };
  }
  try {
    if (record.result !== RESULT_VERIFIED_PASS) throw new Error("record is not a verified_pass");
    if (typeof record.finding_id !== "string" || !record.finding_id) throw new Error("finding_id is required");
    const vulnRunId = record.vuln_run_id;
    const controlRunId = record.control_run_id;
    if (typeof vulnRunId !== "string" || !vulnRunId) throw new Error("vuln_run_id is required");
    if (typeof controlRunId !== "string" || !controlRunId) throw new Error("control_run_id is required");
    // A single run never flips against itself (mirrors the invariant + finding siblings'
    // single-run rejection).
    if (vulnRunId === controlRunId) throw new Error("vuln_run_id must differ from control_run_id");

    const rows = readRepoCommandRunRows(targetDomain);
    // Cycle B: resolve the keyed-MAC verifier ONCE for this re-resolution (not per row;
    // CONSTRAINT 1: no per-row disk re-read). resolveRowVerifierSafely yields a
    // public-key-only verifier (hmacKey:null) for a non-offensive ed25519-only session
    // and null for a pre-keypair session; a signed row with a null verifier fails closed.
    const repoRowVerifier = resolveRowVerifierSafely(targetDomain);
    const vulnRow = resolveRepoRunRow(rows, vulnRunId, repoRowVerifier);
    const controlRow = resolveRepoRunRow(rows, controlRunId, repoRowVerifier);

    // RE-BIND command_hash off the VULN (no-checkout) row for repro-mode records. An
    // oracle-mode record's vuln run is checkout-wrapped, so the equality does not apply.
    const isOracle = record.mode === "oracle_differential";
    if (!isOracle && record.command_hash !== vulnRow.command_hash) {
      throw new Error("command_hash does not match the vuln run's command_hash");
    }

    const vulnRun = runFromRow(targetDomain, vulnRow);
    const controlRun = runFromRow(targetDomain, controlRow);
    const { result, vulnVerdict } = adjudicateDifferential({
      vulnRun, controlRun, controlLabel: "upstream-fix",
    });
    if (result !== RESULT_VERIFIED_PASS) {
      return { ok: false, command_hash: null, control_ref: null, crash_class: null };
    }
    return {
      ok: true,
      // RE-DERIVED from the re-resolved source: command_hash from the vuln row (repro mode)
      // or carried from the record (oracle mode); crash_class re-classified from the bytes.
      command_hash: isOracle ? record.command_hash : vulnRow.command_hash,
      control_ref: record.control_ref,
      crash_class: vulnVerdict.crash_class,
    };
  } catch {
    // Missing / content-inconsistent / non-flipping / single-run / rotated row or capture →
    // the flip is not re-derivable from the source rows + bytes. Fail closed.
    return { ok: false, command_hash: null, control_ref: null, crash_class: null };
  }
}

// Summarize the reproduction-gate ledger — the AUTHORITATIVE O-P4 signal. Reads the
// MCP-write-only, audit-graded repro-verified.jsonl, then RE-ADJUDICATES each verified_pass
// from the repo-command-runs rows + capture files it cites rather than trusting the
// verdict's self-hashed fields.
//
// repro-runs integrity is content-hash (the repo-command-runs row command_hash binds the
// argv, and stdout_hash/stderr_hash bind the captured bytes) + agent-Write-block; each
// verified_pass is RE-ADJUDICATED here from the rows + capture files it cites, raising the
// forgery bar to a CONSISTENT forged run pair (two rows whose captures actually FLIP under
// parseSanitizerReport — crash on vuln, quiet on control), not a bare verdict line. NOTE
// this is content-hash parity with the invariant ledger, NOT MAC-level (the offensive-runs
// ledger's keyed MAC); the deeper close for all content-hash ledgers is the offensive-
// sandbox PR (uid/container separation so the agent UID cannot fabricate trusted source
// rows), the same residual the offensive stack documents (claims.js THREAT-MODEL BOUNDARY,
// finding-differential-verifier.js reverify note).
function readReproVerifiedSummary(domain) {
  const targetDomain = assertSafeDomain(domain);
  let records = [];
  try {
    const raw = fs.readFileSync(reproVerifiedJsonlPath(targetDomain), "utf8");
    records = raw
      .split("\n")
      .filter((line) => line.trim())
      .map((line) => { try { return JSON.parse(line); } catch { return null; } })
      .filter(Boolean);
  } catch {
    records = [];
  }
  const verified = records.filter((r) => r.result === RESULT_VERIFIED_PASS);
  const verifiedByFinding = {};
  for (const r of verified) {
    const rederived = reverifyReproRecord(targetDomain, r);
    if (!rederived.ok) continue;
    // finding_id -> the RE-DERIVED command_hash + crash_class (from the re-resolved source
    // rows/bytes) for the O-P4 gate to require a verified_pass whose command_hash matches
    // the claim's repro_command_argv. The entry shape is byte-identical to the prior reader.
    verifiedByFinding[r.finding_id] = {
      command_hash: rederived.command_hash,
      control_ref: rederived.control_ref,
      crash_class: rederived.crash_class,
    };
  }
  return {
    total_runs: records.length,
    verified_pass_count: verified.length,
    refuted_count: records.filter((r) => r.result === RESULT_REFUTED).length,
    inconclusive_count: records.filter((r) => r.result === RESULT_INCONCLUSIVE).length,
    verified_by_finding: verifiedByFinding,
  };
}

module.exports = {
  REPRO_VERIFIED_MAX_RECORDS,
  REPRO_VERIFIED_VERSION,
  RESULT_VERIFIED_PASS,
  RESULT_REFUTED,
  RESULT_INCONCLUSIVE,
  verifyReproReproduction,
  verifyOracleDifferential,
  reverifyReproRecord,
  readReproVerifiedSummary,
};
