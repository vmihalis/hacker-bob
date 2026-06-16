"use strict";

const fs = require("fs");

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
    reason = "no differential flip: the command also crashes the upstream-fix tree (forged/over-broad/non-attributable)";
  } else if (controlRun.exit_code !== 0) {
    // The fix tree neither crashed NOR completed cleanly (non-zero exit, no crash
    // banner). The most likely cause is that the command FAILED TO BUILD/RUN the
    // harness on the fixed source (e.g. the fix changed an API the harness calls),
    // so the absence of a crash proves nothing — the bug may simply never have been
    // exercised. Treat as inconclusive rather than minting a verified_pass off a
    // false-quiet control. (The reproduction idiom is: crash -> non-zero + banner;
    // clean -> exit 0. A clean control MUST be a zero-exit completion.)
    result = RESULT_INCONCLUSIVE;
    reason = `control (upstream-fix) tree did not crash but exited ${controlRun.exit_code} with no sanitizer banner — cannot distinguish a genuine fix from a failed build/run; differential inconclusive`;
  } else {
    // Real, attributable, flipping crash: vuln crashes with a /src frame; fix builds,
    // runs the harness, and is quiet (exit 0).
    result = RESULT_VERIFIED_PASS;
    reason = "differential reproduction: crashes the vulnerable tree, quiet on the upstream-fix tree";
  }

  const body = {
    version: REPRO_VERIFIED_VERSION,
    target_domain: targetDomain,
    ts: new Date().toISOString(),
    finding_id: findingId,
    result,
    reason,
    command_hash: hashCanonicalJson(input.command),
    control_ref: input.control_ref,
    control_kind: controlKind,
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

// Summarize the reproduction-gate ledger — the AUTHORITATIVE O-P4 signal. Reads the
// MCP-write-only, audit-graded repro-verified.jsonl from disk only; a verified_pass
// cannot be hand-forged (the path is agent-Write-blocked) — only this verifier mints it.
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
  return {
    total_runs: records.length,
    verified_pass_count: verified.length,
    refuted_count: records.filter((r) => r.result === RESULT_REFUTED).length,
    inconclusive_count: records.filter((r) => r.result === RESULT_INCONCLUSIVE).length,
    // finding_id -> the verified_pass record's command_hash, for the O-P4 gate to
    // require a verified_pass whose command_hash matches the claim's repro_command_argv.
    verified_by_finding: Object.fromEntries(
      verified.map((r) => [r.finding_id, { command_hash: r.command_hash, control_ref: r.control_ref, crash_class: r.crash_class }]),
    ),
  };
}

module.exports = {
  REPRO_VERIFIED_MAX_RECORDS,
  REPRO_VERIFIED_VERSION,
  RESULT_VERIFIED_PASS,
  RESULT_REFUTED,
  RESULT_INCONCLUSIVE,
  verifyReproReproduction,
  readReproVerifiedSummary,
};
