"use strict";

// Shared test helper: seed a GENUINE differential repro run pair on disk so the read-time
// re-adjudication in readReproVerifiedSummary (reverifyReproRecord) admits the verified_pass.
//
// reverifyReproRecord re-resolves vuln_run_id/control_run_id against the content-hashed
// repo-command-runs.jsonl, re-checks each capture file's bytes against the row's
// stdout_hash/stderr_hash, and re-runs adjudicateDifferential. A bare forged verdict line
// (the old test idiom) no longer survives that gate, so any test that needs an ADMITTED
// repro verified_pass must seed a real flipping pair: a vuln run that crashes (an
// attributable /src sanitizer frame) and a control run that is quiet (exit 0). This helper
// writes exactly that — two rows + four capture files + the matching verdict line.

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const {
  repoCommandRunsJsonlPath,
  repoRunsDir,
  reproVerifiedJsonlPath,
} = require("../../mcp/core/io/paths.js");
const { appendJsonlLine } = require("../../mcp/core/io/storage.js");
const { hashCanonicalJson } = require("../../mcp/core/verification/verification-contracts.js");
// Cycle B: an admitted LIVE repo-command-runs row now carries a domain-separated
// row_mac. The {sign} opt mints it the way the producer (repo-env.js) does so a test
// that drives reverifyReproRecord through the keyed read path admits the pair; default
// unsigned keeps the legacy-acceptance (accept-with-warning) coverage intact.
const {
  signRowWithMac,
  REPO_COMMAND_RUN_MAC_CONTEXT,
} = require("../../mcp/core/ledger-integrity/index.js");
const {
  ensureHandoffKeypair,
  readHandoffSigningPrivateKey,
} = require("../../mcp/core/ledger-integrity/index.js");

// A real ASAN crash with a /src root-cause frame (the muparser/oss-fuzz shape).
const DEFAULT_VULN_STDERR = `==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x511
    #0 0x4f1c2a in parse /src/parser.c:42:10
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:42:10`;
const DEFAULT_CONTROL_STDERR = "All tests passed\n12/12 ok";

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function writeCapture(domain, runId, stdoutText, stderrText) {
  const dir = repoRunsDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  const stdoutPath = path.join(dir, `${runId}.stdout`);
  const stderrPath = path.join(dir, `${runId}.stderr`);
  fs.writeFileSync(stdoutPath, stdoutText);
  fs.writeFileSync(stderrPath, stderrText);
  return {
    stdout_hash: sha256(Buffer.from(stdoutText)),
    stderr_hash: sha256(Buffer.from(stderrText)),
  };
}

// Append a content-hashed repo-command-runs row whose stdout_hash/stderr_hash bind the
// captures this helper just wrote. command_hash mirrors the live mint:
// sha256(JSON.stringify(command)) === hashCanonicalJson(command) for a scalar argv.
function seedRepoRunRow(domain, {
  runId, command, exitCode, stdoutHash, stderrHash, checkoutRef = null, checkoutKind = null,
  sign = false,
}) {
  const row = {
    version: 1,
    run_id: runId,
    target_domain: domain,
    dry_run: false,
    command_hash: hashCanonicalJson(command),
    exit_code: exitCode,
    timed_out: false,
    network_mode: "none",
    mount_mode: "read_only",
    stdout_hash: stdoutHash,
    stderr_hash: stderrHash,
  };
  if (checkoutRef) row.checkout_ref = checkoutRef;
  if (checkoutKind) row.checkout_kind = checkoutKind;
  // Cycle B: sign the live row exactly as the producer does (ed25519 over the row minus
  // row_mac under the repo-command-run context) when {sign} is set; otherwise leave it a
  // legacy unsigned row (accept-with-warning at the keyed read site).
  if (sign) {
    ensureHandoffKeypair(domain);
    signRowWithMac(REPO_COMMAND_RUN_MAC_CONTEXT, row, readHandoffSigningPrivateKey(domain));
  }
  appendJsonlLine(repoCommandRunsJsonlPath(domain), row);
  return row;
}

// Seed a genuine flipping repro pair + the verified_pass verdict line citing it.
//
// opts:
//   argv          - the claim's repro_command_argv (the command_hash bind target)
//   findingId     - the verdict's finding_id
//   vulnRunId     - vuln (no-checkout) run id
//   controlRunId  - control (checkout-wrapped) run id
//   controlRef    - the upstream-fix commit ref
//   vulnStderr    - vuln capture stderr (default: an attributable /src ASAN crash)
//   controlStderr - control capture stderr (default: a clean pass)
//   controlCommand- the WRAPPED command the control row records (default: a distinct
//                   checkout-wrapped argv, so its command_hash legitimately differs from
//                   the vuln row's — exactly as buildDifferentialCheckoutCommand produces)
//   noflip        - when true, the control crashes identically (re-adjudication → refuted)
//   crashClass    - the crash_class to stamp on the verdict line (provenance only;
//                   re-derived from bytes by reverify)
function seedGenuineReproPair(domain, opts = {}) {
  const argv = opts.argv || ["sh", "-lc", "./harness crash-input.bin"];
  const findingId = opts.findingId || "F-1";
  const vulnRunId = opts.vulnRunId || "repro-vuln-1";
  const controlRunId = opts.controlRunId || "repro-control-1";
  const controlRef = opts.controlRef || "a".repeat(40);
  const vulnStderr = opts.vulnStderr || DEFAULT_VULN_STDERR;
  const controlStderr = opts.noflip ? vulnStderr : (opts.controlStderr || DEFAULT_CONTROL_STDERR);
  const controlCommand = opts.controlCommand || ["sh", "-lc", "git checkout && ./harness crash-input.bin"];
  const crashClass = opts.crashClass || "heap-buffer-overflow";

  const vulnHashes = writeCapture(domain, vulnRunId, "", vulnStderr);
  const controlHashes = writeCapture(domain, controlRunId, "", controlStderr);

  const sign = opts.sign === true;
  seedRepoRunRow(domain, {
    runId: vulnRunId, command: argv, exitCode: 1,
    stdoutHash: vulnHashes.stdout_hash, stderrHash: vulnHashes.stderr_hash,
    sign,
  });
  seedRepoRunRow(domain, {
    runId: controlRunId, command: controlCommand,
    exitCode: opts.noflip ? 1 : 0,
    stdoutHash: controlHashes.stdout_hash, stderrHash: controlHashes.stderr_hash,
    checkoutRef: controlRef, checkoutKind: "upstream_fix",
    sign,
  });

  const verdict = {
    version: 1,
    target_domain: domain,
    ts: "2026-06-01T00:00:00.000Z",
    finding_id: findingId,
    result: "verified_pass",
    reason: "differential reproduction: crashes the vulnerable tree, quiet on the upstream-fix tree",
    command_hash: opts.verdictCommandHash != null ? opts.verdictCommandHash : hashCanonicalJson(argv),
    control_ref: controlRef,
    vuln_run_id: vulnRunId,
    control_run_id: controlRunId,
    crash_class: crashClass,
  };
  if (opts.verdictOver) Object.assign(verdict, opts.verdictOver);
  appendJsonlLine(reproVerifiedJsonlPath(domain), verdict);
  return { verdict, vulnRunId, controlRunId, argv, findingId, controlRef };
}

// Append a BARE forged verified_pass line: result:verified_pass with a command_hash that
// matches the claim argv, but vuln_run_id/control_run_id resolving to NOTHING on disk. This
// is the forgery reverifyReproRecord must exclude.
function seedBareForgedReproPass(domain, opts = {}) {
  const argv = opts.argv || ["sh", "-lc", "./harness crash-input.bin"];
  const findingId = opts.findingId || "F-1";
  const verdict = {
    version: 1,
    target_domain: domain,
    ts: "2026-06-01T00:00:00.000Z",
    finding_id: findingId,
    result: "verified_pass",
    reason: "forged",
    command_hash: hashCanonicalJson(argv),
    control_ref: "a".repeat(40),
    vuln_run_id: opts.vulnRunId || "ghost-vuln",
    control_run_id: opts.controlRunId || "ghost-control",
    crash_class: "heap-buffer-overflow",
  };
  if (opts.verdictOver) Object.assign(verdict, opts.verdictOver);
  appendJsonlLine(reproVerifiedJsonlPath(domain), verdict);
  return verdict;
}

// Decorate a fake repoDockerRunFn so each non-degraded run it returns is PERSISTED as a
// genuine repo-command-runs row + capture files, exactly as a live bob_repo_docker_run
// would. This lets a verifier test that drives verifyReproReproduction / verifyOracleDifferential
// produce a verified_pass that readReproVerifiedSummary's read-time re-adjudication can
// re-resolve. The row's command_hash mirrors the live mint (hashCanonicalJson(command)) so
// the vuln-row command_hash re-bind in reverifyReproRecord matches; degraded results
// (error / timed_out / no exit code) are passed through unpersisted, exactly as the live
// runner records no usable capture.
function persistingRunner(domain, innerRunner) {
  return async (args) => {
    const result = await innerRunner(args);
    if (!result || typeof result !== "object") return result;
    const runId = result.run_id;
    const degraded = typeof result.error === "string" && result.error
      ? true
      : result.timed_out === true || typeof runId !== "string" || !runId;
    if (degraded) return result;
    const stdoutText = typeof result.stdout_text === "string" ? result.stdout_text : "";
    const stderrText = typeof result.stderr_text === "string" ? result.stderr_text : "";
    const hashes = writeCapture(domain, runId, stdoutText, stderrText);
    seedRepoRunRow(domain, {
      runId,
      command: args.command,
      exitCode: typeof result.exit_code === "number" ? result.exit_code : null,
      stdoutHash: hashes.stdout_hash,
      stderrHash: hashes.stderr_hash,
      checkoutRef: args.checkout && args.checkout.ref ? args.checkout.ref : null,
      checkoutKind: args.checkout && args.checkout.kind ? args.checkout.kind : null,
    });
    return result;
  };
}

module.exports = {
  DEFAULT_VULN_STDERR,
  DEFAULT_CONTROL_STDERR,
  seedGenuineReproPair,
  seedBareForgedReproPass,
  seedRepoRunRow,
  writeCapture,
  persistingRunner,
};
