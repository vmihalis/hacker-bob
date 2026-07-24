"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const asyncHooks = require("node:async_hooks");
const childProcess = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const MODULE_PATH = path.join(__dirname, "..", "lib", "safety-deadman.js");
const EXECUTABLE_PATH = path.join(
  __dirname,
  "..",
  "build",
  "Release",
  "safety_watchdog_fixture",
);
const CUSTODY_EVIDENCE_KEY_DOMAIN =
  "hacker-bob/darwin-safety-custody-evidence-key/v1";

process.env.BOB_DARWIN_SAFETY_DEADMAN_FIXTURE = "1";
const api = require(MODULE_PATH);

function digest(label) {
  return crypto.createHash("sha256").update(label, "utf8").digest("hex");
}

function fixtureContract(workerPid, options = {}) {
  return {
    version: 1,
    contract_id: options.contractId || "safety_fixture_contract",
    fixture_only: true,
    instrument_ref_digest: options.instrument || digest("instrument:fixture-1"),
    lease_id_digest: options.lease || digest("lease:fixture-1"),
    fencing_token_digest: digest("fence:fixture-1"),
    fencing_generation: 1,
    worker_pid: workerPid,
    worker_identity_digest: digest("worker-code-identity:fixture-1"),
    cleanup_capability_digest: options.cleanup || digest("cleanup:fixture-1"),
    restore_digest: options.restore || digest("restore:fixture-1"),
    cleanup_provider_manifest_digest: digest("future-cleanup-provider:fixture-1"),
    journal_id_digest: digest(`journal:${options.contractId || "fixture-1"}`),
    heartbeat_interval_ms: options.heartbeatMs || 100,
    miss_tolerance: options.missTolerance || 3,
    cleanup_timeout_ms: options.cleanupTimeoutMs || 150,
    mf1_field_off_reset_restore: options.mf1Restore === undefined
      ? false
      : options.mf1Restore,
    fixture_cleanup_behavior: options.behavior || "ack",
  };
}

function fixturePlan(workerPid, options = {}) {
  const contract = fixtureContract(workerPid, options);
  return api.createDarwinSafetyDeadmanFixturePlan({
    version: 1,
    contract,
    contract_digest: api.deriveDarwinSafetyDeadmanContractDigest(contract),
  });
}

function fixtureRoot(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-safety-deadman-"));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

function journalPath(root, label) {
  return path.join(root, `${label}.journal`);
}

function worker(t) {
  const child = childProcess.spawn(
    "/bin/sleep",
    ["60"],
    { stdio: "ignore" },
  );
  t.after(() => {
    try { child.kill("SIGKILL"); } catch {}
  });
  return child;
}

function blockEventLoop(durationMs) {
  const deadline = process.hrtime.bigint() + BigInt(durationMs) * 1000000n;
  while (process.hrtime.bigint() < deadline) {}
}

function blockUntilFileContains(file, expected, timeoutMs = 2000) {
  const deadline = process.hrtime.bigint() + BigInt(timeoutMs) * 1000000n;
  while (process.hrtime.bigint() < deadline) {
    try {
      if (fs.readFileSync(file, "utf8").includes(expected)) return;
    } catch {}
  }
  assert.fail(`timed out waiting for ${expected}`);
}

function isolatedWorkerGroup(t) {
  const child = childProcess.spawn(
    "/bin/sleep",
    ["60"],
    { detached: true, stdio: "ignore" },
  );
  t.after(() => {
    try { child.kill("SIGKILL"); } catch {}
  });
  return child;
}

function safeError(error, code = "darwin_safety_deadman_rejected") {
  assert.equal(error?.code, code);
  assert.equal(error?.message, "Darwin safety deadman fixture was rejected");
  assert.equal(Object.hasOwn(error, "path"), false);
  assert.equal(Object.hasOwn(error, "pid"), false);
  assert.equal(Object.hasOwn(error, "instrument_ref"), false);
  return true;
}

function hmacLine(fields, key) {
  const payload = fields.join("\t");
  const mac = crypto.createHmac("sha256", key).update(payload, "utf8").digest("hex");
  return `${payload}\t${mac}\n`;
}

function custodyEvidenceKey(raw) {
  return crypto.createHmac("sha256", raw.key)
    .update(`${CUSTODY_EVIDENCE_KEY_DOMAIN}\t${raw.contractDigest}`, "utf8")
    .digest();
}

async function custodyTerminal(raw, timeoutMs = 2000) {
  const fields = (await raw.nextCustody(timeoutMs)).split("\t");
  assert.equal(fields.length, 28, fields.join(" | "));
  assert.equal(fields[0], "CUSTODY1");
  assert.equal(fields[2], raw.contractDigest);
  assert.match(fields[3], /^[a-f0-9]{64}$/u);
  assert.match(fields[4], /^[a-f0-9]{32}$/u);
  const key = custodyEvidenceKey(raw);
  const expected = crypto.createHmac("sha256", key)
    .update(fields.slice(0, -1).join("\t"), "utf8")
    .digest("hex");
  key.fill(0);
  assert.equal(fields[27], expected);
  return fields;
}

function semanticProfile(contract) {
  if (contract.mf1_field_off_reset_restore === null) return "rf_off_only";
  return contract.mf1_field_off_reset_restore
    ? "rf_off_restore_mf1_true"
    : "rf_off_restore_mf1_false";
}

function makeLineReader(readable) {
  let buffered = "";
  const lines = [];
  const waiters = [];
  let ended = false;
  readable.on("data", (chunk) => {
    buffered += chunk.toString("utf8");
    for (;;) {
      const newline = buffered.indexOf("\n");
      if (newline < 0) break;
      const line = buffered.slice(0, newline);
      buffered = buffered.slice(newline + 1);
      if (waiters.length > 0) waiters.shift().resolve(line);
      else lines.push(line);
    }
  });
  readable.on("end", () => {
    ended = true;
    while (waiters.length > 0) waiters.shift().reject(new Error("output ended"));
  });
  return async function nextLine(timeoutMs = 2000) {
    if (lines.length > 0) return lines.shift();
    if (ended) throw new Error("output ended");
    let timer;
    return new Promise((resolve, reject) => {
      const waiter = {
        resolve: (line) => {
          clearTimeout(timer);
          resolve(line);
        },
        reject,
      };
      waiters.push(waiter);
      timer = setTimeout(() => {
        const index = waiters.indexOf(waiter);
        if (index >= 0) waiters.splice(index, 1);
        reject(new Error("output timeout"));
      }, timeoutMs);
    });
  };
}

async function rawWatchdog(t, contract, label, options = {}) {
  const root = fixtureRoot(t);
  const journal = journalPath(root, label);
  const journalFd = fs.openSync(
    journal,
    fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_RDWR
      | fs.constants.O_APPEND,
    0o600,
  );
  const executableDigest = crypto.createHash("sha256")
    .update(fs.readFileSync(EXECUTABLE_PATH))
    .digest("hex");
  const contractDigest = api.deriveDarwinSafetyDeadmanContractDigest(contract);
  const semanticDigest = api.deriveDarwinSafetySemanticCleanupDigest({
    version: 1,
    mf1_field_off_reset_restore: contract.mf1_field_off_reset_restore,
  });
  const key = crypto.randomBytes(32);
  const child = childProcess.spawn(
    EXECUTABLE_PATH,
    ["--watchdog-fixture"],
    {
      env: {},
      detached: true,
      stdio: ["ignore", "pipe", "ignore", "pipe", journalFd, "pipe", "pipe"],
    },
  );
  t.after(() => {
    try { child.kill("SIGKILL"); } catch {}
    try { fs.closeSync(journalFd); } catch {}
    key.fill(0);
  });
  const nextLine = options.consumeStdout === false
    ? null
    : makeLineReader(child.stdout);
  const nextCustody = makeLineReader(child.stdio[6]);
  if (options.closeStdoutBeforeConfig === true) {
    child.stdout.destroy();
    if (!child.stdout.closed) {
      await new Promise((resolve) => child.stdout.once("close", resolve));
    }
  }
  const capability = Buffer.alloc(36);
  capability.write("KEY1", 0, "ascii");
  key.copy(capability, 4);
  child.stdio[5].end(capability, () => capability.fill(0));
  const config = [
    "CFG1",
    "1",
    contractDigest,
    executableDigest,
    contract.instrument_ref_digest,
    contract.lease_id_digest,
    contract.fencing_token_digest,
    String(contract.fencing_generation),
    String(contract.worker_pid),
    contract.worker_identity_digest,
    contract.cleanup_capability_digest,
    contract.restore_digest,
    semanticDigest,
    contract.cleanup_provider_manifest_digest,
    contract.journal_id_digest,
    semanticProfile(contract),
    String(contract.heartbeat_interval_ms * contract.miss_tolerance),
    String(contract.heartbeat_interval_ms * contract.miss_tolerance),
    String(contract.cleanup_timeout_ms),
    contract.fixture_cleanup_behavior,
  ];
  let configLine = hmacLine(config, key);
  if (options.invalidConfigHmac === true) {
    const replacement = configLine.at(-2) === "0" ? "1" : "0";
    configLine = `${configLine.slice(0, -2)}${replacement}\n`;
  }
  child.stdio[3].write(configLine);
  const raw = {
    child,
    control: child.stdio[3],
    key,
    nextLine,
    nextCustody,
    contract,
    contractDigest,
    semanticDigest,
    journal,
    journalFd,
  };
  if (options.awaitReady === false) return raw;
  const ready = (await nextLine()).split("\t");
  assert.equal(ready[0], "READY1", ready.join(" | "));
  return {
    ...raw,
    challenge: ready[1],
    nativeMonotonicAnchor: BigInt(ready[2]),
    hostMonotonicAnchor: process.hrtime.bigint(),
  };
}

function protocolBindings(raw, overrides = {}) {
  return [
    raw.challenge,
    raw.contractDigest,
    overrides.instrument || raw.contract.instrument_ref_digest,
    overrides.lease || raw.contract.lease_id_digest,
    raw.contract.fencing_token_digest,
    String(raw.contract.fencing_generation),
    raw.contract.worker_identity_digest,
    overrides.cleanup || raw.contract.cleanup_capability_digest,
    overrides.restore || raw.contract.restore_digest,
    raw.semanticDigest,
  ];
}

function heartbeatRecord(raw, sequence, options = {}) {
  const issued = options.issued === undefined
    ? raw.nativeMonotonicAnchor
      + (process.hrtime.bigint() - raw.hostMonotonicAnchor)
    : options.issued;
  const valid = options.valid === undefined
    ? issued + BigInt(raw.contract.heartbeat_interval_ms * raw.contract.miss_tolerance) * 1000000n
    : options.valid;
  return hmacLine([
    "HB1", "1", String(sequence), String(issued), String(valid),
    ...protocolBindings(raw, options),
  ], raw.key);
}

function stopRecord(raw, sequence = 1, reason = "operator_stop") {
  const issued = raw.nativeMonotonicAnchor
    + (process.hrtime.bigint() - raw.hostMonotonicAnchor);
  const valid = issued
    + BigInt(raw.contract.heartbeat_interval_ms * raw.contract.miss_tolerance)
      * 1000000n;
  return hmacLine([
    "STOP1", "1", String(sequence), reason, String(issued), String(valid),
    ...protocolBindings(raw),
  ], raw.key);
}

async function waitForChildExit(child, timeoutMs = 2000) {
  if (child.exitCode !== null || child.signalCode !== null) {
    return { code: child.exitCode, signal: child.signalCode };
  }
  let timer;
  return new Promise((resolve, reject) => {
    const onExit = (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal });
    };
    child.once("exit", onExit);
    timer = setTimeout(() => {
      child.removeListener("exit", onExit);
      reject(new Error("child exit timeout"));
    }, timeoutMs);
  });
}

async function waitForProcessGone(pid, timeoutMs = 1500) {
  const expires = Date.now() + timeoutMs;
  while (Date.now() < expires) {
    try {
      process.kill(pid, 0);
    } catch (error) {
      if (error?.code === "ESRCH") return;
      throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.fail(`process ${pid} remained alive`);
}

function readJournalEvents(raw) {
  const text = fs.readFileSync(raw.journal, "utf8");
  if (text.length === 0) return [];
  return text.trimEnd().split("\n").map((line) => line.split("\t")[3]);
}

async function assertSingleCustodyCleanup(raw, fields, expectedReason) {
  assert.equal(fields[5], String(raw.child.pid));
  if (Array.isArray(expectedReason)) {
    assert.ok(expectedReason.includes(fields[16]), fields[16]);
  } else {
    assert.equal(fields[16], expectedReason);
  }
  assert.equal(fields[17], "0");
  assert.equal(fields[18], "fixture_acknowledged_rf_unknown");
  assert.equal(fields[19], "unknown");
  assert.equal(fields[20], "quarantined");
  assert.equal(fields[22], "true");
  const watcherPid = Number(fields[5]);
  const custodianPid = Number(fields[6]);
  const cleanupPid = Number(fields[21]);
  assert.ok(Number.isSafeInteger(watcherPid) && watcherPid > 1);
  assert.ok(Number.isSafeInteger(custodianPid) && custodianPid > 1);
  assert.ok(Number.isSafeInteger(cleanupPid) && cleanupPid > 1);
  assert.equal(new Set([watcherPid, custodianPid, cleanupPid]).size, 3);
  assert.equal(Number(fields[9]), watcherPid);
  assert.equal(Number(fields[10]), watcherPid);
  assert.equal(Number(fields[13]), custodianPid);
  assert.equal(Number(fields[14]), custodianPid);
  assert.equal(Number(fields[24]), cleanupPid);
  assert.equal(Number(fields[25]), cleanupPid);
  for (const index of [8, 11, 12, 15, 23, 26]) {
    assert.match(fields[index], /^[a-f0-9]{64}$/u);
  }
  await waitForProcessGone(cleanupPid);
  await assert.rejects(raw.nextCustody(1000), /output ended/u);
  return { watcherPid, custodianPid, cleanupPid };
}

async function terminateBlockedWatchdog(raw, pids) {
  raw.child.kill("SIGKILL");
  const exit = await waitForChildExit(raw.child, 2000);
  assert.deepEqual(exit, { code: null, signal: "SIGKILL" });
  await waitForProcessGone(pids.watcherPid);
  await waitForProcessGone(pids.custodianPid);
  await waitForProcessGone(pids.cleanupPid);
}

async function rawTerminal(raw, timeoutMs = 3000) {
  for (;;) {
    const fields = (await raw.nextLine(timeoutMs)).split("\t");
    if (fields[0] === "TERM1") {
      if (raw.child.exitCode === null && raw.child.signalCode === null) {
        await new Promise((resolve) => raw.child.once("exit", resolve));
      }
      return fields;
    }
  }
}

test("assurance keeps RF release first and process-identity limitations explicit", () => {
  const assurance = api.DARWIN_SAFETY_DEADMAN_ASSURANCE;
  assert.equal(assurance.production_ready, false);
  assert.equal(assurance.real_launch_enabled, false);
  assert.deepEqual(
    assurance.semantic_cleanup_sequence.map((entry) => entry.reviewed_command_family_id),
    [2101, 4038, 4039],
  );
  assert.equal(assurance.semantic_cleanup_sequence[0].role, "field_release_attempt");
  assert.equal(
    assurance.semantic_cleanup_sequence[1].role,
    "conditional_precommitted_workspace_restore_not_rf_stop",
  );
  assert.equal(assurance.usb_or_process_kill_proves_rf_off, false);
  assert.equal(assurance.emission_state_without_external_observer, "unknown");
  assert.equal(assurance.observed_worker_pid_start_identity_bracketed, true);
  assert.equal(assurance.caller_worker_identity_digest_matches_native_observation, false);
  assert.equal(assurance.worker_identity_digest_protocol_binding_only, true);
  assert.ok(assurance.production_blockers.includes(
    "caller_worker_identity_digest_native_observation_binding_missing",
  ));
  assert.equal(assurance.cleanup_trigger_to_terminal_absolute_deadline, true);
  assert.equal(assurance.cleanup_worker_parent_death_guard, true);
  assert.equal(assurance.independent_cleanup_custodian, true);
  assert.equal(assurance.custody_ready_before_effect_admission, true);
  assert.equal(assurance.custody_arm_acceptance_before_ready, true);
  assert.equal(assurance.custody_ready_round_trip_confirmation_before_controller, true);
  assert.equal(assurance.custody_extension_acceptance_before_heartbeat_success, true);
  assert.equal(assurance.custody_acceptance_host_delivery_deadline_checked, true);
  assert.equal(assurance.controller_command_active_custody_deadline_checked, true);
  assert.equal(assurance.pipe_delivery_is_not_custody_acceptance, true);
  assert.equal(assurance.watcher_launcher_process_group_separated, true);
  assert.equal(assurance.custodian_watcher_session_separated, true);
  assert.equal(assurance.cleanup_custodian_session_separated, true);
  assert.equal(assurance.child_start_session_group_identity_evidence_bound, true);
  assert.equal(assurance.stale_pid_or_pgid_signal_rejected, true);
  assert.equal(assurance.custody_control_fd_eof_observation_only, true);
  assert.equal(assurance.custody_evidence_fixture_hmac_verified, true);
  assert.equal(assurance.custody_evidence_child_exclusive_identity_bound, false);
  assert.equal(assurance.custody_pre_ready_terminal_never_success, true);
});

test("absolute cleanup deadline helpers fail closed on zero clock and overflow", () => {
  const result = childProcess.spawnSync(
    EXECUTABLE_PATH,
    ["--deadline-helper-selftest"],
    { encoding: "utf8", env: {}, timeout: 5000 },
  );
  assert.equal(result.status, 0, result.stderr || result.stdout || result.error?.message);
});

test("child lifecycle refuses stale/reaped targets and kills an owned descendant group once", () => {
  const result = childProcess.spawnSync(
    EXECUTABLE_PATH,
    ["--child-lifecycle-selftest"],
    { encoding: "utf8", env: {}, timeout: 5000 },
  );
  assert.equal(result.status, 0, result.stderr || result.stdout || result.error?.message);
});

test("import and construction are inert; real launch refuses before filesystem or spawn", () => {
  const source = String.raw`
const childProcess = require("node:child_process");
const fs = require("node:fs");
const [modulePath] = process.argv.slice(1);
let spawnCalls = 0;
let openCalls = 0;
childProcess.spawn = () => { spawnCalls += 1; throw new Error("spawn"); };
fs.openSync = () => { openCalls += 1; throw new Error("open"); };
const api = require(modulePath);
const d = (value) => require("node:crypto").createHash("sha256").update(value).digest("hex");
const contract = {
  version: 1, contract_id: "inert_contract", fixture_only: false,
  instrument_ref_digest: d("instrument"), lease_id_digest: d("lease"),
  fencing_token_digest: d("fence"), fencing_generation: 1, worker_pid: process.pid,
  worker_identity_digest: d("worker"), cleanup_capability_digest: d("cleanup"),
  restore_digest: d("restore"), cleanup_provider_manifest_digest: d("provider"),
  journal_id_digest: d("journal"), heartbeat_interval_ms: 100, miss_tolerance: 2,
  cleanup_timeout_ms: 100, mf1_field_off_reset_restore: null,
  fixture_cleanup_behavior: "unavailable",
};
const plan = api.createDarwinSafetyDeadmanPlan({
  version: 1, contract,
  contract_digest: api.deriveDarwinSafetyDeadmanContractDigest(contract),
});
let rejected;
try { api.launchDarwinSafetyDeadman(plan, { journal_path: "/never/touched" }); }
catch (error) { rejected = error; }
if (spawnCalls !== 0 || openCalls !== 0
    || rejected?.code !== "darwin_safety_deadman_real_launch_disabled") process.exit(2);
`;
  const result = childProcess.spawnSync(
    process.execPath,
    ["-e", source, MODULE_PATH],
    { encoding: "utf8", env: { ...process.env, BOB_DARWIN_SAFETY_DEADMAN_FIXTURE: "0" } },
  );
  assert.equal(result.status, 0, result.stderr || result.stdout);
});

test("signed stop launches an exec-separated cleanup fixture and durable terminal quarantine", async (t) => {
  const ownedWorker = worker(t);
  const root = fixtureRoot(t);
  const plan = fixturePlan(ownedWorker.pid, { mf1Restore: false });
  const controller = await api.launchDarwinSafetyDeadmanFixture(plan, {
    version: 1,
    journal_path: journalPath(root, "signed-stop"),
  });
  const heartbeat = await controller.heartbeat();
  assert.equal(heartbeat.sequence, 2);
  assert.equal(heartbeat.accepted, true);
  const result = await controller.stop("operator_stop");
  assert.equal(result.state, "quarantined");
  assert.equal(result.reason_code, "operator_stop");
  assert.equal(result.cleanup_outcome, "fixture_acknowledged_rf_unknown");
  assert.equal(result.emission_state, "unknown");
  assert.equal(result.external_observer_confirmed, false);
  assert.equal(result.cleanup_worker_exec_separate, true);
  assert.equal(result.journal_readback_verified, true);
  const records = api.readDarwinSafetyDeadmanJournal(result);
  assert.deepEqual(records.map((record) => record.event_code), [
    "watchdog_started",
    "cleanup_triggered",
    "cleanup_finished",
    "terminal_quarantine",
  ]);
  const serializationRejected = (error) => safeError(
    error,
    "darwin_safety_capability_not_serializable",
  );
  assert.throws(() => JSON.stringify(plan), serializationRejected);
  assert.throws(() => JSON.stringify(controller), serializationRejected);
  assert.throws(() => JSON.stringify(result), serializationRejected);
});

test("worker process death is independently observed and redeems cleanup once", async (t) => {
  const ownedWorker = worker(t);
  const root = fixtureRoot(t);
  const controller = await api.launchDarwinSafetyDeadmanFixture(
    fixturePlan(ownedWorker.pid),
    { version: 1, journal_path: journalPath(root, "worker-death") },
  );
  ownedWorker.kill("SIGKILL");
  const result = await controller.waitForTerminal();
  assert.equal(result.reason_code, "worker_process_exit");
  assert.equal(result.quarantined, true);
  assert.equal(result.emission_state, "unknown");
});

test("closing the parent control capability requests native cleanup instead of killing it", async (t) => {
  const ownedWorker = worker(t);
  const root = fixtureRoot(t);
  const controller = await api.launchDarwinSafetyDeadmanFixture(
    fixturePlan(ownedWorker.pid),
    { version: 1, journal_path: journalPath(root, "control-close") },
  );
  const result = await controller.closeControlForFixture();
  assert.equal(result.reason_code, "control_channel_closed");
  assert.equal(result.cleanup_outcome, "fixture_acknowledged_rf_unknown");
  assert.equal(result.cleanup_worker_exec_separate, true);
  assert.equal(result.emission_state, "unknown");
  assert.equal(result.quarantined, true);
});

test("deadman timeout is monotonic and never claims that battery-powered RF stopped", async (t) => {
  const ownedWorker = worker(t);
  const root = fixtureRoot(t);
  const started = process.hrtime.bigint();
  const controller = await api.launchDarwinSafetyDeadmanFixture(
    fixturePlan(ownedWorker.pid, { heartbeatMs: 30, missTolerance: 2 }),
    { version: 1, journal_path: journalPath(root, "deadman-timeout") },
  );
  const result = await controller.waitForTerminal();
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  assert.equal(result.reason_code, "deadman_timeout");
  assert.equal(result.emission_state, "unknown");
  assert.ok(elapsedMs >= 40 && elapsedMs < 1500, `elapsed=${elapsedMs}`);
});

test("stuck cleanup is killed within its bound and terminally quarantined", async (t) => {
  const ownedWorker = worker(t);
  const root = fixtureRoot(t);
  const controller = await api.launchDarwinSafetyDeadmanFixture(
    fixturePlan(ownedWorker.pid, {
      behavior: "stuck",
      cleanupTimeoutMs: 60,
      heartbeatMs: 100,
      missTolerance: 3,
    }),
    { version: 1, journal_path: journalPath(root, "stuck-cleanup") },
  );
  const started = process.hrtime.bigint();
  const result = await controller.stop("lease_revoked");
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  assert.equal(result.reason_code, "cleanup_timeout");
  assert.equal(result.cleanup_outcome, "cleanup_timeout");
  assert.equal(result.cleanup_worker_exec_separate, false);
  assert.ok(elapsedMs < 1000, `elapsed=${elapsedMs}`);
});

test("a partial receipt without newline cannot escape the cleanup deadline", async (t) => {
  const ownedWorker = worker(t);
  const root = fixtureRoot(t);
  const controller = await api.launchDarwinSafetyDeadmanFixture(
    fixturePlan(ownedWorker.pid, {
      behavior: "partial_stuck",
      cleanupTimeoutMs: 60,
      heartbeatMs: 100,
      missTolerance: 3,
    }),
    { version: 1, journal_path: journalPath(root, "partial-stuck-cleanup") },
  );
  const started = process.hrtime.bigint();
  const result = await controller.stop("lease_revoked");
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  assert.equal(result.reason_code, "cleanup_timeout");
  assert.equal(result.cleanup_outcome, "cleanup_timeout");
  assert.equal(result.cleanup_worker_exec_separate, false);
  assert.equal(result.emission_state, "unknown");
  assert.ok(elapsedMs < 1000, `elapsed=${elapsedMs}`);
});

test("a substituted cleanup receipt cannot become a successful cleanup claim", async (t) => {
  const ownedWorker = worker(t);
  const root = fixtureRoot(t);
  const controller = await api.launchDarwinSafetyDeadmanFixture(
    fixturePlan(ownedWorker.pid, { behavior: "wrong_receipt" }),
    { version: 1, journal_path: journalPath(root, "wrong-receipt") },
  );
  const result = await controller.stop("operator_stop");
  assert.equal(result.reason_code, "cleanup_receipt_rejected");
  assert.equal(result.cleanup_outcome, "cleanup_receipt_rejected");
  assert.equal(result.cleanup_worker_exec_separate, false);
  assert.equal(result.emission_state, "unknown");
  assert.equal(result.quarantined, true);
});

test("trigger-journal failure cannot suppress cleanup or become a success claim", async (t) => {
  const ownedWorker = worker(t);
  const raw = await rawWatchdog(
    t,
    fixtureContract(ownedWorker.pid, {
      contractId: "journal_trigger_failure",
      behavior: "journal_trigger_fail",
      cleanupTimeoutMs: 300,
    }),
    "journal-trigger-failure",
  );
  raw.control.write(stopRecord(raw));
  const terminal = await rawTerminal(raw);
  assert.equal(raw.child.exitCode, 85);
  assert.equal(terminal[2], "operator_stop");
  assert.equal(terminal[4], "fixture_acknowledged_rf_unknown");
  assert.equal(terminal[5], "unknown");
  assert.equal(terminal[9], "false");
  assert.equal(terminal[12], "true");
  const records = fs.readFileSync(raw.journal, "utf8")
    .trimEnd()
    .split("\n")
    .map((line) => line.split("\t"));
  assert.equal(records.some((record) => record[3] === "cleanup_triggered"), false);
  assert.equal(records.some((record) => record[3] === "cleanup_finished"
    && record[4] === "fixture_acknowledged_rf_unknown"), true);
  assert.equal(records.some((record) => record[3] === "terminal_quarantine"), true);
});

test("READY delivery failure still runs cleanup and terminal quarantine", async (t) => {
  const ownedWorker = worker(t);
  const raw = await rawWatchdog(
    t,
    fixtureContract(ownedWorker.pid, {
      contractId: "ready_delivery_failure",
      cleanupTimeoutMs: 300,
    }),
    "ready-delivery-failure",
    { awaitReady: false, closeStdoutBeforeConfig: true },
  );
  const exit = await waitForChildExit(raw.child, 2000);
  assert.deepEqual(exit, { code: 85, signal: null });
  const records = fs.readFileSync(raw.journal, "utf8")
    .trimEnd()
    .split("\n")
    .map((line) => line.split("\t"));
  assert.deepEqual(records.map((record) => record[3]), [
    "watchdog_started",
    "cleanup_triggered",
    "cleanup_finished",
    "terminal_quarantine",
  ]);
  assert.equal(records[1][4], "ready_delivery_failed");
  assert.equal(records[2][4], "fixture_acknowledged_rf_unknown");
});

test("authenticated armed-startup failure redeems cleanup exactly once", async (t) => {
  const raw = await rawWatchdog(
    t,
    fixtureContract(2147483647, {
      contractId: "armed_startup_failure",
      cleanupTimeoutMs: 300,
    }),
    "armed-startup-failure",
    { awaitReady: false },
  );
  const terminal = await rawTerminal(raw);
  assert.equal(raw.child.exitCode, 86);
  assert.equal(terminal[2], "worker_identity_rejected");
  assert.equal(terminal[4], "fixture_acknowledged_rf_unknown");
  assert.equal(terminal[5], "unknown");
  const records = fs.readFileSync(raw.journal, "utf8")
    .trimEnd()
    .split("\n")
    .map((line) => line.split("\t"));
  assert.deepEqual(records.map((record) => record[3]), [
    "cleanup_triggered",
    "cleanup_finished",
    "terminal_quarantine",
  ]);
  assert.equal(records[0][4], "worker_identity_rejected");
});

test("an invalid CFG is inert and cannot produce cleanup custody evidence", async (t) => {
  const ownedWorker = worker(t);
  const raw = await rawWatchdog(
    t,
    fixtureContract(ownedWorker.pid, { contractId: "invalid_cfg_inert" }),
    "invalid-cfg-inert",
    { awaitReady: false, invalidConfigHmac: true },
  );
  assert.equal(await raw.nextLine(1000), "ERROR1\tlaunch_contract_rejected");
  assert.deepEqual(await waitForChildExit(raw.child, 1000), {
    code: 72,
    signal: null,
  });
  await assert.rejects(raw.nextCustody(1000), /output ended/u);
  assert.equal(fs.fstatSync(raw.journalFd).size, 0);
});

test("independent custody cleans once when first fsync or READY output blocks", async (t) => {
  const behaviors = [
    "watchdog_block_first_journal_fsync",
    "watchdog_block_ready_output",
  ];
  const observedNonces = new Set();
  for (const behavior of behaviors) {
    for (let iteration = 0; iteration < 2; iteration += 1) {
      const ownedWorker = worker(t);
      const label = `${behavior}-${iteration}`;
      const raw = await rawWatchdog(
        t,
        fixtureContract(ownedWorker.pid, {
          contractId: label,
          behavior,
          cleanupTimeoutMs: 300,
        }),
        label,
        {
          awaitReady: false,
          consumeStdout: behavior !== "watchdog_block_ready_output",
        },
      );
      const fields = await custodyTerminal(raw, 2000);
      assert.equal(observedNonces.has(fields[4]), false);
      observedNonces.add(fields[4]);
      const pids = await assertSingleCustodyCleanup(raw, fields, "startup_timeout");
      assert.deepEqual(readJournalEvents(raw), ["watchdog_started"]);
      await terminateBlockedWatchdog(raw, pids);
    }
  }
});

test("control close immediately redeems custody despite blocked fsync or READY output", async (t) => {
  for (const behavior of [
    "watchdog_block_first_journal_fsync",
    "watchdog_block_ready_output",
  ]) {
    const ownedWorker = worker(t);
    const label = `${behavior}-control-close`;
    const raw = await rawWatchdog(
      t,
      fixtureContract(ownedWorker.pid, {
        contractId: label,
        behavior,
        cleanupTimeoutMs: 300,
      }),
      label,
      {
        awaitReady: false,
        consumeStdout: behavior !== "watchdog_block_ready_output",
      },
    );
    const started = process.hrtime.bigint();
    raw.control.end();
    const fields = await custodyTerminal(raw, 2000);
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    const pids = await assertSingleCustodyCleanup(
      raw,
      fields,
      "control_channel_closed",
    );
    assert.ok(elapsedMs < 1000, `behavior=${behavior} elapsed=${elapsedMs}`);
    assert.ok(readJournalEvents(raw).every((event) => event === "watchdog_started"));
    await terminateBlockedWatchdog(raw, pids);
  }
});

test("an ARM arriving after custody expiry cannot revive the deadline", async (t) => {
  const ownedWorker = worker(t);
  const raw = await rawWatchdog(
    t,
    fixtureContract(ownedWorker.pid, {
      contractId: "custody_late_arm",
      behavior: "custody_late_arm_after_expiry",
      cleanupTimeoutMs: 300,
    }),
    "custody-late-arm",
    { awaitReady: false },
  );
  const fields = await custodyTerminal(raw, 2000);
  const pids = await assertSingleCustodyCleanup(raw, fields, "startup_timeout");
  const terminal = await rawTerminal(raw, 2000);
  assert.equal(terminal[2], "startup_timeout");
  assert.equal(terminal[4], "fixture_acknowledged_rf_unknown");
  assert.equal(terminal[11], fields[21]);
  assert.equal(terminal[13], fields[6]);
  assert.equal(raw.child.exitCode, 86);
  assert.deepEqual(readJournalEvents(raw), [
    "watchdog_started",
    "cleanup_triggered",
    "cleanup_finished",
    "terminal_quarantine",
  ]);
  await waitForProcessGone(pids.watcherPid);
  await waitForProcessGone(pids.custodianPid);
  await waitForProcessGone(pids.cleanupPid);
});

test("READY waits for a delayed authenticated ARM acceptance", async (t) => {
  const ownedWorker = worker(t);
  const root = fixtureRoot(t);
  const started = process.hrtime.bigint();
  const controller = await api.launchDarwinSafetyDeadmanFixture(
    fixturePlan(ownedWorker.pid, {
      contractId: "delayed_arm_acceptance",
      behavior: "custody_delay_arm_ack",
      cleanupTimeoutMs: 300,
    }),
    { version: 1, journal_path: journalPath(root, "delayed-arm-acceptance") },
  );
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  assert.ok(elapsedMs >= 60, `READY arrived before custody acceptance: ${elapsedMs}`);
  const result = await controller.stop("operator_stop");
  assert.equal(result.reason_code, "operator_stop");
});

test("expired, forged, and pipe-only ARM acknowledgments never return a controller", async (t) => {
  const root = fixtureRoot(t);
  for (const behavior of [
    "custody_expired_arm_ack",
    "custody_forged_arm_ack",
    "custody_pipe_only_arm",
  ]) {
    const ownedWorker = worker(t);
    await assert.rejects(
      api.launchDarwinSafetyDeadmanFixture(
        fixturePlan(ownedWorker.pid, {
          contractId: `${behavior}_rejects`,
          behavior,
          heartbeatMs: 30,
          missTolerance: 2,
          cleanupTimeoutMs: 300,
        }),
        { version: 1, journal_path: journalPath(root, `${behavior}-rejects`) },
      ),
      (error) => {
        assert.match(error?.code || "", /^darwin_safety_/u);
        assert.equal(error?.message, "Darwin safety deadman fixture was rejected");
        return true;
      },
    );
  }
});

test("late, forged, replayed, and reordered EXTENDED acknowledgments cannot satisfy readiness", async (t) => {
  const root = fixtureRoot(t);
  for (const behavior of [
    "custody_late_extend_ack",
    "custody_forged_extend_ack",
    "custody_replayed_extend_ack",
    "custody_reordered_extend_ack",
  ]) {
    const ownedWorker = worker(t);
    await assert.rejects(
      api.launchDarwinSafetyDeadmanFixture(
        fixturePlan(ownedWorker.pid, {
          contractId: `${behavior}_rejects`,
          behavior,
          heartbeatMs: 30,
          missTolerance: 2,
          cleanupTimeoutMs: 300,
        }),
        { version: 1, journal_path: journalPath(root, `${behavior}-rejects`) },
      ),
      (error) => {
        assert.match(error?.code || "", /^darwin_safety_/u);
        assert.equal(error?.message, "Darwin safety deadman fixture was rejected");
        return true;
      },
    );
  }
});

test("READY delivered after its signed custody window cannot return a controller", async (t) => {
  const ownedWorker = worker(t);
  const root = fixtureRoot(t);
  const journal = journalPath(root, "host-delayed-ready");
  const launch = api.launchDarwinSafetyDeadmanFixture(
    fixturePlan(ownedWorker.pid, {
      contractId: "host_delayed_ready",
      heartbeatMs: 30,
      missTolerance: 2,
      cleanupTimeoutMs: 300,
    }),
    { version: 1, journal_path: journal },
  );
  // The native watcher continues independently while JavaScript cannot
  // consume READY. Observing its durable start makes the delay deterministic.
  blockUntilFileContains(journal, "watchdog_started");
  blockEventLoop(150);
  await assert.rejects(launch, (error) => {
    assert.match(error?.code || "", /^darwin_safety_/u);
    assert.equal(error?.message, "Darwin safety deadman fixture was rejected");
    return true;
  });
});

test("custody expiring after ACK but before launch continuation cannot return a controller", async (t) => {
  const ownedWorker = worker(t);
  const root = fixtureRoot(t);
  const capturedPromises = [];
  let capture = false;
  let readyPromiseId = null;
  let stalled = false;
  const hook = asyncHooks.createHook({
    init(asyncId, type, triggerAsyncId, resource) {
      if (capture && type === "PROMISE") {
        capturedPromises.push({ asyncId, resource, triggerAsyncId });
      }
    },
    promiseResolve(asyncId) {
      if (asyncId === readyPromiseId && !stalled) {
        stalled = true;
        blockEventLoop(150);
      }
    },
  });
  hook.enable();
  let launch;
  try {
    capture = true;
    launch = api.launchDarwinSafetyDeadmanFixture(
      fixturePlan(ownedWorker.pid, {
        contractId: "post_ack_pre_delivery_expiry",
        behavior: "stuck",
        heartbeatMs: 30,
        missTolerance: 2,
        cleanupTimeoutMs: 300,
      }),
      { version: 1, journal_path: journalPath(root, "post-ack-pre-delivery") },
    );
    capture = false;
    const launchRecord = capturedPromises.find((record) => record.resource === launch);
    const readyCandidates = capturedPromises.filter((record) =>
      record.asyncId !== launchRecord?.asyncId
      && capturedPromises.some((candidate) =>
        candidate.triggerAsyncId === record.asyncId));
    assert.equal(readyCandidates.length, 1);
    readyPromiseId = readyCandidates[0].asyncId;
    await assert.rejects(
      launch,
      (error) => safeError(error, "darwin_safety_custody_deadline_expired"),
    );
    assert.equal(stalled, true);
  } finally {
    capture = false;
    hook.disable();
    if (launch) await launch.catch(() => null);
  }
});

test("an expired active deadline synchronously refuses every controller command", async (t) => {
  const root = fixtureRoot(t);
  for (const command of ["heartbeat", "stop", "close"]) {
    const ownedWorker = worker(t);
    const controller = await api.launchDarwinSafetyDeadmanFixture(
      fixturePlan(ownedWorker.pid, {
        contractId: `expired_active_${command}`,
        heartbeatMs: 30,
        missTolerance: 2,
        cleanupTimeoutMs: 300,
      }),
      { version: 1, journal_path: journalPath(root, `expired-active-${command}`) },
    );
    // Native timeout/cleanup can finish while queued JS stream callbacks remain
    // unprocessed. The synchronous command gate must consult the signed active
    // deadline rather than stale `ready` state.
    blockEventLoop(150);
    assert.throws(() => {
      if (command === "heartbeat") controller.heartbeat();
      else if (command === "stop") controller.stop("operator_stop");
      else controller.closeControlForFixture();
    }, (error) => safeError(error, "darwin_safety_custody_deadline_expired"));
    assert.throws(() => controller.heartbeat(), safeError);
    const result = await controller.waitForTerminal();
    assert.equal(result.reason_code, "deadman_timeout");
  }
});

test("an ACK delivered after its signed deadline cannot revive caller-visible custody", async (t) => {
  const ownedWorker = worker(t);
  const root = fixtureRoot(t);
  const controller = await api.launchDarwinSafetyDeadmanFixture(
    fixturePlan(ownedWorker.pid, {
      contractId: "host_delayed_extend_ack",
      heartbeatMs: 30,
      missTolerance: 2,
      cleanupTimeoutMs: 300,
    }),
    { version: 1, journal_path: journalPath(root, "host-delayed-extend-ack") },
  );
  const heartbeat = controller.heartbeat();
  // The ACK is generated promptly, but its JavaScript delivery is later than
  // the signed deadline. The native path still owns cleanup and terminal
  // evidence while the host-side promise is refused.
  blockEventLoop(150);
  await assert.rejects(
    heartbeat,
    (error) => safeError(error, "darwin_safety_custody_ack_delivery_expired"),
  );
  assert.throws(() => controller.heartbeat(), safeError);
  let result;
  try {
    result = await controller.waitForTerminal();
  } catch (error) {
    assert.fail(`unexpected terminal rejection: ${error?.code || "missing_code"}`);
  }
  assert.equal(result.reason_code, "deadman_timeout");
  assert.equal(result.quarantined, true);
});

test("cleanup custody survives watcher-group termination outside the launcher group", async (t) => {
  const ownedWorker = worker(t);
  const raw = await rawWatchdog(
    t,
    fixtureContract(ownedWorker.pid, {
      contractId: "watcher_group_termination",
      cleanupTimeoutMs: 300,
    }),
    "watcher-group-termination",
  );
  process.kill(-raw.child.pid, "SIGKILL");
  const fields = await custodyTerminal(raw, 2000);
  const pids = await assertSingleCustodyCleanup(
    raw,
    fields,
    ["watchdog_process_exit", "custody_channel_closed"],
  );
  assert.deepEqual(await waitForChildExit(raw.child, 1000), {
    code: null,
    signal: "SIGKILL",
  });
  await waitForProcessGone(pids.custodianPid);
});

test("cleanup custody survives active-worker-group termination", async (t) => {
  const ownedWorker = isolatedWorkerGroup(t);
  const raw = await rawWatchdog(
    t,
    fixtureContract(ownedWorker.pid, {
      contractId: "active_worker_group_termination",
      cleanupTimeoutMs: 300,
    }),
    "active-worker-group-termination",
  );
  process.kill(-ownedWorker.pid, "SIGKILL");
  const fields = await custodyTerminal(raw, 2000);
  const pids = await assertSingleCustodyCleanup(raw, fields, "worker_process_exit");
  const terminal = await rawTerminal(raw, 2000);
  assert.equal(terminal[2], "worker_process_exit");
  assert.equal(terminal[11], String(pids.cleanupPid));
  assert.equal(terminal[13], String(pids.custodianPid));
});

test("the JS launcher rejects blocked pre-READY effects and never returns a controller", async (t) => {
  const root = fixtureRoot(t);
  const attempts = [
    "watchdog_block_first_journal_fsync",
    "watchdog_block_ready_output",
  ].map(async (behavior) => {
    const ownedWorker = worker(t);
    await assert.rejects(
      api.launchDarwinSafetyDeadmanFixture(
        fixturePlan(ownedWorker.pid, {
          contractId: `${behavior}_js_rejects`,
          behavior,
          cleanupTimeoutMs: 150,
        }),
        {
          version: 1,
          journal_path: journalPath(root, `${behavior}-js-rejects`),
        },
      ),
      (error) => {
        assert.ok([
          "darwin_safety_custody_pre_ready_terminal",
          "darwin_safety_native_output_rejected",
        ].includes(error?.code), error?.code);
        assert.equal(error?.message, "Darwin safety deadman fixture was rejected");
        assert.equal(Object.hasOwn(error, "path"), false);
        assert.equal(Object.hasOwn(error, "pid"), false);
        return true;
      },
    );
  });
  await Promise.all(attempts);
});

test("cleanup child self-deadline survives a watcher stall after handoff", async (t) => {
  const ownedWorker = worker(t);
  const raw = await rawWatchdog(
    t,
    fixtureContract(ownedWorker.pid, {
      contractId: "watcher_stall_after_handoff",
      behavior: "watchdog_stall_after_cleanup_handoff",
      cleanupTimeoutMs: 300,
    }),
    "watcher-stall-after-handoff",
  );
  raw.control.write(stopRecord(raw));
  const orphan = (await raw.nextCustody(1000)).split("\t");
  assert.deepEqual(orphan.slice(0, 3), [
    "ORPHAN1", orphan[1], "parent_stall_after_handoff",
  ]);
  const cleanupPid = Number(orphan[1]);
  assert.ok(Number.isSafeInteger(cleanupPid) && cleanupPid > 1);
  const observation = (await raw.nextCustody(1000)).split("\t");
  assert.deepEqual(observation, [
    "ORPHAN1", orphan[1], "cleanup_self_deadline_observed",
  ]);
  await waitForProcessGone(cleanupPid);
  const terminal = await rawTerminal(raw, 1500);
  assert.equal(terminal[2], "custody_receipt_rejected");
  assert.equal(terminal[4], "custody_receipt_rejected");
  assert.equal(terminal[5], "unknown");
  assert.equal(terminal[6], "true");
  assert.equal(raw.child.exitCode, 85);
});

test("cleanup child rejects watcher death before kqueue registration", async (t) => {
  const ownedWorker = worker(t);
  const raw = await rawWatchdog(
    t,
    fixtureContract(ownedWorker.pid, {
      contractId: "watcher_exit_before_guard",
      behavior: "watchdog_exit_before_cleanup_guard",
      cleanupTimeoutMs: 300,
    }),
    "watcher-exit-before-guard",
  );
  raw.control.write(stopRecord(raw));
  const orphan = (await raw.nextCustody(1000)).split("\t");
  assert.equal(orphan[0], "ORPHAN1");
  assert.equal(orphan[2], "parent_exit_before_guard");
  const cleanupPid = Number(orphan[1]);
  const exit = await waitForChildExit(raw.child, 1000);
  assert.deepEqual(exit, { code: 85, signal: null });
  await waitForProcessGone(cleanupPid);
});

test("cleanup child observes watcher death after kqueue registration", async (t) => {
  const ownedWorker = worker(t);
  const raw = await rawWatchdog(
    t,
    fixtureContract(ownedWorker.pid, {
      contractId: "watcher_exit_after_guard",
      behavior: "watchdog_exit_after_cleanup_guard",
      cleanupTimeoutMs: 500,
    }),
    "watcher-exit-after-guard",
  );
  raw.control.write(stopRecord(raw));
  const orphan = (await raw.nextCustody(1500)).split("\t");
  assert.equal(orphan[0], "ORPHAN1");
  assert.equal(orphan[2], "parent_exit_after_guard");
  const cleanupPid = Number(orphan[1]);
  const exit = await waitForChildExit(raw.child, 1000);
  assert.deepEqual(exit, { code: 85, signal: null });
  await waitForProcessGone(cleanupPid);
});

test("JS supervisor never returns a controller when the watcher stalls after READY", async (t) => {
  const ownedWorker = worker(t);
  const root = fixtureRoot(t);
  const started = process.hrtime.bigint();
  await assert.rejects(
    api.launchDarwinSafetyDeadmanFixture(
      fixturePlan(ownedWorker.pid, {
        behavior: "watchdog_stall_after_ready",
        heartbeatMs: 10,
        missTolerance: 1,
        cleanupTimeoutMs: 10,
      }),
      { version: 1, journal_path: journalPath(root, "watcher-stall-after-ready") },
    ),
    (error) => safeError(error, "darwin_safety_watchdog_shutdown_timeout"),
  );
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  assert.ok(elapsedMs >= 4500 && elapsedMs < 8000, `elapsed=${elapsedMs}`);
});

test("replayed and stale signed heartbeats fail closed and run only precommitted cleanup", async (t) => {
  for (const scenario of ["replay", "stale"]) {
    const ownedWorker = worker(t);
    const contract = fixtureContract(ownedWorker.pid, {
      contractId: `raw_${scenario}`,
      heartbeatMs: 100,
      missTolerance: 3,
    });
    const raw = await rawWatchdog(t, contract, `raw-${scenario}`);
    if (scenario === "replay") {
      const record = heartbeatRecord(raw, 1);
      raw.control.write(record);
      const ack = (await raw.nextLine()).split("\t");
      assert.equal(ack[0], "ACK1", ack.join(" | "));
      raw.control.write(record);
    } else {
      raw.control.write(heartbeatRecord(raw, 1, { issued: 1n, valid: 2n }));
    }
    const terminal = await rawTerminal(raw);
    assert.equal(terminal[2], scenario === "replay" ? "heartbeat_replay" : "heartbeat_stale");
    assert.equal(terminal[4], "fixture_acknowledged_rf_unknown");
    assert.equal(terminal[5], "unknown");
  }
});

test("wrong instrument, lease, cleanup capability, and restore bindings cannot redirect cleanup", async (t) => {
  const mutations = [
    ["instrument", digest("wrong-instrument")],
    ["lease", digest("wrong-lease")],
    ["cleanup", digest("wrong-cleanup")],
    ["restore", digest("wrong-restore")],
  ];
  for (let index = 0; index < mutations.length; index += 1) {
    const ownedWorker = worker(t);
    const contract = fixtureContract(ownedWorker.pid, {
      contractId: `wrong_binding_${index}`,
      cleanupTimeoutMs: 300,
    });
    const raw = await rawWatchdog(t, contract, `wrong-binding-${index}`);
    const options = { [mutations[index][0]]: mutations[index][1] };
    raw.control.write(heartbeatRecord(raw, 1, options));
    const terminal = await rawTerminal(raw);
    assert.equal(terminal[2], "protocol_binding_mismatch");
    assert.equal(terminal[4], "fixture_acknowledged_rf_unknown");
  }
});

test("a widened stop record is rejected; the cleanup worker receives no operation selector", async (t) => {
  const ownedWorker = worker(t);
  const raw = await rawWatchdog(
    t,
    fixtureContract(ownedWorker.pid, {
      contractId: "widened_stop",
      cleanupTimeoutMs: 300,
    }),
    "widened-stop",
  );
  const issued = process.hrtime.bigint();
  const valid = issued + 300000000n;
  const widened = [
    "STOP1", "1", "1", "operator_stop", String(issued), String(valid),
    ...protocolBindings(raw),
    "instrument.administer",
  ];
  raw.control.write(hmacLine(widened, raw.key));
  const terminal = await rawTerminal(raw);
  assert.equal(terminal[2], "cleanup_operation_widening_rejected");
  assert.equal(terminal[4], "fixture_acknowledged_rf_unknown");
});

test("contract widening and wrong precommitted digests are rejected before process launch", (t) => {
  const ownedWorker = worker(t);
  const contract = fixtureContract(ownedWorker.pid);
  assert.throws(
    () => api.createDarwinSafetyDeadmanFixturePlan({
      version: 1,
      contract: { ...contract, allowed_operation_ids: ["instrument.destroy"] },
      contract_digest: api.deriveDarwinSafetyDeadmanContractDigest(contract),
    }),
    safeError,
  );
  assert.throws(
    () => api.createDarwinSafetyDeadmanFixturePlan({
      version: 1,
      contract,
      contract_digest: digest("wrong-contract"),
    }),
    safeError,
  );
});

test("captured plan intrinsics survive mutation while launch and spawn substitution fail closed", async () => {
  const source = String.raw`
process.env.BOB_DARWIN_SAFETY_DEADMAN_FIXTURE = "1";
const [modulePath, executablePath] = process.argv.slice(1);
const api = require(modulePath);
const childProcess = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const utilTypes = require("node:util").types;
const worker = childProcess.spawn("/bin/sleep", ["60"], {stdio:"ignore"});
const d = (label) => "a".repeat(64);
const basis = {
  version:1, contract_id:"prototype_fixture", fixture_only:true,
  instrument_ref_digest:d(), lease_id_digest:d(), fencing_token_digest:d(),
  fencing_generation:1, worker_pid:worker.pid, worker_identity_digest:d(),
  cleanup_capability_digest:d(), restore_digest:d(), cleanup_provider_manifest_digest:d(),
  journal_id_digest:d(), heartbeat_interval_ms:100, miss_tolerance:3,
  cleanup_timeout_ms:100, mf1_field_off_reset_restore:null, fixture_cleanup_behavior:"ack",
};
const originals = {
  iterator:Array.prototype[Symbol.iterator], isArray:Array.isArray,
  number:Number.isSafeInteger, regexp:RegExp.prototype.test,
  weakGet:WeakMap.prototype.get, weakSet:WeakMap.prototype.set,
  weakAdd:WeakSet.prototype.add, weakHas:WeakSet.prototype.has,
  cryptoHash:crypto.createHash, cryptoHmac:crypto.createHmac, random:crypto.randomBytes,
  fill:Buffer.prototype.fill, toString:Buffer.prototype.toString,
  utilProxy:utilTypes.isProxy,
};
let invoked="none";
const poison = (name) => () => { invoked=name; throw new Error("ambient callback invoked"); };
Array.prototype[Symbol.iterator]=poison("array.iterator"); Array.isArray=poison("array.isArray"); Number.isSafeInteger=poison("number.isSafeInteger");
RegExp.prototype.test=poison("regexp.test"); WeakMap.prototype.get=poison("weakmap.get"); WeakMap.prototype.set=poison("weakmap.set");
WeakSet.prototype.add=poison("weakset.add"); WeakSet.prototype.has=poison("weakset.has"); crypto.createHash=poison("crypto.hash");
crypto.createHmac=poison("crypto.hmac"); crypto.randomBytes=poison("crypto.random"); Buffer.prototype.fill=poison("buffer.fill");
Buffer.prototype.toString=poison("buffer.toString"); utilTypes.isProxy=poison("util.isProxy");
let rejection;
let journal;
try {
  const plan=api.createDarwinSafetyDeadmanFixturePlan({version:1,contract:basis,
    contract_digest:api.deriveDarwinSafetyDeadmanContractDigest(basis)});
  const root=fs.mkdtempSync(path.join(os.tmpdir(),"bob-safety-prototype-")); fs.chmodSync(root,0o700);
  journal=path.join(root,"prototype.journal");
  try { await api.launchDarwinSafetyDeadmanFixture(plan,{version:1,journal_path:journal}); }
  catch (error) { rejection=error; }
} finally {
  Array.prototype[Symbol.iterator]=originals.iterator; Array.isArray=originals.isArray;
  Number.isSafeInteger=originals.number; RegExp.prototype.test=originals.regexp;
  WeakMap.prototype.get=originals.weakGet; WeakMap.prototype.set=originals.weakSet;
  WeakSet.prototype.add=originals.weakAdd; WeakSet.prototype.has=originals.weakHas;
  crypto.createHash=originals.cryptoHash; crypto.createHmac=originals.cryptoHmac;
  crypto.randomBytes=originals.random; Buffer.prototype.fill=originals.fill;
  Buffer.prototype.toString=originals.toString; utilTypes.isProxy=originals.utilProxy;
  worker.kill("SIGKILL");
}
if (invoked !== "none" || rejection?.code !== "darwin_safety_host_runtime_rejected"
    || fs.existsSync(journal)) process.exit(2);
`;
  const result = childProcess.spawnSync(
    process.execPath,
    ["-e", `(async()=>{${source}})().catch((error)=>{console.error(error?.code,error?.stack);process.exit(3)})`, MODULE_PATH, EXECUTABLE_PATH],
    {
      encoding: "utf8",
      env: { ...process.env, BOB_DARWIN_SAFETY_DEADMAN_FIXTURE: "1" },
      timeout: 5000,
    },
  );
  assert.equal(result.status, 0, result.stderr || result.stdout || result.error?.message);

  const ownedWorker = childProcess.spawn("/bin/sleep", ["60"], { stdio: "ignore" });
  try {
    const contract = fixtureContract(ownedWorker.pid, { contractId: "spawn_substitution" });
    const plan = api.createDarwinSafetyDeadmanFixturePlan({
      version: 1,
      contract,
      contract_digest: api.deriveDarwinSafetyDeadmanContractDigest(contract),
    });
    const original = childProcess.spawn;
    childProcess.spawn = () => { throw new Error("substituted spawn"); };
    try {
      await assert.rejects(
        api.launchDarwinSafetyDeadmanFixture(plan, {
          version: 1,
          journal_path: path.join(os.tmpdir(), "never-created.journal"),
        }),
        (error) => safeError(error, "darwin_safety_host_runtime_rejected"),
      );
    } finally {
      childProcess.spawn = original;
    }
    await assert.rejects(
      api.launchDarwinSafetyDeadmanFixture(plan, {
        version: 1,
        journal_path: path.join(os.tmpdir(), "never-created-again.journal"),
      }),
      safeError,
    );
  } finally {
    ownedWorker.kill("SIGKILL");
  }
});
