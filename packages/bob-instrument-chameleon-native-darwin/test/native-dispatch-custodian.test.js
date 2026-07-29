"use strict";

const assert = require("node:assert/strict");
const childProcess = require("node:child_process");
const crypto = require("node:crypto");
const events = require("node:events");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const readline = require("node:readline");
const test = require("node:test");

const BROKER_CONTRACT = require("../../bob-instrument-broker/lib/native-dispatch-contract.js");
const { createArtifactVault } = require("../../bob-artifact-vault/index.js");
const {
  assertProviderResponseRawCustodyReceipt,
  assertProviderResponseSinkCommit,
  consumeNativeProviderResponseRecord,
  createProviderResponseSink,
  nativeProviderResponseSinkWriteDescriptor,
  prepareNativeProviderResponseSink,
} = require("../../bob-artifact-vault/worker.js");
const {
  createInProcessBackupKeyCustodyFixture,
} = require("../../../test/helpers/artifact-vault-backup-key-custody.js");
const CUSTODIAN = require("../lib/native-dispatch-custodian.js");
const NATIVE_BOOTSTRAP_SEMANTICS = CUSTODIAN.CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS;
const ENTRY_PATH = path.join(__dirname, "..", "lib", "native-dispatch-custodian-entry.js");
const RUNNER_PATH = path.join(__dirname, "fixtures", "native-dispatch-custodian-runner.js");
const NODE20 = process.execPath;
const ZERO_DIGEST = "0000000000000000000000000000000000000000000000000000000000000000";
const INTEGRATION_SESSION_HASH = "c".repeat(64);
const EXECUTION_LINEAGE_DOMAIN =
  "hacker-bob/provider-worker-vault-execution-lineage/v1";
const RESPONSE_SINK_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "bob-native-response-sink-"));
const OPEN_RESPONSE_SINK_FDS = new Set();
test.after(() => {
  for (const fd of OPEN_RESPONSE_SINK_FDS) {
    try { fs.closeSync(fd); } catch {}
  }
  fs.rmSync(RESPONSE_SINK_ROOT, { recursive: true, force: true });
});

function digest(label) {
  return crypto.createHash("sha256")
    .update(`native-dispatch-custodian-test:${label}`, "utf8").digest("hex");
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value != null && typeof value === "object") {
    const output = {};
    for (const key of Object.keys(value).sort()) {
      if (value[key] !== undefined) output[key] = canonicalize(value[key]);
    }
    return output;
  }
  return value;
}

function digestRecord(domain, projection) {
  return crypto.createHash("sha256")
    .update(JSON.stringify(canonicalize({ domain, ...projection })), "utf8").digest("hex");
}

function futureIso(minutes = 30) {
  return new Date(Date.now() + minutes * 60_000).toISOString();
}

function inMemoryAnchor(digestField) {
  const states = new Map();
  return Object.freeze({
    readState({ vault_slot: vaultSlot }) {
      const state = states.get(vaultSlot);
      return state == null ? null : structuredClone(state);
    },
    compareAndSet(request) {
      const current = states.get(request.vault_slot) || null;
      const matches = current == null
        ? request.expected_generation == null && request[`expected_${digestField}`] == null
        : request.expected_generation === current.generation
          && request[`expected_${digestField}`] === current[digestField];
      if (!matches) return false;
      states.set(request.vault_slot, structuredClone(request.next_state));
      return true;
    },
  });
}

function integrationVault(t) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "bob-native-vault-integration-"));
  const root = path.join(parent, "vault");
  const vaultId = `vault:v1:${crypto.randomBytes(32).toString("base64url")}`;
  const vaultSlot = `vault-slot:v1:${crypto.randomBytes(32).toString("base64url")}`;
  const masterKey = crypto.randomBytes(32);
  const custody = createInProcessBackupKeyCustodyFixture({
    vaultId,
    vaultSlot,
    sessionNucleusHash: INTEGRATION_SESSION_HASH,
  });
  const vault = createArtifactVault({
    root,
    sessionNucleusHash: INTEGRATION_SESSION_HASH,
    vaultId,
    vaultSlot,
    createNew: true,
    masterKey,
    backupKeyCustody: custody.port,
    deletionLedgerAnchor: inMemoryAnchor("ledger_digest"),
    indexStateAnchor: inMemoryAnchor("index_digest"),
    quotaBytes: 2 * 1024 * 1024,
    maxArtifacts: 64,
    minFreeBytes: 0,
  });
  t.after(() => {
    try { vault.destroy(); } catch {}
    custody.destroy();
    masterKey.fill(0);
    fs.rmSync(parent, { recursive: true, force: true });
  });
  return { root, vault };
}

function integratedLineage(sink, reservationRequest, label) {
  const hash = (field) => digest(`${label}:${field}`);
  const basis = {
    version: 1,
    execution_ref: `execution:${label}`,
    experiment_plan_hash: hash("experiment-plan"),
    exchange_id: `exchange:${label}`,
    grant_envelope_digest: hash("grant-envelope"),
    grant_journal_entry_digest: hash("grant-journal"),
    go_envelope_digest: hash("go-envelope"),
    go_journal_entry_digest: hash("go-journal"),
    session_nucleus_hash: INTEGRATION_SESSION_HASH,
    task_id: reservationRequest.task_id,
    attempt_id: reservationRequest.attempt_id,
    lease_id: `lease:${label}`,
    resource_epoch: "1",
    resource_fence_digest: hash("resource-fence"),
    effect_deadline_monotonic_ns: "18446744073709551615",
    safety_supervisor_plan_digest: hash("safety-plan"),
    provider_id: "chameleon_ultra",
    operation_id: "get_app_version",
    compiler_id: "compiler:chameleon-v1",
    compiler_manifest_digest: hash("compiler-manifest"),
    compiler_registry_digest: hash("compiler-registry"),
    source_profile_digest: hash("source-profile"),
    schema_id: "schema:chameleon-v1",
    capability_id: "capability:get-app-version",
    variant_id: "variant:fixture-native",
    parameter_selector_id: "selector:none",
    canonical_command_digest: hash("canonical-command"),
    compiled_operation_digest: hash("compiled-operation"),
    provider_command_ref: `provider-command:${label}`,
    requested_effects_digest: hash("requested-effects"),
    runtime_availability: "runtime:darwin-native-fixture",
    compiled_command_id: `compiled-command:${label}`,
    compiled_command_capability_digest: hash("compiled-capability"),
    expected_result_code: "get_app_version_ok",
    active_command_input_ref: `command-input:active-${label}`,
    active_command_input_digest: hash("active-command-input"),
    cleanup_command_input_ref: `command-input:cleanup-${label}`,
    cleanup_command_input_digest: hash("cleanup-command-input"),
    maximum_response_bytes: sink.byte_ceiling,
    worker_bundle_digest: hash("worker-bundle"),
    worker_launch_digest: hash("worker-launch"),
    worker_process_instance_digest: hash("worker-process"),
    worker_fence_digest: hash("worker-fence"),
    transport_binding_digest: hash("transport-binding"),
    vault_reservation_handle: sink.vault_reservation_handle,
    vault_reservation_digest: sink.vault_reservation_digest,
    vault_ingest_capability_digest: sink.vault_ingest_capability_digest,
    vault_byte_ceiling: sink.byte_ceiling,
    durable_exchange_plan_digest: hash("durable-exchange-plan"),
    terminal_receipt_recipient_digest: hash("terminal-receipt-recipient"),
  };
  return {
    ...basis,
    execution_lineage_digest: digestRecord(EXECUTION_LINEAGE_DOMAIN, basis),
  };
}

function lrc(bytes) {
  let sum = 0;
  for (const byte of bytes) sum = (sum + byte) & 0xff;
  return (-sum) & 0xff;
}

function frame(commandId, data = Buffer.alloc(0), status = 0) {
  const output = Buffer.alloc(10 + data.length);
  output[0] = 0x11;
  output[1] = 0xef;
  output.writeUInt16BE(commandId, 2);
  output.writeUInt16BE(status, 4);
  output.writeUInt16BE(data.length, 6);
  output[8] = lrc(output.subarray(2, 8));
  data.copy(output, 9);
  output[output.length - 1] = lrc(data);
  return output;
}

function nativeBootstrapOperation(operationId) {
  const operation = NATIVE_BOOTSTRAP_SEMANTICS.operations.find(
    (entry) => entry.operation_id === operationId,
  );
  assert.ok(operation, `unknown fixture bootstrap operation: ${operationId}`);
  return operation;
}

function effectWindow(deadlineOffsetMs, notBeforeOffsetMs = -1000) {
  const now = process.hrtime.bigint();
  return {
    not_before_monotonic_ns: (now + BigInt(notBeforeOffsetMs) * 1000000n).toString(),
    deadline_monotonic_ns: (now + BigInt(deadlineOffsetMs) * 1000000n).toString(),
  };
}

function chunkBytes(bytes, widths = [1, 2, 7, 31, 127]) {
  const output = [];
  let offset = 0;
  let index = 0;
  while (offset < bytes.length) {
    const end = Math.min(bytes.length, offset + widths[index % widths.length]);
    output.push(bytes.subarray(offset, end));
    offset = end;
    index += 1;
  }
  return output;
}

function terminalResultBytes({
  status = 1,
  flags = 0,
  responseLength = 0,
  sequence = 0n,
  settled = 1n,
  envelopeDigest = ZERO_DIGEST,
  descriptorDigest = ZERO_DIGEST,
  responseDigest = ZERO_DIGEST,
  sinkDescriptorDigest = ZERO_DIGEST,
  sinkRecordDigest = ZERO_DIGEST,
} = {}) {
  const bytes = Buffer.alloc(CUSTODIAN.NATIVE_DISPATCH_TERMINAL_RESULT_BYTES);
  bytes.write("HBPHDRS1", 0, "ascii");
  bytes.writeUInt16BE(1, 8);
  bytes.writeUInt16BE(status, 10);
  bytes.writeUInt32BE(flags, 12);
  bytes.writeUInt32BE(responseLength, 16);
  bytes.writeBigUInt64BE(sequence, 20);
  bytes.writeBigUInt64BE(settled, 28);
  Buffer.from(envelopeDigest, "hex").copy(bytes, 36);
  Buffer.from(descriptorDigest, "hex").copy(bytes, 68);
  Buffer.from(responseDigest, "hex").copy(bytes, 100);
  Buffer.from(sinkDescriptorDigest, "hex").copy(bytes, 132);
  Buffer.from(sinkRecordDigest, "hex").copy(bytes, 164);
  return bytes;
}

function assertContractRejected(callback) {
  assert.throws(callback, (error) => {
    assert.equal(error.code, "darwin_native_dispatch_custodian_contract_rejected");
    assert.equal(error.message, "Darwin native dispatch custodian contract was rejected");
    return true;
  });
}

function ed25519KeyPairFromSeed(seedByte) {
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([prefix, Buffer.alloc(32, seedByte)]),
    format: "der",
    type: "pkcs8",
  });
  return { privateKey, publicKey: crypto.createPublicKey(privateKey) };
}

async function ptyFixture(t, behavior = "partial_success") {
  const source = String.raw`
import errno, os, pty, sys, time, tty
behavior = sys.argv[1]
master, slave = pty.openpty()
tty.setraw(slave)
print(os.ttyname(slave), flush=True)
pending = b""
def checksum(value): return (-sum(value)) & 0xff
def response(command, payload=b"fixture"):
    header = command.to_bytes(2, "big") + (0).to_bytes(2, "big") + len(payload).to_bytes(2, "big")
    return bytes([0x11, 0xef]) + header + bytes([checksum(header)]) + payload + bytes([checksum(payload)])
while True:
    try:
        chunk = os.read(master, 64 if behavior == "partial_write_stall" else 4096)
    except OSError as error:
        if error.errno == errno.EIO:
            time.sleep(0.005)
            continue
        break
    if not chunk:
        time.sleep(0.005)
        continue
    if behavior == "partial_write_stall":
        time.sleep(10)
        continue
    pending += chunk
    while len(pending) >= 10:
        expected = int.from_bytes(pending[6:8], "big") + 10
        if len(pending) < expected: break
        request, pending = pending[:expected], pending[expected:]
        command = int.from_bytes(request[2:4], "big")
        encoded = response(command)
        if behavior == "no_response": continue
        if behavior == "late_response":
            time.sleep(1.0)
            os.write(master, encoded)
            continue
        if behavior == "partial_response_stall":
            os.write(master, encoded[:4])
            time.sleep(10)
            continue
        if behavior == "duplicate_response":
            os.write(master, encoded + encoded)
            continue
        if behavior == "partial_success":
            for byte in encoded:
                os.write(master, bytes([byte]))
                time.sleep(0.001)
            continue
        os.write(master, encoded)
`;
  const child = childProcess.spawn("/usr/bin/python3", ["-u", "-c", source, behavior], {
    stdio: ["ignore", "pipe", "ignore"],
  });
  const lines = readline.createInterface({ input: child.stdout });
  const [devicePath] = await events.once(lines, "line");
  t.after(async () => {
    lines.close();
    child.kill("SIGKILL");
    await Promise.race([
      events.once(child, "exit"),
      new Promise((resolve) => setTimeout(resolve, 1000)),
    ]);
  });
  return devicePath;
}

async function auditedPtyFixture(t) {
  const source = String.raw`
import errno, fcntl, hashlib, json, os, pty, select, sys, time, tty
master, slave = pty.openpty()
tty.setraw(slave)
print(os.ttyname(slave), flush=True)
if not sys.stdin.readline(): sys.exit(70)
os.close(slave)
fcntl.fcntl(master, fcntl.F_SETFL, fcntl.fcntl(master, fcntl.F_GETFL) | os.O_NONBLOCK)
initial = bytearray()
total = bytearray()
deadline = time.monotonic() + 8.0
closed = False
while time.monotonic() < deadline:
    readable, _, _ = select.select([master], [], [], 0.05)
    if not readable: continue
    time.sleep(0.05)
    try:
        while True:
            chunk = os.read(master, 65536)
            if not chunk:
                closed = True
                break
            initial.extend(chunk)
            total.extend(chunk)
    except BlockingIOError:
        pass
    except OSError as error:
        if error.errno == errno.EIO:
            closed = True
        elif error.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
            raise
    if initial or closed: break
while not closed and time.monotonic() < deadline:
    readable, _, _ = select.select([master], [], [], 0.05)
    if not readable: continue
    try:
        chunk = os.read(master, 65536)
        if chunk:
            total.extend(chunk)
        else:
            closed = True
            break
    except OSError as error:
        if error.errno == errno.EIO:
            closed = True
            break
        if error.errno not in (errno.EAGAIN, errno.EWOULDBLOCK): raise
print(json.dumps({
    "closed": closed,
    "initial": len(initial),
    "total": len(total),
    "initial_sha256": hashlib.sha256(initial).hexdigest(),
    "total_sha256": hashlib.sha256(total).hexdigest(),
}), flush=True)
`;
  const child = childProcess.spawn("/usr/bin/python3", ["-u", "-c", source], {
    stdio: ["pipe", "pipe", "ignore"],
  });
  const lines = readline.createInterface({ input: child.stdout });
  const [devicePath] = await events.once(lines, "line");
  const observation = events.once(lines, "line").then(([line]) => JSON.parse(line));
  let released = false;
  t.after(async () => {
    lines.close();
    if (!released) child.stdin.destroy();
    if (child.exitCode == null && child.signalCode == null) {
      child.kill("SIGKILL");
      await Promise.race([
        events.once(child, "exit"),
        new Promise((resolve) => setTimeout(resolve, 1000)),
      ]);
    }
  });
  return {
    devicePath,
    observation,
    release() {
      if (released) throw new Error("audited PTY was already released");
      released = true;
      child.stdin.end("go\n");
    },
  };
}

function descriptorIdentity(fd) {
  const status = fs.fstatSync(fd, { bigint: true });
  return {
    version: 1,
    role: BROKER_CONTRACT.NATIVE_DELEGATED_DESCRIPTOR_ROLE,
    fd_number: BROKER_CONTRACT.NATIVE_DELEGATED_DESCRIPTOR_FD,
    purpose: BROKER_CONTRACT.NATIVE_DELEGATED_DESCRIPTOR_PURPOSE,
    dev: status.dev.toString(),
    ino: status.ino.toString(),
    rdev: status.rdev.toString(),
    mode: Number(status.mode),
    nlink: status.nlink.toString(),
    uid: Number(status.uid),
    gid: Number(status.gid),
    character_device: true,
    access_mode: BROKER_CONTRACT.NATIVE_DELEGATED_DESCRIPTOR_ACCESS_MODE,
    status_flags: BROKER_CONTRACT.NATIVE_DELEGATED_DESCRIPTOR_STATUS_FLAGS,
    fd_flags: BROKER_CONTRACT.NATIVE_DELEGATED_DESCRIPTOR_FD_FLAGS,
  };
}

function responseSinkDescriptorIdentity(fd) {
  const status = fs.fstatSync(fd, { bigint: true });
  return {
    version: 1,
    role: BROKER_CONTRACT.NATIVE_RESPONSE_SINK_DESCRIPTOR_ROLE,
    fd_number: BROKER_CONTRACT.NATIVE_RESPONSE_SINK_DESCRIPTOR_FD,
    purpose: BROKER_CONTRACT.NATIVE_RESPONSE_SINK_DESCRIPTOR_PURPOSE,
    dev: status.dev.toString(),
    ino: status.ino.toString(),
    rdev: status.rdev.toString(),
    mode: Number(status.mode),
    nlink: status.nlink.toString(),
    uid: Number(status.uid),
    gid: Number(status.gid),
    regular_file: true,
    access_mode: BROKER_CONTRACT.NATIVE_RESPONSE_SINK_DESCRIPTOR_ACCESS_MODE,
    status_flags: BROKER_CONTRACT.NATIVE_RESPONSE_SINK_DESCRIPTOR_STATUS_FLAGS,
    fd_flags: BROKER_CONTRACT.NATIVE_RESPONSE_SINK_DESCRIPTOR_FD_FLAGS,
    initial_size: status.size.toString(),
  };
}

function buildFixture(fd, overrides = {}) {
  const launcher = overrides.launcher || crypto.generateKeyPairSync("ed25519");
  const dispatch = overrides.dispatch || crypto.generateKeyPairSync("ed25519");
  const operationId = overrides.operation_id || "instrument.inventory";
  const operation = nativeBootstrapOperation(operationId);
  const commandSequence = overrides.command_sequence || 1;
  const commandSemantic = operation.commands.find(
    (entry) => entry.command_sequence === commandSequence,
  );
  const command = overrides.command || frame(commandSemantic?.command_id || 1000);
  const descriptorDigest = BROKER_CONTRACT.deriveNativeDelegatedDescriptorIdentityDigest(
    descriptorIdentity(fd),
  );
  const externalSink = Number.isSafeInteger(overrides.sink_fd);
  const sinkPath = externalSink ? null : path.join(RESPONSE_SINK_ROOT,
    `sink-${crypto.randomBytes(16).toString("hex")}.bin`);
  const sinkFd = externalSink ? overrides.sink_fd : fs.openSync(sinkPath,
    fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT | fs.constants.O_EXCL,
    0o600);
  if (!externalSink) OPEN_RESPONSE_SINK_FDS.add(sinkFd);
  const sinkDescriptorDigest = BROKER_CONTRACT.deriveNativeResponseSinkDescriptorIdentityDigest(
    responseSinkDescriptorIdentity(sinkFd),
  );
  const launcherSpki = launcher.publicKey.export({ type: "spki", format: "der" });
  const dispatchSpki = dispatch.publicKey.export({ type: "spki", format: "der" });
  const contextPayload = {
    version: 1,
    fixture_only: true,
    worker_uid: process.getuid(),
    worker_gid: process.getgid(),
    execution_principal_id: "principal:active-device-worker",
    worker_process_start_digest: digest("worker-start"),
    worker_bundle_digest: digest("worker-bundle"),
    native_loaded_image_identity_digest: digest("native-image"),
    provider_id: "chameleon_ultra",
    provider_descriptor_digest: digest("provider-descriptor"),
    provider_implementation_digest: digest("provider-implementation"),
    semantic_manifest_digest: NATIVE_BOOTSTRAP_SEMANTICS.semantic_manifest_digest,
    device_identity_digest: digest("device-identity"),
    device_enrollment_digest: digest("device-enrollment"),
    connection_generation: "1",
    launcher_ticket_digest: digest("launcher-ticket"),
    device_descriptor_inventory_digest: digest("descriptor-inventory"),
    delegated_descriptor_identity_digest: descriptorDigest,
    clock_epoch_digest: digest("clock-epoch"),
    dispatch_key_id: "dispatch-key:fixture-v1",
    dispatch_public_key_digest: crypto.createHash("sha256").update(dispatchSpki).digest("hex"),
    launcher_public_key_spki_der: launcherSpki,
    dispatch_public_key_spki_der: dispatchSpki,
    launch_nonce: Buffer.alloc(24, 7).toString("base64url"),
    execution_lineage_digest: digest("execution-lineage"),
    vault_reservation_digest: digest("vault-reservation"),
    vault_ingest_capability_digest: digest("vault-ingest-capability"),
    vault_sink_descriptor_identity_digest: sinkDescriptorDigest,
    vault_byte_ceiling: 4096,
    artifact_handle_digest: digest("artifact-handle"),
    bootstrap_manifest_digest: NATIVE_BOOTSTRAP_SEMANTICS.bootstrap_manifest_digest,
    bootstrap_operation_registry_digest:
      NATIVE_BOOTSTRAP_SEMANTICS.bootstrap_operation_registry_digest,
    bootstrap_command_set_digest: operation.command_set_digest,
    native_bootstrap_semantic_table_digest: NATIVE_BOOTSTRAP_SEMANTICS.table_digest,
    bootstrap_invariants_digest: NATIVE_BOOTSTRAP_SEMANTICS.bootstrap_invariants_digest,
    ...(overrides.context_payload || {}),
  };
  const context = CUSTODIAN.signNativeDispatchLauncherContext({
    payload: contextPayload,
    launcher_key_id: "launcher-key:fixture-v1",
    launcher_private_key: launcher.privateKey,
  });
  const now = process.hrtime.bigint();
  const payload = {
    version: 1,
    protocol: "hacker-bob/physical-native-dispatch/v1",
    grant_kind: "bootstrap",
    command_kind: "observe",
    effect_class: "none",
    rf_constraint: "rf_off",
    ticket_id: "native-ticket:fixture-1",
    ticket_nonce: Buffer.alloc(24, 9).toString("base64url"),
    ticket_sequence: "1",
    provider_id: contextPayload.provider_id,
    provider_descriptor_digest: contextPayload.provider_descriptor_digest,
    provider_implementation_digest: contextPayload.provider_implementation_digest,
    semantic_manifest_digest: contextPayload.semantic_manifest_digest,
    device_identity_digest: contextPayload.device_identity_digest,
    device_enrollment_digest: contextPayload.device_enrollment_digest,
    connection_generation: contextPayload.connection_generation,
    execution_principal_id: contextPayload.execution_principal_id,
    worker_process_start_digest: contextPayload.worker_process_start_digest,
    worker_bundle_digest: contextPayload.worker_bundle_digest,
    native_loaded_image_identity_digest: contextPayload.native_loaded_image_identity_digest,
    launcher_ticket_digest: contextPayload.launcher_ticket_digest,
    launcher_delegation_receipt_digest: context.context_digest,
    device_descriptor_inventory_digest: contextPayload.device_descriptor_inventory_digest,
    session_nucleus_hash: digest("session-nucleus"),
    node_id: "PH-P7",
    contract_hash: digest("contract"),
    attempt_ref: "attempt:fixture-1",
    signed_grant_digest: digest("signed-grant"),
    execution_request_digest: digest("execution-request"),
    authority_resolution_digest: digest("authority-resolution"),
    authority_epoch: "1",
    revocation_generation: "0",
    operation_id: operation.operation_id,
    operation_digest: operation.operation_digest,
    parameter_digest: digest("parameters"),
    requested_effects_digest: digest("effects"),
    required_pre_state_digest: digest("pre-state"),
    authorized_transition_digest: digest("transition"),
    resource_bundle_digest: digest("resource-bundle"),
    allocation_digest: digest("allocation"),
    reservation_receipt_digest: digest("reservation"),
    fencing_token_digest: digest("fence"),
    journal_entry_digest: digest("journal"),
    outbox_entry_digest: digest("outbox"),
    provider_redemption_digest: digest("redemption"),
    safety_contract_digest: digest("safety-contract"),
    safety_custody_receipt_digest: digest("safety-custody"),
    cleanup_precommit_digest: digest("cleanup-precommit"),
    observer_plan_digest: digest("observer-plan"),
    command_sequence: String(commandSequence),
    command_bytes_digest: crypto.createHash("sha256").update(command).digest("hex"),
    command_byte_length: command.length,
    maximum_response_bytes: 4096,
    clock_epoch_digest: contextPayload.clock_epoch_digest,
    not_before_monotonic_ns: (now - 1000000000n).toString(),
    deadline_monotonic_ns: (now + 3000000000n).toString(),
    one_use: true,
    delegated_descriptor_identity_digest: descriptorDigest,
    execution_lineage_digest: contextPayload.execution_lineage_digest,
    vault_reservation_digest: contextPayload.vault_reservation_digest,
    vault_ingest_capability_digest: contextPayload.vault_ingest_capability_digest,
    vault_sink_descriptor_identity_digest: sinkDescriptorDigest,
    vault_byte_ceiling: contextPayload.vault_byte_ceiling,
    artifact_handle_digest: contextPayload.artifact_handle_digest,
    ...(overrides.payload || {}),
  };
  const ticket = BROKER_CONTRACT.signNativeDispatchTicket({
    payload,
    key_id: overrides.ticket_key_id || contextPayload.dispatch_key_id,
    private_key: overrides.ticket_private_key || dispatch.privateKey,
  });
  const envelope = Buffer.from(ticket.envelope_b64, "base64url");
  return {
    command,
    context,
    contextBytes: CUSTODIAN.nativeDispatchLauncherContextBytes(context),
    contextPayload,
    descriptorDigest,
    dispatch,
    envelope,
    input: CUSTODIAN.encodeNativeDispatchCustodianInput({
      version: 1,
      envelope_bytes: envelope,
      command_bytes: command,
    }),
    launcher,
    payload,
    sinkDescriptorDigest,
    sinkOwnedExternally: externalSink,
    sinkFd,
    sinkPath,
    ticket,
  };
}

async function runFixture(fd, fixture, options = {}) {
  const entry = options.runner_mode ? RUNNER_PATH : ENTRY_PATH;
  const semanticArgs = options.runner_mode
    ? [entry, options.runner_mode]
    : [entry, "--fixture-native-dispatch-custodian-v1"];
  let controlMutation = "";
  if (options.control_mode === "alias_context_and_input") controlMutation = "os.dup2(3, 5)";
  else if (options.control_mode === "alias_sink_and_result") controlMutation = "os.dup2(6, 7)";
  else if (options.control_mode === "alias_result_to_device") controlMutation = "os.dup2(4, 6)";
  else if (options.control_mode === "alias_result_to_sink") controlMutation = "os.dup2(7, 6)";
  else if (options.control_mode === "nonblocking_context") {
    controlMutation = "fcntl.fcntl(3, fcntl.F_SETFL, fcntl.fcntl(3, fcntl.F_GETFL) | os.O_NONBLOCK)";
  } else if (options.control_mode != null) throw new Error("unknown test control mode");
  const launchSource = String.raw`
import fcntl, os, sys
for descriptor in (3, 4, 5, 6, 7): os.set_inheritable(descriptor, True)
flags = fcntl.fcntl(4, fcntl.F_GETFL)
fcntl.fcntl(4, fcntl.F_SETFL, flags | os.O_NONBLOCK)
${controlMutation}
os.execve(sys.argv[1], [sys.argv[1], *sys.argv[2:]], os.environ)
`;
  const environment = {
    ...process.env,
    ...(options.env || {}),
    BOB_CHAMELEON_DARWIN_NATIVE_DISPATCH_FIXTURE: "1",
  };
  if (options.fixture_gate === false) {
    delete environment.BOB_CHAMELEON_DARWIN_NATIVE_DISPATCH_FIXTURE;
  }
  const child = childProcess.spawn("/usr/bin/python3", [
    "-c",
    launchSource,
    NODE20,
    ...semanticArgs,
  ], {
    env: environment,
    stdio: ["ignore", "ignore", "ignore", "pipe", fd, "pipe", "pipe", fixture.sinkFd],
  });
  const exit = events.once(child, "exit");
  child.stdio[3].on("error", () => {});
  child.stdio[5].on("error", () => {});
  fs.closeSync(fd);
  if (!fixture.sinkOwnedExternally) {
    fs.closeSync(fixture.sinkFd);
    OPEN_RESPONSE_SINK_FDS.delete(fixture.sinkFd);
  }
  const resultChunks = [];
  child.stdio[6].on("data", (chunk) => resultChunks.push(chunk));
  if (options.context_chunks) {
    for (const chunk of options.context_chunks) child.stdio[3].write(chunk);
    child.stdio[3].end();
  } else child.stdio[3].end(fixture.contextBytes);
  if (options.input_chunks) {
    for (const chunk of options.input_chunks) child.stdio[5].write(chunk);
    child.stdio[5].end();
  } else child.stdio[5].end(fixture.input);
  const [code] = await exit;
  const bytes = Buffer.concat(resultChunks);
  return {
    bytes,
    code,
    result: bytes.length === CUSTODIAN.NATIVE_DISPATCH_TERMINAL_RESULT_BYTES
      ? CUSTODIAN.decodeNativeDispatchTerminalResult(bytes)
      : null,
    sinkBytes: fixture.sinkPath == null ? null : fs.readFileSync(fixture.sinkPath),
  };
}

test("import is inert and advertises the exact non-authorizing native boundary", () => {
  assert.equal(CUSTODIAN.DARWIN_NATIVE_DISPATCH_CUSTODIAN_ASSURANCE.production_ready, false);
  assert.deepEqual(CUSTODIAN.DARWIN_NATIVE_DISPATCH_CUSTODIAN_ASSURANCE.fixed_descriptor_map, {
    launcher_context_input: 3,
    launcher_delegated_device_transport: 4,
    dispatch_input: 5,
    redacted_terminal_result_output: 6,
    pre_reserved_response_vault_sink_output: 7,
  });
  assert.equal(CUSTODIAN.DARWIN_NATIVE_DISPATCH_CUSTODIAN_ASSURANCE.raw_response_bytes_projected,
    false);
  assert.ok(CUSTODIAN.DARWIN_NATIVE_DISPATCH_CUSTODIAN_ASSURANCE.production_blockers.includes(
    "independent_production_vault_sink_owner_and_signed_ingest_receipt_missing",
  ));
  assert.ok(CUSTODIAN.DARWIN_NATIVE_DISPATCH_CUSTODIAN_ASSURANCE.production_blockers.includes(
    "native_bootstrap_source_owned_multi_response_aggregation_missing",
  ));
  assert.equal(typeof CUSTODIAN.open, "undefined");
  assert.equal(typeof CUSTODIAN.dispatch, "undefined");
});

test("terminal result decoder accepts only coherent native settlement states", () => {
  const envelopeDigest = digest("terminal-envelope");
  const descriptorDigest = digest("terminal-descriptor");
  const responseDigest = digest("terminal-response");
  const sinkDescriptorDigest = digest("terminal-sink-descriptor");
  const sinkRecordDigest = digest("terminal-sink-record");
  const valid = [
    {
      label: "pre-descriptor rejection",
      bytes: terminalResultBytes(),
      status: "rejected_no_effect",
      responseLength: 0,
    },
    {
      label: "post-descriptor rejection",
      bytes: terminalResultBytes({ flags: 4, descriptorDigest }),
      status: "rejected_no_effect",
      responseLength: 0,
    },
    {
      label: "post-signature rejection",
      bytes: terminalResultBytes({
        flags: 6,
        sequence: 1n,
        envelopeDigest,
        descriptorDigest,
      }),
      status: "rejected_no_effect",
      responseLength: 0,
    },
    {
      label: "ambiguous with no response bytes observed",
      bytes: terminalResultBytes({
        status: 2,
        flags: 15,
        sequence: 1n,
        envelopeDigest,
        descriptorDigest,
      }),
      status: "ambiguous_quarantined",
      responseLength: 0,
    },
    {
      label: "ambiguous with a redacted response prefix",
      bytes: terminalResultBytes({
        status: 2,
        flags: 15,
        responseLength: 4,
        sequence: 1n,
        envelopeDigest,
        descriptorDigest,
        responseDigest,
      }),
      status: "ambiguous_quarantined",
      responseLength: 4,
    },
    {
      label: "ambiguous response durably routed to the sink",
      bytes: terminalResultBytes({
        status: 2,
        flags: 31,
        responseLength: 4,
        sequence: 1n,
        envelopeDigest,
        descriptorDigest,
        responseDigest,
        sinkDescriptorDigest,
        sinkRecordDigest,
      }),
      status: "ambiguous_quarantined",
      responseLength: 4,
    },
    {
      label: "fixture completion",
      bytes: terminalResultBytes({
        status: 3,
        flags: 31,
        responseLength: 17,
        sequence: 1n,
        envelopeDigest,
        descriptorDigest,
        responseDigest,
        sinkDescriptorDigest,
        sinkRecordDigest,
      }),
      status: "fixture_complete_non_authorizing",
      responseLength: 17,
    },
  ];
  for (const vector of valid) {
    const decoded = CUSTODIAN.decodeNativeDispatchTerminalResult(vector.bytes);
    assert.equal(decoded.status, vector.status, vector.label);
    assert.equal(decoded.response_byte_length, vector.responseLength, vector.label);
    assert.equal(decoded.production_ready, false, vector.label);
  }

  const complete = {
    status: 3,
    flags: 31,
    responseLength: 17,
    sequence: 1n,
    envelopeDigest,
    descriptorDigest,
    responseDigest,
    sinkDescriptorDigest,
    sinkRecordDigest,
  };
  const invalid = [
    ["unknown status", { ...complete, status: 4 }],
    ["unknown flag", { ...complete, flags: 63 }],
    ["zero settlement time", { ...complete, settled: 0n }],
    ["complete without write", { ...complete, flags: 30 }],
    ["complete without a committed sink", {
      ...complete,
      flags: 15,
      sinkDescriptorDigest: ZERO_DIGEST,
      sinkRecordDigest: ZERO_DIGEST,
    }],
    ["committed sink without descriptor digest", {
      ...complete, sinkDescriptorDigest: ZERO_DIGEST,
    }],
    ["committed sink without record digest", {
      ...complete, sinkRecordDigest: ZERO_DIGEST,
    }],
    ["complete without sequence", { ...complete, sequence: 0n }],
    ["complete without response length", { ...complete, responseLength: 0 }],
    ["complete with a response shorter than one frame", { ...complete, responseLength: 9 }],
    ["complete beyond the native response ceiling", {
      ...complete, responseLength: 1024 * 1024 + 1,
    }],
    ["complete without envelope digest", { ...complete, envelopeDigest: ZERO_DIGEST }],
    ["complete without descriptor digest", { ...complete, descriptorDigest: ZERO_DIGEST }],
    ["complete without response digest", { ...complete, responseDigest: ZERO_DIGEST }],
    ["ambiguous without write", {
      ...complete, status: 2, flags: 30, responseLength: 0, responseDigest: ZERO_DIGEST,
    }],
    ["ambiguous zero length with digest", {
      ...complete, status: 2, responseLength: 0,
    }],
    ["ambiguous nonzero length without digest", {
      ...complete, status: 2, responseDigest: ZERO_DIGEST,
    }],
    ["ambiguous beyond the native response ceiling", {
      ...complete, status: 2, responseLength: 1024 * 1024 + 1,
    }],
    ["rejected after write", {
      ...complete, status: 1, responseLength: 0, responseDigest: ZERO_DIGEST,
    }],
    ["rejected signature without descriptor", {
      status: 1, flags: 2, envelopeDigest,
    }],
    ["rejected deadline without signature", {
      status: 1, flags: 8, envelopeDigest, descriptorDigest,
    }],
    ["rejected descriptor flag without digest", { status: 1, flags: 4 }],
    ["rejected sequence before envelope", { status: 1, sequence: 1n }],
    ["rejected response observation", {
      status: 1, responseLength: 1, responseDigest,
    }],
  ];
  for (const [label, vector] of invalid) {
    assertContractRejected(() => CUSTODIAN.decodeNativeDispatchTerminalResult(
      terminalResultBytes(vector),
    ), label);
  }

  const badMagic = terminalResultBytes();
  badMagic[0] ^= 0xff;
  assertContractRejected(() => CUSTODIAN.decodeNativeDispatchTerminalResult(badMagic));
  const badVersion = terminalResultBytes();
  badVersion.writeUInt16BE(2, 8);
  assertContractRejected(() => CUSTODIAN.decodeNativeDispatchTerminalResult(badVersion));
  assertContractRejected(() => CUSTODIAN.decodeNativeDispatchTerminalResult(
    terminalResultBytes().subarray(0, 131),
  ));
});

test("launcher context verification maps malformed offsets to one stable rejection", async (t) => {
  const devicePath = await ptyFixture(t);
  const fd = fs.openSync(devicePath,
    fs.constants.O_RDWR | fs.constants.O_NONBLOCK | fs.constants.O_NOCTTY);
  t.after(() => fs.closeSync(fd));
  const fixture = buildFixture(fd);
  const bytes = Buffer.from(fixture.context.context_b64, "base64url");
  const keyIdLength = bytes.readUInt16BE(12);
  const payloadOffset = 50 + keyIdLength;
  bytes.writeUInt32BE(0xffff_ffff, payloadOffset + 14);
  const malformed = {
    ...fixture.context,
    context_b64: bytes.toString("base64url"),
    context_digest: crypto.createHash("sha256").update(bytes).digest("hex"),
  };
  assertContractRejected(() => CUSTODIAN.verifyNativeDispatchLauncherContext(malformed));
});

test("launcher context has a stable Node 20 canonical binary golden vector", () => {
  const launcher = ed25519KeyPairFromSeed(0x11);
  const dispatch = ed25519KeyPairFromSeed(0x22);
  const launcherSpki = launcher.publicKey.export({ type: "spki", format: "der" });
  const dispatchSpki = dispatch.publicKey.export({ type: "spki", format: "der" });
  const payload = {
    version: 1,
    fixture_only: true,
    worker_uid: 501,
    worker_gid: 20,
    execution_principal_id: "principal:golden-worker",
    worker_process_start_digest: digest("golden-worker-start"),
    worker_bundle_digest: digest("golden-worker-bundle"),
    native_loaded_image_identity_digest: digest("golden-native-image"),
    provider_id: "chameleon_ultra",
    provider_descriptor_digest: digest("golden-provider-descriptor"),
    provider_implementation_digest: digest("golden-provider-implementation"),
    semantic_manifest_digest: digest("golden-semantic-manifest"),
    device_identity_digest: digest("golden-device-identity"),
    device_enrollment_digest: digest("golden-device-enrollment"),
    connection_generation: "7",
    launcher_ticket_digest: digest("golden-launcher-ticket"),
    device_descriptor_inventory_digest: digest("golden-inventory"),
    delegated_descriptor_identity_digest: digest("golden-descriptor"),
    clock_epoch_digest: digest("golden-clock"),
    dispatch_key_id: "dispatch-key:golden-v1",
    dispatch_public_key_digest: crypto.createHash("sha256").update(dispatchSpki).digest("hex"),
    launcher_public_key_spki_der: launcherSpki,
    dispatch_public_key_spki_der: dispatchSpki,
    launch_nonce: Buffer.alloc(24, 0x33).toString("base64url"),
    execution_lineage_digest: digest("golden-execution-lineage"),
    vault_reservation_digest: digest("golden-vault-reservation"),
    vault_ingest_capability_digest: digest("golden-vault-ingest-capability"),
    vault_sink_descriptor_identity_digest: digest("golden-vault-sink-descriptor"),
    vault_byte_ceiling: 4096,
    artifact_handle_digest: digest("golden-artifact-handle"),
    bootstrap_manifest_digest: NATIVE_BOOTSTRAP_SEMANTICS.bootstrap_manifest_digest,
    bootstrap_operation_registry_digest:
      NATIVE_BOOTSTRAP_SEMANTICS.bootstrap_operation_registry_digest,
    bootstrap_command_set_digest:
      nativeBootstrapOperation("instrument.inventory").command_set_digest,
    native_bootstrap_semantic_table_digest: NATIVE_BOOTSTRAP_SEMANTICS.table_digest,
    bootstrap_invariants_digest: NATIVE_BOOTSTRAP_SEMANTICS.bootstrap_invariants_digest,
  };
  const context = CUSTODIAN.signNativeDispatchLauncherContext({
    payload,
    launcher_key_id: "launcher-key:golden-v1",
    launcher_private_key: launcher.privateKey,
  });
  const bytes = Buffer.from(context.context_b64, "base64url");
  assert.equal(bytes.length, 1291);
  assert.equal(context.context_digest,
    "0999272cc9aadcc0f72fc9c83e3549b437e50bb062f23f0230bce720aef40827");
  assert.equal(bytes.subarray(0, 96).toString("hex"),
    "48425048444c433100010001001600000483503d8ee46d581c649966569ae095e27041de83322e8e0480e5539e00d2d5d8746c61756e636865722d6b65793a676f6c64656e2d763148425048444c423100010023000100000004000000010002");
  assert.equal(bytes.subarray(-96).toString("hex"),
    "e342f43d9d06710d04e96fcf6e59d37d78373a99b6fdf3a1f42735a331325418bc03b28127a046f7cbf52dd06ff4544ab938520d5c0ab7c4ba84775a722b19cf99e200504c8e679a9b2cad7925ecf8d24cbecf324d8aaa6d45f7cdc8f4a5af06");
  assert.deepEqual(CUSTODIAN.verifyNativeDispatchLauncherContext(context), {
    version: 1,
    algorithm: "ed25519",
    launcher_key_id: "launcher-key:golden-v1",
    context_digest: context.context_digest,
  });
});

test("native custodian verifies the two signatures, inherited descriptor, deadline, and partial response", async (t) => {
  const devicePath = await ptyFixture(t, "partial_success");
  const fd = fs.openSync(devicePath,
    fs.constants.O_RDWR | fs.constants.O_NONBLOCK | fs.constants.O_NOCTTY);
  const fixture = buildFixture(fd);
  const outcome = await runFixture(fd, fixture);
  const expectedResponse = frame(1000, Buffer.from("fixture"));
  const expectedSinkRecordDigest = crypto.createHash("sha256")
    .update(outcome.sinkBytes.subarray(0, 280)).digest("hex");
  assert.equal(outcome.code, 0);
  assert.equal(outcome.bytes.length, CUSTODIAN.NATIVE_DISPATCH_TERMINAL_RESULT_BYTES);
  assert.deepEqual(outcome.result, {
    version: 1,
    status: "fixture_complete_non_authorizing",
    wrote_any_command_bytes: true,
    dispatch_signature_verified: true,
    descriptor_identity_verified: true,
    deadline_rechecked_before_first_write: true,
    response_sink_committed: true,
    response_byte_length: expectedResponse.length,
    ticket_sequence: "1",
    settled_continuous_ns: outcome.result.settled_continuous_ns,
    dispatch_envelope_digest: crypto.createHash("sha256").update(fixture.envelope).digest("hex"),
    delegated_descriptor_identity_digest: fixture.descriptorDigest,
    response_digest: crypto.createHash("sha256")
      .update(expectedResponse).digest("hex"),
    vault_sink_descriptor_identity_digest: fixture.sinkDescriptorDigest,
    vault_sink_record_digest: expectedSinkRecordDigest,
    production_ready: false,
    hardware_access_authorized: false,
    authoritative: false,
  });
  assert.equal(outcome.sinkBytes.subarray(0, 8).toString("ascii"), "HBPHVSR1");
  assert.equal(outcome.sinkBytes.readUInt16BE(8), 1);
  assert.equal(outcome.sinkBytes.readUInt16BE(10), 3);
  assert.equal(outcome.sinkBytes.readUInt32BE(12), expectedResponse.length);
  assert.equal(outcome.sinkBytes.readBigUInt64BE(16), 1n);
  assert.equal(outcome.sinkBytes.subarray(24, 56).toString("hex"),
    fixture.payload.execution_lineage_digest);
  assert.equal(outcome.sinkBytes.subarray(120, 152).toString("hex"),
    fixture.sinkDescriptorDigest);
  assert.equal(outcome.sinkBytes.subarray(152, 184).toString("hex"),
    fixture.payload.vault_reservation_digest);
  assert.equal(outcome.sinkBytes.subarray(184, 216).toString("hex"),
    fixture.payload.vault_ingest_capability_digest);
  assert.equal(outcome.sinkBytes.subarray(216, 248).toString("hex"),
    fixture.payload.artifact_handle_digest);
  assert.deepEqual(outcome.sinkBytes.subarray(280), expectedResponse);
  expectedResponse.fill(0);
});

test("vault-owned sink crosses FD7, native custody, terminal settlement, and encrypted ingest", async (t) => {
  const setup = integrationVault(t);
  const suffix = crypto.randomBytes(8).toString("hex");
  const reservationRequest = {
    version: 1,
    session_nucleus_hash: INTEGRATION_SESSION_HASH,
    task_id: `task-${suffix}`,
    attempt_id: `attempt-${suffix}`,
    reservation_ref: `reservation:native-integration-${suffix}`,
    purpose_ref: "purpose:native-provider-response-integration",
    byte_ceiling: 4096,
    expires_at: futureIso(),
  };
  const reserved = setup.vault.reserve(reservationRequest);
  const sink = createProviderResponseSink(setup.vault, {
    version: 1,
    reservation_handle: reserved.reservation_handle,
    metadata: {
      version: 1,
      session_nucleus_hash: INTEGRATION_SESSION_HASH,
      task_id: reservationRequest.task_id,
      attempt_id: reservationRequest.attempt_id,
      data_class: "credential_secret",
      media_type: "application/octet-stream",
      source_ref: "provider:chameleon-ultra-native-integration",
      retention_expires_at: futureIso(60),
    },
  });
  const nativeSink = prepareNativeProviderResponseSink(setup.vault, {
    version: 1,
    sink,
  });
  const lineage = integratedLineage(sink, reservationRequest, suffix);
  const sinkFd = nativeProviderResponseSinkWriteDescriptor(nativeSink);
  const devicePath = await ptyFixture(t, "partial_success");
  const deviceFd = fs.openSync(devicePath,
    fs.constants.O_RDWR | fs.constants.O_NONBLOCK | fs.constants.O_NOCTTY);
  const fixture = buildFixture(deviceFd, {
    sink_fd: sinkFd,
    context_payload: {
      execution_lineage_digest: lineage.execution_lineage_digest,
      vault_reservation_digest: nativeSink.vault_reservation_digest,
      vault_ingest_capability_digest: nativeSink.vault_ingest_capability_digest,
      vault_sink_descriptor_identity_digest:
        nativeSink.vault_sink_descriptor_identity_digest,
      vault_byte_ceiling: nativeSink.byte_ceiling,
      artifact_handle_digest: nativeSink.artifact_handle_digest,
    },
  });
  assert.equal(fixture.sinkDescriptorDigest,
    nativeSink.vault_sink_descriptor_identity_digest);

  const outcome = await runFixture(deviceFd, fixture);
  assert.equal(outcome.code, 0);
  assert.equal(outcome.sinkBytes, null);
  assert.equal(outcome.result.status, "fixture_complete_non_authorizing");
  assert.equal(outcome.result.response_sink_committed, true);
  const receipt = consumeNativeProviderResponseRecord(nativeSink, {
    version: 1,
    kind: "consume_native_provider_response_record_request",
    lineage,
    native_terminal_result: outcome.result,
    execution_claim_receipt_digest: digest("integrated-execution-claim"),
    deadline_fence_receipt_digest: digest("integrated-deadline-fence"),
  });
  const expectedResponse = frame(1000, Buffer.from("fixture"));
  assert.equal(assertProviderResponseRawCustodyReceipt(receipt), receipt);
  assert.throws(() => assertProviderResponseSinkCommit(receipt), /not privately branded/);
  assert.equal(receipt.execution_lineage_digest, lineage.execution_lineage_digest);
  assert.equal(receipt.vault_reservation_digest, nativeSink.vault_reservation_digest);
  assert.equal(receipt.vault_ingest_capability_digest,
    nativeSink.vault_ingest_capability_digest);
  assert.equal(receipt.response_byte_length, expectedResponse.length);
  assert.equal(receipt.response_digest,
    crypto.createHash("sha256").update(expectedResponse).digest("hex"));
  assert.equal(receipt.source_descriptor_identity_digest,
    outcome.result.delegated_descriptor_identity_digest);
  assert.equal(receipt.semantic_validation_performed, false);
  assert.equal(Object.hasOwn(receipt, "result_code"), false);
  assert.equal(Object.hasOwn(receipt, "device_state_digest"), false);
  assert.deepEqual(fs.readdirSync(path.join(setup.root, "native-provider-response-sinks")), []);
  expectedResponse.fill(0);
});

test("a lost native sink commit cannot become a successful transport receipt", async (t) => {
  const devicePath = await ptyFixture(t, "partial_success");
  const fd = fs.openSync(devicePath,
    fs.constants.O_RDWR | fs.constants.O_NONBLOCK | fs.constants.O_NOCTTY);
  const fixture = buildFixture(fd);
  const outcome = await runFixture(fd, fixture, {
    env: { BOB_CHAMELEON_DARWIN_NATIVE_DISPATCH_FIXTURE_SINK_FAULT: "after_header" },
  });
  assert.equal(outcome.code, 0);
  assert.equal(outcome.result.status, "ambiguous_quarantined");
  assert.equal(outcome.result.wrote_any_command_bytes, true);
  assert.equal(outcome.result.response_sink_committed, false);
  assert.equal(outcome.result.vault_sink_descriptor_identity_digest, ZERO_DIGEST);
  assert.equal(outcome.result.vault_sink_record_digest, ZERO_DIGEST);
  assert.equal(outcome.sinkBytes.length, 280);
  assert.equal(outcome.sinkBytes.subarray(0, 8).toString("ascii"), "HBPHVSR1");
  assert.ok(outcome.sinkBytes.readUInt32BE(12) > 0);
});

test("native response sink descriptor drift is rejected before any device effect", async (t) => {
  const cases = [
    {
      label: "sink already contains bytes",
      mutate(fixture) { fs.writeSync(fixture.sinkFd, Buffer.from("occupied", "utf8")); },
    },
    {
      label: "sink becomes group-readable",
      mutate(fixture) { fs.chmodSync(fixture.sinkPath, 0o640); },
    },
    {
      label: "append authority is removed",
      mutate(fixture) {
        fs.closeSync(fixture.sinkFd);
        OPEN_RESPONSE_SINK_FDS.delete(fixture.sinkFd);
        fixture.sinkFd = fs.openSync(fixture.sinkPath, fs.constants.O_WRONLY);
        OPEN_RESPONSE_SINK_FDS.add(fixture.sinkFd);
      },
    },
    {
      label: "different empty inode is delegated",
      mutate(fixture) {
        fs.closeSync(fixture.sinkFd);
        OPEN_RESPONSE_SINK_FDS.delete(fixture.sinkFd);
        const replacement = path.join(RESPONSE_SINK_ROOT,
          `replacement-${crypto.randomBytes(16).toString("hex")}.bin`);
        fixture.sinkFd = fs.openSync(replacement,
          fs.constants.O_WRONLY | fs.constants.O_APPEND
            | fs.constants.O_CREAT | fs.constants.O_EXCL,
          0o600);
        OPEN_RESPONSE_SINK_FDS.add(fixture.sinkFd);
      },
    },
  ];
  for (const vector of cases) {
    await t.test(vector.label, async (subtest) => {
      const devicePath = await ptyFixture(subtest);
      const fd = fs.openSync(devicePath,
        fs.constants.O_RDWR | fs.constants.O_NONBLOCK | fs.constants.O_NOCTTY);
      const fixture = buildFixture(fd);
      vector.mutate(fixture);
      const outcome = await runFixture(fd, fixture);
      assert.equal(outcome.result.status, "rejected_no_effect");
      assert.equal(outcome.result.wrote_any_command_bytes, false);
      assert.equal(outcome.result.response_sink_committed, false);
    });
  }
  await t.test("sink aliases the terminal result socket", async (subtest) => {
    const devicePath = await ptyFixture(subtest);
    const fd = fs.openSync(devicePath,
      fs.constants.O_RDWR | fs.constants.O_NONBLOCK | fs.constants.O_NOCTTY);
    const fixture = buildFixture(fd);
    const outcome = await runFixture(fd, fixture, { control_mode: "alias_sink_and_result" });
    assert.equal(outcome.result, null);
    assert.equal(outcome.bytes.length, 0);
    assert.equal(outcome.sinkBytes.length, 0);
  });
  await t.test("terminal result aliases the response sink file", async (subtest) => {
    const devicePath = await ptyFixture(subtest);
    const fd = fs.openSync(devicePath,
      fs.constants.O_RDWR | fs.constants.O_NONBLOCK | fs.constants.O_NOCTTY);
    const fixture = buildFixture(fd);
    const outcome = await runFixture(fd, fixture, { control_mode: "alias_result_to_sink" });
    assert.equal(outcome.result, null);
    assert.equal(outcome.bytes.length, 0);
    assert.equal(outcome.sinkBytes.length, 0);
  });
});

test("untrusted terminal descriptor layouts are closed without creating an effect", async (t) => {
  for (const vector of [
    { label: "terminal result aliases device", control_mode: "alias_result_to_device" },
    { label: "fixture authority gate is absent", fixture_gate: false },
  ]) {
    await t.test(vector.label, async (subtest) => {
      const audit = await auditedPtyFixture(subtest);
      const fd = fs.openSync(audit.devicePath,
        fs.constants.O_RDWR | fs.constants.O_NONBLOCK | fs.constants.O_NOCTTY);
      const fixture = buildFixture(fd);
      audit.release();
      const outcome = await runFixture(fd, fixture, vector);
      const observed = await audit.observation;
      assert.equal(outcome.code, 70);
      assert.equal(outcome.result, null);
      assert.equal(outcome.bytes.length, 0);
      assert.equal(outcome.sinkBytes.length, 0);
      assert.equal(observed.initial, 0);
      assert.equal(observed.total, 0);
    });
  }
});

test("post-poll deadline custody and semantic admission are effect-tight", async (t) => {
  await t.test("first write", async (subtest) => {
    const audit = await auditedPtyFixture(subtest);
    const fd = fs.openSync(audit.devicePath,
      fs.constants.O_RDWR | fs.constants.O_NONBLOCK | fs.constants.O_NOCTTY);
    const fixture = buildFixture(fd, { payload: effectWindow(400) });
    audit.release();
    const started = process.hrtime.bigint();
    const outcome = await runFixture(fd, fixture, {
      env: { BOB_CHAMELEON_DARWIN_NATIVE_DISPATCH_FIXTURE_POST_POLL_STALL: "first" },
    });
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    const observed = await audit.observation;
    assert.ok(elapsedMs >= 550, `fixture stall did not run: ${elapsedMs}ms`);
    assert.equal(outcome.code, 0);
    assert.equal(outcome.result.status, "rejected_no_effect");
    assert.equal(outcome.result.wrote_any_command_bytes, false);
    assert.equal(outcome.result.deadline_rechecked_before_first_write, true);
    assert.equal(observed.closed, true);
    assert.equal(observed.initial, 0);
    assert.equal(observed.total, 0);
  });

  await t.test("continuation-sized semantic fork", async (subtest) => {
    const audit = await auditedPtyFixture(subtest);
    const fd = fs.openSync(audit.devicePath,
      fs.constants.O_RDWR | fs.constants.O_NONBLOCK | fs.constants.O_NOCTTY);
    const command = frame(1000, Buffer.alloc(65526, 0xa5));
    assert.equal(command.length, 65536);
    const fixture = buildFixture(fd, { command, payload: effectWindow(2000) });
    audit.release();
    const outcome = await runFixture(fd, fixture);
    const observed = await audit.observation;
    assert.equal(outcome.code, 0);
    assert.equal(outcome.result.status, "rejected_no_effect");
    assert.equal(outcome.result.wrote_any_command_bytes, false);
    assert.equal(outcome.result.deadline_rechecked_before_first_write, false);
    assert.equal(observed.closed, true);
    assert.equal(observed.initial, 0);
    assert.equal(observed.total, 0);
  });
});

test("validly signed operation-to-command substitutions are effect-free", async (t) => {
  for (const vector of [
    { label: "emulation block write", command: frame(4000, Buffer.alloc(18, 0xa5)) },
    { label: "HF reader APDU", command: frame(6004, Buffer.from("00a4040000", "hex")) },
  ]) {
    await t.test(vector.label, async (subtest) => {
      const audit = await auditedPtyFixture(subtest);
      const fd = fs.openSync(audit.devicePath,
        fs.constants.O_RDWR | fs.constants.O_NONBLOCK | fs.constants.O_NOCTTY);
      // buildFixture recomputes the command digest and signs the substituted
      // bytes, so rejection cannot be attributed to an invalid signature.
      const fixture = buildFixture(fd, { command: vector.command });
      assert.equal(
        BROKER_CONTRACT.verifySignedNativeDispatchTicket(
          fixture.ticket,
          fixture.dispatch.publicKey,
          fixture.contextPayload.dispatch_key_id,
        ).command_bytes_digest,
        crypto.createHash("sha256").update(vector.command).digest("hex"),
      );
      audit.release();
      const outcome = await runFixture(fd, fixture);
      const observed = await audit.observation;
      assert.equal(outcome.code, 0);
      assert.equal(outcome.result.status, "rejected_no_effect");
      assert.equal(outcome.result.dispatch_signature_verified, true);
      assert.equal(outcome.result.wrote_any_command_bytes, false);
      assert.equal(observed.initial, 0);
      assert.equal(observed.total, 0);
    });
  }
});

test("generated native bootstrap semantics admit every exact zero-payload command position", async (t) => {
  for (const operation of NATIVE_BOOTSTRAP_SEMANTICS.operations) {
    for (const command of operation.commands) {
      await t.test(`${operation.operation_id}/${command.command_sequence}/${command.command_id}`,
        async (subtest) => {
          const devicePath = await ptyFixture(subtest);
          const fd = fs.openSync(devicePath,
            fs.constants.O_RDWR | fs.constants.O_NONBLOCK | fs.constants.O_NOCTTY);
          const fixture = buildFixture(fd, {
            operation_id: operation.operation_id,
            command_sequence: command.command_sequence,
          });
          const outcome = await runFixture(fd, fixture);
          assert.equal(outcome.code, 0);
          assert.equal(outcome.result.status, "fixture_complete_non_authorizing");
          assert.equal(outcome.result.wrote_any_command_bytes, true);
          assert.equal(outcome.result.dispatch_signature_verified, true);
          assert.equal(outcome.result.ticket_sequence, "1");
          assert.equal(outcome.result.production_ready, false);
        });
    }
  }
});

test("generated native semantics reject cross-operation, sequence, payload, and registry drift before effect", async (t) => {
  const inventory = nativeBootstrapOperation("instrument.inventory");
  const health = nativeBootstrapOperation("instrument.health");
  const drift = digest("native-bootstrap-registry-drift");
  const cases = [
    {
      label: "cross-operation command substitution",
      options: { operation_id: "instrument.health", command: frame(1000) },
    },
    {
      label: "cross-operation digest substitution",
      options: { payload: { operation_digest: health.operation_digest } },
    },
    {
      label: "duplicate earlier command at sequence two",
      options: { command_sequence: 2, command: frame(1000) },
    },
    {
      label: "reordered second command at sequence one",
      options: { command_sequence: 1, command: frame(1017) },
    },
    {
      label: "omission-shaped jump uses the wrong terminal command",
      options: { command_sequence: 2, command: frame(1033) },
    },
    {
      label: "sequence outside the exact command set",
      options: { command_sequence: 4, command: frame(1033) },
    },
    {
      label: "unknown command",
      options: { command: frame(65530) },
    },
    {
      label: "zero-payload schema injection",
      options: { command: frame(1000, Buffer.from([0xa5])) },
    },
    {
      label: "semantic manifest drift",
      options: {
        context_payload: { semantic_manifest_digest: drift },
        payload: { semantic_manifest_digest: drift },
      },
    },
    {
      label: "command-set identity drift",
      options: {
        context_payload: { bootstrap_command_set_digest: health.command_set_digest },
      },
    },
    {
      label: "normalized operation digest drift",
      options: { payload: { operation_digest: drift } },
    },
  ];
  assert.notEqual(inventory.command_set_digest, health.command_set_digest);
  for (const vector of cases) {
    await t.test(vector.label, async (subtest) => {
      const audit = await auditedPtyFixture(subtest);
      const fd = fs.openSync(audit.devicePath,
        fs.constants.O_RDWR | fs.constants.O_NONBLOCK | fs.constants.O_NOCTTY);
      const fixture = buildFixture(fd, vector.options);
      audit.release();
      const outcome = await runFixture(fd, fixture);
      const observed = await audit.observation;
      assert.equal(outcome.code, 0);
      assert.equal(outcome.result.status, "rejected_no_effect");
      assert.equal(outcome.result.dispatch_signature_verified, true);
      assert.equal(outcome.result.wrote_any_command_bytes, false);
      assert.equal(outcome.result.response_byte_length, 0);
      assert.equal(observed.initial, 0);
      assert.equal(observed.total, 0);
    });
  }
});

test("native custodian rejects authority, signature, command, and framing forks before effect", async (t) => {
  const cases = [
    {
      label: "forged dispatch signature",
      prepare(fd) {
        const fixture = buildFixture(fd);
        const envelope = Buffer.from(fixture.envelope);
        envelope[envelope.length - 1] ^= 0x80;
        return {
          ...fixture,
          envelope,
          input: CUSTODIAN.encodeNativeDispatchCustodianInput({
            version: 1,
            envelope_bytes: envelope,
            command_bytes: fixture.command,
          }),
        };
      },
    },
    {
      label: "signed key-id alias rewrite",
      prepare(fd) {
        const fixture = buildFixture(fd);
        const envelope = Buffer.from(fixture.envelope);
        const keyLength = envelope.readUInt16BE(12);
        assert.equal(envelope.subarray(50, 50 + keyLength).toString("utf8"),
          "dispatch-key:fixture-v1");
        envelope[50 + keyLength - 1] = "2".charCodeAt(0);
        return {
          ...fixture,
          envelope,
          input: CUSTODIAN.encodeNativeDispatchCustodianInput({
            version: 1,
            envelope_bytes: envelope,
            command_bytes: fixture.command,
          }),
        };
      },
    },
    {
      label: "validly resigned provider-binding fork",
      prepare(fd) {
        return buildFixture(fd, {
          payload: { provider_descriptor_digest: digest("forked-provider-descriptor") },
        });
      },
    },
    {
      label: "validly resigned execution-lineage fork",
      prepare(fd) {
        return buildFixture(fd, {
          payload: { execution_lineage_digest: digest("forked-execution-lineage") },
        });
      },
    },
    {
      label: "validly resigned vault-sink identity fork",
      prepare(fd) {
        return buildFixture(fd, {
          payload: { vault_sink_descriptor_identity_digest: digest("forked-vault-sink") },
        });
      },
    },
    {
      label: "launcher-context vault capability fork",
      prepare(fd) {
        return buildFixture(fd, {
          context_payload: { vault_ingest_capability_digest: digest("forked-vault-capability") },
          payload: { vault_ingest_capability_digest: digest("vault-ingest-capability") },
        });
      },
    },
    {
      label: "launcher-context worker UID mismatch",
      prepare(fd) {
        return buildFixture(fd, {
          context_payload: { worker_uid: process.getuid() + 1 },
        });
      },
    },
    {
      label: "forged launcher-context signature",
      prepare(fd) {
        const fixture = buildFixture(fd);
        const contextBytes = Buffer.from(fixture.contextBytes);
        contextBytes[contextBytes.length - 1] ^= 0x80;
        return { ...fixture, contextBytes };
      },
    },
    {
      label: "dispatch key substituted behind the enrolled context",
      prepare(fd) {
        return buildFixture(fd, {
          ticket_private_key: crypto.generateKeyPairSync("ed25519").privateKey,
        });
      },
    },
    {
      label: "command bytes differ from the signed digest",
      prepare(fd) {
        const fixture = buildFixture(fd);
        const command = Buffer.from(fixture.command);
        command[8] ^= 1;
        return {
          ...fixture,
          command,
          input: CUSTODIAN.encodeNativeDispatchCustodianInput({
            version: 1,
            envelope_bytes: fixture.envelope,
            command_bytes: command,
          }),
        };
      },
    },
    {
      label: "expired signed effect window",
      prepare(fd) {
        return buildFixture(fd, { payload: effectWindow(-100, -1000) });
      },
    },
    {
      label: "duplicate trailing dispatch frame",
      prepare(fd) {
        const fixture = buildFixture(fd);
        return { ...fixture, input: Buffer.concat([fixture.input, fixture.input]) };
      },
    },
  ];

  for (const vector of cases) {
    await t.test(vector.label, async (subtest) => {
      const devicePath = await ptyFixture(subtest);
      const fd = fs.openSync(devicePath,
        fs.constants.O_RDWR | fs.constants.O_NONBLOCK | fs.constants.O_NOCTTY);
      const fixture = vector.prepare(fd);
      const outcome = await runFixture(fd, fixture);
      assert.equal(outcome.code, 0);
      assert.equal(outcome.result.status, "rejected_no_effect");
      assert.equal(outcome.result.wrote_any_command_bytes, false);
      assert.equal(outcome.result.response_byte_length, 0);
      assert.equal(outcome.result.response_digest, ZERO_DIGEST);
      assert.equal(outcome.result.production_ready, false);
    });
  }
});

test("post-write faults are one-use ambiguous and retain only redacted response evidence", async (t) => {
  const cases = [
    { behavior: "no_response", expectedLength: 0 },
    { behavior: "late_response", expectedLength: 0 },
    { behavior: "partial_response_stall", expectedLength: 4 },
    { behavior: "duplicate_response", minimumLength: 1 },
  ];
  for (const vector of cases) {
    await t.test(vector.behavior, async (subtest) => {
      const devicePath = await ptyFixture(subtest, vector.behavior);
      const fd = fs.openSync(devicePath,
        fs.constants.O_RDWR | fs.constants.O_NONBLOCK | fs.constants.O_NOCTTY);
      const fixture = buildFixture(fd, { payload: effectWindow(800) });
      const outcome = await runFixture(fd, fixture);
      assert.equal(outcome.code, 0);
      assert.equal(outcome.result.status, "ambiguous_quarantined");
      assert.equal(outcome.result.wrote_any_command_bytes, true);
      assert.equal(outcome.result.dispatch_signature_verified, true);
      assert.equal(outcome.result.descriptor_identity_verified, true);
      assert.equal(outcome.result.deadline_rechecked_before_first_write, true);
      if (vector.expectedLength != null) {
        assert.equal(outcome.result.response_byte_length, vector.expectedLength);
      } else {
        assert.ok(outcome.result.response_byte_length >= vector.minimumLength);
      }
      if (outcome.result.response_byte_length === 0) {
        assert.equal(outcome.result.response_digest, ZERO_DIGEST);
      } else {
        assert.notEqual(outcome.result.response_digest, ZERO_DIGEST);
      }
      if (vector.behavior === "partial_response_stall") {
        const partial = frame(1000, Buffer.from("fixture")).subarray(0, 4);
        assert.equal(outcome.result.response_digest,
          crypto.createHash("sha256").update(partial).digest("hex"));
      }
    });
  }

  await t.test("oversized request cannot reach the partial-write seam", async (subtest) => {
    const devicePath = await ptyFixture(subtest, "partial_write_stall");
    const fd = fs.openSync(devicePath,
      fs.constants.O_RDWR | fs.constants.O_NONBLOCK | fs.constants.O_NOCTTY);
    const command = frame(1000, Buffer.alloc(65526, 0xa5));
    assert.equal(command.length, 65536);
    const fixture = buildFixture(fd, {
      command,
      payload: effectWindow(800),
    });
    const outcome = await runFixture(fd, fixture);
    assert.equal(outcome.code, 0);
    assert.equal(outcome.result.status, "rejected_no_effect");
    assert.equal(outcome.result.wrote_any_command_bytes, false);
    assert.equal(outcome.result.deadline_rechecked_before_first_write, false);
    assert.equal(outcome.result.response_sink_committed, false);
    assert.equal(outcome.result.response_byte_length, 0);
    assert.equal(outcome.result.response_digest, ZERO_DIGEST);
  });
});

test("native custody survives JS scheduling stalls and rejects pre-effect queue expiry", async (t) => {
  await t.test("partial socket chunks", async (subtest) => {
    const devicePath = await ptyFixture(subtest);
    const fd = fs.openSync(devicePath,
      fs.constants.O_RDWR | fs.constants.O_NONBLOCK | fs.constants.O_NOCTTY);
    const fixture = buildFixture(fd);
    const outcome = await runFixture(fd, fixture, {
      context_chunks: chunkBytes(fixture.contextBytes),
      input_chunks: chunkBytes(fixture.input, [3, 5, 11, 53]),
    });
    assert.equal(outcome.code, 0);
    assert.equal(outcome.result.status, "fixture_complete_non_authorizing");
  });

  await t.test("busy JavaScript event loop cannot delay native settlement", async (subtest) => {
    const devicePath = await ptyFixture(subtest);
    const fd = fs.openSync(devicePath,
      fs.constants.O_RDWR | fs.constants.O_NONBLOCK | fs.constants.O_NOCTTY);
    const fixture = buildFixture(fd);
    const outcome = await runFixture(fd, fixture, { runner_mode: "busy" });
    assert.equal(outcome.code, 0);
    assert.equal(outcome.result.status, "fixture_complete_non_authorizing");
  });

  await t.test("libuv worker queue delay expires before any write", async (subtest) => {
    const devicePath = await ptyFixture(subtest);
    const fd = fs.openSync(devicePath,
      fs.constants.O_RDWR | fs.constants.O_NONBLOCK | fs.constants.O_NOCTTY);
    const fixture = buildFixture(fd, { payload: effectWindow(350) });
    const outcome = await runFixture(fd, fixture, {
      runner_mode: "queue",
      env: { UV_THREADPOOL_SIZE: "4" },
    });
    assert.equal(outcome.code, 0);
    assert.equal(outcome.result.status, "rejected_no_effect");
    assert.equal(outcome.result.wrote_any_command_bytes, false);
    assert.equal(outcome.result.dispatch_signature_verified, true);
    assert.equal(outcome.result.deadline_rechecked_before_first_write, false);
  });

  await t.test("second call in one process is synchronously rejected", async (subtest) => {
    const devicePath = await ptyFixture(subtest);
    const fd = fs.openSync(devicePath,
      fs.constants.O_RDWR | fs.constants.O_NONBLOCK | fs.constants.O_NOCTTY);
    const fixture = buildFixture(fd);
    const outcome = await runFixture(fd, fixture, { runner_mode: "replay" });
    assert.equal(outcome.code, 0);
    assert.equal(outcome.result.status, "fixture_complete_non_authorizing");
    assert.equal(outcome.bytes.length, CUSTODIAN.NATIVE_DISPATCH_TERMINAL_RESULT_BYTES);
  });
});

test("fixed control descriptors reject aliases and noncanonical status flags", async (t) => {
  for (const controlMode of ["alias_context_and_input", "nonblocking_context"]) {
    await t.test(controlMode, async (subtest) => {
      const devicePath = await ptyFixture(subtest);
      const fd = fs.openSync(devicePath,
        fs.constants.O_RDWR | fs.constants.O_NONBLOCK | fs.constants.O_NOCTTY);
      const fixture = buildFixture(fd);
      const outcome = await runFixture(fd, fixture, { control_mode: controlMode });
      assert.equal(outcome.code, 70);
      assert.equal(outcome.result, null);
      assert.equal(outcome.bytes.length, 0);
      assert.equal(outcome.sinkBytes.length, 0);
    });
  }
});

test("descriptor substitution rejects, while restart replay stays an explicit production blocker", async (t) => {
  await t.test("a ticket for one PTY cannot be transplanted to another", async (subtest) => {
    const firstPath = await ptyFixture(subtest);
    const secondPath = await ptyFixture(subtest);
    const firstFd = fs.openSync(firstPath,
      fs.constants.O_RDWR | fs.constants.O_NONBLOCK | fs.constants.O_NOCTTY);
    const fixture = buildFixture(firstFd);
    fs.closeSync(firstFd);
    const secondFd = fs.openSync(secondPath,
      fs.constants.O_RDWR | fs.constants.O_NONBLOCK | fs.constants.O_NOCTTY);
    const secondDescriptorDigest = BROKER_CONTRACT.deriveNativeDelegatedDescriptorIdentityDigest(
      descriptorIdentity(secondFd),
    );
    assert.notEqual(secondDescriptorDigest, fixture.descriptorDigest);
    const outcome = await runFixture(secondFd, fixture);
    assert.equal(outcome.code, 0);
    assert.equal(outcome.result.status, "rejected_no_effect");
    assert.equal(outcome.result.wrote_any_command_bytes, false);
    assert.equal(outcome.result.delegated_descriptor_identity_digest, secondDescriptorDigest);
  });

  await t.test("a committed sink makes exact-ticket restart replay reject before effect", async (subtest) => {
    const devicePath = await ptyFixture(subtest);
    const firstFd = fs.openSync(devicePath,
      fs.constants.O_RDWR | fs.constants.O_NONBLOCK | fs.constants.O_NOCTTY);
    const fixture = buildFixture(firstFd, { payload: effectWindow(8000) });
    const first = await runFixture(firstFd, fixture);
    assert.equal(first.result.status, "fixture_complete_non_authorizing");
    fixture.sinkFd = fs.openSync(fixture.sinkPath, fs.constants.O_WRONLY | fs.constants.O_APPEND);
    OPEN_RESPONSE_SINK_FDS.add(fixture.sinkFd);
    const secondFd = fs.openSync(devicePath,
      fs.constants.O_RDWR | fs.constants.O_NONBLOCK | fs.constants.O_NOCTTY);
    const second = await runFixture(secondFd, fixture);
    assert.equal(second.result.status, "rejected_no_effect");
    assert.equal(second.result.wrote_any_command_bytes, false);
    assert.equal(second.result.dispatch_envelope_digest, ZERO_DIGEST);
    assert.deepEqual(second.sinkBytes, first.sinkBytes);
    assert.equal(CUSTODIAN.DARWIN_NATIVE_DISPATCH_CUSTODIAN_ASSURANCE.in_process_one_use, true);
    assert.equal(
      CUSTODIAN.DARWIN_NATIVE_DISPATCH_CUSTODIAN_ASSURANCE.durable_restart_replay_authority,
      false,
    );
    assert.ok(CUSTODIAN.DARWIN_NATIVE_DISPATCH_CUSTODIAN_ASSURANCE.production_blockers.includes(
      "durable_restart_replay_and_fork_fence_missing",
    ));
  });
});
