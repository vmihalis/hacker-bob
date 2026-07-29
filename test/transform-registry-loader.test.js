"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const {
  createArtifactVault,
} = require("../packages/bob-artifact-vault/index.js");
const {
  createInProcessBackupKeyCustodyFixture,
} = require("./helpers/artifact-vault-backup-key-custody.js");
const {
  createTransformRegistry,
  runTransform,
} = require("../packages/bob-artifact-vault/worker.js");
const {
  createOperatorTransformPolicyAuthority,
  enrollOperatorTransformPolicy,
} = require("../packages/bob-artifact-vault/operator.js");

const SESSION_HASH = "a".repeat(64);
const FIXTURE_PATH = path.join(
  __dirname,
  "fixtures",
  "artifact-transform-programs.transform.json",
);

function digest(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function makeImplementationRoot(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-transform-registry-"));
  const modulePath = path.join(root, "programs.transform.json");
  const source = fs.readFileSync(FIXTURE_PATH);
  fs.writeFileSync(modulePath, source, { flag: "wx", mode: 0o600 });
  fs.chmodSync(modulePath, 0o600);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, modulePath, source, implementationDigest: digest(source) };
}

function writePrivateModule(root, relativePath, source) {
  const modulePath = path.join(root, relativePath);
  fs.writeFileSync(modulePath, source, { flag: "wx", mode: 0o600 });
  fs.chmodSync(modulePath, 0o600);
  return { modulePath, source: Buffer.from(source), implementationDigest: digest(source) };
}

function manifest(implementationDigest, overrides = {}) {
  return {
    version: 1,
    tool_id: "fixture.identity",
    tool_version: "1.0.0",
    implementation_digest: implementationDigest,
    handler_export: "identityTransform",
    input_data_classes: ["metadata"],
    output_data_classes: ["metadata"],
    parameters: {},
    max_input_handles: 1,
    max_input_bytes: 1024,
    max_output_artifacts: 1,
    max_output_bytes: 1024,
    ...overrides,
  };
}

function enrollPolicy(root, trustedDigests) {
  const current = {
    version: 1,
    policy_id: "transform-registry-loader-test",
    policy_epoch: 1,
    status: "trusted",
    trusted_implementation_root: root,
    trusted_implementation_digests: trustedDigests,
  };
  const authority = createOperatorTransformPolicyAuthority({
    version: 1,
    authority_id: "transform-registry-loader-authority",
    resolve_current_policy: () => structuredClone(current),
  });
  return enrollOperatorTransformPolicy({
    version: 1,
    policy_authority_id: authority.authority_id,
    policy_authority_digest: authority.authority_digest,
    policy_id: current.policy_id,
  }, authority);
}

function createRegistry(root, implementationDigest, definitionOverrides = {}, manifestOverrides = {}) {
  return createTransformRegistry([{
    implementation_module: "programs.transform.json",
    manifest: manifest(implementationDigest, manifestOverrides),
    ...definitionOverrides,
  }], enrollPolicy(root, [implementationDigest]));
}

function makeStateAnchor(digestField) {
  const states = new Map();
  return Object.freeze({
    readState({ vault_slot: vaultSlot }) {
      const state = states.get(vaultSlot);
      return state == null ? null : structuredClone(state);
    },
    compareAndSet(request) {
      const current = states.get(request.vault_slot) || null;
      const expectedDigestField = `expected_${digestField}`;
      const expectedMatches = current == null
        ? request.expected_generation == null && request[expectedDigestField] == null
        : request.expected_generation === current.generation
          && request[expectedDigestField] === current[digestField];
      if (!expectedMatches) return false;
      states.set(request.vault_slot, structuredClone(request.next_state));
      return true;
    },
  });
}

function makeVault(t) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "bob-transform-preflight-"));
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  const masterKey = crypto.randomBytes(32);
  const vaultId = `vault:v1:${crypto.randomBytes(32).toString("base64url")}`;
  const vaultSlot = `vault-slot:v1:${crypto.randomBytes(32).toString("base64url")}`;
  const backupKeyCustodyFixture = createInProcessBackupKeyCustodyFixture({
    vaultId,
    vaultSlot,
    sessionNucleusHash: SESSION_HASH,
  });
  t.after(() => backupKeyCustodyFixture.destroy());
  const vault = createArtifactVault({
    root: path.join(parent, "vault"),
    sessionNucleusHash: SESSION_HASH,
    vaultId,
    vaultSlot,
    backupKeyCustody: backupKeyCustodyFixture.port,
    createNew: true,
    masterKey,
    deletionLedgerAnchor: makeStateAnchor("ledger_digest"),
    indexStateAnchor: makeStateAnchor("index_digest"),
    quotaBytes: 1024 * 1024,
    minFreeBytes: 0,
  });
  masterKey.fill(0);
  t.after(() => vault.destroy());
  return vault;
}

function futureIso() {
  return new Date(Date.now() + 60 * 60_000).toISOString();
}

function reserve(vault, byteCeiling) {
  return vault.reserve({
    version: 1,
    session_nucleus_hash: SESSION_HASH,
    task_id: "task-preflight",
    attempt_id: "attempt-preflight",
    reservation_ref: `reservation:preflight-${crypto.randomBytes(8).toString("hex")}`,
    purpose_ref: "purpose:transform-preflight",
    byte_ceiling: byteCeiling,
    expires_at: futureIso(),
  });
}

function artifactMetadata() {
  return {
    version: 1,
    session_nucleus_hash: SESSION_HASH,
    task_id: "task-preflight",
    attempt_id: "attempt-preflight",
    data_class: "metadata",
    media_type: "application/octet-stream",
    source_ref: "provider:transform-preflight",
    retention_expires_at: futureIso(),
  };
}

test("transform registry derives behavior only from digest-allowlisted declarative program bytes", (t) => {
  const { root, implementationDigest } = makeImplementationRoot(t);
  const registry = createRegistry(root, implementationDigest);

  assert.deepEqual(registry.ids(), ["fixture.identity"]);
  assert.equal(registry.manifest("fixture.identity").implementation_digest, implementationDigest);
  assert.match(registry.manifest("fixture.identity").tool_digest, /^[a-f0-9]{64}$/);

  assert.throws(() => createRegistry(root, implementationDigest, {
    handler() {},
    loaded_implementation_digest: implementationDigest,
  }), /unknown fields: handler, loaded_implementation_digest/);
});

test("transform registry rejects digest drift and absent program exports", (t) => {
  const { root, implementationDigest } = makeImplementationRoot(t);

  const driftedPolicy = enrollPolicy(root, ["f".repeat(64)]);
  assert.throws(() => createTransformRegistry([{
    implementation_module: "programs.transform.json",
    manifest: manifest("f".repeat(64)),
  }], driftedPolicy), /implementation bytes are not digest-allowlisted/);

  assert.throws(() => createRegistry(
    root,
    implementationDigest,
    {},
    { handler_export: "nonHandlerExport" },
  ), /must name an owned declarative transform program/);

  assert.throws(() => createRegistry(
    root,
    implementationDigest,
    {},
    { max_input_handles: 65 },
  ), /count ceiling/);
  assert.throws(() => createRegistry(
    root,
    implementationDigest,
    {},
    { parameters: { mode: { kind: "boolean", required: true } } },
  ), /parameters must be empty until declarative parameter operations exist/);
});

test("transform registry rejects symlinks, hardlinks, and non-private modules", async (t) => {
  await t.test("symlink", (subtest) => {
    const { root, modulePath, implementationDigest } = makeImplementationRoot(subtest);
    fs.symlinkSync(modulePath, path.join(root, "linked.transform.json"));
    assert.throws(() => createRegistry(
      root,
      implementationDigest,
      { implementation_module: "linked.transform.json" },
    ), /must not traverse symbolic links/);
  });

  await t.test("hardlink", (subtest) => {
    const { root, modulePath, implementationDigest } = makeImplementationRoot(subtest);
    fs.linkSync(modulePath, path.join(root, "hardlinked.transform.json"));
    assert.throws(() => createRegistry(root, implementationDigest), /single-link regular file/);
  });

  await t.test("group-readable", (subtest) => {
    const { root, modulePath, implementationDigest } = makeImplementationRoot(subtest);
    fs.chmodSync(modulePath, 0o640);
    assert.throws(() => createRegistry(root, implementationDigest), /must not grant group or other permissions/);
  });
});

test("transform registry confines canonical declarative program paths to the trusted root", (t) => {
  const { root, implementationDigest } = makeImplementationRoot(t);

  assert.throws(() => createRegistry(
    root,
    implementationDigest,
    { implementation_module: "../outside.transform.json" },
  ), /must not contain empty or traversal segments/);
  assert.throws(() => createRegistry(
    root,
    implementationDigest,
    { implementation_module: "/tmp/outside.transform.json" },
  ), /must be a relative slash-delimited module path/);
  assert.throws(() => createRegistry(
    root,
    implementationDigest,
    { implementation_module: "handlers.json" },
  ), /must name a \.transform\.json program bundle/);
  assert.throws(
    () => enrollPolicy("relative/root", [implementationDigest]),
    /must be an absolute directory path/,
  );
});

test("transform programs cannot reach a module loader, process, globals, or mutable helpers", (t) => {
  const { root } = makeImplementationRoot(t);
  const markerPath = path.join(root, "helper-executed");
  writePrivateModule(
    root,
    "helper.js",
    `require("node:fs").writeFileSync(${JSON.stringify(markerPath)}, "executed");\n`
      + "exports.identityTransform = () => ({ outputs: [] });\n",
  );
  const escaped = writePrivateModule(
    root,
    "escape.transform.json",
    "const helper = module.constructor._load('./helper.js', module);\n"
      + "exports.identityTransform = helper.identityTransform;\n",
  );
  const escapedPolicy = enrollPolicy(root, [escaped.implementationDigest]);
  assert.throws(() => createTransformRegistry([{
    implementation_module: "escape.transform.json",
    manifest: manifest(escaped.implementationDigest),
  }], escapedPolicy), /must contain JSON data, not executable module code/);
  assert.equal(fs.existsSync(markerPath), false, "module escape source was parsed only as inert data");

  const unknownOperationSource = JSON.stringify({
    version: 1,
    programs: {
      identityTransform: {
        version: 1,
        outputs: [{
          plaintext: { op: "module.constructor._load", value: "./helper.js" },
          data_class: { op: "literal", value: "metadata" },
          media_type: { op: "literal", value: "application/octet-stream" },
        }],
      },
    },
  });
  const unknownOperation = writePrivateModule(
    root,
    "unknown-operation.transform.json",
    unknownOperationSource,
  );
  const unknownOperationPolicy = enrollPolicy(root, [unknownOperation.implementationDigest]);
  assert.throws(() => createTransformRegistry([{
    implementation_module: "unknown-operation.transform.json",
    manifest: manifest(unknownOperation.implementationDigest),
  }], unknownOperationPolicy), /op is not a registered transform byte operation/);
});

test("transform preflight rejects input-copy amplification before program allocation", (t) => {
  const { root } = makeImplementationRoot(t);
  const repeatedInputs = Array.from({ length: 64 }, () => ({
    op: "input_bytes",
    input_index: 0,
  }));
  const source = JSON.stringify({
    version: 1,
    programs: {
      amplifyThenSlice: {
        version: 1,
        outputs: [{
          plaintext: {
            op: "slice",
            value: { op: "concat", values: repeatedInputs },
            start: 0,
            end: 1,
          },
          data_class: { op: "input_data_class", input_index: 0 },
          media_type: { op: "input_media_type", input_index: 0 },
        }],
      },
    },
  });
  const implementation = writePrivateModule(root, "amplifier.transform.json", source);
  const registry = createTransformRegistry([{
    implementation_module: "amplifier.transform.json",
    manifest: manifest(implementation.implementationDigest, {
      tool_id: "fixture.amplifier",
      handler_export: "amplifyThenSlice",
      max_input_bytes: 1,
      max_output_bytes: 1,
    }),
  }], enrollPolicy(root, [implementation.implementationDigest]));

  const vault = makeVault(t);
  const inputReservation = reserve(vault, 1);
  const input = vault.ingest({
    reservation_handle: inputReservation.reservation_handle,
    metadata: artifactMetadata(),
    plaintext: Buffer.from("x"),
  });
  const outputReservation = reserve(vault, 1);
  assert.throws(() => runTransform({
    registry,
    registry_digest: registry.registry_digest,
    vault,
    transform_attempt_ref: "transform-attempt:preflight-amplifier",
    tool_id: "fixture.amplifier",
    tool_digest: registry.manifest("fixture.amplifier").tool_digest,
    input_handles: [input.artifact_handle],
    outputs: [{
      reservation_handle: outputReservation.reservation_handle,
      metadata: artifactMetadata(),
    }],
  }), /exceeds its preflight allocation budget/);
  assert.equal(vault.usage().active_artifacts, 1);
  assert.equal(vault.usage().active_reservations, 0);
});
