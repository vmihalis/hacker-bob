"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const checkpointContract = require("../mcp/lib/physical-inventory-checkpoint.js");
const {
  PHYSICAL_INVENTORY_CAPTURE_DOMAIN,
  READINESS_BLOCKERS,
  REQUIRED_OPERATION_IDS,
  assertCurrentFixturePhysicalInventoryCheckpoint,
  assertFixturePhysicalInventoryCheckpoint,
  assertFixturePhysicalInventoryCheckpointSource,
  captureFixturePhysicalInventoryCheckpoint,
  createFixturePhysicalInventoryCheckpointSource,
  physicalInventoryCaptureSigningMessage,
  projectFixturePhysicalInventoryCheckpoint,
  publicKeyDigest,
} = checkpointContract;
const {
  TRUSTED_CLOCK_MAPPING_DOMAIN,
  createPhysicalTrustedClockPort,
  physicalClockMappingSigningMessage,
  publicKeyDigest: clockPublicKeyDigest,
} = require("../mcp/lib/physical-trusted-clock.js");
const {
  hashCanonicalJson,
} = require("../mcp/lib/verification-contracts.js");

function digest(label) {
  return hashCanonicalJson({ label });
}

function signClockMapping(keyPair, payload) {
  const payloadDigest = hashCanonicalJson(payload);
  const signature = crypto.sign(
    null,
    physicalClockMappingSigningMessage(payloadDigest),
    keyPair.privateKey,
  ).toString("base64url");
  const basis = {
    version: 1,
    domain: TRUSTED_CLOCK_MAPPING_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    scheme: "ed25519",
    signature,
  };
  return { ...basis, signed_mapping_digest: hashCanonicalJson(basis) };
}

function createClockFixture(options = {}) {
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const control = {
    monotonic_ms: options.monotonic_ms == null ? 1_000 : options.monotonic_ms,
  };
  const mappingPayload = {
    version: 1,
    clock_id: "physical-clock:inventory-checkpoint-fixture",
    monotonic_epoch_id: digest("inventory-checkpoint-clock-epoch"),
    mapping_generation: 1,
    reference_monotonic_ms: 1_000,
    reference_utc: options.reference_utc || "2026-07-18T12:00:30.000Z",
    max_uncertainty_ms: 0,
    not_before: "2026-07-18T11:00:00.000Z",
    expires_at: "2026-07-18T14:00:00.000Z",
    trust_root_epoch: 3,
    authority_epoch: 8,
    revocation_generation: 2,
    signer_key_id: "clock-key:inventory-checkpoint-fixture",
    signer_public_key_digest: clockPublicKeyDigest(keyPair.publicKey),
  };
  const mapping = signClockMapping(keyPair, mappingPayload);
  const trust = {
    version: 1,
    trusted: true,
    revoked: false,
    clock_id: mappingPayload.clock_id,
    monotonic_epoch_id: mappingPayload.monotonic_epoch_id,
    current_mapping_generation: mappingPayload.mapping_generation,
    current_signed_mapping_digest: mapping.signed_mapping_digest,
    trust_root_epoch: mappingPayload.trust_root_epoch,
    authority_epoch: mappingPayload.authority_epoch,
    revocation_generation: mappingPayload.revocation_generation,
    signer_key_id: mappingPayload.signer_key_id,
    signer_public_key_digest: mappingPayload.signer_public_key_digest,
    public_key: keyPair.publicKey,
  };
  return {
    control,
    port: createPhysicalTrustedClockPort({
      port_id: "inventory_checkpoint_test_clock",
      clock_id: mappingPayload.clock_id,
      monotonic_epoch_id: mappingPayload.monotonic_epoch_id,
      uncertainty_ceiling_ms: 0,
      read_monotonic_ms: () => control.monotonic_ms,
      read_signed_mapping: () => mapping,
      resolve_current_trust: () => trust,
    }),
  };
}

const BASE_BINDINGS = Object.freeze({
  session_nucleus_hash: digest("inventory-session-nucleus"),
  physical_scope_axis_digest: digest("inventory-physical-scope-axis"),
  instrument_ref: "instrument:chameleon-ultra-fixture",
  enrollment_candidate_ref: "enrollment-candidate:chameleon-ultra-fixture",
  provider_id: "fixture_provider",
  provider_descriptor_digest: digest("fixture-provider-descriptor"),
  provider_binary_digest: digest("fixture-provider-binary"),
  transport_digest: digest("fixture-transport"),
  bootstrap_manifest_digest: digest("fixture-bootstrap-manifest"),
  connection_generation: 4,
});

function receipt(operationId, bindings = BASE_BINDINGS, overrides = {}) {
  const suffix = operationId.split(".").at(-1);
  const body = {
    version: 1,
    operation_id: operationId,
    ...bindings,
    execution_request_digest: digest(`${suffix}-execution-request`),
    signed_grant_digest: digest(`${suffix}-signed-grant`),
    operation_digest: digest(`${suffix}-operation`),
    response_digest: digest(`${suffix}-response`),
    receipt_ref: `bootstrap-receipt:${suffix}-fixture`,
    observed_at: "2026-07-18T12:00:10.000Z",
    ...overrides,
  };
  delete body.receipt_digest;
  return { ...body, receipt_digest: hashCanonicalJson(body) };
}

function invariantWitness(bindings = BASE_BINDINGS, overrides = {}) {
  const body = {
    version: 1,
    ...bindings,
    rf_state: "off",
    rf_off_witness_digest: digest("rf-off-witness"),
    mode_unchanged: true,
    mode_unchanged_witness_digest: digest("mode-unchanged-witness"),
    workspace_unchanged: true,
    workspace_unchanged_witness_digest: digest("workspace-unchanged-witness"),
    witness_authentication_digest: digest("witness-authentication"),
    witnessed_at: "2026-07-18T12:00:19.000Z",
    ...overrides,
  };
  delete body.witness_set_digest;
  return { ...body, witness_set_digest: hashCanonicalJson(body) };
}

function assuranceClaims(overrides = {}) {
  const body = {
    identity_enrollment: {
      status: "unverified",
      evidence_digest: digest("identity-enrollment-assurance"),
    },
    firmware_provenance: {
      status: "self_reported",
      evidence_digest: digest("firmware-provenance-assurance"),
    },
    command_surface_conformance: {
      status: "bootstrap_allowlisted",
      evidence_digest: digest("command-surface-assurance"),
    },
    transport_trust: {
      status: "local_observed",
      evidence_digest: digest("transport-trust-assurance"),
    },
    ...overrides,
  };
  delete body.claims_digest;
  return { ...body, claims_digest: hashCanonicalJson(body) };
}

function capturePayload(overrides = {}) {
  return {
    version: 1,
    source_id: "physical_inventory_fixture",
    ...BASE_BINDINGS,
    assurance_profile_id: "bootstrap_read_only",
    assurance_claims: assuranceClaims(),
    execution_receipts: REQUIRED_OPERATION_IDS.map((operationId) => receipt(operationId)),
    invariant_witness: invariantWitness(),
    captured_at: "2026-07-18T12:00:20.000Z",
    valid_from: "2026-07-18T12:00:00.000Z",
    expires_at: "2026-07-18T12:10:00.000Z",
    attested_at: "2026-07-18T12:00:21.000Z",
    source_trust_epoch: 6,
    source_revocation_generation: 3,
    ...overrides,
  };
}

function signCapture(keyPair, signerKeyId, payload) {
  const signerPublicKeyDigest = publicKeyDigest(keyPair.publicKey);
  const payloadDigest = hashCanonicalJson(payload);
  const signature = crypto.sign(
    null,
    physicalInventoryCaptureSigningMessage({
      payload_digest: payloadDigest,
      signer_key_id: signerKeyId,
      signer_public_key_digest: signerPublicKeyDigest,
    }),
    keyPair.privateKey,
  ).toString("base64url");
  const basis = {
    version: 1,
    domain: PHYSICAL_INVENTORY_CAPTURE_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    scheme: "ed25519",
    signer_key_id: signerKeyId,
    signer_public_key_digest: signerPublicKeyDigest,
    signature,
  };
  return { ...basis, authenticated_capture_digest: hashCanonicalJson(basis) };
}

function createFixture(options = {}) {
  const clock = createClockFixture(options.clock || {});
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const signerKeyId = "inventory-key:fixture-source-1";
  const control = {
    disposition: "current",
    trust_epoch: 6,
    revocation_generation: 3,
    connection_generation: 4,
    capture: null,
    read_queries: [],
    trust_queries: [],
  };
  control.capture = signCapture(
    keyPair,
    signerKeyId,
    options.payload || capturePayload(),
  );
  const source = createFixturePhysicalInventoryCheckpointSource({
    source_id: "physical_inventory_fixture",
    signer_key_id: signerKeyId,
    signer_public_key_digest: publicKeyDigest(keyPair.publicKey),
    signer_public_key: keyPair.publicKey,
    trusted_clock_port: clock.port,
    read_authenticated_capture: (query) => {
      control.read_queries.push(query);
      return control.capture;
    },
    resolve_current_trust: (query) => {
      control.trust_queries.push(query);
      return {
        version: 1,
        source_id: "physical_inventory_fixture",
        disposition: control.disposition,
        source_trust_epoch: control.trust_epoch,
        source_revocation_generation: control.revocation_generation,
        signer_key_id: signerKeyId,
        signer_public_key_digest: publicKeyDigest(keyPair.publicKey),
        current_connection_generation: control.connection_generation,
      };
    },
  });
  function setPayload(payload) {
    control.capture = signCapture(keyPair, signerKeyId, payload);
  }
  return { clock, control, keyPair, signerKeyId, source, setPayload };
}

test("a signed source yields one current, canonical, byte-free PH-IP1 checkpoint", () => {
  assert.equal(Object.hasOwn(checkpointContract, "assertCurrentPhysicalInventoryCheckpoint"), false);
  const fixture = createFixture();
  const checkpoint = captureFixturePhysicalInventoryCheckpoint(fixture.source, BASE_BINDINGS);
  assert.equal(assertFixturePhysicalInventoryCheckpointSource(fixture.source), fixture.source);
  assert.equal(assertFixturePhysicalInventoryCheckpoint(checkpoint), checkpoint);
  assert.equal(assertCurrentFixturePhysicalInventoryCheckpoint(checkpoint, BASE_BINDINGS), checkpoint);

  const projection = projectFixturePhysicalInventoryCheckpoint(checkpoint);
  assert.equal(projection.disposition, "current");
  assert.deepEqual(projection.required_operation_ids, REQUIRED_OPERATION_IDS);
  assert.deepEqual(
    projection.execution_receipts.map((entry) => entry.operation_id),
    REQUIRED_OPERATION_IDS,
  );
  assert.equal(
    projection.inventory_observation_ref,
    `physical-inventory-observation:${projection.inventory_observation_digest}`,
  );
  assert.equal(
    projection.checkpoint_ref,
    `physical-inventory-checkpoint:${projection.checkpoint_digest}`,
  );
  assert.equal(projection.assurance_class, "fixture_contract_only");
  assert.equal(projection.production_ready, false);
  assert.equal(projection.hil_attested, false);
  assert.equal(projection.lifecycle_authority, false);
  assert.equal(projection.execution_authority, false);
  assert.equal(fixture.source.lifecycle_authority, false);
  assert.equal(fixture.source.execution_authority, false);
  assert.deepEqual(projection.readiness_blockers, READINESS_BLOCKERS);
  assert.equal(Object.keys(projection.assurance_claims).length, 5);
  assert.deepEqual(
    Object.fromEntries(Object.entries(projection.assurance_claims)
      .filter(([axis]) => axis !== "claims_digest")
      .map(([axis, claim]) => [axis, claim.status])),
    {
      identity_enrollment: "unverified",
      firmware_provenance: "self_reported",
      command_surface_conformance: "bootstrap_allowlisted",
      transport_trust: "local_observed",
    },
  );
  assert.deepEqual(
    Object.keys(projection.authenticated_invariant_witness_digests).sort(),
    ["authentication", "mode_unchanged", "rf_off", "witness_set_digest", "workspace_unchanged"],
  );
  assert.ok(Object.isFrozen(checkpoint));
  assert.ok(Object.isFrozen(projection));
  assert.ok(Object.isFrozen(fixture.control.read_queries[0]));
  assert.ok(Object.isFrozen(fixture.control.trust_queries[0]));

  const serialized = JSON.stringify({ source: fixture.source, checkpoint, projection });
  assert.equal(serialized.includes("signature"), false);
  assert.equal(serialized.includes("PRIVATE KEY"), false);
  assert.equal(serialized.includes("read_authenticated_capture"), false);
  assert.equal(serialized.includes("resolve_current_trust"), false);
});

test("source and checkpoint trust brands cannot be recreated by spread or serialization", () => {
  const fixture = createFixture();
  assert.throws(
    () => captureFixturePhysicalInventoryCheckpoint(Object.freeze({ ...fixture.source }), BASE_BINDINGS),
    /privately branded live source/,
  );
  const checkpoint = captureFixturePhysicalInventoryCheckpoint(fixture.source, BASE_BINDINGS);
  const spread = Object.freeze({ ...checkpoint });
  const serialized = Object.freeze(JSON.parse(JSON.stringify(checkpoint)));
  assert.throws(() => assertFixturePhysicalInventoryCheckpoint(spread), /privately branded/);
  assert.throws(() => assertCurrentFixturePhysicalInventoryCheckpoint(serialized, BASE_BINDINGS), /privately branded/);
  assert.throws(() => projectFixturePhysicalInventoryCheckpoint(serialized), /privately branded/);

  const tampered = structuredClone(fixture.control.capture);
  tampered.payload.execution_receipts[0].response_digest = digest("attacker-response");
  fixture.control.capture = tampered;
  assert.throws(
    () => captureFixturePhysicalInventoryCheckpoint(fixture.source, BASE_BINDINGS),
    /receipt_digest does not bind|payload_digest does not bind|signature is invalid/,
  );
});

test("the checkpoint rejects partial, duplicate, and binding-drifted receipt sets", () => {
  const fixture = createFixture();

  const partial = capturePayload({
    execution_receipts: REQUIRED_OPERATION_IDS.slice(0, 2).map((operationId) => receipt(operationId)),
  });
  fixture.setPayload(partial);
  assert.throws(
    () => captureFixturePhysicalInventoryCheckpoint(fixture.source, BASE_BINDINGS),
    /exact three-operation set/,
  );

  const duplicate = capturePayload({
    execution_receipts: [
      receipt("instrument.capabilities"),
      receipt("instrument.capabilities", BASE_BINDINGS, {
        receipt_ref: "bootstrap-receipt:capabilities-duplicate",
      }),
      receipt("instrument.inventory"),
    ],
  });
  fixture.setPayload(duplicate);
  assert.throws(
    () => captureFixturePhysicalInventoryCheckpoint(fixture.source, BASE_BINDINGS),
    /inventory, capabilities, and health exactly once/,
  );

  const driftedBindings = {
    ...BASE_BINDINGS,
    provider_binary_digest: digest("drifted-provider-binary"),
  };
  const driftedReceipt = capturePayload({
    execution_receipts: REQUIRED_OPERATION_IDS.map((operationId) => (
      operationId === "instrument.health"
        ? receipt(operationId, driftedBindings)
        : receipt(operationId)
    )),
  });
  fixture.setPayload(driftedReceipt);
  assert.throws(
    () => captureFixturePhysicalInventoryCheckpoint(fixture.source, BASE_BINDINGS),
    /provider_binary_digest is detached/,
  );

  const nextConnection = { ...BASE_BINDINGS, connection_generation: 5 };
  fixture.setPayload(capturePayload({
    connection_generation: 5,
    execution_receipts: REQUIRED_OPERATION_IDS.map((operationId) => receipt(operationId, nextConnection)),
    invariant_witness: invariantWitness(nextConnection),
  }));
  assert.throws(
    () => captureFixturePhysicalInventoryCheckpoint(fixture.source, BASE_BINDINGS),
    /connection_generation is detached/,
  );
});

test("receipt arrays must be dense and all observations must be inside the capture window", () => {
  const fixture = createFixture();
  const sparseReceipts = new Array(REQUIRED_OPERATION_IDS.length);
  sparseReceipts[0] = receipt(REQUIRED_OPERATION_IDS[0]);
  sparseReceipts[2] = receipt(REQUIRED_OPERATION_IDS[2]);
  fixture.setPayload(capturePayload({ execution_receipts: sparseReceipts }));
  assert.throws(
    () => captureFixturePhysicalInventoryCheckpoint(fixture.source, BASE_BINDINGS),
    /dense array/,
  );

  fixture.setPayload(capturePayload({
    execution_receipts: REQUIRED_OPERATION_IDS.map((operationId) => receipt(
      operationId,
      BASE_BINDINGS,
      operationId === "instrument.inventory"
        ? { observed_at: "2026-07-18T11:59:59.999Z" }
        : {},
    )),
  }));
  assert.throws(
    () => captureFixturePhysicalInventoryCheckpoint(fixture.source, BASE_BINDINGS),
    /observed_at must be inside valid_from through captured_at/,
  );

  fixture.setPayload(capturePayload({
    invariant_witness: invariantWitness(BASE_BINDINGS, {
      witnessed_at: "2026-07-18T11:59:59.999Z",
    }),
  }));
  assert.throws(
    () => captureFixturePhysicalInventoryCheckpoint(fixture.source, BASE_BINDINGS),
    /witnessed_at must be inside valid_from through captured_at/,
  );
});

test("assurance and invariant witnesses are canonical, authenticated, and fail closed", () => {
  const fixture = createFixture();
  const invalidAssurance = assuranceClaims();
  invalidAssurance.claims_digest = digest("forged-assurance-claims");
  fixture.setPayload(capturePayload({ assurance_claims: invalidAssurance }));
  assert.throws(
    () => captureFixturePhysicalInventoryCheckpoint(fixture.source, BASE_BINDINGS),
    /claims_digest does not bind the four assurance axes/,
  );

  fixture.setPayload(capturePayload({
    invariant_witness: invariantWitness(BASE_BINDINGS, { mode_unchanged: false }),
  }));
  assert.throws(
    () => captureFixturePhysicalInventoryCheckpoint(fixture.source, BASE_BINDINGS),
    /mode_unchanged must be true/,
  );

  const forgedWitness = invariantWitness();
  forgedWitness.rf_off_witness_digest = digest("forged-rf-witness");
  fixture.setPayload(capturePayload({ invariant_witness: forgedWitness }));
  assert.throws(
    () => captureFixturePhysicalInventoryCheckpoint(fixture.source, BASE_BINDINGS),
    /witness_set_digest does not bind/,
  );
});

test("live source revocation, disconnect, and connection drift invalidate a prior checkpoint", () => {
  const fixture = createFixture();
  const checkpoint = captureFixturePhysicalInventoryCheckpoint(fixture.source, BASE_BINDINGS);

  fixture.control.disposition = "revoked";
  assert.equal(projectFixturePhysicalInventoryCheckpoint(checkpoint).disposition, "revoked");
  assert.throws(
    () => assertCurrentFixturePhysicalInventoryCheckpoint(checkpoint, BASE_BINDINGS),
    /checkpoint is revoked/,
  );

  fixture.control.disposition = "disconnected";
  assert.equal(projectFixturePhysicalInventoryCheckpoint(checkpoint).disposition, "disconnected");
  assert.throws(
    () => assertCurrentFixturePhysicalInventoryCheckpoint(checkpoint, BASE_BINDINGS),
    /checkpoint is disconnected/,
  );

  fixture.control.disposition = "current";
  fixture.control.connection_generation += 1;
  assert.equal(projectFixturePhysicalInventoryCheckpoint(checkpoint).disposition, "disconnected");

  fixture.control.connection_generation = BASE_BINDINGS.connection_generation;
  fixture.control.trust_epoch += 1;
  assert.equal(projectFixturePhysicalInventoryCheckpoint(checkpoint).disposition, "revoked");
});

test("signed trusted time rejects not-yet-valid and expired checkpoints without a caller-now seam", () => {
  const futureFixture = createFixture({
    payload: capturePayload({
      execution_receipts: REQUIRED_OPERATION_IDS.map((operationId) => receipt(
        operationId,
        BASE_BINDINGS,
        { observed_at: "2026-07-18T12:05:00.000Z" },
      )),
      invariant_witness: invariantWitness(BASE_BINDINGS, {
        witnessed_at: "2026-07-18T12:05:00.000Z",
      }),
      captured_at: "2026-07-18T12:05:00.000Z",
      valid_from: "2026-07-18T12:05:00.000Z",
      attested_at: "2026-07-18T12:05:01.000Z",
    }),
  });
  assert.throws(
    () => captureFixturePhysicalInventoryCheckpoint(futureFixture.source, BASE_BINDINGS),
    /not yet admissible/,
  );

  const fixture = createFixture();
  const checkpoint = captureFixturePhysicalInventoryCheckpoint(fixture.source, BASE_BINDINGS);
  fixture.clock.control.monotonic_ms += 10 * 60 * 1000;
  assert.throws(
    () => assertCurrentFixturePhysicalInventoryCheckpoint(checkpoint, BASE_BINDINGS),
    /has expired/,
  );
  assert.throws(() => projectFixturePhysicalInventoryCheckpoint(checkpoint), /has expired/);
});

test("closed schemas and byte bans stop raw capture material at the source boundary", () => {
  const unknownFixture = createFixture();
  unknownFixture.control.capture = {
    ...unknownFixture.control.capture,
    attacker_field: "unexpected",
  };
  assert.throws(
    () => captureFixturePhysicalInventoryCheckpoint(unknownFixture.source, BASE_BINDINGS),
    /unknown fields: attacker_field/,
  );

  const byteFixture = createFixture();
  byteFixture.control.capture = {
    ...byteFixture.control.capture,
    payload: {
      ...byteFixture.control.capture.payload,
      raw_bytes: Buffer.from([1, 2, 3]),
    },
  };
  assert.throws(
    () => captureFixturePhysicalInventoryCheckpoint(byteFixture.source, BASE_BINDINGS),
    /must not contain raw byte material/,
  );
});
