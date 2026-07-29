"use strict";

// Test-only durable ABI-v3 bootstrap authority for provider conformance. The
// returned callback cannot be serialized into production authority and the
// store is removed on close.

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  normalizeProviderBootstrapIntent,
  normalizeProviderBootstrapRequest,
} = require("../../mcp/lib/instrument-provider-contract.js");
const {
  createDurableInstrumentBootstrapStore,
  createInstrumentBootstrapBrokerCustodyBinding,
  createInstrumentBootstrapBrokerPort,
  createInstrumentBootstrapProviderRedemptionPort,
  readInstrumentBootstrapCustodyProjection,
} = require("../../mcp/lib/instrument-bootstrap-store.js");
const {
  hashCanonicalJson,
} = require("../../mcp/lib/verification-contracts.js");

function digest(label, value = null) {
  return hashCanonicalJson({
    domain: "hacker-bob/durable-provider-bootstrap-test/v1",
    label,
    value,
  });
}

function clone(value) {
  return value == null ? null : structuredClone(value);
}

function createDurableProviderBootstrapHarness({
  descriptor,
  instrumentRef,
  executionPrincipalId = "principal:deterministic-bootstrap-worker",
} = {}) {
  if (!descriptor) throw new Error("durable provider bootstrap harness requires a descriptor");
  if (typeof instrumentRef !== "string" || !instrumentRef.startsWith("instrument:")) {
    throw new Error("durable provider bootstrap harness requires an instrument reference");
  }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-provider-bootstrap-harness-"));
  fs.chmodSync(root, 0o700);
  let anchor = null;
  const stateAnchor = {
    readState() {
      return clone(anchor);
    },
    compareAndSet(input) {
      const expectedGeneration = anchor == null ? null : anchor.generation;
      const expectedHead = anchor == null ? null : anchor.head_event_digest;
      if (input.expected_generation !== expectedGeneration
          || input.expected_head_event_digest !== expectedHead) return false;
      anchor = clone(input.next_state);
      return true;
    },
  };
  const sessionNucleusHash = digest("session-nucleus", descriptor.descriptor_digest);
  const runtimeSeed = digest("runtime", root);
  const store = createDurableInstrumentBootstrapStore({
    root,
    runtimeId: `physical-runtime:v1:${runtimeSeed.slice(0, 32)}`,
    sessionNucleusHash,
    masterKey: crypto.createHash("sha256").update(runtimeSeed).digest(),
    stateAnchor,
    now: () => new Date("2026-07-18T00:10:00.000Z"),
  });
  const broker = createInstrumentBootstrapBrokerPort(store);
  const enrollment = Object.freeze({
    provider_id: descriptor.provider_id,
    provider_descriptor_digest: descriptor.descriptor_digest,
    provider_binary_digest: digest("provider-binary", descriptor.implementation_digest),
    transport_digest: digest("transport"),
    bootstrap_manifest_digest: digest("bootstrap-manifest"),
    bootstrap_invariants_digest: digest("bootstrap-invariants"),
    execution_principal_id: executionPrincipalId,
    instrument_ref: instrumentRef,
    enrollment_candidate_ref: "enrollment-candidate:deterministic-provider-0001",
    connection_ref: "instrument-connection:deterministic-provider-0001",
  });
  const connectionGeneration = 1;
  const custodyBinding = createInstrumentBootstrapBrokerCustodyBinding(broker, {
    custody_authority: Object.freeze(Object.create(null)),
    read_connection_generation() {
      return {
        connection_ref: enrollment.connection_ref,
        connection_generation: connectionGeneration,
        connected: true,
      };
    },
  });
  const port = createInstrumentBootstrapProviderRedemptionPort(store, {
    provider_id: enrollment.provider_id,
    provider_descriptor_digest: enrollment.provider_descriptor_digest,
    provider_binary_digest: enrollment.provider_binary_digest,
    transport_digest: enrollment.transport_digest,
    bootstrap_manifest_digest: enrollment.bootstrap_manifest_digest,
    bootstrap_invariants_digest: enrollment.bootstrap_invariants_digest,
    execution_principal_id: enrollment.execution_principal_id,
    instrument_ref: enrollment.instrument_ref,
    enrollment_candidate_ref: enrollment.enrollment_candidate_ref,
    custody_binding: custodyBinding,
    revalidateBootstrapAuthority() {
      return true;
    },
  });
  let sequence = 0;
  let closed = false;

  function authorize({ descriptor: suppliedDescriptor, operation_id: operationId, operation_digest: operationDigest }) {
    if (suppliedDescriptor.descriptor_digest !== descriptor.descriptor_digest) {
      throw new Error("durable provider bootstrap descriptor drifted");
    }
    sequence += 1;
    const intentInput = {
      version: 1,
      call_kind: "bootstrap",
      attempt_ref: `bootstrap-attempt:provider-${String(sequence).padStart(4, "0")}`,
      session_nucleus_hash: sessionNucleusHash,
      physical_scope_axis_digest: digest("physical-scope-axis"),
      execution_principal_id: enrollment.execution_principal_id,
      instrument_ref: enrollment.instrument_ref,
      enrollment_candidate_ref: enrollment.enrollment_candidate_ref,
      provider_id: descriptor.provider_id,
      provider_descriptor_digest: descriptor.descriptor_digest,
      provider_binary_digest: enrollment.provider_binary_digest,
      transport_digest: enrollment.transport_digest,
      bootstrap_manifest_digest: enrollment.bootstrap_manifest_digest,
      bootstrap_invariants_digest: enrollment.bootstrap_invariants_digest,
      operation_id: operationId,
      operation_digest: operationDigest,
      execution_request_digest: digest("execution-request", sequence),
      authority_resolution_digest: digest("authority-resolution", sequence),
      signed_grant_digest: digest("signed-grant", sequence),
      replay_claim_digest: digest("replay-claim", sequence),
      replay_reservation_receipt_digest: digest("replay-receipt", sequence),
      connection_ref: enrollment.connection_ref,
      connection_generation: connectionGeneration,
      grant_not_before: "2026-07-18T00:00:00.000Z",
      grant_expires_at: "2026-07-18T01:00:00.000Z",
    };
    const intent = normalizeProviderBootstrapIntent(intentInput, descriptor);
    const custodyProjection = readInstrumentBootstrapCustodyProjection(custodyBinding);
    const precommit = broker.precommitAttempt({
      provider_abi_version: descriptor.abi_version,
      ...intentInput,
      bootstrap_intent_digest: intent.bootstrap_intent_digest,
      bootstrap_grant_projection_digest: digest("grant-projection", sequence),
      custody_binding_digest: custodyProjection.custody_binding_digest,
    }, custodyProjection);
    const dispatch = broker.commitDispatch({
      version: 1,
      attempt_ref: precommit.attempt_ref,
      expected_durable_attempt_binding_digest: precommit.durable_attempt_binding_digest,
    }, custodyProjection);
    return normalizeProviderBootstrapRequest({
      ...intent,
      dispatch_record_digest: dispatch.dispatch.dispatch_record_digest,
      dispatch_credential: dispatch.dispatch_credential,
    }, descriptor);
  }

  function close() {
    if (closed) return;
    closed = true;
    store.close();
    fs.rmSync(root, { recursive: true, force: true });
  }

  return Object.freeze({ authorize, close, port, store });
}

module.exports = {
  createDurableProviderBootstrapHarness,
};
