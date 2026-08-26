"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  EDGE_TYPES,
  PHYSICAL_NODE_TYPES,
  PHYSICAL_RELATIONSHIP_EDGE_TYPES,
  PHYSICAL_SURFACE_GRAPH_ONTOLOGY,
  appendEdges,
  createPhysicalSurfaceGraphServerService,
  normalizeEdge,
} = require("../mcp/core/frontier/surface-graph.js");
const {
  buildDurableReceiptTrustRegistry,
} = require("../mcp/core/executed-evidence-registry.js");
const {
  normalizePhysicalSurfaceLiveRevalidationPayload,
  normalizePhysicalSurfaceTransitionPayload,
  physicalSurfaceTransitionClaimPredicateDigest,
} = require("../mcp/domains/physical/physical-surface-transition.js");
const {
  buildSessionNucleus,
  normalizePhysicalScopeNucleusAxis,
} = require("../mcp/core/governance/index.js");
const { acquireSessionLock } = require("../mcp/core/io/storage.js");
const { hashCanonicalJson } = require("../mcp/core/verification/verification-contracts.js");

function digest(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function sessionPath(domain, basename = "") {
  return path.join(os.homedir(), "hacker-bob-sessions", domain, basename);
}

function uniqueDomain() {
  return `bob-ph-s8-${crypto.randomBytes(6).toString("hex")}.local`;
}

function installSession(domain, registryDigest) {
  const physicalScope = normalizePhysicalScopeNucleusAxis({
    version: 1,
    physical_enabled: true,
    policy_version: 1,
    policy_id: "ph_s8_acceptance",
    policy_digest: digest("policy"),
    projection_version: 1,
    projection_digest: digest("scope-projection"),
    provenance_digest: digest("scope-provenance"),
    compatibility_digest: digest("scope-compatibility"),
    transition_receipt_registry_digest: registryDigest,
    authority_epoch: 17,
    revocation_generation: 4,
  });
  const nucleus = buildSessionNucleus({
    target_domain: domain,
    target_url: `https://${domain}`,
    scope_policy: {
      target_domain: domain,
      target_url: `https://${domain}`,
      checkpoint_mode: "normal",
      block_internal_hosts: false,
      block_internal_hosts_source: "mode_default",
    },
    egress_identity: { egress_profile: "default", proxy_configured: false },
    auth_context: { auth_status: "pending" },
    operator_constraint: { handoff_provenance_required: true },
    lifecycle_state: "SETUP",
    physical_scope: physicalScope,
  });
  fs.mkdirSync(sessionPath(domain), { recursive: true, mode: 0o700 });
  fs.writeFileSync(
    sessionPath(domain, "session-nucleus.json"),
    `${JSON.stringify(nucleus)}\n`,
    { encoding: "utf8", mode: 0o600 },
  );
  return nucleus;
}

function receiptFixture(domain) {
  const authorities = {
    physical_surface_transition: {
      keys: crypto.generateKeyPairSync("ed25519"),
      keyId: "signer-key:surface-transition",
      epoch: 23,
    },
    physical_surface_live_revalidation: {
      keys: crypto.generateKeyPairSync("ed25519"),
      keyId: "signer-key:surface-live-state",
      epoch: 29,
    },
  };
  const registry = buildDurableReceiptTrustRegistry({
    version: 1,
    registry_id: "ph-s8-acceptance",
    issuers: Object.entries(authorities).map(([receiptKind, authority]) => ({
      issuer_key_id: authority.keyId,
      issuer_epoch: authority.epoch,
      signature_scheme: "ed25519",
      public_key_pem: authority.keys.publicKey.export({ type: "spki", format: "pem" }),
      receipt_kinds: [receiptKind],
      valid_from: "2020-01-01T00:00:00.000Z",
      expires_at: "2100-01-01T00:00:00.000Z",
      trusted: true,
      revoked: false,
    })),
  });
  const nucleus = installSession(domain, registry.registry_digest);
  const receipts = new Map();
  const prefix = {
    physical_surface_transition: "surface-transition",
    physical_surface_live_revalidation: "surface-live-state",
  };

  function sign(receiptKind, payloadInput, signedAt = new Date().toISOString()) {
    const authority = authorities[receiptKind];
    const payload = receiptKind === "physical_surface_transition"
      ? normalizePhysicalSurfaceTransitionPayload(payloadInput)
      : normalizePhysicalSurfaceLiveRevalidationPayload(payloadInput);
    const semantic = {
      domain: "hacker-bob/durable-evidence-receipt-semantic/v1",
      version: 1,
      receipt_kind: receiptKind,
      payload,
      issuer_registry_digest: registry.registry_digest,
      issuer_key_id: authority.keyId,
      issuer_epoch: authority.epoch,
    };
    const envelope = {
      issuer_registry_digest: registry.registry_digest,
      issuer_key_id: authority.keyId,
      issuer_epoch: authority.epoch,
      semantic_digest: hashCanonicalJson(semantic),
      signature_scheme: "ed25519",
      signed_at: signedAt,
    };
    const signatureInput = hashCanonicalJson({
      domain: "hacker-bob/durable-evidence-receipt/v1",
      version: 1,
      receipt_kind: receiptKind,
      payload,
      ...envelope,
    });
    const signedBody = {
      version: 1,
      receipt_kind: receiptKind,
      payload,
      ...envelope,
      signature: crypto.sign(
        null,
        Buffer.from(signatureInput, "hex"),
        authority.keys.privateKey,
      ).toString("base64url"),
    };
    const receiptDigest = hashCanonicalJson(signedBody);
    const receipt = Object.freeze({
      ...signedBody,
      receipt_digest: receiptDigest,
      receipt_ref: `${prefix[receiptKind]}:v1:${receiptDigest}`,
    });
    receipts.set(receipt.receipt_ref, receipt);
    return receipt;
  }

  return { registry, nucleus, receipts, sign };
}

function topology(domain) {
  return {
    target_domain: domain,
    participants: [{
      participant_id: "subject",
      role: "subject",
      node: { type: "asset", id: "asset:opaque-subject" },
    }, {
      participant_id: "representation",
      role: "source_state",
      node: { type: "representation", id: "representation:opaque-state" },
    }, {
      participant_id: "stimulus",
      role: "instrument",
      node: { type: "instrument", id: "instrument:opaque-source" },
    }, {
      participant_id: "observer",
      role: "verifier",
      node: { type: "verifier", id: "verifier:opaque-observer" },
    }, {
      participant_id: "outcome",
      role: "outcome",
      node: { type: "control_point", id: "control-point:opaque-outcome" },
    }],
    arcs: [{
      arc_id: "subject-to-outcome",
      source_participant_id: "subject",
      target_participant_id: "outcome",
      edge_type: "demonstrated_transition",
    }, {
      arc_id: "representation-to-subject",
      source_participant_id: "representation",
      target_participant_id: "subject",
      edge_type: "demonstrated_transition",
    }, {
      arc_id: "stimulus-to-outcome",
      source_participant_id: "stimulus",
      target_participant_id: "outcome",
      edge_type: "demonstrated_transition",
    }, {
      arc_id: "observer-to-outcome",
      source_participant_id: "observer",
      target_participant_id: "outcome",
      edge_type: "demonstrated_transition",
    }],
  };
}

function transitionPayload(domain, nucleusHash, nowMs) {
  const graphTopology = topology(domain);
  const decidedAt = new Date(nowMs - 5_000).toISOString();
  return {
    version: 1,
    surface_graph_schema_version: 2,
    target_domain: domain,
    session_nucleus_hash: nucleusHash,
    experiment_id: "experiment-ph-s8",
    task_id: "task-ph-s8",
    attempt_id: "attempt-ph-s8",
    plan_hash: digest("plan"),
    execution_request_digest: digest("execution-request"),
    claim_predicate_digest: physicalSurfaceTransitionClaimPredicateDigest(graphTopology),
    claim_verdict_ref: "physical-claim-verdict:ph-s8",
    claim_verdict_hash: digest("claim-verdict"),
    claim_verdict_signer_key_id: "signer-key:server-verifier",
    claim_verdict_signer_principal_ref: "principal:server-verifier",
    claim_verdict_trust_root_epoch: 31,
    claim_verdict_trust_domain_ref: "trust-domain:server-verifier",
    claim_verdict_independence_domain_ref: "independence-domain:server-verifier",
    claim_verdict_trust_registry_digest: digest("claim-trust-registry"),
    claim_verdict_signer_enrollment_digest: digest("claim-signer-enrollment"),
    claim_verdict_authorization_context_digest: digest("claim-authorization-context"),
    verified_claim_projection_digest: digest("verified-claim-projection"),
    verifier_execution_receipt_ref: `verifier-execution:v1:${digest("verifier-execution")}`,
    verifier_execution_receipt_digest: digest("verifier-execution"),
    executed_evidence_registry_digest: digest("executed-evidence-registry"),
    verifier_template_id: "physical.transition-differential",
    verifier_template_version: 7,
    verifier_template_digest: digest("verifier-template"),
    decision_rule_digest: digest("decision-rule"),
    outcome: "verified",
    reason_code: "differential_verified",
    decided_at: decidedAt,
    upstream_execution_identities: ["execution:control", "execution:positive"],
    upstream_context_digest: digest("upstream-context"),
    physical_state_epoch: 41,
    physical_state_digest: digest("physical-state-41"),
    validity_kind: "live_capability",
    valid_from: decidedAt,
    expires_at: new Date(nowMs + 120_000).toISOString(),
    capability_instance_ref: "capability-instance:physical-state-41",
    custody_state_digest: digest("custody-state-41"),
    participants: graphTopology.participants,
    arcs: graphTopology.arcs,
  };
}

function livePayload(request, transition, nowMs, overrides = {}) {
  return {
    version: 1,
    surface_graph_schema_version: 2,
    target_domain: transition.target_domain,
    session_nucleus_hash: transition.session_nucleus_hash,
    authority_context_digest: request.authority_context_digest,
    transition_receipt_ref: request.transition_receipt_ref,
    transition_receipt_digest: request.transition_receipt_digest,
    transition_payload_digest: request.transition_payload_digest,
    challenge_nonce: request.challenge_nonce,
    claim_verdict_ref: transition.claim_verdict_ref,
    claim_verdict_hash: transition.claim_verdict_hash,
    verified_claim_projection_digest: transition.verified_claim_projection_digest,
    claim_verdict_signer_key_id: transition.claim_verdict_signer_key_id,
    claim_verdict_trust_root_epoch: transition.claim_verdict_trust_root_epoch,
    verifier_template_id: transition.verifier_template_id,
    verifier_template_version: transition.verifier_template_version,
    verifier_template_digest: transition.verifier_template_digest,
    decision_rule_digest: transition.decision_rule_digest,
    upstream_execution_identities: transition.upstream_execution_identities,
    upstream_context_digest: transition.upstream_context_digest,
    physical_state_epoch: transition.physical_state_epoch,
    physical_state_digest: transition.physical_state_digest,
    validity_kind: "live_capability",
    valid_from: transition.valid_from,
    expires_at: transition.expires_at,
    capability_instance_ref: transition.capability_instance_ref,
    custody_state_digest: transition.custody_state_digest,
    status: "current",
    revalidated_at: new Date(nowMs - 10).toISOString(),
    revalidation_expires_at: new Date(nowMs + 10_000).toISOString(),
    ...overrides,
  };
}

test("PH-S8 closes the physical ontology and admits only exact, current, signed N-ary transitions", () => {
  const domain = uniqueDomain();
  const nowMs = Date.now();
  const fixture = receiptFixture(domain);
  const payload = transitionPayload(domain, fixture.nucleus.nucleus_hash, nowMs);
  const transition = fixture.sign(
    "physical_surface_transition",
    payload,
    new Date(nowMs - 4_000).toISOString(),
  );
  let liveMode = "current";
  let cachedLiveReceipt = null;
  let liveResolveCount = 0;
  let transitionResolveCount = 0;

  const service = createPhysicalSurfaceGraphServerService({
    target_domain: domain,
    resolve_receipt({ receipt_ref: receiptRef }) {
      transitionResolveCount += 1;
      return fixture.receipts.get(receiptRef) || null;
    },
    resolve_trust_registry({ issuer_registry_digest: registryDigest }) {
      return registryDigest === fixture.registry.registry_digest ? fixture.registry : null;
    },
    resolve_live_revalidation_receipt(request) {
      liveResolveCount += 1;
      if (liveMode === "replay" && cachedLiveReceipt) return cachedLiveReceipt;
      const currentNow = Date.now();
      const overrides = liveMode === "stale_custody"
        ? { custody_state_digest: digest("rotated-custody") }
        : {};
      const candidate = fixture.sign(
        "physical_surface_live_revalidation",
        livePayload(request, payload, currentNow - 100, overrides),
        new Date(currentNow - 100).toISOString(),
      );
      if (liveMode === "replay") cachedLiveReceipt = candidate;
      if (liveMode === "tampered") {
        return { ...candidate, payload: { ...candidate.payload, physical_state_epoch: 42 } };
      }
      return candidate;
    },
  });

  try {
    assert.ok(Object.isFrozen(PHYSICAL_SURFACE_GRAPH_ONTOLOGY));
    assert.equal(PHYSICAL_SURFACE_GRAPH_ONTOLOGY.schema_version, 2);
    assert.deepEqual(PHYSICAL_SURFACE_GRAPH_ONTOLOGY.node_types, PHYSICAL_NODE_TYPES);
    assert.deepEqual(
      PHYSICAL_SURFACE_GRAPH_ONTOLOGY.relationship_edge_types,
      PHYSICAL_RELATIONSHIP_EDGE_TYPES,
    );
    assert.deepEqual(
      PHYSICAL_SURFACE_GRAPH_ONTOLOGY.demonstrated_edge_types,
      ["demonstrated_transition"],
    );
    assert.ok(EDGE_TYPES.includes("demonstrated_transition"));
    assert.throws(
      () => normalizeEdge({
        source: { type: "unknown_physical_kind", id: "opaque:one" },
        target: { type: "asset", id: "opaque:two" },
        edge_type: "represented_by",
      }),
      /node vocabulary/,
    );
    assert.throws(
      () => normalizeEdge({
        source: { type: "asset", id: "opaque:one" },
        target: { type: "asset", id: "opaque:two" },
        edge_type: "inferred_transition",
      }),
      /edge vocabulary/,
    );
    assert.throws(
      () => appendEdges({
        target_domain: domain,
        edges: [{
          source: payload.participants[0].node,
          target: payload.participants[4].node,
          edge_type: "demonstrated_transition",
          source_artifact: "agent-inference",
        }],
      }),
      /signed verified N-ary transition receipt/,
    );
    assert.throws(
      () => normalizePhysicalSurfaceTransitionPayload({ ...payload, outcome: "inferred" }),
      /outcome must be verified/,
    );

    let release = acquireSessionLock(domain);
    try {
      const before = transitionResolveCount;
      assert.throws(
        () => service.appendVerifiedTransition({
          receipt_ref: transition.receipt_ref,
          receipt_digest: transition.receipt_digest,
        }),
        /Session lock busy/,
      );
      assert.equal(transitionResolveCount, before);
      assert.equal(fs.existsSync(sessionPath(domain, "surface-graph.jsonl")), false);
    } finally {
      release();
    }

    const appended = service.appendVerifiedTransition({
      receipt_ref: transition.receipt_ref,
      receipt_digest: transition.receipt_digest,
    });
    assert.equal(appended.derived_arc_count, 4);
    assert.equal(appended.new_count, 4);
    assert.throws(
      () => service.queryVerifiedTransitionEdges({ source_type: "unknown_physical_kind" }),
      /node vocabulary/,
    );

    release = acquireSessionLock(domain);
    try {
      const before = liveResolveCount;
      assert.throws(() => service.queryVerifiedTransitionEdges(), /Session lock busy/);
      assert.equal(liveResolveCount, before, "trusted resolution must occur only after read lock acquisition");
    } finally {
      release();
    }

    const current = service.queryVerifiedTransitionEdges();
    assert.equal(current.edges.length, 4);
    assert.equal(
      current.historical_only_count,
      0,
      JSON.stringify(current.edges.map((edge) => edge.eligibility_reason)),
    );
    assert.ok(current.edges.every((edge) => edge.prerequisite_eligible));
    assert.ok(current.edges.every((edge) => edge.eligibility_reason === "live_capability_current"));
    const binding = current.edges[0].demonstrated_transition_binding;
    assert.equal(binding.session_nucleus_hash, payload.session_nucleus_hash);
    assert.equal(binding.plan_hash, payload.plan_hash);
    assert.equal(binding.execution_request_digest, payload.execution_request_digest);
    assert.equal(binding.claim_predicate_digest, payload.claim_predicate_digest);
    assert.equal(binding.verdict_ref, payload.claim_verdict_ref);
    assert.equal(binding.verdict_hash, payload.claim_verdict_hash);
    assert.equal(binding.verified_claim_projection_digest, payload.verified_claim_projection_digest);
    assert.equal(binding.verdict_signer_key_id, payload.claim_verdict_signer_key_id);
    assert.equal(binding.trust_root_epoch, payload.claim_verdict_trust_root_epoch);
    assert.equal(binding.verdict_trust_domain_ref, payload.claim_verdict_trust_domain_ref);
    assert.equal(binding.verdict_independence_domain_ref, payload.claim_verdict_independence_domain_ref);
    assert.equal(binding.transition_signer_key_id, transition.issuer_key_id);
    assert.equal(binding.transition_trust_root_epoch, transition.issuer_epoch);
    assert.deepEqual(binding.upstream_execution_identities, payload.upstream_execution_identities);
    assert.equal(binding.upstream_context_digest, payload.upstream_context_digest);
    assert.equal(binding.transition_state_epoch, payload.physical_state_epoch);
    assert.equal(binding.transition_state_digest, payload.physical_state_digest);
    assert.equal(binding.validity_kind, "live_capability");
    assert.equal(binding.valid_from, payload.valid_from);
    assert.equal(binding.expires_at, payload.expires_at);
    assert.equal(binding.capability_instance_ref, payload.capability_instance_ref);
    assert.equal(binding.custody_state_digest, payload.custody_state_digest);
    assert.ok(current.edges.every((edge) => edge.live_revalidation.receipt_ref.startsWith(
      "surface-live-state:v1:",
    )));
    assert.ok(current.edges.every((edge) => (
      edge.live_revalidation.signer_key_id === "signer-key:surface-live-state"
      && edge.live_revalidation.trust_root_epoch === 29
      && edge.live_revalidation.signer_key_id !== binding.transition_signer_key_id
    )));

    liveMode = "stale_custody";
    const staleCustody = service.queryVerifiedTransitionEdges();
    assert.ok(staleCustody.edges.every((edge) => !edge.prerequisite_eligible));
    assert.ok(staleCustody.edges.every((edge) => (
      edge.eligibility_reason === "live_revalidation_binding_drift"
    )));

    liveMode = "tampered";
    const tamperedLive = service.queryVerifiedTransitionEdges();
    assert.ok(tamperedLive.edges.every((edge) => !edge.prerequisite_eligible));
    assert.ok(tamperedLive.edges.every((edge) => edge.eligibility_reason === "live_revalidation_invalid"));

    liveMode = "replay";
    cachedLiveReceipt = null;
    const firstChallenge = service.queryVerifiedTransitionEdges();
    assert.ok(firstChallenge.edges.every((edge) => edge.prerequisite_eligible));
    const replayedChallenge = service.queryVerifiedTransitionEdges();
    assert.ok(replayedChallenge.edges.every((edge) => !edge.prerequisite_eligible));
    assert.ok(replayedChallenge.edges.every((edge) => (
      edge.eligibility_reason === "live_revalidation_binding_drift"
    )));

    const noLiveResolver = createPhysicalSurfaceGraphServerService({
      target_domain: domain,
      resolve_receipt: ({ receipt_ref: receiptRef }) => fixture.receipts.get(receiptRef) || null,
      resolve_trust_registry: ({ issuer_registry_digest: registryDigest }) => (
        registryDigest === fixture.registry.registry_digest ? fixture.registry : null
      ),
    });
    const unavailable = noLiveResolver.queryVerifiedTransitionEdges();
    assert.ok(unavailable.edges.every((edge) => !edge.prerequisite_eligible));
    assert.ok(unavailable.edges.every((edge) => edge.eligibility_reason === "live_revalidation_unavailable"));

    const graphPath = sessionPath(domain, "surface-graph.jsonl");
    const originalGraph = fs.readFileSync(graphPath, "utf8");
    const records = originalGraph.trim().split("\n").map(JSON.parse);
    const forged = { ...records[0], source: { type: "asset", id: "asset:redirected" } };
    const { record_digest: _oldDigest, ...forgedBody } = forged;
    forged.record_digest = hashCanonicalJson(forgedBody);
    fs.writeFileSync(
      graphPath,
      `${[forged, ...records.slice(1)].map((row) => JSON.stringify(row)).join("\n")}\n`,
      "utf8",
    );
    assert.throws(() => service.queryVerifiedTransitionEdges(), /arc drift/);
    fs.writeFileSync(graphPath, originalGraph, "utf8");

    const orphanName = `.surface-graph.jsonl.pending-${process.pid}-${"a".repeat(24)}`;
    fs.writeFileSync(sessionPath(domain, orphanName), "partial crash residue", "utf8");
    const recovered = service.appendVerifiedTransition({
      receipt_ref: transition.receipt_ref,
      receipt_digest: transition.receipt_digest,
    });
    assert.equal(recovered.new_count, 0);
    assert.equal(recovered.replaced_count, 4);
    assert.equal(fs.existsSync(sessionPath(domain, orphanName)), false);
    assert.deepEqual(
      fs.readdirSync(sessionPath(domain)).filter((name) => name.startsWith("surface-graph")),
      ["surface-graph.jsonl"],
      "PH-S8 must extend the canonical graph rather than create a second graph store",
    );
  } finally {
    fs.rmSync(sessionPath(domain), { recursive: true, force: true });
  }
});
