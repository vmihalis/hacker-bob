"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const childProcess = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const surfaceGraph = require("../mcp/core/frontier/surface-graph.js");
const {
  appendEdges,
  createPhysicalSurfaceGraphServerService,
  queryEdges,
  normalizeEdge,
  EDGE_TYPES,
  NODE_TYPES,
  PHYSICAL_NODE_TYPES,
} = surfaceGraph;
const {
  buildDurableReceiptTrustRegistry,
} = require("../mcp/core/executed-evidence-registry.js");
const {
  PHYSICAL_SURFACE_NODE_TYPES,
  normalizePhysicalSurfaceTransitionPayload,
  physicalSurfaceTransitionClaimPredicateDigest,
} = require("../mcp/domains/physical/physical-surface-transition.js");
const { acquireSessionLock } = require("../mcp/core/io/storage.js");
const { hashCanonicalJson } = require("../mcp/core/verification/verification-contracts.js");
const {
  buildSessionNucleus,
  normalizePhysicalScopeNucleusAxis,
} = require("../mcp/core/governance/index.js");

const SIGNED_AT = new Date(Date.now() - 5_000).toISOString();
const DECIDED_AT = new Date(Date.parse(SIGNED_AT) - 1_000).toISOString();
const SESSION_NUCLEUS_HASHES = new Map();

function digest(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function uniqueDomain() {
  return `bob-physical-surface-graph-${crypto.randomBytes(4).toString("hex")}.local`;
}

function sessionPath(domain, basename = "") {
  return path.join(os.homedir(), "hacker-bob-sessions", domain, basename);
}

function cleanupDomain(domain) {
  fs.rmSync(sessionPath(domain), { recursive: true, force: true });
  SESSION_NUCLEUS_HASHES.delete(domain);
}

function installPhysicalSession(domain, transitionRegistryDigest) {
  const physicalScope = normalizePhysicalScopeNucleusAxis({
    version: 1,
    physical_enabled: true,
    policy_version: 1,
    policy_id: "surface_transition_fixture",
    policy_digest: digest("physical-policy"),
    projection_version: 1,
    projection_digest: digest("physical-projection"),
    provenance_digest: digest("physical-provenance"),
    compatibility_digest: digest("physical-compatibility"),
    transition_receipt_registry_digest: transitionRegistryDigest,
    authority_epoch: 4,
    revocation_generation: 2,
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
    egress_identity: {
      egress_profile: "default",
      proxy_configured: false,
    },
    auth_context: { auth_status: "pending" },
    operator_constraint: { handoff_provenance_required: true },
    lifecycle_state: "SETUP",
    physical_scope: physicalScope,
  });
  fs.mkdirSync(sessionPath(domain), { recursive: true, mode: 0o700 });
  fs.writeFileSync(
    sessionPath(domain, "session-nucleus.json"),
    `${JSON.stringify(nucleus, null, 2)}\n`,
    { encoding: "utf8", mode: 0o600 },
  );
  SESSION_NUCLEUS_HASHES.set(domain, nucleus.nucleus_hash);
  return nucleus;
}

function ordinaryEdge(suffix = "one") {
  return {
    source: { type: "surface", id: `surface:${suffix}` },
    target: { type: "endpoint", id: `/endpoint/${suffix}` },
    edge_type: "contains",
    source_artifact: "attack_surface.json",
  };
}

function transitionPayload(domain, overrides = {}) {
  const base = {
    version: 1,
    surface_graph_schema_version: 2,
    target_domain: domain,
    session_nucleus_hash: SESSION_NUCLEUS_HASHES.get(domain) || digest("session-nucleus"),
    experiment_id: "experiment-one",
    task_id: "task-one",
    attempt_id: "attempt-one",
    plan_hash: digest("plan"),
    execution_request_digest: digest("execution-request"),
    claim_predicate_digest: digest("placeholder-claim-predicate"),
    claim_verdict_ref: "physical-claim-verdict:one",
    claim_verdict_hash: digest("claim-verdict"),
    claim_verdict_signer_key_id: "signer-key:verifier",
    claim_verdict_signer_principal_ref: "principal:verifier",
    claim_verdict_trust_root_epoch: 9,
    claim_verdict_trust_domain_ref: "trust-domain:verifier",
    claim_verdict_independence_domain_ref: "independence-domain:verifier",
    claim_verdict_trust_registry_digest: digest("verdict-trust-registry"),
    claim_verdict_signer_enrollment_digest: digest("verdict-signer-enrollment"),
    claim_verdict_authorization_context_digest: digest("verdict-authorization-context"),
    verified_claim_projection_digest: digest("verified-claim-projection"),
    verifier_execution_receipt_ref: `verifier-execution:v1:${digest("verifier-receipt")}`,
    verifier_execution_receipt_digest: digest("verifier-receipt"),
    executed_evidence_registry_digest: digest("evidence-registry"),
    verifier_template_id: "physical.transition-positive-control",
    verifier_template_version: 3,
    verifier_template_digest: digest("verifier-template"),
    decision_rule_digest: digest("decision-rule"),
    outcome: "verified",
    reason_code: "differential_verified",
    decided_at: DECIDED_AT,
    upstream_execution_identities: ["execution:control", "execution:positive"],
    upstream_context_digest: digest("upstream-context"),
    physical_state_epoch: 7,
    physical_state_digest: digest("physical-state"),
    validity_kind: "historical_event",
    valid_from: DECIDED_AT,
    participants: [{
      participant_id: "subject",
      role: "subject",
      node: { type: "asset", id: "asset:opaque-subject" },
    }, {
      participant_id: "stimulus",
      role: "instrument",
      node: { type: "instrument", id: "instrument:opaque-source" },
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
      arc_id: "stimulus-to-outcome",
      source_participant_id: "stimulus",
      target_participant_id: "outcome",
      edge_type: "demonstrated_transition",
    }],
  };
  const merged = { ...base, ...overrides };
  if (!Object.prototype.hasOwnProperty.call(overrides, "claim_predicate_digest")) {
    merged.claim_predicate_digest = physicalSurfaceTransitionClaimPredicateDigest({
      target_domain: merged.target_domain,
      participants: merged.participants,
      arcs: merged.arcs,
    });
  }
  return merged;
}

function receiptFixture(domain, {
  signedAt = SIGNED_AT,
  signedAtSequence = null,
  ambiguousCommitOnce = false,
  registryOverrides = {},
  installSession = true,
} = {}) {
  const pair = crypto.generateKeyPairSync("ed25519");
  const publicKeyPem = pair.publicKey.export({ type: "spki", format: "pem" });
  const receipts = new Map();
  const receiptsBySemantic = new Map();
  let resolveCount = 0;
  let commitCount = 0;
  let timeIndex = 0;
  const registry = buildDurableReceiptTrustRegistry({
    version: 1,
    registry_id: "surface-transition-fixture",
    issuers: [{
      issuer_key_id: "signer-key:surface-transition",
      issuer_epoch: 5,
      signature_scheme: "ed25519",
      public_key_pem: publicKeyPem,
      receipt_kinds: ["physical_surface_transition"],
      valid_from: "2020-01-01T00:00:00.000Z",
      expires_at: "2100-01-01T00:00:00.000Z",
      trusted: true,
      revoked: false,
      ...registryOverrides,
    }],
  });
  if (installSession) installPhysicalSession(domain, registry.registry_digest);
  async function issuePhysicalSurfaceTransition(payloadInput) {
    const payload = normalizePhysicalSurfaceTransitionPayload(payloadInput);
    const semanticBody = {
      domain: "hacker-bob/durable-evidence-receipt-semantic/v1",
      version: 1,
      receipt_kind: "physical_surface_transition",
      payload,
      issuer_registry_digest: registry.registry_digest,
      issuer_key_id: "signer-key:surface-transition",
      issuer_epoch: 5,
    };
    const semanticDigest = hashCanonicalJson(semanticBody);
    const prior = receiptsBySemantic.get(semanticDigest);
    if (prior) return prior;
    const currentSignedAt = (() => {
      if (!Array.isArray(signedAtSequence)) return signedAt;
      const value = signedAtSequence[Math.min(timeIndex, signedAtSequence.length - 1)];
      timeIndex += 1;
      return value;
    })();
    const envelope = {
      issuer_registry_digest: registry.registry_digest,
      issuer_key_id: "signer-key:surface-transition",
      issuer_epoch: 5,
      semantic_digest: semanticDigest,
      signature_scheme: "ed25519",
      signed_at: currentSignedAt,
    };
    const signatureInput = hashCanonicalJson({
      domain: "hacker-bob/durable-evidence-receipt/v1",
      version: 1,
      receipt_kind: "physical_surface_transition",
      payload,
      ...envelope,
    });
    const signedBody = {
      version: 1,
      receipt_kind: "physical_surface_transition",
      payload,
      ...envelope,
      signature: crypto.sign(null, Buffer.from(signatureInput, "hex"), pair.privateKey).toString("base64url"),
    };
    const receiptDigest = hashCanonicalJson(signedBody);
    const receipt = Object.freeze({
      ...signedBody,
      receipt_digest: receiptDigest,
      receipt_ref: `surface-transition:v1:${receiptDigest}`,
    });
    commitCount += 1;
    receipts.set(receipt.receipt_ref, receipt);
    receiptsBySemantic.set(semanticDigest, receipt);
    if (ambiguousCommitOnce && commitCount === 1) {
      // Simulate recovery of the canonical durable row after a lost acknowledgement.
      return receiptsBySemantic.get(semanticDigest);
    }
    return receipt;
  }
  const issuer = Object.freeze({ issuePhysicalSurfaceTransition });
  return {
    issuer,
    registry,
    receipts,
    receiptsBySemantic,
    resolveReceipt({ receipt_ref }) {
      resolveCount += 1;
      return receipts.get(receipt_ref) || null;
    },
    resolveRegistry({ issuer_registry_digest }) {
      return issuer_registry_digest === registry.registry_digest ? registry : null;
    },
    get resolveCount() { return resolveCount; },
    get commitCount() { return commitCount; },
  };
}

function serverService(domain, fixture, overrides = {}) {
  return createPhysicalSurfaceGraphServerService({
    target_domain: domain,
    resolve_receipt: overrides.resolve_receipt || fixture.resolveReceipt,
    resolve_trust_registry: overrides.resolve_trust_registry || fixture.resolveRegistry,
  });
}

function appendArgs(domain, fixture, receipt, overrides = {}) {
  return {
    service: overrides.service || serverService(domain, fixture, overrides),
    receipt_ref: receipt.receipt_ref,
    receipt_digest: receipt.receipt_digest,
  };
}

function queryArgs(domain, fixture, overrides = {}) {
  return {
    service: overrides.service || serverService(domain, fixture, overrides),
    ...(overrides.query || {}),
  };
}

function appendVerifiedTransition({ service, ...request }) {
  return service.appendVerifiedTransition(request);
}

function queryVerifiedTransitionEdges({ service, ...request }) {
  return service.queryVerifiedTransitionEdges(request);
}

test("surface graph exposes the closed provider-neutral physical vocabulary", () => {
  assert.deepEqual(PHYSICAL_NODE_TYPES, PHYSICAL_SURFACE_NODE_TYPES);
  for (const nodeType of [
    "instrument", "interface", "medium", "signal_source", "actuator", "control_point",
    "asset", "representation", "verifier", "physical_barrier", "physical_zone",
    "enclosure", "network_attachment", "sensor", "alarm", "workspace",
  ]) assert.ok(NODE_TYPES.includes(nodeType), `missing ${nodeType}`);
  assert.ok(EDGE_TYPES.includes("demonstrated_transition"));
  assert.throws(
    () => normalizeEdge({ ...ordinaryEdge(), source: { type: "unregistered_surface_kind", id: "one" } }),
    /node vocabulary/,
  );
});

test("raw callers cannot mint demonstrated transitions or launder unknown fields", () => {
  const raw = {
    source: { type: "asset", id: "asset:source" },
    target: { type: "control_point", id: "control-point:target" },
    edge_type: "demonstrated_transition",
  };
  assert.throws(() => normalizeEdge(raw), /signed verified N-ary transition receipt/);
  assert.throws(
    () => appendEdges({ target_domain: uniqueDomain(), edges: [raw] }),
    /signed verified N-ary transition receipt/,
  );
  assert.throws(() => normalizeEdge({ ...ordinaryEdge(), submitted_by: "agent" }), /unknown fields/);
  assert.throws(
    () => normalizeEdge({ ...ordinaryEdge(), source: { ...ordinaryEdge().source, secret: "raw" } }),
    /unknown fields/,
  );
});

test("verified graph service is target-bound and exposes no caller-mintable authority surface", async () => {
  const domain = uniqueDomain();
  try {
    const trusted = receiptFixture(domain);
    const attacker = receiptFixture(domain, { installSession: false });
    const attackerReceipt = await attacker.issuer.issuePhysicalSurfaceTransition(transitionPayload(domain));
    assert.equal(surfaceGraph.appendVerifiedTransition, undefined);
    assert.equal(surfaceGraph.queryVerifiedTransitionEdges, undefined);
    assert.equal(surfaceGraph.createPhysicalSurfaceGraphServerAuthority, undefined);

    const attackerService = serverService(domain, attacker);
    assert.throws(
      () => appendVerifiedTransition({
        service: attackerService,
        receipt_ref: attackerReceipt.receipt_ref,
        receipt_digest: attackerReceipt.receipt_digest,
      }),
      /registry is not authorized by the current session/,
    );

    const trustedReceipt = await trusted.issuer.issuePhysicalSurfaceTransition(transitionPayload(domain));
    const trustedService = serverService(domain, trusted);
    assert.throws(
      () => appendVerifiedTransition({
        service: trustedService,
        receipt_ref: trustedReceipt.receipt_ref,
        receipt_digest: trustedReceipt.receipt_digest,
        trusted_now: "2026-07-17T00:00:00.000Z",
        is_issuer_current: () => true,
      }),
      /unknown fields/,
    );
    assert.throws(
      () => createPhysicalSurfaceGraphServerService({
        target_domain: domain,
        resolve_receipt: trusted.resolveReceipt,
        resolve_trust_registry: trusted.resolveRegistry,
        trusted_now: () => new Date().toISOString(),
      }),
      /unknown fields/,
    );
    assert.equal(fs.existsSync(sessionPath(domain, "surface-graph.jsonl")), false);
  } finally {
    cleanupDomain(domain);
  }
});

test("verified graph service rejects symlinked and hardlinked session authority files", () => {
  const domain = uniqueDomain();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "bob-surface-nucleus-"));
  const nucleusPath = sessionPath(domain, "session-nucleus.json");
  const externalPath = path.join(outside, "session-nucleus.json");
  try {
    const fixture = receiptFixture(domain);
    fs.writeFileSync(externalPath, fs.readFileSync(nucleusPath));
    fs.unlinkSync(nucleusPath);
    fs.symlinkSync(externalPath, nucleusPath);
    assert.throws(
      () => serverService(domain, fixture),
      /session-nucleus\.json must not be a symbolic link/,
    );

    fs.unlinkSync(nucleusPath);
    fs.linkSync(externalPath, nucleusPath);
    assert.throws(
      () => serverService(domain, fixture),
      /session-nucleus\.json must be a single-link regular file/,
    );
    assert.equal(fs.existsSync(sessionPath(domain, "surface-graph.jsonl")), false);
  } finally {
    cleanupDomain(domain);
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

test("typed transition payload is closed, N-ary, and exact", () => {
  const domain = uniqueDomain();
  const normalized = normalizePhysicalSurfaceTransitionPayload(transitionPayload(domain));
  assert.deepEqual(normalized.upstream_execution_identities, ["execution:control", "execution:positive"]);
  assert.equal(normalized.arcs.length, 2);
  assert.throws(
    () => normalizePhysicalSurfaceTransitionPayload(transitionPayload(domain, { submitted_by: "agent" })),
    /unknown fields/,
  );
  assert.throws(
    () => normalizePhysicalSurfaceTransitionPayload(transitionPayload(domain, {
      reason_code: "unknown_provenance_value",
    })),
    /reason_code must be differential_verified/,
  );
  assert.throws(
    () => normalizePhysicalSurfaceTransitionPayload(transitionPayload(domain, {
      claim_verdict_ref: "attacker-chosen:opaque",
    })),
    /physical-claim-verdict: namespace/,
  );
  assert.throws(
    () => normalizePhysicalSurfaceTransitionPayload(transitionPayload(domain, {
      arcs: [transitionPayload(domain).arcs[0]],
    })),
    /use every declared participant/,
  );
  assert.throws(
    () => normalizePhysicalSurfaceTransitionPayload(transitionPayload(domain, {
      arcs: [{ ...transitionPayload(domain).arcs[0], target_participant_id: "missing" }],
    })),
    /resolve to declared participants/,
  );
  assert.throws(
    () => normalizePhysicalSurfaceTransitionPayload(transitionPayload(domain, {
      participants: transitionPayload(domain).participants.map((entry, index) => (
        index === 0 ? { ...entry, role: "credential_card" } : entry
      )),
    })),
    /role must be one of/,
  );
  assert.throws(
    () => normalizePhysicalSurfaceTransitionPayload(transitionPayload(domain, {
      arcs: [
        ...transitionPayload(domain).arcs,
        { ...transitionPayload(domain).arcs[0], arc_id: "same-arc-new-id" },
      ],
    })),
    /duplicate semantic arcs/,
  );
  assert.throws(
    () => normalizePhysicalSurfaceTransitionPayload(transitionPayload(domain, {
      participants: [
        ...transitionPayload(domain).participants,
        { ...transitionPayload(domain).participants[0], participant_id: "subject-alias" },
      ],
    })),
    /duplicate role\/node projections/,
  );
});

test("one committed signed receipt atomically derives every arc and is reverified on each trusted read", async () => {
  const domain = uniqueDomain();
  try {
    const fixture = receiptFixture(domain);
    const receipt = await fixture.issuer.issuePhysicalSurfaceTransition(transitionPayload(domain));
    const appended = appendVerifiedTransition(appendArgs(domain, fixture, receipt));
    assert.equal(appended.derived_arc_count, 2);
    assert.equal(appended.new_count, 2);

    const ordinary = queryEdges({ target_domain: domain });
    assert.equal(ordinary.edges.length, 0);
    assert.equal(ordinary.verified_transition_records_withheld, 2);
    assert.throws(
      () => queryEdges({ target_domain: domain, edge_type: "demonstrated_transition" }),
      /queryVerifiedTransitionEdges/,
    );

    const first = queryVerifiedTransitionEdges(queryArgs(domain, fixture));
    assert.equal(first.edges.length, 2);
    assert.equal(first.historical_only_count, 2);
    assert.ok(first.edges.every((edge) => edge.prerequisite_eligible === false));
    assert.ok(first.edges.every((edge) => (
      edge.demonstrated_transition_binding.transition_receipt_digest === receipt.receipt_digest
    )));
    const afterFirst = fixture.resolveCount;
    queryVerifiedTransitionEdges(queryArgs(domain, fixture));
    assert.equal(fixture.resolveCount, afterFirst + 1);

    const repeated = appendVerifiedTransition(appendArgs(domain, fixture, receipt));
    assert.equal(repeated.new_count, 0);
    assert.equal(repeated.replaced_count, 2);
  } finally {
    cleanupDomain(domain);
  }
});

test("verified transition admission resolves mutable authority only after acquiring the persistence lock", async () => {
  const domain = uniqueDomain();
  let release = null;
  try {
    const fixture = receiptFixture(domain);
    const receipt = await fixture.issuer.issuePhysicalSurfaceTransition(transitionPayload(domain));
    const service = serverService(domain, fixture);
    const resolvesBeforeContention = fixture.resolveCount;
    release = acquireSessionLock(domain);
    assert.throws(
      () => service.appendVerifiedTransition({
        receipt_ref: receipt.receipt_ref,
        receipt_digest: receipt.receipt_digest,
      }),
      /Session lock busy/,
    );
    assert.equal(
      fixture.resolveCount,
      resolvesBeforeContention,
      "receipt/trust admission must not run before the persistence lock is acquired",
    );
    release();
    release = null;
    assert.equal(
      service.appendVerifiedTransition({
        receipt_ref: receipt.receipt_ref,
        receipt_digest: receipt.receipt_digest,
      }).new_count,
      2,
    );
  } finally {
    if (release) release();
    cleanupDomain(domain);
  }
});

test("a lost commit acknowledgement recovers one canonical semantic receipt and one arc set", async () => {
  const domain = uniqueDomain();
  try {
    const fixture = receiptFixture(domain, {
      signedAtSequence: [SIGNED_AT, "2026-07-18T00:00:11.000Z"],
      ambiguousCommitOnce: true,
    });
    const payload = transitionPayload(domain);
    const first = await fixture.issuer.issuePhysicalSurfaceTransition(payload);
    const retry = await fixture.issuer.issuePhysicalSurfaceTransition(payload);
    assert.equal(first.receipt_ref, retry.receipt_ref);
    assert.equal(first.semantic_digest, retry.semantic_digest);
    assert.equal(fixture.commitCount, 1);
    assert.equal(fixture.receiptsBySemantic.size, 1);

    appendVerifiedTransition(appendArgs(domain, fixture, first));
    appendVerifiedTransition(appendArgs(domain, fixture, retry));
    const queried = queryVerifiedTransitionEdges(queryArgs(domain, fixture));
    assert.equal(queried.edges.length, 2);
    assert.equal(queried.verified_transition_record_count, 2);
  } finally {
    cleanupDomain(domain);
  }
});

test("uncommitted, future-signed, domain-drifted, nucleus-drifted, and signature-drifted receipts fail closed", async () => {
  const domain = uniqueDomain();
  try {
    const fixture = receiptFixture(domain);
    const receipt = await fixture.issuer.issuePhysicalSurfaceTransition(transitionPayload(domain));
    fixture.receipts.delete(receipt.receipt_ref);
    assert.throws(() => appendVerifiedTransition(appendArgs(domain, fixture, receipt)), /unavailable/);
    fixture.receipts.set(receipt.receipt_ref, receipt);

    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const finalIndex = alphabet.indexOf(receipt.signature.at(-1));
    const alternateFinal = alphabet[(finalIndex & ~3) | ((finalIndex + 1) & 3)];
    const alternateSignature = `${receipt.signature.slice(0, -1)}${alternateFinal}`;
    assert.deepEqual(
      Buffer.from(alternateSignature, "base64url"),
      Buffer.from(receipt.signature, "base64url"),
    );
    const { receipt_digest: _oldReceiptDigest, receipt_ref: _oldReceiptRef, ...alternateBody } = {
      ...receipt,
      signature: alternateSignature,
    };
    const alternateDigest = hashCanonicalJson(alternateBody);
    const alternateReceipt = {
      ...alternateBody,
      receipt_digest: alternateDigest,
      receipt_ref: `surface-transition:v1:${alternateDigest}`,
    };
    fixture.receipts.set(alternateReceipt.receipt_ref, alternateReceipt);
    assert.throws(
      () => appendVerifiedTransition(appendArgs(domain, fixture, alternateReceipt)),
      /canonical Ed25519 base64url/,
    );

    const domainDrift = await fixture.issuer.issuePhysicalSurfaceTransition(transitionPayload(
      "other.example",
      { session_nucleus_hash: SESSION_NUCLEUS_HASHES.get(domain) },
    ));
    assert.throws(
      () => appendVerifiedTransition(appendArgs(domain, fixture, domainDrift)),
      /target_domain drift/,
    );
    const nucleusDrift = await fixture.issuer.issuePhysicalSurfaceTransition(transitionPayload(
      domain,
      { session_nucleus_hash: digest("alien") },
    ));
    assert.throws(
      () => appendVerifiedTransition(appendArgs(domain, fixture, nucleusDrift)),
      /session nucleus drift/,
    );

    fixture.receipts.set(receipt.receipt_ref, {
      ...receipt,
      payload: { ...receipt.payload, task_id: "task-tampered" },
    });
    assert.throws(
      () => appendVerifiedTransition(appendArgs(domain, fixture, receipt)),
      /signature verification failed|semantic_digest/,
    );

    const futureFixture = receiptFixture(domain, {
      signedAt: new Date(Date.now() + 60_000).toISOString(),
    });
    const future = await futureFixture.issuer.issuePhysicalSurfaceTransition(transitionPayload(domain));
    assert.throws(
      () => appendVerifiedTransition(appendArgs(domain, futureFixture, future)),
      /signed_at is in the future/,
    );
  } finally {
    cleanupDomain(domain);
  }
});

test("live capability arcs remain historical until signed current-state projection exists and expire by server time", async () => {
  const domain = uniqueDomain();
  try {
    const now = Date.now();
    const fixture = receiptFixture(domain, { signedAt: new Date(now - 1_000).toISOString() });
    const payload = transitionPayload(domain, {
      decided_at: new Date(now - 2_000).toISOString(),
      validity_kind: "live_capability",
      valid_from: new Date(now - 2_000).toISOString(),
      expires_at: new Date(now + 1_000).toISOString(),
      capability_instance_ref: "capability-instance:one",
      custody_state_digest: digest("custody"),
    });
    const receipt = await fixture.issuer.issuePhysicalSurfaceTransition(payload);
    appendVerifiedTransition(appendArgs(domain, fixture, receipt));

    const current = queryVerifiedTransitionEdges(queryArgs(domain, fixture));
    assert.ok(current.edges.every((edge) => !edge.prerequisite_eligible));
    assert.ok(current.edges.every((edge) => edge.eligibility_reason === "live_revalidation_unavailable"));

    await new Promise((resolve) => setTimeout(resolve, 1_100));
    const expired = queryVerifiedTransitionEdges(queryArgs(domain, fixture));
    assert.ok(expired.edges.every((edge) => !edge.prerequisite_eligible));
    assert.ok(expired.edges.every((edge) => edge.eligibility_reason === "live_capability_expired_or_not_yet_valid"));
  } finally {
    cleanupDomain(domain);
  }
});

test("trusted reads detect missing or attacker-rewritten arcs even when an attacker recomputes the local record digest", async () => {
  const domain = uniqueDomain();
  const graphPath = sessionPath(domain, "surface-graph.jsonl");
  try {
    const fixture = receiptFixture(domain);
    const receipt = await fixture.issuer.issuePhysicalSurfaceTransition(transitionPayload(domain));
    appendVerifiedTransition(appendArgs(domain, fixture, receipt));
    const records = fs.readFileSync(graphPath, "utf8").trim().split("\n").map(JSON.parse);

    fs.writeFileSync(graphPath, `${JSON.stringify(records[0])}\n`, "utf8");
    assert.throws(
      () => queryVerifiedTransitionEdges(queryArgs(domain, fixture)),
      /arc set is incomplete/,
    );

    appendVerifiedTransition(appendArgs(domain, fixture, receipt));
    const restored = fs.readFileSync(graphPath, "utf8").trim().split("\n").map(JSON.parse);
    const forged = { ...restored[0], source: { type: "asset", id: "asset:redirected" } };
    const { record_digest: _oldDigest, ...forgedBody } = forged;
    forged.record_digest = hashCanonicalJson(forgedBody);
    fs.writeFileSync(graphPath, `${JSON.stringify(forged)}\n${JSON.stringify(restored[1])}\n`, "utf8");
    assert.throws(
      () => queryVerifiedTransitionEdges(queryArgs(domain, fixture)),
      /arc drift/,
    );
  } finally {
    cleanupDomain(domain);
  }
});

test("legacy ordinary rows migrate, while unsigned demonstrated and unknown-vocabulary rows are quarantined", () => {
  const ordinaryDomain = uniqueDomain();
  const quarantineDomain = uniqueDomain();
  try {
    fs.mkdirSync(sessionPath(ordinaryDomain), { recursive: true });
    const legacyOrdinary = normalizeEdge({
      ...ordinaryEdge("legacy"),
      observed_at: "2026-01-01T00:00:00.000Z",
    });
    fs.writeFileSync(
      sessionPath(ordinaryDomain, "surface-graph.jsonl"),
      `${JSON.stringify(legacyOrdinary)}\n`,
      "utf8",
    );
    const migratedRead = queryEdges({ target_domain: ordinaryDomain });
    assert.equal(migratedRead.total_matched, 1);
    assert.equal(migratedRead.quarantined_count, 0);
    appendEdges({ target_domain: ordinaryDomain, edges: [ordinaryEdge("current")] });
    const disk = fs.readFileSync(sessionPath(ordinaryDomain, "surface-graph.jsonl"), "utf8");
    assert.match(disk, /"schema_version":2/);

    fs.mkdirSync(sessionPath(quarantineDomain), { recursive: true });
    const unsigned = {
      edge_hash: digest("unsigned"),
      source: { type: "asset", id: "asset:source" },
      target: { type: "control_point", id: "control-point:target" },
      edge_type: "demonstrated_transition",
      confidence: 1,
      source_artifact: "agent.json",
      observed_at: "2026-01-01T00:00:00.000Z",
    };
    const unknown = {
      ...legacyOrdinary,
      edge_hash: digest("unknown"),
      source: { type: "legacy_physical_subject", id: "legacy:source" },
    };
    fs.writeFileSync(
      sessionPath(quarantineDomain, "surface-graph.jsonl"),
      `${JSON.stringify(unsigned)}\n${JSON.stringify(unknown)}\n`,
      "utf8",
    );
    const quarantined = queryEdges({ target_domain: quarantineDomain });
    assert.equal(quarantined.edges.length, 0);
    assert.equal(quarantined.quarantined_count, 2);
    assert.throws(
      () => appendEdges({ target_domain: quarantineDomain, edges: [ordinaryEdge("blocked")] }),
      /explicit migration is required/,
    );

    const fixture = receiptFixture(quarantineDomain);
    const service = serverService(quarantineDomain, fixture);
    const graphPath = sessionPath(quarantineDomain, "surface-graph.jsonl");
    const quarantinePath = sessionPath(quarantineDomain, "surface-graph-quarantine.jsonl");
    const originalGraph = fs.readFileSync(graphPath, "utf8");
    const renameSync = fs.renameSync;
    let renameCount = 0;
    try {
      fs.renameSync = (...args) => {
        renameCount += 1;
        if (renameCount === 2) throw new Error("simulated graph replacement failure");
        return renameSync(...args);
      };
      assert.throws(
        () => service.migrateSurfaceGraph(),
        /simulated graph replacement failure/,
      );
    } finally {
      fs.renameSync = renameSync;
    }
    assert.equal(fs.readFileSync(graphPath, "utf8"), originalGraph);
    const durableBeforeRetry = fs.readFileSync(quarantinePath, "utf8");
    assert.equal(durableBeforeRetry.trim().split("\n").length, 2);
    assert.doesNotMatch(durableBeforeRetry, /asset:source|legacy_physical_subject/);

    const migrated = service.migrateSurfaceGraph();
    assert.equal(migrated.migration_complete, true);
    assert.equal(migrated.canonical_record_count, 0);
    assert.equal(migrated.rejected_source_record_count, 2);
    assert.equal(migrated.new_quarantine_record_count, 0);
    assert.equal(migrated.total_quarantine_record_count, 2);
    assert.equal(fs.readFileSync(graphPath, "utf8"), "");
    const durableAfterRetry = fs.readFileSync(quarantinePath, "utf8");
    assert.equal(durableAfterRetry, durableBeforeRetry);

    const repeated = service.migrateSurfaceGraph();
    assert.equal(repeated.rejected_source_record_count, 0);
    assert.equal(repeated.new_quarantine_record_count, 0);
    assert.equal(repeated.total_quarantine_record_count, 2);
    assert.equal(fs.readFileSync(quarantinePath, "utf8"), durableBeforeRetry);
    assert.equal(
      appendEdges({ target_domain: quarantineDomain, edges: [ordinaryEdge("after-migration")] })
        .new_count,
      1,
    );
  } finally {
    cleanupDomain(ordinaryDomain);
    cleanupDomain(quarantineDomain);
  }
});

test("ordinary and verified appends reject a symlinked sessions root before writing outside Bob storage", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-surface-home-"));
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "bob-surface-outside-"));
  try {
    fs.symlinkSync(outside, path.join(home, "hacker-bob-sessions"), "dir");
    const modulePath = path.resolve(__dirname, "../mcp/core/frontier/surface-graph.js");
    const script = `
      const graph = require(${JSON.stringify(modulePath)});
      const results = [];
      for (const call of [
        () => graph.appendEdges({target_domain:"symlink-test.local",edges:[]}),
        () => graph.createPhysicalSurfaceGraphServerService({
          target_domain:"symlink-test.local",
          resolve_receipt() { return null; },
          resolve_trust_registry() { return null; },
        }),
      ]) {
        try { call(); results.push("accepted"); }
        catch (error) { results.push(String(error.message || error)); }
      }
      process.stdout.write(JSON.stringify(results));
    `;
    const output = childProcess.execFileSync(process.execPath, ["-e", script], {
      encoding: "utf8",
      env: { ...process.env, HOME: home },
    });
    const results = JSON.parse(output);
    assert.equal(results.length, 2);
    assert.ok(results.every((message) => /sessions root.*symlink/.test(message)));
    assert.deepEqual(fs.readdirSync(outside), []);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

test("session-directory and final lock symlinks or hardlinks are rejected before any outside lock write", () => {
  const modulePath = path.resolve(__dirname, "../mcp/core/frontier/surface-graph.js");
  const run = (home) => childProcess.execFileSync(process.execPath, ["-e", `
    const graph = require(${JSON.stringify(modulePath)});
    try {
      graph.appendEdges({target_domain:"session-symlink-test.local",edges:[]});
      process.stdout.write("accepted");
    } catch (error) {
      process.stdout.write(String(error.message || error));
    }
  `], {
    encoding: "utf8",
    env: { ...process.env, HOME: home },
  });

  const directoryHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-surface-session-link-home-"));
  const directoryOutside = fs.mkdtempSync(path.join(os.tmpdir(), "bob-surface-session-link-outside-"));
  try {
    const root = path.join(directoryHome, "hacker-bob-sessions");
    fs.mkdirSync(root, { recursive: true });
    fs.symlinkSync(directoryOutside, path.join(root, "session-symlink-test.local"), "dir");
    assert.match(run(directoryHome), /session directory.*symbolic link/i);
    assert.deepEqual(fs.readdirSync(directoryOutside), []);
  } finally {
    fs.rmSync(directoryHome, { recursive: true, force: true });
    fs.rmSync(directoryOutside, { recursive: true, force: true });
  }

  const lockHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-surface-lock-link-home-"));
  const lockOutside = fs.mkdtempSync(path.join(os.tmpdir(), "bob-surface-lock-link-outside-"));
  try {
    const sessionPathValue = path.join(
      lockHome,
      "hacker-bob-sessions",
      "session-symlink-test.local",
    );
    fs.mkdirSync(sessionPathValue, { recursive: true });
    const outsideTarget = path.join(lockOutside, "outside-lock-target");
    const original = "outside lock target must remain unchanged\n";
    fs.writeFileSync(outsideTarget, original, "utf8");
    fs.symlinkSync(outsideTarget, path.join(sessionPathValue, ".session.lock"));
    assert.match(run(lockHome), /Session lock path must not be a symbolic link/);
    assert.equal(fs.readFileSync(outsideTarget, "utf8"), original);
    assert.deepEqual(fs.readdirSync(lockOutside), ["outside-lock-target"]);
  } finally {
    fs.rmSync(lockHome, { recursive: true, force: true });
    fs.rmSync(lockOutside, { recursive: true, force: true });
  }

  const hardlinkHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-surface-lock-hardlink-home-"));
  const hardlinkOutside = fs.mkdtempSync(path.join(os.tmpdir(), "bob-surface-lock-hardlink-outside-"));
  try {
    const sessionPathValue = path.join(
      hardlinkHome,
      "hacker-bob-sessions",
      "session-symlink-test.local",
    );
    fs.mkdirSync(sessionPathValue, { recursive: true });
    const outsideTarget = path.join(hardlinkOutside, "outside-lock-target");
    const original = "outside hardlink target must remain unchanged\n";
    fs.writeFileSync(outsideTarget, original, "utf8");
    fs.linkSync(outsideTarget, path.join(sessionPathValue, ".session.lock"));
    assert.match(run(hardlinkHome), /Session lock path must be a single-link regular file/);
    assert.equal(fs.readFileSync(outsideTarget, "utf8"), original);
    assert.equal(fs.statSync(outsideTarget).nlink, 2);
  } finally {
    fs.rmSync(hardlinkHome, { recursive: true, force: true });
    fs.rmSync(hardlinkOutside, { recursive: true, force: true });
  }
});

test("session-directory replacement during lock acquisition is detected before graph persistence", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-surface-lock-race-home-"));
  const modulePath = path.resolve(__dirname, "../mcp/core/frontier/surface-graph.js");
  try {
    const output = childProcess.execFileSync(process.execPath, ["-e", `
      const fs = require("node:fs");
      const path = require("node:path");
      const graph = require(${JSON.stringify(modulePath)});
      const domain = "session-race-test.local";
      let movedDirectory = null;
      const originalOpenSync = fs.openSync;
      fs.openSync = (target, flags, ...rest) => {
        const result = originalOpenSync(target, flags, ...rest);
        if (typeof target === "string"
            && path.basename(target) === ".session.lock"
            && (flags & fs.constants.O_EXCL) !== 0
            && movedDirectory == null) {
          const directory = path.dirname(target);
          movedDirectory = directory + ".replaced";
          fs.renameSync(directory, movedDirectory);
          fs.mkdirSync(directory, {mode: 0o700});
        }
        return result;
      };
      let error = null;
      try {
        graph.appendEdges({target_domain:domain,edges:[]});
      } catch (caught) {
        error = String(caught.message || caught);
      } finally {
        fs.openSync = originalOpenSync;
      }
      const directory = path.join(process.env.HOME, "hacker-bob-sessions", domain);
      process.stdout.write(JSON.stringify({
        error,
        graph_in_replacement: fs.existsSync(path.join(directory, "surface-graph.jsonl")),
        graph_in_original: movedDirectory == null
          ? null
          : fs.existsSync(path.join(movedDirectory, "surface-graph.jsonl")),
      }));
    `], {
      encoding: "utf8",
      env: { ...process.env, HOME: home },
    });
    const result = JSON.parse(output);
    assert.match(result.error, /session directory changed during session lock operation/i);
    assert.equal(result.graph_in_replacement, false);
    assert.equal(result.graph_in_original, false);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("surface graph replacement is locked, fsync-backed, atomic, and mode-preserving", () => {
  const domain = uniqueDomain();
  const filePath = sessionPath(domain, "surface-graph.jsonl");
  try {
    appendEdges({ target_domain: domain, edges: [ordinaryEdge("one")] });
    fs.chmodSync(filePath, 0o640);
    const original = fs.readFileSync(filePath, "utf8");

    const release = acquireSessionLock(domain);
    try {
      assert.throws(
        () => appendEdges({ target_domain: domain, edges: [ordinaryEdge("two")] }),
        /Session lock busy/,
      );
      assert.equal(fs.readFileSync(filePath, "utf8"), original);
    } finally {
      release();
    }

    const renameSync = fs.renameSync;
    try {
      fs.renameSync = () => { throw new Error("simulated atomic replace failure"); };
      assert.throws(
        () => appendEdges({ target_domain: domain, edges: [ordinaryEdge("two")] }),
        /simulated atomic replace failure/,
      );
    } finally {
      fs.renameSync = renameSync;
    }
    assert.equal(fs.readFileSync(filePath, "utf8"), original);
    assert.equal(fs.readdirSync(sessionPath(domain)).some((name) => name.includes(".pending-")), false);

    appendEdges({ target_domain: domain, edges: [ordinaryEdge("two")] });
    assert.equal(queryEdges({ target_domain: domain }).total_in_graph, 2);
    assert.equal(fs.statSync(filePath).mode & 0o777, 0o640);
  } finally {
    cleanupDomain(domain);
  }
});
