"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const EXECUTED_EVIDENCE_API = require("../mcp/core/executed-evidence-registry.js");
const EXECUTED_EVIDENCE_CONTRACT = require("../mcp/core/executed-evidence-contract.js");
const {
  DEPENDENCY_PROOF_PROVIDER_KINDS,
  REPLAY_EXECUTOR_MODES,
  buildExecutedEvidenceRegistry,
  resolveAndReverifyExecutedEvidence,
  verifyRegisteredEvidence,
} = EXECUTED_EVIDENCE_API;

const NOW = "2026-07-18T01:00:00.000Z";
const OBSERVED_AT = "2026-07-18T00:30:00.000Z";
const ATTESTED_AT = "2026-07-18T00:00:00.000Z";
const FRESHNESS_MS = 24 * 60 * 60 * 1000;

function digest(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function componentCommon(name, verdictType, implementationKind = "tool", overrides = {}) {
  return {
    version: 1,
    owner_principal: `principal:${name}`,
    [`${implementationKind}_digest`]: digest(`${name}:${implementationKind}`),
    signed_verdict_type: verdictType,
    trust_epoch: 7,
    trust_state: "trusted",
    attested_at: ATTESTED_AT,
    freshness_window_ms: FRESHNESS_MS,
    revoked: false,
    ...overrides,
  };
}

function makeRow({ sourceId, verdictType, implementationDigest, evidenceRef }) {
  return {
    evidence_ref: evidenceRef,
    payload_digest: digest(`${sourceId}:payload`),
    implementation_digest: implementationDigest,
    content_hash_valid: true,
    owner_principal: `principal:${sourceId}`,
    signer_key_id: `signer-key:${sourceId}`,
    signed_verdict_type: verdictType,
    trust_epoch: 7,
    signature_valid: true,
    reverification_valid: true,
    trusted: true,
    revoked: false,
    execution_identity: `execution:${sourceId}`,
    node_contract_digest: digest(`${sourceId}:node-contract`),
    context_digest: digest(`${sourceId}:context`),
    surface_refs: [`asset:${sourceId}`],
    disposition: "verified",
    verdict_hash: digest(`${sourceId}:verdict`),
    observed_at: OBSERVED_AT,
    cleanup_status: "succeeded",
  };
}

function sourceDefinition({ sourceId, refPrefix, verdictType, rows, counters, overrides = {} }) {
  const common = componentCommon(sourceId, verdictType, "artifact", overrides);
  return {
    ...common,
    source_id: sourceId,
    ref_prefix: refPrefix,
    resolve: async (evidenceRef) => rows.get(evidenceRef) || null,
    reverify: async (row) => {
      counters.set(sourceId, (counters.get(sourceId) || 0) + 1);
      return {
        version: 1,
        verified: row.reverification_valid === true,
        verification_digest: digest(`${sourceId}:reverification:${row.payload_digest}`),
      };
    },
    project_integrity: (row) => ({
      payload_digest: row.payload_digest,
      implementation_digest: row.implementation_digest,
      content_hash_valid: row.content_hash_valid,
    }),
    project_signer_trust: (row) => ({
      owner_principal: row.owner_principal,
      signer_key_id: row.signer_key_id,
      signed_verdict_type: row.signed_verdict_type,
      trust_epoch: row.trust_epoch,
      signature_valid: row.signature_valid,
      trusted: row.trusted,
      revoked: row.revoked,
    }),
    project_execution_identity: (row) => row.execution_identity,
    project_node_contract_digest: (row) => row.node_contract_digest,
    project_context_digest: (row) => row.context_digest,
    project_surfaces: (row) => row.surface_refs,
    project_outcome: (row) => ({
      disposition: row.disposition,
      verdict_hash: row.verdict_hash,
      observed_at: row.observed_at,
    }),
    project_cleanup: (row) => ({ status: row.cleanup_status, observed_at: row.observed_at }),
  };
}

function resolverDefinition({ resolverId, contextKind, verdictType, overrides = {} }) {
  return {
    ...componentCommon(resolverId, verdictType, "tool", overrides),
    resolver_id: resolverId,
    context_kind: contextKind,
    resolve_context: async (request) => ({ version: 1, ...request, resolved_at: OBSERVED_AT }),
  };
}

function executorDefinition({ executorId, mode, verdictType, requiredDependencyKeys = [], dependencySeen, overrides = {} }) {
  return {
    ...componentCommon(executorId, verdictType, "tool", overrides),
    executor_id: executorId,
    mode,
    required_dependency_keys: requiredDependencyKeys,
    execute: async ({ evidence, context }, callContext) => {
      if (dependencySeen) dependencySeen.push(Object.keys(callContext.deps).sort());
      return {
        version: 1,
        disposition: evidence.outcome.disposition,
        signed_verdict_type: verdictType,
        verdict_hash: evidence.outcome.verdict_hash,
        consumed_evidence_digest: evidence.evidence_digest,
        execution_identity: context.execution_identity,
        node_contract_digest: context.node_contract_digest,
        context_digest: context.context_digest,
        executed_at: OBSERVED_AT,
        cleanup_status: evidence.cleanup.status,
      };
    },
  };
}

function templateDefinition({ templateId, mode, verdictType, sourceId, resolverId, executorId, providerIds = [], overrides = {} }) {
  return {
    ...componentCommon(templateId, verdictType, "artifact", overrides),
    template_id: templateId,
    template_version: 1,
    mode,
    source_ids: [sourceId],
    context_resolver_id: resolverId,
    replay_executor_id: executorId,
    dependency_provider_ids: providerIds,
    decision_rule_digest: digest(`${templateId}:decision-rule`),
    adjudicate: async ({ replay }) => ({
      version: 1,
      disposition: replay.disposition,
      signed_verdict_type: verdictType,
      verdict_hash: replay.verdict_hash,
      replay_digest: replay.replay_digest,
      execution_identity: replay.execution_identity,
      node_contract_digest: replay.node_contract_digest,
      context_digest: replay.context_digest,
      decided_at: OBSERVED_AT,
    }),
  };
}

function providerDefinition(kind) {
  const providerId = `physical.${kind}`;
  return {
    ...componentCommon(providerId, `dependency.${kind}.v1`, kind === "compiler" ? "artifact" : "tool"),
    provider_id: providerId,
    provider_kind: kind,
    verify_proof: async (proof) => proof,
  };
}

function fixture(options = {}) {
  const rows = new Map();
  const counters = new Map();
  const dependencySeen = [];
  const sourceSpecs = [
    { sourceId: "physical.broker-receipts", refPrefix: "physical-receipt", verdictType: "physical.transition.v1" },
    { sourceId: "web.offensive-runs", refPrefix: "offensive-run", verdictType: "web.offensive.v1" },
    { sourceId: "smart-contract.invariant-runs", refPrefix: "invariant-run", verdictType: "smart-contract.invariant.v1" },
  ];
  const resolverSpecs = [
    { resolverId: "physical.execution-context", contextKind: "physical", verdictType: "physical.transition.v1" },
    { resolverId: "web.execution-context", contextKind: "web", verdictType: "web.offensive.v1" },
    { resolverId: "smart-contract.execution-context", contextKind: "smart-contract", verdictType: "smart-contract.invariant.v1" },
  ];
  const executorSpecs = [
    { executorId: "physical.verified-bind", mode: "verified-verdict-bind", verdictType: "physical.transition.v1", requiredDependencyKeys: [], dependencySeen },
    { executorId: "web.live-reexecute", mode: "reexecute", verdictType: "web.offensive.v1", requiredDependencyKeys: ["base_url", "httpScanFn"] },
    { executorId: "smart-contract.verified-bind", mode: "verified-verdict-bind", verdictType: "smart-contract.invariant.v1", requiredDependencyKeys: [] },
  ];
  const providerKinds = [...DEPENDENCY_PROOF_PROVIDER_KINDS];
  const providerIds = providerKinds.map((kind) => `physical.${kind}`).sort();
  const templateSpecs = [
    {
      templateId: "physical.transition-positive-control",
      mode: "verified-verdict-bind",
      verdictType: "physical.transition.v1",
      sourceId: "physical.broker-receipts",
      resolverId: "physical.execution-context",
      executorId: "physical.verified-bind",
      providerIds,
    },
    {
      templateId: "web.object-auth",
      mode: "reexecute",
      verdictType: "web.offensive.v1",
      sourceId: "web.offensive-runs",
      resolverId: "web.execution-context",
      executorId: "web.live-reexecute",
    },
    {
      templateId: "smart-contract.invariant-differential",
      mode: "verified-verdict-bind",
      verdictType: "smart-contract.invariant.v1",
      sourceId: "smart-contract.invariant-runs",
      resolverId: "smart-contract.execution-context",
      executorId: "smart-contract.verified-bind",
    },
  ];

  const sourceDefinitions = sourceSpecs.map((spec) => sourceDefinition({
    ...spec,
    rows,
    counters,
    overrides: spec.sourceId === options.sourceOverrideId ? options.sourceOverrides : {},
  }));
  for (const definition of sourceDefinitions) {
    const evidenceRef = `${definition.ref_prefix}:row-1`;
    rows.set(evidenceRef, makeRow({
      sourceId: definition.source_id,
      verdictType: definition.signed_verdict_type,
      implementationDigest: definition.artifact_digest,
      evidenceRef,
    }));
  }

  const registry = buildExecutedEvidenceRegistry({
    source_adapters: sourceDefinitions,
    context_resolvers: resolverSpecs.map((spec) => resolverDefinition({ ...spec })),
    replay_executors: executorSpecs.map((spec) => executorDefinition({ ...spec })),
    verifier_templates: templateSpecs.map((spec) => templateDefinition({ ...spec })),
    dependency_proof_providers: providerKinds.map(providerDefinition),
  });
  return { registry, rows, counters, dependencySeen };
}

function requestFor(registry, sourceId, resolverId, executorId, templateId) {
  const source = registry.get("source_adapters", sourceId);
  const resolver = registry.get("context_resolvers", resolverId);
  const executor = registry.get("replay_executors", executorId);
  const template = registry.get("verifier_templates", templateId);
  const evidenceRef = `${source.ref_prefix}:row-1`;
  const rowPrefix = sourceId;
  const executionIdentity = `execution:${rowPrefix}`;
  const nodeContractDigest = digest(`${rowPrefix}:node-contract`);
  const contextDigest = digest(`${rowPrefix}:context`);
  const request = {
    version: 1,
    executed_evidence_ref: {
      version: 1,
      source_id: sourceId,
      source_adapter_digest: source.adapter_digest,
      evidence_ref: evidenceRef,
      expected_payload_digest: digest(`${rowPrefix}:payload`),
      expected_verdict_hash: digest(`${rowPrefix}:verdict`),
      execution_identity: executionIdentity,
      node_contract_digest: nodeContractDigest,
      context_digest: contextDigest,
    },
    context_resolver_ref: { resolver_id: resolverId, resolver_digest: resolver.resolver_digest },
    context_request: {
      execution_identity: executionIdentity,
      node_contract_digest: nodeContractDigest,
      context_digest: contextDigest,
      surface_refs: [`asset:${sourceId}`],
    },
    replay_executor_ref: { executor_id: executorId, executor_digest: executor.executor_digest },
    verifier_template_ref: {
      template_id: templateId,
      template_version: template.template_version,
      template_digest: template.template_digest,
    },
    dependency_proof_refs: [],
  };
  request.dependency_proof_refs = template.dependency_provider_ids.map((providerId) => {
    const provider = registry.get("dependency_proof_providers", providerId);
    return {
      provider_id: providerId,
      provider_digest: provider.provider_digest,
      proof: {
        version: 1,
        owner_principal: provider.owner_principal,
        implementation_digest: provider.artifact_digest || provider.tool_digest,
        signed_verdict_type: provider.signed_verdict_type,
        trust_epoch: provider.trust_epoch,
        signature_valid: true,
        trusted: true,
        revoked: false,
        observed_at: OBSERVED_AT,
        payload_digest: digest(`${providerId}:proof-payload`),
        execution_identity: executionIdentity,
        node_contract_digest: nodeContractDigest,
        context_digest: contextDigest,
        verdict_hash: digest(`${rowPrefix}:verdict`),
      },
    };
  });
  return request;
}

function physicalRequest(registry) {
  return requestFor(
    registry,
    "physical.broker-receipts",
    "physical.execution-context",
    "physical.verified-bind",
    "physical.transition-positive-control",
  );
}

test("the shared evidence contract owns one registry brand without an issuance seam", () => {
  for (const name of [
    "assertDurableReceiptTrustRegistry",
    "assertExecutedEvidenceRegistry",
    "buildDurableReceiptTrustRegistry",
    "buildExecutedEvidenceRegistry",
    "normalizeAndVerifyDurableEvidenceReceipt",
    "normalizeExecutedEvidenceRef",
  ]) {
    assert.equal(
      EXECUTED_EVIDENCE_API[name],
      EXECUTED_EVIDENCE_CONTRACT[name],
      `${name} must retain one shared implementation and private brand`,
    );
  }
  const { registry } = fixture();
  assert.equal(EXECUTED_EVIDENCE_CONTRACT.assertExecutedEvidenceRegistry(registry), registry);
  assert.throws(
    () => EXECUTED_EVIDENCE_CONTRACT.assertExecutedEvidenceRegistry(Object.freeze({ ...registry })),
    /closed Bob executed-evidence registry/u,
  );
  assert.equal(
    Object.hasOwn(EXECUTED_EVIDENCE_CONTRACT, "createDurableEvidenceReceiptIssuer"),
    false,
    "the lower contract must not expose signing or receipt issuance",
  );
  assert.equal(
    Object.hasOwn(EXECUTED_EVIDENCE_CONTRACT, "issuePhysicalSurfaceTransition"),
    false,
    "the lower contract must not accept a caller-supplied claim verification seam",
  );
});

test("closed registries bind all component contracts and all dependency proof provider kinds", () => {
  const { registry } = fixture();
  assert.equal(Object.isFrozen(registry), true);
  assert.equal(typeof registry.set, "undefined");
  assert.match(registry.registry_digest, /^[a-f0-9]{64}$/);
  assert.deepEqual(registry.ids("source_adapters"), [
    "physical.broker-receipts",
    "smart-contract.invariant-runs",
    "web.offensive-runs",
  ]);
  assert.deepEqual(
    registry.ids("dependency_proof_providers").map((id) => registry.get("dependency_proof_providers", id).provider_kind).sort(),
    [...DEPENDENCY_PROOF_PROVIDER_KINDS].sort(),
  );
  assert.equal(Object.isFrozen(registry.describe()), true);
  assert.equal(Object.isFrozen(registry.get("source_adapters", "physical.broker-receipts")), true);
  assert.deepEqual(REPLAY_EXECUTOR_MODES, ["reexecute", "verified-verdict-bind"]);
});

test("a copied registry cannot forge the private registry-instance boundary", async () => {
  const { registry } = fixture();
  const forged = { ...registry };

  assert.deepEqual(Object.getOwnPropertySymbols(registry), []);
  await assert.rejects(
    () => verifyRegisteredEvidence(forged, physicalRequest(registry), { now: NOW }),
    /closed Bob executed-evidence registry/,
  );
});

test("a physical verified-verdict bind runs without web-only dependencies and binds every execution field", async () => {
  const { registry, dependencySeen } = fixture();
  const deps = { now: NOW };
  assert.equal(Object.prototype.hasOwnProperty.call(deps, "base_url"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(deps, "httpScanFn"), false);

  const result = await verifyRegisteredEvidence(registry, physicalRequest(registry), deps);
  assert.equal(result.disposition, "verified");
  assert.equal(result.replay_mode, "verified-verdict-bind");
  assert.equal(result.execution_identity, "execution:physical.broker-receipts");
  assert.equal(result.node_contract_digest, digest("physical.broker-receipts:node-contract"));
  assert.equal(result.context_digest, digest("physical.broker-receipts:context"));
  assert.equal(result.dependency_proofs.length, DEPENDENCY_PROOF_PROVIDER_KINDS.length);
  assert.match(result.verified_outcome_digest, /^[a-f0-9]{64}$/);
  assert.deepEqual(dependencySeen, [["now"]]);

  const evidence = await resolveAndReverifyExecutedEvidence(
    registry,
    physicalRequest(registry).executed_evidence_ref,
    deps,
  );
  assert.equal(evidence.reverification.version, 1);
  assert.equal(evidence.reverification.verified, true);
  assert.match(evidence.reverification.verification_digest, /^[a-f0-9]{64}$/);
});

test("web re-execute and smart-contract bind adapters dispatch through the same registry", async () => {
  const { registry } = fixture();
  const web = requestFor(
    registry,
    "web.offensive-runs",
    "web.execution-context",
    "web.live-reexecute",
    "web.object-auth",
  );
  await assert.rejects(() => verifyRegisteredEvidence(registry, web, { now: NOW }), /requires dependency base_url/);
  const webResult = await verifyRegisteredEvidence(registry, web, {
    now: NOW,
    base_url: "https://owned-fixture.invalid",
    httpScanFn: async () => ({ status: 200 }),
  });
  assert.equal(webResult.replay_mode, "reexecute");

  const smart = requestFor(
    registry,
    "smart-contract.invariant-runs",
    "smart-contract.execution-context",
    "smart-contract.verified-bind",
    "smart-contract.invariant-differential",
  );
  const smartResult = await verifyRegisteredEvidence(registry, smart, { now: NOW });
  assert.equal(smartResult.replay_mode, "verified-verdict-bind");
  assert.equal(smartResult.source_id, "smart-contract.invariant-runs");
});

test("source resolution is read-time reverified and fails closed on unresolved or signed-row drift", async () => {
  const { registry, rows, counters } = fixture();
  const request = physicalRequest(registry);
  await resolveAndReverifyExecutedEvidence(registry, request.executed_evidence_ref, { now: NOW });
  await resolveAndReverifyExecutedEvidence(registry, request.executed_evidence_ref, { now: NOW });
  assert.equal(counters.get("physical.broker-receipts"), 2);

  const row = rows.get("physical-receipt:row-1");
  row.reverification_valid = false;
  await assert.rejects(
    () => resolveAndReverifyExecutedEvidence(registry, request.executed_evidence_ref, { now: NOW }),
    /read-time reverification failed/,
  );
  row.reverification_valid = true;
  row.signature_valid = false;
  await assert.rejects(
    () => resolveAndReverifyExecutedEvidence(registry, request.executed_evidence_ref, { now: NOW }),
    /signer trust is degraded/,
  );
  row.signature_valid = true;
  row.context_digest = digest("drifted-context");
  await assert.rejects(
    () => resolveAndReverifyExecutedEvidence(registry, request.executed_evidence_ref, { now: NOW }),
    /context digest drift/,
  );
  rows.delete("physical-receipt:row-1");
  await assert.rejects(
    () => resolveAndReverifyExecutedEvidence(registry, request.executed_evidence_ref, { now: NOW }),
    /did not resolve/,
  );
});

test("unregistered, digest-drifted, stale, revoked, and trust-degraded components cannot verify", async () => {
  const { registry } = fixture();
  const unregistered = structuredClone(physicalRequest(registry));
  unregistered.executed_evidence_ref.source_id = "physical.future-source";
  await assert.rejects(() => verifyRegisteredEvidence(registry, unregistered, { now: NOW }), /unregistered/);

  for (const [path, expected] of [
    [["executed_evidence_ref", "source_adapter_digest"], /source adapter digest drift/],
    [["context_resolver_ref", "resolver_digest"], /context resolver digest drift/],
    [["replay_executor_ref", "executor_digest"], /replay executor digest drift/],
    [["verifier_template_ref", "template_digest"], /verifier template digest drift/],
  ]) {
    const drift = structuredClone(physicalRequest(registry));
    drift[path[0]][path[1]] = "0".repeat(64);
    await assert.rejects(() => verifyRegisteredEvidence(registry, drift, { now: NOW }), expected);
  }

  await assert.rejects(
    () => verifyRegisteredEvidence(registry, physicalRequest(registry), { now: "2026-07-20T01:00:00.000Z" }),
    /stale/,
  );
  await assert.rejects(
    () => verifyRegisteredEvidence(registry, physicalRequest(registry), {
      now: NOW,
      isTrustEpochTrusted: () => false,
    }),
    /trust epoch is not trusted/,
  );

  const revokedFixture = fixture({
    sourceOverrideId: "physical.broker-receipts",
    sourceOverrides: {
      revoked: true,
      revoked_at: "2026-07-18T00:20:00.000Z",
      revocation_ref: "revocation:physical-source-1",
    },
  });
  await assert.rejects(
    () => verifyRegisteredEvidence(revokedFixture.registry, physicalRequest(revokedFixture.registry), { now: NOW }),
    /is revoked/,
  );
  const degradedFixture = fixture({
    sourceOverrideId: "physical.broker-receipts",
    sourceOverrides: { trust_state: "degraded" },
  });
  await assert.rejects(
    () => verifyRegisteredEvidence(degradedFixture.registry, physicalRequest(degradedFixture.registry), { now: NOW }),
    /trust-degraded/,
  );
});

test("dependency proofs bind provider ownership, implementation, verdict type, epoch, liveness, and execution context", async () => {
  const { registry } = fixture();
  const cases = [
    ["owner_principal", "principal:wrong-owner", /owner principal drift/],
    ["implementation_digest", digest("wrong-tool"), /implementation digest drift/],
    ["signed_verdict_type", "dependency.wrong.v1", /signed verdict type drift/],
    ["trust_epoch", 8, /trust epoch drift/],
    ["signature_valid", false, /signer trust is degraded/],
    ["revoked", true, /is revoked/],
    ["context_digest", digest("wrong-context"), /execution\/context binding drift/],
    ["verdict_hash", digest("wrong-verdict"), /verdict binding drift/],
    ["observed_at", "2026-07-16T00:00:00.000Z", /is stale/],
  ];
  for (const [field, value, expected] of cases) {
    const request = structuredClone(physicalRequest(registry));
    request.dependency_proof_refs[0].proof[field] = value;
    await assert.rejects(() => verifyRegisteredEvidence(registry, request, { now: NOW }), expected, field);
  }
});

test("registry construction rejects duplicate IDs, unregistered relationships, and verdict-type drift", () => {
  const { registry } = fixture();
  const source = registry.get("source_adapters", "physical.broker-receipts");
  const descriptor = registry.describe();
  assert.equal(descriptor.source_adapters[0].resolve, undefined);
  assert.match(source.adapter_digest, /^[a-f0-9]{64}$/);

  const empty = {
    source_adapters: [],
    context_resolvers: [],
    replay_executors: [],
    verifier_templates: [],
    dependency_proof_providers: [],
  };
  const sourceInput = sourceDefinition({
    sourceId: "duplicate.source",
    refPrefix: "duplicate-row",
    verdictType: "duplicate.verdict.v1",
    rows: new Map(),
    counters: new Map(),
  });
  assert.throws(
    () => buildExecutedEvidenceRegistry({ ...empty, source_adapters: [sourceInput, sourceInput] }),
    /duplicate ID/,
  );

  const resolver = resolverDefinition({
    resolverId: "missing.resolver",
    contextKind: "physical",
    verdictType: "duplicate.verdict.v1",
  });
  const executor = executorDefinition({
    executorId: "missing.executor",
    mode: "verified-verdict-bind",
    verdictType: "duplicate.verdict.v1",
  });
  const template = templateDefinition({
    templateId: "missing.template",
    mode: "verified-verdict-bind",
    verdictType: "duplicate.verdict.v1",
    sourceId: "duplicate.source",
    resolverId: "unregistered.resolver",
    executorId: "missing.executor",
  });
  assert.throws(
    () => buildExecutedEvidenceRegistry({
      ...empty,
      source_adapters: [sourceInput],
      context_resolvers: [resolver],
      replay_executors: [executor],
      verifier_templates: [template],
    }),
    /unregistered context resolver/,
  );

  const driftTemplate = templateDefinition({
    templateId: "drift.template",
    mode: "verified-verdict-bind",
    verdictType: "other.verdict.v1",
    sourceId: "duplicate.source",
    resolverId: "missing.resolver",
    executorId: "missing.executor",
  });
  assert.throws(
    () => buildExecutedEvidenceRegistry({
      ...empty,
      source_adapters: [sourceInput],
      context_resolvers: [resolver],
      replay_executors: [executor],
      verifier_templates: [driftTemplate],
    }),
    /signed verdict type drift/,
  );
});
