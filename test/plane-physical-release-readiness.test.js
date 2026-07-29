"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { spawnSync } = require("node:child_process");

const nodesDocument = require("../docs/plane-physical/nodes.json");
const hyperedgesDocument = require("../docs/plane-physical/hyperedges.json");
const {
  PLANE_PHYSICAL_PRODUCTION_NONWAIVABLE_HIL_NODE_IDS,
  PLANE_PHYSICAL_REVIEWED_HYPEREDGE_REGISTRY_SHA256,
  PLANE_PHYSICAL_REVIEWED_NODE_CONTRACT_REGISTRY_SHA256,
  planePhysicalHyperedgeRegistryDigest,
  planePhysicalNodeContractDigest,
  planePhysicalNodeContractRegistryDigest,
} = require("../mcp/lib/plane-physical-release-contracts.js");
const {
  PLANE_PHYSICAL_PACKAGED_RELEASE_SNAPSHOT,
  assertPackagedPlanePhysicalReleaseSnapshot,
  compilePlanePhysicalReleaseSnapshot,
} = require("../mcp/lib/plane-physical-release-snapshot.js");
const {
  createConformancePlanePhysicalGateEvidenceRuntime,
  issuePlanePhysicalGateEvidence,
  planePhysicalReleaseCandidateDigest,
} = require("../mcp/lib/plane-physical-gate-evidence.js");
const {
  PLANE_PHYSICAL_RELEASE_QUALIFICATION_CHECK_REGISTRY,
  PLANE_PHYSICAL_SIGNED_RELEASE_QUALIFICATION_CHECK_REGISTRY,
  assertCurrentSignedPlanePhysicalReleaseReadiness,
  evaluatePackagedPlanePhysicalReleaseReadiness,
  evaluatePlanePhysicalReleaseReadiness,
  evaluateSignedPlanePhysicalReleaseReadiness,
  planePhysicalGateAcceptanceDigest,
  planePhysicalGateContractDigest,
} = require("../mcp/lib/plane-physical-release-readiness.js");
const {
  parsePhysicalProductionRequirement,
} = require("../scripts/release-check.js");
const {
  canonicalInstalledRuntimeFiles,
  expectedCanonicalFiles,
} = require("../scripts/lib/package-policy.js");

const ROOT = path.join(__dirname, "..");

const CLASSES = ["engineering", "review", "hil", "qualification"];

function digest(label) {
  return crypto.createHash("sha256").update(label).digest("hex");
}

function clone(value) {
  return structuredClone(value);
}

function hasBlocker(verdict, code, dimensions = {}) {
  return verdict.blockers.some((blocker) => blocker.code === code
    && Object.entries(dimensions).every(([field, value]) => blocker[field] === value));
}

function fixture(opts = {}) {
  const validityMs = opts.validityMs ?? 60_000;
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-release-"));
  fs.chmodSync(root, 0o700);
  const session = digest(`session-${crypto.randomUUID()}`);
  const signers = CLASSES.map((evidenceClass) => {
    const pair = crypto.generateKeyPairSync("ed25519");
    return {
      evidence_class: evidenceClass,
      signer_principal_id: `principal:release-${evidenceClass}`,
      signer_key_id: `signer-key:release-${evidenceClass}`,
      signer_epoch: 1,
      private_key_pem: pair.privateKey.export({ type: "pkcs8", format: "pem" }),
      signer_validity_ms: validityMs,
      evidence_validity_ms: validityMs,
    };
  });
  const runtime = createConformancePlanePhysicalGateEvidenceRuntime({
    version: 1,
    root,
    runtime_id: "ph_x8_release_readiness",
    target_domain: "hotel.example",
    session_nucleus_hash: session,
    trust_root_id: "trust-root:release",
    trust_root_epoch: 1,
    trust_validity_ms: validityMs,
    signers,
  });
  const contextInputs = {
    session_nucleus_hash: session,
    source_tree_digest: digest("release-source-tree"),
    package_digest: digest("packed-tarball"),
    task_graph_digest: planePhysicalHyperedgeRegistryDigest(hyperedgesDocument),
    release_snapshot_digest: PLANE_PHYSICAL_PACKAGED_RELEASE_SNAPSHOT.snapshot_sha256,
  };
  const context = {
    ...contextInputs,
    release_candidate_digest: planePhysicalReleaseCandidateDigest(contextInputs),
  };
  const nodes = clone(nodesDocument);
  const node = nodes.nodes.find((candidate) => candidate.id === "PH-X8");
  const nodeDigest = planePhysicalNodeContractDigest(node);
  const gateDigest = planePhysicalGateContractDigest(node, "engineering");
  const acceptanceDigest = planePhysicalGateAcceptanceDigest({
    graph_id: nodes.graph_id,
    node_id: node.id,
    gate_kind: "engineering",
    evidence_class: "engineering",
    release_candidate_digest: context.release_candidate_digest,
    node_contract_digest: nodeDigest,
    gate_contract_digest: gateDigest,
    qualification_check_id: null,
    qualification_manifest_digest: null,
  });
  const binding = {
    graph_id: nodes.graph_id,
    node_id: node.id,
    gate_kind: "engineering",
    evidence_class: "engineering",
    ...contextInputs,
    release_candidate_digest: context.release_candidate_digest,
    node_contract_digest: nodeDigest,
    gate_contract_digest: gateDigest,
    acceptance_digest: acceptanceDigest,
    result_digest: digest("ph-x8-engineering-result"),
    verdict: "passed",
  };
  const document = issuePlanePhysicalGateEvidence(runtime, binding);
  const reviewGateDigest = planePhysicalGateContractDigest(node, "review");
  const reviewAcceptanceDigest = planePhysicalGateAcceptanceDigest({
    graph_id: nodes.graph_id,
    node_id: node.id,
    gate_kind: "review",
    evidence_class: "review",
    release_candidate_digest: context.release_candidate_digest,
    node_contract_digest: nodeDigest,
    gate_contract_digest: reviewGateDigest,
    qualification_check_id: null,
    qualification_manifest_digest: null,
  });
  const reviewBinding = {
    ...binding,
    gate_kind: "review",
    evidence_class: "review",
    gate_contract_digest: reviewGateDigest,
    acceptance_digest: reviewAcceptanceDigest,
    result_digest: digest("ph-x8-review-result"),
  };
  const reviewDocument = issuePlanePhysicalGateEvidence(runtime, reviewBinding);
  nodes.gate_tracking[node.id].engineering_evidence_refs = [document.evidence_ref];
  nodes.gate_tracking[node.id].engineering_state = "passed";
  node.review_evidence = [reviewDocument.evidence_ref];
  const input = {
    version: 1,
    nodes_document: nodes,
    hyperedges_document: clone(hyperedgesDocument),
    release_context: context,
    evidence_runtime: runtime,
    evidence_bindings: [
      { evidence_ref: document.evidence_ref, expected_bindings: binding },
      { evidence_ref: reviewDocument.evidence_ref, expected_bindings: reviewBinding },
    ],
    qualification_evidence: [],
  };
  return {
    binding,
    context,
    document,
    input,
    node,
    reviewBinding,
    reviewDocument,
    root,
    runtime,
    cleanup() { fs.rmSync(root, { recursive: true, force: true }); },
  };
}

// Re-issue both gate evidences on the same runtime with different result
// digests, yielding a materially different evaluation input that supersedes the
// prior release-snapshot receipt (idempotent rehydration only collapses byte-
// identical evaluations, not genuine evidence changes).
function reissuedInput(f, engResultTag, reviewResultTag) {
  const engBinding = { ...f.binding, result_digest: digest(engResultTag) };
  const reviewBinding = { ...f.reviewBinding, result_digest: digest(reviewResultTag) };
  const engDoc = issuePlanePhysicalGateEvidence(f.runtime, engBinding);
  const reviewDoc = issuePlanePhysicalGateEvidence(f.runtime, reviewBinding);
  const nodes = clone(f.input.nodes_document);
  const node = nodes.nodes.find((candidate) => candidate.id === "PH-X8");
  nodes.gate_tracking[node.id].engineering_evidence_refs = [engDoc.evidence_ref];
  nodes.gate_tracking[node.id].engineering_state = "passed";
  node.review_evidence = [reviewDoc.evidence_ref];
  return {
    ...f.input,
    nodes_document: nodes,
    evidence_bindings: [
      { evidence_ref: engDoc.evidence_ref, expected_bindings: engBinding },
      { evidence_ref: reviewDoc.evidence_ref, expected_bindings: reviewBinding },
    ],
  };
}

test("release resolves exact conformance evidence but reports custody blockers honestly", (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  const verdict = evaluateSignedPlanePhysicalReleaseReadiness(f.input);
  assert.equal(verdict.version, 1);
  assert.equal(verdict.release_candidate_digest, f.context.release_candidate_digest);
  assert.equal(verdict.physical_production_ready, false);
  assert.equal(verdict.verdict, "blocked");
  assert.ok(hasBlocker(verdict, "gate_evidence_not_production_qualified", {
    node_id: "PH-X8",
    gate_kind: "engineering",
  }));
  assert.ok(hasBlocker(verdict, "independent_signer_custody_unavailable", {
    node_id: "PH-X8",
  }));
  assert.ok(hasBlocker(verdict,
    "authenticated_boot_continuous_trusted_clock_unavailable", { node_id: "PH-X8" }));
  assert.equal(hasBlocker(verdict, "evidence_resolution_failed", { node_id: "PH-X8" }), false);
  assert.equal(verdict.evidence_batch_entry_count, 2);
  assert.match(verdict.evidence_batch_projection_sha256, /^[a-f0-9]{64}$/u);
  assert.match(verdict.evidence_batch_verified_set_sha256, /^[a-f0-9]{64}$/u);
  assert.match(verdict.evidence_batch_common_trusted_time_sha256, /^[a-f0-9]{64}$/u);
  assert.match(verdict.conformance_snapshot_ref,
    /^gate-conformance-snapshot:[a-f0-9]{64}$/u);
  assert.match(verdict.release_snapshot_receipt_ref,
    /^gate-release-snapshot-receipt:[a-f0-9]{64}$/u);
  assert.match(verdict.release_snapshot_receipt_sha256, /^[a-f0-9]{64}$/u);
  assert.match(verdict.release_snapshot_receipt_projection_sha256, /^[a-f0-9]{64}$/u);
  assert.match(verdict.conformance_snapshot_basis_sha256, /^[a-f0-9]{64}$/u);
  assert.equal(verdict.release_snapshot_receipt_sequence, "1");
  assert.equal(verdict.authorization_semantics,
    "committed_conformance_snapshot_requires_currentness_assertion");
  assert.equal(verdict.currentness_assertion_required, true);
  assert.equal(verdict.authoritative_release_action, false);
  assert.equal(assertCurrentSignedPlanePhysicalReleaseReadiness(
    verdict,
    f.runtime,
  ), verdict);
  assert.throws(
    () => assertCurrentSignedPlanePhysicalReleaseReadiness(
      Object.freeze(structuredClone(verdict)),
      f.runtime,
    ),
    /privately branded/u,
  );

  const bridged = evaluateSignedPlanePhysicalReleaseReadiness(f.input);
  assert.equal(bridged.release_candidate_digest, verdict.release_candidate_digest);
  assert.equal(bridged.evidence_batch_entry_count, 2);
  assert.equal(bridged.physical_production_ready, false);
  // Re-evaluating the identical release rehydrates the durable head receipt
  // instead of appending a duplicate, so the sequence does not advance and the
  // earlier verdict projection remains current.
  assert.equal(bridged.release_snapshot_receipt_sequence, "1");
  assert.equal(bridged.release_snapshot_receipt_sha256, verdict.release_snapshot_receipt_sha256);
  assert.equal(
    fs.readdirSync(path.join(f.root, "release-snapshot-receipts")).length,
    1,
  );
  assert.equal(assertCurrentSignedPlanePhysicalReleaseReadiness(
    bridged,
    f.runtime,
  ), bridged);
  assert.equal(assertCurrentSignedPlanePhysicalReleaseReadiness(verdict, f.runtime), verdict);
});

test("release re-evaluating an identical release rehydrates the head receipt", (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  const first = evaluateSignedPlanePhysicalReleaseReadiness(f.input);
  const second = evaluateSignedPlanePhysicalReleaseReadiness(f.input);
  assert.equal(first.release_snapshot_receipt_sequence, "1");
  assert.equal(second.release_snapshot_receipt_sequence, "1");
  assert.equal(
    second.release_snapshot_receipt_sha256,
    first.release_snapshot_receipt_sha256,
  );
  assert.equal(
    fs.readdirSync(path.join(f.root, "release-snapshot-receipts")).length,
    1,
  );
  // Idempotent rehydration does not supersede: both projections stay current.
  assert.equal(assertCurrentSignedPlanePhysicalReleaseReadiness(first, f.runtime), first);
  assert.equal(assertCurrentSignedPlanePhysicalReleaseReadiness(second, f.runtime), second);
  // Only a genuinely different evaluation advances the sequence.
  const third = evaluateSignedPlanePhysicalReleaseReadiness(
    reissuedInput(f, "ph-x8-engineering-idempotency", "ph-x8-review-idempotency"),
  );
  assert.equal(third.release_snapshot_receipt_sequence, "2");
  assert.equal(
    fs.readdirSync(path.join(f.root, "release-snapshot-receipts")).length,
    2,
  );
});

test("release renews the receipt when an identical evaluation's window has expired", (t) => {
  // Evidence must outlive the 5-minute receipt window so the expired-head path
  // is reachable (the default 60s evidence validity would expire first).
  const f = fixture({ validityMs: 20 * 60 * 1000 });
  t.after(() => f.cleanup());
  const first = evaluateSignedPlanePhysicalReleaseReadiness(f.input);
  assert.equal(first.release_snapshot_receipt_sequence, "1");
  const realNow = Date.now;
  // Advance the process clock past the 5-minute receipt validity window: the
  // durable head is now expired, so an unchanged re-evaluation must renew with
  // a current window rather than rehydrate the stale head.
  Date.now = () => realNow() + 6 * 60 * 1000;
  let renewed;
  try {
    renewed = evaluateSignedPlanePhysicalReleaseReadiness(f.input);
    assert.equal(renewed.release_snapshot_receipt_sequence, "2");
    assert.equal(
      assertCurrentSignedPlanePhysicalReleaseReadiness(renewed, f.runtime),
      renewed,
    );
  } finally {
    Date.now = realNow;
  }
  assert.equal(
    fs.readdirSync(path.join(f.root, "release-snapshot-receipts")).length,
    2,
  );
});

test("release rejects a versioned evidence ref as an invalid reference", (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  const nodes = clone(f.input.nodes_document);
  const legacyRef = `bob-evidence:v1:sha256:${"a".repeat(64)}`;
  nodes.gate_tracking["PH-X8"].engineering_evidence_refs = [legacyRef];
  const verdict = evaluateSignedPlanePhysicalReleaseReadiness({
    ...f.input,
    nodes_document: nodes,
    evidence_bindings: [{ evidence_ref: legacyRef, expected_bindings: f.binding }],
  });
  assert.ok(hasBlocker(verdict, "evidence_ref_invalid", {
    node_id: "PH-X8",
    gate_kind: "engineering",
  }));
  assert.equal(verdict.physical_production_ready, false);
});

test("release full graph cannot become conformance-ready from forged versioned references", () => {
  const nodes = clone(nodesDocument);
  let serial = 0;
  const legacyRef = (label) => {
    serial += 1;
    return `bob-evidence:v1:sha256:${digest(`${serial}:${label}`)}`;
  };
  const qualificationRefs = PLANE_PHYSICAL_SIGNED_RELEASE_QUALIFICATION_CHECK_REGISTRY
    .map((check) => ({ check_id: check.check_id, evidence_ref: legacyRef(check.check_id) }));
  const qualificationByCheck = new Map(
    qualificationRefs.map((entry) => [entry.check_id, entry.evidence_ref]),
  );
  for (const node of nodes.nodes) {
    node.status = "done";
    const tracking = nodes.gate_tracking[node.id];
    tracking.engineering_state = "passed";
    tracking.engineering_evidence_refs = node.id === "PH-X8"
      ? PLANE_PHYSICAL_SIGNED_RELEASE_QUALIFICATION_CHECK_REGISTRY.map(
        (check) => qualificationByCheck.get(check.check_id),
      )
      : [legacyRef(`${node.id}:engineering`)];
    node.review_evidence = [legacyRef(`${node.id}:review`)];
    if (node.hil_gate === null) {
      tracking.hil_state = "not_required";
      tracking.hil_evidence_refs = [];
      tracking.hil_waiver_ref = null;
    } else {
      tracking.hil_state = "passed";
      tracking.hil_evidence_refs = [legacyRef(`${node.id}:hil`)];
      tracking.hil_waiver_ref = null;
    }
  }
  const contextInputs = {
    session_nucleus_hash: digest("forged-legacy-full-session"),
    source_tree_digest: digest("forged-legacy-full-source"),
    package_digest: digest("forged-legacy-full-package"),
    task_graph_digest: planePhysicalHyperedgeRegistryDigest(hyperedgesDocument),
    release_snapshot_digest: PLANE_PHYSICAL_PACKAGED_RELEASE_SNAPSHOT.snapshot_sha256,
  };
  const verdict = evaluateSignedPlanePhysicalReleaseReadiness({
    version: 1,
    nodes_document: nodes,
    hyperedges_document: clone(hyperedgesDocument),
    release_context: {
      ...contextInputs,
      release_candidate_digest: planePhysicalReleaseCandidateDigest(contextInputs),
    },
    evidence_runtime: null,
    evidence_bindings: [],
    qualification_evidence: qualificationRefs,
  });
  assert.equal(verdict.evidence_batch_entry_count, 0);
  assert.equal(verdict.evidence_batch_request_set_sha256, null);
  assert.equal(verdict.conformance_snapshot_ref, null);
  assert.equal(hasBlocker(verdict, "evidence_resolution_failed"), false);
  assert.equal(hasBlocker(verdict, "evidence_binding_missing"), false);
  assert.ok(hasBlocker(verdict, "evidence_ref_invalid"));
  assert.equal(
    verdict.blocker_counts.evidence_ref_invalid,
    verdict.evidence_ref_count,
  );
  assert.equal(verdict.conformance_ready, false);
  assert.equal(verdict.physical_production_ready, false);
  assert.throws(
    () => assertCurrentSignedPlanePhysicalReleaseReadiness(verdict, null),
    /privately branded/u,
  );
});

test("a plain object cannot impersonate a branded gate-evidence runtime", (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  // The fixture's refs and bindings are valid, but the evidence runtime is a
  // forged (unbranded) plain object: resolution must fail closed rather than
  // accept it as a live resolver, so no gate can reach production evidence.
  const verdict = evaluateSignedPlanePhysicalReleaseReadiness({
    ...f.input,
    evidence_runtime: Object.freeze({ production_ready: true }),
  });
  assert.ok(hasBlocker(verdict, "evidence_resolution_failed", {
    node_id: "PH-X8",
    gate_kind: "engineering",
  }));
  assert.equal(verdict.physical_production_ready, false);
});

test("release fails closed on candidate, package, task-graph, snapshot, gate, and acceptance drift", (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  const badCandidate = evaluateSignedPlanePhysicalReleaseReadiness({
    ...f.input,
    release_context: {
      ...f.context,
      release_candidate_digest: digest("wrong-candidate"),
    },
  });
  assert.ok(hasBlocker(badCandidate, "release_candidate_digest_mismatch"));

  for (const field of [
    "package_digest",
    "task_graph_digest",
    "release_snapshot_digest",
    "gate_contract_digest",
    "acceptance_digest",
  ]) {
    const expected = { ...f.binding, [field]: digest(`wrong-${field}`) };
    if (["package_digest", "task_graph_digest", "release_snapshot_digest"].includes(field)) {
      expected.release_candidate_digest = planePhysicalReleaseCandidateDigest({
        session_nucleus_hash: expected.session_nucleus_hash,
        source_tree_digest: expected.source_tree_digest,
        package_digest: expected.package_digest,
        task_graph_digest: expected.task_graph_digest,
        release_snapshot_digest: expected.release_snapshot_digest,
      });
    }
    const verdict = evaluateSignedPlanePhysicalReleaseReadiness({
      ...f.input,
      evidence_bindings: f.input.evidence_bindings.map((entry) => (
        entry.evidence_ref === f.document.evidence_ref
          ? { evidence_ref: entry.evidence_ref, expected_bindings: expected }
          : entry
      )),
    });
    assert.ok(hasBlocker(verdict, "evidence_binding_mismatch", { node_id: "PH-X8" }), field);
    assert.equal(verdict.physical_production_ready, false, field);
  }
});

test("release consumes atomic batch plus runtime-owned nonsemantic receipt surfaces", () => {
  const source = fs.readFileSync(
    path.join(__dirname, "../mcp/lib/plane-physical-release-readiness.js"),
    "utf8",
  );
  assert.match(source, /resolveAndVerifyPlanePhysicalGateEvidenceBatch/u);
  assert.match(source, /assertConformancePlanePhysicalGateEvidenceBatch/u);
  assert.match(source, /assertVerifiedPlanePhysicalGateEvidenceBatch/u);
  assert.match(source, /commit_release_snapshot_receipt/u);
  assert.match(source, /assert_current_release_snapshot_receipt/u);
  assert.doesNotMatch(source, /commitPlanePhysicalGateEvidenceReleaseDecision/u);
  assert.doesNotMatch(source, /assertCurrentPlanePhysicalGateEvidenceReleaseDecision/u);
  assert.doesNotMatch(source, /prepareSignedPlanePhysicalReleaseReadinessCommit/u);
  assert.doesNotMatch(source, /recognizesSignedPlanePhysicalReleaseReadinessPlan/u);
  assert.doesNotMatch(source, /resolveAndVerifyPlanePhysicalGateEvidence\s*\(/u);
  assert.doesNotMatch(source, /assertVerifiedPlanePhysicalGateEvidence\s*\(/u);
});

test("release routes a revocation during production recheck to conformance failure", {
  concurrency: false,
}, (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  const gatePath = require.resolve("../mcp/lib/plane-physical-gate-evidence.js");
  const releasePath = require.resolve("../mcp/lib/plane-physical-release-readiness.js");
  const gateModule = require(gatePath);
  const gateCacheEntry = require.cache[gatePath];
  const original = gateModule.assertVerifiedPlanePhysicalGateEvidenceBatch;
  gateCacheEntry.exports = Object.freeze({
    ...gateModule,
    assertVerifiedPlanePhysicalGateEvidenceBatch(batch, runtime, entries) {
      gateModule.revokePlanePhysicalGateEvidenceSigner(runtime, {
        evidence_class: "review",
        reason_digest: digest("injected-mid-qualification-revocation"),
      });
      return original(batch, runtime, entries);
    },
  });
  delete require.cache[releasePath];
  let verdict;
  try {
    verdict = require(releasePath).evaluateSignedPlanePhysicalReleaseReadiness(f.input);
  } finally {
    gateCacheEntry.exports = gateModule;
    delete require.cache[releasePath];
  }
  assert.ok(hasBlocker(verdict, "evidence_resolution_failed", {
    node_id: "PH-X8",
    gate_kind: "engineering",
  }));
  assert.ok(hasBlocker(verdict, "evidence_resolution_failed", {
    node_id: "PH-X8",
    gate_kind: "review",
  }));
  assert.equal(verdict.conformance_ready, false);
  assert.equal(verdict.physical_production_ready, false);
  assert.equal(verdict.evidence_batch_projection_sha256, null);
});

test("release rejects an injected post-batch mutation before receipt commit", {
  concurrency: false,
}, (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  const gatePath = require.resolve("../mcp/lib/plane-physical-gate-evidence.js");
  const releasePath = require.resolve("../mcp/lib/plane-physical-release-readiness.js");
  const gateModule = require(gatePath);
  const gateCacheEntry = require.cache[gatePath];
  const originalConformance = gateModule.assertConformancePlanePhysicalGateEvidenceBatch;
  let conformanceCalls = 0;
  gateCacheEntry.exports = Object.freeze({
    ...gateModule,
    assertConformancePlanePhysicalGateEvidenceBatch(...args) {
      conformanceCalls += 1;
      const batch = originalConformance(...args);
      if (conformanceCalls === 2) {
        gateModule.revokePlanePhysicalGateEvidenceSigner(args[1], {
          evidence_class: "review",
          reason_digest: digest("injected-post-batch-pre-receipt-revocation"),
        });
      }
      return batch;
    },
  });
  delete require.cache[releasePath];
  let dynamicModule;
  let verdict;
  try {
    dynamicModule = require(releasePath);
    verdict = dynamicModule.evaluateSignedPlanePhysicalReleaseReadiness(f.input);
  } finally {
    gateCacheEntry.exports = gateModule;
    delete require.cache[releasePath];
  }
  assert.equal(conformanceCalls, 2);
  assert.ok(hasBlocker(verdict, "evidence_resolution_failed", {
    node_id: "PH-X8",
    gate_kind: "engineering",
  }));
  assert.ok(hasBlocker(verdict, "evidence_resolution_failed", {
    node_id: "PH-X8",
    gate_kind: "review",
  }));
  assert.equal(verdict.conformance_ready, false);
  assert.equal(verdict.physical_production_ready, false);
  assert.equal(verdict.evidence_batch_projection_sha256, null);
  assert.equal(verdict.conformance_snapshot_ref, null);
  assert.equal(fs.readdirSync(path.join(f.root, "release-snapshot-receipts")).length, 0);
  assert.throws(
    () => dynamicModule.assertCurrentSignedPlanePhysicalReleaseReadiness(verdict, f.runtime),
    /privately branded/u,
  );
});

test("release cache substitution cannot mint semantics and stale snapshots fail currentness", {
  concurrency: false,
}, (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  const gatePath = require.resolve("../mcp/lib/plane-physical-gate-evidence.js");
  const releasePath = require.resolve("../mcp/lib/plane-physical-release-readiness.js");
  const gateModule = require(gatePath);
  const gateCacheEntry = require.cache[gatePath];
  let forgedCommitCalls = 0;
  let forgedCurrentCalls = 0;
  const forgedReady = Object.freeze({
    conformance_ready: true,
    physical_production_ready: true,
    authoritative_release_action: true,
    verdict: "ready",
  });
  gateCacheEntry.exports = Object.freeze({
    ...gateModule,
    commitPlanePhysicalGateEvidenceReleaseSnapshotReceipt() {
      forgedCommitCalls += 1;
      return forgedReady;
    },
    assertCurrentPlanePhysicalGateEvidenceReleaseSnapshotReceipt() {
      forgedCurrentCalls += 1;
      return forgedReady;
    },
    commitPlanePhysicalGateEvidenceReleaseDecision() {
      forgedCommitCalls += 1;
      return forgedReady;
    },
    assertCurrentPlanePhysicalGateEvidenceReleaseDecision() {
      forgedCurrentCalls += 1;
      return forgedReady;
    },
    assertPlanePhysicalGateEvidenceReleaseFinalizationToken: () => true,
    consumePlanePhysicalGateEvidenceReleaseFinalizationToken: () => true,
  });
  let dynamicModule;
  delete require.cache[releasePath];
  let first;
  let second;
  try {
    dynamicModule = require(releasePath);
    assert.ok(Object.isFrozen(dynamicModule));
    assert.equal(dynamicModule.prepareSignedPlanePhysicalReleaseReadinessCommit, undefined);
    assert.equal(dynamicModule.finalizeSignedPlanePhysicalReleaseReadinessCommit, undefined);
    first = dynamicModule.evaluateSignedPlanePhysicalReleaseReadiness(f.input);
    assert.equal(first.physical_production_ready, false);
    assert.equal(first.authoritative_release_action, false);
    assert.equal(first.currentness_assertion_required, true);
    assert.equal(dynamicModule.assertCurrentSignedPlanePhysicalReleaseReadiness(
      first,
      f.runtime,
    ), first);
    assert.throws(
      () => dynamicModule.assertCurrentSignedPlanePhysicalReleaseReadiness(
        Object.freeze(structuredClone(first)),
        f.runtime,
      ),
      /privately branded/u,
    );
    // A genuinely different evaluation (re-issued evidence) supersedes the
    // first receipt, so the stale prior projection fails currentness.
    second = dynamicModule.evaluateSignedPlanePhysicalReleaseReadiness(
      reissuedInput(f, "ph-x8-engineering-superseded", "ph-x8-review-superseded"),
    );
    assert.equal(dynamicModule.assertCurrentSignedPlanePhysicalReleaseReadiness(
      second,
      f.runtime,
    ), second);
    assert.throws(
      () => dynamicModule.assertCurrentSignedPlanePhysicalReleaseReadiness(first, f.runtime),
      /generation is no longer current/u,
    );
  } finally {
    gateCacheEntry.exports = gateModule;
    delete require.cache[releasePath];
  }
  assert.equal(forgedCommitCalls, 0);
  assert.equal(forgedCurrentCalls, 0);
  assert.equal(first.release_snapshot_receipt_sequence, "1");
  assert.equal(second.release_snapshot_receipt_sequence, "2");
  assert.equal(
    fs.readdirSync(path.join(f.root, "release-snapshot-receipts")).length,
    2,
  );
});

test("release recovers a durable receipt append whose acknowledgement is lost", {
  concurrency: false,
}, (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  const originalOpen = fs.openSync;
  const originalFsync = fs.fsyncSync;
  let receiptOpened = false;
  let injected = false;
  fs.openSync = (file, ...args) => {
    const descriptor = originalOpen(file, ...args);
    if (typeof file === "string"
        && path.basename(path.dirname(file)) === "release-snapshot-receipts"
        && file.endsWith(".json")) {
      receiptOpened = true;
    }
    return descriptor;
  };
  fs.fsyncSync = (descriptor) => {
    const result = originalFsync(descriptor);
    if (!injected && receiptOpened) {
      injected = true;
      throw new Error("injected receipt fsync acknowledgement loss");
    }
    return result;
  };
  let ambiguous;
  try {
    ambiguous = evaluateSignedPlanePhysicalReleaseReadiness(f.input);
  } finally {
    fs.openSync = originalOpen;
    fs.fsyncSync = originalFsync;
  }
  assert.equal(injected, true);
  assert.equal(ambiguous.conformance_snapshot_ref, null);
  assert.equal(ambiguous.conformance_ready, false);
  assert.throws(
    () => assertCurrentSignedPlanePhysicalReleaseReadiness(ambiguous, f.runtime),
    /privately branded/u,
  );
  assert.equal(fs.readdirSync(path.join(f.root, "release-snapshot-receipts")).length, 1);

  const recovered = evaluateSignedPlanePhysicalReleaseReadiness(f.input);
  // The lost-ack receipt was written durably before the acknowledgement failed,
  // so recovery rehydrates that head (sequence 1) rather than publishing a
  // duplicate sequence 2; the receipt directory still holds exactly one file.
  assert.equal(recovered.release_snapshot_receipt_sequence, "1");
  assert.equal(recovered.release_snapshot_receipt_previous_sha256, null);
  assert.equal(fs.readdirSync(path.join(f.root, "release-snapshot-receipts")).length, 1);
  assert.equal(assertCurrentSignedPlanePhysicalReleaseReadiness(
    recovered,
    f.runtime,
  ), recovered);
});

// ---- structural conformance diagnostics (folded from the former standalone
// readiness module; these exercise the shared graph engine the CI release-check
// consumes) ----

function structuralEvaluate(overrides = {}) {
  return evaluatePlanePhysicalReleaseReadiness({
    nodes_document: clone(nodesDocument),
    hyperedges_document: clone(hyperedgesDocument),
    ...overrides,
  });
}

function structuralHasBlocker(verdict, code, dimensions = {}) {
  return verdict.blockers.some((blocker) => blocker.code === code
    && Object.entries(dimensions).every(([field, value]) => blocker[field] === value));
}

test("structural readiness produces one deterministic production-false verdict over the reviewed graph", () => {
  const first = structuralEvaluate();
  const second = structuralEvaluate();
  assert.equal(first.node_contract_registry_sha256,
    PLANE_PHYSICAL_REVIEWED_NODE_CONTRACT_REGISTRY_SHA256);
  assert.equal(first.hyperedge_registry_sha256,
    PLANE_PHYSICAL_REVIEWED_HYPEREDGE_REGISTRY_SHA256);
  assert.equal(planePhysicalNodeContractRegistryDigest(nodesDocument),
    nodesDocument.node_contract_registry_sha256);
  assert.equal(planePhysicalHyperedgeRegistryDigest(hyperedgesDocument),
    hyperedgesDocument.hyperedge_registry_sha256);
  assert.equal(first.release_node_contract_sha256, planePhysicalNodeContractDigest(
    nodesDocument.nodes.find((node) => node.id === "PH-X8"),
  ));
  assert.equal(first.predecessor_count, 47);
  assert.equal(first.node_count, 48);
  assert.equal(first.production_nonwaivable_hil_count, 22);
  assert.equal(first.qualification_check_count,
    PLANE_PHYSICAL_RELEASE_QUALIFICATION_CHECK_REGISTRY.length);
  assert.equal(first.physical_production_ready, false);
  assert.equal(first.conformance_ready, false);
  assert.equal(first.verdict, "blocked");
  assert.equal(first.verdict_digest, second.verdict_digest);
  const packagedSnapshot = assertPackagedPlanePhysicalReleaseSnapshot();
  assert.equal(
    compilePlanePhysicalReleaseSnapshot(nodesDocument, hyperedgesDocument).snapshot_sha256,
    packagedSnapshot.snapshot_sha256,
  );
  assert.equal(packagedSnapshot, PLANE_PHYSICAL_PACKAGED_RELEASE_SNAPSHOT);
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.blockers), true);
  assert.ok(structuralHasBlocker(first, "release_validator_not_production_qualified"));
  assert.ok(structuralHasBlocker(first, "qualification_evidence_missing", {
    check_id: "canonical_package_sanitization",
  }));
  assert.ok(structuralHasBlocker(first, "release_predecessor_not_done", { node_id: "PH-C10" }));
  const packagedVerdict = evaluatePackagedPlanePhysicalReleaseReadiness();
  assert.equal(packagedVerdict.registry_source, "packaged_reviewed_projection");
  assert.equal(packagedVerdict.physical_production_ready, false);
  assert.deepEqual(packagedVerdict.blocker_counts, first.blocker_counts);
});

test("structural readiness cannot retain a verdict binding under reviewed node/hyperedge drift", () => {
  const nodes = clone(nodesDocument);
  nodes.nodes.find((node) => node.id === "PH-X8").engineering_gate += " drift";
  const nodeDrift = structuralEvaluate({ nodes_document: nodes });
  assert.ok(structuralHasBlocker(nodeDrift, "node_contract_registry_digest_mismatch"));
  assert.ok(structuralHasBlocker(nodeDrift, "reviewed_node_contract_registry_drift"));
  assert.notEqual(nodeDrift.node_contract_registry_sha256,
    PLANE_PHYSICAL_REVIEWED_NODE_CONTRACT_REGISTRY_SHA256);

  const hyperedges = clone(hyperedgesDocument);
  hyperedges.hyperedges.find((edge) => edge.id === "PH-H40").predecessors.pop();
  const edgeDrift = structuralEvaluate({ hyperedges_document: hyperedges });
  assert.ok(structuralHasBlocker(edgeDrift, "hyperedge_registry_digest_mismatch"));
  assert.ok(structuralHasBlocker(edgeDrift, "reviewed_hyperedge_registry_drift"));
  assert.ok(structuralHasBlocker(edgeDrift, "predecessor_projection_mismatch", { node_id: "PH-X8" }));
  assert.notEqual(edgeDrift.verdict_digest, nodeDrift.verdict_digest);
});

test("structural readiness keeps missing or waived production-nonwaivable HIL release-blocking", () => {
  assert.ok(PLANE_PHYSICAL_PRODUCTION_NONWAIVABLE_HIL_NODE_IDS.includes("PH-X8"));
  const waived = clone(nodesDocument);
  waived.gate_tracking["PH-X8"].hil_state = "waived";
  waived.gate_tracking["PH-X8"].hil_waiver_ref = `bob-waiver:v1:sha256:${"a".repeat(64)}`;
  const waivedVerdict = structuralEvaluate({ nodes_document: waived });
  assert.ok(structuralHasBlocker(waivedVerdict, "production_nonwaivable_hil_waived", {
    node_id: "PH-X8",
  }));
  assert.ok(structuralHasBlocker(waivedVerdict, "hil_gate_not_passed", { node_id: "PH-X8" }));
  assert.equal(waivedVerdict.physical_production_ready, false);

  const missing = clone(nodesDocument);
  missing.gate_tracking["PH-X8"].hil_state = "passed";
  missing.gate_tracking["PH-X8"].hil_waiver_ref = null;
  missing.gate_tracking["PH-X8"].hil_evidence_refs = [];
  const missingVerdict = structuralEvaluate({ nodes_document: missing });
  assert.ok(structuralHasBlocker(missingVerdict, "hil_evidence_missing", { node_id: "PH-X8" }));
  assert.equal(missingVerdict.physical_production_ready, false);
});

test("structural readiness fails closed on Proxy, accessor, and unknown-field inputs", () => {
  const base = {
    nodes_document: clone(nodesDocument),
    hyperedges_document: clone(hyperedgesDocument),
  };
  assert.throws(
    () => evaluatePlanePhysicalReleaseReadiness(new Proxy(base, {})),
    /non-Proxy object/,
  );
  const accessor = { hyperedges_document: clone(hyperedgesDocument) };
  Object.defineProperty(accessor, "nodes_document", {
    enumerable: true,
    get() { throw new Error("getter executed"); },
  });
  assert.throws(
    () => evaluatePlanePhysicalReleaseReadiness(accessor),
    /enumerable data property/,
  );
  assert.throws(
    () => evaluatePlanePhysicalReleaseReadiness({ ...base, bypass_hil: true }),
    /unknown field: bypass_hil/,
  );
  assert.throws(
    () => structuralEvaluate({ nodes_document: new Proxy(clone(nodesDocument), {}) }),
    /non-Proxy JSON data/,
  );
});

test("release flag and environment parsing is fail-closed and cannot be negated", () => {
  assert.deepEqual(parsePhysicalProductionRequirement([], undefined), {
    requested: false, valid: true, source: "none",
  });
  assert.equal(parsePhysicalProductionRequirement([], "true").requested, true);
  assert.equal(parsePhysicalProductionRequirement([], "required").requested, true);
  assert.equal(parsePhysicalProductionRequirement(["--physical-production"], "false").requested,
    true);
  assert.deepEqual(parsePhysicalProductionRequirement([], "yes"), {
    requested: true, valid: false, source: "invalid-env",
  });
});

test("release-check rejects both CLI and environment physical-production claims", () => {
  const script = path.join(ROOT, "scripts", "release-check.js");
  const cli = spawnSync(process.execPath, [script, "--physical-production"], {
    cwd: ROOT,
    env: { ...process.env, HACKER_BOB_PHYSICAL_PRODUCTION: "false" },
    encoding: "utf8",
  });
  assert.notEqual(cli.status, 0);
  assert.match(`${cli.stdout}\n${cli.stderr}`, /physical_production_ready:false/);
  assert.match(`${cli.stdout}\n${cli.stderr}`, /physical-production release gate is blocked/);

  const environment = spawnSync(process.execPath, [script], {
    cwd: ROOT,
    env: { ...process.env, HACKER_BOB_PHYSICAL_PRODUCTION: "true" },
    encoding: "utf8",
  });
  assert.notEqual(environment.status, 0);
  assert.match(`${environment.stdout}\n${environment.stderr}`, /physical_production_ready:false/);
  assert.match(`${environment.stdout}\n${environment.stderr}`, /physical-production release gate is blocked/);
});

test("release contract and validator ship in package and installed-runtime manifests", () => {
  for (const relativePath of [
    "mcp/lib/plane-physical-gate-evidence.js",
    "mcp/lib/plane-physical-release-contracts.js",
    "mcp/lib/plane-physical-release-readiness.js",
    "mcp/lib/plane-physical-release-snapshot.js",
  ]) {
    assert.ok(expectedCanonicalFiles(ROOT).includes(relativePath));
    assert.ok(canonicalInstalledRuntimeFiles(ROOT).includes(relativePath));
  }
});

test("extracted npm package runs release-check without excluded Plane-PH documents", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-ph-x8-packed-release-"));
  const npmCache = path.join(tempRoot, "npm-cache");
  try {
    const packed = spawnSync("npm", [
      "pack",
      "--json",
      "--pack-destination",
      tempRoot,
      "--cache",
      npmCache,
    ], { cwd: ROOT, encoding: "utf8" });
    assert.equal(packed.status, 0, packed.stderr || packed.stdout);
    const packResult = JSON.parse(packed.stdout)[0];
    const tarball = path.join(tempRoot, packResult.filename);
    const extracted = spawnSync("tar", ["-xzf", tarball, "-C", tempRoot], {
      encoding: "utf8",
    });
    assert.equal(extracted.status, 0, extracted.stderr);
    const packageRoot = path.join(tempRoot, "package");
    assert.equal(fs.existsSync(path.join(packageRoot, "docs", "plane-physical")), false);
    assert.equal(fs.existsSync(path.join(packageRoot, "scripts", "check-plane-physical.js")), false);
    const environment = { ...process.env };
    delete environment.HACKER_BOB_PHYSICAL_PRODUCTION;
    const diagnostic = spawnSync(
      process.execPath,
      [path.join(packageRoot, "scripts", "release-check.js")],
      { cwd: packageRoot, env: environment, encoding: "utf8" },
    );
    assert.equal(diagnostic.status, 0, `${diagnostic.stdout}\n${diagnostic.stderr}`);
    const output = `${diagnostic.stdout}\n${diagnostic.stderr}`;
    assert.match(output, /installed_package_diagnostic:true/);
    assert.match(output, /compiled release snapshot/);
    assert.match(output, /physical_production_ready:false/);
    assert.doesNotMatch(output, /ENOENT|only partially present|validation could not run/);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});
