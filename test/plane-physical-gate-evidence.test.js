"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const childProcess = require("node:child_process");
const { once } = require("node:events");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  PLANE_PHYSICAL_GATE_EVIDENCE_BLOCKERS,
  assertConformancePlanePhysicalGateEvidence,
  assertConformancePlanePhysicalGateEvidenceBatch,
  assertCurrentPlanePhysicalGateEvidenceReleaseSnapshotReceipt,
  assertVerifiedPlanePhysicalGateEvidence,
  assertVerifiedPlanePhysicalGateEvidenceBatch,
  commitPlanePhysicalGateEvidenceReleaseSnapshotReceipt,
  createConformancePlanePhysicalGateEvidenceRuntime,
  createProductionPlanePhysicalGateEvidenceRuntime,
  issuePlanePhysicalGateEvidence,
  planePhysicalReleaseCandidateDigest,
  resolveAndVerifyPlanePhysicalGateEvidence,
  resolveAndVerifyPlanePhysicalGateEvidenceBatch,
  revokePlanePhysicalGateEvidenceSigner,
} = require("../mcp/domains/physical/plane-physical-gate-evidence.js");

const CLASSES = ["engineering", "review", "hil", "qualification"];

function digest(label) {
  return crypto.createHash("sha256").update(label).digest("hex");
}

let atomicStageOwnerSuffixCache = null;

function atomicStageOwnerSuffix() {
  if (atomicStageOwnerSuffixCache != null) return atomicStageOwnerSuffixCache;
  let processStart;
  if (process.platform === "linux") {
    const stat = fs.readFileSync(`/proc/${process.pid}/stat`, "utf8");
    const close = stat.lastIndexOf(")");
    const fields = stat.slice(close + 2).trim().split(/\s+/u);
    processStart = `linux:${fields[19]}`;
  } else {
    const output = childProcess.execFileSync("/bin/ps", [
      "-p",
      String(process.pid),
      "-o",
      "lstart=",
    ], {
      encoding: "utf8",
      env: { LC_ALL: "C", PATH: "/usr/bin:/bin" },
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    processStart = `${process.platform}:${output}`;
  }
  atomicStageOwnerSuffixCache = `${process.pid}.${digest(os.hostname()).slice(0, 16)}`
    + `.${digest(processStart).slice(0, 32)}`;
  return atomicStageOwnerSuffixCache;
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map(
    (field) => `${JSON.stringify(field)}:${canonicalJson(value[field])}`,
  ).join(",")}}`;
}

function digestJson(value) {
  return crypto.createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function signer(evidenceClass, validity = 60_000) {
  const pair = crypto.generateKeyPairSync("ed25519");
  return {
    evidence_class: evidenceClass,
    signer_principal_id: `principal:ph-x8-${evidenceClass}`,
    signer_key_id: `signer-key:ph-x8-${evidenceClass}`,
    signer_epoch: 1,
    private_key_pem: pair.privateKey.export({ type: "pkcs8", format: "pem" }),
    signer_validity_ms: 60_000,
    evidence_validity_ms: validity,
  };
}

function fixture(options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-gate-"));
  fs.chmodSync(root, 0o700);
  const session = digest(`session-${crypto.randomUUID()}`);
  const signers = CLASSES.map((evidenceClass) => signer(
    evidenceClass,
    options.allValidity || (evidenceClass === "engineering" && options.engineeringValidity
      ? options.engineeringValidity : 60_000),
  ));
  if (options.allValidity) {
    for (const definition of signers) definition.signer_validity_ms = options.allValidity;
  }
  const runtimeInput = {
    version: 1,
    root,
    runtime_id: "ph_x8_gate_evidence",
    target_domain: "hotel.example",
    session_nucleus_hash: session,
    trust_root_id: "trust-root:ph-x8",
    trust_root_epoch: 1,
    trust_validity_ms: options.allValidity || 60_000,
    signers,
  };
  const runtime = createConformancePlanePhysicalGateEvidenceRuntime(runtimeInput);
  const candidateInputs = {
    session_nucleus_hash: session,
    source_tree_digest: digest("source-tree"),
    package_digest: digest("package"),
    task_graph_digest: digest("task-graph"),
    release_snapshot_digest: digest("release-snapshot"),
  };
  const bindings = {
    graph_id: "plane-physical-v1",
    node_id: "PH-X8",
    gate_kind: "engineering",
    evidence_class: "engineering",
    ...candidateInputs,
    release_candidate_digest: planePhysicalReleaseCandidateDigest(candidateInputs),
    node_contract_digest: digest("node-contract"),
    gate_contract_digest: digest("engineering-gate-contract"),
    acceptance_digest: digest("engineering-acceptance"),
    result_digest: digest("engineering-result"),
    verdict: "passed",
  };
  return {
    bindings,
    candidateInputs,
    root,
    runtime,
    runtimeInput,
    signers,
    cleanup() { fs.rmSync(root, { recursive: true, force: true }); },
  };
}

function issueEngineeringReviewBatch(f, label = "release-decision") {
  const engineering = issuePlanePhysicalGateEvidence(f.runtime, f.bindings);
  const reviewBindings = {
    ...f.bindings,
    gate_kind: "review",
    evidence_class: "review",
    gate_contract_digest: digest(`${label}-review-gate`),
    acceptance_digest: digest(`${label}-review-acceptance`),
    result_digest: digest(`${label}-review-result`),
  };
  const review = issuePlanePhysicalGateEvidence(f.runtime, reviewBindings);
  const entries = [
    { evidence_ref: engineering.evidence_ref, expected_bindings: f.bindings },
    { evidence_ref: review.evidence_ref, expected_bindings: reviewBindings },
  ];
  return {
    engineering,
    review,
    reviewBindings,
    entries,
    batch: resolveAndVerifyPlanePhysicalGateEvidenceBatch(entries, f.runtime),
  };
}

test("binds the exact candidate/gate acceptance and durable monotonic receipt", (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  assert.equal(f.runtime.production_ready, false);
  assert.deepEqual(f.runtime.production_blockers, PLANE_PHYSICAL_GATE_EVIDENCE_BLOCKERS);
  assert.ok(f.runtime.production_blockers.includes("independent_signer_custody_unavailable"));

  const first = issuePlanePhysicalGateEvidence(f.runtime, f.bindings);
  const second = issuePlanePhysicalGateEvidence(f.runtime, {
    ...f.bindings,
    result_digest: digest("engineering-result-2"),
  });
  assert.equal(first.payload.sequence, "1");
  assert.equal(second.payload.sequence, "2");
  assert.notEqual(first.payload.nonce, second.payload.nonce);
  assert.match(first.evidence_ref, /^bob-evidence:sha256:[a-f0-9]{64}$/u);

  const projection = resolveAndVerifyPlanePhysicalGateEvidence(
    first.evidence_ref,
    f.runtime,
    f.bindings,
  );
  assert.equal(projection.release_candidate_digest, f.bindings.release_candidate_digest);
  assert.equal(projection.package_digest, f.bindings.package_digest);
  assert.equal(projection.task_graph_digest, f.bindings.task_graph_digest);
  assert.equal(projection.release_snapshot_digest, f.bindings.release_snapshot_digest);
  assert.equal(projection.gate_contract_digest, f.bindings.gate_contract_digest);
  assert.equal(projection.acceptance_digest, f.bindings.acceptance_digest);
  assert.equal(projection.receipt_sequence, "1");
  assert.equal(projection.production_ready, false);
  assert.equal(
    assertConformancePlanePhysicalGateEvidence(projection, f.runtime, f.bindings),
    projection,
  );
  assert.throws(
    () => assertVerifiedPlanePhysicalGateEvidence(projection, f.runtime, f.bindings),
    /independent signer custody|conformance-only/u,
  );
  assert.throws(
    () => assertConformancePlanePhysicalGateEvidence(
      structuredClone(projection),
      f.runtime,
      f.bindings,
    ),
    /privately issued/u,
  );
});

test("rejects caller clock/sequence fields and every exact release-binding drift", (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  assert.throws(
    () => issuePlanePhysicalGateEvidence(f.runtime, { ...f.bindings, issued_at: new Date().toISOString() }),
    /fields are not exact/u,
  );
  const document = issuePlanePhysicalGateEvidence(f.runtime, f.bindings);
  for (const field of [
    "graph_id",
    "node_id",
    "release_candidate_digest",
    "package_digest",
    "task_graph_digest",
    "release_snapshot_digest",
    "node_contract_digest",
    "gate_contract_digest",
    "acceptance_digest",
    "result_digest",
    "session_nucleus_hash",
    "source_tree_digest",
    "verdict",
  ]) {
    const drifted = {
      ...f.bindings,
      [field]: field === "verdict"
        ? "failed"
        : ["graph_id", "node_id"].includes(field)
          ? `drift-${field}`
          : digest(`drift-${field}`),
    };
    if ([
      "package_digest",
      "task_graph_digest",
      "release_snapshot_digest",
      "session_nucleus_hash",
      "source_tree_digest",
    ].includes(field)) {
      drifted.release_candidate_digest = planePhysicalReleaseCandidateDigest({
        session_nucleus_hash: drifted.session_nucleus_hash,
        source_tree_digest: drifted.source_tree_digest,
        package_digest: drifted.package_digest,
        task_graph_digest: drifted.task_graph_digest,
        release_snapshot_digest: drifted.release_snapshot_digest,
      });
    }
    assert.throws(
      () => resolveAndVerifyPlanePhysicalGateEvidence(document.evidence_ref, f.runtime, drifted),
      /exact expected release binding|release_candidate_digest|another release session/u,
      field,
    );
  }
  assert.throws(
    () => resolveAndVerifyPlanePhysicalGateEvidence(document.evidence_ref, f.runtime, {
      ...f.bindings,
      gate_kind: "review",
      evidence_class: "review",
    }),
    /exact expected release binding/u,
  );
  assert.throws(
    () => resolveAndVerifyPlanePhysicalGateEvidence(
      `bob-evidence:v1:sha256:${"a".repeat(64)}`,
      f.runtime,
      f.bindings,
    ),
    /must be bob-evidence:sha256:/u,
  );
});

test("repairs derived mirrors but detects transaction rollback and revocation", (t) => {
  const rollback = fixture();
  t.after(() => rollback.cleanup());
  const document = issuePlanePhysicalGateEvidence(rollback.runtime, rollback.bindings);
  const scopeDirectories = fs.readdirSync(path.join(rollback.root, "scopes"));
  const receiptDirectory = path.join(rollback.root, "scopes", scopeDirectories[0]);
  fs.rmSync(path.join(receiptDirectory, fs.readdirSync(receiptDirectory)[0]));
  assert.equal(resolveAndVerifyPlanePhysicalGateEvidence(
    document.evidence_ref,
    rollback.runtime,
    rollback.bindings,
  ).evidence_ref, document.evidence_ref);
  assert.equal(fs.readdirSync(receiptDirectory).filter((name) => name.endsWith(".json")).length, 1);
  const transactionDirectory = path.join(rollback.root, "issue-transactions");
  fs.rmSync(path.join(transactionDirectory, fs.readdirSync(transactionDirectory)[0]));
  assert.throws(
    () => resolveAndVerifyPlanePhysicalGateEvidence(
      document.evidence_ref,
      rollback.runtime,
      rollback.bindings,
    ),
    /transaction.*rolled back|derived mirrors/u,
  );

  const revoked = fixture();
  t.after(() => revoked.cleanup());
  const revocable = issuePlanePhysicalGateEvidence(revoked.runtime, revoked.bindings);
  revokePlanePhysicalGateEvidenceSigner(revoked.runtime, {
    evidence_class: "engineering",
    reason_digest: digest("engineering-key-retired"),
  });
  assert.throws(
    () => resolveAndVerifyPlanePhysicalGateEvidence(
      revocable.evidence_ref,
      revoked.runtime,
      revoked.bindings,
    ),
    /revoked/u,
  );
  assert.throws(
    () => issuePlanePhysicalGateEvidence(revoked.runtime, revoked.bindings),
    /revoked/u,
  );
});

test("expiry and evidence-class issuer separation fail closed", async (t) => {
  const expiring = fixture({ engineeringValidity: 150 });
  t.after(() => expiring.cleanup());
  const document = issuePlanePhysicalGateEvidence(expiring.runtime, expiring.bindings);
  await new Promise((resolve) => setTimeout(resolve, 220));
  assert.throws(
    () => resolveAndVerifyPlanePhysicalGateEvidence(
      document.evidence_ref,
      expiring.runtime,
      expiring.bindings,
    ),
    /expired/u,
  );

  const separated = fixture();
  t.after(() => separated.cleanup());
  assert.throws(
    () => issuePlanePhysicalGateEvidence(separated.runtime, {
      ...separated.bindings,
      evidence_class: "review",
    }),
    /not authorized for gate_kind/u,
  );
  const duplicatePrincipal = separated.signers.map((entry) => ({ ...entry }));
  duplicatePrincipal[1].signer_principal_id = duplicatePrincipal[0].signer_principal_id;
  assert.throws(
    () => createConformancePlanePhysicalGateEvidenceRuntime({
      ...separated.runtimeInput,
      root: (() => {
        const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-gate-bad-"));
        fs.chmodSync(root, 0o700);
        t.after(() => fs.rmSync(root, { recursive: true, force: true }));
        return root;
      })(),
      signers: duplicatePrincipal,
    }),
    /independent principals/u,
  );
  const duplicateMaterial = separated.signers.map((entry) => ({ ...entry }));
  duplicateMaterial[1].private_key_pem = duplicateMaterial[0].private_key_pem;
  const materialRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-gate-key-"));
  fs.chmodSync(materialRoot, 0o700);
  t.after(() => fs.rmSync(materialRoot, { recursive: true, force: true }));
  assert.throws(
    () => createConformancePlanePhysicalGateEvidenceRuntime({
      ...separated.runtimeInput,
      root: materialRoot,
      signers: duplicateMaterial,
    }),
    /independent.*key material/u,
  );
  const symlinkTarget = fs.mkdtempSync(path.join(os.tmpdir(), "bob-gate-link-target-"));
  fs.chmodSync(symlinkTarget, 0o700);
  const symlinkRoot = `${symlinkTarget}-link`;
  fs.symlinkSync(symlinkTarget, symlinkRoot);
  t.after(() => {
    fs.rmSync(symlinkRoot, { force: true });
    fs.rmSync(symlinkTarget, { recursive: true, force: true });
  });
  assert.throws(
    () => createConformancePlanePhysicalGateEvidenceRuntime({
      ...separated.runtimeInput,
      root: symlinkRoot,
    }),
    /symbolic link/u,
  );
  assert.throws(
    () => createProductionPlanePhysicalGateEvidenceRuntime({}),
    /independent_signer_custody_unavailable/u,
  );
});

test("authority validity is re-derived exactly on every cold reopen", (t) => {
  const trustDrift = fixture();
  t.after(() => trustDrift.cleanup());
  const authorityPath = path.join(trustDrift.root, "authority.json");
  const authority = JSON.parse(fs.readFileSync(authorityPath, "utf8"));
  authority.trust_expires_at = new Date(
    Date.parse(authority.trust_expires_at) + 60_000,
  ).toISOString();
  const trustBasis = { ...authority };
  delete trustBasis.authority_digest;
  authority.authority_digest = digestJson(trustBasis);
  fs.writeFileSync(authorityPath, `${JSON.stringify(authority)}\n`);
  assert.throws(
    () => createConformancePlanePhysicalGateEvidenceRuntime(trustDrift.runtimeInput),
    /trust validity window drift/u,
  );

  const signerDrift = fixture();
  t.after(() => signerDrift.cleanup());
  const signerAuthorityPath = path.join(signerDrift.root, "authority.json");
  const signerAuthority = JSON.parse(fs.readFileSync(signerAuthorityPath, "utf8"));
  signerAuthority.signers[0].signer_expires_at = new Date(
    Date.parse(signerAuthority.signers[0].signer_expires_at) + 60_000,
  ).toISOString();
  const signerBasis = { ...signerAuthority };
  delete signerBasis.authority_digest;
  signerAuthority.authority_digest = digestJson(signerBasis);
  fs.writeFileSync(signerAuthorityPath, `${JSON.stringify(signerAuthority)}\n`);
  assert.throws(
    () => createConformancePlanePhysicalGateEvidenceRuntime(signerDrift.runtimeInput),
    /signer validity window drift/u,
  );
});

test("rejects hardlinked authority, key, time, document, receipt, nonce, and revocation files", (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  const document = issuePlanePhysicalGateEvidence(f.runtime, f.bindings);
  revokePlanePhysicalGateEvidenceSigner(f.runtime, {
    evidence_class: "review",
    reason_digest: digest("review-key-retired"),
  });
  let hardlinkIndex = 0;
  const rejectHardlink = (target, operation) => {
    hardlinkIndex += 1;
    const link = path.join(f.root, `.audit-hardlink-${hardlinkIndex}`);
    fs.linkSync(target, link);
    try {
      assert.throws(operation, /custody|signing key custody/u, target);
    } finally {
      fs.unlinkSync(link);
    }
  };
  rejectHardlink(
    path.join(f.root, "authority.json"),
    () => createConformancePlanePhysicalGateEvidenceRuntime(f.runtimeInput),
  );
  rejectHardlink(
    path.join(f.root, "store-signing-key.pem"),
    () => createConformancePlanePhysicalGateEvidenceRuntime(f.runtimeInput),
  );
  const resolve = () => resolveAndVerifyPlanePhysicalGateEvidence(
    document.evidence_ref,
    f.runtime,
    f.bindings,
  );
  const onlyFile = (directory) => path.join(directory, fs.readdirSync(directory)[0]);
  rejectHardlink(onlyFile(path.join(f.root, "trusted-time")), resolve);
  rejectHardlink(onlyFile(path.join(f.root, "documents")), resolve);
  const scope = path.join(f.root, "scopes", fs.readdirSync(path.join(f.root, "scopes"))[0]);
  rejectHardlink(onlyFile(scope), resolve);
  rejectHardlink(onlyFile(path.join(f.root, "nonces")), resolve);
  rejectHardlink(onlyFile(path.join(f.root, "revocations")), resolve);
});

test("cold reopen preserves authority, receipt sequence, readback, and revocation continuity", (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  const first = issuePlanePhysicalGateEvidence(f.runtime, f.bindings);
  const reopened = createConformancePlanePhysicalGateEvidenceRuntime(f.runtimeInput);
  const firstProjection = resolveAndVerifyPlanePhysicalGateEvidence(
    first.evidence_ref,
    reopened,
    f.bindings,
  );
  assert.equal(firstProjection.receipt_sequence, "1");
  const secondBindings = { ...f.bindings, result_digest: digest("reopened-second-result") };
  const second = issuePlanePhysicalGateEvidence(reopened, secondBindings);
  assert.equal(second.payload.sequence, "2");
  revokePlanePhysicalGateEvidenceSigner(reopened, {
    evidence_class: "review",
    reason_digest: digest("review-revoked-before-second-reopen"),
  });

  const reopenedAgain = createConformancePlanePhysicalGateEvidenceRuntime(f.runtimeInput);
  assert.equal(resolveAndVerifyPlanePhysicalGateEvidence(
    first.evidence_ref,
    reopenedAgain,
    f.bindings,
  ).receipt_sequence, "1");
  assert.equal(resolveAndVerifyPlanePhysicalGateEvidence(
    second.evidence_ref,
    reopenedAgain,
    secondBindings,
  ).receipt_sequence, "2");
  assert.throws(
    () => issuePlanePhysicalGateEvidence(reopenedAgain, {
      ...f.bindings,
      gate_kind: "review",
      evidence_class: "review",
      gate_contract_digest: digest("review-gate-contract"),
      acceptance_digest: digest("review-acceptance"),
      result_digest: digest("review-result"),
    }),
    /revoked/u,
  );
});

test("signer enrollment rejects accessor, sparse, adorned, symbol, and Proxy arrays without traps", (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  let trapCalls = 0;
  const accessor = f.signers.map((entry) => ({ ...entry }));
  Object.defineProperty(accessor, "0", {
    enumerable: true,
    configurable: true,
    get() {
      trapCalls += 1;
      return f.signers[0];
    },
  });
  assert.throws(
    () => createConformancePlanePhysicalGateEvidenceRuntime({
      ...f.runtimeInput,
      signers: accessor,
    }),
    /data property/u,
  );
  assert.equal(trapCalls, 0);

  const sparse = f.signers.map((entry) => ({ ...entry }));
  delete sparse[2];
  assert.throws(
    () => createConformancePlanePhysicalGateEvidenceRuntime({
      ...f.runtimeInput,
      signers: sparse,
    }),
    /dense entries/u,
  );
  const adorned = f.signers.map((entry) => ({ ...entry }));
  adorned.extra = "not-allowed";
  assert.throws(
    () => createConformancePlanePhysicalGateEvidenceRuntime({
      ...f.runtimeInput,
      signers: adorned,
    }),
    /dense entries/u,
  );
  const symbol = f.signers.map((entry) => ({ ...entry }));
  symbol[Symbol("hidden")] = "not-allowed";
  assert.throws(
    () => createConformancePlanePhysicalGateEvidenceRuntime({
      ...f.runtimeInput,
      signers: symbol,
    }),
    /symbol fields/u,
  );
  const proxied = new Proxy(f.signers, {
    get(target, property, receiver) {
      trapCalls += 1;
      return Reflect.get(target, property, receiver);
    },
  });
  assert.throws(
    () => createConformancePlanePhysicalGateEvidenceRuntime({
      ...f.runtimeInput,
      signers: proxied,
    }),
    /non-Proxy/u,
  );
  assert.equal(trapCalls, 0);
});

test("atomic batch resolves multiple evidence classes at one collection/revocation/time cut", (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  const engineering = issuePlanePhysicalGateEvidence(f.runtime, f.bindings);
  const reviewBindings = {
    ...f.bindings,
    gate_kind: "review",
    evidence_class: "review",
    gate_contract_digest: digest("review-gate-contract"),
    acceptance_digest: digest("review-acceptance"),
    result_digest: digest("review-result"),
  };
  const review = issuePlanePhysicalGateEvidence(f.runtime, reviewBindings);
  const entries = [
    { evidence_ref: review.evidence_ref, expected_bindings: reviewBindings },
    { evidence_ref: engineering.evidence_ref, expected_bindings: f.bindings },
  ];
  const batch = resolveAndVerifyPlanePhysicalGateEvidenceBatch(entries, f.runtime);
  assert.equal(batch.entry_count, 2);
  assert.equal(batch.entries.length, 2);
  assert.equal(new Set(batch.entries.map((entry) => entry.evidence_class)).size, 2);
  assert.match(batch.common_trusted_time_digest, /^[a-f0-9]{64}$/u);
  assert.match(batch.collection_snapshot_digest, /^[a-f0-9]{64}$/u);
  assert.match(batch.revocation_set_digest, /^[a-f0-9]{64}$/u);
  assert.equal(batch.production_ready, false);
  const current = assertConformancePlanePhysicalGateEvidenceBatch(
    batch,
    f.runtime,
    [...entries].reverse(),
  );
  assert.notEqual(current.common_trusted_time_digest, batch.common_trusted_time_digest);
  assert.equal(current.verified_entry_set_digest, batch.verified_entry_set_digest);
  assert.throws(
    () => assertVerifiedPlanePhysicalGateEvidenceBatch(current, f.runtime, entries),
    /conformance-only|independent signer custody/u,
  );
  assert.throws(
    () => assertConformancePlanePhysicalGateEvidenceBatch(
      structuredClone(batch),
      f.runtime,
      entries,
    ),
    /privately issued/u,
  );
  assert.throws(
    () => resolveAndVerifyPlanePhysicalGateEvidenceBatch(
      [entries[0], entries[0]],
      f.runtime,
    ),
    /duplicate evidence_ref/u,
  );
  assert.throws(
    () => resolveAndVerifyPlanePhysicalGateEvidenceBatch([
      entries[0],
      {
        ...entries[1],
        expected_bindings: {
          ...entries[1].expected_bindings,
          package_digest: digest("another-package"),
          release_candidate_digest: planePhysicalReleaseCandidateDigest({
            session_nucleus_hash: f.bindings.session_nucleus_hash,
            source_tree_digest: f.bindings.source_tree_digest,
            package_digest: digest("another-package"),
            task_graph_digest: f.bindings.task_graph_digest,
            release_snapshot_digest: f.bindings.release_snapshot_digest,
          }),
        },
      },
    ], f.runtime),
    /one exact session and release candidate/u,
  );
});

test("batch current assertion rejects collection or revocation changes as one whole set", (t) => {
  const collection = fixture();
  t.after(() => collection.cleanup());
  const first = issuePlanePhysicalGateEvidence(collection.runtime, collection.bindings);
  const firstEntries = [{ evidence_ref: first.evidence_ref, expected_bindings: collection.bindings }];
  const beforeAppend = resolveAndVerifyPlanePhysicalGateEvidenceBatch(
    firstEntries,
    collection.runtime,
  );
  issuePlanePhysicalGateEvidence(collection.runtime, {
    ...collection.bindings,
    result_digest: digest("later-unrelated-result"),
  });
  assert.throws(
    () => assertConformancePlanePhysicalGateEvidenceBatch(
      beforeAppend,
      collection.runtime,
      firstEntries,
    ),
    /no longer the current atomic set/u,
  );

  const revocation = fixture();
  t.after(() => revocation.cleanup());
  const engineering = issuePlanePhysicalGateEvidence(revocation.runtime, revocation.bindings);
  const reviewBindings = {
    ...revocation.bindings,
    gate_kind: "review",
    evidence_class: "review",
    gate_contract_digest: digest("batch-revocation-review-gate"),
    acceptance_digest: digest("batch-revocation-review-acceptance"),
    result_digest: digest("batch-revocation-review-result"),
  };
  const review = issuePlanePhysicalGateEvidence(revocation.runtime, reviewBindings);
  const entries = [
    { evidence_ref: engineering.evidence_ref, expected_bindings: revocation.bindings },
    { evidence_ref: review.evidence_ref, expected_bindings: reviewBindings },
  ];
  const beforeRevocation = resolveAndVerifyPlanePhysicalGateEvidenceBatch(
    entries,
    revocation.runtime,
  );
  const reason = digest("review-batch-revocation");
  const firstRevocation = revokePlanePhysicalGateEvidenceSigner(revocation.runtime, {
    evidence_class: "review",
    reason_digest: reason,
  });
  assert.equal(revokePlanePhysicalGateEvidenceSigner(revocation.runtime, {
    evidence_class: "review",
    reason_digest: reason,
  }).revocation_digest, firstRevocation.revocation_digest);
  assert.throws(
    () => revokePlanePhysicalGateEvidenceSigner(revocation.runtime, {
      evidence_class: "review",
      reason_digest: digest("conflicting-review-reason"),
    }),
    /conflicting reason_digest/u,
  );
  assert.throws(
    () => assertConformancePlanePhysicalGateEvidenceBatch(
      beforeRevocation,
      revocation.runtime,
      entries,
    ),
    /revoked/u,
  );
});

test("live runtime custody fences every operation after hardlink, chmod, delete, or replacement", (t) => {
  const hardlinked = fixture();
  t.after(() => hardlinked.cleanup());
  const authorityLink = path.join(hardlinked.root, "authority.audit-link");
  fs.linkSync(path.join(hardlinked.root, "authority.json"), authorityLink);
  assert.throws(
    () => issuePlanePhysicalGateEvidence(hardlinked.runtime, hardlinked.bindings),
    /custody|identity/u,
  );
  fs.unlinkSync(authorityLink);

  const rootMode = fixture();
  t.after(() => rootMode.cleanup());
  fs.chmodSync(rootMode.root, 0o755);
  try {
    assert.throws(
      () => revokePlanePhysicalGateEvidenceSigner(rootMode.runtime, {
        evidence_class: "review",
        reason_digest: digest("root-mode-revocation"),
      }),
      /root.*custody|mode/u,
    );
  } finally {
    fs.chmodSync(rootMode.root, 0o700);
  }

  const childMode = fixture();
  t.after(() => childMode.cleanup());
  const childDocument = issuePlanePhysicalGateEvidence(
    childMode.runtime,
    childMode.bindings,
  );
  const documentsDirectory = path.join(childMode.root, "documents");
  fs.chmodSync(documentsDirectory, 0o755);
  try {
    assert.throws(
      () => resolveAndVerifyPlanePhysicalGateEvidence(
        childDocument.evidence_ref,
        childMode.runtime,
        childMode.bindings,
      ),
      /managed directory.*custody|identity/u,
    );
  } finally {
    fs.chmodSync(documentsDirectory, 0o700);
  }

  const deletedAuthority = fixture();
  t.after(() => deletedAuthority.cleanup());
  const deletedMaterial = issueEngineeringReviewBatch(deletedAuthority, "deleted-authority");
  fs.unlinkSync(path.join(deletedAuthority.root, "authority.json"));
  assert.throws(
    () => assertConformancePlanePhysicalGateEvidenceBatch(
      deletedMaterial.batch,
      deletedAuthority.runtime,
      deletedMaterial.entries,
    ),
    /authority.*open failed|custody/u,
  );

  const replacedKey = fixture();
  t.after(() => replacedKey.cleanup());
  const keyPath = path.join(replacedKey.root, "store-signing-key.pem");
  const keyBytes = fs.readFileSync(keyPath);
  fs.renameSync(keyPath, `${keyPath}.replaced`);
  fs.writeFileSync(keyPath, keyBytes, { flag: "wx", mode: 0o400 });
  assert.throws(
    () => issuePlanePhysicalGateEvidence(replacedKey.runtime, replacedKey.bindings),
    /store key.*identity|custody/u,
  );

  const replacedRoot = fixture();
  const originalRoot = `${replacedRoot.root}.original`;
  t.after(() => {
    replacedRoot.cleanup();
    fs.rmSync(originalRoot, { recursive: true, force: true });
  });
  fs.renameSync(replacedRoot.root, originalRoot);
  fs.mkdirSync(replacedRoot.root, { mode: 0o700 });
  assert.throws(
    () => issuePlanePhysicalGateEvidence(replacedRoot.runtime, replacedRoot.bindings),
    /root identity changed|custody/u,
  );
});

test("release snapshot receipt is nonsemantic despite readiness-module cache poison", {
  concurrency: false,
}, (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  const failedBindings = {
    ...f.bindings,
    result_digest: digest("failed-engineering-result"),
    verdict: "failed",
  };
  const failed = issuePlanePhysicalGateEvidence(f.runtime, failedBindings);
  const failedEntries = [{
    evidence_ref: failed.evidence_ref,
    expected_bindings: failedBindings,
  }];
  const failedBatch = resolveAndVerifyPlanePhysicalGateEvidenceBatch(
    failedEntries,
    f.runtime,
  );
  assert.throws(
    () => commitPlanePhysicalGateEvidenceReleaseSnapshotReceipt(
      f.runtime,
      failedBatch,
      failedEntries,
      Object.freeze({ conformance_ready: true }),
    ),
    /runtime, batch, and entries only/u,
  );

  const releasePath = require.resolve(
    "../mcp/domains/physical/plane-physical-release-readiness.js",
  );
  const originalCacheEntry = require.cache[releasePath];
  require.cache[releasePath] = {
    id: releasePath,
    filename: releasePath,
    loaded: true,
    exports: Object.freeze({
      recognizesPlanePhysicalReleaseReadinessPlan: () => true,
      preparePlanePhysicalReleaseReadinessCommit: () => ({
        decision_basis_digest: digest("forged-basis"),
        blocker_set_digest: digestJson([]),
        conformance_ready: true,
        physical_production_ready: true,
        verdict: "ready",
      }),
      finalizePlanePhysicalReleaseReadinessCommit: () => ({
        conformance_ready: true,
        physical_production_ready: true,
        verdict: "ready",
      }),
    }),
  };
  let receipt;
  try {
    receipt = commitPlanePhysicalGateEvidenceReleaseSnapshotReceipt(
      f.runtime,
      failedBatch,
      failedEntries,
    );
  } finally {
    if (originalCacheEntry) require.cache[releasePath] = originalCacheEntry;
    else delete require.cache[releasePath];
  }
  assert.match(receipt.receipt_ref,
    /^gate-release-snapshot-receipt:[a-f0-9]{64}$/u);
  const forbidden = [
    "decision_basis_digest",
    "blocker_set_digest",
    "conformance_ready",
    "physical_production_ready",
    "verdict",
  ];
  for (const field of forbidden) assert.equal(Object.hasOwn(receipt, field), false, field);

  const receiptDirectory = path.join(
    fs.realpathSync(f.root),
    "release-snapshot-receipts",
  );
  const files = fs.readdirSync(receiptDirectory);
  assert.deepEqual(files, ["00000000000000000001.json"]);
  const signedRecord = JSON.parse(fs.readFileSync(path.join(receiptDirectory, files[0]), "utf8"));
  for (const field of forbidden) {
    assert.equal(Object.hasOwn(signedRecord, field), false, `signed ${field}`);
  }
  const gateModule = require("../mcp/domains/physical/plane-physical-gate-evidence.js");
  assert.equal(gateModule.commitPlanePhysicalGateEvidenceReleaseDecision, undefined);
  assert.ok(Object.isFrozen(gateModule));
});

test("receipt publication cleans an injected partial stage and retries at sequence one", {
  concurrency: false,
}, (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  const material = issueEngineeringReviewBatch(f, "partial-receipt-stage");
  const receiptDirectory = path.join(
    fs.realpathSync(f.root),
    "release-snapshot-receipts",
  );
  const originalOpen = fs.openSync;
  const originalWrite = fs.writeSync;
  const receiptStageDescriptors = new Set();
  let injected = false;
  fs.openSync = (file, ...args) => {
    const descriptor = originalOpen(file, ...args);
    if (typeof file === "string" && path.dirname(file) === receiptDirectory
        && file.endsWith(".stage")) receiptStageDescriptors.add(descriptor);
    return descriptor;
  };
  fs.writeSync = (descriptor, buffer, offset, length, position) => {
    if (!injected && receiptStageDescriptors.has(descriptor)) {
      injected = true;
      originalWrite(descriptor, buffer, offset, Math.max(1, Math.floor(length / 2)), position);
      const error = new Error("injected partial receipt stage write");
      error.code = "ENOSPC";
      throw error;
    }
    return originalWrite(descriptor, buffer, offset, length, position);
  };
  try {
    assert.throws(
      () => commitPlanePhysicalGateEvidenceReleaseSnapshotReceipt(
        f.runtime,
        material.batch,
        material.entries,
      ),
      /partial receipt stage|ENOSPC/u,
    );
  } finally {
    fs.openSync = originalOpen;
    fs.writeSync = originalWrite;
  }
  assert.equal(injected, true);
  assert.deepEqual(fs.readdirSync(receiptDirectory), []);
  const receipt = commitPlanePhysicalGateEvidenceReleaseSnapshotReceipt(
    f.runtime,
    material.batch,
    material.entries,
  );
  assert.equal(receipt.receipt_sequence, "1");
});

test("receipt publication ignores inert crash-orphan stages", (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  const material = issueEngineeringReviewBatch(f, "orphan-receipt-stage");
  const receiptDirectory = path.join(f.root, "release-snapshot-receipts");
  const orphanName = `.00000000000000000001.json.${digest("orphan-stage-content")}`
    + `.0600.${atomicStageOwnerSuffix()}.${"a".repeat(32)}.stage`;
  fs.writeFileSync(path.join(receiptDirectory, orphanName), "{partial", {
    flag: "wx",
    mode: 0o600,
  });
  const receipt = commitPlanePhysicalGateEvidenceReleaseSnapshotReceipt(
    f.runtime,
    material.batch,
    material.entries,
  );
  assert.equal(receipt.receipt_sequence, "1");
  assert.ok(fs.existsSync(path.join(receiptDirectory, orphanName)));
  assert.deepEqual(
    fs.readdirSync(receiptDirectory).filter((name) => name.endsWith(".json")),
    ["00000000000000000001.json"],
  );
  assert.equal(assertCurrentPlanePhysicalGateEvidenceReleaseSnapshotReceipt(
    receipt,
    f.runtime,
    { release_candidate_digest: f.bindings.release_candidate_digest },
  ), receipt);
});

test("bounds inert atomic publication stages and fails closed", (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  const material = issueEngineeringReviewBatch(f, "bounded-receipt-stages");
  const receiptDirectory = path.join(f.root, "release-snapshot-receipts");
  for (let index = 0; index < 64; index += 1) {
    const finalName = `${String(index + 1).padStart(20, "0")}.json`;
    const stageName = `.${finalName}.${digest(`bounded-stage-${index}`)}`
      + `.0600.${atomicStageOwnerSuffix()}.${index.toString(16).padStart(32, "0")}.stage`;
    fs.writeFileSync(path.join(receiptDirectory, stageName), "{partial", {
      flag: "wx",
      mode: 0o600,
    });
  }
  assert.throws(
    () => commitPlanePhysicalGateEvidenceReleaseSnapshotReceipt(
      f.runtime,
      material.batch,
      material.entries,
    ),
    /too many atomic publication stages/u,
  );
  assert.deepEqual(
    fs.readdirSync(receiptDirectory).filter((name) => name.endsWith(".json")),
    [],
  );
});

test("receipt publication reconciles lost link acknowledgement without a second generation", {
  concurrency: false,
}, (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  const material = issueEngineeringReviewBatch(f, "receipt-link-ack");
  const receiptDirectory = path.join(
    fs.realpathSync(f.root),
    "release-snapshot-receipts",
  );
  const originalLink = fs.linkSync;
  let injected = false;
  fs.linkSync = (source, destination) => {
    if (!injected && path.dirname(destination) === receiptDirectory
        && destination.endsWith(".json")) {
      originalLink(source, destination);
      injected = true;
      const error = new Error("injected lost receipt link acknowledgement");
      error.code = "EIO";
      throw error;
    }
    return originalLink(source, destination);
  };
  let receipt;
  try {
    receipt = commitPlanePhysicalGateEvidenceReleaseSnapshotReceipt(
      f.runtime,
      material.batch,
      material.entries,
    );
  } finally {
    fs.linkSync = originalLink;
  }
  assert.equal(injected, true);
  assert.equal(receipt.receipt_sequence, "1");
  assert.deepEqual(fs.readdirSync(receiptDirectory), ["00000000000000000001.json"]);
});

test("receipt publication never deletes or overwrites a conflicting torn final", (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  const material = issueEngineeringReviewBatch(f, "receipt-conflict");
  const finalPath = path.join(
    f.root,
    "release-snapshot-receipts",
    "00000000000000000001.json",
  );
  const torn = "{\"torn\":";
  fs.writeFileSync(finalPath, torn, { flag: "wx", mode: 0o600 });
  assert.throws(
    () => commitPlanePhysicalGateEvidenceReleaseSnapshotReceipt(
      f.runtime,
      material.batch,
      material.entries,
    ),
    /not valid JSON|conflict/u,
  );
  assert.equal(fs.readFileSync(finalPath, "utf8"), torn);
});

test("issue transaction recovers faults at commit and every derived-mirror boundary", {
  concurrency: false,
}, () => {
  const cases = ["transaction", "document", "nonce", "receipt"];
  for (const boundary of cases) {
    const f = fixture();
    try {
      const originalLink = fs.linkSync;
      let injected = false;
      const matchesBoundary = (destination) => {
        const parent = path.basename(path.dirname(destination));
        if (boundary === "transaction") return parent === "issue-transactions";
        if (boundary === "document") return parent === "documents";
        if (boundary === "nonce") return parent === "nonces";
        return path.basename(path.dirname(path.dirname(destination))) === "scopes";
      };
      fs.linkSync = (source, destination) => {
        if (!injected && destination.endsWith(".json") && matchesBoundary(destination)) {
          injected = true;
          const error = new Error(`injected ${boundary} publication failure`);
          error.code = "ENOSPC";
          throw error;
        }
        return originalLink(source, destination);
      };
      try {
        assert.throws(
          () => issuePlanePhysicalGateEvidence(f.runtime, f.bindings),
          new RegExp(`injected ${boundary} publication failure`, "u"),
        );
      } finally {
        fs.linkSync = originalLink;
      }
      assert.equal(injected, true, boundary);
      const transactionDirectory = path.join(f.root, "issue-transactions");
      const transactionFiles = fs.readdirSync(transactionDirectory)
        .filter((name) => name.endsWith(".json"));
      if (boundary === "transaction") {
        assert.deepEqual(transactionFiles, [], boundary);
        assert.deepEqual(fs.readdirSync(path.join(f.root, "documents")), [], boundary);
        assert.deepEqual(fs.readdirSync(path.join(f.root, "nonces")), [], boundary);
        const recovered = issuePlanePhysicalGateEvidence(f.runtime, f.bindings);
        assert.equal(recovered.payload.sequence, "1", boundary);
      } else {
        assert.equal(transactionFiles.length, 1, boundary);
        const transaction = JSON.parse(fs.readFileSync(
          path.join(transactionDirectory, transactionFiles[0]),
          "utf8",
        ));
        const recovered = resolveAndVerifyPlanePhysicalGateEvidence(
          transaction.evidence_ref,
          f.runtime,
          f.bindings,
        );
        assert.equal(recovered.evidence_ref, transaction.evidence_ref, boundary);
        assert.equal(fs.readdirSync(path.join(f.root, "documents"))
          .filter((name) => name.endsWith(".json")).length, 1, boundary);
        assert.equal(fs.readdirSync(path.join(f.root, "nonces"))
          .filter((name) => name.endsWith(".json")).length, 1, boundary);
        const scopeDirectories = fs.readdirSync(path.join(f.root, "scopes"));
        assert.equal(scopeDirectories.length, 1, boundary);
        assert.equal(fs.readdirSync(path.join(f.root, "scopes", scopeDirectories[0]))
          .filter((name) => name.endsWith(".json")).length, 1, boundary);
      }
    } finally {
      f.cleanup();
    }
  }
});

test("issue transaction reconciles a lost commit-link acknowledgement", {
  concurrency: false,
}, (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  const originalLink = fs.linkSync;
  let injected = false;
  fs.linkSync = (source, destination) => {
    if (!injected && path.basename(path.dirname(destination)) === "issue-transactions") {
      originalLink(source, destination);
      injected = true;
      const error = new Error("injected lost transaction link acknowledgement");
      error.code = "EIO";
      throw error;
    }
    return originalLink(source, destination);
  };
  let document;
  try {
    document = issuePlanePhysicalGateEvidence(f.runtime, f.bindings);
  } finally {
    fs.linkSync = originalLink;
  }
  assert.equal(injected, true);
  assert.equal(document.payload.sequence, "1");
  assert.equal(fs.readdirSync(path.join(f.root, "issue-transactions"))
    .filter((name) => name.endsWith(".json")).length, 1);
});

test("issue transaction never deletes a conflicting invalid commit final", {
  concurrency: false,
}, (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  const originalLink = fs.linkSync;
  let conflictPath = null;
  fs.linkSync = (source, destination) => {
    if (conflictPath == null
        && path.basename(path.dirname(destination)) === "issue-transactions") {
      conflictPath = destination;
      fs.writeFileSync(destination, "{conflict", { flag: "wx", mode: 0o600 });
      const error = new Error("injected transaction conflict");
      error.code = "EEXIST";
      throw error;
    }
    return originalLink(source, destination);
  };
  try {
    assert.throws(
      () => issuePlanePhysicalGateEvidence(f.runtime, f.bindings),
      /conflicts with immutable durable state/u,
    );
  } finally {
    fs.linkSync = originalLink;
  }
  assert.ok(conflictPath);
  assert.equal(fs.readFileSync(conflictPath, "utf8"), "{conflict");
  assert.throws(
    () => issuePlanePhysicalGateEvidence(f.runtime, f.bindings),
    /not valid JSON/u,
  );
  assert.equal(fs.readFileSync(conflictPath, "utf8"), "{conflict");
});

test("lock refuses a live owner and recovers killed owner and candidate crashes", {
  concurrency: false,
  timeout: 30_000,
}, async (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  const configPath = path.join(f.root, ".lock-child-config.json");
  fs.writeFileSync(configPath, JSON.stringify({
    runtime_input: f.runtimeInput,
    bindings: f.bindings,
  }), { flag: "wx", mode: 0o600 });
  const modulePath = path.join(
    __dirname,
    "../mcp/domains/physical/plane-physical-gate-evidence.js",
  );
  const childSource = String.raw`
    "use strict";
    const fs = require("node:fs");
    const path = require("node:path");
    const [configPath, modulePath, markerPath, mode] = process.argv.slice(1);
    const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
    const gate = require(modulePath);
    const runtime = gate.createConformancePlanePhysicalGateEvidenceRuntime(
      config.runtime_input,
    );
    const canonicalRoot = fs.realpathSync(config.runtime_input.root);
    const hold = () => {
      fs.writeFileSync(markerPath, "held", { flag: "wx", mode: 0o600 });
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20_000);
    };
    if (mode === "held") {
      const originalRead = fs.readdirSync;
      let blocked = false;
      fs.readdirSync = (directory, ...args) => {
        if (!blocked && fs.existsSync(path.join(config.runtime_input.root,
          ".gate-evidence.lock"))) {
          blocked = true;
          hold();
        }
        return originalRead(directory, ...args);
      };
    } else if (mode === "candidate") {
      const originalLink = fs.linkSync;
      let blocked = false;
      fs.linkSync = (source, destination) => {
        if (!blocked && destination === path.join(canonicalRoot,
          ".gate-evidence.lock")) {
          blocked = true;
          hold();
        }
        return originalLink(source, destination);
      };
    } else if (mode === "candidate-publish") {
      const originalLink = fs.linkSync;
      let blocked = false;
      fs.linkSync = (source, destination) => {
        if (!blocked && destination.endsWith(".candidate")
            && path.dirname(destination) === canonicalRoot) {
          originalLink(source, destination);
          blocked = true;
          hold();
        }
        return originalLink(source, destination);
      };
    } else {
      const originalOpen = fs.openSync;
      const originalWrite = fs.writeSync;
      const candidateStageDescriptors = new Set();
      fs.openSync = (file, ...args) => {
        const descriptor = originalOpen(file, ...args);
        const name = typeof file === "string" ? path.basename(file) : "";
        if (typeof file === "string" && path.dirname(file) === canonicalRoot
            && name.startsWith("..gate-evidence.lock.")
            && name.includes(".candidate.") && name.endsWith(".stage")) {
          candidateStageDescriptors.add(descriptor);
        }
        return descriptor;
      };
      fs.writeSync = (descriptor, buffer, offset, length, position) => {
        if (candidateStageDescriptors.has(descriptor)) {
          originalWrite(
            descriptor,
            buffer,
            offset,
            Math.max(1, Math.floor(length / 2)),
            position,
          );
          fs.writeFileSync(markerPath, "partial", { flag: "wx", mode: 0o600 });
          process.kill(process.pid, "SIGKILL");
        }
        return originalWrite(descriptor, buffer, offset, length, position);
      };
    }
    gate.issuePlanePhysicalGateEvidence(runtime, config.bindings);
  `;
  const pause = new Int32Array(new SharedArrayBuffer(4));
  const spawnAndWait = (mode) => {
    const markerPath = path.join(f.root, `.lock-${mode}-${crypto.randomUUID()}.marker`);
    const child = childProcess.spawn(process.execPath, [
      "-e",
      childSource,
      configPath,
      modulePath,
      markerPath,
      mode,
    ], { stdio: "ignore" });
    const exit = once(child, "exit");
    for (let attempt = 0; attempt < 400 && !fs.existsSync(markerPath); attempt += 1) {
      if (child.exitCode != null) break;
      Atomics.wait(pause, 0, 0, 25);
    }
    assert.ok(fs.existsSync(markerPath), `${mode} child reached its crash boundary`);
    return { child, exit, markerPath };
  };

  const held = spawnAndWait("held");
  assert.throws(
    () => issuePlanePhysicalGateEvidence(f.runtime, f.bindings),
    /contended/u,
  );
  held.child.kill("SIGKILL");
  await held.exit;
  const first = issuePlanePhysicalGateEvidence(f.runtime, f.bindings);
  assert.equal(first.payload.sequence, "1");

  const candidate = spawnAndWait("candidate");
  candidate.child.kill("SIGKILL");
  await candidate.exit;
  const second = issuePlanePhysicalGateEvidence(f.runtime, {
    ...f.bindings,
    result_digest: digest("post-candidate-crash"),
  });
  assert.equal(second.payload.sequence, "2");
  assert.deepEqual(
    fs.readdirSync(f.root).filter((name) => name.endsWith(".candidate")),
    [],
  );

  const partialCandidate = spawnAndWait("candidate-write");
  const [, partialSignal] = await partialCandidate.exit;
  assert.equal(partialSignal, "SIGKILL");
  assert.equal(
    fs.readdirSync(f.root).filter((name) => name.endsWith(".stage")).length,
    1,
  );
  const third = issuePlanePhysicalGateEvidence(f.runtime, {
    ...f.bindings,
    result_digest: digest("post-partial-candidate-stage-crash"),
  });
  assert.equal(third.payload.sequence, "3");

  const livePublishedCandidate = spawnAndWait("candidate-publish");
  assert.equal(
    fs.readdirSync(f.root).filter((name) => name.endsWith(".candidate")).length,
    1,
  );
  assert.equal(
    fs.readdirSync(f.root).filter((name) => name.endsWith(".stage")).length,
    1,
  );
  createConformancePlanePhysicalGateEvidenceRuntime(f.runtimeInput);
  assert.equal(
    fs.readdirSync(f.root).filter((name) => name.endsWith(".candidate")).length,
    1,
  );
  assert.equal(
    fs.readdirSync(f.root).filter((name) => name.endsWith(".stage")).length,
    1,
  );
  livePublishedCandidate.child.kill("SIGKILL");
  await livePublishedCandidate.exit;
  const fourth = issuePlanePhysicalGateEvidence(f.runtime, {
    ...f.bindings,
    result_digest: digest("post-live-candidate-stage-crash"),
  });
  assert.equal(fourth.payload.sequence, "4");
  assert.deepEqual(
    fs.readdirSync(f.root).filter(
      (name) => name.endsWith(".candidate") || name.endsWith(".stage"),
    ),
    [],
  );
});

test("bootstrap recovers SIGKILL during staged store-key and authority writes", {
  concurrency: false,
  timeout: 30_000,
}, async (t) => {
  const template = fixture();
  t.after(() => template.cleanup());
  const roots = [];
  t.after(() => {
    for (const root of roots) fs.rmSync(root, { recursive: true, force: true });
  });
  const modulePath = path.join(
    __dirname,
    "../mcp/domains/physical/plane-physical-gate-evidence.js",
  );
  const childSource = String.raw`
    "use strict";
    const fs = require("node:fs");
    const path = require("node:path");
    const [configPath, modulePath, markerPath, target] = process.argv.slice(1);
    const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
    const canonicalRoot = fs.realpathSync(config.root);
    const finalName = target === "key" ? "store-signing-key.pem" : "authority.json";
    const originalOpen = fs.openSync;
    const originalWrite = fs.writeSync;
    const targetDescriptors = new Set();
    fs.openSync = (file, ...args) => {
      const descriptor = originalOpen(file, ...args);
      const name = typeof file === "string" ? path.basename(file) : "";
      if (typeof file === "string" && path.dirname(file) === canonicalRoot
          && name.startsWith("." + finalName + ".") && name.endsWith(".stage")) {
        targetDescriptors.add(descriptor);
      }
      return descriptor;
    };
    fs.writeSync = (descriptor, buffer, offset, length, position) => {
      if (targetDescriptors.has(descriptor)) {
        originalWrite(
          descriptor,
          buffer,
          offset,
          Math.max(1, Math.floor(length / 2)),
          position,
        );
        fs.writeFileSync(markerPath, "partial", { flag: "wx", mode: 0o600 });
        process.kill(process.pid, "SIGKILL");
      }
      return originalWrite(descriptor, buffer, offset, length, position);
    };
    try {
      require(modulePath).createConformancePlanePhysicalGateEvidenceRuntime(config);
    } catch (error) {
      fs.writeFileSync(markerPath + ".error", String(error.stack || error), {
        flag: "wx",
        mode: 0o600,
      });
      process.exitCode = 2;
    }
  `;
  const pause = new Int32Array(new SharedArrayBuffer(4));
  const crashBootstrap = async (runtimeInput, target) => {
    const configPath = path.join(runtimeInput.root, `.bootstrap-${target}.json`);
    const markerPath = path.join(runtimeInput.root, `.bootstrap-${target}.marker`);
    fs.writeFileSync(configPath, JSON.stringify(runtimeInput), { flag: "wx", mode: 0o600 });
    const child = childProcess.spawn(process.execPath, [
      "-e",
      childSource,
      configPath,
      modulePath,
      markerPath,
      target,
    ], { stdio: "ignore" });
    const exit = once(child, "exit");
    const errorPath = `${markerPath}.error`;
    for (let attempt = 0; attempt < 400
      && !fs.existsSync(markerPath) && !fs.existsSync(errorPath); attempt += 1) {
      Atomics.wait(pause, 0, 0, 25);
    }
    assert.equal(
      fs.existsSync(markerPath),
      true,
      fs.existsSync(errorPath) ? fs.readFileSync(errorPath, "utf8") : `${target} crash boundary`,
    );
    const [, signal] = await exit;
    assert.equal(signal, "SIGKILL");
  };
  const freshInput = (label) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), `bob-gate-${label}-`));
    fs.chmodSync(root, 0o700);
    roots.push(root);
    return {
      ...template.runtimeInput,
      root,
      session_nucleus_hash: digest(`${label}-${crypto.randomUUID()}`),
    };
  };

  const keyInput = freshInput("key-crash");
  await crashBootstrap(keyInput, "key");
  assert.equal(fs.existsSync(path.join(keyInput.root, "store-signing-key.pem")), false);
  assert.equal(fs.readdirSync(keyInput.root).filter((name) => name.endsWith(".stage")).length, 1);
  const keyRecovered = createConformancePlanePhysicalGateEvidenceRuntime(keyInput);
  assert.equal(keyRecovered.runtime_id, keyInput.runtime_id);
  assert.equal(fs.statSync(path.join(keyInput.root, "store-signing-key.pem")).mode & 0o777, 0o400);

  const authorityInput = freshInput("authority-crash");
  createConformancePlanePhysicalGateEvidenceRuntime(authorityInput);
  fs.rmSync(path.join(authorityInput.root, "authority.json"));
  await crashBootstrap(authorityInput, "authority");
  assert.equal(fs.existsSync(path.join(authorityInput.root, "authority.json")), false);
  assert.equal(
    fs.readdirSync(authorityInput.root).filter((name) => name.endsWith(".stage")).length,
    1,
  );
  const authorityRecovered = createConformancePlanePhysicalGateEvidenceRuntime(
    authorityInput,
  );
  assert.equal(authorityRecovered.runtime_id, authorityInput.runtime_id);
  assert.equal(fs.statSync(path.join(authorityInput.root, "authority.json")).mode & 0o777, 0o600);

  const invalidKeyInput = freshInput("invalid-key-final");
  const invalidKeyPath = path.join(invalidKeyInput.root, "store-signing-key.pem");
  fs.writeFileSync(invalidKeyPath, "torn-key", { flag: "wx", mode: 0o400 });
  assert.throws(
    () => createConformancePlanePhysicalGateEvidenceRuntime(invalidKeyInput),
    /valid Ed25519 private key/u,
  );
  assert.equal(fs.readFileSync(invalidKeyPath, "utf8"), "torn-key");

  const invalidAuthorityInput = freshInput("invalid-authority-final");
  createConformancePlanePhysicalGateEvidenceRuntime(invalidAuthorityInput);
  const invalidAuthorityPath = path.join(invalidAuthorityInput.root, "authority.json");
  fs.rmSync(invalidAuthorityPath);
  fs.writeFileSync(invalidAuthorityPath, "{torn-authority", {
    flag: "wx",
    mode: 0o600,
  });
  assert.throws(
    () => createConformancePlanePhysicalGateEvidenceRuntime(invalidAuthorityInput),
    /not valid JSON/u,
  );
  assert.equal(fs.readFileSync(invalidAuthorityPath, "utf8"), "{torn-authority");
});

test("revocation history rejects a valid longer branch with a rewritten observed prefix", (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  const document = issuePlanePhysicalGateEvidence(f.runtime, f.bindings);
  revokePlanePhysicalGateEvidenceSigner(f.runtime, {
    evidence_class: "engineering",
    reason_digest: digest("observed-engineering-revocation"),
  });
  const revocationDirectory = path.join(f.root, "revocations");
  for (const name of fs.readdirSync(revocationDirectory)) {
    fs.rmSync(path.join(revocationDirectory, name));
  }
  const forkRuntime = createConformancePlanePhysicalGateEvidenceRuntime(f.runtimeInput);
  revokePlanePhysicalGateEvidenceSigner(forkRuntime, {
    evidence_class: "review",
    reason_digest: digest("fork-review-revocation"),
  });
  revokePlanePhysicalGateEvidenceSigner(forkRuntime, {
    evidence_class: "hil",
    reason_digest: digest("fork-hil-revocation"),
  });
  assert.throws(
    () => resolveAndVerifyPlanePhysicalGateEvidence(
      document.evidence_ref,
      f.runtime,
      f.bindings,
    ),
    /revocation history rolled back or forked/u,
  );
});

test("trusted-time history rejects a valid longer branch with a rewritten observed prefix", (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  const document = issuePlanePhysicalGateEvidence(f.runtime, f.bindings);
  const timeDirectory = path.join(f.root, "trusted-time");
  for (const name of fs.readdirSync(timeDirectory)) fs.rmSync(path.join(timeDirectory, name));
  const forkRuntime = createConformancePlanePhysicalGateEvidenceRuntime(f.runtimeInput);
  for (const evidenceClass of ["review", "hil", "qualification", "engineering"]) {
    revokePlanePhysicalGateEvidenceSigner(forkRuntime, {
      evidence_class: evidenceClass,
      reason_digest: digest(`fork-time-${evidenceClass}`),
    });
  }
  assert.throws(
    () => resolveAndVerifyPlanePhysicalGateEvidence(
      document.evidence_ref,
      f.runtime,
      f.bindings,
    ),
    /trusted-time history rolled back or forked/u,
  );
});

test("scope mirrors reject a longer prefix rewrite against committed transactions", (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  const first = issuePlanePhysicalGateEvidence(f.runtime, f.bindings);
  issuePlanePhysicalGateEvidence(f.runtime, {
    ...f.bindings,
    result_digest: digest("scope-prefix-second"),
  });
  const scopeName = fs.readdirSync(path.join(f.root, "scopes"))[0];
  const scopeDirectory = path.join(f.root, "scopes", scopeName);
  const secondPath = path.join(scopeDirectory, "00000000000000000002.json");
  const replacement = fs.readFileSync(secondPath);
  fs.rmSync(path.join(scopeDirectory, "00000000000000000001.json"));
  fs.writeFileSync(
    path.join(scopeDirectory, "00000000000000000001.json"),
    replacement,
    { flag: "wx", mode: 0o600 },
  );
  fs.writeFileSync(
    path.join(scopeDirectory, "00000000000000000003.json"),
    replacement,
    { flag: "wx", mode: 0o600 },
  );
  assert.throws(
    () => resolveAndVerifyPlanePhysicalGateEvidence(
      first.evidence_ref,
      f.runtime,
      f.bindings,
    ),
    /conflicts with immutable durable state|fork|drift/u,
  );
});

test("release-receipt history rejects a valid longer branch with a rewritten prefix", (t) => {
  const f = fixture();
  t.after(() => f.cleanup());
  const material = issueEngineeringReviewBatch(f, "receipt-prefix-fork");
  const observed = commitPlanePhysicalGateEvidenceReleaseSnapshotReceipt(
    f.runtime,
    material.batch,
    material.entries,
  );
  const receiptDirectory = path.join(f.root, "release-snapshot-receipts");
  fs.rmSync(path.join(receiptDirectory, "00000000000000000001.json"));
  const forkRuntime = createConformancePlanePhysicalGateEvidenceRuntime(f.runtimeInput);
  const forkBatch = resolveAndVerifyPlanePhysicalGateEvidenceBatch(
    material.entries,
    forkRuntime,
  );
  commitPlanePhysicalGateEvidenceReleaseSnapshotReceipt(
    forkRuntime,
    forkBatch,
    material.entries,
  );
  const forkBatchTwo = resolveAndVerifyPlanePhysicalGateEvidenceBatch(
    material.entries,
    forkRuntime,
  );
  commitPlanePhysicalGateEvidenceReleaseSnapshotReceipt(
    forkRuntime,
    forkBatchTwo,
    material.entries,
  );
  assert.throws(
    () => assertCurrentPlanePhysicalGateEvidenceReleaseSnapshotReceipt(
      observed,
      f.runtime,
      { release_candidate_digest: f.bindings.release_candidate_digest },
    ),
    /release snapshot receipt history rolled back or forked/u,
  );
});
