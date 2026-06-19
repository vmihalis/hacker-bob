"use strict";

// Cycle C.4 invariant: the VERIFY snapshot is built from the immutable
// claim-freeze.json payload, not from a live re-scan of findings.jsonl or any
// other plane-Frontier ledger. Mutating findings.jsonl after the freeze does
// not change the verification target set. Tampering with the freeze's
// claim_freeze_hash fails the integrity check.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  appendCandidateClaim,
} = require("../mcp/lib/claims.js");
const {
  buildClaimFreeze,
  readCurrentClaimFreeze,
} = require("../mcp/lib/claim-freeze.js");
const {
  buildVerificationSnapshot,
  assertFreshVerificationSnapshot,
  findingIdSetFromSnapshot,
  claimIdSetFromSnapshot,
} = require("../mcp/lib/verification-snapshot-contracts.js");
const {
  findingIdSetForVerificationContext,
  claimIdSetFromFindingIds,
} = require("../mcp/lib/verification-finding-id-adapter.js");
const {
  claimFreezePath,
  claimsJsonlPath,
  sessionDir,
  verificationSnapshotPath,
} = require("../mcp/lib/paths.js");
const {
  writeFileAtomic,
} = require("../mcp/lib/storage.js");
const recordFindingTool = require("../mcp/lib/tools/record-candidate-claim.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-verification-from-frozen-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    resetMaterializationDebounce();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function recordFindingViaTool(domain, overrides = {}) {
  const args = {
    target_domain: domain,
    title: overrides.title || "IDOR on billing profile",
    severity: overrides.severity || "high",
    cwe: overrides.cwe || "CWE-639",
    endpoint: overrides.endpoint || "https://victim.example/api/billing/1",
    description: overrides.description || "Tenant boundary allows cross-account view",
    proof_of_concept: overrides.poc || "GET /api/billing/1 returns another tenant payload",
    response_evidence: overrides.response_evidence || "Cross-tenant billing payload",
    impact: overrides.impact || "Cross-tenant billing disclosure",
    validated: true,
    auth_profile: overrides.auth_profile || "attacker",
    surface_id: overrides.surface_id || "surface:billing-profile",
    // Cross-tenant billing IDOR: network-reachable, low-privilege attacker
    // tenant, confidentiality impact.
    cvss_inputs: overrides.cvss_inputs || {
      attack_vector: "network",
      privileges_required: "low",
      confidentiality: "high",
    },
  };
  return JSON.parse(recordFindingTool.handler(args));
}

function appendClaimsJsonlDirect(domain, id, overrides = {}) {
  // Append a CandidateClaim that the dual-write shim would not have produced,
  // so the test can mutate the live claim ledger post-freeze and confirm the
  // snapshot remains anchored to the frozen payload.
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  return appendCandidateClaim({
    target_domain: domain,
    title: overrides.title || `Post-freeze claim ${id}`,
    summary: overrides.description || "Mutated after the freeze",
    severity: overrides.severity || "high",
    status: "candidate",
    surface_ids: [overrides.surface_id || "surface:post-freeze"],
    impact: overrides.impact || "Should not change verification results",
    evidence_refs: [{
      kind: "finding",
      finding_id: id,
      content_hash: "0".repeat(64),
    }],
    payload: {
      attack_class: overrides.cwe || "CWE-639",
      finding: {
        id,
        target_domain: domain,
        title: overrides.title || `Post-freeze claim ${id}`,
        severity: overrides.severity || "high",
        cwe: overrides.cwe || "CWE-639",
        endpoint: overrides.endpoint || `https://victim.example/api/post-freeze/${id}`,
        description: overrides.description || "Mutated after the freeze",
        proof_of_concept: overrides.poc || "POST /api/post-freeze inserted after freeze",
        response_evidence: overrides.response_evidence || "Post-freeze evidence",
        impact: overrides.impact || "Should not change verification results",
        validated: true,
        surface_id: overrides.surface_id || "surface:post-freeze",
        auth_profile: overrides.auth_profile || "attacker",
      },
    },
  });
}

test("buildVerificationSnapshot pulls claim and cluster ids straight from the frozen payload", () => {
  withTempHome(() => {
    const domain = "frozen-payload.example.com";

    // Seed three findings via the record-finding tool. The dual-write shim
    // mirrors each Finding into a CandidateClaim in claims.jsonl.
    const findingIds = [];
    for (let i = 1; i <= 3; i += 1) {
      const response = recordFindingViaTool(domain, {
        title: `Pre-freeze finding ${i}`,
        endpoint: `https://victim.example/api/billing/${i}`,
        poc: `GET /api/billing/${i} returns another tenant payload`,
      });
      assert.equal(response.recorded, true);
      findingIds.push(response.finding_id);
    }

    const freeze = buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-27T01:00:00.000Z"),
    });
    assert.equal(freeze.claim_count, 3, "freeze must capture all three CandidateClaims");

    const snapshot = buildVerificationSnapshot(domain, {
      attemptId: "attempt-01",
      createdAt: "2026-05-27T01:00:05.000Z",
    });

    // Snapshot is anchored to the frozen payload.
    assert.equal(snapshot.claim_freeze_id, freeze.freeze_id);
    assert.equal(snapshot.claim_freeze_hash, freeze.freeze_hash);
    assert.equal(snapshot.input_hashes.claim_freeze, freeze.freeze_hash);

    // Claim membership matches the freeze's claim set, not the live findings
    // ledger (those would happen to match here because the dual-write shim
    // was used, but the later test proves they diverge after mutation).
    assert.equal(snapshot.claim_ids.length, 3);
    assert.deepEqual(
      snapshot.claim_ids.slice().sort(),
      freeze.claims.map((claim) => claim.claim_id).sort(),
    );

    // The legacy finding_ids projection points back at the same findings.
    assert.deepEqual(snapshot.finding_ids.slice().sort(), findingIds.slice().sort());
  });
});

test("mutating claims.jsonl AFTER the freeze leaves the verification snapshot unchanged", () => {
  withTempHome(() => {
    const domain = "frozen-stability.example.com";
    recordFindingViaTool(domain, { endpoint: "https://victim.example/api/billing/1" });
    recordFindingViaTool(domain, { endpoint: "https://victim.example/api/billing/2" });

    const freeze = buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-27T01:00:00.000Z"),
    });
    assert.equal(freeze.claim_count, 2);

    const beforeSnapshot = buildVerificationSnapshot(domain, {
      attemptId: "attempt-stable",
      createdAt: "2026-05-27T01:00:05.000Z",
    });

    // Append a CandidateClaim directly to claims.jsonl AFTER the freeze. A
    // pre-C.4 snapshot would have observed the new claim and rebuilt itself
    // accordingly; D.2's frozen payload keeps it out.
    appendClaimsJsonlDirect(domain, "F-99");

    const afterSnapshot = buildVerificationSnapshot(domain, {
      attemptId: "attempt-stable-2",
      createdAt: "2026-05-27T01:00:10.000Z",
    });

    assert.deepEqual(afterSnapshot.claim_ids, beforeSnapshot.claim_ids);
    assert.deepEqual(afterSnapshot.finding_ids, beforeSnapshot.finding_ids);
    assert.equal(afterSnapshot.claim_freeze_id, beforeSnapshot.claim_freeze_id);
    assert.equal(afterSnapshot.claim_freeze_hash, beforeSnapshot.claim_freeze_hash);
    assert.equal(afterSnapshot.input_hashes.claim_freeze, beforeSnapshot.input_hashes.claim_freeze);
    assert.ok(!afterSnapshot.finding_ids.includes("F-99"));
  });
});

test("a snapshot is invalid if claim_freeze_id is missing or the freeze hash has been tampered with", () => {
  withTempHome(() => {
    const domain = "frozen-integrity.example.com";
    recordFindingViaTool(domain);

    // Auto-freeze runs when buildVerificationSnapshot is called.
    const snapshot = buildVerificationSnapshot(domain, {
      attemptId: "attempt-integrity",
      createdAt: "2026-05-27T01:00:05.000Z",
    });
    writeFileAtomic(verificationSnapshotPath(domain), `${JSON.stringify(snapshot, null, 2)}\n`);

    const state = {
      verification_schema_version: 2,
      verification_attempt_id: "attempt-integrity",
      verification_snapshot_hash: snapshot.snapshot_hash,
    };

    // Baseline: fresh snapshot validates.
    const fresh = assertFreshVerificationSnapshot(domain, state);
    assert.equal(fresh.claim_freeze_id, snapshot.claim_freeze_id);

    // Remove claim_freeze_id from the snapshot artifact — invalid.
    const stripped = { ...snapshot };
    delete stripped.claim_freeze_id;
    writeFileAtomic(verificationSnapshotPath(domain), `${JSON.stringify(stripped, null, 2)}\n`);
    assert.throws(
      () => assertFreshVerificationSnapshot(domain, state),
      /claim_freeze_id|hash mismatch/,
      "missing claim_freeze_id must fail validation",
    );

    // Restore the snapshot and tamper with the freeze hash on disk instead.
    writeFileAtomic(verificationSnapshotPath(domain), `${JSON.stringify(snapshot, null, 2)}\n`);
    const freezePath = claimFreezePath(domain);
    const freezeDoc = JSON.parse(fs.readFileSync(freezePath, "utf8"));
    const tampered = { ...freezeDoc, freeze_hash: "f".repeat(64) };
    writeFileAtomic(freezePath, `${JSON.stringify(tampered, null, 2)}\n`);
    assert.throws(
      () => assertFreshVerificationSnapshot(domain, state),
      /VERIFY input changed after snapshot/,
      "tampering with freeze_hash must fail the integrity check",
    );

    // Replacing the freeze artifact with a different freeze_id also fails.
    const replaced = { ...freezeDoc, freeze_id: "CF-replaced-id" };
    writeFileAtomic(freezePath, `${JSON.stringify(replaced, null, 2)}\n`);
    assert.throws(
      () => assertFreshVerificationSnapshot(domain, state),
      /VERIFY input changed after snapshot/,
      "replacing the freeze with a different freeze_id must fail the integrity check",
    );
  });
});

test("findingIdSetFromSnapshot and claimIdSetFromSnapshot project from the frozen payload", () => {
  withTempHome(() => {
    const domain = "projection.example.com";
    recordFindingViaTool(domain, { endpoint: "https://victim.example/api/billing/1" });
    recordFindingViaTool(domain, { endpoint: "https://victim.example/api/billing/2" });
    buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-27T01:00:00.000Z"),
    });
    const snapshot = buildVerificationSnapshot(domain, {
      attemptId: "attempt-projection",
      createdAt: "2026-05-27T01:00:05.000Z",
    });
    const findingIds = findingIdSetFromSnapshot(snapshot);
    assert.equal(findingIds.size, 2);
    const claimIds = claimIdSetFromSnapshot(snapshot);
    assert.equal(claimIds.size, 2);
  });
});

test("verification adapter resolves finding_ids via the frozen payload, falling back to the live claim ledger when no freeze exists", () => {
  withTempHome(() => {
    const domain = "legacy-adapter.example.com";

    // No freeze yet: adapter falls back to the live claim ledger by projecting
    // finding evidence refs off the recorded CandidateClaims.
    appendClaimsJsonlDirect(domain, "F-1");
    const liveProjection = findingIdSetForVerificationContext({ domain });
    assert.deepEqual([...liveProjection].sort(), ["F-1"]);

    // Once a freeze is taken, the adapter resolves the same set via the
    // frozen claim payload instead of the live ledger.
    recordFindingViaTool(domain, { endpoint: "https://victim.example/api/billing/post-shim" });
    buildClaimFreeze(domain, { write: true, now: new Date("2026-05-27T01:00:00.000Z") });
    const snapshot = buildVerificationSnapshot(domain, {
      attemptId: "attempt-adapter",
      createdAt: "2026-05-27T01:00:05.000Z",
    });
    const fromSnapshot = findingIdSetForVerificationContext({ domain, snapshot });
    assert.ok(fromSnapshot.size > 0);
    const fromArray = findingIdSetForVerificationContext({
      domain,
      finding_ids: [...fromSnapshot],
    });
    assert.deepEqual([...fromArray].sort(), [...fromSnapshot].sort());

    // The reverse projection still works: feed a finding_id array in and
    // recover the matching claim_id set via claim-projections.js.
    const claimIds = claimIdSetFromFindingIds(domain, [...fromSnapshot]);
    assert.ok(claimIds.size > 0);
  });
});

test("buildVerificationSnapshot auto-freezes when no operator-issued freeze exists yet", () => {
  // LEGACY: removed in Plane D — entering VERIFY without a prior freeze in
  // the dual-write window should auto-build one from the current claims so
  // the snapshot still anchors to an immutable ClaimFreeze artifact.
  withTempHome(() => {
    const domain = "auto-freeze.example.com";
    recordFindingViaTool(domain);
    // No buildClaimFreeze call before buildVerificationSnapshot.
    const snapshot = buildVerificationSnapshot(domain, {
      attemptId: "attempt-auto",
      createdAt: "2026-05-27T01:00:05.000Z",
    });
    assert.ok(snapshot.claim_freeze_id);
    assert.equal(snapshot.claim_freeze_hash.length, 64);
    const freeze = readCurrentClaimFreeze(domain);
    assert.ok(freeze);
    assert.equal(freeze.freeze_id, snapshot.claim_freeze_id);
  });
});
