"use strict";

// Cycle C.3 invariant: buildClaimFreeze materializes ClaimCluster rows from
// CandidateClaim grouping signals (surface_id, auth_profile_ref, subject_id,
// attack_class + surface family). The freeze payload references the resulting
// clusters by cluster_id, and a second freeze over the same claim set is a
// no-op — same cluster_id values, same cluster_hash values, no duplicate rows
// in claim-clusters.jsonl.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  appendCandidateClaim,
} = require("../mcp/lib/claims.js");
const {
  readClaimClusters,
} = require("../mcp/lib/claim-clusters.js");
const {
  buildClaimFreeze,
  readCurrentClaimFreeze,
} = require("../mcp/lib/claim-freeze.js");
const {
  correlateClaims,
} = require("../mcp/lib/claim-correlator.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-claim-cluster-compute-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function appendSimpleClaim(domain, { title, surfaceId, subjectId, authProfile, attackClass, createdAt }) {
  const claimInput = {
    target_domain: domain,
    title,
    summary: `${title} summary`,
    severity: "high",
    status: "candidate",
    created_at: createdAt,
    surface_ids: [surfaceId],
    evidence_refs: [{
      kind: "finding",
      artifact_path: "findings.jsonl",
      finding_id: `f-${title}`,
      content_hash: "0".repeat(64),
    }],
  };
  const payload = {};
  if (subjectId) payload.subject_id = subjectId;
  if (authProfile) payload.auth_profile_ref = authProfile;
  if (attackClass) payload.attack_class = attackClass;
  if (Object.keys(payload).length > 0) claimInput.payload = payload;
  return appendCandidateClaim(claimInput);
}

test("two claims sharing surface_id + subject_id produce a shared cluster per signal", () => {
  withTempHome(() => {
    const domain = "cluster-compute.example.com";
    const claimA = appendSimpleClaim(domain, {
      title: "Claim A",
      surfaceId: "surface-billing-profile",
      subjectId: "user-42",
      authProfile: "attacker-1",
      attackClass: "CWE-639",
      createdAt: "2026-05-27T01:00:00.000Z",
    });
    const claimB = appendSimpleClaim(domain, {
      title: "Claim B",
      surfaceId: "surface-billing-profile",
      subjectId: "user-42",
      authProfile: "attacker-2",
      attackClass: "CWE-639",
      createdAt: "2026-05-27T01:05:00.000Z",
    });

    const freeze = buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-27T01:10:00.000Z"),
    });

    const clusters = readClaimClusters(domain);
    // surface_id shared → 1 cluster, subject_id shared → 1 cluster,
    // attack_class+surface_family shared → 1 cluster. auth_profile_ref
    // differs → no cluster from that signal.
    assert.equal(clusters.length, 3, "expected 3 shared clusters");
    const expectedClaimIds = [claimA.claim_id, claimB.claim_id].sort();
    for (const cluster of clusters) {
      assert.deepEqual(cluster.claim_ids, expectedClaimIds, `cluster ${cluster.cluster_id} must group both claims`);
      assert.equal(typeof cluster.cluster_key, "string");
      assert.equal(cluster.cluster_key.length, 64, "cluster_key must be a sha256 hex digest");
      assert.equal(typeof cluster.cluster_hash, "string");
      assert.equal(cluster.cluster_hash.length, 64);
    }

    const signalKinds = clusters.map((c) => c.payload.signal_kind).sort();
    assert.deepEqual(
      signalKinds,
      ["attack_class_surface_family", "subject_id", "surface_id"],
      "the three shared signals must each yield a cluster",
    );

    // freeze references every cluster
    assert.equal(freeze.cluster_count, 3);
    assert.ok(Array.isArray(freeze.cluster_ids), "freeze must carry cluster_ids[]");
    assert.equal(freeze.cluster_ids.length, 3);
    const persistedClusterIds = clusters.map((c) => c.cluster_id).sort();
    assert.deepEqual(freeze.cluster_ids.slice().sort(), persistedClusterIds);
  });
});

test("distinct claims with no shared signal yield no shared clusters", () => {
  withTempHome(() => {
    const domain = "cluster-compute-distinct.example.com";
    appendSimpleClaim(domain, {
      title: "Claim alpha",
      surfaceId: "surface-alpha-one",
      subjectId: "subject-alpha",
      authProfile: "auth-alpha",
      attackClass: "CWE-100",
      createdAt: "2026-05-27T01:00:00.000Z",
    });
    appendSimpleClaim(domain, {
      title: "Claim beta",
      surfaceId: "surface-beta-two",
      subjectId: "subject-beta",
      authProfile: "auth-beta",
      attackClass: "CWE-200",
      createdAt: "2026-05-27T01:05:00.000Z",
    });

    const freeze = buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-27T01:10:00.000Z"),
    });

    const clusters = readClaimClusters(domain);
    assert.equal(clusters.length, 0, "claims with no shared signal must not cluster");
    assert.equal(freeze.cluster_count, 0);
    assert.deepEqual(freeze.cluster_ids, []);
  });
});

test("re-running buildClaimFreeze is idempotent — same cluster_ids, same cluster_hashes, no duplicate rows", () => {
  withTempHome(() => {
    const domain = "cluster-compute-idem.example.com";
    appendSimpleClaim(domain, {
      title: "Claim 1",
      surfaceId: "surface-admin-users",
      subjectId: "tenant-x",
      authProfile: "operator-a",
      attackClass: "CWE-285",
      createdAt: "2026-05-27T02:00:00.000Z",
    });
    appendSimpleClaim(domain, {
      title: "Claim 2",
      surfaceId: "surface-admin-users",
      subjectId: "tenant-x",
      authProfile: "operator-a",
      attackClass: "CWE-285",
      createdAt: "2026-05-27T02:05:00.000Z",
    });

    const firstFreeze = buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-27T02:10:00.000Z"),
    });
    const firstClusters = readClaimClusters(domain);

    const secondFreeze = buildClaimFreeze(domain, {
      write: true,
      now: new Date("2026-05-27T02:20:00.000Z"),
    });
    const secondClusters = readClaimClusters(domain);

    assert.equal(firstClusters.length, secondClusters.length, "second freeze must not append duplicate clusters");
    assert.ok(firstClusters.length > 0, "shared signals must produce clusters");
    const firstHashes = firstClusters.map((c) => c.cluster_hash).sort();
    const secondHashes = secondClusters.map((c) => c.cluster_hash).sort();
    assert.deepEqual(secondHashes, firstHashes, "cluster_hash values must be stable across freeze runs");

    const firstIds = firstClusters.map((c) => c.cluster_id).sort();
    const secondIds = secondClusters.map((c) => c.cluster_id).sort();
    assert.deepEqual(secondIds, firstIds, "cluster_id values must be stable across freeze runs");

    assert.deepEqual(secondFreeze.cluster_ids.slice().sort(), firstFreeze.cluster_ids.slice().sort());
    assert.equal(secondFreeze.freeze_hash, firstFreeze.freeze_hash, "freeze_hash must be stable across runs");

    const persisted = readCurrentClaimFreeze(domain);
    assert.equal(persisted.freeze_hash, secondFreeze.freeze_hash);
    assert.deepEqual(persisted.cluster_ids.slice().sort(), secondFreeze.cluster_ids.slice().sort());
  });
});

test("correlateClaims returns deterministic cluster_keys derived from signal payload", () => {
  const domain = "correlator.example.com";
  const claims = [
    {
      claim_id: "CL-alpha",
      target_domain: domain,
      created_at: "2026-05-27T01:00:00.000Z",
      surface_ids: ["surface-payments-charge"],
      payload: { subject_id: "acct-1", attack_class: "CWE-639" },
    },
    {
      claim_id: "CL-beta",
      target_domain: domain,
      created_at: "2026-05-27T01:05:00.000Z",
      surface_ids: ["surface-payments-charge"],
      payload: { subject_id: "acct-1", attack_class: "CWE-639" },
    },
  ];

  const first = correlateClaims(claims);
  const second = correlateClaims(claims);
  assert.equal(first.length, second.length);
  assert.deepEqual(
    first.map((c) => ({ key: c.cluster_key, kind: c.payload.signal_kind, members: c.claim_ids })),
    second.map((c) => ({ key: c.cluster_key, kind: c.payload.signal_kind, members: c.claim_ids })),
  );
  for (const candidate of first) {
    assert.equal(candidate.cluster_key.length, 64, "cluster_key must be a sha256 hex digest");
    assert.deepEqual(candidate.claim_ids, ["CL-alpha", "CL-beta"]);
  }
});
