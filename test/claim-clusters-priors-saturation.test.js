"use strict";

// TODO: add this entry to test/mcp-test-manifest.json during Phase 8 resolution
// (the manifest is currently in UU conflict state for the PR #61 merge).

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const {
  mergePriorClaimMatches,
  uniquePriorClaimKey,
} = require("../mcp/lib/claim-clusters.js");

test("mergePriorClaimMatches keeps same-target anchor when cross-target window is saturated", () => {
  // Simulates the saturation scenario from the legacy findings-index test:
  // the cross-target scanner caps at N most-recent domains (e.g. 200), so when
  // 205 unrelated cross-target priors crowd the corpus, the current target's
  // anchor claim can fall outside the cross-target scan window. The merge
  // helper must still surface the same-target match because the same-target
  // query path is sourced separately.
  const fingerprint = `bobpriorsaturated${crypto.randomBytes(6).toString("hex")}`;
  const domain = `zz-priors-anchor-${crypto.randomBytes(4).toString("hex")}.local`;

  const anchorMatch = {
    claim_id: "CC-anchor",
    target_domain: domain,
    title: `${fingerprint} reentrancy in current target`,
    attack_class: "reentrancy",
    similarity: 0.42,
  };

  const sameTargetMatches = [anchorMatch];

  // Cross-target scanner returned 200 results that do NOT include the anchor
  // domain (the saturation case: anchor domain was outside the scan window).
  const crossTargetMatches = [];
  for (let i = 0; i < 200; i++) {
    crossTargetMatches.push({
      claim_id: `CC-other-${String(i).padStart(3, "0")}`,
      target_domain: `aa-priors-saturated-${String(i).padStart(3, "0")}.local`,
      title: `${fingerprint} reentrancy in other target ${i}`,
      attack_class: "reentrancy",
      // Higher similarity than the anchor — without the same-target guard,
      // the anchor would be ranked below all of these and clipped by limit.
      similarity: 0.9,
    });
  }

  const merged = mergePriorClaimMatches(domain, sameTargetMatches, crossTargetMatches, 5);

  assert.ok(merged.length > 0, "merge must return at least the anchor match");
  assert.equal(merged[0].claim_id, "CC-anchor", "same-target anchor must rank first");
  assert.equal(merged[0].target_domain, domain);
  const sameTargetCount = merged.filter((m) => m.target_domain === domain).length;
  assert.ok(sameTargetCount >= 1, "at least one same-target match must remain in the slice");
});

test("mergePriorClaimMatches dedupes by (target_domain, claim_id)", () => {
  const domain = "example.local";
  const duplicate = {
    claim_id: "CC-1",
    target_domain: domain,
    similarity: 0.5,
  };
  const merged = mergePriorClaimMatches(
    domain,
    [duplicate],
    [duplicate, { claim_id: "CC-2", target_domain: domain, similarity: 0.4 }],
    10,
  );
  const ids = merged.map((m) => m.claim_id);
  assert.deepEqual(ids.sort(), ["CC-1", "CC-2"]);
});

test("mergePriorClaimMatches sorts cross-target results by descending similarity within same-target tier", () => {
  const domain = "example.local";
  const sameTargetMatches = [
    { claim_id: "CC-self-low", target_domain: domain, similarity: 0.1 },
  ];
  const crossTargetMatches = [
    { claim_id: "CC-other-hi", target_domain: "other-a.local", similarity: 0.9 },
    { claim_id: "CC-other-lo", target_domain: "other-b.local", similarity: 0.2 },
  ];
  const merged = mergePriorClaimMatches(domain, sameTargetMatches, crossTargetMatches, 10);
  assert.equal(merged[0].claim_id, "CC-self-low", "same-target outranks higher-similarity cross-target");
  assert.equal(merged[1].claim_id, "CC-other-hi");
  assert.equal(merged[2].claim_id, "CC-other-lo");
});

test("mergePriorClaimMatches tolerates missing similarity and falls back to claim_id ordering", () => {
  const domain = "example.local";
  const merged = mergePriorClaimMatches(
    domain,
    [],
    [
      { claim_id: "CC-b", target_domain: "x.local" },
      { claim_id: "CC-a", target_domain: "x.local" },
    ],
    10,
  );
  assert.deepEqual(merged.map((m) => m.claim_id), ["CC-a", "CC-b"]);
});

test("mergePriorClaimMatches honors legacy finding_id key alongside claim_id", () => {
  const domain = "example.local";
  const k1 = uniquePriorClaimKey({ target_domain: domain, claim_id: "X-1" });
  const k2 = uniquePriorClaimKey({ target_domain: domain, finding_id: "X-1" });
  assert.equal(k1, k2, "claim_id and legacy finding_id collapse to the same key");
});

test("mergePriorClaimMatches ignores non-object entries", () => {
  const domain = "example.local";
  const merged = mergePriorClaimMatches(
    domain,
    [null, undefined, "string-entry", { claim_id: "CC-ok", target_domain: domain, similarity: 0.5 }],
    [42, { claim_id: "CC-cross", target_domain: "other.local", similarity: 0.5 }],
    10,
  );
  assert.deepEqual(merged.map((m) => m.claim_id), ["CC-ok", "CC-cross"]);
});
