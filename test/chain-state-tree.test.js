"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const {
  appendChainNode,
  queryChainTree,
  frontier,
  ancestry,
  ROOT_PARENT_STATE_HASH,
  VERDICT_VALUES,
} = require("../mcp/lib/chain-state-tree.js");

function uniqueDomain(prefix = "bob-chain-tree-test") {
  const suffix = crypto.randomBytes(4).toString("hex");
  return `${prefix}-${suffix}.local`;
}

function cleanupDomain(domain) {
  const dir = path.join(os.homedir(), "hacker-bob-sessions", domain);
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
}

function genericAction(kind = "http_request") {
  return { kind, target: "/api/users", payload: { method: "GET" } };
}

test("appendChainNode at the root computes node_hash + state_hash and reports new_node true", () => {
  const domain = uniqueDomain();
  try {
    const result = appendChainNode({
      target_domain: domain,
      action: genericAction(),
      observed: { status: 200 },
    });
    assert.equal(result.parent_state_hash, ROOT_PARENT_STATE_HASH);
    assert.equal(result.new_node, true);
    assert.ok(result.node_hash.length === 64);
    assert.ok(result.state_hash.length === 64);
    assert.equal(result.verdict, "pending");
  } finally {
    cleanupDomain(domain);
  }
});

test("identical (parent, action) hashes to the same node_hash; re-appending upserts", () => {
  const domain = uniqueDomain();
  try {
    const first = appendChainNode({ target_domain: domain, action: genericAction(), observed: { status: 200 } });
    const second = appendChainNode({ target_domain: domain, action: genericAction(), observed: { status: 200 } });
    assert.equal(first.node_hash, second.node_hash);
    assert.equal(second.new_node, false);
    assert.equal(second.total_in_tree, 1);
  } finally {
    cleanupDomain(domain);
  }
});

test("different observed under same (parent, action) keeps node_hash but updates state_hash", () => {
  const domain = uniqueDomain();
  try {
    const first = appendChainNode({ target_domain: domain, action: genericAction(), observed: { status: 200 } });
    const second = appendChainNode({ target_domain: domain, action: genericAction(), observed: { status: 500 } });
    assert.equal(first.node_hash, second.node_hash);
    assert.notEqual(first.state_hash, second.state_hash);
  } finally {
    cleanupDomain(domain);
  }
});

test("branching: two distinct actions from the same parent yield distinct node_hashes", () => {
  const domain = uniqueDomain();
  try {
    const first = appendChainNode({ target_domain: domain, action: genericAction("http_request"), observed: { status: 200 } });
    const second = appendChainNode({ target_domain: domain, action: { kind: "evm_call", target: "0xabc" }, observed: { status: 200 } });
    assert.notEqual(first.node_hash, second.node_hash);
    assert.equal(first.parent_state_hash, second.parent_state_hash);
  } finally {
    cleanupDomain(domain);
  }
});

test("child pinned to parent state_hash records the parent linkage", () => {
  const domain = uniqueDomain();
  try {
    const root = appendChainNode({ target_domain: domain, action: genericAction(), observed: { status: 200 } });
    const child = appendChainNode({
      target_domain: domain,
      parent_state_hash: root.state_hash,
      action: { kind: "follow_redirect", target: "/api/v2/users" },
      observed: { status: 200 },
    });
    assert.equal(child.parent_state_hash, root.state_hash);
    assert.notEqual(child.node_hash, root.node_hash);
  } finally {
    cleanupDomain(domain);
  }
});

test("queryChainTree filters by parent_state_hash, verdict, and action.kind", () => {
  const domain = uniqueDomain();
  try {
    const root = appendChainNode({ target_domain: domain, action: genericAction("http_request"), observed: { status: 200 } });
    appendChainNode({
      target_domain: domain,
      parent_state_hash: root.state_hash,
      action: { kind: "follow_redirect", target: "/v2" },
      observed: { status: 200 },
      verdict: "success",
    });
    appendChainNode({
      target_domain: domain,
      parent_state_hash: root.state_hash,
      action: { kind: "fuzz_param", target: "id" },
      observed: { status: 500 },
      verdict: "failure",
    });
    const childrenOfRoot = queryChainTree({ target_domain: domain, parent_state_hash: root.state_hash });
    assert.equal(childrenOfRoot.total_matched, 2);
    const successOnly = queryChainTree({ target_domain: domain, verdict: "success" });
    assert.equal(successOnly.total_matched, 1);
    const fuzzOnly = queryChainTree({ target_domain: domain, action_kind: "fuzz_param" });
    assert.equal(fuzzOnly.total_matched, 1);
  } finally {
    cleanupDomain(domain);
  }
});

test("frontier returns only leaf nodes (no children, default excludes pruned)", () => {
  const domain = uniqueDomain();
  try {
    const root = appendChainNode({ target_domain: domain, action: genericAction("step1"), observed: { status: 200 } });
    const mid = appendChainNode({
      target_domain: domain,
      parent_state_hash: root.state_hash,
      action: { kind: "step2" },
      observed: { status: 200 },
    });
    appendChainNode({
      target_domain: domain,
      parent_state_hash: mid.state_hash,
      action: { kind: "step3a" },
      observed: { status: 200 },
    });
    appendChainNode({
      target_domain: domain,
      parent_state_hash: mid.state_hash,
      action: { kind: "step3b_pruned" },
      observed: { status: 500 },
      verdict: "pruned",
    });
    const live = frontier({ target_domain: domain });
    const liveKinds = live.leaves.map((n) => n.action.kind).sort();
    assert.deepEqual(liveKinds, ["step3a"]);
    const withPruned = frontier({ target_domain: domain, include_pruned: true });
    const allKinds = withPruned.leaves.map((n) => n.action.kind).sort();
    assert.deepEqual(allKinds, ["step3a", "step3b_pruned"]);
  } finally {
    cleanupDomain(domain);
  }
});

test("ancestry walks parent_state_hash links from a state_hash back to the root", () => {
  const domain = uniqueDomain();
  try {
    const root = appendChainNode({ target_domain: domain, action: genericAction("step1"), observed: { status: 200 } });
    const mid = appendChainNode({
      target_domain: domain,
      parent_state_hash: root.state_hash,
      action: { kind: "step2" },
      observed: { status: 200 },
    });
    const leaf = appendChainNode({
      target_domain: domain,
      parent_state_hash: mid.state_hash,
      action: { kind: "step3" },
      observed: { status: 200 },
    });
    const lineage = ancestry({ target_domain: domain, state_hash: leaf.state_hash });
    assert.equal(lineage.lineage.length, 3);
    assert.equal(lineage.lineage[0].action.kind, "step3");
    assert.equal(lineage.lineage[1].action.kind, "step2");
    assert.equal(lineage.lineage[2].action.kind, "step1");
    assert.equal(lineage.reached_root, true);
  } finally {
    cleanupDomain(domain);
  }
});

test("verdict normalization rejects unknown values and defaults to pending when null", () => {
  const domain = uniqueDomain();
  try {
    const noverdict = appendChainNode({ target_domain: domain, action: genericAction(), observed: { status: 200 } });
    assert.equal(noverdict.verdict, "pending");
    assert.throws(
      () => appendChainNode({ target_domain: domain, action: genericAction("step2"), observed: {}, verdict: "bogus" }),
      /verdict/,
    );
  } finally {
    cleanupDomain(domain);
  }
});

test("VERDICT_VALUES enumerates the recognized verdict states", () => {
  for (const verdict of ["pending", "success", "failure", "pruned", "branched"]) {
    assert.ok(VERDICT_VALUES.includes(verdict));
  }
});

test("appendChainNode rejects unsafe target_domain and malformed action", () => {
  assert.throws(
    () => appendChainNode({ target_domain: "../escape", action: genericAction() }),
    /target_domain/,
  );
  assert.throws(
    () => appendChainNode({ target_domain: "ok.example", action: { kind: "" } }),
    /action.kind/,
  );
  assert.throws(
    () => appendChainNode({ target_domain: "ok.example", action: null }),
    /action/,
  );
});

test("on-disk chain-tree.jsonl is sorted by node_hash for replay determinism", () => {
  const domain = uniqueDomain();
  try {
    appendChainNode({ target_domain: domain, action: { kind: "z_first" }, observed: { status: 200 } });
    appendChainNode({ target_domain: domain, action: { kind: "a_second" }, observed: { status: 200 } });
    appendChainNode({ target_domain: domain, action: { kind: "m_third" }, observed: { status: 200 } });
    const filePath = path.join(os.homedir(), "hacker-bob-sessions", domain, "chain-tree.jsonl");
    const content = fs.readFileSync(filePath, "utf8");
    const records = content.split("\n").filter((l) => l.length > 0).map((l) => JSON.parse(l));
    for (let i = 1; i < records.length; i++) {
      assert.ok(records[i - 1].node_hash <= records[i].node_hash);
    }
  } finally {
    cleanupDomain(domain);
  }
});
