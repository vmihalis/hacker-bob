"use strict";

const fs = require("fs");
const {
  assertSafeDomain,
  chainTreeJsonlPath,
  sessionDir,
} = require("./io/paths.js");
const {
  readFileUtf8,
} = require("./io/storage.js");
const { hashCanonicalJson } = require("./verification/verification-contracts.js");

const ROOT_PARENT_STATE_HASH = "root";

const VERDICT_VALUES = Object.freeze([
  "pending",
  "success",
  "failure",
  "pruned",
  "branched",
]);

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function ensureSessionDir(domain) {
  const dir = sessionDir(domain);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function readJsonlNodes(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const raw = readFileUtf8(filePath, { label: "chain-tree.jsonl" });
  const lines = raw.split(/\r?\n/).filter((line) => line.trim().length > 0);
  const records = [];
  for (let i = 0; i < lines.length; i++) {
    try {
      records.push(JSON.parse(lines[i]));
    } catch (err) {
      throw new Error(`Malformed chain-tree.jsonl at line ${i + 1}: ${err.message || String(err)}`);
    }
  }
  return records;
}

function writeJsonlNodes(filePath, nodes) {
  const sorted = nodes.slice().sort((a, b) => {
    const aHash = typeof a.node_hash === "string" ? a.node_hash : "";
    const bHash = typeof b.node_hash === "string" ? b.node_hash : "";
    return aHash.localeCompare(bHash);
  });
  const body = sorted.map((node) => JSON.stringify(node)).join("\n");
  fs.writeFileSync(filePath, body.length > 0 ? body + "\n" : "", "utf8");
}

function normalizeAction(action) {
  if (!isPlainObject(action)) {
    throw new Error("action must be an object");
  }
  if (typeof action.kind !== "string" || action.kind.length === 0) {
    throw new Error("action.kind must be a non-empty string");
  }
  return {
    kind: action.kind,
    target: typeof action.target === "string" ? action.target : null,
    payload: action.payload != null ? action.payload : null,
    description: typeof action.description === "string" ? action.description : null,
  };
}

function normalizeObserved(observed) {
  if (observed == null) return null;
  if (!isPlainObject(observed)) {
    throw new Error("observed must be an object or null");
  }
  return observed;
}

function normalizeVerdict(verdict) {
  if (verdict == null) return "pending";
  if (typeof verdict !== "string" || !VERDICT_VALUES.includes(verdict)) {
    throw new Error(`verdict must be one of ${VERDICT_VALUES.join(", ")}`);
  }
  return verdict;
}

function appendChainNode({
  target_domain,
  parent_state_hash,
  action,
  observed,
  verdict,
  replay_budget,
  notes,
}) {
  const domain = assertSafeDomain(target_domain);
  const parentStateHash = typeof parent_state_hash === "string" && parent_state_hash.length > 0
    ? parent_state_hash
    : ROOT_PARENT_STATE_HASH;
  const normalizedAction = normalizeAction(action);
  const normalizedObserved = normalizeObserved(observed);
  const normalizedVerdict = normalizeVerdict(verdict);
  const nodeIdentity = {
    parent_state_hash: parentStateHash,
    action: normalizedAction,
  };
  const nodeHash = hashCanonicalJson(nodeIdentity);
  const stateHash = normalizedObserved != null
    ? hashCanonicalJson({ node_hash: nodeHash, observed: normalizedObserved })
    : null;
  const record = {
    node_hash: nodeHash,
    parent_state_hash: parentStateHash,
    state_hash: stateHash,
    action: normalizedAction,
    observed: normalizedObserved,
    verdict: normalizedVerdict,
    replay_budget: typeof replay_budget === "number" ? replay_budget : null,
    notes: typeof notes === "string" ? notes : null,
    recorded_at: new Date().toISOString(),
  };
  ensureSessionDir(domain);
  const filePath = chainTreeJsonlPath(domain);
  const existing = readJsonlNodes(filePath);
  const byHash = new Map();
  for (const node of existing) {
    if (node && typeof node.node_hash === "string") byHash.set(node.node_hash, node);
  }
  const previous = byHash.get(nodeHash) || null;
  const merged = previous != null
    ? { ...previous, ...record, recorded_at: previous.recorded_at }
    : record;
  byHash.set(nodeHash, merged);
  writeJsonlNodes(filePath, Array.from(byHash.values()));
  return {
    target_domain: domain,
    node_hash: nodeHash,
    state_hash: stateHash,
    parent_state_hash: parentStateHash,
    verdict: normalizedVerdict,
    new_node: previous == null,
    total_in_tree: byHash.size,
  };
}

function queryChainTree({
  target_domain,
  parent_state_hash,
  verdict,
  action_kind,
  limit,
}) {
  const domain = assertSafeDomain(target_domain);
  const filePath = chainTreeJsonlPath(domain);
  const records = readJsonlNodes(filePath);
  if (records.length === 0) {
    return { nodes: [], total_in_tree: 0, total_matched: 0 };
  }
  const matched = [];
  for (const record of records) {
    if (!isPlainObject(record)) continue;
    if (parent_state_hash != null && record.parent_state_hash !== parent_state_hash) continue;
    if (verdict != null && record.verdict !== verdict) continue;
    if (action_kind != null && (!isPlainObject(record.action) || record.action.kind !== action_kind)) continue;
    matched.push(record);
  }
  const cap = Number.isInteger(limit) && limit > 0 ? Math.min(limit, 1000) : 200;
  return {
    nodes: matched.slice(0, cap),
    total_in_tree: records.length,
    total_matched: matched.length,
  };
}

function frontier({ target_domain, include_pruned, limit }) {
  const domain = assertSafeDomain(target_domain);
  const filePath = chainTreeJsonlPath(domain);
  const records = readJsonlNodes(filePath);
  if (records.length === 0) {
    return { leaves: [], total_in_tree: 0 };
  }
  const childrenByParent = new Map();
  for (const node of records) {
    if (!isPlainObject(node)) continue;
    const parent = node.parent_state_hash;
    if (typeof parent !== "string") continue;
    if (!childrenByParent.has(parent)) childrenByParent.set(parent, 0);
    childrenByParent.set(parent, childrenByParent.get(parent) + 1);
  }
  const leaves = [];
  for (const node of records) {
    if (!isPlainObject(node)) continue;
    if (typeof node.state_hash !== "string") continue;
    if (childrenByParent.get(node.state_hash)) continue;
    if (!include_pruned && node.verdict === "pruned") continue;
    leaves.push(node);
  }
  leaves.sort((a, b) => a.node_hash.localeCompare(b.node_hash));
  const cap = Number.isInteger(limit) && limit > 0 ? Math.min(limit, 500) : 50;
  return {
    leaves: leaves.slice(0, cap),
    total_in_tree: records.length,
    leaf_count: leaves.length,
  };
}

function ancestry({ target_domain, state_hash, limit }) {
  const domain = assertSafeDomain(target_domain);
  const filePath = chainTreeJsonlPath(domain);
  const records = readJsonlNodes(filePath);
  if (records.length === 0) {
    return { lineage: [], total_in_tree: 0 };
  }
  const byStateHash = new Map();
  for (const node of records) {
    if (isPlainObject(node) && typeof node.state_hash === "string") {
      byStateHash.set(node.state_hash, node);
    }
  }
  const lineage = [];
  let cursor = state_hash;
  const cap = Number.isInteger(limit) && limit > 0 ? Math.min(limit, 100) : 25;
  while (cursor && cursor !== ROOT_PARENT_STATE_HASH && lineage.length < cap) {
    const node = byStateHash.get(cursor);
    if (!node) break;
    lineage.push(node);
    cursor = node.parent_state_hash;
  }
  return {
    lineage,
    total_in_tree: records.length,
    reached_root: cursor === ROOT_PARENT_STATE_HASH,
  };
}

module.exports = {
  appendChainNode,
  queryChainTree,
  frontier,
  ancestry,
  ROOT_PARENT_STATE_HASH,
  VERDICT_VALUES,
};
