"use strict";

const fs = require("fs");
const {
  assertSafeDomain,
  sessionDir,
  surfaceGraphJsonlPath,
} = require("./paths.js");
const {
  readFileUtf8,
} = require("./storage.js");
const { hashCanonicalJson } = require("./verification-contracts.js");

const NODE_TYPES = Object.freeze([
  "surface",
  "subdomain",
  "hostname",
  "endpoint",
  "js_file",
  "tech",
  "openapi_spec",
  "archived_url",
  "secret_marker",
  "auth_scheme",
  "static_artifact",
  "principal",
  "credential",
  "policy_gate",
  "effect",
  "intervention",
]);

const EDGE_TYPES = Object.freeze([
  "references",
  "contains",
  "hosts",
  "imports",
  "documents",
  "claims_auth",
  "leaks",
  "uses_credential",
  "requires",
  "tests_gate",
  "produces_effect",
  "permits_effect",
  "blocks_effect",
  "observes_effect",
]);

const DEFAULT_QUERY_LIMIT = 200;
const MAX_QUERY_LIMIT = 1000;

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function ensureSessionDir(domain) {
  const dir = sessionDir(domain);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function normalizeNode(node, label) {
  if (!isPlainObject(node)) {
    throw new Error(`${label} must be an object with type and id`);
  }
  if (typeof node.type !== "string" || node.type.length === 0) {
    throw new Error(`${label}.type must be a non-empty string`);
  }
  if (typeof node.id !== "string" || node.id.length === 0) {
    throw new Error(`${label}.id must be a non-empty string`);
  }
  return { type: node.type, id: node.id };
}

function normalizeEdge(edge) {
  if (!isPlainObject(edge)) {
    throw new Error("edge must be an object");
  }
  const source = normalizeNode(edge.source, "edge.source");
  const target = normalizeNode(edge.target, "edge.target");
  const edgeType = edge.edge_type;
  if (typeof edgeType !== "string" || edgeType.length === 0) {
    throw new Error("edge.edge_type must be a non-empty string");
  }
  const confidence = typeof edge.confidence === "number"
    ? Math.min(Math.max(edge.confidence, 0), 1)
    : 1;
  const sourceArtifact = typeof edge.source_artifact === "string" && edge.source_artifact.length > 0
    ? edge.source_artifact
    : null;
  const observedAt = typeof edge.observed_at === "string" && edge.observed_at.length > 0
    ? edge.observed_at
    : new Date().toISOString();
  const canonical = {
    source,
    target,
    edge_type: edgeType,
    source_artifact: sourceArtifact,
  };
  const edgeHash = hashCanonicalJson(canonical);
  return {
    edge_hash: edgeHash,
    source,
    target,
    edge_type: edgeType,
    confidence,
    source_artifact: sourceArtifact,
    observed_at: observedAt,
  };
}

function readEdgesFromJsonl(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const raw = readFileUtf8(filePath, { label: "surface-graph.jsonl" });
  const lines = raw.split(/\r?\n/).filter((line) => line.trim().length > 0);
  const records = [];
  for (let i = 0; i < lines.length; i++) {
    try {
      records.push(JSON.parse(lines[i]));
    } catch (err) {
      throw new Error(`Malformed surface-graph.jsonl at line ${i + 1}: ${err.message || String(err)}`);
    }
  }
  return records;
}

function writeEdgesToJsonl(filePath, edges) {
  const sorted = edges.slice().sort((a, b) => {
    const aHash = typeof a.edge_hash === "string" ? a.edge_hash : "";
    const bHash = typeof b.edge_hash === "string" ? b.edge_hash : "";
    return aHash.localeCompare(bHash);
  });
  const body = sorted.map((edge) => JSON.stringify(edge)).join("\n");
  fs.writeFileSync(filePath, body.length > 0 ? body + "\n" : "", "utf8");
}

function appendEdges({ target_domain, edges }) {
  const domain = assertSafeDomain(target_domain);
  if (!Array.isArray(edges)) {
    throw new Error("edges must be an array");
  }
  ensureSessionDir(domain);
  const filePath = surfaceGraphJsonlPath(domain);
  const existing = readEdgesFromJsonl(filePath);
  const byHash = new Map();
  for (const record of existing) {
    if (record && typeof record.edge_hash === "string") {
      byHash.set(record.edge_hash, record);
    }
  }
  let newCount = 0;
  let replacedCount = 0;
  for (const rawEdge of edges) {
    const normalized = normalizeEdge(rawEdge);
    if (byHash.has(normalized.edge_hash)) {
      replacedCount += 1;
    } else {
      newCount += 1;
    }
    byHash.set(normalized.edge_hash, normalized);
  }
  const merged = Array.from(byHash.values());
  writeEdgesToJsonl(filePath, merged);
  return {
    target_domain: domain,
    new_count: newCount,
    replaced_count: replacedCount,
    total_in_graph: merged.length,
  };
}

function queryEdges({
  target_domain,
  source_type,
  target_type,
  edge_type,
  source_id,
  target_id,
  limit,
}) {
  const domain = assertSafeDomain(target_domain);
  const filePath = surfaceGraphJsonlPath(domain);
  const records = readEdgesFromJsonl(filePath);
  if (records.length === 0) {
    return { edges: [], total_in_graph: 0, total_matched: 0 };
  }
  const matched = [];
  for (const record of records) {
    if (!isPlainObject(record)) continue;
    if (!isPlainObject(record.source) || !isPlainObject(record.target)) continue;
    if (source_type && record.source.type !== source_type) continue;
    if (target_type && record.target.type !== target_type) continue;
    if (edge_type && record.edge_type !== edge_type) continue;
    if (source_id && record.source.id !== source_id) continue;
    if (target_id && record.target.id !== target_id) continue;
    matched.push(record);
  }
  const cap = Number.isInteger(limit) && limit > 0
    ? Math.min(limit, MAX_QUERY_LIMIT)
    : DEFAULT_QUERY_LIMIT;
  return {
    edges: matched.slice(0, cap),
    total_in_graph: records.length,
    total_matched: matched.length,
  };
}

function neighbors({ target_domain, node_type, node_id, direction, limit }) {
  if (typeof node_type !== "string" || node_type.length === 0) {
    throw new Error("neighbors node_type must be a non-empty string");
  }
  if (typeof node_id !== "string" || node_id.length === 0) {
    throw new Error("neighbors node_id must be a non-empty string");
  }
  const dir = direction === "incoming" ? "incoming" : direction === "outgoing" ? "outgoing" : "both";
  const result = { incoming: [], outgoing: [] };
  if (dir === "outgoing" || dir === "both") {
    const out = queryEdges({ target_domain, source_type: node_type, source_id: node_id, limit });
    result.outgoing = out.edges;
  }
  if (dir === "incoming" || dir === "both") {
    const inc = queryEdges({ target_domain, target_type: node_type, target_id: node_id, limit });
    result.incoming = inc.edges;
  }
  return result;
}

const MECHANISM_NODE_TYPES = Object.freeze([
  "principal",
  "credential",
  "policy_gate",
  "effect",
  "intervention",
]);

function queryMechanismView({ target_domain, principal_id, effect_id, limit }) {
  const cap = Number.isInteger(limit) && limit > 0
    ? Math.min(limit, MAX_QUERY_LIMIT)
    : DEFAULT_QUERY_LIMIT;
  const edges = queryEdges({ target_domain, limit: MAX_QUERY_LIMIT }).edges
    .filter((edge) => MECHANISM_NODE_TYPES.includes(edge.source.type)
      || MECHANISM_NODE_TYPES.includes(edge.target.type));
  const filtered = edges.filter((edge) => {
    if (principal_id && edge.source.id !== principal_id && edge.target.id !== principal_id) return false;
    if (effect_id && edge.source.id !== effect_id && edge.target.id !== effect_id) return false;
    return true;
  });
  return {
    edges: filtered.slice(0, cap),
    total_matched: filtered.length,
    total_mechanism_edges: edges.length,
    total_in_graph: queryEdges({ target_domain, limit: 1 }).total_in_graph,
    node_types: MECHANISM_NODE_TYPES,
  };
}

const SURFACE_SLICE_DEFAULT_LIMIT = 5;
const SURFACE_SLICE_MAX_LIMIT = 25;

function topByCount(map, limit) {
  return Array.from(map.entries())
    .map(([id, count]) => ({ id, count }))
    .sort((a, b) => {
      if (b.count !== a.count) return b.count - a.count;
      return a.id.localeCompare(b.id);
    })
    .slice(0, limit);
}

function summarizeSurfaceGraphForSurface(domain, surfaceObj, options) {
  if (surfaceObj == null || typeof surfaceObj !== "object") return null;
  const surfaceId = typeof surfaceObj.id === "string" ? surfaceObj.id : null;
  if (!surfaceId) return null;
  const opts = options || {};
  const requestedLimit = Number.isInteger(opts.limit) && opts.limit > 0
    ? opts.limit
    : SURFACE_SLICE_DEFAULT_LIMIT;
  const limit = Math.min(requestedLimit, SURFACE_SLICE_MAX_LIMIT);
  let outgoing;
  try {
    outgoing = queryEdges({
      target_domain: domain,
      source_type: "surface",
      source_id: surfaceId,
      limit: MAX_QUERY_LIMIT,
    });
  } catch (_err) {
    return null;
  }
  if (outgoing.total_in_graph === 0) return null;
  const endpointHits = new Map();
  const jsFileHits = new Map();
  const techHits = new Map();
  const subdomainHits = new Map();
  const secretHits = new Map();
  for (const edge of outgoing.edges) {
    const targetType = edge.target && edge.target.type;
    const targetId = edge.target && edge.target.id;
    if (typeof targetId !== "string" || targetId.length === 0) continue;
    const map = targetType === "endpoint" ? endpointHits
      : targetType === "js_file" ? jsFileHits
      : targetType === "tech" ? techHits
      : targetType === "subdomain" ? subdomainHits
      : targetType === "secret_marker" ? secretHits
      : null;
    if (map == null) continue;
    map.set(targetId, (map.get(targetId) || 0) + 1);
  }
  let claimedAuthHits = new Map();
  for (const [endpoint] of endpointHits) {
    let authEdges;
    try {
      authEdges = queryEdges({
        target_domain: domain,
        source_type: "endpoint",
        source_id: endpoint,
        edge_type: "claims_auth",
        limit: 50,
      });
    } catch (_err) {
      continue;
    }
    for (const edge of authEdges.edges) {
      const scheme = edge.target && edge.target.id;
      if (typeof scheme !== "string" || scheme.length === 0) continue;
      claimedAuthHits.set(scheme, (claimedAuthHits.get(scheme) || 0) + 1);
    }
  }
  return {
    total_in_graph: outgoing.total_in_graph,
    edges_summarized: outgoing.total_matched,
    related_endpoints: topByCount(endpointHits, limit),
    related_js_files: topByCount(jsFileHits, limit),
    related_subdomains: topByCount(subdomainHits, limit),
    related_tech: topByCount(techHits, limit),
    leaked_secret_markers: topByCount(secretHits, limit),
    claimed_auth_schemes: topByCount(claimedAuthHits, limit),
    truncated: outgoing.total_matched > outgoing.edges.length,
    limit,
  };
}

module.exports = {
  appendEdges,
  queryEdges,
  queryMechanismView,
  neighbors,
  normalizeEdge,
  summarizeSurfaceGraphForSurface,
  NODE_TYPES,
  EDGE_TYPES,
  DEFAULT_QUERY_LIMIT,
  MAX_QUERY_LIMIT,
};
