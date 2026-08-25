"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const {
  appendEdges,
  queryEdges,
  queryMechanismView,
  neighbors,
  normalizeEdge,
  EDGE_TYPES,
  NODE_TYPES,
} = require("../mcp/core/frontier/surface-graph.js");

function uniqueDomain(prefix = "bob-surface-graph-test") {
  const suffix = crypto.randomBytes(4).toString("hex");
  return `${prefix}-${suffix}.local`;
}

function cleanupDomain(domain) {
  const dir = path.join(os.homedir(), "hacker-bob-sessions", domain);
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
}

function jsToApi(source = "main.bundle.js", target = "/api/users", artifact = "attack_surface.json") {
  return {
    source: { type: "js_file", id: source },
    target: { type: "endpoint", id: target },
    edge_type: "references",
    source_artifact: artifact,
  };
}

test("normalizeEdge canonicalizes and computes a stable hash", () => {
  const edge = normalizeEdge(jsToApi());
  assert.equal(edge.source.type, "js_file");
  assert.equal(edge.target.type, "endpoint");
  assert.equal(edge.edge_type, "references");
  assert.equal(typeof edge.edge_hash, "string");
  const repeated = normalizeEdge(jsToApi());
  assert.equal(edge.edge_hash, repeated.edge_hash);
});

test("normalizeEdge rejects invalid confidence instead of silently changing provenance", () => {
  assert.throws(() => normalizeEdge({ ...jsToApi(), confidence: 1.5 }), /between 0 and 1/);
  assert.throws(() => normalizeEdge({ ...jsToApi(), confidence: -3 }), /between 0 and 1/);
  assert.throws(() => normalizeEdge({ ...jsToApi(), confidence: Number.NaN }), /between 0 and 1/);
  assert.equal(normalizeEdge(jsToApi()).confidence, 1);
});

test("normalizeEdge rejects malformed inputs", () => {
  assert.throws(() => normalizeEdge(null), /edge/);
  assert.throws(() => normalizeEdge({ ...jsToApi(), source: null }), /source/);
  assert.throws(() => normalizeEdge({ ...jsToApi(), edge_type: "" }), /edge_type/);
  assert.throws(() => normalizeEdge({ ...jsToApi(), target: { type: "endpoint", id: "" } }), /id/);
});

test("appendEdges persists edges and reports new vs replaced counts", () => {
  const domain = uniqueDomain();
  try {
    const first = appendEdges({
      target_domain: domain,
      edges: [
        jsToApi("a.js", "/api/users"),
        jsToApi("a.js", "/api/admin"),
      ],
    });
    assert.equal(first.new_count, 2);
    assert.equal(first.replaced_count, 0);
    assert.equal(first.total_in_graph, 2);

    const second = appendEdges({
      target_domain: domain,
      edges: [
        jsToApi("a.js", "/api/users"),  // duplicate
        jsToApi("b.js", "/api/secrets"),  // new
      ],
    });
    assert.equal(second.new_count, 1);
    assert.equal(second.replaced_count, 1);
    assert.equal(second.total_in_graph, 3);

    const filePath = path.join(os.homedir(), "hacker-bob-sessions", domain, "surface-graph.jsonl");
    assert.ok(fs.existsSync(filePath));
  } finally {
    cleanupDomain(domain);
  }
});

test("queryEdges filters by source_type, target_type, edge_type, source_id, target_id", () => {
  const domain = uniqueDomain();
  try {
    appendEdges({
      target_domain: domain,
      edges: [
        jsToApi("a.js", "/api/users"),
        jsToApi("a.js", "/api/admin"),
        {
          source: { type: "openapi_spec", id: "openapi.json" },
          target: { type: "endpoint", id: "/api/users" },
          edge_type: "documents",
        },
        {
          source: { type: "subdomain", id: "api.example.com" },
          target: { type: "endpoint", id: "/api/users" },
          edge_type: "hosts",
        },
      ],
    });
    const fromJs = queryEdges({ target_domain: domain, source_type: "js_file" });
    assert.equal(fromJs.total_matched, 2);
    const documentsOnly = queryEdges({ target_domain: domain, edge_type: "documents" });
    assert.equal(documentsOnly.total_matched, 1);
    const toUsers = queryEdges({ target_domain: domain, target_id: "/api/users" });
    assert.equal(toUsers.total_matched, 3);
    const fromAJs = queryEdges({ target_domain: domain, source_id: "a.js" });
    assert.equal(fromAJs.total_matched, 2);
  } finally {
    cleanupDomain(domain);
  }
});

test("queryEdges returns empty when no edges have been recorded", () => {
  const domain = uniqueDomain();
  try {
    const result = queryEdges({ target_domain: domain });
    assert.equal(result.edges.length, 0);
    assert.equal(result.total_in_graph, 0);
    assert.equal(result.total_matched, 0);
  } finally {
    cleanupDomain(domain);
  }
});

test("queryEdges limit caps results at MAX_QUERY_LIMIT (1000)", () => {
  const domain = uniqueDomain();
  try {
    const edges = [];
    for (let i = 0; i < 1100; i++) {
      edges.push({
        source: { type: "endpoint", id: `/api/${i}` },
        target: { type: "endpoint", id: `/api/${i + 1}` },
        edge_type: "references",
      });
    }
    appendEdges({ target_domain: domain, edges });
    const result = queryEdges({ target_domain: domain, limit: 9999 });
    assert.ok(result.edges.length <= 1000);
    assert.equal(result.total_matched, 1100);
  } finally {
    cleanupDomain(domain);
  }
});

test("neighbors returns incoming, outgoing, or both per direction", () => {
  const domain = uniqueDomain();
  try {
    appendEdges({
      target_domain: domain,
      edges: [
        jsToApi("a.js", "/api/users"),
        jsToApi("b.js", "/api/users"),
        {
          source: { type: "endpoint", id: "/api/users" },
          target: { type: "endpoint", id: "/api/users/{id}" },
          edge_type: "references",
        },
      ],
    });
    const both = neighbors({ target_domain: domain, node_type: "endpoint", node_id: "/api/users" });
    assert.equal(both.incoming.length, 2);
    assert.equal(both.outgoing.length, 1);
    const onlyIn = neighbors({ target_domain: domain, node_type: "endpoint", node_id: "/api/users", direction: "incoming" });
    assert.equal(onlyIn.incoming.length, 2);
    assert.equal(onlyIn.outgoing.length, 0);
    const onlyOut = neighbors({ target_domain: domain, node_type: "endpoint", node_id: "/api/users", direction: "outgoing" });
    assert.equal(onlyOut.outgoing.length, 1);
    assert.equal(onlyOut.incoming.length, 0);
  } finally {
    cleanupDomain(domain);
  }
});

test("neighbors rejects unscoped node lookups", () => {
  assert.throws(() => neighbors({ target_domain: "x.example", node_type: "", node_id: "/api" }), /node_type/);
  assert.throws(() => neighbors({ target_domain: "x.example", node_type: "endpoint", node_id: "" }), /node_id/);
});

test("NODE_TYPES includes emitted surface and tech node kinds", () => {
  assert.ok(NODE_TYPES.includes("surface"));
  assert.ok(NODE_TYPES.includes("tech"));
});

test("NODE_TYPES and EDGE_TYPES include CB-1 mechanism projection vocabulary", () => {
  for (const nodeType of ["principal", "credential", "policy_gate", "effect", "intervention"]) {
    assert.ok(NODE_TYPES.includes(nodeType), `missing ${nodeType}`);
  }
  for (const edgeType of ["uses_credential", "requires", "tests_gate", "produces_effect", "permits_effect", "blocks_effect", "observes_effect"]) {
    assert.ok(EDGE_TYPES.includes(edgeType), `missing ${edgeType}`);
  }
});

test("queryMechanismView returns bounded mechanism edges from surface-graph.jsonl only", () => {
  const domain = uniqueDomain();
  try {
    appendEdges({
      target_domain: domain,
      edges: [
        jsToApi("a.js", "/api/users"),
        {
          source: { type: "principal", id: "principal:unauthenticated" },
          target: { type: "policy_gate", id: "policy_gate:auth-diff:/api/users" },
          edge_type: "tests_gate",
          source_artifact: "auth-differential-results.json",
        },
        {
          source: { type: "policy_gate", id: "policy_gate:auth-diff:/api/users" },
          target: { type: "effect", id: "effect:/api/users:unauth_succeeds_where_auth_blocked" },
          edge_type: "permits_effect",
          source_artifact: "auth-differential-results.json",
        },
      ],
    });
    const result = queryMechanismView({
      target_domain: domain,
      principal_id: "principal:unauthenticated",
      limit: 1,
    });
    assert.equal(result.edges.length, 1);
    assert.equal(result.total_mechanism_edges, 2);
    assert.equal(result.total_in_graph, 3);
    assert.ok(result.node_types.includes("policy_gate"));
  } finally {
    cleanupDomain(domain);
  }
});

test("on-disk surface-graph.jsonl is sorted by edge_hash for replay determinism", () => {
  const domain = uniqueDomain();
  try {
    appendEdges({
      target_domain: domain,
      edges: [
        jsToApi("z.js", "/api/zeta"),
        jsToApi("a.js", "/api/alpha"),
        jsToApi("m.js", "/api/middle"),
      ],
    });
    const filePath = path.join(os.homedir(), "hacker-bob-sessions", domain, "surface-graph.jsonl");
    const content = fs.readFileSync(filePath, "utf8");
    const lines = content.split("\n").filter((line) => line.trim().length > 0);
    const records = lines.map((line) => JSON.parse(line));
    for (let i = 1; i < records.length; i++) {
      assert.ok(records[i - 1].edge_hash <= records[i].edge_hash, `sorted at line ${i}`);
    }
  } finally {
    cleanupDomain(domain);
  }
});

test("appendEdges rejects unsafe target_domain", () => {
  assert.throws(
    () => appendEdges({ target_domain: "../escape", edges: [] }),
    /target_domain/,
  );
});
