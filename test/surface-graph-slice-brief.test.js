"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const {
  appendEdges,
  summarizeSurfaceGraphForSurface,
} = require("../mcp/lib/surface-graph.js");

function uniqueDomain(prefix = "bob-graph-slice-test") {
  const suffix = crypto.randomBytes(4).toString("hex");
  return `${prefix}-${suffix}.local`;
}

function cleanupDomain(domain) {
  const dir = path.join(os.homedir(), "hacker-bob-sessions", domain);
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
}

function seedGraph(domain, surfaceId) {
  appendEdges({
    target_domain: domain,
    edges: [
      { source: { type: "surface", id: surfaceId }, target: { type: "endpoint", id: "/api/users" }, edge_type: "contains" },
      { source: { type: "surface", id: surfaceId }, target: { type: "endpoint", id: "/api/admin" }, edge_type: "contains" },
      { source: { type: "surface", id: surfaceId }, target: { type: "subdomain", id: "api.example.com" }, edge_type: "contains" },
      { source: { type: "surface", id: surfaceId }, target: { type: "tech", id: "express" }, edge_type: "references" },
      { source: { type: "surface", id: surfaceId }, target: { type: "js_file", id: "main.bundle.js" }, edge_type: "references" },
      { source: { type: "surface", id: surfaceId }, target: { type: "secret_marker", id: "sk_live_abc" }, edge_type: "leaks" },
      { source: { type: "endpoint", id: "/api/users" }, target: { type: "auth_scheme", id: "bearerAuth" }, edge_type: "claims_auth" },
      { source: { type: "endpoint", id: "/api/admin" }, target: { type: "auth_scheme", id: "apiKey" }, edge_type: "claims_auth" },
    ],
  });
}

test("summarizeSurfaceGraphForSurface returns null when surface has no id", () => {
  const domain = uniqueDomain();
  try {
    const result = summarizeSurfaceGraphForSurface(domain, { hosts: ["api"] });
    assert.equal(result, null);
  } finally {
    cleanupDomain(domain);
  }
});

test("summarizeSurfaceGraphForSurface returns null when graph is empty", () => {
  const domain = uniqueDomain();
  try {
    const result = summarizeSurfaceGraphForSurface(domain, { id: "S-1" });
    assert.equal(result, null);
  } finally {
    cleanupDomain(domain);
  }
});

test("surface_graph_slice surfaces related endpoints, subdomains, tech, js_files, secret_markers", () => {
  const domain = uniqueDomain();
  try {
    seedGraph(domain, "S-1");
    const slice = summarizeSurfaceGraphForSurface(domain, { id: "S-1" });
    assert.ok(slice);
    assert.equal(slice.related_endpoints.length, 2);
    assert.equal(slice.related_subdomains[0].id, "api.example.com");
    assert.equal(slice.related_tech[0].id, "express");
    assert.equal(slice.related_js_files[0].id, "main.bundle.js");
    assert.equal(slice.leaked_secret_markers[0].id, "sk_live_abc");
  } finally {
    cleanupDomain(domain);
  }
});

test("surface_graph_slice resolves claimed_auth_schemes via second-hop endpoint→auth_scheme edges", () => {
  const domain = uniqueDomain();
  try {
    seedGraph(domain, "S-1");
    const slice = summarizeSurfaceGraphForSurface(domain, { id: "S-1" });
    const schemeIds = slice.claimed_auth_schemes.map((s) => s.id).sort();
    assert.deepEqual(schemeIds, ["apiKey", "bearerAuth"]);
  } finally {
    cleanupDomain(domain);
  }
});

test("surface_graph_slice limit option clamps below the hard ceiling (25)", () => {
  const domain = uniqueDomain();
  try {
    const edges = [];
    for (let i = 0; i < 30; i++) {
      edges.push({
        source: { type: "surface", id: "S-1" },
        target: { type: "endpoint", id: `/api/${i}` },
        edge_type: "contains",
      });
    }
    appendEdges({ target_domain: domain, edges });
    const slice = summarizeSurfaceGraphForSurface(domain, { id: "S-1" }, { limit: 4 });
    assert.equal(slice.limit, 4);
    assert.equal(slice.related_endpoints.length, 4);
  } finally {
    cleanupDomain(domain);
  }
});

test("surface_graph_slice limit clamps to ceiling when too large", () => {
  const domain = uniqueDomain();
  try {
    const edges = [];
    for (let i = 0; i < 30; i++) {
      edges.push({
        source: { type: "surface", id: "S-1" },
        target: { type: "endpoint", id: `/api/${i}` },
        edge_type: "contains",
      });
    }
    appendEdges({ target_domain: domain, edges });
    const slice = summarizeSurfaceGraphForSurface(domain, { id: "S-1" }, { limit: 9999 });
    assert.equal(slice.limit, 25);
  } finally {
    cleanupDomain(domain);
  }
});

test("surface_graph_slice ranks targets by edge count then id (deterministic)", () => {
  const domain = uniqueDomain();
  try {
    appendEdges({
      target_domain: domain,
      edges: [
        { source: { type: "surface", id: "S-1" }, target: { type: "endpoint", id: "/api/zeta" }, edge_type: "contains", source_artifact: "a" },
        { source: { type: "surface", id: "S-1" }, target: { type: "endpoint", id: "/api/zeta" }, edge_type: "contains", source_artifact: "b" },
        { source: { type: "surface", id: "S-1" }, target: { type: "endpoint", id: "/api/alpha" }, edge_type: "contains", source_artifact: "a" },
        { source: { type: "surface", id: "S-1" }, target: { type: "endpoint", id: "/api/middle" }, edge_type: "contains", source_artifact: "a" },
      ],
    });
    const slice = summarizeSurfaceGraphForSurface(domain, { id: "S-1" });
    // /api/zeta has 2 edges, the others have 1. Ties break by id.
    assert.equal(slice.related_endpoints[0].id, "/api/zeta");
    assert.equal(slice.related_endpoints[1].id, "/api/alpha");
    assert.equal(slice.related_endpoints[2].id, "/api/middle");
  } finally {
    cleanupDomain(domain);
  }
});
