"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const {
  buildSurfaceGraph,
  edgesFromAttackSurface,
  edgesFromAuthDifferentialResults,
  edgesFromChainTree,
  edgesFromEvmRoleTableResult,
  edgesFromSchemaCorpus,
} = require("../mcp/lib/surface-graph-builder.js");
const { queryEdges } = require("../mcp/lib/surface-graph.js");
const { ingestSchemaDoc } = require("../mcp/lib/schema-contracts-store.js");
const {
  authDifferentialResultsPath,
  chainTreeJsonlPath,
} = require("../mcp/lib/paths.js");

function uniqueDomain(prefix = "bob-graph-builder-test") {
  const suffix = crypto.randomBytes(4).toString("hex");
  return `${prefix}-${suffix}.local`;
}

function domainDir(domain) {
  return path.join(os.homedir(), "hacker-bob-sessions", domain);
}

function cleanupDomain(domain) {
  const dir = domainDir(domain);
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
}

function writeAttackSurface(domain, surfaces) {
  const dir = domainDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, "attack_surface.json"),
    JSON.stringify({ surfaces }, null, 2),
  );
}

const SAMPLE_SURFACE = Object.freeze({
  id: "S-1",
  hosts: ["api.example.com", "auth.example.com"],
  endpoints: ["/users", "/users/{id}", "/admin"],
  tech_stack: ["express", "node"],
  js_hints: ["main.bundle.js"],
  leaked_secrets: ["sk_live_abcd1234"],
});

test("edgesFromAttackSurface emits surface-contains-endpoint, host-hosts-endpoint, surface-references-tech, and leaks edges", () => {
  const edges = edgesFromAttackSurface({ surfaces: [SAMPLE_SURFACE] });
  const types = new Set(edges.map((e) => `${e.source.type}/${e.target.type}/${e.edge_type}`));
  assert.ok(types.has("surface/endpoint/contains"));
  assert.ok(types.has("subdomain/endpoint/hosts"));
  assert.ok(types.has("surface/subdomain/contains"));
  assert.ok(types.has("surface/tech/references"));
  assert.ok(types.has("surface/js_file/references"));
  assert.ok(types.has("surface/secret_marker/leaks"));
  const secretEdge = edges.find((e) => e.target.type === "secret_marker");
  assert.match(secretEdge.target.id, /^secret-[a-f0-9]{16}$/);
  assert.notEqual(secretEdge.target.id, SAMPLE_SURFACE.leaked_secrets[0]);
});

test("edgesFromAttackSurface emits hosts edges for each (host, endpoint) pair", () => {
  const edges = edgesFromAttackSurface({ surfaces: [SAMPLE_SURFACE] });
  const hostEdges = edges.filter((e) =>
    e.source.type === "subdomain" && e.target.type === "endpoint" && e.edge_type === "hosts");
  // 2 hosts × 3 endpoints
  assert.equal(hostEdges.length, 6);
});

test("edgesFromAttackSurface skips malformed entries without throwing", () => {
  const edges = edgesFromAttackSurface({
    surfaces: [
      null,
      "not-a-surface",
      { id: "" },
      { id: "S-1", endpoints: ["/x"] },
    ],
  });
  // Only the last surface should produce edges
  const validEdges = edges.filter((e) => e.source.type === "surface" && e.source.id === "S-1");
  assert.ok(validEdges.length >= 1);
});

test("edgesFromSchemaCorpus emits openapi_spec-documents-endpoint and endpoint-claims_auth-scheme edges", () => {
  const domain = uniqueDomain();
  try {
    const doc = JSON.stringify({
      openapi: "3.0.3",
      paths: {
        "/users": {
          get: {
            security: [{ bearerAuth: [] }],
            responses: { "200": { description: "ok" } },
          },
        },
      },
    });
    ingestSchemaDoc({
      target_domain: domain,
      raw_doc: doc,
      source_uri: "https://example.com/openapi.json",
    });
    const edges = edgesFromSchemaCorpus(domain);
    const docEdge = edges.find((e) =>
      e.source.type === "openapi_spec"
      && e.target.type === "endpoint"
      && e.target.id === "/users"
      && e.edge_type === "documents");
    assert.ok(docEdge);
    assert.equal(docEdge.source.id, "https://example.com/openapi.json");
    const authEdge = edges.find((e) =>
      e.source.type === "endpoint"
      && e.target.type === "auth_scheme"
      && e.edge_type === "claims_auth");
    assert.ok(authEdge);
    assert.equal(authEdge.target.id, "bearerAuth");
    const gateEdge = edges.find((e) =>
      e.source.type === "endpoint"
      && e.target.type === "policy_gate"
      && e.edge_type === "claims_auth");
    assert.ok(gateEdge);
    const requiresEdge = edges.find((e) =>
      e.source.type === "policy_gate"
      && e.target.type === "credential"
      && e.edge_type === "requires");
    assert.ok(requiresEdge);
    assert.equal(requiresEdge.target.id, "credential:bearerAuth");
  } finally {
    cleanupDomain(domain);
  }
});

function writeAuthDifferential(domain, perEndpoint) {
  fs.mkdirSync(domainDir(domain), { recursive: true });
  fs.writeFileSync(
    authDifferentialResultsPath(domain),
    JSON.stringify({ schema_version: 1, per_endpoint: perEndpoint }, null, 2),
  );
}

test("edgesFromAuthDifferentialResults projects principal/credential/intervention/effect and IDOR-like gate path", () => {
  const domain = uniqueDomain();
  try {
    writeAuthDifferential(domain, [{
      endpoint: "/objects/123",
      method: "GET",
      signatures_by_profile: {
        unauthenticated: { response_class: "ok", sent_with_auth: false },
        victim: { response_class: "forbidden", sent_with_auth: true },
      },
      divergences: [{
        type: "unauth_succeeds_where_auth_blocked",
        severity_class: "security",
      }],
    }]);
    const edges = edgesFromAuthDifferentialResults(domain);
    assert.ok(edges.some((e) =>
      e.source.id === "principal:unauthenticated"
      && e.target.id === "policy_gate:auth-diff:/objects/123"
      && e.edge_type === "tests_gate"));
    assert.ok(edges.some((e) =>
      e.source.id === "policy_gate:auth-diff:/objects/123"
      && e.target.id === "effect:/objects/123:unauth_succeeds_where_auth_blocked"
      && e.edge_type === "permits_effect"));
    assert.ok(edges.some((e) =>
      e.source.type === "credential"
      && e.target.type === "intervention"
      && e.edge_type === "tests_gate"));
    assert.ok(edges.some((e) =>
      e.source.type === "intervention"
      && e.target.type === "effect"
      && e.edge_type === "produces_effect"));
  } finally {
    cleanupDomain(domain);
  }
});

test("edgesFromAuthDifferentialResults does not create a policy-gate effect for public matching responses", () => {
  const domain = uniqueDomain();
  try {
    writeAuthDifferential(domain, [{
      endpoint: "/public",
      method: "GET",
      signatures_by_profile: {
        unauthenticated: { response_class: "ok", sent_with_auth: false },
        victim: { response_class: "ok", sent_with_auth: true },
      },
      divergences: [],
    }]);
    const edges = edgesFromAuthDifferentialResults(domain);
    assert.equal(edges.some((e) => e.target.id === "effect:/public:unauth_succeeds_where_auth_blocked"), false);
  } finally {
    cleanupDomain(domain);
  }
});

test("edgesFromChainTree projects chain outcomes as intervention observed effects", () => {
  const domain = uniqueDomain();
  try {
    fs.mkdirSync(domainDir(domain), { recursive: true });
    fs.writeFileSync(
      chainTreeJsonlPath(domain),
      `${JSON.stringify({
        node_hash: "n1",
        action: { kind: "selector_swap", target: "/objects/123" },
        verdict: "success",
      })}\n`,
    );
    const edges = edgesFromChainTree(domain);
    assert.deepEqual(edges[0].source, { type: "intervention", id: "intervention:chain:n1" });
    assert.deepEqual(edges[0].target, { type: "effect", id: "effect:chain:success" });
    assert.equal(edges[0].edge_type, "observes_effect");
  } finally {
    cleanupDomain(domain);
  }
});

test("edgesFromEvmRoleTableResult projects role matrix rows into principal credentials and policy gates", () => {
  const edges = edgesFromEvmRoleTableResult({
    contract: "0x00000000000000000000000000000000000000AA",
    access_control: [{
      role_hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      accounts: [
        { account: "0x00000000000000000000000000000000000000BB", has_role: true },
        { account: "0x00000000000000000000000000000000000000CC", has_role: false },
      ],
    }],
    wards: [
      { account: "0x00000000000000000000000000000000000000DD", ward: true },
    ],
  });
  assert.ok(edges.some((e) =>
    e.source.id === "policy_gate:evm:0x00000000000000000000000000000000000000aa:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    && e.target.id === "credential:evm-role:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    && e.edge_type === "requires"));
  assert.ok(edges.some((e) =>
    e.source.id === "principal:evm:0x00000000000000000000000000000000000000bb"
    && e.edge_type === "uses_credential"));
  assert.equal(edges.some((e) => e.source.id === "principal:evm:0x00000000000000000000000000000000000000cc"), false);
  assert.ok(edges.some((e) =>
    e.source.id === "principal:evm:0x00000000000000000000000000000000000000dd"
    && e.target.id === "credential:evm-ward:0x00000000000000000000000000000000000000aa"));
});

test("buildSurfaceGraph reads attack_surface.json and the schema corpus and persists merged edges", () => {
  const domain = uniqueDomain();
  try {
    writeAttackSurface(domain, [SAMPLE_SURFACE]);
    ingestSchemaDoc({
      target_domain: domain,
      raw_doc: JSON.stringify({
        openapi: "3.0.3",
        paths: {
          "/users": {
            get: {
              security: [{ bearerAuth: [] }],
              responses: { "200": { description: "ok" } },
            },
          },
        },
      }),
      source_uri: "https://example.com/openapi.json",
    });
    const result = buildSurfaceGraph({ target_domain: domain });
    assert.ok(result.new_count > 0);
    assert.ok(result.total_in_graph > 0);
    assert.equal(result.sources_used.length, 5);
    assert.equal(result.sources_used.find((s) => s.source === "attack_surface").edge_count > 0, true);
    assert.equal(result.sources_used.find((s) => s.source === "schema_corpus").edge_count > 0, true);

    // re-running is idempotent: replaced_count > 0, no growth
    const second = buildSurfaceGraph({ target_domain: domain });
    assert.equal(second.new_count, 0);
    assert.equal(second.replaced_count, result.total_in_graph);
    assert.equal(second.total_in_graph, result.total_in_graph);
  } finally {
    cleanupDomain(domain);
  }
});

test("buildSurfaceGraph honors the sources filter", () => {
  const domain = uniqueDomain();
  try {
    writeAttackSurface(domain, [SAMPLE_SURFACE]);
    const result = buildSurfaceGraph({
      target_domain: domain,
      sources: ["attack_surface"],
    });
    assert.equal(result.sources_used.length, 1);
    assert.equal(result.sources_used[0].source, "attack_surface");
  } finally {
    cleanupDomain(domain);
  }
});

test("buildSurfaceGraph persists mechanism projection edges into the single surface graph store", () => {
  const domain = uniqueDomain();
  try {
    writeAuthDifferential(domain, [{
      endpoint: "/objects/123",
      method: "GET",
      signatures_by_profile: {
        unauthenticated: { response_class: "ok", sent_with_auth: false },
        victim: { response_class: "forbidden", sent_with_auth: true },
      },
      divergences: [{ type: "unauth_succeeds_where_auth_blocked", severity_class: "security" }],
    }]);
    buildSurfaceGraph({ target_domain: domain, sources: ["auth_differential"] });
    const result = queryEdges({
      target_domain: domain,
      source_type: "principal",
      source_id: "principal:unauthenticated",
      target_type: "policy_gate",
    });
    assert.equal(result.total_matched, 1);
  } finally {
    cleanupDomain(domain);
  }
});

test("buildSurfaceGraph reports missing attack_surface.json without throwing", () => {
  const domain = uniqueDomain();
  try {
    const result = buildSurfaceGraph({ target_domain: domain });
    const attackEntry = result.sources_used.find((s) => s.source === "attack_surface");
    assert.equal(attackEntry.missing, true);
    assert.equal(attackEntry.edge_count, 0);
  } finally {
    cleanupDomain(domain);
  }
});

test("queried edges from buildSurfaceGraph are queryable via queryEdges", () => {
  const domain = uniqueDomain();
  try {
    writeAttackSurface(domain, [SAMPLE_SURFACE]);
    buildSurfaceGraph({ target_domain: domain });
    const containsEdges = queryEdges({ target_domain: domain, edge_type: "contains" });
    assert.ok(containsEdges.total_matched > 0);
    const usersEndpoint = queryEdges({ target_domain: domain, target_id: "/users" });
    assert.ok(usersEndpoint.total_matched > 0);
  } finally {
    cleanupDomain(domain);
  }
});
