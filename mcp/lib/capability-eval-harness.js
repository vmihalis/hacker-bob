"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const {
  ingestSchemaDoc,
} = require("./schema-contracts-store.js");
const {
  runDocDelta,
} = require("./doc-delta-runner.js");
const {
  runAuthDifferential,
} = require("./auth-differential-runner.js");
const {
  appendEdges,
  queryEdges,
} = require("./surface-graph.js");
const {
  appendChainNode,
  frontier,
} = require("./chain-state-tree.js");
const { capabilityToolMapFromRegistry } = require("./tool-registry.js");

function uniqueDomain(prefix) {
  return `${prefix}-${crypto.randomBytes(4).toString("hex")}.eval-fixture.local`;
}

function cleanupDomain(domain) {
  // Cycle P.2: clean fixtures from both canonical and legacy session roots so
  // a stale legacy directory from before the migration cannot poison reruns.
  const canonicalDir = path.join(os.homedir(), "hacker-bob-sessions", domain);
  const legacyDir = path.join(os.homedir(), "bounty-agent-sessions", domain);
  for (const dir of [canonicalDir, legacyDir]) {
    if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function withFixtureDomain(prefix, fn) {
  const domain = uniqueDomain(prefix);
  try {
    return await fn(domain);
  } finally {
    cleanupDomain(domain);
  }
}

function expect(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

const FIXTURES = Object.freeze({
  c2_doc_delta_auth_bypass: {
    capability: "C2_doc_vs_behavior",
    description: "Auth-required endpoint that succeeds without auth must surface a security divergence",
    async run() {
      return withFixtureDomain("eval-c2-bypass", async (domain) => {
        ingestSchemaDoc({
          target_domain: domain,
          raw_doc: JSON.stringify({
            openapi: "3.0.3",
            paths: {
              "/users": {
                get: {
                  security: [{ bearerAuth: [] }],
                  responses: { "200": { description: "ok", content: { "application/json": { schema: { type: "object" } } } } },
                },
              },
            },
          }),
        });
        const result = await runDocDelta({
          target_domain: domain,
          base_url: "https://eval.example",
          fetch_fn: async () => ({ status: 200, content_type: "application/json", body: { id: "1" }, sent_with_auth: false }),
        });
        expect(result.summary.divergences_total >= 1, `expected ≥1 divergence, got ${result.summary.divergences_total}`);
        expect(
          result.summary.divergences_by_type.auth_required_but_succeeded_without >= 1,
          `expected auth_required_but_succeeded_without divergence`,
        );
        expect(
          result.summary.divergences_by_severity.security >= 1,
          `expected security-class severity tally`,
        );
        return { divergences_total: result.summary.divergences_total };
      });
    },
  },
  c4_auth_differential_unauth_bypass: {
    capability: "C4_multi_account_differential",
    description: "Unauth profile getting ok where auth profile gets blocked must flag unauth_succeeds_where_auth_blocked as security",
    async run() {
      return withFixtureDomain("eval-c4-bypass", async (domain) => {
        const result = await runAuthDifferential({
          target_domain: domain,
          base_url: "https://eval.example",
          endpoints: ["/admin"],
          auth_profiles: ["guest", "user"],
          fetch_fn: async ({ auth_profile }) => ({
            status: auth_profile === "guest" ? 200 : 401,
            content_type: "application/json",
            body: auth_profile === "guest" ? { secret: "leak" } : null,
            sent_with_auth: auth_profile !== "guest",
          }),
          profile_metadata: {
            guest: { sent_with_auth: false },
            user: { sent_with_auth: true },
          },
        });
        expect(
          (result.summary.divergences_by_type.unauth_succeeds_where_auth_blocked || 0) >= 1,
          `expected unauth_succeeds_where_auth_blocked divergence`,
        );
        expect(
          (result.summary.divergences_by_severity.security || 0) >= 1,
          `expected security-class severity tally`,
        );
        return { divergences_total: result.summary.divergences_total };
      });
    },
  },
  i1_surface_graph_query: {
    capability: "I1_surface_graph",
    description: "Recorded edges must be queryable by source/target and edge_type",
    async run() {
      return withFixtureDomain("eval-i1-query", async (domain) => {
        appendEdges({
          target_domain: domain,
          edges: [
            { source: { type: "surface", id: "S-1" }, target: { type: "endpoint", id: "/api/users" }, edge_type: "contains" },
            { source: { type: "endpoint", id: "/api/users" }, target: { type: "auth_scheme", id: "bearerAuth" }, edge_type: "claims_auth" },
          ],
        });
        const containsEdges = queryEdges({ target_domain: domain, edge_type: "contains" });
        expect(containsEdges.total_matched === 1, `expected 1 contains edge, got ${containsEdges.total_matched}`);
        const userEndpoint = queryEdges({ target_domain: domain, target_id: "/api/users" });
        expect(userEndpoint.total_matched === 1, `expected 1 incoming edge to /api/users, got ${userEndpoint.total_matched}`);
        return { edges_recorded: 2 };
      });
    },
  },
  i7_chain_tree_branching_frontier: {
    capability: "I7_chain_state_tree",
    description: "Branching from the same parent_state_hash must yield two distinct frontier leaves",
    async run() {
      return withFixtureDomain("eval-i7-frontier", async (domain) => {
        const root = appendChainNode({
          target_domain: domain,
          action: { kind: "step1" },
          observed: { status: 200 },
        });
        appendChainNode({
          target_domain: domain,
          parent_state_hash: root.state_hash,
          action: { kind: "branchA" },
          observed: { status: 200 },
        });
        appendChainNode({
          target_domain: domain,
          parent_state_hash: root.state_hash,
          action: { kind: "branchB" },
          observed: { status: 500 },
          verdict: "failure",
        });
        const live = frontier({ target_domain: domain });
        expect(live.leaves.length === 2, `expected 2 frontier leaves, got ${live.leaves.length}`);
        const kinds = live.leaves.map((l) => l.action.kind).sort();
        expect(kinds[0] === "branchA" && kinds[1] === "branchB", `expected [branchA, branchB], got ${JSON.stringify(kinds)}`);
        return { frontier_count: live.leaves.length };
      });
    },
  },
});

const SUPPORTED_CAPABILITY_IDS = Object.freeze(new Set(Object.keys(capabilityToolMapFromRegistry())));

function assertFixturesRegistryBacked(fixtures) {
  for (const [name, spec] of Object.entries(fixtures)) {
    if (!SUPPORTED_CAPABILITY_IDS.has(spec.capability)) {
      throw new Error(`Capability fixture ${name} uses unregistered capability ${spec.capability}`);
    }
  }
}

assertFixturesRegistryBacked(FIXTURES);

async function evaluateAllFixtures() {
  const results = [];
  for (const [name, spec] of Object.entries(FIXTURES)) {
    const startedAt = Date.now();
    try {
      const detail = await spec.run();
      results.push({
        fixture: name,
        capability: spec.capability,
        description: spec.description,
        status: "passed",
        duration_ms: Date.now() - startedAt,
        detail,
      });
    } catch (err) {
      results.push({
        fixture: name,
        capability: spec.capability,
        description: spec.description,
        status: "failed",
        duration_ms: Date.now() - startedAt,
        error: err.message || String(err),
      });
    }
  }
  const summary = {
    total: results.length,
    passed: results.filter((r) => r.status === "passed").length,
    failed: results.filter((r) => r.status === "failed").length,
  };
  return { schema_version: 1, summary, results };
}

async function evaluateOneFixture(name) {
  const spec = FIXTURES[name];
  if (!spec) {
    throw new Error(`Unknown capability fixture: ${name}`);
  }
  const startedAt = Date.now();
  try {
    const detail = await spec.run();
    return {
      fixture: name,
      capability: spec.capability,
      description: spec.description,
      status: "passed",
      duration_ms: Date.now() - startedAt,
      detail,
    };
  } catch (err) {
    return {
      fixture: name,
      capability: spec.capability,
      description: spec.description,
      status: "failed",
      duration_ms: Date.now() - startedAt,
      error: err.message || String(err),
    };
  }
}

module.exports = {
  FIXTURES,
  evaluateAllFixtures,
  evaluateOneFixture,
};
