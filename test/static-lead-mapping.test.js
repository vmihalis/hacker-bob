"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  STATIC_LEAD_SOURCE,
  STATIC_LEAD_SURFACE_TYPE,
  staticFindingToSurfaceLead,
} = require("../mcp/lib/static-lead-mapping.js");
const {
  normalizeSurfaceLead,
} = require("../mcp/lib/lead-intake.js");

function staticFinding(overrides = {}) {
  return {
    target_domain: "repo-static-map.example",
    indexed_at: "2026-06-10T00:00:00.000Z",
    finding_hash: "a".repeat(64),
    tool: "semgrep",
    rule_id: "cpp.unbounded-copy",
    severity: "error",
    location: {
      path: "src/server.c",
      line: 42,
      end_line: 42,
    },
    file: "src/server.c",
    start_line: 42,
    message: "length_field reaches copy_or_index_op before bound_check_site",
    cwe: ["CWE-120"],
    tags: ["copy_or_index_op", "bound_check_site"],
    dataflow_steps: 2,
    surface_id: "RS-1",
    ...overrides,
  };
}

test("staticFindingToSurfaceLead deterministically maps I10 rows into C11 lead shape", () => {
  const reachability = {
    attack_vector: "network",
    network_reachable: true,
    severity_ceiling: "critical",
  };
  const first = staticFindingToSurfaceLead(staticFinding(), reachability, "validate_vs_consume");
  const second = staticFindingToSurfaceLead(staticFinding(), reachability, "validate_vs_consume");

  assert.deepEqual(first, second);
  assert.equal(first.source, STATIC_LEAD_SOURCE);
  assert.equal(first.surface_type, STATIC_LEAD_SURFACE_TYPE);
  assert.equal(first.title, "cpp.unbounded-copy");
  assert.deepEqual(first.endpoints, ["src/server.c:42"]);
  assert.deepEqual(first.bug_class_hints, ["validate_vs_consume"]);
  assert.deepEqual(first.reachability_meta, {
    attack_vector: "network",
    network_reachable: true,
    severity_ceiling: "critical",
  });
  assert.ok(first.high_value_flows.includes("attack_vector=network"));
  assert.ok(first.high_value_flows.includes("network_reachable=true"));
  assert.ok(first.high_value_flows.includes("severity_ceiling=critical"));

  const normalizedFirst = normalizeSurfaceLead(first);
  const normalizedSecond = normalizeSurfaceLead(second);
  assert.equal(normalizedFirst.key, normalizedSecond.key);
});

test("staticFindingToSurfaceLead falls back to CWE and skips malformed locations", () => {
  const lead = staticFindingToSurfaceLead(staticFinding(), {}, null);
  assert.deepEqual(lead.bug_class_hints, ["CWE-120"]);

  const malformed = staticFinding({
    location: { path: "src/server.c" },
    start_line: null,
  });
  assert.equal(staticFindingToSurfaceLead(malformed, {}, null), null);
});

test("staticFindingToSurfaceLead rejects host-absolute and traversing paths", () => {
  assert.deepEqual(staticFindingToSurfaceLead(staticFinding({
    location: {
      path: "subdir/../src/server.c",
      line: 42,
    },
    file: "subdir/../src/server.c",
  }), {}, null).endpoints, ["src/server.c:42"]);

  assert.equal(staticFindingToSurfaceLead(staticFinding({
    location: {
      path: "/Users/operator/project/src/server.c",
      line: 42,
    },
    file: "/Users/operator/project/src/server.c",
  }), {}, null), null);

  assert.equal(staticFindingToSurfaceLead(staticFinding({
    location: {
      path: "C:/Users/operator/project/src/server.c",
      line: 42,
    },
    file: "C:/Users/operator/project/src/server.c",
  }), {}, null), null);

  assert.equal(staticFindingToSurfaceLead(staticFinding({
    location: {
      path: "../src/server.c",
      line: 42,
    },
    file: "../src/server.c",
  }), {}, null), null);
});
