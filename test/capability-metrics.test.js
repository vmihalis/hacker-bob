"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  CAPABILITY_TO_TOOLS,
  summarizeCapabilityMetrics,
} = require("../mcp/lib/capability-metrics.js");
const {
  capabilityToolMapFromRegistry,
  TOOL_MANIFEST,
} = require("../mcp/lib/tool-registry.js");

function event({ tool, status = "ok", latency_ms = 10, timestamp = "2026-05-10T00:00:00Z", ok, error_code }) {
  return { tool, status, latency_ms, timestamp, ok, error_code };
}

test("CAPABILITY_TO_TOOLS is derived from registry capability metadata", () => {
  const registryMap = capabilityToolMapFromRegistry();
  assert.deepEqual(CAPABILITY_TO_TOOLS, registryMap);
  for (const [capability, tools] of Object.entries(CAPABILITY_TO_TOOLS)) {
    assert.ok(tools.length > 0, `${capability} has at least one tool`);
    for (const tool of tools) {
      assert.equal(TOOL_MANIFEST[tool].capability_id, capability);
    }
  }
});

test("summarizeCapabilityMetrics returns zeroed buckets when no events", () => {
  const result = summarizeCapabilityMetrics([]);
  for (const cap of Object.keys(CAPABILITY_TO_TOOLS)) {
    assert.equal(result[cap].call_count, 0);
    assert.equal(result[cap].success_count, 0);
    assert.equal(result[cap].error_count, 0);
    assert.equal(result[cap].success_rate, null);
    assert.equal(result[cap].avg_latency_ms, null);
    assert.equal(result[cap].last_called_at, null);
  }
});

test("call_count, success_count, success_rate, avg_latency aggregate per capability", () => {
  const events = [
    event({ tool: "bob_ingest_schema_doc", latency_ms: 100 }),
    event({ tool: "bob_run_doc_delta", latency_ms: 200 }),
    event({ tool: "bob_run_doc_delta", latency_ms: 300, status: "error", ok: false }),
    event({ tool: "bob_append_chain_node", latency_ms: 50 }),
    event({ tool: "bob_append_chain_node", latency_ms: 50 }),
  ];
  const result = summarizeCapabilityMetrics(events);
  assert.equal(result.C2_doc_vs_behavior.call_count, 3);
  assert.equal(result.C2_doc_vs_behavior.success_count, 2);
  assert.equal(result.C2_doc_vs_behavior.error_count, 1);
  assert.equal(result.C2_doc_vs_behavior.success_rate, 0.6667);
  assert.equal(result.C2_doc_vs_behavior.avg_latency_ms, 200);

  assert.equal(result.I7_chain_state_tree.call_count, 2);
  assert.equal(result.I7_chain_state_tree.success_count, 2);
  assert.equal(result.I7_chain_state_tree.success_rate, 1);
  assert.equal(result.I7_chain_state_tree.avg_latency_ms, 50);
});

test("blocked_count breaks out from error_count", () => {
  const events = [
    event({ tool: "bob_run_auth_differential", status: "blocked", ok: true }),
    event({ tool: "bob_run_auth_differential", status: "ok" }),
    event({ tool: "bob_run_auth_differential", status: "error" }),
  ];
  const result = summarizeCapabilityMetrics(events);
  const c4 = result.C4_multi_account_differential;
  assert.equal(c4.call_count, 3);
  assert.equal(c4.success_count, 1);
  assert.equal(c4.blocked_count, 1);
  assert.equal(c4.error_count, 1);
});

test("last_called_at picks the latest timestamp", () => {
  const events = [
    event({ tool: "bob_query_chain_tree", timestamp: "2026-05-09T00:00:00Z" }),
    event({ tool: "bob_query_chain_tree", timestamp: "2026-05-10T00:00:00Z" }),
    event({ tool: "bob_query_chain_tree", timestamp: "2026-05-08T00:00:00Z" }),
  ];
  const result = summarizeCapabilityMetrics(events);
  assert.equal(result.I7_chain_state_tree.last_called_at, "2026-05-10T00:00:00Z");
});

test("per-tool breakdown reflects per-tool counts and rates", () => {
  const events = [
    event({ tool: "bob_ingest_schema_doc" }),
    event({ tool: "bob_ingest_schema_doc" }),
    event({ tool: "bob_run_doc_delta", status: "error", ok: false }),
  ];
  const result = summarizeCapabilityMetrics(events);
  const perTool = result.C2_doc_vs_behavior.per_tool;
  assert.equal(perTool.bob_ingest_schema_doc.call_count, 2);
  assert.equal(perTool.bob_ingest_schema_doc.success_rate, 1);
  assert.equal(perTool.bob_run_doc_delta.call_count, 1);
  assert.equal(perTool.bob_run_doc_delta.error_count, 1);
  assert.equal(perTool.bob_run_doc_delta.success_rate, 0);
  assert.equal(perTool.bob_query_schema_contracts.call_count, 0);
});

test("events for unrelated tools are ignored", () => {
  const events = [
    event({ tool: "bob_http_scan" }),
    event({ tool: "bob_record_candidate_claim" }),
    event({ tool: "bob_append_chain_node" }),
  ];
  const result = summarizeCapabilityMetrics(events);
  assert.equal(result.I7_chain_state_tree.call_count, 1);
  assert.equal(result.C2_doc_vs_behavior.call_count, 0);
  assert.equal(result.C4_multi_account_differential.call_count, 0);
});

test("malformed events are tolerated", () => {
  const result = summarizeCapabilityMetrics([
    null,
    "not-an-event",
    {},
    { tool: 123 },
    { tool: "bob_append_chain_node" },
  ]);
  assert.equal(result.I7_chain_state_tree.call_count, 1);
});

test("non-array input returns zeroed buckets", () => {
  const result = summarizeCapabilityMetrics(null);
  assert.equal(result.I7_chain_state_tree.call_count, 0);
});
