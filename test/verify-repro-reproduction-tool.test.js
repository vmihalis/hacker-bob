"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { TOOL_MODULES } = require("../mcp/lib/tools/index.js");

function findTool(name) {
  return TOOL_MODULES.find((t) => t.name === name) || null;
}

test("bob_verify_repro_reproduction is registered with the repo-docker-run authority shape", () => {
  const tool = findTool("bob_verify_repro_reproduction");
  assert.ok(tool, "tool must be registered in the TOOLS index");
  assert.equal(typeof tool.handler, "function");
  // It drives sandboxed docker runs and writes an audit-graded ledger: mutating,
  // session-scoped, no network of its own (the toolchain is in the image).
  assert.equal(tool.mutating, true);
  assert.equal(tool.network_access, false);
  assert.equal(tool.scope_required, false);
  assert.equal(tool.sensitive_output, true);
});

test("role_bundles place reproduction in verification, not the (web) evaluator", () => {
  const repro = findTool("bob_verify_repro_reproduction");
  assert.ok(repro);
  // Differential reproduction is a verification activity — verifier re-runs it,
  // evidence collects it. It must NOT be in evaluator-shared, or the web evaluator
  // would carry an OSS-only tool and blow its tool budget.
  assert.deepEqual([...repro.role_bundles].sort(), ["evidence", "verifier"]);
  assert.ok(!repro.role_bundles.includes("evaluator-shared"));
});

test("inputSchema requires the differential's load-bearing fields", () => {
  const tool = findTool("bob_verify_repro_reproduction");
  const req = tool.inputSchema.required;
  for (const field of ["target_domain", "finding_id", "command", "control_ref"]) {
    assert.ok(req.includes(field), `${field} must be required (the differential cannot run without it)`);
  }
  // command is the PoC argv re-run verbatim on both trees.
  assert.equal(tool.inputSchema.properties.command.type, "array");
  // control_ref is the upstream-fix commit that defines the "quiet" half of the flip.
  assert.equal(tool.inputSchema.properties.control_ref.type, "string");
});

test("declares the audit-graded repro-verified.jsonl as a written artifact", () => {
  const tool = findTool("bob_verify_repro_reproduction");
  assert.ok(
    tool.session_artifacts_written.includes("repro-verified.jsonl"),
    "the verified_pass ledger the O-P4 gate grades on must be declared",
  );
});
