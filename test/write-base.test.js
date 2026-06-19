"use strict";

// Y.3 Stage a — _write-base.js wrapper. Asserts:
//   * wrapWriteTool preserves the spec shape (name, role_bundles, etc.)
//   * INVALID_ARGUMENTS thrown by the wrapper carry ToolError code
//   * mcp_server_internal synthetic caller bundle is constructed inside the
//     module (Y-D13) and is NOT exported as a grantable role bundle
//   * The retry-tracker pairs a failure key with a subsequent success and
//     calls the auto-emit path (telemetry-only — best-effort)
//   * The 6 migrated writers still load with their original name + handler
//     contract intact (Y-R21 BIND-equivalence smoke)

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const writeBase = require("../mcp/lib/tools/_write-base.js");
const { ERROR_CODES } = require("../mcp/lib/envelope.js");
const { VALID_ROLE_BUNDLES } = require("../mcp/lib/tool-registry.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-write-base-"));
  process.env.HOME = home;
  try {
    const result = fn(home);
    if (result && typeof result.then === "function") {
      throw new Error("withTempHome callers must be synchronous; use awaiting wrapper for async callers");
    }
    return result;
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

test("wrapWriteTool requires name, handler, and inputSchema", () => {
  assert.throws(() => writeBase.wrapWriteTool({}), /name/);
  assert.throws(
    () => writeBase.wrapWriteTool({ name: "x", inputSchema: { type: "object" } }),
    /handler/,
  );
  assert.throws(
    () => writeBase.wrapWriteTool({ name: "x", handler: () => "ok" }),
    /inputSchema/,
  );
});

test("wrapWriteTool preserves spec fields and wraps handler", () => {
  let invocations = 0;
  const wrapped = writeBase.wrapWriteTool({
    name: "bob_test_writer",
    inputSchema: {
      type: "object",
      properties: { target_domain: { type: "string" } },
      required: ["target_domain"],
    },
    handler: (args) => {
      invocations += 1;
      return JSON.stringify({ ok: true, target_domain: args.target_domain });
    },
    role_bundles: ["orchestrator"],
    mutating: true,
  });
  assert.equal(wrapped.name, "bob_test_writer");
  assert.deepEqual(wrapped.role_bundles, ["orchestrator"]);
  assert.equal(wrapped.mutating, true);
  const result = wrapped.handler({ target_domain: "example.com" });
  assert.equal(invocations, 1);
  assert.match(result, /"target_domain":"example.com"/);
});

test("wrapped handler raises INVALID_ARGUMENTS on schema violations", () => {
  const wrapped = writeBase.wrapWriteTool({
    name: "bob_test_writer",
    inputSchema: {
      type: "object",
      properties: { target_domain: { type: "string" } },
      required: ["target_domain"],
    },
    handler: () => "ok",
  });
  let caught;
  try { wrapped.handler({}); } catch (err) { caught = err; }
  assert.ok(caught, "missing target_domain must throw");
  assert.equal(caught.code, ERROR_CODES.INVALID_ARGUMENTS);
  assert.match(caught.message, /target_domain/);
});

test("MCP_SERVER_INTERNAL_BUNDLE is constructed in-module and not grantable", () => {
  // The bundle exists.
  assert.equal(writeBase.MCP_SERVER_INTERNAL_BUNDLE.bundle_id, "mcp_server_internal");
  // The grantable role-bundle list does NOT include it (Y-D13).
  assert.ok(
    !VALID_ROLE_BUNDLES.includes("mcp_server_internal"),
    "mcp_server_internal must not appear in VALID_ROLE_BUNDLES (Y-D13 / D9 paired guard)",
  );
});

test("retry tracker auto-emits runtime drift after recovered INVALID_ARGUMENTS", () => {
  withTempHome(() => {
    // Initialize a session so the auto-emit can actually append. We use the
    // same path the real writers do; the auto-emit path is best-effort and
    // silently no-ops when target_domain is absent.
    const domain = "audit-target.example";
    const { sessionDir } = require("../mcp/lib/paths.js");
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    fs.writeFileSync(
      path.join(sessionDir(domain), "session-nucleus.json"),
      JSON.stringify({ target_domain: domain, version: 1 }),
    );
    fs.writeFileSync(
      path.join(sessionDir(domain), "state.json"),
      JSON.stringify({ target_domain: domain, version: 1, lifecycle_state: "SETUP" }),
    );

    let calls = 0;
    const wrapped = writeBase.wrapWriteTool({
      name: "bob_test_recovered_writer",
      inputSchema: {
        type: "object",
        properties: {
          target_domain: { type: "string" },
          run_id: { type: "string" },
          payload: { type: "string" },
        },
        required: ["target_domain", "run_id", "payload"],
      },
      handler: (args) => {
        calls += 1;
        return JSON.stringify({ ok: true, payload: args.payload });
      },
    });

    // First call: schema violation -> retry tracker records the pending key.
    let err;
    try { wrapped.handler({ target_domain: domain, run_id: "R-1" }); } catch (e) { err = e; }
    assert.equal(err.code, ERROR_CODES.INVALID_ARGUMENTS);

    // Tracker keyed by (name, target_domain, run_id) carries the failure.
    const key = writeBase._internals.buildRetryKey("bob_test_recovered_writer", {
      target_domain: domain,
      run_id: "R-1",
    });
    assert.ok(writeBase._internals.PENDING_RETRY_KEYS.has(key));

    // Second call with corrected args: handler runs successfully AND the
    // auto-emit is invoked. The auto-emit is best-effort — we assert the
    // tracker is cleared (pending key consumed) regardless of whether the
    // emit succeeded.
    wrapped.handler({ target_domain: domain, run_id: "R-1", payload: "hi" });
    assert.equal(calls, 1);
    assert.ok(!writeBase._internals.PENDING_RETRY_KEYS.has(key));
  });
});

test("six existing writers load through wrapWriteTool with stable name + handler shape", () => {
  const expected = [
    ["../mcp/lib/tools/write-verification-round.js", "bob_write_verification_round"],
    ["../mcp/lib/tools/write-evidence-packs.js", "bob_write_evidence_packs"],
    ["../mcp/lib/tools/write-grade-verdict.js", "bob_write_grade_verdict"],
    ["../mcp/lib/tools/write-wave-handoff.js", "bob_write_wave_handoff"],
    ["../mcp/lib/tools/write-chain-attempt.js", "bob_write_chain_attempt"],
    ["../mcp/lib/tools/finalize-report.js", "bob_finalize_report"],
  ];
  for (const [modPath, toolName] of expected) {
    const mod = require(modPath);
    assert.equal(mod.name, toolName, `${modPath} must export tool ${toolName}`);
    assert.equal(typeof mod.handler, "function", `${toolName} handler must be a function`);
    assert.ok(Array.isArray(mod.role_bundles), `${toolName} must declare role_bundles`);
  }
});

test("no writer module directly calls bob_append_frontier_event (writers go through stores)", () => {
  // Stage a Reviewer-MUST-confirm: writers should not bypass the base by
  // directly appending frontier events. Each writer's module source is short
  // — we scan for the string. The stores they wrap may emit events, but the
  // tool-spec modules themselves should not.
  const writerSources = [
    "mcp/lib/tools/write-verification-round.js",
    "mcp/lib/tools/write-evidence-packs.js",
    "mcp/lib/tools/write-grade-verdict.js",
    "mcp/lib/tools/write-wave-handoff.js",
    "mcp/lib/tools/write-chain-attempt.js",
  ];
  for (const file of writerSources) {
    const text = fs.readFileSync(path.join(__dirname, "..", file), "utf8");
    assert.ok(
      !/bob_append_frontier_event\b/.test(text),
      `${file} must not call bob_append_frontier_event directly`,
    );
  }
});
