"use strict";

// Y.3 Stage a (Y-D12 / D15) — ToolError optionally carries `remediation`,
// errorEnvelope propagates it, and dispatch.executeTool surfaces it through
// the MCP response envelope. Asserts:
//   * ToolError(... { remediation }) stores the field
//   * errorEnvelope(... { remediation }) includes error.remediation
//   * dispatch.executeTool forwards a thrown ToolError's remediation
//   * Legacy ToolError without remediation still works (backward compatible)

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  ERROR_CODES,
  ToolError,
  errorEnvelope,
} = require("../mcp/lib/envelope.js");
const { executeTool } = require("../mcp/lib/dispatch.js");

async function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-tool-error-rem-"));
  process.env.HOME = home;
  try {
    return await fn(home);
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

test("ToolError stores optional remediation field when provided", () => {
  const err = new ToolError(
    ERROR_CODES.STATE_CONFLICT,
    "partial surfaces remain",
    { surfaces: ["s1"] },
    { remediation: "call bob_set_queue_policy({partial_surface_advance_acknowledgements: [...]})" },
  );
  assert.equal(err.code, ERROR_CODES.STATE_CONFLICT);
  assert.equal(err.remediation, "call bob_set_queue_policy({partial_surface_advance_acknowledgements: [...]})");
  assert.deepEqual(err.details, { surfaces: ["s1"] });
});

test("ToolError without remediation remains backward compatible (no remediation property set)", () => {
  const err = new ToolError(ERROR_CODES.NOT_FOUND, "missing");
  assert.equal(err.code, ERROR_CODES.NOT_FOUND);
  assert.equal(err.remediation, undefined);
});

test("ToolError rejects non-string remediation values", () => {
  assert.throws(
    () => new ToolError(ERROR_CODES.STATE_CONFLICT, "m", null, { remediation: 42 }),
    /remediation must be a string/,
  );
});

test("errorEnvelope propagates the optional remediation through error.remediation", () => {
  const env = errorEnvelope("bob_x", ERROR_CODES.STATE_CONFLICT, "conflict", { surfaces: ["s1"] }, {
    remediation: "call bob_some_tool",
  });
  assert.equal(env.ok, false);
  assert.equal(env.error.code, ERROR_CODES.STATE_CONFLICT);
  assert.equal(env.error.remediation, "call bob_some_tool");
  assert.deepEqual(env.error.details, { surfaces: ["s1"] });
});

test("errorEnvelope without options omits the remediation field (no key noise)", () => {
  const env = errorEnvelope("bob_x", ERROR_CODES.NOT_FOUND, "missing");
  assert.equal("remediation" in env.error, false);
});

test("dispatch.executeTool surfaces ToolError remediation through the MCP envelope", async () => {
  await withTempHome(async () => {
    // bob_compose_report rejects bob_verified sections without backing
    // verification_round refs and carries remediation. We bootstrap a session
    // via bob_init_session so the dispatch authority allows the call, then
    // exercise the full dispatch.executeTool path so the test asserts
    // end-to-end propagation.
    const domain = "dispatch-rem.example.com";
    const initEnv = await executeTool("bob_init_session", {
      target_domain: domain,
      target_url: `https://${domain}`,
    });
    assert.equal(initEnv.ok, true, `bob_init_session must succeed: ${JSON.stringify(initEnv)}`);

    const env = await executeTool("bob_compose_report", {
      target_domain: domain,
      sections: [{
        kind: "impact",
        heading: "Impact",
        prose: "unverified",
        provenance: "bob_verified",
      }],
    });
    assert.equal(env.ok, false);
    assert.equal(env.error.code, ERROR_CODES.INVALID_ARGUMENTS);
    assert.equal(typeof env.error.remediation, "string");
    assert.match(env.error.remediation, /verification_round/);
  });
});
