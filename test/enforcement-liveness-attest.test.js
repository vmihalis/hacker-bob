"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const {
  enforcementLiveness,
  assertEnforcementLiveness,
  SHADOW_ACK_ENV,
  SHADOW_ACK_TOKEN,
  AUTHORITY_MODE_ENV,
} = require("../mcp/core/enforcement-attest.js");
const { executeTool } = require("../mcp/core/dispatch/dispatch.js");

const ROOT = path.join(__dirname, "..");

// --- local env helper (self-contained; mirrors mcp-server.test withEnv) ---
async function withEnv(overrides, fn) {
  const prev = {};
  for (const k of Object.keys(overrides)) {
    prev[k] = process.env[k];
    if (overrides[k] === undefined) delete process.env[k];
    else process.env[k] = overrides[k];
  }
  try {
    return await fn();
  } finally {
    for (const k of Object.keys(overrides)) {
      if (prev[k] === undefined) delete process.env[k];
      else process.env[k] = prev[k];
    }
  }
}

const MUTATING_TOOL = { name: "fake_mut", mutating: true };
const READONLY_TOOL = { name: "fake_read", mutating: false };

// ---------------------------------------------------------------------------
// Liveness predicate: the four-corner truth table is the class contract.
// ---------------------------------------------------------------------------
test("enforce (no env) is attested and not degraded", () => {
  const l = enforcementLiveness({});
  assert.equal(l.mode, "enforce");
  assert.equal(l.shadow_active, false);
  assert.equal(l.degraded_unacked, false);
  assert.equal(l.attested, true);
});

test("shadow WITHOUT ack is the dangerous degraded-unacked state, NOT attested", () => {
  const l = enforcementLiveness({ [AUTHORITY_MODE_ENV]: "shadow" });
  assert.equal(l.mode, "shadow");
  assert.equal(l.operator_ack, false);
  assert.equal(l.shadow_active, false);
  assert.equal(l.degraded_unacked, true);
  assert.equal(l.attested, false);
});

test("shadow WITH exact ack token is shadow_active and attested", () => {
  const l = enforcementLiveness({
    [AUTHORITY_MODE_ENV]: "shadow",
    [SHADOW_ACK_ENV]: SHADOW_ACK_TOKEN,
  });
  assert.equal(l.shadow_active, true);
  assert.equal(l.operator_ack, true);
  assert.equal(l.degraded_unacked, false);
  assert.equal(l.attested, true);
});

test("a wrong/typo'd ack token fails closed (still degraded_unacked)", () => {
  const l = enforcementLiveness({
    [AUTHORITY_MODE_ENV]: "shadow",
    [SHADOW_ACK_ENV]: "yes",
  });
  assert.equal(l.shadow_active, false);
  assert.equal(l.degraded_unacked, true);
  assert.equal(l.attested, false);
});

// ---------------------------------------------------------------------------
// assertEnforcementLiveness: mutating refused, read-only allowed, under
// degraded-unacked shadow.
// ---------------------------------------------------------------------------
test("degraded-unacked shadow REFUSES a mutating call", () => {
  assert.throws(
    () => assertEnforcementLiveness(MUTATING_TOOL, { [AUTHORITY_MODE_ENV]: "shadow" }),
    (e) => {
      assert.equal(e.code, "STATE_CONFLICT");
      assert.equal(e.details.authority.authority_error_code, "enforcement_degraded_unacked");
      assert.equal(e.enforcement_liveness.degraded_unacked, true);
      // R1: the decision is mirrored onto err.authority so dispatch telemetry
      // records the enforcement decision instead of authority:null.
      assert.equal(e.authority.authority_error_code, "enforcement_degraded_unacked");
      assert.equal(e.authority.operator_ack, false);
      return true;
    },
  );
});

test("degraded-unacked shadow ALLOWS a read-only call through (kernel handles it)", () => {
  const l = assertEnforcementLiveness(READONLY_TOOL, { [AUTHORITY_MODE_ENV]: "shadow" });
  assert.equal(l.degraded_unacked, true); // returned, not thrown
});

test("acked shadow does NOT refuse a mutating call at the liveness gate", () => {
  const l = assertEnforcementLiveness(MUTATING_TOOL, {
    [AUTHORITY_MODE_ENV]: "shadow",
    [SHADOW_ACK_ENV]: SHADOW_ACK_TOKEN,
  });
  assert.equal(l.shadow_active, true);
});

// ---------------------------------------------------------------------------
// End-to-end through dispatch: the class regression guard.
// A real mutating bob_* tool is REFUSED under un-acked shadow with a loud
// envelope; the SAME call under ack falls through to the normal kernel block
// (no enforcement_degraded_unacked code). This proves the env toggle can no
// longer SILENTLY degrade a session write.
// ---------------------------------------------------------------------------
test("dispatch refuses a mutating tool under un-acked shadow (no silent degrade)", async () => {
  await withEnv(
    { [AUTHORITY_MODE_ENV]: "shadow", [SHADOW_ACK_ENV]: undefined },
    async () => {
      const res = await executeTool("bob_log_coverage", {
        target_domain: "enforce-live.example.com",
        wave: "w1",
        agent: "a1",
        surface_id: "surface-a",
        entries: [],
      });
      assert.equal(res.ok, false);
      assert.equal(res.error.code, "STATE_CONFLICT");
      // Loud, named, audit-recordable reason — not a discarded stderr line.
      assert.match(res.error.message, /shadow mode|operator acknowledgement/i);
      assert.equal(
        res.error.details.authority.authority_error_code,
        "enforcement_degraded_unacked",
      );
    },
  );
});

test("dispatch under ACKed shadow no longer reports enforcement_degraded_unacked", async () => {
  await withEnv(
    { [AUTHORITY_MODE_ENV]: "shadow", [SHADOW_ACK_ENV]: SHADOW_ACK_TOKEN },
    async () => {
      const res = await executeTool("bob_log_coverage", {
        target_domain: "enforce-live.example.com",
        wave: "w1",
        agent: "a1",
        surface_id: "surface-a",
        entries: [],
      });
      assert.equal(res.ok, false);
      // Still blocked (no session) but via the NORMAL kernel path, not the
      // degraded-unacked liveness gate.
      assert.notEqual(
        res.error.details.authority && res.error.details.authority.authority_error_code,
        "enforcement_degraded_unacked",
      );
    },
  );
});

// ---------------------------------------------------------------------------
// R2: the ack env-var name must be single-homed. enforcement-attest.js is the
// ONLY non-test source string-defining BOB_SESSION_AUTHORITY_SHADOW_ACK. If a
// future change re-inlines it anywhere else under mcp/, this test fails CI so
// the registry self-closes.
// ---------------------------------------------------------------------------
test("BOB_SESSION_AUTHORITY_SHADOW_ACK is single-homed in mcp/ (enforcement-attest only)", () => {
  const hits = [];
  const walk = (dir) => {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (ent.name === "node_modules") continue;
        walk(full);
      } else if (ent.isFile() && ent.name.endsWith(".js")) {
        if (fs.readFileSync(full, "utf8").includes("BOB_SESSION_AUTHORITY_SHADOW_ACK")) {
          hits.push(path.relative(ROOT, full).split(path.sep).join("/"));
        }
      }
    }
  };
  walk(path.join(ROOT, "mcp"));
  assert.deepEqual(
    hits.sort(),
    ["mcp/core/enforcement-attest.js"],
    `BOB_SESSION_AUTHORITY_SHADOW_ACK must live only in enforcement-attest.js under mcp/, found: ${hits.join(", ")}`,
  );
});
