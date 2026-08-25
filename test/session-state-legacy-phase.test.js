"use strict";

// Reconnaissance/hunt phase names from the earlier vocabulary resolve to
// lifecycle states, so a session persisted under those names stays readable
// instead of failing closed on the legacy-phase fallback. Asserts the mapping,
// that a genuinely unknown phase still fails closed, and that an explicit
// lifecycle_state still takes precedence over a legacy phase.

const test = require("node:test");
const assert = require("node:assert/strict");

const { normalizeSessionStateDocument } = require("../mcp/core/session/session-state-contracts.js");

const DOMAIN = "legacy-phase.example.com";

test("the reconnaissance phase name resolves to the SETUP lifecycle state", () => {
  const normalized = normalizeSessionStateDocument(
    { target_url: `https://${DOMAIN}`, phase: "RECON" },
    DOMAIN,
  );
  assert.equal(normalized.lifecycle_state, "SETUP");
  // The on-disk legacy phase is preserved verbatim (read-compat backfill, not
  // canonicalization); the lifecycle state is the resolved authority.
  assert.equal(normalized.phase, "RECON");
});

test("the hunt phase name resolves to the OPEN_FRONTIER lifecycle state", () => {
  const normalized = normalizeSessionStateDocument(
    { target_url: `https://${DOMAIN}`, phase: "HUNT" },
    DOMAIN,
  );
  assert.equal(normalized.lifecycle_state, "OPEN_FRONTIER");
});

test("an unknown phase name still fails closed", () => {
  assert.throws(
    () => normalizeSessionStateDocument(
      { target_url: `https://${DOMAIN}`, phase: "NOT_A_PHASE" },
      DOMAIN,
    ),
    /phase must be one of/,
  );
});

test("an explicit lifecycle_state takes precedence over a legacy phase name", () => {
  const normalized = normalizeSessionStateDocument(
    { target_url: `https://${DOMAIN}`, lifecycle_state: "OPEN_FRONTIER", phase: "RECON" },
    DOMAIN,
  );
  assert.equal(normalized.lifecycle_state, "OPEN_FRONTIER");
});
