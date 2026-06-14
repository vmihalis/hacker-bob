"use strict";

// The SubagentStop attestation hook enforces the final-marker + signed-handoff
// contract and settles the AgentRun ledger row; it must NEVER advance
// lifecycle/wave/finding state or produce frontier events (those are
// MCP-owned). This locks that contract so the hook cannot drift into a state
// producer.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const HOOK_PATH = path.join(__dirname, "..", ".claude", "hooks", "agent-run-stop.js");

test("the SubagentStop hook never advances lifecycle/wave/finding state or emits frontier events", () => {
  const source = fs.readFileSync(HOOK_PATH, "utf8");
  const forbidden = [
    "advanceSession",
    "appendFrontierEvent",
    "materializeFrontier",
    "writeSessionStateDocument",
    "appendCandidateClaim",
  ];
  for (const symbol of forbidden) {
    assert.equal(
      source.includes(symbol),
      false,
      `agent-run-stop is attestation-only; found a forbidden state-producing reference: ${symbol}`,
    );
  }
});
