"use strict";

// The finding-differential ledger is MCP-write-only + audit-graded: isAuditGradedPath
// returns true for it, the generated write-guard tables BLOCK an agent Write to it, and
// the mcp-owned-basename inventory stays green because the basename is classified.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const {
  isAuditGradedPath,
  findingDifferentialVerifiedJsonlPath,
} = require("../mcp/lib/paths.js");

test("isAuditGradedPath(finding-differential-verified.jsonl) is true", () => {
  const domain = "fd-audit.example.com";
  const abs = findingDifferentialVerifiedJsonlPath(domain);
  assert.equal(isAuditGradedPath(abs, domain), true);
});

test("the generated write-guard tables BLOCK the basename (agent Write is fenced)", () => {
  const tablesPath = path.join(__dirname, "..", ".claude", "hooks", "write-guard-tables.json");
  const tables = JSON.parse(fs.readFileSync(tablesPath, "utf8"));
  // The audit-graded basenames are re-exported by reference into the BLOCK set, so the
  // new basename must be present (and NOT in any allow set).
  assert.ok(
    tables.audit_graded_basenames.includes("finding-differential-verified.jsonl"),
    "finding-differential-verified.jsonl must be an audit-graded (BLOCK) basename",
  );
  assert.ok(
    !(tables.agent_writable_basenames || []).includes("finding-differential-verified.jsonl"),
    "must not be agent-writable",
  );
});

test("the basename is classified by the resolver inventory (mcp-owned-basename-inventory stays green)", () => {
  const { sessionRootPathInventory } = require("../mcp/lib/paths.js");
  const records = sessionRootPathInventory();
  const produced = records.some((r) => path.basename(r.abs) === "finding-differential-verified.jsonl");
  assert.ok(produced, "the resolver inventory must produce the new basename so the inventory check can classify it");
});
