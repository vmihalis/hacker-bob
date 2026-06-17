"use strict";

// CR-2: the write-guard hook classification tables are rendered from
// mcp/lib/paths.js. These tests close the AUDIT-GRADED class: the on-disk
// manifest === the paths.js projection, the allow/block sets are disjoint, and
// every audit-graded sub-set is fully projected. Closure here covers the
// audit-graded subset only; the full MCP-owned basename inventory is a separate
// follow-up.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");

const {
  WRITE_GUARD_TABLES,
  AUDIT_GRADED_PATHS,
} = require("../mcp/lib/paths.js");
const { render, MANIFEST_PATH } = require("../scripts/generate-write-guard-tables.js");

test("rendered manifest is checked in and byte-identical to paths.js projection", () => {
  assert.ok(fs.existsSync(MANIFEST_PATH), "write-guard-tables.json must be committed");
  const onDisk = fs.readFileSync(MANIFEST_PATH, "utf8");
  assert.equal(onDisk, render(),
    "write-guard-tables.json is stale; run node scripts/generate-write-guard-tables.js");
});

test("manifest round-trips to the exact WRITE_GUARD_TABLES object", () => {
  const parsed = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"));
  assert.deepEqual(parsed, JSON.parse(JSON.stringify(WRITE_GUARD_TABLES)));
});

test("CLASS: every audit-graded basename is a hook BLOCK, never agent-writable", () => {
  const allow = new Set(WRITE_GUARD_TABLES.agent_writable_basenames);
  for (const basename of AUDIT_GRADED_PATHS.basenames) {
    assert.equal(allow.has(basename), false,
      `${basename} is audit-graded but listed agent-writable`);
  }
});

test("CLASS: agent-writable and MCP-owned basename sets are disjoint", () => {
  const allow = new Set(WRITE_GUARD_TABLES.agent_writable_basenames);
  const block = new Set([
    ...WRITE_GUARD_TABLES.audit_graded_basenames,
    ...WRITE_GUARD_TABLES.mcp_owned_basenames,
  ]);
  for (const b of allow) {
    assert.equal(block.has(b), false, `${b} is both allowed and blocked`);
  }
});

test("CLASS: audit-graded and mcp-owned basenames are disjoint (no double-maintain)", () => {
  const audit = new Set(WRITE_GUARD_TABLES.audit_graded_basenames);
  for (const b of WRITE_GUARD_TABLES.mcp_owned_basenames) {
    assert.equal(audit.has(b), false,
      `${b} is in BOTH audit_graded and mcp_owned — re-introduces drift`);
  }
});

test("CLASS: manifest projects every audit-graded sub-set non-empty and complete", () => {
  assert.equal(
    WRITE_GUARD_TABLES.audit_graded_basenames.length,
    AUDIT_GRADED_PATHS.basenames.length,
    "audit_graded_basenames must project the full registry");
  assert.deepEqual(
    WRITE_GUARD_TABLES.audit_graded_relative_dirs,
    AUDIT_GRADED_PATHS.relative_dirs,
    "audit_graded_relative_dirs must equal the registry by value");
  assert.equal(
    WRITE_GUARD_TABLES.audit_graded_filename_patterns.length,
    AUDIT_GRADED_PATHS.filename_patterns.length,
    "audit_graded_filename_patterns must project every registry pattern");
  AUDIT_GRADED_PATHS.filename_patterns.forEach((re, i) => {
    assert.equal(WRITE_GUARD_TABLES.audit_graded_filename_patterns[i], re.source);
  });
  assert.ok(WRITE_GUARD_TABLES.audit_graded_relative_dirs.length > 0);
  assert.ok(WRITE_GUARD_TABLES.audit_graded_filename_patterns.length > 0);
});

test("INSTANCE: report.md and chains.md are blocked, not allowed", () => {
  const allow = new Set(WRITE_GUARD_TABLES.agent_writable_basenames);
  const block = new Set(WRITE_GUARD_TABLES.audit_graded_basenames);
  for (const f of ["report.md", "chains.md"]) {
    assert.equal(allow.has(f), false, `${f} must NOT be agent-writable`);
    assert.equal(block.has(f), true, `${f} must be audit-graded/blocked`);
  }
});

test("audit-graded filename patterns are valid, serializable regexes", () => {
  for (const src of WRITE_GUARD_TABLES.audit_graded_filename_patterns) {
    assert.doesNotThrow(() => new RegExp(src));
  }
});
