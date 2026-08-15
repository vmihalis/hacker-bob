#!/usr/bin/env node
"use strict";

// CR-2: render mcp/core/io/paths.js WRITE_GUARD_TABLES to a committed JSON manifest
// that the PreToolUse write-guard hooks read at runtime, killing the
// hook<->paths.js classification drift. The manifest is asserted byte-identical
// to the paths.js projection by `npm run check:write-guard-tables`.
//
// SCOPE: the manifest carries the AUDIT-GRADED subset (re-exported by reference
// from AUDIT_GRADED_PATHS) plus the hand-maintained plain-MCP-owned and
// agent-writable lists. The full MCP-owned basename inventory cross-check is a
// separate follow-up; this generator closes the audit-graded class only.
//
// The manifest is placed beside BOTH hook sources so the repo is self-consistent
// and `--check` passes; the Claude adapter installs its copy via HOOK_DATA_FILES
// (kimi install wiring is a separate task).

const fs = require("fs");
const path = require("path");
const { WRITE_GUARD_TABLES } = require("../mcp/core/io/paths.js");

const ROOT = path.join(__dirname, "..");
const MANIFEST_RELS = Object.freeze([
  path.join(".claude", "hooks", "write-guard-tables.json"),
  path.join("adapters", "kimi", "hooks", "write-guard-tables.json"),
]);
const MANIFEST_PATHS = MANIFEST_RELS.map((rel) => path.join(ROOT, rel));
// Primary manifest (the one consumed by the tests' MANIFEST_PATH import).
const MANIFEST_REL = MANIFEST_RELS[0];
const MANIFEST_PATH = MANIFEST_PATHS[0];

// Deterministic serialization: WRITE_GUARD_TABLES is already frozen and
// key-ordered by paths.js. Round-trip through JSON to drop any non-enumerable
// surprises and guarantee byte-stable output.
function render() {
  return `${JSON.stringify(WRITE_GUARD_TABLES, null, 2)}\n`;
}

function update({ check = false } = {}) {
  const next = render();
  let changed = false;
  for (let i = 0; i < MANIFEST_PATHS.length; i += 1) {
    const target = MANIFEST_PATHS[i];
    const rel = MANIFEST_RELS[i];
    const existing = fs.existsSync(target) ? fs.readFileSync(target, "utf8") : "";
    if (next === existing) continue;
    if (check) {
      throw new Error(
        `${rel} is stale vs mcp/core/io/paths.js WRITE_GUARD_TABLES; ` +
        `run: node scripts/generate-write-guard-tables.js`,
      );
    }
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, next, "utf8");
    changed = true;
  }
  return changed;
}

function main() {
  const check = process.argv.includes("--check");
  const changed = update({ check });
  if (changed && !check) console.log(`updated ${MANIFEST_REL} (+ kimi mirror)`);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(error.message || String(error));
    process.exit(1);
  }
}

module.exports = { render, update, MANIFEST_PATH, MANIFEST_PATHS };
