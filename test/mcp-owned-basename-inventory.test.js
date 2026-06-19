"use strict";

// T8 (CR-2) — MCP-owned basename inventory closure. Extends the audit-graded
// closure (write-guard-tables-coherence.test.js) to the FULL session-root
// basename inventory: every path a paths.js resolver produces classifies into
// exactly one write-guard class, and no MCP-owned basename is shadowed by the
// agent-writable `.txt` allow.

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");

const {
  run,
  classify,
  buildClasses,
} = require("../scripts/check-mcp-owned-basename-inventory.js");
const {
  WRITE_GUARD_TABLES,
  sessionRootPathInventory,
  sessionDir,
  INVENTORY_PROBE_DOMAIN,
} = require("../mcp/lib/paths.js");

test("LIVE: every session-root basename is classified — no drift", () => {
  const { unclassified } = run();
  assert.deepEqual(
    unclassified,
    [],
    `unclassified session-root basenames: ${unclassified.map((u) => u.rel).join(", ")}`,
  );
});

test("LIVE: the *.txt-before-mcp-owned precedence gap is closed", () => {
  const { txt_shadowed } = run();
  assert.deepEqual(
    txt_shadowed,
    [],
    `MCP-owned basenames shadowed by the agent-writable .txt allow: ${txt_shadowed.join(", ")}`,
  );
});

test("LIVE: the inventory actually enumerated the resolver set (non-trivial)", () => {
  const { total } = run();
  // Guard against a future refactor that silently empties the inventory and
  // makes the closure vacuously green.
  assert.ok(total >= 50, `expected the resolver inventory to be non-trivial, got ${total}`);
});

test("CLASS REGRESSION (a): a synthetic unclassified basename is caught", () => {
  const C = buildClasses();
  const root = path.resolve(sessionDir(INVENTORY_PROBE_DOMAIN));
  // A brand-new resolver basename in no class (and not a .txt) must classify as
  // unclassified — proving a NEW path-function basename turns the check RED.
  const abs = path.join(root, "totally-new-mcp-artifact.bin");
  assert.equal(classify(abs, root, C), "unclassified");
});

test("CLASS REGRESSION (a): a real MCP-owned basename is classified, not unclassified", () => {
  const C = buildClasses();
  const root = path.resolve(sessionDir(INVENTORY_PROBE_DOMAIN));
  const abs = path.join(root, "claims.jsonl");
  assert.equal(classify(abs, root, C), "mcp-owned-basename");
});

test("CLASS REGRESSION (b): an MCP-owned *.txt would be flagged by the gap leg", () => {
  // Simulate the gap: classify an MCP-owned basename that ALSO matches the
  // agent-writable .txt allow. classify() (dir-first, then audit, then mcp,
  // then agent) returns mcp-owned — but the runtime hook tests agent-allow
  // FIRST, so it would be silently writable. run().txt_shadowed is the leg that
  // forbids this; here we prove the agent .txt pattern would shadow it.
  const C = buildClasses();
  const txtPattern = C.agentPatterns.find((re) => re.source === "^.*\\.txt$");
  assert.ok(txtPattern, "the agent-writable .txt pattern must exist for this gap to matter");
  // An MCP-owned basename ending in .txt matches the agent allow -> the hook
  // would allow it. The inventory's txt_shadowed leg must reject such a state.
  assert.ok(txtPattern.test("session-nucleus.txt"));
  // And: no current MCP-owned basename is a .txt (the live closure).
  for (const bn of WRITE_GUARD_TABLES.mcp_owned_basenames) {
    assert.equal(txtPattern.test(bn), false, `${bn} is MCP-owned but matches the agent .txt allow`);
  }
});

test("CLASS: agent-writable .txt scratch (e.g. subdomains.txt) stays agent-writable", () => {
  const C = buildClasses();
  const root = path.resolve(sessionDir(INVENTORY_PROBE_DOMAIN));
  // Scratch .txt at the session root is agent-writable by pattern — the closure
  // must not over-block legitimate scratch.
  assert.equal(classify(path.join(root, "subdomains.txt"), root, C), "agent-writable-pattern");
});

test("CLASS: a static-import .txt is classified by its MCP-owned dir, not the .txt allow", () => {
  const C = buildClasses();
  const root = path.resolve(sessionDir(INVENTORY_PROBE_DOMAIN));
  // static-imports/SA-1.txt: dir precedence must win so the agent cannot write
  // an MCP-owned import via the .txt allow.
  const abs = path.join(root, "static-imports", "SA-1.txt");
  assert.equal(classify(abs, root, C), "mcp-owned-dir");
});

test("INVENTORY covers every multi-arg resolver's produced basename", () => {
  // Spot-check that arity-guarded resolvers contributed concrete (pattern-
  // covered) basenames rather than being skipped.
  const inv = sessionRootPathInventory(INVENTORY_PROBE_DOMAIN);
  const byResolver = new Set(inv.map((r) => r.resolver));
  for (const r of [
    "liveDeadEndsJsonlPath",
    "staticArtifactPath",
    "waveAssignmentsPath",
    "verificationRoundPaths",
  ]) {
    assert.ok(byResolver.has(r), `${r} must contribute to the inventory`);
  }
});
