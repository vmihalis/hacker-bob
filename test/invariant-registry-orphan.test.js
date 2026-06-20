"use strict";

// CR-4 — invariant-registry orphan-check. Closes the CLASS: any tag with no
// registry entry, any registry entry whose enforcing symbol is deleted/renamed,
// any stale allowlist entry, any incomplete SELF_FILES, and (critically) any
// docs-prose homonym mis-binding all fail here.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const {
  REGISTRY, ALLOWLIST_UNDOCUMENTED, SELF_FILES, knownTags, enforcingSites,
} = require("../mcp/lib/invariant-registry.js");
const {
  run, extractTags, assertSelfFilesComplete,
} = require("../scripts/check-invariant-registry.js");

test("REGISTRY / ALLOWLIST / SELF_FILES are frozen (registry-driven, no runtime mutation)", () => {
  assert.equal(Object.isFrozen(REGISTRY), true);
  for (const entry of Object.values(REGISTRY)) {
    assert.equal(Object.isFrozen(entry), true);
    assert.equal(Object.isFrozen(entry.enforced_by), true);
  }
  assert.throws(() => ALLOWLIST_UNDOCUMENTED.add("X"), TypeError);
  assert.equal(Object.isFrozen(SELF_FILES), true);
});

test("the live tree passes the orphan-check (no orphan tags, no dangling sites)", () => {
  const { errors } = run();
  assert.deepEqual(errors, [], "orphan-check must be green:\n" + errors.join("\n"));
});

test("every invariant entry has >=1 live enforcing file:symbol", () => {
  for (const [tag, entry] of Object.entries(REGISTRY)) {
    if (entry.kind !== "invariant") continue;
    assert.ok(entry.enforced_by.length >= 1,
      `invariant ${tag} must declare an enforcing site`);
  }
  // enforcingSites() projects only invariant kind, used by the driver.
  assert.ok(enforcingSites().length >= 1);
});

test("I6 reopenability is registered and bound to ALLOWED_TRANSITIONS", () => {
  const entry = REGISTRY["I6"];
  assert.ok(entry, "I6 must have a registry entry (closes I6)");
  const files = entry.enforced_by.map((s) => `${s.file}:${s.symbol}`);
  assert.ok(files.includes("mcp/lib/lifecycle-gates.js:ALLOWED_TRANSITIONS"),
    "I6 must point at the back-edge table");
  const src = fs.readFileSync(
    path.join(__dirname, "..", "mcp", "lib", "lifecycle-gates.js"), "utf8");
  assert.match(src, /ALLOWED_TRANSITIONS/);
  // The I6 tag must be anchored as a COMMENT in lifecycle-gates.js.
  assert.match(src, /(?:^|\s)\/\/\s*(?:[A-Za-z0-9-]+\s+)?I6\b/m,
    "I6 tag must be anchored as a // comment in lifecycle-gates.js");
  const { ALLOWED_TRANSITIONS } = require("../mcp/lib/lifecycle-gates.js");
  for (const from of ["CLAIM_FREEZE", "VERIFY", "GRADE", "REPORT"]) {
    assert.ok(ALLOWED_TRANSITIONS[from].includes("OPEN_FRONTIER"),
      `${from} -> OPEN_FRONTIER back-edge must remain (I6)`);
  }
});

test("S14 enforced_by binds a UNIQUE S14 symbol, not the generic `checkout`", () => {
  const entry = REGISTRY["S14"];
  const symbols = entry.enforced_by.map((s) => s.symbol);
  assert.ok(!symbols.includes("checkout"),
    "S14 must not be enforced by the generic `checkout` substring");
  assert.ok(symbols.includes("assertContainerCheckoutDest"),
    "S14 must bind the run-scoped /src boundary guard");
  const src = fs.readFileSync(
    path.join(__dirname, "..", "mcp", "lib", "repo-env.js"), "utf8");
  assert.match(src, /assertContainerCheckoutDest/);
  // The S14 tag anchor must be a comment in repo-env.js (the // S14 control... line).
  assert.match(src, /(?:^|\s)\/\/\s*(?:[A-Za-z0-9-]+\s+)?S14\b/m,
    "S14 tag must be anchored as a // comment in repo-env.js");
});

// ── CLASS-closing synthetic regressions (the point of T7) ──────────────────

test("CLASS: a new un-registered, un-allowlisted tag would be flagged", () => {
  const tags = extractTags("// see Y-P99 for the new gate");
  assert.ok(tags.has("Y-P99"));
  assert.ok(!knownTags().has("Y-P99"));
  assert.ok(!ALLOWLIST_UNDOCUMENTED.has("Y-P99"));
});

test("CLASS: a registry entry pointing at a missing symbol is dangling", () => {
  const file = "mcp/lib/lifecycle-gates.js";
  const text = fs.readFileSync(path.join(__dirname, "..", file), "utf8");
  assert.equal(text.includes("ALLOWED_TRANSITIONS"), true);
  assert.equal(text.includes("ALLOWED_TRANSITIONS_RENAMED_v2"), false);
});

test("CLASS: the grammar anchors unique tags (no false-positive on plain tokens)", () => {
  const noise = extractTags("const C99config = 1; // Information about X.md and S99x_helper");
  assert.ok(!noise.has("X.md"), "X.md is a filename, not a tag");
  assert.ok(extractTags("// gated by Y-D15b").has("Y-D15b"));
});

test("a S/C/I tag in PROSE does NOT match; only comment anchors do", () => {
  // Mimics docs/capability-hypergraph.md prose: "`I6` was intended as a memory
  // layer over time" — a homonym of the lifecycle I6.
  const prose = "As of HEAD, `I6` was intended as a memory layer; the I6 store was parked.";
  assert.ok(!extractTags(prose).has("I6"),
    "a prose I6 (capability homonym) must NOT be extracted as a tag");
  // The SAME token, in comment form, IS a tag (this is how lifecycle-gates.js anchors it).
  assert.ok(extractTags("// I6 (CR-4): lifecycle reopenability").has("I6"),
    "a // I6 comment anchor IS a tag");
});

test("the docs capability-hypergraph I6 homonym does NOT resolve to the lifecycle entry", () => {
  // Scan the real docs file (if present) and assert it contributes no I6 tag,
  // so its I6 mentions cannot 'resolve' to REGISTRY['I6'] (lifecycle).
  const docFile = path.join(__dirname, "..", "docs", "capability-hypergraph.md");
  if (fs.existsSync(docFile)) {
    const text = fs.readFileSync(docFile, "utf8");
    assert.ok(text.includes("I6"), "sanity: the docs homonym text exists");
    assert.ok(!extractTags(text).has("I6"),
      "docs capability I6 prose/headings must NOT be scanned as the lifecycle tag");
  }
});

test("SELF_FILES covers every file that mirrors all registry keys", () => {
  assert.deepEqual(assertSelfFilesComplete(), [],
    "no unlisted file may mirror the full registry key set (would mask orphans)");
  // And SELF_FILES is exactly the registry+driver+test trio.
  assert.deepEqual([...SELF_FILES].sort(), [
    "mcp/lib/invariant-registry.js",
    "scripts/check-invariant-registry.js",
    "test/invariant-registry-orphan.test.js",
  ].sort());
});

test("every allowlisted tag still appears in the tree (allowlist only shrinks)", () => {
  const { byTag } = run();
  for (const tag of ALLOWLIST_UNDOCUMENTED) {
    assert.ok(byTag.has(tag), `stale allowlist entry: ${tag} no longer in tree`);
  }
});
