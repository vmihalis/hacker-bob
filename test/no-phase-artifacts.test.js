"use strict";

// Guards `check:no-phase-artifacts`: the diff-aware gate that keeps
// dev-narrative tokens out of ADDED lines. The broad narrative shapes are
// scanned in comments and test-name strings; the tight node-id-literal shape is
// scanned across the whole line so a node id hiding in a string literal,
// fixture name, or assert message is caught too. Asserts the live tree is
// clean, that planted narrative is caught (comment, test-name, AND string
// literal / assert message), and that the allowlist keeps registry/invariant
// tags, finding ids, domain chain-phase prose, and ordinary letter+digit
// identifiers from tripping the scan.

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  run,
  scanLine,
  scanSlice,
  narrativeSlices,
  parseAddedLines,
  normalizeDashes,
  isScannablePath,
} = require("../scripts/check-no-phase-artifacts.js");

test("the live working tree passes the gate (post-scrub, no narrative tokens)", () => {
  const { violations } = run();
  assert.deepEqual(
    violations,
    [],
    "gate must be green on the live tree:\n" +
      violations.map((v) => `  ${v.file}:${v.line} ${v.why} "${v.slice}"`).join("\n"),
  );
});

test("a planted dev-narrative comment is caught", () => {
  const planted = "  // Phase 3 wires the queue policy";
  const { violations } = run({ text: planted });
  assert.equal(violations.length, 1, "planted narrative must be flagged");
  assert.equal(violations[0].rule, "phase-number");
});

test("each forbidden token shape is caught in comment form", () => {
  const cases = [
    ["// Phase 4 of the rollout", "phase-number"],
    ["// Phase B consumers do X", "phase-letter"],
    ["  // Step B muscle", "step-letter"],
    ["// cycle 7 fix-up", "cycle-number"],
    ["// fixup for the gate", "fixup"],
    ["// brutalist roast caught X", "roast"],
    ["// YAGNI: dropped this", "yagni"],
    ["  // F1-a3 host registry", "leading-node-id"],
    ["// an unrelated template is the OW-idx quality risk", "node-id-ow"],
    ["// OW1 refuting-control gate refuses a lone pass", "node-id-ow"],
    ["// registered through the OW4 candidate feed", "node-id-ow"],
    ["// OW3-binding-precision binds the exact executed path", "node-id-ow"],
    ["// gated by the OW-D1 commit decision", "node-id-ow"],
    ["// UF2 fans one verifier triad per finding", "node-id-uf"],
    ["// the UF-meas twin-run measures width", "node-id-uf"],
  ];
  for (const [line, expectedRule] of cases) {
    const hit = scanLine(line);
    assert.ok(hit, `expected a hit on: ${line}`);
    assert.equal(hit.rule.id, expectedRule, `wrong rule for: ${line}`);
  }
});

test("node-id-ow: OWASP / window / below / grow-style words do NOT trip the OW rule", () => {
  const benign = [
    "// follows the OWASP top-ten guidance",
    "// closes the window before the next wave",
    "// see the note below on dedup",
    "// grow2 and flow3 are ordinary identifiers",
    "const workflow = buildWorkflow();",
    "// encode the UTF-8 buffer before hashing",
    "const stuff = collectStuff();",
  ];
  for (const line of benign) {
    assert.equal(scanLine(line), null, `benign OW/UF-adjacent line must pass: ${line}`);
  }
});

test("narrative tokens inside a test() name string are caught", () => {
  const hit = scanLine('test("Step A nesting works", () => {');
  assert.ok(hit, "test-name narrative must be flagged");
  assert.equal(hit.rule.id, "step-letter");
});

test("the scan is locale/dash-safe: a dash-joined label still matches", () => {
  assert.equal(normalizeDashes("Step—B"), "Step-B");
  const hit = scanLine("// Step—B em-dash boundary");
  assert.ok(hit, "an em-dash-joined Step-B must be flagged after normalization");
  assert.equal(hit.rule.id, "step-letter");
});

test("allowlist: registry/invariant tags and finding ids do NOT trip the scan", () => {
  const legit = [
    "// I6 reopenability back-edge holds",
    "// gated by Y-D15b composition path",
    "// X.6 cross-stack object-auth guard",
    "// INV-7 invariant enforced here",
    "// R2-HIGH finding recorded in the ledger",
    "// T-R1 task-graph reachability tag",
  ];
  for (const line of legit) {
    assert.equal(scanLine(line), null, `legit tag must pass: ${line}`);
  }
});

test("allowlist: domain chain-phase F1/F2 prose passes; bare node-id label fails", () => {
  assert.equal(
    scanLine("// F1 chain reachability leaf is covered"),
    null,
    "domain F1 chain-phase prose must pass",
  );
  // A leading bare node id with NO rescuing tag is narrative and must fail.
  const hit = scanLine("  // F1-a3 host registry wiring");
  assert.ok(hit, "a bare F1-a3 node-id label must be flagged");
});

test("precision: plain prose and code identifiers do NOT trip the scan", () => {
  const benign = [
    "// the web pack stays on the legacy spawn body",
    "// step aside from the queue when the budget is exhausted",
    "// the two-step auth flow stores a cookie",
    "const phaserConfig = loadConfig();",
    "  return covered.size === fixpoint.size; // covered-set-at-fixpoint",
    'test("covered-set-at-fixpoint holds under reorder", () => {',
  ];
  for (const line of benign) {
    assert.equal(scanLine(line), null, `benign line must pass: ${line}`);
  }
});

test("node-id-literal: a session node id hiding in a string literal / fixture / assert message is caught", () => {
  const cases = [
    ['const home = mkdtempSync(join(tmpdir(), "bob-g4-crossband-"));', "node-id-literal"], // tmpdir prefix
    ['const domain = "g6-band.example.com";', "node-id-literal"], // fake domain
    ['assert.ok(ok, "the g7 leak guard holds");', "node-id-literal"], // assert message
    ['"... a module (else the g3 wall is vacuous)",', "node-id-literal"], // assert message, mid-string
    ['const label = "F1-a3";', "node-id-literal"], // hyphen-joined node id in a literal
    ['const p = "bob-g5-completeness-";', "node-id-literal"],
  ];
  for (const [line, expectedRule] of cases) {
    const hit = scanLine(line);
    assert.ok(hit, `expected a node-id-literal hit on: ${line}`);
    assert.equal(hit.rule.id, expectedRule, `wrong rule for: ${line}`);
  }
});

test("node-id-literal: ordinary letter+digit identifiers and domain F1/F2 prose do NOT trip the scan", () => {
  const benign = [
    'const everything200 = async ({ url }) => ok({ id: "x", url });',
    'assert.ok(voi > 1.5, "uniform belief over 3 states ~ log2(3)");',
    "if (p > 0) result -= p * Math.log2(p);",
    'const sha = "sha256";',
    'const h = "http200-ok";',
    'const note = "log g level events were emitted";', // "g level" is not a gN node id
    "// F1 chain reachability leaf is covered", // domain phase prose, allowlisted
    'const e = "effect:unauth_succeeds_where_auth_blocked:victim";',
  ];
  for (const line of benign) {
    assert.equal(scanLine(line), null, `benign line must pass: ${line}`);
  }
});

test("leading-node-id: the C-number arm is intentionally absent (every C-digit is an allowlisted registry tag)", () => {
  // A leading `C9` comment is NOT flagged: the `[SICX]-?\d` registry family
  // allowlists every `C\d`, so a `C\d` arm in leading-node-id would be dead. The
  // F1-a / g node-id families (no registry homonym) ARE still caught.
  assert.equal(scanLine("  // C9 wires the queue policy"), null, "a leading C9 is an allowlisted registry tag");
  assert.equal(scanLine("  // C2 invariant enforced here"), null, "C2 registry tag passes");
  assert.ok(scanLine("  // g4 host registry wiring"), "a leading g4 node id is still flagged");
  assert.ok(scanLine("  // F1-a3 host registry"), "a leading F1-a3 node id is still flagged");
});

test("narrativeSlices extracts only comments and test-name strings", () => {
  assert.deepEqual(narrativeSlices("const x = 1;"), []);
  assert.deepEqual(narrativeSlices("const x = 1; // a note"), [" a note"]);
  assert.ok(narrativeSlices('it("does a thing", () => {}').includes("does a thing"));
  // A bare code string is NOT a narrative slice.
  assert.deepEqual(narrativeSlices('const s = "Phase 3";'), []);
});

test("scanSlice does not flag a narrative token that only lives in non-comment code", () => {
  // The forbidden token appears as a plain string literal, not a comment/test
  // name, so the line yields no narrative slice and is not flagged.
  assert.equal(scanLine('const label = "Phase 3";'), null);
});

test("diff parser maps ADDED lines to correct new-side line numbers", () => {
  const diff = [
    "diff --git a/foo.js b/foo.js",
    "index 1111111..2222222 100644",
    "--- a/foo.js",
    "+++ b/foo.js",
    "@@ -10,0 +11,2 @@",
    "+// Phase 5 narrative",
    "+const ok = true;",
  ].join("\n");
  const added = parseAddedLines(diff);
  assert.equal(added.length, 2);
  assert.deepEqual(added[0], { file: "foo.js", lineNo: 11, text: "// Phase 5 narrative" });
  assert.equal(added[1].lineNo, 12);
});

test("isScannablePath scans source, skips narrative homes, fixtures, and non-source", () => {
  assert.equal(isScannablePath("mcp/core/io/paths.js"), true, "source is scanned");
  assert.equal(isScannablePath("CHANGELOG.md"), true, "CHANGELOG stays scanned");
  assert.equal(isScannablePath("README.md"), false, "README is a narrative home");
  assert.equal(isScannablePath("docs/capability-hypergraph.md"), false, "docs/ is a narrative home");
  assert.equal(isScannablePath("package.json"), false, "non-source file not scanned");
  // The gate's own fixture files are exempt — they hold planted narrative.
  assert.equal(isScannablePath("test/no-phase-artifacts.test.js"), false, "fixture file exempt");
  assert.equal(isScannablePath("scripts/check-no-phase-artifacts.js"), false, "the gate itself is exempt");
});

test("scanSlice surfaces the rule object with a human-readable reason", () => {
  const rule = scanSlice(" cycle 9 fixup");
  assert.ok(rule);
  assert.equal(typeof rule.why, "string");
  assert.ok(rule.why.length > 0);
});
