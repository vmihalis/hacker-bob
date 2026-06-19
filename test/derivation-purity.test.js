"use strict";

// Plane Y Cycle Y.4 Do step 6 — X-P4 lint scope extension.
//
// The Y.4 cycle adds two new caller-side modules — friction-selection.js
// (Y-P4 + Y-P6 + Y-P11) and target-class-pack-derivation.js (Y-P4 + O5)
// — both of which MUST stay pure (no clock / random / env / I/O) so the
// Y.5 wave-scheduler caller stays the only side-effecting site for
// friction selection and target_class threading.
//
// This file extends the purity-lint scope to cover both new modules and
// re-asserts the X.5 capability-pack-derivation.js guard for back-compat.
// Each new module ships its own load-time IIFE lint guard; this test file
// is the test-time mirror that:
//   - loads each module (so the IIFE runs and would throw on any
//     forbidden-pattern hit);
//   - re-runs the same regex sweep over each module's source (so a future
//     edit that smuggles a forbidden pattern is caught even if the IIFE
//     were bypassed by a bundler);
//   - positive-controls the regex set against a synthetic source string.
//
// Forbidden patterns (mirrored from X.5 + Y.4 IIFE guards):
//   `Date.`, `Date(`, `new Date`, `Math.random`, `process.env`,
//   `performance.now`.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

// Loading each module runs its IIFE lint guard. If the guard had tripped,
// the require() would throw at load time and this file wouldn't reach the
// test runner. The require itself is the first assertion.
require("../mcp/lib/capability-pack-derivation.js");
require("../mcp/lib/friction-selection.js");
require("../mcp/lib/target-class-pack-derivation.js");

const MODULES_UNDER_LINT = Object.freeze([
  {
    file: path.resolve(__dirname, "..", "mcp/lib/capability-pack-derivation.js"),
    divider: "─── Per-node-kind derivations ───",
    label: "capability-pack-derivation",
  },
  {
    file: path.resolve(__dirname, "..", "mcp/lib/friction-selection.js"),
    divider: "─── Pure friction selection ───",
    label: "friction-selection",
  },
  {
    file: path.resolve(__dirname, "..", "mcp/lib/target-class-pack-derivation.js"),
    divider: "─── Pure target-class derivation ───",
    label: "target-class-pack-derivation",
  },
]);

// Mirror the IIFE patterns. The `process.env` literal must NOT appear as a
// raw source token in this file (the in-source guard would reject the test
// file itself if it scanned us) — so we build the forbidden labels via
// concatenation, identically to how the guards in source build them.
const FORBIDDEN = Object.freeze([
  { re: new RegExp("\\b" + "Date" + "\\s*\\."), label: ["Date", "."].join("") },
  { re: new RegExp("\\b" + "Date" + "\\s*\\("), label: ["Date", "()"].join("") },
  { re: new RegExp("\\bnew\\s+" + "Date" + "\\b"), label: ["new ", "Date"].join("") },
  { re: new RegExp("\\b" + "Math" + "\\.random\\b"), label: ["Math", ".random"].join("") },
  { re: new RegExp("\\b" + "process" + "\\.env\\b"), label: ["process", ".env"].join("") },
  { re: new RegExp("\\b" + "performance" + "\\.now\\b"), label: ["performance", ".now"].join("") },
]);

function stripCommentsAndStrings(source) {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/[^\n]*/g, "")
    .replace(/"(?:\\.|[^"\\])*"/g, '""')
    .replace(/'(?:\\.|[^'\\])*'/g, "''")
    .replace(/`(?:\\.|[^`\\])*`/g, "``")
    .replace(/([=(,:&|!])\s*\/(?:\\.|\[(?:\\.|[^\]\\])*\]|[^/\\])+\/[a-z]*/g, "$1 /__re__/");
}

for (const mod of MODULES_UNDER_LINT) {
  test(`${mod.label}: source below divider contains no forbidden patterns`, () => {
    const source = fs.readFileSync(mod.file, "utf8");
    const dividerIdx = source.indexOf(mod.divider);
    assert.ok(dividerIdx > 0, `${mod.label}: lint divider "${mod.divider}" not found in source`);
    const body = source.slice(dividerIdx);
    const stripped = stripCommentsAndStrings(body);
    for (const { re, label } of FORBIDDEN) {
      assert.equal(
        re.test(stripped),
        false,
        `${mod.label}: forbidden pattern \`${label}\` MUST NOT appear in body below "${mod.divider}"`,
      );
    }
  });
}

test("load-time IIFE guard ran successfully for all three modules (re-require sanity)", () => {
  // Re-require to force the cache hit and confirm the modules export their
  // public surface. If the IIFE had thrown the first require would have
  // already failed the suite, but this catches a future regression where
  // a load-time guard is silenced.
  const m1 = require("../mcp/lib/capability-pack-derivation.js");
  const m2 = require("../mcp/lib/friction-selection.js");
  const m3 = require("../mcp/lib/target-class-pack-derivation.js");
  assert.equal(typeof m1.derivePackForNode, "function");
  assert.equal(typeof m2.selectRelevantFrictions, "function");
  assert.equal(typeof m3.deriveAuxiliaryToolsForTargetClass, "function");
});

test("FORBIDDEN regexes positive-control trip on synthetic forbidden source", () => {
  // Build trigger strings via concatenation so the literal `process.env`
  // token (etc.) never appears verbatim in this file's source. Mirrors
  // the IIFE guard's construction discipline.
  const triggers = [
    "Date" + ".now()",
    "Date" + "(1)",
    "new " + "Date()",
    "Math" + ".random()",
    "process" + ".env.HOME",
    "performance" + ".now()",
  ];
  for (let i = 0; i < FORBIDDEN.length; i++) {
    const synthetic = `function impure() { return ${triggers[i]}; }`;
    assert.ok(
      FORBIDDEN[i].re.test(synthetic),
      `FORBIDDEN[${i}] (${FORBIDDEN[i].label}) must trip on its synthetic trigger "${triggers[i]}"`,
    );
  }
});

test("FORBIDDEN regexes do NOT trip on harmless tokens (negative control)", () => {
  const harmless = [
    "const dateString = 'today';",
    "const d = { date_iso: '2025-01-01' };",
    "function mathRandomLooking() { return 0; }",
    "// Date.now in a comment is fine (lint strips comments).",
  ];
  for (const sample of harmless) {
    const stripped = stripCommentsAndStrings(sample);
    for (const { re } of FORBIDDEN) {
      assert.equal(re.test(stripped), false, `harmless sample tripped: ${sample}`);
    }
  }
});
