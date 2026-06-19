"use strict";

// B1a — the structured PoC recipe field. A finding self-describes the exact argv
// the reproduction verifier re-runs as the differential. Optional in the contract
// (the O-P4 claim gate enforces presence for high/critical native-code findings);
// here we only pin the shape + that it round-trips and never reshuffles dedupe ids.

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  normalizeFindingRecord,
  computeFindingDedupeKey,
  renderFindingMarkdownEntry,
} = require("../mcp/lib/finding-contracts.js");

const BASE = Object.freeze({
  id: "F-1",
  target_domain: "repo-muparser-abcd",
  title: "heap-buffer-overflow in ParseCmdCodeBulk",
  severity: "high",
  cwe: "CWE-787",
  endpoint: "src/muParserBase.cpp:1242",
  description: "An attacker-supplied expression overflows the bytecode buffer.",
  proof_of_concept: "Feed the crashing expression to the ASAN-instrumented harness.",
  validated: true,
});

function normalize(extra) {
  return normalizeFindingRecord({ ...BASE, ...extra });
}

test("repro_command_argv is null when absent (optional field)", () => {
  const finding = normalize({});
  assert.equal(finding.repro_command_argv, null);
});

test("a valid argv token array round-trips verbatim", () => {
  const argv = ["sh", "-lc", "g++ -fsanitize=address poc.cpp -o poc && ./poc crash.bin"];
  const finding = normalize({ repro_command_argv: argv });
  assert.deepEqual(finding.repro_command_argv, argv);
});

test("a non-array repro_command_argv is rejected", () => {
  assert.throws(() => normalize({ repro_command_argv: "sh -lc ./poc" }), /must be an array/);
});

test("an empty argv array is rejected", () => {
  assert.throws(() => normalize({ repro_command_argv: [] }), /non-empty argv/);
});

test("a non-string / empty token is rejected", () => {
  assert.throws(() => normalize({ repro_command_argv: ["sh", ""] }), /\[1\] must be a non-empty string/);
  assert.throws(() => normalize({ repro_command_argv: ["sh", 7] }), /\[1\] must be a non-empty string/);
});

test("an over-long argv (token count) is rejected", () => {
  const tooMany = Array.from({ length: 65 }, (_, i) => `tok${i}`);
  assert.throws(() => normalize({ repro_command_argv: tooMany }), /64 tokens or fewer/);
});

test("repro_command_argv does NOT change the dedupe key (excluded from allowlist)", () => {
  const without = computeFindingDedupeKey({ ...BASE });
  const withArgv = computeFindingDedupeKey({ ...BASE, repro_command_argv: ["sh", "-lc", "./poc"] });
  assert.equal(without, withArgv);
});

test("the markdown mirror renders the argv as JSON when present", () => {
  const md = renderFindingMarkdownEntry(normalize({ repro_command_argv: ["sh", "-lc", "./poc"] }));
  assert.match(md, /\*\*Repro Argv:\*\* `\["sh","-lc","\.\/poc"\]`/);
});
