"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  detectCrash,
  parseSanitizerReport,
  MEMORY_SAFETY_SIGNAL_RE,
} = require("../mcp/lib/sanitizer-report.js");

// The real ASAN report from the live oracle re-execution of ARVO case 25402
// (muparser/oss-fuzz-25402), trimmed to the crash banner + top frames.
const MUPARSER_ASAN = `==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x511000000280 at pc 0x...
READ of size 8 at 0x511000000280 thread T0
    #0 0x4f1c2a in mu::ParserBase::ParseCmdCodeBulk(int, int) const /src/muparser/src/muParserBase.cpp:1242:10
    #1 0x4f0a1b in mu::ParserBase::ParseString() const /src/muparser/src/muParserBase.cpp:1520:12
    #2 0x4d3e90 in LLVMFuzzerTestOneInput /src/set_eval_fuzzer.cc:27:3
    #14 0x712c6581e83f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2083f)
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/muparser/src/muParserBase.cpp:1242:10 in mu::ParserBase::ParseCmdCodeBulk(int, int) const`;

test("parses a real ASAN crash: class + sanitizer + /src root-cause frame", () => {
  const r = parseSanitizerReport(MUPARSER_ASAN, "");
  assert.equal(r.crashed, true);
  assert.equal(r.sanitizer, "asan");
  assert.equal(r.crash_class, "heap-buffer-overflow");
  assert.ok(r.src_frame, "a /src-resolved frame is found");
  assert.equal(r.src_frame.source_path, "/src/muparser/src/muParserBase.cpp");
  assert.equal(r.src_frame.line, 1242);
  assert.match(r.src_frame.func, /ParseCmdCodeBulk/);
  // The libc lib frame is parsed as a module frame (no source_path).
  const libFrame = r.top_frames.find((f) => f.idx === 14);
  assert.equal(libFrame.source_path, null);
  assert.match(libFrame.module, /libc\.so/);
});

test("clean output: no crash, no signal", () => {
  const r = parseSanitizerReport("All tests passed\nctest: 12/12 OK", "");
  assert.equal(r.crashed, false);
  assert.equal(r.crash_class, null);
  assert.equal(r.src_frame, null);
  assert.equal(detectCrash("All tests passed\nctest: 12/12 OK"), false);
});

test("banner with no /src frame: crashed, but no source-resolved root cause", () => {
  // A banner whose only frame is in a shared object — crashed is true (a structured
  // banner exists) but src_frame is null. The differential verifier, not the parser,
  // is what defeats a printf-forged banner.
  const txt = "==2==ERROR: AddressSanitizer: SEGV on unknown address\n    #0 0x10 in (<unknown module>)";
  const r = parseSanitizerReport(txt, "");
  assert.equal(r.crashed, true);
  assert.equal(r.crash_class, "segv");
  assert.equal(r.src_frame, null);
});

test("UBSan runtime error is recognized", () => {
  const r = parseSanitizerReport("muParserBase.cpp:1242:10: runtime error: signed integer overflow", "");
  assert.equal(r.crashed, true);
  assert.equal(r.sanitizer, "ubsan");
  assert.equal(r.crash_class, "runtime-error");
});

test("a bare DEDUP_TOKEN signal (no banner) is a signal but NOT a parsed crash", () => {
  // detectCrash (the broad fuzz-stats canon) fires, but parseSanitizerReport needs a
  // structured banner to call it crashed — so a stray token can't masquerade as one.
  const txt = "DEDUP_TOKEN: operator new(unsigned long)--allocate";
  assert.equal(detectCrash(txt), true);
  assert.equal(parseSanitizerReport(txt, "").crashed, false);
});

test("stdout fallback: sanitizers usually write stderr, but stdout is also scanned", () => {
  const r = parseSanitizerReport("", MUPARSER_ASAN);
  assert.equal(r.crashed, true);
  assert.equal(r.crash_class, "heap-buffer-overflow");
});

test("MEMORY_SAFETY_SIGNAL_RE is exported as the shared canon", () => {
  assert.ok(MEMORY_SAFETY_SIGNAL_RE instanceof RegExp);
  assert.equal(MEMORY_SAFETY_SIGNAL_RE.test("==1==ERROR: AddressSanitizer: heap-buffer-overflow"), true);
});
