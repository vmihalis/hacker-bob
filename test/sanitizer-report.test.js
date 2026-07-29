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

test("UBSan with no stack frames attributes via the runtime-error line's /src location", () => {
  // UBSan's DEFAULT (non-halt) mode prints "<file>:<line>:<col>: runtime error: ..."
  // and NO backtrace. The banner line itself is the attributable source location, so
  // src_frame is derived from it — otherwise a real UBSan finding would be REFUTED by
  // the differential for lacking a /src root-cause frame.
  const r = parseSanitizerReport(
    "/src/muparser/src/muParserBase.cpp:1242:10: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type int",
    "",
  );
  assert.equal(r.crashed, true);
  assert.equal(r.sanitizer, "ubsan");
  assert.equal(r.crash_class, "runtime-error");
  assert.ok(r.src_frame, "UBSan runtime-error line yields a /src src_frame");
  assert.equal(r.src_frame.source_path, "/src/muparser/src/muParserBase.cpp");
  assert.equal(r.src_frame.line, 1242);
});

test("UBSan rooted in a non-/src path stays unattributable (no false-quiet mint)", () => {
  // A "runtime error:" whose location is <stdin>/relative/system has no repo-attributable
  // /src frame; src_frame stays null so adjudicateDifferential REFUTES it as unattributable.
  const r = parseSanitizerReport("stdin:1:1: runtime error: load of misaligned address", "");
  assert.equal(r.crashed, true);
  assert.equal(r.sanitizer, "ubsan");
  assert.equal(r.src_frame, null);
});

test("UBSan with a stack prefers the stack frame over the banner-line fallback", () => {
  const r = parseSanitizerReport(
    "/src/foo.c:42:10: runtime error: signed integer overflow\n    #0 0x4a1b2c in compute /src/foo.c:42:10\n    #1 0x4d3e90 in LLVMFuzzerTestOneInput /src/harness.cc:27:3",
    "",
  );
  assert.equal(r.src_frame.func, "compute");
  assert.equal(r.src_frame.source_path, "/src/foo.c");
});

test("TSan data-race WARNING banner with no-0x frames: crashed + /src root-cause frame", () => {
  // TSan emits a "WARNING: ThreadSanitizer:" banner (not "==N==ERROR:") and frames of
  // the shape "#N <func> <file>:<line> (<module>+<offset>)" — no "0x<addr> in" prefix.
  const txt = [
    "==================",
    "WARNING: ThreadSanitizer: data race (pid=12)",
    "  Write of size 4 at 0x7b0400000040 by thread T1:",
    "    #0 increment /src/race.c:14:7 (race+0x4a1b2c)",
    "    #1 LLVMFuzzerTestOneInput /src/harness.cc:9 (race+0x5b2)",
  ].join("\n");
  const r = parseSanitizerReport(txt, "");
  assert.equal(r.crashed, true);
  assert.equal(r.sanitizer, "tsan");
  assert.equal(r.crash_class, "data race");
  assert.ok(r.src_frame);
  assert.equal(r.src_frame.func, "increment");
  assert.equal(r.src_frame.source_path, "/src/race.c");
  assert.equal(r.src_frame.line, 14);
});

test("MSan use-of-uninitialized-value WARNING banner: crashed + /src root-cause frame", () => {
  const txt = [
    "==1==WARNING: MemorySanitizer: use-of-uninitialized-value",
    "    #0 0x4a1b2c in parse /src/m.c:10:5",
    "    #1 0x4d3e90 in LLVMFuzzerTestOneInput /src/h.cc:3",
  ].join("\n");
  const r = parseSanitizerReport(txt, "");
  assert.equal(r.crashed, true);
  assert.equal(r.sanitizer, "msan");
  assert.equal(r.crash_class, "use-of-uninitialized-value");
  assert.equal(r.src_frame.source_path, "/src/m.c");
});

test("LSan leak banner: crashed + first /src-attributable allocation frame", () => {
  const txt = [
    "==1==ERROR: LeakSanitizer: detected memory leaks",
    "",
    "Direct leak of 8 byte(s) in 1 object(s) allocated from:",
    "    #0 0x4a1b2c in malloc",
    "    #1 0x4d3e90 in alloc_thing /src/leak.c:7:10",
  ].join("\n");
  const r = parseSanitizerReport(txt, "");
  assert.equal(r.crashed, true);
  assert.equal(r.sanitizer, "lsan");
  assert.equal(r.src_frame.source_path, "/src/leak.c");
});

test("MEMORY_SAFETY_SIGNAL_RE recognizes TSan/MSan WARNING banners", () => {
  assert.equal(MEMORY_SAFETY_SIGNAL_RE.test("WARNING: ThreadSanitizer: data race"), true);
  assert.equal(MEMORY_SAFETY_SIGNAL_RE.test("==1==WARNING: MemorySanitizer: use-of-uninitialized-value"), true);
  assert.equal(MEMORY_SAFETY_SIGNAL_RE.test("==1==ERROR: LeakSanitizer: detected memory leaks"), true);
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
