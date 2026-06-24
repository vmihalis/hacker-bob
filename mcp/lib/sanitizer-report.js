"use strict";

// Sanitizer-report parser — the byte-truth primitive for the OSS native-code
// reproduction gate (repro-replay-verifier.js). It derives crash truth from the
// bytes a run actually emitted, NEVER from a self-reported field (an evaluator's
// fuzz_stats.crashes or a claim's response_evidence are command-controlled and
// printf-forgeable). The differential verifier parses the bytes IT captured from
// its OWN fresh re-runs, so the verdict cannot be hand-authored.
//
// Single source of truth: MEMORY_SAFETY_SIGNAL_RE is the canon shared with
// repo-env.js fuzz_stats (crashSeen) so detection never diverges between the
// fuzz-stats path and the proof-contract path.

// A sanitizer / libFuzzer memory-safety crash signal. Matches the
// ASAN/UBSan/MSan/TSan/LSan banners (in their ERROR: and WARNING: banner forms),
// libFuzzer's own error line, a written crash artifact, or a dedup token. Presence
// means "a crash-shaped signal was emitted" — necessary but NOT sufficient for a
// verified reproduction (the verifier additionally requires a /src-resolved frame
// AND a differential vuln-vs-fix flip). TSan/MSan emit a "WARNING:" banner rather
// than "==N==ERROR:", and MSan's body phrase "use-of-uninitialized-value" is matched
// directly so an MSan report routes even if the banner line is truncated.
const MEMORY_SAFETY_SIGNAL_RE = /(?:==\d+==\s*(?:ERROR|WARNING):\s*(?:AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|ThreadSanitizer|LeakSanitizer)|WARNING:\s*(?:ThreadSanitizer|MemorySanitizer):|ERROR:\s*libFuzzer:|use-of-uninitialized-value|Test unit written to|crash-[0-9a-f]{8,}|DEDUP_TOKEN:)/i;

// Structured sanitizer banner. ASAN/LSan emit "==1==ERROR: AddressSanitizer: <klass> ..."
// while TSan/MSan emit a "WARNING:" banner (TSan with the "==N==" pid prefix, MSan
// without) — so both ERROR and WARNING are accepted, and the "==N==" prefix is
// optional. <klass> is the issue family ("heap-buffer-overflow", "data race",
// "use-of-uninitialized-value") used by the §4.3 type gate.
const BANNER_RE = /(?:==\d+==\s*)?(?:ERROR|WARNING):\s*(?<san>[A-Za-z]+Sanitizer):\s*(?<klass>.+?)(?=\s+on\b|\s+at\b|\s*\(|\s*$)/;
// UBSan: "file.c:12:34: runtime error: ...". The captured file:line is the
// attributable location even when UBSan prints no stack frames (its default).
const UBSAN_RE = /(?<file>\S+):(?<line>\d+):(?<col>\d+):\s*runtime error:/;
// libFuzzer deadly signal: "==1==ERROR: libFuzzer: deadly signal"
const LIBFUZZER_RE = /ERROR:\s*libFuzzer:\s*(?<klass>[A-Za-z][A-Za-z -]+?)(?:\s*$|\n)/;
// A backtrace frame. Two shapes are accepted:
//   ASAN/MSan/LSan/UBSan: "    #3 0x4a1b2c in func /src/foo.c:42:10"  ("in" optional)
//   TSan:                 "    #0 func /src/race.c:14:7 (mod+0x4a1b2c)" (NO 0x address)
// TSan omits the leading "0x<addr> in" and appends "(<module>+<offset>)"; the head
// regex therefore makes the "0x<addr> [in]" prefix optional, and the source-tail
// regex below tolerates a trailing " (mod+off)".
const FRAME_HEAD_RE = /^\s*#(?<idx>\d+)\s+(?:0x[0-9a-fA-F]+\s+(?:in\s+)?)?(?<rest>.*\S)\s*$/;
// Frame tail with a source location: "<func> /src/path:line[:col]" with an optional
// trailing " (<module>+<offset>)" that TSan appends after the source location.
const FRAME_SRC_RE = /^(?<func>.+?)\s+(?<file>\/\S+?):(?<line>\d+)(?::\d+)?(?:\s+\([^)]+\))?$/;

// A crash frame is "repo-attributable" only when its source path is NOT a system
// header, libc, or sanitizer-runtime location. The authoritative root-cause frame
// (src_frame) is the first repo-attributable frame, so a crash rooted only in
// /usr/include or the ASan runtime cannot masquerade as a repo bug.
const SYSTEM_FRAME_DENYLIST = [
  /^\/usr\//,
  /^\/lib\//,
  /\/compiler-rt\//,
  /\/llvm-project\//,
];
function isRepoAttributableFrame(sourcePath) {
  return typeof sourcePath === "string" && !SYSTEM_FRAME_DENYLIST.some((re) => re.test(sourcePath));
}
// Frame tail in a shared object: "<func> (/lib/x86_64-linux-gnu/libc.so.6+0x2083f)".
const FRAME_LIB_RE = /^(?<func>.+?)\s+\((?<module>[^)]+)\)$/;

const SANITIZER_CANON = {
  addresssanitizer: "asan",
  undefinedbehaviorsanitizer: "ubsan",
  memorysanitizer: "msan",
  threadsanitizer: "tsan",
  leaksanitizer: "lsan",
  libfuzzer: "libfuzzer",
};

function detectCrash(text) {
  return typeof text === "string" && MEMORY_SAFETY_SIGNAL_RE.test(text);
}

function parseFramesAfter(lines, bannerIdx) {
  const frames = [];
  let started = false;
  for (let i = bannerIdx + 1; i < lines.length; i++) {
    const head = FRAME_HEAD_RE.exec(lines[i]);
    if (head) {
      started = true;
      const rest = head.groups.rest;
      let func = rest;
      let sourcePath = null;
      let line = null;
      let module = null;
      const src = FRAME_SRC_RE.exec(rest);
      if (src) {
        func = src.groups.func;
        sourcePath = src.groups.file;
        line = Number(src.groups.line);
      } else {
        const lib = FRAME_LIB_RE.exec(rest);
        if (lib) {
          func = lib.groups.func;
          module = lib.groups.module;
        }
      }
      frames.push({ idx: Number(head.groups.idx), func: func.trim(), source_path: sourcePath, line, module });
    } else if (started) {
      // First non-frame line ends the (first) crash trace; secondary
      // "allocated by"/"freed by" stacks are intentionally excluded.
      break;
    }
  }
  return frames;
}

// parseSanitizerReport(stderrText, stdoutText) -> structured crash verdict derived
// purely from captured bytes. Sanitizers write to stderr; stdout is scanned as a
// fallback. Returns:
//   { crashed, sanitizer, crash_class, top_frames[], src_frame }
// crash_class is lowercased for the §4.3 type gate. src_frame is the first
// REPO-ATTRIBUTABLE source frame (the allocator/intrinsic/system-header denylist
// walk above skips /usr, libc, and sanitizer-runtime frames) — the authoritative
// root-cause frame, so a crash rooted only in system code yields src_frame=null.
function parseSanitizerReport(stderrText, stdoutText) {
  const text = `${typeof stderrText === "string" ? stderrText : ""}\n${typeof stdoutText === "string" ? stdoutText : ""}`;
  const lines = text.split("\n");

  let sanitizer = null;
  let crashClass = null;
  let bannerIdx = null;
  // UBSan prints "<file>:<line>:<col>: runtime error: ..." and, in its DEFAULT
  // (non-halt) mode, NO backtrace frames. The banner line itself carries the
  // attributable source location, so capture it as a fallback src_frame — but only
  // a repo-attributable, /-rooted path counts (a "runtime error:" rooted in a
  // <stdin>/relative/system path yields no fallback, so a non-/src UBSan line stays
  // unattributable and is REFUTED by the differential, not minted).
  let ubsanFallbackFrame = null;

  for (let i = 0; i < lines.length; i++) {
    const m = BANNER_RE.exec(lines[i]);
    if (m) { sanitizer = m.groups.san; crashClass = m.groups.klass; bannerIdx = i; break; }
  }
  if (bannerIdx === null) {
    for (let i = 0; i < lines.length; i++) {
      const m = UBSAN_RE.exec(lines[i]);
      if (m) {
        sanitizer = "UndefinedBehaviorSanitizer";
        crashClass = "runtime-error";
        bannerIdx = i;
        const file = m.groups.file;
        if (file && file.startsWith("/") && isRepoAttributableFrame(file)) {
          ubsanFallbackFrame = {
            idx: 0,
            func: null,
            source_path: file,
            line: Number(m.groups.line),
            module: null,
          };
        }
        break;
      }
    }
  }
  if (bannerIdx === null) {
    for (let i = 0; i < lines.length; i++) {
      const m = LIBFUZZER_RE.exec(lines[i]);
      if (m) { sanitizer = "libFuzzer"; crashClass = m.groups.klass.trim(); bannerIdx = i; break; }
    }
  }

  const topFrames = bannerIdx === null ? [] : parseFramesAfter(lines, bannerIdx);
  const srcFrame = topFrames.find((f) => isRepoAttributableFrame(f.source_path))
    || ubsanFallbackFrame
    || null;

  return {
    // A crash is real only with a structured banner; a bare MEMORY_SAFETY_SIGNAL
    // (e.g. a printf'd "DEDUP_TOKEN:") without a banner is NOT counted as crashed.
    crashed: bannerIdx !== null,
    sanitizer: sanitizer ? (SANITIZER_CANON[sanitizer.toLowerCase()] || sanitizer.toLowerCase()) : null,
    crash_class: crashClass ? crashClass.toLowerCase() : null,
    top_frames: topFrames,
    src_frame: srcFrame,
  };
}

module.exports = {
  MEMORY_SAFETY_SIGNAL_RE,
  detectCrash,
  parseSanitizerReport,
};
