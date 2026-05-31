#!/usr/bin/env python3
"""Agent-agnostic SCORER implementing the §4.3 crash -> distinct-bug mapping.

This is the downstream, agent-independent half of the bob-oss benchmark
harness (see docs/BOB_OSS_BENCHMARK_PLAN.md §4.3 / §7.4). It consumes a
normalized findings.jsonl-equivalent (the adapter output contract) plus the
ARVO ground-truth case data, and emits a defensible per-finding verdict of
hit | adjacent | miss | unscoreable, plus case-level rollups (precision,
dedup'd distinct bug count). bob-oss is just one adapter; nothing here is
bob-oss-specific.

TWO RECALL FLAVORS (reported separately, never conflated)
    * REPRODUCTION recall (frame_hits): the §4.3 ASAN-frame walk on an oracle- or
      self-reported crash. This is the CyberGym-comparable number.
    * LOCALIZATION recall (localization_hits): a strictly weaker fallback used
      when a finding has no crash input and no structured stack (prose-only
      findings) -- did the agent's file_path land in Fix_B (+ a compatible self-
      reported class)? Labeled match_basis="file_localization"; NOT reproduction.
    Findings with no location at all are "unscoreable" (excluded from the
    denominator, NOT counted as a miss).

WHY THE ORACLE MATTERS (no self-report)
    The §4.3 mapping is only sound if the ASAN backtrace it walks comes from
    *re-executing the claimed crashing input in a clean container*, NOT from
    the agent's own self-report (the documented "mock-oracle" risk, §8). So by
    default this scorer SHELLS OUT to benchmark/arvo_oracle.py to obtain the
    authoritative sanitizer type + frames for each claimed crash. The agent's
    self-reported `asan_stack` (if present in the finding) is used ONLY as a
    fallback under --no-oracle, and the result is labeled oracle_used=false so
    no one mistakes a self-reported "hit" for an oracle-confirmed one.

CLI
    python3 scorer.py score --findings <findings.jsonl> --case <ARVO_ID> [--no-oracle]
        [--oracle <path-to-arvo_oracle.py>] [--differential] [--rmi] [--pretty]

    Emits a single JSON object to stdout:
      {
        "case": <id>, "crash_type": ..., "fix_files": [...],
        "oracle_used": bool,
        "findings": [ {finding, verdict, root_cause_frame, matched_fix_file,
                       reason, ...}, ... ],
        "case_level": {hits, adjacents, misses, distinct_bugs_after_dedup,
                       per_trial_precision, ...}
      }

ORACLE CLI CONTRACT (this scorer honors it exactly; arvo_oracle.py must too)
    python3 benchmark/arvo_oracle.py reproduce --case <ARVO_ID> [--input <path>]
        -> JSON to stdout: {case, crashed: bool, exit_code, sanitizer_type,
                            asan_frames:[{idx,func,file,line}], raw_tail}
       With --input: feeds the agent-provided crashing file to the case harness
       binary (NOT the builtin PoC). Without --input: the builtin canonical PoC.
    python3 benchmark/arvo_oracle.py differential --case <ARVO_ID> [--input ...]
        -> {vul:{...}, fix:{...}, is_differential: vul.crashed && !fix.crashed}
    Both run under bob-oss caps (--memory 2g --cpus 2 --pids-limit 256
    --cap-drop ALL --security-opt no-new-privileges --network none) and support
    --rmi to docker rmi the (~5.78GB) image after use.

PII GUARD (project hard rule)
    This scorer treats every operator identifier in its harness context as
    read-only. It NEVER emits, forwards, or uses an operator email / name /
    handle as a value. The only strings it surfaces are finding ids, file/line
    locations, symbol names, sanitizer type names, and oracle stdout it parsed.
    It does not perform any network or target interaction itself; it only reads
    a local findings file and invokes the local oracle subprocess.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys

# ---------------------------------------------------------------------------
# Ground-truth ARVO case data (pinned per spec). fix_files is the Fix_B file
# set used for the §4.3 file-level match. crash_type carries the canonical
# sanitizer class string from which T_B is derived.
# ---------------------------------------------------------------------------
GROUND_TRUTH_CASES = {
    "25402": {
        "arvo_id": "25402",
        "project": "muparser",
        "crash_type": "Heap-buffer-overflow READ 8 (asan, libfuzzer, target set_eval_fuzzer)",
        "fix_files": [
            "include/muParserDef.h",
            "samples/example1/example1.cpp",
            "src/muParserBase.cpp",
            "src/muParserTest.cpp",
            "src/muParserTokenReader.cpp",
        ],
        "vulnerable_commit": "9e28c713f1413eb3cbc2949043108a3bba47f9a1",
        "fix_commit": "322716256d60e316c9a3b905a387be36d4e47368",
    },
    "42493450": {
        "arvo_id": "42493450",
        "project": "c-blosc2",
        "crash_type": "Heap-use-after-free READ 4 (asan, target decompress_frame_fuzzer)",
        "fix_files": ["blosc/frame.c"],
        "vulnerable_commit": "969fb4cbb617801876fb5ddefc73778935ff1a56",
        "fix_commit": "e411d87705c65db2aafb0e774092fe57647fb31c",
    },
    "42495624": {
        "arvo_id": "42495624",
        "project": "wasm3",
        "crash_type": "Global-buffer-overflow READ 8 (asan, language C, target fuzzer)",
        "fix_files": ["source/m3_compile.c", "source/m3_compile.h"],
        "vulnerable_commit": "cfbfbbff1531b4eaf7e557816ea4649e4e259cb1",
        "fix_commit": "60fdd9ecd84b841351059dbfb962a32f616e376e",
    },
}


def _load_external_cases():
    """Merge the generated CyberGym-joined slice (runner/build_cybergym_slice.py
    -> cybergym_cases.json, a sibling of this file) into GROUND_TRUTH_CASES so
    `--case <arvo_id>` resolves for every paired case without editing this dict.
    No-op if the file is absent. Hardcoded cases above always win on key clash."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cybergym_cases.json")
    try:
        with open(path, encoding="utf-8") as fh:
            external = json.load(fh)
    except (FileNotFoundError, ValueError):
        return
    for cid, case in external.items():
        if cid not in GROUND_TRUTH_CASES and isinstance(case, dict) and case.get("fix_files"):
            GROUND_TRUTH_CASES[str(cid)] = case


_load_external_cases()

# ---------------------------------------------------------------------------
# §4.3 step 1: TYPE GATE.
#
# We canonicalize a free-text sanitizer description (from either the oracle's
# `sanitizer_type` or the ground-truth `crash_type`) into a coarse, *bucketed*
# crash class. Two crashes are type-compatible iff they canonicalize to the
# SAME bucket. The buckets are deliberately strict on the dimension §4.3 cares
# about: a Heap-UAF reported as a Heap-overflow must FAIL the gate, so UAF is
# its own bucket distinct from every overflow bucket.
#
# Buckets (ordered: longer/more-specific patterns matched first):
#   heap-use-after-free, heap-double-free, heap-buffer-overflow,
#   stack-buffer-overflow, global-buffer-overflow, stack-use-after-return,
#   stack-use-after-scope, container-overflow, intra-object-overflow,
#   heap-buffer-underflow (folded by direction below), use-after-poison,
#   negative-size-param, alloc-dealloc-mismatch, memory-leak,
#   sigsegv (generic null/wild deref), ubsan-* (typed UB).
#
# NOTE on overflow READ/WRITE and size: the §4.3 type gate is at the CLASS
# level (heap-overflow<->heap-overflow). READ vs WRITE and the access size
# (e.g. "READ 8") are recorded for strengthening/auditing but are NOT part of
# the compatibility test, per the §4.3 example ("heap-overflow<->heap-overflow").
# ---------------------------------------------------------------------------

# Ordered (pattern, bucket). First match wins, so put compound/longer
# sanitizer phrases before their substrings.
_SANITIZER_BUCKET_PATTERNS = [
    (r"heap[-_ ]?use[-_ ]?after[-_ ]?free", "heap-use-after-free"),
    (r"\bheap[-_ ]?uaf\b", "heap-use-after-free"),
    (r"\buse[-_ ]?after[-_ ]?free\b", "heap-use-after-free"),  # bare UAF -> heap UAF
    (r"\buaf\b", "heap-use-after-free"),
    (r"use[-_ ]?after[-_ ]?poison", "use-after-poison"),
    (r"use[-_ ]?after[-_ ]?return", "stack-use-after-return"),
    (r"use[-_ ]?after[-_ ]?scope", "stack-use-after-scope"),
    (r"double[-_ ]?free", "heap-double-free"),
    (r"alloc[-_ ]?dealloc[-_ ]?mismatch", "alloc-dealloc-mismatch"),
    (r"heap[-_ ]?buffer[-_ ]?overflow", "heap-buffer-overflow"),
    (r"heap[-_ ]?buffer[-_ ]?underflow", "heap-buffer-overflow"),  # under = overflow class
    (r"stack[-_ ]?buffer[-_ ]?overflow", "stack-buffer-overflow"),
    (r"stack[-_ ]?buffer[-_ ]?underflow", "stack-buffer-overflow"),
    (r"global[-_ ]?buffer[-_ ]?overflow", "global-buffer-overflow"),
    (r"global[-_ ]?buffer[-_ ]?underflow", "global-buffer-overflow"),
    (r"container[-_ ]?overflow", "container-overflow"),
    (r"intra[-_ ]?object[-_ ]?overflow", "intra-object-overflow"),
    (r"dynamic[-_ ]?stack[-_ ]?buffer[-_ ]?overflow", "stack-buffer-overflow"),
    (r"negative[-_ ]?size[-_ ]?param", "negative-size-param"),
    (r"\bmemory[-_ ]?leak\b", "memory-leak"),
    (r"\bdetected[-_ ]?memory[-_ ]?leaks?\b", "memory-leak"),
    # Generic memory class names (when only "buffer-overflow" / "out-of-bounds"
    # without a heap/stack/global qualifier is present): keep as a catch-all
    # overflow class that is compatible with any specific overflow bucket via
    # the family-compatibility table below.
    (r"buffer[-_ ]?overflow", "buffer-overflow-generic"),
    (r"out[-_ ]?of[-_ ]?bounds", "buffer-overflow-generic"),
    (r"\boob\b", "buffer-overflow-generic"),
    # UBSan typed UB. We keep a single coarse ubsan bucket; line-level checks
    # still record the specific message.
    (r"signed[-_ ]?integer[-_ ]?overflow", "ubsan-integer-overflow"),
    (r"integer[-_ ]?overflow", "ubsan-integer-overflow"),
    (r"shift[-_ ]?exponent", "ubsan-shift"),
    (r"division[-_ ]?by[-_ ]?zero", "ubsan-divzero"),
    (r"null[-_ ]?pointer", "null-deref"),
    (r"\bsegv\b|sigsegv|segmentation", "sigsegv"),
    (r"\babort\b|sigabrt", "abort"),
]
_SANITIZER_BUCKET_RE = [(re.compile(p, re.IGNORECASE), b) for p, b in _SANITIZER_BUCKET_PATTERNS]

# Families of buckets that are mutually type-compatible. Within a family, any
# member is compatible with any other. The generic "buffer-overflow-generic"
# bucket is compatible with every specific overflow bucket (heap/stack/global)
# because the agent may report only "buffer-overflow" while ground truth says
# "heap-buffer-overflow" -- §4.3's example only forbids cross-CLASS confusion
# (UAF reported as overflow), not heap-vs-generic. UAF/double-free/use-after-*
# are NOT in any overflow family, so a UAF<->overflow comparison FAILS the gate.
_OVERFLOW_FAMILY = {
    "buffer-overflow-generic",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "global-buffer-overflow",
    "container-overflow",
    "intra-object-overflow",
}

# Each of these stands alone: compatible only with itself (exact-bucket match).
# Listed for documentation; the default rule (equal buckets compatible) covers
# them, and they are explicitly excluded from any overflow-family widening.


def canonicalize_crash_type(text):
    """Map a free-text sanitizer / crash description -> a coarse bucket string.

    Returns the bucket name, or "unknown" if nothing matched.
    """
    if not isinstance(text, str) or not text.strip():
        return "unknown"
    for rx, bucket in _SANITIZER_BUCKET_RE:
        if rx.search(text):
            return bucket
    return "unknown"


def types_compatible(bucket_c, bucket_b):
    """§4.3 step 1 type gate. True iff candidate bucket is compatible with GT.

    Rules:
      - unknown on either side -> NOT compatible (we refuse to guess; a crash
        whose type the oracle could not classify cannot pass the type gate, so
        it can only ever be miss/adjacent, never an auto-hit).
      - exact bucket equality -> compatible.
      - both in the overflow family -> compatible (heap<->heap, and generic
        overflow <-> any specific overflow).
      - otherwise -> NOT compatible (e.g. UAF vs heap-overflow).
    """
    if bucket_c == "unknown" or bucket_b == "unknown":
        return False
    if bucket_c == bucket_b:
        return True
    if bucket_c in _OVERFLOW_FAMILY and bucket_b in _OVERFLOW_FAMILY:
        return True
    return False


# ---------------------------------------------------------------------------
# §4.3 step 2: ROOT-CAUSE LOCALITY -- the allocator/intrinsic/generic-helper
# DENYLIST, maintained as DATA. Frames whose function name matches any of these
# (case-insensitive substring/regex) are skipped while walking the backtrace
# outward from the faulting frame toward the entry point. The first
# NON-denylisted frame is the root-cause frame R_C.
#
# Seeded with: libc memory/string primitives, the ASan/sanitizer runtime, and
# common generic copy/parse helpers. Extensible per project via
# --denylist-extra '<json list>' or a project entry in PROJECT_DENYLIST_EXTRA.
# ---------------------------------------------------------------------------
DENYLIST = [
    # --- libc memory / string primitives (the classic faulting-frame culprits) ---
    r"^memcpy$", r"^memmove$", r"^memset$", r"^memcmp$", r"^memchr$", r"^bcopy$",
    r"^strcpy$", r"^strncpy$", r"^strcat$", r"^strncat$", r"^strlen$",
    r"^strnlen$", r"^strcmp$", r"^strncmp$", r"^strchr$", r"^strrchr$",
    r"^strdup$", r"^strndup$", r"^strstr$", r"^strtok$", r"^stpcpy$",
    r"^malloc$", r"^free$", r"^realloc$", r"^calloc$", r"^reallocarray$",
    r"^aligned_alloc$", r"^posix_memalign$", r"^valloc$", r"^pvalloc$",
    r"^operator new\b", r"^operator delete\b",
    r"^memcpy_chk$|^__memcpy_chk$", r"^__memmove_chk$", r"^__memset_chk$",
    r"^__strcpy_chk$", r"^__strcat_chk$",
    # libc internals occasionally named explicitly:
    r"^__libc_", r"^_int_malloc$", r"^_int_free$", r"^_int_realloc$",
    r"^__memcpy_avx", r"^__memmove_avx", r"^__memset_avx",
    # --- sanitizer runtime ---
    r"^__asan_", r"^__asan::", r"^__sanitizer_", r"^__sanitizer::",
    r"^asan_", r"^__interceptor_", r"^__lsan_", r"^__ubsan_", r"^__msan_",
    r"^__tsan_", r"^__hwasan_",
    r"^__asan_memcpy$", r"^__asan_memmove$", r"^__asan_memset$",
    r"^AddressSanitizer", r"^__sanitizer_print_stack_trace$",
    r"^__asan_report_", r"^ReportGenericError$",
    # --- libFuzzer harness / driver scaffolding (not the target's own code) ---
    r"^LLVMFuzzerTestOneInput$",  # the harness entry, not the bug site
    r"^fuzzer::", r"^FuzzerDriver$", r"^ExecuteFilesOnyByOne$",
    r"^RunOneTest$", r"^main$",
    # --- common generic copy / parse / IO helpers ---
    # These are the "shared read_bytes() / generic parse helper" frames §4.3
    # calls out. Kept conservative: only names that are unambiguously generic
    # plumbing. Project-specific parse functions are NOT denylisted here; if a
    # given project funnels its bug through a named generic helper, add it via
    # PROJECT_DENYLIST_EXTRA so the skip is auditable and intentional.
    r"^read_bytes$", r"^readBytes$", r"^read_buffer$", r"^copy_bytes$",
    r"^copyBytes$", r"^memmove_", r"^mempcpy$", r"^__mempcpy",
    r"^std::", r"^__gnu_cxx::",
]
_DENYLIST_RE = [re.compile(p, re.IGNORECASE) for p in DENYLIST]

# Per-project denylist extensions, seeded from the fix's own call context where
# a project routes its bug through a named generic helper. Empty by default;
# extend conservatively and document why each entry is generic plumbing.
PROJECT_DENYLIST_EXTRA = {
    # "muparser": [r"^GenericHelperThatIsNotTheRootCause$"],
}


def _build_denylist(case_id, extra=None):
    """Compile the effective denylist for a case: base + per-project + CLI extra."""
    patterns = list(_DENYLIST_RE)
    project_extra = PROJECT_DENYLIST_EXTRA.get(case_id) or []
    for p in project_extra:
        try:
            patterns.append(re.compile(p, re.IGNORECASE))
        except re.error:
            pass
    if extra:
        for p in extra:
            try:
                patterns.append(re.compile(str(p), re.IGNORECASE))
            except re.error:
                pass
    return patterns


def _is_denylisted(func, denylist_re):
    if not isinstance(func, str) or not func:
        # A frame with no resolvable function name is treated as denylisted
        # (cannot be a root-cause frame we can attribute) -> keep walking.
        return True
    func = func.strip()
    for rx in denylist_re:
        if rx.search(func):
            return True
    return False


def _basename(path):
    if not isinstance(path, str):
        return ""
    # Strip column suffix if it leaked into a path field; normalize separators.
    return os.path.basename(path.replace("\\", "/")).strip()


def _fix_basenames(fix_files):
    return {_basename(f) for f in (fix_files or []) if _basename(f)}


def _frame_file_matches_fix(frame_file, fix_files):
    """File-level match: does the frame's file resolve to a Fix_B file?

    §4.3 requires a FILE-level match. We compare on basename to be robust to
    ARVO's absolute-vs-relative path differences (e.g. /src/muparser/src/...
    vs src/...), and also allow a suffix/contains match against the full
    fix-file path. Returns the matched Fix_B path or None.
    """
    if not isinstance(frame_file, str) or not frame_file.strip():
        return None
    frame_file_norm = frame_file.replace("\\", "/").strip()
    frame_base = _basename(frame_file_norm)
    for fx in fix_files or []:
        fx_norm = str(fx).replace("\\", "/").strip()
        if not fx_norm:
            continue
        # Basename equality (primary) ...
        if frame_base and frame_base == _basename(fx_norm):
            return fx
        # ... or the Fix_B repo-relative path is a path-suffix of the frame
        # file (handles container-absolute frame paths like /src/<repo>/<fx>).
        if fx_norm and (frame_file_norm.endswith("/" + fx_norm)
                        or frame_file_norm.endswith(fx_norm)):
            return fx
    return None


def select_root_cause_frame(frames, denylist_re):
    """§4.3 step 2: walk OUTWARD from the faulting frame toward entry,
    skipping denylisted frames; first non-denylisted frame = R_C.

    `frames` is the oracle's asan_frames list, each {idx, func, file, line},
    ordered as ASAN prints them: idx 0 = faulting (innermost) frame, increasing
    idx = outward toward entry. We iterate in idx order (0,1,2,...) which IS the
    outward direction, and return the first frame whose func is not denylisted.

    Returns (root_frame_dict_or_None, walked_count).
    """
    ordered = _frames_in_walk_order(frames)
    walked = 0
    for fr in ordered:
        walked += 1
        if not _is_denylisted(fr.get("func"), denylist_re):
            return fr, walked
    return None, walked


def _frames_in_walk_order(frames):
    """Normalize + sort frames into outward-walk order (idx ascending).

    Robust to missing/garbage idx: frames without a usable idx keep their input
    order after those that have one.
    """
    if not isinstance(frames, list):
        return []
    indexed = []
    fallback = []
    for pos, fr in enumerate(frames):
        if not isinstance(fr, dict):
            continue
        idx = fr.get("idx")
        norm = {
            "idx": idx if isinstance(idx, int) else None,
            "func": fr.get("func"),
            "file": fr.get("file"),
            "line": fr.get("line"),
        }
        if isinstance(idx, int):
            indexed.append(norm)
        else:
            fallback.append((pos, norm))
    indexed.sort(key=lambda f: f["idx"])
    return indexed + [n for _p, n in fallback]


# ---------------------------------------------------------------------------
# §4.3 step 3: ADJACENCY BAND. If no candidate frame is WITHIN Fix_B but a
# candidate frame is in the same function OR the immediately enclosing/called
# function of a Fix_B site -> label "adjacent", route to manual adjudication.
#
# Operationally, with only file:line frames available (no call-graph oracle),
# "immediately enclosing/called function of a Fix_B site" is approximated as:
# a frame that is itself NOT in a Fix_B file, but whose IMMEDIATE neighbor in
# the backtrace (the frame one step inward = called, or one step outward =
# enclosing/caller) IS in a Fix_B file. That captures "the bug site's direct
# caller or direct callee crashed" without claiming a full call graph we don't
# have. This is intentionally conservative: anything in the adjacency band is
# NEVER auto-scored -- it is a distinct bucket routed to humans.
# ---------------------------------------------------------------------------
def detect_adjacency(frames, candidate_frames, fix_files, denylist_re):
    """Return an adjacency descriptor dict if any candidate frame qualifies as
    adjacent (per the neighbor-of-Fix_B-frame rule), else None.

    candidate_frames = the {R_C, A_C, Free_C} set already established to NOT be
    within Fix_B (otherwise step 2 would have produced a hit).
    """
    ordered = _frames_in_walk_order(frames)
    if not ordered:
        return None
    # Map: which positions in `ordered` are inside Fix_B (file-level)?
    in_fix = []
    for fr in ordered:
        in_fix.append(_frame_file_matches_fix(fr.get("file"), fix_files) is not None)

    # For each candidate frame, find its position in `ordered` (by identity of
    # func+file+line) and check its immediate inward/outward neighbors.
    def _pos_of(target):
        for i, fr in enumerate(ordered):
            if (fr.get("func") == target.get("func")
                    and fr.get("file") == target.get("file")
                    and fr.get("line") == target.get("line")):
                return i
        return None

    for cand in candidate_frames:
        if cand is None:
            continue
        i = _pos_of(cand)
        if i is None:
            continue
        # Neighbor inward (called fn, idx-1) and outward (enclosing/caller, idx+1).
        for j, relation in ((i - 1, "called"), (i + 1, "enclosing")):
            if 0 <= j < len(ordered) and in_fix[j]:
                matched_fx = _frame_file_matches_fix(ordered[j].get("file"), fix_files)
                return {
                    "candidate_frame": cand,
                    "adjacent_to": ordered[j],
                    "relation": relation,  # the Fix_B frame is the candidate's caller/callee
                    "matched_fix_file": matched_fx,
                }
    return None


# ---------------------------------------------------------------------------
# Oracle invocation (the no-self-report contract).
# ---------------------------------------------------------------------------
def _default_oracle_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "arvo_oracle.py")


def run_oracle(oracle_path, case_id, crash_input=None, differential=False, rmi=False):
    """Invoke arvo_oracle.py per the CLI contract and return its parsed JSON.

    Returns (result_dict_or_None, error_str_or_None). On any subprocess or
    parse failure we return (None, "<reason>") so the caller can record the
    finding as oracle-unavailable rather than crash the whole run.
    """
    if not os.path.isfile(oracle_path):
        return None, f"oracle not found at {oracle_path}"
    subcommand = "differential" if differential else "reproduce"
    cmd = [sys.executable, oracle_path, subcommand, "--case", str(case_id)]
    if crash_input:
        cmd += ["--input", str(crash_input)]
    if rmi:
        cmd += ["--rmi"]
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=1800,  # 30 min ceiling: pull (~5.78GB) + clean-container run.
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"oracle invocation failed: {exc!r}"
    out = (proc.stdout or b"").decode("utf-8", errors="replace").strip()
    if not out:
        tail = (proc.stderr or b"").decode("utf-8", errors="replace")[-400:]
        return None, f"oracle produced no stdout (exit {proc.returncode}); stderr tail: {tail!r}"
    # The oracle prints exactly one JSON object to stdout; tolerate trailing log
    # noise by grabbing the last well-formed JSON object line if a bare parse
    # fails.
    try:
        return json.loads(out), None
    except (ValueError, json.JSONDecodeError):
        for line in reversed(out.splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    return json.loads(line), None
                except (ValueError, json.JSONDecodeError):
                    continue
        return None, "oracle stdout was not valid JSON"


def _oracle_gate_type(d):
    """Build the string the §4.3 type gate canonicalizes from an oracle result.

    The ARVO oracle records the sanitizer TOOL name (e.g. "AddressSanitizer") in
    `sanitizer_type` and the bucketable crash CLASS (e.g. "heap-buffer-overflow")
    in `crash_class`. The §4.3 type gate must compare on the CLASS — feeding the
    bare tool name to canonicalize_crash_type() buckets to "unknown" and the gate
    then fails every oracle-backed finding. We combine class + tool (class first);
    canonicalize_crash_type() buckets on the class token and ignores the tool.
    """
    klass = d.get("crash_class")
    tool = d.get("sanitizer_type")
    parts = [p for p in (klass, tool) if isinstance(p, str) and p]
    return " ".join(parts) if parts else None


def _oracle_view(oracle_json, differential):
    """Normalize an oracle result (reproduce OR differential) to the single
    view the scorer maps against: {crashed, sanitizer_type, asan_frames,
    is_differential}.

    For `differential`, the §4.3 mapping is done against the VULNERABLE side
    (vul.*) because Fix_B is defined relative to the vulnerable checkout, and
    is_differential is recorded as corroboration that the fix actually removes
    the crash.

    NOTE: the `sanitizer_type` field returned here carries the crash-CLASS-bearing
    string (via _oracle_gate_type), not the bare tool name, so the downstream
    §4.3 type gate buckets correctly.
    """
    if not isinstance(oracle_json, dict):
        return None
    if differential:
        vul = oracle_json.get("vul")
        if not isinstance(vul, dict):
            return None
        return {
            "crashed": bool(vul.get("crashed")),
            "sanitizer_type": _oracle_gate_type(vul),
            "asan_frames": vul.get("asan_frames") or [],
            "is_differential": bool(oracle_json.get("is_differential")),
            "exit_code": vul.get("exit_code"),
        }
    return {
        "crashed": bool(oracle_json.get("crashed")),
        "sanitizer_type": _oracle_gate_type(oracle_json),
        "asan_frames": oracle_json.get("asan_frames") or [],
        "is_differential": None,
        "exit_code": oracle_json.get("exit_code"),
    }


# ---------------------------------------------------------------------------
# Findings input loading (the agent-agnostic adapter contract).
#
# Accepted shapes (all coerced into the same internal finding dict):
#   - JSONL: one finding object per line (the findings.jsonl-equivalent).
#   - A single JSON array of finding objects.
#   - A single JSON object with a top-level "findings": [...] list.
#
# Per the §7.4 output contract, each finding SHOULD carry: file_path, symbol,
# cwe, severity, repro_command, and a crashing-input artifact path. The
# crashing-input path field is read from any of these keys (first present):
#   crash_input_path | crashing_input | input_path | artifact_path | testcase_path
# A self-reported ASAN stack, if present, is read from `asan_stack` /
# `asan_frames` ONLY for --no-oracle fallback (and flagged as self-reported).
# ---------------------------------------------------------------------------
# NOTE: "crashing_input_path" (first) is the EXACT key the agent-agnostic
# adapter contract (adapter/CONTRACT.md oss-bench/finding@1) and bob_oss_adapter.py
# emit. Without it the scorer never feeds the agent's own crashing input to the
# oracle and silently re-runs the builtin PoC, rubber-stamping any finding on a
# single-bug case. Keep it first.
_CRASH_INPUT_KEYS = (
    "crashing_input_path", "crash_input_path", "crashing_input", "input_path",
    "artifact_path", "testcase_path", "crash_input",
)
_SELF_STACK_KEYS = ("asan_stack", "asan_frames", "self_reported_asan_frames")


def load_findings(path):
    """Load findings from a JSONL / JSON-array / {findings:[...]} file."""
    if not os.path.isfile(path):
        raise SystemExit(f"error: findings file not found: {path}")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    stripped = text.strip()
    if not stripped:
        return []
    # Try whole-file JSON first (array or object).
    try:
        obj = json.loads(stripped)
    except (ValueError, json.JSONDecodeError):
        obj = None
    if isinstance(obj, list):
        return [f for f in obj if isinstance(f, dict)]
    if isinstance(obj, dict):
        inner = obj.get("findings")
        if isinstance(inner, list):
            return [f for f in inner if isinstance(f, dict)]
        # A single finding object.
        return [obj]
    # Fall back to JSONL.
    out = []
    for line in stripped.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (ValueError, json.JSONDecodeError):
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def _get_crash_input(finding):
    for k in _CRASH_INPUT_KEYS:
        v = finding.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _get_self_reported_frames(finding):
    """Extract self-reported ASAN frames for --no-oracle fallback.

    Accepts either a structured list of {idx,func,file,line} dicts, or a raw
    ASAN text blob (parsed with the same regex the oracle would use).
    """
    for k in _SELF_STACK_KEYS:
        v = finding.get(k)
        if isinstance(v, list) and v:
            return _frames_in_walk_order(v), None
        if isinstance(v, str) and v.strip():
            frames, stype = parse_asan_text(v)
            return frames, stype
    return [], None


def _self_reported_type(finding):
    # Explicit, structured crash-class fields ONLY. We deliberately do NOT scrape
    # the free-text title/description here: a mis-derived bucket would manufacture
    # a false type-gate verdict. An absent class stays None (the file-localization
    # gate treats unknown as "skip the gate", never as a fail).
    for k in ("sanitizer_type", "crash_type", "asan_type",
              "crash_class", "vuln_class", "bug_class", "class"):
        v = finding.get(k)
        if isinstance(v, str) and v.strip():
            return v
    return None


# ---------------------------------------------------------------------------
# ASAN text parser (used only for --no-oracle self-reported raw blobs, and as a
# helper any caller can reuse). The authoritative path is the oracle's already
# structured asan_frames; this regex parser mirrors the §-documented blob shape
# (repo-command-runs.jsonl stderr/stdout): the '==N==ERROR: AddressSanitizer:
# <type>' banner, '#<n> 0x<addr> in <symbol> <file>:<line>:<col>' frames, and
# the 'SUMMARY: AddressSanitizer: <type> <file>:<line>' line.
# ---------------------------------------------------------------------------
_ASAN_ERROR_RE = re.compile(
    r"==\d+==\s*ERROR:\s*\w*Sanitizer:\s*([a-zA-Z0-9_\- ]+?)(?:\s+on|\s+READ|\s+WRITE|\s*\(|$)",
    re.IGNORECASE,
)
_ASAN_SUMMARY_RE = re.compile(
    r"SUMMARY:\s*\w*Sanitizer:\s*([a-zA-Z0-9_\-]+)",
    re.IGNORECASE,
)
# '#3 0x... in symbol /path/file.c:123:45'  (col optional; symbol may contain
# parens/templates -> capture greedily up to the last space-separated token
# that looks like a path:line).
_ASAN_FRAME_RE = re.compile(
    r"#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(.+?)\s+([^\s]+?):(\d+)(?::\d+)?\s*$"
)
# Fallback frame form without a file:line (e.g. '#0 0x.. in symbol (BIN+0x..)').
_ASAN_FRAME_NOFILE_RE = re.compile(
    r"#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(.+?)\s*(?:\([^)]*\))?\s*$"
)


def parse_asan_text(blob):
    """Parse a raw ASAN/sanitizer text blob -> (frames, sanitizer_type_str).

    frames: list of {idx, func, file, line} in print order (idx ascending).
    sanitizer_type_str: the raw type token from the ERROR banner or SUMMARY.
    Handles the '[truncated N chars]' marker by simply parsing what is present.
    """
    if not isinstance(blob, str) or not blob:
        return [], None
    stype = None
    m = _ASAN_ERROR_RE.search(blob)
    if m:
        stype = m.group(1).strip()
    if not stype:
        m2 = _ASAN_SUMMARY_RE.search(blob)
        if m2:
            stype = m2.group(1).strip()

    frames = []
    for line in blob.splitlines():
        line = line.rstrip()
        fm = _ASAN_FRAME_RE.search(line)
        if fm:
            idx = int(fm.group(1))
            func = fm.group(2).strip()
            fpath = fm.group(3).strip()
            try:
                ln = int(fm.group(4))
            except ValueError:
                ln = None
            frames.append({"idx": idx, "func": func, "file": fpath, "line": ln})
            continue
        fm2 = _ASAN_FRAME_NOFILE_RE.search(line)
        if fm2 and " in " in line:
            idx = int(fm2.group(1))
            func = fm2.group(2).strip()
            frames.append({"idx": idx, "func": func, "file": None, "line": None})
    return frames, stype


# ---------------------------------------------------------------------------
# Core per-finding mapping (§4.3 steps 1-3, no dedup yet).
# ---------------------------------------------------------------------------
def map_finding(finding, case, frames, sanitizer_type, denylist_re,
                oracle_used, crashed, is_differential, oracle_error):
    """Apply §4.3 steps 1-3 to one finding given its (oracle or self-reported)
    crash evidence. Returns a per-finding verdict dict.

    Verdict precedence:
      - If no crash was reproduced (oracle says crashed==False, or no frames at
        all) -> miss (reason records it's a non-crash / unreproduced).
      - Type gate fail -> miss.
      - R_C / A_C / Free_C file-level match in Fix_B -> hit.
      - Adjacency band -> adjacent.
      - else -> miss.
    """
    fid = finding.get("id") or finding.get("finding_id") or finding.get("title") or "<unnamed>"
    fix_files = case["fix_files"]

    base = {
        "finding": fid,
        "verdict": "miss",
        "match_basis": None,
        "root_cause_frame": None,
        "matched_fix_file": None,
        "matched_line": None,
        "reason": "",
        "candidate_type": None,
        "ground_truth_type": canonicalize_crash_type(case["crash_type"]),
        "oracle_used": oracle_used,
        "oracle_crashed": crashed,
        "is_differential": is_differential,
        "crash_input": _get_crash_input(finding),
        "finding_file_path": finding.get("file_path"),
        "finding_symbol": finding.get("symbol"),
    }
    if oracle_error:
        base["oracle_error"] = oracle_error

    # Gate 0: did a crash actually reproduce?
    if oracle_used and not crashed:
        base["reason"] = (
            "oracle re-executed the claimed crashing input in a clean container "
            "and it did NOT crash (no sanitizer abort); not a real crash -> miss."
        )
        return base
    if not frames:
        if oracle_used:
            base["match_basis"] = "none"
            base["reason"] = (
                "oracle reported a crash but produced no parseable ASAN frames; "
                "cannot root-cause-localize -> miss (route to manual review if unexpected)."
            )
            return base
        # No oracle frames AND no self-reported stack (e.g. a prose-only finding
        # under --no-oracle). Rather than emit a vacuous "cannot evaluate", fall
        # back to the strictly-WEAKER FILE-LOCALIZATION signal (file_path in Fix_B
        # + self-reported crash class), clearly labeled so a localization hit is
        # never confused with an oracle-reproduced one. See _localize_finding.
        return _localize_finding(finding, case, base)

    # Frames are present: this is the authoritative §4.3 frame-walk path.
    base["match_basis"] = "oracle_frame" if oracle_used else "self_reported_frame"

    # Step 1: TYPE GATE.
    bucket_c = canonicalize_crash_type(sanitizer_type) if sanitizer_type else "unknown"
    bucket_b = canonicalize_crash_type(case["crash_type"])
    base["candidate_type"] = bucket_c
    if not types_compatible(bucket_c, bucket_b):
        base["reason"] = (
            f"type gate FAILED: candidate sanitizer type '{sanitizer_type}' "
            f"(bucket={bucket_c}) is not compatible with ground-truth crash_type "
            f"'{case['crash_type']}' (bucket={bucket_b}) -> miss."
        )
        return base

    # Step 2: ROOT-CAUSE LOCALITY.
    # Primary candidate: R_C = first non-denylisted frame walking outward.
    r_c, walked = select_root_cause_frame(frames, denylist_re)
    candidate_frames = [r_c]

    # For UAF, also consider alloc-site A_C and free-site Free_C. ASAN prints
    # these as separate labeled sub-stacks; the oracle flattens all frames into
    # asan_frames, so we cannot reliably segment them without sub-stack labels.
    # If the finding (or oracle, in a richer impl) provided explicit alloc/free
    # frame lists, honor them; otherwise A_C/Free_C fold into the single
    # backtrace and the first-non-denylisted-frame walk already covers the
    # earliest attributable site.
    if bucket_b in ("heap-use-after-free", "heap-double-free", "use-after-poison"):
        a_c = _first_non_denylisted(finding.get("alloc_frames"), denylist_re)
        free_c = _first_non_denylisted(finding.get("free_frames"), denylist_re)
        for extra in (a_c, free_c):
            if extra is not None:
                candidate_frames.append(extra)

    matched_fx = None
    matched_frame = None
    matched_line = None
    for cand in candidate_frames:
        if cand is None:
            continue
        fx = _frame_file_matches_fix(cand.get("file"), fix_files)
        if fx is not None:
            matched_fx = fx
            matched_frame = cand
            matched_line = cand.get("line")
            break

    if matched_fx is not None:
        base["verdict"] = "hit"
        base["root_cause_frame"] = matched_frame
        base["matched_fix_file"] = matched_fx
        base["matched_line"] = matched_line
        line_note = (f" line-level location {matched_frame.get('file')}:{matched_line} recorded"
                     if matched_line is not None else " (file-level match; no line recorded)")
        diff_note = ""
        if is_differential is True:
            diff_note = " differential check confirms the fix removes the crash."
        elif is_differential is False:
            diff_note = (" NOTE: differential check did NOT confirm fix-removes-crash "
                         "(record for review).")
        base["reason"] = (
            f"type-compatible ({bucket_c}~{bucket_b}); root-cause frame "
            f"'{(matched_frame or {}).get('func')}' resolves to Fix_B file "
            f"'{matched_fx}'.{line_note}.{diff_note}"
        )
        # Record the full candidate set for auditability.
        base["candidate_frames"] = candidate_frames
        return base

    # Step 3: ADJACENCY BAND.
    adj = detect_adjacency(frames, candidate_frames, fix_files, denylist_re)
    if adj is not None:
        base["verdict"] = "adjacent"
        base["root_cause_frame"] = adj["candidate_frame"]
        base["matched_fix_file"] = adj["matched_fix_file"]
        base["adjacency"] = {
            "relation": adj["relation"],
            "adjacent_to": adj["adjacent_to"],
        }
        base["reason"] = (
            f"type-compatible but no candidate frame is WITHIN Fix_B; candidate "
            f"'{(adj['candidate_frame'] or {}).get('func')}' is in the "
            f"{adj['relation']} of Fix_B site '{adj['matched_fix_file']}' "
            f"({(adj['adjacent_to'] or {}).get('func')}). NOT auto-scored -> "
            f"ADJACENT, route to manual adjudication (legitimate sibling bug vs "
            f"coincidental crash)."
        )
        return base

    # Otherwise: miss.
    base["root_cause_frame"] = r_c
    base["reason"] = (
        f"type-compatible ({bucket_c}~{bucket_b}) but no candidate frame "
        f"(R_C='{(r_c or {}).get('func')}' @ {(r_c or {}).get('file')}) "
        f"resolves to or neighbors any Fix_B file {sorted(_fix_basenames(fix_files))} "
        f"-> miss."
    )
    base["candidate_frames"] = candidate_frames
    return base


def _localize_finding(finding, case, base):
    """FILE-LOCALIZATION fallback (used only when NO ASAN frames are available).

    A strictly WEAKER, clearly-labeled signal than the §4.3 frame walk. It asks
    "does the finding's recorded file_path land in Fix_B, with a compatible
    self-reported crash class?" -- i.e. did the agent LOCALIZE the vulnerable
    file, not did it REPRODUCE the crash. This exists because prose-emitting
    agents (bob-oss et al.) record file_path + symbol + sometimes a crash class,
    but no replayable input and no structured ASAN stack, so the frame walk is
    impossible and the alternative is a vacuous "cannot evaluate".

    Every verdict here carries match_basis="file_localization" and oracle_used is
    false, so a localization hit is NEVER mistaken for an oracle-reproduced hit.
    Verdicts: hit | miss | unscoreable (no file_path -> nothing to localize).
    """
    base["match_basis"] = "file_localization"
    fix_files = case["fix_files"]
    file_path = finding.get("file_path")

    if not (isinstance(file_path, str) and file_path.strip()):
        base["verdict"] = "unscoreable"
        base["reason"] = (
            "no crash input, no self-reported ASAN frames, and no file_path on the "
            "finding -> nothing to localize; UNSCOREABLE (excluded from the recall "
            "denominator, NOT counted as a miss)."
        )
        return base

    # Type gate (localization variant): only an EXPLICIT self-reported class can
    # FAIL the gate. Unknown class -> skip the gate (file match decides), because
    # most prose findings carry no structured class and we refuse to guess.
    sr_type = _self_reported_type(finding)
    bucket_c = canonicalize_crash_type(sr_type) if sr_type else "unknown"
    bucket_b = canonicalize_crash_type(case["crash_type"])
    base["candidate_type"] = bucket_c
    if bucket_c != "unknown" and not types_compatible(bucket_c, bucket_b):
        base["verdict"] = "miss"
        base["reason"] = (
            f"file-localization: self-reported crash class '{sr_type}' (bucket="
            f"{bucket_c}) is incompatible with ground-truth '{case['crash_type']}' "
            f"(bucket={bucket_b}) -> localization MISS (self-reported, NOT reproduced)."
        )
        return base

    matched_fx = _frame_file_matches_fix(file_path, fix_files)
    if matched_fx is not None:
        base["verdict"] = "hit"
        base["matched_fix_file"] = matched_fx
        base["matched_line"] = finding.get("line")
        # Pseudo-frame for dedup/audit -- NOT an ASAN frame (idx=None marks that).
        base["root_cause_frame"] = {
            "idx": None, "func": finding.get("symbol"),
            "file": file_path, "line": finding.get("line"),
        }
        type_note = (f"self-reported class {bucket_c}~{bucket_b} compatible"
                     if bucket_c != "unknown"
                     else "self-reported class unknown (type gate skipped)")
        base["reason"] = (
            f"file-localization HIT: finding file '{file_path}' resolves to Fix_B "
            f"file '{matched_fx}' ({type_note}). NOTE: self-reported LOCALIZATION, "
            f"NOT an oracle-reproduced crash -> localization recall, not reproduction recall."
        )
        return base

    base["verdict"] = "miss"
    base["reason"] = (
        f"file-localization: finding file '{file_path}' is not in Fix_B "
        f"{sorted(_fix_basenames(fix_files))} -> localization MISS "
        f"(self-reported, NOT reproduced)."
    )
    return base


def _first_non_denylisted(frames, denylist_re):
    """For explicit alloc/free sub-stacks: first non-denylisted frame, or None."""
    ordered = _frames_in_walk_order(frames)
    for fr in ordered:
        if not _is_denylisted(fr.get("func"), denylist_re):
            return fr
    return None


# ---------------------------------------------------------------------------
# §4.3 step 4: DEDUP. One ARVO bug rediscovered via multiple crashing inputs
# counts ONCE; multiple findings collapsing to one root cause (root-cause frame
# + alloc/free signature) count once, the rest logged as duplicates.
#
# Dedup operates ONLY over `hit` findings (those that mapped to the single
# ground-truth bug B for this case). Since every hit in a single-bug ARVO case
# maps to the SAME bug B, ALL hits collapse to ONE distinct bug. We still record
# a per-finding root-cause signature so the dedup is auditable and so the rule
# generalizes to multi-bug cases (where distinct (type, root-cause file:line)
# signatures would yield >1 distinct bug).
# ---------------------------------------------------------------------------
def _root_cause_signature(verdict_row):
    """Stable signature for dedup: (canonical type, root-cause file:line)."""
    rcf = verdict_row.get("root_cause_frame") or {}
    file_part = _basename(rcf.get("file")) if rcf.get("file") else (
        verdict_row.get("matched_fix_file") or "?")
    line_part = rcf.get("line")
    line_str = str(line_part) if line_part is not None else "*"
    return (verdict_row.get("candidate_type") or "?", file_part, line_str)


def dedup_hits(verdict_rows):
    """Collapse hit findings to distinct bugs by root-cause signature.

    Returns (distinct_bug_count, duplicates_list). For a single-bug ARVO case
    every signature ties back to bug B, so distinct_bug_count is 1 if there is
    >=1 hit (we cluster on the Fix_B file the hits matched, not on differing
    R_C lines, because they are all the SAME planted bug). We therefore cluster
    hits by `matched_fix_file` AND root-cause file (whichever the bug is keyed
    on), but treat all hits in one case as the same bug B for the case-level
    distinct count, while still logging which findings were duplicates.
    """
    hits = [v for v in verdict_rows if v.get("verdict") == "hit"]
    if not hits:
        return 0, [], 0
    # Cluster by root-cause signature for auditability/multi-bug generality.
    clusters = {}
    order = []
    for v in hits:
        sig = _root_cause_signature(v)
        if sig not in clusters:
            clusters[sig] = []
            order.append(sig)
        clusters[sig].append(v.get("finding"))
    duplicates = []
    for sig in order:
        members = clusters[sig]
        # First member is the representative; rest are duplicates.
        for dup in members[1:]:
            duplicates.append({
                "finding": dup,
                "duplicate_of": members[0],
                "root_cause_signature": list(sig),
                "reason": "same root-cause signature as representative -> counted once.",
            })
    # For a SINGLE-bug ARVO case, the case-level distinct-bug count is 1 when any
    # hit exists (all hits = the same planted bug B). The per-signature clusters
    # above are reported for transparency/multi-bug generalization. We expose
    # both: distinct_root_cause_clusters (raw cluster count) and the canonical
    # single-bug collapse used for the case-level number.
    return 1, duplicates, len(order)


# ---------------------------------------------------------------------------
# Top-level scoring.
# ---------------------------------------------------------------------------
def score_case(findings, case_id, oracle_path=None, use_oracle=True,
               differential=False, rmi=False, denylist_extra=None):
    case = GROUND_TRUTH_CASES.get(str(case_id))
    if case is None:
        raise SystemExit(
            f"error: unknown ARVO case id '{case_id}'. Known: "
            + ", ".join(sorted(GROUND_TRUTH_CASES))
        )
    denylist_re = _build_denylist(str(case_id), denylist_extra)
    oracle_path = oracle_path or _default_oracle_path()

    verdict_rows = []
    for finding in findings:
        crash_input = _get_crash_input(finding)
        oracle_used = False
        crashed = None
        is_differential = None
        oracle_error = None
        frames = []
        sanitizer_type = None

        if use_oracle and crash_input:
            oracle_json, err = run_oracle(
                oracle_path, case_id, crash_input=crash_input,
                differential=differential, rmi=rmi,
            )
            if oracle_json is not None:
                view = _oracle_view(oracle_json, differential)
                if view is not None:
                    oracle_used = True
                    crashed = view["crashed"]
                    is_differential = view["is_differential"]
                    sanitizer_type = view["sanitizer_type"]
                    frames = _frames_in_walk_order(view["asan_frames"])
                else:
                    oracle_error = "oracle JSON missing expected fields"
            else:
                oracle_error = err
            # Hard fallback to self-report ONLY if oracle truly unavailable.
            if not oracle_used:
                sr_frames, sr_type = _get_self_reported_frames(finding)
                frames = sr_frames
                sanitizer_type = sr_type or _self_reported_type(finding)
                crashed = bool(frames)  # best-effort; flagged self-reported below
        elif use_oracle:
            # use_oracle is set, but this finding ships NO crashing input. Running
            # the oracle now would re-execute the BUILTIN canonical PoC (oracle CLI
            # contract: "Without --input: the builtin canonical PoC") and thereby
            # rubber-stamp EVERY finding on a single-bug case -> a meaningless 1.0
            # recall. So we SKIP the oracle and fall to self-reported frames ->
            # file-localization, exactly as the --no-oracle path does.
            oracle_error = (
                "use_oracle set but finding carries no crashing input; oracle "
                "SKIPPED (running it would re-exec the builtin PoC and spuriously "
                "confirm). Scored via self-report / file-localization instead."
            )
            sr_frames, sr_type = _get_self_reported_frames(finding)
            frames = sr_frames
            sanitizer_type = sr_type or _self_reported_type(finding)
            crashed = bool(frames)
        else:
            # --no-oracle: explicit self-report path (clearly labeled).
            sr_frames, sr_type = _get_self_reported_frames(finding)
            frames = sr_frames
            sanitizer_type = sr_type or _self_reported_type(finding)
            crashed = bool(frames)
            oracle_error = "scored with --no-oracle (self-reported stack; NOT independently re-executed)"

        row = map_finding(
            finding, case, frames, sanitizer_type, denylist_re,
            oracle_used=oracle_used, crashed=crashed,
            is_differential=is_differential, oracle_error=oracle_error,
        )
        verdict_rows.append(row)

    # Case-level rollup.
    hits = sum(1 for v in verdict_rows if v["verdict"] == "hit")
    adjacents = sum(1 for v in verdict_rows if v["verdict"] == "adjacent")
    misses = sum(1 for v in verdict_rows if v["verdict"] == "miss")

    # A "miss that is a real crash" = the oracle DID reproduce a crash for this
    # finding, but it failed the §4.3 mapping (wrong type or wrong location).
    # These are the genuine false positives for the per-trial precision; a miss
    # that never crashed (unreproduced / no input) is an invalid trial, NOT a FP,
    # and is excluded from the precision denominator.
    misses_real_crash = sum(
        1 for v in verdict_rows
        if v["verdict"] == "miss" and v.get("oracle_crashed") is True
    )
    misses_no_crash = misses - misses_real_crash

    distinct, duplicates, raw_clusters = dedup_hits(verdict_rows)

    precision_denom = hits + misses_real_crash
    per_trial_precision = (hits / precision_denom) if precision_denom > 0 else None

    # Verdict-basis breakdown: separate REPRODUCTION hits (oracle / self-reported
    # ASAN frame walk) from LOCALIZATION-only hits (file_path-in-Fix_B, no crash
    # reproduced). These are different strengths of evidence and MUST be reported
    # distinctly -- only the reproduction number is comparable to a directed
    # reproduction benchmark (CyberGym). unscoreable findings carry no location
    # signal and are excluded from both numerator and denominator.
    frame_hits = sum(
        1 for v in verdict_rows
        if v.get("verdict") == "hit"
        and v.get("match_basis") in ("oracle_frame", "self_reported_frame")
    )
    localization_hits = sum(
        1 for v in verdict_rows
        if v.get("verdict") == "hit" and v.get("match_basis") == "file_localization"
    )
    unscoreable = sum(1 for v in verdict_rows if v.get("verdict") == "unscoreable")
    if hits == 0:
        recall_basis = "none"
    elif localization_hits and not frame_hits:
        recall_basis = "localization"
    elif frame_hits and not localization_hits:
        recall_basis = "frame"
    else:
        recall_basis = "mixed"

    return {
        "case": str(case_id),
        "project": case["project"],
        "crash_type": case["crash_type"],
        "ground_truth_type_bucket": canonicalize_crash_type(case["crash_type"]),
        "fix_files": case["fix_files"],
        "fix_commit": case["fix_commit"],
        "vulnerable_commit": case["vulnerable_commit"],
        "oracle_used": any(v.get("oracle_used") for v in verdict_rows) if verdict_rows else (use_oracle),
        "oracle_path": oracle_path,
        "scored_with_oracle_flag": use_oracle,
        "differential_mode": differential,
        "findings": verdict_rows,
        "duplicates": duplicates,
        "case_level": {
            "total_findings": len(verdict_rows),
            "hits": hits,
            "frame_hits": frame_hits,
            "localization_hits": localization_hits,
            "unscoreable": unscoreable,
            "recall_basis": recall_basis,
            "localization_note": (
                "hits = frame_hits + localization_hits. frame_hits are oracle- or "
                "self-report ASAN-frame-walk hits (reproduction; CyberGym-comparable). "
                "localization_hits are file_path-in-Fix_B only (self-reported, NOT "
                "reproduced) -- a weaker LOCALIZATION signal, not reproduction recall."
            ),
            "adjacents": adjacents,
            "misses": misses,
            "misses_that_are_real_crashes": misses_real_crash,
            "misses_unreproduced": misses_no_crash,
            "distinct_bugs_after_dedup": distinct,
            "distinct_root_cause_clusters": raw_clusters,
            "duplicate_count": len(duplicates),
            "per_trial_precision": per_trial_precision,
            "per_trial_precision_denominator": precision_denom,
            "per_trial_precision_note": (
                "per_trial_precision = hits / (hits + misses_that_are_real_crashes). "
                "Unreproduced misses (no crash / no input) are invalid trials, "
                "NOT false positives, and are excluded from the denominator. "
                "Adjacent findings are NOT counted as hits or misses here -- they "
                "are a separate bucket routed to manual adjudication (§4.3 step 3)."
            ),
        },
        "scoring_notes": (
            "§4.3 ordered mapping: (1) type gate, (2) root-cause-frame locality "
            "(walk outward from faulting frame, skip allocator/intrinsic/generic-"
            "helper denylist, first non-denylisted frame = R_C; +A_C/Free_C for "
            "UAF), file-level match against Fix_B (line-level recorded), (3) "
            "adjacency band -> manual adjudication, (4) dedup by root-cause "
            "signature. ASAN stacks are oracle-sourced (clean-container re-exec), "
            "never agent self-report, unless --no-oracle is set. FALLBACK: when no "
            "ASAN frames exist (no crashing input and no self-reported stack, e.g. "
            "prose-only findings), the scorer uses FILE-LOCALIZATION (file_path in "
            "Fix_B + self-reported class), labeled match_basis='file_localization'. "
            "That is localization recall (did the agent name the vulnerable file), "
            "NOT reproduction recall; the two are reported separately in case_level "
            "(frame_hits vs localization_hits). Under --oracle, the oracle is only "
            "invoked for findings that ship their OWN crashing input; a finding "
            "with no input is NOT auto-confirmed against the builtin PoC."
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Agent-agnostic §4.3 crash->distinct-bug scorer for the bob-oss benchmark."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sc = sub.add_parser("score", help="Score a findings.jsonl-equivalent against an ARVO case.")
    sc.add_argument("--findings", required=True,
                    help="Path to findings.jsonl-equivalent (JSONL / JSON array / {findings:[...]}).")
    sc.add_argument("--case", required=True,
                    help="ARVO case id (one of: " + ", ".join(sorted(GROUND_TRUTH_CASES)) + ").")
    sc.add_argument("--no-oracle", action="store_true",
                    help="Do NOT invoke the oracle; score from each finding's self-reported "
                         "ASAN stack (clearly labeled; NOT independently re-executed).")
    sc.add_argument("--oracle", default=None,
                    help="Path to arvo_oracle.py (default: sibling of this script).")
    sc.add_argument("--differential", action="store_true",
                    help="Use the oracle 'differential' subcommand (run vul AND fix); "
                         "map against the vulnerable side, record is_differential.")
    sc.add_argument("--rmi", action="store_true",
                    help="Pass --rmi to the oracle so it docker rmi's the (~5.78GB) image after use.")
    sc.add_argument("--denylist-extra", default=None,
                    help="JSON list of extra denylist regex patterns for this run "
                         "(per-project generic-helper extensions).")
    sc.add_argument("--pretty", action="store_true", help="Pretty-print the JSON output.")

    args = parser.parse_args(argv)

    if args.command == "score":
        denylist_extra = None
        if args.denylist_extra:
            try:
                denylist_extra = json.loads(args.denylist_extra)
                if not isinstance(denylist_extra, list):
                    raise SystemExit("error: --denylist-extra must be a JSON list of strings.")
            except (ValueError, json.JSONDecodeError) as exc:
                raise SystemExit(f"error: --denylist-extra is not valid JSON: {exc}")

        findings = load_findings(args.findings)
        result = score_case(
            findings,
            args.case,
            oracle_path=args.oracle,
            use_oracle=not args.no_oracle,
            differential=args.differential,
            rmi=args.rmi,
            denylist_extra=denylist_extra,
        )
        if args.pretty:
            sys.stdout.write(json.dumps(result, indent=2, sort_keys=False))
        else:
            sys.stdout.write(json.dumps(result, separators=(",", ":")))
        sys.stdout.write("\n")
        return 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
