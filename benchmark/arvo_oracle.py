#!/usr/bin/env python3
"""ARVO clean-container oracle for the bob-oss rediscovery benchmark.

PURPOSE
    Deterministically reproduce a known OSS-Fuzz crash inside ARVO's pre-built
    container images, parse the AddressSanitizer (or other sanitizer) report into
    a structured verdict, and (for differential mode) confirm the fix image does
    NOT crash on the same input. This is the *ground-truth oracle* for scoring an
    agent's rediscovery: the scorer feeds the oracle either ARVO's builtin PoC or
    an agent-produced crashing file, and trusts ONLY the oracle's verdict.

    The oracle is stdlib-only and shells out to `docker`. It targets a LOCAL
    docker daemon (run it on the VPS where Docker lives); there is no SSH layer
    here -- the operator runs this script on the docker host directly.

CLI CONTRACT (the scorer must honor this exactly)
    python3 benchmark/arvo_oracle.py reproduce --case <ARVO_ID> [--input <path>]
        Pull n132/arvo:<id>-vul if absent, run it under bob-oss caps, print a
        JSON verdict to stdout:
          {case, image, crashed, exit_code, sanitizer_type,
           crash_class, asan_frames:[{idx,func,file,line}], raw_tail}
        With --input: feed the agent-provided crashing file to the case harness
        binary (NOT the builtin /tmp/poc). Without --input: reproduce the builtin
        canonical PoC via ARVO's own harness invocation.

    python3 benchmark/arvo_oracle.py differential --case <ARVO_ID> [--input <path>]
        Run BOTH :<id>-vul and :<id>-fix and print:
          {case, vul:{...verdict...}, fix:{...verdict...},
           is_differential: vul.crashed && !fix.crashed}

    Flags:
        --case <ARVO_ID>     Required. ARVO/OSS-Fuzz numeric id used as the image
                             tag (n132/arvo:<id>-vul / -fix).
        --input <path>       Optional crashing input file produced by the agent.
                             When set, the oracle copies it into the container and
                             runs the discovered libFuzzer target binary against it
                             instead of the builtin PoC.
        --rmi                After running, `docker rmi` every image this command
                             touched. Images are ~5.78GB each; use this for disk
                             hygiene when iterating across many cases.
        --timeout <sec>      Per-`docker run` wall-clock timeout (default 600).
        --pretty             Pretty-print the JSON output.

CONTAINER CAPS (bob-oss sandbox parity)
    Every `docker run` uses:
      --memory 2g --cpus 2 --pids-limit 256 --cap-drop ALL
      --security-opt no-new-privileges --network none
    These match the bob-oss repo_docker_run sandbox so reproduction is faithful
    to how the agent's own dynamic harness runs execute.

==============================================================================
CUSTOM-INPUT REPLAY -- RESOLVED (investigated on the VPS, muparser case 25402)
==============================================================================
ARVO images ship a `/bin/arvo` wrapper script and a single libFuzzer target
binary under `/out/`. The relevant facts (verified live on n132/arvo:25402-vul):

  * `/bin/arvo` is a bash wrapper. Its body exports the sanitizer options and
    fuzzing-engine env, then unconditionally runs the libFuzzer target against
    the builtin PoC:
        export ASAN_OPTIONS=...:strip_path_prefix=/workspace/:symbolize=1:...
        export UBSAN_OPTIONS=...print_stacktrace=1...
        export FUZZING_ENGINE=libfuzzer
        export SANITIZER=address
        ...
        /out/set_eval_fuzzer /tmp/poc      # <-- the target + builtin PoC path
    The exact target binary differs per case (muparser -> set_eval_fuzzer,
    c-blosc2 -> decompress_frame_fuzzer, wasm3 -> fuzzer), but the *shape* is
    always `/out/<target> /tmp/poc`.

  * The builtin PoC lives at `/tmp/poc`. `arvo` (no args) and `arvo run` both
    just execute `/out/<target> /tmp/poc`.

  * The libFuzzer target binary accepts ANY file path as a positional arg and
    runs the target once on that file ("Running 1 inputs 1 time(s) each.").
    So to replay an AGENT'S OWN crashing input we do NOT use `/tmp/poc`; we run:
        <target> <our_input_file>

CUSTOM-INPUT REPLAY COMMAND (the one this oracle issues inside the container):
    # 1. source ARVO's sanitizer/env exports so ASAN symbolization + options
    #    match the canonical reproduction exactly:
    eval "$(grep -E '^export ' /bin/arvo)"
    # 2. discover the target binary generically by parsing the wrapper:
    TARGET=$(grep -oE '/out/[A-Za-z0-9_./-]+ /tmp/poc' /bin/arvo | head -1 \
             | awk '{print $1}')
    # 3. run the target against the mounted custom input (NOT /tmp/poc):
    "$TARGET" /work/custom_input

  Validated: copying the builtin PoC to a different path and running the
  discovered target on it reproduces the identical crash:
      ERROR: AddressSanitizer: heap-buffer-overflow
      #0 ... mu::ParserBase::ParseCmdCodeBulk(int,int) const muParserBase.cpp:1242

  FALLBACK: if `/out/` contains exactly one executable and the wrapper parse
  yields nothing, the oracle falls back to that single executable as the target.

CRASH DETECTION (do NOT trust exit code alone)
    Verified exit/banner ground truth on the muparser case:
      * crashing input : exit 1,  output contains "ERROR: AddressSanitizer:"
      * benign / empty : exit 0,  output contains "fuzzing was not performed"
                         and NO sanitizer banner.
    PITFALL: piping container output through `head`/`tail` yields exit 141
    (SIGPIPE) which is NOT a crash. This oracle therefore never pipes inside the
    container; it captures full stdout+stderr in Python and decides crashed-ness
    on the SANITIZER BANNER first, with a non-zero exit code as a secondary
    signal. A run is `crashed` iff a sanitizer ERROR banner is present (libFuzzer
    crash-on-startup runs exit 1; native SIGABRT would be 134, SIGSEGV 139 -- all
    accepted, but the banner is the authoritative signal).

SANITIZER / FRAME PARSING
    `sanitizer_type` and `crash_class` come from the banner line:
        ==NN==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
    Stack frames come from the `    #<idx> 0x... in <func> <file>:<line>:<col>`
    lines of the FIRST (top) stack only -- the allocation/free secondary stacks
    are intentionally not folded into asan_frames so the ordered crash trace is
    unambiguous. `file` and `line` are best-effort (some frames are library
    frames with a `(.../libc.so.6+0xNN)` form and have no source file/line).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

# bob-oss sandbox parity caps applied to every `docker run`.
DOCKER_CAPS = [
    "--memory", "2g",
    "--cpus", "2",
    "--pids-limit", "256",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--network", "none",
]

IMAGE_REPO = "n132/arvo"

# Frozen Phase-0 manifest: pin images by content DIGEST, not floating tag
# (BOB_OSS_BENCHMARK_PLAN.md §3.5). A registry retag/eviction would otherwise
# silently swap the code under test out from under a recorded result.
_MANIFEST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "arvo_phase0_manifest.json")
_PINNED_DIGESTS = None  # lazy { (arvo_id, variant): "sha256:..." }


def _pinned_digests() -> dict:
    global _PINNED_DIGESTS
    if _PINNED_DIGESTS is None:
        _PINNED_DIGESTS = {}
        try:
            with open(_MANIFEST_PATH) as f:
                manifest = json.load(f)
            for c in manifest.get("cases", []):
                for variant, img in c.get("images", {}).items():
                    if isinstance(img, dict) and img.get("digest"):
                        _PINNED_DIGESTS[(str(c.get("arvo_id")), variant)] = img["digest"]
        except (OSError, ValueError, KeyError):
            _PINNED_DIGESTS = {}
    return _PINNED_DIGESTS

# How much of the captured output to surface in `raw_tail`.
RAW_TAIL_LINES = 40

# ---------------------------------------------------------------------------
# Sanitizer report parsing
# ---------------------------------------------------------------------------

# e.g. "==7==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x..."
#      "==7==ERROR: AddressSanitizer: heap-use-after-free on address 0x..."
#      "==7==ERROR: AddressSanitizer: global-buffer-overflow ..."
_BANNER_RE = re.compile(
    r"==\d+==\s*ERROR:\s*(?P<san>[A-Za-z]+Sanitizer):\s*(?P<klass>[A-Za-z0-9_-]+)"
)
# UBSAN style: "file.c:12:34: runtime error: <desc>"
_UBSAN_RE = re.compile(
    r"(?P<file>[^\s:]+):(?P<line>\d+):\d+:\s*runtime error:\s*(?P<klass>.+)"
)
# libFuzzer's own crash banners (timeout / oom / leak) without an ASAN line.
_LIBFUZZER_DEADLY_RE = re.compile(
    r"==\d+==\s*ERROR:\s*libFuzzer:\s*(?P<klass>[A-Za-z0-9 _-]+)"
)

# Frame line, two shapes:
#   source frame : "    #0 0x5798ac in mu::ParserBase::Foo(int) const /src/x.cpp:1242:10"
#   library frame: "    #8 0x4204f8 in _start (/out/set_eval_fuzzer+0x4204f8)"
#                  "    #7 0x70e...3f in __libc_start_main (/lib/.../libc.so.6+0x2083f)"
# Source frames carry a trailing "/path:line[:col]"; library frames carry a
# trailing "(/path+0xNN)" binary offset (no source file/line). We strip both into
# the right fields so `func` stays a clean symbol name and `file`/`line` are only
# set for real source frames.
_FRAME_HEAD_RE = re.compile(r"^\s*#(?P<idx>\d+)\s+0x[0-9a-fA-F]+\s+in\s+(?P<rest>.*\S)\s*$")
_FRAME_SRC_TAIL_RE = re.compile(r"^(?P<func>.+?)\s+(?P<file>/[^\s:]+):(?P<line>\d+)(?::\d+)?$")
_FRAME_LIB_TAIL_RE = re.compile(r"^(?P<func>.+?)\s+\([^)]*\+0x[0-9a-fA-F]+\)$")


def parse_sanitizer_report(output: str) -> dict:
    """Extract sanitizer_type, crash_class, and the ordered TOP stack frames.

    Only the first stack trace (the crash trace) is folded into asan_frames; the
    secondary "allocated by"/"freed by" stacks are skipped so the ordered crash
    trace stays unambiguous.
    """
    lines = output.splitlines()
    sanitizer_type = None
    crash_class = None
    banner_idx = None

    for i, line in enumerate(lines):
        m = _BANNER_RE.search(line)
        if m:
            sanitizer_type = m.group("san")
            crash_class = m.group("klass")
            banner_idx = i
            break

    # No ASAN-style banner: try UBSAN runtime-error, then libFuzzer deadly signals.
    if banner_idx is None:
        for i, line in enumerate(lines):
            m = _UBSAN_RE.search(line)
            if m:
                sanitizer_type = "UndefinedBehaviorSanitizer"
                crash_class = "runtime-error"
                banner_idx = i
                break
    if banner_idx is None:
        for i, line in enumerate(lines):
            m = _LIBFUZZER_DEADLY_RE.search(line)
            if m:
                sanitizer_type = "libFuzzer"
                crash_class = m.group("klass").strip()
                banner_idx = i
                break

    frames: list[dict] = []
    if banner_idx is not None:
        # Collect the first contiguous block of frame lines after the banner.
        started = False
        for line in lines[banner_idx + 1:]:
            head = _FRAME_HEAD_RE.match(line)
            if head:
                started = True
                rest = head.group("rest")
                func, file_, line_no = rest, None, None
                src = _FRAME_SRC_TAIL_RE.match(rest)
                if src:
                    func = src.group("func")
                    file_ = src.group("file")
                    line_no = int(src.group("line"))
                else:
                    lib = _FRAME_LIB_TAIL_RE.match(rest)
                    if lib:
                        func = lib.group("func")
                frames.append({
                    "idx": int(head.group("idx")),
                    "func": func.strip(),
                    "file": file_,
                    "line": line_no,
                })
            elif started:
                # First non-frame line after the trace started -> end of top stack.
                break

    return {
        "sanitizer_type": sanitizer_type,
        "crash_class": crash_class,
        "asan_frames": frames,
    }


def detect_crash(output: str, exit_code) -> bool:
    """A run crashed iff a sanitizer/libFuzzer ERROR banner is present.

    The banner is authoritative; exit code is a secondary corroborating signal
    only. Benign libFuzzer runs print "fuzzing was not performed" and exit 0 with
    no banner. We deliberately do NOT treat a bare non-zero exit as a crash
    (e.g. SIGPIPE 141 from truncated pipes, or a 1 from a usage error).
    """
    if _BANNER_RE.search(output):
        return True
    if _UBSAN_RE.search(output):
        return True
    if _LIBFUZZER_DEADLY_RE.search(output):
        return True
    return False


# ---------------------------------------------------------------------------
# Docker plumbing
# ---------------------------------------------------------------------------

def _image_tag(case: str, variant: str) -> str:
    return f"{IMAGE_REPO}:{case}-{variant}"


def _image_ref(case: str, variant: str) -> str:
    """Digest-pinned image ref from the frozen manifest; floating tag (loudly warned) otherwise.

    Pinning by @sha256 makes the code under test reproducible and tamper-evident.
    A case absent from the manifest is a fabrication risk per the plan, so the
    fallback is explicit and warned, never silent.
    """
    digest = _pinned_digests().get((str(case), variant))
    if digest:
        return f"{IMAGE_REPO}@{digest}"
    sys.stderr.write(
        f"[arvo_oracle] WARNING: {IMAGE_REPO}:{case}-{variant} is NOT in the frozen "
        f"manifest ({os.path.basename(_MANIFEST_PATH)}); using the floating tag. The "
        f"result is NOT reproducibly pinned (BOB_OSS_BENCHMARK_PLAN.md §3.5).\n"
    )
    return _image_tag(case, variant)


def _docker(args: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
    )


def image_present(image: str) -> bool:
    proc = _docker(["image", "inspect", image], timeout=60)
    return proc.returncode == 0


def ensure_image(image: str, timeout: int) -> None:
    if image_present(image):
        return
    sys.stderr.write(f"[arvo_oracle] pulling {image} (~5.78GB, this is slow)...\n")
    sys.stderr.flush()
    proc = _docker(["pull", image], timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(
            f"docker pull failed for {image} (exit {proc.returncode}):\n"
            f"{proc.stdout[-2000:]}"
        )


def remove_image(image: str, timeout: int = 120) -> None:
    proc = _docker(["rmi", "-f", image], timeout=timeout)
    if proc.returncode != 0:
        sys.stderr.write(
            f"[arvo_oracle] warning: docker rmi {image} failed: "
            f"{proc.stdout.strip()[-500:]}\n"
        )


# Single in-container script used for BOTH paths. It sources ARVO's own sanitizer
# env exports (so ASAN_OPTIONS / symbolization match the canonical reproduction),
# discovers the libFuzzer target binary by parsing /bin/arvo (with a single-binary
# /out fallback), then runs that target against $ARVO_INPUT. The caller sets
# ARVO_INPUT to /tmp/poc for the builtin PoC, or /work/custom_input for the agent's
# own file. The target's real exit code is preserved (no `|| true` masking).
_RUN_CMD = r"""
eval "$(grep -E '^export ' /bin/arvo)"
TARGET=$(grep -oE '/out/[A-Za-z0-9_./-]+ /tmp/poc' /bin/arvo | head -1 | awk '{print $1}')
if [ -z "$TARGET" ] || [ ! -x "$TARGET" ]; then
  # Fallback: the single executable in /out is the libFuzzer target.
  cnt=$(find /out -maxdepth 1 -type f -executable | wc -l)
  if [ "$cnt" = "1" ]; then
    TARGET=$(find /out -maxdepth 1 -type f -executable | head -1)
  fi
fi
if [ -z "$TARGET" ] || [ ! -x "$TARGET" ]; then
  echo "arvo_oracle: could not resolve target binary from /bin/arvo or /out" 1>&2
  exit 97
fi
if [ ! -f "$ARVO_INPUT" ]; then
  echo "arvo_oracle: input not found in container: $ARVO_INPUT" 1>&2
  exit 96
fi
echo "arvo_oracle: target=$TARGET input=$ARVO_INPUT" 1>&2
"$TARGET" "$ARVO_INPUT"
"""


def run_case(case: str, variant: str, input_path: str | None, timeout: int) -> dict:
    """Run one ARVO image variant and return a structured verdict."""
    image = _image_ref(case, variant)
    ensure_image(image, timeout)

    if input_path is None:
        # Builtin canonical PoC path: target runs against /tmp/poc (ARVO's PoC).
        run_args = [
            "run", "--rm", *DOCKER_CAPS,
            "-e", "ARVO_INPUT=/tmp/poc",
            image, "bash", "-lc", _RUN_CMD,
        ]
        proc = _docker(run_args, timeout=timeout)
        output = proc.stdout
        exit_code = proc.returncode
    else:
        # Custom-input path: mount the agent's crashing file read-only and run the
        # discovered target binary against it (NOT the builtin /tmp/poc).
        abs_in = os.path.abspath(input_path)
        if not os.path.isfile(abs_in):
            raise FileNotFoundError(f"--input file not found: {abs_in}")
        # Stage into a temp dir we bind-mount, so we control the in-container path
        # and never depend on the host file's name/permissions.
        with tempfile.TemporaryDirectory() as staging:
            staged = os.path.join(staging, "custom_input")
            with open(abs_in, "rb") as src, open(staged, "wb") as dst:
                dst.write(src.read())
            run_args = [
                "run", "--rm", *DOCKER_CAPS,
                "-v", f"{staging}:/work:ro",
                "-e", "ARVO_INPUT=/work/custom_input",
                image, "bash", "-lc", _RUN_CMD,
            ]
            proc = _docker(run_args, timeout=timeout)
            output = proc.stdout
            exit_code = proc.returncode

    parsed = parse_sanitizer_report(output)
    crashed = detect_crash(output, exit_code)
    tail = "\n".join(output.splitlines()[-RAW_TAIL_LINES:])

    return {
        "case": case,
        "image": image,
        "variant": variant,
        "input": os.path.abspath(input_path) if input_path else None,
        "crashed": crashed,
        "exit_code": exit_code,
        "sanitizer_type": parsed["sanitizer_type"],
        "crash_class": parsed["crash_class"],
        "asan_frames": parsed["asan_frames"],
        "raw_tail": tail,
    }


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_reproduce(args) -> dict:
    touched = []
    try:
        verdict = run_case(args.case, "vul", args.input, args.timeout)
        touched.append(verdict["image"])
        return verdict
    finally:
        if args.rmi:
            for img in touched:
                remove_image(img)


def cmd_differential(args) -> dict:
    touched = []
    try:
        vul = run_case(args.case, "vul", args.input, args.timeout)
        touched.append(vul["image"])
        fix = run_case(args.case, "fix", args.input, args.timeout)
        touched.append(fix["image"])
        is_diff = bool(vul["crashed"]) and not bool(fix["crashed"])
        return {
            "case": args.case,
            "vul": vul,
            "fix": fix,
            "is_differential": is_diff,
        }
    finally:
        if args.rmi:
            for img in touched:
                remove_image(img)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="arvo_oracle.py",
        description="ARVO clean-container reproduction oracle for bob-oss benchmark.",
    )
    sub = p.add_subparsers(dest="mode", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--case", required=True, help="ARVO/OSS-Fuzz numeric id (image tag).")
    common.add_argument("--input", default=None,
                        help="Agent-produced crashing input file (custom-input replay).")
    common.add_argument("--rmi", action="store_true",
                        help="docker rmi every image touched after running (~5.78GB each).")
    common.add_argument("--timeout", type=int, default=600,
                        help="Per-docker-run wall-clock timeout in seconds (default 600).")
    common.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")

    sub.add_parser("reproduce", parents=[common],
                   help="Reproduce one case (vul image).")
    sub.add_parser("differential", parents=[common],
                   help="Run vul and fix images; report is_differential.")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.mode == "reproduce":
            result = cmd_reproduce(args)
        elif args.mode == "differential":
            result = cmd_differential(args)
        else:  # pragma: no cover - argparse enforces choices
            raise ValueError(f"unknown mode {args.mode!r}")
    except subprocess.TimeoutExpired as e:
        sys.stderr.write(f"[arvo_oracle] docker timed out: {e}\n")
        return 2
    except (RuntimeError, FileNotFoundError) as e:
        sys.stderr.write(f"[arvo_oracle] error: {e}\n")
        return 3

    indent = 2 if args.pretty else None
    print(json.dumps(result, indent=indent))
    return 0


if __name__ == "__main__":
    sys.exit(main())
