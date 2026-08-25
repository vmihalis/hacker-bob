#!/bin/sh
# bob multi-TU fuzz builder. Image-baked (off the repo_docker_run 2048-char/token
# recipe budget) so it runs byte-identically on the vulnerable and upstream-fix trees
# — the differential repro gate (bob_verify_repro_reproduction) re-runs the same
# command array on both, so the build must be deterministic across checkouts.
#
# Builds the project's LIBRARY with coverage instrumentation via its own build system,
# then links the discovered LLVMFuzzerTestOneInput harness against it. The current
# single-TU recipe (clang ... -o h -- "$HARNESS") fails to link any multi-file library
# (undefined symbols) and instruments only the harness (no library coverage). This
# closes that wall.
#
# ENGINE=libfuzzer (default) builds /work/out/h (ASAN+UBSan+libFuzzer). ENGINE=afl
# builds /work/out/h_afl + /work/out/h_cmplog. ENGINE=tsan builds /work/out/h_tsan
# (ThreadSanitizer+libFuzzer) — a separate binary because TSan and ASAN are mutually
# exclusive instrumentations; its crash banner ("WARNING: ThreadSanitizer: data race")
# is recognized by sanitizer-report.js and routes into the SAME differential repro gate.
# MSan is intentionally NOT an engine here: it requires a fully MSan-instrumented
# toolchain (instrumented libc++ and every dependency) to avoid false uninitialized
# reads, which is not cleanly injectable in this single-image builder; MSan stays
# parser-only (a report from an externally MSan-built run still parses + adjudicates).
# Echoes BOB_MULTITU_LAYER=<cmake|autotools|make|compileall> so the
# build path is observable in the run ledger.
set -eu
ENGINE="${ENGINE:-libfuzzer}"
OUT=/work/out
mkdir -p "$OUT/corpus"
cd /work/repo

NOINT="-fno-sanitize=integer-divide-by-zero,float-divide-by-zero"
INC="-I. -Iinclude -Isrc -Ilib"

# 1. discover the harness TU.
#    An explicit BOB_HARNESS override wins: it names the harness path verbatim,
#    bypassing auto-selection. The named file MUST exist (fail closed, listing the
#    auto-discovered candidates, when it does not) — a differential repro that
#    silently fuzzed the wrong TU is worse than a hard stop.
#    Auto-selection probes every source for LLVMFuzzerTestOneInput (comments +
#    string/char literals stripped first), then RANKS the real harnesses
#    deterministically: an operator-imported harness first, then libFuzzer-named
#    files (fuzz_*, *_fuzz, *_fuzzer), then parser/txn/quic topics ahead of
#    app/config topics (so a Firedancer tree selects a protocol harness, not
#    fuzz_fdctl_config), with the path itself as the final alpha tiebreak. The
#    ranking is purely name-derived, so it is identical on the vuln and upstream-fix
#    checkouts the differential repro gate re-runs. RANK, not bound — every
#    candidate is echoed (BOB_HARNESS_CANDIDATES) so a wrong pick stays overridable.
_is_harness() {
  perl -0ne 's{/\*.*?\*/}{}gs; s{//[^\n]*}{}g; s/"(?:\\.|[^"\\])*"/""/gs; s/'"'"'(?:\\.|[^'"'"'\\])*'"'"'/'"'"''"'"'/gs; exit(/\b(?:extern\s+(?:"C"|""|'"'"'C'"'"'|'"'"''"'"')\s+)?(?:int|auto)\s+LLVMFuzzerTestOneInput\s*\([^;{}]*\)\s*(?:\{|try\b)/s ? 0 : 1)' -- "$1"
}
_rank_key() {
  _p="$1"; _b=$(basename "$_p" | tr 'A-Z' 'a-z')
  case "$_b" in
    bob_imported_fuzzer.*) printf '00\t%s\n' "$_p"; return ;;
  esac
  case "$_b" in
    fuzz_*|*_fuzz.*|*_fuzzer.*) _tier=1 ;;
    *fuzz*) _tier=2 ;;
    *) _tier=3 ;;
  esac
  case "$_b" in
    *pars*|*txn*|*transaction*|*quic*|*decode*|*deserial*|*proto*|*wire*|*packet*|*pkt*|*message*|*msg*|*tls*|*asn1*|*json*|*xml*|*http*|*header*|*record*|*block*|*bincode*) _topic=0 ;;
    *config*|*fdctl*|*cli*|*cmdline*|*args*|*flag*|*topo*|*app*|*ctl*|*setup*) _topic=2 ;;
    *) _topic=1 ;;
  esac
  printf '%s%s\t%s\n' "$_tier" "$_topic" "$_p"
}
CANDIDATES=$(find . -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' \) -print 2>/dev/null | sort \
  | while IFS= read -r f; do _is_harness "$f" && printf '%s\n' "$f"; done || true)
RANKED=$(printf '%s\n' "$CANDIDATES" | while IFS= read -r f; do [ -n "$f" ] && _rank_key "$f"; done | sort | cut -f2-)
if [ -n "${BOB_HARNESS:-}" ]; then
  HARNESS="$BOB_HARNESS"
  case "$HARNESS" in ./*|/*) ;; *) HARNESS="./$HARNESS" ;; esac
  if [ ! -f "$HARNESS" ]; then
    echo "BOB_HARNESS_NOT_FOUND: $BOB_HARNESS" >&2
    echo "auto-discovered LLVMFuzzerTestOneInput candidates (best first):" >&2
    printf '%s\n' "$RANKED" | sed 's/^/  /' >&2
    exit 4
  fi
else
  # Discovered paths are already ./-rooted (find .); take the top-ranked candidate.
  HARNESS=$(printf '%s\n' "$RANKED" | head -1)
fi
test -n "$HARNESS"
echo "BOB_HARNESS=$HARNESS"
echo "BOB_HARNESS_CANDIDATES:"
printf '%s\n' "$RANKED" | sed 's/^/  /'
case "$HARNESS" in *.c) HARNESS_C=1 ;; *) HARNESS_C=0 ;; esac

# 2. build the LIBRARY archive with coverage instrumentation, project-build-system first.
#    $1=output archive path, CC/CXX/LIBFLAGS taken from the environment. Each layer
#    returns 0 and sets LIB on success. Builds into a per-variant dir so afl's asan and
#    cmplog variants don't collide.
build_lib() {
  out_a="$1"; bld="$2"; LIB=""
  rm -rf "$bld"; mkdir -p "$bld"
  # L1a CMake. CMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY so cmake's compiler-id
  # probe builds a static lib, not an executable — otherwise -fsanitize=fuzzer-no-link
  # (no libFuzzer main) makes the probe's executable link fail and config aborts,
  # silently dropping to the lower-fidelity compile-all fallback.
  if command -v cmake >/dev/null 2>&1 && [ -f CMakeLists.txt ]; then
    if cmake -S . -B "$bld" -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=None \
         -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
         -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
         -DCMAKE_C_FLAGS="$LIBFLAGS" -DCMAKE_CXX_FLAGS="$LIBFLAGS" >"$bld/cfg.log" 2>&1; then
      cmake --build "$bld" -j"$(nproc 2>/dev/null || echo 2)" >"$bld/build.log" 2>&1 || true
      LIB=$(find "$bld" -name 'lib*.a' -print 2>/dev/null | sort | head -1)
      [ -n "$LIB" ] && { LAYER=cmake; cp -f "$LIB" "$out_a"; LIB="$out_a"; return 0; }
    fi
  fi
  # L1b autotools
  if [ -x ./configure ] || [ -f configure.ac ] || [ -f Makefile.am ]; then
    [ -x ./configure ] || { command -v autoreconf >/dev/null 2>&1 && autoreconf -fi >"$bld/auto.log" 2>&1 || true; }
    if [ -x ./configure ]; then
      if ./configure --disable-shared --enable-static CC="$CC" CXX="$CXX" CFLAGS="$LIBFLAGS" CXXFLAGS="$LIBFLAGS" >"$bld/cfg.log" 2>&1; then
        make -j"$(nproc 2>/dev/null || echo 2)" >"$bld/build.log" 2>&1 || true
        LIB=$(find . -name 'lib*.a' -print 2>/dev/null | sort | head -1)
        [ -n "$LIB" ] && { LAYER=autotools; cp -f "$LIB" "$out_a"; LIB="$out_a"; return 0; }
      fi
    fi
  fi
  # L1c plain Makefile
  if [ -f Makefile ]; then
    make -j"$(nproc 2>/dev/null || echo 2)" CC="$CC" CXX="$CXX" CFLAGS="$LIBFLAGS" CXXFLAGS="$LIBFLAGS" >"$bld/build.log" 2>&1 || true
    LIB=$(find . -name 'lib*.a' -print 2>/dev/null | sort | head -1)
    [ -n "$LIB" ] && { LAYER=make; cp -f "$LIB" "$out_a"; LIB="$out_a"; return 0; }
  fi
  # compile-all fallback: every non-harness, non-main TU; tolerate per-TU failure.
  ca="$bld/ca"; mkdir -p "$ca"; n=0
  find . -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' \) 2>/dev/null | sort | while IFS= read -r f; do
    [ "$f" = "$HARNESS" ] && continue
    case "$f" in */test/*|*/tests/*|*/example*|*/sample*|*/bench*|*/fuzz/*|*/doc*) continue ;; esac
    grep -qE '\bint[[:space:]]+main[[:space:]]*\(' "$f" && continue
    case "$f" in *.c) cc="$CC" ;; *) cc="$CXX" ;; esac
    "$cc" $LIBFLAGS $INC -c "$f" -o "$ca/o_$n.o" 2>/dev/null || true
    n=$((n + 1))
  done
  if ls "$ca"/*.o >/dev/null 2>&1; then
    ar rcs "$out_a" "$ca"/*.o
    LIB="$out_a"; LAYER=compileall; return 0
  fi
  return 1
}

link_fail() { echo "BOB_MULTITU_BUILD_FAILED ($1)" >&2; tail -25 /work/*/build.log /work/*/cfg.log 2>/dev/null >&2 || true; exit 3; }

if [ "$ENGINE" = afl ]; then
  command -v afl-clang-fast++ >/dev/null 2>&1 || { echo BOB_AFL_UNAVAILABLE >&2; exit 0; }
  DRV=$(find /usr -name libAFLDriver.a -print -quit 2>/dev/null || true)
  test -n "$DRV"
  [ "$HARNESS_C" = 1 ] && HCC=afl-clang-fast || HCC=afl-clang-fast++
  # h_afl: ASAN-instrumented library + harness + driver (afl appends its own flags; no --).
  export CC=afl-clang-fast CXX=afl-clang-fast++ AFL_USE_ASAN=1
  LIBFLAGS="-g -O1 $NOINT"
  build_lib /work/libtarget_afl.a /work/bld_afl || link_fail "afl asan lib"
  echo "BOB_MULTITU_LAYER=$LAYER"
  AFL_USE_ASAN=1 "$HCC" -g -O1 $NOINT $INC -I/work/bld_afl "$HARNESS" -Wl,--start-group /work/libtarget_afl.a -Wl,--end-group "$DRV" -o "$OUT/h_afl" 2>/work/link_afl.log || link_fail "afl harness link"
  # h_cmplog: CmpLog-instrumented library + harness + driver.
  unset AFL_USE_ASAN; export AFL_LLVM_CMPLOG=1
  build_lib /work/libtarget_cl.a /work/bld_cl || link_fail "cmplog lib"
  AFL_LLVM_CMPLOG=1 "$HCC" -g -O1 $NOINT $INC -I/work/bld_cl "$HARNESS" -Wl,--start-group /work/libtarget_cl.a -Wl,--end-group "$DRV" -o "$OUT/h_cmplog" 2>/work/link_cl.log || link_fail "cmplog harness link"
  test -x "$OUT/h_afl" && test -x "$OUT/h_cmplog" && echo BOB_MULTITU_OK
elif [ "$ENGINE" = tsan ]; then
  # ThreadSanitizer arm: a SEPARATE binary because -fsanitize=thread cannot coexist
  # with -fsanitize=address. The library and harness are built with thread (+UBSan,
  # which IS TSan-compatible) and the libFuzzer driver, so a data race surfaces as a
  # "WARNING: ThreadSanitizer:" banner with /src frames — recognized by the same
  # sanitizer-report.js parser and adjudicated by the same differential repro gate.
  [ "$HARNESS_C" = 1 ] && HCC=clang-18 || HCC=clang++-18
  export CC=clang-18 CXX=clang++-18
  LIBFLAGS="-g -O1 -fsanitize=thread,undefined,fuzzer-no-link $NOINT"
  build_lib /work/libtarget_tsan.a /work/bld_tsan || link_fail "tsan lib"
  echo "BOB_MULTITU_LAYER=$LAYER"
  "$HCC" -g -O1 -fsanitize=thread,undefined,fuzzer $NOINT $INC -I/work/bld_tsan "$HARNESS" -Wl,--start-group /work/libtarget_tsan.a -Wl,--end-group -o "$OUT/h_tsan" 2>/work/link_tsan.log || link_fail "tsan harness link"
  test -x "$OUT/h_tsan" && echo BOB_MULTITU_OK
else
  [ "$HARNESS_C" = 1 ] && HCC=clang-18 || HCC=clang++-18
  export CC=clang-18 CXX=clang++-18
  LIBFLAGS="-g -O1 -fsanitize=address,undefined,fuzzer-no-link $NOINT"
  build_lib /work/libtarget.a /work/bld_lf || link_fail "libfuzzer lib"
  echo "BOB_MULTITU_LAYER=$LAYER"
  # link the harness with the libFuzzer driver (fuzzer, NOT fuzzer-no-link) exactly once.
  "$HCC" -g -O1 -fsanitize=address,undefined,fuzzer $NOINT $INC -I/work/bld_lf "$HARNESS" -Wl,--start-group /work/libtarget.a -Wl,--end-group -o "$OUT/h" 2>/work/link_lf.log || link_fail "libfuzzer harness link"
  test -x "$OUT/h" && echo BOB_MULTITU_OK
fi
