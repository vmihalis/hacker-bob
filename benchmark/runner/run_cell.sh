#!/usr/bin/env bash
# run_cell.sh <case_id> <trial_index>
#
# Runs ONE bob-oss trial against ONE ARVO case, then scores it (recall via scorer.py
# + cost via the adapter's cost-join) and appends one row to the ledger.
#
# Designed to run AS the openclaw user on the x86_64 VPS (claude/python/docker all
# inherit that user; no internal sudo).  Idempotent: a cell already marked complete
# in the ledger is skipped.  See README.md for the launch ritual.
set -uo pipefail

CASE_ID="${1:?usage: run_cell.sh <case_id> <trial_index>}"
TRIAL="${2:?usage: run_cell.sh <case_id> <trial_index>}"

# ---- config (override via env) --------------------------------------------
BENCH_DIR="${BENCH_DIR:-/home/openclaw/oss-bench-src/benchmark}"
RUNNER_DIR="${RUNNER_DIR:-$BENCH_DIR/runner}"
OSS_WS="${OSS_WS:-/home/openclaw/oss-bench}"
OPENCLAW_HOME="${OPENCLAW_HOME:-$HOME}"
WORK="${WORK:-/home/openclaw/oss-bench-runs}"
REPOS_DIR="${REPOS_DIR:-$WORK/targets}"
CASES="${CASES:-$RUNNER_DIR/cases.tsv}"
LEDGER="${LEDGER:-$BENCH_DIR/results/cybergym_trials.jsonl}"
MODEL="${MODEL:-}"                                  # e.g. opus ; empty = inherit session default
BUILD_FLAGS="${BUILD_FLAGS:---build --allow-network}"
CELL_TIMEOUT="${CELL_TIMEOUT:-7200}"                # per claude invocation, seconds
MAX_RESUMES="${MAX_RESUMES:-3}"                     # nudges if -p stops before terminal
USE_ORACLE="${USE_ORACLE:-0}"                       # 1 = independent ARVO re-exec (+5.78GB image/case)
KEEP_REPO_RUNS="${KEEP_REPO_RUNS:-0}"               # 1 = keep big repo-runs/ fuzzers+corpora

cell_id="${CASE_ID}-t$(printf '%02d' "$TRIAL")"
target_id="bench-${cell_id}"
out_dir="$WORK/cells/$cell_id"
logf="$WORK/logs/${cell_id}.streamjson"
mkdir -p "$WORK/logs" "$out_dir" "$REPOS_DIR"

# ---- skip if already complete ---------------------------------------------
if [ -f "$LEDGER" ] && grep -q "\"cell_id\":\"${cell_id}\"" "$LEDGER" 2>/dev/null \
   && grep "\"cell_id\":\"${cell_id}\"" "$LEDGER" | grep -q '"status":"complete"'; then
  echo "[cell $cell_id] already complete in ledger; skipping."
  exit 0
fi

# ---- resolve the case row --------------------------------------------------
row=$(awk -F'\t' -v c="$CASE_ID" '!/^#/ && $1==c {print; exit}' "$CASES")
[ -z "$row" ] && { echo "[cell $cell_id] ERROR: case $CASE_ID not in $CASES"; exit 2; }
project=$(printf '%s' "$row" | cut -f2)
source_url=$(printf '%s' "$row" | cut -f5)
vuln_commit=$(printf '%s' "$row" | cut -f6)
vul_repo_url=$(printf '%s' "$row" | cut -f7)

# ---- provision the vulnerable target (per-case dir) ------------------------
REPO="$REPOS_DIR/$CASE_ID"
BOB_TARGET="$REPO"
if [ -n "$vul_repo_url" ]; then
  # TARBALL MODE: CyberGym repo-vul.tar.gz = byte-identical paired target.
  if [ ! -f "$REPO/.bob_provisioned" ]; then
    echo "[cell $cell_id] fetching CyberGym repo-vul tarball"
    rm -rf "$REPO"; mkdir -p "$REPO"
    tb="$out_dir/repo-vul.tar.gz"
    curl -fsSL --max-time 600 "$vul_repo_url" -o "$tb" \
      || { echo "[cell $cell_id] tarball download failed"; exit 3; }
    tar -xzf "$tb" -C "$REPO" || { echo "[cell $cell_id] extract failed"; exit 3; }
    rm -f "$tb"
    touch "$REPO/.bob_provisioned"
  fi
  # descend wrapper dirs: <REPO>/src-vul/<project>/ -> real repo root
  wrap=$(find "$REPO" -mindepth 1 -maxdepth 1 -type d ! -name '.git' | head -1)
  [ -z "$wrap" ] && wrap="$REPO"
  sub=$(find "$wrap" -mindepth 1 -maxdepth 1 -type d)
  if [ "$(printf '%s\n' "$sub" | grep -c .)" = "1" ]; then BOB_TARGET="$sub"; else BOB_TARGET="$wrap"; fi
  if [ ! -d "$BOB_TARGET/.git" ]; then
    ( cd "$BOB_TARGET" && git init -q && git add -A && git -c user.email=b@b -c user.name=b commit -qm "cybergym repo-vul $CASE_ID" ) 2>/dev/null
  fi
  echo "[cell $cell_id] target root: $BOB_TARGET"
else
  # CLONE MODE: git clone @ vulnerable commit (legacy non-CyberGym cases).
  if [ ! -d "$REPO/.git" ]; then
    echo "[cell $cell_id] cloning $source_url -> $REPO"
    git clone --quiet "$source_url" "$REPO" || { echo "[cell $cell_id] clone failed"; exit 3; }
  fi
  git -C "$REPO" fetch --all --tags --quiet 2>/dev/null
  git -C "$REPO" checkout --quiet --detach "$vuln_commit" \
    || { echo "[cell $cell_id] checkout $vuln_commit failed"; exit 3; }
  git -C "$REPO" clean -fdx --quiet 2>/dev/null   # pristine state between trials
fi

# ---- helpers ---------------------------------------------------------------
complete() { local s="$1"; [ -n "$s" ] && [ -f "$s/grade.json" ] && [ -f "$s/report.md" ]; }
resolve_sdir() {
  local p="$OPENCLAW_HOME/bounty-agent-sessions/$target_id"
  if [ -d "$p" ]; then echo "$p"; return; fi
  find "$OPENCLAW_HOME/bounty-agent-sessions" -maxdepth 1 -mindepth 1 -type d \
       -newermt "@$ts" -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-
}
run_claude() {  # $1 = slash command
  timeout "$CELL_TIMEOUT" bash -lc \
    "cd '$OSS_WS' && claude -p '$1' ${MODEL:+--model '$MODEL'} \
       --permission-mode bypassPermissions --output-format stream-json --verbose"
}

# ---- launch ---------------------------------------------------------------
ts=$(date +%s)
echo "[cell $cell_id] launch  case=$CASE_ID project=$project trial=$TRIAL target_id=$target_id"
run_claude "/bob-oss $BOB_TARGET --target-id $target_id $BUILD_FLAGS" >"$logf" 2>&1
rc=$?

# ---- drive to terminal (resume if -p stopped at the launch barrier) -------
resumes=0
SDIR=$(resolve_sdir)
while ! complete "$SDIR" && [ "$resumes" -lt "$MAX_RESUMES" ]; do
  [ $(( $(date +%s) - ts )) -ge "$CELL_TIMEOUT" ] && { echo "[cell $cell_id] timeout"; break; }
  resumes=$((resumes+1))
  echo "[cell $cell_id] not terminal yet; resume #$resumes"
  run_claude "/bob-oss resume $target_id" >>"$logf" 2>&1
  SDIR=$(resolve_sdir)
done
SDIR=$(resolve_sdir)

# ---- locate the Claude Code transcript for cost-join ----------------------
sid=$(grep -ao '"session_id":"[0-9a-fA-F-]\{8,\}"' "$logf" | head -1 | sed 's/.*"session_id":"//;s/"$//')
projdir=$(ls -d "$OPENCLAW_HOME"/.claude/projects/*oss-bench* 2>/dev/null | head -1)
transcript=""
if [ -n "$sid" ] && [ -n "$projdir" ] && [ -f "$projdir/$sid.jsonl" ]; then
  transcript="$projdir/$sid.jsonl"
elif [ -n "$projdir" ]; then
  transcript=$(find "$projdir" -maxdepth 1 -name '*.jsonl' -newermt "@$ts" -printf '%T@ %p\n' 2>/dev/null \
               | sort -rn | head -1 | cut -d' ' -f2-)
fi

status="incomplete"
complete "$SDIR" && status="complete"
echo "[cell $cell_id] status=$status rc=$rc resumes=$resumes sdir=${SDIR:-NONE}"

# ---- score (adapter -> scorer), only when we have a session dir -----------
if [ -n "$SDIR" ] && [ -d "$SDIR" ]; then
  python3 "$BENCH_DIR/adapter/bob_oss_adapter.py" \
      --session-dir "$SDIR" --out-dir "$out_dir" --case-id "$CASE_ID" \
      ${transcript:+--transcript "$transcript"} --trial-index "$TRIAL" --pretty \
      > "$out_dir/adapter.summary.json" 2> "$out_dir/adapter.err" || echo "[cell $cell_id] adapter warn"

  oracle_flag="--no-oracle"; [ "$USE_ORACLE" = "1" ] && oracle_flag=""
  python3 "$BENCH_DIR/scorer.py" score \
      --findings "$out_dir/findings.jsonl" --case "$CASE_ID" $oracle_flag --pretty \
      > "$out_dir/score.json" 2> "$out_dir/score.err" || echo "[cell $cell_id] scorer warn"
fi

# ---- append the ledger row -------------------------------------------------
wall=$(( $(date +%s) - ts ))
python3 "$RUNNER_DIR/emit_row.py" \
  --cell-id "$cell_id" --case "$CASE_ID" --project "$project" --trial "$TRIAL" \
  --target-id "$target_id" --session-dir "${SDIR:-}" --out-dir "$out_dir" \
  --transcript "${transcript:-}" --rc "$rc" --wall "$wall" --resumes "$resumes" \
  --status "$status" --oracle "$USE_ORACLE" --run-mode "headless -p (runner)" \
  --ledger "$LEDGER"

# ---- disk rotation: drop regenerable fuzzers/corpora ----------------------
if [ "$KEEP_REPO_RUNS" != "1" ] && [ -n "$SDIR" ] && [ -d "$SDIR/repo-runs" ]; then
  rm -rf "$SDIR/repo-runs" && echo "[cell $cell_id] pruned repo-runs/"
fi

[ "$status" = "complete" ] && exit 0 || exit 9
