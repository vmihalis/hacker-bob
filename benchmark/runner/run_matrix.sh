#!/usr/bin/env bash
# run_matrix.sh
#
# Drives the whole benchmark matrix: for every case in cases.tsv, run n_trials
# serial bob-oss trials via run_cell.sh, with a HARD cost ceiling.  Resumable —
# completed cells are skipped on re-run.  Run this INSIDE tmux as the openclaw
# user so it survives SSH disconnects.  See README.md.
set -uo pipefail

BENCH_DIR="${BENCH_DIR:-/home/openclaw/oss-bench-src/benchmark}"
RUNNER_DIR="${RUNNER_DIR:-$BENCH_DIR/runner}"
WORK="${WORK:-/home/openclaw/oss-bench-runs}"
CASES="${CASES:-$RUNNER_DIR/cases.tsv}"
LEDGER="${LEDGER:-$BENCH_DIR/results/cybergym_trials.jsonl}"
BUDGET_USD="${BUDGET_USD:-300}"     # stop before launching a cell once spend exceeds this
ONLY_CASE="${ONLY_CASE:-}"          # optional: run a single case id (smoke)
export BENCH_DIR RUNNER_DIR WORK CASES LEDGER

mkdir -p "$WORK/logs" "$WORK/cells" "$(dirname "$LEDGER")"

spent() {  # sum cost_usd across complete rows in the ledger
  [ -f "$LEDGER" ] || { echo 0; return; }
  python3 - "$LEDGER" <<'PY'
import json,sys
t=0.0
for ln in open(sys.argv[1]):
    ln=ln.strip()
    if not ln: continue
    try: r=json.loads(ln)
    except Exception: continue
    c=r.get("cost_usd")
    if isinstance(c,(int,float)): t+=c
print(round(t,2))
PY
}

echo "=== bob-oss benchmark matrix ==="
echo "cases=$CASES  ledger=$LEDGER  budget=\$$BUDGET_USD  (API-equivalent; subscription marginal cost ~\$0)"
echo

while IFS=$'\t' read -r case_id project crash ntr rest; do
  case "$case_id" in ''|\#*) continue;; esac
  [ -n "$ONLY_CASE" ] && [ "$case_id" != "$ONLY_CASE" ] && continue
  ntr="${ntr:-1}"
  for trial in $(seq 1 "$ntr"); do
    cur=$(spent)
    if python3 -c "import sys; sys.exit(0 if float('$cur')>=float('$BUDGET_USD') else 1)"; then
      echo "!! budget ceiling hit: spent \$$cur >= \$$BUDGET_USD. Stopping before ${case_id}-t${trial}."
      echo "   raise BUDGET_USD to continue."
      break 2
    fi
    echo "---- ${case_id} trial ${trial}/${ntr}  (spent so far \$$cur) ----"
    bash "$RUNNER_DIR/run_cell.sh" "$case_id" "$trial" || echo "   (cell returned non-zero; see ledger row)"
  done
done < "$CASES"

echo
echo "=== aggregate ==="
python3 "$RUNNER_DIR/aggregate.py" --ledger "$LEDGER" --out "$BENCH_DIR/results/RESULTS.md" --pretty
echo "wrote $BENCH_DIR/results/RESULTS.md  (total spend \$$(spent) API-equivalent)"
