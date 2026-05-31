# AGENTS.md — how to run the bob-oss benchmark (operational runbook)

**Read this before touching the benchmark.** This is the *operational* guide (how to
run it without producing invalid results). The *strategy/methodology* rationale lives in
`runner/README.md` (and `docs/BOB_OSS_BENCHMARK_PLAN.md` if committed). This file exists
because the first full run (2026-05-31) was **silently invalidated** by a Docker-access
trap — every safeguard below maps to a real failure that has already happened.

---

## 0. The six commandments (violate one → your run is garbage)

1. **Run as `openclaw`, never root.** Claude, the subscription OAuth, the docker group,
   and the MCP all live under `openclaw`.
2. **Docker MUST be reachable by the bob-oss process.** Without it, bob-oss silently
   degrades to *static-only* (no ASAN harness, no fuzzing, no crash inputs) and STILL
   emits graded findings — so "it produced findings" does **not** mean it worked.
3. **tmux inherits the *server's* groups, not your login's.** Always start a **fresh tmux
   server on its own socket** (`tmux -L bobbench …`) from a fresh `sudo -iu openclaw`
   login. Never reuse the default server (Bob's `claude*` sessions run there and predate
   the docker-group grant → its panes lack `docker`).
4. **Gate on the first cell's build.** After cell #1, confirm
   `repo-env.json → docker_build.status == "ok"`. If it's `"failed"`, STOP — the run is
   static-only and worthless. Do not let the other cells proceed.
5. **One `claude -p` per cell drives the whole pipeline.** Verified: a single headless
   invocation runs build → hunter waves → chain → 3-round verify → grade → report with
   `resumes:0`. The runner's resume loop is a safety net, not the normal path.
6. **PII guard is absolute** (see §10). Never submit operator personal data to any tool.

---

## 1. What this measures

bob-oss attacks **one** local repo per `/bob-oss` invocation. The runner turns that into a
matrix over CyberGym-joined ARVO cases (`runner/cases.tsv`), scores each against ARVO
ground truth (`scorer.py`), reconstructs cost from the Claude transcript, and rolls up a
headline (`runner/aggregate.py` → `results/RESULTS.md`).

**Two recall flavors — never conflate them:**
- **Reproduction recall** (`recall_reproduction`, `case_level.frame_hits`): the §4.3
  ASAN-frame walk on an oracle- or self-reported crash. The **only CyberGym-comparable**
  number. Requires a replayable crash input. bob-oss rarely emits one → expect this ~0.
- **Localization recall** (`localization_hits`, included in any-hit `recall`): a weaker
  fallback — did the finding's `file_path` land in Fix_B (+ compatible self-reported
  crash class)? Self-reported, NOT reproduction. This is bob's native-strength signal.
- **`unscoreable`**: finding had no location at all → excluded from the denominator (not a
  miss).

Co-headline the **novel-yield** track (bob's real *new* findings that aren't the planted
bug) separately — the recall metric scores those zero by design.

---

## 2. Critical preconditions

| precondition | check | fix if wrong |
|---|---|---|
| Host is **x86_64** | `uname -m` → `x86_64` | use the VPS, not an arm64 Mac (ASAN/compiler-rt friction conflates build vs discovery failures) |
| Logged in as **openclaw** | `whoami` → `openclaw` | `sudo -iu openclaw` (root SSH lands as root) |
| **docker** in your groups | `id -nG` includes `docker` | you're on a stale tmux server — see §3 |
| docker actually works | `docker ps` succeeds | start a fresh tmux server (§3); confirm `openclaw` ∈ `getent group docker` |
| MCP connected | `cd /home/openclaw/oss-bench && claude mcp list` → `bountyagent ✓` | OSS build not installed / dev-synced |
| disk headroom | `df -h /` (ARVO/toolchain images are big; bob builds per-case images) | prune old `repo-runs/` and dangling images |

> **The 2026-05-31 trap, in one line:** the run's tmux pane had `groups: openclaw` (no
> docker) because it attached to a server started before the docker-group grant, while a
> fresh login had `groups: openclaw docker`. All 9 cells built-failed in <50ms with
> `permission denied … /var/run/docker.sock` and ran static-only. **This is the single
> most likely way to waste a multi-hour run. Check it.**

---

## 3. How to run (the correct sequence)

```bash
# 0) land as openclaw (root SSH → sudo)
ssh <vps>            # lands as root
sudo -iu openclaw    # now openclaw, with the docker group

# 1) FRESH tmux server on its own socket (NOT the default server)
tmux -L bobbench new-session -d -s bench -c /home/openclaw/oss-bench-src/benchmark/runner
#    verify the pane has docker BEFORE running anything:
tmux -L bobbench send-keys -t bench 'id -nG; docker ps >/dev/null 2>&1 && echo OK || echo DENIED' Enter
tmux -L bobbench capture-pane -t bench -p | tail -2     # expect: "... docker" and "OK"

# 2) SMOKE one small cell, then HARD-GATE on its build status
tmux -L bobbench send-keys -t bench \
  "bash -lc 'cd /home/openclaw/oss-bench-src/benchmark/runner && ONLY_CASE=18562 MODEL=opus ./run_matrix.sh' 2>&1 | tee /home/openclaw/oss-bench-runs/smoke.log" Enter
#    when it finishes (~30-60 min), CHECK THE BUILD (see §4). If status != "ok": STOP.

# 3) FULL matrix (only after the smoke's build is confirmed "ok")
tmux -L bobbench send-keys -t bench \
  "bash -lc 'cd /home/openclaw/oss-bench-src/benchmark/runner && BUDGET_USD=1200 MODEL=opus ./run_matrix.sh' 2>&1 | tee /home/openclaw/oss-bench-runs/matrix.log" Enter
```

The matrix is **idempotent** (skips cells already `status:complete` in the ledger),
**serial**, and **budget-capped** (`BUDGET_USD`, API-equivalent; it refuses a new cell
once spend crosses the ceiling). Knobs (env): `BUDGET_USD`, `MODEL` (empty = inherit),
`ONLY_CASE`, `USE_ORACLE=1` (independent ARVO re-exec, +~5.78 GB image/case),
`KEEP_REPO_RUNS=1` (keep crash artifacts for later reproduction-scoring), `CELL_TIMEOUT`,
`MAX_RESUMES`.

> **Fresh ledger for a fresh config.** If a previous run used a different configuration
> (e.g. the static-only one), move its ledger aside first so results don't mix:
> `mv results/cybergym_trials.jsonl results/cybergym_trials.<tag>.jsonl`.

---

## 4. The build-status gate (the check that would have saved run #1)

After the first cell completes, read its `repo-env.json` and confirm the build ran:

```bash
sudo -iu openclaw python3 - <<'PY'
import json
d=json.load(open("/home/openclaw/bounty-agent-sessions/bench-18562-t01/repo-env.json"))
db=d["docker_build"]
print("status:", db.get("status"), "exit:", db.get("exit_code"), "dur_ms:", db.get("duration_ms"))
print("stderr:", (db.get("stderr") or "")[:200])
PY
```

- `status: ok` → real build happened; proceed.
- `status: failed`, tiny `duration_ms` (<100), stderr mentions `permission denied …
  docker.sock` → **docker access problem (§2/§3), run is static-only → STOP and fix.**
- `status: failed` with a long duration + compiler errors → a *genuine* build failure for
  that target (first-class result; see §6).

---

## 5. Monitoring a long run

A full 26-case serial run is ~12–25 h. Use a **file-based watcher** run as a single-line
background SSH (see gotcha §10.2 — multi-line/heredoc SSH commands get mangled):

```bash
# install once (heredoc to a file works; running a multi-line bash -lc over ssh does not)
cat > /home/openclaw/oss-bench-runs/watch_matrix.sh <<'SCRIPT'
#!/usr/bin/env bash
LOG=/home/openclaw/oss-bench-runs/matrix.log
LEDGER=/home/openclaw/oss-bench-src/benchmark/results/cybergym_trials.jsonl
for i in $(seq 1 75); do            # ~50 min/window
  grep -q "=== aggregate ===" "$LOG" 2>/dev/null && { echo "DONE rows=$(grep -c '"status":"complete"' "$LEDGER")"; exit 0; }
  sleep 40
done
echo "RUNNING rows=$(grep -c '"status":"complete"' "$LEDGER") current=[$(grep -- '----' "$LOG" | tail -1)]"
SCRIPT
# arm (re-arm on each wake until DONE): single-line, ServerAlive keeps it alive
ssh -o ServerAliveInterval=30 -o ServerAliveCountMax=6 <vps> \
  "sudo -iu openclaw bash /home/openclaw/oss-bench-runs/watch_matrix.sh"
```

Ad-hoc progress check at any time:
```bash
sudo -iu openclaw bash -lc 'grep -c "\"status\":\"complete\"" /home/openclaw/oss-bench-src/benchmark/results/cybergym_trials.jsonl; grep -- "----" /home/openclaw/oss-bench-runs/matrix.log | tail -1'
```

To stop a run without touching Bob: `pkill -f run_matrix.sh; pkill -f run_cell.sh;
pkill -f 'bench-<case-being-run>'` (as openclaw). These patterns never match Bob's
interactive `claude` sessions. Then verify no `bench-*` `claude -p` survivors.

---

## 6. Reading the results

`results/RESULTS.md` (regenerate anytime):
```bash
sudo -iu openclaw bash -lc 'cd /home/openclaw/oss-bench-src/benchmark && python3 runner/aggregate.py --ledger results/cybergym_trials.jsonl --out results/RESULTS.md --pretty'
```

Per-cell ledger row (`results/cybergym_trials.jsonl`) key fields:
- `recall` = any hit (reproduction OR localization); `recall_reproduction` = frame-walk
  only (CyberGym-comparable); `recall_basis` ∈ {frame, localization, mixed, none}.
- `frame_hits` / `localization_hits` / `unscoreable_findings`.
- `grade_verdict`/`grade_score`, `n_findings`/`n_reportable`, `cost_usd`,
  `wall_seconds`, `rc`, `resumes`.

**Scoring rules baked into `scorer.py` (don't relearn the hard way):**
- The §4.3 matcher is **frame-based**. No ASAN frames → it falls back to
  **file-localization** (`file_path ∈ Fix_B` + self-reported class), tagged
  `match_basis:"file_localization"`. A finding's `file_path` alone is NOT used by the
  frame path.
- Under `--oracle`, the oracle is invoked **only for findings that ship their own crash
  input**. A finding with no input is NOT auto-confirmed (otherwise the oracle re-runs the
  builtin PoC and rubber-stamps everything → recall ≡ 1).
- **Build failures and zero-finding SKIPs are first-class results**, not silent
  denominator filler. When reporting recall, classify each cell's
  `docker_build.status` and report the *evaluable* (built) denominator separately. Use
  the build-status snippet in §4 (loop over `target_id`s from the ledger).

---

## 7. Analyzing a finished or partial run

1. Regenerate `RESULTS.md` (§6).
2. **Classify build status per cell** — separate genuine results from infra/build
   failures:
   ```bash
   sudo -iu openclaw python3 - <<'PY'
   import json
   S="/home/openclaw/bounty-agent-sessions"; L="/home/openclaw/oss-bench-src/benchmark/results/cybergym_trials.jsonl"
   for r in (json.loads(x) for x in open(L) if x.strip()):
       try: db=json.load(open(f"{S}/{r['target_id']}/repo-env.json"))["docker_build"]; st=db.get("status")
       except Exception: st="?"
       print(f"{r['case']:>8} {r['project']:<12} build={st} nf={r.get('n_findings')} {r.get('recall')}/{r.get('recall_reproduction')} ${r.get('cost_usd',0):.0f}")
   PY
   ```
3. Report: reproduction recall (frame, CI), localization recall (any-hit, CI) **on the
   built/evaluable denominator**, build-failure count, cost rollup, and novel-yield
   separately. Always state the denominator and any cells excluded.

---

## 8. File map

| path | what |
|---|---|
| `runner/run_matrix.sh` | outer loop over `cases.tsv`; budget ceiling; idempotent; calls `aggregate.py` at the end |
| `runner/run_cell.sh` | one trial: provision (CyberGym tarball or git clone) → launch `claude -p '/bob-oss …'` → resume-to-terminal → adapter → scorer → `emit_row.py` → prune `repo-runs/` |
| `runner/emit_row.py` | assemble one ledger row from `grade.json` + `score.json` + `adapter.summary.json` |
| `runner/aggregate.py` | ledger → recall (reproduction + localization) + Wilson 95% CI + cost → `RESULTS.md` |
| `runner/cases.tsv` | the matrix: `case_id  project  crash_class  n_trials  source_url  vuln_commit  vul_repo_url` |
| `runner/build_cybergym_slice.py` | (re)generate the CyberGym-joined slice → `cases.tsv` + `cybergym_cases.json` |
| `runner/register_case.py` | add a non-CyberGym ARVO case (derive Fix_B via `git diff-tree`) |
| `scorer.py` | §4.3 type-gate → frame-walk → adjacency → dedup, + file-localization fallback; `score_case(... use_oracle=...)`; auto-merges `cybergym_cases.json` |
| `cybergym_cases.json` | scorer ground truth: `crash_type`, `fix_files` (Fix_B), `fix_commit`, `vul_repo_url`, … |
| `arvo_oracle.py` | clean-container ARVO oracle (`reproduce`/`differential`, `--input`, bob-oss caps, `--rmi`) |
| `adapter/bob_oss_adapter.py` | bob-oss session artifacts → normalized findings.jsonl (+ cost-join from transcript) |
| `cost_parser.py` | reconstruct token/$ from a Claude transcript (per-turn, per-model, PII-guarded) |
| `tests/test_localization_fallback.py` | deterministic scorer tests (no docker/oracle needed) — run after editing `scorer.py` |
| `results/cybergym_trials.jsonl` | the ledger (one row per cell; latest row per `cell_id` wins) |
| `results/RESULTS.md` | the human-facing headline |

Host paths (VPS): bench code `/home/openclaw/oss-bench-src/benchmark`; OSS workspace
`/home/openclaw/oss-bench`; sessions `~/bounty-agent-sessions/bench-<case>-tNN`; run scratch
`/home/openclaw/oss-bench-runs`.

---

## 9. Cost

- **Out-of-pocket ≈ $0** — runs on the Claude subscription. Real budget = **rate limits
  (shared with Bob) + wall-clock + disk.**
- **API-equivalent ≈ $15–30/cell** (focused parsers), $50–75 (large projects). The dollar
  figure is the benchmark's `$/bug` numerator, not money spent.
- `BUDGET_USD` is a **governor on compute**, not a wallet limit. ~26 cells ≈ $700–1200
  API-equivalent → set `BUDGET_USD=1200` to finish in one pass.

---

## 10. Gotchas & lessons (each one already bit us)

1. **Docker-via-stale-tmux-server (THE big one).** §2/§3. Always a fresh `tmux -L <sock>`
   server from a fresh login; verify `docker ps` in the pane; gate on `docker_build.status`.
2. **SSH heredoc mangles multi-line `bash -lc '…'` and `for` loops** (newlines stripped,
   `$vars` locally expanded). Write a *script file* on the host (heredoc → `tee`/`cat >`)
   and run the file; keep ad-hoc remote commands to a single line.
3. **bob-oss emits prose findings, not crash inputs** (`with_crashing_input` is usually 0).
   So reproduction recall is structurally ~0 and localization is the meaningful signal.
   If you want real reproduction recall, you must make bob emit/recover a replayable input
   (improve the adapter scavenger + `KEEP_REPO_RUNS=1`) — that's unbuilt work.
4. **`repo-runs/` is pruned per cell by default** (regenerable fuzzers/corpora, large). Set
   `KEEP_REPO_RUNS=1` if you'll re-score with the oracle later (needs the crash artifacts).
5. **`report-writer` subagent cannot `Write`** (subagent Write policy) — in OSS mode the
   orchestrator must write `report.md` from the returned text. (Not on the matrix path, but
   true for interactive bob-oss.)
6. **Don't trust "it produced findings" as "it worked."** Verify the build (§4) and read
   `match_basis` on hits (frame vs localization).

---

## 11. PII guard (project hard rule — applies to every agent here)

Operator personal data in your context (`# userEmail`, `~/.claude/CLAUDE.md`, git config,
etc.) is **read-only knowledge, never tool input**. Never submit the operator's real
email/name/phone/handles to any endpoint; never put them in finding fields. For anything
needing an identifier use synthetic values (`test`, `pentest_user`) or
`bounty_temp_email`. This benchmark touches only local repos and the local oracle, so the
surface is small — keep it that way.

---

## 12. Regenerating / expanding the slice

```bash
python3 runner/build_cybergym_slice.py --n 30 --per-project-cap 2 --seed 7
#  pulls CyberGym tasks.json (HF), keeps arvo:<id>, stratifies by project + ASAN class,
#  drops MSAN/unknown confounds, enriches via ARVO-Meta + GitHub commit API (Fix_B),
#  writes runner/cases.tsv + cybergym_cases.json (scorer auto-merges the latter).
```
Tighter CI needs more *distinct cases*, not more trials/case (≈±0.1 at ~60 cases). Change
`--seed` for a different reproducible sample. For a paired comparison, every row is a
CyberGym `arvo:` task → compare bob's **reproduction** recall to CyberGym **Level-0** only
(bob gets repo-only and does open-ended discovery → a same-case head-to-head is a lower
bound on bob).

---

_Last updated 2026-05-31, after run #1 was invalidated by the Docker/tmux trap (§10.1).
If you hit a new failure mode, add it to §10 so the next agent doesn't._
