# bob-oss benchmark

A reproducible, defensible benchmark for **bob-oss** — Hacker Bob's OSS-mode autonomous
C/C++ memory-safety vulnerability-discovery pipeline. It measures how well bob-oss
rediscovers real, historically-fixed bugs in open-source projects, on a slice that is
**paired with a published academic benchmark** so the numbers are comparable, not
self-graded.

## What it measures

bob-oss attacks **one** repo per invocation. This harness wraps it into a matrix over a
**CyberGym-joined ARVO slice**: every case is a real CyberGym `arvo:<id>` task (the same
ID space CyberGym uses), so bob's number can be compared to CyberGym's **Level-0**
(repo-only) results. Each case ships the byte-identical vulnerable checkout CyberGym
agents attacked, plus the fix-commit's touched files (`Fix_B`) as ground truth.

For each case the harness: provisions the target → runs bob-oss headless → scores recall
against `Fix_B` → reconstructs cost from the Claude transcript → appends a ledger row.
`runner/aggregate.py` rolls the ledger into the headline with Wilson 95% CIs.

**Two recall flavors — reported separately, never conflated:**

- **Reproduction recall** — the §4.3 ASAN-frame walk on a re-executed crash. The *only*
  number directly comparable to CyberGym. Requires a replayable crash input.
- **Localization recall** — a strictly weaker fallback: did a finding's file land in
  `Fix_B` (with a compatible self-reported crash class)? Self-reported, *not* reproduced.
  This is bob's native-strength signal (it's a discovery + triage tool, not a directed
  reproduction tool).

**Honest framing baked in:** bob gets only the repo and does *open-ended discovery*, while
CyberGym hands the agent the target bug to *reproduce* (directed). A same-case head-to-head
is therefore a **lower bound** on bob. Build failures and zero-finding SKIPs are
**first-class results**, never silent denominator filler. Bob's real *new* findings that
aren't the planted bug score zero by design and are reported as a separate **novel-yield**
track.

## Where to start

| you want to… | read |
|---|---|
| **run the benchmark correctly** (esp. the Docker/tmux trap that silently invalidates runs) | **[`AGENTS.md`](AGENTS.md)** — the operational runbook, read first |
| understand the strategy / why breadth-over-depth / the CyberGym join | [`runner/README.md`](runner/README.md) |
| read/score results, understand the §4.3 mapping | [`scorer.py`](scorer.py) header + `AGENTS.md` §6 |
| see what each file does | `AGENTS.md` §8 (file map) |

## Layout

```
benchmark/
├── AGENTS.md              # operational runbook (read first)
├── README.md              # this file
├── scorer.py              # §4.3 recall scorer (reproduction + localization)
├── arvo_oracle.py         # clean-container ARVO crash oracle
├── cost_parser.py         # token/$ reconstruction from the Claude transcript
├── cybergym_cases.json    # ground truth (Fix_B files per case)
├── adapter/               # agent-agnostic finding contract + bob-oss adapter
├── runner/                # the matrix runner (run_matrix.sh, run_cell.sh, aggregate.py, …)
├── tests/                 # deterministic scorer tests (no docker/oracle needed)
└── results/               # generated ledgers + RESULTS.md (run output)
```

## Status

Harness + scorer + runner + slice built and validated. First full run (2026-05-31) was
invalidated by a Docker-access trap (now documented in `AGENTS.md` §10.1) and the scorer
was hardened (file-localization fallback + oracle-degeneracy guard + dual recall). A
clean, Docker-enabled re-run is the next step. See `AGENTS.md` for the corrected procedure.

_Internal. Not part of the public `hacker-bob` OSS distribution._
