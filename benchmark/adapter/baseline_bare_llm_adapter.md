# Baseline: Single-LLM Ablation Adapter (spec stub)

This is the spec for the **single-LLM ablation** adapter (§6.1) behind the same
agent-agnostic contract (`CONTRACT.md`, §7.4). Its entire reason to exist is to
make the ablation **apples-to-apples**: a bare model gets the **same** vulnerable
checkout + the **same** build/run env + the **same** time/cost budget as
`bob-oss`, and must emit the **same** output contract. No multi-agent pipeline,
no 3-round verifier, no Docker proof orchestration — just one model call with the
source and the task. The contribution thesis ("the *system* beats a bare model")
is decided here (§6.1, §9 OQ3).

> Status: SPEC STUB. Implementation (`baseline_bare_llm_adapter.py`) is deferred
> to Phase 0 step 3 (§8). This file pins the design so the implementation is a
> fill-in, not a redesign.

---

## 1. What it must NOT do (so the ablation stays honest)

- **No multi-agent fan-out.** One model session. No parallel hunters, no
  recon/chain/grader roles.
- **No 3-round verifier.** The bare model's first-and-final answer is the
  finding. There is no brutalist/balanced/final adjudication.
- **No bob-oss MCP / task graph.** It does not call `bounty_*` tools. The only
  shared infrastructure is the §1 input contract and the §1 build sandbox.
- **No privileged scaffolding the harness doesn't grant every agent.** It may
  read the checkout, may run build/run commands in the SAME sandbox the scorer
  uses, and may iterate on a crashing input within the budget — because *that
  capability* (compile + run to confirm a crash) is part of the task
  ("find the memory-safety bug, produce a crashing input"), not pipeline magic.
  It must not get the fix commit, sibling diffs, or advisory text (§5.3 leakage).

## 2. Input (identical to CONTRACT.md §1)

Consumes the exact same `oss-bench/input@1` JSON: `checkout_dir`,
`vulnerable_commit`, `build` (image / build_command / `run_command_template` with
the `@@` crashing-input slot / `network:none` / `memory_limit:2g` / `cap_drop`),
`budget` (`wall_clock_seconds`, `usd_ceiling`, `token_ceiling`), `config`
(`native` | `sanitized`), `trial_index`, `out_dir`.

The model is given: the task statement, the source tree, and the ability to
build/run in the sandbox. It is NOT given ground truth.

## 3. Output (identical to CONTRACT.md §2)

Writes the **same two files** into `out_dir`:

### 3.1 `findings.jsonl` (`oss-bench/finding@1`)

One line per distinct candidate the model asserts. Required fields exactly as in
the contract: `file_path`, `symbol`, `cwe`, `severity` (final — the bare model
has no separate verification stage, so its single severity claim *is* the final
severity), `repro_command` (argv it actually used to trigger the crash),
`crashing_input_path` (absolute host path to the artifact it produced — `null` =
localization-only, not a recall hit), plus the `sanitizer` block (the crash it
observed, advisory only — the scorer re-executes), `reportable:true` for every
emitted candidate (no internal kill stage), `dedupe_key`, `description`,
`validated`.

**Signal-to-noise note (§6.1):** the bare model is expected to emit *more*
candidates per true bug (lower precision). The adapter MUST emit **every**
candidate the model proposes as a separate line (with `reportable:true`) so the
"candidates emitted per true bug" axis is measurable. It must NOT pre-filter to
look competitive — that would corrupt the ablation's precision/noise comparison,
which is half the decision rule.

### 3.2 `run.json` (`oss-bench/run@1`)

Same envelope: `started_at` / `ended_at` / `wall_clock_seconds`, `models` (the
single model id used — e.g. `["claude-opus-4-8"]`), and a `cost` block.

**Cost parity.** Cost is reconstructed the **same way** as bob-oss — from the
Claude Code transcript via `benchmark/cost_parser.py` — so the $/bug axis is
computed identically for both arms. Until the §8 ±5% reconciliation gate passes,
`cost.reconciled:false` and the dollar figure is labeled "(derived externally —
reconciliation pending)", with wall-clock as the fallback (§7.3). `limits_hit`
surfaces budget exhaustion / build failure honestly (§5.4) rather than dropping
the trial.

## 4. Implementation sketch (for the deferred .py)

```
load input JSON (§1)
  -> compose ONE prompt: task + repo manifest/source access + the build/run
     contract (so the model knows the exact sandbox its PoC must crash in)
  -> single model session within budget.wall_clock_seconds / usd_ceiling:
       model may iterate: read source, build, run candidate inputs in the
       §1 sandbox, observe ASAN/exit. (Same sandbox the scorer re-executes in.)
  -> for each crash the model lands: persist the crashing input under out_dir,
     record file_path/symbol/cwe/severity/repro_command/crashing_input_path.
  -> write findings.jsonl (one line per candidate, reportable:true)
  -> reconstruct cost via cost_parser.parse_session(transcript) ; write run.json
```

Same model pinning rules as the capability arm (§5.2): record the **exact**
per-turn model id(s) the transcript shows; a mid-run model switch is a distinct
condition, never pooled.

## 5. Why this earns "apples-to-apples"

Both arms: same case, same vulnerable checkout, same build/run sandbox (same
`--network none` / `--memory 2g` / `--cap-drop ALL` caps the scorer enforces),
same budget, same output contract, same scorer, same §4.3 crash→bug mapping,
same transcript-based cost reconstruction. The ONLY difference is the
multi-agent + 3-round-verifier system layer. That isolated difference is exactly
the contribution under test (§6.1 / §9 OQ3): if the pipeline's recall lift is
small but its precision/noise-reduction lift is large, the headline legitimately
reframes to "operator-grade precision, noise reduction, automation at scale" —
decided from pilot data, not post hoc.
