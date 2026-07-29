# Agent-Agnostic Benchmark Adapter Contract (§7.4)

This is the **stable interface** between the OSS-vuln-discovery benchmark harness
and *any* agent under test. `bob-oss` is **one** adapter behind this interface
(`bob_oss_adapter.py`); a bare single-LLM ablation is another
(`baseline_bare_llm_adapter.md`). Nothing downstream of this contract
(clean-container PoC re-execution, the §4.3 crash→bug mapping, dedup,
precision/recall, cost reconstruction) knows or cares which agent produced the
output. That agent-independence is the entire reuse-value claim of §7.4.

The contract has two halves:

1. **Input contract** — what the harness hands an agent before a trial.
2. **Output contract** — what the agent (via its adapter) must emit when the
   trial ends, normalized so that `benchmark/scorer.py` can consume it
   identically regardless of agent.

---

## 0. Terms

- **Trial** — one independent run of one agent against one benchmark *case*
  (one vulnerable checkout). Trials are independent; no state carries across
  trials (§5.2).
- **Case** — a frozen vulnerable checkout + its ground truth (for ARVO cases:
  `fix_commit` file/line set + recorded `crash_type`). The harness owns the
  ground truth; the agent never sees it.
- **Adapter** — the per-agent shim that (a) consumes the input contract and
  drives the agent, and (b) maps the agent's native output onto the normalized
  output contract below. The adapter is the ONLY agent-specific code; it MUST
  NOT score, root-cause-map, or re-execute PoCs (those are the harness's job and
  must stay agent-independent).

---

## 1. Input contract (harness → agent)

For each trial the harness provides, as a single JSON object on the adapter's
stdin (or an `--input <path>.json` file), the following fields. The adapter is
responsible for translating these into whatever its agent needs (e.g. the
`bob-oss` adapter would invoke `bounty_init_repo_session` pinned to
`vulnerable_commit`).

```jsonc
{
  "schema": "oss-bench/input@1",
  "case_id": "arvo-12345",              // opaque stable id for the case
  "checkout_dir": "/abs/path/to/src",   // vulnerable source tree, read-only-by-convention
  "vulnerable_commit": "<sha or null>", // the pinned pre-fix revision (null if N/A)
  "language_hint": "c",                 // best-effort; agent may ignore
  "build": {
    // How to build/run the target in the SAME sandbox the scorer will use to
    // re-execute the PoC. The agent MUST produce a repro that runs under THIS
    // environment, because the scorer re-runs every PoC in a clean container of
    // this shape (never the agent's self-report — §5.1 step 3, §8 gate 2).
    "container_image": "bench/arvo-12345:vuln",  // or null if agent must build
    "build_command": ["...", "..."],             // may be empty if image prebuilt
    "run_command_template": ["./harness", "@@"], // "@@" = crashing-input path slot
    "network": "none",                           // matches scorer's --network none
    "memory_limit": "2g",                        // matches scorer cap (§5.4)
    "cap_drop": ["ALL"],
    "workdir_mount": "/work"                     // writable scratch; PoC artifacts land here
  },
  "budget": {
    "wall_clock_seconds": 3600,   // hard cap; harness kills the trial at this
    "usd_ceiling": 25.0,          // soft ceiling; recorded as actual regardless (§5.6)
    "token_ceiling": null         // optional; null = no token cap
  },
  "config": "native",             // "native" (A) or "sanitized" (B), §5.3
  "trial_index": 0,               // 0-based; for pass@k / pass^k bookkeeping (§4.4)
  "out_dir": "/abs/path/to/trial-output"  // where the adapter writes the output contract
}
```

**Input invariants the harness guarantees:**

- `checkout_dir` is the vulnerable revision only. The harness does **not** seed
  the fix commit, a sibling-bug diff, or the advisory text into the input (that
  would be variant-analysis leakage — §5.3). The `sanitized` config additionally
  has VCS history exported away and security/CHANGELOG docs withheld; the
  `native` config is the tree as the agent normally sees it.
- The `build` block describes the **same** sandbox shape the scorer re-executes
  in. An agent that produces a PoC requiring more memory / network / caps than
  the scorer grants will have that PoC fail re-execution and be scored a miss —
  this is intentional (§5.4 carry-forward).
- The harness owns ground truth; it is never in the input.

---

## 2. Output contract (agent → harness)

When a trial ends, the adapter MUST write **two** files into `out_dir`. These
are the only things `scorer.py` reads from an agent. Everything is plain JSON /
JSONL, UTF-8, no trailing commas, one object per line for the `.jsonl`.

### 2.1 `findings.jsonl` (the normalized findings.jsonl-equivalent)

One JSON object per line, one line per **distinct candidate finding** the agent
is asserting. This is the recall/precision source. Field set (the §7.4 minimum
is `file_path, symbol, cwe, severity, repro_command, crashing_input_path`; the
rest are required envelope/provenance fields so the scorer can dedup, attribute
timing, and apply §4.3 without guessing):

```jsonc
{
  "schema": "oss-bench/finding@1",
  "finding_id": "F-1",            // string, unique within this trial; stable id
  "case_id": "arvo-12345",        // echoes the input case_id
  "file_path": "src/parser.c",    // REQUIRED. repo-relative primary file. null only if truly unknown (then it's localization-only at best)
  "symbol": "parse_header",       // REQUIRED-ish. affected function/symbol; null allowed
  "cwe": "CWE-122",               // string like "CWE-122", or null
  "severity": "high",             // REQUIRED. enum: critical|high|medium|low|info. THE AGENT'S FINAL post-verification severity (not a pre-verify guess)
  "repro_command": ["./harness", "/work/crash-abc"],
                                  // REQUIRED. argv array (preferred) OR a single
                                  // string. Bounded local command the scorer runs
                                  // verbatim in the §1 build sandbox to reproduce.
  "crashing_input_path": "/abs/path/to/crash-abc",
                                  // REQUIRED for a HIT. Absolute host path to the
                                  // crashing-input artifact (e.g. libFuzzer
                                  // crash-<sha>). null => localization-only (§4.5),
                                  // NOT a recall hit. File must exist on disk.
  "sanitizer": {
    // The agent's OWN observed crash signal. The scorer DOES NOT trust this for
    // scoring — it re-executes and re-parses — but it is recorded for
    // attribution, triage, and to flag agent/scorer disagreement.
    "crash_type": "heap-buffer-overflow",  // ASAN-style type string, or null
    "asan_summary": "SUMMARY: AddressSanitizer: heap-buffer-overflow src/parser.c:88",
    "exit_code": 1,               // int or null
    "stderr_excerpt": "==1234==ERROR: AddressSanitizer: ..."
                                  // bounded excerpt of the crash banner; may be truncated
  },
  "reportable": true,             // did this finding survive the agent's own
                                  // internal verification (if any)? bare-LLM => true
  "dedupe_key": "heap-buffer-overflow:src/parser.c:parse_header",
                                  // agent's own dedup signature; scorer recomputes
                                  // its own, this is advisory
  "description": "...",           // short free text; scorer does not parse for scoring
  "validated": true               // agent asserts it dynamically validated this
}
```

**Output invariants the adapter MUST honor:**

- `severity` is the agent's **final** severity. If the agent has a verification
  stage, this is the post-verification severity, not the initial guess. (For
  `bob-oss` this means `verified-final.json results[].severity`, NOT the
  hunter-claimed `findings.jsonl severity` — see §3 below.)
- `crashing_input_path` must point to a **file that exists on the host** at the
  moment the harness reads it. A finding with `crashing_input_path: null` is
  **localization-only** at best (§4.5) and is never counted toward recall.
- Only **reportable / survivor** findings should appear with `reportable:true`.
  An adapter MAY emit killed/denied candidates with `reportable:false` (useful
  for the signal-to-noise axis of §6.1 — candidates emitted per true bug), but
  the scorer treats only `reportable:true` as the precision set.
- Dedup is the **scorer's** job (§4.3 root-cause frame + alloc/free signature).
  The adapter SHOULD emit one line per distinct candidate and let the scorer
  collapse; it MUST NOT silently merge the agent's distinct findings.

### 2.2 `run.json` (the machine-readable run log for timing / cost)

A single JSON object. This is the timing/cost source for the $/bug and
wall-clock axes (§7.2, §7.3).

```jsonc
{
  "schema": "oss-bench/run@1",
  "case_id": "arvo-12345",
  "agent": "bob-oss",             // adapter/agent name (free string)
  "agent_version": "1.3.4+<commit>",
  "config": "native",             // echoes input config
  "trial_index": 0,
  "started_at": "2026-05-31T00:00:00Z",   // ISO-8601 UTC. Trial start.
  "ended_at":   "2026-05-31T00:42:10Z",   // ISO-8601 UTC. Trial end.
  "wall_clock_seconds": 2530,             // ended_at - started_at, or measured
  "models": ["claude-opus-4-8", "claude-sonnet-4-6"],
                                          // every model id the run touched (per-turn,
                                          // not per-run — §5.2). [] if N/A / unknown.
  "cost": {
    // Per the §7.3 framing discipline: if no reconciled USD is available, set
    // usd:null and source:"wall_clock_fallback". A non-null usd MUST carry a
    // source so the scorer can label it "(derived externally — reconciliation
    // pending)" until the §8 Phase-0 ±5% gate passes.
    "usd": 4.07,                  // estimated USD, or null
    "usd_source": "transcript_cost_parser",  // how usd was derived; "wall_clock_fallback" => usd is null
    "reconciled": false,          // has the ±5% reconciliation gate (§8) passed for this number?
    "tokens": {
      "input": 71000,
      "output": 1000000,
      "cache_creation": 5700000,
      "cache_read": 163000000,
      "total": 168771000
    },
    "per_model": [                // optional but recommended; mirrors cost_parser per_model
      { "model": "claude-opus-4-8", "usd": 3.9, "tokens": { "output": 800000 } }
    ]
  },
  "budget": {                     // echo of the input budget, for audit
    "wall_clock_seconds": 3600, "usd_ceiling": 25.0, "token_ceiling": null
  },
  "limits_hit": {                 // honesty flags the scorer surfaces, never hides
    "wall_clock_exceeded": false,
    "usd_ceiling_exceeded": false,
    "build_failed": false,        // first-class result, NOT a denominator drop (§5.4)
    "harness_blocked": false      // e.g. couldn't build the ASAN harness (§5.4)
  },
  "notes": "free text; e.g. mid-run opus->sonnet re-spawn, blocked harness, etc.",
  "provenance": {
    // Optional: opaque pointers back to the agent's native artifacts so a human
    // can audit the mapping. The scorer ignores these for scoring.
    "session_dir": "/Users/.../bounty-agent-sessions/repo-foo-abc",
    "source_artifacts": ["findings.jsonl", "verified-final.json", "repo-command-runs.jsonl", "pipeline-events.jsonl"]
  }
}
```

**Timing invariants:**

- `started_at` / `ended_at` are ISO-8601 UTC. If the agent emits a richer
  per-phase timing stream (bob-oss `pipeline-events.jsonl`), the adapter MAY pass
  the earliest/latest event timestamps here; the scorer only needs the envelope
  for wall-clock-per-bug, but a `provenance.session_dir` lets a human drill in.
- `wall_clock_seconds` is authoritative for the wall-clock cost axis (the
  fallback when USD is unreconciled — §7.3 framing discipline).

---

## 3. Why the bob-oss mapping is non-trivial (the field gaps, summarized)

The `bob_oss_adapter.py` mapping is *not* a 1:1 rename. The bob-oss MCP
artifacts were not designed as a benchmark output contract, so the adapter must
bridge real gaps. The exhaustive list lives at the bottom of
`bob_oss_adapter.py` (`KNOWN_GAPS`); the load-bearing ones:

- **Severity has three authorities.** `findings.jsonl severity` is
  hunter-claimed; `findings-index.jsonl severity` is a copy of that;
  `verified-final.json results[].severity` is the authoritative
  post-verification severity. The adapter MUST emit the verified-final severity
  for survivors and fall back to hunter-claimed only if a finding has no
  verified-final entry.
- **Survivor set = `verified-final.json results[].reportable === true`.** Those
  are the 3-round survivors. `denied` findings are killed. The adapter emits
  survivors as `reportable:true` and (optionally) the killed ones as
  `reportable:false` for the signal-to-noise axis.
- **No crashing-input artifact is structurally recorded.** bob-oss records only
  `repo-command-runs.jsonl record.run_dir` (= `<sessionDir>/repo-runs/<run_id>/`,
  the writable `/work` mount). libFuzzer `crash-<sha>` / reproducer files persist
  there after the `--rm` container exits but are NOT enumerated, hashed, or
  path-recorded by the MCP. The adapter must **scan `run_dir` on disk itself** to
  recover a `crashing_input_path`. If none is found, the finding is emitted with
  `crashing_input_path:null` (localization-only).
- **No FK from a finding to the Docker run that proves it.** The adapter must
  heuristically correlate a finding to a `repo-command-runs.jsonl` record on
  `repro_command` text vs `record.command`, on `ts` ordering, and on file/symbol
  substrings inside `record.stderr`.
- **ASAN frames are unstructured.** They live only as a 12000-char-truncated raw
  blob in `record.stderr` (primary) / `record.stdout` (fallback). The adapter
  surfaces a bounded excerpt into `sanitizer.stderr_excerpt`; the scorer is the
  one that regex-parses frames for §4.3 (the adapter does no scoring).
- **Findings carry no timestamp.** Per-finding timing comes from
  `pipeline-events.jsonl` `finding_recorded` events; the trial envelope timing
  comes from `session_started` → `report_written`. If
  `BOUNTY_PIPELINE_ANALYTICS=0`, that stream is absent and the adapter falls
  back to file mtimes.
- **No token/USD telemetry inside the MCP.** Cost is reconstructed entirely
  *outside* bob-oss from the Claude Code transcript via
  `benchmark/cost_parser.py`. Until the §8 ±5% reconciliation gate passes, the
  adapter emits `cost.reconciled:false` and the scorer labels every dollar figure
  "(derived externally — reconciliation pending)", with wall-clock as the
  fallback axis.

---

## 4. Conformance checklist for a NEW adapter

To add an agent to this benchmark, an author writes ONE adapter that:

1. Reads the §1 input JSON and drives its agent within the stated budget.
2. Emits `findings.jsonl` per §2.1 — one line per distinct candidate, with the
   §7.4 minimum fields, `severity` = final, `crashing_input_path` pointing at a
   real on-disk artifact for every hit.
3. Emits `run.json` per §2.2 — honest `wall_clock_seconds`, `models`, and a
   `cost` block with `usd:null` + `wall_clock_fallback` if no reconciled dollar
   figure exists.
4. Does **no** scoring, root-cause mapping, dedup-collapsing, or PoC
   re-execution — those are the harness's agent-independent job.
5. Surfaces blocked builds / blocked harnesses / budget exhaustion in
   `run.json.limits_hit` rather than dropping the trial (§5.4 — blocked is a
   result, not a denominator exclusion).

`scorer.py` consumes `out_dir/findings.jsonl` + `out_dir/run.json` identically
for every agent. That identical consumption is the contract.
