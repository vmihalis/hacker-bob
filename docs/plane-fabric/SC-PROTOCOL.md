# Causal-Fabric Proof Protocol (SC-PROTOCOL)

A preregistered, falsifiable program to **prove or refute** the causal-fabric
thesis for Hacker Bob before betting the architecture on it. The thesis: a
fine-grained causal graph (nodes = function/param/guard-site/sink; edges =
data-flow / control-flow / authorization influence) + agents resolving edges +
composition into exploit **paths** finds real, reproducible vulnerabilities —
especially cross-surface compositional ones — that flat-surface Bob misses, at
acceptable cost, without manufacturing false positives.

This document is the **fix-gate**. It exists because a proof you can adjust after
seeing the data proves nothing. Its integrity is the preregistration: thresholds,
corpus, and methods are committed and counter-signed **before any stage runs**.

---

## 0. Preregistration contract (binding)

No stage runs until ALL of the following are committed to version control and the
sign-off block at the bottom is counter-signed by someone who did not author the
stage being gated:

1. This document, with every numeric threshold in §4 filled (no `TBD`).
2. `corpus-manifest.json` (schema in §6): the target list, planted-path specs,
   expected leaf-verdicts, and the frozen DEV/TEST split — committed BEFORE the
   oracle or any target is run.
3. The typed-replay-predicate spec in §5, with the harness gate change implemented
   and merged, before Stage 0 is graded.

An unset threshold, an unfrozen split, or a self-graded oracle voids the result:
the program is then confirmation theater, not a proof.

---

## 1. Thesis decomposed into independently-falsifiable sub-claims

- **SC1 — confirm-half (the dual of the already-proven refuse-half).** The
  harness can *shape-confirm* a path whose every leaf is a typed-replay
  observation (§5: decisive request/response + a discriminating verdict-flipping
  negative control + a full-tuple replay_hash) and *refuse* one that is merely
  bound (benign-but-bound, non-discriminating control, tampered hash, or untyped).
  The §5 predicate is implemented; a shape-confirm carries `verification_required:
  true` — a precondition, not a proven exploit (the harness is offline and executes
  nothing). SC1's confirm-half is *graded on a `verified_pass`* (§8): a **live
  verifier** (`bob_verify_composition_path`) re-executes each `guard` leaf's control
  battery, re-derives the deterministic verdict, and records it to an MCP-write-only
  verified ledger. A shape-confirm alone never satisfies SC1.
- **SC2 — edge-oracle soundness (precondition 1; graph quality gates everything).**
  A fine-grained code-flow edge oracle (taint / def-use / reachability over real
  source files) mints edges with bounded false-NEGATIVE and false-POSITIVE rates
  on a labeled corpus, graded against an **independent** edge label set — not the
  patch diff, which localizes its own answer. This is the highest-risk sub-claim:
  `surface-graph-builder.js` today parses zero source files.
- **SC3 — non-fabricatable leaf verdicts (precondition 2).** Each edge verdict
  (source IS reachable / guard DOES fail / sink IS sensitive) is bound to a
  replayable artifact whose verdict FLIPS under a decisive control flip and is
  INVARIANT to irrelevant edits — the CB-D1 deterministic AND-over-controls
  template generalized per edge-type. The hand-passed-boolean trap must be
  structurally impossible.
- **SC4 — composition recovers true paths.** Given SC2 + SC3, path search
  composes leaves into the KNOWN true exploit path on planted multi-surface
  positives AND refuses every fabricated/benign variant.
- **SC5 — governor is real (precondition 3).** A cost-weighted expected-
  information-gain governor over populated edge marginals reaches the confirmed
  path in fewer resolved edges than uniform/breadth-first order.
- **SC6 — lift under equal budget, verified-only.** On a held-out split, fabric
  Bob produces strictly more *verified* (blinded-replay-confirmed) findings than
  flat Bob at equal budget, concentrated in cross-surface findings flat Bob
  structurally cannot reach, with no increase in false positives.
- **SC7 — acceptable cost.** The marginal cost per verified finding is within a
  committed multiple of flat Bob's.

---

## 2. Why each sub-claim has a kill-criterion

The fabric is gated on three unbuilt preconditions, and a hallucinated graph
parallelizes hallucination across agents — strictly worse than doing nothing. So
the program is ordered to spend the **cheapest decisive falsifier first** and the
**hardest, most load-bearing gate (the edge oracle) before** any composition,
governor, or lift work. If the fabric is a bad bet, that is learned in under a
month of one engineer, not after a quarter and a burned TEST split.

---

## 3. Anti-confirmation-bias rules (non-negotiable)

- **Negatives are mandatory.** The corpus is ~1:1 positives:negatives. A graph
  that mints paths everywhere is caught by the negative stratum, not flattered by
  an all-positive corpus.
- **Independent labels.** The edge oracle is graded against a hand-labeled edge
  set authored by someone who did not build the oracle and who labels *non-patch*
  and *decoy* edges, not only the patch-localized ones.
- **Split authorship.** The bug-planter, the validator-author, the edge-labeler,
  and the final verifier are different people. No one grades their own artifact.
- **Oracle runs blind** to patch diffs (raw source at the vulnerable commit only).
- **Verified-only.** Findings count only if a blinded verifier replays them.
- **Frozen split.** DEV tunes thresholds; TEST is touched exactly once, after all
  DEV thresholds are frozen.

---

## 4. Committed kill-criteria (preregistered thresholds)

Refute-and-stop unless noted. These are the committed contract; changing a number
after a stage runs voids the proof.

### Stage 0 — SC1 representability
- Genuine hand-built evidenced path confirm rate: **= 100%** — the real path must
  `pass` the offline §5 shape gate **AND** mint a live `verified_pass` from
  `bob_verify_composition_path` for its object-auth guard leaf (the confirm-half is
  graded on the `verified_pass` count in the MCP-write-only `composition-verified.jsonl`
  ledger, never on shape-pass). A shape-pass that does not live-verify cannot
  represent a real exploit — refute.
- Benign-but-bound decoy refuse rate: **= 100%** (`fail`).
- Fabricated-ref decoy refuse rate: **= 100%** (the already-proven refuse-half).
- Counterfeit refute-on-live rate: **= 100%** — a self-consistent observation that
  PASSES the offline §5 gate but whose flip does not reproduce on live re-execution
  must yield `refuted` / no `verified_pass`. This is the relocated-fabrication
  closure: the offline gate alone never grades SC1.
- Guard-leaf verdict flip: **= 100%** (`confirmed → denied` when the guard is
  restored and re-captured) — re-derived live by the verifier, not hand-passed.

### Stage 1 — SC2 edge oracle (on the INDEPENDENT label set, incl. non-patch + decoy edges)
- `edge_oracle_FN_rate` per edge-type (reachability / guard / sink): **≤ 15%**.
- `edge_oracle_FP_rate` per edge-type: precision **≥ 70%** (≤ ~0.43 spurious edges
  per true edge).

### Stage 1 — SC3 verdict fidelity (per edge-type)
- `verdict_flip_fidelity`: **100%** flip on the decisive control, **0%** verdict/
  hash change on an irrelevant field edit.
- Any edge-type lacking a committed deterministic AND-over-controls semantics
  table is **excluded** from path confirmation. If the true path requires an
  excluded edge-type, the path is uncomposable — refute.

### Stage 2 — SC4 composition (DEV first, TEST once)
- `path_recall` on planted true paths: **≥ 70%**.
- `confirmed_false_path_rate` on every negative-stratum target (patched-clean,
  defensible-joint-invariant, benign-but-bound): **= 0** (exactly zero — no
  tolerance).

### Stage 3 — SC5 governor (DEMOTE-not-stop)
- `edges_resolved_to_confirmation`: fabric-EIG **≤ 0.70 ×** breadth-first (≥ 30%
  reduction). On failure, ship trivial ordering; precondition 3 is wasted
  complexity, not a blocker.

### Stage 4 — SC6 + SC7 lift (TEST split, paired / randomized / blinded, equal budget)
- `verified_finding_lift_at_equal_budget`: **> 0**, AND **≥ 50%** of the lift is
  cross-surface findings flat Bob structurally misses, AND **≥ 1** such finding
  exists. If the lift is the same single-surface IDOR a flat run already gets, the
  fabric never escaped K=1 — refute.
- False-positive rate: `FP(fabric) ≤ FP(flat)` (no increase).
- `cost_per_verified_finding(fabric) ≤ 3 × cost_per_verified_finding(flat)`.
- Equal budget frozen on all four axes (wall-clock, tool calls, tokens, target
  touches) within **± 10%**; arm order randomized; grading blinded.

### Sample sizes
- DEV: ≥ 3 positives (≥ 1 multi-surface) + matched negatives at 1:1, ≥ 1 of each
  negative sub-stratum.
- TEST: held-out, ≥ DEV size, ≥ 3 planted cross-surface positives, touched once.

---

## 5. Typed-replay-predicate (the binds → exploits gate)

The §5 gate is the current `composition-experiment-harness.js` implementation; it
replaced the original `isNonEmptyPayload` placeholder (gate iii). A leaf's
`evidence_ref` must resolve to a frontier event of the
canonical kind `observation.recorded` (no other stream may carry replay evidence)
whose payload carries:

```
{
  edge_type:   "reachability" | "guard" | "sink",
  request:     <artifact that exercised the edge>,
  response:    <observed result>,
  verdict:     "confirmed" | "denied",
  negative_control: {
    request:   <the decisive control flipped: guard restored / source made
                unreachable / sink made benign — MUST differ from `request`>,
    response:  <observed result of the flipped control — MUST differ from
                `response`>,
    verdict:   "denied" | "confirmed"     // MUST be the opposite of `verdict`
  },
  replay_hash: <sha256 of canonical
                {edge_type, request, response, verdict, negative_control}>
}
```

A leaf passes the gate ONLY if: the kind is `observation.recorded`, the payload
has this exact shape, `verdict !== negative_control.verdict`, the negative control
is a **different input** (not the same request/response with the verdict
relabelled — a physically impossible flip is refused), and `replay_hash`
recomputes over the **whole decisive tuple** (so the flip claim, not just the
positive half, is tamper-evident).

This is an **offline shape gate, not a live verifier**. A pass means the path's
evidence is replay-shaped, discriminating, and tamper-evident — a NECESSARY
precondition carried as `verification_required: true`. It does NOT execute
requests and therefore does NOT by itself prove the exploit: a producer who
authors a self-consistent but counterfeit observation passes the shape gate. SC1
is only *complete* when a **live verifier** independently re-executes each leaf's
request, observes the response, and confirms the flip — the structural
anti-fabrication is shape + tamper-evidence; the semantic anti-fabrication is
re-execution by a party that did not author the artifact.

---

## 6. Corpus manifest schema (`corpus-manifest.json`, committed before any run)

```
{
  "version": 1,
  "frozen_at": "<ISO timestamp committed before DEV is touched>",
  "split": { "dev": ["<target_id> ..."], "test": ["<target_id> ..."] },
  "targets": [
    {
      "target_id": "<stable id>",
      "stratum": "positive" | "negative",
      "negative_kind": "patched_clean" | "defensible_joint_invariant" | "benign_but_bound" | null,
      "source": "planted" | "cve_patch" | "public_postmortem",
      "ground_truth_ref": "<planted-path spec path | CVE id + patch hunk | post-mortem url>",
      "true_path": [                       // ordered leaves; null/[] for negatives
        { "edge_type": "reachability", "expected_verdict": "confirmed", "evidence_ref": "frontier_event:<id>" },
        { "edge_type": "guard",        "expected_verdict": "confirmed", "evidence_ref": "frontier_event:<id>" },
        { "edge_type": "sink",         "expected_verdict": "confirmed", "evidence_ref": "frontier_event:<id>" }
      ],
      "decoys": [                          // fabricated + benign-but-bound variants
        { "kind": "fabricated_ref", "expected_result": "fail" },
        { "kind": "benign_but_bound", "expected_result": "fail" }
      ],
      "independent_edge_labels": "<path to the hand-labeled edge set authored by the edge-labeler, incl. non-patch + decoy edges>"
    }
  ],
  "manifest_hash": "<sha256 of the canonical manifest minus this field>"
}
```

---

## 7. Stage sequence (each gates the next)

| Stage | Proves | Method | Cost | Gate to next |
|---|---|---|---|---|
| Fix-gate | the proof is honest | sign §4 + commit `corpus-manifest.json` + merge §5 predicate | hours | all committed |
| 0 | SC1 representability | 1 self-hosted target, author-A plants a multi-surface auth-composition bug; author-B writes the §5 predicate blind; run the genuine path + fabricated + benign-but-bound variants | ~1–2 days | §4 Stage-0 thresholds met |
| 1 | SC2 + SC3 (**the real gate**) | minimal file-parsing edge oracle for ONE framework family; run blind on 3–5 DEV positives + their negatives; grade FN/FP vs independent labels; verdict-flip per edge-type | ~1–2 wks | §4 Stage-1 thresholds met |
| 2 | SC4 composition | agentic edge-resolution + path search end-to-end on DEV; every confirmed path replayed through the harness | ~1–2 wks | recall floor + zero false paths |
| 3 | SC5 governor | hold graph/oracle/composition fixed; swap only ordering; EIG vs breadth-first vs current | ~1 wk | demote-or-keep |
| 4 | SC6 + SC7 lift | TEST split touched once; paired/randomized/blinded equal-budget flat-vs-fabric; verified-only; cross-surface breakout; cost ratio | ~1–2 wks | **terminal architecture verdict** |

The most probable death is Stage 1: sound fine-grained extraction is an open
research problem, so the first oracle will likely miss true non-patch cross-
surface edges (silent FN) — which the independent label set is designed to catch.
That is the correct, cheap place to die.

---

## 8. What is already in place

- The **§5 typed-replay shape gate** is built: `bob_run_path_composition_experiment`
  resolves each leaf's `evidence_ref` against real `observation.recorded` events
  and refuses any path with a malformed / unresolved / untyped / non-discriminating
  / tamper-evident-hash-mismatched / wrong-kind leaf. A shape-confirm carries
  `verification_required: true`. This is the OFFLINE precondition — the structural
  anti-fabrication (shape + tamper-evidence), not the semantic proof.
- **Built for object-auth/HTTP (K=1) — SC1's confirm-half live verifier:**
  `bob_verify_composition_path` re-executes each `guard` leaf's CB-D1 7-control
  battery live (a network-capable tool; the offline harness still executes nothing),
  re-derives the deterministic `evaluateObjectAuthDifferential` verdict, and confirms
  the flip *reproduces* — so a self-consistent counterfeit observation that passes
  the offline gate is **refuted** on re-execution. Producer-independence is enforced
  at the integrity boundary, not by producer good behavior: the `verified_pass` is
  written only to the MCP-write-only (audit-graded) `composition-verified.jsonl`
  ledger, and SC1 is graded on *that* count — never on a frontier event, which any
  agent can `bob_append_frontier_event`-launder. The live inputs are structurally
  bound to the leaf: the battery must be a cross-principal SAME-object differential
  aimed at the object the offline observation names, on the same origin, with a
  distinct attacker/victim principal and anonymous discriminating controls —
  otherwise the leaf is `inconclusive`, so the verifier cannot be redirected at a
  different bug or "attacker reads its own object". K=1 boundary: every non-`guard`
  / non-HTTP edge returns `inconclusive` (never a producer-string fallback).
  **Documented K=1 residuals (all fail SAFE — `inconclusive`, never a false
  `verified_pass`):** (i) the reached-oracle is response-class + byte-identical
  victim-object body match, not object-identity semantics — an in-scope endpoint
  returning a constant body to ANY authenticated principal at the victim-object URL
  (anon blocked) would still confirm; (ii) the object selector must live in the path
  or query — body-selected (POST) and header-selected object APIs are not modeled by
  the `{method,url,auth_profile}` probe, so they return `inconclusive`; (iii) binary
  objects are degraded (httpScan returns a synthetic `[Binary: …]` summary, never the
  bytes), so a real binary-object IDOR cannot be live-verified without a textual
  representation. Distinguishing these needs object-identity semantics that do not
  exist at K=1. Generalizing past object-auth — and closing this residual —
  is SC3 (a committed per-edge-type control-semantics table); the remaining
  from-scratch precondition is SC2's edge oracle, not the verifier.
- Composition telemetry (`composed` flag, `hypotheses_per_surface`) exists, so the
  baseline "flat Bob composes nothing" is observable.

---

## 9. Sign-off (preregistration)

| Role | Name | Commit | Date |
|---|---|---|---|
| Protocol author | | | |
| Counter-signer (non-author) | | | |
| Corpus manifest author | | | |
| Edge-label author (Stage 1) | | | |

No stage is graded before its gating sign-off row is filled and committed.
