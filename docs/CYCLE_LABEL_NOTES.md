# Cycle Label Notes

Status: documentation-only archaeology for PR #61 post-merge task #133.

The Plane Y realization shipped and PR #61 merged as `eac5aa9`. Cycle labels in
the commit history are useful reading aids, but they are not runtime authority.
Do not rewrite the released history to repair label ordering. Rewriting would
invalidate commit hashes that are already referenced by release notes, local
session transcripts, and downstream branches.

## Plane Y Labels Observed

The following labels were observed from:

```sh
git log --all --oneline | grep -E "Y\\.[0-9]+"
```

| Commit | Label | Subject | Note |
| --- | --- | --- | --- |
| `06493ba` | `Y.0` | pre-cycle hotfixes O2 cap raise + secret_detection_bypass, O3 md5+sha256, benchmark-baseline seed | Intentional pre-cycle hotfix, appears before the numbered realization sequence in content but after some spec discussion. |
| `4e65d1c` | `Y.1` | add capability observation kinds + payload validators with B1 attempt-binding lift | First implementation slice. |
| `f9321a5` | `Y.1` | extend capability-observation-shape test with O2 hotfix cap-threshold reference reading live source | Follow-up test hardening reused `Y.1`. |
| `4b250d4` | `Y.2` | add bob_log_capability_friction + bob_log_protocol_drift + bob_emit_runtime_drift | Main Y.2 tool slice. |
| `0d1bb8e` | `Y.2` | add friction-prompt-fragments registry with 9 canonical Y-D19 fragment ids and forward-compat role-trace cross-reference | Later registry slice reused `Y.2`. |
| `e03fbda` | `Y.2.5` | add _write-base + bob_compose_report + bob_write_chain_rollup + bob_amend_report + bob_set_friction_scanners + AUDIT_GRADED_PATHS registry; remove Write from report-writer + chain-builder | Mid-cycle insertion between Y.2 and Y.3. |
| `a7dea39` | `Y.3` | add bob_write_chain_rollup evidence_refs[] validator with EVIDENCE_REF_HANDLE_PREFIXES + LARGE_BODY_THRESHOLD_BYTES + Y.2.5 source-comment sweep | Main Y.3 implementation slice. |
| `87e72ea` | `Y.3` | bump release-check pack-size ceiling to 2.6 MB to mirror test/package.test.js | Release-check follow-up reused `Y.3`. |
| `1dcc3e4` | `Y.4` | extend derivePackForNode with friction_history + target_class | Target-class and friction derivation. |
| `b45e747` | `Y.5` | wave-scheduler derivation slice + trace-reading composer | Scheduler derivation and composer. |
| `cf2cf62` | `Y.6` | friction-to-Hypothesis promotion + role-trace-expectations + STIGMERGIC_PRODUCERS manifest | Producer manifest slice. |
| `ef01e04` | `Y.7` | adversarial transcript scanner registry + W2 extensions + silent_lead_threshold_drop runtime tripwire | Scanner slice. |
| `c6d083f` | `Y.8` | shared skill-parser IR + check:skill-protocol-coherence + check:skill-runtime-constraint-drift | Protocol and runtime-drift gates. |
| `928f57e` | `Y.9` | STIGMERGIC_CONSUMERS manifest + check:stigmergy-coherence + single-spawner-topology test with rev-4.1 chain-bundle audit | Consumer manifest and topology gate. |
| `8ad5282` | `Y.10` | check:skill-scheduler-coherence + advance-session partial-surface runtime gate with getLatestMergedWavePartialSurfaceIds helper | First Y.10 slice. |
| `1c435dc` | `Y.10` | ~/.bob/session-cap nonce + 5 more STATE_CONFLICT remediation backfills | Follow-up hardening reused `Y.10`. |
| `12b0f8e` | `Y.11` | chain-bundle widening on 5 graph tools + chain-builder graph apparatus prompt + hypergraph-adoption test | Graph-tool widening. |
| `7446863` | `Y.12` | surface-leads producer-side rationale + orchestrator handoff-receipt | Surface-leads rationale work. |
| `51d0def` | `Y.13` | terminal smoke 7-subtest end-to-end + rev-4.1 canonical-vocabulary / terminal-table / chain-bundle assertions | Terminal smoke. |
| `74353a3` | closure | Plane Y rev 4.1 closure: wire 4 dormant tools + absorb brutalist defects | Closure commit intentionally not numbered as Y.14. |

## Irregularities

- `Y.1`, `Y.2`, `Y.3`, and `Y.10` appear on more than one commit.
- `Y.2.5` is an explicit insertion rather than a whole-number cycle.
- Closure work after `Y.13` is labeled by purpose rather than by the next cycle
  number.
- Some follow-up commits are better understood as fixups to a prior cycle than
  as new lifecycle phases.

## Reading Guidance

Use the runtime artifacts and tests as authority:

- lifecycle states are defined in `mcp/lib/lifecycle-gates.js`;
- tool authority is defined in the registry and `scripts/authority-inventory.js`;
- Plane Y terminal behavior is pinned by `test/plane-y-smoke.test.js`;
- stigmergy and single-spawner invariants are pinned by their check scripts.

For future planes, prefer one of these label forms:

- `Z.4: <subject>` for the primary cycle commit;
- `Z.4 fixup: <subject>` for a follow-up that intentionally belongs to the
  same cycle;
- `Plane Z closure: <subject>` for post-terminal absorption work.

Do not amend the existing Plane Y commits solely to rename labels.
