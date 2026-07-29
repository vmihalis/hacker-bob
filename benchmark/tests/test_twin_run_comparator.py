#!/usr/bin/env python3
"""Fixture validation for the twin-run width-experiment comparator.

NO live run. Builds synthetic ledger rows + synthetic session dirs (the four
audit-graded verified ledgers + spawn-ledger.jsonl) and asserts the verdict on the
five canonical scenarios:

  1. ON-better-clean      -> PASS  (more findings, no forged rise, both fixpoint, in-governor)
  2. ON-more-but-forged   -> FAIL  (recall rose but a non-discriminating verified appeared)
  3. ON-fixpoint-broken   -> FAIL  (recall rose but the ON arm hit spawn_budget_exhausted)
  4. ON-over-governor     -> FAIL  (recall rose but ON lifetime total exceeds the sized ceiling)
  5. ON-no-gain           -> FAIL  (no additional finding/chain attributable to a fanned phase)

Each scenario is deterministic and reproducible. Run:
    python3 benchmark/tests/test_twin_run_comparator.py
"""
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import comparator  # noqa: E402


# ---- synthetic-session-dir builders -------------------------------------------

def _write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


def _verified_pass_row(n=0):
    """A GENUINE, discriminating verified_pass (distinct positive/control hashes)."""
    return {
        "result": "verified_pass",
        "finding_id": f"F{n}",
        "positive_row_hash": f"pos{n}",
        "control_row_hash": f"ctl{n}",   # distinct -> a real flip
    }


def _forged_pass_row(n=0):
    """A degenerate verified_pass: positive == control (no discriminating flip)."""
    return {
        "result": "verified_pass",
        "finding_id": f"G{n}",
        "positive_row_hash": f"same{n}",
        "control_row_hash": f"same{n}",  # identical -> non-discriminating
    }


def make_session_dir(root, name, *, verified_pass=0, forged=0,
                     spawned=0, exhausted=False):
    """Build a session dir with the four verified ledgers + a spawn ledger.

    verified_pass: count of genuine discriminating passes (in finding-differential).
    forged: count of degenerate verified_pass rows (the must-not-rise signal).
    spawned: number of spawn-ledger entries (the lifetime total for this cell).
    exhausted: emit a spawn_budget_exhausted coverage-gap entry (governor truncation).
    """
    sdir = os.path.join(root, name)
    os.makedirs(sdir, exist_ok=True)
    diff_rows = [_verified_pass_row(i) for i in range(verified_pass)]
    diff_rows += [_forged_pass_row(i) for i in range(forged)]
    _write_jsonl(os.path.join(sdir, "finding-differential-verified.jsonl"), diff_rows)
    # The other three exist but empty (present-but-zero is a valid, scoreable state).
    for base in ("composition-verified.jsonl", "repro-verified.jsonl",
                 "invariant-verified.jsonl"):
        _write_jsonl(os.path.join(sdir, base), [])
    spawn_rows = [{"agent": f"a{i}", "decision": "spawned"} for i in range(spawned)]
    if exhausted:
        spawn_rows.append({
            "decision": "spawn_budget_exhausted",
            "coverage_gap": {"kind": "spawn_budget_exhausted",
                             "uncovered_surfaces": ["s-leftover"]},
        })
    _write_jsonl(os.path.join(sdir, "spawn-ledger.jsonl"), spawn_rows)
    return sdir


def ledger_row(cell_id, *, n_findings, status="complete", recall="hit",
               recall_repro="miss", session_dir=None, cost_usd=1.0, n_chains=0):
    return {
        "cell_id": cell_id,
        "case": cell_id,
        "status": status,
        "n_findings": n_findings,
        "n_chains": n_chains,
        "recall": recall,
        "recall_reproduction": recall_repro,
        "cost_usd": cost_usd,
        "session_dir": session_dir,
    }


# ---- scenarios -----------------------------------------------------------------

def _arm(rows):
    return comparator.arm_metrics(rows)


def scenario_on_better_clean(root):
    off_sd = make_session_dir(root, "off1", verified_pass=1, forged=0, spawned=2)
    on_sd = make_session_dir(root, "on1", verified_pass=2, forged=0, spawned=6)
    off = [ledger_row("c1", n_findings=1, recall="hit", session_dir=off_sd)]
    on = [ledger_row("c1", n_findings=3, recall="hit", session_dir=on_sd)]
    return comparator.compare(_arm(off), _arm(on))


def scenario_on_more_but_forged(root):
    off_sd = make_session_dir(root, "off2", verified_pass=1, forged=0, spawned=2)
    # ON found more findings AND minted a forged/non-discriminating verified.
    on_sd = make_session_dir(root, "on2", verified_pass=2, forged=1, spawned=6)
    off = [ledger_row("c1", n_findings=1, session_dir=off_sd)]
    on = [ledger_row("c1", n_findings=3, session_dir=on_sd)]
    return comparator.compare(_arm(off), _arm(on))


def scenario_on_fixpoint_broken(root):
    off_sd = make_session_dir(root, "off3", verified_pass=1, spawned=2)
    # ON found more but hit the lifetime-governor exhaustion stop = NOT fixpoint.
    on_sd = make_session_dir(root, "on3", verified_pass=2, spawned=6, exhausted=True)
    off = [ledger_row("c1", n_findings=1, session_dir=off_sd)]
    on = [ledger_row("c1", n_findings=3, session_dir=on_sd)]
    return comparator.compare(_arm(off), _arm(on))


def scenario_on_over_governor(root):
    off_sd = make_session_dir(root, "off4", verified_pass=1, spawned=2)
    # ON found more but spawned 600 > the sized 512 ceiling (governor blown).
    on_sd = make_session_dir(root, "on4", verified_pass=2, spawned=600)
    off = [ledger_row("c1", n_findings=1, session_dir=off_sd)]
    on = [ledger_row("c1", n_findings=3, session_dir=on_sd)]
    # NOTE: 600 spawn entries WITHOUT an exhaustion stop = the governor was NOT
    # enforced (over-spawn), which is exactly the safety regression this axis catches.
    return comparator.compare(_arm(off), _arm(on))


def scenario_on_no_gain(root):
    off_sd = make_session_dir(root, "off5", verified_pass=1, spawned=2)
    # ON spawned more (fan-out engaged) but found NO additional finding/chain.
    on_sd = make_session_dir(root, "on5", verified_pass=1, spawned=6)
    off = [ledger_row("c1", n_findings=2, session_dir=off_sd)]
    on = [ledger_row("c1", n_findings=2, session_dir=on_sd)]
    return comparator.compare(_arm(off), _arm(on))


def scenario_gain_without_fanout(root):
    """Extra guard: recall rose but the ON arm did NOT spawn more agents.

    The gain is then NOT attributable to a fanned phase (run-to-run noise) -> FAIL.
    """
    off_sd = make_session_dir(root, "off6", verified_pass=1, spawned=4)
    on_sd = make_session_dir(root, "on6", verified_pass=1, spawned=4)  # same width
    off = [ledger_row("c1", n_findings=1, session_dir=off_sd)]
    on = [ledger_row("c1", n_findings=3, session_dir=on_sd)]
    return comparator.compare(_arm(off), _arm(on))


# ---- assertions ----------------------------------------------------------------

def run():
    root = tempfile.mkdtemp(prefix="twinrun-fixtures-")
    try:
        r1 = scenario_on_better_clean(root)
        assert r1["verdict"] == "PASS", r1
        assert r1["failing_axis"] is None, r1
        assert r1["feasible"] is True, r1
        assert r1["axes"]["recall"]["recall_gain"] >= 1, r1
        assert r1["axes"]["recall"]["fanned_phase_engaged"] is True, r1
        print("PASS scenario 1 ON-better-clean -> PASS")

        r2 = scenario_on_more_but_forged(root)
        assert r2["verdict"] == "FAIL", r2
        assert r2["failing_axis"] == "non_forgeability", r2
        assert r2["deltas"]["forged"] == 1, r2
        print("PASS scenario 2 ON-more-but-forged -> FAIL (non_forgeability)")

        r3 = scenario_on_fixpoint_broken(root)
        assert r3["verdict"] == "FAIL", r3
        assert r3["failing_axis"] == "fixpoint", r3
        assert r3["axes"]["fixpoint"]["on_spawn_budget_exhausted"] is True, r3
        print("PASS scenario 3 ON-fixpoint-broken -> FAIL (fixpoint)")

        r4 = scenario_on_over_governor(root)
        assert r4["verdict"] == "FAIL", r4
        assert r4["failing_axis"] == "governor", r4
        assert r4["axes"]["governor"]["on_lifetime_total"] > r4["axes"]["governor"]["sized_ceiling"], r4
        print("PASS scenario 4 ON-over-governor -> FAIL (governor)")

        r5 = scenario_on_no_gain(root)
        assert r5["verdict"] == "FAIL", r5
        assert r5["failing_axis"] == "recall", r5
        assert r5["axes"]["recall"]["recall_gain"] == 0, r5
        print("PASS scenario 5 ON-no-gain -> FAIL (recall)")

        r6 = scenario_gain_without_fanout(root)
        assert r6["verdict"] == "FAIL", r6
        assert r6["failing_axis"] == "recall", r6
        assert r6["axes"]["recall"]["fanned_phase_engaged"] is False, r6
        print("PASS scenario 6 gain-without-fanout -> FAIL (recall, unattributable)")

        # Determinism: same inputs -> byte-identical verdict JSON.
        a = json.dumps(scenario_on_better_clean(root), sort_keys=True)
        b = json.dumps(scenario_on_better_clean(root), sort_keys=True)
        assert a == b, "comparator is not deterministic"
        print("PASS determinism: identical inputs -> identical verdict")

        print("\nALL TWIN-RUN COMPARATOR FIXTURES PASSED")
        return 0
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(run())
