#!/usr/bin/env python3
"""Twin-run harness for the cross-role fan-out WIDTH experiment.

Drives the SAME benchmark case slice twice -- an OFF arm and an ON arm -- emitting
one ledger per arm, then hands both ledgers to comparator.compare_ledgers for the
deterministic verdict.

  OFF arm = the shipped default. No queue-policy override (DEFAULT_QUEUE_POLICY:
            max_spawn_depth 1, single-agent recon, governor null).
  ON arm  = width flipped via a per-run queue-policy override (MAX_COVERAGE_PROFILE:
            max_spawn_depth>1, recon fan-out, a SIZED max_total_spawned_agents, an
            in-flight max_concurrent_evaluators cap, NO coverage cap).

HOW EACH ARM SETS ITS POLICY (the operator wiring): an arm exports
BOB_QUEUE_POLICY_OVERRIDE (a JSON object) into the per-cell environment. run_cell.sh
inherits it; the bob session applies it via bob_set_queue_policy at init. The OFF arm
exports NOTHING (shipped default). This module emits the exact override JSON + the
run plan; it does NOT execute the live runs (operator/compute-gated) and does NOT
fabricate a result -- the live drive is run_matrix.sh per arm.

This file is the rig spec + the verdict driver. The fixture tests
(tests/test_twin_run_comparator.py) validate the comparator on synthetic ledgers
with NO live run. Stdlib only.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import comparator  # noqa: E402


# The OFF arm sets no override (shipped default). The ON arm exports this JSON as
# BOB_QUEUE_POLICY_OVERRIDE so the session applies it via bob_set_queue_policy. It is
# exactly comparator.ON_ARM_QUEUE_POLICY -- width flipped, governor SIZED, NO coverage
# cap. Operators size max_total_spawned_agents to host-pool drain before the run.
ON_ARM_OVERRIDE_ENV = "BOB_QUEUE_POLICY_OVERRIDE"


def on_arm_override_json(governor_override=None):
    """The ON arm's queue-policy override JSON (what the harness exports per cell).

    governor_override: optional dict to override the sized ceiling / in-flight cap for
    a specific host pool (e.g. {"max_total_spawned_agents": 256}). Width knobs stay;
    there is NO coverage-cap knob to set -- RANK != BOUND.
    """
    policy = dict(comparator.ON_ARM_QUEUE_POLICY)
    if governor_override:
        policy.update(governor_override)
    return json.dumps(policy, separators=(",", ":"))


def arm_run_plan(arm, ledger_path, governor_override=None):
    """Describe how the operator drives ONE arm (no execution here).

    Returns the env the operator exports + the runner invocation. The OFF arm exports
    no override; the ON arm exports BOB_QUEUE_POLICY_OVERRIDE.
    """
    if arm == "off":
        env = {}  # shipped default; no override
    elif arm == "on":
        env = {ON_ARM_OVERRIDE_ENV: on_arm_override_json(governor_override)}
    else:
        raise ValueError(f"arm must be 'off' or 'on', got {arm!r}")
    return {
        "arm": arm,
        "env": env,
        "ledger": ledger_path,
        # Per-arm matrix drive; LEDGER routes the arm's rows to its own file so the
        # comparator reads two disjoint ledgers. The case slice is identical across
        # arms (same cases.tsv), which is what makes the delta attributable.
        "runner_cmd": ["bash", os.path.join(os.path.dirname(__file__), "run_matrix.sh")],
        "runner_env_extra": {"LEDGER": ledger_path, **env},
    }


def twin_run_plan(off_ledger, on_ledger, governor_override=None):
    """The full two-arm plan the operator executes, then the verdict invocation."""
    return {
        "arms": [
            arm_run_plan("off", off_ledger),
            arm_run_plan("on", on_ledger, governor_override),
        ],
        "verdict_cmd": [
            sys.executable, os.path.join(os.path.dirname(__file__), "..", "comparator.py"),
            "--off-ledger", off_ledger, "--on-ledger", on_ledger, "--pretty",
        ],
        "note": (
            "OPERATOR-GATED: run each arm via its runner_env_extra, then run "
            "verdict_cmd. This planner emits the wiring; it does not run the arms."
        ),
    }


def verdict(off_ledger, on_ledger, governor_override=None):
    """Run the comparator over two FINISHED arm ledgers (post-run convenience)."""
    on_gov = dict(comparator.ON_ARM_QUEUE_POLICY)
    if governor_override:
        on_gov.update(governor_override)
    return comparator.compare_ledgers(off_ledger, on_ledger, on_governor=on_gov)


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    pp = sub.add_parser("plan", help="emit the two-arm run plan (no execution)")
    pp.add_argument("--off-ledger", required=True)
    pp.add_argument("--on-ledger", required=True)

    pv = sub.add_parser("verdict", help="run the comparator over two finished ledgers")
    pv.add_argument("--off-ledger", required=True)
    pv.add_argument("--on-ledger", required=True)

    a = p.parse_args(argv)
    if a.cmd == "plan":
        print(json.dumps(twin_run_plan(a.off_ledger, a.on_ledger), indent=2))
        return 0
    res = verdict(a.off_ledger, a.on_ledger)
    print(json.dumps(res, indent=2))
    return 0 if res["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
