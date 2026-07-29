#!/usr/bin/env python3
"""Twin-run comparator + verdict for the cross-role fan-out width experiment.

Given two finished benchmark arms over the SAME case slice -- an OFF arm (the
shipped default: max_spawn_depth 1, single-agent recon, lifetime governor null)
and an ON arm (width flipped: max_spawn_depth>1, recon fan-out, a SIZED lifetime
governor, an in-flight concurrency cap, NO coverage cap) -- this module computes
the deterministic per-axis deltas and renders the PASS/FAIL verdict.

It builds the HARNESS + the verdict logic. It does NOT run a live measurement and
does NOT fabricate a result: every number is read from artifacts the arms already
wrote (ledger rows + the MCP-owned audit-graded ledgers in each session dir). A
missing artifact yields an explicit "unscoreable" axis, never a silent pass.

Pass bar (faithful to the width experiment; a regression in ANY safety axis FAILS
even if recall rose):
  PASS iff
    (delta findings/chains >= 1 attributable to a FANNED phase)   [recall gain]
  AND (forged / non-discriminating verified rise == 0)            [non-forgeability]
  AND (fixpoint reached in BOTH arms)                             [no truncation]
  AND (ON arm stayed within its sized governor / host pool)       [governor-bounded]
  else FAIL, naming the first failing axis.

Metric sources (each axis names exactly where the number comes from):
  recall  -> ledger rows: recall == "hit" (any) + recall_reproduction == "hit"
             (frame-walk). The fanned-phase attribution rule is below.
  cost    -> ledger rows: cost_usd (reconstructed by cost_parser from the Claude
             transcript by the adapter). Reported as context, NOT a gate axis.
  forged  -> the four MCP-owned audit-graded ledgers per session dir
             (composition-verified / repro-verified / invariant-verified /
             finding-differential-verified). Read from disk; never self-reported.
  fixpoint-> ledger row status == "complete" AND no spawn_budget_exhausted
             coverage-gap in spawn-ledger.jsonl (a governor truncation, not a
             genuine drain to fixpoint).
  governor-> spawn-ledger.jsonl lifetime total <= the ON arm's sized
             max_total_spawned_agents; the OFF arm (governor null) is exempt.

Stdlib only. Deterministic given two arm inputs.
"""
import json
import os


# ---- arm config (the two queue-policy overrides the harness applies per arm) ----
#
# OFF = the shipped DEFAULT_QUEUE_POLICY (queue-policy.js): single-spawner, depth 1,
# governor null. ON = the MAX_COVERAGE_PROFILE (queue-policy.js): width flipped with
# a SIZED lifetime governor + an in-flight cap, NO coverage cap. The harness applies
# these via bob_set_queue_policy at session init; this module records them so the
# verdict can echo the exact arm definition and check the ON governor.
OFF_ARM_QUEUE_POLICY = {
    "max_spawn_depth": 1,           # no nesting: today's single/sequential behavior
    "max_spawn_children": 8,
    "max_concurrent_evaluators": None,
    "max_total_spawned_agents": None,  # null = unbounded = drain to fixpoint
}

# ON arm: operator SIZES max_total_spawned_agents to host-pool drain. 512 mirrors the
# named MAX_COVERAGE_PROFILE; the harness may override per host. RANK != BOUND: this is
# an external operator COST ceiling (stop-and-report on exhaustion), never a coverage
# cap -- there is deliberately NO top-k / coverage truncation knob here.
ON_ARM_QUEUE_POLICY = {
    "max_spawn_depth": 3,           # width flipped: nested cross-role fan-out enabled
    "max_spawn_children": 64,
    "max_concurrent_evaluators": 128,   # the in-flight host-pool concurrency cap
    "max_total_spawned_agents": 512,    # the SIZED lifetime governor (stop+report)
}

# The audit-graded verified-ledger basenames (paths.js AUDIT_GRADED_BASENAMES). These
# are MCP-write-only / agent-Write-blocked, so the verified count cannot be forged by a
# worker; the comparator reads them straight off disk as the non-forgeable source.
VERIFIED_LEDGER_BASENAMES = (
    "composition-verified.jsonl",
    "repro-verified.jsonl",
    "invariant-verified.jsonl",
    "finding-differential-verified.jsonl",
)

SPAWN_LEDGER_BASENAME = "spawn-ledger.jsonl"

# A row in any of the four ledgers carries result in {verified_pass, refuted,
# inconclusive}. A genuine pass requires a DISCRIMINATING flip (distinct positive vs
# control execution hashes); a hash-identical / non-discriminating control is minted
# as refuted, never pass. So the "forged / non-discriminating verified" count we must
# not let rise is: any verified_pass row that is degenerate (missing distinct
# positive/control execution identities) -- a pass that lacks a discriminating flip.
RESULT_VERIFIED_PASS = "verified_pass"


def _read_jsonl(path):
    rows = []
    try:
        with open(path, encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    rows.append(json.loads(ln))
                except Exception:
                    # A malformed line is NOT a silent drop on a safety axis: callers
                    # that gate on this treat a parse error via the file-missing /
                    # unscoreable path. Here we skip the line but the count of parsed
                    # rows is what the verdict sees, so a corrupt ledger reads LOW,
                    # never spuriously high -- it cannot inflate a verified count.
                    pass
    except FileNotFoundError:
        return None
    return rows


# ---- the non-forgeable verified read (per session dir) -------------------------

def _row_has_discriminating_flip(row):
    """A verified_pass is genuine only with two DISTINCT executed identities.

    Mirrors the verifier mint rules (finding-differential-verifier.js /
    repro-replay-verifier.js): a hash-identical or non-discriminating control cannot
    flip. We re-check the persisted row's executed-identity fields so a structurally
    degenerate verified_pass (same positive/control identity, or missing identities)
    is classified as forged/non-discriminating, NOT counted as a real verified.
    """
    # Differential-style ledgers: positive vs control hashes/run-ids must both exist
    # and DIFFER. command_hash style (repro) binds one executed command; the verifier
    # already refused a non-flip, so presence of a command_hash on a pass is the
    # executed binding. Compose ledger: leaf live_verdict_hash bound to executed bytes.
    pos = row.get("positive_row_hash") or row.get("positive_run_id")
    ctl = row.get("control_row_hash") or row.get("control_run_id")
    if pos is not None or ctl is not None:
        # differential row: both must be present AND distinct
        return bool(pos) and bool(ctl) and pos != ctl
    # non-differential executed binding (repro command_hash / composition leaf hash)
    bound = (
        row.get("command_hash")
        or row.get("results_hash")
        or row.get("live_verdict_hash")
        or row.get("snapshot_hash")
    )
    return bool(bound)


def read_verified_counts(session_dir):
    """Read the four audit-graded ledgers and return per-arm verified accounting.

    Returns a dict:
      {
        "ledgers_present": [basename, ...],   # which of the four existed
        "any_present": bool,
        "verified_pass": int,                 # genuine, discriminating passes
        "forged_nondiscriminating": int,      # pass rows lacking a discriminating flip
        "non_pass": int,                      # refuted/inconclusive (context only)
      }
    forged_nondiscriminating is the SAFETY number the verdict gates on.
    """
    present = []
    verified_pass = 0
    forged = 0
    non_pass = 0
    any_present = False
    if session_dir:
        for base in VERIFIED_LEDGER_BASENAMES:
            rows = _read_jsonl(os.path.join(session_dir, base))
            if rows is None:
                continue
            any_present = True
            present.append(base)
            for row in rows:
                result = row.get("result")
                if result == RESULT_VERIFIED_PASS:
                    if _row_has_discriminating_flip(row):
                        verified_pass += 1
                    else:
                        forged += 1
                else:
                    non_pass += 1
    return {
        "ledgers_present": present,
        "any_present": any_present,
        "verified_pass": verified_pass,
        "forged_nondiscriminating": forged,
        "non_pass": non_pass,
    }


# ---- fixpoint + governor reads (per session dir) -------------------------------

def read_spawn_governor(session_dir):
    """Read spawn-ledger.jsonl for the lifetime total + any exhaustion stop.

    Returns:
      {
        "ledger_present": bool,
        "lifetime_total": int,            # spawned agents counted into the ledger
        "spawn_budget_exhausted": bool,   # a governor truncation (NOT fixpoint)
      }
    A spawn_budget_exhausted entry means the lifetime governor stopped the drain and
    reported a coverage gap -- so fixpoint was NOT reached on that arm.
    """
    out = {"ledger_present": False, "lifetime_total": 0, "spawn_budget_exhausted": False}
    if not session_dir:
        return out
    rows = _read_jsonl(os.path.join(session_dir, SPAWN_LEDGER_BASENAME))
    if rows is None:
        return out
    out["ledger_present"] = True
    out["lifetime_total"] = len(rows)
    for row in rows:
        decision = row.get("decision") or row.get("kind")
        gap = row.get("coverage_gap") or {}
        if decision == "spawn_budget_exhausted" or gap.get("kind") == "spawn_budget_exhausted":
            out["spawn_budget_exhausted"] = True
    return out


# ---- per-arm metric assembly from a ledger row set -----------------------------

def _last_rows_by_cell(ledger_rows):
    by_cell = {}
    for r in ledger_rows:
        by_cell[r.get("cell_id")] = r
    return by_cell


def arm_metrics(ledger_rows, session_dir_by_cell=None):
    """Aggregate ONE arm's metrics from its ledger rows + per-cell session dirs.

    ledger_rows: list of emit_row dicts for this arm (over the case slice).
    session_dir_by_cell: optional {cell_id: session_dir} to read the audit-graded
      ledgers + spawn ledger. When a row carries "session_dir", that is used as the
      fallback so the comparator works off a single ledger file too.
    """
    session_dir_by_cell = session_dir_by_cell or {}
    by_cell = _last_rows_by_cell(ledger_rows)

    findings_total = 0
    chains_total = 0
    any_hits = 0
    repro_hits = 0
    cost_usd = 0.0
    cost_present = False
    verified_pass = 0
    forged = 0
    all_complete = True
    any_exhausted = False
    lifetime_total = 0
    governor_ledger_present = False
    n_cells = 0

    for cell_id, row in by_cell.items():
        n_cells += 1
        nf = row.get("n_findings")
        if isinstance(nf, int):
            findings_total += nf
        nc = row.get("n_chains")
        if isinstance(nc, int):
            chains_total += nc
        if row.get("recall") == "hit":
            any_hits += 1
        if row.get("recall_reproduction") == "hit":
            repro_hits += 1
        c = row.get("cost_usd")
        if isinstance(c, (int, float)):
            cost_usd += c
            cost_present = True
        if row.get("status") != "complete":
            all_complete = False

        sdir = session_dir_by_cell.get(cell_id) or row.get("session_dir")
        vc = read_verified_counts(sdir)
        verified_pass += vc["verified_pass"]
        forged += vc["forged_nondiscriminating"]
        gov = read_spawn_governor(sdir)
        if gov["ledger_present"]:
            governor_ledger_present = True
        lifetime_total += gov["lifetime_total"]
        if gov["spawn_budget_exhausted"]:
            any_exhausted = True

    return {
        "n_cells": n_cells,
        "findings_total": findings_total,
        "chains_total": chains_total,
        "any_hits": any_hits,
        "repro_hits": repro_hits,
        "cost_usd": round(cost_usd, 6) if cost_present else None,
        "verified_pass": verified_pass,
        "forged_nondiscriminating": forged,
        # fixpoint reached iff every cell drained to a terminal complete AND no arm
        # cell hit the lifetime-governor exhaustion stop (a truncation, not a drain).
        "fixpoint_reached": all_complete and not any_exhausted,
        "all_complete": all_complete,
        "spawn_budget_exhausted": any_exhausted,
        "lifetime_total": lifetime_total,
        "governor_ledger_present": governor_ledger_present,
    }


# ---- the comparator + verdict --------------------------------------------------

def compare(off_metrics, on_metrics, on_governor=ON_ARM_QUEUE_POLICY,
            require_fanned_attribution=True):
    """Deterministic verdict over two arm-metric dicts (OFF, ON).

    on_governor: the ON arm's sized queue policy (its max_total_spawned_agents is the
      lifetime ceiling the ON arm must stay within).
    require_fanned_attribution: when True, a recall gain only counts if it is
      attributable to a FANNED phase -- expressed as: the ON arm spawned MORE agents
      than the OFF arm (the width actually engaged). Without extra agents, an apparent
      gain is run-to-run noise, not the fan-out, so it does not satisfy the recall axis.

    Returns:
      {
        "axes": { recall, non_forgeability, fixpoint, governor: {pass: bool, ...} },
        "deltas": { findings, chains, any_hits, repro_hits, cost_usd, forged, ... },
        "verdict": "PASS" | "FAIL",
        "failing_axis": str | None,   # the FIRST failing axis on a FAIL
        "feasible": bool,             # rig produced a scoreable comparison
      }
    """
    d_findings = on_metrics["findings_total"] - off_metrics["findings_total"]
    d_chains = on_metrics["chains_total"] - off_metrics["chains_total"]
    d_any = on_metrics["any_hits"] - off_metrics["any_hits"]
    d_repro = on_metrics["repro_hits"] - off_metrics["repro_hits"]
    d_forged = on_metrics["forged_nondiscriminating"] - off_metrics["forged_nondiscriminating"]
    d_lifetime = on_metrics["lifetime_total"] - off_metrics["lifetime_total"]

    cost_off = off_metrics.get("cost_usd")
    cost_on = on_metrics.get("cost_usd")
    d_cost = (cost_on - cost_off) if (isinstance(cost_off, (int, float))
                                      and isinstance(cost_on, (int, float))) else None

    # The recall-gain signal: more findings OR chains OR scored hits on the ON arm.
    recall_gain = max(d_findings, d_chains, d_any, d_repro)
    # Attribution: the gain must come from the fan-out actually engaging. The ON arm
    # spawning strictly more agents is the deterministic, artifact-grounded witness
    # that a fanned phase ran (recon angles / per-finding verifiers / nested cells).
    fanned_engaged = (d_lifetime > 0) if require_fanned_attribution else True

    # ---- axis 1: recall gain attributable to a fanned phase ----
    recall_pass = (recall_gain >= 1) and fanned_engaged
    recall_axis = {
        "pass": recall_pass,
        "recall_gain": recall_gain,
        "delta_findings": d_findings,
        "delta_chains": d_chains,
        "delta_any_hits": d_any,
        "delta_repro_hits": d_repro,
        "fanned_phase_engaged": fanned_engaged,
        "delta_lifetime_agents": d_lifetime,
    }

    # ---- axis 2: non-forgeability (forged/non-discriminating verified must not rise)
    nonforge_pass = d_forged <= 0
    nonforge_axis = {
        "pass": nonforge_pass,
        "off_forged": off_metrics["forged_nondiscriminating"],
        "on_forged": on_metrics["forged_nondiscriminating"],
        "delta_forged": d_forged,
        "off_verified_pass": off_metrics["verified_pass"],
        "on_verified_pass": on_metrics["verified_pass"],
    }

    # ---- axis 3: fixpoint reached in BOTH arms (no truncation) ----
    fixpoint_pass = bool(off_metrics["fixpoint_reached"]) and bool(on_metrics["fixpoint_reached"])
    fixpoint_axis = {
        "pass": fixpoint_pass,
        "off_fixpoint": off_metrics["fixpoint_reached"],
        "on_fixpoint": on_metrics["fixpoint_reached"],
        "off_spawn_budget_exhausted": off_metrics["spawn_budget_exhausted"],
        "on_spawn_budget_exhausted": on_metrics["spawn_budget_exhausted"],
    }

    # ---- axis 4: ON arm within its sized governor / host pool ----
    ceiling = (on_governor or {}).get("max_total_spawned_agents")
    if ceiling is None:
        # An ON arm with a null governor is mis-configured for this experiment: the
        # whole point is a SIZED ceiling. Fail-closed: the governor axis cannot pass.
        governor_pass = False
        governor_reason = "ON arm governor (max_total_spawned_agents) is null; the width arm MUST size it"
    else:
        within = on_metrics["lifetime_total"] <= ceiling
        governor_pass = within
        governor_reason = (
            "within sized governor" if within
            else f"ON lifetime total {on_metrics['lifetime_total']} exceeds sized ceiling {ceiling}"
        )
    governor_axis = {
        "pass": governor_pass,
        "on_lifetime_total": on_metrics["lifetime_total"],
        "sized_ceiling": ceiling,
        "reason": governor_reason,
    }

    axes = {
        "recall": recall_axis,
        "non_forgeability": nonforge_axis,
        "fixpoint": fixpoint_axis,
        "governor": governor_axis,
    }

    # FAIL on the FIRST failing axis, in a fixed order so the verdict is deterministic.
    # Safety axes are evaluated even when recall did not rise, so the verdict names the
    # most informative failure: a recall flat AND a safety regression both surface.
    order = ["recall", "non_forgeability", "fixpoint", "governor"]
    failing_axis = next((name for name in order if not axes[name]["pass"]), None)
    verdict = "PASS" if failing_axis is None else "FAIL"

    feasible = (
        off_metrics["n_cells"] > 0
        and on_metrics["n_cells"] > 0
    )

    return {
        "axes": axes,
        "deltas": {
            "findings": d_findings,
            "chains": d_chains,
            "any_hits": d_any,
            "repro_hits": d_repro,
            "forged": d_forged,
            "cost_usd": d_cost,
            "lifetime_agents": d_lifetime,
        },
        "off": off_metrics,
        "on": on_metrics,
        "verdict": verdict,
        "failing_axis": failing_axis,
        "feasible": feasible,
    }


def compare_ledgers(off_ledger_path, on_ledger_path, on_governor=ON_ARM_QUEUE_POLICY,
                    off_session_dirs=None, on_session_dirs=None):
    """Convenience: load two arm ledger files and run the comparison."""
    off_rows = _read_jsonl(off_ledger_path) or []
    on_rows = _read_jsonl(on_ledger_path) or []
    off_m = arm_metrics(off_rows, off_session_dirs)
    on_m = arm_metrics(on_rows, on_session_dirs)
    return compare(off_m, on_m, on_governor=on_governor)


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--off-ledger", required=True, help="OFF arm ledger (JSONL of emit_row rows)")
    p.add_argument("--on-ledger", required=True, help="ON arm ledger (JSONL of emit_row rows)")
    p.add_argument("--pretty", action="store_true")
    a = p.parse_args(argv)
    res = compare_ledgers(a.off_ledger, a.on_ledger)
    print(json.dumps(res, indent=2 if a.pretty else None,
                     separators=None if a.pretty else (",", ":")))
    return 0 if res["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
