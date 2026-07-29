#!/usr/bin/env python3
"""Assemble one benchmark ledger row from a finished cell's artifacts and append it.

Reads (best-effort, all optional):
  <session-dir>/grade.json          -> grade_verdict, grade_score
  <out-dir>/score.json              -> recall (case_level.hits>=1), per_trial_precision
  <out-dir>/adapter.summary.json    -> n_findings, n_reportable, cost_usd, wall_clock_seconds
Stdlib only. Never reads transcript text — cost already reconciled by the adapter.
"""
import argparse, json, os, sys


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def main(argv=None):
    p = argparse.ArgumentParser()
    for k in ("cell-id", "case", "project", "target-id", "session-dir",
              "out-dir", "transcript", "run-mode", "status", "ledger"):
        p.add_argument("--" + k, default="")
    p.add_argument("--trial", type=int, default=0)
    p.add_argument("--rc", type=int, default=0)
    p.add_argument("--wall", type=int, default=0)
    p.add_argument("--resumes", type=int, default=0)
    p.add_argument("--oracle", default="0")
    a = p.parse_args(argv)

    grade = _read_json(os.path.join(a.session_dir, "grade.json")) if a.session_dir else None
    score = _read_json(os.path.join(a.out_dir, "score.json")) if a.out_dir else None
    summ = _read_json(os.path.join(a.out_dir, "adapter.summary.json")) if a.out_dir else None

    row = {
        "cell_id": a.cell_id,
        "case": a.case,
        "project": a.project,
        "trial": a.trial,
        "target_id": a.target_id,
        "status": a.status or "unknown",
        "grade_verdict": (grade or {}).get("verdict"),
        "grade_score": (grade or {}).get("total_score"),
        "n_findings": (summ or {}).get("findings_written"),
        "n_reportable": (summ or {}).get("reportable"),
        "recall": None,
        "recall_reproduction": None,
        "recall_basis": None,
        "case_level_hits": None,
        "frame_hits": None,
        "localization_hits": None,
        "unscoreable_findings": None,
        "per_trial_precision": None,
        "oracle_used": (a.oracle == "1"),
        # §5.4 first-class results: build status + whether the trial was scoreable.
        # build_failed: True/False from repo-env.json (None = unknown).
        "build_failed": (summ or {}).get("build_failed"),
        "cost_usd": (summ or {}).get("cost_usd"),
        "cost_reconciled": (summ or {}).get("cost_reconciled"),
        "wall_seconds": a.wall or (summ or {}).get("wall_clock_seconds"),
        "rc": a.rc,
        "resumes": a.resumes,
        "session_dir": a.session_dir,
        "transcript": a.transcript,
        "run_mode": a.run_mode,
    }

    if isinstance(score, dict):
        cl = score.get("case_level") or {}
        hits = cl.get("hits")
        row["case_level_hits"] = hits
        if hits is not None:
            # recall = ANY hit (frame OR localization). recall_basis says which.
            row["recall"] = "hit" if hits >= 1 else "miss"
        row["recall_basis"] = cl.get("recall_basis")
        row["frame_hits"] = cl.get("frame_hits")
        row["localization_hits"] = cl.get("localization_hits")
        row["unscoreable_findings"] = cl.get("unscoreable")
        fh = cl.get("frame_hits")
        if fh is not None:
            # The strict, CyberGym-comparable number: only frame-walk reproductions.
            row["recall_reproduction"] = "hit" if fh >= 1 else "miss"
        row["per_trial_precision"] = cl.get("per_trial_precision")

    # §5.4 anti-survivorship: a trial is INVALID/unscoreable (not a clean miss) when
    # it did not reach a terminal, scoreable state — incomplete session, or no score
    # produced (the documented null-serialization / docker-degraded failure modes).
    # The aggregator counts these as misses in the conservative recall AND reports
    # the invalid-trial rate, instead of silently dropping them.
    row["invalid"] = (row["status"] != "complete") or (row["recall"] is None)

    line = json.dumps(row, separators=(",", ":"))
    if a.ledger:
        with open(a.ledger, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    sys.stdout.write(line + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
