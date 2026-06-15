#!/usr/bin/env python3
"""Roll the trial ledger up into the comparable headline numbers + RESULTS.md.

Reports (the metrics that let you compare bob-oss to CyberGym / SEC-bench):
  * single-trial recall over ALL complete trials, with a Wilson 95% CI
    (this is the number CyberGym calls pass@1 / single-attempt resolve rate)
  * per-case pass@k (did ANY of a case's trials hit) -> pooled distinct-bug recall
  * per-trial precision (mean over scored cells)
  * cost: total / mean / median per run, API-equivalent (subscription marginal ~$0)
Stdlib only.
"""
import argparse, json, math, statistics, sys


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (p, max(0.0, (c - h) / d), min(1.0, (c + h) / d))


def load(path):
    rows = []
    try:
        for ln in open(path, encoding="utf-8"):
            ln = ln.strip()
            if ln:
                try:
                    rows.append(json.loads(ln))
                except Exception:
                    pass
    except FileNotFoundError:
        pass
    # keep the LAST row per cell_id (re-runs append; latest wins)
    by_cell = {}
    for r in rows:
        by_cell[r.get("cell_id")] = r
    return list(by_cell.values())


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("--billing-usd", type=float, default=None,
                    help="Actual billed USD for this run window (Anthropic console). "
                         "Enables the §7.3/§8 ±5%% reconciliation gate; omit and the "
                         "dollar figure stays labeled reconciliation-pending.")
    a = ap.parse_args(argv)

    all_rows = load(a.ledger)
    total_candidates = len(all_rows)
    rows = [r for r in all_rows if r.get("status") == "complete"]
    n_trials = len(rows)
    hits = sum(1 for r in rows if r.get("recall") == "hit")
    p, lo, hi = wilson(hits, n_trials)

    # Reproduction recall (frame-walk hits only) is the CyberGym-comparable number;
    # any-hit recall additionally counts the weaker file-localization signal.
    repro_hits = sum(1 for r in rows if r.get("recall_reproduction") == "hit")
    rp, rlo, rhi = wilson(repro_hits, n_trials)
    loc_only = sum(1 for r in rows
                   if r.get("recall") == "hit" and r.get("recall_reproduction") != "hit")
    unscoreable_total = sum(r.get("unscoreable_findings") or 0 for r in rows
                            if isinstance(r.get("unscoreable_findings"), int))

    # per-case rollup
    cases = {}
    for r in rows:
        c = r.get("case")
        cases.setdefault(c, {"project": r.get("project"), "trials": 0, "hits": 0})
        cases[c]["trials"] += 1
        cases[c]["hits"] += 1 if r.get("recall") == "hit" else 0
    case_passk_hit = sum(1 for c in cases.values() if c["hits"] >= 1)
    pk_p, pk_lo, pk_hi = wilson(case_passk_hit, len(cases))

    precs = [r["per_trial_precision"] for r in rows
             if isinstance(r.get("per_trial_precision"), (int, float))]
    costs = [r["cost_usd"] for r in rows if isinstance(r.get("cost_usd"), (int, float))]

    # §5.4 build-success + invalid-trial rates — first-class RESULTS, never filters.
    build_ok = sum(1 for r in all_rows if r.get("build_failed") is False)
    build_failed = sum(1 for r in all_rows if r.get("build_failed") is True)
    build_known = build_ok + build_failed
    build_success_rate = round(build_ok / build_known, 4) if build_known else None
    invalid_trials = sum(1 for r in all_rows
                         if r.get("invalid") is True or r.get("status") != "complete")
    invalid_rate = round(invalid_trials / total_candidates, 4) if total_candidates else None
    # Conservative recall: invalid/incomplete trials count as MISSES (no survivorship).
    cons_p, cons_lo, cons_hi = wilson(hits, total_candidates)
    cons_rp, _, _ = wilson(repro_hits, total_candidates)

    # §7.3/§8 run-level cost reconciliation gate (±5% of operator-supplied billing).
    reconstructed_usd = round(sum(costs), 4) if costs else None
    cost_reconciliation = {
        "reconstructed_usd": reconstructed_usd,
        "billing_usd": a.billing_usd,
        "tolerance": 0.05,
        "reconciled": False,
        "status": "no_billing_input",
        "delta_pct": None,
    }
    if a.billing_usd and a.billing_usd > 0 and reconstructed_usd is not None:
        delta = abs(reconstructed_usd - a.billing_usd) / a.billing_usd
        cost_reconciliation["delta_pct"] = round(delta * 100, 2)
        cost_reconciliation["reconciled"] = delta <= 0.05
        cost_reconciliation["status"] = "within_tolerance" if delta <= 0.05 else "exceeds_tolerance"
    cost_label = ("reconciled (within ±5% of billing)" if cost_reconciliation["reconciled"]
                  else "derived externally — reconciliation pending")

    summary = {
        "complete_trials": n_trials,
        "distinct_cases": len(cases),
        "single_trial_recall": round(p, 4),
        "single_trial_recall_ci95": [round(lo, 4), round(hi, 4)],
        "single_trial_recall_fraction": f"{hits}/{n_trials}",
        "single_trial_recall_reproduction": round(rp, 4),
        "single_trial_recall_reproduction_ci95": [round(rlo, 4), round(rhi, 4)],
        "single_trial_recall_reproduction_fraction": f"{repro_hits}/{n_trials}",
        "localization_only_hits": loc_only,
        "unscoreable_findings_total": unscoreable_total,
        "recall_note": ("single_trial_recall counts ANY hit (reproduction OR file-"
                        "localization). Only *_reproduction is comparable to a directed "
                        "reproduction benchmark (CyberGym); localization is a weaker, "
                        "self-reported 'named the right file' signal."),
        "pass_at_k_recall": round(pk_p, 4),
        "pass_at_k_ci95": [round(pk_lo, 4), round(pk_hi, 4)],
        "pass_at_k_fraction": f"{case_passk_hit}/{len(cases)}",
        "mean_per_trial_precision": round(statistics.mean(precs), 4) if precs else None,
        "cost_total_usd": round(sum(costs), 2) if costs else None,
        "cost_mean_usd": round(statistics.mean(costs), 2) if costs else None,
        "cost_median_usd": round(statistics.median(costs), 2) if costs else None,
        # §5.4 first-class denominators (no survivorship).
        "total_candidate_trials": total_candidates,
        "invalid_trials": invalid_trials,
        "invalid_trial_rate": invalid_rate,
        "build_success_rate": build_success_rate,
        "build_success_fraction": (f"{build_ok}/{build_known}" if build_known else None),
        "single_trial_recall_all_candidates": round(cons_p, 4),
        "single_trial_recall_all_candidates_ci95": [round(cons_lo, 4), round(cons_hi, 4)],
        "single_trial_recall_all_candidates_fraction": f"{hits}/{total_candidates}",
        "single_trial_recall_reproduction_all_candidates": round(cons_rp, 4),
        "recall_framing_note": ("'_all_candidates' counts invalid/incomplete trials as misses "
                                "(conservative, no survivorship); the non-suffixed recall is over "
                                "complete trials only. Both are reported per §5.4."),
        # §7.3/§8 cost gate.
        "cost_reconciliation": cost_reconciliation,
        "cost_label": cost_label,
    }

    md = ["# bob-oss benchmark — results", "",
          "_API-equivalent cost is the metered-pricing reconstruction; on a Claude "
          "subscription the marginal out-of-pocket cost is ~$0 (rate-limit / time bound)._", "",
          "## Headline (comparable to CyberGym / SEC-bench)", "",
          f"- **Reproduction recall (CyberGym-comparable):** "
          f"{summary['single_trial_recall_reproduction']} "
          f"({summary['single_trial_recall_reproduction_fraction']}), 95% CI "
          f"[{summary['single_trial_recall_reproduction_ci95'][0]}, "
          f"{summary['single_trial_recall_reproduction_ci95'][1]}] "
          f"— oracle/frame-walk hits only.",
          f"- **Any-hit recall (incl. file-localization):** {summary['single_trial_recall']} "
          f"({summary['single_trial_recall_fraction']}), 95% CI "
          f"[{summary['single_trial_recall_ci95'][0]}, {summary['single_trial_recall_ci95'][1]}] "
          f"— adds {summary['localization_only_hits']} localization-only hit(s); "
          f"NOT directly comparable to CyberGym (localization, not reproduction).",
          f"- **pass@k recall (pooled, distinct cases):** {summary['pass_at_k_recall']} "
          f"({summary['pass_at_k_fraction']})",
          f"- **Mean per-trial precision:** {summary['mean_per_trial_precision']}",
          f"- **Distinct cases / complete trials:** {summary['distinct_cases']} / {summary['complete_trials']}",
          f"- **Recall over ALL candidate trials (conservative, no survivorship):** "
          f"{summary['single_trial_recall_all_candidates']} "
          f"({summary['single_trial_recall_all_candidates_fraction']}) — invalid/incomplete "
          f"trials counted as misses. Invalid-trial rate: {summary['invalid_trial_rate']} "
          f"({summary['invalid_trials']}/{summary['total_candidate_trials']}).",
          f"- **Build-success rate (bob-oss ASAN harness):** {summary['build_success_rate']} "
          f"({summary['build_success_fraction']}) — first-class result, not a filter.",
          f"- **Cost:** total ${summary['cost_total_usd']} | mean ${summary['cost_mean_usd']}/run "
          f"| median ${summary['cost_median_usd']}/run — {summary['cost_label']}"
          + (f" (reconstructed ${summary['cost_reconciliation']['reconstructed_usd']} vs billed "
             f"${summary['cost_reconciliation']['billing_usd']}, Δ{summary['cost_reconciliation']['delta_pct']}%)"
             if summary['cost_reconciliation']['billing_usd'] is not None else ""), "",
          "## Per-case", "",
          "| case | project | trials | hits | pass@1 | pass@k |",
          "|------|---------|-------:|-----:|-------:|:------:|"]
    for cid, c in sorted(cases.items()):
        pk = "✅" if c["hits"] >= 1 else "—"
        md.append(f"| {cid} | {c['project']} | {c['trials']} | {c['hits']} | "
                  f"{round(c['hits']/c['trials'],3) if c['trials'] else 0} | {pk} |")
    md.append("")
    md.append("_Regenerate: `python3 runner/aggregate.py --ledger results/cybergym_trials.jsonl "
              "--out results/RESULTS.md`_")
    md_text = "\n".join(md) + "\n"

    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(md_text)
    sys.stdout.write(json.dumps(summary, indent=2 if a.pretty else None,
                                separators=None if a.pretty else (",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
