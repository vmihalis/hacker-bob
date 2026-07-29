#!/usr/bin/env python3
"""Deterministic unit tests for the file-localization fallback + oracle-degeneracy
guard in scorer.py. No docker / no oracle required (use_oracle=False, or oracle
path forced missing). Run: python3 benchmark/tests/test_localization_fallback.py

Uses real ARVO case 18562 (lwan), resolved from cybergym_cases.json:
    crash_type = Global-buffer-overflow READ 3   (bucket: global-buffer-overflow)
    fix_files  = ['src/lib/lwan-config.c']
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import scorer  # noqa: E402

CASE = "18562"


def _verdict(findings, **kw):
    res = scorer.score_case(findings, CASE, use_oracle=False, **kw)
    return res, {f["finding"]: f for f in res["findings"]}


def test_localization_hit_miss_unscoreable():
    findings = [
        {"id": "H", "file_path": "src/lib/lwan-config.c", "symbol": "parse"},
        {"id": "M", "file_path": "src/lib/lwan-request.c", "symbol": "url_decode"},
        {"id": "U", "symbol": "no_location"},
    ]
    res, by = _verdict(findings)

    assert by["H"]["verdict"] == "hit", by["H"]
    assert by["H"]["match_basis"] == "file_localization", by["H"]
    assert by["H"]["matched_fix_file"] == "src/lib/lwan-config.c", by["H"]

    assert by["M"]["verdict"] == "miss", by["M"]
    assert by["M"]["match_basis"] == "file_localization", by["M"]

    assert by["U"]["verdict"] == "unscoreable", by["U"]

    cl = res["case_level"]
    assert cl["hits"] == 1, cl
    assert cl["frame_hits"] == 0, cl          # nothing reproduced
    assert cl["localization_hits"] == 1, cl
    assert cl["unscoreable"] == 1, cl
    assert cl["recall_basis"] == "localization", cl
    print("ok: hit/miss/unscoreable + case_level basis breakdown")


def test_localization_type_gate():
    findings = [
        # right file, but explicit INCOMPATIBLE class (UAF vs overflow) -> miss
        {"id": "T", "file_path": "src/lib/lwan-config.c", "crash_class": "heap-use-after-free"},
        # right file, compatible class -> hit
        {"id": "TO", "file_path": "src/lib/lwan-config.c", "crash_class": "global-buffer-overflow"},
    ]
    _res, by = _verdict(findings)
    assert by["T"]["verdict"] == "miss", by["T"]
    assert "incompatible" in by["T"]["reason"], by["T"]
    assert by["TO"]["verdict"] == "hit", by["TO"]
    print("ok: localization type gate (explicit incompatible class fails, compatible passes)")


def test_oracle_no_input_is_not_rubber_stamped():
    """The degeneracy guard: use_oracle=True but a finding with NO crashing input
    must NOT be auto-confirmed against the builtin PoC. A wrong-file finding stays
    a miss; it falls to file-localization, never a spurious reproduction hit."""
    findings = [{"id": "M", "file_path": "src/lib/lwan-request.c", "symbol": "url_decode"}]
    # Force-missing oracle path so even if the guard regressed, run_oracle would
    # fail rather than actually pull an image; but the guard should skip it entirely.
    res = scorer.score_case(findings, CASE, use_oracle=True,
                            oracle_path="/nonexistent/arvo_oracle.py")
    v = res["findings"][0]
    assert v["verdict"] != "hit", v          # NOT rubber-stamped
    assert v["match_basis"] == "file_localization", v
    assert res["case_level"]["frame_hits"] == 0, res["case_level"]
    print("ok: oracle-no-input degeneracy guard (no spurious reproduction hit)")


def test_empty_findings():
    res = scorer.score_case([], CASE, use_oracle=False)
    cl = res["case_level"]
    assert cl["hits"] == 0 and cl["recall_basis"] == "none", cl
    print("ok: empty findings -> recall_basis none")


if __name__ == "__main__":
    test_localization_hit_miss_unscoreable()
    test_localization_type_gate()
    test_oracle_no_input_is_not_rubber_stamped()
    test_empty_findings()
    print("\nALL LOCALIZATION-FALLBACK TESTS PASSED")
