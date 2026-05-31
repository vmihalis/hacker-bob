#!/usr/bin/env python3
"""Register a new ARVO case for the benchmark (the deterministic half of slice expansion).

Given a local clone of the project at the fix commit, derives Fix_B (the fix-commit
file set) via `git diff-tree` and prints BOTH:
  1. a GROUND_TRUTH_CASES python dict entry to paste into ../scorer.py
  2. a cases.tsv row to append to cases.tsv

Picking WHICH cases to add (stratified sampling of arvo.db across project + crash
class + difficulty) is a separate VPS-side step — see README.md "Expanding the slice".

Usage:
  register_case.py --repo /path/to/clone --case 41234567 --project foo \\
      --crash "Heap-buffer-overflow READ 4 (asan, target foo_fuzzer)" \\
      --vuln <vuln_commit> --fix <fix_commit>
"""
import argparse, json, subprocess, sys


def git(repo, *args):
    return subprocess.run(["git", "-C", repo, *args],
                          capture_output=True, text=True, check=True).stdout


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, help="local clone (any commit; fix must be fetched)")
    ap.add_argument("--case", required=True)
    ap.add_argument("--project", required=True)
    ap.add_argument("--crash", required=True, help="free-text crash type (scorer canonicalizes it)")
    ap.add_argument("--vuln", required=True)
    ap.add_argument("--fix", required=True)
    ap.add_argument("--source-url", default="")
    ap.add_argument("--crash-class", default="", help="short label for cases.tsv (e.g. heap-buffer-overflow)")
    a = ap.parse_args(argv)

    try:
        git(a.repo, "cat-file", "-e", a.fix + "^{commit}")
    except subprocess.CalledProcessError:
        sys.stderr.write(f"fix commit {a.fix} not present in {a.repo}; `git fetch --all` first.\n")
        return 2
    out = git(a.repo, "diff-tree", "--no-commit-id", "--name-only", "-r", a.fix)
    fix_files = [l for l in out.splitlines() if l.strip()]
    if not fix_files:
        sys.stderr.write("WARNING: empty fix file set — check the fix commit.\n")

    entry = {
        "arvo_id": a.case, "project": a.project, "crash_type": a.crash,
        "fix_files": fix_files, "vulnerable_commit": a.vuln, "fix_commit": a.fix,
    }
    print("# --- paste into GROUND_TRUTH_CASES in scorer.py ---")
    print(f'    "{a.case}": ' + json.dumps(entry, indent=8).replace("\n", "\n    ") + ",")
    print()
    crash_class = a.crash_class or a.crash.split()[0].lower()
    print("# --- append to cases.tsv (TAB-separated) ---")
    print("\t".join([a.case, a.project, crash_class, "1", a.source_url, a.vuln]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
