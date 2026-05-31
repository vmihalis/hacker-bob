#!/usr/bin/env python3
"""Build a CyberGym-JOINED, stratified benchmark slice so bob-oss results are
directly comparable (paired) to CyberGym.

Every selected case is a real CyberGym `arvo:<id>` task, so we can compare bob's
single-trial recall head-to-head with CyberGym's per-task results on identical
cases. The vulnerable target is CyberGym's own `repo-vul.tar.gz` (byte-identical
to what CyberGym agents attacked). Fix_B (the §4.3 fix file set) comes from the
GitHub commit API on the ARVO-Meta `fix` commit; crash_type from ARVO-Meta.

Emits:
  ../cybergym_cases.json   -> merged into scorer GROUND_TRUTH_CASES at import
  cases.tsv                -> the runner matrix (7-col, tarball mode)

Stdlib only.  Needs: network, and `gh` authenticated (for the commit file list).
"""
import argparse, json, os, random, re, subprocess, sys, urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.dirname(HERE)
sys.path.insert(0, BENCH)
try:
    from scorer import canonicalize_crash_type  # reuse the real §4.3 bucketer
except Exception:
    def canonicalize_crash_type(s):  # fallback
        return (s or "").split()[0].lower() if s else "unknown"

# Crash classes bob-oss's ASAN/UBSAN build can actually surface AND the §4.3 gate
# can bucket. We EXCLUDE 'unknown' (catches MSAN Use-of-uninitialized-value + ASAN
# 'UNKNOWN READ/WRITE'), memory-leak, and generic sigsegv: an ASAN-based discovery
# tool would miss MSAN-only / unclassified bugs for SANITIZER reasons, not capability,
# which would be an unfair confound vs CyberGym's sanitizer-aware reproduction task.
ASAN_CORRUPTION = {
    "heap-buffer-overflow", "global-buffer-overflow", "stack-buffer-overflow",
    "heap-buffer-underflow", "heap-use-after-free", "heap-double-free",
    "stack-use-after-return", "stack-use-after-scope", "use-after-poison",
    "alloc-dealloc-mismatch", "container-overflow", "intra-object-overflow",
    "buffer-overflow-generic", "negative-size-param",
}

META_URL = "https://raw.githubusercontent.com/n132/ARVO-Meta/main/archive_data/meta/{id}.json"
TARBALL = "https://huggingface.co/datasets/sunblaze-ucb/cybergym/resolve/main/data/arvo/{id}/repo-vul.tar.gz"
COMMIT_RE = re.compile(r"github\.com/([^/]+)/([^/]+?)(?:\.git)?/commit/([0-9a-fA-F]{7,40})")


def http_json(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "bob-oss-bench"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def fix_files(fix_url):
    m = COMMIT_RE.search(fix_url or "")
    if not m:
        return None, None
    owner, repo, sha = m.group(1), m.group(2), m.group(3)
    try:
        out = subprocess.run(
            ["gh", "api", f"repos/{owner}/{repo}/commits/{sha}", "--jq", ".files[].filename"],
            capture_output=True, text=True, timeout=60, check=True).stdout
        files = [l.strip() for l in out.splitlines() if l.strip()]
        return files or None, sha
    except Exception:
        return None, sha


def enrich(task):
    arvo_id = task["task_id"].split(":", 1)[1]
    try:
        meta = http_json(META_URL.format(id=arvo_id))
    except Exception:
        return None
    crash = meta.get("crash_type")
    ff, sha = fix_files(meta.get("fix", ""))
    if not crash or not ff:
        return None
    return {
        "arvo_id": arvo_id,
        "cybergym_task_id": task["task_id"],
        "project": task["project_name"],
        "language": task.get("project_language", ""),
        "crash_type": crash,
        "crash_bucket": canonicalize_crash_type(crash),
        "fix_files": ff,
        "fix_commit": sha,
        "vulnerable_commit": "",  # CyberGym ships a repo snapshot, not a clean commit
        "vul_repo_url": TARBALL.format(id=arvo_id),
        "source_url": task.get("project_main_repo", ""),
        "severity": meta.get("severity", ""),
    }


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--tasks", default="/tmp/cg_tasks.json")
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--per-project-cap", type=int, default=2)
    ap.add_argument("--per-bucket-cap", type=int, default=8)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--candidate-mult", type=float, default=2.2)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--out-cases", default=os.path.join(HERE, "cases.tsv"))
    ap.add_argument("--out-json", default=os.path.join(BENCH, "cybergym_cases.json"))
    a = ap.parse_args(argv)

    tasks = [t for t in json.load(open(a.tasks)) if t.get("task_id", "").startswith("arvo:")]
    rng = random.Random(a.seed)

    # project-diverse candidate pool: round-robin across shuffled projects, cap per project,
    # interleave c / c++ for language variety.
    by_proj = defaultdict(list)
    for t in tasks:
        by_proj[t["project_name"]].append(t)
    projects = list(by_proj)
    rng.shuffle(projects)
    for p in projects:
        rng.shuffle(by_proj[p])
    want = int(a.n * a.candidate_mult)
    pool, taken = [], defaultdict(int)
    for _round in range(a.per_project_cap):
        for p in projects:
            if taken[p] < len(by_proj[p]) and taken[p] <= _round:
                pool.append(by_proj[p][taken[p]])
                taken[p] += 1
            if len(pool) >= want:
                break
        if len(pool) >= want:
            break

    print(f"candidates: {len(pool)} (from {len(projects)} projects); enriching via ARVO-Meta + gh ...",
          file=sys.stderr)
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        enriched = [e for e in ex.map(enrich, pool) if e]
    print(f"enriched OK: {len(enriched)} (dropped {len(pool)-len(enriched)} on 404 / no-fix-files)",
          file=sys.stderr)

    # keep only ASAN-detectable corruption classes (drop MSAN/unknown/leak confounds).
    n_before = len(enriched)
    enriched = [e for e in enriched if e["crash_bucket"] in ASAN_CORRUPTION]
    print(f"after ASAN-corruption filter: {len(enriched)} (dropped {n_before-len(enriched)} "
          f"MSAN/unknown/unclassified)", file=sys.stderr)

    # down-select to n, balancing crash buckets + capping per project.
    enriched.sort(key=lambda e: (e["crash_bucket"], e["project"]))
    by_bucket = defaultdict(list)
    for e in enriched:
        by_bucket[e["crash_bucket"]].append(e)
    for b in by_bucket:
        rng.shuffle(by_bucket[b])
    buckets = sorted(by_bucket, key=lambda b: -len(by_bucket[b]))
    chosen, proj_count, bucket_count = [], defaultdict(int), defaultdict(int)
    idx = defaultdict(int)
    while len(chosen) < a.n and any(idx[b] < len(by_bucket[b]) for b in buckets):
        for b in buckets:
            if len(chosen) >= a.n:
                break
            while idx[b] < len(by_bucket[b]):
                e = by_bucket[b][idx[b]]; idx[b] += 1
                if proj_count[e["project"]] < a.per_project_cap and bucket_count[b] < a.per_bucket_cap:
                    chosen.append(e); proj_count[e["project"]] += 1; bucket_count[b] += 1
                    break

    chosen.sort(key=lambda e: (e["crash_bucket"], e["project"], e["arvo_id"]))

    # emit scorer ground-truth json
    gt = {e["arvo_id"]: {k: e[k] for k in
          ("arvo_id", "project", "crash_type", "fix_files", "vulnerable_commit",
           "fix_commit", "cybergym_task_id", "vul_repo_url", "language", "severity")}
          for e in chosen}
    with open(a.out_json, "w") as fh:
        json.dump(gt, fh, indent=2)

    # emit runner matrix (7-col, tarball mode)
    lines = [
        "# CyberGym-JOINED benchmark slice (generated by build_cybergym_slice.py).  TAB-separated.",
        "# Every case is a real CyberGym arvo:<id> task -> paired comparison to CyberGym L0.",
        "# Target = CyberGym repo-vul.tar.gz (byte-identical to what CyberGym agents attacked).",
        f"# seed={a.seed} n={len(chosen)} per_project_cap={a.per_project_cap}",
        "# case_id\tproject\tcrash_class\tn_trials\tsource_url\tvuln_commit\tvul_repo_url",
    ]
    for e in chosen:
        lines.append("\t".join([e["arvo_id"], e["project"], e["crash_bucket"], "1",
                                e["source_url"], "", e["vul_repo_url"]]))
    with open(a.out_cases, "w") as fh:
        fh.write("\n".join(lines) + "\n")

    # summary
    print(f"\nSELECTED {len(chosen)} cases -> {a.out_cases} + {a.out_json}")
    bc, pc, lc = defaultdict(int), defaultdict(int), defaultdict(int)
    for e in chosen:
        bc[e["crash_bucket"]] += 1; pc[e["project"]] += 1; lc[e["language"]] += 1
    print("crash classes:", dict(sorted(bc.items(), key=lambda x: -x[1])))
    print("languages:", dict(lc))
    print("distinct projects:", len(pc))
    for e in chosen:
        print(f"  {e['arvo_id']:>8}  {e['project']:<16} {e['crash_bucket']:<24} "
              f"{len(e['fix_files'])} fix-files  {e['severity']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
