#!/usr/bin/env python3
"""bob-oss adapter for the agent-agnostic benchmark contract (§7.4).

Maps the MCP-owned bob-oss session artifacts onto the normalized output contract
defined in benchmark/adapter/CONTRACT.md, so that benchmark/scorer.py can consume
a bob-oss run identically to any other agent. NO change to bob-oss is required;
this is a pure read-side projection of artifacts bob-oss already writes.

WHAT THIS DOES
    Given a bob-oss session directory (~/bounty-agent-sessions/<domain>/), produce:
      - findings.jsonl  (the normalized findings.jsonl-equivalent, §2.1)
      - run.json        (the machine-readable run log for timing/cost, §2.2)

SOURCE ARTIFACTS (grounded field map; see KNOWN_GAPS for caveats)
    findings.jsonl          -> per-finding fields (file_path, symbol, cwe,
                               repro_command, hunter-claimed severity, ...)
    verified-final.json     -> survivor set + AUTHORITATIVE post-verify severity
    repo-command-runs.jsonl -> exit_code + raw ASAN stderr/stdout + run_dir
                               (the ONLY handle to a crashing-input artifact)
    pipeline-events.jsonl   -> ISO timestamps for trial envelope timing
    grade.json              -> optional: 5-axis grade / verdict (advisory)
    repo-env.json           -> optional: docker_build status (build_failed flag)
    cost_parser.py          -> token/USD reconstruction from the Claude Code
                               transcript (NOT from any MCP artifact)

PII GUARD
    This adapter reads bob-oss artifact JSON and (for cost) defers entirely to
    benchmark/cost_parser.py, which reads ONLY numeric usage + model-id fields.
    This adapter does copy finding description / proof text into the output
    contract's `description` field (the scorer ignores it for scoring), but it
    NEVER reads operator personal data and NEVER submits anything anywhere. It is
    read-only over the session dir + transcript; it writes only into out_dir.

USAGE
    python3 bob_oss_adapter.py \
        --session-dir ~/bounty-agent-sessions/repo-foo-abc \
        --out-dir     /path/to/trial-output \
        [--case-id arvo-12345] \
        [--config native|sanitized] \
        [--trial-index 0] \
        [--agent-version 1.3.4+abc] \
        [--transcript /path/to/<session>.jsonl-or-session-folder] \
        [--input /path/to/input-contract.json]   # supplies case_id/config/budget/etc.

    --input lets the harness pass the §1 input JSON; CLI flags override it.
    If --transcript is given (or auto-discoverable), cost is reconstructed via
    cost_parser.py; otherwise run.json carries usd:null + wall_clock_fallback.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys

# cost_parser lives in the parent benchmark/ dir. Import it as a sibling module.
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_BENCHMARK_DIR = os.path.dirname(_THIS_DIR)
if _BENCHMARK_DIR not in sys.path:
    sys.path.insert(0, _BENCHMARK_DIR)

try:
    import cost_parser  # type: ignore
except Exception:  # pragma: no cover - cost is optional / best-effort
    cost_parser = None


# ---------------------------------------------------------------------------
# Field gaps the bob-oss artifacts do NOT provide for the §7.4 contract.
# Surfaced in run.json.notes and returned by build_known_gaps() so a human (and
# the scorer's provenance audit) can see exactly where the mapping is heuristic.
# ---------------------------------------------------------------------------
KNOWN_GAPS = [
    "crashing_input_path: NOT structurally recorded by bob-oss. The only handle "
    "is repo-command-runs.jsonl record.run_dir (= <sessionDir>/repo-runs/<run_id>/, "
    "the writable /work mount). This adapter scans run_dir on disk for a likely "
    "crash artifact (libFuzzer crash-*/leak-*/oom-*/timeout-* or other files it "
    "wrote); if none is found the finding is emitted with crashing_input_path=null "
    "(localization-only, NOT a recall hit).",
    "No FK from a finding to the repo-command-runs.jsonl run that proves it. "
    "Attribution is heuristic: repro_command text vs record.command, then "
    "file/symbol substrings inside record.stderr, then ts ordering.",
    "ASAN/sanitizer stack frames are NOT structured anywhere -- only a raw "
    "record.stderr (primary) / record.stdout (fallback) blob, EACH truncated to "
    "12000 chars (a verbose build can evict the crash frames). This adapter only "
    "surfaces a bounded excerpt + the parsed crash_type; the scorer owns §4.3 "
    "frame parsing.",
    "Severity authority split: findings.jsonl severity = hunter-claimed; "
    "findings-index.jsonl severity = copy; verified-final.json results[].severity "
    "= authoritative post-verification. This adapter emits verified-final severity "
    "for survivors and falls back to hunter-claimed only when no verified-final "
    "entry exists.",
    "findings.jsonl rows have NO timestamp. Per-finding timing would need "
    "pipeline-events.jsonl 'finding_recorded' ts; trial-envelope timing uses "
    "session_started -> report_written. If BOUNTY_PIPELINE_ANALYTICS=0 the stream "
    "is absent and this adapter falls back to file mtimes for the envelope.",
    "No token/USD telemetry inside the MCP layer. Cost is reconstructed OUTSIDE "
    "bob-oss from the Claude Code transcript via cost_parser.py. Until the §8 "
    "Phase-0 ±5% reconciliation gate passes, cost.reconciled=false and the dollar "
    "figure must be labeled '(derived externally -- reconciliation pending)'.",
    "Docker image BUILD output lives in repo-env.json docker_build.* (separate "
    "artifact), NOT in repo-command-runs.jsonl. A build-time link/ASAN failure "
    "sets limits_hit.build_failed but will not appear among per-command runs.",
    "verified-final.json may be schema v1 or v2; v2-only fields (confidence, "
    "state_sensitive, artifact_hashes, ...) are treated as optional.",
    "grade.json top-level total_score is the MAX per-finding score (not a sum); "
    "this adapter does not fold grade into severity -- severity comes from "
    "verified-final. Grade is carried only as advisory provenance.",
]

# ASAN crash-type, e.g. "==1234==ERROR: AddressSanitizer: heap-buffer-overflow ..."
_ASAN_TYPE_RE = re.compile(r"==\d+==ERROR: AddressSanitizer: ([\w-]+)")
_ASAN_SUMMARY_RE = re.compile(r"SUMMARY: AddressSanitizer: .*")
# UBSAN: "src/x.c:10:5: runtime error: ..."
_UBSAN_RE = re.compile(r"runtime error: .+")
# libFuzzer crash artifacts commonly written under /work.
_CRASH_ARTIFACT_RE = re.compile(r"^(crash|leak|oom|timeout|slow-unit)-[0-9a-fA-F]+")

_SEVERITY_VALUES = ("critical", "high", "medium", "low", "info")
_MAX_EXCERPT = 4000  # bounded crash-banner excerpt we copy into the contract


def _read_jsonl(path):
    """Yield parsed objects from a .jsonl file; tolerant of blank/garbage lines."""
    if not (path and os.path.isfile(path)):
        return
    try:
        fh = open(path, "r", encoding="utf-8", errors="replace")
    except OSError:
        return
    with fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (ValueError, json.JSONDecodeError):
                continue
            if isinstance(obj, dict):
                yield obj


def _read_json(path):
    """Read a single JSON object file; return {} on any failure."""
    if not (path and os.path.isfile(path)):
        return {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            obj = json.load(fh)
    except (OSError, ValueError):
        return {}
    return obj if isinstance(obj, dict) else {}


def _norm_severity(value):
    """Lowercase + validate a severity; return None if not a known value."""
    if not isinstance(value, str):
        return None
    v = value.strip().lower()
    return v if v in _SEVERITY_VALUES else None


def _as_argv(repro_command):
    """Return repro_command as a list[str] argv (preferred) or None.

    findings.jsonl repro_command is a single string. We keep it as a single-string
    argv element (the scorer runs it verbatim); callers that supplied a list are
    passed through. We do NOT shell-split, to avoid mangling quoting -- the scorer
    decides how to execute (the contract allows a single string OR an argv array).
    """
    if repro_command is None:
        return None
    if isinstance(repro_command, list):
        out = [str(x) for x in repro_command if x is not None]
        return out or None
    if isinstance(repro_command, str):
        s = repro_command.strip()
        return [s] if s else None
    return None


# ---------------------------------------------------------------------------
# Crash-artifact recovery: scan record.run_dir for a likely crashing input.
# ---------------------------------------------------------------------------
def _scan_run_dir_for_crash_artifact(run_dir):
    """Return an absolute path to the most likely crashing-input file in run_dir.

    bob-oss does NOT enumerate/path-record crash artifacts (KNOWN_GAPS). We scan
    the writable /work mount on the host. Preference order:
      1. A libFuzzer-style 'crash-<hex>' / 'leak-*' / 'oom-*' / 'timeout-*' file.
      2. Otherwise None (do NOT guess an arbitrary file as 'the crashing input';
         a wrong guess would manufacture a false hit).
    Returns None if run_dir is missing or has no recognizable artifact.
    """
    if not (run_dir and os.path.isdir(run_dir)):
        return None
    candidates = []
    for root, _dirs, files in os.walk(run_dir):
        for name in files:
            if _CRASH_ARTIFACT_RE.match(name):
                full = os.path.join(root, name)
                try:
                    size = os.path.getsize(full)
                except OSError:
                    size = 0
                candidates.append((full, size))
    if not candidates:
        return None
    # Most-recently-modified, tie-broken by smaller size (reducers shrink inputs).
    candidates.sort(
        key=lambda c: (os.path.getmtime(c[0]) if os.path.exists(c[0]) else 0, -c[1]),
        reverse=True,
    )
    return candidates[0][0]


def _parse_crash_signal(stderr_blob, stdout_blob):
    """Extract (crash_type, summary_line, excerpt) from the raw run blobs.

    The scorer owns the real §4.3 frame parsing; here we only surface a bounded
    excerpt + a coarse crash_type for attribution/triage in the contract.
    """
    blob = stderr_blob or ""
    if not blob and stdout_blob:
        blob = stdout_blob

    crash_type = None
    summary = None

    m = _ASAN_TYPE_RE.search(blob)
    if m:
        crash_type = m.group(1)
    s = _ASAN_SUMMARY_RE.search(blob)
    if s:
        summary = s.group(0)
    if crash_type is None:
        u = _UBSAN_RE.search(blob)
        if u:
            crash_type = "undefined-behavior"
            if summary is None:
                summary = u.group(0)

    excerpt = blob[:_MAX_EXCERPT] if blob else ""
    if blob and len(blob) > _MAX_EXCERPT:
        excerpt += "\n[adapter-truncated]"
    return crash_type, summary, excerpt


def _correlate_run(finding, runs):
    """Heuristically pick the repo-command-runs record that proves `finding`.

    No FK exists (KNOWN_GAPS), so this is a deliberately CONSERVATIVE heuristic:
    we attribute a run to a finding ONLY when there is at least one *specific*
    link between them. A run that merely crashed (no shared repro text, file, or
    symbol) is NOT attributed -- otherwise a single crashing run would get
    smeared onto every finding in the session, manufacturing false crashing-input
    hits (exactly the plausible-but-wrong failure mode §4.3 guards against).

    Specific-link signals (at least ONE required for a match):
      +3  repro_command text appears in record.command argv (strong)
      +2  finding file_path basename appears in record.stderr/stdout (medium)
      +2  finding symbol appears in record.stderr/stdout (medium)
    Tie-breaker prior (NOT sufficient on its own):
      +1  record actually crashed (status='failed' / exit_code not in (0,None))
    Returns the best-scoring run with at least one specific link, else None.
    Ties broken by latest ts (a later run is more likely the confirming one).
    """
    repro = finding.get("repro_command")
    repro_text = ""
    if isinstance(repro, str):
        repro_text = repro.strip()
    elif isinstance(repro, list):
        repro_text = " ".join(str(x) for x in repro)

    file_path = finding.get("file_path") or ""
    basename = os.path.basename(file_path) if file_path else ""
    symbol = finding.get("symbol") or ""

    best = None
    best_score = 0
    best_ts = ""
    for rec in runs:
        specific = 0  # points from finding-specific links only
        command = rec.get("command")
        cmd_text = " ".join(str(x) for x in command) if isinstance(command, list) else str(command or "")
        if repro_text and cmd_text and repro_text in cmd_text:
            specific += 3
        stderr = str(rec.get("stderr") or "")
        stdout = str(rec.get("stdout") or "")
        haystack = stderr + "\n" + stdout
        if basename and basename in haystack:
            specific += 2
        if symbol and len(symbol) >= 3 and symbol in haystack:
            specific += 2

        # A crashed run is only a tie-breaker prior; it cannot create a match by
        # itself. No specific link => this run is not attributable to this finding.
        if specific == 0:
            continue

        exit_code = rec.get("exit_code")
        status = rec.get("status")
        crashed = (status == "failed") or (isinstance(exit_code, int) and exit_code != 0)
        score = specific + (1 if crashed else 0)

        ts = str(rec.get("ts") or "")
        if score > best_score or (score == best_score and ts > best_ts):
            best, best_score, best_ts = rec, score, ts
    return best


# ---------------------------------------------------------------------------
# Timing from pipeline-events.jsonl (envelope), else file mtimes.
# ---------------------------------------------------------------------------
def _envelope_timing(session_dir, events):
    """Return (started_at_iso, ended_at_iso, wall_clock_seconds) best-effort."""
    started = None
    ended = None
    for ev in events:
        ts = ev.get("ts")
        if not isinstance(ts, str):
            continue
        etype = ev.get("type")
        if etype == "session_started" and started is None:
            started = ts
        # Track the latest ts as a robust 'ended' even if report_written is absent.
        if ended is None or ts > ended:
            ended = ts
        if etype == "report_written":
            ended = ts  # prefer the explicit terminal event when present

    if started is None or ended is None:
        # Fallback to file mtimes over the session dir.
        started_mtime, ended_mtime = _mtime_bounds(session_dir)
        started = started or _iso(started_mtime)
        ended = ended or _iso(ended_mtime)

    secs = _iso_delta_seconds(started, ended)
    return started, ended, secs


def _mtime_bounds(session_dir):
    """Return (min_mtime, max_mtime) over files in session_dir, or (None, None)."""
    if not (session_dir and os.path.isdir(session_dir)):
        return None, None
    mtimes = []
    for root, _dirs, files in os.walk(session_dir):
        for name in files:
            try:
                mtimes.append(os.path.getmtime(os.path.join(root, name)))
            except OSError:
                continue
    if not mtimes:
        return None, None
    return min(mtimes), max(mtimes)


def _iso(epoch):
    if epoch is None:
        return None
    import datetime
    return datetime.datetime.fromtimestamp(
        epoch, datetime.timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iso_delta_seconds(start_iso, end_iso):
    if not (start_iso and end_iso):
        return None
    import datetime

    def _parse(s):
        s = s.replace("Z", "+00:00")
        try:
            return datetime.datetime.fromisoformat(s)
        except ValueError:
            # bob-oss timestamps are toISOString() -> always 'Z'; this is a guard.
            try:
                return datetime.datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                return None

    a, b = _parse(start_iso), _parse(end_iso)
    if a is None or b is None:
        return None
    delta = (b - a).total_seconds()
    return int(delta) if delta >= 0 else None


def _models_from_events_and_cost(cost_result):
    """Collect model ids the run touched (per-turn, not per-run)."""
    models = []
    if isinstance(cost_result, dict):
        for entry in cost_result.get("per_model", []) or []:
            m = entry.get("model")
            if isinstance(m, str) and m and m not in models:
                models.append(m)
    return models


# ---------------------------------------------------------------------------
# Cost: defer entirely to cost_parser.py (transcript-based, outside the MCP).
# ---------------------------------------------------------------------------
def _reconstruct_cost(transcript_path):
    """Return (cost_block, cost_result_or_None). cost_block matches CONTRACT §2.2.

    If no transcript or cost_parser is available, returns a wall_clock_fallback
    block with usd=null (per §7.3 framing discipline).
    """
    fallback = {
        "usd": None,
        "usd_source": "wall_clock_fallback",
        "reconciled": False,
        "tokens": {"input": 0, "output": 0, "cache_creation": 0, "cache_read": 0, "total": 0},
        "per_model": [],
    }
    if not transcript_path or cost_parser is None:
        return fallback, None
    try:
        result = cost_parser.parse_session(transcript_path)
    except SystemExit:
        # cost_parser raises SystemExit on unresolvable paths; treat as no-cost.
        return fallback, None
    except Exception:
        return fallback, None

    totals = result.get("totals", {}) if isinstance(result, dict) else {}
    tokens = totals.get("tokens", {}) if isinstance(totals, dict) else {}
    usd = totals.get("usd")
    cost_block = {
        "usd": usd,
        # cost_parser produces a *derived-externally* estimate; per §7.3 it is NOT
        # reconciled until the §8 Phase-0 gate passes. The scorer labels it.
        "usd_source": "transcript_cost_parser" if usd is not None else "wall_clock_fallback",
        "reconciled": False,
        "tokens": {
            "input": int(tokens.get("input", 0) or 0),
            "output": int(tokens.get("output", 0) or 0),
            "cache_creation": int(tokens.get("cache_creation", 0) or 0),
            "cache_read": int(tokens.get("cache_read", 0) or 0),
            "total": int(tokens.get("total", 0) or 0),
        },
        "per_model": [
            {
                "model": e.get("model"),
                "usd": e.get("usd"),
                "tokens": (e.get("tokens") or {}),
            }
            for e in (result.get("per_model", []) or [])
            if isinstance(e, dict)
        ],
    }
    return cost_block, result


# ---------------------------------------------------------------------------
# claims.jsonl projection: bob's candidate findings live in claim.payload.finding.
# ---------------------------------------------------------------------------
def _findings_from_claims(claims):
    """Project bob's claims.jsonl rows into the finding-shape map_session consumes.

    Each claim's per-finding detail is the nested claim.payload.finding object, whose
    fields (id, file_path, symbol, cwe, repro_command, description, validated,
    severity, proof_of_concept, response_evidence) are exactly what the finding loop
    reads. finding_id is payload.finding.id (mirrored in claim.evidence_refs[]).
    """
    out = []
    for c in claims:
        if not isinstance(c, dict):
            continue
        fnd = (c.get("payload") or {}).get("finding")
        if isinstance(fnd, dict) and isinstance(fnd.get("id"), str) and fnd.get("id"):
            out.append(fnd)
    return out


# ---------------------------------------------------------------------------
# Core mapping.
# ---------------------------------------------------------------------------
def map_session(session_dir, *, case_id=None, config="native", trial_index=0,
                agent_version=None, transcript_path=None, budget=None):
    """Map a bob-oss session dir onto (findings_list, run_obj) per the contract."""
    session_dir = os.path.abspath(session_dir)

    findings_path = os.path.join(session_dir, "findings.jsonl")
    verified_path = os.path.join(session_dir, "verified-final.json")
    runs_path = os.path.join(session_dir, "repo-command-runs.jsonl")
    events_path = os.path.join(session_dir, "pipeline-events.jsonl")
    repo_env_path = os.path.join(session_dir, "repo-env.json")
    grade_path = os.path.join(session_dir, "grade.json")

    # bob records candidate findings as claims.jsonl (CB-C2): the per-finding detail
    # lives in claim.payload.finding (id, file_path, symbol, cwe, repro_command,
    # description, validated, severity, ...) and links to verified-final.json by
    # finding_id. findings.jsonl does NOT exist in bob — it is a legacy fallback only.
    claims_path = os.path.join(session_dir, "claims.jsonl")
    findings = list(_read_jsonl(findings_path))
    if not findings:
        findings = _findings_from_claims(_read_jsonl(claims_path))
    runs = list(_read_jsonl(runs_path))
    events = list(_read_jsonl(events_path))
    verified = _read_json(verified_path)
    repo_env = _read_json(repo_env_path)
    grade = _read_json(grade_path)

    # Build the verified-final disposition map: finding_id -> (severity, reportable).
    verified_by_id = {}
    for res in (verified.get("results") or []):
        if not isinstance(res, dict):
            continue
        fid = res.get("finding_id")
        if not isinstance(fid, str):
            continue
        verified_by_id[fid] = {
            "severity": _norm_severity(res.get("severity")),
            "reportable": bool(res.get("reportable")),
            "disposition": res.get("disposition"),
        }

    resolved_case_id = case_id or os.path.basename(session_dir)

    out_findings = []
    for f in findings:
        fid = f.get("id")
        if not isinstance(fid, str) or not fid:
            continue

        vfinal = verified_by_id.get(fid)
        # Severity: authoritative verified-final, else hunter-claimed fallback.
        if vfinal and vfinal["severity"]:
            severity = vfinal["severity"]
        else:
            severity = _norm_severity(f.get("severity")) or "info"
        reportable = bool(vfinal["reportable"]) if vfinal else bool(f.get("validated"))

        # Correlate to the run that proves it; recover crashing-input + sanitizer.
        run = _correlate_run(f, runs)
        crashing_input_path = None
        sanitizer = {
            "crash_type": None,
            "asan_summary": None,
            "exit_code": None,
            "stderr_excerpt": "",
        }
        if run is not None:
            crash_type, summary, excerpt = _parse_crash_signal(
                run.get("stderr"), run.get("stdout")
            )
            sanitizer["crash_type"] = crash_type
            sanitizer["asan_summary"] = summary
            sanitizer["stderr_excerpt"] = excerpt
            ec = run.get("exit_code")
            sanitizer["exit_code"] = ec if isinstance(ec, int) else None
            crashing_input_path = _scan_run_dir_for_crash_artifact(run.get("run_dir"))

        out_findings.append({
            "schema": "oss-bench/finding@1",
            "finding_id": fid,
            "case_id": resolved_case_id,
            "file_path": f.get("file_path"),
            "symbol": f.get("symbol"),
            "cwe": f.get("cwe"),
            "severity": severity,
            "repro_command": _as_argv(f.get("repro_command")),
            "crashing_input_path": crashing_input_path,
            "sanitizer": sanitizer,
            "reportable": reportable,
            "dedupe_key": f.get("dedupe_key"),
            "description": f.get("description") or "",
            "validated": bool(f.get("validated")),
        })

    # ---- run.json ----
    started_at, ended_at, wall_secs = _envelope_timing(session_dir, events)
    cost_block, cost_result = _reconstruct_cost(transcript_path)
    models = _models_from_events_and_cost(cost_result)

    # build_failed: from repo-env.json docker_build (separate artifact). A nonzero
    # exit_code or explicit 'failed' status means the ASAN harness build failed.
    docker_build = repo_env.get("docker_build") if isinstance(repo_env, dict) else None
    build_failed = False
    if isinstance(docker_build, dict):
        bstatus = docker_build.get("status")
        bexit = docker_build.get("exit_code")
        build_failed = (bstatus == "failed") or (isinstance(bexit, int) and bexit != 0)

    # harness_blocked: bob-oss records this via blocked_harness_runs[] in state;
    # we surface it best-effort if present in repo_env or state-like fields.
    harness_blocked = bool(repo_env.get("blocked_harness_runs"))

    budget = budget or {}
    run_obj = {
        "schema": "oss-bench/run@1",
        "case_id": resolved_case_id,
        "agent": "bob-oss",
        "agent_version": agent_version or "bob-oss",
        "config": config,
        "trial_index": int(trial_index),
        "started_at": started_at,
        "ended_at": ended_at,
        "wall_clock_seconds": wall_secs,
        "models": models,
        "cost": cost_block,
        "budget": {
            "wall_clock_seconds": budget.get("wall_clock_seconds"),
            "usd_ceiling": budget.get("usd_ceiling"),
            "token_ceiling": budget.get("token_ceiling"),
        },
        "limits_hit": {
            "wall_clock_exceeded": (
                wall_secs is not None
                and budget.get("wall_clock_seconds") is not None
                and wall_secs > budget["wall_clock_seconds"]
            ),
            "usd_ceiling_exceeded": (
                cost_block.get("usd") is not None
                and budget.get("usd_ceiling") is not None
                and cost_block["usd"] > budget["usd_ceiling"]
            ),
            "build_failed": build_failed,
            "harness_blocked": harness_blocked,
        },
        "notes": (
            "Mapped from bob-oss MCP artifacts. Cost is reconstructed externally "
            "via cost_parser.py and is NOT reconciled (see CONTRACT §3 / §7.3). "
            "Crashing-input paths are recovered by scanning repo-runs/<run_id>/ "
            "on disk; absent => localization-only. See KNOWN_GAPS."
        ),
        "provenance": {
            "session_dir": session_dir,
            "source_artifacts": [
                "findings.jsonl",
                "verified-final.json",
                "repo-command-runs.jsonl",
                "pipeline-events.jsonl",
                "repo-env.json",
                "grade.json",
            ],
            "grade_verdict": grade.get("verdict") if isinstance(grade, dict) else None,
            "known_gaps": KNOWN_GAPS,
        },
    }

    return out_findings, run_obj


def _load_input_contract(input_path):
    """Load the §1 input JSON if provided; return {} otherwise."""
    if not input_path:
        return {}
    return _read_json(input_path)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Map a bob-oss session dir onto the §7.4 benchmark output contract."
    )
    parser.add_argument("--session-dir", required=True,
                        help="bob-oss session dir (~/bounty-agent-sessions/<domain>).")
    parser.add_argument("--out-dir", required=True,
                        help="Where to write findings.jsonl + run.json.")
    parser.add_argument("--case-id", default=None)
    parser.add_argument("--config", default=None, choices=("native", "sanitized"),
                        help="Defaults to the input JSON's config, else 'native'.")
    parser.add_argument("--trial-index", type=int, default=None,
                        help="Defaults to the input JSON's trial_index, else 0.")
    parser.add_argument("--agent-version", default=None)
    parser.add_argument("--transcript", default=None,
                        help="Claude Code session jsonl / session folder / project dir "
                             "for cost reconstruction (passed to cost_parser).")
    parser.add_argument("--input", default=None,
                        help="Path to the §1 input-contract JSON; CLI flags override it.")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args(argv)

    contract = _load_input_contract(args.input)
    case_id = args.case_id or contract.get("case_id")
    config = args.config or contract.get("config") or "native"
    if args.trial_index is not None:
        trial_index = args.trial_index
    else:
        trial_index = contract.get("trial_index", 0)
    budget = contract.get("budget") or {}

    findings, run_obj = map_session(
        args.session_dir,
        case_id=case_id,
        config=config,
        trial_index=trial_index,
        agent_version=args.agent_version,
        transcript_path=args.transcript,
        budget=budget,
    )

    os.makedirs(args.out_dir, exist_ok=True)
    findings_out = os.path.join(args.out_dir, "findings.jsonl")
    run_out = os.path.join(args.out_dir, "run.json")

    with open(findings_out, "w", encoding="utf-8") as fh:
        for f in findings:
            fh.write(json.dumps(f, separators=(",", ":")))
            fh.write("\n")

    with open(run_out, "w", encoding="utf-8") as fh:
        if args.pretty:
            json.dump(run_obj, fh, indent=2)
        else:
            json.dump(run_obj, fh, separators=(",", ":"))
        fh.write("\n")

    summary = {
        "session_dir": os.path.abspath(args.session_dir),
        "out_dir": os.path.abspath(args.out_dir),
        "findings_written": len(findings),
        "reportable": sum(1 for f in findings if f.get("reportable")),
        "with_crashing_input": sum(1 for f in findings if f.get("crashing_input_path")),
        "cost_usd": run_obj["cost"].get("usd"),
        "cost_reconciled": run_obj["cost"].get("reconciled"),
        "wall_clock_seconds": run_obj.get("wall_clock_seconds"),
        # §5.4: build status is a first-class result, not a denominator filter.
        # True/False from repo-env.json docker_build; None when status is unknown.
        "build_failed": (run_obj.get("limits_hit") or {}).get("build_failed"),
    }
    sys.stdout.write(json.dumps(summary, indent=2 if args.pretty else None,
                                separators=None if args.pretty else (",", ":")))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
