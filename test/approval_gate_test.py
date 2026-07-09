#!/usr/bin/env python3
"""Unit tests for the bob-approval-gate-impl.py PreToolUse hook (GRADE->REPORT human approval).

The hook is FLAG-CONTROLLED + INERT BY DEFAULT off the AWS branch (BOB_AGENTCORE != "1" ->
immediate exit 0, no stdin read). When enabled it gates only bob_advance_session(to_state=REPORT)
and bob_finalize_report, withholding (exit 2) until an S3-backed approval artifact (content
{"hmac": "<hex>", "grade_verdict_hash": "<hex>"}) exists AND its
HMAC-SHA256(f"{target_domain}|{grade_verdict_hash}", key) recomputes to match AND its stored
grade_verdict_hash equals the CURRENT grade.json's canonical hash -- fx-gate-hardening replaced
the old raw-existence check (forgeable: the artifact lived under the model's own writable EFS
$HOME) with an un-forgeable design (S3 deny-write is the PRIMARY enforcement; the HMAC check here
is defense-in-depth); fx-hmac-content further binds the artifact to the EXACT grade the human
reviewed, so a post-approval amend+re-grade invalidates the SAME previously-valid artifact
(closing the amend-and-reexport gap). This gate FAILS CLOSED: any ambiguity (malformed stdin,
missing artifact, malformed content, missing/stale grade_verdict_hash, HMAC mismatch) resolves to
exit 2 (block), the opposite fail direction from the sibling bob-http-write-confirm gate's "ask"
default, because there is no human to ask inline here — the safe default for a report-release
gate is withhold, not surface-a-choice.

Tests exercise the hook via subprocess (real exit-code behavior) using the
BOB_APPROVAL_ARTIFACT_DIR + BOB_APPROVAL_HMAC_KEY local-backend stand-in seam (dev/test only --
see the hook's own docstring; production reads S3 + Secrets Manager via boto3 instead) AND a
HOME-rooted hacker-bob-sessions/<domain>/grade.json fixture (the hook's own current
grade_verdict_hash source)."""
import hashlib
import hmac as hmac_module
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")
HOOK = os.path.join(REPO_ROOT, ".claude", "hooks", "bob-approval-gate-impl.py")
REPORT_FINALIZE_JS = os.path.join(REPO_ROOT, "mcp", "lib", "report-finalize.js")

ADVANCE = "mcp__hacker-bob__bob_advance_session"
FINALIZE = "mcp__hacker-bob__bob_finalize_report"
DOMAIN = "example.com"
TEST_HMAC_KEY = "test-only-approval-hmac-key-do-not-use-in-prod"


def advance(to_state, target_domain=DOMAIN):
    return {
        "tool_name": ADVANCE,
        "tool_input": {"target_domain": target_domain, "to_state": to_state},
    }


def finalize(target_domain=DOMAIN):
    return {"tool_name": FINALIZE, "tool_input": {"target_domain": target_domain}}


def grade_document(domain=DOMAIN, total_score=75):
    return {
        "version": 1,
        "target_domain": domain,
        "verdict": "SUBMIT",
        "total_score": total_score,
        "findings": [{
            "finding_id": "F-1",
            "impact": 25,
            "proof_quality": 20,
            "severity_accuracy": 10,
            "chain_potential": 10,
            "report_quality": 10,
            "total_score": total_score,
            "feedback": "Clear, reproducible, and reportable.",
        }],
        "graded_at": "2026-05-27T02:00:00.000Z",
    }


def compute_grade_verdict_hash(document):
    """Reference canonicalization independently mirroring bob-approval-gate-impl.py's own
    _current_grade_verdict_hash / mcp/lib/verification-contracts.js hashCanonicalJson (recursive
    sort_keys + compact separators) -- used here to derive the EXPECTED hash for a given fixture,
    not to duplicate production hashing logic (the hook computes its own from disk)."""
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def with_home_and_grade(domain=DOMAIN, document=None):
    """Creates a fresh tempdir HOME with hacker-bob-sessions/<domain>/grade.json written.
    Returns (home, grade_verdict_hash)."""
    home = tempfile.mkdtemp(prefix="bob-approval-gate-test-home-")
    session_dir = os.path.join(home, "hacker-bob-sessions", domain)
    os.makedirs(session_dir, exist_ok=True)
    doc = document if document is not None else grade_document(domain)
    with open(os.path.join(session_dir, "grade.json"), "w") as fh:
        json.dump(doc, fh)
    return home, compute_grade_verdict_hash(doc)


def signed_artifact_json(target_domain, grade_verdict_hash, key=TEST_HMAC_KEY):
    signature = hmac_module.new(
        key.encode("utf-8"),
        f"{target_domain}|{grade_verdict_hash}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return json.dumps({"hmac": signature, "grade_verdict_hash": grade_verdict_hash})


def run(env_overrides, stdin_payload, hmac_key=TEST_HMAC_KEY, home=None):
    env = dict(os.environ)
    env.pop("BOB_AGENTCORE", None)
    env.pop("BOB_APPROVAL_ARTIFACT_DIR", None)
    env.pop("BOB_APPROVAL_HMAC_KEY", None)
    env.pop("BOB_APPROVAL_BUCKET", None)
    env.pop("BOB_APPROVAL_HMAC_SECRET_ID", None)
    if hmac_key is not None:
        env["BOB_APPROVAL_HMAC_KEY"] = hmac_key
    if home is not None:
        env["HOME"] = home
    env.update(env_overrides)
    raw = stdin_payload if isinstance(stdin_payload, str) else json.dumps(stdin_payload)
    return subprocess.run(
        [sys.executable, HOOK], input=raw, capture_output=True, text=True, env=env
    )


def with_approved_artifact(domain=DOMAIN, grade_verdict_hash=None, key=TEST_HMAC_KEY):
    tmpdir = tempfile.mkdtemp(prefix="bob-approval-gate-test-")
    with open(os.path.join(tmpdir, f"{domain}.approved"), "w") as fh:
        fh.write(signed_artifact_json(domain, grade_verdict_hash, key))
    return tmpdir


def with_tampered_artifact(domain=DOMAIN, grade_verdict_hash=None):
    # A well-formed {"hmac": "...", "grade_verdict_hash": "..."} artifact, content-bound to the
    # CURRENT grade -- mere existence, or even a matching content-binding, would have satisfied
    # the old raw-existence check this hardening replaces -- but signed with a DIFFERENT key than
    # the one the hook resolves (TEST_HMAC_KEY). Must still block.
    return with_approved_artifact(domain, grade_verdict_hash, key="a-different-attacker-controlled-key")


def with_malformed_artifact(domain=DOMAIN, content="not json"):
    tmpdir = tempfile.mkdtemp(prefix="bob-approval-gate-test-malformed-")
    with open(os.path.join(tmpdir, f"{domain}.approved"), "w") as fh:
        fh.write(content)
    return tmpdir


def with_traversal_forgery():
    base_dir = tempfile.mkdtemp(prefix="bob-approval-gate-test-traversal-")
    artifact_dir = os.path.join(base_dir, "artifacts")
    os.mkdir(artifact_dir)
    with open(os.path.join(base_dir, "pwned.approved"), "w") as fh:
        # _is_safe_engagement_id rejects the "../pwned" engagement_id before this content is
        # ever read, so the grade_verdict_hash value here is a placeholder -- never resolved.
        fh.write(signed_artifact_json("pwned", "0" * 64))
    return artifact_dir


def build_tests():
    # fx-hmac-content: the artifact is content-bound to grade_verdict_hash, which the hook
    # resolves from HOME/hacker-bob-sessions/<domain>/grade.json. `home` carries the CURRENT
    # grade fixture (grade_verdict_hash); `amended_home` carries a re-graded fixture (a
    # DIFFERENT hash) simulating a post-approval amend+re-grade against the SAME artifact.
    home, grade_verdict_hash = with_home_and_grade(DOMAIN)
    amended_home, amended_grade_verdict_hash = with_home_and_grade(DOMAIN, grade_document(DOMAIN, total_score=10))
    assert amended_grade_verdict_hash != grade_verdict_hash, "amended fixture must hash differently"
    empty_grade_home = tempfile.mkdtemp(prefix="bob-approval-gate-test-empty-home-")

    approved_dir = with_approved_artifact(DOMAIN, grade_verdict_hash)
    empty_dir = tempfile.mkdtemp(prefix="bob-approval-gate-test-empty-")
    traversal_forgery_dir = with_traversal_forgery()
    tampered_dir = with_tampered_artifact(DOMAIN, grade_verdict_hash)
    malformed_not_json_dir = with_malformed_artifact(DOMAIN, "not json")
    malformed_no_hmac_dir = with_malformed_artifact(DOMAIN, json.dumps({"status": "approved"}))
    malformed_no_grade_hash_dir = with_malformed_artifact(
        DOMAIN,
        json.dumps({
            "hmac": hmac_module.new(
                TEST_HMAC_KEY.encode("utf-8"), f"{DOMAIN}|{grade_verdict_hash}".encode("utf-8"), hashlib.sha256
            ).hexdigest(),
        }),
    )

    # (description, env_overrides, stdin_payload, expect_exit_code)
    return [
        # --- inert by default: BOB_AGENTCORE unset -> exit 0, no matter the payload ---
        (
            "BOB_AGENTCORE unset + advance_session(to_state=REPORT) -> allow (inert off AWS branch)",
            {},
            advance("REPORT"),
            0,
        ),
        (
            "BOB_AGENTCORE unset + bob_finalize_report -> allow (inert off AWS branch)",
            {},
            finalize(),
            0,
        ),
        (
            "BOB_AGENTCORE=0 (falsy) + advance_session(to_state=REPORT) -> allow",
            {"BOB_AGENTCORE": "0"},
            advance("REPORT"),
            0,
        ),

        # --- enabled: scoped tools, no artifact -> block ---
        (
            "BOB_AGENTCORE=1 + advance_session(to_state=REPORT) + no artifact dir -> block (exit 2)",
            {"BOB_AGENTCORE": "1"},
            advance("REPORT"),
            2,
        ),
        (
            "BOB_AGENTCORE=1 + advance_session(to_state=REPORT) + empty artifact dir -> block (exit 2)",
            {"BOB_AGENTCORE": "1", "BOB_APPROVAL_ARTIFACT_DIR": empty_dir},
            advance("REPORT"),
            2,
        ),
        (
            "BOB_AGENTCORE=1 + bob_finalize_report + no artifact -> block (exit 2)",
            {"BOB_AGENTCORE": "1"},
            finalize(),
            2,
        ),

        # --- enabled: scoped tools, artifact present + content-bound to the CURRENT grade -> allow ---
        (
            "BOB_AGENTCORE=1 + advance_session(to_state=REPORT) + artifact present -> allow",
            {"BOB_AGENTCORE": "1", "BOB_APPROVAL_ARTIFACT_DIR": approved_dir, "HOME": home},
            advance("REPORT"),
            0,
        ),
        (
            "BOB_AGENTCORE=1 + bob_finalize_report + artifact present -> allow",
            {"BOB_AGENTCORE": "1", "BOB_APPROVAL_ARTIFACT_DIR": approved_dir, "HOME": home},
            finalize(),
            0,
        ),
        (
            "BOB_AGENTCORE=1 + advance_session(to_state=REPORT) + artifact for a DIFFERENT domain -> block",
            {"BOB_AGENTCORE": "1", "BOB_APPROVAL_ARTIFACT_DIR": approved_dir, "HOME": home},
            advance("REPORT", target_domain="other.example"),
            2,
        ),
        (
            "BOB_AGENTCORE=1 + advance_session(to_state=REPORT) + traversal-shaped target with outside artifact -> block",
            {"BOB_AGENTCORE": "1", "BOB_APPROVAL_ARTIFACT_DIR": traversal_forgery_dir},
            advance("REPORT", target_domain="../pwned"),
            2,
        ),
        (
            "BOB_AGENTCORE=1 + bob_finalize_report + traversal-shaped target with outside artifact -> block",
            {"BOB_AGENTCORE": "1", "BOB_APPROVAL_ARTIFACT_DIR": traversal_forgery_dir},
            finalize(target_domain="../pwned"),
            2,
        ),

        # --- enabled: fx-gate-hardening HMAC verification (existence is NOT enough) ---
        (
            "BOB_AGENTCORE=1 + advance_session(to_state=REPORT) + well-formed, content-bound artifact "
            "signed with the WRONG key (tampered/wrong-signature) -> block (exit 2)",
            {"BOB_AGENTCORE": "1", "BOB_APPROVAL_ARTIFACT_DIR": tampered_dir, "HOME": home},
            advance("REPORT"),
            2,
        ),
        (
            "BOB_AGENTCORE=1 + bob_finalize_report + well-formed, content-bound artifact signed with "
            "the WRONG key -> block (exit 2)",
            {"BOB_AGENTCORE": "1", "BOB_APPROVAL_ARTIFACT_DIR": tampered_dir, "HOME": home},
            finalize(),
            2,
        ),
        (
            "BOB_AGENTCORE=1 + advance_session(to_state=REPORT) + artifact content is not JSON -> "
            "block (exit 2)",
            {"BOB_AGENTCORE": "1", "BOB_APPROVAL_ARTIFACT_DIR": malformed_not_json_dir, "HOME": home},
            advance("REPORT"),
            2,
        ),
        (
            "BOB_AGENTCORE=1 + advance_session(to_state=REPORT) + artifact JSON has no hmac field -> "
            "block (exit 2)",
            {"BOB_AGENTCORE": "1", "BOB_APPROVAL_ARTIFACT_DIR": malformed_no_hmac_dir, "HOME": home},
            advance("REPORT"),
            2,
        ),
        (
            "BOB_AGENTCORE=1 + advance_session(to_state=REPORT) + well-formed hmac but NO "
            "grade_verdict_hash field on the artifact -> block (exit 2, fx-hmac-content)",
            {"BOB_AGENTCORE": "1", "BOB_APPROVAL_ARTIFACT_DIR": malformed_no_grade_hash_dir, "HOME": home},
            advance("REPORT"),
            2,
        ),
        (
            "BOB_AGENTCORE=1 + advance_session(to_state=REPORT) + correctly-signed artifact but NO "
            "HMAC key resolvable -> block (exit 2, fails closed rather than skipping verification)",
            {"BOB_AGENTCORE": "1", "BOB_APPROVAL_ARTIFACT_DIR": approved_dir, "BOB_APPROVAL_HMAC_KEY": "", "HOME": home},
            advance("REPORT"),
            2,
        ),

        # --- enabled: fx-hmac-content grade_verdict_hash content binding ---
        (
            "BOB_AGENTCORE=1 + advance_session(to_state=REPORT) + grade.json entirely absent (otherwise "
            "well-formed + correctly-signed artifact) -> block (exit 2, current hash resolves to None)",
            {"BOB_AGENTCORE": "1", "BOB_APPROVAL_ARTIFACT_DIR": approved_dir, "HOME": empty_grade_home},
            advance("REPORT"),
            2,
        ),
        (
            "BOB_AGENTCORE=1 + advance_session(to_state=REPORT) + artifact signed for an OLD "
            "grade_verdict_hash while grade.json was amended+re-graded -> block (exit 2, closes the "
            "amend-and-reexport gap)",
            {"BOB_AGENTCORE": "1", "BOB_APPROVAL_ARTIFACT_DIR": approved_dir, "HOME": amended_home},
            advance("REPORT"),
            2,
        ),
        (
            "BOB_AGENTCORE=1 + bob_finalize_report + artifact signed for an OLD grade_verdict_hash "
            "while grade.json was amended+re-graded -> block (exit 2, closes the amend-and-reexport gap)",
            {"BOB_AGENTCORE": "1", "BOB_APPROVAL_ARTIFACT_DIR": approved_dir, "HOME": amended_home},
            finalize(),
            2,
        ),

        # --- enabled: out-of-scope to_state / tool -> allow, even with no artifact ---
        (
            "BOB_AGENTCORE=1 + advance_session(to_state=VERIFY) -> allow (out of scope to_state)",
            {"BOB_AGENTCORE": "1"},
            advance("VERIFY"),
            0,
        ),
        (
            "BOB_AGENTCORE=1 + advance_session(to_state=CLAIM_FREEZE) -> allow (out of scope to_state)",
            {"BOB_AGENTCORE": "1"},
            advance("CLAIM_FREEZE"),
            0,
        ),
        (
            "BOB_AGENTCORE=1 + unrelated tool (bob_http_scan) -> allow (out of scope tool)",
            {"BOB_AGENTCORE": "1"},
            {"tool_name": "mcp__hacker-bob__bob_http_scan", "tool_input": {"method": "GET"}},
            0,
        ),

        # --- enabled: fail CLOSED on malformed/ambiguous input while in scope ---
        (
            "BOB_AGENTCORE=1 + malformed stdin (not JSON) for bob_finalize_report -> block (fail closed)",
            {"BOB_AGENTCORE": "1"},
            "{not json",
            2,
        ),
        (
            "BOB_AGENTCORE=1 + empty stdin -> allow (empty body parses as {}, no tool_name -> "
            "out of scope, not the fail-closed path)",
            {"BOB_AGENTCORE": "1"},
            "",
            0,
        ),
        (
            "BOB_AGENTCORE=1 + advance_session with missing tool_input -> block (fail closed)",
            {"BOB_AGENTCORE": "1"},
            {"tool_name": ADVANCE},
            2,
        ),
        (
            "BOB_AGENTCORE=1 + advance_session with non-dict tool_input -> block (fail closed)",
            {"BOB_AGENTCORE": "1"},
            {"tool_name": ADVANCE, "tool_input": "not-a-dict"},
            2,
        ),
        (
            "BOB_AGENTCORE=1 + top-level payload is a JSON array, not an object -> block (fail closed)",
            {"BOB_AGENTCORE": "1"},
            "[1, 2, 3]",
            2,
        ),
    ]


def _load_hook_module():
    # Safe to import directly (unlike infra/runner/agentcore-entrypoint.py): the hook has a
    # plain `if __name__ == "__main__": main()` guard and does nothing at module-exec time.
    #
    # sys.dont_write_bytecode is set around the import (and restored in finally) so this
    # never leaves a .claude/hooks/__pycache__/*.pyc on disk. .claude/hooks/ is walked
    # RAW-filesystem by scripts/lib/package-policy.js's expectedCanonicalFiles (via
    # test/package.test.js), which is NOT gitignore-aware -- a stray compiled artifact there
    # would show up as an "expected" packed file that `npm pack` correctly omits (it is not in
    # package.json's `files` allowlist), breaking that unrelated test on a later run.
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec = importlib.util.spec_from_file_location("bob_approval_gate_impl", HOOK)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.dont_write_bytecode = previous


def cross_language_parity_check():
    """fx-hmac-content: an AUTOMATED cross-check (not just code inspection) pinning the Python
    hook's own reimplemented canonicalization (_current_grade_verdict_hash:
    json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + sha256)
    against the REAL production mcp/lib/report-finalize.js's loadGradeVerdictHash (which
    delegates to mcp/lib/verification-contracts.js's hashCanonicalJson), for the SAME on-disk
    grade.json.

    This is the one consumer where such a pin matters: the JS consumer (lifecycle-gates.js) and
    the Python PRODUCER (infra/runner/agentcore-entrypoint.py) both call the real Node
    hashCanonicalJson through a node-shellout bridge (byte-identical BY CONSTRUCTION, nothing
    reimplemented). This Python CONSUMER (the hook) reimplements canonicalization
    independently in pure Python -- the one place a silent divergence (float formatting,
    key-ordering, a future non-string/non-integer field) could creep in undetected by code
    inspection alone. Returns (ok: bool, detail: str)."""
    home = tempfile.mkdtemp(prefix="bob-approval-gate-test-parity-")
    try:
        domain = "parity-check.example"
        session_dir = os.path.join(home, "hacker-bob-sessions", domain)
        os.makedirs(session_dir, exist_ok=True)
        document = grade_document(domain, total_score=42)
        with open(os.path.join(session_dir, "grade.json"), "w") as fh:
            json.dump(document, fh)

        hook_module = _load_hook_module()
        previous_home = os.environ.get("HOME")
        os.environ["HOME"] = home
        try:
            python_hash = hook_module._current_grade_verdict_hash(domain)
        finally:
            if previous_home is None:
                os.environ.pop("HOME", None)
            else:
                os.environ["HOME"] = previous_home

        node_env = dict(os.environ)
        node_env["HOME"] = home
        script = (
            "const { loadGradeVerdictHash } = require(process.argv[1]);"
            "process.stdout.write(loadGradeVerdictHash(process.argv[2]));"
        )
        try:
            node_result = subprocess.run(
                ["node", "-e", script, REPORT_FINALIZE_JS, domain],
                env=node_env, capture_output=True, text=True, timeout=10, check=True,
            )
            node_hash = node_result.stdout.strip()
        except Exception as e:
            return False, f"node reference computation failed: {type(e).__name__}: {e}"

        if not python_hash:
            return False, "hook's _current_grade_verdict_hash returned falsy for a valid fixture"
        if python_hash != node_hash:
            return False, f"python={python_hash!r} node={node_hash!r} (canonicalization diverges)"
        return True, ""
    finally:
        import shutil
        shutil.rmtree(home, ignore_errors=True)


def main():
    tests = build_tests()
    passed = 0
    failed = 0
    for desc, env_overrides, stdin_payload, expect_exit_code in tests:
        result = run(env_overrides, stdin_payload)
        ok = result.returncode == expect_exit_code
        status = "\033[32mPASS\033[0m" if ok else "\033[31mFAIL\033[0m"
        print(f"  {status}: {desc}")
        if not ok:
            print(f"         expected exit {expect_exit_code}, got exit {result.returncode}")
            if result.stdout.strip():
                print(f"         stdout: {result.stdout.strip()}")
            if result.stderr.strip():
                print(f"         stderr: {result.stderr.strip()}")
            failed += 1
        else:
            passed += 1

    parity_ok, parity_detail = cross_language_parity_check()
    status = "\033[32mPASS\033[0m" if parity_ok else "\033[31mFAIL\033[0m"
    print(f"  {status}: cross-language canonicalization parity (Python hook vs Node hashCanonicalJson)")
    if not parity_ok:
        print(f"         {parity_detail}")
        failed += 1
    else:
        passed += 1

    print(f"\n  {passed}/{passed + failed} passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
