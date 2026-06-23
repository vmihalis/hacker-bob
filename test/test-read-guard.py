#!/usr/bin/env python3
"""Unit tests for session-read-guard.sh hook."""
import json
import os
import subprocess
import sys
import tempfile

HOOK = os.path.join(os.path.dirname(__file__), "..", ".claude", "hooks", "session-read-guard.sh")
KIMI_HOOK = os.path.join(os.path.dirname(__file__), "..", "adapters", "kimi", "hooks", "session-read-guard.sh")
# The Claude and Kimi read guards must enforce IDENTICAL policy (no split-brain).
HOOKS = [("claude", HOOK), ("kimi", KIMI_HOOK)]
HOME = os.path.expanduser("~")
SESSION = f"{HOME}/hacker-bob-sessions/example.com"

TESTS = [
    ("Read findings.jsonl blocks",
     {"tool_input": {"file_path": f"{SESSION}/findings.jsonl"}},
     2,
     "bob_read_candidate_claims"),
    ("Read report.md blocks",
     {"tool_input": {"file_path": f"{SESSION}/report.md"}},
     2,
     "bob_read_session_summary"),
    ("Read surface-routes.json blocks",
     {"tool_input": {"file_path": f"{SESSION}/surface-routes.json"}},
     2,
     "bob_read_session_summary"),
    ("Read repo-inventory.json blocks",
     {"tool_input": {"file_path": f"{SESSION}/repo-inventory.json"}},
     2,
     "bob_read_session_summary"),
    ("Read repo-checks.jsonl blocks",
     {"tool_input": {"file_path": f"{SESSION}/repo-checks.jsonl"}},
     2,
     "bob_read_session_summary"),
    ("Read repo-env.json blocks",
     {"tool_input": {"file_path": f"{SESSION}/repo-env.json"}},
     2,
     "bob_read_session_summary"),
    ("Read Dockerfile.bob blocks",
     {"tool_input": {"file_path": f"{SESSION}/Dockerfile.bob"}},
     2,
     "bob_read_session_summary"),
    ("Read repo-command-runs.jsonl blocks",
     {"tool_input": {"file_path": f"{SESSION}/repo-command-runs.jsonl"}},
     2,
     "bob_read_session_summary"),
    ("Read offensive-runs.jsonl blocks",
     {"tool_input": {"file_path": f"{SESSION}/offensive-runs.jsonl"}},
     2,
     "bob_read_session_summary"),
    ("Read massread-evidence raw-PII capture blocks (bob_http_massread_confirm opt-in capture)",
     {"tool_input": {"file_path": f"{SESSION}/massread-evidence/run-massread-abc123.json"}},
     2,
     "bob_read_session_summary"),
    ("Read static-analysis-results.jsonl blocks",
     {"tool_input": {"file_path": f"{SESSION}/static-analysis-results.jsonl"}},
     2,
     "bob_read_session_summary"),
    ("Read static-analysis-index.jsonl blocks",
     {"tool_input": {"file_path": f"{SESSION}/static-analysis-index.jsonl"}},
     2,
     "bob_read_session_summary"),
    ("Read technique-attempts.jsonl blocks",
     {"tool_input": {"file_path": f"{SESSION}/technique-attempts.jsonl"}},
     2,
     "bob_read_session_summary"),
    ("Read technique-pack-reads.jsonl blocks",
     {"tool_input": {"file_path": f"{SESSION}/technique-pack-reads.jsonl"}},
     2,
     "bob_read_session_summary"),
    ("Read diff-impact.json blocks",
     {"tool_input": {"file_path": f"{SESSION}/diff-impact.json"}},
     2,
     "bob_read_session_summary"),
    ("Read handoff signing key blocks",
     {"tool_input": {"file_path": f"{SESSION}/.handoff-signing-key.json"}},
     2,
     "bob_read_session_summary"),
    ("Read attack_surface.json allows",
     {"tool_input": {"file_path": f"{SESSION}/attack_surface.json"}},
     0,
     None),
    ("Read surface-discovery-summary.json allows",
     {"tool_input": {"file_path": f"{SESSION}/surface-discovery-summary.json"}},
     0,
     None),
    ("Read deep-summary.json allows",
     {"tool_input": {"file_path": f"{SESSION}/deep-summary.json"}},
     0,
     None),
    ("Read surface-leads.json allows",
     {"tool_input": {"file_path": f"{SESSION}/surface-leads.json"}},
     0,
     None),
    ("Read outside session allows",
     {"tool_input": {"file_path": "/tmp/report.md"}},
     0,
     None),
    ("Bash cat findings blocks",
     {"tool_input": {"command": f"cat {SESSION}/findings.jsonl"}},
     2,
     "bob_read_candidate_claims"),
    ("Bash head grade blocks",
     {"tool_input": {"command": f"head -n 5 {SESSION}/grade.json"}},
     2,
     "bob_read_session_summary"),
    ("Bash tail http audit blocks",
     {"tool_input": {"command": f"tail -n 20 {SESSION}/http-audit.jsonl"}},
     2,
     "bob_read_http_audit"),
    ("Bash jq verification blocks",
     {"tool_input": {"command": f"jq '.results[]' {SESSION}/verified-final.json"}},
     2,
     "bob_read_session_summary"),
    ("Bash sed findings blocks",
     {"tool_input": {"command": f"sed -n '1,5p' {SESSION}/findings.jsonl"}},
     2,
     "bob_read_candidate_claims"),
    ("Bash awk report blocks",
     {"tool_input": {"command": f"awk '{{print $1}}' {SESSION}/report.md"}},
     2,
     "bob_read_session_summary"),
    ("Bash grep grade blocks",
     {"tool_input": {"command": f"grep HOLD {SESSION}/grade.json"}},
     2,
     "bob_read_session_summary"),
    ("Bash rg session dir blocks",
     {"tool_input": {"command": f"rg token {SESSION}"}},
     2,
     "bob_read_session_summary"),
    ("Bash less evidence blocks",
     {"tool_input": {"command": f"less {SESSION}/evidence-packs.json"}},
     2,
     "bob_read_session_summary"),
    ("Bash wc traffic blocks",
     {"tool_input": {"command": f"wc -l {SESSION}/traffic.jsonl"}},
     2,
     "bob_read_session_summary"),
    ("Bash cat repo inventory blocks",
     {"tool_input": {"command": f"cat {SESSION}/repo-inventory.json"}},
     2,
     "bob_read_session_summary"),
    ("Bash tail repo checks blocks",
     {"tool_input": {"command": f"tail -n 5 {SESSION}/repo-checks.jsonl"}},
     2,
     "bob_read_session_summary"),
    ("Bash cat repo env blocks",
     {"tool_input": {"command": f"cat {SESSION}/repo-env.json"}},
     2,
     "bob_read_session_summary"),
    ("Bash cat Dockerfile.bob blocks",
     {"tool_input": {"command": f"cat {SESSION}/Dockerfile.bob"}},
     2,
     "bob_read_session_summary"),
    ("Bash tail repo command runs blocks",
     {"tool_input": {"command": f"tail -n 5 {SESSION}/repo-command-runs.jsonl"}},
     2,
     "bob_read_session_summary"),
    ("Bash tail offensive runs blocks",
     {"tool_input": {"command": f"tail -n 5 {SESSION}/offensive-runs.jsonl"}},
     2,
     "bob_read_session_summary"),
    ("Bash cd-then-relative-read of offensive-runs.jsonl blocks",
     {"tool_input": {"command": f"cd {SESSION} && cat offensive-runs.jsonl"}},
     2,
     "bob_read_session_summary"),
    ("Bash cd-dashdash-then-relative-read of repo-command-runs.jsonl blocks",
     {"tool_input": {"command": f"cd -- {SESSION} && tail -n 5 repo-command-runs.jsonl"}},
     2,
     "bob_read_session_summary"),
    ("Bash tail static-analysis results blocks",
     {"tool_input": {"command": f"tail -n 5 {SESSION}/static-analysis-results.jsonl"}},
     2,
     "bob_read_session_summary"),
    ("Bash tail static-analysis index blocks",
     {"tool_input": {"command": f"tail -n 5 {SESSION}/static-analysis-index.jsonl"}},
     2,
     "bob_read_session_summary"),
    ("Bash tail technique attempts blocks",
     {"tool_input": {"command": f"tail -n 5 {SESSION}/technique-attempts.jsonl"}},
     2,
     "bob_read_session_summary"),
    ("Bash tail technique pack reads blocks",
     {"tool_input": {"command": f"tail -n 5 {SESSION}/technique-pack-reads.jsonl"}},
     2,
     "bob_read_session_summary"),
    ("Bash cat diff impact blocks",
     {"tool_input": {"command": f"cat {SESSION}/diff-impact.json"}},
     2,
     "bob_read_session_summary"),
    ("Bash strings auth blocks",
     {"tool_input": {"command": f"strings {SESSION}/auth.json"}},
     2,
     "bob_read_session_summary"),
    ("Bash cat handoff signing key blocks",
     {"tool_input": {"command": f"cat {SESSION}/.handoff-signing-key.json"}},
     2,
     "bob_read_session_summary"),
    ("Bash nl handoff blocks",
     {"tool_input": {"command": f"nl -ba {SESSION}/handoff-w1-a1.md"}},
     2,
     "bob_read_session_summary"),
    ("Bash python open read blocks",
     {"tool_input": {"command": f"python3 -c \"open('{SESSION}/findings.jsonl').read()\""}},
     2,
     "bob_read_candidate_claims"),
    ("Bash node readFileSync blocks",
     {"tool_input": {"command": f"node -e \"require('fs').readFileSync('{SESSION}/report.md', 'utf8')\""}},
     2,
     "bob_read_session_summary"),
    ("Bash cat attack surface allows",
     {"tool_input": {"command": f"cat {SESSION}/attack_surface.json"}},
     0,
     None),
    ("Bash cat compact surface-discovery summary allows",
     {"tool_input": {"command": f"cat {SESSION}/surface-discovery-summary.json"}},
     0,
     None),
    ("Bash grep attack surface allows",
     {"tool_input": {"command": f"grep api {SESSION}/attack_surface.json"}},
     0,
     None),
    ("Bash cat non-session allows",
     {"tool_input": {"command": "cat /tmp/example.md"}},
     0,
     None),
    ("Bash echo Python snippet allows",
     {"tool_input": {"command": f"echo \"open('{SESSION}/findings.jsonl').read()\""}},
     0,
     None),
    ("Bash cat raw proof path blocks",
     {"tool_input": {"command": f"cat {SESSION}/raw-response-body.txt"}},
     2,
     "bob_read_session_summary"),

    # --- sensitive session state: OOB tokens + private-target/lab auth ---
    ("Read oob-tokens.jsonl blocks",
     {"tool_input": {"file_path": f"{SESSION}/oob-tokens.jsonl"}},
     2,
     "bob_read_session_summary"),
    ("Read lab-authorization.json blocks",
     {"tool_input": {"file_path": f"{SESSION}/lab-authorization.json"}},
     2,
     "bob_read_session_summary"),

    # --- shlex.split ValueError must block, not silently allow ---
    ("Bash with unterminated quote blocks (shlex ValueError)",
     {"tool_input": {"command": f"cat '{SESSION}/findings.jsonl"}},
     2,
     "cannot be safely parsed"),
]


def run_symlink_alias_case(adapter, hook):
    """A symlink OUTSIDE the session pointing at the raw-PII capture dir must NOT bypass the block:
    Read through `/tmp/.../alias -> <session>/massread-evidence` must still exit 2 (bot-review #101).
    The symlink target need not exist — pathlib.resolve() follows the link to a session-relative path."""
    tmpd = tempfile.mkdtemp(prefix="bob-readguard-")
    alias = os.path.join(tmpd, "evidence-alias")
    try:
        os.symlink(f"{SESSION}/massread-evidence", alias)
        payload = {"tool_input": {"file_path": f"{alias}/run-massread-abc123.json"}}
        result = subprocess.run(
            ["bash", hook], input=json.dumps(payload), capture_output=True, text=True,
        )
        ok = result.returncode == 2
        desc = "Read raw-PII capture via OUTSIDE-session symlink alias blocks (#101)"
        status = "\033[32mPASS\033[0m" if ok else "\033[31mFAIL\033[0m"
        print(f"  {status}: [{adapter}] {desc}")
        if not ok:
            print(f"         expected exit 2 (blocked), got {result.returncode}")
            if result.stderr.strip():
                print(f"         stderr: {result.stderr.strip()}")
        return ok
    finally:
        try:
            os.unlink(alias)
        except OSError:
            pass
        os.rmdir(tmpd)


def main():
    passed = 0
    failed = 0

    for adapter, hook in HOOKS:
        print(f"\n=== {adapter} read guard ===")
        if run_symlink_alias_case(adapter, hook):
            passed += 1
        else:
            failed += 1
        for desc, payload, expected, expected_text in TESTS:
            result = subprocess.run(
                ["bash", hook],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
            )
            ok = result.returncode == expected
            if ok and expected_text:
                ok = expected_text in result.stderr
            status = "\033[32mPASS\033[0m" if ok else "\033[31mFAIL\033[0m"
            print(f"  {status}: [{adapter}] {desc}")
            if not ok:
                print(f"         expected exit {expected}, got {result.returncode}")
                if expected_text:
                    print(f"         expected stderr to include: {expected_text}")
                if result.stderr.strip():
                    print(f"         stderr: {result.stderr.strip()}")
                failed += 1
            else:
                passed += 1

    print(f"\n  {passed}/{passed + failed} passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
