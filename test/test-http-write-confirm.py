#!/usr/bin/env python3
"""Unit tests for the bob-http-write-confirm.js PreToolUse hook.

The hook is FLAG-CONTROLLED + INERT BY DEFAULT: it asks the operator to confirm only when
BOB_HTTP_WRITE_CONFIRM is truthy AND a bob_http_scan call carries a target-mutating method
(POST/PUT/PATCH/DELETE). Everything else passes through (exit 0, no stdout = abstain). Unlike
the exit-2 session-write-guard, an "ask" is an exit-0 stdout decision, so each case asserts
on both the exit code and whether stdout carries permissionDecision:"ask"."""
import json
import os
import subprocess
import sys

HOOK = os.path.join(os.path.dirname(__file__), "..", ".claude", "hooks", "bob-http-write-confirm.js")
SCAN = "mcp__hacker-bob__bob_http_scan"


def scan(method, url="https://target.example/api/x"):
    return {"tool_name": SCAN, "tool_input": {"method": method, "url": url}}


# (description, flag_value_or_None, payload_or_raw_string, expect_ask)
TESTS = [
    # --- inert by default (flag unset) ---
    ("flag unset + POST -> allow (gate inert by default)", None, scan("POST"), False),
    ("flag unset + DELETE -> allow (gate inert by default)", None, scan("DELETE"), False),
    ("flag explicitly off (\"0\") + POST -> allow", "0", scan("POST"), False),
    ("flag explicitly off (\"false\") + POST -> allow", "false", scan("POST"), False),
    ("flag empty string + POST -> allow", "", scan("POST"), False),

    # --- enabled: mutating methods ask ---
    ("flag on (\"1\") + POST -> ask", "1", scan("POST"), True),
    ("flag on (\"true\") + PUT -> ask", "true", scan("PUT"), True),
    ("flag on (\"yes\") + PATCH -> ask", "yes", scan("PATCH"), True),
    ("flag on (\"on\") + DELETE -> ask", "on", scan("DELETE"), True),
    ("flag on + lowercase \"post\" -> ask (case-insensitive)", "1", scan("post"), True),

    # --- enabled: read methods pass through ---
    ("flag on + GET -> allow", "1", scan("GET"), False),
    ("flag on + HEAD -> allow", "1", scan("HEAD"), False),
    ("flag on + OPTIONS -> allow", "1", scan("OPTIONS"), False),

    # --- enabled: scope is bob_http_scan only ---
    ("flag on + non-scan tool with POST-ish input -> allow",
     "1", {"tool_name": "mcp__hacker-bob__bob_read_http_audit", "tool_input": {"method": "POST"}}, False),
    ("flag on + bob_auto_signup -> allow (out of scope; has its own provenance guard)",
     "1", {"tool_name": "mcp__hacker-bob__bob_auto_signup", "tool_input": {}}, False),

    # --- enabled: defensive edges ---
    ("flag on + scan with missing method -> allow (no method = not a write)",
     "1", {"tool_name": SCAN, "tool_input": {"url": "https://target.example/x"}}, False),
    ("flag on + malformed JSON payload -> allow (abstain, don't block harness)", "1", "{not json", False),
    ("flag on + empty payload -> allow", "1", "{}", False),
]


def main():
    passed = 0
    failed = 0
    for desc, flag, payload, expect_ask in TESTS:
        env = dict(os.environ)
        env.pop("BOB_HTTP_WRITE_CONFIRM", None)
        if flag is not None:
            env["BOB_HTTP_WRITE_CONFIRM"] = flag
        raw = payload if isinstance(payload, str) else json.dumps(payload)
        result = subprocess.run(
            ["node", HOOK], input=raw, capture_output=True, text=True, env=env,
        )
        asked = '"permissionDecision":"ask"' in result.stdout.replace(" ", "")
        ok = result.returncode == 0 and asked == expect_ask
        status = "\033[32mPASS\033[0m" if ok else "\033[31mFAIL\033[0m"
        print(f"  {status}: {desc}")
        if not ok:
            print(f"         expected exit 0 + ask={expect_ask}, got exit {result.returncode} + ask={asked}")
            if result.stderr.strip():
                print(f"         stderr: {result.stderr.strip()}")
            failed += 1
        else:
            passed += 1
    print(f"\n  {passed}/{passed + failed} passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
