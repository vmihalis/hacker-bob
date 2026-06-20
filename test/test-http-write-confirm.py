#!/usr/bin/env python3
"""Unit tests for the bob-http-write-confirm.sh PreToolUse hook.

The hook is FLAG-CONTROLLED + INERT BY DEFAULT: a pure-bash flag check exits immediately (allow) when
BOB_HTTP_WRITE_CONFIRM is unset/falsy — no interpreter spawn — so the disabled case (the default) is
free on every bob_http_scan. When enabled, it asks the operator to confirm a target-mutating
bob_http_scan (POST/PUT/PATCH/DELETE) and FAILS CLOSED: any enabled call we cannot positively confirm
to be a read (malformed/missing method) asks rather than silently allowing a possible write. Definitive
reads (GET/HEAD/OPTIONS) and out-of-scope tools pass through. An "ask" is an exit-0 stdout decision, so
each case asserts on both the exit code and whether stdout carries permissionDecision:"ask"."""
import json
import os
import subprocess
import sys

HOOK = os.path.join(os.path.dirname(__file__), "..", ".claude", "hooks", "bob-http-write-confirm.sh")
SCAN = "mcp__hacker-bob__bob_http_scan"


def scan(method, url="https://target.example/api/x"):
    return {"tool_name": SCAN, "tool_input": {"method": method, "url": url}}


# (description, flag_value_or_None, payload_or_raw_string, expect_ask)
TESTS = [
    # --- inert by default (flag unset/falsy): allow with no interpreter spawn ---
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
    ("flag on (\"ON\") uppercase + DELETE -> ask (case-insensitive flag)", "ON", scan("DELETE"), True),
    ("flag on + lowercase \"post\" method -> ask (case-insensitive method)", "1", scan("post"), True),

    # --- enabled: read methods pass through ---
    ("flag on + GET -> allow", "1", scan("GET"), False),
    ("flag on + HEAD -> allow", "1", scan("HEAD"), False),
    ("flag on + OPTIONS -> allow", "1", scan("OPTIONS"), False),

    # --- enabled: a read method that SMUGGLES a write via method-override still asks ---
    ("flag on + GET with ?_method=DELETE -> ask (query method-override)",
     "1", scan("GET", "https://target.example/r?_method=DELETE"), True),
    ("flag on + GET with X-HTTP-Method-Override: DELETE -> ask (header override)",
     "1", {"tool_name": SCAN, "tool_input": {"method": "GET", "url": "https://target.example/r",
                                             "headers": {"X-HTTP-Method-Override": "DELETE"}}}, True),
    ("flag on + GET with X-Method-Override: PUT -> ask (header override)",
     "1", {"tool_name": SCAN, "tool_input": {"method": "GET", "url": "https://target.example/r",
                                             "headers": {"X-Method-Override": "PUT"}}}, True),
    ("flag on + GET with _method=POST form body -> ask (body override)",
     "1", {"tool_name": SCAN, "tool_input": {"method": "GET", "url": "https://target.example/r",
                                             "body": "a=1&_method=POST"}}, True),
    ("flag on + GET with URL-encoded _method=DELETE form body -> ask (decoded override)",
     "1", {"tool_name": SCAN, "tool_input": {"method": "GET", "url": "https://target.example/r",
                                             "body": "a=1&_method=%44%45%4C%45%54%45"}}, True),
    ("flag on + GET with ?_method=GET (non-mutating) -> allow",
     "1", scan("GET", "https://target.example/r?_method=GET"), False),
    ("flag on + GET with unrelated query -> allow",
     "1", scan("GET", "https://target.example/r?page=2"), False),

    # --- enabled: scope is bob_http_scan only ---
    ("flag on + non-scan tool with POST-ish input -> allow",
     "1", {"tool_name": "mcp__hacker-bob__bob_read_http_audit", "tool_input": {"method": "POST"}}, False),
    ("flag on + bob_auto_signup -> allow (out of scope; has its own provenance guard)",
     "1", {"tool_name": "mcp__hacker-bob__bob_auto_signup", "tool_input": {}}, False),

    # --- enabled: FAIL CLOSED on anything we can't confirm is a read ---
    ("flag on + scan with missing method -> ASK (fail closed; can't confirm a read)",
     "1", {"tool_name": SCAN, "tool_input": {"url": "https://target.example/x"}}, True),
    ("flag on + malformed JSON payload -> ASK (fail closed; might be a write)", "1", "{not json", True),
    ("flag on + empty payload -> ASK (fail closed; no method to confirm a read)", "1", "{}", True),
    ("flag on + unknown method -> ASK (fail closed)", "1", scan("FROBNICATE"), True),
    # oversized payload: the bounded read truncates beyond MAX_BODY_BYTES, the JSON parse fails, ask.
    ("flag on + oversized payload (> read ceiling) -> ASK (fail closed, bounded read)",
     "1", {"tool_name": SCAN, "tool_input": {"method": "GET", "url": "https://target.example/r",
                                             "body": "x" * (5 * 1024 * 1024)}}, True),
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
            ["bash", HOOK], input=raw, capture_output=True, text=True, env=env,
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
