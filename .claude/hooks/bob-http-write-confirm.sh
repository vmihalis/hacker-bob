#!/bin/bash
# PreToolUse hook — "ask before writing" gate for bob_http_scan. Opt-in + INERT BY DEFAULT.
#
# Bob ships FULLY-AUTONOMOUS (operator-locked default), so this gate does nothing unless the operator
# opts in by setting a truthy BOB_HTTP_WRITE_CONFIRM in the environment Claude Code launches under.
# When enabled, a bob_http_scan call carrying a target-MUTATING method (POST/PUT/PATCH/DELETE) returns
# permissionDecision:"ask" so the operator confirms before Bob writes to the target. Read methods
# (GET/HEAD/OPTIONS) pass through; the scope is bob_http_scan only (bob_auto_signup has its own
# temp-email provenance guard, and the offensive confirmers fire GETs).
#
# FAST PATH: this hook fires on EVERY bob_http_scan, so the disabled case (the default for every
# install) must cost nothing — the pure-bash flag check below exits before any interpreter is spawned.
# Only when the gate is ON do we spawn python to parse the payload (mirrors session-write-guard.sh).
flag=$(printf '%s' "${BOB_HTTP_WRITE_CONFIRM:-}" | tr '[:upper:]' '[:lower:]')
case "$flag" in
  1|true|yes|on) ;;            # enabled — fall through to the decision logic
  *) exit 0 ;;                 # disabled — abstain (allow) with no interpreter spawn
esac

INPUT=$(cat)
export WRITE_CONFIRM_INPUT="$INPUT"

python3 - <<'PY'
import json
import os
import sys

SCAN_TOOL = "mcp__hacker-bob__bob_http_scan"
READ_METHODS = {"GET", "HEAD", "OPTIONS"}


def allow():
    # Exit 0 with no stdout = the hook abstains; Claude Code proceeds with its normal flow.
    raise SystemExit(0)


def redact_url(raw):
    # Show origin+path only (drop userinfo/query/fragment) — the codebase's value-blind redaction. A
    # write replay of an OAuth callback / signed URL / captured-traffic URL can carry token/code/id in
    # the query or fragment, and the confirmation reason is surfaced (and may be transcribed), so opting
    # into HITL must not expose captured secrets. Mirrors how bob_http_scan redacts persisted audit URLs.
    text = str(raw or "")
    if not text:
        return "(unknown url)"
    try:
        from urllib.parse import urlsplit, urlunsplit
        parts = urlsplit(text)
        if parts.scheme and parts.hostname:
            host = parts.hostname
            if parts.port:
                host = f"{host}:{parts.port}"
            return urlunsplit((parts.scheme, host, parts.path, "", ""))
    except Exception:
        pass
    return "(redacted url)"


def ask(method, url):
    reason = (
        f"Bob is about to send a {method} (write) request to {redact_url(url)}. "
        "Confirm before it mutates the target. "
        "(This gate is on because BOB_HTTP_WRITE_CONFIRM is set; unset it to let writes run autonomously.)"
    )
    sys.stdout.write(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": reason,
        }
    }))
    raise SystemExit(0)


# The gate is ENABLED. Fail CLOSED: a bob_http_scan call whose method we cannot positively confirm to
# be a READ might be a write, so default to asking. Only a definitive read method passes through. This
# is the safe failure mode for an opt-in confirmation gate — an unparseable/malformed payload must not
# silently let a write through.
raw = os.environ.get("WRITE_CONFIRM_INPUT", "")
try:
    payload = json.loads(raw or "{}")
except Exception:
    ask("UNKNOWN", "(unparseable request)")

if not isinstance(payload, dict):
    ask("UNKNOWN", "(unrecognized request)")

tool_name = payload.get("tool_name")
# Defensive: the settings matcher should already scope this hook to bob_http_scan, but if a broad
# matcher (or an operator edit) routes a DIFFERENT named tool here, it is out of this gate's scope.
if tool_name and tool_name != SCAN_TOOL:
    allow()

tool_input = payload.get("tool_input")
if not isinstance(tool_input, dict):
    ask("UNKNOWN", "(unrecognized request)")

method = str(tool_input.get("method", "")).strip().upper()
url = str(tool_input.get("url", "") or "(unknown url)")

if method in READ_METHODS:
    allow()
ask(method or "UNKNOWN", url)
PY
