#!/usr/bin/env python3
"""Decision logic for the bob_http_scan "ask before writing" gate (invoked by bob-http-write-confirm.sh
only when BOB_HTTP_WRITE_CONFIRM is enabled).

Reads the PreToolUse payload from STDIN (not env/argv — a large captured request body must not blow
ARG_MAX). FAILS CLOSED: any bob_http_scan call we cannot positively confirm to be a READ asks the
operator. A target-mutating method (POST/PUT/PATCH/DELETE) asks; so does a read method that smuggles a
write via a method-override (?_method=DELETE, X-HTTP-Method-Override: DELETE, or a _method form body) —
mirroring how the offensive read probes treat those as mutation-shaped. Definitive reads and
out-of-scope tools pass through. The confirmation reason shows the URL redacted to origin+path (drop
userinfo/query/fragment) so opting into HITL never surfaces query/fragment-borne secrets in the prompt."""
import json
import sys

SCAN_TOOL = "mcp__hacker-bob__bob_http_scan"
READ_METHODS = {"GET", "HEAD", "OPTIONS"}
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
OVERRIDE_HEADERS = {"x-http-method-override", "x-method-override", "x-http-method"}


def allow():
    # Exit 0 with no stdout = the hook abstains; Claude Code proceeds with its normal flow.
    raise SystemExit(0)


def redact_url(raw):
    # origin+path only (drop userinfo/query/fragment) — the codebase's value-blind redaction; a write
    # replay of an OAuth callback / signed URL / captured-traffic URL can carry token/code in the query
    # or fragment, and the reason is surfaced (and may be transcribed).
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


def has_write_override(url, headers, body):
    """A read-method request that smuggles a write via _method / override headers must still ask."""
    # ?_method=<mutating> (or a method-override carried as a query param)
    try:
        from urllib.parse import urlsplit, parse_qs
        query = parse_qs(urlsplit(str(url or "")).query, keep_blank_values=True)
        for key, values in query.items():
            if key.strip().lower() in (OVERRIDE_HEADERS | {"_method"}):
                if any(str(v).strip().upper() in MUTATING_METHODS for v in values):
                    return True
    except Exception:
        return True  # unparseable → fail closed
    # X-HTTP-Method-Override / X-Method-Override / X-HTTP-Method: <mutating>
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).strip().lower() in OVERRIDE_HEADERS and str(value).strip().upper() in MUTATING_METHODS:
                return True
    # _method=<mutating> smuggled in a (form) body on a read-method request
    if isinstance(body, str) and "_method" in body.lower():
        import re
        if re.search(r"(?:^|[?&\s;])_method=(?:post|put|patch|delete)\b", body, re.IGNORECASE):
            return True
    return False


def main():
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw or "{}")
    except Exception:
        ask("UNKNOWN", "(unparseable request)")

    if not isinstance(payload, dict):
        ask("UNKNOWN", "(unrecognized request)")

    tool_name = payload.get("tool_name")
    # Defensive: the settings matcher should already scope this hook to bob_http_scan; a different
    # named tool routed here (broad matcher / operator edit) is out of this gate's scope.
    if tool_name and tool_name != SCAN_TOOL:
        allow()

    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        ask("UNKNOWN", "(unrecognized request)")

    method = str(tool_input.get("method", "")).strip().upper()
    url = tool_input.get("url")
    headers = tool_input.get("headers")
    body = tool_input.get("body")

    # Fail CLOSED: only a definitive read with NO write-override slips through; everything else
    # (mutating method, missing/unknown method, or a method-override smuggled into a read) asks.
    if method in READ_METHODS and not has_write_override(url, headers, body):
        allow()
    ask(method or "UNKNOWN", url)


if __name__ == "__main__":
    main()
