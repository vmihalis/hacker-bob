#!/bin/bash
# Scope guard hook — PreToolUse on scoped bountyagent MCP tools
# Validates URL parameters against in-scope domains
# Warn-only for out-of-scope so the MCP server can return a structured blocked audit record
# Hard-block for deny-listed domains (exit 2)

INPUT=$(cat)
export SCOPE_GUARD_INPUT="$INPUT"

python3 - <<'PY'
import datetime
import json
import os
import pathlib
import sys
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_host(value):
    try:
        host = urlsplit(value.strip()).hostname
    except Exception:
        host = None
    if not host:
        return None
    return host.strip().strip(".").lower()


def redact_url(value):
    try:
        parsed = urlsplit(value.strip())
        query = urlencode([(key, "REDACTED") for key, _ in parse_qsl(parsed.query, keep_blank_values=True)])
        netloc = parsed.hostname or ""
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
        return urlunsplit((parsed.scheme, netloc, parsed.path, query, ""))
    except Exception:
        return "[invalid-url]"


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {}


def load_scope(session_dir):
    if session_dir in scope_cache:
        return scope_cache[session_dir]

    allowed = {session_dir.name.lower()}

    state = load_json(session_dir / "state.json")
    target = state.get("target", "").strip().lower()
    if target and target == session_dir.name.lower():
        allowed.add(target)

    attack_surface = load_json(session_dir / "attack_surface.json")
    for surface in attack_surface.get("surfaces", []):
        for host in surface.get("hosts", []):
            normalized = normalize_host(host)
            if normalized:
                allowed.add(normalized)

    scope_cache[session_dir] = allowed
    return allowed


def matches_scope(domain, allowed_domains):
    for allowed in allowed_domains:
        if domain == allowed or domain.endswith("." + allowed):
            return True
    return False


PUBLIC_INTEL_ALLOWED_HOSTS = {
    "web.archive.org",
    "otx.alienvault.com",
    "crt.sh",
    "api.github.com",
    "raw.githubusercontent.com",
}


def target_appears_in_public_intel_url(url_value, target_domain):
    if not target_domain:
        return False
    try:
        parsed = urlsplit(url_value.strip())
    except Exception:
        return False
    target = target_domain.strip().strip(".").lower()
    raw = f"{parsed.path}?{parsed.query}".lower()
    try:
        decoded = unquote(raw)
    except Exception:
        decoded = raw
    return target in raw or target in decoded


def log_line(session_dir, message):
    with open(session_dir / "scope-warnings.log", "a", encoding="utf-8") as handle:
        handle.write(f"[{utc_now()}] {message}\n")


def block(message):
    print(message, file=sys.stderr)
    raise SystemExit(2)


payload = {}
try:
    payload = json.loads(os.environ.get("SCOPE_GUARD_INPUT", ""))
except Exception:
    payload = {}

ti = payload.get("tool_input", {})
url = ti.get("url", "") or ti.get("target_url", "") or ti.get("signup_url", "")
if not url:
    raise SystemExit(0)

domain = normalize_host(url)
if not domain:
    raise SystemExit(0)

sessions_root = pathlib.Path.home() / "bounty-agent-sessions"
session_dirs = []
if sessions_root.is_dir():
    session_dirs = sorted(path for path in sessions_root.iterdir() if path.is_dir())

scope_cache = {}

# If target_domain is provided, resolve session directly from it
target_domain = (ti.get("target_domain") or "").strip().lower()
session_dir = None
if target_domain:
    candidate = sessions_root / target_domain
    if candidate.is_dir():
        session_dir = candidate

if session_dir is None:
    matched_sessions = [session for session in session_dirs if matches_scope(domain, load_scope(session))]

    if len(matched_sessions) == 1:
        session_dir = matched_sessions[0]
    elif len(matched_sessions) > 1:
        block("BLOCKED: unable to resolve a single session for scoped MCP tool")
    elif len(session_dirs) == 1:
        session_dir = session_dirs[0]
    else:
        block("BLOCKED: unable to resolve session for scoped MCP tool")

deny_list = session_dir / "deny-list.txt"
if deny_list.is_file():
    with open(deny_list, "r", encoding="utf-8", errors="ignore") as handle:
        for raw_line in handle:
            denied = raw_line.strip().strip(".").lower()
            if not denied:
                continue
            if matches_scope(domain, {denied}):
                log_line(session_dir, f"BLOCKED (deny-list): {domain} via scoped MCP tool")
                block(f"BLOCKED: {domain} is on the deny list")

allowed = set(load_scope(session_dir))

public_intel_allowed = (
    matches_scope(domain, PUBLIC_INTEL_ALLOWED_HOSTS)
    and target_appears_in_public_intel_url(url, session_dir.name)
)

if not matches_scope(domain, allowed) and not public_intel_allowed:
    log_line(session_dir, f"OUT-OF-SCOPE (http_scan): {domain} (url: {redact_url(url)[:200]})")

raise SystemExit(0)
PY
