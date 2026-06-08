#!/bin/bash
# Session read guard hook — PreToolUse on Bash and Read
# Blocks direct reads of sensitive or bulky Bob session artifacts.
# Exit 0 = allow, Exit 2 = block

INPUT=$(cat)
export READ_GUARD_INPUT="$INPUT"

python3 - <<'PY'
import json
import os
import pathlib
import re
import shlex
import sys


# Cycle P.2: guard both the canonical `hacker-bob-sessions` root and the
# legacy `bounty-agent-sessions` root so direct reads remain blocked during
# the v2.0/v2.1 coexistence window.
SESSIONS_ROOTS = (
    pathlib.Path.home() / "hacker-bob-sessions",
    pathlib.Path.home() / "bounty-agent-sessions",
)
SESSIONS_ROOT = SESSIONS_ROOTS[0]

BLOCKED_EXACT = {
    "state.json",
    "auth.json",
    "findings.jsonl",
    "findings.md",
    "coverage.jsonl",
    "technique-attempts.jsonl",
    "technique-pack-reads.jsonl",
    "chain-attempts.jsonl",
    "brutalist.json",
    "brutalist.md",
    "balanced.json",
    "balanced.md",
    "verified-final.json",
    "verified-final.md",
    "evidence-packs.json",
    "evidence-packs.md",
    "grade.json",
    "grade.md",
    "SESSION_HANDOFF.md",
    "http-audit.jsonl",
    "traffic.jsonl",
    "public-intel.json",
    "Dockerfile.bob",
    "repo-checks.jsonl",
    "repo-command-runs.jsonl",
    "repo-env.json",
    "repo-inventory.json",
    "surface-routes.json",
    "static-artifacts.jsonl",
    "static-scan-results.jsonl",
    "pipeline-events.jsonl",
    "report.md",
    "chains.md",
    ".handoff-signing-key.json",
    # Plane O O.7: OSS-target artifacts. Raw stdout/stderr from sandboxed
    # docker runs and inventory/env documents may carry secret-shaped tokens
    # from build output. Force agents through MCP readers.
    "repo-checks.jsonl",
    "repo-command-runs.jsonl",
    "repo-env.json",
    "Dockerfile.bob",
    "repo-inventory.json",
}

ALLOWED_EXACT = {
    "attack_surface.json",
    "deep-summary.json",
    "surface-discovery-summary.json",
    "surface-leads.json",
}

BLOCKED_DIRS = {
    "static-imports",
    # Plane O O.7: raw docker-run stdout/stderr (`repo-runs/`), any
    # in-container scratch space (`repo-work/`), and S14 materialized
    # control checkouts (`repo-checkouts/`) must stay opaque to agents.
    "repo-runs",
    "repo-work",
    "repo-checkouts",
}

BLOCKED_PATTERNS = [
    re.compile(r"^handoff-w[1-9][0-9]*-a[1-9][0-9]*\.(json|md)$"),
    re.compile(r"^wave-[1-9][0-9]*-assignments\.json$"),
    re.compile(r"^live-dead-ends-w[1-9][0-9]*-a[1-9][0-9]*\.jsonl$"),
]

RISKY_PATH_RE = re.compile(r"(?:^|[._/\-])(raw|proof|poc|dump|body|impact proof)(?:[._/\-]|$)", re.I)
PATH_FRAGMENT_RE = re.compile(r"(~|\$\{?SESSION\}?|\$\{?HOME\}?|/)[^\s'\";|&)<>,]*")
READ_COMMANDS = {
    "awk",
    "cat",
    "grep",
    "head",
    "jq",
    "less",
    "more",
    "nl",
    "node",
    "nodejs",
    "python",
    "python3",
    "rg",
    "sed",
    "strings",
    "tail",
    "wc",
}
RECURSIVE_READ_COMMANDS = {"grep", "rg"}


def resolve_path(raw_path):
    path_text = str(raw_path).strip().strip("\"'")
    env_session = os.environ.get("SESSION", "")
    if env_session:
        path_text = path_text.replace("${SESSION}", env_session).replace("$SESSION", env_session)
    home = str(pathlib.Path.home())
    path_text = path_text.replace("${HOME}", home).replace("$HOME", home)
    if path_text.startswith("~"):
        path_text = os.path.expanduser(path_text)
    return pathlib.Path(path_text)


def is_in_session_dir(resolved):
    for root in SESSIONS_ROOTS:
        try:
            resolved.resolve(strict=False).relative_to(root.resolve(strict=False))
            return True
        except (ValueError, OSError):
            continue
    return False


def session_root_for(resolved):
    for root in SESSIONS_ROOTS:
        try:
            resolved.resolve(strict=False).relative_to(root.resolve(strict=False))
            return root
        except (ValueError, OSError):
            continue
    return None


def check_file(raw_path, *, block_session_dirs=False):
    resolved = resolve_path(raw_path)
    root = session_root_for(resolved)
    if root is None:
        return None

    try:
        session_relative_parts = resolved.resolve(strict=False).relative_to(
            root.resolve(strict=False)
        ).parts
    except (ValueError, OSError):
        session_relative_parts = ()

    if block_session_dirs and len(session_relative_parts) <= 1:
        return resolved.name or "session directory"

    filename = resolved.name
    if filename in ALLOWED_EXACT:
        return None
    if any(part in BLOCKED_DIRS for part in resolved.parts):
        return filename
    if filename in BLOCKED_EXACT:
        return filename
    if any(pattern.match(filename) for pattern in BLOCKED_PATTERNS):
        return filename
    session_relative = str(resolved)
    if RISKY_PATH_RE.search(session_relative):
        return filename
    return None


def block(blocked):
    print(
        f"BLOCKED: Direct read of '{blocked}' in a Bob session directory. "
        "Use MCP readers such as bob_read_session_summary, "
        "bob_read_state_summary, bob_read_candidate_claims, and "
        "bob_read_http_audit instead.",
        file=sys.stderr,
    )
    raise SystemExit(2)


def looks_like_path(token):
    if not token or token.startswith("-"):
        return False
    if token in {"|", ";", "&&", "||"}:
        return False
    return (
        token.startswith("/")
        or token.startswith("~")
        or token.startswith("$")
        or "hacker-bob-sessions" in token
        or "bounty-agent-sessions" in token
        or token.endswith((".json", ".jsonl", ".md", ".txt", ".har"))
        or "/" in token
    )


def candidate_paths(token):
    if looks_like_path(token):
        yield token
    for match in PATH_FRAGMENT_RE.finditer(token):
        fragment = match.group(0)
        if fragment:
            yield fragment


def check_bash_command(command):
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return
    for index, token in enumerate(tokens):
        command_name = pathlib.PurePosixPath(token).name
        if command_name not in READ_COMMANDS:
            continue
        block_session_dirs = command_name in RECURSIVE_READ_COMMANDS
        for candidate in tokens[index + 1:]:
            if candidate in {"|", ";", "&&", "||"}:
                break
            for path_candidate in candidate_paths(candidate):
                blocked = check_file(path_candidate, block_session_dirs=block_session_dirs)
                if blocked:
                    block(blocked)


payload = {}
try:
    payload = json.loads(os.environ.get("READ_GUARD_INPUT", ""))
except Exception:
    payload = {}

tool_input = payload.get("tool_input", {})

if "file_path" in tool_input:
    blocked = check_file(tool_input["file_path"])
    if blocked:
        block(blocked)
    raise SystemExit(0)

command = tool_input.get("command", "")
if command:
    check_bash_command(command)

raise SystemExit(0)
PY
