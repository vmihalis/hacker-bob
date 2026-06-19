#!/bin/bash
# Session write guard hook — PreToolUse on Bash and Write
# Blocks direct writes to MCP-owned files in ~/bounty-agent-sessions/
# Forces agents to use MCP tools for structured output
# Exit 0 = allow, Exit 2 = block

INPUT=$(cat)
export WRITE_GUARD_INPUT="$INPUT"
# CR-2: classification tables are rendered from mcp/lib/paths.js
# WRITE_GUARD_TABLES — never hand-edit. Regenerate with
# `node scripts/generate-write-guard-tables.js`. The manifest travels beside
# this hook (the kimi install copies it into .kimi/hooks/).
export WRITE_GUARD_TABLES_FILE="$(dirname "$0")/write-guard-tables.json"

python3 - <<'PY'
import json
import os
import pathlib
import re
import shlex
import sys


SESSIONS_ROOT = pathlib.Path.home() / "bounty-agent-sessions"

# CR-2: load the classification tables rendered from mcp/lib/paths.js
# WRITE_GUARD_TABLES. The manifest is the single source of truth; closure
# covers the AUDIT-GRADED subset (re-exported by reference from
# AUDIT_GRADED_PATHS) plus the hand-maintained plain-MCP-owned/agent-writable
# lists. The full MCP-owned basename inventory cross-check is a separate
# follow-up.
_tables_path = os.environ.get("WRITE_GUARD_TABLES_FILE", "")
try:
    with open(_tables_path, "r", encoding="utf-8") as _fh:
        _T = json.load(_fh)
except Exception as exc:  # fail closed
    # A missing/corrupt manifest must FAIL CLOSED, not silently allow. Block
    # every session write rather than lose enforcement.
    print(
        "BLOCKED: write-guard tables missing/unreadable "
        f"({_tables_path}: {exc}). Run "
        "`node scripts/generate-write-guard-tables.js`.",
        file=sys.stderr,
    )
    raise SystemExit(2)

# BLOCK set = audit-graded ∪ mcp-owned (both are write-via-MCP-only).
MCP_OWNED_EXACT = set(_T["audit_graded_basenames"]) | set(_T["mcp_owned_basenames"])
MCP_OWNED_DIRS = set(_T["mcp_owned_dirs"])
MCP_OWNED_PATTERNS = [
    re.compile(p) for p in (
        _T["audit_graded_filename_patterns"] + _T["mcp_owned_filename_patterns"]
    )
]
# Audit-graded directory prefixes (verification-attempts/, wave-handoffs/, …):
# anything under them — matched SESSION-RELATIVE, per isAuditGradedPath — is
# blocked regardless of basename.
MCP_OWNED_DIR_PREFIXES = list(_T["audit_graded_relative_dirs"])

AGENT_ALLOWED_EXACT = set(_T["agent_writable_basenames"])
AGENT_ALLOWED_PATTERNS = [re.compile(p) for p in _T["agent_writable_filename_patterns"]]


def is_mcp_owned(filename):
    if filename in MCP_OWNED_EXACT:
        return True
    return any(p.match(filename) for p in MCP_OWNED_PATTERNS)


def is_agent_allowed(filename):
    if filename in AGENT_ALLOWED_EXACT:
        return True
    return any(p.match(filename) for p in AGENT_ALLOWED_PATTERNS)


def resolve_path(raw_path):
    path_text = raw_path.strip().strip("\"'")

    env_session = os.environ.get("SESSION", "")
    if env_session:
        path_text = path_text.replace("${SESSION}", env_session).replace("$SESSION", env_session)

    home = str(pathlib.Path.home())
    path_text = path_text.replace("${HOME}", home).replace("$HOME", home)

    if path_text.startswith("~"):
        path_text = os.path.expanduser(path_text)

    return pathlib.Path(path_text)


def session_relative(resolved):
    """Return the session-RELATIVE PurePath if `resolved` is under the session
    root, else None. Parity with isAuditGradedPath's path.relative() basis."""
    try:
        return resolved.resolve(strict=False).relative_to(SESSIONS_ROOT.resolve(strict=False))
    except (ValueError, OSError):
        return None


def check_file(raw_path):
    """Returns filename to block, or None to allow."""
    resolved = resolve_path(raw_path)
    rel = session_relative(resolved)
    if rel is None:
        return None

    filename = resolved.name

    if any(part in MCP_OWNED_DIRS for part in resolved.parts):
        return filename

    # Relative-path-prefix match (parity with isAuditGradedPath). Component
    # membership on the session-relative parts blocks …/verification-attempts/x
    # and …/wave-handoffs/y while excluding out-of-session lookalikes.
    if any(part in MCP_OWNED_DIR_PREFIXES for part in rel.parts):
        return filename

    if is_agent_allowed(filename):
        return None

    if is_mcp_owned(filename):
        return filename

    # Block by default for unrecognized files in session dir
    return filename


def block(message):
    print(message, file=sys.stderr)
    raise SystemExit(2)


def extract_redirect_targets(command):
    """Extract file paths from shell redirect operators and tee commands."""
    targets = []

    # Match > and >> redirects (skip heredocs like <<EOF and <<'EOF')
    for match in re.finditer(r"(?<!<)>{1,2}\s*[\"']?([^\"'\s|;&)\n]+)", command):
        target = match.group(1)
        # Skip process substitution and fd redirects
        if target.startswith("(") or target.startswith("&") or target == "/dev/null":
            continue
        targets.append(target)

    # Match tee targets: tee [-a] filepath
    for match in re.finditer(r"\btee\s+(?:-[a]\s+)?[\"']?([^\"'\s|;&)\n]+)", command):
        target = match.group(1)
        if not target.startswith("-"):
            targets.append(target)

    return targets


def extract_inline_script_paths(command):
    """Extract file paths from python3/node/ruby/perl inline scripts that write files."""
    targets = []

    # Instead of parsing quoting contexts, scan the entire command for file-write
    # patterns when an interpreter is present. This catches:
    #   python3 -c "open('/path','w').write(...)"
    #   python3 - <<'PY' ... open('/path','w') ... PY
    #   python3 -c "Path('/path').write_text(...)"
    # Regardless of quote escaping or heredoc boundaries.

    # open("/path", ...) or open('/path', ...)
    for match in re.finditer(r"""open\s*\(\s*["']([^"']+)["']""", command):
        targets.append(match.group(1))

    # pathlib.Path("/path").write_text(...) or Path('/path').write_text(...)
    for match in re.finditer(r"""Path\s*\(\s*["']([^"']+)["']\s*\)\s*\.write""", command):
        targets.append(match.group(1))

    return targets


def check_mutating_path_commands(command):
    """Block direct shell mutations of MCP-owned session files."""
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return

    mutators = {"rm", "unlink", "mv", "cp", "chmod", "chown", "install"}
    separators = {"|", ";", "&&", "||"}

    def block_mutator(verb, path):
        blocked = check_file(path)
        if blocked:
            block(
                f"BLOCKED: Bash {verb} on '{blocked}' in session directory. "
                f"Use the appropriate hacker-bob MCP tool instead."
            )

    for index, token in enumerate(tokens):
        command_name = pathlib.PurePosixPath(token).name

        if command_name == "sed":
            args = []
            for candidate in tokens[index + 1:]:
                if candidate in separators:
                    break
                args.append(candidate)
            # Only treat sed as a write when -i is present (covers -i, -i.bak, -ibak).
            if not any(a == "-i" or a.startswith("-i") for a in args):
                continue
            for candidate in args:
                if candidate.startswith("-"):
                    continue
                # Skip the sed script expression (s/x/y/, /pattern/d, etc.) — paths only.
                if not (
                    candidate.startswith("/")
                    or candidate.startswith("~")
                    or candidate.startswith("$")
                    or "/" in candidate
                    or candidate.endswith((".json", ".jsonl", ".md", ".txt", ".log"))
                ):
                    continue
                block_mutator("sed -i", candidate)
            continue

        if command_name == "dd":
            for candidate in tokens[index + 1:]:
                if candidate in separators:
                    break
                if candidate.startswith("of="):
                    block_mutator("dd", candidate[3:])
            continue

        if command_name not in mutators:
            continue

        for candidate in tokens[index + 1:]:
            if candidate in separators:
                break
            if candidate.startswith("-"):
                continue
            block_mutator(command_name, candidate)


# Main
raw_input = os.environ.get("WRITE_GUARD_INPUT", "")
payload = {}
try:
    payload = json.loads(raw_input)
except Exception:
    payload = {}

if not isinstance(payload, dict):
    payload = {}

tool_input = payload.get("tool_input")
if not isinstance(tool_input, dict):
    tool_input = {}

# LOUD fail-open guard. This script parses the Claude Code PreToolUse envelope
# (tool_input.{file_path,command}). The Kimi CLI's stdin payload shape and tool
# names are NOT pinned to this guard's assumptions: Kimi may emit Shell/WriteFile
# tool-names and a different envelope key. If the payload is non-empty but we
# cannot find any recognizable field, we must NOT silently exit 0 (that converts
# a parse miss into an invisible enforcement gap). Emit a LOUD stderr warning and
# allow, so the operator sees that enforcement did not engage rather than getting
# false confidence. Kimi is never bricked — we still exit 0.
_recognized = (
    ("file_path" in tool_input)
    or ("command" in tool_input)
)
if raw_input.strip() and not _recognized:
    print(
        "WARNING: hacker-bob session-write-guard received a non-empty PreToolUse "
        "payload it does not recognize (no tool_input.file_path or "
        "tool_input.command). The guard expects the Claude Code envelope; your "
        "CLI (e.g. Kimi) may use a different tool-name/payload shape. Write "
        "enforcement did NOT engage for this call (fail-OPEN). Verify the guard "
        "against your CLI version before relying on Y-P13 enforcement.",
        file=sys.stderr,
    )
    raise SystemExit(0)

# Detect Write tool vs Bash tool
if "file_path" in tool_input:
    # Write tool
    blocked = check_file(tool_input["file_path"])
    if blocked:
        block(
            f"BLOCKED: Direct write to '{blocked}' in session directory. "
            f"Use the appropriate hacker-bob MCP tool instead."
        )
    raise SystemExit(0)

# Bash tool
command = tool_input.get("command", "")
if not command:
    raise SystemExit(0)

check_mutating_path_commands(command)

# Quick gate: skip the redirect/inline-script extractors if there are no
# matching write indicators (direct-write verbs are already handled above).
has_redirects = re.search(r">{1,2}\s|tee\s", command)
has_open_call = re.search(r"open\s*\(|Path\s*\(", command)

if not has_redirects and not has_open_call:
    raise SystemExit(0)

# Extract and check redirect targets
if has_redirects:
    for target in extract_redirect_targets(command):
        blocked = check_file(target)
        if blocked:
            block(
                f"BLOCKED: Bash redirect to '{blocked}' in session directory. "
                f"Use the appropriate hacker-bob MCP tool instead."
            )

# Extract and check inline script file writes (open(), Path().write_text(), etc.)
if has_open_call:
    for target in extract_inline_script_paths(command):
        blocked = check_file(target)
        if blocked:
            block(
                f"BLOCKED: Inline script writes to '{blocked}' in session directory. "
                f"Use the appropriate hacker-bob MCP tool instead."
            )

raise SystemExit(0)
PY
