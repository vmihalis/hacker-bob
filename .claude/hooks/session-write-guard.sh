#!/bin/bash
# Session write guard hook — PreToolUse on Bash and Write
# Blocks direct writes to MCP-owned files in ~/hacker-bob-sessions/
# (also enforced against the legacy ~/bounty-agent-sessions/ root)
# Forces agents to use MCP tools for structured output
# Exit 0 = allow, Exit 2 = block

INPUT=$(cat)
export WRITE_GUARD_INPUT="$INPUT"
# CR-2: classification tables are rendered from mcp/lib/paths.js
# WRITE_GUARD_TABLES — never hand-edit. Regenerate with
# `node scripts/generate-write-guard-tables.js`. The manifest travels beside
# this hook (installed via the Claude adapter HOOK_DATA_FILES).
export WRITE_GUARD_TABLES_FILE="$(dirname "$0")/write-guard-tables.json"

python3 - <<'PY'
import json
import os
import pathlib
import re
import shlex
import sys


# Cycle P.2: guard both canonical and legacy session roots so MCP-owned
# files stay protected across the v2.0/v2.1 coexistence window.
SESSIONS_ROOTS = (
    pathlib.Path.home() / "hacker-bob-sessions",
    pathlib.Path.home() / "bounty-agent-sessions",
)
SESSIONS_ROOT = SESSIONS_ROOTS[0]

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
    # Key extraction is INSIDE the try so a structurally-wrong manifest (valid
    # JSON but a missing/wrong-typed key) raises KeyError/TypeError here and
    # fails CLOSED with the designed exit 2 — not an unhandled exit 1 that a
    # future adapter could treat as a hook-framework error and fail OPEN.
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
except Exception as exc:  # fail closed
    # A missing/corrupt/incomplete manifest must FAIL CLOSED, not silently allow.
    # Block every session write rather than lose enforcement.
    print(
        "BLOCKED: write-guard tables missing/unreadable/invalid "
        f"({_tables_path}: {exc}). Run "
        "`node scripts/generate-write-guard-tables.js`.",
        file=sys.stderr,
    )
    raise SystemExit(2)


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
    """Return the session-RELATIVE PurePath if `resolved` is under a session
    root, else None. Parity with isAuditGradedPath's path.relative() basis."""
    for root in SESSIONS_ROOTS:
        try:
            rel = resolved.resolve(strict=False).relative_to(root.resolve(strict=False))
            return rel
        except (ValueError, OSError):
            continue
    return None


def extract_cd_targets(command):
    """Directories the command cd's/pushd's into, resolved like other paths.

    PR #108 review (Codex P1): a relative redirect/script target resolves
    against the hook process cwd, so `cd <session_dir> && echo ... >> ledger`
    slips past the guard because the bare `ledger` is judged outside any session
    dir. Collecting cd targets lets check_file also resolve relative paths
    against the shell's working directory, closing that bypass for every
    MCP-owned file (not just offensive-runs.jsonl)."""
    bases = []
    # Consume any cd flags (`-L`/`-P`) and the `--` option terminator before the
    # directory token (PR #108 review, Codex P1: `cd -- <dir>` must not slip the
    # guard). Then drop `cd -` (previous-dir) cases.
    for match in re.finditer(r"\b(?:cd|pushd)\s+(?:-[A-Za-z]+\s+|--\s+)*([\"']?)([^\"'\s;|&]+)\1", command):
        raw = match.group(2)
        if raw.startswith("-") or raw in {"-", "~-", "&&", "||"}:
            continue
        bases.append(resolve_path(raw))
    return bases


def check_file(raw_path, base_dirs=None):
    """Returns filename to block, or None to allow.

    When base_dirs (cd targets) are supplied, a relative path is also resolved
    against each of them so a `cd <session_dir>`-then-relative-redirect cannot
    escape the session-dir check.
    """
    resolved = resolve_path(raw_path)
    candidates = [resolved]
    if not resolved.is_absolute() and base_dirs:
        for base in base_dirs:
            candidates.append(base / resolved)

    for candidate in candidates:
        rel = session_relative(candidate)
        if rel is None:
            continue

        filename = candidate.name

        if any(part in MCP_OWNED_DIRS for part in candidate.parts):
            return filename

        # Relative-path-prefix match (parity with isAuditGradedPath). `rel` is
        # relative to the session ROOT (e.g. <domain>/<run>/verification-attempts/x).
        # Component membership on the session-relative parts blocks
        # …/verification-attempts/x and …/wave-handoffs/y while excluding
        # out-of-session paths that merely share the home prefix.
        if any(part in MCP_OWNED_DIR_PREFIXES for part in rel.parts):
            return filename

        if is_agent_allowed(filename):
            return None

        if is_mcp_owned(filename):
            return filename

        # Block by default for unrecognized files in session dir
        return filename

    return None


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
        block(
            "BLOCKED: Command cannot be safely parsed. "
            "Refusing to allow potentially unsafe shell operation."
        )

    base_dirs = extract_cd_targets(command)
    mutators = {"rm", "unlink", "mv", "cp", "chmod", "chown"}
    for index, token in enumerate(tokens):
        command_name = pathlib.PurePosixPath(token).name
        if command_name not in mutators:
            continue
        for candidate in tokens[index + 1:]:
            if candidate in {"|", ";", "&&", "||"}:
                break
            if candidate.startswith("-"):
                continue
            blocked = check_file(candidate, base_dirs)
            if blocked:
                block(
                    f"BLOCKED: Bash {command_name} on '{blocked}' in session directory. "
                    f"Use the appropriate hacker-bob MCP tool instead."
                )


# Main
payload = {}
try:
    payload = json.loads(os.environ.get("WRITE_GUARD_INPUT", ""))
except Exception:
    payload = {}

tool_input = payload.get("tool_input", {})

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

# Quick gate: skip if no write indicators
has_redirects = re.search(r">{1,2}\s|tee\s", command)
has_open_call = re.search(r"open\s*\(|Path\s*\(", command)

if not has_redirects and not has_open_call:
    raise SystemExit(0)

# Resolve any cd/pushd targets so relative redirect/script paths are checked
# against the shell's working directory, not just the hook process cwd.
cd_targets = extract_cd_targets(command)

# Extract and check redirect targets
if has_redirects:
    for target in extract_redirect_targets(command):
        blocked = check_file(target, cd_targets)
        if blocked:
            block(
                f"BLOCKED: Bash redirect to '{blocked}' in session directory. "
                f"Use the appropriate hacker-bob MCP tool instead."
            )

# Extract and check inline script file writes (open(), Path().write_text(), etc.)
if has_open_call:
    for target in extract_inline_script_paths(command):
        blocked = check_file(target, cd_targets)
        if blocked:
            block(
                f"BLOCKED: Inline script writes to '{blocked}' in session directory. "
                f"Use the appropriate hacker-bob MCP tool instead."
            )

raise SystemExit(0)
PY
