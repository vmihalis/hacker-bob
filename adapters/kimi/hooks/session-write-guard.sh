#!/bin/bash
# Session write guard hook — PreToolUse on Bash and Write
# Blocks direct writes to MCP-owned files in ~/bounty-agent-sessions/
# Forces agents to use MCP tools for structured output
# Exit 0 = allow, Exit 2 = block

INPUT=$(cat)
export WRITE_GUARD_INPUT="$INPUT"

python3 - <<'PY'
import json
import os
import pathlib
import re
import shlex
import sys


SESSIONS_ROOT = pathlib.Path.home() / "bounty-agent-sessions"

# Files that MUST be written through MCP tools only
MCP_OWNED_EXACT = {
    "state.json",
    "coverage.jsonl",
    "technique-attempts.jsonl",
    "technique-pack-reads.jsonl",
    "chain-attempts.jsonl",
    "findings.jsonl",
    "findings.md",
    "claims.jsonl",
    "claim-freeze.json",
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
    "auth.json",
    "http-audit.jsonl",
    "traffic.jsonl",
    "public-intel.json",
    "surface-routes.json",
    "static-artifacts.jsonl",
    "static-scan-results.jsonl",
    "pipeline-events.jsonl",
}

MCP_OWNED_DIRS = {
    "static-imports",
}

MCP_OWNED_PATTERNS = [
    re.compile(r"^handoff-w\d+-a\d+\.(json|md)$"),
    re.compile(r"^wave-\d+-assignments\.json$"),
    re.compile(r"^live-dead-ends-w\d+-a\d+\.jsonl$"),
]

# Files that agents are allowed to write directly. JSON entries here are
# compact recon/report artifacts; bulky raw captures remain blocked by name on
# the read side and should not be written as ad hoc session files.
AGENT_ALLOWED_EXACT = {
    "chains.md",
    "report.md",
    "attack_surface.json",
    "deep-summary.json",
    "recon-summary.json",
    "scope-warnings.log",
    "deny-list.txt",
}

AGENT_ALLOWED_PATTERNS = [
    re.compile(r"^.*\.txt$"),
]


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


def is_in_session_dir(resolved):
    try:
        resolved.resolve(strict=False).relative_to(SESSIONS_ROOT.resolve(strict=False))
        return True
    except (ValueError, OSError):
        return False


def extract_cd_targets(command):
    """Directories the command cd's/pushd's into, resolved like other paths, so a
    `cd <session_dir> && <relative write>` cannot slip the guard. Mirrors the main
    .claude/hooks guard (issue #111: also needed for the new Node fs write patterns)."""
    bases = []
    for match in re.finditer(r"\b(?:cd|pushd)\s+(?:-[A-Za-z]+\s+|--\s+)*([\"']?)([^\"'\s;|&]+)\1", command):
        raw = match.group(2)
        if raw.startswith("-") or raw in {"-", "~-", "&&", "||"}:
            continue
        bases.append(resolve_path(raw))
    return bases


def check_file(raw_path, base_dirs=None):
    """Returns filename to block, or None to allow.

    When base_dirs (cd targets) are supplied, a relative path is also resolved
    against each of them so a `cd <session_dir>`-then-relative-write cannot escape
    the session-dir check."""
    resolved = resolve_path(raw_path)

    candidates = [resolved]
    if not resolved.is_absolute() and base_dirs:
        for base in base_dirs:
            candidates.append(base / resolved)

    for candidate in candidates:
        if not is_in_session_dir(candidate):
            continue

        filename = candidate.name

        if any(part in MCP_OWNED_DIRS for part in candidate.parts):
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

    # node fs writes: (fs.)writeFile/writeFileSync/appendFile/appendFileSync("/path",...)
    # and createWriteStream("/path"). Defense-in-depth (issue #111 sibling) against the
    # easy Node forge vector. Like the Python patterns it extracts only string-LITERAL
    # paths and does NOT close arbitrary in-process code execution (variable/template
    # path, openSync+writeSync, bracket access, child_process) — only sandbox/UID
    # isolation closes that. Mirrors .claude/hooks/session-write-guard.sh.
    for match in re.finditer(r"""(?:write|append)File(?:Sync)?\s*\(\s*["']([^"']+)["']""", command):
        targets.append(match.group(1))
    for match in re.finditer(r"""createWriteStream\s*\(\s*["']([^"']+)["']""", command):
        targets.append(match.group(1))

    return targets


def check_mutating_path_commands(command):
    """Block direct shell mutations of MCP-owned session files."""
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return

    base_dirs = extract_cd_targets(command)
    mutators = {"rm", "unlink", "mv", "cp", "chmod", "chown", "install"}
    separators = {"|", ";", "&&", "||"}

    def block_mutator(verb, path):
        blocked = check_file(path, base_dirs)
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

# Quick gate: skip the redirect/inline-script extractors if there are no
# matching write indicators (direct-write verbs are already handled above).
# Match the extractor's trigger condition: a `>`/`>>` (no-space form like `>file`
# included — Codex P1) followed by a capturable target, but NOT an fd-dup like
# `2>&1`. The earlier `>{1,2}\s` required a space and let `>claims.jsonl` slip the
# gate entirely for every MCP-owned file. Mirrors .claude/hooks.
has_redirects = re.search(r">{1,2}\s*[\"']?[^\"'\s|;&)\n]|tee\s", command)
has_open_call = re.search(r"open\s*\(|Path\s*\(", command)
# node fs write idioms (issue #111 sibling): a pure fs.appendFileSync(...) has no
# open(/Path( token, so without this it would slip the gate entirely.
has_node_write = re.search(r"(?:write|append)File(?:Sync)?\s*\(|createWriteStream\s*\(", command)

if not has_redirects and not has_open_call and not has_node_write:
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

# Extract and check inline script file writes (open(), Path().write_text(),
# node fs.writeFileSync/appendFileSync/createWriteStream, etc.)
if has_open_call or has_node_write:
    for target in extract_inline_script_paths(command):
        blocked = check_file(target, cd_targets)
        if blocked:
            block(
                f"BLOCKED: Inline script writes to '{blocked}' in session directory. "
                f"Use the appropriate hacker-bob MCP tool instead."
            )

raise SystemExit(0)
PY
