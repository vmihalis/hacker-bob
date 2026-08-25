#!/bin/bash
# Session read guard hook — PreToolUse on Bash, Read, and Grep
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


# Per-workspace session roots. The installer gives each workspace its OWN
# disjoint session root (BOB_SESSIONS_ROOT, written into the host config and
# frozen at engine boot by mcp/core/io/paths.js) so two workspaces can run engines
# concurrently. This guard must protect the root the engine actually writes to,
# so the configured root is discovered here — from the environment first, then
# from the workspace host config, which is authoritative even if the host does
# not export the variable to hooks.
#
# STRICTLY ADDITIVE: the canonical and legacy default roots below are always
# guarded, so a missing, blank, or bogus override can only ever add protection,
# never remove it.
def _configured_sessions_roots():
    roots = []

    def add(value):
        if not isinstance(value, str):
            return
        value = value.strip()
        if not value.startswith("/") or "\x00" in value:
            return
        candidate = pathlib.Path(value)
        if candidate not in roots:
            roots.append(candidate)

    add(os.environ.get("BOB_SESSIONS_ROOT"))
    project = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    for relative in (".mcp.json", os.path.join(".kimi", "mcp.json")):
        try:
            with open(os.path.join(project, relative), "r", encoding="utf-8") as handle:
                servers = json.load(handle).get("mcpServers")
            if not isinstance(servers, dict):
                continue
            for entry in servers.values():
                if isinstance(entry, dict) and isinstance(entry.get("env"), dict):
                    add(entry["env"].get("BOB_SESSIONS_ROOT"))
        except Exception:
            continue
    return tuple(roots)


# Cycle P.2: guard both the canonical `hacker-bob-sessions` root and the
# legacy `bounty-agent-sessions` root so direct reads remain blocked during
# the v2.0/v2.1 coexistence window.
SESSIONS_ROOTS = _configured_sessions_roots() + (
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
    "diff-impact.json",
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
    "static-analysis-results.jsonl",
    "static-analysis-index.jsonl",
    "static-scan-results.jsonl",
    "pipeline-events.jsonl",
    "report.md",
    "chains.md",
    # Offensive-tool run ledgers + OOB tokens carry secret-shaped material;
    # lab-authorization.json holds the operator's private-target attestation.
    "offensive-runs.jsonl",
    "oob-tokens.jsonl",
    "lab-authorization.json",
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
    # bob_http_massread_confirm's OPT-IN full raw capture (operator-gated). It holds raw PII bodies
    # OUTSIDE the signed (masked) rail, so the agent must NEVER Read it — only the operator does.
    "massread-evidence",
}

# The directory SEGMENTS a Grep `glob` must never target: the blocked sensitive
# dirs plus the session-root basenames. A glob is a PATTERN (not a resolved path
# that check_file could open), so it is screened by literal path segment.
GLOB_PROTECTED_SEGMENTS = set(BLOCKED_DIRS) | {root.name for root in SESSIONS_ROOTS}

BLOCKED_PATTERNS = [
    re.compile(r"^handoff-w[1-9][0-9]*-a[1-9][0-9]*\.(json|md)$"),
    re.compile(r"^wave-[1-9][0-9]*-assignments\.json$"),
    re.compile(r"^live-dead-ends-w[1-9][0-9]*-a[1-9][0-9]*\.jsonl$"),
]

RISKY_PATH_RE = re.compile(r"(?:^|[._/\-])(raw|proof|poc|dump|body|impact proof)(?:[._/\-]|$)", re.I)
PATH_FRAGMENT_RE = re.compile(r"(~|\$\{?SESSION\}?|\$\{?HOME\}?|/)[^\s'\";|&)<>,]*")
READ_COMMANDS = {
    # text/line tools
    "awk", "cat", "grep", "egrep", "fgrep", "head", "jq", "yq", "less", "more",
    "nl", "rg", "ripgrep", "sed", "gsed", "strings", "tail", "tac", "rev", "wc",
    "cut", "paste", "join", "comm", "column", "fold", "fmt", "pr", "expand",
    "unexpand", "tr", "look", "sort", "uniq", "shuf", "split", "csplit", "diff",
    "sdiff", "cmp", "grep",
    # binary/encoding dumpers
    "xxd", "od", "hexdump", "hd", "base64", "base32", "basenc", "uuencode",
    "x016", "dd",
    # editors that can dump a buffer to stdout
    "ex", "vi", "vim", "view", "nvim",
    # decompress-to-stdout
    "zcat", "bzcat", "xzcat", "zcatx", "gunzip", "zless", "zgrep",
    # interpreters (positional file arg reads / executes the file)
    "node", "nodejs", "python", "python2", "python3", "ruby", "perl", "php",
    "deno", "bun",
}
RECURSIVE_READ_COMMANDS = {"grep", "egrep", "fgrep", "rg", "ripgrep", "zgrep"}


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


def search_root_reaches_session(resolved):
    """Return the session-root basename when `resolved` is an ANCESTOR of (or
    equal to) a session root, else None.

    Grep (ripgrep) recurses: a content search rooted here descends DOWN into the
    session tree, so it reaches every blocked dir (massread-evidence raw PII) and
    every BLOCKED_EXACT secret regardless of the `glob`. This is the mirror of
    session_root_for (which detects a root INSIDE a session); together they cover
    the full overlap between a recursive search scope and the session tree."""
    try:
        base = resolved.resolve(strict=False)
    except OSError:
        return None
    for root in SESSIONS_ROOTS:
        try:
            root.resolve(strict=False).relative_to(base)
            return root.name
        except (ValueError, OSError):
            continue
    return None


def extract_cd_targets(command):
    """Directories the command cd's/pushd's into, resolved like other paths.

    A relative read target (`cd <session_dir> && tail ledger`) otherwise
    resolves against the hook process cwd and slips the guard. Collecting cd
    targets lets check_file also resolve relative paths against the shell's
    working directory.
    """
    bases = []
    for match in re.finditer(r"\b(?:cd|pushd)\s+(?:-[A-Za-z]+\s+|--\s+)*([\"']?)([^\"'\s;|&]+)\1", command):
        raw = match.group(2)
        if raw.startswith("-") or raw in {"-", "~-", "&&", "||"}:
            continue
        bases.append(resolve_path(raw))
    return bases


def check_file(raw_path, *, block_session_dirs=False, base_dirs=None):
    resolved = resolve_path(raw_path)
    candidates = [resolved]
    if not resolved.is_absolute() and base_dirs:
        for base in base_dirs:
            candidates.append(base / resolved)

    for candidate in candidates:
        root = session_root_for(candidate)
        if root is None:
            continue

        try:
            session_relative_parts = candidate.resolve(strict=False).relative_to(
                root.resolve(strict=False)
            ).parts
        except (ValueError, OSError):
            session_relative_parts = ()

        if block_session_dirs and len(session_relative_parts) <= 1:
            return candidate.name or "session directory"

        filename = candidate.name
        # A blocked sensitive dir DOMINATES the basename allowlist: a raw-PII file inside
        # massread-evidence/ (or any blocked dir) whose basename happens to match ALLOWED_EXACT
        # must STILL be blocked, so this check runs BEFORE ALLOWED_EXACT (bot-review #202). It
        # checks BLOCKED_DIRS against the union of the literal `candidate.parts` AND the
        # SYMLINK-RESOLVED, session-relative parts: a symlink alias outside the session
        # (`/tmp/e -> <session>/massread-evidence`) has a literal path with no blocked component,
        # but its resolved target is inside a blocked dir, so the raw parts alone let
        # `Read /tmp/e/<run>.json` bypass the raw-PII block (bot-review #101).
        if any(part in BLOCKED_DIRS for part in (*candidate.parts, *session_relative_parts)):
            return filename
        if filename in ALLOWED_EXACT:
            return None
        if filename in BLOCKED_EXACT:
            return filename
        if any(pattern.match(filename) for pattern in BLOCKED_PATTERNS):
            return filename
        # RISKY_PATH_RE is applied to the BASENAME only, not the full path: a
        # directory the agent happened to name (e.g. proof-of-concept/) must not
        # make an entire subtree of otherwise-allowed scratch files unreadable.
        if RISKY_PATH_RE.search(filename):
            return filename
        return None

    return None


def check_glob(glob_text):
    """Screen a Grep `glob` PATTERN (never a resolved, openable path) for an
    EXPLICIT protected segment. Split the glob into literal path segments and
    block only when a segment EXACTLY equals a protected dir name or a
    session-root basename (e.g. an `.../massread-evidence/**` or
    `hacker-bob-sessions/**` glob).

    Reachability of the session tree is enforced by the search-root checks
    (search_root_reaches_session for an ANCESTOR root, block_session_dirs for a
    root INSIDE a session); ripgrep never reads a file outside its search root,
    so a glob cannot widen the scope. This screen therefore does NOT fnmatch the
    protected NAMES against a wildcard segment — a benign developer `repo-*`
    (which coincidentally matches `repo-runs`) or `*evidence*` (which matches
    `massread-evidence`) targets no session dir and must pass."""
    expanded = str(resolve_path(glob_text))
    segments = [seg for seg in re.split(r"/+", expanded) if seg and seg not in (".", "..")]
    for seg in segments:
        if seg in GLOB_PROTECTED_SEGMENTS:
            return seg
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


# --- Command-aware analysis core (shared shape with session-write-guard.sh) ---
# A shell command is partitioned into (i) a SKELETON — the command with every
# heredoc BODY removed — tokenized by shlex and scanned for shell-level READ
# commands (cat/grep/xxd/python3 file-arg), stdin '<' input redirects, and
# command substitutions, and (ii) PAYLOADS — heredoc bodies and inline -c/-e
# code strings — scanned for genuine read CALLS only when their consumer is a
# real interpreter (shell -c is recursed as shell; os.system/subprocess shell
# strings are recursed too). A blocked basename that appears only as DATA inside
# a heredoc/-c string (never opened/read) no longer trips a block, while genuine
# interpreter reads (open('p').read(), readFileSync('p'), …) still do.
#
# DEFENSE-IN-DEPTH BOUNDARY: this is a signature/allowlist filter over a shell
# string, not a sandbox. A determined agent can still read a protected file via
# runtime indirection the guard cannot statically resolve — a path supplied
# through `xargs`/a shell variable, a subprocess invoked with a list argv, or a
# custom/compiled binary. The guard's role is to keep cooperative agents on the
# MCP readers and stop inadvertent bulk reads; the MCP readers remain the
# supported path for session artifacts.
HEREDOC_RE = re.compile(r"<<-?\s*([\"']?)([A-Za-z_][A-Za-z0-9_]*)\1")
SHELL_INTERPRETERS = {"bash", "sh", "zsh", "dash", "ksh", "ash"}
SCRIPT_INTERPRETERS = {
    "python", "python2", "python3", "node", "nodejs", "ruby", "perl", "php",
    "deno", "bun",
}
INTERPRETERS = SHELL_INTERPRETERS | SCRIPT_INTERPRETERS
HEREDOC_WRAPPERS = {
    "env", "sudo", "doas", "nice", "nohup", "stdbuf", "time", "command", "exec",
    "xargs", "then", "do", "else",
}
PIPE_SEPS = {"|", "||", "&&", ";", "&", "|&"}
INLINE_CODE_FLAGS = {"-c", "-e", "--eval", "--exec", "--command"}
SEPARATORS = {"|", ";", "&&", "||"}

# A read is an open() in a non-write mode, a pathlib read, a Node fs read, or a
# Ruby File/IO read — keyed on the CALL, not bare path presence. (os.open is
# caught by _OPEN_CALL_RE's substring match on `open(`.)
_OPEN_CALL_RE = re.compile(r"""open\s*\(\s*["']([^"']+)["']\s*(?:,\s*["']([^"']*)["'])?""")
READ_OP_RES = [
    re.compile(r"""Path\s*\(\s*["']([^"']+)["']\s*\)\s*\.\s*(?:read_text|read_bytes)\b"""),
    re.compile(r"""(?:readFileSync|readFile|createReadStream)\s*\(\s*["']([^"']+)["']"""),
    re.compile(r"""(?:File|IO)\.(?:read|readlines|foreach)\s*\(?\s*["']([^"']+)["']"""),
]

# Interpreter source that delegates a command back to the shell — recurse it.
SUBPROCESS_SHELL_RE = re.compile(
    r"""(?:os\.system|os\.popen|subprocess\.(?:run|call|check_call|check_output|Popen|getoutput|getstatusoutput))\s*\(\s*["']([^"']+)["']"""
)
MAX_DEPTH = 6


def iter_command_substitutions(text):
    """Yield shell-code fragments that execute at runtime: $(...) and `...`."""
    i = 0
    n = len(text)
    while i < n - 1:
        if text[i] == "$" and text[i + 1] == "(":
            depth = 1
            j = i + 2
            while j < n and depth:
                if text[j] == "(":
                    depth += 1
                elif text[j] == ")":
                    depth -= 1
                j += 1
            if depth == 0:
                yield text[i + 2 : j - 1]
            i = j
        else:
            i += 1
    for match in re.finditer(r"`([^`]+)`", text):
        yield match.group(1)


def extract_input_redirects(command):
    """Paths fed to a command's stdin via a '<' input redirect (so the file is
    read regardless of whether the consuming command is in READ_COMMANDS, e.g.
    `base64 < file`, `tr a-z A-Z < file`, `read -r X < file`)."""
    targets = []
    for match in re.finditer(r"(?<!<)<(?!<)\s*\"([^\"\n]+)\"", command):
        targets.append(match.group(1))
    for match in re.finditer(r"(?<!<)<(?!<)\s*'([^'\n]+)'", command):
        targets.append(match.group(1))
    for match in re.finditer(r"(?<!<)<(?!<)\s*([^\"'\s|;&)<>\n]+)", command):
        target = match.group(1)
        if target.startswith("(") or target.startswith("&"):
            continue
        targets.append(target)
    return [t for t in targets if "$(" not in t and "`" not in t]


def consumer_for_opener_line(prefix):
    """Best-effort: the command word that consumes a heredoc opened on this line.
    Returns None when it cannot be determined (the SAFE direction)."""
    try:
        toks = shlex.split(prefix, posix=True)
    except ValueError:
        toks = prefix.split()
    seg = []
    for tok in toks:
        if tok in PIPE_SEPS:
            seg = []
        else:
            seg.append(tok)
    for word in seg:
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", word):
            continue
        base = pathlib.PurePosixPath(word).name
        if base in HEREDOC_WRAPPERS:
            continue
        return base
    return None


def partition_command(command):
    """Return (skeleton_text, payloads): skeleton_text drops every heredoc body
    + terminator line; payloads is a list of (consumer_basename, body_text,
    expands) where `expands` is True when the heredoc delimiter was UNQUOTED
    (so command substitutions in the body execute at runtime)."""
    lines = command.split("\n")
    out = []
    payloads = []
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)  # keep the command / heredoc-opener line itself
        matches = list(HEREDOC_RE.finditer(line))
        i += 1
        if not matches:
            continue
        consumer = consumer_for_opener_line(line[: matches[0].start()])
        expands = matches[0].group(1) == ""  # unquoted delimiter -> body expands
        pending = [m.group(2) for m in matches]
        body = []
        while pending and i < len(lines):
            if lines[i].strip() == pending[0]:
                pending.pop(0)
            else:
                body.append(lines[i])
            i += 1  # drop body + terminator lines from the skeleton
        payloads.append((consumer, "\n".join(body), expands))
    return "\n".join(out), payloads


def payload_family(consumer):
    if consumer in SHELL_INTERPRETERS:
        return "shell"
    if consumer in SCRIPT_INTERPRETERS:
        return "script"
    return None


def inline_code_token_indices(tokens, interpreters):
    """Indices of tokens that are inline CODE strings passed via -c/-e to a
    command whose basename is in `interpreters`."""
    indices = set()
    active = False
    for i, tok in enumerate(tokens):
        if tok in PIPE_SEPS:
            active = False
            continue
        base = pathlib.PurePosixPath(tok).name
        if base in interpreters:
            active = True
            continue
        if base in INTERPRETERS:
            active = False  # a different-family interpreter resets the context
            continue
        if active and tok in INLINE_CODE_FLAGS and i + 1 < len(tokens):
            indices.add(i + 1)
    return indices


def scan_read_ops(code, depth, base_dirs=None):
    """Block when interpreter source performs a genuine read of a session file,
    and recurse any shell command the source hands back to os.system/subprocess."""
    for match in _OPEN_CALL_RE.finditer(code):
        mode = match.group(2)
        if mode is not None and any(c in mode for c in "wax+"):
            continue  # write/append mode -> not a read
        blocked = check_file(match.group(1), base_dirs=base_dirs)
        if blocked:
            block(blocked)
    for rx in READ_OP_RES:
        for match in rx.finditer(code):
            blocked = check_file(match.group(1), base_dirs=base_dirs)
            if blocked:
                block(blocked)
    for match in SUBPROCESS_SHELL_RE.finditer(code):
        analyze_shell_read(match.group(1), depth + 1)


def analyze_shell_read(text, depth=0):
    """Recursively block direct shell/interpreter reads of blocked session files."""
    if depth > MAX_DEPTH:
        return
    skeleton, payloads = partition_command(text)
    try:
        tokens = shlex.split(skeleton, posix=True)
    except ValueError:
        # The skeleton has no heredoc body, so a parse failure is a genuinely
        # malformed shell skeleton (e.g. an unterminated quote). Fail closed.
        print(
            "BLOCKED: Command cannot be safely parsed. "
            "Refusing to allow potentially unsafe shell operation.",
            file=sys.stderr,
        )
        raise SystemExit(2)

    script_code = inline_code_token_indices(tokens, SCRIPT_INTERPRETERS)
    shell_code = inline_code_token_indices(tokens, SHELL_INTERPRETERS)
    masked = script_code | shell_code

    # cd/pushd targets in this command's skeleton: a relative read target is
    # also resolved against them so `cd <session_dir> && tail ledger` cannot
    # escape the session-dir check.
    base_dirs = extract_cd_targets(skeleton)

    # stdin '<' input redirects read the file regardless of the command word.
    redirect_text = skeleton
    for index in masked:
        redirect_text = redirect_text.replace(tokens[index], " ")
    for target in extract_input_redirects(redirect_text):
        blocked = check_file(target, base_dirs=base_dirs)
        if blocked:
            block(blocked)

    # Shell-level READ commands with a blocked path argument.
    for index, token in enumerate(tokens):
        if index in masked:
            continue
        command_name = pathlib.PurePosixPath(token).name
        if command_name not in READ_COMMANDS:
            continue
        block_session_dirs = command_name in RECURSIVE_READ_COMMANDS
        for offset, candidate in enumerate(tokens[index + 1:], start=index + 1):
            if candidate in {"|", ";", "&&", "||"}:
                break
            if offset in masked:
                continue  # interpreter -c/-e source, scanned separately
            for path_candidate in candidate_paths(candidate):
                blocked = check_file(path_candidate, block_session_dirs=block_session_dirs, base_dirs=base_dirs)
                if blocked:
                    block(blocked)

    # Command substitutions in the (code-redacted) skeleton execute as shell.
    for fragment in iter_command_substitutions(redirect_text):
        analyze_shell_read(fragment, depth + 1)

    # Inline -c/-e source: script code scanned for read calls; shell code
    # recursed as shell.
    for index in script_code:
        scan_read_ops(tokens[index], depth, base_dirs)
    for index in shell_code:
        analyze_shell_read(tokens[index], depth + 1)

    # Heredoc bodies, scanned by consumer family.
    for consumer, body, expands in payloads:
        family = payload_family(consumer)
        if family == "shell":
            analyze_shell_read(body, depth + 1)
        elif family == "script":
            scan_read_ops(body, depth, base_dirs)
        elif expands:
            # Data consumer, but an unquoted heredoc body still runs $(...).
            for fragment in iter_command_substitutions(body):
                analyze_shell_read(fragment, depth + 1)


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

# Grep tool: guard its FULL effective search scope, fail-closed. A Grep call sets no
# file_path/command, so a pattern/glob/path key marks it. Grep (ripgrep) recurses from a
# single search root, so the scope overlaps the session tree in THREE ways, ALL screened:
# (1) the search root is INSIDE/equal-to a session dir (explicit `path`, or NO `path` so
# the root is the process cwd) — check_file(block_session_dirs); (2) the search root is an
# ANCESTOR of a session root (e.g. a broad `$HOME` root), so the recursion descends INTO
# the session tree — search_root_reaches_session; (3) a `glob` that literally names a
# protected segment — check_glob. A content search over a blocked dir (massread-evidence/
# raw-PII captures) exfiltrates the same data a Read would, so block if ANY overlap holds.
if any(key in tool_input for key in ("pattern", "glob", "path")):
    grep_path = tool_input.get("path")
    if isinstance(grep_path, str) and grep_path:
        search_root = grep_path
    else:
        # `path` ABSENT -> the search root is the process cwd.
        search_root = os.getcwd()
    # (1) root inside/equal-to a session dir, or naming a blocked artifact directly.
    blocked = check_file(search_root, block_session_dirs=True)
    if blocked:
        block(blocked)
    # (2) root is an ANCESTOR of a session root: a recursive Grep descends INTO the
    # session tree (massread-evidence raw PII + every BLOCKED_EXACT secret) no matter
    # what `glob` is set, so fail closed regardless of the glob. Closes the
    # broad-ancestor-root fail-open (a `$HOME` root + a generic/absent glob).
    reached = search_root_reaches_session(resolve_path(search_root))
    if reached:
        block(reached)
    # (3) A glob is a PATTERN, not a resolved path: screen it for an EXPLICIT protected
    # segment. Reachability is already enforced by (1)/(2) above (ripgrep never reads
    # outside its root), so this only rejects a glob that literally names a session dir.
    grep_glob = tool_input.get("glob")
    if isinstance(grep_glob, str) and grep_glob:
        blocked = check_glob(grep_glob)
        if blocked:
            block(blocked)
    raise SystemExit(0)

command = tool_input.get("command", "")
if command:
    analyze_shell_read(command)

raise SystemExit(0)
PY
