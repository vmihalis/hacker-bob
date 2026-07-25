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


# Per-workspace session roots. The installer gives each workspace its OWN
# disjoint session root (BOB_SESSIONS_ROOT, written into the host config and
# frozen at engine boot by mcp/lib/paths.js) so two workspaces can run engines
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


# Cycle P.2: guard both canonical and legacy session roots so MCP-owned
# files stay protected across the v2.0/v2.1 coexistence window.
SESSIONS_ROOTS = _configured_sessions_roots() + (
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
    # BLOCK set = audit-graded ∪ mcp-owned (both are write-via-MCP-only). A
    # structurally-incomplete manifest (valid JSON but a missing/wrong-typed key)
    # raises KeyError/TypeError here and must FAIL CLOSED, not crash open.
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
        "BLOCKED: write-guard tables missing/unreadable "
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

    A relative redirect/script target otherwise resolves against the hook
    process cwd, so `cd <session_dir> && echo ... >> ledger` slips past the
    guard because the bare `ledger` is judged outside any session dir.
    Collecting cd targets lets check_file also resolve relative paths against
    the shell's working directory, closing that bypass for every MCP-owned file.
    """
    bases = []
    # Consume any cd flags (`-L`/`-P`) and the `--` option terminator before the
    # directory token (`cd -- <dir>` must not slip the guard). Then drop `cd -`
    # (previous-dir) cases.
    for match in re.finditer(r"\b(?:cd|pushd)\s+(?:-[A-Za-z]+\s+|--\s+)*([\"']?)([^\"'\s;|&]+)\1", command):
        raw = match.group(2)
        if raw.startswith("-") or raw in {"-", "~-", "&&", "||"}:
            continue
        bases.append(resolve_path(raw))
    return bases


def _session_root_config_paths():
    """The host-config files _configured_sessions_roots() reads the session root
    from. They decide WHICH roots this guard fences, so they are themselves
    write-fenced: an agent that could rewrite them could drop the configured
    root and un-fence the engine's real session directory (the default root
    would still be guarded, so the loss of coverage would be silent). The
    installer, doctor, and dev-sync edit these outside the agent tool path and
    are unaffected."""
    explicit = os.environ.get("CLAUDE_PROJECT_DIR")
    if explicit:
        project = pathlib.Path(explicit)
    else:
        # Not every host exports a project dir. Falling back to the bare cwd would shift the
        # fence whenever the tool call runs from a subdirectory, silently leaving the REAL
        # host config unfenced, so walk UP to the nearest ancestor that looks like the
        # workspace instead.
        here = pathlib.Path(os.getcwd()).resolve()
        project = here
        for candidate in [here, *here.parents]:
            if ((candidate / ".mcp.json").exists()
                    or (candidate / ".claude").is_dir()
                    or (candidate / ".kimi").is_dir()):
                project = candidate
                break
    resolved = []
    for relative in (".mcp.json", os.path.join(".kimi", "mcp.json")):
        try:
            resolved.append((project / relative).resolve(strict=False))
        except OSError:
            continue
    return tuple(resolved)


SESSION_ROOT_CONFIG_PATHS = _session_root_config_paths()


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
        # Fenced regardless of session root: these carry the root the guard
        # protects (see _session_root_config_paths).
        try:
            if candidate.resolve(strict=False) in SESSION_ROOT_CONFIG_PATHS:
                return candidate.name
        except OSError:
            pass

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

    # QUOTED targets first: capture the FULL quoted string so a dynamic name
    # like "$SESSION/$(date +%F).txt" keeps its .txt extension (and classifies
    # as agent-writable) instead of being truncated at the first space.
    for match in re.finditer(r"(?<!<)>{1,2}\s*\"([^\"\n]+)\"", command):
        targets.append(match.group(1))
    for match in re.finditer(r"(?<!<)>{1,2}\s*'([^'\n]+)'", command):
        targets.append(match.group(1))
    # Unquoted > / >> redirects (skip heredocs like <<EOF and <<'EOF').
    for match in re.finditer(r"(?<!<)>{1,2}\s*([^\"'\s|;&)<\n]+)", command):
        target = match.group(1)
        # Skip process substitution and fd redirects
        if target.startswith("(") or target.startswith("&") or target == "/dev/null":
            continue
        targets.append(target)

    # Match tee targets: tee [-a] filepath (quoted or bare)
    for match in re.finditer(r"\btee\s+(?:-[ai]+\s+)*\"([^\"\n]+)\"", command):
        targets.append(match.group(1))
    for match in re.finditer(r"\btee\s+(?:-[ai]+\s+)*'([^'\n]+)'", command):
        targets.append(match.group(1))
    for match in re.finditer(r"\btee\s+(?:-[a]\s+)?([^\"'\s|;&)\n]+)", command):
        target = match.group(1)
        if not target.startswith("-"):
            targets.append(target)

    # Drop targets containing an unresolved command substitution ($(...) / `...`):
    # the basename is runtime-dynamic and cannot be proven MCP-owned, and a
    # captured fragment like "$(date" would false-positive on legit timestamped
    # scratch. (A determined agent could hide a write behind a substitution —
    # that is the documented defense-in-depth boundary; MCP-side Y-P13 ledgers
    # are the authoritative integrity guarantee.)
    return [t for t in targets if "$(" not in t and "`" not in t]


# --- Command-aware analysis core (shared shape with session-read-guard.sh) ---
# A shell command is partitioned into (i) a SKELETON — the command with every
# heredoc BODY removed — which is the only text tokenized by shlex and scanned
# for shell-level structure (mutators, redirects, command substitutions), and
# (ii) PAYLOADS — heredoc bodies and inline -c/-e code strings — scanned for
# genuine file I/O ONLY when their consuming command is a real interpreter. A
# heredoc body fed to a DATA consumer (cat/echo/tee) is inert (except for any
# command substitution in an UNQUOTED heredoc, which executes); a body fed to a
# SHELL interpreter (bash/sh) is recursively re-analyzed as shell code; a body
# fed to a SCRIPT interpreter (python/node/…) is scanned for write-call
# signatures (and any os.system/subprocess shell string it delegates to is
# recursed). This kills false positives on blocked basenames that appear only
# as DATA while still catching real writes performed by interpreter code, and
# closes the heredoc bodies (e.g. the discovery scripts' r'...[^\\s"\\'<>]...')
# whose mixed quotes used to break shlex and trip the fail-closed block.
#
# DEFENSE-IN-DEPTH BOUNDARY: this guard is a signature/allowlist filter over a
# shell-command string. It catches inadvertent and naive direct writes and keeps
# cooperative agents on the MCP rails; it is NOT a sandbox. A determined agent
# can still write a protected file via runtime indirection the guard cannot
# statically resolve — e.g. a path supplied through `xargs`/a shell variable, a
# subprocess invoked with a list argv, or a custom/compiled binary. The
# AUTHORITATIVE integrity guarantee for audit-graded artifacts is MCP-side
# (Y-P13 hash-bound ledgers): clobbering report.md on disk does not forge the
# ledger.
HEREDOC_RE = re.compile(r"<<-?\s*([\"']?)([A-Za-z_][A-Za-z0-9_]*)\1")
SHELL_INTERPRETERS = {"bash", "sh", "zsh", "dash", "ksh", "ash"}
SCRIPT_INTERPRETERS = {
    "python", "python2", "python3", "node", "nodejs", "ruby", "perl", "php",
    "deno", "bun",
}
INTERPRETERS = SHELL_INTERPRETERS | SCRIPT_INTERPRETERS
# Words that may precede the real consumer command on a heredoc opener line.
HEREDOC_WRAPPERS = {
    "env", "sudo", "doas", "nice", "nohup", "stdbuf", "time", "command", "exec",
    "xargs", "then", "do", "else",
}
PIPE_SEPS = {"|", "||", "&&", ";", "&", "|&"}
INLINE_CODE_FLAGS = {"-c", "-e", "--eval", "--exec", "--command"}
SEPARATORS = {"|", ";", "&&", "||"}

# Plain shell mutators: file-clobbering verbs whose target(s) appear as path
# arguments. dd (of=), in-place editors (sed/perl/ruby -i), and truncate carry
# their target differently and are handled specially in scan_mutating_tokens.
MUTATORS = {"rm", "unlink", "mv", "cp", "chmod", "chown", "install", "ln", "link"}
INPLACE_EDITORS = {"sed", "gsed", "perl", "ruby"}

# A write is keyed on the CALL, not on bare path presence (so a blocked basename
# appearing only as data, or a read-mode open, never trips a block).
WRITE_OP_RES = [
    re.compile(r"""open\s*\(\s*["']([^"']+)["']\s*,\s*["'][^"']*[wax+][^"']*["']"""),
    re.compile(r"""Path\s*\(\s*["']([^"']+)["']\s*\)\s*\.\s*(?:write_text|write_bytes|open)\b"""),
    re.compile(r"""(?:writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream)\s*\(\s*["']([^"']+)["']"""),
    re.compile(r"""os\.open\s*\(\s*["']([^"']+)["'][^)]*O_(?:WRONLY|RDWR|CREAT|APPEND|TRUNC)"""),
    re.compile(r"""(?:os\.replace|os\.rename|shutil\.(?:copy|copy2|copyfile|move))\s*\(\s*["'][^"']*["']\s*,\s*["']([^"']+)["']"""),
    re.compile(r"""File\.(?:write|open)\s*\(\s*["']([^"']+)["']"""),
    re.compile(r"""open\s*\([^,]*,\s*["'][>+]{1,2}["']\s*,\s*["']([^"']+)["']"""),
]

# Interpreter source that delegates a command back to the shell — the string
# argument is shell code and is recursed as such.
SUBPROCESS_SHELL_RE = re.compile(
    r"""(?:os\.system|os\.popen|subprocess\.(?:run|call|check_call|check_output|Popen|getoutput|getstatusoutput))\s*\(\s*["']([^"']+)["']"""
)
MAX_DEPTH = 6

# pathlib variable-join write form: (BASE / "name"[ / "name2"]).write_text/write_bytes/open.
# The join BASE operand is a runtime expression the guard cannot fully resolve, but
# the THREAT is an agent writing an MCP-owned basename to the SESSION dir. So a join
# is only resolved-under-the-session (and blocked on an MCP-owned basename) when its
# BASE is plausibly the session dir — the shipped idiom's leftmost operand is a var
# named `session` (or a base assigned from the session env / SESSIONS_ROOT). When the
# BASE is a LITERAL path (Path('/tmp'), Path('reports'), a string) or any non-session
# expression, the REAL path is resolved (base + name) so session_relative() returns
# None and the write ALLOWs. Group 1 captures the BASE expression; the last group
# captures the joined NAME. The verb anchor excludes read_text/read_bytes so the
# read-side join idiom is not falsely tripped.
JOIN_WRITE_RE = re.compile(
    r'''\(\s*([^()"']*?)/\s*["']([^"']+)["']\s*\)\s*\.\s*(?:write_text|write_bytes|open)\b''')
# assigned-then-write: `var = BASE / "name"` then a later var.write_text/write_bytes/open.
# Group 1 = assigned var, group 2 = BASE expression, group 3 = joined NAME.
JOIN_ASSIGN_RE = re.compile(
    r'''^\s*([A-Za-z_]\w*)\s*=\s*([^=\n].*?)/\s*["']([^"']+)["']\s*$''', re.M)

# Identifier heads (lowercased) that name a session directory in the shipped idioms.
SESSION_BASE_NAMES = {
    "session", "session_dir", "session_path", "sess",
    "sessions_root", "session_root",
}
# Textual session references that can appear inside a base expression / its RHS.
_SESSION_TOKEN_RE = re.compile(
    r'''\bSESSIONS?_ROOT\b|\bSESSION\b|environ|\$\{?SESSION''')


def _base_is_session(base_expr, code):
    """True when a join's BASE operand is plausibly the session directory.

    Conservative classification keyed on the THREAT (an MCP-owned basename written
    to the session dir): the base names a session var / references the session env
    or SESSIONS_ROOT, or is a var traced (one level) to such a RHS. Anything else
    (literal Path('/tmp'), Path('reports'), an opaque alias) is NOT session-derived.
    """
    b = base_expr.strip()
    if _SESSION_TOKEN_RE.search(b):
        return True
    m = re.match(r"\s*([A-Za-z_]\w*)", b)
    if not m:
        return False
    if m.group(1).lower() in SESSION_BASE_NAMES:
        return True
    # Trace one level: a base var assigned from a session-derived RHS.
    for am in re.finditer(r"^\s*" + re.escape(m.group(1)) + r"\s*=\s*([^\n]+)$", code, re.M):
        rhs = am.group(1)
        if _SESSION_TOKEN_RE.search(rhs):
            return True
        hm = re.match(r"\s*([A-Za-z_]\w*)", rhs)
        if hm and hm.group(1).lower() in SESSION_BASE_NAMES:
            return True
    return False


def _base_literal(base_expr, code):
    """Best-effort literal path string for a NON-session base, so the join resolves
    to its REAL location. Extracts the string from Path('lit')/'lit' in the base
    expression, tracing one assignment level for a bare var. Returns None when no
    literal is recoverable (then the relative name resolves against cwd — outside any
    session root — and ALLOWs)."""
    def _lit(expr):
        m = re.search(r"""(?:Path\s*\(\s*)?["']([^"']+)["']""", expr)
        return m.group(1) if m else None
    direct = _lit(base_expr)
    if direct is not None:
        return direct
    m = re.match(r"\s*([A-Za-z_]\w*)\s*$", base_expr.strip())
    if m:
        for am in re.finditer(r"^\s*" + re.escape(m.group(1)) + r"\s*=\s*([^\n]+)$", code, re.M):
            lit = _lit(am.group(1))
            if lit is not None:
                return lit
    return None


def _pathish(token):
    return (
        token.startswith("/")
        or token.startswith("~")
        or token.startswith("$")
        or "/" in token
        or token.endswith((".json", ".jsonl", ".md", ".txt", ".log", ".har", ".csv", ".html", ".js"))
    )


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


def consumer_for_opener_line(prefix):
    """Best-effort: the command word that consumes a heredoc opened on this line.
    Returns None when it cannot be determined (the SAFE direction — a None
    consumer scans its body for nothing)."""
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
            continue  # FOO=bar assignment
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


def scan_mutating_tokens(tokens, masked, base_dirs=None):
    """Block plain mutators, in-place editors (sed/perl/ruby -i), dd (of=), and
    truncate when their target is an MCP-owned session file."""
    for index, token in enumerate(tokens):
        if index in masked:
            continue
        name = pathlib.PurePosixPath(token).name
        args = []
        for candidate in tokens[index + 1:]:
            if candidate in SEPARATORS:
                break
            args.append(candidate)
        targets = []
        if name == "dd":
            targets = [a[3:] for a in args if a.startswith("of=")]
        elif name in INPLACE_EDITORS:
            if not any(a == "-i" or a.startswith("-i") or a == "--in-place" or a.startswith("--in-place") for a in args):
                continue
            targets = [a for a in args if not a.startswith("-") and _pathish(a)]
        elif name == "truncate":
            skip_value = False
            for a in args:
                if skip_value:
                    skip_value = False
                    continue
                if a in ("-s", "--size", "-r", "--reference"):
                    skip_value = True
                    continue
                if not a.startswith("-") and _pathish(a):
                    targets.append(a)
        elif name in MUTATORS:
            targets = [a for a in args if not a.startswith("-")]
        else:
            continue
        for target in targets:
            blocked = check_file(target, base_dirs)
            if blocked:
                block(
                    f"BLOCKED: Bash {name} on '{blocked}' in session directory. "
                    f"Use the appropriate hacker-bob MCP tool instead."
                )


def scan_write_ops(code, depth, base_dirs=None):
    """Block when interpreter source performs a genuine write to a session file,
    and recurse any shell command the source hands back to os.system/subprocess."""
    for rx in WRITE_OP_RES:
        for match in rx.finditer(code):
            blocked = check_file(match.group(1), base_dirs)
            if blocked:
                block(
                    f"BLOCKED: Inline script writes to '{blocked}' in session directory. "
                    f"Use the appropriate hacker-bob MCP tool instead."
                )
    # pathlib variable-join writes: `(BASE / "name").write_text(...)` and the
    # assigned-then-write `p = BASE / "name"; p.write_text(...)`. The base operand
    # is classified: a SESSION-derived base resolves the joined name under the
    # session and is fed to the UNCHANGED check_file (agent-writable basenames still
    # ALLOW; MCP-owned basenames BLOCK — this preserves the leak fix). A LITERAL /
    # non-session base resolves to its REAL location, so session_relative() returns
    # None and the write ALLOWs (no false positive on a basename collision off-session).
    join_targets = []  # (base_expr, name)
    for m in JOIN_WRITE_RE.finditer(code):
        join_targets.append((m.group(1), m.group(2)))
    for m in JOIN_ASSIGN_RE.finditer(code):
        var, base_expr, name = m.group(1), m.group(2), m.group(3)
        if re.search(r"\b" + re.escape(var) + r"\s*\.\s*(?:write_text|write_bytes|open)\b", code):
            join_targets.append((base_expr, name))
    for base_expr, name in join_targets:
        if _base_is_session(base_expr, code):
            target = str(SESSIONS_ROOT / name)
        else:
            literal = _base_literal(base_expr, code)
            target = str(pathlib.Path(literal) / name) if literal is not None else name
        blocked = check_file(target)
        if blocked:
            block(
                f"BLOCKED: Inline script writes to '{blocked}' in session directory. "
                f"Use the appropriate hacker-bob MCP tool instead."
            )
    for match in SUBPROCESS_SHELL_RE.finditer(code):
        analyze_shell_write(match.group(1), depth + 1)


def analyze_shell_write(text, depth=0):
    """Recursively block direct shell/interpreter writes to MCP-owned files."""
    if depth > MAX_DEPTH:
        return
    skeleton, payloads = partition_command(text)
    try:
        tokens = shlex.split(skeleton, posix=True)
    except ValueError:
        # The skeleton has no heredoc body, so a parse failure is a genuinely
        # malformed shell skeleton (e.g. an unterminated quote). Fail closed.
        block(
            "BLOCKED: Command cannot be safely parsed. "
            "Refusing to allow potentially unsafe shell operation."
        )

    script_code = inline_code_token_indices(tokens, SCRIPT_INTERPRETERS)
    shell_code = inline_code_token_indices(tokens, SHELL_INTERPRETERS)
    masked = script_code | shell_code

    # cd/pushd targets in this command's skeleton: a relative redirect/script
    # target is also resolved against them so `cd <session_dir> && … > ledger`
    # cannot escape the session-dir check.
    base_dirs = extract_cd_targets(skeleton)

    scan_mutating_tokens(tokens, masked, base_dirs)

    # Redirects/tee — scanned on the skeleton with inline -c/-e code strings
    # redacted so a '>'/tee that appears as DATA inside python3 -c "..." is not
    # mistaken for a real redirect target.
    redirect_text = skeleton
    for index in masked:
        redirect_text = redirect_text.replace(tokens[index], " ")
    for target in extract_redirect_targets(redirect_text):
        blocked = check_file(target, base_dirs)
        if blocked:
            block(
                f"BLOCKED: Bash redirect to '{blocked}' in session directory. "
                f"Use the appropriate hacker-bob MCP tool instead."
            )

    # Command substitutions in the (code-redacted) skeleton execute as shell.
    for fragment in iter_command_substitutions(redirect_text):
        analyze_shell_write(fragment, depth + 1)

    # Inline -c/-e source: script code scanned for write calls; shell code
    # recursed as shell.
    for index in script_code:
        scan_write_ops(tokens[index], depth, base_dirs)
    for index in shell_code:
        analyze_shell_write(tokens[index], depth + 1)

    # Heredoc bodies, scanned by consumer family.
    for consumer, body, expands in payloads:
        family = payload_family(consumer)
        if family == "shell":
            analyze_shell_write(body, depth + 1)
        elif family == "script":
            scan_write_ops(body, depth, base_dirs)
        elif expands:
            # Data consumer, but an unquoted heredoc body still runs $(...).
            for fragment in iter_command_substitutions(body):
                analyze_shell_write(fragment, depth + 1)


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

analyze_shell_write(command)

raise SystemExit(0)
PY
