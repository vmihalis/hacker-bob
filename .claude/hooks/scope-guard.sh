#!/bin/bash
# Scope guard hook — PreToolUse on Bash
# Hard-block out-of-scope and deny-listed domains (exit 2).
# Set BOUNTY_SCOPE_LOG_ONLY=1 to restore warn-only out-of-scope logging.

INPUT=$(cat)
export SCOPE_GUARD_INPUT="$INPUT"

python3 - <<'PY'
import datetime
import json
import os
import pathlib
import re
import shlex
import sys
from urllib.parse import urlsplit


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def block(message):
    print(message, file=sys.stderr)
    raise SystemExit(2)


def normalize_host(value, bare=False):
    if not value:
        return None

    value = value.strip().strip("\"'").rstrip("\\),.;")
    if not value or value.startswith("$"):
        return None

    host = None
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", value):
        try:
            host = urlsplit(value).hostname
        except Exception:
            host = None
    else:
        candidate = value.rsplit("@", 1)[-1]
        candidate = re.split(r"[/?#]", candidate, 1)[0]
        if candidate.startswith("["):
            return None
        host = candidate.split(":", 1)[0]

    if not host:
        return None

    host = host.strip().strip(".").lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*\.[a-z]{2,63}", host):
        return None

    if bare:
        fileish_tlds = {
            "txt",
            "json",
            "md",
            "log",
            "csv",
            "xml",
            "js",
            "py",
            "sh",
            "yaml",
            "yml",
            "html",
            "htm",
            "php",
            "tmp",
            "out",
            "bak",
            "old",
            "cfg",
            "conf",
            "ini",
        }
        if host.rsplit(".", 1)[-1] in fileish_tlds:
            return None

    return host


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {}


def session_scopes(session_dir):
    if session_dir in scope_cache:
        return scope_cache[session_dir]

    allowed = {session_dir.name.lower()}

    state = load_json(session_dir / "state.json")
    target = normalize_host(state.get("target", ""), bare=True)
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


def log_line(session_dir, message):
    log_path = session_dir / "scope-warnings.log"
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write(f"[{utc_now()}] {message}\n")


def sanitize_command_snippet(command_text):
    def redact_url(match):
        raw_url = match.group(0)
        try:
            parsed = urlsplit(raw_url)
        except Exception:
            return raw_url.split("?", 1)[0].split("#", 1)[0]

        redacted = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            redacted += "?REDACTED"
        return redacted

    sanitized = re.sub(r"https?://[^\s\"'<>|;]+", redact_url, command_text, flags=re.IGNORECASE)
    return sanitized[:200]


def resolve_path(raw_path, session_dir=None):
    path_text = raw_path.strip().strip("\"'")
    unresolved_session = False

    if "$SESSION" in path_text or "${SESSION}" in path_text:
        replacement = env_session or (str(session_dir) if session_dir else "")
        if replacement:
            path_text = path_text.replace("${SESSION}", replacement).replace("$SESSION", replacement)
        else:
            unresolved_session = True

    path_text = path_text.replace("${HOME}", str(home)).replace("$HOME", str(home))
    if path_text.startswith("~"):
        path_text = os.path.expanduser(path_text)

    return pathlib.Path(path_text), unresolved_session


def session_dir_from_path(raw_path):
    resolved, unresolved = resolve_path(raw_path)
    if unresolved:
        return None, True

    candidate = resolved if resolved.is_dir() else resolved.parent
    try:
        rel = candidate.resolve(strict=False).relative_to(sessions_root.resolve(strict=False))
    except Exception:
        return None, False

    if not rel.parts:
        return None, False

    session_dir = sessions_root / rel.parts[0]
    if session_dir.is_dir():
        return session_dir, False
    return None, False


def split_chunks(command_text):
    return [chunk.strip() for chunk in re.split(r"(?:&&|\|\||;|\n)", command_text) if chunk.strip()]


def unwrap_command(tokens):
    index = 0
    while index < len(tokens):
        token = tokens[index]

        if token in {"do", "then", "if", "while", "until", "for", "in", "{", "(", "!", "time"}:
            index += 1
            continue

        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=.*$", token):
            index += 1
            continue

        if token == "env":
            index += 1
            continue

        if token == "timeout":
            index += 1
            while index < len(tokens) and (
                tokens[index].startswith("-") or re.fullmatch(r"\d+[smhd]?", tokens[index])
            ):
                index += 1
            continue

        tool = pathlib.Path(token).name
        args = tokens[index + 1 :]

        if tool in {"bash", "sh", "zsh"}:
            for arg_index, arg in enumerate(args):
                if arg in {"-c", "-lc", "-ic"} and arg_index + 1 < len(args):
                    return "shell", [args[arg_index + 1]]

        return tool, args

    return None, []


def extract_from_chunk(command_text, base_domains, file_refs):
    try:
        tokens = shlex.split(command_text, posix=True)
    except ValueError:
        return

    tool, args = unwrap_command(tokens)
    if not tool:
        return

    if tool == "shell" and args:
        extract_from_command(args[0], base_domains, file_refs)
        return

    host_value_flags = {"-d", "--domain", "-u", "--url", "--target", "-connect", "-servername"}
    file_value_flags = {"-l", "--list", "-iL"}
    skip_value_flags = {
        "-A",
        "--cookie",
        "--cookie-jar",
        "--data",
        "--data-binary",
        "--data-raw",
        "--data-urlencode",
        "--form",
        "--header",
        "--interface",
        "--max-time",
        "--output",
        "--ports",
        "--proxy",
        "--rate-limit",
        "--referer",
        "--request",
        "--retry",
        "--severity",
        "--timeout",
        "--user",
        "--user-agent",
        "--wordlist",
        "-H",
        "-O",
        "-T",
        "-X",
        "-b",
        "-c",
        "-e",
        "-m",
        "-o",
        "-p",
        "-s",
        "-t",
        "-w",
        "-x",
    }
    positional_host_tools = {"curl", "wget", "nmap", "httpx", "nuclei", "katana", "feroxbuster", "ffuf"}

    gobuster_subcommand_seen = tool != "gobuster"
    index = 0
    while index < len(args):
        arg = args[index]

        if arg == "<" and index + 1 < len(args):
            file_refs.append(args[index + 1])
            index += 2
            continue

        if arg.startswith("--resolve="):
            value = arg.split("=", 1)[1]
            normalized = normalize_host(value.split(":", 1)[0], bare=True)
            if normalized:
                base_domains.add(normalized)
            index += 1
            continue

        if arg == "--resolve" and index + 1 < len(args):
            normalized = normalize_host(args[index + 1].split(":", 1)[0], bare=True)
            if normalized:
                base_domains.add(normalized)
            index += 2
            continue

        if arg.startswith("--header="):
            header_value = arg.split("=", 1)[1]
            if ":" in header_value:
                header_name, header_target = header_value.split(":", 1)
                if header_name.strip().lower() == "host":
                    normalized = normalize_host(header_target.strip(), bare=True)
                    if normalized:
                        base_domains.add(normalized)
            index += 1
            continue

        if arg in {"-H", "--header"} and index + 1 < len(args):
            header_value = args[index + 1]
            if ":" in header_value:
                header_name, header_target = header_value.split(":", 1)
                if header_name.strip().lower() == "host":
                    normalized = normalize_host(header_target.strip(), bare=True)
                    if normalized:
                        base_domains.add(normalized)
            index += 2
            continue

        if arg.startswith("--url=") or arg.startswith("--target="):
            normalized = normalize_host(arg.split("=", 1)[1], bare=True)
            if normalized:
                base_domains.add(normalized)
            index += 1
            continue

        if arg in host_value_flags and index + 1 < len(args):
            value = args[index + 1]
            if arg == "-connect":
                value = value.split(":", 1)[0]
            normalized = normalize_host(value, bare=True)
            if normalized:
                base_domains.add(normalized)
            index += 2
            continue

        if arg.startswith("--list="):
            file_refs.append(arg.split("=", 1)[1])
            index += 1
            continue

        if arg in file_value_flags and index + 1 < len(args):
            file_refs.append(args[index + 1])
            index += 2
            continue

        if arg in skip_value_flags and index + 1 < len(args):
            index += 2
            continue

        if arg.startswith("-"):
            index += 1
            continue

        if tool == "gobuster" and not gobuster_subcommand_seen:
            gobuster_subcommand_seen = True
            index += 1
            continue

        if tool in positional_host_tools:
            normalized = normalize_host(arg, bare=True)
            if normalized:
                base_domains.add(normalized)

        index += 1


def extract_from_command(command_text, base_domains, file_refs):
    for url in re.findall(r"https?://[^\s\"'<>|;]+", command_text, flags=re.IGNORECASE):
        normalized = normalize_host(url)
        if normalized:
            base_domains.add(normalized)

    redirection_re = re.compile(r"<\s*(\"[^\"]+\"|'[^']+'|[^\s|;>&]+)")
    for match in redirection_re.finditer(command_text):
        file_refs.append(match.group(1))

    for chunk in split_chunks(command_text):
        extract_from_chunk(chunk, base_domains, file_refs)


def domains_from_file(path):
    domains = set()
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                for url in re.findall(r"https?://[^\s\"'<>]+", line, flags=re.IGNORECASE):
                    normalized = normalize_host(url)
                    if normalized:
                        domains.add(normalized)

                pieces = line.strip().split()
                if pieces:
                    normalized = normalize_host(pieces[0], bare=True)
                    if normalized:
                        domains.add(normalized)
    except OSError:
        return set()

    return domains


payload = {}
try:
    payload = json.loads(os.environ.get("SCOPE_GUARD_INPUT", ""))
except Exception:
    payload = {}

command = payload.get("tool_input", {}).get("command", "")
if not command:
    raise SystemExit(0)

gate_patterns = [
    r"\bcurl\b",
    r"\bwget\b",
    r"\bhttpx\b",
    r"\bnuclei\b",
    r"\bsubfinder\b",
    r"\bkatana\b",
    r"\bffuf\b",
    r"\bgobuster\b",
    r"\bferoxbuster\b",
    r"\bnmap\b",
    r"\bpython3?\s+(?:-[cmu]|\S+\.py|<<|-)(?:\s|$)",
    r"\bnode\b[^\n]*\s-e(?:\s|$)",
    r"\bopenssl\s+s_client\b",
]
if not any(re.search(pattern, command, flags=re.IGNORECASE) for pattern in gate_patterns):
    raise SystemExit(0)

home = pathlib.Path.home()
sessions_root = home / "bounty-agent-sessions"
env_session = os.environ.get("SESSION", "")
scope_cache = {}

base_domains = set()
file_refs = []
extract_from_command(command, base_domains, file_refs)

session_dirs = []
if sessions_root.is_dir():
    session_dirs = sorted(path for path in sessions_root.iterdir() if path.is_dir())

explicit_candidates = set()
unresolved_session_ref = False

if env_session:
    env_session_path = pathlib.Path(env_session).expanduser()
    try:
        env_session_path.resolve(strict=False).relative_to(sessions_root.resolve(strict=False))
        env_in_sessions_root = True
    except Exception:
        env_in_sessions_root = False
    if env_session_path.is_dir() and env_in_sessions_root:
        explicit_candidates.add(env_session_path)

for ref in file_refs:
    session_dir, unresolved = session_dir_from_path(ref)
    if session_dir:
        explicit_candidates.add(session_dir)
    unresolved_session_ref = unresolved_session_ref or unresolved

explicit_matches = list(explicit_candidates)
if len(explicit_matches) > 1:
    block("BLOCKED: command references multiple session directories")

session_dir = explicit_matches[0] if explicit_matches else None

if session_dir is None and base_domains:
    matched_sessions = []
    for candidate in session_dirs:
        allowed_domains = session_scopes(candidate)
        if any(matches_scope(domain, allowed_domains) for domain in base_domains):
            matched_sessions.append(candidate)

    if len(matched_sessions) == 1:
        session_dir = matched_sessions[0]
    elif len(matched_sessions) > 1:
        block("BLOCKED: unable to resolve a single session for this network command")

if session_dir is None and len(session_dirs) == 1:
    session_dir = session_dirs[0]

if session_dir is None and (base_domains or file_refs or unresolved_session_ref):
    block("BLOCKED: unable to resolve session for network command")

domains = set(base_domains)
for ref in file_refs:
    resolved_path, unresolved = resolve_path(ref, session_dir=session_dir)
    if unresolved:
        block("BLOCKED: unresolved $SESSION path in network command")
    if resolved_path.is_file():
        domains.update(domains_from_file(resolved_path))

if not domains:
    raise SystemExit(0)

if session_dir is None:
    block("BLOCKED: unable to resolve session for network command")

deny_list_path = session_dir / "deny-list.txt"
if deny_list_path.is_file():
    deny_entries = []
    with open(deny_list_path, "r", encoding="utf-8", errors="ignore") as handle:
        for raw_line in handle:
            entry = normalize_host(raw_line.strip(), bare=True)
            if entry:
                deny_entries.append(entry)

    for domain in sorted(domains):
        for denied in deny_entries:
            if matches_scope(domain, {denied}):
                log_line(session_dir, f"BLOCKED (deny-list): {domain}")
                block(f"BLOCKED: {domain} is on the deny list")

allowed = set(session_scopes(session_dir))
allowed.update(
    {
        "web.archive.org",
        "otx.alienvault.com",
        "crt.sh",
        "api.github.com",
        "raw.githubusercontent.com",
    }
)

command_snippet = sanitize_command_snippet(command)
out_of_scope_domains = []
for domain in sorted(domains):
    if not matches_scope(domain, allowed):
        out_of_scope_domains.append(domain)
        log_line(session_dir, f"OUT-OF-SCOPE: {domain} (command: {command_snippet})")

if out_of_scope_domains and os.environ.get("BOUNTY_SCOPE_LOG_ONLY") != "1":
    first_domain = out_of_scope_domains[0]
    block(f"BLOCKED: out-of-scope host {first_domain} for session target {session_dir.name}")

raise SystemExit(0)
PY
