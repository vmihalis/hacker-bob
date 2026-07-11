"""
agentcore-entrypoint.py — the run.mjs-equivalent glue as a Python BedrockAgentCoreApp
(the AgentCore Runtime SDK is Python). Generalizes the ONLY existing headless
spawn-and-collect implementation in the repo — packages/bob-diff-review/src/bob-runner.ts
(spawns `claude --dangerously-skip-permissions --print --mcp-config <cfg> --strict-mcp-config`)
— from the narrow /bob-diff-review skill to the full /hacker-bob:bob-evaluate FSM.

The mcp/server.js stdio engine runs UNMODIFIED as the MCP child. CLAUDE_CODE_USE_BEDROCK=1
routes every subagent model call through Bedrock IAM (no Anthropic-direct key). This is
authorized deployment glue — no offensive capability is added here.

Runbook: aabw-2026/projects/06-aws-hacker-bob/AGENTCORE-BRANCH-PLAN.md
"""
import hashlib, subprocess, json, os, re, secrets, signal, tempfile, time
from datetime import datetime, timezone
from urllib.parse import urlsplit
from urllib.request import urlopen

# TODO(build-day): `pip install bedrock-agentcore` in the Dockerfile.
from bedrock_agentcore import BedrockAgentCoreApp

app = BedrockAgentCoreApp()

HEADLESS_MCP_READINESS_PROMPT = (
    "AgentCore headless execution rule: the hacker-bob MCP server is required. "
    "Claude Code can defer MCP tools behind ToolSearch even after the server starts. "
    "If bob_init_session is not already loaded and directly callable, immediately "
    "call ToolSearch with query: \"select:mcp__hacker-bob__bob_init_session\", then "
    "invoke the returned tool. A name in the deferred-tools listing is not loaded or "
    "directly callable. For any later Bob tool that is not loaded and directly callable, "
    "call ToolSearch with query: \"select:mcp__hacker-bob__TOOL_NAME\", replacing "
    "TOOL_NAME with that tool's exact name, then invoke the returned tool. If the "
    "system says the MCP server is still connecting, wait briefly with Bash sleep "
    "and repeat the concrete ToolSearch. Do not answer with a plan or status update and do not ask the "
    "operator for guidance before making a real Bob MCP call. Never inspect protected Bob session files "
    "directly: use Bob MCP readers and writers. On a fresh URL run, call "
    "bob_init_session before any session-bound read. A session-read-guard denial of "
    "a raw file access is not an MCP outage and is not a reason to stop or ask the "
    "operator. The --private-targets flag selects private-target handling; it is not "
    "authorization or proof of attestation. Do not speculate about operator-side "
    "environment or configuration and do not ask the operator to configure it. Attempt "
    "bob_init_session, and treat its actual structured MCP result as the only authority "
    "truth. If that result reports missing or mismatched authorization or attestation, "
    "surface the structured error and terminate/fail the invocation; never ask or propose setup. "
    "Derive target_domain as the URL hostname exactly (ASCII-normalized, "
    "without scheme or port); preserve an operator-attested loopback or RFC1918 IPv4 "
    "literal byte-for-byte and never replace it with a localhost slug."
)

LIBHEIF_REPLAY_FIXTURE_ID = "libheif-cve-2026-49271"
LIBHEIF_REPLAY_TARGET_DOMAIN = "libheif-cve-2026-49271"
LIBHEIF_VULNERABLE_COMMIT = "b12b733d1716595483413ccd7e2dfb73c44a8d69"
LIBHEIF_EXACT_FIX_COMMIT = "5782bca04a70ebc01c59397205a3cfff22841311"
LIBHEIF_PATCHED_RELEASE_COMMIT = "2b6d5a62fb6151e09d5f36757a5aa5e12f9c2045"
LIBHEIF_HARNESS_SHA256 = "eb4e37a5b6c03618a5a9d7b53e983ea1f3fcfc36f721335e326a96c0f9d8fb55"
LIBHEIF_ORIGINAL_RUN_ID = "run-1779612407619-abb57751"
LIBHEIF_ORIGINAL_RUN_AT = "2026-05-24T08:46:47.619Z"
LIBHEIF_ORIGINAL_COMMAND_SHA256 = "cf78e2b306356df2f5b041e8b0e0c82eb0bf9362c74049ef7eb47dbb5a3cb188"
LIBHEIF_REPLAY_BINARIES = {
    "vulnerable": "/opt/replay/libheif-vulnerable",
    "fixed": "/opt/replay/libheif-fixed",
}


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _libheif_lock_path() -> str:
    image_path = "/opt/replay/target.lock.json"
    if os.path.isfile(image_path):
        return image_path
    return os.path.join(
        os.path.dirname(__file__),
        "demo-targets",
        LIBHEIF_REPLAY_FIXTURE_ID,
        "target.lock.json",
    )


def _load_and_validate_libheif_lock(lock_path: str = None) -> tuple:
    """Load the immutable public-source lock and reject any pin drift.

    Payloads can choose only the fixture id. They can never supply a commit,
    binary path, expected marker, or lock path. The constants below are an
    independent image-code binding over the human-readable lock document.
    """
    path = lock_path or _libheif_lock_path()
    with open(path, "rb") as fh:
        raw = fh.read()
    document = json.loads(raw)
    try:
        pins_match = (
            document["fixture_id"] == LIBHEIF_REPLAY_FIXTURE_ID
            and document["claim_mode"] == "public_historical_reproduction"
            and document["rediscovery"] is False
            and document["source_pins"]["vulnerable"]["commit"] == LIBHEIF_VULNERABLE_COMMIT
            and document["source_pins"]["exact_fix"]["commit"] == LIBHEIF_EXACT_FIX_COMMIT
            and document["source_pins"]["patched_release"]["commit"] == LIBHEIF_PATCHED_RELEASE_COMMIT
            and document["reproduction"]["harness_sha256"] == LIBHEIF_HARNESS_SHA256
            and document["reproduction"]["original_run_id"] == LIBHEIF_ORIGINAL_RUN_ID
            and document["reproduction"]["original_run_at"] == LIBHEIF_ORIGINAL_RUN_AT
            and document["reproduction"]["original_command_sha256"] == LIBHEIF_ORIGINAL_COMMAND_SHA256
        )
    except (KeyError, TypeError) as exc:
        raise RuntimeError("libheif historical-replay lock does not match the image pins") from exc
    if not pins_match:
        raise RuntimeError("libheif historical-replay lock does not match the image pins")
    return document, _sha256_bytes(raw)


def _run_sealed_replay_binary(label: str, path: str, subprocess_run=subprocess.run) -> dict:
    if label not in ("vulnerable", "fixed"):
        raise ValueError(f"unknown replay binary label: {label}")
    if not os.path.isfile(path) or not os.access(path, os.X_OK):
        raise RuntimeError(f"sealed libheif {label} replay binary is unavailable")
    started = time.monotonic()
    child_env = dict(os.environ)
    child_env["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1"
    result = subprocess_run(
        [path],
        env=child_env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    elapsed_ms = int(round((time.monotonic() - started) * 1000))
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    return {
        "label": label,
        "exit_code": result.returncode,
        "duration_ms": elapsed_ms,
        "binary_sha256": _sha256_file(path),
        "stdout_sha256": _sha256_bytes(stdout.encode("utf-8", errors="replace")),
        "stderr_sha256": _sha256_bytes(stderr.encode("utf-8", errors="replace")),
        "stdout": stdout,
        "stderr": stderr,
    }


def _assert_libheif_differential(vulnerable: dict, fixed: dict) -> None:
    vulnerable_text = f"{vulnerable['stdout']}\n{vulnerable['stderr']}"
    fixed_text = f"{fixed['stdout']}\n{fixed['stderr']}"
    required_vulnerable = (
        "AddressSanitizer: heap-buffer-overflow",
        "READ of size 2",
        "libheif/codecs/uncompressed/unc_decoder.cc:178",
    )
    if vulnerable["exit_code"] == 0 or any(marker not in vulnerable_text for marker in required_vulnerable):
        raise RuntimeError("sealed libheif vulnerable replay did not reproduce the pinned ASan signal")
    if fixed["exit_code"] != 0 or "returned error? 1 output=0" not in fixed_text:
        raise RuntimeError("sealed libheif fixed replay did not reject the invalid range cleanly")
    if "AddressSanitizer" in fixed_text or "runtime error:" in fixed_text:
        raise RuntimeError("sealed libheif fixed replay emitted a sanitizer failure")


def _public_replay_receipt(result: dict) -> dict:
    """Strip raw sanitizer bytes while preserving their content hashes."""
    return {key: value for key, value in result.items() if key not in ("stdout", "stderr")}


def resolve_session_dir(home: str, target: str) -> str:
    """$HOME/hacker-bob-sessions/<target> — matches mcp/lib/paths.js:44-46
    sessionsRoot() exactly. No env-var override exists there, so none is
    introduced here either."""
    return f"{home}/hacker-bob-sessions/{target}"


def _port_stripped_host(target: str) -> str:
    """Strip a trailing ":<port>" suffix, if any, from `target`.

    This is the exact `target_domain` form the approval-gate consumers
    (mcp/lib/lifecycle-gates.js's gradeToReportApprovalBlocker,
    .claude/hooks/bob-approval-gate-impl.py) key their artifact lookups by.
    mcp/lib/scope.js's assertHttpScopeDomain (line ~211: `host.includes(":")
    || net.isIP(address) || ...`) and lab-target-attest.js's
    labTargetEligibleHost (`net.isIP(address) !== 4`) both treat a
    colon-bearing host as never a bare IPv4 literal — net.isIP("10.0.0.5:8545")
    returns 0, not 4 — so the engine normalizes target_domain to the
    port-stripped host before a lab target is ever considered eligible. A
    with-port target string (e.g. KyberFork's "10.0.0.5:8545") therefore
    never equals the target_domain the consumers key by; this helper produces
    that same port-stripped form so resolve_session_dir and the resume
    skill-prompt argument (both call sites in run_invocation below) key on the
    identical target_domain the approval-gate consumers and scope.js do."""
    return re.sub(r":\d+$", "", target)


def build_model_env(provider: str, base_env: dict, secrets_client=None) -> dict:
    """Returns a NEW env dict (never mutates base_env) with the model-provider
    credentials wired in. Env is passed straight through to the claude
    subprocess elsewhere — this function only adds the provider-specific keys;
    it must never filter or reimplement bob-runner.ts's CLAUDE_CHILD_ENV_ALLOWLIST."""
    env = dict(base_env)
    if provider == "bedrock":
        # A stale direct-provider secret or gateway URL must never override the
        # declared Bedrock path when this image is launched from a dirty shell.
        for key in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL"):
            env.pop(key, None)
        env["CLAUDE_CODE_USE_BEDROCK"] = "1"  # target: no egress hole, Bedrock VPC endpoint
        # Pass AWS_REGION through only if already present — never fabricate a
        # default here; a missing region should fail loudly downstream, not here.
        if "AWS_REGION" in base_env:
            env["AWS_REGION"] = base_env["AWS_REGION"]
    elif provider == "zai":
        # Interim: unblocks the build before the Bedrock grant lands. Requires
        # the one narrow declared egress hole to the Z.ai gateway. The token is
        # NEVER hardcoded or defaulted here — it is fetched or the call fails.
        secret = secrets_client.get_secret_value(SecretId="zai/agt-token")
        env["ANTHROPIC_BASE_URL"] = base_env["ZAI_GATEWAY_URL"]
        env["ANTHROPIC_AUTH_TOKEN"] = secret["SecretString"]
        env["ANTHROPIC_MODEL"] = "glm-5.1"
        env.pop("CLAUDE_CODE_USE_BEDROCK", None)
    else:
        raise ValueError(f"Unrecognized MODEL_PROVIDER: {provider!r}")
    return env


def ensure_claude_workspace_trust(
    env: dict,
    project_dir: str = "/opt/hacker-bob",
    mcp_server_name: str = "hacker-bob",
) -> None:
    """Accept Claude Code's non-interactive trust gate for the baked workspace.

    AgentCore mounts HOME on EFS, so image-baked dotfiles are not reliable here.
    Claude Code prints the exact required setting when running under --print:
    projects["/opt/hacker-bob"].hasTrustDialogAccepted=true in $HOME/.claude.json.
    The MCP server also needs non-interactive approval, represented by
    enabledMcpjsonServers. Merge only those approval bits before invoking Claude.
    If the file cannot be written, fail before any model spend instead of
    hanging on an interactive trust or MCP-approval state.
    """
    home = env.get("HOME")
    if not home:
        raise RuntimeError("HOME is required to write Claude workspace trust config")
    config_path = os.path.join(home, ".claude.json")
    tmp_path = None
    try:
        os.makedirs(home, exist_ok=True)
        config = {}
        if os.path.exists(config_path):
            with open(config_path) as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                config = loaded
        projects = config.get("projects")
        if not isinstance(projects, dict):
            projects = {}
        project_config = projects.get(project_dir)
        if not isinstance(project_config, dict):
            project_config = {}
        project_config["hasTrustDialogAccepted"] = True
        enabled_servers = project_config.get("enabledMcpjsonServers")
        if not isinstance(enabled_servers, list):
            enabled_servers = []
        if mcp_server_name not in enabled_servers:
            enabled_servers.append(mcp_server_name)
        project_config["enabledMcpjsonServers"] = enabled_servers
        disabled_servers = project_config.get("disabledMcpjsonServers")
        if isinstance(disabled_servers, list):
            project_config["disabledMcpjsonServers"] = [
                name for name in disabled_servers if name != mcp_server_name
            ]
        projects[project_dir] = project_config
        config["projects"] = projects
        fd, tmp_path = tempfile.mkstemp(prefix=".claude.", suffix=".json", dir=home)
        with os.fdopen(fd, "w") as fh:
            json.dump(config, fh)
        os.replace(tmp_path, config_path)
    except Exception as exc:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        raise RuntimeError(f"Failed to write Claude workspace trust config: {exc}") from exc


def apply_runtime_session_home(payload: dict, env: dict) -> dict:
    """Scope AgentCore HOME to the stable runtime session id when supplied.

    The Bob engine singleton lock lives under $HOME/hacker-bob-sessions. A
    stopped AgentCore runtime session can leave that lock on the shared EFS home;
    using the Step Functions runtimeSessionId as a HOME subdirectory gives the
    split GRADE/REPORT pair durable shared state without cross-execution stale
    lock collisions. Off AgentCore, or when no runtime session id is supplied,
    behavior stays unchanged.
    """
    runtime_session_id = payload.get("runtime_session_id") or payload.get("runtimeSessionId")
    if env.get("BOB_AGENTCORE") != "1" or not isinstance(runtime_session_id, str):
        return env
    runtime_session_id = runtime_session_id.strip()
    if not runtime_session_id:
        return env
    safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", runtime_session_id)[:160]
    scoped = dict(env)
    scoped["HOME"] = os.path.join(env["HOME"], "runtime-sessions", safe_id)
    return scoped


def apply_request_context_session_id(payload: dict, context) -> dict:
    """Use AgentCore's request-context session id when direct callers omit it.

    Step Functions already threads runtime_session_id through the JSON payload so
    its split GRADE/REPORT pair stays explicit. Direct InvokeAgentRuntime calls
    usually carry the stable runtime session id only in the AgentCore request
    context; copying it into the payload gives them the same isolated EFS HOME
    behavior and avoids collisions with stale engine singleton locks on the
    shared root home.
    """
    if not isinstance(payload, dict):
        return payload
    if isinstance(payload.get("runtime_session_id"), str) or isinstance(payload.get("runtimeSessionId"), str):
        return payload
    session_id = getattr(context, "session_id", None)
    if not isinstance(session_id, str) or not session_id.strip():
        return payload
    patched = dict(payload)
    patched["runtime_session_id"] = session_id
    return patched


def build_skill_prompt(target: str, resume: bool, target_domain: str = None,
                       no_auth: bool = False, mode: str = "normal",
                       private_targets: bool = False) -> str:
    """The engine-native resume mechanism (.claude/skills/bob-evaluate-runner/
    SKILL.md "## Resume"): `resume [domain]` continues an existing session from
    its persisted state.json. No second resume path is invented here."""
    if resume:
        return f"/bob-evaluate resume {target_domain or target}"
    flags = []
    if no_auth:
        flags.append("--no-auth")
    if private_targets:
        flags.append("--private-targets")
    normalized_mode = mode if mode in ("normal", "paranoid", "yolo") else "normal"
    flags.append(f"--{normalized_mode}")
    return " ".join([f"/bob-evaluate {target}", *flags])


def _target_domain_from_payload(payload: dict) -> str:
    explicit = payload.get("target_domain")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()

    raw_target = payload.get("target_url") or payload["target"]
    if isinstance(raw_target, str) and raw_target.startswith(("http://", "https://")):
        parsed = urlsplit(raw_target)
        if not parsed.hostname:
            raise ValueError(f"target URL has no hostname: {raw_target!r}")
        return parsed.hostname
    return _port_stripped_host(raw_target)


_demo_target_process = None


def start_builtin_demo_target(env: dict, popen=subprocess.Popen):
    """Start the repo-owned synthetic API fixture on loopback when enabled.

    The fixture has no external dependencies or real data. AgentCore exposes
    only port 8080; the target stays container-local on 127.0.0.1:8081.
    """
    global _demo_target_process
    enabled = str(env.get("BOB_BUILTIN_DEMO_TARGET", "false")).lower() in ("1", "true")
    if not enabled:
        return None
    if _demo_target_process is not None and _demo_target_process.poll() is None:
        return _demo_target_process

    child_env = dict(env)
    child_env.update({
        "MOCK_GITHUB_HOST": "127.0.0.1",
        "MOCK_GITHUB_PORT": "8081",
        "MOCK_STRICT_ROUTES": "1",
    })
    script = env.get(
        "BOB_BUILTIN_DEMO_TARGET_SCRIPT",
        "/opt/hacker-bob/scripts/mock-github-api.js",
    )
    _demo_target_process = popen(
        ["node", script, "--port", "8081"],
        env=child_env,
        stdout=None,
        stderr=None,
    )
    return _demo_target_process


def run_bounded_subprocess(cmd, env: dict, timeout_seconds: int, popen=subprocess.Popen):
    """Run Claude in its own process group and kill the group on deadline."""
    process = popen(cmd, env=env, start_new_session=True)
    try:
        returncode = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)
        except Exception:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except Exception:
                pass
        raise TimeoutError(
            f"Claude invocation exceeded the bounded {timeout_seconds}s AgentCore deadline"
        )
    if returncode != 0:
        raise subprocess.CalledProcessError(returncode, cmd)
    return process


def claude_budget_args(env: dict) -> list:
    """Return a bounded Claude Code --print budget guard.

    Wall-clock timeout limits AgentCore session spend, but it is not a token
    budget. Claude Code supports --max-budget-usd in --print mode, so production
    invocations get an explicit dollar ceiling. BOB_MAX_BUDGET_USD=0 disables it
    for local debugging; positive values are clamped to $5 per invocation unless
    the image is edited deliberately.
    """
    raw = env.get("BOB_MAX_BUDGET_USD", "2.00")
    try:
        value = float(raw)
    except (TypeError, ValueError):
        value = 2.00
    if value <= 0:
        return []
    value = min(value, 5.00)
    return ["--max-budget-usd", f"{value:.2f}"]


def _write_caller_auth_mcp_config(mcp_config_path: str, token: str) -> str:
    """fx-gate-bypass defense 2 — mint-and-inject the per-invocation caller-auth token.

    Reads the static mcp-config JSON at `mcp_config_path`, deep-copies it, injects
    `token` into `mcpServers.hacker-bob.env.BOB_MCP_CALLER_TOKEN`, and writes the copy
    to a fresh per-invocation tmp path. Returns that tmp path.

    WHY ONLY VIA THE MCP-CONFIG JSON, NEVER THE MODEL'S OWN ENV: `claude --mcp-config
    <path>` applies that config's `env` block ONLY to the MCP-server child the CLI
    itself spawns -- never to the model's own ambient process env. A rogue second
    engine instance the model spawns directly via Bash (e.g. `env -u BOB_AGENTCORE
    node .../mcp/server.js`, inheriting only the model's own env) therefore never
    receives BOB_MCP_CALLER_TOKEN. mcp/lib/transport.js's caller-auth gate verifies
    this token on the first inbound request when enforcement is active.

    FAILS GRACEFULLY (defense-in-depth, NOT the root of trust): if the config cannot
    be read/parsed, or carries no `mcpServers.hacker-bob` entry, this returns
    `mcp_config_path` UNCHANGED rather than raising -- a malformed/missing mcp-config
    must not hard-fail the whole invocation over what is explicitly a SECOND layer
    (see mcp/lib/transport.js's own header comment: the real structural backstop is
    the independent export-tool approval chokepoint, defense 3). A model that reads
    this per-invocation config via Bash/Read could in principle exfiltrate and replay
    the token into a rogue spawn -- documented residual, not closed by this layer."""
    try:
        with open(mcp_config_path) as fh:
            config = json.load(fh)
        server_entry = config.get("mcpServers", {}).get("hacker-bob")
        if not isinstance(server_entry, dict):
            return mcp_config_path
        server_entry = dict(server_entry)
        server_entry["env"] = {**(server_entry.get("env") or {}), "BOB_MCP_CALLER_TOKEN": token}
        config["mcpServers"] = {**config["mcpServers"], "hacker-bob": server_entry}
        fd, tmp_path = tempfile.mkstemp(prefix="bob-mcp-config-", suffix=".json")
        with os.fdopen(fd, "w") as fh:
            json.dump(config, fh)
        return tmp_path
    except Exception:
        return mcp_config_path


def _load_grade_verdict_hash(target_domain: str, env: dict, subprocess_run=subprocess.run):
    """fx-hmac-content: best-effort grade_verdict_hash for the just-completed GRADE stage.

    Shells out to `node -e` against mcp/lib/report-finalize.js's already-exported
    loadGradeVerdictHash(target_domain) -- the exact node-shellout bridge pattern
    mcp/lib/approval-store.js already uses to reach real AWS SDK v3 (Promise-only)
    calls from a synchronous caller. Here the reason is different but the pattern is
    identical: keep the sha256-over-canonical-JSON logic in ONE place
    (report-finalize.js / verification-contracts.js hashCanonicalJson) rather than
    re-implementing byte-identical canonicalization a second time in Python. Reads
    f"{HOME}/hacker-bob-sessions/{target_domain}/grade.json" via paths.js's own
    gradeArtifactPaths -- the same EFS-mounted session dir this file already reads
    report-snapshots.jsonl from; zero new filesystem access is introduced.

    mcp/lib/report-finalize.js lives alongside mcp/agentcore-mcp-config.json (both
    ship under the same mcp/ directory -- see Dockerfile's `COPY mcp/ ./mcp/` and the
    BOB_MCP_CONFIG env var it bakes in), so the module path is derived from
    env["BOB_MCP_CONFIG"]'s own directory rather than this file's own location
    (which differs between the Docker image layout and this repo's dev/test layout).

    NEVER raises: any failure (missing grade.json, node unavailable, malformed
    output, BOB_MCP_CONFIG unset) yields None. This is a best-effort enrichment of
    the awaiting_verifier_gate sentinel returned to the state machine, NOT a gate -- the
    real fail-closed content-binding happens downstream in mcp/lib/approval-store.js
    (verifyApprovalArtifact) and .claude/hooks/bob-approval-gate-impl.py, which each
    independently resolve their own current grade_verdict_hash before admitting the
    GRADE -> REPORT transition."""
    try:
        mcp_config = env.get("BOB_MCP_CONFIG")
        if not mcp_config:
            return None
        report_finalize_js = os.path.join(os.path.dirname(mcp_config), "lib", "report-finalize.js")
        # `node -e <script> arg0 arg1` puts arg0 at process.argv[1] (NOT [2] -- there is no
        # "[eval]" placeholder in process.argv itself, only in stack-trace text), so the module
        # path is argv[1] and target_domain is argv[2].
        script = (
            "const { loadGradeVerdictHash } = require(process.argv[1]);"
            "process.stdout.write(loadGradeVerdictHash(process.argv[2]));"
        )
        result = subprocess_run(
            ["node", "-e", script, report_finalize_js, target_domain],
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        candidate = (result.stdout or "").strip()
        return candidate if re.fullmatch(r"[0-9a-f]{64}", candidate) else None
    except Exception:
        return None


def _approval_gate_hook_path() -> str:
    image_path = "/opt/hacker-bob/.claude/hooks/bob-approval-gate-impl.py"
    if os.path.isfile(image_path):
        return image_path
    return os.path.abspath(os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        ".claude",
        "hooks",
        "bob-approval-gate-impl.py",
    ))


def _require_content_bound_approval(target_domain: str, env: dict) -> None:
    """Reuse the production approval consumer before deterministic REPORT.

    The fixture path bypasses Claude/MCP intentionally, so it would otherwise
    bypass the PreToolUse matcher that protects the normal Bob REPORT edge. Run
    the exact same hook implementation out-of-process and fail closed on every
    nonzero result. No payload field can stand in for the S3/HMAC artifact.
    """
    payload = {
        "tool_name": "mcp__hacker-bob__bob_finalize_report",
        "tool_input": {"target_domain": target_domain},
    }
    try:
        result = subprocess.run(
            ["python3", _approval_gate_hook_path()],
            input=json.dumps(payload),
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except Exception as exc:
        raise RuntimeError("could not execute the content-bound approval gate") from exc
    if result.returncode != 0:
        detail = (result.stdout or result.stderr or "approval artifact absent").strip()
        raise RuntimeError(f"libheif replay REPORT remains withheld: {detail}")


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _write_json_file(path: str, document: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp-", suffix=".json", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(document, fh, indent=2)
            fh.write("\n")
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def run_libheif_historical_replay(payload: dict, env: dict, s3_client=None,
                                  subprocess_run=subprocess.run,
                                  binary_paths: dict = None,
                                  lock_path: str = None) -> dict:
    """Run the disclosed F-22 vulnerable/fixed differential and freeze it.

    This is deliberately not the general Bob OSS evaluator. The original Bob
    run is historical evidence; this bounded present-time replay proves that
    the pinned vulnerable library still fires and the exact upstream fix
    rejects the same parsed-equivalent harness. Raw sanitizer output is neither
    returned nor persisted; the durable bundle stores content hashes and a
    bounded, address-free semantic proof card instead of raw logs.
    """
    fixture_id = payload.get("fixture_id")
    if fixture_id != LIBHEIF_REPLAY_FIXTURE_ID:
        raise ValueError(f"unsupported historical replay fixture: {fixture_id!r}")
    stage = payload.get("stage")
    if stage not in ("GRADE", "REPORT"):
        raise ValueError(f"historical replay stage must be GRADE or REPORT, got {stage!r}")

    target_domain = LIBHEIF_REPLAY_TARGET_DOMAIN
    sess = resolve_session_dir(env["HOME"], target_domain)
    os.makedirs(sess, exist_ok=True)
    lock, lock_sha256 = _load_and_validate_libheif_lock(lock_path=lock_path)

    if stage == "REPORT":
        grade_verdict_hash = _load_grade_verdict_hash(target_domain, env)
        if not grade_verdict_hash:
            raise RuntimeError("libheif replay REPORT cannot resolve the approved grade hash")
        _require_content_bound_approval(target_domain, env)
        row = {
            "version": 1,
            "status": "historical_replay_report_ready",
            "target_domain": target_domain,
            "fixture_id": fixture_id,
            "claim_mode": "public_historical_reproduction",
            "rediscovery": False,
            "grade_verdict_hash": grade_verdict_hash,
            "findings": ["F-22"],
            "generated_at": _iso_now(),
            "summary": (
                "Exact-library sanitizer replay of Hacker Bob's public historical F-22 finding; "
                "the pinned vulnerable revision fired and the exact upstream fix rejected the range."
            ),
            "caveat": lock["honesty"]["caveat"],
        }
        report_path = os.path.join(sess, "report-snapshots.jsonl")
        with open(report_path, "a") as fh:
            fh.write(json.dumps(row) + "\n")
        return row

    paths = binary_paths or LIBHEIF_REPLAY_BINARIES
    if set(paths) != {"vulnerable", "fixed"}:
        raise RuntimeError("libheif replay requires exactly the image-owned vulnerable and fixed binaries")
    vulnerable = _run_sealed_replay_binary(
        "vulnerable", paths["vulnerable"], subprocess_run=subprocess_run,
    )
    fixed = _run_sealed_replay_binary(
        "fixed", paths["fixed"], subprocess_run=subprocess_run,
    )
    _assert_libheif_differential(vulnerable, fixed)

    replayed_at = _iso_now()
    replay_receipt = {
        "schema_version": 1,
        "fixture_id": fixture_id,
        "claim_mode": "public_historical_reproduction",
        "rediscovery": False,
        "original_run_id": LIBHEIF_ORIGINAL_RUN_ID,
        "original_run_at": LIBHEIF_ORIGINAL_RUN_AT,
        "original_command_sha256": LIBHEIF_ORIGINAL_COMMAND_SHA256,
        "target_lock_sha256": lock_sha256,
        "harness_sha256": LIBHEIF_HARNESS_SHA256,
        "vulnerable_commit": LIBHEIF_VULNERABLE_COMMIT,
        "exact_fix_commit": LIBHEIF_EXACT_FIX_COMMIT,
        "patched_release_commit": LIBHEIF_PATCHED_RELEASE_COMMIT,
        "vulnerable": _public_replay_receipt(vulnerable),
        "fixed": _public_replay_receipt(fixed),
        "semantic_proof": {
            "bug_type": "heap-buffer-overflow",
            "access": "READ of size 2",
            "source_frame": "libheif/codecs/uncompressed/unc_decoder.cc:178",
            "vulnerable_signal_confirmed": True,
            "fixed_marker": "returned error? 1 output=0",
            "fixed_sanitizer_clean": True,
        },
        "network_policy": (
            "Replay binaries accept no network inputs; AgentCore security-group egress is restricted "
            "to the stack's declared AWS service endpoints."
        ),
        "replayed_at": replayed_at,
    }
    grade_document = {
        "version": 1,
        "target_domain": target_domain,
        "verdict": "SUBMIT",
        "total_score": 76,
        "score_origin": "historical_import",
        "original_run_id": LIBHEIF_ORIGINAL_RUN_ID,
        "original_run_at": LIBHEIF_ORIGINAL_RUN_AT,
        "findings": [{
            "finding_id": "F-22",
            "graded_severity": "medium",
            "severity_origin": "published_advisory",
            "historical_session_severity": "high",
            "defender_disposition": "fix_now",
            "impact": 24,
            "proof_quality": 24,
            "severity_accuracy": 14,
            "chain_potential": 0,
            "report_quality": 14,
            "total_score": 76,
            "feedback": "Strong crafted-HEIF OOB read evidence with file-controlled offsets, source sink, and sanitizer replay.",
        }],
        "graded_at": replayed_at,
        "graded_at_semantics": "schema_compatibility_replay_freeze_time",
        "replay_verified_at": replayed_at,
        "claim_mode": "public_historical_reproduction",
        "rediscovery": False,
        "fixture_receipt": replay_receipt,
    }
    finding_payload = {
        "id": "F-22",
        "title": "CVE-2026-49271: wrapped icef range causes libheif out-of-bounds read",
        "description": (
            "The uncompressed HEIF decoder used unit_offset + unit_size for a range check. "
            "The pinned parsed-equivalent harness wraps that addition and produces an ASan "
            "heap-buffer-overflow; the exact upstream fix rejects the same input. Historical reproduction, not rediscovery."
        ),
        "cwe": "CWE-125",
        "cvss_inputs": {
            "attack_vector": "network",
            "attack_complexity": "low",
            "privileges_required": "none",
            "user_interaction": "required",
            "scope": "unchanged",
            "confidentiality": "none",
            "integrity": "none",
            "availability": "high",
        },
        "source": {
            "cve": "CVE-2026-49271",
            "ghsa": "GHSA-r7qj-cg5r-r6vf",
            "advisory_url": lock["advisory"]["url"],
            "published_severity": "MEDIUM",
            "historical_session_severity": "HIGH",
            "vulnerable_commit": LIBHEIF_VULNERABLE_COMMIT,
            "exact_fix_commit": LIBHEIF_EXACT_FIX_COMMIT,
        },
    }

    _write_json_file(os.path.join(sess, "grade.json"), grade_document)
    grade_verdict_hash = _load_grade_verdict_hash(target_domain, env)
    if not grade_verdict_hash:
        raise RuntimeError("libheif historical replay could not compute its grade verdict hash")

    bucket = env.get("BOB_GRADE_FREEZE_BUCKET")
    if not bucket:
        raise RuntimeError("BOB_GRADE_FREEZE_BUCKET is required for libheif historical replay")
    key = f"hacker-bob/grade-freeze/{target_domain}/{grade_verdict_hash}.json"
    bundle = {
        "version": 1,
        "target_domain": target_domain,
        "grade_verdict_hash": grade_verdict_hash,
        "grade": grade_document,
        "findings": [finding_payload],
        "reportable_finding_ids": ["F-22"],
        "fixture_receipt": replay_receipt,
        "frozen_at": _iso_now(),
    }
    grade_freeze_body = f"{json.dumps(bundle, indent=2)}\n".encode("utf-8")
    grade_freeze_bundle_sha256 = _sha256_bytes(grade_freeze_body)
    if s3_client is None:
        import boto3
        s3_client = boto3.client("s3")
    put_result = s3_client.put_object(
        Bucket=bucket,
        Key=key,
        Body=grade_freeze_body,
        ContentType="application/json",
    )
    grade_freeze_version_id = put_result.get("VersionId") if isinstance(put_result, dict) else None
    if not isinstance(grade_freeze_version_id, str) or not grade_freeze_version_id:
        raise RuntimeError("libheif historical replay grade freeze did not return an S3 VersionId")
    return {
        "status": "awaiting_verifier_gate",
        "target": target_domain,
        "target_domain": target_domain,
        "grade_verdict_hash": grade_verdict_hash,
        "grade_freeze_version_id": grade_freeze_version_id,
        "grade_freeze_bundle_sha256": grade_freeze_bundle_sha256,
        "fixture_id": fixture_id,
        "claim_mode": "public_historical_reproduction",
        "rediscovery": False,
        "reportable_finding_ids": ["F-22"],
        "fixture_receipt": replay_receipt,
    }


def run_demo_smoke(payload: dict, env: dict, s3_client=None, opener=urlopen) -> dict:
    """Deterministic owned-target AgentCore smoke path.

    This is a low-cost fallback for the built-in loopback demo. It does not
    claim a real vulnerability. It exercises the production boundaries that the
    demo needs to prove: AgentCore invocation, EFS HOME persistence, S3
    grade-freeze, and the Step Functions automated verifier gate.
    """
    target = payload.get("target_url") or payload["target"]
    target_domain = _target_domain_from_payload(payload)
    stage = payload.get("stage")
    sess = resolve_session_dir(env["HOME"], target_domain)
    os.makedirs(sess, exist_ok=True)

    if isinstance(target, str) and target.startswith(("http://", "https://")):
        parsed = urlsplit(target)
        health_url = f"{parsed.scheme}://{parsed.netloc}/healthz"
        with opener(health_url, timeout=5) as response:
            status = getattr(response, "status", 200)
            if status >= 400:
                raise RuntimeError(f"demo smoke target health check failed: {health_url} status={status}")

    if stage == "REPORT":
        grade_verdict_hash = _load_grade_verdict_hash(target_domain, env)
        row = {
            "version": 1,
            "status": "demo_report_ready",
            "target": target,
            "target_domain": target_domain,
            "grade_verdict_hash": grade_verdict_hash,
            "findings": [],
            "generated_at": _iso_now(),
            "summary": "Deterministic owned-target smoke report; no reportable findings.",
        }
        report_path = os.path.join(sess, "report-snapshots.jsonl")
        with open(report_path, "a") as fh:
            fh.write(json.dumps(row) + "\n")
        return row

    grade_document = {
        "version": 1,
        "target_domain": target_domain,
        "verdict": "NO_FINDINGS",
        "total_score": 0,
        "findings": [],
        "graded_at": _iso_now(),
        "demo_smoke": True,
    }
    _write_json_file(os.path.join(sess, "grade.json"), grade_document)
    grade_verdict_hash = _load_grade_verdict_hash(target_domain, env)
    if not grade_verdict_hash:
        raise RuntimeError(f"demo smoke could not compute grade verdict hash for {target_domain}")

    bucket = env.get("BOB_GRADE_FREEZE_BUCKET")
    if not bucket:
        raise RuntimeError("BOB_GRADE_FREEZE_BUCKET is required for demo smoke grade freeze")
    key = f"hacker-bob/grade-freeze/{target_domain}/{grade_verdict_hash}.json"
    bundle = {
        "version": 1,
        "target_domain": target_domain,
        "grade_verdict_hash": grade_verdict_hash,
        "grade": grade_document,
        "findings": [],
        "reportable_finding_ids": [],
        "frozen_at": _iso_now(),
        "demo_smoke": True,
    }
    grade_freeze_body = f"{json.dumps(bundle, indent=2)}\n".encode("utf-8")
    grade_freeze_bundle_sha256 = _sha256_bytes(grade_freeze_body)
    if s3_client is None:
        import boto3
        s3_client = boto3.client("s3")
    put_result = s3_client.put_object(
        Bucket=bucket,
        Key=key,
        Body=grade_freeze_body,
        ContentType="application/json",
    )
    grade_freeze_version_id = put_result.get("VersionId") if isinstance(put_result, dict) else None
    if not isinstance(grade_freeze_version_id, str) or not grade_freeze_version_id:
        raise RuntimeError("demo smoke grade freeze did not return an S3 VersionId")
    return {
        "status": "awaiting_verifier_gate",
        "target": target,
        "target_domain": target_domain,
        "grade_verdict_hash": grade_verdict_hash,
        "grade_freeze_version_id": grade_freeze_version_id,
        "grade_freeze_bundle_sha256": grade_freeze_bundle_sha256,
        "demo_smoke": True,
    }


def run_invocation(payload: dict, env: dict, secrets_client=None,
                    subprocess_run=subprocess.run) -> dict:
    env = apply_runtime_session_home(payload, env)
    fixture_id = payload.get("fixture_id")
    if payload.get("demo_smoke") is True and fixture_id is not None:
        raise ValueError("demo_smoke and fixture_id are mutually exclusive")
    if fixture_id is not None:
        if fixture_id != LIBHEIF_REPLAY_FIXTURE_ID:
            raise ValueError(f"unsupported historical replay fixture: {fixture_id!r}")
        return run_libheif_historical_replay(payload, env)
    # payload["target"] = our in-VPC target's RFC1918 PRIVATE IP ONLY:
    #   KyberFork anvil node  -> "<10.x.x.x>:8545"   (SC/EVM engagement, the anchor)
    #   self-hosted Locker    -> "<10.x.x.x>"        (web engagement, the breadth demo)
    # SCOPE-GATE FACT (build-verified 2026-07-09): the engine's mcp/lib/lab-target-attest.js
    # REJECTS .internal/.local DNS names — only RFC1918/loopback IPv4 literals are lab-eligible,
    # and ONLY under an explicit operator attestation. The deploy (i1 hacker-bob-stack) MUST set,
    # as AgentCore Runtime env vars (out of the model's reach — a compromised bob cannot
    # self-authorize): BOB_LAB_TARGET_ACK set to the exact lab-attest token (i-own-and-am-authorized-to-test-these-private-targets) and BOB_LAB_TARGET=<that exact IP>. scope.js then
    # permits ONLY that one attested IP.
    # BRIGHT LINE: this MUST be one of our owned in-VPC instances. Never a live/archive RPC,
    # Etherscan, kyberswap.com, Locker's hosted service, real mainnet, or a bounty path.
    target = payload.get("target_url") or payload["target"]
    resume = payload.get("resume", False)
    stage = payload.get("stage")
    # fx-gate-bypass defense 4 (HIGH — CAIP-10 target handling): KyberFork's co-anchor
    # revision uses CAIP-10 smart-contract targets whose engine session dir is
    # `sc-<family>-<chainId>-<addr8>-<hash8>` (mcp/lib/tools/init-contract-session.js's
    # deriveContractTargetDomain), which this entrypoint's own RFC1918/port-stripped
    # derivation below does NOT reproduce (it has no notion of chain_family/chain_id/
    # address, and re-deriving that logic a second time in Python would risk silently
    # diverging from the 8-nibble collision-guard digest suffix invariant the JS side
    # already owns). Prefer the engine-derived target_domain when the SFN Lambda passes
    # it directly in the payload (computed ONCE, upstream, from state.json's already-
    # derived slug) -- this is reuse-first: the derivation stays in the ONE place that
    # already has it. Fall back to the RFC1918/port-stripped form only when the payload
    # carries no target_domain (the existing KyberFork-anvil/Locker web-target shape).
    target_domain = _target_domain_from_payload(payload)
    sess = resolve_session_dir(env["HOME"], target_domain)  # HOME = durable EFS mount
    if payload.get("demo_smoke") is True:
        return run_demo_smoke(payload, env)

    # fx-gate-hardening (P0-1): the model-writable-artifact PRODUCER that used to live here has
    # been REMOVED. Writing the GRADE->REPORT attestation artifact from inside this entrypoint ran
    # as the model's own AgentCore execution role, so a headless --dangerously-skip-permissions
    # model could forge its own attestation by simply reaching this code path (resume=True +
    # approvalToken present, both attacker-observable/replayable shapes). The attestation artifact
    # is now produced OUT OF BAND by a VerifierGate Lambda (see
    # infra/aws/hacker-bob-stack/template.yaml, infra/aws/hacker-bob-stack/statemachine/
    # hacker-bob-engagement.asl.json) that runs under a SEPARATE IAM role the model never assumes,
    # triggered by Step Functions after GRADE -- not by anything this resumed invocation does. This entrypoint no
    # longer reads BOB_APPROVAL_ARTIFACT_DIR or payload["approvalToken"] at all; the resumed
    # session's own internal GRADE->REPORT gate (mcp/lib/lifecycle-gates.js
    # gradeToReportApprovalBlocker, .claude/hooks/bob-approval-gate-impl.py) verifies the
    # HMAC-bound S3 artifact the Lambda wrote, independent of anything in this payload.

    # MODEL PROVIDER FLAG. Pass env DIRECTLY — do NOT route
    # through bob-runner.ts's CLAUDE_CHILD_ENV_ALLOWLIST (L67-94); it omits the model creds and
    # would silently drop them.
    provider = env.get("MODEL_PROVIDER", "bedrock")
    model_env = build_model_env(provider, env, secrets_client=secrets_client)
    ensure_claude_workspace_trust(env)

    skill_prompt = build_skill_prompt(
        target,
        resume,
        target_domain=target_domain,
        no_auth=payload.get("no_auth") is True,
        mode=payload.get("mode", "normal"),
        private_targets=(
            payload.get("private_targets") is True
            or str(env.get("BOB_BUILTIN_DEMO_TARGET", "false")).lower() in ("1", "true")
        ),
    )
    report_path = f"{sess}/report-snapshots.jsonl"
    baseline_line_count = 0
    if os.path.exists(report_path):
        with open(report_path) as fh:
            baseline_line_count = len(fh.read().splitlines())

    # fx-gate-bypass defense 2: mint a per-invocation caller-auth token and inject it
    # into a FRESH per-invocation copy of the mcp-config JSON, passed to `claude
    # --mcp-config` INSTEAD OF the raw BOB_MCP_CONFIG path -- never into model_env (see
    # _write_caller_auth_mcp_config's own docstring for why only the mcp-config route
    # reaches the CLI's own spawned MCP child, never the model's own ambient env).
    caller_auth_token = secrets.token_hex(32)
    mcp_config_path = _write_caller_auth_mcp_config(env["BOB_MCP_CONFIG"], caller_auth_token)

    claude_cmd = [
        "claude", "--dangerously-skip-permissions", "--print",
        *claude_budget_args(env),
        "--append-system-prompt", HEADLESS_MCP_READINESS_PROMPT,
        "--mcp-config", mcp_config_path, "--strict-mcp-config",
        skill_prompt,
    ]
    remove_mcp_config = mcp_config_path != env["BOB_MCP_CONFIG"]
    try:
        if subprocess_run is subprocess.run:
            raw_timeout = env.get("BOB_INVOCATION_TIMEOUT_SECONDS", "780")
            try:
                timeout_seconds = min(max(int(raw_timeout), 1), 780)
            except (TypeError, ValueError):
                timeout_seconds = 780
            run_bounded_subprocess(claude_cmd, model_env, timeout_seconds)
        else:
            subprocess_run(claude_cmd, env=model_env, check=True)
    finally:
        if remove_mcp_config:
            try:
                os.unlink(mcp_config_path)
            except OSError:
                pass

    # Return the last finalized report row as the response payload. The split
    # GRADE→REPORT invocation is handled by invoking this entrypoint twice with
    # resume=True on the second call; the session resumes from EFS-persisted
    # state via the engine's own `resume [domain]` argument above.
    #
    # STAGE-AWARE clean stop (f1-verifier-gate wiring, also gated on BOB_AGENTCORE=="1"): a
    # GRADE-stage call that writes no NEW report-snapshot row is not an error -- it is the
    # expected shape of a session that ran through GRADE and is now correctly withheld at the
    # automated verifier gate (see the fx-gate-hardening comment above: the artifact that satisfies
    # that gate is now written by the out-of-band VerifierGate Lambda, not by this entrypoint)
    # -- but ONLY on the AWS/AgentCore branch where that gate actually exists. Off that branch
    # (BOB_AGENTCORE unset/!="1"), a GRADE-stage call that wrote nothing new is exactly as broken
    # as before this feature existed, and must keep raising RuntimeError byte-for-byte
    # (inert-by-default). The actual REPORT stage (or a caller that omits "stage" entirely,
    # preserving backward compat with pre-stage-aware callers) always keeps the stale-read
    # guard's RuntimeError regardless of BOB_AGENTCORE -- a REPORT-stage/no-stage invocation that
    # wrote nothing new is genuinely broken and must fail loudly, not be mistaken for an approval
    # pause.
    awaiting_verifier_gate_eligible = stage == "GRADE" and env.get("BOB_AGENTCORE") == "1"
    if not os.path.exists(report_path):
        if awaiting_verifier_gate_eligible:
            # fx-hmac-content: bind the pending record (and therefore the eventual
            # verifier attestation artifact) to the exact grade the verifier gate will bind. Computed
            # via the real (non-injected) subprocess.run -- see _load_grade_verdict_hash's
            # own docstring for why this must not share the caller-injected
            # subprocess_run used for the claude invocation above.
            grade_verdict_hash = _load_grade_verdict_hash(target_domain, env)
            if not grade_verdict_hash:
                raise RuntimeError(
                    f"GRADE stage stopped without a grade verdict for {target_domain}; "
                    "refusing to request verifier attestation"
                )
            return {
                "status": "awaiting_verifier_gate",
                "target": target,
                "target_domain": target_domain,
                "grade_verdict_hash": grade_verdict_hash,
            }
        raise RuntimeError(f"No report snapshot written for session dir {sess}")
    with open(report_path) as fh:
        report_lines = fh.read().splitlines()
    if len(report_lines) <= baseline_line_count:
        if awaiting_verifier_gate_eligible:
            grade_verdict_hash = _load_grade_verdict_hash(target_domain, env)
            if not grade_verdict_hash:
                raise RuntimeError(
                    f"GRADE stage stopped without a grade verdict for {target_domain}; "
                    "refusing to request verifier attestation"
                )
            return {
                "status": "awaiting_verifier_gate",
                "target": target,
                "target_domain": target_domain,
                "grade_verdict_hash": grade_verdict_hash,
            }
        raise RuntimeError(f"No new report snapshot written for session dir {sess}")
    return json.loads(report_lines[-1])


@app.entrypoint
def invoke(payload, context):
    import boto3  # real client constructed only here, never inside run_invocation/build_model_env
    payload = apply_request_context_session_id(payload, context)
    return run_invocation(payload, dict(os.environ), secrets_client=boto3.client("secretsmanager"))


start_builtin_demo_target(dict(os.environ))
app.run()  # serves the InvokeAgentRuntime contract; the v2 FSM runs unchanged in the microVM
