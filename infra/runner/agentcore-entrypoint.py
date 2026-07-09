"""
agentcore-entrypoint.py — the run.mjs-equivalent glue as a Python BedrockAgentCoreApp
(the AgentCore Runtime SDK is Python). Generalizes the ONLY existing headless
spawn-and-collect implementation in the repo — packages/bob-diff-review/src/bob-runner.ts
(spawns `claude --dangerously-skip-permissions --print --mcp-config <cfg> --strict-mcp-config`)
— from the narrow /bob-diff-review skill to the full /hacker-bob:bob-evaluate FSM.

The mcp/server.js stdio engine runs UNMODIFIED as the MCP child. CLAUDE_CODE_USE_BEDROCK=1
routes every subagent model call through Bedrock IAM (no Anthropic-direct key). This is
authorized deployment glue — no offensive capability is added here.

Runbook: aabw-2026/projects/06-aws-glassbox/AGENTCORE-BRANCH-PLAN.md
"""
import subprocess, json, os, re, secrets, tempfile

# TODO(build-day): `pip install bedrock-agentcore` in the Dockerfile.
from bedrock_agentcore import BedrockAgentCoreApp

app = BedrockAgentCoreApp()


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
    else:
        raise ValueError(f"Unrecognized MODEL_PROVIDER: {provider!r}")
    return env


def build_skill_prompt(target: str, resume: bool) -> str:
    """The engine-native resume mechanism (.claude/skills/bob-evaluate-runner/
    SKILL.md "## Resume"): `resume [domain]` continues an existing session from
    its persisted state.json. No second resume path is invented here."""
    if resume:
        return f"/bob-evaluate resume {target}"
    return f"/bob-evaluate {target}"


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
    the awaiting_approval sentinel returned to the state machine, NOT a gate -- the
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


def run_invocation(payload: dict, env: dict, secrets_client=None,
                    subprocess_run=subprocess.run) -> dict:
    # payload["target"] = our in-VPC target's RFC1918 PRIVATE IP ONLY:
    #   KyberFork anvil node  -> "<10.x.x.x>:8545"   (SC/EVM engagement, the anchor)
    #   self-hosted Locker    -> "<10.x.x.x>"        (web engagement, the breadth demo)
    # SCOPE-GATE FACT (build-verified 2026-07-09): the engine's mcp/lib/lab-target-attest.js
    # REJECTS .internal/.local DNS names — only RFC1918/loopback IPv4 literals are lab-eligible,
    # and ONLY under an explicit operator attestation. The deploy (i1 glassbox-stack) MUST set,
    # as AgentCore Runtime env vars (out of the model's reach — a compromised bob cannot
    # self-authorize): BOB_LAB_TARGET_ACK set to the exact lab-attest token (i-own-and-am-authorized-to-test-these-private-targets) and BOB_LAB_TARGET=<that exact IP>. scope.js then
    # permits ONLY that one attested IP.
    # BRIGHT LINE: this MUST be one of our owned in-VPC instances. Never a live/archive RPC,
    # Etherscan, kyberswap.com, Locker's hosted service, real mainnet, or a bounty path.
    target = payload["target"]
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
    payload_target_domain = payload.get("target_domain")
    if isinstance(payload_target_domain, str) and payload_target_domain.strip():
        target_domain = payload_target_domain.strip()
    else:
        # P1-8 / fx-gate-hardening: resolve_session_dir and the resume skill-prompt argument both
        # key on the PORT-STRIPPED host (see _port_stripped_host above) -- the exact target_domain
        # form the approval-gate consumers (mcp/lib/lifecycle-gates.js gradeToReportApprovalBlocker,
        # .claude/hooks/bob-approval-gate-impl.py) and mcp/lib/scope.js's lab-target attestation key
        # by. A with-port target string (e.g. KyberFork's "10.0.0.5:8545") must never diverge from
        # this form, or `resume [domain]` and the session dir the engine persists under would
        # silently disagree with what those consumers/scope.js expect.
        target_domain = _port_stripped_host(target)
    sess = resolve_session_dir(env["HOME"], target_domain)  # HOME = durable EFS mount

    # fx-gate-hardening (P0-1): the model-writable-artifact PRODUCER that used to live here has
    # been REMOVED. Writing the GRADE->REPORT approval artifact from inside this entrypoint ran
    # as the model's own AgentCore execution role, so a headless --dangerously-skip-permissions
    # model could forge its own approval by simply reaching this code path (resume=True +
    # approvalToken present, both attacker-observable/replayable shapes). The approval artifact
    # is now produced OUT OF BAND by an ApprovalWriter Lambda (see
    # infra/aws/glassbox-stack/template.yaml, infra/aws/glassbox-stack/statemachine/
    # glassbox-engagement.asl.json) that runs under a SEPARATE IAM role the model never assumes,
    # triggered by a named human's own approval action (which itself calls
    # states:SendTaskSuccess) -- not by anything this resumed invocation does. This entrypoint no
    # longer reads BOB_APPROVAL_ARTIFACT_DIR or payload["approvalToken"] at all; the resumed
    # session's own internal GRADE->REPORT gate (mcp/lib/lifecycle-gates.js
    # gradeToReportApprovalBlocker, .claude/hooks/bob-approval-gate-impl.py) verifies the
    # HMAC-bound S3 artifact the Lambda wrote, independent of anything in this payload.

    # MODEL PROVIDER FLAG (zai now → bedrock when H1 lands). Pass env DIRECTLY — do NOT route
    # through bob-runner.ts's CLAUDE_CHILD_ENV_ALLOWLIST (L67-94); it omits the model creds and
    # would silently drop them.
    provider = env.get("MODEL_PROVIDER", "zai")
    model_env = build_model_env(provider, env, secrets_client=secrets_client)

    skill_prompt = build_skill_prompt(target_domain, resume)
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

    subprocess_run(
        ["claude", "--dangerously-skip-permissions", "--print",
         "--mcp-config", mcp_config_path, "--strict-mcp-config",
         skill_prompt],
        env=model_env,
        check=True,
    )

    # Return the last finalized report row as the response payload. The split
    # GRADE→REPORT invocation (Step Functions .waitForTaskToken pauses between
    # GRADE and REPORT) is handled by invoking this entrypoint twice with
    # resume=True on the second call; the session resumes from EFS-persisted
    # state via the engine's own `resume [domain]` argument above.
    #
    # STAGE-AWARE clean stop (f1-approval-wiring, wave 2: also gated on BOB_AGENTCORE=="1"): a
    # GRADE-stage call that writes no NEW report-snapshot row is not an error -- it is the
    # expected shape of a session that ran through GRADE and is now correctly withheld at the
    # human-approval gate (see the fx-gate-hardening comment above: the artifact that satisfies
    # that gate is now written by the out-of-band ApprovalWriter Lambda, not by this entrypoint)
    # -- but ONLY on the AWS/AgentCore branch where that gate actually exists. Off that branch
    # (BOB_AGENTCORE unset/!="1"), a GRADE-stage call that wrote nothing new is exactly as broken
    # as before this feature existed, and must keep raising RuntimeError byte-for-byte
    # (inert-by-default). The actual REPORT stage (or a caller that omits "stage" entirely,
    # preserving backward compat with pre-stage-aware callers) always keeps the stale-read
    # guard's RuntimeError regardless of BOB_AGENTCORE -- a REPORT-stage/no-stage invocation that
    # wrote nothing new is genuinely broken and must fail loudly, not be mistaken for an approval
    # pause.
    awaiting_approval_eligible = stage == "GRADE" and env.get("BOB_AGENTCORE") == "1"
    if not os.path.exists(report_path):
        if awaiting_approval_eligible:
            # fx-hmac-content: bind the pending record (and therefore the eventual
            # approval artifact) to the exact grade the human will review. Computed
            # via the real (non-injected) subprocess.run -- see _load_grade_verdict_hash's
            # own docstring for why this must not share the caller-injected
            # subprocess_run used for the claude invocation above.
            return {
                "status": "awaiting_approval",
                "target": target,
                "grade_verdict_hash": _load_grade_verdict_hash(target_domain, env),
            }
        raise RuntimeError(f"No report snapshot written for session dir {sess}")
    with open(report_path) as fh:
        report_lines = fh.read().splitlines()
    if len(report_lines) <= baseline_line_count:
        if awaiting_approval_eligible:
            return {
                "status": "awaiting_approval",
                "target": target,
                "grade_verdict_hash": _load_grade_verdict_hash(target_domain, env),
            }
        raise RuntimeError(f"No new report snapshot written for session dir {sess}")
    return json.loads(report_lines[-1])


@app.entrypoint
def invoke(payload):
    import boto3  # real client constructed only here, never inside run_invocation/build_model_env
    return run_invocation(payload, dict(os.environ), secrets_client=boto3.client("secretsmanager"))


app.run()  # serves the InvokeAgentRuntime contract; the v2 FSM runs unchanged in the microVM
