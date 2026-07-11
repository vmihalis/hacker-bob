#!/usr/bin/env python3
"""Unit tests for the AgentCore runner wiring and entrypoint.

The module has a hyphenated filename (not a valid Python identifier), so it is
loaded by path via importlib.util.spec_from_file_location rather than a plain
import. Because the real `bedrock_agentcore` SDK is not installed in this dev
environment (it is only pip-installed inside the Docker image — see
infra/runner/Dockerfile:16), and the module executes `BedrockAgentCoreApp()`,
`@app.entrypoint`, and an unconditional `app.run()` at import time, a minimal
fake `bedrock_agentcore` module is injected into sys.modules before the target
module is exec'd. This lets the real module body run untouched (no
`if __name__ == "__main__":` guard is added around app.run() — none exists in
the stub, and this test does not add one) while still exercising the actual
resolve_session_dir / build_model_env / build_skill_prompt / run_invocation
functions defined in it.

No pytest dependency: plain assertions, a main() that prints a pass/fail
tally, `if __name__ == "__main__": sys.exit(main())` — matching
test/test-write-guard.py's convention.
"""
import hashlib
import hmac
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import types

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")
ENTRYPOINT_PATH = os.path.join(REPO_ROOT, "infra", "runner", "agentcore-entrypoint.py")
DOCKERFILE_PATH = os.path.join(REPO_ROOT, "infra", "runner", "Dockerfile")
BEDROCK_MODEL_OVERRIDES_PATH = os.path.join(
    REPO_ROOT, "infra", "runner", "bedrock-model-overrides.json"
)
# A REAL BOB_MCP_CONFIG path (dirname resolves to the real mcp/ dir this repo ships) so
# _load_grade_verdict_hash's `os.path.dirname(env["BOB_MCP_CONFIG"]) + "/lib/report-finalize.js"`
# resolution finds the real module -- mirrors the Dockerfile's ENV BOB_MCP_CONFIG=
# /opt/hacker-bob/mcp/agentcore-mcp-config.json (dirname = /opt/hacker-bob/mcp, the same
# directory report-finalize.js ships under). The file itself need not exist; only its dirname
# is used.
REAL_MCP_CONFIG_PATH = os.path.join(REPO_ROOT, "mcp", "agentcore-mcp-config.json")
REPORT_FINALIZE_JS_PATH = os.path.join(REPO_ROOT, "mcp", "lib", "report-finalize.js")


def _independent_grade_verdict_hash(target_domain, env):
    """A companion node subprocess independently computing
    mcp/lib/report-finalize.js's loadGradeVerdictHash(target_domain) -- a SEPARATE call site
    from the entrypoint's own _load_grade_verdict_hash bridge, used ONLY to pin cross-language
    parity in tests (so a bug in the entrypoint's bridge cannot silently agree with itself)."""
    # `node -e <script> arg0 arg1` puts arg0 at process.argv[1] (matches
    # infra/runner/agentcore-entrypoint.py's own _load_grade_verdict_hash bridge exactly).
    script = (
        "const { loadGradeVerdictHash } = require(process.argv[1]);"
        "process.stdout.write(loadGradeVerdictHash(process.argv[2]));"
    )
    result = subprocess.run(
        ["node", "-e", script, REPORT_FINALIZE_JS_PATH, target_domain],
        env=env, capture_output=True, text=True, timeout=10, check=True,
    )
    return result.stdout.strip()


def _write_grade_json(session_dir, target_domain, total_score=75):
    os.makedirs(session_dir, exist_ok=True)
    document = {
        "version": 1,
        "target_domain": target_domain,
        "verdict": "SUBMIT",
        "total_score": total_score,
        "findings": [{
            "finding_id": "F-1",
            "impact": 25,
            "proof_quality": 20,
            "severity_accuracy": 10,
            "chain_potential": 10,
            "report_quality": 10,
            "total_score": total_score,
            "feedback": "Clear, reproducible, and reportable.",
        }],
        "graded_at": "2026-05-27T02:00:00.000Z",
    }
    with open(os.path.join(session_dir, "grade.json"), "w") as fh:
        json.dump(document, fh)


def _install_fake_bedrock_agentcore():
    """Injects a stub bedrock_agentcore module into sys.modules so importing
    agentcore-entrypoint.py does not require the real SDK and does not start a
    real server. Returns the fake module (unused by callers; side effect only)."""
    fake = types.ModuleType("bedrock_agentcore")

    class _FakeApp:
        def entrypoint(self, fn):
            # The real decorator registers fn as the AgentCore-facing handler;
            # for our purposes returning it unchanged is sufficient.
            return fn

        def run(self):
            # No-op: never bind a socket or block during test import.
            pass

    fake.BedrockAgentCoreApp = _FakeApp
    sys.modules["bedrock_agentcore"] = fake
    return fake


def _load_entrypoint_module():
    _install_fake_bedrock_agentcore()
    spec = importlib.util.spec_from_file_location("agentcore_entrypoint", ENTRYPOINT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _docker_env(dockerfile_text, name):
    """Return one simple `ENV NAME=value` value from the runner Dockerfile."""
    match = re.search(rf"^ENV {re.escape(name)}=([^\s]+)\s*$", dockerfile_text, re.MULTILINE)
    return match.group(1) if match else None


MODULE = _load_entrypoint_module()


class FakeSecretsClient:
    """Records calls and returns a fixed fake secret; never touches AWS."""

    def __init__(self, secret_string="fake-zai-token-value"):
        self.calls = []
        self._secret_string = secret_string

    def get_secret_value(self, **kwargs):
        self.calls.append(kwargs)
        return {"SecretString": self._secret_string}


def main():
    passed = 0
    failed = 0

    def record(ok, desc, detail=""):
        nonlocal passed, failed
        status = "\033[32mPASS\033[0m" if ok else "\033[31mFAIL\033[0m"
        print(f"  {status}: {desc}")
        if not ok:
            if detail:
                print(f"         {detail}")
            failed += 1
        else:
            passed += 1

    # --- Runner image provider/model contract. These are static image defaults rather than
    #     entrypoint defaults so an AgentCore invocation reaches Bedrock without depending on
    #     an undeclared Runtime environment override. modelOverrides must use canonical
    #     Anthropic source IDs: Claude Code ignores alias keys such as `opus` and `sonnet`. ---
    with open(DOCKERFILE_PATH) as fh:
        dockerfile = fh.read()
    with open(BEDROCK_MODEL_OVERRIDES_PATH) as fh:
        bedrock_overrides = json.load(fh)

    expected_opus = "us.anthropic.claude-opus-4-8"
    expected_sonnet = "us.anthropic.claude-sonnet-5"
    record("@anthropic-ai/claude-code@2.1.202" in dockerfile,
           "runner image pins a Sonnet-5-capable Claude Code release")
    record(_docker_env(dockerfile, "MODEL_PROVIDER") == "bedrock",
           "runner image defaults MODEL_PROVIDER to bedrock",
           f"MODEL_PROVIDER={_docker_env(dockerfile, 'MODEL_PROVIDER')!r}")
    record(_docker_env(dockerfile, "AWS_REGION") == "us-east-1",
           "runner image pins the Bedrock region to us-east-1",
           f"AWS_REGION={_docker_env(dockerfile, 'AWS_REGION')!r}")
    record(_docker_env(dockerfile, "ANTHROPIC_DEFAULT_OPUS_MODEL") == expected_opus,
           "runner image explicitly maps the Opus default to its Bedrock inference profile",
           f"got={_docker_env(dockerfile, 'ANTHROPIC_DEFAULT_OPUS_MODEL')!r}")
    record(_docker_env(dockerfile, "ANTHROPIC_DEFAULT_SONNET_MODEL") == expected_sonnet,
           "runner image explicitly maps the Sonnet default to its Bedrock inference profile",
           f"got={_docker_env(dockerfile, 'ANTHROPIC_DEFAULT_SONNET_MODEL')!r}")
    record(_docker_env(dockerfile, "BOB_MAX_BUDGET_USD") == "2.00",
           "runner image applies a low per-invocation Claude API budget",
           f"BOB_MAX_BUDGET_USD={_docker_env(dockerfile, 'BOB_MAX_BUDGET_USD')!r}")

    model_overrides = bedrock_overrides.get("modelOverrides")
    expected_overrides = {
        "claude-opus-4-8": expected_opus,
        "claude-sonnet-5": expected_sonnet,
    }
    record(model_overrides == expected_overrides,
           "modelOverrides uses canonical Claude IDs and the intended Bedrock targets",
           f"got={model_overrides!r}")
    record(isinstance(model_overrides, dict)
           and "opus" not in model_overrides and "sonnet" not in model_overrides,
           "modelOverrides contains no ignored opus/sonnet alias keys",
           f"got={model_overrides!r}")
    record(MODULE.claude_budget_args({"BOB_MAX_BUDGET_USD": "0"}) == [],
           "claude_budget_args allows an explicit local-debug budget disable")
    record(MODULE.claude_budget_args({"BOB_MAX_BUDGET_USD": "99"}) == ["--max-budget-usd", "5.00"],
           "claude_budget_args clamps unexpectedly high budgets to $5 per invocation")

    with tempfile.TemporaryDirectory() as tmp_home:
        trust_path = os.path.join(tmp_home, ".claude.json")
        with open(trust_path, "w") as fh:
            json.dump({
                "theme": "dark",
                "projects": {
                    "/opt/hacker-bob": {
                        "existing": "kept",
                        "enabledMcpjsonServers": ["other-server"],
                        "disabledMcpjsonServers": ["hacker-bob", "disabled-server"],
                    },
                    "/other/project": {"hasTrustDialogAccepted": False},
                },
            }, fh)
        MODULE.ensure_claude_workspace_trust({"HOME": tmp_home})
        with open(trust_path) as fh:
            trust_config = json.load(fh)
        record(
            trust_config.get("projects", {}).get("/opt/hacker-bob", {}).get("hasTrustDialogAccepted") is True,
            "ensure_claude_workspace_trust accepts the baked /opt/hacker-bob workspace")
        record(
            "hacker-bob" in trust_config.get("projects", {}).get("/opt/hacker-bob", {}).get("enabledMcpjsonServers", [])
            and "other-server" in trust_config.get("projects", {}).get("/opt/hacker-bob", {}).get("enabledMcpjsonServers", [])
            and "hacker-bob" not in trust_config.get("projects", {}).get("/opt/hacker-bob", {}).get("disabledMcpjsonServers", []),
            "ensure_claude_workspace_trust approves the hacker-bob MCP server non-interactively")
        record(
            trust_config.get("projects", {}).get("/opt/hacker-bob", {}).get("existing") == "kept"
            and trust_config.get("theme") == "dark"
            and "disabled-server" in trust_config.get("projects", {}).get("/opt/hacker-bob", {}).get("disabledMcpjsonServers", [])
            and trust_config.get("projects", {}).get("/other/project", {}).get("hasTrustDialogAccepted") is False,
            "ensure_claude_workspace_trust preserves unrelated Claude config")
        scoped_env = MODULE.apply_runtime_session_home(
            {"runtime_session_id": "71c936c0-6e1f-452d-96bb-d878b1034a1e"},
            {"HOME": tmp_home, "BOB_AGENTCORE": "1"},
        )
        record(
            scoped_env.get("HOME") == os.path.join(
                tmp_home, "runtime-sessions", "71c936c0-6e1f-452d-96bb-d878b1034a1e",
            ),
            "apply_runtime_session_home scopes AgentCore HOME by runtime session id",
            f"HOME={scoped_env.get('HOME')!r}")
        unscoped_env = MODULE.apply_runtime_session_home(
            {"runtime_session_id": "71c936c0-6e1f-452d-96bb-d878b1034a1e"},
            {"HOME": tmp_home},
        )
        record(
            unscoped_env.get("HOME") == tmp_home,
            "apply_runtime_session_home is inert outside BOB_AGENTCORE")

    # Prove the same image defaults survive build_model_env and reach the spawned Claude
    # process on the Bedrock path without consulting Secrets Manager.
    bedrock_image_env = {
        "HOME": "/fake/home",
        "AWS_REGION": _docker_env(dockerfile, "AWS_REGION"),
        "ANTHROPIC_DEFAULT_OPUS_MODEL": _docker_env(
            dockerfile, "ANTHROPIC_DEFAULT_OPUS_MODEL"
        ),
        "ANTHROPIC_DEFAULT_SONNET_MODEL": _docker_env(
            dockerfile, "ANTHROPIC_DEFAULT_SONNET_MODEL"
        ),
    }
    image_secrets = FakeSecretsClient()
    resolved_bedrock_env = MODULE.build_model_env(
        "bedrock", bedrock_image_env, secrets_client=image_secrets
    )
    record(resolved_bedrock_env.get("ANTHROPIC_DEFAULT_OPUS_MODEL") == expected_opus
           and resolved_bedrock_env.get("ANTHROPIC_DEFAULT_SONNET_MODEL") == expected_sonnet,
           "build_model_env preserves both explicit Bedrock model defaults",
           f"env={resolved_bedrock_env!r}")
    record(len(image_secrets.calls) == 0,
           "Bedrock image defaults require no Secrets Manager model credential",
           f"calls={image_secrets.calls}")

    # --- (f) resolve_session_dir: HOME-rooted, no env override, no port-stripping of its
    #     OWN -- port-stripping happens at run_invocation's CALL SITE (see (e)/(g) below),
    #     not inside resolve_session_dir itself, which is a pure string-join helper. ---
    got = MODULE.resolve_session_dir("/fake/home", "kyberfork.internal:8545")
    expected = "/fake/home/hacker-bob-sessions/kyberfork.internal:8545"
    record(got == expected, "resolve_session_dir matches paths.js sessionsRoot()",
           f"expected {expected!r}, got {got!r}")

    # --- (a) provider="bedrock": sets CLAUDE_CODE_USE_BEDROCK, never touches secrets_client ---
    fake_secrets = FakeSecretsClient()
    base_env = {"HOME": "/fake/home", "SOME_VAR": "x"}
    env = MODULE.build_model_env("bedrock", base_env, secrets_client=fake_secrets)
    record(env.get("CLAUDE_CODE_USE_BEDROCK") == "1",
           "build_model_env(bedrock) sets CLAUDE_CODE_USE_BEDROCK=1", f"env={env}")
    record(len(fake_secrets.calls) == 0,
           "build_model_env(bedrock) never calls secrets_client", f"calls={fake_secrets.calls}")
    record("ANTHROPIC_AUTH_TOKEN" not in env,
           "build_model_env(bedrock) does not set ANTHROPIC_AUTH_TOKEN", f"env={env}")
    stale_direct_env = MODULE.build_model_env(
        "bedrock",
        {
            "HOME": "/fake/home",
            "ANTHROPIC_API_KEY": "stale-key",
            "ANTHROPIC_AUTH_TOKEN": "stale-token",
            "ANTHROPIC_BASE_URL": "https://stale.example",
        },
        secrets_client=FakeSecretsClient(),
    )
    record(not any(k in stale_direct_env for k in (
        "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL"
    )), "build_model_env(bedrock) strips stale direct-provider credentials")
    record(base_env == {"HOME": "/fake/home", "SOME_VAR": "x"},
           "build_model_env never mutates base_env (bedrock branch)", f"base_env={base_env}")

    # AWS_REGION passthrough: present -> passed through; absent -> not fabricated.
    env_with_region = MODULE.build_model_env(
        "bedrock", {"HOME": "/h", "AWS_REGION": "us-west-2"}, secrets_client=FakeSecretsClient()
    )
    record(env_with_region.get("AWS_REGION") == "us-west-2",
           "build_model_env(bedrock) passes through AWS_REGION when present")
    env_no_region = MODULE.build_model_env("bedrock", {"HOME": "/h"}, secrets_client=FakeSecretsClient())
    record("AWS_REGION" not in env_no_region,
           "build_model_env(bedrock) does not fabricate AWS_REGION when absent")

    # --- (b) provider="zai" (and unset default): calls secrets_client exactly once ---
    for label, provider_value in (("explicit zai", "zai"),):
        fake_secrets_zai = FakeSecretsClient(secret_string="fake-token-abc")
        base_env_zai = {"HOME": "/fake/home", "ZAI_GATEWAY_URL": "https://zai.example.internal"}
        env_zai = MODULE.build_model_env(provider_value, base_env_zai, secrets_client=fake_secrets_zai)
        record(len(fake_secrets_zai.calls) == 1,
               f"build_model_env({label}) calls secrets_client exactly once",
               f"calls={fake_secrets_zai.calls}")
        record(env_zai.get("ANTHROPIC_BASE_URL") == "https://zai.example.internal",
               f"build_model_env({label}) sets ANTHROPIC_BASE_URL from ZAI_GATEWAY_URL")
        record(env_zai.get("ANTHROPIC_AUTH_TOKEN") == "fake-token-abc",
               f"build_model_env({label}) sets ANTHROPIC_AUTH_TOKEN from fetched secret")
        record(env_zai.get("ANTHROPIC_MODEL") == "glm-5.1",
               f"build_model_env({label}) sets ANTHROPIC_MODEL=glm-5.1")
        record("CLAUDE_CODE_USE_BEDROCK" not in env_zai,
               f"build_model_env({label}) does not set CLAUDE_CODE_USE_BEDROCK")
        record(base_env_zai == {"HOME": "/fake/home", "ZAI_GATEWAY_URL": "https://zai.example.internal"},
               f"build_model_env({label}) never mutates base_env")

    # provider unset -> defaults to bedrock at the run_invocation layer (build_model_env
    # itself requires an explicit provider string; the default lives in run_invocation
    # via env.get("MODEL_PROVIDER", "bedrock")). Confirm that default end-to-end below in (e).

    # --- (c) unrecognized MODEL_PROVIDER raises ---
    raised = False
    try:
        MODULE.build_model_env("openai", {"HOME": "/h"}, secrets_client=FakeSecretsClient())
    except ValueError:
        raised = True
    except Exception as e:  # pragma: no cover - defensive, should not happen
        record(False, "build_model_env(unknown) raises ValueError (not some other exception)",
               f"raised {type(e).__name__}: {e}")
    record(raised, "build_model_env(unknown provider) raises ValueError")

    # --- (d) build_skill_prompt: a pure string-format helper, no port-stripping of its OWN
    #     (fx-gate-hardening/P1-8 applies _port_stripped_host at run_invocation's CALL SITE,
    #     not here -- see (e)/(g) below for the port-stripped end-to-end behavior). ---
    got_no_resume = MODULE.build_skill_prompt("kyberfork.internal:8545", resume=False)
    record(got_no_resume == "/bob-evaluate kyberfork.internal:8545 --normal",
           "build_skill_prompt(resume=False) matches exact prompt", f"got={got_no_resume!r}")
    got_resume = MODULE.build_skill_prompt("kyberfork.internal:8545", resume=True)
    record(got_resume == "/bob-evaluate resume kyberfork.internal:8545",
           "build_skill_prompt(resume=True) matches exact prompt", f"got={got_resume!r}")
    demo_url = "http://127.0.0.1:8081/repos/acme/demo/pulls/42"
    got_demo = MODULE.build_skill_prompt(demo_url, resume=False, no_auth=True, mode="normal")
    record(got_demo == f"/bob-evaluate {demo_url} --no-auth --normal",
           "build_skill_prompt preserves a complete fresh-run URL and demo flags",
           f"got={got_demo!r}")

    # --- (e) run_invocation: fake subprocess writes report-snapshots.jsonl,
    #     returns parsed JSON, and provider-specific keys survive into the env
    #     the fake subprocess_run was actually invoked with (never filtered out).
    #
    #     P1-8 / fx-gate-hardening: run_invocation port-strips `target` into
    #     `target_domain` for BOTH resolve_session_dir and the skill-prompt argument --
    #     this target is a bare hostname with no port, so target == target_domain and the
    #     port-stripping is a no-op here (the dedicated port-DIVERGING case is (g) below). ---
    with tempfile.TemporaryDirectory() as tmp_home:
        target = "kyberfork.internal"
        session_dir = MODULE.resolve_session_dir(tmp_home, target)
        report_row = {"status": "published", "target_domain": target, "seal": "abc123"}

        captured = {}

        def fake_subprocess_run(cmd, env=None, check=None):
            captured["cmd"] = cmd
            captured["env"] = env
            captured["check"] = check
            os.makedirs(session_dir, exist_ok=True)
            with open(os.path.join(session_dir, "report-snapshots.jsonl"), "w") as fh:
                fh.write(json.dumps({"status": "draft", "target_domain": target}) + "\n")
                fh.write(json.dumps(report_row) + "\n")

            class _Result:
                returncode = 0

            return _Result()

        env = {
            "HOME": tmp_home,
            "BOB_MCP_CONFIG": "/fake/mcp-config.json",
            "MODEL_PROVIDER": "bedrock",
            "AWS_REGION": "us-east-1",
        }
        fake_secrets_unused = FakeSecretsClient()
        result = MODULE.run_invocation(
            {"target": target, "resume": False},
            env,
            secrets_client=fake_secrets_unused,
            subprocess_run=fake_subprocess_run,
        )
        with open(os.path.join(tmp_home, ".claude.json")) as fh:
            invocation_trust_config = json.load(fh)
        record(result == report_row,
               "run_invocation returns the last parsed JSONL row", f"got={result}")
        record(
            invocation_trust_config.get("projects", {}).get("/opt/hacker-bob", {}).get("hasTrustDialogAccepted") is True,
            "run_invocation writes Claude workspace trust config before spawning Claude")
        record(
            "hacker-bob" in invocation_trust_config.get("projects", {}).get("/opt/hacker-bob", {}).get("enabledMcpjsonServers", []),
            "run_invocation writes Claude MCP approval before spawning Claude")
        record(len(fake_secrets_unused.calls) == 0,
               "run_invocation(bedrock) never calls secrets_client")
        # Regression test: nothing filters provider-specific keys out of the env
        # the subprocess actually receives (the anti-CLAUDE_CHILD_ENV_ALLOWLIST check).
        spawned_env = captured.get("env") or {}
        record(spawned_env.get("CLAUDE_CODE_USE_BEDROCK") == "1",
               "run_invocation passes CLAUDE_CODE_USE_BEDROCK through to the spawned env",
               f"spawned_env={spawned_env}")
        record(spawned_env.get("AWS_REGION") == "us-east-1",
               "run_invocation passes AWS_REGION through to the spawned env")
        record("--mcp-config" in captured["cmd"] and "/fake/mcp-config.json" in captured["cmd"],
               "run_invocation wires BOB_MCP_CONFIG into the claude invocation")
        record("--max-budget-usd" in captured["cmd"] and "2.00" in captured["cmd"],
               "run_invocation adds Claude Code's --max-budget-usd guard by default",
               f"cmd={captured['cmd']}")
        record("--append-system-prompt" in captured["cmd"]
               and MODULE.HEADLESS_MCP_READINESS_PROMPT in captured["cmd"],
               "run_invocation appends the headless MCP readiness instruction",
               f"cmd={captured['cmd']}")
        readiness_prompt = MODULE.HEADLESS_MCP_READINESS_PROMPT
        first_tool_search = 'query: "select:mcp__hacker-bob__bob_init_session"'
        record("call bob_init_session before any session-bound read" in readiness_prompt
               and first_tool_search in readiness_prompt
               and readiness_prompt.index(first_tool_search)
               < readiness_prompt.index("invoke the returned tool")
               and "not already loaded and directly callable" in readiness_prompt
               and "<exact_tool_name>" not in readiness_prompt
               and "is not authorization or proof of attestation" in readiness_prompt
               and "actual structured MCP result as the only authority truth" in readiness_prompt
               and "terminate/fail the invocation; never ask or propose setup" in readiness_prompt
               and "never replace it with a localhost slug" in readiness_prompt,
               "AgentCore headless prompt pins ToolSearch -> init, MCP authority, terminal attestation failure, and hostname semantics")
        record(captured["cmd"][-1] == "/bob-evaluate kyberfork.internal --normal",
               "run_invocation(resume=False) builds the non-resume skill prompt as the final arg")

        # Second call: resume=True, and zai provider this time, to check that
        # path's provider-specific keys also survive into the spawned env.
        captured2 = {}

        def fake_subprocess_run_2(cmd, env=None, check=None):
            captured2["cmd"] = cmd
            captured2["env"] = env
            os.makedirs(session_dir, exist_ok=True)
            with open(os.path.join(session_dir, "report-snapshots.jsonl"), "a") as fh:
                fh.write(json.dumps(report_row) + "\n")
            return None

        env_zai_run = {
            "HOME": tmp_home,
            "BOB_MCP_CONFIG": "/fake/mcp-config.json",
            "MODEL_PROVIDER": "zai",
            "ZAI_GATEWAY_URL": "https://zai.example.internal",
        }
        fake_secrets_zai_run = FakeSecretsClient(secret_string="fake-token-run")
        result2 = MODULE.run_invocation(
            {"target": target, "resume": True},
            env_zai_run,
            secrets_client=fake_secrets_zai_run,
            subprocess_run=fake_subprocess_run_2,
        )
        record(result2 == report_row, "run_invocation (zai, resume) returns parsed JSON")
        record(len(fake_secrets_zai_run.calls) == 1,
               "run_invocation (zai) calls secrets_client exactly once")
        spawned_env2 = captured2.get("env") or {}
        record(spawned_env2.get("ANTHROPIC_AUTH_TOKEN") == "fake-token-run",
               "run_invocation passes ANTHROPIC_AUTH_TOKEN through to the spawned env (zai)",
               f"spawned_env2={spawned_env2}")
        record(spawned_env2.get("ANTHROPIC_MODEL") == "glm-5.1",
               "run_invocation passes ANTHROPIC_MODEL=glm-5.1 through to the spawned env (zai)")
        record(captured2["cmd"][-1] == "/bob-evaluate resume kyberfork.internal",
               "run_invocation(resume=True) builds the resume skill prompt as the final arg")

        # provider unset defaults to Bedrock at run_invocation's own default layer.
        captured3 = {}

        def fake_subprocess_run_3(cmd, env=None, check=None):
            captured3["env"] = env
            os.makedirs(session_dir, exist_ok=True)
            with open(os.path.join(session_dir, "report-snapshots.jsonl"), "a") as fh:
                fh.write(json.dumps(report_row) + "\n")
            return None

        env_unset = {
            "HOME": tmp_home,
            "BOB_MCP_CONFIG": "/fake/mcp-config.json",
            # MODEL_PROVIDER deliberately absent
        }
        fake_secrets_default = FakeSecretsClient(secret_string="fake-default-token")
        MODULE.run_invocation(
            {"target": target}, env_unset,
            secrets_client=fake_secrets_default,
            subprocess_run=fake_subprocess_run_3,
        )
        record(len(fake_secrets_default.calls) == 0,
               "run_invocation with MODEL_PROVIDER unset defaults to Bedrock without a secret")
        record(captured3["env"].get("CLAUDE_CODE_USE_BEDROCK") == "1",
               "run_invocation with MODEL_PROVIDER unset enables Bedrock")

    with tempfile.TemporaryDirectory() as tmp_home:
        demo_url = "http://127.0.0.1:8081/repos/acme/demo/pulls/42"
        s3_puts = []

        class FakeS3:
            def put_object(self, **kwargs):
                s3_puts.append(kwargs)
                return {"VersionId": "fake-version"}

        class FakeResponse:
            status = 200
            def __enter__(self):
                return self
            def __exit__(self, exc_type, exc, tb):
                return False

        def fake_opener(url, timeout=5):
            record(url == "http://127.0.0.1:8081/healthz" and timeout == 5,
                   "run_demo_smoke checks the owned loopback fixture health endpoint")
            return FakeResponse()

        smoke_env = dict(os.environ)
        smoke_env.update({
            "HOME": tmp_home,
            "BOB_MCP_CONFIG": REAL_MCP_CONFIG_PATH,
            "BOB_GRADE_FREEZE_BUCKET": "fake-grade-freeze-bucket",
        })
        smoke_grade = MODULE.run_demo_smoke(
            {"target": demo_url, "stage": "GRADE"},
            smoke_env,
            s3_client=FakeS3(),
            opener=fake_opener,
        )
        smoke_session_dir = MODULE.resolve_session_dir(tmp_home, "127.0.0.1")
        record(smoke_grade.get("status") == "awaiting_verifier_gate"
               and smoke_grade.get("demo_smoke") is True
               and re.fullmatch(r"[0-9a-f]{64}", smoke_grade.get("grade_verdict_hash", ""))
               and smoke_grade.get("grade_freeze_version_id") == "fake-version"
               and smoke_grade.get("grade_freeze_bundle_sha256")
                   == hashlib.sha256(s3_puts[0]["Body"]).hexdigest(),
               "run_demo_smoke(GRADE) returns awaiting_verifier_gate with a real grade hash",
               f"result={smoke_grade!r}")
        record(os.path.exists(os.path.join(smoke_session_dir, "grade.json")),
               "run_demo_smoke(GRADE) persists grade.json under HOME-backed session dir")
        record(len(s3_puts) == 1
               and s3_puts[0]["Bucket"] == "fake-grade-freeze-bucket"
               and smoke_grade["grade_verdict_hash"] in s3_puts[0]["Key"]
               and b'"demo_smoke": true' in s3_puts[0]["Body"],
               "run_demo_smoke(GRADE) writes the S3 grade-freeze bundle")
        smoke_report = MODULE.run_demo_smoke(
            {"target": demo_url, "target_domain": "127.0.0.1", "stage": "REPORT", "resume": True},
            smoke_env,
            s3_client=FakeS3(),
            opener=fake_opener,
        )
        record(smoke_report.get("status") == "demo_report_ready"
               and smoke_report.get("grade_verdict_hash") == smoke_grade.get("grade_verdict_hash"),
               "run_demo_smoke(REPORT) resumes from persisted grade state")

    with tempfile.TemporaryDirectory() as tmp_home:
        class UnversionedFakeS3:
            def put_object(self, **kwargs):
                return {}

        unversioned_refused = False
        try:
            MODULE.run_demo_smoke(
                {"target": "http://127.0.0.1:8081/repos/acme/demo/pulls/42", "stage": "GRADE"},
                {
                    **os.environ,
                    "HOME": tmp_home,
                    "BOB_MCP_CONFIG": REAL_MCP_CONFIG_PATH,
                    "BOB_GRADE_FREEZE_BUCKET": "fake-grade-freeze-bucket",
                },
                s3_client=UnversionedFakeS3(),
                opener=fake_opener,
            )
        except RuntimeError as exc:
            unversioned_refused = "did not return an S3 VersionId" in str(exc)
        record(unversioned_refused,
               "demo grade freeze fails closed when S3 does not return an exact object VersionId")

    # --- disclosed libheif F-22 historical replay: immutable target lock,
    #     vulnerable/fixed semantic flip, WORM bundle, and deterministic report. ---
    with tempfile.TemporaryDirectory() as tmp_home:
        vulnerable_binary = os.path.join(tmp_home, "libheif-vulnerable")
        fixed_binary = os.path.join(tmp_home, "libheif-fixed")
        for path, payload in ((vulnerable_binary, b"vulnerable-binary"),
                              (fixed_binary, b"fixed-binary")):
            with open(path, "wb") as fh:
                fh.write(payload)
            os.chmod(path, 0o755)

        replay_calls = []

        def fake_replay_subprocess(cmd, env=None, capture_output=None, text=None,
                                   timeout=None, check=None):
            replay_calls.append({
                "cmd": cmd,
                "asan": (env or {}).get("ASAN_OPTIONS"),
                "capture_output": capture_output,
                "text": text,
                "timeout": timeout,
                "check": check,
            })

            class _Result:
                pass

            result = _Result()
            if cmd == [vulnerable_binary]:
                result.returncode = -6
                result.stdout = ""
                result.stderr = (
                    "ERROR: AddressSanitizer: heap-buffer-overflow\n"
                    "READ of size 2\n"
                    "#11 /src/libheif/libheif/codecs/uncompressed/unc_decoder.cc:178\n"
                )
            elif cmd == [fixed_binary]:
                result.returncode = 0
                result.stdout = ""
                result.stderr = "returned error? 1 output=0\n"
            else:  # pragma: no cover - a path override would be a security regression
                raise AssertionError(f"unexpected replay command: {cmd!r}")
            return result

        replay_s3_puts = []

        class ReplayFakeS3:
            def put_object(self, **kwargs):
                replay_s3_puts.append(kwargs)
                return {"VersionId": "replay-version-1"}

        replay_env = dict(os.environ)
        replay_env.update({
            "HOME": tmp_home,
            "BOB_MCP_CONFIG": REAL_MCP_CONFIG_PATH,
            "BOB_GRADE_FREEZE_BUCKET": "fake-grade-freeze-bucket",
            "BOB_AGENTCORE": "1",
            "BOB_APPROVAL_ARTIFACT_DIR": os.path.join(tmp_home, "approvals"),
            "BOB_APPROVAL_HMAC_KEY": "test-replay-approval-key",
        })
        replay_grade = MODULE.run_libheif_historical_replay(
            {
                "fixture_id": MODULE.LIBHEIF_REPLAY_FIXTURE_ID,
                "stage": "GRADE",
            },
            replay_env,
            s3_client=ReplayFakeS3(),
            subprocess_run=fake_replay_subprocess,
            binary_paths={
                "vulnerable": vulnerable_binary,
                "fixed": fixed_binary,
            },
        )
        record(replay_grade.get("status") == "awaiting_verifier_gate"
               and replay_grade.get("reportable_finding_ids") == ["F-22"]
               and replay_grade.get("rediscovery") is False
               and re.fullmatch(r"[0-9a-f]{64}", replay_grade.get("grade_verdict_hash", ""))
               and replay_grade.get("grade_freeze_version_id") == "replay-version-1"
               and replay_grade.get("grade_freeze_bundle_sha256")
                   == hashlib.sha256(replay_s3_puts[0]["Body"]).hexdigest(),
               "libheif historical replay returns a content-bound F-22 verifier payload",
               f"result={replay_grade!r}")
        record(len(replay_calls) == 2
               and all(call["asan"] == "detect_leaks=0:halt_on_error=1" for call in replay_calls)
               and all(call["timeout"] == 10 and call["check"] is False for call in replay_calls),
               "libheif replay executes only the two sealed binaries under a bounded sanitizer contract",
               f"calls={replay_calls!r}")
        frozen_bundle = json.loads(replay_s3_puts[0]["Body"])
        record(len(replay_s3_puts) == 1
               and frozen_bundle["reportable_finding_ids"] == ["F-22"]
               and frozen_bundle["findings"][0]["source"]["vulnerable_commit"] == MODULE.LIBHEIF_VULNERABLE_COMMIT
               and frozen_bundle["findings"][0]["source"]["exact_fix_commit"] == MODULE.LIBHEIF_EXACT_FIX_COMMIT
               and frozen_bundle["fixture_receipt"]["rediscovery"] is False
               and frozen_bundle["fixture_receipt"]["original_run_at"] == MODULE.LIBHEIF_ORIGINAL_RUN_AT
               and frozen_bundle["fixture_receipt"]["original_command_sha256"] == MODULE.LIBHEIF_ORIGINAL_COMMAND_SHA256
               and frozen_bundle["fixture_receipt"]["semantic_proof"] == {
                   "bug_type": "heap-buffer-overflow",
                   "access": "READ of size 2",
                   "source_frame": "libheif/codecs/uncompressed/unc_decoder.cc:178",
                   "vulnerable_signal_confirmed": True,
                   "fixed_marker": "returned error? 1 output=0",
                   "fixed_sanitizer_clean": True,
               }
               and all(isinstance(frozen_bundle["fixture_receipt"][label]["duration_ms"], int)
                       for label in ("vulnerable", "fixed")),
               "libheif replay freezes the immutable vulnerable/fix identities and one reportable finding")
        frozen_grade = frozen_bundle["grade"]
        frozen_finding_grade = frozen_grade["findings"][0]
        record(frozen_grade.get("score_origin") == "historical_import"
               and frozen_grade.get("original_run_id") == MODULE.LIBHEIF_ORIGINAL_RUN_ID
               and frozen_grade.get("replay_verified_at") == frozen_grade.get("graded_at")
               and frozen_finding_grade.get("historical_session_severity") == "high"
               and frozen_finding_grade.get("severity_origin") == "published_advisory"
               and [frozen_finding_grade.get(field) for field in (
                   "impact", "proof_quality", "severity_accuracy", "chain_potential", "report_quality",
               )] == [24, 24, 14, 0, 14]
               and frozen_finding_grade.get("feedback")
                   == "Strong crafted-HEIF OOB read evidence with file-controlled offsets, source sink, and sanitizer replay.",
               "libheif replay identifies the 76 score as a historical import and preserves its exact axes")
        record("AddressSanitizer: heap-buffer-overflow" not in replay_s3_puts[0]["Body"].decode("utf-8"),
               "libheif WORM bundle stores output hashes rather than raw sanitizer logs")

        approval_target_dir = os.path.join(
            replay_env["BOB_APPROVAL_ARTIFACT_DIR"],
            MODULE.LIBHEIF_REPLAY_TARGET_DOMAIN,
        )
        os.makedirs(approval_target_dir, exist_ok=True)
        approval_binding = [
            MODULE.LIBHEIF_REPLAY_FIXTURE_ID,
            MODULE.LIBHEIF_REPLAY_TARGET_DOMAIN,
            replay_grade["grade_verdict_hash"],
            replay_grade["grade_freeze_bundle_sha256"],
            replay_grade["grade_freeze_version_id"],
        ]
        approval_signature = hmac.new(
            replay_env["BOB_APPROVAL_HMAC_KEY"].encode("utf-8"),
            json.dumps(approval_binding, separators=(",", ":"), ensure_ascii=False).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        with open(os.path.join(
            approval_target_dir,
            f"{replay_grade['grade_verdict_hash']}.approved",
        ), "w") as fh:
            json.dump({
                "schema_version": 2,
                "binding_version": "grade-freeze-v2",
                "profile": MODULE.LIBHEIF_REPLAY_FIXTURE_ID,
                "target_domain": MODULE.LIBHEIF_REPLAY_TARGET_DOMAIN,
                "hmac": approval_signature,
                "grade_verdict_hash": replay_grade["grade_verdict_hash"],
                "grade_freeze_bundle_sha256": replay_grade["grade_freeze_bundle_sha256"],
                "grade_freeze_version_id": replay_grade["grade_freeze_version_id"],
            }, fh)
        replay_report = MODULE.run_libheif_historical_replay(
            {
                "fixture_id": MODULE.LIBHEIF_REPLAY_FIXTURE_ID,
                "stage": "REPORT",
            },
            replay_env,
            s3_client=ReplayFakeS3(),
            binary_paths={
                "vulnerable": vulnerable_binary,
                "fixed": fixed_binary,
            },
        )
        record(replay_report.get("status") == "historical_replay_report_ready"
               and replay_report.get("grade_verdict_hash") == replay_grade.get("grade_verdict_hash")
               and replay_report.get("rediscovery") is False,
               "libheif historical replay REPORT resumes only after the content-bound approval without rerunning binaries")

    with tempfile.TemporaryDirectory() as tmp_home:
        session_dir = MODULE.resolve_session_dir(tmp_home, MODULE.LIBHEIF_REPLAY_TARGET_DOMAIN)
        _write_grade_json(session_dir, MODULE.LIBHEIF_REPLAY_TARGET_DOMAIN)
        withheld = False
        try:
            MODULE.run_libheif_historical_replay(
                {"fixture_id": MODULE.LIBHEIF_REPLAY_FIXTURE_ID, "stage": "REPORT"},
                {
                    **os.environ,
                    "HOME": tmp_home,
                    "BOB_MCP_CONFIG": REAL_MCP_CONFIG_PATH,
                    "BOB_AGENTCORE": "1",
                    "BOB_APPROVAL_ARTIFACT_DIR": os.path.join(tmp_home, "missing-approvals"),
                    "BOB_APPROVAL_HMAC_KEY": "test-replay-approval-key",
                },
            )
        except RuntimeError as exc:
            withheld = "REPORT remains withheld" in str(exc)
        record(withheld,
               "libheif deterministic REPORT fails closed when the content-bound approval artifact is absent")

    with tempfile.TemporaryDirectory() as tmp_home:
        bad_lock_path = os.path.join(tmp_home, "target.lock.json")
        with open(os.path.join(
            REPO_ROOT, "infra", "runner", "demo-targets",
            "libheif-cve-2026-49271", "target.lock.json",
        )) as fh:
            bad_lock = json.load(fh)
        bad_lock["source_pins"]["vulnerable"]["commit"] = "0" * 40
        with open(bad_lock_path, "w") as fh:
            json.dump(bad_lock, fh)
        drift_refused = False
        try:
            MODULE._load_and_validate_libheif_lock(lock_path=bad_lock_path)
        except RuntimeError:
            drift_refused = True
        record(drift_refused,
               "libheif replay refuses a target lock whose vulnerable pin drifted from image code")

    with open(DOCKERFILE_PATH) as fh:
        dockerfile = fh.read()
    record(MODULE.LIBHEIF_HARNESS_SHA256 in dockerfile
           and "'/fixture/icef_oob.cc'" in dockerfile
           and "sha256sum --check --strict" in dockerfile,
           "runner image build fails closed unless the copied replay harness matches its pinned SHA-256")

    unknown_fixture_refused = False
    try:
        MODULE.run_invocation(
            {"fixture_id": "operator-supplied-commit", "stage": "GRADE"},
            {"HOME": "/tmp/unused"},
        )
    except ValueError:
        unknown_fixture_refused = True
    record(unknown_fixture_refused,
           "run_invocation rejects unknown fixture ids before accepting a target or commit override")

    ambiguous_fixture_refused = False
    try:
        MODULE.run_invocation(
            {
                "fixture_id": MODULE.LIBHEIF_REPLAY_FIXTURE_ID,
                "demo_smoke": True,
                "stage": "GRADE",
            },
            {"HOME": "/tmp/unused"},
        )
    except ValueError:
        ambiguous_fixture_refused = True
    record(ambiguous_fixture_refused,
           "run_invocation refuses ambiguous demo_smoke plus historical fixture input")

    with tempfile.TemporaryDirectory() as tmp_home:
        target = "kyberfork.internal"
        session_dir = MODULE.resolve_session_dir(tmp_home, target)
        os.makedirs(session_dir, exist_ok=True)
        stale_row = {"status": "stale", "target_domain": target, "seal": "old"}
        with open(os.path.join(session_dir, "report-snapshots.jsonl"), "w") as fh:
            fh.write(json.dumps(stale_row) + "\n")

        def fake_subprocess_run_no_write(cmd, env=None, check=None):
            return None

        stale_guard_raised = False
        stale_guard_detail = ""
        try:
            MODULE.run_invocation(
                {"target": target, "resume": False},
                {
                    "HOME": tmp_home,
                    "BOB_MCP_CONFIG": "/fake/mcp-config.json",
                    "MODEL_PROVIDER": "bedrock",
                },
                secrets_client=FakeSecretsClient(),
                subprocess_run=fake_subprocess_run_no_write,
            )
        except RuntimeError as e:
            stale_guard_raised = True
            stale_guard_detail = str(e)
        except Exception as e:  # pragma: no cover - defensive, should not happen
            stale_guard_detail = f"raised {type(e).__name__}: {e}"
        record(stale_guard_raised and session_dir in stale_guard_detail,
               "run_invocation raises instead of returning a stale report row",
               f"detail={stale_guard_detail!r}")

    # --- (f1-verifier-gate wiring g) STAGE-AWARE clean stop: a GRADE-stage call that writes no NEW
    #     report-snapshot row is not an error -- it is the expected shape of a session withheld at
    #     the automated verifier gate -- returns {"status": "awaiting_verifier_gate", ...} instead of
    #     raising, but ONLY when BOB_AGENTCORE == "1" (wave 2 gating). The REPORT-stage (and
    #     no-stage-key, for backward compat -- see the block above) RuntimeError guard is
    #     untouched. ---
    with tempfile.TemporaryDirectory() as tmp_home:
        target = "kyberfork.internal"
        session_dir = MODULE.resolve_session_dir(tmp_home, target)
        os.makedirs(session_dir, exist_ok=True)
        stale_row = {"status": "stale", "target_domain": target, "seal": "old"}
        with open(os.path.join(session_dir, "report-snapshots.jsonl"), "w") as fh:
            fh.write(json.dumps(stale_row) + "\n")

        def fake_subprocess_run_grade_no_write(cmd, env=None, check=None):
            return None  # deliberately writes nothing new -- awaiting verifier gate, not broken

        grade_result = None
        grade_raised = False
        grade_detail = ""
        try:
            grade_result = MODULE.run_invocation(
                {"target": target, "stage": "GRADE"},
                {
                    "HOME": tmp_home,
                    "BOB_MCP_CONFIG": "/fake/mcp-config.json",
                    "MODEL_PROVIDER": "bedrock",
                    "BOB_AGENTCORE": "1",
                },
                secrets_client=FakeSecretsClient(),
                subprocess_run=fake_subprocess_run_grade_no_write,
            )
        except Exception as e:
            grade_raised = True
            grade_detail = f"raised {type(e).__name__}: {e}"
        # A missing grade hash must never create an unapprovable pending record.
        record(
            grade_raised and "without a grade verdict" in grade_detail,
            "run_invocation(stage=GRADE) refuses to request verifier attestation when no grade hash exists",
            f"raised={grade_raised} detail={grade_detail!r} got={grade_result}")

    # --- fx-hmac-content: grade_verdict_hash is populated from a REAL grade.json fixture, and
    #     the value is pinned against an INDEPENDENTLY computed reference (a companion node
    #     subprocess calling mcp/lib/report-finalize.js's loadGradeVerdictHash directly) to
    #     guard cross-language (Python entrypoint <-> Node report-finalize.js) parity. ---
    with tempfile.TemporaryDirectory() as tmp_home:
        target = "kyberfork.internal"
        session_dir = MODULE.resolve_session_dir(tmp_home, target)
        os.makedirs(session_dir, exist_ok=True)
        stale_row = {"status": "stale", "target_domain": target, "seal": "old"}
        with open(os.path.join(session_dir, "report-snapshots.jsonl"), "w") as fh:
            fh.write(json.dumps(stale_row) + "\n")
        _write_grade_json(session_dir, target)

        def fake_subprocess_run_grade_with_verdict(cmd, env=None, check=None):
            return None  # deliberately writes nothing new -- awaiting verifier gate, not broken

        # Base on the REAL os.environ (unlike the hand-built minimal env dicts elsewhere in this
        # file) so PATH is present -- _load_grade_verdict_hash's node shellout is the REAL
        # subprocess.run (never the injected fake), so `node` must actually resolve on PATH here,
        # matching how run_invocation's own production call site (invoke()) always passes
        # dict(os.environ).
        entrypoint_env = dict(os.environ)
        entrypoint_env.update({
            "HOME": tmp_home,
            "BOB_MCP_CONFIG": REAL_MCP_CONFIG_PATH,
            "MODEL_PROVIDER": "bedrock",
            "BOB_AGENTCORE": "1",
        })
        grade_result_with_hash = None
        grade_with_hash_raised = False
        grade_with_hash_detail = ""
        try:
            grade_result_with_hash = MODULE.run_invocation(
                {"target": target, "stage": "GRADE"},
                entrypoint_env,
                secrets_client=FakeSecretsClient(),
                subprocess_run=fake_subprocess_run_grade_with_verdict,
            )
        except Exception as e:
            grade_with_hash_raised = True
            grade_with_hash_detail = f"raised {type(e).__name__}: {e}"

        independent_hash = None
        independent_hash_error = ""
        try:
            # os.environ carries PATH so `node` resolves; only HOME needs to be the fixture home.
            independent_env = dict(os.environ)
            independent_env["HOME"] = tmp_home
            independent_hash = _independent_grade_verdict_hash(target, independent_env)
        except Exception as e:  # pragma: no cover - node must be on PATH in this dev/CI environment
            independent_hash_error = f"{type(e).__name__}: {e}"

        record(
            not grade_with_hash_raised
            and grade_result_with_hash is not None
            and grade_result_with_hash.get("status") == "awaiting_verifier_gate"
            and grade_result_with_hash.get("grade_verdict_hash") is not None,
            "run_invocation(stage=GRADE, real grade.json fixture) returns a non-None "
            "grade_verdict_hash",
            f"raised={grade_with_hash_raised} detail={grade_with_hash_detail!r} "
            f"got={grade_result_with_hash}")
        record(
            independent_hash_error == "" and independent_hash is not None,
            "companion node subprocess independently resolves loadGradeVerdictHash for the "
            "fixture (sanity: node must be reachable to pin parity)",
            f"error={independent_hash_error!r}")
        if grade_result_with_hash is not None and independent_hash:
            record(
                grade_result_with_hash.get("grade_verdict_hash") == independent_hash,
                "run_invocation's grade_verdict_hash matches the independently-computed "
                "reference (cross-language parity, entrypoint bridge vs report-finalize.js)",
                f"entrypoint={grade_result_with_hash.get('grade_verdict_hash')!r} "
                f"independent={independent_hash!r}")

    # --- fx-hmac-content: no grade.json means the workflow has not reached GRADE and must
    #     fail before emitting a verifier attestation request. ---
    with tempfile.TemporaryDirectory() as tmp_home:
        target = "kyberfork.internal"
        session_dir = MODULE.resolve_session_dir(tmp_home, target)
        os.makedirs(session_dir, exist_ok=True)
        stale_row = {"status": "stale", "target_domain": target, "seal": "old"}
        with open(os.path.join(session_dir, "report-snapshots.jsonl"), "w") as fh:
            fh.write(json.dumps(stale_row) + "\n")
        # Deliberately NO _write_grade_json call here.

        def fake_subprocess_run_grade_no_verdict(cmd, env=None, check=None):
            return None

        no_verdict_env = dict(os.environ)
        no_verdict_env.update({
            "HOME": tmp_home,
            "BOB_MCP_CONFIG": REAL_MCP_CONFIG_PATH,
            "MODEL_PROVIDER": "bedrock",
            "BOB_AGENTCORE": "1",
        })
        grade_result_no_verdict = None
        grade_no_verdict_raised = False
        grade_no_verdict_detail = ""
        try:
            grade_result_no_verdict = MODULE.run_invocation(
                {"target": target, "stage": "GRADE"},
                no_verdict_env,
                secrets_client=FakeSecretsClient(),
                subprocess_run=fake_subprocess_run_grade_no_verdict,
            )
        except Exception as e:
            grade_no_verdict_raised = True
            grade_no_verdict_detail = f"raised {type(e).__name__}: {e}"
        record(
            grade_no_verdict_raised and "without a grade verdict" in grade_no_verdict_detail,
            "run_invocation(stage=GRADE, real BOB_MCP_CONFIG but no grade.json) fails closed",
            f"raised={grade_no_verdict_raised} detail={grade_no_verdict_detail!r} "
            f"got={grade_result_no_verdict}")

    # --- (f1-verifier-gate wave-2 b) STAGE-AWARE clean stop, inert-by-default companion: the
    #     identical stale-row/no-new-row GRADE-stage setup as above, but with BOB_AGENTCORE
    #     unset -- must still raise RuntimeError exactly as it did before the STAGE-AWARE change
    #     existed (mirrors the inert-by-default pattern used for the producer test below). ---
    with tempfile.TemporaryDirectory() as tmp_home:
        target = "kyberfork.internal"
        session_dir = MODULE.resolve_session_dir(tmp_home, target)
        os.makedirs(session_dir, exist_ok=True)
        stale_row = {"status": "stale", "target_domain": target, "seal": "old"}
        with open(os.path.join(session_dir, "report-snapshots.jsonl"), "w") as fh:
            fh.write(json.dumps(stale_row) + "\n")

        def fake_subprocess_run_grade_no_write_inert(cmd, env=None, check=None):
            return None  # deliberately writes nothing new

        grade_inert_raised = False
        grade_inert_detail = ""
        try:
            MODULE.run_invocation(
                {"target": target, "stage": "GRADE"},
                {
                    "HOME": tmp_home,
                    "BOB_MCP_CONFIG": "/fake/mcp-config.json",
                    "MODEL_PROVIDER": "bedrock",
                    # BOB_AGENTCORE deliberately absent.
                },
                secrets_client=FakeSecretsClient(),
                subprocess_run=fake_subprocess_run_grade_no_write_inert,
            )
        except RuntimeError as e:
            grade_inert_raised = True
            grade_inert_detail = str(e)
        except Exception as e:  # pragma: no cover - defensive, should not happen
            grade_inert_detail = f"raised {type(e).__name__}: {e}"
        record(grade_inert_raised and session_dir in grade_inert_detail,
               "run_invocation(stage=GRADE) still raises RuntimeError when BOB_AGENTCORE != \"1\" "
               "(inert by default)",
               f"detail={grade_inert_detail!r}")

    # --- fx-gate-hardening (P0-1): the model-writable-artifact PRODUCER is REMOVED. A
    #     resume=True + approvalToken-bearing invocation must behave IDENTICALLY to a plain
    #     resume=True invocation -- no filesystem side effect tied to approvalToken exists
    #     anywhere in this module anymore, regardless of BOB_AGENTCORE or
    #     BOB_APPROVAL_ARTIFACT_DIR. This directly guards against the vulnerability this whole
    #     node fixes: the model could reach this code path in the old design and forge its own
    #     attestation by simply setting approvalToken + resume=True in ITS OWN payload (both
    #     attacker-observable/replayable shapes) while running as its own execution role. ---
    with tempfile.TemporaryDirectory() as tmp_home, tempfile.TemporaryDirectory() as tmp_artifacts:
        target = "kyberfork.internal"
        session_dir = MODULE.resolve_session_dir(tmp_home, target)
        report_row = {"status": "published", "target_domain": target, "seal": "resumed"}

        def fake_subprocess_run_resume(cmd, env=None, check=None):
            os.makedirs(session_dir, exist_ok=True)
            with open(os.path.join(session_dir, "report-snapshots.jsonl"), "w") as fh:
                fh.write(json.dumps(report_row) + "\n")
            return None

        MODULE.run_invocation(
            {"target": target, "resume": True, "stage": "REPORT", "approvalToken": "task-token-abc"},
            {
                "HOME": tmp_home,
                "BOB_MCP_CONFIG": "/fake/mcp-config.json",
                "MODEL_PROVIDER": "bedrock",
                "BOB_AGENTCORE": "1",
                # A model-controlled attempt to resurrect the old producer's trigger condition:
                # even with this set, nothing in run_invocation reads it anymore.
                "BOB_APPROVAL_ARTIFACT_DIR": tmp_artifacts,
            },
            secrets_client=FakeSecretsClient(),
            subprocess_run=fake_subprocess_run_resume,
        )
        record(os.listdir(tmp_artifacts) == [],
               "run_invocation(resume=True, approvalToken=<forged>) writes NOTHING into "
               "BOB_APPROVAL_ARTIFACT_DIR -- the producer that used to write "
               "<target_domain>.approved from inside the model's own execution role is gone",
               f"tmp_artifacts contents={os.listdir(tmp_artifacts)}")

    # --- P1-8 / fx-gate-hardening: dedicated port-stripping test -- a with-port target
    #     (KyberFork-shaped, "10.0.0.5:8545") must resolve_session_dir AND build the
    #     resume-skill-prompt argument using the port-STRIPPED host "10.0.0.5" -- the exact
    #     target_domain form the approval-gate consumers (bob-approval-gate-impl.py,
    #     lifecycle-gates.js) and mcp/lib/scope.js's lab-target attestation key by. Using the
    #     raw with-port string for either would silently desync the session/resume identity
    #     from what those consumers expect. ---
    with tempfile.TemporaryDirectory() as tmp_home:
        raw_target = "10.0.0.5:8545"
        port_stripped_session_dir = MODULE.resolve_session_dir(tmp_home, "10.0.0.5")
        wrong_session_dir = MODULE.resolve_session_dir(tmp_home, raw_target)
        report_row = {"status": "published", "target_domain": "10.0.0.5", "seal": "port-stripped"}

        captured_cmd = {}

        def fake_subprocess_run_port_stripped(cmd, env=None, check=None):
            captured_cmd["cmd"] = cmd
            os.makedirs(port_stripped_session_dir, exist_ok=True)
            with open(os.path.join(port_stripped_session_dir, "report-snapshots.jsonl"), "w") as fh:
                fh.write(json.dumps(report_row) + "\n")
            return None

        MODULE.run_invocation(
            {"target": raw_target, "resume": True, "stage": "REPORT"},
            {
                "HOME": tmp_home,
                "BOB_MCP_CONFIG": "/fake/mcp-config.json",
                "MODEL_PROVIDER": "bedrock",
                "BOB_AGENTCORE": "1",
            },
            secrets_client=FakeSecretsClient(),
            subprocess_run=fake_subprocess_run_port_stripped,
        )
        record(os.path.isdir(port_stripped_session_dir),
               "run_invocation(target='10.0.0.5:8545') resolves the session dir to the "
               "port-stripped host '10.0.0.5'",
               f"expected dir to exist: {port_stripped_session_dir}")
        record(not os.path.isdir(wrong_session_dir),
               "run_invocation(target='10.0.0.5:8545') does NOT use the raw-with-port session dir",
               f"unexpectedly exists: {wrong_session_dir}")
        record(captured_cmd.get("cmd", [None])[-1] == "/bob-evaluate resume 10.0.0.5",
               "run_invocation(resume=True, target='10.0.0.5:8545') builds the resume skill "
               "prompt with the port-STRIPPED host, not '10.0.0.5:8545'",
               f"got={captured_cmd.get('cmd')}")
        record(MODULE._port_stripped_host("10.0.0.5:8545") == "10.0.0.5",
               "_port_stripped_host strips a trailing :<port> suffix")
        record(MODULE._port_stripped_host("10.0.0.5") == "10.0.0.5",
               "_port_stripped_host is a no-op on a host with no port suffix")

    # --- fx-gate-bypass defense 4 (HIGH — CAIP-10 target handling): a payload carrying
    #     an engine-derived target_domain (the SFN Lambda computes this ONCE, upstream,
    #     from state.json's already-derived sc-<family>-<chainId>-<addr8>-<hash8> slug --
    #     see mcp/lib/tools/init-contract-session.js's deriveContractTargetDomain) must be
    #     used BYTE-FOR-BYTE by resolve_session_dir/run_invocation, taking precedence over
    #     the RFC1918/port-stripped derivation entirely -- mirrors the port-stripping
    #     fixture's own assertion style directly above. ---
    with tempfile.TemporaryDirectory() as tmp_home:
        caip10_domain = "sc-evm-1-a1b2c3d4-e5f6a7b8"
        raw_target = "10.0.0.9:8545"  # the underlying anvil endpoint -- NOT the session key here
        caip10_session_dir = MODULE.resolve_session_dir(tmp_home, caip10_domain)
        wrong_rfc1918_session_dir = MODULE.resolve_session_dir(tmp_home, MODULE._port_stripped_host(raw_target))
        report_row = {"status": "published", "target_domain": caip10_domain, "seal": "caip10"}

        captured_cmd = {}

        def fake_subprocess_run_caip10(cmd, env=None, check=None):
            captured_cmd["cmd"] = cmd
            os.makedirs(caip10_session_dir, exist_ok=True)
            with open(os.path.join(caip10_session_dir, "report-snapshots.jsonl"), "w") as fh:
                fh.write(json.dumps(report_row) + "\n")
            return None

        MODULE.run_invocation(
            {"target": raw_target, "target_domain": caip10_domain, "resume": True, "stage": "REPORT"},
            {
                "HOME": tmp_home,
                "BOB_MCP_CONFIG": "/fake/mcp-config.json",
                "MODEL_PROVIDER": "bedrock",
                "BOB_AGENTCORE": "1",
            },
            secrets_client=FakeSecretsClient(),
            subprocess_run=fake_subprocess_run_caip10,
        )
        record(os.path.isdir(caip10_session_dir),
               "run_invocation(payload target_domain=CAIP-10 slug) resolves the session dir to "
               "the engine-derived target_domain byte-for-byte",
               f"expected dir to exist: {caip10_session_dir}")
        record(not os.path.isdir(wrong_rfc1918_session_dir),
               "run_invocation(payload target_domain=CAIP-10 slug) does NOT fall back to the "
               "RFC1918/port-stripped derivation of payload['target']",
               f"unexpectedly exists: {wrong_rfc1918_session_dir}")
        record(captured_cmd.get("cmd", [None])[-1] == f"/bob-evaluate resume {caip10_domain}",
               "run_invocation(resume=True, payload target_domain=CAIP-10 slug) builds the resume "
               "skill prompt with the CAIP-10 target_domain, not the raw target",
               f"got={captured_cmd.get('cmd')}")

    # --- fx-gate-bypass defense 4 companion: an ABSENT payload target_domain must still
    #     fall back to the existing RFC1918/port-stripped derivation byte-for-byte
    #     (regression guard: defense 4 must not change behavior for the pre-existing
    #     KyberFork-anvil/Locker web-target payload shape that carries no target_domain). ---
    with tempfile.TemporaryDirectory() as tmp_home:
        raw_target = "10.0.0.5:8545"
        expected_session_dir = MODULE.resolve_session_dir(tmp_home, "10.0.0.5")
        report_row = {"status": "published", "target_domain": "10.0.0.5", "seal": "fallback"}

        def fake_subprocess_run_no_target_domain(cmd, env=None, check=None):
            os.makedirs(expected_session_dir, exist_ok=True)
            with open(os.path.join(expected_session_dir, "report-snapshots.jsonl"), "w") as fh:
                fh.write(json.dumps(report_row) + "\n")
            return None

        MODULE.run_invocation(
            {"target": raw_target, "resume": False, "stage": "REPORT"},
            {
                "HOME": tmp_home,
                "BOB_MCP_CONFIG": "/fake/mcp-config.json",
                "MODEL_PROVIDER": "bedrock",
                "BOB_AGENTCORE": "1",
            },
            secrets_client=FakeSecretsClient(),
            subprocess_run=fake_subprocess_run_no_target_domain,
        )
        record(os.path.isdir(expected_session_dir),
               "run_invocation with NO payload target_domain still falls back to the "
               "RFC1918/port-stripped derivation (defense 4 does not change this shape)",
               f"expected dir to exist: {expected_session_dir}")

    # --- fx-gate-bypass defense 2: mint-and-inject the per-invocation caller-auth token
    #     into a FRESH copy of a REAL mcp-config JSON, passed to `claude --mcp-config`
    #     INSTEAD OF the raw BOB_MCP_CONFIG path -- the original file is left untouched,
    #     and the copy's mcpServers.hacker-bob.env carries the freshly-minted 64-lowercase-
    #     hex token (never hardcoded/logged; each invocation mints its own). ---
    with tempfile.TemporaryDirectory() as tmp_home, tempfile.TemporaryDirectory() as tmp_config_dir:
        target = "kyberfork.internal"
        session_dir = MODULE.resolve_session_dir(tmp_home, target)
        report_row = {"status": "published", "target_domain": target, "seal": "caller-auth"}

        real_mcp_config_path = os.path.join(tmp_config_dir, "mcp-config.json")
        original_config = {
            "mcpServers": {
                "hacker-bob": {
                    "command": "node",
                    "args": ["/opt/hacker-bob/mcp/server.js"],
                    "env": {"SOME_EXISTING_VAR": "keep-me"},
                },
            },
        }
        with open(real_mcp_config_path, "w") as fh:
            json.dump(original_config, fh)

        captured_cmd = {}

        def fake_subprocess_run_caller_auth(cmd, env=None, check=None):
            captured_cmd["cmd"] = cmd
            spawned_path = cmd[cmd.index("--mcp-config") + 1]
            with open(spawned_path) as fh:
                captured_cmd["spawned_config"] = json.load(fh)
            os.makedirs(session_dir, exist_ok=True)
            with open(os.path.join(session_dir, "report-snapshots.jsonl"), "w") as fh:
                fh.write(json.dumps(report_row) + "\n")
            return None

        MODULE.run_invocation(
            {"target": target, "resume": False, "stage": "REPORT"},
            {
                "HOME": tmp_home,
                "BOB_MCP_CONFIG": real_mcp_config_path,
                "MODEL_PROVIDER": "bedrock",
            },
            secrets_client=FakeSecretsClient(),
            subprocess_run=fake_subprocess_run_caller_auth,
        )

        mcp_config_flag_index = captured_cmd["cmd"].index("--mcp-config")
        spawned_config_path = captured_cmd["cmd"][mcp_config_flag_index + 1]
        record(spawned_config_path != real_mcp_config_path,
               "run_invocation passes a FRESH per-invocation config path to --mcp-config, "
               "not the raw BOB_MCP_CONFIG path",
               f"spawned_config_path={spawned_config_path!r}")

        with open(real_mcp_config_path) as fh:
            original_on_disk = json.load(fh)
        record(original_on_disk == original_config,
               "the ORIGINAL mcp-config.json on disk is left byte-for-byte untouched",
               f"got={original_on_disk}")

        spawned_config = captured_cmd.get("spawned_config", {})
        spawned_env = spawned_config.get("mcpServers", {}).get("hacker-bob", {}).get("env", {})
        token = spawned_env.get("BOB_MCP_CALLER_TOKEN")
        record(isinstance(token, str) and re.fullmatch(r"[0-9a-f]{64}", token) is not None,
               "the spawned per-invocation config injects a well-formed 64-lowercase-hex "
               "BOB_MCP_CALLER_TOKEN into mcpServers.hacker-bob.env",
               f"token={token!r}")
        record(spawned_env.get("SOME_EXISTING_VAR") == "keep-me",
               "pre-existing mcpServers.hacker-bob.env entries survive the token injection",
               f"spawned_env={spawned_env}")
        record(not os.path.exists(spawned_config_path),
               "run_invocation removes the per-invocation mcp-config after the subprocess exits",
               f"spawned_config_path={spawned_config_path!r}")

        # A second invocation mints a DIFFERENT token (never reused across invocations).
        captured_cmd2 = {}

        def fake_subprocess_run_caller_auth_2(cmd, env=None, check=None):
            captured_cmd2["cmd"] = cmd
            spawned_path = cmd[cmd.index("--mcp-config") + 1]
            with open(spawned_path) as fh:
                captured_cmd2["spawned_config"] = json.load(fh)
            with open(os.path.join(session_dir, "report-snapshots.jsonl"), "a") as fh:
                fh.write(json.dumps(report_row) + "\n")
            return None

        MODULE.run_invocation(
            {"target": target, "resume": True, "stage": "REPORT"},
            {
                "HOME": tmp_home,
                "BOB_MCP_CONFIG": real_mcp_config_path,
                "MODEL_PROVIDER": "bedrock",
            },
            secrets_client=FakeSecretsClient(),
            subprocess_run=fake_subprocess_run_caller_auth_2,
        )
        spawned_config_path_2 = captured_cmd2["cmd"][captured_cmd2["cmd"].index("--mcp-config") + 1]
        token2 = captured_cmd2["spawned_config"]["mcpServers"]["hacker-bob"]["env"]["BOB_MCP_CALLER_TOKEN"]
        record(token2 != token,
               "each invocation mints a fresh, distinct caller-auth token",
               f"token={token!r} token2={token2!r}")
        record(not os.path.exists(spawned_config_path_2),
               "run_invocation removes each fresh mcp-config after use",
               f"spawned_config_path_2={spawned_config_path_2!r}")

    # --- fx-gate-bypass defense 2 companion: a malformed/missing BOB_MCP_CONFIG must not
    #     hard-fail the invocation -- _write_caller_auth_mcp_config degrades gracefully by
    #     passing the ORIGINAL path through unchanged (this is defense-in-depth, not the
    #     root of trust; see the function's own docstring). Regression guard: this is the
    #     exact shape ("/fake/mcp-config.json", a path that does not exist on disk) every
    #     other fixture in this file already relies on continuing to work unchanged. ---
    with tempfile.TemporaryDirectory() as tmp_home:
        target = "kyberfork.internal"
        session_dir = MODULE.resolve_session_dir(tmp_home, target)
        report_row = {"status": "published", "target_domain": target, "seal": "fallback-config"}

        captured_cmd = {}

        def fake_subprocess_run_fallback(cmd, env=None, check=None):
            captured_cmd["cmd"] = cmd
            os.makedirs(session_dir, exist_ok=True)
            with open(os.path.join(session_dir, "report-snapshots.jsonl"), "w") as fh:
                fh.write(json.dumps(report_row) + "\n")
            return None

        MODULE.run_invocation(
            {"target": target, "resume": False, "stage": "REPORT"},
            {
                "HOME": tmp_home,
                "BOB_MCP_CONFIG": "/fake/mcp-config.json",
                "MODEL_PROVIDER": "bedrock",
            },
            secrets_client=FakeSecretsClient(),
            subprocess_run=fake_subprocess_run_fallback,
        )
        spawned_config_path = captured_cmd["cmd"][captured_cmd["cmd"].index("--mcp-config") + 1]
        record(spawned_config_path == "/fake/mcp-config.json",
               "a missing/unreadable BOB_MCP_CONFIG falls back to the RAW path unchanged "
               "(graceful degradation, not a hard failure)",
               f"spawned_config_path={spawned_config_path!r}")

    print(f"\n  {passed}/{passed + failed} passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
