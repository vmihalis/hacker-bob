#!/usr/bin/env python3
"""Unit tests for infra/runner/agentcore-entrypoint.py.

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

    # provider unset -> defaults to zai at the run_invocation layer (build_model_env
    # itself requires an explicit provider string; the default lives in run_invocation
    # via env.get("MODEL_PROVIDER", "zai")). Confirm that default end-to-end below in (e).

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
    record(got_no_resume == "/bob-evaluate kyberfork.internal:8545",
           "build_skill_prompt(resume=False) matches exact prompt", f"got={got_no_resume!r}")
    got_resume = MODULE.build_skill_prompt("kyberfork.internal:8545", resume=True)
    record(got_resume == "/bob-evaluate resume kyberfork.internal:8545",
           "build_skill_prompt(resume=True) matches exact prompt", f"got={got_resume!r}")

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
        record(result == report_row,
               "run_invocation returns the last parsed JSONL row", f"got={result}")
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
        record(captured["cmd"][-1] == "/bob-evaluate kyberfork.internal",
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

        # provider unset defaults to zai at run_invocation's own default layer.
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
            "ZAI_GATEWAY_URL": "https://zai.example.internal",
            # MODEL_PROVIDER deliberately absent
        }
        fake_secrets_default = FakeSecretsClient(secret_string="fake-default-token")
        MODULE.run_invocation(
            {"target": target}, env_unset,
            secrets_client=fake_secrets_default,
            subprocess_run=fake_subprocess_run_3,
        )
        record(len(fake_secrets_default.calls) == 1,
               "run_invocation with MODEL_PROVIDER unset defaults to zai (calls secrets_client)")
        record(captured3["env"].get("ANTHROPIC_MODEL") == "glm-5.1",
               "run_invocation with MODEL_PROVIDER unset sets glm-5.1 via zai default path")

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

    # --- (f1-approval-wiring g) STAGE-AWARE clean stop: a GRADE-stage call that writes no NEW
    #     report-snapshot row is not an error -- it is the expected shape of a session withheld at
    #     the human-approval gate -- returns {"status": "awaiting_approval", ...} instead of
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
            return None  # deliberately writes nothing new -- awaiting approval, not broken

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
        # fx-hmac-content: grade_verdict_hash is None here -- BOB_MCP_CONFIG is a fake path with
        # no real mcp/lib/report-finalize.js beneath it, so _load_grade_verdict_hash's node
        # shellout fails closed (never raises out of run_invocation).
        record(
            not grade_raised
            and grade_result == {"status": "awaiting_approval", "target": target, "grade_verdict_hash": None},
            "run_invocation(stage=GRADE, BOB_AGENTCORE=1) returns awaiting_approval (with "
            "grade_verdict_hash: None off a fake BOB_MCP_CONFIG) instead of raising on a clean stop",
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
            return None  # deliberately writes nothing new -- awaiting approval, not broken

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
            and grade_result_with_hash.get("status") == "awaiting_approval"
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

    # --- fx-hmac-content: grade_verdict_hash is None (never raises) when BOB_MCP_CONFIG is REAL
    #     but grade.json itself does not exist yet for this session -- the "no grade.json"
    #     case, distinct from the "fake BOB_MCP_CONFIG" case above. ---
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
            not grade_no_verdict_raised
            and grade_result_no_verdict == {
                "status": "awaiting_approval", "target": target, "grade_verdict_hash": None,
            },
            "run_invocation(stage=GRADE, real BOB_MCP_CONFIG but no grade.json) returns "
            "grade_verdict_hash: None without raising",
            f"raised={grade_no_verdict_raised} detail={grade_no_verdict_detail!r} "
            f"got={grade_result_no_verdict}")

    # --- (f1-approval-wiring wave-2 b) STAGE-AWARE clean stop, inert-by-default companion: the
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
    #     approval by simply setting approvalToken + resume=True in ITS OWN payload (both
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

        with open(spawned_config_path) as fh:
            spawned_config = json.load(fh)
        spawned_env = spawned_config.get("mcpServers", {}).get("hacker-bob", {}).get("env", {})
        token = spawned_env.get("BOB_MCP_CALLER_TOKEN")
        record(isinstance(token, str) and re.fullmatch(r"[0-9a-f]{64}", token) is not None,
               "the spawned per-invocation config injects a well-formed 64-lowercase-hex "
               "BOB_MCP_CALLER_TOKEN into mcpServers.hacker-bob.env",
               f"token={token!r}")
        record(spawned_env.get("SOME_EXISTING_VAR") == "keep-me",
               "pre-existing mcpServers.hacker-bob.env entries survive the token injection",
               f"spawned_env={spawned_env}")

        # A second invocation mints a DIFFERENT token (never reused across invocations).
        captured_cmd2 = {}

        def fake_subprocess_run_caller_auth_2(cmd, env=None, check=None):
            captured_cmd2["cmd"] = cmd
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
        with open(spawned_config_path_2) as fh:
            token2 = json.load(fh)["mcpServers"]["hacker-bob"]["env"]["BOB_MCP_CALLER_TOKEN"]
        record(token2 != token,
               "each invocation mints a fresh, distinct caller-auth token",
               f"token={token!r} token2={token2!r}")

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
