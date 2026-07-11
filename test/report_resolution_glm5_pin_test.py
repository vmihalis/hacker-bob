#!/usr/bin/env python3
"""Regression pin: the authorized GLM-5-on-Bedrock resolver swap passes BOTH the
deterministic validator and the Bob-site publisher end-to-end, using REAL GLM-5
Converse tool output.

Context: the causal resolver's model is the single CloudFormation parameter
BedrockFallbackModelId (it feeds the state machine's Converse ModelId and both
Lambdas' REPORT_DECISION_MODEL_ID). Moving it from the Haiku fallback to zai.glm-5
must remain a one-parameter change with no code/validator edit. This test proves it:
the exact-key envelope the hotfix requires ({ToolUse:{ToolUseId,Name,Input,Type}})
is a property of the Step Functions aws-sdk:bedrockruntime:converse integration, not
of any one model, so a Bedrock-hosted GLM-5 forced-tool response flows through
unchanged.

The GLM5_MODEL_RESULT below was captured from a live `bedrock-runtime converse
--model-id zai.glm-5` call using the state machine's exact ToolConfig/ToolChoice,
then materialized the way Step Functions PascalCases the Bedrock response.

Run: python3 test/report_resolution_glm5_pin_test.py
"""

from __future__ import annotations

import importlib.util
import json
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GLM5_MODEL_ID = "zai.glm-5"


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


VALIDATOR = _load(
    os.path.join(
        REPO_ROOT, "infra", "aws", "hacker-bob-stack", "functions",
        "validate-report-resolution", "index.py",
    ),
    "validate_report_resolution_index",
)
# Reuse the publisher test's exact production fixtures (grade/approval/export/report
# tuple + FakeSecrets/FakeResponse) so this pins the SAME wire contract, only the model
# id differs.
PUB_TEST = _load(
    os.path.join(REPO_ROOT, "test", "publish_bob_site_report_lambda_test.py"),
    "publish_bob_site_report_lambda_test",
)
PUBLISHER = PUB_TEST.load_module()

# Real GLM-5 forced-tool output (Bedrock Converse), PascalCased by the Step Functions
# aws-sdk:bedrockruntime:converse integration exactly as the live state machine emits it.
GLM5_MODEL_RESULT = {
    "StopReason": "tool_use",
    "Output": {"Message": {"Content": [{"ToolUse": {
        "ToolUseId": "tooluse_8x4ecP8Yk6dzQHsY2riaQd",
        "Name": "select_report_framing",
        "Type": "tool_use",
        "Input": {
            "schema_version": 1,
            "primary_reader": "downstream_maintainer",
            "action_order": [
                "upgrade_or_backport",
                "map_downstream_exposure",
                "retain_regression_coverage",
            ],
        },
    }}]}},
}


def glm5_validated_resolution():
    """Drive the REAL validator on the real GLM-5 envelope, pinned to zai.glm-5."""
    os.environ["REPORT_DECISION_MODEL_ID"] = GLM5_MODEL_ID
    event = {
        "profile": "libheif-cve-2026-49271",
        "target": "libheif-cve-2026-49271",
        "gradeResult": {
            "status": "awaiting_verifier_gate",
            "target_domain": "libheif-cve-2026-49271",
            "grade_verdict_hash": PUB_TEST.GRADE_HASH,
            "grade_freeze_bundle_sha256": PUB_TEST.BUNDLE_SHA256,
            "grade_freeze_version_id": PUB_TEST.VERSION_ID,
        },
        "approval": {
            "decision": "approved",
            "target": "libheif-cve-2026-49271",
            "grade_verdict_hash": PUB_TEST.GRADE_HASH,
            "grade_freeze_bundle_sha256": PUB_TEST.BUNDLE_SHA256,
            "grade_freeze_version_id": PUB_TEST.VERSION_ID,
        },
        "reportResult": {
            "status": "historical_replay_report_ready",
            "grade_verdict_hash": PUB_TEST.GRADE_HASH,
        },
        "features": PUB_TEST.RESOLUTION_FEATURES,
        "modelId": GLM5_MODEL_ID,
        "modelResult": GLM5_MODEL_RESULT,
    }
    return VALIDATOR.validate(event)


def test_glm5_forced_tool_output_passes_the_validator(_module=None):
    res = glm5_validated_resolution()
    assert res["status"] == "validated", res
    assert res["model_id"] == GLM5_MODEL_ID, res
    assert res["primary_reader"] == "downstream_maintainer", res
    assert res["action_order"][0] in {"upgrade_or_backport", "map_downstream_exposure"}, res
    assert len(res["decision_hash"]) == 64, res


def test_glm5_resolution_publishes_end_to_end(_module=None):
    resolution = glm5_validated_resolution()
    event = PUB_TEST.sample_event()
    event["resolution"] = resolution  # the real validator output, pinned to GLM-5
    environ = dict(PUB_TEST.env())
    environ["REPORT_DECISION_MODEL_ID"] = GLM5_MODEL_ID

    captured = {}

    def opener(req, timeout):
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return PUB_TEST.FakeResponse({"slug": "r_glm5", "url": "https://bob.example/r/r_glm5"})

    result = PUBLISHER.handle(
        event,
        environ,
        PUB_TEST.FakeSecrets({"token-secret": "tok", "password-secret": "stage-report-password"}),
        opener=opener,
    )
    assert result["published"] is True, result
    assert result["bob_site_slug"] == "r_glm5", result
    # The published record carries the GLM-5 pin, and the model only reordered fixed
    # content — governance holds regardless of which Bedrock model chose the framing.
    assert captured["body"]["model"]["reportResolution"]["modelId"] == GLM5_MODEL_ID
    assert captured["body"]["model"]["brief"]["primaryReader"] == "downstream_maintainer"


def test_publisher_still_pins_the_configured_model(_module=None):
    """A GLM-5 resolution must NOT publish if the deployment is still pinned to Haiku
    (mismatched pin fails closed) — proving the pin is enforced, not cosmetic."""
    resolution = glm5_validated_resolution()
    event = PUB_TEST.sample_event()
    event["resolution"] = resolution
    try:
        PUBLISHER._build_libheif_model(event, PUB_TEST.MODEL_ID)  # Haiku pin vs GLM-5 output
    except RuntimeError as exc:
        assert "model id mismatch" in str(exc), str(exc)
    else:
        raise AssertionError("publisher must fail closed when the resolution model id != the deployed pin")


def test_swap_is_a_single_parameter_change(_module=None):
    """The Haiku and GLM-5 validated resolutions differ ONLY in the model id (and the
    decision hash bound to it) — confirming the swap needs no other change."""
    haiku = PUB_TEST.sample_resolution()  # model_id == Haiku fallback
    glm5 = glm5_validated_resolution()
    assert haiku["model_id"] != glm5["model_id"]
    differing = {k for k in set(haiku) | set(glm5) if haiku.get(k) != glm5.get(k)}
    assert differing == {"model_id", "decision_hash"}, differing


def main():
    tests = [
        test_glm5_forced_tool_output_passes_the_validator,
        test_glm5_resolution_publishes_end_to_end,
        test_publisher_still_pins_the_configured_model,
        test_swap_is_a_single_parameter_change,
    ]
    for test in tests:
        test()
        print(f"ok: {test.__name__}")


if __name__ == "__main__":
    main()
