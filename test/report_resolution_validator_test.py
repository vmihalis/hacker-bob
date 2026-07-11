#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
import os


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULE_PATH = os.path.join(
    ROOT,
    "infra",
    "aws",
    "hacker-bob-stack",
    "functions",
    "validate-report-resolution",
    "index.py",
)
GRADE_HASH = "a" * 64
BUNDLE_HASH = "b" * 64
VERSION_ID = "version-123"
PROFILE = "libheif-cve-2026-49271"
MODEL_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"


def load_module():
    os.environ["REPORT_DECISION_MODEL_ID"] = MODEL_ID
    spec = importlib.util.spec_from_file_location("report_resolution_validator", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def sample_event(module):
    tool_input = {
        "schema_version": 1,
        "primary_reader": "downstream_maintainer",
        "action_order": [
            "upgrade_or_backport",
            "map_downstream_exposure",
            "retain_regression_coverage",
        ],
    }
    return {
        "profile": PROFILE,
        "target": PROFILE,
        "gradeResult": {
            "status": "awaiting_verifier_gate",
            "target_domain": PROFILE,
            "grade_verdict_hash": GRADE_HASH,
            "grade_freeze_bundle_sha256": BUNDLE_HASH,
            "grade_freeze_version_id": VERSION_ID,
        },
        "approval": {
            "decision": "approved",
            "target": PROFILE,
            "grade_verdict_hash": GRADE_HASH,
            "grade_freeze_bundle_sha256": BUNDLE_HASH,
            "grade_freeze_version_id": VERSION_ID,
        },
        "reportResult": {
            "status": "historical_replay_report_ready",
            "grade_verdict_hash": GRADE_HASH,
        },
        "features": copy.deepcopy(module.FEATURES),
        "modelId": MODEL_ID,
        "modelResult": {
            "StopReason": "tool_use",
            "Output": {
                "Message": {
                    "Content": [
                        {
                            "ToolUse": {
                                "ToolUseId": "tool-1",
                                "Name": module.TOOL_NAME,
                                "Input": tool_input,
                            }
                        }
                    ]
                }
            },
        },
    }


def refused(module, event, expected):
    try:
        module.validate(event)
    except RuntimeError as exc:
        assert expected in str(exc), str(exc)
    else:
        raise AssertionError(f"validator should refuse: {expected}")


def test_golden(module):
    result = module.validate(sample_event(module))
    assert result["status"] == "validated"
    assert result["primary_reader"] == "downstream_maintainer"
    assert result["action_order"][0] == "upgrade_or_backport"
    assert len(result["decision_hash"]) == 64


def test_tuple_and_features_are_bound(module):
    for path, expected in [
        (("approval", "grade_verdict_hash"), "approval grade hash mismatch"),
        (("reportResult", "grade_verdict_hash"), "REPORT grade hash mismatch"),
        (("features", "impact_axis"), "feature vector"),
    ]:
        event = sample_event(module)
        event[path[0]][path[1]] = "c" * 64 if "hash" in path[1] else "confidentiality"
        refused(module, event, expected)

def test_model_output_is_exact(module):
    event = sample_event(module)
    tool_input = event["modelResult"]["Output"]["Message"]["Content"][0]["ToolUse"]["Input"]
    tool_input["extra"] = "no"
    refused(module, event, "tool input keys")

    event = sample_event(module)
    tool_input = event["modelResult"]["Output"]["Message"]["Content"][0]["ToolUse"]["Input"]
    tool_input["binding"] = {"grade_verdict_hash": GRADE_HASH}
    refused(module, event, "tool input keys")

    event = sample_event(module)
    event["modelResult"]["Output"]["Message"]["Content"][0]["ToolUse"]["Input"][
        "schema_version"
    ] = True
    refused(module, event, "schema version mismatch")

    event = sample_event(module)
    event["modelResult"]["Output"]["Message"]["Content"].append({"Text": "also trust me"})
    refused(module, event, "exactly one Bedrock content block")

    event = sample_event(module)
    event["modelResult"]["StopReason"] = "end_turn"
    refused(module, event, "tool use")

    event = sample_event(module)
    event["modelResult"]["Output"]["Message"]["Content"][0]["ToolUse"]["ToolUseId"] = "bad id"
    refused(module, event, "tool-use id is invalid")

    event = sample_event(module)
    event["modelId"] = "us.anthropic.some-other-model-v1:0"
    refused(module, event, "deployed resolver")

    event = sample_event(module)
    del os.environ["REPORT_DECISION_MODEL_ID"]
    try:
        refused(module, event, "deployed model id is not configured")
    finally:
        os.environ["REPORT_DECISION_MODEL_ID"] = MODEL_ID


def test_action_permutation_and_reader_compatibility(module):
    event = sample_event(module)
    tool_input = event["modelResult"]["Output"]["Message"]["Content"][0]["ToolUse"]["Input"]
    tool_input["action_order"] = ["upgrade_or_backport"] * 3
    refused(module, event, "exact unique permutation")

    event = sample_event(module)
    tool_input = event["modelResult"]["Output"]["Message"]["Content"][0]["ToolUse"]["Input"]
    tool_input["primary_reader"] = "release_manager"
    tool_input["action_order"] = [
        "map_downstream_exposure",
        "upgrade_or_backport",
        "retain_regression_coverage",
    ]
    refused(module, event, "incompatible")

    compatible_first_actions = {
        "downstream_maintainer": {"upgrade_or_backport", "map_downstream_exposure"},
        "release_manager": {"upgrade_or_backport"},
        "product_security_owner": {"map_downstream_exposure"},
    }
    tails = {
        "upgrade_or_backport": ["map_downstream_exposure", "retain_regression_coverage"],
        "map_downstream_exposure": ["upgrade_or_backport", "retain_regression_coverage"],
    }
    for reader, first_actions in compatible_first_actions.items():
        for first_action in first_actions:
            event = sample_event(module)
            tool_input = event["modelResult"]["Output"]["Message"]["Content"][0]["ToolUse"]["Input"]
            tool_input["primary_reader"] = reader
            tool_input["action_order"] = [first_action, *tails[first_action]]
            result = module.validate(event)
            assert result["primary_reader"] == reader
            assert result["action_order"][0] == first_action


def main():
    module = load_module()
    tests = [
        test_golden,
        test_tuple_and_features_are_bound,
        test_model_output_is_exact,
        test_action_permutation_and_reader_compatibility,
    ]
    for test in tests:
        test(module)
        print(f"ok: {test.__name__}")


if __name__ == "__main__":
    main()
