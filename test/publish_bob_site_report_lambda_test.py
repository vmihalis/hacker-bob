#!/usr/bin/env python3
"""Unit checks for the Bob-site post-REPORT publisher Lambda.

No boto3 dependency: import index.py and call handle() with fake Secrets Manager
and fake urllib opener. This keeps local validation cheap while pinning the wire
contract with Bob-site's /api/reports ingest.
"""

from __future__ import annotations

import importlib.util
import json
import os


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULE_PATH = os.path.join(
    REPO_ROOT,
    "infra",
    "aws",
    "hacker-bob-stack",
    "functions",
    "publish-bob-site-report",
    "index.py",
)


def load_module():
    spec = importlib.util.spec_from_file_location("publish_bob_site_report_lambda", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FakeSecrets:
    def __init__(self, values):
        self.values = values

    def get_secret_value(self, SecretId):
        return {"SecretString": self.values[SecretId]}


class FakeResponse:
    status = 200

    def __init__(self, body):
        self.body = json.dumps(body).encode("utf-8")

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def sample_event():
    return {
        "profile": "libheif-cve-2026-49271",
        "target": "libheif-cve-2026-49271",
        "runtimeSessionId": "session-123",
        "executionName": "hacker-bob-libheif-onloop-20260711T131143Z",
        "approval": {
            "grade_verdict_hash": "03560c0f2980838d5b710c89522ac2eff22852bcc0063d630d7f2aac1cfc16d1",
            "grade_freeze_version_id": "YXA288siWQBctu_KF9zA.aJQng_Od64P",
            "grade_freeze_bundle_sha256": "b87c81713d48a70b9c7e8b0de77cadf4602eb3ff6713707741a31188ebefc372",
            "approval_artifact_key": "approvals/libheif-cve-2026-49271/03560c0f.approved",
        },
        "exportResult": {
            "Payload": {
                "finding_ids": [
                    "hacker-bob/libheif-cve-2026-49271/F-22/03560c0f2980838d"
                ]
            }
        },
        "reportResult": {
            "status": "historical_replay_report_ready",
            "grade_verdict_hash": "03560c0f2980838d5b710c89522ac2eff22852bcc0063d630d7f2aac1cfc16d1",
            "summary": "Exact-library sanitizer replay summary.",
            "caveat": "bounded public historical reproduction.",
        },
    }


def env():
    return {
        "BOB_SITE_BASE_URL": "https://bob.example",
        "INGEST_TOKEN_SECRET_ID": "token-secret",
        "REPORT_PASSWORD_SECRET_ID": "password-secret",
        "REPORT_RECIPIENT": "AABW judges",
    }


def test_not_configured_skip(module):
    result = module.handle(sample_event(), {}, FakeSecrets({}))
    assert result == {"version": 1, "published": False, "reason": "not_configured"}


def test_private_url_rejected(module):
    bad = env()
    bad["BOB_SITE_BASE_URL"] = "https://127.0.0.1"
    try:
        module.handle(
            sample_event(),
            bad,
            FakeSecrets({"token-secret": "tok", "password-secret": "pw"}),
        )
    except ValueError as exc:
        assert "private" in str(exc)
    else:
        raise AssertionError("private Bob-site base URL should be rejected")


def test_unsupported_profile_skips_after_configured(module):
    event = sample_event()
    event["profile"] = "smoke"
    result = module.handle(
        event,
        env(),
        FakeSecrets({"token-secret": "tok", "password-secret": "pw"}),
    )
    assert result["published"] is False
    assert result["reason"] == "unsupported_profile"


def test_publish_posts_shaped_report(module):
    captured = {}

    def opener(req, timeout):
        captured["url"] = req.full_url
        captured["timeout"] = timeout
        captured["auth"] = req.get_header("Authorization")
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return FakeResponse({"slug": "r_abc123", "url": "https://bob.example/r/r_abc123"})

    result = module.handle(
        sample_event(),
        env(),
        FakeSecrets({"token-secret": "tok", "password-secret": "pw"}),
        opener=opener,
    )

    assert result["published"] is True
    assert result["bob_site_url"] == "https://bob.example/r/r_abc123"
    assert result["bob_site_slug"] == "r_abc123"
    assert captured["url"] == "https://bob.example/api/reports"
    assert captured["timeout"] == 15
    assert captured["auth"] == "Bearer tok"
    body = captured["body"]
    assert body["recipient"] == "AABW judges"
    assert body["password"] == "pw"
    assert body["model"]["domain"] == "libheif CVE-2026-49271 replay"
    assert body["model"]["findings"][0]["id"] == "F-22"
    assert body["model"]["findings"][0]["sections"][1]["kind"] == "evidence"
    assert "YXA288siWQBctu_KF9zA.aJQng_Od64P" in body["model"]["findings"][0]["sections"][1]["prose"]
    assert body["business"]["riskLevel"] == "moderate"


def main():
    module = load_module()
    tests = [
        test_not_configured_skip,
        test_private_url_rejected,
        test_unsupported_profile_skips_after_configured,
        test_publish_posts_shaped_report,
    ]
    for test in tests:
        test(module)
        print(f"ok: {test.__name__}")


if __name__ == "__main__":
    main()
