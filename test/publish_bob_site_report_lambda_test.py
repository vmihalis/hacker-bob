#!/usr/bin/env python3
"""Unit checks for the Bob-site post-REPORT publisher Lambda.

No boto3 dependency: import index.py and call handle() with fake Secrets Manager
and fake urllib opener. This keeps local validation cheap while pinning the wire
contract with Bob-site's /api/reports ingest.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import json
import os
import tempfile


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
TARGET_LOCK_PATH = os.path.join(
    REPO_ROOT,
    "infra",
    "runner",
    "demo-targets",
    "libheif-cve-2026-49271",
    "target.lock.json",
)
ARTIFACT_PATH = os.path.join(
    REPO_ROOT,
    "infra",
    "aws",
    "hacker-bob-stack",
    "functions",
    "publish-bob-site-report",
    "finding-artifact.json",
)
GRADE_HASH = "03560c0f2980838d5b710c89522ac2eff22852bcc0063d630d7f2aac1cfc16d1"
VERSION_ID = "YXA288siWQBctu_KF9zA.aJQng_Od64P"
BUNDLE_SHA256 = "b87c81713d48a70b9c7e8b0de77cadf4602eb3ff6713707741a31188ebefc372"
ASFF_ID = f"hacker-bob/libheif-cve-2026-49271/F-22/{GRADE_HASH[:16]}"
VULNERABLE_COMMIT = "b12b733d1716595483413ccd7e2dfb73c44a8d69"
EXACT_FIX_COMMIT = "5782bca04a70ebc01c59397205a3cfff22841311"
PATCHED_RELEASE_COMMIT = "2b6d5a62fb6151e09d5f36757a5aa5e12f9c2045"
CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
VERIFIER_CHECKS = [
    "target_binding",
    "exact_s3_version",
    "object_lock_compliance",
    "body_sha256",
    "embedded_grade_hash",
    "canonical_grade_hash",
]
LIBHEIF_CAVEAT = (
    "The harness constructs parsed-equivalent cmpC/icef decoder objects and exercises the exact "
    "vulnerable library path; it is not a complete malicious .heif parsed through the public decoder API."
)
MODEL_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
RESOLUTION_FEATURES = {
    "target_kind": "oss_library",
    "impact_axis": "availability",
    "fix_state": "upstream_fixed",
    "distribution_scope": "downstream_consumers",
    "reachability": "crafted_file_with_user_interaction",
    "evidence_confidence": "high_bounded",
}


def canonical_hash(value):
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def sample_resolution(primary_reader="downstream_maintainer", action_order=None):
    if action_order is None:
        action_order = [
            "upgrade_or_backport",
            "map_downstream_exposure",
            "retain_regression_coverage",
        ]
    decision = {
        "schema_version": 1,
        "resolution_type": "bedrock_stakeholder_resolution",
        "profile": "libheif-cve-2026-49271",
        "target_domain": "libheif-cve-2026-49271",
        "grade_verdict_hash": GRADE_HASH,
        "grade_freeze_bundle_sha256": BUNDLE_SHA256,
        "grade_freeze_version_id": VERSION_ID,
        "feature_registry": "libheif-impact-v1",
        "feature_hash": canonical_hash(RESOLUTION_FEATURES),
        "model_id": MODEL_ID,
        "primary_reader": primary_reader,
        "action_order": action_order,
    }
    return {"status": "validated", **decision, "decision_hash": canonical_hash(decision)}


def load_module():
    spec = importlib.util.spec_from_file_location("publish_bob_site_report_lambda", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def load_artifact():
    with open(ARTIFACT_PATH, encoding="utf-8") as fh:
        return json.load(fh)


@contextlib.contextmanager
def artifact_override(module, artifact):
    """Point the publisher at a temp artifact so tests can prove data-driven behavior."""
    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(artifact, tmp)
    tmp.close()
    prev = os.environ.get(module.LIBHEIF_ARTIFACT_ENV_VAR)
    os.environ[module.LIBHEIF_ARTIFACT_ENV_VAR] = tmp.name
    try:
        yield
    finally:
        if prev is None:
            os.environ.pop(module.LIBHEIF_ARTIFACT_ENV_VAR, None)
        else:
            os.environ[module.LIBHEIF_ARTIFACT_ENV_VAR] = prev
        os.unlink(tmp.name)


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
    event = {
        "profile": "libheif-cve-2026-49271",
        "target": "libheif-cve-2026-49271",
        "runtimeSessionId": "session-123",
        "executionName": "hacker-bob-libheif-onloop-20260711T131143Z",
        "executionArn": "arn:aws:states:us-east-1:123456789012:execution:hacker-bob:hacker-bob-libheif-onloop-20260711T131143Z",
        "gradeResult": {
            "status": "awaiting_verifier_gate",
            "target": "libheif-cve-2026-49271",
            "target_domain": "libheif-cve-2026-49271",
            "grade_verdict_hash": GRADE_HASH,
            "grade_freeze_version_id": VERSION_ID,
            "grade_freeze_bundle_sha256": BUNDLE_SHA256,
            "fixture_id": "libheif-cve-2026-49271",
            "claim_mode": "public_historical_reproduction",
            "rediscovery": False,
            "reportable_finding_ids": ["F-22"],
            "fixture_receipt": {
                "fixture_id": "libheif-cve-2026-49271",
                "claim_mode": "public_historical_reproduction",
                "rediscovery": False,
                "target_lock_sha256": "a" * 64,
                "harness_sha256": "b" * 64,
                "vulnerable_commit": VULNERABLE_COMMIT,
                "exact_fix_commit": EXACT_FIX_COMMIT,
                "patched_release_commit": PATCHED_RELEASE_COMMIT,
                "semantic_proof": {
                    "bug_type": "heap-buffer-overflow",
                    "access": "READ of size 2",
                    "source_frame": "libheif/codecs/uncompressed/unc_decoder.cc:178",
                    "vulnerable_signal_confirmed": True,
                    "fixed_marker": "returned error? 1 output=0",
                    "fixed_sanitizer_clean": True,
                },
            },
        },
        "approval": {
            "decision": "approved",
            "approval_mode": "verifier_quorum",
            "profile": "libheif-cve-2026-49271",
            "target": "libheif-cve-2026-49271",
            "grade_verdict_hash": GRADE_HASH,
            "grade_freeze_version_id": VERSION_ID,
            "grade_freeze_bundle_sha256": BUNDLE_SHA256,
            "approval_artifact_key": f"approvals/libheif-cve-2026-49271/{GRADE_HASH}.approved",
            "approved_at": "2026-07-11T13:11:50Z",
            "verifier_quorum": VERIFIER_CHECKS,
        },
        "exportResult": {
            "Payload": {
                "target_domain": "libheif-cve-2026-49271",
                "grade_verdict_hash": GRADE_HASH,
                "grade_freeze_version_id": VERSION_ID,
                "grade_freeze_bundle_sha256": BUNDLE_SHA256,
                "verdict": "SUBMIT",
                "exported": [
                    {
                        "asff_id": ASFF_ID,
                        "finding_id": "F-22",
                        "severity_label": "MEDIUM",
                    }
                ],
                "failed": [],
            }
        },
        "reportResult": {
            "status": "historical_replay_report_ready",
            "target_domain": "libheif-cve-2026-49271",
            "fixture_id": "libheif-cve-2026-49271",
            "claim_mode": "public_historical_reproduction",
            "rediscovery": False,
            "grade_verdict_hash": GRADE_HASH,
            "findings": ["F-22"],
            "summary": "Exact-library sanitizer replay summary.",
            "caveat": LIBHEIF_CAVEAT,
            "generated_at": "2026-07-11T13:12:04Z",
        },
    }
    event["resolution"] = sample_resolution()
    return event


def env():
    return {
        "BOB_SITE_BASE_URL": "https://bob.example",
        "INGEST_TOKEN_SECRET_ID": "token-secret",
        "REPORT_PASSWORD_SECRET_ID": "password-secret",
        "REPORT_RECIPIENT": "AABW judges",
        "REPORT_DECISION_MODEL_ID": MODEL_ID,
    }


def test_libheif_publication_configuration_is_required(module):
    try:
        module.handle(sample_event(), {}, FakeSecrets({}))
    except RuntimeError as exc:
        assert "publication is not configured" in str(exc), str(exc)
    else:
        raise AssertionError("libheif demo execution must fail when publication is disabled")


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


def test_libheif_publication_secrets_and_password_strength_are_required(module):
    try:
        module.handle(
            sample_event(),
            env(),
            FakeSecrets({"token-secret": "", "password-secret": ""}),
        )
    except RuntimeError as exc:
        assert "publication secrets are not configured" in str(exc), str(exc)
    else:
        raise AssertionError("libheif demo execution must fail without publication secrets")

    try:
        module.handle(
            sample_event(),
            env(),
            FakeSecrets({"token-secret": "tok", "password-secret": "too-short"}),
        )
    except RuntimeError as exc:
        assert "at least 16 non-whitespace characters" in str(exc), str(exc)
    else:
        raise AssertionError("libheif demo execution must fail with a weak report password")

    try:
        module.handle(
            sample_event(),
            env(),
            FakeSecrets({"token-secret": "tok", "password-secret": "fifteen-chars!! "}),
        )
    except RuntimeError as exc:
        assert "non-whitespace" in str(exc), str(exc)
    else:
        raise AssertionError("trailing whitespace must not satisfy report-password strength")


def test_publish_posts_shaped_report(module):
    captured = {}
    raw_model_text = "DO NOT PUBLISH THIS MODEL TEXT <script>"
    event = sample_event()
    event["reportResolutionModel"] = {
        "Output": {"Message": {"Content": [{"Text": raw_model_text}]}}
    }

    def opener(req, timeout):
        captured["url"] = req.full_url
        captured["timeout"] = timeout
        captured["auth"] = req.get_header("Authorization")
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return FakeResponse({"slug": "r_abc123", "url": "https://bob.example/r/r_abc123"})

    result = module.handle(
        event,
        env(),
        FakeSecrets({"token-secret": "tok", "password-secret": "stage-report-password"}),
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
    assert body["password"] == "stage-report-password"
    assert body["consoleVisible"] is True
    assert len(body["publicationKey"]) == 64
    assert len(body["publicationFingerprint"]) == 64
    assert body["publicationKey"] == module._build_payload(
        sample_event(),
        "stage-report-password",
        "AABW judges",
        MODEL_ID,
    )["publicationKey"]
    assert body["domain"] == "libheif"
    assert body["method"] == "Hacker Bob · verified differential security assessment"
    model = body["model"]
    assert model["domain"] == "libheif"
    assert model["targetKind"] == "oss_library"
    assert model["target"]["kind"] == "oss_library"
    assert model["target"]["name"] == "libheif"
    assert model["target"]["repository"] == "https://github.com/strukturag/libheif"
    assert model["reportKind"] == "security_assessment"
    assert model["disclosure"] == {
        "status": "public_historical_replay",
        "freshTargetTesting": False,
        "boundary": "Exact-library replay of a public historical finding using pinned vulnerable and fixed revisions.",
    }
    assert model["brief"]["primaryReader"] == "downstream_maintainer"
    assert model["brief"]["resolvedFor"] == "Downstream maintainers"
    assert model["brief"]["primaryAction"].startswith("Upgrade to libheif 1.22.1")
    assert len(model["brief"]["stakeholderActions"]) == 3
    resolution = sample_resolution()
    assert model["reportResolution"] == {
        "status": "validated",
        "resolutionType": "bedrock_stakeholder_resolution",
        "schemaVersion": 1,
        "featureRegistry": "libheif-impact-v1",
        "featureHash": resolution["feature_hash"],
        "modelId": MODEL_ID,
        "primaryReader": "downstream_maintainer",
        "actionOrder": [
            "upgrade_or_backport",
            "map_downstream_exposure",
            "retain_regression_coverage",
        ],
        "decisionHash": resolution["decision_hash"],
    }

    finding = model["findings"][0]
    assert finding["id"] == "F-22"
    assert finding["cvssVector"] == CVSS_VECTOR
    assert finding["cvssScore"] == "6.5"
    assert finding["affected"]["versions"] == "<= 1.22.0"
    assert finding["affected"]["vulnerableCommit"] == VULNERABLE_COMMIT
    assert finding["fixed"]["status"] == "upstream_fixed"
    assert finding["fixed"]["version"] == "1.22.1"
    assert finding["fixed"]["exactFixCommit"] == EXACT_FIX_COMMIT
    assert finding["fixed"]["patchedReleaseCommit"] == PATCHED_RELEASE_COMMIT
    assert finding["rootCause"]["operation"] == "unit_offset + unit_size"
    assert finding["rootCause"]["sourceFrame"] == "libheif/codecs/uncompressed/unc_decoder.cc:178"
    assert finding["evidence"]["vulnerableSignal"] == "AddressSanitizer: heap-buffer-overflow"
    assert finding["evidence"]["access"] == "READ of size 2"
    assert finding["evidence"]["fixedMarker"] == "returned error? 1 output=0"
    assert finding["evidence"]["fixedSanitizerClean"] is True
    assert finding["provenance"]["advisory"] == "GHSA-r7qj-cg5r-r6vf"
    assert finding["provenance"]["reportedBy"] == "@vmihalis"
    assert finding["remediation"]["upstreamStatus"] == "fixed"
    downstream_actions = finding["remediation"]["downstreamActions"]
    assert downstream_actions[0].startswith("Upgrade to libheif 1.22.1")
    assert downstream_actions[1].startswith("Map packages and products")
    assert "regression coverage" in downstream_actions[2]
    assert "parsed-equivalent cmpC/icef" in finding["caveats"][0]

    receipt = model["receipt"]
    assert receipt == {
        "evidenceHash": GRADE_HASH,
        "artifactVersion": VERSION_ID,
        "bundleSha256": BUNDLE_SHA256,
        "verifierStatus": "approved",
        "integrityChecksPassed": 6,
        "verifierChecks": VERIFIER_CHECKS,
        "objectLockMode": "COMPLIANCE",
        "sourceCommit": VULNERABLE_COMMIT,
        "fixedCommit": EXACT_FIX_COMMIT,
        "profile": "libheif-cve-2026-49271",
        "generatedAt": "2026-07-11T13:12:04Z",
    }
    provenance = next(section for section in finding["sections"] if section["section_id"] == "f22-provenance")
    assert "public historical reproduction" in provenance["prose"].lower()
    assert "integrity checks" not in provenance["prose"].lower()
    assert body["business"]["riskLevel"] == "moderate"
    assert body["business"]["dimensions"]["ecosystem_impact"]["label"] == "Ecosystem impact"
    assert body["business"]["decisions"][0]["title"] == "Upgrade or backport downstream copies"
    assert body["business"]["decisions"][1]["title"] == "Map releases, packages, and advisories"

    stakeholder_model = dict(model)
    stakeholder_model.pop("receipt", None)
    stakeholder_text = json.dumps(
        {"model": stakeholder_model, "business": body["business"], "method": body["method"]},
        sort_keys=True,
    ).lower()
    for phrase in [
        "aws evidence handoff",
        "the demo proves",
        "review the sealed bob-site report",
        "keep publication boundaries explicit",
        "step functions",
        "agentcore",
        "bob-site",
        "quorum",
        " aws ",
        " demo ",
    ]:
        assert phrase not in stakeholder_text, phrase
    assert "unavailable" not in json.dumps(body).lower()
    assert raw_model_text not in json.dumps(body)


def assert_refused(module, event, expected):
    try:
        module._build_libheif_model(event, MODEL_ID)
    except RuntimeError as exc:
        assert expected in str(exc), str(exc)
    else:
        raise AssertionError(f"publisher should fail closed: {expected}")


def test_rejected_or_incomplete_transaction_is_refused(module):
    event = sample_event()
    event["approval"]["decision"] = "rejected"
    assert_refused(module, event, "decision is not approved")

    event = sample_event()
    event["reportResult"]["status"] = "failed"
    assert_refused(module, event, "REPORT stage is not ready")

    event = sample_event()
    event["gradeResult"].pop("fixture_receipt")
    assert_refused(module, event, "fixture receipt id mismatch")


def test_verifier_checks_must_be_canonical_and_unique(module):
    event = sample_event()
    event["approval"]["verifier_quorum"] = ["bogus"] * 6
    assert_refused(module, event, "canonical six integrity checks")

    event = sample_event()
    event["approval"]["verifier_quorum"] = VERIFIER_CHECKS[:-1] + [VERIFIER_CHECKS[0]]
    assert_refused(module, event, "canonical six integrity checks")


def test_transaction_tuple_must_match_across_stages(module):
    event = sample_event()
    event["approval"]["grade_verdict_hash"] = "c" * 64
    assert_refused(module, event, "approval grade hash mismatch")

    event = sample_event()
    event["reportResult"]["grade_verdict_hash"] = "c" * 64
    assert_refused(module, event, "REPORT grade hash mismatch")

    event = sample_event()
    event["exportResult"]["Payload"]["grade_freeze_version_id"] = "wrong-version"
    assert_refused(module, event, "Security Hub VersionId mismatch")


def test_security_hub_export_must_be_exact(module):
    model, _business = module._build_libheif_model(sample_event(), MODEL_ID)
    assert "securityHubFindingId" not in model["receipt"]
    assert "executionId" not in model["receipt"]
    assert "approvalArtifact" not in model["receipt"]
    assert "runtimeSessionId" not in model["receipt"]

    event = sample_event()
    event["exportResult"]["Payload"]["exported"] = []
    assert_refused(module, event, "exact approved F-22 record")

    event = sample_event()
    event["exportResult"]["Payload"]["exported"][0]["asff_id"] = "unrelated"
    assert_refused(module, event, "exact approved F-22 record")


def test_semantic_proof_must_match_published_claims(module):
    event = sample_event()
    event["gradeResult"]["fixture_receipt"]["semantic_proof"]["fixed_sanitizer_clean"] = False
    assert_refused(module, event, "semantic vulnerable/fixed proof mismatch")


def test_report_resolution_is_required_exact_and_bound(module):
    event = sample_event()
    event.pop("resolution")
    assert_refused(module, event, "validated report resolution is missing")

    event = sample_event()
    event["resolution"]["model_prose"] = "trust this arbitrary model-authored claim"
    assert_refused(module, event, "report resolution keys are invalid")

    event = sample_event()
    event["resolution"]["grade_verdict_hash"] = "c" * 64
    assert_refused(module, event, "report resolution grade hash mismatch")

    event = sample_event()
    event["resolution"]["feature_hash"] = "c" * 64
    assert_refused(module, event, "report resolution feature hash mismatch")

    event = sample_event()
    event["resolution"]["decision_hash"] = "c" * 64
    assert_refused(module, event, "report resolution decision hash mismatch")

    event = sample_event()
    event["resolution"]["schema_version"] = True
    assert_refused(module, event, "report resolution schema mismatch")


def test_report_resolution_enums_and_model_pin_fail_closed(module):
    event = sample_event()
    event["resolution"]["primary_reader"] = "judge"
    assert_refused(module, event, "reader is not allowed")

    event = sample_event()
    event["resolution"]["action_order"] = ["upgrade_or_backport"] * 3
    assert_refused(module, event, "exact unique permutation")

    event = sample_event()
    event["resolution"] = sample_resolution(
        "product_security_owner",
        [
            "upgrade_or_backport",
            "map_downstream_exposure",
            "retain_regression_coverage",
        ],
    )
    assert_refused(module, event, "first action is incompatible")

    event = sample_event()
    event["resolution"]["model_id"] = "us.anthropic.some-other-model-v1:0"
    assert_refused(module, event, "model id mismatch")

    try:
        module._build_libheif_model(sample_event(), "")
    except RuntimeError as exc:
        assert "configured report decision model id is invalid" in str(exc), str(exc)
    else:
        raise AssertionError("publisher should require a configured decision-model pin")


def test_valid_resolution_reorders_only_fixed_report_content(module):
    event = sample_event()
    event["resolution"] = sample_resolution(
        "product_security_owner",
        [
            "map_downstream_exposure",
            "upgrade_or_backport",
            "retain_regression_coverage",
        ],
    )
    model, business = module._build_libheif_model(event, MODEL_ID)

    assert model["brief"]["primaryReader"] == "product_security_owner"
    assert model["brief"]["resolvedFor"] == "Product security owners"
    assert model["brief"]["primaryAction"].startswith("Map packages and products")
    assert [action["audience"] for action in model["brief"]["stakeholderActions"]] == [
        "packagers_and_product_security",
        "downstream_maintainers",
        "maintainers_and_release_managers",
    ]
    assert model["findings"][0]["remediation"]["downstreamActions"] == [
        action["action"] for action in model["brief"]["stakeholderActions"]
    ]
    assert [decision["title"] for decision in business["decisions"]] == [
        "Map releases, packages, and advisories",
        "Upgrade or backport downstream copies",
        "Keep the differential as a regression test",
    ]
    assert model["reportResolution"]["actionOrder"] == event["resolution"]["action_order"]

    default_payload = module._build_payload(
        sample_event(),
        "stage-report-password",
        "AABW judges",
        MODEL_ID,
    )
    reordered_payload = module._build_payload(
        event,
        "stage-report-password",
        "AABW judges",
        MODEL_ID,
    )
    assert len(default_payload["publicationKey"]) == 64
    assert default_payload["publicationKey"] != reordered_payload["publicationKey"]
    assert default_payload["publicationFingerprint"] != reordered_payload["publicationFingerprint"]


def test_payload_matches_pinned_target_lock(module):
    with open(TARGET_LOCK_PATH, encoding="utf-8") as fh:
        lock = json.load(fh)

    model, _business = module._build_libheif_model(sample_event(), MODEL_ID)
    finding = model["findings"][0]
    advisory = lock["advisory"]
    pins = lock["source_pins"]
    reproduction = lock["reproduction"]

    assert finding["cvssVector"] == advisory["cvss_3_1"]
    assert finding["cvssScore"] == "6.5"
    assert finding["affected"]["versions"] == advisory["affected_versions"]
    assert finding["fixed"]["version"] == advisory["patched_versions"]
    assert finding["affected"]["vulnerableCommit"] == pins["vulnerable"]["commit"]
    assert finding["fixed"]["exactFixCommit"] == pins["exact_fix"]["commit"]
    assert finding["fixed"]["patchedReleaseCommit"] == pins["patched_release"]["commit"]
    assert finding["evidence"]["access"] in reproduction["expected_vulnerable"]["required_markers"]
    assert finding["evidence"]["sourceFrame"] in reproduction["expected_vulnerable"]["required_markers"]
    assert finding["evidence"]["fixedMarker"] in reproduction["expected_fixed"]["required_markers"]
    assert finding["caveats"][0] == lock["honesty"]["caveat"]


def test_report_is_built_from_committed_artifact(module):
    """Static report content is sourced verbatim from the committed artifact."""
    artifact = load_artifact()
    assert artifact["schemaVersion"] == 1
    assert artifact["targetKind"] == "oss_library"

    model, business = module._build_libheif_model(sample_event(), MODEL_ID)

    # Top-level static content flows straight from the artifact (not hardcoded).
    assert model["domain"] == artifact["domain"]
    assert model["targetKind"] == artifact["targetKind"]
    assert model["target"] == artifact["target"]
    assert model["reportKind"] == artifact["reportKind"]
    assert model["disclosure"] == artifact["disclosure"]
    assert model["severitySummary"] == artifact["severitySummary"]
    assert model["globalSections"] == artifact["globalSections"]
    assert model["brief"]["headline"] == artifact["brief"]["headline"]
    assert model["brief"]["riskAxes"] == artifact["brief"]["riskAxes"]

    finding = model["findings"][0]
    art_finding = artifact["findings"][0]
    assert finding["title"] == art_finding["title"]
    assert finding["cvssVector"] == art_finding["cvssVector"]
    assert finding["sections"] == art_finding["sections"]
    assert finding["evidence"] == art_finding["evidence"]
    assert finding["reproduction"] == art_finding["reproduction"]
    assert finding["provenance"] == art_finding["provenance"]

    # Business static projection also comes from the artifact.
    assert business["bottomLine"] == artifact["business"]["bottomLine"]
    assert business["dimensions"] == artifact["business"]["dimensions"]
    assert business["ease"] == artifact["business"]["ease"]
    assert business["held"] == artifact["business"]["held"]


def test_editing_the_artifact_changes_the_published_report(module):
    """The report tracks the artifact, proving de-hardcoded / data-driven behavior."""
    artifact = load_artifact()
    artifact["severitySummary"] = "EDITED severity summary sentinel."
    artifact["findings"][0]["sections"][0]["prose"] = "EDITED impact prose sentinel."
    artifact["business"]["bottomLine"] = "EDITED bottom line sentinel."
    with artifact_override(module, artifact):
        model, business = module._build_libheif_model(sample_event(), MODEL_ID)
    assert model["severitySummary"] == "EDITED severity summary sentinel."
    assert model["findings"][0]["sections"][0]["prose"] == "EDITED impact prose sentinel."
    assert business["bottomLine"] == "EDITED bottom line sentinel."


def test_receipt_is_transaction_derived_not_artifact_derived(module):
    """The WORM receipt binds to the approved transaction, never the static artifact."""
    artifact = load_artifact()
    model, _business = module._build_libheif_model(sample_event(), MODEL_ID)
    # The committed artifact ships a placeholder receipt with different hashes.
    assert artifact["receipt"]["evidenceHash"] != GRADE_HASH
    assert model["receipt"]["evidenceHash"] == GRADE_HASH
    assert model["receipt"]["artifactVersion"] == VERSION_ID
    assert model["receipt"]["bundleSha256"] == BUNDLE_SHA256
    # The placeholder artifact hashes must never reach the published model.
    dumped = json.dumps(model)
    assert artifact["receipt"]["evidenceHash"] not in dumped
    assert artifact["receipt"]["bundleSha256"] not in dumped
    assert artifact["receipt"]["artifactVersion"] not in dumped


def test_resolution_still_drives_reader_facing_content_over_the_artifact(module):
    """Resolution overlay (reader/order/actions) wins over any static artifact values."""
    event = sample_event()
    event["resolution"] = sample_resolution(
        "product_security_owner",
        [
            "map_downstream_exposure",
            "upgrade_or_backport",
            "retain_regression_coverage",
        ],
    )
    model, business = module._build_libheif_model(event, MODEL_ID)
    assert model["brief"]["primaryReader"] == "product_security_owner"
    assert model["brief"]["primaryAction"].startswith("Map packages and products")
    assert model["findings"][0]["remediation"]["downstreamActions"] == [
        action["action"] for action in model["brief"]["stakeholderActions"]
    ]
    assert [decision["title"] for decision in business["decisions"]][0] == (
        "Map releases, packages, and advisories"
    )
    # evidenceConfidence is not a published brief field even if present in an artifact.
    assert "evidenceConfidence" not in model["brief"]


def test_missing_artifact_fails_closed(module):
    prev = os.environ.get(module.LIBHEIF_ARTIFACT_ENV_VAR)
    os.environ[module.LIBHEIF_ARTIFACT_ENV_VAR] = os.path.join(
        tempfile.gettempdir(), "definitely-missing-finding-artifact.json"
    )
    try:
        assert_refused(module, sample_event(), "finding artifact is unavailable")
    finally:
        if prev is None:
            os.environ.pop(module.LIBHEIF_ARTIFACT_ENV_VAR, None)
        else:
            os.environ[module.LIBHEIF_ARTIFACT_ENV_VAR] = prev


def test_artifact_must_bind_to_approved_transaction(module):
    artifact = load_artifact()
    artifact["findings"][0]["affected"]["vulnerableCommit"] = "0" * 40
    with artifact_override(module, artifact):
        assert_refused(module, sample_event(), "artifact vulnerable commit mismatch")

    artifact = load_artifact()
    artifact["findings"][0]["fixed"]["exactFixCommit"] = "0" * 40
    with artifact_override(module, artifact):
        assert_refused(module, sample_event(), "artifact exact fix commit mismatch")

    artifact = load_artifact()
    artifact["findings"][0]["id"] = "F-99"
    with artifact_override(module, artifact):
        assert_refused(module, sample_event(), "artifact finding set does not match")

    artifact = load_artifact()
    artifact["findings"][0]["evidence"]["fixedMarker"] = "returned error? 0 output=1"
    with artifact_override(module, artifact):
        assert_refused(module, sample_event(), "artifact evidence fixed marker mismatch")


def main():
    module = load_module()
    tests = [
        test_libheif_publication_configuration_is_required,
        test_private_url_rejected,
        test_unsupported_profile_skips_after_configured,
        test_libheif_publication_secrets_and_password_strength_are_required,
        test_publish_posts_shaped_report,
        test_rejected_or_incomplete_transaction_is_refused,
        test_verifier_checks_must_be_canonical_and_unique,
        test_transaction_tuple_must_match_across_stages,
        test_security_hub_export_must_be_exact,
        test_semantic_proof_must_match_published_claims,
        test_report_resolution_is_required_exact_and_bound,
        test_report_resolution_enums_and_model_pin_fail_closed,
        test_valid_resolution_reorders_only_fixed_report_content,
        test_payload_matches_pinned_target_lock,
        test_report_is_built_from_committed_artifact,
        test_editing_the_artifact_changes_the_published_report,
        test_receipt_is_transaction_derived_not_artifact_derived,
        test_resolution_still_drives_reader_facing_content_over_the_artifact,
        test_missing_artifact_fails_closed,
        test_artifact_must_bind_to_approved_transaction,
    ]
    for test in tests:
        test(module)
        print(f"ok: {test.__name__}")


if __name__ == "__main__":
    main()
