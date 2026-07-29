#!/usr/bin/env python3
"""Enable and verify AgentCore Runtime MMDSv2 after native CFN creation.

The live AWS::BedrockAgentCore::Runtime schema does not yet expose
MetadataConfiguration. The current update API does, so this one bounded
post-deploy step closes that service/schema gap without replacing the native
resource with a provisioning custom resource.
"""

import argparse
import json
import sys
import time
import uuid

import boto3


UPDATE_OPTIONAL_FIELDS = (
    "description",
    "protocolConfiguration",
    "environmentVariables",
    "lifecycleConfiguration",
    "authorizerConfiguration",
    "requestHeaderConfiguration",
    "filesystemConfigurations",
)


def wait_for_stable(client, runtime_id, timeout_seconds=600):
    deadline = time.monotonic() + timeout_seconds
    while True:
        runtime = client.get_agent_runtime(agentRuntimeId=runtime_id)
        status = runtime.get("status")
        if status == "READY":
            return runtime
        if status in {"CREATE_FAILED", "UPDATE_FAILED", "DELETE_FAILED"}:
            raise RuntimeError(
                f"AgentCore Runtime {runtime_id} entered {status}: "
                f"{runtime.get('failureReason') or 'no failure reason returned'}"
            )
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"Timed out waiting for AgentCore Runtime {runtime_id}; last status={status}"
            )
        time.sleep(5)


def update_payload(runtime):
    payload = {
        "agentRuntimeId": runtime["agentRuntimeId"],
        "agentRuntimeArtifact": runtime["agentRuntimeArtifact"],
        "roleArn": runtime["roleArn"],
        "networkConfiguration": runtime["networkConfiguration"],
        "metadataConfiguration": {"requireMMDSV2": True},
        "clientToken": str(uuid.uuid4()),
    }
    for field in UPDATE_OPTIONAL_FIELDS:
        value = runtime.get(field)
        if value not in (None, {}, []):
            payload[field] = value
    return payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-id", required=True)
    parser.add_argument("--profile")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--timeout-seconds", type=int, default=600)
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    client = session.client("bedrock-agentcore-control")
    runtime = wait_for_stable(client, args.runtime_id, args.timeout_seconds)

    enabled = runtime.get("metadataConfiguration", {}).get("requireMMDSV2") is True
    if not enabled:
        if args.check_only:
            print(f"Runtime {args.runtime_id} is not MMDSv2-enabled", file=sys.stderr)
            return 2
        client.update_agent_runtime(**update_payload(runtime))
        runtime = wait_for_stable(client, args.runtime_id, args.timeout_seconds)
        enabled = runtime.get("metadataConfiguration", {}).get("requireMMDSV2") is True

    if not enabled:
        raise RuntimeError(f"Runtime {args.runtime_id} update completed without requireMMDSV2=true")

    print(json.dumps({
        "agentRuntimeArn": runtime.get("agentRuntimeArn"),
        "agentRuntimeId": runtime.get("agentRuntimeId"),
        "agentRuntimeVersion": runtime.get("agentRuntimeVersion"),
        "status": runtime.get("status"),
        "requireMMDSV2": True,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
