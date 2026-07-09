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
import subprocess, json, os

# TODO(build-day): `pip install bedrock-agentcore` in the Dockerfile.
from bedrock_agentcore import BedrockAgentCoreApp

app = BedrockAgentCoreApp()


@app.entrypoint
def invoke(payload):
    # payload["target"] = our in-VPC target's private DNS ONLY:
    #   KyberFork anvil node  -> "kyberfork.internal:8545"   (SC/EVM engagement, the anchor)
    #   self-hosted Locker    -> "locker.internal"           (web engagement, the breadth demo)
    # BRIGHT LINE: this MUST be one of our owned in-VPC instances. Never a live/archive RPC,
    # Etherscan, kyberswap.com, Locker's hosted service, real mainnet, or a bounty path.
    # scope.js enforces block_internal_hosts=true; BOB_LAB_TARGET_ACK stays unset.
    target = payload["target"]
    sess = f"{os.environ['HOME']}/hacker-bob-sessions/{target}"  # HOME = durable EFS mount

    subprocess.run(
        ["claude", "--dangerously-skip-permissions", "--print",
         "--mcp-config", os.environ["BOB_MCP_CONFIG"], "--strict-mcp-config",
         f"/hacker-bob:bob-evaluate {target}"],
        # NOTE: pass env DIRECTLY — do NOT route through bob-runner.ts's
        # CLAUDE_CHILD_ENV_ALLOWLIST (L67-94); it omits CLAUDE_CODE_USE_BEDROCK/AWS_* and
        # would silently drop the Bedrock creds.
        env={**os.environ, "CLAUDE_CODE_USE_BEDROCK": "1"},
        check=True,
    )

    # Return the last finalized report row as the response payload.
    # TODO(build-day): handle the split GRADE→REPORT invocation (Step Functions
    # .waitForTaskToken pauses between GRADE and REPORT; this entrypoint is invoked twice,
    # so the session must resume from EFS-persisted state on the second call).
    with open(f"{sess}/report-snapshots.jsonl") as fh:
        return json.loads(fh.read().splitlines()[-1])


app.run()  # serves the InvokeAgentRuntime contract; the v2 FSM runs unchanged in the microVM
