# feat/agentcore-rail-b — AWS AgentCore Runtime deployment scaffold

This branch authors the `run.mjs`-equivalent glue that `infra/runner/runner-contract.md`
explicitly defers ("Out of scope for this node… a publisher, not a new engine path"),
targeting **AWS AgentCore Runtime** instead of bare EC2. The `mcp` engine, the v2 FSM,
the 19-role two-tier model map, and every containment mechanism run **UNCHANGED** inside
the microVM. This is authorized **wrap / deploy / containment DevOps** of a disclosed
toolkit — it adds **no offensive capability**.

**Full runbook:** `aabw-2026/projects/06-aws-glassbox/AGENTCORE-BRANCH-PLAN.md`
**Targets (owned instances only, never live production/mainnet):**
- `KYBERFORK-SPEC.md` — smart-contract / EVM pack, the deterministic anchor (anvil fork @ block 17050000).
  Runs via the public-archive-fork path (`infra/aws/glassbox-stack/template.yaml`'s
  `ArchiveRpcGatewayEgressRule`, fx-kyber-iac) — see `../aws/kyberfork/README.md`'s "Build-day egress
  hygiene" section for the vendored-source + pre-baked-solc/svm requirement this scaffold's image
  build must satisfy.
- `LOCKER-SPEC.md` — web pack, the breadth demo (self-hosted CyStack Locker).

## Scaffold status: STUBS
Each file below is a skeleton with `TODO(build-day)` markers keyed to the runbook.
Build order (P0 first): grant+MMDSv2 → KyberFork → entrypoint+Dockerfile+Runtime(VPC)
→ Bedrock env → minimal end-to-end capability run. P1 adds the Locker second engagement
(parallel isolated session) + the AWS sinks.

Files:
- `agentcore-entrypoint.py` — the ~5-line BedrockAgentCoreApp wrapper.
- `Dockerfile` — microVM image (claude CLI + Node + hacker-bob; HOME→EFS).
- `bedrock-model-overrides.json` — settings overlay (opus/sonnet → Bedrock inference profiles).
- `callback-ssrf-guard.js` — (P2) runtime SSRF/allowlist guard for callbackUrl.
- `../../mcp/lib/tools/export-security-hub-finding.js` — Security Hub ASFF + S3 Object Lock sink.
- `../../.claude/hooks/bob-approval-gate.{sh,py}` — Step Functions human-approval PreToolUse gate.
- `../aws/{glassbox-stack,kyberfork,locker}/` — IaC.
