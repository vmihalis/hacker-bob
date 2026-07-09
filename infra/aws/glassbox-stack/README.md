# glassbox-stack — AgentCore Runtime + containment VPC + evidence/approval sinks (IaC)

CDK or SAM. Provisions the deployment substrate. Authorized deployment/containment infra.

- **AgentCore Runtime** — `networkMode:VPC` + a **deny-by-default egress SG** (only the
  KyberFork/Locker in-VPC targets + the Bedrock VPC endpoint reachable; no `0.0.0.0/0`) +
  `requireMMDSV2=true`.
- **EFS** mount for `HOME` persistence across the split GRADE / resume-REPORT invocations.
- **S3** bucket with **Object Lock (COMPLIANCE / WORM)** for evidence.
- **Security Hub** custom product ARN registration.
- **Step Functions** state machine: `[invoke Runtime→GRADE] → [.waitForTaskToken human approval] → [invoke Runtime resume→REPORT/finalize/export-security-hub]`.
- **Execution role:** `bedrock:InvokeModel` + `InvokeModelWithResponseStream`, `s3:PutObject`
  (object-lock), `securityhub:BatchImportFindings`; trust `bedrock-agentcore.amazonaws.com`.
- **CloudTrail** (config only — the independent second witness).

**Hard prereq:** Bedrock model-access grant for Opus 4.8 + Sonnet 5, us-east-1, acct 359924468907.
Runbook: `aabw-2026/projects/06-aws-glassbox/AGENTCORE-BRANCH-PLAN.md`. TODO(build-day): author the stack.
