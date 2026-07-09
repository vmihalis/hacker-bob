# glassbox-stack — AgentCore Runtime + containment VPC + evidence/approval sinks (IaC)

**AWS SAM** (plain CloudFormation YAML, `Transform: AWS::Serverless-2016-10-31`) — not CDK. Provisions
the deployment substrate. Authorized deployment/containment infra; adds no offensive capability.

## Why SAM, not CDK
`hacker-bob`'s `package.json` has zero `aws-cdk-lib`/`cdk` dependencies today, and no `cdk.json` anywhere
in the repo. SAM is plain CloudFormation YAML plus a thin macro layer (`AWS::Serverless::Function`,
`AWS::Serverless::StateMachine`) — it needs no new npm toolchain, no bundler, no synth step beyond the SAM
CLI itself. That's the lightest option that still gets `AWS::Serverless::StateMachine`'s `DefinitionUri`
convenience for the Step Functions definition below. If a later node wants CDK's programmatic
constructs, that's a deliberate toolchain addition, not a default.

## Resources declared in `template.yaml`

- **AgentCore Runtime** (`GlassboxAgentCoreRuntime`) — `networkMode:VPC` + `requireMMDSV2:true`.
  See **"AgentCore Runtime provisioning"** below — this is the one piece authored as a documented
  custom resource rather than a native CFN resource type.
- **`glassbox-deny-egress-sg`** — deny-by-default egress security group. Egress limited to exactly:
  (i) `locker.internal` via an SG-to-SG reference (imported as the `LockerSecurityGroupId`
  parameter from the i3 stack — never a CIDR; `i2-kyberfork-iac`'s private anvil node is
  superseded, see `infra/aws/kyberfork/README.md`'s SUPERSEDED banner, so there is no
  corresponding SG-to-SG rule for it here anymore);
  (ii) the Bedrock VPC interface endpoint (`com.amazonaws.<region>.bedrock-runtime`), SG-to-SG only;
  (iii) **exactly one** parameterized, toggleable HTTPS rule to the Z.ai gateway
  (`ZaiGatewayEgressRule`, gated by `EnableZaiEgress`, default `true`) — the single declared
  `MODEL_PROVIDER=zai` interim hole, never an open exit. **Zero `0.0.0.0/0` rules anywhere** in this
  template — every security group (deny-SG, Bedrock endpoint SG, EFS SG) explicitly declares its own
  `SecurityGroupEgress` list specifically to suppress CloudFormation's implicit "allow all outbound"
  default that any SG omitting that property silently receives.
- **EFS** (`HomeFileSystem` + two `HomeMountTarget*` + `HomeAccessPoint`) — mount for `$HOME`
  persistence across the split GRADE / resume-REPORT invocations. `mcp/lib/paths.js:44`'s
  `sessionsRoot()` has no env override, so `$HOME/hacker-bob-sessions` must resolve onto this mount at
  the container/task layer (the Dockerfile/entrypoint node's job, not this stack's) — this stack only
  supplies the durable mount + POSIX-scoped access point.
- **S3** (`EvidenceBucket`) — `ObjectLockEnabled: true`, default retention **`Mode: COMPLIANCE`**
  (never `GOVERNANCE`) for the evidence bundle (evidence pack + `report.md` + `grade.json` + snapshot
  row).
- **Security Hub** (`GlassboxSecurityHub`) — custom product registration. Enabling the Hub makes the
  account's own default product ARN
  (`arn:aws:securityhub:<region>:<account>:product/<account>/default`, exposed as the
  `SecurityHubProductArn` output) usable by `BatchImportFindings` for self-owned custom findings — no
  separate `CreateProductSubscription` call is needed for your own account's findings.
- **Step Functions** (`GlassboxEngagementStateMachine`, `AWS::Serverless::StateMachine`, definition at
  `statemachine/glassbox-engagement.asl.json`) — four logical stages: `InvokeAgentRuntimeThroughGrade`
  → `AwaitHumanApproval` (`.waitForTaskToken`, zero compute while waiting, fails closed on timeout or
  explicit rejection) → `ExportToSecurityHub` (ARCHITECTURAL FIX — see below; runs only once approval
  resolves, before the REPORT-stage runtime invocation) → `ResumeAgentRuntimeThroughReport`. The ASL only
  orchestrates two opaque Runtime invocations, one human pause, and one downstream export Lambda
  invocation — it does **not** encode or duplicate `mcp/lib/lifecycle-gates.js`'s
  `ALLOWED_TRANSITIONS`/`gateGradeToReport()` (unmodified, untouched by this node), consistent with
  `runner-contract.md`'s "no second grading path, no second seal" stance.
- **Execution role** (`GlassboxAgentRuntimeExecutionRole`) — trust `bedrock-agentcore.amazonaws.com`;
  policy grants exactly `bedrock:InvokeModel` + `InvokeModelWithResponseStream` (scoped to the two named
  inference-profile ARNs), `s3:PutObject` (scoped to `EvidenceBucket.Arn/*` — this also covers the
  GRADE-time WORM freeze write, see "ARCHITECTURAL FIX" below), `s3:GetObject` (scoped to
  `approvals/*.approved`), and `secretsmanager:GetSecretValue` (scoped to the zai token + approval HMAC
  key). No wildcard `Action`/`Resource` in this role's policy. **This role does NOT hold
  `securityhub:BatchImportFindings`** — see "ARCHITECTURAL FIX" below.
- **ARCHITECTURAL FIX — downstream Security Hub export** (`ExportSecurityHubFunction` /
  `ExportSecurityHubRole`) — the un-forgeable "human approval before external notification" property
  cannot be enforced by an in-process gate under `claude --dangerously-skip-permissions` (the model
  controls its own env/Bash, so any in-process gate leaks). AWS Security Hub export was moved OUT of the
  model-reachable MCP tools entirely (`bob_export_security_hub_finding` was deregistered — the
  implementation module survives as a library, `mcp/lib/tools/export-security-hub-finding.js`, sharing
  its pure ASFF-building logic with the Lambda below via `mcp/lib/asff-builder.js`) and now runs ONLY as
  `ExportSecurityHubFunction`, a Step Functions Task invoked strictly AFTER `AwaitHumanApproval` resolves
  (see `statemachine/glassbox-engagement.asl.json`'s `ExportToSecurityHub` state). It executes under its
  own `ExportSecurityHubRole` — trust `lambda.amazonaws.com`; granted `securityhub:BatchImportFindings`
  (the ONLY grant of that action in this template) and `s3:GetObject` scoped to
  `EvidenceBucket.Arn/hacker-bob/grade-freeze/*` only (never `s3:PutObject`/`DeleteObject` — it cannot
  write or remove the evidence it exports). It reads ONLY the GRADE-time WORM freeze object written by
  `mcp/lib/grade-freeze-store.js`'s `writeGradeFreezeBundleSync` (called from `writeGradeVerdict`,
  additive, BEFORE any human approval exists, keyed by content-derived `grade_verdict_hash`) — never live
  EFS session state, never `claims.jsonl`, never a re-run `bob_finalize_report` snapshot. The model's own
  execution role neither assumes `ExportSecurityHubRole` nor holds `securityhub:BatchImportFindings`
  itself, so even a rogue in-process model with full Bash access cannot call `BatchImportFindings`
  directly, and cannot change what an already-approved `grade_verdict_hash` exports (a post-approval
  mutation of `claims.jsonl`/`report.md` either lands under a different hash-keyed WORM object or is
  refused outright — the object is retained under the SAME `EvidenceBucket` Object Lock COMPLIANCE
  policy). `BOB_GRADE_FREEZE_BUCKET` (threaded into the Runtime env, same `EvidenceBucket`) activates the
  freeze write; it is a silent no-op wherever that env var is unset (every non-AWS-branch local/CI/
  interactive session).
- **CloudTrail** (`GlassboxTrail`) — management events + optional S3 data events scoped to
  `EvidenceBucket` only (who touched the WORM-locked evidence), config only. The independent second
  witness alongside the hash-chained finding pipeline.
- **fx-kyber-iac archive-RPC egress path** — the single declared public-egress hole so
  `bob_foundry_run(chain_id=1, fork_block=17050000)` (the KyberFork EVM pack's public-archive-fork
  run, per `KYBERFORK-SPEC.md`'s REFRAMED retarget — see `infra/aws/kyberfork/README.md`) can reach
  its one pinned archive-RPC host from *inside* the deny-egress microVM. Two enforcement layers for
  the SAME one path, gated together by `EnableArchiveRpcEgress` (default `true`, mirrors
  `EnableZaiEgress`): (i) `ArchiveRpcGatewayEgressRule`, a standalone HTTPS-only
  `AWS::EC2::SecurityGroupEgress` scoped to `ArchiveRpcCidr`; (ii) a Route 53 Resolver DNS Firewall
  ALLOW/BLOCK-all pair (`ArchiveRpcAllowedDomainList` allowing only `ArchiveRpcHost`,
  `ArchiveRpcDenyAllDomainList` catching `["*"]`, `ArchiveRpcFirewallRuleGroup` +
  `ArchiveRpcAllowRule`/`ArchiveRpcDenyAllRule` at Priority 100/200, associated to the VPC at
  Priority 101) — the explicit catch-all BLOCK rule is what makes the allow-list deny-by-default,
  since Resolver DNS Firewall's own undeclared default is ALLOW. `ArchiveRpcHost` is also threaded
  into the Runtime env as `BOB_EVM_RPCS_1` (see "AgentCore Runtime provisioning" below), populating
  the pre-existing `mcp/lib/evm-rpc-pool.js` `BOB_EVM_RPCS_<CHAIN_ID>` contract for `chain_id=1` so
  `bob_foundry_run` forks from exactly that one host — not a new contract, an existing one populated
  at deploy time, out of the model's reach.

## AgentCore Runtime provisioning

At authoring time this template could not confirm a stable, GA'd native `AWS::BedrockAgentCore::Runtime`
CloudFormation resource type/property schema. Per this node's instructions ("if no native CFN resource
type exists yet, declare it as a documented custom resource / manual step... do not silently omit it"),
the Runtime is **not silently omitted** — it's declared as a Lambda-backed CloudFormation custom resource
(`Custom::AgentCoreRuntime`, backed by `AgentCoreRuntimeProvisionerFunction` in `template.yaml`) that
calls `create_agent_runtime`/`update_agent_runtime`/`delete_agent_runtime` with
`networkConfiguration.networkMode: VPC` and `instanceMetadataConfiguration.httpTokens: required` (the
IMDSv2-required semantics `requireMMDSV2` maps to, mirroring EC2's `MetadataOptions.HttpTokens`).

Before `sam deploy`, a human should:
1. Check whether AWS has since published a native `AWS::BedrockAgentCore::Runtime` CFN resource type in
   the target account/region. If so, swap the `Custom::AgentCoreRuntime` block for the native resource —
   the custom-resource Lambda's inline handler documents the exact property shape it currently guesses at
   (`agentRuntimeArtifact.containerConfiguration.containerUri`, `roleArn`, `networkConfiguration`,
   `instanceMetadataConfiguration`), which is the mapping to carry over.
2. If no native resource exists yet, verify the `bedrock-agentcore-control` boto3 client/operation names
   the inline handler assumes, against the SDK version available at deploy time.
3. As a fully manual fallback (skip the custom resource entirely), the equivalent is a human running
   `aws bedrock-agentcore-control create-agent-runtime` directly with the same network/role config — also
   human-gated, also not run by this node.

`BOB_EVM_RPCS_1` (fx-kyber-iac) is set the same way as `BOB_LAB_TARGET` above: resolved from the
`ArchiveRpcHost` custom-resource property inside `AgentCoreRuntimeProvisionerFunction`'s inline
handler, in **both** the Create and Update branches, and only when non-empty (i.e. only when
`EnableArchiveRpcEgress="true"` — see `GlassboxAgentCoreRuntime`'s `ArchiveRpcHost` property). It
populates the pre-existing `mcp/lib/evm-rpc-pool.js` `BOB_EVM_RPCS_<CHAIN_ID>` contract for
`chain_id=1` (a comma-separated URL list — a single pinned URL is a valid one-element list); the
engine file itself is untouched by this node.

## Known limitations

- **`ZaiGatewayCidr`** ships with a `203.0.113.1/32` placeholder (TEST-NET-3, RFC 5737) — a human must
  override it with the real resolved Z.ai gateway address before deploy, and refresh it if that address
  changes. Security groups can't match on FQDN; this CIDR is the SG-level proxy for `ZaiGatewayHost`.
- **`ZaiGatewayHost` is load-bearing, not documentation-only.** `EnableZaiEgress` defaults to `"true"`
  and `ZaiGatewayHost` defaults to `""` — left at that default, the SG-level CIDR hole
  (`ZaiGatewayEgressRule`) still opens, but the Route 53 Resolver DNS Firewall allow-list
  (`ArchiveRpcAllowedDomainList`, gated by `ZaiGatewayHostKnownCondition`) only admits the real Z.ai
  FQDN when `ZaiGatewayHost` is non-empty, so a default deploy blackholes DNS resolution (NODATA via the
  Priority-200 `"*"` catch-all) for the gateway the default `MODEL_PROVIDER=zai` path needs. The template
  now refuses to deploy in this state (see the top-level `Rules:` block,
  `ZaiGatewayHostRequiredWhenEgressEnabled`) — set `ZaiGatewayHost` to the real FQDN before deploy
  whenever `EnableZaiEgress="true"`, or pass `EnableZaiEgress="false"` if the interim path is not needed.
- **`ArchiveRpcCidr`** ships with a `198.51.100.1/32` placeholder (TEST-NET-2, RFC 5737, deliberately
  distinct from `ZaiGatewayCidr`'s TEST-NET-3 placeholder) — a human must override it with the real
  resolved archive-RPC IP/CIDR before deploy, and refresh it if that address changes. This is the
  SG-level enforcement companion to the `ArchiveRpcHost` Route 53 Resolver DNS Firewall ALLOW rule;
  never widen either to `0.0.0.0/0`.
- **`AWS::SecurityHub::Hub`** is a singleton per account/region — if Security Hub is already enabled by
  another stack in the target account/region, this resource fails on create. Adopt the existing Hub (drop
  this resource, keep the `SecurityHubProductArn` output as-is — the default product ARN format doesn't
  change) rather than deploying a second one.
- **VPC/NAT topology is assumed, not provisioned.** `VpcId`/`SubnetIds` are parameters pointing at an
  existing VPC. If the interim `MODEL_PROVIDER=zai` egress path needs a NAT gateway/IGW route to reach
  the public Z.ai host, that routing is expected to already exist on the imported subnets — this stack
  only opens the security-group port, it does not build NAT/IGW/route-table resources. Same convention
  applies to `ArchiveRpcGatewayEgressRule` (fx-kyber-iac): it only opens the SG port; a human must
  ensure the imported `VpcId`/`SubnetIds` already have a NAT Gateway/IGW route to the archive-RPC host
  before deploy.
- **`LockerSecurityGroupId`** is a plain `String` parameter, not `AWS::EC2::SecurityGroup::Id`-typed,
  specifically so a human can pass `!ImportValue` from the i3 stack's own Output once it's deployed
  (i3-locker-iac — a separate node). `i2-kyberfork-iac` no longer has a corresponding parameter here:
  it's superseded by the archive-RPC egress path above (see `infra/aws/kyberfork/README.md`).
- **Bedrock inference-profile ARNs** (`BedrockOpusModelId`/`BedrockSonnetModelId` defaults
  `us.anthropic.claude-opus-4-8` / `us.anthropic.claude-sonnet-5`) are best-effort; confirm the exact
  suffix against `aws bedrock list-inference-profiles` before the `MODEL_PROVIDER=bedrock` flip. Not
  needed to build or deploy on the interim `MODEL_PROVIDER=zai` path.

## How to validate/deploy (HUMAN-GATED — do not run these yourself)

```bash
# From infra/aws/glassbox-stack/
sam validate --template template.yaml     # HUMAN-GATED
sam deploy --guided                        # HUMAN-GATED
```

Neither command was executed while authoring this stack. `sam validate`/`cdk synth`-equivalent structural
checks are the live-AWS-credential-requiring step a human runs separately; this node's own done-condition
is the structural verify below, not a live validate.

**Hard prereq (Bedrock path only):** a Bedrock model-access grant for **Opus 4.8 + Sonnet 5**,
**us-east-1**, **acct `<ACCOUNT_ID>`** is required only to flip `MODEL_PROVIDER=bedrock` for the final
AI/ML-on-AWS run (`GlassboxAgentRuntimeExecutionRole`'s `bedrock:InvokeModel` grant, and the Bedrock VPC
endpoint above, are pre-wired for it). It is **not** required to build this stack or to run the interim
`MODEL_PROVIDER=zai` path — see `AGENTCORE-BRANCH-PLAN.md`'s "Model prerequisite (no longer a hard
blocker)" section.

Runbook: `aabw-2026/projects/06-aws-glassbox/AGENTCORE-BRANCH-PLAN.md` (whole file — the build-day
runbook this stack implements `Files` line `infra/aws/glassbox-stack/` from).

## Downstream consumption

- `i3-locker-iac` attaches its own security group's id as this stack's `LockerSecurityGroupId`
  parameter (via stack Output → `!ImportValue`, or a direct sg-id) so `glassbox-deny-egress-sg` can
  reference it by SG-to-SG rule. `i2-kyberfork-iac` no longer participates here — see the
  `fx-kyber-iac archive-RPC egress path` bullet above.
- `h2-deploy` invokes this stack's `AgentRuntimeArn` output and `StateMachineArn` output.

## Outputs

`DenyEgressSecurityGroupId`, `EfsAccessPointArn`, `EfsFileSystemId`, `EvidenceBucketArn`,
`SecurityHubProductArn`, `StateMachineArn`, `ExecutionRoleArn`, `AgentRuntimeArn`.

## Scope-gate attestation (build-verified 2026-07-09 — REQUIRED at deploy)
The engine's `mcp/lib/lab-target-attest.js` rejects `.internal`/`.local` DNS targets; only RFC1918/loopback IPv4 literals are lab-eligible, under an explicit operator attestation. So the AgentCore Runtime env MUST carry (set here at deploy, out of the model's reach so a compromised bob cannot self-authorize):
- `BOB_AGENTCORE=1` — REQUIRED at deploy. Activates every AgentCore-only branch: the GRADE→REPORT
  human-approval gate (`mcp/lib/lifecycle-gates.js`'s `gradeToReportApprovalBlocker` +
  `.claude/hooks/bob-approval-gate-impl.py`) as well as the `BOB_LAB_TARGET_ACK` scope-gate check
  below. Without it the engine behaves exactly as it does today (local/interactive/CI) — every
  gate this stack wires up is inert until this flag is set (see `template.yaml`'s
  `AgentCoreRuntimeProvisionerFunction`, the sole place it's set, out of the model's reach).
- `BOB_LAB_TARGET_ACK=i-own-and-am-authorized-to-test-these-private-targets`
- `BOB_LAB_TARGET=<the target's exact RFC1918 IP>` (the `BobLabTarget` CFN parameter — the
  KyberFork anvil node / Locker service private IP from i2 / i3)
- **Approval artifact — S3, NOT model-writable, content-bound (revised 2026-07-09c,
  fx-hmac-content closes the amend-and-reexport gap):**
  the human's `approvals/<target_domain>.approved` artifact =
  `{"hmac": HMAC-SHA256(target_domain + "|" + grade_verdict_hash, key), "grade_verdict_hash": <hash>}`
  lives in the dedicated `GlassboxApprovalsBucket`. The signature is bound to the EXACT graded
  content the human reviewed (`grade_verdict_hash` = the sha256-over-canonical-JSON of
  `grade.json`, the same hash `mcp/lib/report-finalize.js`'s `loadGradeVerdictHash` /
  `resolveReportFinalizationHashes` produce) — not merely `target_domain`. A post-approval
  amend+re-grade changes the current hash, so the SAME previously-valid artifact no longer
  verifies; re-export of amended content as "human-approved" is already blocked by this content
  binding (a short `approvals/` S3 lifecycle TTL, `template.yaml`'s
  `GlassboxApprovalsBucket.LifecycleConfiguration`, is a cheap belt-and-suspenders backstop on
  top, not load-bearing). The model's execution role has `s3:GetObject`
  on `approvals/*.approved` **only** — never `PutObject`/`Delete`/`List` — so a compromised bob
  **cannot forge it**. The SOLE producer is `ApprovalWriterFunction` (its own role is the only
  `PutObject` principal + the only `SendTaskSuccess` caller), invoked out-of-band after a human
  approves; it reads the pending record written by `ApprovalPendingRecorderFunction` (the ASL
  `AwaitHumanApproval` `.waitForTaskToken` state), which carries `gradeResult.grade_verdict_hash`
  threaded through unmodified from the GRADE-stage AgentCore invocation
  (`infra/runner/agentcore-entrypoint.py`'s `awaiting_approval` sentinel) — the writer refuses to
  sign if that hash is missing. Consumers (`lifecycle-gates.js` via
  `mcp/lib/approval-store.js`, and `.claude/hooks/bob-approval-gate-impl.py`) fetch from S3,
  independently resolve the CURRENT `grade_verdict_hash` (from the live `grade.json`), require it
  to equal the artifact's stored value, and verify the HMAC (`hmac.compare_digest`), keyed by the
  **port-stripped** `target_domain` — the same normalization the producer Lambda applies, so
  producer and consumer always agree.
and the engagement payload `target` must be that same RFC1918 IP (never a `.internal` name). `scope.js` then permits ONLY that one attested IP; everything else is refused at the scope gate AND has no network route.
