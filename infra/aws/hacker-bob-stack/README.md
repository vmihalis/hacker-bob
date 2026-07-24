# hacker-bob-stack - AgentCore Runtime + VPC containment + verifier/evidence sinks

This directory is the deployable AWS path for the Hacker Bob demo. It uses plain
CloudFormation/SAM transform YAML, not CDK.

The default demo target is the synthetic GitHub API fixture baked into the
runner image at `127.0.0.1:8081`. That keeps the demo owned, deterministic, and
cheap. External owned targets must disable `EnableBuiltInDemoTarget` and set
`BobLabTarget` to the exact approved private/loopback IPv4 host.

## What It Creates

- Native `AWS::BedrockAgentCore::Runtime` in `networkMode: VPC`.
- EFS access point mounted at `/mnt/efs`, with `$HOME=/mnt/efs/bob-home`, so
  `~/hacker-bob-sessions` persists across GRADE and REPORT invocations.
- Deny-by-default runtime security group with only these exits:
  - AWS interface endpoint SG on 443 for Bedrock Runtime, ECR, Logs, and Secrets Manager.
  - AWS-managed S3 prefix list on 443 for the S3 gateway endpoint.
  - EFS SG on 2049.
  - Optional Locker, Z.ai, and archive-RPC egress paths, all disabled by default.
- Object Lock COMPLIANCE evidence bucket for grade freeze bundles.
- Mutable approval-control bucket, HMAC signing key, integrity-verifier Lambda,
  verifier-only approval writer, SNS notification, plus task-token pending
  recorder / human approval writer for break-glass manual mode.
- Security Hub export Lambda under a separate role. The model runtime role never gets
  `securityhub:BatchImportFindings`.
- Bob-site sealed-report publisher Lambda under a separate role. The model runtime
  role never receives the Bob-site ingest token or report password.
- Standard Step Functions state machine:
  `InvokeAgentRuntimeThroughGrade -> RunVerifierGate -> WriteVerifierApproval -> NotifyHumanOnLoop -> ExportToSecurityHub -> ResumeAgentRuntimeThroughReport -> PublishBobSiteReport`.

GRADE returns the exact S3 `VersionId` and SHA-256 of the exact bytes it wrote.
The verifier reads that version directly (never `HEAD`/latest), confirms active
Object Lock COMPLIANCE retention, recomputes the byte hash and canonical grade
hash. A separate verifier-only writer signs compact UTF-8 JSON
`[profile,target,grade_hash,body_sha256,version_id]` and stores the result at
`approvals/<target>/<grade_hash>.approved`. Export consumes the verifier-approved
version and byte hash, not mutable session state or the latest S3 version. The
human is on the loop via SNS and Step Functions observability, with stop/reject
authority outside the model path; the default transition is owned by verifier
success, not by a callback token.

## Model State

Opus 4.8 and Sonnet 5 stay the intended production mapping:

- `us.anthropic.claude-opus-4-8`
- `us.anthropic.claude-sonnet-5`

Until a data-plane invoke succeeds for those profiles, use:

- `UseBedrockFallback=true`
- `BedrockFallbackModelId=us.anthropic.claude-haiku-4-5-20251001-v1:0`

That is a labeled demo/rehearsal fallback. It does not prove the newest-model
Bedrock gate is green.

The runtime also sets `BOB_MAX_BUDGET_USD=2.00`; the entrypoint passes this to
Claude Code as `--max-budget-usd` for each `--print` invocation.

## Build Image

From the repo root:

```bash
docker buildx build \
  --platform linux/arm64 \
  --load \
  -t hacker-bob-agentcore:demo \
  -f infra/runner/Dockerfile .

docker image inspect hacker-bob-agentcore:demo \
  --format '{{.Architecture}} {{.Size}}'
```

AgentCore currently caps images at 2048 MB. The build must report `arm64` and a
size below that cap before pushing.

## Package Template

From the repo root:

```bash
infra/aws/hacker-bob-stack/scripts/prepare-package.sh

aws cloudformation package \
  --profile hacker-bob-359924468907 \
  --region us-east-1 \
  --template-file infra/aws/hacker-bob-stack/template.yaml \
  --s3-bucket <private-package-bucket> \
  --output-template-file /tmp/hacker-bob-packaged.yaml

aws cloudformation validate-template \
  --profile hacker-bob-359924468907 \
  --region us-east-1 \
  --template-body file:///tmp/hacker-bob-packaged.yaml
```

Preflight the regional S3 prefix list:

```bash
aws ec2 describe-managed-prefix-lists \
  --profile hacker-bob-359924468907 \
  --region us-east-1 \
  --query "PrefixLists[?PrefixListName=='com.amazonaws.us-east-1.s3'].PrefixListId" \
  --output text
```

For us-east-1 this should be `pl-63a5400a`, the template default.

## In-place deployment safety

The live demo stack is `glassbox-agentcore-demo`. Its `Glassbox*` logical IDs and
`glassbox-*` physical names are deliberately retained in this Hacker Bob template:
the Object-Lock evidence bucket cannot be replaced, the account has only one
Security Hub, and duplicate private-DNS VPC endpoints would fail. Do not rename
those infrastructure identities and do not deploy this template as a second stack.

Every update starts as an unexecuted UPDATE change set. Reuse all live parameters,
overriding only the new private ECR image digest:

```bash
STACK=glassbox-agentcore-demo
CHANGE_SET=hacker-bob-libheif-$(date +%Y%m%d%H%M%S)
IMAGE_URI=<account>.dkr.ecr.us-east-1.amazonaws.com/hacker-bob-agentcore-demo@sha256:<digest>
ARTIFACT_BUCKET=<private-cfn-artifact-bucket>

aws cloudformation describe-stacks \
  --profile hacker-bob-359924468907 --region us-east-1 \
  --stack-name "$STACK" --query 'Stacks[0].Parameters' --output json \
| jq --arg image "$IMAGE_URI" '[
    .[]
    | select(.ParameterKey != "HumanApprovalTimeoutSeconds")
    | if .ParameterKey == "AgentContainerImageUri"
      then {ParameterKey,ParameterValue:$image}
      else {ParameterKey,UsePreviousValue:true}
      end
  ]' > /tmp/hacker-bob-change-parameters.json

aws s3 cp /tmp/hacker-bob-packaged.yaml \
  "s3://${ARTIFACT_BUCKET}/change-sets/${CHANGE_SET}.yaml" \
  --profile hacker-bob-359924468907 --region us-east-1

aws cloudformation create-change-set \
  --profile hacker-bob-359924468907 --region us-east-1 \
  --stack-name "$STACK" --change-set-name "$CHANGE_SET" \
  --change-set-type UPDATE \
  --template-url "https://${ARTIFACT_BUCKET}.s3.us-east-1.amazonaws.com/change-sets/${CHANGE_SET}.yaml" \
  --parameters file:///tmp/hacker-bob-change-parameters.json \
  --capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND

aws cloudformation wait change-set-create-complete \
  --profile hacker-bob-359924468907 --region us-east-1 \
  --stack-name "$STACK" --change-set-name "$CHANGE_SET"

aws cloudformation describe-change-set \
  --profile hacker-bob-359924468907 --region us-east-1 \
  --stack-name "$STACK" --change-set-name "$CHANGE_SET" \
  --query 'Changes[].ResourceChange.{Action:Action,Logical:LogicalResourceId,Type:ResourceType,Replacement:Replacement}' \
  --output table
```

Hard stop if the preview contains any `Remove`, any `Replacement: True`, or an
`Add` other than the new verifier role/function (and transform-generated Lambda
version/layer artifacts). In particular, `EvidenceBucket`, EFS/access points,
VPC endpoints/security groups, `GlassboxSecurityHub`, `GlassboxAgentCoreRuntime`,
`GlassboxEngagementStateMachine`, and the approval/CloudTrail buckets must show no
replacement. Delete the unexecuted change set after audit if any invariant fails.
Execution remains a separate human decision.

After the runtime is `READY`, enforce MMDSv2 with boto3 because the current
CloudFormation resource schema does not expose `metadataConfiguration`:

```bash
uv run --with boto3==1.43.46 --with 'botocore[crt]==1.43.46' python \
  infra/aws/hacker-bob-stack/scripts/enforce-mmdsv2.py \
  --profile hacker-bob-359924468907 \
  --region us-east-1 \
  --runtime-id <agent-runtime-id>
```

Run the same helper with `--check-only` after deploys.

## Human-on-the-loop libheif demo

The hero input is intentionally only the sealed profile name. It accepts no
operator-selected commit, harness, binary path, or expected sanitizer marker:

```json
{"profile":"libheif-cve-2026-49271"}
```

Start it with a memorable execution name. The default path no longer pauses on a
task token: verifier success writes the content-bound approval artifact, publishes
a token-free notification, and continues to Security Hub + REPORT + optional
Bob-site sealed-report publish.

```bash
EXECUTION_NAME=hacker-bob-libheif-hero-<date-or-rehearsal-id>

aws stepfunctions start-execution \
  --region <region> \
  --state-machine-arn <StateMachineArn> \
  --name "$EXECUTION_NAME" \
  --input '{"profile":"libheif-cve-2026-49271"}'
```

The visible path is:

```text
sealed replay -> exact WORM freeze -> automated integrity verifier
              -> verifier approval artifact -> human-on-loop notice
              -> Security Hub -> deterministic REPORT -> Bob-site /r/<slug>
```

The SNS notification contains only the safe verifier-approval summary: profile,
target, grade hash, exact body SHA-256, exact VersionId, approval artifact key,
and verifier quorum names. There is no task token in the default path.

```bash
aws s3api list-objects-v2 \
  --region <region> \
  --bucket <HumanApprovalsBucketName> \
  --prefix approvals/libheif-cve-2026-49271/ \
  --query 'Contents[].{Key:Key,LastModified:LastModified,Size:Size}' \
  --output table
```

Critical demo opsec: do not project raw freeze bodies, raw sanitizer output, or
CloudWatch logs. Show the graph nodes, execution name, grade hash, WORM VersionId,
Object Lock status, verifier approval artifact key, Security Hub export result,
final report state, and the returned Bob-site `bob_site_url` / `bob_site_slug`
when publishing is configured.

Bob-site publishing is inert unless all three deploy parameters are set:
`BobSiteReportBaseUrl`, `BobSiteReportIngestToken`, and
`BobSiteReportAccessPassword`. The first is an HTTPS origin; the token must match
Bob-site `INGEST_TOKEN`; the password is what unlocks `/r/<slug>` and must be
sent out of band.

## Break-glass manual approval mode

`ApprovalPendingRecorderFunction` and `ApprovalWriterFunction` remain in the stack
for old executions that started before the verifier-on-loop state machine was
deployed. They are not on the new default state-machine path. The stack
intentionally does not grant the runtime role
permission to invoke `ApprovalWriterFunction`; the state-machine role does not need
it on the default verifier-on-loop path. Before the event, a human IAM
administrator must grant `lambda:InvokeFunction` on exactly
`<ApprovalWriterFunctionArn>` to the named approver. That access decision remains a
human gate; this template does not invent or auto-assign an approver.

After reviewing the exact frozen version, the named human approves out of band:

```bash
aws lambda invoke \
  --region <region> \
  --function-name <ApprovalWriterFunctionArn> \
  --cli-binary-format raw-in-base64-out \
  --payload "{\"decision\":\"approve\",\"pendingRecordKey\":\"approvals/pending/${EXECUTION_NAME}.json\"}" \
  /tmp/hacker-bob-approval-response.json
```

That one call reads the pending binding, writes the schema-v2 HMAC artifact, and
only then calls `SendTaskSuccess`. It is the only success-resume path. A human can
reject instead; rejection writes no approval and resolves the task with
`SendTaskFailure`:

```bash
aws lambda invoke \
  --region <region> \
  --function-name <ApprovalWriterFunctionArn> \
  --cli-binary-format raw-in-base64-out \
  --payload "{\"decision\":\"reject\",\"reason\":\"evidence review failed\",\"pendingRecordKey\":\"approvals/pending/${EXECUTION_NAME}.json\"}" \
  /tmp/hacker-bob-rejection-response.json
```

The legacy target-only input and named `smoke` profile remain available for
plumbing rehearsals. They traverse the same verifier and verifier-approval
boundary by default; they never bypass WORM verification.

## Validation

Current local checks for this stack:

```bash
infra/aws/hacker-bob-stack/scripts/prepare-package.sh
uvx cfn-lint infra/aws/hacker-bob-stack/template.yaml
aws stepfunctions validate-state-machine-definition \
  --profile hacker-bob-359924468907 \
  --region us-east-1 \
  --definition file://infra/aws/hacker-bob-stack/statemachine/hacker-bob-engagement.asl.json
node --test test/export-security-hub-lambda.test.js test/asff-builder.test.js test/grade-freeze-store.test.js test/hacker-bob-template-approval-env.test.js
python3 test/publish_bob_site_report_lambda_test.py
```

## Outputs

Important outputs are `AgentRuntimeArn`, `ExecutionRoleArn`, `StateMachineArn`,
`EvidenceBucketArn`, `VerifierAttestationBucketArn`, `VerifierAttestationHmacSecretArn`,
`HumanApprovalsBucketName`, `ApprovalWriterFunctionArn`,
`ApprovalNotificationTopicArn`, `ExportSecurityHubFunctionArn`,
`PublishBobSiteReportFunctionArn`, `EfsAccessPointArn`, and `DenyEgressSecurityGroupId`.
