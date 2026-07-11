"use strict";

// Structural checks for the native AgentCore Runtime, execution boundary, and
// Step Functions orchestration in infra/aws/hacker-bob-stack.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const TEMPLATE_PATH = path.join(
  __dirname, "..", "infra", "aws", "hacker-bob-stack", "template.yaml",
);

const REQUIRED_ENV_KEYS = Object.freeze([
  "BOB_AGENTCORE",
  "BOB_LAB_TARGET_ACK",
  "BOB_LAB_TARGET",
  // fx-gate-hardening: BOB_APPROVAL_ARTIFACT_DIR (a writable-EFS path the model's own
  // execution role could reach) is REMOVED from production env vars — replaced by the
  // S3-backed verifier-attestation store's bucket + HMAC secret id.
  "BOB_APPROVAL_BUCKET",
  "BOB_APPROVAL_HMAC_SECRET_ID",
  "BOB_MAX_BUDGET_USD",
]);

function readTemplate() {
  return fs.readFileSync(TEMPLATE_PATH, "utf8");
}

test("GlassboxAgentCoreRuntime uses the live native CloudFormation resource", () => {
  const text = readTemplate();
  const runtime = extractResourceBlock(text, "GlassboxAgentCoreRuntime");
  assert.match(runtime, /Type:\s*AWS::BedrockAgentCore::Runtime/);
  assert.doesNotMatch(text, /Custom::AgentCoreRuntime|AgentCoreRuntimeProvisioner/);
  assert.match(runtime, /AgentRuntimeName:\s*glassbox_agent_runtime/);
  assert.match(runtime, /ProtocolConfiguration:\s*HTTP/);
  assert.match(runtime, /NetworkMode:\s*VPC/);
  assert.match(runtime, /ContainerUri:\s*!Ref AgentContainerImageUri/);
});

test("template preserves the deployed Glassbox identities for an in-place demo-stack update", () => {
  const text = readTemplate();
  const expected = [
    ["GlassboxAgentCoreRuntime", /AgentRuntimeName:\s*glassbox_agent_runtime/],
    ["GlassboxAgentRuntimeExecutionRole", /RoleName:\s*glassbox-agent-runtime-execution-role/],
    ["GlassboxDenyEgressSg", /GroupName:\s*glassbox-deny-egress-sg/],
    ["GlassboxApprovalsBucket", /BucketName:\s*!Sub glassbox-approvals-/],
    ["GlassboxApprovalHmacKey", /Name:\s*glassbox\/approval-hmac-key/],
    ["GlassboxEngagementStateMachine", /Name:\s*glassbox-engagement/],
    ["GlassboxStateMachineRole", /RoleName:\s*glassbox-state-machine-role/],
    ["GlassboxTrail", /TrailName:\s*glassbox-engagement-trail/],
    ["BedrockEndpointSecurityGroup", /GroupName:\s*glassbox-aws-service-endpoints-sg/],
    ["EfsSecurityGroup", /GroupName:\s*glassbox-efs-sg/],
    ["CloudTrailLogBucket", /BucketName:\s*!Sub glassbox-cloudtrail-/],
    ["ApprovalNotificationTopic", /TopicName:\s*glassbox-approval-notifications/],
    ["VerifierApprovalRole", /RoleName:\s*glassbox-verifier-approval-role/],
    ["VerifierApprovalFunction", /FunctionName:\s*glassbox-verifier-approval/],
    ["ApprovalPendingRecorderRole", /RoleName:\s*glassbox-approval-pending-recorder-role/],
    ["ApprovalPendingRecorderFunction", /FunctionName:\s*glassbox-approval-pending-recorder/],
    ["ApprovalWriterRole", /RoleName:\s*glassbox-approval-writer-role/],
    ["ApprovalWriterFunction", /FunctionName:\s*glassbox-approval-writer/],
    ["ExportSecurityHubRole", /RoleName:\s*glassbox-export-security-hub-role/],
    ["ExportSecurityHubFunction", /FunctionName:\s*glassbox-export-security-hub/],
    ["AsffBuilderLayer", /LayerName:\s*glassbox-asff-builder/],
    ["HomeAccessPoint", /Path:\s*\/home\/glassbox/],
  ];
  for (const [logicalId, physicalName] of expected) {
    assert.match(extractResourceBlock(text, logicalId), physicalName, `${logicalId} must retain its live identity`);
  }
  assert.match(extractResourceBlock(text, "GlassboxSecurityHub"), /Type:\s*AWS::SecurityHub::Hub/);
  assert.match(text, /Default:\s*glassbox-evidence/);
  assert.match(text, /ApprovalsBucketArn:/);
  assert.match(text, /ApprovalHmacSecretArn:/);
});

test("native Runtime carries the verifier-attestation, scope, provider, and model environment", () => {
  const runtime = extractResourceBlock(readTemplate(), "GlassboxAgentCoreRuntime");
  for (const key of REQUIRED_ENV_KEYS) {
    assert.match(runtime, new RegExp(`\\n\\s*${key}:`), `Runtime must set ${key}`);
  }
  for (const key of [
    "BOB_GRADE_FREEZE_BUCKET",
    "MODEL_PROVIDER",
    "CLAUDE_CODE_USE_BEDROCK",
    "ANTHROPIC_MODEL",
    "ANTHROPIC_DEFAULT_OPUS_MODEL",
    "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL",
  ]) {
    assert.match(runtime, new RegExp(`\\n\\s*${key}:`), `Runtime must set ${key}`);
  }
  assert.match(runtime, /MODEL_PROVIDER:\s*bedrock/);
  assert.match(runtime, /BedrockFallbackEnabledCondition/);
});

test("native Runtime mounts the declared EFS access point at /mnt/efs", () => {
  const runtime = extractResourceBlock(readTemplate(), "GlassboxAgentCoreRuntime");
  assert.match(runtime, /FilesystemConfigurations:/);
  assert.match(runtime, /AccessPointArn:\s*!GetAtt HomeAccessPoint\.Arn/);
  assert.match(runtime, /MountPath:\s*\/mnt\/efs/);
  assert.match(runtime, /HomeMountTargetA/);
  assert.match(runtime, /HomeMountTargetB/);
});
test("template.yaml defaults BobLabTarget only to the image-owned loopback fixture", () => {
  const text = readTemplate();
  const paramMatch = text.match(/\n {2}BobLabTarget:\n([\s\S]*?)(?=\n {2}\S|\nConditions:)/);
  assert.ok(paramMatch, "BobLabTarget parameter block not found under Parameters:");
  const body = paramMatch[1];
  assert.match(body, /Type:\s*String/, "BobLabTarget must be Type: String");
  assert.match(body, /Default:\s*127\.0\.0\.1/);
  const rule = extractResourceBlock(text, "BuiltInDemoTargetUsesLoopback");
  assert.match(rule, /BobLabTarget/);
  assert.match(rule, /127\.0\.0\.1/);
});

test("GlassboxAgentCoreRuntime threads the operator-owned target into its environment", () => {
  const runtime = extractResourceBlock(readTemplate(), "GlassboxAgentCoreRuntime");
  assert.match(
    runtime,
    /BOB_LAB_TARGET:\s*!Ref BobLabTarget/,
    "Runtime environment must set BOB_LAB_TARGET from the operator-controlled parameter",
  );
});

// ---------------------------------------------------------------------------------------
// fx-gate-hardening: IAM-boundary structural checks. Same "structural, not a full CFN/YAML
// parse" remit as the rest of this file — walks the raw text, bounding each named
// top-level Resource's block by dedenting to the resource key's indentation.
// ---------------------------------------------------------------------------------------

function extractResourceBlock(templateText, resourceName) {
  const match = templateText.match(new RegExp(`\\n {2}${resourceName}:\\n([\\s\\S]*?)(?=\\n {2}\\S|\\nOutputs:)`));
  assert.ok(match, `${resourceName} resource block not found in template.yaml`);
  return match[1];
}

// Strips full-line `#` comments (this template never uses trailing same-line comments after
// YAML content, only whole-comment-lines) so a negative assertion like "never mentions
// s3:PutObject" isn't tripped by prose EXPLAINING the absence in a neighboring comment.
function stripYamlComments(block) {
  return block
    .split("\n")
    .filter((line) => !/^\s*#/.test(line))
    .join("\n");
}

// Bounds the IAM statement (one `- Sid: ...` entry) that references `needle` (e.g. a
// specific bucket's .Arn), from that Sid's own `- Sid:` line up to the next `- Sid:` line
// (or the end of the role block). Scoped narrowly so a check about "the verifier bucket"
// grant never accidentally matches an unrelated statement elsewhere in the same role (e.g.
// GlassboxAgentRuntimeExecutionRole's pre-existing, legitimate PutEvidenceObjects Sid,
// which grants s3:PutObject on the UNRELATED EvidenceBucket).
function statementsReferencing(roleBlockNoComments, needle) {
  const sidStarts = [...roleBlockNoComments.matchAll(/\n( *)- Sid:/g)].map((m) => m.index + 1);
  const windows = [];
  for (let i = 0; i < sidStarts.length; i += 1) {
    const start = sidStarts[i];
    const end = i + 1 < sidStarts.length ? sidStarts[i + 1] : roleBlockNoComments.length;
    const window = roleBlockNoComments.slice(start, end);
    if (window.includes(needle)) windows.push(window);
  }
  return windows;
}

test("Runtime role covers profile and all US backing foundation-model ARNs", () => {
  const role = extractResourceBlock(readTemplate(), "GlassboxAgentRuntimeExecutionRole");
  for (const parameter of [
    "BedrockOpusModelId", "BedrockSonnetModelId", "BedrockFallbackModelId",
  ]) {
    assert.match(role, new RegExp(`inference-profile/\\$\\{${parameter}\\}`));
  }
  for (const region of ["us-east-1", "us-east-2", "us-west-2"]) {
    for (const parameter of [
      "BedrockOpusFoundationModelId",
      "BedrockSonnetFoundationModelId",
      "BedrockFallbackFoundationModelId",
    ]) {
      assert.match(role, new RegExp(`bedrock:${region}::foundation-model/\\$\\{${parameter}\\}`));
    }
  }
});

test("Runtime role includes scoped image, EFS, logs, and confused-deputy protections", () => {
  const role = extractResourceBlock(readTemplate(), "GlassboxAgentRuntimeExecutionRole");
  assert.match(role, /ecr:BatchGetImage/);
  assert.match(role, /Resource:\s*!Ref AgentContainerRepositoryArn/);
  assert.match(role, /elasticfilesystem:ClientMount/);
  assert.match(role, /elasticfilesystem:ClientWrite/);
  assert.match(role, /elasticfilesystem:DescribeAccessPoints/);
  assert.match(role, /elasticfilesystem:DescribeMountTargets/);
  assert.match(role, /elasticfilesystem:AccessPointArn:\s*!GetAtt HomeAccessPoint\.Arn/);
  assert.match(role, /logs:PutLogEvents/);
  assert.match(role, /aws:SourceAccount:\s*!Ref AWS::AccountId/);
  assert.match(role, /aws:SourceArn:\s*!Sub arn:aws:bedrock-agentcore:/);
});

test("deny-egress VPC includes the endpoints and NFS path required by the container runtime", () => {
  const text = readTemplate();
  for (const resource of [
    "BedrockRuntimeVpcEndpoint",
    "EcrApiVpcEndpoint",
    "EcrDkrVpcEndpoint",
    "LogsVpcEndpoint",
    "SecretsManagerVpcEndpoint",
    "S3GatewayVpcEndpoint",
  ]) {
    extractResourceBlock(text, resource);
  }
  const s3 = extractResourceBlock(text, "S3GatewayVpcEndpoint");
  assert.match(s3, /RouteTableIds:\s*!Ref PrivateRouteTableIds/);
  assert.match(s3, /prod-\$\{AWS::Region\}-starport-layer-bucket/);
  assert.match(s3, /s3:GetObjectVersion/);
  const s3Egress = extractResourceBlock(text, "S3GatewayEgressRule");
  assert.match(s3Egress, /DestinationPrefixListId:\s*!Ref S3GatewayPrefixListId/);
  assert.match(s3Egress, /FromPort:\s*443/);
  const nfs = extractResourceBlock(text, "EfsNfsEgressRule");
  assert.match(nfs, /FromPort:\s*2049/);
  assert.match(nfs, /DestinationSecurityGroupId:\s*!Ref EfsSecurityGroup/);
});

test("non-AWS model egress is disabled by default", () => {
  const text = readTemplate();
  const match = text.match(/\n {2}EnableZaiEgress:\n([\s\S]*?)(?=\n {2}\S)/);
  assert.ok(match);
  assert.match(match[1], /Default:\s*"false"/);
});

test("GlassboxAgentRuntimeExecutionRole never grants s3:PutObject/DeleteObject/* on the verifier attestation bucket", () => {
  const role = stripYamlComments(extractResourceBlock(readTemplate(), "GlassboxAgentRuntimeExecutionRole"));
  const approvalsStatements = statementsReferencing(role, "GlassboxApprovalsBucket.Arn");
  assert.ok(approvalsStatements.length > 0, "expected at least one statement referencing GlassboxApprovalsBucket.Arn");
  for (const statement of approvalsStatements) {
    assert.doesNotMatch(
      statement,
      /s3:PutObject|s3:DeleteObject|s3:\*/,
      "GlassboxAgentRuntimeExecutionRole (the model's execution role) must never be granted "
        + "s3:PutObject, s3:DeleteObject, or a wildcard s3 action on the verifier attestation bucket — "
        + "the model must be structurally unable to write its own verifier attestation",
    );
  }
  assert.ok(
    approvalsStatements.some((s) => /s3:GetObject/.test(s)),
    "GlassboxAgentRuntimeExecutionRole must still be granted s3:GetObject on the verifier attestation bucket "
      + "(defense-in-depth verification requires reading the artifact)",
  );
});

test("GlassboxAgentRuntimeExecutionRole's human-approval GetObject grant is grade-keyed and excludes pending records", () => {
  const role = extractResourceBlock(readTemplate(), "GlassboxAgentRuntimeExecutionRole");
  assert.match(
    role,
    /Resource:\s*!Sub \$\{GlassboxApprovalsBucket\.Arn\}\/approvals\/\*\/\*\.approved/,
    "the model role's s3:GetObject Resource must be scoped to approvals/*/*.approved specifically, "
      + "not a bare approvals/* prefix",
  );
});

test("GlassboxAgentRuntimeExecutionRole has a scoped (non-wildcard-Resource) secretsmanager:GetSecretValue statement for zai/agt-token", () => {
  const role = extractResourceBlock(readTemplate(), "GlassboxAgentRuntimeExecutionRole");
  assert.match(role, /secretsmanager:GetSecretValue/, "expected a secretsmanager:GetSecretValue action");
  assert.match(
    role,
    /arn:aws:secretsmanager:\$\{AWS::Region\}:\$\{AWS::AccountId\}:secret:zai\/agt-token-\?{6}/,
    "the zai/agt-token grant must be scoped to that secret's ARN pattern, not a bare '*'",
  );
  // Never a wildcard-only Resource for this statement's action.
  const secretValueStatement = role.slice(role.indexOf("secretsmanager:GetSecretValue"));
  const nextSidIdx = secretValueStatement.indexOf("- Sid:", 1);
  const statementWindow = nextSidIdx === -1 ? secretValueStatement : secretValueStatement.slice(0, nextSidIdx);
  assert.doesNotMatch(
    statementWindow,
    /Resource:\s*"\*"/,
    "secretsmanager:GetSecretValue must not be granted Resource: \"*\"",
  );
});

test("only verifier/human approval writers can PutObject final .approved artifacts", () => {
  const text = readTemplate();
  const roleNames = [
    "GlassboxAgentRuntimeExecutionRole",
    "VerifierGateRole",
    "VerifierApprovalRole",
    "ApprovalPendingRecorderRole",
    "ApprovalWriterRole",
    "GlassboxStateMachineRole",
  ];
  const principalsWithPutOnApprovals = [];
  for (const roleName of roleNames) {
    const role = stripYamlComments(extractResourceBlock(text, roleName));
    const statements = statementsReferencing(role, "GlassboxApprovalsBucket.Arn}/approvals/")
      .filter((s) => !/approvals\/pending\//.test(s));
    if (statements.some((s) => /s3:PutObject/.test(s))) {
      principalsWithPutOnApprovals.push(roleName);
    }
  }
  assert.deepEqual(
    principalsWithPutOnApprovals,
    ["VerifierApprovalRole", "ApprovalWriterRole"],
    "Only verifier/human approval writers may be granted s3:PutObject on the final approval "
      + "prefix (the final .approved artifact) — found: " + JSON.stringify(principalsWithPutOnApprovals),
  );
});

test("GlassboxApprovalsBucket is not Object Lock (WORM) enabled — verifier attestation artifacts remain mutable control records", () => {
  const bucket = extractResourceBlock(readTemplate(), "GlassboxApprovalsBucket");
  assert.doesNotMatch(bucket, /ObjectLockEnabled/, "GlassboxApprovalsBucket must not declare ObjectLockEnabled");
  assert.match(bucket, /NoncurrentVersionExpiration:/);
  assert.match(bucket, /NoncurrentDays:\s*7/);
  assert.match(bucket, /ExpiredObjectDeleteMarker:\s*true/);
});

test("GlassboxApprovalHmacKey is declared as a Secrets Manager secret with a generated (never literal) value", () => {
  const secret = extractResourceBlock(readTemplate(), "GlassboxApprovalHmacKey");
  assert.match(secret, /Type: AWS::SecretsManager::Secret/);
  assert.match(secret, /GenerateSecretString/, "the HMAC key must be generated, never a hardcoded literal");
});

test("state machine advances on verifier approval and notifies human on the loop", () => {
  const aslPath = path.join(
    __dirname, "..", "infra", "aws", "hacker-bob-stack", "statemachine", "hacker-bob-engagement.asl.json",
  );
  const asl = JSON.parse(fs.readFileSync(aslPath, "utf8"));
  const verifier = asl.States.RunVerifierGate;
  assert.equal(verifier.Resource, "arn:aws:states:::lambda:invoke");
  assert.equal(verifier.Parameters.FunctionName, "${VerifierGateFunctionArn}");
  assert.equal(Object.prototype.hasOwnProperty.call(verifier.Parameters.Payload, "token.$"), false);
  assert.equal(verifier.Next, "WriteVerifierApproval");
  const writer = asl.States.WriteVerifierApproval;
  assert.equal(writer.Resource, "arn:aws:states:::lambda:invoke");
  assert.equal(writer.Parameters.FunctionName, "${VerifierApprovalFunctionArn}");
  assert.equal(Object.prototype.hasOwnProperty.call(writer.Parameters.Payload, "token.$"), false);
  assert.equal(writer.Parameters.Payload["verifiedFreeze.$"], "$.verifierGate.Payload");
  assert.equal(writer.Next, "RecordVerifierApproval");
  const record = asl.States.RecordVerifierApproval;
  assert.equal(record.Parameters["approval_mode.$"], "$.verifierApproval.Payload.approval_mode");
  assert.equal(record.Parameters["approval_artifact_key.$"], "$.verifierApproval.Payload.approval_artifact_key");
  assert.equal(record.Next, "NotifyHumanOnLoop");
  const notify = asl.States.NotifyHumanOnLoop;
  assert.equal(notify.Resource, "arn:aws:states:::sns:publish");
  assert.equal(notify.Parameters.TopicArn, "${ApprovalNotificationTopicArn}");
  assert.equal(notify.Parameters["Message.$"], "States.JsonToString($.approval)");
  assert.equal(notify.Next, "ExportToSecurityHub");

  // Break-glass/manual state remains present for old executions and recovery,
  // but is no longer on the default verifier-driven path.
  const human = asl.States.AwaitHumanApproval;
  assert.equal(human.Resource, "arn:aws:states:::lambda:invoke.waitForTaskToken");
  assert.equal(human.Parameters.FunctionName, "${ApprovalPendingRecorderFunctionArn}");
  assert.equal(human.Parameters.Payload["token.$"], "$$.Task.Token");
  assert.equal(human.Parameters.Payload["profile.$"], "$.profile");
  assert.equal(human.Parameters.Payload["verifiedFreeze.$"], "$.verifierGate.Payload");
  assert.equal(human.TimeoutSeconds, 86400);
  assert.equal(human.Next, "ExportToSecurityHub");
});

test("state machine preserves smoke and routes only the named immutable libheif profile through one stable session id", () => {
  const aslPath = path.join(
    __dirname, "..", "infra", "aws", "hacker-bob-stack", "statemachine", "hacker-bob-engagement.asl.json",
  );
  const asl = JSON.parse(fs.readFileSync(aslPath, "utf8"));
  for (const stateName of ["InvokeAgentRuntimeThroughGrade", "ResumeAgentRuntimeThroughReport"]) {
    const state = asl.States[stateName];
    assert.equal(state.Resource, "arn:aws:states:::aws-sdk:bedrockagentcore:invokeAgentRuntime");
    assert.equal(state.Parameters.AgentRuntimeArn, "${AgentRuntimeArn}");
    assert.equal(state.Parameters["RuntimeSessionId.$"], "$.runtimeSessionId");
    assert.equal(state.Parameters["Payload.$"], `States.JsonToString($.${stateName === "InvokeAgentRuntimeThroughGrade" ? "gradePayload" : "reportPayload"})`);
  }
  for (const prepareName of ["PrepareLegacySmoke", "PrepareNamedSmoke", "PrepareLibheifReplay"]) {
    assert.equal(asl.States[prepareName].Parameters["runtimeSessionId.$"], "States.UUID()");
  }
  assert.equal(asl.States.SelectEngagementProfile.Default, "PrepareLegacySmoke");
  assert.equal(asl.States.PrepareLegacySmoke.Next, "BuildSmokeGradePayload");
  assert.equal(asl.States.PrepareNamedSmoke.Next, "BuildSmokeGradePayload");
  assert.equal(asl.States.PrepareLibheifReplay.Next, "BuildLibheifGradePayload");
  assert.equal(asl.States.BuildSmokeGradePayload.Next, "InvokeAgentRuntimeThroughGrade");
  assert.equal(asl.States.BuildLibheifGradePayload.Next, "InvokeAgentRuntimeThroughGrade");
  assert.equal(
    asl.States.BuildSmokeGradePayload.Parameters.gradePayload["runtime_session_id.$"],
    "$.runtimeSessionId",
  );
  assert.equal(asl.States.BuildSmokeGradePayload.Parameters.gradePayload.demo_smoke, true);
  assert.equal(
    asl.States.BuildLibheifGradePayload.Parameters.gradePayload["fixture_id.$"],
    "$.fixtureId",
  );
  assert.equal(asl.States.PrepareLibheifReplay.Parameters.fixtureId, "libheif-cve-2026-49271");
  assert.equal(Object.prototype.hasOwnProperty.call(
    asl.States.PrepareLibheifReplay.Parameters, "commit",
  ), false, "execution input/profile routing must not carry an operator-selected commit");
  assert.equal(
    asl.States.BuildSmokeReportPayload.Parameters.reportPayload["runtime_session_id.$"],
    "$.runtimeSessionId",
  );
  assert.equal(asl.States.BuildSmokeReportPayload.Parameters.reportPayload.demo_smoke, true);
  assert.equal(
    asl.States.BuildLibheifReportPayload.Parameters.reportPayload.fixture_id,
    "libheif-cve-2026-49271",
  );
  assert.equal(asl.States.DecodeGradeResult.Parameters["gradeResult.$"], "States.StringToJson($.gradeInvoke.Response)");
  assert.equal(asl.States.DecodeReportResult.Parameters["reportResult.$"], "States.StringToJson($.reportInvoke.Response)");
});

test("GlassboxStateMachineRole may invoke the AgentCore default runtime endpoint", () => {
  const role = extractResourceBlock(readTemplate(), "GlassboxStateMachineRole");
  assert.match(role, /bedrock-agentcore:InvokeAgentRuntime/);
  assert.match(role, /RuntimeArn:\s*!GetAtt GlassboxAgentCoreRuntime\.AgentRuntimeArn/);
  assert.match(role, /\$\{RuntimeArn\}\/runtime-endpoint\/DEFAULT/);
});

// ---------------------------------------------------------------------------------------
// ARCHITECTURAL FIX: the downstream ExportSecurityHubFunction Lambda is
// invoked ONLY after verifier approval, and the model's own execution role must
// structurally lose securityhub:BatchImportFindings entirely.
// ---------------------------------------------------------------------------------------

test("state machine orders verifier -> verifier approval -> human-on-loop notice -> exact-version export -> REPORT", () => {
  const aslPath = path.join(
    __dirname, "..", "infra", "aws", "hacker-bob-stack", "statemachine", "hacker-bob-engagement.asl.json",
  );
  const asl = JSON.parse(fs.readFileSync(aslPath, "utf8"));
  assert.equal(asl.States.DecodeGradeResult.Next, "RunVerifierGate");
  assert.equal(asl.States.RunVerifierGate.Next, "WriteVerifierApproval");
  assert.equal(asl.States.WriteVerifierApproval.Next, "RecordVerifierApproval");
  assert.equal(asl.States.RecordVerifierApproval.Next, "NotifyHumanOnLoop");
  assert.equal(asl.States.NotifyHumanOnLoop.Next, "ExportToSecurityHub");
  const exportState = asl.States.ExportToSecurityHub;
  assert.ok(exportState, "ExportToSecurityHub state must exist");
  assert.equal(exportState.Type, "Task");
  assert.equal(exportState.Resource, "arn:aws:states:::lambda:invoke");
  assert.equal(exportState.Parameters.FunctionName, "${ExportSecurityHubFunctionArn}");
  assert.equal(exportState.Parameters.Payload["target.$"], "$.approval.target");
  assert.equal(exportState.Parameters.Payload["gradeVerdictHash.$"], "$.approval.grade_verdict_hash");
  assert.equal(exportState.Parameters.Payload["gradeFreezeVersionId.$"], "$.approval.grade_freeze_version_id");
  assert.equal(exportState.Parameters.Payload["gradeFreezeBundleSha256.$"], "$.approval.grade_freeze_bundle_sha256");
  assert.equal(exportState.Next, "SelectReportProfile");
  assert.equal(asl.States.BuildSmokeReportPayload.Next, "ResumeAgentRuntimeThroughReport");
  assert.equal(asl.States.BuildLibheifReportPayload.Next, "ResumeAgentRuntimeThroughReport");
});

test("libheif historical-replay target lock pins the original tested revision, exact fix, patched release, and harness", () => {
  const lockPath = path.join(
    __dirname, "..", "infra", "runner", "demo-targets",
    "libheif-cve-2026-49271", "target.lock.json",
  );
  const lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));
  assert.equal(lock.fixture_id, "libheif-cve-2026-49271");
  assert.equal(lock.claim_mode, "public_historical_reproduction");
  assert.equal(lock.rediscovery, false);
  assert.equal(lock.source_pins.vulnerable.commit, "b12b733d1716595483413ccd7e2dfb73c44a8d69");
  assert.equal(lock.source_pins.exact_fix.commit, "5782bca04a70ebc01c59397205a3cfff22841311");
  assert.equal(lock.source_pins.patched_release.commit, "2b6d5a62fb6151e09d5f36757a5aa5e12f9c2045");
  assert.equal(lock.reproduction.harness_sha256, "eb4e37a5b6c03618a5a9d7b53e983ea1f3fcfc36f721335e326a96c0f9d8fb55");
  assert.equal(lock.reproduction.original_run_id, "run-1779612407619-abb57751");
});

test("GlassboxAgentRuntimeExecutionRole (the model's role) never grants securityhub:BatchImportFindings anywhere in template.yaml", () => {
  const role = stripYamlComments(extractResourceBlock(readTemplate(), "GlassboxAgentRuntimeExecutionRole"));
  assert.doesNotMatch(
    role,
    /securityhub:BatchImportFindings/,
    "the model's execution role must never be granted securityhub:BatchImportFindings -- AWS Security " +
      "Hub export now runs ONLY as the downstream ExportSecurityHubFunction Lambda, under its own role",
  );
});

test("ExportSecurityHubRole is the only principal in template.yaml granted securityhub:BatchImportFindings", () => {
  const text = readTemplate();
  const roleNames = [
    "GlassboxAgentRuntimeExecutionRole",
    "VerifierGateRole",
    "VerifierApprovalRole",
    "ApprovalPendingRecorderRole",
    "ApprovalWriterRole",
    "GlassboxStateMachineRole",
    "ExportSecurityHubRole",
  ];
  const principalsWithBatchImport = roleNames.filter((roleName) => {
    const role = stripYamlComments(extractResourceBlock(text, roleName));
    return /securityhub:BatchImportFindings/.test(role);
  });
  assert.deepEqual(principalsWithBatchImport, ["ExportSecurityHubRole"]);
});

test("ExportSecurityHubRole's S3 read grant is scoped to the grade-freeze prefix only, and it is never granted s3:PutObject/DeleteObject", () => {
  const role = stripYamlComments(extractResourceBlock(readTemplate(), "ExportSecurityHubRole"));
  assert.match(
    role,
    /Resource:\s*!Sub \$\{EvidenceBucket\.Arn\}\/hacker-bob\/grade-freeze\/\*/,
    "ExportSecurityHubRole's s3:GetObject Resource must be scoped to the grade-freeze prefix, not a bare EvidenceBucket/*",
  );
  assert.match(role, /s3:GetObjectVersion/);
  assert.doesNotMatch(
    role,
    /s3:PutObject|s3:DeleteObject|s3:\*/,
    "ExportSecurityHubRole must never be able to write or delete the evidence it exports from",
  );
});

test("ExportSecurityHubFunction uses the slim Node 22 function plus generated pure-ASFF layer", () => {
  const fn = extractResourceBlock(readTemplate(), "ExportSecurityHubFunction");
  assert.match(fn, /Runtime:\s*nodejs22\.x/);
  assert.match(fn, /Handler:\s*index\.handler/);
  assert.match(fn, /CodeUri:\s*functions\/export-security-hub/);
  assert.match(fn, /!Ref AsffBuilderLayer/);
  assert.match(fn, /ASFF_BUILDER_PATH:\s*\/opt\/lib\/asff-builder\.js/);
  assert.match(fn, /Role:\s*!GetAtt ExportSecurityHubRole\.Arn/);
  assert.match(fn, /GRADE_FREEZE_BUCKET:\s*!Ref EvidenceBucket/);
  assert.match(fn, /SECURITY_HUB_PRODUCT_ARN:/);
});

test("verifier reads and hashes only the exact GRADE-returned WORM VersionId and cannot approve", () => {
  const gate = extractResourceBlock(readTemplate(), "VerifierGateFunction");
  assert.match(gate, /GRADE_FREEZE_BUCKET:\s*!Ref EvidenceBucket/);
  assert.match(gate, /s3\.get_object\(/);
  assert.match(gate, /VersionId=grade_freeze_version_id/);
  assert.match(gate, /hashlib\.sha256\(body\)/);
  assert.match(gate, /_canonical_hash\(bundle\["grade"\]\)/);
  assert.match(gate, /s3\.get_object_retention\(/);
  assert.match(gate, /retention\.get\("Mode"\) != "COMPLIANCE"/);
  assert.doesNotMatch(gate, /head_object\(/);
  assert.doesNotMatch(gate, /s3\.put_object\(/);
  assert.doesNotMatch(gate, /secretsmanager|HMAC_SECRET_ID/);
  assert.doesNotMatch(gate, /send_task_success/);

  const gateRole = extractResourceBlock(readTemplate(), "VerifierGateRole");
  assert.match(gateRole, /ReadGradeFreezeVersion/);
  assert.match(gateRole, /s3:GetObjectVersion/);
  assert.match(gateRole, /s3:GetObjectRetention/);
  assert.match(gateRole, /EvidenceBucket\.Arn\}\/hacker-bob\/grade-freeze\/\*/);
  assert.doesNotMatch(gateRole, /GlassboxApprovalsBucket|secretsmanager|states:SendTask/);
});

test("verifier approval writer signs the full v2 freeze tuple without Step Functions callback permission", () => {
  const writer = extractResourceBlock(readTemplate(), "VerifierApprovalFunction");
  assert.match(writer, /FunctionName:\s*glassbox-verifier-approval/);
  assert.match(writer, /binding = \[/);
  assert.match(writer, /expected\["grade_verdict_hash"\]/);
  assert.match(writer, /expected\["grade_freeze_bundle_sha256"\]/);
  assert.match(writer, /expected\["grade_freeze_version_id"\]/);
  assert.match(writer, /"approval_mode": "verifier_quorum"/);
  assert.match(writer, /"approved_by": "automated_verifier_gate"/);
  assert.match(writer, /approvals\/\{target\}\/\{expected\['grade_verdict_hash'\]\}\.approved/);
  assert.match(writer, /s3\.put_object\(/);
  assert.doesNotMatch(writer, /send_task_success|send_task_failure|taskToken|pendingRecordKey/);

  const writerRole = stripYamlComments(extractResourceBlock(readTemplate(), "VerifierApprovalRole"));
  assert.match(writerRole, /approvals\/\*\/\*\.approved/);
  assert.match(writerRole, /s3:PutObject/);
  assert.match(writerRole, /secretsmanager:GetSecretValue/);
  assert.doesNotMatch(writerRole, /states:SendTask|approvals\/pending|EvidenceBucket/);
});

test("pending recorder cannot approve/callback and human writer binds the full v2 freeze tuple", () => {
  const recorder = extractResourceBlock(readTemplate(), "ApprovalPendingRecorderFunction");
  assert.match(recorder, /approvals\/pending\/\{execution_name\}\.json/);
  assert.match(recorder, /grade_freeze_bundle_sha256/);
  assert.match(recorder, /grade_freeze_version_id/);
  assert.match(recorder, /sns\.publish\(/);
  assert.doesNotMatch(recorder, /send_task_success|send_task_failure|\.approved/);

  const writer = extractResourceBlock(readTemplate(), "ApprovalWriterFunction");
  assert.match(writer, /decision not in \{"approve", "reject"\}/);
  assert.match(writer, /binding = \[profile, target, grade_hash, body_sha256, version_id\]/);
  assert.match(writer, /"binding_version": BINDING_VERSION/);
  assert.match(writer, /approvals\/\{target\}\/\{grade_hash\}\.approved/);
  assert.match(writer, /sfn\.send_task_success\(/);
  assert.match(writer, /sfn\.send_task_failure\(/);
  assert.ok(
    writer.indexOf("s3.put_object(") < writer.indexOf("sfn.send_task_success("),
    "human approval artifact must be durable before the success callback",
  );

  const recorderRole = stripYamlComments(extractResourceBlock(readTemplate(), "ApprovalPendingRecorderRole"));
  assert.match(recorderRole, /approvals\/pending\/\*/);
  assert.doesNotMatch(recorderRole, /approvals\/\*\/\*\.approved|states:SendTask/);
  const writerRole = stripYamlComments(extractResourceBlock(readTemplate(), "ApprovalWriterRole"));
  assert.match(writerRole, /approvals\/\*\/\*\.approved/);
  assert.match(writerRole, /states:SendTaskSuccess/);
  assert.match(writerRole, /states:SendTaskFailure/);
});

test("state-machine role invokes verifier writer and notification, but never the out-of-band manual writer", () => {
  const role = stripYamlComments(extractResourceBlock(readTemplate(), "GlassboxStateMachineRole"));
  assert.match(role, /VerifierApprovalFunction\.Arn/);
  assert.match(role, /sns:Publish/);
  assert.match(role, /ApprovalNotificationTopic/);
  assert.match(role, /ApprovalPendingRecorderFunction\.Arn/);
  assert.doesNotMatch(role, /ApprovalWriterFunction\.Arn/);
  const machine = extractResourceBlock(readTemplate(), "GlassboxEngagementStateMachine");
  assert.match(machine, /VerifierApprovalFunctionArn:\s*!GetAtt VerifierApprovalFunction\.Arn/);
  assert.match(machine, /ApprovalNotificationTopicArn:\s*!Ref ApprovalNotificationTopic/);
  assert.match(machine, /ApprovalPendingRecorderFunctionArn:\s*!GetAtt ApprovalPendingRecorderFunction\.Arn/);
});

test("GlassboxStateMachineRole may invoke ExportSecurityHubFunction", () => {
  const role = extractResourceBlock(readTemplate(), "GlassboxStateMachineRole");
  assert.match(role, /Resource:\s*!GetAtt ExportSecurityHubFunction\.Arn/);
});
