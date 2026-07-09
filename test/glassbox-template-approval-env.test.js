"use strict";

// Structural checks for infra/aws/glassbox-stack/template.yaml's
// AgentCoreRuntimeProvisionerFunction InlineCode block (f1-approval-wiring).
//
// No existing test parses template.yaml as CFN/YAML (SAM's `Fn::Sub`/multi-doc intrinsics and
// the embedded Python InlineCode block make a generic YAML parser an awkward fit here), so this
// walks the raw text directly -- string/regex structural assertions, matching this node's own
// "structural, not a full CFN/YAML parse" remit. It is precise about BOTH call sites
// (create_agent_runtime AND update_agent_runtime) and all four required env keys, unlike the
// Verify script's own single `grep -q BOB_AGENTCORE template.yaml` smoke check.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const TEMPLATE_PATH = path.join(
  __dirname, "..", "infra", "aws", "glassbox-stack", "template.yaml",
);

const REQUIRED_ENV_KEYS = Object.freeze([
  "BOB_AGENTCORE",
  "BOB_LAB_TARGET_ACK",
  "BOB_LAB_TARGET",
  // fx-gate-hardening: BOB_APPROVAL_ARTIFACT_DIR (a writable-EFS path the model's own
  // execution role could reach) is REMOVED from production env vars — replaced by the
  // S3-backed approval store's bucket + HMAC secret id.
  "BOB_APPROVAL_BUCKET",
  "BOB_APPROVAL_HMAC_SECRET_ID",
]);

function readTemplate() {
  return fs.readFileSync(TEMPLATE_PATH, "utf8");
}

function leadingSpaces(line) {
  return line.match(/^(\s*)/)[1].length;
}

// Extracts the full `InlineCode: |` block's raw text (the Python Lambda handler source),
// walking lines until one dedents back to (or past) the "InlineCode:" key's own indentation --
// i.e. a sibling Properties key or the next Resource, whichever comes first.
function extractInlineCode(templateText) {
  const lines = templateText.split("\n");
  const startIdx = lines.findIndex((line) => line.trim() === "InlineCode: |");
  assert.ok(startIdx !== -1, "template.yaml must declare an `InlineCode: |` block");
  const startIndent = leadingSpaces(lines[startIdx]);

  const blockLines = [];
  for (let i = startIdx + 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (line.trim() !== "" && leadingSpaces(line) <= startIndent) break;
    blockLines.push(line);
  }
  assert.ok(blockLines.length > 0, "InlineCode block must not be empty");
  return blockLines.join("\n");
}

// Bounds a `client.<calleeName>(...)` call's kwargs to a window ending at the next sibling
// branch/handler marker, so a later call's kwargs can't bleed into an earlier call's window.
function extractCallSite(inlineCode, calleeName) {
  const marker = `client.${calleeName}(`;
  const callIdx = inlineCode.indexOf(marker);
  assert.ok(callIdx !== -1, `InlineCode block must call client.${calleeName}(...)`);
  // The env dict is built as `environment_variables = { ... }` just above the call (needed for
  // the conditional BOB_EVM_RPCS_1), then passed as `environmentVariables=environment_variables`.
  // Start the window at that dict-building so the required-key assertions still see the keys.
  const envBuild = inlineCode.lastIndexOf("environment_variables = {", callIdx);
  const start = envBuild !== -1 ? envBuild : callIdx;

  const boundaryMarkers = ["elif request_type ==", "except Exception as exc:", "def _send_response"];
  let end = inlineCode.length;
  for (const boundary of boundaryMarkers) {
    const idx = inlineCode.indexOf(boundary, start + marker.length);
    if (idx !== -1 && idx < end) end = idx;
  }
  assert.ok(end > start, `could not bound the client.${calleeName}(...) call site`);
  return inlineCode.slice(start, end);
}

function assertEnvironmentVariablesWired(callSiteText, calleeName) {
  assert.match(
    callSiteText,
    /environmentVariables\s*=\s*(\{|environment_variables\b)/,
    `client.${calleeName}(...) must pass an environmentVariables= kwarg (dict literal or the environment_variables var)`,
  );
  for (const key of REQUIRED_ENV_KEYS) {
    assert.match(
      callSiteText,
      new RegExp(`"${key}"\\s*:`),
      `client.${calleeName}(...)'s environmentVariables map must set ${key}`,
    );
  }
}

test("AgentCoreRuntimeProvisionerFunction: create_agent_runtime carries the approval-gate + lab-target env", () => {
  const inlineCode = extractInlineCode(readTemplate());
  const callSite = extractCallSite(inlineCode, "create_agent_runtime");
  assertEnvironmentVariablesWired(callSite, "create_agent_runtime");
});

test("AgentCoreRuntimeProvisionerFunction: update_agent_runtime carries the approval-gate + lab-target env", () => {
  const inlineCode = extractInlineCode(readTemplate());
  const callSite = extractCallSite(inlineCode, "update_agent_runtime");
  assertEnvironmentVariablesWired(callSite, "update_agent_runtime");
});

test("update_agent_runtime's environmentVariables map is not merely a copy-paste of create's Resource kwargs", () => {
  // Sanity check distinguishing the two call sites are genuinely separate windows (regression
  // guard against a future edit collapsing both into one shared block that only Create reaches).
  const inlineCode = extractInlineCode(readTemplate());
  const createCall = extractCallSite(inlineCode, "create_agent_runtime");
  const updateCall = extractCallSite(inlineCode, "update_agent_runtime");
  assert.ok(!createCall.includes("client.update_agent_runtime("));
  assert.ok(!updateCall.includes("client.create_agent_runtime("));
});

test("template.yaml declares BobLabTarget as a no-default, human-supplied String parameter", () => {
  const text = readTemplate();
  const paramMatch = text.match(/\n {2}BobLabTarget:\n([\s\S]*?)(?=\n {2}\S|\nConditions:)/);
  assert.ok(paramMatch, "BobLabTarget parameter block not found under Parameters:");
  const body = paramMatch[1];
  assert.match(body, /Type:\s*String/, "BobLabTarget must be Type: String");
  assert.doesNotMatch(body, /\n\s*Default:/, "BobLabTarget must have NO Default (human-supplied only)");
});

test("GlassboxAgentCoreRuntime threads BobLabTarget into the custom resource's ResourceProperties", () => {
  const text = readTemplate();
  const resourceMatch = text.match(/\n {2}GlassboxAgentCoreRuntime:\n([\s\S]*?)(?=\n {2}\S)/);
  assert.ok(resourceMatch, "GlassboxAgentCoreRuntime resource block not found");
  assert.match(
    resourceMatch[1],
    /BobLabTarget:\s*!Ref BobLabTarget/,
    "GlassboxAgentCoreRuntime Properties must set BobLabTarget: !Ref BobLabTarget "
      + "so the provisioner's inline handler can read props[\"BobLabTarget\"]",
  );
});

// ---------------------------------------------------------------------------------------
// fx-gate-hardening: IAM-boundary structural checks. Same "structural, not a full CFN/YAML
// parse" remit as the rest of this file — walks the raw text, bounding each named
// top-level Resource's block the same way extractInlineCode bounds the InlineCode block
// above (dedent back to the resource key's own 2-space indentation).
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
// (or the end of the role block). Scoped narrowly so a check about "the approvals bucket"
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

test("GlassboxAgentRuntimeExecutionRole never grants s3:PutObject/DeleteObject/* on the approvals bucket", () => {
  const role = stripYamlComments(extractResourceBlock(readTemplate(), "GlassboxAgentRuntimeExecutionRole"));
  const approvalsStatements = statementsReferencing(role, "GlassboxApprovalsBucket.Arn");
  assert.ok(approvalsStatements.length > 0, "expected at least one statement referencing GlassboxApprovalsBucket.Arn");
  for (const statement of approvalsStatements) {
    assert.doesNotMatch(
      statement,
      /s3:PutObject|s3:DeleteObject|s3:\*/,
      "GlassboxAgentRuntimeExecutionRole (the model's execution role) must never be granted "
        + "s3:PutObject, s3:DeleteObject, or a wildcard s3 action on the approvals bucket — "
        + "the model must be structurally unable to write its own approval",
    );
  }
  assert.ok(
    approvalsStatements.some((s) => /s3:GetObject/.test(s)),
    "GlassboxAgentRuntimeExecutionRole must still be granted s3:GetObject on the approvals bucket "
      + "(defense-in-depth verification requires reading the artifact)",
  );
});

test("GlassboxAgentRuntimeExecutionRole's approvals GetObject grant is scoped to *.approved (excludes approvals/pending/*)", () => {
  const role = extractResourceBlock(readTemplate(), "GlassboxAgentRuntimeExecutionRole");
  assert.match(
    role,
    /Resource:\s*!Sub \$\{GlassboxApprovalsBucket\.Arn\}\/approvals\/\*\.approved/,
    "the model role's s3:GetObject Resource must be scoped to approvals/*.approved specifically, "
      + "not a bare approvals/* prefix (which would also match approvals/pending/*.json — the "
      + "in-flight taskToken records)",
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

test("ApprovalWriterRole is the only principal in template.yaml granted s3:PutObject on the bare approvals/* prefix", () => {
  const text = readTemplate();
  const roleNames = [
    "GlassboxAgentRuntimeExecutionRole",
    "ApprovalPendingRecorderRole",
    "ApprovalWriterRole",
    "AgentCoreRuntimeProvisionerRole",
    "GlassboxStateMachineRole",
  ];
  // "the bare approvals/* prefix" excludes the pending sub-prefix (approvals/pending/*),
  // which ApprovalPendingRecorderRole legitimately PutObjects to for its own pending
  // records — a distinct, narrower resource than the final .approved artifact prefix.
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
    ["ApprovalWriterRole"],
    "ApprovalWriterRole must be the ONLY principal granted s3:PutObject on the bare approvals/* "
      + "prefix (the final .approved artifact) — found: " + JSON.stringify(principalsWithPutOnApprovals),
  );

  const recorderRole = extractResourceBlock(text, "ApprovalPendingRecorderRole");
  // The recorder role legitimately PutObjects, but only under approvals/pending/*, never
  // the bare approvals/* prefix ApprovalWriterRole uses for the final artifact.
  assert.match(recorderRole, /approvals\/pending\/\*/, "ApprovalPendingRecorderRole must be scoped to approvals/pending/*");
});

test("GlassboxApprovalsBucket is not Object Lock (WORM) enabled — approvals/pending/* must remain mutable", () => {
  const bucket = extractResourceBlock(readTemplate(), "GlassboxApprovalsBucket");
  assert.doesNotMatch(bucket, /ObjectLockEnabled/, "GlassboxApprovalsBucket must not declare ObjectLockEnabled");
});

test("GlassboxApprovalHmacKey is declared as a Secrets Manager secret with a generated (never literal) value", () => {
  const secret = extractResourceBlock(readTemplate(), "GlassboxApprovalHmacKey");
  assert.match(secret, /Type: AWS::SecretsManager::Secret/);
  assert.match(secret, /GenerateSecretString/, "the HMAC key must be generated, never a hardcoded literal");
});

test("statemachine/glassbox-engagement.asl.json: AwaitHumanApproval no longer calls sns:publish.waitForTaskToken directly", () => {
  const aslPath = path.join(
    __dirname, "..", "infra", "aws", "glassbox-stack", "statemachine", "glassbox-engagement.asl.json",
  );
  const asl = JSON.parse(fs.readFileSync(aslPath, "utf8"));
  const state = asl.States.AwaitHumanApproval;
  assert.equal(state.Resource, "arn:aws:states:::lambda:invoke.waitForTaskToken");
  assert.equal(state.Parameters.FunctionName, "${ApprovalPendingRecorderFunctionArn}");
  assert.equal(state.Parameters.Payload["token.$"], "$$.Task.Token");
});

// ---------------------------------------------------------------------------------------
// ARCHITECTURAL FIX (Eric-approved): the downstream ExportSecurityHubFunction Lambda is
// invoked ONLY after AwaitHumanApproval resolves, and the model's own execution role must
// structurally lose securityhub:BatchImportFindings entirely.
// ---------------------------------------------------------------------------------------

test("statemachine/glassbox-engagement.asl.json: AwaitHumanApproval -> ExportToSecurityHub -> ResumeAgentRuntimeThroughReport, in that order", () => {
  const aslPath = path.join(
    __dirname, "..", "infra", "aws", "glassbox-stack", "statemachine", "glassbox-engagement.asl.json",
  );
  const asl = JSON.parse(fs.readFileSync(aslPath, "utf8"));
  assert.equal(asl.States.AwaitHumanApproval.Next, "ExportToSecurityHub");
  const exportState = asl.States.ExportToSecurityHub;
  assert.ok(exportState, "ExportToSecurityHub state must exist");
  assert.equal(exportState.Type, "Task");
  assert.equal(exportState.Resource, "arn:aws:states:::lambda:invoke");
  assert.equal(exportState.Parameters.FunctionName, "${ExportSecurityHubFunctionArn}");
  assert.equal(exportState.Parameters.Payload["target.$"], "$.target");
  assert.equal(exportState.Parameters.Payload["gradeVerdictHash.$"], "$.gradeResult.grade_verdict_hash");
  assert.equal(exportState.Next, "ResumeAgentRuntimeThroughReport");
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
    "ApprovalPendingRecorderRole",
    "ApprovalWriterRole",
    "AgentCoreRuntimeProvisionerRole",
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
  assert.doesNotMatch(
    role,
    /s3:PutObject|s3:DeleteObject|s3:\*/,
    "ExportSecurityHubRole must never be able to write or delete the evidence it exports from",
  );
});

test("ExportSecurityHubFunction is a Node Lambda wired to the shared infra/aws/glassbox-stack/functions/export-security-hub/index.js handler under its own dedicated role", () => {
  const fn = extractResourceBlock(readTemplate(), "ExportSecurityHubFunction");
  assert.match(fn, /Runtime:\s*nodejs20\.x/);
  assert.match(fn, /Handler:\s*infra\/aws\/glassbox-stack\/functions\/export-security-hub\/index\.handler/);
  assert.match(fn, /Role:\s*!GetAtt ExportSecurityHubRole\.Arn/);
  assert.match(fn, /GRADE_FREEZE_BUCKET:\s*!Ref EvidenceBucket/);
  assert.match(fn, /SECURITY_HUB_PRODUCT_ARN:/);
});

test("GlassboxStateMachineRole may invoke ExportSecurityHubFunction", () => {
  const role = extractResourceBlock(readTemplate(), "GlassboxStateMachineRole");
  assert.match(role, /Resource:\s*!GetAtt ExportSecurityHubFunction\.Arn/);
});
