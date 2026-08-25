# runner-host — Release A dispatch host (EC2)

The self-hosted execution side of the www dispatch contract. One arm64 EC2
instance runs the **dispatch service** (systemd, Node 22) which accepts the
www handoff (`POST /dispatch`, schemaVersion 1 — see
`www/convex/assessments.ts` `submitRunnerRequest`), dedupes by
`Idempotency-Key` on a JSONL ledger, and spawns per-run Bob runner containers
with env-only secrets.

## Layout

- `template.yaml` — CloudFormation: VPC, ALB + ACM, deny-egress instance SG
  (443 + DNS out only), IAM role, SSM SecureString secrets, EC2 `t4g.large`
  (arm64, AL2023, IMDSv2 required, Session Manager only unless a key pair is
  passed), Route53 record when `DispatchDomainName` is set.
- `dispatch/` — the service. `server.js` (HTTP) + `service.js` (core) +
  tests. No runtime dependencies.

## Egress honesty

The instance security group is **port-level deny-egress** (HTTPS + DNS only).
Security groups cannot enforce domain allowlists, so per-run DOMAIN
enforcement is Bob's own egress-profile/scope kernel inside the runner
container (the same machinery the engine already uses for
`block_internal_hosts` and egress profiles). For Release A this is the
documented posture; per-run dynamic egress via a forwarding proxy is the
fast-follow if the design partner needs targets outside the static posture.

## Deploy

```bash
# 0. Prereqs: AWS profile with the target account, us-east-1. ACM cert ARN
#    for the dispatch domain (or use the ALB DNS name with no domain).

# 1. Pack + upload the dispatch service.
tar -czf /tmp/dispatch.tar.gz -C infra/runner-host/dispatch .
aws s3 cp /tmp/dispatch.tar.gz s3://<bucket>/runner-host/dispatch.tar.gz

# 2. Build + push the runner image (Phase 4) and note its ECR URI.

# 3. Validate + deploy.
aws cloudformation validate-template --template-body file://infra/runner-host/template.yaml
aws cloudformation create-stack \
  --stack-name bob-runner-host \
  --template-body file://infra/runner-host/template.yaml \
  --parameters \
    ParameterKey=DispatchServiceArtifactBucket,ParameterValue=<bucket> \
    ParameterKey=RunnerImageUri,ParameterValue=<account>.dkr.ecr.us-east-1.amazonaws.com/bob-runner@sha256:<digest> \
    ParameterKey=ConvexProjectionBaseUrl,ParameterValue=https://<deployment>.convex.site \
    ParameterKey=DispatchCertificateArn,ParameterValue=<cert-arn> \
    ParameterKey=DispatchDomainName,ParameterValue=<domain or empty> \
    ParameterKey=DispatchHostedZoneId,ParameterValue=<zone or empty> \
  --capabilities CAPABILITY_NAMED_IAM
```

## Post-deploy

1. **Rotate the four secrets**: `aws ssm put-parameter --overwrite --type
   SecureString` for `/bob-dispatch/{DISPATCH_SECRET,RUNNER_SECRET,REPORTS_SECRET,DEEPSEEK_API_KEY}`.
   The placeholders are `CHANGE_ME`; the service boots with them until
   rotated. `RUNNER_SECRET` and `REPORTS_SECRET` must match the www Convex
   deployment env; `DISPATCH_SECRET` becomes www's `RUNNER_DISPATCH_SECRET`.
2. **Set www's `RUNNER_DISPATCH_URL`** to the stack's `DispatchUrl` output.
3. **Smoke**: `curl -i https://<url>/health` → 200; a POST /dispatch with a
   wrong bearer → 401; with the right bearer + valid payload → 202 and one
   runner container on the box.

## Known lint note

`cfn-lint` 1.55 flags `Type: SecureString` on the four SSM parameters
(E3030) — a spec-data false positive; CloudFormation's own
`validate-template` (authoritative) accepts it.

## Teardown

```bash
aws cloudformation delete-stack --stack-name bob-runner-host
```

## Dispatch contract (implemented verbatim)

- `POST /dispatch`; headers `Authorization: Bearer <DISPATCH_SECRET>`,
  `Idempotency-Key: <runId>`; body schemaVersion 1:
  `assessmentId, runId, runSlug, target (https), targetDomain, targetKind
  (web|repo|contract), runMode, autonomy:"operator-approved", objective,
  scope?, sourceRef, kind (assessment|retest), retestOf[], projectionKey`.
- 2xx = accepted (credit consumed on www's side). 4xx = rejected (credit
  refunded, assessment blocked by www).
- Idempotent: a replayed key returns the stored 202 and spawns nothing,
  including across service restarts.
- Container env: payload at `BOB_PAYLOAD_PATH`, secrets `RUNNER_SECRET` /
  `REPORTS_SECRET` / `DEEPSEEK_API_KEY`, `BOB_PROJECTION_URL`,
  `BOB_RUN_SLUG` / `BOB_PROJECTION_KEY` / `BOB_RUN_KIND` / `BOB_RETEST_OF`
  / `BOB_REPORT_SLUG` — the contract `bob_finalize_report` consumes for the
  seal projection.
- Concurrency cap 2 (FIFO queue), per-run timeout 90 minutes (`docker kill`),
  logs at `/var/lib/bob-dispatch/logs/<runId>.log`.
