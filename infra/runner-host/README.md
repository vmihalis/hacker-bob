# runner-host — Release A dispatch host (EC2)

The self-hosted execution side of the www dispatch contract. One arm64 EC2
instance runs the Node 22 dispatch service as the dedicated `bob-dispatch`
user, accepts `POST /dispatch`, persists replay state, and launches one
digest-pinned Bob runner container per admitted run.

## Layout

- `template.yaml` — CloudFormation for the VPC, mandatory ALB TLS hostname,
  deny-egress instance security group, least-privilege IAM role, hardened
  systemd service, and arm64 AL2023 host. The stack references three existing
  SSM `SecureString` parameters; it never creates or stores their values.
- `dispatch/` — HTTP service, replayable dispatch core, focused tests, and a
  locked Convex client dependency. The host installs it with `npm ci`.

## Egress honesty

The instance security group is **port-level deny-egress** (HTTPS + DNS only).
Security groups cannot enforce domain allowlists, so per-run DOMAIN
enforcement is Bob's own egress-profile/scope kernel inside the runner
container (the same machinery the engine already uses for
`block_internal_hosts` and egress profiles). For Release A this is the
documented posture; per-run dynamic egress via a forwarding proxy is the
fast-follow if the design partner needs targets outside the static posture.

## Host security model

- `DispatchDomainName`, `DispatchHostedZoneId`, and a matching ACM certificate
  are required. The public dispatch URL is always HTTPS on that hostname.
- The instance role can read only the three named SSM parameters, the exact S3
  artifact, pull layers from the exact ECR repository, and signal only its
  current CloudFormation stack. ECR authorization remains account-scoped
  because AWS requires `ecr:GetAuthorizationToken` on `"*"`. Cloud-init
  verifies the operator-supplied SHA-256 digest before extracting the S3
  artifact. Stack creation waits for the local dispatch health check and fails
  if bootstrap or service startup fails.
- The root-owned mode-`0700` start wrapper fetches and decrypts secrets only
  into shell variables, rejects empty or placeholder values, authenticates to
  ECR through an ephemeral `/run` Docker config, and pulls the digest-pinned
  image before dropping to `bob-dispatch`.
- systemd confines the service with `NoNewPrivileges`, `PrivateTmp`,
  `ProtectSystem=strict`, kernel/filesystem protections, and explicit writable
  paths. The service retains Docker-group access because it must launch and
  reattach runner containers; treat that account as host-privileged.
- EC2 requires IMDSv2 with hop limit 1, preventing ordinary bridge containers
  from receiving instance-metadata responses.

## Deploy

```bash
# 0. Preprovision three SSM SecureString parameters using the operator's
#    secured secret-management flow. These are parameter names, not values.
DISPATCH_SECRET_PARAMETER=/bob-dispatch/DISPATCH_SECRET
RUNNER_SECRET_PARAMETER=/bob-dispatch/RUNNER_SECRET
DEEPSEEK_API_KEY_PARAMETER=/bob-dispatch/DEEPSEEK_API_KEY
# Resolve the current AL2023 arm64 image through EC2. Passing the image ID
# avoids requiring the CloudFormation caller to read the public /aws SSM namespace.
RUNNER_AMI_ID=$(aws ec2 describe-images \
  --region <region> \
  --owners amazon \
  --filters \
    Name=name,Values='al2023-ami-2023.*-kernel-6.1-arm64' \
    Name=state,Values=available \
    Name=architecture,Values=arm64 \
    Name=root-device-type,Values=ebs \
  --query 'sort_by(Images,&CreationDate)[-1].ImageId' \
  --output text)
test -n "$RUNNER_AMI_ID" && test "$RUNNER_AMI_ID" != None

# 1. Pack and upload the dispatch service, retaining its immutable digest.
tar -czf /tmp/dispatch.tar.gz -C infra/runner-host/dispatch server.js service.js package.json package-lock.json
DISPATCH_SERVICE_ARTIFACT_SHA256=$(openssl dgst -sha256 -r /tmp/dispatch.tar.gz | cut -d' ' -f1)
aws s3 cp /tmp/dispatch.tar.gz s3://<bucket>/runner-host/dispatch.tar.gz
# 2. Build and push the linux/arm64 runner image. Resolve both the immutable
#    image URI (<repository-uri>@sha256:<64 lowercase hex>) and repository ARN.

# 3. Validate and deploy. AMI ID, domain, hosted zone, certificate, both
#    Convex URLs, three parameter names, pinned image, and exact ECR repository
#    are required.
#    The sizing below is a cost-conscious staging profile: keep one active run
#    and two queued runs on the 2 GiB t4g.small host.
#    RunnerSubnet defaults to the second configured AZ; set it to a only when
#    that AZ has the required instance capacity.
aws cloudformation validate-template \
  --template-body file://infra/runner-host/template.yaml
aws cloudformation create-stack \
  --stack-name bob-runner-host \
  --template-body file://infra/runner-host/template.yaml \
  --parameters \
    ParameterKey=DispatchServiceArtifactBucket,ParameterValue=<bucket> \
    ParameterKey=DispatchServiceArtifactKey,ParameterValue=runner-host/dispatch.tar.gz \
    ParameterKey=DispatchServiceArtifactSha256,ParameterValue=$DISPATCH_SERVICE_ARTIFACT_SHA256 \
    ParameterKey=RunnerImageUri,ParameterValue=<account>.dkr.ecr.us-east-1.amazonaws.com/bob-runner@sha256:<digest> \
    ParameterKey=RunnerImageRepositoryArn,ParameterValue=arn:aws:ecr:us-east-1:<account>:repository/bob-runner \
    ParameterKey=ConvexProjectionBaseUrl,ParameterValue=https://<deployment>.convex.site \
    ParameterKey=ConvexUrl,ParameterValue=https://<deployment>.convex.cloud \
    ParameterKey=DispatchSecretParameterName,ParameterValue=$DISPATCH_SECRET_PARAMETER \
    ParameterKey=RunnerSecretParameterName,ParameterValue=$RUNNER_SECRET_PARAMETER \
    ParameterKey=DeepSeekApiKeyParameterName,ParameterValue=$DEEPSEEK_API_KEY_PARAMETER \
    ParameterKey=DispatchCertificateArn,ParameterValue=<cert-arn> \
    ParameterKey=DispatchDomainName,ParameterValue=<dispatch.example.com> \
    ParameterKey=DispatchHostedZoneId,ParameterValue=<zone-id> \
    ParameterKey=RunnerAmiId,ParameterValue=$RUNNER_AMI_ID \
    ParameterKey=InstanceType,ParameterValue=t4g.small \
    ParameterKey=RunnerSubnet,ParameterValue=b \
    ParameterKey=MaxConcurrentRuns,ParameterValue=1 \
    ParameterKey=MaxQueuedRuns,ParameterValue=2 \
    ParameterKey=MaxQueueAgeMs,ParameterValue=900000 \
    ParameterKey=LedgerCompactRows,ParameterValue=10000 \
    ParameterKey=RunTimeoutMinutes,ParameterValue=90 \
  --capabilities CAPABILITY_NAMED_IAM
```

## Post-deploy and rotation

1. Set www's `RUNNER_DISPATCH_URL` to the stack `DispatchUrl`,
   `RUNNER_DISPATCH_SECRET` to the referenced dispatch secret, and
   `RUNNER_SECRET` to the same value referenced by
   `RunnerSecretParameterName`.
2. To rotate a secret, overwrite the existing SSM `SecureString`, then restart
   `bob-dispatch` through Session Manager. The wrapper fetches all three current
   values on every start and refuses to launch for an empty or known placeholder
   value. No host environment file contains them.
3. Check `systemctl status bob-dispatch` and `journalctl -u bob-dispatch` through
   Session Manager.
4. Smoke `GET https://<dispatch-domain>/health` for 200; a dispatch with a
   wrong bearer must return 401; a valid exact payload must return 202 and
   create one labeled runner container.

## Teardown

```bash
aws cloudformation delete-stack --stack-name bob-runner-host
```

## Dispatch contract

- `POST /dispatch`; headers `Authorization: Bearer <DISPATCH_SECRET>` and
  `Idempotency-Key: <runId>`; body schema version 1 has exactly:
  `assessmentId`, `runId`, `runSlug`, `target`, `targetDomain`, `targetKind`,
  `runMode`, `autonomy:"operator-approved"`, `objective`, optional `scope`,
  optional `sourceRef`, `kind`, `retestOf`, and `projectionKey`.
- Web targets are canonical HTTPS URLs without userinfo; repositories are
  canonical GitHub clone URLs pinned by an exact commit; contracts are
  lowercase EVM CAIP-10 identities. `targetDomain` must match the shared
  selector algorithm for its target kind.
- 202 means admitted. Exact in-flight and terminal replays return the stored
  state without spawning again. A digest mismatch is 409. A replay of an
  interrupted run creates exactly one new generation. Queue saturation is 429
  with `Retry-After: 60`.
- The host passes `BOB_PAYLOAD_JSON`, `RUNNER_SECRET`,
  `DEEPSEEK_API_KEY`, `BOB_PROJECTION_URL`, and lifecycle metadata by named
  Docker environment variables; secret values are not written to payload or
  env files. The Bob MCP receives only its explicit allowlist and never the
  model API key.
- Defaults: two concurrent runs, eight queued runs, 15-minute queue age, and a
  90-minute per-run timeout. Replay ledger and redacted logs live under
  mode-`0700` `/var/lib/bob-dispatch/{ledger,logs}`; transient repository
  checkouts live under `/run/bob-dispatch`.
