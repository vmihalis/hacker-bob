# locker — web target (the breadth demo). IaC.

A **self-hosted** CyStack Locker (`github.com/lockerpm/core-api`, GPLv3, Django/MySQL/Redis)
as an in-VPC service, private DNS `locker.internal`, seeded with **synthetic** multi-tenant
data + one documented-class IDOR/BOLA (**disclosed as seeded** — no public CVE, which is why
Locker is the breadth demo and KyberFork is the anchor). Our own instance, our own synthetic
data; no real user vaults. Testing our own self-hosted instance is fully within GPLv3 rights
(no redistribution → copyleft not triggered).

Spec: `aabw-2026/projects/06-aws-hacker-bob/LOCKER-SPEC.md`.

**BRIGHT LINE:** scope = `locker.internal` ONLY — never Locker's hosted/cloud service, never real user data.

## Architecture

`template.yaml` is an AWS SAM/CloudFormation template that creates the private
Locker target inside the same VPC/subnet set used by `infra/aws/hacker-bob-stack`.
It commits to the ECS-on-EC2 baked-AMI path: build the Locker AMI elsewhere
with the seeded `lockerpm/core-api` image, MySQL image, Redis image, Docker, the
ECS agent, and the synthetic data already local, then run it in the
no-IGW/no-NAT private subnet with no runtime ECR pull path.

The Locker app, MySQL, and Redis are colocated in one ECS EC2 task using host
networking, so intra-stack traffic is localhost. The only network-facing
listener is `locker.internal` on
`LockerServicePort` (default `443`). `LockerSecurityGroup` accepts ingress only
from the hacker-bob stack's deny-egress security group by SG reference, never from
a CIDR. Its egress list is explicit to suppress CloudFormation's implicit
allow-all behavior.

Because `infra/aws/hacker-bob-stack/template.yaml` receives `VpcId` as a parameter
and does not create a Route 53 private hosted zone, this stack creates the
minimal private zone and `A` record for `locker.internal`, scoped to that VPC.
Its `LockerSecurityGroupId` output is shaped for the hacker-bob stack's existing
`LockerSecurityGroupId` parameter.

## Seed And Manifest

Reuse the existing seed directory as the source of truth:

- `seed/seed-idor.patch` is the disclosed primary BOLA/IDOR seed on
  `GET /api/v1/ciphers/{cipher_id}`. The section 2.2 sharing variant remains
  a clearly labeled non-graded fallback.
- `seed/seed-data.py` emits the synthetic U-A/U-B/U-C and TEAM-1 fixture. U-C
  is the control tenant and must always deny.
- `seed/README.md` records the decoys: list scoped to caller, update keeps the
  ownership check, and U-C is never attacked.

`MANIFEST.yaml` pre-registers the seven LOCKER-SPEC section 1.2 endpoints,
marks exactly one row vulnerable, records the seed patch hash and seed-data
snapshot hash, and leaves the upstream `lockerpm/core-api` commit as
`{{SLOT: pin at build day}}` until a build-day operator can resolve and pin the
real commit. Do not backfill the manifest from hacker-bob report output.

## How To Validate/Deploy

No live AWS command was run while authoring this node. Human-gated build-day
steps are:

1. Build the Locker AMI outside the no-egress VPC with the exact pinned
   `lockerpm/core-api` commit, the reviewed `seed/seed-idor.patch`, the output
   of `python3 infra/aws/locker/seed/seed-data.py`, local MySQL/Redis images,
   Docker, and the ECS agent configured for the local cluster.
2. Update `MANIFEST.yaml` with the real upstream commit, keeping the existing
   hashes unless the seed files intentionally changed before any live run.
3. Deploy `template.yaml` with the same `VpcId` and `SubnetIds` passed to
   `infra/aws/hacker-bob-stack/template.yaml`, plus the hacker-bob stack's
   `DenyEgressSecurityGroupId` output as `HackerBobDenyEgressSecurityGroupId`.
4. Pass this stack's `LockerSecurityGroupId` output back into the hacker-bob
   stack's `LockerSecurityGroupId` parameter.

`sam validate` and `sam deploy` are intentionally not part of this node's
mechanical verification gate.

## Scope-Gate Discrepancy

LOCKER-SPEC section 0 says `locker.internal` "passes the scope gate on its
merits." The engine in this repository does not currently do that.

`mcp/lib/url-surface.js:221-234` defines `isBlockedInternalHost()` and blocks
any host ending in `.internal`. `mcp/lib/scope.js:201-228` runs
`assertHttpScopeDomain()`, checks `isBlockedInternalHost(host)`, and only tries
the operator-attested bypass after `labTargetEligibleHost(host)` passes.
`mcp/lib/lab-target-attest.js:111-115` makes only loopback or RFC1918 IPv4
literals lab-eligible; DNS hostnames are never eligible.

As the engine stands today, `target_domain: "locker.internal"` is rejected by
`assertHttpScopeDomain()` with `target_domain is not a public DNS domain`. That
contradicts LOCKER-SPEC section 0 and is deliberately not fixed in this IaC
node. Per `infra/runner/runner-contract.md:8-10` and
`infra/runner/runner-contract.md:247-253`, the runner-glue node owns any
in-place edits to scope, egress, and session authority.

## Honesty Lines

Locker is a real Vietnamese open-source product, but the finding is a bug we
seeded ourselves and disclose as seeded. The data is synthetic only; no real
vaults, credentials, people, CyStack hosted service, WhiteHub API, or bounty
submission path are touched. GPLv3 is satisfied by internal use because this
node redistributes nothing. The manifest is pre-committed and reproducible, but
unlike KyberFork it is not independent ground truth because we authored the
seed. If live containment or reporting evidence does not materialize, it is cut,
not faked.
