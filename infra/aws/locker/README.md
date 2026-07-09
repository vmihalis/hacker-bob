# locker — web target (the breadth demo). IaC.

A **self-hosted** CyStack Locker (`github.com/lockerpm/core-api`, GPLv3, Django/MySQL/Redis)
as an in-VPC service, private DNS `locker.internal`, seeded with **synthetic** multi-tenant
data + one documented-class IDOR/BOLA (**disclosed as seeded** — no public CVE, which is why
Locker is the breadth demo and KyberFork is the anchor). Our own instance, our own synthetic
data; no real user vaults. Testing our own self-hosted instance is fully within GPLv3 rights
(no redistribution → copyleft not triggered).

Spec: `aabw-2026/projects/06-aws-glassbox/LOCKER-SPEC.md`. TODO(build-day): author the stack.

**BRIGHT LINE:** scope = `locker.internal` ONLY — never Locker's hosted/cloud service, never real user data.
