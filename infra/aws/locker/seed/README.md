# infra/aws/locker/seed/ — seeded / synthetic artifacts (disclosure)

`seed-idor.patch` and `seed-data.py` in this directory are **seeded/synthetic
artifacts authored by us for this engagement** — not native defects and not
real data. `seed-idor.patch` is a disclosed, one-line-removal BOLA/IDOR
(OWASP API1:2023) against an *illustrative* single-cipher-read handler,
targeting the primary variant specced in `LOCKER-SPEC.md` §2.1 (with the
§2.2 shared-cipher variant included as a clearly-labeled, non-graded
FALLBACK hunk in the same file). `seed-data.py` re-runnably generates the
synthetic multi-tenant fixture matching `LOCKER-SPEC.md` §1.3 exactly:
`U-A` (alice@acme.test, ciphers `c1001-c1010`, victim), `U-B` (bob@rival.test,
ciphers `c2001-c2010`, attacker's own valid authenticated account), `U-C`
(carol@control.test, ciphers `c3001-c3010`), and `TEAM-1` (shared ciphers
`s5001-s5005`, members `U-A`+`U-C` only). Cross-reference: `LOCKER-SPEC.md`
§1.3 (tenancy model) and §2 (seed mechanism, both variants).

**`U-C` is the control tenant and is never attacked.** Every probe against
any `U-C` resource, under any endpoint, must return a correct authorization
denial — this is a hard invariant of the seed, not a soft expectation.

**Decoys that must remain correctly protected (per `LOCKER-SPEC.md` §2.3) —
a future implementer applying `seed-idor.patch` against the real pinned
`lockerpm/core-api` commit must not widen the bug to touch these:**

- `GET /api/v1/ciphers` (list) — must keep returning only the caller's own
  ciphers; no BOLA on list.
- `PUT /api/v1/ciphers/{id}` (update) — must keep enforcing the ownership
  check on write; the seed only removes the check on the **read** path.
- **All of `U-C`'s resources**, under every endpoint, including the seeded
  one.

A report that flags any of the above as vulnerable is a graded **false
positive**, not partial credit.

`infra/aws/locker/MANIFEST.yaml` (out of scope for this node, owned
downstream) will reference `seed-idor.patch`'s content hash once written —
this directory does not create or assume that file.
