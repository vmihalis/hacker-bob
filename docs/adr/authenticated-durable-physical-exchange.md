# ADR: Authenticated durable physical grant/GO/receipt/outbox exchange

- Status: provider-neutral source contract implemented; production blocked
- Date: 2026-07-19
- Applies to: Plane-PH PH-S7 and PH-X7 final-effect recovery boundary

## Decision

Bob uses the closed
`hacker-bob/authenticated-durable-physical-exchange/v1` contract between native
post-exec capability release and any physical effect. The JavaScript module is
an inert contract and hostile-test fixture. It does not open hardware, persist
production state, or turn caller-held keys or caller-reported fsyncs into
authority.

Four pairwise-distinct Ed25519 principals and key usages are mandatory:

| Role | Key usage | Signed records |
| --- | --- | --- |
| Grant authority | `physical_capability_grant_signing` | one-use capability grant |
| GO authority / supervisor | `physical_commit_go_signing` | one-use `COMMIT_GO` |
| Effect worker | `physical_terminal_receipt_signing` | exact terminal receipt |
| Durability custodian | `physical_durable_exchange_signing` | journal, outbox, and durability attestations |

Every record repeats one canonical binding. It covers the release manifest,
component manifest and artifact, capability ABI, handoff session, supervisor
and worker audit tokens, PID/pidversion/start/instance/mapped-image identities,
principals and principal policy, exact worker-direct-parent lineage, supervisor
listener generation, exact launch nonce, SHA-256 of its decoded 32 bytes, and
launch generation, authority and revocation
epochs, resource epoch, capability set and generation, descriptor semantics,
grant and GO sequences, monotonic clock epoch, and all phase/parent deadlines.
All cross-native lineage, authority, resource, revocation, capability, grant,
and GO generation/epoch/sequence values are canonical unsigned 64-bit decimal
strings. `go_sequence` must be strictly greater than `grant_sequence`; neither
equality nor reversal is accepted.

The worker direct-parent audit token, process-instance digest, and start digest
must exactly equal the supervisor values. The GO signing principal must be the
bound supervisor, and the terminal-receipt signer must be the bound worker.
Expected and observed descriptor-semantics digests must match, receiver
`CLOEXEC` application is mandatory, aliases are forbidden, and unexpected
descriptors must already be closed.
Every live phase check repeats the artifact digest, capability ABI digest, and
handoff session identifier as well as their surrounding release/component and
handoff digests. The effect phase closes at the signed result deadline; it has
no inferred or unsigned deadline.

## Durable ordering

Journal and outbox records are separately signed hash chains. A record cannot
claim its own fsync without a circular digest, so durability uses a third
signed chain of post-fsync attestations. Each attestation references:

- the exact signed record envelope and payload digests;
- SHA-256 and byte length of its canonical serialized bytes;
- the previous record and previous durability-attestation digests;
- stable store/file identity, generation, and contiguous byte offset;
- globally forward append, data-fsync, and directory-fsync sequences and
  monotonic completion times; and
- the enrolled exclusive durability-writer principal.

For each durability attestation the sequence identifiers are strictly ordered
`append < data-fsync < directory-fsync`. Completion timestamps may tie where
the storage provider reports the same monotonic tick, but sequence identifiers
may not. Signed journal, outbox, receipt, durability, store/file-generation,
and record-offset coordinates are canonical uint64 decimal strings too; only
locally bounded counts and byte lengths remain JavaScript safe integers.

The contract refuses capability transfer before a durable grant history, GO
issuance before durable `READY_NO_EFFECT`, effect start before the GO journal
record is durably committed, terminal transition before receipt fsync, outbox
enqueue before terminal-journal fsync, or terminal acknowledgement before the
outbox enqueue fsync.

The legal state path is closed:

`none -> grant_reserved -> capabilities_transferred -> ready_no_effect -> go_reserved -> effect_started -> receipt_recorded -> terminal`

Before GO, the exact child may terminate into an authenticated
`rejected_no_effect` terminal only with a no-GO/child-exit evidence digest.
Its signed journal subject kind is closed to `no_go_child_exit_evidence`, so an
arbitrary digest label cannot be substituted and treated as that proof.
After GO, a missing or malformed receipt is always
`ambiguous_quarantined`. It is not an authenticated terminal until the
durability custodian has signed and fsynced the exact quarantine journal and
outbox projections.

## Replay and restart

Grant nonce, launch generation, capability generation, grant sequence, and GO
sequence are single-use. Duplicate consumption inside a transcript and reuse
across supplied exchange records fail closed. Restart reconciliation returns a
closed recovery action for every boundary:

- discard an uncommitted grant;
- terminate the exact pre-GO child and record rejected-no-effect;
- persist an authenticated post-GO ambiguous quarantine;
- persist a receipt-derived terminal;
- enqueue a signed terminal; or
- redeliver an already durable outbox item only.

Effect retry is never returned as a recovery action and an explicit automatic
retry request is rejected. Outbox delivery may be retried without replaying the
effect.

## Production boundary

`createFixtureExchangeSigner` hides a caller-provided private `KeyObject` in a
module-private `WeakMap`; private material is never projected in a signer,
envelope, verifier, reconciliation result, or error. The verifier accepts only
caller-supplied public keys and is explicitly marked
`caller_held_javascript_contract_fixture`, `caller_supplied_trust: true`, and
`production_ready: false`. Durability attestations likewise require
`caller_asserted_non_production_fixture` as their evidence origin.

Production still requires a native exclusive writer using an immutable
external keyring, descriptor-relative journal/outbox custody, actual append +
data/directory fsync, authenticated stable-byte readback after restart, native
monotonic/live authority reads, OS-separated principals and ACLs, post-exec
running-image attestation, the native SCM_RIGHTS/GO state machine, and HIL.
Until those exist, the module always reports `production_ready: false` and
`hardware_access_authorized: false`.

Native prebuild manifest/evidence v2 must expose and cross-bind the exact
supervisor/worker parent/start/listener/nonce vocabulary above. A session
transcript containing only audit token, PID/pidversion, nonce digest, and
generation is insufficient to prove this exchange binding.
