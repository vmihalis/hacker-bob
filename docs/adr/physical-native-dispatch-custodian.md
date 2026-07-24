# ADR: Physical native dispatch custodian

- Status: source-only fixture implemented; production blocked
- Date: 2026-07-19
- Applies to: Plane-PH final hardware effect seam

## Decision

Bob uses a separately scheduled native custodian as the last verifier and sole
owner of a delegated physical-device descriptor. JavaScript may construct and
sign canonical inputs, but cannot select a path or descriptor, invoke a generic
transport, supply a callback, or receive raw response bytes at this seam.

The implemented Darwin fixture is deliberately non-authorizing. It has one
zero-argument Node-API entry and a fixed process ABI:

| FD | Direction | Exact content |
| --- | --- | --- |
| 3 | child receives | One canonical `HBPHDLC1` signed launcher-context envelope |
| 4 | child owns | One exact character device, normalized to `O_RDWR\|O_NONBLOCK` |
| 5 | child receives | One canonical `HBPHDIN1` dispatch envelope plus command frame |
| 6 | child sends | One fixed 196-byte `HBPHDRS1` redacted terminal result |
| 7 | child sends | One fixed `HBPHVSR1` record into an empty pre-reserved owner-only `O_WRONLY\|O_APPEND` vault descriptor |

FDs 3, 5, and 6 must be distinct anonymous AF_UNIX `SOCK_STREAM` capabilities
with exact access/status/descriptor flags and closed directions. FDs 4 and 7
must also be distinct from every control capability and each other. The
custodian derives both delegated kernel descriptor identities independently,
duplicates it to a private close-on-exec descriptor, revalidates the duplicate,
and closes public FD 4 before parsing authority. There is no path lookup,
enumeration, or caller-chosen descriptor fallback.

The fixture currently receives that ABI at process creation. Production must
instead pathname-exec the custodian while powerless, attest its live audit
token, exact code requirement, and retained-FD-to-mapped `MH_EXECUTE` image,
then transfer this same closed ABI with `SCM_RIGHTS` and issue a durable one-use
GO as specified by `darwin-post-exec-capability-release.md`.

## Signed authority envelopes

Launcher and dispatch authority use separate Ed25519 domains. Both canonical
envelopes sign their magic, version, algorithm ID, key-ID length and bytes,
payload length, public-SPKI digest, and ordered TLV payload. The key ID is signed;
rewriting an alias cannot resurrect revoked authority that happens to reuse key
material.

The launcher payload embeds and binds the launcher and dispatch SPKIs, execution
principal, worker process/bundle and loaded-image identities, provider and
implementation, semantic manifest, device and enrollment, connection generation,
launcher ticket, descriptor inventory, exact delegated descriptor, clock epoch,
launch nonce, execution lineage, vault reservation/ingest capability, exact
vault-sink identity, response ceiling, and artifact-handle digest. The dispatch
payload cross-binds those values with the
session/node/attempt, grant and authority, operation/parameters/effects,
pre-state/transition, resource allocation/fence, journal/outbox/redemption,
safety and cleanup, observer, command, response limit, and signed time window.

Native code independently parses every field, verifies both signatures, checks
the current UID/GID, derives the canonical `HBPHDID1` descriptor digest, validates
the command digest and exact Chameleon frame, and, after every readiness wait,
rereads continuous monotonic time, real/effective UID/GID, and the exact private
descriptor identity and flags immediately before each first or continuation
write. A delayed libuv work item or post-poll scheduling stall cannot convert an
expired ticket into a first or partial continuation effect.

## Terminal semantics

The process is one-use. Before this state machine exists, FD 6 must be proved to
be a distinct AF_UNIX result socket and retained as a private identity-pinned
capability. An absent fixture gate or invalid/aliased fixed topology closes
silently; native code emits no purported rejection through an untrusted FD.
Only the trusted parent may durably classify the resulting missing receipt.

Once that terminal capability is established, its result state is closed:

- `rejected_no_effect`: no command byte crossed the effect seam;
- `ambiguous_quarantined`: at least one command byte crossed the seam and the
  exact transaction did not complete; or
- `fixture_complete_non_authorizing`: exactly one correlated response frame was
  validated in the PTY fixture.

Complete and ambiguous states require verified dispatch authority, descriptor,
positive ticket sequence, and the before-write deadline recheck. Complete results
require a committed sink record and contain the response length and SHA-256
digest. Ambiguous results preserve the
length and digest of any response prefix actually read; if no response byte was
observed, both are zero. Before terminal emission the native custodian writes the
fixed 280-byte binding header plus the raw observation to FD 7, fsyncs and
revalidates that exact inode, closes its private sink capability, and exposes
only the header digest and sink identity digest on FD 6. Raw response bytes never
cross FD 6.
The JavaScript decoder rejects unreachable combinations of status, flags,
sequence, lengths, and digests.

The artifact-vault owner now pre-creates FD 7, retains a distinct read owner,
and accepts only the complete decoded terminal object plus the broker's exact
50-field execution lineage. It recomputes the lineage digest, cross-binds every
native header digest, commits a complete fixture response into encrypted raw
custody, and then overwrites, truncates, unlinks, and directory-fsyncs its
managed staging inode. That commit yields only the separately private-branded
`provider_response_raw_custody_receipt`, with
`semantic_validation_performed: false`. It carries the delegated source
descriptor identity only as `source_descriptor_identity_digest`; it contains no
`result_code` or `device_state_digest` and cannot satisfy the broker's semantic
sink-commit assertion. A syntactically valid Chameleon error frame or an
operation-specific malformed payload therefore remains raw evidence. The first
fixed provider-owned validator now materializes only that exact encrypted
artifact behind vault custody, runs the bounded source-owned frame parser and
exact `get_app_version` payload decoder, zeroizes the vault and parser custody
buffers, and emits a distinct private-branded semantic observation. That
observation binds the raw receipt, complete execution lineage, reviewed semantic
manifest, fixed operation schema, native cleanup receipt, and a fresh signed
monotonic-wall-clock sample. It requires command 1000, status `0x0068`, and
exactly two version bytes; it emits no `device_state_digest` and remains
non-authoritative and non-production. Native staging cleanup is durably
confirmed only after overwrite/truncate/unlink/fsync succeeds, so a raw commit
followed by ambiguous cleanup cannot be promoted. A durable,
reservation-scoped fence binds one ingest capability to exactly one execution
lineage and either raw-custody or semantic-result journal mode before any
prepared intent, preventing crash, restart, or competing-lineage reconciliation
from crossing those journal classes. The semantic observation is an
authenticated successor inside the already selected raw-custody journal, not a
legacy semantic sink commit. A fully committed `ambiguous_quarantined` record
is retained in that same encrypted, digest-bound raw-custody journal under its
exact lineage and reservation. It cannot enter the complete-settlement semantic
validator or mint expected-result success. Plaintext staging cleanup follows
durable custody, and crash or lost-ack recovery reads back only the private raw
receipt. Sink preparation uses exclusive creation, and a failed duplicate
preparation never unlinks or mutates the pre-existing live inode. A later
preparation failure deliberately does not unlink its partial path: Node has no
atomic unlink-by-open-file-description primitive, so check-then-unlink would
permit a same-principal replacement race. The inert orphan blocks reuse until a
separate identity-safe recovery custodian exists. Filesystem failures cross the
public boundary only as one stable redacted preparation error, without the
vault root or capability-derived filename. This owner remains
non-production because a parent cannot transitively revoke descriptors
duplicated into an external writer, the native terminal origin is not privately
authenticated, and crash recovery for a plaintext staging inode is not
installed. Identity-safe partial-preparation orphan recovery is also not
installed. The semantic validator additionally lacks a separately isolated
principal, current provider-principal trust proof, an external monotonic receipt
anchor, and real Chameleon HIL qualification.

Response completion means one exact correlated frame followed by an immediate
kernel queued-byte check. It is not a two-millisecond or other time-based
quiescence claim. A byte arriving later is bounded by terminal closure of the
one-use connection before result emission and is not relabelled as absent.

## Verification

No test opens or scans Chameleon hardware. Darwin PTYs and anonymous socketpairs
exercise:

- a Node 20 canonical envelope golden vector and native/JavaScript descriptor
  digest agreement;
- key-ID rewriting, forged context/dispatch signatures, substituted keys,
  validly resigned binding forks, UID drift, command drift, malformed/trailing
  frames, and expired tickets;
- exact fixed-descriptor flags, alias rejection, descriptor substitution, and
  in-process one-use rejection;
- partial input sockets, libuv queue saturation, and a blocked JavaScript event
  loop, plus deterministic post-poll stalls before first and continuation writes;
- partial device writes and no, late, partial, or duplicate responses, all
  terminally ambiguous with redacted observations;
- every accepted and rejected terminal-result matrix combination;
- vault descriptor issuance, revocation, cancellation, destroy-time draining,
  hardlink and identity drift, terminal/header forks, and ambiguity refusal; and
- a real fixture-process FD 7 crossing from vault reservation through native
  custody into encrypted ingest without projecting raw bytes through the broker.

An exact-ticket restart against the already committed sink is rejected before
effect because the inode is no longer empty. Whole-domain rollback or a trusted
launcher that substitutes a fresh sink remains outside this local mechanism;
the native atomic fence is not independently retained durable replay authority.

## Consequences and blockers

`production_ready`, `hardware_access_authorized`, and `authoritative` remain
false. The current fixture dynamically uses Ed25519 EVP symbols from the pinned
Node 20 executable; it is not an independently linked or signed verifier. The
launcher context is self-verifying but not yet anchored to a qualified external
keyring/revocation authority. The fixed terminal result is neither authenticated
nor durably committed.

Production additionally requires all of:

- a signed immutable Node 20 arm64 prebuild or standalone native custodian and
  matching qualified launcher;
- external launcher/dispatch key enrollment, rotation, and revocation;
- durable restart replay and signed-fork fencing;
- authenticated native terminal receipts and a durable outbox;
- a separately isolated response-vault principal and key, authenticated native
  terminal/claim/deadline origins, external-writer lifecycle custody, and
  restart-safe plaintext-staging reconciliation;
- real Chameleon hardware-in-the-loop qualification; and
- a continuously bound external DTR/RTS witness.

Until those gates close, no installer, provider, broker, or launcher may convert
this fixture into hardware authority.
