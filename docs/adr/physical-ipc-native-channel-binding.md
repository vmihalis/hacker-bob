# ADR: Native descriptor-to-IPC channel binding

- Status: native channel and source-only dispatch fixture complete; production custodian attestation blocked
- Date: 2026-07-19
- Applies to: Plane-PH separate-identity issuer/worker IPC

## Decision

The IPC design uses a two-flight, request-key-authenticated channel binding. A
caller-selected socket nonce, a JavaScript `net.Socket`, or a credential
snapshot that merely contains the enrolled request-key digest is not sufficient
proof that the signed request belongs to the descriptor inspected by the
kernel adapter.

The current JavaScript broker can admit only a branded, closed-script
`deterministic_mock` dispatch port. It cannot construct a production,
hardware-authorized, or separate-identity dispatch port. Hardware IPC additionally
requires an independently scheduled worker, process, or native custodian that
rechecks the trusted signed deadline immediately before its effect seam. Until
that boundary exists and is attested, hardware dispatch fails closed.

The production listener must accept and duplicate the Unix descriptor in the
native boundary before JavaScript receives a request. It must never recover a
descriptor from `socket._handle`, an inherited getter, a pathname, or a
caller-supplied numeric claim. The existing one-message IPC v1 route remains a
deterministic/conformance-only route and cannot authorize hardware.

## Protocol

The server moves one connection through this closed state machine:

```text
accepted_native
  -> descriptor_registered
  -> peer_snapshot_stable
  -> challenge_reserved
  -> challenge_sent
  -> request_and_proof_received
  -> global_request_reserved
  -> channel_proof_reserved
  -> test_only_fixture_dispatch_admitted | rejected_closed
```

There is no transition from a rejected, expired, disconnected, replayed, or
ambiguous state back to admission. Every descriptor token, challenge, and proof
is one-use. The closed request replay identity (request key, principals,
provider, nonce, and sequence) is also one-use across channels and process
restarts, independently of the fresh challenge and proof. A lost
reservation response is reconciled by exact readback and is never retried as a
new claim.

### Server challenge

The response-key-signed challenge binds at least:

- protocol/domain/version and a random server challenge nonce;
- listener, socket-root, socket-inode, connection-generation, and native
  acceptor implementation digests;
- native descriptor-registration nonce and binding-scheme digest;
- peer UID/GID/PID, audit-token, PID-version/process-start, executable signing,
  selected 20-byte CDHash plus its supported algorithm, full candidate-CDHash-set
  digest, and mapped-code identity digests;
- native add-on loaded-image identity and immutable server bundle/launch
  attestation digests;
- exact expected request key ID/public-key digest, issuer peer principal,
  execution principal, provider ID, provider descriptor and implementation
  digests, the exact closed fixture script and non-hardware dispatch-boundary
  semantics, and startup-authority digest;
- trusted monotonic coordinate, issue time, expiry, and authority epoch.

The challenge contains no raw descriptor, socket path, executable path, audit
token, serial number, key material, or provider payload.

### Client proof

After verifying the challenge against its enrolled server response key, the
client signs a proof with the exact IPC request key. The proof binds:

- the complete challenge digest;
- the complete signed request digest plus request nonce and sequence;
- request key ID/public-key digest, both principals, and provider ID,
  descriptor, and implementation digests;
- client bundle and launch-attestation digests;
- a fresh proof nonce and deadline.

The request signature and channel-proof signature are independently verified.
Key reuse between request, response, launch, grant, receipt, or descriptor
evidence domains is a provisioning failure. A proof cannot be transplanted to a
second challenge, request, descriptor, process generation, provider, role, or
server identity.

### Admission and response

The server brackets verification with current launch/startup authority and live
native evidence reads. It first reserves a global request claim keyed only by a
domain/version-separated closed tuple of request key ID/public-key digest,
peer/execution principals, provider ID/descriptor/implementation digests, nonce,
and sequence.
The stored claim separately binds the complete signed request digest, request
ID, and operation ID/payload digest. Channel and challenge identity, request ID,
and operation are deliberately excluded from the replay key, so neither an
exact request nor a differently signed request fork can dispatch once per fresh
connection under the same replay identity. This closed identity digest is a
required field in reservation-port and receipt schema v2; v1 records are not
silently reinterpreted. It then
reserves the channel-specific proof tuple
`(descriptor_registration, challenge, request, proof, request_key,
process_start, authority_epoch, global_request_receipt)` before provider
dispatch. Post-reservation authority and descriptor readback are mandatory even
when a reservation reply is malformed or lost.

Trusted logical time is re-read after each potentially delayed durable
reservation and authority readback, after channel I/O, and immediately before
dispatch. Rollback or expiry of the challenge, request, or proof closes without
dispatch. The admitted test port has no caller-supplied callback: its constructor
accepts only a finite fixture-script enum, and the broker executes the selected
deterministic behavior internally. Provider ID, descriptor and implementation
digests, fixture source and script, same-event-loop semantics, lack of independent
preemption and worker-side deadline recheck, and false hardware/production flags
are bound into the challenge, durable claims, dispatch projection, and response.

The same-event-loop timer is only a conformance-fixture liveness backstop. It
cannot preempt the closed 300 ms blocking fixture; an immediate post-dispatch
trusted-time fence instead maps every overrun to ambiguous, non-retryable
`dispatch_timeout`. This is not a hardware authorization boundary. Raw callbacks,
forged ports, provider-binding drift, production claims, and separate-identity
claims reject during configuration normalization before authority reads,
reservation, or effects.

The response binds the challenge and proof digests in addition to the request
digest and both durable reservation receipts. Disconnect or timeout after
durable admission is an ambiguous response, not permission to replay the
operation. The channel is acquired before server configuration normalization
and terminally closed after the single response and every subsequent failure,
including key/configuration rejection. Response transport loss after durable
admission is surfaced as a distinct non-retryable ambiguous outcome.

## Process boundary

Node 20 does not expose an API that proves a `net.Socket` owns the descriptor
being inspected. The native descriptor-registration precursor therefore proves
only the exact duplicate of the supplied descriptor and correctly reports
`descriptor_provenance_complete: false`. Production requires one of:

1. a native acceptor that creates both the Node-facing channel and the
   one-shot descriptor token without a JavaScript descriptor handoff; or
2. a reviewed native IPC service that performs framing, challenge/proof
   verification, and descriptor inspection before emitting a digest-only
   admitted request to the broker.

The native channel source follows option 1: native code owns listener creation,
accept, descriptor registration, and bounded asynchronous framing; JavaScript
receives opaque ports and digest-only evidence. It rejects group- or
other-writable socket roots. Listener shutdown cancels an accept even while its
work is queued behind a saturated shared pool. Accept-operation descriptors are
atomically detached before their sole owner closes them, preventing a stale
numeric descriptor from shutting down an unrelated reused socket. Native I/O
deadlines begin before queue submission, and an event-loop deadline cancels
queued work or shuts down a running operation. This source
implementation does not itself satisfy production custody. The generic broker
cannot safely host a preemptible hardware transport, so no constructible
production dispatch port exists. No JavaScript fallback is permitted for
hardware or `separate_identity`, and the build remains gated on a separately
attested custodian plus the qualification evidence below.

Framing rejects a half-close only when the kernel already exposes the FIN at
the immediate post-request check or the later pre-response check. Tests await
the client's completed local shutdown before reading to exercise that observable
case repeatedly. A FIN that becomes observable only after both checks remains a
future-FIN scheduling window; the terminal one-use close bounds it, but the
implementation does not claim instantaneous detection.

## Acceptance

Engineering qualification requires source-pinned native code, signed immutable
prebuilds, exact loaded-image measurement, root-owned immutable worker bundles,
privileged launch-ticket verification, dedicated principals, durable replay
custody, and stable redacted errors.

HIL must demonstrate request capture/relay, descriptor substitution and reuse,
PID reuse, socket replacement, client/server restart, request-key rotation,
launch drift, authority revocation, reservation-response loss, disconnect, and
deadline faults. Adversarial tests must also prove raw callbacks and forged
production ports are rejected before durable admission, a closed blocking fixture
is post-fenced as ambiguous without hardware claims, and an ambiguously admitted
request cannot replay. Every negative case must reach rejection or quarantine
without hardware dispatch. Until the independently scheduled custodian and this
evidence exist, channel binding remains `production_attested: false` and cannot
enable device access.
