# ADR: Darwin production-shaped trusted-clock source

- Status: source, fixed local build/loader, and conformance contract complete;
  signed delivery, provisioning, native attestation, and HIL pending
- Date: 2026-07-20
- Applies to: Plane-PH trusted monotonic source and future external clock anchor

## Decision

The Darwin arm64 trusted-clock source is a provider-neutral native service, not
a Chameleon capability and not a Node clock callback. The production shape is a
launchd-managed standalone daemon with a fixed client binding. The checked-in
source package is intentionally unprovisioned and always reports
`production_ready: false`.

The fixed identities are:

- daemon signing identifier and launchd label:
  `io.hacker-bob.physical.trusted-clockd`;
- client signing identifier:
  `io.hacker-bob.physical.trusted-clock-client`;
- dedicated no-login daemon principal: `_hackerbobclock`;
- launchd socket key: `TrustedClockSocket`;
- endpoint: `/private/var/run/hacker-bob/physical-trusted-clock-v1.sock`.

The production-shaped client exposes one sample operation. It has no path,
callback, file descriptor, clock selector, authority root, trust key, enrollment,
readiness override, or fallback argument. The package exposes a portable
conformance verifier and an explicit non-authorizing local native client. Import
is inert; client construction verifies a fixed local build receipt and loads the
addon, while every result preserves `production_ready: false`.

## Native boundary

launchd creates and owns the listener. The daemon receives it with
`launch_activate_socket`; it cannot bind a caller-selected endpoint. A future
installer must prove root-owned no-symlink ancestry, exact socket owner/group and
mode, immutable signed binaries, and a distinct daemon UID before activation.
Before accepting, the daemon requires one `AF_UNIX`/`SOCK_STREAM` accepting
listener whose `getsockname` path is the fixed endpoint. Listener, accepted, and
client descriptors are `FD_CLOEXEC`; connected sockets set `SO_NOSIGPIPE` and
fixed receive/send timeouts, with the client configuring them before `connect`.

Each side obtains the connected peer's `LOCAL_PEERTOKEN`, `LOCAL_PEERPID`, and
`getpeereid` values. PID, UID, GID, and audit-token PID version must agree. The
audit token is passed to
`SecCodeCopyGuestWithAttributes(..., kSecGuestAttributeAudit, ...)`, and the live
guest must satisfy the exact manifest-enrolled `SecRequirement`. Pathnames,
process listings, argv, environment variables, and caller assertions are not
identity inputs. Both client and daemon perform this validation.

RAII cleanup overwrites raw boot UUID, audit token, request/challenge, response,
and derived digest buffers through volatile byte writes on every return path.
Only the bounded daemon replay set retains challenge digests; it retains no raw
challenge or request bytes.

The checked-in requirements contain the impossible team value `UNPROVISIONED`,
all enrolled identity digests are zero, and `HB_CLOCK_SOURCE_PROVISIONED` is
zero. A future signed release must generate a replacement enrollment header and
cover its exact bytes, requirement digests, client/service identities, and
enrollment digest in static and loaded-image attestations. A compiler flag or
runtime configuration is not enrollment.

## Clock and boot epoch

The daemon reads `mach_continuous_time()` and converts ticks to nanoseconds with
`mach_timebase_info`. Unlike `mach_absolute_time`, this primitive advances while
the machine sleeps. Host `CLOCK_REALTIME`, `Date.now`, `process.hrtime`, NTP
status, and the daemon's wall clock are not trusted-time sources.

For every sample the daemon:

1. reads `kern.bootsessionuuid` into a fixed bounded buffer;
2. reads `mach_continuous_time()`;
3. reads `kern.bootsessionuuid` again;
4. rejects the sample unless both bounded byte strings are identical; and
5. hashes the domain, boot-session bytes, service identity digest, and enrollment
   digest into the public monotonic epoch ID.

The raw boot-session UUID is never returned or logged. Restart in the same boot
retains the epoch and continuous counter. Sleep advances the counter. Reboot
changes the epoch; the upper trusted-time layer must reject the old mapping and
require a newly authorized monotonic-to-UTC mapping. No fallback is permitted.

## Closed request/response protocol

One AF_UNIX connection carries exactly one 64-byte request and one 232-byte
response under fixed two-second receive/send timeouts. The client half-closes
its write side after the request and both peers require end-of-stream after the
one frame, so extra, short, malformed, or trailing frames fail closed. Integers
are unsigned big-endian and digests are 32 raw SHA-256 bytes.

The request contains a fixed header, a client-generated 16-byte request ID, and
a client-generated 32-byte challenge. Both are generated internally with
`SecRandomCopyBytes`. The response binds:

- request ID and domain-separated challenge digest;
- `mach_continuous_time` nanoseconds;
- hashed boot epoch;
- enrolled service and client identity digests;
- enrollment digest; and
- a domain-separated digest over every preceding sample field.

The daemon keeps a bounded replay set for accepted challenge digests. The client
accepts only its one outstanding challenge and consumes it on the first response
attempt, including a malformed attempt. A verifier instance binds the first boot
epoch and rejects later epoch drift or monotonic rollback. Reopening a verifier
after a legitimate reboot does not itself authorize the new epoch; that decision
belongs to the durable signed mapping/high-water layer.

Verified conformance samples are frozen, privately branded, non-serializable
in-memory capabilities. JSON, object spread, structured clone, or reconstruction
cannot recreate their brand. They contain digests and bounded counters, never
audit tokens, boot UUIDs, socket descriptors, requirement bytes, keys, or raw
paths beyond the public fixed contract.

## Custody and restart model

This slice supplies neither signer custody nor durable high-water custody.
Production integration must additionally provide:

- an operator-pinned trust root outside project- and caller-owned storage;
- a trusted-clock signing key distinct from every grant, worker, release, vault,
  observer, verifier, and anchor key;
- a non-exportable Secure Enclave or external-HSM key, or another custody design
  that meets the accepted Plane-PH key matrix;
- daemon-owned or independently anchored forward-only compare-and-set state;
- short-lived externally authenticated monotonic-to-UTC mappings; and
- explicit failure on unavailable, stale, rolled-back, revoked, or wrong-epoch
  mappings.

The checked-in C++ client is wrapped by a zero-input, process-local one-shot
Node-API addon. Its fixed loader binds the exact source suite, addon, and service
through a local receipt, measures the addon before and after direct `dlopen`,
then retains the authentic loader and native function only in private closures.
The locked loader and addon CommonJS cache entries expose frozen, null-prototype,
non-callable tombstones, so ordinary post-construction `require()` and
`require.cache` access cannot consume the native one-shot capability. This proves
a locally built source relationship and stable on-disk bytes only. It does not
attest the mapped image, authenticate release provenance, or survive a hostile
same-UID source rewrite.

Captured validation intrinsics reject mutation after the first authentic import,
but this is not same-process capability isolation. Pre-import internal loading,
an alternate copied-addon path or direct `dlopen`, hooks on module/filesystem
machinery, debugger access, process-memory inspection, and arbitrary in-process
code remain unqualified. Production therefore keeps
`trusted_clock_native_client_same_process_capability_custody_not_isolated` as an
explicit blocker and requires an independently signed client process or
equivalently isolated native runtime plus loaded-image attestation.
A production release must cover the wrapper, fixed loader, exact receipt/enrollment
bytes, and loaded-image identity without adding configuration inputs.

The current filesystem-held same-UID monotonic owner and a caller-selected
authority root cannot make this source production-ready. Wiring the source while
retaining either must preserve an explicit blocker.

## Delivery and qualification

Native-prebuild manifest v2 has an exact six-component role set. This source
does not modify or extend v2. Signed delivery must use either a domain-separated
v3/profile with `trusted_clock_client` and `trusted_clock_service` roles or a
separate trusted-clock release envelope. It must cover release signature,
Developer ID and notarization policy, exact designated requirements, immutable
installation, loaded-image identity, principal/ACL policy, enrollment bytes,
signer custody, and evidence freshness.

The package allowlist is source-only and excluded from the canonical Hacker Bob
tarball. An explicit developer build creates an ignored addon, standalone daemon,
and local non-authorizing receipt under `build/Release`; none is packaged. The
source tree contains no `.node`, executable, launchd plist, credential, private
key, production enrollment, installer, or daemon activation command. Fixed
prebuild slots remain disabled and fail closed until the separate signed release
verifier and trust root exist.

Production remains blocked until operator-run Darwin HIL proves at least:

- fake socket, wrong UID/GID, wrong/ad-hoc code, PID reuse, socket replacement,
  malformed/trailing frames, replay, timeout, and crash fail closed;
- agent/MCP/worker principals cannot read the key or state, replace the service,
  or forge samples;
- launchd and Bob restart retain same-boot continuity;
- sleep/wake advances the continuous counter;
- reboot changes epoch and rejects the old mapping;
- wall-clock rollback does not alter the source and cannot bypass mapping/high-
  water checks; and
- key, requirement, enrollment, mapping, trust epoch, and revocation rotation
  invalidate old authority.

Until signed immutable native attestation, principal provisioning, signer and
anchor custody, and that HIL evidence exist, the fixed blocker is
`signed_immutable_trusted_clock_native_attestation_and_provisioning_missing`.
