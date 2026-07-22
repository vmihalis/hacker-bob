# Hacker Bob Darwin native boundary

This optional, provider-neutral package contains kernel-facing primitives used
by privilege-separated instrument workers on macOS. It is intentionally not a
dependency of Hacker Bob core, has no install script, performs no discovery or
device I/O on import, and is excluded from the canonical root package.
`gypfile: false` suppresses npm's implicit install-time `node-gyp rebuild`;
native compilation is an explicit operator/developer action. The package is
source-only: its allowlist carries `binding.gyp`, native source, JavaScript, and
documentation, never a `.node` binary or build tree. Run `npm run build`
explicitly in a trusted checkout. A binary distribution remains a separate,
future release problem.

The first slice inspects one explicitly supplied, registered Unix-domain stream
descriptor. It does not accept or claim identity for a JavaScript `net.Socket`.
Registration immediately duplicates the supplied descriptor with
`F_DUPFD_CLOEXEC`, requires a connected `AF_UNIX` plus `SOCK_STREAM` endpoint,
and returns a frozen, native type-tagged token. Inspection atomically removes
the native wrap, adopts the duplicate, and closes it on success or every later
failure. The token is one-use; an abandoned token closes its duplicate in its
native finalizer. A Security.framework random secret and the descriptor's peer
audit token produce a domain-separated registration-token digest. That digest
is non-secret evidence, exposed as non-enumerable token metadata and in the
projection; the random input, descriptor number, and native wrap remain hidden.
The addon then reads
`LOCAL_PEERTOKEN` and cross-checks its
UID, GID, and PID against both `getpeereid` and `LOCAL_PEERPID`. It binds the
audit-token PID version to a before/after `PROC_PIDTBSDINFO` process-start tuple
and obtains the executable path through `proc_pidpath_audittoken`; only a
domain-separated path digest leaves native code.

Between those two kernel snapshots, the addon passes the registered descriptor's
peer audit token as `CFData` under `kSecGuestAttributeAudit` to
`SecCodeCopyGuestWithAttributes`. It never reconstructs this lookup from a
fresh PID. The resulting dynamic `SecCode` is validated before, between, and
after two signing-information reads. The two reads must agree exactly. The
closed projection includes the selected CodeDirectory hash (CDHash), digest
algorithm, signature class, certificate count, and presence states. Signing
identifier, team identifier, all CodeDirectory hashes, certificate chain,
designated requirement, static flags, and dynamic status leave native code only
as domain-separated SHA-256 digests. Ad-hoc and teamless signatures are labeled
explicitly and do not claim a complete signer identity.

This is a complete, audit-token-bound dynamic code-identity measurement only
under the stated Security.framework scheme. `SecCodeCheckValidity` uses
`kSecCSDefaultFlags`: it establishes default dynamic validity, not strict
validation, all-architectures validation, trust-policy qualification, or a
signer allowlist decision. The identity is not an executable-byte hash. The
projection therefore marks path measurement complete while keeping executable
byte measurement unavailable and incomplete. The JavaScript port hides the
native token in branded local state, consumes each registration once, and emits
no descriptor number, socket path, executable path, signing identifier, team
identifier, certificate, or requirement bytes. Its evidence scope is exactly
the native duplicate of the descriptor value supplied at registration. It does
not establish which JavaScript object, accept event, or request produced that
number. If mutable JavaScript socket internals cause the caller to supply a
different descriptor, the evidence reports that different registered
descriptor and never labels it as the original socket.

The second slice is a worker self-identity measurement and performs no broker
activation or device operation. Its zero-argument native primitive obtains the
current task's audit token with `task_info(TASK_AUDIT_TOKEN)`. It cross-checks
the token's effective and real UID/GID, PID, PID version, process-start tuple,
and audit-token-resolved executable path against the current process and
`PROC_PIDTBSDINFO`; no PID, path, or process claim is supplied by JavaScript.
The audit-token guest identity is measured under separate self-specific digest
domains and must exactly match a separately resolved `SecCodeCopySelf` identity.
Only scoped identifiers, presence states, CDHash metadata, and digests leave
native code. Audit-token and path bytes do not.

The private JavaScript self port is inert on import and one-shot. It places a
non-configurable process-local mark before native inspection, so deleting and
reloading the CommonJS module cannot authorize a second policy inspection.
The raw N-API function remains deliberately repeatable for conformance, so this
is not a cross-isolate or hostile-in-process one-shot guarantee; that limitation
is an explicit production blocker. A self snapshot binds the stable signing
identity to the audit token, PID version, process start, on-disk addon digest,
and adapter identifier under a distinct snapshot domain.

The third slice binds the native callback that performs this work to the addon
image actually mapped by dyld. `dladdr` must resolve the callback into exactly
one dyld header; the dyld image count, header, slide, and canonical image name
must remain stable across measurement, and the dyld and `dladdr` paths must
canonicalize identically. The addon opens that path with `O_NOFOLLOW`, requires
a stable single-link regular file without group/world write permission, and
hashes the complete file. Its mapped Mach-O header and load commands must equal
the file bytes, including one `LC_UUID`. Every executable segment must have no
zero-fill tail (`vmsize == filesize`), occupy read/execute and non-writable VM
regions, contain the attestation callback, and equal its corresponding file
bytes exactly. The native whole-file SHA-256 must equal JavaScript's before/after
direct-`dlopen` file measurement. Paths and addresses leave the boundary only
as domain-separated digests; a single aggregate loaded-image identity digest is
included in peer and self projections.

This proves the origin and current bytes of the addon's executable mapping under
the stated scheme. It does not normalize or attest dyld-rebased, bound, lazy,
or writable non-executable runtime state, and it does not establish signed or
immutable delivery. Those limitations remain explicit false fields and
production blockers.

The fourth slice implements that handoff as an opaque native Unix listener and
accepted-connection state machine. Native code creates, binds, and accepts the
socket, duplicates the accepted descriptor for one-shot registration, and
finishes registration before JavaScript receives a digest-only connection port.
No descriptor number, native token, socket path, `net.Socket`, or `_handle`
crosses that port. The socket root must be canonical, owned by the effective
user, and not group- or other-writable. An opened root descriptor brackets bind;
device, inode, mode, owner, group, and the filesystem-appropriate link-count
change must remain consistent, and the bound socket must resolve to the same
inode through both the held root and canonical path. Closing a listener cancels
its registered native async work before it starts or wakes a running accept.
The accept-operation descriptor is atomically detached from the shutdown slot
before its sole owner closes it, so descriptor-number reuse cannot redirect a
later shutdown onto an unrelated socket.

Native asynchronous I/O enforces one challenge frame, one request-and-proof
frame, and one response frame in that order. Challenge bytes are written before
request bytes can be read. Each deadline is captured before shared-pool queue
submission. A native event-loop timer cancels work that is still queued and
shuts down work that has started, while the worker independently checks the same
absolute steady-clock deadline. Timeout, coalesced extra input, phase misuse,
or a half-close already observable at the immediate post-request or later
pre-response check rejects and closes the connection. Repeated tests await the
client's completed local shutdown before reading and establish that observable
half-close case without sleeps. A FIN that becomes observable only after both
checks remains a future-FIN scheduling window; instantaneous detection is not
claimed. Pool-saturation regressions cover queued read, queued response write,
and queued accept cancellation; the response-write test also proves no bytes
appear after expiry. A second frame that arrives after the reader's immediate
extra-input check has the analogous window; response writing checks again, and
the broker terminally closes the one-use connection after every response or
failure. HIL must still qualify these remaining scheduling windows.

`@hacker-bob/instrument-broker` now supplies the signed two-flight channel
contract. The response-key challenge binds listener and descriptor identity,
peer credentials and mapped code, immutable-launch evidence, authority, the
expected request key, principals, provider, expiry, and durable reservation
readback. The request key independently signs both the complete request and a
proof over the complete challenge and request digests. A fresh reservation
attempt nonce makes a pre-existing durable record a replay while still allowing
exact readback after a lost reserve response. A separate global reservation is
keyed by a closed domain/version-separated tuple of request key, principals,
provider, nonce, and sequence. Its stored claim binds the full signed request
digest, request ID, and operation, so neither an exact request nor a
differently signed fork under the same replay identity can use a fresh channel.
The required identity digest and receipt are reservation schema/domain v2; v1
durable records fail closed rather than being reinterpreted. Authority,
descriptor identity, and trusted logical time are re-read after each
reservation, with one last deadline fence immediately before dispatch.
The currently constructible broker dispatch port is branded for
`deterministic_mock`, has no caller-supplied function, and accepts only a closed
finite fixture-script enum. Provider ID, descriptor and implementation digests,
fixture source and script, cooperative same-event-loop deadline semantics, and
false separate-identity, independent-preemption, worker-recheck, hardware, and
production flags are signed into the transcript. Its timer is a fixture liveness
backstop, not a preemptible authorization boundary; a closed blocking fixture is
mapped by the post-dispatch trusted-time fence to non-retryable
`dispatch_timeout`. Raw callbacks and forged production ports reject before
authority reads or durable reservation.
The signed response binds challenge, proof, request, both reservation receipts,
authority, and descriptor readback. Transport loss or dispatch timeout after
durable admission produces a distinct non-retryable ambiguous outcome, and the
channel is acquired before configuration normalization so every genuine-port
failure terminally closes it. The older one-message IPC v1 surface remains
mock/conformance-only and cannot authorize hardware.

Security.framework's selected CDHash is modeled explicitly as a 20-byte value,
not as a full SHA-256 artifact digest. Its supported algorithm identifier is
signed beside it, while `peer_code_directory_hashes_digest` separately binds the
complete candidate CDHash set returned by Security.framework. The selected
CDHash must never be treated as collision-equivalent to executable-byte or full
CodeDirectory measurement. The peer executable path digest likewise does not
claim a byte-for-byte measurement of executable pages; the loaded-image proof
applies only to this native addon.

This source slice has real native end-to-end tests over temporary local Unix
sockets, but remains non-production. Signed immutable native prebuilds,
privileged launcher custody, root-owned immutable worker bundles, a qualified
external durable reservation store, dedicated principals, device ACLs,
launch-ticket verification, policy allowlists, safety-supervisor activation,
an independently scheduled worker/process/native dispatch custodian with a
trusted worker-side deadline recheck immediately before effects, and full
negative HIL are still required. No production, hardware-authorized, or
separate-identity dispatch port is currently constructible. Accordingly every projection keeps
`production_ready: false` and `production_attested: false`. Tests never enumerate
or open hardware. Raw legacy descriptor registration remains conformance-only;
its tokens are one-use but a source descriptor can be registered again. Raw
self-inspection and loaded-image primitives also remain repeatable for
conformance, with self one-shot policy enforced only by the private JavaScript
port.
