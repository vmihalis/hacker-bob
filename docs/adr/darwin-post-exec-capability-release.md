# ADR: Darwin post-exec attestation and capability release

Status: accepted architecture; source implementation and production qualification pending

## Context

Darwin exposes pathname-based `execve` and `posix_spawn`, but no supported
`fexecve`, `execveat`, or `AT_EMPTY_PATH` equivalent that executes the exact
regular-file descriptor retained during static admission. Verifying a helper
pathname before and after `execve` therefore cannot prove that the admitted
file is the image the kernel executed.

The source-only privileged launcher currently projects target/device
capabilities into child descriptors before pathname `execve`. That fixture is
useful for validating descriptor topology and credential-drop ordering, but it
is not a production launch design: a substituted executable could inherit the
capabilities before Bob had bound the live process to the enrolled component.

This decision applies to every delegated native effect, including the
descriptor-relative lifecycle custodian and the native physical-dispatch
custodian. It does not authorize hardware or package mutation.

## Decision

Pathname execution is permitted only while the child is powerless. A trusted
supervisor releases target, source, request, result, device, or dispatch
descriptors only after it has attested the live post-`exec` process and bound
the mapped executable to the retained signed artifact.

The supervisor remains resident and owns the launch state machine. A child is
never treated as the authority merely because it was forked by the supervisor,
connected to the expected socket, supplied the launch nonce, or ran under the
expected UID.

## Closed launch protocol

1. The supervisor resolves a fixed enrolled helper beneath an immutable,
   root-owned install root with a no-symlink descriptor walk. It retains the
   artifact FD and verifies release-manifest identity, complete SHA-256,
   filesystem identity and mode, link count, Mach-O structure and dependencies,
   static signature, selected CDHash, designated requirement, entitlements,
   launch role, and principal-policy digest.
2. It creates a root-controlled, single-launch AF_UNIX listener and a random
   launch nonce. A bounded inherited bootstrap channel may convey only that
   non-authorizing endpoint and nonce; it cannot carry any effect capability.
3. The fork child closes every unlisted descriptor, changes to `/var/empty`,
   applies `setgroups -> setgid -> setuid`, reads credentials back, and uses an
   empty environment. It inherits no target, source, request, result, device,
   dispatch, grant, receipt, or signing-key descriptor. It then pathname-execs
   the fixed helper.
4. The post-`exec` helper opens a fresh connection to the listener. An inherited
   connected socket is not evidence of the post-`exec` peer image.
5. The supervisor binds the connection to the direct child with kernel-origin
   evidence: `LOCAL_PEERTOKEN`, `LOCAL_PEERPID`, `getpeereid`, audit-token
   UID/GID/PID/PID-version, `PROC_PIDTBSDINFO` start identity, and
   `proc_pidpath_audittoken`. PID, PID-version, start identity, principal,
   listener generation, and launch nonce must all match.
6. It creates a live `SecCodeRef` with
   `SecCodeCopyGuestWithAttributes(..., kSecGuestAttributeAudit, ...)`, loads the
   exact signed `SecRequirement` bytes, and calls `SecCodeCheckValidity` with
   kernel guest-requirement matching. It double-reads and matches the selected
   CDHash, ordered candidate-CDHash-set digest, team/signing identity,
   designated requirement, code flags, entitlements, dynamic status, and
   architecture against the manifest.
7. Only after the kernel identity gate passes may the supervisor send the
   retained executable FD. The helper's enrolled measurement routine compares
   the complete retained-file digest, Mach-O type/UUID/load commands, and every
   executable segment against its live `MH_EXECUTE` mappings. The measurement
   callback must itself reside in a measured executable segment, and retained
   FD identity is checked before and after. A pathname reopen is not accepted.
8. The supervisor repeats live process, trust, revocation, authority, and
   deadline reads, then durably reserves the exact capability-set digest and
   one-use grant sequence.
9. One `SCM_RIGHTS` message transfers the closed capability set. Both sides
   reject truncation, extra control records, wrong descriptor count/order/type,
   status or access drift, aliases, and unexpected descriptors. The receiver
   reapplies `FD_CLOEXEC`, remaps only the closed ABI roles, and closes all
   other copies. Transfer never preserves descriptor flags implicitly.
10. The child validates the received capabilities and returns
    `READY_NO_EFFECT`. The supervisor refreshes live identity, trust,
    revocation, authority, resource fences, and time again, durably records the
    GO sequence, and sends a domain-bound, one-use `COMMIT_GO`. No mutation or
    device write is legal before GO. The child immediately repeats its local
    pre-effect checks before the first effect.
11. The supervisor and child produce authenticated terminal/outbox records
    binding the release and component manifest, retained artifact, live audit
    token and process identity, mapped measurement, principal, launch nonce and
    generation, authority/revocation/resource epochs, capability-set digest,
    grant and GO sequences, deadlines, exact result, and cleanup/quarantine
    state.

The lifecycle and physical-dispatch custodians must be refactored to receive
their fixed descriptor ABI after `exec`; their existing source fixtures that
inherit descriptors at process creation cannot be promoted to production.

## Failure and replay semantics

- Before capability transfer, every failure is `rejected_no_effect`.
- After transfer but before GO, `rejected_no_effect` is allowed only after the
  exact audit-token-bound child exits and durable state proves GO was never
  issued. Otherwise the attempt is ambiguous and quarantined.
- After GO, a missing or malformed terminal receipt is
  `ambiguous_quarantined`, never an automatic retry.
- A grant nonce, capability generation, or GO sequence is single-use and
  consumed durably. Restart recovery reconciles the authenticated supervisor
  journal and child outbox before another grant can issue.
- Revocation before GO terminates without effect. Revocation after GO fences
  the transport/resource and produces an ambiguous result until cleanup or
  quarantine is independently evidenced.
- Signalling and termination use audit-token-bound process operations followed
  by `waitpid`; a bare recycled PID is not a process authority.

A byte-for-byte, signature-identical copy that satisfies the exact live
requirement and mapped-image measurement is equivalent to the enrolled release
artifact. A different signer, CDHash, requirement, entitlement set, mapped
image, principal, process generation, or artifact never receives effect
descriptors.

## Release manifest and trust requirements

Native release manifest v2 retains the existing native IPC, CDC custody,
safety watchdog, and privileged launcher roles and adds at least
`lifecycle_custodian` and `native_dispatch_custodian`.

Each executable record binds:

- selected SHA-256 CodeDirectory CDHash and ordered candidate-set digest;
- bounded serialized `SecRequirement` bytes and digest;
- required and forbidden code-signature flags and entitlements digest;
- Mach-O file type, CPU subtype, UUID, deployment target, and dependency policy;
- launch role, execution-principal policy, and mapped-image measurement scheme;
- capability-protocol ABI digest and exact descriptor role/count/type/status/
  access table.

Global policy binds the supervisor component, the
`post_exec_audittoken_seccode_scm_rights_v1` handshake, retained-FD image
measurement, PID/start/principal pairing, bounded HELLO/attestation/grant/READY/
GO/result ages, nonce and generation rules, durable grant/GO/receipt/outbox
policy, termination semantics, and ambiguous-result policy.

Production keyring and revocation state are root-owned and external to project
files and caller-supplied JavaScript. They use forward-only signed transitions,
monotonic trust epochs, bounded freshness, and distinct key usages for release,
grant, dispatch, receipt, and HIL evidence. Revocation can target key material,
release ID, manifest digest, component/CDHash, or authority generation. No
private key or production trust root ships in Bob packages or fixtures.

## Qualification and limits

Source tests must cover opened-A/executed-B swaps, post-`exec` swaps, copies and
hardlinks, wrong signer/CDHash/requirement/entitlements, PID/principal/start
drift, listener hijack, nonce replay, malformed ancillary data, missing
`FD_CLOEXEC`, descriptor aliases, deadline/revocation drift, and crashes at
every transfer, READY, GO, result, and recovery boundary.

Production additionally requires immutable signed installation, dedicated
no-login principals, negative target/device pathname-access matrices, exclusive
journal/outbox ownership or authenticated records, Developer ID/notarization,
credential-drop HIL, and the relevant physical-plane gates.

This protocol closes delegated Bob effects. It does not by itself prove that an
otherwise attested child lacks unrelated ambient filesystem or network access;
that stronger claim requires a qualified sandbox or equivalent OS policy.
Until the native supervisor, manifest v2, immutable keyring, principals, ACLs,
authenticated state, and HIL evidence all exist, `production_attested`,
`production_ready`, `hardware_access_authorized`, and lifecycle mutation remain
false.
