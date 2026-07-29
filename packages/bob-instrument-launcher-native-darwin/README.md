# Hacker Bob Darwin privileged-launcher boundary

This private package contains four deliberately separate production-false
surfaces.

- Importing the CommonJS modules is inert. It performs no filesystem access,
  native loading, descriptor inspection, identity change, process creation, or
  hardware operation, and exposes no launch or exec function.
- Explicitly invoking `bob-darwin-launcher-fixture` starts a terminal,
  non-activating verifier. Its only accepted CLI is
  `--verify-fixture --root ABSOLUTE --manifest-sha256 HEX --report-fd 3`, with
  an empty environment and non-root real/effective UID. It never changes
  credentials or calls an exec primitive.
- `native/darwin-privileged-launch-executor.source.c` is a separately compiled,
  source-gated executor core. It is not linked into the diagnostic fixture,
  installed as a binary, exported to JavaScript, or reachable through a CLI.
- `native/darwin-post-exec-capability-release.source.c` is a separate
  source/test-gated supervisor-and-child protocol fixture. It is not linked,
  installed as a binary, exported, or reachable from the diagnostic CLI. Its
  source build refuses every production release; its test build exists only in
  a temporary test directory.

The verifier retains descriptors and exact identities for `/`, every absolute
root-ancestry component, the root, all eight bundle entries/directories, and
the manifest. It uses `fstatat(AT_SYMLINK_NOFOLLOW)`, `openat(O_NOFOLLOW)`, and
pre/open/post identity comparisons. It performs two complete retained-FD
content-hash and identity passes, repeats exact directory enumeration, reopens
every bundle path to compare it with the retained object, rehashes the retained
and current manifest objects, terminally rewalks the entire absolute ancestry,
and finally restats every held descriptor. It then closes all unlisted
descriptors, reopens standard input/output/error to `/dev/null`, writes one
digest-only JSON object to descriptor 3, and exits.

These brackets detect the tested mutations, but a user-writable fixture is not
production immutability. A production launch path still requires independently
qualified root-owned immutable ancestry and bundle objects. Darwin provides no
`fexecve`/`execveat` equivalent here, so a later pathname `execve` cannot be
claimed as bound to these retained descriptors. Fixture mode therefore has no
activation path.

## Contract record, not provenance

The emitted v2 object is a
`darwin_native_launcher_fixture_contract_record`. Its plan, worker, native
evidence, path, argv, environment, descriptor-set, and credential-plan values
are explicitly named `declared_*` digests. The public record parser verifies
exact shape and a domain-separated unkeyed checksum; any caller can fabricate a
self-consistent object. `bindDarwinNativeFixtureContractConsistency` requires a
private verified launch-plan brand and checks declared digest consistency, but
does **not** authenticate a child process, PID/start identity, exit status,
report channel, or native record provenance.

`native_launcher_on_disk_path_object_sha256` is exactly a bracketed SHA-256 of
the regular file currently reached through the process executable pathname. It
is not a measurement of the mapped process image. Every record and consistency
result therefore publishes
`native_launcher_mapped_process_image_identity_bound: false` and
`native_fixture_record_provenance_attested: false`.

The deterministic late-mutation tests compile a separate temporary binary with
the unmistakable `HB_TEST_ONLY_PHASE_BARRIER` guard. That binary is deleted
after the test. The production build explicitly undefines the guard, and build
and binary gates reject any test-hook marker or symbol in the shipped Mach-O.
The shipped binary also has an exact pinned undefined-symbol allowlist and only
exports the Mach-O header plus `main`.

## Source-only post-exec capability release

The post-exec fixture implements the accepted powerless-child architecture
without changing the inherited-FD executor fixture. Its test supervisor creates
a mode-0700 single-launch AF_UNIX listener and a 256-bit nonce, forks a child,
closes every child descriptor above standard I/O, changes to `/var/empty`, and
pathname-execs the test image with an empty environment. The new image must
open a fresh connection; an inherited connected socket is deliberately tested
and is never admitted as post-exec evidence.

The wrong-peer selftest removes listener scheduling from the assertion: it
connects and accepts the live impostor before the direct child is created, then
admits the hostile disposition only when the kernel peer identity and HELLO
both name that exact impostor PID and not the subsequently created direct child.

The supervisor binds the accepted connection twice with kernel-origin
`LOCAL_PEERTOKEN`, `LOCAL_PEERPID`, `getpeereid`, PID-version,
`PROC_PIDTBSDINFO` parent/start identity, and `proc_pidpath_audittoken`. The
direct child PID, direct parent, real/effective principal, executable path,
launch nonce, and listener generation must match. The test-only mechanics gate
then transfers four temporary capability surrogates in exactly one
`SCM_RIGHTS` record. A role-table ABI digest binds count, fixed remap FDs,
descriptor type, exact `O_ACCMODE`, a public Darwin status-flag mask, and the
required `FD_CLOEXEC` mask/value. The receiver requires exactly one
`SCM_RIGHTS` control record whose own payload is exactly four descriptors; it
rejects split control records even when their aggregate count is four,
oversized or out-of-bounds control lengths, ancillary truncation, extra
descriptors, aliases, order/type/access drift, missing `FD_CLOEXEC`, and
unexpected FDs. Control-base/end bounds are proven before any
`cmsg_len`-derived access. It reapplies close-on-exec, remaps only FDs 4 through
7, and proves the terminal inventory is exactly FDs 0 through 7.

No simulated effect is accepted before `READY_NO_EFFECT` and a fresh one-use
`COMMIT_GO`; the unsigned 64-bit GO sequence is strictly greater than the grant
sequence. The native selftest covers inherited connected sockets, wrong
peer/nonce/generation, descriptor and ancillary attacks, replayed grant and GO,
pre-GO effect, and crashes after HELLO, grant, READY, GO, and effect. Only
temporary regular files and a socketpair effect surrogate are used. No serial,
USB, NFC/RFID, Chameleon, hotel, network, camera, credential, or system-policy
surface is opened or enumerated.

After RESULT, the supervisor repeats the complete kernel peer identity read and
requires equality with the admitted PID/PID-version, direct-parent, principal,
start identity, audit token, and executable path before returning a terminal
ACK. The child remains alive until that ACK. A buffered RESULT followed by a
closed or exited peer is ambiguous and never accepted as terminal success; the
selftest includes a crash immediately after RESULT.

This fixture is not live-process attestation. Production functions for exact
`SecCodeCopyGuestWithAttributes`/`SecCodeCheckValidity` requirement checking,
retained-FD-to-live-`MH_EXECUTE` measurement, and authenticated durable
grant/GO/receipt/outbox state are explicit fail-closed source stubs. The test
transcript is nonce-bound but unauthenticated, uses in-memory one-use state, and
does not qualify termination or sandbox policy. It always reports
`security_framework_attested`, `mapped_image_bound`,
`durable_state_authenticated`, `production_attested`, `production_ready`, and
`hardware_access_authorized` as false.

## Source-only privileged executor

`native/darwin-privileged-launch-executor.source.c` replaces the former audit
stub with a closed projection primitive. The only source descriptors are 7
through 11 and the only child descriptors are 3 through 7. It retains and
rechecks every source identity, rejects descriptor aliases, projects through
`F_DUPFD_CLOEXEC`, makes descriptor 3 and 5 receive-only and descriptor 6
send-only, and requires descriptor 4 to be the sole exact
`O_RDWR|O_NONBLOCK` character device. Descriptor 7 is the sole pre-reserved
vault response sink: an empty, single-link, owner-only regular file with exact
`O_WRONLY|O_APPEND` authority whose owning UID cannot equal the active worker
UID. All five sources are retained before the fixed
target projection, so the intentional source-7/target-7 slot reuse cannot
replace an unretained capability. It closes every unlisted descriptor,
including launcher duplicates, and proves the terminal inventory is exactly
0 through 7. The result socket contract is the custodian's 196-byte terminal
record; raw provider bytes travel only through the independent vault sink.

After projection it uses a fixed working directory, applies
`setgroups` -> `setgid` -> `setuid`, reads back Darwin real/effective/saved IDs
and the exact supplementary group set, and calls absolute `execve` with the
standalone child argv `[image, "--fixture-native-dispatch-custodian-v1"]` and
an empty environment. The in-memory evidence includes PID, parent PID, process
start identity, launcher pathname digest, and before/after descriptor inventory
digests. Every failure closes descriptors and exits terminally in the
source-only production build.

This is deliberately an executor primitive, not an authority parser or release
artifact. The currently tested Chameleon custodian uses Node 20 with a
three-element process argv before reducing it to the exact two-element semantic
argv inside its entry module. That adapter is not accepted by this standalone
executor contract. A signed standalone custodian prebuild, canonical signed
launcher-context parser/keyring, immutable installation, parent-side provenance
persistence, and root HIL are still required before activation.

The `HB_PRIVILEGED_LAUNCH_TEST_ONLY` build replaces only credential-changing and
exec syscalls. Its nineteen hostile selftests use local AF_UNIX socketpairs, a
PTY, and a private temporary vault inode to exercise aliasing, duplicate
source/target plans, exact flag/type/access policy, occupied or overbroad vault
sinks, vault/worker principal aliasing, close failure, source substitution,
credential drift, extra descriptor
injection, argv/environment rejection, exec failure, and descriptor inventory.
It never opens or enumerates Chameleon hardware and never mutates real users,
groups, ACLs, or system files. The shipped diagnostic Mach-O still imports no
credential-changing or exec symbol.

Every result remains `production_attested: false` and
`production_ready: false`. Native fixture blockers are:

- `adhoc_native_signature_not_production_qualified`
- `root_owned_immutable_install_not_qualified`
- `real_credential_drop_readback_hil_missing`
- `negative_principal_matrix_hil_missing`
- `capability_fd_projection_not_linked_into_fixture`
- `privileged_launch_wire_authority_verifier_not_integrated`
- `privileged_launch_provenance_persistence_not_integrated`
- `standalone_native_dispatch_custodian_prebuild_missing`
- `node_fixture_adapter_argv_not_executor_contract`
- `production_executor_not_linked`
- `fixture_mode_execve_disabled`
- `root_owned_immutable_ancestry_hil_missing`
- `darwin_fd_bound_exec_unavailable`
- `post_exec_security_framework_live_guest_attestation_stubbed`
- `post_exec_retained_fd_mapped_image_measurement_stubbed`
- `post_exec_durable_grant_go_receipt_outbox_stubbed`
- `post_exec_transcript_authentication_missing`
- `post_exec_production_termination_qualification_missing`
- `native_launcher_mapped_process_image_identity_unbound`
- `native_fixture_record_provenance_unattested`
- `writable_fixture_bracketing_not_production_immutability`

The wider JavaScript contract additionally remains blocked on canonical broker
co-install packaging and production HIL. This package is not registered in
Bob's MCP, provider, canonical installer, or model-facing surfaces. Building
and testing require Darwin arm64, Node 20, the macOS SDK, and Apple's `clang`
and `codesign`; the generated binary is ad-hoc signed for local fixture testing
only.
