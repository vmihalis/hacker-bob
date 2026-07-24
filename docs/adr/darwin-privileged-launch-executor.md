# ADR: Darwin privileged launch executor boundary

Status: implemented as a source-only pre-exec fixture; production launch is
superseded by `darwin-post-exec-capability-release.md`

## Decision

Bob's Darwin privileged launcher uses a terminal, separately compiled executor
whose projection and child process contract are closed at build time. The
executor accepts no path, argv, environment, descriptor number, UID, or GID from
a command line or environment variable. A future authenticated launcher-context
parser may populate its internal fixed-size context only after verifying the
enrolled authority envelope and executable identity.

The descriptor projection is fixed:

| Launcher source | Child FD | Contract |
| --- | --- | --- |
| 7 | 3 | Distinct anonymous AF_UNIX `SOCK_STREAM`; launcher applies `SHUT_WR`; bounded canonical signed launcher-context receipt |
| 8 | 4 | Sole exact `O_RDWR\|O_NONBLOCK` character-device transport |
| 9 | 5 | Distinct anonymous AF_UNIX `SOCK_STREAM`; launcher applies `SHUT_WR`; one `HBPHDIN1` dispatch frame |
| 10 | 6 | Distinct anonymous AF_UNIX `SOCK_STREAM`; launcher applies `SHUT_RD`; one 196-byte `HBPHDRS1` redacted terminal result |
| 11 | 7 | Empty, single-link, owner-only regular file with exact `O_WRONLY\|O_APPEND`; pre-reserved response-vault sink owned by a UID distinct from the active worker |

Every source starts with exactly `FD_CLOEXEC`. The executor captures and compares
device, inode, special-device, type/mode, link, owner, size, access, status, descriptor,
and socket-type identity fields. It rejects aliases and plan collisions, retains
each source with `F_DUPFD_CLOEXEC`, rechecks identity after direction shutdown,
projects to 3 through 7, clears `FD_CLOEXEC` only on those child descriptors, and
closes all unlisted descriptors including source and retained duplicates. The
terminal inventory must be exactly 0 through 7; 0 through 2 are `/dev/null`.
All five sources are retained before target projection, making the intentional
source-7/target-7 slot reuse independent of the original context descriptor.

The process order is fixed:

1. Validate the source-gated context and collect PID, parent PID, start identity,
   launcher-path digest, and the initial descriptor inventory.
2. Reopen standard descriptors, retain/recheck/project capabilities, close
   unlisted descriptors, and collect the exact child inventory.
3. Change to `/var/empty`.
4. Apply `setgroups`, then `setgid`, then `setuid`.
5. Read back Darwin real, effective, and saved IDs plus the exact supplementary
   group set.
6. Recheck the exact descriptor inventory.
7. Call absolute `execve` with standalone argv
   `[image, "--fixture-native-dispatch-custodian-v1"]` and an empty environment.

Any error closes descriptors and terminates the executor child. No error record
contains authority material, paths, command bytes, or device data.

## Verification strategy

The installed diagnostic fixture remains non-activating and contains no
credential or exec imports. The executor is syntax checked independently with
`HB_PRIVILEGED_LAUNCH_SOURCE_ONLY`; it has no production `main` and is not linked
or installed as an executable.

A temporary `HB_PRIVILEGED_LAUNCH_TEST_ONLY` build replaces only credential and
exec syscalls. Its native selftest uses AF_UNIX socketpairs, a PTY, and a private
temporary vault inode and covers:

- descriptor aliasing and duplicate source/target plans;
- exact device status, type, and access modes;
- exact empty/append-only vault-sink policy, occupied, mode, and alias drift,
  and vault/worker principal separation;
- close failure and injected extra descriptors;
- source descriptor substitution after retention;
- credential-plan drift and credential operation ordering;
- path, argv, and environment injection;
- exec failure and fail-closed descriptor cleanup; and
- before/after descriptor inventories and process provenance fields.

It never enumerates or opens Chameleon hardware, performs a real identity change,
changes ACLs, or writes system configuration.

## Remaining production blockers

This executor source does not authorize activation. Its pre-exec descriptor
projection is retained only as a topology and credential-ordering fixture; it
cannot become the production launcher by adding a pathname pre/post check.
Production uses the powerless-child, live-process-attestation, post-exec
`SCM_RIGHTS`, and one-use GO protocol in
`darwin-post-exec-capability-release.md`. Production remains false
until all of the following are independently complete:

- canonical signed launcher-context wire parsing and current keyring/revocation
  integration;
- a signed standalone native dispatch custodian matching the two-element exec
  argv (the current Node fixture adapter has a different process argv);
- signed launcher and custodian prebuild admission with immutable installation;
- parent-side persistence and signature of PID/start and inventory provenance;
- root credential-drop, negative principal-matrix, descriptor-close, exec-failure,
  and lifecycle HIL; and
- Chameleon-specific DTR/RTS safety qualification and the wider physical-plane
  release gates.

Consequently `production_attested`, `production_ready`, and
`hardware_authorized` remain false, mapped process-image identity remains
unbound, and no canonical installer or runtime can activate this source.
