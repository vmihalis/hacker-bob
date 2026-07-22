# ADR: Darwin native safety custody and process isolation

- Status: accepted for the fixture precursor; production remains disabled
- Date: 2026-07-19
- Applies to: `@hacker-bob/instrument-safety-native-darwin`

## Context

A successful pipe write does not prove that an independent deadman accepted a
deadline. Likewise, a PID or process-group number is not durable authority to
signal a child after it may have exited and been reaped. Finally, a cleanup
custodian in the same process group as its launcher, watcher, or active worker
dies under the same group termination event it is meant to recover from.

The package is fixture-only and has no hardware provider, but its precursor
contract must still fail closed before later provider work can rely on it.

## Decision

The watchdog forks a custodian before startup effects. `CUSTODY_READY1` proves
only that the custodian registered its initial parent/control/timer custody. It
does not admit a controller. The watcher next sends `CUSTODY_ARM1` and waits for
an evidence-key-HMAC `CUSTODY_ARMED1` bound to sequence zero, the exact contract
and action digests, nonce, startup deadline, runtime deadline, instrument,
lease, fence, worker, cleanup, restore, watcher identity, and custodian
identity. `READY1` is emitted only after native verification and carries the
complete acceptance. JavaScript treats READY as phase one: it verifies the ARM
acceptance, sends private heartbeat sequence one without extending the signed
ARM deadline, and returns a controller only after native and JavaScript verify
the matching `CUSTODY_EXTENDED1`. Operator-visible protocol commands therefore
begin at sequence two.

The same rule applies to extension. Each `heartbeat()` returns a promise. The
promise resolves only after native and JavaScript verification of
`CUSTODY_EXTENDED1` for the exact next sequence and deadline. Queuing bytes on a
pipe is never reported as acceptance. Late, expired, forged, replayed, and
reordered acknowledgments trigger or preserve cleanup and cannot revive a
prior deadline.

Host delivery is part of acceptance. JavaScript records monotonic host send and
receive timestamps for every heartbeat. Signed custodian `acceptedAt` plus the
full host round trip is a conservative native-now upper bound; acceptance
requires that upper bound to be strictly earlier than signed `validUntil`.
Every valid ACK refreshes separate native lower and conservative upper clock
anchors and the active signed custody deadline. JavaScript rechecks that active
deadline after the private-ready await continuation, immediately before
controller delivery, twice around public heartbeat construction, and before
stop or fixture-close admission. Expiry invalidates the controller and requests
native cleanup without replacing independently valid terminal evidence. The
outer supervisor maps signed absolute `validUntil` through the upper anchor and
adds only the cleanup deadline plus last-resort kill margin; delayed host
delivery never starts a fresh deadman interval. Before confirmation establishes
an upper anchor, phase-one READY starts only a cleanup-timeout-plus-kill
fallback and cannot make custody caller-visible.

JavaScript spawns the watcher detached from the launcher group. The custodian
and cleanup worker each call `setsid()` before other work, producing three
separate session/process-group kill domains. Authenticated custody and terminal
evidence binds each process start identity, PGID, SID, and a framed group
identity digest. Cleanup therefore remains outside watcher and active-worker
group termination.

Every direct child has one lifecycle owner. Before a signal, that owner:

1. calls `waitpid(child, WNOHANG)` and stops on reap or `ECHILD`;
2. revalidates the recorded Darwin process-start identity, PGID, SID, and group
   digest;
3. signals the verified child group at most once; and
4. drives blocking `waitpid` through `EINTR` to definite reap or `ECHILD`.

A terminal lifecycle cannot signal again. The pre-signal direct-child proof
prevents PID/PGID reuse from turning stale evidence into a new kill target, and
group signaling covers descendants of the cleanup fixture.

## Evidence and tests

The native selftest covers already-reaped and synthetic stale/ECHILD targets,
repeated cleanup, and descendant-group termination. Package tests cover
delayed, expired, forged, pipe-only, late, replayed, and reordered custody
acknowledgments; READY delivery delayed beyond ARM; ACK delivery delayed beyond
EXTEND; expiry after ACK parsing but before the launch continuation; refusal of
a second controller admission after expiry; and cleanup survival after watcher-
group and active-worker-group termination. The injected post-handoff stall uses
three strictly ordered fixture-only boundaries—cleanup-child self-deadline,
custodian observation/exit, then watcher terminal deadline—so the test proves
the child timed itself out before the parent failure while leaving deterministic
time for the watcher to emit its fail-closed terminal path. Tests use local
inert processes and temporary files only.

## Consequences and remaining boundary

This closes fixture protocol and child-lifecycle ambiguity. It does not enable
production or hardware access. Fixture HMAC is not an independent production
signature authority; dedicated principals, immutable signed prebuilds, atomic
spawn/exec identity, durable external evidence, real cleanup provider, device
HIL, and an external RF witness remain required. Battery-powered RF state is
still `unknown`, and every terminal state remains quarantined.
