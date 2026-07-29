# Darwin safety deadman precursor

This private optional package is a provider-neutral Phase-4 precursor for an
independent Hacker Bob instrument deadman and cleanup-only worker. It is not an
MCP server, is not wired into Bob's agent surfaces, and has no provider,
hardware-enumeration, device-open, vault, administration, destruction, or
agent-to-cleanup IPC capability.

The only active implementation is an explicitly gated non-production fixture.
Import, plan construction, digest derivation, and the production launch path do
not enumerate or open hardware. `launchDarwinSafetyDeadman` always rejects with
`darwin_safety_deadman_real_launch_disabled`.

## Fixture boundary

With `BOB_DARWIN_SAFETY_DEADMAN_FIXTURE=1`, the fixture launcher can:

- spawn a measured standalone Darwin watcher with an empty environment;
- pass a random HMAC fixture key through a one-shot private capability FD;
- bind signed configuration, heartbeat, and stop records to the exact contract;
- after accepting CFG1, fork an independent cleanup custodian and require its
  authenticated `CUSTODY_READY1` before executable measurement, journal
  mutation, worker observation, or watcher READY output;
- require a sequence-zero, contract- and deadline-bound, evidence-key-signed
  `CUSTODY_ARMED1` from that custodian before emitting `READY1`; READY carries
  the complete acceptance so JavaScript verifies it independently, then sends
  a private sequence-one heartbeat capped at the same ARM deadline; only the
  resulting `CUSTODY_EXTENDED1` round trip can return a controller, so
  operator-visible protocol traffic begins at sequence two;
- keep custody admission inert on pipe, fork, registration, or READY failure:
  those failures emit no cleanup evidence and admit no later startup work;
- bind every custody command and observation to a committed action digest, a
  fresh launch nonce, watcher and custodian PIDs, their process-start, process
  group, and session identities, the absolute startup deadline, and the
  contract's instrument/lease/fence/worker/cleanup/restore bindings;
- derive separate command and evidence HMAC key domains, independently verify
  ARM and EXTEND windows, and require `CUSTODY_EXTENDED1` before a heartbeat
  promise succeeds; a pipe write, late, expired, forged, replayed, or reordered
  acknowledgment cannot extend caller-visible custody;
- timestamp each host heartbeat send and ACK receipt, conservatively project
  native delivery time as signed custodian `acceptedAt` plus the full host
  round trip, and reject equality with or passage beyond `validUntil`;
- launch the watcher outside the launcher process group, then put the
  custodian and cleanup worker into their own distinct sessions and groups, so
  terminating the watcher or active-worker group does not terminate cleanup;
- let the custodian observe the inherited control FD only for EOF—it never
  reads configuration or heartbeat bytes—and independently observe watcher
  exit and its own absolute timer;
- use the watcher's `CLOCK_MONOTONIC` attestation as the initial heartbeat
  lower anchor, then refresh separate signed lower and conservative upper
  anchors on every accepted custody ACK;
- bracket `EVFILT_PROC/NOTE_EXIT` registration with two `proc_pidinfo`
  observations of PID, real/effective UID and GID, process start time, and
  command;
- have only the custodian execute the measured same binary in cleanup-only mode
  with fixed argv, an empty environment, and only handoff, receipt, and key FDs
  3/4/5;
- enforce one absolute `CLOCK_MONOTONIC` trigger-to-terminal deadline across
  remeasurement, pipe/fork/exec handoff, receipt, reap, journal/readback, and
  terminal reporting;
- give the cleanup child its own earlier deadline plus a bracketed kqueue
  parent-death guard, so watcher death cannot leave it running;
- bind every direct child to its Darwin process-start/session/group identity,
  prove it is still an unreaped direct child with `waitpid(WNOHANG)` before any
  signal, target its verified group once, and drive `waitpid` through `EINTR`
  to a definite reap or fail closed on `ECHILD`;
- append, `fsync`, and independently read back a hash-chained journal through a
  preopened regular-file capability FD; and
- end once in quarantine, with a bounded cleanup timeout and redacted errors.

Parent-side stream or attestation failure closes the control capability so the
custodian can observe EOF and redeem cleanup without depending on watcher
progress; JavaScript does not immediately kill the watcher. READY is only the
first phase of admission. JavaScript rechecks the active signed deadline after
the private confirmation continuation, immediately before controller delivery,
and synchronously before every heartbeat, stop, or fixture-close command. A
queued native terminal callback therefore cannot leave a stale controller
command-admissible. After each accepted confirmation JavaScript maps the signed
absolute `validUntil` through the conservative upper clock anchor and rearms a
fixture-only supervisor with the signed cleanup timeout plus a five-second
last-resort margin; delayed delivery never creates a fresh deadman window. The
bound covers autonomous deadman and worker-exit paths as well as explicit stop
and never produces a successful cleanup claim. Before the confirmation
establishes an upper clock anchor, phase-one READY starts only a
cleanup-timeout-plus-kill fallback; it does not start or extend caller-visible
custody. Fixture startup also has a ten-second readiness bound. The
deterministic blocked-startup fixtures use a
300 ms custody trigger; even when JavaScript rejects output immediately, its
kill bound is the full signed cleanup timeout plus five seconds. It cannot
preempt the custodian's cleanup/evidence deadline.

The custodian publishes one authenticated `CUSTODY1` observation on private FD6
and one receipt to the watcher. JavaScript can use that observation only to
reject or correlate a terminal result, never to manufacture success. Its HMAC
proves the fixture custodian path possessed a key derived from the inherited
launch secret. Custody and terminal records cross-check watcher, custodian, and
cleanup process-start/session/group evidence, including the cleanup group used
for descendant termination. It is **not** independent provenance against a compromised
watcher, is not child-exclusive attestation, and is not a production signing
authority. Production readiness and device/RF HIL therefore remain false.

The watcher observes the configured PID independently. The caller-provided
`worker_identity_digest` is only an immutable protocol binding in this
precursor; it is **not** compared with the native process-observation digest.
Darwin audit-token binding and that digest-to-observation binding remain
explicit production blockers.

The fixture remeasures canonical owner-controlled executable paths immediately
before `spawn`/`exec`, but Darwin's path-based calls do not atomically bind the
previously opened file to execution. Same-user path substitution is therefore
not claimed away; immutable signed deployment plus atomic launch/exec identity
qualification remain production blockers.

The fixture key is HMAC test material, not a production signing authority. The
JavaScript controller never returns the key or its FD. Buffers remain owned
until stream write completion and are then cleared; the controller also bounds
the number of outstanding private writes.

## Cleanup semantics

The closed semantic cleanup profile is deliberately narrower than a general
instrument API:

1. Reviewed Chameleon command family **2101** is the field-release operation
   and must be attempted first by any future qualified provider.
2. Command family **4038** is only a conditional, precommitted restore of the
   MIFARE field-off-reset setting. It is not an RF-stop operation.
3. When that restore applies, command family **4039** is its required readback.

This package contains semantic family identifiers only—no command frames,
command bytes, device selector, or real provider. A Chameleon Ultra can be
battery powered, so USB disconnect or worker-process termination does not prove
that RF emission stopped. Without an independent external RF witness, every
terminal result remains `emission_state: "unknown"` and `state: "quarantined"`.

## Contract and journal authority

A fixture plan commits digests for the instrument reference, lease, fence,
worker identity label, cleanup capability, restore state, future provider
manifest, journal identity, and semantic cleanup profile. Heartbeats and stop
records repeat those bindings exactly. Replays, gaps, stale windows, binding
changes, and appended operation selectors trigger only the already committed
cleanup path.

The journal path is discovery input only. JavaScript creates a new no-follow,
owner-only file beneath an owner-only canonical parent and passes its FD. The
native watcher requires a regular file with link count one, matching owner,
restrictive mode, read/write append flags, empty initial content, and an
exclusive lock. The custodian gives the cleanup-only child its signed handoff
before the watcher attempts trigger-evidence append/fsync, so a blocked or
failed watcher journal cannot suppress cleanup. Any journal failure preserves
quarantine/unknown, makes readback false, and prevents a successful fixture
result even when the cleanup attempt is observable on FD6. Valid terminal
delivery requires native and JavaScript hash-chain readback.

## Development

Darwin arm64 and Node.js 20 are required.

```sh
npm run build
npm run check:syntax
npm test
```

Tests use only inert local worker processes, pipes, and temporary journal files.
They cover process death, monotonic timeout, signed stop, replay/staleness,
binding substitution, cleanup widening, stuck cleanup, partial receipts,
trigger-journal failure, READY delivery failure, invalid-CFG inertness,
authenticated startup failure, repeated first-fsync and READY-output stalls,
immediate control close during both stalls, late-ARM deadline revival,
delayed/expired/forged/pipe-only ARM acceptance, late/forged/replayed/reordered
EXTEND acceptance, delayed READY delivery, delayed ACK delivery,
post-ACK/pre-controller expiry, active-deadline second-admission refusal,
single-custodian/single-cleanup evidence, stale/reaped PID and repeated-cleanup
refusal, descendant group termination, active-worker and watcher group
isolation, PID disappearance, watcher stalls,
parent-death races before and after child kqueue registration,
an injected handoff stall with strictly ordered cleanup-child,
custodian-observation, and watcher terminal deadlines, zero-clock/overflow
deadlines, prototype/runtime substitution, durable
readback, and terminal quarantine. They do not enumerate, open, or transmit to
attached hardware. `npm pack --dry-run` contains source and metadata only; it
does not include the locally built fixture binary.

`DARWIN_SAFETY_DEADMAN_ASSURANCE.production_blockers` is authoritative for the
remaining boundary. It includes a qualified launcher and dedicated principals,
ACL qualification, a signed immutable arm64 prebuild, production signature
authority, native observation/audit-token binding, an independent worker fence,
a durable external journal store, qualified cleanup-child custody and blocking
storage deadline behavior, a real cleanup provider, device HIL, and an external
RF observer HIL.
