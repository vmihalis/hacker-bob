# Chameleon Darwin native custody precursors

This private, source-only optional package is the Darwin kernel serial boundary
for the Chameleon Ultra provider. Import and ordinary construction are inert.
It does not enumerate devices and exports no path, serial number, file
descriptor, generic read, or generic write surface.

## Non-negotiable DTR limitation

Darwin's public tty interface cannot establish the required pre-open DTR
history. `O_NOCTTY` prevents a tty from becoming the controlling terminal; it
does not configure modem-control lines. `TIOCCDTR` and `TIOCMBIC` require an
already-open descriptor, so they cannot prove that a USB serial driver did not
assert DTR during `open(2)` or before the first ioctl. This package therefore
reports `production_ready: false` and rejects every real-device open before
loading native code. Post-open observation cannot be relabelled as proof of
pre-open history.

The concrete lower-level experiment is an exclusive IOUSBHost CDC ACM owner,
not another BSD tty wrapper. It would capture the exact USB device/interface
before any tty driver owns it, then send the class/interface
`SET_CONTROL_LINE_STATE` request (`bRequest=0x22`, `wValue=0`) before exposing
bulk endpoints to Bob. Apple's SDK says `IOUSBHostObject` ownership is
exclusive. Its `DeviceCapture` option terminates current clients and drivers
and requires `com.apple.vm.device-access` plus `IOServiceAuthorize()` (or root);
`DeviceSeize` only asks the current owner to close. A durable DriverKit owner
instead needs a signed system extension with the
`com.apple.developer.driverkit.transport.usb` entitlement and an exact
VID/PID/interface match. It must expose a narrow, authenticated user client,
not a generic USB pipe.

Neither route alone proves physical history: driver capture/reset and the time
before the first CDC request can still contain an unobserved transition. The
acceptance gate therefore also needs a HIL trace that shows the device's actual
DTR/RTS pins remained low from a defined pre-capture boundary through the
control request and first transaction. If the measured USB owner cannot make
that guarantee, the required successor is an independent line-state witness
that cryptographically binds continuous DTR/RTS observations to the exact
device, open generation, challenge nonce, monotonic time window, worker/native
code identity, and transaction digest. No post-open `TIOCMGET` sample can close
that transient-history claim.

## Implemented precursor boundary

The native code is exercised only against an explicitly marked Darwin
pseudo-terminal fixture. That path validates the remaining boundary mechanics:

- an exact operator identity digest, expected parent-directory identity, exact
  character-device stat, equal real/effective worker UID and GID bound into a
  worker-identity digest, and an extended-ACL profile digest;
- `openat(2)` beneath a verified directory with close-on-exec, no controlling
  tty, no-follow, final-component revalidation, single-link/type/owner/mode/rdev
  checks, and `TIOCEXCL`;
- bounded raw 115200 8-N-1 configuration with software/hardware flow control
  disabled and explicit DTR/RTS clearing attempts;
- one-use open generations and one-use, monotonically sequenced exact
  transactions containing one valid Chameleon request frame and one bounded,
  command-correlated response frame;
- native deadlines, abort fencing, connection quarantine on ambiguous I/O,
  descriptor cleanup, and request/response zeroization.

The measured native addon is loaded with a captured, revalidated
`process.dlopen` into a private module record; mutable `.node` extension hooks
are never consulted. The resulting cache record, binding, functions, and
function prototypes are closure-branded and frozen. Any pre-existing
`require.cache` entry without that private brand is rejected. Exact Node-API
function shape is checked only after the measured binary populated that direct
loader, so forged or bound JavaScript functions are not accepted as native
evidence.

The pseudo-terminal mode is not evidence for USB CDC line behavior, identity,
device ACL deployment, code signing, or HIL. It accepts only `/dev/ttys*`
fixtures and is itself marked `fixture_only` in every capability and result.
The operator identity digest is a broker/enrollment binding, not a kernel USB
identity measurement; matching an enrolled ACL digest likewise does not decide
that the ACL policy is least-privilege. Those decisions remain external gates.
The package remains private and source-only until those gates and a signed
Node 20 arm64 prebuild exist.

## IOUSBHost direct-CDC successor boundary

`./direct-cdc-custody` is the isolated, inert successor experiment. Import,
plan construction, and open-generation construction do not enumerate, match,
open, capture, seize, or otherwise contact a USB device. Real activation is
terminally refused before native loading. The Objective-C++ target compiles
against the Darwin SDK to pin the intended IOUSBHost, Security, and IOKit
contracts, but its real-device helpers are not exported or reachable from the
Node-API fixture path.

The boundary enrolls one exact VID, PID, location ID, serial-number digest,
configuration, CDC control/data interface pair, complete interface descriptor
set digest, and exact bulk IN/OUT endpoint descriptors. It also requires a
launch-ticket shape that claims either root or both
`com.apple.vm.device-access` and `IOServiceAuthorize`. That ticket is currently
only shape- and digest-checked: no signature authority, expiry authority, nonce
replay authority, entitlement qualification, or kernel authorization is
claimed or inferred.

The SDK-backed design keeps the ownership modes distinct:

- `DeviceCapture` terminates existing device/interface clients and drivers;
- `DeviceSeize` merely requests that the current owner close;
- after ownership, the control interface must receive exactly
  `bmRequestType=0x21`, `bRequest=0x22`, `wValue=0`, `wLength=0` before the
  enrolled bulk endpoint descriptors may be bound;
- every generation has one bounded, one-use, command-correlated Chameleon
  transaction followed by synchronous abort/destroy or clean destroy;
- any uncertainty after redemption terminally quarantines the generation.

Only an environment-gated, in-memory descriptor/transaction fixture is active.
Its ability to inject an exact frame and project response bytes is explicitly
fixture-only, not a real generic USB read/write API. Production integration
now routes a complete FD 7 record into encrypted, pre-reserved raw custody, but
the included provider-owned `get_app_version` validator remains deliberately
non-production. Production still needs its isolated principal, current trust
proofs, external monotonic receipt anchor, HIL qualification, and real transport
path so Bob never grants caller-shaped transport access or infers semantic
success from framing alone.

This successor remains `production_ready: false` until it has a signed,
immutable Node 20 arm64 prebuild; a dedicated worker principal and qualified
device ACL; authoritative launch-ticket signature, expiry, and replay checks;
qualified entitlement and `IOServiceAuthorize` deployment; kernel-bound
registry identity evidence; continuous DTR/RTS HIL witnessing; and real
Chameleon IOUSBHost HIL. Fixture tests cannot discharge any of those gates.

## Signed native-dispatch custodian fixture

`./native-dispatch-custodian` defines the closed binary contract for the final
write/deadline seam. Import is inert: it neither opens nor enumerates a device,
and it exports no spawn, path, descriptor, generic read, generic write, or raw
response surface. The separately loaded fixture addon accepts zero JavaScript
arguments and consumes only this inherited descriptor map:

| Child descriptor | Fixed capability |
| --- | --- |
| 3 | Receive-only anonymous AF_UNIX stream containing one signed launcher context |
| 4 | Sole delegated character-device transport, normalized and revalidated as exact `O_RDWR\|O_NONBLOCK` |
| 5 | Receive-only anonymous AF_UNIX stream containing one canonical signed dispatch envelope plus command bytes |
| 6 | Send-only anonymous AF_UNIX stream for one fixed 196-byte redacted terminal result |
| 7 | Sole delegated empty owner-only regular-file sink, normalized as exact `O_WRONLY\|O_APPEND`, for one pre-reserved vault response record |

The launcher context and dispatch ticket are independently Ed25519 signed,
canonical TLV envelopes. Both signatures cover the key ID, public-key digest,
payload framing, and every payload byte. Native code independently parses and
cross-binds the worker principal/start/bundle, loaded image, provider and
implementation, semantic manifest, device/enrollment/generation, launcher,
descriptor inventory, exact delegated descriptor identity, trusted clock, and
dispatch key. The signed launcher context additionally binds the exact PH-P8
bootstrap-manifest digest, normalized-operation-registry digest, per-operation
command-set digest, generated native-table digest, and bootstrap-invariants
digest. They also cross-bind the execution lineage, vault reservation,
one-use ingest capability, exact sink descriptor identity, response ceiling,
and artifact-handle digest.

The native semantic table is generated, not separately authored. Running
`scripts/generate-bootstrap-semantics.js` reads the closed transport-neutral
bootstrap registry and full source-pinned Chameleon semantic manifest, verifies
their reviewed artifact digests, and emits both the frozen JavaScript
projection and the C++ header. `npm run check:generated` fails when either
generated surface is missing or stale; native builds run that gate first. The
compiled table admits exactly these normalized operations and one-based command
positions, all with an empty request payload:

| Normalized operation | Command sequence |
| --- | --- |
| `instrument.inventory` | `1:1000`, `2:1017`, `3:1033` |
| `instrument.capabilities` | `1:1035` |
| `instrument.health` | `1:1025` |

Native code independently compares the signed semantic/bootstrap manifest,
operation-registry, operation, command-set, table, and invariant digests to the
compiled generated constants. It then requires bootstrap / observe / no-effect /
RF-off posture, the exact command at the signed sequence position, a canonical
ten-byte frame, status zero, and a zero-byte payload. Another valid Chameleon
command cannot hide behind a normalized operation or command-set label.

`./native-bootstrap-sequence` is a separate effect-free sequencing precursor.
It accepts only the privately branded output of the PH-P8 compiler, stores its
state in private weak collections, emits no command bytes, and rejects
duplicates, reorder, omission, and premature completion. Import and use cannot
enumerate or open hardware, load native code, spawn, use USB, or access a
network. It is not durable and is not yet cryptographically joined to native
process launch, so it does not establish production multi-command custody.
After every device-readiness wait, the native thread rechecks
continuous monotonic time, the real/effective UID and GID, and the exact private
descriptor identity and flags immediately before each first or continuation
write. It terminally closes the private device generation before emitting the
result and after one attempt.

Native code writes a fixed 280-byte binding header followed by the raw response
directly to descriptor 7, calls `fsync(2)`, revalidates the exact inode, flags,
mode, and final size, and closes the sink before declaring completion. The
header binds the execution lineage, signed dispatch envelope, delegated source
descriptor identity and sink descriptor, reservation, ingest capability,
artifact handle, response length,
and response digest. Terminal results never contain response bytes. A complete
fixture result carries only their length and SHA-256 digest plus the sink
descriptor and record-header digests. If any command byte was written and later
I/O becomes uncertain, the status is `ambiguous_quarantined`; any response prefix
actually read is likewise retained only as length and digest. A zero length must
have the all-zero digest. After the terminal capability is validated, a
before-write rejection is `rejected_no_effect`. An absent fixture gate or an
invalid/aliased fixed-descriptor topology closes without a native receipt; only
the trusted parent may durably classify that missing-receipt condition.
The decoder enforces the exact reachable flag/digest/sequence/sink matrix rather
than accepting arbitrary combinations. A partial or lost sink commit makes the
device result ambiguous and cannot mint a successful transport receipt.

A complete FD 7 ingest likewise does not mint semantic transport success. The
vault returns only a distinct private-branded
`provider_response_raw_custody_receipt` with
`semantic_validation_performed: false`, explicit source/sink descriptor identity
digests, and no `result_code` or `device_state_digest`. Consequently a validly
framed error status, or command 1000 with a payload that violates the pinned
`get_app_version` schema, remains encrypted raw evidence. The fixed
provider-owned validator is now present as a closed vault-worker port: it accepts
only a private raw receipt plus the exact execution lineage, selects only the
registry-pinned `chameleon_ultra/get_app_version` transform, materializes
plaintext solely inside vault custody, and reuses the bounded worker codec and
source-owned payload decoder. A successful observation requires command 1000,
status `0x0068`, exactly two version bytes, the reviewed semantic manifest and
operation schema, a fresh signed trusted-clock sample, and durable confirmation
that the native staging inode cleanup completed. It returns only the safe
application version and binding digests in a distinct private semantic-
observation receipt; it never returns raw bytes, accepts a callback/module
path/readiness claim, or fabricates `device_state_digest`. The receipt remains
`production_ready: false`, `authoritative: false`, and HIL-unproven. Raw-custody
and semantic-result journals are mutually exclusive behind a durable
reservation-and-lineage fence, including prepared-state crash and restart
reconciliation; the new observation is an authenticated successor within the
already selected raw-custody journal rather than a legacy semantic sink commit.

Response framing means the exact first correlated frame plus an immediate
`FIONREAD == 0` check. It does not claim a time-based quiescence interval or that
a later byte could never arrive. Closing the terminal one-use connection before
the result write bounds that later-byte case. The native producer side now has
a precommitted source-owned descriptor handoff, but the result socket is not yet
an authenticated durable receipt and no independently deployed production
vault principal owns, attests, and signs the ingest. Those remain blockers.

The no-hardware suite uses only PTYs and anonymous socketpairs. It covers fixed
descriptor aliases and flags, partial control writes, every signature/key/binding
fork, command drift, every exact generated operation/command position,
cross-operation substitution, sequence duplication/reorder/omission-shaped
forks, unknown commands, payload injection, registry/set/manifest drift,
expired and libuv-queued deadlines, a blocked JavaScript event loop, partial
device writes, no/late/partial/duplicate responses, descriptor
substitution, response-sink inode/mode/flag/alias drift, deterministic lost sink
commit, deterministic post-poll first/continuation deadline stalls, in-process
replay, coherent result tampering, error/malformed-payload raw-only custody,
reservation-fence crash/restart and competing-lineage races, a deterministic
Node 20 golden envelope, and
the explicit process-restart replay limitation. A committed non-empty sink
blocks an exact-ticket replay before effect, but snapshotting or rolling back the
whole local sink domain is not an independently retained replay fence.

This source intentionally remains `production_ready: false`. It still needs a
signed immutable Node 20 arm64 image or standalone custodian, qualified external
launcher-key enrollment and revocation, durable restart replay/fork fencing, an
authenticated terminal receipt and outbox, an independently deployed and signed
vault ingest owner, durable native multi-command sequencing joined to the
bootstrap authority and launch, source-owned multi-response aggregation and
semantic validation beyond the existing command-1000 fixture validator,
real Chameleon HIL, and a continuous external DTR/RTS witness. The fixture uses
Ed25519 EVP symbols supplied by the pinned Node image, so it is not evidence for
an independently signed standalone verifier.
