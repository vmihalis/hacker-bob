# Plane-PH Brutalist architecture review adjudication

Date: 2026-07-18

Brutalist context: `01fb0032-ff3a-4923-84de-629f86b1d6bb`

The local Brutalist MCP server ran its architecture roast with Claude and Agy
critics. The run was read-only and did not open a transport, device, serial
node, network target, or RF path. This document records Bob's adjudication of
the adversarial output; critic severity and conclusions are not accepted
without repository evidence.

## Review-quality limits

- The Claude critic inspected the Brutalist checkout rather than the supplied
  Hacker Bob target. Its claimed repository search and all conclusions presented
  as code review are non-evidence. Its design checklist remains useful only as
  threat-model prompts.
- The Agy critic reached Hacker Bob and cited real files, but confused proposed
  hypergraph coverage with executable runtime coverage in several places.
- Line numbers in critic output are volatile in this uncommitted implementation.
  The stable evidence below names the owning file and symbol.

## Accepted findings

### 1. The durable lease store has bounded recovery, but retained-state growth remains

`mcp/lib/instrument-lease-store.js` now keeps a live authenticated projection
and offers an explicit `bounded_checkpoint` mode. That mode encrypts the full
projection with a checkpoint-specific HKDF key, fsyncs a private append-only
checkpoint file before publishing it, and commits its digest through a private-
branded monotonic CAS callback port. The local brand proves callback custody in
the worker process, not that the backing state is independently hosted or
durable. Readiness therefore reports the anchor assurance as
`caller_asserted_callback_unattested`, keeps `production_ready: false`, and
separately reports whether bounded recovery is ready. Independent hosting and
principal/rollback attestation remain provisioning gates. The checkpoint binds the runtime, session
nucleus, event generation and head, projection schema, ciphertext/envelope,
checkpoint generation, and prior checkpoint digest. Cold recovery decrypts the
current externally anchored checkpoint and replays at most 1,024 retained event
files. Rejected or response-lost checkpoint CAS commits reconcile only the one
exact crash-left file. No event or checkpoint is deleted.

`legacy_full_audit` remains available for migration and explicit historical
audit, but reports `production_ready: false`. An existing legacy root migrates
by opening in full-audit mode with the external checkpoint port, calling the
explicit `checkpointNow()` publication boundary, closing, and reopening the
same root and port in `bounded_checkpoint` mode. There is no implicit default or
silent upgrade. Bounded mode fails closed without the enrolled checkpoint port,
but the callback contract alone cannot claim production readiness.
Adversarial tests cover rollback/fork/outage, missing/corrupt/oversize/symlink/
hardlink files, AEAD failure, private-capability clones, crash-left reconciliation,
and internally inconsistent projections.

The scalability finding is narrowed, not erased. Startup still enumerates every
retained event and checkpoint filename to prove contiguity. Projection clones,
event-key/digest indexes, and checkpoint materialization still grow with the
ledger, and checkpoint plaintext is capped at 32 MiB. If that enrolled capacity
is exhausted, ordinary events are refused before publication and readiness
reports `checkpoint_capacity_exhausted`; only the reserved fencing, containment,
receipt, and cleanup event classes remain admissible. Automatic publication
catches only Bob-branded capacity outcomes, so authentication, integrity, CAS,
and anchor errors still escape and fail the caller. Bounded recovery does not
decrypt pre-checkpoint event history, so a deliberate full-history integrity
audit still requires `legacy_full_audit`. Ordinary admissions stop at 83,616
events (`MAX_EVENTS - SAFETY_EVENT_RESERVE`), while the final 16,384 events are
reserved for fencing and cleanup. A production backend still needs indexed
bounded-time mutation paths and retention-safe proof-preserving archival before
the 100,000-event ceiling can be lifted.

### 2. Same-UID separation is not a security boundary

The architecture already states this in
`docs/plane-physical/task-hypergraph.md`. A same-UID agent can address local
store paths and broadly writable device nodes even when JavaScript objects are
carefully branded. Production PH-S3 therefore still requires an OS-enforced
device-owning principal, a separate grant issuer/key custodian, a restricted
worker IPC protocol, and an agent sandbox that cannot open the device.

### 3. Semantic command coverage is not executable command coverage

`packages/bob-instrument-chameleon/lib/operations.js` provides reviewed
semantic and source-provenance coverage. `codec.js` deliberately enables only
37 source-reviewed system-command maxima in its v2.2.0 outbound profile, with a
smaller read-only bootstrap profile. This does not "brick" a completed active
provider: it truthfully means the active provider is not completed yet.

PH3 must add closed, operation-specific compilers and reviewed payload bounds
before enabling each active command family. It must not solve this by exposing
a generic raw command/frame/APDU encoder to evaluators or by assigning guessed
maxima to every firmware command.

### 4. Store contention and replay cost threaten watchdog availability

`instrument-safety-supervisor.js` obtains current lease state through the
synchronous store snapshot. The store lock fails busy rather than waiting.
Hot reads and bounded-checkpoint restart no longer perform a full replay, but
projection cloning/materialization and retained filename scans remain
ledger-sized work. The critic's claimed automatic "false-positive kill after
500 ms" is not the implemented behavior: a busy `currentLease()` rejects the
cycle before a fence decision. The real risk is a failed or delayed liveness
cycle and loss of a timely containment decision.

PH-S3/PH-S7 need a trusted, bounded-time current-state port that cannot be
forged by the agent and whose availability semantics are explicitly connected
to an independent deadman/fence mechanism.

### 5. Trusted time remains a production dependency

The supervisor correctly fails closed on a backwards clock. A host wall clock
is nevertheless not the production trusted-clock service required by leases,
grant validity, observation offsets, heartbeats, and recovery deadlines. The
production worker boundary needs monotonic duration measurement plus an
authenticated wall-time mapping and explicit clock-failure evidence.

### 6. Chameleon hardware ceilings must not become Plane-PH ceilings

The coverage registry accurately marks passive capture, universal relay, and
some raw decoding as unavailable on this provider, and explicitly limits
DESFire work to bounded enumeration/authentication probes. These are not
missing generic concepts: the normalized operation registry retains the
provider-neutral dimensions. Full-plane closure still needs another provider
or composed instruments to demonstrate that unsupported Chameleon features do
not constrain Bob's architecture.

### 7. A stateful physical instrument is a serialized scheduling resource

The Chameleon is not a fungible fan-out worker. Scheduling must bind exclusive
instrument leases, pre/post state epochs, mode transitions, restoration cost,
operator presence, and assurance invalidation. Coverage is a target registry,
not authorization to materialize the cross-product of every operation and
parameter combination.

## Rejected or corrected claims

- "All 146/147 firmware commands must be added to the generic codec" is unsafe.
  Active commands require semantic compilers, exact effects, and reviewed
  payload constraints.
- "Store contention triggers a watchdog timeout and kills the worker" does not
  follow the current synchronous busy-lock path. It causes availability loss;
  containment behavior must be supplied by the external deadman design.
- "The store locks entirely at 83,616 events" omits the safety reserve. Normal
  work stops, but fencing and cleanup retain a bounded reserve until 100,000.
- Surface-graph quarantine blocking trusted append is deliberate fail-closed
  behavior, not by itself a vulnerability. Operational recovery still needs a
  bounded adjudication procedure.
- The artifact-vault package exists. What remains missing is production
  privilege separation, external key custody/anchors, and a worker principal;
  not the vault contract itself.
- Unsupported passive capture and relay are Chameleon provider limitations,
  not reasons to weaken the generic physical capability vocabulary.

## Dependency-correct action order

1. Replace broker-local grant projections with the core cryptographically
   verified one-use active grant.
2. Add a provider-verified durable dispatch/fencing capability and make the
   broker/worker the sole owner of raw provider methods.
3. Establish OS principal, device-node, IPC, key-custody, trusted-clock, and
   independent deadman boundaries.
4. Keep the externally anchored encrypted checkpoint path mandatory in
   production, then replace remaining ledger-sized projection clones and
   directory scans with indexed bounded-time mutation/read paths.
5. Build operation-specific Chameleon compilers and source-reviewed codec
   profiles, then the USB transport, without evaluator raw-command access.
6. Run read-only inventory HIL and disconnect/re-enumeration/fence failure
   matrices before enabling target-facing RF.
7. Expand active capabilities by effect family, then demonstrate cross-provider
   composition for hardware ceilings that Chameleon cannot satisfy.
