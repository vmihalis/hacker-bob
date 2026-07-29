# ADR: Physical vault custody and transform isolation

Status: accepted for Plane-PH implementation

## Context

Plane-PH handles credential images, traces, nonces, keys, device snapshots, and
other artifacts that must never enter a model-facing prompt or ordinary MCP
process. A same-UID library can provide opaque handles, authenticated storage,
and logical deletion, but it cannot by itself provide OS-principal separation,
rollback-resistant monotonic state, or backup-resistant cryptographic erasure.

The Chameleon Ultra capability ceiling also needs transforms beyond simple byte
operations: dictionary and nested-key recovery, trace analysis, image
conversion, protocol parsing, and future provider-specific research tools.
Allowing caller-supplied JavaScript callbacks in the process that holds vault
plaintext would turn every transform into an unrestricted exfiltration path.

## Decision

Bob uses three distinct execution boundaries.

### 1. Model-facing broker

The MCP and agent receive only random or keyed-pseudorandom session-scoped
handles, masked summaries, provenance, and bounded verdicts. They never receive
vault keys, plaintext, direct transform inputs, export capabilities, or an API
that accepts executable code.

### 2. Privilege-separated vault service

The production vault runs under a separately owned OS principal or equivalent
service identity. Its state root, socket, keys, and operator channel are not
readable or connectable by the model-facing principal. The service owns:

- encrypted local indexes and segmented append-only journals;
- a monotonic compare-and-set anchor in a rollback domain separate from vault
  backups;
- an external per-artifact key custodian. Backups contain ciphertext and opaque
  key references, never the custodian material needed to unwrap a destroyed
  artifact;
- pre-stimulus logical and physical reservations, durable operation claims,
  retention, erasure, recovery, and operator-authenticated export;
- handle-only RPC methods with closed schemas and request identities.

An implementation without the separate principal, monotonic backend, and key
custodian is a contract/reference implementation, not the production HIL
boundary and not evidence of backup-resistant cryptographic erasure.

### 3. Two transform tiers

Tier 0 is the in-process declarative `.transform.json` interpreter. It supports
only reviewed, closed byte primitives and performs output, allocation, and work
preflight before allocating. It is appropriate for identity, slicing, hashing,
reversal, concatenation, and similarly auditable primitives.

Tier 1 is a separate transform worker for advanced tools. Each worker image or
binary has a content-addressed, recursively closed executable/dependency
manifest. It runs with:

- no network, agent IPC, shell, package manager, home directory, or operator
  channel;
- a read-only executable image and empty ephemeral work directory;
- CPU, memory, output, process, descriptor, and wall-time limits;
- one-use job authority bound to tool/version/image digest, input handles,
  output reservations, parameters, session, task, attempt, and transform claim;
- a private vault-worker channel capable only of materializing the claimed
  inputs and committing the reserved outputs;
- durable pre-materialization input pins and at-most-once attempt claims;
- mandatory zeroization/worker teardown and provenance receipts.

Hardware-native operations are not transforms. They remain provider operations
behind Plane-PH grants, leases, requested effects, stop, and restoration.

## Rejected alternatives

- Caller-supplied in-process callbacks or self-asserted implementation digests.
- Treating file mode `0600` under the same UID as privilege separation.
- Deriving every artifact wrapping key from one backup-restorable master key and
  calling a tombstone “cryptographic erasure.”
- Expanding the declarative interpreter until it becomes a general programming
  language.
- Giving an isolated worker arbitrary paths, URLs, commands, or raw key export.

## Acceptance consequences

Production readiness requires HIL from the model-facing OS principal proving it
cannot read vault control state or keys, connect to operator export, bypass the
handle protocol, roll back monotonic heads, or make a destroyed artifact from an
old backup decryptable. Advanced transform HIL must prove network isolation,
recursive image attestation, resource enforcement, input pinning, at-most-once
execution, and output-only commit semantics.

