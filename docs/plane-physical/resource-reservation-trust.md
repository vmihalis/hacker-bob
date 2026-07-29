# Physical resource reservation trust

Bob's reservation authority treats aggregate hardware inventory and broker
scheduling state as different objects.

- `attested_inventory` is the exact Ed25519-signed external observation. It is
  the ceiling for physical availability, capacity, identity, mode, workspace,
  freshness, and fencing.
- `inventory` is Bob's durable logical projection. Atomic holds may reduce its
  available capacity, disable exclusivity, or advance fences without asking the
  external inventory signer to attest Bob's bookkeeping. It may never widen
  beyond `attested_inventory`.
- A signed refresh is bound to the exact prior state revision, state digest,
  logical inventory digest, authority, session, graph, signer epochs, and
  trusted-clock coordinates. The authority verifies current external trust
  twice, derives the logical projection around active holds, and commits the
  result with one exact compare-and-set.
- A fenced or quarantined resource cannot be resurrected by editing durable
  state. Recovery requires a later signed observation whose fencing generation
  crosses the terminal allocation's safety floor.

## Genesis and restart

Unattested genesis is deliberately a two-stage operation.

1. An external checkpoint anchors revision 0 and the inventory authority signs
   the exact revision-0 observation.
2. Construction provisions that inventory lineage with one exact CAS to
   revision 1, but the returned bootstrap authority is mutation-disabled.
3. The checkpoint authority independently anchors revision 1.
4. Reconstructing the authority against that exact checkpoint and the same
   current inventory attestation enables reservations and effect authority.

The stable test sequence is exercised in
`packages/bob-instrument-broker/test/resource-reservations.test.js` and shared
provider tests use
`packages/bob-instrument-broker/test/helpers/physical-reservation-fixture.js`.

Restart admission verifies an externally anchored, contiguous signed checkpoint
chain against the exact durable head and independently verifies the current
inventory attestation. Checkpoints bind reservation and terminal-history
digests, their sorted receipt and exact terminal-record member digests, every
exact tombstone digest, every compacted source-record digest, compaction
lineage, inventory-attestation lineage, state ancestry,
authority/session/workspace coordinates, signer epochs, and trusted clock
transitions. A checkpoint signer is not an inventory signer.

## Proof-preserving terminal compaction

`compactPhysicalResourceReservationHistory()` is an explicit authority
operation, not automatic garbage collection. It accepts only an externally
signed checkpoint chain for the exact durable head. The authority verifies the
chain and current trust twice, with an exact durable-state read after each
verification, before proposing one compare-and-set successor. A stale,
malformed, untrusted, raced, or losing proof path commits nothing. An exact
response-lost CAS is reconciled by reading back the one expected successor;
any other uncertain outcome makes the authority fail closed.

Only terminal records with resolved safety state are compactable. Held and
cleanup-pending records always remain full records. Fenced and quarantined
records also remain full until `attested_inventory` reports every allocated
resource available at a fencing generation strictly newer than the allocation
floor.

A compacted record becomes a closed terminal tombstone. It removes the bundle,
full request, lock-order values, and raw-fence structure while retaining the
exact request identity digest, attempt and budget domain, terminal receipt,
allocation-plan and lock-order digests, terminal effect disposition, and the
digest of the full source record. Consequently:

- an exact duplicate remains idempotent and returns the same public terminal
  receipt and broker projection;
- a conflicting reuse of the request or attempt identity is still rejected;
- completed, unknown-effect, and quarantined attempts still consume their
  original budget, while cancelled-before-effect attempts still do not; and
- fenced and quarantined tombstones continue to enforce inventory safety
  floors after restart.

Each generation advances a domain-separated accumulator over the prior
accumulator, every source-record digest in that batch, the exact source
checkpoint and source state, the complete tombstone-set digest and count, the
cumulative compacted count, and the generation. The successor checkpoint binds
those same coordinates and the cumulative exact tombstone/source-record member
sets. A contiguous checkpoint chain requires both sets to be monotonic and the
new source-record set difference to equal the claimed batch, so a later
compaction cannot rewrite an older tombstone or point its accumulator at an old
record. Every new batch member must also have been an exact terminal-record
member of the signed source checkpoint, while consuming its immediate signed
predecessor.

Retention is deliberately bounded. A state admits at most 16,384 tombstones;
only 16,128 may be ordinary released history, reserving 256 slots for fenced or
quarantined safety history. Ceiling exhaustion fails closed without deleting a
tombstone, resetting an attempt budget, or compacting another record.

## Honest readiness

`physicalResourceReservationReadiness()` is callback-free and always reports
`production_ready: false`. It distinguishes:

- `verified_exact_head_at_authority_start`: the verified checkpoint matches the
  cached live head;
- `verified_exact_head_at_authority_operation`: an explicit compaction check
  verified the unchanged live head (normally observable after a no-op);
- `inventory_successor_unanchored`: genesis or restart inventory provisioning
  committed a successor that still needs an external checkpoint and cannot be
  used; and
- `stale_after_live_mutation`: the authority remains a single live exact-CAS
  writer, but its startup checkpoint is now historical.

The projection exposes the verified checkpoint revision/digest and cached live
revision/digest separately. Bob does not claim that a live CAS automatically
published an external crash-recovery checkpoint. A crash after a live mutation
therefore requires the external checkpoint service to anchor the exact durable
head before a new authority can start. Readiness also exposes full-record and
tombstone counts, both ceilings, the safety reserve, and the observed compaction
generation; this remains operational telemetry, not a production-readiness
claim.

## Production boundary

The JavaScript state, inventory-trust, checkpoint-trust, and clock ports are
branded synchronous integration contracts. Their callbacks do not prove HSM
custody, process isolation, linearizable durable storage, monotonic external
anchoring, key revocation delivery, or automatic checkpoint publication.
Production qualification must supply and attest those properties outside Bob's
process. Historical checkpoint documents are transitively committed by the
external first anchor and current signed head; the external checkpoint service
must validate what it anchors because Bob does not reconstruct every historical
signer's trust state locally.

Compaction does not make the deleted full record retrievable. The tombstone and
accumulator prove its committed digest and preserve Bob's replay, projection,
budget, and safety decisions, but they cannot reconstruct the full request,
bundle, lock order, or other removed fields. Operators that require forensic
retrieval must archive the signed source checkpoint and its exact source state
outside Bob before authorizing compaction. Bob does not attest that archive's
durability, availability, confidentiality, retention period, or erasure policy.
