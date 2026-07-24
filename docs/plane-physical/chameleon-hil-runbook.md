# Chameleon Ultra staged HIL runbook

Status: plan contract implemented; live execution and evidence remain pending.

The authoritative failure-plan contract is
`test/manual/chameleon-failure-matrix.js`. Printing it is inert:

```bash
node test/manual/chameleon-failure-matrix.js --print-plan
```

The packaged `@hacker-bob/instrument-chameleon/failure-matrix-engineering`
module deterministically evaluates the authenticated plan as a passive value
graph. It classifies all 734 cases once, checks zero-active-effect cleanup,
USB/BLE parity, maintenance invalidation, and independent-reader obligations,
and emits a digest-only engineering summary. It deliberately has no hardware,
transport, persistence, clock, or callback port. Its `engineering_gate_passed`
flag therefore never changes `hil_gate_passed`, `production_ready`, or
`live_hil_evidence_present` from `false`.

Matrix v5 recomputes and binds the reviewed Plane-PH node-contract digest, the Chameleon
semantic-manifest and capability-dependency digests, and the complete
16-profile effect registry. It carries a closed failure-plan binding for all
112 availability variants and a separately reviewed, digest-pinned registry of
734 exact cases. Effect cases are selected through the closed
`{scenario, effect profile} -> eligible operations` relation; they are not an
operation/technique/profile Cartesian product. All variants receive formula
and operation-drift cases, every technique-bound variant receives its own exact
selector case, and every physical effect receives matching staged cases.
USB/BLE parity cases bind a reviewed composite pair containing both transport
endpoint digests, the same normalized operation/effect contract, both signed
attempt receipts, and a signed comparison verdict. All nine T55xx write
variants bind the independent-reader case. Infrastructure-only cases are
explicitly typed and cannot masquerade as variant coverage. Registry drift, an
omitted or substituted variant/case, unknown nodes/scenarios, stale source
digests, effect-family/profile laundering, and partial coverage fail before a
live runner can consume the plan. `validateFailureMatrix` accepts and
authenticates the complete printed envelope, including its `matrix_digest`.

There is deliberately no `--execute` mode. A live runner must be a separate,
reviewed component that consumes the exact `matrix_digest`, an operator-signed
scope and fixture manifest, the enrolled device identity, an independent
witness registry, and the current signed native release. It must return signed
per-scenario evidence into Bob-owned session state; it must never edit the
package-safe matrix or mark a gate passed itself.

PH-P6 currently provides only the inert, registry-bound NUS contract and fixed
synthetic fragmentation vectors in
`packages/bob-instrument-chameleon/lib/ble.js`. A live BLE runner must use a
dedicated native CoreBluetooth service/characteristic custodian under the
enrolled worker principal. Bluetooth-created `/dev/cu.*` pseudo-serial devices,
arbitrary serial paths, caller-selected UUIDs, pairing-key reads, bond
administration, and evaluator-supplied frames are not BLE transports. They must
be rejected rather than adapted. Pairing posture crosses the boundary only as
a redacted current verdict; the key never does.

The order is non-negotiable:

1. `rf_off`: negative-principal access, descriptor substitution, process death
   before GO, partial frames, timeouts, disconnect, lease expiry, workspace
   drift, vault failure, and semantic formula/operation/technique-selector
   substitution. The semantic substitution cases are explicitly effectless.
   Their deterministic classifier returns `rejected_no_effect` only when the
   independent witness proves no dispatch/effect, zero active effects, and complete residue
   accounting; incomplete evidence resolves to `unknown_effect`. These cases
   must prove no target/environment effect and zero remaining leases.
2. `shielded_active`: an owned non-target load inside the enrolled containment
   fixture, with an independent RF/power observer. Exercise post-GO death,
   observer loss, and lost acknowledgements; reconcile or quarantine without an
   automatic effect retry.
3. `owned_media`: reversible media first, then explicit persistent-write cases.
   Write-only media such as T55xx requires a distinct assurance-qualified
   reader; an Ultra acknowledgement is not the outcome verdict. USB/BLE parity
   compares the same closed semantic operation and effect contract for target
   transmit, presentation, reversible mutation, stateful mutation, and the
   separately authorized destructive variant. The RF-off stage separately
   compares the USB/BLE instrument-transport effect.
4. `owned_maintenance_fixture`: settings, DFU, and erase use the maintenance
   authority, never cleanup authority. Every case carries distinct required
   signed-contract references for pre-state, backup, expected delta,
   inventory/assurance invalidation, and recovery or quarantine; the future HIL
   runner must materialize those exact contracts before execution. A reference
   alone is never evidence that the contract was satisfied. Erase
   additionally requires a backup and an enrolled witness principal distinct
   from the executor. `irreversible_authorized` is emitted only by the ordered
   classifier when current irreversible authority, the expected independently
   observed terminal state, proven containment, zero active effects, witness
   separation, and complete residue accounting
   all hold; otherwise the classifier deterministically chooses rejection,
   quarantine, or `unknown_effect` from the closed observation record.
5. `cross_plane`: a real verified physical transition is consumed by a real
   downstream execution. The downstream request must revalidate the exact
   capability instance, state epoch, custody, scope, and fresh authority.

For every scenario and every exact case evidence key, retain the signed grant/GO/result lineage, exact durable
journal and outbox bytes, provider/native terminal evidence, independent
observation, cleanup/residue verdict, and zero-active-effect assertion. A test
process exit code, a simulated fixture, USB disconnect alone, or a provider
receipt cannot substitute for the required external observation.

Until the live runner, enrolled fixtures/witnesses, and signed evidence exist,
all rows remain `pending_hil`, Plane-PH remains non-production, and no package or
release check may infer otherwise from this runbook.
