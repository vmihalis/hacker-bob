# Plane-PH task-hypergraph Brutalist adjudication

Date: 2026-07-18  
Brutalist context: `a7fbb5ab-114d-486b-9ee4-bd7b499e9c90`  
Mode: architecture  
Elapsed time: `1,867,066 ms` (31 minutes, 7.066 seconds)

## Verdict

The Brutalist review is directionally right: Plane-PH is a potential-maximizing
full-closure roadmap for Bob, but it is not a production physical runtime. Four
bounded implementation slices are now real and useful. They do not close the
native worker, OS isolation, independent containment, real hardware-in-the-loop
(HIL), cross-plane execution, or campaign-scale storage gaps.

The full 48-node hypergraph should remain the canonical definition of complete
Plane-PH. Delivery should use staged capability profiles so that a narrow,
truthful capability can ship before the full release sink closes. A profile may
reduce what Bob claims and exposes; it may not waive authority, evidence,
restoration, containment, or production HIL requirements.

This adjudication treats the Brutalist output as adversarial design input, not
as proof. Every disposition below is based on repository state. No Chameleon,
USB, RF, network, hotel system, credential, or other target was touched during
this review.

## Disposition summary

| Disposition | Finding | Adjudication |
| --- | --- | --- |
| fixed | Installer omitted nested runtime packages | Fixed for the project-local install surface; exact admitted runtime files are copied and smoke-tested. |
| fixed | Root/broker test discovery omitted the request registry | Fixed; the package suite and root discovery guard now include `resource-request-registry.test.js`. |
| fixed, bounded | Transferred-before-effect cancellation and reservation compaction lineage | Fixed for the implemented seams; private one-shot cancellation and exact signed compaction ancestry are covered by focused tests. This is not an OS fence or general scaling solution. |
| fixed, bounded | No closed HF14A semantic compiler | Fixed only for REQA and WUPA ATQA probes. Execution remains disabled and the compiler is not a public package subpath. |
| fixed, bounded | No supported physical-only canonical session bootstrap | Fixed for effect-free canonical creation from a privately resolved authenticated import. The bootstrap remains deliberately unable to dispatch hardware, and a physical-only session cannot leave `SETUP` until a future production-authoritative inventory checkpoint exists. |
| fixed, bounded | Caller-asserted Chameleon bootstrap invariants and receipt references | Fixed at the semantic boundary: normalization now requires a source-owned decoded payload, an authenticated invariant witness, a content-addressed source-acknowledged allocation, and the exact branded grant. RF and mode assurance remain explicitly pending/not-observed, and the fixture allocation has no production or execution authority. |
| fixed, bounded | No provider-neutral physical inventory checkpoint contract | Fixed only at fixture-contract level. The exact three-operation receipt set, live connection/trust disposition, signed time, invariant witnesses, and four-axis assurance are normalized, but the projection explicitly has no lifecycle or execution authority and cannot satisfy production HIL. |
| accepted-residual | Dispatch/fence, native isolation, containment, resource semantics, durability, composition, scaling, assurance, ABI, and packaging gaps | Accepted as detailed below. These remain release blockers where the hypergraph says they are blockers. |
| accepted correction | PH-C9 calls a simulated fixture “HIL” while also being production-nonwaivable | Accepted. The simulation is engineering evidence, not production HIL evidence. |
| qualified | The graph is too broad and cyclic to implement effectively | Staged profiles are warranted, but the explicit full-closure graph remains valuable. Its blocking dependency topology is intended to be acyclic; operational feedback/recovery loops are not dependency cycles. |
| rejected/qualified | Bob hides the absence of native I/O or should bypass gates when operating aggressively | Rejected as stated. The code advertises the native gap. Aggressiveness can affect authorized search strategy, not scope, authority, safety, or evidence gates. |

## Fixed

### 1. Fresh installs now include nested Plane-PH runtime packages

`scripts/install.js` now calls the registry-driven
`copyCanonicalRuntimePackages()` path. `scripts/lib/package-policy.js` is the
single admission authority for these four package roots:

- `packages/bob-artifact-vault`
- `packages/bob-instrument-broker`
- `packages/bob-instrument-chameleon`
- `packages/bob-instrument-deterministic`

Only package metadata, declared root entry points, and flat `lib/*.js` runtime
files are admitted. The installer clears each Bob-owned destination subtree
before copying, preventing removed modules or test fixtures from surviving a
reinstall. `test/install-smoke.test.js` compares every installed nested-package
file against the admitted source surface, checks that broker runtime modules
such as `resource-reservations.js` exist, and checks that package test
directories are absent.

This closes the fresh-install relative-import failure. It does not supply a
native serial driver, worker isolation, or HIL evidence.

### 2. Request-registry tests are part of normal discovery

`packages/bob-instrument-broker/package.json` explicitly runs
`test/resource-request-registry.test.js`. The root broker aggregator
`test/instrument-broker.test.js` requires that suite, and
`test/mcp-test-discovery.test.js` maps
`lib/resource-request-registry.js` to the root guard.

The fix is test discovery, not production admission integration.
`physicalResourceArbiterAdmissionReadiness()` still reports
`production_ready: false` and identifies the missing authenticated, durable
request-registry binding.

### 3. Transferred-before-effect cancellation is now private and one-shot

`packages/bob-instrument-broker/lib/physical-provider-dispatch.js` now issues a
private branded cancellation capability. Cancellation can be armed only while
the transferred reservation is exactly `held` and `not_started`; it exposes no
raw credential or fence, consumes an ordinary command at most once, and repeats
the exact reservation/effect authorization check inside the scheduled provider
callback. Ambiguous completion remains fail-closed and non-replayable.

`mcp/lib/physical-resource-graph-coordinator.js` keeps the capability in private
handle state. Under the session lock it arms the bridge, tombstones or
invalidates the TaskGraph reservation, then performs one broker close or
explicit expiry. Tests cover before-effect cancellation, after-effect refusal,
failed-start cancellation, exact tombstone retry, lost acknowledgement,
ambiguous close, and entry-gap revalidation.

This closes the transferred-before-effect race in the current same-process
design. Dispatch readiness remains honestly false because the durable active
lease fence, OS watchdog, process custody, cleanup boundary, and HIL are not
integrated.

### 4. Reservation compaction binds exact ancestry

`packages/bob-instrument-broker/lib/resource-reservation-attestations.js` now
binds sorted, bounded sets of reservation tombstone digests, compacted source
record digests, and terminal record digests into each checkpoint. Validation
requires monotonic ancestry, exact predecessor checkpoint generation/digest and
state, and an exact match between each new compaction batch and previously
signed terminal members. Tests reject rewritten tombstones, detached prior
batches, and invented source records.

This hardens reservation-history compaction. It does not remove the separate
capacity and whole-projection costs in the request registry, arbiter, lease
store, experiment ledger, vault, or SurfaceGraph.

### 5. The HF14A compiler is closed, source-pinned, and non-executing

`packages/bob-instrument-chameleon/lib/hf14a-probe-compiler.js` accepts exactly
two versioned semantic schemas:

- `iso14443a.requa_atqa_v1`
- `iso14443a.wupa_atqa_v1`

They compile to fixed command-2010 frames with a six-byte provider payload,
seven-bit request, 100 ms timeout, source-pinned v2.2.0 digests, and no public
byte material. The input object is closed; raw commands, frames, RF options,
timeouts, payloads, hostile getters, symbols, and sparse inputs are refused.
Only the provider-private worker encoder can recover the fixed bytes from a
branded compiler result.

The manifest deliberately says
`runtime_availability: "unavailable_pending_hil_conformance"`, binds the exact
`enrolled_conformance_tested` assurance profile and distinct
`conformance:chameleon_hf14a_closed_probe_v1` proof dependency, and retains
`execution_authority: false`. REQA and WUPA map bijectively to separate
availability variants. The package export map does not expose the compiler
subpath, command 2010 remains outside the compiled codec profile, and
`CU-HF-14A-COMPILED-PROBE` remains `planned` in `operations.js`. This is a
correct negative-only semantic/HIL contract, not a runnable RF feature or HIL
result.

## Fixed, bounded follow-on slices

### Supported physical-only canonical bootstrap

`bob_init_physical_session` is now a registry-generated, orchestrator-only
initializer whose public schema accepts one namespaced opaque
`physical-scope-import:*` reference. A private synchronous resolver supplies
the authenticated envelope, verifier, effect-template registry, and session
namespace; none of those authority-bearing objects enters the MCP request or
response.

The initializer derives a collision-checked `physical-<digest>` session id,
persists only the compact physical authority axis in canonical state and the
session nucleus, and brackets creation with a durable pending/complete
bootstrap journal. Verified reads reject symbolic links, hard links, identity
swaps, oversized files, and unstable session-directory identities. Exact
retries do not resolve or consume the import again, while pending or incoherent
state requires operator recovery. Ordinary coherent nucleus mutations retain
the immutable physical axis.

Physical-only authority cannot authorize HTTP, browser, smart-contract, or
repository/container execution. Repository tools now declare a registry-driven
`required_session_axes: ["repo"]` constraint with explicit all-of semantics.
`SETUP -> OPEN_FRONTIER` remains unconditionally blocked by
`physical_inventory_required`; neither generic seed surfaces nor
`operator_force` can waive it.

This is an effect-free front door, not an operational device path. The default
resolver is unconfigured, no external grant-issuer adapter is shipped, and a
process death inside the replay-consuming import call before it returns cannot
yet rehydrate the external projection. That case remains fail-closed.

### Fixture-only inventory checkpoint and Chameleon response evidence

`mcp/lib/physical-inventory-checkpoint.js` now defines an exact, provider-neutral
fixture checkpoint over `instrument.inventory`, `instrument.capabilities`, and
`instrument.health`. It binds the session nucleus, physical axis, instrument,
enrollment candidate, provider/binary/transport/manifest, connection
generation, all three execution receipts, authenticated invariant witnesses,
signed-clock validity, live revocation/disconnect state, and a four-axis
assurance vector. Its source and projections say `production_ready: false`,
`hil_attested: false`, `lifecycle_authority: false`, and
`execution_authority: false`; no generic production-current assertion exists.

The Chameleon bootstrap response normalizer no longer accepts raw RF/mode/
workspace assertions or caller-selected observation and receipt references.
It consumes only branded source-decoded payloads, authenticated witnesses,
content-addressed source-acknowledged allocations, and the exact signed grant.
Command 1002 remains outside the bootstrap allowlist, so device mode is
reported as not observed and RF continuity remains pending independent
observation/HIL. The workspace no-write statement is only the consequence of
the closed command-effect manifest. These projections cannot clear the
physical inventory lifecycle gate.

## Accepted residuals

### 1. Two dispatch and fence lineages are not yet one production seam

The older broker path in `packages/bob-instrument-broker/lib/broker.js` owns its
durable attempt journal, dispatch record, lease checks, and provider ABI
`execute` call. The newer `physical-provider-dispatch.js` path consumes
`mcp/lib/physical-dispatch-authority.js` and the graph-coordinator reservation
bridge. The newer readiness projection still says
`durable_active_instrument_lease_fence_not_integrated` and
`same-process-callback-observation-unattested`.

The new cancellation work improves one lineage but does not prove that every
provider effect is forced through one durable, provider-redeemed fence. The
production design still needs one authority/dispatch/fence lineage and one
worker-owned raw-provider boundary.

### 2. No native OS-principal, device-ACL, immutable-worker, or real-HIL boundary

`packages/bob-instrument-chameleon/lib/usb-cdc-custody.js` explicitly states
that it has no serial/native USB dependency, performs no device discovery or
open, exports no read/write/transact primitive, and cannot turn same-process
callbacks into an OS boundary. Broker IPC readiness remains
`production_ready: false`; its blockers state that native peer credentials need
operator HIL, pathname checks do not replace native open-at custody, and pure
IPC conformance does not prove OS-principal or device-ACL separation.

Therefore JavaScript brands and closed objects are useful contract controls,
not proof that an agent principal cannot open the device, modify worker code, or
reach key/state custody directly.

### 3. No independent kill switch or deadman

`mcp/lib/instrument-safety-supervisor.js` models watchdog deadlines and bounded
containment callbacks, but those ports are constructed in-process. A confirmed
reset/kill callback intentionally leaves `emission_state: "unknown"`; the code
does not pretend a callback acknowledgement is an independent observation that
RF or another physical effect stopped.

Production PH-S7 still needs a separately hosted and powered stop/deadman path,
an independently observable terminal state, and HIL for process death,
disconnect, stuck calls, stale leases, failed reset, and power isolation.

### 4. The resource grammar conflates materially different semantics

`mcp/lib/physical-resource-contract.js` names batteries, consumables, controls,
instruments, observers, operator presence, power, RF bands/zones, target media,
thermal zones, and workspaces. All are nevertheless projected through one
reservation grammar with only `exclusive|shared` ownership,
`never|before_effect_only` preemption, and the same held/cleanup/released/fenced/
quarantined state family.

That is adequate contract scaffolding, but not a complete ontology for a
consumed quantity, replenishable capacity, continuous signal, signed
attestation, media custody, environmental envelope, and leasable device. These
need distinct accounting and terminal semantics before scheduling claims can be
considered general.

### 5. Experiment rows and their receipts are not one crash-atomic commit

`createPhysicalAppendIssuer()` reserves a journal sequence and then commits a
signed append receipt through separate caller callbacks.
`createPhysicalExperimentLedger().append()` subsequently rebuilds the complete
in-memory ledger and returns the accepted row. Its own comment assigns durable
row bytes to the caller's append journal, but the ledger exposes no transaction
that atomically commits the receipt and row.

A crash can therefore leave a reserved/committed append receipt without its row,
or require caller-specific reconciliation. Production evidence storage needs a
single durable publication protocol with an explicit recovery state for every
crash point.

### 6. Vault privilege separation, plaintext lifetime, and backup erasure remain

The artifact vault encrypts objects and indexes and requires a 32-byte master
key supplied outside the vault filesystem. However,
`createArtifactVault()` receives and derives all keys in the calling process;
worker access is a WeakMap/brand boundary in that process. Materialization and
the operator export channel necessarily produce plaintext buffers there. This
is not an OS-principal or hardware-backed key-custody boundary.

Backups are encrypted and authenticated, but an archive contains the then-live
index, wrapped data keys, and ciphertext objects. Current restore filters
deleted handles through the authoritative deletion ledger, which prevents a
normal rollback through that vault. There is no per-artifact backup key
revocation or archive-erasure operation that makes every previously created
backup independently unable to recover erased material. Production claims must
therefore distinguish current-store cryptographic deletion from backup-media
erasure and custody.

### 7. Physical-to-cyber edges are stored but intentionally prerequisite-ineligible

`mcp/lib/surface-graph.js` can verify signed physical transition receipts and
project their arcs. Every projected demonstrated transition currently returns
`prerequisite_eligible: false`. For live capabilities, even a currently trusted
receipt resolves to `live_revalidation_unavailable` because PH-S7 has not yet
provided the signed current custody/state projection.

This is safe and honest, but it means physical reachability does not yet unlock
downstream cyber work. PH-C9's intended fresh per-edge authority and actual
downstream-consumption proof remain roadmap behavior.

### 8. Scaling cliffs remain across the campaign state path

The implementations are bounded, but several bounds are exhaustion points or
whole-state work rather than scalable continuation:

- The request registry caps records at 4,096 and reports that proof-preserving
  compaction is not implemented.
- The arbiter admits as many as 65,536 queue tickets and repeatedly maps/sorts
  queue-wide projections.
- The lease store caps 100,000 events, 64 active leases, and a 32 MiB checkpoint
  plaintext. It still clones large projections and enumerates retained files.
- Every experiment append creates `[...state.rows, rowInput]` and calls
  `normalizeLedger()` across the full row history; live claim projection also
  revalidates the full ledger.
- The vault caps 4,096 artifacts and 128 MiB and materializes authenticated
  indexes and backup object inventories in-process.
- SurfaceGraph reads, parses, maps, sorts, and rewrites the JSONL record set;
  its 1,000-edge query cap limits output, not the preceding full-file work.

These are legitimate fail-closed ceilings. They are not yet the linked,
proof-preserving campaign segmentation promised by PH-S12.

### 9. `conformance_tested` is now a negative-only HIL contract

The Chameleon assurance lattice now has the distinct
`enrolled_conformance_tested` profile, used only by the provider-neutral
`protocol.discovery_probe` operation. The two closed HF14A variants additionally
require `conformance:chameleon_hf14a_closed_probe_v1`, whose contract binds the
provider binary, exact source/firmware/transport/compiler/fixture material, the
provider registry and fixture epoch, and an owned HIL run. The compiler proof
and generic frame-codec proof cannot substitute for it.

No HIL verdict is shipped, and command 2010 remains absent from the compiled
codec profile. Consequently even a structurally accepted conformance claim and
proof projection leaves both variants unavailable and authority-free. The next
step is a real signed HIL producer, not another profile-string change.

### 10. Provider ABI v2 lacks first-class continuous-instrument semantics

`mcp/lib/instrument-provider-contract.js` exposes the unary lifecycle methods
`describe`, `inventory`, `capabilities`, `prepare`, `snapshot`, `execute`,
`status`, `stop`, `reconcile`, `restore`, and `health`. There is no first-class
stream, hardware trigger, shared timebase, calibration, or producer/consumer
backpressure contract.

Those concerns can be hidden in provider-specific parameters today, but then
multi-instrument scheduling, synchronized observation, loss accounting, and
portable conformance cannot be proven at the provider-neutral boundary. The ABI
needs versioned optional interfaces rather than vendor-specific core branches.

### 11. Cross-plane live revalidation is absent

The legacy composition verifier has strong execution-keyed replay and binding
checks for its existing surfaces. The physical SurfaceGraph adapter does not yet
resolve current physical state/custody, intersect fresh authority per edge, or
prove downstream consumption under that current state. Its explicit
`live_revalidation_unavailable` result is the correct fail-closed behavior.

PH-C9 should reuse the existing executed-evidence and composition concepts, but
must add a physical current-state resolver and per-edge authority adapter. A
historical verified transition is evidence that something happened, not a live
capability token.

### 12. Runtime packages remain monorepo-coupled

The broker, deterministic provider, and Chameleon modules import contracts by
relative paths such as `../../../mcp/lib/...`. The installer fix deliberately
reproduces this repository layout, which makes fresh installs work, but package
independence and third-party provider version negotiation are not proved.

Provider authoring still depends on Bob's monorepo topology and exact core
contract implementation. A stable contract package, compatibility policy, and
orthogonal provider install/conformance proof remain necessary before claiming
a provider ecosystem.

## Accepted correction: PH-C9 simulation is not production HIL

`docs/plane-physical/nodes.json` places `PH-C9` in
`production_nonwaivable_hil_node_ids`, with its HIL state still `pending`. The
same node's HIL gate says only: a simulated physical-to-cyber fixture proves two
effects and composes their bound edge.

That fixture can be valuable engineering evidence for adapter shape, binding,
negative controls, and causal composition. It cannot prove real physical state,
custody, timing, device behavior, independent observation, or the transition
into an actual downstream surface. The present gate text must be treated as an
engineering gate or renamed simulation gate. Production PH-C9 HIL must use an
owned fixture with a real physical transition, a real downstream effect,
independent evidence for both, current-state/custody revalidation, and fresh
authority at the consumption edge.

No simulated result should populate a production-nonwaivable HIL evidence slot.

## Qualified and rejected conclusions

### Staging is warranted; deleting the full-closure graph is not

The checked documents contain 48 nodes, 41 blocking hyperedges, 22
production-nonwaivable HIL nodes, and one sink, `PH-X8`. Every engineering gate
remains pending, and each of those 22 HIL gates remains pending. That is too much
to expose as one all-or-nothing operator feature and makes dependency,
observation, containment, and recovery feedback loops hard to reason about
operationally.

The stronger conclusion that the graph itself is invalid does not follow. Its
blocking topology is explicitly a dependency DAG with a single release sink;
the “cycles” of inventory, act, observe, reconcile, restore, and re-inventory
are runtime causal/recovery loops. Keeping full closure explicit prevents a
narrow demo from being confused with production readiness. Staged profiles
should name the verified subset while `PH-X8` remains the full release verdict.

### “No native I/O” is an honest gap, not a hidden capability claim

The Chameleon custody module says imports do not discover or open hardware and
that a future native adapter and HIL are required. The compiler says execution
authority is false. Broker and IPC readiness say production is false. The
proper response is to implement and qualify the native boundary, not to score
the repository as though it secretly claimed live RF support.

### Aggressive operation does not supersede authority or evidence

Bob can be aggressive inside a signed, current scope: schedule breadth-first
coverage, keep testing after the first success, exercise bounded negative
controls, prioritize high-leverage transitions, and reopen unsupported cells.
It cannot treat test windows, asset/custody bounds, RF zones, irreversible
effects, restoration, stop authority, or independent verification as somebody
else's concern. Adjacency, a plugged-in Chameleon, and operator intent are not
execution authority. These constraints are what make aggressive research
repeatable and defensible rather than merely energetic.

## Dependency-correct staged delivery

The practical delivery sequence is:

1. **Contract scaffolding** — keep all execution disabled; close bootstrap,
   authority, resource, evidence, vault, provider, dispatch, and migration
   contracts with deterministic fixtures.
2. **Read-only inventory** — introduce an OS-isolated worker and real HIL for
   device identity, firmware/app version, capability intersection, battery,
   mode, slots, disconnect, and re-enumeration without RF emission.
3. **Controlled Chameleon USB** — qualify native custody, authenticated IPC,
   durable fence redemption, trusted time, independent stop/deadman, and
   ambiguity recovery. Still expose no general RF technique to the evaluator.
4. **Finding-capable RF** — enable only closed, conformance-tested semantic
   compilers on owned/shielded fixtures, starting with bounded discovery and a
   differential external verifier. Add mutation, emulation, recovery, and
   protocol families only with their effect, cleanup, residue, and HIL cells.
5. **Full Plane-PH** — close PH-C9 live composition, PH-S12 campaign scaling,
   PH-C10 pack/claim/report closure, orthogonal-provider conformance, failure
   matrices, packaging/migration, and every production-nonwaivable HIL gate at
   `PH-X8`.

This sequence maximizes useful hardware leverage while preserving Bob's core
architectural distinction: models choose authorized semantic experiments;
trusted infrastructure owns raw devices, effects, durable state, containment,
and proof.
