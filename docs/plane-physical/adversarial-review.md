# Plane-PH adversarial architecture review

Date: 2026-07-17

Reviewed proposal: `v0.3-proposed`

## Verdict

Plane-PH is now potential-maximizing as an implementation roadmap, not yet as a
runtime. It reaches the right architectural leverage points in Hacker Bob, maps
the available Chameleon surface without making the device the core model, and
has one release sink spanning campaign scale, containment, HIL recovery,
packaging, migration, and an orthogonal provider proof. Calling Bob physically
capable before the PH2 trusted loop passes would still be false.

“Maximal” means authorized applicable-cell closure and verified downstream
effects. It does not mean exposing every device command, inferring firmware
support, treating a successful RF exchange as a physical outcome, or weakening
asset/effect authority.

## Review method

The graph was challenged against the actual Bob registry, session nucleus,
capability packs, TaskGraph, SurfaceGraph, scheduler, evidence, composition,
claim, grading, verifier, installer, and release paths.

The latest installed `@brutalist/mcp` v1.18.7 then ran a unified architecture
roast at depth 3 over the repository (context
`c14b0f58-cbb3-4a24-a2ee-46d01b544160`). Codex returned a substantive review;
Claude failed and Agy timed out, so this is one critic's output, not multi-critic
consensus. Three independent repository audits checked its authority/evidence,
Ultra/coverage, and TaskGraph/scaling claims. Only findings supported by direct
code or pinned upstream-source evidence were accepted; overstated cleanup and
direct-dependency claims were narrowed.

After those remediations, the v1.18.7 MCP roster remained responsive, but a
context continuation and two fresh regression roasts returned Brutalist's
sanitized internal-error response before any critic output. They add no opinion
and are not represented as a successful panel run. After the final hardening,
one additional three-critic roast and one Codex-only roast were started; neither
yielded critic output within the bounded review window, so both calls were
terminated and likewise add no opinion.

No Chameleon command or RF operation was executed during review.

## Defects found and resolved

1. **Mock/broker dependency deadlock.** The broker gate required a mock operation
   while the mock depended on the broker. `PH-P0` is now a pure provider-ABI mock
   after `PH-S4`; leases and the broker build on it.
2. **Unsafe first-command ordering.** USB inventory was scheduled before the
   semantic command/effect manifest. `PH-P8` is now a tiny read-only bootstrap
   allowlist; `PH-P7` is the sole first hardware operation. Active admission is a
   separate `PH-X6`, containment integration is `PH-X7`, and `PH-C1` is the
   first target-facing RF node.
3. **RFID-shaped effects.** Flat `LR/LW/RR/RE/TW/PT/DA` codes conflated action,
   channel, persistence, administration, destruction, and verified outcomes.
   Plane-PH now uses structured effect templates plus exact per-run bounds;
   outcomes are verifier-owned and separate.
4. **Stable secret identifiers.** Content hashes of low-entropy card identifiers
   are guessable and correlate engagements. Public references are now random,
   scoped handles; vault-only digests and engagement-keyed HMACs support
   integrity/comparison.
5. **Policy-theater broker isolation and ambiguous signing custody.**
   Authenticated same-UID IPC did not prevent bypass, and a monolithic broker
   could both mint authority and exercise it. Real hardware now separates an
   issuer that owns the grant key but cannot open hardware from an execution
   worker that owns the device and a distinct receipt key but cannot mint a
   grant. Both are inaccessible to the agent; epochs, generations, rotation,
   and revocation fail closed. Same-UID mode is mock-only.
6. **Over-broad cleanup.** Post-scope cleanup could have become a mutation/admin
   escape hatch. Cleanup is now a precommitted, nondelegable compensating
   capability; administration/destruction are never cleanup, and external-media
   rollback is separately authorized or quarantined.
7. **Mutable experiment rows and claim/cleanup conflation.** A later verdict
   could mutate the object whose hash was meant to bind the run, while cleanup
   failure could erase a proven outcome. The immutable experiment plan now binds
   `session_nucleus_hash` and `execution_request_digest`; execution,
   observation, claim, and cleanup are separate append-only signed rows joined
   by a rebuildable index. Failed cleanup stops active work but does not rewrite
   fact.
8. **Credential-centric ontology.** The original types did not genuinely admit
   USB, SDR, GPIO, optical, sensors, or actuators. The base ontology now includes
   interface, medium, signal source, actuator, control point, verifier,
   enclosure, and zone; credentials/readers are specializations.
9. **False composition reuse.** Bob's existing live composition is specialized
   for HTTP and smart-contract sources. `PH-S10` now extracts executed-evidence,
   execution-context, and replay-executor adapters while retaining specialized
   adjudicators. A physical bind path has no `base_url`/`httpScanFn` dependency
   and binds the exact verdict, execution identity, and downstream context that
   consumed it.
10. **Web-shaped coverage and untrusted closure.** Physical coverage cannot use
    endpoint/method/bug/auth cells or agent-authored completion refs. `PH-I3`
    provides pack-declared physical dimensions and requires broker/verifier
    witnesses. Repeated blocking never auto-counts as covered.
11. **No scarce-resource scheduling.** Bob's scheduler had no instrument,
    workspace, mode, observer, or exclusive-lease model. `PH-S11` now anchors
    the real graph scheduler and contract hash, adds resource requirements,
    broker reservations, fencing tokens, stale-graph rechecks, and deterministic
    compatible batching so one Ultra drives progress instead of retry thrash.
12. **Web-shaped findings and grading.** Physical proof cannot safely fit an
    endpoint plus raw PoC. `PH-C10` now anchors the actual claim contracts and
    record/freeze/verify/grade/finalize path and requires pack-declared claim,
    evidence, verdict, grade-gap, replay, and report-safe rendering adapters.
13. **Incomplete and non-mechanical hardware accounting.** Coverage originally
    omitted trace/config/codec/diagnostic paths and several destructive
    variants, then relied on prose rather than exact ownership. The registry now
    gives every one of 146 declared command IDs plus private ID `6010` one
    primary disposition, models the three declared-but-unregistered IDs, and
    checks the pinned Ultra runtime formula (`146 - 3 + 1 = 144`). Higher-order
    techniques remain explicitly derived rather than inventing command IDs.
14. **Self-asserted observer independence.** A submitting evaluator could have
    labeled two feeds as separate trust domains. Observer keys and identities
    are now operator-enrolled; the server derives trust domains and checks
    plan/challenge binding, sequence, rotation, and revocation.
15. **Vault as encrypted storage, not a secret-execution boundary.** Host
    recovery tools would still have needed raw keys/nonces. `PH-S5` now requires
    separate vault key custody, randomized encryption, keyed comparison tokens,
    handle-in/handle-out allowlisted transforms, and a distinct authenticated
    operator export channel.
16. **Applicability/scheduling inversion.** `PH-I3` claimed a cell was
    resource-schedulable before the resource scheduler existed. It now requires
    declarations only; `PH-S11` and active admission prove current
    schedulability and reservation state.
17. **Status theater.** A task could be labeled `done` while its prose gates had
    no evidence. `gate_tracking` and the validator now require engineering
    evidence and, where declared, HIL evidence or a signed waiver.
18. **Restoration overclaim for irreversible techniques.** A destructive
    authorized variant cannot honestly restore all media. Capstone closure now
    requires zero active leases and no unexplained residue; a verifier-bound,
    operator-authorized irreversible terminal state is explicit and does not
    masquerade as restoration.
19. **Execution grant not bound to Bob's dispatched task.** The evaluator role
    can carry a broad generated tool union and Bob's existing invocation check is
    partly finalize-time. Grants and admission now bind the node, Contract, prep
    token, dispatch event, graph context, pack/version/digest, technique cell,
    caller/requester/execution principals, attempt, and experiment plan; issuer
    and worker both revalidate those fields before hardware opens.
20. **Evidence contracts promised signatures without carrying them.** The
    concrete observation lacked signer/signature and exact execution-attempt
    binding; the plan lacked hypothesis, expected outcomes, verifier version,
    decision rule, observation window, and retry identity. The schemas now carry
    those fields, mint a fresh attempt/challenge per retry, and distinguish a
    historical event from a live custody-bound capability.
21. **Typed raw/APDU access was still a semantic escape hatch.** Packet length,
    protocol state, and teardown do not stop a valid state-changing instruction.
    Raw frame/APDU primitives are now provider-private; evaluators receive closed
    versioned technology/application/AID/opcode compilers with canonical-byte
    digests and worst-case effects. No generic evaluator or operator passthrough
    exists; new bounded schemas require reviewed registry extensions.
22. **Validator accepted semantic swaps and bogus refs.** A direct negative probe
    showed that swapping command IDs `2000` and `2010`, inventing an operation,
    and using `"bogus"` gate refs passed v0.2. v0.3 pins canonical ID-to-owner and
    full coverage-semantic digests, closes operation/technique registries, and
    restricts package-safe evidence/waiver URI schemes. Runtime advancement must
    still resolve and verify the signed object; syntax alone never proves a gate.
23. **Exhaustive closure exceeded Bob's ledger architecture.** A successful cell
    consumes at least seven frontier events, TaskGraph folds refuse at 18,000,
    and other ledgers trim at 20,000/5,000. `PH-S12` adds cardinality preflight,
    bounded linked segments, shared-nucleus signed/Merkle closure roots, aggregate
    no-gap/no-duplicate reconciliation, and above-limit fixtures. An unlinked
    session split is not proof continuation.
24. **RF bounds and persistent read/auth effects were incomplete.** Every RF
    profile now requires duration, attempts, band, power ceiling, duty cycle,
    zone, containment, and deadline. Mutate/destroy adds state-delta and
    cleanup/residual/terminal plans. Ultralight/NTAG, DESFire auth, EMV, and raw
    primitives declare counter/log/lockout worst cases instead of laundering
    them through `target.transmit`.
25. **Key custody and stop authority were not exhaustive.** Existing issuer/
    worker isolation survived review, but cleanup, verifier, observer, vault,
    journal, and enrollment stores lacked a complete ACL matrix. The roadmap now
    assigns every principal/key/store operation, provisions rotation/recovery/
    anti-rollback, and tests forbidden access through shell indirection,
    descriptors, links, backups, and crash artifacts.
26. **Revocation did not stop a running operation.** Provider cancellation on the
    same failed path is only best effort. `PH-S7` and `PH-X7` require fsync-before-
    effect journal/outbox ordering, signed bounded stop acknowledgements,
    independent deadman/fencing/kill/reset or explicit operator containment,
    startup status reconciliation, and no automatic retry from ambiguous state.
    Cleanup uses a distinct narrow safety root rather than contradicting active
    authority-epoch invalidation.
27. **Resource scheduling was one-instrument shaped.** `PH-S11` now reserves an
    all-or-none bundle across instruments, target media/custody, observers,
    controls, operator presence, RF zone/band, budgets, power, battery/thermal,
    cooldown, and setup cost with TTL, total lock order, rollback, deadlock
    avoidance, fencing, and starvation bounds.
28. **Firmware and transport assurance were overstated.** P7 is now an inventory
    and provenance observation with `self_reported`, `operator_provisioned`, or
    `hardware_attested` assurance. The v2.2.0 source ceiling is 4096 bytes while
    the public protocol page is stale at 512, so the codec uses fixed version
    profiles rather than invented negotiation. BLE boundary behavior and full
    effect parity are split across P6 and X5.
29. **Manual and write-only evidence was under-modeled.** Button actions have no
    command ID and now require a pinned semantic source/procedure plus operator
    and independent witness receipts. Ultra T55xx write emission and OK response
    are not read-back; verification requires an independent assurance-qualified
    reader.
30. **No release convergence or complete migration task existed.** Packaging now
    depends on redaction, per-technique HIL includes recovery/C2/C3/C8, and
    `PH-X8` joins C10, X3, X4, X5, S12, and X7. It owns versioned governance,
    TaskGraph, SurfaceGraph, pack, composition, finding, old-session, successor-
    nucleus, rollback, and unknown-version behavior.
31. **Vault lifecycle and packaged evidence overlays were absent.** `PH-S5`
    adds pre-stimulus capacity reservation, disk-full backpressure, retention,
    audited deletion/cryptographic erasure, safe GC, backup, corruption, and
    recovery. Design JSON may ship; live gate/HIL/vault overlays must remain in
    user-owned session state and pass release sanitization.
32. **Genericity was designed but weakly proved.** C1–C7 are explicitly the RF
    credential reference vertical. X4 now requires an orthogonal two-instrument
    GPIO/optical or equivalent SDR fixture through authority, atomic scheduling,
    vault, pack, verifier, reachability, composition, claim/report, packaging,
    install, and doctor paths.
33. **Hypergraph semantics were overstated, not broken.** All dependencies are
    conjunctive and each target has one incoming blocking clause, so flattening
    preserves current readiness. The files now call this a conjunctive
    implementation-dependency hypergraph; runtime any-of/quorum/conditional/
    reopen semantics belong to signed pack, experiment, and resource contracts.
34. **Derived capabilities could float free of their primitives.** Every
    supported capability now has digest-bound schedulable variants over exact
    command predicates, primitive capabilities, proof providers, and manual
    procedures. Validation rejects gaps, unknowns, unsupported refs, semantic-
    union drift, command omissions, and variant cycles.
35. **Assurance and grants were too coarse.** Assurance is now a four-axis
    profile over identity enrollment, firmware provenance, command-surface
    conformance, and transport trust. Grants additionally bind inventory,
    assurance, provider manifest, transition set, resource bundle, fencing
    token, and workspace snapshot, and workers revalidate them before effects.
36. **Vault, manual, and physical-proof paths were incomplete.** Active and
    cleanup workers now receive one-time plan/grant-bound vault bridges; `PH-P9`
    supplies an operator-mediated manual-action adapter; release-critical HIL
    gates are explicitly non-waivable for a production-ready verdict.
37. **The physical schema was RF-centric.** A versioned unit-aware quantity
    registry, spatial-envelope bounds, and canonical stimulus-sequence bounds
    make GPIO, optical, acoustic, SDR, coupling-distance, and temporal/state
    experiments representable without introducing evaluator passthrough.
38. **Bootstrap authority was circular.** A closed grant union now separates
    bootstrap, preparation, active, and operator-maintenance authority. The
    bootstrap grant cannot require the inventory it produces; preparation can
    create the first RF-off snapshot; active grants require both prior outputs.
39. **Multi-command rows overclaimed availability.** Forty-four supported rows
    now expand to 112 digest-bound schedulable variants. Every operation,
    technique, effect profile, and owned command is covered exactly; MFC
    recovery, EMV acquire/replay, LF formats, emulation profiles, and
    administration are independently resolvable.
40. **Named proof predicates were not evidence.** Compiler, conformance,
    observer, transport, and vault-tool refs now resolve through a closed
    registry binding owner principal, artifact/tool digest, verdict type, trust
    epoch, freshness, and revocation. Unresolved or unused entries fail closed.
41. **Administration could not reach an honest terminal state.** Persistent
    settings/DFU/BLE and irreversible erase now require owned-fixture pre-state,
    backup, exact delta, expected terminal state, post-operation inventory,
    assurance invalidation, recovery/quarantine or disposal custody, and HIL.
42. **Reviewed gates were mutable underneath evidence.** Closed node/hyperedge
    schemas and reviewed semantic digests now make gate or topology drift fail
    validation. Production HIL membership is independently pinned; runtime
    evidence must bind the exact node-contract digest and still be resolved and
    signature-verified from Bob-owned state.
43. **Recovery availability did not prove a recovery implementation.** Classic
    nonce/challenge variants could bind a recovery technique using only device
    commands. Every recovery family now requires its exact allowlisted
    vault-tool proof, including trace, autopwn, and destructive MFU recovery;
    swapping in an unrelated vault proof fails validation.
44. **Generic capability dependencies made variant selection ambiguous.** A
    snapshot could have satisfied the clone button's workspace dependency, and
    a destructive T55xx technique had no exact write primitive. Generic
    capability refs are now forbidden. All dependencies name exact variants;
    DESFire alternatives are an explicit `any_of`, and selected dependency
    variants and formula digests bind transitively into the plan and grant.
45. **MFU acquisition collapsed materially different effects.** Plain reads,
    authenticated reads with persistent counter state, and terminal-risk
    authentication paths shared one selector carrying transmit, mutate, and
    destroy authority. They are now three independent variants whose exact
    operations, effects, and family-specific mandatory vault dependency are
    grant-bound and independently protected by provider safety guards.

## Architecture that survived review

- Device commands remain below normalized operations and generic techniques.
- Slots are provider workspaces, not credential assets.
- Active HF “sniff” is modeled as target presentation; LF capture is active RF.
- Physical authority extends the existing hash-bound session nucleus.
- TaskGraph owns hypotheses and work; only verifier-approved outcomes project
  demonstrated SurfaceGraph transitions.
- Bob stays aggressive after the first finding and closes every authorized,
  applicable cell to a trusted terminal disposition.
- Hotel, campus, room, controller vendor, and optional timing constraints remain
  engagement data rather than core ontology.

## Claims that remain prohibited

The current attached unit has not been queried. Upstream v2.2.0 is an acceptance
ceiling, not installed-firmware evidence. The graph does not prove that the
broker, vault, physical pack, verifier, scheduler, campaign partitioner, safety
supervisor, Chameleon provider, migration path, claim adapters, or HIL gates
exist. Only implementation plus resolved, signature-verified node-specific
review evidence may advance those tasks to `done`.
