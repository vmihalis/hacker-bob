# Plane-PH fourth Brutalist adjudication

Review date: 2026-07-20

Brutalist context: `19240c8d-f0f8-4ee2-855e-709f335e88e0`

Server: `brutalist-mcp-server` 1.18.9 at `e56f31b`

Mode: architecture and implementation red-team, depth 3

## Evidence boundary

The server's default command timeout was verified as 7,200,000 milliseconds
before the review. Codex returned a substantive review after 1,719,070
milliseconds and Agy returned after 140,931 milliseconds. Claude failed after
about 4.2 seconds, then failed again after about 6.9 seconds in a narrower
security-only retry. Those failures are recorded as tool failures; they are not
votes. Agy's response discussed unrelated EVM, RPC, and out-of-band material and
assigned incorrect meanings to Chameleon commands 1000, 1017, and 1033, so none
of its unsupported claims are accepted as repository evidence.

The remaining Codex output is adversarial review input, not authority. Every
disposition below was checked against source and focused tests. Neither the
review nor its remediation enumerated or opened a Chameleon device, emitted an
RF operation, contacted a network or facility system, or exercised a live
credential. Production and hardware-in-loop claims remain false.

## Dispositions

| Finding | Disposition | Repository result |
| --- | --- | --- |
| An authenticated `ambiguous_quarantined` native record was discarded after an effect may have occurred | fixed, P1 | A complete ambiguous native record now commits through the existing encrypted, authenticated raw-custody journal before plaintext staging cleanup. Its private receipt exposes no bytes or paths, remains non-semantic and non-authoritative, and cannot mint expected-result success. Zero-byte observations are preserved too. Exact terminal-publication crash and lost-ack recovery return the same artifact. Rejected, malformed, drifted, oversized, partial, and lost-sink-commit inputs still fail closed. |
| Duplicate sink preparation unlinked a live inode it did not create and leaked its absolute path | fixed, P1/P2 | A failed `O_EXCL` duplicate now leaves the existing sink untouched and emits one stable path-free error. A later partial-preparation failure never unlinks: it leaves an inert orphan that blocks reuse because JavaScript cannot make path check plus unlink atomic against replacement. The hostile duplicate reject, exact-inode readback, third reject, original-port cancellation, partial-failure orphan, and redaction sequences are covered. Identity-safe orphan recovery remains an explicit production blocker. |
| PH-P7's five-command bootstrap sequence is only process-local | accepted, explicit promotion blocker | The exact command order and one-use guard are useful fixture evidence, but the `WeakMap` counter is not durable custody and is not bound to a native launch. Current non-authorizing operation stays closed; production promotion requires a durable journal/CAS owner. |
| Native dispatch omits parts of the compiled authority lineage | accepted, explicit promotion blocker | The compiler retains bootstrap and core grants, replay receipt, execution request, and compiled-operation digests. The current native ticket does not bind that complete identity. No production constructor exists, so the defect is fail-closed today and critical before promotion. |
| Exact response validators for commands 1017, 1025, 1033, and 1035 are missing | corrected | Source-owned exact decoders and ordered aggregate validation already exist for all five bootstrap commands. The real gap is that the vault-owned semantic registry and durable aggregate integration cover command 1000 only. |
| The production provider/worker/vault path can wait forever | accepted, promotion blocker | Conformance ports have a 300 ms race; production callbacks are awaited without a native watchdog. Transport, cancellation, restoration, terminal commit, and readback need monotonic deadlines, independent restoration, and reconciliation before a production constructor can exist. |
| The production composition root bypasses the worker/vault transaction | fixed in O0, fail-closed | The root revalidates its private dependencies and then rejects with `physical_technique_production_execution_spine_unavailable`. It cannot call the legacy callback dispatch or independently invoke a worker. A single private durable transaction owner remains the enabling blocker. |
| PH-X8 v2 can recommit after lost acknowledgement and is not used by release checking | accepted, open integration defect | v2 verdict authority is process-local and a repeated evaluation can publish sequence 2 rather than rehydrate sequence 1. The release command still invokes v1. Physical production stays rejected; exact candidate/evidence/basis idempotency and v2 release wiring are required. |
| The broker and vault are provider-neutral | narrowed, package-boundary debt | Requested-effect contracts and public technique abstractions are provider-neutral, but the generic broker exports a Chameleon executor and the generic response vault imports Chameleon validation code. Provider-specific code must move behind an immutable server-owned profile catalog before multiple providers are promoted. |
| Seven physical tool families cap the hardware plane | rejected as stated | The seven names are coarse operator-facing execution families, not the provider-operation catalog or technique registry. They may be refined for operator ergonomics, but they do not prove a capability ceiling. |
| Multi-instrument execution is complete because resource reservation is atomic | rejected as a completion claim | Resource reservation already atomically owns 1–64 resources. Shared trigger/timebase, calibration, loss accounting, and backpressure for synchronized instruments remain explicitly unimplemented. |
| The vault has neither limits nor streaming | corrected | Cardinality and byte quotas exist. Whole-buffer ingest, encryption, and materialization are real scaling limits; chunked authenticated streaming remains required for large SDR and trace artifacts. |
| SurfaceGraph append and query will not scale to campaigns | accepted, documented scaling blocker | It reads and reconstructs the complete JSONL graph and rewrites persistence on append. Repeated singleton appends become at least cumulatively quadratic. Segmented persistence and indexes are required before large-trace campaigns. |
| Composition proves downstream consumption | accepted as an overstatement risk | Composition explicitly reports `downstream_consumption_verified: false`, while another readiness field can say `production_ready: true`. PH-C9 correctly remains blocked. Production naming must stay subordinate to a server-owned receipt proving consumption of the exact current transition context. |
| The plane is release-ready without HIL | rejected and already prohibited | Static topology, package, and fixture gates do not substitute for current external principals, a connected Chameleon, authorized real-device traces, restoration evidence, or production-qualified durable owners. |

## Dependency-correct implementation order

1. Preserve post-effect ambiguity in durable raw custody. **Completed in this
   pass.**
2. Install one private `PhysicalExecutionTransactionOwner` as the sole effect
   path, with a durable lineage-keyed journal and phases equivalent to
   `CLAIMED -> GO_DURABLE -> EFFECT_ARMED -> EFFECT_RECORDED|UNKNOWN ->
   VAULT_COMMITTED -> RESTORING -> TERMINAL`.
3. Bind every PH-P7 sequence step and native launch ticket to the complete
   compiled authority identity, resource generation, lease, attempt, deadline,
   sink reservation, and replay identity.
4. Add native monotonic watchdogs, deadline preemption, independently runnable
   cancellation/restoration, terminal reconciliation, and exact outbox
   readback. Once an effect is armed, recovery must never replay the provider.
5. Register the existing five exact bootstrap decoders with the vault owner and
   commit one ordered aggregate receipt without exposing raw provider bytes.
6. Make PH-X8 v2 idempotent by candidate, evidence, and basis digest; rehydrate
   lost acknowledgements; then wire release checking to v2 without weakening
   the frozen production blockers.
7. Introduce signed immutable provider profiles and move Chameleon adapters out
   of generic broker and vault package surfaces. Profiles may select reviewed
   registry entries, never caller callbacks, module paths, signers, or parsers.
8. Require a server-owned downstream-consumption receipt before any physical
   production-readiness claim can be true.
9. Add synchronized multi-instrument execution, chunked AEAD vault streaming,
   and segmented/indexed SurfaceGraph persistence before broad high-volume
   hardware campaigns.

External signer enrollment, independent principal custody, real Chameleon
enumeration, authorized HIL, and restoration/containment witness evidence are
separate non-waivable dependencies. Software completion cannot synthesize them.

## Verification recorded in this pass

- Native provider-response vault: `21/21` under Node 20.19.4, including
  nonzero and zero-byte ambiguity, terminal-publication crash, lost
  acknowledgement, and duplicate preparation without inode removal or
  internal-path disclosure.
- Full artifact-vault package: `78/78` in the implementation pass.
- Fresh hostile acceptance: no P1/P2. Independent duplicate, partial-failure,
  and replacement-interleaving probes proved the original live inode is
  preserved, an unrelated replacement inode and its bytes are never unlinked,
  retries stay rejected, cancellation succeeds, and errors expose no internal
  root or capability-derived filename.
- PH-P7 native provider package: `97/97`; fresh hostile bootstrap, inventory,
  manual, dispatch, worker/vault, and clean-build matrices remained green in the
  preceding acceptance pass.
- Production composition root: focused `16/16`; broader composition,
  runtime, dispatch, and worker/vault group `52/52`.
- Root broad gate: syntax, plane coherence, authority inventory, portable
  physical packages, MCP, prompt, update, adapter, package, install, and CLI
  suites passed. The run stopped only at `release:check:clean` because this
  intentionally untracked Plane-PH worktree is dirty.
- `release:check`, policy replay, hooks, AgentCore, Darwin clean-build matrix,
  dry packaging, and `git diff --check` passed independently.

These results accept the ambiguity repair and the fail-closed O0 boundary. They
do not claim a production execution spine, durable PH-P7 sequencing, v2 release
integration, downstream consumption, external-principal evidence, connected
hardware, or HIL completion.
