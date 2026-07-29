# Plane-PH second Brutalist adjudication

Review date: 2026-07-19  
Repository adjudication updated: 2026-07-20  
Brutalist context: `08a6a18a-d98c-41cc-a7ee-2ef39ec10355`  
Mode: architecture and implementation red-team  

## Evidence boundary

This was not a panel consensus. Codex returned the substantive review; the Agy
request exceeded its usable prompt surface and Claude failed internally. The
surviving output is adversarial input, not evidence. Every disposition below
was checked against repository code and tests.

No Chameleon command, USB transaction, RF operation, network request, hotel or
facility system, credential, or target was exercised while applying these
changes. The physical capability pack remains non-dispatchable and production
HIL remains non-waivable.

## Dispositions

| Finding | Disposition | Repository result |
| --- | --- | --- |
| Generic public `node.transitioned` writes and stale TaskGraph transitions | fixed | Transition events now use the sanctioned locked compare-and-append path. Generic frontier append rejects transition events; replay ignores orphan, jump, and stale transitions. |
| Network, browser, chain, and temporary-email tools could escape a physical-only or wrong-axis session | fixed | All 53 external-access tools require `target_domain`, disable global preapproval, and declare the exact URL/contracts axis. Repository tools require the repository axis. Registry construction rejects an external tool without those invariants. |
| Physical frontier provenance could be dropped and then routed through web fallback | fixed | Surface materialization preserves physical provenance and required-pack metadata. Missing, malformed, duplicate, and tombstoned routes quarantine and deny tools, technique packs, wave briefs, and dispatch. |
| Transferred provider reservation could outlive a generic TaskGraph reaper | fixed, bounded | The coordinator holds a reservation-bound TaskGraph head fence and revalidates dispatch/preparation immediately before the broker seam. The guarantee is cooperative and same-process; crash and uncooperative cross-process writers remain production blockers. |
| Provider callback could self-assert `completion: confirmed` | fixed, bounded | Definitive provider outcomes now require an exact branded synchronous verify/commit/readback port. Evidence binds the reservation and receipt fences, TaskGraph head, provider/device/custody, command/input/capability/effects, and committed receipt; lost replies recover only by exact readback and never replay the provider. The callback-backed conformance port is explicitly non-production until an independently attested durable backend exists. |
| Independently reconstructed physical experiment ledgers could fork | fixed, bounded | Append issuance now has exact reservation/receipt readback, and the ledger requires a shared synchronous compare-and-append head with exact row/receipt binding and lost-ack reconciliation. Only a test adapter exists; no production durable backend is claimed. |
| Native CI silently skipped Darwin-only qualification | fixed | Portable Linux still runs installer and CLI coverage. A required Node 20 `macos-14` lane runs the Darwin native/source qualification aggregate and release publish depends on it. This is not hardware HIL. |
| Reinstall retained deleted Bob-owned runtime files | fixed, bounded | The wholly Bob-owned `mcp/lib` root is exact-converged. Mixed top-level `mcp/*.js` retirement uses a bounded ownership receipt and identity/digest checks while preserving foreign or locally modified files. The `mcp/lib` replacement remains pathname-based and non-crash-atomic. |
| Native optional-provider install still admitted the four-role v1 topology | fixed | The lifecycle now verifies only the domain-separated six-role v2 envelope, installs lifecycle and dispatch custodians, and explicitly rejects a v1 envelope. |
| Signed ABI and durable-exchange schema references were not installed or counted | fixed | The optional lifecycle requires all 28 manifest-bound component/exchange schema artifacts in addition to the six native roles, verifies their exact bytes and mode, and rejects missing, executable, or extra schema payloads. |
| Receipt/outbox durability authenticated caller-shaped claims rather than exact durable bytes | fixed, bounded | Reconciliation now requires a privately branded synchronous strong-readback port and treats the exact canonical journal, outbox, and durability bytes as authoritative. Store identity, generation, offsets, sequences, heads, and GO/effect correlation are verified; the sole non-exact caller transcript is the exact lost-ACK prefix, which permits delivery recovery but forbids effect replay. The JavaScript port remains a non-production fixture. |
| Availability accepted caller-asserted command, assurance, and dependency-proof claims | fixed, bounded | Availability now accepts only branded resolver-issued evidence that binds manifests, inventory/device/custody/session/authority identity, reported commands, assurance axes, and dependency owner/artifact/epoch/verdict/freshness/revocation state. Plain, lookalike, cross-context, stale, revoked, weak, asynchronous, or alternative-selection fabrication fails closed. The only resolver factory is explicitly test-only and cannot set runtime readiness, evaluator callability, or execution authority. |
| Public codec profile allowed arbitrary source-pinned v2.2.0 command bytes | fixed, bounded | The public codec surface exposes metadata only. Its encoder admits only the five closed zero-data bootstrap commands; the v2.2.0 command table is no longer an encoder authority. A package-private compiled-command capability is still required at the worker custody seam for reviewed non-bootstrap compilers. |
| Dependency copy is atomic and crash-safe | accepted residual | Current dependency-tree installation has bounded preflight and mutation checks but is not a single atomic filesystem transaction. Documentation and readiness must continue to say so. |
| Future native lifecycle-custodian substitution is already production-safe | accepted residual | The production custodian cannot yet admit the required `mcp/lib` selection or prove the required image/openat binding. Node fallback deletion is not production custody. |

## Still-open production blockers

The fixes above do not make Plane-PH production-ready. At minimum, the
following remain open:

- independently attested production backends for provider completion,
  experiment heads, receipts/outboxes, replay state, and key custody;
- process-preemptible provider execution rather than a same-event-loop timeout;
- one coherent broker/native dispatch lineage instead of parallel fixture
  lineages;
- external artifact-vault key custody, rotation, and a backup/erasure contract
  that cannot resurrect cryptographically erased material;
- a full semantic compiler/provider bridge for every advertised enabled
  operation. The public v2.2.0 raw encoder is closed, while the package-private
  compiled-command/custody boundary and exhaustive reviewed compilers remain
  incomplete;
- a production signed proof-provider and availability verifier backend. The
  semantic resolver now enforces current revocation/freshness and exact
  evidence bindings, but its only implementation is deliberately test-only;
- closed optional worker dependency installation without ambient `serialport`
  or sibling-package resolution;
- real Developer ID/notarized immutable native artifacts, dedicated principals,
  ACL/device custody, native journal/outbox ownership, and post-exec capability
  transfer;
- RF-off HIL, authorized owned-fixture active HIL, negative principal/device
  matrices, cleanup/quarantine fault injection, USB/BLE parity, and cross-plane
  composition evidence;
- final broad MCP, prompt, install, package, clean-release, and full portable
  gates after all concurrent changes settle.

## Verification recorded so far

- TaskGraph, routing, and related focused integration: `281/281`.
- Session-axis authority selected suites and generated checks: green.
- Instrument broker after the provider-completion and authenticated-exchange
  convergence: `301/301` on Node `20.19.4`.
- Provider completion plus authority/coordinator focused integration: `53/53`.
- Chameleon availability trust-boundary tests: `11/11`; the full Chameleon
  package was `160/160` before the concurrent private-command seam edit.
- Physical experiment contract after the atomic-head change: `22/22`.
- Optional-provider lifecycle after v2 topology/schema closure: `35/35` on
  Node `20.19.4`.
- Installer, CLI, package, and native qualification before the concurrent broker
  edits: installer `62/62`, CLI `23/23`, package `24/24`, native aggregate
  `192/192`.

These counts are scoped evidence, not a release verdict. A combined installer
run performed while broker source files were changing produced two expected
source/copy integrity mismatches; it must be rerun after the concurrent edits
stop. Production completion remains unproven until the full hypergraph and HIL
evidence close.
