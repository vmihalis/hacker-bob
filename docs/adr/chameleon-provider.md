# ADR: Chameleon Ultra provider substrate

- Status: accepted for Plane-PH implementation
- Date: 2026-07-17
- Decision owners: Hacker Bob physical-plane maintainers
- Applies to: `PH-P1`, with constraints inherited by `PH-P2..PH-P8`

## Context

Bob is Apache-2.0 and Node 20. The first Plane-PH acceptance provider must cover
the Chameleon Ultra without making vendor commands, RF primitives, GPL client
code, or a native serial dependency part of Bob core. The public Plane-PH ABI is
provider-neutral and exposes normalized operations only.

The reviewed device ceiling is the upstream
[Chameleon Ultra v2.2.0 release](https://github.com/RfidResearchGroup/ChameleonUltra/releases/tag/v2.2.0),
built from upstream commit
`f349dbeeaa315776b272ae8fb851cc4042d55f07`. Its public framing contract is documented
in the upstream [protocol description](https://rfidresearchgroup.github.io/ChameleonUltra/protocol.html).
The source-tree review ledger for pinned command declarations, handlers,
ownership hashes, and semantic coverage lives in
`docs/plane-physical/coverage.json`. That mutable engineering ledger is not
installed with canonical Bob; the installed provider carries its reviewed,
generated operation manifest in
`packages/bob-instrument-chameleon/lib/operations.js`.

The upstream repository is distributed under
[GPL-3.0](https://github.com/RfidResearchGroup/ChameleonUltra/blob/v2.2.0/LICENSE).
Bob must not copy, translate, vendor, link, or generate code from its client,
firmware, or helper implementations into an Apache package. Protocol facts and
observed interoperability behavior may inform a separately authored codec, but
implementation text and structure do not cross the boundary.

## Decision

1. Bob core owns only the provider-neutral ABI, effect/authority contracts,
   broker client, and opaque artifact interfaces. It contains no Chameleon name,
   command ID, serial-port open, APDU/frame shell, or device-specific fallback.
2. A separately versioned optional provider package will contain a clean-room
   binary codec and the reviewed v2.2.0 semantic manifest. The implementation is
   written from the published wire contract and black-box fixtures, not derived
   from upstream GPL source code.
   `chameleon-ultra.js@0.4.7` was evaluated as the SDK alternative. It is MIT and
   advertises CommonJS, but its broad serial/Web Serial/BLE dependency graph and
   command-surface coverage are not the authority boundary Bob needs. It is not
   a runtime dependency; it may be used only as an independently installed
   interoperability oracle in non-shipping conformance work.
3. The provider runs behind the instrument broker as a separate process. Only
   that process can open the device transport. The model-facing MCP, policy
   issuer, verifier, and vault cannot import the provider or access its file
   descriptors.
4. The initial USB transport dependency is `serialport@13.0.0`, confined to the
   optional provider package. The current package is MIT-licensed and targets
   Node 20; its native binding and platform install probes do not become a
   dependency of the canonical `hacker-bob` package. See the official
   [SerialPort installation guide](https://serialport.io/docs/guide-installation/)
   and [npm package record](https://www.npmjs.com/package/serialport).
5. Protocol compatibility is an explicit fixed profile. v2.2.0 does not imply
   compatibility with future firmware, and the stale public 512-byte statement
   does not override the source-pinned profile. An unknown version, command,
   frame shape, response status, or manifest digest is unavailable until a new
   reviewed provider profile and conformance corpus land.
6. Device commands stay provider-private. Model-facing techniques resolve only
   closed compiler/profile IDs whose exact variant, worst-case effects, provider
   manifest, assurance vector, and formula digest bind the execution grant.
7. No provider package is auto-installed merely because hardware is attached.
   Install and doctor surfaces may inspect package/platform compatibility and
   broker reachability, but may not enumerate/open the device or energize RF.

## Closed ISO14443-A discovery compiler

The first active compiler slice contains exactly two versioned schemas: a
seven-bit REQA/ATQA probe and a seven-bit WUPA/ATQA probe. Both compile to the
source-pinned v2.2.0 command-2010 layout with fixed 100 ms response timeout,
field activation plus response wait, no CRC append/check, no auto-select, and
firmware field release after the exchange. Callers can choose only the schema
ID; they cannot provide bytes, frames, RF flags, timeout, bit length, CRC mode,
or keep-field behavior. The generic frame encoder refuses command 2010, and
only the branded closed result can enter its dedicated codec path. Public
compiled projections contain semantic and canonical-command digests but no raw
byte material or vendor command ID.

The semantic registry binds those schemas bijectively to
`CU-HF-14A-COMPILED-PROBE/requa_atqa_v1` and
`CU-HF-14A-COMPILED-PROBE/wupa_atqa_v1`. Each selector owns only the
provider-neutral `protocol.discovery_probe` operation and
`EP-TARGET-TRANSMIT-RF`; the shared `protocol.compiled_exchange` operation used
by DESFire and EMV remains on `enrolled_source_pinned`. No default or third
variant exists.

These are non-persistent discovery probes, not effect-free reads. Both transmit
RF and can move an idle target into the ISO14443-A READY state; WUPA can also
wake a halted target. Their exact effect union therefore remains
`EP-TARGET-TRANSMIT-RF`, and the WUPA transition is explicit in its semantic
contract. The module pins the v2.2.0 declaration, registry, official Python
packing, and RC522 reader source hashes. Pure fixture tests prove the two exact
encodings and negative input surface; they do not enumerate hardware, energize
RF, establish HIL conformance, or make the compiler proof automatically trusted.
Command 2010 therefore remains outside the runtime codec-availability profile;
activation requires the distinct `enrolled_conformance_tested` assurance profile
and the independently owned
`conformance:chameleon_hf14a_closed_probe_v1` HIL verdict in addition to the
compiler proof. That verdict binds provider binary, compiler registry, source,
firmware, transport, fixture, trust epoch, and an owned HIL run. Source review,
unit fixtures, the compiler proof, and the generic frame-codec conformance proof
cannot substitute for it. Even a structurally accepted future HIL verdict cannot
make either variant available while command 2010 remains absent from the
compiled codec profile, and every projection continues to carry
`execution_authority: false`.

## RF-off USB custody precursor

The pure CommonJS USB CDC custody module is a production precursor, not a native
transport implementation. Import and construction remain inert: the module has
no serial dependency and exposes no read, write, transact, enumerate, or raw
handle method. A driver callback capability can be created only from the exact
private device-enrollment capability and the worker-authority capability already
bound into that enrollment. The worker authority is one-shot, as are the driver,
enrollment, and custody controller, so none can be reused for another device or
custody instance.

Every creation/open seam revalidates a live Ed25519-signed closed authority
payload. The payload binds the high-entropy enrolled hardware-identity digest,
custody and driver IDs, driver implementation and binary digests, execution
principal and worker UID, provider descriptor and transport digests, signer and
trust-root identities, and monotonic trust-root, authority, and revocation
epochs. A newer signed epoch permanently raises the in-process rollback floor
even when its binding is rejected. A valid signed binding drift, explicit
revocation, or epoch rollback permanently invalidates that in-process authority
or driver capability; recovery requires a newly enrolled instance. Driver
creation also compares the enrolled worker UID with the live effective UID.
Public projections and stable errors contain none of the raw identity, node
path, serial value, signature bytes, signed payload, driver callback, or handle.

This is deliberately insufficient for hardware acceptance. WeakSet branding,
JavaScript callbacks, `process.getuid()`, and a public-key resolver in one
process do not attest callback code or an installed binary, protect a trust root,
prove an execution-principal credential, or enforce a device ACL. Epoch floors
are not durable across process restart. Promise timeouts cannot preempt a native
call that blocks the event loop, and Windows needs a reviewed native identity
resolver. Before HIL, the provider still requires a dedicated worker process and
UID, immutable/code-signed binary measurement, externally anchored epoch state,
native device-node and exclusive-lock proof, kill/reconcile behavior, and the
negative-principal matrix in the broker-custody ADR. No attached device is
enumerated or opened by these RF-off tests.

## TaskGraph physical-dispatch seam

The public `bob_prepare_node` path refuses every Contract that carries a
`physical_resource_bundle`. Physical preparation is reachable only through the
internal graph coordinator with the exact broker-factory-branded eligibility
port. While holding the session lock, that coordinator rechecks the signed
session nucleus, source graph, node, Contract, and bundle; resolves fresh broker
eligibility; and appends both preparation transitions. The dispatched event,
brief, prep token, and result bind only a compact safe proof projection
(reservation reference and digests), never raw fences or credentials.
Cancelling a prepared reservation first verifies that exact durable projection
and appends a bound `dispatched -> failed` cancellation tombstone while the
same session lock is held; only then may broker capacity be released. A
deadline-crossed close uses the broker's explicit expiry transition rather than
misreporting an unexplained release failure.

This seam is fail-closed against public JSON and lookalike objects, but its
JavaScript brands and re-entrant lock remain same-isolate controls. They do not
prevent arbitrary code in the MCP process from importing private modules or
ignoring Bob's cooperative lock file. Production authority therefore still
requires the separately authenticated broker process and filesystem/IPC
principal controls described above.

## Bootstrap response trust boundary

The bootstrap response normalizer accepts no caller-authored response object.
It requires four exact-bound artifacts: a parser-aggregated decoded payload
branded by the source-pinned v2.2.0 decoder, an authenticated and branded
`BootstrapInvariantWitness`, a canonically resolved content-addressed receipt
allocation, and the original branded bootstrap grant. Observation and receipt
references are derived from those bindings; an operator, evaluator, or model
cannot choose them or submit RF, mode, workspace, or timestamp assertions as
substitute evidence.

This bootstrap subset intentionally does not add `GET_DEVICE_MODE` command
1002 and does not relax per-parser-epoch command correlation. The USB responses
therefore establish neither an RF-off bracket nor mode continuity. Their RF
verdict remains `pending_independent_observation_hil`, their mode verdict is
`not_observed_get_device_mode_not_allowlisted`, and workspace non-write is only
the result of the closed command-effect manifest. Production RF/mode assurance
remains pending an independent bracket/continuity witness and PH-P7 HIL. The
local receipt callback seam is likewise classified
`fixture_source_acknowledged`, with `production_ready: false` and
`execution_authority: false`, and `lifecycle_authority: false`, until it is
backed by an authenticated durable Bob receipt-store port. ABI v3 must also
bind a durable bootstrap attempt/dispatch credential and the USB connection
generation before this chain can prove call-to-frame continuity across a
reconnect.

## Package and license boundary

The transport-neutral closure is split along dependency direction rather than
assembled from sibling source paths. `@hacker-bob/instrument-contracts` is the
canonical provider-neutral ABI/effect/quantity layer. The checked-in
`@hacker-bob/instrument-chameleon-worker-runtime` owns the codec, closed probe
compiler, compiled-command capability, and USB custody implementation and
declares only the contracts package. The optional privilege-separated worker
declares that runtime. MCP and the broader Chameleon development package use
compatibility projections of those canonical packages; the signed worker never
imports `mcp/core` or another package through `../` traversal.

| Surface | Distribution | License | Permitted dependency direction |
| --- | --- | --- | --- |
| `hacker-bob` core contracts/client | canonical npm package | Apache-2.0 | provider-neutral only |
| instrument broker | independent package/process | Apache-2.0 | imports the pure ABI; never imports MCP/model code |
| artifact vault | independent package/process | Apache-2.0 | imports public handle/transform contracts only |
| Chameleon worker runtime | canonical inert library and signed optional-closure dependency | Apache-2.0 authored code | imports only `@hacker-bob/instrument-contracts`; contains no serial dependency |
| Chameleon Ultra provider worker | optional independent package/process | Apache-2.0 authored code | imports the worker runtime and, after native qualification, optional `serialport`; contains device profile |
| upstream Chameleon repository/client/firmware | external, operator-owned | GPL-3.0 | reference and interoperability source only; no code dependency |
| `chameleon-ultra.js@0.4.7` | external conformance oracle only | MIT | no runtime or packaging dependency; npm integrity `sha512-186iaCTJG5T0/EURD6DKlnnNnC165PJND5ASjnAssiAbNJyrSL+RMn3o0NHsxSjAMzvkWia+b5etvVv84zling==` |
| `serialport@13.0.0` | provider dependency only | MIT | provider transport implementation only |

Every release artifact needs an automated inventory proving that GPL files,
upstream generated artifacts, device captures, live manifests, HIL evidence,
vault state, and native provider dependencies are absent from the canonical Bob
tarball.

## Rejected alternatives

- **Import or port the upstream GPL CLI.** Rejected because it crosses the GPL
  boundary, exposes a broad command surface, couples Bob to Python/client
  behavior, and defeats the normalized provider ABI.
- **Use the MIT JavaScript SDK as Bob's provider contract.** Rejected because
  SDK API breadth, transport dependencies, and incomplete semantic/effect
  coverage cannot substitute for Bob's closed ABI and reviewed command map.
- **Open serial ports directly from the MCP server.** Rejected because it gives
  the model-facing process device authority, collapses issuer/worker isolation,
  and makes native installation mandatory for every Bob user.
- **Shell out to an operator-installed upstream CLI.** Rejected for effectful
  execution because command construction, output parsing, cancellation,
  ambiguous-effect reconciliation, and artifact custody cannot satisfy the
  broker contract. An operator may still use external tooling outside Bob.
- **Vendor a GPL sidecar with Bob.** Rejected for the initial distribution. A
  separately obtained GPL program could be interoperated with later only after
  legal review and a narrow, documented process boundary; it cannot satisfy or
  weaken this provider's acceptance gate.
- **Use Web Serial or a generic TTY shell.** Rejected for the first provider:
  Node-host portability and deterministic cancellation/reconciliation are not
  adequate, and a generic shell would reintroduce raw device passthrough.

## Acceptance consequences

- PH0 uses only the deterministic mock provider and can pass with no native
  dependency or hardware present.
- PH1 adds the clean-room frame codec, fixed semantic manifest, USB transport,
  and read-only inventory behind the broker.
- BLE remains a later independent transport profile and must prove effect and
  boundary parity rather than inheriting USB assurance.
- A provider implementation is not release-ready until Node 20 install probes
  pass on supported macOS, Linux, and Windows fixtures and the clean-room corpus
  proves framing, partial reads, corruption, timeout, disconnect, cancellation,
  unknown-command refusal, and secret-free public envelopes.
