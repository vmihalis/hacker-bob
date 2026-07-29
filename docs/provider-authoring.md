# Physical provider authoring

Hacker Bob physical providers implement the provider-neutral Plane-PH ABI. A
provider translates reviewed semantic operations into instrument behavior; it
does not decide engagement scope, mint grants, schedule resources, adjudicate a
security claim, or expose raw instrument material to an evaluator.

This guide describes ABI version 3. It is an engineering authoring contract,
not evidence that a provider or instrument is production-qualified. Production
readiness additionally requires independently enrolled identities, durable
authority and evidence owners, native principal separation, and the applicable
hardware-in-loop gates.

The npm artifact carries this guide, and `hacker-bob install` copies the exact
packaged bytes to `.hacker-bob/docs/provider-authoring.md`. `hacker-bob doctor`
rejects a missing, substituted, or stale installed copy without treating the
project's general `docs/` directory as Bob-owned.

## Boundary map

| Owner | Responsibility | Must not do |
| --- | --- | --- |
| Plane-PH core | Scope, grants, effect policy, resource scheduling, evidence and lifecycle gates | Branch on a vendor, command number, RFID family, or transport |
| Broker | Redeem one-use authority, fence dispatch, journal effects, drive cleanup and reconcile ambiguous completion | Let a provider self-authorize or treat an acknowledgement as external proof |
| Provider | Describe capabilities and implement the closed lifecycle for registered semantic operations | Mint grants, return raw bytes publicly, choose unregistered effects, or silently retry ambiguity |
| Vault/transform worker | Hold response material and apply allowlisted transforms | Return secret material or arbitrary transform output to the model-facing process |
| Verifier/observer | Establish an independently evidenced outcome and residual state | Inherit provider trust or treat graph adjacency as authority |

The evaluator-facing surface contains opaque execution, cell, artifact,
observation, and receipt references. Provider IDs, device locators, command
numbers, frames, keys, dumps, and transport credentials stay behind the broker.

## Authoring inputs

A provider is assembled from existing registries rather than a second manifest
language:

1. A requested-effect registry defines the only subject, action, channel,
   persistence, quantity, unit, and bound combinations that may be requested.
2. A normalized-operation registry defines semantic operation IDs, typed
   parameters, public outcome codes, and worst-case effect templates.
3. A provider descriptor binds ABI and provider versions, implementation
   digest, operation-registry digest, and a closed capability list.
4. Plane-PH resource bundles bind each technique cell to every instrument,
   media item, observer, controller, operator-presence requirement, power or
   thermal budget, workspace, and cleanup resource needed for the attempt.
5. Signed inventory and capability observations determine current availability.
   A firmware string or provider declaration alone cannot enable a technique.

Use the factories and normalizers exported by
`packages/bob-instrument-contracts/lib/` and
`mcp/lib/physical-resource-contract.js`. Do not construct normalized objects by
copying their JSON shape: Bob uses private brands at authority boundaries.

`mcp/lib/physical-provider-authoring.js` is the executable assembly validator.
`createPhysicalProviderAuthoringManifest` accepts the branded descriptor,
operation registry, effect registry, and normalized resource bundles and emits
only their closed, content-addressed authoring projection. The projection never
contains candidate resource locators, device paths, provider callbacks, or
authority. `assertPhysicalProviderAuthoringBindings` re-derives the projection
from the live registries and rejects drift; a JSON clone does not inherit the
private normalized brand.

## Provider descriptor

The descriptor is exact and content-addressed:

```js
const {
  PROVIDER_ABI_VERSION,
  defineProviderDescriptor,
} = require("@hacker-bob/instrument-contracts");

const descriptor = defineProviderDescriptor({
  version: 1,
  abi_version: PROVIDER_ABI_VERSION,
  provider_id: "optical_actuator_fixture",
  provider_version: "1.0.0",
  implementation_digest: reviewedImplementationDigest,
  operation_registry_digest: operationRegistry.registry_digest,
  capabilities: reviewedCapabilities,
}, operationRegistry, effectRegistry);
```

IDs describe semantics, not vendor commands. A GPIO actuator plus optical
sensor provider might implement `environment.actuate` and
`environment.observe`; its private pin numbers and bus transactions are not
normalized operation IDs. Every capability declares one registered operation,
typed parameter domains, exact worst-case effects, idempotency, retry policy,
stop semantics, restore policy, and bounded public summary codes.

The descriptor and all responses are closed objects. Unknown fields, getters,
proxies, symbols, raw byte containers, undeclared summary codes, digest drift,
duplicate capability IDs, and ABI drift fail validation.

## Required ABI methods

ABI-v3 providers implement all of these methods:

| Method | Purpose |
| --- | --- |
| `describe` | Return the exact provider descriptor |
| `inventory` | Redeem bootstrap authority and record enrolled instrument state |
| `capabilities` | Redeem bootstrap authority and observe the descriptor-bound capability set |
| `health` | Redeem bootstrap authority and return a bounded availability result |
| `prepare` | Validate the exact operation, parameters, instrument, attempt, and plan before dispatch |
| `snapshot` | Materialize a precommitted restore basis when the capability requires one |
| `execute` | Redeem the broker-issued dispatch credential once and journal before effect |
| `status` | Resolve the exact attempt without repeating it |
| `stop` | Request the declared bounded stop behavior |
| `reconcile` | Classify an interrupted attempt as confirmed effect, confirmed no-effect, ambiguous, or unknown |
| `restore` | Apply only the precommitted restore plan and emit residual-state evidence |

State transitions use Bob's attempt-state table. An ambiguous or unknown effect
is never an automatic-retry basis. A retry, where policy permits one, receives a
new attempt reference and fresh authority only after a durable confirmed-no-
effect terminal.

Bootstrap authority can call only the reviewed instrument-local inventory,
capability, and health operations. It cannot carry target or environmental
effects and cannot claim the inventory or snapshot it is intended to create.

## Multi-resource attempts

Providers do not reserve resources themselves. A technique cell declares a
resource bundle, and the Plane-PH scheduler plus arbiter reserve the complete
bundle atomically before active admission. The provider receives only the exact
broker projection for its assigned resource.

For an actuator-plus-sensor experiment, a bundle normally contains:

- The actuator as an effect resource.
- The optical sensor as a disjoint observation resource.
- A controller or verifier resource owned by a different trust domain.
- A positive fixture and a discriminating control.
- Zone, containment, power, timing, and operator-presence bounds.
- A pre-state snapshot, stop plan, restore plan, and quarantine destination.

Failure to acquire any required resource leaves the cell blocked or denied; it
must not degrade to a smaller experiment. Reservation order, lease fences, and
resource aliases are core contracts and must not be reimplemented by a
provider.

## Raw custody and public results

Instrument responses flow directly from the isolated worker to a vault-owned
sink. The provider-facing completion path receives authenticated, durable raw-
custody and semantic receipts, not response bytes supplied by a caller. Any
decoding or secret-bearing transform is allowlisted, bounded, versioned, and
executed in the vault/worker boundary.

Public provider results contain only:

- A registered outcome and summary code.
- Opaque artifact references.
- Bounded, non-sensitive integer metrics.

They never contain frames, dumps, identifiers, credential values, device paths,
transport secrets, request bodies, or arbitrary provider diagnostics. A
provider receipt establishes instrument behavior; it does not by itself prove
an external security outcome.

## Observation, cleanup, and verification

An effectful capability declares stop and restore semantics before admission.
Disconnect, cancellation, deadline, revocation, worker death, or lost
acknowledgement enters reconciliation and cleanup. The cleanup-only authority
may apply only the precommitted restore digest; it cannot administer, destroy,
or introduce a new effect. Restore failure yields quarantine or an unknown
residual state, never a fabricated restoration result.

The verifier joins positive and control execution receipts with independently
enrolled observations. The provider cannot enroll its own observer or assign an
independence domain. Same-domain provider and sensor evidence cannot alone prove
an external outcome. Only a server-verified verdict may mint a demonstrated
SurfaceGraph transition or a finding input.

Downstream composition obtains fresh authority. It revalidates the exact
upstream verdict, capability instance, physical-state epoch, custody, and
consumed context, then records actual consumption or fresh re-execution.
Reachability is evidence, not inherited permission.

## Engineering conformance

The deterministic provider package supplies a portable lifecycle runner and
fault scripts for success, refusal, corruption, timeout, disconnect, ambiguous
dispatch, stale state, and restore failure. Use it to test registry and ABI
behavior without hardware. Its injected authorizers are test-only and cannot
qualify production authority or evidence.

Its `./orthogonal-fixture` export supplies a non-RFID GPIO-actuator plus optical-
sensor assembly with disjoint instruments, an independently enrolled observer,
a discriminating control, an owned workspace, operator presence, and unit-aware
effect bounds. It is intentionally inert. The focused PH-X4 suite validates the
assembly, plans all resources atomically, proves that a missing sensor yields no
partial allocation, and drives both observe and act/restore through Bob's
durable test authority ports. These results are engineering evidence only.
The integrated PH-X4/PH-C10 capstone additionally binds this same provider
manifest through a verified ledger and SurfaceGraph transition into the real
claim, evidence, proof, grade, finalized-report, and downstream-composition
adapters. It still reports `full_provider_matrix: false`, `hil_verified: false`,
and `production_ready: false`; the test closes the provider-neutral software
seam without laundering a simulated actuator into hardware qualification.

A provider's engineering suite should prove at least:

- Descriptor, capability, operation, effect, and parameter drift fail closed.
- Every lifecycle result normalizes and every state transition is legal.
- Raw/public-output guards reject nested bytes, getters, proxies, and sensitive field names.
- Atomic multi-resource admission cannot be reduced to a partial bundle.
- Lost acknowledgement performs status/reconciliation and never repeats the effect.
- Stop, restore, quarantine, and restart behavior are deterministic.
- Provider absence becomes bounded unavailability and opens no hardware.
- Core modules contain no provider, vendor, transport, or domain-specific branch.
- Package, clean install, update, uninstall, and doctor paths perform no device I/O.

Mock and fake-port runs are engineering evidence only.

## Production and HIL qualification

Production qualification requires signed, independently resolvable evidence
for the concrete provider build and environment. At minimum it binds:

- The provider, compiler, worker bundle, native launcher, and transport build digests.
- Current enrolled provider, device, issuer, worker, vault, observer, and cleanup principals.
- Trust-root, signer, authority, revocation, inventory, custody, connection, and physical-state epochs.
- Native peer credentials, device ACLs, descriptor inheritance controls, and signing-key isolation.
- An external monotonic time/sequence anchor and restart-durable receipt store.
- Per-operation positive/control, fault, containment, cleanup, and residual-state evidence.
- The exact packaging, install, and doctor candidate under qualification.

An orthogonal provider must complete authorize, observe, act, stop, reconcile,
restore, verify, reachability, downstream composition, claim, grade, report,
package, install, and doctor flows without changes to physical core. A mock-only
run cannot satisfy this gate. For a two-resource actuator/sensor provider, HIL
must use owned fixtures and an independently enrolled external observer with
unit-aware bounds.

## Compatibility policy

- ABI 3 is the current bootstrap-plus-active contract. ABI 2 remains readable
  only for the documented active-only compatibility path.
- Unknown ABI, descriptor, operation, effect, quantity, schema, capability,
  or pack versions fail closed.
- Additive provider capability changes produce a new descriptor digest and
  require fresh inventory and availability resolution.
- Effect, parameter, compiler, restore, or public-result changes require a new
  reviewed semantic version and invalidate prior conformance evidence.
- Core ABI migrations preserve old-session read/resume behavior. Physical
  opt-in uses a signed successor session nucleus and reissues authority; it
  never mutates an immutable prior nucleus.
- Rollback must be idempotent and must revoke authority issued only under the
  successor contract.

Provider-specific setup, command tables, native binaries, live evidence, and
operator secrets do not belong in the canonical Hacker Bob package. Ship them
through the optional-provider lifecycle with explicit platform and trust
qualification.
