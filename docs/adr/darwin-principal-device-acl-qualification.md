# ADR: Darwin dedicated-principal and descriptor-custody qualification

- Status: accepted as a provider-neutral, nonauthorizing contract
- Date: 2026-07-19
- Applies to: Darwin physical-instrument principal provisioning, device custody,
  native qualification evidence, doctor output, and provisioning-plan data

## Context

Darwin physical instruments may initially appear through a serial-style
character device and IORegistry, but a provider worker must not gain durable
pathname access merely because one instrument currently uses that transport.
Giving active, safety, and cleanup accounts a shared device group or extended
ACL would collapse three independent authorities into one raw-transport
principal. It would also let safety execute effects and let cleanup operate
before fencing.

The framework therefore needs a provider-neutral representation of the desired
OS identities and custody boundary. That representation must be useful to an
operator and a future reviewed native provisioner without enumerating accounts,
changing ACLs, opening hardware, or treating caller-supplied evidence as
authority.

## Decision

`packages/bob-instrument-principal-acl-darwin` is a private CommonJS Node 20
data-contract package. Import, policy construction, observation normalization,
doctor evaluation, and plan construction are pure. The package has no account,
filesystem, process, command, network, IORegistry, or hardware adapter. It never
provisions or authorizes anything.

The fixed principal set is:

| Role | OS identity and ancestry | Physical custody |
| --- | --- | --- |
| `operator_control` | Distinct non-root, no-login service principal; not launcher-parented | Policy/control only |
| `grant_issuer` | Distinct non-root, no-login service principal; not launcher-parented | Grant issuance only |
| `active_device_worker` | Distinct non-root, no-login service principal launched by the qualified launcher | One exclusive delegated active descriptor |
| `safety_supervisor` | Distinct non-root, no-login service principal launched by the qualified launcher | Control-only stop/fence authority; no raw transport |
| `cleanup_worker` | Distinct non-root, no-login service principal launched by the qualified launcher | Precommitted closed cleanup descriptor only after fencing |
| `privileged_launcher` | Distinct no-login root principal with an exact root-authorization digest | Verify/open the enrolled node and delegate one descriptor; no provider effects |

Every principal ID and UID is distinct. Every primary and supplementary GID is
globally distinct in this contract; group aliasing is rejected. Executable,
bundle, prebuild, and launch-attestation digests are exact per role. Only the
launcher may claim root, and its root-authorization digest is fixed by policy.
The authenticated role-edge matrix is fixed rather than caller-extensible.

## Device custody model

The enrolled device node is `root:wheel`, mode `0600`, with no extended
service-account ACL, inherited ACL, broad group, or everyone entry. The policy
stores only digests for the expected path, file ID, major/minor identity,
directory used for relative open, device identity, and IORegistry identity. Raw
paths never enter the policy output or provisioning plan.

Only the privileged launcher may perform the future native open. Because this
contract fixes the launcher as root, its one closed authorization mode is
`root_device_capture_v1`: entitlement state must be exactly absent and
IOServiceAuthorize state exactly not required. The policy binds the exact
authorization-scope, root-authorization, executable, bundle, prebuild, and
launch digests. It does not ambiguously require root plus a second authorization
mode. The launcher must use directory-relative no-follow resolution, prove a
character device with one link, compare stat and IORegistry identities before
and after, and close any redundant descriptor after delegation.

Two closed delegation profiles exist:

1. `active_device_session` delegates a read/write descriptor exclusively to
   `active_device_worker` for the active phase.
2. `cleanup_recovery_session` binds a precommitted closed read/write cleanup
   capability to `cleanup_worker`. It becomes usable only after fencing and
   revocation of the active descriptor.

The profiles are mutually exclusive. Neither worker may reopen the node by
pathname. `safety_supervisor` receives no descriptor, entitlement, device ACL,
or transport capability; it controls stop, fence, and cleanup transition state
only. These rules specialize the normative custody model in
[Plane-PH broker principal, key, and store custody](physical-broker-principal-custody.md)
without introducing a second device-access model.

Qualification also requires a policy-bound complete descriptor-inventory
digest. The read-only observer brackets one closed snapshot and proves that its
before, after, and policy digests are identical; enumeration is complete; the
launcher has closed its redundant open descriptor; no launcher-held,
active-worker, cleanup-worker, unlisted, or inherited copy remains; and the
custody state is exactly `closed`. An `active` or `cleanup` snapshot is useful
runtime evidence but is not accepted by this quiescent provisioning
qualification. Mutual exclusion remains independently required by both closed
delegation profiles.

## Diagnostic observation contract

An observation is explicit caller-supplied data from a future read-only native
observer. Exact schemas bind:

- Darwin version/build, boot epoch, security epoch, policy epoch, observation
  validity, and policy-bounded maximum age;
- account and group records, real/effective/saved credentials, supplementary
  groups, audit/process-start evidence, executable identity, and ancestry;
- device/path/file/major-minor/open-directory and IORegistry identities,
  character-device and no-follow semantics, link count, ownership, mode, empty
  service-account ACL, and before/after stability;
- launcher `root_device_capture_v1`, explicit entitlement absence,
  IOServiceAuthorize-not-required state, authorization scope, root
  authorization, and the two exact descriptor-delegation profiles;
- a complete, before/after-stable descriptor inventory bound to the policy,
  with the redundant launcher copy closed and zero launcher, active, cleanup,
  unlisted, or inherited descriptors at the closed qualification snapshot;
- observer implementation, prebuild, bundle, launch, code-signature
  requirement, signing identity, signature-verification result, and stable
  before/after snapshots.

Normalization only makes the data exact, immutable, and branded for in-process
use. It does not make any digest or boolean trustworthy. The doctor therefore
uses `diagnostic_match_pending_native_prebuild_hil` for a complete match, not an
authorization status. Missing data is `unavailable`; aliasing, broad or
inherited access, replacement, symlink/hardlink drift, simultaneous active and
cleanup descriptors, incomplete or forked inventory, a retained launcher or
inherited/unlisted descriptor, safety raw access, stale/forked data, or unqualified
root/entitlement evidence is `blocked`.

Policy, observation, doctor, and plan outputs always set
`production_ready: false` and `hardware_access_authorized: false`. A signed
immutable native apply component, reviewed prebuild chain, operator approval,
and negative-principal HIL remain mandatory external gates.

## Declarative provisioning plan

The planner computes a deterministic diff from a branded policy and optional
branded observation. Actions describe desired account/group/launch bindings,
root-only device-node state, launcher open authorization, exact native observer
binding, exclusive descriptor-delegation policy, and a separate exact closed
descriptor-inventory action. Actions contain only
identifiers and current/desired state digests. They contain no executable
commands, argument vectors, passwords, tokens, environment, or raw paths.

The plan is not an apply recipe and is never dispatched by this package. A
future native provisioner must have its own signed immutable prebuild, validate
the policy digest and operator approval, apply changes transactionally, emit a
new independent observation, and pass the HIL matrix. A zero-action plan means
only that the supplied diagnostic data matches the policy; it is not proof of
production readiness or permission to touch hardware.

## Consequences

- The first instrument provider does not define the abstraction. Additional
  providers can bind their own identity and authorization digests while keeping
  the same principal and descriptor-custody boundary.
- Direct worker device groups and dynamic cleanup ACL widening are prohibited.
  Cleanup authority is expressed as a precommitted descriptor capability, not a
  filesystem permission mutation.
- Reboot, OS update, device replacement, observer/prebuild drift, authorization
  drift, or policy-epoch rotation requires a new diagnostic observation and may
  require a new policy.
- The package is intentionally insufficient for deployment until the separate
  native observation/apply, immutable prebuild, and HIL work is implemented and
  reviewed.
