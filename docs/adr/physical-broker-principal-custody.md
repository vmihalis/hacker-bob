# ADR: Plane-PH broker principal, key, and store custody

- Status: accepted as the PH-S3 production boundary
- Date: 2026-07-18
- Applies to: physical issuer, broker, provider workers, safety recovery,
  artifact vault, observers, and verifiers

## Decision

Physical execution is a multi-principal protocol. JavaScript object branding,
module boundaries, Unix sockets, or signatures alone do not establish the
boundary. Production admission requires all of the role, key, filesystem,
device, IPC, epoch, and recovery checks below. A deployment that cannot satisfy
them is unavailable; it does not fall back to a same-UID hardware mode.

The only same-UID mode is the exact operator-enrolled deterministic mock
implementation. It has no serial, USB, BLE, network, child-process, or device
opening dependency and cannot load a hardware provider by name substitution or
descriptor drift.

## Normative custody matrix

`R` means read, `W` means append/mutate through the owning protocol, `S` means
sign with a non-exportable key, and `O` means open or own the live resource.
Absence of a grant is a denial, including inherited file descriptors, shell
indirection, backups, crash dumps, debug endpoints, and symlink/hardlink aliases.

| Principal | Authorized custody | Explicitly denied |
| --- | --- | --- |
| Model-facing MCP/agent | Submit normalized requests; read redacted status and opaque evidence refs | Every physical signing key; device nodes; provider imports; raw transports; vault keys/plaintext; lease/anchor mutation; observer/verifier keys |
| Operator control plane | `S` scope/enrollment/policy decisions; provision trust roots and aliases; authenticated operator export | Unattended provider dispatch; worker receipt signing; cleanup delegation to the model; arbitrary vault-worker execution |
| Grant issuer | `R` immutable session nucleus, current scope, task/pack/plan/resource state; `S` one-use grant | `O` hardware; worker receipt key; vault decrypt/HMAC/export keys; cleanup root; verifier/observer keys |
| Active device worker | `O` one exclusive launcher-delegated descriptor, never its pathname; `S` worker receipt/provenance; `W` exact lease journal/outbox; consume exact one-use vault materialization capabilities | Opening or resolving the device node; direct device group/ACL membership; grant signing; scope authoring; arbitrary vault lookup/export; cleanup-root minting; observer/verifier signing; a second device or alias |
| Safety supervisor | `R/W` deadman, fencing, containment, and cleanup journal; hold nondelegable narrow cleanup root; authorize an exact cleanup transition | Every raw transport, device pathname, and device descriptor; general provider execution; active-grant minting; administration/destruction; model delegation; vault export |
| Cleanup-only worker | `O` the precommitted closed cleanup descriptor/capability after fencing and active-descriptor revocation; consume only the precommitted lease/snapshot/restore digest and terminal receipt capability | Opening or resolving the device node; simultaneous custody with the active worker; new target effects; maintenance/admin/destroy operations; any other vault handle; grant signing; scope changes |
| Privileged launcher | `O` the enrolled root-owned device node long enough to verify and open it; delegate one closed, profile-bound descriptor to either active or cleanup; close its redundant copy | Provider protocol execution; safety or model delegation; simultaneous active/cleanup delegation; arbitrary paths/devices; grants, receipts, scope, vault, or report authority |
| Vault worker | `O` encrypted vault and externally anchored index; decrypt/HMAC/transform keys; exact one-use ingest/materialize operations | Hardware; grant or receipt signing; model-visible plaintext; operator export key/channel |
| Operator export process | `S/O` audience-bound export key/channel; consume one exact export request | Provider/device access; arbitrary vault enumeration; transform execution; model-facing output |
| Observer | `O` one enrolled independent sensor; `S` observation rows | Provider receipt signing; grant/verdict signing; device-worker state mutation; vault plaintext outside an exact ingest capability |
| Verifier | `R` signed receipts/observations and opaque evidence; `S` claim/cleanup verdicts | Hardware effects; grant signing; observer signing; artifact plaintext; rewriting plans or cleanup outcomes |
| External anchor/time services | Monotonic compare-and-set state; signed short-lived monotonic-to-UTC mappings | Provider execution; vault plaintext; scope/task decisions; report or finding authority |

Keys have distinct usage domains and identities: physical scope, active grant,
bootstrap grant, worker receipt, cleanup root, recovery receipt, vault storage,
vault comparison, vault export, observer, verifier, IPC request, IPC response,
external anchor, and trusted clock. Reusing key bytes or key IDs across rows is
a provisioning failure.

## Unix IPC and filesystem profile

For `separate_identity`, the operator preprovisions a dedicated worker-owned
socket directory and a dedicated IPC group shared only by the issuer and active
worker. The broker binds the configured UID/GID and inode identities before
listen, at accept, and at close.

- socket root: real directory, no symlink component, owner = active-worker UID,
  group = enrolled transport GID, mode `0710`;
- socket: owner = active-worker UID, group = enrolled transport GID, mode
  `0660`, exact inode retained for the server lifetime;
- peer identity: native trusted `SO_PEERCRED`/platform-equivalent resolver binds
  issuer UID, transport GID, PID, IPC request key, peer principal, execution
  principal, and provider descriptor to the signed request;
- device node: owner `root:wheel`, mode `0600`, no extended service-account ACL,
  no inheritance, and no broad group/everyone grant. Only the independently
  attested privileged launcher may resolve and open the enrolled character
  device with directory-relative, no-follow semantics after binding its path,
  file ID, major/minor identity, and IORegistry identity;
- descriptor delegation: the launcher passes an exact profile-bound descriptor
  to the active worker or the cleanup worker, never both. Safety has control-only
  stop/fence authority and never receives a raw descriptor. Cleanup can receive
  only its precommitted closed cleanup capability after the active descriptor is
  revoked. Workers are not device-group members and cannot reopen by pathname;
- worker lease/journal store: worker-owned real directory, mode `0700`, files
  `0600`/`0400`, externally anchored; no shared group access;
- issuer state and grant key: issuer-owned real directory/HSM namespace, no
  worker or agent access;
- receipt keys: worker-owned key store, no issuer or agent access;
- cleanup root and launcher state: safety-supervisor-owned, unavailable to the
  active worker until the exact fenced recovery launch is authorized;
- vault root and keys: vault-worker-owned, separate from provider and session
  roots; ciphertext presence never implies decrypt-key access;
- provider binaries and declarative transform programs: immutable,
  digest-enrolled, non-writable by the agent/issuer/worker execution accounts.

`same_uid_deterministic_mock` instead uses a worker-owned `0700` root and `0600`
socket, but startup additionally needs a live private enrollment authority that
pins the exact deterministic provider ID, descriptor digest, and implementation
digest. A prefix such as `deterministic_` is not an identity proof.

## Provisioning and rotation order

1. Create distinct OS identities and dedicated IPC/key/vault/recovery groups;
   prove unique UID/GID membership and no-login policy for each service account.
   No worker or model-facing account receives a device group or device-node ACL.
2. Install immutable broker/provider binaries and record their implementation
   digests. Provision the provider alias and hardware identity without exposing
   raw node paths or serial-derived values to the model.
3. Provision independent keys and trust registries, then external anchor and
   trusted-clock services. Record key-usage, owner principal, epoch, generation,
   and revocation policy for each.
4. Install the minimal immutable privileged launcher and bind its executable,
   bundle, prebuild, launch, root-authorization, and authorization-scope digests.
   The closed Darwin `root_device_capture_v1` profile requires entitlement
   absence and records IOServiceAuthorize as not required; it must not combine
   root authority with an ambiguous second authorization mode. The launcher
   verifies `root:wheel`/`0600`, character
   device, directory-relative no-follow resolution, file and major/minor identity,
   IORegistry identity, and before/after stability before any descriptor exists.
5. Create private stores and the preprovisioned IPC root. Start the workers,
   issuer, safety, vault, observer, and verifier processes. Each performs
   negative reads/opens against every denied row before the runtime becomes
   available.
6. Import the signed session nucleus and scope into issuer custody. A bootstrap
   request may then be minted, but the launcher does not open or delegate the
   hardware descriptor until peer, replay, scope, provider, transport, device,
   exclusive-delegation, and effect invariants revalidate.

Rotation advances the relevant trust epoch or revocation generation before old
material is removed. Issuer/worker disagreement fails closed. In-flight active
authority is fenced; the independent cleanup root remains usable only for its
precommitted restore. Device replacement, provider binary drift, group/ACL
change, socket-root replacement, anchor rollback, clock-epoch change, or worker
receipt-key rotation creates a new capability instance and invalidates prior
inventory/assurance as declared by policy. The provider-neutral Darwin
qualification and planning representation is specified by
[Darwin dedicated-principal and descriptor-custody qualification](darwin-principal-device-acl-qualification.md);
it does not itself provision identities, open the device, or authorize hardware.

## Failure and evidence contract

- Nonce/sequence reservation is durable before dispatch. An admitted request
  is never replayed merely because a response was lost.
- The worker journals and fsyncs the exact provider intent before the final
  live grant/lease/fence check and provider effect seam.
- Disconnect, deadline, resolver outage, clock failure, revocation, peer drift,
  socket replacement, and ambiguous acknowledgement produce fixed safe public
  dispositions and private diagnostic evidence; raw paths, credentials,
  payloads, signatures, keys, and artifact bytes are not logged.
- A killed or unreachable active worker is fenced by an independent supervisor.
  Cleanup either restores the exact precommitted snapshot or records quarantine
  or unknown residue. It never reports restoration from provider acknowledgement
  alone.

Node 20 does not expose trustworthy Unix peer credentials in its standard
library, and pathname operations do not provide the full `openat`/`renameat`
discipline needed to eliminate final-component races. Production therefore
requires a reviewed native/platform peer-credential adapter and, where the OS
ACL/path threat model requires it, a small privileged launcher/native custody
helper. Injected JavaScript callbacks and same-process tests are conformance
fixtures, not evidence that these OS boundaries exist.

The broker now defines the closed conformance contract for that native adapter.
On Linux the only admitted profile is `SO_PEERCRED`; on macOS it is
`getpeereid` plus `LOCAL_PEERPID`. A snapshot must bind the exact accepted
socket nonce, UID, GID, PID, process-start token, executable-byte measurement,
platform primitive, and implementation digest. Broker enrollment independently
pins those values together with the request key and issuer/worker principals;
any drift fails before replay reservation or dispatch. Pathnames, remote-address
strings, caller-supplied process objects, argv, and asynchronous lookups are not
credential inputs. The shipped adapter factory is nevertheless explicitly a
pure injectable conformance fixture (`production_attested: false`) and cannot
authorize hardware or `separate_identity`. Production remains unavailable until
a reviewed native binding obtains the socket credentials and process measurement
without a PID-reuse window, its binary is immutably measured, and the HIL
negative-principal matrix qualifies that exact binding.

## HIL acceptance

Before the first read-only hardware inventory, an operator-run negative matrix
must prove every denied principal cannot open the device or receive/inherit its
descriptor, connect outside its
IPC role, read any other principal's keys or plaintext, mutate anchors/stores,
or inherit forbidden descriptors through a subprocess. The matrix includes
symlink/hardlink paths, backups, crash artifacts, group membership, shell
redirection, process inspection, active/cleanup descriptor overlap, descriptor
inheritance, worker kill, socket replacement, and key/epoch rotation. Safety
raw-transport access and worker pathname reopen are hard failures. Same-UID
hardware operation is a hard failure, not a waiver.
