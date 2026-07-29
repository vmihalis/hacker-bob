# ADR: Signed immutable native-prebuild release trust

- Status: source contract complete; release signing, immutable installation,
  native attestation, principal provisioning, and HIL pending
- Date: 2026-07-19
- Applies to: versioned Plane-PH Darwin arm64 native IPC, Chameleon custody,
  safety, privileged-launch, lifecycle-custody, and native-dispatch components

## Decision

Plane-PH native delivery uses a closed, provider-neutral release manifest and a
caller-supplied trust policy. The version 1 manifest contains exactly four
pairwise-distinct artifacts: two
Node-API bundles (`native_ipc_acceptor` and `chameleon_cdc_custody`) and two
standalone executables (`safety_watchdog` and `privileged_launcher`). It binds
package/release identity and epoch, Darwin arm64, Node 20, Node-API 9, artifact
paths/kinds/sizes/digests, source and build provenance, dynamic dependencies,
Mach-O policy, filesystem policy, native-attestation policy, principal/ACL
policy, and the required HIL gate set.

Version 2 is independently domain-separated and contains exactly six
pairwise-distinct artifacts: the four v1 roles plus the standalone
`lifecycle_custodian` and `native_dispatch_custodian` executables. Its signed
`privileged_launcher` is the one supervisor component and is attested once;
the other five components are the exact ordered post-exec capability-recipient
set. V2 additionally closes exact SecRequirement bytes, Mach-O and mapped-image
identity, launch principals, descriptor and schema ABIs, typed direct-child
lineage, fresh listener/connection identities, canonical uint64 replay
generations, and authenticated grant/GO/receipt/outbox exchange. The detailed
native sequence and production boundary are specified in
`darwin-post-exec-capability-release.md`.

The envelope uses an Ed25519 signature over a domain-separated manifest-digest
claim. Key ID, public-key digest, trust epoch, and key usage are part of the
signed claim. Trust policy is external to the release and closes key validity
windows, package/component scope, release-epoch floor, key revocation, and
emergency revocation of release IDs or manifest digests. The verifier contains
no signer, private key, embedded trust root, or placeholder production
signature.

Ed25519 key material is globally unique within a trust policy. The same
normalized SPKI or public-key digest cannot appear under two key IDs, regardless
of whether either record is active or revoked. Revocation therefore applies to
the key material and cannot be bypassed through an active alias.

Artifacts must use lowercase ASCII canonical relative paths. Absolute paths,
dot components, backslashes, percent-encoded or Unicode-normalization aliases,
mixed-case/case-fold aliases, repeated separators, duplicate paths, and
file/directory prefix aliases are rejected. Artifact SHA-256 digests, signing
identifiers, and designated-requirement identities are pairwise distinct across
the selected version's complete role set—four roles in v1 and six in v2. The
dependency set is strictly sorted and exact; weak, upward, and rpath
dependencies are forbidden.

## Qualification layers are not interchangeable

1. **Ed25519 release signature.** Authenticates the closed manifest under the
   current external trust policy. It says nothing by itself about an installed
   file or running process.
2. **Mach-O signature.** Static inspection must match the declared Developer ID
   team, signing identifier, code type, SHA-256 CDHash policy, hardened-runtime
   flag, entitlements digest, and notarization policy. An ad-hoc signature is a
   blocker. This still does not identify the mapped image.
3. **Filesystem custody.** Installation evidence must show root-owned ancestry
   and artifacts, a no-symlink `openat` descriptor walk, regular single-link
   files, stable identity and terminal reopen, retained descriptors, immutable
   artifacts/root, and a read-only mount or system immutability. Pathname checks
   and owner UID alone are insufficient. Retained descriptor identities and
   static CDHashes must also remain pairwise distinct across component roles.
4. **Loaded or executed image.** Kernel-originated native evidence must bind
   the retained on-disk object, artifact hash and static CDHash to the loaded or
   executed and mapped process image with pre/post live reads. Node bundles use
   that exact openat-to-loaded-image binding as their equivalent control because
   a stock Node host cannot be presumed to enforce same-team Darwin library
   validation. Standalone executables require hardened-runtime designated
   requirement and exec/mapped-image binding. On-disk object, loaded/exec image,
   and mapped-process identities must be pairwise distinct; implicit component
   co-location is forbidden.
5. **Principal and ACL.** A signed artifact does not create a dedicated system
   principal or ACL. The release binds a policy digest; static and native
   evidence must independently bind it. Provisioning and enforcement remain
   outside this package.
6. **HIL.** Real device behavior remains separately qualified. Required gates
   cover descriptor binding, read-only Chameleon inventory, safety cleanup
   faults, launcher principal isolation, cross-component custody, and negative
   tamper cases. Evidence cross-binds the signed suite and policy digests,
   authority scope, fixture manifest, context-pinned device identity and
   operator witness, and the exact native-attestation digest.

The install-root digest and native-attestor implementation, source, and
loaded-image digests are signed manifest fields. Native on-disk descriptor
identity must equal the corresponding static-inspection descriptor identity. A
domain-separated component binding digest covers the artifact kind/hash,
static CDHash and designated requirement, retained descriptor identity,
loaded/exec and mapped-image identities, validation mode, attestor, manifest,
inspection, and ACL evidence. Independently changing any constituent invalidates
the claim. Static, native, and HIL records have signed maximum-age policy and
explicit `valid_until` bounds; future, expired, stale, and overlong claims are
rejected.

Principal/ACL policy and observed ACL evidence are separate digests. The signed
manifest binds policy, the local evaluation context pins the expected observed
evidence, and static/native records must agree on both. Static and native layers
also cross-bind the selected install root and filesystem-immutability evidence.

## Non-authorizing doctor

The doctor is a pure evaluator of caller-supplied records and trusted time. It
does not read the filesystem, inspect code signing, call native code, discover
hardware, open a device, launch a process, use the network, or mutate state.
Missing release trust is `unavailable`; invalid or incomplete static/native/HIL
evidence is `blocked`; complete static and native evidence without HIL is
`qualified_pending_hil`; complete supplied evidence is
`diagnostic_complete_non_authorizing`.

All reports hold `production_ready: false`,
`hardware_access_authorized: false`, and `authoritative: false`. Self-consistent
evidence digests provide deterministic comparison, not provenance. Production
admission must be a separate server-enforced authority that verifies the
provenance and freshness of native and HIL evidence.

## Consequences and remaining work

The contract can be exercised without native binaries or hardware and cannot
activate either. Production remains blocked on a real offline release-signing
ceremony and trust-root provisioning, immutable root-owned installation,
source-pinned native attestation of loaded/exec images, dedicated
principal/ACL provisioning, authenticated evidence custody, and every required
HIL result. No release signature, native binary, private key, trust root, or HIL
claim is supplied by this change.
