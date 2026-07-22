# Hacker Bob native-prebuild trust contracts

This private CommonJS package defines a provider-neutral release-verification
contract for Hacker Bob's Darwin arm64 native components. It verifies an
Ed25519-signed, closed release manifest and evaluates caller-supplied diagnostic
evidence. Importing it performs no filesystem access, native loading, process
launch, network access, hardware discovery, or device access.

The version 1 closed release set contains exactly four pairwise-distinct artifacts:

| Component | Artifact form | Host or equivalent validation |
| --- | --- | --- |
| `native_ipc_acceptor` | Node-API bundle | retained `openat` object identity must match loaded and mapped image identity |
| `chameleon_cdc_custody` | Node-API bundle | retained `openat` object identity must match loaded and mapped image identity |
| `safety_watchdog` | standalone Mach-O executable | hardened-runtime designated requirement plus exec/mapped-image binding |
| `privileged_launcher` | standalone Mach-O executable | hardened-runtime designated requirement plus exec/mapped-image binding |

The target is exactly Darwin arm64, Node 20, Node-API 9, Node-API-only. Every
artifact binds a lowercase ASCII relative non-traversing path, kind, byte size, SHA-256 digest,
source/builder/toolchain/provenance digests, exact dynamic dependencies, and a
component-specific Mach-O signing policy. Release keys are scoped to package
names and the complete component set. Trust policy can revoke a key, release
ID, or manifest digest and can reject an old release epoch. A normalized SPKI or
public-key digest may occur under only one key ID across active and revoked
records, so compromised key material cannot survive revocation through an alias.

Mixed-case/case-fold, Unicode-normalization, duplicate, and file/directory-prefix
path aliases are rejected. The v1 artifact SHA-256 digests, component signing
identifiers, and designated-requirement identities must be distinct. Static and
native evidence must additionally keep the retained descriptor, static CDHash,
loaded/exec image, and mapped-process image identities pairwise distinct; this
contract permits no implicit multi-role artifact.

The signed policy also pins the digest of the intended install root and the
implementation, source, and loaded-image digests of the native attestor. Static
file-descriptor identity must equal the native attestor's on-disk identity—not
merely describe another valid object. A domain-separated component binding
digest closes the artifact hash, static CDHash and designated requirement,
retained descriptor, loaded/exec image, mapped process image, selected host
validation mode, attestor implementation, manifest/inspection, and actual ACL
evidence into one claim. Static, native, and HIL evidence carries a bounded
`valid_until`; the doctor rejects future, expired, or over-age claims.

## API

- `digestReleaseManifest(manifest)` validates and digests a closed manifest.
- `releaseSignatureMessage(claim)` returns the domain-separated bytes an
  external release signer signs. This package has no signing API and contains
  no private key.
- `verifyReleaseEnvelope({ envelope, trust_policy, now })` verifies an Ed25519
  envelope against a caller-supplied trust policy and trusted time.
- `digestStaticInspectionEvidenceBody`,
  `digestNativeAttestationEvidenceBody`, and `digestHilEvidenceBody` close and
  digest the three diagnostic evidence bodies.
- `evaluateNativePrebuildDoctor(input)` compares the signed release, pinned
  evaluation context, static inspection, native loaded-image attestation, and
  HIL evidence.

The doctor consumes data only. It does not inspect the host, open artifacts,
load native code, enumerate a Chameleon, or provision a principal. Its reports
are `unavailable`, `blocked`, `qualified_pending_hil`, or
`diagnostic_complete_non_authorizing`. Every report sets `production_ready`,
`hardware_access_authorized`, and `authoritative` to `false`, including a report
with complete caller-supplied HIL evidence. A separate server-enforced admission
authority must consume independently authenticated evidence before hardware
access can ever become reachable.

## Distinct trust layers

An Ed25519 release signature authenticates the release manifest. It is not a
Mach-O code signature. A Mach-O Developer ID signature and notarization result
describe a particular on-disk code object; they do not prove that object is the
one mapped or executed. Native loaded/exec-image evidence must bind retained
file descriptors and static CDHashes to the process image observed by the
kernel.

Root ownership is not immutability. Static evidence separately covers a
root-owned ancestry walk, `openat` with no-follow semantics, regular single-link
objects, stable pre/post identity, retained descriptors, and a read-only mount
or system immutable flags. Those facts still do not establish the dedicated
principal or its ACL. The manifest binds a principal/ACL policy digest, and
the evaluation context pins a distinct observed ACL-evidence digest. Static and
native layers must bind both and must also agree on the filesystem-immutability
evidence digest. A policy digest is never treated as its own observation.

Finally, none of those layers proves real hardware behavior. HIL remains a
separate closed gate set for IPC descriptor binding, read-only Chameleon
inventory, safety cleanup faults, launcher principal isolation, cross-component
custody, and negative tamper cases. The HIL record must cross-bind the signed
suite, authority scope, device-qualification policy, fixture manifest, operator
witness policy, the context-pinned device and witness identities, and the exact
native attestation it exercised.

This package intentionally ships source and documentation only. It does not
ship native binaries, a production signature, an installer, a trust root,
native attestation, principal/ACL provisioning, or HIL results.

## Version 2 post-exec capability handoff seam

Version 1 remains unchanged and continues to describe its original closed
four-component release and three-layer diagnostic evidence chain. Version 2 is
an independently domain-separated contract; a v1 manifest, envelope, trust
policy, signature, or evidence digest cannot be substituted into a v2 call.
The v2 release set contains the four v1 roles plus two standalone executables:

| Component | V2 form |
| --- | --- |
| `native_ipc_acceptor` | Node-API bundle |
| `chameleon_cdc_custody` | Node-API bundle |
| `safety_watchdog` | Mach-O executable |
| `privileged_launcher` | Mach-O executable |
| `lifecycle_custodian` | Mach-O executable |
| `native_dispatch_custodian` | Mach-O executable |

For every role, the v2 manifest pins the artifact and build provenance plus the
exact selected CDHash, digest and canonicalization scheme of the complete
CodeDirectory candidate set, the bounded canonical-base64url bytes, size,
format, and digest returned by `SecRequirementCopyData`, CodeDirectory flags,
entitlements digest and scheme, signing identifier, team, and code type. The
native supervisor can therefore call `SecRequirementCreateWithData` using
signed bytes; it never obtains requirement text or binary from caller evidence.
The Security.framework representation is an opaque stable binary blob, not an
ASN.1 value that this JS package attempts to reinterpret. It separately
pins the arm64 Mach-O slice metadata and UUID; launch UID, GID, no-login
principal and group/audit/sandbox policies; expected mapped text and `__LINKEDIT`
measurements; and the capability ABI. Each ABI carries an exact ordered
descriptor role/count/type/access/status-flag/descriptor-flag table and signed
bounded references for request, result, effect-journal, and receipt schema
artifacts: relative path, byte size, SHA-256, media type, canonicalization, and
descriptor-relative loading scheme. The global grant, GO, receipt, and outbox
schemas use the same signed reference form. No parser input required by the
handoff is supplied solely by doctor evidence. Artifact hashes, CDHashes,
candidate sets, serialized
requirements, signing identifiers, Mach-O UUIDs, principal IDs, UIDs, GIDs, and
ABI IDs are pairwise role-distinct.

Darwin descriptor access is encoded without a string-only assertion: the
signed required/forbidden status masks close `O_ACCMODE` to `O_RDONLY`,
`O_WRONLY`, or `O_RDWR` for the declared access mode, and both the signed and
observed descriptor masks require `FD_CLOEXEC` before acknowledgement.

`darwin_cdhash_candidate_set_jcs_v1` means a JCS-encoded array containing every
CodeDirectory candidate as `{algorithm, cdhash}`, sorted first by lowercase
ASCII algorithm and then by lowercase hexadecimal CDHash, with duplicates
rejected before SHA-256. `security_entitlements_der_sha256_v1` means SHA-256 of
the exact DER entitlements payload selected from the validated CodeDirectory.
These scheme identifiers are signed so a native implementation cannot silently
choose a different candidate or entitlement canonicalization.

The global authority handoff scheme is exactly
`post_exec_audittoken_seccode_scm_rights_v1`. Its intended native sequence is:

1. Start the selected signed child without target or device descriptors.
2. Obtain the post-exec peer audit token and pidversion from the AF_UNIX socket.
3. Resolve the running guest with `SecCodeCopyGuestWithAttributes`, compare the
   exact serialized requirement, CDHash candidate set, Mach-O identity, mapped
   measurement, and dropped principal, and finish this before any grant.
4. Persist a single-use 256-bit nonce plus monotonically increasing 64-bit
   generation replay fence, then transfer the closed ABI once with
   `SCM_RIGHTS`.
5. Persist and authenticate the grant, SCM_RIGHTS acknowledgement, GO, effect,
   receipt, and recovery outbox under the signed continuous-clock phase and
   total deadlines. Capabilities close before the durable receipt.

The `privileged_launcher` is the one signed supervisor component and is
attested once; it is never also modeled as its own worker. The other five
components form the exact ordered capability-recipient set. Each recipient has
a fresh post-exec connection and typed worker lineage binding audit token, PID,
pidversion, process instance/start identities, direct-parent supervisor
identity, mapped image, launch principal, and per-launch listener identity.
The tagged component handoff and component-binding digest repeat the appropriate
supervisor or recipient structure, while each recipient session repeats its
worker lineage and authenticated exchange exactly.

Listener, launch, capability, grant, GO, and committed replay-fence counters are
canonical unsigned 64-bit decimal strings, including values above JavaScript's
safe-integer ceiling. A launch nonce is never embedded in diagnostic evidence;
`launch_nonce_digest` is SHA-256 of the decoded canonical 32-byte launch nonce.
Listener generations, launch generations, capability generations, and the
shared grant/GO sequence space increase strictly; GO is exactly the grant
sequence plus one. Per-session audit tokens, process instances/starts, listener
and connection identities, nonce digests, capability sets, grant identities,
GO identities, and terminal record digests are single-use. Recomputable grant
and GO record digests take the typed supervisor snapshot, worker lineage,
connection, nonce, capability ABI/set, and record IDs/sequences as inputs.

The manifest rejects alternate transports, wall-clock deadlines, unbounded
phases, weaker nonce generation, path reopen, multiple grants, missing replay
durability, unauthenticated receipts, or non-durable grant/GO/receipt/outbox
ordering. It also rejects missing or aliased schema references, mismatched
descriptor counts, unknown descriptor types/access modes, overlapping required
and forbidden flags, noncanonical or over-bound requirement data, and any
requirement byte/digest mismatch. V2 evidence repeats the peer/SecCode schemes
and binds immutable `openat` schema descriptors, verified byte hashes, and
compiled parsers to every signed schema reference. Each of the five recipient
session transcripts is a recomputable domain-separated digest over its typed
worker lineage, exchange binding, timestamps, durable terminal records, and
ordering assertions. Each tagged component binding closes either the one
supervisor identity or a recipient transcript with the observed code, Mach-O,
principal, mapped image, capability ABI, and native attestor identities.

### V2 API

- `digestReleaseManifestV2(manifest)` validates and digests the six-component
  v2 manifest.
- `releaseSignatureMessageV2(claim)` produces only the domain-separated bytes
  for an external Ed25519 signer; the package still has no signing API.
- `verifyReleaseEnvelopeV2({ envelope, trust_policy, now })` verifies a v2
  release envelope against caller-supplied data.
- `digestHandoffSessionV2`, `digestObservedMachoIdentityV2`,
  `digestObservedLaunchPrincipalV2`, `digestObservedMappedMeasurementV2`,
  `digestObservedCapabilityAbiV2`, `digestCapabilitySetV2`,
  `digestGrantRecordV2`, `digestGoRecordV2`, `digestComponentBindingV2`, and
  `digestNativePrebuildAttestationV2Body` build closed diagnostic evidence
  digests without inspecting or changing the host.
- `evaluateNativePrebuildDoctorV2(input)` checks the v2 envelope, pinned
  evaluation context, external-keyring evidence, immutable-install evidence,
  post-exec sessions, and six component observations.

The checked-in golden vector fixes the v2 manifest digest to
`5ad26bd5c565fc5a4fa988046736f9736fca3068a1886c0f3e9ead1b54eba215` and its
complete diagnostic evidence digest to
`fed40f811a985e917c0ea8f5a6237bfe03b0665a386e2f38c387a22d6109ddaa`.
These vectors are synthetic schema and diagnostic fixtures; they are not a
valid native, Security.framework, or hardware-in-the-loop attestation.

V2 JS is a schema and diagnostic seam only. It does not read an external
keyring, observe a kernel audit token, call Security.framework, map a Mach-O,
transfer descriptors, persist a replay fence or outbox, or authenticate a live
receipt. Caller assertions such as `root_owned`, `immutable`, or
`verified_by_native_attestor` never become authority merely by passing schema
validation. Both v2 verification and doctor results always set
`production_ready`, `hardware_access_authorized`, and `authoritative` to
`false`; the doctor additionally records that it performed no host inspection,
native execution, keyring read, or capability transfer. Production requires an
external immutable enrolled keyring, a signed native implementation of the
post-exec protocol, and a separate server-enforced admission decision.
