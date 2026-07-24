# ADR: Descriptor-relative lifecycle custodian

Status: accepted architecture; production mutation intentionally blocked

## Context

Bob installs two optional Chameleon provider packages and six canonical nested
runtime packages into an operator-selected project. Retaining and repeatedly
revalidating pathname ancestry in JavaScript did not close the interval between
the last check and `mkdir`, `rename`, or recursive removal. An attacker able to
swap an ancestor during that interval could redirect an otherwise allowlisted
mutation outside the project.

This decision covers package lifecycle only. It does not create a generic
privileged path mutator and does not authorize hardware access.

## Decision

All optional-provider replace/remove operations and canonical nested-package
replace/remove operations cross one provider-neutral native custodian.

The production controller must:

1. Resolve only a fixed, enrolled, signed platform helper. No caller path,
   environment selector, or search-path lookup may choose it.
2. Prove the helper's release identity, exact mode, size, digest, signing
   requirement, and stable single-link regular-file identity.
3. Bind the retained, qualified helper to the image the kernel actually execs
   or maps. Pathname pre/post verification is insufficient.
4. Open the project root once with directory and no-follow semantics and prepare
   and open one immutable source root, but retain those authorities in the
   supervisor while pathname exec occurs. Transfer them on the fixed descriptor
   ABI only after the post-exec audit-token, code-signing, and mapped-image
   protocol in `darwin-post-exec-capability-release.md` succeeds. The child
   receives no target or source pathname and may not mutate before one-use GO.

The native custodian accepts only an operation enum and one of eight enrolled
selections:

- `chameleon_ultra:worker_source`
- `chameleon_ultra:darwin_arm64_native_prebuild`
- the six roots in `CANONICAL_RUNTIME_PACKAGE_ROOTS`

Names for the parent components, leaf, staging directory, backup directory,
and journal are derived inside native code. Request paths are normalized
relative file components, bounded to 128 files, 16 components per file, and a
128 KiB request.

After authority starts, target operations use only `openat`, `fstatat` with
`AT_SYMLINK_NOFOLLOW`, `mkdirat`, `renameat`, `unlinkat`, and bounded
descriptor-relative recursion. `/dev/fd` path bridges and target pathname
mutation are forbidden. Prepared input and the request must be regular,
single-link objects with exact modes, sizes, and SHA-256 digests. Created files
and directories receive exact modes and are fsynced along with their parent
directories.

The four inherited capabilities have exact topology: fds 3 and 4 are distinct
read-only directories, fd 5 is a single-link mode-0444 regular request, and fd
6 is a connected AF_UNIX stream. Status flags and descriptor flags are exact,
object aliases are rejected, and the result socket's receive half is shut down
before request parsing. An invalid fd 6 is neither written nor permitted to
reach target-parent creation, so mutation cannot precede result-capability
admission.

Replace uses a bounded, checksummed binary journal with building, prepared,
backup-renamed, installed, and committed phases. Recovery is selection-bound
and replacement replay is plan-digest-bound. Removal can recover or clean only
the exact enrolled leaf and transaction names. Recursive cleanup has explicit
depth and entry ceilings and never follows a symlink or modifies bytes through
a hardlink.

Journal version 2 also binds the original leaf and staged tree by device,
inode, Darwin inode generation, birth time, and exact object type/mode. Its
header and both identity records have zero-only reserved words covered by the
checksum. Recovery distinguishes the durable prepared and backup-renamed
states, rolls a fresh install back to absence when staging was renamed before
the installed journal became durable, and restores an update's original leaf.
If a leaf or backup no longer has the full journaled identity, recovery rejects
and preserves the unknown entry instead of deleting or committing it. Replace
recovery also requires an identity-matched staged directory to reproduce the
request's complete file tree before that directory can be deleted or committed.
Removal remains a separately authorized cleanup operation over the enrolled
names and does not claim this replace-replay property.

The checksum detects torn or corrupt journal bytes; it is not authentication
against an actor who can replace the journal and recompute the checksum.
Production admission therefore also requires journal ownership to be protected
by the exclusive custodian principal or an authenticated journal MAC/signature.
The current production wrapper stays closed and does not claim this source-only
fixture satisfies that requirement.

## Bootstrap and current release state

The C implementation under
`packages/bob-lifecycle-custodian-native-darwin` is a source-only local test
projection. Its executable is built under a test-only compile gate, takes a
fixed test brand, and is excluded from both its own pack surface and canonical
Bob. Tests install it through a private `require.cache` preload fixture; no
shipped CLI flag, environment variable, or lifecycle input selects it.

Production remains blocked with
`openat_to_exec_or_mapped_image_binding_missing`. `install`, update, and
non-dry-run uninstall fail before their first target mutation when the signed
qualified loader is unavailable. There is no JavaScript mutation fallback.
Status, doctor, import, and dry-run inspection remain inert and read-only.

## Consequences

- Swapping the project pathname after its root descriptor is retained cannot
  redirect native mutation to a matching outside leaf or transaction name.
- Symlink leaves are renamed or unlinked as links; symlink ancestors are
  rejected. Removing a target hardlink removes only that directory entry.
- A crash may leave bounded enrolled transaction state, which a request with
  the exact plan digest can recover deterministically.
- Canonical source admission and optional package qualification remain separate
  from mutation authority. Passing either does not activate hardware.
- Shipping production mutation requires a signed Darwin loader/prebuild and
  exec-or-mapped-image binding evidence; the source projection cannot be
  promoted by changing a path or copying its test executable.
