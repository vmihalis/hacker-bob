# Darwin lifecycle custodian source projection

This private, source-only package contains Bob's descriptor-relative lifecycle
custodian and its local test build. It is not a production helper and is
excluded from the canonical `hacker-bob` package.

The test executable accepts only fixed inherited descriptors: target root on
fd 3, prepared source root on fd 4, a read-only request on fd 5, and the result
AF_UNIX stream capability on fd 6. It validates exact access/status and
descriptor flags, rejects descriptor aliases, and shuts down fd 6's receive
half before parsing a request or mutating the target. Target operations use
`openat`, `fstatat` with
`AT_SYMLINK_NOFOLLOW`, `mkdirat`, `renameat`, and `unlinkat`. No caller path is
accepted by the executable.

The checksummed v2 transaction journal binds both the original leaf and the
staged tree by device, inode, inode generation, birth time, and exact type/mode.
Recovery rolls back an identity-matched pre-commit rename and rejects an
unknown substituted leaf or backup without deleting it. Replace recovery also
revalidates the complete staged tree against the exact request before deleting
or committing it.

Production mutation remains fail-closed until a signed loader binds an opened,
qualified helper to the image the kernel actually executes or maps. This
source projection does not satisfy that release qualification. Its journal
checksum detects corruption but is not adversarial authentication; production
must protect or authenticate journal ownership under the exclusive custodian
principal.
