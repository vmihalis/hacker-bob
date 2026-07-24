# Optional provider package lifecycle

Status: accepted for the non-activating Plane-PH packaging boundary.

## Decision

Canonical Hacker Bob ships provider-neutral runtime code, the
`@hacker-bob/instrument-contracts` package, the transport-neutral Chameleon
worker-runtime library, and the pure native release-trust and Darwin
principal/ACL contracts. It does not ship the privilege-separated worker
assembly, native implementation sources, native fixtures, native extensions,
executables, or a native prebuild. Real release envelopes, trust roots, HIL
evidence, and project-local install metadata are also absent from the canonical
tarball.

Optional packages are described by the frozen registry in
`scripts/lib/optional-provider-registry.js`. Installation policy is
`explicit_operator_only`; activation policy is `never_automatic`. Device
attachment is not an install or activation signal.

The lifecycle reports only these bounded states:

- `absent`
- `unsupported_host`
- `installed_unqualified`
- `qualified_diagnostic`
- `blocked`

Every state is non-authorizing. In particular, `installed_unqualified` never
means that a release signature is currently valid. `qualified_diagnostic`
requires fresh, explicit caller-supplied trust and qualification evidence to
cross-bind the exact installed files, and still reports
`production_ready: false` and `hardware_access_authorized: false`. Filenames,
package metadata, a cached manifest digest, or the presence of six files can
never imply qualification.

## Operator lifecycle

The explicit command surface is:

```text
hacker-bob optional-provider status PROJECT --provider ID --package ID [--release-verification FILE] --json
hacker-bob optional-provider install PROJECT --provider ID --package ID --source DIR --json
hacker-bob optional-provider update PROJECT --provider ID --package ID --source DIR --json
hacker-bob optional-provider uninstall PROJECT --provider ID --package ID --yes --json
```

Signed JavaScript worker-closure and native-prebuild install/update require
`--release-verification FILE`, whose JSON contains the caller-supplied release
envelope and trust policy. Status accepts the same evidence to reverify the
installed bytes as a non-authorizing diagnostic. Bob has no embedded real
trust root. Omitting `--yes` makes optional-package uninstall a dry run. None
of these commands loads provider JavaScript, loads a `.node` file, opens a
serial device, enumerates USB, performs network I/O, spawns a worker, or
activates a provider.

Ordinary `install` and `update` never create the optional-provider root.
Ordinary `doctor` performs a read-only compatibility/package-integrity probe;
absence and unsupported OS/architecture/Node 20/N-API are informational or
warnings and do not break core Bob. Full shared `uninstall` removes every
Bob-owned canonical nested package and all optional-package transaction state
while preserving unrelated packages.

## Package and transaction boundary

Worker-source install admits one signed three-package closure: the checked-in
worker assembly, `@hacker-bob/instrument-chameleon-worker-runtime`, and
`@hacker-bob/instrument-contracts`. Each package is bound to its actual
manifest, declared exports, exact dependencies, and package root. Relative
imports may not leave their declaring package; every cross-package import must
name a declared dependency export. An AST-based CommonJS policy admits only a
direct one-literal `require(...)` call, and the closed in-memory loader resolves
that call only through the verified edge table. Computed, optional, aliased,
process-backed, eval, and dynamic-import loaders are rejected. npm lifecycle
scripts, bins, native payloads, symlinks, hard links, ambient `node_modules`,
and undeclared files are rejected.

A native prebuild admits one v2 signed-manifest-bound package, exactly six
native components, and all 28 signed ABI/exchange schema artifacts. Legacy v1
four-component envelopes are rejected at this lifecycle boundary:

1. native IPC acceptor
2. Chameleon CDC custody component
3. safety watchdog
4. privileged launcher
5. lifecycle custodian
6. native dispatch custodian

Each component and schema path, size, and SHA-256 digest must match a currently
verified Ed25519 release envelope. Missing schemas are rejected rather than
deferred to runtime lookup. The registry also binds installed mode: native
addons, schemas, JavaScript, manifests, and docs are read-only `0444`; the four
signed standalone executables are read/execute `0555`. Mode is part of the
closed installed-file record and content digest. Source execute-bit drift,
installed mode drift, executable addons/schemas/docs, and an extra artifact all
fail closed.

Source and Bob-owned destination directory identities are retained and
revalidated across reads, writes, and renames. Package updates use fixed,
bounded `building -> prepared -> committed` journal states. A later explicit
install/update deterministically restores or finalizes an interrupted
transaction; an unjournaled staging/backup is blocked. Explicit package
uninstall and full Bob uninstall remove package, staging, backup, journal, and
temporary journal entries without following a symlinked owned ancestor.

Installed metadata contains only registry identity, hashes, sizes, timestamps,
release ID and epoch, trust/revocation epochs, and release-policy identity
digests. Update and repair compare those durable installed high-water values;
lower epochs and same-epoch release or policy equivocation fail before
destination mutation. It never stores source paths, envelopes, trust policies,
qualification evidence, local secrets, or hardware identifiers.

JavaScript signatures prove only the provenance of the signed package closure.
The closed loader is not a native running-code identity or an execution grant.
The lifecycle therefore continues to report `production_ready: false`,
`hardware_access_authorized: false`, and `activation_performed: false` until an
external immutable keyring and probe-to-exec identity binding exist.
