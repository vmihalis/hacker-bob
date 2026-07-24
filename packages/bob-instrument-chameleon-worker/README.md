# Chameleon native worker (acceptance precursor)

This optional package is the native USB CDC boundary for the Chameleon
provider. It is deliberately separate from both Hacker Bob core and the pure
`@hacker-bob/instrument-chameleon` codec/custody package. Import and driver
construction are inert. The driver never resolves or imports `serialport` from
ambient `node_modules`, and it does not accept a caller loader, constructor, or
binding as production dependency authority. With no private dependency port,
discovery fails closed before enumeration or open.

The only dependency port currently implemented is deliberately named and
branded as a test-only fixture. Its optional surface qualifier re-reads an
exact synthetic `serialport@13.0.0` fixture tree and rejects symlinks, hardlinks,
unexpected or missing entries, byte or mode drift, package/lock mismatch, and
post-qualification replacement. The expected file records are still supplied
by the fixture caller, the checked files are never loaded, and the injected
fixture constructor is not cryptographically bound to those bytes. Accordingly
the projection is explicit that it is caller-asserted, fixture-only,
non-authoritative, and not production-ready.

Worker-source installation now accepts only a separately signed immutable
CommonJS closure. The release manifest binds the exact worker entrypoint, its
closure-local `@hacker-bob/instrument-chameleon` package manifest and exports,
every transitively reachable JavaScript byte, and every literal module edge.
Only an exact Node.js 20 package graph is admitted. Dynamic loaders, lifecycle
scripts, undeclared dependencies, and fallback to ambient `node_modules` are
rejected. `serialport` is intentionally not a production dependency: its only
remaining representation is the synthetic test-only dependency port described
above.

This JavaScript release envelope remains separate from signed native-prebuild
v2. It proves package bytes against the supplied release-key policy, including
trust epoch, revocation epoch, release floor, and emergency revocations. The
repository has no production external immutable worker-keyring custodian and no
probe-to-exec mapped-image binding yet, so this package-provenance result is
explicitly non-authorizing. Installation and probe remain `production_ready:
false`; native code identity and HIL are still required before execution.

The stock `serialport@13.0.0` open API cannot prove that DTR was never asserted
between the native open and a later `set({ dtr: false })` call. The driver
therefore refuses to open with stock SerialPort alone. Its open seam requires an
injected native atomic-open implementation that returns an exact DTR-off,
exclusive-lock attestation and separately transfers the hardware identity
measured from the opened endpoint. The worker compares that transferred identity
with enrollment before DTR activation; it does not copy discovery identity into
an "opened identity" result.

That seam is dependency-injected for fixture tests, but is not itself trusted
evidence. The JavaScript callback receives the expected fields and can forge
them; the opaque `native_proof_digest` is shape-checked, not cryptographically
verified by this precursor. Neither an exact object match nor the fixture test
proves DTR history, endpoint identity, path continuity, or an OS lock. A
separately measured native implementation, verifier/trust root, path-swap
negative test, and HIL verdict are still required before this package can claim
production readiness.

Serial number, VID/PID, USB location, and device-node path are never hashed and
relabelled as high-entropy device identity. Discovery also requires an
operator-owned private resolver that maps those native facts to the separately
enrolled custody identity; without it, discovery fails closed.

No generic read, write, transact, path, byte, or raw-handle API is exported. The
transport contract distinguishes that absent generic write surface from the
single exact brokered request/response write needed by a Chameleon command:
the latter is disabled before activation and becomes available only through the
custody package's one-use connection-generation handoff. The only constructor
returns the existing branded USB CDC driver capability. The adapter correlates
the response command, rejects oversized or trailing frames, and never retries
an ambiguous write. These are local protocol guards, not execution authority or
a hardware-conformance result; `production_ready` and `hil_proven` remain false.
