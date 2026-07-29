# Hacker Bob Darwin trusted-clock native source and local loader

This optional, provider-neutral package closes the source, portable framing,
zero-configuration Node-API client, and fail-closed local build/loader contract
for a future Darwin arm64 trusted-clock service. It is not installed by Hacker
Bob and cannot authorize physical work.

The checked-in native enrollment is deliberately impossible: its designated
requirements contain `UNPROVISIONED`, its identity digests are zero, and its
compile-time provisioned gate is false. `trusted_clock_service.cc` obtains only a
launchd socket, and `trusted_clock_client.cc` exposes only
`hb_trusted_clock_sample(output)`; neither accepts a caller path, callback,
readiness flag, clock selector, or trust root.

`lib/source-contract.js` is a portable conformance surface. It issues an internal
random challenge, verifies the exact fixed response frame, enforces one sample
per connection, rejects replay/identity/epoch/monotonic drift, and returns only a
private non-serializable sample branded `production_ready: false`.

`native/trusted_clock_node.cc` is a zero-input, process-local one-shot Node-API
wrapper around that fixed C client. The public JavaScript client accepts no path,
callback, descriptor, requirement, trust root, enrollment, fallback, or readiness
override. Explicit construction verifies an exact local source/artifact receipt,
measures the addon before and after direct `dlopen`, locks its CommonJS cache
entry, and retains the raw loader and native function only in private closures.
Immediately after capture, the loader and addon cache exports are replaced with
frozen, null-prototype, non-callable tombstones. Ordinary post-construction
`require()` and `require.cache` access therefore cannot consume the native
one-shot before the branded client does. The source enrollment is impossible,
so a local call deterministically fails closed before socket access.

The local receipt binds the addon and standalone service to the exact checked-in
native and JavaScript execution/build source suite. It is same-UID development
evidence—not a signature, immutable installation proof, or mapped-image
attestation. Validation intrinsics are captured during the first authentic
client import and later drift is rejected; a hostile same-process actor that
replaces Node built-ins before that import is outside this local receipt's trust
boundary and remains an explicit production blocker. The tombstones are a
post-construction CommonJS custody hardening, not process isolation: an actor
with arbitrary in-process code execution can pre-import internals, copy or load
the addon through another path, hook module/filesystem machinery, attach a
debugger, or inspect process memory. Production capability custody therefore
requires a separate signed client process or equivalently isolated native
boundary with loaded-image attestation. The explicit blocker is
`trusted_clock_native_client_same_process_capability_custody_not_isolated`.
Any file in the fixed prebuild slots causes the loader to reject: prebuild
loading remains disabled until a separate signed trusted-clock release envelope
and operator-pinned trust root are implemented.

Build and run the focused native suite on Darwin arm64 with pinned Node 20:

```sh
npm run test:native --prefix packages/bob-instrument-trusted-clock-native-darwin
```

Run on Darwin arm64 with Node 20:

```sh
npm test --prefix packages/bob-instrument-trusted-clock-native-darwin
```

The JavaScript contract alone is portable:

```sh
npm run test:portable --prefix packages/bob-instrument-trusted-clock-native-darwin
```

The full test performs strict source checks, builds the unprovisioned addon and
service, verifies hostile receipt/cache/prebuild cases, and confirms that the
one-shot client returns the fixed unprovisioned failure. It never installs,
launches, or connects to a daemon. Build output is ignored and excluded from the
package allowlist. See
`docs/adr/darwin-trusted-clock-source.md` for custody, release-envelope, restart,
and HIL requirements. Native-prebuild v2 is intentionally unchanged.
