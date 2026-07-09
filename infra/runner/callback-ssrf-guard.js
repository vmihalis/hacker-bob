// callback-ssrf-guard.js — (P2) runtime SSRF / host-allowlist check for callbackUrl.
// authorization.schema.json (L67) flags this as a REQUIRED runtime check that JSON Schema
// cannot cover: a schema-valid host may still resolve to 127.0.0.1, 169.254.169.254,
// RFC1918, or a DNS-rebind target. This guard RESOLVES + REJECTS private/link-local/metadata
// destinations before any callback write. It is a DEFENSIVE guard (blocks exfil / SSRF), not
// offensive tooling. Only needed if the branch wires the Rail B callback/seal half.
//
// Runbook: aabw-2026/projects/06-aws-glassbox/AGENTCORE-BRANCH-PLAN.md
'use strict';

// TODO(build-day): resolve the callbackUrl host; REJECT loopback, link-local (169.254/16),
// RFC1918 (10/8, 172.16/12, 192.168/16), IPv6 ULA/loopback, and the metadata address
// (169.254.169.254). Re-check AFTER DNS resolution to defeat DNS-rebind. Allowlist ONLY the
// pre-declared seal endpoint. Fail closed.
module.exports = {
  assertCallbackUrlSafe(/* url */) {
    // TODO(build-day)
    throw new Error('callback-ssrf-guard not yet implemented (P2)');
  },
};
