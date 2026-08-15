// callback-ssrf-guard.js — runtime SSRF / host-allowlist check for callbackUrl.
// authorization.schema.json (L67) flags this as a REQUIRED runtime check that JSON Schema
// cannot cover: a schema-valid host may still resolve to 127.0.0.1, 169.254.169.254,
// RFC1918, or a DNS-rebind target. This guard RESOLVES + REJECTS private/link-local/metadata
// destinations before any callback write. It is a DEFENSIVE guard (blocks exfil / SSRF), not
// offensive tooling.
//
// Runbook: aabw-2026/projects/06-aws-hacker-bob/AGENTCORE-BRANCH-PLAN.md
'use strict';

const net = require('net');
const dns = require('dns');
const { isBlockedInternalHost } = require('../../mcp/core/url-surface.js');

// Mirrors mcp/lib/safe-fetch.js:86-96 — wraps dns.lookup(hostname, { all: true }, cb) in a
// Promise. Overridable via options.lookup so tests can inject a stub (DNS-rebind scenario)
// without touching the real network.
function lookupAll(hostname, lookupFn) {
  return new Promise((resolve, reject) => {
    lookupFn(hostname, { all: true }, (error, addresses) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(addresses || []);
    });
  });
}

// Verifies, at RUNTIME, that a signed authorization payload's callbackUrl is safe to write
// a curated run_event/report to: (a) exactly the pre-declared seal endpoint (operator/
// deploy-time configuration, never taken from the untrusted payload's own claim) and (b)
// resolves to a public, non-internal address — re-checked AFTER DNS resolution so a rebind
// (hostname first resolves public, then to a private/metadata address on a later lookup)
// cannot slip through. Fails closed on every branch: every rejection path throws, none
// return a falsy "safe-ish" value.
async function assertCallbackUrlSafe(url, options = {}) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('Invalid callbackUrl');
  }

  if (parsed.protocol !== 'https:') {
    throw new Error(`callbackUrl must use https: (got ${parsed.protocol})`);
  }

  const allowedHost = options.allowedHost || process.env.RUNNER_CALLBACK_ALLOWED_HOST;
  if (!allowedHost) {
    throw new Error('No callback allowlist configured (RUNNER_CALLBACK_ALLOWED_HOST or options.allowedHost)');
  }

  const hostname = parsed.hostname.toLowerCase();
  const normalizedAllowedHost = String(allowedHost).toLowerCase();
  if (hostname !== normalizedAllowedHost) {
    throw new Error(`callbackUrl host "${hostname}" is not the allowlisted callback host`);
  }

  if (isBlockedInternalHost(hostname)) {
    throw new Error(`callbackUrl host "${hostname}" is a blocked internal/private host`);
  }

  if (!net.isIP(hostname)) {
    const lookupFn = options.lookup || dns.lookup;
    const addresses = await lookupAll(hostname, lookupFn);
    if (!addresses.length) {
      throw new Error(`DNS lookup returned no addresses for callbackUrl host "${hostname}"`);
    }
    for (const addr of addresses) {
      if (isBlockedInternalHost(addr.address)) {
        throw new Error(`callbackUrl host "${hostname}" resolved to a blocked internal/private address: ${addr.address}`);
      }
    }
  }

  return { url: parsed.toString(), host: hostname };
}

module.exports = { assertCallbackUrlSafe };
