"use strict";

// Operator-attested lab / private-target authorization.
//
// Bob's scope kernel (scope.js assertHttpScopeDomain) rejects any target_domain
// that is not a public, registrable DNS domain — bare IPs, loopback, and RFC1918
// hosts all fail with "not a public DNS domain". That gate is the scope-ownership
// control: a registrable public domain is provable program scope; a private IP
// carries no ownership signal. This module is the ONLY sanctioned escape — an
// operator who OWNS a private lab host attests to it at bob_init_session, and
// that attestation, recorded as an audit-graded (agent-unforgeable) session
// artifact, lets the kernel scope a session to that one private host.
//
// Design mirrors enforcement-attest.js:
//   * one home for the exact-match ack token; a typo fails CLOSED (no escape);
//   * OFF by default — no attestation, no escape, default public-DNS gate intact;
//   * eligibility is deliberately narrow: IPv4 loopback (127.0.0.0/8) + RFC1918
//     (10/8, 172.16/12, 192.168/16) only. IPv6, hostnames (incl. "localhost"),
//     link-local (169.254/16), cloud-metadata, and .internal/.local names are
//     NOT eligible even WITH a valid attestation — defense in depth against an
//     attested session pivoting to SSRF-to-metadata or a neighboring host.
//
// lab-authorization.json is in AUDIT_GRADED_BASENAMES, so the PreToolUse
// write-guard blocks any agent Write to it. Only bob_init_session (via
// recordLabAuthorization below) can create it, so a prompt-injected evaluator
// cannot self-grant a private-target scan by forging the file.

const net = require("net");

// Exact attestation token. The operator must pass it verbatim; any other value
// (typo, truncation, "yes") fails closed and the private target stays rejected.
const LAB_TARGET_ACK_TOKEN = "i-own-and-am-authorized-to-test-these-private-targets";

const LAB_AUTHORIZATION_BASENAME = "lab-authorization.json";

function ipv4Octets(address) {
  const parts = String(address).split(".");
  if (parts.length !== 4) return null;
  const octets = parts.map((part) => Number(part));
  if (octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) return null;
  return octets;
}

function isLoopbackIpv4(address) {
  const octets = ipv4Octets(address);
  return octets != null && octets[0] === 127;
}

function isRfc1918Ipv4(address) {
  const octets = ipv4Octets(address);
  if (octets == null) return false;
  const [a, b] = octets;
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  return false;
}

// A host is lab-eligible iff it is an IPv4 literal in the loopback or RFC1918
// ranges. IPv6, hostnames, link-local, and cloud-metadata are intentionally
// excluded — eligibility is the FIRST of two gates (the second is a valid
// attestation), so a non-eligible host can never be reached even under ack.
function labTargetEligibleHost(host) {
  const address = String(host || "").replace(/^\[|\]$/g, "");
  if (net.isIP(address) !== 4) return false;
  return isLoopbackIpv4(address) || isRfc1918Ipv4(address);
}

// Validate + normalize an operator attestation. Returns a frozen authorization
// object or null. FAIL CLOSED: anything malformed, or a non-exact ack, → null.
function parseLabAuthorization(raw) {
  if (raw == null || typeof raw !== "object" || Array.isArray(raw)) return null;
  if (raw.private_targets !== true) return null;
  if (raw.ack !== LAB_TARGET_ACK_TOKEN) return null;
  return Object.freeze({
    private_targets: true,
    ack: LAB_TARGET_ACK_TOKEN,
    scope: "rfc1918_loopback_ipv4",
  });
}

// A host is permitted iff it is lab-eligible AND a valid attestation is present.
function labTargetPermitted(host, { authorization } = {}) {
  if (!labTargetEligibleHost(host)) return false;
  return parseLabAuthorization(authorization) != null;
}

// Read the persisted, audit-graded attestation for a target's session. Returns
// the normalized authorization or null. FAIL CLOSED on any read/parse error
// (missing file, malformed JSON, forged shape). Lazy-require paths/storage to
// avoid a load-order cycle through scope.js.
function labAuthorizationForTarget(targetDomain) {
  if (!targetDomain) return null;
  try {
    const { labAuthorizationPath } = require("./paths.js");
    const { readJsonFile } = require("./storage.js");
    const doc = readJsonFile(labAuthorizationPath(targetDomain), {
      label: LAB_AUTHORIZATION_BASENAME,
    });
    return parseLabAuthorization(doc);
  } catch {
    return null;
  }
}

// Persist the attestation as an audit-graded session artifact. The caller
// (initSession) must already hold the session lock and have created the session
// directory. No-op when the authorization is null — the default OFF path writes
// nothing. Returns the normalized authorization that was written, or null.
function recordLabAuthorization(targetDomain, authorization) {
  const normalized = parseLabAuthorization(authorization);
  if (!normalized) return null;
  const { labAuthorizationPath } = require("./paths.js");
  const { writeFileAtomic } = require("./storage.js");
  writeFileAtomic(
    labAuthorizationPath(targetDomain),
    `${JSON.stringify(normalized, null, 2)}\n`,
  );
  return normalized;
}

module.exports = {
  LAB_TARGET_ACK_TOKEN,
  LAB_AUTHORIZATION_BASENAME,
  labTargetEligibleHost,
  parseLabAuthorization,
  labTargetPermitted,
  labAuthorizationForTarget,
  recordLabAuthorization,
};
