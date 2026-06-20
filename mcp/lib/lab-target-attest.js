"use strict";

// Operator-attested lab / private-target authorization.
//
// Bob's scope kernel (scope.js assertHttpScopeDomain) rejects any target_domain
// that is not a public, registrable DNS domain — bare IPs, loopback, and RFC1918
// hosts all fail with "not a public DNS domain". That gate is the scope-ownership
// control: a registrable public domain is provable program scope; a private IP
// carries no ownership signal. This module is the ONLY sanctioned escape — an
// operator who OWNS a private lab host sets BOB_LAB_TARGET_ACK (consent) and
// BOB_LAB_TARGET (the exact authorized host) in the server environment AND
// declares private_targets intent at bob_init_session; that attestation,
// recorded as an audit-graded (agent-unforgeable) session artifact, lets the
// kernel scope a session to that one named private host. Both controls are
// operator env vars, never tool arguments, so a model can neither self-authorize
// by reading a published token from its own schema nor — while an ack is set for
// one lab box — pivot the grant to a neighboring private host.
//
// Design mirrors enforcement-attest.js:
//   * the ack is an operator ENV var (BOB_LAB_TARGET_ACK), out of the model's
//     reach; a typo/unset fails CLOSED (no escape);
//   * OFF by default — no env ack, no escape, default public-DNS gate intact;
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

// Operator attestation channel. The ack is an ENVIRONMENT variable, NOT a tool
// argument: a model that can call bob_init_session must not be able to authorize
// a private target by passing a value it can read from its own tool schema. The
// operator sets BOB_LAB_TARGET_ACK to this exact token in the MCP server's
// environment at launch; a running model cannot mutate the server process's
// environment (nor a peer process's), so this is an operator-only control even
// for a prompt-injected evaluator with shell access. The token value is the
// agreed env contract — a deliberate, exact opt-in signal whose typo/unset fails
// CLOSED — not a secret, which is why it is fine for it to live in source.
const LAB_TARGET_ACK_TOKEN = "i-own-and-am-authorized-to-test-these-private-targets";
const LAB_TARGET_ACK_ENV = "BOB_LAB_TARGET_ACK";
// The operator also names the EXACT host(s) they authorize, comma-separated, in
// BOB_LAB_TARGET. This binds the grant to the intended host: while the ack is set
// for one lab box, a prompt-injected orchestrator must not be able to scope a
// session to a NEIGHBORING private host (e.g. sweep the operator's RFC1918 LAN).
const LAB_TARGET_HOST_ENV = "BOB_LAB_TARGET";

const LAB_AUTHORIZATION_BASENAME = "lab-authorization.json";

// The operator-only consent gate: true iff the exact ack token is set in the
// server environment. Read ONLY from process.env — never from a tool argument or
// the published schema — so a prompt-injected evaluator cannot satisfy it.
function operatorLabAckPresent() {
  return process.env[LAB_TARGET_ACK_ENV] === LAB_TARGET_ACK_TOKEN;
}

// The operator-declared set of exact authorized lab hosts (from BOB_LAB_TARGET).
// Bracketed IPv6-style wrappers are stripped for comparison parity.
function operatorAuthorizedLabHosts() {
  const raw = process.env[LAB_TARGET_HOST_ENV];
  if (!raw) return [];
  return raw
    .split(",")
    .map((h) => h.trim().replace(/^\[|\]$/g, ""))
    .filter(Boolean);
}

// The operator-only host-binding gate: true iff `host` is one of the exact hosts
// the operator named in BOB_LAB_TARGET. Read ONLY from process.env, so the agent
// (which controls target_domain) cannot widen the grant to another private host.
function operatorAuthorizedLabHost(host) {
  const address = String(host || "").replace(/^\[|\]$/g, "");
  return operatorAuthorizedLabHosts().includes(address);
}

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
// object or null. FAIL CLOSED: anything malformed, intent not asserted, OR the
// operator env ack absent → null. The tool argument carries only the non-secret
// INTENT (private_targets); the binding operator control is the env ack, so a
// model that supplies the intent (even with a guessed/published token field) is
// rejected unless the operator has set BOB_LAB_TARGET_ACK. The legacy `ack`
// argument field is intentionally ignored (it is no longer a control surface).
function parseLabAuthorization(raw) {
  // Read the operator gate FIRST, before touching any attacker-influenced field
  // of `raw`. A hostile in-process object could expose `private_targets` as a
  // getter that sets the env var as a read side-effect and then satisfy the gate;
  // checking the env before reading `raw` makes that ordering impossible (and we
  // return early without ever invoking the getter). The stdio JSON transport
  // already delivers inert plain data, so this is defense for any future
  // non-JSON / in-process caller.
  if (!operatorLabAckPresent()) return null;
  if (raw == null || typeof raw !== "object" || Array.isArray(raw)) return null;
  if (raw.private_targets !== true) return null;
  return Object.freeze({
    private_targets: true,
    ack_source: "operator_env",
    scope: "rfc1918_loopback_ipv4",
  });
}

// A host is permitted iff it is lab-eligible AND a valid attestation is present
// AND the operator named this exact host in BOB_LAB_TARGET. The host-binding
// stops an active ack (set for one lab box) from being reused by a prompt-injected
// agent to scope a session to a neighboring private host.
function labTargetPermitted(host, { authorization } = {}) {
  if (!labTargetEligibleHost(host)) return false;
  if (parseLabAuthorization(authorization) == null) return false;
  return operatorAuthorizedLabHost(host);
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
  // Persist a self-describing audit record: the normalized attestation PLUS the
  // exact host this session was scoped to and the operator's authorized-host set
  // at mint time, so the artifact is forensically meaningful on its own. The
  // live gate still reads the env (operatorAuthorizedLabHost), not this file.
  const record = {
    ...normalized,
    target_host: targetDomain,
    authorized_hosts: operatorAuthorizedLabHosts(),
  };
  writeFileAtomic(
    labAuthorizationPath(targetDomain),
    `${JSON.stringify(record, null, 2)}\n`,
  );
  return normalized;
}

module.exports = {
  LAB_TARGET_ACK_TOKEN,
  LAB_TARGET_ACK_ENV,
  LAB_TARGET_HOST_ENV,
  operatorLabAckPresent,
  operatorAuthorizedLabHost,
  LAB_AUTHORIZATION_BASENAME,
  labTargetEligibleHost,
  parseLabAuthorization,
  labTargetPermitted,
  labAuthorizationForTarget,
  recordLabAuthorization,
};
