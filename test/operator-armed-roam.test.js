"use strict";

// Operator-armed cross-host roam (BOB_HTTP_ROAM_AUTHORIZED=<target_domain>). Proves the scope kernel's
// default-OFF, target-bound relaxation: when armed for THIS session's target, a cross-host URL is allowed
// (reason operator_armed_roam); otherwise the public first-party gate is UNCHANGED. The lab-attested
// private-target path is NOT relaxed (no 169.254 pivot from a lab session), and block_internal_hosts is a
// separate DNS-layer policy this never touches.

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  ROAM_AUTHORIZED_ENV,
  assertHttpScopeDomain,
  roamAuthorizedForTarget,
  validateHttpScanScope,
} = require("../mcp/lib/scope.js");
const {
  LAB_TARGET_ACK_TOKEN,
  LAB_TARGET_ACK_ENV,
  LAB_TARGET_HOST_ENV,
} = require("../mcp/lib/lab-target-attest.js");
const { stripCredentialHeaders } = require("../mcp/lib/safe-fetch.js");
const { isFirstPartyHost } = require("../mcp/lib/url-surface.js");

const TARGET = "vu.nl";
const CROSS_HOST_URL = "https://attacker.example.org/x"; // host outside vu.nl; registrable example.org
const FIRST_PARTY_URL = "https://www.vu.nl/en/research"; // subdomain of the target

function withRoamEnv(value, fn) {
  const prev = process.env[ROAM_AUTHORIZED_ENV];
  if (value === null) delete process.env[ROAM_AUTHORIZED_ENV];
  else process.env[ROAM_AUTHORIZED_ENV] = value;
  try {
    return fn();
  } finally {
    if (prev === undefined) delete process.env[ROAM_AUTHORIZED_ENV];
    else process.env[ROAM_AUTHORIZED_ENV] = prev;
  }
}

test("default (roam OFF): a cross-host URL is blocked", () => {
  withRoamEnv(null, () => {
    assert.throws(() => validateHttpScanScope(CROSS_HOST_URL, TARGET), /outside target_domain/);
  });
});

test("roam ARMED for this target: a cross-host URL is allowed with reason operator_armed_roam", () => {
  withRoamEnv(TARGET, () => {
    const result = validateHttpScanScope(CROSS_HOST_URL, TARGET);
    assert.equal(result.allowed, true);
    assert.equal(result.scope_decision, "allowed");
    assert.equal(result.reason, "operator_armed_roam");
    assert.equal(result.host, "attacker.example.org");
    assert.equal(result.target_domain, TARGET);
    // The roamed host is described from ITS OWN public-suffix info, so the audit shows where it went.
    assert.equal(result.registrable_domain, "example.org");
  });
});

test("roam armed for a DIFFERENT target does not relax this session", () => {
  withRoamEnv("some-other-engagement.com", () => {
    assert.throws(() => validateHttpScanScope(CROSS_HOST_URL, TARGET), /outside target_domain/);
  });
});

test("roam matches the WHOLE target (trim + case-insensitive), not a suffix", () => {
  withRoamEnv(`  ${TARGET.toUpperCase()}  `, () => {
    assert.equal(validateHttpScanScope(CROSS_HOST_URL, TARGET).reason, "operator_armed_roam");
  });
  withRoamEnv("nl", () => {
    // A public-suffix fragment of the target must NOT authorize roam.
    assert.throws(() => validateHttpScanScope(CROSS_HOST_URL, TARGET), /outside target_domain/);
  });
});

test("roam ON: a FIRST-PARTY URL still resolves via the normal first_party_host path", () => {
  withRoamEnv(TARGET, () => {
    const result = validateHttpScanScope(FIRST_PARTY_URL, TARGET);
    assert.equal(result.allowed, true);
    assert.equal(result.reason, "first_party_host"); // not operator_armed_roam — roam only fires off-apex
  });
});

test("CRITICAL: an attested LAB target is NOT roamed off even with roam armed (no 169.254 pivot)", () => {
  const prevAck = process.env[LAB_TARGET_ACK_ENV];
  const prevHost = process.env[LAB_TARGET_HOST_ENV];
  process.env[LAB_TARGET_ACK_ENV] = LAB_TARGET_ACK_TOKEN;
  process.env[LAB_TARGET_HOST_ENV] = "127.0.0.1";
  try {
    withRoamEnv("127.0.0.1", () => {
      const labOpts = { labAuthorization: { private_targets: true } };
      // Same attested host: allowed via the lab path.
      assert.equal(
        validateHttpScanScope("http://127.0.0.1/api", "127.0.0.1", labOpts).reason,
        "lab_attested_private_target",
      );
      // Cross-host (cloud metadata IP) stays BLOCKED despite roam being armed for the lab target — the lab
      // path returns/throws before the roam check, so a lab session can never pivot off the attested host.
      assert.throws(
        () => validateHttpScanScope("http://169.254.169.254/latest/meta-data/", "127.0.0.1", labOpts),
        /outside attested lab target/,
      );
    });
  } finally {
    if (prevAck === undefined) delete process.env[LAB_TARGET_ACK_ENV];
    else process.env[LAB_TARGET_ACK_ENV] = prevAck;
    if (prevHost === undefined) delete process.env[LAB_TARGET_HOST_ENV];
    else process.env[LAB_TARGET_HOST_ENV] = prevHost;
  }
});

test("CRITICAL: roam armed for a PUBLIC target does NOT reach an internal/metadata host", () => {
  // The SSRF case the browser navigate path (blockInternalHosts:false) leans ENTIRELY on this kernel to
  // block. Roam authorizes cross-host to other PUBLIC hosts only — an IP literal / internal name is not
  // public, so it falls through to the cross-host block even with roam armed for the public target.
  withRoamEnv(TARGET, () => {
    assert.throws(
      () => validateHttpScanScope("http://169.254.169.254/latest/meta-data/", TARGET),
      /outside target_domain/,
      "cloud-metadata IP must stay blocked under roam",
    );
    for (const u of [
      "http://127.0.0.1/",          // loopback
      "http://10.0.0.5/",           // RFC1918
      "http://[::1]/",              // IPv6 loopback
      "http://metadata.internal/",  // non-public name
      "http://printer.local/",      // non-public name
      "http://intranet/",           // bare host, no public suffix
    ]) {
      assert.throws(() => validateHttpScanScope(u, TARGET), undefined, `must stay blocked under roam: ${u}`);
    }
  });
});

test("roam matches an IDN target armed in its Unicode form (normalized to punycode)", () => {
  // assertHttpScopeDomain normalizes the session domain to ASCII before validateHttpScanScope sees it;
  // the arm must normalize the same way so the operator can arm with the Unicode name.
  const PUNY = "xn--85x722f.com.cn"; // 食狮.com.cn
  withRoamEnv("食狮.com.cn", () => {
    assert.equal(validateHttpScanScope(CROSS_HOST_URL, PUNY).reason, "operator_armed_roam");
  });
});

// ── P1 #2: roamed redirects must not carry the target's credentials ──────────────────────────────────

test("cross-site redirect headers: allowlist keeps only safe headers, drops ALL credential headers", () => {
  const out = stripCredentialHeaders({
    Cookie: "sid=secret",
    authorization: "Bearer a",
    AUTHORIZATION: "Bearer b",
    "Proxy-Authorization": "Basic z",
    "X-Api-Key": "k", // custom auth header — must NOT slip through a Cookie/Authorization-only denylist
    "X-Auth-Token": "t",
    "User-Agent": "bob",
    Accept: "application/json",
  });
  // dropped: every credential-bearing header, including custom + proxy
  assert.equal(out.Cookie, undefined);
  assert.equal(out.authorization, undefined);
  assert.equal(out.AUTHORIZATION, undefined);
  assert.equal(out["Proxy-Authorization"], undefined);
  assert.equal(out["X-Api-Key"], undefined);
  assert.equal(out["X-Auth-Token"], undefined);
  // kept: only the safe, non-credential allowlist
  assert.equal(out["User-Agent"], "bob");
  assert.equal(out.Accept, "application/json");
});

test("stripCredentialHeaders is null/empty safe", () => {
  assert.equal(stripCredentialHeaders(null), null);
  assert.equal(stripCredentialHeaders(undefined), undefined);
  assert.deepEqual(stripCredentialHeaders({}), {});
});

test("redirect cred-strip decision: a roamed cross-site host is not first-party (strip), a first-party subdomain is (keep)", () => {
  // safeFetch strips credentials on a redirect whose host is NOT first-party to targetDomain — so a 302
  // from the target to a roamed host never replays the target's Cookie/Authorization, while a first-party
  // subdomain redirect keeps them. This is the predicate that gates the strip.
  assert.equal(isFirstPartyHost("evil.example.org", "vu.nl"), false); // roamed → strip
  assert.equal(isFirstPartyHost("api.vu.nl", "vu.nl"), true);         // first-party subdomain → keep
  assert.equal(isFirstPartyHost("vu.nl", "vu.nl"), true);            // same host → keep
});

test("CRITICAL: roam's public-host check is lab-BLIND — an attested internal host is rejected", () => {
  // Round-2 CRITICAL: assertHttpScopeDomain(host) honors a lab attestation, so without ignoreLabAttestation
  // a concurrent BOB_LAB_TARGET would reclassify an internal host as roamable → LAN/loopback SSRF.
  const prevAck = process.env[LAB_TARGET_ACK_ENV];
  const prevHost = process.env[LAB_TARGET_HOST_ENV];
  process.env[LAB_TARGET_ACK_ENV] = LAB_TARGET_ACK_TOKEN;
  process.env[LAB_TARGET_HOST_ENV] = "192.168.1.53";
  try {
    // With the attestation, the internal host IS accepted by the normal check...
    assert.equal(
      assertHttpScopeDomain("192.168.1.53", { labAuthorization: { private_targets: true } }),
      "192.168.1.53",
    );
    // ...but the lab-BLIND form the roam gate uses rejects it regardless of the attestation.
    assert.throws(
      () => assertHttpScopeDomain("192.168.1.53", { ignoreLabAttestation: true }),
      /not a public DNS domain/,
    );
  } finally {
    if (prevAck === undefined) delete process.env[LAB_TARGET_ACK_ENV];
    else process.env[LAB_TARGET_ACK_ENV] = prevAck;
    if (prevHost === undefined) delete process.env[LAB_TARGET_HOST_ENV];
    else process.env[LAB_TARGET_HOST_ENV] = prevHost;
  }
});

test("the roam decision carries enforce_internal_block (fetch/driver then resolves + blocks internal IPs)", () => {
  withRoamEnv(TARGET, () => {
    const result = validateHttpScanScope(CROSS_HOST_URL, TARGET);
    assert.equal(result.reason, "operator_armed_roam");
    assert.equal(result.enforce_internal_block, true);
  });
});

test("roamAuthorizedForTarget unit: empty/whitespace/mismatch false; exact (trim/case) true", () => {
  withRoamEnv(null, () => assert.equal(roamAuthorizedForTarget(TARGET), false));
  withRoamEnv("   ", () => assert.equal(roamAuthorizedForTarget(TARGET), false));
  withRoamEnv("other.com", () => assert.equal(roamAuthorizedForTarget(TARGET), false));
  withRoamEnv(TARGET, () => assert.equal(roamAuthorizedForTarget(TARGET), true));
  withRoamEnv(`  ${TARGET.toUpperCase()} `, () => assert.equal(roamAuthorizedForTarget(TARGET), true));
  withRoamEnv(TARGET, () => assert.equal(roamAuthorizedForTarget(""), false)); // empty target never roams
});
