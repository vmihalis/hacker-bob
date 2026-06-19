"use strict";

// Structured CVSS v3.1 inputs on the candidate claim.
// Asserts:
//   * cvss_inputs survives the claim write -> findingPayloadsFromClaims read-back
//   * unknown cvss_inputs values / keys are rejected server-side
//   * cvss_inputs does NOT enter the finding dedupe_key (adding/refining it
//     leaves the dedupe key — and therefore finding-id minting — unchanged)
//   * the OSS reachability-assertion attack_vector fallback fills cvss_inputs
//     when no explicit attack_vector is supplied, without overriding one that is

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const recordClaimTool = require("../mcp/lib/tools/record-candidate-claim.js");
const {
  computeFindingDedupeKey,
  normalizeFindingRecord,
} = require("../mcp/lib/finding-contracts.js");
const { normalizeCvssInputs } = require("../mcp/lib/cvss31.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cvss-claim-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

const BASE_CLAIM = Object.freeze({
  title: "IDOR in /api/orders",
  severity: "high",
  cwe: "CWE-639",
  endpoint: "https://audit.example.com/api/orders/1",
  description: "An attacker can read other users' orders.",
  proof_of_concept: "curl https://audit.example.com/api/orders/2",
  validated: true,
});

test("cvss_inputs survives the claim write and read-back projection", () => {
  withTempHome(() => {
    const domain = "audit.example.com";
    recordClaimTool.handler({
      target_domain: domain,
      ...BASE_CLAIM,
      cvss_inputs: {
        attack_vector: "network",
        privileges_required: "low",
        confidentiality: "high",
        integrity: "none",
        availability: "none",
      },
    });
    const findings = recordClaimTool.findingPayloadsFromClaims(domain);
    assert.equal(findings.length, 1);
    assert.deepEqual(findings[0].cvss_inputs, {
      attack_vector: "network",
      privileges_required: "low",
      confidentiality: "high",
      integrity: "none",
      availability: "none",
    });
  });
});

test("unknown cvss_inputs values are rejected server-side", () => {
  withTempHome(() => {
    const domain = "audit.example.com";
    let err;
    try {
      recordClaimTool.handler({
        target_domain: domain,
        ...BASE_CLAIM,
        cvss_inputs: { attack_vector: "satellite", privileges_required: "low", confidentiality: "high" },
      });
    } catch (e) { err = e; }
    assert.ok(err, "bad enum value must throw");
    assert.match(err.message, /attack_vector/);
    assert.match(err.message, /not a valid value/);
  });
});

test("unknown cvss_inputs keys are rejected server-side", () => {
  withTempHome(() => {
    const domain = "audit.example.com";
    let err;
    try {
      recordClaimTool.handler({
        target_domain: domain,
        ...BASE_CLAIM,
        cvss_inputs: { bogus_metric: "x", attack_vector: "network", privileges_required: "low", confidentiality: "high" },
      });
    } catch (e) { err = e; }
    assert.ok(err, "unknown key must throw");
    assert.match(err.message, /bogus_metric/);
    assert.match(err.message, /not a recognized CVSS v3\.1 metric/);
  });
});

test("cvss_inputs does NOT enter the finding dedupe_key", () => {
  const withoutInputs = computeFindingDedupeKey({ ...BASE_CLAIM, target_domain: "audit.example.com" });
  const withInputs = computeFindingDedupeKey({
    ...BASE_CLAIM,
    target_domain: "audit.example.com",
    cvss_inputs: { attack_vector: "network", privileges_required: "low", confidentiality: "high" },
  });
  assert.equal(withInputs, withoutInputs);

  // And end-to-end: a second record whose cvss_inputs are REFINED relative to the
  // first is still detected as the same finding (dedupe hit), proving the key did
  // not shift when the CVSS inputs changed. Both records carry derivable inputs
  // because the write path requires them for a reportable (high) finding.
  withTempHome(() => {
    const domain = "audit.example.com";
    const first = JSON.parse(recordClaimTool.handler({
      target_domain: domain,
      ...BASE_CLAIM,
      cvss_inputs: { attack_vector: "network", privileges_required: "low", confidentiality: "high" },
    }));
    assert.equal(first.recorded, true);
    const second = JSON.parse(recordClaimTool.handler({
      target_domain: domain,
      ...BASE_CLAIM,
      cvss_inputs: { attack_vector: "network", privileges_required: "low", confidentiality: "high", integrity: "low" },
    }));
    assert.equal(second.duplicate, true);
    assert.equal(second.dedupe_key, first.dedupe_key);
  });
});

test("OSS reachability assertion fills cvss_inputs.attack_vector when none is supplied", () => {
  const networkFinding = normalizeFindingRecord({
    id: "F-1",
    target_domain: "repo.example.com",
    title: "OOB write in parser",
    severity: "high",
    cwe: "CWE-787",
    endpoint: "src/parse.c",
    description: "Heap out-of-bounds write.",
    proof_of_concept: "afl crash",
    validated: true,
    capability_pack: "oss_native_code",
    evaluator_agent: "evaluator-agent",
    brief_profile: "oss",
    reachability_assertion: {
      attack_vector: "network",
      network_reachable: true,
      call_path: "UDP-161 SNMP SET -> write_status -> parse_oid",
    },
    cvss_inputs: { privileges_required: "none", confidentiality: "high", integrity: "high", availability: "high" },
  }, { expectedDomain: "repo.example.com", requireCwe: true });
  assert.equal(networkFinding.cvss_inputs.attack_vector, "network");

  // A CONFLICTING explicit attack_vector is REJECTED. reachability_assertion is
  // authoritative for AV, so a finding cannot assert network-reachable while
  // claiming a "local" CVSS attack vector. (Previously the explicit value was
  // silently kept, persisting a self-contradictory finding.)
  assert.throws(
    () => normalizeFindingRecord({
      id: "F-2",
      target_domain: "repo.example.com",
      title: "OOB write in parser",
      severity: "high",
      cwe: "CWE-787",
      endpoint: "src/parse.c",
      description: "Heap out-of-bounds write.",
      proof_of_concept: "afl crash",
      validated: true,
      capability_pack: "oss_native_code",
      evaluator_agent: "evaluator-agent",
      brief_profile: "oss",
      reachability_assertion: {
        attack_vector: "network",
        network_reachable: true,
        call_path: "UDP-161 SNMP SET -> write_status -> parse_oid",
      },
      cvss_inputs: { attack_vector: "local", privileges_required: "none", confidentiality: "high" },
    }, { expectedDomain: "repo.example.com", requireCwe: true }),
    /conflicts with reachability_assertion/,
  );

  // An explicit attack_vector that AGREES with the assertion is accepted.
  const agreeingFinding = normalizeFindingRecord({
    id: "F-3",
    target_domain: "repo.example.com",
    title: "OOB write in parser",
    severity: "high",
    cwe: "CWE-787",
    endpoint: "src/parse.c",
    description: "Heap out-of-bounds write.",
    proof_of_concept: "afl crash",
    validated: true,
    capability_pack: "oss_native_code",
    evaluator_agent: "evaluator-agent",
    brief_profile: "oss",
    reachability_assertion: {
      attack_vector: "network",
      network_reachable: true,
      call_path: "UDP-161 SNMP SET -> write_status -> parse_oid",
    },
    cvss_inputs: { attack_vector: "network", privileges_required: "none", confidentiality: "high" },
  }, { expectedDomain: "repo.example.com", requireCwe: true });
  assert.equal(agreeingFinding.cvss_inputs.attack_vector, "network");
});

test("normalizeCvssInputs canonicalizes single-letter aliases and drops empty", () => {
  assert.deepEqual(
    normalizeCvssInputs({ attack_vector: "N", privileges_required: "L", confidentiality: "H" }),
    { attack_vector: "network", privileges_required: "low", confidentiality: "high" },
  );
  assert.equal(normalizeCvssInputs(null), null);
  assert.equal(normalizeCvssInputs({}), null);
});
