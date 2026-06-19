"use strict";

// Step 3 — Finding-EVIDENCE vs secret-LEAK separation.
//
// A candidate claim whose proof_of_concept legitimately contains secret-shaped
// evidence (a CORS Authorization:/cookie reflection that IS the finding) must be
// recordable WITH an operator-approved secret_detection_bypass, persist that
// bypass on the claim, and re-honor it on every subsequent read so the
// CLAIM_FREEZE -> VERIFY snapshot bootstrap no longer re-throws and strands the
// session in INTERNAL_ERROR. The structural sensitive-KEY check and the
// length cap still fire everywhere; only the operator-approved value-paths skip
// the value-pattern scan. A claim with the same PoC and NO bypass must still
// throw (negative control), and a persisted row whose bypass rationale is
// missing must NOT suppress the read-time scan.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const recordCandidateClaimTool = require("../mcp/lib/tools/record-candidate-claim.js");
const {
  appendCandidateClaim,
  readCandidateClaims,
} = require("../mcp/lib/claims.js");
const {
  buildClaimFreeze,
} = require("../mcp/lib/claim-freeze.js");
const {
  advanceSession,
  initSession,
} = require("../mcp/lib/session-state.js");
const {
  readSessionNucleus,
} = require("../mcp/lib/governance-store.js");
const {
  claimsJsonlPath,
} = require("../mcp/lib/paths.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-secret-bypass-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    resetMaterializationDebounce();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

// A proof-of-concept body that trips SENSITIVE_VALUE_RE: the reflected
// Authorization: Bearer header is the CORS finding's evidence.
const SECRET_SHAPED_POC =
  "Cross-origin response reflects the victim session: Authorization: Bearer abc123def456ghi789 "
  + "and cookie: sid=ABC123DEF456 are echoed to attacker-origin.example.";

function findingInput(domain, overrides = {}) {
  return {
    target_domain: domain,
    title: "Credentialed CORS reflects victim auth header",
    severity: "medium",
    cwe: "CWE-200",
    endpoint: `https://${domain}/api/account`,
    description: "Permissive CORS reflects the request Origin with credentials, exposing the victim's auth header.",
    proof_of_concept: SECRET_SHAPED_POC,
    impact: "An attacker page reads the victim's authenticated response cross-origin.",
    validated: true,
    // CORS credentialed read: network-reachable, no privileges, confidentiality.
    cvss_inputs: {
      attack_vector: "network",
      privileges_required: "none",
      confidentiality: "high",
    },
    ...overrides,
  };
}

function advanceTo(domain, toState) {
  return JSON.parse(advanceSession({ target_domain: domain, to_state: toState }));
}

test("a secret-shaped PoC records, reads, freezes, and advances to VERIFY when an approved bypass is supplied", () => {
  withTempHome(() => {
    const domain = "cors-bypass.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}/` });

    const response = JSON.parse(recordCandidateClaimTool.handler(findingInput(domain, {
      secret_detection_bypass: [{
        field: "proof_of_concept",
        rationale: "The reflected Authorization/cookie IS the CORS finding evidence; it is the victim's own header, not a persisted credential.",
      }],
    })));
    assert.equal(response.recorded, true, "claim with an approved bypass must be recorded");

    // The bypass is persisted on the claim payload so reads can re-honor it.
    const raw = fs.readFileSync(claimsJsonlPath(domain), "utf8").trim().split(/\r?\n/);
    assert.equal(raw.length, 1, "exactly one claim row written");
    const persisted = JSON.parse(raw[0]);
    assert.ok(Array.isArray(persisted.payload.secret_evidence_bypass), "claim payload must carry secret_evidence_bypass[]");
    const bypassRow = persisted.payload.secret_evidence_bypass.find((r) => r.path === "payload.finding.proof_of_concept");
    assert.ok(bypassRow, "persisted bypass must name the proof_of_concept value-path");
    assert.equal(bypassRow.field, "proof_of_concept");
    assert.ok(typeof bypassRow.rationale === "string" && bypassRow.rationale.length > 0, "persisted bypass row must keep the rationale");

    // readCandidateClaims must NOT throw — the persisted bypass is re-honored.
    const claims = readCandidateClaims(domain);
    assert.equal(claims.length, 1, "readCandidateClaims returns the secret-shaped claim without throwing");
    assert.match(claims[0].payload.finding.proof_of_concept, /Authorization: Bearer/);
    // The re-normalized read-back row must be byte-identical to the persisted
    // one (stable claim_hash recompute across write -> read).
    assert.equal(claims[0].claim_hash, persisted.claim_hash, "claim_hash must be stable across write/read");
    assert.deepEqual(claims[0].payload.secret_evidence_bypass, persisted.payload.secret_evidence_bypass);

    // buildClaimFreeze({write:true}) yields a freeze id (it re-reads claims).
    const freeze = buildClaimFreeze(domain, { write: true });
    assert.equal(typeof freeze.freeze_id, "string");
    assert.ok(freeze.freeze_id.length > 0, "freeze id must be non-empty");

    // advanceSession -> VERIFY completes; nucleus lands on VERIFY (not INTERNAL_ERROR).
    advanceTo(domain, "OPEN_FRONTIER");
    advanceTo(domain, "CLAIM_FREEZE");
    const verify = advanceTo(domain, "VERIFY");
    assert.equal(verify.advanced, true);
    assert.equal(verify.to_state, "VERIFY");
    assert.equal(readSessionNucleus(domain).lifecycle_state, "VERIFY");
  });
});

test("NEGATIVE CONTROL: the same secret-shaped PoC with NO bypass still throws at record time", () => {
  withTempHome(() => {
    const domain = "cors-nobypass.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}/` });

    assert.throws(
      () => recordCandidateClaimTool.handler(findingInput(domain)),
      /appears to contain secrets, auth headers, cookies, or tokens/,
      "recording a secret-shaped PoC without a bypass must still throw",
    );
  });
});

test("a bypass RATIONALE that smuggles a raw secret is redacted before it is persisted", () => {
  withTempHome(() => {
    const domain = "cors-rationale-secret.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}/` });

    // The bypass legitimately clears the secret-shaped PoC value-path, but the
    // rationale free-text itself carries the raw token. The rationale is
    // persisted into claims.jsonl and is NOT covered by the finding value-paths,
    // so it must be scrubbed independently — otherwise the bypass metadata
    // becomes a covert channel for secrets into the persistent ledger. The claim
    // still records (redaction, not rejection), but the raw token never lands.
    // A token that appears ONLY in the rationale (distinct from the PoC's own
    // bypassed secret-shaped evidence), so we can prove the rationale-borne
    // value is scrubbed everywhere it could land.
    const rationaleToken = "rationaleOnlyTok123ABC456def";
    const response = JSON.parse(recordCandidateClaimTool.handler(findingInput(domain, {
      secret_detection_bypass: [{
        field: "proof_of_concept",
        rationale: `The evidence is the reflected header Authorization: Bearer ${rationaleToken} captured from the victim.`,
      }],
    })));
    assert.equal(response.recorded, true, "the claim still records — the rationale is redacted, not rejected");

    // The persisted rationale must NOT contain the rationale-borne token; it was
    // redacted, while the descriptive prose around it survives.
    const persisted = JSON.parse(fs.readFileSync(claimsJsonlPath(domain), "utf8").trim());
    const bypassRow = persisted.payload.secret_evidence_bypass.find((r) => r.field === "proof_of_concept");
    assert.ok(bypassRow, "the bypass row must persist");
    assert.match(bypassRow.rationale, /REDACTED/, "the redaction marker must replace the secret value");
    // The rationale-borne token must not survive anywhere in claims.jsonl (the
    // PoC's own bypassed token is a separate, legitimately-recorded value).
    assert.doesNotMatch(
      fs.readFileSync(claimsJsonlPath(domain), "utf8"),
      new RegExp(rationaleToken),
      "the rationale-borne token must be scrubbed from the persistent ledger",
    );
  });
});

test("a descriptive (secret-free) bypass rationale still records", () => {
  withTempHome(() => {
    const domain = "cors-rationale-clean.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}/` });

    // Positive control: the rationale DESCRIBES the secret-shaped evidence
    // without embedding a raw token, so the new rationale value-scan passes and
    // the claim records normally.
    const response = JSON.parse(recordCandidateClaimTool.handler(findingInput(domain, {
      secret_detection_bypass: [{
        field: "proof_of_concept",
        rationale: "The reflected authorization header is the CORS finding evidence; it is the victim's own request header, not a persisted credential.",
      }],
    })));
    assert.equal(response.recorded, true, "a secret-free rationale must still record");
  });
});

test("the read-time value-scan still fires when a persisted row lacks a backing rationale", () => {
  withTempHome(() => {
    const domain = "cors-stripped.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}/` });

    // Persist a claim whose embedded PoC trips the value scan, write-validated
    // via the explicit bypass option, but with NO persisted secret_evidence_bypass
    // rows (simulating an older/hand-stripped row). The read-time scan has no
    // honorable path to skip, so it must re-throw.
    const claimInput = {
      target_domain: domain,
      title: "Stripped-bypass claim",
      summary: "Reflects the victim auth header cross-origin.",
      severity: "medium",
      status: "candidate",
      payload: {
        finding: {
          id: "F-1",
          proof_of_concept: SECRET_SHAPED_POC,
        },
      },
    };
    appendCandidateClaim(claimInput, {
      payloadBypassValuePaths: new Set(["payload.finding.proof_of_concept"]),
    });

    assert.throws(
      () => readCandidateClaims(domain),
      /appears to contain secrets, auth headers, cookies, or tokens/,
      "readCandidateClaims must re-throw when no persisted bypass row backs the path",
    );
  });
});

// Persist a claim whose embedded PoC trips the value scan but carries NO
// honorable bypass (simulating a pre-Step-3 / stripped row), then drive to
// CLAIM_FREEZE so the next VERIFY transition runs the snapshot bootstrap.
function seedTrippingClaimAtClaimFreeze(domain) {
  initSession({ target_domain: domain, target_url: `https://${domain}/` });
  appendCandidateClaim({
    target_domain: domain,
    title: "Legacy secret-shaped claim",
    summary: "Reflects the victim auth header cross-origin.",
    severity: "medium",
    status: "candidate",
    payload: { finding: { id: "F-1", proof_of_concept: SECRET_SHAPED_POC } },
  }, { payloadBypassValuePaths: new Set(["payload.finding.proof_of_concept"]) });
  advanceTo(domain, "OPEN_FRONTIER");
  advanceTo(domain, "CLAIM_FREEZE");
}

test("CLAIM_FREEZE -> VERIFY fails closed as a classified STATE_CONFLICT (not INTERNAL_ERROR) when a persisted claim trips the scan", () => {
  withTempHome(() => {
    const domain = "verify-block.example.com";
    seedTrippingClaimAtClaimFreeze(domain);

    let captured = null;
    try {
      advanceTo(domain, "VERIFY");
    } catch (error) {
      captured = error;
    }
    assert.ok(captured, "VERIFY must be blocked when a persisted claim trips the scan");
    assert.equal(captured.code, "STATE_CONFLICT", `expected STATE_CONFLICT, got ${captured.code}`);
    assert.equal(captured.details && captured.details.block_code, "claim_evidence_secret_blocked");
  });
});

test("operator_force proceeds past the secret-blocked VERIFY transition", () => {
  withTempHome(() => {
    const domain = "verify-force.example.com";
    seedTrippingClaimAtClaimFreeze(domain);

    const forced = JSON.parse(advanceSession({
      target_domain: domain,
      to_state: "VERIFY",
      override: "operator_force",
      override_reason: "operator forced VERIFY past a pre-validated secret-shaped claim",
    }));
    assert.equal(forced.advanced, true);
    assert.equal(forced.to_state, "VERIFY");
    assert.equal(readSessionNucleus(domain).lifecycle_state, "VERIFY");
  });
});

test("the structural sensitive-KEY check is NOT bypassable by a value-path bypass", () => {
  withTempHome(() => {
    const domain = "key-scan.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}/` });

    // A sensitive KEY name (authorization) anywhere in the payload must throw at
    // write even with a (value-path) bypass present — the bypass only skips the
    // value regex, never the structural key check.
    const claimInput = {
      target_domain: domain,
      title: "Sensitive-key claim",
      summary: "Carries a forbidden key name.",
      severity: "medium",
      status: "candidate",
      payload: {
        secret_evidence_bypass: [{
          field: "proof_of_concept",
          rationale: "value-path bypass present",
          path: "payload.finding.proof_of_concept",
        }],
        finding: {
          id: "F-1",
          // A literal sensitive KEY name — structural SENSITIVE_KEY_RE fires
          // regardless of any value-path bypass.
          authorization: "anything",
        },
      },
    };
    assert.throws(
      () => appendCandidateClaim(claimInput),
      /appears to contain secrets, auth headers, cookies, or tokens/,
      "a forbidden key name must still throw even with a value-path bypass persisted",
    );
  });
});
