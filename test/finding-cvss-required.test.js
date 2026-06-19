"use strict";

// cvss_inputs is required and must be sufficient to derive a CVSS v3.1 base
// vector on the fresh write path for reportable findings (severity
// critical/high/medium), optional for low/info, and tolerant on legacy read-back
// projection (a persisted medium+ row missing cvss_inputs still projects — it
// renders the insufficient-verified-facts marker on the report, never throws).
// The gate runs AFTER the OSS reachability attack_vector fallback, so an OSS
// finding that asserts reachability + privileges + impact but no explicit
// attack_vector still passes. This mirrors the CWE gate: strict on the handler
// write path, tolerant in the normalizer read path.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const recordCandidateClaimTool = require("../mcp/lib/tools/record-candidate-claim.js");
const {
  findingPayloadsFromClaims,
} = require("../mcp/lib/tools/record-candidate-claim.js");
const {
  readCandidateClaims,
} = require("../mcp/lib/claims.js");
const {
  claimsJsonlPath,
} = require("../mcp/lib/paths.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");
const {
  buildRepoInventory,
  initRepoSession,
} = require("../mcp/lib/repo-target.js");
const {
  routeSurfaces,
} = require("../mcp/lib/surface-router.js");
const {
  advanceSession,
} = require("../mcp/lib/session-state.js");
const {
  startWave,
} = require("../mcp/lib/waves.js");
const {
  materializeFrontier,
} = require("../mcp/lib/frontier-materializer.js");
const {
  currentSurfaces,
} = require("../mcp/lib/frontier-projections.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cvss-required-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    resetMaterializationDebounce();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function parseResult(value) {
  return typeof value === "string" ? JSON.parse(value) : value;
}

// A reportable web IDOR with derivable cvss_inputs: cross-tenant record
// disclosure (network, low-privilege attacker tenant, confidentiality).
function baseFinding(domain, overrides = {}) {
  return {
    target_domain: domain,
    title: "IDOR exposes another tenant record",
    severity: "medium",
    cwe: "CWE-639",
    endpoint: `https://${domain}/api/records/1`,
    description: "Changing the record identifier returns another tenant payload.",
    proof_of_concept: "GET /api/records/1 as the attacker tenant returns private fields.",
    response_evidence: "Response leaked another tenant identifier and email.",
    impact: "Cross-tenant record disclosure.",
    validated: true,
    auth_profile: "attacker",
    surface_id: "surface:record-1",
    cvss_inputs: {
      attack_vector: "network",
      privileges_required: "low",
      confidentiality: "high",
      integrity: "none",
      availability: "none",
    },
    ...overrides,
  };
}

test("write path requires derivable cvss_inputs for medium/high/critical findings", () => {
  for (const severity of ["medium", "high", "critical"]) {
    withTempHome(() => {
      const domain = `cvss-required-${severity}.example.com`;
      assert.throws(
        () => recordCandidateClaimTool.handler(baseFinding(domain, { severity, cvss_inputs: undefined })),
        (err) => {
          assert.match(err.message, /cvss_inputs is required/i);
          assert.match(err.message, /CVSS v3\.1 base vector/);
          // The remediation names the missing base metrics.
          assert.match(err.message, /attack_vector/);
          assert.match(err.message, /privileges_required/);
          assert.match(err.message, /confidentiality\/integrity\/availability/);
          return true;
        },
        `${severity} without cvss_inputs must be rejected`,
      );
    });
  }
});

test("write path rejects partial cvss_inputs that cannot derive a vector and names the gap", () => {
  withTempHome(() => {
    const domain = "cvss-partial.example.com";
    // Has an attack_vector + impact but no privileges_required: still insufficient.
    assert.throws(
      () => recordCandidateClaimTool.handler(baseFinding(domain, {
        cvss_inputs: { attack_vector: "network", confidentiality: "high" },
      })),
      (err) => {
        assert.match(err.message, /cvss_inputs is required/i);
        assert.match(err.message, /privileges_required/);
        // attack_vector and the impact triad were supplied, so they are not listed.
        assert.doesNotMatch(err.message, /\(attack_vector,/);
        return true;
      },
    );
  });
});

test("write path rejects all-none impact cvss_inputs for medium+ (derives base score 0.0)", () => {
  // Regression: confidentiality/integrity/availability all "none" derives a
  // CVSS v3.1 base score of 0.0 / band "none" — which is derivable (not
  // insufficient) but cannot back a medium+ severity claim. The gate must reject
  // it rather than letting a "none"-banded score satisfy a high finding.
  withTempHome(() => {
    const domain = "cvss-all-none.example.com";
    assert.throws(
      () => recordCandidateClaimTool.handler(baseFinding(domain, {
        severity: "high",
        cvss_inputs: {
          attack_vector: "network",
          privileges_required: "none",
          confidentiality: "none",
          integrity: "none",
          availability: "none",
        },
      })),
      (err) => {
        assert.match(err.message, /must describe real impact/i);
        assert.match(err.message, /base score of 0\.0/);
        return true;
      },
      "all-none impact must be rejected for a high finding",
    );
  });
});

test("gate guidance does NOT point web findings at reachability_assertion", () => {
  // Regression: reachability_assertion is rejected outside the oss_native_code
  // pack, so the gate must not tell a web evaluator to supply it. baseFinding is
  // a web IDOR (no oss_native_code pack), so its insufficiency message must omit
  // the reachability hint.
  withTempHome(() => {
    const domain = "cvss-web-hint.example.com";
    assert.throws(
      () => recordCandidateClaimTool.handler(baseFinding(domain, { cvss_inputs: undefined })),
      (err) => {
        assert.match(err.message, /cvss_inputs is required/i);
        assert.doesNotMatch(err.message, /reachability_assertion/);
        return true;
      },
      "web findings must not be told to use reachability_assertion",
    );
  });
});

test("write path allows absent cvss_inputs for low and info findings", () => {
  for (const severity of ["low", "info"]) {
    withTempHome(() => {
      const domain = `cvss-optional-${severity}.example.com`;
      const response = JSON.parse(
        recordCandidateClaimTool.handler(baseFinding(domain, { severity, cvss_inputs: undefined })),
      );
      assert.equal(response.recorded, true, `${severity} without cvss_inputs must be accepted`);

      const findings = findingPayloadsFromClaims(domain);
      assert.equal(findings.length, 1);
      assert.equal(findings[0].cvss_inputs, undefined, `${severity} finding has no cvss_inputs`);
    });
  }
});

test("write path accepts a reportable finding once derivable cvss_inputs are supplied", () => {
  withTempHome(() => {
    const domain = "cvss-supplied.example.com";
    const response = JSON.parse(recordCandidateClaimTool.handler(baseFinding(domain)));
    assert.equal(response.recorded, true);

    const findings = findingPayloadsFromClaims(domain);
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

test("write path accepts an OSS finding whose attack_vector is filled by the reachability fallback", () => {
  withTempHome((home) => {
    const targetDomain = "cvss-oss-reachability";
    const repo = path.join(home, targetDomain);
    fs.mkdirSync(repo, { recursive: true });
    fs.writeFileSync(path.join(repo, "CMakeLists.txt"), "cmake_minimum_required(VERSION 3.22)\nproject(native_proof C)\n");
    fs.mkdirSync(path.join(repo, "src"), { recursive: true });
    fs.writeFileSync(path.join(repo, "src", "parser.c"), "int parse_packet(const char *buf, int len) { return len > 0 ? buf[0] : 0; }\n");

    const init = parseResult(initRepoSession({ repo_path: repo, target_domain: targetDomain }));
    parseResult(buildRepoInventory({ target_domain: init.target_domain }));
    parseResult(routeSurfaces({ target_domain: init.target_domain }));
    materializeFrontier(init.target_domain, { write: true });
    const nativeSurface = currentSurfaces(init.target_domain).surfaces.find((s) => s.title === "src/parser.c");
    assert.ok(nativeSurface, "expected src/parser.c surface");
    parseResult(advanceSession({ target_domain: init.target_domain, to_state: "OPEN_FRONTIER" }));
    const wave = parseResult(startWave({
      target_domain: init.target_domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: nativeSurface.id, task_lens: "code_surface_scout" }],
    }));
    const assignment = wave.assignments.find((item) => item.surface_id === nativeSurface.id);
    assert.equal(assignment.capability_pack, "oss_native_code");

    // No explicit cvss_inputs.attack_vector, but a network reachability assertion
    // plus privileges + impact. The fallback fills AV:N, so the gate passes.
    // Medium severity keeps the high/critical native-proof gate out of the way.
    const response = JSON.parse(recordCandidateClaimTool.handler({
      target_domain: init.target_domain,
      wave: `w${wave.wave_number}`,
      agent: "a1",
      surface_id: nativeSurface.id,
      title: "Out-of-bounds read in packet parser",
      severity: "medium",
      cwe: "CWE-125",
      endpoint: "src/parser.c",
      file_path: "src/parser.c",
      symbol: "parse_packet",
      description: "The packet parser reads attacker-controlled bytes past the buffer.",
      proof_of_concept: "Run the ASAN harness against the crafted packet.",
      response_evidence: "AddressSanitizer: heap-buffer-overflow in parse_packet",
      impact: "Remote input can crash the process and disclose adjacent memory.",
      validated: true,
      reachability_assertion: {
        attack_vector: "network",
        network_reachable: true,
        call_path: "UDP-161 packet -> serve -> parse_packet",
      },
      cvss_inputs: { privileges_required: "none", confidentiality: "low", availability: "high" },
    }));
    assert.equal(response.recorded, true, "OSS reachability fallback must satisfy the gate");

    const findings = findingPayloadsFromClaims(init.target_domain);
    const oob = findings.find((f) => f.id === response.finding_id);
    assert.equal(oob.cvss_inputs.attack_vector, "network", "attack_vector derived from reachability");
    assert.equal(oob.cvss_inputs.privileges_required, "none");
  });
});

test("legacy read-back projects a medium+ claim row lacking cvss_inputs without throwing", () => {
  withTempHome(() => {
    const domain = "cvss-legacy.example.com";
    // Record with derivable inputs to clear the write gate, then strip the
    // persisted cvss_inputs to simulate a legacy row lacking cvss_inputs.
    // Read-back is tolerant: the projection still surfaces the finding (the
    // report renders the insufficient-verified-facts marker for it).
    const response = JSON.parse(recordCandidateClaimTool.handler(baseFinding(domain)));
    assert.equal(response.recorded, true);

    const file = claimsJsonlPath(domain);
    const lines = fs.readFileSync(file, "utf8").split("\n").filter((l) => l.trim());
    assert.equal(lines.length, 1);
    const claim = JSON.parse(lines[0]);
    delete claim.payload.finding.cvss_inputs;
    fs.writeFileSync(file, `${JSON.stringify(claim)}\n`);

    // Sanity: the row truly lacks cvss_inputs now.
    const reread = readCandidateClaims(domain);
    assert.equal(reread.length, 1);
    assert.equal(reread[0].payload.finding.cvss_inputs, undefined);

    const findings = findingPayloadsFromClaims(domain);
    assert.equal(findings.length, 1, "legacy cvss_inputs-less row must still project");
    assert.equal(findings[0].cvss_inputs, undefined, "projection leaves cvss_inputs absent");
    assert.equal(findings[0].severity, "medium");
  });
});
