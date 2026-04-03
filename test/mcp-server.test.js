const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  findingsJsonlPath,
  findingsMarkdownPath,
  gradeArtifactPaths,
  listFindings,
  mergeWaveHandoffs,
  readFindings,
  readGradeVerdict,
  readVerificationRound,
  recordFinding,
  sessionDir,
  verificationRoundPaths,
  waveHandoffStatus,
  waveStatus,
  writeFileAtomic,
  writeGradeVerdict,
  writeHandoff,
  writeVerificationRound,
  writeWaveHandoff,
} = require("../mcp/server.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bountyagent-test-"));
  process.env.HOME = tempHome;

  try {
    fn(tempHome);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
}

function seedFinding(domain, overrides = {}) {
  return JSON.parse(recordFinding({
    target_domain: domain,
    title: "IDOR on account export",
    severity: "high",
    cwe: "CWE-639",
    endpoint: "/api/export",
    description: "Authenticated user can export another account's data by changing account_id.",
    proof_of_concept: "curl https://example.com/api/export?account_id=2",
    response_evidence: "{\"account_id\":2}",
    impact: "Cross-account PII disclosure.",
    validated: true,
    wave: "w1",
    agent: "a1",
    ...overrides,
  }));
}

test("bounty_write_handoff still writes SESSION_HANDOFF.md without wave fields", () => {
  withTempHome(() => {
    const domain = "example.com";
    const result = JSON.parse(writeHandoff({
      target_domain: domain,
      session_number: 7,
      target_url: "https://example.com",
      explored_with_results: ["surface-a"],
      must_do_next: [{ priority: "P1", description: "Keep testing surface-a" }],
    }));

    const handoffPath = path.join(sessionDir(domain), "SESSION_HANDOFF.md");
    assert.equal(result.written, handoffPath);
    assert.ok(fs.existsSync(handoffPath));

    const content = fs.readFileSync(handoffPath, "utf8");
    assert.match(content, /# Handoff — Session 7/);
    assert.match(content, /## Explored/);
    assert.doesNotMatch(content, /handoff-w7-a1/);
  });
});

test("bounty_write_wave_handoff writes matching markdown and json with normalized defaults", () => {
  withTempHome(() => {
    const domain = "example.com";
    const content = "# Handoff\n\nFreeform markdown.";
    const result = JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      content,
    }));

    assert.ok(fs.existsSync(result.written_md));
    assert.ok(fs.existsSync(result.written_json));
    assert.equal(fs.readFileSync(result.written_md, "utf8"), content);

    const payload = JSON.parse(fs.readFileSync(result.written_json, "utf8"));
    assert.deepEqual(payload, {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      dead_ends: [],
      waf_blocked_endpoints: [],
      lead_surface_ids: [],
    });
  });
});

test("bounty_wave_handoff_status reports complete when all assigned handoffs exist", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });

    writeFileAtomic(path.join(dir, "wave-1-assignments.json"), `${JSON.stringify({
      wave_number: 1,
      assignments: [
        { agent: "a1", surface_id: "surface-a" },
        { agent: "a2", surface_id: "surface-b" },
      ],
    }, null, 2)}\n`);

    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      content: "# A1",
    });

    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a2",
      surface_id: "surface-b",
      surface_status: "partial",
      content: "# A2",
    });

    const status = JSON.parse(waveHandoffStatus({ target_domain: domain, wave_number: 1 }));

    assert.deepEqual(status, {
      assignments_total: 2,
      handoffs_total: 2,
      received_agents: ["a1", "a2"],
      missing_agents: [],
      unexpected_agents: [],
      is_complete: true,
    });
  });
});

test("bounty_wave_handoff_status reports partial completion and unexpected handoffs without parsing payloads", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });

    writeFileAtomic(path.join(dir, "wave-2-assignments.json"), `${JSON.stringify({
      wave_number: 2,
      assignments: [
        { agent: "a1", surface_id: "surface-a" },
        { agent: "a2", surface_id: "surface-b" },
        { agent: "a3", surface_id: "surface-c" },
      ],
    }, null, 2)}\n`);

    writeFileAtomic(path.join(dir, "handoff-w2-a1.json"), "{bad json");
    writeWaveHandoff({
      target_domain: domain,
      wave: "w2",
      agent: "a9",
      surface_id: "surface-z",
      surface_status: "complete",
      content: "# unexpected",
    });

    const status = JSON.parse(waveHandoffStatus({ target_domain: domain, wave_number: 2 }));

    assert.deepEqual(status, {
      assignments_total: 3,
      handoffs_total: 2,
      received_agents: ["a1"],
      missing_agents: ["a2", "a3"],
      unexpected_agents: ["a9"],
      is_complete: false,
    });
  });
});

test("bounty_wave_handoff_status hard-fails when the assignment file is missing", () => {
  withTempHome(() => {
    assert.throws(
      () => waveHandoffStatus({ target_domain: "example.com", wave_number: 7 }),
      /Missing assignment file/,
    );
  });
});

test("bounty_merge_wave_handoffs merges valid handoffs and dedupes optional arrays", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });

    writeFileAtomic(path.join(dir, "wave-2-assignments.json"), `${JSON.stringify({
      wave_number: 2,
      assignments: [
        { agent: "a1", surface_id: "surface-a" },
        { agent: "a2", surface_id: "surface-b" },
      ],
    }, null, 2)}\n`);

    writeWaveHandoff({
      target_domain: domain,
      wave: "w2",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      content: "# A1",
      dead_ends: [" /users/1 ", "/users/1", ""],
      waf_blocked_endpoints: ["/admin"],
      lead_surface_ids: ["surface-b", "surface-b", "surface-c"],
    });

    writeWaveHandoff({
      target_domain: domain,
      wave: "w2",
      agent: "a2",
      surface_id: "surface-b",
      surface_status: "partial",
      content: "# A2",
      dead_ends: ["/billing"],
      waf_blocked_endpoints: ["/admin", " /reports "],
      lead_surface_ids: ["surface-c", "surface-d"],
    });

    const merged = JSON.parse(mergeWaveHandoffs({ target_domain: domain, wave_number: 2 }));

    assert.deepEqual(merged, {
      assignments_total: 2,
      handoffs_total: 2,
      received_agents: ["a1", "a2"],
      invalid_agents: [],
      unexpected_agents: [],
      completed_surface_ids: ["surface-a"],
      partial_surface_ids: ["surface-b"],
      missing_surface_ids: [],
      dead_ends: ["/users/1", "/billing"],
      waf_blocked_endpoints: ["/admin", "/reports"],
      lead_surface_ids: ["surface-b", "surface-c", "surface-d"],
    });
  });
});

test("bounty_merge_wave_handoffs requeues missing and invalid assigned handoffs while ignoring unexpected agents", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });

    writeFileAtomic(path.join(dir, "wave-3-assignments.json"), `${JSON.stringify({
      wave_number: 3,
      assignments: [
        { agent: "a1", surface_id: "surface-a" },
        { agent: "a2", surface_id: "surface-b" },
      ],
    }, null, 2)}\n`);

    writeFileAtomic(path.join(dir, "handoff-w3-a1.json"), "{bad json");
    writeWaveHandoff({
      target_domain: domain,
      wave: "w3",
      agent: "a9",
      surface_id: "surface-z",
      surface_status: "complete",
      content: "# unexpected",
      dead_ends: ["/ignored"],
    });

    const merged = JSON.parse(mergeWaveHandoffs({ target_domain: domain, wave_number: 3 }));

    assert.deepEqual(merged, {
      assignments_total: 2,
      handoffs_total: 2,
      received_agents: [],
      invalid_agents: ["a1"],
      unexpected_agents: ["a9"],
      completed_surface_ids: [],
      partial_surface_ids: [],
      missing_surface_ids: ["surface-b"],
      dead_ends: [],
      waf_blocked_endpoints: [],
      lead_surface_ids: [],
    });
  });
});

test("bounty_merge_wave_handoffs hard-fails when the assignment file is missing", () => {
  withTempHome(() => {
    assert.throws(
      () => mergeWaveHandoffs({ target_domain: "example.com", wave_number: 4 }),
      /Missing assignment file/,
    );
  });
});

test("bounty_record_finding appends findings.jsonl and bounty_read_findings preserves insertion order", () => {
  withTempHome(() => {
    const domain = "example.com";
    const first = seedFinding(domain);
    const second = seedFinding(domain, {
      title: "Stored XSS in comments",
      severity: "medium",
      endpoint: "/comments",
      description: "Unsanitized comment body executes in admin view.",
      proof_of_concept: "<script>alert(1)</script>",
      response_evidence: "<script>alert(1)</script>",
      impact: "Admin session compromise.",
      wave: "w2",
      agent: "a2",
    });

    assert.equal(first.finding_id, "F-1");
    assert.equal(second.finding_id, "F-2");

    const findingsPath = findingsJsonlPath(domain);
    const jsonlLines = fs.readFileSync(findingsPath, "utf8").trim().split("\n");
    assert.equal(jsonlLines.length, 2);
    assert.equal(JSON.parse(jsonlLines[0]).id, "F-1");
    assert.equal(JSON.parse(jsonlLines[1]).id, "F-2");

    const readResult = JSON.parse(readFindings({ target_domain: domain }));
    assert.deepEqual(readResult, {
      version: 1,
      target_domain: domain,
      findings: [
        {
          id: "F-1",
          target_domain: domain,
          title: "IDOR on account export",
          severity: "high",
          cwe: "CWE-639",
          endpoint: "/api/export",
          description: "Authenticated user can export another account's data by changing account_id.",
          proof_of_concept: "curl https://example.com/api/export?account_id=2",
          response_evidence: "{\"account_id\":2}",
          impact: "Cross-account PII disclosure.",
          validated: true,
          wave: "w1",
          agent: "a1",
        },
        {
          id: "F-2",
          target_domain: domain,
          title: "Stored XSS in comments",
          severity: "medium",
          cwe: "CWE-639",
          endpoint: "/comments",
          description: "Unsanitized comment body executes in admin view.",
          proof_of_concept: "<script>alert(1)</script>",
          response_evidence: "<script>alert(1)</script>",
          impact: "Admin session compromise.",
          validated: true,
          wave: "w2",
          agent: "a2",
        },
      ],
    });
  });
});

test("bounty_record_finding still writes readable findings.md", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    const markdown = fs.readFileSync(findingsMarkdownPath(domain), "utf8");
    assert.match(markdown, /## FINDING 1 \(HIGH\): IDOR on account export/);
    assert.match(markdown, /\*\*ID:\*\* F-1/);
    assert.match(markdown, /curl https:\/\/example.com\/api\/export\?account_id=2/);
  });
});

test("bounty_record_finding returns warning metadata when markdown sync fails after JSONL success", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(path.join(dir, "findings.md"), { recursive: true });

    const result = seedFinding(domain);

    assert.equal(result.recorded, true);
    assert.equal(result.finding_id, "F-1");
    assert.ok(result.markdown_sync_error);
    assert.equal(fs.readFileSync(findingsJsonlPath(domain), "utf8").trim().split("\n").length, 1);
    assert.ok(fs.statSync(path.join(dir, "findings.md")).isDirectory());
  });
});

test("bounty_read_findings, bounty_list_findings, and bounty_wave_status return empty-state results when findings.jsonl is absent", () => {
  withTempHome(() => {
    const domain = "example.com";

    assert.deepEqual(JSON.parse(readFindings({ target_domain: domain })), {
      version: 1,
      target_domain: domain,
      findings: [],
    });
    assert.deepEqual(JSON.parse(listFindings({ target_domain: domain })), {
      count: 0,
      findings: [],
    });
    assert.deepEqual(JSON.parse(waveStatus({ target_domain: domain })), {
      total: 0,
      by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      has_high_or_critical: false,
      findings_summary: [],
    });
  });
});

test("malformed findings.jsonl hard-fails bounty_read_findings, bounty_list_findings, and bounty_wave_status", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      findingsJsonlPath(domain),
      `${JSON.stringify({
        id: "F-1",
        target_domain: domain,
        title: "Valid first line",
        severity: "low",
        cwe: null,
        endpoint: "/ok",
        description: "Still valid.",
        proof_of_concept: "curl https://example.com/ok",
        response_evidence: null,
        impact: null,
        validated: true,
        wave: null,
        agent: null,
      })}\nnot-json\n`,
    );

    assert.throws(() => readFindings({ target_domain: domain }), /Malformed findings\.jsonl at line 2/);
    assert.throws(() => listFindings({ target_domain: domain }), /Malformed findings\.jsonl at line 2/);
    assert.throws(() => waveStatus({ target_domain: domain }), /Malformed findings\.jsonl at line 2/);
  });
});

test("bounty_list_findings and bounty_wave_status keep their external shapes while reading findings.jsonl", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain, { severity: "critical" });
    seedFinding(domain, {
      title: "Verbose stack trace leak",
      severity: "low",
      endpoint: "/boom",
      description: "Exception page leaks internal paths.",
      proof_of_concept: "curl https://example.com/boom",
      response_evidence: "ReferenceError",
      impact: "Improves exploit development.",
      wave: null,
      agent: null,
    });

    assert.deepEqual(JSON.parse(listFindings({ target_domain: domain })), {
      count: 2,
      findings: [
        {
          id: "F-1",
          severity: "critical",
          title: "IDOR on account export",
          endpoint: "/api/export",
        },
        {
          id: "F-2",
          severity: "low",
          title: "Verbose stack trace leak",
          endpoint: "/boom",
        },
      ],
    });

    assert.deepEqual(JSON.parse(waveStatus({ target_domain: domain })), {
      total: 2,
      by_severity: { critical: 1, high: 0, medium: 0, low: 1, info: 0 },
      has_high_or_critical: true,
      findings_summary: [
        {
          id: "F-1",
          severity: "critical",
          title: "IDOR on account export",
          endpoint: "/api/export",
          wave_agent: "w1/a1",
        },
        {
          id: "F-2",
          severity: "low",
          title: "Verbose stack trace leak",
          endpoint: "/boom",
          wave_agent: null,
        },
      ],
    });
  });
});

test("bounty_write_verification_round writes the correct JSON and markdown pair for each round", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    for (const round of ["brutalist", "balanced", "final"]) {
      const result = JSON.parse(writeVerificationRound({
        target_domain: domain,
        round,
        notes: null,
        results: [],
      }));
      const paths = verificationRoundPaths(domain, round);

      assert.equal(result.round, round);
      assert.equal(result.results_count, 0);
      assert.equal(result.written_json, paths.json);
      assert.equal(result.written_md, paths.markdown);

      assert.deepEqual(JSON.parse(fs.readFileSync(paths.json, "utf8")), {
        version: 1,
        target_domain: domain,
        round,
        notes: null,
        results: [],
      });
      assert.match(fs.readFileSync(paths.markdown, "utf8"), /No verification results recorded\./);

      assert.deepEqual(JSON.parse(readVerificationRound({ target_domain: domain, round })), {
        version: 1,
        target_domain: domain,
        round,
        notes: null,
        results: [],
      });
    }
  });
});

test("bounty_write_verification_round accepts notes null and validates duplicate and unknown finding_ids", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "brutalist",
      notes: null,
      results: [
        {
          finding_id: "F-1",
          disposition: "confirmed",
          severity: "high",
          reportable: true,
          reasoning: "Still exploitable.",
        },
        {
          finding_id: "F-1",
          disposition: "downgraded",
          severity: "medium",
          reportable: true,
          reasoning: "Duplicate entry should fail.",
        },
      ],
    }), /Duplicate finding_id in results: F-1/);

    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "balanced",
      notes: null,
      results: [
        {
          finding_id: "F-99",
          disposition: "denied",
          severity: null,
          reportable: false,
          reasoning: "Unknown ID.",
        },
      ],
    }), /Unknown finding_id: F-99/);
  });
});

test("bounty_read_verification_round hard-fails on missing or malformed JSON", () => {
  withTempHome(() => {
    const domain = "example.com";

    assert.throws(
      () => readVerificationRound({ target_domain: domain, round: "final" }),
      /Missing final verification round JSON/,
    );

    const paths = verificationRoundPaths(domain, "final");
    fs.mkdirSync(path.dirname(paths.json), { recursive: true });
    fs.writeFileSync(paths.json, "{bad json");

    assert.throws(
      () => readVerificationRound({ target_domain: domain, round: "final" }),
      /Malformed final verification round JSON/,
    );
  });
});

test("bounty_read_verification_round rejects JSON that references non-existent findings", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    const paths = verificationRoundPaths(domain, "balanced");
    fs.mkdirSync(path.dirname(paths.json), { recursive: true });
    fs.writeFileSync(paths.json, `${JSON.stringify({
      version: 1,
      target_domain: domain,
      round: "balanced",
      notes: null,
      results: [
        {
          finding_id: "F-99",
          disposition: "denied",
          severity: null,
          reportable: false,
          reasoning: "Manually edited bad artifact.",
        },
      ],
    }, null, 2)}\n`);

    assert.throws(
      () => readVerificationRound({ target_domain: domain, round: "balanced" }),
      /Unknown finding_id: F-99/,
    );
  });
});

test("bounty_write_grade_verdict writes grade.json and grade.md and accepts empty findings", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    const result = JSON.parse(writeGradeVerdict({
      target_domain: domain,
      verdict: "SKIP",
      total_score: 0,
      findings: [],
      feedback: null,
    }));
    const paths = gradeArtifactPaths(domain);

    assert.equal(result.verdict, "SKIP");
    assert.equal(result.findings_count, 0);
    assert.equal(result.written_json, paths.json);
    assert.equal(result.written_md, paths.markdown);
    assert.deepEqual(JSON.parse(fs.readFileSync(paths.json, "utf8")), {
      version: 1,
      target_domain: domain,
      verdict: "SKIP",
      total_score: 0,
      findings: [],
      feedback: null,
    });
    assert.match(fs.readFileSync(paths.markdown, "utf8"), /No graded findings\./);

    assert.deepEqual(JSON.parse(readGradeVerdict({ target_domain: domain })), {
      version: 1,
      target_domain: domain,
      verdict: "SKIP",
      total_score: 0,
      findings: [],
      feedback: null,
    });
  });
});

test("bounty_write_grade_verdict rejects duplicate or unknown finding_ids", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    assert.throws(() => writeGradeVerdict({
      target_domain: domain,
      verdict: "HOLD",
      total_score: 80,
      findings: [
        {
          finding_id: "F-1",
          impact: 20,
          proof_quality: 20,
          severity_accuracy: 15,
          chain_potential: 10,
          report_quality: 15,
          total_score: 80,
          feedback: null,
        },
        {
          finding_id: "F-1",
          impact: 10,
          proof_quality: 10,
          severity_accuracy: 10,
          chain_potential: 10,
          report_quality: 10,
          total_score: 50,
          feedback: "duplicate",
        },
      ],
      feedback: "Need stronger chain.",
    }), /Duplicate finding_id in findings: F-1/);

    assert.throws(() => writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 80,
      findings: [
        {
          finding_id: "F-99",
          impact: 20,
          proof_quality: 20,
          severity_accuracy: 15,
          chain_potential: 10,
          report_quality: 15,
          total_score: 80,
          feedback: null,
        },
      ],
      feedback: null,
    }), /Unknown finding_id: F-99/);
  });
});

test("bounty_read_grade_verdict hard-fails on missing or malformed JSON", () => {
  withTempHome(() => {
    const domain = "example.com";
    const paths = gradeArtifactPaths(domain);

    assert.throws(
      () => readGradeVerdict({ target_domain: domain }),
      /Missing grade verdict JSON/,
    );

    fs.mkdirSync(path.dirname(paths.json), { recursive: true });
    fs.writeFileSync(paths.json, "{bad json");

    assert.throws(
      () => readGradeVerdict({ target_domain: domain }),
      /Malformed grade verdict JSON/,
    );
  });
});

test("bounty_read_grade_verdict rejects JSON that references non-existent findings", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    const paths = gradeArtifactPaths(domain);
    fs.mkdirSync(path.dirname(paths.json), { recursive: true });
    fs.writeFileSync(paths.json, `${JSON.stringify({
      version: 1,
      target_domain: domain,
      verdict: "HOLD",
      total_score: 10,
      findings: [
        {
          finding_id: "F-99",
          impact: 2,
          proof_quality: 2,
          severity_accuracy: 2,
          chain_potential: 2,
          report_quality: 2,
          total_score: 10,
          feedback: null,
        },
      ],
      feedback: "Bad manual edit.",
    }, null, 2)}\n`);

    assert.throws(
      () => readGradeVerdict({ target_domain: domain }),
      /Unknown finding_id: F-99/,
    );
  });
});
