"use strict";

/**
 * Tests for S6 — findings-serializer.ts.
 *
 * Verifies acceptance criteria:
 *   1. Top-level keys: session_id, target_domain, generated_at, impacted_entries[],
 *      findings[] present in output.
 *   2. Each finding includes: surface_id, file, line_start, line_end, title,
 *      severity, description (<=500 chars), evidence (<=EVIDENCE_MAX_CHARS),
 *      hunk_text.
 *   3. Findings with no matching impacted_entry are excluded (orphaned).
 *   4. Zero findings: file still written with empty findings[].
 *   5. Claims from prior sessions are filtered by session_id.
 *   6. Binary evidence is base64-encoded to prevent JSON parse errors.
 *   7. writeFindings produces valid JSON (mirrors CI jq . check).
 *   8. rangesOverlap correctly computes overlap including edge cases.
 *   9. normaliseSeverity maps known and unknown values correctly.
 *  10. hunk_text falls back to impacted_entry.hunk_summary when claim has none.
 *  11. Missing file/title claims are excluded as orphaned.
 *  12. formatS6FailureJson produces parseable JSON with step 'S6.findings_serialization'.
 *  13. description capped at 500 chars.
 *  14. evidence capped at EVIDENCE_MAX_CHARS.
 *  15. Both PATH A and PATH B impacted_entry formats are accepted identically.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  EVIDENCE_MAX_CHARS,
  VALID_SEVERITIES,
  normaliseSeverity,
  truncate,
  sanitiseEvidence,
  normaliseCandidateClaim,
  rangesOverlap,
  findMatchingEntry,
  serializeFindings,
  writeFindings,
  validateJsonFile,
  formatS6FailureJson,
} = require("../packages/bob-diff-review/dist/findings-serializer.js");

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeEntry(file, surface_ids, lineStart = 1, lineEnd = 50, hunkSummary = "") {
  return {
    file,
    line_start: lineStart,
    line_end: lineEnd,
    surface_ids,
    hunk_summary: hunkSummary || `change in ${file}:${lineStart}-${lineEnd}`,
  };
}

function makeClaim(overrides = {}) {
  return {
    session_id: "sess-001",
    surface_id: "heuristic:authentication",
    file: "src/auth/login.ts",
    line_start: 10,
    line_end: 20,
    title: "Authentication bypass via missing validation",
    severity: "high",
    description: "Attacker can bypass password check by sending null value.",
    evidence: "POST /login HTTP/1.1\n\nResponse: 200 OK — {token: 'abc'}",
    hunk_text: "@@ -10,3 +10,5 @@ function authenticate() {}",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// normaliseSeverity
// ---------------------------------------------------------------------------

test("normaliseSeverity returns valid values unchanged", () => {
  for (const sev of VALID_SEVERITIES) {
    assert.equal(normaliseSeverity(sev), sev);
  }
});

test("normaliseSeverity normalises aliases", () => {
  assert.equal(normaliseSeverity("crit"), "critical");
  assert.equal(normaliseSeverity("severe"), "high");
  assert.equal(normaliseSeverity("moderate"), "medium");
  assert.equal(normaliseSeverity("minor"), "low");
});

test("normaliseSeverity returns 'info' for unknown values", () => {
  assert.equal(normaliseSeverity("unknown-severity"), "info");
  assert.equal(normaliseSeverity(undefined), "info");
  assert.equal(normaliseSeverity(""), "info");
});

test("normaliseSeverity is case-insensitive", () => {
  assert.equal(normaliseSeverity("HIGH"), "high");
  assert.equal(normaliseSeverity("Critical"), "critical");
  assert.equal(normaliseSeverity("MEDIUM"), "medium");
});

// ---------------------------------------------------------------------------
// truncate
// ---------------------------------------------------------------------------

test("truncate leaves short strings unchanged", () => {
  assert.equal(truncate("hello", 100), "hello");
});

test("truncate appends [truncated] on long strings", () => {
  const long = "a".repeat(2100);
  const result = truncate(long, 2000);
  assert.ok(result.endsWith("[truncated]"));
  assert.equal(result.length, 2000);
});

test("truncate at exactly maxChars does not truncate", () => {
  const s = "a".repeat(500);
  assert.equal(truncate(s, 500), s);
});

// ---------------------------------------------------------------------------
// sanitiseEvidence
// ---------------------------------------------------------------------------

test("sanitiseEvidence passes through clean ASCII", () => {
  const ev = "GET /api HTTP/1.1\n\nHTTP/1.1 200 OK\nContent-Type: application/json";
  assert.equal(sanitiseEvidence(ev), ev);
});

test("sanitiseEvidence returns empty string for undefined", () => {
  assert.equal(sanitiseEvidence(undefined), "");
});

test("sanitiseEvidence base64-encodes binary content", () => {
  const binary = "\x00\x01\x02binary data";
  const result = sanitiseEvidence(binary);
  assert.ok(result.startsWith("[binary evidence base64] "));
});

// ---------------------------------------------------------------------------
// rangesOverlap
// ---------------------------------------------------------------------------

test("rangesOverlap: identical ranges overlap", () => {
  assert.ok(rangesOverlap(10, 20, 10, 20));
});

test("rangesOverlap: adjacent non-overlapping ranges", () => {
  assert.ok(!rangesOverlap(1, 5, 6, 10));
  assert.ok(!rangesOverlap(6, 10, 1, 5));
});

test("rangesOverlap: touching at boundary", () => {
  assert.ok(rangesOverlap(1, 5, 5, 10));
  assert.ok(rangesOverlap(5, 10, 1, 5));
});

test("rangesOverlap: fully contained range overlaps", () => {
  assert.ok(rangesOverlap(10, 20, 12, 15));
  assert.ok(rangesOverlap(12, 15, 10, 20));
});

test("rangesOverlap: partial overlap", () => {
  assert.ok(rangesOverlap(10, 20, 15, 25));
  assert.ok(rangesOverlap(15, 25, 10, 20));
});

// ---------------------------------------------------------------------------
// normaliseCandidateClaim
// ---------------------------------------------------------------------------

test("normaliseCandidateClaim normalises a well-formed claim", () => {
  const raw = makeClaim();
  const result = normaliseCandidateClaim(raw);
  assert.ok(result !== null, "should return non-null");
  assert.equal(result.file, "src/auth/login.ts");
  assert.equal(result.title, "Authentication bypass via missing validation");
  assert.equal(result.severity, "high");
  assert.equal(result.line_start, 10);
  assert.equal(result.line_end, 20);
});

test("normaliseCandidateClaim returns null when file is missing", () => {
  const raw = makeClaim({ file: undefined });
  assert.equal(normaliseCandidateClaim(raw), null);
});

test("normaliseCandidateClaim returns null when file is empty string", () => {
  const raw = makeClaim({ file: "" });
  assert.equal(normaliseCandidateClaim(raw), null);
});

test("normaliseCandidateClaim returns null when title is missing", () => {
  const raw = makeClaim({ title: undefined });
  assert.equal(normaliseCandidateClaim(raw), null);
});

test("normaliseCandidateClaim defaults line_start to 1 when missing", () => {
  const raw = makeClaim({ line_start: undefined });
  const result = normaliseCandidateClaim(raw);
  assert.ok(result !== null);
  assert.equal(result.line_start, 1);
});

test("normaliseCandidateClaim defaults line_end to line_start when missing", () => {
  const raw = makeClaim({ line_end: undefined, line_start: 15 });
  const result = normaliseCandidateClaim(raw);
  assert.ok(result !== null);
  assert.equal(result.line_end, 15);
});

test("normaliseCandidateClaim truncates description at 500 chars", () => {
  const long = "x".repeat(600);
  const raw = makeClaim({ description: long });
  const result = normaliseCandidateClaim(raw);
  assert.ok(result !== null);
  assert.ok(result.description.length <= 500);
  assert.ok(result.description.endsWith("[truncated]"));
});

test("normaliseCandidateClaim truncates evidence at EVIDENCE_MAX_CHARS", () => {
  const long = "e".repeat(EVIDENCE_MAX_CHARS + 500);
  const raw = makeClaim({ evidence: long });
  const result = normaliseCandidateClaim(raw);
  assert.ok(result !== null);
  assert.ok(result.evidence.length <= EVIDENCE_MAX_CHARS);
  assert.ok(result.evidence.endsWith("[truncated]"));
});

// ---------------------------------------------------------------------------
// findMatchingEntry
// ---------------------------------------------------------------------------

test("findMatchingEntry returns null when no entries exist for file", () => {
  const entries = [makeEntry("other/file.ts", ["heuristic:api-route"])];
  const claim = { file: "src/auth/login.ts", line_start: 10, line_end: 20, surface_id: "" };
  assert.equal(findMatchingEntry(claim, entries), null);
});

test("findMatchingEntry returns null when file matches but lines do not overlap", () => {
  const entries = [makeEntry("src/auth/login.ts", ["heuristic:authentication"], 30, 50)];
  const claim = { file: "src/auth/login.ts", line_start: 10, line_end: 20, surface_id: "" };
  assert.equal(findMatchingEntry(claim, entries), null);
});

test("findMatchingEntry returns entry when file + line range overlap", () => {
  const entry = makeEntry("src/auth/login.ts", ["heuristic:authentication"], 5, 25);
  const claim = { file: "src/auth/login.ts", line_start: 10, line_end: 20, surface_id: "" };
  assert.deepEqual(findMatchingEntry(claim, [entry]), entry);
});

test("findMatchingEntry prefers entry whose surface_ids includes claim surface_id", () => {
  const entryA = makeEntry("src/auth/login.ts", ["heuristic:api-route"], 1, 50);
  const entryB = makeEntry("src/auth/login.ts", ["heuristic:authentication"], 1, 50);
  const claim = {
    file: "src/auth/login.ts",
    line_start: 10,
    line_end: 20,
    surface_id: "heuristic:authentication",
  };
  const result = findMatchingEntry(claim, [entryA, entryB]);
  assert.deepEqual(result, entryB);
});

test("findMatchingEntry falls back to first overlapping entry when surface_id has no match", () => {
  const entryA = makeEntry("src/auth/login.ts", ["heuristic:api-route"], 1, 50);
  const claim = {
    file: "src/auth/login.ts",
    line_start: 10,
    line_end: 20,
    surface_id: "heuristic:unknown",
  };
  const result = findMatchingEntry(claim, [entryA]);
  assert.deepEqual(result, entryA);
});

test("findMatchingEntry normalises backslash paths on Windows-style file names", () => {
  const entry = makeEntry("src/auth/login.ts", ["heuristic:authentication"], 1, 50);
  const claim = {
    file: "src\\auth\\login.ts",
    line_start: 5,
    line_end: 15,
    surface_id: "",
  };
  const result = findMatchingEntry(claim, [entry]);
  assert.deepEqual(result, entry);
});

// ---------------------------------------------------------------------------
// serializeFindings — full document structure
// ---------------------------------------------------------------------------

test("serializeFindings produces required top-level keys", () => {
  const entries = [makeEntry("src/auth/login.ts", ["heuristic:authentication"], 1, 50)];
  const claims = [makeClaim()];
  const result = serializeFindings({
    session_id: "sess-001",
    target_domain: "gh-abc123",
    impacted_entries: entries,
    raw_claims: claims,
    generated_at: "2026-06-07T00:00:00.000Z",
  });

  const doc = result.findings_doc;
  assert.equal(doc.session_id, "sess-001");
  assert.equal(doc.target_domain, "gh-abc123");
  assert.equal(doc.generated_at, "2026-06-07T00:00:00.000Z");
  assert.ok(Array.isArray(doc.impacted_entries));
  assert.ok(Array.isArray(doc.findings));
});

test("serializeFindings produces one finding for a matched claim", () => {
  const entries = [makeEntry("src/auth/login.ts", ["heuristic:authentication"], 1, 50)];
  const claims = [makeClaim()];
  const result = serializeFindings({
    session_id: "sess-001",
    target_domain: "gh-abc123",
    impacted_entries: entries,
    raw_claims: claims,
  });

  assert.equal(result.findings_doc.findings.length, 1);
  assert.equal(result.orphaned_count, 0);
});

test("serializeFindings finding contains all required fields", () => {
  const entries = [makeEntry("src/auth/login.ts", ["heuristic:authentication"], 1, 50)];
  const claims = [makeClaim()];
  const result = serializeFindings({
    session_id: "sess-001",
    target_domain: "gh-abc123",
    impacted_entries: entries,
    raw_claims: claims,
  });

  const finding = result.findings_doc.findings[0];
  assert.ok(typeof finding.surface_id === "string", "surface_id must be string");
  assert.ok(typeof finding.file === "string", "file must be string");
  assert.ok(typeof finding.line_start === "number", "line_start must be number");
  assert.ok(typeof finding.line_end === "number", "line_end must be number");
  assert.ok(typeof finding.title === "string", "title must be string");
  assert.ok(
    VALID_SEVERITIES.includes(finding.severity),
    `severity must be one of ${VALID_SEVERITIES.join(", ")}`
  );
  assert.ok(typeof finding.description === "string", "description must be string");
  assert.ok(finding.description.length <= 500, "description must be <=500 chars");
  assert.ok(typeof finding.evidence === "string", "evidence must be string");
  assert.ok(
    finding.evidence.length <= EVIDENCE_MAX_CHARS,
    `evidence must be <=${EVIDENCE_MAX_CHARS} chars`
  );
  assert.ok(typeof finding.hunk_text === "string", "hunk_text must be string");
});

test("serializeFindings excludes orphaned claim (no matching impacted_entry)", () => {
  const entries = [makeEntry("other/file.ts", ["heuristic:api-route"], 1, 50)];
  const claims = [makeClaim({ file: "src/auth/login.ts", line_start: 10, line_end: 20 })];
  const result = serializeFindings({
    session_id: "sess-001",
    target_domain: "gh-abc123",
    impacted_entries: entries,
    raw_claims: claims,
  });

  assert.equal(result.findings_doc.findings.length, 0);
  assert.equal(result.orphaned_count, 1);
});

test("serializeFindings writes empty findings[] when zero claims match", () => {
  const entries = [makeEntry("src/auth/login.ts", ["heuristic:authentication"], 1, 50)];
  const result = serializeFindings({
    session_id: "sess-001",
    target_domain: "gh-abc123",
    impacted_entries: entries,
    raw_claims: [],
  });

  assert.equal(result.findings_doc.findings.length, 0);
  assert.ok(Array.isArray(result.findings_doc.findings));
});

test("serializeFindings filters claims from prior sessions", () => {
  const entries = [makeEntry("src/auth/login.ts", ["heuristic:authentication"], 1, 50)];
  const claims = [
    makeClaim({ session_id: "sess-old", title: "Old session claim" }),
    makeClaim({ session_id: "sess-001", title: "Current session claim" }),
  ];
  const result = serializeFindings({
    session_id: "sess-001",
    target_domain: "gh-abc123",
    impacted_entries: entries,
    raw_claims: claims,
  });

  assert.equal(result.session_filtered_count, 1);
  assert.equal(result.findings_doc.findings.length, 1);
  assert.equal(result.findings_doc.findings[0].title, "Current session claim");
});

test("serializeFindings includes claim with empty session_id (session not set)", () => {
  // Claims without session_id set are assumed to belong to the current session.
  const entries = [makeEntry("src/auth/login.ts", ["heuristic:authentication"], 1, 50)];
  const claims = [makeClaim({ session_id: undefined })];
  const result = serializeFindings({
    session_id: "sess-001",
    target_domain: "gh-abc123",
    impacted_entries: entries,
    raw_claims: claims,
  });

  assert.equal(result.session_filtered_count, 0);
  assert.equal(result.findings_doc.findings.length, 1);
});

test("serializeFindings excludes claim missing required file field", () => {
  const entries = [makeEntry("src/auth/login.ts", ["heuristic:authentication"], 1, 50)];
  const claims = [makeClaim({ file: undefined })];
  const result = serializeFindings({
    session_id: "sess-001",
    target_domain: "gh-abc123",
    impacted_entries: entries,
    raw_claims: claims,
  });

  assert.equal(result.orphaned_count, 1);
  assert.equal(result.findings_doc.findings.length, 0);
});

test("serializeFindings excludes claim missing required title field", () => {
  const entries = [makeEntry("src/auth/login.ts", ["heuristic:authentication"], 1, 50)];
  const claims = [makeClaim({ title: undefined })];
  const result = serializeFindings({
    session_id: "sess-001",
    target_domain: "gh-abc123",
    impacted_entries: entries,
    raw_claims: claims,
  });

  assert.equal(result.orphaned_count, 1);
  assert.equal(result.findings_doc.findings.length, 0);
});

test("serializeFindings uses impacted_entry hunk_summary when claim has no hunk_text", () => {
  const entries = [makeEntry("src/auth/login.ts", ["heuristic:authentication"], 1, 50, "Auth change summary")];
  const claims = [makeClaim({ hunk_text: undefined })];
  const result = serializeFindings({
    session_id: "sess-001",
    target_domain: "gh-abc123",
    impacted_entries: entries,
    raw_claims: claims,
  });

  assert.equal(result.findings_doc.findings.length, 1);
  assert.equal(result.findings_doc.findings[0].hunk_text, "Auth change summary");
});

test("serializeFindings uses claim hunk_text when present", () => {
  const entries = [makeEntry("src/auth/login.ts", ["heuristic:authentication"], 1, 50, "Entry summary")];
  const claims = [makeClaim({ hunk_text: "@@ -10 +10 @@ custom hunk text" })];
  const result = serializeFindings({
    session_id: "sess-001",
    target_domain: "gh-abc123",
    impacted_entries: entries,
    raw_claims: claims,
  });

  assert.equal(result.findings_doc.findings[0].hunk_text, "@@ -10 +10 @@ custom hunk text");
});

test("serializeFindings: empty impacted_entries yields empty findings and orphaned count", () => {
  const claims = [makeClaim()];
  const result = serializeFindings({
    session_id: "sess-001",
    target_domain: "gh-abc123",
    impacted_entries: [],
    raw_claims: claims,
  });

  assert.equal(result.findings_doc.findings.length, 0);
  assert.equal(result.orphaned_count, 1);
  assert.ok(Array.isArray(result.findings_doc.impacted_entries));
  assert.equal(result.findings_doc.impacted_entries.length, 0);
});

test("serializeFindings uses provided generated_at when supplied", () => {
  const ts = "2026-01-01T12:00:00.000Z";
  const result = serializeFindings({
    session_id: "sess-001",
    target_domain: "gh-abc123",
    impacted_entries: [],
    raw_claims: [],
    generated_at: ts,
  });
  assert.equal(result.findings_doc.generated_at, ts);
});

test("serializeFindings defaults generated_at to current ISO timestamp", () => {
  const before = Date.now();
  const result = serializeFindings({
    session_id: "sess-001",
    target_domain: "gh-abc123",
    impacted_entries: [],
    raw_claims: [],
  });
  const after = Date.now();
  const ts = new Date(result.findings_doc.generated_at).getTime();
  assert.ok(ts >= before && ts <= after, "generated_at should be approximately now");
});

// ---------------------------------------------------------------------------
// PATH A and PATH B impacted_entries are treated identically
// ---------------------------------------------------------------------------

test("serializeFindings works with PATH A (index-derived) surface_ids", () => {
  const entries = [makeEntry("src/contracts/Token.sol", ["smart_contract:token-vault"], 50, 120)];
  const claims = [{
    session_id: "sess-001",
    surface_id: "smart_contract:token-vault",
    file: "src/contracts/Token.sol",
    line_start: 60,
    line_end: 80,
    title: "Integer overflow in transfer",
    severity: "critical",
    description: "Unchecked arithmetic allows overflow.",
    evidence: "uint256 amount = balances[from] - value; // wraps on underflow",
    hunk_text: "@@ -60,5 +60,7 @@ function transfer() {",
  }];
  const result = serializeFindings({
    session_id: "sess-001",
    target_domain: "gh-abc123",
    impacted_entries: entries,
    raw_claims: claims,
  });

  assert.equal(result.findings_doc.findings.length, 1);
  assert.equal(result.findings_doc.findings[0].severity, "critical");
  assert.equal(result.findings_doc.findings[0].surface_id, "smart_contract:token-vault");
});

test("serializeFindings works with PATH B (heuristic:) prefixed surface_ids", () => {
  const entries = [makeEntry("routes/api.ts", ["heuristic:api-route"], 1, 30)];
  const claims = [{
    session_id: "sess-001",
    surface_id: "heuristic:api-route",
    file: "routes/api.ts",
    line_start: 5,
    line_end: 15,
    title: "IDOR in user endpoint",
    severity: "high",
    description: "User ID not validated against session.",
    evidence: "GET /api/users/999 -> 200 OK with another user's data",
    hunk_text: "@@ -5,3 +5,5 @@ router.get('/users/:id', ...",
  }];
  const result = serializeFindings({
    session_id: "sess-001",
    target_domain: "gh-abc123",
    impacted_entries: entries,
    raw_claims: claims,
  });

  assert.equal(result.findings_doc.findings.length, 1);
  assert.equal(result.findings_doc.findings[0].surface_id, "heuristic:api-route");
});

// ---------------------------------------------------------------------------
// writeFindings — file I/O and JSON validity
// ---------------------------------------------------------------------------

test("writeFindings produces a valid JSON file", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-s6-test-"));
  try {
    const doc = {
      session_id: "sess-001",
      target_domain: "gh-abc123",
      generated_at: "2026-06-07T00:00:00.000Z",
      impacted_entries: [makeEntry("src/auth/login.ts", ["heuristic:authentication"], 1, 50)],
      findings: [],
    };
    const outPath = writeFindings(tmpDir, doc);
    assert.ok(fs.existsSync(outPath));
    assert.ok(outPath.endsWith("diff-review-findings.json"));
    const parsed = JSON.parse(fs.readFileSync(outPath, "utf8"));
    assert.equal(parsed.session_id, "sess-001");
    assert.ok(Array.isArray(parsed.findings));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("writeFindings creates output-dir if it does not exist", () => {
  const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), "bob-s6-base-"));
  const outputDir = path.join(tmpBase, "nested", "output");
  try {
    const doc = {
      session_id: "sess-001",
      target_domain: "gh-abc123",
      generated_at: "2026-06-07T00:00:00.000Z",
      impacted_entries: [],
      findings: [],
    };
    const outPath = writeFindings(outputDir, doc);
    assert.ok(fs.existsSync(outPath));
    assert.ok(validateJsonFile(outPath));
  } finally {
    fs.rmSync(tmpBase, { recursive: true, force: true });
  }
});

test("writeFindings rejects relative traversal output-dir", () => {
  const doc = {
    session_id: "sess-001",
    target_domain: "gh-abc123",
    generated_at: "2026-06-07T00:00:00.000Z",
    impacted_entries: [],
    findings: [],
  };
  assert.throws(
    () => writeFindings("../../outside", doc),
    /outputDir must be an absolute path/
  );
});

test("writeFindings result file is accessible (not inside session dir)", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-s6-access-"));
  try {
    const doc = {
      session_id: "sess-001",
      target_domain: "gh-abc123",
      generated_at: "2026-06-07T00:00:00.000Z",
      impacted_entries: [],
      findings: [],
    };
    const outPath = writeFindings(tmpDir, doc);
    // Verify the file is in the specified output-dir, not a sub-directory.
    assert.equal(path.dirname(outPath), tmpDir);
    assert.equal(path.basename(outPath), "diff-review-findings.json");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("validateJsonFile returns true for valid JSON file", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-s6-validate-"));
  try {
    const filePath = path.join(tmpDir, "test.json");
    fs.writeFileSync(filePath, JSON.stringify({ ok: true }), "utf8");
    assert.ok(validateJsonFile(filePath));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("validateJsonFile returns false for malformed JSON", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-s6-invalid-"));
  try {
    const filePath = path.join(tmpDir, "bad.json");
    fs.writeFileSync(filePath, "{not valid json", "utf8");
    assert.ok(!validateJsonFile(filePath));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// End-to-end: serializeFindings -> writeFindings -> valid JSON
// ---------------------------------------------------------------------------

test("end-to-end: serializeFindings then writeFindings produces valid jq-parseable JSON", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-s6-e2e-"));
  try {
    const entries = [
      makeEntry("src/auth/login.ts", ["heuristic:authentication"], 1, 50),
      makeEntry("routes/api.ts", ["heuristic:api-route"], 1, 80),
    ];
    const claims = [
      makeClaim(),
      makeClaim({
        surface_id: "heuristic:api-route",
        file: "routes/api.ts",
        line_start: 10,
        line_end: 25,
        title: "Missing rate limiting on login endpoint",
        severity: "medium",
        description: "No rate limit allows brute force.",
        evidence: "POST /login — 200 OK after 1000 attempts",
        hunk_text: "@@ -10,5 +10,6 @@ router.post('/login', ...",
      }),
    ];

    const { findings_doc } = serializeFindings({
      session_id: "sess-001",
      target_domain: "gh-abc123",
      impacted_entries: entries,
      raw_claims: claims,
      generated_at: "2026-06-07T00:00:00.000Z",
    });

    const outPath = writeFindings(tmpDir, findings_doc);
    assert.ok(validateJsonFile(outPath));

    const parsed = JSON.parse(fs.readFileSync(outPath, "utf8"));
    assert.equal(parsed.session_id, "sess-001");
    assert.equal(parsed.target_domain, "gh-abc123");
    assert.equal(typeof parsed.generated_at, "string");
    assert.ok(Array.isArray(parsed.impacted_entries));
    assert.ok(Array.isArray(parsed.findings));
    assert.equal(parsed.findings.length, 2);

    for (const f of parsed.findings) {
      assert.ok(typeof f.surface_id === "string");
      assert.ok(typeof f.file === "string");
      assert.ok(typeof f.line_start === "number");
      assert.ok(typeof f.line_end === "number");
      assert.ok(typeof f.title === "string");
      assert.ok(["critical", "high", "medium", "low", "info"].includes(f.severity));
      assert.ok(typeof f.description === "string");
      assert.ok(f.description.length <= 500);
      assert.ok(typeof f.evidence === "string");
      assert.ok(f.evidence.length <= EVIDENCE_MAX_CHARS);
      assert.ok(typeof f.hunk_text === "string");
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// formatS6FailureJson
// ---------------------------------------------------------------------------

test("formatS6FailureJson produces valid JSON with step S6.findings_serialization", () => {
  const result = formatS6FailureJson({ code: "no_impacted_entries", message: "Both S4 and S4b failed" });
  const parsed = JSON.parse(result);
  assert.equal(parsed.step, "S6.findings_serialization");
  assert.equal(parsed.ok, false);
  assert.equal(parsed.error.code, "no_impacted_entries");
  assert.equal(parsed.error.message, "Both S4 and S4b failed");
});
