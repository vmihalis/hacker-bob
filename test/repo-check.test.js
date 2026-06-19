"use strict";

// Cycle O.5 — read-only repo evidence probe via bob_repo_check.
//
// Coverage:
// - file_exists: hit / miss.
// - file_contains: literal substring match / miss.
// - regex_match: regex hit / miss; per-line matched_lines[].
// - Safe behavior on binary files (no crash, no excerpt of binary blob).
// - 4 MB cap: oversized file produces structured `file_too_large`.
// - O-P7 secret-scrub regression (critical): synthetic .env-shaped content
//   with `API_KEY=sk-live-abc123XYZdef` matched by `API_KEY=.*` produces a
//   REDACTED excerpt; the raw secret string MUST NOT appear anywhere in
//   the persisted JSONL output. Asserted via grep on the JSONL bytes.
// - Path safety: absolute and `..`-escaping paths refused.
// - Tool wrapper exposes role_bundles per O.5 §4 (broad reach).
// - Authority class registered.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  initRepoSession,
  repoCheck,
  REPO_CHECK_MAX_FILE_BYTES,
} = require("../mcp/lib/repo-target.js");
const {
  redactTextSensitiveValues,
  validateNoSensitiveMaterial,
} = require("../mcp/lib/sensitive-material.js");
const {
  repoChecksJsonlPath,
} = require("../mcp/lib/paths.js");
const repoCheckTool = require("../mcp/lib/tools/repo-check.js");
const {
  EXPLICIT_AUTHORITY_CLASS_BY_TOOL,
} = require("../mcp/lib/session-authority.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-repo-check-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function makeTempRepoDir(prefix = "bob-repo-check-fixture-") {
  const raw = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  return fs.realpathSync.native ? fs.realpathSync.native(raw) : fs.realpathSync(raw);
}

function write(repoRoot, rel, content = "") {
  const abs = path.join(repoRoot, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  if (Buffer.isBuffer(content)) {
    fs.writeFileSync(abs, content);
  } else {
    fs.writeFileSync(abs, content, "utf8");
  }
}

function readJsonl(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const raw = fs.readFileSync(filePath, "utf8");
  return raw.split(/\r?\n/).filter((line) => line.trim().length > 0).map((line) => JSON.parse(line));
}

function rawJsonlBytes(filePath) {
  if (!fs.existsSync(filePath)) return "";
  return fs.readFileSync(filePath, "utf8");
}

test("repoCheck file_exists returns matched=true for present file", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "README.md", "# hello\n");
    const init = initRepoSession({ repo_path: repoRoot });

    const result = repoCheck({
      target_domain: init.target_domain,
      check_type: "file_exists",
      file_path: "README.md",
    });
    assert.equal(result.created, true);
    assert.equal(result.matched, true);
    assert.equal(result.not_found, false);
    assert.equal(result.file_path, "README.md");
    assert.match(result.file_hash, /^[0-9a-f]{64}$/);
    assert.equal(result.binary, false);
    assert.match(result.check_id, /^chk_[0-9a-f]{8}_\d+$/);

    const rows = readJsonl(repoChecksJsonlPath(init.target_domain));
    assert.equal(rows.length, 1);
    assert.equal(rows[0].matched, true);
    assert.equal(rows[0].check_type, "file_exists");
    assert.equal(rows[0].file_path, "README.md");
  });
});

test("repoCheck on missing file returns matched=false + not_found:true", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "README.md", "# hello\n");
    const init = initRepoSession({ repo_path: repoRoot });

    const result = repoCheck({
      target_domain: init.target_domain,
      file_path: "does-not-exist.txt",
    });
    assert.equal(result.matched, false);
    assert.equal(result.not_found, true);
    assert.equal(result.file_hash, null);

    const rows = readJsonl(repoChecksJsonlPath(init.target_domain));
    assert.equal(rows.length, 1);
    assert.equal(rows[0].matched, false);
    assert.equal(rows[0].not_found, true);
  });
});

test("repoCheck file_contains literal-substring match writes matched_lines", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "src/util.js", [
      "function helper() {",
      "  return 'TODO_MARKER';",
      "}",
      "// nothing of interest below",
    ].join("\n"));
    const init = initRepoSession({ repo_path: repoRoot });

    const result = repoCheck({
      target_domain: init.target_domain,
      check_type: "file_contains",
      file_path: "src/util.js",
      pattern: "TODO_MARKER",
    });
    assert.equal(result.matched, true);
    assert.equal(result.matched_lines.length, 1);
    assert.equal(result.matched_lines[0].line, 2);
    assert.match(result.matched_lines[0].excerpt, /TODO_MARKER/);
  });
});

test("repoCheck file_contains miss writes matched=false and an empty matched_lines[]", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "src/util.js", "nothing in here\n");
    const init = initRepoSession({ repo_path: repoRoot });

    const result = repoCheck({
      target_domain: init.target_domain,
      check_type: "file_contains",
      file_path: "src/util.js",
      pattern: "TODO_MARKER",
    });
    assert.equal(result.matched, false);
    assert.deepEqual(result.matched_lines, []);
  });
});

test("repoCheck regex_match returns per-line matched_lines with line numbers", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "src/main.c", [
      "#include <stdio.h>",
      "int strcpy_unsafe(char *dst, const char *src) {",
      "  return 0;",
      "}",
      "void another_strcpy_unsafe(void) {}",
    ].join("\n"));
    const init = initRepoSession({ repo_path: repoRoot });

    const result = repoCheck({
      target_domain: init.target_domain,
      check_type: "regex_match",
      file_path: "src/main.c",
      regex: "strcpy_unsafe",
    });
    assert.equal(result.matched, true);
    assert.equal(result.matched_lines.length, 2);
    assert.equal(result.matched_lines[0].line, 2);
    assert.equal(result.matched_lines[1].line, 5);
  });
});

test("repoCheck regex_match accepts /body/flags syntax and forces multi-line", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "src/x.txt", [
      "alpha",
      "BETA",
      "gamma",
    ].join("\n"));
    const init = initRepoSession({ repo_path: repoRoot });

    const result = repoCheck({
      target_domain: init.target_domain,
      check_type: "regex_match",
      file_path: "src/x.txt",
      regex: "/beta/i",
    });
    assert.equal(result.matched, true);
    assert.equal(result.matched_lines.length, 1);
    assert.equal(result.matched_lines[0].line, 2);
  });
});

test("repoCheck against a binary file does not crash and does not excerpt binary bytes", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    const binary = Buffer.concat([
      Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00]),
      Buffer.alloc(512, 0xff),
      Buffer.from([0x00, 0x42, 0x42, 0x42]),
    ]);
    write(repoRoot, "bin/blob.so", binary);
    const init = initRepoSession({ repo_path: repoRoot });

    const result = repoCheck({
      target_domain: init.target_domain,
      check_type: "regex_match",
      file_path: "bin/blob.so",
      regex: ".+",
    });
    // Binary files always report matched=false and binary=true; no excerpts.
    assert.equal(result.matched, false);
    assert.equal(result.binary, true);
    assert.deepEqual(result.matched_lines, []);

    // Belt-and-suspenders: raw binary bytes (the BBB sentinel) MUST NOT
    // appear inside the JSONL row.
    const raw = rawJsonlBytes(repoChecksJsonlPath(init.target_domain));
    assert.doesNotMatch(raw, /BBB/);
  });
});

test("repoCheck enforces the 4 MB read cap with a structured file_too_large error", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    // 5 MB > 4 MB cap. Use sparse fill so the fixture builds quickly.
    const oversizedPath = path.join(repoRoot, "huge.txt");
    fs.mkdirSync(path.dirname(oversizedPath), { recursive: true });
    const fd = fs.openSync(oversizedPath, "w");
    try {
      const oneMb = Buffer.alloc(1024 * 1024, 0x61); // 'a'
      for (let i = 0; i < 5; i++) {
        fs.writeSync(fd, oneMb, 0, oneMb.length, null);
      }
    } finally {
      fs.closeSync(fd);
    }
    const init = initRepoSession({ repo_path: repoRoot });

    assert.throws(
      () => repoCheck({
        target_domain: init.target_domain,
        check_type: "file_exists",
        file_path: "huge.txt",
      }),
      (error) => {
        assert.match(error.message, /file_path exceeds/);
        assert.equal(error.details && error.details.repo_error_code, "file_too_large");
        assert.equal(error.details.limit_bytes, REPO_CHECK_MAX_FILE_BYTES);
        return true;
      },
    );
  });
});

test("repoCheck refuses absolute file_path with structured error (O-P1)", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "README.md", "# hi\n");
    const init = initRepoSession({ repo_path: repoRoot });

    assert.throws(
      () => repoCheck({
        target_domain: init.target_domain,
        check_type: "file_exists",
        file_path: "/etc/shadow",
      }),
      (error) => {
        assert.equal(error.details && error.details.repo_error_code, "file_path_must_be_relative");
        return true;
      },
    );
  });
});

test("repoCheck refuses `..`-escaping file_path with structured error (O-P1)", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "README.md", "# hi\n");
    const init = initRepoSession({ repo_path: repoRoot });

    assert.throws(
      () => repoCheck({
        target_domain: init.target_domain,
        check_type: "file_exists",
        file_path: "../../../etc/shadow",
      }),
      (error) => {
        assert.equal(error.details && error.details.repo_error_code, "file_path_escapes_repo_root");
        return true;
      },
    );
  });
});

test("CRITICAL O-P7 regression: synthetic .env API_KEY value is REDACTED in the persisted JSONL row", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    // Synthetic .env-shaped content. The literal secret bytes MUST NOT
    // survive the redactTextSensitiveValues pass.
    const secretValue = "sk-live-abc123XYZdef";
    const envContent = [
      "# fixture .env (no real keys)",
      "DEBUG=true",
      `API_KEY=${secretValue}`,
      "ANOTHER=harmless",
    ].join("\n");
    write(repoRoot, ".env.fixture", envContent);
    const init = initRepoSession({ repo_path: repoRoot });

    const result = repoCheck({
      target_domain: init.target_domain,
      check_type: "regex_match",
      file_path: ".env.fixture",
      regex: "API_KEY=.*",
    });
    assert.equal(result.matched, true);
    assert.equal(result.matched_lines.length, 1);
    // The excerpt the caller sees in-process is already redacted; the
    // literal secret bytes must not be in the in-process return either.
    assert.doesNotMatch(result.matched_lines[0].excerpt, new RegExp(secretValue));
    assert.match(result.matched_lines[0].excerpt, /REDACTED/);

    // Load-bearing assertion: open the JSONL bytes on disk and grep for
    // the literal secret. The full value MUST NOT appear in any byte of
    // the persisted artifact.
    const rawBytes = rawJsonlBytes(repoChecksJsonlPath(init.target_domain));
    assert.doesNotMatch(rawBytes, new RegExp(secretValue));
    assert.match(rawBytes, /REDACTED/);

    // The structural row metadata must still round-trip through
    // validateNoSensitiveMaterial without raising — matched_lines[].excerpt
    // and the X.7 retrofit's summary.top_3_match_lines[].redacted_excerpt
    // are the redaction-owned fields (assignment-shaped content like
    // `API_KEY=REDACTED` legitimately remains there); the surrounding
    // metadata is what the structural validator covers.
    const rows = readJsonl(repoChecksJsonlPath(init.target_domain));
    for (const row of rows) {
      const probe = {
        ...row,
        matched_lines: (row.matched_lines || []).map(({ line, offset }) => ({ line, offset })),
        summary: row.summary ? {
          ...row.summary,
          top_3_match_lines: row.summary.top_3_match_lines.map(({ line_num, excerpt_hash }) => ({ line_num, excerpt_hash })),
        } : row.summary,
      };
      validateNoSensitiveMaterial(probe, "repo_checks");
    }
  });
});

test("CRITICAL O-P7 regression: Authorization-bearer-shaped excerpt is redacted before append", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    const bearer = "eyJabcdefghij.eyJklmnopqrst.uvwxyz0123";
    const content = `Authorization: Bearer ${bearer}\nother line\n`;
    write(repoRoot, "config/headers.txt", content);
    const init = initRepoSession({ repo_path: repoRoot });

    const result = repoCheck({
      target_domain: init.target_domain,
      check_type: "regex_match",
      file_path: "config/headers.txt",
      regex: "Authorization",
    });
    assert.equal(result.matched, true);
    assert.equal(result.matched_lines.length, 1);
    assert.doesNotMatch(result.matched_lines[0].excerpt, new RegExp(bearer));

    const rawBytes = rawJsonlBytes(repoChecksJsonlPath(init.target_domain));
    assert.doesNotMatch(rawBytes, new RegExp(bearer));
  });
});

test("repoCheck refuses unknown check_type", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "x.txt", "x");
    const init = initRepoSession({ repo_path: repoRoot });

    assert.throws(
      () => repoCheck({
        target_domain: init.target_domain,
        check_type: "not_a_real_check",
        file_path: "x.txt",
      }),
      (error) => {
        assert.equal(error.details && error.details.repo_error_code, "check_type_invalid");
        return true;
      },
    );
  });
});

test("repoCheck infers check_type from pattern/regex when omitted", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "x.txt", "alpha\nBETA\n");
    const init = initRepoSession({ repo_path: repoRoot });

    const regexResult = repoCheck({
      target_domain: init.target_domain,
      file_path: "x.txt",
      regex: "BETA",
    });
    assert.equal(regexResult.check_type, "regex_match");
    assert.equal(regexResult.matched, true);

    const containsResult = repoCheck({
      target_domain: init.target_domain,
      file_path: "x.txt",
      pattern: "alpha",
    });
    assert.equal(containsResult.check_type, "file_contains");
    assert.equal(containsResult.matched, true);

    const existsResult = repoCheck({
      target_domain: init.target_domain,
      file_path: "x.txt",
    });
    assert.equal(existsResult.check_type, "file_exists");
    assert.equal(existsResult.matched, true);
  });
});

test("repoCheck accepts and persists replay_context for evaluator correlation", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "x.txt", "x");
    const init = initRepoSession({ repo_path: repoRoot });

    const result = repoCheck({
      target_domain: init.target_domain,
      file_path: "x.txt",
      replay_context: {
        wave: "W1",
        agent: "evaluator-web-agent",
        surface_id: "endpoint:GET:/api/v1/users",
        purpose: "validate dependency manifest exists",
      },
    });
    assert.equal(result.matched, true);

    const rows = readJsonl(repoChecksJsonlPath(init.target_domain));
    assert.equal(rows.length, 1);
    assert.equal(rows[0].replay_context.wave, "W1");
    assert.equal(rows[0].replay_context.agent, "evaluator-web-agent");
    assert.equal(rows[0].replay_context.surface_id, "endpoint:GET:/api/v1/users");
  });
});

test("bob_repo_check tool handler returns a JSON envelope and persists a row", () => {
  withTempHome(() => {
    const repoRoot = makeTempRepoDir();
    write(repoRoot, "README.md", "# fixture\n");
    const init = initRepoSession({ repo_path: repoRoot });

    const payload = JSON.parse(repoCheckTool.handler({
      target_domain: init.target_domain,
      check_type: "file_exists",
      file_path: "README.md",
    }));
    assert.equal(payload.version, 1);
    assert.equal(payload.created, true);
    assert.equal(payload.matched, true);
    assert.match(payload.file_hash, /^[0-9a-f]{64}$/);

    const rows = readJsonl(repoChecksJsonlPath(init.target_domain));
    assert.equal(rows.length, 1);
  });
});

test("bob_repo_check tool descriptor exposes the O.5 broad role-bundle reach and writes only repo-checks.jsonl", () => {
  assert.deepEqual(
    [...repoCheckTool.role_bundles].sort(),
    ["evaluator-shared", "verifier", "evidence", "grader", "reporter"].sort(),
  );
  assert.equal(repoCheckTool.network_access, false);
  assert.equal(repoCheckTool.browser_access, false);
  assert.equal(repoCheckTool.scope_required, false);
  assert.equal(repoCheckTool.mutating, true);
  assert.deepEqual([...repoCheckTool.session_artifacts_written], ["repo-checks.jsonl"]);
});

test("bob_repo_check authority class is registered as initialized_session_mutation", () => {
  assert.equal(EXPLICIT_AUTHORITY_CLASS_BY_TOOL.bob_repo_check, "initialized_session_mutation");
});

test("redactTextSensitiveValues is exported from sensitive-material.js (Plane O O.5 import contract)", () => {
  // The spec is explicit: every matched_lines[].excerpt MUST go through
  // redactTextSensitiveValues from mcp/lib/sensitive-material.js. This
  // assertion locks the import-site contract so a future refactor that
  // moves the symbol elsewhere breaks compile-time.
  assert.equal(typeof redactTextSensitiveValues, "function");
  const before = "API_KEY=sk-live-abc123XYZdef";
  const after = redactTextSensitiveValues(before);
  assert.doesNotMatch(after, /sk-live-abc123XYZdef/);
  assert.match(after, /REDACTED/);
});
