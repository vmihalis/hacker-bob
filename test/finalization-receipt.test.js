"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  normalizeFinalizationReceipt,
  readFinalizationReceipt,
  writeFinalizationReceipt,
} = require("../mcp/lib/finalization-receipt.js");
const {
  WRITE_GUARD_TABLES,
  finalizationReceiptPath,
  finalizationReceiptSidecarPath,
  isAuditGradedPath,
  sessionDir,
} = require("../mcp/lib/paths.js");

const DOMAIN = "receipt.example.com";
const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);
const HASH_C = "c".repeat(64);
const HASH_D = "d".repeat(64);
const HASH_E = "e".repeat(64);

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-finalization-receipt-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function receipt(overrides = {}) {
  return {
    schemaVersion: 1,
    runSlug: "run-receipt",
    targetDomain: DOMAIN,
    reportSlug: "run-receipt-report",
    completedAt: "2026-08-25T10:00:00.000Z",
    freezeHash: HASH_A,
    snapshotHash: HASH_B,
    evidenceHash: HASH_C,
    reportContentHash: HASH_E,
    artifact: {
      emitted: true,
      sha256: HASH_D,
      findingCount: 1,
    },
    projection: {
      required: true,
      succeeded: true,
      duplicate: false,
      projected: 1,
      reopened: 0,
      closed: 0,
    },
    consoleReport: {
      schemaVersion: 1,
      domain: DOMAIN,
      findings: [{
        fingerprint: HASH_A,
        fingerprintVersion: 1,
        refId: "F-1",
        dedupeKey: "e".repeat(24),
        title: "Missing Authorization — Web",
        plainRead: "Web finding classified as CWE-862: Missing Authorization.",
        severity: "high",
        disposition: "fix-now",
        reproduced: true,
        reachable: true,
        reportable: true,
        score: 60,
        scoreAxes: {
          impact: 20,
          proof: 20,
          severityAccuracy: 10,
          chain: 5,
          report: 5,
        },
        cwe: [{ id: "CWE-862", name: "Missing Authorization" }],
        surfaceType: "web",
        endpoint: "receipt.example.com/admin/{param}?tenant=*",
        evidenceHash: HASH_C,
        snapshotHash: HASH_B,
        open: true,
      }],
    },
    ...overrides,
  };
}

test("finalization receipt writes an exclusive atomic pair and replays identically", () => {
  withTempHome(() => {
    const first = writeFinalizationReceipt(DOMAIN, receipt());
    assert.equal(first.written, true);
    assert.match(first.sha256, /^[0-9a-f]{64}$/);
    assert.equal(fs.existsSync(finalizationReceiptPath(DOMAIN)), true);
    assert.equal(fs.existsSync(finalizationReceiptSidecarPath(DOMAIN)), true);

    const loaded = readFinalizationReceipt(DOMAIN);
    assert.deepEqual(loaded.receipt, first.receipt);
    assert.equal(loaded.sha256, first.sha256);

    const replay = writeFinalizationReceipt(DOMAIN, receipt());
    assert.equal(replay.written, false);
    assert.deepEqual(replay.receipt, first.receipt);
    assert.deepEqual(
      fs.readdirSync(sessionDir(DOMAIN)).filter((name) => name.endsWith(".tmp")),
      [],
    );
  });
});

test("finalization receipt never overwrites a conflicting completion", () => {
  withTempHome(() => {
    writeFinalizationReceipt(DOMAIN, receipt());
    assert.throws(
      () => writeFinalizationReceipt(DOMAIN, receipt({ reportSlug: "different-report" })),
      /completed finalization receipt conflicts/,
    );
    assert.equal(readFinalizationReceipt(DOMAIN).receipt.reportSlug, "run-receipt-report");
  });
});

test("finalization receipt read rejects digest tampering and partial pairs", () => {
  withTempHome(() => {
    writeFinalizationReceipt(DOMAIN, receipt());
    fs.appendFileSync(finalizationReceiptPath(DOMAIN), " ");
    assert.throws(
      () => readFinalizationReceipt(DOMAIN),
      /sidecar digest does not match/,
    );
  });

  withTempHome(() => {
    fs.mkdirSync(sessionDir(DOMAIN), { recursive: true });
    fs.writeFileSync(finalizationReceiptPath(DOMAIN), JSON.stringify(receipt()));
    assert.throws(
      () => readFinalizationReceipt(DOMAIN),
      /must either both exist or both be absent/,
    );
    assert.equal(readFinalizationReceipt(DOMAIN, { required: false }), null);
    const recovered = writeFinalizationReceipt(DOMAIN, receipt());
    assert.equal(recovered.written, true);
    assert.deepEqual(readFinalizationReceipt(DOMAIN).receipt, recovered.receipt);
  });
});

test("receipt shape is exact and supports an honest clean local completion", () => {
  const normalized = normalizeFinalizationReceipt(receipt({
    artifact: {
      emitted: false,
      sha256: null,
      findingCount: 0,
    },
    projection: {
      required: false,
      succeeded: false,
      duplicate: false,
      projected: 0,
      reopened: 0,
      closed: 0,
    },
    consoleReport: {
      schemaVersion: 1,
      domain: DOMAIN,
      findings: [],
    },
  }));
  assert.deepEqual(Object.keys(normalized), [
    "schemaVersion",
    "runSlug",
    "targetDomain",
    "reportSlug",
    "completedAt",
    "freezeHash",
    "snapshotHash",
    "evidenceHash",
    "reportContentHash",
    "artifact",
    "projection",
    "consoleReport",
  ]);
  assert.deepEqual(normalized.artifact, {
    emitted: false,
    sha256: null,
    findingCount: 0,
  });
  assert.deepEqual(normalized.consoleReport.findings, []);
});

test("receipt admits the bounded smart-contract browser shape", () => {
  const value = receipt();
  const webFinding = value.consoleReport.findings[0];
  value.consoleReport.findings = [{
    ...webFinding,
    surfaceType: "smart_contract",
    endpoint: undefined,
    chainFamily: "evm",
    scEvidence: {
      chainId: "1",
      contractIdentity: `0x${"f".repeat(40)}`,
      functionSignature: "withdraw(uint256)",
    },
  }];
  const normalized = normalizeFinalizationReceipt(value);
  assert.deepEqual(normalized.consoleReport.findings[0].scEvidence, {
    chainId: "1",
    contractIdentity: `0x${"f".repeat(40)}`,
    functionSignature: "withdraw(uint256)",
  });
  assert.equal(
    Object.prototype.hasOwnProperty.call(normalized.consoleReport.findings[0], "endpoint"),
    false,
  );
});

test("receipt rejects extra fields and unsafe browser content", () => {
  const withProjectionKey = receipt({ projectionKey: "must-not-ship" });
  assert.throws(
    () => normalizeFinalizationReceipt(withProjectionKey),
    /unsupported field: projectionKey/,
  );

  const unsafeRows = [
    {
      label: "remediation",
      mutate: (finding) => ({ ...finding, remediation: "raw fix steps" }),
      expected: /unsupported field: remediation/,
    },
    {
      label: "script title",
      mutate: (finding) => ({ ...finding, title: "<script>alert(1)</script>" }),
      expected: /must not contain markup delimiters/,
    },
    {
      label: "concrete query value",
      mutate: (finding) => ({ ...finding, endpoint: "receipt.example.com/admin?token=secret" }),
      expected: /query values must use key=\* placeholders/,
    },
    {
      label: "URI credentials",
      mutate: (finding) => ({ ...finding, endpoint: "https://user:pass@receipt.example.com/admin" }),
      expected: /must not contain URI userinfo/,
    },
  ];
  for (const { label, mutate, expected } of unsafeRows) {
    const value = receipt();
    value.consoleReport.findings = [mutate(value.consoleReport.findings[0])];
    assert.throws(
      () => normalizeFinalizationReceipt(value),
      expected,
      label,
    );
  }

  const wrongDomain = receipt();
  wrongDomain.consoleReport.domain = "forged.example.com";
  assert.throws(
    () => normalizeFinalizationReceipt(wrongDomain),
    /consoleReport.domain must equal targetDomain/,
  );
});

test("receipt paths are audit-graded and agent-write blocked", () => {
  for (const basename of ["finalization-receipt.json", "finalization-receipt.sha256"]) {
    assert.equal(WRITE_GUARD_TABLES.audit_graded_basenames.includes(basename), true);
    assert.equal(WRITE_GUARD_TABLES.agent_writable_basenames.includes(basename), false);
  }
  assert.equal(isAuditGradedPath(finalizationReceiptPath(DOMAIN), DOMAIN), true);
  assert.equal(isAuditGradedPath(finalizationReceiptSidecarPath(DOMAIN), DOMAIN), true);
});
