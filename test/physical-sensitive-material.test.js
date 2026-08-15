"use strict";

const assert = require("node:assert/strict");
const childProcess = require("node:child_process");
const test = require("node:test");

const {
  PHYSICAL_BINARY_REDACTED_VALUE,
  PHYSICAL_REDACTED_VALUE,
  assertPackageSafePhysicalDesignDocument,
  budgetPhysicalPublicOutput,
  containsPhysicalSensitiveText,
  isPhysicalSensitiveField,
  redactPhysicalSensitiveValues,
  redactPhysicalStructuredOutput,
  validateNoPhysicalSensitiveMaterial,
} = require("../mcp/lib/physical-sensitive-material.js");
const {
  redactTextSensitiveValues,
} = require("../mcp/core/redaction/sensitive-material.js");
const {
  safeErrorMessage,
} = require("../mcp/core/telemetry/tool-telemetry.js");

test("physical field classifier distinguishes raw values from opaque metadata", () => {
  for (const field of [
    "card_uid",
    "credential_dump",
    "rf_trace",
    "apdu_response",
    "track2",
    "device_serial",
    "device_path",
    "artifact_path",
    "command_bytes",
    "cardUID",
    "ATQA",
    "cctvFrame",
    "accessLog",
    "bleAddress",
  ]) {
    assert.equal(isPhysicalSensitiveField(field), true, field);
  }
  for (const field of [
    "card_uid_digest",
    "credential_handle",
    "rf_trace_ref",
    "apdu_response_digest",
    "device_identity_hash",
    "artifact_ref",
    "command_byte_length",
    "credential_type",
    "cardUIDDigest",
    "cctvFrameRef",
  ]) {
    assert.equal(isPhysicalSensitiveField(field), false, field);
  }
});

test("physical structured validator accepts only handle/digest projections", () => {
  const safe = {
    credential_handle: "artifact:fixture-secret-handle",
    card_uid_digest: "a".repeat(64),
    rf_trace_ref: "artifact:fixture-rf-trace",
    device_identity_hash: "b".repeat(64),
    operation: "credential.observe",
  };
  assert.doesNotThrow(() => validateNoPhysicalSensitiveMaterial(safe, "result"));
  assert.doesNotThrow(() => validateNoPhysicalSensitiveMaterial({
    card_uid: PHYSICAL_REDACTED_VALUE,
  }, "redacted_result"));

  for (const value of [
    { card_uid: "04:A1:B2:C3:D4:E5:F6" },
    { credential_dump: "00112233445566778899aabbccddeeff" },
    { apdu_response: "9000" },
    { track2: ";4111111111111111=29011234567890000000?" },
    { device_path: "/dev/cu.usbmodem-fixture" },
    { nested: { note: "sector key A: a0a1a2a3a4a5" } },
    Buffer.from([0x01, 0x02, 0x03]),
    { uid: "04A1B2C3D4E5F6" },
    { atqa: "0400" },
    { cctvFrame: "base64-fixture" },
    { accessLog: [{ door: "fixture" }] },
  ]) {
    assert.throws(
      () => validateNoPhysicalSensitiveMaterial(value, "result"),
      (error) => error && error.code === "physical_sensitive_material_rejected",
    );
  }
});

test("physical validation and sanitization never execute getters or proxies", () => {
  let getterRuns = 0;
  const hostile = {};
  Object.defineProperty(hostile, "card_uid", {
    enumerable: true,
    get() {
      getterRuns += 1;
      return "04A1B2C3";
    },
  });
  assert.throws(() => validateNoPhysicalSensitiveMaterial(hostile));
  assert.throws(() => redactPhysicalStructuredOutput(hostile));
  assert.equal(getterRuns, 0);

  const proxy = new Proxy({ credential_handle: "artifact:fixture" }, {});
  assert.throws(() => validateNoPhysicalSensitiveMaterial(proxy));
  assert.throws(() => redactPhysicalStructuredOutput(proxy));
  for (const invalid of [undefined, 1n, Symbol("physical"), () => {}, NaN, Infinity]) {
    assert.throws(() => validateNoPhysicalSensitiveMaterial(invalid));
    assert.throws(() => redactPhysicalStructuredOutput(invalid));
  }
});

test("structured sanitization bypasses inherited array-index setters", () => {
  const modulePath = require.resolve("../mcp/lib/physical-sensitive-material.js");
  const script = String.raw`
    const physical = require(${JSON.stringify(modulePath)});
    const input = Array.from({ length: 401 }, (_, index) => String(index));
    let substitutions = 0;
    Object.defineProperty(Array.prototype, "400", {
      configurable: true,
      set() { substitutions += 1; },
    });
    try {
      const output = physical.redactPhysicalStructuredOutput(input);
      if (substitutions !== 0 || !Object.hasOwn(output, "400") || output[400] !== "400") {
        process.exitCode = 2;
      }
    } finally {
      delete Array.prototype[400];
    }
  `;
  childProcess.execFileSync(process.execPath, ["-e", script], {
    stdio: "pipe",
    timeout: 5000,
  });
});

test("physical text redaction removes labeled reusable material and local paths", () => {
  const input = [
    "card UID: 04:A1:B2:C3:D4:E5:F6",
    "sector key A=a0a1a2a3a4a5",
    "APDU response: 112233449000",
    "track2: ;4111111111111111=29011234567890000000?",
    "device path=/dev/cu.usbmodem-fixture",
    "artifact path=/Users/fixture/private/session/dump.bin",
    "capture path=/tmp/physical-fixture/trace.bin",
  ].join("\n");
  assert.equal(containsPhysicalSensitiveText(input), true);
  const redacted = redactPhysicalSensitiveValues(input);
  for (const forbidden of [
    "04:A1:B2:C3:D4:E5:F6",
    "a0a1a2a3a4a5",
    "112233449000",
    "4111111111111111",
    "/dev/cu.usbmodem-fixture",
    "/Users/fixture/private/session/dump.bin",
    "/tmp/physical-fixture/trace.bin",
  ]) {
    assert.equal(redacted.includes(forbidden), false, forbidden);
  }
  assert.match(redacted, /physical-sensitive-redacted/);
});

test("shared redaction and telemetry error projection apply physical masking", () => {
  const raw = [
    "card UID=04A1B2C3D4E5F6",
    "device path=/dev/cu.usbmodem-fixture",
    "cctvFrame=encoded-private-fixture",
    "BLE address=AA:BB:CC:DD:EE:FF",
  ].join("\n");
  const shared = redactTextSensitiveValues(raw);
  const telemetry = safeErrorMessage(raw);
  assert.equal(shared.includes("04A1B2C3D4E5F6"), false);
  assert.equal(shared.includes("/dev/cu.usbmodem-fixture"), false);
  assert.equal(telemetry.includes("04A1B2C3D4E5F6"), false);
  assert.equal(telemetry.includes("/dev/cu.usbmodem-fixture"), false);
  assert.equal(telemetry.includes("encoded-private-fixture"), false);
  assert.equal(telemetry.includes("AA:BB:CC:DD:EE:FF"), false);
});

test("structured sanitizer masks sensitive leaves while retaining safe evidence refs", () => {
  const sanitized = redactPhysicalStructuredOutput({
    credential_handle: "artifact:fixture-opaque",
    card_uid_digest: "c".repeat(64),
    card_uid: "04A1B2C3D4E5F6",
    raw_capture: Uint8Array.from([1, 2, 3]),
    notes: ["tag UID: 11223344", "bounded observation"],
  });
  assert.equal(sanitized.credential_handle, "artifact:fixture-opaque");
  assert.equal(sanitized.card_uid_digest, "c".repeat(64));
  assert.equal(sanitized.card_uid, PHYSICAL_REDACTED_VALUE);
  assert.equal(sanitized.raw_capture, PHYSICAL_REDACTED_VALUE);
  assert.equal(sanitized.notes[0].includes("11223344"), false);
  assert.equal(sanitized.notes[1], "bounded observation");
  assert.equal(Object.isFrozen(sanitized.notes), true);

  assert.equal(
    redactPhysicalStructuredOutput(Uint8Array.from([4, 5, 6])),
    PHYSICAL_BINARY_REDACTED_VALUE,
  );
});

test("package-safe design sanitizer permits typed schemes but rejects live overlays", () => {
  const safe = assertPackageSafePhysicalDesignDocument({
    dependency: "vault_tool:classic_trace_recovery_v1",
    proof_type: "bob-proof:vault-transform:v1",
    engineering_evidence_refs: [],
    hil_evidence_refs: [],
    hil_waiver_ref: null,
    anchors: ["mcp/lib/physical-sensitive-material.js"],
  });
  assert.equal(safe.dependency, "vault_tool:classic_trace_recovery_v1");

  for (const unsafe of [
    { engineering_evidence_refs: ["gate-evidence:v1:abcdefghijklmnop"] },
    { hil_evidence_refs: ["hil-evidence:v1:abcdefghijklmnop"] },
    { hil_waiver_ref: "hil-waiver:v1:abcdefghijklmnop" },
    { artifact: "artifact:v1:abcdefghijklmnop" },
    { path: "/Users/operator/session/evidence.json" },
    { device_path: "/dev/cu.usbmodem-fixture" },
  ]) {
    assert.throws(
      () => assertPackageSafePhysicalDesignDocument(unsafe),
      (error) => error && error.code === "physical_sensitive_material_rejected",
    );
  }
});

test("telemetry, brief, and report budgets are deterministic, bounded, and redacted", () => {
  const input = {
    card_uid: "04A1B2C3D4E5F6",
    credential_handle: "artifact:fixture-opaque",
    note: `tag UID: 11223344 ${"x".repeat(400)}`,
    details: "x".repeat(400),
    rows: Array.from({ length: 40 }, (_, index) => ({
      index,
      evidence_ref: `evidence:fixture-${index}`,
    })),
  };
  const first = budgetPhysicalPublicOutput(input, "telemetry");
  const second = budgetPhysicalPublicOutput(input, "telemetry");
  assert.deepEqual(second, first);
  assert.equal(first.data.card_uid, PHYSICAL_REDACTED_VALUE);
  assert.equal(first.data.credential_handle, "artifact:fixture-opaque");
  assert.equal(JSON.stringify(first).includes("04A1B2C3D4E5F6"), false);
  assert.equal(JSON.stringify(first).includes("11223344"), false);
  assert.equal(first.data.rows.length, 24);
  assert.equal(first.budget.truncated, true);
  assert.equal(first.budget.omitted_items, 16);
  assert.equal(first.budget.truncated_strings, 1);
  assert.equal(first.data.details.length, first.budget.max_text_chars);
  assert.ok(first.budget.emitted_data_bytes <= first.budget.max_total_bytes);
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.data), true);

  const report = budgetPhysicalPublicOutput({ note: "bounded" }, "report");
  assert.equal(report.budget.truncated, false);
  assert.equal(report.data.note, "bounded");
  assert.throws(() => budgetPhysicalPublicOutput({}, "unknown"));
});
