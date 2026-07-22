"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const clock = require("../lib/source-contract.js");

const ROOT = path.resolve(__dirname, "..");
const HEX = Object.freeze({
  service_requirement: "11".repeat(32),
  client_requirement: "22".repeat(32),
  service_identity: "33".repeat(32),
  client_identity: "44".repeat(32),
  release_manifest: "55".repeat(32),
  native_attestation: "66".repeat(32),
  principal_policy: "77".repeat(32),
  trust_root: "88".repeat(32),
  epoch_a: "99".repeat(32),
  epoch_b: "aa".repeat(32),
});

function enrollmentInput(overrides = {}) {
  return {
    service_uid: 451,
    service_gid: 451,
    client_uid: 502,
    client_gid: 20,
    service_requirement_digest: HEX.service_requirement,
    client_requirement_digest: HEX.client_requirement,
    service_identity_digest: HEX.service_identity,
    client_identity_digest: HEX.client_identity,
    native_release_manifest_digest: HEX.release_manifest,
    native_attestation_digest: HEX.native_attestation,
    principal_policy_digest: HEX.principal_policy,
    trust_root_digest: HEX.trust_root,
    ...overrides,
  };
}

function createEnrollment() {
  return clock.createDarwinTrustedClockConformanceEnrollment(enrollmentInput());
}

function makeResponseFrame(enrollment, challenge, options = {}) {
  const fields = {
    request_id: options.request_id || challenge.request_id,
    challenge_digest: options.challenge_digest || challenge.challenge_digest,
    monotonic_ns: options.monotonic_ns || "1000000000",
    boot_epoch_digest: options.boot_epoch_digest || HEX.epoch_a,
    service_identity_digest:
      options.service_identity_digest || enrollment.service_identity_digest,
    client_identity_digest:
      options.client_identity_digest || enrollment.client_identity_digest,
    enrollment_digest: options.enrollment_digest || enrollment.enrollment_digest,
  };
  const digest = options.source_sample_digest
    || clock.computeDarwinTrustedClockSourceSampleDigest(fields);
  const frame = Buffer.alloc(clock.RESPONSE_FRAME_BYTES);
  Buffer.from([0x48, 0x42, 0x43, 0x4c, 0x4b, 0x31, 0x52, 0x00]).copy(frame, 0);
  frame.writeUInt16BE(1, 8);
  frame.writeUInt16BE(2, 10);
  frame.writeUInt32BE(clock.RESPONSE_FRAME_BYTES, 12);
  Buffer.from(fields.request_id, "hex").copy(frame, 16);
  Buffer.from(fields.challenge_digest, "hex").copy(frame, 32);
  frame.writeBigUInt64BE(BigInt(fields.monotonic_ns), 64);
  Buffer.from(fields.boot_epoch_digest, "hex").copy(frame, 72);
  Buffer.from(fields.service_identity_digest, "hex").copy(frame, 104);
  Buffer.from(fields.client_identity_digest, "hex").copy(frame, 136);
  Buffer.from(fields.enrollment_digest, "hex").copy(frame, 168);
  Buffer.from(digest, "hex").copy(frame, 200);
  return frame;
}

function reason(error, reasonCode) {
  return error?.code === "darwin_trusted_clock_source_rejected"
    && error?.reason_code === reasonCode;
}

test("contract fixes daemon/client/endpoint and rejects caller-selected surfaces", () => {
  const enrollment = createEnrollment();
  assert.equal(enrollment.service_id, "io.hacker-bob.physical.trusted-clockd");
  assert.equal(enrollment.client_id, "io.hacker-bob.physical.trusted-clock-client");
  assert.equal(enrollment.service_principal, "_hackerbobclock");
  assert.equal(
    enrollment.socket_path,
    "/private/var/run/hacker-bob/physical-trusted-clock-v1.sock",
  );
  assert.equal(enrollment.monotonic_primitive, "mach_continuous_time_v1");
  assert.equal(
    enrollment.boot_epoch_scheme,
    "sha256_double_read_kern_bootsessionuuid_v1",
  );
  assert.equal(enrollment.request_frame_bytes, 64);
  assert.equal(enrollment.response_frame_bytes, 232);
  assert.equal(enrollment.max_samples_per_connection, 1);
  assert.equal(enrollment.production_ready, false);
  assert.equal(enrollment.native_attested, false);
  assert.equal(enrollment.provisioning_verified, false);
  assert.equal(enrollment.hil_verified, false);
  assert.ok(Object.isFrozen(enrollment));
  assert.equal(
    clock.assertDarwinTrustedClockConformanceEnrollment(enrollment),
    enrollment,
  );

  for (const injected of [
    { socket_path: "/tmp/fake.sock" },
    { read_monotonic_ns: () => 1n },
    { invoke_native: () => ({}) },
    { production_ready: true },
    { readiness_override: true },
  ]) {
    assert.throws(
      () => clock.createDarwinTrustedClockConformanceEnrollment({
        ...enrollmentInput(),
        ...injected,
      }),
      (error) => reason(error, "enrollment_shape_invalid"),
    );
  }
  assert.throws(
    () => clock.createDarwinTrustedClockConformanceEnrollment(
      enrollmentInput({ service_uid: 502 }),
    ),
    (error) => reason(error, "dedicated_service_uid_required"),
  );
  assert.throws(
    () => clock.createDarwinTrustedClockConformanceEnrollment(
      enrollmentInput({ service_gid: 20 }),
    ),
    (error) => reason(error, "dedicated_service_gid_required"),
  );
  assert.throws(
    () => clock.createDarwinTrustedClockConformanceEnrollment(
      enrollmentInput({ client_identity_digest: HEX.service_identity }),
    ),
    (error) => reason(error, "service_client_identity_must_be_distinct"),
  );
  const accessorInput = enrollmentInput();
  Object.defineProperty(accessorInput, "service_uid", {
    get() { return 451; },
    enumerable: true,
  });
  assert.throws(
    () => clock.createDarwinTrustedClockConformanceEnrollment(accessorInput),
    (error) => reason(error, "enrollment_shape_invalid"),
  );
  assert.throws(
    () => clock.createDarwinTrustedClockConformanceEnrollment(
      new Proxy(enrollmentInput(), {}),
    ),
    (error) => reason(error, "enrollment_shape_invalid"),
  );
});

test("zero-argument challenge is bounded and one-at-a-time", () => {
  const enrollment = createEnrollment();
  const verifier = clock.createDarwinTrustedClockSourceConformanceVerifier(enrollment);
  assert.equal(
    clock.assertDarwinTrustedClockSourceConformanceVerifier(verifier),
    verifier,
  );
  assert.equal(verifier.production_ready, false);
  assert.equal(verifier.native_attested, false);
  assert.throws(
    () => verifier.issueChallenge("caller-nonce"),
    (error) => reason(error, "challenge_argument_injection"),
  );
  const challenge = verifier.issueChallenge();
  assert.throws(
    () => verifier.issueChallenge(),
    (error) => reason(error, "one_outstanding_challenge_required"),
  );
  assert.throws(
    () => challenge.requestFrame("/tmp/socket"),
    (error) => reason(error, "request_frame_argument_injection"),
  );
  const frame = challenge.requestFrame();
  assert.equal(frame.length, clock.REQUEST_FRAME_BYTES);
  assert.deepEqual(
    [...frame.subarray(0, 8)],
    [0x48, 0x42, 0x43, 0x4c, 0x4b, 0x31, 0x00, 0x00],
  );
  assert.equal(frame.readUInt16BE(8), 1);
  assert.equal(frame.readUInt16BE(10), 1);
  assert.equal(frame.readUInt32BE(12), 64);
  assert.equal(frame.subarray(16, 32).toString("hex"), challenge.request_id);
  assert.notEqual(frame.subarray(32).toString("hex"), "00".repeat(32));
  frame.fill(0);
  assert.notEqual(challenge.requestFrame().subarray(0, 8).toString("hex"), "00".repeat(8));
});

test("valid response yields only a branded non-authorizing in-memory sample", () => {
  const enrollment = createEnrollment();
  const verifier = clock.createDarwinTrustedClockSourceConformanceVerifier(enrollment);
  const challenge = verifier.issueChallenge();
  const sample = verifier.verifyResponse(
    challenge,
    makeResponseFrame(enrollment, challenge),
  );
  assert.equal(clock.assertDarwinTrustedClockSourceSample(sample), sample);
  assert.equal(sample.source, "mach_continuous_time_v1");
  assert.equal(sample.monotonic_ns, "1000000000");
  assert.equal(sample.monotonic_epoch_id, HEX.epoch_a);
  assert.equal(sample.production_ready, false);
  assert.equal(sample.native_attested, false);
  assert.equal(sample.provisioning_verified, false);
  assert.equal(sample.hil_verified, false);
  assert.equal(
    sample.blocker_code,
    "signed_immutable_trusted_clock_native_attestation_and_provisioning_missing",
  );
  assert.throws(
    () => JSON.stringify(sample),
    (error) => reason(error, "trusted_clock_capability_not_serializable"),
  );
  assert.throws(
    () => JSON.stringify(verifier),
    (error) => reason(error, "trusted_clock_capability_not_serializable"),
  );
  assert.throws(
    () => JSON.stringify(challenge),
    (error) => reason(error, "trusted_clock_capability_not_serializable"),
  );
  assert.throws(
    () => structuredClone(sample),
    (error) => error?.name === "DataCloneError",
  );
  assert.throws(
    () => clock.assertDarwinTrustedClockSourceSample({ ...sample }),
    (error) => reason(error, "source_sample_brand_invalid"),
  );
  assert.throws(
    () => challenge.requestFrame(),
    (error) => reason(error, "challenge_consumed_or_crosswired"),
  );
});

test("closed frames reject truncation, extension, header drift and digest tamper", () => {
  const invalidFrames = [
    (frame) => frame.subarray(0, frame.length - 1),
    (frame) => Buffer.concat([frame, Buffer.from([0])]),
    (frame) => { frame[0] ^= 0xff; return frame; },
    (frame) => { frame.writeUInt16BE(3, 10); return frame; },
    (frame) => { frame.writeUInt32BE(231, 12); return frame; },
    (frame) => { frame[200] ^= 0xff; return frame; },
  ];
  for (const mutate of invalidFrames) {
    const enrollment = createEnrollment();
    const verifier = clock.createDarwinTrustedClockSourceConformanceVerifier(enrollment);
    const challenge = verifier.issueChallenge();
    const frame = mutate(makeResponseFrame(enrollment, challenge));
    assert.throws(
      () => verifier.verifyResponse(challenge, frame),
      (error) => error?.code === "darwin_trusted_clock_source_rejected",
    );
    assert.throws(
      () => verifier.verifyResponse(challenge, frame),
      (error) => reason(error, "challenge_consumed_or_crosswired"),
    );
  }
});

test("response rejects shared backing and captured Buffer intrinsics resist drift", () => {
  const enrollment = createEnrollment();
  let verifier = clock.createDarwinTrustedClockSourceConformanceVerifier(enrollment);
  let challenge = verifier.issueChallenge();
  const ordinary = makeResponseFrame(enrollment, challenge);
  const shared = Buffer.from(new SharedArrayBuffer(clock.RESPONSE_FRAME_BYTES));
  ordinary.copy(shared);
  assert.throws(
    () => verifier.verifyResponse(challenge, shared),
    (error) => reason(error, "response_frame_shared_backing_invalid"),
  );

  verifier = clock.createDarwinTrustedClockSourceConformanceVerifier(enrollment);
  const originalCopy = Buffer.prototype.copy;
  const originalToString = Buffer.prototype.toString;
  try {
    Buffer.prototype.copy = () => { throw new Error("prototype drift"); };
    Buffer.prototype.toString = () => { throw new Error("prototype drift"); };
    challenge = verifier.issueChallenge();
    assert.equal(challenge.requestFrame().length, clock.REQUEST_FRAME_BYTES);
  } finally {
    Buffer.prototype.copy = originalCopy;
    Buffer.prototype.toString = originalToString;
  }
  const response = makeResponseFrame(enrollment, challenge);
  let sample;
  try {
    Buffer.prototype.copy = () => { throw new Error("prototype drift"); };
    Buffer.prototype.toString = () => { throw new Error("prototype drift"); };
    sample = verifier.verifyResponse(challenge, response);
  } finally {
    Buffer.prototype.copy = originalCopy;
    Buffer.prototype.toString = originalToString;
  }
  assert.equal(clock.assertDarwinTrustedClockSourceSample(sample), sample);
});

test("challenge replay, verifier cross-wire and identity drift fail closed", () => {
  const enrollment = createEnrollment();
  const first = clock.createDarwinTrustedClockSourceConformanceVerifier(enrollment);
  const second = clock.createDarwinTrustedClockSourceConformanceVerifier(enrollment);
  const crosswired = first.issueChallenge();
  assert.throws(
    () => second.verifyResponse(crosswired, makeResponseFrame(enrollment, crosswired)),
    (error) => reason(error, "challenge_consumed_or_crosswired"),
  );
  first.verifyResponse(crosswired, makeResponseFrame(enrollment, crosswired));
  assert.throws(
    () => first.verifyResponse(crosswired, makeResponseFrame(enrollment, crosswired)),
    (error) => reason(error, "challenge_consumed_or_crosswired"),
  );

  for (const options of [
    { request_id: "ab".repeat(16) },
    { challenge_digest: "bc".repeat(32) },
    { service_identity_digest: "cd".repeat(32) },
    { client_identity_digest: "de".repeat(32) },
    { enrollment_digest: "ef".repeat(32) },
  ]) {
    const verifier = clock.createDarwinTrustedClockSourceConformanceVerifier(enrollment);
    const challenge = verifier.issueChallenge();
    assert.throws(
      () => verifier.verifyResponse(
        challenge,
        makeResponseFrame(enrollment, challenge, options),
      ),
      (error) => error?.code === "darwin_trusted_clock_source_rejected",
    );
  }
});

test("one verifier binds one boot epoch and rejects monotonic rollback", () => {
  const enrollment = createEnrollment();
  const epochVerifier = clock.createDarwinTrustedClockSourceConformanceVerifier(enrollment);
  let challenge = epochVerifier.issueChallenge();
  epochVerifier.verifyResponse(
    challenge,
    makeResponseFrame(enrollment, challenge, {
      monotonic_ns: "200",
      boot_epoch_digest: HEX.epoch_a,
    }),
  );
  challenge = epochVerifier.issueChallenge();
  assert.throws(
    () => epochVerifier.verifyResponse(
      challenge,
      makeResponseFrame(enrollment, challenge, {
        monotonic_ns: "201",
        boot_epoch_digest: HEX.epoch_b,
      }),
    ),
    (error) => reason(error, "response_boot_epoch_drift"),
  );

  const rollbackVerifier = clock.createDarwinTrustedClockSourceConformanceVerifier(enrollment);
  challenge = rollbackVerifier.issueChallenge();
  rollbackVerifier.verifyResponse(
    challenge,
    makeResponseFrame(enrollment, challenge, { monotonic_ns: "200" }),
  );
  challenge = rollbackVerifier.issueChallenge();
  assert.throws(
    () => rollbackVerifier.verifyResponse(
      challenge,
      makeResponseFrame(enrollment, challenge, { monotonic_ns: "199" }),
    ),
    (error) => reason(error, "response_monotonic_rollback"),
  );
});

test("source package is unprovisioned, source-only and contains no prebuild", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  assert.ok(!manifest.files.some((entry) => /(?:dist|build|\.node)/u.test(entry)));
  const header = fs.readFileSync(
    path.join(ROOT, "native", "trusted_clock_protocol.h"),
    "utf8",
  );
  assert.match(header, /HB_CLOCK_SOURCE_PROVISIONED = 0/u);
  assert.match(header, /UNPROVISIONED/u);
  assert.doesNotMatch(header, /HB_CLOCK_SOURCE_PROVISIONED = 1/u);
  assert.equal(clock.DARWIN_TRUSTED_CLOCK_SOURCE_ASSURANCE,
    "source_only_closed_conformance_non_authorizing");
  assert.ok(clock.DARWIN_TRUSTED_CLOCK_PRODUCTION_BLOCKERS.includes(
    "trusted_clock_native_release_envelope_v3_or_separate_missing",
  ));
  assert.ok(clock.DARWIN_TRUSTED_CLOCK_PRODUCTION_BLOCKERS.includes(
    "trusted_clock_node_api_loaded_image_attestation_and_signed_delivery_missing",
  ));
});
