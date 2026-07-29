"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const codec = require("../lib/codec.js");
const {
  ABSOLUTE_MAX_DATA_LENGTH,
  ABSOLUTE_MAX_FRAME_LENGTH,
  BOOTSTRAP_MAX_DATA_LENGTH,
  FIXED_FRAME_BYTES,
  MAX_FRAMES_PER_PUSH,
  SOF,
  SOF_LRC,
  V2_2_0_COMMAND_DATA_LIMITS,
  V2_2_0_PROFILE_PINS,
  bootstrapOutboundProfile,
  calculateLrc,
  createCommandCorrelationQueue,
  createFrameEncoder,
  createFrameParser,
  eraseDecodedFrameCustodyBytes,
  v220CodecProfileSnapshot,
} = codec;

function encoder() {
  return createFrameEncoder({});
}

function decoded(parser, command, status, data) {
  const result = parser.push(wireFrame(command, status, data));
  assert.deepEqual(result.errors, []);
  assert.equal(result.frames.length, 1);
  return result.frames[0];
}

function wireFrame(command, status, dataInput) {
  const data = Buffer.from(dataInput);
  const frame = Buffer.alloc(FIXED_FRAME_BYTES + data.length);
  frame[0] = SOF;
  frame[1] = SOF_LRC;
  frame.writeUInt16BE(command, 2);
  frame.writeUInt16BE(status, 4);
  frame.writeUInt16BE(data.length, 6);
  frame[8] = calculateLrc(frame.subarray(2, 8));
  data.copy(frame, 9);
  frame[9 + data.length] = calculateLrc(data);
  return frame;
}

test("encoder emits the published big-endian frame and two's-complement LRCs", () => {
  const frame = encoder().encode({
    command: 1000,
    status: 0,
    data: Buffer.alloc(0),
  });
  assert.equal(frame.length, FIXED_FRAME_BYTES);
  assert.equal(frame[0], SOF);
  assert.equal(frame[1], SOF_LRC);
  assert.equal(frame.readUInt16BE(2), 1000);
  assert.equal(frame.readUInt16BE(4), 0);
  assert.equal(frame.readUInt16BE(6), 0);
  assert.equal((frame.subarray(2, 9).reduce((sum, byte) => sum + byte, 0) & 0xff), 0);
  assert.deepEqual([...frame.subarray(9)], [0]);
  assert.equal(calculateLrc(Buffer.alloc(0)), 0);

  const empty = encoder().encode({ command: 1000, status: 0, data: Buffer.alloc(0) });
  assert.equal(empty.length, FIXED_FRAME_BYTES);
  assert.equal(empty[9], 0);
});

test("parser-issued payload custody can be explicitly zeroized without returning its buffer", () => {
  const parser = createFrameParser();
  const frame = decoded(parser, 1000, 0x0068, [2, 2]);
  const callerCopy = frame.data;
  assert.deepEqual([...callerCopy], [2, 2]);
  assert.equal(eraseDecodedFrameCustodyBytes(frame), true);
  assert.deepEqual([...frame.data], [0, 0]);
  assert.deepEqual([...callerCopy], [2, 2]);
  callerCopy.fill(0);
  assert.throws(
    () => eraseDecodedFrameCustodyBytes({ ...frame }),
    /live Chameleon frame parser/u,
  );
});

test("bootstrap and exact source-pinned profiles enforce fixed outbound ceilings", () => {
  assert.deepEqual(Object.keys(codec).sort(), [
    "ABSOLUTE_MAX_DATA_LENGTH",
    "ABSOLUTE_MAX_FRAME_LENGTH",
    "BOOTSTRAP_COMMAND_DATA_LIMITS",
    "BOOTSTRAP_MAX_DATA_LENGTH",
    "FIXED_FRAME_BYTES",
    "MAX_FRAMES_PER_PUSH",
    "SOF",
    "SOF_LRC",
    "V2_2_0_COMMAND_DATA_LIMITS",
    "V2_2_0_PROFILE_PINS",
    "assertDecodedFrame",
    "bootstrapOutboundProfile",
    "calculateLrc",
    "createCommandCorrelationQueue",
    "createFrameEncoder",
    "createFrameParser",
    "eraseDecodedFrameCustodyBytes",
    "v220CodecProfileSnapshot",
  ].sort());
  for (const forbiddenFactory of [
    "buildV220ProvisioningProjection",
    "createProfileProvisioningVerifierPort",
    "provisionV220OutboundProfile",
  ]) {
    assert.equal(
      Object.prototype.hasOwnProperty.call(codec, forbiddenFactory),
      false,
      `${forbiddenFactory} cannot make profile authority caller-controlled`,
    );
  }
  const bootstrap = bootstrapOutboundProfile();
  assert.equal(bootstrap.max_data_length, BOOTSTRAP_MAX_DATA_LENGTH);
  const bootstrapEncoder = createFrameEncoder({});
  assert.equal(bootstrapEncoder.profile, bootstrap);
  assert.equal(bootstrapEncoder.encode({
    command: 1000,
    status: 0,
    data: Buffer.alloc(0),
  }).length, FIXED_FRAME_BYTES);
  assert.throws(
    () => bootstrapEncoder.encode({ command: 1000, status: 0, data: Buffer.alloc(1) }),
    /exceeds its 0-byte ceiling/,
  );
  assert.throws(
    () => bootstrapEncoder.encode({ command: 65535, status: 0, data: Buffer.alloc(0) }),
    /command 65535 is not declared/,
  );

  assert.throws(
    () => createFrameEncoder({
      outbound_profile: {
        profile_id: "chameleon_ultra_v2_2_0_source_pinned_v1",
        max_data_length: ABSOLUTE_MAX_DATA_LENGTH,
      },
    }),
    /unknown fields: outbound_profile/,
  );

  const provisioned = v220CodecProfileSnapshot();
  assert.equal(Object.isFrozen(provisioned), true);
  assert.deepEqual(
    {
      release_tag: provisioned.release_tag,
      tag_commit: provisioned.tag_commit,
      declaration_source_sha256: provisioned.declaration_source_sha256,
      registry_source_sha256: provisioned.registry_source_sha256,
    },
    V2_2_0_PROFILE_PINS,
  );
  assert.throws(
    () => createFrameEncoder({ outbound_profile: provisioned }),
    /unknown fields: outbound_profile/,
  );
  assert.throws(
    () => createFrameEncoder({
      outbound_profile: provisioned,
      command_data_limits: { 1000: ABSOLUTE_MAX_DATA_LENGTH },
    }),
    /unknown fields: command_data_limits/,
  );
});

test("each encoder refuses undeclared commands and its smaller command ceiling", () => {
  const strict = encoder();
  assert.equal(strict.commands.length, 5);
  assert.equal(strict.commands.includes(2010), false);
  assert.throws(
    () => strict.encode({ command: 2010, status: 0, data: Buffer.alloc(6) }),
    /requires its closed provider-private compiler/u,
  );
  assert.throws(
    () => strict.encode({ command: 1007, status: 0, data: Buffer.alloc(34) }),
    /not declared by this encoder/,
  );
  assert.throws(
    () => strict.encode({ command: 65535, status: 0, data: Buffer.alloc(0) }),
    /command 65535 is not declared/,
  );
  assert.throws(
    () => strict.encode({ command: 1009, status: -1, data: Buffer.alloc(0) }),
    /status must be an unsigned 16-bit integer/,
  );
  assert.throws(
    () => strict.encode({ command: 1009, status: 1, data: Buffer.alloc(0) }),
    /outbound request status must be 0x0000/,
  );
  assert.throws(
    () => strict.encode({ command: 1000, status: 0, data: "raw command" }),
    /must be a Buffer or Uint8Array/,
  );

  let getterCalls = 0;
  const accessorFrame = { status: 0, data: Buffer.alloc(0) };
  Object.defineProperty(accessorFrame, "command", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return 1009;
    },
  });
  assert.throws(
    () => strict.encode(accessorFrame),
    /command must be an enumerable data field/u,
  );
  assert.equal(getterCalls, 0);
});

test("incremental parser accepts every-byte fragmentation and coalesced frames", () => {
  const first = wireFrame(1000, 0, [1, 2, 3, 4]);
  const second = wireFrame(1001, 7, [5, 6]);
  const fragmented = createFrameParser();
  const fragmentedFrames = [];
  for (const byte of first) {
    const result = fragmented.push(Buffer.from([byte]));
    fragmentedFrames.push(...result.frames);
  }
  assert.equal(fragmentedFrames.length, 1);
  assert.equal(fragmentedFrames[0].command, 1000);
  assert.equal(fragmentedFrames[0].status, 0);
  assert.deepEqual([...fragmentedFrames[0].data], [1, 2, 3, 4]);
  const callerCopy = fragmentedFrames[0].data;
  callerCopy.fill(0xff);
  assert.deepEqual(
    [...fragmentedFrames[0].data],
    [1, 2, 3, 4],
    "callers cannot mutate parser-issued frame bytes before correlation",
  );
  assert.equal(fragmented.stats().buffered_bytes, 0);

  const coalesced = createFrameParser().push(Buffer.concat([first, second]));
  assert.deepEqual(coalesced.frames.map((frame) => frame.command), [1000, 1001]);
  assert.deepEqual(coalesced.frames.map((frame) => frame.status), [0, 7]);
  assert.deepEqual(coalesced.errors, []);

  const maximumData = Buffer.alloc(ABSOLUTE_MAX_DATA_LENGTH, 0xa5);
  const maximum = createFrameParser().push(wireFrame(1000, 0, maximumData));
  assert.deepEqual(maximum.errors, []);
  assert.equal(maximum.frames.length, 1);
  assert.equal(maximum.frames[0].data.length, ABSOLUTE_MAX_DATA_LENGTH);
});

test("parser resynchronizes after garbage, corrupt LRCs, and oversized headers", () => {
  const one = wireFrame(1000, 0, [1]);
  const two = wireFrame(1001, 0, [2]);
  const three = wireFrame(1002, 0, [3]);
  const corruptHeader = Buffer.from(one);
  corruptHeader[8] ^= 0x01;
  const corruptData = Buffer.from(two);
  corruptData[corruptData.length - 1] ^= 0x01;
  const oversizedHeader = Buffer.alloc(9);
  oversizedHeader[0] = SOF;
  oversizedHeader[1] = SOF_LRC;
  oversizedHeader.writeUInt16BE(4000, 2);
  oversizedHeader.writeUInt16BE(0, 4);
  oversizedHeader.writeUInt16BE(ABSOLUTE_MAX_DATA_LENGTH + 1, 6);
  oversizedHeader[8] = calculateLrc(oversizedHeader.subarray(2, 8));

  const parser = createFrameParser();
  const result = parser.push(Buffer.concat([
    Buffer.from([0xaa, 0xbb, SOF]),
    corruptHeader,
    one,
    corruptData,
    two,
    oversizedHeader,
    three,
  ]));
  assert.deepEqual(result.frames.map((frame) => frame.command), [1000, 1001, 1002]);
  assert.ok(result.frames.every((frame) => frame.stream_tainted));
  const codes = new Set(result.errors.map((error) => error.code));
  assert.ok(codes.has("desynchronized_bytes"));
  assert.ok(codes.has("header_lrc_mismatch"));
  assert.ok(codes.has("data_lrc_mismatch"));
  assert.ok(codes.has("frame_too_large"));
  assert.equal(result.buffered_bytes, 0);
});

test("parser buffering and diagnostics stay bounded under hostile input", async () => {
  const parser = createFrameParser();
  const garbage = parser.push(Buffer.alloc(1_000_000, 0xaa));
  assert.ok(garbage.errors.length <= 65);
  assert.equal(garbage.frames.length, 0);
  assert.equal(garbage.buffered_bytes, 0);
  assert.ok(parser.stats().maximum_buffered_bytes <= ABSOLUTE_MAX_FRAME_LENGTH);

  const emptyFrame = wireFrame(1000, 0, []);
  const validFloodParser = createFrameParser();
  const validFlood = validFloodParser.push(Buffer.concat(
    Array.from({ length: MAX_FRAMES_PER_PUSH + 100 }, () => emptyFrame),
  ));
  assert.equal(validFlood.frames.length, MAX_FRAMES_PER_PUSH);
  assert.equal(validFlood.poisoned, true);
  assert.equal(validFlood.poisoned_reason, "frame_output_budget_exceeded");
  assert.ok(validFlood.errors.some((error) => error.code === "frame_output_budget_exceeded"));
  assert.throws(
    () => validFloodParser.push(emptyFrame),
    /frame parser is poisoned: frame_output_budget_exceeded/,
  );
  assert.equal(validFloodParser.reset().prior_poisoned_reason, "frame_output_budget_exceeded");

  const partial = Buffer.alloc(9);
  partial[0] = SOF;
  partial[1] = SOF_LRC;
  partial.writeUInt16BE(1000, 2);
  partial.writeUInt16BE(0, 4);
  partial.writeUInt16BE(ABSOLUTE_MAX_DATA_LENGTH, 6);
  partial[8] = calculateLrc(partial.subarray(2, 8));
  const held = parser.push(partial);
  assert.equal(held.buffered_bytes, 9);
  assert.ok(parser.stats().buffered_bytes <= ABSOLUTE_MAX_FRAME_LENGTH);
  const finished = parser.finish();
  assert.deepEqual(finished.errors.map((error) => error.code), ["truncated_frame"]);
  assert.equal(finished.buffered_bytes, 0);

  const resetParser = createFrameParser();
  const preResetFrame = decoded(resetParser, 1000, 0, []);
  resetParser.reset();
  const resetQueue = createCommandCorrelationQueue({
    allowed_commands: [1000],
    parser: resetParser,
  });
  const resetTicket = resetQueue.enqueue({ command: 1000, timeout_ms: 1000 });
  resetQueue.nextDispatch();
  assert.deepEqual(
    resetQueue.accept(preResetFrame),
    { kind: "foreign_parser_frame_rejected" },
    "a frame branded before parser-session reset cannot cross into the new session",
  );
  resetQueue.accept(decoded(resetParser, 1000, 0, []));
  assert.equal(resetQueue.snapshot().active, null);
  assert.throws(
    () => resetParser.reset(),
    /correlation-bound frame-parser epoch cannot reset/,
  );
  assert.equal((await resetTicket.response).kind, "response");
  resetQueue.close();
});

test("corrupt large candidates are discarded once without embedded-frame recovery", () => {
  const inner = wireFrame(1000, 0, []);
  const outer = wireFrame(2000, 0, inner);
  outer[outer.length - 1] ^= 0x01;
  const parser = createFrameParser();
  const embedded = parser.push(outer);
  assert.deepEqual(embedded.frames, []);
  assert.ok(embedded.errors.some((error) => error.code === "data_lrc_mismatch"));

  const header = Buffer.alloc(9);
  header[0] = SOF;
  header[1] = SOF_LRC;
  header.writeUInt16BE(2000, 2);
  header.writeUInt16BE(0, 4);
  header.writeUInt16BE(ABSOLUTE_MAX_DATA_LENGTH, 6);
  header[8] = calculateLrc(header.subarray(2, 8));
  const pattern = Buffer.concat([header, Buffer.from([0xaa])]);
  const hostile = Buffer.alloc(100_000);
  for (let offset = 0; offset < hostile.length; offset += pattern.length) {
    pattern.copy(hostile, offset, 0, Math.min(pattern.length, hostile.length - offset));
  }
  const started = Date.now();
  const stressed = createFrameParser().push(hostile);
  assert.ok(Date.now() - started < 1000, "corrupt-stream work must remain linearly bounded");
  assert.equal(stressed.frames.length, 0);
  assert.ok(stressed.buffered_bytes <= ABSOLUTE_MAX_FRAME_LENGTH);
});

test("correlation queue dispatches one command at a time in FIFO order", async (t) => {
  const parser = createFrameParser();
  const queue = createCommandCorrelationQueue({ allowed_commands: [1000, 1001], parser });
  t.after(() => queue.close());
  const first = queue.enqueue({ command: 1000, timeout_ms: 1000 });
  const second = queue.enqueue({ command: 1001, timeout_ms: 1000 });
  assert.equal(queue.nextDispatch().correlation_id, first.correlation_id);
  assert.equal(queue.nextDispatch(), null);
  assert.deepEqual(
    queue.accept(decoded(parser, 6000, 0, [])),
    { kind: "unknown_command", command: 6000 },
  );
  assert.equal(queue.snapshot().active.correlation_id, first.correlation_id);

  const firstFrame = decoded(parser, 1000, 0, [1, 2]);
  assert.deepEqual(queue.accept(firstFrame), {
    kind: "matched",
    correlation_id: first.correlation_id,
  });
  const firstResult = await first.response;
  assert.equal(firstResult.kind, "response");
  assert.deepEqual([...firstResult.frame.data], [1, 2]);
  assert.deepEqual(queue.accept(firstFrame), {
    kind: "duplicate",
    command: 1000,
    prior_correlation_id: first.correlation_id,
  });

  assert.equal(queue.nextDispatch().correlation_id, second.correlation_id);
  queue.accept(decoded(parser, 1001, 9, [3]));
  const secondResult = await second.response;
  assert.equal(secondResult.kind, "response");
  assert.equal(secondResult.frame.status, 9);
  assert.equal(queue.snapshot().active, null);
  assert.throws(
    () => queue.enqueue({ command: 1000, timeout_ms: 10 }),
    /cannot be reused in one correlation epoch/,
  );
  assert.throws(
    () => queue.enqueue({ command: 9999, timeout_ms: 10 }),
    /unknown command 9999/,
  );
  assert.throws(
    () => createCommandCorrelationQueue({ allowed_commands: [1000], parser }),
    /frame-parser epoch can bind only one correlation queue/,
  );

  const nextParser = createFrameParser();
  const nextEpoch = createCommandCorrelationQueue({ allowed_commands: [1000], parser: nextParser });
  t.after(() => nextEpoch.close());
  const nextTicket = nextEpoch.enqueue({ command: 1000, timeout_ms: 1000 });
  nextEpoch.nextDispatch();
  assert.deepEqual(nextEpoch.accept(firstFrame), { kind: "foreign_parser_frame_rejected" });
  assert.equal(nextEpoch.snapshot().active.correlation_id, nextTicket.correlation_id);
  nextEpoch.accept(decoded(nextParser, 1000, 0, [9]));
  assert.deepEqual([...(await nextTicket.response).frame.data], [9]);

  const boundaryParser = createFrameParser();
  const preDispatchFrame = decoded(boundaryParser, 1000, 0, [7]);
  const boundaryQueue = createCommandCorrelationQueue({
    allowed_commands: [1000],
    parser: boundaryParser,
  });
  t.after(() => boundaryQueue.close());
  const boundaryTicket = boundaryQueue.enqueue({ command: 1000, timeout_ms: 1000 });
  boundaryQueue.nextDispatch();
  assert.deepEqual(boundaryQueue.accept(preDispatchFrame), {
    kind: "pre_dispatch_frame_rejected",
    frame_sequence: 1,
  });
  boundaryQueue.accept(decoded(boundaryParser, 1000, 0, [8]));
  assert.deepEqual([...(await boundaryTicket.response).frame.data], [8]);
});

test("queued cancellation is harmless while in-flight cancellation poisons correlation", async (t) => {
  const parser = createFrameParser();
  const queue = createCommandCorrelationQueue({ allowed_commands: [1000, 1001], parser });
  t.after(() => queue.close());
  const first = queue.enqueue({ command: 1000, timeout_ms: 1000 });
  const second = queue.enqueue({ command: 1001, timeout_ms: 1000 });
  const pendingCancellation = queue.cancel(second.correlation_id);
  assert.equal(pendingCancellation.kind, "cancelled");
  assert.equal(pendingCancellation.dispatched, false);
  assert.equal((await second.response).desynchronized, false);

  queue.nextDispatch();
  const activeCancellation = queue.cancel(first.correlation_id);
  assert.equal(activeCancellation.kind, "cancelled");
  assert.equal(activeCancellation.desynchronized, true);
  assert.equal((await first.response).kind, "cancelled");
  assert.equal(queue.snapshot().desynchronized_reason, "in_flight_cancelled");
  assert.deepEqual(queue.accept(decoded(parser, 1000, 0, [])), {
    kind: "late",
    command: 1000,
    prior_correlation_id: first.correlation_id,
    prior_outcome: "cancelled",
  });
  assert.throws(() => queue.nextDispatch(), /desynchronized: in_flight_cancelled/);
});

test("in-flight timeout is terminal, aborts FIFO waiters, and classifies late response", async (t) => {
  const parser = createFrameParser();
  const queue = createCommandCorrelationQueue({ allowed_commands: [1000, 1001], parser });
  t.after(() => queue.close());
  const first = queue.enqueue({ command: 1000, timeout_ms: 15 });
  const second = queue.enqueue({ command: 1001, timeout_ms: 1000 });
  queue.nextDispatch();
  const firstResult = await first.response;
  const secondResult = await second.response;
  assert.equal(firstResult.kind, "timeout");
  assert.equal(firstResult.desynchronized, true);
  assert.deepEqual(secondResult, {
    kind: "aborted",
    correlation_id: second.correlation_id,
    command: 1001,
    reason: "in_flight_timeout",
    dispatched: false,
  });
  assert.deepEqual(queue.accept(decoded(parser, 1000, 0, [])), {
    kind: "late",
    command: 1000,
    prior_correlation_id: first.correlation_id,
    prior_outcome: "timeout",
  });
  assert.throws(
    () => queue.enqueue({ command: 1000, timeout_ms: 10 }),
    /desynchronized: in_flight_timeout/,
  );
});

test("corruption-tainted resynchronization can never satisfy command correlation", async (t) => {
  const parser = createFrameParser();
  const queue = createCommandCorrelationQueue({ allowed_commands: [1000], parser });
  t.after(() => queue.close());
  const ticket = queue.enqueue({ command: 1000, timeout_ms: 1000 });
  queue.nextDispatch();
  const corrupt = wireFrame(1001, 0, [1]);
  corrupt[8] ^= 0x01;
  const parsed = parser.push(Buffer.concat([
    corrupt,
    wireFrame(1000, 0, [2]),
  ]));
  assert.equal(parsed.frames.length, 1);
  assert.equal(parsed.frames[0].stream_tainted, true);
  assert.deepEqual(queue.accept(parsed.frames[0]), {
    kind: "tainted_frame_rejected",
    affected_correlation_id: ticket.correlation_id,
    desynchronized: true,
  });
  assert.equal((await ticket.response).kind, "protocol_corruption");
  assert.equal(queue.snapshot().desynchronized_reason, "protocol_corruption");
  assert.deepEqual(
    queue.accept({ command: 1000, status: 0, data: Buffer.alloc(0), stream_tainted: false }),
    { kind: "foreign_parser_frame_rejected" },
  );
});
