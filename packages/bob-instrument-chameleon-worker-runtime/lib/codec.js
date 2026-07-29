"use strict";

// Clean-room implementation of the published Chameleon frame contract. This
// module is deliberately transport-neutral: it cannot enumerate, open, read,
// or write a serial/BLE device and it exposes no model-facing command surface.

const crypto = require("node:crypto");

const SOF = 0x11;
const SOF_LRC = 0xef;
const FIXED_FRAME_BYTES = 10;
const BOOTSTRAP_MAX_DATA_LENGTH = 512;
const ABSOLUTE_MAX_DATA_LENGTH = 4096;
const ABSOLUTE_MAX_FRAME_LENGTH = ABSOLUTE_MAX_DATA_LENGTH + FIXED_FRAME_BYTES;
const MAX_PARSE_ERRORS_PER_PUSH = 64;
const MAX_FRAMES_PER_PUSH = 256;

const V2_2_0_PROFILE_PINS = Object.freeze({
  release_tag: "v2.2.0",
  tag_commit: "f349dbeeaa315776b272ae8fb851cc4042d55f07",
  declaration_source_sha256: "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
  registry_source_sha256: "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
});

const profileCommandLimits = new WeakMap();
const decodedFrames = new WeakSet();
const decodedFrameMetadata = new WeakMap();
const decodedFrameCustodyBytes = new WeakMap();
const parserStates = new WeakMap();
const correlationBoundParsers = new WeakSet();
const PROVIDER_PRIVATE_COMPILED_COMMAND_IDS = new Set([2010]);

function assertDecodedFrame(value, label = "chameleon decoded frame") {
  const metadata = value == null ? null : decodedFrameMetadata.get(value);
  if (!value || !decodedFrames.has(value) || !metadata || !Object.isFrozen(value)
      || !Number.isSafeInteger(value.command) || !Number.isSafeInteger(value.status)
      || typeof value.stream_tainted !== "boolean") {
    throw new Error(`${label} must be emitted by a live Chameleon frame parser`);
  }
  return value;
}

function eraseDecodedFrameCustodyBytes(value) {
  const frame = assertDecodedFrame(value);
  const bytes = decodedFrameCustodyBytes.get(frame);
  if (bytes) bytes.fill(0);
  return true;
}

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertClosedObject(value, label, required, optional = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const keys = Reflect.ownKeys(value);
  if (keys.some((field) => typeof field !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const allowed = new Set([...required, ...optional]);
  const unknown = keys.filter((field) => !allowed.has(field)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = required.filter((field) => !keys.includes(field));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  for (const field of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || !descriptor.enumerable) {
      throw new Error(`${label}.${field} must be an enumerable data field`);
    }
  }
  return value;
}

function assertUInt16(value, label) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
    throw new Error(`${label} must be an unsigned 16-bit integer`);
  }
  return value;
}

function assertPositiveInteger(value, label, maximum) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new Error(`${label} must be a safe integer from 1 through ${maximum}`);
  }
  return value;
}

function calculateLrc(value) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
    throw new Error("LRC input must be bytes");
  }
  let sum = 0;
  for (const byte of value) sum = (sum + byte) & 0xff;
  return (-sum) & 0xff;
}

if (calculateLrc(Uint8Array.of(SOF)) !== SOF_LRC) {
  throw new Error("internal Chameleon SOF/LRC contract mismatch");
}

function digestJson(value) {
  return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function makeProfile(value, commandLimits) {
  const profile = Object.freeze(value);
  profileCommandLimits.set(profile, commandLimits);
  return profile;
}

const BOOTSTRAP_COMMAND_DATA_LIMITS = Object.freeze({
  1000: 0,
  1017: 0,
  1025: 0,
  1033: 0,
  1035: 0,
});
const bootstrapCommandLimits = normalizeCommandDataLimits(
  BOOTSTRAP_COMMAND_DATA_LIMITS,
  BOOTSTRAP_MAX_DATA_LENGTH,
);
const bootstrapCommandLimitsDigest = digestJson([...bootstrapCommandLimits.entries()]);
const BOOTSTRAP_OUTBOUND_PROFILE = makeProfile({
  profile_id: "bootstrap_unknown_v1",
  assurance: "bootstrap_or_unknown",
  max_data_length: BOOTSTRAP_MAX_DATA_LENGTH,
  command_data_limits_digest: bootstrapCommandLimitsDigest,
  command_count: bootstrapCommandLimits.size,
}, bootstrapCommandLimits);

function bootstrapOutboundProfile() {
  return BOOTSTRAP_OUTBOUND_PROFILE;
}

// This is immutable provenance/ceiling metadata for closed provider compilers,
// not a caller-selectable encoder profile. Expanding the reviewed table is a
// code/registry release, never a device report or caller runtime option.
const V2_2_0_COMMAND_DATA_LIMITS = Object.freeze({
  1000: 0,
  1001: 1,
  1002: 0,
  1003: 1,
  1004: 3,
  1005: 3,
  1006: 3,
  1007: 34,
  1008: 2,
  1009: 0,
  1010: 0,
  1011: 0,
  1012: 0,
  1013: 0,
  1014: 0,
  1015: 1,
  1016: 0,
  1017: 0,
  1018: 0,
  1019: 0,
  1020: 0,
  1021: 2,
  1023: 0,
  1024: 2,
  1025: 0,
  1026: 1,
  1027: 2,
  1028: 1,
  1029: 2,
  1030: 6,
  1031: 0,
  1032: 0,
  1033: 0,
  1034: 0,
  1035: 0,
  1036: 0,
  1037: 1,
});
const v220CommandLimits = normalizeCommandDataLimits(
  V2_2_0_COMMAND_DATA_LIMITS,
  ABSOLUTE_MAX_DATA_LENGTH,
);
const V2_2_0_CODEC_PROFILE_SNAPSHOT = Object.freeze({
  profile_id: "chameleon_ultra_v2_2_0_source_pinned_v1",
  assurance: "code_reviewed_source_pinned",
  ...V2_2_0_PROFILE_PINS,
  max_data_length: ABSOLUTE_MAX_DATA_LENGTH,
  command_data_limits_digest: digestJson([...v220CommandLimits.entries()]),
  command_count: v220CommandLimits.size,
});

function v220CodecProfileSnapshot() {
  return V2_2_0_CODEC_PROFILE_SNAPSHOT;
}

function normalizeCommandDataLimits(input, maximumDataLength) {
  if (!isPlainObject(input)) throw new Error("command_data_limits must be an object");
  if (Object.getOwnPropertySymbols(input).length > 0) {
    throw new Error("command_data_limits cannot contain symbol fields");
  }
  const entries = Object.entries(input);
  if (entries.length < 1 || entries.length > 0x10000) {
    throw new Error("command_data_limits must declare between 1 and 65536 commands");
  }
  const limits = new Map();
  for (const [rawCommand, rawLimit] of entries) {
    if (!/^(0|[1-9][0-9]{0,4})$/u.test(rawCommand)) {
      throw new Error(`command_data_limits has a non-canonical command key: ${rawCommand}`);
    }
    const command = assertUInt16(Number(rawCommand), `command_data_limits.${rawCommand} command`);
    if (!Number.isSafeInteger(rawLimit) || rawLimit < 0
        || rawLimit > maximumDataLength) {
      throw new Error(
        `command_data_limits.${rawCommand} must be from 0 through ${maximumDataLength}`,
      );
    }
    limits.set(command, rawLimit);
  }
  return limits;
}

function normalizeBytes(value, label) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
    throw new Error(`${label} must be a Buffer or Uint8Array`);
  }
  return Buffer.from(value);
}

function byteView(value, label) {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  throw new Error(`${label} must be a Buffer or Uint8Array`);
}

function encodeOutboundFrame(frameInput, profile, commandLimits) {
  assertClosedObject(frameInput, "chameleon outbound frame", ["command", "status", "data"]);
  const command = assertUInt16(frameInput.command, "chameleon outbound frame.command");
  const status = assertUInt16(frameInput.status, "chameleon outbound frame.status");
  if (status !== 0) {
    throw new Error("chameleon outbound request status must be 0x0000");
  }
  const compilerOnly = PROVIDER_PRIVATE_COMPILED_COMMAND_IDS.has(command);
  if (compilerOnly) {
    throw new Error(
      `chameleon outbound command ${command} requires its closed provider-private compiler`,
    );
  }
  if (!commandLimits.has(command)) {
    throw new Error(`chameleon outbound command ${command} is not declared by this encoder`);
  }
  const data = normalizeBytes(frameInput.data, "chameleon outbound frame.data");
  try {
    const commandMaximum = commandLimits.get(command);
    if (data.length > commandMaximum) {
      throw new Error(
        `chameleon outbound command ${command} DATA exceeds its ${commandMaximum}-byte ceiling`,
      );
    }
    if (data.length > profile.max_data_length) {
      throw new Error(
        `chameleon outbound DATA exceeds profile ${profile.profile_id} ceiling`,
      );
    }
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
  } finally {
    data.fill(0);
  }
}

function createFrameEncoder(input) {
  assertClosedObject(input, "frame_encoder", []);
  const profile = BOOTSTRAP_OUTBOUND_PROFILE;
  const commandLimits = profileCommandLimits.get(profile);

  function encode(frameInput) {
    return encodeOutboundFrame(frameInput, profile, commandLimits);
  }

  return Object.freeze({
    commands: Object.freeze([...commandLimits.keys()]
      .filter((command) => !PROVIDER_PRIVATE_COMPILED_COMMAND_IDS.has(command))
      .sort((left, right) => left - right)),
    encode,
    profile,
  });
}

function createFrameParser() {
  let buffer = Buffer.alloc(0);
  let maximumBufferedBytes = 0;
  let poisonedReason = null;
  let streamTainted = false;
  const parserState = {
    correlation_bound: false,
    next_frame_sequence: 0,
    session_identity: Object.freeze({}),
  };
  let parserCapability = null;

  function replaceBuffer(next) {
    const replacement = Buffer.from(next);
    buffer.fill(0);
    buffer = replacement;
  }

  function appendToBuffer(next) {
    const replacement = Buffer.concat([buffer, next]);
    buffer.fill(0);
    buffer = replacement;
  }

  function findSignature(value) {
    for (let index = 0; index + 1 < value.length; index += 1) {
      if (value[index] === SOF && value[index + 1] === SOF_LRC) return index;
    }
    return -1;
  }

  function makeRecorder(errors) {
    let suppressed = 0;
    return {
      record(error) {
        streamTainted = true;
        if (errors.length < MAX_PARSE_ERRORS_PER_PUSH) errors.push(Object.freeze(error));
        else suppressed += 1;
      },
      finish() {
        if (suppressed > 0) {
          errors.push(Object.freeze({ code: "parse_errors_suppressed", count: suppressed }));
        }
      },
    };
  }

  function drain(frames, recorder) {
    while (buffer.length > 0) {
      if (buffer.length === 1) {
        if (buffer[0] !== SOF) {
          recorder.record({ code: "desynchronized_bytes", discarded_bytes: 1 });
          replaceBuffer(Buffer.alloc(0));
        }
        return;
      }
      const signature = findSignature(buffer);
      if (signature < 0) {
        const preserve = buffer[buffer.length - 1] === SOF ? 1 : 0;
        const discarded = buffer.length - preserve;
        if (discarded > 0) {
          recorder.record({ code: "desynchronized_bytes", discarded_bytes: discarded });
        }
        replaceBuffer(preserve === 1 ? buffer.subarray(buffer.length - 1) : Buffer.alloc(0));
        return;
      }
      if (signature > 0) {
        recorder.record({ code: "desynchronized_bytes", discarded_bytes: signature });
        replaceBuffer(buffer.subarray(signature));
      }
      if (buffer.length < 8) return;
      const dataLength = buffer.readUInt16BE(6);
      if (dataLength > ABSOLUTE_MAX_DATA_LENGTH) {
        recorder.record({ code: "frame_too_large", declared_data_length: dataLength });
        replaceBuffer(buffer.subarray(1));
        continue;
      }
      if (buffer.length < 9) return;
      const expectedHeaderLrc = calculateLrc(buffer.subarray(2, 8));
      if (buffer[8] !== expectedHeaderLrc) {
        recorder.record({ code: "header_lrc_mismatch" });
        replaceBuffer(buffer.subarray(1));
        continue;
      }
      const totalLength = dataLength + FIXED_FRAME_BYTES;
      if (buffer.length < totalLength) return;
      const dataEnd = 9 + dataLength;
      const expectedDataLrc = calculateLrc(buffer.subarray(9, dataEnd));
      if (buffer[dataEnd] !== expectedDataLrc) {
        recorder.record({ code: "data_lrc_mismatch", declared_data_length: dataLength });
        // LEN and LRC2 authenticated the candidate boundary. Discard the
        // complete corrupt candidate, never scan its untrusted DATA for an
        // embedded SOF that could be mistaken for a standalone response.
        replaceBuffer(buffer.subarray(totalLength));
        continue;
      }
      if (frames.length >= MAX_FRAMES_PER_PUSH) {
        recorder.record({
          code: "frame_output_budget_exceeded",
          maximum_frames_per_push: MAX_FRAMES_PER_PUSH,
        });
        replaceBuffer(Buffer.alloc(0));
        poisonedReason = "frame_output_budget_exceeded";
        return;
      }
      const decodedData = Buffer.from(buffer.subarray(9, dataEnd));
      const decodedFrame = {
        command: buffer.readUInt16BE(2),
        status: buffer.readUInt16BE(4),
        stream_tainted: streamTainted,
      };
      Object.defineProperty(decodedFrame, "data", {
        enumerable: true,
        get() { return Buffer.from(decodedData); },
      });
      Object.freeze(decodedFrame);
      parserState.next_frame_sequence += 1;
      decodedFrames.add(decodedFrame);
      decodedFrameCustodyBytes.set(decodedFrame, decodedData);
      decodedFrameMetadata.set(decodedFrame, Object.freeze({
        parser: parserCapability,
        session_identity: parserState.session_identity,
        frame_sequence: parserState.next_frame_sequence,
      }));
      frames.push(decodedFrame);
      replaceBuffer(buffer.subarray(totalLength));
    }
  }

  function result(frames, errors) {
    return Object.freeze({
      frames: Object.freeze(frames),
      errors: Object.freeze(errors),
      buffered_bytes: buffer.length,
      poisoned: poisonedReason != null,
      poisoned_reason: poisonedReason,
      stream_tainted: streamTainted,
    });
  }

  function push(chunk) {
    if (poisonedReason != null) {
      throw new Error(`frame parser is poisoned: ${poisonedReason}; reset is required`);
    }
    // Do not duplicate an arbitrarily large transport chunk. Only the bounded
    // candidate slices copied into `buffer` are retained by the parser.
    const input = byteView(chunk, "frame parser chunk");
    const frames = [];
    const errors = [];
    const recorder = makeRecorder(errors);
    let cursor = 0;
    while (cursor < input.length && poisonedReason == null) {
      drain(frames, recorder);
      let available = ABSOLUTE_MAX_FRAME_LENGTH - buffer.length;
      if (available < 1) {
        // A full candidate is always decidable. This branch is a defensive
        // fail-closed invariant, not a normal resynchronization path.
        recorder.record({ code: "parser_capacity_invariant" });
        replaceBuffer(buffer.subarray(1));
        available = ABSOLUTE_MAX_FRAME_LENGTH - buffer.length;
      }
      const count = Math.min(available, input.length - cursor);
      appendToBuffer(input.subarray(cursor, cursor + count));
      maximumBufferedBytes = Math.max(maximumBufferedBytes, buffer.length);
      cursor += count;
      drain(frames, recorder);
    }
    if (poisonedReason == null) drain(frames, recorder);
    recorder.finish();
    return result(frames, errors);
  }

  function finish() {
    const frames = [];
    const errors = [];
    const recorder = makeRecorder(errors);
    drain(frames, recorder);
    if (buffer.length > 0) {
      recorder.record({ code: "truncated_frame", buffered_bytes: buffer.length });
      replaceBuffer(Buffer.alloc(0));
    }
    recorder.finish();
    return result(frames, errors);
  }

  function reset() {
    if (parserState.correlation_bound) {
      throw new Error(
        "a correlation-bound frame-parser epoch cannot reset; transport turnover requires a new parser",
      );
    }
    const discarded = buffer.length;
    replaceBuffer(Buffer.alloc(0));
    const priorPoisonedReason = poisonedReason;
    poisonedReason = null;
    streamTainted = false;
    parserState.next_frame_sequence = 0;
    parserState.session_identity = Object.freeze({});
    return Object.freeze({
      discarded_bytes: discarded,
      prior_poisoned_reason: priorPoisonedReason,
    });
  }

  function stats() {
    return Object.freeze({
      buffered_bytes: buffer.length,
      maximum_buffered_bytes: maximumBufferedBytes,
      absolute_maximum_buffered_bytes: ABSOLUTE_MAX_FRAME_LENGTH,
      poisoned: poisonedReason != null,
      poisoned_reason: poisonedReason,
      stream_tainted: streamTainted,
    });
  }

  parserCapability = Object.freeze({ finish, push, reset, stats });
  parserStates.set(parserCapability, parserState);
  return parserCapability;
}

function frameFingerprint(frame) {
  const header = Buffer.alloc(6);
  header.writeUInt16BE(frame.command, 0);
  header.writeUInt16BE(frame.status, 2);
  header.writeUInt16BE(frame.data.length, 4);
  return crypto.createHash("sha256").update(header).update(frame.data).digest("hex");
}

function normalizeDecodedFrame(input, label) {
  if (!decodedFrames.has(input)) {
    throw new Error(`${label} must be issued by the bounded frame parser`);
  }
  // Parser-issued frames deliberately expose DATA through a frozen copy-on-read
  // accessor so callers cannot mutate bytes still awaiting correlation. The
  // private brand above makes that one accessor trusted; every other field and
  // the exact own-key set remain closed data.
  const ownKeys = Reflect.ownKeys(input);
  const expectedKeys = ["command", "data", "status", "stream_tainted"];
  if (ownKeys.length !== expectedKeys.length
      || ownKeys.some((field) => typeof field !== "string")
      || ownKeys.slice().sort().some((field, index) => field !== expectedKeys[index])) {
    throw new Error(`${label} has an invalid parser-issued frame shape`);
  }
  for (const field of ["command", "status", "stream_tainted"]) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || !descriptor.enumerable) {
      throw new Error(`${label}.${field} must be an enumerable data field`);
    }
  }
  const dataDescriptor = Object.getOwnPropertyDescriptor(input, "data");
  if (!dataDescriptor || typeof dataDescriptor.get !== "function"
      || dataDescriptor.set !== undefined || !dataDescriptor.enumerable) {
    throw new Error(`${label}.data must be the parser copy-on-read field`);
  }
  const data = normalizeBytes(input.data, `${label}.data`);
  if (data.length > ABSOLUTE_MAX_DATA_LENGTH) {
    throw new Error(`${label}.data exceeds the parser ceiling`);
  }
  return Object.freeze({
    command: assertUInt16(input.command, `${label}.command`),
    status: assertUInt16(input.status, `${label}.status`),
    data,
    stream_tainted: input.stream_tainted === true,
  });
}

function createCommandCorrelationQueue(input) {
  assertClosedObject(input, "command_correlation_queue", ["allowed_commands", "parser"], [
    "max_queue_depth",
    "max_tombstones",
  ]);
  const parserState = parserStates.get(input.parser);
  if (!parserState) {
    throw new Error("command_correlation_queue.parser must be a branded frame-parser epoch");
  }
  if (correlationBoundParsers.has(input.parser)) {
    throw new Error(
      "a frame-parser epoch can bind only one correlation queue; transport turnover requires a new parser",
    );
  }
  const boundParser = input.parser;
  const boundSessionIdentity = parserState.session_identity;
  if (!Array.isArray(input.allowed_commands) || input.allowed_commands.length < 1
      || input.allowed_commands.length > 0x10000) {
    throw new Error("command_correlation_queue.allowed_commands must be a non-empty array");
  }
  const allowedCommands = new Set(input.allowed_commands.map((command, index) => (
    assertUInt16(command, `command_correlation_queue.allowed_commands[${index}]`)
  )));
  if (allowedCommands.size !== input.allowed_commands.length) {
    throw new Error("command_correlation_queue.allowed_commands cannot contain duplicates");
  }
  const maxQueueDepth = input.max_queue_depth == null
    ? 64
    : assertPositiveInteger(input.max_queue_depth, "max_queue_depth", 1024);
  const maxTombstones = input.max_tombstones == null
    ? 128
    : assertPositiveInteger(input.max_tombstones, "max_tombstones", 4096);
  correlationBoundParsers.add(boundParser);
  parserState.correlation_bound = true;
  let nextCorrelationId = 1;
  let pending = [];
  let active = null;
  let tombstones = [];
  const usedCommands = new Set();
  let desynchronizedReason = null;
  let closed = false;

  function makePublicResult(value) {
    return Object.freeze(value);
  }

  function settle(entry, value) {
    if (entry.settled) return;
    entry.settled = true;
    entry.resolve(makePublicResult(value));
  }

  function addTombstone(entry, outcome, fingerprint = null) {
    tombstones.push(Object.freeze({
      correlation_id: entry.correlation_id,
      command: entry.command,
      outcome,
      fingerprint,
    }));
    if (tombstones.length > maxTombstones) {
      tombstones = tombstones.slice(tombstones.length - maxTombstones);
    }
  }

  function abortPending(reason) {
    const abandoned = pending;
    pending = [];
    for (const entry of abandoned) {
      usedCommands.delete(entry.command);
      settle(entry, {
        kind: "aborted",
        correlation_id: entry.correlation_id,
        command: entry.command,
        reason,
        dispatched: false,
      });
    }
  }

  function terminateActive(kind) {
    if (active == null) return null;
    const entry = active;
    active = null;
    clearTimeout(entry.timer);
    entry.timer = null;
    desynchronizedReason = {
      timeout: "in_flight_timeout",
      cancelled: "in_flight_cancelled",
      protocol_corruption: "protocol_corruption",
    }[kind];
    addTombstone(entry, kind);
    const resultValue = {
      kind,
      correlation_id: entry.correlation_id,
      command: entry.command,
      dispatched: true,
      desynchronized: true,
    };
    settle(entry, resultValue);
    abortPending(desynchronizedReason);
    return makePublicResult(resultValue);
  }

  function enqueue(request) {
    if (closed) throw new Error("command correlation queue is closed");
    if (desynchronizedReason != null) {
      throw new Error(`command correlation queue is desynchronized: ${desynchronizedReason}`);
    }
    assertClosedObject(request, "command correlation request", ["command", "timeout_ms"]);
    const command = assertUInt16(request.command, "command correlation request.command");
    if (!allowedCommands.has(command)) {
      throw new Error(`command correlation request uses unknown command ${command}`);
    }
    if (usedCommands.has(command)) {
      throw new Error(
        `command ${command} cannot be reused in one correlation epoch; create a new queue after transport turnover`,
      );
    }
    const timeoutMs = assertPositiveInteger(
      request.timeout_ms,
      "command correlation request.timeout_ms",
      600000,
    );
    const depth = pending.length + (active == null ? 0 : 1);
    if (depth >= maxQueueDepth) throw new Error("command correlation queue is full");
    let resolve;
    const response = new Promise((resolver) => { resolve = resolver; });
    const entry = {
      correlation_id: `chameleon-correlation-${nextCorrelationId}`,
      command,
      timeout_ms: timeoutMs,
      resolve,
      response,
      settled: false,
      timer: null,
    };
    nextCorrelationId += 1;
    usedCommands.add(command);
    pending.push(entry);
    return Object.freeze({
      correlation_id: entry.correlation_id,
      command,
      response,
    });
  }

  function nextDispatch() {
    if (closed) throw new Error("command correlation queue is closed");
    if (desynchronizedReason != null) {
      throw new Error(`command correlation queue is desynchronized: ${desynchronizedReason}`);
    }
    if (active != null || pending.length === 0) return null;
    active = pending.shift();
    active.minimum_frame_sequence = parserState.next_frame_sequence;
    active.timer = setTimeout(() => terminateActive("timeout"), active.timeout_ms);
    return Object.freeze({
      correlation_id: active.correlation_id,
      command: active.command,
      timeout_ms: active.timeout_ms,
    });
  }

  function classifyUnmatched(frame, fingerprint) {
    const prior = [...tombstones].reverse().find((candidate) => (
      candidate.command === frame.command
    ));
    if (prior && prior.outcome === "completed" && prior.fingerprint === fingerprint) {
      return makePublicResult({
        kind: "duplicate",
        command: frame.command,
        prior_correlation_id: prior.correlation_id,
      });
    }
    if (prior && ["cancelled", "timeout", "protocol_corruption"].includes(prior.outcome)) {
      return makePublicResult({
        kind: "late",
        command: frame.command,
        prior_correlation_id: prior.correlation_id,
        prior_outcome: prior.outcome,
      });
    }
    return makePublicResult({ kind: "unknown_command", command: frame.command });
  }

  function accept(frameInput) {
    const frameMetadata = decodedFrameMetadata.get(frameInput);
    if (!frameMetadata || frameMetadata.parser !== boundParser
        || frameMetadata.session_identity !== boundSessionIdentity) {
      return makePublicResult({ kind: "foreign_parser_frame_rejected" });
    }
    const frame = normalizeDecodedFrame(frameInput, "correlated response frame");
    if (frame.stream_tainted) {
      const affected = active == null ? null : active.correlation_id;
      if (active != null) terminateActive("protocol_corruption");
      else {
        desynchronizedReason = "protocol_corruption";
        abortPending(desynchronizedReason);
      }
      return makePublicResult({
        kind: "tainted_frame_rejected",
        affected_correlation_id: affected,
        desynchronized: true,
      });
    }
    if (active != null && frameMetadata.frame_sequence <= active.minimum_frame_sequence) {
      return makePublicResult({
        kind: "pre_dispatch_frame_rejected",
        frame_sequence: frameMetadata.frame_sequence,
      });
    }
    const fingerprint = frameFingerprint(frame);
    if (active == null || frame.command !== active.command) {
      return classifyUnmatched(frame, fingerprint);
    }
    const entry = active;
    active = null;
    clearTimeout(entry.timer);
    entry.timer = null;
    addTombstone(entry, "completed", fingerprint);
    const responseFrame = Object.freeze({
      command: frame.command,
      status: frame.status,
      data: Buffer.from(frame.data),
    });
    const outcome = {
      kind: "response",
      correlation_id: entry.correlation_id,
      command: entry.command,
      frame: responseFrame,
    };
    settle(entry, outcome);
    return makePublicResult({ kind: "matched", correlation_id: entry.correlation_id });
  }

  function cancel(correlationId) {
    if (typeof correlationId !== "string" || correlationId.length < 1) {
      throw new Error("correlation_id must be a non-empty string");
    }
    if (active && active.correlation_id === correlationId) return terminateActive("cancelled");
    const index = pending.findIndex((entry) => entry.correlation_id === correlationId);
    if (index >= 0) {
      const [entry] = pending.splice(index, 1);
      usedCommands.delete(entry.command);
      const value = {
        kind: "cancelled",
        correlation_id: entry.correlation_id,
        command: entry.command,
        dispatched: false,
        desynchronized: false,
      };
      settle(entry, value);
      return makePublicResult(value);
    }
    const terminal = [...tombstones].reverse().find((entry) => (
      entry.correlation_id === correlationId
    ));
    if (terminal) {
      return makePublicResult({
        kind: "already_terminal",
        correlation_id: correlationId,
        terminal_kind: terminal.outcome,
      });
    }
    return makePublicResult({ kind: "unknown_correlation", correlation_id: correlationId });
  }

  function close() {
    if (closed) return makePublicResult({ already_closed: true });
    if (active != null) terminateActive("cancelled");
    else abortPending("queue_closed");
    closed = true;
    return makePublicResult({ already_closed: false });
  }

  function snapshot() {
    return Object.freeze({
      active: active == null ? null : Object.freeze({
        correlation_id: active.correlation_id,
        command: active.command,
      }),
      queued: Object.freeze(pending.map((entry) => Object.freeze({
        correlation_id: entry.correlation_id,
        command: entry.command,
      }))),
      desynchronized: desynchronizedReason != null,
      desynchronized_reason: desynchronizedReason,
      closed,
      tombstone_count: tombstones.length,
      used_command_count: usedCommands.size,
    });
  }

  return Object.freeze({ accept, cancel, close, enqueue, nextDispatch, snapshot });
}

module.exports = {
  ABSOLUTE_MAX_DATA_LENGTH,
  ABSOLUTE_MAX_FRAME_LENGTH,
  BOOTSTRAP_MAX_DATA_LENGTH,
  BOOTSTRAP_COMMAND_DATA_LIMITS,
  FIXED_FRAME_BYTES,
  MAX_FRAMES_PER_PUSH,
  SOF,
  SOF_LRC,
  V2_2_0_COMMAND_DATA_LIMITS,
  V2_2_0_PROFILE_PINS,
  assertDecodedFrame,
  bootstrapOutboundProfile,
  calculateLrc,
  createCommandCorrelationQueue,
  createFrameEncoder,
  createFrameParser,
  eraseDecodedFrameCustodyBytes,
  v220CodecProfileSnapshot,
};
