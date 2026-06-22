"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  frontierEventsJsonlPath,
  pipelineEventsJsonlPath,
} = require("../mcp/lib/paths.js");
const { normalizePipelineEvent } = require("../mcp/lib/pipeline-events.js");
const {
  MAX_FRAME_BYTES,
  readSessionEventFrames,
  framesAfter,
  readJsonlTolerant,
  enforceFrameBudget,
} = require("../mcp/lib/dashboard-event-tail.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-event-tail-test-"));
  process.env.HOME = tempHome;
  const cleanup = () => {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  };
  try {
    const result = fn(tempHome);
    cleanup();
    return result;
  } catch (error) {
    cleanup();
    throw error;
  }
}

function writeFrontier(domain, records) {
  const filePath = frontierEventsJsonlPath(domain);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, records.map((r) => JSON.stringify(r)).join("\n") + "\n", "utf8");
}

function writePipeline(domain, events) {
  const filePath = pipelineEventsJsonlPath(domain);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, events.map((e) => JSON.stringify(e)).join("\n") + "\n", "utf8");
}

function frontierRecord(eventId, ts, kind, payload) {
  return { event_id: eventId, ts, kind, target_domain: "tail.example", payload: payload || {} };
}

test("readSessionEventFrames folds + orders both ledgers (frontier before pipeline on ts tie)", () => {
  withTempHome(() => {
    const domain = "tail.example";
    writeFrontier(domain, [
      frontierRecord("FE-1", "2026-06-21T10:00:00.000Z", "surface.observed", { surface_type: "web_route" }),
      frontierRecord("FE-2", "2026-06-21T10:00:02.000Z", "frontier.enqueued", {}),
    ]);
    writePipeline(domain, [
      normalizePipelineEvent(domain, "finding_recorded", { ts: "2026-06-21T10:00:01.000Z", surface_id: "S-1" }),
      normalizePipelineEvent(domain, "wave_started", { ts: "2026-06-21T10:00:00.000Z", wave: 1 }),
    ]);

    const frames = readSessionEventFrames(domain);
    assert.equal(frames.length, 4);
    assert.deepEqual(
      frames.map((f) => [f.source, f.ts]),
      [
        ["frontier", "2026-06-21T10:00:00.000Z"], // tie → frontier rank 0 first
        ["pipeline", "2026-06-21T10:00:00.000Z"],
        ["pipeline", "2026-06-21T10:00:01.000Z"],
        ["frontier", "2026-06-21T10:00:02.000Z"],
      ],
    );
  });
});

test("frame ids are content-addressed: FE- preserved, PE- synthesized, id = ts|source|recordId", () => {
  withTempHome(() => {
    const domain = "tail.example";
    writeFrontier(domain, [frontierRecord("FE-keep", "2026-06-21T10:00:00.000Z", "surface.observed", {})]);
    writePipeline(domain, [normalizePipelineEvent(domain, "grade_written", { ts: "2026-06-21T10:00:01.000Z" })]);

    const frames = readSessionEventFrames(domain);
    const frontier = frames.find((f) => f.source === "frontier");
    const pipeline = frames.find((f) => f.source === "pipeline");
    assert.equal(frontier.record_id, "FE-keep");
    assert.match(pipeline.record_id, /^PE-[0-9a-f]{24}$/);
    assert.equal(frontier.id, `${frontier.ts}|frontier|FE-keep`);
    assert.equal(pipeline.id, `${pipeline.ts}|pipeline|${pipeline.record_id}`);
  });
});

test("readJsonlTolerant + readSessionEventFrames skip a partial/corrupt trailing line, never throw", () => {
  withTempHome(() => {
    const domain = "tail.example";
    writeFrontier(domain, [frontierRecord("FE-good", "2026-06-21T10:00:00.000Z", "surface.observed", {})]);
    // simulate a concurrent half-written append
    fs.appendFileSync(frontierEventsJsonlPath(domain), '{"event_id":"FE-partial","ts":"2026', "utf8");

    const raw = readJsonlTolerant(frontierEventsJsonlPath(domain));
    assert.equal(raw.length, 1, "tolerant reader keeps the one valid record");
    const frames = readSessionEventFrames(domain);
    assert.equal(frames.length, 1);
    assert.equal(frames[0].record_id, "FE-good");
  });
});

test("missing ledgers yield an empty stream (no throw)", () => {
  withTempHome(() => {
    assert.deepEqual(readSessionEventFrames("never-seeded.example"), []);
  });
});

test("payload is key-allowlisted + shape-gated: nested dropped, freeform scalar dropped, structural token kept, secrets masked", () => {
  withTempHome(() => {
    const domain = "tail.example";
    writeFrontier(domain, [
      frontierRecord("FE-x", "2026-06-21T10:00:00.000Z", "observation.recorded", {
        surface_type: "web_route",         // allowlisted structural token → kept
        status: "verifying",               // allowlisted structural token → kept
        count: 3,                          // allowlisted numeric → kept
        decision: "skip for now per operator",     // allowlisted but FREEFORM (spaces) → dropped
        nested: { secret: "SHOULD_NOT_LEAK" },     // non-primitive → dropped
        list: ["SHOULD_NOT_LEAK_TOO"],             // non-primitive → dropped
        token: "SHOULD_NOT_LEAK_SCALAR",           // non-allowlisted scalar → dropped
        severity: "Authorization: Bearer sk-secret-abc", // allowlisted but secret → not on wire
      }),
    ]);
    const frames = readSessionEventFrames(domain);
    const serialized = JSON.stringify(frames[0].event);
    assert.ok(!serialized.includes("SHOULD_NOT_LEAK"), "nested object dropped");
    assert.ok(!serialized.includes("SHOULD_NOT_LEAK_TOO"), "array dropped");
    assert.ok(!serialized.includes("SHOULD_NOT_LEAK_SCALAR"), "non-allowlisted scalar dropped");
    assert.ok(!serialized.includes("sk-secret-abc"), "secret in an allowlisted field is not on the wire");
    assert.ok(!serialized.includes("skip for now"), "freeform allowlisted value dropped by shape gate");
    assert.equal(frames[0].event.payload.surface_type, "web_route");
    assert.equal(frames[0].event.payload.status, "verifying");
    assert.equal(frames[0].event.payload.count, 3);
    assert.equal(frames[0].event.payload.decision, undefined, "freeform decision dropped by shape gate");
    assert.equal(frames[0].event.payload.token, undefined);
  });
});

test("frontier tags are shape-gated: structural labels kept, freeform/secret tags dropped", () => {
  withTempHome(() => {
    const domain = "tail.example";
    writeFrontier(domain, [
      {
        event_id: "FE-tags",
        ts: "2026-06-21T10:00:00.000Z",
        kind: "surface.observed",
        target_domain: domain,
        tags: [
          "money-movement",                            // structural label → kept
          "auth",                                      // structural label → kept
          "operator note SHOULD_NOT_LEAK",             // freeform (spaces) → dropped
          "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  // bare secret → scrubbed before the wire
        ],
        payload: {},
      },
    ]);
    const ev = readSessionEventFrames(domain)[0].event;
    const serialized = JSON.stringify(ev);
    assert.ok(ev.tags.includes("money-movement"), "structural tag kept");
    assert.ok(ev.tags.includes("auth"), "structural tag kept");
    assert.ok(!serialized.includes("SHOULD_NOT_LEAK"), "freeform tag dropped by shape gate");
    assert.ok(!serialized.includes("ghp_"), "bare-secret tag not on the wire");
  });
});

test("enforceFrameBudget truncates oversized events under MAX_FRAME_BYTES (byte-measured)", () => {
  // direct, redaction-independent check of the budget logic
  const big = {
    event_id: "FE-big",
    ts: "2026-06-21T10:00:00.000Z",
    kind: "observation.recorded",
    note: "x".repeat(5000),
  };
  const result = enforceFrameBudget(big, "frontier");
  assert.equal(result._truncated, true);
  assert.equal(result.event_id, "FE-big");
  assert.equal(result.kind, "observation.recorded");
  assert.ok(Buffer.byteLength(JSON.stringify(result), "utf8") <= MAX_FRAME_BYTES);

  // a within-budget event is returned untouched
  const small = { event_id: "FE-small", ts: "2026-06-21T10:00:00.000Z", kind: "surface.observed" };
  assert.equal(enforceFrameBudget(small, "frontier"), small);
});

test("oversized freeform frontier payload values are stripped by the shape gate, keeping frames within budget", () => {
  withTempHome(() => {
    const domain = "tail.example";
    const payload = {};
    for (const key of ["surface_type", "framework", "method", "status", "kind"]) {
      payload[key] = "web route api handler ".repeat(60); // freeform (spaces) + huge
    }
    writeFrontier(domain, [frontierRecord("FE-big", "2026-06-21T10:00:00.000Z", "observation.recorded", payload)]);
    const ev = readSessionEventFrames(domain)[0].event;
    // freeform values never reach the wire (dropped by construction) ...
    assert.equal(ev.payload, undefined, "all-freeform payload dropped → no payload object");
    assert.ok(!JSON.stringify(ev).includes("web route api handler"), "no freeform prose on the wire");
    // ... and the frame is comfortably within the byte budget
    assert.ok(Buffer.byteLength(JSON.stringify(ev), "utf8") <= MAX_FRAME_BYTES);
  });
});

test("records with an unparseable or empty timestamp are rejected", () => {
  withTempHome(() => {
    const domain = "tail.example";
    writeFrontier(domain, [
      frontierRecord("FE-good", "2026-06-21T10:00:00.000Z", "surface.observed", {}),
      frontierRecord("FE-bad", "not-a-timestamp", "surface.observed", {}),
      frontierRecord("FE-empty", "", "surface.observed", {}),
    ]);
    const frames = readSessionEventFrames(domain);
    assert.deepEqual(frames.map((f) => f.record_id), ["FE-good"]);
  });
});

test("two same-content pipeline events at the same ts are not deduped (ids disambiguated)", () => {
  withTempHome(() => {
    const domain = "tail.example";
    const event = normalizePipelineEvent(domain, "wave_started", { ts: "2026-06-21T10:00:00.000Z", wave: 1 });
    writePipeline(domain, [event, event]);
    const frames = readSessionEventFrames(domain);
    assert.equal(frames.length, 2, "both surface, not silently deduped");
    assert.notEqual(frames[0].record_id, frames[1].record_id, "record ids disambiguated");
  });
});

test("frame ids strip control chars so SSE fields cannot be injected", () => {
  withTempHome(() => {
    const domain = "tail.example";
    writeFrontier(domain, [
      { event_id: "FE-evil\ninjected", ts: "2026-06-21T10:00:00.000Z", kind: "surface.observed", target_domain: domain, payload: {} },
    ]);
    const frames = readSessionEventFrames(domain);
    assert.ok(!frames[0].id.includes("\n"), "no newline in frame id");
    assert.ok(!frames[0].record_id.includes("\n"), "no newline in record id");
    assert.equal(frames[0].record_id, "FE-evilinjected");
  });
});

test("a secret-shaped explicit frontier event_id is redacted in the frame id, not just the payload", () => {
  withTempHome(() => {
    const domain = "tail.example";
    writeFrontier(domain, [
      {
        event_id: "FE-Authorization: Bearer sk-id-leak-9999",
        ts: "2026-06-21T10:00:00.000Z",
        kind: "surface.observed",
        target_domain: domain,
        payload: {},
      },
    ]);
    const frames = readSessionEventFrames(domain);
    // the id line / Last-Event-ID cursor must not carry the secret token
    assert.ok(!frames[0].id.includes("sk-id-leak-9999"), "secret-shaped id redacted in SSE id line");
    assert.ok(!frames[0].record_id.includes("sk-id-leak-9999"), "secret-shaped id redacted in record_id");
  });
});

test("a freeform/opaque explicit frontier event_id is replaced by a content hash; a structural id is preserved", () => {
  withTempHome(() => {
    const domain = "tail.example";
    writeFrontier(domain, [
      { event_id: "operator note SHOULD_NOT_LEAK", ts: "2026-06-21T10:00:00.000Z", kind: "surface.observed", target_domain: domain, payload: {} },
      { event_id: "evt-abc-123", ts: "2026-06-21T10:00:01.000Z", kind: "surface.observed", target_domain: domain, payload: {} },
    ]);
    const frames = readSessionEventFrames(domain);
    const freeform = frames.find((f) => f.ts === "2026-06-21T10:00:00.000Z");
    const structural = frames.find((f) => f.ts === "2026-06-21T10:00:01.000Z");
    assert.ok(freeform.record_id.startsWith("FE-"), "non-token event_id replaced by a synthesized FE-<hash>");
    assert.ok(!freeform.id.includes("SHOULD_NOT_LEAK"), "no freeform id on the SSE id line");
    assert.ok(!JSON.stringify(freeform.event).includes("SHOULD_NOT_LEAK"), "no freeform id in the event payload");
    assert.equal(structural.record_id, "evt-abc-123", "a structural explicit id is preserved as the cursor");
  });
});

test("a Stripe-style bare token (sk_live_) in an allowlisted field is redacted", () => {
  withTempHome(() => {
    const domain = "tail.example";
    writeFrontier(domain, [
      frontierRecord("FE-stripe", "2026-06-21T10:00:00.000Z", "observation.recorded", {
        // built at runtime so no contiguous secret literal sits in the source
        // (GitHub push-protection flags a literal sk_live_ string)
        status: ["sk", "live", "0123456789abcdefABCDEF12"].join("_"),
      }),
    ]);
    const ev = readSessionEventFrames(domain)[0].event;
    assert.ok(!JSON.stringify(ev).includes("sk_live_"), "Stripe-style bare token not on the wire");
  });
});

test("framesAfter resumes strictly after a present Last-Event-ID (no dup, no gap, no resync)", () => {
  withTempHome(() => {
    const domain = "tail.example";
    writeFrontier(domain, [
      frontierRecord("FE-1", "2026-06-21T10:00:00.000Z", "surface.observed", {}),
      frontierRecord("FE-2", "2026-06-21T10:00:01.000Z", "surface.observed", {}),
      frontierRecord("FE-3", "2026-06-21T10:00:02.000Z", "surface.observed", {}),
    ]);
    const frames = readSessionEventFrames(domain);
    const resumed = framesAfter(frames, frames[0].id);
    assert.equal(resumed.resync, false);
    assert.deepEqual(resumed.frames.map((f) => f.record_id), ["FE-2", "FE-3"]);
  });
});

test("framesAfter flags resync when the cursor was trimmed off the front", () => {
  withTempHome(() => {
    const domain = "tail.example";
    writeFrontier(domain, [
      frontierRecord("FE-2", "2026-06-21T10:00:01.000Z", "surface.observed", {}),
      frontierRecord("FE-3", "2026-06-21T10:00:02.000Z", "surface.observed", {}),
    ]);
    const frames = readSessionEventFrames(domain);
    // cursor older than everything present (its frame was trimmed away)
    const resumed = framesAfter(frames, "2026-06-21T09:59:00.000Z|frontier|FE-1");
    assert.equal(resumed.resync, true);
    assert.equal(resumed.frames.length, 2);
  });
});

test("framesAfter signals resync per-source: a peer ledger's older frame does not mask a front-trim gap", () => {
  withTempHome(() => {
    const domain = "tail.example";
    // frontier front-trimmed past the cursor: only T>=20 survive
    writeFrontier(domain, [
      frontierRecord("FE-20", "2026-06-21T10:00:20.000Z", "surface.observed", {}),
      frontierRecord("FE-21", "2026-06-21T10:00:21.000Z", "surface.observed", {}),
    ]);
    // pipeline still retains an OLDER frame (T=5), below the frontier cursor
    writePipeline(domain, [
      normalizePipelineEvent(domain, "wave_started", { ts: "2026-06-21T10:00:05.000Z", wave: 1 }),
    ]);
    const frames = readSessionEventFrames(domain);
    // resume from a frontier cursor at T=10 that was trimmed off the front
    const resumed = framesAfter(frames, "2026-06-21T10:00:10.000Z|frontier|FE-10");
    assert.equal(
      resumed.resync,
      true,
      "frontier front-trim gap is signaled despite the surviving older pipeline frame",
    );
    // the surviving older pipeline frame (T=5) is below the cursor → not replayed
    assert.deepEqual(resumed.frames.map((f) => f.record_id), ["FE-20", "FE-21"]);
  });
});

test("framesAfter with no cursor returns all frames and no resync", () => {
  withTempHome(() => {
    const domain = "tail.example";
    writeFrontier(domain, [frontierRecord("FE-1", "2026-06-21T10:00:00.000Z", "surface.observed", {})]);
    const frames = readSessionEventFrames(domain);
    const resumed = framesAfter(frames, undefined);
    assert.equal(resumed.resync, false);
    assert.equal(resumed.frames.length, 1);
  });
});

test("readJsonlTolerant tail-reads under a byte cap and drops the partial first line", () => {
  withTempHome(() => {
    const domain = "tail.example";
    const filePath = frontierEventsJsonlPath(domain);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    const lines = [];
    for (let i = 0; i < 6; i += 1) lines.push(JSON.stringify({ n: i, pad: "y".repeat(50) }));
    fs.writeFileSync(filePath, lines.join("\n") + "\n", "utf8");

    assert.equal(readJsonlTolerant(filePath).length, 6, "full read returns all records");
    const capped = readJsonlTolerant(filePath, 140);
    assert.ok(capped.length >= 1 && capped.length < 6, "tail-read returns a bounded suffix");
    assert.ok(capped.every((r) => typeof r.n === "number"), "no partial/corrupt record survives the tail read");
  });
});

test("pipeline read path DROPS freeform fields (key allowlist) and keeps structural ones", () => {
  withTempHome(() => {
    const domain = "tail.example";
    const event = normalizePipelineEvent(domain, "evaluator_stopped", {
      ts: "2026-06-21T10:00:00.000Z",
      surface_id: "S-keep",     // allowlisted → kept
      kind: "evaluator",        // allowlisted → kept
      status: "stopped via Authorization: Bearer sk-leak-xyz", // freeform → dropped
      source: "operator-note-SHOULD_NOT_LEAK",                 // freeform → dropped
      agent: "agent-SHOULD_NOT_LEAK",                          // freeform → dropped
    });
    writePipeline(domain, [event]);
    const ev = readSessionEventFrames(domain)[0].event;
    assert.equal(ev.surface_id, "S-keep", "structural surface_id surfaced");
    assert.equal(ev.kind, "evaluator", "structural kind surfaced");
    assert.equal(ev.status, undefined, "freeform status dropped by the allowlist");
    assert.equal(ev.source, undefined, "freeform source dropped by the allowlist");
    assert.equal(ev.agent, undefined, "freeform agent dropped by the allowlist");
    const s = JSON.stringify(ev);
    assert.ok(!s.includes("SHOULD_NOT_LEAK") && !s.includes("sk-leak-xyz"), "no freeform content reaches the wire");
  });
});

test("pipeline freeform surface_id (evidence mode) is dropped by the shape gate, structural kind kept", () => {
  withTempHome(() => {
    const domain = "tail.example";
    const event = normalizePipelineEvent(domain, "evaluator_stopped", {
      ts: "2026-06-21T10:00:00.000Z",
      surface_id: "evidence topic with spaces SHOULD_NOT_LEAK", // freeform evidence topic → dropped
      kind: "evaluator",                                        // structural → kept
    });
    writePipeline(domain, [event]);
    const ev = readSessionEventFrames(domain)[0].event;
    assert.equal(ev.surface_id, undefined, "freeform pipeline surface_id dropped");
    assert.equal(ev.kind, "evaluator", "structural kind kept");
    assert.ok(!JSON.stringify(ev).includes("SHOULD_NOT_LEAK"), "no freeform surface_id content on the wire");
  });
});

test("pipeline counts{} (arbitrary freeform keys) is dropped by the allowlist", () => {
  withTempHome(() => {
    const domain = "tail.example";
    const event = normalizePipelineEvent(domain, "wave_started", {
      ts: "2026-06-21T10:00:00.000Z",
      wave: 1,
      counts: { "Authorization: Bearer sk-counts-leak-9999": 3 },
    });
    writePipeline(domain, [event]);
    const ev = readSessionEventFrames(domain)[0].event;
    assert.equal(ev.counts, undefined, "counts dropped (arbitrary, un-enumerated keys)");
    assert.ok(!JSON.stringify(ev).includes("sk-counts-leak-9999"), "no counts-key content reaches the wire");
  });
});

test("frontier rows whose target_domain mismatches the session are dropped (domain affinity)", () => {
  withTempHome(() => {
    const domain = "tail.example";
    writeFrontier(domain, [
      frontierRecord("FE-mine", "2026-06-21T10:00:00.000Z", "surface.observed", {}), // target_domain = tail.example
      { event_id: "FE-other", ts: "2026-06-21T10:00:01.000Z", kind: "surface.observed", target_domain: "evil.example", payload: {} },
    ]);
    const frames = readSessionEventFrames(domain);
    assert.deepEqual(frames.map((f) => f.record_id), ["FE-mine"], "cross-domain frontier row dropped, matching the pipeline path");
  });
});

test("frontier top-level freeform `actor` is dropped from live frames (kept: structural ids)", () => {
  withTempHome(() => {
    const domain = "tail.example";
    writeFrontier(domain, [
      { event_id: "FE-a", ts: "2026-06-21T10:00:00.000Z", kind: "surface.observed", target_domain: domain, actor: "operator-SHOULD_NOT_LEAK", surface_id: "S1", payload: {} },
    ]);
    const ev = readSessionEventFrames(domain)[0].event;
    assert.equal(ev.actor, undefined, "freeform/identity actor dropped");
    assert.equal(ev.surface_id, "S1", "structural surface_id retained");
    assert.ok(!JSON.stringify(ev).includes("SHOULD_NOT_LEAK"), "no actor content on the wire");
  });
});

test("an overlong all-token-char value is dropped, not truncated-and-emitted (P1: no prefix leak)", () => {
  withTempHome(() => {
    const domain = "tail.example";
    // all token chars + >64 long + NOT a known secret shape (an opaque sk_live_-style
    // token). The gate must REJECT it on length, never truncate to a passing prefix.
    const opaque = "LEAKPREFIX_" + "x".repeat(100);
    writeFrontier(domain, [
      {
        event_id: "FE-long", ts: "2026-06-21T10:00:00.000Z", kind: "surface.observed",
        target_domain: domain, tags: [opaque], payload: { status: opaque },
      },
    ]);
    const ev = readSessionEventFrames(domain)[0].event;
    const s = JSON.stringify(ev);
    assert.ok(!s.includes("LEAKPREFIX"), "no truncated 64-char prefix of the overlong token on the wire");
    assert.equal(ev.tags, undefined, "overlong tag dropped (not truncated)");
    assert.equal(ev.payload, undefined, "overlong payload value dropped → no payload object");
  });
});

test("frontier top-level ids are shape-gated: a freeform surface_id is dropped, a structural one kept", () => {
  withTempHome(() => {
    const domain = "tail.example";
    writeFrontier(domain, [
      { event_id: "FE-f", ts: "2026-06-21T10:00:00.000Z", kind: "surface.observed", target_domain: domain, surface_id: "evidence topic with spaces SHOULD_NOT_LEAK", payload: {} },
      { event_id: "FE-s", ts: "2026-06-21T10:00:01.000Z", kind: "surface.observed", target_domain: domain, surface_id: "auth-login-form", payload: {} },
    ]);
    const frames = readSessionEventFrames(domain);
    const f = frames.find((x) => x.record_id === "FE-f").event;
    const ok = frames.find((x) => x.record_id === "FE-s").event;
    assert.equal(f.surface_id, undefined, "freeform top-level surface_id dropped");
    assert.ok(!JSON.stringify(f).includes("SHOULD_NOT_LEAK"), "no freeform id content on the wire");
    assert.equal(ok.surface_id, "auth-login-form", "structural top-level surface_id kept");
  });
});

test("a marker-only secret (PEM) in an allowlisted field is redacted WHOLE, not just the marker", () => {
  withTempHome(() => {
    const domain = "tail.example";
    // payload.status is allowlisted but still scrubbed. A PEM header is a marker-only
    // regex match; masking only the marker would leave the key body on the wire.
    writeFrontier(domain, [
      frontierRecord("FE-pem", "2026-06-21T10:00:00.000Z", "observation.recorded", {
        status: "-----BEGIN PRIVATE KEY-----MIIBODYSECRETzzz-----END PRIVATE KEY-----",
        severity: "high", // an ordinary allowlisted value still passes through
      }),
    ]);
    const ev = readSessionEventFrames(domain)[0].event;
    const s = JSON.stringify(ev);
    assert.ok(!s.includes("MIIBODYSECRET"), "PEM body redacted (whole value), not just the BEGIN marker");
    assert.equal(ev.payload.severity, "high", "an ordinary allowlisted value is unaffected");
  });
});

test("a bare standalone secret token (AKIA) in an allowlisted field is redacted", () => {
  withTempHome(() => {
    const domain = "tail.example";
    writeFrontier(domain, [
      frontierRecord("FE-tok", "2026-06-21T10:00:00.000Z", "observation.recorded", {
        status: "AKIA1234567890ABCDEF",
      }),
    ]);
    const s = JSON.stringify(readSessionEventFrames(domain)[0].event);
    assert.ok(!/AKIA1234567890ABCDEF/.test(s), "bare AWS key redacted (redactTextSensitiveValues alone misses these)");
  });
});

test("enforceFrameBudget fail-safe stubs a frame whose serialized form still carries a secret shape", () => {
  // a value that bypassed the per-field scrub (e.g. an overlooked path) must not stream
  const evt = { event_id: "FE-x", ts: "2026-06-21T10:00:00.000Z", kind: "surface.observed", leaked: "AKIA1234567890ABCDEF" };
  const result = enforceFrameBudget(evt, "frontier");
  assert.equal(result._redacted, true, "secret-shaped frame collapsed to a flagged stub");
  assert.ok(!JSON.stringify(result).includes("AKIA1234567890ABCDEF"), "secret value not in the stub");
  assert.equal(result.event_id, "FE-x");
  assert.equal(result.kind, "surface.observed");
});

test("pipeline rows with a missing ts are dropped (no now()-substituted unstable id); valid-ts rows surface", () => {
  withTempHome(() => {
    const domain = "tail.example";
    const filePath = pipelineEventsJsonlPath(domain);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    const valid = normalizePipelineEvent(domain, "wave_started", { ts: "2026-06-21T10:00:00.000Z", wave: 2 });
    const noTs = { type: "wave_started", wave: 1 }; // no ts → normalize would fill now()
    fs.writeFileSync(filePath, `${[JSON.stringify(noTs), JSON.stringify(valid)].map((l) => l).join("\n")}\n`, "utf8");
    const frames = readSessionEventFrames(domain);
    assert.equal(frames.length, 1, "only the valid-ts row surfaces");
    assert.equal(frames[0].ts, "2026-06-21T10:00:00.000Z");
  });
});

test("readJsonlTolerant rejects a symlinked ledger (no follow outside the session root)", () => {
  withTempHome((home) => {
    const domain = "tail.example";
    const filePath = frontierEventsJsonlPath(domain);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    const outside = path.join(home, "outside-secrets.jsonl");
    fs.writeFileSync(outside, `${JSON.stringify({ event_id: "FE-outside", ts: "2026-06-21T10:00:00.000Z", kind: "x", target_domain: domain })}\n`, "utf8");
    fs.symlinkSync(outside, filePath);
    assert.deepEqual(readJsonlTolerant(filePath), [], "symlinked ledger is not followed");
    assert.deepEqual(readSessionEventFrames(domain), [], "folded stream is empty for a symlinked ledger");
  });
});
