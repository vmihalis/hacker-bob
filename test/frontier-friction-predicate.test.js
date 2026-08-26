"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  capabilityFrictionPayloads,
  aggregateFrictionByPack,
} = require("../mcp/core/frontier/frontier-events.js");

function frictionPayload(surfaceId, wantedTool, extra = {}) {
  return {
    observation_kind: "capability_friction_observed",
    surface_id: surfaceId,
    wanted_tool: wantedTool,
    ...extra,
  };
}

function frictionEvent(surfaceId, frictionKind, extra = {}) {
  return {
    kind: "observation.recorded",
    payload: {
      observation_kind: "capability_friction_observed",
      surface_id: surfaceId,
      friction_kind: frictionKind,
      ...extra,
    },
  };
}

test("per-surface: { surfaceId } returns only payloads whose surface_id matches", () => {
  const events = [
    frictionEvent("surface-a", "tool_absent"),
    frictionEvent("surface-b", "tool_inadequate"),
    frictionEvent("surface-a", "tool_inadequate"),
  ];
  const out = capabilityFrictionPayloads(events, { surfaceId: "surface-a" });
  assert.equal(out.length, 2);
  assert.ok(out.every((p) => p.surface_id === "surface-a"));
  // order preserved: first surface-a event before the later surface-a event
  assert.equal(out[0].friction_kind, "tool_absent");
  assert.equal(out[1].friction_kind, "tool_inadequate");
  // returns the payload objects (not the events)
  assert.equal(out[0], events[0].payload);
});

test("global: no surfaceId returns all capability_friction payloads across surfaces", () => {
  const events = [
    frictionEvent("surface-a", "tool_absent"),
    frictionEvent("surface-b", "tool_inadequate"),
    frictionEvent("surface-c", "tool_absent"),
  ];
  const out = capabilityFrictionPayloads(events);
  assert.equal(out.length, 3);
  assert.deepEqual(
    out.map((p) => p.surface_id),
    ["surface-a", "surface-b", "surface-c"],
  );
});

test("friction_kind gate drops non-allowed kinds and keeps the two allowed kinds", () => {
  const events = [
    frictionEvent("surface-a", "tool_absent"),
    frictionEvent("surface-a", "some_other_kind"),
    frictionEvent("surface-a", "tool_inadequate"),
    // friction_kind absent entirely
    {
      kind: "observation.recorded",
      payload: { observation_kind: "capability_friction_observed", surface_id: "surface-a" },
    },
  ];
  const out = capabilityFrictionPayloads(events, {
    frictionKinds: ["tool_absent", "tool_inadequate"],
  });
  assert.equal(out.length, 2);
  assert.deepEqual(
    out.map((p) => p.friction_kind),
    ["tool_absent", "tool_inadequate"],
  );
});

test("malformed rejection: non-array input and skipped/excluded events", () => {
  // non-array input → []
  assert.deepEqual(capabilityFrictionPayloads(null), []);
  assert.deepEqual(capabilityFrictionPayloads(undefined), []);
  assert.deepEqual(capabilityFrictionPayloads("not-an-array"), []);
  assert.deepEqual(capabilityFrictionPayloads({}), []);

  const events = [
    // a non-plain-object event is skipped
    null,
    "string-event",
    ["array-event"],
    42,
    // an observation.recorded event whose observation_kind is not
    // capability_friction_observed is excluded
    {
      kind: "observation.recorded",
      payload: { observation_kind: "jwt_observed", surface_id: "surface-a" },
    },
    // an event whose payload is a non-object is skipped
    { kind: "observation.recorded", payload: "not-an-object" },
    { kind: "observation.recorded", payload: null },
    { kind: "observation.recorded", payload: ["array"] },
    // a non-observation.recorded event is excluded
    {
      kind: "surface.observed",
      payload: { observation_kind: "capability_friction_observed", surface_id: "surface-a" },
    },
    // one genuine match survives
    frictionEvent("surface-a", "tool_absent"),
  ];
  const out = capabilityFrictionPayloads(events);
  assert.equal(out.length, 1);
  assert.equal(out[0].observation_kind, "capability_friction_observed");
  assert.equal(out[0].friction_kind, "tool_absent");
});

test("aggregateFrictionByPack: groups (pack, wanted_tool, surfaces) across surfaces", () => {
  const payloads = [
    frictionPayload("surface-a", "bob_ws_probe"),
    frictionPayload("surface-b", "bob_ws_probe"),
  ];
  const map = { "surface-a": "web_default", "surface-b": "web_default" };
  const out = aggregateFrictionByPack(payloads, map);
  assert.deepEqual(out, {
    web_default: { bob_ws_probe: { count: 2, surface_ids: ["surface-a", "surface-b"] } },
  });
});

test("aggregateFrictionByPack: surface_ids dedupe within a (pack, tool) bucket, first-seen order", () => {
  const payloads = [
    frictionPayload("surface-a", "bob_ws_probe"),
    frictionPayload("surface-a", "bob_ws_probe"),
  ];
  const map = { "surface-a": "web_default" };
  const out = aggregateFrictionByPack(payloads, map);
  assert.equal(out.web_default.bob_ws_probe.count, 2);
  assert.deepEqual(out.web_default.bob_ws_probe.surface_ids, ["surface-a"]);
});

test("aggregateFrictionByPack: a Map map yields the same result as a plain-object map", () => {
  const payloads = [
    frictionPayload("surface-a", "bob_ws_probe"),
    frictionPayload("surface-b", "bob_ws_probe"),
  ];
  const objMap = { "surface-a": "web_default", "surface-b": "web_default" };
  const mapMap = new Map([["surface-a", "web_default"], ["surface-b", "web_default"]]);
  assert.deepEqual(
    aggregateFrictionByPack(payloads, mapMap),
    aggregateFrictionByPack(payloads, objMap),
  );
});

test("aggregateFrictionByPack: a payload whose surface_id is absent from the map is skipped", () => {
  const payloads = [
    frictionPayload("surface-a", "bob_ws_probe"),
    frictionPayload("surface-unknown", "bob_ws_probe"),
  ];
  const map = { "surface-a": "web_default" };
  const out = aggregateFrictionByPack(payloads, map);
  assert.deepEqual(out, {
    web_default: { bob_ws_probe: { count: 1, surface_ids: ["surface-a"] } },
  });
});

test("aggregateFrictionByPack: a payload missing wanted_tool is skipped", () => {
  const payloads = [
    frictionPayload("surface-a", "bob_ws_probe"),
    // wanted_tool absent entirely
    { observation_kind: "capability_friction_observed", surface_id: "surface-a" },
    // wanted_tool is a non-string
    { observation_kind: "capability_friction_observed", surface_id: "surface-a", wanted_tool: 42 },
  ];
  const map = { "surface-a": "web_default" };
  const out = aggregateFrictionByPack(payloads, map);
  assert.equal(out.web_default.bob_ws_probe.count, 1);
});

test("aggregateFrictionByPack: empty/malformed inputs return {}", () => {
  assert.deepEqual(aggregateFrictionByPack([], {}), {});
  assert.deepEqual(aggregateFrictionByPack(null, {}), {});
  assert.deepEqual(aggregateFrictionByPack("not-an-array", {}), {});
  assert.deepEqual(aggregateFrictionByPack([frictionPayload("surface-a", "bob_ws_probe")], null), {});
  assert.deepEqual(aggregateFrictionByPack([frictionPayload("surface-a", "bob_ws_probe")], "not-a-map"), {});
});

test("aggregateFrictionByPack: does not mutate its inputs", () => {
  const payloads = Object.freeze([Object.freeze(frictionPayload("surface-a", "bob_ws_probe"))]);
  const map = Object.freeze({ "surface-a": "web_default" });
  // Frozen inputs would throw on any write; a clean run proves no mutation.
  const out = aggregateFrictionByPack(payloads, map);
  assert.equal(out.web_default.bob_ws_probe.count, 1);
});
