"use strict";

const REPLAY_CONTEXT_SCHEMA = Object.freeze({
  type: "object",
  properties: {
    purpose: { type: "string" },
    verification_attempt_id: { type: "string" },
    verification_snapshot_hash: { type: "string" },
    round: { type: "string", enum: ["brutalist", "balanced", "final"] },
    finding_id: { type: "string", pattern: "^F-[1-9][0-9]*$" },
  },
});

module.exports = {
  REPLAY_CONTEXT_SCHEMA,
};
