"use strict";

// Plane Y Cycle Y.4 — Closed target_class enum + assertion.
//
// `target_class` is a bounded caller-side input to `derivePackForNode` that
// surfaces auxiliary tool families per target shape (web app vs smart
// contract vs phishing kit ...). The derivation function consumes the
// value purely — no runtime resolution, no env reads, no clock — and the
// caller (Y.5 wave scheduler) is responsible for picking the right value
// from session metadata or `queue-policy.target_class_default`.
//
// The enum is closed by design (Y-P4 bounded input). Unknown values throw
// from `assertTargetClass` so a stray free-form string from queue-policy
// can't smuggle in a side-channel.

const TARGET_CLASS_VALUES = Object.freeze([
  "web_application",
  "smart_contract",
  "phishing_fraud",
  "mobile_app",
  "infrastructure",
  "other",
]);

function assertTargetClass(value) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(
      `assertTargetClass: target_class must be a non-empty string; got ${typeof value}`,
    );
  }
  if (!TARGET_CLASS_VALUES.includes(value)) {
    throw new Error(
      `assertTargetClass: target_class "${value}" is not in the closed enum `
      + `(${TARGET_CLASS_VALUES.join(", ")})`,
    );
  }
  return value;
}

module.exports = {
  TARGET_CLASS_VALUES,
  assertTargetClass,
};
