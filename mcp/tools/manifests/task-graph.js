"use strict";

const taskReproVerificationTools = Object.freeze([
  require("../propose-hypothesis.js"),
  require("../propose-transition.js"),
  require("../materialize-task-graph.js"),
  require("../materialize-cell-floor.js"),
  require("../read-task-graph.js"),
  require("../read-composition-telemetry.js"),
  require("../run-path-composition-experiment.js"),
  require("../verify-composition-path.js"),
  require("../repo/verify-repro-reproduction.js"),
  require("../repo/verify-oracle-differential.js"),
]);

const findingVerificationTools = Object.freeze([
  require("../verify-finding-differential.js"),
]);

const taskGraphExecutionTools = Object.freeze([
  require("../attach-contract.js"),
  require("../resolve-body.js"),
  require("../prepare-node.js"),
  require("../finalize-node.js"),
  require("../schedule-graph-nodes.js"),
  require("../materialize-producer-floor.js"),
  require("../schedule-seed-producers.js"),
  require("../materialize-frontier.js"),
  require("../read-queue-policy.js"),
  require("../set-queue-policy.js"),
  require("../schedule-tasks.js"),
]);

const browserSessionExecutionTools = Object.freeze([
  require("../web/browser-session-start.js"),
  require("../web/browser-navigate.js"),
  require("../web/browser-snapshot.js"),
  require("../web/browser-click.js"),
  require("../web/browser-type.js"),
  require("../web/browser-evaluate.js"),
  require("../web/browser-network-requests.js"),
  require("../web/browser-console-messages.js"),
  require("../web/browser-wait-for.js"),
  require("../web/browser-press-key.js"),
  require("../web/browser-take-screenshot.js"),
  require("../web/browser-fill-form.js"),
  require("../web/browser-session-close.js"),
  require("../web/browser-session-start-recording.js"),
  require("../web/browser-flush-recorded-requests.js"),
]);

const packTelemetryTools = Object.freeze([
  require("../set-pack-telemetry-config.js"),
]);

const taskGraphTools = [
  ...taskReproVerificationTools,
  ...findingVerificationTools,
  ...taskGraphExecutionTools,
  ...browserSessionExecutionTools,
  ...packTelemetryTools,
];

Object.defineProperty(taskGraphTools, "taskReproVerificationTools", {
  value: taskReproVerificationTools,
  enumerable: false,
  writable: false,
  configurable: false,
});
Object.defineProperty(taskGraphTools, "findingVerificationTools", {
  value: findingVerificationTools,
  enumerable: false,
  writable: false,
  configurable: false,
});
Object.defineProperty(taskGraphTools, "taskGraphExecutionTools", {
  value: taskGraphExecutionTools,
  enumerable: false,
  writable: false,
  configurable: false,
});
Object.defineProperty(taskGraphTools, "browserSessionExecutionTools", {
  value: browserSessionExecutionTools,
  enumerable: false,
  writable: false,
  configurable: false,
});
Object.defineProperty(taskGraphTools, "packTelemetryTools", {
  value: packTelemetryTools,
  enumerable: false,
  writable: false,
  configurable: false,
});

module.exports = Object.freeze(taskGraphTools);
