"use strict";

const { capabilityToolMapFromRegistry } = require("../dispatch/tool-registry.js");
const { readToolTelemetryEvents } = require("../telemetry/tool-telemetry.js");

const CAPABILITY_TO_TOOLS = capabilityToolMapFromRegistry();

const TOOL_TO_CAPABILITY = (() => {
  const map = new Map();
  for (const [capability, tools] of Object.entries(CAPABILITY_TO_TOOLS)) {
    for (const tool of tools) {
      map.set(tool, capability);
    }
  }
  return map;
})();

function emptyBucket(capability, tools) {
  return {
    capability,
    tools,
    call_count: 0,
    success_count: 0,
    error_count: 0,
    blocked_count: 0,
    total_latency_ms: 0,
    latency_samples: 0,
    last_called_at: null,
    per_tool: Object.fromEntries(tools.map((tool) => [tool, {
      call_count: 0,
      success_count: 0,
      error_count: 0,
      blocked_count: 0,
      total_latency_ms: 0,
      latency_samples: 0,
    }])),
  };
}

function emitFinalMetrics(buckets) {
  const result = {};
  for (const [capability, bucket] of Object.entries(buckets)) {
    const successRate = bucket.call_count > 0 ? bucket.success_count / bucket.call_count : null;
    const avgLatency = bucket.latency_samples > 0
      ? Math.round(bucket.total_latency_ms / bucket.latency_samples)
      : null;
    const perTool = {};
    for (const [tool, perToolBucket] of Object.entries(bucket.per_tool)) {
      const tSuccess = perToolBucket.call_count > 0 ? perToolBucket.success_count / perToolBucket.call_count : null;
      const tAvg = perToolBucket.latency_samples > 0
        ? Math.round(perToolBucket.total_latency_ms / perToolBucket.latency_samples)
        : null;
      perTool[tool] = {
        call_count: perToolBucket.call_count,
        success_count: perToolBucket.success_count,
        error_count: perToolBucket.error_count,
        blocked_count: perToolBucket.blocked_count,
        success_rate: tSuccess == null ? null : Number(tSuccess.toFixed(4)),
        avg_latency_ms: tAvg,
      };
    }
    result[capability] = {
      capability,
      tools: bucket.tools,
      call_count: bucket.call_count,
      success_count: bucket.success_count,
      error_count: bucket.error_count,
      blocked_count: bucket.blocked_count,
      success_rate: successRate == null ? null : Number(successRate.toFixed(4)),
      avg_latency_ms: avgLatency,
      last_called_at: bucket.last_called_at,
      per_tool: perTool,
    };
  }
  return result;
}

function summarizeCapabilityMetrics(events) {
  const buckets = Object.fromEntries(
    Object.entries(CAPABILITY_TO_TOOLS).map(([capability, tools]) => [capability, emptyBucket(capability, tools.slice())]),
  );
  if (!Array.isArray(events)) return emitFinalMetrics(buckets);
  for (const event of events) {
    if (event == null || typeof event !== "object") continue;
    const tool = typeof event.tool === "string" ? event.tool : null;
    if (!tool) continue;
    const capability = TOOL_TO_CAPABILITY.get(tool);
    if (!capability) continue;
    const bucket = buckets[capability];
    bucket.call_count += 1;
    const status = event.status;
    const isBlocked = status === "blocked";
    const ok = !isBlocked && (event.ok === true || status === "ok" || status === "success" || status === "allowed");
    if (ok) bucket.success_count += 1;
    if (isBlocked) bucket.blocked_count += 1;
    if (event.error_code != null || event.error != null || (status != null && status !== "ok" && status !== "success" && status !== "allowed")) {
      if (!isBlocked) bucket.error_count += 1;
    }
    if (typeof event.latency_ms === "number" && event.latency_ms >= 0) {
      bucket.total_latency_ms += event.latency_ms;
      bucket.latency_samples += 1;
    }
    if (typeof event.timestamp === "string" && event.timestamp.length > 0) {
      if (bucket.last_called_at == null || bucket.last_called_at < event.timestamp) {
        bucket.last_called_at = event.timestamp;
      }
    }
    const perTool = bucket.per_tool[tool];
    perTool.call_count += 1;
    if (ok) perTool.success_count += 1;
    if (isBlocked) perTool.blocked_count += 1;
    if (event.error_code != null || event.error != null || (status != null && status !== "ok" && status !== "success" && status !== "allowed")) {
      if (!isBlocked) perTool.error_count += 1;
    }
    if (typeof event.latency_ms === "number" && event.latency_ms >= 0) {
      perTool.total_latency_ms += event.latency_ms;
      perTool.latency_samples += 1;
    }
  }
  return emitFinalMetrics(buckets);
}

function readCapabilityMetrics({ target_domain, env } = {}) {
  const events = readToolTelemetryEvents({ target_domain, env });
  return {
    schema_version: 1,
    target_domain: target_domain || null,
    capabilities: summarizeCapabilityMetrics(events),
    capability_count: Object.keys(CAPABILITY_TO_TOOLS).length,
    total_events_scanned: Array.isArray(events) ? events.length : 0,
  };
}

module.exports = {
  CAPABILITY_TO_TOOLS,
  summarizeCapabilityMetrics,
  readCapabilityMetrics,
};
