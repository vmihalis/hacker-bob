"use strict";

let implementations = null;

function configurePhysicalCapabilityPackRuntimePorts(ports) {
  if (implementations !== null) {
    throw new Error("physical capability-pack runtime ports are already configured");
  }
  const required = ["artifacts", "grade", "evidence"];
  if (ports == null || typeof ports !== "object"
      || required.some((name) => typeof ports[name] !== "function")) {
    throw new Error("physical capability-pack runtime ports are incomplete");
  }
  implementations = Object.freeze({
    artifacts: ports.artifacts,
    grade: ports.grade,
    evidence: ports.evidence,
  });
}

function invoke(name, args) {
  if (implementations === null) {
    throw new Error("physical capability-pack runtime ports are not configured");
  }
  return implementations[name](...args);
}

const PHYSICAL_CAPABILITY_PACK_ADAPTERS = Object.freeze({
  artifacts: Object.freeze({
    physical_verified_transition_artifacts_v1: (...args) => invoke("artifacts", args),
  }),
  grade: Object.freeze({
    physical_verified_transition_grade_binding_v1: (...args) => invoke("grade", args),
  }),
  evidence: Object.freeze({
    physical_report_safe_evidence_pack_v1: (...args) => invoke("evidence", args),
  }),
});

module.exports = Object.freeze({
  configurePhysicalCapabilityPackRuntimePorts,
  PHYSICAL_CAPABILITY_PACK_ADAPTERS,
});
