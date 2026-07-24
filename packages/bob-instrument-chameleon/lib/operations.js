"use strict";

// PH-P4 is the immutable, transport-free Chameleon Ultra semantic manifest.
// The reviewed registry is embedded in this package release. Runtime code must
// never load docs/plane-physical, enumerate/open hardware, or accept raw command,
// frame, APDU, responder, or device-administration input from an evaluator.

const crypto = require("node:crypto");
const {
  isAsyncFunction,
  isPromise,
  isProxy,
} = require("node:util").types;
const {
  CHAMELEON_AVAILABILITY_BACKEND_VERSION,
  assertChameleonAvailabilityEvidenceBackendProjection,
  resolveChameleonAvailabilityEvidenceBackend,
} = require("./availability-evidence-backend.js");

const MANIFEST_VERSION = 1;
const PROVIDER_ID = "chameleon_ultra";
const HASH_PATTERN = /^[a-f0-9]{64}$/u;
const DOMAIN_PATTERN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const OPERATION_ID_PATTERN = /^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$/u;
const CAPABILITY_ID_PATTERN = /^CU-[A-Z0-9]+(?:-[A-Z0-9]+)*$/u;
const VARIANT_ID_PATTERN = /^[a-z][a-z0-9._-]*$/u;
const ASSURANCE_AXES = Object.freeze([
  "identity_enrollment",
  "firmware_provenance",
  "command_surface_conformance",
  "transport_trust",
]);
const EVALUATOR_EXPOSURE = "technique_compiled";
const EVALUATOR_DISPOSITIONS = new Set(["planned", "optional"]);
const COMMAND_SOURCE_PROFILE_ID = "chameleon_ultra_v2_2_0_source_pinned_v1";
const DECLARATION_SYMBOL_PATTERN = /^DATA_CMD_[A-Z0-9_]+$/u;
const RUNTIME_SYMBOL_PATTERN = /^[a-z][a-z0-9_]*$/u;
const AVAILABILITY_PROJECTIONS = new WeakSet();
const AVAILABILITY_EVIDENCE_PROJECTIONS = new WeakSet();
const TEST_AVAILABILITY_EVIDENCE_RESOLVER_PORTS = new WeakSet();
const TEST_AVAILABILITY_EVIDENCE_RESOLVER_STATE = new WeakMap();
const CHAMELEON_AVAILABILITY_EVIDENCE_VERSION = 1;
const AVAILABILITY_EVIDENCE_RESOLVER_PORT_VERSION =
  CHAMELEON_AVAILABILITY_EVIDENCE_VERSION;
const AVAILABILITY_EVIDENCE_VERIFICATION_MODEL =
  "synchronous_exact_evidence_and_current_state";
const TEST_AVAILABILITY_EVIDENCE_ASSURANCE =
  "test_only_injected_callbacks_no_production_verifier_backend";
const AVAILABILITY_MANIFEST_BINDING_FIELDS = Object.freeze([
  "semantic_manifest_digest",
  "source_profile_digest",
  "codec_profile_digest",
  "assurance_profile_registry_digest",
  "dependency_proof_registry_digest",
]);
const AVAILABILITY_IDENTITY_BINDING_FIELDS = Object.freeze([
  "inventory_projection_digest",
  "device_identity_digest",
  "custody_id",
  "custody_projection_digest",
  "session_id",
  "authority_id",
  "authority_epoch",
  "revocation_generation",
  "authority_resolution_digest",
]);
const AVAILABILITY_EVIDENCE_REQUEST_FIELDS = Object.freeze([
  "version",
  "provider_id",
  "evidence_ref",
  ...AVAILABILITY_MANIFEST_BINDING_FIELDS,
  ...AVAILABILITY_IDENTITY_BINDING_FIELDS,
]);
const PRODUCTION_AVAILABILITY_EVIDENCE_REQUEST_FIELDS = Object.freeze([
  "version",
  "provider_id",
  "evidence_ref",
  "target_domain",
  "session_nucleus_hash",
  ...AVAILABILITY_MANIFEST_BINDING_FIELDS,
  ...AVAILABILITY_IDENTITY_BINDING_FIELDS,
]);
const AVAILABILITY_VARIANT_QUALIFICATION_FIELDS = Object.freeze([
  "version",
  "provider_id",
  "capability_id",
  "variant_id",
  "availability_variant_digest",
  "parameter_selector_id",
  "normalized_operations_digest",
  "technique_bindings_digest",
  "effect_profile_refs_digest",
  "request_context_digest",
  "dependency_binding_digest",
  "reported_command_ids_digest",
  "assurance_claims_digest",
  "dependency_proofs_digest",
  "alternative_selections_digest",
  "qualification_digest",
]);

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || isProxy(value) || Array.isArray(value)) {
    return false;
  }
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

function assertDataArray(value, label, maximum) {
  if (isProxy(value) || !Array.isArray(value) || value.length > maximum) {
    throw new Error(`${label} must be a bounded data array`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || !descriptor.enumerable) {
      throw new Error(`${label} must be a dense enumerable data array`);
    }
  }
  const extra = Reflect.ownKeys(descriptors).filter((field) => (
    field !== "length" && (typeof field !== "string" || !/^\d+$/u.test(field))
  ));
  if (extra.length > 0) throw new Error(`${label} cannot contain extra or symbol fields`);
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertOpaqueIdentity(value, label) {
  if (typeof value !== "string" || value.length < 1 || value.length > 256
      || !/^[A-Za-z0-9][A-Za-z0-9:._/-]*$/u.test(value)) {
    throw new Error(`${label} must be a bounded opaque identity`);
  }
  return value;
}

function assertSafeInteger(value, label, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) {
    throw new Error(`${label} must be a safe integer greater than or equal to ${minimum}`);
  }
  return value;
}

function assertBoolean(value, label) {
  if (typeof value !== "boolean") throw new Error(`${label} must be a boolean`);
  return value;
}

function assertTimestamp(value, label) {
  if (typeof value !== "string") throw new Error(`${label} must be an ISO timestamp`);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw new Error(`${label} must be a canonical ISO timestamp`);
  }
  return value;
}

function hashJson(value) {
  return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function sorted(values) {
  return [...values].sort((left, right) => String(left).localeCompare(String(right)));
}

function sameValues(left, right) {
  return left.length === right.length
    && left.every((value, index) => value === right[index]);
}

function normalizeCommandIds(value, label) {
  assertDataArray(value, label, 4096);
  const ids = value.map((entry, index) => {
    if (!Number.isSafeInteger(entry) || entry < 1 || entry > 0xffff) {
      throw new Error(`${label}[${index}] must be an unsigned 16-bit command ID`);
    }
    return entry;
  });
  if (new Set(ids).size !== ids.length) throw new Error(`${label} must not contain duplicates`);
  return Object.freeze([...ids].sort((left, right) => left - right));
}

// Replaced at review time from docs/plane-physical/coverage.json. This literal
// is deliberately package-local and is never regenerated or widened at runtime.
const REVIEWED_DATA = deepFreeze(
{
  "schema_version": 1,
  "graph_id": "plane-physical-security",
  "version": "v0.3-proposed (2026-07-17)",
  "provider": "chameleon_ultra",
  "provider_baseline": "upstream v2.2.0 acceptance envelope; runtime availability requires assurance-qualified inventory, operator enrollment where declared, and provider conformance",
  "coverage_contract": "device surface -> normalized provider operation -> generic technique binding; no layer implies the next",
  "runtime_rule": "effect profiles are maximum templates only; every execution binds exact subject refs and bounds in a single-use broker grant",
  "upstream_command_registry": {
    "version": "v2.2.0",
    "source_commit": "f349dbeeaa315776b272ae8fb851cc4042d55f07",
    "declaration_source": "https://github.com/RfidResearchGroup/ChameleonUltra/blob/v2.2.0/firmware/application/src/data_cmd.h",
    "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
    "registry_source": "https://github.com/RfidResearchGroup/ChameleonUltra/blob/v2.2.0/firmware/application/src/app_cmd.c",
    "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
    "declared_command_ids": [
      1000,
      1001,
      1002,
      1003,
      1004,
      1005,
      1006,
      1007,
      1008,
      1009,
      1010,
      1011,
      1012,
      1013,
      1014,
      1015,
      1016,
      1017,
      1018,
      1019,
      1020,
      1021,
      1023,
      1024,
      1025,
      1026,
      1027,
      1028,
      1029,
      1030,
      1031,
      1032,
      1033,
      1034,
      1035,
      1036,
      1037,
      1038,
      1039,
      1040,
      2000,
      2001,
      2002,
      2003,
      2004,
      2005,
      2006,
      2007,
      2008,
      2009,
      2010,
      2011,
      2012,
      2013,
      2014,
      2015,
      2016,
      2017,
      2020,
      2100,
      2101,
      2200,
      2201,
      3000,
      3001,
      3002,
      3003,
      3004,
      3005,
      3006,
      3007,
      3008,
      3009,
      3010,
      3011,
      3012,
      3013,
      3014,
      3015,
      3016,
      3018,
      3019,
      3020,
      3030,
      3031,
      3032,
      4000,
      4001,
      4004,
      4005,
      4006,
      4007,
      4008,
      4009,
      4010,
      4011,
      4012,
      4013,
      4014,
      4015,
      4016,
      4017,
      4018,
      4019,
      4020,
      4021,
      4022,
      4023,
      4024,
      4025,
      4026,
      4027,
      4028,
      4029,
      4030,
      4031,
      4032,
      4033,
      4034,
      4035,
      4036,
      4037,
      4038,
      4039,
      4040,
      4041,
      5000,
      5001,
      5002,
      5003,
      5004,
      5005,
      5006,
      5007,
      5008,
      5009,
      5010,
      5011,
      5012,
      5013,
      6000,
      6001,
      6002,
      6003,
      6004,
      6005
    ],
    "declared_unregistered_ids": [
      3007,
      3008,
      3032
    ],
    "registry_private_ids": [
      6010
    ],
    "command_ownership_sha256": "f92a84341f8d79b0340071fe90eb00beafab1cc3b099f2e6252299e744aab2f7",
    "coverage_semantics_sha256": "5e197912d21dafc7c99c9ece6cdca645913ddc23a74151436b71ea5ff2b78e12",
    "expected_ultra_capabilities_rule": "declared_command_ids - declared_unregistered_ids + registry_private_ids"
  },
  "declared_command_ids_sha256": "cfe13141d3e196c456546a678ff9c1a0a0bdd296bbaef9ffec0805e6f20a23e4",
  "assurance_profile_registry": {
    "bootstrap_read_only": {
      "identity_enrollment": "unverified",
      "firmware_provenance": "self_reported",
      "command_surface_conformance": "bootstrap_allowlisted",
      "transport_trust": "local_observed"
    },
    "enrolled_conformance_tested": {
      "identity_enrollment": "operator_enrolled",
      "firmware_provenance": "operator_pinned",
      "command_surface_conformance": "conformance_tested",
      "transport_trust": "operator_provisioned"
    },
    "enrolled_source_pinned": {
      "identity_enrollment": "operator_enrolled",
      "firmware_provenance": "operator_pinned",
      "command_surface_conformance": "manifest_intersected",
      "transport_trust": "operator_provisioned"
    },
    "offline_local": {
      "identity_enrollment": "not_required",
      "firmware_provenance": "not_required",
      "command_surface_conformance": "not_required",
      "transport_trust": "not_required"
    },
    "unavailable": {
      "identity_enrollment": "not_applicable",
      "firmware_provenance": "not_applicable",
      "command_surface_conformance": "not_applicable",
      "transport_trust": "not_applicable"
    }
  },
  "assurance_profile_registry_sha256": "6ca848e291e9630560fef47875e4f111b24f418804d5b271f517d3243d3e9c55",
  "assurance_satisfaction_registry": {
    "identity_enrollment": {
      "not_required": [
        "not_required"
      ],
      "unverified": [
        "not_required",
        "unverified"
      ],
      "operator_enrolled": [
        "not_required",
        "unverified",
        "operator_enrolled"
      ],
      "hardware_bound": [
        "not_required",
        "unverified",
        "operator_enrolled",
        "hardware_bound"
      ],
      "not_applicable": [
        "not_required",
        "not_applicable"
      ]
    },
    "firmware_provenance": {
      "not_required": [
        "not_required"
      ],
      "self_reported": [
        "not_required",
        "self_reported"
      ],
      "operator_pinned": [
        "not_required",
        "self_reported",
        "operator_pinned"
      ],
      "hardware_attested": [
        "not_required",
        "self_reported",
        "operator_pinned",
        "hardware_attested"
      ],
      "not_applicable": [
        "not_required",
        "not_applicable"
      ]
    },
    "command_surface_conformance": {
      "not_required": [
        "not_required"
      ],
      "bootstrap_allowlisted": [
        "not_required",
        "bootstrap_allowlisted"
      ],
      "manifest_intersected": [
        "not_required",
        "bootstrap_allowlisted",
        "manifest_intersected"
      ],
      "conformance_tested": [
        "not_required",
        "bootstrap_allowlisted",
        "manifest_intersected",
        "conformance_tested"
      ],
      "not_applicable": [
        "not_required",
        "not_applicable"
      ]
    },
    "transport_trust": {
      "not_required": [
        "not_required"
      ],
      "local_observed": [
        "not_required",
        "local_observed"
      ],
      "operator_provisioned": [
        "not_required",
        "local_observed",
        "operator_provisioned"
      ],
      "hardware_attested": [
        "not_required",
        "local_observed",
        "operator_provisioned",
        "hardware_attested"
      ],
      "not_applicable": [
        "not_required",
        "not_applicable"
      ]
    }
  },
  "assurance_satisfaction_registry_sha256": "3da45ca0dd100715317e704bbb0e7a603e490f4398f3e0b15ac1f17563f808df",
  "normalized_operation_registry": {
    "emulator.configure": {
      "exposure": "technique_compiled",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "emulator.present": {
      "exposure": "technique_compiled",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "emulator.profile_configure": {
      "exposure": "technique_compiled",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "emulator.profile_observe": {
      "exposure": "provider_private",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "instrument.admin_configure": {
      "exposure": "operator_only",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "instrument.capabilities": {
      "exposure": "provider_private",
      "minimum_assurance_profile_id": "bootstrap_read_only"
    },
    "instrument.enrollment_match": {
      "exposure": "provider_private",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "instrument.erase": {
      "exposure": "operator_only",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "instrument.firmware_manage": {
      "exposure": "operator_only",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "instrument.health": {
      "exposure": "provider_private",
      "minimum_assurance_profile_id": "bootstrap_read_only"
    },
    "instrument.identity_observe": {
      "exposure": "provider_private",
      "minimum_assurance_profile_id": "bootstrap_read_only"
    },
    "instrument.inventory": {
      "exposure": "provider_private",
      "minimum_assurance_profile_id": "bootstrap_read_only"
    },
    "instrument.manual_action": {
      "exposure": "operator_only",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "instrument.restore": {
      "exposure": "provider_private",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "interaction.trace": {
      "exposure": "technique_compiled",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "protocol.apdu_exchange": {
      "exposure": "provider_private",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "protocol.authenticate": {
      "exposure": "technique_compiled",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "protocol.challenge_collect": {
      "exposure": "technique_compiled",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "protocol.compiled_exchange": {
      "exposure": "technique_compiled",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "protocol.compiled_responder": {
      "exposure": "technique_compiled",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "protocol.diagnostics_observe": {
      "exposure": "provider_private",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "protocol.discovery_probe": {
      "exposure": "technique_compiled",
      "minimum_assurance_profile_id": "enrolled_conformance_tested"
    },
    "protocol.discover": {
      "exposure": "technique_compiled",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "protocol.relay": {
      "exposure": "unsupported",
      "minimum_assurance_profile_id": "unavailable"
    },
    "protocol.respond": {
      "exposure": "provider_private",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "protocol.transceive": {
      "exposure": "provider_private",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "provider.command_correlate": {
      "exposure": "provider_private",
      "minimum_assurance_profile_id": "offline_local"
    },
    "provider.frame_decode": {
      "exposure": "provider_private",
      "minimum_assurance_profile_id": "offline_local"
    },
    "provider.frame_encode": {
      "exposure": "provider_private",
      "minimum_assurance_profile_id": "offline_local"
    },
    "reader_profile.configure": {
      "exposure": "provider_private",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "reader_profile.observe": {
      "exposure": "provider_private",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "representation.compose": {
      "exposure": "technique_compiled",
      "minimum_assurance_profile_id": "offline_local"
    },
    "representation.decode": {
      "exposure": "technique_compiled",
      "minimum_assurance_profile_id": "offline_local"
    },
    "representation.decode_raw": {
      "exposure": "unsupported",
      "minimum_assurance_profile_id": "unavailable"
    },
    "representation.fingerprint": {
      "exposure": "technique_compiled",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "representation.read": {
      "exposure": "technique_compiled",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "representation.stage": {
      "exposure": "technique_compiled",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "representation.write": {
      "exposure": "technique_compiled",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "response_profile.stage": {
      "exposure": "technique_compiled",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "rf_session.acquire": {
      "exposure": "provider_private",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "rf_session.observe": {
      "exposure": "provider_private",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "rf_session.release": {
      "exposure": "provider_private",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "signal.capture": {
      "exposure": "technique_compiled",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "signal.capture_passive": {
      "exposure": "unsupported",
      "minimum_assurance_profile_id": "unavailable"
    },
    "trace.derive": {
      "exposure": "technique_compiled",
      "minimum_assurance_profile_id": "offline_local"
    },
    "transport.connect": {
      "exposure": "provider_private",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "transport.disconnect": {
      "exposure": "provider_private",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "transport.exchange": {
      "exposure": "provider_private",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "workspace.restore": {
      "exposure": "provider_private",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    },
    "workspace.snapshot": {
      "exposure": "provider_private",
      "minimum_assurance_profile_id": "enrolled_source_pinned"
    }
  },
  "normalized_operation_registry_sha256": "2d048b7a95212ebf3dab3880465c5a920fb2236ac591334a3c940dab606ce8f1",
  "capability_dependency_registry": {
    "CU-CORE-INVENTORY": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "identity_version": {
          "parameter_selector_id": "identity_version",
          "all_of": [
            "command:1000",
            "command:1017",
            "command:1033"
          ],
          "any_of": [],
          "normalized_operations": [
            "instrument.inventory"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-INSTRUMENT-OBSERVE-USB"
          ]
        },
        "capabilities": {
          "parameter_selector_id": "capabilities",
          "all_of": [
            "command:1035"
          ],
          "any_of": [],
          "normalized_operations": [
            "instrument.capabilities"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-INSTRUMENT-OBSERVE-USB"
          ]
        },
        "battery_health": {
          "parameter_selector_id": "battery_health",
          "all_of": [
            "command:1025"
          ],
          "any_of": [],
          "normalized_operations": [
            "instrument.health"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-INSTRUMENT-OBSERVE-USB"
          ]
        }
      }
    },
    "CU-CORE-IDENTITY-ENROLLMENT": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "enrollment_inputs": {
          "parameter_selector_id": "enrollment_inputs",
          "all_of": [
            "command:1011",
            "command:1012"
          ],
          "any_of": [],
          "normalized_operations": [
            "instrument.identity_observe",
            "instrument.enrollment_match"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-INSTRUMENT-OBSERVE-USB"
          ]
        }
      }
    },
    "CU-CORE-FRAME-CODEC": {
      "all_of": [
        "conformance:chameleon_frame_codec_v1"
      ],
      "any_of": [],
      "variants": {
        "default": {
          "parameter_selector_id": "default",
          "all_of": [],
          "any_of": [],
          "normalized_operations": [
            "provider.frame_encode",
            "provider.frame_decode",
            "provider.command_correlate"
          ],
          "technique_bindings": [],
          "effect_profile_refs": []
        }
      }
    },
    "CU-TRANSPORT-USB": {
      "all_of": [
        "transport:usb_cdc_acm_115200_dtr_v1"
      ],
      "any_of": [],
      "variants": {
        "default": {
          "parameter_selector_id": "default",
          "all_of": [],
          "any_of": [],
          "normalized_operations": [
            "transport.connect",
            "transport.exchange",
            "transport.disconnect"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-INSTRUMENT-TRANSMIT-USB"
          ]
        }
      }
    },
    "CU-TRANSPORT-BLE": {
      "all_of": [
        "transport:ble_nus_v1"
      ],
      "any_of": [],
      "variants": {
        "default": {
          "parameter_selector_id": "default",
          "all_of": [],
          "any_of": [],
          "normalized_operations": [
            "transport.connect",
            "transport.exchange",
            "transport.disconnect"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-INSTRUMENT-TRANSMIT-BLE"
          ]
        }
      }
    },
    "CU-WORKSPACE-SLOTS": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "snapshot": {
          "parameter_selector_id": "snapshot",
          "all_of": [
            "command:1008",
            "command:1018",
            "command:1019",
            "command:1023",
            "command:1038"
          ],
          "any_of": [],
          "normalized_operations": [
            "workspace.snapshot"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-INSTRUMENT-OBSERVE-USB"
          ]
        },
        "stage": {
          "parameter_selector_id": "stage",
          "all_of": [
            "command:1003",
            "command:1004",
            "command:1005",
            "command:1006",
            "command:1007",
            "command:1009"
          ],
          "any_of": [],
          "normalized_operations": [
            "representation.stage"
          ],
          "technique_bindings": [
            "credential.stage_representation"
          ],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB"
          ]
        },
        "restore": {
          "parameter_selector_id": "restore",
          "all_of": [
            "command:1003",
            "command:1004",
            "command:1005",
            "command:1006",
            "command:1007",
            "command:1009",
            "command:1021",
            "command:1024"
          ],
          "any_of": [],
          "normalized_operations": [
            "workspace.restore"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB"
          ]
        }
      }
    },
    "CU-RF-SESSION": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "mode_observe": {
          "parameter_selector_id": "mode_observe",
          "all_of": [
            "command:1002"
          ],
          "any_of": [],
          "normalized_operations": [
            "rf_session.observe"
          ],
          "technique_bindings": [],
          "effect_profile_refs": []
        },
        "mode_change": {
          "parameter_selector_id": "mode_change",
          "all_of": [
            "command:1001"
          ],
          "any_of": [],
          "normalized_operations": [
            "rf_session.acquire",
            "rf_session.release",
            "instrument.restore"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB",
            "EP-TARGET-PRESENT-RF"
          ]
        },
        "field_on": {
          "parameter_selector_id": "field_on",
          "all_of": [
            "command:2100"
          ],
          "any_of": [],
          "normalized_operations": [
            "rf_session.acquire"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB",
            "EP-TARGET-TRANSMIT-RF",
            "EP-ENVIRONMENT-TRANSMIT-RF"
          ]
        },
        "field_off": {
          "parameter_selector_id": "field_off",
          "all_of": [
            "command:2101"
          ],
          "any_of": [],
          "normalized_operations": [
            "rf_session.release",
            "instrument.restore"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB"
          ]
        }
      }
    },
    "CU-HF-14A-DISCOVERY": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "default": {
          "parameter_selector_id": "default",
          "all_of": [
            "command:2000"
          ],
          "any_of": [],
          "normalized_operations": [
            "protocol.discover",
            "representation.fingerprint"
          ],
          "technique_bindings": [
            "credential.classify"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF"
          ]
        }
      }
    },
    "CU-HF-14A-RAW": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "default": {
          "parameter_selector_id": "default",
          "all_of": [
            "command:2010"
          ],
          "any_of": [],
          "normalized_operations": [
            "protocol.transceive"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF",
            "EP-TARGET-MUTATE-RF-STATEFUL",
            "EP-TARGET-DESTROY-RF"
          ]
        }
      }
    },
    "CU-HF-14A-COMPILED-PROBE": {
      "all_of": [
        "capability_variant:CU-HF-14A-RAW/default",
        "compiler:iso14443a_closed_probe_v1",
        "conformance:chameleon_hf14a_closed_probe_v1"
      ],
      "any_of": [],
      "variants": {
        "requa_atqa_v1": {
          "parameter_selector_id": "requa_atqa_v1",
          "all_of": [],
          "any_of": [],
          "normalized_operations": [
            "protocol.discovery_probe"
          ],
          "technique_bindings": [
            "protocol.probe"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF"
          ]
        },
        "wupa_atqa_v1": {
          "parameter_selector_id": "wupa_atqa_v1",
          "all_of": [],
          "any_of": [],
          "normalized_operations": [
            "protocol.discovery_probe"
          ],
          "technique_bindings": [
            "protocol.probe"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF"
          ]
        }
      }
    },
    "CU-HF-14A-ACTIVE-TRACE": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "default": {
          "parameter_selector_id": "default",
          "all_of": [
            "command:2020"
          ],
          "any_of": [],
          "normalized_operations": [
            "emulator.present",
            "interaction.trace"
          ],
          "technique_bindings": [
            "verifier.interaction_trace",
            "protocol.frame_analysis"
          ],
          "effect_profile_refs": [
            "EP-TARGET-PRESENT-RF"
          ]
        }
      }
    },
    "CU-HF-14A-READER-CONFIG": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "observe": {
          "parameter_selector_id": "observe",
          "all_of": [
            "command:2200"
          ],
          "any_of": [],
          "normalized_operations": [
            "reader_profile.observe"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-INSTRUMENT-OBSERVE-USB"
          ]
        },
        "compatibility_profile": {
          "parameter_selector_id": "compatibility_profile",
          "all_of": [
            "command:2200",
            "command:2201"
          ],
          "any_of": [],
          "normalized_operations": [
            "reader_profile.observe",
            "reader_profile.configure"
          ],
          "technique_bindings": [
            "protocol.compatibility_probe"
          ],
          "effect_profile_refs": [
            "EP-INSTRUMENT-OBSERVE-USB",
            "EP-INSTRUMENT-CONFIGURE-USB"
          ]
        }
      }
    },
    "CU-HF-ISO14443-4-APDU": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "reader_apdu": {
          "parameter_selector_id": "reader_apdu",
          "all_of": [
            "command:6004"
          ],
          "any_of": [],
          "normalized_operations": [
            "protocol.apdu_exchange"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF",
            "EP-TARGET-MUTATE-RF-STATEFUL",
            "EP-TARGET-DESTROY-RF"
          ]
        },
        "scan_keep_reader_apdu": {
          "parameter_selector_id": "scan_keep_reader_apdu",
          "all_of": [
            "command:2016",
            "command:6004"
          ],
          "any_of": [],
          "normalized_operations": [
            "protocol.apdu_exchange"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF",
            "EP-TARGET-MUTATE-RF-STATEFUL",
            "EP-TARGET-DESTROY-RF"
          ]
        }
      }
    },
    "CU-HF-MFC-ACQUIRE": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "support_probe": {
          "parameter_selector_id": "support_probe",
          "all_of": [
            "command:2001"
          ],
          "any_of": [],
          "normalized_operations": [
            "protocol.authenticate"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF"
          ]
        },
        "acquire_read": {
          "parameter_selector_id": "acquire_read",
          "all_of": [
            "command:2007",
            "command:2008"
          ],
          "any_of": [],
          "normalized_operations": [
            "protocol.authenticate",
            "representation.read"
          ],
          "technique_bindings": [
            "credential.acquire"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF"
          ]
        },
        "sector_key_candidates": {
          "parameter_selector_id": "sector_key_candidates",
          "all_of": [
            "command:2012"
          ],
          "any_of": [],
          "normalized_operations": [
            "protocol.authenticate"
          ],
          "technique_bindings": [
            "secret.check_candidates"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF"
          ]
        },
        "block_key_candidates": {
          "parameter_selector_id": "block_key_candidates",
          "all_of": [
            "command:2015"
          ],
          "any_of": [],
          "normalized_operations": [
            "protocol.authenticate"
          ],
          "technique_bindings": [
            "secret.check_candidates"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF"
          ]
        }
      }
    },
    "CU-HF-MFC-RECOVERY": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "prng_classification": {
          "parameter_selector_id": "prng_classification",
          "all_of": [
            "command:2002"
          ],
          "any_of": [],
          "normalized_operations": [
            "protocol.challenge_collect"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF"
          ]
        },
        "static_nested": {
          "parameter_selector_id": "static_nested",
          "all_of": [
            "command:2003",
            "vault_tool:classic_static_nested_recovery_v1"
          ],
          "any_of": [],
          "normalized_operations": [
            "protocol.challenge_collect",
            "representation.read"
          ],
          "technique_bindings": [
            "secret.recover.static_nested"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF"
          ]
        },
        "darkside": {
          "parameter_selector_id": "darkside",
          "all_of": [
            "command:2004",
            "vault_tool:classic_darkside_recovery_v1"
          ],
          "any_of": [],
          "normalized_operations": [
            "protocol.challenge_collect",
            "representation.read"
          ],
          "technique_bindings": [
            "secret.recover.darkside"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF"
          ]
        },
        "nested": {
          "parameter_selector_id": "nested",
          "all_of": [
            "command:2005",
            "command:2006",
            "vault_tool:classic_nested_recovery_v1"
          ],
          "any_of": [],
          "normalized_operations": [
            "protocol.challenge_collect",
            "representation.read"
          ],
          "technique_bindings": [
            "secret.recover.nested"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF"
          ]
        },
        "hardnested": {
          "parameter_selector_id": "hardnested",
          "all_of": [
            "command:2013",
            "vault_tool:classic_hardnested_recovery_v1"
          ],
          "any_of": [],
          "normalized_operations": [
            "protocol.challenge_collect",
            "representation.read"
          ],
          "technique_bindings": [
            "secret.recover.hardnested"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF"
          ]
        },
        "encrypted_nested": {
          "parameter_selector_id": "encrypted_nested",
          "all_of": [
            "command:2014",
            "vault_tool:classic_encrypted_nested_recovery_v1"
          ],
          "any_of": [],
          "normalized_operations": [
            "protocol.challenge_collect",
            "representation.read"
          ],
          "technique_bindings": [
            "secret.recover.encrypted_nested"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF"
          ]
        },
        "autopwn": {
          "parameter_selector_id": "autopwn",
          "all_of": [
            "capability_variant:CU-HF-MFC-ACQUIRE/acquire_read",
            "vault_tool:classic_autopwn_v1"
          ],
          "any_of": [
            [
              "capability_variant:CU-HF-MFC-RECOVERY/static_nested",
              "capability_variant:CU-HF-MFC-RECOVERY/darkside",
              "capability_variant:CU-HF-MFC-RECOVERY/nested",
              "capability_variant:CU-HF-MFC-RECOVERY/hardnested",
              "capability_variant:CU-HF-MFC-RECOVERY/encrypted_nested"
            ]
          ],
          "normalized_operations": [
            "protocol.challenge_collect",
            "representation.read"
          ],
          "technique_bindings": [
            "secret.recover.autopwn"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF"
          ]
        }
      }
    },
    "CU-HF-MFC-AUTH-TRACE": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "default": {
          "parameter_selector_id": "default",
          "all_of": [
            "command:2017"
          ],
          "any_of": [],
          "normalized_operations": [
            "protocol.authenticate",
            "interaction.trace"
          ],
          "technique_bindings": [
            "credential.auth_trace",
            "protocol.frame_analysis"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF"
          ]
        }
      }
    },
    "CU-HF-MFC-EMULATOR-TRACE": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "trace": {
          "parameter_selector_id": "trace",
          "all_of": [
            "command:4004",
            "command:4005",
            "command:4006",
            "command:4007"
          ],
          "any_of": [],
          "normalized_operations": [
            "emulator.present",
            "interaction.trace"
          ],
          "technique_bindings": [
            "verifier.interaction_trace"
          ],
          "effect_profile_refs": [
            "EP-TARGET-PRESENT-RF"
          ]
        }
      }
    },
    "CU-HF-MFC-TRACE-RECOVERY": {
      "all_of": [
        "capability_variant:CU-HF-MFC-AUTH-TRACE/default",
        "vault_tool:classic_trace_recovery_v1"
      ],
      "any_of": [],
      "variants": {
        "default": {
          "parameter_selector_id": "default",
          "all_of": [],
          "any_of": [],
          "normalized_operations": [
            "trace.derive"
          ],
          "technique_bindings": [
            "secret.recover_from_trace"
          ],
          "effect_profile_refs": []
        }
      }
    },
    "CU-HF-14A-EMULATOR-CONFIG": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "observe": {
          "parameter_selector_id": "observe",
          "all_of": [
            "command:4018"
          ],
          "any_of": [],
          "normalized_operations": [
            "emulator.profile_observe"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-INSTRUMENT-OBSERVE-USB"
          ]
        },
        "configure": {
          "parameter_selector_id": "configure",
          "all_of": [
            "command:4001"
          ],
          "any_of": [],
          "normalized_operations": [
            "emulator.profile_configure"
          ],
          "technique_bindings": [
            "credential.stage_representation"
          ],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB"
          ]
        }
      }
    },
    "CU-HF-MFC-EMULATION": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "base_memory": {
          "parameter_selector_id": "base_memory",
          "all_of": [
            "command:4000",
            "command:4008",
            "command:4009"
          ],
          "any_of": [],
          "normalized_operations": [
            "representation.stage",
            "emulator.configure",
            "emulator.present"
          ],
          "technique_bindings": [
            "credential.replay"
          ],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB",
            "EP-TARGET-PRESENT-RF"
          ]
        },
        "gen1a": {
          "parameter_selector_id": "gen1a",
          "all_of": [
            "command:4010",
            "command:4011"
          ],
          "any_of": [],
          "normalized_operations": [
            "emulator.configure",
            "emulator.present"
          ],
          "technique_bindings": [
            "credential.replay"
          ],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB",
            "EP-TARGET-PRESENT-RF"
          ]
        },
        "gen2": {
          "parameter_selector_id": "gen2",
          "all_of": [
            "command:4012",
            "command:4013"
          ],
          "any_of": [],
          "normalized_operations": [
            "emulator.configure",
            "emulator.present"
          ],
          "technique_bindings": [
            "credential.replay"
          ],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB",
            "EP-TARGET-PRESENT-RF"
          ]
        },
        "block_anticollision": {
          "parameter_selector_id": "block_anticollision",
          "all_of": [
            "command:4014",
            "command:4015"
          ],
          "any_of": [],
          "normalized_operations": [
            "emulator.configure",
            "emulator.present"
          ],
          "technique_bindings": [
            "credential.replay"
          ],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB",
            "EP-TARGET-PRESENT-RF"
          ]
        },
        "write_mode": {
          "parameter_selector_id": "write_mode",
          "all_of": [
            "command:4016",
            "command:4017"
          ],
          "any_of": [],
          "normalized_operations": [
            "emulator.configure",
            "emulator.present"
          ],
          "technique_bindings": [
            "credential.replay"
          ],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB",
            "EP-TARGET-PRESENT-RF"
          ]
        },
        "field_reset": {
          "parameter_selector_id": "field_reset",
          "all_of": [
            "command:4038",
            "command:4039"
          ],
          "any_of": [],
          "normalized_operations": [
            "emulator.configure",
            "emulator.present"
          ],
          "technique_bindings": [
            "credential.replay"
          ],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB",
            "EP-TARGET-PRESENT-RF"
          ]
        },
        "prng_profile": {
          "parameter_selector_id": "prng_profile",
          "all_of": [
            "command:4040",
            "command:4041"
          ],
          "any_of": [],
          "normalized_operations": [
            "emulator.configure",
            "emulator.present"
          ],
          "technique_bindings": [
            "credential.replay"
          ],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB",
            "EP-TARGET-PRESENT-RF"
          ]
        }
      }
    },
    "CU-HF-MFC-WRITE": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "block_write": {
          "parameter_selector_id": "block_write",
          "all_of": [
            "command:2009"
          ],
          "any_of": [],
          "normalized_operations": [
            "representation.write"
          ],
          "technique_bindings": [
            "credential.mutate"
          ],
          "effect_profile_refs": [
            "EP-TARGET-MUTATE-RF"
          ]
        },
        "value_semantics": {
          "parameter_selector_id": "value_semantics",
          "all_of": [
            "command:2011"
          ],
          "any_of": [],
          "normalized_operations": [
            "representation.read",
            "representation.write"
          ],
          "technique_bindings": [
            "credential.value_semantics_probe"
          ],
          "effect_profile_refs": [
            "EP-TARGET-MUTATE-RF"
          ]
        }
      }
    },
    "CU-HF-MFU-ACQUIRE": {
      "all_of": [
        "capability_variant:CU-HF-14A-RAW/default",
        "compiler:mfu_acquire_v1",
        "vault_tool:mfu_secret_transform_v1"
      ],
      "any_of": [],
      "variants": {
        "plain_read": {
          "parameter_selector_id": "plain_read",
          "all_of": [],
          "any_of": [],
          "normalized_operations": [
            "protocol.discover",
            "representation.read"
          ],
          "technique_bindings": [
            "credential.classify",
            "credential.acquire"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF"
          ]
        },
        "authenticated_read": {
          "parameter_selector_id": "authenticated_read",
          "all_of": [],
          "any_of": [],
          "normalized_operations": [
            "protocol.discover",
            "protocol.authenticate",
            "representation.read"
          ],
          "technique_bindings": [
            "credential.classify",
            "credential.acquire"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF",
            "EP-TARGET-MUTATE-RF-STATEFUL"
          ]
        },
        "terminal_risk_authenticated_read": {
          "parameter_selector_id": "terminal_risk_authenticated_read",
          "all_of": [],
          "any_of": [],
          "normalized_operations": [
            "protocol.discover",
            "protocol.authenticate",
            "representation.read"
          ],
          "technique_bindings": [
            "credential.classify",
            "credential.acquire"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF",
            "EP-TARGET-MUTATE-RF-STATEFUL",
            "EP-TARGET-DESTROY-RF"
          ]
        }
      }
    },
    "CU-HF-MFU-EMULATION": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "uid_magic": {
          "parameter_selector_id": "uid_magic",
          "all_of": [
            "command:4019",
            "command:4020"
          ],
          "any_of": [],
          "normalized_operations": [
            "emulator.configure",
            "emulator.present"
          ],
          "technique_bindings": [
            "credential.replay"
          ],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB",
            "EP-TARGET-PRESENT-RF"
          ]
        },
        "page_data": {
          "parameter_selector_id": "page_data",
          "all_of": [
            "command:4021",
            "command:4022"
          ],
          "any_of": [],
          "normalized_operations": [
            "representation.stage",
            "emulator.configure",
            "emulator.present"
          ],
          "technique_bindings": [
            "credential.replay"
          ],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB",
            "EP-TARGET-PRESENT-RF"
          ]
        },
        "version_data": {
          "parameter_selector_id": "version_data",
          "all_of": [
            "command:4023",
            "command:4024"
          ],
          "any_of": [],
          "normalized_operations": [
            "emulator.configure",
            "emulator.present"
          ],
          "technique_bindings": [
            "credential.replay"
          ],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB",
            "EP-TARGET-PRESENT-RF"
          ]
        },
        "signature_data": {
          "parameter_selector_id": "signature_data",
          "all_of": [
            "command:4025",
            "command:4026"
          ],
          "any_of": [],
          "normalized_operations": [
            "emulator.configure",
            "emulator.present"
          ],
          "technique_bindings": [
            "credential.replay"
          ],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB",
            "EP-TARGET-PRESENT-RF"
          ]
        },
        "counter_data": {
          "parameter_selector_id": "counter_data",
          "all_of": [
            "command:4027",
            "command:4028"
          ],
          "any_of": [],
          "normalized_operations": [
            "emulator.configure",
            "emulator.present"
          ],
          "technique_bindings": [
            "credential.replay"
          ],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB",
            "EP-TARGET-PRESENT-RF"
          ]
        },
        "auth_counter_reset": {
          "parameter_selector_id": "auth_counter_reset",
          "all_of": [
            "command:4029"
          ],
          "any_of": [],
          "normalized_operations": [
            "emulator.configure",
            "emulator.present"
          ],
          "technique_bindings": [
            "credential.replay"
          ],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB",
            "EP-TARGET-PRESENT-RF"
          ]
        },
        "page_count": {
          "parameter_selector_id": "page_count",
          "all_of": [
            "command:4030"
          ],
          "any_of": [],
          "normalized_operations": [
            "emulator.configure",
            "emulator.present"
          ],
          "technique_bindings": [
            "credential.replay"
          ],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB",
            "EP-TARGET-PRESENT-RF"
          ]
        },
        "write_mode": {
          "parameter_selector_id": "write_mode",
          "all_of": [
            "command:4031",
            "command:4032"
          ],
          "any_of": [],
          "normalized_operations": [
            "emulator.configure",
            "emulator.present"
          ],
          "technique_bindings": [
            "credential.replay"
          ],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB",
            "EP-TARGET-PRESENT-RF"
          ]
        },
        "base_config": {
          "parameter_selector_id": "base_config",
          "all_of": [
            "command:4037"
          ],
          "any_of": [],
          "normalized_operations": [
            "emulator.configure",
            "emulator.present"
          ],
          "technique_bindings": [
            "credential.replay"
          ],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB",
            "EP-TARGET-PRESENT-RF"
          ]
        }
      }
    },
    "CU-HF-MFU-EMULATOR-TRACE": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "trace": {
          "parameter_selector_id": "trace",
          "all_of": [
            "command:4033",
            "command:4034",
            "command:4035",
            "command:4036"
          ],
          "any_of": [],
          "normalized_operations": [
            "emulator.present",
            "interaction.trace"
          ],
          "technique_bindings": [
            "verifier.interaction_trace"
          ],
          "effect_profile_refs": [
            "EP-TARGET-PRESENT-RF"
          ]
        }
      }
    },
    "CU-HF-MFU-WRITE": {
      "all_of": [
        "capability_variant:CU-HF-14A-RAW/default",
        "compiler:mfu_write_v1"
      ],
      "any_of": [],
      "variants": {
        "default": {
          "parameter_selector_id": "default",
          "all_of": [],
          "any_of": [],
          "normalized_operations": [
            "representation.read",
            "representation.write"
          ],
          "technique_bindings": [
            "credential.mutate"
          ],
          "effect_profile_refs": [
            "EP-TARGET-MUTATE-RF"
          ]
        }
      }
    },
    "CU-HF-MFU-DESTRUCTIVE-RECOVERY": {
      "all_of": [
        "capability_variant:CU-HF-14A-RAW/default",
        "compiler:mfu_destructive_recovery_v1",
        "vault_tool:mfu_secret_transform_v1"
      ],
      "any_of": [],
      "variants": {
        "default": {
          "parameter_selector_id": "default",
          "all_of": [],
          "any_of": [],
          "normalized_operations": [
            "protocol.challenge_collect",
            "representation.read",
            "representation.write"
          ],
          "technique_bindings": [
            "secret.recover.destructive_clone_variant"
          ],
          "effect_profile_refs": [
            "EP-TARGET-DESTROY-RF"
          ]
        }
      }
    },
    "CU-HF-ISO14443-4-RESPONDER": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "default": {
          "parameter_selector_id": "default",
          "all_of": [
            "command:6002",
            "command:6003"
          ],
          "any_of": [],
          "normalized_operations": [
            "response_profile.stage",
            "emulator.present",
            "protocol.compiled_responder"
          ],
          "technique_bindings": [
            "protocol.scripted_responder"
          ],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB",
            "EP-TARGET-PRESENT-RF"
          ]
        }
      }
    },
    "CU-HF-ISO14443-4-RESPOND-PRIMITIVE": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "default": {
          "parameter_selector_id": "default",
          "all_of": [
            "command:6000",
            "command:6001"
          ],
          "any_of": [],
          "normalized_operations": [
            "protocol.respond"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-TARGET-PRESENT-RF"
          ]
        }
      }
    },
    "CU-HF-ISO14443-4-DIAGNOSTICS": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "default": {
          "parameter_selector_id": "default",
          "all_of": [
            "command:6010"
          ],
          "any_of": [],
          "normalized_operations": [
            "protocol.diagnostics_observe"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-INSTRUMENT-OBSERVE-USB"
          ]
        }
      }
    },
    "CU-HF-DESFIRE-ENUMERATE": {
      "all_of": [
        "compiler:desfire_enumerate_v1"
      ],
      "any_of": [
        [
          "capability_variant:CU-HF-ISO14443-4-APDU/reader_apdu",
          "capability_variant:CU-HF-ISO14443-4-APDU/scan_keep_reader_apdu"
        ]
      ],
      "variants": {
        "default": {
          "parameter_selector_id": "default",
          "all_of": [],
          "any_of": [],
          "normalized_operations": [
            "protocol.compiled_exchange",
            "representation.fingerprint"
          ],
          "technique_bindings": [
            "application.enumerate",
            "credential.classify"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF"
          ]
        }
      }
    },
    "CU-HF-DESFIRE-AUTH-PROBE": {
      "all_of": [
        "compiler:desfire_auth_probe_v1"
      ],
      "any_of": [
        [
          "capability_variant:CU-HF-ISO14443-4-APDU/reader_apdu",
          "capability_variant:CU-HF-ISO14443-4-APDU/scan_keep_reader_apdu"
        ]
      ],
      "variants": {
        "default": {
          "parameter_selector_id": "default",
          "all_of": [],
          "any_of": [],
          "normalized_operations": [
            "protocol.compiled_exchange"
          ],
          "technique_bindings": [
            "credential.auth_probe",
            "secret.check_candidates"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF",
            "EP-TARGET-MUTATE-RF-STATEFUL"
          ]
        }
      }
    },
    "CU-HF-EMV-PROFILE": {
      "all_of": [
        "compiler:emv_profile_v1"
      ],
      "any_of": [],
      "variants": {
        "acquire": {
          "parameter_selector_id": "acquire",
          "all_of": [
            "command:6005"
          ],
          "any_of": [],
          "normalized_operations": [
            "protocol.compiled_exchange",
            "representation.read"
          ],
          "technique_bindings": [
            "application_profile.acquire"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF",
            "EP-TARGET-MUTATE-RF-STATEFUL"
          ]
        },
        "replay": {
          "parameter_selector_id": "replay",
          "all_of": [
            "capability_variant:CU-HF-ISO14443-4-RESPONDER/default"
          ],
          "any_of": [],
          "normalized_operations": [
            "response_profile.stage",
            "protocol.compiled_responder"
          ],
          "technique_bindings": [
            "application_profile.replay"
          ],
          "effect_profile_refs": [
            "EP-TARGET-PRESENT-RF"
          ]
        }
      }
    },
    "CU-LF-DISCOVERY": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "format_3000": {
          "parameter_selector_id": "format_3000",
          "all_of": [
            "command:3000"
          ],
          "any_of": [],
          "normalized_operations": [
            "protocol.discover",
            "representation.decode",
            "representation.fingerprint"
          ],
          "technique_bindings": [
            "credential.classify"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF"
          ]
        },
        "format_3002": {
          "parameter_selector_id": "format_3002",
          "all_of": [
            "command:3002"
          ],
          "any_of": [],
          "normalized_operations": [
            "protocol.discover",
            "representation.decode",
            "representation.fingerprint"
          ],
          "technique_bindings": [
            "credential.classify"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF"
          ]
        },
        "format_3004": {
          "parameter_selector_id": "format_3004",
          "all_of": [
            "command:3004"
          ],
          "any_of": [],
          "normalized_operations": [
            "protocol.discover",
            "representation.decode",
            "representation.fingerprint"
          ],
          "technique_bindings": [
            "credential.classify"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF"
          ]
        },
        "format_3010": {
          "parameter_selector_id": "format_3010",
          "all_of": [
            "command:3010"
          ],
          "any_of": [],
          "normalized_operations": [
            "protocol.discover",
            "representation.decode",
            "representation.fingerprint"
          ],
          "technique_bindings": [
            "credential.classify"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF"
          ]
        },
        "format_3014": {
          "parameter_selector_id": "format_3014",
          "all_of": [
            "command:3014"
          ],
          "any_of": [],
          "normalized_operations": [
            "protocol.discover",
            "representation.decode",
            "representation.fingerprint"
          ],
          "technique_bindings": [
            "credential.classify"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF"
          ]
        },
        "format_3019": {
          "parameter_selector_id": "format_3019",
          "all_of": [
            "command:3019"
          ],
          "any_of": [],
          "normalized_operations": [
            "protocol.discover",
            "representation.decode",
            "representation.fingerprint"
          ],
          "technique_bindings": [
            "credential.classify"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF"
          ]
        },
        "format_3030": {
          "parameter_selector_id": "format_3030",
          "all_of": [
            "command:3030"
          ],
          "any_of": [],
          "normalized_operations": [
            "protocol.discover",
            "representation.decode",
            "representation.fingerprint"
          ],
          "technique_bindings": [
            "credential.classify"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF"
          ]
        }
      }
    },
    "CU-LF-SIGNAL-CAPTURE": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "adc_capture": {
          "parameter_selector_id": "adc_capture",
          "all_of": [
            "command:3009"
          ],
          "any_of": [],
          "normalized_operations": [
            "signal.capture"
          ],
          "technique_bindings": [
            "signal.classify",
            "representation.decode_raw"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF"
          ]
        },
        "lf_sniff_capture": {
          "parameter_selector_id": "lf_sniff_capture",
          "all_of": [
            "command:3031"
          ],
          "any_of": [],
          "normalized_operations": [
            "signal.capture"
          ],
          "technique_bindings": [
            "signal.classify",
            "representation.decode_raw"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF"
          ]
        }
      }
    },
    "CU-LF-IOPROX-CODEC": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "decode": {
          "parameter_selector_id": "decode",
          "all_of": [
            "command:3012"
          ],
          "any_of": [],
          "normalized_operations": [
            "representation.decode"
          ],
          "technique_bindings": [
            "credential.classify"
          ],
          "effect_profile_refs": []
        },
        "compose": {
          "parameter_selector_id": "compose",
          "all_of": [
            "command:3013"
          ],
          "any_of": [],
          "normalized_operations": [
            "representation.compose"
          ],
          "technique_bindings": [
            "credential.stage_representation"
          ],
          "effect_profile_refs": []
        }
      }
    },
    "CU-LF-EMULATION": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "em410x": {
          "parameter_selector_id": "em410x",
          "all_of": [
            "command:5000",
            "command:5001"
          ],
          "any_of": [],
          "normalized_operations": [
            "representation.stage",
            "emulator.present"
          ],
          "technique_bindings": [
            "credential.replay"
          ],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB",
            "EP-TARGET-PRESENT-RF"
          ]
        },
        "hid_prox": {
          "parameter_selector_id": "hid_prox",
          "all_of": [
            "command:5002",
            "command:5003"
          ],
          "any_of": [],
          "normalized_operations": [
            "representation.stage",
            "emulator.present"
          ],
          "technique_bindings": [
            "credential.replay"
          ],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB",
            "EP-TARGET-PRESENT-RF"
          ]
        },
        "viking": {
          "parameter_selector_id": "viking",
          "all_of": [
            "command:5004",
            "command:5005"
          ],
          "any_of": [],
          "normalized_operations": [
            "representation.stage",
            "emulator.present"
          ],
          "technique_bindings": [
            "credential.replay"
          ],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB",
            "EP-TARGET-PRESENT-RF"
          ]
        },
        "pac": {
          "parameter_selector_id": "pac",
          "all_of": [
            "command:5006",
            "command:5007"
          ],
          "any_of": [],
          "normalized_operations": [
            "representation.stage",
            "emulator.present"
          ],
          "technique_bindings": [
            "credential.replay"
          ],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB",
            "EP-TARGET-PRESENT-RF"
          ]
        },
        "ioprox": {
          "parameter_selector_id": "ioprox",
          "all_of": [
            "command:5008",
            "command:5009"
          ],
          "any_of": [],
          "normalized_operations": [
            "representation.stage",
            "emulator.present"
          ],
          "technique_bindings": [
            "credential.replay"
          ],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB",
            "EP-TARGET-PRESENT-RF"
          ]
        },
        "jablotron": {
          "parameter_selector_id": "jablotron",
          "all_of": [
            "command:5010",
            "command:5011"
          ],
          "any_of": [],
          "normalized_operations": [
            "representation.stage",
            "emulator.present"
          ],
          "technique_bindings": [
            "credential.replay"
          ],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB",
            "EP-TARGET-PRESENT-RF"
          ]
        },
        "idteck": {
          "parameter_selector_id": "idteck",
          "all_of": [
            "command:5012",
            "command:5013"
          ],
          "any_of": [],
          "normalized_operations": [
            "representation.stage",
            "emulator.present"
          ],
          "technique_bindings": [
            "credential.replay"
          ],
          "effect_profile_refs": [
            "EP-INSTRUMENT-CONFIGURE-USB",
            "EP-TARGET-PRESENT-RF"
          ]
        }
      }
    },
    "CU-LF-T55XX-WRITE": {
      "all_of": [
        "observer:independent_t55xx_reader_v1"
      ],
      "any_of": [],
      "variants": {
        "em410x": {
          "parameter_selector_id": "em410x",
          "all_of": [
            "command:3001"
          ],
          "any_of": [],
          "normalized_operations": [
            "representation.write"
          ],
          "technique_bindings": [
            "credential.clone_to_media",
            "credential.mutate"
          ],
          "effect_profile_refs": [
            "EP-TARGET-MUTATE-RF"
          ]
        },
        "hid_prox": {
          "parameter_selector_id": "hid_prox",
          "all_of": [
            "command:3003"
          ],
          "any_of": [],
          "normalized_operations": [
            "representation.write"
          ],
          "technique_bindings": [
            "credential.clone_to_media",
            "credential.mutate"
          ],
          "effect_profile_refs": [
            "EP-TARGET-MUTATE-RF"
          ]
        },
        "viking": {
          "parameter_selector_id": "viking",
          "all_of": [
            "command:3005"
          ],
          "any_of": [],
          "normalized_operations": [
            "representation.write"
          ],
          "technique_bindings": [
            "credential.clone_to_media",
            "credential.mutate"
          ],
          "effect_profile_refs": [
            "EP-TARGET-MUTATE-RF"
          ]
        },
        "electra": {
          "parameter_selector_id": "electra",
          "all_of": [
            "command:3006"
          ],
          "any_of": [],
          "normalized_operations": [
            "representation.write"
          ],
          "technique_bindings": [
            "credential.clone_to_media",
            "credential.mutate"
          ],
          "effect_profile_refs": [
            "EP-TARGET-MUTATE-RF"
          ]
        },
        "ioprox": {
          "parameter_selector_id": "ioprox",
          "all_of": [
            "command:3011"
          ],
          "any_of": [],
          "normalized_operations": [
            "representation.write"
          ],
          "technique_bindings": [
            "credential.clone_to_media",
            "credential.mutate"
          ],
          "effect_profile_refs": [
            "EP-TARGET-MUTATE-RF"
          ]
        },
        "pac": {
          "parameter_selector_id": "pac",
          "all_of": [
            "command:3015"
          ],
          "any_of": [],
          "normalized_operations": [
            "representation.write"
          ],
          "technique_bindings": [
            "credential.clone_to_media",
            "credential.mutate"
          ],
          "effect_profile_refs": [
            "EP-TARGET-MUTATE-RF"
          ]
        },
        "generic": {
          "parameter_selector_id": "generic",
          "all_of": [
            "command:3016"
          ],
          "any_of": [],
          "normalized_operations": [
            "representation.write"
          ],
          "technique_bindings": [
            "credential.clone_to_media",
            "credential.mutate"
          ],
          "effect_profile_refs": [
            "EP-TARGET-MUTATE-RF"
          ]
        },
        "idteck": {
          "parameter_selector_id": "idteck",
          "all_of": [
            "command:3018"
          ],
          "any_of": [],
          "normalized_operations": [
            "representation.write"
          ],
          "technique_bindings": [
            "credential.clone_to_media",
            "credential.mutate"
          ],
          "effect_profile_refs": [
            "EP-TARGET-MUTATE-RF"
          ]
        },
        "jablotron": {
          "parameter_selector_id": "jablotron",
          "all_of": [
            "command:3020"
          ],
          "any_of": [],
          "normalized_operations": [
            "representation.write"
          ],
          "technique_bindings": [
            "credential.clone_to_media",
            "credential.mutate"
          ],
          "effect_profile_refs": [
            "EP-TARGET-MUTATE-RF"
          ]
        }
      }
    },
    "CU-LF-T55XX-DESTRUCTIVE": {
      "all_of": [
        "capability_variant:CU-LF-T55XX-WRITE/generic",
        "observer:independent_t55xx_reader_v1"
      ],
      "any_of": [],
      "variants": {
        "default": {
          "parameter_selector_id": "default",
          "all_of": [],
          "any_of": [],
          "normalized_operations": [
            "representation.write"
          ],
          "technique_bindings": [
            "credential.wipe_media"
          ],
          "effect_profile_refs": [
            "EP-TARGET-DESTROY-RF"
          ]
        }
      }
    },
    "CU-ADMIN-BLE-PAIRING": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "pairing_key": {
          "parameter_selector_id": "pairing_key",
          "all_of": [
            "command:1030",
            "command:1031"
          ],
          "any_of": [],
          "normalized_operations": [
            "instrument.admin_configure"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-INSTRUMENT-ADMINISTER-BLE"
          ]
        },
        "delete_bonds": {
          "parameter_selector_id": "delete_bonds",
          "all_of": [
            "command:1032"
          ],
          "any_of": [],
          "normalized_operations": [
            "instrument.admin_configure"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-INSTRUMENT-ADMINISTER-BLE"
          ]
        },
        "pairing_enable": {
          "parameter_selector_id": "pairing_enable",
          "all_of": [
            "command:1036",
            "command:1037"
          ],
          "any_of": [],
          "normalized_operations": [
            "instrument.admin_configure"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-INSTRUMENT-ADMINISTER-BLE"
          ]
        }
      }
    },
    "CU-ADMIN-DEVICE-SETTINGS": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "save": {
          "parameter_selector_id": "save",
          "all_of": [
            "command:1013"
          ],
          "any_of": [],
          "normalized_operations": [
            "instrument.admin_configure"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-INSTRUMENT-ADMINISTER-LOCAL"
          ]
        },
        "reset": {
          "parameter_selector_id": "reset",
          "all_of": [
            "command:1014"
          ],
          "any_of": [],
          "normalized_operations": [
            "instrument.admin_configure"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-INSTRUMENT-ADMINISTER-LOCAL"
          ]
        },
        "animation": {
          "parameter_selector_id": "animation",
          "all_of": [
            "command:1015",
            "command:1016"
          ],
          "any_of": [],
          "normalized_operations": [
            "instrument.admin_configure"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-INSTRUMENT-ADMINISTER-LOCAL"
          ]
        },
        "button_short": {
          "parameter_selector_id": "button_short",
          "all_of": [
            "command:1026",
            "command:1027"
          ],
          "any_of": [],
          "normalized_operations": [
            "instrument.admin_configure"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-INSTRUMENT-ADMINISTER-LOCAL"
          ]
        },
        "button_long": {
          "parameter_selector_id": "button_long",
          "all_of": [
            "command:1028",
            "command:1029"
          ],
          "any_of": [],
          "normalized_operations": [
            "instrument.admin_configure"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-INSTRUMENT-ADMINISTER-LOCAL"
          ]
        },
        "settings_observe": {
          "parameter_selector_id": "settings_observe",
          "all_of": [
            "command:1034"
          ],
          "any_of": [],
          "normalized_operations": [
            "instrument.admin_configure"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-INSTRUMENT-ADMINISTER-LOCAL"
          ]
        },
        "sleep_timeout": {
          "parameter_selector_id": "sleep_timeout",
          "all_of": [
            "command:1039",
            "command:1040"
          ],
          "any_of": [],
          "normalized_operations": [
            "instrument.admin_configure"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-INSTRUMENT-ADMINISTER-LOCAL"
          ]
        }
      }
    },
    "CU-ADMIN-FIELD-GENERATOR-INVOKE": {
      "all_of": [
        "manual_procedure:manual.chameleon_ultra.nfc_field_generator.v1",
        "observer:independent_rf_witness_v1"
      ],
      "any_of": [],
      "variants": {
        "default": {
          "parameter_selector_id": "default",
          "all_of": [],
          "any_of": [],
          "normalized_operations": [
            "instrument.manual_action"
          ],
          "technique_bindings": [
            "environment.rf_field_exposure"
          ],
          "effect_profile_refs": [
            "EP-ENVIRONMENT-TRANSMIT-RF-MANUAL"
          ]
        }
      }
    },
    "CU-ADMIN-BUTTON-CLONE-INVOKE": {
      "all_of": [
        "capability_variant:CU-HF-14A-DISCOVERY/default",
        "capability_variant:CU-WORKSPACE-SLOTS/stage",
        "manual_procedure:manual.chameleon_ultra.clone_ic_uid.v1",
        "observer:independent_operator_witness_v1"
      ],
      "any_of": [],
      "variants": {
        "default": {
          "parameter_selector_id": "default",
          "all_of": [],
          "any_of": [],
          "normalized_operations": [
            "instrument.manual_action",
            "protocol.discover",
            "representation.stage"
          ],
          "technique_bindings": [
            "credential.acquire_and_stage"
          ],
          "effect_profile_refs": [
            "EP-TARGET-TRANSMIT-RF-MANUAL",
            "EP-INSTRUMENT-CONFIGURE-MANUAL"
          ]
        }
      }
    },
    "CU-ADMIN-DFU": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "default": {
          "parameter_selector_id": "default",
          "all_of": [
            "command:1010"
          ],
          "any_of": [],
          "normalized_operations": [
            "instrument.firmware_manage"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-INSTRUMENT-ADMINISTER-LOCAL"
          ]
        }
      }
    },
    "CU-ADMIN-DATA-ERASE": {
      "all_of": [],
      "any_of": [],
      "variants": {
        "default": {
          "parameter_selector_id": "default",
          "all_of": [
            "command:1020"
          ],
          "any_of": [],
          "normalized_operations": [
            "instrument.erase"
          ],
          "technique_bindings": [],
          "effect_profile_refs": [
            "EP-INSTRUMENT-DESTROY-USB"
          ]
        }
      }
    }
  },
  "capability_dependency_registry_sha256": "62ae7c98a576cb3d19aeaefad5860216a89692e29ba443f94163e260fe6ecfca",
  "dependency_proof_provider_registry": {
    "compiler:desfire_auth_probe_v1": {
      "provider_kind": "compiler",
      "owner_principal": "physical_pack_compiler",
      "artifact_digest_binding": "signed_pack_tool_digest",
      "signed_verdict_type": "bob-proof:compiler-conformance:v1",
      "trust_epoch_binding": "session_authority_epoch",
      "freshness_policy": "pack_version_and_grant",
      "revocation_policy": "deny_on_epoch_or_registry_drift"
    },
    "compiler:desfire_enumerate_v1": {
      "provider_kind": "compiler",
      "owner_principal": "physical_pack_compiler",
      "artifact_digest_binding": "signed_pack_tool_digest",
      "signed_verdict_type": "bob-proof:compiler-conformance:v1",
      "trust_epoch_binding": "session_authority_epoch",
      "freshness_policy": "pack_version_and_grant",
      "revocation_policy": "deny_on_epoch_or_registry_drift"
    },
    "compiler:emv_profile_v1": {
      "provider_kind": "compiler",
      "owner_principal": "specialist_pack_compiler",
      "artifact_digest_binding": "signed_pack_tool_digest",
      "signed_verdict_type": "bob-proof:compiler-conformance:v1",
      "trust_epoch_binding": "session_authority_epoch",
      "freshness_policy": "pack_version_and_grant",
      "revocation_policy": "deny_on_epoch_or_registry_drift"
    },
    "compiler:iso14443a_closed_probe_v1": {
      "provider_kind": "compiler",
      "owner_principal": "physical_pack_compiler",
      "artifact_digest_binding": "signed_pack_tool_digest",
      "signed_verdict_type": "bob-proof:compiler-conformance:v1",
      "trust_epoch_binding": "session_authority_epoch",
      "freshness_policy": "pack_version_and_grant",
      "revocation_policy": "deny_on_epoch_or_registry_drift"
    },
    "compiler:mfu_acquire_v1": {
      "provider_kind": "compiler",
      "owner_principal": "physical_pack_compiler",
      "artifact_digest_binding": "signed_pack_tool_digest",
      "signed_verdict_type": "bob-proof:compiler-conformance:v1",
      "trust_epoch_binding": "session_authority_epoch",
      "freshness_policy": "pack_version_and_grant",
      "revocation_policy": "deny_on_epoch_or_registry_drift"
    },
    "compiler:mfu_destructive_recovery_v1": {
      "provider_kind": "compiler",
      "owner_principal": "specialist_pack_compiler",
      "artifact_digest_binding": "signed_pack_tool_digest",
      "signed_verdict_type": "bob-proof:compiler-conformance:v1",
      "trust_epoch_binding": "session_authority_epoch",
      "freshness_policy": "pack_version_and_grant",
      "revocation_policy": "deny_on_epoch_or_registry_drift"
    },
    "compiler:mfu_write_v1": {
      "provider_kind": "compiler",
      "owner_principal": "physical_pack_compiler",
      "artifact_digest_binding": "signed_pack_tool_digest",
      "signed_verdict_type": "bob-proof:compiler-conformance:v1",
      "trust_epoch_binding": "session_authority_epoch",
      "freshness_policy": "pack_version_and_grant",
      "revocation_policy": "deny_on_epoch_or_registry_drift"
    },
    "conformance:chameleon_frame_codec_v1": {
      "provider_kind": "conformance",
      "owner_principal": "provider_conformance_runner",
      "artifact_digest_binding": "provider_binary_and_fixture_digest",
      "signed_verdict_type": "bob-proof:provider-conformance:v1",
      "trust_epoch_binding": "provider_registry_epoch",
      "freshness_policy": "provider_build_and_transport",
      "revocation_policy": "deny_on_provider_or_fixture_drift"
    },
    "conformance:chameleon_hf14a_closed_probe_v1": {
      "provider_kind": "conformance",
      "owner_principal": "provider_hil_conformance_runner",
      "artifact_digest_binding": "provider_binary_compiler_registry_source_firmware_transport_and_hil_fixture_digests",
      "signed_verdict_type": "bob-proof:provider-hil-conformance:v1",
      "trust_epoch_binding": "provider_registry_and_hil_fixture_epoch",
      "freshness_policy": "provider_build_firmware_transport_compiler_and_owned_hil_run",
      "revocation_policy": "deny_on_provider_firmware_transport_compiler_fixture_or_epoch_drift"
    },
    "observer:independent_operator_witness_v1": {
      "provider_kind": "observer",
      "owner_principal": "enrolled_observer",
      "artifact_digest_binding": "observer_enrollment_and_procedure_digest",
      "signed_verdict_type": "bob-proof:operator-witness:v1",
      "trust_epoch_binding": "observer_trust_epoch",
      "freshness_policy": "attempt_challenge_window",
      "revocation_policy": "deny_on_observer_revocation_or_challenge_reuse"
    },
    "observer:independent_rf_witness_v1": {
      "provider_kind": "observer",
      "owner_principal": "enrolled_rf_observer",
      "artifact_digest_binding": "observer_enrollment_and_instrument_digest",
      "signed_verdict_type": "bob-proof:rf-witness:v1",
      "trust_epoch_binding": "observer_trust_epoch",
      "freshness_policy": "attempt_challenge_window",
      "revocation_policy": "deny_on_observer_revocation_or_challenge_reuse"
    },
    "observer:independent_t55xx_reader_v1": {
      "provider_kind": "observer",
      "owner_principal": "enrolled_external_reader",
      "artifact_digest_binding": "observer_enrollment_and_reader_digest",
      "signed_verdict_type": "bob-proof:external-readback:v1",
      "trust_epoch_binding": "observer_trust_epoch",
      "freshness_policy": "attempt_and_media_custody",
      "revocation_policy": "deny_on_observer_or_reader_assurance_drift"
    },
    "transport:ble_nus_v1": {
      "provider_kind": "transport",
      "owner_principal": "device_execution_worker",
      "artifact_digest_binding": "provider_transport_module_digest",
      "signed_verdict_type": "bob-proof:transport-conformance:v1",
      "trust_epoch_binding": "provider_registry_epoch",
      "freshness_policy": "connection_and_inventory_observation",
      "revocation_policy": "deny_on_disconnect_identity_or_provider_drift"
    },
    "transport:usb_cdc_acm_115200_dtr_v1": {
      "provider_kind": "transport",
      "owner_principal": "device_execution_worker",
      "artifact_digest_binding": "provider_transport_module_digest",
      "signed_verdict_type": "bob-proof:transport-conformance:v1",
      "trust_epoch_binding": "provider_registry_epoch",
      "freshness_policy": "open_and_inventory_observation",
      "revocation_policy": "deny_on_disconnect_identity_or_provider_drift"
    },
    "vault_tool:classic_trace_recovery_v1": {
      "provider_kind": "vault_tool",
      "owner_principal": "vault_transform_worker",
      "artifact_digest_binding": "allowlisted_vault_tool_digest",
      "signed_verdict_type": "bob-proof:vault-transform:v1",
      "trust_epoch_binding": "vault_tool_registry_epoch",
      "freshness_policy": "plan_grant_and_input_handle",
      "revocation_policy": "deny_on_tool_epoch_or_input_binding_drift"
    },
    "vault_tool:classic_autopwn_v1": {
      "provider_kind": "vault_tool",
      "owner_principal": "vault_transform_worker",
      "artifact_digest_binding": "allowlisted_family_specific_vault_tool_digest",
      "signed_verdict_type": "bob-proof:vault-transform:v1",
      "trust_epoch_binding": "vault_tool_registry_epoch",
      "freshness_policy": "plan_grant_and_input_handle",
      "revocation_policy": "deny_on_tool_epoch_or_input_binding_drift"
    },
    "vault_tool:classic_darkside_recovery_v1": {
      "provider_kind": "vault_tool",
      "owner_principal": "vault_transform_worker",
      "artifact_digest_binding": "allowlisted_family_specific_vault_tool_digest",
      "signed_verdict_type": "bob-proof:vault-transform:v1",
      "trust_epoch_binding": "vault_tool_registry_epoch",
      "freshness_policy": "plan_grant_and_input_handle",
      "revocation_policy": "deny_on_tool_epoch_or_input_binding_drift"
    },
    "vault_tool:classic_encrypted_nested_recovery_v1": {
      "provider_kind": "vault_tool",
      "owner_principal": "vault_transform_worker",
      "artifact_digest_binding": "allowlisted_family_specific_vault_tool_digest",
      "signed_verdict_type": "bob-proof:vault-transform:v1",
      "trust_epoch_binding": "vault_tool_registry_epoch",
      "freshness_policy": "plan_grant_and_input_handle",
      "revocation_policy": "deny_on_tool_epoch_or_input_binding_drift"
    },
    "vault_tool:classic_hardnested_recovery_v1": {
      "provider_kind": "vault_tool",
      "owner_principal": "vault_transform_worker",
      "artifact_digest_binding": "allowlisted_family_specific_vault_tool_digest",
      "signed_verdict_type": "bob-proof:vault-transform:v1",
      "trust_epoch_binding": "vault_tool_registry_epoch",
      "freshness_policy": "plan_grant_and_input_handle",
      "revocation_policy": "deny_on_tool_epoch_or_input_binding_drift"
    },
    "vault_tool:classic_nested_recovery_v1": {
      "provider_kind": "vault_tool",
      "owner_principal": "vault_transform_worker",
      "artifact_digest_binding": "allowlisted_family_specific_vault_tool_digest",
      "signed_verdict_type": "bob-proof:vault-transform:v1",
      "trust_epoch_binding": "vault_tool_registry_epoch",
      "freshness_policy": "plan_grant_and_input_handle",
      "revocation_policy": "deny_on_tool_epoch_or_input_binding_drift"
    },
    "vault_tool:classic_static_nested_recovery_v1": {
      "provider_kind": "vault_tool",
      "owner_principal": "vault_transform_worker",
      "artifact_digest_binding": "allowlisted_family_specific_vault_tool_digest",
      "signed_verdict_type": "bob-proof:vault-transform:v1",
      "trust_epoch_binding": "vault_tool_registry_epoch",
      "freshness_policy": "plan_grant_and_input_handle",
      "revocation_policy": "deny_on_tool_epoch_or_input_binding_drift"
    },
    "vault_tool:mfu_secret_transform_v1": {
      "provider_kind": "vault_tool",
      "owner_principal": "vault_transform_worker",
      "artifact_digest_binding": "allowlisted_vault_tool_digest",
      "signed_verdict_type": "bob-proof:vault-transform:v1",
      "trust_epoch_binding": "vault_tool_registry_epoch",
      "freshness_policy": "plan_grant_and_input_handle",
      "revocation_policy": "deny_on_tool_epoch_or_input_binding_drift"
    }
  },
  "dependency_proof_provider_registry_sha256": "67e4b6a4c2545e836c6680dd102e12017fa3706a692f45bc96612f17abd49f42",
  "technique_registry": [
    "application_profile.acquire",
    "application_profile.replay",
    "application.enumerate",
    "credential.acquire",
    "credential.acquire_and_stage",
    "credential.auth_probe",
    "credential.auth_trace",
    "credential.classify",
    "credential.clone_to_media",
    "credential.mutate",
    "credential.relay",
    "credential.replay",
    "credential.stage_representation",
    "credential.value_semantics_probe",
    "credential.wipe_media",
    "environment.rf_field_exposure",
    "protocol.compatibility_probe",
    "protocol.frame_analysis",
    "protocol.probe",
    "protocol.scripted_responder",
    "representation.decode_raw",
    "secret.check_candidates",
    "secret.recover_from_trace",
    "secret.recover.autopwn",
    "secret.recover.darkside",
    "secret.recover.destructive_clone_variant",
    "secret.recover.encrypted_nested",
    "secret.recover.hardnested",
    "secret.recover.nested",
    "secret.recover.static_nested",
    "signal.classify",
    "signal.passive_trace",
    "verifier.interaction_trace"
  ],
  "technique_registry_sha256": "94f7d1f1b313d4b4a33c2c476c9676e2d9668a7d83b41252e89ada5ffbc65726",
  "effect_profiles": {
    "EP-INSTRUMENT-OBSERVE-USB": {
      "subject_kind": "instrument",
      "action": "observe",
      "channel": "usb",
      "persistence": "none",
      "required_bounds": [
        "instrument_ref"
      ]
    },
    "EP-INSTRUMENT-CONFIGURE-USB": {
      "subject_kind": "instrument",
      "action": "configure",
      "channel": "usb",
      "persistence": "persistent",
      "required_bounds": [
        "instrument_ref",
        "cleanup_plan_digest"
      ]
    },
    "EP-INSTRUMENT-TRANSMIT-USB": {
      "subject_kind": "instrument",
      "action": "transmit",
      "channel": "usb",
      "persistence": "ephemeral",
      "required_bounds": [
        "instrument_ref",
        "duration_ms",
        "byte_limit"
      ]
    },
    "EP-INSTRUMENT-TRANSMIT-BLE": {
      "subject_kind": "instrument",
      "action": "transmit",
      "channel": "ble",
      "persistence": "ephemeral",
      "required_bounds": [
        "instrument_ref",
        "duration_ms",
        "byte_limit"
      ]
    },
    "EP-TARGET-TRANSMIT-RF": {
      "subject_kind": "target",
      "action": "transmit",
      "channel": "rf",
      "persistence": "ephemeral",
      "required_bounds": [
        "instrument_ref",
        "target_ref",
        "duration_ms",
        "attempt_limit",
        "frequency_band",
        "power_ceiling",
        "duty_cycle",
        "zone_ref",
        "containment_plan_ref",
        "execution_deadline",
        "spatial_envelope_ref",
        "stimulus_sequence_ref"
      ]
    },
    "EP-TARGET-PRESENT-RF": {
      "subject_kind": "target",
      "action": "present",
      "channel": "rf",
      "persistence": "ephemeral",
      "required_bounds": [
        "instrument_ref",
        "target_ref",
        "duration_ms",
        "attempt_limit",
        "frequency_band",
        "power_ceiling",
        "duty_cycle",
        "zone_ref",
        "containment_plan_ref",
        "execution_deadline",
        "spatial_envelope_ref",
        "stimulus_sequence_ref"
      ]
    },
    "EP-ENVIRONMENT-TRANSMIT-RF": {
      "subject_kind": "environment",
      "action": "transmit",
      "channel": "rf",
      "persistence": "ephemeral",
      "required_bounds": [
        "instrument_ref",
        "duration_ms",
        "attempt_limit",
        "frequency_band",
        "power_ceiling",
        "duty_cycle",
        "zone_ref",
        "containment_plan_ref",
        "execution_deadline",
        "spatial_envelope_ref",
        "stimulus_sequence_ref"
      ]
    },
    "EP-TARGET-MUTATE-RF": {
      "subject_kind": "target",
      "action": "mutate",
      "channel": "rf",
      "persistence": "persistent",
      "required_bounds": [
        "instrument_ref",
        "target_ref",
        "duration_ms",
        "attempt_limit",
        "byte_limit",
        "state_delta_plan_ref",
        "frequency_band",
        "power_ceiling",
        "duty_cycle",
        "zone_ref",
        "containment_plan_ref",
        "execution_deadline",
        "spatial_envelope_ref",
        "stimulus_sequence_ref",
        "cleanup_plan_digest"
      ]
    },
    "EP-TARGET-MUTATE-RF-STATEFUL": {
      "subject_kind": "target",
      "action": "mutate",
      "channel": "rf",
      "persistence": "persistent",
      "required_bounds": [
        "instrument_ref",
        "target_ref",
        "duration_ms",
        "attempt_limit",
        "auth_attempt_limit",
        "counter_delta_limit",
        "lockout_headroom_ref",
        "log_event_limit",
        "byte_limit",
        "state_delta_plan_ref",
        "frequency_band",
        "power_ceiling",
        "duty_cycle",
        "zone_ref",
        "containment_plan_ref",
        "execution_deadline",
        "spatial_envelope_ref",
        "stimulus_sequence_ref",
        "residual_state_plan_ref"
      ]
    },
    "EP-TARGET-DESTROY-RF": {
      "subject_kind": "target",
      "action": "destroy",
      "channel": "rf",
      "persistence": "irreversible",
      "required_bounds": [
        "instrument_ref",
        "target_ref",
        "duration_ms",
        "attempt_limit",
        "byte_limit",
        "state_delta_plan_ref",
        "frequency_band",
        "power_ceiling",
        "duty_cycle",
        "zone_ref",
        "containment_plan_ref",
        "execution_deadline",
        "spatial_envelope_ref",
        "stimulus_sequence_ref",
        "operator_receipt_ref",
        "terminal_state_plan_ref"
      ]
    },
    "EP-TARGET-TRANSMIT-RF-MANUAL": {
      "subject_kind": "target",
      "action": "transmit",
      "channel": "rf",
      "persistence": "ephemeral",
      "required_bounds": [
        "instrument_ref",
        "target_ref",
        "duration_ms",
        "attempt_limit",
        "frequency_band",
        "power_ceiling",
        "duty_cycle",
        "zone_ref",
        "containment_plan_ref",
        "execution_deadline",
        "spatial_envelope_ref",
        "stimulus_sequence_ref",
        "operator_receipt_ref",
        "witness_receipt_ref"
      ]
    },
    "EP-ENVIRONMENT-TRANSMIT-RF-MANUAL": {
      "subject_kind": "environment",
      "action": "transmit",
      "channel": "rf",
      "persistence": "ephemeral",
      "required_bounds": [
        "instrument_ref",
        "duration_ms",
        "attempt_limit",
        "frequency_band",
        "power_ceiling",
        "duty_cycle",
        "zone_ref",
        "containment_plan_ref",
        "execution_deadline",
        "spatial_envelope_ref",
        "stimulus_sequence_ref",
        "operator_receipt_ref",
        "witness_receipt_ref"
      ]
    },
    "EP-INSTRUMENT-CONFIGURE-MANUAL": {
      "subject_kind": "instrument",
      "action": "configure",
      "channel": "manual",
      "persistence": "persistent",
      "required_bounds": [
        "instrument_ref",
        "cleanup_plan_digest",
        "operator_receipt_ref",
        "witness_receipt_ref"
      ]
    },
    "EP-INSTRUMENT-ADMINISTER-BLE": {
      "subject_kind": "instrument",
      "action": "administer",
      "channel": "ble",
      "persistence": "persistent",
      "required_bounds": [
        "instrument_ref",
        "pre_state_snapshot_ref",
        "backup_artifact_ref",
        "state_delta_plan_ref",
        "expected_terminal_state_ref",
        "post_operation_inventory_plan_ref",
        "assurance_invalidation_plan_ref",
        "recovery_or_quarantine_plan_ref",
        "owned_fixture_ref",
        "hil_evidence_plan_ref",
        "operator_receipt_ref"
      ]
    },
    "EP-INSTRUMENT-ADMINISTER-LOCAL": {
      "subject_kind": "instrument",
      "action": "administer",
      "channel": "instrument_local",
      "persistence": "persistent",
      "required_bounds": [
        "instrument_ref",
        "pre_state_snapshot_ref",
        "backup_artifact_ref",
        "state_delta_plan_ref",
        "expected_terminal_state_ref",
        "post_operation_inventory_plan_ref",
        "assurance_invalidation_plan_ref",
        "recovery_or_quarantine_plan_ref",
        "owned_fixture_ref",
        "hil_evidence_plan_ref",
        "operator_receipt_ref"
      ]
    },
    "EP-INSTRUMENT-DESTROY-USB": {
      "subject_kind": "instrument",
      "action": "destroy",
      "channel": "usb",
      "persistence": "irreversible",
      "required_bounds": [
        "instrument_ref",
        "pre_state_snapshot_ref",
        "backup_artifact_ref",
        "state_delta_plan_ref",
        "terminal_state_plan_ref",
        "post_operation_inventory_plan_ref",
        "assurance_invalidation_plan_ref",
        "quarantine_or_disposal_plan_ref",
        "owned_fixture_ref",
        "hil_evidence_plan_ref",
        "operator_receipt_ref"
      ]
    }
  },
  "manual_action_registry": {
    "CU-ADMIN-BUTTON-CLONE-INVOKE": {
      "source_url": "https://raw.githubusercontent.com/RfidResearchGroup/ChameleonUltra/v2.2.0/firmware/application/src/app_main.c",
      "source_sha256": "95a62be3fffe6b66b635216523d7beb5d74692db14747549da37b29aea8828bd",
      "source_symbol": "run_button_function_by_settings",
      "source_case": "SettingsButtonCloneIcUid",
      "procedure_id": "manual.chameleon_ultra.clone_ic_uid.v1",
      "effect_profile_refs": [
        "EP-TARGET-TRANSMIT-RF-MANUAL",
        "EP-INSTRUMENT-CONFIGURE-MANUAL"
      ],
      "required_receipts": [
        "operator_receipt_ref",
        "witness_receipt_ref"
      ],
      "rf_off_deadline_required": true
    },
    "CU-ADMIN-FIELD-GENERATOR-INVOKE": {
      "source_url": "https://raw.githubusercontent.com/RfidResearchGroup/ChameleonUltra/v2.2.0/firmware/application/src/app_main.c",
      "source_sha256": "95a62be3fffe6b66b635216523d7beb5d74692db14747549da37b29aea8828bd",
      "source_symbol": "run_button_function_by_settings",
      "source_case": "SettingsButtonNfcFieldGenerator",
      "procedure_id": "manual.chameleon_ultra.nfc_field_generator.v1",
      "effect_profile_refs": [
        "EP-ENVIRONMENT-TRANSMIT-RF-MANUAL"
      ],
      "required_receipts": [
        "operator_receipt_ref",
        "witness_receipt_ref"
      ],
      "rf_off_deadline_required": true
    }
  },
  "manual_action_registry_sha256": "fce6a16f56c002d9e6259762b7887461d1be145aa0c1cd059790f8955c2dd9c7",
  "data_classes": [
    "metadata",
    "linkable",
    "credential_secret",
    "regulated"
  ],
  "dispositions": [
    "planned",
    "optional",
    "provider_internal",
    "operator_only",
    "unsupported"
  ],
  "coverage": [
    {
      "provider_capability_id": "CU-CORE-INVENTORY",
      "provider": "chameleon_ultra",
      "protocol_family": "instrument",
      "device_surface": "device model, application version, Git revision, reported command-ID list, and battery; device mode is not observed by the bootstrap subset",
      "upstream_command_ids": [
        1000,
        1017,
        1025,
        1033,
        1035
      ],
      "normalized_operations": [
        "instrument.inventory",
        "instrument.capabilities",
        "instrument.health"
      ],
      "technique_bindings": [],
      "effect_profile_refs": [
        "EP-INSTRUMENT-OBSERVE-USB"
      ],
      "data_class": "metadata",
      "node_refs": [
        "PH-P7",
        "PH-P8",
        "PH-I1"
      ],
      "disposition": "provider_internal",
      "reason": "This mandatory first provider bootstrap operation records assurance-qualified self-reported inventory and provenance; availability is derived from the returned command-ID list, not a firmware label or an implied cryptographic attestation. Command 1002 remains outside the bootstrap allowlist, so device-mode and RF-continuity assurance stays pending an independent bracket/continuity witness and PH-P7 HIL."
    },
    {
      "provider_capability_id": "CU-CORE-IDENTITY-ENROLLMENT",
      "provider": "chameleon_ultra",
      "protocol_family": "instrument",
      "device_surface": "device chip ID and BLE device address used only as vaulted operator-enrollment inputs",
      "upstream_command_ids": [
        1011,
        1012
      ],
      "normalized_operations": [
        "instrument.identity_observe",
        "instrument.enrollment_match"
      ],
      "technique_bindings": [],
      "effect_profile_refs": [
        "EP-INSTRUMENT-OBSERVE-USB"
      ],
      "data_class": "linkable",
      "node_refs": [
        "PH-S3",
        "PH-P7",
        "PH-P8",
        "PH-I1",
        "PH-X2"
      ],
      "disposition": "provider_internal",
      "reason": "Raw hardware identity never reaches the agent; the broker vault binds it to an operator-enrolled alias and refuses ambiguous or replacement-device matches."
    },
    {
      "provider_capability_id": "CU-CORE-FRAME-CODEC",
      "provider": "chameleon_ultra",
      "protocol_family": "instrument",
      "device_surface": "binary frame encoding, checksums, command correlation, status parsing, and bounded timeouts",
      "upstream_command_ids": [],
      "normalized_operations": [
        "provider.frame_encode",
        "provider.frame_decode",
        "provider.command_correlate"
      ],
      "technique_bindings": [],
      "effect_profile_refs": [],
      "data_class": "metadata",
      "node_refs": [
        "PH-P0",
        "PH-P1",
        "PH-P2",
        "PH-X4"
      ],
      "disposition": "provider_internal",
      "reason": "Transport mechanics are tested behind the provider ABI and never exposed as evaluator escape hatches."
    },
    {
      "provider_capability_id": "CU-TRANSPORT-USB",
      "provider": "chameleon_ultra",
      "protocol_family": "transport",
      "device_surface": "USB CDC ACM at 115200 baud with DTR",
      "upstream_command_ids": [],
      "normalized_operations": [
        "transport.connect",
        "transport.exchange",
        "transport.disconnect"
      ],
      "technique_bindings": [],
      "effect_profile_refs": [
        "EP-INSTRUMENT-TRANSMIT-USB"
      ],
      "data_class": "metadata",
      "node_refs": [
        "PH-S3",
        "PH-P2",
        "PH-P3",
        "PH-X3",
        "PH-X5"
      ],
      "disposition": "provider_internal",
      "reason": "USB is the initial deterministic transport and remains inaccessible to ordinary evaluator tools."
    },
    {
      "provider_capability_id": "CU-TRANSPORT-BLE",
      "provider": "chameleon_ultra",
      "protocol_family": "transport",
      "device_surface": "Nordic UART Service over BLE",
      "upstream_command_ids": [],
      "normalized_operations": [
        "transport.connect",
        "transport.exchange",
        "transport.disconnect"
      ],
      "technique_bindings": [],
      "effect_profile_refs": [
        "EP-INSTRUMENT-TRANSMIT-BLE"
      ],
      "data_class": "metadata",
      "node_refs": [
        "PH-S3",
        "PH-P2",
        "PH-P6",
        "PH-X3",
        "PH-X5"
      ],
      "disposition": "provider_internal",
      "reason": "A second transport increases field utility but must preserve identical framing, broker policy, and conformance behavior."
    },
    {
      "provider_capability_id": "CU-WORKSPACE-SLOTS",
      "provider": "chameleon_ultra",
      "protocol_family": "instrument",
      "device_surface": "eight dual HF/LF workspaces, active workspace selection, enablement, load, save, and delete",
      "upstream_command_ids": [
        1003,
        1004,
        1005,
        1006,
        1007,
        1008,
        1009,
        1018,
        1019,
        1021,
        1023,
        1024,
        1038
      ],
      "normalized_operations": [
        "workspace.snapshot",
        "representation.stage",
        "workspace.restore"
      ],
      "technique_bindings": [
        "credential.stage_representation"
      ],
      "effect_profile_refs": [
        "EP-INSTRUMENT-OBSERVE-USB",
        "EP-INSTRUMENT-CONFIGURE-USB"
      ],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-S5",
        "PH-S7",
        "PH-P4",
        "PH-P5",
        "PH-C2",
        "PH-C4"
      ],
      "disposition": "provider_internal",
      "reason": "Slots are mutable provider workspaces with snapshot and restoration receipts, never credential assets."
    },
    {
      "provider_capability_id": "CU-RF-SESSION",
      "provider": "chameleon_ultra",
      "protocol_family": "instrument",
      "device_surface": "reader/emulator mode, field activation, field release, sleep, and scan-keep behavior",
      "upstream_command_ids": [
        1001,
        1002,
        2100,
        2101
      ],
      "normalized_operations": [
        "rf_session.observe",
        "rf_session.acquire",
        "rf_session.release",
        "instrument.restore"
      ],
      "technique_bindings": [],
      "effect_profile_refs": [
        "EP-INSTRUMENT-CONFIGURE-USB",
        "EP-TARGET-TRANSMIT-RF",
        "EP-TARGET-PRESENT-RF",
        "EP-ENVIRONMENT-TRANSMIT-RF"
      ],
      "data_class": "metadata",
      "node_refs": [
        "PH-S3",
        "PH-S7",
        "PH-P4",
        "PH-P5",
        "PH-X5"
      ],
      "disposition": "provider_internal",
      "reason": "RF and mode state are lease-bound broker controls shared by higher-level techniques."
    },
    {
      "provider_capability_id": "CU-HF-14A-DISCOVERY",
      "provider": "chameleon_ultra",
      "protocol_family": "ISO14443-A",
      "device_surface": "card scan and UID, ATQA, SAK, and ATS fingerprinting",
      "upstream_command_ids": [
        2000
      ],
      "normalized_operations": [
        "protocol.discover",
        "representation.fingerprint"
      ],
      "technique_bindings": [
        "credential.classify"
      ],
      "effect_profile_refs": [
        "EP-TARGET-TRANSMIT-RF"
      ],
      "data_class": "linkable",
      "node_refs": [
        "PH-P4",
        "PH-C1",
        "PH-I2",
        "PH-I3"
      ],
      "disposition": "planned",
      "reason": "The primary HF classification primitive feeds brand-neutral applicability decisions."
    },
    {
      "provider_capability_id": "CU-HF-14A-RAW",
      "provider": "chameleon_ultra",
      "protocol_family": "ISO14443-A",
      "device_surface": "firmware raw-frame handler accepting caller-controlled bytes, isolated behind the provider compiler",
      "upstream_command_ids": [
        2010
      ],
      "normalized_operations": [
        "protocol.transceive"
      ],
      "technique_bindings": [],
      "effect_profile_refs": [
        "EP-TARGET-TRANSMIT-RF",
        "EP-TARGET-MUTATE-RF-STATEFUL",
        "EP-TARGET-DESTROY-RF"
      ],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-P4",
        "PH-IP3",
        "PH-X5"
      ],
      "disposition": "provider_internal",
      "reason": "Command 2010 is a broker-private primitive with no evaluator-facing arbitrary-byte path. Only reviewed schema extensions may compile canonical frames, and admission uses the worst-case effect union."
    },
    {
      "provider_capability_id": "CU-HF-14A-COMPILED-PROBE",
      "provider": "chameleon_ultra",
      "protocol_family": "ISO14443-A",
      "device_surface": "closed, versioned probe schemas compiled to canonical ISO14443-A frames by the provider",
      "upstream_command_ids": [],
      "normalized_operations": [
        "protocol.discovery_probe"
      ],
      "technique_bindings": [
        "protocol.probe"
      ],
      "effect_profile_refs": [
        "EP-TARGET-TRANSMIT-RF"
      ],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-P4",
        "PH-C6",
        "PH-IP3",
        "PH-X5"
      ],
      "disposition": "planned",
      "reason": "The evaluator selects exactly REQA or WUPA through a schema-bijective variant. Runtime remains unavailable until the provider supplies canonical bytes through the private raw handler and a fresh source-, firmware-, transport-, compiler-, fixture-, and owned-HIL-bound conformance verdict satisfies the distinct assurance contract."
    },
    {
      "provider_capability_id": "CU-HF-14A-ACTIVE-TRACE",
      "provider": "chameleon_ultra",
      "protocol_family": "ISO14443-A",
      "device_surface": "active emulated-card interaction trace returned as directional ISO14443-A frames",
      "upstream_command_ids": [
        2020
      ],
      "normalized_operations": [
        "emulator.present",
        "interaction.trace"
      ],
      "technique_bindings": [
        "verifier.interaction_trace",
        "protocol.frame_analysis"
      ],
      "effect_profile_refs": [
        "EP-TARGET-PRESENT-RF"
      ],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-P4",
        "PH-P5",
        "PH-C4",
        "PH-C7",
        "PH-I4"
      ],
      "disposition": "planned",
      "reason": "Upstream calls this sniffing, but the instrument actively presents its staged emulation to a reader; it is not passive over-the-air capture."
    },
    {
      "provider_capability_id": "CU-HF-14A-READER-CONFIG",
      "provider": "chameleon_ultra",
      "protocol_family": "ISO14443-A",
      "device_surface": "reader compatibility configuration read and bounded provider-managed update",
      "upstream_command_ids": [
        2200,
        2201
      ],
      "normalized_operations": [
        "reader_profile.observe",
        "reader_profile.configure"
      ],
      "technique_bindings": [
        "protocol.compatibility_probe"
      ],
      "effect_profile_refs": [
        "EP-INSTRUMENT-OBSERVE-USB",
        "EP-INSTRUMENT-CONFIGURE-USB"
      ],
      "data_class": "metadata",
      "node_refs": [
        "PH-S7",
        "PH-P4",
        "PH-P5",
        "PH-C6",
        "PH-X5"
      ],
      "disposition": "provider_internal",
      "reason": "Compatibility settings are snapshot/restore-managed provider state; evaluators select a declared probe profile rather than editing raw configuration."
    },
    {
      "provider_capability_id": "CU-HF-ISO14443-4-APDU",
      "provider": "chameleon_ultra",
      "protocol_family": "ISO14443-4",
      "device_surface": "reader-side firmware APDU handler accepting caller-controlled bytes, isolated behind the provider compiler",
      "upstream_command_ids": [
        2016,
        6004
      ],
      "normalized_operations": [
        "protocol.apdu_exchange"
      ],
      "technique_bindings": [],
      "effect_profile_refs": [
        "EP-TARGET-TRANSMIT-RF",
        "EP-TARGET-MUTATE-RF-STATEFUL",
        "EP-TARGET-DESTROY-RF"
      ],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-P4",
        "PH-IP3",
        "PH-X5"
      ],
      "disposition": "provider_internal",
      "reason": "Commands 2016 and 6004 are broker-private primitives with no evaluator-facing arbitrary-APDU path. Only reviewed schema extensions may compile canonical APDUs, and admission uses the worst-case effect union."
    },
    {
      "provider_capability_id": "CU-HF-MFC-ACQUIRE",
      "provider": "chameleon_ultra",
      "protocol_family": "MIFARE Classic",
      "device_surface": "authentication, block reads, dumps, and bounded sector-key checks",
      "upstream_command_ids": [
        2001,
        2007,
        2008,
        2012,
        2015
      ],
      "normalized_operations": [
        "protocol.authenticate",
        "representation.read"
      ],
      "technique_bindings": [
        "credential.acquire",
        "secret.check_candidates"
      ],
      "effect_profile_refs": [
        "EP-TARGET-TRANSMIT-RF"
      ],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-P4",
        "PH-P5",
        "PH-C2",
        "PH-I4"
      ],
      "disposition": "planned",
      "reason": "Acquisition preserves opaque dumps and keys while returning only fingerprints and artifact references to Bob."
    },
    {
      "provider_capability_id": "CU-HF-MFC-RECOVERY",
      "provider": "chameleon_ultra",
      "protocol_family": "MIFARE Classic",
      "device_surface": "PRNG/nonce-distance detection plus darkside, nested, static nested, encrypted nested, and hardnested acquisition primitives",
      "upstream_command_ids": [
        2002,
        2003,
        2004,
        2005,
        2006,
        2013,
        2014
      ],
      "normalized_operations": [
        "protocol.challenge_collect",
        "representation.read"
      ],
      "technique_bindings": [
        "secret.recover.darkside",
        "secret.recover.nested",
        "secret.recover.static_nested",
        "secret.recover.encrypted_nested",
        "secret.recover.hardnested",
        "secret.recover.autopwn"
      ],
      "effect_profile_refs": [
        "EP-TARGET-TRANSMIT-RF"
      ],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-P4",
        "PH-C2",
        "PH-C3",
        "PH-I3",
        "PH-I4"
      ],
      "disposition": "planned",
      "reason": "Each recovery family is separately applicable, bounded, attributable, and measured; a single success does not close the matrix."
    },
    {
      "provider_capability_id": "CU-HF-MFC-AUTH-TRACE",
      "provider": "chameleon_ultra",
      "protocol_family": "MIFARE Classic",
      "device_surface": "active reader-side anti-collision and Crypto1 authentication trace",
      "upstream_command_ids": [
        2017
      ],
      "normalized_operations": [
        "protocol.authenticate",
        "interaction.trace"
      ],
      "technique_bindings": [
        "credential.auth_trace",
        "protocol.frame_analysis"
      ],
      "effect_profile_refs": [
        "EP-TARGET-TRANSMIT-RF"
      ],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-P4",
        "PH-C2",
        "PH-C7",
        "PH-I4"
      ],
      "disposition": "planned",
      "reason": "This is an active reader exchange against a credential and remains distinct from emulator-side reader logging."
    },
    {
      "provider_capability_id": "CU-HF-MFC-EMULATOR-TRACE",
      "provider": "chameleon_ultra",
      "protocol_family": "MIFARE Classic",
      "device_surface": "emulator authentication/detection logs and nonce collection",
      "upstream_command_ids": [
        4004,
        4005,
        4006,
        4007
      ],
      "normalized_operations": [
        "emulator.present",
        "interaction.trace"
      ],
      "technique_bindings": [
        "verifier.interaction_trace"
      ],
      "effect_profile_refs": [
        "EP-TARGET-PRESENT-RF"
      ],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-P4",
        "PH-P5",
        "PH-C4",
        "PH-C7",
        "PH-I4"
      ],
      "disposition": "planned",
      "reason": "Despite the trace/sniff label, this surface actively emulates toward a verifier and is governed as target presentation over RF."
    },
    {
      "provider_capability_id": "CU-HF-MFC-TRACE-RECOVERY",
      "provider": "chameleon_ultra",
      "protocol_family": "MIFARE Classic",
      "device_surface": "mfkey-style key recovery from captured authentication exchanges",
      "upstream_command_ids": [],
      "normalized_operations": [
        "trace.derive"
      ],
      "technique_bindings": [
        "secret.recover_from_trace"
      ],
      "effect_profile_refs": [],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-P4",
        "PH-C3",
        "PH-C7",
        "PH-I4"
      ],
      "disposition": "planned",
      "reason": "Offline recovery is separated from the active emulation that produced the trace so effects and evidence remain truthful."
    },
    {
      "provider_capability_id": "CU-HF-14A-EMULATOR-CONFIG",
      "provider": "chameleon_ultra",
      "protocol_family": "ISO14443-A emulator",
      "device_surface": "shared emulator anti-collision data read and write",
      "upstream_command_ids": [
        4001,
        4018
      ],
      "normalized_operations": [
        "emulator.profile_observe",
        "emulator.profile_configure"
      ],
      "technique_bindings": [
        "credential.stage_representation"
      ],
      "effect_profile_refs": [
        "EP-INSTRUMENT-OBSERVE-USB",
        "EP-INSTRUMENT-CONFIGURE-USB"
      ],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-P4",
        "PH-P5",
        "PH-C4"
      ],
      "disposition": "provider_internal",
      "reason": "Shared anti-collision state is staged as a workspace representation and never exposed as raw provider configuration."
    },
    {
      "provider_capability_id": "CU-HF-MFC-EMULATION",
      "provider": "chameleon_ultra",
      "protocol_family": "MIFARE Classic",
      "device_surface": "emulator UID/ATQA/SAK/ATS, memory and keys, static/weak/hard PRNG behavior, Gen1A/Gen2 and block-0 behavior, field-reset behavior, detection, and normal/deny/deceive/shadow write modes",
      "upstream_command_ids": [
        4000,
        4008,
        4009,
        4010,
        4011,
        4012,
        4013,
        4014,
        4015,
        4016,
        4017,
        4038,
        4039,
        4040,
        4041
      ],
      "normalized_operations": [
        "representation.stage",
        "emulator.configure",
        "emulator.present"
      ],
      "technique_bindings": [
        "credential.replay"
      ],
      "effect_profile_refs": [
        "EP-INSTRUMENT-CONFIGURE-USB",
        "EP-TARGET-PRESENT-RF"
      ],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-P4",
        "PH-P5",
        "PH-C4",
        "PH-C8"
      ],
      "disposition": "planned",
      "reason": "Credential replay becomes a finding only through an independently observed differential physical experiment."
    },
    {
      "provider_capability_id": "CU-HF-MFC-WRITE",
      "provider": "chameleon_ultra",
      "protocol_family": "MIFARE Classic",
      "device_surface": "block writes, value increment/decrement, restore, and transfer operations",
      "upstream_command_ids": [
        2009,
        2011
      ],
      "normalized_operations": [
        "representation.read",
        "representation.write"
      ],
      "technique_bindings": [
        "credential.mutate",
        "credential.value_semantics_probe"
      ],
      "effect_profile_refs": [
        "EP-TARGET-MUTATE-RF"
      ],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-P4",
        "PH-C5",
        "PH-C8",
        "PH-X5"
      ],
      "disposition": "planned",
      "reason": "Persistent external-media changes require exact asset/action authority, pre-image capture, bounded writes, read-back, and restoration where possible."
    },
    {
      "provider_capability_id": "CU-HF-MFU-ACQUIRE",
      "provider": "chameleon_ultra",
      "protocol_family": "MIFARE Ultralight/NTAG",
      "device_surface": "version, signature, counters, pages, password authentication, and dump acquisition",
      "upstream_command_ids": [],
      "normalized_operations": [
        "protocol.discover",
        "protocol.authenticate",
        "representation.read"
      ],
      "technique_bindings": [
        "credential.classify",
        "credential.acquire"
      ],
      "effect_profile_refs": [
        "EP-TARGET-TRANSMIT-RF",
        "EP-TARGET-MUTATE-RF-STATEFUL",
        "EP-TARGET-DESTROY-RF"
      ],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-P4",
        "PH-C1",
        "PH-C2",
        "PH-I3"
      ],
      "disposition": "planned",
      "reason": "Plain reads and password-authenticated variants are separate compiled techniques. Counter increments require a persistent residual-state effect; any AUTHLIM-style irreversible lockout path requires explicit destroy authority and a terminal-state plan."
    },
    {
      "provider_capability_id": "CU-HF-MFU-EMULATION",
      "provider": "chameleon_ultra",
      "protocol_family": "MIFARE Ultralight/NTAG",
      "device_surface": "emulator UID-magic behavior, pages, counters and tearing state, version, signature, authentication-counter reset, page count, write modes, and emulator configuration",
      "upstream_command_ids": [
        4019,
        4020,
        4021,
        4022,
        4023,
        4024,
        4025,
        4026,
        4027,
        4028,
        4029,
        4030,
        4031,
        4032,
        4037
      ],
      "normalized_operations": [
        "representation.stage",
        "emulator.configure",
        "emulator.present"
      ],
      "technique_bindings": [
        "credential.replay"
      ],
      "effect_profile_refs": [
        "EP-INSTRUMENT-CONFIGURE-USB",
        "EP-TARGET-PRESENT-RF"
      ],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-P4",
        "PH-P5",
        "PH-C4",
        "PH-C8"
      ],
      "disposition": "planned",
      "reason": "Variant fidelity and verifier outcome are recorded separately."
    },
    {
      "provider_capability_id": "CU-HF-MFU-EMULATOR-TRACE",
      "provider": "chameleon_ultra",
      "protocol_family": "MIFARE Ultralight/NTAG",
      "device_surface": "emulator detection enablement, count, logs, and current detection state",
      "upstream_command_ids": [
        4033,
        4034,
        4035,
        4036
      ],
      "normalized_operations": [
        "emulator.present",
        "interaction.trace"
      ],
      "technique_bindings": [
        "verifier.interaction_trace"
      ],
      "effect_profile_refs": [
        "EP-TARGET-PRESENT-RF"
      ],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-P4",
        "PH-P5",
        "PH-C4",
        "PH-C7",
        "PH-I4"
      ],
      "disposition": "planned",
      "reason": "Detection logs are collected from an active emulator interaction and remain separate from offline log analysis."
    },
    {
      "provider_capability_id": "CU-HF-MFU-WRITE",
      "provider": "chameleon_ultra",
      "protocol_family": "MIFARE Ultralight/NTAG",
      "device_surface": "page writes and supported configuration mutations",
      "upstream_command_ids": [],
      "normalized_operations": [
        "representation.read",
        "representation.write"
      ],
      "technique_bindings": [
        "credential.mutate"
      ],
      "effect_profile_refs": [
        "EP-TARGET-MUTATE-RF"
      ],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-P4",
        "PH-C5",
        "PH-C8",
        "PH-X5"
      ],
      "disposition": "planned",
      "reason": "Media writes require a distinct target-mutation template and exact grant even when the same provider can read the media."
    },
    {
      "provider_capability_id": "CU-HF-MFU-DESTRUCTIVE-RECOVERY",
      "provider": "chameleon_ultra",
      "protocol_family": "MIFARE Ultralight compatible clones",
      "device_surface": "ULCG/USCUID-UL challenge collection and recovery workflows that intentionally overwrite key pages",
      "upstream_command_ids": [],
      "normalized_operations": [
        "protocol.challenge_collect",
        "representation.read",
        "representation.write"
      ],
      "technique_bindings": [
        "secret.recover.destructive_clone_variant"
      ],
      "effect_profile_refs": [
        "EP-TARGET-DESTROY-RF"
      ],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-P4",
        "PH-C3",
        "PH-C5",
        "PH-C8",
        "PH-X5"
      ],
      "disposition": "optional",
      "reason": "This hardware-supported path is retained for maximum authorized coverage but requires a separately enabled destructive-recovery variant, explicit media authority, pre-image capture, and an irreversible terminal-state plan."
    },
    {
      "provider_capability_id": "CU-HF-ISO14443-4-RESPONDER",
      "provider": "chameleon_ultra",
      "protocol_family": "ISO14443-4",
      "device_surface": "closed static response maps and anti-collision profile compiled for emulator presentation",
      "upstream_command_ids": [
        6002,
        6003
      ],
      "normalized_operations": [
        "response_profile.stage",
        "emulator.present",
        "protocol.compiled_responder"
      ],
      "technique_bindings": [
        "protocol.scripted_responder"
      ],
      "effect_profile_refs": [
        "EP-INSTRUMENT-CONFIGURE-USB",
        "EP-TARGET-PRESENT-RF"
      ],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-P4",
        "PH-P5",
        "PH-C4",
        "PH-C6",
        "PH-C8"
      ],
      "disposition": "planned",
      "reason": "The evaluator selects a reviewed response-profile schema; the compiler emits only canonical static maps and anti-collision data under a bounded presentation grant."
    },
    {
      "provider_capability_id": "CU-HF-ISO14443-4-RESPOND-PRIMITIVE",
      "provider": "chameleon_ultra",
      "protocol_family": "ISO14443-4",
      "device_surface": "host-driven APDU receive/send firmware handlers isolated behind the response compiler",
      "upstream_command_ids": [
        6000,
        6001
      ],
      "normalized_operations": [
        "protocol.respond"
      ],
      "technique_bindings": [],
      "effect_profile_refs": [
        "EP-TARGET-PRESENT-RF"
      ],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-P4",
        "PH-IP3",
        "PH-X5"
      ],
      "disposition": "provider_internal",
      "reason": "Commands 6000 and 6001 remain broker-private. Evaluators cannot inject arbitrary host responses; only a reviewed responder compiler may drive this primitive."
    },
    {
      "provider_capability_id": "CU-HF-ISO14443-4-DIAGNOSTICS",
      "provider": "chameleon_ultra",
      "protocol_family": "ISO14443-4",
      "device_surface": "registry-private T=CL debug counters",
      "upstream_command_ids": [
        6010
      ],
      "normalized_operations": [
        "protocol.diagnostics_observe"
      ],
      "technique_bindings": [],
      "effect_profile_refs": [
        "EP-INSTRUMENT-OBSERVE-USB"
      ],
      "data_class": "metadata",
      "node_refs": [
        "PH-P4",
        "PH-P5",
        "PH-C6",
        "PH-X5"
      ],
      "disposition": "provider_internal",
      "reason": "Command 6010 is registered and reported for Ultra in app_cmd.c but has no public data_cmd.h symbol; it remains typed provider diagnostics, never a raw command escape hatch."
    },
    {
      "provider_capability_id": "CU-HF-DESFIRE-ENUMERATE",
      "provider": "chameleon_ultra",
      "protocol_family": "MIFARE DESFire",
      "device_surface": "version, UID, and application identifier enumeration through APDUs",
      "upstream_command_ids": [],
      "normalized_operations": [
        "protocol.compiled_exchange",
        "representation.fingerprint"
      ],
      "technique_bindings": [
        "application.enumerate",
        "credential.classify"
      ],
      "effect_profile_refs": [
        "EP-TARGET-TRANSMIT-RF"
      ],
      "data_class": "linkable",
      "node_refs": [
        "PH-P4",
        "PH-C1",
        "PH-C6",
        "PH-I3"
      ],
      "disposition": "planned",
      "reason": "Enumeration is supported as an APDU technique and does not imply full DESFire semantics or emulation."
    },
    {
      "provider_capability_id": "CU-HF-DESFIRE-AUTH-PROBE",
      "provider": "chameleon_ultra",
      "protocol_family": "MIFARE DESFire",
      "device_surface": "bounded DES, 2TDEA, 3K3DES, and AES dictionary authentication attempts",
      "upstream_command_ids": [],
      "normalized_operations": [
        "protocol.compiled_exchange"
      ],
      "technique_bindings": [
        "credential.auth_probe",
        "secret.check_candidates"
      ],
      "effect_profile_refs": [
        "EP-TARGET-TRANSMIT-RF",
        "EP-TARGET-MUTATE-RF-STATEFUL"
      ],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-P4",
        "PH-C2",
        "PH-C3",
        "PH-C6"
      ],
      "disposition": "planned",
      "reason": "Attempt budgets and potential verifier lockout or logging are engagement-scoped constraints."
    },
    {
      "provider_capability_id": "CU-HF-EMV-PROFILE",
      "provider": "chameleon_ultra",
      "protocol_family": "EMV contactless",
      "device_surface": "application/profile acquisition and static response emulation",
      "upstream_command_ids": [
        6005
      ],
      "normalized_operations": [
        "protocol.compiled_exchange",
        "representation.read",
        "response_profile.stage",
        "protocol.compiled_responder"
      ],
      "technique_bindings": [
        "application_profile.acquire",
        "application_profile.replay"
      ],
      "effect_profile_refs": [
        "EP-TARGET-TRANSMIT-RF",
        "EP-TARGET-MUTATE-RF-STATEFUL",
        "EP-TARGET-PRESENT-RF"
      ],
      "data_class": "regulated",
      "node_refs": [
        "PH-P4",
        "PH-C2",
        "PH-C4",
        "PH-C6",
        "PH-X2"
      ],
      "disposition": "optional",
      "reason": "Regulated payment data requires a separately enabled specialist pack, stricter context isolation, and engagement-specific authority."
    },
    {
      "provider_capability_id": "CU-LF-DISCOVERY",
      "provider": "chameleon_ultra",
      "protocol_family": "LF 125 kHz",
      "device_surface": "EM410x, HID Prox, ioProx, PAC, Viking, Jablotron, and EM4x05 family detection and decoding",
      "upstream_command_ids": [
        3000,
        3002,
        3004,
        3010,
        3014,
        3019,
        3030
      ],
      "normalized_operations": [
        "protocol.discover",
        "representation.decode",
        "representation.fingerprint"
      ],
      "technique_bindings": [
        "credential.classify"
      ],
      "effect_profile_refs": [
        "EP-TARGET-TRANSMIT-RF"
      ],
      "data_class": "linkable",
      "node_refs": [
        "PH-P4",
        "PH-C1",
        "PH-I2",
        "PH-I3"
      ],
      "disposition": "planned",
      "reason": "LF discovery energizes the instrument's reader field and is not represented as passive observation."
    },
    {
      "provider_capability_id": "CU-LF-SIGNAL-CAPTURE",
      "provider": "chameleon_ultra",
      "protocol_family": "LF 125 kHz",
      "device_surface": "waveform sampling, modulation/clock classification, and raw decode workflows",
      "upstream_command_ids": [
        3009,
        3031
      ],
      "normalized_operations": [
        "signal.capture"
      ],
      "technique_bindings": [
        "signal.classify",
        "representation.decode_raw"
      ],
      "effect_profile_refs": [
        "EP-TARGET-TRANSMIT-RF"
      ],
      "data_class": "linkable",
      "node_refs": [
        "PH-P4",
        "PH-P5",
        "PH-C1",
        "PH-C7",
        "PH-I4"
      ],
      "disposition": "planned",
      "reason": "The device supplies its own LF field during capture, so the provider declares active reader RF regardless of command naming."
    },
    {
      "provider_capability_id": "CU-LF-DECLARED-UNREGISTERED",
      "provider": "chameleon_ultra",
      "protocol_family": "LF 125 kHz",
      "device_surface": "generic read, correlated generic read, and EM4x05 read-sniff declarations absent from the Ultra v2.2.0 runtime registry",
      "upstream_command_ids": [
        3007,
        3008,
        3032
      ],
      "normalized_operations": [
        "signal.capture",
        "representation.decode_raw"
      ],
      "technique_bindings": [
        "signal.classify"
      ],
      "effect_profile_refs": [],
      "data_class": "linkable",
      "node_refs": [
        "PH-P4",
        "PH-I1",
        "PH-I3",
        "PH-C7"
      ],
      "disposition": "unsupported",
      "reason": "These IDs are declared in data_cmd.h but absent from the Ultra command registry/capability response; they remain unavailable unless a later reviewed, assurance-qualified firmware profile registers and version-gates them."
    },
    {
      "provider_capability_id": "CU-LF-IOPROX-CODEC",
      "provider": "chameleon_ultra",
      "protocol_family": "ioProx",
      "device_surface": "pure-local raw-frame decode and identifier composition",
      "upstream_command_ids": [
        3012,
        3013
      ],
      "normalized_operations": [
        "representation.decode",
        "representation.compose"
      ],
      "technique_bindings": [
        "credential.classify",
        "credential.stage_representation"
      ],
      "effect_profile_refs": [],
      "data_class": "linkable",
      "node_refs": [
        "PH-P4",
        "PH-C1",
        "PH-C7"
      ],
      "disposition": "planned",
      "reason": "These transformations operate on already-held data and do not inherit the active RF effect of live LF discovery."
    },
    {
      "provider_capability_id": "CU-LF-EMULATION",
      "provider": "chameleon_ultra",
      "protocol_family": "LF 125 kHz",
      "device_surface": "EM410x/Electra, HID Prox, ioProx, PAC, Viking, Jablotron, and IDTECK LF identifier staging and emulation",
      "upstream_command_ids": [
        5000,
        5001,
        5002,
        5003,
        5004,
        5005,
        5006,
        5007,
        5008,
        5009,
        5010,
        5011,
        5012,
        5013
      ],
      "normalized_operations": [
        "representation.stage",
        "emulator.present"
      ],
      "technique_bindings": [
        "credential.replay"
      ],
      "effect_profile_refs": [
        "EP-INSTRUMENT-CONFIGURE-USB",
        "EP-TARGET-PRESENT-RF"
      ],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-P4",
        "PH-P5",
        "PH-C4",
        "PH-C8"
      ],
      "disposition": "planned",
      "reason": "Format-specific staging is separate from the independently observed verifier response."
    },
    {
      "provider_capability_id": "CU-LF-T55XX-WRITE",
      "provider": "chameleon_ultra",
      "protocol_family": "T55xx",
      "device_surface": "protocol-specific and generic T55xx writes used by supported clone workflows",
      "upstream_command_ids": [
        3001,
        3003,
        3005,
        3006,
        3011,
        3015,
        3016,
        3018,
        3020
      ],
      "normalized_operations": [
        "representation.write"
      ],
      "technique_bindings": [
        "credential.clone_to_media",
        "credential.mutate"
      ],
      "effect_profile_refs": [
        "EP-TARGET-MUTATE-RF"
      ],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-P4",
        "PH-C2",
        "PH-C5",
        "PH-C8",
        "PH-X5"
      ],
      "disposition": "planned",
      "reason": "The Ultra emits the write stimulus but its acknowledgement is not write verification. Raw block/password/lock/pre-image state remains inconclusive unless an independent assurance-qualified T55xx reader supplies before/after evidence."
    },
    {
      "provider_capability_id": "CU-LF-T55XX-DESTRUCTIVE",
      "provider": "chameleon_ultra",
      "protocol_family": "T55xx",
      "device_surface": "optional wipe/reinitialization technique composed from generic T55xx writes; not a distinct firmware command",
      "upstream_command_ids": [],
      "normalized_operations": [
        "representation.write"
      ],
      "technique_bindings": [
        "credential.wipe_media"
      ],
      "effect_profile_refs": [
        "EP-TARGET-DESTROY-RF"
      ],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-P4",
        "PH-C5",
        "PH-C8",
        "PH-X5"
      ],
      "disposition": "optional",
      "reason": "This capability remains disabled until an independent assurance-qualified T55xx read provider is present; enabling it also requires explicit target authority, pre-image capture, and an irreversible terminal-state plan."
    },
    {
      "provider_capability_id": "CU-ADMIN-BLE-PAIRING",
      "provider": "chameleon_ultra",
      "protocol_family": "instrument administration",
      "device_surface": "BLE pairing key, bond management, and advertising posture",
      "upstream_command_ids": [
        1030,
        1031,
        1032,
        1036,
        1037
      ],
      "normalized_operations": [
        "instrument.admin_configure"
      ],
      "technique_bindings": [],
      "effect_profile_refs": [
        "EP-INSTRUMENT-ADMINISTER-BLE"
      ],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-P5",
        "PH-P6",
        "PH-X3"
      ],
      "disposition": "operator_only",
      "reason": "Transport administration changes access to the instrument and is not an evaluator capability."
    },
    {
      "provider_capability_id": "CU-ADMIN-DEVICE-SETTINGS",
      "provider": "chameleon_ultra",
      "protocol_family": "instrument administration",
      "device_surface": "settings save/reset, LED/animation, sleep timeout, and button bindings including selection of clone or field-generator actions; this row does not invoke those actions",
      "upstream_command_ids": [
        1013,
        1014,
        1015,
        1016,
        1026,
        1027,
        1028,
        1029,
        1034,
        1039,
        1040
      ],
      "normalized_operations": [
        "instrument.admin_configure"
      ],
      "technique_bindings": [],
      "effect_profile_refs": [
        "EP-INSTRUMENT-ADMINISTER-LOCAL"
      ],
      "data_class": "metadata",
      "node_refs": [
        "PH-P5",
        "PH-X3",
        "PH-X5"
      ],
      "disposition": "operator_only",
      "reason": "Ordinary evaluator techniques do not need persistent device-preference mutation; binding a button does not grant authority to invoke its target-facing action."
    },
    {
      "provider_capability_id": "CU-ADMIN-FIELD-GENERATOR-INVOKE",
      "provider": "chameleon_ultra",
      "protocol_family": "instrument administration",
      "device_surface": "manual invocation of a configured field-generator button action",
      "upstream_command_ids": [],
      "normalized_operations": [
        "instrument.manual_action"
      ],
      "technique_bindings": [
        "environment.rf_field_exposure"
      ],
      "effect_profile_refs": [
        "EP-ENVIRONMENT-TRANSMIT-RF-MANUAL"
      ],
      "data_class": "metadata",
      "node_refs": [
        "PH-P4",
        "PH-P5",
        "PH-P9",
        "PH-C6",
        "PH-X5"
      ],
      "disposition": "operator_only",
      "reason": "Invocation is an operator-mediated field-exposure technique, not a generic button tool. It needs complete spatial/temporal RF bounds, reservation/admission, operator and independent witness receipts, and verifier-owned outcome evidence."
    },
    {
      "provider_capability_id": "CU-ADMIN-BUTTON-CLONE-INVOKE",
      "provider": "chameleon_ultra",
      "protocol_family": "instrument administration",
      "device_surface": "manual invocation of a configured read-and-stage clone button action",
      "upstream_command_ids": [],
      "normalized_operations": [
        "instrument.manual_action",
        "protocol.discover",
        "representation.stage"
      ],
      "technique_bindings": [
        "credential.acquire_and_stage"
      ],
      "effect_profile_refs": [
        "EP-TARGET-TRANSMIT-RF-MANUAL",
        "EP-INSTRUMENT-CONFIGURE-MANUAL"
      ],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-P4",
        "PH-P5",
        "PH-P9",
        "PH-C1",
        "PH-C2",
        "PH-X5"
      ],
      "disposition": "operator_only",
      "reason": "The physical button action combines active credential discovery with workspace mutation, cannot inherit authority from the harmless binding command, and closes only from operator plus independent witness receipts."
    },
    {
      "provider_capability_id": "CU-ADMIN-DFU",
      "provider": "chameleon_ultra",
      "protocol_family": "instrument administration",
      "device_surface": "bootloader/DFU entry followed by operator-owned firmware tooling",
      "upstream_command_ids": [
        1010
      ],
      "normalized_operations": [
        "instrument.firmware_manage"
      ],
      "technique_bindings": [],
      "effect_profile_refs": [
        "EP-INSTRUMENT-ADMINISTER-LOCAL"
      ],
      "data_class": "metadata",
      "node_refs": [
        "PH-P1",
        "PH-P5",
        "PH-X3",
        "PH-X5"
      ],
      "disposition": "operator_only",
      "reason": "Bootloader entry changes the instrument trust state but is not itself data erasure; firmware tooling stays outside the routine pentest pack."
    },
    {
      "provider_capability_id": "CU-ADMIN-DATA-ERASE",
      "provider": "chameleon_ultra",
      "protocol_family": "instrument administration",
      "device_surface": "FDS data erase",
      "upstream_command_ids": [
        1020
      ],
      "normalized_operations": [
        "instrument.erase"
      ],
      "technique_bindings": [],
      "effect_profile_refs": [
        "EP-INSTRUMENT-DESTROY-USB"
      ],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-P5",
        "PH-X3",
        "PH-X5"
      ],
      "disposition": "operator_only",
      "reason": "Instrument data erasure is irreversible administration and remains distinct from settings reset and DFU entry."
    },
    {
      "provider_capability_id": "CU-GAP-ICLASS",
      "provider": "chameleon_ultra",
      "protocol_family": "iCLASS",
      "device_surface": "credential discovery, acquisition, and emulation",
      "upstream_command_ids": [],
      "normalized_operations": [
        "protocol.discover",
        "representation.read",
        "emulator.present"
      ],
      "technique_bindings": [
        "credential.classify",
        "credential.acquire",
        "credential.replay"
      ],
      "effect_profile_refs": [],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-I1",
        "PH-I3",
        "PH-P4"
      ],
      "disposition": "unsupported",
      "reason": "No provider capability is claimed for this family; a different instrument provider is required."
    },
    {
      "provider_capability_id": "CU-GAP-ISO15693",
      "provider": "chameleon_ultra",
      "protocol_family": "ISO15693",
      "device_surface": "vicinity-card discovery, acquisition, and emulation",
      "upstream_command_ids": [],
      "normalized_operations": [
        "protocol.discover",
        "representation.read",
        "emulator.present"
      ],
      "technique_bindings": [
        "credential.classify",
        "credential.acquire",
        "credential.replay"
      ],
      "effect_profile_refs": [],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-I1",
        "PH-I3",
        "PH-P4"
      ],
      "disposition": "unsupported",
      "reason": "No provider capability is claimed for this family; the technique matrix records the hardware prerequisite."
    },
    {
      "provider_capability_id": "CU-GAP-MIFARE-PLUS",
      "provider": "chameleon_ultra",
      "protocol_family": "MIFARE Plus",
      "device_surface": "native secure-mode acquisition and emulation",
      "upstream_command_ids": [],
      "normalized_operations": [
        "representation.read",
        "emulator.present"
      ],
      "technique_bindings": [
        "credential.acquire",
        "credential.replay"
      ],
      "effect_profile_refs": [],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-I1",
        "PH-I3",
        "PH-P4"
      ],
      "disposition": "unsupported",
      "reason": "ISO14443-A fingerprinting may observe a card, but native secure-mode support is not inferred from discovery."
    },
    {
      "provider_capability_id": "CU-GAP-DESFIRE-FULL",
      "provider": "chameleon_ultra",
      "protocol_family": "MIFARE DESFire",
      "device_surface": "complete authenticated file operations and faithful full-card emulation",
      "upstream_command_ids": [],
      "normalized_operations": [
        "representation.read",
        "emulator.present"
      ],
      "technique_bindings": [
        "credential.acquire",
        "credential.replay"
      ],
      "effect_profile_refs": [],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-I1",
        "PH-I3",
        "PH-P4"
      ],
      "disposition": "unsupported",
      "reason": "APDU enumeration and dictionary probes do not establish complete DESFire acquisition or emulation."
    },
    {
      "provider_capability_id": "CU-GAP-PASSIVE-HF-SNIFF",
      "provider": "chameleon_ultra",
      "protocol_family": "ISO14443-A",
      "device_surface": "passive over-the-air capture of an unrelated card-reader exchange",
      "upstream_command_ids": [],
      "normalized_operations": [
        "signal.capture_passive"
      ],
      "technique_bindings": [
        "signal.passive_trace"
      ],
      "effect_profile_refs": [],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-I1",
        "PH-I3",
        "PH-P4",
        "PH-C7"
      ],
      "disposition": "unsupported",
      "reason": "The Ultra's HF sniff workflow is active emulation plus reader trace, not passive RF interception."
    },
    {
      "provider_capability_id": "CU-GAP-UNIVERSAL-RELAY",
      "provider": "chameleon_ultra",
      "protocol_family": "multi-protocol",
      "device_surface": "transparent low-latency universal credential relay",
      "upstream_command_ids": [],
      "normalized_operations": [
        "protocol.relay"
      ],
      "technique_bindings": [
        "credential.relay"
      ],
      "effect_profile_refs": [],
      "data_class": "credential_secret",
      "node_refs": [
        "PH-I1",
        "PH-I3",
        "PH-P4",
        "PH-C6"
      ],
      "disposition": "unsupported",
      "reason": "Host-driven APDU experiments are not represented as a transparent or timing-faithful universal relay."
    }
  ],
  "command_source_registry": [
    {
      "command_id": 1000,
      "declaration_symbol": "DATA_CMD_GET_APP_VERSION",
      "runtime_handler_symbol": "cmd_processor_get_app_version",
      "hook_symbols": [],
      "provider_capability_id": "CU-CORE-INVENTORY",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "4fecd2137b367544cc19bd88436c6f4af037f3640417ee70b9b75911a733abd1"
    },
    {
      "command_id": 1001,
      "declaration_symbol": "DATA_CMD_CHANGE_DEVICE_MODE",
      "runtime_handler_symbol": "cmd_processor_change_device_mode",
      "hook_symbols": [],
      "provider_capability_id": "CU-RF-SESSION",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "32c823563e7dc2afdade0dcf424fd8e7db55bd6e5fedc676c4056b3c384421dc"
    },
    {
      "command_id": 1002,
      "declaration_symbol": "DATA_CMD_GET_DEVICE_MODE",
      "runtime_handler_symbol": "cmd_processor_get_device_mode",
      "hook_symbols": [],
      "provider_capability_id": "CU-RF-SESSION",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "cdf7de0f0f9c7a1785f4a7bd4e0e81a01f22d41d3879628cfc9c9112583afc80"
    },
    {
      "command_id": 1003,
      "declaration_symbol": "DATA_CMD_SET_ACTIVE_SLOT",
      "runtime_handler_symbol": "cmd_processor_set_active_slot",
      "hook_symbols": [],
      "provider_capability_id": "CU-WORKSPACE-SLOTS",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "4277578d0afa4e6bc4a7972683b02d4ed32a4712ad94ed87a70fed953d044064"
    },
    {
      "command_id": 1004,
      "declaration_symbol": "DATA_CMD_SET_SLOT_TAG_TYPE",
      "runtime_handler_symbol": "cmd_processor_set_slot_tag_type",
      "hook_symbols": [],
      "provider_capability_id": "CU-WORKSPACE-SLOTS",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "8e250fb8ab819353a11b3444b0297978738a965405896364c9e7a38d1a5a4613"
    },
    {
      "command_id": 1005,
      "declaration_symbol": "DATA_CMD_SET_SLOT_DATA_DEFAULT",
      "runtime_handler_symbol": "cmd_processor_set_slot_data_default",
      "hook_symbols": [],
      "provider_capability_id": "CU-WORKSPACE-SLOTS",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "80ba57cf71b519030841f087f53802a0999a587dd30ddac458e957fb5fe264aa"
    },
    {
      "command_id": 1006,
      "declaration_symbol": "DATA_CMD_SET_SLOT_ENABLE",
      "runtime_handler_symbol": "cmd_processor_set_slot_enable",
      "hook_symbols": [],
      "provider_capability_id": "CU-WORKSPACE-SLOTS",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "5f266ecde3e72f3c377743ac4d40c0b671954b5537d3d6871d9788b7c5049fd9"
    },
    {
      "command_id": 1007,
      "declaration_symbol": "DATA_CMD_SET_SLOT_TAG_NICK",
      "runtime_handler_symbol": "cmd_processor_set_slot_tag_nick",
      "hook_symbols": [],
      "provider_capability_id": "CU-WORKSPACE-SLOTS",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "ad2c813d4e69c9ed2ecb68b11282211e445865053077df87012cccf27ea41eb3"
    },
    {
      "command_id": 1008,
      "declaration_symbol": "DATA_CMD_GET_SLOT_TAG_NICK",
      "runtime_handler_symbol": "cmd_processor_get_slot_tag_nick",
      "hook_symbols": [],
      "provider_capability_id": "CU-WORKSPACE-SLOTS",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "c76192d024ffa16b241d5204df249b1a512d4e315f1c35d0095ebead881696e9"
    },
    {
      "command_id": 1009,
      "declaration_symbol": "DATA_CMD_SLOT_DATA_CONFIG_SAVE",
      "runtime_handler_symbol": "cmd_processor_slot_data_config_save",
      "hook_symbols": [],
      "provider_capability_id": "CU-WORKSPACE-SLOTS",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "7a31fc1310057c621038649ddcda268191ece5258dbf6607d1ab82bd5ca6a937"
    },
    {
      "command_id": 1010,
      "declaration_symbol": "DATA_CMD_ENTER_BOOTLOADER",
      "runtime_handler_symbol": "cmd_processor_enter_bootloader",
      "hook_symbols": [],
      "provider_capability_id": "CU-ADMIN-DFU",
      "disposition": "operator_only",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "bbe26e678b23504193dd365fbdccaea3391879a116c001fb6d4f3fa392ad9366"
    },
    {
      "command_id": 1011,
      "declaration_symbol": "DATA_CMD_GET_DEVICE_CHIP_ID",
      "runtime_handler_symbol": "cmd_processor_get_device_chip_id",
      "hook_symbols": [],
      "provider_capability_id": "CU-CORE-IDENTITY-ENROLLMENT",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "bcb9bed76a7bc59adf0043866a8d11dc6244a241b87f8bb761bf286ca39f868c"
    },
    {
      "command_id": 1012,
      "declaration_symbol": "DATA_CMD_GET_DEVICE_ADDRESS",
      "runtime_handler_symbol": "cmd_processor_get_device_address",
      "hook_symbols": [],
      "provider_capability_id": "CU-CORE-IDENTITY-ENROLLMENT",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "dbf4f95dc3d368f44992dda4147859e5178c7dd19a21f5ec5f3521c2dda022ab"
    },
    {
      "command_id": 1013,
      "declaration_symbol": "DATA_CMD_SAVE_SETTINGS",
      "runtime_handler_symbol": "cmd_processor_save_settings",
      "hook_symbols": [],
      "provider_capability_id": "CU-ADMIN-DEVICE-SETTINGS",
      "disposition": "operator_only",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "96a5c0c488b1678ce8d8cd95dcd658d633e9be7425fe8f1a9e78984f9fcf9f1b"
    },
    {
      "command_id": 1014,
      "declaration_symbol": "DATA_CMD_RESET_SETTINGS",
      "runtime_handler_symbol": "cmd_processor_reset_settings",
      "hook_symbols": [],
      "provider_capability_id": "CU-ADMIN-DEVICE-SETTINGS",
      "disposition": "operator_only",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "d719af8278e267631202242c7657f7a312e106277ac4d331e326c805402dc8ae"
    },
    {
      "command_id": 1015,
      "declaration_symbol": "DATA_CMD_SET_ANIMATION_MODE",
      "runtime_handler_symbol": "cmd_processor_set_animation_mode",
      "hook_symbols": [],
      "provider_capability_id": "CU-ADMIN-DEVICE-SETTINGS",
      "disposition": "operator_only",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "57d6267d4ac1a993170517a61f1fd4a6fece6fd605afcfe34a3279c91cd6b7fe"
    },
    {
      "command_id": 1016,
      "declaration_symbol": "DATA_CMD_GET_ANIMATION_MODE",
      "runtime_handler_symbol": "cmd_processor_get_animation_mode",
      "hook_symbols": [],
      "provider_capability_id": "CU-ADMIN-DEVICE-SETTINGS",
      "disposition": "operator_only",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "5e324fbe62a11aa417e73d3f980f8b53981d12190634046ee957f0b1686982f9"
    },
    {
      "command_id": 1017,
      "declaration_symbol": "DATA_CMD_GET_GIT_VERSION",
      "runtime_handler_symbol": "cmd_processor_get_git_version",
      "hook_symbols": [],
      "provider_capability_id": "CU-CORE-INVENTORY",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "0737dfd58891a7a9e69f024e3aa286235070976951ef16b8c2fe0ee6db9bfcc0"
    },
    {
      "command_id": 1018,
      "declaration_symbol": "DATA_CMD_GET_ACTIVE_SLOT",
      "runtime_handler_symbol": "cmd_processor_get_active_slot",
      "hook_symbols": [],
      "provider_capability_id": "CU-WORKSPACE-SLOTS",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "ea210d2a059e7d484d800a9306a5a9ad76e7567722f37c29333ff0632403a22c"
    },
    {
      "command_id": 1019,
      "declaration_symbol": "DATA_CMD_GET_SLOT_INFO",
      "runtime_handler_symbol": "cmd_processor_get_slot_info",
      "hook_symbols": [],
      "provider_capability_id": "CU-WORKSPACE-SLOTS",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "ff406db6fc5b6f5a45f9b94ae142a6ac44eab8912670ab1c387b49fa97024c3b"
    },
    {
      "command_id": 1020,
      "declaration_symbol": "DATA_CMD_WIPE_FDS",
      "runtime_handler_symbol": "cmd_processor_wipe_fds",
      "hook_symbols": [],
      "provider_capability_id": "CU-ADMIN-DATA-ERASE",
      "disposition": "operator_only",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "b5a1209eaff2f594b71a80c97d1a9bb4eeafb0a36f6722f7c470a29d4436cb98"
    },
    {
      "command_id": 1021,
      "declaration_symbol": "DATA_CMD_DELETE_SLOT_TAG_NICK",
      "runtime_handler_symbol": "cmd_processor_delete_slot_tag_nick",
      "hook_symbols": [],
      "provider_capability_id": "CU-WORKSPACE-SLOTS",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "137f49d51671dcc779d7842dc86235689eddac13fa142ad38512592110fef190"
    },
    {
      "command_id": 1023,
      "declaration_symbol": "DATA_CMD_GET_ENABLED_SLOTS",
      "runtime_handler_symbol": "cmd_processor_get_enabled_slots",
      "hook_symbols": [],
      "provider_capability_id": "CU-WORKSPACE-SLOTS",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "c92cb438342c73cab57cf987a00677d275fbd0ef28e95eb3457372e072b9414d"
    },
    {
      "command_id": 1024,
      "declaration_symbol": "DATA_CMD_DELETE_SLOT_SENSE_TYPE",
      "runtime_handler_symbol": "cmd_processor_delete_slot_sense_type",
      "hook_symbols": [],
      "provider_capability_id": "CU-WORKSPACE-SLOTS",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "96459b19b91151d3adeff47d0f0674546e1a082506054f4c6ddaca6156ce2521"
    },
    {
      "command_id": 1025,
      "declaration_symbol": "DATA_CMD_GET_BATTERY_INFO",
      "runtime_handler_symbol": "cmd_processor_get_battery_info",
      "hook_symbols": [],
      "provider_capability_id": "CU-CORE-INVENTORY",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "8e76c427e200a18c783195037758b01a62ba4629f10abc61911581a060e1fd22"
    },
    {
      "command_id": 1026,
      "declaration_symbol": "DATA_CMD_GET_BUTTON_PRESS_CONFIG",
      "runtime_handler_symbol": "cmd_processor_get_button_press_config",
      "hook_symbols": [],
      "provider_capability_id": "CU-ADMIN-DEVICE-SETTINGS",
      "disposition": "operator_only",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "adb2d63755310880558487aeacdc15362b6cb3b1031b3287d9269aa01148ed83"
    },
    {
      "command_id": 1027,
      "declaration_symbol": "DATA_CMD_SET_BUTTON_PRESS_CONFIG",
      "runtime_handler_symbol": "cmd_processor_set_button_press_config",
      "hook_symbols": [],
      "provider_capability_id": "CU-ADMIN-DEVICE-SETTINGS",
      "disposition": "operator_only",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "e9f88a81f64889f27955113d3a14a11b0e806d7ba9c78fa37e3c3880b5e530b9"
    },
    {
      "command_id": 1028,
      "declaration_symbol": "DATA_CMD_GET_LONG_BUTTON_PRESS_CONFIG",
      "runtime_handler_symbol": "cmd_processor_get_long_button_press_config",
      "hook_symbols": [],
      "provider_capability_id": "CU-ADMIN-DEVICE-SETTINGS",
      "disposition": "operator_only",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "cb3a8e41ec63d2e135d508cb75974eba67056e9bb7a593168e1f7065e1362bb2"
    },
    {
      "command_id": 1029,
      "declaration_symbol": "DATA_CMD_SET_LONG_BUTTON_PRESS_CONFIG",
      "runtime_handler_symbol": "cmd_processor_set_long_button_press_config",
      "hook_symbols": [],
      "provider_capability_id": "CU-ADMIN-DEVICE-SETTINGS",
      "disposition": "operator_only",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "3dc6643805a863832467b870a922e281738864a9c1c4816c7cc591bfb275a3a9"
    },
    {
      "command_id": 1030,
      "declaration_symbol": "DATA_CMD_SET_BLE_PAIRING_KEY",
      "runtime_handler_symbol": "cmd_processor_set_ble_connect_key",
      "hook_symbols": [],
      "provider_capability_id": "CU-ADMIN-BLE-PAIRING",
      "disposition": "operator_only",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "dd64a9fce254450755ae34f060e546df4decccc0fcfad365f4b2731b0a5fccbb"
    },
    {
      "command_id": 1031,
      "declaration_symbol": "DATA_CMD_GET_BLE_PAIRING_KEY",
      "runtime_handler_symbol": "cmd_processor_get_ble_connect_key",
      "hook_symbols": [],
      "provider_capability_id": "CU-ADMIN-BLE-PAIRING",
      "disposition": "operator_only",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "ee5d951cb991739cb3493f1088c45b86340d957bfd706dd4ab16b98818870b59"
    },
    {
      "command_id": 1032,
      "declaration_symbol": "DATA_CMD_DELETE_ALL_BLE_BONDS",
      "runtime_handler_symbol": "cmd_processor_delete_all_ble_bonds",
      "hook_symbols": [],
      "provider_capability_id": "CU-ADMIN-BLE-PAIRING",
      "disposition": "operator_only",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "833ad7f96a5b6d70a02aecaf9dfd813af660f4d17e3a36581a529b2df18b5cce"
    },
    {
      "command_id": 1033,
      "declaration_symbol": "DATA_CMD_GET_DEVICE_MODEL",
      "runtime_handler_symbol": "cmd_processor_get_device_model",
      "hook_symbols": [],
      "provider_capability_id": "CU-CORE-INVENTORY",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "61c3bcf8b05c53b5b600f9066726a60a0e6b1aefe1910f0234fbf7d0a90aa25b"
    },
    {
      "command_id": 1034,
      "declaration_symbol": "DATA_CMD_GET_DEVICE_SETTINGS",
      "runtime_handler_symbol": "cmd_processor_get_device_settings",
      "hook_symbols": [],
      "provider_capability_id": "CU-ADMIN-DEVICE-SETTINGS",
      "disposition": "operator_only",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "fabf4605d7ceefca40ff77acfa957e053189dcf5f70f8a43bda18e99af58ed21"
    },
    {
      "command_id": 1035,
      "declaration_symbol": "DATA_CMD_GET_DEVICE_CAPABILITIES",
      "runtime_handler_symbol": "cmd_processor_get_device_capabilities",
      "hook_symbols": [],
      "provider_capability_id": "CU-CORE-INVENTORY",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "507e1ac6074f80de4ce93c7716c01645327510956fa6e8c72cd20d65ba6b1def"
    },
    {
      "command_id": 1036,
      "declaration_symbol": "DATA_CMD_GET_BLE_PAIRING_ENABLE",
      "runtime_handler_symbol": "cmd_processor_get_ble_pairing_enable",
      "hook_symbols": [],
      "provider_capability_id": "CU-ADMIN-BLE-PAIRING",
      "disposition": "operator_only",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "9b3e586f3613b2f5c9fa21fe16c8d5f9890982a56c58aa4739007dcedf0dc457"
    },
    {
      "command_id": 1037,
      "declaration_symbol": "DATA_CMD_SET_BLE_PAIRING_ENABLE",
      "runtime_handler_symbol": "cmd_processor_set_ble_pairing_enable",
      "hook_symbols": [],
      "provider_capability_id": "CU-ADMIN-BLE-PAIRING",
      "disposition": "operator_only",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "0480bef03ea7de35b4cc728a10f44f7e5dd691e6d05649b8fdaacdf0e3e57209"
    },
    {
      "command_id": 1038,
      "declaration_symbol": "DATA_CMD_GET_ALL_SLOT_NICKS",
      "runtime_handler_symbol": "cmd_processor_get_all_slot_nicks",
      "hook_symbols": [],
      "provider_capability_id": "CU-WORKSPACE-SLOTS",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "dfc260ff291c92a9e00cb1b5f7fd2f971293ea4fcd04c80b876c95923bc8315d"
    },
    {
      "command_id": 1039,
      "declaration_symbol": "DATA_CMD_GET_SLEEP_TIMEOUT",
      "runtime_handler_symbol": "cmd_processor_get_sleep_timeout",
      "hook_symbols": [],
      "provider_capability_id": "CU-ADMIN-DEVICE-SETTINGS",
      "disposition": "operator_only",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "6f703a1a668d46fa5f49aab9e004a44fdc8fa8ec43f916e0106eedd3e91d9a4d"
    },
    {
      "command_id": 1040,
      "declaration_symbol": "DATA_CMD_SET_SLEEP_TIMEOUT",
      "runtime_handler_symbol": "cmd_processor_set_sleep_timeout",
      "hook_symbols": [],
      "provider_capability_id": "CU-ADMIN-DEVICE-SETTINGS",
      "disposition": "operator_only",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "775a2a3e75b328bdeb3c39a4303b5f234b90e7727ce1429bc4cce89b87fc26c1"
    },
    {
      "command_id": 2000,
      "declaration_symbol": "DATA_CMD_HF14A_SCAN",
      "runtime_handler_symbol": "cmd_processor_hf14a_scan",
      "hook_symbols": [
        "after_hf_reader_run",
        "before_hf_reader_run"
      ],
      "provider_capability_id": "CU-HF-14A-DISCOVERY",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "8e914936c8327cfa0fd9cda4c45b5e4e75be42fc4aad0e4f934ebb370de99a08"
    },
    {
      "command_id": 2001,
      "declaration_symbol": "DATA_CMD_MF1_DETECT_SUPPORT",
      "runtime_handler_symbol": "cmd_processor_mf1_detect_support",
      "hook_symbols": [
        "after_hf_reader_run",
        "before_hf_reader_run"
      ],
      "provider_capability_id": "CU-HF-MFC-ACQUIRE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "c0b9f0ee722edf1adf18cb8c9975b5fe8e81bd57566c7295fbe899224d1a38b5"
    },
    {
      "command_id": 2002,
      "declaration_symbol": "DATA_CMD_MF1_DETECT_PRNG",
      "runtime_handler_symbol": "cmd_processor_mf1_detect_prng",
      "hook_symbols": [
        "after_hf_reader_run",
        "before_hf_reader_run"
      ],
      "provider_capability_id": "CU-HF-MFC-RECOVERY",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "f893081795b1829dcfdfba7539d87be4d2d168508def93dd74227fbd56310e4c"
    },
    {
      "command_id": 2003,
      "declaration_symbol": "DATA_CMD_MF1_STATIC_NESTED_ACQUIRE",
      "runtime_handler_symbol": "cmd_processor_mf1_static_nested_acquire",
      "hook_symbols": [
        "after_hf_reader_run",
        "before_hf_reader_run"
      ],
      "provider_capability_id": "CU-HF-MFC-RECOVERY",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "a651e31ee2fa40e7ad582943a5b1a860c169202429302f2d2a5730dcada4c197"
    },
    {
      "command_id": 2004,
      "declaration_symbol": "DATA_CMD_MF1_DARKSIDE_ACQUIRE",
      "runtime_handler_symbol": "cmd_processor_mf1_darkside_acquire",
      "hook_symbols": [
        "after_hf_reader_run",
        "before_hf_reader_run"
      ],
      "provider_capability_id": "CU-HF-MFC-RECOVERY",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "76bbe66a41ef313734cfe07f3a33c04b45839c9dbc8122bcd2d7ec3cbda4306c"
    },
    {
      "command_id": 2005,
      "declaration_symbol": "DATA_CMD_MF1_DETECT_NT_DIST",
      "runtime_handler_symbol": "cmd_processor_mf1_detect_nt_dist",
      "hook_symbols": [
        "after_hf_reader_run",
        "before_hf_reader_run"
      ],
      "provider_capability_id": "CU-HF-MFC-RECOVERY",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "6ebf94e327b04de0fae1692e4a23f65592c13472e545b33ad6d1b03098878279"
    },
    {
      "command_id": 2006,
      "declaration_symbol": "DATA_CMD_MF1_NESTED_ACQUIRE",
      "runtime_handler_symbol": "cmd_processor_mf1_nested_acquire",
      "hook_symbols": [
        "after_hf_reader_run",
        "before_hf_reader_run"
      ],
      "provider_capability_id": "CU-HF-MFC-RECOVERY",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "3e6c189e4587b76ed4dcad1bba5e9e9c7ae4b610b49e8e32b9613229360390f0"
    },
    {
      "command_id": 2007,
      "declaration_symbol": "DATA_CMD_MF1_AUTH_ONE_KEY_BLOCK",
      "runtime_handler_symbol": "cmd_processor_mf1_auth_one_key_block",
      "hook_symbols": [
        "after_hf_reader_run",
        "before_hf_reader_run"
      ],
      "provider_capability_id": "CU-HF-MFC-ACQUIRE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "fc554a21662682b0b69d37d62063ba1216d693e9c631ce3dba8dbbfa085b19b4"
    },
    {
      "command_id": 2008,
      "declaration_symbol": "DATA_CMD_MF1_READ_ONE_BLOCK",
      "runtime_handler_symbol": "cmd_processor_mf1_read_one_block",
      "hook_symbols": [
        "after_hf_reader_run",
        "before_hf_reader_run"
      ],
      "provider_capability_id": "CU-HF-MFC-ACQUIRE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "c99517baffdac2dc85b7eeb787fe6926d38a6f4cb42ddd3f0bd2d1b16ecd3b9f"
    },
    {
      "command_id": 2009,
      "declaration_symbol": "DATA_CMD_MF1_WRITE_ONE_BLOCK",
      "runtime_handler_symbol": "cmd_processor_mf1_write_one_block",
      "hook_symbols": [
        "after_hf_reader_run",
        "before_hf_reader_run"
      ],
      "provider_capability_id": "CU-HF-MFC-WRITE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "fc23c7cf7d69f9042fe9f38178d019f6f33430f47a86ce20c82400815361e7e1"
    },
    {
      "command_id": 2010,
      "declaration_symbol": "DATA_CMD_HF14A_RAW",
      "runtime_handler_symbol": "cmd_processor_hf14a_raw",
      "hook_symbols": [
        "before_reader_run"
      ],
      "provider_capability_id": "CU-HF-14A-RAW",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "5c0e55bcdbff72f951c6b390fda95b86a36ac5148cffbc0e6312a3ab21cb0be4"
    },
    {
      "command_id": 2011,
      "declaration_symbol": "DATA_CMD_MF1_MANIPULATE_VALUE_BLOCK",
      "runtime_handler_symbol": "cmd_processor_mf1_manipulate_value_block",
      "hook_symbols": [
        "after_hf_reader_run",
        "before_hf_reader_run"
      ],
      "provider_capability_id": "CU-HF-MFC-WRITE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "d56b46aa1064d6071ee4669ed58e33db2d92f083921f36b0f9a8b6b6fbe452f5"
    },
    {
      "command_id": 2012,
      "declaration_symbol": "DATA_CMD_MF1_CHECK_KEYS_OF_SECTORS",
      "runtime_handler_symbol": "cmd_processor_mf1_check_keys_of_sectors",
      "hook_symbols": [
        "after_hf_reader_run",
        "before_hf_reader_run"
      ],
      "provider_capability_id": "CU-HF-MFC-ACQUIRE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "12069ece066309f083e829e58ec688ac90753fb1b663fcb940cbf1924a7f538d"
    },
    {
      "command_id": 2013,
      "declaration_symbol": "DATA_CMD_MF1_HARDNESTED_ACQUIRE",
      "runtime_handler_symbol": "cmd_processor_mf1_hardnested_nonces_acquire",
      "hook_symbols": [
        "after_hf_reader_run",
        "before_hf_reader_run"
      ],
      "provider_capability_id": "CU-HF-MFC-RECOVERY",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "6cc8595fe670e865215487f082f8950ca442f81e068a0d398ce2cde3fc1c013f"
    },
    {
      "command_id": 2014,
      "declaration_symbol": "DATA_CMD_MF1_ENC_NESTED_ACQUIRE",
      "runtime_handler_symbol": "cmd_processor_mf1_enc_nested_acquire",
      "hook_symbols": [
        "after_hf_reader_run",
        "before_hf_reader_run"
      ],
      "provider_capability_id": "CU-HF-MFC-RECOVERY",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "eeaff1157249a5830389d20e240a6cb848c0c2151e7dc1b2f47dbcc55cb9f3ac"
    },
    {
      "command_id": 2015,
      "declaration_symbol": "DATA_CMD_MF1_CHECK_KEYS_ON_BLOCK",
      "runtime_handler_symbol": "cmd_processor_mf1_check_keys_on_block",
      "hook_symbols": [
        "after_hf_reader_run",
        "before_hf_reader_run"
      ],
      "provider_capability_id": "CU-HF-MFC-ACQUIRE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "6ed2c4f7ffed1af89f7af0d1279e10fa8844f4fbbfa7aa50d3faaadcc1f5c4ef"
    },
    {
      "command_id": 2016,
      "declaration_symbol": "DATA_CMD_HF14A_SCAN_KEEP",
      "runtime_handler_symbol": "cmd_processor_hf14a_scan_keep",
      "hook_symbols": [
        "before_hf_reader_run"
      ],
      "provider_capability_id": "CU-HF-ISO14443-4-APDU",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "40bfd34ecc5b4c9afa0acaee2c2b570ce6a7308c6d7442c63d0d76fcea850027"
    },
    {
      "command_id": 2017,
      "declaration_symbol": "DATA_CMD_HF14A_AUTH_TRACE",
      "runtime_handler_symbol": "cmd_processor_hf14a_auth_trace",
      "hook_symbols": [
        "after_hf_reader_run",
        "before_hf_reader_run"
      ],
      "provider_capability_id": "CU-HF-MFC-AUTH-TRACE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "ddc068958b2a568ff66e5192cd5cb202521e2ba0e6e4942c1a3542eb2699d746"
    },
    {
      "command_id": 2020,
      "declaration_symbol": "DATA_CMD_HF14A_SNIFF",
      "runtime_handler_symbol": "cmd_processor_hf14a_sniff",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-14A-ACTIVE-TRACE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "04620677c62c62495088cea97e6052ca0394305648480bd9e62230becbc07c0f"
    },
    {
      "command_id": 2100,
      "declaration_symbol": "DATA_CMD_HF14A_SET_FIELD_ON",
      "runtime_handler_symbol": "cmd_processor_hf14a_set_field_on",
      "hook_symbols": [
        "before_reader_run"
      ],
      "provider_capability_id": "CU-RF-SESSION",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "047e5363f3ea0ebf70d2bc84871f7ed20f91390483c291c1059468903cd8e6e0"
    },
    {
      "command_id": 2101,
      "declaration_symbol": "DATA_CMD_HF14A_SET_FIELD_OFF",
      "runtime_handler_symbol": "cmd_processor_hf14a_set_field_off",
      "hook_symbols": [
        "before_reader_run"
      ],
      "provider_capability_id": "CU-RF-SESSION",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "51a82552301e10fa23110459e84d5fe1e70e56e82bd04e04d731e1980621a118"
    },
    {
      "command_id": 2200,
      "declaration_symbol": "DATA_CMD_HF14A_GET_CONFIG",
      "runtime_handler_symbol": "cmd_processor_hf14a_get_config",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-14A-READER-CONFIG",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "6dd9cc5acf987f23c8cef5456a4344d1ef3c3e99a69b53bc8f0c77e84f181ee9"
    },
    {
      "command_id": 2201,
      "declaration_symbol": "DATA_CMD_HF14A_SET_CONFIG",
      "runtime_handler_symbol": "cmd_processor_hf14a_set_config",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-14A-READER-CONFIG",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "f2f2d5521c399948d5076100c0c4edbb62457eec17dbb19cdc1873b660043b3e"
    },
    {
      "command_id": 3000,
      "declaration_symbol": "DATA_CMD_EM410X_SCAN",
      "runtime_handler_symbol": "cmd_processor_em410x_scan",
      "hook_symbols": [
        "before_reader_run"
      ],
      "provider_capability_id": "CU-LF-DISCOVERY",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "e6afa25860342e4ff3d830d36a96872ed8426f32195ec0860c18f44540d3f9fa"
    },
    {
      "command_id": 3001,
      "declaration_symbol": "DATA_CMD_EM410X_WRITE_TO_T55XX",
      "runtime_handler_symbol": "cmd_processor_em410x_write_to_t55xx",
      "hook_symbols": [
        "before_reader_run"
      ],
      "provider_capability_id": "CU-LF-T55XX-WRITE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "c843c62e9b2d3f5534416870f591e6f843631cb89ec05cf39f0d0d8b089a8495"
    },
    {
      "command_id": 3002,
      "declaration_symbol": "DATA_CMD_HIDPROX_SCAN",
      "runtime_handler_symbol": "cmd_processor_hidprox_scan",
      "hook_symbols": [
        "before_reader_run"
      ],
      "provider_capability_id": "CU-LF-DISCOVERY",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "b77a011fa16256fc528ddac089d26f9ab035778c5f12877a2b5809bf97bb80e9"
    },
    {
      "command_id": 3003,
      "declaration_symbol": "DATA_CMD_HIDPROX_WRITE_TO_T55XX",
      "runtime_handler_symbol": "cmd_processor_hidprox_write_to_t55xx",
      "hook_symbols": [
        "before_reader_run"
      ],
      "provider_capability_id": "CU-LF-T55XX-WRITE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "b5703364a0200e99ceb4883c48f95f8f82c6748a6f516f8d6736f8344b3ef9b8"
    },
    {
      "command_id": 3004,
      "declaration_symbol": "DATA_CMD_VIKING_SCAN",
      "runtime_handler_symbol": "cmd_processor_viking_scan",
      "hook_symbols": [
        "before_reader_run"
      ],
      "provider_capability_id": "CU-LF-DISCOVERY",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "449e110173af512a296cdf4c78672faab0b2285ad53356cc1fbcde71ea86762c"
    },
    {
      "command_id": 3005,
      "declaration_symbol": "DATA_CMD_VIKING_WRITE_TO_T55XX",
      "runtime_handler_symbol": "cmd_processor_viking_write_to_t55xx",
      "hook_symbols": [
        "before_reader_run"
      ],
      "provider_capability_id": "CU-LF-T55XX-WRITE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "12971ed2268a6608e4f86bbc0b556ff977a44379d5ec665d3bc364f4317325bd"
    },
    {
      "command_id": 3006,
      "declaration_symbol": "DATA_CMD_EM410X_ELECTRA_WRITE_TO_T55XX",
      "runtime_handler_symbol": "cmd_processor_em410x_electra_write_to_t55xx",
      "hook_symbols": [
        "before_reader_run"
      ],
      "provider_capability_id": "CU-LF-T55XX-WRITE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "3edbc2058e15dddb2eb243446ca87e3a2ee7aa0c6339e2a3b4fff8d16df78333"
    },
    {
      "command_id": 3007,
      "declaration_symbol": "DATA_CMD_GENERIC_READ",
      "runtime_handler_symbol": null,
      "hook_symbols": [],
      "provider_capability_id": "CU-LF-DECLARED-UNREGISTERED",
      "disposition": "unsupported",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "1daf4c138a654ffe4151a6b55f4850d0d5d010644e0aacd22124bbc84423e5b4"
    },
    {
      "command_id": 3008,
      "declaration_symbol": "DATA_CMD_CORR_GENERIC_READ",
      "runtime_handler_symbol": null,
      "hook_symbols": [],
      "provider_capability_id": "CU-LF-DECLARED-UNREGISTERED",
      "disposition": "unsupported",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "8ff4f3d9ca2d686898b5c9f6ed0da974539f1156875bbcb467b4c00fdf4d7e04"
    },
    {
      "command_id": 3009,
      "declaration_symbol": "DATA_CMD_ADC_GENERIC_READ",
      "runtime_handler_symbol": "cmd_processor_generic_read",
      "hook_symbols": [
        "before_reader_run"
      ],
      "provider_capability_id": "CU-LF-SIGNAL-CAPTURE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "675da71d7de31b14a213ed6e8cd375b08860c937264a0ac1d89ea5cf3e7f5905"
    },
    {
      "command_id": 3010,
      "declaration_symbol": "DATA_CMD_IOPROX_SCAN",
      "runtime_handler_symbol": "cmd_processor_ioprox_scan",
      "hook_symbols": [
        "before_reader_run"
      ],
      "provider_capability_id": "CU-LF-DISCOVERY",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "1c4feaefb4fb09f2ae5b0a30eb2f09e396c37d122d3fa03d44e81b91ae67f596"
    },
    {
      "command_id": 3011,
      "declaration_symbol": "DATA_CMD_IOPROX_WRITE_TO_T55XX",
      "runtime_handler_symbol": "cmd_processor_ioprox_write_to_t55xx",
      "hook_symbols": [
        "before_reader_run"
      ],
      "provider_capability_id": "CU-LF-T55XX-WRITE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "bbbe3fcd631bd936785730a92062f3a8ff32e7f52cb26f1b9a82cbf3d4107b7b"
    },
    {
      "command_id": 3012,
      "declaration_symbol": "DATA_CMD_IOPROX_DECODE_RAW",
      "runtime_handler_symbol": "cmd_processor_ioprox_decode_raw",
      "hook_symbols": [],
      "provider_capability_id": "CU-LF-IOPROX-CODEC",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "0edefff24182a2c7160f8523e0caf81c1c894c53294219a0623e7d6ce2bdea58"
    },
    {
      "command_id": 3013,
      "declaration_symbol": "DATA_CMD_IOPROX_COMPOSE_ID",
      "runtime_handler_symbol": "cmd_processor_ioprox_compose_id",
      "hook_symbols": [],
      "provider_capability_id": "CU-LF-IOPROX-CODEC",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "b73806c259a49751fb6f1fb0e80bc71b9c1f3c0ae5eac287c8b971e7a16686bd"
    },
    {
      "command_id": 3014,
      "declaration_symbol": "DATA_CMD_PAC_SCAN",
      "runtime_handler_symbol": "cmd_processor_pac_scan",
      "hook_symbols": [
        "before_reader_run"
      ],
      "provider_capability_id": "CU-LF-DISCOVERY",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "ac335fa796a411638e422d52e659df8b5d6b52557809594a1c1e41bfcedd19ed"
    },
    {
      "command_id": 3015,
      "declaration_symbol": "DATA_CMD_PAC_WRITE_TO_T55XX",
      "runtime_handler_symbol": "cmd_processor_pac_write_to_t55xx",
      "hook_symbols": [
        "before_reader_run"
      ],
      "provider_capability_id": "CU-LF-T55XX-WRITE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "3c9cc9068ef2f6c9a95d51d4d4b24485ac055e1e62af8a9c23fa1939da41b878"
    },
    {
      "command_id": 3016,
      "declaration_symbol": "DATA_CMD_LF_T55XX_WRITE",
      "runtime_handler_symbol": "cmd_processor_lf_t55xx_write",
      "hook_symbols": [
        "before_reader_run"
      ],
      "provider_capability_id": "CU-LF-T55XX-WRITE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "cbcf7816ad2cf195ca55edabf6d98fc38c3467aebee24ee688142235007d140d"
    },
    {
      "command_id": 3018,
      "declaration_symbol": "DATA_CMD_IDTECK_WRITE_TO_T55XX",
      "runtime_handler_symbol": "cmd_processor_idteck_write_to_t55xx",
      "hook_symbols": [
        "before_reader_run"
      ],
      "provider_capability_id": "CU-LF-T55XX-WRITE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "fffc9fca68943be7e4abe819cd5181de5c988fd2c899d0f5dd913086bb8ce916"
    },
    {
      "command_id": 3019,
      "declaration_symbol": "DATA_CMD_JABLOTRON_SCAN",
      "runtime_handler_symbol": "cmd_processor_jablotron_scan",
      "hook_symbols": [
        "before_reader_run"
      ],
      "provider_capability_id": "CU-LF-DISCOVERY",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "75fa5dd40ca0a629c50b6a8698d8af6652bb57030332b83b618802fb044db04b"
    },
    {
      "command_id": 3020,
      "declaration_symbol": "DATA_CMD_JABLOTRON_WRITE_TO_T55XX",
      "runtime_handler_symbol": "cmd_processor_jablotron_write_to_t55xx",
      "hook_symbols": [
        "before_reader_run"
      ],
      "provider_capability_id": "CU-LF-T55XX-WRITE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "7ef938d9985aff75e6c1a69432e0126a4bc3b91c1d76a101314f8811430ece83"
    },
    {
      "command_id": 3030,
      "declaration_symbol": "DATA_CMD_EM4X05_SCAN",
      "runtime_handler_symbol": "cmd_processor_em4x05_scan",
      "hook_symbols": [
        "before_reader_run"
      ],
      "provider_capability_id": "CU-LF-DISCOVERY",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "20dc9e71363f5c341c841b7eaf3e2fb730e22e12d49f2053b05db3e13e58db6e"
    },
    {
      "command_id": 3031,
      "declaration_symbol": "DATA_CMD_LF_SNIFF",
      "runtime_handler_symbol": "cmd_processor_lf_sniff",
      "hook_symbols": [
        "before_reader_run"
      ],
      "provider_capability_id": "CU-LF-SIGNAL-CAPTURE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "8c2ba30d81960106ca7c261ef13f4f0251642cf25a74d0148938507cb2b89366"
    },
    {
      "command_id": 3032,
      "declaration_symbol": "DATA_CMD_EM4X05_READSNIFF",
      "runtime_handler_symbol": null,
      "hook_symbols": [],
      "provider_capability_id": "CU-LF-DECLARED-UNREGISTERED",
      "disposition": "unsupported",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "12952c04e737038054a73aa7f698ae1b4e3745a9b76d9edfe036c4d2b134af70"
    },
    {
      "command_id": 4000,
      "declaration_symbol": "DATA_CMD_MF1_WRITE_EMU_BLOCK_DATA",
      "runtime_handler_symbol": "cmd_processor_mf1_write_emu_block_data",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFC-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "41c3a41d6d8f0d185d7c4c874e6ed291bb2c211c7ee194b41d49fedfbe4d19bc"
    },
    {
      "command_id": 4001,
      "declaration_symbol": "DATA_CMD_HF14A_SET_ANTI_COLL_DATA",
      "runtime_handler_symbol": "cmd_processor_hf14a_set_anti_coll_data",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-14A-EMULATOR-CONFIG",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "727ab2092e8e9c37131f723ad96d2623ff0c24170a0e9e881a5f9fbde732eeda"
    },
    {
      "command_id": 4004,
      "declaration_symbol": "DATA_CMD_MF1_SET_DETECTION_ENABLE",
      "runtime_handler_symbol": "cmd_processor_mf1_set_detection_enable",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFC-EMULATOR-TRACE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "1011b8998951306bde7dba7e5f199cb7ded747fd7d4175657d629cafd7120e1e"
    },
    {
      "command_id": 4005,
      "declaration_symbol": "DATA_CMD_MF1_GET_DETECTION_COUNT",
      "runtime_handler_symbol": "cmd_processor_mf1_get_detection_count",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFC-EMULATOR-TRACE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "990adb4ac5b4f380e55ada0f8619b5ef7c62d85180c57447c9b79cb912c7b78e"
    },
    {
      "command_id": 4006,
      "declaration_symbol": "DATA_CMD_MF1_GET_DETECTION_LOG",
      "runtime_handler_symbol": "cmd_processor_mf1_get_detection_log",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFC-EMULATOR-TRACE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "173a31012dff14cbc416c6533bf6467b80e9dd7f35a102d10dfb5e79860f75de"
    },
    {
      "command_id": 4007,
      "declaration_symbol": "DATA_CMD_MF1_GET_DETECTION_ENABLE",
      "runtime_handler_symbol": "cmd_processor_mf1_get_detection_enable",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFC-EMULATOR-TRACE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "0b88b68cf29529fa5d58d835f78fa9b43f28b072f79deba330420ed4d8756a32"
    },
    {
      "command_id": 4008,
      "declaration_symbol": "DATA_CMD_MF1_READ_EMU_BLOCK_DATA",
      "runtime_handler_symbol": "cmd_processor_mf1_read_emu_block_data",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFC-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "605e270a2d7ba80bd451058c2fad4678c1a5513221afc92f2761251ddd160d78"
    },
    {
      "command_id": 4009,
      "declaration_symbol": "DATA_CMD_MF1_GET_EMULATOR_CONFIG",
      "runtime_handler_symbol": "cmd_processor_mf1_get_emulator_config",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFC-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "bb91b853b3a2f46cc2023dc19e2268a8c1b8af8348b864c26f908399456e85ef"
    },
    {
      "command_id": 4010,
      "declaration_symbol": "DATA_CMD_MF1_GET_GEN1A_MODE",
      "runtime_handler_symbol": "cmd_processor_mf1_get_gen1a_mode",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFC-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "586cb86f6fe1ce44747735df7a972d7f02eeef89151a8025f12fb49565a80eb3"
    },
    {
      "command_id": 4011,
      "declaration_symbol": "DATA_CMD_MF1_SET_GEN1A_MODE",
      "runtime_handler_symbol": "cmd_processor_mf1_set_gen1a_mode",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFC-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "d7b7f4d8eb523e5722e18240873f4313f7f01f205e5737bae0b64e902d7768e6"
    },
    {
      "command_id": 4012,
      "declaration_symbol": "DATA_CMD_MF1_GET_GEN2_MODE",
      "runtime_handler_symbol": "cmd_processor_mf1_get_gen2_mode",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFC-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "ba16bc7fd012ec165ce65911d3b546f129b59f1f1d3bee8c3652c09e00a40662"
    },
    {
      "command_id": 4013,
      "declaration_symbol": "DATA_CMD_MF1_SET_GEN2_MODE",
      "runtime_handler_symbol": "cmd_processor_mf1_set_gen2_mode",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFC-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "6260959b6ea8e52e3af015005a9766593662b1212efaff94e8c6185acd2569bc"
    },
    {
      "command_id": 4014,
      "declaration_symbol": "DATA_CMD_MF1_GET_BLOCK_ANTI_COLL_MODE",
      "runtime_handler_symbol": "cmd_processor_mf1_get_block_anti_coll_mode",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFC-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "3f7ba78f36c4e7c9c202c5e005165b314cb2d538ba52c5c4a2d6a9f1eccd01af"
    },
    {
      "command_id": 4015,
      "declaration_symbol": "DATA_CMD_MF1_SET_BLOCK_ANTI_COLL_MODE",
      "runtime_handler_symbol": "cmd_processor_mf1_set_block_anti_coll_mode",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFC-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "85e478ac276c323adbbe4fb30788917d736b2cb646b7a20aacf368dac610cf81"
    },
    {
      "command_id": 4016,
      "declaration_symbol": "DATA_CMD_MF1_GET_WRITE_MODE",
      "runtime_handler_symbol": "cmd_processor_mf1_get_write_mode",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFC-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "99abfc873d40ae9fd0756335d075bbaac852d814205df302e1bf4fd8b96e46e2"
    },
    {
      "command_id": 4017,
      "declaration_symbol": "DATA_CMD_MF1_SET_WRITE_MODE",
      "runtime_handler_symbol": "cmd_processor_mf1_set_write_mode",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFC-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "6cb6bb16d02d44a49fb16b190cc80f89a1377d737c0f9ad70a80620681835953"
    },
    {
      "command_id": 4018,
      "declaration_symbol": "DATA_CMD_HF14A_GET_ANTI_COLL_DATA",
      "runtime_handler_symbol": "cmd_processor_hf14a_get_anti_coll_data",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-14A-EMULATOR-CONFIG",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "a001bb1138cb9b774e50dc3b789d91d5533d268eaf515a22f2530c3f4ece2c3b"
    },
    {
      "command_id": 4019,
      "declaration_symbol": "DATA_CMD_MF0_NTAG_GET_UID_MAGIC_MODE",
      "runtime_handler_symbol": "cmd_processor_mf0_ntag_get_uid_mode",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFU-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "778166472430a517a8e102af72d27f85bf9e2d6f24fc5f4a5bfe86a43be58251"
    },
    {
      "command_id": 4020,
      "declaration_symbol": "DATA_CMD_MF0_NTAG_SET_UID_MAGIC_MODE",
      "runtime_handler_symbol": "cmd_processor_mf0_ntag_set_uid_mode",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFU-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "6edbe16a2bedc70ec2eeae88a3317e657dcecd720a048cbf82cda0601ab07b98"
    },
    {
      "command_id": 4021,
      "declaration_symbol": "DATA_CMD_MF0_NTAG_READ_EMU_PAGE_DATA",
      "runtime_handler_symbol": "cmd_processor_mf0_ntag_read_emu_page_data",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFU-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "9efd5bc17672a5aa9f7e0e3e51d014d9906a1c9593c19afb579967f9ea3b63bc"
    },
    {
      "command_id": 4022,
      "declaration_symbol": "DATA_CMD_MF0_NTAG_WRITE_EMU_PAGE_DATA",
      "runtime_handler_symbol": "cmd_processor_mf0_ntag_write_emu_page_data",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFU-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "69f33de7e48affc2d9c74ea647d903ac2f04203e63340b371606be2b4f9c2ed4"
    },
    {
      "command_id": 4023,
      "declaration_symbol": "DATA_CMD_MF0_NTAG_GET_VERSION_DATA",
      "runtime_handler_symbol": "cmd_processor_mf0_ntag_get_version_data",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFU-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "84c7457aae6266727fef58fd7a36d47f4b6562befcd96cfae279b12e72777e47"
    },
    {
      "command_id": 4024,
      "declaration_symbol": "DATA_CMD_MF0_NTAG_SET_VERSION_DATA",
      "runtime_handler_symbol": "cmd_processor_mf0_ntag_set_version_data",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFU-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "e687259431d763a9d3086497198ab3780da028ba726089a85ae5673ca00d5b94"
    },
    {
      "command_id": 4025,
      "declaration_symbol": "DATA_CMD_MF0_NTAG_GET_SIGNATURE_DATA",
      "runtime_handler_symbol": "cmd_processor_mf0_ntag_get_signature_data",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFU-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "ea3a624465102e10f77a0b9f9125c0864a043db918675d924e4596c7502b98cb"
    },
    {
      "command_id": 4026,
      "declaration_symbol": "DATA_CMD_MF0_NTAG_SET_SIGNATURE_DATA",
      "runtime_handler_symbol": "cmd_processor_mf0_ntag_set_signature_data",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFU-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "b3d22789e9c64565dbd48b307d05985276da855a9be0737d7f7b400bfd96bda5"
    },
    {
      "command_id": 4027,
      "declaration_symbol": "DATA_CMD_MF0_NTAG_GET_COUNTER_DATA",
      "runtime_handler_symbol": "cmd_processor_mf0_ntag_get_counter_data",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFU-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "9d8e68300c9c6405faa9d6a20633c5ef5a987499fa154f51b9afef6ffe717c14"
    },
    {
      "command_id": 4028,
      "declaration_symbol": "DATA_CMD_MF0_NTAG_SET_COUNTER_DATA",
      "runtime_handler_symbol": "cmd_processor_mf0_ntag_set_counter_data",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFU-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "7e199b313cd22a26081d0d78d6dc949342f4f9f05429f95b313520b2f4e92943"
    },
    {
      "command_id": 4029,
      "declaration_symbol": "DATA_CMD_MF0_NTAG_RESET_AUTH_CNT",
      "runtime_handler_symbol": "cmd_processor_mf0_ntag_reset_auth_cnt",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFU-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "68b4483680ab377eee6955b698929acf2e037591b03a40f62e99410b5eb118d4"
    },
    {
      "command_id": 4030,
      "declaration_symbol": "DATA_CMD_MF0_NTAG_GET_PAGE_COUNT",
      "runtime_handler_symbol": "cmd_processor_mf0_ntag_get_emu_page_count",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFU-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "8426b9dea59c0a74a514c045139ac5d8c2c12c502b29bfae23a843dcf3025f20"
    },
    {
      "command_id": 4031,
      "declaration_symbol": "DATA_CMD_MF0_NTAG_GET_WRITE_MODE",
      "runtime_handler_symbol": "cmd_processor_mf0_ntag_get_write_mode",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFU-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "5fdac27ec613057983492efdc42140714e1c4d8856733a7e0689a55419b27ee4"
    },
    {
      "command_id": 4032,
      "declaration_symbol": "DATA_CMD_MF0_NTAG_SET_WRITE_MODE",
      "runtime_handler_symbol": "cmd_processor_mf0_ntag_set_write_mode",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFU-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "9521d73f031636ee87eaf96fab60be8ffde82917ae82be6092392859909cb801"
    },
    {
      "command_id": 4033,
      "declaration_symbol": "DATA_CMD_MF0_NTAG_SET_DETECTION_ENABLE",
      "runtime_handler_symbol": "cmd_processor_mf0_ntag_set_detection_enable",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFU-EMULATOR-TRACE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "a4bf7060291bd3c3a376df0b6ef097749b54e17287b9e56d8405daa5d250e586"
    },
    {
      "command_id": 4034,
      "declaration_symbol": "DATA_CMD_MF0_NTAG_GET_DETECTION_COUNT",
      "runtime_handler_symbol": "cmd_processor_mf0_ntag_get_detection_count",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFU-EMULATOR-TRACE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "76b731952755a7f1984d3ba8811931f61719cf261449ace637e75188b6f646d8"
    },
    {
      "command_id": 4035,
      "declaration_symbol": "DATA_CMD_MF0_NTAG_GET_DETECTION_LOG",
      "runtime_handler_symbol": "cmd_processor_mf0_ntag_get_detection_log",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFU-EMULATOR-TRACE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "f7384e57e9567d53e8e9dc63ed535ec06fcf75b32db75aa2fc60c586aa2b5bd5"
    },
    {
      "command_id": 4036,
      "declaration_symbol": "DATA_CMD_MF0_NTAG_GET_DETECTION_ENABLE",
      "runtime_handler_symbol": "cmd_processor_mf0_ntag_get_detection_enable",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFU-EMULATOR-TRACE",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "1d04d7dd345c32358de8dee71a77d7701652d1ecb541d4ccb13800f070790c1c"
    },
    {
      "command_id": 4037,
      "declaration_symbol": "DATA_CMD_MF0_NTAG_GET_EMULATOR_CONFIG",
      "runtime_handler_symbol": "cmd_processor_mf0_get_emulator_config",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFU-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "e92e6950a27d5ba2c567c3e0a9226a716ae09cbd7d44fc9faa7c5cc770dae901"
    },
    {
      "command_id": 4038,
      "declaration_symbol": "DATA_CMD_MF1_SET_FIELD_OFF_DO_RESET",
      "runtime_handler_symbol": "cmd_processor_mf1_set_field_off_do_reset",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFC-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "4f3ace45d4aa5849242cb6d1c50c03ccbeae09e914bdbc28782c9aa022830d8f"
    },
    {
      "command_id": 4039,
      "declaration_symbol": "DATA_CMD_MF1_GET_FIELD_OFF_DO_RESET",
      "runtime_handler_symbol": "cmd_processor_mf1_get_field_off_do_reset",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFC-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "86f6fea60f75a700e22d9fa816b2eba9f43bdc29bd943661f22fbf8d5bc05699"
    },
    {
      "command_id": 4040,
      "declaration_symbol": "DATA_CMD_MF1_GET_PRNG_TYPE",
      "runtime_handler_symbol": "cmd_processor_mf1_get_prng_type",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFC-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "ae3f965ff7851fdbab1763dd2360d4bbc13631418d6a309e929be38e4138d7fe"
    },
    {
      "command_id": 4041,
      "declaration_symbol": "DATA_CMD_MF1_SET_PRNG_TYPE",
      "runtime_handler_symbol": "cmd_processor_mf1_set_prng_type",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-MFC-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "23514c5c4012aeecfe17c981721e8b87a0cf9b5ebc35e6cc829e0dba9d8409e4"
    },
    {
      "command_id": 5000,
      "declaration_symbol": "DATA_CMD_EM410X_SET_EMU_ID",
      "runtime_handler_symbol": "cmd_processor_em410x_set_emu_id",
      "hook_symbols": [],
      "provider_capability_id": "CU-LF-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "e4f0eeb470fee3320a644664931c3710c9633013fad7c565743014f5995a5266"
    },
    {
      "command_id": 5001,
      "declaration_symbol": "DATA_CMD_EM410X_GET_EMU_ID",
      "runtime_handler_symbol": "cmd_processor_em410x_get_emu_id",
      "hook_symbols": [],
      "provider_capability_id": "CU-LF-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "fe9601781e28d55ceac3041914187338ce6be1c43b68e72abf648e775d142fa6"
    },
    {
      "command_id": 5002,
      "declaration_symbol": "DATA_CMD_HIDPROX_SET_EMU_ID",
      "runtime_handler_symbol": "cmd_processor_hidprox_set_emu_id",
      "hook_symbols": [],
      "provider_capability_id": "CU-LF-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "e7e8e16efca3529f8fe40eebea9eebbc7df9b6214d93e215dd5553b1f59540f0"
    },
    {
      "command_id": 5003,
      "declaration_symbol": "DATA_CMD_HIDPROX_GET_EMU_ID",
      "runtime_handler_symbol": "cmd_processor_hidprox_get_emu_id",
      "hook_symbols": [],
      "provider_capability_id": "CU-LF-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "a1ec625fe900b40d4876cc4663d2216ea5deb6bf0680759dbb9f82e3880fa4f7"
    },
    {
      "command_id": 5004,
      "declaration_symbol": "DATA_CMD_VIKING_SET_EMU_ID",
      "runtime_handler_symbol": "cmd_processor_viking_set_emu_id",
      "hook_symbols": [],
      "provider_capability_id": "CU-LF-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "aab4d9f8f856d17f39ca0262b0be2fed43764127c57bf2cf382fba3aa943971a"
    },
    {
      "command_id": 5005,
      "declaration_symbol": "DATA_CMD_VIKING_GET_EMU_ID",
      "runtime_handler_symbol": "cmd_processor_viking_get_emu_id",
      "hook_symbols": [],
      "provider_capability_id": "CU-LF-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "e142799d8a18da4aad876142af6b801bfd8e894876e483d39f65ddc6aa24dc6e"
    },
    {
      "command_id": 5006,
      "declaration_symbol": "DATA_CMD_PAC_SET_EMU_ID",
      "runtime_handler_symbol": "cmd_processor_pac_set_emu_id",
      "hook_symbols": [],
      "provider_capability_id": "CU-LF-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "0b8a2a8b321f2490d1cc22a08c5511d828246f362b55890937047f2b9a4d1087"
    },
    {
      "command_id": 5007,
      "declaration_symbol": "DATA_CMD_PAC_GET_EMU_ID",
      "runtime_handler_symbol": "cmd_processor_pac_get_emu_id",
      "hook_symbols": [],
      "provider_capability_id": "CU-LF-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "14f17a9d56a05fdb703c38608335d95101f4fb76e8de688ef353df4f14772108"
    },
    {
      "command_id": 5008,
      "declaration_symbol": "DATA_CMD_IOPROX_SET_EMU_ID",
      "runtime_handler_symbol": "cmd_processor_ioprox_set_emu_id",
      "hook_symbols": [],
      "provider_capability_id": "CU-LF-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "d66a8278e5c7e71aaa3f9c0e0cc401fad81c9ed5ad527d8bbeab2af31ccb2e2e"
    },
    {
      "command_id": 5009,
      "declaration_symbol": "DATA_CMD_IOPROX_GET_EMU_ID",
      "runtime_handler_symbol": "cmd_processor_ioprox_get_emu_id",
      "hook_symbols": [],
      "provider_capability_id": "CU-LF-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "a1c73f5390e4cc85f0f6f2e18db8a79fb4c9671266a595c1e296c7a93a32fe01"
    },
    {
      "command_id": 5010,
      "declaration_symbol": "DATA_CMD_JABLOTRON_SET_EMU_ID",
      "runtime_handler_symbol": "cmd_processor_jablotron_set_emu_id",
      "hook_symbols": [],
      "provider_capability_id": "CU-LF-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "36b66b0fcc315a6478d8a01b5e3ab36cbcd31adeb224f07a1554bf22fbc0cbba"
    },
    {
      "command_id": 5011,
      "declaration_symbol": "DATA_CMD_JABLOTRON_GET_EMU_ID",
      "runtime_handler_symbol": "cmd_processor_jablotron_get_emu_id",
      "hook_symbols": [],
      "provider_capability_id": "CU-LF-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "fafc151ef9a80e9fe64c1b6a2471061795c695d325c78f4c60e664afe6902780"
    },
    {
      "command_id": 5012,
      "declaration_symbol": "DATA_CMD_IDTECK_SET_EMU_ID",
      "runtime_handler_symbol": "cmd_processor_idteck_set_emu_id",
      "hook_symbols": [],
      "provider_capability_id": "CU-LF-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "fc6607df0bc8baeb523023acdbf4da8ebd5f67daafb91b9f95de5d054284f0f4"
    },
    {
      "command_id": 5013,
      "declaration_symbol": "DATA_CMD_IDTECK_GET_EMU_ID",
      "runtime_handler_symbol": "cmd_processor_idteck_get_emu_id",
      "hook_symbols": [],
      "provider_capability_id": "CU-LF-EMULATION",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "664076dc58b527f721dcfbcedd7cbe13883ab8826cdeaf258bcc60db15188613"
    },
    {
      "command_id": 6000,
      "declaration_symbol": "DATA_CMD_HF14A_4_APDU_RECV",
      "runtime_handler_symbol": "cmd_processor_hf14a_4_apdu_recv",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-ISO14443-4-RESPOND-PRIMITIVE",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "21dd780174bedb05cf7f6cf3f759f9e996a9dd9f45dc9e68435e98232a161f70"
    },
    {
      "command_id": 6001,
      "declaration_symbol": "DATA_CMD_HF14A_4_APDU_SEND",
      "runtime_handler_symbol": "cmd_processor_hf14a_4_apdu_send",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-ISO14443-4-RESPOND-PRIMITIVE",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "c15128c6a9e239b27e111286bf3164fb1aed5e883a712b0c5a2e66e555151d27"
    },
    {
      "command_id": 6002,
      "declaration_symbol": "DATA_CMD_HF14A_4_SET_ANTI_COLL",
      "runtime_handler_symbol": "cmd_processor_hf14a_4_set_anti_coll",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-ISO14443-4-RESPONDER",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "9678952b6cd26acef5bffe26a0afe03332795d4ce7cde1186187c99cc5ca9700"
    },
    {
      "command_id": 6003,
      "declaration_symbol": "DATA_CMD_HF14A_4_STATIC_RESP",
      "runtime_handler_symbol": "cmd_processor_hf14a_4_static_resp",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-ISO14443-4-RESPONDER",
      "disposition": "planned",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "76ef76f6d0e98f66c142b86291275179560d364ce2cb657bd43ab9af3e5fa24e"
    },
    {
      "command_id": 6004,
      "declaration_symbol": "DATA_CMD_HF14A_4_READER_APDU",
      "runtime_handler_symbol": "cmd_processor_hf14a_4_reader_apdu",
      "hook_symbols": [
        "before_hf_reader_run"
      ],
      "provider_capability_id": "CU-HF-ISO14443-4-APDU",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "68d7b3b6f67721835c9b1b97630182507d6586ac889dd836b27103abd5e93fa4"
    },
    {
      "command_id": 6005,
      "declaration_symbol": "DATA_CMD_HF14A_4_EMV_SCAN",
      "runtime_handler_symbol": "cmd_processor_hf14a_4_emv_scan",
      "hook_symbols": [
        "before_hf_reader_run"
      ],
      "provider_capability_id": "CU-HF-EMV-PROFILE",
      "disposition": "optional",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "f51b92fee93cdcd0191446b1631fb863316fd0f3d8775af1d5922f0503db4118"
    },
    {
      "command_id": 6010,
      "declaration_symbol": null,
      "runtime_handler_symbol": "cmd_processor_hf14a_4_debug_counters",
      "hook_symbols": [],
      "provider_capability_id": "CU-HF-ISO14443-4-DIAGNOSTICS",
      "disposition": "provider_internal",
      "source_profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
      "source_profile_digest": "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
      "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
      "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
      "entry_digest": "390a736b167abf04567e6fda6b23e80d4a6d8660681ac2be764b78dedb84b9ab"
    }
  ],
  "command_source_registry_sha256": "464bcd9c4ef1045a48d052832b8ad2e67aa240c4375b6ce51298b29abeb617c5",
  "codec_profile": {
    "profile_id": "chameleon_ultra_v2_2_0_source_pinned_v1",
    "assurance": "code_reviewed_source_pinned",
    "release_tag": "v2.2.0",
    "tag_commit": "f349dbeeaa315776b272ae8fb851cc4042d55f07",
    "declaration_source_sha256": "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
    "registry_source_sha256": "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
    "command_data_limits_digest": "18ca8994c06d60978c452fcac61645342a61ca486585ab8ef9ffff6757327eba",
    "command_ids": [
      1000,
      1001,
      1002,
      1003,
      1004,
      1005,
      1006,
      1007,
      1008,
      1009,
      1010,
      1011,
      1012,
      1013,
      1014,
      1015,
      1016,
      1017,
      1018,
      1019,
      1020,
      1021,
      1023,
      1024,
      1025,
      1026,
      1027,
      1028,
      1029,
      1030,
      1031,
      1032,
      1033,
      1034,
      1035,
      1036,
      1037
    ]
  }
}
);

function canonicalOperationRegistry(registry) {
  return Object.entries(registry).map(([operationId, contract]) => [operationId, {
    exposure: contract.exposure,
    minimum_assurance_profile_id: contract.minimum_assurance_profile_id,
  }]).sort(([left], [right]) => left.localeCompare(right));
}

function canonicalAssuranceProfiles(registry) {
  return Object.entries(registry).map(([profileId, profile]) => [profileId, {
    identity_enrollment: profile.identity_enrollment,
    firmware_provenance: profile.firmware_provenance,
    command_surface_conformance: profile.command_surface_conformance,
    transport_trust: profile.transport_trust,
  }]).sort(([left], [right]) => left.localeCompare(right));
}

function canonicalAssuranceSatisfaction(registry) {
  return Object.entries(registry).map(([axis, actualClaims]) => [axis,
    Object.entries(actualClaims)
      .map(([actual, minima]) => [actual, sorted(minima)])
      .sort(([left], [right]) => left.localeCompare(right)),
  ]).sort(([left], [right]) => left.localeCompare(right));
}

function canonicalFormula(formula) {
  return {
    all_of: sorted(formula.all_of),
    any_of: formula.any_of.map((group) => sorted(group))
      .sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right))),
  };
}

function canonicalCapabilityDependencies(registry) {
  return Object.entries(registry).map(([capabilityId, dependency]) => [capabilityId, {
    ...canonicalFormula(dependency),
    variants: Object.entries(dependency.variants).map(([variantId, variant]) => [variantId, {
      parameter_selector_id: variant.parameter_selector_id,
      ...canonicalFormula(variant),
      normalized_operations: sorted(variant.normalized_operations),
      technique_bindings: sorted(variant.technique_bindings),
      effect_profile_refs: sorted(variant.effect_profile_refs),
    }]).sort(([left], [right]) => left.localeCompare(right)),
  }]).sort(([left], [right]) => left.localeCompare(right));
}

function canonicalDependencyProofProviders(registry) {
  return Object.entries(registry).map(([ref, provider]) => [ref, {
    provider_kind: provider.provider_kind,
    owner_principal: provider.owner_principal,
    artifact_digest_binding: provider.artifact_digest_binding,
    signed_verdict_type: provider.signed_verdict_type,
    trust_epoch_binding: provider.trust_epoch_binding,
    freshness_policy: provider.freshness_policy,
    revocation_policy: provider.revocation_policy,
  }]).sort(([left], [right]) => left.localeCompare(right));
}

function canonicalEffectProfiles(profiles) {
  return Object.entries(profiles).map(([profileId, profile]) => [profileId, {
    subject_kind: profile.subject_kind,
    action: profile.action,
    channel: profile.channel,
    persistence: profile.persistence,
    required_bounds: sorted(profile.required_bounds),
  }]).sort(([left], [right]) => left.localeCompare(right));
}

function canonicalManualActions(registry) {
  return Object.entries(registry).map(([capabilityId, action]) => [capabilityId, {
    source_url: action.source_url,
    source_sha256: action.source_sha256,
    source_symbol: action.source_symbol,
    source_case: action.source_case,
    procedure_id: action.procedure_id,
    effect_profile_refs: sorted(action.effect_profile_refs),
    required_receipts: sorted(action.required_receipts),
    rf_off_deadline_required: action.rf_off_deadline_required,
  }]).sort(([left], [right]) => left.localeCompare(right));
}

function canonicalCommandSourceEntryBasis(entry) {
  return {
    command_id: entry.command_id,
    declaration_symbol: entry.declaration_symbol,
    runtime_handler_symbol: entry.runtime_handler_symbol,
    hook_symbols: sorted(entry.hook_symbols),
    provider_capability_id: entry.provider_capability_id,
    disposition: entry.disposition,
    source_profile_id: entry.source_profile_id,
    source_profile_digest: entry.source_profile_digest,
    declaration_source_sha256: entry.declaration_source_sha256,
    registry_source_sha256: entry.registry_source_sha256,
  };
}

function canonicalCommandSourceRegistry(registry) {
  return registry.map((entry) => ({
    ...canonicalCommandSourceEntryBasis(entry),
    entry_digest: entry.entry_digest,
  })).sort((left, right) => left.command_id - right.command_id);
}

function canonicalCoverageRows(rows) {
  return rows.map((row) => ({
    provider_capability_id: row.provider_capability_id,
    provider: row.provider,
    protocol_family: row.protocol_family,
    device_surface: row.device_surface,
    upstream_command_ids: [...row.upstream_command_ids].sort((left, right) => left - right),
    normalized_operations: sorted(row.normalized_operations),
    technique_bindings: sorted(row.technique_bindings),
    effect_profile_refs: sorted(row.effect_profile_refs),
    data_class: row.data_class,
    node_refs: sorted(row.node_refs),
    disposition: row.disposition,
    reason: row.reason,
  })).sort((left, right) => left.provider_capability_id.localeCompare(right.provider_capability_id));
}

function canonicalCoverageSemantics(data) {
  const source = data.upstream_command_registry;
  return {
    version: data.version,
    provider: data.provider,
    provider_baseline: data.provider_baseline,
    coverage_contract: data.coverage_contract,
    runtime_rule: data.runtime_rule,
    upstream_source: {
      version: source.version,
      declaration_source: source.declaration_source,
      declaration_source_sha256: source.declaration_source_sha256,
      registry_source: source.registry_source,
      registry_source_sha256: source.registry_source_sha256,
      declared_command_ids: [...source.declared_command_ids].sort((left, right) => left - right),
      declared_unregistered_ids: [...source.declared_unregistered_ids]
        .sort((left, right) => left - right),
      registry_private_ids: [...source.registry_private_ids].sort((left, right) => left - right),
      expected_ultra_capabilities_rule: source.expected_ultra_capabilities_rule,
    },
    command_source_registry: canonicalCommandSourceRegistry(data.command_source_registry),
    normalized_operation_registry: canonicalOperationRegistry(data.normalized_operation_registry),
    assurance_profile_registry: canonicalAssuranceProfiles(data.assurance_profile_registry),
    assurance_satisfaction_registry: canonicalAssuranceSatisfaction(
      data.assurance_satisfaction_registry,
    ),
    capability_dependency_registry: canonicalCapabilityDependencies(
      data.capability_dependency_registry,
    ),
    dependency_proof_provider_registry: canonicalDependencyProofProviders(
      data.dependency_proof_provider_registry,
    ),
    technique_registry: sorted(data.technique_registry),
    effect_profiles: canonicalEffectProfiles(data.effect_profiles),
    manual_action_registry: canonicalManualActions(data.manual_action_registry),
    coverage: canonicalCoverageRows(data.coverage),
  };
}

const OPERATION_BY_ID = new Map(Object.entries(REVIEWED_DATA.normalized_operation_registry));
const CAPABILITY_ROW_BY_ID = new Map(
  REVIEWED_DATA.coverage.map((row) => [row.provider_capability_id, row]),
);
const CAPABILITY_DEPENDENCY_BY_ID = new Map(
  Object.entries(REVIEWED_DATA.capability_dependency_registry),
);
const COMMAND_OWNER_BY_ID = new Map();
const COMMAND_SOURCE_BY_ID = new Map(
  REVIEWED_DATA.command_source_registry.map((entry) => [entry.command_id, entry]),
);
const VARIANT_BY_KEY = new Map();
const PROOF_CONTRACT_BY_REF = new Map();
const COMPILED_COMMAND_IDS = new Set(REVIEWED_DATA.codec_profile.command_ids);

for (const row of REVIEWED_DATA.coverage) {
  for (const commandId of row.upstream_command_ids) {
    if (COMMAND_OWNER_BY_ID.has(commandId)) {
      throw new Error(`reviewed Chameleon command ${commandId} has multiple semantic owners`);
    }
    COMMAND_OWNER_BY_ID.set(commandId, row);
  }
}

for (const [ref, provider] of Object.entries(REVIEWED_DATA.dependency_proof_provider_registry)) {
  PROOF_CONTRACT_BY_REF.set(ref, deepFreeze({
    dependency_ref: ref,
    contract_digest: hashJson(provider),
    provider_kind: provider.provider_kind,
    owner_principal: provider.owner_principal,
    artifact_digest_binding: provider.artifact_digest_binding,
    signed_verdict_type: provider.signed_verdict_type,
    trust_epoch_binding: provider.trust_epoch_binding,
    freshness_policy: provider.freshness_policy,
    revocation_policy: provider.revocation_policy,
  }));
}
for (const [capabilityId, action] of Object.entries(REVIEWED_DATA.manual_action_registry)) {
  PROOF_CONTRACT_BY_REF.set(`manual_procedure:${action.procedure_id}`, deepFreeze({
    dependency_ref: `manual_procedure:${action.procedure_id}`,
    contract_digest: hashJson({ capability_id: capabilityId, ...action }),
    provider_kind: "manual_procedure",
    owner_principal: "enrolled_operator",
    artifact_digest_binding: "procedure_and_receipt_digest",
    signed_verdict_type: "bob-proof:manual-procedure:v1",
    trust_epoch_binding: "session_authority_epoch",
    freshness_policy: "attempt_and_operator_receipt",
    revocation_policy: "deny_on_operator_session_or_receipt_drift",
  }));
}

for (const [capabilityId, dependency] of CAPABILITY_DEPENDENCY_BY_ID) {
  for (const [variantId, variant] of Object.entries(dependency.variants)) {
    const key = `${capabilityId}/${variantId}`;
    const row = CAPABILITY_ROW_BY_ID.get(capabilityId);
    const basis = {
      version: MANIFEST_VERSION,
      provider_id: PROVIDER_ID,
      capability_id: capabilityId,
      variant_id: variantId,
      disposition: row.disposition,
      parameter_selector_id: variant.parameter_selector_id,
      all_of: sorted([...dependency.all_of, ...variant.all_of]),
      any_of: [...dependency.any_of, ...variant.any_of].map((group) => sorted(group)),
      normalized_operations: sorted(variant.normalized_operations),
      technique_bindings: sorted(variant.technique_bindings),
      effect_profile_refs: sorted(variant.effect_profile_refs),
    };
    VARIANT_BY_KEY.set(key, deepFreeze({
      ...basis,
      availability_variant_digest: hashJson(basis),
    }));
  }
}

const CHAMELEON_SEMANTIC_DIGESTS = deepFreeze({
  declaration_source_sha256: REVIEWED_DATA.upstream_command_registry.declaration_source_sha256,
  registry_source_sha256: REVIEWED_DATA.upstream_command_registry.registry_source_sha256,
  declared_command_ids_sha256: REVIEWED_DATA.declared_command_ids_sha256,
  command_ownership_sha256: REVIEWED_DATA.upstream_command_registry.command_ownership_sha256,
  coverage_semantics_sha256: REVIEWED_DATA.upstream_command_registry.coverage_semantics_sha256,
  normalized_operation_registry_sha256: REVIEWED_DATA.normalized_operation_registry_sha256,
  assurance_profile_registry_sha256: REVIEWED_DATA.assurance_profile_registry_sha256,
  assurance_satisfaction_registry_sha256: REVIEWED_DATA.assurance_satisfaction_registry_sha256,
  capability_dependency_registry_sha256: REVIEWED_DATA.capability_dependency_registry_sha256,
  dependency_proof_provider_registry_sha256:
    REVIEWED_DATA.dependency_proof_provider_registry_sha256,
  technique_registry_sha256: REVIEWED_DATA.technique_registry_sha256,
  manual_action_registry_sha256: REVIEWED_DATA.manual_action_registry_sha256,
  command_source_registry_sha256: REVIEWED_DATA.command_source_registry_sha256,
  codec_command_profile_sha256: REVIEWED_DATA.codec_profile.command_data_limits_digest,
});

const codecProfileBasis = {
  profile_id: REVIEWED_DATA.codec_profile.profile_id,
  assurance: REVIEWED_DATA.codec_profile.assurance,
  release_tag: REVIEWED_DATA.codec_profile.release_tag,
  tag_commit: REVIEWED_DATA.codec_profile.tag_commit,
  declaration_source_sha256: REVIEWED_DATA.codec_profile.declaration_source_sha256,
  registry_source_sha256: REVIEWED_DATA.codec_profile.registry_source_sha256,
  command_data_limits_digest: REVIEWED_DATA.codec_profile.command_data_limits_digest,
  command_ids: REVIEWED_DATA.codec_profile.command_ids,
};
const CHAMELEON_V220_CODEC_PROFILE = deepFreeze({
  ...codecProfileBasis,
  codec_profile_digest: hashJson(codecProfileBasis),
});

const sourceProfileBasis = {
  version: REVIEWED_DATA.upstream_command_registry.version,
  declaration_source: REVIEWED_DATA.upstream_command_registry.declaration_source,
  declaration_source_sha256: CHAMELEON_SEMANTIC_DIGESTS.declaration_source_sha256,
  registry_source: REVIEWED_DATA.upstream_command_registry.registry_source,
  registry_source_sha256: CHAMELEON_SEMANTIC_DIGESTS.registry_source_sha256,
  expected_ultra_capabilities_rule:
    REVIEWED_DATA.upstream_command_registry.expected_ultra_capabilities_rule,
  declared_command_ids: REVIEWED_DATA.upstream_command_registry.declared_command_ids,
  declared_unregistered_ids: REVIEWED_DATA.upstream_command_registry.declared_unregistered_ids,
  registry_private_ids: REVIEWED_DATA.upstream_command_registry.registry_private_ids,
};
const CHAMELEON_V220_SOURCE_PROFILE = deepFreeze({
  ...sourceProfileBasis,
  source_profile_digest: hashJson(sourceProfileBasis),
});

const manifestBasis = {
  version: MANIFEST_VERSION,
  provider_id: PROVIDER_ID,
  source_profile_digest: CHAMELEON_V220_SOURCE_PROFILE.source_profile_digest,
  codec_profile_digest: CHAMELEON_V220_CODEC_PROFILE.codec_profile_digest,
  semantic_digests: CHAMELEON_SEMANTIC_DIGESTS,
  command_source_metadata_authority: "provenance_only",
  counts: {
    normalized_operations: OPERATION_BY_ID.size,
    coverage_rows: REVIEWED_DATA.coverage.length,
    availability_variants: VARIANT_BY_KEY.size,
    effect_profiles: Object.keys(REVIEWED_DATA.effect_profiles).length,
    technique_ids: REVIEWED_DATA.technique_registry.length,
    dependency_proof_providers:
      Object.keys(REVIEWED_DATA.dependency_proof_provider_registry).length,
    command_owners: COMMAND_OWNER_BY_ID.size,
    command_source_entries: COMMAND_SOURCE_BY_ID.size,
    compiled_commands: COMPILED_COMMAND_IDS.size,
  },
};
const CHAMELEON_SEMANTIC_MANIFEST = deepFreeze({
  ...manifestBasis,
  manifest_digest: hashJson(manifestBasis),
});

const CHAMELEON_BOOTSTRAP_SUBSET = deepFreeze({
  version: MANIFEST_VERSION,
  operation_ids: [
    "instrument.capabilities",
    "instrument.health",
    "instrument.inventory",
  ],
  command_ids: [1000, 1017, 1025, 1033, 1035],
});

function assertReviewedRegistry() {
  const failures = [];
  const expectDigest = (label, actual, expected) => {
    if (actual !== expected) failures.push(`${label} digest drift`);
  };
  expectDigest(
    "declared commands",
    hashJson(REVIEWED_DATA.upstream_command_registry.declared_command_ids),
    REVIEWED_DATA.declared_command_ids_sha256,
  );
  expectDigest(
    "normalized operations",
    hashJson(canonicalOperationRegistry(REVIEWED_DATA.normalized_operation_registry)),
    REVIEWED_DATA.normalized_operation_registry_sha256,
  );
  expectDigest(
    "assurance profiles",
    hashJson(canonicalAssuranceProfiles(REVIEWED_DATA.assurance_profile_registry)),
    REVIEWED_DATA.assurance_profile_registry_sha256,
  );
  expectDigest(
    "assurance satisfaction",
    hashJson(canonicalAssuranceSatisfaction(REVIEWED_DATA.assurance_satisfaction_registry)),
    REVIEWED_DATA.assurance_satisfaction_registry_sha256,
  );
  expectDigest(
    "capability dependencies",
    hashJson(canonicalCapabilityDependencies(REVIEWED_DATA.capability_dependency_registry)),
    REVIEWED_DATA.capability_dependency_registry_sha256,
  );
  expectDigest(
    "dependency proof providers",
    hashJson(canonicalDependencyProofProviders(REVIEWED_DATA.dependency_proof_provider_registry)),
    REVIEWED_DATA.dependency_proof_provider_registry_sha256,
  );
  expectDigest(
    "techniques",
    hashJson(sorted(REVIEWED_DATA.technique_registry)),
    REVIEWED_DATA.technique_registry_sha256,
  );
  expectDigest(
    "manual actions",
    hashJson(canonicalManualActions(REVIEWED_DATA.manual_action_registry)),
    REVIEWED_DATA.manual_action_registry_sha256,
  );
  expectDigest(
    "command source registry",
    hashJson(canonicalCommandSourceRegistry(REVIEWED_DATA.command_source_registry)),
    REVIEWED_DATA.command_source_registry_sha256,
  );
  expectDigest(
    "coverage semantics",
    hashJson(canonicalCoverageSemantics(REVIEWED_DATA)),
    REVIEWED_DATA.upstream_command_registry.coverage_semantics_sha256,
  );

  const canonicalOwners = [...COMMAND_OWNER_BY_ID]
    .map(([id, row]) => ({
      id,
      provider_capability_id: row.provider_capability_id,
      disposition: row.disposition,
    }))
    .sort((left, right) => left.id - right.id
      || left.provider_capability_id.localeCompare(right.provider_capability_id));
  expectDigest(
    "command ownership",
    hashJson(canonicalOwners),
    REVIEWED_DATA.upstream_command_registry.command_ownership_sha256,
  );

  if (OPERATION_BY_ID.size !== 50) failures.push("expected exactly 50 normalized operations");
  if (REVIEWED_DATA.coverage.length !== 51) failures.push("expected exactly 51 coverage rows");
  if (CAPABILITY_ROW_BY_ID.size !== REVIEWED_DATA.coverage.length) {
    failures.push("coverage capability IDs must be unique");
  }
  if (CAPABILITY_DEPENDENCY_BY_ID.size !== 44) {
    failures.push("expected exactly 44 supported capability formulas");
  }
  if (VARIANT_BY_KEY.size !== 112) failures.push("expected exactly 112 availability variants");
  if (COMMAND_OWNER_BY_ID.size !== 147) failures.push("expected exactly 147 command owners");
  if (REVIEWED_DATA.command_source_registry.length !== 147
      || COMMAND_SOURCE_BY_ID.size !== 147) {
    failures.push("expected exactly 147 unique command source entries");
  }
  if (COMPILED_COMMAND_IDS.size !== 37) failures.push("expected exactly 37 reviewed codec commands");
  if (REVIEWED_DATA.codec_profile.declaration_source_sha256
      !== REVIEWED_DATA.upstream_command_registry.declaration_source_sha256
      || REVIEWED_DATA.codec_profile.registry_source_sha256
        !== REVIEWED_DATA.upstream_command_registry.registry_source_sha256) {
    failures.push("codec source pins drifted from the semantic source profile");
  }

  for (const [operationId, contract] of OPERATION_BY_ID) {
    if (!OPERATION_ID_PATTERN.test(operationId)) failures.push(`invalid operation ${operationId}`);
    if (!REVIEWED_DATA.assurance_profile_registry[contract.minimum_assurance_profile_id]) {
      failures.push(`operation ${operationId} has unknown assurance profile`);
    }
  }
  for (const rawOperation of [
    "protocol.apdu_exchange",
    "protocol.respond",
    "protocol.transceive",
  ]) {
    if (OPERATION_BY_ID.get(rawOperation)?.exposure !== "provider_private") {
      failures.push(`${rawOperation} must remain provider-private`);
    }
  }
  const conformanceProfileUsers = [...OPERATION_BY_ID]
    .filter(([, contract]) => contract.minimum_assurance_profile_id
      === "enrolled_conformance_tested")
    .map(([operationId]) => operationId)
    .sort();
  if (!sameValues(conformanceProfileUsers, ["protocol.discovery_probe"])) {
    failures.push("enrolled_conformance_tested must bind only protocol.discovery_probe");
  }
  if (OPERATION_BY_ID.get("protocol.compiled_exchange")?.minimum_assurance_profile_id
      !== "enrolled_source_pinned") {
    failures.push("shared protocol.compiled_exchange assurance widened");
  }
  const closedProbeDependency = CAPABILITY_DEPENDENCY_BY_ID.get(
    "CU-HF-14A-COMPILED-PROBE",
  );
  const closedProbeRefs = [
    "capability_variant:CU-HF-14A-RAW/default",
    "compiler:iso14443a_closed_probe_v1",
    "conformance:chameleon_hf14a_closed_probe_v1",
  ];
  const closedProbeVariantIds = ["requa_atqa_v1", "wupa_atqa_v1"];
  if (!closedProbeDependency
      || !sameValues(sorted(closedProbeDependency.all_of), sorted(closedProbeRefs))
      || closedProbeDependency.any_of.length !== 0
      || !sameValues(sorted(Object.keys(closedProbeDependency.variants)), closedProbeVariantIds)) {
    failures.push("closed HF14A probe dependency ceiling drifted");
  }
  for (const variantId of closedProbeVariantIds) {
    const variant = closedProbeDependency?.variants?.[variantId];
    if (!variant || variant.parameter_selector_id !== variantId
        || variant.all_of.length !== 0 || variant.any_of.length !== 0
        || !sameValues(variant.normalized_operations, ["protocol.discovery_probe"])
        || !sameValues(variant.technique_bindings, ["protocol.probe"])
        || !sameValues(variant.effect_profile_refs, ["EP-TARGET-TRANSMIT-RF"])) {
      failures.push(`closed HF14A probe variant ${variantId} drifted`);
    }
  }
  if (COMPILED_COMMAND_IDS.has(2010)) {
    failures.push("command 2010 must remain outside the reviewed codec profile");
  }
  const expectedHf14aConformanceProvider = {
    provider_kind: "conformance",
    owner_principal: "provider_hil_conformance_runner",
    artifact_digest_binding:
      "provider_binary_compiler_registry_source_firmware_transport_and_hil_fixture_digests",
    signed_verdict_type: "bob-proof:provider-hil-conformance:v1",
    trust_epoch_binding: "provider_registry_and_hil_fixture_epoch",
    freshness_policy: "provider_build_firmware_transport_compiler_and_owned_hil_run",
    revocation_policy: "deny_on_provider_firmware_transport_compiler_fixture_or_epoch_drift",
  };
  if (hashJson(REVIEWED_DATA.dependency_proof_provider_registry[
    "conformance:chameleon_hf14a_closed_probe_v1"
  ]) !== hashJson(expectedHf14aConformanceProvider)) {
    failures.push("closed HF14A HIL conformance provider contract drifted");
  }

  for (const row of REVIEWED_DATA.coverage) {
    if (!CAPABILITY_ID_PATTERN.test(row.provider_capability_id)) {
      failures.push(`invalid capability ${row.provider_capability_id}`);
    }
    if (row.provider !== PROVIDER_ID) failures.push(`${row.provider_capability_id} provider drift`);
    for (const operationId of row.normalized_operations) {
      const operation = OPERATION_BY_ID.get(operationId);
      if (!operation) failures.push(`${row.provider_capability_id} has unknown operation`);
      if (operation?.exposure === "provider_private" && row.disposition !== "provider_internal") {
        failures.push(`${row.provider_capability_id} exposes a provider-private operation`);
      }
      if (operation?.exposure === "operator_only" && row.disposition !== "operator_only") {
        failures.push(`${row.provider_capability_id} exposes an operator-only operation`);
      }
      if (operation?.exposure === "unsupported" && row.disposition !== "unsupported") {
        failures.push(`${row.provider_capability_id} exposes an unsupported operation`);
      }
    }
    for (const effectRef of row.effect_profile_refs) {
      if (!REVIEWED_DATA.effect_profiles[effectRef]) {
        failures.push(`${row.provider_capability_id} has unknown effect profile`);
      }
    }
  }

  const declaredUnregistered = new Set(
    REVIEWED_DATA.upstream_command_registry.declared_unregistered_ids,
  );
  const registryPrivate = new Set(REVIEWED_DATA.upstream_command_registry.registry_private_ids);
  for (let index = 0; index < REVIEWED_DATA.command_source_registry.length; index += 1) {
    const entry = REVIEWED_DATA.command_source_registry[index];
    const owner = COMMAND_OWNER_BY_ID.get(entry.command_id);
    if (index > 0
        && REVIEWED_DATA.command_source_registry[index - 1].command_id >= entry.command_id) {
      failures.push("command source registry must be strictly ordered by command ID");
    }
    if (!owner || owner.provider_capability_id !== entry.provider_capability_id
        || owner.disposition !== entry.disposition) {
      failures.push(`command ${entry.command_id} source metadata drifted from its semantic owner`);
    }
    if (registryPrivate.has(entry.command_id)) {
      if (entry.declaration_symbol !== null) {
        failures.push(`command ${entry.command_id} registry-private declaration must be null`);
      }
    } else if (typeof entry.declaration_symbol !== "string"
        || !DECLARATION_SYMBOL_PATTERN.test(entry.declaration_symbol)) {
      failures.push(`command ${entry.command_id} has an invalid declaration symbol`);
    }
    if (declaredUnregistered.has(entry.command_id)) {
      if (entry.runtime_handler_symbol !== null) {
        failures.push(`command ${entry.command_id} declared-unregistered handler must be null`);
      }
    } else if (typeof entry.runtime_handler_symbol !== "string"
        || !RUNTIME_SYMBOL_PATTERN.test(entry.runtime_handler_symbol)) {
      failures.push(`command ${entry.command_id} has an invalid runtime handler symbol`);
    }
    if (!sameValues(entry.hook_symbols, sorted(new Set(entry.hook_symbols)))) {
      failures.push(`command ${entry.command_id} hook symbols must be unique and sorted`);
    }
    if (entry.hook_symbols.some((symbol) => !RUNTIME_SYMBOL_PATTERN.test(symbol))) {
      failures.push(`command ${entry.command_id} has an invalid hook symbol`);
    }
    if (entry.runtime_handler_symbol === null && entry.hook_symbols.length > 0) {
      failures.push(`command ${entry.command_id} cannot have hooks without a runtime row`);
    }
    if (entry.source_profile_id !== COMMAND_SOURCE_PROFILE_ID
        || entry.source_profile_digest !== CHAMELEON_V220_SOURCE_PROFILE.source_profile_digest
        || entry.declaration_source_sha256
          !== CHAMELEON_V220_SOURCE_PROFILE.declaration_source_sha256
        || entry.registry_source_sha256 !== CHAMELEON_V220_SOURCE_PROFILE.registry_source_sha256) {
      failures.push(`command ${entry.command_id} source profile binding drifted`);
    }
    if (entry.entry_digest !== hashJson(canonicalCommandSourceEntryBasis(entry))) {
      failures.push(`command ${entry.command_id} source entry digest drifted`);
    }
  }

  const knownProofRefs = new Set(PROOF_CONTRACT_BY_REF.keys());
  const knownVariantRefs = new Set(
    [...VARIANT_BY_KEY.keys()].map((key) => `capability_variant:${key}`),
  );
  const bootstrapRow = CAPABILITY_ROW_BY_ID.get("CU-CORE-INVENTORY");
  if (!bootstrapRow
      || !sameValues(sorted(bootstrapRow.normalized_operations), CHAMELEON_BOOTSTRAP_SUBSET.operation_ids)
      || !sameValues([...bootstrapRow.upstream_command_ids].sort((a, b) => a - b),
        CHAMELEON_BOOTSTRAP_SUBSET.command_ids)) {
    failures.push("bootstrap registry is not the exact strict full-manifest subset");
  }

  const variantEdges = new Map([...VARIANT_BY_KEY.keys()].map((key) => [key, new Set()]));
  for (const [capabilityId, dependency] of CAPABILITY_DEPENDENCY_BY_ID) {
    const row = CAPABILITY_ROW_BY_ID.get(capabilityId);
    if (!row) {
      failures.push(`${capabilityId} has no coverage owner`);
      continue;
    }
    if (row.disposition === "unsupported") {
      failures.push(`${capabilityId} gives an unsupported row an availability formula`);
    }
    const seenCommands = new Set();
    const operationUnion = new Set();
    const techniqueUnion = new Set();
    const effectUnion = new Set();
    for (const [variantId, rawVariant] of Object.entries(dependency.variants)) {
      if (rawVariant.parameter_selector_id !== variantId) {
        failures.push(`${capabilityId}/${variantId} selector drift`);
      }
      for (const operationId of rawVariant.normalized_operations) operationUnion.add(operationId);
      for (const techniqueId of rawVariant.technique_bindings) techniqueUnion.add(techniqueId);
      for (const effectRef of rawVariant.effect_profile_refs) effectUnion.add(effectRef);
      const formulaRefs = [
        ...dependency.all_of,
        ...dependency.any_of.flat(),
        ...rawVariant.all_of,
        ...rawVariant.any_of.flat(),
      ];
      if (formulaRefs.length === 0) failures.push(`${capabilityId}/${variantId} has an empty formula`);
      for (const ref of formulaRefs) {
        if (ref.startsWith("command:")) seenCommands.add(Number(ref.slice("command:".length)));
      }
      for (const techniqueId of rawVariant.technique_bindings) {
        if (!REVIEWED_DATA.technique_registry.includes(techniqueId)) {
          failures.push(`${capabilityId}/${variantId} uses an unknown technique`);
        }
      }
    }
    for (const [label, actual, expected] of [
      ["operations", sorted(operationUnion), sorted(row.normalized_operations)],
      ["techniques", sorted(techniqueUnion), sorted(row.technique_bindings)],
      ["effects", sorted(effectUnion), sorted(row.effect_profile_refs)],
      ["commands", [...seenCommands].sort((a, b) => a - b),
        [...row.upstream_command_ids].sort((a, b) => a - b)],
    ]) {
      if (!sameValues(actual, expected)) failures.push(`${capabilityId} variant ${label} union drift`);
    }
  }

  for (const [key, variant] of VARIANT_BY_KEY) {
    if (!VARIANT_ID_PATTERN.test(variant.variant_id)) failures.push(`invalid variant ${key}`);
    const row = CAPABILITY_ROW_BY_ID.get(variant.capability_id);
    for (const operationId of variant.normalized_operations) {
      if (!row.normalized_operations.includes(operationId)) {
        failures.push(`${key} operation escapes its coverage owner`);
      }
    }
    for (const effectRef of variant.effect_profile_refs) {
      if (!row.effect_profile_refs.includes(effectRef)) {
        failures.push(`${key} effect escapes its coverage owner`);
      }
    }
    for (const ref of [...variant.all_of, ...variant.any_of.flat()]) {
      if (ref.startsWith("command:")) {
        const commandId = Number(ref.slice("command:".length));
        if (!COMMAND_OWNER_BY_ID.has(commandId)) failures.push(`${key} uses unknown command`);
        if (COMMAND_OWNER_BY_ID.get(commandId)?.provider_capability_id !== variant.capability_id) {
          failures.push(`${key} uses a command owned by another capability`);
        }
      } else if (ref.startsWith("capability_variant:")) {
        if (!knownVariantRefs.has(ref)) failures.push(`${key} uses unknown capability variant`);
        const target = ref.slice("capability_variant:".length);
        if (target === key) failures.push(`${key} depends on itself`);
        else if (VARIANT_BY_KEY.has(target)) variantEdges.get(key).add(target);
      } else if (!knownProofRefs.has(ref)) {
        failures.push(`${key} uses an unresolved dependency proof`);
      }
    }
  }

  const visiting = new Set();
  const visited = new Set();
  function visitVariant(key) {
    if (visiting.has(key)) {
      failures.push(`availability dependency cycle contains ${key}`);
      return;
    }
    if (visited.has(key)) return;
    visiting.add(key);
    for (const target of variantEdges.get(key) || []) visitVariant(target);
    visiting.delete(key);
    visited.add(key);
  }
  for (const key of variantEdges.keys()) visitVariant(key);

  if (failures.length > 0) {
    throw new Error(`invalid reviewed Chameleon semantic registry: ${sorted(new Set(failures)).join("; ")}`);
  }
}

assertReviewedRegistry();

function getChameleonOperation(operationId) {
  if (typeof operationId !== "string" || !OPERATION_ID_PATTERN.test(operationId)) return null;
  const contract = OPERATION_BY_ID.get(operationId);
  if (!contract) return null;
  return deepFreeze({
    operation_id: operationId,
    exposure: contract.exposure,
    minimum_assurance_profile_id: contract.minimum_assurance_profile_id,
    operation_contract_digest: hashJson({ operation_id: operationId, ...contract }),
  });
}

function getChameleonCapability(capabilityId) {
  if (typeof capabilityId !== "string" || !CAPABILITY_ID_PATTERN.test(capabilityId)) return null;
  const row = CAPABILITY_ROW_BY_ID.get(capabilityId);
  if (!row) return null;
  return deepFreeze({
    ...row,
    coverage_row_digest: hashJson(canonicalCoverageRows([row])[0]),
    manifest_supported: row.disposition !== "unsupported",
    evaluator_callable: EVALUATOR_DISPOSITIONS.has(row.disposition)
      && row.normalized_operations.some(
        (operationId) => OPERATION_BY_ID.get(operationId)?.exposure === EVALUATOR_EXPOSURE,
      ),
  });
}

function getChameleonCommandOwner(commandId) {
  if (!Number.isSafeInteger(commandId) || commandId < 1 || commandId > 0xffff) return null;
  const row = COMMAND_OWNER_BY_ID.get(commandId);
  const source = COMMAND_SOURCE_BY_ID.get(commandId);
  if (!row) return null;
  return deepFreeze({
    command_id: commandId,
    provider_capability_id: row.provider_capability_id,
    disposition: row.disposition,
    effect_profile_refs: row.effect_profile_refs,
    source_entry_digest: source.entry_digest,
    command_owner_digest: hashJson({
      command_id: commandId,
      provider_capability_id: row.provider_capability_id,
      disposition: row.disposition,
      effect_profile_refs: sorted(row.effect_profile_refs),
    }),
  });
}

function getChameleonCommandSourceProvenance(commandId) {
  if (!Number.isSafeInteger(commandId) || commandId < 1 || commandId > 0xffff) return null;
  const entry = COMMAND_SOURCE_BY_ID.get(commandId);
  if (!entry) return null;
  return deepFreeze({
    ...entry,
    metadata_authority: "provenance_only",
    dispatch_authority: false,
    compiler_authority: false,
  });
}

function getChameleonAvailabilityVariant(capabilityId, variantId) {
  if (typeof capabilityId !== "string" || typeof variantId !== "string") return null;
  return VARIANT_BY_KEY.get(`${capabilityId}/${variantId}`) || null;
}

function normalizeAssuranceClaims(input, label) {
  assertClosedObject(input, label, ASSURANCE_AXES);
  const normalized = {};
  for (const axis of ASSURANCE_AXES) {
    const actual = input[axis];
    if (typeof actual !== "string"
        || !REVIEWED_DATA.assurance_satisfaction_registry[axis]?.[actual]) {
      throw new Error(`${label}.${axis} is not a registered actual assurance claim`);
    }
    normalized[axis] = actual;
  }
  return deepFreeze(normalized);
}

function assertAvailabilityManifestBindings(input, label) {
  const expected = {
    semantic_manifest_digest: CHAMELEON_SEMANTIC_MANIFEST.manifest_digest,
    source_profile_digest: CHAMELEON_V220_SOURCE_PROFILE.source_profile_digest,
    codec_profile_digest: CHAMELEON_V220_CODEC_PROFILE.codec_profile_digest,
    assurance_profile_registry_digest:
      CHAMELEON_SEMANTIC_DIGESTS.assurance_profile_registry_sha256,
    dependency_proof_registry_digest:
      CHAMELEON_SEMANTIC_DIGESTS.dependency_proof_provider_registry_sha256,
  };
  for (const field of AVAILABILITY_MANIFEST_BINDING_FIELDS) {
    if (input[field] !== expected[field]) throw new Error(`${label}.${field} drifted`);
  }
}

function assertExactAvailabilityBindings(input, expected, fields, label) {
  for (const field of fields) {
    if (input[field] !== expected[field]) throw new Error(`${label}.${field} drifted`);
  }
}

function normalizeAvailabilityEvidenceRequest(input, label) {
  assertClosedObject(input, label, AVAILABILITY_EVIDENCE_REQUEST_FIELDS);
  if (input.version !== AVAILABILITY_EVIDENCE_RESOLVER_PORT_VERSION) {
    throw new Error(`${label}.version must be ${AVAILABILITY_EVIDENCE_RESOLVER_PORT_VERSION}`);
  }
  if (input.provider_id !== PROVIDER_ID) throw new Error(`${label}.provider_id drifted`);
  assertOpaqueIdentity(input.evidence_ref, `${label}.evidence_ref`);
  assertAvailabilityManifestBindings(input, label);
  assertDigest(input.inventory_projection_digest, `${label}.inventory_projection_digest`);
  assertDigest(input.device_identity_digest, `${label}.device_identity_digest`);
  assertOpaqueIdentity(input.custody_id, `${label}.custody_id`);
  assertDigest(input.custody_projection_digest, `${label}.custody_projection_digest`);
  assertOpaqueIdentity(input.session_id, `${label}.session_id`);
  assertOpaqueIdentity(input.authority_id, `${label}.authority_id`);
  assertSafeInteger(input.authority_epoch, `${label}.authority_epoch`, 1);
  assertSafeInteger(input.revocation_generation, `${label}.revocation_generation`, 0);
  assertDigest(input.authority_resolution_digest, `${label}.authority_resolution_digest`);
  return deepFreeze(Object.fromEntries(
    AVAILABILITY_EVIDENCE_REQUEST_FIELDS.map((field) => [field, input[field]]),
  ));
}

function normalizeProductionAvailabilityEvidenceRequest(input, label) {
  assertClosedObject(input, label, PRODUCTION_AVAILABILITY_EVIDENCE_REQUEST_FIELDS);
  if (input.version !== CHAMELEON_AVAILABILITY_BACKEND_VERSION) {
    throw new Error(`${label}.version must be ${CHAMELEON_AVAILABILITY_BACKEND_VERSION}`);
  }
  if (input.provider_id !== PROVIDER_ID) throw new Error(`${label}.provider_id drifted`);
  assertOpaqueIdentity(input.evidence_ref, `${label}.evidence_ref`);
  if (typeof input.target_domain !== "string" || !DOMAIN_PATTERN.test(input.target_domain)) {
    throw new Error(`${label}.target_domain must be a canonical DNS domain`);
  }
  assertDigest(input.session_nucleus_hash, `${label}.session_nucleus_hash`);
  assertAvailabilityManifestBindings(input, label);
  assertDigest(input.inventory_projection_digest, `${label}.inventory_projection_digest`);
  assertDigest(input.device_identity_digest, `${label}.device_identity_digest`);
  assertOpaqueIdentity(input.custody_id, `${label}.custody_id`);
  assertDigest(input.custody_projection_digest, `${label}.custody_projection_digest`);
  assertOpaqueIdentity(input.session_id, `${label}.session_id`);
  assertOpaqueIdentity(input.authority_id, `${label}.authority_id`);
  assertSafeInteger(input.authority_epoch, `${label}.authority_epoch`, 1);
  assertSafeInteger(input.revocation_generation, `${label}.revocation_generation`, 0);
  assertDigest(input.authority_resolution_digest, `${label}.authority_resolution_digest`);
  return deepFreeze(Object.fromEntries(
    PRODUCTION_AVAILABILITY_EVIDENCE_REQUEST_FIELDS.map((field) => [field, input[field]]),
  ));
}

function productionAvailabilityRequestContextDigest(request) {
  return hashJson({
    domain: "bob.chameleon.availability.variant-request-context.v2",
    ...Object.fromEntries(
      PRODUCTION_AVAILABILITY_EVIDENCE_REQUEST_FIELDS.map((field) => [field, request[field]]),
    ),
  });
}

function buildChameleonAvailabilityVariantQualification(
  input,
  label = "chameleon_availability_variant_qualification_input",
) {
  assertClosedObject(input, label, [
    "request",
    "capability_id",
    "variant_id",
    "dependency_binding_digest",
    "reported_command_ids_digest",
    "assurance_claims_digest",
    "dependency_proofs_digest",
    "alternative_selections_digest",
  ]);
  const request = normalizeProductionAvailabilityEvidenceRequest(
    input.request,
    `${label}.request`,
  );
  if (typeof input.capability_id !== "string"
      || !CAPABILITY_ID_PATTERN.test(input.capability_id)) {
    throw new Error(`${label}.capability_id is invalid`);
  }
  if (typeof input.variant_id !== "string" || !VARIANT_ID_PATTERN.test(input.variant_id)) {
    throw new Error(`${label}.variant_id is invalid`);
  }
  const variant = VARIANT_BY_KEY.get(`${input.capability_id}/${input.variant_id}`);
  if (!variant) throw new Error(`${label} names an unknown reviewed availability variant`);
  for (const field of [
    "dependency_binding_digest",
    "reported_command_ids_digest",
    "assurance_claims_digest",
    "dependency_proofs_digest",
    "alternative_selections_digest",
  ]) assertDigest(input[field], `${label}.${field}`);
  const basis = {
    version: CHAMELEON_AVAILABILITY_BACKEND_VERSION,
    provider_id: PROVIDER_ID,
    capability_id: variant.capability_id,
    variant_id: variant.variant_id,
    availability_variant_digest: variant.availability_variant_digest,
    parameter_selector_id: variant.parameter_selector_id,
    normalized_operations_digest: hashJson(variant.normalized_operations),
    technique_bindings_digest: hashJson(variant.technique_bindings),
    effect_profile_refs_digest: hashJson(variant.effect_profile_refs),
    request_context_digest: productionAvailabilityRequestContextDigest(request),
    dependency_binding_digest: input.dependency_binding_digest,
    reported_command_ids_digest: input.reported_command_ids_digest,
    assurance_claims_digest: input.assurance_claims_digest,
    dependency_proofs_digest: input.dependency_proofs_digest,
    alternative_selections_digest: input.alternative_selections_digest,
  };
  return deepFreeze({
    ...basis,
    qualification_digest: hashJson({
      domain: "bob.chameleon.availability.variant-qualification.v2",
      ...basis,
    }),
  });
}

function normalizeAvailabilityVariantQualifications(input, request, label) {
  assertDataArray(input, label, VARIANT_BY_KEY.size);
  const qualifications = new Map();
  for (let index = 0; index < input.length; index += 1) {
    const at = `${label}[${index}]`;
    const value = assertClosedObject(
      input[index],
      at,
      AVAILABILITY_VARIANT_QUALIFICATION_FIELDS,
    );
    const expected = buildChameleonAvailabilityVariantQualification({
      request,
      capability_id: value.capability_id,
      variant_id: value.variant_id,
      dependency_binding_digest: value.dependency_binding_digest,
      reported_command_ids_digest: value.reported_command_ids_digest,
      assurance_claims_digest: value.assurance_claims_digest,
      dependency_proofs_digest: value.dependency_proofs_digest,
      alternative_selections_digest: value.alternative_selections_digest,
    }, at);
    for (const field of AVAILABILITY_VARIANT_QUALIFICATION_FIELDS) {
      if (value[field] !== expected[field]) throw new Error(`${at}.${field} drifted`);
    }
    const key = `${expected.capability_id}/${expected.variant_id}`;
    if (qualifications.has(key)) throw new Error(`${label} has duplicate variant qualifications`);
    qualifications.set(key, expected);
  }
  return qualifications;
}

function availabilityDependencyProofDigest(basis) {
  return hashJson({
    domain: "bob.chameleon.availability.dependency-proof.v1",
    ...basis,
  });
}

function normalizeDependencyProofs(input, request, label) {
  assertDataArray(input, label, PROOF_CONTRACT_BY_REF.size);
  const proofs = new Map();
  const bindingFields = AVAILABILITY_EVIDENCE_REQUEST_FIELDS;
  for (let index = 0; index < input.length; index += 1) {
    const at = `${label}[${index}]`;
    const proof = assertClosedObject(input[index], at, [
      ...bindingFields,
      "dependency_ref",
      "provider_contract_digest",
      "owner_principal",
      "artifact_digest",
      "trust_epoch",
      "verdict",
      "observed_at",
      "expires_at",
      "revoked",
      "proof_digest",
    ]);
    assertExactAvailabilityBindings(proof, request, bindingFields, at);
    const contract = PROOF_CONTRACT_BY_REF.get(proof.dependency_ref);
    if (!contract) throw new Error(`${at}.dependency_ref is not registered`);
    if (proof.provider_contract_digest !== contract.contract_digest) {
      throw new Error(`${at}.provider_contract_digest does not match the reviewed dependency contract`);
    }
    if (proof.owner_principal !== contract.owner_principal) {
      throw new Error(`${at}.owner_principal does not match the reviewed dependency owner`);
    }
    assertDigest(proof.artifact_digest, `${at}.artifact_digest`);
    assertSafeInteger(proof.trust_epoch, `${at}.trust_epoch`, 1);
    if (!['satisfied', 'unsatisfied'].includes(proof.verdict)) {
      throw new Error(`${at}.verdict must be satisfied or unsatisfied`);
    }
    assertTimestamp(proof.observed_at, `${at}.observed_at`);
    assertTimestamp(proof.expires_at, `${at}.expires_at`);
    if (Date.parse(proof.expires_at) <= Date.parse(proof.observed_at)) {
      throw new Error(`${at} freshness interval is empty`);
    }
    assertBoolean(proof.revoked, `${at}.revoked`);
    const basis = {
      ...Object.fromEntries(bindingFields.map((field) => [field, proof[field]])),
      dependency_ref: proof.dependency_ref,
      provider_contract_digest: proof.provider_contract_digest,
      owner_principal: proof.owner_principal,
      artifact_digest: proof.artifact_digest,
      trust_epoch: proof.trust_epoch,
      verdict: proof.verdict,
      observed_at: proof.observed_at,
      expires_at: proof.expires_at,
      revoked: proof.revoked,
    };
    const proofDigest = availabilityDependencyProofDigest(basis);
    if (assertDigest(proof.proof_digest, `${at}.proof_digest`) !== proofDigest) {
      throw new Error(`${at}.proof_digest does not bind the exact evidence context and verdict`);
    }
    if (proofs.has(proof.dependency_ref)) throw new Error(`${label} has duplicate dependency refs`);
    proofs.set(proof.dependency_ref, deepFreeze({ ...basis, proof_digest: proofDigest }));
  }
  return proofs;
}

function assertFreshAvailabilityEvidence(observedAt, expiresAt, currentTime, label) {
  const observed = Date.parse(observedAt);
  const expires = Date.parse(expiresAt);
  const current = Date.parse(currentTime);
  if (observed > current) throw new Error(`${label} is not yet current`);
  if (current >= expires) throw new Error(`${label} is stale`);
}

function normalizeResolvedAvailabilityEvidence(input, request, label) {
  assertClosedObject(input, label, [
    ...AVAILABILITY_EVIDENCE_REQUEST_FIELDS,
    "evidence_owner_principal",
    "evidence_artifact_digest",
    "evidence_trust_epoch",
    "observed_at",
    "expires_at",
    "revoked",
    "reported_command_ids",
    "assurance_claims",
    "dependency_proofs",
  ]);
  assertExactAvailabilityBindings(
    input,
    request,
    AVAILABILITY_EVIDENCE_REQUEST_FIELDS,
    label,
  );
  const evidenceOwnerPrincipal = assertOpaqueIdentity(
    input.evidence_owner_principal,
    `${label}.evidence_owner_principal`,
  );
  const evidenceArtifactDigest = assertDigest(
    input.evidence_artifact_digest,
    `${label}.evidence_artifact_digest`,
  );
  const evidenceTrustEpoch = assertSafeInteger(
    input.evidence_trust_epoch,
    `${label}.evidence_trust_epoch`,
    1,
  );
  const observedAt = assertTimestamp(input.observed_at, `${label}.observed_at`);
  const expiresAt = assertTimestamp(input.expires_at, `${label}.expires_at`);
  if (Date.parse(expiresAt) <= Date.parse(observedAt)) {
    throw new Error(`${label} freshness interval is empty`);
  }
  const revoked = assertBoolean(input.revoked, `${label}.revoked`);
  const reportedCommandIds = normalizeCommandIds(
    input.reported_command_ids,
    `${label}.reported_command_ids`,
  );
  const claims = normalizeAssuranceClaims(input.assurance_claims, `${label}.assurance_claims`);
  const dependencyProofs = normalizeDependencyProofs(
    input.dependency_proofs,
    request,
    `${label}.dependency_proofs`,
  );
  const dependencyProofList = [...dependencyProofs.values()].sort(
    (left, right) => left.dependency_ref.localeCompare(right.dependency_ref),
  );
  const basis = {
    ...request,
    evidence_owner_principal: evidenceOwnerPrincipal,
    evidence_artifact_digest: evidenceArtifactDigest,
    evidence_trust_epoch: evidenceTrustEpoch,
    observed_at: observedAt,
    expires_at: expiresAt,
    revoked,
    reported_command_ids: reportedCommandIds,
    assurance_claims: claims,
    dependency_proofs: dependencyProofList,
  };
  return deepFreeze({
    ...basis,
    evidence_projection_digest: hashJson({
      domain: "bob.chameleon.availability.evidence-projection.v1",
      ...basis,
    }),
  });
}

function availabilityCurrentStateRequest(request, evidence) {
  const dependencyProofBindings = evidence.dependency_proofs.map((proof) => deepFreeze({
    dependency_ref: proof.dependency_ref,
    provider_contract_digest: proof.provider_contract_digest,
    owner_principal: proof.owner_principal,
    artifact_digest: proof.artifact_digest,
    trust_epoch: proof.trust_epoch,
    verdict: proof.verdict,
    proof_digest: proof.proof_digest,
  }));
  return deepFreeze({
    ...request,
    evidence_projection_digest: evidence.evidence_projection_digest,
    evidence_owner_principal: evidence.evidence_owner_principal,
    evidence_artifact_digest: evidence.evidence_artifact_digest,
    evidence_trust_epoch: evidence.evidence_trust_epoch,
    observed_at: evidence.observed_at,
    expires_at: evidence.expires_at,
    reported_command_ids_digest: hashJson(evidence.reported_command_ids),
    assurance_claims_digest: hashJson(evidence.assurance_claims),
    dependency_proofs_digest: hashJson(evidence.dependency_proofs),
    dependency_proof_bindings: dependencyProofBindings,
  });
}

function normalizeAvailabilityCurrentState(input, request, evidence, label) {
  assertClosedObject(input, label, [
    ...AVAILABILITY_EVIDENCE_REQUEST_FIELDS,
    "evidence_projection_digest",
    "evidence_owner_principal",
    "evidence_artifact_digest",
    "evidence_trust_epoch",
    "current_time",
    "evidence_revoked",
    "inventory_current",
    "device_current",
    "custody_current",
    "session_current",
    "authority_current",
    "reported_command_ids_digest",
    "assurance_claims_digest",
    "dependency_states",
  ]);
  assertExactAvailabilityBindings(
    input,
    request,
    AVAILABILITY_EVIDENCE_REQUEST_FIELDS,
    label,
  );
  for (const [field, expected] of Object.entries({
    evidence_projection_digest: evidence.evidence_projection_digest,
    evidence_owner_principal: evidence.evidence_owner_principal,
    evidence_artifact_digest: evidence.evidence_artifact_digest,
    evidence_trust_epoch: evidence.evidence_trust_epoch,
    reported_command_ids_digest: hashJson(evidence.reported_command_ids),
    assurance_claims_digest: hashJson(evidence.assurance_claims),
  })) {
    if (input[field] !== expected) throw new Error(`${label}.${field} drifted`);
  }
  const currentTime = assertTimestamp(input.current_time, `${label}.current_time`);
  if (assertBoolean(input.evidence_revoked, `${label}.evidence_revoked`)
      || evidence.revoked) {
    throw new Error(`${label} evidence is revoked`);
  }
  for (const field of [
    "inventory_current",
    "device_current",
    "custody_current",
    "session_current",
    "authority_current",
  ]) {
    if (assertBoolean(input[field], `${label}.${field}`) !== true) {
      throw new Error(`${label}.${field} must be true`);
    }
  }
  assertFreshAvailabilityEvidence(
    evidence.observed_at,
    evidence.expires_at,
    currentTime,
    `${label} evidence`,
  );
  assertDataArray(input.dependency_states, `${label}.dependency_states`, evidence.dependency_proofs.length);
  const states = new Map();
  for (let index = 0; index < input.dependency_states.length; index += 1) {
    const at = `${label}.dependency_states[${index}]`;
    const state = assertClosedObject(input.dependency_states[index], at, [
      "dependency_ref",
      "provider_contract_digest",
      "owner_principal",
      "artifact_digest",
      "trust_epoch",
      "verdict",
      "proof_digest",
      "revoked",
    ]);
    const proof = evidence.dependency_proofs.find(
      (entry) => entry.dependency_ref === state.dependency_ref,
    );
    if (!proof) throw new Error(`${at}.dependency_ref is not present in resolved evidence`);
    for (const field of [
      "provider_contract_digest",
      "owner_principal",
      "artifact_digest",
      "trust_epoch",
      "verdict",
      "proof_digest",
    ]) {
      if (state[field] !== proof[field]) throw new Error(`${at}.${field} drifted`);
    }
    if (assertBoolean(state.revoked, `${at}.revoked`) || proof.revoked) {
      throw new Error(`${at} is revoked`);
    }
    assertFreshAvailabilityEvidence(
      proof.observed_at,
      proof.expires_at,
      currentTime,
      `${at} proof`,
    );
    if (states.has(state.dependency_ref)) {
      throw new Error(`${label}.dependency_states has duplicate dependency refs`);
    }
    states.set(state.dependency_ref, deepFreeze({
      dependency_ref: state.dependency_ref,
      provider_contract_digest: state.provider_contract_digest,
      owner_principal: state.owner_principal,
      artifact_digest: state.artifact_digest,
      trust_epoch: state.trust_epoch,
      verdict: state.verdict,
      proof_digest: state.proof_digest,
      revoked: false,
    }));
  }
  if (states.size !== evidence.dependency_proofs.length) {
    throw new Error(`${label}.dependency_states must resolve every dependency proof exactly once`);
  }
  const basis = {
    ...request,
    evidence_projection_digest: evidence.evidence_projection_digest,
    evidence_owner_principal: evidence.evidence_owner_principal,
    evidence_artifact_digest: evidence.evidence_artifact_digest,
    evidence_trust_epoch: evidence.evidence_trust_epoch,
    current_time: currentTime,
    evidence_revoked: false,
    inventory_current: true,
    device_current: true,
    custody_current: true,
    session_current: true,
    authority_current: true,
    reported_command_ids_digest: input.reported_command_ids_digest,
    assurance_claims_digest: input.assurance_claims_digest,
    dependency_states: [...states.values()].sort(
      (left, right) => left.dependency_ref.localeCompare(right.dependency_ref),
    ),
  };
  return deepFreeze({
    ...basis,
    current_state_digest: hashJson({
      domain: "bob.chameleon.availability.current-state.v1",
      ...basis,
    }),
  });
}

function assertProductionAvailabilityDependencyProofsCurrent(
  dependencyProofs,
  backendProjection,
  label,
) {
  const definitelyCurrentAt = Date.parse(backendProjection.current_time_earliest);
  const definitelyCurrentThrough = Date.parse(backendProjection.current_time_latest);
  if (!Number.isFinite(definitelyCurrentAt) || !Number.isFinite(definitelyCurrentThrough)
      || definitelyCurrentAt > definitelyCurrentThrough) {
    throw new Error(`${label} trusted-clock uncertainty interval is invalid`);
  }
  for (let index = 0; index < dependencyProofs.length; index += 1) {
    const proof = dependencyProofs[index];
    const at = `${label}.dependency_proofs[${index}]`;
    if (proof.revoked === true) throw new Error(`${at} is revoked`);
    if (Date.parse(proof.observed_at) > definitelyCurrentAt) {
      throw new Error(`${at} is not yet definitely current`);
    }
    if (definitelyCurrentThrough >= Date.parse(proof.expires_at)) {
      throw new Error(`${at} is stale at trusted-clock uncertainty`);
    }
  }
}

// This is deliberately the only resolver-port factory in this module. It
// brands a closed provider-neutral callback contract for hostile tests, but it
// cannot attest that the injected verifier is durable, independent, or backed
// by a production trust registry. Runtime readiness is therefore hard-coded
// false downstream; callers cannot promote this port by changing a field.
function createTestChameleonAvailabilityEvidenceResolverPort(input = {}) {
  assertClosedObject(input, "test_chameleon_availability_evidence_resolver_port", [
    "version",
    "port_id",
    "test_only",
    "verification_model",
    "resolve_evidence",
    "resolve_current_state",
  ]);
  if (input.version !== AVAILABILITY_EVIDENCE_RESOLVER_PORT_VERSION) {
    throw new Error(
      `test_chameleon_availability_evidence_resolver_port.version must be ${AVAILABILITY_EVIDENCE_RESOLVER_PORT_VERSION}`,
    );
  }
  if (input.test_only !== true) {
    throw new Error("Chameleon availability evidence resolver port factory is test-only");
  }
  if (input.verification_model !== AVAILABILITY_EVIDENCE_VERIFICATION_MODEL) {
    throw new Error("Chameleon availability evidence resolver rejects weak verification models");
  }
  for (const name of ["resolve_evidence", "resolve_current_state"]) {
    if (typeof input[name] !== "function" || isProxy(input[name]) || isAsyncFunction(input[name])) {
      throw new Error(`Chameleon availability evidence resolver ${name} must be synchronous`);
    }
  }
  const port = deepFreeze({
    version: AVAILABILITY_EVIDENCE_RESOLVER_PORT_VERSION,
    port_id: assertOpaqueIdentity(
      input.port_id,
      "test_chameleon_availability_evidence_resolver_port.port_id",
    ),
    verification_model: AVAILABILITY_EVIDENCE_VERIFICATION_MODEL,
    production_ready: false,
    backend_assurance: TEST_AVAILABILITY_EVIDENCE_ASSURANCE,
  });
  TEST_AVAILABILITY_EVIDENCE_RESOLVER_PORTS.add(port);
  TEST_AVAILABILITY_EVIDENCE_RESOLVER_STATE.set(port, {
    resolve_evidence: input.resolve_evidence,
    resolve_current_state: input.resolve_current_state,
  });
  return port;
}

function assertTestAvailabilityEvidenceResolverPort(port) {
  if (!port || isProxy(port) || !Object.isFrozen(port)
      || !TEST_AVAILABILITY_EVIDENCE_RESOLVER_PORTS.has(port)
      || !TEST_AVAILABILITY_EVIDENCE_RESOLVER_STATE.has(port)) {
    throw new Error(
      "Chameleon availability evidence requires a branded synchronous resolver port",
    );
  }
  return port;
}

function callSynchronousAvailabilityResolver(callback, label, request) {
  const result = callback(request);
  if (isPromise(result)) {
    throw new Error(`${label} must be synchronous; async resolver ports are rejected`);
  }
  if (isProxy(result)) throw new Error(`${label} cannot return a proxy`);
  return result;
}

function resolveChameleonAvailabilityEvidence(
  resolverPort,
  input,
  label = "chameleon_availability_evidence_request",
) {
  if (arguments.length < 2 || arguments.length > 3) {
    throw new Error("availability evidence resolution accepts a resolver port and closed request");
  }
  const port = assertTestAvailabilityEvidenceResolverPort(resolverPort);
  const request = normalizeAvailabilityEvidenceRequest(input, label);
  const resolverState = TEST_AVAILABILITY_EVIDENCE_RESOLVER_STATE.get(port);
  const evidence = normalizeResolvedAvailabilityEvidence(
    callSynchronousAvailabilityResolver(
      resolverState.resolve_evidence,
      "Chameleon availability evidence resolver",
      request,
    ),
    request,
    "resolved_chameleon_availability_evidence",
  );
  const currentStateRequest = availabilityCurrentStateRequest(request, evidence);
  const currentState = normalizeAvailabilityCurrentState(
    callSynchronousAvailabilityResolver(
      resolverState.resolve_current_state,
      "Chameleon availability current-state resolver",
      currentStateRequest,
    ),
    request,
    evidence,
    "current_chameleon_availability_evidence_state",
  );
  const projection = deepFreeze({
    ...evidence,
    resolver_port_id: port.port_id,
    resolver_verification_model: port.verification_model,
    resolver_backend_assurance: TEST_AVAILABILITY_EVIDENCE_ASSURANCE,
    current_time: currentState.current_time,
    current_state_digest: currentState.current_state_digest,
    resolver_verified: true,
    production_ready: false,
    runtime_ready: false,
    execution_authority: false,
    readiness_blockers: ["production_availability_evidence_verifier_not_implemented"],
  });
  AVAILABILITY_EVIDENCE_PROJECTIONS.add(projection);
  return projection;
}

function resolveProductionShapedChameleonAvailabilityEvidence(
  backendPort,
  input,
  label = "production_chameleon_availability_evidence_resolution",
) {
  if (arguments.length < 2 || arguments.length > 3) {
    throw new Error(
      "production availability evidence resolution accepts a backend port and one closed signed resolution",
    );
  }
  assertClosedObject(input, label, [
    "version",
    "request",
    "signed_current_trust",
    "signed_evidence",
  ]);
  if (input.version !== CHAMELEON_AVAILABILITY_BACKEND_VERSION) {
    throw new Error(`${label}.version must be ${CHAMELEON_AVAILABILITY_BACKEND_VERSION}`);
  }
  const request = normalizeProductionAvailabilityEvidenceRequest(
    input.request,
    `${label}.request`,
  );
  const backendProjection = assertChameleonAvailabilityEvidenceBackendProjection(
    resolveChameleonAvailabilityEvidenceBackend(backendPort, {
      version: CHAMELEON_AVAILABILITY_BACKEND_VERSION,
      request,
      signed_current_trust: input.signed_current_trust,
      signed_evidence: input.signed_evidence,
    }),
  );
  for (const field of PRODUCTION_AVAILABILITY_EVIDENCE_REQUEST_FIELDS) {
    if (backendProjection[field] !== request[field]) {
      throw new Error(`${label} backend projection ${field} drifted`);
    }
  }
  const commonRequest = deepFreeze(Object.fromEntries(
    AVAILABILITY_EVIDENCE_REQUEST_FIELDS.map((field) => [field, request[field]]),
  ));
  const normalized = normalizeResolvedAvailabilityEvidence({
    ...commonRequest,
    evidence_owner_principal: backendProjection.evidence_owner_principal,
    evidence_artifact_digest: backendProjection.evidence_artifact_digest,
    evidence_trust_epoch: backendProjection.evidence_trust_epoch,
    observed_at: backendProjection.observed_at,
    expires_at: backendProjection.expires_at,
    revoked: false,
    reported_command_ids: backendProjection.reported_command_ids,
    assurance_claims: backendProjection.assurance_claims,
    dependency_proofs: backendProjection.dependency_proofs,
  }, commonRequest, `${label}.verified_evidence`);
  assertProductionAvailabilityDependencyProofsCurrent(
    normalized.dependency_proofs,
    backendProjection,
    `${label}.verified_evidence`,
  );
  const variantQualifications = normalizeAvailabilityVariantQualifications(
    backendProjection.variant_qualifications,
    request,
    `${label}.variant_qualifications`,
  );
  const currentStateDigest = hashJson({
    domain: "bob.chameleon.availability.production-current-state.v2",
    target_domain: request.target_domain,
    session_nucleus_hash: request.session_nucleus_hash,
    signed_evidence_digest: backendProjection.signed_evidence_digest,
    trust_statement_digest: backendProjection.trust_statement_digest,
    current_time: backendProjection.current_time,
    current_monotonic_ms: backendProjection.current_monotonic_ms,
    trusted_clock_mapping_digest: backendProjection.trusted_clock_mapping_digest,
    trusted_clock_durable_state_digest:
      backendProjection.trusted_clock_durable_state_digest,
    replay_receipt: backendProjection.replay_receipt,
  });
  const projection = deepFreeze({
    ...normalized,
    target_domain: request.target_domain,
    session_nucleus_hash: request.session_nucleus_hash,
    evidence_identity_digest: backendProjection.evidence_identity_digest,
    issuer_key_id: backendProjection.issuer_key_id,
    issuer_public_key_digest: backendProjection.issuer_public_key_digest,
    issuer_revocation_generation: backendProjection.issuer_revocation_generation,
    evidence_sequence: backendProjection.evidence_sequence,
    signed_evidence_digest: backendProjection.signed_evidence_digest,
    trust_statement_digest: backendProjection.trust_statement_digest,
    variant_qualifications: deepFreeze([...variantQualifications.values()]),
    resolver_port_id: backendProjection.backend_port_id,
    resolver_verification_model: backendProjection.backend_mode,
    resolver_backend_assurance: backendProjection.backend_assurance,
    current_time: backendProjection.current_time,
    current_state_digest: currentStateDigest,
    replay_receipt: backendProjection.replay_receipt,
    resolver_verified: true,
    independently_signed: true,
    atomic_durable_replay_claimed: true,
    production_ready: backendProjection.production_ready,
    runtime_ready: true,
    release_ready: false,
    hil_verified: false,
    execution_authority: false,
    readiness_blockers: backendProjection.readiness_blockers,
  });
  AVAILABILITY_EVIDENCE_PROJECTIONS.add(projection);
  return projection;
}

function normalizeAlternativeSelections(input, label) {
  assertDataArray(input, label, VARIANT_BY_KEY.size);
  const selections = new Map();
  for (let index = 0; index < input.length; index += 1) {
    const at = `${label}[${index}]`;
    const selection = assertClosedObject(
      input[index],
      at,
      ["capability_id", "variant_id", "group_index", "dependency_ref"],
    );
    if (typeof selection.capability_id !== "string"
        || !CAPABILITY_ID_PATTERN.test(selection.capability_id)) {
      throw new Error(`${at}.capability_id is invalid`);
    }
    if (typeof selection.variant_id !== "string"
        || !VARIANT_ID_PATTERN.test(selection.variant_id)) {
      throw new Error(`${at}.variant_id is invalid`);
    }
    if (!Number.isSafeInteger(selection.group_index) || selection.group_index < 0) {
      throw new Error(`${at}.group_index must be a non-negative safe integer`);
    }
    const variant = VARIANT_BY_KEY.get(`${selection.capability_id}/${selection.variant_id}`);
    if (!variant) throw new Error(`${at} names an unknown availability variant`);
    const group = variant.any_of[selection.group_index];
    if (!group) throw new Error(`${at}.group_index does not name an any-of group`);
    if (!group.includes(selection.dependency_ref)) {
      throw new Error(`${at}.dependency_ref is not an alternative in the selected group`);
    }
    const key = `${selection.capability_id}/${selection.variant_id}:${selection.group_index}`;
    if (selections.has(key)) throw new Error(`${label} selects an any-of group more than once`);
    selections.set(key, deepFreeze({
      capability_id: selection.capability_id,
      variant_id: selection.variant_id,
      group_index: selection.group_index,
      dependency_ref: selection.dependency_ref,
    }));
  }
  return selections;
}

function assuranceFailures(operationIds, actualClaims) {
  const failures = [];
  for (const operationId of operationIds) {
    const operation = OPERATION_BY_ID.get(operationId);
    const required = REVIEWED_DATA.assurance_profile_registry[
      operation.minimum_assurance_profile_id
    ];
    for (const axis of ASSURANCE_AXES) {
      const actual = actualClaims[axis];
      const satisfies = REVIEWED_DATA.assurance_satisfaction_registry[axis][actual];
      if (!satisfies.includes(required[axis])) {
        failures.push(`${operationId}:${axis}:${required[axis]}`);
      }
    }
  }
  return sorted(new Set(failures));
}

function resolveChameleonAvailability(input, label = "chameleon_availability_input") {
  if (arguments.length < 1 || arguments.length > 2) {
    throw new Error("availability resolution accepts only a closed verified projection input");
  }
  assertClosedObject(input, label, [
    "version",
    "provider_id",
    "evidence_projection",
    "alternative_selections",
  ]);
  if (input.version !== MANIFEST_VERSION) throw new Error(`${label}.version must be 1`);
  if (input.provider_id !== PROVIDER_ID) throw new Error(`${label}.provider_id drifted`);
  const evidence = input.evidence_projection;
  if (!evidence || isProxy(evidence) || !Object.isFrozen(evidence)
      || !AVAILABILITY_EVIDENCE_PROJECTIONS.has(evidence)) {
    throw new Error(`${label}.evidence_projection must be resolver-issued branded evidence`);
  }
  const reportedCommandIds = evidence.reported_command_ids;
  const reportedCommands = new Set(reportedCommandIds);
  const claims = evidence.assurance_claims;
  const dependencyProofs = new Map(
    evidence.dependency_proofs.map((proof) => [proof.dependency_ref, proof]),
  );
  const dependencyProofList = [...dependencyProofs.values()].sort(
    (left, right) => left.dependency_ref.localeCompare(right.dependency_ref),
  );
  const evidenceVariantQualifications = new Map(
    (evidence.variant_qualifications || []).map((qualification) => (
      [`${qualification.capability_id}/${qualification.variant_id}`, qualification]
    )),
  );
  const alternativeSelections = normalizeAlternativeSelections(
    input.alternative_selections,
    `${label}.alternative_selections`,
  );
  const alternativeSelectionList = [...alternativeSelections.values()].sort((left, right) => (
    left.capability_id.localeCompare(right.capability_id)
    || left.variant_id.localeCompare(right.variant_id)
    || left.group_index - right.group_index
  ));
  const reportedCommandIdsDigest = hashJson(reportedCommandIds);
  const assuranceClaimsDigest = hashJson(claims);
  const dependencyProofsDigest = hashJson(dependencyProofList);
  const alternativeSelectionsDigest = hashJson(alternativeSelectionList);
  const cache = new Map();
  const resolving = new Set();

  function resolveRef(ref) {
    if (ref.startsWith("command:")) {
      const commandId = Number(ref.slice(8));
      return reportedCommands.has(commandId) && COMPILED_COMMAND_IDS.has(commandId);
    }
    if (ref.startsWith("capability_variant:")) {
      return resolveVariant(ref.slice("capability_variant:".length)).requirements_satisfied;
    }
    return dependencyProofs.get(ref)?.verdict === "satisfied";
  }

  function dependencyBinding(ref) {
    if (ref.startsWith("command:")) {
      const commandId = Number(ref.slice(8));
      return deepFreeze({
        dependency_ref: ref,
        dependency_kind: "command",
        reported: reportedCommands.has(commandId),
        compiled: COMPILED_COMMAND_IDS.has(commandId),
        satisfied: resolveRef(ref),
      });
    }
    if (ref.startsWith("capability_variant:")) {
      const status = resolveVariant(ref.slice("capability_variant:".length));
      return deepFreeze({
        dependency_ref: ref,
        dependency_kind: "capability_variant",
        availability_variant_digest: status.availability_variant_digest,
        dependency_binding_digest: status.dependency_binding_digest,
        satisfied: status.requirements_satisfied,
      });
    }
    const proof = dependencyProofs.get(ref);
    return deepFreeze({
      dependency_ref: ref,
      dependency_kind: ref.split(":", 1)[0],
      provider_contract_digest: PROOF_CONTRACT_BY_REF.get(ref).contract_digest,
      proof_digest: proof?.proof_digest || null,
      owner_principal: proof?.owner_principal || null,
      artifact_digest: proof?.artifact_digest || null,
      trust_epoch: proof?.trust_epoch || null,
      verdict: proof?.verdict || null,
      satisfied: proof?.verdict === "satisfied",
    });
  }

  function resolveVariant(key) {
    if (cache.has(key)) return cache.get(key);
    const variant = VARIANT_BY_KEY.get(key);
    if (!variant) throw new Error(`reviewed availability formula names unknown variant ${key}`);
    if (resolving.has(key)) throw new Error(`reviewed availability formula cycle contains ${key}`);
    resolving.add(key);
    const allOfBindings = variant.all_of.map(dependencyBinding);
    const anyOfBindings = variant.any_of.map((group) => group.map(dependencyBinding));
    const missingAllOf = allOfBindings
      .filter((binding) => !binding.satisfied)
      .map((binding) => binding.dependency_ref);
    const selectedAlternatives = anyOfBindings.map((group, groupIndex) => {
      const selection = alternativeSelections.get(`${key}:${groupIndex}`);
      return selection?.dependency_ref || null;
    });
    const unsatisfiedAnyOf = anyOfBindings
      .filter((group, groupIndex) => {
        const selectedRef = selectedAlternatives[groupIndex];
        return selectedRef == null
          || !group.find((binding) => binding.dependency_ref === selectedRef)?.satisfied;
      })
      .map((group) => group.map((binding) => binding.dependency_ref));
    const dependencyBindings = deepFreeze({
      all_of: allOfBindings,
      any_of: anyOfBindings,
      selected_alternatives: selectedAlternatives,
    });
    const dependencyBindingDigest = hashJson(dependencyBindings);
    const failedAssurance = assuranceFailures(variant.normalized_operations, claims);
    const requirementsSatisfied = missingAllOf.length === 0
      && unsatisfiedAnyOf.length === 0
      && failedAssurance.length === 0;
    const row = CAPABILITY_ROW_BY_ID.get(variant.capability_id);
    const qualification = evidenceVariantQualifications.get(key) || null;
    const evidenceQualified = evidence.runtime_ready === true
      && qualification != null
      && qualification.availability_variant_digest === variant.availability_variant_digest
      && qualification.dependency_binding_digest === dependencyBindingDigest
      && qualification.reported_command_ids_digest === reportedCommandIdsDigest
      && qualification.assurance_claims_digest === assuranceClaimsDigest
      && qualification.dependency_proofs_digest === dependencyProofsDigest
      && qualification.alternative_selections_digest === alternativeSelectionsDigest;
    const runtimeAvailable = row.disposition !== "unsupported"
      && requirementsSatisfied
      && evidenceQualified;
    // A signed conformance projection may make a semantic variant useful to
    // diagnostics, but it must never cross the evaluator-callable boundary.
    // Keep this check local even though downstream execution also requires a
    // separately issued authority: availability is an exposure decision, not
    // merely a dependency report.
    const evaluatorCallable = runtimeAvailable
      && evidence.production_ready === true
      && EVALUATOR_DISPOSITIONS.has(row.disposition)
      && variant.normalized_operations.some(
        (operationId) => OPERATION_BY_ID.get(operationId)?.exposure === EVALUATOR_EXPOSURE,
      );
    const result = deepFreeze({
      version: MANIFEST_VERSION,
      provider_id: PROVIDER_ID,
      capability_id: variant.capability_id,
      variant_id: variant.variant_id,
      parameter_selector_id: variant.parameter_selector_id,
      availability_variant_digest: variant.availability_variant_digest,
      disposition: row.disposition,
      manifest_supported: row.disposition !== "unsupported",
      requirements_satisfied: requirementsSatisfied,
      evidence_qualified: evidenceQualified,
      availability_qualification_digest: qualification?.qualification_digest || null,
      production_ready: runtimeAvailable && evidence.production_ready === true,
      runtime_available: runtimeAvailable,
      evaluator_callable: evaluatorCallable,
      execution_authority: false,
      normalized_operations: variant.normalized_operations,
      technique_bindings: variant.technique_bindings,
      effect_profile_refs: variant.effect_profile_refs,
      dependency_binding_digest: dependencyBindingDigest,
      selected_alternatives: deepFreeze(selectedAlternatives),
      missing_all_of: sorted(missingAllOf),
      unsatisfied_any_of: deepFreeze(unsatisfiedAnyOf.map((group) => sorted(group))),
      assurance_failures: failedAssurance,
    });
    cache.set(key, result);
    resolving.delete(key);
    return result;
  }

  const variants = [...VARIANT_BY_KEY.keys()].sort().map(resolveVariant);
  const runtimeReady = variants.some((variant) => variant.runtime_available);
  const readinessBlockers = [...(evidence.readiness_blockers || [])];
  if (evidence.runtime_ready === true && !runtimeReady) {
    readinessBlockers.push("no_signed_variant_qualification_matches_current_dependencies");
  }
  const knownCommands = new Set(COMMAND_OWNER_BY_ID.keys());
  const projectionBasis = {
    version: MANIFEST_VERSION,
    provider_id: PROVIDER_ID,
    semantic_manifest_digest: CHAMELEON_SEMANTIC_MANIFEST.manifest_digest,
    source_profile_digest: CHAMELEON_V220_SOURCE_PROFILE.source_profile_digest,
    codec_profile_digest: CHAMELEON_V220_CODEC_PROFILE.codec_profile_digest,
    inventory_projection_digest: evidence.inventory_projection_digest,
    device_identity_digest: evidence.device_identity_digest,
    custody_id: evidence.custody_id,
    custody_projection_digest: evidence.custody_projection_digest,
    session_id: evidence.session_id,
    authority_id: evidence.authority_id,
    authority_epoch: evidence.authority_epoch,
    revocation_generation: evidence.revocation_generation,
    authority_resolution_digest: evidence.authority_resolution_digest,
    assurance_profile_registry_digest: evidence.assurance_profile_registry_digest,
    dependency_proof_registry_digest: evidence.dependency_proof_registry_digest,
    evidence_projection_digest: evidence.evidence_projection_digest,
    evidence_current_state_digest: evidence.current_state_digest,
    evidence_resolver_port_id: evidence.resolver_port_id,
    evidence_resolver_verification_model: evidence.resolver_verification_model,
    evidence_backend_assurance: evidence.resolver_backend_assurance,
    evidence_trust_epoch: evidence.evidence_trust_epoch,
    evidence_observed_at: evidence.observed_at,
    evidence_expires_at: evidence.expires_at,
    evidence_current_time: evidence.current_time,
    reported_command_ids_digest: reportedCommandIdsDigest,
    assurance_claims_digest: assuranceClaimsDigest,
    dependency_proofs_digest: dependencyProofsDigest,
    alternative_selections_digest: alternativeSelectionsDigest,
    unrecognized_reported_command_ids: reportedCommandIds.filter((id) => !knownCommands.has(id)),
    uncompiled_reported_command_ids: reportedCommandIds.filter(
      (id) => knownCommands.has(id) && !COMPILED_COMMAND_IDS.has(id),
    ),
    variants,
    production_ready: runtimeReady && evidence.production_ready === true,
    runtime_ready: runtimeReady,
    release_ready: false,
    hil_verified: false,
    readiness_blockers: sorted(new Set(readinessBlockers)),
    execution_authority: false,
  };
  const projection = deepFreeze({
    ...projectionBasis,
    availability_projection_digest: hashJson(projectionBasis),
  });
  AVAILABILITY_PROJECTIONS.add(projection);
  return projection;
}

function normalizeChameleonEvaluatorSelection(
  input,
  availabilityProjection,
  label = "chameleon_evaluator_selection",
) {
  if (arguments.length < 2 || arguments.length > 3) {
    throw new Error("evaluator selection accepts only a selector and resolver-issued availability");
  }
  if (!AVAILABILITY_PROJECTIONS.has(availabilityProjection)) {
    throw new Error(`${label} requires a resolver-issued availability projection`);
  }
  assertClosedObject(input, label, [
    "capability_id",
    "variant_id",
    "operation_id",
    "technique_id",
    "parameters",
  ]);
  if (typeof input.capability_id !== "string" || !CAPABILITY_ID_PATTERN.test(input.capability_id)) {
    throw new Error(`${label}.capability_id is invalid`);
  }
  if (typeof input.variant_id !== "string" || !VARIANT_ID_PATTERN.test(input.variant_id)) {
    throw new Error(`${label}.variant_id is invalid`);
  }
  if (typeof input.operation_id !== "string" || !OPERATION_ID_PATTERN.test(input.operation_id)) {
    throw new Error(`${label}.operation_id is invalid`);
  }
  if (input.technique_id !== null
      && (typeof input.technique_id !== "string"
        || !REVIEWED_DATA.technique_registry.includes(input.technique_id))) {
    throw new Error(`${label}.technique_id is not in the closed technique registry`);
  }
  const status = availabilityProjection.variants.find((entry) => (
    entry.capability_id === input.capability_id && entry.variant_id === input.variant_id
  ));
  if (!status) throw new Error(`${label} names an unknown availability variant`);
  if (!status.runtime_available) throw new Error(`${label} variant is not runtime available`);
  if (!status.production_ready || !status.evaluator_callable) {
    throw new Error(
      `${label} variant is not production-qualified evaluator-callable availability`,
    );
  }
  const operation = OPERATION_BY_ID.get(input.operation_id);
  if (!operation || !status.normalized_operations.includes(input.operation_id)) {
    throw new Error(`${label}.operation_id is not owned by the selected variant`);
  }
  if (operation.exposure !== EVALUATOR_EXPOSURE) {
    throw new Error(`${label}.operation_id is provider-private, operator-only, or unsupported`);
  }
  if (status.technique_bindings.length === 0) {
    if (input.technique_id !== null) {
      throw new Error(`${label}.technique_id must be null for an unbound semantic operation`);
    }
  } else if (!status.technique_bindings.includes(input.technique_id)) {
    throw new Error(`${label}.technique_id is not owned by the selected variant`);
  }
  assertClosedObject(input.parameters, `${label}.parameters`, ["parameter_selector_id"]);
  if (input.parameters.parameter_selector_id !== status.parameter_selector_id) {
    throw new Error(`${label}.parameters.parameter_selector_id drifted from the closed variant`);
  }
  const selectionBasis = {
    version: MANIFEST_VERSION,
    provider_id: PROVIDER_ID,
    availability_projection_digest: availabilityProjection.availability_projection_digest,
    semantic_manifest_digest: availabilityProjection.semantic_manifest_digest,
    capability_id: status.capability_id,
    variant_id: status.variant_id,
    availability_variant_digest: status.availability_variant_digest,
    operation_id: input.operation_id,
    operation_contract_digest: hashJson({ operation_id: input.operation_id, ...operation }),
    technique_id: input.technique_id,
    parameter_selector_id: status.parameter_selector_id,
    effect_profile_refs: status.effect_profile_refs,
    execution_authority: false,
  };
  return deepFreeze({
    ...selectionBasis,
    semantic_selection_digest: hashJson(selectionBasis),
  });
}

function dependencyProofContract(dependencyRef) {
  if (typeof dependencyRef !== "string") return null;
  return PROOF_CONTRACT_BY_REF.get(dependencyRef) || null;
}

function reviewedManifestSnapshot() {
  return REVIEWED_DATA;
}

module.exports = {
  CHAMELEON_AVAILABILITY_EVIDENCE_VERSION,
  CHAMELEON_AVAILABILITY_BACKEND_VERSION,
  CHAMELEON_BOOTSTRAP_SUBSET,
  CHAMELEON_SEMANTIC_DIGESTS,
  CHAMELEON_SEMANTIC_MANIFEST,
  CHAMELEON_V220_CODEC_PROFILE,
  CHAMELEON_V220_SOURCE_PROFILE,
  buildChameleonAvailabilityVariantQualification,
  createTestChameleonAvailabilityEvidenceResolverPort,
  dependencyProofContract,
  getChameleonAvailabilityVariant,
  getChameleonCapability,
  getChameleonCommandOwner,
  getChameleonCommandSourceProvenance,
  getChameleonOperation,
  normalizeChameleonEvaluatorSelection,
  resolveChameleonAvailability,
  resolveChameleonAvailabilityEvidence,
  resolveProductionShapedChameleonAvailabilityEvidence,
  reviewedManifestSnapshot,
};
