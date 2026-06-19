"use strict";

// Curated offline CWE catalog. This module is the single source of truth for
// every CWE identifier Hacker Bob will accept on a finding and for the
// impact-class -> CWE mappings the reporter prompt renders. The prompt and the
// write-path validator both read from here so they cannot drift.
//
// Entries cover: every CWE referenced anywhere in prompts/, test/, and mcp/,
// the smart-contract family mappings, the OSS impact-class examples, and the
// common web classics (CSRF, SSRF, open redirect, IDOR, auth bypass, path
// traversal, command/SQL injection, XXE, deserialization, SSTI, info exposure).

const CWE_CATALOG = Object.freeze({
  "CWE-20": "Improper Input Validation",
  "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)",
  "CWE-77": "Improper Neutralization of Special Elements used in a Command (Command Injection)",
  "CWE-78": "Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)",
  "CWE-79": "Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)",
  "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)",
  "CWE-94": "Improper Control of Generation of Code (Code Injection)",
  "CWE-100": "Deprecated: Was catch-all for input validation issues",
  "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
  "CWE-120": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
  "CWE-125": "Out-of-bounds Read",
  "CWE-190": "Integer Overflow or Wraparound",
  "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
  "CWE-269": "Improper Privilege Management",
  "CWE-284": "Improper Access Control",
  "CWE-285": "Improper Authorization",
  "CWE-287": "Improper Authentication",
  "CWE-294": "Authentication Bypass by Capture-replay",
  "CWE-345": "Insufficient Verification of Data Authenticity",
  "CWE-352": "Cross-Site Request Forgery (CSRF)",
  "CWE-384": "Session Fixation",
  "CWE-400": "Uncontrolled Resource Consumption",
  "CWE-416": "Use After Free",
  "CWE-434": "Unrestricted Upload of File with Dangerous Type",
  "CWE-494": "Download of Code Without Integrity Check",
  "CWE-502": "Deserialization of Untrusted Data",
  "CWE-601": "URL Redirection to Untrusted Site (Open Redirect)",
  "CWE-611": "Improper Restriction of XML External Entity Reference (XXE)",
  "CWE-639": "Authorization Bypass Through User-Controlled Key (IDOR)",
  "CWE-664": "Improper Control of a Resource Through its Lifetime",
  "CWE-668": "Exposure of Resource to Wrong Sphere",
  "CWE-674": "Uncontrolled Recursion",
  "CWE-682": "Incorrect Calculation",
  "CWE-787": "Out-of-bounds Write",
  "CWE-798": "Use of Hard-coded Credentials",
  "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
  "CWE-835": "Loop with Unreachable Exit Condition (Infinite Loop)",
  "CWE-840": "Business Logic Errors",
  "CWE-841": "Improper Enforcement of Behavioral Workflow",
  "CWE-843": "Access of Resource Using Incompatible Type (Type Confusion)",
  "CWE-862": "Missing Authorization",
  "CWE-863": "Incorrect Authorization",
  "CWE-915": "Improperly Controlled Modification of Dynamically-Determined Object Attributes (Mass Assignment)",
  "CWE-918": "Server-Side Request Forgery (SSRF)",
  "CWE-1284": "Improper Validation of Specified Quantity in Input",
  "CWE-1336": "Improper Neutralization of Special Elements Used in a Template Engine (SSTI)",
});

// OSS impact-class examples rendered in the reporter's OSS branch. Each value
// lists the catalog CWE ids appropriate to that impact class.
const OSS_IMPACT_CLASS_CWE = Object.freeze({
  "memory out-of-bounds": Object.freeze(["CWE-125", "CWE-787"]),
  "use-after-free": Object.freeze(["CWE-416"]),
  "integer overflow": Object.freeze(["CWE-190"]),
  "improper access control / authz": Object.freeze(["CWE-284", "CWE-862", "CWE-863"]),
  "config secret exposure": Object.freeze(["CWE-200", "CWE-798"]),
  "command / path injection": Object.freeze(["CWE-77", "CWE-22"]),
});

// Smart-contract family -> CWE mapping. The keys are the finding vocabulary the
// evaluator/verifier emit; the reporter renders the title from these. The
// canonical CWE is the first id; an alternate is listed when a family has two
// defensible categories.
const SMART_CONTRACT_FAMILY_CWE = Object.freeze({
  reentrancy: Object.freeze(["CWE-841"]),
  reentrancy_via_cpi: Object.freeze(["CWE-841"]),
  discriminator_collision: Object.freeze(["CWE-841"]),
  "access-control bypass": Object.freeze(["CWE-284"]),
  owner_check_missing: Object.freeze(["CWE-284"]),
  pda_collision: Object.freeze(["CWE-284"]),
  upgrade_authority_compromise: Object.freeze(["CWE-284"]),
  package_upgrade_authority: Object.freeze(["CWE-284"]),
  resource_account_takeover: Object.freeze(["CWE-284"]),
  missing_signer: Object.freeze(["CWE-862"]),
  signer_capability_leak: Object.freeze(["CWE-862"]),
  signature_replay: Object.freeze(["CWE-294"]),
  nonce_reuse: Object.freeze(["CWE-294"]),
  init_replay: Object.freeze(["CWE-294"]),
  oracle_staleness: Object.freeze(["CWE-1284", "CWE-829"]),
  stale_read: Object.freeze(["CWE-1284", "CWE-829"]),
  clock_object_tampering: Object.freeze(["CWE-1284", "CWE-829"]),
  account_validation_gap: Object.freeze(["CWE-345"]),
  sysvar_tampering: Object.freeze(["CWE-345"]),
  token_account_substitution: Object.freeze(["CWE-345"]),
  object_creator_check_missing: Object.freeze(["CWE-345"]),
  coin_store_substitution: Object.freeze(["CWE-345"]),
  transfer_object_between_packages: Object.freeze(["CWE-345"]),
  cpi_privilege_escalation: Object.freeze(["CWE-863"]),
  capability_leakage: Object.freeze(["CWE-863"]),
  dynamic_field_unauthorized_remove: Object.freeze(["CWE-863"]),
  object_ownership_violation: Object.freeze(["CWE-863"]),
  execute_only_callable_internally: Object.freeze(["CWE-863"]),
  integer_overflow: Object.freeze(["CWE-682"]),
  realloc_drain: Object.freeze(["CWE-682"]),
  arithmetic_overflow_unchecked: Object.freeze(["CWE-682"]),
  integer_overflow_unchecked: Object.freeze(["CWE-682"]),
  cw20_allowance_overflow: Object.freeze(["CWE-682"]),
  donation: Object.freeze(["CWE-682"]),
  share_price_manipulation: Object.freeze(["CWE-682"]),
  input_validation: Object.freeze(["CWE-20"]),
  funds_validation_missing: Object.freeze(["CWE-20"]),
  non_payable_check_missing: Object.freeze(["CWE-20"]),
  generic_type_confusion: Object.freeze(["CWE-843"]),
  transfer_to_immutable: Object.freeze(["CWE-664"]),
  shared_object_consensus_bypass: Object.freeze(["CWE-664"]),
  key_drop_resource_theft: Object.freeze(["CWE-664"]),
  store_phantom_drop: Object.freeze(["CWE-664"]),
  transfer_to_invalid_recipient: Object.freeze(["CWE-664"]),
  key_rotation_replay: Object.freeze(["CWE-294"]),
  ibc_packet_replay: Object.freeze(["CWE-294"]),
  set_code_hash_unauthorized: Object.freeze(["CWE-284"]),
  delegate_call_misuse: Object.freeze(["CWE-284"]),
  migrate_msg_open: Object.freeze(["CWE-284"]),
  caller_spoof: Object.freeze(["CWE-345"]),
  transferred_value_misuse: Object.freeze(["CWE-345"]),
  reentrancy_cross_contract: Object.freeze(["CWE-841"]),
  submessage_reply_misuse: Object.freeze(["CWE-841"]),
  always_vs_success_reply_mismatch: Object.freeze(["CWE-841"]),
  selector_collision: Object.freeze(["CWE-668"]),
  storage_namespace_collision: Object.freeze(["CWE-668"]),
  storage_key_collision: Object.freeze(["CWE-668"]),
  storage_layout_mismatch: Object.freeze(["CWE-668"]),
  stargate_query_injection: Object.freeze(["CWE-77"]),
});

function canonicalizeCwe(id) {
  if (id == null) return null;
  if (typeof id === "number") {
    if (!Number.isInteger(id) || id < 0) return null;
    return `CWE-${id}`;
  }
  if (typeof id !== "string") return null;
  const trimmed = id.trim();
  if (!trimmed) return null;
  const match = /^(?:cwe[-_\s]?)?(\d+)$/i.exec(trimmed);
  if (!match) return null;
  return `CWE-${Number(match[1])}`;
}

function isKnownCwe(id) {
  const canonical = canonicalizeCwe(id);
  return canonical != null && Object.prototype.hasOwnProperty.call(CWE_CATALOG, canonical);
}

function assertValidCwe(id) {
  const canonical = canonicalizeCwe(id);
  if (canonical == null) {
    throw new Error(`cwe must be a CWE identifier like "CWE-79"; got ${JSON.stringify(id)}`);
  }
  if (!Object.prototype.hasOwnProperty.call(CWE_CATALOG, canonical)) {
    throw new Error(`cwe ${canonical} is not in the curated CWE catalog (mcp/lib/cwe-catalog.js); use a catalog id`);
  }
  return canonical;
}

function cweTitle(id) {
  const canonical = canonicalizeCwe(id);
  if (canonical == null) return null;
  return Object.prototype.hasOwnProperty.call(CWE_CATALOG, canonical) ? CWE_CATALOG[canonical] : null;
}

module.exports = {
  CWE_CATALOG,
  OSS_IMPACT_CLASS_CWE,
  SMART_CONTRACT_FAMILY_CWE,
  canonicalizeCwe,
  isKnownCwe,
  assertValidCwe,
  cweTitle,
};
