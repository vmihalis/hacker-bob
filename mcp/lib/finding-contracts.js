"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const {
  APTOS_NETWORK_VALUES,
  ATTACK_VECTOR_VALUES,
  CHAIN_FAMILY_VALUES,
  COSMWASM_NETWORK_VALUES,
  SEVERITY_VALUES,
  SUBSTRATE_NETWORK_VALUES,
  SUI_NETWORK_VALUES,
  SURFACE_TYPE_VALUES,
  SVM_CLUSTER_VALUES,
} = require("./constants.js");
const {
  assertBoolean,
  assertEnumValue,
  assertNonEmptyString,
  assertRequiredText,
  normalizeOptionalText,
  parseAgentId,
  parseFindingId,
  parseWaveId,
} = require("./validation.js");
const {
  capabilityPackForLegacyFinding,
} = require("./capability-packs.js");

function normalizeEndpointForDedupe(endpoint) {
  const raw = String(endpoint || "").trim();
  try {
    const parsed = new URL(raw);
    parsed.hash = "";
    parsed.hostname = parsed.hostname.toLowerCase();
    parsed.pathname = parsed.pathname.replace(/\/+$/, "") || "/";
    const queryKeys = Array.from(parsed.searchParams.keys()).sort();
    parsed.search = queryKeys.map((key) => `${encodeURIComponent(key)}=*`).join("&");
    return parsed.toString().toLowerCase();
  } catch {
    return raw
      .replace(/#.*$/, "")
      .replace(/\?.*$/, (query) => {
        const keys = query.slice(1).split("&").map((part) => part.split("=", 1)[0]).filter(Boolean).sort();
        return keys.length ? `?${keys.map((key) => `${key}=*`).join("&")}` : "";
      })
      .replace(/\/+$/, "")
      .toLowerCase();
  }
}

function normalizeTextForDedupe(value) {
  return String(value || "").trim().toLowerCase().replace(/\s+/g, " ");
}

function shortFingerprint(value) {
  return crypto.createHash("sha256").update(String(value || "")).digest("hex").slice(0, 16);
}

function normalizeSurfaceType(value) {
  if (value == null) return null;
  if (typeof value !== "string") {
    throw new Error("surface_type must be a string");
  }
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (!SURFACE_TYPE_VALUES.includes(trimmed)) {
    throw new Error(`surface_type must be one of: ${SURFACE_TYPE_VALUES.join(", ")}`);
  }
  return trimmed;
}

const REACHABILITY_ASSERTION_ATTACK_VECTOR_VALUES = Object.freeze(
  ATTACK_VECTOR_VALUES.filter((value) => value !== "unknown"),
);

function normalizeReachabilityAssertion(value, fieldName = "reachability_assertion") {
  if (value == null) return null;
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${fieldName} must be an object`);
  }
  const attackVector = assertEnumValue(
    value.attack_vector,
    REACHABILITY_ASSERTION_ATTACK_VECTOR_VALUES,
    `${fieldName}.attack_vector`,
  );
  const networkReachable = assertBoolean(value.network_reachable, `${fieldName}.network_reachable`);
  if (attackVector === "network" && networkReachable !== true) {
    throw new Error(`${fieldName}.network_reachable must be true when attack_vector is network`);
  }
  if (attackVector === "local" && networkReachable !== false) {
    throw new Error(`${fieldName}.network_reachable must be false when attack_vector is local`);
  }
  const callPath = normalizeReachabilityCallPath(value.call_path, `${fieldName}.call_path`);
  const justification = normalizeOptionalText(value.justification, `${fieldName}.justification`);
  const normalized = {
    attack_vector: attackVector,
    network_reachable: networkReachable,
    call_path: callPath,
  };
  if (justification) normalized.justification = justification;
  return normalized;
}

function normalizeReachabilityCallPath(value, fieldName) {
  const callPath = assertRequiredText(value, fieldName);
  if (/[\r\n]/.test(callPath)) {
    throw new Error(`${fieldName} must not contain line breaks`);
  }
  const segments = callPath.split("->").map((segment) => segment.trim());
  if (segments.some((segment) => !segment)) {
    throw new Error(`${fieldName} must not contain empty '->'-separated segments`);
  }
  if (segments.length < 3) {
    throw new Error(`${fieldName} must cite an entrypoint-to-sink path with at least two '->' hops`);
  }
  return segments.join(" -> ");
}

function findingSupportsReachabilityAssertion(finding) {
  return finding
    && typeof finding.capability_pack === "string"
    && finding.capability_pack === "oss_native_code";
}

function assertReachabilityAssertionScope(finding, fieldName = "reachability_assertion") {
  if (!findingSupportsReachabilityAssertion(finding)) {
    throw new Error(`${fieldName} is only allowed for oss_native_code findings`);
  }
}

const EVM_ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;
const SVM_PUBKEY_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const SVM_PUBKEY_BYTE_LENGTH = 32;
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Decode(input) {
  if (typeof input !== "string" || input.length === 0) return null;
  let zeros = 0;
  while (zeros < input.length && input[zeros] === "1") zeros += 1;
  let big = 0n;
  for (let i = zeros; i < input.length; i += 1) {
    const idx = BASE58_ALPHABET.indexOf(input[i]);
    if (idx < 0) return null;
    big = big * 58n + BigInt(idx);
  }
  const tail = [];
  while (big > 0n) {
    tail.unshift(Number(big & 0xFFn));
    big >>= 8n;
  }
  return Buffer.from([...new Array(zeros).fill(0), ...tail]);
}

const MOVE_ADDRESS_RE = /^0x[a-fA-F0-9]{1,64}$/;
const MOVE_ADDRESS_HEX_LENGTH = 64;

function normalizeMoveAddress(input) {
  if (typeof input !== "string" || !MOVE_ADDRESS_RE.test(input)) return null;
  const hexBody = input.slice(2).toLowerCase();
  if (hexBody.length === MOVE_ADDRESS_HEX_LENGTH) return `0x${hexBody}`;
  return `0x${hexBody.padStart(MOVE_ADDRESS_HEX_LENGTH, "0")}`;
}

const SS58_BASE58_RE = /^[1-9A-HJ-NP-Za-km-z]+$/;
const SS58_LENGTH_RANGE = { min: 45, max: 52 };
const SS58_BYTE_LENGTH_RANGE = { min: 33, max: 38 };

function normalizeSs58Address(input) {
  if (typeof input !== "string") return null;
  const trimmed = input.trim();
  if (trimmed.length < SS58_LENGTH_RANGE.min || trimmed.length > SS58_LENGTH_RANGE.max) return null;
  if (!SS58_BASE58_RE.test(trimmed)) return null;
  const decoded = base58Decode(trimmed);
  if (!decoded) return null;
  if (decoded.length < SS58_BYTE_LENGTH_RANGE.min || decoded.length > SS58_BYTE_LENGTH_RANGE.max) return null;
  return trimmed;
}

const BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function bech32Polymod(values) {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i += 1) {
      if ((top >> i) & 1) chk ^= BECH32_GENERATORS[i];
    }
  }
  return chk >>> 0;
}

function bech32HrpExpand(hrp) {
  const out = [];
  for (let i = 0; i < hrp.length; i += 1) out.push(hrp.charCodeAt(i) >> 5);
  out.push(0);
  for (let i = 0; i < hrp.length; i += 1) out.push(hrp.charCodeAt(i) & 31);
  return out;
}

function bech32Decode(input) {
  if (typeof input !== "string") return null;
  if (input.length < 8 || input.length > 90) return null;
  let hasUpper = false;
  let hasLower = false;
  for (let i = 0; i < input.length; i += 1) {
    const code = input.charCodeAt(i);
    if (code < 33 || code > 126) return null;
    if (code >= 97 && code <= 122) hasLower = true;
    if (code >= 65 && code <= 90) hasUpper = true;
  }
  if (hasUpper && hasLower) return null;
  const lower = input.toLowerCase();
  const idx = lower.lastIndexOf("1");
  if (idx < 1 || idx + 7 > lower.length) return null;
  const hrp = lower.slice(0, idx);
  for (let i = 0; i < hrp.length; i += 1) {
    const c = hrp.charCodeAt(i);
    if (c < 33 || c > 126) return null;
  }
  const data = [];
  for (let i = idx + 1; i < lower.length; i += 1) {
    const v = BECH32_ALPHABET.indexOf(lower[i]);
    if (v < 0) return null;
    data.push(v);
  }
  if (bech32Polymod([...bech32HrpExpand(hrp), ...data]) !== 1) return null;
  return { hrp, data: data.slice(0, data.length - 6) };
}

function normalizeBech32Address(input) {
  if (typeof input !== "string") return null;
  const trimmed = input.trim();
  const decoded = bech32Decode(trimmed);
  if (!decoded) return null;
  return trimmed.toLowerCase();
}

const SC_EVIDENCE_REQUIRED_FIELDS = ["chain_id", "contract_address", "harness_path", "match_test"];

function realpathHome() {
  try {
    return fs.realpathSync(os.homedir());
  } catch {
    return os.homedir();
  }
}

function realpathContainingPath(resolvedPath) {
  const missing = [];
  let current = resolvedPath;
  while (true) {
    try {
      const realCurrent = fs.realpathSync(current);
      return missing.length ? path.join(realCurrent, ...missing) : realCurrent;
    } catch (error) {
      if (!error || error.code !== "ENOENT") {
        throw new Error(`sc_evidence.harness_path could not be resolved: ${error.message || String(error)}`);
      }
      const parent = path.dirname(current);
      if (parent === current) {
        throw new Error(`sc_evidence.harness_path could not be resolved: ${error.message || String(error)}`);
      }
      missing.unshift(path.basename(current));
      current = parent;
    }
  }
}

function assertHarnessPathUnderHome(harnessPath) {
  const resolved = path.resolve(harnessPath);
  const realHome = realpathHome();
  const realResolved = realpathContainingPath(resolved);
  if (!(realResolved === realHome || realResolved.startsWith(realHome + path.sep))) {
    throw new Error(`sc_evidence.harness_path must live under the user home directory; received: ${realResolved}`);
  }
  return resolved;
}

function normalizeScEvidence(value) {
  if (value == null) return null;
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new Error("sc_evidence must be an object");
  }

  let chainFamily = "evm";
  if (value.chain_family != null) {
    if (typeof value.chain_family !== "string") {
      throw new Error("sc_evidence.chain_family must be a string");
    }
    const trimmed = value.chain_family.trim();
    if (trimmed) {
      if (!CHAIN_FAMILY_VALUES.includes(trimmed)) {
        throw new Error(`sc_evidence.chain_family must be one of: ${CHAIN_FAMILY_VALUES.join(", ")}`);
      }
      chainFamily = trimmed;
    }
  }

  for (const field of SC_EVIDENCE_REQUIRED_FIELDS) {
    if (value[field] == null) {
      throw new Error(`sc_evidence.${field} is required`);
    }
  }

  let chainId;
  if (chainFamily === "evm") {
    chainId = value.chain_id;
    if (!Number.isInteger(chainId) || chainId < 1 || chainId > Number.MAX_SAFE_INTEGER) {
      throw new Error("sc_evidence.chain_id must be a positive integer when chain_family='evm'");
    }
  } else if (chainFamily === "svm") {
    chainId = value.chain_id;
    if (typeof chainId !== "string" || !SVM_CLUSTER_VALUES.includes(chainId)) {
      throw new Error(`sc_evidence.chain_id must be one of: ${SVM_CLUSTER_VALUES.join(", ")} when chain_family='svm'`);
    }
  } else if (chainFamily === "aptos") {
    chainId = value.chain_id;
    if (typeof chainId !== "string" || !APTOS_NETWORK_VALUES.includes(chainId)) {
      throw new Error(`sc_evidence.chain_id must be one of: ${APTOS_NETWORK_VALUES.join(", ")} when chain_family='aptos'`);
    }
  } else if (chainFamily === "sui") {
    chainId = value.chain_id;
    if (typeof chainId !== "string" || !SUI_NETWORK_VALUES.includes(chainId)) {
      throw new Error(`sc_evidence.chain_id must be one of: ${SUI_NETWORK_VALUES.join(", ")} when chain_family='sui'`);
    }
  } else if (chainFamily === "substrate") {
    chainId = value.chain_id;
    if (typeof chainId !== "string" || !SUBSTRATE_NETWORK_VALUES.includes(chainId)) {
      throw new Error(`sc_evidence.chain_id must be one of: ${SUBSTRATE_NETWORK_VALUES.join(", ")} when chain_family='substrate'`);
    }
  } else {
    chainId = value.chain_id;
    if (typeof chainId !== "string" || !COSMWASM_NETWORK_VALUES.includes(chainId)) {
      throw new Error(`sc_evidence.chain_id must be one of: ${COSMWASM_NETWORK_VALUES.join(", ")} when chain_family='cosmwasm'`);
    }
  }

  const contractAddressRaw = String(value.contract_address);
  let contractAddress;
  if (chainFamily === "evm") {
    if (!EVM_ADDRESS_RE.test(contractAddressRaw)) {
      throw new Error("sc_evidence.contract_address must be a 0x-prefixed 40-hex EVM address when chain_family='evm'");
    }
    contractAddress = contractAddressRaw.toLowerCase();
  } else if (chainFamily === "svm") {
    if (!SVM_PUBKEY_RE.test(contractAddressRaw)) {
      throw new Error("sc_evidence.contract_address must be a base58 32-44 char Solana program id when chain_family='svm'");
    }
    const decoded = base58Decode(contractAddressRaw);
    if (!decoded || decoded.length !== SVM_PUBKEY_BYTE_LENGTH) {
      throw new Error(`sc_evidence.contract_address must base58-decode to exactly ${SVM_PUBKEY_BYTE_LENGTH} bytes when chain_family='svm'; received ${decoded ? decoded.length : "null"} bytes`);
    }
    contractAddress = contractAddressRaw;
  } else if (chainFamily === "aptos" || chainFamily === "sui") {
    const familyLabel = chainFamily;
    if (EVM_ADDRESS_RE.test(contractAddressRaw)) {
      throw new Error(`sc_evidence.contract_address looks like a canonical EVM address (0x + 40 hex) but chain_family='${familyLabel}'; if this is genuinely a Move address with 12 leading zero bytes, encode it canonically as 0x000...<40hex> (64 hex chars total)`);
    }
    const normalized = normalizeMoveAddress(contractAddressRaw);
    if (!normalized) {
      throw new Error(`sc_evidence.contract_address must be a 0x-prefixed hex address (1-64 hex chars) when chain_family='${familyLabel}'`);
    }
    contractAddress = normalized;
  } else if (chainFamily === "substrate") {
    const normalized = normalizeSs58Address(contractAddressRaw);
    if (!normalized) {
      throw new Error("sc_evidence.contract_address must be a valid SS58-encoded substrate address (base58, 45-52 chars, decoded length 33-38 bytes) when chain_family='substrate'");
    }
    contractAddress = normalized;
  } else {
    const normalized = normalizeBech32Address(contractAddressRaw);
    if (!normalized) {
      throw new Error("sc_evidence.contract_address must be a valid bech32-encoded CosmWasm address (e.g., osmo1..., juno1...) with a checksum that verifies when chain_family='cosmwasm'");
    }
    contractAddress = normalized;
  }

  const harnessPath = String(value.harness_path);
  if (!harnessPath.trim()) {
    throw new Error("sc_evidence.harness_path is required");
  }
  const resolved = assertHarnessPathUnderHome(harnessPath);

  const matchTest = String(value.match_test);
  if (matchTest.length < 1 || matchTest.length > 200) {
    throw new Error("sc_evidence.match_test must be 1..200 chars");
  }

  const normalized = {
    chain_family: chainFamily,
    chain_id: chainId,
    contract_address: contractAddress,
    harness_path: resolved,
    match_test: matchTest,
  };

  if (value.match_contract != null) {
    const matchContract = String(value.match_contract);
    if (matchContract.length < 1 || matchContract.length > 200) {
      throw new Error("sc_evidence.match_contract must be 1..200 chars when provided");
    }
    normalized.match_contract = matchContract;
  }

  if (value.fork_block != null) {
    const forkBlock = value.fork_block;
    if (!Number.isInteger(forkBlock) || forkBlock < 0 || forkBlock > Number.MAX_SAFE_INTEGER) {
      throw new Error("sc_evidence.fork_block must be a non-negative integer when provided");
    }
    normalized.fork_block = forkBlock;
  }

  if (value.function_signature != null) {
    const sig = String(value.function_signature);
    if (sig.length < 1 || sig.length > 200) {
      throw new Error("sc_evidence.function_signature must be 1..200 chars when provided");
    }
    normalized.function_signature = sig;
  }

  return normalized;
}

function computeFindingDedupeKey(record) {
  const endpoint = normalizeEndpointForDedupe(record.endpoint);
  const classification = normalizeTextForDedupe(record.title || record.cwe || record.severity);
  const authContext = normalizeTextForDedupe(record.auth_profile || "");
  const evidence = shortFingerprint(`${record.response_evidence || ""}\n${record.proof_of_concept || ""}`);
  return crypto.createHash("sha256")
    .update(JSON.stringify([endpoint, classification, authContext, evidence]))
    .digest("hex")
    .slice(0, 24);
}

function summarizeFindings(findings) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) {
    bySeverity[finding.severity] += 1;
  }
  return {
    total: findings.length,
    by_severity: bySeverity,
    has_high_or_critical: bySeverity.critical + bySeverity.high > 0,
  };
}

function normalizeFindingRecord(record, { expectedDomain = null, lineNumber = null } = {}) {
  if (record == null || typeof record !== "object" || Array.isArray(record)) {
    throw new Error(lineNumber == null
      ? "finding record must be an object"
      : `Malformed findings.jsonl at line ${lineNumber}: expected object`);
  }

  try {
    const finding = {
      id: parseFindingId(record.id, "id"),
      target_domain: assertNonEmptyString(record.target_domain, "target_domain"),
      title: assertRequiredText(record.title, "title"),
      severity: assertEnumValue(record.severity, SEVERITY_VALUES, "severity"),
      cwe: normalizeOptionalText(record.cwe, "cwe"),
      endpoint: assertRequiredText(record.endpoint, "endpoint"),
      file_path: normalizeOptionalText(record.file_path, "file_path"),
      symbol: normalizeOptionalText(record.symbol, "symbol"),
      manifest: normalizeOptionalText(record.manifest, "manifest"),
      affected_package: normalizeOptionalText(record.affected_package, "affected_package"),
      affected_version_range: normalizeOptionalText(record.affected_version_range, "affected_version_range"),
      repro_command: normalizeOptionalText(record.repro_command, "repro_command"),
      description: assertRequiredText(record.description, "description"),
      proof_of_concept: assertRequiredText(record.proof_of_concept, "proof_of_concept"),
      response_evidence: normalizeOptionalText(record.response_evidence, "response_evidence"),
      impact: normalizeOptionalText(record.impact, "impact"),
      validated: assertBoolean(record.validated, "validated"),
      wave: record.wave == null ? null : parseWaveId(record.wave),
      agent: record.agent == null ? null : parseAgentId(record.agent),
      surface_id: normalizeOptionalText(record.surface_id, "surface_id"),
      surface_type: normalizeSurfaceType(record.surface_type),
      capability_pack: normalizeOptionalText(record.capability_pack, "capability_pack"),
      evaluator_agent: normalizeOptionalText(record.evaluator_agent, "evaluator_agent"),
      brief_profile: normalizeOptionalText(record.brief_profile, "brief_profile"),
      sc_evidence: normalizeScEvidence(record.sc_evidence),
      auth_profile: normalizeOptionalText(record.auth_profile, "auth_profile"),
      dedupe_key: normalizeOptionalText(record.dedupe_key, "dedupe_key"),
    };
    const missingRouting = !finding.capability_pack || !finding.evaluator_agent || !finding.brief_profile;
    if (missingRouting) {
      const backfill = capabilityPackForLegacyFinding({
        surface_type: finding.surface_type,
        sc_evidence: finding.sc_evidence,
      });
      if (backfill) {
        if (!finding.capability_pack) finding.capability_pack = backfill.capability_pack;
        if (!finding.evaluator_agent) finding.evaluator_agent = backfill.evaluator_agent;
        if (!finding.brief_profile) finding.brief_profile = backfill.brief_profile;
      }
    }
    const reachabilityAssertion = normalizeReachabilityAssertion(record.reachability_assertion);
    if (reachabilityAssertion) {
      assertReachabilityAssertionScope(finding);
      finding.reachability_assertion = reachabilityAssertion;
    }
    if (finding.surface_type === "smart_contract" && !finding.sc_evidence) {
      throw new Error("smart-contract findings must include sc_evidence");
    }
    if (finding.surface_type !== "smart_contract" && finding.sc_evidence) {
      throw new Error("sc_evidence is only allowed on smart_contract findings");
    }
    if (!finding.dedupe_key) {
      finding.dedupe_key = computeFindingDedupeKey(record);
    }
    if (record.force_record === true) {
      finding.force_record = true;
    }

    if (expectedDomain != null && finding.target_domain !== expectedDomain) {
      throw new Error("target_domain mismatch");
    }

    return finding;
  } catch (error) {
    if (lineNumber == null) {
      throw error;
    }
    throw new Error(`Malformed findings.jsonl at line ${lineNumber}: ${error.message || String(error)}`);
  }
}

function renderFindingMarkdownEntry(finding) {
  const waveAgent = finding.wave || finding.agent
    ? `\n- **Wave/Agent:** ${finding.wave || "?"}/${finding.agent || "?"}`
    : "";
  const surfaceLabel = finding.surface_id
    ? `${finding.surface_id}${finding.surface_type ? ` (${finding.surface_type})` : ""}`
    : (finding.surface_type ? `(${finding.surface_type})` : "");
  const surface = surfaceLabel ? `\n- **Surface:** ${surfaceLabel}` : "";
  const routing = finding.capability_pack
    ? `\n- **Capability Pack:** ${finding.capability_pack}${finding.evaluator_agent ? ` (${finding.evaluator_agent})` : ""}`
    : "";
  const authProfile = finding.auth_profile ? `\n- **Auth Profile:** ${finding.auth_profile}` : "";
  const repoFields = [
    finding.file_path ? `\n- **File:** ${finding.file_path}` : "",
    finding.symbol ? `\n- **Symbol:** ${finding.symbol}` : "",
    finding.manifest ? `\n- **Manifest:** ${finding.manifest}` : "",
    finding.affected_package ? `\n- **Affected Package:** ${finding.affected_package}` : "",
    finding.affected_version_range ? `\n- **Affected Version Range:** ${finding.affected_version_range}` : "",
    finding.repro_command ? `\n- **Repro Command:** \`${finding.repro_command}\`` : "",
  ].join("");
  let scBlock = "";
  if (finding.sc_evidence) {
    const e = finding.sc_evidence;
    const family = e.chain_family || "evm";
    let idLabel; let addressLabel; let blockLabel;
    if (family === "svm") {
      idLabel = "cluster"; addressLabel = "program_id"; blockLabel = "fork_slot";
    } else if (family === "aptos") {
      idLabel = "network"; addressLabel = "module_address"; blockLabel = "fork_version";
    } else if (family === "sui") {
      idLabel = "network"; addressLabel = "package_id"; blockLabel = "fork_checkpoint";
    } else if (family === "substrate") {
      idLabel = "network"; addressLabel = "ss58_address"; blockLabel = "fork_block";
    } else if (family === "cosmwasm") {
      idLabel = "network"; addressLabel = "contract_address"; blockLabel = "fork_block";
    } else {
      idLabel = "chain_id"; addressLabel = "contract"; blockLabel = "fork_block";
    }
    const lines = [
      `\n- **SC Evidence:**`,
      `  - chain_family: ${family}`,
      `  - ${idLabel}: ${e.chain_id}`,
      `  - ${addressLabel}: ${e.contract_address}`,
      `  - harness: ${e.harness_path}`,
      `  - match_test: ${e.match_test}`,
    ];
    if (e.match_contract) lines.push(`  - match_contract: ${e.match_contract}`);
    if (e.fork_block != null) lines.push(`  - ${blockLabel}: ${e.fork_block}`);
    if (e.function_signature) lines.push(`  - function: ${e.function_signature}`);
    scBlock = lines.join("\n");
  }

  return [
    `## FINDING ${finding.id.slice(2)} (${finding.severity.toUpperCase()}): ${finding.title}`,
    `- **ID:** ${finding.id}`,
    `- **CWE:** ${finding.cwe || "N/A"}`,
    `- **Endpoint:** ${finding.endpoint}`,
    `- **Validated:** ${finding.validated ? "YES" : "NO"}`,
    `- **Description:** ${finding.description}`,
    `- **PoC:**`,
    "```",
    finding.proof_of_concept,
    "```",
    `- **Evidence:** ${finding.response_evidence || "See PoC"}`,
    `- **Impact:** ${finding.impact || "N/A"}`,
    waveAgent,
    surface,
    routing,
    authProfile,
    repoFields,
    scBlock,
    "---\n\n",
  ].join("\n");
}

module.exports = {
  computeFindingDedupeKey,
  normalizeBech32Address,
  normalizeFindingRecord,
  normalizeReachabilityAssertion,
  findingSupportsReachabilityAssertion,
  normalizeScEvidence,
  normalizeSs58Address,
  renderFindingMarkdownEntry,
  summarizeFindings,
};
