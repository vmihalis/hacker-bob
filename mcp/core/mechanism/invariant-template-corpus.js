"use strict";

const {
  canonicalizeCwe,
  isKnownCwe,
} = require("../scoring/cwe-catalog.js");

// The tier a hardcoded corpus template carries: tier-2, confirmed, validated,
// trusted for reuse. The trust-gradient's tier-2 exemplar is object-auth. A
// registered candidate from the live registry is tier-3 advisory and stays
// distinguishable; promotion (mechanism-promotion-gate.js) is the only path to 2.
const CORPUS_TEMPLATE_TIER = 2;

const TEMPLATES = Object.freeze([
  Object.freeze({
    id: "INV-REENTRANCY-CALLBACK-001",
    vulnerability_class: "reentrancy",
    name: "External-call-then-state-update reentrancy",
    description: "Asserts that a withdraw-style function reverts when the recipient is a contract whose receive callback re-enters the same function before state updates apply.",
    parameter_slots: ["target_contract", "vulnerable_function", "withdraw_amount"],
    foundry_test_template: [
      "function testReentrancyDuringExternalCall() public {",
      "    Reenterer attacker = new Reenterer({TARGET_CONTRACT}(address(target)));",
      "    deal(address(target), 10 ether);",
      "    vm.prank(address(attacker));",
      "    target.{VULNERABLE_FUNCTION}({WITHDRAW_AMOUNT});",
      "    assertGt(address(attacker).balance, {WITHDRAW_AMOUNT});",
      "}",
    ].join("\n"),
  }),
  Object.freeze({
    id: "INV-ACCESS-CONTROL-EOA-001",
    vulnerability_class: "access_control",
    name: "Unauthorized EOA can call admin function",
    description: "Asserts that a privileged function reverts when called from a fresh EOA without the admin role.",
    parameter_slots: ["target_contract", "admin_function", "admin_role_check"],
    foundry_test_template: [
      "function testUnauthorizedCallerReverts() public {",
      "    address attacker = makeAddr(\"attacker\");",
      "    vm.expectRevert();",
      "    vm.prank(attacker);",
      "    {TARGET_CONTRACT}.{ADMIN_FUNCTION}();",
      "}",
    ].join("\n"),
  }),
  Object.freeze({
    id: "INV-ARITH-OVERFLOW-MAX-001",
    vulnerability_class: "arithmetic_overflow",
    name: "Edge-value arithmetic overflow",
    description: "Asserts that arithmetic on type(uint256).max-bordering inputs reverts (Solidity 0.8+) or returns the expected sentinel (older versions).",
    parameter_slots: ["target_contract", "vulnerable_function"],
    foundry_test_template: [
      "function testOverflowOnMaxInputReverts() public {",
      "    vm.expectRevert();",
      "    {TARGET_CONTRACT}.{VULNERABLE_FUNCTION}(type(uint256).max);",
      "}",
    ].join("\n"),
  }),
  Object.freeze({
    id: "INV-ORACLE-MANIPULATION-SPOT-001",
    vulnerability_class: "oracle_manipulation",
    name: "Spot-price oracle manipulation via flash deposit",
    description: "Asserts that a price-dependent action reverts when the oracle's spot price is moved within the same transaction by a flash-loan-funded swap.",
    parameter_slots: ["oracle_contract", "victim_function", "swap_pool"],
    foundry_test_template: [
      "function testSpotPriceManipulationReverts() public {",
      "    vm.startPrank(makeAddr(\"flashUser\"));",
      "    deal(address({SWAP_POOL}.token0()), msg.sender, 1_000_000e18);",
      "    {SWAP_POOL}.swap(1_000_000e18, 0, address(this), \"\");",
      "    vm.expectRevert();",
      "    {VICTIM_FUNCTION}();",
      "    vm.stopPrank();",
      "}",
    ].join("\n"),
  }),
  Object.freeze({
    id: "INV-UNCHECKED-CALL-RETURN-001",
    vulnerability_class: "unchecked_call",
    name: "Low-level call return value ignored",
    description: "Asserts that a low-level external call's return value is checked by causing the callee to revert and observing whether the caller propagates the failure.",
    parameter_slots: ["target_contract", "vulnerable_function", "callee_contract"],
    foundry_test_template: [
      "function testLowLevelCallReturnIsChecked() public {",
      "    vm.mockCall(address({CALLEE_CONTRACT}), abi.encodeWithSelector(bytes4(keccak256(\"anything()\"))), abi.encode(false));",
      "    vm.expectRevert();",
      "    {TARGET_CONTRACT}.{VULNERABLE_FUNCTION}();",
      "}",
    ].join("\n"),
  }),
  Object.freeze({
    id: "INV-SIGNATURE-REPLAY-001",
    vulnerability_class: "signature_validation",
    name: "Signature replay across chains or accounts",
    description: "Asserts that a signature accepted on one chain or by one account is rejected when replayed on another (no chain ID or nonce binding).",
    parameter_slots: ["target_contract", "vulnerable_function"],
    foundry_test_template: [
      "function testSignatureReplayRejected() public {",
      "    bytes memory sig = makeSig(/* domain */ 1, /* message */ \"x\");",
      "    {TARGET_CONTRACT}.{VULNERABLE_FUNCTION}(sig);",
      "    vm.expectRevert();",
      "    {TARGET_CONTRACT}.{VULNERABLE_FUNCTION}(sig);",
      "}",
    ].join("\n"),
  }),
  Object.freeze({
    id: "INV-DELEGATECALL-STORAGE-001",
    vulnerability_class: "delegatecall_storage",
    name: "Storage collision via delegatecall",
    description: "Asserts that a delegatecall'd implementation cannot rewrite the proxy's storage slot 0 (admin).",
    parameter_slots: ["proxy_contract", "implementation_contract"],
    foundry_test_template: [
      "function testStorageSlotZeroProtected() public {",
      "    address admin_before = address(uint160(uint256(vm.load(address({PROXY_CONTRACT}), bytes32(uint256(0))))));",
      "    {PROXY_CONTRACT}.delegateToImpl(abi.encodeWithSignature(\"writeSlotZero(bytes32)\", bytes32(uint256(uint160(makeAddr(\"hijack\"))))));",
      "    address admin_after = address(uint160(uint256(vm.load(address({PROXY_CONTRACT}), bytes32(uint256(0))))));",
      "    assertEq(admin_after, admin_before);",
      "}",
    ].join("\n"),
  }),
  // CROSS-STACK auth replay — the CONSUMING template. Its VIOLATE is CONTINGENT on the
  // web-captured artifact: the generated test reads bobConsumedArtifact() (the bytes the
  // stack-A web attack captured, delivered as BOB_CONSUMED_ARTIFACT) and feeds them into the
  // gated on-chain call as the AUTHORIZATION argument. The invariant is that the call
  // REVERTS — a privileged effect must not be reachable with an authorization payload minted
  // off-chain. The contract's OWN gate decides the outcome (the test never branches on the
  // artifact's presence, so it is not a tautology): with the artifact ABSENT (control,
  // empty env) the call passes an empty authorization and a correct gate reverts -> HELD;
  // with the well-formed-but-forged artifact PRESENT (positive) a vulnerable gate that trusts
  // an off-chain payload accepts it, the effect lands, the call does NOT revert -> VIOLATED.
  // The present->VIOLATE / absent->HOLD flip is provably contingent on consuming the bytes,
  // which is exactly the same-tree artifact-presence differential the cross-stack verifier
  // requires. Same bug family as INV-SIGNATURE-REPLAY-001, but the replayed material crosses
  // from the web stack to the EVM stack via the consumed artifact.
  Object.freeze({
    id: "INV-CROSS-STACK-AUTH-REPLAY-001",
    vulnerability_class: "signature_validation",
    name: "Web-captured authorization payload accepted on-chain",
    description: "Asserts that a privileged on-chain call REVERTS when invoked with an authorization payload (a forged identity / signed relayer message / session-bound token) captured off-chain by a web-stack attack and consumed as BOB_CONSUMED_ARTIFACT. The invariant HOLDS when the contract REJECTS the captured payload and is VIOLATED only when the gate ACCEPTS it (the call does not revert). SCOPE: this demonstrates an AUTH-ACCEPTANCE differential — the on-chain gate accepted an off-chain-captured payload as valid authorization — NOT that an arbitrary downstream privileged effect landed; the call's post-state impact is not asserted here, so severity must follow the demonstrated acceptance, not a claimed impact. The control arm runs artifact-absent (empty BOB_CONSUMED_ARTIFACT) over the SAME path with a benign empty authorization and the gate holds, so the flip is contingent on the web-captured bytes being CONSUMED, not on the tree.",
    // SEALED. This template does NOT run an agent-authored harness. The runner generates the WHOLE
    // Foundry project from these DATA slots via mcp/core/differential/sealed-cross-stack-harness.js — a
    // self-contained test with an INLINED Vm (no agent forge-std on the build path), a pinned setUp
    // binding the target by address, and a pinned foundry.toml — so an agent setUp cannot
    // vm.mockCall/vm.store the real target, nor a rigged forge-std subvert vm/expectRevert, to forge
    // the differential against the real bytecode. The slots are DATA the generator validates and
    // interpolates as LITERALS (an address, a function name, a victim type + literal value), never
    // Solidity names an agent harness would define. The pinned BOB_TARGET_BIND emission + the
    // trusted-ladder eth_getCode cross-check still run inside the sealed test (defense in depth).
    sealed: true,
    parameter_slots: ["target_address", "gated_function", "victim_type", "victim_value"],
    // A marker only — the sealed generator owns the actual source; fillSlots returns this unchanged
    // for a sealed template (no {SLOT} substitution, no agent text ever reaches a Solidity body).
    foundry_test_template: "// SEALED cross-stack template — runner-generated (sealed-cross-stack-harness.js)",
  }),
]);

const OBJECT_AUTHORIZATION_MECHANISM_TEMPLATE = Object.freeze({
  id: "object_authorization",
  mechanism_id: "CWE-639",
  name: "Object authorization",
  description: "A principal can cause an effect on an object they should not be authorized to access by changing an object selector, credential, or equivalent request binding.",
  required_entities: Object.freeze([
    "principal",
    "credential",
    "object",
    "policy_gate",
    "effect",
  ]),
  interventions: Object.freeze([
    "principal_fixed_object_swap",
    "credential_fixed_object_swap",
    "victim_auth_same_object",
  ]),
  positive_controls: Object.freeze([
    "attacker_owned_object_allowed",
    "victim_object_denied_or_different_effect",
  ]),
  negative_controls: Object.freeze([
    "public_object_check",
    "nonexistent_object_check",
    "stale_session_check",
  ]),
  confounders: Object.freeze([
    "public_object",
    "role_inheritance",
    "cache_bleed",
    "eventual_consistency",
    "response_reflection",
  ]),
  evidence_predicate: Object.freeze({
    kind: "differential_effect",
    required_edges: Object.freeze([
      "principal->policy_gate",
      "policy_gate->effect",
    ]),
    required_cwe: "CWE-639",
  }),
});

const MECHANISM_TEMPLATES = Object.freeze([
  OBJECT_AUTHORIZATION_MECHANISM_TEMPLATE,
]);

const TEMPLATES_BY_CLASS = (() => {
  const map = new Map();
  for (const template of TEMPLATES) {
    if (!map.has(template.vulnerability_class)) map.set(template.vulnerability_class, []);
    map.get(template.vulnerability_class).push(template);
  }
  return map;
})();

const SUPPORTED_CLASSES = Object.freeze(Array.from(TEMPLATES_BY_CLASS.keys()).sort());

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function stringArray(value, fieldName, warnings) {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.some((item) => typeof item !== "string" || !item.trim())
  ) {
    warnings.push(`${fieldName} must be a non-empty string array`);
    return null;
  }
  return Object.freeze(value.map((item) => item.trim()));
}

function normalizeMechanismTemplate(record) {
  const warnings = [];
  if (!isPlainObject(record)) {
    return { template: null, warnings: ["record must be an object"] };
  }
  const id = typeof record.id === "string" && record.id.trim() ? record.id.trim() : null;
  if (!id) warnings.push("id is required");
  // CWE membership is an ANNOTATION, not a drop-gate. The SHAPE floor stays: a
  // mechanism_id must canonicalize to a CWE-N identifier (so the template names
  // SOME mechanism class), but a canonicalized id that is not in the curated
  // catalog now LOADS — annotated cwe_in_catalog:false — instead of nullifying
  // the template. A free-form / novel mechanism class is admitted as tier-3
  // advisory rather than vanishing; the executed-proof floor still gates
  // confirmation downstream. Only a non-CWE-shaped id fails the shape check.
  const mechanismId = canonicalizeCwe(record.mechanism_id);
  if (!mechanismId) {
    warnings.push(`mechanism_id must canonicalize to a CWE identifier like "CWE-79"; got ${JSON.stringify(record.mechanism_id)}`);
  }
  const cweInCatalog = mechanismId ? isKnownCwe(mechanismId) : false;
  const requiredEntities = stringArray(record.required_entities, "required_entities", warnings);
  const interventions = stringArray(record.interventions, "interventions", warnings);
  const positiveControls = stringArray(record.positive_controls, "positive_controls", warnings);
  const negativeControls = stringArray(record.negative_controls, "negative_controls", warnings);
  const confounders = stringArray(record.confounders, "confounders", warnings);
  const evidencePredicate = isPlainObject(record.evidence_predicate)
    ? Object.freeze({ ...record.evidence_predicate })
    : null;
  if (!evidencePredicate) warnings.push("evidence_predicate must be an object");
  if (warnings.length > 0) {
    return { template: null, warnings };
  }
  // Preserve the trust-gradient markers. A record that declares its own
  // tier/candidate/claim_authority/source_tier (a registered tier-3 candidate)
  // keeps them; a record that does not (a hardcoded corpus template) defaults to
  // tier-2 / candidate:false (confirmed, trusted reuse). The merge that layers
  // the live registry over the corpus relies on these markers to keep a tier-3
  // candidate structurally distinguishable from a confirmed corpus template.
  const declaredTier = Number.isInteger(record.tier) ? record.tier : CORPUS_TEMPLATE_TIER;
  const isCandidate = record.candidate === true || declaredTier === 3;
  const claimAuthority = record.claim_authority === true && !isCandidate;
  const projected = {
    id,
    mechanism_id: mechanismId,
    name: typeof record.name === "string" && record.name.trim() ? record.name.trim() : id,
    description: typeof record.description === "string" ? record.description.trim() : "",
    required_entities: requiredEntities,
    interventions,
    positive_controls: positiveControls,
    negative_controls: negativeControls,
    confounders,
    evidence_predicate: evidencePredicate,
    // Annotation, not a gate: catalog membership rides along for routing.
    cwe_in_catalog: cweInCatalog,
    // Trust-gradient markers (distinguishability). A tier-3 candidate is advisory;
    // a tier-2 corpus template is confirmed.
    tier: isCandidate ? declaredTier : CORPUS_TEMPLATE_TIER,
    candidate: isCandidate,
    claim_authority: claimAuthority,
  };
  if (typeof record.source_tier === "string" && record.source_tier) {
    projected.source_tier = record.source_tier;
  }
  // The merely-believed marker (executed_proof:false) is preserved when present so
  // a reader cannot lose it by inspecting only the shape keys.
  if (isPlainObject(record.advisory_evidence)) {
    projected.advisory_evidence = Object.freeze({ ...record.advisory_evidence });
  }
  return {
    template: Object.freeze(projected),
    warnings: [],
  };
}

function loadMechanismTemplates(records) {
  const input = Array.isArray(records) ? records : [];
  const templates = [];
  const warnings = [];
  const seen = new Set();
  for (const [index, record] of input.entries()) {
    const normalized = normalizeMechanismTemplate(record);
    if (!normalized.template) {
      warnings.push({ index, warnings: normalized.warnings });
      continue;
    }
    if (seen.has(normalized.template.id)) {
      warnings.push({ index, warnings: [`duplicate mechanism template id: ${normalized.template.id}`] });
      continue;
    }
    seen.add(normalized.template.id);
    templates.push(normalized.template);
  }
  return {
    templates: Object.freeze(templates),
    warnings: Object.freeze(warnings),
  };
}

const LOADED_MECHANISM_TEMPLATES = loadMechanismTemplates(MECHANISM_TEMPLATES);
const MECHANISM_TEMPLATES_BY_ID = (() => {
  const map = new Map();
  for (const template of LOADED_MECHANISM_TEMPLATES.templates) {
    map.set(template.id, template);
  }
  return map;
})();

// Read the per-session live registry of tier-3 advisory candidates and run each
// through the loader (so a registered candidate is validated identically to a
// corpus template and carries its preserved tier markers). The frozen corpus is
// the static tier-2 base; the registry is the additive open-vocab tier-3 layer.
// A candidate id collision with a corpus id NEVER overwrites the confirmed corpus
// template — the corpus base wins, so opening the vocab cannot silently demote a
// confirmed template to advisory. The store I/O is lazy-required to avoid the
// store<->corpus require cycle and to keep this module's frozen base load-time-pure.
function loadRegisteredCandidates(targetDomain) {
  if (typeof targetDomain !== "string" || !targetDomain) return [];
  let raw = [];
  try {
    // eslint-disable-next-line global-require
    const { readMechanismCandidates } = require("./mechanism-candidate-store.js");
    raw = readMechanismCandidates(targetDomain) || [];
  } catch {
    return [];
  }
  if (raw.length === 0) return [];
  const loaded = loadMechanismTemplates(raw);
  return loaded.templates.filter((template) => !MECHANISM_TEMPLATES_BY_ID.has(template.id));
}

// The frozen corpus templates merged with the live per-session registry, keyed by
// id. Corpus templates (tier-2 confirmed) win on id collision; registered
// candidates (tier-3 advisory) layer over the top. When targetDomain is omitted
// this returns the frozen corpus base alone (back-compat).
function getMechanismTemplatesForDomain(targetDomain) {
  const byId = new Map(MECHANISM_TEMPLATES_BY_ID);
  for (const candidate of loadRegisteredCandidates(targetDomain)) {
    if (!byId.has(candidate.id)) byId.set(candidate.id, candidate);
  }
  return Array.from(byId.values());
}

// Resolve a template by id. With no targetDomain this reads the frozen corpus
// alone (back-compat: existing callers are unchanged). With a targetDomain it
// merges the live registry so a registered tier-3 candidate is visible WITH its
// tier marker — a consumer that grants trust reads tier and treats tier-3 as
// advisory-only, so a candidate is never read as confirmed.
function getMechanismTemplate(id, targetDomain) {
  if (typeof id !== "string") return null;
  const fromCorpus = MECHANISM_TEMPLATES_BY_ID.get(id) || null;
  if (fromCorpus) return fromCorpus;
  if (typeof targetDomain === "string" && targetDomain) {
    for (const candidate of loadRegisteredCandidates(targetDomain)) {
      if (candidate.id === id) return candidate;
    }
  }
  return null;
}

function getTemplatesForClass(vulnerabilityClass) {
  if (typeof vulnerabilityClass !== "string") return [];
  return (TEMPLATES_BY_CLASS.get(vulnerabilityClass) || []).slice();
}

// The cross-stack consuming template id. The consume-bind path (a cause_run_id
// injection that feeds a web-captured artifact into the generated test as the
// on-chain authorization argument) is reachable ONLY for this template, whose body
// is fixed corpus text that reads bobConsumedArtifact() and passes it as the auth
// argument. An arbitrary corpus template (whose body is fully agent-influenced via
// slots) may never bind a cause.
const CROSS_STACK_CONSUME_TEMPLATE_ID = "INV-CROSS-STACK-AUTH-REPLAY-001";

// fillSlots does RAW string substitution into a Solidity test body. Without a
// lexical floor a slot value can carry parentheses/braces/semicolons/whitespace and
// thereby inject arbitrary Solidity (closing the gated call early, then defining a
// tautological self-gate inside the generated test). The restricted grammar makes
// each slot a single TOKEN of one admissible lexical class, never a statement: by
// construction no `(` `)` `{` `}` `;` `,` whitespace newline quote can survive into
// the generated body. The class is keyed by the slot's ROLE; an unmapped slot
// defaults to the most restrictive useful class (a Solidity identifier) and must
// opt into hex/uint explicitly.
const SLOT_KIND_IDENTIFIER = "identifier";
const SLOT_KIND_HEX_ADDRESS = "hex_address";
const SLOT_KIND_NUMERIC = "numeric";

const SLOT_VALUE_GRAMMAR = Object.freeze({
  // A bare Solidity identifier: leading [A-Za-z_$], then [A-Za-z0-9_$], bounded
  // length. No `.` member path, no parentheses/commas/whitespace/braces/semicolons.
  [SLOT_KIND_IDENTIFIER]: /^[A-Za-z_$][A-Za-z0-9_$]{0,63}$/,
  // A 20-byte hex address literal.
  [SLOT_KIND_HEX_ADDRESS]: /^0x[0-9a-fA-F]{40}$/,
  // A Solidity numeric literal: a decimal/hex/scientific number (digits, underscores,
  // one decimal point, an `e`/`E` exponent, or a 0x-hex form) with an OPTIONAL single
  // unit suffix (wei/gwei/ether/seconds/minutes/hours/days/weeks) after one space. The
  // anchored class admits `1`, `1_000`, `1e18`, `0xff`, `1 ether` but forbids EVERY
  // injection character (no parentheses/braces/semicolons/commas/quotes/newline and no
  // second token), so a value can only ever be a numeric argument, never a statement.
  [SLOT_KIND_NUMERIC]: /^(0x[0-9a-fA-F]+|[0-9][0-9_]*(?:\.[0-9_]+)?(?:[eE][0-9]+)?)( (?:wei|gwei|ether|seconds|minutes|hours|days|weeks))?$/,
});

// The lexical class for each known slot. Identifier is the conservative default for
// any slot absent from this map (validateSlotValues falls back to it), so a new slot
// is a single identifier unless it explicitly opts into hex/uint here.
const SLOT_KIND_BY_NAME = Object.freeze({
  target_contract: SLOT_KIND_IDENTIFIER,
  vulnerable_function: SLOT_KIND_IDENTIFIER,
  admin_function: SLOT_KIND_IDENTIFIER,
  admin_role_check: SLOT_KIND_IDENTIFIER,
  gated_function: SLOT_KIND_IDENTIFIER,
  victim_object: SLOT_KIND_IDENTIFIER,
  oracle_contract: SLOT_KIND_IDENTIFIER,
  victim_function: SLOT_KIND_IDENTIFIER,
  swap_pool: SLOT_KIND_IDENTIFIER,
  callee_contract: SLOT_KIND_IDENTIFIER,
  proxy_contract: SLOT_KIND_IDENTIFIER,
  implementation_contract: SLOT_KIND_IDENTIFIER,
  withdraw_amount: SLOT_KIND_NUMERIC,
});

function slotKindFor(slotName) {
  return SLOT_KIND_BY_NAME[slotName] || SLOT_KIND_IDENTIFIER;
}

// Validate the supplied values for THIS template's declared slots against the restricted
// grammar for each slot's lexical class. A value for a slot NOT declared by this template
// is IGNORED (not a violation): the suggest API applies one shared slot_values object across
// every template in a class, so a sibling template's slot key legitimately rides along, and
// such a key never substitutes into THIS template's body (so it cannot inject here). The
// undeclared-key smuggling-into-run_hash concern is the RUNNER's (one chosen template), and
// is enforced separately there. Returns { ok, violations: [{ slot, kind, value }] }.
function validateSlotValues(template, values) {
  const violations = [];
  if (!isPlainObject(values)) return { ok: true, violations };
  for (const slot of Array.isArray(template.parameter_slots) ? template.parameter_slots : []) {
    if (!Object.prototype.hasOwnProperty.call(values, slot)) continue;
    const kind = slotKindFor(slot);
    const re = SLOT_VALUE_GRAMMAR[kind];
    if (!re.test(String(values[slot]))) {
      violations.push({ slot, kind, value: String(values[slot]) });
    }
  }
  return { ok: violations.length === 0, violations };
}

function fillSlots(template, values) {
  const body = template.foundry_test_template;
  // SEALED templates are never agent-substituted: the runner generates the whole project from DATA
  // slots via the sealed-cross-stack-harness generator (which validates them strictly), so there is
  // no {SLOT} substitution here and no agent text reaches a Solidity body. Return the marker as-is.
  if (template.sealed === true) return body;
  if (!isPlainObject(values)) return body;
  // Validate FIRST and throw on any violation — the corpus module is the single
  // substitution chokepoint, so validating here covers every caller (suggest-for-
  // finding, suggest-for-report, the runner). An injected value never substitutes.
  const { ok, violations } = validateSlotValues(template, values);
  if (!ok) {
    const detail = violations
      .map((v) => `${v.slot} (not a valid ${v.kind})`)
      .join(", ");
    throw new Error(
      `slot value(s) violate the restricted invariant-template grammar (identifiers/0x-addresses/decimal-uints only, no parentheses/braces/semicolons/whitespace): ${detail}`,
    );
  }
  let filled = body;
  for (const slot of template.parameter_slots) {
    const placeholder = `{${slot.toUpperCase()}}`;
    if (Object.prototype.hasOwnProperty.call(values, slot)) {
      const value = values[slot];
      filled = filled.split(placeholder).join(String(value));
    }
  }
  return filled;
}

function suggestInvariantsForFinding(finding, options) {
  if (!isPlainObject(finding)) {
    throw new TypeError("finding must be an object");
  }
  const vulnerabilityClass = typeof finding.vulnerability_class === "string"
    ? finding.vulnerability_class
    : "unknown";
  const templates = getTemplatesForClass(vulnerabilityClass);
  if (templates.length === 0) {
    return {
      vulnerability_class: vulnerabilityClass,
      template_count: 0,
      suggestions: [],
      missing_class: !SUPPORTED_CLASSES.includes(vulnerabilityClass),
    };
  }
  const limit = options && Number.isInteger(options.limit) && options.limit > 0
    ? Math.min(options.limit, 25)
    : templates.length;
  const slotValues = options && isPlainObject(options.slot_values) ? options.slot_values : null;
  const suggestions = templates.slice(0, limit).map((template) => ({
    template_id: template.id,
    name: template.name,
    description: template.description,
    parameter_slots: template.parameter_slots,
    unfilled_slots: slotValues
      ? template.parameter_slots.filter((slot) => !Object.prototype.hasOwnProperty.call(slotValues, slot))
      : template.parameter_slots.slice(),
    foundry_test: fillSlots(template, slotValues || {}),
  }));
  return {
    vulnerability_class: vulnerabilityClass,
    template_count: templates.length,
    suggestions,
    missing_class: false,
  };
}

function suggestInvariantsForReport(parsedReport, options) {
  if (!isPlainObject(parsedReport) || !Array.isArray(parsedReport.findings)) {
    throw new TypeError("parsedReport must be an object with findings array");
  }
  const slotValuesByClass = options && isPlainObject(options.slot_values_by_class)
    ? options.slot_values_by_class
    : {};
  const grouped = {};
  for (const finding of parsedReport.findings) {
    if (!isPlainObject(finding)) continue;
    const vulnerabilityClass = typeof finding.vulnerability_class === "string"
      ? finding.vulnerability_class
      : "unknown";
    const slotValues = slotValuesByClass[vulnerabilityClass] || null;
    const suggestion = suggestInvariantsForFinding(finding, {
      slot_values: slotValues,
      limit: options && options.per_finding_limit,
    });
    if (!grouped[vulnerabilityClass]) grouped[vulnerabilityClass] = { count: 0, suggestions: [] };
    grouped[vulnerabilityClass].count += 1;
    grouped[vulnerabilityClass].suggestions.push({
      finding_index: finding.finding_index,
      finding_title: finding.title,
      finding_hash: finding.finding_hash,
      ...suggestion,
    });
  }
  return {
    total_templates: TEMPLATES.length,
    supported_classes: SUPPORTED_CLASSES,
    by_class: grouped,
  };
}

module.exports = {
  MECHANISM_TEMPLATES,
  OBJECT_AUTHORIZATION_MECHANISM_TEMPLATE,
  TEMPLATES,
  SUPPORTED_CLASSES,
  CORPUS_TEMPLATE_TIER,
  CROSS_STACK_CONSUME_TEMPLATE_ID,
  SLOT_VALUE_GRAMMAR,
  validateSlotValues,
  getTemplatesForClass,
  getMechanismTemplate,
  getMechanismTemplatesForDomain,
  loadMechanismTemplates,
  normalizeMechanismTemplate,
  suggestInvariantsForFinding,
  suggestInvariantsForReport,
};
