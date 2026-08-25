"use strict";

// Generative authorization-differential schema-family.
//
// The corpus ships ONE hardcoded mechanism template
// (OBJECT_AUTHORIZATION_MECHANISM_TEMPLATE in invariant-template-corpus.js).
// That template encodes a single authorization mechanism: a principal causing
// an effect on an object it should not reach by swapping an object selector or
// credential. Authorization bugs are a family, not a singleton: function-level
// access control, privilege escalation, IDOR variants, business-logic authz,
// and SSRF-as-authz are all the SAME differential shape with different
// bindings.
//
// This module lifts that singleton into a GENERATIVE family parameterized by
// four axes:
//
//   (principal x resource x policy-gate x effect)
//
// A binding of the four axes instantiates one authorization mechanism, emitted
// in the EXACT shape that loadMechanismTemplates() validates. The object-auth
// binding reproduces OBJECT_AUTHORIZATION_MECHANISM_TEMPLATE field-for-field,
// proving the abstraction is faithful (not lossy): the hardcoded template is
// just one point in the family's binding space.
//
// NON-FORGEABILITY: instantiating the family MINTS template DATA only. A minted
// template is advisory / tier-3 (claim_authority: false) and RESOLVES only via
// an EXECUTED differential — the same flip discipline as adjudicateDifferential
// in repro-replay-verifier.js: the authorization check must FIRE/hold for the
// legitimate principal and VIOLATE for the swapped principal, attributably, on
// the same resource. Every emitted template therefore carries a refuting
// negative control (the differential MUST flip; a non-discriminating control is
// refused downstream). Minting NEVER self-confirms.
//
// SCOPE: this is a STANDALONE module that PRODUCES template data and the family
// abstraction. It does NOT register into MECHANISM_TEMPLATES, does NOT feed the
// live loadMechanismTemplates loader, and does NOT relax any claim-recording
// gate. Wiring the family into the live corpus/loader is deferred.

const {
  loadMechanismTemplates,
} = require("./mechanism/index.js");

// Every minted template is advisory until an executed differential confirms it.
const CLAIM_AUTHORITY = false;
const TEMPLATE_TIER = 3;

// ---------------------------------------------------------------------------
// The four axes.
//
// An authorization mechanism is a binding of:
//   - principal:  WHO is making the request (the identity / actor whose
//                 authority is under test). The swap dimension: a second
//                 principal that should NOT be authorized.
//   - resource:   WHAT is acted upon (the object / function / endpoint / URL
//                 target). The thing the policy gate is supposed to protect.
//   - policy_gate: the check that is SUPPOSED to mediate (principal -> resource).
//                 The mechanism asserts this edge exists and is enforced.
//   - effect:     the observable OUTCOME the gate controls (read, write, state
//                 change, side-effect). The differential is measured here.
//
// A faithful instance must name, for its mechanism, the concrete entities that
// fill each axis plus the swap interventions and controls that exercise the
// gate. The differential predicate always asserts the two edges
// principal->policy_gate and policy_gate->effect.
// ---------------------------------------------------------------------------

const AXES = Object.freeze(["principal", "resource", "policy_gate", "effect"]);

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function nonEmptyStringArray(value) {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.every((item) => typeof item === "string" && item.trim().length > 0)
  );
}

// A binding is the per-mechanism filling of the four axes plus the
// differential scaffolding the loadMechanismTemplates shape requires.
function assertValidBinding(binding) {
  if (!isPlainObject(binding)) {
    throw new TypeError("binding must be an object");
  }
  if (typeof binding.id !== "string" || !binding.id.trim()) {
    throw new TypeError("binding.id must be a non-empty string");
  }
  if (typeof binding.mechanism_id !== "string" || !binding.mechanism_id.trim()) {
    throw new TypeError("binding.mechanism_id must be a non-empty CWE string");
  }
  if (typeof binding.name !== "string" || !binding.name.trim()) {
    throw new TypeError("binding.name must be a non-empty string");
  }
  if (typeof binding.description !== "string" || !binding.description.trim()) {
    throw new TypeError("binding.description must be a non-empty string");
  }
  if (!isPlainObject(binding.axes)) {
    throw new TypeError("binding.axes must be an object");
  }
  for (const axis of AXES) {
    const entity = binding.axes[axis];
    if (typeof entity !== "string" || !entity.trim()) {
      throw new TypeError(`binding.axes.${axis} must name a concrete entity`);
    }
  }
  // The swap intervention is what makes a mechanism a DIFFERENTIAL: a second
  // principal (or resource) substituted across an otherwise-fixed request.
  if (!nonEmptyStringArray(binding.interventions)) {
    throw new TypeError("binding.interventions must be a non-empty string array");
  }
  if (!nonEmptyStringArray(binding.positive_controls)) {
    throw new TypeError("binding.positive_controls must be a non-empty string array");
  }
  // The refuting arm. A confirm path with no negative control that MUST flip is
  // refused: a single legitimate-principal pass proves nothing.
  if (!nonEmptyStringArray(binding.negative_controls)) {
    throw new TypeError("binding.negative_controls must be a non-empty string array (the refuting arm)");
  }
  if (!nonEmptyStringArray(binding.confounders)) {
    throw new TypeError("binding.confounders must be a non-empty string array");
  }
  // required_entities defaults to the canonical authorization roles derived
  // from the four axes; a binding may override to a documented SUPERSET only.
  if (
    binding.required_entities !== undefined &&
    !nonEmptyStringArray(binding.required_entities)
  ) {
    throw new TypeError("binding.required_entities, when present, must be a non-empty string array");
  }
  if (
    binding.evidence_predicate !== undefined &&
    !isPlainObject(binding.evidence_predicate)
  ) {
    throw new TypeError("binding.evidence_predicate, when present, must be an object");
  }
  return binding;
}

// The canonical authorization roles a binding's axes resolve to. The object
// distinguishes credential (a binding may present a credential separate from
// the principal identity) from the bare principal; resource maps onto the
// protected "object" role. This list is what required_entities defaults to and
// it MUST match OBJECT_AUTHORIZATION_MECHANISM_TEMPLATE.required_entities for
// the object-auth binding so reproduction is field-for-field.
const CANONICAL_REQUIRED_ENTITIES = Object.freeze([
  "principal",
  "credential",
  "object",
  "policy_gate",
  "effect",
]);

// The differential predicate every authorization mechanism asserts: the gate
// edge from principal to policy_gate, and the effect edge from policy_gate to
// effect. The swap must FLIP the effect across these edges to confirm.
function deriveEvidencePredicate(binding) {
  if (binding.evidence_predicate !== undefined) {
    return Object.freeze({ ...binding.evidence_predicate });
  }
  return Object.freeze({
    kind: "differential_effect",
    required_edges: Object.freeze([
      "principal->policy_gate",
      "policy_gate->effect",
    ]),
    required_cwe: binding.mechanism_id,
  });
}

// Instantiate ONE template from a binding, in the loadMechanismTemplates shape.
// The returned object carries advisory tier/authority metadata; the
// loadMechanismTemplates-validated fields are a strict subset of it.
function instantiateTemplate(binding) {
  assertValidBinding(binding);
  const requiredEntities = binding.required_entities
    ? Object.freeze(binding.required_entities.slice())
    : CANONICAL_REQUIRED_ENTITIES;
  return Object.freeze({
    id: binding.id,
    mechanism_id: binding.mechanism_id,
    name: binding.name,
    description: binding.description,
    required_entities: requiredEntities,
    interventions: Object.freeze(binding.interventions.slice()),
    positive_controls: Object.freeze(binding.positive_controls.slice()),
    negative_controls: Object.freeze(binding.negative_controls.slice()),
    confounders: Object.freeze(binding.confounders.slice()),
    evidence_predicate: deriveEvidencePredicate(binding),
    // Advisory metadata. NOT part of the loadMechanismTemplates shape; the
    // loader ignores extra fields. A minted template never self-confirms.
    claim_authority: CLAIM_AUTHORITY,
    tier: TEMPLATE_TIER,
    axes: Object.freeze({ ...binding.axes }),
  });
}

// Project an instantiated template down to the exact field set
// loadMechanismTemplates validates, dropping advisory metadata.
function toCorpusRecord(template) {
  return {
    id: template.id,
    mechanism_id: template.mechanism_id,
    name: template.name,
    description: template.description,
    required_entities: template.required_entities.slice(),
    interventions: template.interventions.slice(),
    positive_controls: template.positive_controls.slice(),
    negative_controls: template.negative_controls.slice(),
    confounders: template.confounders.slice(),
    evidence_predicate: { ...template.evidence_predicate },
  };
}

// ---------------------------------------------------------------------------
// The family bindings.
//
// OBJECT_AUTH_BINDING reproduces OBJECT_AUTHORIZATION_MECHANISM_TEMPLATE
// field-for-field (the faithfulness witness). The remaining bindings are the
// other authorization mechanisms the same four axes generate.
// ---------------------------------------------------------------------------

// Faithfulness witness: object authorization (IDOR / direct object reference).
// principal=requesting user, resource=referenced object, gate=ownership check,
// effect=the action on that object. Reproduces the hardcoded template exactly.
const OBJECT_AUTH_BINDING = Object.freeze({
  id: "object_authorization",
  mechanism_id: "CWE-639",
  name: "Object authorization",
  description:
    "A principal can cause an effect on an object they should not be authorized to access by changing an object selector, credential, or equivalent request binding.",
  axes: Object.freeze({
    principal: "requesting_principal",
    resource: "referenced_object",
    policy_gate: "ownership_or_acl_check",
    effect: "action_on_object",
  }),
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
});

// Function-level access control: a privileged function reachable by an
// unprivileged principal. principal=caller role, resource=the function/route,
// gate=role/permission check, effect=the privileged action.
const FUNCTION_ACCESS_CONTROL_BINDING = Object.freeze({
  id: "function_access_control",
  mechanism_id: "CWE-862",
  name: "Function-level access control",
  description:
    "An unprivileged principal can invoke a privileged function or route by reaching it directly while the policy gate fails to enforce the required role or permission.",
  axes: Object.freeze({
    principal: "caller_role",
    resource: "privileged_function",
    policy_gate: "role_or_permission_check",
    effect: "privileged_action",
  }),
  interventions: Object.freeze([
    "unprivileged_principal_direct_invoke",
    "missing_credential_invoke",
    "guessed_hidden_route_invoke",
  ]),
  positive_controls: Object.freeze([
    "privileged_principal_allowed",
    "unprivileged_principal_denied",
  ]),
  negative_controls: Object.freeze([
    "public_function_check",
    "nonexistent_route_check",
    "expired_role_check",
  ]),
  confounders: Object.freeze([
    "client_side_only_gating",
    "role_inheritance",
    "default_deny_misconfig",
    "verb_tunneling",
    "response_reflection",
  ]),
});

// Privilege escalation: a principal grants itself authority it should not hold,
// then exercises it. principal=actor, resource=the authority/role grant,
// gate=grant authorization, effect=elevated action under the new authority.
const PRIVILEGE_ESCALATION_BINDING = Object.freeze({
  id: "privilege_escalation",
  mechanism_id: "CWE-269",
  name: "Privilege escalation",
  description:
    "A principal can elevate its own authority — by editing a role binding, claim, or grant the policy gate should reserve — and then cause an effect reserved for the higher privilege.",
  axes: Object.freeze({
    principal: "self_elevating_principal",
    resource: "role_or_grant_binding",
    policy_gate: "grant_authorization_check",
    effect: "elevated_action",
  }),
  interventions: Object.freeze([
    "self_assign_higher_role",
    "tamper_privilege_claim",
    "reuse_grant_across_principal",
  ]),
  positive_controls: Object.freeze([
    "authorized_granter_allowed",
    "self_elevation_denied",
  ]),
  negative_controls: Object.freeze([
    "no_op_self_role_check",
    "nonexistent_role_check",
    "revoked_grant_check",
  ]),
  confounders: Object.freeze([
    "role_inheritance",
    "transitive_grant",
    "default_admin_seed",
    "claim_caching",
    "eventual_consistency",
  ]),
});

// Business-logic authorization: a principal reaches a state-changing effect by
// sequencing legitimate steps out of order or skipping an authorizing step,
// where no single request is denied but the COMPOSITION violates the gate.
// principal=actor, resource=the workflow/state machine, gate=ordering/limit
// invariant, effect=the unauthorized state transition.
const BUSINESS_LOGIC_AUTHZ_BINDING = Object.freeze({
  id: "business_logic_authorization",
  mechanism_id: "CWE-840",
  name: "Business-logic authorization",
  description:
    "A principal can cause a state-changing effect they are not authorized to reach by sequencing otherwise-permitted steps out of order, skipping an authorizing step, or violating a quantity or ownership invariant the policy gate is supposed to enforce across the workflow.",
  axes: Object.freeze({
    principal: "workflow_actor",
    resource: "workflow_state_machine",
    policy_gate: "ordering_or_limit_invariant",
    effect: "unauthorized_state_transition",
  }),
  interventions: Object.freeze([
    "skip_authorizing_step",
    "replay_consumed_step",
    "exceed_quantity_or_ownership_limit",
  ]),
  positive_controls: Object.freeze([
    "in_order_authorized_actor_allowed",
    "out_of_order_actor_denied",
  ]),
  negative_controls: Object.freeze([
    "idempotent_step_check",
    "nonexistent_workflow_check",
    "already_finalized_state_check",
  ]),
  confounders: Object.freeze([
    "eventual_consistency",
    "retry_idempotency",
    "compensating_transaction",
    "cache_bleed",
    "race_window",
  ]),
});

// SSRF-as-authorization: the SERVER is the principal, and a user-supplied URL
// resource crosses a trust boundary the gate should mediate, letting the
// requester borrow the server's authority to reach an internal effect.
// principal=server identity, resource=user-controlled URL target, gate=egress
// allow-list, effect=internal request made under server authority.
const SSRF_AS_AUTHZ_BINDING = Object.freeze({
  id: "ssrf_as_authorization",
  mechanism_id: "CWE-918",
  name: "Server-side request forgery as authorization",
  description:
    "A principal can borrow the server's authority to cause an effect on an internal resource by supplying a URL or destination the egress policy gate should deny, turning the server into a confused deputy that reaches an otherwise-unauthorized internal target.",
  axes: Object.freeze({
    principal: "server_identity",
    resource: "user_controlled_url_target",
    policy_gate: "egress_allow_list",
    effect: "internal_request_under_server_authority",
  }),
  interventions: Object.freeze([
    "supply_internal_url_target",
    "redirect_to_internal_after_allowed",
    "encode_or_dns_rebind_target",
  ]),
  positive_controls: Object.freeze([
    "allowed_external_target_reached",
    "internal_target_denied",
  ]),
  negative_controls: Object.freeze([
    "public_target_check",
    "nonexistent_host_check",
    "blocked_scheme_check",
  ]),
  confounders: Object.freeze([
    "open_redirect_chain",
    "dns_rebinding",
    "response_reflection",
    "cache_bleed",
    "metadata_endpoint_quirk",
  ]),
});

const FAMILY_BINDINGS = Object.freeze([
  OBJECT_AUTH_BINDING,
  FUNCTION_ACCESS_CONTROL_BINDING,
  PRIVILEGE_ESCALATION_BINDING,
  BUSINESS_LOGIC_AUTHZ_BINDING,
  SSRF_AS_AUTHZ_BINDING,
]);

// Emit every family instance as an advisory template.
function instantiateFamily() {
  return Object.freeze(FAMILY_BINDINGS.map((binding) => instantiateTemplate(binding)));
}

// Project the whole family down to corpus records and run them through the
// REAL loadMechanismTemplates validator, proving every instance loads in the
// existing shape with zero warnings. This is the abstraction's load gate; it
// does NOT mutate the live corpus.
function validateFamilyAgainstLoader() {
  const records = instantiateFamily().map((template) => toCorpusRecord(template));
  return loadMechanismTemplates(records);
}

module.exports = {
  AXES,
  CANONICAL_REQUIRED_ENTITIES,
  CLAIM_AUTHORITY,
  TEMPLATE_TIER,
  FAMILY_BINDINGS,
  OBJECT_AUTH_BINDING,
  FUNCTION_ACCESS_CONTROL_BINDING,
  PRIVILEGE_ESCALATION_BINDING,
  BUSINESS_LOGIC_AUTHZ_BINDING,
  SSRF_AS_AUTHZ_BINDING,
  assertValidBinding,
  instantiateTemplate,
  instantiateFamily,
  toCorpusRecord,
  deriveEvidencePredicate,
  validateFamilyAgainstLoader,
};
