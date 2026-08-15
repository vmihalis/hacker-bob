"use strict";

const { authStore } = require("../core/auth/auth.js");

module.exports = Object.freeze({
  name: "bob_auth_store",
  description:
    "Store an authentication profile by profile_name. Names such as attacker, victim, admin, and tenant_b are caller-defined auth profiles.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "profile_name": {
        "type": "string"
      },
      "cookies": {
        "type": "object",
        "additionalProperties": {
          "type": "string"
        }
      },
      "headers": {
        "type": "object",
        "additionalProperties": {
          "type": "string"
        }
      },
      "local_storage": {
        "type": "object",
        "additionalProperties": {
          "type": "string"
        }
      },
      "credentials": {
        "type": "object",
        "properties": {
          "email": {
            "type": "string"
          },
          "password": {
            "type": "string"
          }
        }
      }
    },
    "required": [
      "target_domain",
      "profile_name"
    ]
  },
  handler: authStore,
  // evaluator-web: an evaluator that captured a second principal's credential (browser
  // record->flush of a 201/JWT) can promote it into a named auth profile to run the id-bearing
  // cross-tenant differential in-wave, when the orchestrator SETUP victim step did not provision
  // one. Minimal-privilege: no network, no browser, no account creation; and the dispatcher seam
  // supplies no provenance (auth.js:198-220), so a promoted profile carries no synthetic stamp and
  // cannot clear the provenance-gated IDOR / mass-read producer arms. It also cannot poison a
  // concurrent worker: the namespace-clobber guard (persistAuthProfiles) refuses a dispatcher-path
  // overwrite of an orchestrator-provisioned "attacker"/"victim" (a profile carrying synthetic
  // provenance) with a STATE_CONFLICT — the evaluator must store the captured credential under a
  // NEW profile name instead.
  role_bundles: ["auth", "evaluator-web"],
  mutating: true,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: true,
  session_artifacts_written: ["auth.json"],
});
