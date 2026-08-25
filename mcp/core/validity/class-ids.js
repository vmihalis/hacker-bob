"use strict";

const CONTROL_VALIDITY_CLASS_OBJECT_AUTH = "object_authorization";

const OBJECT_AUTH_CLASS_ALIASES = Object.freeze(new Set([
  CONTROL_VALIDITY_CLASS_OBJECT_AUTH,
  "guard",
  "CWE-639",
]));

module.exports = {
  CONTROL_VALIDITY_CLASS_OBJECT_AUTH,
  OBJECT_AUTH_CLASS_ALIASES,
};
