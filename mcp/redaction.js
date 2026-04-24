"use strict";

const SENSITIVE_QUERY_KEY_RE = /(?:^|[_-])(token|code|session|sid|password|passwd|secret|jwt|auth|authorization|key|api[_-]?key|credential|csrf|xsrf|access[_-]?token|refresh[_-]?token|id[_-]?token)(?:$|[_-])/i;
const REDACTED_VALUE = "REDACTED";

function isSensitiveQueryKey(key) {
  return SENSITIVE_QUERY_KEY_RE.test(String(key || ""));
}

function redactUrlSensitiveValues(urlValue) {
  if (urlValue == null) return urlValue;
  const original = String(urlValue);
  let parsed;
  try {
    parsed = new URL(original);
  } catch {
    return original;
  }

  let changed = false;
  if (parsed.username) {
    parsed.username = REDACTED_VALUE;
    changed = true;
  }
  if (parsed.password) {
    parsed.password = REDACTED_VALUE;
    changed = true;
  }
  if (parsed.hash) {
    parsed.hash = "";
    changed = true;
  }

  for (const key of Array.from(parsed.searchParams.keys())) {
    // Query values are frequently tokens, emails, object IDs, signed URL
    // fragments, or one-time auth codes even when the key looks harmless.
    parsed.searchParams.set(key, REDACTED_VALUE);
    changed = true;
  }

  return changed ? parsed.toString() : original;
}

module.exports = {
  REDACTED_VALUE,
  isSensitiveQueryKey,
  redactUrlSensitiveValues,
};
