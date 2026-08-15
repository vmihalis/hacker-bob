"use strict";

function defineLazyExports(load, names) {
  for (const name of names) {
    Object.defineProperty(module.exports, name, {
      enumerable: true,
      get() {
        return load()[name];
      },
    });
  }
}

defineLazyExports(() => require("./public-intel.js"), [
  "assertAllowedPublicIntelUrl",
  "bountyPublicIntel",
  "buildCveScopeMatches",
  "compactPolicyText",
  "extractStructuredScopes",
  "fetchTextWithTimeout",
  "normalizeProgramHandle",
  "parseHacktivityReportsFromHtml",
  "parseHacktivityReportsFromJson",
  "pickProgramStats",
  "readPublicIntelDocument",
  "readResponseTextCapped",
  "summarizePublicIntelForSurface",
]);

defineLazyExports(() => require("./public-intel-limits.js"), [
  "PUBLIC_INTEL_MAX_ITEMS",
  "PUBLIC_INTEL_MAX_RESPONSE_BYTES",
]);
