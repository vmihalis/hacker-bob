"use strict";

// Shared CVSS v3.1 qualitative severity banding. Extracted into a tiny, pure,
// I/O-free module so the two surfaces that need the cut points — the
// domain-level CVE feed parser (cve-feed-parser.js) and the pure base-score
// derivation utility (cvss31.js) — both read the SAME numeric thresholds
// without either depending on the other. Previously cvss31.js imported
// classifyCvss from cve-feed-parser.js, which transitively pulled the
// feed-ingestion module into claim recording and report composition (wrong
// dependency direction). Both now import from here instead.
//
// Thresholds are the FIRST.org CVSS v3.1 qualitative rating scale. The bottom
// band is "informational" here; cvss31.severityBand relabels it to the spec's
// "none" for base-vector parity.
function classifyCvss(score) {
  if (typeof score !== "number" || Number.isNaN(score)) return "unknown";
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score > 0) return "low";
  return "informational";
}

module.exports = { classifyCvss };
