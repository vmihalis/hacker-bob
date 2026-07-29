"use strict";

// OD2 — well-known smart-contract library denylist for oss_repo_ref leads.
//
// Modeled on the surface-discovery family-deny tuple: a frozen set of
// canonical third-party stdlib repos whose org slug is recognized so the
// SC-address expander does NOT auto-run an evaluation against an audited,
// upstream-owned library. RANK != BOUND: the denylist gates only
// auto_run_eligible — every discovered github ref is still surfaced as an
// oss_repo_ref lead; nothing is silently dropped. Match is org-level and
// case-insensitive.
//
// Pure module: no I/O, clock, random, or env reads, and it does NOT require
// lead-promotion (which requires this) so there is no cycle.

// Canonical documentation list of lowercased "org/repo" strings. The
// denylist decision keys on the ORG slug derived from this list, so a new
// repo under an already-listed org (e.g. another OpenZeppelin package) is
// covered automatically; add a fresh org's repo here when extending coverage.
const STDLIB_REPO_REFS = Object.freeze([
  "openzeppelin/openzeppelin-contracts",
  "openzeppelin/openzeppelin-contracts-upgradeable",
  "transmissions11/solmate",
  "foundry-rs/forge-std",
  "uniswap/v2-core",
  "uniswap/v3-core",
  "uniswap/v3-periphery",
  "uniswap/solidity-lib",
  "rari-capital/solmate",
  "dapphub/ds-test",
  "smartcontractkit/chainlink",
]);

// Frozen set of lowercased org slugs derived from STDLIB_REPO_REFS. An input
// ref whose parsed org is in this set is a stdlib/library ref.
const DENYLISTED_ORGS = Object.freeze(
  new Set(STDLIB_REPO_REFS.map((ref) => ref.split("/")[0])),
);

// repoRefOrg(ref): parse the org slug out of a github ref in any of the
// accepted shapes — "org/repo", "github.com/org/repo",
// "https://github.com/org/repo", "git@github.com:org/repo",
// "www.github.com/org/repo" — returning the first non-empty path segment
// lowercased, or "" when none can be parsed.
function repoRefOrg(ref) {
  if (typeof ref !== "string") return "";
  let rest = ref.trim();
  if (!rest) return "";
  rest = rest.replace(/^https?:\/\//i, "");
  rest = rest.replace(/^git@/i, "");
  rest = rest.replace(/^www\.github\.com[:/]+/i, "");
  rest = rest.replace(/^github\.com[:/]+/i, "");
  const segments = rest.split(/[/:]/);
  for (const segment of segments) {
    const trimmed = segment.trim();
    if (trimmed) return trimmed.toLowerCase();
  }
  return "";
}

// isStdlibRepoRef(githubRefOrOrgRepo) -> boolean. Org-level, case-insensitive;
// non-string/empty input -> false.
function isStdlibRepoRef(githubRefOrOrgRepo) {
  return DENYLISTED_ORGS.has(repoRefOrg(githubRefOrOrgRepo));
}

module.exports = {
  isStdlibRepoRef,
  STDLIB_REPO_REFS,
  DENYLISTED_ORGS,
};
