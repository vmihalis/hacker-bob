"use strict";

// Pure target-token intake classifier — no fs/network/clock/process-env I/O.
//
// `classifyTargetToken` maps a single operator-supplied target token onto a
// bounded axis ("web_url" or "contract") or an explicit refusal. It mirrors
// the fail-closed posture of `assertTargetClass` (target-classes.js): a
// caller-contract violation (non-string/empty) throws, while a well-formed
// but unrecognized string is refused by NAME — never silently dropped
// (rank, do not bound: every token is accounted for in the output).
//
// `classifyTargets` lifts that single-token classifier to a batch of tokens
// with a TOTAL multi-axis precedence order: web_url > repo > contract. It
// returns exactly one `primary` (the first token of the highest-precedence
// axis present) and a `companions` object whose `contracts`/`repos`/`urls`
// arrays are ALWAYS present (empty when none) and hold every remaining token —
// including same-axis siblings. No axis is inferred from another; mixed
// programs keep their companions explicit (O-P6 generalization).
//
// Remote VCS forms (git@…, git+https/ssh, ssh://, bare owner/repo, …/.git)
// are REFUSED here by name (O-P1, local-repo first): this module never
// implies or performs a clone. An https(s) URL is a web target even when it
// carries a `.git` suffix — web precedence wins, so it is not a remote here.
//
// RANK != BOUND is fail-closed at the batch level: if ANY token is a remote
// form or otherwise unrecognized, `classifyTargets` refuses the WHOLE batch
// and names every offending token in `reasons[]` — it never partially
// proceeds or silently drops a token. Caller-contract violations (non-array,
// empty array, or any non-string/empty element) THROW, mirroring
// `assertTargetClass`.
//
// Purity is preserved: repo detection is SHAPE-only (a leading "/", "~", or
// "./"). Absoluteness and directory existence are NOT checked here — that
// O-P1 enforcement is deferred downstream to `assertRepoRootPath`
// (governance-contracts.js) at the init handlers.
//
// The chain-family vocabulary is single-sourced from constants.js; this
// module imports `CHAIN_FAMILY_VALUES` and never redefines it. The
// CAIP-10 namespace map is frozen and asserted at load time to be a subset
// of that vocabulary so it can never drift from the canonical family list.
// Contract classification flows ONLY through `classifyTargetToken` /
// `CHAIN_FAMILY_VALUES` / `CAIP_NAMESPACE_TO_CHAIN_FAMILY` — no second copy.
//
// `parseRpcFlag` parses the VALUE of a `--rpc` flag ("family:chainId=url")
// into {chain_family, chain_id, url}. It reuses the same `CHAIN_FAMILY_VALUES`
// family validation as `classifyTargetToken` (never re-copying the list) and
// validates the url SCHEME ONLY: any non-`https:` (or unparseable) url is
// refused by NAME. It does NOT validate the destination HOST — a `https:` url
// pointing at loopback (127.0.0.1), link-local cloud metadata (169.254.169.254),
// or an RFC1918 host parses and is returned. This is a scheme check, NOT an
// SSRF/egress gate. It is intentionally NOT wired into session/init here — that
// plumbing is deferred to a later wave — and any future caller that wires this
// into egress MUST additionally run the private-host/SSRF DNS preflight
// (sc-egress-policy.filterResolvedPublicRpcEndpoints) before dialing, exactly
// as the live SC RPC clients already do. It preserves the module's "no
// fs/network/clock/process-env I/O" purity contract (URL parsing is pure and
// side-effect-free).

const { CHAIN_FAMILY_VALUES } = require("../lib/constants.js");

const CAIP_NAMESPACE_TO_CHAIN_FAMILY = Object.freeze({
  eip155: "evm",
  solana: "svm",
  aptos: "aptos",
  sui: "sui",
  polkadot: "substrate",
  cosmos: "cosmwasm",
});

// Load-time fail-closed guard: every mapped chain_family must exist in the
// canonical vocabulary, so the CAIP map can never name an orphan family.
for (const family of Object.values(CAIP_NAMESPACE_TO_CHAIN_FAMILY)) {
  if (!CHAIN_FAMILY_VALUES.includes(family)) {
    throw new Error(
      `target-intake: CAIP_NAMESPACE_TO_CHAIN_FAMILY maps to "${family}", `
      + `which is not in CHAIN_FAMILY_VALUES (${CHAIN_FAMILY_VALUES.join(", ")})`,
    );
  }
}

function classifyTargetToken(token) {
  if (typeof token !== "string" || token.length === 0) {
    throw new Error(
      `classifyTargetToken: token must be a non-empty string; got ${typeof token}`,
    );
  }

  // Rule 1 — web URL. Checked first because URLs contain colons and would
  // otherwise be parsed as a namespace:reference:address triple.
  if (/^https?:\/\//i.test(token)) {
    return { axis: "web_url", value: token };
  }

  // Parse the colon form once. `address` keeps every segment past the
  // reference so Move/Sui module paths (0x1::coin::Coin) survive intact.
  const parts = token.split(":");
  const namespace = parts[0];
  const reference = parts[1];
  const address = parts.slice(2).join(":");

  if (parts.length >= 3 && namespace && reference && address) {
    // Rule 2 — CAIP-10 namespace. hasOwnProperty (not `in`) so prototype
    // keys like "toString" cannot masquerade as a known namespace.
    if (
      Object.prototype.hasOwnProperty.call(
        CAIP_NAMESPACE_TO_CHAIN_FAMILY,
        namespace,
      )
    ) {
      return {
        axis: "contract",
        chain_family: CAIP_NAMESPACE_TO_CHAIN_FAMILY[namespace],
        chain_id: reference,
        address,
      };
    }

    // Rule 3 — ergonomic family:chainId:address. The aptos/sui overlap with
    // the CAIP map is benign: rule 2 already returns the identical
    // chain_family, so precedence does not change the output.
    if (CHAIN_FAMILY_VALUES.includes(namespace)) {
      return {
        axis: "contract",
        chain_family: namespace,
        chain_id: reference,
        address,
      };
    }
  }

  // Rule 4 — refuse, naming the token so nothing is silently dropped.
  return { refuse: true, reason: "unrecognized_target_token: " + token };
}

// Pure parser for the VALUE of a `--rpc` flag of the form
// "family:chainId=url" → {chain_family, chain_id, url}. Mirrors
// classifyTargetToken's caller-contract / fail-closed-by-NAME posture:
//   - a malformed CALL (non-string/empty arg) THROWS (programming error);
//   - well-formed-but-rejected CONTENT returns {refuse:true, reason:<named>}.
// HTTPS-SCHEME-only: only `https:` urls are accepted; http/ws/wss/file/any
// other scheme and unparseable urls are refused (protocol gate mirrors
// sc-egress-policy.js isHttpsUrl, implemented INLINE to preserve this
// module's "no fs/network/clock/process-env I/O" + dependency-light posture).
// This validates the SCHEME, NOT the destination host: `https://127.0.0.1`,
// `https://169.254.169.254` (cloud metadata), and RFC1918 hosts all PASS here.
// It is therefore NOT an SSRF/egress gate. Any caller that wires this into
// egress MUST additionally run the private-host DNS preflight
// (sc-egress-policy.filterResolvedPublicRpcEndpoints) before dialing — as the
// live SC RPC clients do — this function must never be the sole egress gate.
// Family validation REUSES the imported CHAIN_FAMILY_VALUES (never re-copied).
function parseRpcFlag(arg) {
  if (typeof arg !== "string" || arg.length === 0) {
    throw new Error(
      `parseRpcFlag: arg must be a non-empty string; got ${typeof arg}`,
    );
  }

  // Split left/url on the FIRST "=" — urls legitimately contain "=" in query
  // strings, so only the first separator divides "family:chainId" from "url".
  const eq = arg.indexOf("=");
  if (eq === -1) {
    return { refuse: true, reason: "missing_rpc_url_separator: " + arg };
  }
  const left = arg.slice(0, eq);
  const url = arg.slice(eq + 1).trim();

  // Left side must be exactly "family:chainId" — two non-empty segments.
  const segments = left.split(":");
  if (segments.length !== 2 || !segments[0] || !segments[1]) {
    return { refuse: true, reason: "malformed_rpc_target: " + left };
  }
  const family = segments[0];
  const chain_id = segments[1];

  // Family validation reuses the imported CHAIN_FAMILY_VALUES (single-source),
  // identical to classifyTargetToken Rule 3 — the list is never re-copied.
  if (!CHAIN_FAMILY_VALUES.includes(family)) {
    return { refuse: true, reason: "unrecognized_chain_family: " + family };
  }

  // HTTPS-SCHEME gate only (NOT an egress/SSRF gate). Parse with the WHATWG URL
  // constructor and require the https: protocol; anything else (http/ws/wss/
  // file/unparseable) is refused by NAME. The destination HOST is deliberately
  // NOT checked here — private/loopback/link-local https hosts pass; the
  // private-host DNS preflight (filterResolvedPublicRpcEndpoints) is the egress
  // gate and remains the caller's responsibility before any dial.
  let parsed;
  try {
    parsed = new URL(url);
  } catch (_err) {
    return { refuse: true, reason: "invalid_rpc_url: " + url };
  }
  if (parsed.protocol !== "https:") {
    return { refuse: true, reason: "non_https_rpc_url: " + url };
  }

  return { chain_family: family, chain_id, url };
}

// Pure, SHAPE-only repo-axis classifier. A leading "/", "~", or "./" marks a
// local repo path. We deliberately do NOT touch the filesystem here: this
// module's contract is "no fs/network/clock/process-env I/O", so absoluteness
// and directory existence (O-P1) are enforced downstream by
// `assertRepoRootPath` (governance-contracts.js) at the init handlers. Returns
// the same shape even for non-existent paths (shape, not existence).
function classifyRepoShape(token) {
  if (typeof token === "string" && /^(\/|~|\.\/)/.test(token)) {
    return { axis: "repo", path: token };
  }
  return null;
}

// Pure O-P1 remote-form refusal: returns a distinct, NAMED reason string
// (citing O-P1 and including the offending token) for every remote VCS form,
// or null when the token is not a remote form. This module never implies or
// performs a clone — the local-repo-first invariant is enforced by refusing
// the remote shapes outright.
function remoteFormRefusalReason(token) {
  if (typeof token !== "string" || token.length === 0) {
    return null;
  }

  // An https(s) URL is a web target even when it carries a `.git` suffix:
  // web precedence wins, so it is never refused as a remote here.
  if (/^https?:\/\//i.test(token)) {
    return null;
  }

  if (/^git@/.test(token)) {
    return (
      "O-P1 remote_form_refused: scp/ssh git remote (git@host:owner/repo) is "
      + "not a local repo path; clone it locally first, then pass the path: "
      + token
    );
  }

  if (/^git\+/.test(token)) {
    return (
      "O-P1 remote_form_refused: git+ URL scheme (git+https/git+ssh) is a "
      + "remote, not a local repo path; clone it locally first, then pass the "
      + "path: " + token
    );
  }

  if (/^(?:ssh|git):\/\//i.test(token)) {
    return (
      "O-P1 remote_form_refused: VCS remote scheme (ssh://, git://) is not a "
      + "local repo path; clone it locally first, then pass the path: " + token
    );
  }

  if (/\.git$/.test(token)) {
    return (
      "O-P1 remote_form_refused: bare .git remote (owner/repo.git) is not a "
      + "local repo path; clone it locally first, then pass the path: " + token
    );
  }

  // A single-slash bare slug (owner/repo) is remote shorthand. classifyRepoShape
  // excludes leading "/", "~", "./" paths (e.g. "./x" matches this slug regex
  // but is a local path), and CAIP/Move colon-forms carry no plain slash, so
  // they are not caught here.
  if (/^[\w.-]+\/[\w.-]+$/.test(token) && !classifyRepoShape(token)) {
    return (
      "O-P1 remote_form_refused: bare owner/repo slug is remote shorthand, not "
      + "a local repo path; clone it locally first, then pass the path: "
      + token
    );
  }

  return null;
}

// Lift `classifyTargetToken` to a batch with a TOTAL precedence order
// (web_url > repo > contract), an explicit `companions` object, O-P1 remote
// refusal, and a RANK != BOUND name-every-token posture. Pure: no I/O.
function classifyTargets(tokens) {
  // Caller-contract guard mirrors classifyTargetToken / assertTargetClass:
  // a malformed CALL throws (programming error); well-formed-but-rejected
  // CONTENT returns a structured {refuse:true, reasons:[...]}.
  if (!Array.isArray(tokens) || tokens.length === 0) {
    throw new Error(
      "classifyTargets: tokens must be a non-empty array; got "
      + (Array.isArray(tokens) ? "empty array" : typeof tokens),
    );
  }
  for (const token of tokens) {
    if (typeof token !== "string" || token.length === 0) {
      throw new Error(
        "classifyTargets: every token must be a non-empty string; got "
        + (typeof token === "string" ? "empty string" : typeof token),
      );
    }
  }

  const urls = [];
  const repos = [];
  const contracts = [];
  const reasons = [];

  for (const token of tokens) {
    // a) Remote VCS forms are refused here (O-P1) before any axis match.
    const remoteReason = remoteFormRefusalReason(token);
    if (remoteReason) {
      reasons.push(remoteReason);
      continue;
    }

    // b) Local repo path — SHAPE only, via the shared shape classifier.
    const repo = classifyRepoShape(token);
    if (repo) {
      repos.push(repo);
      continue;
    }

    // c) Web / contract / unrecognized — single-sourced through
    // classifyTargetToken so the CAIP / CHAIN_FAMILY vocabulary is never
    // re-copied here.
    const classified = classifyTargetToken(token);
    if (classified.refuse) {
      reasons.push(classified.reason);
      continue;
    }
    if (classified.axis === "web_url") {
      urls.push(classified);
    } else if (classified.axis === "contract") {
      contracts.push(classified);
    } else {
      // Defensive: an unknown accepted axis must be named, not dropped
      // (RANK != BOUND).
      reasons.push("unrecognized_target_axis: " + token);
    }
  }

  // RANK != BOUND fail-closed: if ANY token was refused, refuse the WHOLE
  // batch and name every offending token — never partially proceed.
  if (reasons.length > 0) {
    return { refuse: true, reasons };
  }

  // Total precedence: web_url > repo > contract. The primary is the first
  // token of the highest-precedence axis present; every remaining token
  // (including same-axis siblings) becomes a companion keyed by its axis.
  let primary;
  let urlCompanions = urls;
  let repoCompanions = repos;
  let contractCompanions = contracts;

  if (urls.length > 0) {
    primary = urls[0];
    urlCompanions = urls.slice(1);
  } else if (repos.length > 0) {
    primary = repos[0];
    repoCompanions = repos.slice(1);
  } else {
    // tokens is non-empty and all were accepted, so contracts must be
    // non-empty here.
    primary = contracts[0];
    contractCompanions = contracts.slice(1);
  }

  return {
    primary,
    companions: {
      contracts: contractCompanions,
      repos: repoCompanions,
      urls: urlCompanions,
    },
  };
}

module.exports = {
  CAIP_NAMESPACE_TO_CHAIN_FAMILY,
  classifyTargetToken,
  classifyTargets,
  parseRpcFlag,
};
