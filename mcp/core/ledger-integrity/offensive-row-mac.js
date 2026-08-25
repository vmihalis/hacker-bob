"use strict";

const crypto = require("crypto");
const {
  canonicalJson,
} = require("../verification/verification-contracts.js");
const {
  ERROR_CODES,
  ToolError,
} = require("../io/envelope.js");

// Distinct from HANDOFF_PROVENANCE_SIGNATURE_CONTEXT (wave-handoff-contracts.js) so a
// wave-handoff signature can never be replayed as an offensive row signature even though
// both reuse the same per-session signing material.
// The context label retains its original "row-hmac:v1" token as the FROZEN WIRE VALUE:
// it now domain-separates the ed25519 v2 signature (it is the preimage context in
// signRowWithMac's ed25519 branch), NOT just the legacy v1 HMAC. Do NOT change the
// string or every existing offensive-runs.jsonl ed25519 signature breaks (the literal
// is hashed into the signed preimage). The "v1" in the token is a stale-sounding but
// load-bearing wire constant, not a version of the current scheme.
const OFFENSIVE_ROW_MAC_CONTEXT = "hacker-bob:offensive-run:row-hmac:v1";
const OFFENSIVE_ROW_MAC_ALGORITHM = "hmac-sha256";
const OFFENSIVE_ROW_MAC_VERSION = 1;
// The scheme-tagged envelope version. version 1 carries {algorithm:"hmac-sha256",
// digest}; version 2 carries {scheme, digest|signature}. Both bind the SAME
// context+payload bytes, so a v1 row recomputes byte-identically to before the
// split — old offensive-runs.jsonl rows keep verifying with no re-sign.
const OFFENSIVE_ROW_MAC_VERSION_V2 = 2;
const MAC_SCHEME_HMAC = "hmac-sha256";
const MAC_SCHEME_ED25519 = "ed25519";

// The default envelope field. Cycle B keys three additional verdict-backing ledgers
// that each carry their MAC under a DIFFERENT field name (a JSONL row keys row_mac;
// claim-freeze.json keys freeze_mac). The same envelope + preimage + dispatch is
// reused per Cycle B's "reuse signRowWithMac, do not invent a new MAC" discipline —
// only the carrier field name varies, selected by the optional macField option.
const DEFAULT_MAC_FIELD = "row_mac";

// Domain-separation context strings for the four keyed verdict ledgers. Each ledger
// binds its OWN context into the signed preimage (context + "\n" + canonical(row minus
// the mac field)), so a row minted for one ledger cannot be replayed as a row for
// another even when both reuse the same per-session signing key. OFFENSIVE_ROW_MAC_
// CONTEXT (above) is offensive-runs.jsonl; the three below join it in Cycle B.
const INVARIANT_RUN_MAC_CONTEXT = "bob.invariant-run.v1";
const REPO_COMMAND_RUN_MAC_CONTEXT = "bob.repo-command-run.v1";
const CLAIM_FREEZE_MAC_CONTEXT = "bob.claim-freeze.v1";
// The auth-differential sweep ledger (auth-differential-results.json per_endpoint rows).
// Joins the Cycle B family: it binds its OWN domain-separation context into the signed
// preimage so a cross-tenant-flip row minted for the sweep ledger cannot be replayed as a
// row for another ledger even though all reuse the same per-session ed25519 key. Reuses
// signRowWithMac/verifyRowWithMac/assertRowMac verbatim — NOT a new MAC scheme.
const AUTH_DIFFERENTIAL_ROW_MAC_CONTEXT = "bob.auth-differential-row.v1";

// Sign over the WHOLE row minus the MAC envelope field, so every trusted field is
// bound; flipping any of them invalidates the MAC. The excluded field defaults to
// row_mac (offensive/invariant/repo rows) and is freeze_mac for claim-freeze.json.
function offensiveRowMacPayload(row, macField = DEFAULT_MAC_FIELD) {
  const copy = { ...row };
  delete copy[macField];
  return canonicalJson(copy);
}

// The exact signed-bytes preimage for any context: context + "\n" + canonical(row
// minus the MAC field). Both schemes sign these identical bytes — the HMAC keys them,
// the ed25519 signature signs them. The "\n" delimiter prevents a context/payload
// boundary ambiguity, byte-identical to the original v1 HMAC update sequence.
function rowMacPreimage(context, row, macField = DEFAULT_MAC_FIELD) {
  return `${context}\n${offensiveRowMacPayload(row, macField)}`;
}

// --- core sign/verify, scheme-polymorphic on the signer/verifier descriptor ---
//
// A signer/verifier is a plain object that names its scheme:
//   * hmac:    { scheme:"hmac-sha256", key:Buffer }  (sign AND verify use the key)
//   * ed25519: signer   { scheme:"ed25519", privateKey:KeyObject }
//              verifier { scheme:"ed25519", publicKey:KeyObject }
// The ed25519 split is the load-bearing point of the asymmetric custody: a verifier
// holds only the PUBLIC key (or, for legacy rows, the symmetric key it already had),
// never the ed25519 private key. Verification is in-process crypto only — no disk
// re-read and no subprocess on the per-row path.

function hmacDigestForContext(context, row, key, macField = DEFAULT_MAC_FIELD) {
  if (!Buffer.isBuffer(key) || key.length === 0) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "offensive row HMAC key is required");
  }
  return crypto
    .createHmac("sha256", key)
    .update(context)
    .update("\n")
    .update(offensiveRowMacPayload(row, macField))
    .digest("hex");
}

// Mint row[macField] in place under `context` with `signer` and return the row.
//   * an hmac signer mints the v1 envelope {version:1, algorithm:"hmac-sha256", digest}
//     so the compat facade keeps producing rows the legacy verify path accepts;
//   * an ed25519 signer mints the v2 envelope {version:2, scheme:"ed25519", signature}.
// `context` is the domain-separation string. Cycle A signed only offensive-runs.jsonl
// (OFFENSIVE_ROW_MAC_CONTEXT, macField "row_mac"); Cycle B reuses this EXACT envelope to
// key three more verdict ledgers, each with its own context and (for claim-freeze) its
// own carrier field via the optional macField — NOT a new MAC.
function signRowWithMac(context, row, signer, { macField = DEFAULT_MAC_FIELD } = {}) {
  if (typeof context !== "string" || context.length === 0) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "row MAC context string is required");
  }
  if (row == null || typeof row !== "object" || Array.isArray(row)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "offensive run row must be an object to sign");
  }
  if (row[macField] != null) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `offensive run ${macField} must be assigned by the signer`);
  }
  if (signer == null || typeof signer !== "object") {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "row MAC signer descriptor is required");
  }
  if (signer.scheme === MAC_SCHEME_HMAC) {
    row[macField] = {
      version: OFFENSIVE_ROW_MAC_VERSION,
      algorithm: OFFENSIVE_ROW_MAC_ALGORITHM,
      digest: hmacDigestForContext(context, row, signer.key, macField),
    };
    return row;
  }
  if (signer.scheme === MAC_SCHEME_ED25519) {
    if (signer.privateKey == null) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, "ed25519 signer requires a privateKey");
    }
    const signature = crypto
      .sign(null, Buffer.from(rowMacPreimage(context, row, macField)), signer.privateKey)
      .toString("base64url");
    row[macField] = {
      version: OFFENSIVE_ROW_MAC_VERSION_V2,
      scheme: MAC_SCHEME_ED25519,
      signature,
    };
    return row;
  }
  throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `unsupported row MAC signer scheme: ${signer.scheme}`);
}

// Verify row.row_mac under `context` with `verifier`. Dispatches on the ROW's OWN
// declared scheme/version — this is the backward-compat shim: a legacy v1 row routes
// to the v1 HMAC recompute over the identical context+payload, so old rows verify
// unchanged. Returns a boolean (never throws) so the gate fails-fast on any
// malformed/forged/cross-scheme row. The verifier is the scheme-appropriate
// descriptor: for an ed25519 row a {publicKey} (no secret); for an hmac row the
// symmetric key. A combined verifier bundle (resolveOffensiveRowVerifier in
// handoff-signing-key.js) lets per-row dispatch pick without a second lookup.
function verifyRowWithMac(context, row, verifier, { macField = DEFAULT_MAC_FIELD } = {}) {
  if (typeof context !== "string" || context.length === 0) return false;
  if (row == null || typeof row !== "object") return false;
  if (verifier == null || typeof verifier !== "object") return false;
  const env = row[macField];
  if (env == null || typeof env !== "object" || Array.isArray(env)) return false;

  // Legacy v1 symmetric HMAC — recompute over the SAME context+payload with the
  // symmetric key (CONSTRAINT 7: in-flight/old rows verify byte-identically).
  if (env.version === OFFENSIVE_ROW_MAC_VERSION && env.algorithm === MAC_SCHEME_HMAC) {
    if (typeof env.digest !== "string" || !/^[0-9a-f]{64}$/.test(env.digest)) return false;
    const key = verifier.scheme === MAC_SCHEME_HMAC ? verifier.key : verifier.hmacKey;
    if (!Buffer.isBuffer(key) || key.length === 0) return false;
    let expectedHex;
    try {
      expectedHex = hmacDigestForContext(context, row, key, macField);
    } catch {
      return false;
    }
    const actual = Buffer.from(env.digest, "hex");
    const expected = Buffer.from(expectedHex, "hex");
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  }

  if (env.version === OFFENSIVE_ROW_MAC_VERSION_V2) {
    // v2 HMAC (forward-compat for the symmetric context if ever needed).
    if (env.scheme === MAC_SCHEME_HMAC) {
      if (typeof env.digest !== "string" || !/^[0-9a-f]{64}$/.test(env.digest)) return false;
      const key = verifier.scheme === MAC_SCHEME_HMAC ? verifier.key : verifier.hmacKey;
      if (!Buffer.isBuffer(key) || key.length === 0) return false;
      let expectedHex;
      try {
        expectedHex = hmacDigestForContext(context, row, key, macField);
      } catch {
        return false;
      }
      const actual = Buffer.from(env.digest, "hex");
      const expected = Buffer.from(expectedHex, "hex");
      return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
    }
    // v2 ed25519 — verify with the PUBLIC key only (CONSTRAINT 1: fast, in-memory,
    // no disk re-check, no subprocess). The verifier never needs the private key.
    if (env.scheme === MAC_SCHEME_ED25519) {
      if (typeof env.signature !== "string" || !/^[A-Za-z0-9_-]+$/.test(env.signature)) return false;
      // Both the standalone ed25519 verifier {scheme:"ed25519", publicKey} and the
      // combined bundle {publicKey, hmacKey} expose publicKey directly.
      const publicKey = verifier.publicKey;
      if (publicKey == null) return false;
      let sig;
      try {
        sig = Buffer.from(env.signature, "base64url");
      } catch {
        return false;
      }
      try {
        return crypto.verify(null, Buffer.from(rowMacPreimage(context, row, macField)), publicKey, sig);
      } catch {
        return false;
      }
    }
    return false;
  }
  return false;
}

// --- two-state read-time gate shared by all four keyed verdict ledgers ---
//
// assertRowMacOrLegacy folds CONSTRAINT 7 (backward-compat) into ONE decision the
// invariant/repo/freeze read sites call AFTER their existing content-hash/capture
// re-derivation passes. It NEVER replaces that re-derivation — the MAC is an added
// O(1) keyed layer on top of a row that already re-derived.
//
// Two states:
//   * row[macField] == null  → OLD in-flight artifact. Return {legacy:true} (no throw).
//     The caller still trusts it via the existing keyless content-hash re-derivation
//     and SHOULD record an accepted_unsigned warning. This {legacy} return is the exact
//     seam Cycle C N5 enforce-mode flips to BLOCK unsigned rows for NEW claims — same
//     helper, no per-site change.
//   * row[macField] present  → verifyRowWithMac. Valid → {legacy:false}. INVALID
//     (forged/tampered/cross-context) → THROW (the invariant/repo sites already wrap
//     their re-derivation in try/catch → ok:false; the freeze reader maps the throw to
//     null). A present-but-invalid MAC is a HARD fail, never an accept-with-warning.
//
// Honest scope (Cycle B): this KEYS the ledgers — forging a row now needs the signing
// key, not just a recomputable content hash. It does NOT close F3: the ed25519 private
// key is still 0600 at the AGENT uid, so a same-uid in-process actor can require()
// readHandoffSigningPrivateKey and mint a valid MAC for any of the four contexts. F2
// collapses INTO F3; the genuine close is the Cycle C separate-uid guardian + enforce
// attestation. An actor can also STRIP the MAC to masquerade as a legacy {legacy:true}
// row — but that masquerade is GATE-COMPENSATED, not silent: verdictLedgerMacClasses
// (sandbox-isolation-gate.js) classifies an unsigned/stripped row as the laundering-risk
// class, so under BOB_SANDBOX_ATTESTATION_MODE=enforce the verdict gate BLOCKS a NEW
// reportable claim backed by such a row. This accept-with-warning compat window is the
// documented, enforce-gate-compensated cost of keeping in-flight unsigned rows readable.
function assertRowMacOrLegacy(context, row, verifier, { macField = DEFAULT_MAC_FIELD } = {}) {
  if (row == null || typeof row !== "object" || Array.isArray(row) || row[macField] == null) {
    return { legacy: true };
  }
  if (!verifyRowWithMac(context, row, verifier, { macField })) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `${macField} present but does not verify under ${context} (forged/tampered/cross-context row)`,
    );
  }
  return { legacy: false };
}

// assertRowMac — the STRICT twin of assertRowMacOrLegacy. An UNSIGNED row (no MAC
// envelope) is REJECTED here, never accepted-with-warning. This is the gate the
// cross-stack bind sites use: a row feeding a NON-FORGEABLE verified_pass must carry
// a REAL signature, because invariant-runs.jsonl was for a window only best-effort
// hook-blocked (not audit-graded), so a same-uid agent could append an unsigned row
// that assertRowMacOrLegacy would wave through as {legacy:true}. assertRowMacOrLegacy
// keeps its accept-with-warning compat at the general FV READ sites; the cross-stack
// bind demands this strict variant on top of the content-hash re-derivation. A
// present-but-invalid MAC throws exactly as the lenient twin does.
function assertRowMac(context, row, verifier, { macField = DEFAULT_MAC_FIELD } = {}) {
  if (row == null || typeof row !== "object" || Array.isArray(row) || row[macField] == null) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `${macField} is required: an unsigned row cannot back a cross-stack verified_pass (sign the row under ${context})`,
    );
  }
  if (!verifyRowWithMac(context, row, verifier, { macField })) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `${macField} present but does not verify under ${context} (forged/tampered/cross-context row)`,
    );
  }
  return { legacy: false };
}

// --- compat facades (RETAINED): the 27 test files and any in-flight producer that
// pass a raw symmetric Buffer keep working. sign delegates to the v1 hmac path so it
// still mints a v1-verifiable row; verify delegates to verifyRowWithMac with an hmac
// verifier descriptor. ---

function computeOffensiveRowMacDigest(row, signingKey) {
  return hmacDigestForContext(OFFENSIVE_ROW_MAC_CONTEXT, row, signingKey);
}

function signOffensiveRunRow(row, signingKey) {
  return signRowWithMac(OFFENSIVE_ROW_MAC_CONTEXT, row, { scheme: MAC_SCHEME_HMAC, key: signingKey });
}

function verifyOffensiveRunRowMac(row, signingKey) {
  if (!Buffer.isBuffer(signingKey) || signingKey.length === 0) return false;
  return verifyRowWithMac(OFFENSIVE_ROW_MAC_CONTEXT, row, { scheme: MAC_SCHEME_HMAC, key: signingKey });
}

module.exports = {
  OFFENSIVE_ROW_MAC_CONTEXT,
  OFFENSIVE_ROW_MAC_ALGORITHM,
  OFFENSIVE_ROW_MAC_VERSION,
  OFFENSIVE_ROW_MAC_VERSION_V2,
  MAC_SCHEME_HMAC,
  MAC_SCHEME_ED25519,
  INVARIANT_RUN_MAC_CONTEXT,
  REPO_COMMAND_RUN_MAC_CONTEXT,
  CLAIM_FREEZE_MAC_CONTEXT,
  AUTH_DIFFERENTIAL_ROW_MAC_CONTEXT,
  signRowWithMac,
  verifyRowWithMac,
  assertRowMacOrLegacy,
  assertRowMac,
  computeOffensiveRowMacDigest,
  signOffensiveRunRow,
  verifyOffensiveRunRowMac,
};
