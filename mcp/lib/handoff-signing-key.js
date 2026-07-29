"use strict";

const crypto = require("crypto");
const fs = require("fs");
const {
  handoffSigningKeyPath,
  handoffSigningPrivateKeyPath,
  handoffSigningPublicKeyPath,
} = require("./paths.js");
const {
  writeFileAtomic,
  writeFileExclusiveAtomic,
} = require("./storage.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  MAC_SCHEME_ED25519,
  signRowWithMac,
} = require("./offensive-row-mac.js");

const HANDOFF_SIGNING_KEY_VERSION = 1;
const HANDOFF_SIGNING_KEY_BYTES = 32;

// Custody perms for the signing secrets. These constants are the single source
// of truth shared by the in-process key writers (ensure*) and the operator
// launcher (scripts/launch-bob-signer.sh, via the rendered perm projection in
// signing-key-custody.js): a deployment that runs the server under a dedicated
// signer uid relies on these exact modes so the agent uid gets EACCES.
//   * the symmetric handoff-provenance key stays owner read/write (0600): the
//     server rewrites nothing but must be able to read it back;
//   * the ed25519 verdict-ledger PRIVATE key is owner READ-only (0400): it is
//     written once and never rewritten, so the tighter mode removes even the
//     owner write bit while the secure reader's (mode & 0o077)===0 check still
//     accepts it. Both keys are EACCES to any uid other than the owner, which is
//     the load-bearing fact when the owner is a dedicated signer uid.
const SYMMETRIC_SIGNING_KEY_MODE = 0o600;
const ED25519_PRIVATE_KEY_MODE = 0o400;
// The session directory that holds the keys must be owner-only (0700) so the
// agent uid cannot list, read, or raw-write the audit-graded ledgers it carries.
const SIGNING_KEY_DIR_MODE = 0o700;

// The asymmetric keypair version. The private key DER (pkcs8) and public key DER
// (spki) are stored base64url and re-imported via crypto.createPrivateKey /
// createPublicKey — DER export/import roundtrips on this Node.
const HANDOFF_KEYPAIR_VERSION = 1;

function decodeSigningKeyDocument(document, filePath) {
  if (document == null || typeof document !== "object" || Array.isArray(document)) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Malformed handoff signing key: ${filePath}`);
  }
  const keys = Object.keys(document).sort();
  if (keys.length !== 2 || keys[0] !== "key" || keys[1] !== "version") {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Malformed handoff signing key schema in ${filePath}`);
  }
  if (document.version !== HANDOFF_SIGNING_KEY_VERSION) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Unsupported handoff signing key version in ${filePath}`);
  }
  if (typeof document.key !== "string" || !/^[A-Za-z0-9_-]+$/.test(document.key)) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Malformed handoff signing key material in ${filePath}`);
  }
  const key = Buffer.from(document.key, "base64url");
  if (key.length !== HANDOFF_SIGNING_KEY_BYTES) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Malformed handoff signing key length in ${filePath}`);
  }
  return key;
}

function readSigningKeyDocumentSecure(filePath) {
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  let fd;
  try {
    fd = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
    const stats = fs.fstatSync(fd);
    if (!stats.isFile()) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Handoff signing key is not a regular file: ${filePath}`);
    }
    if ((stats.mode & 0o077) !== 0) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Handoff signing key must be owner-only 0600: ${filePath}`);
    }
    if (stats.nlink !== 1) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Handoff signing key must not have hard links: ${filePath}`);
    }
    return JSON.parse(fs.readFileSync(fd, "utf8"));
  } catch (error) {
    if (error instanceof ToolError) throw error;
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `Could not read handoff signing key: ${filePath} (${error.message || String(error)})`,
    );
  } finally {
    if (fd != null) {
      try { fs.closeSync(fd); } catch {}
    }
  }
}

function readHandoffSigningKey(domain) {
  const filePath = handoffSigningKeyPath(domain);
  if (!fs.existsSync(filePath)) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Missing handoff signing key: ${filePath}`);
  }
  return decodeSigningKeyDocument(readSigningKeyDocumentSecure(filePath), filePath);
}

function ensureHandoffSigningKey(domain) {
  const filePath = handoffSigningKeyPath(domain);
  const document = {
    version: HANDOFF_SIGNING_KEY_VERSION,
    key: crypto.randomBytes(HANDOFF_SIGNING_KEY_BYTES).toString("base64url"),
  };
  const wrote = writeFileExclusiveAtomic(filePath, `${JSON.stringify(document, null, 2)}\n`, { mode: SYMMETRIC_SIGNING_KEY_MODE });
  if (!wrote) {
    return readHandoffSigningKey(domain);
  }
  return decodeSigningKeyDocument(document, filePath);
}

// --- ed25519 keypair (asymmetric custody: sign vs verify) ---
//
// THE SPLIT, STATED HONESTLY: new offensive rows are signed with the ed25519 private
// key, and the verifiers hold only the world-readable public key (no secret). That is
// the structural prerequisite for running the signer under a separate OS uid. But the
// private key below is STILL minted at the AGENT's uid in a 0600 file the agent uid can
// read — exactly like the symmetric key. A same-uid Bash + Write + runtime-indirection
// agent can therefore STILL read this private key and forge MAC-valid rows. This file
// makes NO custody claim; the residual (claims.js:848-858) is NOT closed here. The
// close requires the operator to run the signer under a separate uid (gated by the
// sandbox-isolation attestation), which is not wired in this surface.

function decodePrivateKeyDocument(document, filePath) {
  if (document == null || typeof document !== "object" || Array.isArray(document)) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Malformed ed25519 private key: ${filePath}`);
  }
  const keys = Object.keys(document).sort();
  if (keys.length !== 3 || keys[0] !== "key" || keys[1] !== "scheme" || keys[2] !== "version") {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Malformed ed25519 private key schema in ${filePath}`);
  }
  if (document.version !== HANDOFF_KEYPAIR_VERSION) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Unsupported ed25519 private key version in ${filePath}`);
  }
  if (document.scheme !== MAC_SCHEME_ED25519) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Unsupported ed25519 private key scheme in ${filePath}`);
  }
  if (typeof document.key !== "string" || !/^[A-Za-z0-9_-]+$/.test(document.key)) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Malformed ed25519 private key material in ${filePath}`);
  }
  try {
    return crypto.createPrivateKey({
      key: Buffer.from(document.key, "base64url"),
      format: "der",
      type: "pkcs8",
    });
  } catch (error) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Could not import ed25519 private key from ${filePath} (${error.message || String(error)})`);
  }
}

function decodePublicKeyDocument(document, filePath) {
  if (document == null || typeof document !== "object" || Array.isArray(document)) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Malformed ed25519 public key: ${filePath}`);
  }
  const keys = Object.keys(document).sort();
  if (keys.length !== 3 || keys[0] !== "key" || keys[1] !== "scheme" || keys[2] !== "version") {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Malformed ed25519 public key schema in ${filePath}`);
  }
  if (document.version !== HANDOFF_KEYPAIR_VERSION) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Unsupported ed25519 public key version in ${filePath}`);
  }
  if (document.scheme !== MAC_SCHEME_ED25519) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Unsupported ed25519 public key scheme in ${filePath}`);
  }
  if (typeof document.key !== "string" || !/^[A-Za-z0-9_-]+$/.test(document.key)) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Malformed ed25519 public key material in ${filePath}`);
  }
  try {
    return crypto.createPublicKey({
      key: Buffer.from(document.key, "base64url"),
      format: "der",
      type: "spki",
    });
  } catch (error) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Could not import ed25519 public key from ${filePath} (${error.message || String(error)})`);
  }
}

// Read the owner-only private key the same hardened way the symmetric key is read:
// O_NOFOLLOW, regular-file, owner-only (the secure reader's (mode & 0o077)===0
// check accepts the 0400 the key is minted at), single-hard-link. The owner-only
// enforcement does not by itself exclude the agent: it is load-bearing only when
// the owner is a dedicated signer uid the agent cannot impersonate.
function readHandoffSigningPrivateKey(domain) {
  const filePath = handoffSigningPrivateKeyPath(domain);
  if (!fs.existsSync(filePath)) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Missing ed25519 private key: ${filePath}`);
  }
  const privateKey = decodePrivateKeyDocument(readSigningKeyDocumentSecure(filePath), filePath);
  return { scheme: MAC_SCHEME_ED25519, privateKey };
}

// Read the world-readable public key. No 0600 enforcement (it is public verify
// material), but it is realpath/regular-file checked via a plain read.
//
// When the public key file is transiently absent — the cross-file write window
// between the private-key create and the public-key write in ensureHandoffKeypair,
// or a session whose public half was lost — the public key is RE-DERIVED from the
// private key (the ed25519 public key is a pure function of the private key). A
// present private key therefore always yields a verifiable public key, so a
// concurrent reader catching the partial-write window never spuriously rejects a
// valid row. The re-derivation is gated on the private key being present and
// readable; if neither file is usable this still throws (fail-closed for a
// pre-keypair session).
function readHandoffSigningPublicKey(domain) {
  const filePath = handoffSigningPublicKeyPath(domain);
  if (!fs.existsSync(filePath)) {
    return derivePublicKeyFromPrivate(domain, filePath);
  }
  let document;
  try {
    document = JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (error) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Could not read ed25519 public key: ${filePath} (${error.message || String(error)})`);
  }
  const publicKey = decodePublicKeyDocument(document, filePath);
  return { scheme: MAC_SCHEME_ED25519, publicKey };
}

// Re-derive the public key from the on-disk private key. Used only when the
// public file is transiently missing (the partial-write window) — ed25519's
// public key is a deterministic function of the private key, so this yields the
// exact verify material the missing file would have held. Throws the original
// "Missing ed25519 public key" if the private key is itself absent, so a
// genuinely pre-keypair session still fails closed.
function derivePublicKeyFromPrivate(domain, publicFilePath) {
  const privFilePath = handoffSigningPrivateKeyPath(domain);
  if (!fs.existsSync(privFilePath)) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Missing ed25519 public key: ${publicFilePath}`);
  }
  const { privateKey } = readHandoffSigningPrivateKey(domain);
  return { scheme: MAC_SCHEME_ED25519, publicKey: crypto.createPublicKey(privateKey) };
}

// Idempotently provision the ed25519 keypair alongside the symmetric key. The
// private key is the secret and is the single arbiter: it is created exclusive-
// atomic at 0400 (one writer wins), then the world-readable public key is written.
// The two writes are not atomic across files, so a concurrent reader can catch a
// window where the private key exists but the public key does not; that window is
// closed on the READER side — readHandoffSigningPublicKey re-derives the public key
// from the private key when the public file is missing (ed25519's public key is a
// pure function of the private key), so a present private key is never spuriously
// unverifiable. On a concurrent loser of the exclusive create, the existing files
// are read back (the key material is identical for callers because each re-import
// is a fresh KeyObject of the persisted DER).
function ensureHandoffKeypair(domain) {
  const privPath = handoffSigningPrivateKeyPath(domain);
  const pubPath = handoffSigningPublicKeyPath(domain);
  if (fs.existsSync(privPath) && fs.existsSync(pubPath)) {
    return {
      privateKey: readHandoffSigningPrivateKey(domain),
      publicKey: readHandoffSigningPublicKey(domain),
    };
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const privDer = privateKey.export({ type: "pkcs8", format: "der" }).toString("base64url");
  const pubDer = publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  const privDocument = {
    version: HANDOFF_KEYPAIR_VERSION,
    scheme: MAC_SCHEME_ED25519,
    key: privDer,
  };
  const pubDocument = {
    version: HANDOFF_KEYPAIR_VERSION,
    scheme: MAC_SCHEME_ED25519,
    key: pubDer,
  };
  // Private key first, exclusive-atomic at owner-read-only 0400 (written once,
  // never rewritten). If a concurrent init won the race, fall through to reading
  // the persisted pair (never overwrite the existing key).
  const wrotePriv = writeFileExclusiveAtomic(privPath, `${JSON.stringify(privDocument, null, 2)}\n`, { mode: ED25519_PRIVATE_KEY_MODE });
  if (!wrotePriv) {
    return {
      privateKey: readHandoffSigningPrivateKey(domain),
      publicKey: readHandoffSigningPublicKey(domain),
    };
  }
  // The public key is world-readable; writeFileAtomic uses the default mode (umask).
  // Only write it after we own the private key, so the published verify key always
  // matches the private key this init minted. A reader that catches the gap before
  // this write re-derives the same public key from the private key, so the cross-
  // file window is non-spurious-rejecting (see readHandoffSigningPublicKey).
  writeFileAtomic(pubPath, `${JSON.stringify(pubDocument, null, 2)}\n`);
  return {
    privateKey: { scheme: MAC_SCHEME_ED25519, privateKey },
    publicKey: { scheme: MAC_SCHEME_ED25519, publicKey },
  };
}

// The per-row verifier bundle handed to the offensive-row verify sites. It carries
// BOTH the ed25519 public key (for v2 ed25519 rows — no secret) AND the symmetric key
// (for legacy v1 hmac rows — CONSTRAINT 7), so verifyRowWithMac dispatches per row on
// the row's declared scheme without a second key lookup. Both keys are read at session
// creation cost (the public key + the symmetric key when present); no disk re-read
// happens per row.
//
// The symmetric key is OPTIONAL. New verdict rows are v2 ed25519 (the post-split MAC),
// and an ed25519-only session need not have a symmetric handoff key on disk. Reading it
// unconditionally threw STATE_CONFLICT ("Missing handoff signing key") into the live
// verdict path, so the read is GUARDED: a missing symmetric key yields hmacKey:null.
// assertRowMacOrLegacy dispatches on the row's declared scheme — an ed25519 row never
// consults hmacKey, and a legacy v1-HMAC row with hmacKey:null fails CLOSED (correct).
function resolveOffensiveRowVerifier(domain) {
  let publicKey = null;
  try {
    publicKey = readHandoffSigningPublicKey(domain).publicKey;
  } catch {
    // A session created before keypair provisioning has only the symmetric key.
    // Leaving publicKey null is fine: only legacy v1 hmac rows exist for it, and
    // ensureHandoffKeypair backfills the pair on the next session touch.
    publicKey = null;
  }
  let hmacKey = null;
  try {
    hmacKey = readHandoffSigningKey(domain);
  } catch {
    // Absent symmetric key (an ed25519-only session): hmacKey:null. A v2 ed25519 row
    // never reads it; a legacy v1-HMAC row with a null hmacKey fails closed.
    hmacKey = null;
  }
  return { publicKey, hmacKey };
}

// The SINGLE safe verifier resolver every read-time verify site converges on. It is
// the converged form of the public-key-only fallback those sites used to duplicate:
//   * the common path returns resolveOffensiveRowVerifier's { publicKey, hmacKey } —
//     with the fix above, hmacKey is null (not a throw) when the symmetric key is
//     absent (an ed25519-only session); the ed25519 public key still verifies v2 rows;
//   * a session with NO key material at all (neither public nor symmetric) yields
//     null — the documented pre-keypair-session null-verifier contract. A present
//     row_mac with a null (or all-null) verifier fails closed at assertRowMacOrLegacy.
// The inner try is a defensive fallback should resolveOffensiveRowVerifier ever throw
// (its key reads are guarded, so this is rare). Resolve ONCE per call (it reads keys
// from disk), never per row (CONSTRAINT 1).
function resolveRowVerifierSafely(domain) {
  let verifier;
  try {
    verifier = resolveOffensiveRowVerifier(domain);
  } catch {
    try {
      verifier = { publicKey: readHandoffSigningPublicKey(domain).publicKey, hmacKey: null };
    } catch {
      return null;
    }
  }
  // No key material at all (a pre-keypair session): collapse to the null verifier
  // contract so callers' `verifier === null` sentinels and fail-closed paths behave
  // exactly as they did before the convergence.
  if (verifier && verifier.publicKey == null && verifier.hmacKey == null) return null;
  return verifier;
}

// The SINGLE seam every verdict-ledger producer signs through. It custodies the
// secret behind one decision so no producer reaches the ed25519 private key
// directly: a future out-of-uid signer backend can swap the body here without
// touching any of the four sign sites.
//
// WHAT EXCLUDES THE AGENT (and what does NOT). When the operator runs the MCP
// server under a dedicated signer uid (sessionsRoot resolves to that uid's HOME,
// the session tree is 0700 / keys 0400/0600 signer-owned), this in-process sign
// IS the isolated signer: the legitimate signer is the server itself at the
// signer uid, and the agent uid gets EACCES on the key. There is then no
// separate same-uid actor to fence off — the agent's Bash is at the agent uid,
// the server (the sole legitimate signer) is at the signer uid — so no socket or
// guardian process is needed.
//
// WHEN ISOLATION IS ABSENT (the same-uid dev box), signing STILL succeeds here
// so in-flight sessions never hard-crash: the row is minted locally at the agent
// uid. That degrade is NOT a silent pass — the TRUST consequence is enforced at
// the verdict-level attestation gate (a live re-probe at grade/compose), never
// here on the fast in-lock sign path. This keeps the close fail-closed at the
// verdict boundary while the sign path stays simple and lock-bound.
//
// The caller MUST already hold the session lock (every existing sign site does);
// this only moves the ensure-keypair + read-key + sign trio behind one call.
function signRowViaIsolatedSignerOrLocal(domain, context, row, options = {}) {
  ensureHandoffKeypair(domain);
  return signRowWithMac(context, row, readHandoffSigningPrivateKey(domain), options);
}

module.exports = {
  HANDOFF_SIGNING_KEY_BYTES,
  HANDOFF_SIGNING_KEY_VERSION,
  HANDOFF_KEYPAIR_VERSION,
  SYMMETRIC_SIGNING_KEY_MODE,
  ED25519_PRIVATE_KEY_MODE,
  SIGNING_KEY_DIR_MODE,
  ensureHandoffSigningKey,
  readHandoffSigningKey,
  ensureHandoffKeypair,
  readHandoffSigningPrivateKey,
  readHandoffSigningPublicKey,
  resolveOffensiveRowVerifier,
  resolveRowVerifierSafely,
  signRowViaIsolatedSignerOrLocal,
};
