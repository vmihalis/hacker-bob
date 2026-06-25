"use strict";

// Custody intent the operator launcher (scripts/launch-bob-signer.sh) renders
// into chmod/chown commands. The genuine signer-isolation close is an OS fact of
// WHO runs the MCP server (a dedicated signer uid), not a path change: when the
// server runs under that uid, sessionsRoot() resolves to the signer uid's HOME,
// so the entire session tree — every signing secret AND every audit-graded
// ledger — is created owned by the signer uid. With the perms below, the agent
// uid then gets EACCES on (a) reading the signing keys (cannot forge a MAC) and
// (b) raw-writing the audit-graded ledgers (cannot bypass MCP).
//
// This module is the single source of truth for those perms shared between the
// in-process key writers (handoff-signing-key.js) and the launcher, so the
// launcher cannot drift from the modes the server actually mints. It is pure
// (no fs, no env) so the launcher's intent is testable on a same-uid box without
// a real second uid: assert the rendered commands/modes, not a live chown.

const {
  SYMMETRIC_SIGNING_KEY_MODE,
  ED25519_PRIVATE_KEY_MODE,
  SIGNING_KEY_DIR_MODE,
} = require("./handoff-signing-key.js");

// The basenames of the signing secrets that MUST be custodied behind the signer
// uid. Covers BOTH signing surfaces with one boundary: the ed25519 verdict-
// ledger private key AND the symmetric handoff-provenance key. Custodying only
// the ed25519 key would leave handoff provenance forgeable; both live in the
// session dir, so relocating the whole tree to the signer uid covers both.
const SIGNING_SECRET_BASENAMES = Object.freeze([
  ".handoff-signing-key.json",
  ".handoff-signing-key-ed25519.json",
]);

// The per-secret intended octal mode. The symmetric key is owner read/write (the
// server reads it back); the ed25519 private key is owner read-only (written once).
const SIGNING_SECRET_MODES = Object.freeze({
  ".handoff-signing-key.json": SYMMETRIC_SIGNING_KEY_MODE,
  ".handoff-signing-key-ed25519.json": ED25519_PRIVATE_KEY_MODE,
});

// Render the chmod/chown intent the launcher applies to the signer-owned session
// root. Returns a frozen plan keyed by purpose so a test asserts the exact octal
// modes + owner without running a live chown. `signerUid` may be a numeric uid or
// a username string (the launcher passes whichever the operator declared).
function renderCustodyPlan(sessionsRootPath, signerUid) {
  if (typeof sessionsRootPath !== "string" || !sessionsRootPath) {
    throw new Error("renderCustodyPlan requires a sessions root path");
  }
  if (signerUid == null || signerUid === "") {
    throw new Error("renderCustodyPlan requires a signer uid/owner");
  }
  const owner = String(signerUid);
  return Object.freeze({
    // The session root (and every session dir under it) must be owner-only 0700
    // so the agent uid cannot list/read/raw-write its contents.
    sessions_root: Object.freeze({
      path: sessionsRootPath,
      mode: SIGNING_KEY_DIR_MODE,
      owner,
      recursive_owner: true,
    }),
    // Each signing secret tightened to its intended mode, owned by the signer uid.
    secrets: Object.freeze(
      SIGNING_SECRET_BASENAMES.map((basename) => Object.freeze({
        basename,
        mode: SIGNING_SECRET_MODES[basename],
        owner,
      })),
    ),
  });
}

// Format an octal mode as the 4-digit string chmod expects (e.g. 0o700 -> "0700").
function octalModeString(mode) {
  if (!Number.isInteger(mode) || mode < 0) {
    throw new Error("octalModeString requires a non-negative integer mode");
  }
  return `0${mode.toString(8).padStart(3, "0")}`;
}

module.exports = {
  SIGNING_SECRET_BASENAMES,
  SIGNING_SECRET_MODES,
  SYMMETRIC_SIGNING_KEY_MODE,
  ED25519_PRIVATE_KEY_MODE,
  SIGNING_KEY_DIR_MODE,
  renderCustodyPlan,
  octalModeString,
};
