"use strict";

// Y.10 (Y-D12 / D6 + D14) — operator session-cap nonce.
//
// The session-cap is a per-host operator-attestation nonce stored at
// `~/.bob/session-cap` with mode 0600 so only the local operator account
// can read it. Its sole purpose is to back the `attestation_token` field
// on `bob_set_queue_policy({partial_surface_advance_acknowledgements: [...]})`:
// when an operator wants to advance past the OPEN_FRONTIER -> CLAIM_FREEZE
// gate while partial surfaces remain in the latest merged wave, they must
// pass the nonce string in the attestation_token field of each ack entry.
//
// The nonce is generated on first call (typically during install or at the
// first acknowledgement path), 64 hex chars from crypto.randomBytes(32).
// Subsequent reads return the same value, so an operator can paste the
// nonce into automation. The file mode is checked on every read and is
// re-enforced to 0600 if it drifted. When the file is absent (no operator
// has ever provisioned the cap), the gate falls back to non-empty-string
// validation so the runtime gate still rejects empty tokens but the
// acknowledgement entry is recorded with `cap_status: "uninitialized"` for
// audit. When the file exists, tokens MUST match exactly; mismatch is
// recorded with `cap_status: "mismatched"` and treated as not-acknowledged.

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const SESSION_CAP_FILENAME = "session-cap";
const SESSION_CAP_DIRNAME = ".bob";
const SESSION_CAP_MODE = 0o600;
const SESSION_CAP_DIR_MODE = 0o700;
const SESSION_CAP_NONCE_BYTES = 32;

function bobHome(homedirOverride = null) {
  const home = typeof homedirOverride === "string" && homedirOverride
    ? homedirOverride
    : os.homedir();
  return path.join(home, SESSION_CAP_DIRNAME);
}

function sessionCapPath(homedirOverride = null) {
  return path.join(bobHome(homedirOverride), SESSION_CAP_FILENAME);
}

function generateSessionCapNonce() {
  return crypto.randomBytes(SESSION_CAP_NONCE_BYTES).toString("hex");
}

// Atomic-create-with-correct-mode: create the parent dir at mode 0700,
// write the nonce file with mode 0600 using O_CREAT|O_EXCL so a concurrent
// caller cannot win the race and write a different value. On EEXIST we
// fall through to the read+re-enforce-mode path.
function ensureSessionCapNonce(homedirOverride = null) {
  const dir = bobHome(homedirOverride);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: SESSION_CAP_DIR_MODE });
  } else {
    try {
      fs.chmodSync(dir, SESSION_CAP_DIR_MODE);
    } catch {
      // best-effort; on platforms where mode is unenforceable we keep going.
    }
  }
  const filePath = sessionCapPath(homedirOverride);
  if (!fs.existsSync(filePath)) {
    const nonce = generateSessionCapNonce();
    let fd;
    try {
      fd = fs.openSync(filePath, "wx", SESSION_CAP_MODE);
      fs.writeSync(fd, `${nonce}\n`);
    } catch (error) {
      if (error && error.code === "EEXIST") {
        // Lost the race — fall through to the read path.
      } else {
        throw error;
      }
    } finally {
      if (fd != null) {
        try { fs.closeSync(fd); } catch {}
      }
    }
  }
  // Re-enforce mode 0600 in case the file existed at a wider mode.
  try {
    fs.chmodSync(filePath, SESSION_CAP_MODE);
  } catch {
    // best-effort.
  }
  return readSessionCapNonce(homedirOverride);
}

function readSessionCapNonce(homedirOverride = null) {
  const filePath = sessionCapPath(homedirOverride);
  if (!fs.existsSync(filePath)) return null;
  let raw;
  try {
    raw = fs.readFileSync(filePath, "utf8");
  } catch {
    return null;
  }
  const trimmed = String(raw || "").trim();
  return trimmed || null;
}

function readSessionCapMode(homedirOverride = null) {
  const filePath = sessionCapPath(homedirOverride);
  if (!fs.existsSync(filePath)) return null;
  try {
    const stat = fs.statSync(filePath);
    return stat.mode & 0o777;
  } catch {
    return null;
  }
}

// Verify an operator-supplied attestation token. Returns one of:
//   {ok: true, cap_status: "matched"}      — token matched the nonce.
//   {ok: true, cap_status: "uninitialized"} — file absent; token recorded.
//                                              gate may still admit the
//                                              acknowledgement when the
//                                              operator runs without the
//                                              install-managed nonce, but
//                                              the audit reflects that no
//                                              cap was provisioned.
//   {ok: false, cap_status: "mismatched"}   — file present and token did
//                                              not match. Gate treats the
//                                              acknowledgement as invalid.
//   {ok: false, cap_status: "empty_token"}  — token missing or empty.
function verifyAttestationToken(token, homedirOverride = null) {
  if (typeof token !== "string" || token.trim().length === 0) {
    return { ok: false, cap_status: "empty_token" };
  }
  const expected = readSessionCapNonce(homedirOverride);
  if (expected == null) {
    return { ok: true, cap_status: "uninitialized" };
  }
  const a = Buffer.from(token.trim(), "utf8");
  const b = Buffer.from(expected, "utf8");
  if (a.length !== b.length) {
    return { ok: false, cap_status: "mismatched" };
  }
  if (!crypto.timingSafeEqual(a, b)) {
    return { ok: false, cap_status: "mismatched" };
  }
  return { ok: true, cap_status: "matched" };
}

module.exports = {
  SESSION_CAP_DIRNAME,
  SESSION_CAP_FILENAME,
  SESSION_CAP_MODE,
  SESSION_CAP_DIR_MODE,
  SESSION_CAP_NONCE_BYTES,
  bobHome,
  ensureSessionCapNonce,
  generateSessionCapNonce,
  readSessionCapMode,
  readSessionCapNonce,
  sessionCapPath,
  verifyAttestationToken,
};
