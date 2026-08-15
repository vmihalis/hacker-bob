"use strict";

// Provider-neutral identity and revision contracts shared by core consumers
// and the repo-plane session implementation.

const crypto = require("node:crypto");
const path = require("node:path");

const { assertNonEmptyString } = require("./io/validation.js");
const { ERROR_CODES, ToolError } = require("./io/envelope.js");

const GIT_REF_MAX_CHARS = 120;
const HEX_REF_RE = /^[0-9a-f]{7,64}$/i;
const LOCAL_REF_RE = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,119}$/;

function safeBasename(value) {
  const base = path.basename(value || "").trim();
  if (!base) return "repo";
  const folded = base.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
  return folded || "repo";
}

function sha8(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex").slice(0, 8);
}

function sha64(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function deriveRepoTargetDomain(realpathValue) {
  return `repo-${safeBasename(realpathValue)}-${sha8(realpathValue)}`;
}

function deriveRepoHashFromPath(realpathValue) {
  return sha64(realpathValue);
}

function gitMetadataError(message, repoErrorCode, details = {}) {
  return new ToolError(ERROR_CODES.INVALID_ARGUMENTS, message, {
    repo_error_code: repoErrorCode,
    ...details,
  });
}

function normalizeHistoryRef(ref, fieldName = "checkout.ref") {
  const normalized = assertNonEmptyString(ref, fieldName);
  if (normalized.length > GIT_REF_MAX_CHARS) {
    throw gitMetadataError(
      `${fieldName} must be at most ${GIT_REF_MAX_CHARS} characters`,
      "invalid_differential_ref",
    );
  }
  if (HEX_REF_RE.test(normalized)) return normalized;
  if (!LOCAL_REF_RE.test(normalized)
      || normalized.includes("..")
      || normalized.includes("//")
      || normalized.includes("@{")
      || normalized.endsWith("/")
      || normalized.endsWith(".")
      || normalized.endsWith(".lock")) {
    throw gitMetadataError(
      `${fieldName} must be a 7-64 hex object prefix or safe local git ref`,
      "invalid_differential_ref",
    );
  }
  return normalized;
}

module.exports = Object.freeze({
  HEX_REF_RE,
  deriveRepoHashFromPath,
  deriveRepoTargetDomain,
  gitMetadataError,
  normalizeHistoryRef,
  safeBasename,
  sha8,
});
