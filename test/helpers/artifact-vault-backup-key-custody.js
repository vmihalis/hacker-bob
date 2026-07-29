"use strict";

// Test-only in-process stand-in for the operator-owned external backup-key
// custodian.  It deliberately reports production/HIL false.  Runtime code must
// receive a separately isolated native/keychain/HSM-backed implementation.

const crypto = require("node:crypto");

const {
  createOperatorBackupKeyCustodyPort,
} = require("../../packages/bob-artifact-vault/operator.js");

const REVOCATION_POLICY = "whole_archive_key_on_member_erasure";

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value != null && typeof value === "object") {
    const output = {};
    for (const key of Object.keys(value).sort()) output[key] = canonicalize(value[key]);
    return output;
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function digest(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function createInProcessBackupKeyCustodyFixture({
  vaultId,
  vaultSlot,
  sessionNucleusHash,
} = {}) {
  const custodyId = `backup-custody:v1:${crypto.randomBytes(32).toString("base64url")}`;
  const custodyEpoch = 1;
  const receiptKey = crypto.randomBytes(32);
  const archives = new Map();
  const retirements = new Map();
  const restoreFences = new Map();
  const binding = Object.freeze({
    custody_id: custodyId,
    custody_epoch: custodyEpoch,
    vault_id: vaultId,
    vault_slot: vaultSlot,
    session_nucleus_hash: sessionNucleusHash,
  });

  function currentState() {
    return {
      version: 1,
      ...binding,
      status: "active",
      production_ready: false,
      hil_verified: false,
      revocation_policy: REVOCATION_POLICY,
      backup_media_erasure_attested: false,
    };
  }

  const callbacks = {
    resolve_current_custody() {
      return currentState();
    },

    seal_archive(request, plaintext) {
      if (archives.has(request.backup_ref)) throw new Error("duplicate test backup reference");
      if (request.artifact_inventory.some((entry) => retirements.has(entry.artifact_handle))) {
        throw new Error("test backup contains a retired artifact");
      }
      const key = crypto.randomBytes(32);
      const nonce = crypto.randomBytes(12);
      const aad = canonicalJson(request);
      const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
      cipher.setAAD(Buffer.from(aad));
      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const sealed = Buffer.from(canonicalJson({
        algorithm: "aes-256-gcm",
        nonce: nonce.toString("base64"),
        ciphertext: ciphertext.toString("base64"),
        tag: cipher.getAuthTag().toString("base64"),
      }));
      const state = {
        version: 1,
        status: "active",
        ...binding,
        backup_ref: request.backup_ref,
        backup_digest: request.backup_digest,
        artifact_inventory_digest: request.artifact_inventory_digest,
        seal_effect_ref: request.seal_effect_ref,
        seal_ref: `backup-seal:v1:${crypto.randomBytes(32).toString("base64url")}`,
        custody_format: "test-in-process-aes-256-gcm-v1",
        sealed_archive: sealed.toString("base64"),
        sealed_archive_digest: digest(sealed),
        revocation_effect_ref: null,
        revoked_at: null,
      };
      sealed.fill(0);
      archives.set(request.backup_ref, {
        aad,
        artifact_handles: request.artifact_inventory.map((entry) => entry.artifact_handle),
        key,
        state,
      });
      return cloneJson(state);
    },

    read_archive_state(request) {
      const record = archives.get(request.backup_ref);
      if (!record
          || record.state.backup_digest !== request.backup_digest
          || record.state.artifact_inventory_digest !== request.artifact_inventory_digest
          || record.state.seal_effect_ref !== request.seal_effect_ref) return null;
      return cloneJson(record.state);
    },

    open_archive(request) {
      const record = archives.get(request.backup_ref);
      if (!record || record.state.status !== "active" || !record.key) {
        throw new Error("test archive key is revoked");
      }
      for (const field of [
        "backup_digest",
        "artifact_inventory_digest",
        "seal_effect_ref",
        "seal_ref",
        "custody_format",
        "sealed_archive",
        "sealed_archive_digest",
      ]) {
        if (request[field] !== record.state[field]) throw new Error("test archive binding drift");
      }
      if (request.restore_ref !== null) {
        const fence = restoreFences.get(request.restore_ref);
        if (!fence || fence.status !== "active" || fence.backup_ref !== request.backup_ref) {
          throw new Error("test restore fence is absent or inactive");
        }
      }
      const envelope = JSON.parse(Buffer.from(request.sealed_archive, "base64").toString("utf8"));
      const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        record.key,
        Buffer.from(envelope.nonce, "base64"),
      );
      decipher.setAAD(Buffer.from(record.aad));
      decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(envelope.ciphertext, "base64")),
        decipher.final(),
      ]);
      return {
        version: 1,
        ...binding,
        backup_ref: request.backup_ref,
        backup_digest: request.backup_digest,
        artifact_inventory_digest: request.artifact_inventory_digest,
        seal_ref: request.seal_ref,
        open_ref: request.open_ref,
        restore_ref: request.restore_ref,
        plaintext_archive: plaintext,
      };
    },

    acquire_restore_fence(request) {
      if (restoreFences.has(request.restore_ref)) {
        return cloneJson(restoreFences.get(request.restore_ref));
      }
      const archive = archives.get(request.backup_ref);
      if (!archive || archive.state.status !== "active") throw new Error("test archive is not active");
      const fence = {
        version: 1,
        status: "active",
        ...binding,
        backup_ref: request.backup_ref,
        backup_digest: request.backup_digest,
        artifact_inventory_digest: request.artifact_inventory_digest,
        seal_effect_ref: request.seal_effect_ref,
        seal_ref: request.seal_ref,
        restore_ref: request.restore_ref,
        acquire_effect_ref: request.acquire_effect_ref,
        release_effect_ref: null,
        production_ready: false,
        hil_verified: false,
      };
      restoreFences.set(request.restore_ref, fence);
      return cloneJson(fence);
    },

    read_restore_fence(request) {
      const fence = restoreFences.get(request.restore_ref);
      return fence ? cloneJson(fence) : null;
    },

    release_restore_fence(request) {
      const fence = restoreFences.get(request.restore_ref);
      if (!fence) throw new Error("test restore fence is absent");
      if (fence.status === "released") {
        if (fence.release_effect_ref !== request.release_effect_ref) {
          throw new Error("test restore fence release effect drift");
        }
        return cloneJson(fence);
      }
      const released = {
        ...fence,
        status: "released",
        release_effect_ref: request.release_effect_ref,
      };
      restoreFences.set(request.restore_ref, released);
      return cloneJson(released);
    },

    retire_artifact(request) {
      if (retirements.has(request.artifact_handle)) {
        return cloneJson(retirements.get(request.artifact_handle));
      }
      const memberRecords = [...archives.values()].filter(
        (record) => record.artifact_handles.includes(request.artifact_handle),
      );
      if (memberRecords.some((record) => [...restoreFences.values()].some(
        (fence) => fence.status === "active" && fence.backup_ref === record.state.backup_ref,
      ))) {
        throw new Error("test member archive holds an active restore fence");
      }
      const revoked = [];
      for (const record of memberRecords) {
        if (record.state.status === "active") {
          record.key.fill(0);
          record.key = null;
          record.state = {
            ...record.state,
            status: "revoked",
            revocation_effect_ref: request.retirement_effect_ref,
            revoked_at: request.requested_at,
          };
        }
        const summary = {
          backup_ref: record.state.backup_ref,
          backup_digest: record.state.backup_digest,
          artifact_inventory_digest: record.state.artifact_inventory_digest,
          seal_effect_ref: record.state.seal_effect_ref,
          seal_ref: record.state.seal_ref,
          sealed_archive_digest: record.state.sealed_archive_digest,
          revocation_effect_ref: record.state.revocation_effect_ref,
          revoked_at: record.state.revoked_at,
        };
        revoked.push({
          ...summary,
          revocation_receipt: crypto.createHmac("sha256", receiptKey)
            .update("archive-revocation\0")
            .update(canonicalJson(summary))
            .digest("hex"),
        });
      }
      revoked.sort((left, right) => left.backup_ref.localeCompare(right.backup_ref));
      const observedMemberRegistry = revoked.map((entry) => ({
        backup_ref: entry.backup_ref,
        backup_digest: entry.backup_digest,
        artifact_inventory_digest: entry.artifact_inventory_digest,
        seal_effect_ref: entry.seal_effect_ref,
        seal_ref: entry.seal_ref,
        sealed_archive_digest: entry.sealed_archive_digest,
      }));
      if (canonicalJson(observedMemberRegistry) !== canonicalJson(request.member_archive_registry)
        || digest(canonicalJson(observedMemberRegistry)) !== request.member_archive_registry_digest) {
        throw new Error("test member archive registry mismatch");
      }
      const retirementBody = {
        version: 1,
        status: "retired",
        ...binding,
        artifact_handle: request.artifact_handle,
        reason_ref: request.reason_ref,
        retirement_effect_ref: request.retirement_effect_ref,
        retired_at: request.requested_at,
        revocation_policy: REVOCATION_POLICY,
        member_archive_registry_digest: request.member_archive_registry_digest,
        revoked_archives: revoked,
        revoked_archives_digest: digest(canonicalJson(revoked)),
        active_archive_count: 0,
        production_ready: false,
        hil_verified: false,
        backup_media_erasure_attested: false,
      };
      const retirement = {
        ...retirementBody,
        retirement_receipt: crypto.createHmac("sha256", receiptKey)
          .update("artifact-retirement\0")
          .update(canonicalJson(retirementBody))
          .digest("hex"),
      };
      retirements.set(request.artifact_handle, retirement);
      return cloneJson(retirement);
    },

    read_artifact_retirement(request) {
      const retirement = retirements.get(request.artifact_handle);
      return retirement ? cloneJson(retirement) : null;
    },
  };

  const port = createOperatorBackupKeyCustodyPort({
    version: 1,
    ...binding,
    ...callbacks,
  });

  return Object.freeze({
    port,
    destroy() {
      for (const record of archives.values()) {
        if (record.key) record.key.fill(0);
      }
      receiptKey.fill(0);
    },
  });
}

module.exports = Object.freeze({
  createInProcessBackupKeyCustodyFixture,
});
