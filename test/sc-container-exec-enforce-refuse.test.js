"use strict";

// HIGH-1 PRIMARY MECHANISM — REFUSE-UNDER-ENFORCE at the SC seam source.
//
// On an isolated signer (the live key probe says isolated) under enforce, with NO
// SC-toolchain image (the container route unavailable), the seam REFUSES rather than
// running the SC tool host-as-signer — so a host-as-signer SC run never even
// produces a forgeable row. Under degrade it still degrades loud; on a same-uid
// (non-isolated) box it degrades exactly as before (CONSTRAINT 7 backward-compat).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  scSubprocessContainerExec,
  SC_ISOLATION_REFUSED_CODE,
  SC_TOOLCHAIN_IMAGE_ENV,
} = require("../mcp/domains/blockchain/smart-contracts/sc-container-exec.js");
const { handoffSigningPrivateKeyPath } = require("../mcp/core/io/paths.js");
const {
  SANDBOX_ATTESTATION_MODE_ENV,
  SANDBOX_SIGNER_UID_ENV,
  SANDBOX_AGENT_UID_ENV,
} = require("../mcp/core/ledger-integrity/sandbox-isolation-attest.js");

const DOMAIN = "sc-refuse.example.com";

function withEnv(overrides, fn) {
  const keys = Object.keys(overrides);
  const prev = {};
  for (const k of keys) prev[k] = process.env[k];
  for (const k of keys) {
    if (overrides[k] === undefined) delete process.env[k];
    else process.env[k] = overrides[k];
  }
  try {
    return fn();
  } finally {
    for (const k of keys) {
      if (prev[k] === undefined) delete process.env[k];
      else process.env[k] = prev[k];
    }
  }
}

// Stub the structural Mechanism-A isolated signer so probeVerdictLedgerKeyIsolation
// reports isolated:true (owner-only 0400 key owned by this process == declared
// signer, distinct non-root declared agent uid, not root).
function withStructuralIsolatedKey(signerUid, agentUid, fn) {
  const realLstat = fs.lstatSync;
  const realGetuid = process.getuid;
  const keyPath = handoffSigningPrivateKeyPath(DOMAIN);
  fs.lstatSync = function stubLstat(p) {
    if (p === keyPath) return { uid: signerUid, mode: 0o400, isFile: () => true };
    return realLstat.apply(fs, arguments);
  };
  process.getuid = () => signerUid;
  return withEnv({
    [SANDBOX_SIGNER_UID_ENV]: String(signerUid),
    [SANDBOX_AGENT_UID_ENV]: String(agentUid),
  }, () => {
    try {
      return fn();
    } finally {
      fs.lstatSync = realLstat;
      process.getuid = realGetuid;
    }
  });
}

function withNoImage(fn) {
  return withEnv({ [SC_TOOLCHAIN_IMAGE_ENV]: undefined }, fn);
}

test("enforce + isolated signer + no image: the seam REFUSES (throws sc_isolation_refused) instead of host-as-signer", () => {
  withEnv({ [SANDBOX_ATTESTATION_MODE_ENV]: "enforce" }, () => withNoImage(() => {
    withStructuralIsolatedKey(424242, 1000, () => {
      assert.throws(
        () => scSubprocessContainerExec(
          process.execPath, ["-e", ""],
          { stdio: ["ignore", "ignore", "ignore"], targetDomain: DOMAIN },
          { dockerAvailable: false },
        ),
        (err) => err && err.code === SC_ISOLATION_REFUSED_CODE,
        "an isolated signer under enforce with no image must REFUSE rather than run host-as-signer",
      );
    });
  }));
});

test("degrade + isolated signer + no image: REFUSES (an isolated signer never runs agent SC as the signer, in ANY mode)", () => {
  // On an isolated-signer box the host-as-signer SC run would let agent code read
  // the 0400 key and forge a MAC-valid row for ANY keyed ledger, so the refuse
  // fires regardless of mode (covering all 7 SC families, not just foundry's
  // container_isolated-tagged row). Degrade only keeps producing on an UN-isolated
  // box, where the probe is not isolated and the refuse never fires.
  withEnv({ [SANDBOX_ATTESTATION_MODE_ENV]: "degrade" }, () => withNoImage(() => {
    withStructuralIsolatedKey(424242, 1000, () => {
      assert.throws(
        () => scSubprocessContainerExec(
          process.execPath, ["-e", ""],
          { stdio: ["ignore", "ignore", "ignore"], targetDomain: DOMAIN },
          { dockerAvailable: false },
        ),
        (err) => err && err.code === "sc_isolation_refused",
        "an isolated signer with no image must REFUSE under degrade too, not run host-as-signer",
      );
    });
  }));
});

test("enforce + same-uid (non-isolated) box + no image: DEGRADES as before (CONSTRAINT 7)", () => {
  // No structural stub: the real probe on a same-uid box (no distinct signer/agent
  // uids declared) reports isolated:false, so the refuse never fires.
  withEnv({
    [SANDBOX_ATTESTATION_MODE_ENV]: "enforce",
    [SANDBOX_SIGNER_UID_ENV]: undefined,
    [SANDBOX_AGENT_UID_ENV]: undefined,
  }, () => withNoImage(() => {
    const child = scSubprocessContainerExec(
      process.execPath, ["-e", ""],
      { stdio: ["ignore", "ignore", "ignore"], targetDomain: DOMAIN },
      { dockerAvailable: false },
    );
    assert.equal(child.container_isolated, false, "a same-uid box degrades (not refuses) even under enforce");
    try { child.kill("SIGKILL"); } catch {}
  }));
});

test("enforce + isolated signer + no targetDomain: degrades (cannot probe domain-less, fails safe to degrade)", () => {
  withEnv({ [SANDBOX_ATTESTATION_MODE_ENV]: "enforce" }, () => withNoImage(() => {
    withStructuralIsolatedKey(424242, 1000, () => {
      // baseOpts carries NO targetDomain -> the seam cannot probe -> it degrades
      // (loud + gate-downgraded) rather than refuse blindly.
      const child = scSubprocessContainerExec(
        process.execPath, ["-e", ""],
        { stdio: ["ignore", "ignore", "ignore"] },
        { dockerAvailable: false },
      );
      assert.equal(child.container_isolated, false);
      try { child.kill("SIGKILL"); } catch {}
    });
  }));
});
