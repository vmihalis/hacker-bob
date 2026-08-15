"use strict";

// Signing-key isolation self-attestation (Mechanism A). Proves the truth channel
// is honest and fail-closed. Under Mechanism A the server runs AS the signer uid
// and OWNS its own 0400 key; the threat actor is the AGENT (a different process
// at a different uid). isolated:true requires: the MEASURED signer-side facts (the
// key is owner-only mode, this process owns it AND is the declared signer, the
// process is not root) AND the OPERATOR-ASSERTED agent-uid declaration (the
// declared agent uid is present, distinct from the signer, and not root). The
// declared agent uid is a trust INPUT the operator must set to the REAL agent uid;
// the probe binds to it but cannot itself measure the agent's uid. attested:true
// additionally requires the operator env ack + a matching declared signer uid.
//
// WHAT THESE STUBBED TESTS PROVE (honestly): they stub fs.lstatSync / getuid / the
// operator env from WITHIN THE SAME PROCESS, so they prove the probe's BRANCH
// REACHABILITY and correct wiring (which leg flips which field), NOT live OS-level
// uid exclusion of a real agent process. That a same-uid test CAN rewrite the
// probe's inputs is itself the demonstration that the probe is meaningful only on a
// real cross-uid Mechanism-A box. On a same-uid dev box the agent uid is not
// distinct from the signer, so isolated:false. Nothing gates on the recorded value
// at init (forensic by design).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  SANDBOX_ISOLATION_ACK_ENV,
  SANDBOX_ISOLATION_ACK_TOKEN,
  SANDBOX_SIGNER_UID_ENV,
  SANDBOX_AGENT_UID_ENV,
  SANDBOX_ISOLATION_BASENAME,
  SANDBOX_ISOLATION_SCHEMA_VERSION,
  operatorSandboxAckPresent,
  operatorSignerUid,
  operatorAgentUid,
  probeSigningKeyIsolation,
  evaluateSandboxIsolation,
  recordSandboxIsolationAttestation,
  readSandboxIsolationAttestation,
} = require("../mcp/core/ledger-integrity/sandbox-isolation-attest.js");
const {
  isAuditGradedPath,
  sandboxIsolationPath,
  handoffSigningKeyPath,
  sessionDir,
} = require("../mcp/core/io/paths.js");

// Set/clear the operator env controls (consent ack + declared signer uid +
// declared agent uid) around fn. All three are restored afterward.
function withSandboxEnv(fn, { ack = true, uid = null, agentUid = null } = {}) {
  const prevAck = process.env[SANDBOX_ISOLATION_ACK_ENV];
  const prevUid = process.env[SANDBOX_SIGNER_UID_ENV];
  const prevAgent = process.env[SANDBOX_AGENT_UID_ENV];
  if (ack) process.env[SANDBOX_ISOLATION_ACK_ENV] = SANDBOX_ISOLATION_ACK_TOKEN;
  else delete process.env[SANDBOX_ISOLATION_ACK_ENV];
  if (uid != null) process.env[SANDBOX_SIGNER_UID_ENV] = String(uid);
  else delete process.env[SANDBOX_SIGNER_UID_ENV];
  if (agentUid != null) process.env[SANDBOX_AGENT_UID_ENV] = String(agentUid);
  else delete process.env[SANDBOX_AGENT_UID_ENV];
  try {
    return fn();
  } finally {
    if (prevAck === undefined) delete process.env[SANDBOX_ISOLATION_ACK_ENV];
    else process.env[SANDBOX_ISOLATION_ACK_ENV] = prevAck;
    if (prevUid === undefined) delete process.env[SANDBOX_SIGNER_UID_ENV];
    else process.env[SANDBOX_SIGNER_UID_ENV] = prevUid;
    if (prevAgent === undefined) delete process.env[SANDBOX_AGENT_UID_ENV];
    else process.env[SANDBOX_AGENT_UID_ENV] = prevAgent;
  }
}

// Attest context: a temp HOME for the session root. The session dir for `domain`
// is created so the probe can lstat/open a synthetic key file.
function withTempHome(fn, envOpts = {}) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-sandbox-attest-"));
  process.env.HOME = tempHome;
  try {
    return withSandboxEnv(() => fn(tempHome), envOpts);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
  }
}

// Create a synthetic 0600 signing key for `domain` under the active HOME and
// return its absolute path.
function plantKey(domain) {
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  const keyPath = handoffSigningKeyPath(domain);
  fs.writeFileSync(keyPath, JSON.stringify({ version: 1, key: "x" }), { mode: 0o600 });
  return keyPath;
}

test("operator ack: exact token only; typo/unset fails closed", () => {
  withSandboxEnv(() => {
    assert.equal(operatorSandboxAckPresent(), true);
  }, { ack: true });
  withSandboxEnv(() => {
    assert.equal(operatorSandboxAckPresent(), false);
  }, { ack: false });
  // A typo'd token (trailing space) must fail closed — exact match required.
  const prev = process.env[SANDBOX_ISOLATION_ACK_ENV];
  process.env[SANDBOX_ISOLATION_ACK_ENV] = `${SANDBOX_ISOLATION_ACK_TOKEN} `;
  try {
    assert.equal(operatorSandboxAckPresent(), false);
  } finally {
    if (prev === undefined) delete process.env[SANDBOX_ISOLATION_ACK_ENV];
    else process.env[SANDBOX_ISOLATION_ACK_ENV] = prev;
  }
});

test("operator signer uid: parses non-negative int, else null (fail closed)", () => {
  withSandboxEnv(() => assert.equal(operatorSignerUid(), 501), { uid: 501 });
  withSandboxEnv(() => assert.equal(operatorSignerUid(), 0), { uid: 0 });
  withSandboxEnv(() => assert.equal(operatorSignerUid(), null), { uid: null });
  for (const bad of ["-1", "5x", "abc", "1.5", " ", "0x10"]) {
    const prev = process.env[SANDBOX_SIGNER_UID_ENV];
    process.env[SANDBOX_SIGNER_UID_ENV] = bad;
    try {
      assert.equal(operatorSignerUid(), null, `${JSON.stringify(bad)} must parse to null`);
    } finally {
      if (prev === undefined) delete process.env[SANDBOX_SIGNER_UID_ENV];
      else process.env[SANDBOX_SIGNER_UID_ENV] = prev;
    }
  }
});

test("operator agent uid: parses non-negative int, else null (fail closed)", () => {
  withSandboxEnv(() => assert.equal(operatorAgentUid(), 1000), { agentUid: 1000 });
  withSandboxEnv(() => assert.equal(operatorAgentUid(), 0), { agentUid: 0 });
  withSandboxEnv(() => assert.equal(operatorAgentUid(), null), { agentUid: null });
  for (const bad of ["-1", "5x", "abc", "1.5", " ", "0x10"]) {
    const prev = process.env[SANDBOX_AGENT_UID_ENV];
    process.env[SANDBOX_AGENT_UID_ENV] = bad;
    try {
      assert.equal(operatorAgentUid(), null, `${JSON.stringify(bad)} must parse to null`);
    } finally {
      if (prev === undefined) delete process.env[SANDBOX_AGENT_UID_ENV];
      else process.env[SANDBOX_AGENT_UID_ENV] = prev;
    }
  }
});

test("probe: absent key => isolated:false (cannot prove isolation of a missing key)", () => {
  withTempHome((home) => {
    const probe = probeSigningKeyIsolation("example.com");
    assert.equal(probe.key_present, false);
    assert.equal(probe.isolated, false);
    assert.equal(probe.owner_uid, null);
    void home;
  });
});

test("probe: a same-uid 0600 key with no declared signer/agent uid (the dev reality) => isolated:false", () => {
  withTempHome(() => {
    plantKey("example.com");
    const probe = probeSigningKeyIsolation("example.com");
    assert.equal(probe.key_present, true);
    // The running uid OWNS its own key, but no declared signer/agent uid is set,
    // so the agent is not provably DAC-excluded → not isolated.
    assert.equal(probe.process_owns_key, true);
    assert.equal(probe.process_is_signer, false, "no declared signer uid → not the signer");
    assert.equal(probe.agent_distinct, false, "no declared agent uid → agent not distinct");
    assert.equal(probe.isolated, false);
    if (typeof process.getuid === "function") {
      assert.equal(probe.owner_uid, process.getuid());
      assert.equal(probe.process_uid, process.getuid());
    }
  });
});

test("probe: same declared signer AND agent uid (same-uid dev box, agent==signer) => isolated:false", () => {
  // Even with a planted owner-only key the running process owns AND declares as
  // the signer, an agent uid EQUAL to the signer means the agent is NOT excluded.
  const me = typeof process.getuid === "function" ? process.getuid() : 0;
  withTempHome(() => {
    plantKey("example.com");
    const probe = probeSigningKeyIsolation("example.com");
    assert.equal(probe.process_is_signer, true, "getuid == declared signer");
    assert.equal(probe.agent_distinct, false, "agent uid == signer uid → not distinct");
    assert.equal(probe.isolated, false, "a same-uid agent is the dev-box non-isolated invariant");
  }, { ack: true, uid: me, agentUid: me });
});

test("evaluate: even with ack + matching signer uid, a same-uid agent => attested:false", () => {
  const ownerUid = typeof process.getuid === "function" ? process.getuid() : 0;
  withTempHome(() => {
    plantKey("example.com");
    const evaluated = evaluateSandboxIsolation("example.com");
    // The declared agent uid equals the signer uid (the dev box): the agent is not
    // DAC-excluded, so isolated:false dominates regardless of ack.
    assert.equal(evaluated.probe.isolated, false);
    assert.equal(evaluated.attested, false);
    assert.equal(evaluated.operator.ack_present, true);
    assert.equal(evaluated.operator.declared_signer_uid, ownerUid);
  }, { ack: true, uid: ownerUid, agentUid: ownerUid });
});

// SAME-UID MONKEYPATCH — proves the live probe is NOT same-uid-tamper-resistant.
// This helper stubs fs.lstatSync / process.getuid / the operator env from WITHIN
// THE SAME PROCESS at the SAME uid: that it CAN is the constructive proof that a
// same-uid actor rewrites the probe's inputs at will. So isolated:true here proves
// the allow BRANCH is REACHABLE and correctly wired, NOT live OS-level uid
// exclusion. The genuine OS exclusion holds only on a real Mechanism-A box (server
// at the signer uid, agent at a distinct uid), which no unit test can stand up.
//
// DISTINCT-PER-LEG STUBS: the probe reads THREE independent inputs that a naive
// stub would collapse onto one variable — the key OWNER (lstat.uid), the RUNNING
// uid (process.getuid), and the DECLARED signer uid (env). They are taken as three
// params so a refactor that conflates, e.g., "key owner" with "declared signer"
// is caught. They default to one shared value for the happy-path equality the
// probe legitimately requires (process_owns_key needs getuid===owner;
// process_is_signer needs getuid===declaredSigner), but the positive test asserts
// each probe field (owner_uid / process_uid / declared_signer_uid) separately so a
// conflation surfaces. agentUid is the declared distinct agent. asRoot forces
// getuid()===0 (root bypasses DAC). The stubs restore in a finally (leak-safe,
// scoped per test) even if fn throws.
function withStructuralIsolatedKey(
  signerUid,
  agentUid,
  { mode = 0o400, asRoot = false, keyOwnerUid = signerUid, runningUid = signerUid, declaredSignerUid = signerUid } = {},
  fn,
) {
  const realLstat = fs.lstatSync;
  const realGetuid = process.getuid;
  fs.lstatSync = function stubLstat(p) {
    if (typeof p === "string" && p.endsWith(".handoff-signing-key.json")) {
      return { uid: keyOwnerUid, mode, isFile: () => true };
    }
    return realLstat.apply(fs, arguments);
  };
  process.getuid = () => (asRoot ? 0 : runningUid);
  return withSandboxEnv(() => {
    try {
      return fn();
    } finally {
      fs.lstatSync = realLstat;
      process.getuid = realGetuid;
    }
  }, { ack: true, uid: declaredSignerUid, agentUid });
}

test("probe: owner-only key + process owns it + is the signer + distinct agent + not root => isolated:true", () => {
  withTempHome(() => {
    // The three signer-side inputs (key owner / running uid / declared signer) are
    // pinned to ONE constant only where the probe legitimately requires equality;
    // each is asserted by its OWN probe field below so a leg conflation is caught.
    const SIGNER = 424242;
    const AGENT = 1000;
    withStructuralIsolatedKey(SIGNER, AGENT, {}, () => {
      const probe = probeSigningKeyIsolation("example.com");
      assert.equal(probe.key_present, true);
      assert.equal(probe.owner_only_mode, true);
      assert.equal(probe.process_owns_key, true);
      assert.equal(probe.process_is_signer, true);
      assert.equal(probe.agent_distinct, true);
      assert.equal(probe.not_root, true);
      assert.equal(probe.isolated, true, "a correct Mechanism-A layout => allow is REACHABLE");
      // Assert each independent input via its OWN probe field (not one collapsed
      // value), so conflating key-owner / running-uid / declared-signer is caught.
      assert.equal(probe.owner_uid, SIGNER, "key OWNER field (lstat.uid)");
      assert.equal(probe.process_uid, SIGNER, "RUNNING uid field (getuid)");
      assert.equal(probe.declared_signer_uid, SIGNER, "DECLARED signer uid field (env)");
      assert.equal(probe.declared_agent_uid, AGENT, "DECLARED agent uid field (env)");
      assert.notEqual(probe.declared_agent_uid, probe.declared_signer_uid, "agent uid is a distinct input from the signer uid");
    });
  });
});

test("probe (distinct-per-leg): a key owner != the declared signer breaks isolation (no leg conflation)", () => {
  // Drive the three signer-side inputs to DISTINCT values: the running uid owns the
  // key (process_owns_key true) but the DECLARED signer uid differs, so
  // process_is_signer is false and isolated:false. This fails if a refactor
  // conflated "key owner" / "running uid" with "declared signer".
  withTempHome(() => {
    withStructuralIsolatedKey(0, 1000, {
      keyOwnerUid: 424242, runningUid: 424242, declaredSignerUid: 999999,
    }, () => {
      const probe = probeSigningKeyIsolation("example.com");
      assert.equal(probe.owner_uid, 424242, "key owner is the lstat.uid input");
      assert.equal(probe.process_uid, 424242, "running uid is the getuid input");
      assert.equal(probe.declared_signer_uid, 999999, "declared signer is the env input (distinct)");
      assert.equal(probe.process_owns_key, true, "getuid == key owner");
      assert.equal(probe.process_is_signer, false, "getuid != declared signer => not the signer");
      assert.equal(probe.isolated, false, "a declared-signer != key-owner layout is NOT isolated");
    });
  });
});

test("probe: agent uid EQUAL to signer uid (same-uid dev box) => isolated:false", () => {
  withTempHome(() => {
    withStructuralIsolatedKey(1000, 1000, {}, () => {
      const probe = probeSigningKeyIsolation("example.com");
      assert.equal(probe.agent_distinct, false);
      assert.equal(probe.isolated, false, "agent==signer is the dev-box non-isolated invariant");
    });
  });
});

test("ROOT-AGENT GUARD: declared agent uid 0 (root agent) => agent_distinct:false => isolated:false", () => {
  // A root AGENT bypasses DAC and reads the 0400 signer key regardless of the
  // signer uid, so a declared agent uid of 0 must NEVER yield isolated:true — even
  // with an owner-only key, the signer owning+declaring its own uid, and not-root.
  // The agent uid (0) IS still distinct from the signer uid (424242), so the OLD
  // distinct-only check would have wrongly passed; the new !== 0 leg closes it.
  withTempHome(() => {
    withStructuralIsolatedKey(424242, 0, {}, () => {
      const probe = probeSigningKeyIsolation("example.com");
      assert.equal(probe.owner_only_mode, true, "the key is owner-only (every other leg is isolated)");
      assert.equal(probe.process_owns_key, true);
      assert.equal(probe.process_is_signer, true);
      assert.equal(probe.not_root, true, "the SIGNER is not root");
      assert.equal(probe.declared_agent_uid, 0, "the declared agent uid is recorded honestly as 0 (forensics)");
      assert.equal(probe.agent_distinct, false, "a root agent (uid 0) is never DAC-excluded -> not distinct");
      assert.equal(probe.isolated, false, "a root agent uid must NEVER yield isolated:true");
    });
  });
});

test("probe: declared agent uid UNSET => isolated:false (agent not provably excluded)", () => {
  withTempHome(() => {
    withStructuralIsolatedKey(424242, null, {}, () => {
      const probe = probeSigningKeyIsolation("example.com");
      assert.equal(probe.declared_agent_uid, null);
      assert.equal(probe.agent_distinct, false);
      assert.equal(probe.isolated, false);
    });
  });
});

test("probe: process is NOT the signer (getuid != owner uid) => isolated:false", () => {
  withTempHome(() => {
    // lstat owner = 424242, but getuid is stubbed to 9999 (asRoot:false → 9999).
    const realLstat = fs.lstatSync;
    const realGetuid = process.getuid;
    fs.lstatSync = function stubLstat(p) {
      if (typeof p === "string" && p.endsWith(".handoff-signing-key.json")) {
        return { uid: 424242, mode: 0o400, isFile: () => true };
      }
      return realLstat.apply(fs, arguments);
    };
    process.getuid = () => 9999;
    try {
      withSandboxEnv(() => {
        const probe = probeSigningKeyIsolation("example.com");
        assert.equal(probe.process_owns_key, false, "getuid 9999 != owner 424242");
        assert.equal(probe.process_is_signer, false, "getuid 9999 != declared signer 424242");
        assert.equal(probe.isolated, false);
      }, { ack: true, uid: 424242, agentUid: 1000 });
    } finally {
      fs.lstatSync = realLstat;
      process.getuid = realGetuid;
    }
  });
});

test("probe: group/other-readable key (mode 0o440) => isolated:false (not owner-only)", () => {
  withTempHome(() => {
    withStructuralIsolatedKey(424242, 1000, { mode: 0o440 }, () => {
      const probe = probeSigningKeyIsolation("example.com");
      assert.equal(probe.owner_only_mode, false, "0o440 grants group read → not owner-only");
      assert.equal(probe.isolated, false);
    });
  });
});

test("probe: running AS ROOT (getuid 0) => isolated:false even with distinct declared uids", () => {
  withTempHome(() => {
    withStructuralIsolatedKey(424242, 1000, { asRoot: true }, () => {
      const probe = probeSigningKeyIsolation("example.com");
      assert.equal(probe.not_root, false, "root bypasses DAC");
      assert.equal(probe.isolated, false);
    });
  });
});

test("probe: a MODE-LESS stat (mode undefined/NaN) => owner_only_mode:false + isolated:false (fail CLOSED)", () => {
  // LOW 1: without the Number.isInteger guard, Number(undefined) -> NaN and NaN & 0o077
  // is 0, so (=== 0) is TRUE and a mode-less stat is mis-proven owner-only (a fail-OPEN).
  // The guard fails it CLOSED to owner_only_mode:false (and thus isolated:false). The stub
  // mirrors a structurally-isolated layout in EVERY other leg (process owns + is signer,
  // distinct agent, not root) so the ONLY thing forcing isolated:false is the mode-less stat.
  withTempHome(() => {
    const realLstat = fs.lstatSync;
    const realGetuid = process.getuid;
    fs.lstatSync = function stubLstat(p) {
      if (typeof p === "string" && p.endsWith(".handoff-signing-key.json")) {
        // No `mode` field at all -> stat.mode is undefined -> Number(undefined) is NaN.
        return { uid: 424242, isFile: () => true };
      }
      return realLstat.apply(fs, arguments);
    };
    process.getuid = () => 424242;
    try {
      withSandboxEnv(() => {
        const probe = probeSigningKeyIsolation("example.com");
        assert.equal(probe.owner_only_mode, false, "a mode-less stat fails CLOSED to owner_only_mode:false");
        assert.equal(probe.process_owns_key, true, "every OTHER leg is structurally isolated");
        assert.equal(probe.process_is_signer, true);
        assert.equal(probe.agent_distinct, true);
        assert.equal(probe.not_root, true);
        assert.equal(probe.isolated, false, "the mode-less stat alone forces isolated:false (no fail-open)");
      }, { ack: true, uid: 424242, agentUid: 1000 });
    } finally {
      fs.lstatSync = realLstat;
      process.getuid = realGetuid;
    }
  });
});

test("evaluate: attested:true ONLY with ack + declared signer uid == owner uid + isolated", () => {
  // isolated:true (structural) + ack + matching declared signer uid => attested:true.
  withTempHome(() => {
    withStructuralIsolatedKey(424242, 1000, {}, () => {
      const evaluated = evaluateSandboxIsolation("example.com");
      assert.equal(evaluated.probe.isolated, true);
      assert.equal(evaluated.attested, true);
    });
  });
  // isolated:true but NO ack => attested:false. withStructuralIsolatedKey sets the
  // ack on; override by deleting it inside.
  withTempHome(() => {
    withStructuralIsolatedKey(424242, 1000, {}, () => {
      const prevAck = process.env[SANDBOX_ISOLATION_ACK_ENV];
      delete process.env[SANDBOX_ISOLATION_ACK_ENV];
      try {
        assert.equal(evaluateSandboxIsolation("example.com").attested, false);
      } finally {
        if (prevAck !== undefined) process.env[SANDBOX_ISOLATION_ACK_ENV] = prevAck;
      }
    });
  });
  // isolated:true + ack but a MISMATCHED declared signer uid => the probe binds
  // owner_uid to the declared signer, so a mismatched signer breaks process_is_signer
  // and attested both. Set the declared signer != the key owner.
  withTempHome(() => {
    const realLstat = fs.lstatSync;
    const realGetuid = process.getuid;
    fs.lstatSync = function stubLstat(p) {
      if (typeof p === "string" && p.endsWith(".handoff-signing-key.json")) {
        return { uid: 424242, mode: 0o400, isFile: () => true };
      }
      return realLstat.apply(fs, arguments);
    };
    process.getuid = () => 424242;
    try {
      withSandboxEnv(() => {
        // declared signer 999999 != owner 424242 == getuid → process_is_signer false.
        const evaluated = evaluateSandboxIsolation("example.com");
        assert.equal(evaluated.probe.isolated, false);
        assert.equal(evaluated.attested, false);
      }, { ack: true, uid: 999999, agentUid: 1000 });
    } finally {
      fs.lstatSync = realLstat;
      process.getuid = realGetuid;
    }
  });
});

test("record: always writes a forensic record; attested:false on the same-uid box", () => {
  withTempHome((home) => {
    plantKey("example.com");
    const record = recordSandboxIsolationAttestation("example.com");
    const sidecar = path.join(home, "hacker-bob-sessions", "example.com", "sandbox-isolation.json");
    assert.equal(sandboxIsolationPath("example.com"), sidecar);
    assert.equal(fs.existsSync(sidecar), true);
    const persisted = JSON.parse(fs.readFileSync(sidecar, "utf8"));
    assert.equal(persisted.schema_version, SANDBOX_ISOLATION_SCHEMA_VERSION);
    assert.equal(persisted.target_domain, "example.com");
    // Same-uid readable key: honestly recorded as NOT attested.
    assert.equal(persisted.attested, false);
    assert.equal(record.attested, false);
    assert.equal(persisted.probe.key_present, true);
    assert.equal(persisted.probe.isolated, false);
    assert.equal(typeof persisted.recorded_at, "string");
    assert.equal(persisted.platform, process.platform);
  });
});

test("record + read round-trip; the artifact is audit-graded (agent Write blocked)", () => {
  withTempHome((home) => {
    plantKey("morphic.io");
    recordSandboxIsolationAttestation("morphic.io");
    const read = readSandboxIsolationAttestation("morphic.io");
    // Same-uid box → recorded but not attested.
    assert.equal(read.attested, false);
    assert.equal(read.source, "recorded");
    const sidecar = path.join(home, "hacker-bob-sessions", "morphic.io", "sandbox-isolation.json");
    assert.equal(isAuditGradedPath(sidecar, "morphic.io"), true);
  });
});

test("reader fails closed on an absent artifact", () => {
  withTempHome(() => {
    assert.deepEqual(readSandboxIsolationAttestation("nope.example"), {
      attested: false,
      source: "absent_or_corrupt",
    });
  });
});

test("reader rejects a forged sandbox-isolation.json", () => {
  withTempHome(() => {
    const domain = "forged.example";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });
    // A hand-forged file claiming attested:true must NOT read back as attested
    // unless the schema is valid AND the boolean is literally true. Corrupt
    // shape => absent_or_corrupt; a literal {attested:true} with a valid schema
    // reads back true ONLY because nothing GATES on it (forensic). The forgery
    // that MATTERS — writing this file at all — is blocked by the audit-graded
    // write-guard, asserted separately.
    fs.writeFileSync(sandboxIsolationPath(domain), JSON.stringify({ bogus: true }));
    assert.deepEqual(readSandboxIsolationAttestation(domain), {
      attested: false,
      source: "absent_or_corrupt",
    });
    // Wrong schema_version => fail closed.
    fs.writeFileSync(sandboxIsolationPath(domain), JSON.stringify({ schema_version: 99, attested: true }));
    assert.deepEqual(readSandboxIsolationAttestation(domain), {
      attested: false,
      source: "absent_or_corrupt",
    });
    // Corrupt JSON => fail closed.
    fs.writeFileSync(sandboxIsolationPath(domain), "{not json");
    assert.equal(readSandboxIsolationAttestation(domain).attested, false);
  });
});

test("INERT: recording an attested:false artifact does not change a session init verdict", () => {
  // The artifact is recorded at init but no claim/grade/handoff/verify path reads
  // it. Two sessions — one where the artifact exists, one where it is deleted —
  // must produce an identical init result, proving zero behavior change.
  function initAndStrip(domain, deleteArtifact) {
    return withTempHome((home) => {
      const { initSession } = require("../mcp/core/session/session-state.js");
      const result = JSON.parse(initSession({
        target_domain: domain,
        target_url: `https://${domain}/`,
      }));
      const sidecar = sandboxIsolationPath(domain);
      assert.equal(fs.existsSync(sidecar), true, "init must always write the forensic artifact");
      if (deleteArtifact) fs.unlinkSync(sidecar);
      void home;
      return { lifecycle_state: result.state.lifecycle_state, created: result.created };
    });
  }
  const withArtifact = initAndStrip("inert-a.example", false);
  const withoutArtifact = initAndStrip("inert-b.example", true);
  assert.equal(withArtifact.created, true);
  assert.equal(withoutArtifact.created, true);
  assert.deepEqual(withArtifact, withoutArtifact, "init verdict identical with/without the artifact");
});

void SANDBOX_ISOLATION_BASENAME;
