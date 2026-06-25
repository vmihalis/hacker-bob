"use strict";

// Signing-key isolation self-attestation (Mechanism A).
//
// Under Mechanism A the operator runs the WHOLE MCP server AS the signer uid
// (scripts/launch-bob-signer.sh: exec sudo -u SIGNER node mcp/server.js) and the
// server signs every verdict-ledger row in-process. The signing key
// (.handoff-signing-key.json / .handoff-signing-key-ed25519.json) is born
// signer-owned 0400 in the signer's session tree. The threat actor is the AGENT
// — a DIFFERENT process running at a DIFFERENT uid (the operator's invoking uid).
// The structural close is that the agent uid gets EACCES on the 0400
// signer-owned key by OS discretionary access control; the server itself OWNS
// and CAN read its own key, which is required for signing to work.
//
// This module is the truth channel for that posture. The probe runs FROM INSIDE
// THE SIGNER. Its legs split into two honestly-distinguished classes:
//
//   MEASURED (structural facts the model cannot fake — getuid/lstat on the real
//   key, read live at probe time):
//   (a) the key is owner-ONLY (mode & 0o077 === 0);
//   (b) this process OWNS the key (getuid === owner uid);
//   (c) this process IS the declared signer (getuid === BOB_SANDBOX_SIGNER_UID);
//   (e) this process (the signer) is NOT root (root bypasses DAC).
//
//   OPERATOR-ASSERTED (a trust INPUT the probe binds to but cannot itself
//   structurally measure):
//   (d) the declared agent uid (BOB_SANDBOX_AGENT_UID) is present, distinct from
//       the signer uid, AND not root. This is the operator's DECLARATION of the
//       uid the agent runs under — the probe has no way to independently observe
//       the agent process's uid, so the operator MUST declare the REAL agent uid
//       (the launcher derives it from SUDO_UID and exports it out of model reach).
//       The probe binds the attestation to that declaration; a root agent bypasses
//       DAC and reads the 0400 key, so a declared agent uid of 0 never yields
//       isolated:true.
//
// So isolated:true is the conjunction of the MEASURED signer-side facts AND the
// operator's ASSERTED agent-uid declaration. The probe proves OS-level uid
// exclusion only on a REAL Mechanism-A box (server at the signer uid, agent at a
// distinct declared uid); it cannot, by itself, observe the agent's uid.
// On a same-uid dev box (no distinct signer/agent uids, or agent_uid===signer_uid,
// or running as root) a leg fails => isolated:false. On a box launched per
// scripts/launch-bob-signer.sh (server at the signer uid, key 0400 signer-owned,
// agent uid distinct, not root) all legs hold => isolated:true.
//
// Design mirrors lab-target-attest.js + enforcement-attest.js:
//   * the ack is an operator ENV var (BOB_SANDBOX_ISOLATION_ACK), out of the
//     model's reach; a typo/unset fails CLOSED (attested:false);
//   * the declared signer/agent uids are operator ENV vars
//     (BOB_SANDBOX_SIGNER_UID / BOB_SANDBOX_AGENT_UID), also out of model reach;
//   * OFF by default — no env ack/uids, attested:false;
//   * the MEASURED legs are not self-asserted: the running uid, the key owner, and
//     the key mode are live lstat/getuid facts the model cannot fake, and the
//     operator-set server env is out of model reach. The ONE operator-asserted leg
//     (the declared agent uid) is a trust input the operator declares, not a fact
//     the probe measures — see leg (d) above.
//
// The probe is observe-only: it NEVER weakens the 0400 enforcement and NEVER
// branches a platform into a bypass.
//
// sandbox-isolation.json is in AUDIT_GRADED_BASENAMES, so the PreToolUse
// write-guard blocks any agent Write to it. Only bob_init_session (via
// recordSandboxIsolationAttestation below) writes it, so a prompt-injected
// agent cannot forge a "the signer is isolated" fact.

const fs = require("fs");

// Operator attestation channel. The ack is an ENVIRONMENT variable, NOT a tool
// argument: a model that can call bob_init_session must not be able to assert
// that the signer runs under a separate uid by passing a value it reads from
// its own tool schema. The operator sets BOB_SANDBOX_ISOLATION_ACK to this
// exact token in the MCP server's environment at launch; a running model cannot
// mutate the server process's environment, so this is operator-only even for a
// prompt-injected evaluator with shell access. The token is the agreed env
// contract whose typo/unset fails CLOSED — not a secret, hence fine in source.
const SANDBOX_ISOLATION_ACK_TOKEN = "i-run-the-bob-signer-under-a-separate-os-uid";
const SANDBOX_ISOLATION_ACK_ENV = "BOB_SANDBOX_ISOLATION_ACK";
// The operator also declares the EXACT OS uid the signer runs under, in
// BOB_SANDBOX_SIGNER_UID. The probe binds the attestation to it: attested:true
// requires the keyfile owner uid to equal this declared uid, so a stale ack
// cannot survive a uid change.
const SANDBOX_SIGNER_UID_ENV = "BOB_SANDBOX_SIGNER_UID";
// The operator ALSO declares the uid the AGENT runs under, in
// BOB_SANDBOX_AGENT_UID. Under Mechanism A the MCP server runs AS the signer
// uid and the threat actor is the AGENT — a DIFFERENT process at a different
// uid. The probe asserts that agent uid is DISTINCT from the signer uid, so the
// agent is excluded from the 0400 signer-owned key by OS discretionary access
// control. The launcher derives it from the invoking (SUDO_UID) uid and exports
// it into the server env (out of model reach, exactly like the ack/signer-uid
// channels). A malformed or absent value fails CLOSED (null => isolated:false).
const SANDBOX_AGENT_UID_ENV = "BOB_SANDBOX_AGENT_UID";

const SANDBOX_ISOLATION_BASENAME = "sandbox-isolation.json";

// Bumped when the probe record shape changes so a stale-shape artifact fails the
// reader's version check (fail-closed). The structural Mechanism-A probe record
// replaces the inverted readability fields, so the on-disk shape changed.
const SANDBOX_ISOLATION_SCHEMA_VERSION = 2;

// Verdict-level attestation mode. The operator declares it in the SERVER
// environment (BOB_SANDBOX_ATTESTATION_MODE), out of the model's reach, exactly
// like the ack/uid channels above. Resolution:
//   * an explicit "enforce" or "degrade" is honored on EVERY platform;
//   * unset, malformed, or any other value defaults to "degrade" on every
//     platform — a LOUD advisory downgrade, never a silent disable.
// DEGRADE-DEFAULT, ENFORCE OPT-IN: the common fleet deployment is same-uid (the
// harness spawns the MCP server and the agent's Bash at the same uid), so the
// live isolation probe is always isolated:false there. Defaulting to enforce on
// linux would HARD-BLOCK every verdict-ledger-backed reportable medium+ finding
// on every unconfigured linux box — a fleet-wide block of legitimate findings.
// Degrade keeps producing findings as a loud advisory downgrade (the no-rubber-
// stamp stance: it NEVER silently trusts a non-isolated SC verdict; it downgrades
// to advisory with remediation pointing at scripts/launch-bob-signer.sh). enforce
// is the operator's deliberate opt-in for a box that IS configured with a
// dedicated signer uid — scripts/launch-bob-signer.sh sets it explicitly — where
// the allow branch is reachable and a hard block is meaningful.
// "enforce" BLOCKS a verdict-ledger-backed reportable medium+ claim when the
// live probe cannot prove signer isolation; "degrade" downgrades that claim to
// advisory with a loud warning. Neither posture silently disables.
const SANDBOX_ATTESTATION_MODE_ENV = "BOB_SANDBOX_ATTESTATION_MODE";

function resolveSandboxAttestationMode(env = process.env, platform = process.platform) {
  const raw = env[SANDBOX_ATTESTATION_MODE_ENV];
  if (raw === "enforce" || raw === "degrade") {
    return Object.freeze({ mode: raw, platform, defaulted: false });
  }
  // Unset, malformed, or any other value: degrade-default on EVERY platform. This
  // is the loud-advisory posture (never a silent disable); enforce is the
  // operator's explicit opt-in for a configured isolated-signer deployment.
  return Object.freeze({ mode: "degrade", platform, defaulted: true });
}

// The operator-only consent gate: true iff the exact ack token is set in the
// server environment. Read ONLY from process.env — never from a tool argument
// or the published schema — so a prompt-injected evaluator cannot satisfy it.
function operatorSandboxAckPresent() {
  return process.env[SANDBOX_ISOLATION_ACK_ENV] === SANDBOX_ISOLATION_ACK_TOKEN;
}

// The operator-declared signer uid (from BOB_SANDBOX_SIGNER_UID), parsed to a
// non-negative integer, or null when unset/malformed. Env-only, out of model
// reach. A malformed value fails CLOSED (null → attested:false). The optional
// `env` arg (default process.env) lets a test resolve the uid against a stub
// env without mutating the real process environment; production callers pass
// nothing and read process.env.
function operatorSignerUid(env = process.env) {
  return parseUidEnv(env[SANDBOX_SIGNER_UID_ENV]);
}

// The operator-declared agent uid (from BOB_SANDBOX_AGENT_UID), parsed the same
// way. The probe requires it to be present, distinct from the signer uid, AND not
// root so the agent is excluded by OS DAC from the signer-owned key (a root agent
// bypasses DAC). Env-only, out of model reach; a malformed or absent value fails
// CLOSED (null => isolated:false). A declared 0 IS parsed (recorded honestly in the
// forensic declared_agent_uid) but the agent_distinct conjunction drives
// isolated:false. The optional `env` arg (default process.env) is for the same
// stub-env use as operatorSignerUid above.
function operatorAgentUid(env = process.env) {
  return parseUidEnv(env[SANDBOX_AGENT_UID_ENV]);
}

// Shared non-negative-integer uid parser: a non-negative decimal integer or null
// for any malformed/absent value. Hex, signs, decimals, and whitespace fail
// closed to null.
function parseUidEnv(raw) {
  if (raw == null) return null;
  const trimmed = String(raw).trim();
  if (!/^\d+$/.test(trimmed)) return null;
  const uid = Number.parseInt(trimmed, 10);
  if (!Number.isInteger(uid) || uid < 0) return null;
  return uid;
}

// The truth channel. Probe whether the AGENT uid is OS-excluded from the signer
// key. Returns a frozen self-describing record. Under Mechanism A the MCP server
// runs AS the signer uid and signs in-process, so the server OWNS and CAN read
// its own key — the threat actor is the AGENT (a DIFFERENT process at a
// different uid), not the signer reading its own key. The probe therefore runs
// FROM INSIDE THE SIGNER and asserts the AGENT is excluded by OS discretionary
// access control. isolated:true requires ALL of (legs a/b/c/e are MEASURED
// structural facts; leg d is an OPERATOR-ASSERTED trust input — see the file header):
//   (a) owner_only_mode — the key is present and owner-ONLY ((mode & 0o077)===0,
//       no group/other read/write/exec), so only its owner can read it; [MEASURED]
//   (b) process_owns_key — getuid() === the key's owner uid (this process owns it); [MEASURED]
//   (c) process_is_signer — getuid() === the operator-declared signer uid; [MEASURED]
//   (d) agent_distinct — the OPERATOR-DECLARED agent uid is present, distinct from
//       the signer uid, AND not root (a root agent bypasses DAC and reads the key).
//       The probe binds to this declaration; it cannot itself measure the agent's
//       uid, so the operator must declare the REAL agent uid; [OPERATOR-ASSERTED]
//   (e) not_root — getuid() !== 0 (root bypasses DAC entirely). [MEASURED]
// On a same-uid dev box (no distinct signer/agent uids, or agent_uid===signer_uid,
// or running as root) the relevant leg fails => isolated:false. A key that is not
// present cannot have its isolation proven, so it fails CLOSED.
function probeSigningKeyIsolation(domain) {
  const { handoffSigningKeyPath } = require("./paths.js");
  return probeKeyPathIsolation(handoffSigningKeyPath(domain));
}

// The N5 verdict gate consumes a probe of the ed25519 PRIVATE key, not the
// symmetric key: that private key is the secret that actually backs the four
// reportable verdict ledgers (offensive/invariant/repro/freeze). Under
// Mechanism A both keys live in the same signer-uid-owned 0700 session tree, so
// in a correctly isolated deployment both probe isolated:true; but the gate must
// probe the SPECIFIC secret it is protecting, so a deployment that somehow left
// the ed25519 key readable while the symmetric key was isolated still fails the
// gate. The symmetric handoff-provenance key is covered by the SAME boundary but
// is not separately gated this cycle (it backs wave routing, not a reportable
// claim — see the residual notes in the gate module).
function probeVerdictLedgerKeyIsolation(domain) {
  const { handoffSigningPrivateKeyPath } = require("./paths.js");
  return probeKeyPathIsolation(handoffSigningPrivateKeyPath(domain));
}

// Shared probe body: the Mechanism-A isolation test against a specific key path,
// run FROM INSIDE THE SIGNER. isolated:true requires legs (a)-(e) documented
// above — the MEASURED legs (a/b/c/e) are live lstat/getuid facts, leg (d) binds
// the OPERATOR-ASSERTED agent-uid declaration. No "the server cannot read its own
// key" simulation is required (that simulation is impossible on a correctly
// isolated Mechanism-A box, where the server IS the signer and CAN read its own
// 0400 key). Kept parameterized so the init-time forensic probe (symmetric key)
// and the N5 verdict gate (ed25519 private key) share one implementation.
function probeKeyPathIsolation(keyPath) {
  const me = typeof process.getuid === "function" ? process.getuid() : null;
  const signerUid = operatorSignerUid();
  const agentUid = operatorAgentUid();

  let stat;
  try {
    stat = fs.lstatSync(keyPath);
  } catch {
    // Cannot prove isolation of a key that is not there — fail closed.
    return Object.freeze({
      key_present: false,
      owner_only_mode: false,
      owner_uid: null,
      process_uid: me,
      process_owns_key: false,
      process_is_signer: false,
      declared_signer_uid: signerUid,
      declared_agent_uid: agentUid,
      agent_distinct: false,
      not_root: me != null && me !== 0,
      isolated: false,
    });
  }

  const owner_uid = stat.uid;
  // (a) owner-ONLY mode: no group/other rwx. A mode-less stat (a test stub or a
  // stat shape without mode bits) fails CLOSED to owner_only_mode:false — without
  // the Number.isInteger guard a NaN/undefined mode coerces to 0 and (0 & 0o077)===0
  // is TRUE, mis-proving a mode-less key as owner-only (a fail-open). The real lstat
  // always carries integer mode bits, so this only ever rejects a degenerate stat.
  const mode = Number(stat.mode);
  const owner_only_mode = Number.isInteger(mode) && (mode & 0o077) === 0;
  // (b) this process owns the key.
  const process_owns_key = me != null && owner_uid === me;
  // (c) this process is the operator-declared signer.
  const process_is_signer = me != null && signerUid != null && me === signerUid;
  // (d) the operator-declared agent uid is present AND distinct from the signer AND
  // not root. agentUid 0 = root agent bypasses DAC -> can read the 0400 signer key
  // regardless of the signer uid -> never isolated. parseUidEnv still accepts 0
  // (so declared_agent_uid records 0 honestly for forensics), but the conjunction
  // here drives isolated false.
  const agent_distinct = signerUid != null && agentUid != null
    && agentUid !== signerUid && agentUid !== 0;
  // (e) not running as root (root bypasses DAC).
  const not_root = me != null && me !== 0;

  const isolated = Boolean(
    owner_only_mode
      && process_owns_key
      && process_is_signer
      && agent_distinct
      && not_root,
  );
  return Object.freeze({
    key_present: true,
    owner_only_mode,
    owner_uid,
    process_uid: me,
    process_owns_key,
    process_is_signer,
    declared_signer_uid: signerUid,
    declared_agent_uid: agentUid,
    agent_distinct,
    not_root,
    isolated,
  });
}

// Combine the live probe with the operator env channel. attested:true requires
// ALL of: the ack token present AND a declared signer uid AND the probe proves
// isolation (legs (a)-(e), which already subsume process==signer and
// agent-distinct) AND the keyfile owner uid equals the declared signer uid. No
// ack, no declared uid, or a non-isolated layout => attested:false. The ack +
// owner==declared bind is the HUMAN-attestation layer on top of the OS-enforced
// facts probe.isolated already proves. Nothing branches on this value at init —
// it is forensic; the gate recomputes the same posture off the live probe.
function evaluateSandboxIsolation(domain) {
  const probe = probeSigningKeyIsolation(domain);
  const ackPresent = operatorSandboxAckPresent();
  const declaredUid = operatorSignerUid();
  const attested = Boolean(
    ackPresent
      && declaredUid != null
      && probe.isolated
      && probe.owner_uid === declaredUid,
  );
  return {
    attested,
    probe,
    operator: {
      ack_present: ackPresent,
      declared_signer_uid: declaredUid,
    },
  };
}

// Persist the isolation posture as an audit-graded session artifact. The caller
// (initSession) must already hold the session lock, must have created the
// session directory, AND must have already ensured the signing key — the probe
// lstat/opens the key file itself, the inverse ordering from lab-authorization
// (which records before the key is ensured). Unlike lab-authorization (which
// no-ops when there is no attestation), this ALWAYS writes a forensic record so
// the artifact is a positive audit fact whether attested is true or false.
function recordSandboxIsolationAttestation(domain) {
  const { sandboxIsolationPath } = require("./paths.js");
  const { writeFileAtomic } = require("./storage.js");
  const evaluated = evaluateSandboxIsolation(domain);
  const record = {
    schema_version: SANDBOX_ISOLATION_SCHEMA_VERSION,
    target_domain: domain,
    attested: evaluated.attested,
    recorded_at: new Date().toISOString(),
    probe: {
      key_present: evaluated.probe.key_present,
      owner_only_mode: evaluated.probe.owner_only_mode,
      owner_uid: evaluated.probe.owner_uid,
      process_uid: evaluated.probe.process_uid,
      process_owns_key: evaluated.probe.process_owns_key,
      process_is_signer: evaluated.probe.process_is_signer,
      declared_signer_uid: evaluated.probe.declared_signer_uid,
      declared_agent_uid: evaluated.probe.declared_agent_uid,
      agent_distinct: evaluated.probe.agent_distinct,
      not_root: evaluated.probe.not_root,
      isolated: evaluated.probe.isolated,
    },
    operator: {
      ack_present: evaluated.operator.ack_present,
      declared_signer_uid: evaluated.operator.declared_signer_uid,
    },
    platform: process.platform,
  };
  writeFileAtomic(
    sandboxIsolationPath(domain),
    `${JSON.stringify(record, null, 2)}\n`,
  );
  return Object.freeze(record);
}

// Fail-closed reader. Returns { attested, source } and never trusts a forged
// field beyond the boolean the artifact stores. On an absent file, a parse
// error, or a record missing the validated shape => { attested:false,
// source:"absent_or_corrupt" }. The persisted attested boolean must be
// LITERALLY true to read back as attested. Because nothing GATES on this value,
// the read is forensic only — the validation exists so a future guardian that
// DOES gate inherits a fail-closed reader rather than a permissive one.
function readSandboxIsolationAttestation(domain) {
  if (!domain) return { attested: false, source: "absent_or_corrupt" };
  try {
    const { sandboxIsolationPath } = require("./paths.js");
    const { readJsonFile } = require("./storage.js");
    const doc = readJsonFile(sandboxIsolationPath(domain), {
      label: SANDBOX_ISOLATION_BASENAME,
    });
    if (doc == null || typeof doc !== "object" || Array.isArray(doc)) {
      return { attested: false, source: "absent_or_corrupt" };
    }
    if (doc.schema_version !== SANDBOX_ISOLATION_SCHEMA_VERSION) {
      return { attested: false, source: "absent_or_corrupt" };
    }
    if (doc.attested !== true) {
      return { attested: false, source: "recorded" };
    }
    return { attested: true, source: "recorded" };
  } catch {
    return { attested: false, source: "absent_or_corrupt" };
  }
}

module.exports = {
  SANDBOX_ISOLATION_ACK_ENV,
  SANDBOX_ISOLATION_ACK_TOKEN,
  SANDBOX_SIGNER_UID_ENV,
  SANDBOX_AGENT_UID_ENV,
  SANDBOX_ATTESTATION_MODE_ENV,
  SANDBOX_ISOLATION_BASENAME,
  SANDBOX_ISOLATION_SCHEMA_VERSION,
  operatorSandboxAckPresent,
  operatorSignerUid,
  operatorAgentUid,
  resolveSandboxAttestationMode,
  probeSigningKeyIsolation,
  probeVerdictLedgerKeyIsolation,
  evaluateSandboxIsolation,
  recordSandboxIsolationAttestation,
  readSandboxIsolationAttestation,
};
