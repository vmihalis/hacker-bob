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
const path = require("path");
const { types: utilTypes } = require("node:util");

// Capture the data-shape intrinsics at trusted module load. The production
// signer owner must not let a later Array/Object prototype mutation turn option
// validation into a caller-controlled branch.
const arrayIsArray = Array.isArray;
const arrayEvery = Function.call.bind(Array.prototype.every);
const arrayFind = Function.call.bind(Array.prototype.find);
const arrayIncludes = Function.call.bind(Array.prototype.includes);
const arrayMap = Function.call.bind(Array.prototype.map);
const arraySome = Function.call.bind(Array.prototype.some);
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Function.call.bind(Object.prototype.hasOwnProperty);
const reflectOwnKeys = Reflect.ownKeys;

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

// Hardened Mechanism-A probe for a production signing owner.  Unlike the
// legacy verdict probe above, this binds one exact private-key inode to an
// exact owner-only custody subtree and rechecks the whole parent chain around
// a no-follow descriptor open.  `custodyRoot` is the outer trusted root (for
// Plane-PH this is the exact session directory); `expectedRoot` is the
// component-owned root below it (for example experiment-trust).  Returning a
// path-less structural projection lets an owner port bind the proof without
// exposing a signer home or private-key pathname to model-facing consumers.
function probeExactSigningKeyPathIsolation(keyPathInput, options = {}) {
  if (typeof keyPathInput !== "string" || keyPathInput.length === 0
      || !path.isAbsolute(keyPathInput) || path.normalize(keyPathInput) !== keyPathInput) {
    throw new Error("exact signing-key isolation requires a normalized absolute key path");
  }
  if (options == null || typeof options !== "object" || arrayIsArray(options)
      || utilTypes.isProxy(options)) {
    throw new Error("exact signing-key isolation options must be an object");
  }
  const optionsPrototype = objectGetPrototypeOf(options);
  if (optionsPrototype !== Object.prototype && optionsPrototype !== null) {
    throw new Error("exact signing-key isolation options must be a plain object");
  }
  const optionKeys = reflectOwnKeys(options);
  if (arraySome(optionKeys, (key) => typeof key !== "string")
      || arraySome(optionKeys, (key) => !arrayIncludes(["expectedRoot", "custodyRoot"], key))) {
    throw new Error("exact signing-key isolation options have unknown fields");
  }
  for (const key of optionKeys) {
    const descriptor = objectGetOwnPropertyDescriptor(options, key);
    if (!descriptor || !objectHasOwn(descriptor, "value")
        || descriptor.enumerable !== true) {
      throw new Error(`exact signing-key isolation option ${key} must be an enumerable data field`);
    }
  }
  if (!objectHasOwn(options, "expectedRoot")) {
    throw new Error("exact signing-key isolation requires expectedRoot");
  }
  const expectedRootInput = options.expectedRoot;
  const custodyRootInput = options.custodyRoot == null
    ? expectedRootInput
    : options.custodyRoot;
  for (const [label, value] of [
    ["expectedRoot", expectedRootInput],
    ["custodyRoot", custodyRootInput],
  ]) {
    if (typeof value !== "string" || value.length === 0
        || !path.isAbsolute(value) || path.normalize(value) !== value) {
      throw new Error(`exact signing-key isolation ${label} must be a normalized absolute path`);
    }
  }

  const keyPath = keyPathInput;
  const expectedRoot = expectedRootInput;
  const custodyRoot = custodyRootInput;
  const me = typeof process.getuid === "function" ? process.getuid() : null;
  const signerUid = operatorSignerUid();
  const agentUid = operatorAgentUid();
  const ackPresent = operatorSandboxAckPresent();
  const notRoot = me != null && me !== 0;
  const processIsSigner = me != null && signerUid != null && me === signerUid;
  const agentDistinct = signerUid != null && agentUid != null
    && agentUid !== signerUid && agentUid !== 0;
  const noFollowSupported = Number.isInteger(fs.constants.O_NOFOLLOW)
    && fs.constants.O_NOFOLLOW !== 0;

  const result = {
    version: 1,
    assurance: "mechanism_a_exact_signing_key_path_isolation",
    operator_ack_present: ackPresent,
    process_uid: me,
    declared_signer_uid: signerUid,
    declared_agent_uid: agentUid,
    process_is_signer: processIsSigner,
    agent_distinct: agentDistinct,
    not_root: notRoot,
    expected_root_within_custody_root: false,
    key_within_expected_root: false,
    custody_root_present: false,
    custody_root_real_directory: false,
    custody_root_owner_only_mode: false,
    custody_root_owner_uid: null,
    custody_root_identity: null,
    expected_root_present: false,
    expected_root_real_directory: false,
    expected_root_owner_only_mode: false,
    expected_root_owner_uid: null,
    expected_root_identity: null,
    parent_chain_real_directories: false,
    parent_chain_owner_only_mode: false,
    parent_chain_owned_by_signer: false,
    parent_chain_stable: false,
    nofollow_open_supported: noFollowSupported,
    key_present: false,
    key_regular_file: false,
    key_single_link: false,
    key_owner_only_mode: false,
    key_owner_read_only_mode: false,
    key_owner_uid: null,
    key_identity: null,
    process_owns_key: false,
    key_inode_stable: false,
    isolated: false,
  };

  function freezeResult() {
    return Object.freeze({ ...result });
  }

  function isContained(root, child, { allowSame }) {
    const relative = path.relative(root, child);
    if (relative === "") return allowSame;
    return !path.isAbsolute(relative)
      && relative !== ".."
      && !relative.startsWith(`..${path.sep}`);
  }

  result.expected_root_within_custody_root = isContained(
    custodyRoot,
    expectedRoot,
    { allowSame: true },
  );
  result.key_within_expected_root = isContained(
    expectedRoot,
    keyPath,
    { allowSame: false },
  );
  if (!result.expected_root_within_custody_root || !result.key_within_expected_root) {
    return freezeResult();
  }

  function identity(stats) {
    return `${String(stats.dev)}:${String(stats.ino)}`;
  }

  function ownerOnly(stats) {
    const mode = Number(stats.mode);
    return Number.isInteger(mode) && (mode & 0o077) === 0;
  }

  function sameNode(left, right) {
    return left != null && right != null
      && left.dev === right.dev
      && left.ino === right.ino
      && left.uid === right.uid
      && left.mode === right.mode
      && left.nlink === right.nlink;
  }

  const keyParent = path.dirname(keyPath);
  const relativeParent = path.relative(custodyRoot, keyParent);
  const components = relativeParent === "" ? [] : relativeParent.split(path.sep);
  const chainPaths = [custodyRoot];
  let cursor = custodyRoot;
  for (const component of components) {
    if (!component || component === "." || component === "..") return freezeResult();
    cursor = path.join(cursor, component);
    chainPaths.push(cursor);
  }
  if (cursor !== keyParent || !arrayIncludes(chainPaths, expectedRoot)) return freezeResult();

  const chainBefore = [];
  try {
    for (const directoryPath of chainPaths) {
      chainBefore.push({ directoryPath, stats: fs.lstatSync(directoryPath) });
    }
  } catch {
    return freezeResult();
  }
  const custodyEntry = chainBefore[0];
  const expectedEntry = arrayFind(
    chainBefore,
    (entry) => entry.directoryPath === expectedRoot,
  );
  result.custody_root_present = true;
  result.custody_root_owner_uid = custodyEntry.stats.uid;
  result.custody_root_identity = identity(custodyEntry.stats);
  result.custody_root_real_directory = custodyEntry.stats.isDirectory()
    && !custodyEntry.stats.isSymbolicLink();
  result.custody_root_owner_only_mode = ownerOnly(custodyEntry.stats);
  if (expectedEntry) {
    result.expected_root_present = true;
    result.expected_root_owner_uid = expectedEntry.stats.uid;
    result.expected_root_identity = identity(expectedEntry.stats);
    result.expected_root_real_directory = expectedEntry.stats.isDirectory()
      && !expectedEntry.stats.isSymbolicLink();
    result.expected_root_owner_only_mode = ownerOnly(expectedEntry.stats);
  }
  result.parent_chain_real_directories = arrayEvery(chainBefore, ({ stats }) => (
    stats.isDirectory() && !stats.isSymbolicLink()
  ));
  result.parent_chain_owner_only_mode = arrayEvery(
    chainBefore,
    ({ stats }) => ownerOnly(stats),
  );
  result.parent_chain_owned_by_signer = signerUid != null
    && arrayEvery(chainBefore, ({ stats }) => stats.uid === signerUid);
  if (!result.parent_chain_real_directories
      || !result.parent_chain_owner_only_mode
      || !result.parent_chain_owned_by_signer) {
    return freezeResult();
  }

  let keyBefore;
  try {
    keyBefore = fs.lstatSync(keyPath);
  } catch {
    return freezeResult();
  }
  result.key_present = true;
  result.key_owner_uid = keyBefore.uid;
  result.key_identity = identity(keyBefore);
  result.key_regular_file = keyBefore.isFile() && !keyBefore.isSymbolicLink();
  result.key_single_link = keyBefore.nlink === 1;
  result.key_owner_only_mode = ownerOnly(keyBefore);
  result.key_owner_read_only_mode = Number.isInteger(Number(keyBefore.mode))
    && (Number(keyBefore.mode) & 0o777) === 0o400;
  result.process_owns_key = me != null && keyBefore.uid === me;
  if (!result.key_regular_file || !result.key_single_link
      || !result.key_owner_only_mode || !result.key_owner_read_only_mode
      || !result.process_owns_key || !noFollowSupported) {
    return freezeResult();
  }

  let descriptor = null;
  let descriptorStats = null;
  try {
    descriptor = fs.openSync(
      keyPath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
    );
    descriptorStats = fs.fstatSync(descriptor);
  } catch {
    return freezeResult();
  } finally {
    if (descriptor != null) {
      try { fs.closeSync(descriptor); } catch {}
    }
  }

  let keyAfter;
  let chainAfter;
  try {
    keyAfter = fs.lstatSync(keyPath);
    chainAfter = arrayMap(chainBefore, ({ directoryPath }) => ({
      directoryPath,
      stats: fs.lstatSync(directoryPath),
    }));
  } catch {
    return freezeResult();
  }
  result.key_inode_stable = sameNode(keyBefore, descriptorStats)
    && sameNode(keyBefore, keyAfter)
    && descriptorStats.isFile()
    && descriptorStats.nlink === 1;
  result.parent_chain_stable = chainAfter.length === chainBefore.length
    && arrayEvery(chainAfter, (entry, index) => (
      entry.directoryPath === chainBefore[index].directoryPath
      && sameNode(entry.stats, chainBefore[index].stats)
    ));
  result.isolated = Boolean(
    ackPresent
      && processIsSigner
      && agentDistinct
      && notRoot
      && result.expected_root_within_custody_root
      && result.key_within_expected_root
      && result.custody_root_real_directory
      && result.custody_root_owner_only_mode
      && result.expected_root_real_directory
      && result.expected_root_owner_only_mode
      && result.parent_chain_real_directories
      && result.parent_chain_owner_only_mode
      && result.parent_chain_owned_by_signer
      && result.parent_chain_stable
      && result.key_regular_file
      && result.key_single_link
      && result.key_owner_only_mode
      && result.key_owner_read_only_mode
      && result.process_owns_key
      && result.key_inode_stable
      && noFollowSupported,
  );
  return freezeResult();
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
  probeExactSigningKeyPathIsolation,
  evaluateSandboxIsolation,
  recordSandboxIsolationAttestation,
  readSandboxIsolationAttestation,
};
