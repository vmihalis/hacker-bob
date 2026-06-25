#!/usr/bin/env bash
# launch-bob-signer.sh — OPERATOR-run launcher that runs the Hacker Bob MCP
# server under a DEDICATED signer OS uid, so the signing secrets and audit-graded
# ledgers are owned by a uid the agent uid cannot read or raw-write.
#
# This is the load-bearing half of the signer-isolation close. Claude Code spawns
# the MCP server AND the agent's Bash at the SAME uid by default (.mcp.json runs
# `node mcp/server.js` as a stdio child), so peer-uid auth alone cannot tell the
# server apart from the agent's own `node -e`: they are one uid. The only way to
# make the legitimate signer a uid the agent cannot impersonate is to RUN the
# server under a different uid. That is exactly what this launcher does. Once the
# server runs at the signer uid, sessionsRoot() resolves to the signer uid's HOME,
# so the whole session tree (keys + ledgers) is born signer-owned; the agent uid
# then gets EACCES on the keys (cannot forge a MAC) and on the ledgers (cannot
# bypass MCP). No socket or guardian process is needed.
#
# THIS SCRIPT IS NEVER AGENT-SPAWNABLE. It is not referenced from .mcp.json, is
# not a bob_* MCP tool, and is not on any agent tool path. The operator points
# Claude Code's .mcp.json `command` at this launcher (or runs the server as a
# signer-uid launchd/systemd unit on prod). The .mcp.json `command` is
# operator-owned; the genuine close depends on the operator setting it here.
#
# REQUIRED operator inputs (env or flags):
#   BOB_SIGNER_USER        the dedicated OS user to run the server as (e.g. bob-signer)
#   BOB_SANDBOX_SIGNER_UID the numeric uid of that user (bound into the attestation)
# Optional:
#   BOB_SANDBOX_ATTESTATION_MODE  enforce|degrade (default: degrade on every
#                                 platform — a loud advisory downgrade. enforce is
#                                 the opt-in for THIS configured isolated-signer
#                                 deployment; this launcher sets it explicitly below
#                                 so a correctly-launched signer box hard-blocks an
#                                 un-isolated SC verdict.)
#   BOB_SIGNER_HOME        HOME for the signer (default: that user's home dir)
#   BOB_SC_TOOLCHAIN_IMAGE the SC container-isolation channel: the pinned image tag
#                          the smart-contract test/build tools run inside (out of
#                          model reach). On an isolated signer, OMITTING it forces the
#                          host-as-signer degrade, which the server now REFUSES under
#                          enforce (HIGH-1) — so an operator who wants TRUSTED SC
#                          verdicts MUST set it. It is preserved across the sudo drop.
#
# OPERATOR/LAUNCHER-SET (auto-derived, NOT an agent argument):
#   BOB_SANDBOX_AGENT_UID  the uid the AGENT runs under. This launcher derives it
#                          from the invoking uid (SUDO_UID if the operator already
#                          sudo'd to launch, else the current uid) and exports it
#                          into the SERVER's environment (out of model reach). The
#                          in-server isolation probe uses it to prove the agent uid
#                          is DAC-excluded from the signer-owned 0400 key — i.e.
#                          that the declared agent uid is DISTINCT from the signer
#                          uid. A model cannot mutate the server process env, so a
#                          prompt-injected evaluator cannot forge it.
#
# Fail-closed: any missing required input, or an inability to establish the
# signer-owned 0700 session root, aborts WITHOUT launching the server.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_JS="${REPO_ROOT}/mcp/server.js"
ACK_TOKEN="i-run-the-bob-signer-under-a-separate-os-uid"

die() { echo "launch-bob-signer: $*" >&2; exit 1; }

[ -f "${SERVER_JS}" ] || die "cannot find MCP server at ${SERVER_JS}"

SIGNER_USER="${BOB_SIGNER_USER:-}"
SIGNER_UID="${BOB_SANDBOX_SIGNER_UID:-}"
[ -n "${SIGNER_USER}" ] || die "BOB_SIGNER_USER (the dedicated signer OS user) is required"
[ -n "${SIGNER_UID}" ] || die "BOB_SANDBOX_SIGNER_UID (the signer's numeric uid) is required"
case "${SIGNER_UID}" in
  ''|*[!0-9]*) die "BOB_SANDBOX_SIGNER_UID must be a non-negative integer" ;;
esac

# The signer uid MUST differ from the current uid: if the operator runs this as
# the same uid the agent runs as, there is no isolation to establish. Fail closed.
CURRENT_UID="$(id -u)"
[ "${SIGNER_UID}" != "${CURRENT_UID}" ] || \
  die "BOB_SANDBOX_SIGNER_UID (${SIGNER_UID}) equals the current uid; the signer must be a SEPARATE uid"

# Validate SIGNER_USER is a clean username BEFORE any passwd lookup. getent/dscl
# are already safe (no shell expansion), but bounding the input is defense in
# depth and refuses an injection attempt at the door.
case "${SIGNER_USER}" in
  ''|*[!A-Za-z0-9_.-]*) die "BOB_SIGNER_USER has invalid characters (allowed: A-Za-z0-9_.-)" ;;
esac

# Resolve the signer HOME (where sessionsRoot() will live) and the session root.
# NEVER eval a user-controlled string: use a bounded passwd lookup. getent on
# linux, dscl on darwin (which has no getent). Both are pure passwd reads with no
# shell expansion of SIGNER_USER.
if [ -n "${BOB_SIGNER_HOME:-}" ]; then
  SIGNER_HOME="${BOB_SIGNER_HOME}"
elif command -v getent >/dev/null 2>&1; then
  SIGNER_HOME="$(getent passwd "${SIGNER_USER}" | cut -d: -f6)"
elif command -v dscl >/dev/null 2>&1; then
  SIGNER_HOME="$(dscl . -read "/Users/${SIGNER_USER}" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
else
  die "no getent or dscl available to resolve HOME for ${SIGNER_USER}; set BOB_SIGNER_HOME"
fi
[ -n "${SIGNER_HOME}" ] || die "could not resolve HOME for ${SIGNER_USER}"
SESSIONS_ROOT="${SIGNER_HOME}/hacker-bob-sessions"

# Render the custody plan (dir/key modes + owner) from the SINGLE in-repo source
# of truth so the launcher cannot drift from the modes the server actually mints.
DIR_MODE="$(node -e 'const c=require(process.argv[1]);process.stdout.write(c.octalModeString(c.SIGNING_KEY_DIR_MODE))' "${REPO_ROOT}/mcp/lib/signing-key-custody.js")"

# Establish the signer-owned, owner-only session root. Key files minted later by the
# server (ensureHandoffSigningKey / ensureHandoffKeypair) are then born signer-owned
# at their intended modes automatically — the launcher only establishes the uid+dir.
#
# FIRST-RUN ORDERING: when SESSIONS_ROOT does NOT yet exist, mkdir -p as root would
# create it ROOT-owned (uid 0); the foreign-owner refusal below (owner != signer)
# would then abort a clean first run before the chown ever ran. So a root THIS
# launcher just created is born signer-owned right here, BEFORE the refusal block —
# `chown` (non-recursive) on the empty dir is safe (it has no contents to redirect).
# A PRE-EXISTING tree is left untouched and still goes through the full
# foreign-owner + group/other-writable refusal below (the attacker-seeded case is
# preserved). set -euo pipefail keeps a failed chown fatal.
if [ ! -d "${SESSIONS_ROOT}" ]; then
  mkdir -p "${SESSIONS_ROOT}" || die "could not create ${SESSIONS_ROOT}"
  chown "${SIGNER_USER}" "${SESSIONS_ROOT}" || die "could not chown freshly-created ${SESSIONS_ROOT} to ${SIGNER_USER}"
fi

# Before chowning -R as root, REFUSE to operate on a PRE-EXISTING SESSIONS_ROOT that
# is not already safe. A pre-existing tree owned by another uid, OR group/other-
# writable, may have been attacker-seeded (e.g. with a planted symlink); chown -R as
# root over it is a privilege-escalation primitive. A root we JUST created above is
# already signer-owned, so it passes this refusal by construction.
#
# PORTABLE stat (GNU/linux vs BSD/darwin): the two stats DIVERGE on the same flag —
# GNU `stat -f` means --file-system and EXITS 0 with the WRONG value (the filesystem,
# not the file owner), so a `stat -f ... || stat -c ...` chain NEVER falls through on
# GNU and the refusal would operate on garbage. PROBE GNU (`stat -c`) FIRST: on GNU it
# succeeds, so we never reach the BSD form; on BSD `stat -c` fails (BSD has no -c), so
# we fall through to the BSD `stat -f` form. A system with NEITHER form DIES
# (fail-closed) rather than producing a garbage owner/mode. The chosen forms yield the
# REAL owner uid + octal mode on their platform:
#   GNU:  `stat -c '%u'`=owner uid, `stat -c '%a'`=octal mode (e.g. 700)
#   BSD:  `stat -f '%u'`=owner uid, `stat -f '%Lp'`=low 12 mode bits octal (e.g. 700)
if stat -c '%u' "${SESSIONS_ROOT}" >/dev/null 2>&1; then
  STAT_OWNER=(stat -c '%u'); STAT_PERM=(stat -c '%a')
elif stat -f '%u' "${SESSIONS_ROOT}" >/dev/null 2>&1; then
  STAT_OWNER=(stat -f '%u'); STAT_PERM=(stat -f '%Lp')
else
  die "neither GNU (stat -c) nor BSD (stat -f) stat works on ${SESSIONS_ROOT}"
fi
# The forms are now FIXED (not an A || B chain), so a genuine stat failure DIES rather
# than silently producing the wrong field.
ROOT_OWNER_UID="$("${STAT_OWNER[@]}" "${SESSIONS_ROOT}")" \
  || die "could not stat owner of ${SESSIONS_ROOT}"
ROOT_PERM="$("${STAT_PERM[@]}" "${SESSIONS_ROOT}")" \
  || die "could not stat mode of ${SESSIONS_ROOT}"
[ -n "${ROOT_OWNER_UID}" ] || die "could not determine owner uid of ${SESSIONS_ROOT}"
[ -n "${ROOT_PERM}" ] || die "could not determine mode of ${SESSIONS_ROOT}"
# Refuse a foreign-owned tree (anything not already owned by the signer uid).
[ "${ROOT_OWNER_UID}" = "${SIGNER_UID}" ] \
  || die "SESSIONS_ROOT ${SESSIONS_ROOT} is owned by uid ${ROOT_OWNER_UID}, not the signer uid (${SIGNER_UID}); refusing to chown -R as root over a foreign tree"
# Refuse a group/other-writable tree (the 0o022 mask). Use explicit base-8
# arithmetic (8#...) so the octal mode string from stat is parsed unambiguously
# as octal regardless of a leading zero or the shell's default-base behavior.
if [ "$(( 8#${ROOT_PERM} & 8#22 ))" -ne 0 ]; then
  die "SESSIONS_ROOT ${SESSIONS_ROOT} is group/other-writable (mode ${ROOT_PERM}); refusing to chown -R as root over a writable tree"
fi

# chown -Rh: -h operates on symlinks THEMSELVES (never their targets), so a
# benign-or-malicious symlink inside the tree cannot redirect the recursive chown
# to an out-of-tree path. The refusal above already rejects an attacker-seeded
# tree; -h is the belt-and-braces against a symlink the signer's own tree may
# carry. chmod stays on the root dir only (non-recursive) — correct.
chown -Rh "${SIGNER_USER}" "${SESSIONS_ROOT}" || die "could not chown -Rh ${SESSIONS_ROOT} to ${SIGNER_USER}"
# SYMLINK-SAFE chmod (TOCTOU close): POSIX `chmod` FOLLOWS symlinks for the mode
# change, racing the owner/mode stat above — a symlink swapped into place at
# SESSIONS_ROOT between the check and the chmod would redirect the mode change
# off-tree. POSIX chmod has no portable `-h` for mode (only BSD/darwin), so the
# robust cross-platform close is to REFUSE a symlinked target here: the dir was
# just lstat-validated (owner == signer, not group/other-writable), so a symlink
# appearing at this exact path is hostile. Fail closed, matching the established
# die idiom; no new portability branch.
if [ -L "${SESSIONS_ROOT}" ]; then
  die "SESSIONS_ROOT ${SESSIONS_ROOT} is a symlink; refusing to chmod (TOCTOU)"
fi
chmod "${DIR_MODE}" "${SESSIONS_ROOT}" || die "could not chmod ${SESSIONS_ROOT} to ${DIR_MODE}"

# Exec the server under the dedicated uid with the operator env contract set in the
# SERVER's environment (out of model reach — a prompt-injected agent cannot mutate
# the server process env). The ack token + declared uid bind the attestation. The
# server now defaults to DEGRADE on every platform; this launcher IS the configured
# isolated-signer deployment (a dedicated signer uid distinct from the agent uid),
# so it OPTS IN to enforce by default. The operator can still override by setting
# BOB_SANDBOX_ATTESTATION_MODE=degrade explicitly before invoking this launcher.
export BOB_SANDBOX_ISOLATION_ACK="${ACK_TOKEN}"
export BOB_SANDBOX_SIGNER_UID="${SIGNER_UID}"
# Declare the AGENT uid for the in-server isolation probe's agent-distinct leg.
# When the operator already sudo'd to launch this script, SUDO_UID is the
# invoking (agent) uid; otherwise it is the current uid. The guard above
# (SIGNER_UID != CURRENT_UID) plus this derivation guarantees agent_uid !=
# signer_uid on a correctly-launched box, so probe leg (d) holds by construction.
export BOB_SANDBOX_AGENT_UID="${SUDO_UID:-${CURRENT_UID}}"
export HOME="${SIGNER_HOME}"
# enforce-by-default for a launcher-configured isolated signer (the server's own
# default is degrade everywhere). An operator who explicitly set the mode wins.
export BOB_SANDBOX_ATTESTATION_MODE="${BOB_SANDBOX_ATTESTATION_MODE:-enforce}"
# The SC container-isolation channel. BOB_SC_TOOLCHAIN_IMAGE is the operator-only tag
# the SC seam (sc-container-exec.js) consumes to run smart-contract test/build tools
# CONTAINERIZED instead of host-as-signer. sudo strips any env not in --preserve-env,
# so it MUST be exported here AND listed below — otherwise the server sees no image,
# the SC seam degrades to a host-as-signer spawn, and (on an isolated signer under
# enforce) the SC run is now refused, so a trusted SC verdict becomes impossible.
# Conditional so an UNSET value is not forced to empty-string (a distinct degrade
# reason). Only BOB_SC_TOOLCHAIN_IMAGE is read by the seam today; any future BOB_SC_*
# container-config vars ride this same conditional-export + --preserve-env pattern.
if [ -n "${BOB_SC_TOOLCHAIN_IMAGE:-}" ]; then
  export BOB_SC_TOOLCHAIN_IMAGE
fi

# Drop to the signer uid. sudo -u is the portable path; the operator may instead
# wire a launchd/systemd unit that sets User=bob-signer and the same env.
# BOB_SANDBOX_AGENT_UID must survive the drop so the in-server probe can read it.
# BOB_SC_TOOLCHAIN_IMAGE must survive so the SC seam runs containerized, not
# host-as-signer.
exec sudo -u "${SIGNER_USER}" --preserve-env=BOB_SANDBOX_ISOLATION_ACK,BOB_SANDBOX_SIGNER_UID,BOB_SANDBOX_AGENT_UID,BOB_SANDBOX_ATTESTATION_MODE,BOB_SC_TOOLCHAIN_IMAGE,HOME \
  node "${SERVER_JS}"
