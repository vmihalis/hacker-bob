#!/bin/bash
# PreToolUse hook — "ask before writing" gate for bob_http_scan. Opt-in + INERT BY DEFAULT.
#
# Bob ships FULLY-AUTONOMOUS (operator-locked default), so this gate does nothing unless the operator
# opts in by setting a truthy BOB_HTTP_WRITE_CONFIRM in the environment Claude Code launches under.
#
# FAST PATH: this hook fires on EVERY bob_http_scan, so the disabled case (the default for every
# install) must cost nothing — the pure-bash flag check below exits before any interpreter is spawned.
# When the gate is ON we exec the python impl, which reads the PreToolUse payload from STDIN (never an
# env var / argv: a large captured request body would blow ARG_MAX and abort the hook with a non-2
# exit, which Claude Code treats as non-blocking → the very writes that need confirmation would slip
# through; stdin also keeps the payload out of /proc/<pid>/environ). exec → the impl's exit is the
# hook's exit, and the impl always exits 0 (ask or allow), failing CLOSED on any error.
flag=$(printf '%s' "${BOB_HTTP_WRITE_CONFIRM:-}" | tr '[:upper:]' '[:lower:]')
case "$flag" in
  1|true|yes|on) ;;            # enabled — hand off to the decision logic
  *) exit 0 ;;                 # disabled — abstain (allow) with no interpreter spawn
esac

# Fail CLOSED on exec failure: if python3 is missing or not executable, a bare failed `exec` would exit
# this non-interactive shell with 127/126 — a non-2 code Claude Code treats as NON-BLOCKING, silently
# disabling the opt-in gate exactly when the operator believes writes require confirmation. `shopt -s
# execfail` makes a failed exec RETURN instead of exiting, so the explicit `exit 2` (Claude Code's
# block-with-error sentinel) runs. On exec SUCCESS the impl replaces this process and always exits 0
# with an ask/allow decision (and a missing/broken impl makes python3 itself exit non-0 → still blocked).
shopt -s execfail
exec python3 "$(dirname "$0")/bob-http-write-confirm-impl.py"
exit 2
