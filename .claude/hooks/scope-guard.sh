#!/bin/bash
# Scope guard hook — PreToolUse on Bash
#
# Bob is now allowed to reach arbitrary third-party hosts during a target run,
# so this hook no longer blocks out-of-scope or deny-listed domains. The MCP
# runtime still enforces SSRF protections (loopback / RFC1918 / cloud metadata)
# inside safeFetch, which is the safety boundary that matters.
#
# The hook is preserved as a no-op so existing settings.json registrations
# remain valid and so we have a single seam to reintroduce per-target controls
# later if a program ever requires them.

exit 0
