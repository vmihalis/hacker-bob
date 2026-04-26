#!/bin/bash
# Scope guard hook — PreToolUse on scoped bountyagent MCP tools
#
# Bob is allowed to reach whatever hosts the user authorizes during a target
# run, including third-party, local, private, and internal destinations. The MCP
# HTTP tools can opt into blocking loopback / RFC1918 / cloud metadata-style
# destinations with block_internal_hosts=true when a program requires it.
#
# The hook is preserved as a no-op so existing settings.json registrations
# remain valid and so we have a single seam to reintroduce per-target controls
# later if a program ever requires them.

exit 0
