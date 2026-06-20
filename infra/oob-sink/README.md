# Bob OOB sink — operator-provisioned reference daemon (PR6)

This is the **server-owned out-of-band (OOB) sink** that Hacker Bob's `bob_oob_mint` /
`bob_oob_poll` tools depend on. It is **operator infrastructure**, NOT part of the MCP
runtime: it is never copied by `install.sh`, never loaded by the MCP server, and not in the
merge gate. The MCP tools ship **inert** until you provision this sink and point the MCP at it.

## What it does

When Bob mints a token, the agent injects `<token>.<OOB_ZONE>` (or `https://<OOB_ZONE>/<token>`)
into the target as a benign blind-vuln payload. If the **target's backend** makes a server-side
request to that name, this daemon records the interaction (token + protocol + source IP + first-seen
timestamp — **never the raw request body**). `bob_oob_poll` then queries the token-scoped poll API;
an interaction carrying the exact 128-bit token is the sound positive Bob signs as a **MEDIUM**
finding (server-side egress reachability — see the tool docs for the honest residuals: agent
self-hit, trusted-reporter, intermediary attribution).

Knowing the unguessable token is the only authorization to read its interactions; there is **no
listing endpoint**, so tokens are read-isolated across sessions.

## Provisioning (the live-arm prerequisite — PR6 cannot self-generate this)

1. **Own a registrable domain** and delegate an authoritative subdomain zone to this host:
   - `NS  oob.example.com  ->  <this VPS public IP>`
   - `A/AAAA  *.oob.example.com  ->  <this VPS public IP>`  (wildcard, so any `<token>.oob.example.com` resolves here)
2. **Open the firewall**: inbound `udp 53` (DNS — UDP only; tiny A answers need no TCP fallback), `tcp 80` (HTTP callback), and the poll port (default `8443`).
3. **TLS for the poll API**: obtain a cert for the poll host (e.g. Let's Encrypt). The MCP polls
   `https://` only, so `OOB_POLL_TLS_CERT` + `OOB_POLL_TLS_KEY` are **required in production**.
4. **Run the daemon** (see the systemd unit). DNS/HTTP callbacks need no TLS (the target chooses the scheme).
5. **Point the MCP at it** — set these in the **MCP server launch environment** (env is the
   agent-un-suppliable channel; do NOT use a config file):
   - `BOB_OOB_HOST=oob.example.com`            (must equal `OOB_ZONE` below)
   - `BOB_OOB_POLL_URL=https://poll.oob.example.com:8443`
   - optional `BOB_OOB_SELF_EGRESS_IP=<your egress IP>` — enables the HTTP-only self-hit withhold.

   **Topology recommendation:** run the MCP (and the 0600 signing key) on the **dev box**, not this
   internet-facing VPS. The dev box only needs outbound HTTPS to poll; the TARGET — not Bob — calls
   back to the VPS. A VPS compromise then cannot read the signing key (though it can still report a
   token-matched interaction the MCP would sign — the trusted-reporter residual).

## Daemon env

| Var | Meaning | Default |
|---|---|---|
| `OOB_ZONE` (required) | wildcard base host tokens are prepended to; must equal the MCP's `BOB_OOB_HOST` | — |
| `OOB_ANSWER_IP` | the A record returned for `*.<OOB_ZONE>` (this VPS IP) | (header-only answer if unset) |
| `OOB_POLL_PORT` | poll API port | `8443` |
| `OOB_POLL_TLS_CERT` / `OOB_POLL_TLS_KEY` | PEM paths; both set ⇒ poll is HTTPS (required in prod) | — (HTTP dev fallback) |
| `OOB_DNS_PORT` / `OOB_HTTP_PORT` | override `53` / `80` (e.g. unprivileged dev run) | `53` / `80` |
| `OOB_TTL_MS` | interaction retention window | 48h |

## Scope / hardening notes

- **Body-less by design**: the HTTP callback never reads the request body; only metadata is stored.
- **DNS+HTTP only**: SMTP/LDAP are intentionally not implemented (smaller internet-facing surface;
  a concrete reason this reference does NOT embed projectdiscovery interactsh).
- **At-rest encryption** of the interaction store is an optional post-MVP hardening — use an
  **authenticated** mode (AES-GCM), never an unauthenticated stream cipher.
- Run it under a dedicated unprivileged user; the systemd unit uses `AmbientCapabilities=CAP_NET_BIND_SERVICE`
  so it can bind `:53`/`:80` without root.

## Dev smoke (no public DNS)

```sh
OOB_ZONE=oob.local OOB_DNS_PORT=15353 OOB_HTTP_PORT=18080 OOB_POLL_PORT=18443 node infra/oob-sink/oob-sink.js &
# simulate a callback:
curl -s "http://127.0.0.1:18080/oobdeadbeefdeadbeefdeadbeefdeadbeef" >/dev/null
# poll it back:
curl -s "http://127.0.0.1:18443/poll?token=oobdeadbeefdeadbeefdeadbeefdeadbeef"
# => {"token":"oob...","interactions":[{"token":"oob...","protocol":"http","source_ip":"127.0.0.1","first_seen_ts":...}]}
```
