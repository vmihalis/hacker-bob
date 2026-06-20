#!/usr/bin/env node
"use strict";

// infra/oob-sink/oob-sink.js — OPERATOR-PROVISIONED reference OOB sink daemon for
// Hacker Bob PR6 (bob_oob_mint / bob_oob_poll). NOT part of the MCP runtime, NOT
// copied by install.sh, NOT merge-gated — it lives under infra/ and is run by the
// operator on a public host (e.g. the Linux VPS) under a Bob-owned wildcard zone.
//
// It is the server-owned sink the TARGET's backend reaches when Bob's minted token
// is injected as a blind-SSRF/SSTI/RCE-callback payload. It records ONLY interaction
// METADATA (token + protocol + source IP + timestamp) — it deliberately DROPS raw
// request bodies (no exfil of target data beyond the token). bob_oob_poll queries
// the token-scoped poll API; knowing the unguessable 128-bit token is the only
// authorization to read its interactions (there is NO listing endpoint, so tokens
// are read-isolated across sessions).
//
// Three listeners (all plain JSON, no interactsh wire-protocol / client crypto):
//   * DNS  (UDP :53)              — authoritative responder for *.<ZONE>; logs the
//                                    queried FQDN's leftmost label as the token.
//                                    UDP only: the A answer is tiny, so TCP fallback
//                                    is not required for OOB detection; a TCP :53
//                                    listener is an optional operator hardening.
//   * HTTP (:80, the callback)    — logs Host/path -> token; body is never read.
//   * Poll (HTTPS :8443 by default)— GET /poll?token=<token> -> {interactions:[...]}.
//
// Config via env:
//   OOB_ZONE            the wildcard base host tokens are prepended to (must equal
//                       the MCP's BOB_OOB_HOST), e.g. "oob.example.com".
//   OOB_ANSWER_IP       the A record this responder returns for *.<ZONE> (the VPS IP).
//   OOB_POLL_PORT       poll API port (default 8443).
//   OOB_POLL_TLS_CERT / OOB_POLL_TLS_KEY  PEM paths; if both set, poll is HTTPS
//                       (REQUIRED for production — the MCP polls https:// only).
//   OOB_DNS_PORT / OOB_HTTP_PORT  override 53 / 80 (e.g. for an unprivileged dev run).
//   OOB_TTL_MS          interaction retention (default 48h).
//
// SMTP/LDAP are intentionally NOT implemented (they widen the internet-facing
// surface for no MVP benefit). At-rest encryption of the interaction store is an
// optional post-MVP hardening (use AES-GCM, never an unauthenticated mode).

const dgram = require("dgram");
const http = require("http");
const https = require("https");
const fs = require("fs");

const ZONE = (process.env.OOB_ZONE || "").trim().toLowerCase();
const ANSWER_IP = (process.env.OOB_ANSWER_IP || "").trim();
const POLL_PORT = Number(process.env.OOB_POLL_PORT || 8443);
const DNS_PORT = Number(process.env.OOB_DNS_PORT || 53);
const HTTP_PORT = Number(process.env.OOB_HTTP_PORT || 80);
const TTL_MS = Number(process.env.OOB_TTL_MS || 48 * 60 * 60 * 1000);
const TLS_CERT = process.env.OOB_POLL_TLS_CERT || "";
const TLS_KEY = process.env.OOB_POLL_TLS_KEY || "";

if (!ZONE) {
  process.stderr.write("OOB_ZONE is required (must equal the MCP's BOB_OOB_HOST)\n");
  process.exit(2);
}

// token -> [{ protocol, source_ip, first_seen_ts }] (insertion-ordered Map).
const interactions = new Map();
const TOKEN_RE = /^[a-z0-9-]{8,128}$/;
// Cap on DISTINCT tracked tokens — without it an internet client could spray
// unique labels/paths and grow the Map unbounded for the whole TTL window (a
// trivial memory-exhaustion DoS). The per-token list cap below bounds only one
// token's interactions, not the number of tokens.
const MAX_TRACKED_TOKENS = 4096;

function nowMs() {
  return Date.now();
}

function record(token, protocol, sourceIp) {
  if (typeof token !== "string" || !TOKEN_RE.test(token)) return;
  if (!interactions.has(token)) {
    if (interactions.size >= MAX_TRACKED_TOKENS) {
      // Evict the oldest tracked token (Map preserves insertion order) to bound
      // memory under a unique-token spray.
      const oldest = interactions.keys().next().value;
      if (oldest !== undefined) interactions.delete(oldest);
    }
    interactions.set(token, []);
  }
  const list = interactions.get(token);
  // Cap per-token interactions so a flood cannot exhaust memory.
  if (list.length < 256) {
    list.push({ protocol, source_ip: sourceIp || null, first_seen_ts: nowMs() });
  }
}

// The token is the leftmost label of the FQDN/Host below the configured zone, or
// the first path segment of an HTTP callback. Strip the zone suffix and take the
// last label of what remains (so token.<zone> and a.b.token.<zone> both work).
function tokenFromName(name) {
  const host = String(name || "").toLowerCase().replace(/\.$/, "");
  if (host === ZONE) return null;
  if (!host.endsWith(`.${ZONE}`)) return null;
  const prefix = host.slice(0, host.length - ZONE.length - 1);
  const labels = prefix.split(".").filter(Boolean);
  return labels.length ? labels[labels.length - 1] : null;
}

function pruneExpired() {
  const cutoff = nowMs() - TTL_MS;
  for (const [token, list] of interactions) {
    const kept = list.filter((i) => i.first_seen_ts >= cutoff);
    if (kept.length === 0) interactions.delete(token);
    else interactions.set(token, kept);
  }
}

// ── DNS responder (minimal A-record authoritative answer + query logging) ──────

function parseDnsQuestionName(buf) {
  // Header is 12 bytes; the question name starts at offset 12 as length-prefixed
  // labels terminated by a zero length octet.
  let offset = 12;
  const labels = [];
  while (offset < buf.length) {
    const len = buf[offset];
    if (len === 0) { offset += 1; break; }
    if ((len & 0xc0) === 0xc0) break; // compression pointer — not expected in a question
    labels.push(buf.toString("ascii", offset + 1, offset + 1 + len));
    offset += 1 + len;
  }
  // The question section is QNAME + QTYPE(2) + QCLASS(2); questionEnd must include
  // those 4 trailing bytes, else the echoed question is malformed and the appended
  // answer is parsed at the wrong offset (RFC 1035 §4.1.2).
  if (offset + 4 > buf.length) {
    throw new Error("truncated DNS question (missing QTYPE/QCLASS)");
  }
  return { name: labels.join("."), questionEnd: offset + 4 };
}

function buildDnsAnswer(query, questionEnd) {
  // Echo the query, set QR + AA, ANCOUNT=1 (only when we have an answer IP), and
  // append an A record pointing at ANSWER_IP. Best-effort: a malformed query is
  // answered with a header-only response.
  const header = Buffer.from(query.subarray(0, 12));
  header[2] = 0x84; // QR=1, Opcode=0, AA=1
  header[3] = 0x00; // RA=0, RCODE=0
  header.writeUInt16BE(1, 4); // QDCOUNT=1
  const question = Buffer.from(query.subarray(12, questionEnd));
  if (!ANSWER_IP || !/^\d+\.\d+\.\d+\.\d+$/.test(ANSWER_IP)) {
    header.writeUInt16BE(0, 6); // ANCOUNT=0
    return Buffer.concat([header, question]);
  }
  header.writeUInt16BE(1, 6); // ANCOUNT=1
  const rr = Buffer.alloc(16);
  rr.writeUInt16BE(0xc00c, 0); // name pointer to the question
  rr.writeUInt16BE(1, 2); // TYPE A
  rr.writeUInt16BE(1, 4); // CLASS IN
  rr.writeUInt32BE(30, 6); // TTL 30s
  rr.writeUInt16BE(4, 10); // RDLENGTH 4
  ANSWER_IP.split(".").forEach((o, i) => { rr[12 + i] = Number(o) & 0xff; });
  return Buffer.concat([header, question, rr]);
}

function startDns() {
  const sock = dgram.createSocket("udp4");
  sock.on("message", (msg, rinfo) => {
    try {
      const { name, questionEnd } = parseDnsQuestionName(msg);
      const token = tokenFromName(name);
      if (token) record(token, "dns", rinfo.address);
      sock.send(buildDnsAnswer(msg, questionEnd), rinfo.port, rinfo.address);
    } catch {
      // ignore malformed packets
    }
  });
  sock.bind(DNS_PORT, () => process.stdout.write(`oob-sink DNS listening on :${DNS_PORT} for *.${ZONE}\n`));
}

// ── HTTP callback logger (body-less) ───────────────────────────────────────────

function startHttpCallback() {
  const server = http.createServer((req, res) => {
    // Never read the request body — we record metadata only, no target-data exfil.
    req.resume();
    const hostHeader = String(req.headers.host || "").split(":")[0];
    const sourceIp = req.socket.remoteAddress || null;
    const token = tokenFromName(hostHeader) || tokenFromPath(req.url);
    if (token) record(token, "http", sourceIp);
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok\n");
  });
  server.listen(HTTP_PORT, () => process.stdout.write(`oob-sink HTTP callback on :${HTTP_PORT}\n`));
}

function tokenFromPath(url) {
  try {
    const p = new URL(url, "http://x").pathname.split("/").filter(Boolean);
    const seg = p.length ? p[0] : null;
    return seg && TOKEN_RE.test(seg) ? seg : null;
  } catch {
    return null;
  }
}

// ── Poll API (token-scoped; the only read path) ────────────────────────────────

function pollHandler(req, res) {
  pruneExpired();
  let token = null;
  try {
    token = new URL(req.url, "http://x").searchParams.get("token");
  } catch {
    token = null;
  }
  if (req.method !== "GET" || !token || !TOKEN_RE.test(token)) {
    res.writeHead(400, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "token query param required" }));
    return;
  }
  const list = interactions.get(token) || [];
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ token, interactions: list.map((i) => ({ token, ...i })) }));
}

function startPoll() {
  if (TLS_CERT && TLS_KEY) {
    const opts = { cert: fs.readFileSync(TLS_CERT), key: fs.readFileSync(TLS_KEY) };
    https.createServer(opts, pollHandler).listen(POLL_PORT, () => process.stdout.write(`oob-sink poll API (HTTPS) on :${POLL_PORT}\n`));
  } else {
    process.stdout.write("WARNING: OOB_POLL_TLS_CERT/KEY unset — poll API is HTTP (dev only; the MCP polls https:// in production)\n");
    http.createServer(pollHandler).listen(POLL_PORT, () => process.stdout.write(`oob-sink poll API (HTTP, dev) on :${POLL_PORT}\n`));
  }
}

startDns();
startHttpCallback();
startPoll();
setInterval(pruneExpired, 60 * 60 * 1000).unref();
