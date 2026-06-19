#!/usr/bin/env node
/**
 * mock-github-api.js — Lightweight GitHub API mock server for act local testing.
 *
 * Handles the subset of GitHub API endpoints the bob-diff-review action calls:
 *   GET  /repos/:owner/:repo/pulls/:number  (check PR exists)
 *   GET  /repos/:owner/:repo/pulls/:number/files  (diff as file list - unused but safe)
 *   GET  /repos/:owner/:repo/pulls/:number  with Accept: application/vnd.github.diff
 *   POST /repos/:owner/:repo/checks            (create check run)
 *   PATCH /repos/:owner/:repo/check-runs/:id   (update check run)
 *   POST /repos/:owner/:repo/pulls/:number/reviews  (post PR review)
 *   GET  /repos/:owner/:repo/commits/:sha      (commit info)
 *
 * All write endpoints return mock 200/201 responses with logged payloads
 * so the test can verify the correct calls were made via the log output.
 *
 * Usage:
 *   node scripts/mock-github-api.js [--port 8080] [--diff-fixture path/to/pr.diff]
 *
 * Environment overrides:
 *   MOCK_GITHUB_PORT      — port to listen on (default 8080)
 *   MOCK_DIFF_FIXTURE     — path to a .diff file to serve as the PR diff
 */

'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

// Resolve diff fixture path and port from CLI args first, then env vars
const args = process.argv.slice(2);
let diffFixturePath = null;
let cliPort = null;
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--diff-fixture' && args[i + 1]) {
    diffFixturePath = args[i + 1];
    i++;
  } else if (args[i] === '--port' && args[i + 1]) {
    cliPort = args[i + 1];
    i++;
  }
}

const PORT = parseInt(cliPort ?? process.env.MOCK_GITHUB_PORT ?? '8080', 10);

if (!diffFixturePath) {
  // Default: look for pr_42.diff relative to repo root
  const repoRoot = path.resolve(__dirname, '..');
  const candidate = path.join(repoRoot, 'test', 'fixtures', 'pr_42.diff');
  if (fs.existsSync(candidate)) {
    diffFixturePath = candidate;
  }
}

const DIFF_CONTENT = diffFixturePath && fs.existsSync(diffFixturePath)
  ? fs.readFileSync(diffFixturePath, 'utf8')
  : `diff --git a/src/example.ts b/src/example.ts\nindex 0000001..0000002 100644\n--- a/src/example.ts\n+++ b/src/example.ts\n@@ -1,3 +1,4 @@\n const x = 1;\n+const y = 2;\n const z = 3;\n`;

// ---------------------------------------------------------------------------
// Request log — written to MOCK_LOG_FILE when set, else stdout
// ---------------------------------------------------------------------------
const LOG_FILE = process.env.MOCK_LOG_FILE ?? null;
const logStream = LOG_FILE
  ? fs.createWriteStream(LOG_FILE, { flags: 'a' })
  : process.stdout;

function log(msg) {
  const line = `[mock-github-api] ${new Date().toISOString()} ${msg}\n`;
  logStream.write(line);
}

// ---------------------------------------------------------------------------
// Route table
// ---------------------------------------------------------------------------

const ROUTES = [
  // PR diff — served as application/vnd.github.diff
  {
    method: 'GET',
    pattern: /^\/repos\/[^/]+\/[^/]+\/pulls\/\d+$/,
    handler(req, res, match) {
      const accept = req.headers['accept'] ?? '';
      if (accept.includes('vnd.github.diff') || accept.includes('vnd.github.v3.diff')) {
        log(`GET ${req.url} => 200 diff (${DIFF_CONTENT.length} bytes)`);
        res.writeHead(200, { 'Content-Type': 'application/vnd.github.diff' });
        res.end(DIFF_CONTENT);
        return;
      }
      // Return PR JSON
      log(`GET ${req.url} => 200 PR JSON`);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        number: 42,
        state: 'open',
        head: { sha: 'abc1234def5678abc1234def5678abc1234def56' },
        base: { ref: 'main', sha: 'fedcba9876543210fedcba9876543210fedcba98' },
      }));
    },
  },

  // Create check run
  {
    method: 'POST',
    pattern: /^\/repos\/[^/]+\/[^/]+\/check-runs$/,
    handler(req, res) {
      collectBody(req, (body) => {
        log(`POST ${req.url} check-runs body=${body} => 201`);
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ id: 9999, html_url: 'https://github.com/checks/9999' }));
      });
    },
  },

  // Also match /repos/.../checks (older path used by some action versions)
  {
    method: 'POST',
    pattern: /^\/repos\/[^/]+\/[^/]+\/checks$/,
    handler(req, res) {
      collectBody(req, (body) => {
        log(`POST ${req.url} checks body=${body} => 201`);
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ id: 9999, html_url: 'https://github.com/checks/9999' }));
      });
    },
  },

  // Update check run
  {
    method: 'PATCH',
    pattern: /^\/repos\/[^/]+\/[^/]+\/check-runs\/\d+$/,
    handler(req, res) {
      collectBody(req, (body) => {
        log(`PATCH ${req.url} check-run body=${body} => 200`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ id: 9999, html_url: 'https://github.com/checks/9999' }));
      });
    },
  },

  // Post PR review — this is the key endpoint we want to log
  {
    method: 'POST',
    pattern: /^\/repos\/[^/]+\/[^/]+\/pulls\/\d+\/reviews$/,
    handler(req, res) {
      collectBody(req, (body) => {
        log(`POST ${req.url} PR_REVIEW_POSTED body=${body} => 200`);
        const reviewId = 111222333;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          id: reviewId,
          html_url: `https://github.com/bobnetsec/test-target/pull/42#pullrequestreview-${reviewId}`,
          state: 'COMMENTED',
          user: { login: 'github-actions[bot]' },
        }));
      });
    },
  },

  // Get commit (used internally by some actions)
  {
    method: 'GET',
    pattern: /^\/repos\/[^/]+\/[^/]+\/commits\/[^/]+$/,
    handler(req, res) {
      log(`GET ${req.url} => 200 commit`);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ sha: 'abc1234def5678abc1234def5678abc1234def56' }));
    },
  },

  // PR files list (unused but prevents 404 noise)
  {
    method: 'GET',
    pattern: /^\/repos\/[^/]+\/[^/]+\/pulls\/\d+\/files$/,
    handler(req, res) {
      log(`GET ${req.url} => 200 empty files list`);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify([]));
    },
  },
];

// ---------------------------------------------------------------------------
// Body helper
// ---------------------------------------------------------------------------

function collectBody(req, cb) {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const raw = Buffer.concat(chunks).toString('utf8');
    cb(raw.length > 500 ? raw.slice(0, 500) + '...(truncated)' : raw);
  });
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

const server = http.createServer((req, res) => {
  // Use URL constructor for spec-compliant parsing (avoids url.parse deprecation)
  let pathname = '/';
  try {
    pathname = new URL(req.url, 'http://localhost').pathname;
  } catch {
    pathname = req.url.split('?')[0] ?? '/';
  }

  for (const route of ROUTES) {
    if (route.method === req.method && route.pattern.test(pathname)) {
      route.handler(req, res, pathname);
      return;
    }
  }

  // Catch-all — log and return empty 200 so the action doesn't abort
  log(`UNMATCHED ${req.method} ${req.url} => 200 empty`);
  collectBody(req, () => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({}));
  });
});

// Listen on all interfaces so the server is reachable from:
//   - the host (127.0.0.1:<PORT>)
//   - Docker containers via host.docker.internal:<PORT> (macOS/Windows Docker Desktop)
//   - Docker containers via --add-host=host.docker.internal:host-gateway (Linux)
server.listen(PORT, '0.0.0.0', () => {
  log(`Mock GitHub API listening on http://0.0.0.0:${PORT} (all interfaces)`);
  log(`Serving diff fixture: ${diffFixturePath ?? '(inline default)'}`);
  // Signal to the parent shell that the server is ready.
  // Written to stdout so test-local.sh can grep the log for "READY port=".
  process.stdout.write(`READY port=${PORT}\n`);
});

server.on('error', (err) => {
  process.stderr.write(`[mock-github-api] Server error: ${err.message}\n`);
  process.exit(1);
});

// Graceful shutdown
process.on('SIGTERM', () => { server.close(); process.exit(0); });
process.on('SIGINT',  () => { server.close(); process.exit(0); });
