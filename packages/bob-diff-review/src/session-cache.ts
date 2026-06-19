/**
 * Session cache helpers for bob-runner.
 *
 * After the C2 composite action restores ~/hacker-bob-sessions/gh-<repository_id>,
 * these utilities determine whether the S3 phase (route extraction + symbol index
 * build) can be skipped, and resolve the deterministic target_domain override used
 * throughout the bob-diff-review pipeline.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Directory under HOME where Bob writes all repository sessions. */
const BOB_SESSIONS_BASE = path.join(os.homedir(), "hacker-bob-sessions");

/** Filename written by S3 (bob_build_symbol_surface_index). */
const SYMBOL_INDEX_FILENAME = "symbol-surface-index.json";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SessionCacheInfo {
  /** Absolute path to the session directory, e.g. ~/hacker-bob-sessions/gh-12345678 */
  sessionDir: string;
  /**
   * target_domain string to pass to bob_init_repo_session.
   * Always 'gh-' + repositoryId so the session path is deterministic across runs.
   */
  targetDomain: string;
  /** Whether symbol-surface-index.json exists in the restored session dir. */
  hasSymbolIndex: boolean;
}

// ---------------------------------------------------------------------------
// Core helpers
// ---------------------------------------------------------------------------

/**
 * Return the deterministic target_domain string for a GitHub repository.
 *
 * The 'gh-' prefix distinguishes GitHub-action sessions from human-launched
 * sessions (which use a real hostname). The numeric repository_id guarantees
 * uniqueness across forks and renames.
 *
 * @param repositoryId - github.repository_id (numeric, but passed as string)
 */
export function buildTargetDomain(repositoryId: string): string {
  if (!repositoryId || repositoryId === "0") {
    throw new Error(
      `repository_id is empty or zero ("${repositoryId}"). ` +
        "Pass github.repository_id to buildTargetDomain."
    );
  }
  return `gh-${repositoryId}`;
}

/**
 * Return the absolute path to the Bob session directory for a given repository.
 *
 * This must match the cache path used by the C2 composite action:
 *   ~/hacker-bob-sessions/gh-<repository_id>
 *
 * @param repositoryId - github.repository_id (numeric, but passed as string)
 */
export function resolveSessionDir(repositoryId: string): string {
  const targetDomain = buildTargetDomain(repositoryId);
  return path.join(BOB_SESSIONS_BASE, targetDomain);
}

/**
 * Check whether symbol-surface-index.json exists in the session directory.
 *
 * Returns true only when the file is present AND readable. A stale or
 * zero-byte file is accepted here; downstream validation (mtime check against
 * the diff) is the responsibility of the S3 step in bob-runner.
 *
 * @param sessionDir - absolute path returned by resolveSessionDir
 */
export function hasSymbolSurfaceIndex(sessionDir: string): boolean {
  const indexPath = path.join(sessionDir, SYMBOL_INDEX_FILENAME);
  try {
    fs.accessSync(indexPath, fs.constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * Collect all session cache metadata from the environment after the C2 action
 * has run. Reads GITHUB_OUTPUT-style env vars set by the composite action, with
 * a filesystem fallback so the module also works in local/dry-run mode.
 *
 * Sets the SKIP_SURFACE_BUILD environment variable if symbol-surface-index.json
 * is detected, matching the W1 workflow's expectation.
 *
 * @param repositoryId - github.repository_id (numeric string)
 * @returns SessionCacheInfo — callers pass sessionDir and targetDomain to MCP
 */
export function resolveCacheState(repositoryId: string): SessionCacheInfo {
  const targetDomain = buildTargetDomain(repositoryId);
  const sessionDir = resolveSessionDir(repositoryId);
  const hasIndex = hasSymbolSurfaceIndex(sessionDir);

  // Propagate skip signal to process environment so sub-processes (e.g. a
  // headless claude invocation) inherit it without re-computing.
  if (hasIndex) {
    process.env["SKIP_SURFACE_BUILD"] = "true";
  } else {
    // Explicitly clear in case a previous run left a stale value.
    delete process.env["SKIP_SURFACE_BUILD"];
  }

  return { sessionDir, targetDomain, hasSymbolIndex: hasIndex };
}

// ---------------------------------------------------------------------------
// GitHub Actions output helpers
// ---------------------------------------------------------------------------

/**
 * Write a key=value pair to the GITHUB_OUTPUT file if running inside a
 * GitHub Actions runner. No-op otherwise.
 *
 * @param name  - output variable name
 * @param value - string value
 */
export function setOutput(name: string, value: string): void {
  const outputFile = process.env["GITHUB_OUTPUT"];
  if (!outputFile) return;
  fs.appendFileSync(outputFile, `${name}=${value}\n`, { encoding: "utf-8" });
}

/**
 * Emit all C2-relevant outputs to GITHUB_OUTPUT and log a summary.
 * Call this from bob-runner.ts after resolveCacheState.
 */
export function emitCacheOutputs(info: SessionCacheInfo): void {
  setOutput("session_dir", info.sessionDir);
  setOutput("target_domain", info.targetDomain);
  setOutput(
    "cache_hit_symbol_index",
    info.hasSymbolIndex ? "true" : "false"
  );

  const indexStatus = info.hasSymbolIndex
    ? "found — S3 phase will be skipped (SKIP_SURFACE_BUILD=true)"
    : "not found — S3 phase will run";

  console.log(`[session-cache] session_dir:    ${info.sessionDir}`);
  console.log(`[session-cache] target_domain:  ${info.targetDomain}`);
  console.log(`[session-cache] symbol index:   ${indexStatus}`);
}
