/**
 * S3 — Route extraction + symbol surface index (conditional on cache miss).
 *
 * This module implements the conditional logic that guards the two expensive
 * MCP calls in the S3 pipeline step:
 *
 *   1. bob_extract_routes — analyzes framework-specific routing (Express,
 *      FastAPI, Rails, etc.) and returns a route list persisted to the session.
 *
 *   2. bob_build_symbol_surface_index — links routes to handler symbols and
 *      their transitive callees, writing symbol-surface-index.json to the
 *      session directory.
 *
 * Both calls are skipped entirely when the SKIP_SURFACE_BUILD environment
 * variable is set to "true" (signal emitted by the C2 cache step when a warm
 * session already contains symbol-surface-index.json).
 *
 * All MCP calls are executed by the orchestrator agent (SKILL.md); this module
 * provides only the TypeScript types and helper functions that bob-runner.ts
 * uses to drive those calls and interpret their results.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Environment variable set by the C2 cache step to skip S3. */
const SKIP_VAR = "SKIP_SURFACE_BUILD";

/** Filename written by bob_build_symbol_surface_index to the session dir. */
export const SYMBOL_INDEX_FILENAME = "symbol-surface-index.json";

/** Directory under HOME where Bob writes all repository sessions. */
const BOB_SESSIONS_BASE = path.join(os.homedir(), "hacker-bob-sessions");

// ---------------------------------------------------------------------------
// Symbol surface index schema
// ---------------------------------------------------------------------------

/**
 * A single entry in symbol-surface-index.json.
 *
 * The MCP tool bob_build_symbol_surface_index writes an array of these to
 * the session directory. bob_summarize_diff_impact reads the index to resolve
 * diff hunks (file + line range) to the security-relevant surfaces they touch.
 */
export interface SymbolSurfaceEntry {
  /** Fully-qualified symbol name (function, class, route handler, etc.). */
  symbol: string;
  /** Repo-relative file path where the symbol is defined. */
  file: string;
  /** Line number of the symbol definition start (1-indexed). */
  line_start: number;
  /** Line number of the symbol definition end (1-indexed, inclusive). */
  line_end: number;
  /**
   * Surface identifier this symbol belongs to.
   * Matches the surface_id used in bob session surface graph nodes.
   */
  surface_id: string;
  /**
   * Broad surface classification for dispatch.
   * Common values: 'api-route', 'authentication', 'authorization',
   * 'admin', 'smart-contract', 'data-model', 'upload', 'crypto', 'other'.
   */
  surface_type: string;
}

// ---------------------------------------------------------------------------
// Route extraction result types
// ---------------------------------------------------------------------------

/**
 * A single route entry returned by bob_extract_routes.
 */
export interface ExtractedRoute {
  /** HTTP method, e.g. 'GET', 'POST'. Empty for non-HTTP entry points. */
  method?: string;
  /** Route path pattern, e.g. '/api/v1/users/:id'. */
  path: string;
  /** Repo-relative path to the file containing the handler. */
  handler_file: string;
  /** Name of the handler function, class method, or entry point. */
  handler_symbol?: string;
  /** Line number of the handler definition (1-indexed). */
  handler_line?: number;
  /**
   * Framework that produced this route, e.g. 'express', 'fastapi', 'rails',
   * 'gin', 'nextjs', 'unknown'.
   */
  framework?: string;
  /** Surface ID inferred from the route path pattern (may be updated by S3). */
  surface_id?: string;
}

/**
 * Result of the bob_extract_routes MCP call.
 */
export interface S3RoutesResult {
  ok: boolean;
  /** Number of routes/entry-points extracted. */
  route_count: number;
  /** Representative sample of extracted routes (first 20). */
  sample: ExtractedRoute[];
  /** Error details if ok is false. */
  error?: { code: string; message: string };
}

/**
 * Result of the bob_build_symbol_surface_index MCP call.
 */
export interface S3IndexResult {
  ok: boolean;
  /**
   * Number of distinct surfaces discovered.
   * Logged for smoke-test validation per acceptance criteria.
   */
  surface_count: number;
  /**
   * Number of symbol entries written to symbol-surface-index.json.
   */
  symbol_count: number;
  /** Absolute path to the written symbol-surface-index.json. */
  index_path?: string;
  /** Error details if ok is false. */
  error?: { code: string; message: string };
}

// ---------------------------------------------------------------------------
// Combined S3 step result
// ---------------------------------------------------------------------------

/**
 * Outcome of the S3 step returned by prepareS3 for decision-making.
 *
 * When `skipped` is true, no MCP calls are made and both `routes` and `index`
 * are null. When `skipped` is false, the orchestrator agent executes the MCP
 * calls and passes their responses to normaliseRoutesResult /
 * normaliseIndexResult.
 */
export type S3StepDecision =
  | { skipped: true; reason: "env_var" | "file_exists" }
  | { skipped: false; target_domain: string; session_dir: string };

// ---------------------------------------------------------------------------
// Skip detection helpers
// ---------------------------------------------------------------------------

/**
 * Return true when the SKIP_SURFACE_BUILD environment variable is set to
 * "true" (case-insensitive). The C2 cache step sets this when it detects a
 * warm symbol-surface-index.json in the restored session dir.
 */
export function isSkipEnvSet(): boolean {
  return (process.env[SKIP_VAR] ?? "").toLowerCase() === "true";
}

/**
 * Return true when symbol-surface-index.json already exists in the session
 * directory (direct filesystem check, used as a belt-and-suspenders guard
 * alongside the env-var signal).
 *
 * @param targetDomain - e.g. 'gh-12345678'
 */
export function indexFileExists(targetDomain: string): boolean {
  const indexPath = path.join(
    BOB_SESSIONS_BASE,
    targetDomain,
    SYMBOL_INDEX_FILENAME
  );
  try {
    fs.accessSync(indexPath, fs.constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// S3 step decision function
// ---------------------------------------------------------------------------

/**
 * Determine whether the S3 step should run or be skipped.
 *
 * The step is skipped when either:
 *   a) SKIP_SURFACE_BUILD=true is set in the environment (set by C2 cache step
 *      or resolveCacheState() in session-cache.ts), OR
 *   b) symbol-surface-index.json already exists in the session directory
 *      (filesystem fallback for cases where the env var was cleared).
 *
 * Logs the skip reason or build intent to stdout for observability.
 *
 * @param targetDomain - 'gh-' + github.repository_id from C2
 * @returns S3StepDecision — callers branch on `skipped` before calling MCP
 */
export function decideS3(targetDomain: string): S3StepDecision {
  // Check env var first (fastest, set by C2 step).
  if (isSkipEnvSet()) {
    console.log("CACHE HIT: skipping index build (SKIP_SURFACE_BUILD=true)");
    return { skipped: true, reason: "env_var" };
  }

  // Belt-and-suspenders: check the filesystem in case the env var was cleared.
  if (indexFileExists(targetDomain)) {
    console.log(
      `CACHE HIT: skipping index build (${SYMBOL_INDEX_FILENAME} already present in session dir)`
    );
    return { skipped: true, reason: "file_exists" };
  }

  const sessionDir = path.join(BOB_SESSIONS_BASE, targetDomain);
  console.log(
    `[S3] symbol index not found — running route extraction + index build for session: ${sessionDir}`
  );
  return { skipped: false, target_domain: targetDomain, session_dir: sessionDir };
}

// ---------------------------------------------------------------------------
// MCP result normalisation
// ---------------------------------------------------------------------------

/**
 * Normalise a raw bob_extract_routes MCP response into an S3RoutesResult.
 *
 * @param raw - Raw MCP response (parsed JSON or thrown error object).
 */
export function normaliseRoutesResult(raw: unknown): S3RoutesResult {
  if (
    raw instanceof Error ||
    (typeof raw === "object" && raw !== null && "error" in (raw as object))
  ) {
    const errObj = raw as Record<string, unknown>;
    return {
      ok: false,
      route_count: 0,
      sample: [],
      error: {
        code: (errObj["code"] as string | undefined) ?? "mcp_error",
        message:
          (errObj["message"] as string | undefined) ??
          (raw instanceof Error ? raw.message : JSON.stringify(raw)),
      },
    };
  }

  if (typeof raw === "object" && raw !== null) {
    const resp = raw as Record<string, unknown>;
    // Support both flat and nested `data` wrappers.
    const data =
      (resp["data"] as Record<string, unknown> | undefined) ?? resp;

    const rawRoutes =
      (data["routes"] as unknown[] | undefined) ??
      (data["entries"] as unknown[] | undefined) ??
      [];

    const sample: ExtractedRoute[] = rawRoutes.slice(0, 20).map((r) => {
      if (typeof r === "object" && r !== null) {
        const re = r as Record<string, unknown>;
        return {
          method: re["method"] as string | undefined,
          path: (re["path"] as string | undefined) ?? "",
          handler_file: (re["handler_file"] as string | undefined) ?? "",
          handler_symbol: re["handler_symbol"] as string | undefined,
          handler_line: re["handler_line"] as number | undefined,
          framework: re["framework"] as string | undefined,
          surface_id: re["surface_id"] as string | undefined,
        };
      }
      return { path: String(r), handler_file: "" };
    });

    const route_count =
      (data["route_count"] as number | undefined) ??
      (data["total"] as number | undefined) ??
      rawRoutes.length;

    return { ok: true, route_count, sample };
  }

  return {
    ok: false,
    route_count: 0,
    sample: [],
    error: {
      code: "unknown",
      message: `bob_extract_routes returned unexpected value type (${typeof raw})`,
    },
  };
}

/**
 * Normalise a raw bob_build_symbol_surface_index MCP response into an
 * S3IndexResult.
 *
 * Logs the surface count on success for smoke-test validation (acceptance
 * criterion: "surface count is logged for smoke-test validation").
 *
 * @param raw - Raw MCP response (parsed JSON or thrown error object).
 */
export function normaliseIndexResult(raw: unknown): S3IndexResult {
  if (
    raw instanceof Error ||
    (typeof raw === "object" && raw !== null && "error" in (raw as object))
  ) {
    const errObj = raw as Record<string, unknown>;
    return {
      ok: false,
      surface_count: 0,
      symbol_count: 0,
      error: {
        code: (errObj["code"] as string | undefined) ?? "mcp_error",
        message:
          (errObj["message"] as string | undefined) ??
          (raw instanceof Error ? raw.message : JSON.stringify(raw)),
      },
    };
  }

  if (typeof raw === "object" && raw !== null) {
    const resp = raw as Record<string, unknown>;
    const data =
      (resp["data"] as Record<string, unknown> | undefined) ?? resp;

    const surface_count =
      (data["surface_count"] as number | undefined) ??
      (data["surfaces"] as number | undefined) ??
      0;

    const symbol_count =
      (data["symbol_count"] as number | undefined) ??
      (data["symbols"] as number | undefined) ??
      (data["entry_count"] as number | undefined) ??
      0;

    const index_path =
      (data["index_path"] as string | undefined) ??
      (data["path"] as string | undefined);

    // Log surface count for smoke-test validation.
    console.log(
      `[S3] symbol index built: ${surface_count} surface(s), ${symbol_count} symbol(s)` +
        (index_path ? ` → ${index_path}` : "")
    );

    return { ok: true, surface_count, symbol_count, index_path };
  }

  return {
    ok: false,
    surface_count: 0,
    symbol_count: 0,
    error: {
      code: "unknown",
      message: `bob_build_symbol_surface_index returned unexpected value type (${typeof raw})`,
    },
  };
}

// ---------------------------------------------------------------------------
// Failure JSON formatting
// ---------------------------------------------------------------------------

/**
 * Format a structured JSON error string for S3 step failure surfacing.
 *
 * The orchestrator agent writes this to stdout so downstream callers
 * (bob-runner.ts, GitHub Actions step summary) can parse it without
 * regex-scraping prose messages.
 *
 * @param sub_step - Sub-step label, e.g. 'S3.extract_routes' or 'S3.index'.
 * @param error    - The error detail object.
 */
export function formatS3FailureJson(
  sub_step: string,
  error: { code: string; message: string }
): string {
  return JSON.stringify(
    {
      step: sub_step,
      ok: false,
      error: {
        code: error.code,
        message: error.message,
      },
    },
    null,
    2
  );
}
