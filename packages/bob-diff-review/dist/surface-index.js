"use strict";
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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.SYMBOL_INDEX_FILENAME = void 0;
exports.isSkipEnvSet = isSkipEnvSet;
exports.indexFileExists = indexFileExists;
exports.decideS3 = decideS3;
exports.normaliseRoutesResult = normaliseRoutesResult;
exports.normaliseIndexResult = normaliseIndexResult;
exports.formatS3FailureJson = formatS3FailureJson;
const fs = __importStar(require("node:fs"));
const path = __importStar(require("node:path"));
const os = __importStar(require("node:os"));
// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
/** Environment variable set by the C2 cache step to skip S3. */
const SKIP_VAR = "SKIP_SURFACE_BUILD";
/** Filename written by bob_build_symbol_surface_index to the session dir. */
exports.SYMBOL_INDEX_FILENAME = "symbol-surface-index.json";
/** Directory under HOME where Bob writes all repository sessions. */
const BOB_SESSIONS_BASE = path.join(os.homedir(), "hacker-bob-sessions");
// ---------------------------------------------------------------------------
// Skip detection helpers
// ---------------------------------------------------------------------------
/**
 * Return true when the SKIP_SURFACE_BUILD environment variable is set to
 * "true" (case-insensitive). The C2 cache step sets this when it detects a
 * warm symbol-surface-index.json in the restored session dir.
 */
function isSkipEnvSet() {
    return (process.env[SKIP_VAR] ?? "").toLowerCase() === "true";
}
/**
 * Return true when symbol-surface-index.json already exists in the session
 * directory (direct filesystem check, used as a belt-and-suspenders guard
 * alongside the env-var signal).
 *
 * @param targetDomain - e.g. 'gh-12345678'
 */
function indexFileExists(targetDomain) {
    const indexPath = path.join(BOB_SESSIONS_BASE, targetDomain, exports.SYMBOL_INDEX_FILENAME);
    try {
        fs.accessSync(indexPath, fs.constants.R_OK);
        return true;
    }
    catch {
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
function decideS3(targetDomain) {
    // Check env var first (fastest, set by C2 step).
    if (isSkipEnvSet()) {
        console.log("CACHE HIT: skipping index build (SKIP_SURFACE_BUILD=true)");
        return { skipped: true, reason: "env_var" };
    }
    // Belt-and-suspenders: check the filesystem in case the env var was cleared.
    if (indexFileExists(targetDomain)) {
        console.log(`CACHE HIT: skipping index build (${exports.SYMBOL_INDEX_FILENAME} already present in session dir)`);
        return { skipped: true, reason: "file_exists" };
    }
    const sessionDir = path.join(BOB_SESSIONS_BASE, targetDomain);
    console.log(`[S3] symbol index not found — running route extraction + index build for session: ${sessionDir}`);
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
function normaliseRoutesResult(raw) {
    if (raw instanceof Error ||
        (typeof raw === "object" && raw !== null && "error" in raw)) {
        const errObj = raw;
        return {
            ok: false,
            route_count: 0,
            sample: [],
            error: {
                code: errObj["code"] ?? "mcp_error",
                message: errObj["message"] ??
                    (raw instanceof Error ? raw.message : JSON.stringify(raw)),
            },
        };
    }
    if (typeof raw === "object" && raw !== null) {
        const resp = raw;
        // Support both flat and nested `data` wrappers.
        const data = resp["data"] ?? resp;
        const rawRoutes = data["routes"] ??
            data["entries"] ??
            [];
        const sample = rawRoutes.slice(0, 20).map((r) => {
            if (typeof r === "object" && r !== null) {
                const re = r;
                return {
                    method: re["method"],
                    path: re["path"] ?? "",
                    handler_file: re["handler_file"] ?? "",
                    handler_symbol: re["handler_symbol"],
                    handler_line: re["handler_line"],
                    framework: re["framework"],
                    surface_id: re["surface_id"],
                };
            }
            return { path: String(r), handler_file: "" };
        });
        const route_count = data["route_count"] ??
            data["total"] ??
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
function normaliseIndexResult(raw) {
    if (raw instanceof Error ||
        (typeof raw === "object" && raw !== null && "error" in raw)) {
        const errObj = raw;
        return {
            ok: false,
            surface_count: 0,
            symbol_count: 0,
            error: {
                code: errObj["code"] ?? "mcp_error",
                message: errObj["message"] ??
                    (raw instanceof Error ? raw.message : JSON.stringify(raw)),
            },
        };
    }
    if (typeof raw === "object" && raw !== null) {
        const resp = raw;
        const data = resp["data"] ?? resp;
        const surface_count = data["surface_count"] ??
            data["surfaces"] ??
            0;
        const symbol_count = data["symbol_count"] ??
            data["symbols"] ??
            data["entry_count"] ??
            0;
        const index_path = data["index_path"] ??
            data["path"];
        // Log surface count for smoke-test validation.
        console.log(`[S3] symbol index built: ${surface_count} surface(s), ${symbol_count} symbol(s)` +
            (index_path ? ` → ${index_path}` : ""));
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
function formatS3FailureJson(sub_step, error) {
    return JSON.stringify({
        step: sub_step,
        ok: false,
        error: {
            code: error.code,
            message: error.message,
        },
    }, null, 2);
}
//# sourceMappingURL=surface-index.js.map