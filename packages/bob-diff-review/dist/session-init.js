"use strict";
/**
 * S2 — Session init + inventory.
 *
 * Implements the two MCP calls that form the structural foundation of the
 * bob-diff-review pipeline:
 *
 *   1. bob_init_repo_session — binds a Bob session to the locally checked-out
 *      repo.  Uses the deterministic `gh-<repository_id>` target_domain from
 *      C2 so the session path is stable across PR runs.  Passes resume:true
 *      (via existing-dir detection) so a C2 cache restore is honoured rather
 *      than overwritten.
 *
 *   2. bob_repo_inventory — walks the bound repo and materialises
 *      repo-inventory.json plus frontier surface.observed events. Required
 *      before S3 (symbol surface index) or S4b (heuristic dispatch) can run.
 *
 * All MCP calls are executed by the orchestrator agent; this module only
 * provides the TypeScript types and helper functions that bob-runner.ts uses
 * to drive those calls and interpret their results.
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
exports.resolveCacheState = exports.resolveSessionDir = exports.buildTargetDomain = void 0;
exports.validateRepoPath = validateRepoPath;
exports.sessionDirExists = sessionDirExists;
exports.buildInitParams = buildInitParams;
exports.normaliseInitResult = normaliseInitResult;
exports.normaliseInventoryResult = normaliseInventoryResult;
exports.prepareS2 = prepareS2;
exports.formatStepFailureJson = formatStepFailureJson;
const fs = __importStar(require("node:fs"));
const path = __importStar(require("node:path"));
const os = __importStar(require("node:os"));
// ---------------------------------------------------------------------------
// Re-export session-cache helpers so callers only need one import
// ---------------------------------------------------------------------------
var session_cache_js_1 = require("./session-cache.js");
Object.defineProperty(exports, "buildTargetDomain", { enumerable: true, get: function () { return session_cache_js_1.buildTargetDomain; } });
Object.defineProperty(exports, "resolveSessionDir", { enumerable: true, get: function () { return session_cache_js_1.resolveSessionDir; } });
Object.defineProperty(exports, "resolveCacheState", { enumerable: true, get: function () { return session_cache_js_1.resolveCacheState; } });
// ---------------------------------------------------------------------------
// Repo path validation helpers
// ---------------------------------------------------------------------------
/**
 * Remote-shape patterns that are never valid for --repo.
 * The agent must refuse these before calling bob_init_repo_session.
 */
const REMOTE_SHAPE_PATTERNS = [
    /^git@/,
    /^git\+/,
    /^ssh:\/\//,
    /^https?:\/\//,
    // Bare "owner/repo" slug — two non-empty path segments with no leading slash.
    /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/,
];
/**
 * Validate the --repo argument before calling bob_init_repo_session.
 *
 * Returns null on success, or a structured S2InitError on failure.
 *
 * @param repoPath - The value supplied via --repo (may be relative at entry).
 * @param resolved  - The resolved absolute path (from path.resolve(repoPath)).
 */
function validateRepoPath(repoPath, resolved) {
    // 1. Refuse remote shapes (checked against the raw input, not the resolved
    //    path, since remote shapes cannot produce a valid local absolute path).
    for (const pattern of REMOTE_SHAPE_PATTERNS) {
        if (pattern.test(repoPath.trim())) {
            return {
                code: "repo_path_remote_shape",
                message: `--repo value looks like a remote reference: "${repoPath}". ` +
                    "bob-diff-review requires a locally checked-out directory. " +
                    "Pass an absolute path to a directory on the runner filesystem.",
            };
        }
    }
    // 2. Must exist.
    if (!fs.existsSync(resolved)) {
        return {
            code: "repo_path_not_found",
            message: `Resolved repo path "${resolved}" does not exist. ` +
                "Ensure the repository is checked out before invoking the skill.",
        };
    }
    // 3. Must be a directory.
    const stat = fs.statSync(resolved);
    if (!stat.isDirectory()) {
        return {
            code: "repo_path_not_directory",
            message: `Resolved repo path "${resolved}" exists but is not a directory (it is a file). ` +
                "Pass the repository root, not a file path.",
        };
    }
    return null;
}
/**
 * Detect whether a Bob session already exists for this target_domain.
 *
 * The session directory lives at ~/hacker-bob-sessions/<target_domain>.
 * When it exists (restored from C2 cache), bob_init_repo_session should be
 * called with the same arguments so the MCP server resumes rather than
 * creating a fresh session.  bob-runner.ts logs this as a cache resume.
 *
 * @param targetDomain - e.g. 'gh-12345678'
 * @returns true when the session directory exists.
 */
function sessionDirExists(targetDomain) {
    const sessionDir = path.join(os.homedir(), "hacker-bob-sessions", targetDomain);
    return fs.existsSync(sessionDir);
}
/**
 * Build the bob_init_repo_session parameters for the S2 step.
 *
 * The caller should pass these to the MCP tool via the orchestrator agent.
 * `is_resume` is set based on whether the session directory already exists
 * so the agent can log the correct context without re-checking the filesystem.
 *
 * @param repoPath     - Validated absolute path to the checked-out repo.
 * @param targetDomain - 'gh-' + github.repository_id from C2.
 * @param opts         - Optional provenance and profile overrides.
 */
function buildInitParams(repoPath, targetDomain, opts = {}) {
    const is_resume = sessionDirExists(targetDomain);
    return {
        repo_path: repoPath,
        target_domain: targetDomain,
        egress_profile: opts.egress_profile ?? "default",
        deep_mode: opts.deep_mode ?? false,
        is_resume,
        ...(opts.commit !== undefined && { commit: opts.commit }),
        ...(opts.branch !== undefined && { branch: opts.branch }),
        ...(opts.source_url !== undefined && { source_url: opts.source_url }),
    };
}
// ---------------------------------------------------------------------------
// MCP result normalisation
// ---------------------------------------------------------------------------
/**
 * Normalise a raw bob_init_repo_session MCP response into an S2InitResult.
 *
 * The MCP tool returns a JSON object whose shape varies between success and
 * error. This function coerces either shape into the discriminated union used
 * by bob-runner.ts so that all error handling is in one place.
 *
 * @param raw        - Raw MCP response (parsed JSON or thrown error object).
 * @param params     - Parameters that were passed to the MCP call.
 * @param isResume   - Whether the call was a resume (session dir pre-existed).
 */
function normaliseInitResult(raw, params, isResume) {
    // MCP errors are typically thrown as objects with a `code` and `message`.
    if (raw instanceof Error || (typeof raw === "object" && raw !== null && "error" in raw)) {
        const errObj = raw;
        const code = errObj["code"] ?? "mcp_error";
        const message = errObj["message"] ??
            (raw instanceof Error ? raw.message : JSON.stringify(raw));
        return {
            ok: false,
            error: {
                code: mapMcpErrorCode(code),
                message,
                cause: raw,
            },
        };
    }
    // Success path: MCP returns an object with session_id and session_dir.
    if (typeof raw === "object" && raw !== null) {
        const resp = raw;
        const session_id = resp["session_id"] ??
            resp["data"]?.["session_id"];
        const session_dir = resp["session_dir"] ??
            resp["data"]?.["session_dir"];
        if (session_id && session_dir) {
            return {
                ok: true,
                session_id,
                session_dir,
                target_domain: params.target_domain,
                is_resume: isResume,
            };
        }
        // Got an object but missing required fields — treat as unknown error.
        return {
            ok: false,
            error: {
                code: "mcp_error",
                message: `bob_init_repo_session returned an unexpected response shape: ` +
                    JSON.stringify(raw).slice(0, 500),
                cause: raw,
            },
        };
    }
    return {
        ok: false,
        error: {
            code: "unknown",
            message: `bob_init_repo_session returned an unexpected value type (${typeof raw}): ` +
                String(raw).slice(0, 200),
            cause: raw,
        },
    };
}
/**
 * Map raw MCP error code strings to our typed S2InitError codes.
 */
function mapMcpErrorCode(raw) {
    const MAP = {
        repo_path_not_found: "repo_path_not_found",
        repo_path_not_directory: "repo_path_not_directory",
        remote_repo_forbidden: "repo_path_remote_shape",
        target_domain_mismatch: "target_domain_mismatch",
        session_corrupt: "session_corrupt",
    };
    return MAP[raw] ?? "mcp_error";
}
/**
 * Normalise a raw bob_repo_inventory MCP response into an S2InventoryResult.
 *
 * @param raw - Raw MCP response object.
 */
function normaliseInventoryResult(raw) {
    if (raw instanceof Error || (typeof raw === "object" && raw !== null && "error" in raw)) {
        const errObj = raw;
        return {
            ok: false,
            file_count: 0,
            sample: [],
            languages: {},
            error: {
                code: errObj["code"] ?? "mcp_error",
                message: errObj["message"] ??
                    (raw instanceof Error ? raw.message : JSON.stringify(raw)),
            },
        };
    }
    if (typeof raw === "object" && raw !== null) {
        const resp = raw;
        // Support both flat and nested `data` wrappers from the MCP server.
        const data = resp["data"] ?? resp;
        const file_count = data["file_count"] ??
            data["total_files"] ??
            (Array.isArray(data["files"]) ? data["files"].length : 0);
        const rawFiles = data["files"] ?? [];
        const sample = rawFiles.slice(0, 50).map((f) => {
            if (typeof f === "object" && f !== null) {
                const fe = f;
                return {
                    path: fe["path"] ?? fe["file"] ?? "",
                    language: fe["language"] ?? fe["lang"],
                    kind: fe["kind"] ?? fe["type"],
                };
            }
            return { path: String(f) };
        });
        const rawLangs = data["languages"] ?? {};
        const languages = {};
        for (const [lang, count] of Object.entries(rawLangs)) {
            if (typeof count === "number")
                languages[lang] = count;
        }
        return { ok: true, file_count, sample, languages };
    }
    return {
        ok: false,
        file_count: 0,
        sample: [],
        languages: {},
        error: {
            code: "unknown",
            message: `bob_repo_inventory returned unexpected value type (${typeof raw})`,
        },
    };
}
/**
 * Validate repo_arg, derive InitRepoSessionParams, and return both the params
 * and a pre-flight validation error (if any) so the orchestrator agent can
 * perform the MCP calls itself.
 *
 * This function does NOT call MCP tools — it is a pure helper that the agent
 * uses to determine what to pass and whether to proceed.
 *
 * Pattern:
 *   1. Agent calls `prepareS2` to validate inputs and learn resume semantics.
 *   2. Agent calls `mcp__hacker-bob__bob_init_repo_session` with params.mcp_params.
 *   3. Agent calls `normaliseInitResult` on the response.
 *   4. Agent calls `mcp__hacker-bob__bob_repo_inventory` with params.target_domain.
 *   5. Agent calls `normaliseInventoryResult` on the response.
 *   6. Agent surfaces failure_json if either step fails.
 */
function prepareS2(args) {
    const resolved = path.resolve(args.repo_arg);
    const validation_error = validateRepoPath(args.repo_arg, resolved);
    if (validation_error !== null) {
        return {
            validation_error,
            mcp_params: null,
            resolved_repo_path: resolved,
            is_resume: false,
        };
    }
    const mcp_params = buildInitParams(resolved, args.target_domain, {
        commit: args.commit,
        branch: args.branch,
        source_url: args.source_url,
        egress_profile: "default",
        deep_mode: false,
    });
    return {
        validation_error: null,
        mcp_params,
        resolved_repo_path: resolved,
        is_resume: mcp_params.is_resume ?? false,
    };
}
/**
 * Format a structured JSON error string for step failure surfacing.
 *
 * The orchestrator agent writes this to stdout as a JSON line so that
 * downstream callers (bob-runner.ts, GitHub Actions step summary) can parse it
 * without regex-scraping prose error messages.
 *
 * @param step   - Pipeline step label, e.g. 'S2.init' or 'S2.inventory'.
 * @param error  - The S2InitError to serialise.
 */
function formatStepFailureJson(step, error) {
    return JSON.stringify({
        step,
        ok: false,
        error: {
            code: error.code,
            message: error.message,
        },
    }, null, 2);
}
//# sourceMappingURL=session-init.js.map