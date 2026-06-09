/**
 * S5 — Evaluator agents: background, per impacted surface.
 *
 * This module implements the deduplication, prioritization, capping, and
 * agent-spawn protocol for the S5 pipeline step. For each unique surface_id
 * found in impacted_entries (from S4 PATH A or S4b PATH B), exactly one
 * evaluator agent is spawned. Agents run in background (parallel) and S6
 * waits for all to exit before proceeding.
 *
 * Acceptance criteria implemented here:
 *   1. One evaluator agent spawned per unique surface_id (deduplicated).
 *   2. Max concurrent evaluator agents capped at MAX_EVALUATOR_AGENTS (8,
 *      configurable via SKILL.md parameter).
 *   3. Each agent receives: session_id, surface_id, diff_hunks[] (file +
 *      line_start + line_end + hunk_text), target_domain.
 *   4. Each agent calls bob_record_candidate_claim for any confirmed finding
 *      before exiting.
 *   5. Each agent calls bob_log_coverage for its surface before exiting.
 *   6. S6 only starts after all spawned agents have exited (success or timeout).
 *
 * Failure modes guarded here:
 *   - Agent exits before calling bob_log_coverage — S6 must check coverage
 *     and log gap.
 *   - All agents timeout on a slow target — S6 must still produce valid
 *     (empty findings) output.
 *   - surface_id collision between PATH A and PATH B — deduplication normalises
 *     IDs (Set-based).
 *
 * Prioritization when capping:
 *   When unique surface_ids > MAX_EVALUATOR_AGENTS, surfaces are prioritized by
 *   surface_type order: smart_contract > auth > api-route > other.
 */
import type { ImpactedEntry } from "./heuristic-dispatch.js";
/**
 * Maximum number of concurrent evaluator agents spawned by S5.
 *
 * When the number of unique surface_ids exceeds this cap, surfaces are
 * prioritized by surface_type and the lowest-priority surfaces are dropped.
 * Configurable in SKILL.md via the `max_evaluator_agents` parameter.
 */
export declare const MAX_EVALUATOR_AGENTS = 8;
/**
 * Per-agent timeout in milliseconds (5 minutes).
 *
 * If an agent does not exit within this window, it is marked timed-out and
 * skipped in S6. S6 must check coverage for timed-out agents and log the gap.
 */
export declare const AGENT_TIMEOUT_MS: number;
/**
 * A diff hunk passed to each spawned evaluator agent.
 *
 * Provides the agent with precise code-change context for the surface it is
 * probing. For PATH B entries, hunk_text may be empty when only file-level
 * line ranges are available.
 */
export interface EvalDiffHunk {
    /** Repo-relative file path that changed. */
    file: string;
    /** First changed line (1-indexed). */
    line_start: number;
    /** Last changed line (1-indexed). */
    line_end: number;
    /**
     * Raw text of the diff hunk (may be empty for PATH B heuristic entries
     * where full hunk text was not available).
     */
    hunk_text: string;
}
/**
 * Context injected into each evaluator agent at spawn time.
 *
 * All four fields are required acceptance criteria from the S5 spec.
 */
export interface EvaluatorAgentContext {
    /** Bob session target_domain (e.g. 'gh-12345678'). */
    target_domain: string;
    /** Bob session_id returned by bob_init_repo_session. */
    session_id: string;
    /** The unique surface_id this agent is scoped to evaluate. */
    surface_id: string;
    /**
     * Diff hunks relevant to this surface_id — all impacted_entries that
     * carried this surface_id, with their file + line range + hunk text.
     */
    diff_hunks: EvalDiffHunk[];
}
/**
 * A spawned evaluator agent record tracked by the S5 orchestrator.
 */
export interface SpawnedAgent {
    /** The surface_id this agent was assigned. */
    surface_id: string;
    /** Context passed to the agent at spawn. */
    context: EvaluatorAgentContext;
    /** Epoch timestamp (ms) when the agent was spawned. */
    spawned_at: number;
    /**
     * Current lifecycle state of the agent.
     * - "running"    : agent is still running (background).
     * - "completed"  : agent exited successfully within the timeout window.
     * - "timed_out"  : agent did not exit within AGENT_TIMEOUT_MS.
     * - "skipped"    : agent was pruned by the surface cap before spawning.
     */
    status: "running" | "completed" | "timed_out" | "skipped";
    /** Epoch timestamp (ms) when the agent exited. Null if still running. */
    exited_at: number | null;
}
/**
 * Result returned by deduplicateAndPrioritize.
 */
export interface DeduplicationResult {
    /**
     * Deduplicated, priority-sorted, capped list of surface_ids to spawn.
     * Length is at most MAX_EVALUATOR_AGENTS.
     */
    surface_ids: string[];
    /**
     * Total unique surface_ids before the cap was applied.
     * Equals surface_ids.length when no cap was needed.
     */
    total_unique: number;
    /**
     * Number of surfaces dropped by the cap. Zero when total_unique <=
     * MAX_EVALUATOR_AGENTS.
     */
    capped_count: number;
    /**
     * Surface_ids dropped by the cap (for logging / diagnostics).
     */
    dropped_surfaces: string[];
}
/**
 * Result returned by buildAgentContexts.
 */
export interface AgentContextsResult {
    /** One context per spawned surface_id (after deduplication and capping). */
    contexts: EvaluatorAgentContext[];
    /** Deduplication metadata (for logging). */
    deduplication: DeduplicationResult;
}
/**
 * Result returned by buildS5SpawnPlan.
 *
 * Consumed by bob-runner.ts to drive background agent spawning and S6
 * readiness polling.
 */
export interface S5SpawnPlan {
    /**
     * Ordered list of agent contexts to spawn, one per unique surface_id.
     * Length is capped at MAX_EVALUATOR_AGENTS.
     */
    agents: EvaluatorAgentContext[];
    /**
     * Total unique surface_ids found in impacted_entries before capping.
     */
    total_unique_surfaces: number;
    /**
     * Number of surfaces dropped by the cap. Zero on normal-size PRs.
     */
    capped_count: number;
    /**
     * Surface_ids that were pruned by the cap (for log transparency).
     */
    dropped_surfaces: string[];
    /**
     * True when impacted_entries was empty or all entries had empty
     * surface_ids[]. When true, S5 logs 'no impacted surfaces' and exits
     * cleanly without spawning any agents.
     */
    is_empty: boolean;
}
/**
 * Collect all unique surface_ids from impacted_entries, then sort by priority
 * and cap at MAX_EVALUATOR_AGENTS.
 *
 * Surface_id normalisation:
 *   - Trimmed and lowercased for set membership (preserves original case for
 *     the returned list).
 *   - PATH A and PATH B IDs are deduped by exact string equality after trim;
 *     the normalisation avoids collisions between e.g. "heuristic:auth" and
 *     "auth" by treating them as distinct (they are distinct surfaces).
 *
 * @param impactedEntries - Array of ImpactedEntry from S4/S4b.
 * @param maxAgents       - Max agents to spawn (defaults to MAX_EVALUATOR_AGENTS).
 * @returns DeduplicationResult with capped surface list and diagnostics.
 */
export declare function deduplicateAndPrioritize(impactedEntries: ImpactedEntry[], maxAgents?: number): DeduplicationResult;
/**
 * Build the diff_hunks[] array for a given surface_id by collecting all
 * impacted_entries that include the surface_id.
 *
 * @param surfaceId       - The surface_id to collect hunks for.
 * @param impactedEntries - Full list of impacted_entries from S4/S4b.
 * @returns Array of EvalDiffHunk scoped to the surface.
 */
export declare function buildDiffHunksForSurface(surfaceId: string, impactedEntries: ImpactedEntry[]): EvalDiffHunk[];
/**
 * Build one EvaluatorAgentContext per deduplicated, capped surface_id.
 *
 * @param params - Spawn parameters.
 * @returns AgentContextsResult with one context per surface.
 */
export declare function buildAgentContexts(params: {
    impactedEntries: ImpactedEntry[];
    targetDomain: string;
    sessionId: string;
    maxAgents?: number;
}): AgentContextsResult;
/**
 * Build the complete S5 spawn plan from impacted_entries.
 *
 * This is the primary entry point consumed by bob-runner.ts. The caller uses
 * the returned `agents[]` to spawn one background evaluator agent per entry,
 * then polls for completion before unblocking S6.
 *
 * Logs:
 *   - 'S5: N unique surfaces from impacted_entries'
 *   - 'S5: spawning M evaluator agents (cap: MAX_EVALUATOR_AGENTS)'  (when not capped)
 *   - 'S5: capping at MAX_EVALUATOR_AGENTS — dropped K surfaces: [...]'  (when capped)
 *   - 'no impacted surfaces'  (when is_empty)
 *
 * @param impactedEntries - ImpactedEntry[] from S4 PATH A or S4b PATH B.
 * @param targetDomain    - Bob session target_domain (e.g. 'gh-12345678').
 * @param sessionId       - Bob session_id from bob_init_repo_session.
 * @param maxAgents       - Override for MAX_EVALUATOR_AGENTS (optional).
 * @returns S5SpawnPlan — callers pass agents[] to the background spawn loop.
 */
export declare function buildS5SpawnPlan(impactedEntries: ImpactedEntry[], targetDomain: string, sessionId: string, maxAgents?: number): S5SpawnPlan;
/**
 * Initialise a SpawnedAgent record when an agent is first spawned.
 *
 * @param context - The agent context passed at spawn time.
 * @returns A SpawnedAgent in "running" state.
 */
export declare function initSpawnedAgent(context: EvaluatorAgentContext): SpawnedAgent;
/**
 * Mark a running agent as completed.
 *
 * @param agent - The SpawnedAgent record to update.
 * @returns A new SpawnedAgent with status "completed" and exited_at set.
 */
export declare function markAgentCompleted(agent: SpawnedAgent): SpawnedAgent;
/**
 * Mark a running agent as timed-out.
 *
 * @param agent - The SpawnedAgent record to update.
 * @returns A new SpawnedAgent with status "timed_out" and exited_at set.
 */
export declare function markAgentTimedOut(agent: SpawnedAgent): SpawnedAgent;
/**
 * Check whether all spawned agents have exited (completed or timed_out).
 *
 * This is the S6 readiness predicate. S6 must not start until this returns
 * true.
 *
 * @param agents - Array of SpawnedAgent records tracked by the orchestrator.
 * @returns True when every agent is in a terminal state.
 */
export declare function allAgentsExited(agents: SpawnedAgent[]): boolean;
/**
 * Identify agents that have exceeded the per-agent timeout.
 *
 * The orchestrator polls this list to mark timed-out agents and unblock S6
 * when the timeout fires.
 *
 * @param agents    - Array of SpawnedAgent records.
 * @param timeoutMs - Timeout threshold (defaults to AGENT_TIMEOUT_MS).
 * @param nowMs     - Current epoch timestamp (defaults to Date.now()).
 * @returns Array of agents whose elapsed time exceeds timeoutMs.
 */
export declare function findTimedOutAgents(agents: SpawnedAgent[], timeoutMs?: number, nowMs?: number): SpawnedAgent[];
/**
 * Identify surfaces for which no coverage log was recorded.
 *
 * Called by S6 to detect agents that exited (or timed out) without calling
 * bob_log_coverage. S6 must log a gap entry for each missing surface.
 *
 * @param agents           - All spawned agents from S5.
 * @param coveredSurfaces  - Set of surface_ids that have logged coverage.
 * @returns Array of surface_ids that need a gap log entry in S6.
 */
export declare function findCoverageGaps(agents: SpawnedAgent[], coveredSurfaces: ReadonlySet<string>): string[];
/**
 * Format a structured JSON failure string for S5 error surfacing.
 *
 * @param error - Error detail.
 * @returns Pretty-printed JSON string.
 */
export declare function formatS5FailureJson(error: {
    code: string;
    message: string;
}): string;
//# sourceMappingURL=evaluator-dispatch.d.ts.map