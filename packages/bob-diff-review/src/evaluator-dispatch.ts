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

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Maximum number of concurrent evaluator agents spawned by S5.
 *
 * When the number of unique surface_ids exceeds this cap, surfaces are
 * prioritized by surface_type and the lowest-priority surfaces are dropped.
 * Configurable in SKILL.md via the `max_evaluator_agents` parameter.
 */
export const MAX_EVALUATOR_AGENTS = 8;

/**
 * Per-agent timeout in milliseconds (5 minutes).
 *
 * If an agent does not exit within this window, it is marked timed-out and
 * skipped in S6. S6 must check coverage for timed-out agents and log the gap.
 */
export const AGENT_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Surface type priority order for capping.
 * Higher index = lower priority. Surfaces not listed here get the lowest priority.
 *
 * Both underscore and hyphen variants are listed so heuristic:smart-contract
 * (PATH B) and smart_contract:vault (PATH A) both resolve to the highest
 * priority bucket.
 */
const SURFACE_TYPE_PRIORITY: ReadonlyArray<string> = [
  "smart_contract",
  "smart-contract",
  "authentication",
  "auth",
  "admin",
  "api-route",
  "api_route",
  "api",
  "upload",
  "data-model",
  "data_model",
  "crypto",
];

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Surface type extraction
// ---------------------------------------------------------------------------

/**
 * Infer a surface_type string from a surface_id for prioritization.
 *
 * Handles both index-derived IDs (e.g. "auth:login-handler") and PATH B
 * heuristic IDs (e.g. "heuristic:authentication"). Returns the raw surface_id
 * lowercased when no known type prefix is detected.
 */
function inferSurfaceType(surfaceId: string): string {
  const lower = surfaceId.toLowerCase();

  // PATH A index-derived IDs use colon-separated "type:name" convention.
  // PATH B heuristic IDs use "heuristic:type" convention.
  const colonIdx = lower.indexOf(":");
  if (colonIdx > -1) {
    const prefix = lower.slice(0, colonIdx);
    const suffix = lower.slice(colonIdx + 1);
    // "heuristic:<type>" -> extract the type portion after the colon.
    if (prefix === "heuristic") {
      return suffix;
    }
    // "auth:login-handler" -> prefix is "auth".
    return prefix;
  }

  return lower;
}

/**
 * Compute a numeric priority for a surface_id (lower = higher priority).
 *
 * Surfaces whose inferred type matches an earlier entry in SURFACE_TYPE_PRIORITY
 * get a lower (more important) priority number.
 *
 * @param surfaceId - Surface ID to score.
 * @returns An integer priority index (lower is better).
 */
function surfacePriority(surfaceId: string): number {
  const type = inferSurfaceType(surfaceId);
  const idx = SURFACE_TYPE_PRIORITY.findIndex(
    (t) => type === t || type.startsWith(t)
  );
  return idx === -1 ? SURFACE_TYPE_PRIORITY.length : idx;
}

// ---------------------------------------------------------------------------
// Deduplication and capping
// ---------------------------------------------------------------------------

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
export function deduplicateAndPrioritize(
  impactedEntries: ImpactedEntry[],
  maxAgents: number = MAX_EVALUATOR_AGENTS
): DeduplicationResult {
  // Collect unique surface_ids preserving the first-seen casing.
  const seen = new Set<string>();
  const uniqueSurfaces: string[] = [];

  for (const entry of impactedEntries) {
    for (const surfaceId of entry.surface_ids) {
      const normalised = surfaceId.trim();
      if (normalised.length === 0) continue;
      if (!seen.has(normalised)) {
        seen.add(normalised);
        uniqueSurfaces.push(normalised);
      }
    }
  }

  const total_unique = uniqueSurfaces.length;

  // Sort by priority (stable sort preserves insertion order for ties).
  const sorted = [...uniqueSurfaces].sort(
    (a, b) => surfacePriority(a) - surfacePriority(b)
  );

  const surface_ids = sorted.slice(0, maxAgents);
  const dropped_surfaces = sorted.slice(maxAgents);
  const capped_count = dropped_surfaces.length;

  return {
    surface_ids,
    total_unique,
    capped_count,
    dropped_surfaces,
  };
}

// ---------------------------------------------------------------------------
// Hunk aggregation
// ---------------------------------------------------------------------------

/**
 * Build the diff_hunks[] array for a given surface_id by collecting all
 * impacted_entries that include the surface_id.
 *
 * @param surfaceId       - The surface_id to collect hunks for.
 * @param impactedEntries - Full list of impacted_entries from S4/S4b.
 * @returns Array of EvalDiffHunk scoped to the surface.
 */
export function buildDiffHunksForSurface(
  surfaceId: string,
  impactedEntries: ImpactedEntry[]
): EvalDiffHunk[] {
  const hunks: EvalDiffHunk[] = [];

  for (const entry of impactedEntries) {
    if (!entry.surface_ids.includes(surfaceId)) continue;

    hunks.push({
      file: entry.file,
      line_start: entry.line_start,
      line_end: entry.line_end,
      // hunk_summary from ImpactedEntry becomes hunk_text for the evaluator.
      // Full hunk body text is not available in the ImpactedEntry schema;
      // hunk_summary is the closest available representation.
      hunk_text: entry.hunk_summary,
    });
  }

  return hunks;
}

// ---------------------------------------------------------------------------
// Agent context construction
// ---------------------------------------------------------------------------

/**
 * Build one EvaluatorAgentContext per deduplicated, capped surface_id.
 *
 * @param params - Spawn parameters.
 * @returns AgentContextsResult with one context per surface.
 */
export function buildAgentContexts(params: {
  impactedEntries: ImpactedEntry[];
  targetDomain: string;
  sessionId: string;
  maxAgents?: number;
}): AgentContextsResult {
  const { impactedEntries, targetDomain, sessionId, maxAgents } = params;

  const deduplication = deduplicateAndPrioritize(
    impactedEntries,
    maxAgents ?? MAX_EVALUATOR_AGENTS
  );

  const contexts: EvaluatorAgentContext[] = deduplication.surface_ids.map(
    (surfaceId) => ({
      target_domain: targetDomain,
      session_id: sessionId,
      surface_id: surfaceId,
      diff_hunks: buildDiffHunksForSurface(surfaceId, impactedEntries),
    })
  );

  return { contexts, deduplication };
}

// ---------------------------------------------------------------------------
// High-level S5 spawn plan
// ---------------------------------------------------------------------------

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
export function buildS5SpawnPlan(
  impactedEntries: ImpactedEntry[],
  targetDomain: string,
  sessionId: string,
  maxAgents: number = MAX_EVALUATOR_AGENTS
): S5SpawnPlan {
  if (impactedEntries.length === 0) {
    console.log("no impacted surfaces");
    return {
      agents: [],
      total_unique_surfaces: 0,
      capped_count: 0,
      dropped_surfaces: [],
      is_empty: true,
    };
  }

  const { contexts, deduplication } = buildAgentContexts({
    impactedEntries,
    targetDomain,
    sessionId,
    maxAgents,
  });

  // Empty after dedup (all entries had empty surface_ids[]).
  if (deduplication.total_unique === 0) {
    console.log("no impacted surfaces");
    return {
      agents: [],
      total_unique_surfaces: 0,
      capped_count: 0,
      dropped_surfaces: [],
      is_empty: true,
    };
  }

  console.log(
    `S5: ${deduplication.total_unique} unique surface${deduplication.total_unique === 1 ? "" : "s"} from impacted_entries`
  );

  if (deduplication.capped_count > 0) {
    console.warn(
      `S5: capping at ${maxAgents} — dropped ${deduplication.capped_count} surface${deduplication.capped_count === 1 ? "" : "s"}: ` +
        deduplication.dropped_surfaces.join(", ")
    );
  } else {
    console.log(
      `S5: spawning ${contexts.length} evaluator agent${contexts.length === 1 ? "" : "s"} (cap: ${maxAgents})`
    );
  }

  return {
    agents: contexts,
    total_unique_surfaces: deduplication.total_unique,
    capped_count: deduplication.capped_count,
    dropped_surfaces: deduplication.dropped_surfaces,
    is_empty: false,
  };
}

// ---------------------------------------------------------------------------
// Agent lifecycle helpers
// ---------------------------------------------------------------------------

/**
 * Initialise a SpawnedAgent record when an agent is first spawned.
 *
 * @param context - The agent context passed at spawn time.
 * @returns A SpawnedAgent in "running" state.
 */
export function initSpawnedAgent(context: EvaluatorAgentContext): SpawnedAgent {
  return {
    surface_id: context.surface_id,
    context,
    spawned_at: Date.now(),
    status: "running",
    exited_at: null,
  };
}

/**
 * Mark a running agent as completed.
 *
 * @param agent - The SpawnedAgent record to update.
 * @returns A new SpawnedAgent with status "completed" and exited_at set.
 */
export function markAgentCompleted(agent: SpawnedAgent): SpawnedAgent {
  return {
    ...agent,
    status: "completed",
    exited_at: Date.now(),
  };
}

/**
 * Mark a running agent as timed-out.
 *
 * @param agent - The SpawnedAgent record to update.
 * @returns A new SpawnedAgent with status "timed_out" and exited_at set.
 */
export function markAgentTimedOut(agent: SpawnedAgent): SpawnedAgent {
  return {
    ...agent,
    status: "timed_out",
    exited_at: Date.now(),
  };
}

/**
 * Check whether all spawned agents have exited (completed or timed_out).
 *
 * This is the S6 readiness predicate. S6 must not start until this returns
 * true.
 *
 * @param agents - Array of SpawnedAgent records tracked by the orchestrator.
 * @returns True when every agent is in a terminal state.
 */
export function allAgentsExited(agents: SpawnedAgent[]): boolean {
  return agents.every(
    (a) => a.status === "completed" || a.status === "timed_out" || a.status === "skipped"
  );
}

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
export function findTimedOutAgents(
  agents: SpawnedAgent[],
  timeoutMs: number = AGENT_TIMEOUT_MS,
  nowMs: number = Date.now()
): SpawnedAgent[] {
  return agents.filter(
    (a) => a.status === "running" && nowMs - a.spawned_at >= timeoutMs
  );
}

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
export function findCoverageGaps(
  agents: SpawnedAgent[],
  coveredSurfaces: ReadonlySet<string>
): string[] {
  return agents
    .filter(
      (a) =>
        (a.status === "completed" || a.status === "timed_out") &&
        !coveredSurfaces.has(a.surface_id)
    )
    .map((a) => a.surface_id);
}

/**
 * Format a structured JSON failure string for S5 error surfacing.
 *
 * @param error - Error detail.
 * @returns Pretty-printed JSON string.
 */
export function formatS5FailureJson(error: {
  code: string;
  message: string;
}): string {
  return JSON.stringify(
    {
      step: "S5.evaluator_dispatch",
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
