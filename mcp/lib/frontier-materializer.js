"use strict";

const {
  assertSafeDomain,
  surfaceIndexPath,
  taskQueuePath,
} = require("./paths.js");
const {
  hashDocumentExcluding,
  normalizeOptionalTextArray,
  sortByTextField,
  writeJsonDocument,
} = require("./fabric-common.js");
const {
  readFrontierEvents,
} = require("./frontier-events.js");
const {
  withSessionLock,
} = require("./storage.js");
const {
  normalizeTask,
  taskQueueKey,
} = require("./tasks.js");
const {
  compareQueuedTasks,
  normalizeQueuePolicy,
} = require("./queue-policy.js");
const {
  compareObservationEvents,
  normalizeObservationEvent,
} = require("./frontier-projections.js");
const {
  SURFACE_KIND_VALUES,
} = require("./constants.js");
const {
  TRANSITION_KIND_VALUES,
} = require("./task-graph-events.js");

function uniqueSorted(values) {
  return Array.from(new Set(values.filter((value) => typeof value === "string" && value.length > 0))).sort();
}

function addUnique(target, value) {
  if (typeof value === "string" && value.length > 0 && !target.includes(value)) {
    target.push(value);
  }
}

function ensureSurface(surfacesById, domain, surfaceId, ts) {
  if (!surfacesById.has(surfaceId)) {
    surfacesById.set(surfaceId, {
      surface_id: surfaceId,
      target_domain: domain,
      state: "open",
      first_seen_at: ts,
      last_seen_at: ts,
      labels: [],
      source_event_ids: [],
      task_ids: [],
      observation_event_ids: [],
      observations: [],
      control_expectation_event_ids: [],
      blocker_event_ids: [],
      closure_event_ids: [],
    });
  }
  const surface = surfacesById.get(surfaceId);
  if (Date.parse(ts) < Date.parse(surface.first_seen_at)) surface.first_seen_at = ts;
  if (Date.parse(ts) > Date.parse(surface.last_seen_at)) surface.last_seen_at = ts;
  return surface;
}

// Scalar text fields that a surface.observed payload may carry. Captured into
// the materialized surface so downstream readers (phase-gates, ranking,
// surface-router) can consume surface-index.json as the authoritative source
// instead of reading attack_surface.json directly (Cycle F.5).
const SURFACE_SCALAR_TEXT_FIELDS = [
  "title",
  "uri",
  "method",
  "kind",
  "owner",
  "priority",
  "surface_type",
  "attack_vector",
  "severity_ceiling",
  "chain_family",
  "file_path",
  "language",
];

const SURFACE_BOOLEAN_FIELDS = [
  "network_reachable",
  "native_source",
  "native_build",
];

// Array text fields carried by surface.observed payloads. Mirrors the legacy
// attack_surface.json schema fields used by ranking.scoreSurfaceRanking and
// related readers.
const SURFACE_TEXT_ARRAY_FIELDS = [
  "hosts",
  "tech_stack",
  "endpoints",
  "interesting_params",
  "nuclei_hits",
  "js_hints",
  "leaked_secrets",
  "bug_class_hints",
  "high_value_flows",
  "evidence",
  "network_reachable_anchors",
  "network_reachable_dirs",
  "local_only_candidate_dirs",
  "residual_hunt_targets",
];

function safeStringArray(value) {
  if (value == null) return [];
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed ? [trimmed] : [];
  }
  if (!Array.isArray(value)) return [];
  const seen = new Set();
  const result = [];
  for (const item of value) {
    if (typeof item !== "string") continue;
    const trimmed = item.trim();
    if (!trimmed || seen.has(trimmed)) continue;
    seen.add(trimmed);
    result.push(trimmed);
  }
  return result;
}

function applySurfaceFields(surface, event) {
  const payload = event.payload || {};
  for (const field of SURFACE_SCALAR_TEXT_FIELDS) {
    if (typeof payload[field] === "string" && payload[field].trim()) {
      surface[field] = payload[field].trim();
    }
  }
  for (const field of SURFACE_BOOLEAN_FIELDS) {
    if (typeof payload[field] === "boolean") {
      surface[field] = payload[field];
    } else if (payload[field] === "true" || payload[field] === "false") {
      surface[field] = payload[field] === "true";
    }
  }
  for (const field of SURFACE_TEXT_ARRAY_FIELDS) {
    const values = safeStringArray(payload[field]);
    if (values.length === 0) continue;
    if (!Array.isArray(surface[field])) surface[field] = [];
    for (const value of values) addUnique(surface[field], value);
    surface[field].sort();
  }
  for (const label of normalizeOptionalTextArray(payload.labels || event.tags, "labels")) {
    addUnique(surface.labels, label);
  }
  surface.labels.sort();
  addUnique(surface.source_event_ids, event.event_id);
}

function taskInputFromEvent(event) {
  const payload = event.payload || {};
  const taskPayload = payload.task && typeof payload.task === "object" && !Array.isArray(payload.task)
    ? payload.task
    : payload;
  return {
    ...taskPayload,
    target_domain: event.target_domain,
    surface_id: event.surface_id || taskPayload.surface_id,
    lens: taskPayload.lens || "surface_scout",
    priority: taskPayload.priority || "medium",
    status: taskPayload.status || "queued",
    created_at: event.ts,
    source_event_id: event.event_id,
    frontier_item_id: event.frontier_item_id || taskPayload.frontier_item_id,
  };
}

function refreshTaskHash(task) {
  return normalizeTask(task, { targetDomain: task.target_domain, now: new Date(task.created_at) });
}

function markTask(tasksByKey, event, statusField, eventListField) {
  const key = event.frontier_item_id || event.task_id;
  if (!key || !tasksByKey.has(key)) return;
  const task = { ...tasksByKey.get(key) };
  task.status = statusField;
  const refs = Array.isArray(task[eventListField]) ? task[eventListField].slice() : [];
  addUnique(refs, event.event_id);
  task[eventListField] = refs;
  tasksByKey.set(key, refreshTaskHash(task));
}

// X.3 / X-P6: a transition surface persisted in surface-index.json with
// kind: "transition". The transition_id is derived deterministically so a
// repeated transition_proposed event for the same (from, to, transition_kind)
// folds into the same entry. Per X-P9 the payload is summary-grade:
// trust_assumption is already capped at 512 chars at append time (X.1).
function transitionSurfaceId(payload, eventId) {
  const proposalId = typeof payload.proposal_id === "string" ? payload.proposal_id.trim() : "";
  if (proposalId) return `transition:${proposalId}`;
  const from = typeof payload.from_surface === "string" ? payload.from_surface.trim() : "";
  const to = typeof payload.to_surface === "string" ? payload.to_surface.trim() : "";
  const kind = typeof payload.transition_kind === "string" ? payload.transition_kind.trim() : "";
  if (from && to && kind) {
    return `transition:${from}::${to}::${kind}`;
  }
  // Last-resort: bind to the event id so the fold is still stable. Should be
  // unreachable because appendTransitionProposal rejects missing fields.
  return `transition:event:${eventId}`;
}

function ensureTransition(transitionsById, domain, transitionId, ts, fromSurface, toSurface, transitionKind) {
  if (!transitionsById.has(transitionId)) {
    transitionsById.set(transitionId, {
      transition_id: transitionId,
      target_domain: domain,
      // X-P6: kind: "transition" is the surface-kind discriminator. The
      // closed enum lives in SURFACE_KIND_VALUES (X.3 / constants.js).
      kind: "transition",
      from_surface: fromSurface,
      to_surface: toSurface,
      transition_kind: transitionKind,
      trust_assumption: null,
      evidence_refs: [],
      first_seen_at: ts,
      last_seen_at: ts,
      source_event_ids: [],
    });
  }
  const transition = transitionsById.get(transitionId);
  if (Date.parse(ts) < Date.parse(transition.first_seen_at)) transition.first_seen_at = ts;
  if (Date.parse(ts) > Date.parse(transition.last_seen_at)) transition.last_seen_at = ts;
  return transition;
}

function applyTransitionFields(transition, payload) {
  if (typeof payload.trust_assumption === "string" && payload.trust_assumption.trim()) {
    // The most recent trust_assumption wins (a re-proposal with refined
    // wording overwrites). Already capped at 512 chars by appendTransitionProposal.
    transition.trust_assumption = payload.trust_assumption.trim();
  }
  if (Array.isArray(payload.evidence_refs)) {
    for (const ref of payload.evidence_refs) {
      if (typeof ref !== "string") continue;
      const trimmed = ref.trim();
      if (!trimmed) continue;
      if (!transition.evidence_refs.includes(trimmed)) {
        transition.evidence_refs.push(trimmed);
      }
    }
  }
}

function materializeFrontierDocument(domain, { write = false, now = new Date(), queuePolicy = {} } = {}) {
  const events = readFrontierEvents(domain);
  const policy = normalizeQueuePolicy(queuePolicy);
  const surfacesById = new Map();
  const tasksByKey = new Map();
  // X.3 / X-P6: transitions persist alongside surfaces in surface-index.json
  // as first-class entries (kind: "transition"). They are keyed by
  // transitionSurfaceId() not surface_id so they cannot collide with
  // surface-observed entries (which are keyed by surface_id from the event).
  const transitionsById = new Map();

  for (const event of events) {
    if (event.surface_id) {
      const surface = ensureSurface(surfacesById, domain, event.surface_id, event.ts);
      addUnique(surface.source_event_ids, event.event_id);
    }

    if (event.kind === "surface.observed" && event.surface_id) {
      applySurfaceFields(ensureSurface(surfacesById, domain, event.surface_id, event.ts), event);
    }

    if (event.kind === "observation.recorded" && event.surface_id) {
      const surface = ensureSurface(surfacesById, domain, event.surface_id, event.ts);
      addUnique(surface.observation_event_ids, event.event_id);
      surface.observations.push(normalizeObservationEvent(event));
    }

    // X.3: transition_proposed observation events fold into the transitions[]
    // section of surface-index.json. These observation events do NOT carry a
    // surface_id (they describe a bridge between two surfaces) so they do not
    // attach observations to either endpoint; the materializer surfaces the
    // bridge as its own entry per X-P6.
    if (
      event.kind === "observation.recorded"
      && event.payload
      && event.payload.kind === "transition_proposed"
    ) {
      const payload = event.payload;
      const fromSurface = typeof payload.from_surface === "string" ? payload.from_surface.trim() : "";
      const toSurface = typeof payload.to_surface === "string" ? payload.to_surface.trim() : "";
      const transitionKind = typeof payload.transition_kind === "string" ? payload.transition_kind.trim() : "";
      if (fromSurface && toSurface && transitionKind) {
        const transitionId = transitionSurfaceId(payload, event.event_id);
        const transition = ensureTransition(
          transitionsById,
          domain,
          transitionId,
          event.ts,
          fromSurface,
          toSurface,
          transitionKind,
        );
        applyTransitionFields(transition, payload);
        if (!transition.source_event_ids.includes(event.event_id)) {
          transition.source_event_ids.push(event.event_id);
        }
      }
    }

    if (event.kind === "control_expectation.recorded" && event.surface_id) {
      const surface = ensureSurface(surfacesById, domain, event.surface_id, event.ts);
      addUnique(surface.control_expectation_event_ids, event.event_id);
    }

    if (event.kind === "frontier.enqueued") {
      // frontier.enqueued events from intake (bob_record_surface_leads) do
      // not carry a surface_id until the lead is promoted via
      // bob_promote_surface_leads. Skip task materialization for those
      // intake-only enqueues; the promotion path emits a separate
      // surface.observed event with the allocated surface_id, and a
      // subsequent enqueue with surface_ref binds the lead-task to a
      // promoted surface.
      const taskInput = taskInputFromEvent(event);
      if (typeof taskInput.surface_id === "string" && taskInput.surface_id.trim()) {
        const task = normalizeTask(taskInput, { targetDomain: domain, now: new Date(event.ts) });
        tasksByKey.set(taskQueueKey(task), task);
        const surface = ensureSurface(surfacesById, domain, task.surface_id, event.ts);
        addUnique(surface.task_ids, task.task_id);
        addUnique(surface.source_event_ids, event.event_id);
      }
    }

    if (event.kind === "blocker.asserted") {
      markTask(tasksByKey, event, "blocked", "blocker_event_ids");
      if (event.surface_id) {
        const surface = ensureSurface(surfacesById, domain, event.surface_id, event.ts);
        addUnique(surface.blocker_event_ids, event.event_id);
        if (surface.state !== "closed") surface.state = "blocked";
      }
    }

    if (event.kind === "closure.recorded") {
      markTask(tasksByKey, event, "closed", "closure_event_ids");
      if (event.surface_id) {
        const surface = ensureSurface(surfacesById, domain, event.surface_id, event.ts);
        addUnique(surface.closure_event_ids, event.event_id);
        surface.state = "closed";
      }
    }
  }

  const surfaces = Array.from(surfacesById.values())
    .map((surface) => {
      // Deduplicate observation entries by event_id (events can be referenced
      // by multiple branches of the fold) and order them deterministically by
      // (ts, event_id) so the same event log always yields the same hash.
      const observationsById = new Map();
      for (const observation of surface.observations) {
        if (observation && observation.event_id && !observationsById.has(observation.event_id)) {
          observationsById.set(observation.event_id, observation);
        }
      }
      const observations = Array.from(observationsById.values()).sort(compareObservationEvents);
      return {
        ...surface,
        labels: uniqueSorted(surface.labels),
        source_event_ids: uniqueSorted(surface.source_event_ids),
        task_ids: uniqueSorted(surface.task_ids),
        observation_event_ids: uniqueSorted(surface.observation_event_ids),
        observations,
        control_expectation_event_ids: uniqueSorted(surface.control_expectation_event_ids),
        blocker_event_ids: uniqueSorted(surface.blocker_event_ids),
        closure_event_ids: uniqueSorted(surface.closure_event_ids),
      };
    })
    .sort(sortByTextField("surface_id"));

  const tasks = Array.from(tasksByKey.values()).sort((a, b) => compareQueuedTasks(a, b, policy));
  const materializedAt = now instanceof Date ? now.toISOString() : new Date(now).toISOString();

  // X.3 / X-P6: transitions persist alongside surfaces in surface-index.json
  // so downstream readers (the X.5 capability-pack deriver, the X.11 cross-
  // stack brief composer) can recover the bridge fabric in one read. Each
  // entry carries kind: "transition" per the SURFACE_KIND_VALUES enum. Sort
  // by transition_id for stable hashing across re-materializations.
  const transitions = Array.from(transitionsById.values())
    .map((transition) => ({
      ...transition,
      evidence_refs: transition.evidence_refs.slice().sort(),
      source_event_ids: transition.source_event_ids.slice().sort(),
    }))
    .sort(sortByTextField("transition_id"));

  const surfaceIndex = {
    version: 1,
    target_domain: domain,
    materialized_at: materializedAt,
    source_event_count: events.length,
    surface_count: surfaces.length,
    transition_count: transitions.length,
    surfaces,
    transitions,
  };
  surfaceIndex.surface_index_hash = hashDocumentExcluding(surfaceIndex, [
    "materialized_at",
    "surface_index_hash",
  ]);

  const taskQueue = {
    version: 1,
    target_domain: domain,
    materialized_at: materializedAt,
    source_event_count: events.length,
    policy,
    task_count: tasks.length,
    tasks,
  };
  taskQueue.task_queue_hash = hashDocumentExcluding(taskQueue, [
    "materialized_at",
    "task_queue_hash",
  ]);

  if (write) {
    writeJsonDocument(surfaceIndexPath(domain), surfaceIndex);
    writeJsonDocument(taskQueuePath(domain), taskQueue);
  }

  return {
    surface_index: surfaceIndex,
    task_queue: taskQueue,
  };
}

function materializeFrontier(targetDomain, options = {}) {
  const domain = assertSafeDomain(targetDomain);
  if (options.write) {
    return withSessionLock(domain, () => materializeFrontierDocument(domain, options));
  }
  return materializeFrontierDocument(domain, options);
}

module.exports = {
  materializeFrontier,
};
