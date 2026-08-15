"use strict";

// run-event-curation — pure curate(rawEvent) -> WitnessEvent | null.
//
// One raw engine record in, one bounded display event out (or null, dropped).
// This is the projection that stands between bob's verbose on-disk ledgers
// (frontier-events.jsonl, coverage.jsonl, pipeline-events.jsonl, grade.json
// findings) and the live Witness the hosted-run visitor reads. It selects the
// DRAMATIC, NON-SENSITIVE subset and shapes it to the vocabulary the Witness
// drum already renders — the same Panel `kind`s a frozen report uses, arriving
// in time instead of pre-composed.
//
// PURITY: no fs, no clock, no env, no engine state. The runner reads the
// ledgers and feeds records here one at a time; the caller is responsible for
// writing the returned WitnessEvent into Convex (the streaming layer). This
// module decides only WHAT may be witnessed and in WHAT shape.
//
// DESIGN LAW (the surface this feeds is register-disciplined):
//   - A run_event is BREATH that accretes. Most curated events carry
//     register:"breath" — they manifest and stay.
//   - A genuine claim ("that one's mine") is the only STRIKE — register:"strike"
//     is reserved and rare (the cut-in, never decoration). curate() emits at
//     most strike-eligible events for real findings, never for traffic.
//   - The run's standing prose / disclosure is BODY — register:"body".
//   - There is no fourth register. There is no "status" / "log" / "badge".
//   - GOLD (signal) rides only on a found/severe terminus. curate() marks
//     `signal:true` ONLY on a reportable finding at the fix-now disposition or
//     a severe band — never on liveness, never on "running", never on closures.
//
// The frozen-report Panel kinds (witness.ts) are the rendering contract; the
// `kind` field below is drawn from that same set so a live event can flow into
// the existing renderers, with a `phase` (felt, never labeled) and a `signal`
// (gold permission) added as the temporal/liveness dimension the live run needs.

const {
  validateNoSensitiveMaterial,
} = require("../redaction/sensitive-material.js");
const {
  FRONTIER_EVENT_KINDS,
} = require("../frontier/frontier-events.js");
const {
  COVERAGE_STATUS_VALUES,
} = require("../../lib/constants.js");
const {
  PIPELINE_EVENT_TYPES,
} = require("./pipeline-events.js");
const {
  DEFENDER_DISPOSITION_VALUES,
} = require("../defender-disposition.js");

// ---------------------------------------------------------------------------
// Display bounds. The Witness reads, not audits — projected strings are short
// and the cardinality of any list is capped. These mirror the spirit of the
// engine's own caps (COVERAGE_SUMMARY_MAX_ITEMS et al) without importing them,
// because the DISPLAY budget is a perceptual choice, not a storage one.
// ---------------------------------------------------------------------------
const MAX_LABEL_CHARS = 64;
const MAX_CAPTION_CHARS = 160;
const MAX_DETAIL_CHARS = 200;
const MAX_LIST_ITEMS = 5;

// The felt lifecycle. These are NEVER rendered as text on the surface (the
// state is felt, not labeled) — they exist only to drive the unlabeled depth
// gauge and the field choreography. The order mirrors the Witness gauge's
// PHASE_ORDER so a live run reads on the same instrument a frozen story does.
const PHASE = Object.freeze({
  SETUP: "setup",
  FRONTIER: "frontier",
  CLAIM: "claim",
  VERIFY: "verify",
  GRADE: "grade",
  REPORT: "report",
  SEAL: "seal",
});

// Coverage status is severity-as-WEIGHT, not a color stack. `promising` is the
// only status that leans toward the lit end (it is a lead, breath that wants
// attention); everything else recedes to dim breath. No red/yellow/green.
const COVERAGE_WEIGHT = Object.freeze({
  promising: "lit",
  needs_auth: "dim",
  requeue: "dim",
  tested: "dim",
  blocked: "dim",
});

// Frontier kinds that are dramatic enough to witness live. Most of the ledger
// is bookkeeping (enqueue churn, control expectations, node transitions); the
// visitor sees the SEARCH, not the scheduler. session.seeded opens the field;
// surface.observed is the breadth ("one becomes many"); closure.recorded is the
// coverage_closeout lens (a door tried and held — it recedes, never deletes).
const WITNESSED_FRONTIER_KINDS = Object.freeze(new Set([
  "session.seeded",
  "surface.observed",
  "closure.recorded",
]));

// Pipeline types worth a beat. The provision/identity binding is the
// wait-as-presence + egress-disclosure moment; the report/seal types are the
// finality beat. finding_recorded is the genuine claim. Everything else
// (wave merges, verification archive churn, severity clamps) is internal
// bookkeeping the visitor never needs.
const WITNESSED_PIPELINE_TYPES = Object.freeze(new Set([
  "session_started",
  "egress_identity_bound",
  "finding_recorded",
  "report_written",
]));

// ---------------------------------------------------------------------------
// Small pure helpers.
// ---------------------------------------------------------------------------
function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

// Collapse whitespace and bound length. Returns "" for empty/non-string so the
// caller can decide whether an empty projection is allowed.
function clip(value, maxChars) {
  if (value == null) return "";
  const text = String(value).replace(/\s+/g, " ").trim();
  if (!text) return "";
  return text.length > maxChars ? `${text.slice(0, maxChars - 1)}…` : text;
}

// Surface family from a frontier surface_type, glossed for a non-expert. Kept
// to the engine's own surface_type tokens; unknowns pass through as the raw
// (already-bounded) token so the projection never invents a taxonomy.
const SURFACE_GLOSS = Object.freeze({
  api: "an API",
  admin: "an admin surface",
  billing: "a billing path",
  upload: "a file-upload path",
  secrets: "exposed key material",
  smart_contract: "a contract",
  web: "a web surface",
});

// ---------------------------------------------------------------------------
// The defender DISPOSITION is the deterministic relens the grade verdict ALREADY
// stamped on each finding — grade-verdict-store -> computeDefenderDisposition is
// the SINGLE producer (authoritative inputs: the reachability-graded severity, the
// per-finding score against the SAME imported HOLD/SUBMIT floors, and the verified
// reportable bit). curate() CONSUMES that word verbatim; it never re-derives it, so
// the live word streamed to the witness IS the sealed word on /r — one vocabulary,
// no drift. The canonical form is snake_case (DEFENDER_DISPOSITION_VALUES); the site
// maps it to its spoken form ("fix now" …) at render, not here.
// SUBMIT/HOLD/SKIP/EV/triager NEVER leak. `signal` (gold) rides ONLY "fix_now".
// ---------------------------------------------------------------------------
const FIX_NOW = "fix_now";
const HELD = "held";

// ---------------------------------------------------------------------------
// The WitnessEvent shape. A bounded, register-tagged, phase-felt display event.
// The runner writes this into Convex; the browser subscribes; Witness.svelte
// renders by `kind` exactly as it renders a frozen Panel, with `phase` driving
// the unlabeled gauge and `signal` granting (or withholding) gold.
//
//   {
//     kind:    one of the Witness Panel kinds (wire|attempts|spill|pivot|
//              matrix|code|grade|verdict) — the live event reuses a frozen face.
//     phase:   felt lifecycle (never labeled on-screen); drives the depth gauge.
//     register:"body" | "breath" | "strike" — the three-register law.
//     weight:  "lit" | "dim" — severity/attention as weight, never color.
//     signal:  boolean — gold permission; true ONLY at found/severe terminus.
//     event_hash: the content-addressed id from the source ledger (idempotency
//              key for the Convex writer — dedupes replays).
//     payload: the bounded, kind-specific display body.
//   }
// ---------------------------------------------------------------------------
function witnessEvent({ kind, phase, register, weight = "dim", signal = false, eventHash = null, payload }) {
  const event = {
    kind,
    phase,
    register,
    weight,
    signal: signal === true,
    payload,
  };
  if (eventHash) event.event_hash = String(eventHash).slice(0, 80);
  // Final fail-closed gate: the projected display event must carry NO secret,
  // auth header, cookie, or token in any field. The engine validated at
  // append-time, but curate() is the LAST boundary before a public surface, so
  // it re-asserts on the projection it just built. A throw here means a curator
  // branch leaked something — caught by the caller, which drops the event.
  validateNoSensitiveMaterial(event, "witness_event", { maxTextChars: MAX_DETAIL_CHARS });
  return event;
}

// ---------------------------------------------------------------------------
// Per-source curators. Each returns a WitnessEvent or null. Null is the common
// case (the ledger is mostly bookkeeping); the visitor sees the drama.
// ---------------------------------------------------------------------------

// FRONTIER — the search. session.seeded opens the field (body); surface.observed
// is breadth accreting (breath); closure.recorded is the coverage_closeout
// (breath that recedes, the door tried and held).
function curateFrontierEvent(raw) {
  const kind = raw.kind;
  if (!FRONTIER_EVENT_KINDS.includes(kind)) return null;
  if (!WITNESSED_FRONTIER_KINDS.has(kind)) return null;
  const payload = isPlainObject(raw.payload) ? raw.payload : {};
  const eventHash = raw.event_hash || null;

  if (kind === "session.seeded") {
    // The field opens. Body: the run's standing prose. No target name is
    // projected (the seed map can carry a real domain) — only that the engagement
    // began. Bob narrates the wait; this is the first true line.
    return witnessEvent({
      kind: "wire",
      phase: PHASE.SETUP,
      register: "body",
      weight: "dim",
      eventHash,
      payload: {
        label: clip("the field opens", MAX_LABEL_CHARS),
        // Bob's voice: first person, two clauses, present tense, no promise.
        caption: clip("I have the scope. I start from the outside.", MAX_CAPTION_CHARS),
        req: "",
        res: "",
      },
    });
  }

  if (kind === "surface.observed") {
    // Breadth: one observation. The spill/cascade lens — "one becomes many".
    // Projected as `wire` (a surface seen) with a count when present; the field
    // performs the cascade, this carries only the bounded line.
    const surfaceType = clip(payload.surface_type, 32);
    const gloss = SURFACE_GLOSS[surfaceType]
      || (surfaceType && surfaceType !== "unknown" ? surfaceType : "a surface");
    const endpoints = Array.isArray(payload.endpoints) ? payload.endpoints.length : 0;
    const title = clip(payload.title, MAX_LABEL_CHARS) || "surface";
    return witnessEvent({
      kind: "wire",
      phase: PHASE.FRONTIER,
      register: "breath",
      weight: "dim", // a lead is breath; it does not get gold or warn.
      eventHash,
      payload: {
        label: title,
        caption: clip(`I see ${gloss}.`, MAX_CAPTION_CHARS),
        req: "",
        res: "",
        routes: endpoints > 0 ? Math.min(endpoints, 9999) : undefined,
      },
    });
  }

  // closure.recorded — coverage_closeout. A door was tried. It recedes to
  // breath-weight; it is NEVER a strike and NEVER deleted from the ledger.
  const tested = Number.isFinite(payload.tested) ? payload.tested : 0;
  const blocked = Number.isFinite(payload.blocked) ? payload.blocked : 0;
  const promising = Number.isFinite(payload.promising) ? payload.promising : 0;
  const items = [];
  if (tested) items.push({ attempt: `${tested} tried`, held: "tested" });
  if (blocked) items.push({ attempt: `${blocked} blocked`, held: "held" });
  if (promising) items.push({ attempt: `${promising} promising`, held: "open" });
  if (items.length === 0) return null; // an empty closure is not dramatic.
  return witnessEvent({
    kind: "attempts",
    phase: PHASE.FRONTIER,
    register: "breath",
    weight: promising > 0 ? "lit" : "dim",
    eventHash,
    payload: {
      label: clip("doors", MAX_LABEL_CHARS),
      caption: clip("I close what holds.", MAX_CAPTION_CHARS),
      stamp: clip(raw.surface_id, 48) || "surface",
      items: items.slice(0, MAX_LIST_ITEMS),
    },
  });
}

// COVERAGE — the per-endpoint probe. A `promising` lead is the dramatic case
// (breath that leans lit); everything else is dim breath that accretes. The
// evidence_summary is bob's own words and is bounded; next_step "none -
// hardened" is the hardened lens (a clean miss, witnessed honestly).
function curateCoverageRecord(raw) {
  const status = raw.status;
  if (!COVERAGE_STATUS_VALUES.includes(status)) return null;
  // Witness only the PATH — drop any ?query/#fragment before display. A probed URL
  // routinely carries a reset/session token or PII in its query; that must not ride
  // onto the public witness surface (the sensitive-material gate is the backstop,
  // not the only line of defense).
  const pathOnly = typeof raw.endpoint === "string" ? raw.endpoint.split(/[?#]/)[0] : raw.endpoint;
  const endpoint = clip(pathOnly, MAX_LABEL_CHARS);
  if (!endpoint) return null;
  const bugClass = clip(raw.bug_class, 40);
  const summary = clip(raw.evidence_summary, MAX_CAPTION_CHARS);
  const nextStep = clip(raw.next_step, MAX_DETAIL_CHARS);
  // A hardened miss ("none - hardened" / "none") still witnesses honestly — bob
  // does not hide a clean target. But a bare tested record with no summary is
  // not dramatic; drop it to keep the ledger a search, not a log.
  if (status === "tested" && !summary) return null;
  return witnessEvent({
    kind: "matrix",
    phase: PHASE.FRONTIER,
    register: "breath",
    weight: COVERAGE_WEIGHT[status] || "dim",
    eventHash: null, // coverage records are not content-addressed; caller keys on ts+endpoint.
    payload: {
      label: bugClass || "probe",
      caption: clip(`I test ${endpoint}.`, MAX_CAPTION_CHARS),
      cols: [{ name: endpoint, status, open: status === "promising" }],
      confirm: summary || nextStep || "",
    },
  });
}

// PIPELINE — provision, identity, the genuine claim, the seal.
function curatePipelineEvent(raw) {
  const type = raw.type;
  if (!PIPELINE_EVENT_TYPES.includes(type)) return null;
  if (!WITNESSED_PIPELINE_TYPES.has(type)) return null;

  if (type === "session_started") {
    // Wait-as-presence. The container is provisioning; Bob narrates. Body voice,
    // no spinner, no percent — the line itself is the proof a wait is held.
    return witnessEvent({
      kind: "wire",
      phase: PHASE.SETUP,
      register: "body",
      weight: "dim",
      payload: {
        label: clip("a room is made", MAX_LABEL_CHARS),
        caption: clip("I spin up a clean machine. It exists only for this.", MAX_CAPTION_CHARS),
        req: "",
        res: "",
      },
    });
  }

  if (type === "egress_identity_bound") {
    // Egress-identity disclosure. Plain Body/Breath, /transparency voice — who
    // the container IS on the wire. The hash is a fingerprint, never a secret;
    // it is disclosure, NOT a verified-checkmark or lock icon, and NOT gold.
    const hash = clip(raw.egress_profile_identity_hash, 64);
    const region = clip(raw.egress_region, 48);
    const profile = clip(raw.egress_profile, 48);
    const where = region ? ` from ${region}` : "";
    const fingerprint = hash ? ` ${hash.slice(0, 12)}…` : "";
    return witnessEvent({
      kind: "wire",
      phase: PHASE.SETUP,
      register: "body",
      weight: "dim",
      payload: {
        label: clip("the adversary you watch", MAX_LABEL_CHARS),
        caption: clip(`This is who I am on the wire${where}.`, MAX_CAPTION_CHARS),
        req: clip(profile || "egress profile", 48),
        res: clip(`identity${fingerprint}`, MAX_DETAIL_CHARS),
      },
    });
  }

  if (type === "report_written") {
    // The finality / seal beat. Strike discipline reused as a CLOSING, not a
    // finding — reads as cleanliness and relief, never as error/disconnected.
    // The mechanical forgetting is witnessed: the room is sealed and will be
    // destroyed. No gold (this is not a found event).
    return witnessEvent({
      kind: "verdict",
      phase: PHASE.SEAL,
      register: "strike",
      weight: "dim",
      payload: {
        label: clip("sealed", MAX_LABEL_CHARS),
        verdict: "",
        total: "",
        // Bob's voice: the forgetting is mechanical, not rhetorical.
        meta: clip("I sealed the result. The room is gone.", MAX_CAPTION_CHARS),
        filing: "",
      },
    });
  }

  // finding_recorded — a claim is staked. The genuine "that one's mine" moment.
  // This is the ONE strike-eligible live event, and the ONLY place a coverage/
  // frontier stream earns a cut-in. Gold is NOT granted here yet — gold rides
  // the DISPOSITION at grade time (curateGradeFinding), not at first sighting.
  const findingId = clip(raw.identifier_hint, 16) || clip(raw.kind, 16) || "finding";
  return witnessEvent({
    kind: "pivot",
    phase: PHASE.CLAIM,
    register: "strike",
    weight: "lit",
    payload: {
      label: clip("a claim", MAX_LABEL_CHARS),
      caption: clip("That one is mine.", MAX_CAPTION_CHARS),
      key: findingId,
      probes: [],
    },
  });
}

// GRADE FINDING — the live disposition crystallizing. Takes one graded finding
// (the shape in grade.json's findings[], optionally with its final severity +
// reachability disposition) and projects the deterministic defender takeaway.
// This is the relens: the customer reads "fix now / worth fixing / watch /
// held", never SUBMIT/EV/triager. Gold (signal) is granted ONLY at "fix now".
function curateGradeFinding(raw) {
  if (!isPlainObject(raw)) return null;
  const findingId = clip(raw.finding_id, 16);
  if (!findingId) return null;
  const score = Number.isFinite(raw.total_score) ? raw.total_score : null;
  if (score == null) return null;

  // The disposition is the word the verdict already stamped (the single producer);
  // consume it verbatim. An unstamped finding (legacy/malformed grade.json) is
  // streamed conservatively as HELD — never re-derived here, so a sniffed fail-open
  // can never over-state a held finding as worth-fixing.
  const disposition = DEFENDER_DISPOSITION_VALUES.includes(raw.defender_disposition)
    ? raw.defender_disposition
    : HELD;
  const fixNow = disposition === FIX_NOW;

  // band is a DISPLAY weight input only (the lit/ember cue), never the disposition.
  // It is the actual graded SEVERITY — from the reachability stamp when it spoke,
  // else the finding's top-level graded_severity (grade-verdict-store carries it for
  // every finding whose reachability was silent, i.e. every web/SC target). The
  // 0-100 grade RUBRIC score is not a severity and is never read as one. A severe
  // live-target finding therefore lights even without a reachability stamp.
  const reach = isPlainObject(raw.reachability) ? raw.reachability : null;
  const gradedSeverity = reach
    ? clip(reach.graded_severity, 16)
    : clip(raw.graded_severity, 16);
  const band = ["critical", "high", "medium", "low"].includes(gradedSeverity)
    ? gradedSeverity
    : "";
  const severe = band === "high" || band === "critical";
  // Reachability is a display note only; unknown (no stamp) makes NO claim — the
  // customer is never told "reachable" on absence.
  const reachable = reach
    ? reach.network_reachable === true && reach.disposition !== "capped"
    : null;
  const reachMeta = reachable === true
    ? "reachable"
    : reachable === false ? "not reachable from the network" : "";

  return witnessEvent({
    kind: "verdict",
    phase: PHASE.GRADE,
    register: fixNow ? "strike" : "breath", // only fix_now cuts in.
    // Severity as WEIGHT: severe bands light up; the lone warn ember (high/
    // critical) is the renderer's to add from `weight:"lit"` + band, not a color
    // chosen here.
    weight: severe ? "lit" : "dim",
    // GOLD: granted ONLY at the fix_now / found terminus. Never on watch/held.
    signal: fixNow,
    payload: {
      label: findingId,
      // The CANONICAL word (snake_case) — identical to the sealed grade verdict,
      // so a consumer comparing the live word to the sealed word never diverges.
      verdict: disposition,
      // band is the renderer's weight/ember input — a word (severity), not a color.
      total: band,
      // No EV, no triager, no SUBMIT. The disposition IS the meta.
      meta: clip(reachMeta, MAX_CAPTION_CHARS),
      filing: "",
    },
  });
}

// ---------------------------------------------------------------------------
// curate(rawEvent) -> WitnessEvent | null
//
// The single entry point. Routes a raw record to its curator by the marker the
// source ledger stamps:
//   - frontier-events.jsonl rows carry plane:"frontier" + kind.
//   - pipeline-events.jsonl rows carry version + type (a PIPELINE_EVENT_TYPE).
//   - coverage.jsonl rows carry status + endpoint + bug_class (no plane/type).
//   - grade.json findings carry finding_id + total_score (the disposition src).
// An explicit { _source } hint overrides sniffing when the caller knows it.
//
// Returns null for anything non-dramatic, sensitive, or unrecognized. Any
// curator that throws (a sensitive-material leak) is caught and dropped —
// fail-closed: when in doubt, the visitor does not see it.
// ---------------------------------------------------------------------------
function curate(rawEvent) {
  if (!isPlainObject(rawEvent)) return null;
  try {
    const source = rawEvent._source;
    if (source === "frontier" || rawEvent.plane === "frontier") {
      return curateFrontierEvent(rawEvent);
    }
    if (source === "pipeline" || (rawEvent.type && PIPELINE_EVENT_TYPES.includes(rawEvent.type))) {
      return curatePipelineEvent(rawEvent);
    }
    if (source === "grade" || (rawEvent.finding_id != null && rawEvent.total_score != null)) {
      return curateGradeFinding(rawEvent);
    }
    if (source === "coverage" || (rawEvent.status != null && rawEvent.endpoint != null && rawEvent.bug_class != null)) {
      return curateCoverageRecord(rawEvent);
    }
    return null;
  } catch {
    // A sensitive-material throw (or any normalization error) means this record
    // cannot be safely witnessed. Drop it. Fail closed — for a PUBLIC surface,
    // silently withholding a record is always safe; emitting a possibly-tainted one
    // is not, so the drop is never traded for observability here. This module is
    // pure (no clock/fs/log), so it cannot instrument the drop itself: the runner is
    // responsible for counting null returns (curated vs dropped) so a rise in drops
    // — a curator bug OR a spike in sensitive records — is visible operationally.
    return null;
  }
}

module.exports = {
  curate,
  // The canonical defender vocabulary the witness word is drawn from — identical to
  // the value grade-verdict-store stamps, re-exported from the single producer.
  DEFENDER_DISPOSITION_VALUES,
  PHASE,
  WITNESSED_FRONTIER_KINDS,
  WITNESSED_PIPELINE_TYPES,
  // Internal curators exported for unit isolation; curate() is the entry point.
  curateFrontierEvent,
  curateCoverageRecord,
  curatePipelineEvent,
  curateGradeFinding,
};
