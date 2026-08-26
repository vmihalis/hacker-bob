"use strict";

// Plane T Cycle T.2 — CLI tool pack registry + selection / rendering primitives.
//
// A "pack" binds a CLI tool (ffuf, arjun, jwt_tool, ...) to:
//   - install_check : shell snippet that probes installation. Used by the
//     presence cache; never evaluated here.
//   - invocation_template : one-line example invocation. Placeholders use
//     "<name>" syntax; the renderer fills them from surface/observation
//     context, and leaves unfilled placeholders as-is.
//   - applicable_when : pure predicate of
//       ({ surface, lens, observations, install_status }) -> boolean.
//     Invariant T-R8: predicates MUST be pure functions of inputs. No
//     Date.now(), no random, no env reads, no I/O. Determinism is what lets
//     the brief renderer cache a projection across a wave.
//   - narrative : <= 120 char human-readable line shown in the brief.
//   - lens_affinity? : optional array of task_lens identifiers a pack is
//     foregrounded for (T.4 uses this; T.2 stores but does not branch on it).
//   - min_version? : optional semver-ish floor; presence cache may surface
//     install_status.version which downstream code can compare against.
//
// Plane T pact:
//   T-P2 "conditional, not totaled" — selection projects to a small subset.
//   T-P3 "install-graceful" — packs whose tool is not installed remain in
//        the registry; the brief renderer is responsible for hiding them
//        (renderAvailableCliToolsSection in assignment-brief.js).
//   T-R8 "pure predicates" — see invariant above.

const KEBAB_CASE_RE = /^[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*$/;
const NARRATIVE_MAX_CHARS = 120;

function isPureFunction(value) {
  return typeof value === "function";
}

function normalizeCliToolPack(pack) {
  if (!pack || typeof pack !== "object" || Array.isArray(pack)) {
    throw new Error("cli-tool pack must be a plain object");
  }
  const id = pack.id;
  if (typeof id !== "string" || !KEBAB_CASE_RE.test(id)) {
    throw new Error(`cli-tool pack id must be kebab-case (got ${JSON.stringify(id)})`);
  }
  if (typeof pack.install_check !== "string" || !pack.install_check.trim()) {
    throw new Error(`cli-tool pack ${id}: install_check must be a non-empty string`);
  }
  if (typeof pack.invocation_template !== "string" || !pack.invocation_template.trim()) {
    throw new Error(`cli-tool pack ${id}: invocation_template must be a non-empty string`);
  }
  if (!isPureFunction(pack.applicable_when)) {
    throw new Error(`cli-tool pack ${id}: applicable_when must be a function`);
  }
  if (typeof pack.narrative !== "string" || !pack.narrative.trim()) {
    throw new Error(`cli-tool pack ${id}: narrative must be a non-empty string`);
  }
  if (pack.narrative.length > NARRATIVE_MAX_CHARS) {
    throw new Error(`cli-tool pack ${id}: narrative exceeds ${NARRATIVE_MAX_CHARS} chars (got ${pack.narrative.length})`);
  }
  if (pack.min_version != null && typeof pack.min_version !== "string") {
    throw new Error(`cli-tool pack ${id}: min_version must be a string when set`);
  }
  if (pack.lens_affinity != null) {
    if (!Array.isArray(pack.lens_affinity)
        || pack.lens_affinity.some((entry) => typeof entry !== "string" || !entry.trim())) {
      throw new Error(`cli-tool pack ${id}: lens_affinity must be a string[] when set`);
    }
  }
  return Object.freeze({
    id,
    install_check: pack.install_check,
    invocation_template: pack.invocation_template,
    applicable_when: pack.applicable_when,
    narrative: pack.narrative,
    ...(pack.min_version ? { min_version: pack.min_version } : {}),
    ...(pack.lens_affinity ? { lens_affinity: Object.freeze(pack.lens_affinity.slice()) } : {}),
  });
}

// Seed packs. Order is the registry order; selection re-sorts.
const SEED_PACKS = [
  {
    id: "ffuf",
    install_check: "ffuf -V",
    invocation_template:
      "ffuf -w <wordlist:seclists/api-endpoints> -u https://<host>/FUZZ -t 10 -mc 200,302,401,403",
    applicable_when: ({ surface, observations }) => {
      if (!surface || surface.kind !== "web") return false;
      const routesCount = (observations && observations.routes_count) || 0;
      return routesCount < 20;
    },
    narrative: "Content discovery — fuzz hidden endpoints when known routes < 20.",
  },
  {
    id: "arjun",
    install_check: "arjun --version",
    invocation_template: "arjun -u https://<host>/<endpoint> -m GET --stable",
    applicable_when: ({ surface, observations }) => {
      if (!surface || surface.kind !== "web") return false;
      const endpoints = observations && observations.observed_endpoints;
      return Array.isArray(endpoints) && endpoints.length >= 1;
    },
    narrative: "Parameter discovery — find hidden params on known endpoints.",
  },
  {
    id: "jwt-tool",
    install_check: "which jwt_tool",
    invocation_template: "jwt_tool -t <token> -M at",
    applicable_when: ({ observations }) => {
      const list = observationList(observations);
      return list.some((o) => o && o.kind === "jwt_observed");
    },
    narrative: "JWT seen — test alg confusion, kid SQLi, key stuffing, signature stripping.",
  },
  {
    id: "sqlmap",
    install_check: "sqlmap --version",
    invocation_template:
      "sqlmap -u \"https://<host>/<endpoint>?<param>=1\" --batch --level 3 --risk 2 --random-agent",
    applicable_when: ({ observations }) => {
      const list = observationList(observations);
      return list.some((o) => o && o.kind === "sql_injection_signal");
    },
    narrative: "SQLi confirmation — run only when manual probe already returned a signal.",
  },
  {
    id: "dalfox",
    install_check: "dalfox version",
    invocation_template: "dalfox url \"https://<host>/<endpoint>?<param>=test\" --skip-bav",
    applicable_when: ({ surface, observations }) => {
      if (!surface || surface.kind !== "web") return false;
      const list = observationList(observations);
      return list.some((o) => o && o.kind === "reflected_param");
    },
    narrative: "Reflected XSS — verify reflection-to-execution conversion.",
  },
  {
    id: "swaks",
    install_check: "swaks --version",
    invocation_template: "swaks --to <recipient> --from <spoofed-sender> --server <host>",
    applicable_when: ({ surface, observations }) => {
      if (surface && surface.kind === "mail") return true;
      const list = observationList(observations);
      return list.some((o) => o && o.kind === "dmarc_policy_observed");
    },
    narrative: "Mail spoofing — actually deliver a forged-sender mail to confirm DMARC enforcement.",
  },
  {
    id: "mailspoof",
    install_check: "which mailspoof",
    invocation_template: "mailspoof check <target_domain>",
    applicable_when: ({ surface, observations }) => {
      if (surface && surface.kind === "mail") return true;
      const list = observationList(observations);
      return list.some((o) => o && o.kind === "dmarc_policy_observed");
    },
    narrative: "Mail-policy audit — SPF, DKIM, DMARC posture summary.",
  },
  {
    id: "gowitness",
    install_check: "gowitness version",
    invocation_template: "gowitness single -u \"https://<host>\" --destination <session_dir>/screenshots/",
    applicable_when: ({ surface }) => Boolean(surface && surface.kind === "web"),
    narrative: "Visual reconnaissance — screenshot surface for triage.",
  },
  // ── Plane T Cycle T.6 — OpenAPI / GraphQL schema-observation packs ──────
  {
    id: "schemathesis",
    install_check: "schemathesis --version",
    invocation_template: "schemathesis run https://<host>/openapi.json --checks all",
    applicable_when: ({ observations }) => {
      const list = observationList(observations);
      return list.some((o) => o && o.kind === "openapi_schema_observed");
    },
    narrative: "OpenAPI fuzz — property-based testing against the spec.",
  },
  {
    id: "graphql-cop",
    install_check: "graphql-cop --help",
    invocation_template: "graphql-cop -t https://<host>/graphql",
    applicable_when: ({ observations }) => {
      const list = observationList(observations);
      return list.some((o) => o && o.kind === "graphql_schema_observed");
    },
    narrative: "GraphQL security audit — introspection, batching, depth, field suggestions.",
  },
  {
    id: "clairvoyance",
    install_check: "clairvoyance --help",
    invocation_template: "clairvoyance -i <wordlist> -o schema.json https://<host>/graphql",
    applicable_when: ({ observations }) => {
      const list = observationList(observations);
      return list.some((o) => (
        o
        && o.kind === "graphql_schema_observed"
        && o.payload
        && o.payload.has_introspection_disabled === true
      ));
    },
    narrative: "GraphQL schema reconstruction when introspection is locked.",
  },
  {
    id: "graphqlcat",
    install_check: "graphqlcat --help",
    invocation_template: "graphqlcat -t https://<host>/graphql -i schema.json",
    applicable_when: ({ observations }) => {
      const list = observationList(observations);
      return list.some((o) => o && o.kind === "graphql_schema_observed");
    },
    narrative: "GraphQL recon — type/field enumeration, mutation discovery.",
  },
  // ── Plane O Cycle O.6 / I10 — OSS surfacing CLI tool packs ───────────────
  // Initial seeds: semgrep, trivy, cargo-audit, npm-audit, pip-audit.
  // I10 adds the repo-gated CodeQL/Coccinelle source-analysis seeds.
  // Deferred: bandit, gosec, syft, grype, radare2/binwalk/ghidra — added
  // when operator demand justifies.
  //
  // `semgrep` and `trivy` apply to every OSS surface (surface.kind === "repo"
  // OR any observation present); the per-ecosystem audit tools fire on
  // matching dependency_observed events.
  {
    id: "semgrep",
    install_check: "semgrep --version",
    invocation_template: "semgrep --sarif --config auto /src",
    applicable_when: ({ surface }) => Boolean(surface && surface.kind === "repo"),
    narrative: "Static analysis — auto-config rulepack scan over /src for bug-class hints.",
  },
  {
    id: "trivy",
    install_check: "trivy --version",
    invocation_template: "trivy fs --format sarif --output /work/trivy.sarif --scanners vuln,secret,misconfig /src",
    applicable_when: ({ surface }) => Boolean(surface && surface.kind === "repo"),
    narrative: "Repo scanner — vulnerabilities, leaked secrets, misconfigurations in /src.",
  },
  {
    id: "codeql",
    install_check: "codeql version",
    invocation_template:
      "codeql database create /work/codeql-db --source-root=/src --language=<language> --command=<build-command> && codeql database analyze /work/codeql-db <query-suite> --format=sarif-latest --output=/work/codeql.sarif",
    applicable_when: ({ surface }) => Boolean(surface && surface.kind === "repo"),
    narrative: "CodeQL source analysis — emit SARIF from a local /src database when a build exists.",
  },
  {
    id: "coccinelle",
    install_check: "spatch --version",
    invocation_template: "spatch --sp-file <semantic-patch> --dir /src --very-quiet --timeout 60",
    applicable_when: ({ surface }) => Boolean(surface && surface.kind === "repo"),
    narrative: "Coccinelle semantic patching — structural C/C++ source idiom checks over /src.",
  },
  {
    id: "cargo-audit",
    install_check: "cargo audit --version",
    invocation_template: "cargo audit",
    applicable_when: ({ observations }) => {
      const list = observationList(observations);
      return list.some((o) => {
        if (!o) return false;
        const payload = o.payload && typeof o.payload === "object" ? o.payload : o;
        return o.kind === "dependency_observed" && payload && payload.ecosystem === "cargo";
      });
    },
    narrative: "Rust dep audit — runs against Cargo.lock for known CVE advisories.",
  },
  {
    id: "npm-audit",
    install_check: "npm --version",
    invocation_template: "npm audit --json",
    applicable_when: ({ observations }) => {
      const list = observationList(observations);
      return list.some((o) => {
        if (!o) return false;
        const payload = o.payload && typeof o.payload === "object" ? o.payload : o;
        return o.kind === "dependency_observed" && payload && payload.ecosystem === "npm";
      });
    },
    narrative: "Node dep audit — surfaces known CVE advisories from npm package metadata.",
  },
  {
    id: "pip-audit",
    install_check: "pip-audit --version",
    invocation_template: "pip-audit",
    applicable_when: ({ observations }) => {
      const list = observationList(observations);
      return list.some((o) => {
        if (!o) return false;
        const payload = o.payload && typeof o.payload === "object" ? o.payload : o;
        return o.kind === "dependency_observed" && payload && payload.ecosystem === "pypi";
      });
    },
    narrative: "Python dep audit — checks installed pypi dists against advisory database.",
  },
];

const CLI_TOOL_PACKS = Object.freeze(SEED_PACKS.map(normalizeCliToolPack));

// observations may be passed as:
//   - an array of observation objects ({ kind, ... })
//   - a "summary" object ({ routes_count, observed_endpoints, items: [...] })
// We expose a list view for predicates that need to ask `.some(...)`.
function observationList(observations) {
  if (Array.isArray(observations)) return observations;
  if (observations && Array.isArray(observations.items)) return observations.items;
  return [];
}

// Pure selection. install_status is a map { [pack_id]: { installed, version? } }.
// The predicate is the source of truth for applicability. install_status is
// passed through so downstream rendering can rank installed packs higher.
//
// Plane T Cycle T.8 — optional `pack_telemetry` argument carries adaptive
// curation signals. When a pack id appears in `pack_telemetry` with
// `demoted: true`, the returned pack is wrapped with a `demoted: true` flag
// so the brief renderer can apply the score penalty (T-D5: operator-gated
// opt-in; T-R8: deterministic for fixed telemetry). The pack frozen object
// itself is left untouched — we surface the annotation on a sibling
// `demoted` property of the returned reference so the registry contract
// (frozen packs only) holds.
function selectCliToolPacks({
  surface_fingerprint,
  task_lens,
  observations,
  install_status,
  pack_telemetry,
} = {}) {
  const surface = surface_fingerprint || null;
  const observationsArg = observations == null ? [] : observations;
  const installStatusMap = install_status && typeof install_status === "object" && !Array.isArray(install_status)
    ? install_status
    : {};
  const telemetryMap = pack_telemetry && typeof pack_telemetry.get === "function"
    ? pack_telemetry
    : null;
  const selected = [];
  for (const pack of CLI_TOOL_PACKS) {
    let applicable = false;
    try {
      applicable = Boolean(pack.applicable_when({
        surface,
        lens: task_lens || null,
        observations: observationsArg,
        install_status: installStatusMap,
      }));
    } catch {
      applicable = false;
    }
    if (!applicable) continue;
    const telemetry = telemetryMap ? telemetryMap.get(pack.id) : null;
    if (telemetry && telemetry.demoted === true) {
      selected.push(Object.freeze({ ...pack, demoted: true }));
      continue;
    }
    selected.push(pack);
  }
  return selected;
}

// Render a single pack into a one-line markdown snippet. Placeholders are
// "<name>" pairs; fillable from {host, endpoint, param, token, recipient,
// spoofed_sender, target_domain, session_dir, wordlist}. Unfilled placeholders
// are returned verbatim so the operator sees the slot to fill.
function renderCliToolPackSnippet(pack, context) {
  if (!pack || typeof pack !== "object") {
    throw new Error("renderCliToolPackSnippet requires a pack object");
  }
  const ctx = context && typeof context === "object" ? context : {};
  const filled = fillInvocationPlaceholders(pack.invocation_template, ctx);
  return `- **${pack.id}** — ${pack.narrative}\n  \`${filled}\``;
}

function fillInvocationPlaceholders(template, context) {
  // Replace <key> or <key:default> with ctx[key] when available. Otherwise
  // leave the placeholder verbatim (operators must see the slot to fill).
  return template.replace(/<([a-zA-Z0-9_:\/-]+)>/g, (match, slot) => {
    const colonIdx = slot.indexOf(":");
    const key = colonIdx >= 0 ? slot.slice(0, colonIdx) : slot;
    const value = context[key];
    if (value == null || value === "") return match;
    return sanitizeInvocationPlaceholderValue(value);
  });
}

function sanitizeInvocationPlaceholderValue(value) {
  return String(value)
    .replace(/[\u0000-\u001f\u007f]+/g, "_")
    .replace(/[\s`"'$;|&()\\<>!{}\[\]*?#]+/g, "_")
    .replace(/_{2,}/g, "_")
    .replace(/^_+|_+$/g, "")
    .trim();
}

module.exports = {
  CLI_TOOL_PACKS,
  NARRATIVE_MAX_CHARS,
  fillInvocationPlaceholders,
  normalizeCliToolPack,
  observationList,
  renderCliToolPackSnippet,
  selectCliToolPacks,
};
