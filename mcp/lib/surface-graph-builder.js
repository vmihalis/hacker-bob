"use strict";

const fs = require("fs");
const {
  attackSurfacePath,
  authDifferentialResultsPath,
  chainTreeJsonlPath,
  evmRoleTableResultsPath,
} = require("./paths.js");
const { readJsonFile } = require("./storage.js");
const { appendEdges } = require("./surface-graph.js");
const { querySchemaContracts } = require("./schema-contracts-store.js");
const { hashCanonicalJson } = require("./verification-contracts.js");

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function safeReadAttackSurface(domain) {
  const filePath = attackSurfacePath(domain);
  if (!fs.existsSync(filePath)) return null;
  try {
    const parsed = readJsonFile(filePath, { label: "attack_surface.json" });
    if (!isPlainObject(parsed) || !Array.isArray(parsed.surfaces)) return null;
    return parsed;
  } catch (_err) {
    return null;
  }
}

function pushEdge(edges, edge) {
  edges.push(edge);
}

function edgesFromAttackSurface(parsedSurface) {
  if (parsedSurface == null) return [];
  const edges = [];
  for (const surface of parsedSurface.surfaces) {
    if (!isPlainObject(surface)) continue;
    const surfaceId = typeof surface.id === "string" ? surface.id : null;
    if (!surfaceId) continue;
    const hosts = Array.isArray(surface.hosts)
      ? surface.hosts.filter((h) => typeof h === "string" && h.length > 0)
      : [];
    const endpoints = Array.isArray(surface.endpoints)
      ? surface.endpoints.filter((e) => typeof e === "string" && e.length > 0)
      : [];
    const techStack = Array.isArray(surface.tech_stack)
      ? surface.tech_stack.filter((t) => typeof t === "string" && t.length > 0)
      : [];
    const jsHints = Array.isArray(surface.js_hints)
      ? surface.js_hints.filter((j) => typeof j === "string" && j.length > 0)
      : [];
    const leakedSecrets = Array.isArray(surface.leaked_secrets)
      ? surface.leaked_secrets.filter((s) => typeof s === "string" && s.length > 0)
      : [];
    for (const endpoint of endpoints) {
      pushEdge(edges, {
        source: { type: "surface", id: surfaceId },
        target: { type: "endpoint", id: endpoint },
        edge_type: "contains",
        source_artifact: "attack_surface.json",
        confidence: 1,
      });
      for (const host of hosts) {
        pushEdge(edges, {
          source: { type: "subdomain", id: host },
          target: { type: "endpoint", id: endpoint },
          edge_type: "hosts",
          source_artifact: "attack_surface.json",
          confidence: 0.9,
        });
      }
    }
    for (const host of hosts) {
      pushEdge(edges, {
        source: { type: "surface", id: surfaceId },
        target: { type: "subdomain", id: host },
        edge_type: "contains",
        source_artifact: "attack_surface.json",
        confidence: 1,
      });
    }
    for (const tech of techStack) {
      pushEdge(edges, {
        source: { type: "surface", id: surfaceId },
        target: { type: "tech", id: tech.toLowerCase() },
        edge_type: "references",
        source_artifact: "attack_surface.json",
        confidence: 0.8,
      });
    }
    for (const jsHint of jsHints) {
      pushEdge(edges, {
        source: { type: "surface", id: surfaceId },
        target: { type: "js_file", id: jsHint },
        edge_type: "references",
        source_artifact: "attack_surface.json",
        confidence: 0.7,
      });
    }
    for (const secret of leakedSecrets) {
      const markerId = `secret-${hashCanonicalJson({ secret }).slice(0, 16)}`;
      pushEdge(edges, {
        source: { type: "surface", id: surfaceId },
        target: { type: "secret_marker", id: markerId },
        edge_type: "leaks",
        source_artifact: "attack_surface.json",
        confidence: 0.6,
      });
    }
  }
  return edges;
}

function edgesFromSchemaCorpus(domain) {
  let queryResult;
  try {
    queryResult = querySchemaContracts({ target_domain: domain });
  } catch (_err) {
    return [];
  }
  if (!queryResult || !Array.isArray(queryResult.contracts)) return [];
  const edges = [];
  for (const contract of queryResult.contracts) {
    if (!isPlainObject(contract)) continue;
    const endpoint = typeof contract.endpoint === "string" ? contract.endpoint : null;
    if (!endpoint) continue;
    const sourceDocHash = typeof contract.source_doc_hash === "string"
      ? contract.source_doc_hash
      : null;
    const sourceUri = typeof contract.source_uri === "string" ? contract.source_uri : null;
    const specId = sourceUri || (sourceDocHash ? `spec-${sourceDocHash.slice(0, 16)}` : null);
    if (specId) {
      pushEdge(edges, {
        source: { type: "openapi_spec", id: specId },
        target: { type: "endpoint", id: endpoint },
        edge_type: "documents",
        source_artifact: "schema-contracts.jsonl",
        confidence: 1,
      });
    }
    const claimedAuth = isPlainObject(contract.claimed_auth) ? contract.claimed_auth : null;
    if (claimedAuth && Array.isArray(claimedAuth.schemes)) {
      for (const scheme of claimedAuth.schemes) {
        if (typeof scheme !== "string" || scheme.length === 0) continue;
        const gateId = `policy_gate:schema:${endpoint}:${scheme}`;
        const credentialId = `credential:${scheme}`;
        pushEdge(edges, {
          source: { type: "endpoint", id: endpoint },
          target: { type: "auth_scheme", id: scheme },
          edge_type: "claims_auth",
          source_artifact: "schema-contracts.jsonl",
          confidence: 1,
        });
        pushEdge(edges, {
          source: { type: "endpoint", id: endpoint },
          target: { type: "policy_gate", id: gateId },
          edge_type: "claims_auth",
          source_artifact: "schema-contracts.jsonl",
          confidence: 1,
        });
        pushEdge(edges, {
          source: { type: "policy_gate", id: gateId },
          target: { type: "credential", id: credentialId },
          edge_type: "requires",
          source_artifact: "schema-contracts.jsonl",
          confidence: 1,
        });
      }
    }
  }
  return edges;
}

function safeReadJson(filePath, label) {
  if (!fs.existsSync(filePath)) return null;
  try {
    const parsed = readJsonFile(filePath, { label });
    return isPlainObject(parsed) ? parsed : null;
  } catch (_err) {
    return null;
  }
}

function responseClassEffectId(endpoint, profile, signature) {
  const responseClass = signature && typeof signature.response_class === "string"
    ? signature.response_class
    : "unknown";
  return `effect:${endpoint}:${profile}:${responseClass}`;
}

function edgesFromAuthDifferentialResults(domain) {
  const parsed = safeReadJson(authDifferentialResultsPath(domain), "auth-differential-results.json");
  if (!parsed || !Array.isArray(parsed.per_endpoint)) return [];
  const edges = [];
  for (const entry of parsed.per_endpoint) {
    if (!isPlainObject(entry) || typeof entry.endpoint !== "string") continue;
    const endpoint = entry.endpoint;
    const signatures = isPlainObject(entry.signatures_by_profile) ? entry.signatures_by_profile : {};
    const profiles = Object.keys(signatures).sort();
    for (const profile of profiles) {
      const signature = signatures[profile];
      if (!isPlainObject(signature)) continue;
      const principalId = `principal:${profile}`;
      const credentialId = signature.sent_with_auth === true
        ? `credential:${profile}:auth`
        : `credential:${profile}:unauth`;
      const interventionId = `intervention:auth-diff:${endpoint}:${profile}`;
      const effectId = responseClassEffectId(endpoint, profile, signature);
      pushEdge(edges, {
        source: { type: "principal", id: principalId },
        target: { type: "credential", id: credentialId },
        edge_type: "uses_credential",
        source_artifact: "auth-differential-results.json",
        confidence: 1,
      });
      pushEdge(edges, {
        source: { type: "credential", id: credentialId },
        target: { type: "intervention", id: interventionId },
        edge_type: "tests_gate",
        source_artifact: "auth-differential-results.json",
        confidence: 1,
      });
      pushEdge(edges, {
        source: { type: "intervention", id: interventionId },
        target: { type: "effect", id: effectId },
        edge_type: "produces_effect",
        source_artifact: "auth-differential-results.json",
        confidence: 1,
      });
    }
    const divergences = Array.isArray(entry.divergences) ? entry.divergences : [];
    for (const divergence of divergences) {
      if (!isPlainObject(divergence) || divergence.type !== "unauth_succeeds_where_auth_blocked") continue;
      const gateId = `policy_gate:auth-diff:${endpoint}`;
      const effectId = `effect:${endpoint}:unauth_succeeds_where_auth_blocked`;
      pushEdge(edges, {
        source: { type: "endpoint", id: endpoint },
        target: { type: "policy_gate", id: gateId },
        edge_type: "claims_auth",
        source_artifact: "auth-differential-results.json",
        confidence: 1,
      });
      pushEdge(edges, {
        source: { type: "policy_gate", id: gateId },
        target: { type: "effect", id: effectId },
        edge_type: "permits_effect",
        source_artifact: "auth-differential-results.json",
        confidence: 1,
      });
      pushEdge(edges, {
        source: { type: "principal", id: "principal:unauthenticated" },
        target: { type: "policy_gate", id: gateId },
        edge_type: "tests_gate",
        source_artifact: "auth-differential-results.json",
        confidence: 1,
      });
    }
  }
  return edges;
}

function readJsonl(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const raw = fs.readFileSync(filePath, "utf8");
  return raw.split(/\r?\n/)
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line));
}

function edgesFromChainTree(domain) {
  let nodes;
  try {
    nodes = readJsonl(chainTreeJsonlPath(domain));
  } catch (_err) {
    return [];
  }
  const edges = [];
  for (const node of nodes) {
    if (!isPlainObject(node) || !isPlainObject(node.action)) continue;
    const actionKind = typeof node.action.kind === "string" ? node.action.kind : null;
    if (!actionKind) continue;
    const interventionId = `intervention:chain:${node.node_hash}`;
    pushEdge(edges, {
      source: { type: "intervention", id: interventionId },
      target: { type: "effect", id: `effect:chain:${node.verdict || "pending"}` },
      edge_type: "observes_effect",
      source_artifact: "chain-tree.jsonl",
      confidence: 1,
    });
  }
  return edges;
}

function edgesFromEvmRoleTableResult(result) {
  if (!isPlainObject(result) || typeof result.contract !== "string") return [];
  const contract = result.contract.toLowerCase();
  const edges = [];
  const accessControl = Array.isArray(result.access_control) ? result.access_control : [];
  for (const row of accessControl) {
    if (!isPlainObject(row) || typeof row.role_hash !== "string") continue;
    const gateId = `policy_gate:evm:${contract}:${row.role_hash.toLowerCase()}`;
    const credentialId = `credential:evm-role:${row.role_hash.toLowerCase()}`;
    pushEdge(edges, {
      source: { type: "policy_gate", id: gateId },
      target: { type: "credential", id: credentialId },
      edge_type: "requires",
      source_artifact: "evm-role-table-results.json",
      confidence: 1,
    });
    const accounts = Array.isArray(row.accounts) ? row.accounts : [];
    for (const accountRow of accounts) {
      if (!isPlainObject(accountRow) || accountRow.has_role !== true || typeof accountRow.account !== "string") continue;
      pushEdge(edges, {
        source: { type: "principal", id: `principal:evm:${accountRow.account.toLowerCase()}` },
        target: { type: "credential", id: credentialId },
        edge_type: "uses_credential",
        source_artifact: "evm-role-table-results.json",
        confidence: 1,
      });
    }
  }
  const wards = Array.isArray(result.wards) ? result.wards : [];
  if (wards.length > 0) {
    const gateId = `policy_gate:evm:${contract}:wards`;
    const credentialId = `credential:evm-ward:${contract}`;
    pushEdge(edges, {
      source: { type: "policy_gate", id: gateId },
      target: { type: "credential", id: credentialId },
      edge_type: "requires",
      source_artifact: "evm-role-table-results.json",
      confidence: 1,
    });
    for (const wardRow of wards) {
      if (!isPlainObject(wardRow) || wardRow.ward !== true || typeof wardRow.account !== "string") continue;
      pushEdge(edges, {
        source: { type: "principal", id: `principal:evm:${wardRow.account.toLowerCase()}` },
        target: { type: "credential", id: credentialId },
        edge_type: "uses_credential",
        source_artifact: "evm-role-table-results.json",
        confidence: 1,
      });
    }
  }
  return edges;
}

function edgesFromEvmRoleTableResults(domain) {
  const parsed = safeReadJson(evmRoleTableResultsPath(domain), "evm-role-table-results.json");
  if (!parsed) return [];
  if (Array.isArray(parsed.results)) {
    return parsed.results.flatMap(edgesFromEvmRoleTableResult);
  }
  return edgesFromEvmRoleTableResult(parsed);
}

function buildSurfaceGraph({ target_domain, sources }) {
  const enabledSources = Array.isArray(sources) && sources.length > 0
    ? new Set(sources)
    : new Set(["attack_surface", "schema_corpus", "auth_differential", "evm_role_table", "chain_tree"]);
  const allEdges = [];
  const sourcesUsed = [];
  if (enabledSources.has("attack_surface")) {
    const parsed = safeReadAttackSurface(target_domain);
    if (parsed) {
      const edges = edgesFromAttackSurface(parsed);
      allEdges.push(...edges);
      sourcesUsed.push({ source: "attack_surface", edge_count: edges.length });
    } else {
      sourcesUsed.push({ source: "attack_surface", edge_count: 0, missing: true });
    }
  }
  if (enabledSources.has("schema_corpus")) {
    const edges = edgesFromSchemaCorpus(target_domain);
    allEdges.push(...edges);
    sourcesUsed.push({ source: "schema_corpus", edge_count: edges.length });
  }
  if (enabledSources.has("auth_differential")) {
    const edges = edgesFromAuthDifferentialResults(target_domain);
    allEdges.push(...edges);
    sourcesUsed.push({ source: "auth_differential", edge_count: edges.length });
  }
  if (enabledSources.has("evm_role_table")) {
    const edges = edgesFromEvmRoleTableResults(target_domain);
    allEdges.push(...edges);
    sourcesUsed.push({ source: "evm_role_table", edge_count: edges.length });
  }
  if (enabledSources.has("chain_tree")) {
    const edges = edgesFromChainTree(target_domain);
    allEdges.push(...edges);
    sourcesUsed.push({ source: "chain_tree", edge_count: edges.length });
  }
  const result = appendEdges({ target_domain, edges: allEdges });
  return {
    target_domain: result.target_domain,
    sources_used: sourcesUsed,
    new_count: result.new_count,
    replaced_count: result.replaced_count,
    total_in_graph: result.total_in_graph,
  };
}

module.exports = {
  buildSurfaceGraph,
  edgesFromAttackSurface,
  edgesFromAuthDifferentialResults,
  edgesFromChainTree,
  edgesFromEvmRoleTableResult,
  edgesFromEvmRoleTableResults,
  edgesFromSchemaCorpus,
};
