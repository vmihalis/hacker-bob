# CB-2 -- Object Authorization Template

## Node

- `id`: `CB-2`
- `action`: `merge`
- `anchor`: `mcp/core/mechanism/invariant-template-corpus.js`;
  `mcp/domains/repo/oss-rootcause-family-corpus.js`; `mcp/core/scoring/cwe-catalog.js`
- `status`: `done`

## Contract

`object_authorization` is a closed, catalog-backed mechanism template inside the
existing invariant and OSS root-cause corpora. It does not create a parallel
registry, a new mechanism-class authority, or an LLM-promoted class path.

## Implementation

- `mcp/core/mechanism/invariant-template-corpus.js` adds
  `OBJECT_AUTHORIZATION_MECHANISM_TEMPLATE` with required entities,
  interventions, positive controls, negative controls, confounders, and a
  differential-effect evidence predicate.
- The mechanism template is bound to `CWE-639` through `assertValidCwe`, so it
  resolves through the existing CWE catalog instead of an invented identifier.
- `loadMechanismTemplates` and `normalizeMechanismTemplate` provide a
  bounded-warning loader: malformed records are skipped and reported, not
  thrown.
- `mcp/domains/repo/oss-rootcause-family-corpus.js` adds a matching
  `object_authorization` family with a principal/object/policy/effect
  source-sink signature.
- Stigmergy pair: producer `object_authorization_mechanism_template` consumed by
  `mechanism_template_loader_object_authorization`.

## Findings

- Resolved during review: `object_authorization` initially shared all three
  native-code OSS lens affinities and displaced `validate_vs_consume` from the
  capped root-cause brief slice. Narrowed the new family to `behavior_probe` so
  the corpus record does not compete with native-code families.

## Review Evidence

Engineering review passed:

- `node --test test/invariant-template-corpus.test.js test/oss-rootcause-family-index.test.js test/cwe-catalog.test.js`
- `npm run check:syntax`
- `npm run check:stigmergy-coherence`
- `npm run test:mcp`
- `npm run test:prompts`
- `verify-CB-2-object-authorization-template: PASS`

No field review is required for this node.
