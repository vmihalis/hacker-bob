**Doc-vs-Behavior Differential.** Ingest OpenAPI 3 / GraphQL SDL / Postman v2.1 with `bob_ingest_schema_doc` (content-hashed, idempotent), confirm coverage with `bob_query_schema_contracts`, run per auth profile via `bob_run_doc_delta({ target_domain, base_url, auth_profile, run_id, egress_profile, block_internal_hosts })`, read with `bob_read_doc_delta_results({ target_domain, summary_only: true })`. Divergence classes: `security`, `info_leak_potential`, `doc_or_infra`.

Web evaluators also see the schema corpus through `schema_slice` in their brief once it's seeded.
