---
description: Run or resume a Hacker Bob bug bounty evaluate.
allowed-tools:
  - Task
  - Read
  - mcp__hacker-bob__bob_start_next_wave
  - mcp__hacker-bob__bob_start_wave
  - mcp__hacker-bob__bob_route_surfaces
  - mcp__hacker-bob__bob_read_surface_routes
  - mcp__hacker-bob__bob_import_http_traffic
  - mcp__hacker-bob__bob_public_intel
  - mcp__hacker-bob__bob_ingest_schema_doc
  - mcp__hacker-bob__bob_query_schema_contracts
  - mcp__hacker-bob__bob_run_doc_delta
  - mcp__hacker-bob__bob_read_doc_delta_results
  - mcp__hacker-bob__bob_run_auth_differential
  - mcp__hacker-bob__bob_read_auth_differential_results
  - mcp__hacker-bob__bob_record_candidate_claim
  - mcp__hacker-bob__bob_list_candidate_claims
  - mcp__hacker-bob__bob_read_chain_attempts
  - mcp__hacker-bob__bob_append_chain_node
  - mcp__hacker-bob__bob_query_chain_tree
  - mcp__hacker-bob__bob_chain_frontier
  - mcp__hacker-bob__bob_chain_ancestry
  - mcp__hacker-bob__bob_read_verification_round
  - mcp__hacker-bob__bob_read_verification_context
  - mcp__hacker-bob__bob_diff_verification_attempts
  - mcp__hacker-bob__bob_build_verification_adjudication
  - mcp__hacker-bob__bob_read_evidence_packs
  - mcp__hacker-bob__bob_write_proof_bundle
  - mcp__hacker-bob__bob_read_grade_verdict
  - mcp__hacker-bob__bob_init_session
  - mcp__hacker-bob__bob_init_repo_session
  - mcp__hacker-bob__bob_repo_inventory
  - mcp__hacker-bob__bob_repo_prepare_env
  - mcp__hacker-bob__bob_read_session_state
  - mcp__hacker-bob__bob_read_session_nucleus
  - mcp__hacker-bob__bob_advance_session
  - mcp__hacker-bob__bob_apply_wave_merge
  - mcp__hacker-bob__bob_write_handoff
  - mcp__hacker-bob__bob_wave_handoff_status
  - mcp__hacker-bob__bob_merge_wave_handoffs
  - mcp__hacker-bob__bob_read_wave_handoffs
  - mcp__hacker-bob__bob_wave_status
  - mcp__hacker-bob__bob_list_auth_profiles
  - mcp__hacker-bob__bob_read_state_summary
  - mcp__hacker-bob__bob_read_session_summary
  - mcp__hacker-bob__bob_set_operator_note
  - mcp__hacker-bob__bob_clear_operator_note
  - mcp__hacker-bob__bob_clear_terminal_block
  - mcp__hacker-bob__bounty_report_written
  - mcp__hacker-bob__bob_compose_report
  - mcp__hacker-bob__bob_amend_report
  - mcp__hacker-bob__bob_write_chain_rollup
  - mcp__hacker-bob__bob_set_friction_scanners
  - mcp__hacker-bob__bob_read_capability_playbook
  - mcp__hacker-bob__bob_get_context_budget
  - mcp__hacker-bob__bob_select_technique_packs
  - mcp__hacker-bob__bob_read_technique_pack
  - mcp__hacker-bob__bob_log_technique_attempt
  - mcp__hacker-bob__bob_read_tool_telemetry
  - mcp__hacker-bob__bob_read_pipeline_analytics
  - mcp__hacker-bob__bob_read_capability_metrics
  - mcp__hacker-bob__bob_evaluate_capabilities
  - mcp__hacker-bob__bob_ingest_audit_report
  - mcp__hacker-bob__bob_query_audit_reports
  - mcp__hacker-bob__bob_suggest_invariants
  - mcp__hacker-bob__bob_run_invariant_for_finding
  - mcp__hacker-bob__bob_read_invariant_runs
  - mcp__hacker-bob__bob_extract_routes
  - mcp__hacker-bob__bob_build_symbol_surface_index
  - mcp__hacker-bob__bob_summarize_diff_impact
  - mcp__hacker-bob__bob_record_surface_leads
  - mcp__hacker-bob__bob_read_surface_leads
  - mcp__hacker-bob__bob_promote_surface_leads
  - mcp__hacker-bob__bob_build_surface_graph
  - mcp__hacker-bob__bob_query_surface_graph
  - mcp__hacker-bob__bob_append_frontier_event
  - mcp__hacker-bob__bob_propose_hypothesis
  - mcp__hacker-bob__bob_propose_transition
  - mcp__hacker-bob__bob_materialize_task_graph
  - mcp__hacker-bob__bob_read_task_graph
  - mcp__hacker-bob__bob_attach_contract
  - mcp__hacker-bob__bob_prepare_node
  - mcp__hacker-bob__bob_finalize_node
  - mcp__hacker-bob__bob_schedule_graph_nodes
  - mcp__hacker-bob__bob_materialize_frontier
  - mcp__hacker-bob__bob_read_queue_policy
  - mcp__hacker-bob__bob_set_queue_policy
  - mcp__hacker-bob__bob_schedule_tasks
  - mcp__hacker-bob__bob_set_pack_telemetry_config
  - mcp__hacker-bob__bob_log_capability_friction
  - mcp__hacker-bob__bob_log_protocol_drift
  - mcp__hacker-bob__bob_emit_runtime_drift
  - mcp__hacker-bob__bob_propose_friction_promotion
  - mcp__hacker-bob__bob_scan_transcript_for_friction
  - mcp__hacker-bob__bob_http_scan
  - mcp__hacker-bob__bob_temp_email
  - mcp__hacker-bob__bob_signup_detect
  - mcp__hacker-bob__bob_auth_store
  - mcp__hacker-bob__bob_auto_signup
argument-hint: "[target-url | resume <domain> [force-merge]] [--no-auth] [--normal|--paranoid|--yolo] [--deep] [--egress <profile>] [--block-internal-hosts|--allow-internal-hosts]"
---
Run or resume a Hacker Bob bug bounty evaluate.

You ARE the Hacker Bob orchestrator for this run. Load the runner playbook and
execute it verbatim. Do NOT invoke it through the Skill tool — the
`bob-evaluate-runner` skill is `disable-model-invocation: true` and cannot be
called that way.

1. Read the playbook at the project-relative path
   `.claude/skills/bob-evaluate-runner/SKILL.md`
   (under `${CLAUDE_PROJECT_DIR:-$PWD}`).
2. Act as that skill's orchestrator, treating the text below as its exact input:

```text
$ARGUMENTS
```

Follow the runner skill's guardrails exactly: the lifecycle FSM
(SETUP -> OPEN_FRONTIER -> CLAIM_FREEZE -> VERIFY -> GRADE -> REPORT), role
separation (you schedule and read; per-surface evaluators own
`bob_repo_docker_run` and the smart-contract family runners — never call them
yourself), the scope / SSRF / PII rules, and the re-entry reconciliation
contract. The playbook is authoritative; do not improvise around it.
