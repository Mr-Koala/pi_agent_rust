# Swarm Activity Ledger

The swarm activity ledger is a redacted JSONL stream for reconstructing what happened during a multi-agent run without storing prompt bodies or secrets.

Each row uses schema `pi.swarm.activity_ledger.v1` and carries:

- `sequence`: monotonic producer-local order.
- `timestamp_ms`: Unix milliseconds for timeline reconstruction.
- `kind`: one of `bead_status`, `agent_mail`, `file_reservation`, `rch_job`, `verification`, `git_commit`, `recovery`, or `note`.
- `ids.correlation_id`: required stable ID used to join related Beads, Agent Mail, RCH, verification, and Git events.
- Optional IDs for bead, Agent Mail thread/message, agent, file reservation, RCH job, verification run, and git SHA.
- `details`: structured metadata redacted by default.
- `redaction`: count and field names redacted before serialization.

The module is intentionally library-first. Operators or later CLI surfaces can append events as work happens, export JSONL with `SwarmActivityLedger::to_jsonl`, and reconstruct a deterministic timeline with `timeline_from_jsonl`. Timeline reconstruction sorts by `timestamp_ms`, then `sequence`, then `correlation_id`, so incident review stays deterministic even when rows are collected out of order.

Redaction is fail-closed for common sensitive fields. Keys containing `prompt`, `body`, `transcript`, `token`, `secret`, `password`, `authorization`, `bearer`, `cookie`, or `key` serialize as `[REDACTED]`; values that look like bearer tokens, API keys, or password/token assignments are also redacted. Store command names, artifact paths, status codes, and IDs rather than prompts, model outputs, or raw credentials.

## Bounded summaries

`SwarmActivityLedger::summarize` and `SwarmActivitySketch` derive schema `pi.swarm.activity_summary.v1` from the raw rows without replacing or mutating them. The raw JSONL remains the audit source; summaries are a bounded-memory view for dashboards, handoff notes, and swarm health checks.

Summaries retain exact totals for event count, redacted entries, redacted fields, and activity kind counts. Hot spot lists are bounded independently for agents, beads, verification IDs, tools, providers/models, and selected detail key/value pairs. Ties sort deterministically by count descending and then key ascending. Long hot spot keys are truncated before retention so a single large detail value cannot dominate memory.

Latency details named `latency_ms`, `duration_ms`, or `elapsed_ms` feed a bounded sample sketch. The summary reports retained sample count, min, p50, p95, p99, max, and a conservative rank-error bound. Sketches can be merged across runs; the receiving sketch keeps its configured capacities and downsamples merged latency samples back to the requested bound.

Example row:

```json
{"schema":"pi.swarm.activity_ledger.v1","sequence":0,"timestamp_ms":1778223600000,"kind":"verification","summary":"cargo check completed","ids":{"correlation_id":"bd-2zcs5.17:verify:1","bead_id":"bd-2zcs5.17","agent_name":"CopperOx","rch_job_id":"29832517041259999","verification_id":"check-all-targets"},"details":{"command":"cargo check --all-targets","status":"passed"},"redaction":{"redacted_count":0}}
```

Use the ledger for incident review and handoff. It complements Beads and Agent Mail; it does not replace them as sources of truth.
