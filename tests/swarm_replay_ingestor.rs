#![allow(clippy::too_many_lines)]
#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use pi::swarm_replay::{
    SWARM_REPLAY_TRACE_SCHEMA, SwarmReplayIngestRequest, SwarmReplayTrace, build_swarm_replay_trace,
};
use serde_json::{Value, json};

const GENERATED_AT: &str = "2026-05-13T18:40:00Z";
const GOLDEN_TRACE: &str = "tests/golden_corpus/swarm_replay_trace/normalized_trace.json";

type TestResult = Result<(), Box<dyn Error>>;

static WORKSPACE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn test_workspace(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let nonce = WORKSPACE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let target_root = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target"),
        PathBuf::from,
    );
    let root = target_root
        .join("swarm_replay_ingestor_tests")
        .join(format!("{name}-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&root)?;
    Ok(root)
}

fn write_text(root: &Path, rel: &str, text: &str) -> std::io::Result<()> {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, text)
}

fn write_json(root: &Path, rel: &str, value: &Value) -> std::io::Result<()> {
    write_text(root, rel, &serde_json::to_string_pretty(value)?)
}

fn base_request(root: &Path) -> SwarmReplayIngestRequest {
    SwarmReplayIngestRequest::new("fixture-clean-replay-trace", GENERATED_AT, root)
        .with_git_identity("abc123", "main")
        .with_source_override("agent_mail_archive", "mail/archive.json")
        .with_source_override("git_refs", "git/refs.json")
        .with_source_override("validation_command_records", "validation/records.json")
        .with_source_override("swarm_flight_recorder", "flight/events.jsonl")
        .with_source_override("swarm_activity_ledger", "activity/events.jsonl")
}

fn write_clean_sources(root: &Path, include_agent_mail: bool) -> std::io::Result<()> {
    write_text(
        root,
        ".beads/issues.jsonl",
        r#"{"id":"bd-clean","status":"in_progress","priority":3,"assignee":"AmberOsprey","updated_at":"2026-05-13T18:00:00Z"}"#,
    )?;
    write_text(root, ".beads/beads.db", "sqlite fixture bytes")?;
    if include_agent_mail {
        write_json(
            root,
            "mail/archive.json",
            &json!({
                "messages": [{
                    "thread_id": "bd-clean",
                    "sender": "AmberOsprey",
                    "recipients": ["SilentReef"],
                    "importance": "normal",
                    "ack_required": true,
                    "created_at": "2026-05-13T18:01:00Z",
                    "body": "SECRET BODY SHOULD NOT SURVIVE"
                }],
                "reservations": [{
                    "id": "res-1",
                    "path_patterns": ["src/swarm_replay.rs"],
                    "exclusive": true,
                    "ttl_seconds": 3600,
                    "reason": "bd-in57w.2",
                    "holder": "AmberOsprey",
                    "created_at": "2026-05-13T18:02:00Z"
                }],
                "reservation_conflicts": [{
                    "path_pattern": "src/doctor.rs",
                    "holder": "SunnyBeacon",
                    "conflict_reason": "active exclusive lease",
                    "created_at": "2026-05-13T18:03:00Z"
                }],
                "build_slots": [{
                    "slot": "cargo-all-targets",
                    "holder": "AmberOsprey",
                    "state": "released",
                    "expires_at_utc": "2026-05-13T19:00:00Z",
                    "created_at": "2026-05-13T18:04:00Z"
                }]
            }),
        )?;
    }
    write_json(
        root,
        "docs/evidence/doctor-swarm.json",
        &json!({
            "findings": [{
                "finding_id": "mail_degraded",
                "severity": "degraded",
                "surface": "agent_mail",
                "status": "observed",
                "created_at": "2026-05-13T18:05:00Z"
            }]
        }),
    )?;
    write_json(
        root,
        "docs/evidence/rch-queue-status.json",
        &json!({
            "jobs": [{
                "job_id": "rch-1",
                "state": "finished",
                "worker": "worker-redacted",
                "command": "rch exec -- cargo check --all-targets",
                "queue_position": 0,
                "created_at": "2026-05-13T18:06:00Z"
            }]
        }),
    )?;
    write_json(
        root,
        "docs/evidence/swarm-operator-runpack.json",
        &json!({
            "recommendations": [{
                "action": "continue_bd_in57w_2",
                "severity": "normal",
                "evidence_paths": ["docs/contracts/swarm-replay-trace-contract.json"],
                "operator_notes": "read-only replay ingestion",
                "created_at": "2026-05-13T18:07:00Z"
            }],
            "operator_handoff": {
                "handoff_id": "handoff-clean",
                "summary": "continue replay lab",
                "next_actions": ["implement replay engine"],
                "evidence_paths": ["tests/golden_corpus/swarm_replay_trace/normalized_trace.json"],
                "created_at": "2026-05-13T18:08:00Z"
            }
        }),
    )?;
    write_json(
        root,
        "git/refs.json",
        &json!({
            "head": "abc123",
            "branch": "main",
            "dirty": false,
            "changed_paths": [],
            "created_at": "2026-05-13T18:09:00Z"
        }),
    )?;
    write_json(
        root,
        "validation/records.json",
        &json!({
            "commands": [{
                "command": "rch exec -- cargo test --test swarm_replay_ingestor",
                "runner": "rch",
                "exit_code": 0,
                "target_dir": "/data/tmp/pi_agent_rust_cargo/amberosprey/target",
                "tmpdir": "/data/tmp/pi_agent_rust_cargo/amberosprey/tmp",
                "created_at": "2026-05-13T18:10:00Z"
            }],
            "artifacts": [{
                "artifact_path": "tests/golden_corpus/swarm_replay_trace/normalized_trace.json",
                "artifact_schema": "pi.swarm.replay_trace.v1",
                "verdict": "pass",
                "command": "cargo test --test swarm_replay_ingestor",
                "created_at": "2026-05-13T18:11:00Z"
            }]
        }),
    )?;
    write_json(
        root,
        "docs/evidence/context-intelligence-closeout-gate.json",
        &json!({
            "schema": "pi.context_intelligence.closeout_gate.v1",
            "verdict": "pass",
            "generated_at": "2026-05-13T18:12:00Z"
        }),
    )?;
    write_text(
        root,
        "flight/events.jsonl",
        r#"{"schema":"pi.swarm.flight_recorder.event.v1","event_kind":"agent_turn","agent_name":"AmberOsprey","created_at":"2026-05-13T18:13:00Z"}"#,
    )?;
    write_text(
        root,
        "activity/events.jsonl",
        r#"{"schema":"pi.swarm.activity_ledger.v1","event_kind":"operator_handoff","handoff_id":"activity-handoff","summary":"handoff from activity ledger","next_actions":["inspect replay"],"evidence_paths":["tests/full_suite_gate/swarm_activity_digest.json"],"created_at":"2026-05-13T18:14:00Z"}"#,
    )
}

fn source_row<'a>(
    trace: &'a SwarmReplayTrace,
    source_id: &str,
) -> Result<&'a pi::swarm_replay::SwarmReplaySourceInventoryRow, String> {
    trace
        .source_inventory
        .iter()
        .find(|row| row.source_id == source_id)
        .ok_or_else(|| format!("missing source row {source_id}"))
}

fn event_types(trace: &SwarmReplayTrace) -> BTreeSet<String> {
    trace
        .events
        .iter()
        .map(|event| event.event_type.clone())
        .collect()
}

fn assert_monotonic_sequence(trace: &SwarmReplayTrace) -> TestResult {
    for (index, event) in trace.events.iter().enumerate() {
        let expected = u64::try_from(index + 1)?;
        assert_eq!(event.sequence, expected);
    }
    Ok(())
}

#[test]
fn clean_sources_normalize_into_contract_events() -> TestResult {
    let root = test_workspace("clean_sources")?;
    write_clean_sources(&root, true)?;

    let trace = build_swarm_replay_trace(&base_request(&root))?;
    assert_eq!(trace.schema, SWARM_REPLAY_TRACE_SCHEMA);
    assert_eq!(trace.source_inventory.len(), 11);
    assert!(trace.replay_guards.read_only);
    assert!(trace.replay_guards.no_live_mutation);
    assert_eq!(trace.redaction_summary.raw_secret_bytes_emitted, 0);
    assert!(
        trace
            .redaction_summary
            .redacted_fields
            .iter()
            .any(|field| field.contains("body")),
        "agent mail body must be redacted"
    );

    let required_event_types = [
        "bead_lifecycle",
        "reservation_intent",
        "reservation_conflict",
        "agent_message",
        "build_slot_state",
        "rch_job_state",
        "cargo_gate_result",
        "worktree_state",
        "doctor_finding",
        "runpack_recommendation",
        "validation_artifact",
        "operator_handoff",
    ];
    let observed = event_types(&trace);
    for required in required_event_types {
        assert!(
            observed.contains(required),
            "missing normalized event type {required}"
        );
    }
    assert_monotonic_sequence(&trace)
}

#[test]
fn missing_agent_mail_keeps_beads_rch_and_doctor_usable() -> TestResult {
    let root = test_workspace("missing_agent_mail")?;
    write_clean_sources(&root, false)?;

    let trace = build_swarm_replay_trace(&base_request(&root))?;
    let mail = source_row(&trace, "agent_mail_archive")?;
    assert_eq!(mail.availability, "unavailable");
    assert_eq!(mail.freshness_state, "missing");
    assert!(
        mail.uncertainty
            .iter()
            .any(|reason| reason == "source_missing")
    );

    let observed = event_types(&trace);
    assert!(observed.contains("bead_lifecycle"));
    assert!(observed.contains("rch_job_state"));
    assert!(observed.contains("doctor_finding"));
    assert!(
        trace
            .uncertainty_summary
            .suppressed_claims
            .iter()
            .any(|claim| claim == "mail_thread_completeness")
    );
    Ok(())
}

#[test]
fn malformed_rch_snapshot_suppresses_queue_claims() -> TestResult {
    let root = test_workspace("malformed_rch_snapshot")?;
    write_clean_sources(&root, true)?;
    write_text(&root, "docs/evidence/rch-queue-status.json", "{not-json")?;

    let trace = build_swarm_replay_trace(&base_request(&root))?;
    let rch = source_row(&trace, "rch_queue_status")?;
    assert_eq!(rch.availability, "malformed");
    assert_eq!(rch.freshness_state, "malformed");
    assert!(!event_types(&trace).contains("rch_job_state"));
    assert!(
        trace
            .uncertainty_summary
            .suppressed_claims
            .iter()
            .any(|claim| claim == "queue_depth")
    );
    Ok(())
}

#[test]
fn stale_runpack_is_classified_without_discarding_inventory() -> TestResult {
    let root = test_workspace("stale_runpack")?;
    write_clean_sources(&root, true)?;
    write_json(
        &root,
        "docs/evidence/swarm-operator-runpack.json",
        &json!({
            "freshness_state": "stale",
            "operator_handoff": {
                "handoff_id": "stale-handoff",
                "summary": "old runpack",
                "next_actions": ["refresh"],
                "evidence_paths": [],
                "created_at": "2026-05-13T18:08:00Z"
            }
        }),
    )?;

    let trace = build_swarm_replay_trace(&base_request(&root))?;
    let runpack = source_row(&trace, "operator_runpack")?;
    assert_eq!(runpack.availability, "stale");
    assert_eq!(runpack.freshness_state, "stale");
    assert!(
        trace
            .uncertainty_summary
            .stale_sources
            .iter()
            .any(|source| source == "operator_runpack")
    );
    Ok(())
}

#[test]
fn duplicate_source_event_ids_are_deduplicated_and_marked() -> TestResult {
    let root = test_workspace("duplicate_source_event_ids")?;
    write_clean_sources(&root, true)?;
    write_json(
        &root,
        "validation/records.json",
        &json!({
            "artifacts": [
                {
                    "artifact_path": "same.json",
                    "artifact_schema": "pi.test",
                    "verdict": "pass",
                    "command": "first",
                    "created_at": "2026-05-13T18:11:00Z"
                },
                {
                    "artifact_path": "same.json",
                    "artifact_schema": "pi.test",
                    "verdict": "pass",
                    "command": "second",
                    "created_at": "2026-05-13T18:11:00Z"
                }
            ]
        }),
    )?;

    let trace = build_swarm_replay_trace(&base_request(&root))?;
    let mut ids = BTreeSet::new();
    for event in &trace.events {
        assert!(
            ids.insert(event.event_id.clone()),
            "duplicate final event id {}",
            event.event_id
        );
    }
    assert!(trace.events.iter().any(|event| {
        event
            .uncertainty
            .reasons
            .iter()
            .any(|reason| reason == "duplicate_source_event_id_deduplicated")
    }));
    Ok(())
}

#[test]
fn checked_in_golden_trace_fixture_is_downstream_consumable() -> TestResult {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(GOLDEN_TRACE);
    let raw = fs::read_to_string(path)?;
    let trace: SwarmReplayTrace = serde_json::from_str(&raw)?;

    assert_eq!(trace.schema, SWARM_REPLAY_TRACE_SCHEMA);
    assert_eq!(trace.contract_version, "1.0.0");
    assert_eq!(trace.source_inventory.len(), 11);
    assert!(trace.replay_guards.read_only);
    assert!(
        trace
            .events
            .iter()
            .any(|event| event.event_type == "bead_lifecycle")
    );
    assert!(
        trace
            .events
            .iter()
            .any(|event| event.event_type == "validation_artifact")
    );
    assert_monotonic_sequence(&trace)
}
