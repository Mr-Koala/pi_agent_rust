#![allow(clippy::too_many_lines)]
#![forbid(unsafe_code)]

use serde_json::Value;
use std::collections::HashSet;
use std::path::PathBuf;

const CONTRACT_PATH: &str = "docs/contracts/validation-broker-contract.json";
const EXPECTED_SCHEMA: &str = "pi.validation_broker.contract.v1";
const EXPECTED_REQUEST_SCHEMA: &str = "pi.validation_broker.request.v1";
const EXPECTED_SLOT_SCHEMA: &str = "pi.validation_broker.slot.v1";
const EXPECTED_DECISION_SCHEMA: &str = "pi.validation_broker.decision.v1";
const EXPECTED_BEAD_ID: &str = "bd-gusp4.1";
const EXPECTED_PARENT_BEAD_ID: &str = "bd-gusp4";

const REQUIRED_SOURCE_IDS: &[&str] = &[
    "beads_jsonl",
    "beads_db",
    "agent_mail_reservations",
    "rch_status",
    "rch_queue",
    "cargo_headroom_preflight",
    "doctor_swarm_preflight",
    "git_status",
    "validation_artifact_manifest",
    "cargo_command_request",
    "agent_identity",
];

type TestResult = Result<(), String>;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_contract() -> Result<Value, String> {
    let path = repo_root().join(CONTRACT_PATH);
    let raw = std::fs::read_to_string(&path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|err| format!("failed to parse {} as JSON: {err}", path.display()))
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn pointer<'a>(value: &'a Value, path: &str) -> Result<&'a Value, String> {
    value
        .pointer(path)
        .ok_or_else(|| format!("missing JSON pointer {path}"))
}

fn pointer_str<'a>(value: &'a Value, path: &str) -> Result<&'a str, String> {
    pointer(value, path)?
        .as_str()
        .ok_or_else(|| format!("{path} must be a string"))
}

fn pointer_bool(value: &Value, path: &str) -> Result<bool, String> {
    pointer(value, path)?
        .as_bool()
        .ok_or_else(|| format!("{path} must be a bool"))
}

fn pointer_array<'a>(value: &'a Value, path: &str) -> Result<&'a [Value], String> {
    pointer(value, path)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| format!("{path} must be an array"))
}

fn string_set<'a>(value: &'a Value, path: &str) -> Result<HashSet<&'a str>, String> {
    let mut entries = HashSet::new();
    let non_string_message = format!("{path} entries must be strings");
    let blank_message = format!("{path} has blank entry");
    for entry in pointer_array(value, path)? {
        let Some(raw) = entry.as_str() else {
            return Err(non_string_message);
        };
        if raw.trim().is_empty() {
            return Err(blank_message);
        }
        entries.insert(raw);
    }
    Ok(entries)
}

fn require_set(value: &Value, path: &str, expected: &[&str], label: &str) -> TestResult {
    let observed = string_set(value, path)?;
    if let Some(missing) = expected.iter().find(|item| !observed.contains(**item)) {
        return Err(format!("missing {label}: {missing}"));
    }
    Ok(())
}

fn require_array_contains_fragment(value: &Value, path: &str, fragment: &str) -> TestResult {
    let entries = pointer_array(value, path)?;
    require(
        entries
            .iter()
            .any(|entry| entry.as_str().is_some_and(|text| text.contains(fragment))),
        format!("{path} must contain fragment {fragment:?}"),
    )
}

#[test]
fn validation_broker_contract_has_identity_and_advisory_purpose() -> TestResult {
    let contract = load_contract()?;

    require(
        pointer_str(&contract, "/schema")? == EXPECTED_SCHEMA,
        "schema mismatch",
    )?;
    require(
        pointer_str(&contract, "/request_schema")? == EXPECTED_REQUEST_SCHEMA,
        "request schema mismatch",
    )?;
    require(
        pointer_str(&contract, "/slot_schema")? == EXPECTED_SLOT_SCHEMA,
        "slot schema mismatch",
    )?;
    require(
        pointer_str(&contract, "/decision_schema")? == EXPECTED_DECISION_SCHEMA,
        "decision schema mismatch",
    )?;
    require(
        pointer_str(&contract, "/bead_id")? == EXPECTED_BEAD_ID,
        "bead linkage mismatch",
    )?;
    require(
        pointer_str(&contract, "/parent_bead_id")? == EXPECTED_PARENT_BEAD_ID,
        "parent bead linkage mismatch",
    )?;
    require(
        pointer_str(&contract, "/purpose")?
            == "live_validation_admission_advisory_not_ci_or_rch_replacement",
        "purpose must keep broker advisory",
    )?;
    require_array_contains_fragment(&contract, "/non_goals", "replace_rch")?;
    require_array_contains_fragment(&contract, "/non_goals", "suppress_required")?;

    Ok(())
}

#[test]
fn validation_broker_contract_declares_source_inventory_and_boundaries() -> TestResult {
    let contract = load_contract()?;

    require_set(
        &contract,
        "/required_source_ids",
        REQUIRED_SOURCE_IDS,
        "source id",
    )?;
    require_set(
        &contract,
        "/source_status_contract/required_fields",
        &[
            "source_id",
            "source_kind",
            "availability",
            "freshness_state",
            "source_hash",
            "authoritative_for",
            "redaction_state",
            "degraded_reasons",
            "suppressed_claims",
        ],
        "source status field",
    )?;

    let boundaries = pointer_array(&contract, "/authoritative_source_boundaries")?;
    require(
        boundaries.len() >= 7,
        "source boundary list must cover all major input surfaces",
    )?;
    let boundary_ids: HashSet<&str> = boundaries
        .iter()
        .filter_map(|entry| entry.get("source_id").and_then(Value::as_str))
        .collect();
    let required_boundaries = [
        "beads_jsonl",
        "agent_mail_reservations",
        "rch_status",
        "cargo_headroom_preflight",
        "doctor_swarm_preflight",
        "git_status",
        "validation_artifact_manifest",
    ];
    if let Some(missing) = required_boundaries
        .iter()
        .find(|required| !boundary_ids.contains(**required))
    {
        return Err(format!("missing authoritative boundary for {missing}"));
    }

    Ok(())
}

#[test]
fn validation_broker_contract_fails_closed_for_missing_sources() -> TestResult {
    let contract = load_contract()?;

    require_set(
        &contract,
        "/source_status_contract/allowed_availability",
        &[
            "unavailable",
            "partial",
            "malformed",
            "stale",
            "not_configured",
        ],
        "availability state",
    )?;
    require_set(
        &contract,
        "/source_status_contract/allowed_freshness_states",
        &["missing", "malformed", "freshness_unknown"],
        "freshness state",
    )?;

    let policy = pointer_str(&contract, "/source_status_contract/missing_source_policy")?;
    require(
        policy.contains("must not infer or invent facts"),
        "missing source policy must forbid invented facts",
    )?;
    require(
        policy.contains("must not become allow or coalesce"),
        "missing source policy must block allow/coalesce",
    )?;
    require_set(
        &contract,
        "/decision_contract/allowed_decisions",
        &["degraded_block", "wait", "narrow", "stale_recover"],
        "safe degraded decision",
    )
}

#[test]
fn validation_broker_contract_covers_request_slot_and_decision_shapes() -> TestResult {
    let contract = load_contract()?;

    require_set(
        &contract,
        "/request_contract/required_top_level_keys",
        &[
            "schema",
            "request_id",
            "agent_name",
            "bead_id",
            "cwd",
            "git_head",
            "command",
            "command_class",
            "requested_scope",
            "target_dir",
            "tmpdir",
            "runner_requirement",
            "dirty_worktree_policy",
            "evidence_requirements",
        ],
        "request key",
    )?;
    require_set(
        &contract,
        "/slot_lease_contract/required_top_level_keys",
        &[
            "schema",
            "slot_id",
            "state",
            "owner_agent",
            "bead_id",
            "command_fingerprint",
            "environment_fingerprint",
            "git_head",
            "target_dir",
            "tmpdir",
            "runner",
            "heartbeat_at_utc",
            "expires_at_utc",
            "artifacts",
        ],
        "slot key",
    )?;
    require_set(
        &contract,
        "/decision_contract/required_top_level_keys",
        &[
            "schema",
            "decision_id",
            "request_id",
            "decision",
            "confidence",
            "reasons",
            "source_statuses",
            "required_actions",
            "suppressed_claims",
            "no_claims",
        ],
        "decision key",
    )?;
    require_set(
        &contract,
        "/decision_contract/coalescing_equivalence_fields",
        &[
            "command_fingerprint",
            "cwd",
            "git_head",
            "feature_flags",
            "target_dir",
            "tmpdir",
            "runner",
            "rust_toolchain",
            "environment_fingerprint",
            "artifact_schema",
            "artifact_hash",
        ],
        "coalescing equivalence field",
    )
}

#[test]
fn validation_broker_contract_is_read_only_in_plan_mode() -> TestResult {
    let contract = load_contract()?;

    require(
        !pointer_bool(
            &contract,
            "/mutation_policy/plan_mode_live_mutation_allowed",
        )?,
        "plan mode must be read-only",
    )?;
    require_set(
        &contract,
        "/mutation_policy/forbidden_mutations",
        &[
            "git_reset",
            "git_clean",
            "file_delete",
            "kill_other_agent_process",
            "stash_or_checkout_other_agent_work",
            "rewrite_mail_archive",
            "rewrite_beads_without_br",
        ],
        "forbidden mutation",
    )?;
    require_set(
        &contract,
        "/slot_lease_contract/stale_policy/safe_next_actions",
        &[
            "wait_for_owner",
            "request_owner_update",
            "open_new_non_overlapping_slot",
            "surface_blocker",
            "rerun_after_provenance_mismatch",
        ],
        "safe stale action",
    )
}

#[test]
fn validation_broker_contract_preserves_redaction_and_no_claims() -> TestResult {
    let contract = load_contract()?;

    require_set(
        &contract,
        "/redaction_contract/required_redacted_classes",
        &[
            "api_key",
            "bearer_token",
            "oauth_token",
            "mail_body",
            "private_prompt",
            "absolute_home_path_when_not_needed",
            "large_command_output_body",
        ],
        "redacted class",
    )?;
    require_set(
        &contract,
        "/decision_contract/required_no_claims",
        &[
            "not_ci_success",
            "not_release_performance_evidence",
            "not_dropin_certification_evidence",
            "not_permission_to_skip_required_gates",
            "not_permission_to_modify_other_agents_files",
        ],
        "no-claim marker",
    )
}

#[test]
fn validation_broker_contract_links_downstream_beads_and_requirements() -> TestResult {
    let contract = load_contract()?;

    require_set(
        &contract,
        "/downstream_dependencies/unblocked_by_this_contract",
        &["bd-gusp4.2", "bd-gusp4.3"],
        "downstream bead",
    )?;
    require(
        pointer_str(&contract, "/downstream_dependencies/final_closeout_bead")? == "bd-gusp4.11",
        "final closeout bead mismatch",
    )?;

    let requirements = pointer_array(&contract, "/must_requirements")?;
    require(
        requirements.len() >= 8,
        "contract must define enough must-requirements for closeout",
    )?;
    for requirement in requirements {
        let id = requirement
            .get("id")
            .and_then(Value::as_str)
            .ok_or("requirement id must be a string")?;
        require(
            id.starts_with("VALIDBROKER-MUST-"),
            "requirement id must use VALIDBROKER-MUST- prefix",
        )?;
        require(
            requirement
                .get("description")
                .and_then(Value::as_str)
                .is_some_and(|description| !description.trim().is_empty()),
            "requirement must have a description",
        )?;
        require(
            requirement
                .get("validated_by")
                .and_then(Value::as_array)
                .is_some_and(|validated_by| !validated_by.is_empty()),
            "requirement must name validation hooks",
        )?;
    }

    Ok(())
}
