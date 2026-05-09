#!/usr/bin/env python3
"""Report swarm-scale evidence freshness and claim readiness.

Normal report generation is read-only. Without --gate it exits 0 and prints the
current evidence state for operators. With --gate it exits 1 when release-facing
claim evidence is missing, stale, no-data, invalid, or provenance-mismatched.
The --self-test mode writes disposable fixture directories under TMPDIR and does
not delete them.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


REPORT_SCHEMA = "pi.swarm.claim_readiness_report.v1"
STALE_CLAIM_REPORT_SCHEMA = "pi.swarm.stale_claim_report.v1"
DEFAULT_MAX_AGE_DAYS = 14
DEFAULT_STALE_CLAIM_AFTER_HOURS = 24
DEFAULT_STALE_CLAIM_ACTIVITY_FRESH_HOURS = 6
DEFAULT_STALE_CLAIM_ACTIVITY_PATHS = (
    "tests/full_suite_gate/swarm_activity_events.jsonl",
    "tests/full_suite_gate/swarm_activity_ledger.jsonl",
)

DEFAULT_TIMESTAMP_PATHS = (
    "generated_at",
    "generated_at_utc",
    "effective_date_utc",
    "summary.generated_at",
)
DEFAULT_PROVENANCE_PATHS = (
    "correlation_id",
    "run_id",
    "ci_run_id",
    "git_commit",
    "git_ref",
    "bead_id",
)


@dataclass(frozen=True)
class EvidenceSpec:
    id: str
    category: str
    path: str
    description: str
    claim_surface: str
    release_blocking: bool = True
    generated: bool = True
    required_schema: str | None = None
    timestamp_paths: tuple[str, ...] = DEFAULT_TIMESTAMP_PATHS
    status_path: str | None = None
    ok_values: tuple[Any, ...] = ()
    zero_paths: tuple[str, ...] = ()
    provenance_paths: tuple[str, ...] = DEFAULT_PROVENANCE_PATHS
    provenance_group: str | None = None


@dataclass(frozen=True)
class EvidenceIssue:
    kind: str
    detail: str
    blocking: bool

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "detail": self.detail,
            "blocking": self.blocking,
        }


@dataclass
class EvidenceCheck:
    spec: EvidenceSpec
    exists: bool
    generated_at: datetime | None
    age_days: float | None
    schema: str | None
    provenance_value: str | None
    issues: list[EvidenceIssue]

    def status(self) -> str:
        kinds = {issue.kind for issue in self.issues}
        for kind in (
            "missing",
            "invalid_json",
            "schema_mismatch",
            "status_not_ready",
            "no_data",
            "missing_timestamp",
            "stale",
            "provenance_mismatch",
        ):
            if kind in kinds:
                return kind
        if self.spec.claim_surface == "historical_snapshot":
            return "historical_snapshot"
        return "ready"

    def blocking_issue_count(self) -> int:
        return sum(1 for issue in self.issues if issue.blocking)

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.spec.id,
            "category": self.spec.category,
            "path": self.spec.path,
            "description": self.spec.description,
            "claim_surface": self.spec.claim_surface,
            "release_blocking": self.spec.release_blocking,
            "status": self.status(),
            "exists": self.exists,
            "schema": self.schema,
            "generated_at": format_datetime(self.generated_at),
            "age_days": round(self.age_days, 2) if self.age_days is not None else None,
            "provenance_value": self.provenance_value,
            "issues": [issue.to_json() for issue in self.issues],
        }


@dataclass(frozen=True)
class ClaimActivityEvidence:
    bead_id: str
    timestamp: datetime
    source: str
    agent_name: str | None


EVIDENCE_SPECS = (
    EvidenceSpec(
        id="perf_budget_summary",
        category="perf",
        path="tests/perf/reports/budget_summary.json",
        description="CI-enforced performance budget summary.",
        claim_surface="release_facing",
        required_schema="pi.perf.budget_summary.v1",
        zero_paths=("ci_fail", "ci_no_data", "data_contract_failures_count"),
        provenance_group="perf",
    ),
    EvidenceSpec(
        id="perf_stress_triage",
        category="perf",
        path="tests/perf/reports/stress_triage.json",
        description="Extension stress and reactor queue performance triage.",
        claim_surface="release_facing",
        status_path="pass",
        ok_values=(True,),
        provenance_group="perf",
    ),
    EvidenceSpec(
        id="perf3x_bead_coverage",
        category="perf",
        path="tests/full_suite_gate/perf3x_bead_coverage_audit.json",
        description="Perf evidence bead coverage audit.",
        claim_surface="release_facing",
        required_schema="pi.perf3x.bead_coverage.audit.v1",
        status_path="status",
        ok_values=("pass",),
        zero_paths=("missing_evidence_count",),
        provenance_group="full_suite",
    ),
    EvidenceSpec(
        id="full_suite_verdict",
        category="full_suite",
        path="tests/full_suite_gate/full_suite_verdict.json",
        description="Full-suite gate verdict.",
        claim_surface="release_facing",
        required_schema="pi.ci.full_suite_gate.v1",
        status_path="verdict",
        ok_values=("pass",),
        provenance_group="full_suite",
    ),
    EvidenceSpec(
        id="certification_lane",
        category="full_suite",
        path="tests/full_suite_gate/certification_verdict.json",
        description="Certification lane verdict.",
        claim_surface="release_facing",
        required_schema="pi.ci.certification_lane.v1",
        status_path="verdict",
        ok_values=("pass",),
        provenance_group="full_suite",
    ),
    EvidenceSpec(
        id="evidence_bundle_index",
        category="full_suite",
        path="tests/evidence_bundle/index.json",
        description="Indexed evidence bundle for release triage.",
        claim_surface="release_facing",
        required_schema="pi.ci.evidence_bundle.v1",
        provenance_group="full_suite",
    ),
    EvidenceSpec(
        id="dropin_certification_verdict",
        category="dropin",
        path="docs/evidence/dropin-certification-verdict.json",
        description="Strict drop-in release claim gate.",
        claim_surface="release_facing",
        required_schema="pi.dropin.certification_verdict.v1",
        status_path="overall_verdict",
        ok_values=("CERTIFIED",),
        provenance_group="dropin",
    ),
    EvidenceSpec(
        id="dropin_contract",
        category="dropin",
        path="docs/contracts/dropin-certification-contract.json",
        description="Normative drop-in claim policy contract.",
        claim_surface="release_policy",
        generated=False,
        required_schema="pi.dropin.certification_contract.v1",
    ),
    EvidenceSpec(
        id="dropin_differential_suite",
        category="dropin",
        path="docs/evidence/dropin-differential-evidence-suite.json",
        description="Differential evidence suite backing drop-in claims.",
        claim_surface="release_facing",
        required_schema="pi.dropin.differential_evidence_suite.v1",
        provenance_group="dropin",
    ),
    EvidenceSpec(
        id="dropin_feature_inventory",
        category="dropin",
        path="docs/evidence/dropin-feature-inventory-matrix.json",
        description="Feature inventory matrix for drop-in parity.",
        claim_surface="release_facing",
        required_schema="pi.dropin.feature_inventory.v1",
        provenance_group="dropin",
    ),
    EvidenceSpec(
        id="dropin_gap_ledger",
        category="dropin",
        path="docs/evidence/dropin-parity-gap-ledger.json",
        description="Parity gap ledger used by release claim policy.",
        claim_surface="release_facing",
        required_schema="pi.dropin.parity_gap_ledger.v1",
        provenance_group="dropin",
    ),
    EvidenceSpec(
        id="extension_must_pass_gate",
        category="extension",
        path="tests/ext_conformance/reports/gate/must_pass_gate_verdict.json",
        description="Strict extension must-pass verdict.",
        claim_surface="release_facing",
        required_schema="pi.ext.must_pass_gate.v1",
        status_path="status",
        ok_values=("pass",),
        zero_paths=("observed.must_pass_failed", "observed.must_pass_skipped"),
        provenance_group="extension",
    ),
    EvidenceSpec(
        id="extension_health_delta",
        category="extension",
        path="tests/ext_conformance/reports/health_delta/health_delta_report.json",
        description="Extension health delta against baseline.",
        claim_surface="release_facing",
        required_schema="pi.ext.health_delta.v1",
        zero_paths=("current_summary.skipped",),
        provenance_group="extension",
    ),
    EvidenceSpec(
        id="extension_journey_report",
        category="extension",
        path="tests/ext_conformance/reports/journeys/journey_report.json",
        description="Historical extension journey and remaining stretch failures.",
        claim_surface="historical_snapshot",
        generated=False,
    ),
    EvidenceSpec(
        id="extension_reactor_queue_coverage",
        category="extension",
        path="docs/evidence/ext-stress-reactor-queue-coverage.json",
        description="Reactor queue stress coverage evidence.",
        claim_surface="release_facing",
        required_schema="pi.ext.reactor_queue_coverage_evidence.v1",
        status_path="status",
        ok_values=("PASS", "pass"),
        provenance_group="extension",
    ),
    EvidenceSpec(
        id="activity_ledger_docs",
        category="activity_ledger",
        path="docs/swarm-activity-ledger.md",
        description="Operator contract for swarm activity ledger rows and digests.",
        claim_surface="historical_snapshot",
        generated=False,
    ),
    EvidenceSpec(
        id="activity_ledger_digest",
        category="activity_ledger",
        path="tests/full_suite_gate/swarm_activity_digest.json",
        description="Generated bounded digest for the latest multi-agent run.",
        claim_surface="release_facing",
        required_schema="pi.swarm.activity_digest.v1",
        provenance_group="activity_ledger",
    ),
)


def as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def parse_iso_datetime(raw: Any) -> datetime | None:
    if not isinstance(raw, str):
        return None
    value = raw.strip()
    if not value:
        return None
    if value.endswith("Z"):
        value = f"{value[:-1]}+00:00"
    if "." in value:
        prefix, suffix = value.split(".", 1)
        digits = []
        rest_start = 0
        for idx, char in enumerate(suffix):
            if char.isdigit():
                digits.append(char)
                rest_start = idx + 1
            else:
                break
        if digits:
            fraction = "".join(digits)[:6].ljust(6, "0")
            value = f"{prefix}.{fraction}{suffix[rest_start:]}"
    try:
        return as_utc(datetime.fromisoformat(value))
    except ValueError:
        return None


def format_datetime(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def get_path(payload: Any, path: str) -> Any:
    current = payload
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def first_path(payload: Any, paths: tuple[str, ...]) -> tuple[str | None, Any]:
    for path in paths:
        value = get_path(payload, path)
        if value is not None:
            return path, value
    return None, None


def normalize_value(value: Any) -> Any:
    if isinstance(value, str):
        return value.strip()
    return value


def is_zero(value: Any) -> bool:
    if value is False:
        return True
    if value is True:
        return False
    if isinstance(value, (int, float)):
        return value == 0
    if isinstance(value, str):
        stripped = value.strip().lower()
        if stripped in {"", "0", "0.0", "false", "none", "null"}:
            return True
        try:
            return float(stripped) == 0.0
        except ValueError:
            return False
    if isinstance(value, (list, tuple, dict, set)):
        return len(value) == 0
    return value is None


def issue_for(spec: EvidenceSpec, kind: str, detail: str) -> EvidenceIssue:
    blocking = spec.release_blocking and spec.claim_surface == "release_facing"
    return EvidenceIssue(kind=kind, detail=detail, blocking=blocking)


def load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        with path.open(encoding="utf-8") as handle:
            payload = json.load(handle)
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON: {exc}"
    except UnicodeDecodeError:
        return None, "artifact is not UTF-8"
    except OSError as exc:
        return None, f"failed to read artifact: {exc}"
    if not isinstance(payload, dict):
        return None, "JSON artifact must be an object"
    return payload, None


def load_jsonl_objects(path: Path) -> tuple[list[dict[str, Any]], str | None]:
    objects: list[dict[str, Any]] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    payload = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    return objects, f"{path}:{line_number}: invalid JSON: {exc}"
                if isinstance(payload, dict):
                    payload["_source_line"] = line_number
                    objects.append(payload)
    except UnicodeDecodeError:
        return objects, f"{path}: artifact is not UTF-8"
    except OSError as exc:
        return objects, f"{path}: failed to read artifact: {exc}"
    return objects, None


def parse_epoch_millis(raw: Any) -> datetime | None:
    if isinstance(raw, bool) or raw is None:
        return None
    if isinstance(raw, (int, float)):
        try:
            return datetime.fromtimestamp(float(raw) / 1000.0, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
    if isinstance(raw, str):
        stripped = raw.strip()
        if stripped.isdigit():
            try:
                return datetime.fromtimestamp(int(stripped) / 1000.0, tz=timezone.utc)
            except (OSError, OverflowError, ValueError):
                return None
    return None


def first_timestamp(payload: dict[str, Any]) -> datetime | None:
    timestamp_ms = parse_epoch_millis(get_path(payload, "timestamp_ms"))
    if timestamp_ms is not None:
        return timestamp_ms
    _, raw = first_path(
        payload,
        (
            "timestamp",
            "created_ts",
            "created_at",
            "updated_at",
            "details.timestamp",
            "details.created_ts",
            "details.updated_at",
        ),
    )
    return parse_iso_datetime(raw)


def collect_claim_activity(
    repo_root: Path,
    activity_paths: tuple[str, ...],
) -> tuple[dict[str, ClaimActivityEvidence], list[str], list[str]]:
    latest: dict[str, ClaimActivityEvidence] = {}
    used_paths: list[str] = []
    warnings: list[str] = []
    for relative_path in activity_paths:
        full_path = repo_root / relative_path
        if not full_path.exists():
            continue
        used_paths.append(relative_path)
        rows, error = load_jsonl_objects(full_path)
        if error is not None:
            warnings.append(error)
        for row in rows:
            bead_id = get_path(row, "ids.bead_id") or row.get("bead_id")
            if not isinstance(bead_id, str) or not bead_id.strip():
                continue
            timestamp = first_timestamp(row)
            if timestamp is None:
                continue
            agent_name = get_path(row, "ids.agent_name") or row.get("agent_name")
            if not isinstance(agent_name, str):
                agent_name = None
            line_number = row.get("_source_line", "?")
            kind = row.get("kind") or row.get("phase") or "activity"
            source = f"{relative_path}:{line_number}:{kind}"
            evidence = ClaimActivityEvidence(
                bead_id=bead_id,
                timestamp=timestamp,
                source=source,
                agent_name=agent_name,
            )
            current = latest.get(bead_id)
            if current is None or evidence.timestamp > current.timestamp:
                latest[bead_id] = evidence
    return latest, used_paths, warnings


def read_beads_records(repo_root: Path) -> tuple[list[dict[str, Any]], str | None, str]:
    relative_path = ".beads/issues.jsonl"
    rows, error = load_jsonl_objects(repo_root / relative_path)
    return rows, error, relative_path


def issue_assignee(issue: dict[str, Any]) -> str | None:
    raw = issue.get("assignee") or issue.get("assigned_to") or issue.get("owner")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    return None


def classify_stale_claim(
    issue: dict[str, Any],
    *,
    now: datetime,
    stale_after_hours: int,
    activity_fresh_after_hours: int,
    activity: ClaimActivityEvidence | None,
    bead_source: str,
) -> dict[str, Any]:
    bead_id = str(issue.get("id") or "")
    title = str(issue.get("title") or "")
    status = str(issue.get("status") or "")
    assignee = issue_assignee(issue)
    updated_at_raw = issue.get("updated_at")
    updated_at = parse_iso_datetime(updated_at_raw)
    bead_age_hours: float | None = None
    latest_activity_age_hours: float | None = None
    latest_activity_at: str | None = None
    evidence_source = bead_source
    reasons: list[str] = []

    if updated_at is not None:
        bead_age_hours = max(0.0, (now - updated_at).total_seconds() / 3600.0)
    else:
        reasons.append("bead updated_at is missing or unparseable")

    if activity is not None:
        latest_activity_at = format_datetime(activity.timestamp)
        latest_activity_age_hours = max(0.0, (now - activity.timestamp).total_seconds() / 3600.0)
        evidence_source = activity.source

    if updated_at is None:
        classification = "missing_evidence"
        recommended_action = (
            f"Report-only: do not reopen or reassign {bead_id}; inspect Beads and Agent Mail "
            "for owner evidence, then update the bead manually only after confirmation."
        )
    elif bead_age_hours < stale_after_hours:
        classification = "active"
        recommended_action = (
            f"No status change for {bead_id}; bead updated {bead_age_hours:.1f}h ago, "
            f"below stale threshold {stale_after_hours}h."
        )
    elif (
        activity is not None
        and latest_activity_age_hours is not None
        and latest_activity_age_hours < activity_fresh_after_hours
    ):
        classification = "active_recent_coordination"
        reasons.append(
            f"coordination activity is {latest_activity_age_hours:.1f}h old, "
            f"below activity freshness threshold {activity_fresh_after_hours}h"
        )
        recommended_action = (
            f"No reopen for {bead_id}; recent coordination evidence from {activity.source} "
            "indicates the claim is still active."
        )
    elif assignee is None:
        classification = "stale_unassigned"
        reasons.append("in_progress bead has no assignee")
        recommended_action = (
            f"Report-only: consider `br update {bead_id} --status open` only after confirming "
            "there is no owner in Agent Mail or the activity ledger; no automatic change was made."
        )
    else:
        classification = "stale_needs_owner_follow_up"
        reasons.append(f"bead update age {bead_age_hours:.1f}h meets threshold {stale_after_hours}h")
        if activity is None:
            reasons.append("no optional coordination activity evidence was available")
        else:
            reasons.append(
                f"latest coordination activity age {latest_activity_age_hours:.1f}h "
                f"meets freshness threshold {activity_fresh_after_hours}h"
            )
        recommended_action = (
            f"Report-only: message {assignee} in thread {bead_id}; run "
            f"`br update {bead_id} --status open` only after confirming the owner is stale. "
            "No automatic reopen or reassignment was performed."
        )

    return {
        "bead_id": bead_id,
        "title": title,
        "status": status,
        "assignee": assignee,
        "last_update": format_datetime(updated_at),
        "bead_age_hours": round(bead_age_hours, 2) if bead_age_hours is not None else None,
        "latest_activity_at": latest_activity_at,
        "latest_activity_age_hours": (
            round(latest_activity_age_hours, 2)
            if latest_activity_age_hours is not None
            else None
        ),
        "evidence_source": evidence_source,
        "classification": classification,
        "recommended_operator_action": recommended_action,
        "reasons": reasons,
    }


def build_stale_claim_report(
    repo_root: Path,
    *,
    now: datetime,
    stale_after_hours: int,
    activity_fresh_after_hours: int,
    activity_paths: tuple[str, ...],
) -> dict[str, Any]:
    rows, beads_error, beads_path = read_beads_records(repo_root)
    activity_by_bead, used_activity_paths, activity_warnings = collect_claim_activity(
        repo_root,
        activity_paths,
    )
    warnings = activity_warnings[:]
    if beads_error is not None:
        warnings.append(beads_error)

    items = [
        classify_stale_claim(
            issue,
            now=now,
            stale_after_hours=stale_after_hours,
            activity_fresh_after_hours=activity_fresh_after_hours,
            activity=activity_by_bead.get(str(issue.get("id") or "")),
            bead_source=beads_path,
        )
        for issue in rows
        if issue.get("status") == "in_progress"
    ]
    classifications: dict[str, int] = {}
    for item in items:
        classification = item["classification"]
        classifications[classification] = classifications.get(classification, 0) + 1

    stale_count = sum(
        count
        for classification, count in classifications.items()
        if classification.startswith("stale_")
    )
    missing_evidence_count = classifications.get("missing_evidence", 0)
    status = "needs_coordination" if stale_count or missing_evidence_count or warnings else "ready"
    return {
        "schema": STALE_CLAIM_REPORT_SCHEMA,
        "status": status,
        "policy": "report_only_no_auto_reopen_or_reassign",
        "thresholds": {
            "stale_after_hours": stale_after_hours,
            "activity_fresh_after_hours": activity_fresh_after_hours,
        },
        "source_paths": {
            "beads_ledger": beads_path,
            "activity_jsonl": used_activity_paths,
        },
        "warnings": warnings,
        "summary": {
            "in_progress_count": len(items),
            "active_count": classifications.get("active", 0)
            + classifications.get("active_recent_coordination", 0),
            "stale_count": stale_count,
            "unassigned_count": classifications.get("stale_unassigned", 0),
            "missing_evidence_count": missing_evidence_count,
            "classifications": classifications,
        },
        "items": items,
    }


def check_spec(
    repo_root: Path,
    spec: EvidenceSpec,
    now: datetime,
    max_age: timedelta,
) -> EvidenceCheck:
    full_path = repo_root / spec.path
    issues: list[EvidenceIssue] = []
    generated_at: datetime | None = None
    age_days: float | None = None
    schema: str | None = None
    provenance_value: str | None = None

    if not full_path.exists():
        return EvidenceCheck(
            spec=spec,
            exists=False,
            generated_at=None,
            age_days=None,
            schema=None,
            provenance_value=None,
            issues=[issue_for(spec, "missing", "artifact path does not exist")],
        )

    payload: dict[str, Any] | None = None
    if spec.path.endswith(".json"):
        payload, json_error = load_json(full_path)
        if json_error is not None:
            issues.append(issue_for(spec, "invalid_json", json_error))
        if payload is not None:
            raw_schema = payload.get("schema")
            if isinstance(raw_schema, str):
                schema = raw_schema
            if spec.required_schema is not None and schema != spec.required_schema:
                issues.append(issue_for(
                    spec,
                    "schema_mismatch",
                    f"expected schema {spec.required_schema!r}, found {schema!r}",
                ))

            _, raw_generated_at = first_path(payload, spec.timestamp_paths)
            generated_at = parse_iso_datetime(raw_generated_at)
            _, raw_provenance = first_path(payload, spec.provenance_paths)
            if raw_provenance is not None:
                provenance_value = str(raw_provenance)

            if spec.status_path is not None:
                raw_status = normalize_value(get_path(payload, spec.status_path))
                ok_values = tuple(normalize_value(value) for value in spec.ok_values)
                if raw_status not in ok_values:
                    issues.append(issue_for(
                        spec,
                        "status_not_ready",
                        f"{spec.status_path}={raw_status!r}, expected one of {ok_values!r}",
                    ))

            for zero_path in spec.zero_paths:
                value = get_path(payload, zero_path)
                if value is None:
                    issues.append(issue_for(spec, "no_data", f"{zero_path} is missing"))
                elif not is_zero(value):
                    issues.append(issue_for(spec, "no_data", f"{zero_path}={value!r}"))

    if generated_at is None and spec.generated:
        issues.append(issue_for(spec, "missing_timestamp", "artifact lacks a parseable generated timestamp"))

    if generated_at is not None:
        age = now - generated_at
        age_days = age.total_seconds() / 86400
        if age > max_age:
            issues.append(issue_for(
                spec,
                "stale",
                f"generated timestamp is {age_days:.1f} days old; limit is {max_age.days} days",
            ))

    return EvidenceCheck(
        spec=spec,
        exists=True,
        generated_at=generated_at,
        age_days=age_days,
        schema=schema,
        provenance_value=provenance_value,
        issues=issues,
    )


def add_provenance_mismatches(checks: list[EvidenceCheck]) -> None:
    groups: dict[str, dict[str, list[EvidenceCheck]]] = {}
    for check in checks:
        group = check.spec.provenance_group
        if group is None or not check.provenance_value or check.blocking_issue_count() > 0:
            continue
        groups.setdefault(group, {}).setdefault(check.provenance_value, []).append(check)

    for group, values in groups.items():
        if len(values) <= 1:
            continue
        summary = ", ".join(
            f"{value}: {[check.spec.path for check in group_checks]}"
            for value, group_checks in sorted(values.items())
        )
        for group_checks in values.values():
            for check in group_checks:
                check.issues.append(issue_for(
                    check.spec,
                    "provenance_mismatch",
                    f"{group} evidence has multiple provenance values: {summary}",
                ))


def category_summary(checks: list[EvidenceCheck]) -> list[dict[str, Any]]:
    categories = sorted({check.spec.category for check in checks})
    summaries: list[dict[str, Any]] = []
    for category in categories:
        category_checks = [check for check in checks if check.spec.category == category]
        blocking = sum(check.blocking_issue_count() for check in category_checks)
        statuses: dict[str, int] = {}
        for check in category_checks:
            statuses[check.status()] = statuses.get(check.status(), 0) + 1
        summaries.append({
            "category": category,
            "status": "blocked" if blocking else "ready",
            "blocking_issues": blocking,
            "statuses": statuses,
        })
    return summaries


def remediation_for(kind: str) -> str:
    return {
        "missing": "Regenerate the artifact at the exact path or remove/soften the claim that cites it.",
        "invalid_json": "Fix the artifact writer or replace the malformed artifact with a valid generated artifact.",
        "schema_mismatch": "Regenerate with the current schema before using the artifact for release claims.",
        "status_not_ready": "Do not make the release-facing claim until the gate verdict is passing.",
        "no_data": "Regenerate the evidence from a run with real measurements and clean data contracts.",
        "missing_timestamp": "Regenerate with generated_at or generated_at_utc provenance.",
        "stale": "Regenerate the evidence and update claim citations, or soften the claim to historical language.",
        "provenance_mismatch": "Use a single correlated evidence run for the claim or split the claim by run.",
    }.get(kind, "Review the artifact before using it for release claims.")


def build_report(
    repo_root: Path,
    *,
    now: datetime | None = None,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    stale_claim_after_hours: int = DEFAULT_STALE_CLAIM_AFTER_HOURS,
    stale_claim_activity_fresh_hours: int = DEFAULT_STALE_CLAIM_ACTIVITY_FRESH_HOURS,
    stale_claim_activity_paths: tuple[str, ...] = DEFAULT_STALE_CLAIM_ACTIVITY_PATHS,
) -> dict[str, Any]:
    now = as_utc(now or datetime.now(timezone.utc))
    max_age = timedelta(days=max_age_days)
    checks = [check_spec(repo_root, spec, now, max_age) for spec in EVIDENCE_SPECS]
    add_provenance_mismatches(checks)
    stale_claims = build_stale_claim_report(
        repo_root,
        now=now,
        stale_after_hours=stale_claim_after_hours,
        activity_fresh_after_hours=stale_claim_activity_fresh_hours,
        activity_paths=stale_claim_activity_paths,
    )

    blocking_issues = [
        {
            "path": check.spec.path,
            "category": check.spec.category,
            "kind": issue.kind,
            "detail": issue.detail,
            "remediation": remediation_for(issue.kind),
        }
        for check in checks
        for issue in check.issues
        if issue.blocking
    ]

    return {
        "schema": REPORT_SCHEMA,
        "generated_at": format_datetime(now),
        "repo_root": str(repo_root),
        "max_age_days": max_age_days,
        "overall_status": "blocked" if blocking_issues else "ready",
        "blocking_issue_count": len(blocking_issues),
        "categories": category_summary(checks),
        "artifacts": [check.to_json() for check in checks],
        "stale_claims": stale_claims,
        "blocking_issues": blocking_issues,
    }


def print_text_report(report: dict[str, Any]) -> None:
    print(f"schema: {report['schema']}")
    print(f"generated_at: {report['generated_at']}")
    print(f"overall_status: {report['overall_status']}")
    print(f"blocking_issue_count: {report['blocking_issue_count']}")
    print("")
    print("categories:")
    for category in report["categories"]:
        print(
            f"  {category['category']}: {category['status']} "
            f"({category['blocking_issues']} blocking)"
        )
    print("")
    print("artifacts:")
    for artifact in report["artifacts"]:
        age = artifact["age_days"]
        age_text = "n/a" if age is None else f"{age}d"
        print(
            f"  {artifact['status']}: {artifact['path']} "
            f"[{artifact['category']}, {artifact['claim_surface']}, age={age_text}]"
        )
        for issue in artifact["issues"]:
            marker = "BLOCK" if issue["blocking"] else "INFO"
            print(f"    {marker} {issue['kind']}: {issue['detail']}")
    stale_claims = report["stale_claims"]
    print("")
    print("stale in-progress claims:")
    print(
        f"  {stale_claims['status']}: "
        f"{stale_claims['summary']['in_progress_count']} in_progress, "
        f"{stale_claims['summary']['stale_count']} stale, "
        f"{stale_claims['summary']['missing_evidence_count']} missing evidence"
    )
    for item in stale_claims["items"]:
        print(
            f"  {item['classification']}: {item['bead_id']} "
            f"assignee={item['assignee'] or 'none'} "
            f"last_update={item['last_update'] or 'unknown'} "
            f"source={item['evidence_source']}"
        )
        print(f"    action: {item['recommended_operator_action']}")
    if report["blocking_issues"]:
        print("")
        print("release-facing claim blockers:")
        for issue in report["blocking_issues"]:
            print(f"  {issue['path']}: {issue['kind']}: {issue['detail']}")
            print(f"    remediation: {issue['remediation']}")


def write_artifact(
    repo_root: Path,
    relative_path: str,
    payload: dict[str, Any] | None,
    *,
    text: str | None = None,
    mtime: datetime | None = None,
) -> None:
    full_path = repo_root / relative_path
    full_path.parent.mkdir(parents=True, exist_ok=True)
    if payload is not None:
        full_path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    else:
        assert text is not None
        full_path.write_text(text, encoding="utf-8")
    if mtime is not None:
        ts = mtime.timestamp()
        os.utime(full_path, (ts, ts))


def fixture_payload(
    spec: EvidenceSpec,
    now: datetime,
    provenance: str,
) -> dict[str, Any] | None:
    if spec.path.endswith(".md"):
        return None

    payload: dict[str, Any] = {
        "generated_at": format_datetime(now),
        "correlation_id": provenance,
    }
    if spec.required_schema is not None:
        payload["schema"] = spec.required_schema
    if spec.status_path is not None:
        ok_value = spec.ok_values[0] if spec.ok_values else "pass"
        assign_path(payload, spec.status_path, ok_value)
    for zero_path in spec.zero_paths:
        assign_path(payload, zero_path, 0)
    if spec.id == "dropin_certification_verdict":
        payload["overall_verdict"] = "CERTIFIED"
    if spec.id == "dropin_contract":
        payload.pop("generated_at", None)
        payload["effective_date_utc"] = format_datetime(now)
        payload["status"] = "active_blocking_policy"
    return payload


def assign_path(payload: dict[str, Any], path: str, value: Any) -> None:
    current = payload
    parts = path.split(".")
    for part in parts[:-1]:
        next_value = current.get(part)
        if not isinstance(next_value, dict):
            next_value = {}
            current[part] = next_value
        current = next_value
    current[parts[-1]] = value


def make_complete_fixture(
    repo_root: Path,
    now: datetime,
    provenance: str = "fixture-run",
    skip_ids: set[str] | None = None,
) -> None:
    skip_ids = skip_ids or set()
    for spec in EVIDENCE_SPECS:
        if spec.id in skip_ids:
            continue
        payload = fixture_payload(spec, now, provenance)
        if payload is None:
            write_artifact(repo_root, spec.path, None, text=f"# {spec.id}\n", mtime=now)
        else:
            write_artifact(repo_root, spec.path, payload, mtime=now)


def write_beads_ledger(repo_root: Path, issues: list[dict[str, Any]]) -> None:
    ledger_path = repo_root / ".beads" / "issues.jsonl"
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    with ledger_path.open("w", encoding="utf-8") as handle:
        for issue in issues:
            handle.write(json.dumps(issue, sort_keys=True))
            handle.write("\n")


def write_activity_jsonl(
    repo_root: Path,
    relative_path: str,
    rows: list[dict[str, Any]],
) -> None:
    full_path = repo_root / relative_path
    full_path.parent.mkdir(parents=True, exist_ok=True)
    with full_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True))
            handle.write("\n")


def stale_claim_item(report: dict[str, Any], bead_id: str) -> dict[str, Any]:
    for item in report["stale_claims"]["items"]:
        if item["bead_id"] == bead_id:
            return item
    raise AssertionError(f"missing stale claim item for {bead_id}")


def assert_condition(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def run_self_test() -> int:
    now = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)
    stale = now - timedelta(days=30)

    try:
        repo_root = fixture_root()
        make_complete_fixture(repo_root, now)
        report = build_report(repo_root, now=now)
        assert_condition(report["overall_status"] == "ready", "fresh fixture should be ready")

        repo_root = fixture_root()
        make_complete_fixture(repo_root, now)
        payload = fixture_payload(EVIDENCE_SPECS[0], stale, "fixture-run")
        assert payload is not None
        write_artifact(repo_root, EVIDENCE_SPECS[0].path, payload, mtime=stale)
        report = build_report(repo_root, now=now)
        kinds = {issue["kind"] for issue in report["blocking_issues"]}
        assert_condition("stale" in kinds, "stale artifact should block gate mode")

        repo_root = fixture_root()
        make_complete_fixture(repo_root, now, skip_ids={"activity_ledger_digest"})
        report = build_report(repo_root, now=now)
        paths = {issue["path"] for issue in report["blocking_issues"]}
        assert_condition(
            "tests/full_suite_gate/swarm_activity_digest.json" in paths,
            "missing artifact should be reported with exact path",
        )

        repo_root = fixture_root()
        make_complete_fixture(repo_root, now)
        budget_path = "tests/perf/reports/budget_summary.json"
        payload = fixture_payload(EVIDENCE_SPECS[0], now, "fixture-run")
        assert payload is not None
        payload["ci_no_data"] = 2
        write_artifact(repo_root, budget_path, payload, mtime=now)
        report = build_report(repo_root, now=now)
        details = "\n".join(issue["detail"] for issue in report["blocking_issues"])
        assert_condition("ci_no_data=2" in details, "no-data budget summary should block")

        repo_root = fixture_root()
        make_complete_fixture(repo_root, now)
        payload = fixture_payload(EVIDENCE_SPECS[1], now, "other-run")
        assert payload is not None
        write_artifact(repo_root, EVIDENCE_SPECS[1].path, payload, mtime=now)
        report = build_report(repo_root, now=now)
        kinds = {issue["kind"] for issue in report["blocking_issues"]}
        assert_condition(
            "provenance_mismatch" in kinds,
            "mixed provenance should be reported",
        )

        repo_root = fixture_root()
        make_complete_fixture(repo_root, now)
        historical_path = "tests/ext_conformance/reports/journeys/journey_report.json"
        write_artifact(repo_root, historical_path, {"note": "old"}, mtime=stale)
        report = build_report(repo_root, now=now)
        blocker_paths = {issue["path"] for issue in report["blocking_issues"]}
        assert_condition(
            historical_path not in blocker_paths,
            "historical snapshots should not block release-facing gate status",
        )

        repo_root = fixture_root()
        make_complete_fixture(repo_root, now)
        write_beads_ledger(
            repo_root,
            [
                {
                    "id": "bd-active",
                    "title": "Fresh owner",
                    "status": "in_progress",
                    "assignee": "ActiveAgent",
                    "updated_at": format_datetime(now - timedelta(hours=1)),
                },
                {
                    "id": "bd-stale",
                    "title": "Old owner",
                    "status": "in_progress",
                    "assignee": "OldAgent",
                    "updated_at": format_datetime(now - timedelta(hours=30)),
                },
                {
                    "id": "bd-unassigned",
                    "title": "No owner",
                    "status": "in_progress",
                    "updated_at": format_datetime(now - timedelta(hours=30)),
                },
                {
                    "id": "bd-missing",
                    "title": "Missing updated_at",
                    "status": "in_progress",
                    "assignee": "MissingAgent",
                },
            ],
        )
        report = build_report(repo_root, now=now)
        stale_claims = report["stale_claims"]
        assert_condition(
            stale_claims["policy"] == "report_only_no_auto_reopen_or_reassign",
            "stale claim report must remain report-only",
        )
        assert_condition(
            stale_claim_item(report, "bd-active")["classification"] == "active",
            "recent in-progress work should be active",
        )
        stale_item = stale_claim_item(report, "bd-stale")
        assert_condition(
            stale_item["classification"] == "stale_needs_owner_follow_up",
            "old assigned in-progress work should request owner follow-up",
        )
        assert_condition(
            "message OldAgent" in stale_item["recommended_operator_action"],
            "assigned stale claim should include exact owner follow-up action",
        )
        unassigned_item = stale_claim_item(report, "bd-unassigned")
        assert_condition(
            unassigned_item["classification"] == "stale_unassigned",
            "old unassigned in-progress work should be reported separately",
        )
        assert_condition(
            "br update bd-unassigned --status open"
            in unassigned_item["recommended_operator_action"],
            "unassigned stale claim should include exact reopen command",
        )
        missing_item = stale_claim_item(report, "bd-missing")
        assert_condition(
            missing_item["classification"] == "missing_evidence",
            "missing updated_at should be missing evidence",
        )
        assert_condition(
            "do not reopen or reassign bd-missing"
            in missing_item["recommended_operator_action"],
            "missing evidence action should fail closed",
        )

        repo_root = fixture_root()
        make_complete_fixture(repo_root, now)
        write_beads_ledger(
            repo_root,
            [
                {
                    "id": "bd-coordinated",
                    "title": "Old bead with fresh mail",
                    "status": "in_progress",
                    "assignee": "MailAgent",
                    "updated_at": format_datetime(now - timedelta(hours=30)),
                },
            ],
        )
        activity_path = "tests/full_suite_gate/swarm_activity_events.jsonl"
        write_activity_jsonl(
            repo_root,
            activity_path,
            [
                {
                    "schema": "pi.swarm.activity_ledger.v1",
                    "kind": "agent_mail",
                    "timestamp_ms": int((now - timedelta(hours=2)).timestamp() * 1000),
                    "ids": {
                        "bead_id": "bd-coordinated",
                        "agent_name": "MailAgent",
                    },
                    "summary": "owner posted fresh status",
                },
            ],
        )
        report = build_report(
            repo_root,
            now=now,
            stale_claim_activity_fresh_hours=6,
            stale_claim_activity_paths=(activity_path,),
        )
        coordinated_item = stale_claim_item(report, "bd-coordinated")
        assert_condition(
            coordinated_item["classification"] == "active_recent_coordination",
            "fresh optional activity should keep an old bead active",
        )
        assert_condition(
            coordinated_item["evidence_source"].startswith(f"{activity_path}:1:agent_mail"),
            "activity-backed classification should name the evidence source",
        )

        report = build_report(repo_root, now=now, stale_claim_after_hours=48)
        assert_condition(
            stale_claim_item(report, "bd-coordinated")["classification"] == "active",
            "configured stale threshold should control bead-age classification",
        )
    except AssertionError as exc:
        print(f"SELF-TEST FAIL: {exc}")
        return 2

    print("SELF-TEST PASS")
    return 0


def fixture_root() -> Path:
    return Path(tempfile.mkdtemp(prefix="pi_claim_readiness_"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root to inspect",
    )
    parser.add_argument(
        "--max-age-days",
        type=int,
        default=DEFAULT_MAX_AGE_DAYS,
        help="freshness threshold for generated release-facing artifacts",
    )
    parser.add_argument(
        "--stale-claim-after-hours",
        type=int,
        default=DEFAULT_STALE_CLAIM_AFTER_HOURS,
        help="age threshold for reporting in-progress beads as stale",
    )
    parser.add_argument(
        "--stale-claim-activity-fresh-hours",
        type=int,
        default=DEFAULT_STALE_CLAIM_ACTIVITY_FRESH_HOURS,
        help="freshness window for optional Agent Mail or activity-ledger evidence",
    )
    parser.add_argument(
        "--stale-claim-activity-jsonl",
        action="append",
        default=None,
        help="optional repo-relative JSONL activity source with bead IDs and timestamps",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON report",
    )
    parser.add_argument(
        "--gate",
        action="store_true",
        help="exit 1 when release-facing claim evidence is not ready",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run fixture-backed reporter tests",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        return run_self_test()
    if args.stale_claim_after_hours < 0:
        print("ERROR: --stale-claim-after-hours must be non-negative", file=sys.stderr)
        return 2
    if args.stale_claim_activity_fresh_hours < 0:
        print("ERROR: --stale-claim-activity-fresh-hours must be non-negative", file=sys.stderr)
        return 2

    repo_root = args.repo_root.resolve()
    activity_paths = (
        tuple(args.stale_claim_activity_jsonl)
        if args.stale_claim_activity_jsonl is not None
        else DEFAULT_STALE_CLAIM_ACTIVITY_PATHS
    )
    report = build_report(
        repo_root,
        max_age_days=args.max_age_days,
        stale_claim_after_hours=args.stale_claim_after_hours,
        stale_claim_activity_fresh_hours=args.stale_claim_activity_fresh_hours,
        stale_claim_activity_paths=activity_paths,
    )
    if args.json:
        json.dump(report, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print_text_report(report)

    if args.gate and report["blocking_issue_count"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    with contextlib.suppress(BrokenPipeError):
        sys.exit(main())
