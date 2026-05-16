#!/usr/bin/env python3
"""Build a deterministic operator handoff invariant summary.

The summary is an advisory handoff artifact. It consumes already-captured
Beads, git, validation, evidence freshness, Agent Mail, RCH, and action-plan
signals and emits stable JSON plus Markdown. It does not mutate those sources.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


INPUT_SCHEMA = "pi.operator.handoff_summary_input.v1"
OUTPUT_SCHEMA = "pi.operator.handoff_summary.v1"
CONTRACT_SCHEMA = "pi.operator.handoff_summary_contract.v1"
FIXTURE_SCHEMA = "pi.operator.handoff_summary_fixtures.v1"
CONTRACT_PATH = Path("docs/contracts/operator-handoff-summary-contract.json")
FIXTURE_PATH = Path("tests/fixtures/operator_handoff_summary/scenarios.json")
STATUSES = ("clean", "watch", "blocked")
INVARIANT_STATUSES = ("pass", "warn", "block")
SENSITIVE_KEY_RE = re.compile(
    r"(?i)(authorization|bearer|body|cookie|key|password|prompt|secret|token|transcript)"
)
SENSITIVE_VALUE_RE = re.compile(
    r"(?i)\b(bearer\s+[A-Za-z0-9._~+/=-]+|"
    r"(?:api[_-]?key|authorization|password|secret|token)"
    r"\s*[:=]\s*[\"']?[^\"'\s,}]+)"
)


class HandoffError(Exception):
    """Raised when handoff input, fixtures, or contracts are not usable."""


def json_dumps(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise HandoffError(f"missing JSON file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise HandoffError(f"malformed JSON file {path}: {exc}") from exc


def as_object(value: Any, *, field: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise HandoffError(f"{field} must be an object")
    return value


def as_list(value: Any, *, field: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise HandoffError(f"{field} must be an array")
    return value


def int_value(value: Any, *, field: str) -> int:
    if value is None:
        return 0
    if isinstance(value, bool):
        raise HandoffError(f"{field} must be an integer, not bool")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and value.strip().lstrip("-").isdigit():
        result = int(value.strip())
    else:
        raise HandoffError(f"{field} must be an integer")
    return result


def string_list(value: Any, *, field: str) -> list[str]:
    return [str(item) for item in as_list(value, field=field) if str(item)]


def redact(value: Any, *, key: str = "", counter: dict[str, int] | None = None) -> Any:
    if counter is None:
        counter = {"redacted": 0}
    if key and SENSITIVE_KEY_RE.search(key):
        counter["redacted"] += 1
        return "[REDACTED]"
    if isinstance(value, dict):
        return {
            str(child_key): redact(child_value, key=str(child_key), counter=counter)
            for child_key, child_value in sorted(value.items(), key=lambda item: str(item[0]))
        }
    if isinstance(value, list):
        return [redact(item, counter=counter) for item in value]
    if isinstance(value, str):
        redacted = SENSITIVE_VALUE_RE.sub("[REDACTED]", value)
        if redacted != value:
            counter["redacted"] += 1
        return redacted
    return value


def normalize_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, int]]:
    if not isinstance(payload, dict):
        raise HandoffError("input payload must be an object")
    schema = payload.get("schema")
    if schema not in (None, INPUT_SCHEMA):
        raise HandoffError(f"unsupported input schema: {schema}")
    redaction_counter = {"redacted": 0}
    payload = redact(payload, counter=redaction_counter)

    project = as_object(payload.get("project"), field="project")
    git = as_object(payload.get("git"), field="git")
    validation = as_object(payload.get("validation"), field="validation")
    evidence = as_object(payload.get("evidence_freshness"), field="evidence_freshness")
    agent_mail = as_object(payload.get("agent_mail"), field="agent_mail")
    rch = as_object(payload.get("rch"), field="rch")
    action_plan = as_object(payload.get("action_plan"), field="action_plan")
    beads = as_object(payload.get("beads"), field="beads")

    return (
        {
            "schema": INPUT_SCHEMA,
            "project": {
                "name": str(project.get("name") or "pi_agent_rust"),
                "root": str(project.get("root") or "/data/projects/pi_agent_rust"),
            },
            "git": {
                "branch": str(git.get("branch") or "unknown"),
                "head": str(git.get("head") or "unknown"),
                "upstream": str(git.get("upstream") or ""),
                "ahead": int_value(git.get("ahead"), field="git.ahead"),
                "behind": int_value(git.get("behind"), field="git.behind"),
                "dirty_files": sorted(string_list(git.get("dirty_files"), field="git.dirty_files")),
                "untracked_files": sorted(string_list(git.get("untracked_files"), field="git.untracked_files")),
                "recent_commits": normalize_records(git.get("recent_commits"), "git.recent_commits"),
            },
            "beads": {
                "ready": normalize_records(beads.get("ready"), "beads.ready"),
                "in_progress": normalize_records(beads.get("in_progress"), "beads.in_progress"),
                "closed_recent": normalize_records(beads.get("closed_recent"), "beads.closed_recent"),
                "stalled_candidates": normalize_records(
                    beads.get("stalled_candidates"), "beads.stalled_candidates"
                ),
            },
            "validation": {
                "status": str(validation.get("status") or "unknown"),
                "gates": normalize_records(validation.get("gates"), "validation.gates"),
            },
            "evidence_freshness": {
                "status": str(evidence.get("status") or "unknown"),
                "stale_artifacts": normalize_records(
                    evidence.get("stale_artifacts"), "evidence_freshness.stale_artifacts"
                ),
            },
            "agent_mail": {
                "health": str(agent_mail.get("health") or "unknown"),
                "semantic_readiness": str(agent_mail.get("semantic_readiness") or "unknown"),
                "reservations": normalize_records(
                    agent_mail.get("reservations"), "agent_mail.reservations"
                ),
                "ack_required": normalize_records(
                    agent_mail.get("ack_required"), "agent_mail.ack_required"
                ),
            },
            "rch": {
                "status": str(rch.get("status") or "unknown"),
                "active_jobs": normalize_records(rch.get("active_jobs"), "rch.active_jobs"),
            },
            "action_plan": {
                "decisions": normalize_records(
                    action_plan.get("decisions"), "action_plan.decisions"
                ),
            },
        },
        redaction_counter,
    )


def normalize_records(value: Any, field: str) -> list[dict[str, Any]]:
    records = []
    for index, item in enumerate(as_list(value, field=field)):
        record = as_object(item, field=f"{field}[{index}]")
        records.append(
            {str(key): record[key] for key in sorted(record.keys(), key=str)}
        )
    return records


def invariant(invariant_id: str, status: str, summary: str, evidence: list[str]) -> dict[str, Any]:
    if status not in INVARIANT_STATUSES:
        raise HandoffError(f"invalid invariant status {status}")
    return {
        "id": invariant_id,
        "status": status,
        "summary": summary,
        "evidence": evidence,
    }


def build_invariants(payload: dict[str, Any]) -> list[dict[str, Any]]:
    git = payload["git"]
    validation = payload["validation"]
    evidence = payload["evidence_freshness"]
    agent_mail = payload["agent_mail"]
    rch = payload["rch"]
    action_plan = payload["action_plan"]
    dirty_count = len(git["dirty_files"]) + len(git["untracked_files"])
    expired_reservations = [
        item
        for item in agent_mail["reservations"]
        if str(item.get("status") or "").lower() == "expired"
    ]
    open_decisions = [
        item
        for item in action_plan["decisions"]
        if str(item.get("status") or "").lower() not in ("closed", "resolved", "done")
    ]
    return [
        invariant(
            "git_worktree_clean",
            "pass" if dirty_count == 0 else "warn",
            "Worktree is clean" if dirty_count == 0 else f"{dirty_count} worktree path(s) need attention",
            git["dirty_files"] + git["untracked_files"],
        ),
        invariant(
            "git_pushed",
            "pass" if git["ahead"] == 0 and git["behind"] == 0 else "warn",
            "HEAD matches upstream"
            if git["ahead"] == 0 and git["behind"] == 0
            else f"ahead={git['ahead']} behind={git['behind']}",
            [git["head"], git["upstream"]],
        ),
        invariant(
            "validation_gates",
            "pass" if validation["status"] == "pass" else "block",
            f"validation status={validation['status']}",
            [str(gate.get("id") or gate.get("name") or "unnamed") for gate in validation["gates"]],
        ),
        invariant(
            "evidence_freshness",
            "pass" if evidence["status"] == "fresh" else "block",
            f"evidence freshness={evidence['status']}",
            [str(item.get("path") or item.get("id") or "unknown") for item in evidence["stale_artifacts"]],
        ),
        invariant(
            "agent_mail_usable",
            "pass" if agent_mail["health"] in ("green", "ok") else "warn",
            f"agent mail health={agent_mail['health']} semantic={agent_mail['semantic_readiness']}",
            [str(item.get("id") or item.get("subject") or "ack_required") for item in agent_mail["ack_required"]],
        ),
        invariant(
            "reservations_current",
            "pass" if not expired_reservations else "warn",
            "No expired reservations" if not expired_reservations else f"{len(expired_reservations)} expired reservation(s)",
            [str(item.get("path") or item.get("path_pattern") or item.get("id")) for item in expired_reservations],
        ),
        invariant(
            "rch_available",
            "pass" if rch["status"] in ("ok", "green") else "warn",
            f"rch status={rch['status']}",
            [str(item.get("id") or item.get("command") or "active_job") for item in rch["active_jobs"]],
        ),
        invariant(
            "action_plan_decisions",
            "pass" if not open_decisions else "warn",
            "No open action-plan decisions"
            if not open_decisions
            else f"{len(open_decisions)} open action-plan decision(s)",
            [str(item.get("id") or item.get("decision") or "open_decision") for item in open_decisions],
        ),
    ]


def derive_status(invariants: list[dict[str, Any]]) -> str:
    if any(item["status"] == "block" for item in invariants):
        return "blocked"
    if any(item["status"] == "warn" for item in invariants):
        return "watch"
    return "clean"


def build_safe_next_actions(payload: dict[str, Any], invariants: list[dict[str, Any]]) -> list[str]:
    status_by_id = {item["id"]: item for item in invariants}
    actions = []
    if status_by_id["validation_gates"]["status"] == "block":
        actions.append("Fix or rerun the failed validation gates before claiming more implementation work.")
    if status_by_id["evidence_freshness"]["status"] == "block":
        actions.append("Renew stale or missing evidence before relying on release or drop-in claims.")
    if status_by_id["git_worktree_clean"]["status"] == "warn":
        actions.append("Inspect and preserve dirty worktree paths before editing overlapping files.")
    if status_by_id["git_pushed"]["status"] == "warn":
        actions.append("Push or rebase local commits so the handoff does not strand work locally.")
    if status_by_id["reservations_current"]["status"] == "warn":
        actions.append("Refresh or release expired reservations before treating ownership as current.")
    if status_by_id["agent_mail_usable"]["status"] == "warn":
        actions.append("Use Beads comments as the coordination record until Agent Mail is healthy.")
    if status_by_id["rch_available"]["status"] == "warn":
        actions.append("Wait for RCH pressure to clear or use a smaller validation proof.")
    if status_by_id["action_plan_decisions"]["status"] == "warn":
        actions.append("Resolve open action-plan decisions before starting the dependent operator lane.")
    if not actions:
        ready = payload["beads"]["ready"]
        if ready:
            actions.append(f"Claim the next ready bead: {ready[0].get('id', 'unknown')}.")
        else:
            actions.append("Capture fresh triage with bv/br before starting new work.")
    return actions


def build_must_not_touch(payload: dict[str, Any], invariants: list[dict[str, Any]]) -> list[str]:
    git = payload["git"]
    items = []
    for path in git["dirty_files"] + git["untracked_files"]:
        items.append(f"Do not overwrite dirty path without ownership: {path}")
    for reservation in payload["agent_mail"]["reservations"]:
        if str(reservation.get("status") or "").lower() == "active":
            holder = reservation.get("holder") or reservation.get("agent") or "unknown"
            path = reservation.get("path") or reservation.get("path_pattern") or "unknown"
            items.append(f"Do not edit reserved path {path} held by {holder}")
    if any(item["id"] == "validation_gates" and item["status"] == "block" for item in invariants):
        items.append("Do not claim validation is green until failed gates pass.")
    if any(item["id"] == "evidence_freshness" and item["status"] == "block" for item in invariants):
        items.append("Do not make strict release/drop-in claims from stale evidence.")
    return items or ["No additional protected paths beyond repo instructions and active Beads ownership."]


def build_gates(payload: dict[str, Any]) -> list[dict[str, str]]:
    gates = []
    for gate in payload["validation"]["gates"]:
        gates.append(
            {
                "id": str(gate.get("id") or gate.get("name") or "unnamed"),
                "status": str(gate.get("status") or "unknown"),
                "evidence": str(gate.get("evidence") or gate.get("evidence_path") or ""),
            }
        )
    return gates


def render_markdown(output: dict[str, Any]) -> str:
    lines = [
        "# Operator Handoff Summary",
        "",
        f"- Status: {output['status']}",
        f"- Project: {output['project']['name']}",
        f"- Branch: {output['git']['branch']}",
        f"- Head: {output['git']['head']}",
        f"- Generated: {output['generated_at']}",
        "",
        "## What Changed",
    ]
    closed = output["beads"]["closed_recent"]
    if closed:
        for item in closed:
            lines.append(f"- {item.get('id', 'unknown')}: {item.get('title', 'untitled')}")
    else:
        lines.append("- No recently closed beads were provided.")
    lines.extend(["", "## Safe Next Actions"])
    lines.extend(f"- {item}" for item in output["safe_next_actions"])
    lines.extend(["", "## Must Not Touch"])
    lines.extend(f"- {item}" for item in output["must_not_touch"])
    lines.extend(["", "## Gates"])
    if output["gates_proving_claim"]:
        lines.extend(
            f"- {gate['id']}: {gate['status']} {gate['evidence']}".rstrip()
            for gate in output["gates_proving_claim"]
        )
    else:
        lines.append("- No validation gates were provided.")
    lines.extend(["", "## Open Action-Plan Decisions"])
    open_decisions = output["open_action_plan_decisions"]
    if open_decisions:
        for item in open_decisions:
            lines.append(f"- {item.get('id', 'unknown')}: {item.get('decision', 'unknown')}")
    else:
        lines.append("- None.")
    lines.extend(["", "## Invariants"])
    lines.extend(
        f"- {item['id']}: {item['status']} - {item['summary']}"
        for item in output["invariants"]
    )
    return "\n".join(lines) + "\n"


def evaluate(payload: dict[str, Any], *, generated_at: str) -> dict[str, Any]:
    normalized, redaction_counter = normalize_payload(payload)
    invariants = build_invariants(normalized)
    status = derive_status(invariants)
    open_decisions = [
        item
        for item in normalized["action_plan"]["decisions"]
        if str(item.get("status") or "").lower() not in ("closed", "resolved", "done")
    ]
    output = {
        "schema": OUTPUT_SCHEMA,
        "generated_at": generated_at,
        "status": status,
        "purpose": "operator_handoff_invariant_summary",
        "project": normalized["project"],
        "git": normalized["git"],
        "beads": normalized["beads"],
        "source_statuses": {
            "git": "dirty" if normalized["git"]["dirty_files"] or normalized["git"]["untracked_files"] else "clean",
            "validation": normalized["validation"]["status"],
            "evidence_freshness": normalized["evidence_freshness"]["status"],
            "agent_mail": normalized["agent_mail"]["health"],
            "rch": normalized["rch"]["status"],
            "action_plan": "open_decisions" if open_decisions else "clear",
        },
        "invariants": invariants,
        "safe_next_actions": build_safe_next_actions(normalized, invariants),
        "must_not_touch": build_must_not_touch(normalized, invariants),
        "gates_proving_claim": build_gates(normalized),
        "open_action_plan_decisions": open_decisions,
        "redaction_summary": {
            "redacted_fields": redaction_counter["redacted"],
            "raw_sensitive_values_retained": False,
        },
        "guardrails": {
            "read_only_summary": True,
            "no_source_mutation": True,
            "no_git_mutation": True,
            "no_beads_mutation": True,
            "no_agent_mail_mutation": True,
            "output_overwrite_refusal": True,
        },
    }
    output["markdown"] = render_markdown(output)
    return output


def load_fixture(fixture_id: str, *, repo_root: Path) -> dict[str, Any]:
    fixture = load_json(repo_root / FIXTURE_PATH)
    if fixture.get("schema") != FIXTURE_SCHEMA:
        raise HandoffError(f"invalid fixture schema in {FIXTURE_PATH}")
    for scenario in fixture.get("scenarios", []):
        if isinstance(scenario, dict) and scenario.get("id") == fixture_id:
            input_payload = scenario.get("input")
            if not isinstance(input_payload, dict):
                raise HandoffError(f"fixture {fixture_id} has invalid input")
            return input_payload
    known = ", ".join(
        sorted(str(item.get("id")) for item in fixture.get("scenarios", []) if isinstance(item, dict))
    )
    raise HandoffError(f"unknown fixture id {fixture_id!r}; known fixtures: {known}")


def assert_contract(output: dict[str, Any], *, repo_root: Path) -> None:
    contract = load_json(repo_root / CONTRACT_PATH)
    if contract.get("schema") != CONTRACT_SCHEMA:
        raise HandoffError(f"invalid contract schema in {CONTRACT_PATH}")
    for key in contract["required_top_level_keys"]:
        if key not in output:
            raise HandoffError(f"contract violation: missing output key {key}")
    if output["status"] not in contract["allowed_statuses"]:
        raise HandoffError(f"contract violation: unsupported status {output['status']}")
    for guard in contract["required_true_guardrails"]:
        if output["guardrails"].get(guard) is not True:
            raise HandoffError(f"contract violation: guardrail {guard} is not true")
    invariant_ids = {item["id"] for item in output["invariants"]}
    for invariant_id in contract["required_invariants"]:
        if invariant_id not in invariant_ids:
            raise HandoffError(f"contract violation: missing invariant {invariant_id}")


def assert_expected(
    output: dict[str, Any],
    expected: dict[str, Any],
    *,
    fixture_id: str,
) -> None:
    if output["status"] != expected.get("status"):
        raise HandoffError(f"{fixture_id}: expected status {expected.get('status')}, got {output['status']}")
    for text in expected.get("markdown_contains", []):
        if text not in output["markdown"]:
            raise HandoffError(f"{fixture_id}: markdown missing {text!r}")
    for text in expected.get("json_not_contains", []):
        if text in json_dumps(output):
            raise HandoffError(f"{fixture_id}: sensitive text leaked: {text!r}")
    for invariant_id, status in expected.get("invariants", {}).items():
        matches = [item for item in output["invariants"] if item["id"] == invariant_id]
        if not matches or matches[0]["status"] != status:
            raise HandoffError(
                f"{fixture_id}: expected invariant {invariant_id}={status}"
            )


def self_test(*, repo_root: Path, generated_at: str) -> dict[str, Any]:
    fixture = load_json(repo_root / FIXTURE_PATH)
    if fixture.get("schema") != FIXTURE_SCHEMA:
        raise HandoffError(f"invalid fixture schema in {FIXTURE_PATH}")
    results = []
    for scenario in fixture.get("scenarios", []):
        fixture_id = str(scenario.get("id"))
        output = evaluate(scenario["input"], generated_at=generated_at)
        assert_contract(output, repo_root=repo_root)
        assert_expected(output, scenario.get("expected", {}), fixture_id=fixture_id)
        results.append(
            {
                "id": fixture_id,
                "status": output["status"],
                "invariant_count": len(output["invariants"]),
                "redacted_fields": output["redaction_summary"]["redacted_fields"],
            }
        )
    return {
        "schema": "pi.operator.handoff_summary_self_test.v1",
        "generated_at": generated_at,
        "status": "pass",
        "scenario_count": len(results),
        "scenarios": results,
    }


def write_output(path: Path, text: str) -> None:
    if path.exists():
        raise HandoffError(f"refusing to overwrite existing output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build an operator handoff summary.")
    parser.add_argument("--input-json", type=Path, help="Input snapshot JSON")
    parser.add_argument("--fixture-id", help="Run a named fixture scenario")
    parser.add_argument("--out-json", type=Path, help="Write JSON output")
    parser.add_argument("--out-md", type=Path, help="Write Markdown output")
    parser.add_argument("--generated-at", help="Override generated_at timestamp")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    parser.add_argument("--markdown", action="store_true", help="Print Markdown output")
    parser.add_argument("--self-test", action="store_true", help="Run fixture self-test")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve()
    generated_at = args.generated_at or utc_now_iso()
    try:
        if args.self_test:
            payload = self_test(repo_root=repo_root, generated_at=generated_at)
            if args.out_json:
                write_output(args.out_json, json_dumps(payload))
            if args.json or not args.out_json:
                sys.stdout.write(json_dumps(payload))
            return 0
        if args.fixture_id:
            input_payload = load_fixture(args.fixture_id, repo_root=repo_root)
        elif args.input_json:
            input_payload = load_json(args.input_json)
        else:
            raise HandoffError("provide --input-json, --fixture-id, or --self-test")
        output = evaluate(input_payload, generated_at=generated_at)
        assert_contract(output, repo_root=repo_root)
        if args.out_json:
            write_output(args.out_json, json_dumps(output))
        if args.out_md:
            write_output(args.out_md, output["markdown"])
        if args.markdown:
            sys.stdout.write(output["markdown"])
        elif args.json or not (args.out_json or args.out_md):
            sys.stdout.write(json_dumps(output))
        return 0
    except HandoffError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
