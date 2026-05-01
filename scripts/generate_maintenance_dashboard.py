#!/usr/bin/env python3
"""Generate the operator maintenance dashboard artifact.

The dashboard tracks the weekly burn-down inputs that matter for release
resilience: open critical/high parity-ledger gaps, open Beads work, and the
current drop-in hard-gate verdict trend.
"""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "pi.operations.maintenance_dashboard.v1"
DEFAULT_OUTPUT = Path("docs/evidence/maintenance-dashboard.json")
LEDGER_CANDIDATES = (
    Path("docs/evidence/dropin-parity-gap-ledger.json"),
    Path("docs/dropin-parity-gap-ledger.json"),
)
VERDICT_CANDIDATES = (
    Path("docs/evidence/dropin-certification-verdict.json"),
    Path("docs/dropin-certification-verdict.json"),
)
JSON_DECODER = json.JSONDecoder()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root. Defaults to this script's parent repository.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Dashboard output path, relative to repo root unless absolute.",
    )
    parser.add_argument(
        "--generated-at",
        help="Override generated_at_utc for deterministic tests.",
    )
    return parser.parse_args()


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def resolve_existing(repo_root: Path, candidates: tuple[Path, ...]) -> Path:
    for candidate in candidates:
        path = repo_root / candidate
        if path.exists():
            return path
    return repo_root / candidates[0]


def parse_json_value(payload: str, context: str) -> Any:
    try:
        return JSON_DECODER.decode(payload)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{context}: invalid JSON: {exc}") from exc


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return parse_json_value(path.read_text(encoding="utf-8"), str(path))


def read_issues(path: Path) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if not path.exists():
        return issues
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        record = parse_json_value(stripped, f"{path}:{line_number}: invalid JSONL record")
        if isinstance(record, dict):
            issues.append(record)
    return issues


def git_metadata_dir(repo_root: Path) -> Path | None:
    git_path = repo_root / ".git"
    if git_path.is_dir():
        return git_path
    if git_path.is_file():
        try:
            gitdir_line = git_path.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        prefix = "gitdir: "
        if gitdir_line.startswith(prefix):
            gitdir = Path(gitdir_line[len(prefix) :])
            return gitdir if gitdir.is_absolute() else (repo_root / gitdir).resolve()
    return None


def read_packed_ref(git_dir: Path, ref_name: str) -> str | None:
    packed_refs = git_dir / "packed-refs"
    if not packed_refs.exists():
        return None
    try:
        lines = packed_refs.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "^")):
            continue
        parts = stripped.split(" ", 1)
        if len(parts) == 2 and parts[1] == ref_name:
            return parts[0]
    return None


def git_commit(repo_root: Path) -> str:
    if os.environ.get("GITHUB_SHA"):
        return os.environ["GITHUB_SHA"]
    git_dir = git_metadata_dir(repo_root)
    if git_dir is None:
        return "unknown"
    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return "unknown"
    ref_prefix = "ref: "
    if not head.startswith(ref_prefix):
        return head or "unknown"
    ref_name = head[len(ref_prefix) :]
    try:
        ref_value = (git_dir / ref_name).read_text(encoding="utf-8").strip()
    except OSError:
        ref_value = read_packed_ref(git_dir, ref_name)
    return ref_value or "unknown"


def is_open_ledger_gap(entry: dict[str, Any]) -> bool:
    if entry.get("severity") not in {"critical", "high"}:
        return False
    retired_values = {"retired", "resolved", "closed"}
    status = str(entry.get("status", "")).lower()
    mismatch_kind = str(entry.get("mismatch_kind", "")).lower()
    return status not in retired_values and mismatch_kind not in retired_values


def summarize_ledger(ledger: dict[str, Any]) -> dict[str, Any]:
    entries = [entry for entry in ledger.get("entries", []) if isinstance(entry, dict)]
    open_gaps = [entry for entry in entries if is_open_ledger_gap(entry)]
    by_severity = Counter(str(entry.get("severity", "unknown")) for entry in open_gaps)
    by_area = Counter(str(entry.get("area", "unknown")) for entry in open_gaps)
    return {
        "open_critical_high_count": len(open_gaps),
        "open_by_severity": dict(sorted(by_severity.items())),
        "open_by_area": dict(sorted(by_area.items())),
        "open_gaps": [
            {
                "gap_id": entry.get("gap_id"),
                "severity": entry.get("severity"),
                "area": entry.get("area"),
                "status": entry.get("status"),
                "owner_issue_primary": entry.get("owner_issue_primary"),
            }
            for entry in sorted(open_gaps, key=lambda e: str(e.get("gap_id", "")))
        ],
    }


def summarize_beads(issues: list[dict[str, Any]]) -> dict[str, Any]:
    by_status = Counter(str(issue.get("status", "unknown")) for issue in issues)
    open_issues = [issue for issue in issues if issue.get("status") == "open"]
    in_progress = [issue for issue in issues if issue.get("status") == "in_progress"]
    open_by_priority = Counter(str(issue.get("priority", "unknown")) for issue in open_issues)
    open_by_type = Counter(str(issue.get("issue_type", "unknown")) for issue in open_issues)
    return {
        "total_count": len(issues),
        "by_status": dict(sorted(by_status.items())),
        "open_count": len(open_issues),
        "in_progress_count": len(in_progress),
        "open_by_priority": dict(sorted(open_by_priority.items())),
        "open_by_type": dict(sorted(open_by_type.items())),
        "open_high_priority": [
            {
                "id": issue.get("id"),
                "priority": issue.get("priority"),
                "title": issue.get("title"),
                "labels": issue.get("labels", []),
            }
            for issue in sorted(
                open_issues,
                key=lambda i: (int(i.get("priority", 99)), str(i.get("id", ""))),
            )
            if int(issue.get("priority", 99)) <= 1
        ],
    }


def summarize_verdict(verdict: dict[str, Any]) -> dict[str, Any]:
    gates = verdict.get("hard_gate_results", [])
    if not isinstance(gates, list):
        gates = []
    status_counts = Counter(str(gate.get("status", "unknown")) for gate in gates if isinstance(gate, dict))
    blocking_not_pass = [
        {
            "gate_id": gate.get("gate_id"),
            "status": gate.get("status"),
            "detail": gate.get("detail"),
            "artifact_path": gate.get("artifact_path"),
            "bead": gate.get("bead"),
        }
        for gate in gates
        if isinstance(gate, dict) and gate.get("blocking") and gate.get("status") != "pass"
    ]
    return {
        "overall_verdict": verdict.get("overall_verdict", "unknown"),
        "generated_at_utc": verdict.get("generated_at_utc"),
        "git_commit": verdict.get("git_commit"),
        "hard_gate_count": len(gates),
        "hard_gate_status_counts": dict(sorted(status_counts.items())),
        "blocking_not_pass": blocking_not_pass,
    }


def update_trend_history(
    existing_dashboard: dict[str, Any],
    generated_at: str,
    ledger_summary: dict[str, Any],
    bead_summary: dict[str, Any],
    verdict_summary: dict[str, Any],
) -> list[dict[str, Any]]:
    snapshot = {
        "date_utc": generated_at[:10],
        "open_critical_high_ledger_gaps": ledger_summary["open_critical_high_count"],
        "open_beads": bead_summary["open_count"],
        "in_progress_beads": bead_summary["in_progress_count"],
        "overall_verdict": verdict_summary["overall_verdict"],
        "hard_gate_status_counts": verdict_summary["hard_gate_status_counts"],
    }
    history = existing_dashboard.get("trend_history", [])
    if not isinstance(history, list):
        history = []
    history = [
        item for item in history if isinstance(item, dict) and item.get("date_utc") != snapshot["date_utc"]
    ]
    history.append(snapshot)
    return history[-26:]


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    output_path = args.output if args.output.is_absolute() else repo_root / args.output
    generated_at = args.generated_at or os.environ.get("GENERATED_AT_UTC") or utc_now()

    ledger_path = resolve_existing(repo_root, LEDGER_CANDIDATES)
    verdict_path = resolve_existing(repo_root, VERDICT_CANDIDATES)
    issues_path = repo_root / ".beads" / "issues.jsonl"

    ledger = read_json(ledger_path, {"entries": []})
    verdict = read_json(verdict_path, {"hard_gate_results": []})
    issues = read_issues(issues_path)
    existing_dashboard = read_json(output_path, {})

    ledger_summary = summarize_ledger(ledger)
    bead_summary = summarize_beads(issues)
    verdict_summary = summarize_verdict(verdict)

    dashboard = {
        "schema": SCHEMA,
        "generated_at_utc": generated_at,
        "git_commit": git_commit(repo_root),
        "source_files": {
            "ledger": str(ledger_path.relative_to(repo_root)),
            "beads": str(issues_path.relative_to(repo_root)),
            "verdict": str(verdict_path.relative_to(repo_root)),
        },
        "metrics": {
            "ledger": ledger_summary,
            "beads": bead_summary,
            "hard_gates": verdict_summary,
        },
        "trend_history": update_trend_history(
            existing_dashboard,
            generated_at,
            ledger_summary,
            bead_summary,
            verdict_summary,
        ),
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(dashboard, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        display_path = output_path.relative_to(repo_root)
    except ValueError:
        display_path = output_path
    print(f"Wrote {display_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
