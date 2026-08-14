from __future__ import annotations

import json
from pathlib import Path
import shutil
from typing import Any

from .models import ArtifactRecord, safe_filename_part, utc_now


ACTIVE_STATE_FILE = "active_case.json"
RESET_STATE_KEYS = {
    "current_domain": "",
    "active_domain": "",
    "domain_data": {},
    "current_ip": "",
    "ip_data": {},
    "current_findings": [],
    "current_artifacts": [],
    "current_domain_data": {},
    "current_report_data": {},
    "decoded_artifacts": [],
    "trackers": [],
    "technologies": [],
    "security_findings": [],
    "sensitive_files": [],
    "network_requests": [],
    "emails": [],
    "phones": [],
    "endpoints": [],
}


def reset_runtime_target_state(
    data_dir: Path,
    output_dir: Path,
    language: str = "ru",
) -> dict[str, Any]:
    old_state = load_active_state(data_dir)
    old_target = (
        old_state.get("target")
        or old_state.get("active_target")
        or old_state.get("current_target")
        or old_state.get("last_target")
        or "none"
    )
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    for name in ("report.html", "artifacts.json", "findings.json"):
        path = output_dir / name
        if path.exists():
            path.unlink()
    debug_path = output_dir / "debug.log"
    debug_path.write_text("", encoding="utf-8")
    state = {
        "target": "",
        "target_type": "",
        "last_action": "",
        "case_path": str(output_dir),
        "case_file": "",
        "report_path": str(output_dir / "report.html"),
        "debug_path": str(debug_path),
        "language": language,
        "started_at": utc_now(),
        "last_analysis": "none",
    }
    for key, default_value in RESET_STATE_KEYS.items():
        state[key] = default_value.copy() if isinstance(default_value, (dict, list)) else default_value
    write_active_state(data_dir, state)
    append_debug(output_dir, "\n".join([
        "[state] reset runtime state",
        f"[state] old target: {old_target}",
    ]))
    return state


def update_runtime_target_state(
    data_dir: Path,
    *,
    target: str,
    target_type: str,
    last_action: str,
    case_file: str | Path | None = None,
    report_path: str | Path | None = None,
    **updates: Any,
) -> dict[str, Any]:
    state = load_active_state(data_dir)
    state.update(
        {
            "target": target,
            "target_type": target_type,
            "last_action": last_action,
            "last_analysis": f"{target_type}: {target}",
        }
    )
    if case_file is not None:
        state["case_file"] = str(case_file)
    if report_path is not None:
        state["report_path"] = str(report_path)
    state.update(updates)
    write_active_state(data_dir, state)
    case_path = active_case_path(state)
    if case_path:
        append_debug(case_path, "\n".join([
            f"[state] new target: {target}",
            f"[state] target type: {target_type}",
            f"[state] case file: {state.get('case_file') or 'none'}",
            f"[state] report path: {state.get('report_path') or 'none'}",
        ]))
    return state


def start_domain_case(
    data_dir: Path,
    target: str,
    output_dir: Path | None = None,
    language: str = "ru",
) -> dict[str, Any]:
    case_path = (output_dir or (data_dir / "cases" / "active")).resolve()
    state = reset_runtime_target_state(data_dir, case_path, language=language)
    state = update_runtime_target_state(
        data_dir,
        target=target,
        target_type="domain",
        last_action="domain_analysis",
        report_path=case_path / "report.html",
    )
    append_debug(case_path, f"start analyze domain\ntarget={target}\nreport path={case_path / 'report.html'}")
    return state


def load_active_state(data_dir: Path) -> dict[str, Any]:
    path = data_dir / ACTIVE_STATE_FILE
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        case_path = Path(payload.get("case_path") or "")
        if case_path.exists():
            return payload
    except Exception:
        return {}
    return {}


def write_active_state(data_dir: Path, state: dict[str, Any]) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / ACTIVE_STATE_FILE).write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def update_active_state(data_dir: Path, **updates: Any) -> dict[str, Any]:
    state = load_active_state(data_dir)
    state.update(updates)
    write_active_state(data_dir, state)
    return state


def active_case_path(state: dict[str, Any]) -> Path | None:
    raw = state.get("case_path")
    if not raw:
        return None
    path = Path(raw)
    return path if path.exists() else None


def write_artifacts(case_path: Path, artifacts: list[ArtifactRecord]) -> Path:
    payload = [artifact.to_dict() for artifact in artifacts]
    path = case_path / "artifacts.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def load_artifacts(case_path: Path) -> list[ArtifactRecord]:
    path = case_path / "artifacts.json"
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    return [ArtifactRecord.from_dict(item) for item in payload if isinstance(item, dict)]


def write_findings(case_path: Path, payload: dict[str, Any]) -> Path:
    path = case_path / "findings.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def save_case_artifact(case_path: Path, artifact: ArtifactRecord) -> Path:
    path = case_path / f"{artifact.type}_{safe_filename_part(artifact.label)}.json"
    path.write_text(json.dumps(artifact.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def append_debug(case_path: Path, message: str) -> None:
    case_path.mkdir(parents=True, exist_ok=True)
    timestamp = utc_now()
    with (case_path / "debug.log").open("a", encoding="utf-8") as handle:
        handle.write(f"[{timestamp}] {message}\n")


def append_debug_json(case_path: Path, title: str, payload: Any) -> None:
    append_debug(
        case_path,
        f"{title}\n{json.dumps(payload, ensure_ascii=False, indent=2, default=str)}",
    )


def build_findings_payload(
    target: str,
    artifacts: list[ArtifactRecord],
) -> dict[str, Any]:
    domain_data = {}
    for artifact in artifacts:
        if artifact.type == "domain":
            domain_data = artifact.data
    return {
        "target": target,
        "generated_at": utc_now(),
        "artifact_count": len(artifacts),
        "security_findings": domain_data.get("security_findings") or [],
        "discovery": {
            "summary": (domain_data.get("discovery") or {}).get("summary") or {},
            "findings": (domain_data.get("discovery") or {}).get("findings") or [],
        },
        "sqli_analysis": {
            "summary": (domain_data.get("sqli_analysis") or {}).get("summary") or {},
            "findings": (domain_data.get("sqli_analysis") or {}).get("findings") or [],
            "interesting_parameters": (domain_data.get("sqli_analysis") or {}).get("interesting_parameters") or [],
        },
        "agent_workflow": domain_data.get("agent_workflow") or [],
        "decoded_classified_artifacts": domain_data.get("decoded_classified_artifacts") or [],
        "sensitive_public_files": (domain_data.get("sensitive_public_files") or {}).get("findings") or [],
        "api_endpoints": domain_data.get("api_endpoints") or [],
    }


def _clear_case_folder(case_path: Path, cases_dir: Path) -> None:
    _ensure_inside(case_path.resolve(), cases_dir)
    for child in case_path.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()


def _ensure_inside(path: Path, root: Path) -> None:
    path = path.resolve()
    root = root.resolve()
    if path != root and root not in path.parents:
        raise ValueError(f"Case path is outside cases directory: {path}")
