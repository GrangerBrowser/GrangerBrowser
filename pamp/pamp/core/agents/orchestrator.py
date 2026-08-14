from __future__ import annotations

from copy import deepcopy
import traceback
from typing import Any

from .crawler_agent import run_crawler_agent
from .devtools_agent import run_devtools_agent
from .discovery_agent import discovery_endpoint_rows, run_discovery_agent
from .report_agent import run_report_agent
from .sqli_agent import run_sqli_agent
from .technology_agent import run_technology_agent


def run_orchestrator(
    target: str,
    domain_data: dict[str, Any] | None = None,
    config: dict[str, Any] | None = None,
    debug_log: Any | None = None,
) -> dict[str, Any]:
    domain_data = deepcopy(domain_data or {})
    config = config or {}
    steps = []

    crawler, step = _run_agent("crawler_agent", lambda: run_crawler_agent(domain_data), debug_log)
    steps.append(step)

    devtools, step = _run_agent("devtools_agent", lambda: run_devtools_agent(domain_data), debug_log)
    steps.append(step)

    technology, step = _run_agent("technology_agent", lambda: run_technology_agent(domain_data), debug_log)
    steps.append(step)

    discovery, step = _run_agent(
        "discovery_agent",
        lambda: run_discovery_agent(target, domain_data, config=config.get("discovery")),
        debug_log,
    )
    steps.append(step)

    discovery_endpoints = discovery_endpoint_rows(discovery)
    domain_data["api_endpoints"] = _merge_endpoint_rows(domain_data.get("api_endpoints") or [], discovery_endpoints)
    domain_data["discovery"] = discovery

    sqli, step = _run_agent(
        "sqli_analysis_agent",
        lambda: run_sqli_agent(target, domain_data, discovery, config=config.get("sqli")),
        debug_log,
    )
    domain_data["sqli_analysis"] = sqli
    steps.append(step)

    report, step = _run_agent("report_agent", lambda: run_report_agent(domain_data), debug_log)
    steps.append(step)

    return {
        "agent": {"name": "orchestrator", "role": "local Pamp agent workflow"},
        "target": target,
        "steps": steps,
        "crawler": crawler,
        "devtools": devtools,
        "technology": technology,
        "discovery": discovery,
        "discovery_endpoints": discovery_endpoints,
        "sqli_analysis": sqli,
        "report": report,
        "domain_updates": {
            "api_endpoints": domain_data.get("api_endpoints") or [],
            "discovery": discovery,
            "sqli_analysis": sqli,
            "agent_workflow": steps,
        },
    }


def _run_agent(agent: str, operation: Any, debug_log: Any | None) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        result = operation()
        if not isinstance(result, dict):
            raise TypeError(f"{agent} returned {type(result).__name__}, expected dict")
        return result, _step(agent, result.get("summary") or {})
    except Exception as exc:
        reason = f"{type(exc).__name__}: {exc}"
        if debug_log:
            try:
                debug_log(f"[ORCHESTRATOR][{agent}] {reason}\n{traceback.format_exc()}")
            except Exception:
                pass
        fallback = {
            "agent": {"name": agent},
            "status": "failed",
            "summary": {},
            "errors": [reason],
            "findings": [],
            "all_results": [],
        }
        return fallback, _step(agent, {}, status="failed", reason=reason)


def _step(
    agent: str,
    summary: dict[str, Any],
    *,
    status: str = "done",
    reason: str = "",
) -> dict[str, Any]:
    row = {"agent": agent, "status": status, "summary": summary}
    if reason:
        row["reason"] = reason
    return row


def _merge_endpoint_rows(existing: list[dict[str, Any]], new_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged = []
    seen = set()
    for row in list(existing or []) + list(new_rows or []):
        endpoint = str(row.get("endpoint") or "")
        method = str(row.get("method") or "")
        if not endpoint:
            continue
        key = f"{method}|{endpoint}"
        if key in seen:
            continue
        seen.add(key)
        merged.append(row)
    return merged[:350]
