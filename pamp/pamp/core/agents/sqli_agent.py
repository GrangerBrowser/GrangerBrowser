from __future__ import annotations

from typing import Any

from ..ffuf_discovery import normalize_base_url
from ..sqli_analysis import analyze_sqli, collect_parameter_candidates, SQLiConfig


def run_sqli_agent(
    target: str,
    domain_data: dict[str, Any] | None = None,
    discovery: dict[str, Any] | None = None,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    settings = SQLiConfig.from_mapping(config)
    domain_data = domain_data or {}
    discovery = discovery or {}
    http = domain_data.get("http") or {}
    base_url = normalize_base_url(http.get("final_url") or http.get("url") or target)
    candidates = collect_parameter_candidates(
        base_url,
        domain_data,
        discovery,
        settings,
    )
    result = analyze_sqli(target, domain_data=domain_data, discovery=discovery, config=settings)
    result["agent"] = {
        "name": "sqli_agent",
        "parameter_sources": _parameter_sources(candidates),
    }
    return result


def _parameter_sources(candidates: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for candidate in candidates:
        source = str(candidate.get("source") or "unknown")
        counts[source] = counts.get(source, 0) + 1
    return dict(sorted(counts.items()))
