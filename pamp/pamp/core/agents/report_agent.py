from __future__ import annotations

from typing import Any


def run_report_agent(domain_data: dict[str, Any] | None = None) -> dict[str, Any]:
    domain_data = domain_data or {}
    discovery = domain_data.get("discovery") or {}
    sqli = domain_data.get("sqli_analysis") or {}
    return {
        "agent": {"name": "report_agent", "role": "final local HTML report assembly"},
        "output": "output/report.html",
        "summary": {
            "security_findings": len(domain_data.get("security_findings") or []),
            "discovery_findings": len(discovery.get("findings") or []),
            "sqli_findings": len(sqli.get("findings") or []),
            "api_endpoints": len(domain_data.get("api_endpoints") or []),
        },
    }
