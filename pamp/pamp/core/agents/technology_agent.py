from __future__ import annotations

from typing import Any


def run_technology_agent(domain_data: dict[str, Any] | None = None) -> dict[str, Any]:
    domain_data = domain_data or {}
    technologies = sorted({str(item) for item in domain_data.get("detected_technologies") or [] if str(item).strip()})
    trackers = sorted({str(item) for item in domain_data.get("analytics_tracker_hints") or [] if str(item).strip()})
    headers = domain_data.get("security_headers") or {}
    return {
        "agent": {"name": "technology_agent", "role": "technology and header fingerprint summary"},
        "technologies": technologies[:200],
        "trackers": trackers[:200],
        "server": (domain_data.get("http") or {}).get("server") or "",
        "powered_by": (domain_data.get("http") or {}).get("x_powered_by") or "",
        "security_headers": headers,
        "summary": {
            "technologies": len(technologies),
            "trackers": len(trackers),
            "headers": len(headers),
        },
    }
