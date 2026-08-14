from __future__ import annotations

from .discovery_agent import discovery_endpoint_rows, run_discovery_agent


def run_ffuf_agent(*args, **kwargs):
    return run_discovery_agent(*args, **kwargs)
