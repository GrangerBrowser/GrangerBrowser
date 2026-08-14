from __future__ import annotations

from pathlib import Path
from typing import Any

from .ffuf_discovery import DiscoveryConfig, run_discovery


def run_discovery_engine(
    target: str,
    config: DiscoveryConfig | dict[str, Any] | None = None,
    wordlist_dir: str | Path | None = None,
) -> dict[str, Any]:
    return run_discovery(target, config=config, wordlist_dir=wordlist_dir)
