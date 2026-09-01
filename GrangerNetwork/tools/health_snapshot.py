#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from granger_network.health_snapshot import write_health_snapshot


def _value(path: Path | None) -> object:
    if path is None:
        return {}
    return json.loads(path.resolve().read_text(encoding="utf-8"))


def _document(path: Path | None) -> dict[str, object]:
    value = _value(path)
    if not isinstance(value, dict):
        raise ValueError("diagnostic source must be a JSON object")
    return value


def _peer_documents(path: Path | None) -> tuple[dict[str, object], ...]:
    value = _value(path)
    if isinstance(value, dict):
        value = value.get("peers", ())
    if not isinstance(value, (list, tuple)):
        raise ValueError("peer diagnostic source must be a JSON array")
    if any(not isinstance(item, dict) for item in value):
        raise ValueError("peer diagnostic entries must be JSON objects")
    return tuple(value)


def _network_document(path: Path | None) -> dict[str, object]:
    document = _document(path)
    nested = document.get("network")
    return nested if isinstance(nested, dict) else document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export a redacted Granger health snapshot")
    parser.add_argument("--generation", type=Path)
    parser.add_argument("--network", type=Path)
    parser.add_argument("--peers", type=Path)
    parser.add_argument("--routing", type=Path)
    parser.add_argument("--hosting", type=Path)
    parser.add_argument("--rendezvous", type=Path)
    parser.add_argument("--tor", type=Path)
    parser.add_argument("--i2p", type=Path)
    parser.add_argument("--resources", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--required-peers", type=int, default=4)
    parser.add_argument("--started-at", type=int, default=0)
    parser.add_argument("--source-version", default="")
    options = parser.parse_args(argv)
    try:
        snapshot = write_health_snapshot(
            options.output,
            generation=_document(options.generation),
            network=_network_document(options.network),
            peers=_peer_documents(options.peers),
            routing=_document(options.routing),
            hosting=_document(options.hosting),
            rendezvous=_document(options.rendezvous),
            tor=_document(options.tor),
            i2p=_document(options.i2p),
            resources=_document(options.resources),
            required_peers=options.required_peers,
            started_at=options.started_at,
            source_version=options.source_version,
        )
        print(json.dumps({
            "networkState": snapshot["network"]["state"],
            "ok": True,
            "output": str(options.output.resolve()),
            "version": snapshot["version"],
        }, ensure_ascii=True, sort_keys=True))
        return 0
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"error": type(error).__name__, "ok": False}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
