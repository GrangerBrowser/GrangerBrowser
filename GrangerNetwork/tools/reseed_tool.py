#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from granger_network.bootstrap import DEFAULT_NETWORK_ID, DEFAULT_PROTOCOL_VERSION
from granger_network.reseed import ReseedStore
from granger_network.wan_config import load_authority_pin


def _store(options: argparse.Namespace) -> ReseedStore:
    pins = tuple(load_authority_pin(path.resolve()) for path in options.authority_pin)
    return ReseedStore(
        options.store.resolve(),
        pins,
        network_id=options.network_id,
        protocol_version=options.protocol_version,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Import, inspect, or export signed Granger bootstrap/reseed bundles"
    )
    parser.add_argument("--store", type=Path, required=True)
    parser.add_argument("--authority-pin", type=Path, action="append", required=True)
    parser.add_argument("--network-id", default=DEFAULT_NETWORK_ID)
    parser.add_argument("--protocol-version", type=int, default=DEFAULT_PROTOCOL_VERSION)
    commands = parser.add_subparsers(dest="command", required=True)
    import_bundle = commands.add_parser("import")
    import_bundle.add_argument("--bundle", type=Path, required=True)
    import_bundle.add_argument("--source", default="manual")
    import_directory = commands.add_parser("import-directory")
    import_directory.add_argument("--directory", type=Path, required=True)
    commands.add_parser("list")
    export = commands.add_parser("export")
    export.add_argument("--destination", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    options = _build_parser().parse_args(argv)
    try:
        store = _store(options)
        if options.command == "import":
            result: object = store.import_path(
                options.bundle.resolve(),
                source=options.source,
            ).to_document()
        elif options.command == "import-directory":
            result = {
                "imports": [
                    item.to_document()
                    for item in store.import_directory(options.directory.resolve())
                ],
                "ok": True,
                "version": 1,
            }
        elif options.command == "export":
            result = {
                "exported": [str(path) for path in store.export_active(options.destination)],
                "ok": True,
                "version": 1,
            }
        else:
            result = {**store.diagnostics(), "ok": True}
        print(json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
        return 0
    except Exception as error:
        print(
            json.dumps(
                {"error": type(error).__name__, "ok": False},
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
