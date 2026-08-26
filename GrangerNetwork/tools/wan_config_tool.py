#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from granger_network.identity import ServiceIdentity
from granger_network.wan_config import (
    load_browser_wan_config,
    write_signed_browser_wan_config,
)


def _verify(config_path: Path, trust_anchor_path: Path) -> dict[str, object]:
    config_path = config_path.resolve()
    trust_anchor_path = trust_anchor_path.resolve()
    config = load_browser_wan_config(
        config_path,
        trust_anchor_path=trust_anchor_path,
        allow_legacy=False,
    )
    root = config_path.parent
    return {
        "authorityPin": config.authority_pin_path.relative_to(root).as_posix(),
        "bootstrap": config.bootstrap_path.relative_to(root).as_posix(),
        "config": config_path.name,
        "configSha256": config.sha256,
        "expiresAt": config.expires_at,
        "generation": config.generation,
        "issuedAt": config.issued_at,
        "networkId": config.network_id,
        "ok": True,
        "protocolVersion": config.protocol_version,
        "trustAnchor": trust_anchor_path.name,
        "version": config.version,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sign or verify a Granger WAN release bundle")
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--config", type=Path, required=True)
    verify.add_argument("--trust-anchor", type=Path, required=True)
    sign = commands.add_parser("sign")
    sign.add_argument("--config", type=Path, required=True)
    sign.add_argument("--config-authority-identity", type=Path, required=True)
    sign.add_argument("--bootstrap", type=Path, required=True)
    sign.add_argument("--authority-pin", type=Path, required=True)
    sign.add_argument("--generation", type=int, required=True)
    sign.add_argument("--issued-at", type=int, default=0)
    sign.add_argument("--expires-at", type=int, default=0)
    sign.add_argument("--route-attempts", type=int, default=6)
    sign.add_argument("--replication-factor", type=int, default=6)
    sign.add_argument("--minimum-replicas", type=int, default=2)
    sign.add_argument("--timeout-seconds", type=float, default=8.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    options = _build_parser().parse_args(argv)
    try:
        if options.command == "sign":
            identity = ServiceIdentity.load(options.config_authority_identity)
            write_signed_browser_wan_config(
                options.config,
                identity,
                options.bootstrap,
                options.authority_pin,
                generation=options.generation,
                issued_at=options.issued_at or int(time.time()),
                expires_at=options.expires_at or None,
                route_attempts=options.route_attempts,
                replication_factor=options.replication_factor,
                minimum_replicas=options.minimum_replicas,
                timeout_seconds=options.timeout_seconds,
            )
        print(
            json.dumps(
                _verify(options.config, options.config.parent / "config-authority.pin")
                if options.command == "sign"
                else _verify(options.config, options.trust_anchor),
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
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
