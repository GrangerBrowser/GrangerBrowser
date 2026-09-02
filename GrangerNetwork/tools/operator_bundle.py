#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from granger_network.bootstrap import (
    DEFAULT_NETWORK_ID,
    DEFAULT_PROTOCOL_VERSION,
    BootstrapSet,
)
from granger_network.identity import ServiceIdentity
from granger_network.peer import NodeDescriptor
from granger_network.wan_config import (
    load_browser_wan_config,
    write_bootstrap_bundle,
    write_signed_browser_wan_config,
)


class BundleLifetimeError(ValueError):
    def __init__(self, state: str, remaining_seconds: int) -> None:
        super().__init__(state)
        self.state = state
        self.remaining_seconds = remaining_seconds


def _remaining_seconds(value: str) -> int:
    try:
        result = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("remaining lifetime must be an integer") from error
    if not 0 <= result <= 7 * 24 * 60 * 60:
        raise argparse.ArgumentTypeError("remaining lifetime must be between 0 and 604800")
    return result


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def _identity(path: Path) -> ServiceIdentity:
    if path.exists():
        return ServiceIdentity.load(path)
    identity = ServiceIdentity.generate()
    identity.save(path)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return identity


def _separate_roots(private_root: Path, public_root: Path) -> None:
    if (
        private_root == public_root
        or private_root.is_relative_to(public_root)
        or public_root.is_relative_to(private_root)
    ):
        raise ValueError("private authority state and public bundle roots must be separate")


def create_bundle(options: argparse.Namespace) -> dict[str, object]:
    private_root = options.private_root.resolve()
    public_root = options.public_root.resolve()
    _separate_roots(private_root, public_root)
    if len(options.descriptor) < 2:
        raise ValueError("at least two independent bootstrap descriptors are required")
    private_root.mkdir(parents=True, exist_ok=True)
    public_root.mkdir(parents=True, exist_ok=True)
    try:
        private_root.chmod(0o700)
        public_root.chmod(0o755)
    except OSError:
        pass
    descriptors = tuple(
        NodeDescriptor.from_json(
            path.resolve().read_text(encoding="utf-8"),
            expected_network_id=DEFAULT_NETWORK_ID,
            expected_protocol_version=DEFAULT_PROTOCOL_VERSION,
        )
        for path in options.descriptor
    )
    now = int(time.time())
    remaining = min(descriptor.expires_at for descriptor in descriptors) - now
    if options.lifetime < 60 or options.lifetime > remaining:
        raise ValueError(
            "bundle lifetime must be at least 60 seconds and cannot outlive "
            f"the shortest node descriptor ({remaining} seconds remaining)"
        )
    bootstrap_authority = _identity(private_root / "bootstrap-authority.json")
    config_authority = _identity(private_root / "config-authority.json")
    bootstrap = BootstrapSet.create(
        bootstrap_authority,
        descriptors,
        network_id=DEFAULT_NETWORK_ID,
        protocol_version=DEFAULT_PROTOCOL_VERSION,
        generation=options.generation,
        issued_at=now,
        lifetime=options.lifetime,
    )
    bootstrap_path = public_root / "bootstrap-set.json"
    bootstrap_pin_path = public_root / "bootstrap-authority.pin"
    write_bootstrap_bundle(bootstrap, bootstrap_path, bootstrap_pin_path)
    config_path = public_root / "browser-wan.json"
    write_signed_browser_wan_config(
        config_path,
        config_authority,
        bootstrap_path,
        bootstrap_pin_path,
        generation=options.generation,
        issued_at=now,
        expires_at=bootstrap.expires_at,
        route_attempts=options.route_attempts,
        replication_factor=options.replication_factor,
        minimum_replicas=options.minimum_replicas,
        timeout_seconds=options.timeout_seconds,
    )
    config_pin_path = public_root / "config-authority.pin"
    config = load_browser_wan_config(
        config_path,
        trust_anchor_path=config_pin_path,
        allow_legacy=False,
    )
    public_files = (
        bootstrap_path,
        bootstrap_pin_path,
        config_path,
        config_pin_path,
    )
    if any(b"privateKey" in path.read_bytes() for path in public_files):
        raise ValueError("public bundle contains private key material")
    report = {
        "bootstrapGeneration": bootstrap.generation,
        "bootstrapPeers": [descriptor.node_id for descriptor in bootstrap.peers],
        "browserConfigSha256": config.sha256.upper(),
        "expiresAt": bootstrap.expires_at,
        "files": {
            path.name: {"sha256": _sha256(path), "sizeBytes": path.stat().st_size}
            for path in public_files
        },
        "networkId": bootstrap.network_id,
        "ok": True,
        "privateKeysPublished": False,
        "protocolVersion": bootstrap.protocol_version,
        "version": 1,
    }
    manifest = public_root / "bootstrap-manifest.json"
    manifest.write_text(
        json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    try:
        manifest.chmod(0o644)
    except OSError:
        pass
    return report


def verify_bundle(options: argparse.Namespace) -> dict[str, object]:
    root = options.public_root.resolve()
    config_path = root / "browser-wan.json"
    config_pin_path = root / "config-authority.pin"
    now = int(time.time())
    try:
        unsigned_expiry = json.loads(config_path.read_text(encoding="utf-8"))["expiresAt"]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise ValueError("browser WAN lifetime metadata is invalid") from error
    if isinstance(unsigned_expiry, bool) or not isinstance(unsigned_expiry, int):
        raise ValueError("browser WAN lifetime metadata is invalid")
    if unsigned_expiry <= now:
        raise BundleLifetimeError("EXPIRED", unsigned_expiry - now)
    config = load_browser_wan_config(
        config_path,
        trust_anchor_path=config_pin_path,
        allow_legacy=False,
    )
    remaining = config.expires_at - now
    if remaining <= 0:
        raise BundleLifetimeError("EXPIRED", remaining)
    if remaining < options.minimum_remaining_seconds:
        raise BundleLifetimeError("EXPIRING_SOON", remaining)
    files = (
        root / "bootstrap-set.json",
        root / "bootstrap-authority.pin",
        config_path,
        config_pin_path,
    )
    if any(b"privateKey" in path.read_bytes() for path in files):
        raise ValueError("public bundle contains private key material")
    return {
        "configSha256": config.sha256.upper(),
        "expiresAt": config.expires_at,
        "files": {path.name: _sha256(path) for path in files},
        "generation": config.generation,
        "issuedAt": config.issued_at,
        "lifetimeState": "VALID",
        "networkId": config.network_id,
        "ok": True,
        "privateKeysPublished": False,
        "protocolVersion": config.protocol_version,
        "remainingSeconds": remaining,
        "version": 1,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create or verify a public Granger bootstrap and browser WAN bundle"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--private-root", type=Path, required=True)
    create.add_argument("--public-root", type=Path, required=True)
    create.add_argument("--descriptor", type=Path, action="append", required=True)
    create.add_argument("--generation", type=int, required=True)
    create.add_argument("--lifetime", type=int, default=6 * 60 * 60)
    create.add_argument("--route-attempts", type=int, default=6)
    create.add_argument("--replication-factor", type=int, default=3)
    create.add_argument("--minimum-replicas", type=int, default=2)
    create.add_argument("--timeout-seconds", type=float, default=8.0)
    verify = commands.add_parser("verify")
    verify.add_argument("--public-root", type=Path, required=True)
    verify.add_argument(
        "--minimum-remaining-seconds",
        type=_remaining_seconds,
        default=0,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    options = _build_parser().parse_args(argv)
    try:
        report = create_bundle(options) if options.command == "create" else verify_bundle(options)
        print(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True))
        return 0
    except Exception as error:
        failure = {"error": type(error).__name__, "ok": False}
        if isinstance(error, BundleLifetimeError):
            failure.update(
                {
                    "lifetimeState": error.state,
                    "remainingSeconds": error.remaining_seconds,
                }
            )
        print(
            json.dumps(
                failure,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
