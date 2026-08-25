from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path


NETWORK_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(NETWORK_ROOT / "src"))

from granger_network.bootstrap import BootstrapSet
from granger_network.identity import ServiceIdentity
from granger_network.peer import NodeDescriptor
from granger_network.wan_config import write_bootstrap_bundle


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create a pinned, signed Granger Network bootstrap bundle"
    )
    parser.add_argument("--authority-state", type=Path, required=True)
    parser.add_argument("--descriptor", type=Path, action="append", required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--authority-pin", type=Path, required=True)
    parser.add_argument("--lifetime", type=int, default=6 * 60 * 60)
    return parser


def main(argv: list[str] | None = None) -> int:
    options = _parser().parse_args(argv)
    if len(options.descriptor) < 2:
        raise SystemExit("at least two independent bootstrap descriptors are required")
    authority_path = options.authority_state.resolve()
    if authority_path.exists():
        authority = ServiceIdentity.load(authority_path)
    else:
        authority = ServiceIdentity.generate()
        authority.save(authority_path)
    peers = tuple(
        NodeDescriptor.from_json(path.resolve().read_text(encoding="utf-8"))
        for path in options.descriptor
    )
    now = int(time.time())
    remaining = min(peer.expires_at for peer in peers) - now
    if options.lifetime < 60 or options.lifetime > remaining:
        raise SystemExit(
            "bootstrap lifetime must be at least 60 seconds and cannot outlive "
            f"the shortest node descriptor ({remaining} seconds remaining)"
        )
    bootstrap = BootstrapSet.create(authority, peers, lifetime=options.lifetime)
    bundle_path = options.bundle.resolve()
    pin_path = options.authority_pin.resolve()
    write_bootstrap_bundle(bootstrap, bundle_path, pin_path)
    report = {
        "authorityPin": pin_path.read_text(encoding="ascii").strip(),
        "bundle": str(bundle_path),
        "bundleSha256": hashlib.sha256(bundle_path.read_bytes()).hexdigest().upper(),
        "expiresAt": bootstrap.expires_at,
        "peerCount": len(bootstrap.peers),
        "peerNodeIds": [peer.node_id for peer in bootstrap.peers],
        "version": 1,
    }
    print(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
