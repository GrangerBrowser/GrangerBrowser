from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ._codec import atomic_write_text, decode_base64url, encode_base64url
from .bootstrap import BootstrapPool, BootstrapSet, PeerCache
from .errors import DiscoveryError
from .identity import ServiceIdentity
from .wan_discovery import WanDiscoveryClient


@dataclass(frozen=True)
class WanDiscoveryRuntime:
    identity: ServiceIdentity
    bootstrap: BootstrapSet
    cache: PeerCache
    discovery: WanDiscoveryClient


def write_bootstrap_bundle(
    bootstrap: BootstrapSet,
    bootstrap_path: Path,
    authority_pin_path: Path,
) -> None:
    bootstrap.verify(bootstrap.authority_public_key)
    atomic_write_text(Path(bootstrap_path), bootstrap.to_json(), mode=0o644)
    atomic_write_text(
        Path(authority_pin_path),
        encode_base64url(bootstrap.authority_public_key) + "\n",
        mode=0o644,
    )


def load_authority_pin(path: Path) -> bytes:
    try:
        value = decode_base64url(Path(path).read_text(encoding="ascii").strip())
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise DiscoveryError(f"bootstrap authority pin is invalid: {error}") from error
    if len(value) != 32:
        raise DiscoveryError("bootstrap authority pin has an invalid length")
    return value


def load_or_create_identity(path: Path) -> ServiceIdentity:
    destination = Path(path)
    if destination.exists():
        return ServiceIdentity.load(destination)
    identity = ServiceIdentity.generate()
    identity.save(destination)
    return identity


def load_discovery_runtime(
    bootstrap_path: Path,
    authority_pin_path: Path,
    cache_path: Path,
    identity_path: Path,
    *,
    timeout: float = 5.0,
    replication_factor: int = 3,
    minimum_replicas: int = 2,
) -> WanDiscoveryRuntime:
    pin = load_authority_pin(authority_pin_path)
    bootstrap = BootstrapSet.from_json(
        Path(bootstrap_path).read_text(encoding="utf-8"),
        pin,
    )
    identity = load_or_create_identity(identity_path)
    cache = PeerCache(cache_path)
    pool = BootstrapPool(bootstrap, cache)
    discovery = WanDiscoveryClient(
        identity,
        pool,
        cache=cache,
        timeout=timeout,
        replication_factor=replication_factor,
        minimum_replicas=minimum_replicas,
    )
    return WanDiscoveryRuntime(identity, bootstrap, cache, discovery)
