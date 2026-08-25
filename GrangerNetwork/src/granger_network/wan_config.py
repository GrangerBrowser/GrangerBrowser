from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ._codec import (
    atomic_write_text,
    decode_base64url,
    encode_base64url,
    parse_json_object,
)
from .address import normalize_name
from .bootstrap import BootstrapPool, BootstrapSet, PeerCache
from .errors import DiscoveryError
from .identity import ServiceIdentity
from .rendezvous_control import validate_service_id
from .wan_discovery import WanDiscoveryClient


@dataclass(frozen=True)
class WanDiscoveryRuntime:
    identity: ServiceIdentity
    bootstrap: BootstrapSet
    cache: PeerCache
    discovery: WanDiscoveryClient


@dataclass(frozen=True)
class BrowserWanConfig:
    bootstrap_path: Path
    authority_pin_path: Path
    alias_pins: dict[str, str]
    route_attempts: int
    replication_factor: int
    minimum_replicas: int
    timeout: float


def _config_member(root: Path, value: object, label: str) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise DiscoveryError(f"browser WAN {label} path is invalid")
    candidate = (root / value).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise DiscoveryError(f"browser WAN {label} path escapes its config root") from error
    if not candidate.is_file():
        raise DiscoveryError(f"browser WAN {label} file is unavailable")
    return candidate


def load_browser_wan_config(path: Path) -> BrowserWanConfig:
    source = Path(path).resolve()
    try:
        document = parse_json_object(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise DiscoveryError(f"browser WAN config is invalid: {error}") from error
    expected = {
        "aliasPins",
        "authorityPin",
        "bootstrap",
        "minimumReplicas",
        "replicationFactor",
        "routeAttempts",
        "timeoutSeconds",
        "version",
    }
    if set(document) != expected or document["version"] != 1:
        raise DiscoveryError("browser WAN config schema is unsupported")
    aliases = document["aliasPins"]
    if not isinstance(aliases, dict) or len(aliases) > 256:
        raise DiscoveryError("browser WAN alias pins are invalid")
    alias_pins: dict[str, str] = {}
    try:
        for alias, service_id in aliases.items():
            if not isinstance(alias, str) or not isinstance(service_id, str):
                raise DiscoveryError("browser WAN alias pin must contain text")
            alias_pins[normalize_name(alias)] = validate_service_id(service_id)
    except ValueError as error:
        raise DiscoveryError(f"browser WAN alias pin is invalid: {error}") from error
    route_attempts = document["routeAttempts"]
    replication_factor = document["replicationFactor"]
    minimum_replicas = document["minimumReplicas"]
    timeout = document["timeoutSeconds"]
    if (
        isinstance(route_attempts, bool)
        or not isinstance(route_attempts, int)
        or not 1 <= route_attempts <= 8
        or isinstance(replication_factor, bool)
        or not isinstance(replication_factor, int)
        or not 2 <= replication_factor <= 8
        or isinstance(minimum_replicas, bool)
        or not isinstance(minimum_replicas, int)
        or not 2 <= minimum_replicas <= replication_factor
        or isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not 1.0 <= float(timeout) <= 30.0
    ):
        raise DiscoveryError("browser WAN policy values are invalid")
    root = source.parent
    return BrowserWanConfig(
        _config_member(root, document["bootstrap"], "bootstrap"),
        _config_member(root, document["authorityPin"], "authority pin"),
        alias_pins,
        route_attempts,
        replication_factor,
        minimum_replicas,
        float(timeout),
    )


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
