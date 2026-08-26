from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import time
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._codec import (
    atomic_write_text,
    canonical_json,
    decode_base64url,
    encode_base64url,
    parse_json_object,
)
from .address import normalize_name
from .bootstrap import BootstrapPool, BootstrapSet, PeerCache
from .errors import DiscoveryError
from .identity import ServiceIdentity
from .protocol import VERSION_3
from .rendezvous_control import validate_service_id
from .wan_discovery import WanDiscoveryClient


SIGNED_CONFIG_VERSION = 2
SIGNED_CONFIG_NETWORK_ID = "granger-network-v0.4"
SIGNED_CONFIG_SIGNATURE_DOMAIN = b"granger-network-v0.4/browser-wan-config\x00"
MAX_SIGNED_CONFIG_LIFETIME = 180 * 24 * 60 * 60
MAX_CONFIG_CLOCK_SKEW = 120
_MAX_GENERATION = 2**63 - 1
_SHA256_HEX_LENGTH = 64


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
    version: int = 1
    network_id: str = "development"
    protocol_version: int = VERSION_3
    generation: int = 0
    issued_at: int = 0
    expires_at: int = 0
    sha256: str = ""


def _read_document(path: Path, label: str) -> tuple[Path, bytes, dict[str, object]]:
    source = Path(path).resolve()
    try:
        content = source.read_bytes()
        document = parse_json_object(content.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise DiscoveryError(f"{label} is invalid: {error}") from error
    return source, content, document


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


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with Path(path).open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise DiscoveryError(f"browser WAN file could not be hashed: {error}") from error
    return digest.hexdigest()


def _validate_sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != _SHA256_HEX_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise DiscoveryError(f"browser WAN {label} SHA-256 is invalid")
    return value


def _load_public_pin(path: Path, label: str) -> bytes:
    try:
        value = decode_base64url(Path(path).read_text(encoding="ascii").strip())
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise DiscoveryError(f"{label} is invalid: {error}") from error
    if len(value) != 32:
        raise DiscoveryError(f"{label} has an invalid length")
    return value


def _validate_policy(document: dict[str, object]) -> tuple[dict[str, str], int, int, int, float]:
    aliases = document["aliasPins"]
    if not isinstance(aliases, dict) or len(aliases) > 256:
        raise DiscoveryError("browser WAN alias pins are invalid")
    alias_pins: dict[str, str] = {}
    try:
        for alias, service_id in aliases.items():
            if not isinstance(alias, str) or not isinstance(service_id, str):
                raise DiscoveryError("browser WAN alias pin must contain text")
            normalized = normalize_name(alias)
            if normalized in alias_pins:
                raise DiscoveryError("browser WAN alias pins contain a duplicate name")
            alias_pins[normalized] = validate_service_id(service_id)
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
    return alias_pins, route_attempts, replication_factor, minimum_replicas, float(timeout)


def _load_legacy_config(
    source: Path,
    content: bytes,
    document: dict[str, object],
) -> BrowserWanConfig:
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
    alias_pins, route_attempts, replication_factor, minimum_replicas, timeout = (
        _validate_policy(document)
    )
    root = source.parent
    return BrowserWanConfig(
        _config_member(root, document["bootstrap"], "bootstrap"),
        _config_member(root, document["authorityPin"], "authority pin"),
        alias_pins,
        route_attempts,
        replication_factor,
        minimum_replicas,
        timeout,
        sha256=hashlib.sha256(content).hexdigest(),
    )


def _load_rollback_state(path: Path | None) -> dict[str, object] | None:
    if path is None or not Path(path).exists():
        return None
    _source, _content, document = _read_document(Path(path), "browser WAN rollback state")
    if set(document) != {"configSha256", "generation", "networkId", "version"}:
        raise DiscoveryError("browser WAN rollback state schema is unsupported")
    generation = document["generation"]
    if (
        document["version"] != 1
        or document["networkId"] != SIGNED_CONFIG_NETWORK_ID
        or isinstance(generation, bool)
        or not isinstance(generation, int)
        or not 1 <= generation <= _MAX_GENERATION
    ):
        raise DiscoveryError("browser WAN rollback state is invalid")
    _validate_sha256(document["configSha256"], "rollback state")
    return document


def _enforce_rollback(config: BrowserWanConfig, rollback_state_path: Path | None) -> None:
    state = _load_rollback_state(rollback_state_path)
    if state is None:
        return
    highest = int(state["generation"])
    if config.generation < highest:
        raise DiscoveryError("browser WAN config rollback was rejected")
    if config.generation == highest and config.sha256 != state["configSha256"]:
        raise DiscoveryError("browser WAN config generation equivocation was rejected")


def _load_signed_config(
    source: Path,
    content: bytes,
    document: dict[str, object],
    trust_anchor_path: Path,
    rollback_state_path: Path | None,
    now: int | None,
) -> BrowserWanConfig:
    expected = {
        "aliasPins",
        "authorityPin",
        "authorityPinSha256",
        "bootstrap",
        "bootstrapSha256",
        "configAuthorityKey",
        "expiresAt",
        "generation",
        "issuedAt",
        "minimumReplicas",
        "networkId",
        "protocolVersion",
        "replicationFactor",
        "routeAttempts",
        "signature",
        "timeoutSeconds",
        "version",
    }
    if set(document) != expected or document["version"] != SIGNED_CONFIG_VERSION:
        raise DiscoveryError("signed browser WAN config schema is unsupported")
    if document["networkId"] != SIGNED_CONFIG_NETWORK_ID:
        raise DiscoveryError("signed browser WAN config network is unsupported")
    if document["protocolVersion"] != VERSION_3:
        raise DiscoveryError("signed browser WAN config protocol is unsupported")
    generation = document["generation"]
    issued_at = document["issuedAt"]
    expires_at = document["expiresAt"]
    if (
        isinstance(generation, bool)
        or not isinstance(generation, int)
        or not 1 <= generation <= _MAX_GENERATION
        or isinstance(issued_at, bool)
        or not isinstance(issued_at, int)
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, int)
        or issued_at < 0
        or expires_at <= issued_at
        or expires_at - issued_at > MAX_SIGNED_CONFIG_LIFETIME
    ):
        raise DiscoveryError("signed browser WAN config validity is invalid")
    current = int(time.time()) if now is None else now
    if issued_at > current + MAX_CONFIG_CLOCK_SKEW or expires_at <= current:
        raise DiscoveryError("signed browser WAN config is not currently valid")

    trust_anchor = _load_public_pin(trust_anchor_path, "browser WAN trust anchor")
    try:
        embedded_key = decode_base64url(document["configAuthorityKey"])
        signature = decode_base64url(document["signature"])
    except (TypeError, ValueError) as error:
        raise DiscoveryError("signed browser WAN config key or signature is invalid") from error
    if len(embedded_key) != 32 or embedded_key != trust_anchor or len(signature) != 64:
        raise DiscoveryError("signed browser WAN config authority does not match its trust anchor")
    unsigned = dict(document)
    del unsigned["signature"]
    try:
        Ed25519PublicKey.from_public_bytes(trust_anchor).verify(
            signature,
            SIGNED_CONFIG_SIGNATURE_DOMAIN + canonical_json(unsigned),
        )
    except (InvalidSignature, ValueError) as error:
        raise DiscoveryError("signed browser WAN config signature is invalid") from error

    alias_pins, route_attempts, replication_factor, minimum_replicas, timeout = (
        _validate_policy(document)
    )
    root = source.parent
    bootstrap = _config_member(root, document["bootstrap"], "bootstrap")
    authority_pin = _config_member(root, document["authorityPin"], "authority pin")
    expected_bootstrap_sha = _validate_sha256(document["bootstrapSha256"], "bootstrap")
    expected_pin_sha = _validate_sha256(document["authorityPinSha256"], "authority pin")
    if _sha256(bootstrap) != expected_bootstrap_sha:
        raise DiscoveryError("signed browser WAN bootstrap digest does not match")
    if _sha256(authority_pin) != expected_pin_sha:
        raise DiscoveryError("signed browser WAN authority pin digest does not match")
    bootstrap_pin = load_authority_pin(authority_pin)
    try:
        bootstrap_set = BootstrapSet.from_json(
            bootstrap.read_text(encoding="utf-8"),
            bootstrap_pin,
            now=current,
        )
    except (OSError, UnicodeDecodeError) as error:
        raise DiscoveryError(f"signed browser WAN bootstrap is unavailable: {error}") from error
    if issued_at < bootstrap_set.issued_at or expires_at > bootstrap_set.expires_at:
        raise DiscoveryError("signed browser WAN validity exceeds its bootstrap validity")

    result = BrowserWanConfig(
        bootstrap,
        authority_pin,
        alias_pins,
        route_attempts,
        replication_factor,
        minimum_replicas,
        timeout,
        version=SIGNED_CONFIG_VERSION,
        network_id=SIGNED_CONFIG_NETWORK_ID,
        protocol_version=VERSION_3,
        generation=generation,
        issued_at=issued_at,
        expires_at=expires_at,
        sha256=hashlib.sha256(content).hexdigest(),
    )
    _enforce_rollback(result, rollback_state_path)
    return result


def load_browser_wan_config(
    path: Path,
    *,
    trust_anchor_path: Path | None = None,
    rollback_state_path: Path | None = None,
    now: int | None = None,
    allow_legacy: bool = True,
) -> BrowserWanConfig:
    source, content, document = _read_document(Path(path), "browser WAN config")
    version = document.get("version")
    if version == 1:
        if not allow_legacy or trust_anchor_path is not None or rollback_state_path is not None:
            raise DiscoveryError("unsigned browser WAN config is not allowed in packaged mode")
        return _load_legacy_config(source, content, document)
    if version != SIGNED_CONFIG_VERSION or trust_anchor_path is None:
        raise DiscoveryError("browser WAN config schema is unsupported or untrusted")
    return _load_signed_config(
        source,
        content,
        document,
        Path(trust_anchor_path),
        rollback_state_path,
        now,
    )


def write_signed_browser_wan_config(
    path: Path,
    config_authority: ServiceIdentity,
    bootstrap_path: Path,
    authority_pin_path: Path,
    *,
    generation: int,
    issued_at: int | None = None,
    expires_at: int | None = None,
    alias_pins: dict[str, str] | None = None,
    route_attempts: int = 6,
    replication_factor: int = 6,
    minimum_replicas: int = 2,
    timeout_seconds: float = 8.0,
) -> None:
    destination = Path(path).resolve()
    root = destination.parent
    bootstrap = Path(bootstrap_path).resolve()
    authority_pin = Path(authority_pin_path).resolve()
    try:
        bootstrap_relative = bootstrap.relative_to(root).as_posix()
        authority_pin_relative = authority_pin.relative_to(root).as_posix()
    except ValueError as error:
        raise DiscoveryError("signed browser WAN members must be inside the bundle root") from error
    timestamp = int(time.time()) if issued_at is None else issued_at
    bootstrap_pin = load_authority_pin(authority_pin)
    bootstrap_set = BootstrapSet.from_json(
        bootstrap.read_text(encoding="utf-8"),
        bootstrap_pin,
        now=timestamp,
    )
    expiry = bootstrap_set.expires_at if expires_at is None else expires_at
    unsigned: dict[str, object] = {
        "aliasPins": {} if alias_pins is None else alias_pins,
        "authorityPin": authority_pin_relative,
        "authorityPinSha256": _sha256(authority_pin),
        "bootstrap": bootstrap_relative,
        "bootstrapSha256": _sha256(bootstrap),
        "configAuthorityKey": encode_base64url(config_authority.public_key_bytes),
        "expiresAt": expiry,
        "generation": generation,
        "issuedAt": timestamp,
        "minimumReplicas": minimum_replicas,
        "networkId": SIGNED_CONFIG_NETWORK_ID,
        "protocolVersion": VERSION_3,
        "replicationFactor": replication_factor,
        "routeAttempts": route_attempts,
        "timeoutSeconds": timeout_seconds,
        "version": SIGNED_CONFIG_VERSION,
    }
    signature = config_authority.sign(
        SIGNED_CONFIG_SIGNATURE_DOMAIN + canonical_json(unsigned)
    )
    document = dict(unsigned)
    document["signature"] = encode_base64url(signature)
    atomic_write_text(
        destination,
        json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        mode=0o644,
    )
    trust_anchor = root / "config-authority.pin"
    atomic_write_text(
        trust_anchor,
        encode_base64url(config_authority.public_key_bytes) + "\n",
        mode=0o644,
    )
    load_browser_wan_config(
        destination,
        trust_anchor_path=trust_anchor,
        now=timestamp,
        allow_legacy=False,
    )


class _ProvisionLock(AbstractContextManager[None]):
    def __init__(self, path: Path, timeout: float = 10.0) -> None:
        self.path = Path(path)
        self.timeout = timeout
        self.descriptor: int | None = None

    def __enter__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                self.descriptor = os.open(
                    self.path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                os.write(self.descriptor, f"{os.getpid()}\n".encode("ascii"))
                os.fsync(self.descriptor)
                return None
            except FileExistsError:
                try:
                    stale = time.time() - self.path.stat().st_mtime > 30.0
                except OSError:
                    stale = False
                if stale:
                    try:
                        self.path.unlink()
                    except OSError:
                        pass
                    continue
                if time.monotonic() >= deadline:
                    raise DiscoveryError("browser WAN provisioning lock timed out")
                time.sleep(0.05)

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self.descriptor is not None:
            os.close(self.descriptor)
            self.descriptor = None
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


def _active_config_path(install_root: Path) -> tuple[Path, int, str] | None:
    pointer_path = install_root / "active.json"
    if not pointer_path.exists():
        return None
    _source, _content, pointer = _read_document(pointer_path, "browser WAN active pointer")
    if set(pointer) != {"config", "configSha256", "generation", "version"}:
        raise DiscoveryError("browser WAN active pointer schema is unsupported")
    generation = pointer["generation"]
    if (
        pointer["version"] != 1
        or isinstance(generation, bool)
        or not isinstance(generation, int)
        or not 1 <= generation <= _MAX_GENERATION
    ):
        raise DiscoveryError("browser WAN active pointer is invalid")
    digest = _validate_sha256(pointer["configSha256"], "active pointer")
    config = _config_member(install_root, pointer["config"], "installed config")
    return config, generation, digest


def _install_bundle(
    bundle_path: Path,
    config: BrowserWanConfig,
    install_root: Path,
) -> Path:
    bundles_root = install_root / "bundles"
    bundles_root.mkdir(parents=True, exist_ok=True)
    destination = bundles_root / f"{config.generation:020d}-{config.sha256[:16]}"
    if not destination.exists():
        temporary = Path(tempfile.mkdtemp(prefix=".provision-", dir=bundles_root))
        try:
            _source, _content, document = _read_document(bundle_path, "browser WAN bundle")
            for member in (document["bootstrap"], document["authorityPin"]):
                if not isinstance(member, str):
                    raise DiscoveryError("browser WAN bundle member path is invalid")
                source = _config_member(bundle_path.parent, member, "bundle member")
                target = temporary / member
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
            shutil.copyfile(bundle_path, temporary / "browser-wan.json")
            os.replace(temporary, destination)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary, ignore_errors=True)
    return destination / "browser-wan.json"


def _write_activation_state(
    installed_config: Path,
    config: BrowserWanConfig,
    install_root: Path,
    rollback_state_path: Path,
) -> None:
    relative = installed_config.relative_to(install_root).as_posix()
    atomic_write_text(
        install_root / "active.json",
        json.dumps(
            {
                "config": relative,
                "configSha256": config.sha256,
                "generation": config.generation,
                "version": 1,
            },
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        mode=0o600,
    )
    atomic_write_text(
        rollback_state_path,
        json.dumps(
            {
                "configSha256": config.sha256,
                "generation": config.generation,
                "networkId": config.network_id,
                "version": 1,
            },
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        mode=0o600,
    )


def ensure_browser_wan_config(
    bundle_config_path: Path,
    trust_anchor_path: Path,
    install_root: Path,
    rollback_state_path: Path,
    *,
    now: int | None = None,
) -> Path:
    bundle_path = Path(bundle_config_path).resolve()
    trust_anchor = Path(trust_anchor_path).resolve()
    destination_root = Path(install_root).resolve()
    rollback_path = Path(rollback_state_path).resolve()
    destination_root.mkdir(parents=True, exist_ok=True)
    with _ProvisionLock(destination_root / ".provision.lock"):
        bundled = load_browser_wan_config(
            bundle_path,
            trust_anchor_path=trust_anchor,
            now=now,
            allow_legacy=False,
        )
        rollback = _load_rollback_state(rollback_path)
        active = _active_config_path(destination_root)
        if active is not None:
            active_path, active_generation, active_digest = active
            if active_generation > bundled.generation:
                raise DiscoveryError("browser WAN bundled config rollback was rejected")
            if active_generation == bundled.generation:
                installed = load_browser_wan_config(
                    active_path,
                    trust_anchor_path=trust_anchor,
                    rollback_state_path=rollback_path,
                    now=now,
                    allow_legacy=False,
                )
                if (
                    installed.generation != active_generation
                    or installed.sha256 != active_digest
                    or installed.sha256 != bundled.sha256
                ):
                    raise DiscoveryError("browser WAN config generation equivocation was rejected")
                return active_path
        if rollback is not None:
            highest = int(rollback["generation"])
            if bundled.generation < highest:
                raise DiscoveryError("browser WAN bundled config rollback was rejected")
            if bundled.generation == highest and bundled.sha256 != rollback["configSha256"]:
                raise DiscoveryError("browser WAN bundled config equivocation was rejected")

        installed_path = _install_bundle(bundle_path, bundled, destination_root)
        verified = load_browser_wan_config(
            installed_path,
            trust_anchor_path=trust_anchor,
            now=now,
            allow_legacy=False,
        )
        if verified.sha256 != bundled.sha256 or verified.generation != bundled.generation:
            raise DiscoveryError("installed browser WAN config does not match its signed bundle")
        _write_activation_state(installed_path, verified, destination_root, rollback_path)
        for candidate in (destination_root / "bundles").iterdir():
            if candidate.is_dir() and candidate != installed_path.parent:
                shutil.rmtree(candidate, ignore_errors=True)
        return installed_path


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
    return _load_public_pin(path, "bootstrap authority pin")


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
