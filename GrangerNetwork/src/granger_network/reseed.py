from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ._codec import atomic_write_text, canonical_json, parse_json_object
from .binary import BinaryReader, BinaryWriter
from .bootstrap import BootstrapSet, DEFAULT_NETWORK_ID, DEFAULT_PROTOCOL_VERSION
from .errors import DiscoveryError, ProtocolError


MAX_RESEED_AUTHORITIES = 8
MAX_RESEED_BUNDLES_PER_AUTHORITY = 4
MAX_RESEED_BUNDLE_BYTES = 4 * 1024 * 1024
MAX_ACTIVE_RESEED_GENERATIONS_PER_AUTHORITY = 2
MAX_RESEED_TRANSPORT_CHUNK_BYTES = 64 * 1024
MAX_RESEED_TRANSPORT_ADVERTISEMENTS = MAX_RESEED_AUTHORITIES * 2


@dataclass(frozen=True)
class ReseedImportResult:
    authority_id: str
    generation: int
    sha256: str
    installed: bool

    def to_document(self) -> dict[str, object]:
        return {
            "authorityId": self.authority_id,
            "generation": self.generation,
            "installed": self.installed,
            "sha256": self.sha256,
            "version": 1,
        }


@dataclass(frozen=True)
class ReseedAdvertisement:
    authority_public_key: bytes
    generation: int
    sha256: str
    expires_at: int
    size: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.authority_public_key, bytes)
            or len(self.authority_public_key) != 32
            or isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or not 1 <= self.generation <= 2**63 - 1
            or not isinstance(self.sha256, str)
            or len(self.sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.sha256)
            or isinstance(self.expires_at, bool)
            or not isinstance(self.expires_at, int)
            or self.expires_at < 0
            or isinstance(self.size, bool)
            or not isinstance(self.size, int)
            or not 1 <= self.size <= MAX_RESEED_BUNDLE_BYTES
        ):
            raise ProtocolError("reseed advertisement is invalid")


def encode_reseed_advertisements(
    advertisements: Iterable[ReseedAdvertisement],
) -> bytes:
    selected = tuple(advertisements)
    if len(selected) > MAX_RESEED_TRANSPORT_ADVERTISEMENTS:
        raise ProtocolError("reseed advertisement count exceeds its limit")
    writer = BinaryWriter(32 * 1024).u8(len(selected))
    for advertisement in selected:
        advertisement.__post_init__()
        writer.fixed(advertisement.authority_public_key, 32)
        writer.u64(advertisement.generation)
        writer.fixed(bytes.fromhex(advertisement.sha256), 32)
        writer.u64(advertisement.expires_at)
        writer.u32(advertisement.size)
    return writer.build()


def decode_reseed_advertisements(content: bytes) -> tuple[ReseedAdvertisement, ...]:
    reader = BinaryReader(content, 32 * 1024)
    count = reader.u8()
    if count > MAX_RESEED_TRANSPORT_ADVERTISEMENTS:
        raise ProtocolError("reseed advertisement count exceeds its limit")
    result: list[ReseedAdvertisement] = []
    seen: set[tuple[bytes, int]] = set()
    for _ in range(count):
        advertisement = ReseedAdvertisement(
            reader.fixed(32),
            reader.u64(),
            reader.fixed(32).hex(),
            reader.u64(),
            reader.u32(),
        )
        key = (advertisement.authority_public_key, advertisement.generation)
        if key in seen:
            raise ProtocolError("reseed advertisement repeats a generation")
        seen.add(key)
        result.append(advertisement)
    reader.finish()
    return tuple(result)


def encode_reseed_chunk_request(sha256: str, offset: int) -> bytes:
    if (
        not isinstance(sha256, str)
        or len(sha256) != 64
        or any(character not in "0123456789abcdef" for character in sha256)
        or isinstance(offset, bool)
        or not isinstance(offset, int)
        or not 0 <= offset < MAX_RESEED_BUNDLE_BYTES
    ):
        raise ProtocolError("reseed chunk request is invalid")
    return BinaryWriter(40).fixed(bytes.fromhex(sha256), 32).u32(offset).build()


def decode_reseed_chunk_request(content: bytes) -> tuple[str, int]:
    reader = BinaryReader(content, 40)
    digest = reader.fixed(32).hex()
    offset = reader.u32()
    reader.finish()
    if offset >= MAX_RESEED_BUNDLE_BYTES:
        raise ProtocolError("reseed chunk offset exceeds its limit")
    return digest, offset


def encode_reseed_chunk_response(
    sha256: str,
    offset: int,
    total_size: int,
    content: bytes,
) -> bytes:
    if (
        not isinstance(sha256, str)
        or len(sha256) != 64
        or any(character not in "0123456789abcdef" for character in sha256)
        or isinstance(offset, bool)
        or not isinstance(offset, int)
        or not 0 <= offset < MAX_RESEED_BUNDLE_BYTES
        or isinstance(total_size, bool)
        or not isinstance(total_size, int)
        or not 1 <= total_size <= MAX_RESEED_BUNDLE_BYTES
        or not isinstance(content, bytes)
        or not 1 <= len(content) <= MAX_RESEED_TRANSPORT_CHUNK_BYTES
        or offset + len(content) > total_size
    ):
        raise ProtocolError("reseed chunk response is invalid")
    return (
        BinaryWriter(MAX_RESEED_TRANSPORT_CHUNK_BYTES + 48)
        .fixed(bytes.fromhex(sha256), 32)
        .u32(offset)
        .u32(total_size)
        .bytes_u32(content, MAX_RESEED_TRANSPORT_CHUNK_BYTES)
        .build()
    )


def decode_reseed_chunk_response(content: bytes) -> tuple[str, int, int, bytes]:
    reader = BinaryReader(content, MAX_RESEED_TRANSPORT_CHUNK_BYTES + 48)
    digest = reader.fixed(32).hex()
    offset = reader.u32()
    total_size = reader.u32()
    chunk = reader.bytes_u32(MAX_RESEED_TRANSPORT_CHUNK_BYTES)
    reader.finish()
    if (
        not 1 <= total_size <= MAX_RESEED_BUNDLE_BYTES
        or offset >= total_size
        or offset + len(chunk) > total_size
        or not chunk
    ):
        raise ProtocolError("reseed chunk response is invalid")
    return digest, offset, total_size, chunk


def _authority_id(public_key: bytes) -> str:
    return hashlib.sha256(b"granger-network/reseed-authority\x00" + public_key).hexdigest()[:24]


class ReseedStore:
    """Atomic signed bootstrap rotation store with per-authority rollback state."""

    def __init__(
        self,
        root: Path,
        authority_pins: Iterable[bytes],
        *,
        network_id: str = DEFAULT_NETWORK_ID,
        protocol_version: int = DEFAULT_PROTOCOL_VERSION,
    ) -> None:
        pins = tuple(dict.fromkeys(authority_pins))
        if (
            not 1 <= len(pins) <= MAX_RESEED_AUTHORITIES
            or any(not isinstance(pin, bytes) or len(pin) != 32 for pin in pins)
        ):
            raise DiscoveryError("reseed trust anchors are invalid")
        self.root = Path(root)
        self.authority_pins = pins
        self.network_id = network_id
        self.protocol_version = protocol_version
        self._lock = threading.Lock()

    @property
    def state_path(self) -> Path:
        return self.root / "state.json"

    @property
    def bundles_root(self) -> Path:
        return self.root / "bundles"

    def _load_state_unlocked(self) -> dict[str, dict[str, object]]:
        if not self.state_path.exists():
            return {}
        try:
            document = parse_json_object(self.state_path.read_text(encoding="utf-8"))
            if set(document) != {"authorities", "networkId", "protocolVersion", "version"}:
                raise ValueError("unexpected reseed state fields")
            version = document["version"]
            if (
                version not in {1, 2}
                or document["networkId"] != self.network_id
                or document["protocolVersion"] != self.protocol_version
                or not isinstance(document["authorities"], dict)
                or len(document["authorities"]) > MAX_RESEED_AUTHORITIES
            ):
                raise ValueError("reseed state policy mismatch")
            result: dict[str, dict[str, object]] = {}
            for authority_id, state in document["authorities"].items():
                expected_fields = (
                    {"generation", "sha256"}
                    if version == 1
                    else {"accepted", "generation", "sha256"}
                )
                if (
                    not isinstance(authority_id, str)
                    or len(authority_id) != 24
                    or any(character not in "0123456789abcdef" for character in authority_id)
                    or not isinstance(state, dict)
                    or set(state) != expected_fields
                    or isinstance(state["generation"], bool)
                    or not isinstance(state["generation"], int)
                    or not 1 <= state["generation"] <= 2**63 - 1
                    or not isinstance(state["sha256"], str)
                    or len(state["sha256"]) != 64
                    or any(character not in "0123456789abcdef" for character in state["sha256"])
                ):
                    raise ValueError("reseed authority state is invalid")
                accepted = (
                    [{"generation": state["generation"], "sha256": state["sha256"]}]
                    if version == 1
                    else state["accepted"]
                )
                if (
                    not isinstance(accepted, list)
                    or not 1 <= len(accepted) <= MAX_RESEED_BUNDLES_PER_AUTHORITY
                ):
                    raise ValueError("reseed accepted history is invalid")
                normalized: list[dict[str, object]] = []
                generations: set[int] = set()
                for item in accepted:
                    if (
                        not isinstance(item, dict)
                        or set(item) != {"generation", "sha256"}
                        or isinstance(item["generation"], bool)
                        or not isinstance(item["generation"], int)
                        or not 1 <= item["generation"] <= state["generation"]
                        or item["generation"] in generations
                        or not isinstance(item["sha256"], str)
                        or len(item["sha256"]) != 64
                        or any(
                            character not in "0123456789abcdef"
                            for character in item["sha256"]
                        )
                    ):
                        raise ValueError("reseed accepted history entry is invalid")
                    generations.add(item["generation"])
                    normalized.append(dict(item))
                normalized.sort(key=lambda item: int(item["generation"]), reverse=True)
                if (
                    normalized[0]["generation"] != state["generation"]
                    or normalized[0]["sha256"] != state["sha256"]
                ):
                    raise ValueError("reseed accepted history does not match its high-water mark")
                result[authority_id] = {
                    "accepted": normalized,
                    "generation": state["generation"],
                    "sha256": state["sha256"],
                }
            return result
        except (OSError, TypeError, ValueError) as error:
            raise DiscoveryError(f"reseed rollback state is invalid: {error}") from error

    def _write_state_unlocked(self, state: dict[str, dict[str, object]]) -> None:
        atomic_write_text(
            self.state_path,
            json.dumps(
                {
                    "authorities": state,
                    "networkId": self.network_id,
                    "protocolVersion": self.protocol_version,
                    "version": 2,
                },
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            mode=0o600,
        )

    def _parse(self, content: str, now: int | None) -> BootstrapSet:
        failures: list[str] = []
        for pin in self.authority_pins:
            try:
                return BootstrapSet.from_json(
                    content,
                    pin,
                    now=now,
                    expected_network_id=self.network_id,
                    expected_protocol_version=self.protocol_version,
                )
            except DiscoveryError as error:
                failures.append(str(error))
        detail = failures[-1] if failures else "no trust anchors"
        raise DiscoveryError(f"signed reseed bundle is not trusted: {detail}")

    def _expired_installed_content_unlocked(
        self,
        content: str,
        state: dict[str, dict[str, object]],
        current: int,
    ) -> ReseedImportResult | None:
        try:
            document = parse_json_object(content)
            digest = hashlib.sha256(canonical_json(document)).hexdigest()
            generation = document["generation"]
            expiries = [document["expiresAt"]]
            peers = document["peers"]
            if (
                isinstance(generation, bool)
                or not isinstance(generation, int)
                or not isinstance(peers, list)
            ):
                return None
            for peer in peers:
                if not isinstance(peer, dict):
                    return None
                expiries.append(peer["expiresAt"])
            if any(
                isinstance(expiry, bool) or not isinstance(expiry, int)
                for expiry in expiries
            ):
                return None
        except (KeyError, TypeError, ValueError):
            return None
        trusted_authorities = {_authority_id(pin) for pin in self.authority_pins}
        for authority_id, expected in state.items():
            accepted = expected.get("accepted", ())
            if authority_id not in trusted_authorities or not isinstance(accepted, list):
                continue
            for item in accepted:
                if (
                    item["generation"] == generation
                    and item["sha256"] == digest
                    and min(expiries) <= current
                ):
                    return ReseedImportResult(authority_id, generation, digest, False)
        return None

    def expired_installed_bundle(
        self,
        path: Path,
        *,
        now: int | None = None,
    ) -> ReseedImportResult | None:
        source_path = Path(path).resolve()
        current = int(time.time()) if now is None else now
        if isinstance(current, bool) or not isinstance(current, int):
            raise DiscoveryError("reseed verification time is invalid")
        try:
            if source_path.stat().st_size > MAX_RESEED_BUNDLE_BYTES:
                return None
            content = source_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None
        with self._lock:
            return self._expired_installed_content_unlocked(
                content,
                self._load_state_unlocked(),
                current,
            )

    def import_content(
        self,
        content: str,
        *,
        source: str = "manual",
        now: int | None = None,
        expected_advertisement: ReseedAdvertisement | None = None,
    ) -> ReseedImportResult:
        if not isinstance(content, str) or len(content.encode("utf-8")) > MAX_RESEED_BUNDLE_BYTES:
            raise DiscoveryError("signed reseed bundle exceeds its size limit")
        if not isinstance(source, str) or not source or len(source) > 96:
            raise DiscoveryError("reseed source label is invalid")
        bundle = self._parse(content, now)
        canonical_content = bundle.to_json()
        digest = bundle.sha256
        if expected_advertisement is not None and (
            bundle.authority_public_key != expected_advertisement.authority_public_key
            or bundle.generation != expected_advertisement.generation
            or digest != expected_advertisement.sha256
            or bundle.expires_at != expected_advertisement.expires_at
            or len(canonical_content.encode("ascii")) != expected_advertisement.size
        ):
            raise DiscoveryError("reseed transfer does not match signed bundle metadata")
        authority_id = _authority_id(bundle.authority_public_key)
        destination = self.bundles_root / (
            f"{authority_id}-{bundle.generation:020d}-{digest[:16]}.json"
        )
        with self._lock:
            state = self._load_state_unlocked()
            previous = state.get(authority_id)
            if previous is not None:
                previous_generation = int(previous["generation"])
                if bundle.generation < previous_generation:
                    raise DiscoveryError("reseed bootstrap rollback was rejected")
                if bundle.generation == previous_generation:
                    if digest != previous["sha256"]:
                        raise DiscoveryError("reseed bootstrap generation equivocation was rejected")
                    try:
                        stored_content = destination.read_text(encoding="utf-8")
                    except (OSError, UnicodeDecodeError):
                        stored_content = ""
                    if stored_content != canonical_content:
                        self.bundles_root.mkdir(parents=True, exist_ok=True)
                        atomic_write_text(destination, canonical_content, mode=0o600)
                    return ReseedImportResult(authority_id, bundle.generation, digest, False)
            self.bundles_root.mkdir(parents=True, exist_ok=True)
            if not destination.exists():
                atomic_write_text(destination, canonical_content, mode=0o600)
            accepted = list(previous["accepted"]) if previous is not None else []
            accepted.insert(0, {"generation": bundle.generation, "sha256": digest})
            accepted = accepted[:MAX_RESEED_BUNDLES_PER_AUTHORITY]
            state[authority_id] = {
                "accepted": accepted,
                "generation": bundle.generation,
                "sha256": digest,
            }
            self._write_state_unlocked(state)
            self._prune_unlocked(authority_id, accepted)
            return ReseedImportResult(authority_id, bundle.generation, digest, True)

    def import_path(
        self,
        path: Path,
        *,
        source: str = "manual",
        now: int | None = None,
    ) -> ReseedImportResult:
        source_path = Path(path).resolve()
        try:
            if source_path.stat().st_size > MAX_RESEED_BUNDLE_BYTES:
                raise DiscoveryError("signed reseed bundle exceeds its size limit")
            content = source_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise DiscoveryError(f"signed reseed bundle is unavailable: {error}") from error
        return self.import_content(content, source=source, now=now)

    def _prune_unlocked(
        self,
        authority_id: str,
        accepted: list[dict[str, object]],
    ) -> None:
        retained = {
            f"{authority_id}-{int(item['generation']):020d}-{str(item['sha256'])[:16]}.json"
            for item in accepted
        }
        for candidate in self.bundles_root.glob(f"{authority_id}-*.json"):
            if candidate.name in retained:
                continue
            try:
                candidate.unlink()
            except FileNotFoundError:
                pass

    def load_active(self, now: int | None = None) -> tuple[BootstrapSet, ...]:
        with self._lock:
            state = self._load_state_unlocked()
            current = int(time.time()) if now is None else now
            if isinstance(current, bool) or not isinstance(current, int):
                raise DiscoveryError("reseed verification time is invalid")
            bundles: list[BootstrapSet] = []
            for pin in self.authority_pins:
                authority_id = _authority_id(pin)
                expected = state.get(authority_id)
                if expected is None:
                    continue
                active_for_authority = 0
                for item in expected["accepted"]:
                    pattern = (
                        f"{authority_id}-{int(item['generation']):020d}-"
                        f"{str(item['sha256'])[:16]}.json"
                    )
                    path = self.bundles_root / pattern
                    try:
                        content = path.read_text(encoding="utf-8")
                    except (OSError, UnicodeDecodeError) as error:
                        if item["generation"] == expected["generation"]:
                            raise DiscoveryError(
                                f"active reseed bundle is unavailable: {error}"
                            ) from error
                        continue
                    try:
                        bundle = BootstrapSet.from_json(
                            content,
                            pin,
                            now=now,
                            expected_network_id=self.network_id,
                            expected_protocol_version=self.protocol_version,
                        )
                    except DiscoveryError:
                        if self._expired_installed_content_unlocked(
                            content,
                            {authority_id: expected},
                            current,
                        ) is not None:
                            if item["generation"] == expected["generation"]:
                                break
                            continue
                        raise
                    if bundle.sha256 != item["sha256"]:
                        raise DiscoveryError(
                            "active reseed bundle digest does not match accepted state"
                        )
                    if bundle.generation != item["generation"]:
                        raise DiscoveryError(
                            "active reseed generation does not match accepted state"
                        )
                    bundles.append(bundle)
                    active_for_authority += 1
                    if active_for_authority >= MAX_ACTIVE_RESEED_GENERATIONS_PER_AUTHORITY:
                        break
            return tuple(sorted(bundles, key=lambda item: (-item.generation, item.sha256)))

    def high_water_marks(self) -> dict[bytes, tuple[int, str]]:
        with self._lock:
            state = self._load_state_unlocked()
            result: dict[bytes, tuple[int, str]] = {}
            for pin in self.authority_pins:
                expected = state.get(_authority_id(pin))
                if expected is not None:
                    result[pin] = (
                        int(expected["generation"]),
                        str(expected["sha256"]),
                    )
            return result

    def advertisements(
        self,
        now: int | None = None,
    ) -> tuple[ReseedAdvertisement, ...]:
        return tuple(
            ReseedAdvertisement(
                bundle.authority_public_key,
                bundle.generation,
                bundle.sha256,
                bundle.expires_at,
                len(bundle.to_json().encode("ascii")),
            )
            for bundle in self.load_active(now=now)
        )

    def transport_chunk(
        self,
        sha256: str,
        offset: int,
        *,
        now: int | None = None,
    ) -> tuple[int, bytes]:
        if (
            not isinstance(sha256, str)
            or len(sha256) != 64
            or any(character not in "0123456789abcdef" for character in sha256)
            or isinstance(offset, bool)
            or not isinstance(offset, int)
            or offset < 0
        ):
            raise ProtocolError("reseed chunk request is invalid")
        for bundle in self.load_active(now=now):
            if bundle.sha256 != sha256:
                continue
            content = bundle.to_json().encode("ascii")
            if offset >= len(content):
                raise ProtocolError("reseed chunk offset exceeds bundle size")
            return len(content), content[
                offset : offset + MAX_RESEED_TRANSPORT_CHUNK_BYTES
            ]
        raise DiscoveryError("requested reseed bundle is unavailable")

    def import_directory(self, path: Path, *, now: int | None = None) -> tuple[ReseedImportResult, ...]:
        directory = Path(path).resolve()
        if not directory.is_dir():
            raise DiscoveryError("reseed source directory is unavailable")
        results: list[ReseedImportResult] = []
        for candidate in sorted(directory.glob("*.json"))[:64]:
            results.append(
                self.import_path(candidate, source=f"directory:{candidate.name[:64]}", now=now)
            )
        return tuple(results)

    def export_active(self, destination: Path, now: int | None = None) -> tuple[Path, ...]:
        bundles = self.load_active(now=now)
        target_root = Path(destination).resolve()
        target_root.mkdir(parents=True, exist_ok=True)
        exported: list[Path] = []
        for bundle in bundles:
            target = target_root / (
                f"bootstrap-{_authority_id(bundle.authority_public_key)}-"
                f"{bundle.generation}.json"
            )
            atomic_write_text(target, bundle.to_json(), mode=0o644)
            exported.append(target)
        return tuple(exported)

    def diagnostics(self, now: int | None = None) -> dict[str, object]:
        bundles = self.load_active(now=now)
        return {
            "activeAuthorities": len(
                {bundle.authority_public_key for bundle in bundles}
            ),
            "activeBundles": len(bundles),
            "generations": [bundle.generation for bundle in bundles],
            "networkId": self.network_id,
            "protocolVersion": self.protocol_version,
            "version": 2,
        }
