from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ._codec import atomic_write_text, parse_json_object
from .bootstrap import BootstrapSet, DEFAULT_NETWORK_ID, DEFAULT_PROTOCOL_VERSION
from .errors import DiscoveryError


MAX_RESEED_AUTHORITIES = 8
MAX_RESEED_BUNDLES_PER_AUTHORITY = 4
MAX_RESEED_BUNDLE_BYTES = 4 * 1024 * 1024


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
            if (
                document["version"] != 1
                or document["networkId"] != self.network_id
                or document["protocolVersion"] != self.protocol_version
                or not isinstance(document["authorities"], dict)
                or len(document["authorities"]) > MAX_RESEED_AUTHORITIES
            ):
                raise ValueError("reseed state policy mismatch")
            result: dict[str, dict[str, object]] = {}
            for authority_id, state in document["authorities"].items():
                if (
                    not isinstance(authority_id, str)
                    or len(authority_id) != 24
                    or any(character not in "0123456789abcdef" for character in authority_id)
                    or not isinstance(state, dict)
                    or set(state) != {"generation", "sha256"}
                    or isinstance(state["generation"], bool)
                    or not isinstance(state["generation"], int)
                    or not 1 <= state["generation"] <= 2**63 - 1
                    or not isinstance(state["sha256"], str)
                    or len(state["sha256"]) != 64
                    or any(character not in "0123456789abcdef" for character in state["sha256"])
                ):
                    raise ValueError("reseed authority state is invalid")
                result[authority_id] = dict(state)
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
                    "version": 1,
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

    def import_content(
        self,
        content: str,
        *,
        source: str = "manual",
        now: int | None = None,
    ) -> ReseedImportResult:
        if not isinstance(content, str) or len(content.encode("utf-8")) > MAX_RESEED_BUNDLE_BYTES:
            raise DiscoveryError("signed reseed bundle exceeds its size limit")
        if not isinstance(source, str) or not source or len(source) > 96:
            raise DiscoveryError("reseed source label is invalid")
        bundle = self._parse(content, now)
        canonical_content = bundle.to_json()
        digest = bundle.sha256
        authority_id = _authority_id(bundle.authority_public_key)
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
                    return ReseedImportResult(authority_id, bundle.generation, digest, False)
            self.bundles_root.mkdir(parents=True, exist_ok=True)
            destination = self.bundles_root / (
                f"{authority_id}-{bundle.generation:020d}-{digest[:16]}.json"
            )
            if not destination.exists():
                atomic_write_text(destination, canonical_content, mode=0o600)
            state[authority_id] = {"generation": bundle.generation, "sha256": digest}
            self._write_state_unlocked(state)
            self._prune_unlocked(authority_id, destination)
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

    def _prune_unlocked(self, authority_id: str, active: Path) -> None:
        candidates = sorted(
            self.bundles_root.glob(f"{authority_id}-*.json"),
            key=lambda path: path.name,
            reverse=True,
        )
        for candidate in candidates[MAX_RESEED_BUNDLES_PER_AUTHORITY:]:
            if candidate != active:
                try:
                    candidate.unlink()
                except FileNotFoundError:
                    pass

    def load_active(self, now: int | None = None) -> tuple[BootstrapSet, ...]:
        with self._lock:
            state = self._load_state_unlocked()
            bundles: list[BootstrapSet] = []
            for pin in self.authority_pins:
                authority_id = _authority_id(pin)
                expected = state.get(authority_id)
                if expected is None:
                    continue
                pattern = (
                    f"{authority_id}-{int(expected['generation']):020d}-"
                    f"{str(expected['sha256'])[:16]}.json"
                )
                path = self.bundles_root / pattern
                try:
                    content = path.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError) as error:
                    raise DiscoveryError(f"active reseed bundle is unavailable: {error}") from error
                try:
                    bundle = BootstrapSet.from_json(
                        content,
                        pin,
                        now=now,
                        expected_network_id=self.network_id,
                        expected_protocol_version=self.protocol_version,
                    )
                except DiscoveryError as error:
                    if "not currently valid" in str(error):
                        continue
                    raise
                if bundle.sha256 != expected["sha256"]:
                    raise DiscoveryError("active reseed bundle digest does not match rollback state")
                if bundle.generation != expected["generation"]:
                    raise DiscoveryError("active reseed generation does not match rollback state")
                bundles.append(bundle)
            return tuple(sorted(bundles, key=lambda item: (-item.generation, item.sha256)))

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
            "activeAuthorities": len(bundles),
            "generations": [bundle.generation for bundle in bundles],
            "networkId": self.network_id,
            "protocolVersion": self.protocol_version,
            "version": 1,
        }
