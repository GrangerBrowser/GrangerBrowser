from __future__ import annotations

import json
from pathlib import Path

from ._codec import atomic_write_text, parse_json_object
from .address import is_canonical_name, normalize_name, service_id_from_name
from .descriptor import ServiceDescriptor
from .discovery import DiscoveryProvider, validate_rendezvous_id
from .errors import AddressError, DescriptorError, DiscoveryError, ResolutionError
from .transport import RendezvousEndpoint


class LocalResolver(DiscoveryProvider):
    """A local descriptor store. It never delegates to DNS or another resolver."""

    def __init__(self, registry_root: Path) -> None:
        self.registry_root = Path(registry_root)
        self.services_root = self.registry_root / "services"
        self.aliases_path = self.registry_root / "aliases.json"
        self.rendezvous_path = self.registry_root / "rendezvous.json"

    def import_descriptor(self, descriptor: ServiceDescriptor, alias: str | None = None) -> None:
        descriptor.verify()
        self.services_root.mkdir(parents=True, exist_ok=True)
        destination = self.services_root / f"{descriptor.service_id}.json"
        atomic_write_text(destination, descriptor.to_json(), mode=0o644)
        if alias is not None:
            normalized_alias = normalize_name(alias)
            aliases = self._load_aliases()
            aliases[normalized_alias] = descriptor.canonical_name
            atomic_write_text(
                self.aliases_path,
                json.dumps({"aliases": aliases, "version": 1}, indent=2, sort_keys=True) + "\n",
                mode=0o600,
            )

    def resolve(self, name: str) -> ServiceDescriptor:
        try:
            normalized = normalize_name(name)
            if is_canonical_name(normalized):
                service_id = service_id_from_name(normalized)
            else:
                canonical = self._load_aliases().get(normalized)
                if canonical is None:
                    raise ResolutionError(f"unknown local .granger alias: {normalized}")
                service_id = service_id_from_name(canonical)
            descriptor_path = self.services_root / f"{service_id}.json"
            if not descriptor_path.is_file():
                raise ResolutionError(f"service descriptor is not installed: {service_id}.granger")
            descriptor = ServiceDescriptor.from_json(descriptor_path.read_text(encoding="utf-8"))
            if descriptor.service_id != service_id:
                raise ResolutionError("descriptor filename and identity do not match")
            return descriptor
        except (AddressError, DescriptorError, OSError) as error:
            if isinstance(error, ResolutionError):
                raise
            raise ResolutionError(str(error)) from error

    def configure_rendezvous(
        self,
        rendezvous_id: str,
        endpoint: RendezvousEndpoint,
    ) -> None:
        identifier = validate_rendezvous_id(rendezvous_id)
        if not isinstance(endpoint, RendezvousEndpoint):
            raise DiscoveryError("unsupported rendezvous endpoint")
        entries = self._load_rendezvous()
        entries[identifier] = {
            "host": endpoint.host,
            "port": endpoint.port,
            "type": "tcp",
        }
        atomic_write_text(
            self.rendezvous_path,
            json.dumps({"rendezvous": entries, "version": 1}, indent=2, sort_keys=True) + "\n",
            mode=0o600,
        )

    def resolve_rendezvous(self, rendezvous_id: str) -> RendezvousEndpoint:
        identifier = validate_rendezvous_id(rendezvous_id)
        entry = self._load_rendezvous().get(identifier)
        if entry is None:
            raise DiscoveryError(f"rendezvous bootstrap is not configured: {identifier}")
        try:
            return RendezvousEndpoint(entry["host"], entry["port"])
        except (KeyError, TypeError, ValueError) as error:
            raise DiscoveryError(f"invalid rendezvous bootstrap: {error}") from error

    def _load_aliases(self) -> dict[str, str]:
        if not self.aliases_path.exists():
            return {}
        try:
            document = parse_json_object(self.aliases_path.read_text(encoding="utf-8"))
            if (
                set(document) != {"aliases", "version"}
                or isinstance(document["version"], bool)
                or not isinstance(document["version"], int)
                or document["version"] != 1
            ):
                raise ValueError("unsupported alias registry")
            if not isinstance(document["aliases"], dict):
                raise ValueError("alias registry must contain an object")
            result: dict[str, str] = {}
            for alias, canonical in document["aliases"].items():
                normalized_alias = normalize_name(alias)
                service_id_from_name(canonical)
                result[normalized_alias] = canonical
            return result
        except (AddressError, OSError, TypeError, ValueError) as error:
            raise ResolutionError(f"invalid local alias registry: {error}") from error

    def _load_rendezvous(self) -> dict[str, dict[str, object]]:
        if not self.rendezvous_path.exists():
            return {}
        try:
            document = parse_json_object(self.rendezvous_path.read_text(encoding="utf-8"))
            if (
                set(document) != {"rendezvous", "version"}
                or isinstance(document["version"], bool)
                or not isinstance(document["version"], int)
                or document["version"] != 1
                or not isinstance(document["rendezvous"], dict)
            ):
                raise ValueError("unsupported rendezvous registry")
            result: dict[str, dict[str, object]] = {}
            for identifier, entry in document["rendezvous"].items():
                valid_id = validate_rendezvous_id(identifier)
                if not isinstance(entry, dict) or set(entry) != {"host", "port", "type"}:
                    raise ValueError("invalid rendezvous entry")
                if entry["type"] != "tcp":
                    raise ValueError("unsupported rendezvous transport")
                endpoint = RendezvousEndpoint(entry["host"], entry["port"])
                result[valid_id] = {
                    "host": endpoint.host,
                    "port": endpoint.port,
                    "type": "tcp",
                }
            return result
        except (DiscoveryError, OSError, TypeError, ValueError) as error:
            raise DiscoveryError(f"invalid rendezvous registry: {error}") from error
