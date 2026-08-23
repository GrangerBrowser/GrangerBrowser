from __future__ import annotations

import json
from pathlib import Path

from ._codec import atomic_write_text, parse_json_object
from .address import is_canonical_name, normalize_name, service_id_from_name
from .descriptor import ServiceDescriptor
from .errors import AddressError, DescriptorError, ResolutionError


class LocalResolver:
    """A local descriptor store. It never delegates to DNS or another resolver."""

    def __init__(self, registry_root: Path) -> None:
        self.registry_root = Path(registry_root)
        self.services_root = self.registry_root / "services"
        self.aliases_path = self.registry_root / "aliases.json"

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
