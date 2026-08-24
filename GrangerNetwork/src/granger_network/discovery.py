from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from .errors import DiscoveryError

if TYPE_CHECKING:
    from .descriptor import ServiceDescriptor
    from .transport import RendezvousEndpoint


_RENDEZVOUS_ID = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")


def validate_rendezvous_id(value: str) -> str:
    if not isinstance(value, str) or not _RENDEZVOUS_ID.fullmatch(value):
        raise DiscoveryError("rendezvous identifier is invalid")
    return value


class DiscoveryProvider(ABC):
    """Resolves identities and transport bootstrap data without DNS fallback."""

    @abstractmethod
    def resolve(self, name: str) -> "ServiceDescriptor":
        raise NotImplementedError

    @abstractmethod
    def resolve_rendezvous(self, rendezvous_id: str) -> "RendezvousEndpoint":
        raise NotImplementedError
