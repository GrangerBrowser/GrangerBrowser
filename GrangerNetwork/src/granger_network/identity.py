from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ._codec import atomic_write_text, decode_base64url, encode_base64url, parse_json_object
from .errors import DescriptorError


@dataclass(frozen=True)
class ServiceIdentity:
    _private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "ServiceIdentity":
        return cls(Ed25519PrivateKey.generate())

    @property
    def public_key_bytes(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    @property
    def private_key_bytes(self) -> bytes:
        return self._private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message)

    def save(self, path: Path, overwrite: bool = False) -> None:
        destination = Path(path)
        if destination.exists() and not overwrite:
            raise FileExistsError(f"identity already exists: {destination}")
        document = {
            "algorithm": "Ed25519",
            "privateKey": encode_base64url(self.private_key_bytes),
            "publicKey": encode_base64url(self.public_key_bytes),
            "version": 1,
        }
        atomic_write_text(destination, json.dumps(document, indent=2, sort_keys=True) + "\n")

    @classmethod
    def load(cls, path: Path) -> "ServiceIdentity":
        try:
            document = parse_json_object(Path(path).read_text(encoding="utf-8"))
            if set(document) != {"algorithm", "privateKey", "publicKey", "version"}:
                raise ValueError("unexpected identity fields")
            if (
                isinstance(document["version"], bool)
                or not isinstance(document["version"], int)
                or document["version"] != 1
                or document["algorithm"] != "Ed25519"
            ):
                raise ValueError("unsupported identity format")
            private_bytes = decode_base64url(document["privateKey"])
            expected_public = decode_base64url(document["publicKey"])
            if len(private_bytes) != 32 or len(expected_public) != 32:
                raise ValueError("invalid Ed25519 key length")
            identity = cls(Ed25519PrivateKey.from_private_bytes(private_bytes))
            if identity.public_key_bytes != expected_public:
                raise ValueError("identity public key does not match its private key")
            return identity
        except (OSError, KeyError, TypeError, ValueError) as error:
            raise DescriptorError(f"unable to load service identity: {error}") from error
