from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from granger_network.address import canonical_address, service_id_from_public_key
from granger_network.descriptor import ServiceDescriptor
from granger_network.errors import AddressError, DescriptorError, ResolutionError, TransportPolicyError
from granger_network.host import initialize_service, load_service
from granger_network.identity import ServiceIdentity
from granger_network.resolver import LocalResolver
from granger_network.transport import LoopbackEndpoint


class AddressAndResolverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = ServiceIdentity.generate()
        self.descriptor = ServiceDescriptor.create(
            self.identity,
            LoopbackEndpoint("127.0.0.1", 17777),
        )

    def test_canonical_address_is_derived_from_identity(self) -> None:
        service_id = service_id_from_public_key(self.identity.public_key_bytes)
        self.assertEqual(len(service_id), 52)
        self.assertEqual(canonical_address(self.identity.public_key_bytes), f"{service_id}.granger")
        self.assertEqual(self.descriptor.canonical_name, f"{service_id}.granger")

    def test_signed_descriptor_rejects_tampering(self) -> None:
        document = json.loads(self.descriptor.to_json())
        document["transport"]["port"] += 1
        with self.assertRaises(DescriptorError):
            ServiceDescriptor.from_json(json.dumps(document))

    def test_signed_descriptor_rejects_duplicate_fields(self) -> None:
        duplicate = self.descriptor.to_json().replace(
            '"version": 1',
            '"version": 1, "version": 1',
        )
        with self.assertRaises(DescriptorError):
            ServiceDescriptor.from_json(duplicate)

    def test_non_loopback_transport_is_rejected(self) -> None:
        with self.assertRaises(TransportPolicyError):
            LoopbackEndpoint("203.0.113.1", 7777)

        document = json.loads(self.descriptor.to_json())
        document["transport"]["host"] = "203.0.113.1"
        with self.assertRaises(DescriptorError):
            ServiceDescriptor.from_json(json.dumps(document))

    def test_resolver_supports_local_alias_and_canonical_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            resolver = LocalResolver(Path(temporary))
            resolver.import_descriptor(self.descriptor, "test.granger")
            self.assertEqual(resolver.resolve("test.granger"), self.descriptor)
            self.assertEqual(resolver.resolve(self.descriptor.canonical_name), self.descriptor)

    def test_host_initialization_persists_identity_and_registry_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            descriptor = initialize_service(
                root / "service",
                LoopbackEndpoint("127.0.0.1", 17778),
                root / "registry",
                "test.granger",
            )
            identity, loaded = load_service(root / "service")
            self.assertEqual(identity.public_key_bytes, descriptor.identity_public_key)
            self.assertEqual(loaded, descriptor)
            self.assertEqual(LocalResolver(root / "registry").resolve("test.granger"), descriptor)

    def test_resolver_never_accepts_dns_or_unknown_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            resolver = LocalResolver(Path(temporary))
            resolver.import_descriptor(self.descriptor)
            for name in ("example.com", "localhost", "test.granger.example", "unknown.granger"):
                with self.subTest(name=name), self.assertRaises((AddressError, ResolutionError)):
                    resolver.resolve(name)


if __name__ == "__main__":
    unittest.main()
