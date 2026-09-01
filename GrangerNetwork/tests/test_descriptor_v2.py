from __future__ import annotations

import json
import unittest

from granger_network._codec import encode_base64url
from granger_network.descriptor import ServiceDescriptor
from granger_network.errors import DescriptorError
from granger_network.identity import ServiceIdentity


class RemoteDescriptorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = ServiceIdentity.generate()
        self.descriptor = ServiceDescriptor.create_remote(
            self.identity,
            "test-relay",
            metadata={"contentType": "text/html", "title": "Test service"},
            issued_at=1_000_000,
            lifetime=3600,
        )

    def test_remote_descriptor_contains_no_service_endpoint(self) -> None:
        document = json.loads(self.descriptor.to_json())
        self.assertNotIn("host", document)
        self.assertNotIn("port", document)
        self.assertNotIn("endpoint", document)
        self.assertNotIn("127.0.0.1", self.descriptor.to_json())
        self.assertEqual(document["transports"], ["rendezvous-v1"])
        self.assertEqual(document["protocolVersion"], 3)
        self.assertIsNone(self.descriptor.endpoint)

    def test_signed_protocol_version_prevents_downgrade(self) -> None:
        document = json.loads(self.descriptor.to_json())
        document["protocolVersion"] = 2
        with self.assertRaises(DescriptorError):
            ServiceDescriptor.from_json(json.dumps(document), now=1_000_001)

    def test_legacy_wire_v2_descriptor_remains_readable(self) -> None:
        descriptor = ServiceDescriptor.create_remote(
            self.identity,
            "test-relay",
            issued_at=1_000_000,
            lifetime=3600,
            protocol_version=2,
        )
        parsed = ServiceDescriptor.from_json(descriptor.to_json(), now=1_000_001)
        self.assertEqual(parsed.protocol_version, 2)

    def test_modified_descriptor_is_rejected(self) -> None:
        document = json.loads(self.descriptor.to_json())
        document["metadata"]["title"] = "Substituted service"
        with self.assertRaises(DescriptorError):
            ServiceDescriptor.from_json(json.dumps(document), now=1_000_001)

    def test_expired_descriptor_is_rejected(self) -> None:
        with self.assertRaises(DescriptorError):
            ServiceDescriptor.from_json(self.descriptor.to_json(), now=1_003_600)

    def test_expired_owner_state_can_only_be_loaded_for_signed_refresh(self) -> None:
        loaded = ServiceDescriptor.from_json_for_owner_refresh(
            self.descriptor.to_json(), self.identity, now=1_003_600,
        )
        self.assertEqual(loaded, self.descriptor)

        with self.assertRaises(DescriptorError):
            ServiceDescriptor.from_json_for_owner_refresh(
                self.descriptor.to_json(), ServiceIdentity.generate(), now=1_003_600,
            )

        modified = json.loads(self.descriptor.to_json())
        modified["metadata"]["title"] = "Substituted service"
        with self.assertRaises(DescriptorError):
            ServiceDescriptor.from_json_for_owner_refresh(
                json.dumps(modified), self.identity, now=1_003_600,
            )

    def test_owner_refresh_rejects_future_descriptor_state(self) -> None:
        future = ServiceDescriptor.create_remote(
            self.identity,
            "test-relay",
            issued_at=1_010_000,
            lifetime=3600,
        )
        with self.assertRaises(DescriptorError):
            ServiceDescriptor.from_json_for_owner_refresh(
                future.to_json(), self.identity, now=1_000_000,
            )

    def test_wrong_descriptor_signature_is_rejected(self) -> None:
        document = json.loads(self.descriptor.to_json())
        document["signature"] = encode_base64url(ServiceIdentity.generate().sign(b"wrong"))
        with self.assertRaises(DescriptorError):
            ServiceDescriptor.from_json(json.dumps(document), now=1_000_001)

    def test_private_or_unbounded_metadata_is_rejected(self) -> None:
        with self.assertRaises(DescriptorError):
            ServiceDescriptor.create_remote(
                self.identity,
                "test-relay",
                metadata={"operatorIp": "203.0.113.5"},
            )
        with self.assertRaises(DescriptorError):
            ServiceDescriptor.create_remote(
                self.identity,
                "test-relay",
                metadata={"title": "x" * 300},
            )


if __name__ == "__main__":
    unittest.main()
