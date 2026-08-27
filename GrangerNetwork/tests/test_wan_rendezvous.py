from __future__ import annotations

import hashlib
import secrets
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from granger_network.cells import CellMultiplexer
from granger_network.circuit import CircuitBuilder
from granger_network.descriptor import ServiceDescriptor
from granger_network.identity import ServiceIdentity
from granger_network.introduction import IntroductionDescriptor
from granger_network.node import WanNodeServer
from granger_network.peer import NodeDescriptor, RelayPolicy
from granger_network.peer_rpc import PeerRole, RpcType
from granger_network.protocol import VERSION_3, client_handshake, server_handshake
from granger_network.transport import RendezvousEndpoint
from granger_network.wan_control import (
    IntroductionRequest,
    RendezvousGrant,
    RendezvousJoin,
    RendezvousRegistration,
    decode_intro_request,
    encode_intro_registration,
    encode_intro_request,
)


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class WanRendezvousTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="granger-wan-rendezvous-")
        self.root = Path(self.temporary.name)
        definitions = (
            "access",
            "entry",
            "middle",
            "access",
            "service-relay",
            "middle",
            "introduction",
            "rendezvous",
        )
        self.identities = [ServiceIdentity.generate() for _ in definitions]
        self.descriptors = [
            NodeDescriptor.create(
                identity,
                RendezvousEndpoint("127.0.0.1", available_port()),
                (role,),
                RelayPolicy(
                    enabled=True,
                    max_circuits=32,
                    max_streams=32,
                    max_connections=64,
                    max_bandwidth_kib_per_second=64 * 1024,
                    idle_timeout_seconds=30,
                ),
                lifetime=3600,
            )
            for identity, role in zip(self.identities, definitions, strict=True)
        ]
        self.nodes = [
            WanNodeServer(identity, descriptor, self.root / f"node-{index}")
            for index, (identity, descriptor) in enumerate(
                zip(self.identities, self.descriptors, strict=True)
            )
        ]
        for node in self.nodes:
            node.start_background()
        (
            self.client_access,
            self.client_entry,
            self.client_middle,
            self.service_access,
            self.service_entry,
            self.host_middle,
            self.introduction_node,
            self.rendezvous_node,
        ) = self.descriptors
        self.service_identity = ServiceIdentity.generate()
        self.service = ServiceDescriptor.create_remote(
            self.service_identity,
            "wan-overlay",
            lifetime=1800,
        )
        self.introduction = IntroductionDescriptor.create(
            self.service_identity,
            self.service,
            [self.introduction_node.node_id],
            sequence=1,
            lifetime=900,
        )

    def tearDown(self) -> None:
        for node in self.nodes:
            node.stop()
        self.temporary.cleanup()

    def test_independent_intro_and_rendezvous_paths_create_e2e_service_channel(self) -> None:
        host_builder = CircuitBuilder(self.service_identity, PeerRole.SERVICE, timeout=5.0)
        client_identity = ServiceIdentity.generate()
        client_builder = CircuitBuilder(client_identity, PeerRole.CLIENT, timeout=5.0)
        host_intro = host_builder.open(
            (
                (self.service_access, "access"),
                (self.service_entry, "service-relay"),
                (self.host_middle, "middle"),
                (self.introduction_node, "introduction"),
            )
        )
        host_rendezvous = host_builder.open(
            (
                (self.service_access, "access"),
                (self.service_entry, "service-relay"),
                (self.host_middle, "middle"),
                (self.rendezvous_node, "rendezvous"),
            )
        )
        cookie = secrets.token_bytes(32)
        expires_at = int(time.time()) + 120
        host_cell_id = secrets.token_bytes(16)
        registration = RendezvousRegistration.create(
            cookie,
            expires_at,
            host_cell_id,
        )
        registration_wire = registration.encode()
        self.assertNotIn(cookie, registration_wire)
        self.assertNotIn(self.service.service_id.encode("ascii"), registration_wire)
        self.assertNotIn(self.service.identity_public_key, registration_wire)
        host_rendezvous.endpoint.rpc.request(
            RpcType.RENDEZVOUS_REGISTER,
            registration_wire,
            expected=RpcType.RENDEZVOUS_REGISTER,
        )
        host_mux = CellMultiplexer(
            host_rendezvous.endpoint.channel,
            host_cell_id,
            initiator=True,
        )
        host_stream = host_mux.open_stream(5.0)

        host_intro.endpoint.rpc.request(
            RpcType.INTRO_REGISTER,
            encode_intro_registration(self.service, self.introduction),
            expected=RpcType.INTRO_REGISTER,
        )
        host_failures: list[BaseException] = []

        def answer_introduction() -> None:
            try:
                delivered = host_intro.endpoint.rpc.receive()
                self.assertEqual(delivered.message_type, RpcType.INTRO_DELIVER)
                request = decode_intro_request(delivered.payload)
                grant = RendezvousGrant.create(
                    self.service_identity,
                    self.service,
                    request.nonce,
                    self.rendezvous_node,
                    cookie=cookie,
                    lifetime=100,
                )
                host_intro.endpoint.rpc.send(
                    RpcType.INTRO_DELIVER,
                    grant.encode(),
                    request_id=delivered.request_id,
                    response=True,
                )
            except BaseException as error:
                host_failures.append(error)

        host_intro_thread = threading.Thread(target=answer_introduction, daemon=True)
        host_intro_thread.start()
        client_intro = client_builder.open(
            (
                (self.client_access, "access"),
                (self.client_entry, "entry"),
                (self.client_middle, "middle"),
                (self.introduction_node, "introduction"),
            )
        )
        request_nonce = secrets.token_bytes(16)
        intro_response = client_intro.endpoint.rpc.request(
            RpcType.INTRO_REQUEST,
            encode_intro_request(
                IntroductionRequest(
                    self.service.service_id,
                    self.introduction.points[0].token,
                    request_nonce,
                )
            ),
            expected=RpcType.INTRO_REQUEST,
        )
        grant = RendezvousGrant.decode(
            intro_response.payload,
            self.service,
            request_nonce=request_nonce,
        )
        self.assertEqual(grant.rendezvous, self.rendezvous_node)
        client_intro.close()
        host_intro_thread.join(timeout=5.0)
        self.assertEqual(host_failures, [])

        client_rendezvous = client_builder.open(
            (
                (self.client_access, "access"),
                (self.client_entry, "entry"),
                (self.client_middle, "middle"),
                (grant.rendezvous, "rendezvous"),
            )
        )
        client_cell_id = secrets.token_bytes(16)
        rendezvous_join = RendezvousJoin.create(
            grant.cookie,
            client_cell_id,
        )
        join_wire = rendezvous_join.encode()
        self.assertNotIn(grant.cookie, join_wire)
        self.assertNotIn(self.service.service_id.encode("ascii"), join_wire)
        client_rendezvous.endpoint.rpc.request(
            RpcType.RENDEZVOUS_JOIN,
            join_wire,
            expected=RpcType.RENDEZVOUS_JOIN,
        )
        client_mux = CellMultiplexer(
            client_rendezvous.endpoint.channel,
            client_cell_id,
            initiator=True,
        )
        client_stream = client_mux.open_stream(5.0)

        session_id = hashlib.sha256(
            b"granger-network-v0.4/rendezvous-session\x00" + cookie
        ).digest()[:16]
        server_result: list[object] = []

        def accept_service() -> None:
            try:
                server_result.append(
                    server_handshake(
                        host_stream,
                        self.service_identity,
                        expected_session_id=session_id,
                        protocol_version=VERSION_3,
                    )
                )
            except BaseException as error:
                server_result.append(error)

        server_thread = threading.Thread(target=accept_service, daemon=True)
        server_thread.start()
        client_channel = client_handshake(
            client_stream,
            self.service.identity_public_key,
            session_id=session_id,
            protocol_version=VERSION_3,
        )
        server_thread.join(timeout=8.0)
        self.assertTrue(server_result)
        self.assertNotIsInstance(server_result[0], BaseException)
        server_channel = server_result[0]
        marker = b"GRANGER_RENDEZVOUS_E2E_MARKER_123"
        client_channel.send_bytes(marker)
        self.assertEqual(server_channel.receive_bytes(), marker)
        server_channel.send_bytes(b"response:" + marker)
        self.assertEqual(client_channel.receive_bytes(), b"response:" + marker)
        rendezvous_observations = self.nodes[-1].circuit_observations
        self.assertTrue(rendezvous_observations)
        self.assertTrue(all(not observation.contains(marker) for observation in rendezvous_observations))
        self.assertNotEqual(
            self.nodes[0].peer_addresses,
            self.nodes[3].peer_addresses,
        )
        self.assertEqual(
            host_intro.hop_authentication_keys[-1],
            self.service_identity.public_key_bytes,
        )
        self.assertNotIn(
            self.service_identity.public_key_bytes,
            host_intro.hop_authentication_keys[:-1],
        )
        self.assertNotIn(
            self.service_identity.public_key_bytes,
            host_rendezvous.hop_authentication_keys,
        )
        self.assertNotIn(
            client_identity.public_key_bytes,
            client_rendezvous.hop_authentication_keys,
        )

        client_channel.destroy()
        server_channel.destroy()
        client_mux.close()
        host_mux.close()
        client_rendezvous.close()
        host_rendezvous.close()
        host_intro.close()


if __name__ == "__main__":
    unittest.main()
