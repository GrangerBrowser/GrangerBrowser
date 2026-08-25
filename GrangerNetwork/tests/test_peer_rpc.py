from __future__ import annotations

import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from granger_network.bootstrap import BootstrapPool, BootstrapSet, PeerCache
from granger_network.errors import DiscoveryError, IdentityVerificationError, ProtocolError
from granger_network.identity import ServiceIdentity
from granger_network.peer import NodeDescriptor, RelayPolicy
from granger_network.peer_rpc import (
    PeerRole,
    RpcFrame,
    RpcType,
    authenticate_server_stream,
    connect_authenticated_peer,
    decode_rpc_frame,
    encode_rpc_frame,
)
from granger_network.transport import RendezvousEndpoint


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def make_descriptor(
    identity: ServiceIdentity,
    port: int,
    capabilities: tuple[str, ...] = ("bootstrap", "discovery", "entry"),
) -> NodeDescriptor:
    return NodeDescriptor.create(
        identity,
        RendezvousEndpoint("127.0.0.1", port),
        capabilities,
        RelayPolicy(
            enabled=any(
                capability in {"entry", "middle", "introduction", "rendezvous", "service-relay"}
                for capability in capabilities
            ),
            max_bandwidth_kib_per_second=64 * 1024,
        ),
        lifetime=3600,
    )


class PeerRpcTests(unittest.TestCase):
    def test_real_socket_peer_authentication_and_ping(self) -> None:
        relay_identity = ServiceIdentity.generate()
        client_identity = ServiceIdentity.generate()
        descriptor = make_descriptor(relay_identity, available_port())
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(descriptor.endpoint.socket_address)
        listener.listen(1)
        listener.settimeout(5.0)
        failures: list[BaseException] = []
        observations: list[tuple] = []

        def serve() -> None:
            connection = None
            peer = None
            try:
                connection, address = listener.accept()
                observations.append(address)
                connection.settimeout(5.0)
                peer = authenticate_server_stream(connection, relay_identity, descriptor)
                request = peer.rpc.receive()
                self.assertEqual(request.message_type, RpcType.PING)
                self.assertEqual(request.payload, b"bounded-ping")
                self.assertEqual(peer.remote.role, PeerRole.CLIENT)
                self.assertIsNone(peer.remote.descriptor)
                peer.rpc.send(
                    RpcType.PONG,
                    b"bounded-pong",
                    request_id=request.request_id,
                    response=True,
                )
            except BaseException as error:
                failures.append(error)
            finally:
                if peer is not None:
                    peer.close()
                elif connection is not None:
                    connection.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        client = connect_authenticated_peer(
            descriptor,
            client_identity,
            PeerRole.CLIENT,
            timeout=5.0,
        )
        try:
            response = client.rpc.request(
                RpcType.PING,
                b"bounded-ping",
                expected=RpcType.PONG,
            )
            self.assertEqual(response.payload, b"bounded-pong")
            self.assertEqual(client.remote.node_id, descriptor.node_id)
            self.assertEqual(client.remote.descriptor, descriptor)
        finally:
            client.close()
            thread.join(timeout=5.0)
            listener.close()
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(len(observations), 1)

    def test_server_identity_substitution_is_rejected(self) -> None:
        actual_identity = ServiceIdentity.generate()
        claimed_identity = ServiceIdentity.generate()
        actual_descriptor = make_descriptor(actual_identity, available_port())
        claimed_descriptor = make_descriptor(
            claimed_identity,
            actual_descriptor.endpoint.port,
        )
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(actual_descriptor.endpoint.socket_address)
        listener.listen(1)

        def serve() -> None:
            connection, _address = listener.accept()
            connection.settimeout(3.0)
            try:
                authenticate_server_stream(connection, actual_identity, actual_descriptor)
            except (OSError, ProtocolError):
                pass
            finally:
                connection.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        with self.assertRaises(IdentityVerificationError):
            connect_authenticated_peer(
                claimed_descriptor,
                ServiceIdentity.generate(),
                PeerRole.CLIENT,
                timeout=3.0,
            )
        thread.join(timeout=5.0)
        listener.close()

    def test_binary_rpc_rejects_unknown_type_size_and_sequence_shape(self) -> None:
        frame = RpcFrame(RpcType.PING, 0, b"r" * 16, 7, b"payload")
        encoded = encode_rpc_frame(frame)
        self.assertEqual(decode_rpc_frame(encoded), frame)
        unknown = bytearray(encoded)
        unknown[5] = 0xFF
        with self.assertRaisesRegex(ProtocolError, "unknown"):
            decode_rpc_frame(bytes(unknown))
        malformed_length = bytearray(encoded)
        malformed_length[32:36] = (99).to_bytes(4, "big")
        with self.assertRaisesRegex(ProtocolError, "length"):
            decode_rpc_frame(bytes(malformed_length))
        with self.assertRaises(ProtocolError):
            encode_rpc_frame(RpcFrame(RpcType.PING, 0, b"short", 0, b""))

    def test_bootstrap_set_requires_pin_multiple_peers_and_valid_signatures(self) -> None:
        authority = ServiceIdentity.generate()
        peers = [
            make_descriptor(ServiceIdentity.generate(), available_port())
            for _ in range(3)
        ]
        issued_at = int(time.time())
        bootstrap = BootstrapSet.create(
            authority,
            peers,
            issued_at=issued_at,
            lifetime=600,
        )
        parsed = BootstrapSet.from_json(
            bootstrap.to_json(),
            authority.public_key_bytes,
            now=issued_at,
        )
        self.assertEqual(parsed, bootstrap)
        with self.assertRaisesRegex(DiscoveryError, "pin"):
            BootstrapSet.from_json(
                bootstrap.to_json(),
                ServiceIdentity.generate().public_key_bytes,
                now=issued_at,
            )
        document = json.loads(bootstrap.to_json())
        document["peers"][0]["endpoint"]["port"] += 1
        with self.assertRaises(DiscoveryError):
            BootstrapSet.from_json(
                json.dumps(document),
                authority.public_key_bytes,
                now=issued_at,
            )

    def test_peer_cache_preserves_only_verified_latest_descriptors(self) -> None:
        authority = ServiceIdentity.generate()
        identities = [ServiceIdentity.generate() for _ in range(3)]
        now = int(time.time())
        peers = [make_descriptor(identity, available_port()) for identity in identities]
        bootstrap = BootstrapSet.create(authority, peers, issued_at=now, lifetime=600)
        with tempfile.TemporaryDirectory() as temporary:
            cache = PeerCache(Path(temporary) / "peers.json")
            cache.store(peers, now=now)
            loaded = cache.load(now=now)
            self.assertEqual({peer.node_id for peer in loaded}, {peer.node_id for peer in peers})
            pool = BootstrapPool(bootstrap, cache)
            self.assertEqual(len(pool.candidates("bootstrap", now=now)), 3)
            newer = NodeDescriptor.create(
                identities[0],
                peers[0].endpoint,
                peers[0].capabilities,
                peers[0].relay_policy,
                issued_at=now + 1,
                lifetime=600,
            )
            cache.add(newer, now=now + 1)
            by_id = {peer.node_id: peer for peer in cache.load(now=now + 1)}
            self.assertEqual(by_id[newer.node_id].issued_at, now + 1)


if __name__ == "__main__":
    unittest.main()
