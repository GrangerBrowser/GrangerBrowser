from __future__ import annotations

import queue
import secrets
import socket
import threading
import time
import unittest

from granger_network.crypto import (
    SUITE_X25519_MLKEM768,
    SessionParameters,
    combine_hybrid_secrets,
    derive_session_secrets,
)
from granger_network.errors import IdentityVerificationError, ProtocolError, ReplayError
from granger_network.identity import ServiceIdentity
from granger_network.protocol import (
    CLIENT_HELLO_V3,
    FRAME_FLAGS_NONE,
    FRAME_HEADER_V3,
    FRAME_KIND_DATA,
    MAGIC_V3,
    MAX_MESSAGE_SIZE,
    MAX_SEQUENCE_NUMBER,
    SERVER_AUTH_DOMAIN_V3,
    SERVER_HELLO_BODY_V3,
    VERSION_3,
    SecureChannel,
    client_handshake,
    server_handshake,
)


class RecordingSocket:
    def __init__(
        self,
        wrapped: socket.socket,
        wire: bytearray,
        mutations: dict[int, int] | None = None,
    ) -> None:
        self._wrapped = wrapped
        self._wire = wire
        self._mutations = mutations or {}
        self._send_count = 0
        self.sent_chunks: list[bytes] = []

    def recv(self, size: int) -> bytes:
        return self._wrapped.recv(size)

    def sendall(self, data: bytes) -> None:
        self._send_count += 1
        payload = bytearray(data)
        if self._send_count in self._mutations:
            offset = self._mutations[self._send_count]
            payload[offset] ^= 0x01
        encoded = bytes(payload)
        self.sent_chunks.append(encoded)
        self._wire.extend(encoded)
        self._wrapped.sendall(encoded)

    def replay(self, data: bytes) -> None:
        self._wrapped.sendall(data)

    def __getattr__(self, name: str):
        return getattr(self._wrapped, name)


def establish_v3(
    identity: ServiceIdentity,
    *,
    session_id: bytes | None = None,
    rekey_interval: int = 1 << 20,
    client_mutations: dict[int, int] | None = None,
    server_mutations: dict[int, int] | None = None,
) -> tuple[SecureChannel, SecureChannel, RecordingSocket, RecordingSocket, bytearray]:
    left, right = socket.socketpair()
    wire = bytearray()
    client_socket = RecordingSocket(left, wire, client_mutations)
    server_socket = RecordingSocket(right, wire, server_mutations)
    session = session_id or secrets.token_bytes(16)
    result: queue.Queue[SecureChannel | BaseException] = queue.Queue()

    def accept() -> None:
        try:
            result.put(
                server_handshake(
                    server_socket,
                    identity,
                    expected_session_id=session,
                    protocol_version=VERSION_3,
                    rekey_interval=rekey_interval,
                )
            )
        except BaseException as error:
            result.put(error)

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    try:
        client = client_handshake(
            client_socket,
            identity.public_key_bytes,
            session_id=session,
            protocol_version=VERSION_3,
            rekey_interval=rekey_interval,
        )
    except Exception:
        client_socket.close()
        thread.join(timeout=2.0)
        raise
    thread.join(timeout=2.0)
    if thread.is_alive():
        client_socket.close()
        server_socket.close()
        raise AssertionError("v0.3 server handshake did not finish")
    server = result.get_nowait()
    if isinstance(server, BaseException):
        client_socket.close()
        server_socket.close()
        raise server
    return client, server, client_socket, server_socket, wire


class ProtocolV3Tests(unittest.TestCase):
    def test_hybrid_handshake_authenticates_control_and_data(self) -> None:
        identity = ServiceIdentity.generate()
        client, server, client_socket, server_socket, wire = establish_v3(identity)
        control_secret = b"private-control-marker"
        data_secret = b"private-data-marker"
        try:
            self.assertEqual(client.protocol_version, VERSION_3)
            self.assertEqual(client.suite, SUITE_X25519_MLKEM768)
            self.assertEqual(client.channel_binding, server.channel_binding)
            self.assertEqual(len(client.channel_binding), 32)
            client.send_json({"marker": control_secret.decode("ascii")})
            self.assertEqual(server.receive_json(), {"marker": control_secret.decode("ascii")})
            server.send_bytes(data_secret)
            self.assertEqual(client.receive_bytes(), data_secret)
            self.assertNotIn(control_secret, wire)
            self.assertNotIn(data_secret, wire)
        finally:
            client.destroy()
            server.destroy()
            client_socket.close()
            server_socket.close()

    def test_key_schedule_separates_directions_and_purposes(self) -> None:
        mlkem = b"m" * 32
        x25519 = b"x" * 32
        parameters = SessionParameters(SUITE_X25519_MLKEM768, 4096, 64, 60)
        secrets_derived = derive_session_secrets(
            combine_hybrid_secrets(mlkem, x25519),
            b"authenticated transcript",
            b"c" * 32,
            b"s" * 32,
            b"session-id-12345",
            parameters,
        )
        keys = {
            secrets_derived.client_data,
            secrets_derived.server_data,
            secrets_derived.client_control,
            secrets_derived.server_control,
            secrets_derived.client_finished,
            secrets_derived.server_finished,
            secrets_derived.exporter,
        }
        self.assertEqual(len(keys), 7)
        self.assertTrue(all(len(key) == 32 for key in keys))
        self.assertEqual(combine_hybrid_secrets(mlkem, x25519), mlkem + x25519)

    def test_rekey_rotates_epochs_without_losing_frame_order(self) -> None:
        identity = ServiceIdentity.generate()
        client, server, client_socket, server_socket, _wire = establish_v3(
            identity,
            rekey_interval=2,
        )
        try:
            client.send_json({"sequence": 0})
            self.assertEqual(server.receive_json(), {"sequence": 0})
            client.send_bytes(b"sequence-1")
            self.assertEqual(server.receive_bytes(), b"sequence-1")
            client.send_json({"sequence": 2})
            self.assertEqual(server.receive_json(), {"sequence": 2})
            self.assertEqual(client.tx_epoch, 1)
            self.assertEqual(server.rx_epoch, 1)
        finally:
            client.destroy()
            server.destroy()
            client_socket.close()
            server_socket.close()

    def test_replayed_frame_poisoned_the_channel(self) -> None:
        identity = ServiceIdentity.generate()
        client, server, client_socket, server_socket, _wire = establish_v3(identity)
        try:
            client_socket.sent_chunks.clear()
            client.send_bytes(b"single-use")
            encrypted = client_socket.sent_chunks[-1]
            self.assertEqual(server.receive_bytes(), b"single-use")
            client_socket.replay(encrypted)
            with self.assertRaises(ReplayError):
                server.receive_bytes()
            with self.assertRaises(ProtocolError):
                server.receive_bytes()
        finally:
            client.destroy()
            server.destroy()
            client_socket.close()
            server_socket.close()

    def test_modified_v3_ciphertext_is_rejected(self) -> None:
        identity = ServiceIdentity.generate()
        client, server, client_socket, server_socket, _wire = establish_v3(
            identity,
            client_mutations={3: -1},
        )
        try:
            client.send_bytes(b"authenticated-v3-payload")
            with self.assertRaisesRegex(ProtocolError, "authentication failed"):
                server.receive_bytes()
            with self.assertRaises(ProtocolError):
                server.receive_bytes()
        finally:
            client.destroy()
            server.destroy()
            client_socket.close()
            server_socket.close()

    def test_old_session_frame_is_rejected_by_new_session(self) -> None:
        identity = ServiceIdentity.generate()
        old_client, old_server, old_client_socket, old_server_socket, _wire = establish_v3(identity)
        old_client_socket.sent_chunks.clear()
        old_client.send_bytes(b"old-session")
        old_frame = old_client_socket.sent_chunks[-1]
        self.assertEqual(old_server.receive_bytes(), b"old-session")
        old_client.destroy()
        old_server.destroy()
        old_client_socket.close()
        old_server_socket.close()

        client, server, client_socket, server_socket, _wire = establish_v3(identity)
        try:
            client_socket.replay(old_frame)
            with self.assertRaises(ProtocolError):
                server.receive_bytes()
        finally:
            client.destroy()
            server.destroy()
            client_socket.close()
            server_socket.close()

    def test_out_of_order_and_oversized_frames_are_rejected(self) -> None:
        identity = ServiceIdentity.generate()
        client, server, client_socket, server_socket, _wire = establish_v3(identity)
        try:
            out_of_order = FRAME_HEADER_V3.pack(
                FRAME_KIND_DATA,
                FRAME_FLAGS_NONE,
                0,
                16,
                1,
            )
            client_socket.replay(out_of_order)
            with self.assertRaises(ReplayError):
                server.receive_bytes()
        finally:
            client.destroy()
            server.destroy()
            client_socket.close()
            server_socket.close()

        client, server, client_socket, server_socket, _wire = establish_v3(identity)
        try:
            oversized = FRAME_HEADER_V3.pack(
                FRAME_KIND_DATA,
                FRAME_FLAGS_NONE,
                0,
                MAX_MESSAGE_SIZE + 17,
                0,
            )
            client_socket.replay(oversized)
            with self.assertRaises(ProtocolError):
                server.receive_bytes()
        finally:
            client.destroy()
            server.destroy()
            client_socket.close()
            server_socket.close()

    def test_invalid_frame_kind_flags_and_channel_kind_are_rejected(self) -> None:
        identity = ServiceIdentity.generate()
        client, server, client_socket, server_socket, _wire = establish_v3(identity)
        try:
            unknown_kind = FRAME_HEADER_V3.pack(0x7F, FRAME_FLAGS_NONE, 0, 16, 0)
            client_socket.replay(unknown_kind)
            with self.assertRaisesRegex(ProtocolError, "kind is invalid"):
                server.receive_bytes()
        finally:
            client.destroy()
            server.destroy()
            client_socket.close()
            server_socket.close()

        client, server, client_socket, server_socket, _wire = establish_v3(identity)
        try:
            unknown_flags = FRAME_HEADER_V3.pack(FRAME_KIND_DATA, 1, 0, 16, 0)
            client_socket.replay(unknown_flags)
            with self.assertRaisesRegex(ProtocolError, "flags are invalid"):
                server.receive_bytes()
        finally:
            client.destroy()
            server.destroy()
            client_socket.close()
            server_socket.close()

        client, server, client_socket, server_socket, _wire = establish_v3(identity)
        try:
            client.send_json({"kind": "control"})
            with self.assertRaisesRegex(ProtocolError, "unexpected channel kind"):
                server.receive_bytes()
            with self.assertRaises(ProtocolError):
                server.receive_json()
        finally:
            client.destroy()
            server.destroy()
            client_socket.close()
            server_socket.close()

    def test_nonce_exhaustion_and_session_expiry_fail_closed(self) -> None:
        identity = ServiceIdentity.generate()
        client, server, client_socket, server_socket, _wire = establish_v3(identity)
        try:
            client._tx_counter = MAX_SEQUENCE_NUMBER + 1
            with self.assertRaises(ProtocolError):
                client.send_bytes(b"must-not-send")
            client._tx_counter = 0
            with self.assertRaises(ProtocolError):
                client.send_bytes(b"channel-remains-poisoned")
        finally:
            client.destroy()
            server.destroy()
            client_socket.close()
            server_socket.close()

        client, server, client_socket, server_socket, _wire = establish_v3(identity)
        try:
            client._created_at -= client.max_session_age + 1
            with self.assertRaises(ProtocolError):
                client.send_json({"expired": True})
        finally:
            client.destroy()
            server.destroy()
            client_socket.close()
            server_socket.close()

    def test_handshake_transcript_tampering_is_rejected(self) -> None:
        identity = ServiceIdentity.generate()
        session = secrets.token_bytes(16)
        left, right = socket.socketpair()
        client_socket = RecordingSocket(left, bytearray())
        server_socket = RecordingSocket(right, bytearray(), {1: 40})
        result: queue.Queue[BaseException | None] = queue.Queue()

        def accept() -> None:
            try:
                server_handshake(
                    server_socket,
                    identity,
                    expected_session_id=session,
                    protocol_version=VERSION_3,
                )
                result.put(None)
            except BaseException as error:
                result.put(error)
            finally:
                server_socket.close()

        thread = threading.Thread(target=accept, daemon=True)
        thread.start()
        try:
            with self.assertRaises(IdentityVerificationError):
                client_handshake(
                    client_socket,
                    identity.public_key_bytes,
                    session_id=session,
                    protocol_version=VERSION_3,
                )
        finally:
            client_socket.close()
        thread.join(timeout=2.0)
        self.assertIsInstance(result.get_nowait(), ProtocolError)

    def test_downgraded_suite_offer_is_rejected(self) -> None:
        identity = ServiceIdentity.generate()
        session = secrets.token_bytes(16)
        left, right = socket.socketpair()
        client_socket = RecordingSocket(left, bytearray(), {1: 8})
        server_socket = RecordingSocket(right, bytearray())
        result: queue.Queue[BaseException | None] = queue.Queue()

        def accept() -> None:
            try:
                server_handshake(
                    server_socket,
                    identity,
                    expected_session_id=session,
                    protocol_version=VERSION_3,
                )
                result.put(None)
            except BaseException as error:
                result.put(error)
            finally:
                server_socket.close()

        thread = threading.Thread(target=accept, daemon=True)
        thread.start()
        try:
            with self.assertRaises(ProtocolError):
                client_handshake(
                    client_socket,
                    identity.public_key_bytes,
                    session_id=session,
                    protocol_version=VERSION_3,
                )
        finally:
            client_socket.close()
        thread.join(timeout=2.0)
        server_error = result.get_nowait()
        self.assertIsInstance(server_error, ProtocolError)
        self.assertIn("mutually supported", str(server_error))

    def test_signed_wrong_algorithm_selection_is_rejected(self) -> None:
        identity = ServiceIdentity.generate()
        session = secrets.token_bytes(16)
        left, right = socket.socketpair()
        result: queue.Queue[BaseException | None] = queue.Queue()

        def fake_server() -> None:
            try:
                hello = bytearray()
                while len(hello) < CLIENT_HELLO_V3.size:
                    hello.extend(right.recv(CLIENT_HELLO_V3.size - len(hello)))
                fields = CLIENT_HELLO_V3.unpack(bytes(hello))
                body = SERVER_HELLO_BODY_V3.pack(
                    MAGIC_V3,
                    VERSION_3,
                    2,
                    fields[3],
                    fields[5],
                    fields[6],
                    fields[7],
                    b"x" * 32,
                    b"k" * 1088,
                    identity.public_key_bytes,
                    b"s" * 32,
                )
                right.sendall(body + identity.sign(SERVER_AUTH_DOMAIN_V3 + bytes(hello) + body))
                result.put(None)
            except BaseException as error:
                result.put(error)
            finally:
                right.close()

        thread = threading.Thread(target=fake_server, daemon=True)
        thread.start()
        try:
            with self.assertRaisesRegex(ProtocolError, "unoffered crypto suite"):
                client_handshake(
                    left,
                    identity.public_key_bytes,
                    session_id=session,
                    protocol_version=VERSION_3,
                )
        finally:
            left.close()
        thread.join(timeout=2.0)
        self.assertIsNone(result.get_nowait())

    def test_identity_mismatch_and_finished_tampering_are_rejected(self) -> None:
        actual = ServiceIdentity.generate()
        expected = ServiceIdentity.generate()
        session = secrets.token_bytes(16)
        left, right = socket.socketpair()
        result: queue.Queue[BaseException | None] = queue.Queue()

        def accept_identity() -> None:
            try:
                server_handshake(
                    right,
                    actual,
                    expected_session_id=session,
                    protocol_version=VERSION_3,
                )
                result.put(None)
            except BaseException as error:
                result.put(error)
            finally:
                right.close()

        thread = threading.Thread(target=accept_identity, daemon=True)
        thread.start()
        try:
            with self.assertRaises(IdentityVerificationError):
                client_handshake(
                    left,
                    expected.public_key_bytes,
                    session_id=session,
                    protocol_version=VERSION_3,
                )
        finally:
            left.close()
        thread.join(timeout=2.0)
        self.assertIsInstance(result.get_nowait(), ProtocolError)

        session = secrets.token_bytes(16)
        left, right = socket.socketpair()
        client_socket = RecordingSocket(left, bytearray(), {2: -1})
        server_socket = RecordingSocket(right, bytearray())
        result = queue.Queue()

        def accept_finished() -> None:
            try:
                server_handshake(
                    server_socket,
                    actual,
                    expected_session_id=session,
                    protocol_version=VERSION_3,
                )
                result.put(None)
            except BaseException as error:
                result.put(error)
            finally:
                server_socket.close()

        thread = threading.Thread(target=accept_finished, daemon=True)
        thread.start()
        try:
            with self.assertRaises(ProtocolError):
                client_handshake(
                    client_socket,
                    actual.public_key_bytes,
                    session_id=session,
                    protocol_version=VERSION_3,
                )
        finally:
            client_socket.close()
        thread.join(timeout=2.0)
        self.assertIn("key confirmation", str(result.get_nowait()))


if __name__ == "__main__":
    unittest.main()
