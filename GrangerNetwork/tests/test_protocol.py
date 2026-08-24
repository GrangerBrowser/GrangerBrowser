from __future__ import annotations

import queue
import socket
import threading
import unittest

from granger_network.errors import IdentityVerificationError, ProtocolError, ReplayError
from granger_network.identity import ServiceIdentity
from granger_network.protocol import VERSION_2, SecureChannel, client_handshake, server_handshake


class RecordingSocket:
    def __init__(self, wrapped: socket.socket, wire: bytearray) -> None:
        self._wrapped = wrapped
        self._wire = wire
        self.mutate_next_send = False
        self.sent_chunks: list[bytes] = []

    def sendall(self, data: bytes) -> None:
        transmitted = data
        if self.mutate_next_send:
            self.mutate_next_send = False
            modified = bytearray(data)
            modified[-1] ^= 0x01
            transmitted = bytes(modified)
        self.sent_chunks.append(transmitted)
        self._wire.extend(transmitted)
        self._wrapped.sendall(transmitted)

    def replay(self, data: bytes) -> None:
        self._wire.extend(data)
        self._wrapped.sendall(data)

    def __getattr__(self, name: str):
        return getattr(self._wrapped, name)


def establish_channels(
    identity: ServiceIdentity,
) -> tuple[SecureChannel, SecureChannel, bytearray, tuple[RecordingSocket, RecordingSocket]]:
    left, right = socket.socketpair()
    wire = bytearray()
    client_socket = RecordingSocket(left, wire)
    server_socket = RecordingSocket(right, wire)
    result: queue.Queue[SecureChannel | BaseException] = queue.Queue()

    def accept_handshake() -> None:
        try:
            result.put(server_handshake(server_socket, identity))
        except BaseException as error:
            result.put(error)

    thread = threading.Thread(target=accept_handshake, daemon=True)
    thread.start()
    client_channel = client_handshake(client_socket, identity.public_key_bytes)
    thread.join(timeout=2.0)
    if thread.is_alive():
        raise AssertionError("server handshake did not finish")
    server_result = result.get_nowait()
    if isinstance(server_result, BaseException):
        raise server_result
    return client_channel, server_result, wire, (client_socket, server_socket)


class ProtocolTests(unittest.TestCase):
    def test_handshake_authenticates_and_frames_are_encrypted(self) -> None:
        identity = ServiceIdentity.generate()
        client, server, wire, sockets = establish_channels(identity)
        request_secret = b"private-request-marker"
        response_secret = b"private-response-marker"
        try:
            client.send_bytes(request_secret)
            self.assertEqual(server.receive_bytes(), request_secret)
            server.send_bytes(response_secret)
            self.assertEqual(client.receive_bytes(), response_secret)
            self.assertNotIn(request_secret, wire)
            self.assertNotIn(response_secret, wire)
        finally:
            sockets[0].close()
            sockets[1].close()

    def test_client_rejects_a_different_service_identity(self) -> None:
        actual_identity = ServiceIdentity.generate()
        expected_identity = ServiceIdentity.generate()
        left, right = socket.socketpair()
        server_finished = threading.Event()

        def run_server() -> None:
            try:
                server_handshake(right, actual_identity)
            finally:
                server_finished.set()
                right.close()

        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()
        try:
            with self.assertRaises(IdentityVerificationError):
                client_handshake(left, expected_identity.public_key_bytes)
        finally:
            left.close()
            server_finished.wait(timeout=2.0)
            thread.join(timeout=2.0)

    def test_modified_encrypted_frame_is_rejected(self) -> None:
        identity = ServiceIdentity.generate()
        client, server, _wire, sockets = establish_channels(identity)
        try:
            sockets[0].mutate_next_send = True
            client.send_bytes(b"authenticated payload")
            with self.assertRaises(ProtocolError):
                server.receive_bytes()
        finally:
            sockets[0].close()
            sockets[1].close()

    def test_v2_session_is_bound_and_replayed_frame_is_rejected(self) -> None:
        identity = ServiceIdentity.generate()
        session_id = b"v0.2-session-id!"
        left, right = socket.socketpair()
        wire = bytearray()
        client_socket = RecordingSocket(left, wire)
        server_socket = RecordingSocket(right, wire)
        result: queue.Queue[SecureChannel | BaseException] = queue.Queue()

        def accept_handshake() -> None:
            try:
                result.put(
                    server_handshake(
                        server_socket,
                        identity,
                        expected_session_id=session_id,
                        protocol_version=VERSION_2,
                    )
                )
            except BaseException as error:
                result.put(error)

        thread = threading.Thread(target=accept_handshake, daemon=True)
        thread.start()
        client = client_handshake(
            client_socket,
            identity.public_key_bytes,
            session_id=session_id,
            protocol_version=VERSION_2,
        )
        thread.join(timeout=2.0)
        server = result.get_nowait()
        if isinstance(server, BaseException):
            raise server
        try:
            self.assertEqual(client.session_id, session_id)
            self.assertEqual(server.session_id, session_id)
            client_socket.sent_chunks.clear()
            client.send_bytes(b"single-use encrypted frame")
            encrypted_frame = client_socket.sent_chunks[-1]
            self.assertEqual(server.receive_bytes(), b"single-use encrypted frame")
            client_socket.replay(encrypted_frame)
            with self.assertRaises(ReplayError):
                server.receive_bytes()
        finally:
            client_socket.close()
            server_socket.close()

    def test_v2_stale_handshake_is_rejected(self) -> None:
        identity = ServiceIdentity.generate()
        session_id = b"stale-session-id"
        left, right = socket.socketpair()
        result: queue.Queue[BaseException | None] = queue.Queue()

        def accept_handshake() -> None:
            try:
                server_handshake(
                    right,
                    identity,
                    expected_session_id=session_id,
                    protocol_version=VERSION_2,
                    now=1_000,
                )
                result.put(None)
            except BaseException as error:
                result.put(error)
            finally:
                right.close()

        thread = threading.Thread(target=accept_handshake, daemon=True)
        thread.start()
        try:
            with self.assertRaises(ProtocolError):
                client_handshake(
                    left,
                    identity.public_key_bytes,
                    session_id=session_id,
                    protocol_version=VERSION_2,
                    now=800,
                )
        finally:
            left.close()
        thread.join(timeout=2.0)
        server_result = result.get_nowait()
        self.assertIsInstance(server_result, ReplayError)


if __name__ == "__main__":
    unittest.main()
