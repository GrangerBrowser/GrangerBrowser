from __future__ import annotations

import secrets
import socket
import threading
import time
import unittest

from granger_network.cells import (
    CELL_PAYLOAD_SIZE,
    CELL_SIZE,
    CellMultiplexer,
    CellType,
    RelayCell,
    decode_cell,
    encode_cell,
)
from granger_network.errors import ProtocolError
from granger_network.identity import ServiceIdentity
from granger_network.protocol import VERSION_3, client_handshake, server_handshake


def channel_pair():
    left, right = socket.socketpair()
    left.settimeout(5.0)
    right.settimeout(5.0)
    identity = ServiceIdentity.generate()
    session_id = secrets.token_bytes(16)
    result: list[object] = []

    def accept() -> None:
        try:
            result.append(
                server_handshake(
                    right,
                    identity,
                    expected_session_id=session_id,
                    protocol_version=VERSION_3,
                )
            )
        except BaseException as error:
            result.append(error)

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    client = client_handshake(
        left,
        identity.public_key_bytes,
        session_id=session_id,
        protocol_version=VERSION_3,
    )
    thread.join(timeout=5.0)
    if not result or isinstance(result[0], BaseException):
        raise AssertionError(f"server handshake failed: {result}")
    return client, result[0]


class RelayCellTests(unittest.TestCase):
    def test_cell_encoding_is_fixed_size_padded_and_strict(self) -> None:
        circuit = secrets.token_bytes(16)
        cell = RelayCell(CellType.DATA, 0, circuit, 1, 0, b"secret")
        encoded_a = encode_cell(cell)
        encoded_b = encode_cell(cell)
        self.assertEqual(len(encoded_a), CELL_SIZE)
        self.assertEqual(len(encoded_b), CELL_SIZE)
        self.assertNotEqual(encoded_a, encoded_b)
        self.assertEqual(decode_cell(encoded_a), cell)
        with self.assertRaisesRegex(ProtocolError, "fixed"):
            decode_cell(encoded_a[:-1])
        unknown = bytearray(encoded_a)
        unknown[5] = 0xFF
        with self.assertRaisesRegex(ProtocolError, "unknown"):
            decode_cell(bytes(unknown))
        with self.assertRaises(ProtocolError):
            encode_cell(RelayCell(CellType.DATA, 0, circuit, 1, 0, b"x" * (CELL_PAYLOAD_SIZE + 1)))

    def test_multiplexer_fragments_reassembles_and_separates_streams(self) -> None:
        client_channel, server_channel = channel_pair()
        circuit = secrets.token_bytes(16)
        client_mux = CellMultiplexer(client_channel, circuit, initiator=True)
        server_mux = CellMultiplexer(server_channel, circuit, initiator=False)
        accepted: list = []
        failures: list[BaseException] = []

        def accept_two() -> None:
            try:
                accepted.extend(
                    [server_mux.accept_stream(3.0), server_mux.accept_stream(3.0)]
                )
            except BaseException as error:
                failures.append(error)

        thread = threading.Thread(target=accept_two, daemon=True)
        thread.start()
        first = client_mux.open_stream(3.0)
        second = client_mux.open_stream(3.0)
        thread.join(timeout=4.0)
        self.assertEqual(failures, [])
        self.assertEqual(len(accepted), 2)
        payload_a = b"a" * (CELL_PAYLOAD_SIZE * 3 + 117)
        payload_b = b"b" * (CELL_PAYLOAD_SIZE + 31)
        first.sendall(payload_a)
        second.sendall(payload_b)

        def read_exact(stream, size: int) -> bytes:
            content = bytearray()
            while len(content) < size:
                content.extend(stream.recv(size - len(content)))
            return bytes(content)

        by_id = {stream.stream_id: stream for stream in accepted}
        self.assertEqual(read_exact(by_id[first.stream_id], len(payload_a)), payload_a)
        self.assertEqual(read_exact(by_id[second.stream_id], len(payload_b)), payload_b)
        by_id[first.stream_id].sendall(b"response-a")
        by_id[second.stream_id].sendall(b"response-b")
        self.assertEqual(first.recv(64), b"response-a")
        self.assertEqual(second.recv(64), b"response-b")
        first.close()
        second.close()
        client_mux.close()
        server_mux.close()

    def test_flow_control_blocks_sender_until_receiver_consumes(self) -> None:
        client_channel, server_channel = channel_pair()
        circuit = secrets.token_bytes(16)
        window = CELL_PAYLOAD_SIZE * 2
        client_mux = CellMultiplexer(
            client_channel,
            circuit,
            initiator=True,
            stream_window=window,
        )
        server_mux = CellMultiplexer(
            server_channel,
            circuit,
            initiator=False,
            stream_window=window,
        )
        accepted: list = []
        accept_thread = threading.Thread(
            target=lambda: accepted.append(server_mux.accept_stream(3.0)),
            daemon=True,
        )
        accept_thread.start()
        sender = client_mux.open_stream(3.0)
        accept_thread.join(timeout=3.0)
        receiver = accepted[0]
        payload = secrets.token_bytes(window * 4)
        failures: list[BaseException] = []

        def send() -> None:
            try:
                sender.sendall(payload)
            except BaseException as error:
                failures.append(error)

        send_thread = threading.Thread(target=send, daemon=True)
        send_thread.start()
        time.sleep(0.1)
        self.assertTrue(send_thread.is_alive(), "sender bypassed the explicit receive window")
        received = bytearray()
        while len(received) < len(payload):
            received.extend(receiver.recv(4096))
        send_thread.join(timeout=3.0)
        self.assertFalse(send_thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(bytes(received), payload)
        client_mux.close()
        server_mux.close()


if __name__ == "__main__":
    unittest.main()
