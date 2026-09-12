from __future__ import annotations

import secrets
import socket
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from granger_network.cells import (
    CELL_PAYLOAD_SIZE,
    CELL_SIZE,
    MAX_CELLS_PER_BATCH,
    CellMultiplexer,
    CellType,
    CoverTrafficPolicy,
    CoverTrafficProfile,
    RelayCell,
    MuxStream,
    ReceiveMemoryBudget,
    decode_cell,
    encode_cell,
    cover_profile_from_environment,
)
from granger_network.errors import ProtocolError, ResourceLimitError
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
    def test_cell_dispatch_does_not_invert_stream_and_mux_locks(self) -> None:
        client, server = channel_pair()
        mux = CellMultiplexer(client, secrets.token_bytes(16), initiator=True)
        stream = MuxStream(mux, 1, send_credit=1024, opened=True)
        mux._streams[1] = stream
        entered = threading.Event()
        feed = stream._feed

        def blocked_feed(payload):
            entered.set()
            feed(payload)

        worker = threading.Thread(target=mux._handle_cell, args=(
            RelayCell(CellType.DATA, 0, mux.circuit_id, 1, 0, b"asset"),), daemon=True)
        acquired = False
        try:
            with patch.object(stream, "_feed", blocked_feed):
                with stream._condition:
                    worker.start()
                    self.assertTrue(entered.wait(1.0))
                    # recv holds the stream lock while checking mux.failed.
                    # The reader must not hold the mux lock while feeding it.
                    acquired = mux._condition.acquire(timeout=0.2)
                    if acquired:
                        mux._condition.release()
                worker.join(1.0)
            self.assertFalse(worker.is_alive())
            self.assertTrue(acquired, "cell dispatch inverted stream/multiplexer locks")
            self.assertEqual(bytes(stream._buffer), b"asset")
        finally:
            mux.close()
            server.connection.close()
            server.destroy()

    def test_close_wakes_blocked_socket_reader(self) -> None:
        client, server = channel_pair()
        client.connection.settimeout(None)
        receiving = threading.Event()
        receive = client.receive_bytes

        def waiting_receive():
            receiving.set()
            return receive()

        with patch.object(client, "receive_bytes", waiting_receive):
            mux = CellMultiplexer(client, secrets.token_bytes(16), initiator=True)
            try:
                self.assertTrue(receiving.wait(1.0))
                time.sleep(0.05)
                started = time.monotonic()
                mux.close()
                self.assertFalse(mux._reader.is_alive(), "closed socket left its reader blocked")
                self.assertLess(time.monotonic() - started, 1.0)
                mux.close()
            finally:
                server.connection.shutdown(socket.SHUT_RDWR)
                server.connection.close()
                server.destroy()
                mux.close()
                mux._reader.join(1.0)

    def test_shared_receive_budget_bounds_multiple_stream_buffers(self) -> None:
        budget = ReceiveMemoryBudget(1024)
        multiplexer = SimpleNamespace(
            failed=False,
            receive_budget=budget,
            stream_window=4096,
            _send=lambda *_args, **_kwargs: None,
        )
        first = MuxStream(multiplexer, 1, send_credit=4096, opened=True)
        second = MuxStream(multiplexer, 3, send_credit=4096, opened=True)
        first._feed(b"a" * 800)
        second._feed(b"b" * 300)

        self.assertEqual(budget.used_bytes, 800)
        self.assertIsInstance(second._error, ResourceLimitError)
        self.assertEqual(first.recv(800), b"a" * 800)
        self.assertEqual(budget.used_bytes, 0)

        first._feed(b"c" * 512)
        self.assertEqual(budget.used_bytes, 512)
        first.close()
        self.assertEqual(budget.used_bytes, 0)

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

    def test_cover_cells_are_fixed_authenticated_and_never_reach_a_stream(self) -> None:
        circuit = secrets.token_bytes(16)
        cell = RelayCell(CellType.COVER, 0, circuit, 0, 4, b"")
        encoded = encode_cell(cell)
        self.assertEqual(len(encoded), CELL_SIZE)
        self.assertEqual(decode_cell(encoded), cell)
        with self.assertRaises(ProtocolError):
            encode_cell(RelayCell(CellType.COVER, 0, circuit, 1, 4, b""))
        with self.assertRaises(ProtocolError):
            encode_cell(RelayCell(CellType.COVER, 0, circuit, 0, 4, b"application"))

        client_channel, server_channel = channel_pair()
        client_mux = CellMultiplexer(
            client_channel,
            circuit,
            initiator=True,
            cover_profile=CoverTrafficProfile.HIGH_PRIVACY,
        )
        server_mux = CellMultiplexer(server_channel, circuit, initiator=False)
        time.sleep(client_mux.cover_policy.quiet_after_real_seconds + 0.05)
        self.assertTrue(client_mux.send_cover())
        deadline = time.monotonic() + 2.0
        while (
            server_mux.traffic_counters["coverCellsReceived"] != 1
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        self.assertEqual(server_mux.active_streams, 0)
        self.assertEqual(server_mux.traffic_counters["coverCellsReceived"], 1)
        self.assertEqual(client_mux.traffic_counters["coverCellsSent"], 1)
        client_mux.close()
        server_mux.close()

    def test_cover_profile_environment_is_strict_and_supports_low_bandwidth_off(self) -> None:
        from unittest.mock import patch

        with patch.dict("os.environ", {"GRANGER_COVER_PROFILE": "off"}):
            self.assertIs(cover_profile_from_environment(), CoverTrafficProfile.OFF)
        with patch.dict("os.environ", {"GRANGER_COVER_PROFILE": "high"}):
            self.assertIs(
                cover_profile_from_environment(),
                CoverTrafficProfile.HIGH_PRIVACY,
            )
        with patch.dict("os.environ", {"GRANGER_COVER_PROFILE": "unbounded"}):
            with self.assertRaises(ProtocolError):
                cover_profile_from_environment()

    def test_cover_budget_is_bounded_and_yields_when_real_send_owns_channel(self) -> None:
        client_channel, server_channel = channel_pair()
        circuit = secrets.token_bytes(16)
        client_mux = CellMultiplexer(client_channel, circuit, initiator=True)
        server_mux = CellMultiplexer(server_channel, circuit, initiator=False)
        client_mux.cover_policy = CoverTrafficPolicy(
            CoverTrafficProfile.STANDARD,
            0.01,
            0.02,
            0.0,
            2,
        )
        self.assertTrue(client_mux.send_cover())
        self.assertTrue(client_mux.send_cover())
        self.assertFalse(client_mux.send_cover())
        with client_mux._metrics_lock:
            client_mux._cover_send_times.clear()
        client_mux._send_lock.acquire()
        try:
            self.assertFalse(client_mux.send_cover())
        finally:
            client_mux._send_lock.release()
        deadline = time.monotonic() + 2.0
        while (
            server_mux.traffic_counters["coverCellsReceived"] != 2
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        self.assertEqual(server_mux.traffic_counters["coverCellsReceived"], 2)
        client_mux.close()
        server_mux.close()

    def test_cover_send_failure_closes_mux_and_wakes_stream(self) -> None:
        client_channel, server_channel = channel_pair()
        circuit = secrets.token_bytes(16)
        client_mux = CellMultiplexer(client_channel, circuit, initiator=True)
        server_mux = CellMultiplexer(server_channel, circuit, initiator=False)
        accepted: list = []
        accept_thread = threading.Thread(
            target=lambda: accepted.append(server_mux.accept_stream(3.0)),
            daemon=True,
        )
        accept_thread.start()
        sender = client_mux.open_stream(3.0)
        accept_thread.join(timeout=3.0)
        self.assertEqual(len(accepted), 1)
        client_mux.cover_policy = CoverTrafficPolicy(
            CoverTrafficProfile.STANDARD,
            0.01,
            0.02,
            0.0,
            2,
        )

        def fail_send(_payload: bytes, *_args, **_kwargs) -> None:
            raise OSError("simulated transport failure")

        client_channel.send_bytes = fail_send
        self.assertFalse(client_mux.send_cover())
        self.assertTrue(client_mux.failed)
        with self.assertRaises(ProtocolError):
            sender.recv(1)
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

    def test_data_cells_are_bounded_batches_and_malformed_batches_close_channel(self) -> None:
        client_channel, server_channel = channel_pair()
        sent_frames: list[int] = []
        original_send = client_channel.send_bytes

        def record_send(payload: bytes, *args, **kwargs) -> None:
            sent_frames.append(len(payload))
            original_send(payload, *args, **kwargs)

        client_channel.send_bytes = record_send
        circuit = secrets.token_bytes(16)
        client_mux = CellMultiplexer(client_channel, circuit, initiator=True)
        server_mux = CellMultiplexer(server_channel, circuit, initiator=False)
        accepted: list = []
        accept_thread = threading.Thread(
            target=lambda: accepted.append(server_mux.accept_stream(3.0)),
            daemon=True,
        )
        accept_thread.start()
        sender = client_mux.open_stream(3.0)
        accept_thread.join(timeout=3.0)
        sent_frames.clear()
        payload = secrets.token_bytes(CELL_PAYLOAD_SIZE * 10)
        sender.sendall(payload)
        receiver = accepted[0]
        received = bytearray()
        while len(received) < len(payload):
            received.extend(receiver.recv(len(payload) - len(received)))
        self.assertEqual(bytes(received), payload)
        self.assertIn(CELL_SIZE * 10, sent_frames)
        self.assertTrue(
            all(
                size % CELL_SIZE == 0
                and CELL_SIZE <= size <= CELL_SIZE * MAX_CELLS_PER_BATCH
                for size in sent_frames
            )
        )
        client_mux.close()
        server_mux.close()

        attacker_channel, victim_channel = channel_pair()
        victim_mux = CellMultiplexer(
            victim_channel,
            secrets.token_bytes(16),
            initiator=False,
        )
        attacker_channel.send_bytes(b"x" * (CELL_SIZE + 1))
        deadline = time.monotonic() + 3.0
        while not victim_mux.failed and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(victim_mux.failed)
        attacker_channel.destroy()
        attacker_channel.connection.close()
        victim_mux.close()

    def test_fixed_cells_do_not_hide_total_size_or_application_burst_timing(self) -> None:
        def measure(payloads: tuple[bytes, ...], gap_seconds: float = 0.0):
            client_channel, server_channel = channel_pair()
            events: list[tuple[int, int]] = []
            original_send = client_channel.send_bytes

            def record_send(payload: bytes, *args, **kwargs) -> None:
                events.append((time.perf_counter_ns(), len(payload)))
                original_send(payload, *args, **kwargs)

            client_channel.send_bytes = record_send
            circuit = secrets.token_bytes(16)
            client_mux = CellMultiplexer(
                client_channel,
                circuit,
                initiator=True,
                cover_profile=CoverTrafficProfile.OFF,
            )
            server_mux = CellMultiplexer(
                server_channel,
                circuit,
                initiator=False,
                cover_profile=CoverTrafficProfile.OFF,
            )
            accepted: list = []
            accept_thread = threading.Thread(
                target=lambda: accepted.append(server_mux.accept_stream(3.0)),
                daemon=True,
            )
            accept_thread.start()
            sender = client_mux.open_stream(3.0)
            accept_thread.join(timeout=3.0)
            events.clear()
            for index, payload in enumerate(payloads):
                sender.sendall(payload)
                if gap_seconds and index + 1 < len(payloads):
                    time.sleep(gap_seconds)
            expected = sum(len(payload) for payload in payloads)
            received = bytearray()
            while len(received) < expected:
                received.extend(accepted[0].recv(expected - len(received)))
            measured = tuple(events)
            sender.close()
            client_mux.close()
            server_mux.close()
            return measured

        small = measure((b"s" * 97,))
        large_payload = b"l" * (CELL_PAYLOAD_SIZE * 3 + 97)
        large = measure((large_payload,))
        self.assertEqual(sum(size // CELL_SIZE for _time, size in small), 1)
        self.assertEqual(sum(size // CELL_SIZE for _time, size in large), 4)
        self.assertTrue(all(size % CELL_SIZE == 0 for _time, size in (*small, *large)))

        burst = measure((b"a" * 97, b"b" * 97), gap_seconds=0.03)
        self.assertEqual(len(burst), 2)
        visible_gap_seconds = (burst[1][0] - burst[0][0]) / 1_000_000_000
        self.assertGreaterEqual(visible_gap_seconds, 0.015)


if __name__ == "__main__":
    unittest.main()
