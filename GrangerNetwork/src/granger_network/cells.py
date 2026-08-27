from __future__ import annotations

import os
import secrets
import struct
import threading
import time
from collections import deque
from dataclasses import dataclass
from enum import Enum, IntEnum

from .errors import ProtocolError, ResourceLimitError
from .protocol import VERSION_3, SecureChannel


CELL_MAGIC = b"GNC1"
CELL_VERSION = 1
CELL_SIZE = 1024
CELL_HEADER = struct.Struct("!4sBBBB16sIQH")
CELL_PAYLOAD_SIZE = CELL_SIZE - CELL_HEADER.size
CELL_FLAG_ACK = 0x01
CELL_ALLOWED_FLAGS = CELL_FLAG_ACK
DEFAULT_STREAM_WINDOW = 256 * 1024
MAX_STREAM_WINDOW = 4 * 1024 * 1024
MAX_STREAMS_PER_MULTIPLEXER = 1024
MAX_CELL_SEQUENCE = 2**64 - 1
MAX_CELLS_PER_BATCH = 64


class CellType(IntEnum):
    OPEN = 1
    DATA = 2
    CLOSE = 3
    RESET = 4
    WINDOW_UPDATE = 5
    COVER = 6


class CoverTrafficProfile(str, Enum):
    OFF = "off"
    LIGHT = "light"
    STANDARD = "standard"
    HIGH_PRIVACY = "high-privacy"


@dataclass(frozen=True)
class CoverTrafficPolicy:
    profile: CoverTrafficProfile
    minimum_interval_seconds: float
    maximum_interval_seconds: float
    quiet_after_real_seconds: float
    max_cells_per_minute: int

    @classmethod
    def for_profile(
        cls,
        profile: CoverTrafficProfile | str,
    ) -> "CoverTrafficPolicy":
        try:
            normalized = (
                profile
                if isinstance(profile, CoverTrafficProfile)
                else CoverTrafficProfile(str(profile).strip().lower())
            )
        except ValueError as error:
            raise ProtocolError("cover traffic profile is invalid") from error
        values = {
            CoverTrafficProfile.OFF: (0.0, 0.0, 0.0, 0),
            CoverTrafficProfile.LIGHT: (7.5, 15.0, 2.0, 6),
            CoverTrafficProfile.STANDARD: (3.5, 8.0, 1.5, 14),
            CoverTrafficProfile.HIGH_PRIVACY: (1.5, 4.0, 0.75, 32),
        }
        return cls(normalized, *values[normalized])


def cover_profile_from_environment(
    default: CoverTrafficProfile = CoverTrafficProfile.STANDARD,
) -> CoverTrafficProfile:
    value = os.environ.get("GRANGER_COVER_PROFILE", default.value).strip().lower()
    aliases = {"high": CoverTrafficProfile.HIGH_PRIVACY.value}
    try:
        return CoverTrafficProfile(aliases.get(value, value))
    except ValueError as error:
        raise ProtocolError("GRANGER_COVER_PROFILE is invalid") from error


class RelayCell:
    __slots__ = ("cell_type", "flags", "circuit_id", "stream_id", "sequence", "payload")

    def __init__(
        self,
        cell_type: CellType,
        flags: int,
        circuit_id: bytes,
        stream_id: int,
        sequence: int,
        payload: bytes,
    ) -> None:
        self.cell_type = cell_type
        self.flags = flags
        self.circuit_id = circuit_id
        self.stream_id = stream_id
        self.sequence = sequence
        self.payload = payload

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RelayCell):
            return NotImplemented
        return (
            self.cell_type,
            self.flags,
            self.circuit_id,
            self.stream_id,
            self.sequence,
            self.payload,
        ) == (
            other.cell_type,
            other.flags,
            other.circuit_id,
            other.stream_id,
            other.sequence,
            other.payload,
        )


def encode_cell(cell: RelayCell, padding_factory=secrets.token_bytes) -> bytes:
    if not isinstance(cell.cell_type, CellType):
        raise ProtocolError("relay cell type is invalid")
    if (
        isinstance(cell.flags, bool)
        or not isinstance(cell.flags, int)
        or cell.flags & ~CELL_ALLOWED_FLAGS
        or (cell.cell_type is not CellType.OPEN and cell.flags)
    ):
        raise ProtocolError("relay cell flags are invalid")
    if not isinstance(cell.circuit_id, bytes) or len(cell.circuit_id) != 16:
        raise ProtocolError("relay cell circuit identifier is invalid")
    is_cover = cell.cell_type is CellType.COVER
    if (
        isinstance(cell.stream_id, bool)
        or not isinstance(cell.stream_id, int)
        or (is_cover and cell.stream_id != 0)
        or (not is_cover and not 1 <= cell.stream_id <= 0xFFFFFFFF)
    ):
        raise ProtocolError("relay cell stream identifier is invalid")
    if (
        isinstance(cell.sequence, bool)
        or not isinstance(cell.sequence, int)
        or not 0 <= cell.sequence <= MAX_CELL_SEQUENCE
    ):
        raise ProtocolError("relay cell sequence is invalid")
    if not isinstance(cell.payload, bytes) or len(cell.payload) > CELL_PAYLOAD_SIZE:
        raise ProtocolError("relay cell payload exceeds its fixed cell capacity")
    if is_cover and cell.payload:
        raise ProtocolError("relay COVER cell contains application data")
    header = CELL_HEADER.pack(
        CELL_MAGIC,
        CELL_VERSION,
        int(cell.cell_type),
        cell.flags,
        0,
        cell.circuit_id,
        cell.stream_id,
        cell.sequence,
        len(cell.payload),
    )
    padding_size = CELL_PAYLOAD_SIZE - len(cell.payload)
    padding = padding_factory(padding_size)
    if not isinstance(padding, bytes) or len(padding) != padding_size:
        raise ProtocolError("relay cell padding source returned an invalid value")
    return header + cell.payload + padding


def decode_cell(content: bytes) -> RelayCell:
    if not isinstance(content, bytes) or len(content) != CELL_SIZE:
        raise ProtocolError("relay cell is not the fixed protocol size")
    (
        magic,
        version,
        raw_type,
        flags,
        reserved,
        circuit_id,
        stream_id,
        sequence,
        payload_size,
    ) = CELL_HEADER.unpack(content[: CELL_HEADER.size])
    if magic != CELL_MAGIC or version != CELL_VERSION or reserved != 0:
        raise ProtocolError("relay cell header is invalid")
    try:
        cell_type = CellType(raw_type)
    except ValueError as error:
        raise ProtocolError("relay cell type is unknown") from error
    if flags & ~CELL_ALLOWED_FLAGS or (cell_type is not CellType.OPEN and flags):
        raise ProtocolError("relay cell flags are invalid")
    is_cover = cell_type is CellType.COVER
    if (
        (is_cover and stream_id != 0)
        or (not is_cover and not 1 <= stream_id <= 0xFFFFFFFF)
        or payload_size > CELL_PAYLOAD_SIZE
        or (is_cover and payload_size != 0)
    ):
        raise ProtocolError("relay cell field is outside its limit")
    return RelayCell(
        cell_type,
        flags,
        circuit_id,
        stream_id,
        sequence,
        content[CELL_HEADER.size : CELL_HEADER.size + payload_size],
    )


class MuxStream:
    def __init__(
        self,
        multiplexer: "CellMultiplexer",
        stream_id: int,
        *,
        send_credit: int,
        opened: bool,
    ) -> None:
        self.multiplexer = multiplexer
        self.stream_id = stream_id
        self._send_credit = send_credit
        self._buffer = bytearray()
        self._received_not_consumed = 0
        self._open = threading.Event()
        if opened:
            self._open.set()
        self._condition = threading.Condition()
        self._local_closed = False
        self._remote_closed = False
        self._error: BaseException | None = None
        self._timeout: float | None = None

    def _wait_deadline(self) -> float | None:
        return None if self._timeout is None else time.monotonic() + self._timeout

    @property
    def closed(self) -> bool:
        with self._condition:
            stream_closed = (
                self._local_closed
                or self._remote_closed
                or self._error is not None
            )
        return stream_closed or self.multiplexer.failed

    def _wait(self, predicate, deadline: float | None) -> None:
        while not predicate():
            if self._error is not None:
                raise ProtocolError(f"multiplexed stream failed: {type(self._error).__name__}")
            if self.multiplexer.failed:
                raise ProtocolError("multiplexed channel is unavailable")
            timeout = None if deadline is None else deadline - time.monotonic()
            if timeout is not None and timeout <= 0:
                raise TimeoutError("multiplexed stream operation timed out")
            self._condition.wait(timeout)

    def _mark_open(self, credit: int) -> None:
        with self._condition:
            if self._open.is_set() or not 1 <= credit <= MAX_STREAM_WINDOW:
                self._fail(ProtocolError("multiplexed stream OPEN acknowledgement is invalid"))
                return
            self._send_credit = credit
            self._open.set()
            self._condition.notify_all()

    def _feed(self, payload: bytes) -> None:
        with self._condition:
            if self._remote_closed or self._error is not None:
                return
            if self._received_not_consumed + len(payload) > self.multiplexer.stream_window:
                self._fail(ResourceLimitError("multiplexed stream receive window was exceeded"))
                return
            self._buffer.extend(payload)
            self._received_not_consumed += len(payload)
            self._condition.notify_all()

    def _add_credit(self, credit: int) -> None:
        with self._condition:
            if not 1 <= credit <= MAX_STREAM_WINDOW or self._send_credit + credit > MAX_STREAM_WINDOW:
                self._fail(ProtocolError("multiplexed stream flow-control update is invalid"))
                return
            self._send_credit += credit
            self._condition.notify_all()

    def _remote_close(self, reset: bool = False) -> None:
        with self._condition:
            self._remote_closed = True
            if reset:
                self._error = ProtocolError("multiplexed stream was reset")
            self._condition.notify_all()

    def _fail(self, error: BaseException) -> None:
        with self._condition:
            if self._error is None:
                self._error = error
            self._condition.notify_all()

    def wait_open(self) -> None:
        deadline = self._wait_deadline()
        with self._condition:
            self._wait(self._open.is_set, deadline)

    def sendall(self, data: bytes) -> None:
        if not isinstance(data, bytes):
            raise ProtocolError("multiplexed stream accepts only bytes")
        if not data:
            return
        self.wait_open()
        offset = 0
        deadline = self._wait_deadline()
        while offset < len(data):
            with self._condition:
                self._wait(
                    lambda: self._send_credit > 0 or self._local_closed or self._remote_closed,
                    deadline,
                )
                if self._local_closed or self._remote_closed:
                    raise ProtocolError("multiplexed stream is closed")
                size = min(
                    CELL_PAYLOAD_SIZE * MAX_CELLS_PER_BATCH,
                    self._send_credit,
                    len(data) - offset,
                )
                chunk = data[offset : offset + size]
                self._send_credit -= size
            self.multiplexer._send_data_batch(self.stream_id, chunk)
            offset += size

    def recv(self, size: int) -> bytes:
        if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
            raise ProtocolError("multiplexed stream receive size is invalid")
        deadline = self._wait_deadline()
        with self._condition:
            self._wait(
                lambda: bool(self._buffer)
                or self._remote_closed
                or self._local_closed,
                deadline,
            )
            if not self._buffer and (self._remote_closed or self._local_closed):
                return b""
            result = bytes(self._buffer[:size])
            del self._buffer[:size]
            self._received_not_consumed -= len(result)
        if result:
            self.multiplexer._send(
                CellType.WINDOW_UPDATE,
                self.stream_id,
                len(result).to_bytes(4, "big"),
            )
        return result

    def settimeout(self, value: float | None) -> None:
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0
        ):
            raise ProtocolError("multiplexed stream timeout is invalid")
        self._timeout = None if value is None else float(value)

    def close(self) -> None:
        with self._condition:
            if self._local_closed:
                return
            self._local_closed = True
            self._condition.notify_all()
        if not self.multiplexer.failed:
            try:
                self.multiplexer._send(CellType.CLOSE, self.stream_id, b"")
            except (OSError, ProtocolError):
                pass

    def reset(self) -> None:
        with self._condition:
            if self._local_closed:
                return
            self._local_closed = True
            self._error = ProtocolError("multiplexed stream was reset locally")
            self._condition.notify_all()
        if not self.multiplexer.failed:
            try:
                self.multiplexer._send(CellType.RESET, self.stream_id, b"")
            except (OSError, ProtocolError):
                pass


class CellMultiplexer:
    def __init__(
        self,
        channel: SecureChannel,
        circuit_id: bytes,
        *,
        initiator: bool,
        stream_window: int = DEFAULT_STREAM_WINDOW,
        max_streams: int = MAX_STREAMS_PER_MULTIPLEXER,
        cover_profile: CoverTrafficProfile | str = CoverTrafficProfile.OFF,
    ) -> None:
        if not isinstance(channel, SecureChannel) or channel.protocol_version != VERSION_3:
            raise ProtocolError("relay cells require a wire 3 channel")
        if not isinstance(circuit_id, bytes) or len(circuit_id) != 16:
            raise ProtocolError("relay circuit identifier is invalid")
        if (
            isinstance(stream_window, bool)
            or not isinstance(stream_window, int)
            or not CELL_PAYLOAD_SIZE <= stream_window <= MAX_STREAM_WINDOW
            or isinstance(max_streams, bool)
            or not isinstance(max_streams, int)
            or not 1 <= max_streams <= MAX_STREAMS_PER_MULTIPLEXER
        ):
            raise ResourceLimitError("relay multiplexer limits are invalid")
        self.channel = channel
        self.circuit_id = circuit_id
        self.initiator = initiator
        self.stream_window = stream_window
        self.max_streams = max_streams
        self.cover_policy = CoverTrafficPolicy.for_profile(cover_profile)
        self._streams: dict[int, MuxStream] = {}
        self._accept_queue: deque[MuxStream] = deque()
        self._condition = threading.Condition()
        self._send_lock = threading.Lock()
        self._metrics_lock = threading.Lock()
        self._tx_sequence = 0
        self._rx_sequence = 0
        self._next_stream_id = 1 if initiator else 2
        self._failed: BaseException | None = None
        self._closed = False
        self._real_send_waiters = 0
        self._last_real_send = time.monotonic()
        self._real_cells_sent = 0
        self._cover_cells_sent = 0
        self._cover_cells_received = 0
        self._cover_send_times: deque[float] = deque()
        self._cover_stop = threading.Event()
        self._cover_thread: threading.Thread | None = None
        self._reader = threading.Thread(
            target=self._read_loop,
            name=f"granger-cell-{circuit_id.hex()[:8]}",
            daemon=True,
        )
        self._reader.start()
        if self.cover_policy.profile is not CoverTrafficProfile.OFF:
            self._cover_thread = threading.Thread(
                target=self._cover_loop,
                name=f"granger-cover-{circuit_id.hex()[:8]}",
                daemon=True,
            )
            self._cover_thread.start()

    @property
    def failed(self) -> bool:
        with self._condition:
            return self._failed is not None or self._closed

    @property
    def active_streams(self) -> int:
        with self._condition:
            return len(self._streams)

    @property
    def traffic_counters(self) -> dict[str, int | str]:
        with self._metrics_lock:
            return {
                "coverBytesSent": self._cover_cells_sent * CELL_SIZE,
                "coverCellsReceived": self._cover_cells_received,
                "coverCellsSent": self._cover_cells_sent,
                "profile": self.cover_policy.profile.value,
                "realCellsSent": self._real_cells_sent,
            }

    def _send(self, cell_type: CellType, stream_id: int, payload: bytes, flags: int = 0) -> None:
        self._send_batch(((cell_type, stream_id, payload, flags),))

    def _send_data_batch(self, stream_id: int, payload: bytes) -> None:
        if not isinstance(payload, bytes) or not payload:
            raise ProtocolError("relay DATA batch is empty")
        cells = tuple(
            (
                CellType.DATA,
                stream_id,
                payload[offset : offset + CELL_PAYLOAD_SIZE],
                0,
            )
            for offset in range(0, len(payload), CELL_PAYLOAD_SIZE)
        )
        self._send_batch(cells)

    def _send_batch(
        self,
        cells: tuple[tuple[CellType, int, bytes, int], ...],
    ) -> None:
        if not 1 <= len(cells) <= MAX_CELLS_PER_BATCH:
            raise ProtocolError("relay cell batch count is invalid")
        with self._metrics_lock:
            self._real_send_waiters += 1
        self._send_lock.acquire()
        try:
            with self._metrics_lock:
                self._real_send_waiters -= 1
            if self._failed is not None or self._closed:
                raise ProtocolError("relay multiplexer is closed")
            self._transmit_locked(cells)
            with self._metrics_lock:
                self._last_real_send = time.monotonic()
                self._real_cells_sent += len(cells)
        finally:
            self._send_lock.release()

    def _transmit_locked(
        self,
        cells: tuple[tuple[CellType, int, bytes, int], ...],
    ) -> None:
        if self._tx_sequence > MAX_CELL_SEQUENCE - (len(cells) - 1):
            raise ProtocolError("relay cell transmit sequence is exhausted")
        encoded = b"".join(
            encode_cell(
                RelayCell(
                    cell_type,
                    flags,
                    self.circuit_id,
                    stream_id,
                    self._tx_sequence + index,
                    payload,
                )
            )
            for index, (cell_type, stream_id, payload, flags) in enumerate(cells)
        )
        self.channel.send_bytes(encoded)
        self._tx_sequence += len(cells)

    def send_cover(self) -> bool:
        policy = self.cover_policy
        if policy.profile is CoverTrafficProfile.OFF:
            return False
        now = time.monotonic()
        with self._metrics_lock:
            while self._cover_send_times and now - self._cover_send_times[0] >= 60.0:
                self._cover_send_times.popleft()
            if (
                self._real_send_waiters
                or now - self._last_real_send < policy.quiet_after_real_seconds
                or len(self._cover_send_times) >= policy.max_cells_per_minute
            ):
                return False
        if not self._send_lock.acquire(blocking=False):
            return False
        try:
            now = time.monotonic()
            with self._metrics_lock:
                if (
                    self._real_send_waiters
                    or now - self._last_real_send < policy.quiet_after_real_seconds
                ):
                    return False
            if self._failed is not None or self._closed:
                return False
            self._transmit_locked(((CellType.COVER, 0, b"", 0),))
            with self._metrics_lock:
                self._cover_send_times.append(now)
                self._cover_cells_sent += 1
            return True
        except (OSError, ProtocolError) as error:
            if not self._closed:
                self._fail(error)
            return False
        finally:
            self._send_lock.release()

    def _cover_loop(self) -> None:
        policy = self.cover_policy
        random_source = secrets.SystemRandom()
        while not self._cover_stop.wait(
            random_source.uniform(
                policy.minimum_interval_seconds,
                policy.maximum_interval_seconds,
            )
        ):
            self.send_cover()

    def open_stream(self, timeout: float = 10.0) -> MuxStream:
        with self._condition:
            if self._failed is not None or self._closed:
                raise ProtocolError("relay multiplexer is closed")
            if len(self._streams) >= self.max_streams or self._next_stream_id > 0xFFFFFFFF:
                raise ResourceLimitError("relay stream limit is exhausted")
            stream_id = self._next_stream_id
            self._next_stream_id += 2
            stream = MuxStream(self, stream_id, send_credit=0, opened=False)
            stream.settimeout(timeout)
            self._streams[stream_id] = stream
        try:
            self._send(
                CellType.OPEN,
                stream_id,
                self.stream_window.to_bytes(4, "big"),
            )
            stream.wait_open()
            return stream
        except Exception:
            stream.reset()
            raise

    def accept_stream(self, timeout: float = 10.0) -> MuxStream:
        deadline = time.monotonic() + timeout
        with self._condition:
            while not self._accept_queue:
                if self._failed is not None or self._closed:
                    raise ProtocolError("relay multiplexer is closed")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("relay stream accept timed out")
                self._condition.wait(remaining)
            stream = self._accept_queue.popleft()
            stream.settimeout(timeout)
            return stream

    def _fail(self, error: BaseException) -> None:
        with self._condition:
            if self._failed is None:
                self._failed = error
            streams = tuple(self._streams.values())
            self._condition.notify_all()
        for stream in streams:
            stream._fail(error)

    def _read_loop(self) -> None:
        try:
            while True:
                batch = self.channel.receive_bytes()
                if (
                    not batch
                    or len(batch) % CELL_SIZE
                    or len(batch) > CELL_SIZE * MAX_CELLS_PER_BATCH
                ):
                    raise ProtocolError("relay cell batch framing is invalid")
                for offset in range(0, len(batch), CELL_SIZE):
                    cell = decode_cell(batch[offset : offset + CELL_SIZE])
                    if cell.circuit_id != self.circuit_id:
                        raise ProtocolError("relay cell belongs to a different circuit")
                    if cell.sequence != self._rx_sequence:
                        raise ProtocolError("relay cell sequence is out of order")
                    self._rx_sequence += 1
                    self._handle_cell(cell)
        except BaseException as error:
            if not self._closed:
                self._fail(error)

    def _handle_cell(self, cell: RelayCell) -> None:
        if cell.cell_type is CellType.COVER:
            with self._metrics_lock:
                self._cover_cells_received += 1
            return
        with self._condition:
            stream = self._streams.get(cell.stream_id)
            if cell.cell_type is CellType.OPEN:
                if len(cell.payload) != 4:
                    raise ProtocolError("relay stream OPEN payload is invalid")
                credit = int.from_bytes(cell.payload, "big")
                if not 1 <= credit <= MAX_STREAM_WINDOW:
                    raise ProtocolError("relay stream OPEN window is invalid")
                if cell.flags & CELL_FLAG_ACK:
                    if stream is None:
                        raise ProtocolError("relay stream OPEN acknowledgement is unsolicited")
                    stream._mark_open(credit)
                    return
                expected_parity = 0 if self.initiator else 1
                if cell.stream_id % 2 != expected_parity:
                    raise ProtocolError("relay stream identifier parity is invalid")
                if stream is not None or len(self._streams) >= self.max_streams:
                    raise ResourceLimitError("relay stream limit is exhausted")
                stream = MuxStream(self, cell.stream_id, send_credit=credit, opened=True)
                self._streams[cell.stream_id] = stream
                self._accept_queue.append(stream)
                self._condition.notify_all()
            elif stream is None:
                raise ProtocolError("relay cell references an unknown stream")
            elif cell.cell_type is CellType.DATA:
                if not cell.payload:
                    raise ProtocolError("relay DATA cell is empty")
                stream._feed(cell.payload)
            elif cell.cell_type is CellType.WINDOW_UPDATE:
                if len(cell.payload) != 4:
                    raise ProtocolError("relay flow-control update is invalid")
                stream._add_credit(int.from_bytes(cell.payload, "big"))
            elif cell.cell_type is CellType.CLOSE:
                if cell.payload:
                    raise ProtocolError("relay CLOSE cell has a payload")
                stream._remote_close()
            elif cell.cell_type is CellType.RESET:
                if cell.payload:
                    raise ProtocolError("relay RESET cell has a payload")
                stream._remote_close(reset=True)
            else:
                raise ProtocolError("relay cell state is invalid")
        if cell.cell_type is CellType.OPEN and not cell.flags & CELL_FLAG_ACK:
            self._send(
                CellType.OPEN,
                cell.stream_id,
                self.stream_window.to_bytes(4, "big"),
                CELL_FLAG_ACK,
            )

    def close(self) -> None:
        with self._condition:
            if self._closed:
                return
            self._closed = True
            streams = tuple(self._streams.values())
            self._condition.notify_all()
        self._cover_stop.set()
        for stream in streams:
            stream._fail(ProtocolError("relay multiplexer closed"))
        self.channel.destroy()
        try:
            self.channel.connection.close()
        except OSError:
            pass
        if self._reader is not threading.current_thread():
            self._reader.join(timeout=2.0)
        if (
            self._cover_thread is not None
            and self._cover_thread is not threading.current_thread()
        ):
            self._cover_thread.join(timeout=1.0)
