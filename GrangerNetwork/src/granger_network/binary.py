from __future__ import annotations

import struct

from .errors import ProtocolError


class BinaryWriter:
    def __init__(self, maximum: int) -> None:
        if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum <= 0:
            raise ProtocolError("binary writer limit is invalid")
        self.maximum = maximum
        self._parts: list[bytes] = []
        self._size = 0

    def _append(self, value: bytes) -> None:
        if self._size + len(value) > self.maximum:
            raise ProtocolError("binary message exceeds its size limit")
        self._parts.append(value)
        self._size += len(value)

    def u8(self, value: int) -> "BinaryWriter":
        self._integer(value, 0xFF, "!B")
        return self

    def u16(self, value: int) -> "BinaryWriter":
        self._integer(value, 0xFFFF, "!H")
        return self

    def u32(self, value: int) -> "BinaryWriter":
        self._integer(value, 0xFFFFFFFF, "!I")
        return self

    def u64(self, value: int) -> "BinaryWriter":
        self._integer(value, 0xFFFFFFFFFFFFFFFF, "!Q")
        return self

    def _integer(self, value: int, maximum: int, format_string: str) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
            raise ProtocolError("binary integer is outside its encoded range")
        self._append(struct.pack(format_string, value))

    def fixed(self, value: bytes, size: int) -> "BinaryWriter":
        if not isinstance(value, bytes) or len(value) != size:
            raise ProtocolError("binary fixed field has an invalid size")
        self._append(value)
        return self

    def bytes_u16(self, value: bytes, maximum: int = 0xFFFF) -> "BinaryWriter":
        if not isinstance(value, bytes) or len(value) > min(maximum, 0xFFFF):
            raise ProtocolError("binary byte field has an invalid size")
        self.u16(len(value))
        self._append(value)
        return self

    def bytes_u32(self, value: bytes, maximum: int) -> "BinaryWriter":
        if not isinstance(value, bytes) or len(value) > min(maximum, 0xFFFFFFFF):
            raise ProtocolError("binary byte field has an invalid size")
        self.u32(len(value))
        self._append(value)
        return self

    def text_u16(self, value: str, maximum: int = 0xFFFF) -> "BinaryWriter":
        if not isinstance(value, str):
            raise ProtocolError("binary text field must be text")
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ProtocolError("binary text field is not valid UTF-8") from error
        return self.bytes_u16(encoded, maximum)

    def build(self) -> bytes:
        return b"".join(self._parts)


class BinaryReader:
    def __init__(self, content: bytes, maximum: int) -> None:
        if not isinstance(content, bytes) or len(content) > maximum:
            raise ProtocolError("binary message exceeds its size limit")
        self._content = content
        self._offset = 0

    @property
    def remaining(self) -> int:
        return len(self._content) - self._offset

    def _take(self, size: int) -> bytes:
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ProtocolError("binary field size is invalid")
        end = self._offset + size
        if end > len(self._content):
            raise ProtocolError("binary message is truncated")
        value = self._content[self._offset : end]
        self._offset = end
        return value

    def u8(self) -> int:
        return struct.unpack("!B", self._take(1))[0]

    def u16(self) -> int:
        return struct.unpack("!H", self._take(2))[0]

    def u32(self) -> int:
        return struct.unpack("!I", self._take(4))[0]

    def u64(self) -> int:
        return struct.unpack("!Q", self._take(8))[0]

    def fixed(self, size: int) -> bytes:
        return self._take(size)

    def bytes_u16(self, maximum: int = 0xFFFF) -> bytes:
        size = self.u16()
        if size > maximum:
            raise ProtocolError("binary byte field exceeds its size limit")
        return self._take(size)

    def bytes_u32(self, maximum: int) -> bytes:
        size = self.u32()
        if size > maximum:
            raise ProtocolError("binary byte field exceeds its size limit")
        return self._take(size)

    def text_u16(self, maximum: int = 0xFFFF) -> str:
        try:
            return self.bytes_u16(maximum).decode("utf-8")
        except UnicodeDecodeError as error:
            raise ProtocolError("binary text field is not valid UTF-8") from error

    def finish(self) -> None:
        if self.remaining:
            raise ProtocolError("binary message has trailing bytes")
