from __future__ import annotations

import json
import os
import socket
import threading
import time
from pathlib import Path


_installed = False
_lock = threading.Lock()


def install_socket_audit(path: Path, role: str) -> None:
    global _installed
    if _installed:
        return
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_sendto = socket.socket.sendto
    original_getaddrinfo = socket.getaddrinfo
    original_gethostbyname = socket.gethostbyname
    original_gethostbyname_ex = socket.gethostbyname_ex

    def record(event: str, **fields: object) -> None:
        document = {
            "event": event,
            "pid": os.getpid(),
            "role": role,
            "thread": threading.current_thread().name,
            "timeNs": time.time_ns(),
            **fields,
        }
        encoded = json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        with _lock:
            with destination.open("a", encoding="ascii", newline="\n") as output:
                output.write(encoded + "\n")

    def safe_address(address: object) -> object:
        if isinstance(address, tuple):
            return [str(item) if index == 0 else item for index, item in enumerate(address)]
        return type(address).__name__

    def audited_connect(instance: socket.socket, address: object) -> None:
        record(
            "connect",
            address=safe_address(address),
            family=int(instance.family),
            socketType=int(instance.type),
        )
        return original_connect(instance, address)

    def audited_connect_ex(instance: socket.socket, address: object) -> int:
        record(
            "connect_ex",
            address=safe_address(address),
            family=int(instance.family),
            socketType=int(instance.type),
        )
        return original_connect_ex(instance, address)

    def audited_sendto(instance: socket.socket, data: bytes, *args: object) -> int:
        address = args[-1] if args else None
        record(
            "udp_send",
            address=safe_address(address),
            bytes=len(data),
            family=int(instance.family),
            socketType=int(instance.type),
        )
        return original_sendto(instance, data, *args)

    def audited_getaddrinfo(host: object, port: object, *args: object, **kwargs: object):
        record("dns_getaddrinfo", host=str(host), port=str(port))
        return original_getaddrinfo(host, port, *args, **kwargs)

    def audited_gethostbyname(host: str) -> str:
        record("dns_gethostbyname", host=str(host))
        return original_gethostbyname(host)

    def audited_gethostbyname_ex(host: str):
        record("dns_gethostbyname_ex", host=str(host))
        return original_gethostbyname_ex(host)

    socket.socket.connect = audited_connect
    socket.socket.connect_ex = audited_connect_ex
    socket.socket.sendto = audited_sendto
    socket.getaddrinfo = audited_getaddrinfo
    socket.gethostbyname = audited_gethostbyname
    socket.gethostbyname_ex = audited_gethostbyname_ex
    _installed = True


def install_from_environment(default_role: str) -> None:
    path = os.environ.get("GRANGER_NETWORK_SOCKET_AUDIT", "").strip()
    if not path:
        return
    role = os.environ.get("GRANGER_NETWORK_PROCESS_ROLE", default_role).strip() or default_role
    install_socket_audit(Path(path), role)
