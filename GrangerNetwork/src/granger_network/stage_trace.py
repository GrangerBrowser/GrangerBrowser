"""Opt-in, bounded acceptance diagnostics. Never records arguments or frame locals."""
from __future__ import annotations

import atexit
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
import json
import os
from pathlib import Path
import sys
import threading
import time

from ._codec import atomic_write_text
from .errors import PeerRpcError

_state = None
_init_lock = threading.Lock()
_SAFE_RPC_ERRORS = frozenset({
    "SERVICE_OFFLINE", "INTRODUCTION_BUSY", "INTRODUCTION_TIMEOUT", "INTRODUCTION_FAILED",
    "RENDEZVOUS_UNAVAILABLE", "RENDEZVOUS_TIMEOUT", "REMOTE_ERROR",
})


def _utc():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class StageTrace:
    def __init__(self, directory: Path):
        self.directory = directory
        self.lock = threading.RLock()
        self.active = {}
        self.completed = deque(maxlen=512)
        self.summaries = {}
        self.total = 0
        self.dropped = 0
        self.stop = threading.Event()
        self.started = _utc()

    def begin(self, name):
        with self.lock:
            self.total += 1
            token = self.total
            if len(self.active) >= 128:
                self.dropped += 1
                return None
            self.active[token] = {
                "id": token, "stage": name, "startUtc": _utc(),
                "startMonotonic": time.monotonic(), "pid": os.getpid(),
                "thread": threading.get_native_id(), "pythonThread": threading.get_ident(),
            }
            return token

    def end(self, token, error=None):
        if token is None:
            return
        with self.lock:
            record = self.active.pop(token)
            record["durationMs"] = round((time.monotonic() - record.pop("startMonotonic")) * 1000, 3)
            record.update(endUtc=_utc(), result="TIMEOUT" if isinstance(error, TimeoutError)
                          else "FAIL" if error else "PASS",
                          errorCategory=type(error).__name__ if error else "")
            if error is not None:
                hop = getattr(error, "circuit_failure_hop_index", None)
                phase = getattr(error, "circuit_failure_stage", None)
                if isinstance(hop, int) and not isinstance(hop, bool) and 0 <= hop < 8:
                    record["failedHop"] = hop
                if isinstance(phase, str) and phase in {"tcp", "authentication", "extension", "stream-open"}:
                    record["failedCircuitStage"] = phase
                cause = error
                for _ in range(4):
                    if isinstance(cause, PeerRpcError):
                        record["remoteErrorCategory"] = (
                            cause.code if cause.code in _SAFE_RPC_ERRORS else "OTHER_REMOTE_ERROR"
                        )
                        break
                    cause = cause.__cause__
                    if cause is None:
                        break
                sites = []
                traceback = error.__traceback__
                while traceback is not None and len(sites) < 12:
                    frame = traceback.tb_frame
                    sites.append({"file": Path(frame.f_code.co_filename).name,
                                  "function": frame.f_code.co_name, "line": traceback.tb_lineno})
                    traceback = traceback.tb_next
                record["errorSites"] = sites
                if isinstance(error, OSError):
                    record["errno"] = error.errno
                    record["winerror"] = getattr(error, "winerror", None)
                    record["fileName"] = Path(error.filename).name if error.filename else ""
                    record["destinationName"] = Path(error.filename2).name if error.filename2 else ""
            self.completed.append(record)
            if record["stage"] not in self.summaries and len(self.summaries) < 64:
                self.summaries[record["stage"]] = {
                    "firstStartUtc": record["startUtc"], "calls": 0,
                    "durationMs": 0, "PASS": 0, "FAIL": 0, "TIMEOUT": 0,
                }
            summary = self.summaries.get(record["stage"])
            if summary is not None:
                summary["calls"] += 1
                summary[record["result"]] += 1
                summary["lastEndUtc"] = record["endUtc"]
                summary["durationMs"] = round(summary["durationMs"] + record["durationMs"], 3)

    def snapshot(self):
        now = time.monotonic()
        with self.lock:
            active = [{**{k: v for k, v in r.items() if k != "startMonotonic"},
                       "endUtc": None, "result": "PENDING", "durationMs": round((now-r["startMonotonic"])*1000, 3)}
                      for r in self.active.values()]
            document = {"version": 1, "pid": os.getpid(), "startedUtc": self.started,
                        "capturedUtc": _utc(), "active": active, "completed": list(self.completed),
                        "summaries": {key: dict(value) for key, value in self.summaries.items()},
                        "calls": self.total, "dropped": self.dropped, "threadCount": threading.active_count()}
        stacks = []
        for ident, frame in list(sys._current_frames().items())[:128]:
            entries = []
            for _ in range(12):
                if frame is None:
                    break
                entries.append({"file": Path(frame.f_code.co_filename).name,
                                "function": frame.f_code.co_name, "line": frame.f_lineno})
                frame = frame.f_back
            stacks.append({"pythonThread": ident, "frames": entries})
        document["stacks"] = stacks
        if sys.platform == "linux":
            try:
                fields = {}
                for line in Path("/proc/self/status").read_text().splitlines():
                    key, _, value = line.partition(":")
                    if key in {"Threads", "VmRSS", "FDSize", "Seccomp", "NoNewPrivs", "voluntary_ctxt_switches", "nonvoluntary_ctxt_switches"}:
                        fields[key] = value.strip()
                descriptors = list(Path("/proc/self/fd").iterdir())
                sockets = 0
                for descriptor in descriptors:
                    try:
                        sockets += os.readlink(descriptor).startswith("socket:")
                    except OSError:
                        pass  # A descriptor may close while the snapshot is collected.
                document["resources"] = {"status": fields, "fileDescriptors": len(descriptors),
                    "sockets": sockets}
            except OSError:
                document["resourceSnapshotUnavailable"] = True
        return document

    def flush(self):
        atomic_write_text(self.directory / f"python-{os.getpid()}.json",
                          json.dumps(self.snapshot(), ensure_ascii=True, separators=(",", ":")) + "\n", mode=0o600)

    def run(self):
        while not self.stop.wait(1):
            try:
                self.flush()
            except OSError:
                pass

    def close(self):
        self.stop.set()
        try:
            self.flush()
        except OSError:
            pass


def _get():
    global _state
    directory = os.environ.get("GRANGER_ACCEPTANCE_TRACE_DIR", "")
    if not directory:
        return None
    with _init_lock:
        if _state is None:
            _state = StageTrace(Path(directory))
            threading.Thread(target=_state.run, name="acceptance-stage-snapshot", daemon=True).start()
            atexit.register(_state.close)
    return _state


@contextmanager
def stage(name):
    trace = _get()
    token = trace.begin(name) if trace else None
    try:
        yield
    except BaseException as error:
        if trace:
            trace.end(token, error)
        raise
    else:
        if trace:
            trace.end(token)


def traced(name):
    def decorate(function):
        @wraps(function)
        def call(*args, **kwargs):
            if not os.environ.get("GRANGER_ACCEPTANCE_TRACE_DIR"):
                return function(*args, **kwargs)
            with stage(name):
                return function(*args, **kwargs)
        return call
    return decorate
