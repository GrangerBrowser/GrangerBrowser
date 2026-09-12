"""Bounded, opt-in process diagnostics collected before acceptance termination."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def _utc():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def process_snapshot(root_pid):
    if sys.platform != "linux":
        return {"rootPid": root_pid, "procfs": False}
    table = {}
    for directory in Path("/proc").iterdir():
        if not directory.name.isdecimal():
            continue
        try:
            fields = {}
            for line in (directory / "status").read_text().splitlines():
                key, _, value = line.partition(":")
                if key in {"Name", "State", "Pid", "PPid", "Threads", "VmRSS", "Seccomp", "NoNewPrivs"}:
                    fields[key] = value.strip()
            table[int(directory.name)] = fields
        except OSError:
            pass
    owned = {root_pid}
    for _ in range(16):
        found = {pid for pid, record in table.items() if int(record.get("PPid", 0)) in owned}
        if found <= owned:
            break
        owned.update(found)
    result = []
    for pid in sorted(owned)[:128]:
        record = dict(table.get(pid, {"Pid": str(pid)}))
        directory = Path(f"/proc/{pid}")
        try:
            record["tasks"] = [{"tid": int(p.name), "waitChannel": (p / "wchan").read_text()[:128]}
                               for p in list((directory / "task").iterdir())[:128]]
            fds = list((directory / "fd").iterdir())
            record["fdCount"] = len(fds)
            socket_inodes = set()
            for descriptor in fds[:4096]:
                try:
                    target = os.readlink(descriptor)
                    if target.startswith("socket:["):
                        socket_inodes.add(target[8:-1])
                except OSError:
                    pass
            states = {}
            for protocol in ("tcp", "tcp6", "udp", "udp6", "unix"):
                # Store states/counts only, never endpoints or IPC paths.
                for line in (directory / "net" / protocol).read_text().splitlines()[1:]:
                    fields = line.split()
                    index = 6 if protocol == "unix" else 9
                    if len(fields) > index and fields[index] in socket_inodes:
                        key = protocol + ":" + fields[5 if protocol == "unix" else 3]
                        states[key] = states.get(key, 0) + 1
            record["socketCount"] = len(socket_inodes)
            record["socketStates"] = states
        except OSError:
            record["partial"] = True
        result.append(record)
    return {"rootPid": root_pid, "procfs": True, "processes": result}


def capture(directory, qt_path, pid, reason, started, start_utc):
    document = {"startUtc": start_utc, "endUtc": _utc(),
                "durationMs": round((time.monotonic() - started) * 1000, 3),
                "result": "TIMEOUT" if reason == "deadline" else "PENDING",
                "errorCategory": "AcceptanceDeadline" if reason == "deadline" else "",
                "capturedBeforeTermination": True, "processState": process_snapshot(pid), "traces": []}
    for path in [qt_path, *sorted(directory.glob("python-*.json"))[:64]]:
        try:
            if path.stat().st_size > 2 * 1024 * 1024:
                continue
            document["traces"].append({"file": path.name, "state": json.loads(path.read_text())})
        except (OSError, ValueError):
            pass
    target = directory / f"capture-{reason}.json"
    target.write_text(json.dumps(document, separators=(",", ":")) + "\n")
    target.chmod(0o600)


def run_traced(command, *, cwd, env, directory, qt_path, timeout=300):
    directory.mkdir(parents=True, exist_ok=True)
    started, start_utc = time.monotonic(), _utc()
    with (directory / "stdout.log").open("w+b") as stdout, (directory / "stderr.log").open("w+b") as stderr:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=stdout, stderr=stderr, start_new_session=os.name != "nt")
        try:
            try:
                process.wait(timeout=max(0.01, timeout - min(15, timeout / 2)))
            except subprocess.TimeoutExpired:
                capture(directory, qt_path, process.pid, "near-deadline", started, start_utc)
                process.wait(timeout=max(0.01, timeout - (time.monotonic() - started)))
        except subprocess.TimeoutExpired as error:
            capture(directory, qt_path, process.pid, "deadline", started, start_utc)
            raise subprocess.TimeoutExpired(command, timeout) from error
        finally:
            if process.poll() is None:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
                process.wait(timeout=5)
        tails = []
        for stream in (stdout, stderr):
            stream.seek(0, os.SEEK_END)
            stream.seek(max(0, stream.tell() - 4000))
            tails.append(stream.read(4000).decode("utf-8", errors="replace"))
        return subprocess.CompletedProcess(command, process.returncode, *tails)
