from __future__ import annotations

import argparse
import ctypes
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


NETWORK_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = NETWORK_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from granger_network._codec import atomic_write_text
from granger_network.bootstrap import BootstrapSet
from granger_network.identity import ServiceIdentity
from granger_network.network_audit import install_socket_audit
from granger_network.node import NODE_DESCRIPTOR_FILE, initialize_node
from granger_network.peer import NodeDescriptor, RELAY_CAPABILITIES, RelayPolicy
from granger_network.transport import RendezvousEndpoint
from granger_network.wan_config import load_discovery_runtime, write_bootstrap_bundle


MESSAGE = "GRANGER_TEST_MESSAGE_123"
PLAINTEXT_MARKERS = (
    MESSAGE.encode("ascii"),
    b"GRANGER_BROWSER_WAN_MESSAGE_456",
    b"GET / HTTP/1.1",
    b"POST /message HTTP/1.1",
    b"Granger test forum",
    b"Granger hosted site",
)


class AcceptanceError(RuntimeError):
    pass


@dataclass
class ChildProcess:
    name: str
    process: subprocess.Popen[bytes]
    stdout_path: Path
    stderr_path: Path
    stdout: BinaryIO
    stderr: BinaryIO

    def close_logs(self) -> None:
        self.stdout.close()
        self.stderr.close()


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def process_is_running(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name != "nt":
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        return False
    try:
        exit_code = ctypes.c_ulong()
        return bool(
            ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
        ) and exit_code.value == 259
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def child_environment(audit_path: Path, role: str) -> dict[str, str]:
    environment = os.environ.copy()
    current_python_path = environment.get("PYTHONPATH", "")
    environment["PYTHONPATH"] = str(SOURCE_ROOT) + (
        os.pathsep + current_python_path if current_python_path else ""
    )
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONUNBUFFERED"] = "1"
    environment["GRANGER_NETWORK_SOCKET_AUDIT"] = str(audit_path)
    environment["GRANGER_NETWORK_PROCESS_ROLE"] = role
    return environment


def start_child(
    root: Path,
    name: str,
    command: list[str],
    *,
    role: str,
) -> ChildProcess:
    logs = root / "logs"
    audits = root / "audit"
    logs.mkdir(parents=True, exist_ok=True)
    audits.mkdir(parents=True, exist_ok=True)
    stdout_path = logs / f"{name}.stdout.log"
    stderr_path = logs / f"{name}.stderr.log"
    stdout = stdout_path.open("wb")
    stderr = stderr_path.open("wb")
    try:
        process = subprocess.Popen(
            command,
            cwd=NETWORK_ROOT,
            env=child_environment(audits / f"{name}.jsonl", role),
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
        )
    except Exception:
        stdout.close()
        stderr.close()
        raise
    return ChildProcess(name, process, stdout_path, stderr_path, stdout, stderr)


def wait_json(path: Path, child: ChildProcess, timeout: float) -> dict:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if child.process.poll() is not None:
            raise AcceptanceError(
                f"{child.name} exited before readiness with code {child.process.returncode}"
            )
        if path.exists():
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(document, dict):
                    return document
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
                last_error = error
        time.sleep(0.05)
    suffix = f": {last_error}" if last_error is not None else ""
    raise AcceptanceError(f"timed out waiting for {child.name} readiness{suffix}")


def wait_exit(child: ChildProcess, timeout: float) -> int:
    try:
        return child.process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise AcceptanceError(f"{child.name} did not exit within {timeout:.0f}s") from error


def terminate_child(child: ChildProcess, timeout: float = 8.0) -> None:
    if child.process.poll() is not None:
        return
    child.process.terminate()
    try:
        child.process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        child.process.kill()
        child.process.wait(timeout=3.0)


def stop_children(children: list[ChildProcess]) -> list[str]:
    for child in reversed(children):
        if child.process.poll() is None:
            child.process.terminate()
    deadline = time.monotonic() + 8.0
    for child in reversed(children):
        if child.process.poll() is None:
            remaining = max(0.1, deadline - time.monotonic())
            try:
                child.process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                child.process.kill()
    for child in reversed(children):
        if child.process.poll() is None:
            try:
                child.process.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                pass
        child.close_logs()
    return [child.name for child in children if child.process.poll() is None]


def read_events(path: Path) -> list[dict]:
    if not path.exists():
        return []
    result: list[dict] = []
    for line in path.read_text(encoding="ascii").splitlines():
        if not line:
            continue
        document = json.loads(line)
        if not isinstance(document, dict):
            raise AcceptanceError(f"socket audit entry is not an object: {path}")
        result.append(document)
    return result


def destination_ports(events: list[dict]) -> set[int]:
    result: set[int] = set()
    for event in events:
        if event.get("event") not in {"connect", "connect_ex"}:
            continue
        address = event.get("address")
        if isinstance(address, list) and len(address) >= 2 and isinstance(address[1], int):
            result.add(address[1])
    return result


def initialize_topology(root: Path) -> tuple[list[NodeDescriptor], dict[str, Path]]:
    specifications = (
        ("bootstrap-a", ("bootstrap", "discovery")),
        ("bootstrap-b", ("bootstrap", "discovery")),
        ("bootstrap-c", ("bootstrap", "discovery")),
        ("discovery-a", ("discovery",)),
        ("discovery-b", ("discovery",)),
        ("discovery-c", ("discovery",)),
        ("client-entry-a", ("entry",)),
        ("client-entry-b", ("entry",)),
        ("middle-a", ("middle",)),
        ("middle-b", ("middle",)),
        ("middle-c", ("middle",)),
        ("middle-d", ("middle",)),
        ("middle-e", ("middle",)),
        ("service-entry-a", ("service-relay",)),
        ("service-entry-b", ("service-relay",)),
        ("introduction-a", ("introduction",)),
        ("introduction-b", ("introduction",)),
        ("rendezvous", ("rendezvous",)),
    )
    descriptors: list[NodeDescriptor] = []
    state_paths: dict[str, Path] = {}
    for name, capabilities in specifications:
        state = root / "nodes" / name
        policy = RelayPolicy(
            enabled=bool(set(capabilities) & RELAY_CAPABILITIES),
            max_circuits=128,
            max_streams=256,
            max_connections=256,
            max_bytes_per_circuit=128 * 1024 * 1024,
            max_bandwidth_kib_per_second=64 * 1024,
            burst_kib=64 * 1024,
            memory_budget_kib=128 * 1024,
            connection_timeout_seconds=8,
            idle_timeout_seconds=180,
        )
        descriptor = initialize_node(
            state,
            RendezvousEndpoint("127.0.0.1", available_port()),
            capabilities,
            policy,
        )
        descriptors.append(descriptor)
        state_paths[name] = state
    return descriptors, state_paths


def run_checked(command: list[str], environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=NETWORK_ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30.0,
    )
    if result.returncode != 0:
        raise AcceptanceError(
            f"command failed ({result.returncode}): {' '.join(command)}\n{result.stderr}"
        )
    return result


def run_acceptance(
    root: Path,
    report_path: Path,
    *,
    browser: Path | None = None,
    qt_bin: Path | None = None,
    expect_packaged_runtime: bool = False,
    hosting_source: Path | None = None,
) -> dict:
    root = Path(root).resolve()
    report_path = Path(report_path).resolve()
    if hosting_source is not None:
        hosting_source = Path(hosting_source).resolve()
        if not (hosting_source / "index.html").is_file():
            raise AcceptanceError("hosting source does not contain index.html")
    root.mkdir(parents=True, exist_ok=False)
    children: list[ChildProcess] = []
    report: dict = {
        "directFallback": False,
        "physicalWan": "UNVERIFIED",
        "status": "RUNNING",
        "version": 1,
    }
    failure: Exception | None = None
    try:
        descriptors, state_paths = initialize_topology(root)
        descriptors_by_name = {
            name: NodeDescriptor.from_json(
                (state / NODE_DESCRIPTOR_FILE).read_text(encoding="utf-8")
            )
            for name, state in state_paths.items()
        }
        authority = ServiceIdentity.generate()
        bootstrap = BootstrapSet.create(
            authority,
            [descriptors_by_name[f"bootstrap-{letter}"] for letter in "abc"],
            lifetime=24 * 60 * 60,
        )
        bootstrap_path = root / "bootstrap-set.json"
        authority_pin_path = root / "bootstrap-authority.pin"
        write_bootstrap_bundle(bootstrap, bootstrap_path, authority_pin_path)

        descriptor_paths = [state / NODE_DESCRIPTOR_FILE for state in state_paths.values()]
        node_ready: dict[str, dict] = {}
        node_children: dict[str, ChildProcess] = {}
        for name, state in state_paths.items():
            ready_path = root / "ready" / f"{name}.json"
            command = [
                sys.executable,
                "-m",
                "granger_network.node",
                "run",
                "--state-dir",
                str(state),
                "--ready-file",
                str(ready_path),
                "--capture",
                str(root / "capture" / f"{name}.bin"),
                "--diagnostics",
                str(root / "diagnostics" / f"{name}.jsonl"),
            ]
            for descriptor_path in descriptor_paths:
                command.extend(("--peer-descriptor", str(descriptor_path)))
            child = start_child(root, name, command, role=f"node:{name}")
            children.append(child)
            node_children[name] = child
            node_ready[name] = wait_json(ready_path, child, 20.0)

        provisioner_audit = root / "audit" / "provisioner.jsonl"
        install_socket_audit(provisioner_audit, "provisioner")
        runtime = load_discovery_runtime(
            bootstrap_path,
            authority_pin_path,
            root / "provisioner-peer-cache.json",
            root / "provisioner-identity.json",
            timeout=4.0,
            replication_factor=6,
            minimum_replicas=2,
        )
        replica_counts = {
            descriptor.node_id: runtime.discovery.publish(descriptor)
            for descriptor in descriptors
        }
        failed_bootstrap_name = "bootstrap-a"
        failed_bootstrap_id = descriptors_by_name[failed_bootstrap_name].node_id
        terminate_child(node_children[failed_bootstrap_name])

        backend_ready_path = root / "ready" / "backend.json"
        backend = start_child(
            root,
            "backend",
            [
                sys.executable,
                str(NETWORK_ROOT / "tools" / "wan_forum_fixture.py"),
                "--ready-file",
                str(backend_ready_path),
            ],
            role="backend",
        )
        children.append(backend)
        backend_ready = wait_json(backend_ready_path, backend, 10.0)

        service_state = root / "service"
        host_environment = child_environment(root / "audit" / "host.jsonl", "service")
        initialized = run_checked(
            [
                sys.executable,
                "-m",
                "granger_network.wan_host",
                "init",
                "--state-dir",
                str(service_state),
                "--title",
                "Granger WAN acceptance forum",
            ],
            host_environment,
        )
        canonical_name = initialized.stdout.strip().splitlines()[-1]
        host_ready_path = root / "ready" / "host.json"
        def host_command(ready_path: Path) -> list[str]:
            return [
                sys.executable,
                "-m",
                "granger_network.wan_host",
                "serve",
                "--state-dir",
                str(service_state),
                "--bootstrap",
                str(bootstrap_path),
                "--authority-pin",
                str(authority_pin_path),
                "--upstream",
                f"http://127.0.0.1:{backend_ready['port']}",
                "--ready-file",
                str(ready_path),
                "--timeout",
                "8",
                "--replication-factor",
                "6",
            ]

        host = start_child(
            root,
            "host",
            host_command(host_ready_path),
            role="service",
        )
        children.append(host)
        host_ready = wait_json(host_ready_path, host, 45.0)
        if host_ready.get("canonicalName") != canonical_name:
            raise AcceptanceError("host readiness returned a different service identity")
        host_route_ids = sorted(
            {
                node_id
                for route in host_ready["introductionRoutes"]
                for node_id in route
            }
            | set(host_ready["rendezvousRoute"])
        )
        route_exclusion_arguments: list[str] = []
        for node_id in host_route_ids:
            route_exclusion_arguments.extend(("--exclude-node", node_id))

        def start_fetch_client(
            name: str,
            exclusions: list[str],
            *,
            attempts: int = 6,
        ) -> tuple[ChildProcess, Path, Path]:
            client_report_path = root / f"{name}-report.json"
            client_output_path = root / f"{name}-messages.txt"
            client_process = start_child(
                root,
                name,
                [
                    sys.executable,
                    "-m",
                    "granger_network.wan_client",
                    "fetch",
                    canonical_name,
                    "--state-dir",
                    str(root / name),
                    "--bootstrap",
                    str(bootstrap_path),
                    "--authority-pin",
                    str(authority_pin_path),
                    "--path",
                    "/messages",
                    "--output",
                    str(client_output_path),
                    "--report",
                    str(client_report_path),
                    "--timeout",
                    "8",
                    "--route-attempts",
                    str(attempts),
                    "--replication-factor",
                    "6",
                    *exclusions,
                ],
                role=name,
            )
            children.append(client_process)
            return client_process, client_report_path, client_output_path

        client_a_report_path = root / "client-a-report.json"
        client_a = start_child(
            root,
            "client-a",
            [
                sys.executable,
                "-m",
                "granger_network.wan_client",
                "demo",
                canonical_name,
                "--state-dir",
                str(root / "client-a"),
                "--bootstrap",
                str(bootstrap_path),
                "--authority-pin",
                str(authority_pin_path),
                "--message",
                MESSAGE,
                "--report",
                str(client_a_report_path),
                "--timeout",
                "8",
                "--replication-factor",
                "6",
                *route_exclusion_arguments,
            ],
            role="client-a",
        )
        children.append(client_a)
        client_a_exit = wait_exit(client_a, 75.0)
        if client_a_exit != 0:
            raise AcceptanceError(f"first client demo failed with exit code {client_a_exit}")
        client_a_report = json.loads(client_a_report_path.read_text(encoding="utf-8"))
        if not client_a_report.get("messagePresent"):
            raise AcceptanceError("forum POST was not visible to the subsequent reader")

        unrestricted_client, unrestricted_report_path, unrestricted_output_path = (
            start_fetch_client("client-unrestricted", [], attempts=6)
        )
        unrestricted_exit = wait_exit(unrestricted_client, 90.0)
        if unrestricted_exit != 0:
            raise AcceptanceError(
                "client without test-only host-route exclusions failed to use the overlay"
            )
        unrestricted_report = json.loads(
            unrestricted_report_path.read_text(encoding="utf-8")
        )
        if MESSAGE.encode("ascii") not in unrestricted_output_path.read_bytes():
            raise AcceptanceError("unrestricted client did not receive the forum message")

        browser_result: dict = {}
        hosting_browser_result: dict = {}
        if browser is not None:
            browser_config_path = root / "browser-wan.json"
            atomic_write_text(
                browser_config_path,
                json.dumps(
                    {
                        "aliasPins": {},
                        "authorityPin": authority_pin_path.name,
                        "bootstrap": bootstrap_path.name,
                        "minimumReplicas": 2,
                        "replicationFactor": 6,
                        "routeAttempts": 6,
                        "timeoutSeconds": 8,
                        "version": 1,
                    },
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                mode=0o644,
            )
            browser_output = root / "browser-wan-smoke.json"
            browser_environment = child_environment(
                root / "audit" / "browser.jsonl",
                "browser-gateway",
            )
            browser_environment["GRANGER_DATA_ROOT"] = str(root / "browser-data")
            browser_environment["GRANGER_CACHE_ROOT"] = str(root / "browser-cache")
            browser_environment["GRANGER_SETTINGS_ROOT"] = str(root / "browser-settings")
            browser_environment["GRANGER_DOWNLOAD_ROOT"] = str(root / "browser-downloads")
            if expect_packaged_runtime:
                system_root = Path(browser_environment.get("SystemRoot", r"C:\Windows"))
                browser_environment["PATH"] = os.pathsep.join(
                    (str(system_root / "System32"), str(system_root))
                )
                for name in (
                    "PYTHONHOME",
                    "PYTHONPATH",
                    "PYTHONUSERBASE",
                    "QTDIR",
                    "CMAKE_PREFIX_PATH",
                    "QT_PLUGIN_PATH",
                    "QT_QPA_PLATFORM_PLUGIN_PATH",
                ):
                    browser_environment.pop(name, None)
            elif qt_bin is not None:
                browser_environment["PATH"] = (
                    str(qt_bin) + os.pathsep + browser_environment.get("PATH", "")
                )
            browser_command = [
                str(browser),
                "--smoke-granger-network-wan",
                f"--smoke-output={browser_output}",
                f"--granger-network-wan-config={browser_config_path}",
                f"--granger-network-canonical={canonical_name}",
            ]
            if not expect_packaged_runtime:
                browser_command.extend(
                    (
                        f"--granger-network-source={NETWORK_ROOT}",
                        f"--granger-network-python={sys.executable}",
                    )
                )
            browser_completed = subprocess.run(
                browser_command,
                cwd=root,
                env=browser_environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            if browser_output.is_file():
                browser_result = json.loads(browser_output.read_text(encoding="utf-8"))
            worker_pid = int(browser_result.get("runtime", {}).get("workerPid", 0))
            time.sleep(0.25)
            browser_result["harness"] = {
                "exitCode": browser_completed.returncode,
                "orphanGateway": process_is_running(worker_pid),
                "packagedRuntimeRequested": expect_packaged_runtime,
                "stderr": browser_completed.stderr[-4000:],
                "stdout": browser_completed.stdout[-4000:],
            }
            atomic_write_text(
                root / "browser-process.json",
                json.dumps(
                    browser_result,
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                mode=0o644,
            )
            if (
                browser_completed.returncode != 0
                or browser_result.get("ok") is not True
                or browser_result["harness"]["orphanGateway"]
            ):
                raise AcceptanceError("real Qt WebEngine WAN browser smoke failed")

            if hosting_source is not None:
                hosting_output = root / "browser-hosting-smoke.json"
                hosting_environment = child_environment(
                    root / "audit" / "browser-hosting.jsonl",
                    "browser-hosting",
                )
                hosting_environment["GRANGER_DATA_ROOT"] = str(root / "browser-hosting-data")
                hosting_environment["GRANGER_CACHE_ROOT"] = str(root / "browser-hosting-cache")
                hosting_environment["GRANGER_SETTINGS_ROOT"] = str(root / "browser-hosting-settings")
                hosting_environment["GRANGER_DOWNLOAD_ROOT"] = str(root / "browser-hosting-downloads")
                if expect_packaged_runtime:
                    system_root = Path(hosting_environment.get("SystemRoot", r"C:\Windows"))
                    hosting_environment["PATH"] = os.pathsep.join(
                        (str(system_root / "System32"), str(system_root))
                    )
                    for name in (
                        "PYTHONHOME",
                        "PYTHONPATH",
                        "PYTHONUSERBASE",
                        "QTDIR",
                        "CMAKE_PREFIX_PATH",
                        "QT_PLUGIN_PATH",
                        "QT_QPA_PLATFORM_PLUGIN_PATH",
                    ):
                        hosting_environment.pop(name, None)
                elif qt_bin is not None:
                    hosting_environment["PATH"] = (
                        str(qt_bin) + os.pathsep + hosting_environment.get("PATH", "")
                    )
                hosting_command = [
                    str(browser),
                    "--smoke-granger-hosting",
                    f"--smoke-output={hosting_output}",
                    f"--granger-network-wan-config={browser_config_path}",
                    f"--granger-hosting-source={hosting_source}",
                ]
                if not expect_packaged_runtime:
                    hosting_command.extend(
                        (
                            f"--granger-network-source={NETWORK_ROOT}",
                            f"--granger-network-python={sys.executable}",
                        )
                    )
                hosting_completed = subprocess.run(
                    hosting_command,
                    cwd=root,
                    env=hosting_environment,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=False,
                )
                if hosting_output.is_file():
                    hosting_browser_result = json.loads(
                        hosting_output.read_text(encoding="utf-8")
                    )
                hosting_pids = {
                    int(hosting_browser_result.get("hostProcessPid", 0)),
                    int(hosting_browser_result.get("recoveryProcessPid", 0)),
                }
                hosting_pids.discard(0)
                time.sleep(0.25)
                hosting_browser_result["harness"] = {
                    "exitCode": hosting_completed.returncode,
                    "hostProcessOrphan": any(process_is_running(pid) for pid in hosting_pids),
                    "hostProcessPids": sorted(hosting_pids),
                    "packagedRuntimeRequested": expect_packaged_runtime,
                    "stderr": hosting_completed.stderr[-4000:],
                    "stdout": hosting_completed.stdout[-4000:],
                }
                atomic_write_text(
                    root / "browser-hosting-process.json",
                    json.dumps(
                        hosting_browser_result,
                        ensure_ascii=True,
                        indent=2,
                        sort_keys=True,
                    )
                    + "\n",
                    mode=0o644,
                )
                if (
                    hosting_completed.returncode != 0
                    or hosting_browser_result.get("ok") is not True
                    or hosting_browser_result["harness"]["hostProcessOrphan"]
                ):
                    raise AcceptanceError("real Qt WebEngine hosting smoke failed")

        initial_host_ready = host_ready
        terminate_child(host)
        offline_client, offline_report_path, offline_output_path = start_fetch_client(
            "client-offline",
            route_exclusion_arguments,
            attempts=2,
        )
        offline_exit = wait_exit(offline_client, 45.0)
        if offline_exit == 0:
            raise AcceptanceError("client reached a service after its host stopped")
        if offline_report_path.exists() or offline_output_path.exists():
            raise AcceptanceError("offline service request produced a successful response artifact")

        time.sleep(0.5)
        restarted_ready_path = root / "ready" / "host-restarted.json"
        host_restarted = start_child(
            root,
            "host-restarted",
            host_command(restarted_ready_path),
            role="service-restarted",
        )
        children.append(host_restarted)
        host_ready = wait_json(restarted_ready_path, host_restarted, 45.0)
        if host_ready.get("canonicalName") != canonical_name:
            raise AcceptanceError("restarted host changed its service identity")
        host_route_ids = sorted(
            {
                node_id
                for route in host_ready["introductionRoutes"]
                for node_id in route
            }
            | set(host_ready["rendezvousRoute"])
        )
        route_exclusion_arguments = []
        for node_id in host_route_ids:
            route_exclusion_arguments.extend(("--exclude-node", node_id))

        client_b, client_b_report_path, client_b_output_path = start_fetch_client(
            "client-b",
            route_exclusion_arguments,
        )
        client_b_exit = wait_exit(client_b, 75.0)
        if client_b_exit != 0:
            raise AcceptanceError(f"post-restart client failed with exit code {client_b_exit}")
        client_b_report = json.loads(client_b_report_path.read_text(encoding="utf-8"))
        client_b_messages = client_b_output_path.read_bytes()
        if MESSAGE.encode("ascii") not in client_b_messages:
            raise AcceptanceError("post-restart client did not receive the forum message")

        node_names_by_id = {
            descriptor.node_id: name for name, descriptor in descriptors_by_name.items()
        }
        failed_middle_id = client_b_report["clientMiddleNodeId"]
        failed_middle_name = node_names_by_id[failed_middle_id]
        terminate_child(node_children[failed_middle_name])

        client_c, client_c_report_path, client_c_output_path = start_fetch_client(
            "client-c",
            route_exclusion_arguments,
        )
        client_c_exit = wait_exit(client_c, 90.0)
        if client_c_exit != 0:
            raise AcceptanceError(f"middle recovery client failed with exit code {client_c_exit}")
        client_c_report = json.loads(client_c_report_path.read_text(encoding="utf-8"))
        client_c_messages = client_c_output_path.read_bytes()
        if MESSAGE.encode("ascii") not in client_c_messages:
            raise AcceptanceError("middle recovery client did not receive the forum message")
        if client_c_report["clientMiddleNodeId"] == failed_middle_id:
            raise AcceptanceError("client reused a stopped middle relay")

        failed_entry_id = client_c_report["clientEntryNodeId"]
        failed_entry_name = node_names_by_id[failed_entry_id]
        terminate_child(node_children[failed_entry_name])

        client_d, client_d_report_path, client_d_output_path = start_fetch_client(
            "client-d",
            route_exclusion_arguments,
        )
        client_d_exit = wait_exit(client_d, 90.0)
        if client_d_exit != 0:
            raise AcceptanceError(f"entry recovery client failed with exit code {client_d_exit}")
        client_d_report = json.loads(client_d_report_path.read_text(encoding="utf-8"))
        client_d_messages = client_d_output_path.read_bytes()
        if MESSAGE.encode("ascii") not in client_d_messages:
            raise AcceptanceError("entry recovery client did not receive the forum message")
        if client_d_report["clientEntryNodeId"] == failed_entry_id:
            raise AcceptanceError("client reused a stopped entry relay")

        cached_client_state = root / "client-cache"
        cached_client_state.mkdir(parents=True, exist_ok=True)
        shutil.copy2(
            root / "client-d" / "peer-cache.json",
            cached_client_state / "peer-cache.json",
        )
        for bootstrap_name in ("bootstrap-b", "bootstrap-c"):
            terminate_child(node_children[bootstrap_name])

        cached_client, cached_report_path, cached_output_path = start_fetch_client(
            "client-cache",
            route_exclusion_arguments,
        )
        cached_exit = wait_exit(cached_client, 90.0)
        if cached_exit != 0:
            raise AcceptanceError(
                f"cached client failed with all bootstrap seeds down: {cached_exit}"
            )
        cached_report = json.loads(cached_report_path.read_text(encoding="utf-8"))
        cached_messages = cached_output_path.read_bytes()
        if MESSAGE.encode("ascii") not in cached_messages:
            raise AcceptanceError("cached client did not receive the forum message")

        fresh_client, fresh_report_path, fresh_output_path = start_fetch_client(
            "client-fresh",
            route_exclusion_arguments,
            attempts=2,
        )
        fresh_exit = wait_exit(fresh_client, 45.0)
        if fresh_exit == 0:
            raise AcceptanceError("fresh profile connected with every bootstrap seed down")
        if fresh_report_path.exists() or fresh_output_path.exists():
            raise AcceptanceError("fresh unavailable profile produced a response artifact")

        time.sleep(0.25)
        if host_restarted.process.poll() is not None:
            raise AcceptanceError(
                f"restarted host failed with exit code {host_restarted.process.returncode}"
            )

        audit_events = {
            path.stem: read_events(path)
            for path in sorted((root / "audit").glob("*.jsonl"))
        }
        all_events = [event for events in audit_events.values() for event in events]
        dns_events = [event for event in all_events if str(event.get("event", "")).startswith("dns_")]
        udp_events = [event for event in all_events if event.get("event") == "udp_send"]
        client_ports = destination_ports(
            audit_events.get("client-a", [])
            + audit_events.get("browser", [])
            + audit_events.get("client-offline", [])
            + audit_events.get("client-unrestricted", [])
            + audit_events.get("client-b", [])
            + audit_events.get("client-c", [])
            + audit_events.get("client-d", [])
            + audit_events.get("client-cache", [])
            + audit_events.get("client-fresh", [])
        )
        host_ports = destination_ports(
            audit_events.get("host", []) + audit_events.get("host-restarted", [])
        )
        hosting_browser_ports = destination_ports(audit_events.get("browser-hosting", []))
        discovery_ports = {
            descriptor.endpoint.port
            for descriptor in descriptors_by_name.values()
            if "discovery" in descriptor.capabilities
        }
        descriptors_by_id = {
            descriptor.node_id: descriptor for descriptor in descriptors_by_name.values()
        }
        all_client_entry_ports = {
            descriptor.endpoint.port
            for descriptor in descriptors_by_name.values()
            if "entry" in descriptor.capabilities
        }
        all_service_entry_ports = {
            descriptor.endpoint.port
            for descriptor in descriptors_by_name.values()
            if "service-relay" in descriptor.capabilities
        }
        host_entry_ports = {
            descriptors_by_id[route[0]].endpoint.port
            for readiness in (initial_host_ready, host_ready)
            for route in (*readiness["introductionRoutes"], readiness["rendezvousRoute"])
        }
        backend_port = int(backend_ready["port"])
        allowed_client_ports = discovery_ports | all_client_entry_ports
        allowed_host_ports = discovery_ports | host_entry_ports | {backend_port}
        all_overlay_ports = {descriptor.endpoint.port for descriptor in descriptors}

        captures = sorted((root / "capture").glob("*.bin"))
        marker_hits: list[dict[str, str]] = []
        for capture in captures:
            payload = capture.read_bytes()
            for marker in PLAINTEXT_MARKERS:
                if marker in payload:
                    marker_hits.append({"file": capture.name, "marker": marker.decode("ascii")})

        process_ids = [int(document["pid"]) for document in node_ready.values()]
        process_ids.extend(
            (
                int(backend_ready["pid"]),
                int(initial_host_ready["pid"]),
                int(host_ready["pid"]),
                int(client_a_report["pid"]),
                int(unrestricted_report["pid"]),
                int(offline_client.process.pid),
                int(client_b_report["pid"]),
                int(client_c_report["pid"]),
                int(client_d_report["pid"]),
                int(cached_report["pid"]),
                int(fresh_client.process.pid),
            )
        )
        checks = {
            "allBootstrapDownCacheRecovered": cached_exit == 0
            and cached_report.get("status") == 200
            and MESSAGE.encode("ascii") in cached_messages,
            "bootstrapFailureRecovered": node_children[failed_bootstrap_name].process.poll()
            is not None,
            "browserWanIntegration": browser is None
            or (
                browser_result.get("ok") is True
                and browser_result.get("post") is True
                and browser_result.get("runtime", {}).get("gatewayMode") == "wan"
                and browser_result.get("runtime", {}).get("dnsRequests") == 0
            ),
            "browserHostingIntegration": browser is None
            or hosting_source is None
            or (
                hosting_browser_result.get("ok") is True
                and hosting_browser_result.get("settingsPage") is True
                and hosting_browser_result.get("staticAssets") is True
                and hosting_browser_result.get("failClosedWhileOffline") is True
                and hosting_browser_result.get("recovery") is True
                and hosting_browser_result.get("removed") is True
                and hosting_browser_result.get("dnsRequests") == 0
                and hosting_browser_result.get("directFallback") is False
                and not hosting_browser_result.get("harness", {}).get("hostProcessOrphan", True)
            ),
            "clientConnectedOnlyToBootstrapAndEntry": bool(client_ports)
            and client_ports.issubset(allowed_client_ports),
            "clientDidNotConnectToHostBackend": backend_port not in client_ports,
            "clientDidNotConnectToServiceEntry": client_ports.isdisjoint(
                all_service_entry_ports
            ),
            "dnsCalls": len(dns_events) == 0,
            "forumAssets": all(
                client_a_report.get(field) == expected
                for field, expected in (
                    ("pageStatus", 200),
                    ("postStatus", 201),
                    ("scriptStatus", 200),
                    ("styleStatus", 200),
                )
            ),
            "forumMessageRoundTrip": client_a_report.get("messagePresent") is True,
            "independentClientRoute": unrestricted_report.get("status") == 200,
            "hostOfflineFailClosed": offline_exit != 0
            and not offline_report_path.exists()
            and not offline_output_path.exists(),
            "hostRestartRecovered": client_b_report.get("status") == 200
            and MESSAGE.encode("ascii") in client_b_messages
            and initial_host_ready["pid"] != host_ready["pid"],
            "hostConnectedOnlyToBootstrapEntryAndBackend": bool(host_ports)
            and host_ports.issubset(allowed_host_ports),
            "hostDidNotConnectToClientEntry": host_ports.isdisjoint(
                all_client_entry_ports
            ),
            "hostingConnectedOnlyToOverlayNodes": hosting_source is None
            or (
                bool(hosting_browser_ports)
                and hosting_browser_ports.issubset(all_overlay_ports)
            ),
            "independentProcesses": len(process_ids) == len(set(process_ids)),
            "middleFailureRecovered": client_c_report["clientMiddleNodeId"]
            != failed_middle_id,
            "relayPlaintextMarkers": len(marker_hits) == 0,
            "replicationQuorum": all(count >= 2 for count in replica_counts.values()),
            "secondClientRead": client_b_report.get("status") == 200
            and MESSAGE.encode("ascii") in client_b_messages,
            "entryFailureRecovered": client_d_report["clientEntryNodeId"]
            != failed_entry_id,
            "thirdClientRead": client_c_report.get("status") == 200
            and MESSAGE.encode("ascii") in client_c_messages,
            "fourthClientRead": client_d_report.get("status") == 200
            and MESSAGE.encode("ascii") in client_d_messages,
            "freshProfileNetworkUnavailable": fresh_exit != 0
            and not fresh_report_path.exists()
            and not fresh_output_path.exists(),
            "introductionSequenceAdvanced": int(
                (service_state / "introduction-sequence.txt")
                .read_text(encoding="ascii")
                .strip()
            )
            >= 2,
            "multipleIntroductionCircuits": all(
                len(readiness.get("introductionRoutes", [])) >= 2
                and len(set(readiness.get("introductionNodeIds", []))) >= 2
                for readiness in (initial_host_ready, host_ready)
            ),
            "udpSends": len(udp_events) == 0,
        }
        report.update(
            {
                "canonicalName": canonical_name,
                "browser": browser_result,
                "hostingBrowser": hosting_browser_result,
                "checks": checks,
                "clientDestinationPorts": sorted(client_ports),
                "clientRoutes": [
                    [
                        client_a_report["clientEntryNodeId"],
                        client_a_report["clientMiddleNodeId"],
                        initial_host_ready["rendezvousNodeId"],
                    ],
                    [
                        client_b_report["clientEntryNodeId"],
                        client_b_report["clientMiddleNodeId"],
                        host_ready["rendezvousNodeId"],
                    ],
                    [
                        client_c_report["clientEntryNodeId"],
                        client_c_report["clientMiddleNodeId"],
                        host_ready["rendezvousNodeId"],
                    ],
                    [
                        client_d_report["clientEntryNodeId"],
                        client_d_report["clientMiddleNodeId"],
                        host_ready["rendezvousNodeId"],
                    ],
                    [
                        cached_report["clientEntryNodeId"],
                        cached_report["clientMiddleNodeId"],
                        host_ready["rendezvousNodeId"],
                    ],
                ],
                "eventCount": len(all_events),
                "hostDestinationPorts": sorted(host_ports),
                "hostingBrowserDestinationPorts": sorted(hosting_browser_ports),
                "hostRoutes": {
                    "initialIntroductions": initial_host_ready["introductionRoutes"],
                    "initialRendezvous": initial_host_ready["rendezvousRoute"],
                    "restartedIntroductions": host_ready["introductionRoutes"],
                    "restartedRendezvous": host_ready["rendezvousRoute"],
                },
                "markerHits": marker_hits,
                "nodeCount": len(descriptors),
                "processCount": len(process_ids),
                "relayFailures": {
                    "bootstrap": failed_bootstrap_id,
                    "entry": failed_entry_id,
                    "middle": failed_middle_id,
                },
                "routeAttempts": [
                    client_a_report["routeAttempts"],
                    client_b_report["routeAttempts"],
                    client_c_report["routeAttempts"],
                    client_d_report["routeAttempts"],
                    cached_report["routeAttempts"],
                ],
                "replicaCounts": replica_counts,
                "status": "PASS" if all(checks.values()) else "FAIL",
            }
        )
        if report["status"] != "PASS":
            failed = sorted(name for name, passed in checks.items() if not passed)
            raise AcceptanceError(f"WAN process checks failed: {', '.join(failed)}")
    except Exception as error:
        failure = error
        report["status"] = "FAIL"
        report["error"] = f"{type(error).__name__}: {error}"
    finally:
        orphan_processes = stop_children(children)
        report["orphanProcesses"] = orphan_processes
        if orphan_processes:
            report["status"] = "FAIL"
            if failure is None:
                failure = AcceptanceError("child processes remained after cleanup")
        atomic_write_text(
            report_path,
            json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            mode=0o644,
        )
    if failure is not None:
        raise failure
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Granger Network multi-process WAN acceptance")
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--browser", type=Path)
    parser.add_argument("--qt-bin", type=Path)
    parser.add_argument("--expect-packaged-runtime", action="store_true")
    parser.add_argument("--hosting-source", type=Path)
    options = parser.parse_args(argv)
    try:
        if options.browser is not None and not options.expect_packaged_runtime and options.qt_bin is None:
            parser.error("--qt-bin is required for a non-packaged browser")
        if options.hosting_source is not None and options.browser is None:
            parser.error("--hosting-source requires --browser")
        report = run_acceptance(
            options.work_dir,
            options.report,
            browser=options.browser.resolve() if options.browser is not None else None,
            qt_bin=options.qt_bin.resolve() if options.qt_bin is not None else None,
            expect_packaged_runtime=options.expect_packaged_runtime,
            hosting_source=(
                options.hosting_source.resolve() if options.hosting_source is not None else None
            ),
        )
    except Exception as error:
        print(f"wan-process-acceptance: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
