from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .intelligence_common import DebugLog, compact_text, record_error


SCAN_PROFILE = "service-light-top-1000"
SCAN_TIMEOUT_SECONDS = 360
NMAP_ARGUMENTS = (
    "-sV",
    "--version-light",
    "-T3",
    "--top-ports",
    "1000",
    "--open",
    "--max-retries",
    "2",
    "--host-timeout",
    "4m",
    "-oX",
    "-",
)

SENSITIVE_PORTS: dict[int, tuple[str, str]] = {
    21: ("FTP", "File transfer service is reachable from the Internet."),
    22: ("SSH", "Remote shell service is reachable from the Internet."),
    23: ("Telnet", "Unencrypted remote shell service is reachable from the Internet."),
    111: ("RPC", "RPC service is reachable from the Internet."),
    135: ("RPC", "Windows RPC service is reachable from the Internet."),
    139: ("SMB", "SMB/NetBIOS service is reachable from the Internet."),
    389: ("LDAP", "Directory service is reachable from the Internet."),
    445: ("SMB", "SMB service is reachable from the Internet."),
    636: ("LDAP", "Encrypted directory service is reachable from the Internet."),
    2375: ("Docker API", "Docker API service is reachable from the Internet."),
    2376: ("Docker API", "Docker API service is reachable from the Internet."),
    3306: ("MySQL", "Database service is reachable from the Internet."),
    3389: ("RDP", "Remote desktop service is reachable from the Internet."),
    5432: ("PostgreSQL", "Database service is reachable from the Internet."),
    5985: ("WinRM", "Remote management service is reachable from the Internet."),
    5986: ("WinRM", "Remote management service is reachable from the Internet."),
    6379: ("Redis", "Data store service is reachable from the Internet."),
    6443: ("Kubernetes API", "Kubernetes API service is reachable from the Internet."),
    9200: ("Elasticsearch", "Search/database service is reachable from the Internet."),
    9300: ("Elasticsearch", "Elasticsearch transport service is reachable from the Internet."),
    10250: ("Kubernetes API", "Kubernetes node API is reachable from the Internet."),
    10255: ("Kubernetes API", "Kubernetes read-only node API is reachable from the Internet."),
    27017: ("MongoDB", "Database service is reachable from the Internet."),
}
SENSITIVE_SERVICE_MARKERS = {
    "docker": "Docker API",
    "elasticsearch": "Elasticsearch",
    "ftp": "FTP",
    "kubernetes": "Kubernetes API",
    "ldap": "LDAP",
    "mongodb": "MongoDB",
    "ms-wbt-server": "RDP",
    "mysql": "MySQL",
    "postgresql": "PostgreSQL",
    "rdp": "RDP",
    "redis": "Redis",
    "rpc": "RPC",
    "smb": "SMB",
    "ssh": "SSH",
    "telnet": "Telnet",
    "vnc": "VNC",
    "winrm": "WinRM",
}
WEB_SERVICES = {"http", "https", "http-proxy", "https-alt", "ssl/http"}


def analyze_port_surface(
    target: str,
    ip: str,
    debug_log: DebugLog | None = None,
    *,
    timeout: int = SCAN_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Collect a lightweight TCP service inventory with the system Nmap binary."""
    started = time.monotonic()
    result = _empty_result(target, ip)
    if not ip:
        result["status"] = "skipped"
        result["skip_reason"] = "No resolved IP address"
        result["reason"] = result["skip_reason"]
        return _finish(result, started)

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        result["status"] = "skipped"
        result["skip_reason"] = "Invalid target IP address"
        result["reason"] = result["skip_reason"]
        record_error(result["errors"], debug_log, "[DOMAIN][PORT]", f"target={target} ip={ip} error=invalid IP address")
        return _finish(result, started)

    nmap_path = _resolve_nmap_path()
    if not nmap_path:
        result["status"] = "unavailable"
        result["skip_reason"] = "Nmap is not installed or is not available in PATH"
        result["reason"] = result["skip_reason"]
        record_error(result["errors"], debug_log, "[DOMAIN][PORT]", f"target={target} error=nmap not found")
        return _finish(result, started)

    command = [nmap_path]
    if address.version == 6:
        command.append("-6")
    command.extend(NMAP_ARGUMENTS)
    command.append(str(address))
    result["executable"] = nmap_path
    result["command"] = ["nmap", *command[1:]]

    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(1, int(timeout)),
            check=False,
            creationflags=creation_flags,
        )
    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
        result["skip_reason"] = f"Nmap exceeded the {timeout}-second execution limit"
        result["reason"] = result["skip_reason"]
        record_error(result["errors"], debug_log, "[DOMAIN][PORT]", f"target={target} ip={ip} error=scan timeout")
        return _finish(result, started)
    except OSError as exc:
        result["status"] = "error"
        result["skip_reason"] = "Nmap could not be started"
        result["reason"] = f"{result['skip_reason']}: {exc}"
        record_error(result["errors"], debug_log, "[DOMAIN][PORT]", f"target={target} ip={ip} error={exc}")
        return _finish(result, started)

    result["exit_code"] = completed.returncode
    result["stderr"] = compact_text(completed.stderr, 4000)
    result["xml_bytes"] = len(completed.stdout.encode("utf-8", errors="replace"))
    if not completed.stdout.strip():
        result["status"] = "error"
        detail = compact_text(completed.stderr, 400) or f"nmap exited with code {completed.returncode}"
        result["skip_reason"] = detail
        result["reason"] = detail
        record_error(result["errors"], debug_log, "[DOMAIN][PORT]", f"target={target} ip={ip} error={detail}")
        return _finish(result, started)

    try:
        parsed = parse_nmap_xml(completed.stdout)
    except (ET.ParseError, ValueError) as exc:
        result["status"] = "error"
        result["skip_reason"] = "Nmap returned invalid XML"
        result["reason"] = f"{result['skip_reason']}: {exc}"
        record_error(result["errors"], debug_log, "[DOMAIN][PORT]", f"target={target} ip={ip} error={exc}")
        return _finish(result, started)

    result.update(parsed)
    result["xml_parsed"] = True
    hosts_timed_out = int((parsed.get("scan_metadata") or {}).get("hosts_timed_out") or 0)
    if hosts_timed_out:
        result["status"] = "partial" if result.get("open_ports") else "timeout"
        result["reason"] = f"Nmap host timeout affected {hosts_timed_out} host(s); results may be incomplete"
        record_error(
            result["errors"],
            debug_log,
            "[DOMAIN][PORT]",
            f"target={target} ip={ip} error={result['reason']}",
        )
    else:
        result["status"] = "completed" if completed.returncode == 0 else "partial"
    if completed.returncode != 0 and not result["reason"]:
        detail = compact_text(completed.stderr, 400) or f"nmap exited with code {completed.returncode}"
        result["reason"] = detail
        record_error(result["errors"], debug_log, "[DOMAIN][PORT]", f"target={target} ip={ip} error={detail}")
    return _finish(result, started)


def parse_nmap_xml(xml_text: str) -> dict[str, Any]:
    root = ET.fromstring(xml_text)
    open_ports: list[dict[str, Any]] = []
    for port_node in root.findall("./host/ports/port"):
        state_node = port_node.find("state")
        state = str(state_node.get("state") if state_node is not None else "")
        if state != "open":
            continue
        service_node = port_node.find("service")
        service_node = service_node if service_node is not None else ET.Element("service")
        port = int(port_node.get("portid") or 0)
        protocol = str(port_node.get("protocol") or "tcp")
        service = compact_text(service_node.get("name"), 80)
        product = compact_text(service_node.get("product"), 120)
        version = compact_text(service_node.get("version"), 80)
        extra_info = compact_text(service_node.get("extrainfo"), 180)
        tunnel = compact_text(service_node.get("tunnel"), 30)
        sensitive_name, risk_reason = _sensitive_service(port, service, product)
        open_ports.append(
            {
                "port": port,
                "protocol": protocol,
                "state": state,
                "service": service or "unknown",
                "product": product,
                "version": version,
                "extra_info": extra_info,
                "tunnel": tunnel,
                "cpe": [compact_text(node.text, 180) for node in service_node.findall("cpe") if node.text],
                "sensitive": bool(sensitive_name),
                "risk": "warning" if sensitive_name else "info",
                "risk_label": sensitive_name,
                "risk_reason": risk_reason,
            }
        )

    open_ports.sort(key=lambda row: (int(row["port"]), str(row["protocol"])))
    identified = [row for row in open_ports if row["service"] != "unknown"]
    sensitive = [row for row in open_ports if row["sensitive"]]
    web = [row for row in open_ports if _is_web_service(row)]
    host_nodes = root.findall("./host")
    finished_node = root.find("./runstats/finished")
    hosts_node = root.find("./runstats/hosts")
    hosts_timed_out = sum(1 for node in host_nodes if str(node.get("timedout") or "").lower() == "true")
    scan_metadata = {
        "hosts_timed_out": hosts_timed_out,
        "hosts_up": int(hosts_node.get("up") or 0) if hosts_node is not None else 0,
        "hosts_down": int(hosts_node.get("down") or 0) if hosts_node is not None else 0,
        "hosts_total": int(hosts_node.get("total") or 0) if hosts_node is not None else len(host_nodes),
        "finished_exit": str(finished_node.get("exit") or "") if finished_node is not None else "",
        "elapsed_seconds": str(finished_node.get("elapsed") or "") if finished_node is not None else "",
        "nmap_summary": str(finished_node.get("summary") or "") if finished_node is not None else "",
    }
    return {
        "open_ports": open_ports,
        "scan_metadata": scan_metadata,
        "summary": {
            "open_ports": len(open_ports),
            "services_identified": len(identified),
            "sensitive_services": len(sensitive),
            "web_services": len(web),
            "non_web_services": len(open_ports) - len(web),
            "service_names": sorted({str(row["service"]) for row in identified}),
            "scan_timed_out": bool(hosts_timed_out),
        },
    }


def port_surface_notes(port_surface: dict[str, Any]) -> list[str]:
    ports = list(port_surface.get("open_ports") or [])
    if not ports:
        return []
    notes: list[str] = []
    web = [row for row in ports if _is_web_service(row)]
    sensitive = [row for row in ports if row.get("sensitive")]
    database_labels = {"MySQL", "PostgreSQL", "MongoDB", "Redis", "Elasticsearch"}
    administrative_labels = {"SSH", "RDP", "Telnet", "VNC", "WinRM", "Docker API", "Kubernetes API"}
    labels = {str(row.get("risk_label") or "") for row in sensitive}

    if len(web) == len(ports):
        notes.append("Only HTTP/HTTPS services are exposed.")
    if "SSH" in labels:
        notes.append("SSH service is publicly accessible.")
    if labels & database_labels:
        notes.append("Database service is exposed.")
    if len(labels & administrative_labels) > 1:
        notes.append("Multiple administrative services detected.")
    if len(web) < len(ports):
        notes.append("Non-web services are reachable from the Internet.")
    return notes


def _empty_result(target: str, ip: str) -> dict[str, Any]:
    return {
        "scanner": "nmap",
        "profile": SCAN_PROFILE,
        "target": target,
        "ip": ip,
        "status": "pending",
        "command": [],
        "executable": "",
        "exit_code": None,
        "stderr": "",
        "reason": "",
        "xml_bytes": 0,
        "xml_parsed": False,
        "open_ports": [],
        "summary": {
            "open_ports": 0,
            "services_identified": 0,
            "sensitive_services": 0,
            "web_services": 0,
            "non_web_services": 0,
            "service_names": [],
            "scan_timed_out": False,
        },
        "scan_metadata": {
            "hosts_timed_out": 0,
            "hosts_up": 0,
            "hosts_down": 0,
            "hosts_total": 0,
            "finished_exit": "",
            "elapsed_seconds": "",
            "nmap_summary": "",
        },
        "skip_reason": "",
        "errors": [],
        "started_at": _utc_timestamp(),
        "completed_at": "",
        "duration_ms": 0,
    }


def _finish(result: dict[str, Any], started: float) -> dict[str, Any]:
    result["completed_at"] = _utc_timestamp()
    result["duration_ms"] = round((time.monotonic() - started) * 1000)
    return result


def _resolve_nmap_path() -> str:
    discovered = shutil.which("nmap")
    if discovered:
        return discovered
    if os.name != "nt":
        return ""
    roots = [
        os.environ.get("ProgramFiles"),
        os.environ.get("ProgramFiles(x86)"),
        os.environ.get("LOCALAPPDATA"),
    ]
    candidates = []
    for root in roots:
        if not root:
            continue
        base = Path(root)
        candidates.append(base / "Nmap" / "nmap.exe")
        candidates.append(base / "Programs" / "Nmap" / "nmap.exe")
    candidates.extend(
        [
            Path(r"C:\Program Files\Nmap\nmap.exe"),
            Path(r"C:\Program Files (x86)\Nmap\nmap.exe"),
        ]
    )
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return ""


def _sensitive_service(port: int, service: str, product: str) -> tuple[str, str]:
    if 5900 <= port <= 5999:
        return "VNC", "Remote desktop service is reachable from the Internet."
    if port in SENSITIVE_PORTS:
        return SENSITIVE_PORTS[port]
    combined = f"{service} {product}".lower()
    for marker, label in SENSITIVE_SERVICE_MARKERS.items():
        if marker in combined:
            return label, f"{label} service is reachable from the Internet."
    return "", ""


def _is_web_service(row: dict[str, Any]) -> bool:
    service = str(row.get("service") or "").lower()
    tunnel = str(row.get("tunnel") or "").lower()
    return service in WEB_SERVICES or service.startswith("http") or (tunnel == "ssl" and service == "http")


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
