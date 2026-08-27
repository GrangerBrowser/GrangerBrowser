#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


CHUNK_SIZE = 1024 * 1024
OVERLAP_SIZE = 4096
ASCII_RULES = (
    (
        "pem-private-key",
        re.compile(
            rb"-----BEGIN ((?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY)-----"
            rb"[\r\n]+[A-Za-z0-9+/=\r\n]{64,}-----END \1-----"
        ),
        True,
    ),
    (
        "serialized-private-key",
        re.compile(
            rb'''(?ix)["'](?:private[_-]?key|identity[_-]?seed|signing[_-]?seed)["']\s*:\s*["'][a-z0-9+/_=-]{40,}["']'''
        ),
        True,
    ),
    (
        "windows-user-path",
        re.compile(rb"(?i)[a-z]:\\Users\\(?!<)[^\\\x00\r\n]{1,64}\\"),
        False,
    ),
    (
        "linux-home-path",
        re.compile(rb"/home/(?!<)[^/\x00\r\n]{1,64}/"),
        False,
    ),
)
PRIVATE_STATE_NAMES = frozenset(
    {
        "client-identity.json",
        "network-identity.json",
        "node-identity.json",
        "service-identity.json",
        "service.key",
    }
)


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    marker_index: int | None = None
    blocking: bool = True

    def document(self) -> dict[str, object]:
        result: dict[str, object] = {"path": self.path, "rule": self.rule}
        if self.marker_index is not None:
            result["markerIndex"] = self.marker_index
        return result


def _markers(path: Path | None, require: bool) -> tuple[bytes, ...]:
    if path is None:
        if require:
            raise ValueError("a private marker file is required")
        return ()
    if not path.is_file():
        raise ValueError(f"private marker file was not found: {path}")
    result: list[bytes] = []
    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        encoded = line.encode("utf-8")
        if len(encoded) < 4:
            raise ValueError("private markers must contain at least four UTF-8 bytes")
        if encoded not in result:
            result.append(encoded)
    if require and not result:
        raise ValueError("the private marker file contains no markers")
    return tuple(result)


def _encoded_markers(markers: tuple[bytes, ...]) -> tuple[tuple[int, bytes], ...]:
    result: list[tuple[int, bytes]] = []
    for index, marker in enumerate(markers):
        text = marker.decode("utf-8")
        for encoded in (marker, text.encode("utf-16-le"), text.encode("utf-16-be")):
            result.append((index, encoded))
    return tuple(result)


def _scan_file(
    path: Path,
    relative: str,
    markers: tuple[tuple[int, bytes], ...],
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, int | None]] = set()
    carry = b""
    with path.open("rb") as source:
        while True:
            content = source.read(CHUNK_SIZE)
            if not content:
                break
            sample = carry + content
            for index, marker in markers:
                key = ("private-marker", index)
                if key not in seen and marker in sample:
                    findings.append(Finding("private-marker", relative, index))
                    seen.add(key)
            for name, pattern, blocking in ASCII_RULES:
                key = (name, None)
                if key not in seen and pattern.search(sample):
                    findings.append(Finding(name, relative, blocking=blocking))
                    seen.add(key)
            for encoding in ("utf-16-le", "utf-16-be"):
                decoded = sample.decode(encoding, errors="ignore").encode("utf-8")
                for name, pattern, blocking in ASCII_RULES:
                    key = (f"{name}-utf16", None)
                    if key not in seen and pattern.search(decoded):
                        findings.append(Finding(name, relative, blocking=blocking))
                        seen.add(key)
            carry = sample[-OVERLAP_SIZE:]
    return findings


def _files(root: Path):
    if root.is_file():
        yield root, root.name
        return
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            yield path, path.relative_to(root).as_posix()


def _tracked_files(root: Path):
    if not root.is_dir():
        raise ValueError(f"Git tracked root was not found: {root}")
    completed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode(errors="replace").strip()[:512]
        raise ValueError(f"could not enumerate Git tracked files below {root}: {detail}")
    for raw_relative in completed.stdout.split(b"\0"):
        if not raw_relative:
            continue
        relative = os.fsdecode(raw_relative)
        path = root / relative
        if path.is_file() and not path.is_symlink():
            yield path, relative.replace("\\", "/")


def scan_roots(
    roots: tuple[Path, ...],
    markers: tuple[bytes, ...],
    tracked_roots: tuple[Path, ...] = (),
) -> dict[str, object]:
    encoded = _encoded_markers(markers)
    findings: list[Finding] = []
    files_scanned = 0
    bytes_scanned = 0
    sources = []
    for root in roots:
        if not root.exists():
            raise ValueError(f"privacy scan root was not found: {root}")
        sources.append(_files(root))
    sources.extend(_tracked_files(root) for root in tracked_roots)
    for source in sources:
        for path, relative in source:
            files_scanned += 1
            bytes_scanned += path.stat().st_size
            if (
                path.name.lower() in PRIVATE_STATE_NAMES
                or path.suffix.lower() in {".p12", ".pfx"}
            ):
                findings.append(Finding("private-state-file", relative))
            findings.extend(_scan_file(path, relative, encoded))
    blocking = [finding for finding in findings if finding.blocking]
    advisories = [finding for finding in findings if not finding.blocking]
    return {
        "advisories": [finding.document() for finding in advisories],
        "bytesScanned": bytes_scanned,
        "filesScanned": files_scanned,
        "findings": [finding.document() for finding in blocking],
        "markerCount": len(markers),
        "ok": not blocking,
        "rootsScanned": len(roots),
        "trackedRootsScanned": len(tracked_roots),
        "version": 1,
    }


def _extract_appimage(path: Path, target: Path) -> Path:
    target.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["APPIMAGE_EXTRACT_AND_RUN"] = "1"
    completed = subprocess.run(
        [str(path), "--appimage-extract"],
        cwd=target,
        env=environment,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        timeout=180,
    )
    extracted = target / "squashfs-root"
    if completed.returncode != 0 or not extracted.is_dir():
        raise ValueError(
            "AppImage extraction failed: " + completed.stderr.strip()[:512]
        )
    return extracted


def _self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="granger-privacy-scan-") as temporary:
        root = Path(temporary)
        marker = "operator-marker-7f5e19"
        safe = root / "safe"
        safe.mkdir()
        (safe / "readme.txt").write_text("RFC1918 example: 192.168.10.20\n", encoding="utf-8")
        if not scan_roots((safe,), (marker.encode("ascii"),))["ok"]:
            return 2
        (safe / "leak.bin").write_bytes(b"prefix " + marker.encode("ascii") + b" suffix")
        if scan_roots((safe,), (marker.encode("ascii"),))["ok"]:
            return 3
        (safe / "leak.bin").write_text(
            "-----BEGIN "
            + "PRIVATE KEY-----\n"
            + "A" * 80
            + "\n-----END PRIVATE KEY-----\n",
            encoding="ascii",
        )
        if scan_roots((safe,), ())["ok"]:
            return 4
        tracked = root / "tracked"
        tracked.mkdir()
        subprocess.run(["git", "init", "-q", str(tracked)], check=True)
        (tracked / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
        (tracked / "safe.txt").write_text("public source\n", encoding="utf-8")
        (tracked / "ignored.txt").write_text(marker, encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(tracked), "add", ".gitignore", "safe.txt"],
            check=True,
        )
        if not scan_roots((), (marker.encode("ascii"),), (tracked,))["ok"]:
            return 5
        subprocess.run(
            ["git", "-C", str(tracked), "add", "-f", "ignored.txt"],
            check=True,
        )
        if scan_roots((), (marker.encode("ascii"),), (tracked,))["ok"]:
            return 6
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan release artifacts for private build markers")
    parser.add_argument("--root", type=Path, action="append", default=[])
    parser.add_argument("--git-tracked-root", type=Path, action="append", default=[])
    parser.add_argument("--appimage", type=Path, action="append", default=[])
    parser.add_argument("--marker-file", type=Path)
    parser.add_argument("--require-marker-file", action="store_true")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--self-test", action="store_true")
    options = parser.parse_args(argv)
    if options.self_test:
        return _self_test()
    if not options.root and not options.git_tracked_root and not options.appimage:
        parser.error("at least one --root, --git-tracked-root or --appimage is required")
    temporary = Path(tempfile.mkdtemp(prefix="granger-appimage-scan-"))
    try:
        roots = tuple(options.root) + tuple(
            _extract_appimage(path, temporary / f"image-{index}")
            for index, path in enumerate(options.appimage)
        )
        markers = _markers(options.marker_file, options.require_marker_file)
        report = scan_roots(roots, markers, tuple(options.git_tracked_root))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report = {"error": str(error), "ok": False, "version": 1}
    finally:
        shutil.rmtree(temporary, ignore_errors=True)
    encoded = json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    if options.report is not None:
        options.report.parent.mkdir(parents=True, exist_ok=True)
        options.report.write_text(encoded, encoding="utf-8", newline="\n")
    sys.stdout.write(encoded)
    return 0 if report.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
