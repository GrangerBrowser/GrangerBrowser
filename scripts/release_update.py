"""Verified update preparation and explicitly approved Windows installer apply.

The browser supplies privacy-routed downloads. This module never downloads or
creates trust. Prepared installers require fresh verification and restart consent.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from windows_artifact_trust import verify as verify_authenticode

DOMAIN = b"Granger Browser release manifest v1\x00"
MAX_MANIFEST = 64 * 1024
MAX_ARTIFACT = 2 * 1024 * 1024 * 1024
MAX_VALIDITY = 31 * 24 * 60 * 60


class UpdateError(ValueError):
    pass


def canonical(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise UpdateError("DUPLICATE_FIELD")
        result[key] = value
    return result


def read_json(path: Path):
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_MANIFEST + 1)
        if len(raw) > MAX_MANIFEST:
            raise UpdateError("METADATA_TOO_LARGE")
        result = json.loads(raw, object_pairs_hook=_pairs)
        if not isinstance(result, dict):
            raise UpdateError("INVALID_METADATA")
        return result
    except (OSError, UnicodeError, ValueError, RecursionError) as error:
        raise UpdateError("INVALID_OR_MISSING_METADATA") from error


def _local_path(path: Path):
    if str(path).startswith(("\\\\", "//")):
        raise UpdateError("NETWORK_FILESYSTEM_REJECTED")
    absolute = path.absolute()
    for member in (absolute, *absolute.parents):
        if member.is_symlink() or getattr(member, "is_junction", lambda: False)():
            raise UpdateError("INDIRECT_FILESYSTEM_PATH_REJECTED")


def _atomic(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".update-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        if os.name != "nt":
            fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    finally:
        Path(name).unlink(missing_ok=True)


@contextmanager
def _lease(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as stream:
        if stream.seek(0, os.SEEK_END) == 0:
            stream.write(b"\x00")
            stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise UpdateError("UPDATE_BUSY") from error
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def policy(root: Path):
    _local_path(root)
    path = root / "policy.json"
    if not path.exists():
        return {"version": 1, "mode": "ask", "revision": 0}
    value = read_json(path)
    if (set(value) != {"version", "mode", "revision"} or value["version"] != 1
            or type(value["version"]) is not int or not isinstance(value["mode"], str) or value["mode"] not in {"ask", "auto"}
            or type(value["revision"]) is not int or not 1 <= value["revision"] < 2**63):
        raise UpdateError("INVALID_POLICY")
    return value


def set_policy(root: Path, mode: str, *, user_consent: bool = False):
    _local_path(root)
    if mode not in {"ask", "auto"} or (mode == "auto" and not user_consent):
        raise UpdateError("USER_CONSENT_REQUIRED")
    with _lease(root / "policy.lock"):
        previous = policy(root)
        value = {"version": 1, "mode": mode, "revision": previous["revision"] + 1}
        if value["revision"] >= 2**63:
            raise UpdateError("POLICY_REVISION_EXHAUSTED")
        _atomic(root / "policy.json", canonical(value))
    return value


def _version(value):
    if not isinstance(value, str) or not re.fullmatch(r"(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})", value):
        raise UpdateError("INVALID_PRODUCT_VERSION")
    return tuple(map(int, value.split(".")))


def _decode(value, size):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise UpdateError("INVALID_SIGNATURE_ENCODING")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError as error:
        raise UpdateError("INVALID_SIGNATURE_ENCODING") from error
    if len(decoded) != size or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
        raise UpdateError("INVALID_SIGNATURE_ENCODING")
    return decoded


def load_trust(path: Path):
    if not path.is_file():
        raise UpdateError("SIGNING_TRUST_NOT_CONFIGURED")
    value = read_json(path)
    if (set(value) != {"version", "manifestPublicKey", "windowsCertificateSha1"}
            or type(value["version"]) is not int or value["version"] != 1
            or not isinstance(value["windowsCertificateSha1"], str)
            or not re.fullmatch(r"[A-Fa-f0-9]{40}", value["windowsCertificateSha1"])):
        raise UpdateError("INVALID_SIGNING_TRUST")
    _decode(value["manifestPublicKey"], 32)
    return value


def verify_manifest(path: Path, trust, *, current_version: str, platform="windows-x64", now=None):
    value = read_json(path)
    fields = {"version", "sequence", "productVersion", "platform", "issuedAt", "expiresAt",
              "artifact", "size", "sha256", "windowsCertificateSha1", "releaseNotes", "signature"}
    if set(value) != fields or type(value["version"]) is not int or value["version"] != 1:
        raise UpdateError("INVALID_MANIFEST_SCHEMA")
    unsigned = {key: item for key, item in value.items() if key != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(_decode(trust["manifestPublicKey"], 32)).verify(
            _decode(value["signature"], 64), DOMAIN + canonical(unsigned))
    except (InvalidSignature, TypeError) as error:
        raise UpdateError("INVALID_MANIFEST_SIGNATURE") from error
    for name, low, high in (("sequence", 1, 2**63-1), ("size", 1, MAX_ARTIFACT),
                            ("issuedAt", 1, 2**63-1), ("expiresAt", 1, 2**63-1)):
        if type(value[name]) is not int or not low <= value[name] <= high:
            raise UpdateError("INVALID_MANIFEST_BOUNDS")
    current = int(time.time()) if now is None else now
    if not (value["issuedAt"] <= current < value["expiresAt"]
            and 0 < value["expiresAt"] - value["issuedAt"] <= MAX_VALIDITY):
        raise UpdateError("MANIFEST_NOT_CURRENTLY_VALID")
    if value["platform"] != platform or platform != "windows-x64":
        raise UpdateError("WRONG_PLATFORM")
    if _version(value["productVersion"]) <= _version(current_version):
        raise UpdateError("DOWNGRADE_REJECTED")
    if (value["artifact"] != "GrangerSetup.exe"
            or not isinstance(value["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", value["sha256"])
            or value["windowsCertificateSha1"] != trust["windowsCertificateSha1"]
            or not isinstance(value["releaseNotes"], str) or len(value["releaseNotes"]) > 8192
            or any(ord(char) < 32 and char not in "\n\t" for char in value["releaseNotes"])):
        raise UpdateError("INVALID_ARTIFACT_METADATA")
    return value


def verify_windows_signature(path: Path, thumbprint: str):
    try:
        verify_authenticode(path, thumbprint)
    except (OSError, ValueError) as error:
        raise UpdateError("WINDOWS_TRUST_VERIFICATION_FAILED") from error


def prepare(root: Path, manifest: Path, artifact: Path, trust_path: Path, *,
            current_version: str, user_approved: bool = False, now=None):
    for path in (root, manifest, artifact, trust_path):
        _local_path(path)
    initial_policy = policy(root)
    if not user_approved and initial_policy["mode"] != "auto":
        raise UpdateError("USER_CONSENT_REQUIRED")
    trust = load_trust(trust_path)
    value = verify_manifest(manifest, trust, current_version=current_version, now=now)
    digest = hashlib.sha256(canonical(value)).hexdigest()
    with _lease(root / "prepare.lock"):
        name = f"{value['sequence']:019d}-{digest}.exe"
        retained = [item for item in root.iterdir() if re.fullmatch(r"[0-9]{19}-[a-f0-9]{64}\.exe", item.name)]
        if len(retained) >= 2 and not (root / name).exists():
            raise UpdateError("PREPARED_UPDATE_LIMIT_REACHED")
        high_path = root / "high-water.json"
        if high_path.exists():
            high = read_json(high_path)
            if (set(high) != {"sequence", "manifestSha256", "productVersion"}
                    or type(high["sequence"]) is not int or not 1 <= high["sequence"] < 2**63
                    or not isinstance(high["manifestSha256"], str)
                    or not re.fullmatch(r"[a-f0-9]{64}", high["manifestSha256"])):
                raise UpdateError("INVALID_UPDATE_HIGH_WATER")
            if (value["sequence"] < high["sequence"] or _version(value["productVersion"]) < _version(high["productVersion"])
                    or (value["sequence"] == high["sequence"] and digest != high["manifestSha256"])):
                raise UpdateError("UPDATE_ROLLBACK_OR_EQUIVOCATION")
        with tempfile.TemporaryDirectory(prefix=".candidate-", dir=root) as temporary:
            candidate = Path(temporary) / "GrangerSetup.exe"
            checksum, total = hashlib.sha256(), 0
            with artifact.open("rb") as source, candidate.open("xb") as destination:
                while chunk := source.read(1024 * 1024):
                    total += len(chunk)
                    if total > value["size"]:
                        raise UpdateError("ARTIFACT_SIZE_MISMATCH")
                    checksum.update(chunk)
                    destination.write(chunk)
                destination.flush()
                os.fsync(destination.fileno())
            if total != value["size"] or checksum.hexdigest() != value["sha256"]:
                raise UpdateError("ARTIFACT_HASH_MISMATCH")
            verify_windows_signature(candidate, trust["windowsCertificateSha1"])
            # Consent/trust changes during slow copying or OS verification cancel
            # activation. Neither a manifest nor remote policy can opt a user in.
            with _lease(root / "policy.lock"):
                if policy(root) != initial_policy or load_trust(trust_path) != trust:
                    raise UpdateError("CONSENT_OR_TRUST_CHANGED")
                if verify_manifest(manifest, trust, current_version=current_version, now=now) != value:
                    raise UpdateError("MANIFEST_CHANGED")
                final = root / name
                os.replace(candidate, final)
                _atomic(root / (name + ".json"), canonical(value))
                high = {"sequence": value["sequence"], "manifestSha256": digest, "productVersion": value["productVersion"]}
                _atomic(high_path, canonical(high))
                pending = dict(high, artifact=name, artifactSha256=value["sha256"], state="AWAITING_RESTART_CONSENT")
                _atomic(root / "pending.json", canonical(pending))
                return pending


def _pending_artifact(root: Path):
    pending = read_json(root / "pending.json")
    name = pending.get("artifact", "")
    if not isinstance(name, str) or not re.fullmatch(r"[0-9]{19}-[a-f0-9]{64}\.exe", name):
        raise UpdateError("INVALID_PENDING_UPDATE")
    artifact = (root / name).absolute()
    _local_path(artifact)
    return pending, artifact


def verify_pending(root: Path, trust_path: Path, *, current_version: str, user_approved=False):
    if not user_approved:
        raise UpdateError("RESTART_CONSENT_REQUIRED")
    _local_path(root)
    _local_path(trust_path)
    initial_policy = policy(root)
    trust = load_trust(trust_path)
    pending, artifact = _pending_artifact(root)
    name = artifact.name
    manifest = root / (name + ".json")
    _local_path(manifest)
    value = verify_manifest(manifest, trust, current_version=current_version)
    digest = hashlib.sha256(canonical(value)).hexdigest()
    high = {"sequence": value["sequence"], "manifestSha256": digest, "productVersion": value["productVersion"]}
    expected = dict(high, artifact=name, artifactSha256=value["sha256"], state="AWAITING_RESTART_CONSENT")
    if pending != expected or read_json(root / "high-water.json") != high:
        raise UpdateError("PENDING_UPDATE_STATE_MISMATCH")
    checksum, total = hashlib.sha256(), 0
    with artifact.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            total += len(chunk)
            if total > value["size"]:
                raise UpdateError("ARTIFACT_SIZE_MISMATCH")
            checksum.update(chunk)
    if total != value["size"] or checksum.hexdigest() != value["sha256"]:
        raise UpdateError("ARTIFACT_HASH_MISMATCH")
    verify_windows_signature(artifact, trust["windowsCertificateSha1"])
    if policy(root) != initial_policy or load_trust(trust_path) != trust:
        raise UpdateError("CONSENT_OR_TRUST_CHANGED")
    return artifact


@contextmanager
def _locked_windows_artifact(path: Path):
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32.dll", winmode=0x800, use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    # Deny writes/replacement between the final hash/trust checks and CreateProcess.
    handle = kernel.CreateFileW(str(path), 0x80000000, 1, None, 3, 0x80, None)
    if handle == wintypes.HANDLE(-1).value:
        raise UpdateError("UPDATE_ARTIFACT_LOCK_FAILED")
    try:
        yield
    finally:
        kernel.CloseHandle(handle)


def apply_after_exit(root: Path, trust: Path, *, current_version: str, parent_pid: int, user_approved=False):
    if not user_approved:
        raise UpdateError("RESTART_CONSENT_REQUIRED")
    if os.name != "nt":
        raise UpdateError("WRONG_PLATFORM")
    if type(parent_pid) is not int or not 4 < parent_pid < 2**32:
        raise UpdateError("INVALID_BROWSER_PID")
    _local_path(root)
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32.dll", winmode=0x800, use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x100000, False, parent_pid)
    if not handle and ctypes.get_last_error() != 87:
        raise UpdateError("BROWSER_EXIT_WAIT_UNAVAILABLE")
    try:
        if handle and kernel.WaitForSingleObject(handle, 60000) != 0:
            raise UpdateError("BROWSER_STILL_RUNNING")
    finally:
        if handle:
            kernel.CloseHandle(handle)
    with _lease(root / "prepare.lock"):
        _pending, candidate = _pending_artifact(root)
        with _locked_windows_artifact(candidate):
            artifact = verify_pending(root, trust, current_version=current_version, user_approved=True)
            if artifact != candidate:
                raise UpdateError("PENDING_UPDATE_CHANGED")
            # Existing embedded-payload setup owns rollback and rechecks running browsers.
            process = subprocess.Popen([str(artifact)], cwd=root, close_fds=True)
            return {"state": "INSTALLER_STARTED", "pid": process.pid}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    change = commands.add_parser("policy")
    change.add_argument("mode", choices=("ask", "auto"))
    change.add_argument("--user-consent", action="store_true")
    stage = commands.add_parser("prepare")
    for name in ("manifest", "artifact", "trust"):
        stage.add_argument("--" + name, type=Path, required=True)
    stage.add_argument("--current-version", required=True)
    stage.add_argument("--user-approved", action="store_true")
    check = commands.add_parser("verify-manifest")
    check.add_argument("--manifest", type=Path, required=True)
    check.add_argument("--trust", type=Path, required=True)
    check.add_argument("--current-version", required=True)
    trust_check = commands.add_parser("verify-trust")
    trust_check.add_argument("--trust", type=Path, required=True)
    apply = commands.add_parser("apply")
    apply.add_argument("--trust", type=Path, required=True)
    apply.add_argument("--current-version", required=True)
    apply.add_argument("--parent-pid", type=int, required=True)
    apply.add_argument("--user-approved", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "policy":
            result = set_policy(args.state_dir, args.mode, user_consent=args.user_consent)
        elif args.command == "prepare":
            result = prepare(args.state_dir, args.manifest, args.artifact, args.trust,
                             current_version=args.current_version, user_approved=args.user_approved)
        elif args.command == "verify-trust":
            _local_path(args.trust)
            load_trust(args.trust)
            result = {"ok": True}
        elif args.command == "verify-manifest":
            _local_path(args.manifest)
            _local_path(args.trust)
            result = verify_manifest(args.manifest, load_trust(args.trust), current_version=args.current_version)
        elif args.command == "apply":
            result = apply_after_exit(args.state_dir, args.trust, current_version=args.current_version,
                                      parent_pid=args.parent_pid, user_approved=args.user_approved)
        else:
            result = {"policy": policy(args.state_dir), "automaticExecution": False,
                      "pending": (read_json(args.state_dir / "pending.json")
                                  if (args.state_dir / "pending.json").exists() else None)}
        print(json.dumps(result, sort_keys=True))
        return 0
    except (UpdateError, OSError) as error:
        print(json.dumps({"status": "BLOCKED", "code": str(error) if isinstance(error, UpdateError) else "LOCAL_IO_FAILURE"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
