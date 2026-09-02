from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path, PurePosixPath


SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_FILES = 4096
MAX_RELATIVE_PATH_BYTES = 512
_SOURCE_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class RuntimeIntegrityError(ValueError):
    def __init__(self, status: str, message: str) -> None:
        super().__init__(message)
        self.status = status


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_bytes(document: object) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _relative_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise RuntimeIntegrityError("MANIFEST_INVALID", f"{label} is invalid")
    if "\\" in value or len(value.encode("utf-8")) > MAX_RELATIVE_PATH_BYTES:
        raise RuntimeIntegrityError("MANIFEST_INVALID", f"{label} is not canonical")
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or any(part in ("", ".", "..") for part in candidate.parts):
        raise RuntimeIntegrityError("MANIFEST_INVALID", f"{label} escaped the runtime root")
    canonical = candidate.as_posix()
    if canonical != value:
        raise RuntimeIntegrityError("MANIFEST_INVALID", f"{label} is not canonical")
    return canonical


def _managed_roots(values: list[str]) -> tuple[str, ...]:
    roots = tuple(sorted({_relative_path(value, "managed root") for value in values}))
    if not roots or len(roots) != len(values):
        raise RuntimeIntegrityError("MANIFEST_INVALID", "managed roots are empty or duplicated")
    for index, root in enumerate(roots):
        prefix = root + "/"
        if any(other.startswith(prefix) for other in roots[index + 1 :]):
            raise RuntimeIntegrityError("MANIFEST_INVALID", "managed roots overlap")
    return roots


def _collect_files(root: Path, managed_roots: tuple[str, ...]) -> list[dict[str, object]]:
    package_root = root.resolve(strict=True)
    records: list[dict[str, object]] = []
    for relative_root in managed_roots:
        directory = package_root.joinpath(*PurePosixPath(relative_root).parts)
        if directory.is_symlink() or not directory.is_dir():
            raise RuntimeIntegrityError("MISSING_FILE", f"managed root is unavailable: {relative_root}")
        try:
            directory.resolve(strict=True).relative_to(package_root)
        except (OSError, ValueError) as error:
            raise RuntimeIntegrityError(
                "MANIFEST_INVALID", f"managed root escaped the package: {relative_root}"
            ) from error
        for current, directories, files in os.walk(directory, followlinks=False):
            current_path = Path(current)
            directories.sort()
            files.sort()
            for name in directories:
                if (current_path / name).is_symlink():
                    raise RuntimeIntegrityError(
                        "MANIFEST_INVALID", "symbolic links are not allowed in immutable runtime"
                    )
            for name in files:
                path = current_path / name
                if path.is_symlink() or not path.is_file():
                    raise RuntimeIntegrityError(
                        "MANIFEST_INVALID", "non-regular immutable runtime file was rejected"
                    )
                relative = path.relative_to(package_root).as_posix()
                records.append(
                    {
                        "relativePath": relative,
                        "sha256": _sha256_file(path),
                        "size": path.stat().st_size,
                    }
                )
                if len(records) > MAX_MANIFEST_FILES:
                    raise RuntimeIntegrityError("MANIFEST_INVALID", "runtime manifest has too many files")
    records.sort(key=lambda item: str(item["relativePath"]))
    return records


def _content_document(document: dict[str, object]) -> dict[str, object]:
    return {
        "files": document["files"],
        "managedRoots": document["managedRoots"],
        "protocolVersion": document["protocolVersion"],
        "schemaVersion": document["schemaVersion"],
        "sourceCommit": document["sourceCommit"],
    }


def _release_id(source_commit: str, protocol_version: int, content_sha256: str) -> str:
    return (
        f"granger-runtime-v{SCHEMA_VERSION}-p{protocol_version}-"
        f"{source_commit[:12]}-{content_sha256[:16]}"
    )


def create_manifest(
    root: Path,
    managed_roots: list[str],
    source_commit: str,
    protocol_version: int,
    *,
    created_at: int | None = None,
) -> dict[str, object]:
    if not _SOURCE_COMMIT.fullmatch(source_commit):
        raise RuntimeIntegrityError("MANIFEST_INVALID", "source commit must be a lowercase SHA-1")
    if (
        isinstance(protocol_version, bool)
        or not isinstance(protocol_version, int)
        or not 1 <= protocol_version <= 2**31 - 1
    ):
        raise RuntimeIntegrityError("PROTOCOL_MISMATCH", "protocol version is invalid")
    timestamp = int(time.time()) if created_at is None else created_at
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 1:
        raise RuntimeIntegrityError("MANIFEST_INVALID", "creation timestamp is invalid")
    normalized_roots = _managed_roots(managed_roots)
    document: dict[str, object] = {
        "createdAt": timestamp,
        "files": _collect_files(Path(root), normalized_roots),
        "managedRoots": list(normalized_roots),
        "protocolVersion": protocol_version,
        "schemaVersion": SCHEMA_VERSION,
        "sourceCommit": source_commit,
    }
    content_sha256 = hashlib.sha256(_canonical_bytes(_content_document(document))).hexdigest()
    document["contentSha256"] = content_sha256
    document["runtimeReleaseId"] = _release_id(
        source_commit, protocol_version, content_sha256
    )
    return document


def write_manifest(path: Path, document: dict[str, object]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + f".tmp-{os.getpid()}")
    try:
        temporary.write_text(
            json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _load_manifest(path: Path) -> dict[str, object]:
    source = Path(path)
    try:
        if source.stat().st_size > MAX_MANIFEST_BYTES:
            raise RuntimeIntegrityError("MANIFEST_INVALID", "runtime manifest is too large")
        document = json.loads(source.read_text(encoding="utf-8"))
    except RuntimeIntegrityError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeIntegrityError("MANIFEST_INVALID", "runtime manifest is unreadable") from error
    expected_keys = {
        "contentSha256",
        "createdAt",
        "files",
        "managedRoots",
        "protocolVersion",
        "runtimeReleaseId",
        "schemaVersion",
        "sourceCommit",
    }
    if not isinstance(document, dict) or set(document) != expected_keys:
        raise RuntimeIntegrityError("MANIFEST_INVALID", "runtime manifest schema is invalid")
    if document["schemaVersion"] != SCHEMA_VERSION:
        raise RuntimeIntegrityError("MANIFEST_INVALID", "runtime manifest version is unsupported")
    source_commit = document["sourceCommit"]
    protocol_version = document["protocolVersion"]
    created_at = document["createdAt"]
    if not isinstance(source_commit, str) or not _SOURCE_COMMIT.fullmatch(source_commit):
        raise RuntimeIntegrityError("MANIFEST_INVALID", "runtime source commit is invalid")
    if isinstance(protocol_version, bool) or not isinstance(protocol_version, int) or not 1 <= protocol_version <= 2**31 - 1:
        raise RuntimeIntegrityError("MANIFEST_INVALID", "runtime protocol version is invalid")
    if isinstance(created_at, bool) or not isinstance(created_at, int) or created_at < 1:
        raise RuntimeIntegrityError("MANIFEST_INVALID", "runtime creation timestamp is invalid")
    roots = document["managedRoots"]
    if not isinstance(roots, list) or any(not isinstance(item, str) for item in roots):
        raise RuntimeIntegrityError("MANIFEST_INVALID", "runtime managed roots are invalid")
    normalized_roots = _managed_roots(roots)
    if list(normalized_roots) != roots:
        raise RuntimeIntegrityError("MANIFEST_INVALID", "runtime managed roots are unsorted")
    files = document["files"]
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_MANIFEST_FILES:
        raise RuntimeIntegrityError("MANIFEST_INVALID", "runtime file list is invalid")
    previous = ""
    for record in files:
        if not isinstance(record, dict) or set(record) != {"relativePath", "sha256", "size"}:
            raise RuntimeIntegrityError("MANIFEST_INVALID", "runtime file record is invalid")
        relative = _relative_path(record["relativePath"], "runtime file path")
        if relative <= previous:
            raise RuntimeIntegrityError("MANIFEST_INVALID", "runtime file list is unsorted or duplicated")
        previous = relative
        if not any(relative.startswith(root + "/") for root in normalized_roots):
            raise RuntimeIntegrityError("MANIFEST_INVALID", "runtime file escaped managed roots")
        size = record["size"]
        digest = record["sha256"]
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise RuntimeIntegrityError("MANIFEST_INVALID", "runtime file size is invalid")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise RuntimeIntegrityError("MANIFEST_INVALID", "runtime file digest is invalid")
    content_sha256 = hashlib.sha256(_canonical_bytes(_content_document(document))).hexdigest()
    if document["contentSha256"] != content_sha256:
        raise RuntimeIntegrityError("MANIFEST_INVALID", "runtime content digest is invalid")
    expected_release_id = _release_id(source_commit, protocol_version, content_sha256)
    if document["runtimeReleaseId"] != expected_release_id:
        raise RuntimeIntegrityError("MANIFEST_INVALID", "runtime release ID is invalid")
    return document


def verify_manifest(
    root: Path,
    manifest_path: Path,
    *,
    expected_protocol_version: int | None = None,
    expected_source_commit: str = "",
    expected_release_id: str = "",
) -> dict[str, object]:
    document = _load_manifest(manifest_path)
    if expected_protocol_version is not None and document["protocolVersion"] != expected_protocol_version:
        raise RuntimeIntegrityError("PROTOCOL_MISMATCH", "runtime protocol version differs from policy")
    if expected_source_commit and document["sourceCommit"] != expected_source_commit:
        raise RuntimeIntegrityError("MIXED_RELEASE", "runtime source commit differs from policy")
    if expected_release_id and document["runtimeReleaseId"] != expected_release_id:
        raise RuntimeIntegrityError("MIXED_RELEASE", "runtime release ID differs from policy")
    actual = _collect_files(Path(root), tuple(document["managedRoots"]))
    expected_by_path = {str(item["relativePath"]): item for item in document["files"]}
    actual_by_path = {str(item["relativePath"]): item for item in actual}
    missing = sorted(set(expected_by_path) - set(actual_by_path))
    unexpected = sorted(set(actual_by_path) - set(expected_by_path))
    mismatches = sorted(
        path
        for path in set(expected_by_path) & set(actual_by_path)
        if expected_by_path[path]["size"] != actual_by_path[path]["size"]
        or expected_by_path[path]["sha256"] != actual_by_path[path]["sha256"]
    )
    status = "COMPLETE"
    if missing:
        status = "MISSING_FILE"
    elif unexpected:
        status = "UNEXPECTED_FILE"
    elif mismatches:
        status = "HASH_MISMATCH"
    return {
        "contentSha256": document["contentSha256"],
        "fileCount": len(document["files"]),
        "hashMismatches": mismatches,
        "missingFiles": missing,
        "ok": status == "COMPLETE",
        "protocolVersion": document["protocolVersion"],
        "runtimeReleaseId": document["runtimeReleaseId"],
        "sourceCommit": document["sourceCommit"],
        "status": status,
        "unexpectedFiles": unexpected,
        "version": 1,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create or verify a Granger runtime manifest")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--root", type=Path, required=True)
    create.add_argument("--manifest", type=Path, required=True)
    create.add_argument("--managed-root", action="append", required=True)
    create.add_argument("--source-commit", required=True)
    create.add_argument("--protocol-version", type=int, required=True)
    create.add_argument("--created-at", type=int)
    verify = commands.add_parser("verify")
    verify.add_argument("--root", type=Path, required=True)
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--expected-protocol-version", type=int)
    verify.add_argument("--expected-source-commit", default="")
    verify.add_argument("--expected-release-id", default="")
    return parser


def main(argv: list[str] | None = None) -> int:
    options = _parser().parse_args(argv)
    try:
        if options.command == "create":
            document = create_manifest(
                options.root,
                options.managed_root,
                options.source_commit,
                options.protocol_version,
                created_at=options.created_at,
            )
            write_manifest(options.manifest, document)
            result = {
                "contentSha256": document["contentSha256"],
                "fileCount": len(document["files"]),
                "ok": True,
                "runtimeReleaseId": document["runtimeReleaseId"],
                "status": "COMPLETE",
                "version": 1,
            }
        else:
            result = verify_manifest(
                options.root,
                options.manifest,
                expected_protocol_version=options.expected_protocol_version,
                expected_source_commit=options.expected_source_commit,
                expected_release_id=options.expected_release_id,
            )
    except RuntimeIntegrityError as error:
        result = {
            "error": str(error),
            "ok": False,
            "status": error.status,
            "version": 1,
        }
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
