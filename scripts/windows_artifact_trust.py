"""Offline-only Windows Authenticode verification against an owner public pin."""
from __future__ import annotations

import ctypes as c
import hashlib
import os
import uuid
from pathlib import Path


def verify(path: Path, expected_thumbprint: str) -> None:
    if os.name != "nt":
        raise ValueError("WINDOWS_TRUST_VERIFICATION_UNAVAILABLE")
    from ctypes import wintypes as w

    class FileInfo(c.Structure):
        _fields_ = [("size", w.DWORD), ("path", w.LPCWSTR), ("file", w.HANDLE), ("subject", c.c_void_p)]

    class TrustData(c.Structure):
        _fields_ = [("size", w.DWORD), ("callback", c.c_void_p), ("sip", c.c_void_p),
                    ("ui", w.DWORD), ("revocation", w.DWORD), ("choice", w.DWORD),
                    ("file", c.POINTER(FileInfo)), ("action", w.DWORD), ("state", w.HANDLE),
                    ("url", w.LPWSTR), ("flags", w.DWORD), ("context", w.DWORD), ("settings", c.c_void_p)]

    class Signer(c.Structure):
        _fields_ = [("size", w.DWORD), ("verifiedAt", w.FILETIME), ("certCount", w.DWORD),
                    ("certificates", c.c_void_p), ("type", w.DWORD), ("signer", c.c_void_p),
                    ("error", w.DWORD), ("timestampCount", w.DWORD), ("timestamps", c.c_void_p),
                    ("chain", c.c_void_p)]

    class Certificate(c.Structure):
        _fields_ = [("encoding", w.DWORD), ("encoded", c.POINTER(c.c_ubyte)),
                    ("length", w.DWORD), ("info", c.c_void_p), ("store", w.HANDLE)]

    class ProviderCertificatePrefix(c.Structure):
        _fields_ = [("size", w.DWORD), ("certificate", c.POINTER(Certificate)),
                    ("commercial", w.BOOL), ("trustedRoot", w.BOOL),
                    ("selfSigned", w.BOOL), ("testCertificate", w.BOOL)]

    library = c.WinDLL("wintrust.dll", winmode=0x800)  # LOAD_LIBRARY_SEARCH_SYSTEM32
    library.WinVerifyTrust.argtypes = [w.HWND, c.c_void_p, c.POINTER(TrustData)]
    library.WinVerifyTrust.restype = w.LONG
    library.WTHelperProvDataFromStateData.argtypes = [w.HANDLE]
    library.WTHelperProvDataFromStateData.restype = c.c_void_p
    library.WTHelperGetProvSignerFromChain.argtypes = [c.c_void_p, w.DWORD, w.BOOL, w.DWORD]
    library.WTHelperGetProvSignerFromChain.restype = c.POINTER(Signer)
    library.WTHelperGetProvCertFromChain.argtypes = [c.POINTER(Signer), w.DWORD]
    library.WTHelperGetProvCertFromChain.restype = c.POINTER(ProviderCertificatePrefix)
    guid = c.create_string_buffer(uuid.UUID("00AAC56B-CD44-11d0-8CC2-00C04FC295EE").bytes_le)
    file = FileInfo(c.sizeof(FileInfo), str(path.resolve()), None, None)
    data = TrustData()
    data.size, data.ui, data.choice, data.action = c.sizeof(TrustData), 2, 1, 1
    data.file = c.pointer(file)
    # Enforce revocation using cached evidence, prohibit URL retrieval, reject
    # obsolete digests, and apply Internet-origin policy even to staged copies.
    data.flags = 0x80 | 0x1000 | 0x2000 | 0x4000
    try:
        result = library.WinVerifyTrust(w.HWND(-1), c.byref(guid), c.byref(data))
        if result != 0:
            raise ValueError("WINDOWS_TRUST_VERIFICATION_FAILED")
        provider = library.WTHelperProvDataFromStateData(data.state)
        signer = library.WTHelperGetProvSignerFromChain(provider, 0, False, 0) if provider else None
        if not signer or signer.contents.error or not signer.contents.timestampCount:
            raise ValueError("VALID_TIMESTAMP_REQUIRED")
        timestamp = library.WTHelperGetProvSignerFromChain(provider, 0, True, 0)
        if not timestamp or timestamp.contents.error:
            raise ValueError("VALID_TIMESTAMP_REQUIRED")
        leaf = library.WTHelperGetProvCertFromChain(signer, 0)
        if not leaf or not leaf.contents.certificate or leaf.contents.selfSigned or leaf.contents.testCertificate:
            raise ValueError("TRUSTED_PUBLISHER_REQUIRED")
        certificate = leaf.contents.certificate.contents
        if not certificate.encoded or not 1 <= certificate.length <= 1024 * 1024:
            raise ValueError("INVALID_PUBLISHER_CERTIFICATE")
        encoded = c.string_at(certificate.encoded, certificate.length)
        if hashlib.sha1(encoded).hexdigest().lower() != expected_thumbprint.lower():
            raise ValueError("PUBLISHER_PIN_MISMATCH")
    finally:
        data.action = 2
        library.WinVerifyTrust(w.HWND(-1), c.byref(guid), c.byref(data))
