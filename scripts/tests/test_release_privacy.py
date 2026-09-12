from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "release_privacy", Path(__file__).resolve().parents[1] / "test-release-privacy.py"
)
privacy = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = privacy
spec.loader.exec_module(privacy)


class PublicSelfTestClassificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        # Synthetic, non-key payloads test classification without storing key material.
        self.vector = b"-----BEGIN PRIVATE KEY-----\n" + b"A" * 96 + b"\n-----END PRIVATE KEY-----"
        self.other = self.vector.replace(b"A" * 96, b"B" * 96)
        self.allowed = frozenset({hashlib.sha256(self.vector).hexdigest()})

    def scan(self, content, name="libgnutls.so.30", markers=()):
        (self.root / name).write_bytes(content)
        with patch.object(privacy, "GNUTLS_PUBLIC_SELF_TEST_SHA256", self.allowed):
            return privacy.scan_roots((self.root,), markers)

    def test_exact_public_vector_is_reported_not_hidden(self):
        result = self.scan(b"\x7fELF\0" + self.vector)
        self.assertTrue(result["ok"])
        self.assertEqual(result["advisories"][0]["rule"], "upstream-public-self-test")

    def test_unknown_key_in_same_library_remains_blocked(self):
        result = self.scan(b"\x7fELF\0" + self.vector + b"\0" + self.other)
        self.assertFalse(result["ok"])
        self.assertIn("pem-private-key", [f["rule"] for f in result["findings"]])

    def test_changed_vector_remains_blocked(self):
        self.assertFalse(self.scan(b"\x7fELF\0" + self.other)["ok"])

    def test_filename_alone_does_not_exempt_text(self):
        self.assertFalse(self.scan(self.vector)["ok"])

    def test_public_vector_in_application_state_is_not_exempt(self):
        self.assertFalse(self.scan(b"\x7fELF\0" + self.vector, name="service.key")["ok"])

    def test_private_marker_always_blocks_even_public_vector(self):
        result = self.scan(b"\x7fELF\0" + self.vector, markers=(b"A" * 96,))
        self.assertFalse(result["ok"])
        self.assertIn("private-marker", [f["rule"] for f in result["findings"]])

    def test_later_chunk_unknown_key_is_not_masked_by_public_match(self):
        content = b"\x7fELF\0" + self.vector + b"\0" * privacy.CHUNK_SIZE + self.other
        self.assertFalse(self.scan(content)["ok"])

    def test_utf16_key_remains_blocked(self):
        content = b"\x7fELF\0" + self.vector.decode().encode("utf-16-le")
        self.assertFalse(self.scan(content)["ok"])


if __name__ == "__main__":
    unittest.main()
