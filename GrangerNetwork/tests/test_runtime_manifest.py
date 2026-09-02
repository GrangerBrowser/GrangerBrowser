from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


TOOL = Path(__file__).resolve().parents[1] / "tools" / "runtime_manifest.py"
SPEC = importlib.util.spec_from_file_location("granger_runtime_manifest", TOOL)
assert SPEC is not None and SPEC.loader is not None
runtime_manifest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime_manifest)


class RuntimeManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="granger-runtime-manifest-")
        self.root = Path(self.temporary.name)
        self.source = self.root / "runtime" / "src" / "granger_network"
        self.tools = self.root / "tools"
        self.source.mkdir(parents=True)
        self.tools.mkdir()
        (self.source / "__init__.py").write_text('__version__ = "0.4.0"\n')
        (self.source / "operator.py").write_text("RUNTIME = 'release-a'\n")
        (self.tools / "runtime_manifest.py").write_bytes(TOOL.read_bytes())
        self.manifest_path = self.root / "runtime-manifest.json"
        self.commit = "a" * 40

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def create(self) -> dict[str, object]:
        document = runtime_manifest.create_manifest(
            self.root,
            ["runtime/src/granger_network", "tools"],
            self.commit,
            3,
            created_at=1_700_000_000,
        )
        runtime_manifest.write_manifest(self.manifest_path, document)
        return document

    def verify(self, **kwargs: object) -> dict[str, object]:
        return runtime_manifest.verify_manifest(
            self.root,
            self.manifest_path,
            expected_protocol_version=3,
            **kwargs,
        )

    def test_complete_manifest_binds_source_protocol_and_content(self) -> None:
        document = self.create()
        result = self.verify(
            expected_source_commit=self.commit,
            expected_release_id=str(document["runtimeReleaseId"]),
        )

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "COMPLETE")
        self.assertEqual(result["fileCount"], 3)
        self.assertIn(self.commit[:12], str(result["runtimeReleaseId"]))

    def test_missing_file_is_rejected(self) -> None:
        self.create()
        (self.source / "operator.py").unlink()

        result = self.verify()

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "MISSING_FILE")
        self.assertEqual(result["missingFiles"], ["runtime/src/granger_network/operator.py"])

    def test_unexpected_file_is_rejected(self) -> None:
        self.create()
        (self.source / "partial-copy.py").write_text("OLD_RELEASE = True\n")

        result = self.verify()

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "UNEXPECTED_FILE")

    def test_manifest_x_with_module_y_is_rejected(self) -> None:
        self.create()
        (self.source / "operator.py").write_text("RUNTIME = 'release-b'\n")

        result = self.verify()

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "HASH_MISMATCH")
        self.assertEqual(
            result["hashMismatches"],
            ["runtime/src/granger_network/operator.py"],
        )

    def test_expected_release_id_detects_complete_wrong_release(self) -> None:
        self.create()

        with self.assertRaises(runtime_manifest.RuntimeIntegrityError) as context:
            self.verify(expected_release_id="granger-runtime-v1-p3-wrong")

        self.assertEqual(context.exception.status, "MIXED_RELEASE")

    def test_protocol_mismatch_is_fail_closed(self) -> None:
        self.create()

        with self.assertRaises(runtime_manifest.RuntimeIntegrityError) as context:
            runtime_manifest.verify_manifest(
                self.root,
                self.manifest_path,
                expected_protocol_version=2,
            )

        self.assertEqual(context.exception.status, "PROTOCOL_MISMATCH")

    def test_manifest_path_traversal_is_rejected(self) -> None:
        document = self.create()
        document["files"][0]["relativePath"] = "../escape.py"
        self.manifest_path.write_text(json.dumps(document), encoding="utf-8")

        with self.assertRaises(runtime_manifest.RuntimeIntegrityError) as context:
            runtime_manifest.verify_manifest(self.root, self.manifest_path)

        self.assertEqual(context.exception.status, "MANIFEST_INVALID")

    def test_symbolic_links_are_rejected_when_supported(self) -> None:
        link = self.source / "linked.py"
        try:
            link.symlink_to(self.source / "operator.py")
        except OSError:
            self.skipTest("symbolic link creation is unavailable")

        with self.assertRaises(runtime_manifest.RuntimeIntegrityError) as context:
            runtime_manifest.create_manifest(
                self.root,
                ["runtime/src/granger_network", "tools"],
                self.commit,
                3,
            )

        self.assertEqual(context.exception.status, "MANIFEST_INVALID")


if __name__ == "__main__":
    unittest.main()
