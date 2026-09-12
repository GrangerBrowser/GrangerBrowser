from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from granger_network.descriptor import ServiceDescriptor
from granger_network.distributed import SERVICE_RECORD, encode_record
from granger_network.errors import DescriptorError
from granger_network.hosting import HostingTraffic, initialize_hosted_service, load_hosted_service, set_hosted_visibility
from granger_network import hosting
from granger_network.http_bridge import HttpResult
from granger_network.identity import ServiceIdentity
from granger_network.wan_discovery import PersistentRecordStore, decode_public_service_sample, encode_public_service_sample


class HostingDashboardTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows atomic rename sharing semantics")
    def test_status_publication_survives_a_short_lived_reader(self):
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = ServiceDescriptor.create_remote(ServiceIdentity.generate(), "distributed-overlay")
            hosting._write_status(root, "starting", service)
            path = root / hosting.STATUS_FILE
            previous = path.read_bytes()
            handle = kernel.CreateFileW(str(path), 0x80000000, 7, None, 3, 0x80, None)
            self.assertNotEqual(handle, wintypes.HANDLE(-1).value)
            closed = False
            def release_reader(_delay):
                nonlocal closed
                self.assertEqual(path.read_bytes(), previous)
                kernel.CloseHandle(handle)
                closed = True
            try:
                with patch.object(hosting.time, "sleep", side_effect=release_reader) as pause:
                    hosting._write_status(root, "online", service)
                    self.assertEqual(pause.call_count, 1)
                self.assertEqual(json.loads(path.read_bytes())["state"], "online")
                self.assertFalse(list(path.parent.glob("*.tmp")))
            finally:
                if not closed:
                    kernel.CloseHandle(handle)

    @unittest.skipUnless(os.name == "nt", "Windows sharing retry budget")
    def test_permanent_status_permission_error_is_not_hidden(self):
        service = ServiceDescriptor.create_remote(ServiceIdentity.generate(), "distributed-overlay")
        error = PermissionError("denied")
        error.winerror = 5
        with patch.object(hosting, "atomic_write_text", side_effect=error) as write:
            with patch.object(hosting.time, "sleep") as pause:
                with self.assertRaises(PermissionError):
                    hosting._write_status(Path("unused-fixture"), "online", service)
        self.assertEqual(write.call_count, 6)
        self.assertEqual(sum(call.args[0] for call in pause.call_args_list), 0.15)

    def test_visibility_survives_reload_and_other_services_are_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            site = root / "site"
            site.mkdir()
            (site / "index.html").write_text("<h1>Fixture</h1>")
            services = root / "services"
            for name in ("a", "b", "c"):
                initialize_hosted_service(services, name * 32, name, "static", source=str(site))
            before = {name: load_hosted_service(services / (name * 32)) for name in ("b", "c")}
            for visibility in ("public", "unlisted", "public", "unlisted"):
                set_hosted_visibility(services / ("a" * 32), visibility)
                self.assertEqual(load_hosted_service(services / ("a" * 32))[0].visibility, visibility)
            shutil.rmtree(services / ("a" * 32))
            for name in ("b", "c"):
                config, identity, descriptor = load_hosted_service(services / (name * 32))
                self.assertEqual(config, before[name][0])
                self.assertEqual(identity.public_key_bytes, before[name][1].public_key_bytes)
                self.assertEqual(descriptor, before[name][2])

    def test_network_store_never_lists_hidden_but_exact_lookup_survives_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "records.json"
            store = PersistentRecordStore(path)
            identity = ServiceIdentity.generate()
            now = int(time.time())
            public = ServiceDescriptor.create_remote(identity, "distributed-overlay",
                metadata={"visibility": "public"}, issued_at=now, lifetime=1800)
            store.store(encode_record(public))
            self.assertEqual(decode_public_service_sample(encode_public_service_sample(store.public_service_sample())), (public,))
            hidden = ServiceDescriptor.create_remote(identity, "distributed-overlay",
                metadata={}, issued_at=now + 1, lifetime=1800)
            store.store(encode_record(hidden))
            reopened = PersistentRecordStore(path)
            self.assertEqual(reopened.public_service_sample(), ())
            self.assertEqual(reopened.fetch(SERVICE_RECORD, hidden.service_id), encode_record(hidden))
            with self.assertRaises(DescriptorError):
                ServiceDescriptor.create_remote(identity, "distributed-overlay", metadata={"visibility": "private"})

    def test_traffic_is_thread_safe_aggregate_only(self):
        class Bridge:
            def fetch(self, *args, **kwargs):
                return HttpResult(200, "OK", {}, b"response")
        traffic = HostingTraffic(Bridge())
        workers = [threading.Thread(target=traffic.fetch, args=("POST", "/secret", {}, b"data")) for _ in range(32)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(2)
            self.assertFalse(worker.is_alive())
        self.assertEqual(traffic.snapshot(), {"requests": 32, "receivedBytes": 128, "sentBytes": 256})
        self.assertNotIn("secret", json.dumps(traffic.snapshot()))


if __name__ == "__main__":
    unittest.main()
