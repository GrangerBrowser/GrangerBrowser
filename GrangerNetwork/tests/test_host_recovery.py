from __future__ import annotations

import argparse
import json
import tempfile
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from granger_network import hosting, wan_host
from granger_network.descriptor import ServiceDescriptor
from granger_network.errors import IdentityVerificationError, NetworkUnavailableError
from granger_network.identity import ServiceIdentity
from granger_network.peer import node_id_from_public_key


class Finished(BaseException):
    pass


class HostRecoveryTests(unittest.TestCase):
    def run_case(self, kind: str, *, failure_at: int | range, error: Exception,
                 phase: str = "publish") -> dict:
        with tempfile.TemporaryDirectory(prefix="granger-host-recovery-") as temporary:
            root = Path(temporary)
            identity = ServiceIdentity.generate()
            service = ServiceDescriptor.create_remote(identity, "recovery-test", lifetime=86400)
            if kind == "cli":
                identity.save(root / wan_host.SERVICE_IDENTITY_FILE)
                (root / wan_host.SERVICE_DESCRIPTOR_FILE).write_text(service.to_json(), encoding="utf-8")
            peers = tuple(SimpleNamespace(node_id=node_id_from_public_key(ServiceIdentity.generate().public_key_bytes))
                          for _ in range(3))
            route = SimpleNamespace(route=tuple((peer, "middle") for peer in peers))
            health = {"updatedAt": int(time.time()), "state": "CONNECTED", "dhtReady": True}
            discovery = Mock()
            discovery.health.return_value.to_document.side_effect = lambda: dict(health)
            calls, published, hosts, sleeps, unavailable = [], [], [], [], []
            route_calls = []
            failures = {failure_at} if isinstance(failure_at, int) else set(failure_at)

            def route_candidates(*args):
                route_calls.append(args)
                if phase == "discovery" and len(route_calls) in failures:
                    health.update(state="DEGRADED", dhtReady=False)
                    raise error
                return peers

            discovery.route_candidates.side_effect = route_candidates

            def publish(record):
                calls.append(record)
                if phase == "publish" and len(calls) in failures:
                    health.update(state="DEGRADED", dhtReady=False)
                    raise error
                health.update(state="CONNECTED", dhtReady=True)
                published.append(record)
                return 4

            discovery.publish.side_effect = publish
            runtime = SimpleNamespace(identity=identity, discovery=discovery)

            def make_host(*_args, **_kwargs):
                host = Mock()
                host.recovery_requested = len(hosts) == 0
                host.recovery_reason = "introduction unavailable"
                host.wait.side_effect = [False, True] if not hosts else [False, Finished()]
                host.health.return_value = {
                    "recoveryRequested": False, "running": True, "ready": True,
                    "healthyIntroductions": 2, "requiredIntroductions": 2,
                }
                hosts.append(host)
                return host

            def sleep(delay):
                sleeps.append(delay)
                if health["dhtReady"] is False:
                    if kind == "cli":
                        unavailable.append(not (root / "ready.json").exists())
                    else:
                        state = json.loads((root / hosting.STATUS_FILE).read_text(encoding="utf-8"))
                        unavailable.append(state["state"] == "network-unavailable")
                    self.assertTrue(all(host.stop.called for host in hosts))

            module = wan_host if kind == "cli" else hosting
            captured = None
            with ExitStack() as stack:
                stack.enter_context(patch.object(module, "load_discovery_runtime", return_value=runtime))
                stack.enter_context(patch.object(module, "WanRouteSelector"))
                stack.enter_context(patch.object(module, "select_service_route_set", return_value=((route, route), route, False)))
                stack.enter_context(patch.object(module, "WanServiceHost", side_effect=make_host))
                stack.enter_context(patch.object(module.time, "sleep", side_effect=sleep))
                if kind == "cli":
                    options = argparse.Namespace(
                        state_dir=root, bootstrap=root / "bootstrap.json", authority_pin=root / "pin",
                        upstream="http://127.0.0.1:8080", ready_file=root / "ready.json",
                        minimum_introduction_points=2, introduction_points=2,
                        refresh_margin=120, introduction_lifetime=900,
                        service_lifetime=86400, service_refresh_margin=3600,
                        timeout=8, replication_factor=4, minimum_replicas=4,
                        startup_attempts=2, startup_timeout=15, rendezvous_lifetime=600,
                    )
                    invoke = lambda: wan_host.run_host(options)
                else:
                    config = SimpleNamespace(kind="static", entry_page="index.html", max_file_bytes=1024)
                    browser_config = SimpleNamespace(bootstrap_path=root / "bootstrap.json",
                        authority_pin_path=root / "pin", timeout=8, replication_factor=4, minimum_replicas=4)
                    stack.enter_context(patch.object(hosting, "load_hosted_service", return_value=(config, identity, service)))
                    stack.enter_context(patch.object(hosting, "load_browser_wan_config", return_value=browser_config))
                    stack.enter_context(patch.object(hosting, "_ensure_publication_snapshot"))
                    stack.enter_context(patch.object(hosting, "StaticSiteBridge"))
                    invoke = lambda: hosting.serve_hosted_service(root, root / "wan.json")
                try:
                    invoke()
                except BaseException as caught:
                    captured = caught
            return {"error": captured, "hosts": hosts, "sleeps": sleeps,
                    "unavailable": unavailable, "published": published, "service": service}

    def test_recovery_waits_for_service_and_introduction_quorum(self):
        for kind in ("cli", "browser"):
            for failure_at in (3, 4):
                with self.subTest(kind=kind, failure_at=failure_at):
                    result = self.run_case(kind, failure_at=failure_at,
                                           error=NetworkUnavailableError("replica quorum unavailable"))
                    self.assertIsInstance(result["error"], Finished)
                    self.assertEqual(result["unavailable"], [True])
                    self.assertTrue(all(host.stop.called for host in result["hosts"]))
                    self.assertTrue(all(0 < delay <= 30 for delay in result["sleeps"]))
                    records = [record for record in result["published"] if isinstance(record, ServiceDescriptor)]
                    self.assertTrue(all(record.canonical_name == result["service"].canonical_name for record in records))
                    sequences = [record.sequence for record in result["published"] if not isinstance(record, ServiceDescriptor)]
                    self.assertEqual(sequences, sorted(set(sequences)))

    def test_discovery_outage_keeps_host_recoverable(self):
        for kind in ("cli", "browser"):
            for failure_at in (3, 4):
                with self.subTest(kind=kind, failure_at=failure_at):
                    result = self.run_case(kind, failure_at=failure_at, phase="discovery",
                                           error=NetworkUnavailableError("first contact unavailable"))
                    self.assertIsInstance(result["error"], Finished)
                    self.assertEqual(result["unavailable"], [True])

    def test_prolonged_outage_uses_bounded_backoff_without_new_hosts(self):
        for kind in ("cli", "browser"):
            with self.subTest(kind=kind):
                result = self.run_case(kind, failure_at=range(3, 25),
                                       error=NetworkUnavailableError("quorum unavailable"))
                self.assertIsInstance(result["error"], Finished)
                self.assertEqual(result["unavailable"], [True] * 22)
                self.assertEqual(len(result["hosts"]), 2)
                self.assertIn(30.0, result["sleeps"])
                self.assertTrue(all(0 < delay <= 30 for delay in result["sleeps"]))

    def test_initial_quorum_failure_still_fails_startup(self):
        for kind in ("cli", "browser"):
            with self.subTest(kind=kind):
                result = self.run_case(kind, failure_at=1, error=NetworkUnavailableError("unavailable"))
                self.assertIsInstance(result["error"], NetworkUnavailableError)
                self.assertEqual(result["hosts"], [])
                self.assertEqual(result["sleeps"], [])

    def test_identity_failure_is_not_retried(self):
        for kind in ("cli", "browser"):
            with self.subTest(kind=kind):
                result = self.run_case(kind, failure_at=3, error=IdentityVerificationError("invalid signature"))
                self.assertIsInstance(result["error"], IdentityVerificationError)
                self.assertEqual(result["unavailable"], [])


if __name__ == "__main__":
    unittest.main()
