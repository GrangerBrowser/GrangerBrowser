from __future__ import annotations

import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from granger_network.bootstrap import BootstrapPool, BootstrapSet, PeerCache
from granger_network.descriptor import ServiceDescriptor
from granger_network.distributed import INTRODUCTION_RECORD, NODE_RECORD, SERVICE_RECORD, RecordEnvelope, encode_record
from granger_network.errors import DiscoveryError, IdentityVerificationError, ProtocolError, ReplayError, ResolutionError, ResourceLimitError
from granger_network.identity import ServiceIdentity
from granger_network.introduction import IntroductionDescriptor
from granger_network.node import WanNodeServer
from granger_network.peer import NodeDescriptor, RelayPolicy
from granger_network.peer_rpc import PeerRole, RpcType, connect_authenticated_peer
from granger_network.transport import RendezvousEndpoint
from granger_network.wan_discovery import (
    MAX_PRIVATE_ROUTE_ROLE_CANDIDATES,
    MAX_PARALLEL_DISCOVERY_REQUESTS,
    _RecordCircuits,
    WanDiscoveryClient,
    WanDistributedResolver,
    encode_optional_record,
    encode_record_envelope,
)
from granger_network.network_health import NetworkState


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class RecordCircuitScopeTests(unittest.TestCase):
    def peer(self):
        return NodeDescriptor.create(
            ServiceIdentity.generate(), RendezvousEndpoint("127.0.0.1", available_port()),
            ("discovery",), RelayPolicy(enabled=False), lifetime=3600,
        )

    def circuit(self, peer):
        circuit = SimpleNamespace(_closed=False, route=((peer, "discovery"),),
                                  endpoint=SimpleNamespace(remote=SimpleNamespace(descriptor=peer)),
                                  multiplexers=[])
        circuit.close = Mock(side_effect=lambda: setattr(circuit, "_closed", True))
        return circuit

    def test_scope_rejects_another_record_and_closes_on_failure(self):
        peer = self.peer()
        circuit = self.circuit(peer)
        with self.assertRaises(DiscoveryError):
            with _RecordCircuits(b"a" * 32, RpcType.FIND_RECORD, b"record-a", 8) as scope:
                scope.keep(peer, circuit)
                scope.validate_request(RpcType.FIND_RECORD, b"record-a")
                scope.validate_request(RpcType.FIND_RECORD, b"record-b")
        circuit.close.assert_called_once()
        self.assertFalse(scope.circuits)
        with self.assertRaises(DiscoveryError):
            scope.validate_request(RpcType.FIND_RECORD, b"record-a")

    def test_scope_retains_no_more_than_one_batch(self):
        circuits = []
        with _RecordCircuits(b"a" * 32, RpcType.FIND_RECORD, b"record", 8) as scope:
            for _ in range(MAX_PARALLEL_DISCOVERY_REQUESTS + 1):
                peer = self.peer()
                circuit = self.circuit(peer)
                circuits.append(circuit)
                scope.keep(peer, circuit)
            self.assertEqual(len(scope.circuits), MAX_PARALLEL_DISCOVERY_REQUESTS)
            self.assertTrue(circuits[-1]._closed)
        self.assertTrue(all(circuit._closed for circuit in circuits))
        late = self.circuit(peer)
        scope.keep(peer, late)
        late.close.assert_called_once()

    def test_reuse_rechecks_identity_expiry_and_transport(self):
        for reason in ("identity", "expiry", "transport"):
            with self.subTest(reason=reason):
                peer = self.peer()
                circuit = self.circuit(peer)
                with _RecordCircuits(b"a" * 32, RpcType.FIND_RECORD, b"record", 8) as scope:
                    with patch("granger_network.wan_discovery.time.monotonic", return_value=100):
                        scope.keep(peer, circuit)
                    if reason == "identity":
                        circuit.endpoint.remote.descriptor = self.peer()
                    elif reason == "transport":
                        circuit.multiplexers = [SimpleNamespace(failed=True)]
                    with patch("granger_network.wan_discovery.time.monotonic",
                               return_value=109 if reason == "expiry" else 101):
                        self.assertIsNone(scope.take(peer))
                circuit.close.assert_called_once()


class ConnectionRecordTests(unittest.TestCase):
    def test_records_overlap_but_require_service_binding_and_join_workers(self):
        identity = ServiceIdentity.generate()
        service = ServiceDescriptor.create_remote(identity, "connection-records", lifetime=1800)
        node = NodeDescriptor.create(
            ServiceIdentity.generate(), RendezvousEndpoint("127.0.0.1", available_port()),
            ("introduction",), RelayPolicy(enabled=True), lifetime=1800,
        )
        intro = IntroductionDescriptor.create(
            identity, service, [node.node_id], sequence=1, lifetime=900,
        )
        other_identity = ServiceIdentity.generate()
        other_service = ServiceDescriptor.create_remote(other_identity, "other", lifetime=1800)
        wrong_intro = IntroductionDescriptor.create(
            other_identity, other_service, [node.node_id], sequence=1, lifetime=900,
        )
        for candidate in (intro, wrong_intro, ResolutionError("quorum unavailable")):
            barrier = threading.Barrier(2, timeout=1)
            workers = []
            def lookup(kind, key, **_kwargs):
                self.assertEqual(key, service.service_id)
                workers.append(threading.current_thread())
                barrier.wait()
                if kind == SERVICE_RECORD:
                    return service
                self.assertEqual(kind, INTRODUCTION_RECORD)
                if isinstance(candidate, Exception):
                    raise candidate
                return candidate
            resolver = WanDistributedResolver(SimpleNamespace(lookup=lookup))
            if candidate is intro:
                self.assertEqual(resolver.resolve_connection(service.canonical_name), (service, intro))
            else:
                from granger_network.errors import GrangerNetworkError
                with self.assertRaises(GrangerNetworkError):
                    resolver.resolve_connection(service.canonical_name)
            self.assertEqual(len(workers), 2)
            self.assertTrue(all(not worker.is_alive() for worker in workers))


class PrivateDiscoveryFailureTests(unittest.TestCase):
    def setUp(self):
        self.peers = tuple(NodeDescriptor.create(
            ServiceIdentity.generate(), RendezvousEndpoint("127.0.0.1", 24000 + index),
            ("access", "bootstrap", "discovery", "entry", "middle"),
            RelayPolicy(enabled=True), lifetime=3600,
        ) for index in range(4))
        bootstrap = BootstrapSet.create(ServiceIdentity.generate(), self.peers, lifetime=1800)
        self.client = WanDiscoveryClient(ServiceIdentity.generate(), BootstrapPool(bootstrap), timeout=2)
        self.client._joined = True
        self.client._private_routes_ready = True

    def test_failed_candidate_prefix_does_not_hide_an_untried_route(self):
        attempted = []

        def open_route(route):
            attempted.append(tuple(p.node_id for p, _ in route))
            if len(attempted) <= 4:
                raise TimeoutError("controlled end-to-end transport loss")
            circuit = Mock(route=route)
            circuit.endpoint.rpc.request.return_value = SimpleNamespace(payload=b"response")
            return circuit

        with patch("granger_network.wan_discovery.secrets.token_bytes", return_value=b"\x00" * 4), \
                patch("granger_network.circuit.CircuitBuilder") as builder:
            builder.return_value.open.side_effect = open_route
            result = self.client._request(self.peers[0], RpcType.FIND_NODE, b"request", RpcType.FIND_NODE)
        self.assertEqual(result, b"response")
        self.assertEqual(len(attempted), 5)
        self.assertEqual(len(set(attempted)), 5)
        self.assertEqual(self.client.direct_first_contact_requests, 0)

    def test_private_ingress_prefers_authenticated_peers_with_equal_diversity(self):
        extra = tuple(NodeDescriptor.create(
            ServiceIdentity.generate(), RendezvousEndpoint("127.0.0.1", 24100 + index),
            ("access", "bootstrap", "discovery", "entry", "middle"),
            RelayPolicy(enabled=True), lifetime=3600,
        ) for index in range(4))
        peers = (*self.peers, *extra)
        bootstrap = BootstrapSet.create(ServiceIdentity.generate(), peers, lifetime=1800)
        client = WanDiscoveryClient(ServiceIdentity.generate(), BootstrapPool(bootstrap))
        for peer in self.peers:
            client._record_peer_success(peer.node_id)
        route = client._private_route_candidates(self.peers[0], limit=1)[0]
        self.assertEqual({p.node_id for p, _ in route}, {p.node_id for p in self.peers})

    def test_direct_failure_only_excludes_the_failed_access_role(self):
        target = self.peers[0]
        failed_access = self.peers[1]
        self.client._record_peer_failure(
            failed_access.node_id,
            time.monotonic() + 60.0,
        )

        routes = self.client._private_route_candidates(target, limit=6)

        self.assertTrue(routes)
        for route in routes:
            self.assertEqual(len(route), 4)
            self.assertEqual(len({peer.node_id for peer, _role in route}), 4)
            self.assertNotEqual(route[0][0].node_id, failed_access.node_id)
            self.assertIn(failed_access.node_id, {peer.node_id for peer, _role in route[1:]})

    def test_record_phases_do_not_restart_an_exhausted_route_search(self):
        from granger_network.wan_discovery import _RecordCircuits, encode_find_node
        target = b"t" * 32
        attempted = []
        def fail(route):
            attempted.append(tuple(p.node_id for p, _ in route))
            raise TimeoutError("controlled transport failure")
        with patch("granger_network.circuit.CircuitBuilder") as builder:
            builder.return_value.open.side_effect = fail
            with _RecordCircuits(target, RpcType.FIND_RECORD, b"record", 2) as circuits:
                with self.assertRaises((TimeoutError, DiscoveryError)):
                    self.client._request(self.peers[0], RpcType.FIND_NODE,
                        encode_find_node(target, "discovery"), RpcType.FIND_NODE, record_circuits=circuits)
                before = len(attempted)
                self.assertGreater(before, 0)
                with self.assertRaises(DiscoveryError):
                    self.client._request(self.peers[0], RpcType.FIND_RECORD,
                        b"record", RpcType.FIND_RECORD, record_circuits=circuits)
                self.assertEqual(len(attempted), before)
            self.assertFalse(circuits.route_failures)
            with self.assertRaises((TimeoutError, DiscoveryError)):
                self.client._request(self.peers[0], RpcType.FIND_NODE, b"new request", RpcType.FIND_NODE)
            self.assertGreater(len(attempted), before)

    def test_record_transaction_uses_responding_storage_peers_not_unverified_hints(self):
        from granger_network.wan_discovery import _RecordCircuits, encode_node_list
        from granger_network.network_health import NetworkState
        payload = encode_node_list(self.peers)
        responsive = {p.node_id for p in self.peers[:2]}
        def responses(peers, *_args, **_kwargs):
            return [(p, payload if p.node_id in responsive else None) for p in peers]
        with patch.object(self.client, 'join_network', return_value=SimpleNamespace(state=NetworkState.CONNECTED)), \
                patch.object(self.client, '_request_batch', side_effect=responses):
            with _RecordCircuits(b't' * 32, RpcType.FIND_RECORD, b'record', 2) as circuits:
                found = self.client.find_nodes(b't' * 32, 'discovery', record_circuits=circuits)
        self.assertEqual({p.node_id for p in found}, responsive)

    def test_successful_private_circuit_records_authenticated_ingress(self):
        route = self.client._private_route_candidates(self.peers[0])[0]
        circuit = Mock(route=route)
        circuit.endpoint.rpc.request.return_value = SimpleNamespace(payload=b'response')
        with patch('granger_network.circuit.CircuitBuilder') as builder:
            builder.return_value.open.return_value = circuit
            self.client._request(self.peers[0], RpcType.FIND_NODE, b'request', RpcType.FIND_NODE)
        self.assertEqual(set(self.client._authenticated_nodes), {p.node_id for p, _ in route})

    def test_terminal_discovery_edge_backoff_spans_searches_but_expires(self):
        attempted = []

        def fail(route):
            attempted.append(route)
            error = TimeoutError("controlled last-hop extension failure")
            error.circuit_failure_hop_index = len(route) - 1
            error.circuit_failure_stage = "extension"
            raise error

        with patch('granger_network.circuit.CircuitBuilder') as builder:
            builder.return_value.open.side_effect = fail
            with self.assertRaises((TimeoutError, DiscoveryError)):
                self.client._request(self.peers[0], RpcType.FIND_NODE, b'first', RpcType.FIND_NODE)
            before = len(attempted)
            self.assertGreater(before, 0)
            with self.assertRaises(DiscoveryError):
                self.client._request(self.peers[0], RpcType.FIND_NODE, b'next', RpcType.FIND_NODE)
            self.assertEqual(len(attempted), before)
            self.assertFalse(self.client._failed_until)
            # Neither the target identity nor the preceding relay is globally excluded.
            other = self.client._private_route_candidates(self.peers[1])
            self.assertTrue(any(self.peers[0] in [p for p, _ in r[:-1]] for r in other))
            later = time.monotonic() + 301
            with patch('granger_network.wan_discovery.time.monotonic', return_value=later):
                with self.assertRaises((TimeoutError, DiscoveryError)):
                    self.client._request(self.peers[0], RpcType.FIND_NODE, b'retry', RpcType.FIND_NODE)
            self.assertGreater(len(attempted), before)

    def test_terminal_edge_memory_is_bounded_and_descriptor_version_specific(self):
        middle, target = self.peers[1], self.peers[0]
        key = (middle.node_id, middle.issued_at - 1, 'middle', target.node_id, target.issued_at, 'discovery')
        self.client._failed_route_edges[key] = time.monotonic() + 60
        routes = self.client._private_route_candidates(target, limit=6)
        self.assertTrue(any(route[-2][0].node_id == middle.node_id for route in routes))
        with patch('granger_network.wan_discovery.MAX_DISCOVERY_PEER_TRACKING_ENTRIES', 2):
            for peer in self.peers:
                self.client._failed_route_edges[(peer.node_id, peer.issued_at, 'middle',
                    target.node_id, target.issued_at, 'discovery')] = time.monotonic() + 60
            with self.client._lock:
                self.client._prune_peer_tracking_unlocked(time.monotonic())
            self.assertEqual(len(self.client._failed_route_edges), 2)

    def test_node_response_uses_one_bounded_cache_ingest(self):
        from granger_network.wan_discovery import encode_node_list
        payload = encode_node_list(self.peers)
        cache = Mock()
        with patch.object(self.client, 'cache', cache), \
                patch.object(self.client, 'join_network', return_value=SimpleNamespace(state=NetworkState.CONNECTED)), \
                patch.object(self.client, '_request_batch', side_effect=lambda peers, *a, **kw: [(p, payload) for p in peers]):
            self.client.find_nodes(b't' * 32, 'discovery')
        self.assertEqual(cache.ingest.call_count, len(self.peers))
        cache.add.assert_not_called()
        for call in cache.ingest.call_args_list:
            self.assertEqual(call.args, (self.peers,))
            self.assertIn(call.kwargs['source'], {'peer:' + p.node_id for p in self.peers})

    def test_exhausted_terminal_search_is_not_restarted_by_the_next_find_node(self):
        extra = tuple(NodeDescriptor.create(ServiceIdentity.generate(),
            RendezvousEndpoint('127.0.0.1', 24200 + index),
            ('access', 'bootstrap', 'discovery', 'entry', 'middle'),
            RelayPolicy(enabled=True), lifetime=3600) for index in range(16))
        pool = BootstrapPool(BootstrapSet.create(ServiceIdentity.generate(), (*self.peers, *extra), lifetime=1800))
        client = WanDiscoveryClient(ServiceIdentity.generate(), pool, timeout=1)
        client._joined = client._private_routes_ready = True
        attempted = []
        def fail(route):
            attempted.append(route)
            error = TimeoutError('controlled terminal endpoint timeout')
            error.circuit_failure_hop_index = 3
            error.circuit_failure_stage = 'extension'
            raise error
        with patch('granger_network.circuit.CircuitBuilder') as builder:
            builder.return_value.open.side_effect = fail
            with self.assertRaises(TimeoutError):
                client._request(self.peers[0], RpcType.FIND_NODE, b'first', RpcType.FIND_NODE)
            self.assertEqual(len(attempted), 12)
            with self.assertRaises((TimeoutError, DiscoveryError)):
                client._request(self.peers[0], RpcType.FIND_NODE, b'next', RpcType.FIND_NODE)
            self.assertEqual(len(attempted), 12)
            self.assertFalse(client._failed_until)
            self.assertTrue(client._private_route_candidates(self.peers[1]))
            with patch('granger_network.wan_discovery.time.monotonic', return_value=time.monotonic() + 301):
                with self.assertRaises(TimeoutError):
                    client._request(self.peers[0], RpcType.FIND_NODE, b'after-backoff', RpcType.FIND_NODE)
            self.assertEqual(len(attempted), 24)

    def test_search_backoff_is_bounded_and_does_not_disable_record_rpcs(self):
        peer = self.peers[0]
        self.client._exhausted_discovery_searches[(peer.node_id, peer.issued_at)] = time.monotonic() + 60
        route = self.client._private_route_candidates(peer)[0]
        circuit = Mock(route=route)
        circuit.endpoint.rpc.request.return_value = SimpleNamespace(payload=b'record')
        with patch('granger_network.circuit.CircuitBuilder') as builder:
            builder.return_value.open.return_value = circuit
            self.assertEqual(self.client._request(peer, RpcType.FIND_RECORD, b'request', RpcType.FIND_RECORD), b'record')
            self.client._exhausted_discovery_searches.clear()
            self.client._exhausted_discovery_searches[(peer.node_id, peer.issued_at - 1)] = time.monotonic() + 60
            self.assertEqual(self.client._request(peer, RpcType.FIND_NODE, b'current', RpcType.FIND_NODE), b'record')
        with patch('granger_network.wan_discovery.MAX_DISCOVERY_PEER_TRACKING_ENTRIES', 2):
            for p in self.peers:
                self.client._exhausted_discovery_searches[(p.node_id, p.issued_at)] = time.monotonic() + 60
            with self.client._lock:
                self.client._prune_peer_tracking_unlocked(time.monotonic())
            self.assertEqual(len(self.client._exhausted_discovery_searches), 2)

    def test_exhausted_search_retains_backoff_after_mixed_extension_failures(self):
        extra = tuple(NodeDescriptor.create(ServiceIdentity.generate(),
            RendezvousEndpoint('127.0.0.1', 24300 + index),
            ('access', 'bootstrap', 'discovery', 'entry', 'middle'),
            RelayPolicy(enabled=True), lifetime=3600) for index in range(16))
        pool = BootstrapPool(BootstrapSet.create(ServiceIdentity.generate(), (*self.peers, *extra), lifetime=1800))
        client = WanDiscoveryClient(ServiceIdentity.generate(), pool, timeout=1)
        client._joined = client._private_routes_ready = True
        attempted = []

        def fail(route):
            attempted.append(route)
            error = TimeoutError('controlled mixed extension failure')
            error.circuit_failure_hop_index = 2 if len(attempted) == 1 else 3
            error.circuit_failure_stage = 'extension'
            raise error

        with patch('granger_network.circuit.CircuitBuilder') as builder:
            builder.return_value.open.side_effect = fail
            with self.assertRaises(TimeoutError):
                client._request(self.peers[0], RpcType.FIND_NODE, b'first', RpcType.FIND_NODE)
            self.assertEqual(len(attempted), 12)
            with self.assertRaises((TimeoutError, DiscoveryError)):
                client._request(self.peers[0], RpcType.FIND_NODE, b'next', RpcType.FIND_NODE)
            self.assertEqual(len(attempted), 12)
            self.assertFalse(client._failed_until)
            self.assertTrue(client._private_route_candidates(self.peers[1]))

    def test_small_terminal_search_backoff_starts_after_alternatives_are_exhausted(self):
        clock = [time.monotonic()]
        attempted = []

        def fail(route):
            attempted.append(route)
            clock[0] += 8
            error = TimeoutError('controlled terminal extension timeout')
            error.circuit_failure_hop_index = 3
            error.circuit_failure_stage = 'extension'
            raise error

        with patch('granger_network.wan_discovery.time.monotonic', side_effect=lambda: clock[0]), \
                patch('granger_network.circuit.CircuitBuilder') as builder:
            builder.return_value.open.side_effect = fail
            with self.assertRaises((TimeoutError, DiscoveryError)):
                self.client._request(self.peers[0], RpcType.FIND_NODE, b'first', RpcType.FIND_NODE)
            self.assertEqual(len(attempted), 3)
            # The earliest edge cooldown has elapsed, but the completed search
            # must still own its retry window instead of starting over.
            clock[0] += 50
            with self.assertRaises((TimeoutError, DiscoveryError)):
                self.client._request(self.peers[0], RpcType.FIND_NODE, b'next', RpcType.FIND_NODE)
            self.assertEqual(len(attempted), 3)

    def test_intermediate_failure_memory_keeps_direction_roles_and_versions(self):
        attempted = []

        def open_route(route):
            attempted.append(route)
            if len(attempted) == 1:
                error = TimeoutError('controlled entry to middle failure')
                error.circuit_failure_hop_index = 2
                error.circuit_failure_stage = 'extension'
                raise error
            circuit = Mock(route=route)
            circuit.endpoint.rpc.request.return_value = SimpleNamespace(payload=b'ok')
            return circuit

        with patch('granger_network.circuit.CircuitBuilder') as builder:
            builder.return_value.open.side_effect = open_route
            self.client._request(self.peers[0], RpcType.FIND_NODE, b'first', RpcType.FIND_NODE)
        left, right = attempted[0][1][0], attempted[0][2][0]
        routes = self.client._private_route_candidates(self.peers[0], limit=64)
        self.assertFalse(any(r[1][0] == left and r[2][0] == right for r in routes))
        self.assertTrue(any(r[1][0] == right and r[2][0] == left for r in routes))
        self.assertTrue(any(r[0][0] == right for r in routes))
        self.assertFalse(self.client._failed_until)
        with patch('granger_network.wan_discovery.time.monotonic', return_value=time.monotonic() + 301):
            routes = self.client._private_route_candidates(self.peers[0], limit=64)
            self.assertTrue(any(r[1][0] == left and r[2][0] == right for r in routes))

    def test_pending_routes_recheck_failures_learned_by_another_request(self):
        from granger_network.wan_discovery import _route_edge_key

        routes = self.client._private_route_candidates(self.peers[0], limit=6)
        first = routes[0]
        first_edge = _route_edge_key(first[0][0], 'access', first[1][0], 'entry')
        pending = next(route for route in routes[1:] if
            _route_edge_key(route[0][0], 'access', route[1][0], 'entry') != first_edge)
        learned_edge = _route_edge_key(pending[1][0], 'entry', pending[2][0], 'middle')
        healthy = next(route for route in routes if
            _route_edge_key(route[0][0], 'access', route[1][0], 'entry') != first_edge
            and _route_edge_key(route[1][0], 'entry', route[2][0], 'middle') != learned_edge)
        attempted = []

        def open_route(route):
            attempted.append(route)
            if len(attempted) == 1:
                with self.client._lock:
                    self.client._failed_route_edges[learned_edge] = time.monotonic() + 60
                error = TimeoutError('controlled concurrent extension failure')
                error.circuit_failure_hop_index = 1
                error.circuit_failure_stage = 'extension'
                raise error
            circuit = Mock(route=route)
            circuit.endpoint.rpc.request.return_value = SimpleNamespace(payload=b'ok')
            return circuit

        with patch.object(self.client, '_private_route_candidates', return_value=(first, pending, healthy)), \
                patch('granger_network.circuit.CircuitBuilder') as builder:
            builder.return_value.open.side_effect = open_route
            self.assertEqual(self.client._request(self.peers[0], RpcType.FIND_NODE,
                b'request', RpcType.FIND_NODE), b'ok')
        self.assertEqual(attempted, [first, healthy])
        self.assertFalse(self.client._failed_until)

    def test_intermediate_only_exhaustion_retains_search_cooldown(self):
        clock = [time.monotonic()]
        attempted = []

        def fail(route):
            attempted.append(route)
            clock[0] += 8
            error = TimeoutError('controlled access to entry timeout')
            error.circuit_failure_hop_index = 1
            error.circuit_failure_stage = 'extension'
            raise error

        with patch('granger_network.wan_discovery.time.monotonic', side_effect=lambda: clock[0]), \
                patch('granger_network.circuit.CircuitBuilder') as builder:
            builder.return_value.open.side_effect = fail
            with self.assertRaises(TimeoutError):
                self.client._request(self.peers[0], RpcType.FIND_NODE, b'first', RpcType.FIND_NODE)
            before = len(attempted)
            self.assertEqual(before, 6)
            clock[0] += 50
            with self.assertRaises(DiscoveryError):
                self.client._request(self.peers[0], RpcType.FIND_NODE, b'next', RpcType.FIND_NODE)
            self.assertEqual(len(attempted), before)
        self.assertFalse(self.client._failed_until)

    def test_diverse_route_order_matches_reference_with_ties(self):
        import itertools
        from granger_network.wan_routing import order_diverse_relay_combinations
        combinations = [(index % 3, index % 2, index % 5, *nodes)
                        for index, nodes in enumerate(itertools.permutations(self.peers, 3))]
        def reference(items, limit):
            remaining = list(enumerate(sorted(items, key=lambda item: item[:3])))
            uses, pairs, ordered = {}, {}, []
            def keys(item):
                return tuple((a.node_id, b.node_id) for a, b in itertools.combinations(item[3:], 2))
            while remaining and len(ordered) < limit:
                selected = min(remaining, key=lambda item: (
                    max(pairs.get(p, 0) for p in keys(item[1])),
                    sum(pairs.get(p, 0) for p in keys(item[1])),
                    max(uses.get(n.node_id, 0) for n in item[1][3:]),
                    sum(uses.get(n.node_id, 0) for n in item[1][3:]), item[0]))
                ordered.append(selected[1])
                for p in keys(selected[1]): pairs[p] = pairs.get(p, 0) + 1
                for n in selected[1][3:]: uses[n.node_id] = uses.get(n.node_id, 0) + 1
                remaining.remove(selected)
            return tuple(ordered)
        for limit in (1, 4, 12, 32):
            self.assertEqual(order_diverse_relay_combinations(list(combinations), limit=limit),
                             reference(combinations, limit))

    def test_intermediate_failure_does_not_quarantine_a_four_node_overlay(self):
        for hop in (1, 2, 3):
            with self.subTest(hop=hop):
                attempted = []
                opened = []
                self.client._failed_until.clear()
                self.client._private_route_hints.clear()

                def open_route(route):
                    attempted.append(route)
                    if len(attempted) == 1:
                        error = TimeoutError("controlled extension loss")
                        error.circuit_failure_hop_index = hop
                        error.circuit_failure_stage = "extension"
                        raise error
                    circuit = Mock(route=route)
                    circuit.endpoint.rpc.request.return_value = SimpleNamespace(payload=b"response")
                    opened.append(circuit)
                    return circuit

                with patch("granger_network.circuit.CircuitBuilder") as builder:
                    builder.return_value.open.side_effect = open_route
                    response = self.client._request(self.peers[0], RpcType.FIND_NODE, b"request", RpcType.FIND_NODE)
                self.assertEqual(response, b"response")
                self.assertEqual(len(attempted), 2)
                failed_edge = attempted[0][hop - 1:hop + 1]
                self.assertFalse(any(attempted[1][i:i + 2] == failed_edge for i in range(3)))
                self.assertEqual({p.node_id for p, _ in attempted[0]}, {p.node_id for p, _ in attempted[1]})
                self.assertFalse(self.client._failed_until)
                self.assertEqual(self.client.direct_first_contact_requests, 0)
                self.assertEqual(len(opened), 1)
                opened[0].close.assert_called_once_with()

    def test_exhaustion_is_bounded_and_does_not_poison_later_operations(self):
        attempted = []

        def fail_route(route):
            attempted.append(tuple((p.node_id, role) for p, role in route))
            error = TimeoutError("controlled route loss")
            error.circuit_failure_hop_index = 2
            error.circuit_failure_stage = "authentication"
            raise error

        with patch("granger_network.circuit.CircuitBuilder") as builder:
            builder.return_value.open.side_effect = fail_route
            with self.assertRaises(TimeoutError):
                self.client._request(self.peers[0], RpcType.FIND_NODE, b"request", RpcType.FIND_NODE)
        self.assertLessEqual(len(attempted), 12)
        self.assertEqual(len(attempted), len(set(attempted)))
        self.assertFalse(self.client._failed_until)
        self.assertTrue(self.client._private_route_candidates(self.peers[0]))
        self.assertEqual(self.client.direct_first_contact_requests, 0)

    def test_observed_first_hop_failure_keeps_its_local_cooldown(self):
        failed_access = []

        def fail_access(route):
            failed_access.append(route[0][0].node_id)
            error = ConnectionRefusedError("controlled first-hop refusal")
            error.circuit_failure_hop_index = 0
            error.circuit_failure_stage = "tcp"
            raise error

        with patch("granger_network.circuit.CircuitBuilder") as builder:
            builder.return_value.open.side_effect = fail_access
            with self.assertRaises((DiscoveryError, ConnectionRefusedError)):
                self.client._request(self.peers[0], RpcType.FIND_NODE, b"request", RpcType.FIND_NODE)
        self.assertEqual(
            set(failed_access),
            {peer.node_id for peer in self.peers[1:]},
        )
        self.assertTrue(set(failed_access) <= set(self.client._failed_until))
        self.assertNotIn(self.peers[0].node_id, self.client._failed_until)


class WanDiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="granger-wan-dht-")
        self.root = Path(self.temporary.name)
        self.now = int(time.time())
        self.authority = ServiceIdentity.generate()
        self.identities = [ServiceIdentity.generate() for _ in range(6)]
        self.descriptors = [
            NodeDescriptor.create(
                identity,
                RendezvousEndpoint("127.0.0.1", available_port()),
                ("access", "bootstrap", "discovery", "entry", "middle"),
                RelayPolicy(enabled=True, max_bandwidth_kib_per_second=64 * 1024),
                issued_at=self.now,
                lifetime=3600,
            )
            for identity in self.identities
        ]
        self.nodes = [
            WanNodeServer(
                identity,
                descriptor,
                self.root / f"node-{index}",
                known_peers=self.descriptors,
            )
            for index, (identity, descriptor) in enumerate(
                zip(self.identities, self.descriptors, strict=True)
            )
        ]
        for node in self.nodes:
            node.start_background()
        self.bootstrap = BootstrapSet.create(
            self.authority,
            self.descriptors,
            issued_at=self.now,
            lifetime=1800,
        )
        self.cache = PeerCache(self.root / "client-peers.json")
        self.client = WanDiscoveryClient(
            ServiceIdentity.generate(),
            BootstrapPool(self.bootstrap, self.cache),
            cache=self.cache,
            timeout=2.0,
        )

    def tearDown(self) -> None:
        for node in self.nodes:
            node.stop()
        self.temporary.cleanup()

    def test_lookup_reuses_only_its_own_record_circuits_and_closes_them(self) -> None:
        from granger_network.circuit import CircuitBuilder

        service = ServiceDescriptor.create_remote(
            ServiceIdentity.generate(), "scoped-lookup", issued_at=self.now, lifetime=1800,
        )
        self.client.join_network()
        self.client.publish(service)
        original = CircuitBuilder.open
        circuits = []

        def opened(builder, route):
            circuit = original(builder, route)
            circuits.append(circuit)
            return circuit

        with patch.object(CircuitBuilder, "open", opened):
            self.assertEqual(self.client.lookup(SERVICE_RECORD, service.service_id), service)
            first = list(circuits)
            self.assertLess(len(first), 2 * len(self.descriptors))
            self.assertTrue(all(circuit._closed for circuit in first))
            self.assertEqual(self.client.lookup(SERVICE_RECORD, service.service_id), service)
            self.assertGreater(len(circuits), len(first))
            self.assertTrue(all(circuit._closed for circuit in circuits))
            self.assertFalse({c.circuit_ids[0] for c in first} &
                             {c.circuit_ids[0] for c in circuits[len(first):]})

    def test_quorum_failure_closes_transaction_circuits(self) -> None:
        from granger_network.circuit import CircuitBuilder

        self.client.join_network()
        circuits = []
        original = CircuitBuilder.open
        def opened(builder, route):
            circuit = original(builder, route)
            circuits.append(circuit)
            return circuit
        with patch.object(CircuitBuilder, "open", opened), self.assertRaises(ResolutionError):
            missing = ServiceDescriptor.create_remote(ServiceIdentity.generate(), "absent", lifetime=1800)
            self.client.lookup(SERVICE_RECORD, missing.service_id)
        self.assertTrue(circuits)
        self.assertTrue(all(circuit._closed for circuit in circuits))

    def test_resolve_node_uses_current_signed_bootstrap_descriptor(self) -> None:
        resolver = WanDistributedResolver(self.client)
        expected = self.descriptors[0]
        with patch.object(
            self.client,
            "lookup",
            side_effect=AssertionError("signed bootstrap node performed a DHT lookup"),
        ):
            self.assertEqual(resolver.resolve_node(expected.node_id, now=self.now), expected)

    def test_resolve_node_uses_dht_after_signed_bootstrap_descriptor_expires(self) -> None:
        resolver = WanDistributedResolver(self.client)
        expired = self.descriptors[0]
        replacement = NodeDescriptor.create(
            self.identities[0],
            RendezvousEndpoint("127.0.0.1", available_port()),
            expired.capabilities,
            expired.relay_policy,
            issued_at=self.now + 3601,
            lifetime=3600,
        )
        with patch.object(self.client, "lookup", return_value=replacement) as lookup:
            self.assertEqual(
                resolver.resolve_node(expired.node_id, now=self.now + 3601),
                replacement,
            )
        lookup.assert_called_once_with(NODE_RECORD, expired.node_id, now=self.now + 3601)

    def test_batch_start_failure_joins_already_started_workers(self) -> None:
        first = []
        finished = threading.Event()
        original = threading.Thread.start
        def start(worker):
            if first:
                raise RuntimeError("thread capacity reached")
            first.append(worker)
            return original(worker)
        def request(*_args, **_kwargs):
            time.sleep(.05)
            finished.set()
            return b""
        with (
            patch.object(threading.Thread, "start", start),
            patch.object(self.client, "_request", side_effect=request),
            self.assertRaises(RuntimeError),
        ):
            self.client._request_batch(list(self.descriptors[:2]), RpcType.FIND_NODE, b"", RpcType.FIND_NODE)
        self.assertTrue(finished.is_set())
        self.assertFalse(first[0].is_alive())

    def test_public_hidden_public_uses_signed_network_discovery(self) -> None:
        identity = ServiceIdentity.generate()
        public = ServiceDescriptor.create_remote(identity, "distributed-overlay",
            metadata={"title": "Listed", "visibility": "public"}, issued_at=self.now, lifetime=1800)
        hidden = ServiceDescriptor.create_remote(identity, "distributed-overlay",
            metadata={"title": "Unlisted"}, issued_at=self.now + 1, lifetime=1800)
        public_again = ServiceDescriptor.create_remote(identity, "distributed-overlay",
            metadata={"title": "Listed again", "visibility": "public"}, issued_at=self.now + 2, lifetime=1800)
        self.client.join_network()
        self.client.publish(public)
        self.assertIn(public.service_id, {item.service_id for item in self.client.public_service_sample()})
        self.client.publish(hidden)
        self.assertNotIn(hidden.service_id, {item.service_id for item in self.client.public_service_sample()})
        self.assertEqual(self.client.lookup(SERVICE_RECORD, hidden.service_id), hidden)
        self.client.publish(public_again)
        self.assertIn(public_again.service_id, {item.service_id for item in self.client.public_service_sample()})

    def test_private_route_enumeration_is_bounded_with_large_peer_view(self) -> None:
        from granger_network.wan_routing import order_diverse_relay_combinations

        descriptors = [
            NodeDescriptor.create(
                ServiceIdentity.generate(),
                RendezvousEndpoint(f"198.{index}.0.1", 27000),
                ("access", "discovery", "entry", "middle"),
                RelayPolicy(enabled=True), issued_at=self.now, lifetime=3600,
            )
            for index in range(96)
        ]
        self.client._route_nodes = {node.node_id: node for node in descriptors}
        with patch(
            "granger_network.wan_discovery.order_diverse_relay_combinations",
            wraps=order_diverse_relay_combinations,
        ) as order:
            routes = self.client._private_route_candidates(self.descriptors[0])
        combinations = order.call_args.args[0]
        self.assertLessEqual(len(combinations), MAX_PRIVATE_ROUTE_ROLE_CANDIDATES ** 3)
        for route in routes:
            self.assertEqual(len({node.node_id for node, _role in route}), 4)
            self.assertEqual(route[-1][0], self.descriptors[0])
        for position in range(3):
            self.assertLessEqual(
                len({combination[3 + position].node_id for combination in combinations}),
                MAX_PRIVATE_ROUTE_ROLE_CANDIDATES,
            )

    def test_expired_live_route_descriptor_cannot_be_reused(self) -> None:
        expired = NodeDescriptor.create(
            ServiceIdentity.generate(), RendezvousEndpoint("198.51.100.1", 27000),
            ("access", "entry", "middle"), RelayPolicy(enabled=True),
            issued_at=self.now - 121, lifetime=120,
        )
        self.client._route_nodes[expired.node_id] = expired
        routes = self.client._private_route_candidates(self.descriptors[0])
        self.assertTrue(routes)
        self.assertNotIn(expired.node_id, {node.node_id for route in routes for node, _ in route})

    def test_first_contact_failures_retain_safe_stage_codes(self) -> None:
        cases = (
            ("tcp", TimeoutError("private detail"), "FIRST_CONTACT_TCP_TIMEOUT"),
            ("tcp", ConnectionRefusedError("private detail"), "FIRST_CONTACT_TCP_REFUSED"),
            ("authentication", TimeoutError("private detail"), "FIRST_CONTACT_AUTH_TIMEOUT"),
            ("authentication", IdentityVerificationError("private detail"), "FIRST_CONTACT_AUTH_REJECTED"),
            ("peer-sample", TimeoutError("private detail"), "FIRST_CONTACT_PEER_SAMPLE_TIMEOUT"),
            ("peer-sample", ProtocolError("private detail"), "FIRST_CONTACT_PEER_SAMPLE_REJECTED"),
        )
        operations = set()
        for stage, failure, reason in cases:
            with self.subTest(stage=stage, reason=reason):
                client = WanDiscoveryClient(
                    ServiceIdentity.generate(), BootstrapPool(self.bootstrap), timeout=0.1,
                )

                def connect(*_args, **options):
                    options["on_stage"]("tcp", 1)
                    if stage != "tcp":
                        options["on_stage"]("authentication", 1)
                    if stage == "peer-sample":
                        return SimpleNamespace(
                            rpc=SimpleNamespace(request=Mock(side_effect=type(failure)("private detail"))),
                            close=Mock(),
                        )
                    raise type(failure)("private detail")

                with patch("granger_network.wan_discovery.connect_authenticated_peer", side_effect=connect):
                    with self.assertRaisesRegex(DiscoveryError, reason):
                        client.route_candidates(b"t" * 32, "introduction")
                self.assertEqual(client.health().failure_reason, reason)
                trace = client.first_contact_diagnostics()
                self.assertTrue(trace)
                self.assertLessEqual(len(trace), 32)
                self.assertTrue(all(event["stage"] == stage for event in trace))
                self.assertTrue(all(event["reason"] == reason for event in trace))
                self.assertTrue(all(event["attempt"] == 1 for event in trace))
                self.assertTrue(all(event["elapsedMs"] >= 0 for event in trace))
                operation_ids = {event["operationId"] for event in trace}
                self.assertEqual(len(operation_ids), 1)
                self.assertFalse(operation_ids & operations)
                operations.update(operation_ids)
                self.assertNotIn("private detail", json.dumps(trace))
                self.assertNotIn("127.0.0.1", json.dumps(trace))
                trace[0]["reason"] = "changed by consumer"
                self.assertEqual(client.first_contact_diagnostics()[0]["reason"], reason)

    def test_first_contact_diagnostics_are_bounded(self) -> None:
        for _ in range(40):
            self.client._record_first_contact(
                self.descriptors[0], "tcp", "FIRST_CONTACT_TCP_TIMEOUT", time.monotonic(), 1,
            )
        self.assertEqual(len(self.client.first_contact_diagnostics()), 32)

    def test_long_lived_peer_outcome_tracking_is_bounded(self) -> None:
        node_ids = [descriptor.node_id for descriptor in self.descriptors[:3]]
        with patch("granger_network.wan_discovery.MAX_DISCOVERY_PEER_TRACKING_ENTRIES", 2):
            for node_id in node_ids:
                self.client._record_peer_success(node_id)
            self.assertEqual(len(self.client._authenticated_nodes), 2)

            for node_id in node_ids:
                self.client._record_peer_failure(node_id, time.monotonic() + 60.0)
            self.assertEqual(len(self.client._failed_until), 2)

            expired = node_ids[-1]
            self.client._failed_until[expired] = time.monotonic() - 1.0
            self.client._record_peer_success(node_ids[0])
            self.assertNotIn(expired, self.client._failed_until)

    def test_live_rollback_tracking_fails_closed_and_expires(self) -> None:
        self.client._max_rollback_tracking_entries = 1
        self.client._remember_record_sequence(
            SERVICE_RECORD,
            "first",
            2,
            self.now + 30,
            now=self.now,
        )
        with self.assertRaisesRegex(ReplayError, "rollback"):
            self.client._remember_record_sequence(
                SERVICE_RECORD,
                "first",
                1,
                self.now + 30,
                now=self.now,
            )
        with self.assertRaisesRegex(ResourceLimitError, "tracking limit"):
            self.client._remember_record_sequence(
                SERVICE_RECORD,
                "second",
                1,
                self.now + 30,
                now=self.now,
            )

        self.client._remember_record_sequence(
            SERVICE_RECORD,
            "second",
            1,
            self.now + 61,
            now=self.now + 31,
        )
        self.assertNotIn((SERVICE_RECORD, "first"), self.client._highest_seen)

    def test_no_seed_error_preserves_join_reason(self) -> None:
        with (
            patch.object(self.client.pool, "candidates", return_value=()),
            patch.object(self.client.pool, "seed_candidates", return_value=()),
            patch.object(self.client.cache, "ranked", return_value=()),
        ):
            with self.assertRaisesRegex(DiscoveryError, "NO_RESEED_SOURCE"):
                self.client.find_nodes(b"t" * 32, "discovery")
        self.assertEqual(self.client.first_contact_diagnostics(), ())

    def test_signed_record_replication_and_lookup_use_real_authenticated_sockets(self) -> None:
        service_identity = ServiceIdentity.generate()
        service = ServiceDescriptor.create_remote(
            service_identity,
            "wan-overlay",
            issued_at=self.now,
            lifetime=1800,
        )
        with (
            patch("socket.getaddrinfo", side_effect=AssertionError("DNS used")) as getaddrinfo,
            patch("socket.gethostbyname", side_effect=AssertionError("DNS used")) as gethostbyname,
            patch("socket.gethostbyname_ex", side_effect=AssertionError("DNS used")) as gethostbyname_ex,
        ):
            self.assertEqual(self.client.publish(service, now=self.now), 3)
            resolved = self.client.lookup(SERVICE_RECORD, service.service_id, now=self.now)
        self.assertEqual(resolved, service)
        self.assertEqual(getaddrinfo.call_count, 0)
        self.assertEqual(gethostbyname.call_count, 0)
        self.assertEqual(gethostbyname_ex.call_count, 0)
        self.assertTrue(all(node.accepted_connections > 0 for node in self.nodes))
        self.assertTrue(all(node.rpc_requests > 0 for node in self.nodes))
        self.assertEqual(len(self.cache.load(now=self.now)), 6)
        health = self.client.health()
        self.assertEqual(health.state, NetworkState.CONNECTED)
        self.assertTrue(health.dht_ready)
        self.assertGreaterEqual(health.authenticated_peers, 2)

    def test_record_replication_and_lookup_retry_transient_private_route_failures(self) -> None:
        service = ServiceDescriptor.create_remote(
            ServiceIdentity.generate(),
            "wan-retry",
            issued_at=self.now,
            lifetime=1800,
        )
        envelope = encode_record(service, now=self.now)
        encoded = encode_optional_record(envelope)
        absent = encode_optional_record(None)
        peers = tuple(self.descriptors[:3])
        publish_calls = 0

        def publish_batch(batch, *_args, **_kwargs):
            nonlocal publish_calls
            publish_calls += 1
            if publish_calls == 1:
                return tuple(
                    (peer, b"" if index == 0 else None)
                    for index, peer in enumerate(batch)
                )
            return tuple(
                (peer, b"" if peer.node_id == peers[1].node_id else None)
                for peer in batch
            )

        with (
            patch.object(self.client, "find_nodes", return_value=peers),
            patch.object(self.client, "_request_batch", side_effect=publish_batch),
            patch("granger_network.wan_discovery.time.sleep"),
        ):
            self.assertEqual(self.client.publish(service, now=self.now), 2)
        self.assertEqual(publish_calls, 2)

        lookup_calls = 0

        def lookup_batch(batch, *_args, **_kwargs):
            nonlocal lookup_calls
            lookup_calls += 1
            if lookup_calls == 1:
                outcomes = {
                    peers[0].node_id: encoded,
                    peers[1].node_id: None,
                    peers[2].node_id: absent,
                }
            else:
                outcomes = {
                    peers[1].node_id: encoded,
                    peers[2].node_id: absent,
                }
            return tuple((peer, outcomes[peer.node_id]) for peer in batch)

        with (
            patch.object(self.client, "find_nodes", return_value=peers),
            patch.object(self.client, "_request_batch", side_effect=lookup_batch),
            patch("granger_network.wan_discovery.time.sleep"),
        ):
            self.assertEqual(
                self.client.lookup(SERVICE_RECORD, service.service_id, now=self.now),
                service,
            )
        self.assertEqual(lookup_calls, 2)

    def test_route_candidates_cache_role_specific_dht_results(self) -> None:
        candidate = NodeDescriptor.create(
            ServiceIdentity.generate(),
            RendezvousEndpoint("127.0.0.1", available_port()),
            ("rendezvous",),
            RelayPolicy(enabled=True, max_bandwidth_kib_per_second=64 * 1024),
            issued_at=self.now,
            lifetime=3600,
        )
        self.client._joined = True
        self.client._health.update(
            NetworkState.CONNECTED,
            authenticated_peers=3,
            known_peers=6,
            reachable_relays=6,
            dht_ready=True,
            failure_reason="",
        )
        target = b"r" * 32
        with patch.object(
            self.client,
            "find_nodes",
            return_value=(candidate,),
        ) as find_nodes:
            first = self.client.route_candidates(target, "rendezvous")
            second = self.client.route_candidates(target, "rendezvous")
        self.assertEqual(first, (candidate,))
        self.assertEqual(second, first)
        self.assertEqual(find_nodes.call_count, 1)

    def test_discovery_batch_workers_do_not_block_process_shutdown(self) -> None:
        daemon_states: list[bool] = []

        def request(*_args, **_kwargs) -> bytes:
            daemon_states.append(threading.current_thread().daemon)
            return b"response"

        with patch.object(self.client, "_request", side_effect=request):
            results = self.client._request_batch(
                list(self.descriptors[:3]),
                RpcType.FIND_NODE,
                b"request",
                RpcType.FIND_NODE,
            )
        self.assertEqual([content for _peer, content in results], [b"response"] * 3)
        self.assertEqual(daemon_states, [True] * 3)

    def test_private_discovery_gives_each_route_the_signed_timeout(self) -> None:
        timeouts: list[float] = []

        class FailingBuilder:
            def __init__(self, *_args, timeout: float, **_kwargs) -> None:
                timeouts.append(timeout)

            def open(self, _route):
                raise TimeoutError("controlled route timeout")

        self.client._joined = True
        self.client._private_routes_ready = True
        routes = tuple(
            ((descriptor, "access"),)
            for descriptor in self.descriptors[:4]
        )
        with (
            patch.object(self.client, "_private_route_candidates", return_value=routes),
            patch("granger_network.circuit.CircuitBuilder", FailingBuilder),
            patch(
                "granger_network.wan_discovery.connect_authenticated_peer",
                side_effect=AssertionError("post-join discovery dialed its target directly"),
            ),
            self.assertRaises(TimeoutError),
        ):
            self.client._request(
                self.descriptors[0],
                RpcType.FIND_NODE,
                b"request",
                RpcType.FIND_NODE,
            )
        self.assertEqual(timeouts, [self.client.timeout] * len(routes))

    def test_private_discovery_reaches_fourth_route_and_bounds_final_rpc(self) -> None:
        assigned_timeouts: list[float | None] = []
        attempts: list[tuple] = []

        class FakeConnection:
            def settimeout(self, value: float | None) -> None:
                assigned_timeouts.append(value)

        class FakeRpc:
            def request(self, *_args, **_kwargs):
                return SimpleNamespace(payload=b"response")

        class FakeCircuit:
            endpoint = SimpleNamespace(
                channel=SimpleNamespace(connection=FakeConnection()),
                rpc=FakeRpc(),
            )

            def __init__(self, route):
                self.route = route

            def close(self) -> None:
                return

        class RecoveringBuilder:
            def __init__(self, *_args, **_kwargs) -> None:
                return

            def open(self, _route):
                attempts.append(_route)
                if len(attempts) < 4:
                    raise TimeoutError("controlled earlier route loss")
                return FakeCircuit(_route)

        self.client._joined = True
        self.client._private_routes_ready = True
        routes = self.client._private_route_candidates(self.descriptors[0], limit=4)
        with (
            patch.object(self.client, "_private_route_candidates", return_value=routes),
            patch("granger_network.circuit.CircuitBuilder", RecoveringBuilder),
        ):
            response = self.client._request(
                self.descriptors[0],
                RpcType.FIND_NODE,
                b"request",
                RpcType.FIND_NODE,
            )
        self.assertEqual(response, b"response")
        self.assertEqual(len(attempts), 4)
        self.assertEqual(assigned_timeouts, [self.client.timeout])

    def test_private_discovery_remembers_a_working_four_node_ingress(self) -> None:
        self.client._joined = True
        self.client._private_routes_ready = True
        peer = self.descriptors[0]
        attempted: list[tuple[str, ...]] = []
        with patch("granger_network.wan_discovery.secrets.token_bytes", return_value=b"\0" * 4):
            routes = self.client._private_route_candidates(peer)
            working_ids = tuple(node.node_id for node, _role in routes[-1])

            def open_route(route):
                route_ids = tuple(node.node_id for node, _role in route)
                attempted.append(route_ids)
                if route_ids != working_ids:
                    raise TimeoutError("controlled unavailable ingress")
                circuit = Mock(route=route)
                circuit.endpoint.rpc.request.return_value = SimpleNamespace(payload=b"response")
                return circuit

            with patch("granger_network.circuit.CircuitBuilder") as builder:
                builder.return_value.open.side_effect = open_route
                self.client._request(peer, RpcType.FIND_NODE, b"first", RpcType.FIND_NODE)
                self.assertEqual(len(attempted), 4)
                attempted.clear()
                self.client._request(peer, RpcType.FIND_NODE, b"next", RpcType.FIND_NODE)
        self.assertEqual(attempted, [working_ids])
        self.assertEqual(len(set(working_ids)), 4)
        self.assertEqual(self.client.direct_first_contact_requests, 0)

    def test_private_route_hint_expires_without_changing_route_policy(self) -> None:
        peer = self.descriptors[0]
        with patch("granger_network.wan_discovery.secrets.token_bytes", return_value=b"\0" * 4):
            routes = self.client._private_route_candidates(peer)
            preferred = tuple(node.node_id for node, _role in routes[-1])
            self.client._private_route_hints[peer.node_id] = (time.monotonic() + 60.0, preferred)
            self.assertEqual(self.client._private_route_candidates(peer)[0], routes[-1])
            self.client._private_route_hints[peer.node_id] = (time.monotonic() - 1.0, preferred)
            self.assertEqual(self.client._private_route_candidates(peer), routes)
        self.assertNotIn(peer.node_id, self.client._private_route_hints)

    def test_private_route_hint_cannot_restore_an_ineligible_relay(self) -> None:
        peer = self.descriptors[0]
        route = self.client._private_route_candidates(peer)[-1]
        preferred = tuple(node.node_id for node, _role in route)
        removed_id = preferred[0]
        self.client._private_route_hints[peer.node_id] = (time.monotonic() + 60.0, preferred)
        eligible = tuple(node for node in self.descriptors if node.node_id != removed_id)
        with patch.object(self.client.pool, "candidates", return_value=eligible):
            routes = self.client._private_route_candidates(peer)
        self.assertNotIn(peer.node_id, self.client._private_route_hints)
        for candidate in routes:
            ids = {node.node_id for node, _role in candidate}
            self.assertEqual(len(ids), 4)
            self.assertNotIn(removed_id, ids)

    def test_failed_private_route_hint_is_discarded_without_losing_alternatives(self) -> None:
        from granger_network.wan_discovery import MAX_PRIVATE_ROUTE_ATTEMPTS
        self.client._joined = True
        self.client._private_routes_ready = True
        peer = self.descriptors[0]
        preferred = tuple(
            node.node_id for node, _role in self.client._private_route_candidates(peer)[-1]
        )
        self.client._private_route_hints[peer.node_id] = (time.monotonic() + 60.0, preferred)
        with patch("granger_network.circuit.CircuitBuilder") as builder:
            builder.return_value.open.side_effect = TimeoutError("controlled route loss")
            with self.assertRaises(TimeoutError):
                self.client._request(peer, RpcType.FIND_NODE, b"request", RpcType.FIND_NODE)
        self.assertEqual(builder.return_value.open.call_count, MAX_PRIVATE_ROUTE_ATTEMPTS)
        attempted = [tuple(p.node_id for p, _ in call.args[0])
                     for call in builder.return_value.open.call_args_list]
        self.assertEqual(len(attempted), len(set(attempted)))
        first_route = builder.return_value.open.call_args_list[0].args[0]
        self.assertEqual(tuple(node.node_id for node, _role in first_route), preferred)
        self.assertNotIn(peer.node_id, self.client._private_route_hints)
        self.assertEqual(self.client.direct_first_contact_requests, 0)

    def test_private_route_hint_storage_is_bounded(self) -> None:
        self.client._joined = True
        self.client._private_routes_ready = True

        def open_route(route):
            circuit = Mock(route=route)
            circuit.endpoint.rpc.request.return_value = SimpleNamespace(payload=b"response")
            return circuit

        with (
            patch("granger_network.wan_discovery.MAX_ROUTE_CANDIDATE_CACHE_ENTRIES", 2),
            patch("granger_network.circuit.CircuitBuilder") as builder,
        ):
            builder.return_value.open.side_effect = open_route
            for peer in self.descriptors[:3]:
                self.client._request(peer, RpcType.FIND_NODE, b"request", RpcType.FIND_NODE)
        self.assertEqual(
            tuple(self.client._private_route_hints),
            tuple(node.node_id for node in self.descriptors[1:3]),
        )

    def test_one_bootstrap_failure_keeps_quorum_and_two_failures_close_route(self) -> None:
        service_identity = ServiceIdentity.generate()
        service = ServiceDescriptor.create_remote(
            service_identity,
            "wan-failure",
            issued_at=self.now,
            lifetime=1800,
        )
        self.client.publish(service, now=self.now)
        replica_indexes = [
            index
            for index, node in enumerate(self.nodes)
            if node.records.fetch(SERVICE_RECORD, service.service_id) is not None
        ]
        self.assertEqual(len(replica_indexes), 3)
        self.nodes[replica_indexes[0]].stop()
        self.assertEqual(
            self.client.lookup(SERVICE_RECORD, service.service_id, now=self.now),
            service,
        )
        self.nodes[replica_indexes[1]].stop()
        with self.assertRaises(ResolutionError):
            self.client.lookup(SERVICE_RECORD, service.service_id, now=self.now)

    def test_unreachable_cache_entries_cannot_mask_signed_bootstrap_seeds(self) -> None:
        stale = [
            NodeDescriptor.create(
                ServiceIdentity.generate(),
                RendezvousEndpoint("127.0.0.1", available_port()),
                ("discovery",),
                RelayPolicy(enabled=False),
                issued_at=self.now,
                lifetime=3600,
            )
            for _ in range(8)
        ]
        self.cache.ingest(stale, source="peer:stale", now=self.now)
        client = WanDiscoveryClient(
            ServiceIdentity.generate(),
            BootstrapPool(self.bootstrap, self.cache),
            cache=self.cache,
            timeout=0.25,
        )
        health = client.join_network()
        self.assertEqual(health.state, NetworkState.JOINING)
        self.assertGreaterEqual(health.bootstrap_attempted, 2)
        self.assertGreaterEqual(health.authenticated_peers, 2)

    def test_private_discovery_retries_cover_guard_middle_pairs(self) -> None:
        role_nodes: dict[str, list[NodeDescriptor]] = {
            "access": [],
            "entry": [],
            "middle": [],
        }
        port = 45000
        for role in role_nodes:
            for index in range(2):
                role_nodes[role].append(
                    NodeDescriptor.create(
                        ServiceIdentity.generate(),
                        RendezvousEndpoint(f"127.{port - 44999}.0.{index + 1}", port),
                        ("bootstrap", role),
                        RelayPolicy(enabled=True),
                        issued_at=self.now,
                        lifetime=3600,
                    )
                )
                port += 1
        peer = NodeDescriptor.create(
            ServiceIdentity.generate(),
            RendezvousEndpoint("127.7.0.1", port),
            ("bootstrap", "discovery"),
            RelayPolicy(enabled=True),
            issued_at=self.now,
            lifetime=3600,
        )
        bootstrap = BootstrapSet.create(
            self.authority,
            [node for nodes in role_nodes.values() for node in nodes] + [peer],
            issued_at=self.now,
            lifetime=1800,
        )
        client = WanDiscoveryClient(
            ServiceIdentity.generate(),
            BootstrapPool(bootstrap, PeerCache(self.root / "route-peers.json")),
            timeout=0.1,
        )

        routes = client._private_route_candidates(peer, limit=4)
        self.assertEqual(len(routes), 4)
        self.assertEqual(
            {
                (route[1][0].node_id, route[2][0].node_id)
                for route in routes
            },
            {
                (guard.node_id, middle.node_id)
                for guard in role_nodes["entry"]
                for middle in role_nodes["middle"]
            },
        )
        for failed_guard in role_nodes["entry"]:
            for failed_middle in role_nodes["middle"]:
                self.assertTrue(
                    any(
                        route[1][0].node_id != failed_guard.node_id
                        and route[2][0].node_id != failed_middle.node_id
                        for route in routes
                    )
                )

    def test_malformed_signed_record_is_rejected_by_remote_store(self) -> None:
        service_identity = ServiceIdentity.generate()
        service = ServiceDescriptor.create_remote(
            service_identity,
            "wan-poison",
            issued_at=self.now,
            lifetime=1800,
        )
        envelope = encode_record(service, now=self.now)
        document = json.loads(envelope.payload)
        document["serviceId"] = "a" * 52
        poisoned = RecordEnvelope(
            envelope.kind,
            envelope.key,
            envelope.sequence,
            envelope.expires_at,
            json.dumps(document, separators=(",", ":"), sort_keys=True).encode("ascii"),
        )
        peer = connect_authenticated_peer(
            self.descriptors[0],
            ServiceIdentity.generate(),
            PeerRole.CLIENT,
            timeout=2.0,
        )
        try:
            with self.assertRaises(ProtocolError):
                peer.rpc.request(
                    RpcType.STORE_RECORD,
                    encode_record_envelope(poisoned),
                    expected=RpcType.STORE_RECORD,
                )
        finally:
            peer.close()
        self.assertIsNone(self.nodes[0].records.fetch(SERVICE_RECORD, service.service_id))

    def test_persistent_store_survives_node_restart(self) -> None:
        service_identity = ServiceIdentity.generate()
        service = ServiceDescriptor.create_remote(
            service_identity,
            "wan-persist",
            issued_at=self.now,
            lifetime=1800,
        )
        self.client.publish(service, now=self.now)
        stored_index = next(
            index
            for index, node in enumerate(self.nodes)
            if node.records.fetch(SERVICE_RECORD, service.service_id) is not None
        )
        first = self.nodes[stored_index]
        first.stop()
        replacement = WanNodeServer(
            self.identities[stored_index],
            self.descriptors[stored_index],
            self.root / f"node-{stored_index}",
            known_peers=self.descriptors,
        )
        self.nodes[stored_index] = replacement
        self.assertEqual(
            replacement.records.fetch(SERVICE_RECORD, service.service_id),
            encode_record(service, now=self.now),
        )
        replacement.start_background()
        self.assertEqual(
            self.client.lookup(SERVICE_RECORD, service.service_id, now=self.now),
            service,
        )


if __name__ == "__main__":
    unittest.main()
