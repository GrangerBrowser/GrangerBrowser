from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from granger_network.descriptor import ServiceDescriptor
from granger_network.errors import OverlayRoutingError, ReplayError, ResolutionError
from granger_network.identity import ServiceIdentity
from granger_network.introduction import IntroductionDescriptor
from granger_network.peer import NodeDescriptor, RelayPolicy
from granger_network.transport import RendezvousEndpoint
from granger_network.wan_client import connect_service
from granger_network.wan_routing import WanRouteSelection


class IntroductionRefreshTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = ServiceIdentity.generate()
        self.service = ServiceDescriptor.create_remote(self.identity, "intro-refresh", lifetime=1800)
        self.nodes = [
            NodeDescriptor.create(
                ServiceIdentity.generate(), RendezvousEndpoint("127.0.0.1", 30000 + index),
                ("access", "entry", "middle", "introduction"), RelayPolicy(enabled=True),
                lifetime=1800,
            )
            for index in range(5)
        ]
        self.old = self.introduction(2, self.nodes[3])
        self.new = self.introduction(3, self.nodes[4])
        self.runtime = SimpleNamespace(identity=ServiceIdentity.generate(), discovery=Mock())
        self.resolver = Mock()
        self.resolver.resolve.return_value = self.service
        self.resolver.resolve_introduction.side_effect = [self.old, self.new]
        by_id = {node.node_id: node for node in self.nodes}
        self.resolver.resolve_node.side_effect = by_id.__getitem__
        self.route = SimpleNamespace(route=tuple(zip(self.nodes[:3], ("access", "entry", "middle"))))
        self.selector = Mock()
        self.selector.client_candidates.return_value = [self.route] * 6
        self.used_sequences = []
        self.session = object()

    def introduction(self, sequence, node):
        return IntroductionDescriptor.create(
            self.identity, self.service, [node.node_id], sequence=sequence, lifetime=900,
        )

    def connect(self, *, failure="introduction stage failed during request (ProtocolError)", attempts=6):
        def client(_identity, service, introduction, _route, **_options):
            self.assertEqual(service, self.service)

            def open_session(node):
                self.used_sequences.append(introduction.sequence)
                self.assertIn(node.node_id, {point.node_id for point in introduction.points})
                if introduction == self.new:
                    return self.session
                raise OverlayRoutingError(failure)

            return SimpleNamespace(connect=open_session)

        with (
            patch("granger_network.wan_client.WanRouteSelector", return_value=self.selector),
            patch("granger_network.wan_client.WanServiceClient", side_effect=client),
        ):
            return connect_service(self.runtime, self.resolver, self.service.canonical_name,
                                   route_attempts=attempts)

    def test_refreshes_signed_introduction_after_request_rejection(self):
        connected = self.connect()
        self.assertEqual(self.used_sequences, [2, 3])
        self.assertEqual(connected.attempts, 2)
        self.assertIs(connected.session, self.session)
        self.assertEqual(connected.introduction_node, self.nodes[4])
        self.assertEqual(self.resolver.resolve_introduction.call_count, 2)

    def test_retries_signed_resolution_until_new_sequence_propagates(self):
        self.resolver.resolve_introduction.side_effect = [self.old, self.old, self.new]
        connected = self.connect()
        self.assertEqual(self.used_sequences, [2, 2, 3])
        self.assertEqual(connected.attempts, 3)
        self.assertIs(connected.session, self.session)
        self.assertEqual(self.resolver.resolve_introduction.call_count, 3)

    def test_unchanged_introduction_does_not_expand_attempt_budget(self):
        self.resolver.resolve_introduction.side_effect = None
        self.resolver.resolve_introduction.return_value = self.old
        with self.assertRaises(OverlayRoutingError):
            self.connect()
        self.assertEqual(self.used_sequences, [2] * 6)
        self.assertEqual(self.resolver.resolve_introduction.call_count, 6)

    def test_alternates_redundant_introduction_points(self):
        self.old = IntroductionDescriptor.create(
            self.identity,
            self.service,
            [self.nodes[3].node_id, self.nodes[4].node_id],
            sequence=2,
            lifetime=900,
        )
        self.resolver.resolve_introduction.side_effect = None
        self.resolver.resolve_introduction.return_value = self.old
        used_nodes = []

        def client(_identity, _service, _introduction, _route, **_options):
            def reject(node):
                used_nodes.append(node.node_id)
                raise OverlayRoutingError(
                    "introduction stage failed during request (ProtocolError)"
                )

            return SimpleNamespace(connect=reject)

        with (
            patch("granger_network.wan_client.WanRouteSelector", return_value=self.selector),
            patch("granger_network.wan_client.WanServiceClient", side_effect=client),
            self.assertRaises(OverlayRoutingError),
        ):
            connect_service(
                self.runtime,
                self.resolver,
                self.service.canonical_name,
                route_attempts=4,
            )
        ordered_points = [point.node_id for point in self.old.points]
        self.assertEqual(used_nodes, ordered_points * 2)

    def test_single_attempt_does_not_start_unused_refresh(self):
        with self.assertRaises(OverlayRoutingError):
            self.connect(attempts=1)
        self.assertEqual(self.used_sequences, [2])
        self.assertEqual(self.resolver.resolve_introduction.call_count, 1)

    def test_refreshes_signed_introduction_after_rendezvous_rejection(self):
        connected = self.connect(failure="rendezvous stage failed during join (ProtocolError)")
        self.assertEqual(self.used_sequences, [2, 3])
        self.assertEqual(connected.attempts, 2)
        self.assertIs(connected.session, self.session)
        self.assertEqual(connected.introduction_node, self.nodes[4])
        self.assertEqual(self.resolver.resolve_introduction.call_count, 2)

    def test_unchanged_introduction_after_rendezvous_failure_does_not_expand_budget(self):
        self.resolver.resolve_introduction.side_effect = None
        self.resolver.resolve_introduction.return_value = self.old
        with self.assertRaises(OverlayRoutingError):
            self.connect(failure="rendezvous stage failed during join (ProtocolError)")
        self.assertEqual(self.used_sequences, [2] * 6)
        self.assertEqual(self.resolver.resolve_introduction.call_count, 6)

    def test_rendezvous_route_failure_does_not_refresh_introduction(self):
        with self.assertRaises(OverlayRoutingError):
            self.connect(failure="rendezvous stage failed during route build (ProtocolError)")
        self.assertEqual(self.used_sequences, [2] * 6)
        self.assertEqual(self.resolver.resolve_introduction.call_count, 1)

    def test_refresh_failure_remains_fail_closed(self):
        self.resolver.resolve_introduction.side_effect = [self.old, ResolutionError("quorum unavailable")]
        with self.assertRaises(ResolutionError):
            self.connect()
        self.assertEqual(self.used_sequences, [2])

    def test_refresh_rejects_rollback_and_equivocation(self):
        for replacement in (self.introduction(1, self.nodes[4]), self.introduction(2, self.nodes[4])):
            with self.subTest(sequence=replacement.sequence):
                self.used_sequences.clear()
                self.resolver.resolve_introduction.side_effect = [self.old, replacement]
                with self.assertRaises(ReplayError):
                    self.connect()
                self.assertEqual(self.used_sequences, [2])


class RouteRetryCoverageTests(unittest.TestCase):
    def test_shared_budget_covers_live_pairs_across_introduction_points(self):
        identity = ServiceIdentity.generate()
        service = ServiceDescriptor.create_remote(identity, "retry-coverage", lifetime=1800)
        nodes = [
            NodeDescriptor.create(
                ServiceIdentity.generate(), RendezvousEndpoint("127.0.0.1", 31000 + index),
                ("access", "entry", "middle", "introduction"), RelayPolicy(enabled=True),
                lifetime=1800,
            )
            for index in range(8)
        ]
        access, guards, middles, points = nodes[0], nodes[1:3], nodes[3:6], nodes[6:8]
        introduction = IntroductionDescriptor.create(
            identity, service, [node.node_id for node in points], sequence=1, lifetime=900,
        )
        pairs = ((0, 0), (1, 1), (0, 2), (1, 0), (0, 1), (1, 2))
        routes = [
            WanRouteSelection(
                ((access, "access"), (guards[guard], "entry"), (middles[middle], "middle")),
                True,
            )
            for guard, middle in pairs
        ]
        resolver = Mock()
        resolver.resolve.return_value = service
        resolver.resolve_introduction.return_value = introduction
        resolver.resolve_node.side_effect = {node.node_id: node for node in points}.__getitem__
        runtime = SimpleNamespace(identity=ServiceIdentity.generate(), discovery=Mock())
        selector = Mock()
        selector.client_candidates.return_value = tuple(routes)
        session = object()

        for failed_guard in guards:
            for failed_middle in middles:
                with self.subTest(guard=guards.index(failed_guard), middle=middles.index(failed_middle)):
                    attempted = []
                    used_points = []

                    def client(_identity, _service, _introduction, route, **_options):
                        def connect(node):
                            attempted.append((route[1][0], route[2][0]))
                            used_points.append(node.node_id)
                            if route[1][0] == failed_guard or route[2][0] == failed_middle:
                                raise OverlayRoutingError(
                                    "introduction stage failed during route build (TimeoutError)"
                                )
                            return session
                        return SimpleNamespace(connect=connect)

                    with (
                        patch("granger_network.wan_client.WanRouteSelector", return_value=selector),
                        patch("granger_network.wan_client.WanServiceClient", side_effect=client),
                    ):
                        connected = connect_service(
                            runtime, resolver, service.canonical_name, route_attempts=6,
                        )
                    self.assertIs(connected.session, session)
                    self.assertLessEqual(connected.attempts, 6)
                    self.assertEqual(attempted[0], (guards[0], middles[0]))
                    self.assertEqual(len(set(attempted)), len(attempted))
                    ordered_points = [point.node_id for point in introduction.points]
                    self.assertEqual(used_points, (ordered_points * 3)[:len(used_points)])


if __name__ == "__main__":
    unittest.main()
