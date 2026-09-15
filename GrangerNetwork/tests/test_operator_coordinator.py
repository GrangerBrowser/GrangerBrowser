from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import operator_bundle
import operator_renewal as renewal
from granger_network.bootstrap import DEFAULT_NETWORK_ID, DEFAULT_PROTOCOL_VERSION
from granger_network.errors import DiscoveryError
from granger_network.identity import ServiceIdentity
from granger_network.peer import NodeDescriptor, RelayPolicy
from granger_network.transport import RendezvousEndpoint
from granger_network.wan_config import _ProvisionLock


class FleetFixture:
    def __init__(self, nodes, descriptors, initial):
        self.nodes = nodes
        self.reports = {n['name']: dict(descriptor=json.loads(p.to_json()), generation=1,
            configSha256=initial.sha256, state='RUNNING', nodeId=p.node_id)
            for n, p in zip(nodes, descriptors, strict=True)}
        self.fail = None
        self.deployed = []
        self.verified = []

    def collect(self, node):
        if self.fail == ('collect', node['name']):
            raise renewal.RenewalError('NODE_UNAVAILABLE')
        return copy.deepcopy(self.reports[node['name']])

    def deploy(self, node, root, config):
        if self.fail == ('deploy', node['name']):
            raise OSError('simulated transport failure')
        self.reports[node['name']].update(generation=config.generation, configSha256=config.sha256)
        self.deployed.append((node['name'], config.generation, config.sha256))

    def verify(self, node, root, config):
        if self.fail and self.fail[0] == 'verify' and self.fail[1] == node['name']:
            raise renewal.RenewalError(self.fail[2])
        self.verified.append(node['name'])


class OperatorCoordinatorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='Granger-renew-coordinator-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.now = int(time.time())
        self.descriptors = [NodeDescriptor.create(ServiceIdentity.generate(),
            RendezvousEndpoint('127.0.0.1', 24000 + i),
            ('bootstrap', 'discovery', 'access', 'entry', 'middle'), RelayPolicy(enabled=True),
            issued_at=self.now, lifetime=86400) for i in range(4)]
        self.nodes = [dict(name='node-' + chr(97+i), host='127.0.0.1', nodeId=p.node_id)
                      for i, p in enumerate(self.descriptors)]
        paths = []
        for i, peer in enumerate(self.descriptors):
            path = self.root / f'peer-{i}.json'
            path.write_text(peer.to_json(), encoding='utf-8')
            paths.append(path)
        self.previous = self.root / 'public-bundles/generation1'
        operator_bundle.create_bundle(argparse.Namespace(private_root=self.root/'private',
            public_root=self.previous, descriptor=paths, generation=1, lifetime=600,
            route_attempts=6, replication_factor=3, minimum_replicas=2, timeout_seconds=8.0))
        trust = self.root / 'public-trust'
        trust.mkdir()
        for name in ('bootstrap-authority.pin', 'config-authority.pin'):
            (trust/name).write_bytes((self.previous/name).read_bytes())
        self.options = dict(operatorRoot=str(self.root), initialGeneration=1, nodes=self.nodes)
        self.clock = lambda: self.now
        base = renewal.Coordinator(self.options, None, clock=self.clock)
        self.fleet = FleetFixture(self.nodes, self.descriptors, base.initial[0])

    def coordinator(self):
        return renewal.Coordinator(self.options, self.fleet, clock=self.clock)

    def retry(self):
        path = self.root/'renewal-state.json'
        state = json.loads(path.read_text())
        state['nextRetry'] = 0
        path.write_text(json.dumps(state), encoding='utf-8')

    def test_normal_renewal_existing_authorities_and_browser_verification(self):
        with patch.object(ServiceIdentity, 'generate', side_effect=AssertionError('new authority')):
            state = self.coordinator().run_once()
        self.assertEqual(state['lastRenewalResult'], 'PASS')
        self.assertEqual(state['currentGeneration'], 2)
        self.assertTrue(state['complete'])
        self.assertEqual(set(self.fleet.verified), {n['name'] for n in self.nodes})
        self.assertEqual(state['fleet'], {n['name']: 'VERIFIED' for n in self.nodes})
        self.assertLess(state['renewalWindowStart'], state['currentExpiresAt'] - 3600)
        self.assertEqual(self.coordinator().run_once()['lastRenewalResult'], 'PASS')
        self.assertEqual(len(self.fleet.deployed), 4)

    def test_one_node_offline_does_not_sign_partial_fleet(self):
        self.fleet.fail = ('collect', 'node-b')
        state = self.coordinator().run_once()
        self.assertEqual(state['lastRenewalResult'], 'NODE_UNAVAILABLE')
        self.assertFalse((self.root/'public-bundles/generation2').exists())
        self.assertGreater(state['nextRetry'], self.now)

    def test_missing_authority_never_generates_replacement(self):
        key = self.root/'private/config-authority.json'
        key.unlink()
        with patch.object(ServiceIdentity, 'generate', side_effect=AssertionError('new authority')):
            state = self.coordinator().run_once()
        self.assertEqual(state['lastRenewalResult'], 'AUTHORITY_UNAVAILABLE')
        self.assertFalse(key.exists())
        self.assertFalse(self.fleet.deployed)

    def test_wrong_authority_is_rejected(self):
        key = self.root/'private/config-authority.json'
        key.unlink()
        ServiceIdentity.generate().save(key)
        self.assertEqual(self.coordinator().run_once()['lastRenewalResult'], 'AUTHORITY_PIN_MISMATCH')
        self.assertFalse(self.fleet.deployed)

    def test_wrong_external_pin_fails_before_signing(self):
        (self.root/'public-trust/config-authority.pin').write_text('invalid\n', encoding='ascii')
        with self.assertRaises((DiscoveryError, renewal.RenewalError)):
            self.coordinator()

    def test_descriptor_signature_and_expiry_fail_closed(self):
        original = copy.deepcopy(self.fleet.reports['node-a'])
        for field, value in (('signature', 'invalid'), ('expiresAt', self.now - 10)):
            with self.subTest(field=field):
                self.fleet.reports['node-a'] = copy.deepcopy(original)
                self.fleet.reports['node-a']['descriptor'][field] = value
                self.assertNotEqual(self.coordinator().run_once()['lastRenewalResult'], 'PASS')
                self.assertFalse((self.root/'public-bundles/generation2').exists())
                self.retry()

    def test_changed_router_identity_is_rejected(self):
        identities = [ServiceIdentity.generate() for _ in range(4)]
        # A changed identity is independently rejected, before any signing.
        p = NodeDescriptor.create(identities[0], RendezvousEndpoint('127.0.0.1', 25000),
            ('bootstrap', 'discovery'), RelayPolicy(), lifetime=1800)
        self.fleet.reports['node-a']['descriptor'] = json.loads(p.to_json())
        self.assertEqual(self.coordinator().run_once()['lastRenewalResult'], 'NODE_IDENTITY_MISMATCH')
        self.assertFalse(self.fleet.deployed)

    def test_descriptor_headroom_does_not_create_near_expiry_generation(self):
        self.now += 23 * 3600
        self.assertEqual(self.coordinator().run_once()['lastRenewalResult'], 'FRESH_DESCRIPTORS_NOT_READY')
        self.assertFalse((self.root/'public-bundles/generation2').exists())
        self.assertFalse(self.fleet.deployed)

    def test_partial_deployment_resumes_exact_signed_bytes(self):
        self.fleet.fail = ('deploy', 'node-c')
        first = self.coordinator().run_once()
        self.assertFalse(first['complete'])
        self.assertEqual(first['currentGeneration'], 2)
        self.assertEqual(set(first['fleet']), {'node-a', 'node-b'})
        original = (self.root/'public-bundles/generation2/browser-wan.json').read_bytes()
        self.fleet.fail = None
        self.retry()
        with patch.object(operator_bundle, 'renew_bundle', side_effect=AssertionError('resigning')):
            final = self.coordinator().run_once()
        self.assertEqual(final['lastRenewalResult'], 'PASS')
        self.assertEqual(original, (self.root/'public-bundles/generation2/browser-wan.json').read_bytes())

    def test_health_or_publication_failure_never_marks_complete(self):
        for category in ('NODE_RESTART_FAILED', 'DHT_NOT_READY', 'CONFIG_PUBLICATION_UNAVAILABLE'):
            with self.subTest(category=category):
                self.fleet.fail = ('verify', 'node-d', category)
                state = self.coordinator().run_once()
                self.assertFalse(state['complete'])
                self.assertEqual(state['lastRenewalResult'], category)
                self.retry()
        self.fleet.fail = None
        self.assertTrue(self.coordinator().run_once()['complete'])

    def test_completed_signing_before_journal_crash_reuses_existing_successor(self):
        coordinator = self.coordinator()
        with patch.object(coordinator, '_adopt', side_effect=RuntimeError('simulated crash')):
            with self.assertRaises(RuntimeError):
                coordinator.run_once()
        self.assertFalse((self.root/'renewal-state.json').exists())
        original = (self.root/'public-bundles/generation2/browser-wan.json').read_bytes()
        with patch.object(operator_bundle, 'renew_bundle', side_effect=AssertionError('resigning')):
            self.assertTrue(self.coordinator().run_once()['complete'])
        self.assertEqual(original, (self.root/'public-bundles/generation2/browser-wan.json').read_bytes())

    def test_same_generation_remote_conflict_stops(self):
        self.fleet.reports['node-a']['configSha256'] = '0' * 64
        self.assertEqual(self.coordinator().run_once()['lastRenewalResult'], 'GENERATION_EQUIVOCATION')
        self.assertFalse(self.fleet.deployed)

    def test_changed_local_signed_generation_fails_high_water_check(self):
        self.coordinator().run_once()
        self.retry()
        path = self.root/'renewal-state.json'
        state = json.loads(path.read_text())
        state['currentSha256'] = '0' * 64
        path.write_text(json.dumps(state), encoding='utf-8')
        with self.assertRaisesRegex(renewal.RenewalError, 'EQUIVOCATION'):
            self.coordinator().run_once()

    def test_duplicate_scheduler_and_race_fail_without_stealing_lease(self):
        with _ProvisionLock(self.root/'renewal.lock', timeout=0):
            with self.assertRaises(DiscoveryError):
                self.coordinator().run_once()
        self.assertFalse(self.fleet.deployed)
        self.assertTrue(self.coordinator().run_once()['complete'])

    def test_ssh_flags_are_key_only_and_remote_payload_is_public_only(self):
        options = dict(self.options, sshExecutable='ssh.exe', sshIdentity='unread-private-key')
        fleet = renewal.SshFleet(options)
        with patch.object(renewal.subprocess, 'run') as run:
            run.return_value.returncode = 0
            run.return_value.stdout = '{"ok":true}'
            fleet.collect(self.nodes[0])
        args, kwargs = run.call_args
        self.assertIn('BatchMode=yes', args[0])
        self.assertIn('StrictHostKeyChecking=yes', args[0])
        self.assertIn('IdentitiesOnly=yes', args[0])
        self.assertIn('unread-private-key', args[0])
        self.assertNotIn('unread-private-key', kwargs['input'])
        self.assertNotIn('bootstrap-authority.json', kwargs['input'])
        self.assertNotIn('config-authority.json', kwargs['input'])

    def test_null_remote_health_is_not_ready_instead_of_crashing_verification(self):
        options = dict(
            self.options,
            sshExecutable='ssh.exe',
            sshIdentity='unread-private-key',
        )
        fleet = renewal.SshFleet(options)
        config = SimpleNamespace(generation=8, sha256='a' * 64)
        report = {
            'state': 'RUNNING',
            'nodeId': self.nodes[0]['nodeId'],
            'generation': config.generation,
            'configSha256': config.sha256,
            'network': {
                'authenticatedPeers': None,
                'dhtReady': None,
                'state': 'RECOVERING',
            },
        }
        with (
            patch.object(fleet, 'collect', return_value=report),
            patch.object(renewal.time, 'monotonic', side_effect=(
                0.0, 1.0, renewal.FLEET_HEALTH_TIMEOUT_SECONDS + 1.0,
            )),
            patch.object(renewal.time, 'sleep'),
            self.assertRaisesRegex(renewal.RenewalError, 'FLEET_HEALTH_NOT_READY'),
        ):
            fleet.verify(self.nodes[0], self.root, config)


if __name__ == '__main__':
    unittest.main()
