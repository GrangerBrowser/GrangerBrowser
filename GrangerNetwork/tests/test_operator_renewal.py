from __future__ import annotations

import argparse
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import operator_bundle
from granger_network.identity import ServiceIdentity
from granger_network.errors import DescriptorError
from granger_network.peer import NodeDescriptor, RelayPolicy
from granger_network.transport import RendezvousEndpoint


class OperatorRenewalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='Granger-renewal-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.now = int(time.time())
        self.descriptors = []
        for index in range(2):
            descriptor = NodeDescriptor.create(
                ServiceIdentity.generate(), RendezvousEndpoint('127.0.0.1', 23000 + index),
                ('bootstrap', 'discovery'), RelayPolicy(), issued_at=self.now, lifetime=3600,
            )
            path = self.root / f'node-{index}.json'
            path.write_text(descriptor.to_json(), encoding='utf-8')
            self.descriptors.append(path)
        self.private = self.root / 'private'
        self.previous = self.root / 'old'
        operator_bundle.create_bundle(argparse.Namespace(
            private_root=self.private, public_root=self.previous, descriptor=self.descriptors,
            generation=13, lifetime=60, route_attempts=6, replication_factor=3,
            minimum_replicas=2, timeout_seconds=8.0,
        ))
        self.options = argparse.Namespace(
            private_root=self.private, previous_public_root=self.previous,
            public_root=self.root / 'new', descriptor=self.descriptors, lifetime=600,
        )

    def test_expired_generation_renews_with_same_authorities_and_policy(self):
        before = {p.name: p.read_bytes() for p in self.private.iterdir()}
        with mock.patch.object(operator_bundle.time, 'time', return_value=self.now + 61), \
                mock.patch.object(ServiceIdentity, 'generate', side_effect=AssertionError('new authority')):
            report = operator_bundle.renew_bundle(self.options)
        self.assertEqual(report['generation'], 14)
        self.assertFalse(report['newAuthorityCreated'])
        self.assertTrue(report['identitiesPreserved'])
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.private.iterdir()})
        for name in ('bootstrap-authority.pin', 'config-authority.pin'):
            self.assertEqual((self.previous / name).read_bytes(), (self.options.public_root / name).read_bytes())
        self.assertFalse(list(self.root.glob('.granger-renew-*')))

    def test_missing_authority_does_not_generate_replacement(self):
        key = self.private / 'config-authority.json'
        key.unlink()
        with mock.patch.object(ServiceIdentity, 'generate', side_effect=AssertionError('new authority')):
            with self.assertRaisesRegex(ValueError, 'existing authority'):
                operator_bundle.renew_bundle(self.options)
        self.assertFalse(key.exists())
        self.assertFalse(self.options.public_root.exists())

    def test_wrong_authority_is_rejected(self):
        (self.private / 'config-authority.json').unlink()
        ServiceIdentity.generate().save(self.private / 'config-authority.json')
        with self.assertRaisesRegex(ValueError, 'previous pin'):
            operator_bundle.renew_bundle(self.options)
        self.assertFalse(self.options.public_root.exists())

    def test_changed_router_set_is_rejected(self):
        self.options.descriptor = self.descriptors[:1]
        with self.assertRaisesRegex(ValueError, 'router identities'):
            operator_bundle.renew_bundle(self.options)
        self.assertFalse(self.options.public_root.exists())

    def test_no_overwrite_of_existing_generation(self):
        self.options.public_root = self.previous
        with self.assertRaisesRegex(ValueError, 'new public destination'):
            operator_bundle.renew_bundle(self.options)

    def test_expired_new_descriptors_are_rejected(self):
        with mock.patch.object(operator_bundle.time, 'time', return_value=self.now + 3601):
            with self.assertRaises(DescriptorError):
                operator_bundle.renew_bundle(self.options)
        self.assertFalse(self.options.public_root.exists())

    def test_failed_renewal_removes_only_its_temporary_output(self):
        self.options.lifetime = 7200
        with self.assertRaisesRegex(ValueError, 'cannot outlive'):
            operator_bundle.renew_bundle(self.options)
        self.assertFalse(self.options.public_root.exists())
        self.assertFalse(list(self.root.glob('.granger-renew-*')))
        self.assertTrue((self.private / 'config-authority.json').is_file())
        self.assertTrue((self.previous / 'browser-wan.json').is_file())
