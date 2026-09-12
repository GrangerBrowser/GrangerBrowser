from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import operator_bundle
import operator_publication as publication
import test_operator_coordinator as coordinator_tests
from granger_network._codec import encode_base64url


class OperatorPublicationTests(unittest.TestCase):
    def setUp(self):
        # Reuse the signed, isolated four-node fixture, never production authority material.
        fixture = coordinator_tests.OperatorCoordinatorTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.remote = fixture.root/'remote'
        self.public = self.remote/'etc/granger-node/public-bootstrap'
        shutil.copytree(fixture.previous, self.public)
        node = self.remote/'var/lib/granger-node/node-a'
        node.mkdir(parents=True)
        (node/'node-descriptor.json').write_text(fixture.descriptors[0].to_json(), encoding='utf-8')
        run = self.remote/'run/granger-node/node-a'
        run.mkdir(parents=True)
        self.status = run/'status.json'
        self.status.write_text(json.dumps(dict(state='RUNNING', nodeId=fixture.nodes[0]['nodeId'],
            network=dict(state='CONNECTED', authenticatedPeers=4, dhtReady=True))), encoding='utf-8')
        self.request = dict(operation='collect', node='node-a', nodeId=fixture.nodes[0]['nodeId'],
            pins={name:(fixture.previous/name).read_text().strip()
                  for name in ('bootstrap-authority.pin','config-authority.pin')})
        self.next = fixture.root/'public-bundles/generation2'
        operator_bundle.renew_bundle(argparse.Namespace(private_root=fixture.root/'private',
            previous_public_root=fixture.previous, public_root=self.next,
            descriptor=[fixture.root/f'peer-{i}.json' for i in range(4)], lifetime=3600))
        self.config = json.loads((self.next/'browser-wan.json').read_text())
        import hashlib
        self.deploy = dict(self.request, operation='deploy', generation=2,
            configSha256=hashlib.sha256((self.next/'browser-wan.json').read_bytes()).hexdigest(),
            files={name:encode_base64url((self.next/name).read_bytes()) for name in publication.FILES})
        def fixture_path(value):
            value = str(value)
            return self.remote/value.lstrip('/') if value.startswith(('/etc/','/var/','/run/')) else Path(value)
        self.enterContext(patch.object(publication, 'Path', side_effect=fixture_path))
        self.enterContext(patch.object(publication, '_sync_directory'))
        self.enterContext(patch.object(publication.os, 'chown', create=True))
        self.exchanges = []
        def exchange(left, right):
            self.exchanges.append((left, right))
            backup = left.parent/'previous'
            right.rename(backup)
            left.rename(right)
            backup.rename(left)
        self.enterContext(patch.object(publication, '_exchange', side_effect=exchange))

    def test_collect_is_public_only_and_read_only(self):
        before = {p.name:p.read_bytes() for p in self.public.iterdir()}
        result = publication.handle(self.request)
        self.assertTrue(result['ok'])
        self.assertEqual(result['generation'], 1)
        self.assertEqual(result['network']['authenticatedPeers'], 4)
        self.assertNotIn('privateKey', json.dumps(result))
        self.assertEqual(before, {p.name:p.read_bytes() for p in self.public.iterdir()})

    def test_valid_bundle_validated_before_one_exchange_and_idempotent_retry(self):
        result = publication.handle(self.deploy)
        self.assertTrue(result['ok'], result)
        self.assertEqual(len(self.exchanges), 1)
        for name in publication.FILES:
            self.assertEqual((self.public/name).read_bytes(), (self.next/name).read_bytes())
        result = publication.handle(self.deploy)
        self.assertTrue(result['reused'])
        self.assertEqual(len(self.exchanges), 1)
        self.assertFalse(list(self.public.parent.glob('.public-staged-*')))

    def test_bad_signature_hash_member_pin_and_identity_never_exchange(self):
        cases = []
        request = copy.deepcopy(self.deploy)
        request['configSha256'] = '0'*64
        cases.append(request)
        request = copy.deepcopy(self.deploy)
        request['files']['../key'] = 'AAAA'
        cases.append(request)
        request = copy.deepcopy(self.deploy)
        request['pins']['config-authority.pin'] = 'AAAA'
        cases.append(request)
        request = copy.deepcopy(self.deploy)
        request['nodeId'] = self.fixture.nodes[1]['nodeId']
        cases.append(request)
        request = copy.deepcopy(self.deploy)
        bad = dict(self.config, signature='invalid')
        encoded = json.dumps(bad).encode()
        import hashlib
        request['configSha256'] = hashlib.sha256(encoded).hexdigest()
        request['files']['browser-wan.json'] = encode_base64url(encoded)
        cases.append(request)
        for index, request in enumerate(cases):
            with self.subTest(index=index):
                self.assertFalse(publication.handle(request)['ok'])
                self.assertFalse(self.exchanges)
                self.assertEqual(json.loads((self.public/'browser-wan.json').read_text())['generation'], 1)

    def test_rollback_equivocation_and_no_atomic_exchange_fail_closed(self):
        request = dict(self.deploy, generation=1)
        self.assertFalse(publication.handle(request)['ok'])
        self.assertFalse(self.exchanges)
        with patch.object(publication, '_exchange', side_effect=OSError('unsupported')):
            self.assertFalse(publication.handle(self.deploy)['ok'])
        self.assertEqual(json.loads((self.public/'browser-wan.json').read_text())['generation'], 1)
        self.assertFalse(list(self.public.parent.glob('.public-staged-*')))

    def test_stale_status_does_not_prove_health(self):
        import os
        os.utime(self.status, (1, 1))
        self.assertFalse(publication.handle(self.request)['ok'])


if __name__ == '__main__':
    unittest.main()
