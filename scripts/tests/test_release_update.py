from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import release_update as update


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')


class ReleaseUpdateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root / 'state'
        self.manifest = self.root / 'release.json'
        self.artifact = self.root / 'GrangerSetup.exe'
        self.artifact.write_bytes(b'MZ isolated test payload')
        self.trust = self.root / 'trust.json'
        self.key = Ed25519PrivateKey.generate()
        self.pin = {'version': 1, 'manifestPublicKey': b64(self.key.public_key().public_bytes_raw()),
                    'windowsCertificateSha1': 'a' * 40}
        self.trust.write_bytes(update.canonical(self.pin))
        self.now = int(time.time())
        self.value = {'version': 1, 'sequence': 1, 'productVersion': '0.4.5', 'platform': 'windows-x64',
                      'issuedAt': self.now - 1, 'expiresAt': self.now + 600, 'artifact': 'GrangerSetup.exe',
                      'size': self.artifact.stat().st_size, 'sha256': hashlib.sha256(self.artifact.read_bytes()).hexdigest(),
                      'windowsCertificateSha1': 'a' * 40, 'releaseNotes': 'Local fixture'}
        self.sign()

    def sign(self, **changes):
        self.value.update(changes)
        signed = dict(self.value, signature=b64(self.key.sign(update.DOMAIN + update.canonical(self.value))))
        self.manifest.write_bytes(update.canonical(signed))

    def prepare(self, **kwargs):
        return update.prepare(self.state, self.manifest, self.artifact, self.trust,
                              current_version='0.4.4', **kwargs)

    def test_default_is_ask_and_later_creates_no_candidate(self):
        self.assertEqual(update.policy(self.state)['mode'], 'ask')
        with self.assertRaisesRegex(update.UpdateError, 'CONSENT'):
            self.prepare()
        self.assertFalse(self.state.exists())

    def test_opt_in_requires_explicit_consent_and_revocation_persists(self):
        with self.assertRaisesRegex(update.UpdateError, 'CONSENT'):
            update.set_policy(self.state, 'auto')
        update.set_policy(self.state, 'auto', user_consent=True)
        self.assertEqual(update.policy(self.state)['mode'], 'auto')
        update.set_policy(self.state, 'ask')
        with self.assertRaisesRegex(update.UpdateError, 'CONSENT'):
            self.prepare()

    def test_missing_trust_blocks_without_creating_replacement(self):
        self.trust.unlink()
        with self.assertRaisesRegex(update.UpdateError, 'TRUST_NOT_CONFIGURED'):
            self.prepare(user_approved=True)
        self.assertFalse(self.trust.exists())
        self.assertFalse(self.state.exists())

    def test_explicit_update_prepares_but_never_executes_installer(self):
        with mock.patch.object(update, 'verify_windows_signature') as verify:
            pending = self.prepare(user_approved=True)
        verify.assert_called_once()
        self.assertEqual(pending['state'], 'AWAITING_RESTART_CONSENT')
        self.assertEqual((self.state / pending['artifact']).read_bytes(), self.artifact.read_bytes())

    def test_signature_tampering_is_rejected(self):
        value = json.loads(self.manifest.read_bytes())
        value['productVersion'] = '0.4.6'
        self.manifest.write_bytes(update.canonical(value))
        with self.assertRaisesRegex(update.UpdateError, 'SIGNATURE'):
            self.prepare(user_approved=True)
        self.assertFalse(self.state.exists())

    def test_restart_revalidates_payload_and_requires_new_consent(self):
        with mock.patch.object(update, 'verify_windows_signature'):
            pending = self.prepare(user_approved=True)
            with self.assertRaisesRegex(update.UpdateError, 'RESTART_CONSENT'):
                update.verify_pending(self.state, self.trust, current_version='0.4.4')
            candidate = update.verify_pending(self.state, self.trust, current_version='0.4.4', user_approved=True)
            self.assertEqual(candidate.name, pending['artifact'])
            candidate.write_bytes(b'corrupt')
            with self.assertRaisesRegex(update.UpdateError, 'HASH'):
                update.verify_pending(self.state, self.trust, current_version='0.4.4', user_approved=True)

    def test_pending_record_cannot_authorize_another_installer(self):
        with mock.patch.object(update, 'verify_windows_signature'):
            pending = self.prepare(user_approved=True)
            for name in ('../escape.exe', 'GrangerSetup.exe'):
                changed = dict(pending, artifact=name)
                (self.state / 'pending.json').write_bytes(update.canonical(changed))
                with self.assertRaisesRegex(update.UpdateError, 'INVALID_PENDING'):
                    update.verify_pending(self.state, self.trust, current_version='0.4.4', user_approved=True)

    def test_changed_high_water_blocks_restart_without_changing_last_good(self):
        installed = self.root / 'last-known-good.exe'
        installed.write_bytes(b'last known good')
        with mock.patch.object(update, 'verify_windows_signature'):
            self.prepare(user_approved=True)
            (self.state / 'high-water.json').write_text('{}')
            with self.assertRaisesRegex(update.UpdateError, 'STATE_MISMATCH'):
                update.verify_pending(self.state, self.trust, current_version='0.4.4', user_approved=True)
        self.assertEqual(installed.read_bytes(), b'last known good')

    @unittest.skipUnless(os.name == 'nt', 'Windows file sharing semantics')
    def test_final_verification_lock_rejects_artifact_mutation(self):
        with update._locked_windows_artifact(self.artifact):
            with self.assertRaises(OSError):
                self.artifact.write_bytes(b'changed')

    def test_metadata_rejections(self):
        cases = ({'platform': 'linux-x64'}, {'productVersion': '0.4.3'}, {'artifact': '../GrangerSetup.exe'},
                 {'issuedAt': self.now + 60}, {'expiresAt': self.now - 1}, {'sequence': True},
                 {'windowsCertificateSha1': 'b' * 40}, {'size': 2**32})
        original = self.value.copy()
        for changes in cases:
            with self.subTest(changes=changes):
                self.value = original.copy()
                self.sign(**changes)
                with self.assertRaises(update.UpdateError):
                    self.prepare(user_approved=True)
        self.assertFalse(self.state.exists())

    def test_corrupt_artifact_and_invalid_authenticode_do_not_activate(self):
        original = self.artifact.read_bytes()
        self.artifact.write_bytes(b'broken')
        with self.assertRaisesRegex(update.UpdateError, 'HASH'):
            self.prepare(user_approved=True)
        self.artifact.write_bytes(original)
        with mock.patch.object(update, 'verify_windows_signature', side_effect=update.UpdateError('untrusted')):
            with self.assertRaisesRegex(update.UpdateError, 'untrusted'):
                self.prepare(user_approved=True)
        self.assertFalse((self.state / 'pending.json').exists())
        self.assertFalse((self.state / 'high-water.json').exists())
        self.assertFalse(list(self.state.glob('.candidate-*')))

    def test_rollback_and_equivocation_preserve_high_water(self):
        with mock.patch.object(update, 'verify_windows_signature'):
            self.sign(sequence=2)
            self.prepare(user_approved=True)
            previous = (self.state / 'high-water.json').read_bytes()
            for changes in ({'sequence': 1}, {'sequence': 2, 'releaseNotes': 'different'}):
                self.sign(**changes)
                with self.assertRaisesRegex(update.UpdateError, 'ROLLBACK_OR_EQUIVOCATION'):
                    self.prepare(user_approved=True)
            self.assertEqual(previous, (self.state / 'high-water.json').read_bytes())

    def test_revocation_during_preparation_cancels_activation(self):
        update.set_policy(self.state, 'auto', user_consent=True)
        with mock.patch.object(update, 'verify_windows_signature', side_effect=lambda *_: update.set_policy(self.state, 'ask')):
            with self.assertRaisesRegex(update.UpdateError, 'CONSENT_OR_TRUST_CHANGED'):
                self.prepare()
        self.assertFalse((self.state / 'pending.json').exists())

    def test_signed_manifest_replacement_during_verification_is_rejected(self):
        with mock.patch.object(update, 'verify_windows_signature', side_effect=lambda *_: self.sign(sequence=2)):
            with self.assertRaisesRegex(update.UpdateError, 'MANIFEST_CHANGED'):
                self.prepare(user_approved=True)
        self.assertFalse((self.state / 'pending.json').exists())

    def test_interrupted_activation_can_retry_exact_generation(self):
        atomic = update._atomic
        def crash(path, content):
            if path.name == 'pending.json':
                raise OSError('injected interruption')
            return atomic(path, content)
        with mock.patch.object(update, 'verify_windows_signature'):
            with mock.patch.object(update, '_atomic', side_effect=crash):
                with self.assertRaises(OSError):
                    self.prepare(user_approved=True)
            self.assertTrue((self.state / 'high-water.json').exists())
            self.assertFalse((self.state / 'pending.json').exists())
            self.assertEqual(self.prepare(user_approved=True)['sequence'], 1)

    def test_duplicate_and_oversized_metadata(self):
        for content in (b'{"version":1,"version":1}', b' ' * (update.MAX_MANIFEST + 1), b'[' * 2000):
            self.manifest.write_bytes(content)
            with self.assertRaises(update.UpdateError):
                self.prepare(user_approved=True)

    def test_network_path_rejected_before_any_filesystem_read(self):
        with mock.patch.object(Path, 'open', side_effect=AssertionError('must not access remote path')):
            with self.assertRaisesRegex(update.UpdateError, 'NETWORK_FILESYSTEM'):
                update.prepare(Path('//server/share/state'), self.manifest, self.artifact, self.trust,
                               current_version='0.4.4', user_approved=True)

    def test_candidate_count_is_bounded(self):
        with mock.patch.object(update, 'verify_windows_signature'):
            self.prepare(user_approved=True)
            self.sign(sequence=2, productVersion='0.4.6')
            self.prepare(user_approved=True)
            self.sign(sequence=3, productVersion='0.4.7')
            with self.assertRaisesRegex(update.UpdateError, 'LIMIT'):
                self.prepare(user_approved=True)

    @unittest.skipUnless(os.name == 'nt', 'Windows trust API')
    def test_windows_loader_trust_rejects_unsigned_payload_offline(self):
        with self.assertRaisesRegex(update.UpdateError, 'WINDOWS_TRUST'):
            update.verify_windows_signature(self.artifact, 'a' * 40)


if __name__ == '__main__':
    unittest.main()
