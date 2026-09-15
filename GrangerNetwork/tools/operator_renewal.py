#!/usr/bin/env python3
"""Operator-side signed generation renewal; never installs authority keys on peers."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time

TOOLS_ROOT = Path(__file__).resolve().parent
if str(TOOLS_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLS_ROOT))
import operator_bundle
from granger_network._codec import atomic_write_text, encode_base64url
from granger_network.bootstrap import BootstrapSet, DEFAULT_NETWORK_ID, DEFAULT_PROTOCOL_VERSION
from granger_network.errors import GrangerNetworkError
from granger_network.identity import ServiceIdentity
from granger_network.peer import NodeDescriptor
from granger_network.wan_config import _ProvisionLock, load_authority_pin, load_browser_wan_config
from granger_network.wan_config_recovery import WanConfigRecovery, export_public_config

PUBLIC_FILES = ('browser-wan.json', 'bootstrap-set.json', 'bootstrap-authority.pin', 'config-authority.pin')
MAX_CONTROL_BYTES = 256 * 1024
FLEET_HEALTH_TIMEOUT_SECONDS = 240


class RenewalError(ValueError):
    """Only a fixed error category is emitted by the CLI."""


def _document(path):
    path = Path(path)
    if path.is_symlink() or path.stat().st_size > MAX_CONTROL_BYTES:
        raise RenewalError('UNSAFE_CONTROL_FILE')
    return json.loads(path.read_text(encoding='utf-8'))


def _write(path, document):
    atomic_write_text(path, json.dumps(document, sort_keys=True, separators=(',', ':')) + '\n', mode=0o600)


def _same_policy(left, right):
    return all(getattr(left, name) == getattr(right, name) for name in (
        'network_id', 'protocol_version', 'route_attempts', 'replication_factor', 'minimum_replicas', 'timeout'))


class Coordinator:
    def __init__(self, options, transport, *, clock=time.time):
        self.options = options
        self.transport = transport
        self.clock = clock
        self.root = Path(options['operatorRoot']).resolve()
        self.store = self.root / 'public-bundles'
        self.private = self.root / 'private'
        self.trust = self.root / 'public-trust'
        self.state_path = self.root / 'renewal-state.json'
        self.nodes = options['nodes']
        if len(self.nodes) != 4 or len({n['nodeId'] for n in self.nodes}) != 4:
            raise RenewalError('FLEET_IDENTITY_SET_INVALID')
        if len({n['name'] for n in self.nodes}) != 4:
            raise RenewalError('FLEET_NAME_SET_INVALID')
        if any(not re.fullmatch(r'node-[a-z0-9]{1,16}', n['name']) for n in self.nodes):
            raise RenewalError('NODE_NAME_INVALID')
        initial = options['initialGeneration']
        if type(initial) is not int or initial < 1:
            raise RenewalError('INITIAL_GENERATION_INVALID')
        self.initial = self.bundle(initial, historical=True)
        if self.initial[0].generation != initial:
            raise RenewalError('INITIAL_GENERATION_INVALID')
        self.state = None

    def path(self, generation):
        return self.store / f'generation{generation}'

    def bundle(self, generation, *, historical=False):
        root = self.path(generation)
        operator_bundle._separate_roots(self.private, root)
        for name in PUBLIC_FILES:
            path = root / name
            if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_CONTROL_BYTES:
                raise RenewalError('UNSAFE_PUBLIC_BUNDLE')
        for name in ('config-authority.pin', 'bootstrap-authority.pin'):
            if load_authority_pin(root / name) != load_authority_pin(self.trust / name):
                raise RenewalError('AUTHORITY_PIN_MISMATCH')
        at = _document(root / 'browser-wan.json')['issuedAt'] if historical else int(self.clock())
        config = load_browser_wan_config(root / 'browser-wan.json',
            trust_anchor_path=self.trust / 'config-authority.pin', now=at, allow_legacy=False)
        peers = BootstrapSet.from_json(config.bootstrap_path.read_text(encoding='utf-8'),
            load_authority_pin(self.trust / 'bootstrap-authority.pin'), now=at,
            expected_network_id=DEFAULT_NETWORK_ID, expected_protocol_version=DEFAULT_PROTOCOL_VERSION)
        if config.generation != generation or {p.node_id for p in peers.peers} != {n['nodeId'] for n in self.nodes}:
            raise RenewalError('FLEET_IDENTITY_SET_CHANGED')
        if hasattr(self, 'initial') and not _same_policy(config, self.initial[0]):
            raise RenewalError('SIGNED_POLICY_CHANGED')
        return config, peers

    def authorities(self):
        # Existing identity loading is confined to the trusted coordinator process.
        for name in ('bootstrap-authority', 'config-authority'):
            path = self.private / (name + '.json')
            if not path.is_file() or path.is_symlink():
                raise RenewalError('AUTHORITY_UNAVAILABLE')
            identity = ServiceIdentity.load(path)
            if identity.public_key_bytes != load_authority_pin(self.trust / (name + '.pin')):
                raise RenewalError('AUTHORITY_PIN_MISMATCH')

    def save(self):
        _write(self.state_path, self.state)

    def load_state(self):
        if self.state_path.exists():
            self.state = _document(self.state_path)
            if (self.state.get('version') != 1 or type(self.state.get('currentGeneration')) is not int
                    or self.state['currentGeneration'] < self.initial[0].generation):
                raise RenewalError('COORDINATOR_STATE_INVALID')
            tip, _ = self.bundle(self.state['currentGeneration'], historical=True)
            if tip.sha256 != self.state.get('currentSha256'):
                raise RenewalError('GENERATION_EQUIVOCATION')
        else:
            tip = self.initial[0]
            self.state = dict(version=1, currentGeneration=tip.generation, currentSha256=tip.sha256,
                complete=True, fleet={}, failures=0, nextRetry=0, jitter=secrets.randbelow(301),
                lastRenewalAttempt=None, lastRenewalResult='INITIALIZED')
        self.state['currentExpiresAt'] = tip.expires_at
        window = min(21600, max(600, (tip.expires_at - tip.issued_at) // 3))
        self.state['renewalWindowStart'] = tip.expires_at - window - self.state['jitter']
        return tip

    def collect(self, tip):
        reports = {}
        now = int(self.clock())
        for node in self.nodes:
            report = self.transport.collect(node)
            peer = NodeDescriptor.from_json(json.dumps(report['descriptor']), now=now,
                expected_network_id=DEFAULT_NETWORK_ID, expected_protocol_version=DEFAULT_PROTOCOL_VERSION)
            if peer.node_id != node['nodeId']:
                raise RenewalError('NODE_IDENTITY_MISMATCH')
            if report['generation'] > tip.generation + 1:
                raise RenewalError('UNEXPECTED_FLEET_GENERATION')
            known, _ = self.bundle(report['generation'], historical=True)
            if known.sha256 != report['configSha256']:
                raise RenewalError('GENERATION_EQUIVOCATION')
            if report.get('state') != 'RUNNING':
                raise RenewalError('NODE_NOT_RUNNING')
            reports[node['name']] = (report, peer)
        return reports

    def _adopt(self, config):
        self.state.update(currentGeneration=config.generation, currentSha256=config.sha256,
            currentExpiresAt=config.expires_at, complete=False, fleet={}, nextGeneration=config.generation,
            lastRenewalResult='SIGNED_PENDING_DEPLOYMENT')
        self.save()

    def run_once(self):
        # The OS releases this same-inode lease after crash/reboot; no PID/age lock stealing.
        with _ProvisionLock(self.root / 'renewal.lock', timeout=0):
            tip = self.load_state()
            now = int(self.clock())
            if now < self.state.get('nextRetry', 0):
                return self.state
            self.state['lastRenewalAttempt'] = now
            try:
                next_path = self.path(tip.generation + 1)
                due = now >= self.state['renewalWindowStart']
                if not due and self.state['complete'] and not next_path.exists():
                    self.state.update(lastRenewalResult='NOT_DUE', nextRetry=self.state['renewalWindowStart'])
                    self.save()
                    return self.state
                reports = self.collect(tip)
                self.authorities()
                if next_path.exists():
                    # Signing may have completed immediately before coordinator death.
                    # Reuse exact signed bytes, never sign competing content for this number.
                    next_config, _ = self.bundle(tip.generation + 1, historical=True)
                    self._adopt(next_config)
                    tip = next_config
                if (self.state['complete'] and due) or tip.expires_at <= now:
                    with tempfile.TemporaryDirectory(prefix='.renew-descriptors-', dir=self.root) as temporary:
                        paths = []
                        for name, (_, peer) in reports.items():
                            path = Path(temporary) / (name + '.json')
                            atomic_write_text(path, peer.to_json(), mode=0o600)
                            paths.append(path)
                        lifetime = min(24 * 3600, min(peer.expires_at for _, peer in reports.values()) - now - 30)
                        if lifetime < 6 * 3600:
                            raise RenewalError('FRESH_DESCRIPTORS_NOT_READY')
                        operator_bundle.renew_bundle(argparse.Namespace(private_root=self.private,
                            previous_public_root=self.path(tip.generation), public_root=self.path(tip.generation + 1),
                            descriptor=paths, lifetime=lifetime))
                    next_config, _ = self.bundle(tip.generation + 1)
                    self._adopt(next_config)
                    tip = next_config
                self.bundle(tip.generation)  # Current validity required for publication.
                for node in self.nodes:
                    name = node['name']
                    self.transport.deploy(node, self.path(tip.generation), tip)
                    self.state['fleet'][name] = 'DEPLOYED'
                    self.save()
                # Re-query all peers, including successful peers from a previous interrupted run.
                for node in self.nodes:
                    self.transport.verify(node, self.path(tip.generation), tip)
                    self.state['fleet'][node['name']] = 'VERIFIED'
                    self.save()
                self.state.update(complete=True, failures=0, lastRenewalResult='PASS', nextGeneration=None,
                    renewalWindowStart=tip.expires_at - min(21600, max(600, (tip.expires_at-tip.issued_at)//3))
                        - self.state['jitter'])
                self.state['nextRetry'] = self.state['renewalWindowStart']
                self.save()
            except (GrangerNetworkError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                failures = min(8, self.state.get('failures', 0) + 1)
                delay = min(1800, 30 * 2 ** (failures - 1))
                self.state.update(failures=failures,
                    nextRetry=now + delay + secrets.randbelow(max(1, delay // 5)),
                    lastRenewalResult=str(error) if isinstance(error, RenewalError) else type(error).__name__)
                self.save()
            return self.state


class SshFleet:
    def __init__(self, options):
        self.options = options
        self.root = Path(options['operatorRoot']).resolve()
        self.ssh = Path(options['sshExecutable'])
        self.key = Path(options['sshIdentity'])  # Path only; OpenSSH alone reads the key.
        for node in options['nodes']:
            ipaddress.ip_address(node['host'])
            if not re.fullmatch(r'node-[a-z0-9]{1,16}', node['name']):
                raise RenewalError('NODE_NAME_INVALID')
        self.remote_source = Path(__file__).with_name('operator_publication.py').read_text(encoding='utf-8')

    def _run(self, node, request):
        program = self.remote_source + '\nprint(json.dumps(handle(json.loads(' + repr(json.dumps(request)) + '))))\n'
        command = [str(self.ssh), '-i', str(self.key), '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=8', '-o', 'ServerAliveInterval=10',
            '-o', 'ServerAliveCountMax=2', 'root@' + node['host'],
            '/opt/granger-node/runtime/venv/bin/python3 -I -B -']
        # Public control documents only; no shell interpolation from a network descriptor.
        result = subprocess.run(command, input=program, text=True, capture_output=True, timeout=40)
        if result.returncode or len(result.stdout) > MAX_CONTROL_BYTES:
            raise RenewalError('SSH_CONTROL_FAILED')
        response = json.loads(result.stdout)
        if not response.get('ok'):
            raise RenewalError('REMOTE_' + response.get('category', 'CONTROL_REJECTED'))
        return response

    def _request(self, node, operation):
        return dict(operation=operation, node=node['name'], nodeId=node['nodeId'], pins={
            name: encode_base64url(load_authority_pin(self.root / 'public-trust' / name))
            for name in ('bootstrap-authority.pin', 'config-authority.pin')})

    def collect(self, node):
        return self._run(node, self._request(node, 'collect'))

    def deploy(self, node, root, config):
        request = self._request(node, 'deploy')
        request.update(generation=config.generation, configSha256=config.sha256,
            files={name: encode_base64url((root / name).read_bytes()) for name in PUBLIC_FILES})
        self._run(node, request)

    def verify(self, node, root, config):
        end = time.monotonic() + FLEET_HEALTH_TIMEOUT_SECONDS
        report = None
        while time.monotonic() < end:
            report = self.collect(node)
            network = report.get('network', {})
            authenticated_peers = network.get('authenticatedPeers')
            if (report.get('state') == 'RUNNING' and report['nodeId'] == node['nodeId']
                    and report['generation'] == config.generation and report['configSha256'] == config.sha256
                    and type(authenticated_peers) is int and authenticated_peers >= 4
                    and network.get('dhtReady') is True
                    and network.get('state') == 'CONNECTED'):
                break
            time.sleep(5)
        else:
            raise RenewalError('FLEET_HEALTH_NOT_READY')
        peer = NodeDescriptor.from_json(json.dumps(report['descriptor']))
        from granger_network.peer_rpc import ConfigRecoveryContact
        contact = ConfigRecoveryContact(peer.identity_public_key, peer.endpoint, peer.network_id,
                                        peer.protocol_version, peer.issued_at)
        with tempfile.TemporaryDirectory(prefix='.renew-fetch-', dir=self.root) as directory:
            recovery = WanConfigRecovery(root / 'browser-wan.json', self.root / 'public-trust/config-authority.pin',
                Path(directory) / 'installed', Path(directory) / 'rollback.json')
            # Exercise the browser's real wire-v3 fetch, signature, hash and activation pipeline.
            recovery.contacts = lambda **_: (contact,)
            fetched = recovery.refresh(ServiceIdentity.generate())
            if fetched is None or hashlib.sha256(fetched.read_bytes()).hexdigest() != config.sha256:
                raise RenewalError('BROWSER_CONFIG_FETCH_FAILED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--watch', action='store_true', help='Run on the trusted operator machine until interrupted')
    options = parser.parse_args()
    try:
        config = _document(options.config)
        coordinator = Coordinator(config, SshFleet(config))
    except (GrangerNetworkError, OSError, ValueError, KeyError) as error:
        print(json.dumps({'ok': False, 'category': type(error).__name__}), flush=True)
        return 2
    while True:
        try:
            state = coordinator.run_once()
            print(json.dumps(state, sort_keys=True), flush=True)
            if not options.watch:
                return 0 if state['lastRenewalResult'] in ('PASS', 'NOT_DUE') else 2
            time.sleep(max(5, min(300, state['nextRetry'] - time.time())))
        except KeyboardInterrupt:
            return 0
        except (GrangerNetworkError, OSError, ValueError) as error:
            print(json.dumps({'ok': False, 'category': type(error).__name__}), flush=True)
            return 2


if __name__ == '__main__':
    raise SystemExit(main())
