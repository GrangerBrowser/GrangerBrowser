"""Public-only fleet control, executed by the operator through authenticated SSH.

No authority or node private identity is loaded by this tool. Runtime, systemd,
firewall and persistent peer state are never replaced by a publication update.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time

sys.path.insert(0, '/opt/granger-node/runtime/src')
from granger_network._codec import atomic_write_bytes, decode_base64url
from granger_network.bootstrap import BootstrapSet, DEFAULT_NETWORK_ID, DEFAULT_PROTOCOL_VERSION
from granger_network.peer import NodeDescriptor
from granger_network.wan_config import _ProvisionLock, load_authority_pin, load_browser_wan_config
from granger_network.wan_config_recovery import export_public_config

FILES = frozenset({'browser-wan.json', 'bootstrap-set.json', 'bootstrap-authority.pin', 'config-authority.pin'})


def _load(path):
    if path.is_symlink() or path.stat().st_size > 256 * 1024:
        raise ValueError('control file bounds')
    return json.loads(path.read_text(encoding='utf-8'))


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _exchange(left, right):
    # Linux RENAME_EXCHANGE swaps two nonempty directories atomically on one filesystem.
    # If unavailable, refuse deployment rather than expose a half-written bundle.
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(left), -100, os.fsencode(right), 2) != 0:
        raise OSError(ctypes.get_errno(), 'atomic public exchange failed')
    _sync_directory(right.parent)


def _pins(root, expected):
    for name in ('bootstrap-authority.pin', 'config-authority.pin'):
        if load_authority_pin(root / name) != decode_base64url(expected[name]):
            raise ValueError('public trust mismatch')


def handle(request):
    try:
        return _handle(request)
    except Exception as error:
        # No stderr traceback, raw errors, shell output or private paths cross the control channel.
        return {'ok': False, 'category': type(error).__name__}


def _handle(request):
    node = request['node']
    if not isinstance(node, str) or not re.fullmatch(r'node-[a-z0-9]{1,16}', node):
        raise ValueError('node name')
    state = Path('/var/lib/granger-node') / node
    status_path = Path('/run/granger-node') / node / 'status.json'
    public = Path('/etc/granger-node/public-bootstrap')
    if not public.is_dir() or public.is_symlink():
        raise ValueError('public root type')
    _pins(public, request['pins'])
    descriptor = NodeDescriptor.from_json((state / 'node-descriptor.json').read_text(encoding='utf-8'),
        expected_network_id=DEFAULT_NETWORK_ID, expected_protocol_version=DEFAULT_PROTOCOL_VERSION)
    if descriptor.node_id != request['nodeId']:
        raise ValueError('node identity')
    old_document = _load(public / 'browser-wan.json')
    old = load_browser_wan_config(public / 'browser-wan.json', trust_anchor_path=public / 'config-authority.pin',
        now=old_document['issuedAt'], allow_legacy=False)
    if request['operation'] == 'collect':
        status = _load(status_path)
        if (status.get('nodeId') != descriptor.node_id or
                not 0 <= time.time() - status_path.stat().st_mtime <= 30):
            raise ValueError('stale status or wrong process')
        network = status.get('network', {})
        return dict(ok=True, nodeId=descriptor.node_id, descriptor=json.loads(descriptor.to_json()),
            generation=old.generation, configSha256=old.sha256, state=status.get('state'), network={
                key: network.get(key) for key in ('state', 'authenticatedPeers', 'dhtReady')})
    if request['operation'] != 'deploy' or set(request['files']) != FILES:
        raise ValueError('unsupported operation')
    if type(request['generation']) is not int or request['generation'] < old.generation:
        raise ValueError('generation rollback')
    if request['generation'] == old.generation:
        if request['configSha256'] != old.sha256:
            raise ValueError('generation equivocation')
        export_public_config(public / 'browser-wan.json', public / 'config-authority.pin')
        return dict(ok=True, generation=old.generation, reused=True)
    decoded = {name: decode_base64url(data) for name, data in request['files'].items()}
    if any(len(data) > 256 * 1024 or b'privateKey' in data for data in decoded.values()):
        raise ValueError('public member bounds')
    if hashlib.sha256(decoded['browser-wan.json']).hexdigest() != request['configSha256']:
        raise ValueError('public digest')
    # Stable lock inode survives exchange and process death. No node process is stopped.
    with _ProvisionLock(public.parent / '.publication.lock', timeout=0):
        with tempfile.TemporaryDirectory(prefix='.public-staged-', dir=public.parent) as temporary:
            staged = Path(temporary) / 'bundle'
            staged.mkdir(mode=0o750)
            ownership = public.stat()
            os.chown(staged, ownership.st_uid, ownership.st_gid)
            for name, data in decoded.items():
                atomic_write_bytes(staged / name, data, mode=0o640)
                os.chown(staged / name, ownership.st_uid, ownership.st_gid)
            _pins(staged, request['pins'])
            new = load_browser_wan_config(staged / 'browser-wan.json',
                trust_anchor_path=public / 'config-authority.pin', allow_legacy=False)
            export_public_config(staged / 'browser-wan.json', public / 'config-authority.pin')
            previous_peers = BootstrapSet.from_json(old.bootstrap_path.read_text(encoding='utf-8'),
                load_authority_pin(public / 'bootstrap-authority.pin'), now=old.issued_at)
            next_peers = BootstrapSet.from_json(new.bootstrap_path.read_text(encoding='utf-8'),
                load_authority_pin(public / 'bootstrap-authority.pin'))
            if ({p.node_id for p in previous_peers.peers} != {p.node_id for p in next_peers.peers}
                    or new.generation != request['generation'] or new.sha256 != request['configSha256']
                    or new.expires_at - time.time() < 60
                    or any(getattr(new, k) != getattr(old, k) for k in (
                        'network_id', 'protocol_version', 'route_attempts', 'replication_factor',
                        'minimum_replicas', 'timeout'))):
                raise ValueError('identity, generation or policy changed')
            # Re-read under lease: a concurrent publisher may have advanced while validating.
            current = _load(public / 'browser-wan.json')
            if current['generation'] != old.generation or hashlib.sha256(
                    (public / 'browser-wan.json').read_bytes()).hexdigest() != old.sha256:
                raise ValueError('concurrent publication changed')
            _sync_directory(staged)
            _exchange(staged, public)
    return dict(ok=True, generation=new.generation, reused=False)
