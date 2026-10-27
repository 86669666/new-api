#!/usr/bin/env python3
"""Build once, then schedule Go tests across trusted required resource tiers.

The default retains every root (except the embed-only main), relaykit and
tokenkit package. Required PG tests run in fixed isolated resource tiers;
optional external-engine matrices are not represented as a three-DB pass.
No database history is authored here: only the same-source gateway CLI seals.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time

# Installed-controller injection point, not a candidate CLI/environment option.
# The outer controller owns producer isolation and returns a completed named
# namespace. The constrained PG tier must use a root-authenticated proxy to it;
# it must never acquire a Docker socket or create nested namespaces.
OUTER_BIRTH = None


class OuterBirthControlClient:
    """Root-only constrained-controller transport; never exposed to test UID997.

    The outer launcher must mount its control directory read-only at the fixed
    path below and supply the root-custodied descriptor. This class does not
    activate a hook, register a runner or create any namespaces/containers.
    """
    def __init__(self, attempt):
        if os.geteuid() != 0 or not re.fullmatch('[a-zA-Z0-9_-]{1,80}', attempt):
            raise ValueError('root controller required')
        directory = Path('/run/newapi-formal-control')
        descriptor = directory / 'control.json'
        for path in (descriptor, *descriptor.parents):
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('outer control custody mismatch')
        info = descriptor.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 4096 or info.st_mode & 0o077:
            raise ValueError('invalid outer control descriptor')
        value = json.loads(descriptor.read_text())
        if (set(value) != {'attempt', 'socket_device', 'socket_inode', 'nonce'} or value['attempt'] != attempt or
                not re.fullmatch('[0-9a-f]{64}', value['nonce'])):
            raise ValueError('outer control descriptor mismatch')
        endpoint = directory / 'control.sock'
        info = endpoint.lstat()
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or
                (info.st_dev, info.st_ino) != (value['socket_device'], value['socket_inode'])):
            raise ValueError('outer control socket replaced')
        self.attempt_id, self.nonce = attempt, value['nonce']
        self.sequence, self.failed = 0, False
        self.lock = threading.Lock()
        self.connection = socket.socket(socket.AF_UNIX)
        self.connection.settimeout(240)
        try:
            self.connection.connect(str(endpoint))
            _, uid, gid = struct.unpack('3i', self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if (uid, gid) != (0, 0):
                raise ValueError('outer server is not root')
            self.reader = self.connection.makefile('rb')
        except BaseException:
            self.connection.close()
            raise

    def close(self):
        self.failed = True
        self.reader.close()
        self.connection.close()

    def request(self, operation, engine, purpose):
        with self.lock:
            if self.failed:
                raise ValueError('outer control connection closed; no retry')
            try:
                message = dict(attempt=self.attempt_id, nonce=self.nonce, sequence=self.sequence,
                               operation=operation, engine=engine, purpose=purpose)
                self.connection.sendall(json.dumps(message, separators=(',', ':')).encode() + b'\n')
                line = self.reader.readline(65537)
                if not line.endswith(b'\n') or len(line) > 65536:
                    raise ValueError('invalid outer control frame')
                reply = json.loads(line)
                if (type(reply) is not dict or set(reply) != {'sequence', 'result'} or
                        type(reply['sequence']) is not int or reply['sequence'] != self.sequence):
                    raise ValueError('outer control sequence or result mismatch')
                self.sequence += 1
                return reply['result']
            except BaseException:
                # An interrupted birth is ambiguous. Never reconnect/retry or
                # fall back to executing a candidate producer as root.
                self.close()
                raise

    def __call__(self, engine, purpose):
        return self.request('birth', engine, purpose)

    def verify_daemon(self, engine, daemon):
        if daemon is None:
            raise ValueError('same owned daemon required')
        observed = daemon.verify()
        binding = hashlib.sha256(json.dumps(observed, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        remote = self.request('verify-daemon', engine, '')
        if remote != {'binding': binding}:
            self.close()
            raise ValueError('outer and service daemon observations differ')


def outer_birth(engine, purpose, daemon=None):
    if OUTER_BIRTH is None:
        return None
    allowed = {'installer': ('sqlite',), 'postgres': ('postgres',),
               'admission': ('sqlite',), 'wallet': ('sqlite', 'postgres', 'mysql')}
    if os.geteuid() != 0 or engine not in allowed.get(purpose, ()):
        raise ValueError('unadmitted outer birth operation')
    # Only names cross the operation boundary: never commands, credentials,
    # target paths or producer-supplied database observations.
    if engine != 'sqlite':
        OUTER_BIRTH.verify_daemon(engine, daemon)
    result = OUTER_BIRTH(engine, purpose)
    if (type(result) is not dict or set(result) != {'id', 'engine', 'target', 'journal', 'output_sha256'} or
            result['engine'] != engine or not re.fullmatch('[0-9a-f]{32}', result['id']) or
            not re.fullmatch('[0-9a-f]{64}', result['output_sha256'])):
        raise ValueError('invalid completed outer birth')
    attempt = OUTER_BIRTH.attempt_id
    if not re.fullmatch('[a-zA-Z0-9_-]{1,80}', attempt):
        raise ValueError('invalid outer attempt')
    publication = Path('/opt/newapi-box-formal/work') / attempt
    target, journal = Path(result['target']), Path(result['journal'])
    if journal != publication / 'journals' / (result['id'] + '.json'):
        raise ValueError('invalid outer journal path')
    if engine == 'sqlite':
        if target != publication / ('birth-' + result['id']) / 'new.db':
            raise ValueError('invalid outer SQLite path')
    elif result['target'] != 'birth_' + result['id']:
        raise ValueError('outer SQL namespace mismatch')
    # Root publication is checked independently of the transport response. The
    # broker must mount this exact sealed journal read-only before returning.
    for path in (journal, *journal.parents):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('outer journal custody mismatch')
    state = json.loads(journal.read_text())
    if state['phase'] != 'READY' or state['engine'] != engine or state['target'] != result['target']:
        raise ValueError('outer birth not published READY')
    return result


DIALECT_TESTS = {
    'service': ('TestOAuthDerivedTextRawUsageRejection', 'TestOAuthDerivedTransportDatabaseCASWire'),
    'controller': ('TestOAuthDerivedSelectedHTTP',),
}
PRODUCER_TEST = 'TestOAuthBootstrapProducer'
PG_IMAGE = 'sha256:85b1ab67e7c7410b11da3f5b42913fc51b5b46f9cf5f07cc28a98e5f62083c5e'
PG_SELECTOR = '^TestSessionRevocationS1Namespace$'
JOINT_IMAGE = 'sha256:85b1ab67e7c7410b11da3f5b42913fc51b5b46f9cf5f07cc28a98e5f62083c5e'
JOINT_SELECTOR = '^TestSessionRevocationS1RealRedis$'
MYSQL_IMAGE = 'sha256:d78bbb8f2cfdeb362aff7fcbea6b7954bef6429bef26b308f0e65ca5d9410482'
# Same MySQL base plus signed, pinned Redis runtime closure; lifecycle alone requires both.
LIFECYCLE_MYSQL_IMAGE = 'sha256:d78bbb8f2cfdeb362aff7fcbea6b7954bef6429bef26b308f0e65ca5d9410482'
WALLET_TESTS = ('TestBillingSessionSQLAdmission', 'TestBillingLegacySQLRegressions')
WALLET_ENGINES = ('sqlite', 'mysql', 'postgres')
WALLET_SCENARIOS = ('arrears_retry', 'arrears_retry_held', 'arrears_retry_claimed', 'arrears_settle', 'held_refund', 'image_available', 'search_available', 'zero_held', 'trusted_held', 'task_zero_held', 'task_trusted_held')

def wallet_selector(engine):
    if engine not in WALLET_ENGINES:
        raise ValueError('unknown wallet engine')
    return '^(' + '|'.join(WALLET_TESTS) + ')$/^' + engine + '$'

METADATA_SELECTOR = '^TestOAuthTokensConsumerHTTP$'
METADATA_CASES = ('bridge_only_rejected', 'empty_current_grant_no_writes', 'wrong_client', 'wrong_actor', 'wrong_audience', 'wrong_issuer', 'refresh_bearer', 'expired', 'future', 'write_scope_not_supported', 'old_grant_missing_read_scope', 'post_encoding_revocation_discards_empty_success', 'missing_store_is_not_empty')
METADATA_TIERS = tuple('metadata-'+e for e in WALLET_ENGINES)
ORDINARY_AUDIT_SELECTOR = '^TestOAuthTokensConsumerHTTP$/^ordinary_key_creation$'
LIFECYCLE_SELECTOR = '^TestOAuthDerivedTokenOwnerLifecycle$'
LIFECYCLE_CASES = ('owner_reveal_and_mutation', 'revoke_and_rollback', 'disable_delete_rollback',
                   'unknown_is_not_manual', 'same_user_creation_limit', 'registration_default_token',
                   'historical_finalize_after_revoke', 'real_redis', 'create_revoke_order')
LIFECYCLE_TIERS = tuple('lifecycle-'+e for e in WALLET_ENGINES)


JOINT_CASES = ('nonempty_source_restricted_rollback', 'deny_wrong_type', 'outbox_rollback', 'late_active_fill', 'credential_rollback')


def digest(path):
    with open(path, 'rb') as stream:
        result = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
        return result.hexdigest()


def command(argv, **kwargs):
    subprocess.run(argv, check=True, **kwargs)


def prepare(args):
    if args.tier == "admission":
        return prepare_admission(args)
    if sys.platform != 'linux':
        raise ValueError('trusted provenance test runner requires Linux')
    if args.tier == 'all' and (args.package or args.run != '.'):
        raise ValueError('bounded selectors require an explicit resource --tier')
    if args.tier == 'ordinary-audit' or args.tier in ORDINARY_AUDIT_SHARED:
        if args.package not in (None, ['./router']) or args.run not in ('.', ORDINARY_AUDIT_SELECTOR):
            raise ValueError('ordinary audit tier requires its exact OAuth route inventory')
        args.package, args.run = ['./router'], ORDINARY_AUDIT_SELECTOR
    if args.tier in LIFECYCLE_TIERS:
        if args.package not in (None, ['./controller']) or args.run not in ('.', LIFECYCLE_SELECTOR):
            raise ValueError('lifecycle tier requires the exact controller lifecycle inventory')
        args.package, args.run = ['./controller'], LIFECYCLE_SELECTOR
    if args.tier in METADATA_TIERS:
        if args.package not in (None, ['./router']) or args.run not in ('.', METADATA_SELECTOR):
            raise ValueError('metadata tier requires the exact metadata consumer inventory')
        args.package, args.run = ['./router'], METADATA_SELECTOR
    if args.tier.startswith('wallet-'):
        selector = wallet_selector(args.tier.removeprefix('wallet-'))
        if args.package not in (None, ['./service']) or args.run not in ('.', selector):
            raise ValueError('wallet owner tier requires exact two-matrix inventory')
        args.package, args.run = ['./service'], selector
    if args.tier in ('postgres', 'postgres-redis'):
        selector = PG_SELECTOR if args.tier == 'postgres' else JOINT_SELECTOR
        if args.package not in (None, ['./router']) or args.run not in ('.', selector):
            raise ValueError('PG-only tier requires the exact Namespace test inventory')
        args.package, args.run = ['./router'], selector
    repo = Path(__file__).resolve().parents[2]
    bundle = Path(args.bundle).absolute()
    if bundle == repo or repo in bundle.parents:
        raise ValueError("build bundle must be outside the checkout")
    bundle.mkdir(mode=0o700, parents=True, exist_ok=False)
    source = bundle / 'source'
    source.mkdir()
    names = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=repo).decode().split('\0')
    for name in filter(None, names):
        src = repo / name
        if src.is_symlink() or not src.is_file():
            raise ValueError('source snapshot requires regular files')
        dst = source / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        dst.chmod(0o755 if src.stat().st_mode & 0o111 else 0o644)
    # Real existing assets are required; this runner never fabricates web output.
    if not (repo / 'web/dist/index.html').is_file():
        raise ValueError('build real frontend assets first; web/dist/index.html is absent')
    shutil.copytree(repo / 'web/dist', source / 'web/dist', symlinks=False)
    env = dict(os.environ, GOWORK='off')
    command(['go', 'build', '-mod=readonly', '-p=2', '-o', str(bundle / 'new-api'), '.'], cwd=repo, env=env)
    modules = [('', args.package or ['./...'])]
    if not args.package:
        modules += [('relaykit', ['./...']), ('tokenkit', ['./...'])]
    entries = []
    for module, patterns in modules:
        cwd = repo / module
        prefix = subprocess.check_output(['go', 'list', '-m'], cwd=cwd, env=env, text=True).strip()
        packages = subprocess.check_output(['go', 'list', *patterns], cwd=cwd, env=env, text=True).splitlines()
        for package in packages:
            if not module and package == prefix:
                continue
            rel = package.removeprefix(prefix).lstrip('/')
            binary = f'test-{len(entries)}'
            command(['go', 'test', '-c', '-mod=readonly', '-p=2', '-o', str(bundle / binary), package], cwd=cwd, env=env)
            if (bundle / binary).exists():
                entries.append({'binary': binary, 'cwd': str(Path(module) / rel), 'run': args.run})
    shutil.copyfile(__file__, bundle / 'runner.py')
    metadata = {'tier': args.tier, 'entries': entries, 'files': {str(p.relative_to(bundle)): digest(p) for p in sorted(bundle.rglob('*')) if p.is_file()}}
    if args.tier == 'all':
        metadata['inventory'] = compiled_inventory(bundle, entries)
        metadata['partitions'] = resource_partitions(entries, metadata['inventory'])
    (bundle / 'manifest.json').write_text(json.dumps(metadata, sort_keys=True))
    if args.prepare_only:
        print(json.dumps({'bundle': str(bundle), 'producer_sha256': digest(bundle / 'new-api'), 'packages': len(entries)}))
        return
    execute_prepared(bundle, args.tier)


def compiled_inventory(bundle, entries):
    inventory = {}
    for entry in entries:
        binary = entry['binary']
        if binary in inventory or not re.fullmatch(r'test-[0-9]+', binary):
            raise ValueError('duplicate or invalid package binary')
        cwd = Path(entry['cwd'])
        if cwd.is_absolute() or '..' in cwd.parts:
            raise ValueError('inventory directory escape')
        output = subprocess.check_output([str(bundle / binary), '-test.list=.'],
                                         cwd=bundle / 'source' / entry['cwd'], text=True)
        names = [line for line in output.splitlines()
                 if re.fullmatch(r'(?:Test|Example|Fuzz)\w*', line)]
        if len(names) != len(set(names)):
            raise ValueError('duplicate compiled test name')
        inventory[binary] = names
    return inventory


def resource_partitions(entries, inventory):
    # Partition the compiled top-level set, expanding only the two mandatory
    # wallet matrices into their three exact engine jobs. No prefix exclusions.
    if set(inventory) != {e['binary'] for e in entries} or any(e['run'] != '.' for e in entries):
        raise ValueError('default inventory package mismatch')
    routers = [e for e in entries if e['cwd'] == 'router']
    services = [e for e in entries if e['cwd'] == 'service']
    controllers = [e for e in entries if e['cwd'] == 'controller']
    if len(routers) != 1 or len(services) != 1 or len(controllers) != 1:
        raise ValueError('default requires complete router and service packages')
    router, service, controller = routers[0], services[0], controllers[0]
    lifecycle_name = LIFECYCLE_SELECTOR[1:-1]
    if lifecycle_name not in inventory[controller['binary']]:
        raise ValueError('required lifecycle inventory missing')
    required = {'postgres': PG_SELECTOR[1:-1], 'postgres-redis': JOINT_SELECTOR[1:-1]}
    if (not set(required.values()).issubset(inventory[router['binary']]) or
            not set(WALLET_TESTS).issubset(inventory[service['binary']])):
        raise ValueError('required compiled test missing')
    partitions = {tier: [] for tier in (*required, *('wallet-'+e for e in WALLET_ENGINES), *LIFECYCLE_TIERS, 'sqlite')}
    assigned = []
    for entry in entries:
        names = inventory[entry['binary']]
        if len(names) != len(set(names)):
            raise ValueError('duplicate inventory member')
        excluded = set(required.values()) if entry == router else set(WALLET_TESTS) if entry == service else {lifecycle_name} if entry == controller else set()
        ordinary = [n for n in names if n not in excluded]
        run = '^(' + '|'.join(re.escape(n) for n in ordinary) + ')$' if excluded else '.'
        if excluded and not ordinary:
            raise ValueError('empty ordinary package partition')
        partitions['sqlite'].append(dict(entry, run=run))
        assigned.extend((entry['binary'], n, '') for n in ordinary)
    for tier, name in required.items():
        partitions[tier] = [dict(router, run='^'+name+'$')]
        assigned.append((router['binary'], name, ''))
    for engine in WALLET_ENGINES:
        partitions['wallet-'+engine] = [dict(service, run=wallet_selector(engine))]
        assigned.extend((service['binary'], name, engine) for name in WALLET_TESTS)
        partitions['lifecycle-'+engine] = [dict(controller, run=LIFECYCLE_SELECTOR)]
        assigned.append((controller['binary'], lifecycle_name, engine))
    expected = {(b, n, engine) for b, names in inventory.items() for n in names
                for engine in (WALLET_ENGINES if (b == service['binary'] and n in WALLET_TESTS or b == controller['binary'] and n == lifecycle_name) else ('',))}
    if len(assigned) != len(set(assigned)) or set(assigned) != expected:
        raise ValueError('resource partitions overlap or omit tests')
    return partitions


def verified_manifest(bundle):
    if bundle.is_symlink() or not bundle.is_dir():
        raise ValueError('invalid prepared bundle')
    metadata = json.loads((bundle / 'manifest.json').read_text())
    if not isinstance(metadata.get('files'), dict) or not isinstance(metadata.get('entries'), list):
        raise ValueError('invalid prepared metadata')
    for entry in metadata['entries']:
        cwd = Path(entry['cwd'])
        if (not re.fullmatch(r'test-[0-9]+', entry['binary']) or entry['binary'] not in metadata['files'] or
                cwd.is_absolute() or '..' in cwd.parts or not isinstance(entry['run'], str)):
            raise ValueError('invalid prepared entry')
    if 'new-api' not in metadata['files'] or 'source/scripts/ci/bootstrap_test_runner.py' not in metadata['files']:
        raise ValueError('missing prepared producer/source')
    for name, expected in metadata['files'].items():
        rel = Path(name)
        src = bundle / rel
        if (rel.is_absolute() or '..' in rel.parts or
                any(p.is_symlink() for p in [src, *src.parents]) or not src.is_file() or digest(src) != expected):
            raise ValueError('prepared input hash/path mismatch')
    if metadata['files'].get('runner.py') != digest(Path(__file__)):
        raise ValueError('prepared runner mismatch')
    return metadata


def broker_inventory(bundle):
    """Unprivileged inventory only; never evidence of completed formal tiers."""
    if os.geteuid() != 997 or os.getegid() != 990 or os.getgroups():
        raise ValueError('broker inventory requires isolated executor 997:990 without groups')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    if status['NoNewPrivs'].strip() != '1' or int(status['CapEff'].strip(), 16) != 0:
        raise ValueError('broker inventory forbids elevation and effective capabilities')
    bundle = Path(bundle).absolute()
    metadata = verified_manifest(bundle)
    if metadata['tier'] != 'all':
        raise ValueError('broker inventory requires full prepared manifest')
    inventory = compiled_inventory(bundle, metadata['entries'])
    partitions = resource_partitions(metadata['entries'], inventory)
    if inventory != metadata.get('inventory') or partitions != metadata.get('partitions'):
        raise ValueError('broker inventory differs from admitted full plan')
    return {'scope': 'inventory-only', 'manifest_sha256': digest(bundle / 'manifest.json'),
            'inventory': inventory, 'partitions': partitions}


def required_leaves(tier):
    if tier == 'ordinary-audit' or tier in ORDINARY_AUDIT_SHARED:
        return ['TestOAuthTokensConsumerHTTP/ordinary_key_creation/audit_insert_failure/'+case
                for case in ('success', 'authenticated_rejection')]
    if tier in LIFECYCLE_TIERS:
        return ['TestOAuthDerivedTokenOwnerLifecycle/'+case for case in LIFECYCLE_CASES]
    if tier in METADATA_TIERS:
        return ['TestOAuthTokensConsumerHTTP/'+case for case in METADATA_CASES]
    if tier.startswith('wallet-'):
        engine = tier.removeprefix('wallet-')
        wallet_selector(engine)
        return ([WALLET_TESTS[0]+'/'+engine+'/'+case for case in WALLET_SCENARIOS] +
                [WALLET_TESTS[1]+'/'+engine+'/'+case for case in ('starts_after_free', 'arrears', 'top_up')])
    if tier == 'postgres':
        return ['TestSessionRevocationS1Namespace/restricted_'+v for v in ('false', 'true')]
    if tier == 'postgres-redis':
        return ['TestSessionRevocationS1RealRedis/'+v for v in JOINT_CASES]
    return []


def validate_required_output(tier, output, exit_code):
    events = re.findall(r'^\s*--- (PASS|FAIL|SKIP): (\S+) \(', output, re.M)
    required = required_leaves(tier)
    if (exit_code or any(status != 'PASS' for status, _ in events) or
            any(events.count(('PASS', name)) != 1 for name in required)):
        raise RuntimeError('required resource test failed, skipped or missing')
    return required


def validate_tier_receipt(metadata, manifest_hash, output, exit_code):
    receipts = []
    for line in output.splitlines():
        if line.startswith('BOOTSTRAP_TIER_RESULT '):
            receipts.append(json.loads(line.removeprefix('BOOTSTRAP_TIER_RESULT ')))
    expected = {'tier': metadata['tier'], 'invocation': metadata['invocation'],
                'manifest_sha256': manifest_hash, 'producer_sha256': metadata['files']['new-api'],
                'runner_sha256': metadata['files']['runner.py'], 'entries': metadata['entries'],
                'required_leaves': required_leaves(metadata['tier']), 'exit': 0, 'cleanup': True}
    if exit_code or receipts != [expected]:
        raise RuntimeError('missing, duplicate or mismatched current tier receipt')
    if metadata['tier'] != 'sqlite':
        validate_required_output(metadata['tier'], output, exit_code)
    return expected


def dispatch_tier(bundle, tier):
    metadata = verified_manifest(bundle)
    if tier not in ('sqlite', 'ordinary-audit', *ORDINARY_AUDIT_SHARED, 'postgres', 'postgres-redis', 'admission', *METADATA_TIERS, *LIFECYCLE_TIERS, *('wallet-'+e for e in WALLET_ENGINES)) or metadata['tier'] != tier:
        raise ValueError('dispatch tier mismatch')
    if tier in ORDINARY_AUDIT_SHARED:
        ordinary_audit_shared_dispatch(bundle,tier)
        return
    if tier == 'admission':
        available=int(re.search(r'^MemAvailable:\s+(\d+)',Path('/proc/meminfo').read_text(),re.M)[1])*1024
        if available < 4*1024**3:raise RuntimeError('admission needs 1GiB tmpfs plus 3GiB process margin')
        if sum((bundle/name).stat().st_size for name in metadata['files']) > 768*1024**2:
            raise RuntimeError('admission bundle exceeds private tmpfs safety budget')
        command(['sudo', '-n', 'unshare', '--mount', '--net', '--pid', '--fork', 'sh', '-c', 'mount --make-rprivate / && mount -t tmpfs -o size=1G,mode=0755,nosuid,nodev tmpfs /run && mount -t proc proc /proc && exec "$@"', 'admission-tests', sys.executable, str(bundle/'runner.py'), '_admission_run', str(bundle)])
        return
    if tier.startswith('wallet-') or tier in METADATA_TIERS or tier in LIFECYCLE_TIERS:
        available=int(re.search(r'^MemAvailable:\s+(\d+)',Path('/proc/meminfo').read_text(),re.M)[1])*1024
        size=sum((bundle/name).stat().st_size for name in metadata['files'])
        if size*2+1024**3 >= 4*1024**3 or available < size*2+1024**3+3*1024**3:
            raise RuntimeError('wallet resource memory budget unavailable')
    if tier in ('wallet-sqlite', 'metadata-sqlite'):
        command(['sudo', '-n', 'unshare', '--mount', '--net', '--pid', '--fork', 'sh', '-c',
                 'mount --make-rprivate / && mount -t tmpfs -o size=4G,mode=0755,nosuid,nodev tmpfs /run && mount -t proc proc /proc && '+('ip link set lo up && ' if tier == 'metadata-sqlite' else '')+'exec "$@"',
                 'wallet-tests', sys.executable, str(bundle/'runner.py'), '_wallet_run', str(bundle), tier])
        return
    if tier not in ('sqlite', 'ordinary-audit'):
        postgres_container(bundle, tier)
        return
    # Docker remains in the host controller, never this private net namespace.
    command(['sudo', '-n', 'unshare', '--mount', '--net', '--pid', '--fork',
             'sh', '-c', 'mount --make-rprivate / && mount -t tmpfs -o size=4G,mode=0755,nosuid,nodev tmpfs /run && ip link set lo up && exec "$@"',
             'bootstrap-tests', sys.executable, str(bundle / 'runner.py'), '_run', str(bundle), tier])


def execute_prepared(bundle, tier):
    bundle = Path(bundle).absolute()
    metadata = verified_manifest(bundle)
    if metadata['tier'] != tier:
        raise ValueError('prepared resource tier mismatch')
    if tier != 'all':
        dispatch_tier(bundle, tier)
        return
    if {n for n in metadata['files'] if re.fullmatch(r'test-[0-9]+', n)} != {e['binary'] for e in metadata['entries']}:
        raise ValueError('default compiled package omitted')
    inventory = compiled_inventory(bundle, metadata['entries'])
    plan = resource_partitions(metadata['entries'], inventory)
    if inventory != metadata.get('inventory') or plan != metadata.get('partitions'):
        raise ValueError('compiled inventory or partition changed')
    # Every invocation gets new receipts. Retain logs and input views for audit;
    # hardlinks are read-only reuse, never overwritten or chmod-ed.
    execution = Path(tempfile.mkdtemp(prefix='execution-', dir=bundle))
    invocation = secrets.token_hex(32)
    summary = {'scope': 'default-full', 'invocation': invocation,
               'manifest_sha256': digest(bundle / 'manifest.json'), 'tiers': [], 'exit': 1,
               'unexecuted': list(plan)}
    try:
        for resource in list(summary['unexecuted']):
            child = execution / resource
            child.mkdir(mode=0o700)
            entries = plan[resource]
            selected = {e['binary'] for e in entries}
            files = {name: value for name, value in metadata['files'].items()
                     if not re.fullmatch(r'test-[0-9]+', name) or name in selected}
            for name in files:
                target = child / name
                target.parent.mkdir(parents=True, exist_ok=True)
                os.link(bundle / name, target)
            sub = {'tier': resource, 'entries': entries, 'files': files, 'invocation': invocation}
            (child / 'manifest.json').write_text(json.dumps(sub, sort_keys=True))
            log = execution / (resource+'.log')
            argv = [sys.executable, str(child / 'runner.py'), '_dispatch', str(child), resource]
            print(json.dumps({'tier_start': resource, 'log': str(log), 'argv': argv}), flush=True)
            with log.open('xb') as stream:
                result = subprocess.run(argv, stdout=stream, stderr=subprocess.STDOUT)
            output = log.read_text(errors='replace')
            print(output, end='', flush=True)
            record = {'tier': resource, 'exit': result.returncode, 'log': str(log), 'log_sha256': digest(log)}
            summary['tiers'].append(record)
            summary['unexecuted'].remove(resource)
            record['receipt'] = validate_tier_receipt(sub, digest(child / 'manifest.json'), output, result.returncode)
        if {r['tier'] for r in summary['tiers']} != set(plan):
            raise RuntimeError('required tier omitted')
        summary['exit'] = 0
    finally:
        (execution / 'result.json').write_text(json.dumps(summary, sort_keys=True))
        print('BOOTSTRAP_DEFAULT_RESULT '+json.dumps(summary, sort_keys=True), flush=True)


def demote(uid):
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)
    # Even an installed setuid sudo cannot elevate the test service principal.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), 'no_new_privs failed')


def bootstrap_observation(side, phase, started, peer_pid, *, label='unspecified',
                          outcome='progress', error=None, cli_exit=None, request_id=None):
    """Best-effort bounded diagnostics, never exception text or birth payloads."""
    try:
        categories = ((subprocess.TimeoutExpired, 'cli_timeout'), (TimeoutError, 'socket_timeout'),
                      (ConnectionResetError, 'connection_reset'), (BrokenPipeError, 'broken_pipe'),
                      (ConnectionRefusedError, 'connection_refused'), (FileNotFoundError, 'not_found'),
                      (PermissionError, 'permission'), (json.JSONDecodeError, 'json_decode'),
                      (OSError, 'os_error'), (ValueError, 'validation'),
                      (KeyError, 'key_error'), (RuntimeError, 'runtime_error'))
        category = 'none' if error is None else next((name for kind, name in categories if isinstance(error, kind)), 'other')
        phases = ('begin', 'connect', 'peer_check', 'request_write', 'response_read', 'decode',
                  'stdout_write', 'request_read', 'resource_check', 'data_create', 'cli_begin',
                  'cli_return', 'file_owner', 'file_mode', 'directory_owner', 'reply_write', 'complete',
                  'wallet_rpc', 'wallet_peer', 'wallet_read', 'wallet_dispatch', 'wallet_reply',
                  'wallet_qualify', 'wallet_immutable', 'wallet_snapshot',
                  'wallet_mysql_verify', 'wallet_mysql_endpoint', 'wallet_mysql_observer')
        if side not in ('client', 'installer') or phase not in phases:
            return
        label = label if label in ('oauth_birth', 'organization_task_read', 'fresh', 'redis', 'pg', 'wallet') else 'unspecified'
        if label == 'wallet' and isinstance(error, subprocess.TimeoutExpired):
            category = 'subprocess_timeout'
        errno = getattr(error, 'errno', None)
        row = {'bootstrap_observation': 1, 'side': side, 'phase': phase, 'label': label,
               'request_id': 'pid-'+str(peer_pid if isinstance(peer_pid, int) and 0 < peer_pid < 2**31 else 0),
               'monotonic_ns': time.monotonic_ns(),
               'elapsed_ms': min(86400000, max(0, int((time.monotonic()-started)*1000))),
               'outcome': outcome if outcome in ('progress', 'success', 'rejected', 'error', 'cli_nonzero', 'enter', 'exit') else 'error',
               'category': category, 'errno': errno if isinstance(errno, int) and 0 <= errno <= 4095 else None,
               'cli_exit': cli_exit if isinstance(cli_exit, int) and -255 <= cli_exit <= 255 else None}
        if (side == 'installer' and label == 'wallet' and isinstance(request_id, str) and
                len(request_id) <= 64 and re.fullmatch(r'wallet-[0-9]{1,10}-[0-9]{1,19}', request_id)):
            row['request_id'] = request_id
        data = (json.dumps(row, separators=(',', ':'))+'\n').encode()
        if len(data) > 768:
            return
        sink = (_wallet_observation_fd if side == 'installer' and label == 'wallet' and
                _wallet_observation_fd is not None else 2 if side == 'client' else 1)
        if sink == _wallet_observation_fd and _wallet_observation_attempts is not None:
            next(_wallet_observation_attempts, None)
        original = os.fstat(sink)
        # O_NONBLOCK cannot bound regular-file/device writes. Unsupported sinks
        # lose diagnostics rather than acquiring a new operation dependency.
        if not stat.S_ISFIFO(original.st_mode):
            return
        # On Linux, reopening proc/self/fd creates an independent open file
        # description. dup()/F_SETFL would change the caller's shared flags.
        diagnostic = os.open('/proc/self/fd/' + str(sink),
                             os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            opened = os.fstat(diagnostic)
            if (not stat.S_ISFIFO(opened.st_mode) or
                    (opened.st_dev, opened.st_ino) != (original.st_dev, original.st_ino)):
                return
            # One <= PIPE_BUF write is all-or-EAGAIN, even with concurrent
            # writers. No readiness-check race, retry, queue or retained fd.
            if len(data) <= os.fpathconf(diagnostic, 'PC_PIPE_BUF'):
                os.write(diagnostic, data)
        finally:
            os.close(diagnostic)
    except Exception:
        # A closed/broken diagnostic sink cannot change the operation's result.
        pass


def client(sock, action="fresh"):
    started = time.monotonic()
    pid, phase = os.getpid(), 'begin'
    label = os.environ.get('NEWAPI_BOOTSTRAP_DIAGNOSTIC_LABEL', 'unspecified')
    bootstrap_observation('client', phase, started, pid, label=label)
    try:
        if os.geteuid() == 0:
            raise ValueError('fixture client must be the service principal')
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(120)
            phase = 'connect'
            conn.connect(sock)
            if action not in ('fresh', 'redis') and not re.fullmatch(r'(pg|s1-seed):[0-9a-f]{32}', action):
                raise ValueError('unsupported installer request')
            phase = 'peer_check'
            _, peer_uid, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if peer_uid != 0:
                raise ValueError('installer peer must be root')
            phase = 'request_write'
            conn.sendall((action + '\n').encode())
            conn.shutdown(socket.SHUT_WR)
            data = b''
            phase = 'response_read'
            while len(data) <= 8192:
                part = conn.recv(8192)
                if not part:
                    break
                data += part
            phase = 'decode'
            result = json.loads(data)
            if action == 'fresh':
                fields = {'Engine', 'DSN', 'Journal'}
                if result.get('Engine') == 'postgres':
                    fields.add('ResourceReceipt')
                if set(result) != fields or result['Engine'] not in ('sqlite', 'postgres'):
                    raise ValueError('invalid installer response')
            phase = 'stdout_write'
            sys.stdout.write(json.dumps(result))
        bootstrap_observation('client', 'complete', started, pid, label=label, outcome='success')
    except Exception as error:
        bootstrap_observation('client', phase, started, pid, label=label, outcome='error', error=error)
        # Unhandled client exceptions historically exit1. Preserve it, without
        # the raw traceback (which may embed a DSN or a response payload).
        raise SystemExit(1) from None


class Installer:
    def __init__(self, root, uid, redis_resource=None, pg_resource=None, metadata=None):
        self.root, self.uid = root, uid
        self.redis_resource = redis_resource
        self.pg_resource = pg_resource
        self.stopped = threading.Event()
        self.server = socket.socket(socket.AF_UNIX)
        self.server.bind(str(root / 'installer.sock'))
        os.chmod(root / 'installer.sock', 0o666)
        self.server.listen(8)
        self.server.settimeout(0.2)
        self.receipts = []
        self.metadata = metadata
        self.process = None
        self.process_ready = threading.Event()
        self.seed_births = {}

    def s1_peer(self, pid):
        # Only the fixed joint tier's exact root-launched router binary may
        # request synthetic input. A same-UID sibling or shell grandchild is
        # not its authenticated client. No actor/path/SQL is accepted over IPC.
        if (not self.metadata or self.metadata.get('tier') != 'postgres-redis' or
                len(self.metadata['entries']) != 1 or
                self.metadata['entries'][0]['cwd'] != 'router' or
                self.metadata['entries'][0]['run'] != JOINT_SELECTOR or
                not self.process_ready.wait(3) or self.process is None):
            raise ValueError('S1 seed caller unavailable')
        status = dict(line.split(':', 1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
        if (int(status['PPid']) != self.process.pid or
                any(int(v) != self.uid for v in status['Uid'].split()) or
                status['NoNewPrivs'].strip() != '1' or int(status['CapEff'], 16)):
            raise ValueError('S1 seed peer denied')
        binary = self.metadata['entries'][0]['binary']
        identity = admission_identity(self.process, self.uid, self.root/'bundle'/binary)
        if identity['ExeSHA256'] != self.metadata['files'][binary]:
            raise ValueError('S1 seed binary changed')
        return identity

    def s1_provenance(self, database):
        rows = '\n'.join(self.pg_resource.sql(database, 'SELECT row_to_json(t)::text FROM '+table+' t ORDER BY id;')
                         for table in ('oauth_derived_token_history', 'oauth_derived_token_bootstrap_identity'))
        return hashlib.sha256(rows.encode()).hexdigest()

    def seed_s1(self, ident, peer):
        record = self.seed_births[ident]
        if record['used'] or time.monotonic() >= record['deadline'] or peer != record['peer']:
            raise ValueError('S1 seed expired, replayed or foreign')
        receipt = self.pg_resource.qualify(ident)
        database = receipt['database']
        if (digest(self.root/('pg-resource-'+ident+'.json')) != record['receipt_sha256'] or
                self.s1_provenance(database) != record['provenance_sha256']):
            raise ValueError('S1 seed birth changed')
        # One fixed fixture. Root reads identity from its own born database,
        # never from an actor claimed by the client. All predicates are repeated
        # under User -> session -> grant -> Token locks before the sole INSERT.
        projection = """SELECT u.id AS user_id,g.grant_ref,g.grant_id,g.policy_hash,g.created_at,
                   t.id AS token_id,t.key,t.expired_time
            FROM users u JOIN user_sessions s ON s.user_id=u.id
            JOIN oauth_grants g ON g.user_id=u.id AND g.origin_s_id=s.sid
            JOIN tokens t ON t.user_id=u.id
            WHERE u.username='s2-owner' AND u.status=1 AND u.deleted_at IS NULL
              AND s.status='active' AND s.user_auth_version=u.auth_version
              AND s.version=g.session_version AND g.user_auth_version=u.auth_version
              AND s.expires_at>EXTRACT(EPOCH FROM clock_timestamp())
              AND g.subject=u.id::text AND g.state='active' AND g.revision=1
              AND g.issuer='https://s1-seed.invalid/' AND g.client_id='s1-seed-client'
              AND g.consent_request_id='s1-seed-consent' AND g.hydra_login_session_id='s1-seed-login'
              AND g.scopes='["tokens:write"]' AND g.policy_hash=repeat('b',64)
              AND g.expires_at>=t.expired_time AND t.expired_time>EXTRACT(EPOCH FROM clock_timestamp())
              AND t.expired_time<=EXTRACT(EPOCH FROM clock_timestamp())+600
              AND t.name='s1-seed-token' AND t.status=1 AND t.deleted_at IS NULL
              AND NOT t.unlimited_quota AND t.remain_quota=1000 AND t.used_quota=0
              AND NOT EXISTS(SELECT 1 FROM oauth_derived_token_sources)
            """
        raw = self.pg_resource.sql(database, "SELECT row_to_json(x)::text FROM ("+projection+") x;")
        rows = raw.splitlines()
        if len(rows) != 1:
            raise ValueError('S1 seed fixed fixture binding absent')
        row = json.loads(rows[0])
        if (not re.fullmatch(r'[0-9a-f]{64}', row['grant_ref']) or
                not re.fullmatch(r'[A-Za-z0-9_-]{43}', row['grant_id']) or
                row['grant_ref'] != hashlib.sha256(('newapi.oauth.grant.v1\x00https://s1-seed.invalid/\x00'+row['grant_id']).encode()).hexdigest() or
                not re.fullmatch(r'[A-Za-z0-9]{32,48}', row['key']) or
                not 0 < row['user_id'] <= 2147483647 or not 0 < row['token_id'] <= 2147483647 or
                not int(time.time())-60 <= row['created_at'] <= int(time.time())):
            raise ValueError('S1 seed fixture bounds denied')
        key_ref = hashlib.sha256(b'newapi.oauth.derived-key.v1\x00'+row['key'].encode()).hexdigest()
        grant, token, user = row['grant_ref'], row['token_id'], row['user_id']
        # Fixed-format integer/hex/alphanumeric values only; no arbitrary SQL.
        statement = f"""BEGIN;
            SELECT id FROM users WHERE id={user} FOR UPDATE;
            SELECT sid FROM user_sessions WHERE sid=(SELECT origin_s_id FROM oauth_grants WHERE grant_ref='{grant}') FOR UPDATE;
            SELECT grant_ref FROM oauth_grants WHERE grant_ref='{grant}' FOR UPDATE;
            SELECT id FROM tokens WHERE id={token} FOR UPDATE;
            INSERT INTO oauth_derived_token_sources
            (grant_ref,user_id,schema_version,quota_limit,expires_at,policy_hash,binding_hash,
             verified_at,proof_expires_at,permit_deadline,verified_method,proof_flow_id,
             token_id,key_ref,idem_hash,request_hash,created_at)
            SELECT x.grant_ref,x.user_id,1,1000,x.expired_time,x.policy_hash,repeat('c',64),
                   x.created_at-1,x.created_at+40,x.created_at+40,'password',1,
                   x.token_id,'{key_ref}',repeat('d',64),repeat('e',64),x.created_at
            FROM ({projection}) x
            WHERE x.user_id={user} AND x.grant_ref='{grant}' AND x.token_id={token}
              AND x.key='{row["key"]}' AND x.grant_id='{row["grant_id"]}' AND x.created_at={row['created_at']}
              AND EXTRACT(EPOCH FROM clock_timestamp())<{record['expires_at']};
            COMMIT;"""
        self.pg_resource.sql(database, statement)
        count = self.pg_resource.sql(database, f"SELECT COUNT(*) FROM oauth_derived_token_sources WHERE grant_ref='{grant}' AND token_id={token};")
        if count != '1':
            raise ValueError('S1 seed current binding changed')
        record['used'] = True
        if self.s1_provenance(database) != record['provenance_sha256']:
            raise RuntimeError('S1 seed immutable provenance changed')
        return {'seeded': True}

    def serve(self):
        while not self.stopped.is_set():
            try:
                conn, _ = self.server.accept()
            except socket.timeout:
                continue
            started = time.monotonic()
            pid, phase, label = 0, 'peer_check', 'unspecified'
            outcome, failure, cli_exit = 'rejected', None, None
            with conn:
                try:
                    conn.settimeout(5)
                    pid, peer_uid, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    if peer_uid != self.uid:
                        continue
                    # No client-controlled path, command, environment or namespace.
                    try:
                        phase = 'request_read'
                        request = conn.recv(64)
                        if conn.recv(1) != b'':
                            continue
                        if request == b'redis\n' and self.redis_resource is not None:
                            label, phase = 'redis', 'resource_check'
                            self.redis_resource.verify()
                            phase = 'reply_write'
                            conn.sendall(json.dumps(self.redis_resource.receipt).encode())
                            outcome = 'success'
                            continue
                        if re.fullmatch(rb's1-seed:[0-9a-f]{32}\n', request) and self.pg_resource is not None:
                            label, phase = 's1_seed', 'peer_check'
                            peer = self.s1_peer(pid)
                            phase = 'fixed_seed'
                            reply = self.seed_s1(request[8:-1].decode(), peer)
                            conn.sendall(json.dumps(reply).encode())
                            outcome = 'success'
                            continue
                        if re.fullmatch(rb'pg:[0-9a-f]{32}\n', request) and self.pg_resource is not None:
                            label, phase = 'pg', 'resource_check'
                            reply = self.pg_resource.qualify(request[3:-1].decode())
                            phase = 'reply_write'
                            conn.sendall(json.dumps(reply).encode())
                            outcome = 'success'
                            continue
                        if request != b'fresh\n':
                            continue
                        label = 'fresh'
                        if self.pg_resource is not None:
                            phase = 'cli_begin'
                            bootstrap_observation('installer', phase, started, pid, label=label)
                            reply = self.pg_resource.birth()
                            if self.metadata and self.metadata.get('tier') == 'postgres-redis':
                                peer = self.s1_peer(pid)
                                ident = Path(reply['Journal']).stem
                                receipt = self.pg_resource.qualify(ident)
                                self.seed_births[ident] = {'peer': peer, 'deadline': time.monotonic()+120, 'expires_at': int(time.time())+120, 'used': False,
                                    'receipt_sha256': digest(reply['ResourceReceipt']),
                                    'provenance_sha256': self.s1_provenance(receipt['database'])}
                            phase = 'reply_write'
                            conn.sendall(json.dumps(reply).encode())
                            outcome = 'success'
                            continue
                        phase = 'data_create'
                        completed_birth = outer_birth('sqlite', 'installer')
                        if completed_birth is not None:
                            ident = completed_birth['id']
                            target = Path(completed_birth['target'])
                            data = target.parent
                            journal = Path(completed_birth['journal'])
                            self.receipts.append({'operation': 'outer-birth', 'id': ident, 'exit': 0,
                                'output_sha256': completed_birth['output_sha256'], 'peer_uid': peer_uid})
                        else:
                            ident = secrets.token_hex(16)
                            data = self.root / ('data-' + ident)
                            data.mkdir(mode=0o755)
                            target = data / 'new.db'
                            journal = self.root / 'journals' / (ident + '.json')
                            argv = [str(self.root / 'bundle/new-api'), 'db-bootstrap', 'fresh', '--engine', 'sqlite', '--target', str(target), '--journal', str(journal)]
                            phase = 'cli_begin'
                            bootstrap_observation('installer', phase, started, pid, label=label)
                            proc = subprocess.run(argv, env={'PATH': '/usr/bin:/bin'}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
                            cli_exit = proc.returncode
                            phase = 'cli_return'
                            bootstrap_observation('installer', phase, started, pid, label=label, cli_exit=cli_exit)
                            self.receipts.append({'argv': argv, 'exit': proc.returncode, 'output_sha256': hashlib.sha256(proc.stdout).hexdigest(), 'peer_uid': peer_uid})
                            if proc.returncode:
                                outcome = 'cli_nonzero'
                                continue
                        phase = 'file_owner'
                        os.chown(target, self.uid, self.uid)
                        phase = 'file_mode'
                        os.chmod(target, 0o600)
                        phase = 'directory_owner'
                        os.chown(data, self.uid, self.uid)
                        phase = 'reply_write'
                        conn.sendall(json.dumps({'Engine': 'sqlite', 'DSN': str(target), 'Journal': str(journal)}).encode())
                        outcome = 'success'
                    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
                        failure, outcome = error, 'error'
                        continue
                except Exception as error:
                    # Preserve formerly uncaught peer/socket failures as failures.
                    failure, outcome = error, 'error'
                    raise
                finally:
                    bootstrap_observation('installer', phase, started, pid, label=label,
                                          outcome=outcome, error=failure, cli_exit=cli_exit)



class OwnedRedis:
    """One ephemeral daemon in the installer's already-private namespaces."""
    def __init__(self, root, uid):
        self.root, self.uid = root, uid
        self.process = None
        self.log = None
        self.receipt = None
        self.address = None
        self.kernel_identity = None
        self.executable = None

    def request(self, *parts):
        # Bounded RESP2 for fixed installer commands only; no shell or client RPC.
        with socket.create_connection(self.address, timeout=1) as conn:
            conn.settimeout(1)
            data = b'*' + str(len(parts)).encode() + b'\r\n'
            for value in parts:
                value = str(value).encode()
                data += b'$' + str(len(value)).encode() + b'\r\n' + value + b'\r\n'
            conn.sendall(data)
            with conn.makefile('rb') as stream:
                line = stream.readline(65537)
                if not line.endswith(b'\r\n'):
                    raise ValueError('invalid Redis response')
                kind, value = line[:1], line[1:-2]
                if kind == b'+':
                    return value.decode()
                if kind == b':':
                    return int(value)
                if kind == b'$':
                    size = int(value)
                    if not 0 <= size <= 65536:
                        raise ValueError('invalid Redis bulk size')
                    body = stream.read(size)
                    if len(body) != size or stream.read(2) != b'\r\n':
                        raise ValueError('incomplete Redis response')
                    return body.decode()
                raise ValueError('unexpected Redis response class')

    def kernel_binding(self):
        # /proc can still be mounted for the host PID namespace. Resolve only
        # our kernel-listed children; never treat namespace-local Popen.pid as
        # a /proc directory number. NSpid's last component is our child PID.
        children = set()
        for task in Path('/proc/self/task').iterdir():
            children.update((task / 'children').read_text().split())
        matches = []
        for child in children:
            proc = Path('/proc') / child
            try:
                status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
                if (int(status['NSpid'].split()[-1]) == self.process.pid and
                        os.readlink(proc / 'ns/pid') == os.readlink('/proc/self/ns/pid')):
                    matches.append((proc, status))
            except FileNotFoundError:
                continue
        if len(matches) != 1:
            raise RuntimeError('Redis child proc binding unavailable')
        proc, status = matches[0]
        if (any(int(uid) != self.uid for uid in status['Uid'].split()) or
                os.readlink(proc / 'ns/net') != os.readlink('/proc/self/ns/net')):
            raise RuntimeError('Redis child namespace/UID mismatch')
        exe = (proc / 'exe').stat()
        expected_exe = self.executable.stat()
        if (exe.st_dev, exe.st_ino) != (expected_exe.st_dev, expected_exe.st_ino):
            raise RuntimeError('Redis child executable mismatch')
        # stat comm may contain spaces or parentheses; fields after final ')' start at 3.
        start_time = (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19]
        expected = '0100007F:' + format(self.address[1], '04X')
        rows = [line.split() for line in Path('/proc/net/tcp').read_text().splitlines()[1:]]
        rows = [row for row in rows if row[1] == expected and row[3] == '0A']
        if len(rows) != 1 or int(rows[0][7]) != self.uid:
            raise RuntimeError('Redis loopback listener ownership mismatch')
        inode = rows[0][9]
        descriptors = set()
        for fd in (proc / 'fd').iterdir():
            try:
                descriptors.add(os.readlink(fd))
            except FileNotFoundError:
                continue
        if 'socket:[' + inode + ']' not in descriptors:
            raise RuntimeError('Redis listener is not owned by child')
        identity = {'proc_pid': int(proc.name), 'start_time': start_time,
                    'socket_inode': inode, 'exe_device': exe.st_dev, 'exe_inode': exe.st_ino,
                    'pid_namespace': os.readlink(proc / 'ns/pid')}
        if self.kernel_identity is not None and identity != self.kernel_identity:
            raise RuntimeError('Redis kernel identity changed')
        return identity

    def verify(self):
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError('owned Redis exited')
        if self.request('PING') != 'PONG':
            raise RuntimeError('owned Redis PING failed')
        identity = self.kernel_binding()
        info = dict(line.split(':', 1) for line in self.request('INFO', 'server').splitlines()
                    if ':' in line and not line.startswith('#'))
        if (info.get('process_id') != str(self.process.pid) or
                info.get('tcp_port') != str(self.address[1]) or
                not re.fullmatch(r'[0-9a-f]{40}', info.get('run_id', ''))):
            raise RuntimeError('Redis process/listener identity mismatch')
        if self.receipt and (info['run_id'] != self.receipt['run_id'] or
                             info['redis_version'] != self.receipt['version']):
            raise RuntimeError('Redis resource replaced')
        if self.kernel_binding() != identity:
            raise RuntimeError('Redis listener changed during qualification')
        self.kernel_identity = identity
        return info

    def require_namespace(self):
        for namespace in ('mnt', 'net', 'pid'):
            if os.readlink('/proc/self/ns/' + namespace) == os.readlink('/proc/1/ns/' + namespace):
                raise ValueError('Redis requires private mount/net/PID namespaces')

    def start(self):
        self.require_namespace()
        binary = Path('/usr/bin/redis-server')
        # Fixed system dependency; fail before handing off an endpoint if absent.
        resolved = binary.resolve(strict=True)
        self.executable = resolved
        info = resolved.stat()
        if info.st_uid != 0 or info.st_mode & 0o022 or not stat.S_ISREG(info.st_mode):
            raise ValueError('untrusted Redis executable')
        version = subprocess.check_output([str(binary), '--version'], env={'PATH': '/usr/bin:/bin'}, timeout=5, text=True)
        match = re.search(r'\bv=([0-9]+\.[0-9]+\.[0-9]+)\b', version)
        if not match:
            raise ValueError('unrecognized Redis version')
        data = self.root / 'redis-data'
        data.mkdir(mode=0o700)
        os.chown(data, self.uid, self.uid)
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            self.address = reservation.getsockname()
        self.log = (self.root / 'redis.log').open('xb')
        argv = [str(binary), '--bind', '127.0.0.1', '--port', str(self.address[1]),
                '--protected-mode', 'yes', '--save', '', '--appendonly', 'no',
                '--daemonize', 'no', '--dir', str(data), '--loglevel', 'warning',
                '--user', 'default', 'on', 'nopass', '~*', '&*', '+@all', '-@admin',
                '-save', '-bgsave', '-bgrewriteaof', '-replicaof', '-slaveof']
        self.process = subprocess.Popen(argv, env={'PATH': '/usr/bin:/bin'},
                                        stdout=self.log, stderr=subprocess.STDOUT,
                                        preexec_fn=lambda: demote(self.uid))
        deadline = time.monotonic() + 5
        while True:
            if self.process.poll() is not None:
                raise RuntimeError('owned Redis failed to start')
            try:
                info = self.verify()
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise RuntimeError('owned Redis readiness deadline exceeded') from None
                time.sleep(0.02)  # Bounded readiness polling, never a test assertion.
        if info['redis_version'] != match[1]:
            raise RuntimeError('Redis executable/server version mismatch')
        key, value = 'bootstrap-probe:' + secrets.token_hex(24), secrets.token_hex(24)
        if (self.request('EXISTS', key) != 0 or self.request('SET', key, value, 'NX') != 'OK' or
                self.request('GET', key) != value or self.request('DEL', key) != 1 or
                self.request('EXISTS', key) != 0):
            raise RuntimeError('Redis random-key lifecycle failed')
        self.receipt = {'address': self.address[0] + ':' + str(self.address[1]),
                        'port': self.address[1], 'pid': self.process.pid, 'service_uid': self.uid,
                        'run_id': info['run_id'], 'version': info['redis_version'],
                        'net_namespace': os.readlink('/proc/self/ns/net'),
                        'binary_sha256': digest(resolved), 'kernel_identity': self.kernel_identity, 'persistence': False,
                        'key_lifecycle': 'EXISTS0/SET-NX/GET/DEL1/EXISTS0'}
        receipt = self.root / 'redis-resource.json'
        with receipt.open('x') as stream:
            json.dump(self.receipt, stream, sort_keys=True)
        receipt.chmod(0o644)
        return {'NEWAPI_BOOTSTRAP_REDIS_RECEIPT': str(receipt),
                'NEWAPI_TOKEN_STATE_REDIS_ADDR': self.receipt['address'],
                'NEWAPI_TOKEN_STATE_REDIS_PORT': str(self.address[1]),
                'NEWAPI_W01_REDIS_ADDR': self.receipt['address'],
                'NEWAPI_W01_REDIS_ALLOWED_PORT': str(self.address[1])}

    def close(self):
        if self.process is not None:
            # Popen owns exactly this unreaped child, never an adopted PID.
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
                    raise RuntimeError('owned Redis required forced shutdown')
            if self.address:
                with socket.socket() as probe:
                    probe.settimeout(1)
                    if probe.connect_ex(self.address) == 0:
                        raise RuntimeError('Redis listener survived owned process exit')
        if self.log:
            self.log.close()
        print(json.dumps({'redis_resource': self.receipt,
                          'redis_exit': self.process.returncode if self.process else None,
                          'redis_log_sha256': digest(self.root / 'redis.log') if self.log else None,
                          'cleanup': 'owned Redis process stopped and listener absent'}), flush=True)

class OwnedPostgres:
    """Fixed PG-only substrate; root provisions, daemon and service cannot."""
    def __init__(self, root, uid):
        self.root, self.uid = root, uid
        self.daemon_uid = pwd.getpwnam('postgres').pw_uid
        if self.daemon_uid in (0, uid):
            raise ValueError('PG daemon principal must be independent')
        self.bin = Path('/usr/lib/postgresql/15/bin')
        self.socket_dir = root / 'pg-socket'
        self.socket_path = self.socket_dir / '.s.PGSQL.5432'
        self.process = self.log = self.identity = None
        self.password = secrets.token_hex(32)
        self.births = {}
        self.commands = []

    def sql(self, database, statement):
        if not re.fullmatch(r'[a-z][a-z0-9_]{0,47}', database):
            raise ValueError('invalid installer database')
        q = subprocess.run([str(self.bin / 'psql'), '-X', '-qAt', '-v', 'ON_ERROR_STOP=1',
                            '-h', str(self.socket_dir), '-U', 'bootstrap', '-d', database],
                           input=statement.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           env={'PATH': '/usr/bin:/bin', 'PGPASSWORD': self.password}, timeout=30)
        self.commands.append({'operation': 'installer SQL', 'exit': q.returncode,
                              'stderr_sha256': hashlib.sha256(q.stderr).hexdigest()})
        if q.returncode:
            raise RuntimeError('PG installer SQL failed; output retained only as digest')
        return q.stdout.decode().strip()

    def verify(self):
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError('owned PG exited')
        # Container /proc is mounted in this PID namespace. Bind via peer PID,
        # exact parentage, executable and listener FD, not SQL self-report.
        proc = Path('/proc') / str(self.process.pid)
        status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
        if (int(status['NSpid'].split()[-1]) != self.process.pid or
                int(status['PPid']) != os.getpid() or
                any(int(v) != self.daemon_uid for v in status['Uid'].split())):
            raise RuntimeError('PG process namespace/ownership mismatch')
        exe, expected = (proc / 'exe').stat(), (self.bin / 'postgres').stat()
        if (exe.st_dev, exe.st_ino) != (expected.st_dev, expected.st_ino):
            raise RuntimeError('PG executable mismatch')
        st = self.socket_dir.lstat()
        if st.st_uid != self.daemon_uid or st.st_mode & 0o022 or not stat.S_ISDIR(st.st_mode):
            raise RuntimeError('PG socket directory ownership mismatch')
        socket_stat = self.socket_path.lstat()
        if not stat.S_ISSOCK(socket_stat.st_mode) or socket_stat.st_uid != self.daemon_uid:
            raise RuntimeError('PG endpoint not owned socket')
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(2)
            conn.connect(str(self.socket_path))
            peer = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if peer[:2] != (self.process.pid, self.daemon_uid):
                raise RuntimeError('PG endpoint peer mismatch')
        rows = [line.split() for line in Path('/proc/net/unix').read_text().splitlines()[1:]]
        rows = [row for row in rows if len(row) == 8 and row[7] == str(self.socket_path) and row[3] == '00010000']
        fds = set()
        for fd in (proc / 'fd').iterdir():
            try:
                fds.add(os.readlink(fd))
            except FileNotFoundError:
                continue
        if len(rows) != 1 or 'socket:[' + rows[0][6] + ']' not in fds:
            raise RuntimeError('PG listener is not owned by child')
        identity = {'pid': self.process.pid, 'daemon_uid': self.daemon_uid,
                    'start_time': (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19],
                    'socket_inode': rows[0][6], 'socket_file_inode': socket_stat.st_ino,
                    'directory_inode': st.st_ino, 'exe_inode': exe.st_ino, 'exe_device': exe.st_dev,
                    'pid_namespace': os.readlink(proc / 'ns/pid'), 'net_namespace': os.readlink(proc / 'ns/net')}
        if self.identity is not None and self.identity != identity:
            raise RuntimeError('PG resource replaced')
        self.identity = identity
        return identity

    def start(self):
        for name in ('postgres', 'initdb', 'psql'):
            p = self.bin / name
            st = p.stat()
            if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
                raise ValueError('untrusted PG dependency')
        data = self.root / 'pg-data'
        for path in (data, self.socket_dir):
            path.mkdir(mode=0o700 if path == data else 0o755)
            os.chown(path, self.daemon_uid, self.daemon_uid)
        password_file = self.root / 'pg-initial-password'
        fd = os.open(password_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.fchown(fd, self.daemon_uid, self.daemon_uid)
            os.write(fd, (self.password+'\n').encode())
        finally:
            os.close(fd)
        try:
            q = subprocess.run([str(self.bin / 'initdb'), '-D', str(data), '--username=bootstrap',
                                '--auth=scram-sha-256', '--pwfile='+str(password_file), '--no-locale', '--encoding=UTF8'],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               preexec_fn=lambda: demote(self.daemon_uid), env={'PATH': '/usr/bin:/bin'}, timeout=30)
        finally:
            password_file.unlink()
        self.commands.append({'operation': 'initdb', 'exit': q.returncode, 'output_sha256': hashlib.sha256(q.stdout+q.stderr).hexdigest(), 'error': q.stderr.decode(errors='replace').replace(self.password, '[redacted]') if q.returncode else None})
        if q.returncode:
            raise RuntimeError('PG initdb failed')
        self.log = (self.root / 'postgres.log').open('xb')
        self.process = subprocess.Popen([str(self.bin / 'postgres'), '-D', str(data),
                                         '-c', 'listen_addresses=', '-c', 'unix_socket_directories='+str(self.socket_dir),
                                         '-c', 'unix_socket_permissions=0777', '-c', 'shared_buffers=16MB',
                                         '-c', 'max_connections=30', '-c', 'log_statement=none',
                                         '-c', 'log_min_error_statement=panic'],
                                        stdout=self.log, stderr=subprocess.STDOUT, env={'PATH': '/usr/bin:/bin'},
                                        preexec_fn=lambda: demote(self.daemon_uid))
        deadline = time.monotonic()+10
        while not self.socket_path.exists():
            if self.process.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError('PG startup failed')
            time.sleep(0.02)
        self.verify()
        self.version = self.sql('postgres', 'SHOW server_version;')
        self.sql('postgres', 'REVOKE CONNECT ON DATABASE postgres FROM PUBLIC; REVOKE CONNECT ON DATABASE template1 FROM PUBLIC;')
        return {'NEWAPI_BOOTSTRAP_ENGINE': 'postgres', 'NEWAPI_S2_MAIN': 'postgres',
                'NEWAPI_W01_MAIN_KIND': 'postgres', 'NEWAPI_BOOTSTRAP_TIER': 'postgres'}

    def birth(self):
        self.verify()
        completed_birth = outer_birth('postgres', 'postgres', self)
        if completed_birth is not None:
            ident = completed_birth['id']
            database = completed_birth['target']
            journal = Path(completed_birth['journal'])
            role, restricted = 'svc_' + ident, 'limited_' + ident
            self.commands.append({'operation': 'outer-birth', 'database': database, 'exit': 0,
                                  'output_sha256': completed_birth['output_sha256']})
        else:
            ident = secrets.token_hex(16)
            database, role, restricted = 'birth_'+ident, 'svc_'+ident, 'limited_'+ident
            journal = self.root / 'journals' / (ident+'.json')
            # URL syntax is the permanent product CLI contract. Password only in env.
            admin = 'postgresql://bootstrap:'+self.password+'@/postgres?host='+str(self.socket_dir)+'&sslmode=disable'
            q = subprocess.run([str(self.root / 'bundle/new-api'), 'db-bootstrap', 'fresh', '--engine', 'postgres',
                                '--target', database, '--journal', str(journal)],
                               env={'PATH': '/usr/bin:/bin', 'GOMAXPROCS': '2', 'BOOTSTRAP_ADMIN_DSN': admin},
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
            self.commands.append({'operation': 'permanent CLI fresh', 'database': database, 'exit': q.returncode,
                                  'output_sha256': hashlib.sha256(q.stdout+q.stderr).hexdigest(), 'journal_phase': json.loads(journal.read_text()).get('phase') if journal.exists() else None, 'error': (q.stdout+q.stderr).decode(errors='replace').replace(self.password, '[redacted]') if q.returncode else None})
            if q.returncode:
                self.commands.append({'operation': 'birth failure boundary',
                                      'lock_exists': Path(str(journal)+'.lock').exists(),
                                      'protected_ancestors': [{'path': str(p), 'uid': p.stat().st_uid, 'mode': oct(p.stat().st_mode & 0o777)} for p in (journal.parent, self.root, Path('/run'), Path('/'))],
                                      'admin_superuser': self.sql('postgres', 'SELECT rolsuper FROM pg_roles WHERE rolname=current_user;'),
                                      'pg_error_categories': [category for category in ('password authentication failed', 'role does not exist', 'database does not exist', 'no pg_hba.conf entry', 'unsupported frontend protocol', 'invalid startup packet') if category in (self.root/'postgres.log').read_text()]})
                raise RuntimeError('permanent PG birth failed')
            j = json.loads(journal.read_text())
            if j['phase'] != 'READY' or j['target'] != database or j['engine'] != 'postgres':
                raise RuntimeError('PG birth journal mismatch')
        password = secrets.token_hex(32)
        self.sql(database, f"CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD '{password}'; CREATE ROLE {restricted} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; GRANT {restricted} TO {role}; REVOKE ALL ON SCHEMA public FROM PUBLIC; GRANT USAGE,CREATE ON SCHEMA public TO {role}; CREATE SCHEMA app; GRANT USAGE,CREATE ON SCHEMA app TO {role}; GRANT USAGE ON SCHEMA app TO {restricted};")
        # Exactly the existing organization fixture's mutable tables. History and
        # birth identity stay installer-owned and SELECT-only for the service.
        mutable = ('users','user_sessions','session_revocation_events','user_access_tokens','options','tokens','tasks','logs',
                   'casbin_rule','authz_roles','organizations','organization_members','organization_invitations',
                   'organization_ownership_transfers','organization_events','organization_creation_requests',
                   'organization_wallets','organization_wallet_entries','oauth_grants','o_auth_operations',
                   'o_auth_artifacts','o_auth_cleanup_jobs')
        existing = set(self.sql(database, "SELECT tablename FROM pg_tables WHERE schemaname='public';").splitlines())
        for table in mutable:
            if table in existing:
                self.sql(database, f'GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.{table} TO {role};')
        for table in ('oauth_derived_token_sources','oauth_derived_token_history','oauth_derived_token_bootstrap_identity'):
            self.sql(database, f'GRANT SELECT ON TABLE public.{table} TO {role};')
        self.sql(database, f'GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO {role}; ALTER TABLE public.users OWNER TO {role}; ALTER TABLE public.session_revocation_events OWNER TO {role}; GRANT SELECT,UPDATE ON public.users TO {restricted}; GRANT SELECT,INSERT,UPDATE ON public.session_revocation_events TO {restricted};')
        self.sql('postgres', f'GRANT CONNECT ON DATABASE {database} TO {role}; ALTER DATABASE {database} CONNECTION LIMIT 20;')
        receipt = {'id': ident, 'database': database, 'role': role, 'restricted_role': restricted, 'schema': 'app',
                   'socket_dir': str(self.socket_dir), 'port': 5432, 'service_uid': self.uid,
                   'journal': str(journal), 'journal_sha256': digest(journal), 'kernel': self.verify(), 'version': self.version}
        path = self.root / ('pg-resource-'+ident+'.json')
        path.write_text(json.dumps(receipt, sort_keys=True));path.chmod(0o644)
        self.births[ident] = receipt
        return {'Engine': 'postgres', 'DSN': 'postgresql://'+role+':'+password+'@/'+database+'?host='+str(self.socket_dir)+'&sslmode=disable',
                'Journal': str(journal), 'ResourceReceipt': str(path)}

    def qualify(self, ident):
        self.verify()
        receipt = self.births[ident]
        if digest(receipt['journal']) != receipt['journal_sha256']:
            raise RuntimeError('PG journal changed')
        return receipt

    def close(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.send_signal(2)  # PostgreSQL fast shutdown, owns only this child.
                self.process.wait(timeout=15)
            if self.socket_path.exists():
                raise RuntimeError('PG socket survived process exit')
        if self.log:
            self.log.close()
        print(json.dumps({'pg_version': getattr(self, 'version', None), 'kernel': self.identity,
                          'births': list(self.births.values()), 'commands': self.commands,
                          'pg_exit': self.process.returncode if self.process else None,
                          'cleanup': 'owned PG child stopped; socket absent'}), flush=True)


def daemon_process_identity(process, uid):
    # This adapter is container-only: /proc and Popen use the same PID namespace.
    if process.poll() is not None:
        raise RuntimeError('owned daemon exited')
    proc = Path('/proc') / str(process.pid)
    status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
    if (status['NSpid'].split() != [str(process.pid)] or int(status['PPid']) != os.getpid() or
            any(int(v) != uid for v in status['Uid'].split()) or status['Groups'].strip() or
            status['NoNewPrivs'].strip() != '1' or int(status['CapEff'], 16)):
        raise RuntimeError('owned daemon PID/parent/UID/capability mismatch')
    return (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19]


def observe_daemon(process, uid, executable, listener):
    """Fixed fork-only observer; no exec/dumpable window or client-selected code.

    Same-UID signals can deny service, but cannot supply a successful observation.
    The parent requires a complete private packet, normal exit and stable child.
    """
    start = daemon_process_identity(process, uid)
    expected_exe = executable.stat()
    expected_hash = digest(executable)
    namespaces = {n: os.readlink('/proc/self/ns/'+n) for n in ('pid', 'net', 'mnt')}
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    parent.settimeout(3)
    child.settimeout(3)
    # Close inherited installer/SQL/daemon descriptors in the observer. It must
    # retain only its private IPC; daemon/service cannot open its nondumpable fd.
    inherited = [int(p.name) for p in Path('/proc/self/fd').iterdir()]
    observer = os.fork()
    if observer == 0:
        try:
            parent.close()
            os.setsid()  # A different-UID app cannot use the same-session SIGCONT exception.
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(4, 0, 0, 0, 0) or Path('/proc/sys/fs/suid_dumpable').read_text().strip() != '0':
                os._exit(1)
            demote(uid)
            if libc.prctl(4, 0, 0, 0, 0) or libc.prctl(3, 0, 0, 0, 0) != 0:
                os._exit(1)
            for fd in inherited:
                if fd != child.fileno():
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            if {n: os.readlink('/proc/self/ns/'+n) for n in namespaces} != namespaces:
                os._exit(1)
            child.sendall(b'ready')
            if child.recv(16) != b'observe':
                os._exit(1)
            proc = Path('/proc') / str(process.pid)
            before = (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19]
            with (proc / 'exe').open('rb') as stream:
                exe = os.fstat(stream.fileno())
                hasher = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    hasher.update(chunk)
                exe_hash = hasher.hexdigest()
            ns = {n: os.readlink(proc / 'ns' / n) for n in namespaces}
            fds = set()
            for fd in (proc / 'fd').iterdir():
                try:
                    fds.add(os.readlink(fd))
                except FileNotFoundError:
                    continue
            after = (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19]
            if (before != start or after != start or ns != namespaces or
                    (exe.st_dev, exe.st_ino) != (expected_exe.st_dev, expected_exe.st_ino) or
                    exe_hash != expected_hash or 'socket:['+listener+']' not in fds):
                os._exit(1)
            child.sendall(json.dumps({'pid': process.pid, 'start_time': start,
                                     'exe_device': exe.st_dev, 'exe_inode': exe.st_ino,
                                     'exe_sha256': exe_hash, 'namespaces': ns,
                                     'socket_inode': listener}).encode())
            os._exit(0)
        except BaseException:
            os._exit(1)
    child.close()
    reaped = False
    try:
        if parent.recv(32) != b'ready':
            raise RuntimeError('observer readiness failed')
        status = dict(line.split(':', 1) for line in Path(f'/proc/{observer}/status').read_text().splitlines() if ':' in line)
        observer_stat = Path(f'/proc/{observer}/stat').read_text().rsplit(')', 1)[1].split()
        observer_start = observer_stat[19]
        if int(observer_stat[3]) != observer:
            raise RuntimeError('observer session isolation missing')
        if (status['NSpid'].split() != [str(observer)] or int(status['PPid']) != os.getpid() or any(int(v) != uid for v in status['Uid'].split()) or
                status['Groups'].strip() or status['NoNewPrivs'].strip() != '1' or int(status['CapEff'], 16) or
                Path(f'/proc/{observer}/status').stat().st_uid != 0):
            raise RuntimeError('observer credential/dumpability mismatch')
        parent.sendall(b'observe')
        packet, _, flags, _ = parent.recvmsg(4096)
        if flags & socket.MSG_TRUNC or not packet:
            raise RuntimeError('observer output missing or truncated')
        # EOF, not an additional attacker-controlled packet, closes the protocol.
        if parent.recv(1):
            raise RuntimeError('observer trailing output')
        if Path(f'/proc/{observer}/stat').read_text().rsplit(')', 1)[1].split()[19] != observer_start:
            raise RuntimeError('observer PID identity changed')
        _, exit_status = os.waitpid(observer, 0)
        reaped = True
        if exit_status != 0:
            raise RuntimeError('observer abnormal exit')
        result = json.loads(packet)
        expected = {'pid': process.pid, 'start_time': start, 'exe_device': expected_exe.st_dev,
                    'exe_inode': expected_exe.st_ino, 'exe_sha256': expected_hash,
                    'namespaces': namespaces, 'socket_inode': listener}
        if result != expected or daemon_process_identity(process, uid) != start:
            raise RuntimeError('observer identity changed')
        return result
    finally:
        parent.close()
        if not reaped:
            # Unreaped fork child belongs to this call; never an adopted PID.
            try:
                os.kill(observer, 9)
            except ProcessLookupError:
                pass
            os.waitpid(observer, 0)


class CombinedRedis(OwnedRedis):
    """Joint tier only; host Redis namespace/proc guard remains unchanged."""
    def __init__(self, root, service_uid):
        # Root reserves this separate daemon principal before any app is started.
        super().__init__(root, service_uid + 1)
        self.service_uid = service_uid
        try:
            pwd.getpwuid(self.uid)
            raise ValueError('Redis daemon UID already registered')
        except KeyError:
            pass
        for status in Path('/proc').glob('[0-9]*/status'):
            if re.search(r'^Uid:\s+'+str(self.uid)+r'\s', status.read_text(), re.M):
                raise ValueError('Redis daemon UID already active')

    def require_namespace(self):
        # The caller has already verified the constrained direct-root container.
        caps = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
        if int(caps['CapBnd'], 16) & ((1 << 19) | (1 << 21)):
            raise ValueError('joint observer tier forbids ptrace and sys_admin capabilities')

    def kernel_binding(self):
        expected = '0100007F:' + format(self.address[1], '04X')
        rows = [line.split() for line in Path('/proc/net/tcp').read_text().splitlines()[1:]]
        rows = [row for row in rows if row[1] == expected and row[3] == '0A']
        if len(rows) != 1 or int(rows[0][7]) != self.uid:
            raise RuntimeError('Redis loopback listener ownership mismatch')
        observed = observe_daemon(self.process, self.uid, self.executable, rows[0][9])
        identity = {'proc_pid': self.process.pid, 'start_time': observed['start_time'],
                    'socket_inode': observed['socket_inode'], 'exe_device': observed['exe_device'],
                    'exe_inode': observed['exe_inode'], 'pid_namespace': observed['namespaces']['pid'],
                    'exe_sha256': observed['exe_sha256']}
        if self.kernel_identity is not None and identity != self.kernel_identity:
            raise RuntimeError('Redis kernel identity changed')
        return identity

    def start(self):
        env = super().start()
        self.receipt['daemon_uid'] = self.uid
        self.receipt['service_uid'] = self.service_uid
        (self.root / 'redis-resource.json').write_text(json.dumps(self.receipt, sort_keys=True))
        return env


class CombinedPostgres(OwnedPostgres):
    def birth(self):
        result = super().birth()
        receipt = json.loads(Path(result['ResourceReceipt']).read_text())
        # These pre-existing tables are only schema prerequisites of the S1
        # fixture. No write/ownership rights are required by its four scenarios.
        for table in ('auth_flows', 'two_fas', 'two_fa_backup_codes', 'passkey_credentials',
                      'user_oauth_bindings', 'external_identity_claims'):
            self.sql(receipt['database'], f"GRANT SELECT ON TABLE public.{table} TO {receipt['role']};")
        return result

    def verify(self):
        daemon_process_identity(self.process, self.daemon_uid)
        st = self.socket_dir.lstat()
        socket_stat = self.socket_path.lstat()
        if (st.st_uid != self.daemon_uid or st.st_mode & 0o022 or not stat.S_ISDIR(st.st_mode) or
                not stat.S_ISSOCK(socket_stat.st_mode) or socket_stat.st_uid != self.daemon_uid):
            raise RuntimeError('PG socket ownership mismatch')
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(2)
            conn.connect(str(self.socket_path))
            peer = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if peer[:2] != (self.process.pid, self.daemon_uid):
                raise RuntimeError('PG endpoint peer mismatch')
        rows = [line.split() for line in Path('/proc/net/unix').read_text().splitlines()[1:]]
        rows = [r for r in rows if len(r) == 8 and r[7] == str(self.socket_path) and r[3] == '00010000']
        if len(rows) != 1:
            raise RuntimeError('PG listener unavailable')
        observed = observe_daemon(self.process, self.daemon_uid, self.bin / 'postgres', rows[0][6])
        identity = {'pid': self.process.pid, 'daemon_uid': self.daemon_uid,
                    'start_time': observed['start_time'], 'socket_inode': rows[0][6],
                    'socket_file_inode': socket_stat.st_ino, 'directory_inode': st.st_ino,
                    'exe_inode': observed['exe_inode'], 'exe_device': observed['exe_device'],
                    'pid_namespace': observed['namespaces']['pid'], 'net_namespace': observed['namespaces']['net'],
                    'exe_sha256': observed['exe_sha256']}
        if self.identity is not None and self.identity != identity:
            raise RuntimeError('PG resource replaced')
        self.identity = identity
        return identity


def postgres_container(bundle, tier='postgres'):
    # Host controller alone operates Docker. No socket, host mount, privileged
    # flag, SYS_ADMIN, sudo/ip or nested namespace tools enter the container.
    image_id = LIFECYCLE_MYSQL_IMAGE if tier == 'lifecycle-mysql' else MYSQL_IMAGE if tier in ('wallet-mysql', 'metadata-mysql') else PG_IMAGE if tier in ('postgres', 'wallet-postgres', 'metadata-postgres') else JOINT_IMAGE
    nonce = secrets.token_hex(12)
    image = json.loads(subprocess.check_output(['docker', 'image', 'inspect', image_id]))[0]
    if image['Id'] != image_id:
        raise ValueError('pinned PG image mismatch')
    argv = ['docker', 'create', '--pull=never', '--name', 'newapi-pg-'+nonce,
            '--label', 'newapi.bootstrap.owner='+nonce, '--network=none', '--read-only',
            '--security-opt', 'no-new-privileges', '--memory=2g', '--memory-swap=2g', '--pids-limit=128',
            '--cap-drop=ALL', '--cap-add=CHOWN', '--cap-add=DAC_OVERRIDE', '--cap-add=FOWNER',
            '--cap-add=SETUID', '--cap-add=SETGID', '--cap-add=KILL', *(['--cap-add=SYS_PTRACE'] if tier == 'postgres' else []),
            '--tmpfs', '/run:rw,exec,nosuid,nodev,size=4g,mode=0755',
            '--tmpfs', ('/var/lib/mysql' if tier in ('wallet-mysql', 'metadata-mysql', 'lifecycle-mysql') else '/var/lib/postgresql/data')+':rw,noexec,nosuid,nodev,size=1m,mode=0700',
            '--entrypoint', '/bin/sh', image_id, '-c', 'exec sleep 600']
    cid = subprocess.check_output(argv, text=True).strip()
    try:
        info = json.loads(subprocess.check_output(['docker','inspect',cid]))[0]
        if any(x['Type']=='volume' for x in info['Mounts']):
            raise ValueError('unexpected PG volume')
        command(['docker','start',cid])
        command(['docker','exec',cid,'mkdir','/run/input'])
        archive = subprocess.Popen(['tar', '-C', str(bundle), '-cf', '-', '.'], stdout=subprocess.PIPE)
        try:
            command(['docker','exec','-i',cid,'tar','-xf','-','-C','/run/input'], stdin=archive.stdout)
        finally:
            archive.stdout.close()
            if archive.wait() != 0:
                raise RuntimeError('bundle streaming failed')
        remote_hash = subprocess.check_output(['docker','exec',cid,'sha256sum','/run/input/runner.py'], text=True).split()[0]
        if remote_hash != digest(bundle / 'runner.py'):
            raise RuntimeError('container runner hash mismatch')
        # Detached execution keeps the authoritative result inside the owned
        # container; a Docker attach EOF cannot be mistaken for test completion.
        command(['docker','exec','-d',cid,'/bin/sh','-c',
                 'python3 /run/input/runner.py '+('_wallet_run' if tier.startswith('wallet-') or tier in METADATA_TIERS or tier in LIFECYCLE_TIERS else '_run')+' /run/input '+tier+' > /run/result.log 2>&1; printf "%s\\n" "$?" > /run/result.exit'])
        deadline = time.monotonic() + 300
        while True:
            receipt = subprocess.run(['docker','exec',cid,'cat','/run/result.exit'], capture_output=True, text=True)
            if re.fullmatch(r'[0-9]+\s*', receipt.stdout):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError('PG execution result deadline exceeded')
            time.sleep(0.2)
        output = subprocess.check_output(['docker','exec',cid,'cat','/run/result.log']).decode(errors='replace')
        print(output, end='', flush=True)
        print(json.dumps({'container_execution_exit': int(receipt.stdout)}), flush=True)
        validate_required_output(tier, output, int(receipt.stdout))
    finally:
        info = json.loads(subprocess.check_output(['docker','inspect',cid]))[0]
        if info['Config']['Labels'].get('newapi.bootstrap.owner') != nonce or info['Image'] != image_id:
            raise RuntimeError('container cleanup ownership mismatch')
        command(['docker','stop','--time','20',cid])
        command(['docker','rm','-v',cid])
        remaining = subprocess.check_output(['docker','ps','-a','--no-trunc','--filter','id='+cid,'--format','{{.ID}}']).strip()
        if remaining:
            raise RuntimeError('owned PG container remains')
        print(json.dumps({'image': image_id, 'cid': cid, 'cleanup': 'owned PG container removed; no volumes'}), flush=True)


def trusted_run(bundle, tier="sqlite"):
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise ValueError('installer requires Linux root; use the normal prepare entry')
    bundle = Path(bundle).resolve(strict=True)
    metadata = json.loads((bundle / 'manifest.json').read_text())
    if not isinstance(metadata.get('files'), dict) or not isinstance(metadata.get('entries'), list):
        raise ValueError('invalid bundle manifest')
    for entry in metadata['entries']:
        cwd = Path(entry['cwd'])
        if not re.fullmatch(r'test-[0-9]+', entry['binary']) or cwd.is_absolute() or '..' in cwd.parts:
            raise ValueError('test entry path escape')
        if entry['binary'] not in metadata['files'] or not isinstance(entry['run'], str):
            raise ValueError('unbound test entry')
    for required in ('new-api', 'runner.py'):
        if required not in metadata['files']:
            raise ValueError('missing producer input')
    if tier not in ('sqlite', 'ordinary-audit', *ORDINARY_AUDIT_SHARED, 'postgres', 'postgres-redis') or metadata.get('tier', 'sqlite') != tier:
        raise ValueError('resource tier mismatch')
    if tier == 'ordinary-audit' and (len(metadata['entries']) != 1 or
            metadata['entries'][0]['cwd'] != 'router' or
            metadata['entries'][0]['run'] != ORDINARY_AUDIT_SELECTOR):
        raise ValueError('ordinary audit mandatory inventory mismatch')
    if tier in ('postgres', 'postgres-redis') and (len(metadata['entries']) != 1 or metadata['entries'][0]['cwd'] != 'router' or metadata['entries'][0]['run'] != (PG_SELECTOR if tier == 'postgres' else JOINT_SELECTOR)):
        raise ValueError('PG mandatory inventory mismatch')
    if tier in ('postgres', 'postgres-redis'):
        # Direct-root is only the fixed container path, never a host PG launch.
        rootfs = os.statvfs('/')
        mounts = [line.split() for line in Path('/proc/mounts').read_text().splitlines()]
        run_mounts = [row for row in mounts if row[1] == '/run']
        caps = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
        if (not rootfs.f_flag & os.ST_RDONLY or
                Path('/proc/1/comm').read_text().strip() != 'sleep' or
                len(run_mounts) != 1 or run_mounts[0][2] != 'tmpfs' or
                not {'nosuid', 'nodev'}.issubset(set(run_mounts[0][3].split(','))) or
                'noexec' in run_mounts[0][3].split(',') or
                os.statvfs('/run').f_blocks * os.statvfs('/run').f_frsize > 4 * 1024**3 or
                int(caps['CapBnd'].strip(), 16) & (1 << 21) or caps['NoNewPrivs'].strip() != '1'):
            raise ValueError('PG direct-root requires the constrained private container')
        if tier == 'postgres-redis' and int(caps['CapBnd'].strip(), 16) & (1 << 19):
            raise ValueError('joint tier forbids SYS_PTRACE')
    root = Path(tempfile.mkdtemp(prefix='newapi-bootstrap-tests-', dir='/run'))
    root.chmod(0o755)
    root_stat = root.stat()
    installer = None
    redis_resource = None
    pg_resource = None
    thread = None
    status = 1
    completed = []
    try:
        # Snapshot and verify before any execution; no service writes to tools.
        for name, expected in metadata['files'].items():
            rel = Path(name)
            if rel.is_absolute() or '..' in rel.parts:
                raise ValueError('bundle path escape')
            src = bundle / rel
            if any(p.is_symlink() for p in [src, *src.parents]) or not src.is_file():
                raise ValueError('bundle symlink or non-file')
            dst = root / 'bundle' / rel
            dst.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
            dst.chmod(0o755 if src.stat().st_mode & 0o111 else 0o644)
            if digest(dst) != expected:
                raise ValueError('bundle hash mismatch')
        if digest(root / 'bundle/runner.py') != digest(Path(__file__)):
            raise ValueError('runner producer mismatch')
        # Freeze the verified manifest beside root-owned tools before service launch.
        (root / 'bundle/manifest.json').write_text(json.dumps(metadata, sort_keys=True))
        # No persistent account/sudoers changes. Reserve an unused numeric UID.
        uid = 200000 + secrets.randbelow(100000000)
        try:
            pwd.getpwuid(uid)
            raise ValueError('service UID already exists')
        except KeyError:
            pass
        for proc in Path('/proc').glob('[0-9]*/status'):
            try:
                if re.search(r'^Uid:\s+' + str(uid) + r'\s', proc.read_text(), re.M):
                    raise ValueError('service UID already active')
            except (FileNotFoundError, PermissionError):
                pass
        for name in ('journals', 'producer-tests', 'tmp'):
            (root / name).mkdir(mode=0o755)
        os.chown(root / 'tmp', uid, uid)
        launcher = root / 'client'
        launcher.write_text('#!/bin/sh\nexec /usr/bin/python3 ' + str(root / 'bundle/runner.py') + ' client ' + str(root / 'installer.sock') + ' "$@"\n')
        launcher.chmod(0o755)
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(root / 'tmp'), 'TMPDIR': str(root / 'tmp'), 'NEWAPI_TEST_PROFILE': 'isolated-ci', 'NEWAPI_BOOTSTRAP_CLIENT': str(launcher), 'NEWAPI_BOOTSTRAP_ENGINE': 'sqlite'}
        if tier in ('postgres', 'postgres-redis'):
            pg_resource = OwnedPostgres(root, uid) if tier == 'postgres' else CombinedPostgres(root, uid)
            env.update(pg_resource.start())
            env['GOMAXPROCS'] = '2'
            if tier == 'postgres-redis':
                redis_resource = CombinedRedis(root, uid)
                env.update(redis_resource.start())
                env['NEWAPI_BOOTSTRAP_TIER'] = tier
        elif any(entry['cwd'] == 'router' for entry in metadata['entries']):
            redis_resource = OwnedRedis(root, uid)
            env.update(redis_resource.start())
        # Root-only negative producer tests execute separately, not skipped away.
        for entry in metadata['entries']:
            if entry['cwd'] == 'model':
                print('BOOTSTRAP_TEST_START '+json.dumps(dict(entry, phase='producer')), flush=True)
                command([str(root / 'bundle' / entry['binary']), '-test.run=^' + PRODUCER_TEST + '$', '-test.v'], cwd=root / 'bundle/source/model', env=dict(env, NEWAPI_BOOTSTRAP_ROOT_TEST_DIR=str(root / 'producer-tests')))
                print('BOOTSTRAP_TEST_END '+json.dumps(dict(entry, phase='producer', exit=0)), flush=True)
        installer = Installer(root, uid, redis_resource, pg_resource, metadata)
        thread = threading.Thread(target=installer.serve)
        thread.start()
        for entry in metadata['entries']:
            binary = entry['binary']
            cwd = Path(entry['cwd'])
            if not re.fullmatch(r'test-[0-9]+', binary) or cwd.is_absolute() or '..' in cwd.parts:
                raise ValueError('test entry path escape')
            special = DIALECT_TESTS.get(str(cwd), ())
            skip = '|'.join(('^' + PRODUCER_TEST + '$', *('^' + n + '$' for n in special)))
            argv = [str(root / 'bundle' / binary), '-test.v', '-test.count=1', '-test.run=' + entry['run'], '-test.skip=' + skip]
            print('BOOTSTRAP_TEST_START '+json.dumps(dict(entry, phase='ordinary')), flush=True)
            if redis_resource:
                redis_resource.verify()
            if pg_resource or tier == 'ordinary-audit':
                if pg_resource:
                    pg_resource.verify()
                installer.process_ready.clear()
                with subprocess.Popen(argv, cwd=root / 'bundle/source' / cwd, env=env, preexec_fn=lambda: demote(uid), stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as process:
                    installer.process = process
                    installer.process_ready.set()
                    try:
                        stdout, _ = process.communicate(timeout=180)
                    except BaseException:
                        process.kill()
                        process.communicate()
                        raise
                    result = subprocess.CompletedProcess(argv, process.returncode, stdout)
                output = result.stdout.decode(errors='replace')
                print(output, end='', flush=True)
                validate_required_output(tier, output, result.returncode)
                if pg_resource:
                    pg_resource.verify()
            else:
                command(argv, cwd=root / 'bundle/source' / cwd, env=env, preexec_fn=lambda: demote(uid))
            if redis_resource:
                redis_resource.verify()
            print('BOOTSTRAP_TEST_END '+json.dumps(dict(entry, phase='ordinary', exit=0)), flush=True)
            for name in special:
                # Go's regexp syntax is not Python's; ask the test binary whether
                # the requested top-level selector includes this dialect test.
                listing = subprocess.check_output([str(root / 'bundle' / binary), '-test.list=' + entry['run'].split('/')[0]], env=env, preexec_fn=lambda: demote(uid), text=True)
                if name in listing.splitlines():
                    print('BOOTSTRAP_TEST_START '+json.dumps(dict(entry, phase='sqlite-dialect', run='^'+name+'$/sqlite')), flush=True)
                    command([str(root / 'bundle' / binary), '-test.v', '-test.count=1', '-test.run=^' + name + '$/sqlite'], cwd=root / 'bundle/source' / cwd, env=env, preexec_fn=lambda: demote(uid))
                    print('BOOTSTRAP_TEST_END '+json.dumps(dict(entry, phase='sqlite-dialect', exit=0)), flush=True)
            completed.append(entry)
        # Explicitly prove protected anchor ownership from the actual service UID.
        journals = list((root / 'journals').glob('*.json'))
        if journals:
            probe = 'import os,sys\np=sys.argv[1]\nfor f in (lambda:os.chmod(p,0o666),lambda:open(p,"w")):\n try:f()\n except PermissionError:continue\n raise SystemExit(1)\nassert os.getuid()!=0\nassert "NoNewPrivs:\\t1" in open("/proc/self/status").read()\n'
            command(['/usr/bin/python3', '-c', probe, str(journals[0])], env=env, preexec_fn=lambda: demote(uid))
        status = 0
    finally:
        if installer:
            installer.stopped.set()
            thread.join(timeout=100)
            installer.server.close()
            if thread.is_alive():
                raise RuntimeError('installer did not stop; preserve owned run')
            print(json.dumps({'producer_sha256': digest(root / 'bundle/new-api'), 'fixture_receipts': installer.receipts, 'service_uid': uid, 'status': status}), flush=True)
        if redis_resource:
            redis_resource.close()
        if pg_resource:
            pg_resource.close()
        # Exact inode/device and root ownership: never clean an adopted directory.
        current = root.lstat()
        if (current.st_dev, current.st_ino, current.st_uid) != (root_stat.st_dev, root_stat.st_ino, 0) or not stat.S_ISDIR(current.st_mode):
            raise RuntimeError('cleanup ownership mismatch')
        shutil.rmtree(root)
        print(json.dumps({'cleanup': 'removed owned ephemeral run', 'run': str(root), 'exit': status}), flush=True)

    if 'invocation' in metadata:
        if completed != metadata['entries'] or not re.fullmatch(r'[0-9a-f]{64}', metadata['invocation']):
            raise RuntimeError('incomplete tier execution')
        print('BOOTSTRAP_TIER_RESULT '+json.dumps({
            'tier': tier, 'invocation': metadata['invocation'],
            'manifest_sha256': digest(bundle / 'manifest.json'),
            'producer_sha256': metadata['files']['new-api'], 'runner_sha256': metadata['files']['runner.py'],
            'entries': completed, 'required_leaves': required_leaves(tier), 'exit': status, 'cleanup': True}, sort_keys=True), flush=True)


# Explicit fixed-actor read tier; existing default resource scheduling is unchanged.
ADMISSION_CASES = ('allowed', 'held', 'send_claimed', 'task_held', 'task_send_claimed',
                   'notfound', 'storeerror', 'deadline', 'inflight', 'model_first', 'unrelated', 'shutdown')
ADMISSION_SELECTOR = '^TestAdmission(Unit|Live)$'


def prepare_admission(args):
    if sys.platform != 'linux' or args.package or args.run != '.' or not args.admission_assets:
        raise ValueError('admission requires Linux, exact inventory and real --admission-assets')
    repo = Path(__file__).resolve().parents[2]
    bundle = Path(args.bundle).absolute()
    if bundle == repo or repo in bundle.parents:
        raise ValueError('bundle must be outside checkout')
    assets = Path(args.admission_assets).resolve(strict=True)
    if not (assets / 'index.html').is_file():
        raise ValueError('real embed assets missing')
    bundle.mkdir(mode=0o700, parents=True, exist_ok=False)
    source = bundle / 'source'
    source.mkdir()
    names = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=repo).decode().split('\0')
    for name in filter(None, names):
        src, dst = repo/name, source/name
        if src.is_symlink() or not src.is_file():
            raise ValueError('nonregular source')
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        dst.chmod(0o755 if src.stat().st_mode & 0o111 else 0o644)
    if any(p.is_symlink() for p in assets.rglob('*')):
        raise ValueError('asset symlink')
    shutil.copytree(assets, source/'web/dist')
    env = dict(os.environ, GOWORK='off')
    command(['go', 'build', '-mod=readonly', '-p=2', '-o', str(bundle/'new-api'), '.'], cwd=source, env=env)
    command(['go', 'build', '-mod=readonly', '-p=2', '-o', str(bundle/'admission-broker'), './cmd/admission-broker'], cwd=source, env=env)
    command(['go', 'test', '-c', '-mod=readonly', '-p=2', '-o', str(bundle/'test-0'), './internal/admissionbroker'], cwd=source, env=env)
    shutil.copyfile(__file__, bundle/'runner.py')
    metadata = {'tier': 'admission', 'entries': [{'binary': 'test-0', 'cwd': 'internal/admissionbroker', 'run': ADMISSION_SELECTOR}],
                'files': {str(p.relative_to(bundle)): digest(p) for p in sorted(bundle.rglob('*')) if p.is_file()}}
    (bundle/'manifest.json').write_text(json.dumps(metadata, sort_keys=True))
    print(json.dumps({'scope': 'explicit-admission-only', 'manifest_sha256': digest(bundle/'manifest.json'), 'packages': 1}), flush=True)
    if not args.prepare_only:
        execute_prepared(bundle, 'admission')


def admission_identity(process, uid, executable, listener=None):
    # Fixed fork observer, same UID as target but nondumpable; no external code,
    # PID, path or command accepted from the service qualification packet.
    start = daemon_process_identity(process, uid)
    namespaces = {n: os.readlink('/proc/self/ns/'+n) for n in ('pid', 'mnt', 'net')}
    expected_hash, expected_stat = digest(executable), executable.stat()
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    parent.settimeout(3)
    inherited = [int(p.name) for p in Path('/proc/self/fd').iterdir()]
    observer = os.fork()
    if observer == 0:
        try:
            parent.close()
            os.setsid()
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(4, 0, 0, 0, 0) or Path('/proc/sys/fs/suid_dumpable').read_text().strip() != '0': os._exit(1)
            demote(uid)
            if libc.prctl(4, 0, 0, 0, 0) or libc.prctl(3, 0, 0, 0, 0) != 0: os._exit(1)
            for fd in inherited:
                if fd != child.fileno():
                    try: os.close(fd)
                    except OSError: pass
            proc = Path('/proc')/str(process.pid)
            stat_before = (proc/'stat').read_text().rsplit(')', 1)[1].split()[19]
            actual = (proc/'exe').stat()
            if ((actual.st_dev, actual.st_ino) != (expected_stat.st_dev, expected_stat.st_ino) or
                    digest(proc/'exe') != expected_hash or stat_before != start or
                    {n: os.readlink(proc/'ns'/n) for n in namespaces} != namespaces): os._exit(1)
            if listener:
                fds = {os.readlink(fd) for fd in (proc/'fd').iterdir()}
                if 'socket:['+listener+']' not in fds: os._exit(1)
            if (proc/'stat').read_text().rsplit(')', 1)[1].split()[19] != start: os._exit(1)
            child.sendall(json.dumps({'PID': process.pid, 'UID': uid, 'StartTime': start,
                'ExeSHA256': expected_hash, 'PIDNamespace': namespaces['pid'],
                'MountNamespace': namespaces['mnt'], 'NetworkNamespace': namespaces['net'],
                'SocketInode': listener or ''}).encode())
            os._exit(0)
        except BaseException:
            os._exit(1)
    child.close()
    try:
        packet, _, flags, _ = parent.recvmsg(4096)
        if flags & socket.MSG_TRUNC or not packet or parent.recv(1):
            raise ValueError('observer packet invalid')
        _, status = os.waitpid(observer, 0)
        observer = None
        if status or daemon_process_identity(process, uid) != start:
            raise ValueError('observer identity changed')
        return json.loads(packet)
    finally:
        parent.close()
        if observer:
            try: os.kill(observer, 9)
            except ProcessLookupError: pass
            os.waitpid(observer, 0)


class AdmissionFixture:
    def __init__(self, root, metadata, service, service_uid, broker_uid, case):
        import sqlite3
        self.root, self.metadata, self.service = root, metadata, service
        self.service_uid, self.broker_uid = service_uid, broker_uid
        self.case, self.process = case, None
        self.closed = False
        self.lock = None
        self.event_buffer = b''
        self.event_r = self.ack_w = None
        self.stopped = threading.Event()
        self.assigned = threading.Event()
        self.thread = None
        root.mkdir(mode=0o755)
        self.identity = root.stat()
        for name, gid, mode in [('data', broker_uid, 0o750), ('socket', broker_uid, 0o771), ('control', 0, 0o755)]:
            p = root/name; p.mkdir(); os.chown(p, 0, gid); p.chmod(mode)
        completed_birth = outer_birth('sqlite', 'admission')
        if completed_birth is not None:
            self.db, self.journal = Path(completed_birth['target']), Path(completed_birth['journal'])
            print(json.dumps({'admission_birth': case, 'exit': 0,
                              'output_sha256': completed_birth['output_sha256']}), flush=True)
        else:
            self.db, self.journal = root/'data/main.db', root/'control/birth.json'
            producer = root.parent/'bundle/new-api'
            birth = subprocess.run([str(producer), 'db-bootstrap', 'fresh', '--engine', 'sqlite', '--target', str(self.db), '--journal', str(self.journal)],
                                   env={'PATH':'/usr/bin:/bin'}, capture_output=True, timeout=90)
            print(json.dumps({'admission_birth': case, 'exit': birth.returncode, 'output_sha256': hashlib.sha256(birth.stdout+birth.stderr).hexdigest()}), flush=True)
            if birth.returncode or json.loads(self.journal.read_text())['phase'] != 'READY':
                raise ValueError('permanent birth failed')
        if completed_birth is not None:
            os.chown(self.db.parent, 0, broker_uid); self.db.parent.chmod(0o770)
        os.chown(self.db, 0, broker_uid); self.db.chmod(0o660); (root/'data').chmod(0o770)
        os.chown(self.journal,0,broker_uid);self.journal.chmod(0o640)
        conn = sqlite3.connect(self.db)
        conn.execute('PRAGMA journal_mode=WAL')
        if case != 'notfound':
            conn.execute("INSERT INTO users(id,username,password,quota,used_quota,auth_version) VALUES(1,'admission-synthetic','',100,0,1)")
        if case in ('held', 'send_claimed'):
            fields = conn.execute('PRAGMA table_info(oauth_derived_text_charges)').fetchall()
            values = {r[1]: (0 if 'int' in r[2].lower() else '') for r in fields if r[3]}
            values.update(ref='c'*64, user_id=1, state=case)
            cols = list(values)
            conn.execute('INSERT INTO oauth_derived_text_charges('+','.join('"'+c+'"' for c in cols)+') VALUES('+','.join('?' for c in cols)+')', list(values.values()))
        if case in ('task_held', 'task_send_claimed'):
            conn.execute('INSERT INTO tasks(user_id,billing_protocol,billing_state) VALUES(1,1,?)', (case[5:],))
        if case == 'storeerror': conn.execute('DROP TABLE oauth_derived_text_charges')
        conn.commit(); conn.close()
        self.before = self.snapshot()
        self.binding = secrets.token_hex(32)
        self.socket = root/'socket/broker.sock'
        self.authority = socket.socket(socket.AF_UNIX)
        self.authority.bind(str(root/'control/authority.sock')); os.chmod(root/'control/authority.sock', 0o666)
        self.authority.listen(8); self.authority.settimeout(0.2)
        worker = case in ('inflight', 'model_first', 'unrelated', 'shutdown')
        self.executable = root.parent/'bundle'/('test-0' if worker else 'admission-broker')
        st = self.db.stat()
        self.config = {'Version':1, 'Actor':1, 'Database':str(self.db), 'Journal':str(self.journal), 'JournalSHA256':digest(self.journal),
            'Socket':str(self.socket), 'Authority':str(root/'control/authority.sock'), 'Binding':self.binding,
            'Capability':secrets.token_hex(32), 'ManifestSHA256':digest(root.parent/'bundle/manifest.json'),
            'BrokerSHA256':digest(self.executable), 'ServiceSHA256':digest(root.parent/'bundle/test-0'),
            'BrokerUID':broker_uid, 'ServiceUID':service_uid, 'DatabaseDevice':st.st_dev, 'DatabaseInode':st.st_ino}
        for name, uid in [('broker.json',broker_uid),('service.json',service_uid)]:
            path=root/'control'/name;path.write_text(json.dumps(self.config));os.chown(path,0,uid);path.chmod(0o640)
        self.thread = threading.Thread(target=self.qualifications)
        self.thread.start()
        env = {'PATH':'/usr/bin:/bin','SQL_MAX_OPEN_CONNS':'1','SQL_MAX_IDLE_CONNS':'1'}
        argv = [str(self.executable),str(root/'control/broker.json')]
        if worker:
            env.update(ADMISSION_WORKER_CONFIG=str(root/'control/broker.json'), ADMISSION_WORKER_CASE=case)
            argv=[str(self.executable),'-test.run=^TestAdmissionWorker$','-test.v']
        self.log=(root/'control/broker.log').open('w+b')
        pass_fds=()
        if worker:
            self.event_r,event_w=os.pipe();ack_r,self.ack_w=os.pipe()
            env.update(ADMISSION_EVENT_FD=str(event_w),ADMISSION_ACK_FD=str(ack_r))
            pass_fds=(event_w,ack_r)
        self.process=subprocess.Popen(argv,env=env,preexec_fn=lambda:demote(broker_uid),stdout=subprocess.PIPE,stderr=self.log,pass_fds=pass_fds)
        if worker:
            os.close(event_w);os.close(ack_r)
        self.assigned.set()
        import select
        ready=b'';until=time.monotonic()+15
        while not any(line==b'READY' for line in ready.splitlines()):
            left=until-time.monotonic()
            if left<=0 or not select.select([self.process.stdout],[],[],left)[0]:raise RuntimeError('broker readiness timeout')
            part=os.read(self.process.stdout.fileno(),1024)
            if not part:raise RuntimeError('broker exited before readiness')
            ready+=part
            if len(ready)>4096:raise RuntimeError('broker startup output limit')
        self.log.write(ready);self.log.flush()
        if case in ('deadline','inflight'):
            self.lock=sqlite3.connect(self.db)
            self.lock.execute('BEGIN IMMEDIATE')
        self.initial_kernel=admission_identity(self.process,broker_uid,self.executable,self.listener_inode())
        print(json.dumps({'admission_kernel_binding':case,'broker':self.initial_kernel,'service':admission_identity(service,service_uid,root.parent/'bundle/test-0'),'database_device':st.st_dev,'database_inode':st.st_ino,'journal_sha256':self.config['JournalSHA256']}),flush=True)
        if case=='allowed':self.startup_negatives()

    def startup_negatives(self):
        # Fixed launcher tests only. The service cannot choose a mutation or
        # supply a pathname, UID, SQL statement, seed or executable here.
        checks=[]
        for label in ('wrong_hash','wrong_uid','missing_journal','journal_hash','database_inode','writable_config','symlink_config','missing_authority'):
            cfg=dict(self.config);uid=self.broker_uid
            cfg['Socket']=str(self.root/'socket'/'negative.sock')
            if label=='wrong_hash':cfg['BrokerSHA256']='0'*64
            if label=='wrong_uid':uid=self.service_uid
            if label=='missing_journal':cfg['Journal']=str(self.root/'control'/'absent')
            if label=='journal_hash':cfg['JournalSHA256']='0'*64
            if label=='database_inode':cfg['DatabaseInode']+=1
            if label=='missing_authority':cfg['Authority']=str(self.root/'control'/'absent.sock')
            path=self.root/'control'/'negative.json'
            path.write_text(json.dumps(cfg));os.chown(path,0,uid);path.chmod(0o660 if label=='writable_config' else 0o640)
            argument=path
            if label=='symlink_config':
                argument=self.root/'control'/'negative-link.json';argument.symlink_to(path)
            probe=subprocess.run([str(self.executable),str(argument)],env={'PATH':'/usr/bin:/bin'},preexec_fn=lambda:demote(uid),capture_output=True,timeout=12)
            if not probe.returncode or b'READY' in probe.stdout or (self.root/'socket'/'negative.sock').exists():
                raise RuntimeError('startup rejection/cleanup failed')
            checks.append({'case':label,'exit':probe.returncode,'output_sha256':hashlib.sha256(probe.stdout+probe.stderr).hexdigest(),'endpoint_removed':True})
            if argument!=path:argument.unlink()
            path.unlink()
        for label,exe,inode in (('wrong_kernel_exe',self.root.parent/'bundle/new-api',self.listener_inode()),('wrong_kernel_listener',self.executable,'0')):
            try:admission_identity(self.process,self.broker_uid,exe,inode)
            except (ValueError,RuntimeError,OSError):checks.append({'case':label,'rejected':True})
            else:raise RuntimeError('kernel mismatch accepted')
        for label,uid in (('wrong_peer_uid',self.service_uid+1),('same_uid_wrong_process',self.service_uid)):
            # This fork has no service-written code and sends only the already
            # fixed CHECK. Even a valid capability cannot replace peer identity.
            inherited=[int(fd.name) for fd in Path('/proc/self/fd').iterdir()]
            child=os.fork()
            if child==0:
                try:
                    os.setsid()
                    libc=ctypes.CDLL(None,use_errno=True)
                    if libc.prctl(4,0,0,0,0) or Path('/proc/sys/fs/suid_dumpable').read_text().strip()!='0':os._exit(1)
                    # No installer listener, journal, database, barrier or log
                    # descriptor may survive into a service-UID probe.
                    for fd in inherited:
                        try:os.close(fd)
                        except OSError:pass
                    demote(uid)
                    if libc.prctl(4,0,0,0,0) or libc.prctl(3,0,0,0,0)!=0:os._exit(1)
                    for fd in list(Path('/proc/self/fd').iterdir()):
                        try:os.readlink(fd)
                        except FileNotFoundError:continue
                        os._exit(1)
                    with socket.socket(socket.AF_UNIX) as conn:
                        conn.settimeout(5);conn.connect(str(self.socket))
                        frame=json.dumps({'version':1,'operation':'CHECK','binding':self.binding,'capability':self.config['Capability']}).encode()
                        try:conn.sendall(frame);conn.shutdown(socket.SHUT_WR)
                        except (BrokenPipeError,ConnectionResetError):pass
                        data=b''
                        try:
                            while len(data)<4096:
                                part=conn.recv(4096-len(data))
                                if not part:break
                                data+=part
                        except ConnectionResetError:pass
                        if data and json.loads(data)['operation_result']['status']!='REJECTED':os._exit(1)
                    os._exit(0)
                except BaseException:os._exit(1)
            import select
            pidfd=os.pidfd_open(child)
            try:
                if not select.select([pidfd],[],[],8)[0]:
                    os.kill(child,9);os.waitpid(child,0)
                    raise RuntimeError('peer probe exit timeout')
                _,status=os.waitpid(child,0)
            finally:os.close(pidfd)
            if status:raise RuntimeError('peer rejection failed')
            checks.append({'case':label,'exit':status,'inherited_fds_closed_before_demotion':True,'nondumpable':True,'bounded_pidfd_wait':True})
        if b'"event":"model_enter"' in (self.root/'control/broker.log').read_bytes():
            raise RuntimeError('rejected control called model')
        if self.snapshot()!=self.before:raise RuntimeError('startup controls modified protected state')
        print(json.dumps({'admission_startup_negatives':checks,'actual_model_calls':0,'state_unchanged':True}),flush=True)

    def listener_inode(self):
        rows=[r.split() for r in Path('/proc/net/unix').read_text().splitlines()[1:]]
        matches=[r[6] for r in rows if len(r)==8 and r[7]==str(self.socket) and r[3]=='00010000']
        if len(matches)!=1:raise ValueError('listener missing')
        return matches[0]

    def wait_event(self, expected):
        import select
        until=time.monotonic()+12
        while True:
            while b'\n' in self.event_buffer:
                line,self.event_buffer=self.event_buffer.split(b'\n',1)
                if line.decode()==expected:return
                raise ValueError('unexpected fixed barrier event')
            left=until-time.monotonic()
            if left<=0 or not select.select([self.event_r],[],[],left)[0]:raise RuntimeError('barrier timeout')
            part=os.read(self.event_r,1024)
            if not part:raise RuntimeError('barrier EOF')
            self.event_buffer+=part
            if len(self.event_buffer)>4096:raise ValueError('barrier limit')

    def result(self):
        if self.event_r is not None:self.wait_event('TERMINAL')
        self.log.flush()
        raw=self.root.joinpath('control/broker.log').read_bytes()
        events=[]
        for line in raw.splitlines():
            try:value=json.loads(line)
            except ValueError:continue
            if isinstance(value,dict) and 'event' in value:events.append(value)
        returns=[e['result'] for e in events if e['event']=='model_return']
        calls=sum(e['event']=='model_enter' for e in events)
        if len(returns)!=1 or calls!=1:raise RuntimeError('actual call inventory')
        if self.lock:self.lock.rollback();self.lock.close();self.lock=None
        now=admission_identity(self.process,self.broker_uid,self.executable,self.listener_inode())
        if now!=self.initial_kernel:raise RuntimeError('post request kernel identity changed')
        unchanged=self.snapshot()==self.before and digest(self.journal)==self.config['JournalSHA256']
        if not unchanged:raise RuntimeError('admission modified state')
        return {'Operation':returns[0]['operation_result'],'Context':returns[0]['context_status'],'Calls':calls,'Unchanged':unchanged}

    def snapshot(self):
        import sqlite3
        conn=sqlite3.connect(self.db); data={}
        for table in ('users','oauth_derived_token_sources','oauth_derived_token_history','oauth_derived_token_bootstrap_identity','oauth_derived_text_charges','tasks'):
            exists=conn.execute('SELECT 1 FROM sqlite_master WHERE name=? AND type=?',(table,'table')).fetchone()
            data[table]=conn.execute('SELECT * FROM '+table+' ORDER BY 1').fetchall() if exists else None
        conn.close()
        return hashlib.sha256(json.dumps(data,sort_keys=True).encode()).hexdigest()

    def qualifications(self):
        while not self.stopped.is_set():
            try: conn,_=self.authority.accept()
            except socket.timeout: continue
            except OSError: return
            with conn:
                try:
                    conn.settimeout(3)
                    pid,uid,_=struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                    data=b''
                    while len(data)<=512:
                        part=conn.recv(513-len(data))
                        if not part:break
                        data+=part
                    q=json.loads(data)
                    if set(q)!={'version','role','binding','challenge'} or q['version']!=1 or q['role'] not in ('broker','service') or q['binding']!=self.binding or not re.fullmatch('[0-9a-f]{64}',q['challenge']):raise ValueError('qualification request')
                    if not self.assigned.wait(3):raise ValueError('unassigned child')
                    if (pid,uid) not in ((self.service.pid,self.service_uid),(self.process.pid,self.broker_uid)):raise ValueError('qualification peer')
                    role=q['role'];process=self.process if role=='broker' else self.service;roleuid=self.broker_uid if role=='broker' else self.service_uid
                    exe=self.executable if role=='broker' else self.root.parent/'bundle/test-0'
                    listener=None
                    if role=='broker':
                        rows=[r.split() for r in Path('/proc/net/unix').read_text().splitlines()[1:]]
                        matches=[r[6] for r in rows if len(r)==8 and r[7]==str(self.socket) and r[3]=='00010000']
                        if len(matches)!=1:raise ValueError('listener missing')
                        listener=matches[0]
                    result=admission_identity(process,roleuid,exe,listener)
                    result.update(OK=True,Challenge=q['challenge'],Binding=self.binding,ManifestSHA256=self.config['ManifestSHA256'])
                    conn.sendall(json.dumps(result).encode())
                except (OSError,ValueError,KeyError,RuntimeError,subprocess.SubprocessError):
                    continue

    def close(self):
        if self.closed:return
        self.closed=True
        errors=[]
        if self.lock:self.lock.rollback();self.lock.close();self.lock=None
        if self.ack_w is not None and self.case!='shutdown':
            try:os.write(self.ack_w,b'1')
            except OSError:pass
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(timeout=12)
            except subprocess.TimeoutExpired:
                self.process.kill();self.process.wait();errors.append('drain timeout')
        self.stopped.set()
        if self.thread:self.thread.join(timeout=5)
        self.authority.close()
        if self.thread and self.thread.is_alive():errors.append('authority did not stop')
        for fd in (self.event_r,self.ack_w):
            if fd is not None:os.close(fd)
        if self.process and self.process.stdout:
            tail=self.process.stdout.read(65537);self.log.write(tail);self.process.stdout.close()
        self.log.flush();self.log.seek(0);raw=self.log.read(65537);self.log.close()
        unchanged=self.snapshot()==self.before and digest(self.journal)==self.config['JournalSHA256']
        print(json.dumps({'admission_case':self.case,'broker_exit':self.process.returncode,'broker_log':raw[:65536].decode(errors='replace'),'log_truncated':len(raw)>65536,'state_unchanged':unchanged}),flush=True)
        if self.case=='shutdown':
            events=[json.loads(line) for line in raw.splitlines() if line.startswith(b'{"event":')]
            calls=sum(e['event']=='model_enter' for e in events)
            terminal=any(e['event']=='terminal' for e in events)
            if self.process.returncode!=1 or b'ADMISSION_SHUTDOWN_TIMEOUT' not in raw or terminal or calls!=1 or not unchanged or errors:
                raise RuntimeError('shutdown timeout did not fail closed')
            return {'Exit':1,'Calls':calls,'NoTerminal':True,'Unchanged':True}
        if self.process.returncode or not unchanged or errors:raise RuntimeError('broker exit/state/cleanup failure')
        return {'Closed':True}


def trusted_admission(bundle):
    if os.geteuid()!=0 or os.getpid()!=1:
        raise ValueError('private root PID1 controller required')
    # Root /proc is mounted inside the new PID namespace; no host PID aliases.
    if Path('/proc/self/status').read_text().split('NSpid:',1)[1].splitlines()[0].split()!=['1']:
        raise ValueError('private proc required')
    mounts=[line.split() for line in Path('/proc/mounts').read_text().splitlines()]
    run_mounts=[row for row in mounts if row[1]=='/run']
    root_mounts=[line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines() if line.split()[4]=='/']
    if (len(run_mounts)!=1 or run_mounts[0][2]!='tmpfs' or
            not {'nosuid','nodev'}.issubset(set(run_mounts[0][3].split(','))) or
            'noexec' in run_mounts[0][3].split(',') or
            os.statvfs('/run').f_blocks*os.statvfs('/run').f_frsize>1024**3 or
            [name for _,name in socket.if_nameindex()]!=['lo'] or
            any(any(item.startswith('shared:') for item in row[6:]) for row in root_mounts)):
        raise ValueError('private executable bounded run mount/net required')
    bundle=Path(bundle).resolve(strict=True);metadata=verified_manifest(bundle)
    expected=[{'binary':'test-0','cwd':'internal/admissionbroker','run':ADMISSION_SELECTOR}]
    if metadata['tier']!='admission' or metadata['entries']!=expected or 'admission-broker' not in metadata['files']:raise ValueError('admission inventory mismatch')
    root=Path(tempfile.mkdtemp(prefix='admission-tests-',dir='/run'));root.chmod(0o755);owned=root.stat()
    fixtures={};service=None;status=1;failure=[];thread=None;control=None;stop=threading.Event()
    try:
        for name,value in metadata['files'].items():
            src=bundle/name;dst=root/'bundle'/name;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dst);dst.chmod(0o755 if src.stat().st_mode&0o111 else 0o644)
            if digest(dst)!=value:raise ValueError('admission copy hash')
        (root/'bundle/manifest.json').write_text(json.dumps(metadata,sort_keys=True))
        service_uid=30000000+secrets.randbelow(10000000);broker_uid=service_uid+10000001
        for uid in (service_uid,broker_uid):
            try:pwd.getpwuid(uid);raise ValueError('existing UID')
            except KeyError:pass
            for proc in Path('/proc').iterdir():
                if proc.name.isdecimal():
                    try:values=(proc/'status').read_text().split('Uid:',1)[1].splitlines()[0].split()
                    except (OSError,IndexError):continue
                    if str(uid) in values:raise ValueError('active UID collision')
        control=socket.socket(socket.AF_UNIX);control.bind(str(root/'fixtures.sock'));os.chmod(root/'fixtures.sock',0o666);control.listen(8);control.settimeout(0.2)
        assigned=threading.Event();seen=set();finished=set()
        def serve_fixtures():
            while not stop.is_set():
                try:conn,_=control.accept()
                except socket.timeout:continue
                except OSError:return
                with conn:
                    try:
                        conn.settimeout(90);pid,uid,_=struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                        if not assigned.wait(3) or (pid,uid)!=(service.pid,service_uid):raise ValueError('fixture peer')
                        request=bytearray()
                        while len(request)<=128:
                            part=conn.recv(129-len(request))
                            if not part:break
                            request.extend(part)
                        if len(request)>128:raise ValueError('fixture frame')
                        action,case=request.decode().removesuffix('\n').split(':')
                        if case not in ADMISSION_CASES:raise ValueError('fixture case')
                        admission_identity(service,service_uid,root/'bundle/test-0')
                        if action=='new' and case not in seen:
                            seen.add(case)
                            fixture=AdmissionFixture.__new__(AdmissionFixture)
                            fixtures[case]=fixture
                            fixture.__init__(root/case,metadata,service,service_uid,broker_uid,case)
                            response={'Config':str(fixture.root/'control/service.json'),'BrokerPID':fixture.process.pid}
                        elif action=='entry' and case in ('inflight','model_first','unrelated','shutdown'):
                            fixtures[case].wait_event('MODEL_DONE' if case=='model_first' else 'SQL_ENTRY');response={'Ready':True}
                        elif action=='release' and case in ('model_first','unrelated'):
                            os.write(fixtures[case].ack_w,b'1');response={'Released':True}
                        elif action=='result':response=fixtures[case].result()
                        elif action=='finish' and case not in finished:
                            response=fixtures[case].close();finished.add(case)
                        else:raise ValueError('fixture action/replay')
                        conn.sendall(json.dumps(response).encode())
                    except BaseException as error:
                        failure.append(type(error).__name__)
                        print(json.dumps({'admission_control_failure':type(error).__name__,'action':locals().get('action','unknown'),'case':locals().get('case','unknown')}),flush=True)
        thread=threading.Thread(target=serve_fixtures);thread.start()
        env={'PATH':'/usr/bin:/bin','TMPDIR':str(root/'service-tmp'),'ADMISSION_FIXTURE_SOCKET':str(root/'fixtures.sock')}
        (root/'service-tmp').mkdir();os.chown(root/'service-tmp',service_uid,service_uid);(root/'service-tmp').chmod(0o700)
        service=subprocess.Popen([str(root/'bundle/test-0'),'-test.v','-test.count=1','-test.run='+ADMISSION_SELECTOR],env=env,preexec_fn=lambda:demote(service_uid),cwd=root/'bundle/source/internal/admissionbroker',stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        assigned.set();output,_=service.communicate(timeout=180);print(output.decode(errors='replace'),end='',flush=True)
        if service.returncode:raise RuntimeError('admission tests failed')
        events=re.findall(r'^\s*--- (PASS|FAIL|SKIP): (\S+) \(',output.decode(errors='replace'),re.M)
        required=['TestAdmissionLive/'+case for case in ADMISSION_CASES]+['TestAdmissionUnit','TestAdmissionLive']
        if any(v!='PASS' for v,_ in events) or any(events.count(('PASS',n))!=1 for n in required):raise RuntimeError('admission skipped/missing result')
        if failure or set(ADMISSION_CASES)!=seen or finished!=seen:raise RuntimeError('incomplete admission fixture inventory')
        status=0
    finally:
        stop.set()
        if service and service.poll() is None:service.kill();service.wait()
        if control:control.close()
        if thread:thread.join(timeout=95)
        for fixture in fixtures.values():
            try:fixture.close()
            except Exception as error:
                status=1;print(json.dumps({'admission_cleanup_failure':type(error).__name__}),flush=True)
        if thread and thread.is_alive():raise RuntimeError('fixture controller did not join')
        now=root.stat()
        if (now.st_dev,now.st_ino,now.st_uid)!=(owned.st_dev,owned.st_ino,0):raise RuntimeError('admission cleanup ownership')
        shutil.rmtree(root)
        print('ADMISSION_RESULT '+json.dumps({'manifest_sha256':digest(bundle/'manifest.json'),'runner_sha256':metadata['files']['runner.py'],'status':status,'cleanup':True,'scope':'explicit-admission-only'}),flush=True)
    if status:raise RuntimeError('admission cleanup failed')


# Wallet matrices are trusted DB-owner tests, never gateway/service processes.
# This role is granted only to the two exact compiled matrix jobs above.
WALLET_MUTABLE = ('users', 'tokens', 'user_sessions', 'session_revocation_events',
                  'oauth_grants', 'o_auth_operations', 'o_auth_artifacts', 'o_auth_cleanup_jobs',
                  'oauth_derived_text_charges', 'tasks', 'logs', 'channels', 'midjourneys',
                  'top_ups', 'user_subscriptions', 'system_task_locks', 'system_tasks')
WALLET_IMMUTABLE = ('oauth_derived_token_history', 'oauth_derived_token_bootstrap_identity')


_wallet_observation_fd = None
_wallet_observation_attempts = None


class WalletObservationCollector:
    """Root-private bounded diagnostics, independent of business stdout/exit.

    No path or descriptor is accepted from the caller/environment. The emitter
    retains its one nonblocking atomic write. A daemon reader never delays the
    installer, including when the existing result sink is full or unavailable.
    """
    def __enter__(self):
        global _wallet_observation_fd, _wallet_observation_attempts
        self.attempts = iter(range(2049))
        self.owns_sink = False
        self.read = self.write = self.sink = None
        self.thread = None
        self.stop = threading.Event()
        self.received = self.delivered = self.dropped = 0
        self.failed = False
        try:
            if os.geteuid() != 0 or _wallet_observation_fd is not None:
                raise ValueError('collector requires sole root owner')
            original = os.fstat(1)
            if not (stat.S_ISFIFO(original.st_mode) or
                    stat.S_ISREG(original.st_mode) and original.st_uid == 0 and not original.st_mode & 0o022):
                raise ValueError('unsupported collector result stream')
            self.sink = (os.dup(1) if stat.S_ISREG(original.st_mode) else
                         os.open('/proc/self/fd/1', os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC))
            opened = os.fstat(self.sink)
            if (original.st_dev,original.st_ino) != (opened.st_dev,opened.st_ino):
                raise ValueError('collector output replaced')
            self.read,self.write = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
            _wallet_observation_fd = self.write
            _wallet_observation_attempts = self.attempts
            self.owns_sink = True
            self.thread = threading.Thread(target=self.drain, daemon=True)
            self.thread.start()
        except Exception:
            self.failed = True
            if self.owns_sink:
                _wallet_observation_fd = _wallet_observation_attempts = None
        return self

    def drain(self):
        pending = b''
        discarding = False
        try:
            while not self.stop.is_set():
                try:part = os.read(self.read,4096)
                except BlockingIOError:
                    self.stop.wait(0.005)
                    continue
                if not part:break
                for byte in part:
                    if byte == 10:
                        if not discarding and pending:
                            self.received += 1
                            if self.received <= 2048:
                                try:
                                    # Bytes come only from the fixed in-process emitter.
                                    count = os.write(self.sink,pending+b'\n')
                                    if count != len(pending)+1:raise OSError('partial diagnostic')
                                    self.delivered += 1
                                except OSError:self.dropped += 1
                            else:self.dropped += 1
                        pending,discarding = b'',False
                    elif len(pending) < 768 and not discarding:pending += bytes((byte,))
                    else:
                        self.failed = True
                        pending,discarding = b'',True
        except Exception:self.failed = True
        finally:
            try:
                if pending or discarding:self.failed = True
                attempted = next(self.attempts, 2049)
                summary = ('BOOTSTRAP_OBSERVATION_RESULT '+json.dumps({'attempted':attempted,'received':self.received,
                    'delivered':self.delivered,'dropped':self.dropped,
                    'capture_complete':not self.failed and self.dropped==0 and attempted==self.delivered and self.delivered>0})+'\n').encode()
                os.write(self.sink,summary)
            except Exception:pass

    def __exit__(self, kind, error, traceback):
        global _wallet_observation_fd, _wallet_observation_attempts
        if self.owns_sink:
            _wallet_observation_fd = _wallet_observation_attempts = None
        if self.write is not None:os.close(self.write);self.write=None
        if self.thread:self.thread.join(timeout=0.5)
        alive = bool(self.thread and self.thread.is_alive())
        if alive:self.failed = True
        self.stop.set()
        # A stalled regular-file sink may retain only this bounded daemon thread
        # until process exit; never close/reuse its descriptor from another thread.
        if not alive:
            for fd in (self.read,self.sink):
                if fd is not None:os.close(fd)
        return False


class WalletObservation:
    """Bounded wallet phases on the existing drop-on-backpressure diagnostic sink.

    Correlation is generated by the installer, never from receipt IDs or wire
    input. No queue, worker, file path or retained descriptor is introduced.
    Each process attempts at most 2048 records and each request at most 64;
    exhausted/unsupported sinks lose diagnostics without changing the operation.
    """
    local = threading.local()
    sequences = iter(range(1, 2**63))
    slots = iter(range(2048))

    def __init__(self, phase, *, request=False):
        self.phase, self.request = phase, request
        self.previous = self.current = None
        self.started = 0

    def emit(self, outcome, error=None):
        try:
            if self.current is None or self.current[1] >= 64 or next(self.slots, None) is None:
                return
            self.current[1] += 1
            bootstrap_observation('installer', self.phase, self.started, 0, label='wallet',
                                  outcome=outcome, error=error, request_id=self.current[0])
        except Exception:
            pass

    def __enter__(self):
        try:
            self.previous = getattr(self.local, 'current', None)
            self.current = self.previous
            if self.request or self.current is None:
                self.current = ['wallet-'+str(os.getpid())+'-'+str(next(self.sequences)), 0]
            self.started = time.monotonic()
            self.local.current = self.current
            self.emit('enter')
        except Exception:
            pass
        return self

    def __exit__(self, kind, error, traceback):
        try:
            self.emit('error' if kind is not None else 'exit', error)
            self.local.current = self.previous
        except Exception:
            pass
        # The original error, including cancellation, always propagates.
        return False


class OwnedWalletMySQL:
    def __init__(self, root):
        self.root = root
        self.daemon_uid = pwd.getpwnam('mysql').pw_uid
        if self.daemon_uid == 0:
            raise ValueError('MySQL daemon cannot be root')
        self.executable = Path('/usr/sbin/mysqld')
        self.socket_dir = root/'mysql-socket'
        self.socket_path = self.socket_dir/'mysql.sock'
        self.process = self.log = self.identity = None
        self.password = secrets.token_hex(32)
        self.commands = []

    def sql(self, database, statement, initial=False):
        if not re.fullmatch(r'[a-z][a-z0-9_]{0,47}', database):
            raise ValueError('invalid installer database')
        q = subprocess.run(['/usr/bin/mysql', '--no-defaults', '--protocol=SOCKET',
                            '--socket='+str(self.socket_path), '-uroot', '-N', '-B', database],
                           input=statement.encode(), capture_output=True,
                           env={'PATH':'/usr/bin:/bin', 'MYSQL_PWD':'' if initial else self.password}, timeout=30)
        self.commands.append({'operation':'installer SQL', 'exit':q.returncode,
                              'error_sha256':hashlib.sha256(q.stderr).hexdigest()})
        if q.returncode:
            raise RuntimeError('MySQL installer SQL failed')
        return q.stdout.decode().strip()

    def verify(self):
        with WalletObservation('wallet_mysql_verify'):
            daemon_process_identity(self.process, self.daemon_uid)
            st, endpoint = self.socket_dir.lstat(), self.socket_path.lstat()
            if (not stat.S_ISDIR(st.st_mode) or st.st_mode & 0o022 or st.st_uid != self.daemon_uid or
                    not stat.S_ISSOCK(endpoint.st_mode) or endpoint.st_uid != self.daemon_uid):
                raise RuntimeError('MySQL socket path ownership mismatch')
            with WalletObservation('wallet_mysql_endpoint'):
                with socket.socket(socket.AF_UNIX) as conn:
                    conn.settimeout(2);conn.connect(str(self.socket_path))
                    peer = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    if peer[:2] != (self.process.pid, self.daemon_uid):
                        raise RuntimeError('MySQL endpoint peer mismatch')
            rows = [l.split() for l in Path('/proc/net/unix').read_text().splitlines()[1:]]
            rows = [r for r in rows if len(r) == 8 and r[7] == str(self.socket_path) and r[3] == '00010000']
            if len(rows) != 1:
                raise RuntimeError('MySQL listener missing or ambiguous')
            with WalletObservation('wallet_mysql_observer'):
                observed = observe_daemon(self.process, self.daemon_uid, self.executable, rows[0][6])
            identity = dict(observed, socket_file_inode=endpoint.st_ino, directory_inode=st.st_ino,
                            pid=self.process.pid, daemon_uid=self.daemon_uid)
            if self.identity is not None and identity != self.identity:
                raise RuntimeError('MySQL listener replaced')
            self.identity = identity
            return identity

    def start(self):
        for executable in (self.executable, Path('/usr/bin/mysql')):
            st = executable.stat()
            if st.st_uid != 0 or st.st_mode & 0o022 or not stat.S_ISREG(st.st_mode):
                raise ValueError('untrusted MySQL dependency')
        data, temp = self.root/'mysql-data', self.root/'mysql-tmp'
        for path in (data, temp, self.socket_dir):
            path.mkdir(mode=0o700 if path == data else 0o755)
            os.chown(path, self.daemon_uid, self.daemon_uid)
        argv = [str(self.executable), '--no-defaults', '--datadir='+str(data), '--tmpdir='+str(temp)]
        init = subprocess.run(argv+['--initialize-insecure'], preexec_fn=lambda:demote(self.daemon_uid),
                              capture_output=True, timeout=90, env={'PATH':'/usr/bin:/bin'})
        self.commands.append({'operation':'initialize', 'exit':init.returncode,
                              'output_sha256':hashlib.sha256(init.stdout+init.stderr).hexdigest()})
        if init.returncode:
            raise RuntimeError('MySQL initialization failed')
        self.log = (self.root/'mysql.log').open('xb')
        self.process = subprocess.Popen(argv+['--socket='+str(self.socket_path),
            '--pid-file='+str(self.socket_dir/'mysql.pid'), '--skip-networking', '--mysqlx=OFF',
            '--skip-log-bin', '--innodb-buffer-pool-size=64M'], stdout=self.log, stderr=self.log,
            preexec_fn=lambda:demote(self.daemon_uid), env={'PATH':'/usr/bin:/bin'})
        deadline = time.monotonic()+40
        while not self.socket_path.exists():
            if self.process.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError('MySQL startup failed')
            time.sleep(0.02)
        self.verify()
        self.sql('mysql', "ALTER USER 'root'@'localhost' IDENTIFIED BY '"+self.password+"';", initial=True)
        self.version = self.sql('mysql', 'SELECT VERSION();')

    def close(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.process.kill();self.process.wait(timeout=5)
        if self.log:self.log.close()
        print(json.dumps({'wallet_mysql_version':getattr(self,'version',None), 'commands':self.commands,
            'kernel':self.identity, 'exit':self.process.returncode if self.process else None,
            'cleanup':'owned MySQL child reaped'}), flush=True)


class WalletInstaller:
    mutable_tables = WALLET_MUTABLE
    source_access = 'SELECT,INSERT'

    def __init__(self, root, uid, engine, metadata):
        self.root, self.uid, self.engine, self.metadata = root, uid, engine, metadata
        self.resource = None
        self.process = None
        self.births = {}
        self.stopped = threading.Event()
        self.failures = []
        self.first_birth = threading.Event()
        self.server = socket.socket(socket.AF_UNIX)
        self.server.bind(str(root/'wallet.sock'));os.chmod(root/'wallet.sock',0o666)
        self.server.listen(4);self.server.settimeout(0.2)

    def start(self):
        if self.engine == 'postgres':
            self.resource = CombinedPostgres(self.root, self.uid)
        elif self.engine == 'mysql':
            self.resource = OwnedWalletMySQL(self.root)
        if self.resource:self.resource.start()

    def snapshot(self, database):
        with WalletObservation('wallet_snapshot'):
            if self.engine == 'sqlite':
                import sqlite3
                with sqlite3.connect(database) as conn:
                    rows = [conn.execute('SELECT * FROM '+table+' ORDER BY id').fetchall() for table in WALLET_IMMUTABLE]
                return hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()
            result = '\n'.join(self.resource.sql(database, 'SELECT * FROM '+table+' ORDER BY id;') for table in WALLET_IMMUTABLE)
            return hashlib.sha256(result.encode()).hexdigest()

    def qualify(self, ident):
        with WalletObservation('wallet_qualify'):
            row = self.births[ident]
            receipt = row['receipt']
            if self.resource and self.resource.verify() != row['kernel']:
                raise RuntimeError('wallet endpoint changed')
            with WalletObservation('wallet_immutable'):
                if (digest(receipt['Journal']) != receipt['JournalSHA256'] or
                        self.snapshot(receipt['Database']) != receipt['ProvenanceSHA256'] or
                        digest(row['path']) != row['receipt_hash']):
                    raise RuntimeError('wallet immutable provenance changed')
            if self.engine == 'sqlite':
                st = Path(receipt['Database']).lstat()
                if (st.st_dev,st.st_ino,st.st_uid) != tuple(row['file_identity']):
                    raise RuntimeError('wallet SQLite database replaced')
            return receipt

    def audit_owner_permissions(self, database, role, password):
        # Fixed probes against this born synthetic DB. No SQL is accepted over
        # IPC, and the owner receives no global administration credentials.
        if self.engine == 'sqlite':
            return
        if self.engine == 'postgres':
            argv=[str(self.resource.bin/'psql'),'-X','-qAt','-v','ON_ERROR_STOP=1',
                  '-h',str(self.resource.socket_dir),'-U',role,'-d',database]
            env={'PATH':'/usr/bin:/bin','PGPASSWORD':password}
            probes=(('global_create','CREATE DATABASE wallet_forbidden;'),
                    ('create_role','CREATE ROLE wallet_forbidden;'),
                    ('grant','GRANT SELECT ON oauth_derived_token_history TO PUBLIC;'))
        else:
            argv=['/usr/bin/mysql','--no-defaults','--protocol=SOCKET','--socket='+str(self.resource.socket_path),'-u'+role,'-N','-B',database]
            env={'PATH':'/usr/bin:/bin','MYSQL_PWD':password}
            probes=(('global_create','CREATE DATABASE wallet_forbidden;'),
                    ('create_role',"CREATE USER 'wallet_forbidden'@'localhost';"),
                    ('grant',f"GRANT SELECT ON {database}.oauth_derived_token_history TO '{role}'@'localhost';"))
        probes += (('write_history','DELETE FROM oauth_derived_token_history WHERE 1=0;'),
                   ('write_identity','DELETE FROM oauth_derived_token_bootstrap_identity WHERE 1=0;'),
                   ('mutate_source','DELETE FROM oauth_derived_token_sources WHERE 1=0;'))
        if isinstance(self, LifecycleInstaller):
            probes += (('insert_source','INSERT INTO oauth_derived_token_sources (grant_ref) SELECT grant_ref FROM oauth_derived_token_sources WHERE 1=0;'),
                       ('alter_source','ALTER TABLE oauth_derived_token_sources ADD COLUMN forbidden_owner INTEGER;'),
                       ('write_task','DELETE FROM tasks WHERE 1=0;'),
                       ('select_source_state','UPDATE oauth_derived_token_sources SET terminal_reason=terminal_reason WHERE 1=0;'))
        for label,statement in [('select_history','SELECT COUNT(*) FROM oauth_derived_token_history;'),*probes,('select_identity','SELECT COUNT(*) FROM oauth_derived_token_bootstrap_identity;')]:
            acl_query = "SELECT relacl::text FROM pg_class WHERE oid='public.oauth_derived_token_history'::regclass;"
            before_acl = self.resource.sql(database,acl_query) if self.engine=='postgres' and label=='grant' else None
            result=subprocess.run(argv,input=statement.encode(),env=env,preexec_fn=lambda:demote(self.uid),capture_output=True,timeout=10)
            expected=label.startswith('select_')
            print(json.dumps({'wallet_owner_permission':label,'engine':self.engine,'exit':result.returncode,
                'expected_success':expected,'stderr_sha256':hashlib.sha256(result.stderr).hexdigest()}),flush=True)
            if before_acl is not None:
                # PostgreSQL reports an unauthorized GRANT as a warning, not
                # necessarily a nonzero exit. Verify the physical ACL, too.
                unchanged=self.resource.sql(database,acl_query)==before_acl
                print(json.dumps({'wallet_grant_acl_unchanged':unchanged,'warning_present':bool(result.stderr)}),flush=True)
                if not unchanged or not result.stderr:raise RuntimeError('wallet owner acquired grant authority')
            elif (result.returncode==0)!=expected:
                raise RuntimeError('wallet owner permission boundary failed')

    def birth(self):
        if self.resource:self.resource.verify()
        completed_birth = outer_birth(self.engine, 'wallet', self.resource)
        if completed_birth is not None:
            ident, database = completed_birth['id'], completed_birth['target']
            journal = Path(completed_birth['journal'])
            role, password = 'owner_' + ident[:20], secrets.token_hex(32)
            if self.engine == 'sqlite':
                data = Path(database).parent
            print(json.dumps({'wallet_birth': ident, 'engine': self.engine, 'exit': 0,
                              'output_sha256': completed_birth['output_sha256']}), flush=True)
        else:
            ident = secrets.token_hex(16)
            journal = self.root/'journals'/(ident+'.json')
            env = {'PATH':'/usr/bin:/bin', 'GOMAXPROCS':'2'}
            role, password = 'owner_'+ident[:20], secrets.token_hex(32)
            if self.engine == 'sqlite':
                data = self.root/('data-'+ident);data.mkdir(mode=0o700)
                database = str(data/'main.db')
            else:
                database = 'birth_'+ident
                if self.engine == 'postgres':
                    env['BOOTSTRAP_ADMIN_DSN'] = 'postgresql://bootstrap:'+self.resource.password+'@/postgres?host='+str(self.resource.socket_dir)+'&sslmode=disable'
                else:
                    env['BOOTSTRAP_ADMIN_DSN'] = 'root:'+self.resource.password+'@unix('+str(self.resource.socket_path)+')/mysql?parseTime=true'
            result = subprocess.run([str(self.root/'bundle/new-api'), 'db-bootstrap', 'fresh', '--engine', self.engine,
                '--target', database, '--journal', str(journal)], env=env, capture_output=True, timeout=120)
            print(json.dumps({'wallet_birth':ident, 'engine':self.engine, 'exit':result.returncode,
                'output_sha256':hashlib.sha256(result.stdout+result.stderr).hexdigest()}),flush=True)
            if result.returncode:
                raise RuntimeError('permanent wallet birth failed')
            j = json.loads(journal.read_text())
            if j['phase'] != 'READY' or j['engine'] != self.engine or j['target'] != database:
                raise RuntimeError('wallet birth identity mismatch')
        provenance = self.snapshot(database)
        file_identity = None
        if self.engine == 'sqlite':
            os.chown(database,self.uid,self.uid);os.chmod(database,0o600)
            os.chown(data,self.uid,self.uid)
            st = Path(database).stat();file_identity=(st.st_dev,st.st_ino,st.st_uid)
            dsn, endpoint, role = database, database, 'file-owner'
        elif self.engine == 'postgres':
            self.resource.sql(database, f"CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD '{password}'; REVOKE ALL ON SCHEMA public FROM PUBLIC; GRANT USAGE,CREATE ON SCHEMA public TO {role};")
            existing = set(self.resource.sql(database,"SELECT tablename FROM pg_tables WHERE schemaname='public';").splitlines())
            for table in self.mutable_tables:
                if table in existing:self.resource.sql(database,f'ALTER TABLE public.{table} OWNER TO {role};')
            for table in WALLET_IMMUTABLE:
                self.resource.sql(database,f'GRANT SELECT ON public.{table} TO {role};')
            self.resource.sql(database,f'GRANT {self.source_access} ON public.oauth_derived_token_sources TO {role};')
            if not isinstance(self,LifecycleInstaller):
                self.resource.sql(database,f'GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO {role};')
            self.resource.sql('postgres',f'REVOKE ALL ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {role}; ALTER DATABASE {database} CONNECTION LIMIT 20;')
            endpoint = str(self.resource.socket_path)
            dsn = 'postgresql://'+role+':'+password+'@/'+database+'?host='+str(self.resource.socket_dir)+'&sslmode=disable'
        else:
            self.resource.sql(database,f"CREATE USER '{role}'@'localhost' IDENTIFIED BY '{password}';")
            for table in self.mutable_tables:
                self.resource.sql(database,f"GRANT SELECT,INSERT,UPDATE,DELETE,CREATE,ALTER,DROP,INDEX,REFERENCES ON {database}.{table} TO '{role}'@'localhost';")
            for table in WALLET_IMMUTABLE:
                self.resource.sql(database,f"GRANT SELECT ON {database}.{table} TO '{role}'@'localhost';")
            self.resource.sql(database,f"GRANT {self.source_access} ON {database}.oauth_derived_token_sources TO '{role}'@'localhost';")
            endpoint = str(self.resource.socket_path)
            dsn = role+':'+password+'@unix('+endpoint+')/'+database+'?parseTime=true&loc=Local'
        if not self.births:self.audit_owner_permissions(database,role,password)
        receipt = {'ID':ident,'RoleClass':'TRUSTED_DB_TEST_OWNER','Engine':self.engine,'Database':database,
            'DBUser':role,'Endpoint':endpoint,'OwnerUID':self.uid,'Journal':str(journal),
            'JournalSHA256':digest(journal),'ProvenanceSHA256':provenance,
            'DSNSHA256':hashlib.sha256(dsn.encode()).hexdigest(),'BinarySHA256':self.metadata['files'][self.metadata['entries'][0]['binary']],
            'ManifestSHA256':digest(self.root/'bundle/manifest.json'),
            'Version':self.resource.version if self.resource else 'SQLite via permanent CLI'}
        path=self.root/('wallet-'+ident+'.json');path.write_text(json.dumps(receipt,sort_keys=True));path.chmod(0o644)
        self.births[ident]={'receipt':receipt,'path':path,'receipt_hash':digest(path),
            'kernel':self.resource.verify() if self.resource else None,'file_identity':file_identity}
        self.first_birth.set()
        return {'Engine':self.engine,'DSN':dsn,'Journal':str(journal),'ResourceReceipt':str(path)}

    def serve(self):
        while not self.stopped.is_set():
            try:conn,_=self.server.accept()
            except socket.timeout:continue
            with WalletObservation('wallet_rpc', request=True):
                with conn:
                    conn.settimeout(3)
                    try:
                        with WalletObservation('wallet_peer'):
                            pid,uid,_=struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                            if uid != self.uid or not self.process or self.process.poll() is not None:
                                continue
                            # Only the root-launched, hash-bound owner test can spawn
                            # this fixed client. A different service UID has no route.
                            status=dict(line.split(':',1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
                            if int(status['PPid']) != self.process.pid:continue
                            identity=admission_identity(self.process,self.uid,self.root/'bundle'/self.metadata['entries'][0]['binary'])
                            if identity['ExeSHA256'] != self.metadata['files'][self.metadata['entries'][0]['binary']]:continue
                        with WalletObservation('wallet_read'):
                            request=conn.recv(160 if isinstance(self, LifecycleInstaller) else 96)
                            if conn.recv(1):continue
                        with WalletObservation('wallet_dispatch'):
                            if request==b'fresh\n':response=self.birth()
                            elif re.fullmatch(rb'qualify:[0-9a-f]{32}\n',request):response=self.qualify(request[8:-1].decode())
                            elif isinstance(self, LifecycleInstaller):response=self.fixture_action(request)
                            else:continue
                        with WalletObservation('wallet_reply'):
                            conn.sendall(json.dumps(response,sort_keys=True).encode())
                    except (OSError,ValueError,KeyError,RuntimeError,subprocess.SubprocessError) as error:
                        self.failures.append(type(error).__name__)
                        self.first_birth.set()

    def close(self):
        for ident in self.births:self.qualify(ident)
        print(json.dumps({'wallet_immutable_provenance':list(self.births), 'unchanged':True,
            'owner_uid':self.uid,'role':'TRUSTED_DB_TEST_OWNER','installer_errors':self.failures}),flush=True)


class LifecycleInstaller(WalletInstaller):
    # Synthetic lifecycle fixture owner only. No Task, subscription, top-up or
    # system-task rights; immutable history remains owned by the installer.
    mutable_tables = ('users', 'tokens', 'user_sessions', 'session_revocation_events',
                      'user_access_tokens', 'oauth_grants', 'o_auth_operations',
                      'o_auth_artifacts', 'o_auth_cleanup_jobs',
                      'oauth_derived_text_charges', 'audit_logs', 'logs')
    source_access = 'SELECT,UPDATE'

    def __init__(self, root, uid, engine, metadata):
        super().__init__(root, uid, engine, metadata)
        self.redis = CombinedRedis(root, uid)
        self.redis_path = root/'redis-resource.json'

    def start(self):
        super().start()
        self.redis.start()
        self.redis_hash = digest(self.redis_path)

    def qualify(self, ident):
        if digest(self.redis_path) != self.redis_hash:
            raise RuntimeError('lifecycle Redis receipt changed')
        self.redis.verify()
        return super().qualify(ident)

    def fixture_action(self, request):
        # Only a verified direct child of the exact lifecycle test binary can
        # request these two fixed fixture operations. No caller SQL or secret.
        match = re.fullmatch(rb'(seed|source_absent):([0-9a-f]{32})(?::([0-9a-f]{64}):([0-9]{1,10}))?\n', request)
        if not match:
            raise ValueError('lifecycle fixture request denied')
        action, ident = match[1].decode(), match[2].decode()
        receipt = self.qualify(ident)
        database = receipt['Database']
        if action == 'source_absent':
            if match[3] is not None:raise ValueError('invalid source fault')
            statement = 'DROP TABLE oauth_derived_token_sources;'
        else:
            if match[3] is None:raise ValueError('missing source fixture binding')
            grant, token = match[3].decode(), int(match[4])
            # The SQL INSERT SELECT takes all identity and token fields from
            # this newly born DB. Fixed bounded fixture facts are not issuance.
            now = int(time.time())
            key_col = '"key"' if self.engine == 'postgres' else '`key`'
            token_fields = 'NULL,NULL,NULL,NULL,NULL'
            expires = str(now+600)
            if token:
                if self.engine == 'sqlite':
                    import sqlite3
                    with sqlite3.connect(database) as conn:
                        rows = conn.execute('SELECT '+key_col+',expired_time FROM tokens WHERE id=? AND user_id=(SELECT user_id FROM oauth_grants WHERE grant_ref=?)', (token,grant)).fetchall()
                else:
                    raw = self.resource.sql(database, f"SELECT {key_col},expired_time FROM tokens WHERE id={token} AND user_id=(SELECT user_id FROM oauth_grants WHERE grant_ref='{grant}');")
                    rows = [raw.split('|' if self.engine=='postgres' else '\t')] if raw else []
                if len(rows)!=1 or len(rows[0])!=2:raise ValueError('synthetic token binding absent')
                key, expiry = rows[0]
                expires = str(int(expiry))
                key_ref = hashlib.sha256(b'newapi.oauth.derived-key.v1\x00'+str(key).encode()).hexdigest()
                idem = hashlib.sha256(('fixture-idem:'+grant).encode()).hexdigest()
                req = hashlib.sha256(('fixture-request:'+grant).encode()).hexdigest()
                token_fields = f"{token},'{key_ref}','{idem}','{req}',{now}"
            statement = f"""INSERT INTO oauth_derived_token_sources
                (grant_ref,user_id,schema_version,quota_limit,expires_at,policy_hash,binding_hash,
                 verified_at,proof_expires_at,permit_deadline,verified_method,proof_flow_id,
                 token_id,key_ref,idem_hash,request_hash,created_at)
                SELECT grant_ref,user_id,1,1000,{expires},policy_hash,'{'b'*64}',
                 {now-10},{now+40},{now+40},'password',
                 (SELECT COALESCE(MAX(proof_flow_id),0)+1 FROM oauth_derived_token_sources),{token_fields}
                FROM oauth_grants WHERE grant_ref='{grant}' AND state='active';"""
        if self.engine == 'sqlite':
            import sqlite3
            with sqlite3.connect(database) as conn:
                cursor = conn.execute(statement)
                if action=='seed' and cursor.rowcount!=1:raise ValueError('synthetic grant missing')
        else:
            self.resource.sql(database,statement)
            if action=='seed' and self.resource.sql(database,f"SELECT COUNT(*) FROM oauth_derived_token_sources WHERE grant_ref='{grant}';")!='1':
                raise ValueError('synthetic grant missing')
        self.qualify(ident)
        return {'fixture_action':action,'applied':True}


def wallet_client(path, action):
    if os.geteuid()==0 or (action!='fresh' and not re.fullmatch(r'(qualify:[0-9a-f]{32}|seed:[0-9a-f]{32}:[0-9a-f]{64}:[0-9]{1,10}|source_absent:[0-9a-f]{32})',action)):
        raise ValueError('wallet client action or UID denied')
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(150);conn.connect(path)
        if struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]!=0:
            raise ValueError('wallet installer must be root')
        conn.sendall((action+'\n').encode());conn.shutdown(socket.SHUT_WR)
        data=b''
        while len(data)<=8192:
            part=conn.recv(8192)
            if not part:break
            data+=part
        if len(data)>8192:raise ValueError('wallet response too large')
        result=json.loads(data)
        sys.stdout.write(json.dumps(result))


def trusted_wallet_run(bundle,tier):
    metadata=verified_manifest(bundle)
    metadata_tier = tier in METADATA_TIERS
    lifecycle_tier = tier in LIFECYCLE_TIERS
    engine=tier.removeprefix('lifecycle-' if lifecycle_tier else 'metadata-' if metadata_tier else 'wallet-')
    expected_cwd = 'controller' if lifecycle_tier else 'router' if metadata_tier else 'service'
    expected_selector = LIFECYCLE_SELECTOR if lifecycle_tier else METADATA_SELECTOR if metadata_tier else wallet_selector(engine)
    if (os.geteuid()!=0 or metadata['tier']!=tier or len(metadata['entries'])!=1 or
        metadata['entries'][0]['cwd']!=expected_cwd or metadata['entries'][0]['run']!=expected_selector):
        raise ValueError('wallet trusted owner inventory mismatch')
    mounts=[line.split() for line in Path('/proc/mounts').read_text().splitlines()]
    runs=[m for m in mounts if m[1]=='/run']
    if (len(runs)!=1 or runs[0][2]!='tmpfs' or 'noexec' in runs[0][3].split(',') or
        not {'nosuid','nodev'}.issubset(runs[0][3].split(',')) or
        os.statvfs('/run').f_blocks*os.statvfs('/run').f_frsize>4*1024**3):
        raise ValueError('wallet requires bounded private executable tmpfs')
    if engine!='sqlite' or lifecycle_tier:
        caps=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
        if (not os.statvfs('/').f_flag & os.ST_RDONLY or Path('/proc/1/comm').read_text().strip()!='sleep' or
            int(caps['CapBnd'],16)&((1<<19)|(1<<21)) or caps['NoNewPrivs'].strip()!='1'):
            raise ValueError('wallet requires constrained fixed-image container')
    root=Path(tempfile.mkdtemp(prefix='newapi-wallet-',dir='/run'));root.chmod(0o755);owned=root.stat()
    installer=thread=process=test_log=None
    output_printed=False
    status=1
    try:
        for name,expected in metadata['files'].items():
            dst=root/'bundle'/name;dst.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(bundle/name,dst);dst.chmod(0o755 if (bundle/name).stat().st_mode&0o111 else 0o644)
            if digest(dst)!=expected:raise ValueError('wallet copied input mismatch')
        (root/'bundle/manifest.json').write_bytes((bundle/'manifest.json').read_bytes())
        uid=200000+secrets.randbelow(100000000)
        try:pwd.getpwuid(uid);raise ValueError('owner UID occupied')
        except KeyError:pass
        for proc in Path('/proc').glob('[0-9]*/status'):
            try:
                if re.search(r'^Uid:\s+'+str(uid)+r'\s',proc.read_text(),re.M):raise ValueError('owner UID active')
            except (FileNotFoundError,PermissionError):pass
        (root/'journals').mkdir(mode=0o755);(root/'tmp').mkdir(mode=0o700);os.chown(root/'tmp',uid,uid)
        launcher=root/'owner-client'
        launcher.write_text('#!/bin/sh\nexec /usr/bin/python3 '+str(root/'bundle/runner.py')+' _wallet_client '+str(root/'wallet.sock')+' "$@"\n');launcher.chmod(0o755)
        installer=(LifecycleInstaller if lifecycle_tier else WalletInstaller)(root,uid,engine,metadata);installer.start()
        env={'PATH':'/usr/bin:/bin','HOME':str(root/'tmp'),'TMPDIR':str(root/'tmp'),'GOMAXPROCS':'2',
            'NEWAPI_BOOTSTRAP_CLIENT':str(launcher),'NEWAPI_BOOTSTRAP_ENGINE':engine,
            'NEWAPI_DB_TEST_ROLE':'TRUSTED_DB_TEST_OWNER'}
        if metadata_tier or lifecycle_tier:
            env['NEWAPI_BOOTSTRAP_TIER'] = tier
        if lifecycle_tier:
            env['NEWAPI_LIFECYCLE_REDIS_RECEIPT'] = str(installer.redis_path)
        entry=metadata['entries'][0]
        print('BOOTSTRAP_TEST_START '+json.dumps(dict(entry,phase='trusted-db-test-owner',engine=engine,uid=uid)),flush=True)
        test_log=(root/'owner-test.log').open('xb')
        process=subprocess.Popen([str(root/'bundle'/entry['binary']),'-test.v','-test.count=1','-test.run='+entry['run']],
            cwd=root/'bundle/source'/expected_cwd,env=env,preexec_fn=lambda:demote(uid),stdout=test_log,stderr=subprocess.STDOUT)
        installer.process=process
        thread=threading.Thread(target=installer.serve);thread.start()
        if not installer.first_birth.wait(timeout=150) or not installer.births:
            raise RuntimeError('wallet first birth unavailable')
        # A separate non-root service receives no owner env or credentials. It
        # cannot request them through the owner IPC, or write the root journal.
        denied_uid=uid+(2 if lifecycle_tier else 1)
        try:pwd.getpwuid(denied_uid);raise ValueError('restricted probe UID occupied')
        except KeyError:pass
        for proc in Path('/proc').glob('[0-9]*/status'):
            try:
                if re.search(r'^Uid:\s+'+str(denied_uid)+r'\s',proc.read_text(),re.M):raise ValueError('restricted probe UID active')
            except (FileNotFoundError,PermissionError):pass
        first=next(iter(installer.births.values()))['receipt']
        probe = """import os,socket,sys
s=socket.socket(socket.AF_UNIX);s.settimeout(10);s.connect(sys.argv[1])
try:s.sendall(b'fresh\\n');s.shutdown(socket.SHUT_WR)
except BrokenPipeError:pass # The rejecting peer may close before request completion.
try:data=s.recv(8192)
except ConnectionResetError:data=b''
assert not data
for p in sys.argv[2:]:
 try:fd=os.open(p,os.O_WRONLY)
 except PermissionError:continue
 else:os.close(fd);raise SystemExit(1)
assert os.getgroups()==[] and 'NoNewPrivs:\\t1' in open('/proc/self/status').read()
"""
        protected=[first['Journal']]
        if engine=='sqlite':protected.append(first['Database'])
        command(['/usr/bin/python3','-c',probe,str(root/'wallet.sock'),*protected],
            env={'PATH':'/usr/bin:/bin'},preexec_fn=lambda:demote(denied_uid))
        if lifecycle_tier:
            command(['/usr/bin/python3','-c',probe,str(root/'wallet.sock'),first['Journal']],
                env={'PATH':'/usr/bin:/bin'},preexec_fn=lambda:demote(uid))
            print(json.dumps({'lifecycle_same_uid_unrelated_parent_denied':True}),flush=True)
        print(json.dumps({'wallet_restricted_service_uid':denied_uid,'owner_uid':uid,
            'owner_credentials_rejected':True,'protected_files_write_denied':protected,'empty_groups_nnp':True}),flush=True)
        process.wait(timeout=240)
        test_log.close()
        output=(root/'owner-test.log').read_bytes()
        print(output.decode(errors='replace'),end='',flush=True)
        output_printed=True
        print('BOOTSTRAP_TEST_END '+json.dumps(dict(entry,phase='trusted-db-test-owner',exit=process.returncode)),flush=True)
        validate_required_output(tier,output.decode(errors='replace'),process.returncode)
        installer.close()
        status=0
    finally:
        if process and process.poll() is None:process.kill();process.wait(timeout=10)
        if test_log:
            test_log.close()
            if not output_printed:print((root/'owner-test.log').read_text(errors='replace'),end='',flush=True)
        if installer:
            installer.stopped.set()
            if thread:thread.join(timeout=150)
            installer.server.close()
            if thread and thread.is_alive():raise RuntimeError('wallet installer did not join')
            if isinstance(installer, LifecycleInstaller):installer.redis.close()
            if installer.resource:installer.resource.close()
        now=root.lstat()
        if (now.st_dev,now.st_ino,now.st_uid)!=(owned.st_dev,owned.st_ino,0):raise RuntimeError('wallet cleanup identity changed')
        shutil.rmtree(root)
        print(json.dumps({'wallet_cleanup':str(root),'exit':status,'cleanup':True}),flush=True)
    if 'invocation' in metadata:
        print('BOOTSTRAP_TIER_RESULT '+json.dumps({'tier':tier,'invocation':metadata['invocation'],
            'manifest_sha256':digest(bundle/'manifest.json'),'producer_sha256':metadata['files']['new-api'],
            'runner_sha256':metadata['files']['runner.py'],'entries':metadata['entries'],
            'required_leaves':required_leaves(tier),'exit':status,'cleanup':True},sort_keys=True),flush=True)


# These explicit daily audit jobs reuse shared engines, never the gate databases
# or wallet owner protocol. The only mutable names have a generated W01/W82 prefix.
ORDINARY_AUDIT_SHARED = ('ordinary-audit-mysql', 'ordinary-audit-postgres', 'ordinary-audit-clickhouse')
ORDINARY_AUDIT_IMAGE = 'sha256:85b1ab67e7c7410b11da3f5b42913fc51b5b46f9cf5f07cc28a98e5f62083c5e'
ORDINARY_AUDIT_RESOURCES = {
 'mysql': ('newapi-cherry-20261022-mysql', 'sha256:6cd09145362dfe6831b14545de3d5fd6cc75c37cfd6ef8561429c1fc73518b39', '/usr/sbin/mysqld', 3306),
 'postgres': ('newapi-cherry-20261022-postgres', 'sha256:20fd00b87c6f0a89c5defff2312154761c1d84580af196bcaac19dcb0bf51547', '/usr/lib/postgresql/15/bin/postgres', 5432),
 'clickhouse': ('newapi-cherry-20261022-clickhouse', 'sha256:21c0b0ead100ba822e65cb5d1e467824be8df4af88e5972ada0ab1556d47b8c3', '/usr/bin/clickhouse', 9000),
}


def ordinary_audit_shared_dispatch(bundle, tier):
    # Docker control stays in the outer host controller. The test container gets
    # neither a daemon socket nor host networking, and starts no database daemon.
    metadata = verified_manifest(bundle)
    expected = [{'binary': 'test-0', 'cwd': 'router', 'run': ORDINARY_AUDIT_SELECTOR}]
    if tier not in ORDINARY_AUDIT_SHARED or metadata['tier'] != tier or metadata['entries'] != expected:
        raise ValueError('ordinary audit shared inventory mismatch')
    kind = tier.removeprefix('ordinary-audit-')
    name, image, executable, port = ORDINARY_AUDIT_RESOURCES[kind]
    info = json.loads(subprocess.check_output(['docker', 'inspect', name]))[0]
    if info['Image'] != image or not info['State']['Running']:
        raise ValueError('ordinary audit shared engine identity mismatch')
    executable_hash=None
    if kind=='clickhouse':
        # The exec attach transport returned empty EOF for this large binary.
        # Stream one fixed executable through Docker's archive API instead;
        # never copy an image, retain a binary, or accept an external digest.
        import tarfile
        archive=subprocess.Popen(['docker','cp',info['Id']+':'+executable,'-'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            with tarfile.open(fileobj=archive.stdout,mode='r|') as stream:
                member=stream.next()
                if member is None or not member.isfile() or member.name!='clickhouse' or not 0<member.size<=2*1024**3:
                    raise ValueError('ordinary audit daemon archive identity mismatch')
                reader=stream.extractfile(member);hasher=hashlib.sha256();total=0
                for block in iter(lambda:reader.read(1024**2),b''):
                    total+=len(block);hasher.update(block)
                if total!=member.size or stream.next() is not None:raise ValueError('ordinary audit daemon archive incomplete')
                executable_hash=hasher.hexdigest()
            archive.stdout.close()
            if archive.wait(timeout=30):raise RuntimeError('ordinary audit daemon archive failed')
        finally:
            archive.stdout.close()
            if archive.poll() is None:archive.kill();archive.wait(timeout=5)
            archive.stderr.close()
    else:
        observed=subprocess.run(['docker','exec',info['Id'],'sha256sum',executable],capture_output=True)
        match=re.fullmatch(rb'([0-9a-f]{64})  '+re.escape(executable.encode())+rb'\n',observed.stdout)
        if observed.returncode==0 and match:executable_hash=match[1].decode()
    if executable_hash is None:raise RuntimeError('ordinary audit daemon hash receipt unavailable')
    env = dict(item.split('=', 1) for item in info['Config']['Env'] if '=' in item)
    if kind == 'mysql':
        if not env.get('MYSQL_ROOT_PASSWORD') and env.get('MYSQL_ALLOW_EMPTY_PASSWORD') not in ('yes','1','true'):raise ValueError('shared MySQL administrator credential unavailable')
        admin = 'root:'+env.get('MYSQL_ROOT_PASSWORD','')+'@unix(/audit-sockets/mysql.sock)/mysql?parseTime=true'
    elif kind == 'postgres':
        from urllib.parse import quote
        if not env.get('POSTGRES_PASSWORD') and env.get('POSTGRES_HOST_AUTH_METHOD')!='trust':raise ValueError('shared PostgreSQL administrator credential unavailable')
        admin = 'postgresql://'+quote(env.get('POSTGRES_USER', 'postgres'), safe='')+':'+quote(env.get('POSTGRES_PASSWORD',''), safe='')+'@/postgres?host=/audit-sockets&sslmode=disable'
    else:
        from urllib.parse import urlencode
        if not env.get('CLICKHOUSE_PASSWORD') and env.get('CLICKHOUSE_SKIP_USER_SETUP')!='1':raise ValueError('shared ClickHouse administrator credential unavailable')
        admin = 'clickhouse://127.0.0.1:9000/default?'+urlencode({'username':env.get('CLICKHOUSE_USER','default'), 'password':env.get('CLICKHOUSE_PASSWORD','')})
    size = sum((bundle/n).stat().st_size for n in metadata['files'])
    available = int(re.search(r'^MemAvailable:\s+(\d+)', Path('/proc/meminfo').read_text(), re.M)[1])*1024
    if size+1024**3 >= 4*1024**3 or available < size+1024**3+3*1024**3:
        raise RuntimeError('ordinary audit memory budget unavailable')
    subprocess.run(['docker','image','inspect',ORDINARY_AUDIT_IMAGE],check=True,stdout=subprocess.DEVNULL)
    merged=info.get('GraphDriver',{}).get('Data',{}).get('MergedDir','')
    if kind!='clickhouse' and not re.fullmatch(r'/var/lib/docker/overlay2/[0-9a-f]{64}/merged',merged):raise ValueError('shared engine socket mount substrate unsupported')
    cid = None
    try:
        cid = subprocess.check_output(['docker','create','--pull=never','--network=container:'+info['Id'],
            '--pid=container:'+info['Id'],'--read-only','--security-opt=no-new-privileges',
            '--cap-drop=ALL','--cap-add=SETUID','--cap-add=SETGID','--cap-add=CHOWN','--cap-add=FOWNER',
            '--cap-add=DAC_OVERRIDE','--cap-add=KILL','--memory=3g','--pids-limit=128',
            '--tmpfs=/run:rw,exec,nosuid,nodev,size=4g,mode=0755',
            '--tmpfs=/var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=1m,mode=0700',
            *(['--mount=type=bind,src='+merged+('/run/mysqld/mysqld.sock' if kind=='mysql' else '/run/postgresql/.s.PGSQL.5432')+',dst=/audit-sockets/'+('mysql.sock' if kind=='mysql' else '.s.PGSQL.5432')+',readonly'] if kind!='clickhouse' else []),
            '--entrypoint=/bin/sleep',ORDINARY_AUDIT_IMAGE,'600'],text=True).strip()
        command(['docker','start',cid],stdout=subprocess.DEVNULL)
        command(['docker','exec',cid,'mkdir','/run/input'])
        archive=subprocess.Popen(['tar','-C',str(bundle),'-cf','-','.'],stdout=subprocess.PIPE)
        try:command(['docker','exec','-i',cid,'tar','-xf','-','-C','/run/input'],stdin=archive.stdout)
        finally:
            archive.stdout.close()
            if archive.wait()!=0:raise RuntimeError('ordinary audit bundle stream failed')
        control=json.dumps({'admin':admin,'exe_sha256':executable_hash,'port':port,'engine_image':image}).encode()
        subprocess.run(['docker','exec','-i',cid,'sh','-c','umask 077; cat > /run/audit-control.json'],input=control,check=True)
        command(['docker','exec','-d',cid,'sh','-c',
            'umask 077; python3 /run/input/runner.py _ordinary_audit_shared /run/input '+tier+' < /run/audit-control.json > /run/audit-result.log 2>&1; printf "%s\\n" "$?" > /run/audit-result.exit'])
        deadline=time.monotonic()+480
        receipt=None
        while receipt is None:
            probe=subprocess.run(['docker','exec',cid,'sh','-c',
                'if test -f /run/audit-result.exit; then printf "AUDIT_DONE:"; cat /run/audit-result.exit; sha256sum /run/audit-result.log; fi'],capture_output=True)
            match=re.fullmatch(rb'AUDIT_DONE:([0-9]{1,3})\n([0-9a-f]{64})  /run/audit-result.log\n',probe.stdout)
            if probe.returncode==0 and match:receipt=(int(match[1]),match[2].decode());break
            if time.monotonic()>=deadline:raise RuntimeError('ordinary audit completion receipt unavailable')
            time.sleep(0.2)
        output=b''
        while hashlib.sha256(output).hexdigest()!=receipt[1]:
            read=subprocess.run(['docker','exec',cid,'cat','/run/audit-result.log'],capture_output=True)
            if read.returncode==0:output=read.stdout
            if hashlib.sha256(output).hexdigest()==receipt[1]:break
            if time.monotonic()>=deadline:raise RuntimeError('ordinary audit retained output hash unavailable')
            time.sleep(0.2)
        exit_code=receipt[0]
        print('ORDINARY_AUDIT_EXEC '+json.dumps({'exit':exit_code,'output_bytes':len(output),'output_sha256':hashlib.sha256(output).hexdigest()}),flush=True)
        sys.stdout.buffer.write(output);sys.stdout.flush()
        after = json.loads(subprocess.check_output(['docker','inspect',name]))[0]
        if (after['Id'],after['Image'],after['State']['Pid'],after['State']['StartedAt']) != (info['Id'],info['Image'],info['State']['Pid'],info['State']['StartedAt']):
            raise RuntimeError('ordinary audit shared engine changed')
        validate_required_output(tier,output.decode(errors='replace'),exit_code)
        print('ORDINARY_AUDIT_SHARED_RESOURCE '+json.dumps({'engine':kind,'container_id':info['Id'],'engine_image':image,
            'tool_image':ORDINARY_AUDIT_IMAGE,'exe_sha256':executable_hash,'engine_unchanged':True}),flush=True)
    finally:
        if cid:
            command(['docker','rm','-f',cid],stdout=subprocess.DEVNULL)
            print('ORDINARY_AUDIT_TOOL_CLEANUP '+json.dumps({'container_id':cid,'removed':True,'shared_engine_touched':False}),flush=True)


def ordinary_audit_shared_kernel(kind, expected):
    # Shared engines are deliberately not claimed as owned Popen children.
    # Observe their current executable and listener from their same PID/net NS.
    # A fixed fork-only, nondumpable same-UID observer reads kernel metadata;
    # only its root-held socketpair can carry a complete successful result.
    comm = {'mysql':'mysqld','postgres':'postgres','clickhouse':'clickhouse-serv'}[kind]
    listeners = set()
    for name in ('tcp','tcp6'):
        for line in Path('/proc/net/'+name).read_text().splitlines()[1:]:
            row=line.split()
            if row[3]=='0A' and int(row[1].split(':')[1],16)==expected['port']:listeners.add(row[9])
    if kind!='clickhouse':
        path='/var/run/mysqld/mysqld.sock' if kind=='mysql' else '/var/run/postgresql/.s.PGSQL.5432'
        rows=[r.split() for r in Path('/proc/net/unix').read_text().splitlines()[1:]]
        unix=[r[6] for r in rows if len(r)==8 and r[7]==path and r[3]=='00010000']
        if len(unix)!=1:raise RuntimeError('ordinary audit Unix listener missing')
        listeners.update(unix)
    if not listeners:raise RuntimeError('ordinary audit listener missing')
    candidates=[]
    for p in Path('/proc').glob('[0-9]*'):
        try:
            if not (p/'comm').read_text().strip().startswith(comm):continue
            status=dict(l.split(':',1) for l in (p/'status').read_text().splitlines() if ':' in l)
            candidates.append((int(p.name),int(status['Uid'].split()[0]),(p/'stat').read_text().rsplit(')',1)[1].split()[19]))
        except (FileNotFoundError,ProcessLookupError):continue
    # PG backends may share the executable but only the postmaster owns every
    # fixed-port listening socket. Require exactly one matching kernel result.
    results=[]
    for pid,uid,start in candidates:
        if uid==0:raise RuntimeError('shared database daemon must be nonroot')
        parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);parent.settimeout(3)
        inherited=[int(p.name) for p in Path('/proc/self/fd').iterdir()]
        observer=os.fork()
        if observer==0:
            try:
                parent.close();os.setsid();libc=ctypes.CDLL(None,use_errno=True)
                if libc.prctl(4,0,0,0,0) or Path('/proc/sys/fs/suid_dumpable').read_text().strip()!='0':os._exit(1)
                demote(uid)
                if libc.prctl(4,0,0,0,0) or libc.prctl(3,0,0,0,0)!=0:os._exit(1)
                for fd in inherited:
                    if fd!=child.fileno():
                        try:os.close(fd)
                        except OSError:pass
                p=Path('/proc')/str(pid)
                before=(p/'stat').read_text().rsplit(')',1)[1].split()[19]
                exe=p/'exe';st=exe.stat();exe_hash=digest(exe)
                fds=set()
                for fd in (p/'fd').iterdir():
                    try:fds.add(os.readlink(fd))
                    except FileNotFoundError:pass
                after=(p/'stat').read_text().rsplit(')',1)[1].split()[19]
                ns={n:os.readlink(p/'ns'/n) for n in ('pid','net')}
                if before!=start or after!=start or exe_hash!=expected['exe_sha256'] or not all('socket:['+n+']' in fds for n in listeners) or ns!={n:os.readlink('/proc/self/ns/'+n) for n in ns}:os._exit(2)
                child.sendall(json.dumps({'pid':pid,'uid':uid,'start':start,'exe_sha256':exe_hash,'device':st.st_dev,'inode':st.st_ino,'listeners':sorted(listeners),'namespaces':ns}).encode());os._exit(0)
            except BaseException:os._exit(1)
        child.close();packet=b'';normal=False
        try:
            # Child may not have demoted yet; packet is accepted only after exit,
            # not from filesystem JSON, INFO, or a service-supplied claim.
            packet,_,flags,_=parent.recvmsg(4096)
            if flags&socket.MSG_TRUNC or parent.recv(1):raise RuntimeError('ordinary audit observer framing')
        except (TimeoutError,ConnectionResetError):
            os.kill(observer,9)
        finally:
            parent.close();_,status=os.waitpid(observer,0);normal=os.WIFEXITED(status) and os.WEXITSTATUS(status)==0
        if normal and packet:results.append(json.loads(packet))
    if len(results)!=1:raise RuntimeError('ordinary audit daemon/listener observation unavailable or ambiguous')
    return results[0]


def ordinary_audit_shared_run(bundle,tier):
    if os.geteuid()!=0 or tier not in ORDINARY_AUDIT_SHARED:raise ValueError('ordinary audit installer denied')
    metadata=verified_manifest(bundle)
    if metadata['tier']!=tier or metadata['entries']!=[{'binary':'test-0','cwd':'router','run':ORDINARY_AUDIT_SELECTOR}]:raise ValueError('ordinary audit inventory changed')
    mounts=[r.split() for r in Path('/proc/mounts').read_text().splitlines() if len(r.split())>3]
    run=[r for r in mounts if r[1]=='/run']
    status=dict(l.split(':',1) for l in Path('/proc/self/status').read_text().splitlines() if ':' in l)
    if (not os.statvfs('/').f_flag&os.ST_RDONLY or len(run)!=1 or run[0][2]!='tmpfs' or 'noexec' in run[0][3].split(',') or
        not {'nosuid','nodev'}.issubset(run[0][3].split(',')) or os.statvfs('/run').f_blocks*os.statvfs('/run').f_frsize>4*1024**3 or
        status['NoNewPrivs'].strip()!='1' or int(status['CapBnd'],16)&((1<<19)|(1<<21))):raise ValueError('ordinary audit isolation missing')
    expected=json.loads(sys.stdin.buffer.read(8193))
    if set(expected)!={'admin','exe_sha256','port','engine_image'}:raise ValueError('ordinary audit control input mismatch')
    kind=tier.removeprefix('ordinary-audit-');kernel=ordinary_audit_shared_kernel(kind,expected)
    root=Path(tempfile.mkdtemp(prefix='ordinary-audit-',dir='/run'));root.chmod(0o755)
    (root/'bundle').mkdir(mode=0o755);(root/'bundle').chmod(0o755)
    shutil.copyfile(bundle/'manifest.json',root/'bundle/manifest.json');(root/'bundle/manifest.json').chmod(0o644)
    uid=200000+secrets.randbelow(100000000)
    try:pwd.getpwuid(uid);raise ValueError('ordinary audit UID occupied')
    except KeyError:pass
    for p in Path('/proc').glob('[0-9]*/status'):
        try:
            if re.search(r'^Uid:\s+'+str(uid)+r'\s',p.read_text(),re.M):raise ValueError('ordinary audit UID active')
        except (FileNotFoundError,PermissionError):pass
    ident=secrets.token_hex(12);password=secrets.token_hex(32)
    main_kind=kind if kind!='clickhouse' else 'sqlite'
    main_name='newapi_w01_w82_'+ident+'_main';log_name='newapi_w01_w82_'+ident+'_log'
    main_role='w82_'+ident[:20]+'_main';log_role='w82_'+ident[:20]+'_log'
    (root/'journals').mkdir(mode=0o755);(root/'journals').chmod(0o755);(root/'data').mkdir(mode=0o700)
    (root/'tmp').mkdir(mode=0o700);os.chown(root/'tmp',uid,uid)
    journal=root/'journals/birth.json'
    env={'PATH':'/usr/bin:/bin','GOMAXPROCS':'2'}
    if main_kind!='sqlite':env['BOOTSTRAP_ADMIN_DSN']=expected['admin']
    target=str(root/'data/main.db') if main_kind=='sqlite' else main_name
    cfg={'MainKind':main_kind,'LogKind':kind,'MainDatabase':main_name,'LogDatabase':log_name,'MainRole':main_role,'LogRole':log_role,'Password':password,
         'MainDSN':'','LogDSN':'','MainAdminDSN':expected['admin'] if main_kind!='sqlite' else '', 'LogAdminDSN':expected['admin'],
         'UID':uid,'Journal':str(journal),'BinarySHA256':metadata['files']['test-0'],'ManifestSHA256':digest(bundle/'manifest.json')}
    if kind=='mysql':
        cfg['MainDSN']=main_role+':'+password+'@unix(/audit-sockets/mysql.sock)/'+main_name+'?parseTime=true'
        cfg['LogDSN']=log_role+':'+password+'@unix(/audit-sockets/mysql.sock)/'+log_name+'?parseTime=true'
    elif kind=='postgres':
        cfg['MainDSN']='postgresql://'+main_role+':'+password+'@/'+main_name+'?host=/audit-sockets&sslmode=disable'
        cfg['LogDSN']='postgresql://'+log_role+':'+password+'@/'+log_name+'?host=/audit-sockets&sslmode=disable'
    else:
        cfg['MainDSN']=target;cfg['LogDSN']='clickhouse://127.0.0.1:9000/'+log_name+'?username='+log_role+'&password='+password
    print('ORDINARY_AUDIT_IDENTITY '+json.dumps({'tier':tier,'main_database':main_name,'log_database':log_name,'main_role':main_role,'log_role':log_role,'uid':uid}),flush=True)
    private=root/'admin.json';public=root/'service.json'
    private.write_text(json.dumps(cfg));private.chmod(0o600)
    def fixture(mode):
        result=subprocess.run([str(bundle/'test-0'),'-test.v','-test.run=^TestOAuthTokensConsumerHTTP$'],
            cwd=bundle/'source/router',env=dict(env,NEWAPI_ORDINARY_AUDIT_CONFIG=str(private),NEWAPI_ORDINARY_AUDIT_SETUP=mode),capture_output=True,timeout=90)
        # Installer errors are never echoed: a server may quote SQL/credentials.
        print('ORDINARY_AUDIT_PROVISION '+json.dumps({'phase':mode,'exit':result.returncode,'output_sha256':hashlib.sha256(result.stdout+result.stderr).hexdigest(),
            'source_lines':sorted(set(re.findall(r'oauth_public_test.go:[0-9]+',(result.stdout+result.stderr).decode(errors='replace'))))[-8:],
            'metadata_controls':re.findall(r'^\s*--- (PASS|FAIL|SKIP): (TestOAuthTokensConsumerHTTP/(?:cleanup|grant|include)_metadata/[a-z0-9_]+) \(', result.stdout.decode(errors='replace'), re.M),
            'compatibility_controls':re.findall(r'PG96_ROW_SHAPE_CONTROL actual_server=([0-9]+) modified_queries=([0-9]+) actual_96_runtime=false',result.stdout.decode(errors='replace'))}),flush=True)
        if result.returncode:raise RuntimeError('ordinary audit fixture '+mode+' failed')
    try:
        result=subprocess.run([str(bundle/'new-api'),'db-bootstrap','fresh','--engine',main_kind,'--target',target,'--journal',str(journal)],env=env,capture_output=True,timeout=120)
        print('ORDINARY_AUDIT_BIRTH '+json.dumps({'engine':main_kind,'exit':result.returncode,'output_sha256':hashlib.sha256(result.stdout+result.stderr).hexdigest()}),flush=True)
        if result.returncode:raise RuntimeError('ordinary audit permanent birth failed')
        birth=json.loads(journal.read_text())
        if birth['phase']!='READY' or birth['target']!=target or birth['engine']!=main_kind:raise RuntimeError('ordinary audit birth mismatch')
        fixture('provision')
        if main_kind=='sqlite':os.chown(root/'data',uid,uid);os.chown(target,uid,uid)
        public_cfg=dict(cfg,MainAdminDSN='',LogAdminDSN='')
        public.write_text(json.dumps(public_cfg));os.chown(public,0,uid);public.chmod(0o640)
        before=digest(journal)
        service_env={'PATH':'/usr/bin:/bin','HOME':str(root/'tmp'),'TMPDIR':str(root/'tmp'),'GOMAXPROCS':'2','NEWAPI_ORDINARY_AUDIT_CONFIG':str(public)}
        result=subprocess.run([str(bundle/'test-0'),'-test.v','-test.count=1','-test.run='+ORDINARY_AUDIT_SELECTOR],cwd=bundle/'source/router',
            env=service_env,preexec_fn=lambda:demote(uid),capture_output=True,timeout=180)
        sys.stdout.buffer.write(result.stdout+result.stderr);sys.stdout.flush()
        validate_required_output(tier,result.stdout.decode(errors='replace'),result.returncode)
        if digest(journal)!=before or ordinary_audit_shared_kernel(kind,expected)!=kernel:raise RuntimeError('ordinary audit birth/kernel changed')
        print('ORDINARY_AUDIT_RESULT '+json.dumps({'tier':tier,'main_database':main_name,'log_database':log_name,'uid':uid,'kernel':kernel,
            'manifest_sha256':digest(bundle/'manifest.json'),'binary_sha256':metadata['files']['test-0'],'runner_sha256':metadata['files']['runner.py'],
            'journal_sha256':before,'exit':0,'required_leaves':required_leaves(tier),'source':'permanent CLI fresh; synthetic actors only'}),flush=True)
    finally:
        try:fixture('cleanup')
        finally:shutil.rmtree(root)
        print('ORDINARY_AUDIT_DATABASE_CLEANUP '+json.dumps({'main':main_name,'log':log_name,'cleanup':True}),flush=True)


def main():
    if len(sys.argv)==4 and sys.argv[1]=="_ordinary_audit_shared":
        ordinary_audit_shared_run(Path(sys.argv[2]),sys.argv[3]);return
    if len(sys.argv) == 4 and sys.argv[1] == '_wallet_run':
        with WalletObservationCollector():
            trusted_wallet_run(Path(sys.argv[2]), sys.argv[3])
        return
    if len(sys.argv) in (3, 4) and sys.argv[1] == '_wallet_client':
        wallet_client(sys.argv[2], sys.argv[3] if len(sys.argv) == 4 else 'fresh')
        return
    if len(sys.argv) == 3 and sys.argv[1] == '_admission_run':
        trusted_admission(sys.argv[2])
        return
    if len(sys.argv) in (3, 4) and sys.argv[1] == 'client':
        client(sys.argv[2], sys.argv[3] if len(sys.argv) == 4 else 'fresh')
        return
    if len(sys.argv) in (3, 4) and sys.argv[1] == '_run':
        trusted_run(sys.argv[2], sys.argv[3] if len(sys.argv) == 4 else 'sqlite')
        return
    if len(sys.argv) == 4 and sys.argv[1] == '_dispatch':
        dispatch_tier(Path(sys.argv[2]), sys.argv[3])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tier', choices=('all', 'sqlite', 'ordinary-audit', *ORDINARY_AUDIT_SHARED, 'postgres', 'postgres-redis', 'admission', *METADATA_TIERS, *LIFECYCLE_TIERS, *('wallet-'+e for e in WALLET_ENGINES)), default='all', help='separate required resource tier; ordinary-audit uses SQLite and does not qualify external log stores')
    parser.add_argument('--admission-assets', help='existing real embed assets, explicit admission prepare only')
    parser.add_argument('--bundle', required=True, help='new dedicated build output directory')
    parser.add_argument('--broker-inventory', action='store_true', help='uid997 isolated inventory only; not formal execution')
    parser.add_argument('--execute-prepared', action='store_true', help='verify and execute an existing prepared bundle through its outer resource scheduler')
    parser.add_argument('--prepare-only', action='store_true', help='prepare for an isolated root container instead of local sudo')
    parser.add_argument('--package', action='append', help='bounded root-package check; default retains all three Go modules')
    parser.add_argument('--run', default='.', help='Go test selector; defaults to every test')
    args = parser.parse_args()
    if args.broker_inventory:
        if args.execute_prepared or args.prepare_only or args.package or args.run != '.' or args.tier != 'all':
            parser.error('--broker-inventory cannot change full-plan selectors or execute tiers')
        print(json.dumps(broker_inventory(args.bundle), sort_keys=True))
    elif args.execute_prepared:
        if args.prepare_only or args.package or args.run != '.':
            parser.error('--execute-prepared cannot change compiled selectors')
        execute_prepared(args.bundle, args.tier)
    else:
        prepare(args)


if __name__ == '__main__':
    main()
