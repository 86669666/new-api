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

DIALECT_TESTS = {
    'service': ('TestOAuthDerivedTextRawUsageRejection', 'TestOAuthDerivedTransportDatabaseCASWire'),
    'controller': ('TestOAuthDerivedSelectedHTTP',),
}
PRODUCER_TEST = 'TestOAuthBootstrapProducer'
PG_IMAGE = 'sha256:ba9938eb70de48e82a511ea812eef26cc1399b0b072d6f2f7dc22a977e783401'
PG_SELECTOR = '^TestSessionRevocationS1Namespace$'
JOINT_IMAGE = 'sha256:894680346c8e75455a0a6c969b7b8241aeb9b6e9c0d0d95689669153d4627c4d'
JOINT_SELECTOR = '^TestSessionRevocationS1RealRedis$'
JOINT_CASES = ('deny_wrong_type', 'outbox_rollback', 'late_active_fill', 'credential_rollback')


def digest(path):
    with open(path, 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def command(argv, **kwargs):
    subprocess.run(argv, check=True, **kwargs)


def prepare(args):
    if args.tier == "admission":
        return prepare_admission(args)
    if sys.platform != 'linux':
        raise ValueError('trusted provenance test runner requires Linux')
    if args.tier == 'all' and (args.package or args.run != '.'):
        raise ValueError('bounded selectors require an explicit resource --tier')
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
    # Exact names, not prefix exclusions. Test.list freezes the compiled set;
    # each (binary, top-level test) belongs to exactly one required partition.
    if set(inventory) != {entry['binary'] for entry in entries}:
        raise ValueError('inventory package mismatch')
    routers = [e for e in entries if e['cwd'] == 'router']
    if len(routers) != 1 or any(e['run'] != '.' for e in entries):
        raise ValueError('default inventory requires one complete router package')
    router = routers[0]
    required = {'postgres': PG_SELECTOR[1:-1], 'postgres-redis': JOINT_SELECTOR[1:-1]}
    if not set(required.values()).issubset(inventory[router['binary']]):
        raise ValueError('required compiled test missing')
    partitions = {'sqlite': [], 'postgres': [], 'postgres-redis': []}
    assigned = []
    for entry in entries:
        names = inventory[entry['binary']]
        if len(names) != len(set(names)):
            raise ValueError('duplicate inventory member')
        ordinary = [n for n in names if entry != router or n not in required.values()]
        run = entry['run'] if entry != router else '^(' + '|'.join(re.escape(n) for n in ordinary) + ')$'
        if entry == router and not ordinary:
            raise ValueError('empty ordinary router partition')
        partitions['sqlite'].append(dict(entry, run=run))
        assigned.extend((entry['binary'], n) for n in ordinary)
    for tier, name in required.items():
        partitions[tier] = [dict(router, run='^'+name+'$')]
        assigned.append((router['binary'], name))
    expected = {(b, n) for b, names in inventory.items() for n in names}
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


def required_leaves(tier):
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
    if tier not in ('sqlite', 'postgres', 'postgres-redis', 'admission') or metadata['tier'] != tier:
        raise ValueError('dispatch tier mismatch')
    if tier == 'admission':
        available=int(re.search(r'^MemAvailable:\s+(\d+)',Path('/proc/meminfo').read_text(),re.M)[1])*1024
        if available < 4*1024**3:raise RuntimeError('admission needs 1GiB tmpfs plus 3GiB process margin')
        if sum((bundle/name).stat().st_size for name in metadata['files']) > 768*1024**2:
            raise RuntimeError('admission bundle exceeds private tmpfs safety budget')
        command(['sudo', '-n', 'unshare', '--mount', '--net', '--pid', '--fork', 'sh', '-c', 'mount --make-rprivate / && mount -t tmpfs -o size=1G,mode=0755,nosuid,nodev tmpfs /run && mount -t proc proc /proc && exec "$@"', 'admission-tests', sys.executable, str(bundle/'runner.py'), '_admission_run', str(bundle)])
        return
    if tier != 'sqlite':
        postgres_container(bundle, tier)
        return
    # Docker remains in the host controller, never this private net namespace.
    command(['sudo', '-n', 'unshare', '--mount', '--net', '--pid', '--fork',
             'sh', '-c', 'mount --make-rprivate / && mount -t tmpfs -o size=4G,mode=0755,nosuid,nodev tmpfs /run && ip link set lo up && exec "$@"',
             'bootstrap-tests', sys.executable, str(bundle / 'runner.py'), '_run', str(bundle)])


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
               'unexecuted': ['postgres', 'postgres-redis', 'sqlite']}
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


def client(sock, action="fresh"):
    if os.geteuid() == 0:
        raise ValueError('fixture client must be the service principal')
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(120)
        conn.connect(sock)
        if action not in ('fresh', 'redis') and not re.fullmatch(r'pg:[0-9a-f]{32}', action):
            raise ValueError('unsupported installer request')
        _, peer_uid, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if peer_uid != 0:
            raise ValueError('installer peer must be root')
        conn.sendall((action + '\n').encode())
        conn.shutdown(socket.SHUT_WR)
        data = b''
        while len(data) <= 8192:
            part = conn.recv(8192)
            if not part:
                break
            data += part
        result = json.loads(data)
        if action == 'fresh':
            fields = {'Engine', 'DSN', 'Journal'}
            if result.get('Engine') == 'postgres':
                fields.add('ResourceReceipt')
            if set(result) != fields or result['Engine'] not in ('sqlite', 'postgres'):
                raise ValueError('invalid installer response')
        sys.stdout.write(json.dumps(result))


class Installer:
    def __init__(self, root, uid, redis_resource=None, pg_resource=None):
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

    def serve(self):
        while not self.stopped.is_set():
            try:
                conn, _ = self.server.accept()
            except socket.timeout:
                continue
            with conn:
                conn.settimeout(5)
                _, peer_uid, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if peer_uid != self.uid:
                    continue
                # No client-controlled path, command, environment or namespace.
                try:
                    request = conn.recv(64)
                    if conn.recv(1) != b'':
                        continue
                    if request == b'redis\n' and self.redis_resource is not None:
                        self.redis_resource.verify()
                        conn.sendall(json.dumps(self.redis_resource.receipt).encode())
                        continue
                    if re.fullmatch(rb'pg:[0-9a-f]{32}\n', request) and self.pg_resource is not None:
                        conn.sendall(json.dumps(self.pg_resource.qualify(request[3:-1].decode())).encode())
                        continue
                    if request != b'fresh\n':
                        continue
                    if self.pg_resource is not None:
                        conn.sendall(json.dumps(self.pg_resource.birth()).encode())
                        continue
                    ident = secrets.token_hex(16)
                    data = self.root / ('data-' + ident)
                    data.mkdir(mode=0o755)
                    target = data / 'new.db'
                    journal = self.root / 'journals' / (ident + '.json')
                    argv = [str(self.root / 'bundle/new-api'), 'db-bootstrap', 'fresh', '--engine', 'sqlite', '--target', str(target), '--journal', str(journal)]
                    proc = subprocess.run(argv, env={'PATH': '/usr/bin:/bin'}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
                    self.receipts.append({'argv': argv, 'exit': proc.returncode, 'output_sha256': hashlib.sha256(proc.stdout).hexdigest(), 'peer_uid': peer_uid})
                    if proc.returncode:
                        continue
                    os.chown(target, self.uid, self.uid)
                    os.chmod(target, 0o600)
                    os.chown(data, self.uid, self.uid)
                    conn.sendall(json.dumps({'Engine': 'sqlite', 'DSN': str(target), 'Journal': str(journal)}).encode())
                except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError):
                    # Producer failure is a client failure, never a seal fallback.
                    continue



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
                exe_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
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
    image_id = PG_IMAGE if tier == 'postgres' else JOINT_IMAGE
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
            '--tmpfs', '/var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=1m,mode=0700',
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
                 'python3 /run/input/runner.py _run /run/input '+tier+' > /run/result.log 2>&1; printf "%s\\n" "$?" > /run/result.exit'])
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
    if tier not in ('sqlite', 'postgres', 'postgres-redis') or metadata.get('tier', 'sqlite') != tier:
        raise ValueError('resource tier mismatch')
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
        installer = Installer(root, uid, redis_resource, pg_resource)
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
            if pg_resource:
                pg_resource.verify()
                result = subprocess.run(argv, cwd=root / 'bundle/source' / cwd, env=env, preexec_fn=lambda: demote(uid), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
                output = result.stdout.decode(errors='replace')
                print(output, end='', flush=True)
                validate_required_output(tier, output, result.returncode)
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
        self.db, self.journal = root/'data/main.db', root/'control/birth.json'
        producer = root.parent/'bundle/new-api'
        birth = subprocess.run([str(producer), 'db-bootstrap', 'fresh', '--engine', 'sqlite', '--target', str(self.db), '--journal', str(self.journal)],
                               env={'PATH':'/usr/bin:/bin'}, capture_output=True, timeout=90)
        print(json.dumps({'admission_birth': case, 'exit': birth.returncode, 'output_sha256': hashlib.sha256(birth.stdout+birth.stderr).hexdigest()}), flush=True)
        if birth.returncode or json.loads(self.journal.read_text())['phase'] != 'READY':
            raise ValueError('permanent birth failed')
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
                    if libc.prctl(4,0,0,0,0):os._exit(1)
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


def main():
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
    parser.add_argument('--tier', choices=('all', 'sqlite', 'postgres', 'postgres-redis', 'admission'), default='all', help='separate required resource tier; no PG-to-SQLite fallback')
    parser.add_argument('--admission-assets', help='existing real embed assets, explicit admission prepare only')
    parser.add_argument('--bundle', required=True, help='new dedicated build output directory')
    parser.add_argument('--execute-prepared', action='store_true', help='verify and execute an existing prepared bundle through its outer resource scheduler')
    parser.add_argument('--prepare-only', action='store_true', help='prepare for an isolated root container instead of local sudo')
    parser.add_argument('--package', action='append', help='bounded root-package check; default retains all three Go modules')
    parser.add_argument('--run', default='.', help='Go test selector; defaults to every test')
    args = parser.parse_args()
    if args.execute_prepared:
        if args.prepare_only or args.package or args.run != '.':
            parser.error('--execute-prepared cannot change compiled selectors')
        execute_prepared(args.bundle, args.tier)
    else:
        prepare(args)


if __name__ == '__main__':
    main()
