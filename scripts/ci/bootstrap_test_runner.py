#!/usr/bin/env python3
"""Build once, then run Go tests with a Linux trusted SQLite fixture producer.

The default retains every root (except the embed-only main), relaykit and
 tokenkit package. External-engine subtests remain a separate database tier;
this entry runs their SQLite variants, never reports those as a three-DB pass.
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

DIALECT_TESTS = {
    'service': ('TestOAuthDerivedTextRawUsageRejection', 'TestOAuthDerivedTransportDatabaseCASWire'),
    'controller': ('TestOAuthDerivedSelectedHTTP',),
}
PRODUCER_TEST = 'TestOAuthBootstrapProducer'


def digest(path):
    with open(path, 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def command(argv, **kwargs):
    subprocess.run(argv, check=True, **kwargs)


def prepare(args):
    if sys.platform != 'linux':
        raise ValueError('trusted provenance test runner requires Linux')
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
    metadata = {'entries': entries, 'files': {str(p.relative_to(bundle)): digest(p) for p in sorted(bundle.rglob('*')) if p.is_file()}}
    (bundle / 'manifest.json').write_text(json.dumps(metadata, sort_keys=True))
    if args.prepare_only:
        print(json.dumps({'bundle': str(bundle), 'producer_sha256': digest(bundle / 'new-api'), 'packages': len(entries)}))
        return
    # The invoking developer is the installer authority, never the service UID.
    command(['sudo', '-n', sys.executable, str(Path(__file__).resolve()), '_run', str(bundle)])


def demote(uid):
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)
    # Even an installed setuid sudo cannot elevate the test service principal.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), 'no_new_privs failed')


def client(sock):
    if os.geteuid() == 0:
        raise ValueError('fixture client must be the service principal')
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(120)
        conn.connect(sock)
        conn.sendall(b'fresh\n')
        conn.shutdown(socket.SHUT_WR)
        data = b''
        while len(data) <= 8192:
            part = conn.recv(8192)
            if not part:
                break
            data += part
        result = json.loads(data)
        if set(result) != {'Engine', 'DSN', 'Journal'} or result['Engine'] != 'sqlite':
            raise ValueError('invalid installer response')
        sys.stdout.write(json.dumps(result))


class Installer:
    def __init__(self, root, uid):
        self.root, self.uid = root, uid
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
                    if request != b'fresh\n' or conn.recv(1) != b'':
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
                except (OSError, ValueError, subprocess.SubprocessError):
                    # Producer failure is a client failure, never a seal fallback.
                    continue


def trusted_run(bundle):
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
    root = Path(tempfile.mkdtemp(prefix='newapi-bootstrap-tests-', dir='/run'))
    root.chmod(0o755)
    root_stat = root.stat()
    installer = None
    thread = None
    status = 1
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
        launcher.write_text('#!/bin/sh\nexec /usr/bin/python3 ' + str(root / 'bundle/runner.py') + ' client ' + str(root / 'installer.sock') + '\n')
        launcher.chmod(0o755)
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(root / 'tmp'), 'TMPDIR': str(root / 'tmp'), 'NEWAPI_TEST_PROFILE': 'isolated-ci', 'NEWAPI_BOOTSTRAP_CLIENT': str(launcher), 'NEWAPI_BOOTSTRAP_ENGINE': 'sqlite'}
        # Root-only negative producer tests execute separately, not skipped away.
        for entry in metadata['entries']:
            if entry['cwd'] == 'model':
                command([str(root / 'bundle' / entry['binary']), '-test.run=^' + PRODUCER_TEST + '$', '-test.v'], cwd=root / 'bundle/source/model', env=dict(env, NEWAPI_BOOTSTRAP_ROOT_TEST_DIR=str(root / 'producer-tests')))
        installer = Installer(root, uid)
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
            command(argv, cwd=root / 'bundle/source' / cwd, env=env, preexec_fn=lambda: demote(uid))
            for name in special:
                # Go's regexp syntax is not Python's; ask the test binary whether
                # the requested top-level selector includes this dialect test.
                listing = subprocess.check_output([str(root / 'bundle' / binary), '-test.list=' + entry['run'].split('/')[0]], env=env, preexec_fn=lambda: demote(uid), text=True)
                if name in listing.splitlines():
                    command([str(root / 'bundle' / binary), '-test.v', '-test.count=1', '-test.run=^' + name + '$/sqlite'], cwd=root / 'bundle/source' / cwd, env=env, preexec_fn=lambda: demote(uid))
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
        # Exact inode/device and root ownership: never clean an adopted directory.
        current = root.lstat()
        if (current.st_dev, current.st_ino, current.st_uid) != (root_stat.st_dev, root_stat.st_ino, 0) or not stat.S_ISDIR(current.st_mode):
            raise RuntimeError('cleanup ownership mismatch')
        shutil.rmtree(root)
        print(json.dumps({'cleanup': 'removed owned ephemeral run', 'run': str(root), 'exit': status}), flush=True)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == 'client':
        client(sys.argv[2])
        return
    if len(sys.argv) == 3 and sys.argv[1] == '_run':
        trusted_run(sys.argv[2])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True, help='new dedicated build output directory')
    parser.add_argument('--prepare-only', action='store_true', help='prepare for an isolated root container instead of local sudo')
    parser.add_argument('--package', action='append', help='bounded root-package check; default retains all three Go modules')
    parser.add_argument('--run', default='.', help='Go test selector; defaults to every test')
    prepare(parser.parse_args())


if __name__ == '__main__':
    main()
