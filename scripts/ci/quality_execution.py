#!/usr/bin/env python3
"""Credential-free bounded execution; output is NEVER an authenticated receipt.

Only an independently pinned executor may import this module. Runtime is supplied
by its installed launcher, not deserialized from PR data. The launcher owns OS
isolation, the original shared heavy-test lease, and immutable tool provisioning.
The publisher must not import this module or run any candidate code.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import stat
import subprocess
import time
from typing import Callable


REPOSITORY = '86669666/new-api'
FORMAL_TIERS = ('postgres', 'postgres-redis', 'wallet-sqlite', 'wallet-mysql',
                'wallet-postgres', 'lifecycle-sqlite', 'lifecycle-mysql',
                'lifecycle-postgres', 'sqlite')


@dataclass(frozen=True)
class Command:
    id: str
    tool: str
    args: tuple[str, ...]
    cwd: str = '.'
    timeout: int = 900


# Fixed commands from ci.yml. No selectors/argv/cwd arrive in a request. Real
# assets must already exist, as required by bootstrap_test_runner.prepare.
COMMANDS = (
    Command('vet-root', 'go', ('vet', './...')),
    Command('vet-relaykit', 'go', ('vet', './...'), 'relaykit'),
    Command('vet-tokenkit', 'go', ('vet', './...'), 'tokenkit'),
    Command('build-root', 'go', ('build', './...')),
    Command('build-relaykit', 'go', ('build', './...'), 'relaykit'),
    Command('build-tokenkit', 'go', ('build', './...'), 'tokenkit'),
    Command('frontend-install', 'bun', ('install', '--frozen-lockfile'), 'web', 600),
    Command('frontend-typecheck', 'bun', ('run', 'typecheck'), 'web', 600),
    Command('frontend-test', 'bun', ('run', 'test'), 'web', 600),
    Command('database', 'python', ('-I', '-B', 'scripts/ci/database_gate.py'), timeout=1200),
    Command('policy-tests', 'python', ('-I', '-B', '-m', 'unittest', 'discover', '-s',
                                     'scripts/ci', '-p', 'test_*.py')),
    Command('consumer-tests', 'python', ('-I', '-B', '-m', 'unittest', 'discover', '-s',
                                       '.github/actions/box-formal-consumer', '-p', 'test_*.py')),
)
REQUIRED = tuple(command.id for command in COMMANDS) + ('formal',)


class ExecutionError(ValueError):
    """Sanitized, fixed error code; never include child output or credentials."""


@dataclass(frozen=True)
class Tool:
    path: Path
    sha256: str


@dataclass(frozen=True)
class Runtime:
    checkout: Path
    evidence_root: Path
    tools: dict[str, Tool]
    # These hashes must be supplied by the trusted launcher from its frozen
    # installation. A matching digest proves bytes, NOT custody/authentication.
    executor_sha256: str
    contract_sha256: str
    assets_sha256: str
    # Callbacks belong to the launcher; there is no plugin/import path in JSON.
    # Must raise on lease loss / sandbox loss, including between commands.
    check_lease: Callable[[], None]
    check_isolation: Callable[[], None]
    # Only isolated-ci loopback DSNs; never application or publisher credentials.
    database_environment: dict[str, str]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def file_digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def regular_path(path):
    path = Path(path)
    if not path.is_absolute() or any(part.is_symlink() for part in (path, *path.parents)):
        raise ExecutionError('unsafe_path')
    if not path.is_file():
        raise ExecutionError('missing_dependency')
    return path


def validate_request(request):
    keys = {'schema', 'repository', 'candidate_sha', 'candidate_tree', 'attempt_id', 'invocation'}
    if not isinstance(request, dict) or set(request) != keys:
        raise ExecutionError('invalid_request')
    if request['schema'] != 'quality-execution-request/v1' or request['repository'] != REPOSITORY:
        raise ExecutionError('wrong_repository_or_schema')
    for name, pattern in (('candidate_sha', '[0-9a-f]{40}'), ('candidate_tree', '[0-9a-f]{40}'),
                          ('attempt_id', '[a-zA-Z0-9_-]{1,80}'), ('invocation', '[0-9a-f]{64}')):
        if not isinstance(request[name], str) or re.fullmatch(pattern, request[name]) is None:
            raise ExecutionError('invalid_identity')


def child_environment(runtime, work):
    """Do not inherit HOME, PATH, Python imports, Git auth, or loader injection."""
    return {'PATH': ':'.join(dict.fromkeys(str(tool.path.parent) for tool in runtime.tools.values())) + ':/usr/bin:/bin',
            'HOME': str(work / 'home'), 'TMPDIR': str(work / 'tmp'),
            'GOCACHE': str(work / 'go-cache'), 'GOMODCACHE': str(work / 'go-mod'),
            'GOWORK': 'off', 'GOTOOLCHAIN': 'local', 'GOFLAGS': '-mod=readonly -p=2',
            'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1',
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
            'GIT_OPTIONAL_LOCKS': '0', 'GIT_TERMINAL_PROMPT': '0', 'GIT_NO_REPLACE_OBJECTS': '1',
            'LC_ALL': 'C.UTF-8', 'CI': 'true'}


def git_read(runtime, args, env):
    result = subprocess.run([str(runtime.tools['git'].path), '-c', 'core.fsmonitor=false', *args],
                            cwd=runtime.checkout, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30,
                            check=False)
    if result.returncode:
        raise ExecutionError('source_query_failed')
    return result.stdout


def source_identity(runtime, request, env):
    """Verify HEAD/tree/index and raw tracked bytes, without running clean filters."""
    head = git_read(runtime, ['rev-parse', '--verify', 'HEAD'], env).decode().strip()
    tree = git_read(runtime, ['rev-parse', '--verify', 'HEAD^{tree}'], env).decode().strip()
    if (head, tree) != (request['candidate_sha'], request['candidate_tree']):
        raise ExecutionError('source_identity_drift')
    listing = git_read(runtime, ['ls-tree', '-rz', '--full-tree', 'HEAD'], env)
    files = {}
    expected_index = []
    for entry in filter(None, listing.split(b'\0')):
        descriptor, raw_name = entry.split(b'\t', 1)
        mode, kind, blob = descriptor.split()
        if kind != b'blob' or mode not in (b'100644', b'100755'):
            raise ExecutionError('unsupported_source_entry')
        name = raw_name.decode('utf-8')
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts:
            raise ExecutionError('unsafe_source_path')
        path = regular_path(runtime.checkout / relative)
        data = path.read_bytes()
        identity = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        if identity != blob.decode() or bool(path.stat().st_mode & stat.S_IXUSR) != (mode == b'100755'):
            raise ExecutionError('dirty_source')
        files[name] = hashlib.sha256(data).hexdigest()
        expected_index.append(mode + b' ' + blob + b' 0\t' + raw_name)
    index = git_read(runtime, ['ls-files', '--stage', '-z'], env)
    if sorted(filter(None, index.split(b'\0'))) != sorted(expected_index):
        raise ExecutionError('dirty_index')
    if git_read(runtime, ['ls-files', '--others', '--exclude-standard', '-z'], env):
        raise ExecutionError('untracked_source')
    # Re-read HEAD after hashing so a concurrent ref move is not silently bound.
    if git_read(runtime, ['rev-parse', '--verify', 'HEAD'], env).decode().strip() != head:
        raise ExecutionError('source_identity_drift')
    if not files:
        raise ExecutionError('missing_source')
    return {'sha': head, 'tree': tree, 'files_sha256': hashlib.sha256(canonical(files)).hexdigest()}


def assets_identity(checkout):
    root = checkout / 'web/dist'
    regular_path(root / 'index.html')
    files = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ExecutionError('unsafe_assets')
        if path.is_file():
            files[str(path.relative_to(root))] = file_digest(path)
    return hashlib.sha256(canonical(files)).hexdigest()


def verify_runtime(runtime):
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ExecutionError('unsupported_platform')
    if os.geteuid() == 0:
        raise ExecutionError('privileged_executor_forbidden')
    if runtime.check_isolation() is not None or runtime.check_lease() is not None:
        raise ExecutionError('launcher_boundary_failed')
    checkout = runtime.checkout
    if not checkout.is_absolute() or any(p.is_symlink() for p in (checkout, *checkout.parents)):
        raise ExecutionError('unsafe_checkout')
    if checkout in Path(__file__).resolve().parents:
        raise ExecutionError('candidate_executor_forbidden')
    if set(runtime.tools) != {'git', 'go', 'bun', 'python'}:
        raise ExecutionError('missing_toolchain')
    for tool in runtime.tools.values():
        path = regular_path(tool.path)
        if checkout == path or checkout in path.parents or not os.access(path, os.X_OK):
            raise ExecutionError('unsafe_tool')
        if file_digest(path) != tool.sha256:
            raise ExecutionError('toolchain_drift')
    if file_digest(Path(__file__)) != runtime.executor_sha256:
        raise ExecutionError('executor_drift')
    if file_digest(Path(__file__).with_name('quality_execution_contract.json')) != runtime.contract_sha256:
        raise ExecutionError('contract_drift')
    if assets_identity(checkout) != runtime.assets_sha256:
        raise ExecutionError('assets_drift')


def run_child(argv, cwd, env, timeout, output_limit=8 * 1024 * 1024):
    """Real child boundary. Called only with fixed plan argv by execute().

    Hash output while draining it; never retain or echo PR-controlled output.
    A process group kill is bounded cleanup, not proof of OS sandbox teardown.
    The launcher must independently check its cgroup/namespace cleanup.
    """
    started = int(time.time())
    begin = time.monotonic()
    record = {'started_at': started, 'process_exit': None, 'status': 'launch_failed',
              'cleanup': False, 'process_reaped': False, 'stdout_bytes': 0, 'stderr_bytes': 0}
    hashes = {name: hashlib.sha256() for name in ('stdout', 'stderr')}
    process = None
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True, close_fds=True)
        record['status'] = 'running'
        with selectors.DefaultSelector() as poller:
            for name in hashes:
                pipe = getattr(process, name)
                os.set_blocking(pipe.fileno(), False)
                poller.register(pipe, selectors.EVENT_READ, name)
            while poller.get_map():
                if time.monotonic() - begin >= timeout:
                    record['status'] = 'timeout'
                    break
                for key, _ in poller.select(min(0.05, max(0, timeout - (time.monotonic() - begin)))):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        poller.unregister(key.fileobj)
                        continue
                    record[key.data + '_bytes'] += len(chunk)
                    hashes[key.data].update(chunk)
                    if record['stdout_bytes'] + record['stderr_bytes'] > output_limit:
                        record['status'] = 'output_limit'
                        break
                if record['status'] == 'output_limit':
                    break
            if record['status'] == 'running':
                try:
                    process.wait(timeout=max(0.001, timeout - (time.monotonic() - begin)))
                    record['status'] = 'passed' if process.returncode == 0 else 'failed'
                except subprocess.TimeoutExpired:
                    record['status'] = 'timeout'
    except OSError:
        record['status'] = 'launch_failed' if process is None else 'capture_failed'
    finally:
        if process is not None:
            # Kill remaining descendants even when the direct child exited zero.
            try:
                os.killpg(process.pid, signal.SIGKILL)
                if record['status'] == 'passed':
                    record['status'] = 'descendants_remaining'
            except ProcessLookupError:
                pass
            except OSError:
                record['status'] = 'cleanup_failed'
            try:
                process.wait(timeout=5)
                record['process_exit'] = process.returncode
                record['process_reaped'] = True
                # A successful kill syscall is not evidence that descendants
                # have exited. Only report group cleanup when it is absent.
                try:
                    os.killpg(process.pid, 0)
                except ProcessLookupError:
                    record['cleanup'] = record['status'] != 'cleanup_failed'
                except OSError:
                    record['status'] = 'cleanup_failed'
                if not record['cleanup'] and record['status'] == 'passed':
                    record['status'] = 'cleanup_failed'
            except subprocess.TimeoutExpired:
                record['status'] = 'cleanup_failed'
            for name in hashes:
                getattr(process, name).close()
        record.update({name + '_sha256': value.hexdigest() for name, value in hashes.items()})
        record['completed_at'] = int(time.time())
        record['duration_ms'] = max(0, int((time.monotonic() - begin) * 1000))
    return record


def execute(request, runtime):
    """Run fixed non-formal commands serially and return unauthenticated evidence.

    Full formal scope is deliberately blocked: invoking the existing default
    runner would restart stopped real authorization inventory. No fallback to
    sudo, legacy dispatch, hosted tests, or receipt synthesis is permitted.
    """
    validate_request(request)
    request = dict(request)
    inventory = [dict(id=c.id, tool=c.tool, argv=list(c.args), cwd=c.cwd, timeout=c.timeout)
                 for c in COMMANDS]
    result = {'schema': 'quality-execution-evidence/v1', 'authentication': 'UNAUTHENTICATED',
              'binding': request, 'started_at': int(time.time()), 'completed_at': None,
              'provenance': {}, 'commands': [], 'required': list(REQUIRED),
              'command_inventory': inventory,
              'command_plan_sha256': hashlib.sha256(canonical(inventory)).hexdigest(),
              'unexecuted': list(REQUIRED), 'blocked': {'formal': 'stopped_inventory_and_unproved_sanctioned_transport'},
              'formal_required_tiers': list(FORMAL_TIERS), 'exit': 1, 'cleanup': False, 'error': None}
    work = None
    try:
        verify_runtime(runtime)
        root = runtime.evidence_root
        if (not root.is_absolute() or not root.is_dir() or root == runtime.checkout or
                runtime.checkout in root.parents or any(p.is_symlink() for p in (root, *root.parents))):
            raise ExecutionError('unsafe_evidence_root')
        # Exclusive creation is the local replay guard. Retain failed attempts;
        # do not retry/reuse them or delete evidence automatically.
        candidate_work = root / request['attempt_id']
        try:
            candidate_work.mkdir(mode=0o700)
        except FileExistsError:
            raise ExecutionError('replayed_attempt') from None
        work = candidate_work
        try:
            with (root / ('invocation-' + request['invocation'])).open('x') as stream:
                stream.write(canonical(request).decode())
        except FileExistsError:
            raise ExecutionError('replayed_invocation') from None
        for name in ('home', 'tmp', 'go-cache', 'go-mod'):
            (work / name).mkdir(mode=0o700)
        env = child_environment(runtime, work)
        source = source_identity(runtime, request, env)
        result['provenance'] = {'source': source, 'executor_sha256': runtime.executor_sha256,
                                'contract_sha256': runtime.contract_sha256,
                                'assets_sha256': runtime.assets_sha256,
                                'tools': {name: {'path': str(tool.path), 'sha256': tool.sha256}
                                          for name, tool in runtime.tools.items()},
                                'platform': 'linux/amd64',
                                'custody': 'not_authenticated', 'remote_head': 'not_observed'}
        for command in COMMANDS:
            verify_runtime(runtime)
            if source_identity(runtime, request, env) != source:
                raise ExecutionError('source_identity_drift')
            stage_env = dict(env)
            if command.id == 'database':
                # Validate here without importing candidate Python into supervisor.
                db = runtime.database_environment
                if set(db) != {'NEWAPI_TEST_PROFILE', 'TEST_MYSQL_DSN', 'TEST_POSTGRES_DSN'} or db['NEWAPI_TEST_PROFILE'] != 'isolated-ci':
                    raise ExecutionError('missing_database_environment')
                if (not re.fullmatch(r'root@tcp\(127\.0\.0\.1:[0-9]{1,5}\)/newapi_ci_[a-z0-9_]+\?parseTime=true', db['TEST_MYSQL_DSN']) or
                        not re.fullmatch(r'postgres://postgres@127\.0\.0\.1:[0-9]{1,5}/newapi_ci_[a-z0-9_]+\?sslmode=disable', db['TEST_POSTGRES_DSN'])):
                    raise ExecutionError('unsafe_database_environment')
                stage_env.update(db)
            cwd = runtime.checkout / command.cwd
            if not cwd.is_dir() or any(p.is_symlink() for p in (cwd, *cwd.parents)):
                raise ExecutionError('missing_command_directory')
            argv = [str(runtime.tools[command.tool].path), *command.args]
            record = dict(id=command.id, argv=argv, cwd=command.cwd,
                          **run_child(argv, cwd, stage_env, command.timeout))
            result['commands'].append(record)
            if record['process_exit'] is not None:
                result['unexecuted'].remove(command.id)
            if record['status'] != 'passed' or not record['cleanup']:
                raise ExecutionError('command_failed')
            verify_runtime(runtime)
            if source_identity(runtime, request, env) != source:
                raise ExecutionError('source_identity_drift')
        result['error'] = 'formal_execution_blocked'
    except ExecutionError as error:
        result['error'] = str(error)
    except Exception:
        # Do not expose launcher exceptions, paths from requests, or subprocess
        # stderr. Failure remains evidence of failure, never success.
        result['error'] = 'execution_boundary_failed'
    finally:
        result['completed_at'] = int(time.time())
        # OS-isolation cleanup is not proven here. Process observations are per
        # record only; a sanctioned controller must provide authenticated proof.
        result['cleanup'] = False
        if work is not None:
            try:
                with (work / 'execution.json').open('x') as stream:
                    json.dump(result, stream, sort_keys=True)
            except OSError:
                result['error'] = 'evidence_write_failed'
    return result


def inspect_formal_result(summary, expected, process_exit, logs):
    """Inspect the existing runner's raw result, without authenticating it.

    Expected is the independently frozen full runner plan, not a plan obtained
    from the summary. Logs are bounded bytes keyed by tier; never follow paths
    in a candidate-authored result. This API neither starts the runner nor
    converts its output into a consumer receipt/admission.
    """
    try:
        if (type(process_exit) is not int or process_exit != 0 or
                summary['scope'] != 'default-full' or type(summary['exit']) is not int or
                summary['exit'] != 0 or summary['unexecuted'] != [] or
                summary['invocation'] != expected['invocation'] or
                summary['manifest_sha256'] != expected['manifest_sha256'] or
                set(expected['tiers']) != set(FORMAL_TIERS) or
                set(logs) != set(FORMAL_TIERS) or len(summary['tiers']) != len(FORMAL_TIERS)):
            raise ExecutionError('incomplete_formal_evidence')
        for name in ('invocation', 'manifest_sha256', 'producer_sha256', 'runner_sha256'):
            if not isinstance(expected[name], str) or not re.fullmatch('[0-9a-f]{64}', expected[name]):
                raise ExecutionError('invalid_formal_identity')
        seen = set()
        for record in summary['tiers']:
            tier = record['tier']
            if tier not in expected['tiers'] or tier in seen:
                raise ExecutionError('duplicate_or_unknown_formal_tier')
            seen.add(tier)
            plan = expected['tiers'][tier]
            log = logs[tier]
            if (not isinstance(log, bytes) or len(log) > 8 * 1024 * 1024 or
                    hashlib.sha256(log).hexdigest() != record['log_sha256'] or
                    type(record['exit']) is not int or record['exit'] != 0 or
                    not plan['entries'] or not isinstance(plan['required_leaves'], list) or
                    not re.fullmatch('[0-9a-f]{64}', plan['manifest_sha256'])):
                raise ExecutionError('invalid_formal_tier_evidence')
            receipt = record['receipt']
            required = dict(tier=tier, invocation=expected['invocation'],
                            manifest_sha256=plan['manifest_sha256'],
                            producer_sha256=expected['producer_sha256'],
                            runner_sha256=expected['runner_sha256'], entries=plan['entries'],
                            required_leaves=plan['required_leaves'], exit=0, cleanup=True)
            if (receipt != required or type(receipt['exit']) is not int or
                    receipt['cleanup'] is not True):
                raise ExecutionError('mismatched_formal_receipt')
            text = log.decode('utf-8', errors='strict')
            receipts = [json.loads(line.removeprefix('BOOTSTRAP_TIER_RESULT '))
                        for line in text.splitlines() if line.startswith('BOOTSTRAP_TIER_RESULT ')]
            if canonical(receipts) != canonical([required]):
                raise ExecutionError('missing_formal_log_receipt')
            events = re.findall(r'^\s*--- (PASS|FAIL|SKIP): (\S+) \(', text, re.M)
            if any(status != 'PASS' for status, _ in events) or any(
                    events.count(('PASS', leaf)) != 1 for leaf in plan['required_leaves']):
                raise ExecutionError('missing_formal_leaves')
        return {'authentication': 'UNAUTHENTICATED', 'structurally_complete': True,
                'summary_sha256': hashlib.sha256(canonical(summary)).hexdigest(),
                'provenance_authenticated': False}
    except (KeyError, TypeError, AttributeError, UnicodeError, ValueError):
        raise ExecutionError('formal_evidence_rejected') from None


if __name__ == '__main__':
    # There is intentionally no CLI accepting Runtime, shell commands, dynamic
    # adapters or trusted booleans from PR JSON. Installed callers use execute().
    print('Use execute(request, trusted_runtime) in the credential-free executor; no publisher authority.')
    raise SystemExit(2)
