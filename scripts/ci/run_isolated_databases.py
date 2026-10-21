#!/usr/bin/env python3
"""Run the bounded A03 database contract suite on its dedicated Colima daemon."""
import argparse
import functools
import json
import hashlib
import ipaddress
import socket
import os
from pathlib import Path
import re
import signal
import secrets
import stat
from urllib.parse import quote, unquote, urlsplit
from xml.sax.saxutils import escape
import subprocess
import sys
import time


SOCKET = 'unix://' + str(Path.home() / '.colima/newapi-a03/docker.sock')
IMAGES = {
    'mysql': 'docker.io/library/mysql@sha256:213bbfaf699693a40a20a12bb4342d2589a15a3dc7153db698eaed252a92458e',
    'postgres': 'docker.io/library/postgres@sha256:91a22c143801df42c2e4a8f9926eab5e48f39f40beb5220b7c29d4478263c341',
}


# The original two-engine profile stays independent of the optional log-store profile.
CLICKHOUSE_IMAGE = 'docker.io/clickhouse/clickhouse-server@sha256:55719d0c430c468baed505842a08834574bef0a76c9860d1f344d026d52c5457'
RELAY_IMAGES = dict(IMAGES, clickhouse=CLICKHOUSE_IMAGE)
NATIVE_PORTS = {'mysql': 3306, 'postgres': 5432, 'clickhouse': 9000}
CLICKHOUSE_CLIENT = '/run/newapi-clickhouse/client.xml'


class ClickHouseAuth:
    """Ephemeral owner files; never serialize this object or a usable DSN."""
    def __init__(self, directory):
        self.directory = Path(directory)
        self.owned = {}
        self.owns_directory = False
        self._password = None
        self._identity = None
        self.validate()

    @staticmethod
    def client_xml(password):
        return ('<config><host>127.0.0.1</host><port>9000</port><user>default</user>'
                '<password>' + escape(password) + '</password></config>\n').encode()

    @classmethod
    def create(cls, directory):
        directory = Path(directory)
        if not directory.is_absolute() or directory.parent.resolve() != directory.parent:
            raise ValueError('ClickHouse auth requires an absolute canonical owner directory')
        directory.mkdir(mode=0o700)  # Existing directories are never adopted.
        owned = {}
        try:
            password = secrets.token_urlsafe(48)  # 384 random bits; no real account credential.
            for name, data in (('password', password.encode()), ('client.xml', cls.client_xml(password))):
                fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as output:
                    info = os.fstat(output.fileno())
                    owned[name] = (info.st_dev, info.st_ino)
                    output.write(data)
            auth = cls(directory)
            auth.owned = owned
            auth.owns_directory = True
            return auth
        except BaseException as error:
            failures = []
            for name, identity in owned.items():
                try:
                    info = (directory / name).lstat()
                    if (info.st_dev, info.st_ino) != identity or not stat.S_ISREG(info.st_mode):
                        raise ValueError('auth file ownership changed')
                    (directory / name).unlink()
                except BaseException:
                    failures.append('owned auth file cleanup failed')
            try:
                directory.rmdir()
            except OSError:
                failures.append('owned auth directory cleanup failed')
            if failures:
                error.process_cleanup_error = '; '.join(failures)
            raise

    def validate(self):
        try:
            root = self.directory.lstat()
            if (not self.directory.is_absolute() or self.directory.resolve() != self.directory
                    or not stat.S_ISDIR(root.st_mode) or stat.S_IMODE(root.st_mode) != 0o700
                    or root.st_uid != os.getuid()
                    or {p.name for p in self.directory.iterdir()} != {'password', 'client.xml'}):
                raise ValueError('invalid owner directory')
            values = {}
            identities = [(root.st_dev, root.st_ino)]
            for name in ('password', 'client.xml'):
                with os.fdopen(os.open(self.directory / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
                    info = os.fstat(source.fileno())
                    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                            or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_size > 4096):
                        raise ValueError('invalid credential file')
                    values[name] = source.read(4097)
                    identities.append((info.st_dev, info.st_ino))
            password = values['password'].decode('ascii')
            if not 32 <= len(password) <= 256 or any(ord(c) < 33 or ord(c) > 126 for c in password):
                raise ValueError('invalid temporary password')
            # Exact reconstruction is a field allowlist: no include/env/remote host/config directives.
            if values['client.xml'] != self.client_xml(password):
                raise ValueError('client config or password mismatch')
            if self._password is not None and (self._password != password or self._identity != identities):
                raise ValueError('credential identity changed')
            self._password, self._identity = password, identities
        except (OSError, ValueError, UnicodeError):
            raise ValueError('ClickHouse private credential validation failed') from None

    def dsn(self, port, database):
        self.validate()
        if not isinstance(port, int) or not 0 < port < 65536 or not re.fullmatch(r'newapi_(?:ci|audit)_[a-z0-9_]+', database):
            raise ValueError('invalid owned ClickHouse endpoint')
        return f'clickhouse://default:{quote(self._password, safe="")}@127.0.0.1:{port}/{database}'

    def secret_values(self, env):
        """Include the actual probe credentials, even when authentication must fail."""
        values = {self._password}
        for key, value in env.items():
            if key.endswith('_DSN') and value and value != 'local':
                values.add(value)
                try:
                    password = urlsplit(value).password
                    if password:
                        values.update((password, unquote(password)))
                except ValueError:
                    pass  # The target validator rejects malformed DSNs without echoing them.
        return values

    def redact(self, text, secrets=()):
        forms = set()
        for secret in (self._password, *secrets):
            if not secret:
                continue
            encoded = quote(secret, safe='')
            forms.update((secret, encoded, re.sub(r'%[0-9A-F]{2}', lambda m: m[0].lower(), encoded),
                          escape(secret), json.dumps(secret)[1:-1]))
        for value in sorted(forms, key=len, reverse=True):
            text = text.replace(value, '[redacted-clickhouse-secret]')
        return text

    def sanitize_error(self, error, secrets=()):
        # Preserve exception classes, numeric timeout/exit fields, and every cleanup failure.
        # cmd and nested causes can participate in __str__, independently of args.
        seen = set()

        def sanitize(value):
            if isinstance(value, str):
                return self.redact(value, secrets)
            if isinstance(value, bytes):
                return self.redact(value.decode(errors='replace'), secrets).encode()
            if isinstance(value, BaseException):
                if id(value) in seen:
                    return value
                seen.add(id(value))
                value.args = sanitize(value.args)
                for name, item in list(vars(value).items()):
                    setattr(value, name, sanitize(item))
                for name in ('cmd', 'stdout', 'stderr', 'output', 'filename', 'filename2',
                             'strerror', 'reason', 'object', 'text', 'msg'):
                    if getattr(value, name, None) is not None:
                        setattr(value, name, sanitize(getattr(value, name)))
                if value.__cause__ is not None:
                    sanitize(value.__cause__)
                if value.__context__ is not None:
                    sanitize(value.__context__)
                return value
            if isinstance(value, tuple):
                return tuple(sanitize(item) for item in value)
            if isinstance(value, list):
                return [sanitize(item) for item in value]
            if isinstance(value, dict):
                return {sanitize(key): sanitize(item) for key, item in value.items()}
            return value

        return sanitize(error)

    def close(self):
        """The creating launcher calls this only after its container has been removed."""
        if not self.owns_directory:
            return
        try:
            root = self.directory.lstat()
        except FileNotFoundError:
            self.owns_directory = False
            return
        if ((root.st_dev, root.st_ino) != self._identity[0] or not stat.S_ISDIR(root.st_mode)
                or root.st_uid != os.getuid()):
            raise RuntimeError('owned ClickHouse directory identity changed')
        errors = []
        for name, identity in list(self.owned.items()):
            try:
                info = (self.directory / name).lstat()
                if ((info.st_dev, info.st_ino) != identity or not stat.S_ISREG(info.st_mode)
                        or info.st_uid != os.getuid()):
                    raise ValueError('credential ownership changed')
                (self.directory / name).unlink()
                del self.owned[name]
            except FileNotFoundError:
                del self.owned[name]
            except (OSError, ValueError):
                errors.append('owned ClickHouse credential cleanup unknown')
        if not self.owned:
            try:
                self.directory.rmdir()
                self.owns_directory = False
            except FileNotFoundError:
                pass
            except OSError:
                errors.append('owned ClickHouse directory cleanup unknown')
        if errors:
            raise RuntimeError('; '.join(errors))


def clickhouse_compose(docker, project, auth):
    """Build and validate only the optional CH service; caller owns up/down and auth.close."""
    validate_inherited_environment(os.environ)
    auth.validate()
    if not re.fullmatch(r'newapi-ci-[a-z0-9-]+', project):
        raise ValueError('invalid ClickHouse project')
    command = docker + ['compose', '-p', project, '-f', str(Path(__file__).with_name('database-compose.yml')),
                        '--profile', 'isolated-clickhouse']
    env = dict(os.environ, NEWAPI_CH_SECRET_DIR=str(auth.directory))
    spec = json.loads(run(command + ['config', '--format', 'json', 'clickhouse'], env=env))
    if (set(spec['services']) != {'clickhouse'} or set(spec['networks']) != {'isolated'}
            or spec['networks']['isolated'].get('internal') is not True):
        raise ValueError('ClickHouse must run alone on its owned internal network')
    service = dict(spec['services']['clickhouse'])
    network = dict(spec['networks']['isolated'])
    # Compose emits explicit defaults: only null preserves the image command and
    # entrypoint; empty strings/lists override them and must still be rejected.
    for field in ('command', 'entrypoint'):
        if field in service and service[field] is None:
            del service[field]
    # An empty IPAM object supplies no custom IPAM settings. Keep all other
    # representations and nonempty objects subject to the strict key allowlist.
    if network.get('ipam') == {}:
        del network['ipam']
    expected_env = {'CLICKHOUSE_PASSWORD_FILE': '/run/newapi-clickhouse/password',
                    'CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT': '0'}
    mounts = service.get('volumes', [])
    if (set(service) - {'profiles', 'image', 'pull_policy', 'platform', 'environment', 'volumes', 'networks', 'healthcheck'}
            or service.get('profiles') != ['isolated-clickhouse']
            or set(network) - {'name', 'internal'}
            or service['image'] != CLICKHOUSE_IMAGE or service.get('pull_policy') != 'never'
            or service.get('platform') != 'linux/arm64' or service.get('ports') or service.get('privileged')
            or set(service.get('networks', {})) != {'isolated'} or service.get('environment') != expected_env
            or len(mounts) != 1 or mounts[0].get('type') != 'bind'
            or mounts[0].get('source') != str(auth.directory)
            or mounts[0].get('target') != '/run/newapi-clickhouse' or mounts[0].get('read_only') is not True
            or mounts[0].get('bind', {}).get('create_host_path') is not False
            or service.get('entrypoint') or service.get('command') or service.get('network_mode')
            or service.get('healthcheck', {}).get('test') != ['CMD', 'clickhouse-client', '--config-file', CLICKHOUSE_CLIENT, '--query', 'SELECT 1']):
        raise ValueError('ClickHouse service/auth contract differs')
    return command, env


def validate_inherited_environment(env):
    """Reject application/relay configuration before any Docker operation."""
    forbidden = {'DATABASE_URL', 'SQLITE_PATH', 'DOCKER_HOST', 'DOCKER_CONTEXT',
                 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'COMPOSE_FILE',
                 'COMPOSE_PROJECT_NAME', 'COMPOSE_PROFILES'}
    if any(value and (key in forbidden or key.lower() in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy') or key.endswith('_DSN') or key.startswith('REDIS')
                      or key.startswith(('AUDIT_', 'TEST_TASK_DB', 'COMPOSE_', 'PG', 'MYSQL_', 'CLICKHOUSE_', 'NEWAPI_CH_')))
           for key, value in env.items()):
        raise ValueError('inherited database, Redis, relay or Docker override configuration is forbidden')


def live_group_members(group):
    result = subprocess.run(['ps', '-axo', 'pgid=,pid=,stat='], capture_output=True,
                            text=True, timeout=3, check=True)
    return [int(parts[1]) for line in result.stdout.splitlines()
            if len(parts := line.split()) == 3 and parts[0] == str(group)
            and not parts[2].startswith('Z')]


def terminate_group(process):
    """Coalesce repeated cancellation until this owned group is quiescent."""
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    for sig in previous:
        signal.signal(sig, signal.SIG_IGN)
    errors = []
    try:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.communicate(timeout=5)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            pass
        finally:
            # EOF/reaped group leader does not imply descendants have exited.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            process.communicate(timeout=3)
        except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
            errors.append(type(error).__name__ + ' while reaping group leader')
        deadline = time.monotonic() + 3
        while members := live_group_members(process.pid):
            if time.monotonic() >= deadline:
                errors.append('live owned process group members remain: ' + str(members))
                break
            time.sleep(0.05)
    except (Exception, KeyboardInterrupt) as error:
        errors.append(type(error).__name__ + ': process group cleanup failed')
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    return '; '.join(errors) or None


def run(command, *, env=None, timeout=30, safe_failure_output=False, guard=None, final_guard=None, binary=False):
    """Bound the child group; only explicitly sanitized gate output may be surfaced."""
    if guard is not None:
        guard()
    process = subprocess.Popen(command, env=env, text=not binary, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    try:
        stdout, stderr = guarded_communicate(process, timeout=timeout, guard=guard, final_guard=final_guard)
    except BaseException as error:
        cleanup = terminate_group(process)
        error.process_cleanup_error = '; '.join(filter(None, [getattr(error, 'process_cleanup_error', None), cleanup])) or None
        raise
    if process.returncode:
        message = f'{Path(command[0]).name} subprocess exited {process.returncode}'
        if safe_failure_output:
            output = stdout + stderr
            from database_gate import redact_output
            output = redact_output(output, env or {})
            print(output, end='', file=sys.stderr)
            message += '; sanitized database gate diagnostics emitted above'
        raise RuntimeError(message)
    return stdout


def preflight(docker, engines=('mysql', 'postgres'), preserve_volumes=None):
    if tuple(engines) not in (('mysql', 'postgres'), ('clickhouse',)):
        raise ValueError('unsupported isolated service profile')
    context = json.loads(run(docker + ['context', 'inspect']))
    if len(context) != 1 or context[0]['Endpoints']['docker']['Host'] != SOCKET:
        raise ValueError('context must resolve to the exact dedicated newapi-a03 socket')
    info = json.loads(run(docker + ['info', '--format', '{{json .}}']))
    if info['OSType'] != 'linux' or info['Architecture'] not in ('aarch64', 'arm64'):
        raise ValueError('dedicated daemon must be linux/arm64')
    # A stopped container, orphan network or unused volume can still belong to another run.
    if run(docker + ['ps', '-aq']).strip():
        raise ValueError('dedicated daemon contains existing containers or volumes; refusing takeover')
    volumes = set(run(docker + ['volume', 'ls', '-q']).splitlines())
    if preserve_volumes is None:
        if volumes:
            raise ValueError('dedicated daemon contains existing containers or volumes; refusing takeover')
    else:
        if tuple(engines) != ('mysql', 'postgres') or volumes != set(preserve_volumes):
            raise ValueError('volume set differs from the explicit organization identity baseline')
        verify_preserved_volumes(docker, preserve_volumes)
    networks = run(docker + ['network', 'ls', '--format', '{{.Name}}']).splitlines()
    if set(networks) != {'bridge', 'host', 'none'}:
        raise ValueError('dedicated daemon contains an existing non-default network')
    for image in (RELAY_IMAGES[engine] for engine in engines):
        data = json.loads(run(docker + ['image', 'inspect', image]))[0]
        expected = image.removeprefix('docker.io/').removeprefix('library/')
        digests = {digest.removeprefix('docker.io/').removeprefix('library/') for digest in data.get('RepoDigests', [])}
        if expected not in digests or data['Architecture'] != 'arm64' or data['Os'] != 'linux':
            raise ValueError('complete fixed linux/arm64 image is required; this runner never pulls')


class RelayIdentityError(RuntimeError):
    """The owned route is no longer safe; abort all dependent phases."""


def check_relays(relays, *, fresh=False):
    """One guard tick: every relay verifies its own route; identical reads are taken once."""
    tick = None if fresh else {}
    for relay in relays:
        relay.check_listener()
    for relay in relays:
        relay.check(tick)


def guarded_communicate(process, *, timeout, guard=None, input_bytes=None, final_guard=None):
    if guard is None and final_guard is None:
        return process.communicate(input_bytes, timeout=timeout)
    deadline = time.monotonic() + timeout
    first = True
    while True:
        if guard is not None:
            guard()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(process.args, timeout)
        try:
            result = process.communicate(input_bytes if first else None, timeout=min(1, remaining))
        except subprocess.TimeoutExpired:
            first = False
            continue
        # A final check is part of the same child budget. Its failures must not
        # be mistaken for a communicate polling timeout and retried.
        if time.monotonic() >= deadline:
            raise subprocess.TimeoutExpired(process.args, timeout)
        check = final_guard if final_guard is not None else guard
        if check is not None:
            check()
        if time.monotonic() >= deadline:
            raise subprocess.TimeoutExpired(process.args, timeout)
        return result


def docker_command(config, context):
    if (not config.is_absolute() or not config.is_dir() or config.is_symlink()
            or config.resolve() == (Path.home() / '.docker').resolve()):
        raise ValueError('an existing task-local Docker config directory is required')
    settings = config / 'config.json'
    values = json.loads(settings.read_text()) if settings.exists() else {}
    if set(values) - {'currentContext', 'cliPluginsExtraDirs'}:
        raise ValueError('Docker credentials/helpers/proxies are forbidden')
    if 'cliPluginsExtraDirs' in values:
        directory = config / 'cli-plugins'
        plugin = directory / 'docker-compose'
        if (values['cliPluginsExtraDirs'] != [str(directory)] or directory.is_symlink()
                or not plugin.exists() or plugin.resolve() != Path('/opt/homebrew/bin/docker-compose').resolve()):
            raise ValueError('only the exact task-local existing Compose plugin is allowed')
    return ['docker', '--config', str(config), '--context', context]


def owned_container_identity(data,network,project,engine,cid):
    labels=data['Config'].get('Labels',{})
    endpoints=data['NetworkSettings']['Networks']
    if (data['Id']!=cid or not re.fullmatch('[a-f0-9]{64}',cid) or labels.get('com.docker.compose.project')!=project
        or labels.get('com.docker.compose.service')!=engine or data['Config']['Image']!=RELAY_IMAGES[engine]
        or data['Image']!=RELAY_IMAGES[engine].split('@')[1]
        or not data['State']['Running'] or data['State'].get('Health',{}).get('Status')!='healthy'
        or data['HostConfig'].get('Privileged') or data['HostConfig']['NetworkMode']=='host' or len(endpoints)!=1):
        raise ValueError('container ownership/state/image mismatch')
    name,ep=next(iter(endpoints.items()))
    if (network['Id']!=ep['NetworkID'] or network['Name']!=name or network['Driver']!='bridge'
        or network['Internal'] is not True or network.get('Options') not in ({},None)
        or network.get('EnableIPv6') or network.get('Labels',{}).get('com.docker.compose.project')!=project
        or network.get('Labels',{}).get('com.docker.compose.network')!='isolated'
        or cid not in network.get('Containers',{})):
        raise ValueError('network ownership/isolation mismatch')
    configs=network['IPAM']['Config']
    if len(configs)!=1:raise ValueError('ambiguous subnet')
    subnet=ipaddress.IPv4Network(configs[0]['Subnet']);ip=ipaddress.IPv4Address(ep['IPAddress'])
    attached=network['Containers'][cid]['IPv4Address']
    if (ipaddress.IPv4Address('10.10.88.120') in subnet or not ip.is_private or ip not in subnet
        or ip in (subnet.network_address,subnet.broadcast_address,ipaddress.IPv4Address(configs[0]['Gateway']))
        or attached!=str(ip)+'/'+str(subnet.prefixlen) or ep.get('GlobalIPv6Address')):
        raise ValueError('invalid/protected target subnet or endpoint')
    return {'container_id':cid,'network_id':network['Id'],'ip':str(ip),'subnet':str(subnet),'image':data['Config']['Image'],'engine':engine,'project':project, 'peers':sorted(network['Containers'])}

def listeners(text,pid,port):
    lines=text.splitlines()
    return (lines.count('p'+str(pid))==1 and [line for line in lines if line.startswith('n')]==['n127.0.0.1:'+str(port)])

def published_loopback_port(data, port):
    bindings = data.get('NetworkSettings', {}).get('Ports', {}).get(port)
    if not isinstance(bindings, list) or len(bindings) != 1 or bindings[0].get('HostIp') != '127.0.0.1':
        raise ValueError('no actual literal loopback publication; null is not an endpoint')
    value = bindings[0].get('HostPort', '')
    if not isinstance(value, str) or not value.isdigit() or not 0 < int(value) < 65536:
        raise ValueError('invalid published loopback port')
    return int(value)


class OwnedRelay:
    """One foreground SSH process, one immutable owned container target, no port receipts as input."""
    def __init__(self, docker, project, engine, container, image_receipt, clickhouse_auth=None, *, organization_metadata=None):
        self.docker, self.project, self.engine, self.container = docker, project, engine, container
        self.process = None
        self.port = None
        self.initial = None
        self.boot = None
        self.receipt = {}
        if (engine not in RELAY_IMAGES or not re.fullmatch(r'newapi-ci-[a-z0-9-]+', project)
                or not re.fullmatch(r'[a-f0-9]{64}', container)):
            raise ValueError('unsupported relay engine or owner')
        self.image_receipt = Path(image_receipt)
        self.clickhouse_auth = clickhouse_auth
        self.organization_metadata = organization_metadata
        self.organization_image = None
        if organization_metadata is not None and engine not in IMAGES:
            raise ValueError('live organization image binding supports MySQL/PostgreSQL only')
        if engine == 'clickhouse':
            if not isinstance(clickhouse_auth, ClickHouseAuth):
                raise ValueError('ClickHouse requires validated private auth')
            clickhouse_auth.validate()

    def read(self, command, tick):
        # A tick memo lives only for one check_relays/cleaning pass and holds raw
        # stdout of reads that completed; every consumer parses its own copy.
        if tick is None:
            return run(command, timeout=5)
        key = tuple(command)
        if key not in tick:
            tick[key] = run(command, timeout=5)
        return tick[key]

    def snapshot(self, tick=None):
        data = json.loads(self.read(self.docker + ['inspect', self.container], tick))[0]
        if self.engine == 'clickhouse':
            self.clickhouse_auth.validate()
            expected_env = {'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                            'LANG=en_US.UTF-8', 'TZ=UTC', 'CLICKHOUSE_CONFIG=/etc/clickhouse-server/config.xml',
                            'CLICKHOUSE_PASSWORD_FILE=/run/newapi-clickhouse/password',
                            'CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=0'}
            mounts = data.get('Mounts', [])
            private = [m for m in mounts if m.get('Destination') == '/run/newapi-clickhouse']
            if (set(data['Config'].get('Env', [])) != expected_env or len(private) != 1
                    or private[0].get('Type') != 'bind' or private[0].get('RW') is not False
                    or private[0].get('Source') != str(self.clickhouse_auth.directory)
                    or any(m.get('Destination') not in ('/run/newapi-clickhouse', '/var/lib/clickhouse') for m in mounts)
                    or data['Config'].get('Entrypoint') != ['/entrypoint.sh'] or data['Config'].get('Cmd')):
                raise RelayIdentityError('ClickHouse mounted auth or entrypoint differs')
        endpoints = data['NetworkSettings']['Networks']
        if len(endpoints) != 1:
            raise RelayIdentityError('container must have exactly one internal network')
        network_id = next(iter(endpoints.values()))['NetworkID']
        network = json.loads(self.read(self.docker + ['network', 'inspect', network_id], tick))[0]
        identity = owned_container_identity(data, network, self.project, self.engine, self.container)
        if self.engine == 'clickhouse' and identity['peers'] != [self.container]:
            raise RelayIdentityError('ClickHouse profile must be the only network peer')
        # The shared internal network may contain the other explicitly owned engine only.
        for peer in identity['peers']:
            other = json.loads(self.read(self.docker + ['inspect', peer], tick))[0]
            service = other['Config'].get('Labels', {}).get('com.docker.compose.service')
            if service not in (('clickhouse',) if self.engine == 'clickhouse' else IMAGES):
                raise RelayIdentityError('unexpected network peer')
            owned_container_identity(other, network, self.project, service, peer)
        if data['HostConfig'].get('PortBindings') or any(data['NetworkSettings'].get('Ports', {}).values()):
            raise RelayIdentityError('owned relay containers must not publish host ports')
        if self.organization_image is not None:
            identity['mounts'] = data.get('Mounts', [])
        return identity

    def start(self):
        try:
            context = json.loads(run(self.docker + ['context', 'inspect'], timeout=5))
            if len(context) != 1 or context[0]['Endpoints']['docker']['Host'] != SOCKET:
                raise RelayIdentityError('wrong dedicated Docker socket')
            self.boot = run(['colima', 'ssh', '-p', 'newapi-a03', '--', 'cat', '/proc/sys/kernel/random/boot_id'], timeout=5).strip()
            if self.organization_metadata is not None:
                raw = self.image_receipt.read_bytes()
                if len(raw) > 32768:
                    raise RelayIdentityError('image receipt too large')
                proof = json.loads(raw)
                live = verify_live_organization_image(self.docker, self.engine, self.organization_metadata)
                if proof != live or live['boot_id'] != self.boot:
                    raise RelayIdentityError('current live image binding differs from the receipt')
                self.organization_image = live
            else:
                # Consume the unchanged, independently reviewed image gate's current-boot receipt.
                # The launcher must run that gate before this runner; a generic image-inspect pass is insufficient.
                with self.image_receipt.open('rb') as receipt_file:
                    raw = receipt_file.read(32769)
                if len(raw) > 32768:
                    raise ValueError('image receipt too large')
                proof = json.loads(raw)
                metadata_hash = {
                    'mysql': 'e9be5a831164f8c536fa0b5eb1355b9eb41ee779508861b2789cf3dd47861bdb',
                    'postgres': '3f68f93b0699efc8488e736c6cf876fa181236193769d266777cf3886edb7156',
                    'clickhouse': '6f7289f17ab9509426e76c1729356bbc0017ddc1dd2e58e74d8ea80c90560509',
                }[self.engine]
                checks = proof.get('containerd_binding', {}).get('checks', {})
                required = {'metadata_hash', 'metadata_object', 'verified', 'fixed_image', 'platform', 'manifest_type',
                            'config_reference', 'rootfs', 'ready', 'ready_boot', 'host', 'recorded_daemon',
                            'recorded_context', 'live_boot', 'live_context', 'live_daemon', 'receipt_metadata_hash', 'requested_image'}
                if (proof.get('accepted') is not True or proof.get('identity_mode') != 'containerd-platform-manifest'
                        or proof.get('config_proof') != 'config_bound_via_verified_manifest'
                        or proof.get('metadata_sha256') != metadata_hash
                        or proof.get('image') != RELAY_IMAGES[self.engine] or proof.get('socket') != SOCKET
                        or proof.get('boot_id') != self.boot.replace('-', '')
                        or proof.get('containerd_binding', {}).get('accepted') is not True
                        or not required <= checks.keys() or any(checks[key] is not True for key in required)):
                    raise RelayIdentityError('accepted current-boot full image mapping receipt required')
                image = json.loads(run(self.docker + ['image', 'inspect', RELAY_IMAGES[self.engine]], timeout=5))[0]
                fields = proof['fields']
                repositories = {value.removeprefix('docker.io/').removeprefix('library/') for value in image.get('RepoDigests', [])}
                expected_repository = RELAY_IMAGES[self.engine].removeprefix('docker.io/').removeprefix('library/')
                if self.engine == 'clickhouse' and (not image.get('RepoDigests') or not set(image['RepoDigests']) <= {RELAY_IMAGES[self.engine], expected_repository}):
                    raise RelayIdentityError('ClickHouse repository alias differs from fixed identity')
                if (expected_repository not in repositories or image['Id'] != RELAY_IMAGES[self.engine].split('@')[1]
                        or image['Descriptor']['digest'] != image['Id']
                        or image['Descriptor']['mediaType'] != fields['Descriptor.mediaType']['actual']
                        or image['Os'] != 'linux' or image['Architecture'] != 'arm64'
                        or image['RootFS']['Type'] != 'layers'
                        or image['RootFS']['Layers'] != [item['actual'] for item in fields['RootFS.Layers']['actual']]):
                    raise RelayIdentityError('live image no longer matches accepted mapping')
            self.initial = self.snapshot()
            config = Path.home() / '.colima/_lima/colima-newapi-a03/ssh.config'
            alias = 'lima-colima-newapi-a03'
            env = dict(os.environ, LIMA_HOME=str(Path.home() / '.colima/_lima'))
            instances = [json.loads(line) for line in run(['limactl', 'list', '--json'], env=env, timeout=5).splitlines() if line.strip()]
            vm = [item for item in instances if item.get('name') == 'colima-newapi-a03']
            ssh = run(['/usr/bin/ssh', '-G', '-F', str(config), alias], timeout=5)
            fields = dict(line.split(None, 1) for line in ssh.splitlines() if ' ' in line)
            if (len(vm) != 1 or vm[0].get('status') != 'Running' or fields.get('hostname') != '127.0.0.1'
                    or int(fields['port']) != vm[0].get('sshLocalPort')
                    or fields.get('proxycommand', 'none') != 'none' or fields.get('proxyjump', 'none') != 'none'
                    or any(key in fields for key in ('localforward', 'remoteforward', 'dynamicforward'))
                    or fields.get('permitlocalcommand', 'no') != 'no'
                    or fields.get('localcommand', 'none') != 'none'
                    or fields.get('forkafterauthentication', 'no') != 'no'):
                raise RelayIdentityError('SSH endpoint does not belong to current dedicated VM')
            destination = self.initial['ip']
            target_port = NATIVE_PORTS[self.engine]
            run(['colima', 'ssh', '-p', 'newapi-a03', '--', 'timeout', '3', 'bash', '-c',
                 '</dev/tcp/' + destination + '/' + str(target_port)], timeout=5)
            with socket.socket() as available:
                available.bind(('127.0.0.1', 0))
                self.port = available.getsockname()[1]
            command = ['/usr/bin/ssh', '-F', str(config), '-N', '-T', '-L',
                       f'127.0.0.1:{self.port}:{destination}:{target_port}']
            for option in ('GatewayPorts=no', 'ForwardAgent=no', 'ExitOnForwardFailure=yes', 'BatchMode=yes',
                           'ConnectTimeout=5', 'ServerAliveInterval=10', 'ServerAliveCountMax=2',
                           'ControlMaster=no', 'ControlPath=none'):
                command += ['-o', option]
            command.append(alias)
            self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                            text=True, start_new_session=True)
            self.receipt = dict(self.initial, boot_id=self.boot, local_address='127.0.0.1', local_port=self.port,
                                pid=self.process.pid, process_group=self.process.pid, ssh_port=int(fields['port']),
                                existing_ssh_trust=fields.get('stricthostkeychecking'),
                                image_receipt_sha256=hashlib.sha256(raw).hexdigest())
            deadline = time.monotonic() + 10
            while True:
                try:
                    self.check_listener()
                    break
                except RelayIdentityError:
                    if self.process.poll() is not None or time.monotonic() >= deadline:
                        raise
                    time.sleep(0.1)
            self.check()
            return self.port
        except BaseException as error:
            try:
                self.close()
            except BaseException as cleanup:
                error.process_cleanup_error = '; '.join(filter(None, [getattr(error, 'process_cleanup_error', None), str(cleanup)]))
            raise

    def check_listener(self):
        if self.process is None or self.process.poll() is not None:
            raise RelayIdentityError('owned relay is not alive')
        try:
            if os.getpgid(self.process.pid) != self.process.pid:
                raise RelayIdentityError('relay process group changed')
            output = run(['/usr/sbin/lsof', '-nP', '-a', '-p', str(self.process.pid), '-iTCP', '-sTCP:LISTEN', '-Fpn'], timeout=2)
            if not listeners(output, self.process.pid, self.port):
                raise RelayIdentityError('relay PID/loopback listener mismatch')
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            raise RelayIdentityError('relay listener verification failed') from error

    def check(self, tick=None):
        self.check_listener()
        try:
            if self.snapshot(tick) != self.initial:
                raise RelayIdentityError('container/network endpoint changed during test')
            boot = self.read(['colima', 'ssh', '-p', 'newapi-a03', '--', 'cat', '/proc/sys/kernel/random/boot_id'], tick).strip()
            if boot != self.boot:
                raise RelayIdentityError('VM boot changed during test')
            if self.organization_image is not None:
                current = organization_daemon_image(self.docker, self.engine, self.read, tick)
                if current != self.organization_image['daemon_image']:
                    raise RelayIdentityError('daemon, socket or fixed image binding changed during test')
        except (ValueError, OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            raise RelayIdentityError('owned route identity verification failed') from error

    def close(self):
        if self.process is not None:
            error = terminate_group(self.process)
            if error:
                raise RelayIdentityError(error)
            self.process = None
        if self.port is not None:
            with socket.socket() as probe:
                probe.settimeout(0.3)
                if probe.connect_ex(('127.0.0.1', self.port)) == 0:
                    raise RelayIdentityError('local port remains open after relay teardown')
            self.port = None



ORGANIZATION_IDENTITY_ROOTS = frozenset(('TestOrganizationLifecycleInvitationIdentity',
                                        'TestOrganizationLifecycleInvitationConflicts'))
ORGANIZATION_READ_SUITES = {
    'organization-identity': (ORGANIZATION_IDENTITY_ROOTS, 'g10-organization-identity'),
    'organization-task-read': (frozenset(('TestOrganizationTaskReadLifecycle',)), 'g10-organization-task-read'),
    'organization-invitation-presentation': (frozenset(('TestOrganizationInvitationPresentation',)), 'g11-organization-invitation-presentation'),
    'organization-task-batch': (frozenset(('TestOrganizationTaskBatchRead',)), 'g12-organization-task-batch'),
    'organization-task-export': (frozenset(('TestOrganizationTaskExport',)), 'g13-organization-task-export'),
    'organization-task-list-revocation': (frozenset(('TestOrganizationTaskListRevocation',)), 'g14-organization-task-list-revocation'),
    'organization-task-funding-isolation': (frozenset(('TestOrganizationTaskFundingIsolation',)), 'g15-organization-task-funding-isolation'),
    'organization-capabilities': (frozenset(('TestOrganizationCapabilityProjection', 'TestOrganizationAccessHTTP')), 'g16-organization-capabilities'),
    'organization-wallet': (frozenset(('TestOrganizationWalletLifecycle',)), 'g17-organization-wallet'),
    'tools-search': (frozenset(('TestToolsSearchRelayHTTP',)), 'g19-tools-search'),
    'client-events-receiver': (frozenset(('TestClientEventsReceiverHTTP',)), 'g19-client-events-receiver'),
    'client-events-receiver-http-only': (frozenset(('TestClientEventsReceiverHTTP',)), 'g19-client-events-receiver'),
    'site-description': (frozenset(('TestSiteDescriptionHTTP',)), 'g18-site-description'),
    'oauth-userinfo': (frozenset(('TestOAuthUserInfoHTTP',)), 'g19-oauth-userinfo'),
    'oauth-provider-bridge': (frozenset(('TestOAuthProviderBridgeHTTP',)), 'g19-oauth-provider-bridge'),
    'model-capability-metadata': (frozenset(('TestModelCapabilityMetadataHTTP',)), 'g19-model-capability-metadata'),
    'organization-name-uniqueness': (frozenset(('TestOrganizationNameUniqueness',)), 'g19-organization-name-uniqueness'),
}
ORGANIZATION_NAME_CASES = frozenset((
    'comparison_and_rename', 'disabled_dissolution_and_history', 'authorization_precedence',
    'transfer_preview_and_proof', 'transfer_final_recheck', 'create_create', 'rename_rename',
    'transfer_transfer', 'create_transfer', 'different_owners'))
ORGANIZATION_WALLET_CASES = frozenset((
    'proof_expired', 'root_role_revoked', 'credit_reversal_idempotency_and_retained_history',
    'quota_ceiling_reserved_protection_and_atomic_rollback', 'concurrent_request_identity',
    'credit_and_dissolution_serialize', 'publication_governance_removed', 'publication_session_revoked'))
ORGANIZATION_METADATA_SHA = {
    'mysql': 'e9be5a831164f8c536fa0b5eb1355b9eb41ee779508861b2789cf3dd47861bdb',
    'postgres': '3f68f93b0699efc8488e736c6cf876fa181236193769d266777cf3886edb7156',
}
VOLUME_FIELDS = ('Name', 'Driver', 'Labels', 'Options', 'CreatedAt', 'Scope')
CONTAINERD = ['colima', 'ssh', '-p', 'newapi-a03', '--', 'sudo', 'ctr',
              '--address', '/run/containerd/containerd.sock', '--namespace', 'moby']


def organization_daemon_image(docker, engine, read=None, tick=None):
    if engine not in IMAGES:
        raise ValueError('organization identity supports MySQL/PostgreSQL only')
    if read is None:
        read = lambda command, unused: run(command, timeout=5)
    context = json.loads(read(docker + ['context', 'inspect'], tick))
    info = json.loads(read(docker + ['info', '--format', '{{json .}}'], tick))
    image = json.loads(read(docker + ['image', 'inspect', IMAGES[engine]], tick))[0]
    expected = IMAGES[engine].removeprefix('docker.io/').removeprefix('library/')
    repositories = {v.removeprefix('docker.io/').removeprefix('library/') for v in image.get('RepoDigests', [])}
    if (len(context) != 1 or context[0]['Endpoints']['docker']['Host'] != SOCKET
            or not info.get('ID') or info.get('OSType') != 'linux' or info.get('Architecture') not in ('aarch64', 'arm64')
            or expected not in repositories or image['Id'] != IMAGES[engine].split('@')[1]
            or image['Descriptor']['digest'] != image['Id']
            or image['Descriptor']['mediaType'] != 'application/vnd.oci.image.manifest.v1+json'
            or image.get('Os') != 'linux' or image.get('Architecture') != 'arm64'
            or image.get('RootFS', {}).get('Type') != 'layers'):
        raise RelayIdentityError('dedicated daemon or fixed platform image differs')
    return {'socket': SOCKET, 'daemon_id': info['ID'], 'image': IMAGES[engine],
            'descriptor': image['Descriptor'], 'rootfs': image['RootFS'],
            'volumes': sorted((image.get('Config', {}).get('Volumes') or {}).keys())}


def verify_live_organization_image(docker, engine, metadata_file):
    """Recompute the pinned manifest/config on this boot, without old activation receipts."""
    metadata_bytes = Path(metadata_file).read_bytes()
    if len(metadata_bytes) > 65536 or hashlib.sha256(metadata_bytes).hexdigest() != ORGANIZATION_METADATA_SHA[engine]:
        raise RelayIdentityError('fixed image metadata hash differs')
    metadata = json.loads(metadata_bytes)
    if (metadata.get('mode') != 'metadata' or metadata.get('verified') is not True
            or metadata.get('digest') != IMAGES[engine].split('@')[1]
            or metadata.get('repository') != 'library/' + engine
            or metadata.get('platform') != {'os': 'linux', 'architecture': 'arm64'}):
        raise RelayIdentityError('fixed image metadata identity differs')
    boot = run(['colima', 'ssh', '-p', 'newapi-a03', '--', 'cat', '/proc/sys/kernel/random/boot_id'], timeout=5).strip()
    manifest_bytes = run(CONTAINERD + ['content', 'get', metadata['digest']], timeout=10, binary=True)
    config_bytes = run(CONTAINERD + ['content', 'get', metadata['config_digest']], timeout=10, binary=True)
    manifest, config = json.loads(manifest_bytes), json.loads(config_bytes)
    daemon_image = organization_daemon_image(docker, engine)
    if ('sha256:' + hashlib.sha256(manifest_bytes).hexdigest() != metadata['digest']
            or manifest != metadata['manifest']
            or manifest.get('mediaType') != 'application/vnd.oci.image.manifest.v1+json'
            or manifest['config']['digest'] != metadata['config_digest']
            or manifest['config']['size'] != len(config_bytes)
            or 'sha256:' + hashlib.sha256(config_bytes).hexdigest() != metadata['config_digest']
            or config.get('os') != 'linux' or config.get('architecture') != 'arm64'
            or config.get('rootfs') != metadata['rootfs']
            or daemon_image['rootfs'] != {'Type': 'layers', 'Layers': metadata['rootfs']['diff_ids']}
            or daemon_image['volumes'] != sorted((config.get('config', {}).get('Volumes') or {}).keys())
            or daemon_image['descriptor'].get('size') != len(manifest_bytes)
            or run(['colima', 'ssh', '-p', 'newapi-a03', '--', 'cat', '/proc/sys/kernel/random/boot_id'], timeout=5).strip() != boot):
        raise RelayIdentityError('current containerd manifest/config/rootfs binding differs')
    return {'format': 'live-fixed-organization-image-v1', 'boot_id': boot,
            'metadata_sha256': ORGANIZATION_METADATA_SHA[engine],
            'manifest_sha256': hashlib.sha256(manifest_bytes).hexdigest(),
            'config_sha256': hashlib.sha256(config_bytes).hexdigest(),
            'containerd_socket': '/run/containerd/containerd.sock', 'containerd_namespace': 'moby',
            'daemon_image': daemon_image}


def volume_identity(value):
    return {field: value[field] for field in VOLUME_FIELDS}


def preserved_volume_baseline(path):
    values = json.loads(path.read_text())
    if (not isinstance(values, list) or len(values) != 2
            or any(not isinstance(value, dict) or set(value) != set(VOLUME_FIELDS)
                   or not re.fullmatch(r'[a-f0-9]{64}', value.get('Name', '')) for value in values)):
        raise ValueError('exact two-volume preservation baseline required')
    result = {value['Name']: value for value in values}
    if len(result) != 2:
        raise ValueError('duplicate preservation volume')
    return result


def verify_preserved_volumes(docker, baseline):
    for name, expected in baseline.items():
        actual = json.loads(run(docker + ['volume', 'inspect', name]))
        if len(actual) != 1 or volume_identity(actual[0]) != expected:
            raise ValueError('preserved volume identity changed')
        if run(docker + ['ps', '-aq', '--filter', 'volume=' + name]).strip():
            raise ValueError('preserved volume must remain unmounted')


def capture_organization_mounts(docker, project, engine, cid, image, preserved, owned):
    """Only claim anonymous image data volumes seen on our unstarted container."""
    data = json.loads(run(docker + ['inspect', cid]))[0]
    labels = data.get('Config', {}).get('Labels', {})
    if (data.get('Id') != cid or labels.get('com.docker.compose.project') != project
            or labels.get('com.docker.compose.service') != engine
            or data['Config'].get('Image') != IMAGES[engine] or data.get('Image') != IMAGES[engine].split('@')[1]
            or data.get('State', {}).get('Running') or data.get('State', {}).get('StartedAt') != '0001-01-01T00:00:00Z'
            or data.get('HostConfig', {}).get('Binds') or data['HostConfig'].get('Mounts')
            or data['HostConfig'].get('VolumesFrom')):
        raise ValueError('unstarted owned container identity or mount configuration differs')
    mounts = data.get('Mounts', [])
    if {mount.get('Destination') for mount in mounts} != set(image['daemon_image']['volumes']) or len(mounts) != len(image['daemon_image']['volumes']):
        raise ValueError('container mounts differ from fixed image data directories')
    for mount in mounts:
        name = mount.get('Name', '')
        if (mount.get('Type') != 'volume' or mount.get('Driver') != 'local' or mount.get('RW') is not True
                or not re.fullmatch(r'[a-f0-9]{64}', name) or name in preserved or name in owned):
            raise ValueError('historical, duplicate or unknown container mount refused before start')
        value = json.loads(run(docker + ['volume', 'inspect', name]))[0]
        if (value.get('Name') != name or value.get('Driver') != 'local' or value.get('Scope') != 'local'
                or value.get('Options') not in (None, {}) or value.get('Labels') != {'com.docker.volume.anonymous': ''}
                or value.get('Mountpoint') != mount.get('Source')):
            raise ValueError('new anonymous image volume identity differs')
        attached = run(docker + ['ps', '-aq', '--no-trunc', '--filter', 'volume=' + name]).splitlines()
        if attached != [cid]:
            raise ValueError('new data volume is shared with another container')
        owned[name] = volume_identity(value)
    return mounts


def cleanup_organization_volumes(docker, preserved, owned):
    """Never infer ownership from a volume-set difference or remove preserved volumes."""
    verify_preserved_volumes(docker, preserved)
    errors = []
    for name, identity in owned.items():
        try:
            if name in preserved:
                raise ValueError('preserved volume cannot be owned')
            actual = json.loads(run(docker + ['volume', 'inspect', name]))
            if len(actual) != 1 or volume_identity(actual[0]) != identity:
                raise ValueError('owned volume identity changed')
            if run(docker + ['ps', '-aq', '--filter', 'volume=' + name]).strip():
                raise ValueError('owned volume remains attached')
            run(docker + ['volume', 'rm', name])
        except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as error:
            errors.append(str(error))
    verify_preserved_volumes(docker, preserved)
    if set(run(docker + ['volume', 'ls', '-q']).splitlines()) != set(preserved):
        errors.append('unknown or owned volumes remain; no unrecorded volume was deleted')
    if errors:
        raise RuntimeError('; '.join(errors))


def validate_organization_identity_events(events, suite='organization-identity'):
    if suite not in ORGANIZATION_READ_SUITES:
        raise ValueError('unsupported organization read suite')
    required, _ = ORGANIZATION_READ_SUITES[suite]
    package = 'github.com/QuantumNous/new-api/router'
    if any(event.get('Action') in ('fail', 'skip') for event in events):
        raise ValueError('organization identity suite failed or skipped')
    passed = {event.get('Test') for event in events if event.get('Action') == 'pass' and event.get('Package') == package}
    roots = {name.split('/', 1)[0] for name in passed if name is not None}
    if roots != required or None not in passed:
        raise ValueError('both exact HTTP roots and router package must pass')
    if suite == 'organization-capabilities' and passed != required | {None,
            'TestOrganizationCapabilityProjection/capability_projection',
            'TestOrganizationAccessHTTP/five_operations_roles_and_wire_precision'}:
        raise ValueError('both exact capability projection subtests must pass without unrelated tests')
    if suite == 'organization-wallet' and passed != required | {None} | {
            'TestOrganizationWalletLifecycle/' + name for name in ORGANIZATION_WALLET_CASES}:
        raise ValueError('every exact wallet regression case must pass without unrelated tests')
    if suite == 'tools-search' and passed != required | {None} | {
            'TestToolsSearchRelayHTTP/' + name for name in (
                'admission_and_fixed_routing', 'structured_response_and_request_settlement',
                'upstream_failures_and_refunds')}:
        raise ValueError('every exact native search case must pass without unrelated tests')
    if suite == 'site-description' and passed != required | {None,
            'TestSiteDescriptionHTTP/shared_identity_and_reopen',
            'TestSiteDescriptionHTTP/reserved_option_and_failures',
            'TestSiteDescriptionHTTP/anonymous_links_and_navigation'}:
        raise ValueError('every exact site description case must pass without unrelated tests')
    if suite in ('client-events-receiver', 'client-events-receiver-http-only') and passed != required | {None} | {
            'TestClientEventsReceiverHTTP/' + name for name in (
                'current_credentials_and_isolation', 'validation_and_resource_limits',
                'durability_and_deduplication', 'cleanup_and_current_authority')}:
        raise ValueError('every exact client receiver case must pass without unrelated tests')
    if suite == 'oauth-provider-bridge' and passed != required | {None} | {
            'TestOAuthProviderBridgeHTTP/' + name for name in (
                'real_session_and_explicit_decision', 'challenge_client_pkce_binding',
                'claim_production_and_userinfo', 'replay_revocation_and_privacy')}:
        raise ValueError('every exact OAuth provider bridge case must pass without unrelated tests')
    if suite == 'oauth-userinfo' and passed != required | {None} | {
            'TestOAuthUserInfoHTTP/' + name for name in (
                'default_off_and_type_boundary', 'live_profile_and_scope', 'uncached_final_state', 'upstream_failure_and_isolation')}:
        raise ValueError('every exact OAuth userinfo case must pass without unrelated tests')
    if suite == 'model-capability-metadata' and passed != required | {None} | {
            'TestModelCapabilityMetadataHTTP/' + name for name in (
                'authorized_projection_and_versions', 'strict_input_and_atomicity', 'reserved_option_identity', 'reload_and_catalog_independence')}:
        raise ValueError('every exact model metadata case must pass without unrelated tests')
    if suite == 'organization-name-uniqueness' and passed != required | {None} | {
            'TestOrganizationNameUniqueness/' + name for name in ORGANIZATION_NAME_CASES}:
        raise ValueError('every exact name uniqueness case must pass without unrelated tests')
    return {'roots': sorted(required), 'passed_tests_and_subtests': len(passed) - 1,
            'package': package, 'skip': 0, 'fail': 0}


def run_organization_identity(args, docker):
    suite = getattr(args, 'suite', 'organization-identity')
    if suite not in ORGANIZATION_READ_SUITES:
        raise ValueError('unsupported organization read suite')
    required_roots, fixture_owner = ORGANIZATION_READ_SUITES[suite]
    wallet_runtime = getattr(args, 'wallet_runtime', None)
    client_events_runtime = getattr(args, 'client_events_runtime', None)
    root = Path(__file__).resolve().parents[2]
    migration_runtime = wallet_runtime if suite == 'organization-wallet' else client_events_runtime
    if suite in ('organization-wallet', 'client-events-receiver'):
        if (migration_runtime is None or not migration_runtime.is_absolute() or migration_runtime.resolve() != migration_runtime
                or migration_runtime.exists() or not migration_runtime.parent.is_dir() or root in migration_runtime.parents):
            raise ValueError('migration suite requires its new explicit runtime outside the checkout')
    if wallet_runtime is not None and suite != 'organization-wallet':
        raise ValueError('wallet runtime cannot alter another suite')
    if client_events_runtime is not None and suite != 'client-events-receiver':
        raise ValueError('client event runtime cannot alter another suite')
    if args.image_metadata is None or args.preserve_volumes is None or args.go is None:
        raise ValueError('organization identity requires explicit metadata, preservation baseline and Go paths')
    if any(value and key.startswith('NEWAPI_S2_') for key, value in os.environ.items()):
        raise ValueError('inherited organization fixture configuration is forbidden')
    if args.image_evidence.exists() or args.relay_evidence.exists():
        raise ValueError('organization image directory and relay evidence must be new')
    preserved = preserved_volume_baseline(args.preserve_volumes)
    preflight(docker, preserve_volumes=preserved)
    compose = docker + ['compose', '-p', args.project, '-f', str(Path(__file__).with_name('database-compose.yml')), '--profile', 'isolated-ci']
    spec = json.loads(run(compose + ['config', '--format', 'json', 'mysql', 'postgres']))
    if set(spec['services']) != set(IMAGES) or set(spec['networks']) != {'isolated'} or spec['networks']['isolated'].get('internal') is not True:
        raise ValueError('organization identity requires exactly the existing isolated MySQL/PostgreSQL profile')
    for engine, fixed in IMAGES.items():
        item = spec['services'][engine]
        allowed = {'profiles', 'image', 'pull_policy', 'platform', 'environment', 'networks', 'healthcheck', 'command', 'entrypoint'}
        if (set(item) - allowed or item['image'] != fixed or item.get('pull_policy') != 'never'
                or item.get('platform') != 'linux/arm64' or item.get('command') is not None or item.get('entrypoint') is not None
                or set(item.get('networks', {})) != {'isolated'}):
            raise ValueError('organization Compose service differs from fixed no-mount inputs')
    images = {engine: verify_live_organization_image(docker, engine, args.image_metadata / (engine + '-metadata.json')) for engine in IMAGES}
    if len({(image['boot_id'], image['daemon_image']['daemon_id']) for image in images.values()}) != 1:
        raise ValueError('image verification crossed a boot or daemon change')
    args.image_evidence.mkdir(mode=0o700)
    for engine, image in images.items():
        (args.image_evidence / (engine + '.json')).write_text(json.dumps(image, indent=2) + '\n')
    containers, mounts, owned, relays, results = {}, {}, {}, [], {}
    primary_error = cleanup_error = process_cleanup_error = None
    migrations = None
    try:
        # create never starts entrypoints. Inspect all mounts before either DB can write.
        run(compose + ['create', '--pull', 'never', 'mysql', 'postgres'], timeout=90)
        for engine in IMAGES:
            cid = run(compose + ['ps', '-aq', engine]).strip()
            if not re.fullmatch(r'[a-f0-9]{64}', cid):
                raise ValueError('one exact owned unstarted container required')
            containers[engine] = cid
            mounts[engine] = capture_organization_mounts(docker, args.project, engine, cid, images[engine], preserved, owned)
        verify_preserved_volumes(docker, preserved)
        if set(run(docker + ['volume', 'ls', '-q']).splitlines()) != set(preserved) | set(owned):
            raise ValueError('unrecorded volume appeared before start')
        run(compose + ['start', '--wait', '--wait-timeout', '180', 'mysql', 'postgres'], timeout=210)
        endpoints = {}
        for engine, cid in containers.items():
            relay = OwnedRelay(docker, args.project, engine, cid, args.image_evidence / (engine + '.json'),
                               organization_metadata=args.image_metadata / (engine + '-metadata.json'))
            relays.append(relay)
            port = relay.start()
            if relay.initial['mounts'] != mounts[engine]:
                raise RelayIdentityError('mount identity changed between create and relay start')
            endpoints[engine] = port
        args.relay_evidence.write_text(json.dumps([relay.receipt for relay in relays], indent=2) + '\n')
        root = Path(__file__).resolve().parents[2]
        if suite in ('organization-wallet', 'client-events-receiver'):
            from released_database_gate import run_organization_wallet_migrations
            migrations = run_organization_wallet_migrations(root, migration_runtime,
                args.image_evidence / ('client-events-migration' if suite == 'client-events-receiver' else 'wallet-migration'),
                args.go, docker, args.project, containers, relays, client_events=suite == 'client-events-receiver')
            print(json.dumps({'suite': suite, 'migration_phases': len(migrations['phases']),
                              'release_commit': migrations['release_commit'], 'migration_passed': migrations['passed']}), flush=True)
        for dialect in ('sqlite', 'mysql', 'postgres'):
            env = dict(os.environ, NEWAPI_TEST_PROFILE='isolated-ci', NEWAPI_S2_OWNED=fixture_owner,
                       NEWAPI_S2_MAIN=dialect, NEWAPI_S2_LOG=dialect, NEWAPI_S2_CACHE_MODE='none',
                       NEWAPI_S2_MAIN_DSN='', NEWAPI_S2_LOG_DSN='')
            if dialect != 'sqlite':
                port = endpoints[dialect]
                env['NEWAPI_S2_' + dialect.upper() + '_PORT'] = str(port)
                env['NEWAPI_S2_MAIN_DSN'] = (f'root@tcp(127.0.0.1:{port})/newapi_ci_contracts?parseTime=true' if dialect == 'mysql'
                                              else f'postgres://postgres@127.0.0.1:{port}/newapi_ci_contracts?sslmode=disable')
            selection = '^(' + '|'.join(sorted(required_roots)) + ')$'
            if suite == 'organization-capabilities':
                selection += '/^(capability_projection|five_operations_roles_and_wire_precision)$'
            command = [str(args.go), '-C', str(root), 'test', '-json', '-count=1', '-timeout=240s',
                       '-run=' + selection, './router']
            output = run(command, env=env, timeout=270, safe_failure_output=True,
                         guard=functools.partial(check_relays, relays), final_guard=functools.partial(check_relays, relays, fresh=True))
            from database_gate import redact_output
            (args.image_evidence / (dialect + '-http.jsonl')).write_text(redact_output(output, env))
            events = [json.loads(line) for line in output.splitlines() if line.strip()]
            results[dialect] = validate_organization_identity_events(events, suite)
            print(json.dumps({'dialect': dialect, **results[dialect]}), flush=True)
        if set(results) != {'sqlite', 'mysql', 'postgres'}:
            raise ValueError('organization identity requires all three real dialects')
    except (Exception, KeyboardInterrupt) as error:
        primary_error = f'{type(error).__name__}: {error}'
        process_cleanup_error = getattr(error, 'process_cleanup_error', None)
    finally:
        saved = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        for sig in saved:
            signal.signal(sig, signal.SIG_IGN)
        errors = []
        for relay in reversed(relays):
            try:
                relay.close()
            except BaseException as error:
                errors.append(str(error))
        if errors:
            process_cleanup_error = '; '.join(errors)
        try:
            boot = run(['colima', 'ssh', '-p', 'newapi-a03', '--', 'cat', '/proc/sys/kernel/random/boot_id'], timeout=5).strip()
            for engine in IMAGES:
                if boot != images[engine]['boot_id'] or organization_daemon_image(docker, engine) != images[engine]['daemon_image']:
                    raise RelayIdentityError('cleanup cannot cross a boot, daemon or fixed image change')
                # A failed create can still have made an unstarted owned service.
                # Reconcile that exact service before down; unknown mounts stay unclaimed.
                if engine not in containers:
                    cid = run(compose + ['ps', '-aq', engine]).strip()
                    if cid:
                        if not re.fullmatch(r'[a-f0-9]{64}', cid):
                            raise ValueError('ambiguous partial-create container')
                        containers[engine] = cid
                        capture_organization_mounts(docker, args.project, engine, cid, images[engine], preserved, owned)
            current = set(run(docker + ['ps', '-aq', '--no-trunc', '--filter', 'label=com.docker.compose.project=' + args.project]).splitlines())
            if current != set(containers.values()):
                raise ValueError('unknown project container appeared; refusing project cleanup')
            # No --volumes: preserved/unknown mounts can never be deleted by Compose.
            run(compose + ['down', '--timeout', '20'], timeout=90)
            if run(docker + ['ps', '-aq', '--filter', 'label=com.docker.compose.project=' + args.project]).strip():
                raise RuntimeError('owned containers remain')
            if run(docker + ['network', 'ls', '-q', '--filter', 'label=com.docker.compose.project=' + args.project]).strip():
                raise RuntimeError('owned network remains')
            cleanup_organization_volumes(docker, preserved, owned)
        except (Exception, KeyboardInterrupt) as error:
            cleanup_error = f'{type(error).__name__}: {error}'
        finally:
            for sig, handler in saved.items():
                signal.signal(sig, handler)
    summary = {'suite': suite, 'dialects': results, 'primary_error': primary_error,
               'process_cleanup_error': process_cleanup_error, 'cleanup_error': cleanup_error}
    if suite in ('organization-wallet', 'client-events-receiver'):
        summary['migrations'] = migrations
    print(json.dumps(summary), flush=True)
    return int(primary_error is not None or process_cleanup_error is not None or cleanup_error is not None)

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', required=True)
    parser.add_argument('--project', required=True)
    parser.add_argument('--docker-config', type=Path, required=True)
    parser.add_argument('--image-evidence', type=Path, required=True)
    parser.add_argument('--relay-evidence', type=Path, required=True)
    parser.add_argument('--suite', choices=('database-contract', *ORGANIZATION_READ_SUITES), default='database-contract')
    parser.add_argument('--image-metadata', type=Path)
    parser.add_argument('--preserve-volumes', type=Path)
    parser.add_argument('--go', type=Path)
    parser.add_argument('--wallet-runtime', type=Path)
    parser.add_argument('--client-events-runtime', type=Path)
    args = parser.parse_args(argv)
    validate_inherited_environment(os.environ)
    if not re.fullmatch(r'newapi-ci-[a-z0-9-]+', args.project):
        raise ValueError('a unique newapi-ci-* project name is required')
    docker = docker_command(args.docker_config, args.context)
    if args.suite in ORGANIZATION_READ_SUITES:
        return run_organization_identity(args, docker)
    if args.image_metadata is not None or args.preserve_volumes is not None or args.go is not None or args.wallet_runtime is not None or args.client_events_runtime is not None:
        raise ValueError('organization-only inputs cannot alter the default database gate')
    preflight(docker)
    compose = docker + ['compose', '-p', args.project, '-f', str(Path(__file__).with_name('database-compose.yml')),
                        '--profile', 'isolated-ci']
    spec = json.loads(run(compose + ['config', '--format', 'json', 'mysql', 'postgres']))
    if set(spec['services']) != set(IMAGES) or set(spec['networks']) != {'isolated'} or not spec['networks']['isolated'].get('internal'):
        raise ValueError('Compose must contain only the two isolated database services and internal network')
    for service, image in IMAGES.items():
        item = spec['services'][service]
        if (item['image'] != image or item.get('pull_policy') != 'never'
                or item.get('platform') != 'linux/arm64' or item.get('volumes')
                or set(item.get('networks', {})) != {'isolated'}
                or item.get('ports')):
            raise ValueError('Compose image, mount, internal network or no-publication contract differs')
    if args.relay_evidence.exists():
        raise ValueError('relay evidence must be a new file')
    relays = []
    primary_error = None
    cleanup_error = None
    process_cleanup_error = None
    try:
        run(compose + ['up', '-d', '--pull', 'never', '--wait', '--wait-timeout', '180', 'mysql', 'postgres'], timeout=210)
        env = dict(os.environ, NEWAPI_TEST_PROFILE='isolated-ci')
        for service, key in [('mysql', 'TEST_MYSQL_DSN'), ('postgres', 'TEST_POSTGRES_DSN')]:
            identity = run(compose + ['ps', '-q', service]).strip()
            if not re.fullmatch(r'[0-9a-f]{12,64}', identity):
                raise ValueError('expected exactly one owned service container')
            relay = OwnedRelay(docker, args.project, service, identity,
                               args.image_evidence / (service + '-cache') / 'inspect-receipt.json')
            relays.append(relay)
            host_port = relay.start()
            address = '127.0.0.1:' + str(host_port)
            env[key] = (f'root@tcp({address})/newapi_ci_contracts?parseTime=true' if service == 'mysql'
                        else f'postgres://postgres@{address}/newapi_ci_contracts?sslmode=disable')
            print(f'{service}: {address}, owned container={identity}', flush=True)
        args.relay_evidence.write_text(json.dumps([relay.receipt for relay in relays], indent=2))
        print(run([sys.executable, str(Path(__file__).with_name('database_gate.py'))], env=env, timeout=1230,
                  safe_failure_output=True, guard=functools.partial(check_relays, relays),
                  final_guard=functools.partial(check_relays, relays, fresh=True)), end='')
    except (Exception, KeyboardInterrupt) as error:
        primary_error = f'{type(error).__name__}: {error}'
        process_cleanup_error = getattr(error, 'process_cleanup_error', None)
    finally:
        # Keep repeated cancellation from interrupting bounded resource teardown.
        saved_handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        for sig in saved_handlers:
            signal.signal(sig, signal.SIG_IGN)
        relay_errors = []
        for relay in reversed(relays):
            try:
                relay.close()
            except BaseException as error:
                relay_errors.append(str(error))
        if relay_errors:
            process_cleanup_error = '; '.join(relay_errors)
        # Preflight proved no existing resources. Compose scopes cleanup to this project.
        try:
            run(compose + ['down', '--volumes', '--timeout', '20'], timeout=90)
            for resource in (['ps', '-aq'], ['network', 'ls', '-q'], ['volume', 'ls', '-q']):
                if run(docker + resource + ['--filter', 'label=com.docker.compose.project=' + args.project]).strip():
                    raise RuntimeError('owned resources remain after cleanup')
        except (Exception, KeyboardInterrupt) as error:
            cleanup_error = f'{type(error).__name__}: {error}'
        finally:
            for sig, handler in saved_handlers.items():
                signal.signal(sig, handler)
    print(json.dumps({'primary_error': primary_error, 'process_cleanup_error': process_cleanup_error, 'cleanup_error': cleanup_error}))
    return int(primary_error is not None or process_cleanup_error is not None or cleanup_error is not None)


def cancel(signum, frame):
    raise KeyboardInterrupt('termination requested')


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, cancel)
    try:
        sys.exit(main())
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        print(f'Isolated database runner refused: {type(error).__name__}: {error}', file=sys.stderr)
        sys.exit(1)
