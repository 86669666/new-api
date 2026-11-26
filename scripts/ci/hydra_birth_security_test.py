#!/usr/bin/env python3
"""Negative checks for the hydra-birth custody boundary. No root tier is started."""
import io
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.request
from contextlib import redirect_stdout
from pathlib import Path

import bootstrap_test_runner as runner


DEV_HEADER = (
    'Inter-|   Receive                                                |  Transmit\n'
    ' face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n'
)
ROUTE_HEADER = 'Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n'
IPV6_REJECT_ON_LO = (
    '00000000000000000000000000000000 00 00000000000000000000000000000000 00 '
    '00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n'
)


class HydraBirthSecurityTest(unittest.TestCase):
    def test_host_network_and_default_route_are_rejected(self):
        interfaces = runner.proc_net_dev_names(Path('/proc/net/dev').read_text())
        route_v6 = ''
        ipv6 = Path('/proc/net/ipv6_route')
        if ipv6.exists():
            route_v6 = ipv6.read_text()
        live = runner.network_departure_error(Path('/proc/net/route').read_text(), route_v6, interfaces)
        self.assertIsNotNone(live)
        self.assertIsNotNone(runner.network_departure_error(
            'Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n'
            'eth0 00000000 0100A8C0 0003 0 0 0 00000000 0 0 0\n', '', ['lo', 'eth0']))
        with self.assertRaises(ValueError):
            runner.require_private_loopback()

    def test_loopback_only_network_is_accepted(self):
        self.assertIsNone(runner.network_departure_error(
            'Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n', '', ['lo']))

    def test_parent_sysfs_is_not_this_netns(self):
        proc = DEV_HEADER + '    lo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n'
        self.assertIsNone(runner.private_loopback_error(
            'net:[parent]', 'net:[private]', ROUTE_HEADER, IPV6_REJECT_ON_LO, proc))
        self.assertEqual(runner.proc_net_dev_names(proc), ['lo'])

    def test_nic_inside_the_private_netns_is_rejected(self):
        proc = DEV_HEADER + '    lo: 0\n  eth0: 0\n'
        error = runner.private_loopback_error('net:[parent]', 'net:[private]', ROUTE_HEADER, '', proc)
        self.assertIsNotNone(error)
        self.assertIn('eth0', str(error))
        same = runner.private_loopback_error('net:[same]', 'net:[same]', ROUTE_HEADER, '', DEV_HEADER + '    lo: 0\n')
        self.assertIsNotNone(same)

    def test_unconfigured_kernel_fallback_cannot_leave(self):
        proc = DEV_HEADER + '    lo: 0\n  sit0: 0\n ip6tnl0: 0\n'
        self.assertIsNone(runner.private_loopback_error(
            'net:[parent]', 'net:[private]', ROUTE_HEADER, IPV6_REJECT_ON_LO, proc))
        routed = ROUTE_HEADER + 'sit0 00000000 0100A8C0 0003 0 0 0 00000000 0 0 0\n'
        self.assertIsNotNone(runner.private_loopback_error(
            'net:[parent]', 'net:[private]', routed, '', proc))
        addressed = '20010db8000000000000000000000001 02 40 00 80 sit0\n'
        self.assertIsNotNone(runner.private_loopback_error(
            'net:[parent]', 'net:[private]', ROUTE_HEADER, '', proc, addressed))
        gateway = (
            '00000000000000000000000000000000 00 00000000000000000000000000000000 00 '
            '20010db8000000000000000000000001 00000000 00000000 00000000 00000003 eth0\n'
        )
        self.assertIsNotNone(runner.network_departure_error(ROUTE_HEADER, gateway, ['lo', 'eth0']))
        plain_default = (
            '00000000000000000000000000000000 00 00000000000000000000000000000000 00 '
            '00000000000000000000000000000000 00000000 00000000 00000000 00000001 lo\n'
        )
        self.assertIsNotNone(runner.network_departure_error(ROUTE_HEADER, plain_default, ['lo']))

    def test_external_and_rebound_hosts_are_rejected(self):
        for value in ('https://192.0.2.10:4445', 'https://127.0.0.1.example:4445', 'https://localhost:4445',
                      'http://127.0.0.1:4445', 'https://127.0.0.1', 'https://2130706433:4445',
                      'https://user@127.0.0.1:4445', 'https://127.0.0.1:4445/admin'):
            with self.assertRaises(ValueError):
                runner.require_loopback_hydra_url(value, 'Admin')
        runner.require_loopback_hydra_url('https://127.0.0.1:4445', 'Admin')
        runner.require_loopback_hydra_url('https://[::1]:4445/', 'Public')

    def test_symlink_world_writable_and_replaced_input_are_rejected(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            root = Path(temporary)
            sealed = root / 'input.json'
            sealed.write_text('{"sealed":true}')
            sealed.chmod(0o644)
            replacement = root / 'other.json'
            replacement.write_text('{"sealed":false}')
            replacement.chmod(0o644)
            link = root / 'input.link'
            link.symlink_to(sealed)
            with self.assertRaises(ValueError):
                runner.read_custodied_file(link, os.geteuid())
            sealed.chmod(0o666)
            with self.assertRaises(ValueError):
                runner.read_custodied_file(sealed, os.geteuid())
            sealed.chmod(0o644)
            original = runner.read_custodied_file(sealed, os.geteuid())
            os.replace(replacement, sealed)
            replaced = runner.read_custodied_file(sealed, os.geteuid())
            self.assertNotEqual(original, replaced)
            digest = runner.digest_bytes(original)
            self.assertIsNone(runner.manifest_binding_error(original, digest, digest))
            self.assertIsNotNone(runner.manifest_binding_error(replaced, digest, digest))

    def test_sealed_loopback_input_binds_to_its_digest(self):
        document = {'Admin': 'https://127.0.0.1:4445', 'Public': 'https://127.0.0.1:4444/',
                    'Issuer': 'https://[::1]:4446', 'CA': '/certs/ca.pem',
                    'Certificate': '/certs/cert.pem', 'Key': '/certs/key.pem'}
        runner.require_loopback_hydra_document(document)
        raw = b'{"Admin":"https://127.0.0.1:4445"}'
        digest = runner.digest_bytes(raw)
        self.assertIsNone(runner.manifest_binding_error(raw, digest, digest))
        rewritten = runner.rewritten_hydra_document(dict(document), {
            'CA': '/owned/hydra-ca.pem', 'Certificate': '/owned/hydra-cert.pem', 'Key': '/owned/hydra-key.pem'})
        self.assertEqual(rewritten['Admin'], document['Admin'])
        self.assertEqual(rewritten['CA'], '/owned/hydra-ca.pem')

    def test_ordinary_audit_keeps_its_private_network(self):
        audit = runner.isolated_namespace_argv('ordinary-audit', Path('/bundle'))
        hydra = runner.isolated_namespace_argv('hydra-birth', Path('/bundle'))
        self.assertEqual(audit[:7], ['sudo', '-n', 'unshare', '--mount', '--net', '--pid', '--fork'])
        self.assertEqual(hydra[:7], audit[:7])
        self.assertIn('ip link set lo up', audit[9])
        self.assertEqual(audit[9], hydra[9])
        self.assertNotIn('hydra-input.path', audit)
        self.assertNotIn('hydra-input.path', hydra)
        self.assertNotIn('--hydra-bin', hydra)
        self.assertEqual(audit[12], str(Path('/bundle') / 'runner.py'))
        self.assertEqual(hydra[12], str(Path(runner.__file__).resolve()))
        self.assertNotEqual(hydra[12], str(Path('/bundle') / 'runner.py'))

    def test_digest_mismatch_does_not_execute(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            binary = Path(temporary) / 'hydra'
            binary.write_bytes(b'not-hydra')
            binary.chmod(0o755)
            calls = []
            original = subprocess.run

            def trap(*args, **kwargs):
                calls.append(args)
                raise AssertionError('digest mismatch must not execute')

            subprocess.run = trap
            try:
                with self.assertRaises(ValueError):
                    runner.seal_hydra_binary(binary, '00' * 32, os.geteuid())
            finally:
                subprocess.run = original
            self.assertEqual(calls, [])

    def test_version_token_is_exact(self):
        self.assertIsNone(runner.hydra_version_error('Version: v26.2.0\n'))
        self.assertIsNotNone(runner.hydra_version_error('Version: v26.2.0.1\n'))
        self.assertIsNotNone(runner.hydra_version_error('Version: v26.2.1\n'))
        self.assertIsNotNone(runner.hydra_version_error(''))

    def test_rendered_config_is_loopback_only(self):
        secret = 'ab' * 32
        text = runner.render_hydra_config('/owned/hydra.sqlite', '/owned/cert.pem', '/owned/key.pem', secret)
        self.assertIsNone(runner.hydra_config_url_error(text))
        self.assertIn('host: 127.0.0.1', text)
        self.assertIn('sqlite:///owned/hydra.sqlite?_fk=true&mode=rwc', text)
        self.assertIn('access_token: 15m', text)
        self.assertIn('enabled: true', text)
        self.assertNotIn('0.0.0.0', text)
        self.assertIsNotNone(runner.hydra_config_url_error(text.replace('127.0.0.1', '192.0.2.10')))
        self.assertIsNotNone(runner.hydra_config_url_error(text + '\nhost: 0.0.0.0\n'))
        with self.assertRaises(ValueError):
            runner.render_hydra_config('/owned/hydra.sqlite', '/owned/cert.pem', '/owned/bad"key.pem', secret)
        with self.assertRaises(ValueError):
            runner.render_hydra_config('/owned/hydra.sqlite', '/owned/cert.pem', '/owned/key.pem', 'short')

    def test_launch_argv_is_fixed(self):
        binary, config = Path('/owned/bundle/hydra'), Path('/owned/hydra.yaml')
        self.assertEqual(runner.hydra_migrate_argv(binary, config),
                         ['/owned/bundle/hydra', 'migrate', 'sql', 'up', '-e', '--yes', '--config', '/owned/hydra.yaml'])
        self.assertEqual(runner.hydra_serve_argv(binary, config),
                         ['/owned/bundle/hydra', 'serve', 'all', '--config', '/owned/hydra.yaml'])

    def test_inventory_does_not_treat_a_matching_manifest_as_the_anchor(self):
        swapped = {'entries': [{'cwd': 'router', 'run': runner.HYDRA_BIRTH_SELECTOR}],
                   'files': {'hydra': 'cd' * 32}, 'hydra_bin_sha256': 'cd' * 32}
        self.assertIsNone(runner.hydra_birth_inventory_error(swapped))
        self.assertIsNotNone(runner.hydra_birth_inventory_error(dict(swapped, hydra_bin_sha256='not-a-digest')))

    def custodied(self, directory, name, data):
        path = Path(directory) / name
        path.write_bytes(data)
        path.chmod(0o644)
        return path

    def test_bundle_and_manifest_swap_is_not_the_release_anchor(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            official, evil = b'official-hydra-bytes', b'evil-hydra-bytes'
            official_sha = runner.digest_bytes(official)
            evil_sha = runner.digest_bytes(evil)
            binary = self.custodied(temporary, 'hydra', official)
            sha_file = self.custodied(temporary, 'hydra.sha256', (official_sha + '\n').encode())
            with self.assertRaisesRegex(ValueError, 'not the root release anchor'):
                runner.load_trusted_hydra(binary, sha_file, evil_sha, os.geteuid())
            payload, anchor = runner.load_trusted_hydra(binary, sha_file, official_sha, os.geteuid())
            self.assertEqual(payload, official)
            self.assertNotEqual(payload, evil)
            self.assertEqual(anchor, official_sha)
            binary.write_bytes(evil)
            binary.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'not the release anchor'):
                runner.load_trusted_hydra(binary, sha_file, official_sha, os.geteuid())

    def test_symlink_and_hardlink_are_rejected(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            body = b'official-hydra-bytes'
            binary = self.custodied(temporary, 'hydra', body)
            sha_file = self.custodied(temporary, 'hydra.sha256', (runner.digest_bytes(body) + '\n').encode())
            link = Path(temporary) / 'hydra.link'
            link.symlink_to(binary)
            self.assertEqual(runner.digest(link), runner.digest_bytes(body))
            with self.assertRaises(ValueError):
                runner.load_trusted_hydra(link, sha_file, runner.digest_bytes(body), os.geteuid())
            os.link(binary, Path(temporary) / 'hydra-hard')
            with self.assertRaises(ValueError):
                runner.load_trusted_hydra(binary, sha_file, runner.digest_bytes(body), os.geteuid())

    def test_version_migrate_and_serve_share_one_payload(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            payload = b'same-trusted-bytes'
            anchor = runner.digest_bytes(payload)
            staged = runner.stage_trusted_executable(Path(temporary) / 'hydra', payload, anchor, os.geteuid())
            config = Path(temporary) / 'hydra.yaml'
            commands = [
                [str(staged), 'version'],
                runner.hydra_migrate_argv(staged, config),
                runner.hydra_serve_argv(staged, config),
            ]
            executed = []
            open_fd = None
            for argv in commands:
                bound, fd = runner.bound_hydra_argv(staged, payload, anchor, os.geteuid(), argv)
                try:
                    self.assertTrue(bound[0].startswith('/proc/self/fd/'))
                    os.lseek(fd, 0, os.SEEK_SET)
                    self.assertEqual(os.read(fd, len(payload)), payload)
                    executed.append(bound[1])
                    if open_fd is None:
                        open_fd = os.dup(fd)
                finally:
                    os.close(fd)
            self.assertEqual(executed, ['version', 'migrate', 'serve'])
            staged.chmod(0o755)
            staged.unlink()
            staged.symlink_to(self.custodied(temporary, 'replacement', b'replaced-bytes'))
            os.lseek(open_fd, 0, os.SEEK_SET)
            self.assertEqual(os.read(open_fd, len(payload)), payload)
            os.close(open_fd)
            with self.assertRaises(ValueError):
                runner.bound_hydra_argv(staged, payload, anchor, os.geteuid(), commands[1])
            self.assertEqual(executed, ['version', 'migrate', 'serve'])

    def test_start_digest_mismatch_does_not_exec(self):
        root = Path(tempfile.mkdtemp())
        try:
            owned = runner.OwnedHydra(root, os.getuid(), b'not-the-binary', 'ab' * 32)
            calls = []
            original_net = runner.require_private_loopback
            original_popen = subprocess.Popen
            runner.require_private_loopback = lambda: None

            def trap(*args, **kwargs):
                calls.append(args)
                raise AssertionError('digest mismatch must not exec')

            subprocess.Popen = trap
            try:
                with self.assertRaises(ValueError):
                    owned.start()
            finally:
                runner.require_private_loopback = original_net
                subprocess.Popen = original_popen
            self.assertEqual(calls, [])
            self.assertIsNone(owned.process)
        finally:
            shutil.rmtree(root)

    def test_wrong_version_does_not_serve(self):
        root = Path(tempfile.mkdtemp(dir=Path.home()))
        try:
            body = b'not-hydra'
            owned = runner.OwnedHydra(root, os.getuid(), body, runner.digest_bytes(body))
            original_net = runner.require_private_loopback
            original_run = subprocess.run
            original_popen = subprocess.Popen
            runner.require_private_loopback = lambda: None
            popen_calls = []

            def fake_run(argv, **kwargs):
                class Result:
                    returncode = 0
                    stdout = b'Version: v26.2.1\n'
                    stderr = b''
                return Result()

            def trap(*args, **kwargs):
                popen_calls.append(args)
                raise AssertionError('wrong version must not serve')

            subprocess.run = fake_run
            subprocess.Popen = trap
            try:
                with self.assertRaisesRegex(ValueError, 'not fixed'):
                    owned.start()
            finally:
                runner.require_private_loopback = original_net
                subprocess.run = original_run
                subprocess.Popen = original_popen
            self.assertEqual(popen_calls, [])
            self.assertFalse(owned.directory.exists())
            self.assertIsNone(owned.process)
        finally:
            shutil.rmtree(root)

    def test_non_sqlite_release_is_not_the_anchor(self):
        self.assertIsNotNone(runner.release_anchor_error(runner.HYDRA_NON_SQLITE_RELEASE_SHA256))
        self.assertIsNone(runner.release_anchor_error(runner.HYDRA_SQLITE_RELEASE_SHA256))
        self.assertEqual(runner.HYDRA_NON_SQLITE_RELEASE_SHA256, 'b1437b7882f1863b2173003d6be86ad7b1f9381808cb5f4a19f9c27659595ddf')

    def test_fresh_clients_registration_contract(self):
        owned = runner.OwnedHydra(Path('/unused'), os.getuid(), b'', '')
        context = ssl.create_default_context()
        with patch.object(runner.ssl, 'create_default_context', return_value=context) as tls_context, \
                patch('http.client.HTTPSConnection') as connection:
            connection.return_value.getresponse.return_value.status = 201
            owned.register_clients()
            tls_context.assert_called_once_with(cafile=str(owned.directory / 'ca.pem'))
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(context.check_hostname)
            self.assertEqual(connection.call_count, 2)
            for call in connection.call_args_list:
                self.assertEqual(call.args, ('127.0.0.1', 4445))
                self.assertEqual(call.kwargs, {'context': context, 'timeout': 5})
            documents = []
            for call in connection.return_value.request.call_args_list:
                self.assertEqual(call.args[:2], ('POST', '/admin/clients'))
                self.assertEqual(call.kwargs['headers'], {'Content-Type': 'application/json'})
                documents.append(json.loads(call.kwargs['body']))
            self.assertEqual([doc['client_id'] for doc in documents],
                             ['newapi-w01-desktop', 'newapi-w01-independent'])
            for doc in documents:
                self.assertEqual(doc['token_endpoint_auth_method'], 'none')
                self.assertEqual(doc['subject_type'], 'public')
                self.assertEqual(doc['grant_types'], ['authorization_code', 'refresh_token'])
                self.assertEqual(doc['response_types'], ['code'])
                self.assertEqual(doc['audience'], ['newapi-userinfo'])
                self.assertIs(doc['skip_consent'], False)
                self.assertEqual(doc['scope'].split(),
                                 ['openid', 'profile', 'email', 'offline_access', 'balance:read', 'usage:read', 'tokens:read'])
            self.assertEqual(documents[0]['redirect_uris'],
                             ['http://127.0.0.1:29873/oauth/callback', 'boxnai://oauth/callback'])
            self.assertEqual(documents[1]['redirect_uris'], ['http://127.0.0.1:29873/oauth/callback'])
            self.assertEqual(connection.return_value.close.call_count, 2)

            for status in (200, 302, 404, 409, 503):
                with self.subTest(status=status):
                    connection.reset_mock()
                    connection.return_value.getresponse.return_value.status = status
                    with self.assertRaisesRegex(RuntimeError, '^hydra client registration failed: status ' + str(status) + '$'):
                        owned.register_clients()
                    connection.return_value.request.assert_called_once()
                    connection.return_value.close.assert_called_once()

    def test_official_sqlite_binary_migrates_and_serves(self):
        binary = os.environ.get('NEWAPI_HYDRA_SQLITE_BIN', '')
        if not binary:
            self.skipTest('NEWAPI_HYDRA_SQLITE_BIN is not set')
        payload = Path(binary).read_bytes()
        self.assertEqual(runner.digest_bytes(payload), runner.HYDRA_SQLITE_RELEASE_SHA256)
        root = Path(tempfile.mkdtemp(dir=Path.home()))
        proc = None
        try:
            key, cert = root / 'key.pem', root / 'cert.pem'
            issued = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-keyout', str(key), '-out', str(cert),
                                     '-days', '2', '-nodes', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'],
                                    check=False, capture_output=True, timeout=30)
            self.assertEqual(issued.returncode, 0)
            secret = '12' * 32
            config = root / 'hydra.yaml'
            config.write_text(runner.render_hydra_config(str(root / 'hydra.sqlite'), str(cert), str(key), secret))
            migration = subprocess.run(runner.hydra_migrate_argv(binary, config), check=False, capture_output=True, timeout=60)
            self.assertEqual(migration.returncode, 0)
            proc = subprocess.Popen(runner.hydra_serve_argv(binary, config), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            context = ssl.create_default_context(cafile=str(cert))
            deadline = time.time() + 20
            ready = False
            while time.time() < deadline:
                self.assertIsNone(proc.poll())
                try:
                    with urllib.request.urlopen('https://127.0.0.1:4445/health/ready', context=context, timeout=1) as response:
                        ready = response.status == 200
                        if ready:
                            break
                except OSError:
                    time.sleep(0.2)
            self.assertTrue(ready)
            owned = runner.OwnedHydra(root, os.getuid(), payload, runner.HYDRA_SQLITE_RELEASE_SHA256)
            owned.directory = root
            shutil.copyfile(cert, root / 'ca.pem')
            for client_id in ('newapi-w01-desktop', 'newapi-w01-independent'):
                with self.assertRaises(urllib.error.HTTPError) as missing:
                    urllib.request.urlopen('https://127.0.0.1:4445/admin/clients/' + client_id, context=context, timeout=5)
                self.assertEqual(missing.exception.code, 404)
                missing.exception.close()
            owned.register_clients()
            for client_id in ('newapi-w01-desktop', 'newapi-w01-independent'):
                with urllib.request.urlopen('https://127.0.0.1:4445/admin/clients/' + client_id, context=context, timeout=5) as response:
                    self.assertEqual(response.status, 200)
                    registration = json.load(response)
                self.assertEqual(registration['client_id'], client_id)
                self.assertEqual(registration['token_endpoint_auth_method'], 'none')
                self.assertIs(registration['skip_consent'], False)
                self.assertIn('tokens:read', registration['scope'].split())
                self.assertNotIn('tokens:write', registration['scope'].split())
        finally:
            if proc is not None and proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)
            shutil.rmtree(root)

    def test_startup_report_is_a_fixed_category(self):
        secret = 'ab' * 32
        captured = io.StringIO()
        with redirect_stdout(captured):
            error = runner.report_hydra_failure('migrate', 'exited', 2)
            refused = None
            try:
                runner.report_hydra_failure('serve ' + secret, 'exited', 1)
            except RuntimeError as caught:
                refused = caught
            timed = runner.report_hydra_failure('serve', 'ready_timeout', -15)
        text = captured.getvalue() + str(error) + str(timed) + str(refused)
        self.assertEqual(str(error), 'hydra start failed: migrate exited exit 2')
        self.assertIn('"phase":"migrate"', captured.getvalue())
        self.assertIn('"failure":"exited"', captured.getvalue())
        self.assertIn('"exit":2', captured.getvalue())
        self.assertEqual(str(timed), 'hydra start failed: serve ready_timeout exit null')
        self.assertIn('"exit":null', captured.getvalue())
        self.assertNotIn('-15', text)
        self.assertNotIn(secret, text)
        self.assertNotIn('note', captured.getvalue())

    def test_owned_serve_reader_reports_status_without_output(self):
        cookie = 'cookie=' + ('c0ffee' * 8)
        jwk = '"d":"jwk-d-7f3a91c0","p":"jwk-p-88ab12"'
        partial_key = '-----BEGIN PRIVATE KEY-----\nMIIEpartialkeymaterial'
        dsn = 'postgres://hydra:s3cret-pass@10.1.2.3/hydra'
        blob = '\n'.join((cookie, jwk, partial_key, dsn, 'sqlite:///var/lib/hydra.sqlite?_fk=true'))
        root = Path(tempfile.mkdtemp(dir=Path.home()))
        try:
            owned = runner.OwnedHydra(root, os.getuid(), b'payload', runner.digest_bytes(b'payload'))
            proc = subprocess.Popen(
                [sys.executable, '-c', 'import os,sys; sys.stdout.write(os.environ["BLOB"]); sys.exit(4)'],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=dict(os.environ, BLOB=blob * 400))
            owned.process = proc
            owned.start_output_reader()
            captured = io.StringIO()
            with redirect_stdout(captured):
                with self.assertRaises(RuntimeError) as caught:
                    owned.finish_serve(timeout=3)
            text = captured.getvalue() + str(caught.exception)
            self.assertIn('serve exited exit 4', text)
            self.assertIn('"exit":4', captured.getvalue())
            for planted in (cookie, jwk, 'jwk-d-7f3a91c0', 'jwk-p-88ab12', partial_key, 'MIIEpartial', dsn, 's3cret-pass', 'sqlite:///var/lib/hydra.sqlite'):
                self.assertNotIn(planted, text)
            self.assertIsNone(owned._serve_reader)
            self.assertTrue(proc.stdout.closed)
            self.assertEqual(proc.poll(), 4)
            sleeper = subprocess.Popen(['/bin/sleep', '30'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            owned.process = sleeper
            owned.start_output_reader()
            captured = io.StringIO()
            with redirect_stdout(captured):
                with self.assertRaises(RuntimeError) as timed:
                    owned.finish_serve(timeout=0.3)
            timed_text = captured.getvalue() + str(timed.exception)
            self.assertIn('ready_timeout', timed_text)
            self.assertIn('exit null', timed_text)
            self.assertIn('"exit":null', captured.getvalue())
            self.assertNotIn('-15', timed_text)
            self.assertNotIn('143', timed_text)
            self.assertIsNone(owned._serve_reader)
            self.assertTrue(sleeper.stdout.closed)
            self.assertIsNotNone(sleeper.poll())
        finally:
            shutil.rmtree(root)

    def test_exited_process_is_not_ready_and_close_is_idempotent(self):
        root = Path(tempfile.mkdtemp())
        try:
            owned = runner.OwnedHydra(root, os.getuid(), b'', 'cd' * 32)
            proc = subprocess.Popen(['/bin/false'])
            proc.wait(timeout=5)
            owned.process = proc
            with self.assertRaises(runner.HydraExited):
                owned.wait_ready()
            owned.close()
            owned.close()
            self.assertIsNone(owned.process)
        finally:
            shutil.rmtree(root)

    def test_close_stops_a_running_process(self):
        root = Path(tempfile.mkdtemp())
        try:
            owned = runner.OwnedHydra(root, os.getuid(), b'', 'ef' * 32)
            proc = subprocess.Popen(['/bin/sleep', '30'])
            owned.process = proc
            owned.close()
            proc.wait(timeout=5)
            self.assertIsNotNone(proc.poll())
            self.assertIsNone(owned.process)
        finally:
            shutil.rmtree(root)


if __name__ == '__main__':
    unittest.main()
