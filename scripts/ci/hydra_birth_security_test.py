#!/usr/bin/env python3
"""Negative checks for the hydra-birth custody boundary. No root tier is started."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import bootstrap_test_runner as runner


class HydraBirthSecurityTest(unittest.TestCase):
    def test_host_network_and_default_route_are_rejected(self):
        interfaces = sorted(path.name for path in Path('/sys/class/net').iterdir())
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

    def test_inventory_requires_the_sealed_binary_digest(self):
        good = {'entries': [{'cwd': 'router', 'run': runner.HYDRA_BIRTH_SELECTOR}],
                'files': {'hydra': 'ab' * 32}, 'hydra_bin_sha256': 'ab' * 32}
        self.assertIsNone(runner.hydra_birth_inventory_error(good))
        broken = dict(good, hydra_bin_sha256='cd' * 32)
        self.assertIsNotNone(runner.hydra_birth_inventory_error(broken))

    def test_start_digest_mismatch_does_not_exec(self):
        root = Path(tempfile.mkdtemp())
        try:
            binary = root / 'hydra'
            binary.write_bytes(b'not-the-binary')
            owned = runner.OwnedHydra(root, os.getuid(), binary, 'ab' * 32)
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
        root = Path(tempfile.mkdtemp())
        try:
            binary = root / 'bundle-hydra'
            body = b'not-hydra'
            binary.write_bytes(body)
            owned = runner.OwnedHydra(root, os.getuid(), binary, runner.digest_bytes(body))
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

    def test_exited_process_is_not_ready_and_close_is_idempotent(self):
        root = Path(tempfile.mkdtemp())
        try:
            owned = runner.OwnedHydra(root, os.getuid(), root / 'hydra', 'cd' * 32)
            proc = subprocess.Popen(['/bin/false'])
            proc.wait(timeout=5)
            owned.process = proc
            with self.assertRaises(RuntimeError):
                owned.wait_ready()
            owned.close()
            owned.close()
            self.assertIsNone(owned.process)
        finally:
            shutil.rmtree(root)

    def test_close_stops_a_running_process(self):
        root = Path(tempfile.mkdtemp())
        try:
            owned = runner.OwnedHydra(root, os.getuid(), root / 'hydra', 'ef' * 32)
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
