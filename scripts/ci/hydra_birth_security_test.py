#!/usr/bin/env python3
"""Negative checks for the hydra-birth custody boundary. No root tier is started."""
import os
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


if __name__ == '__main__':
    unittest.main()
