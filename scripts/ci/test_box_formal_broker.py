"""Offline runner adapter tests; no binaries, namespaces or databases execute."""
import copy
import json
import io
import threading
import stat
import struct
from types import SimpleNamespace
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import bootstrap_test_runner as runner


class BrokerInventoryTests(unittest.TestCase):
    def fixture(self):
        return {'tier': 'all', 'entries': [{'binary': 'test-0', 'cwd': 'router', 'run': '.'}],
                'inventory': {'test-0': ['TestExample']},
                'partitions': {'sqlite': [{'binary': 'test-0', 'cwd': 'router', 'run': '.'}]}}

    def test_inventory_matches_full_prepared_plan_only(self):
        manifest = self.fixture()
        with patch.object(runner.os, 'geteuid', return_value=997), \
             patch.object(runner.os, 'getegid', return_value=990), \
             patch.object(runner.os, 'getgroups', return_value=[]), \
             patch.object(Path, 'read_text', return_value='NoNewPrivs:\t1\nCapEff:\t0\n'), \
             patch.object(runner, 'verified_manifest', return_value=manifest), \
             patch.object(runner, 'compiled_inventory', return_value=manifest['inventory']) as listing, \
             patch.object(runner, 'resource_partitions', return_value=manifest['partitions']), \
             patch.object(runner, 'digest', return_value='a' * 64):
            result = runner.broker_inventory('/admitted/bundle')
            self.assertEqual('inventory-only', result['scope'])
            self.assertNotIn('exit', result)
            listing.assert_called_once()
            bad = copy.deepcopy(manifest['inventory'])
            bad['test-0'] = []
            listing.return_value = bad
            with self.assertRaisesRegex(ValueError, 'differs'):
                runner.broker_inventory('/admitted/bundle')

    def test_privileged_or_supplementary_identity_rejected_before_listing(self):
        for uid, gid, groups in [(0, 0, []), (997, 0, []), (997, 990, [123])]:
            with self.subTest(uid=uid, gid=gid, groups=groups), \
                 patch.object(runner.os, 'geteuid', return_value=uid), \
                 patch.object(runner.os, 'getegid', return_value=gid), \
                 patch.object(runner.os, 'getgroups', return_value=groups), \
                 patch.object(runner, 'compiled_inventory') as listing:
                with self.assertRaises(ValueError):
                    runner.broker_inventory('/admitted/bundle')
                listing.assert_not_called()

    def test_capability_or_elevation_rejected(self):
        for status in ('NoNewPrivs:\t0\nCapEff:\t0\n', 'NoNewPrivs:\t1\nCapEff:\t1\n'):
            with self.subTest(status=status), \
                 patch.object(runner.os, 'geteuid', return_value=997), \
                 patch.object(runner.os, 'getegid', return_value=990), \
                 patch.object(runner.os, 'getgroups', return_value=[]), \
                 patch.object(Path, 'read_text', return_value=status), \
                 patch.object(runner, 'compiled_inventory') as listing:
                with self.assertRaises(ValueError):
                    runner.broker_inventory('/admitted/bundle')
                listing.assert_not_called()


class OuterBirthTests(unittest.TestCase):
    def test_selected_adapter_requires_exact_ready_publication(self):
        ident = 'a' * 32
        base = Path('/opt/newapi-box-formal/work/attempt')
        adapter = Mock(attempt_id='attempt')
        for engine in ('sqlite', 'postgres', 'mysql'):
            result = dict(id=ident, engine=engine,
                          target=str(base / ('birth-' + ident) / 'new.db') if engine == 'sqlite' else 'birth_' + ident,
                          journal=str(base / 'journals' / (ident + '.json')), output_sha256='b' * 64)
            adapter.return_value = result
            state = dict(phase='READY', engine=engine, target=result['target'])
            with self.subTest(engine=engine), patch.object(runner, 'OUTER_BIRTH', adapter), \
                 patch.object(runner.os, 'geteuid', return_value=0), \
                 patch.object(Path, 'lstat', return_value=SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o644)), \
                 patch.object(Path, 'read_text', return_value=json.dumps(state)):
                self.assertEqual(result, runner.outer_birth(engine, 'wallet', 'owned-daemon'))
                if engine != 'sqlite':
                    adapter.verify_daemon.assert_called_with(engine, 'owned-daemon')
                for changed in ({**result, 'journal': '/etc/foreign'}, {**result, 'engine': 'unknown'},
                                {**result, 'target': '/outside'}, {**result, 'unexpected': 'private'}):
                    adapter.return_value = changed
                    with self.assertRaises(ValueError):
                        runner.outer_birth(engine, 'wallet', 'owned-daemon')
                adapter.return_value = result
                with patch.object(Path, 'read_text', return_value=json.dumps({**state, 'phase': 'MIGRATING'})):
                    with self.assertRaisesRegex(ValueError, 'READY'):
                        runner.outer_birth(engine, 'wallet', 'owned-daemon')
                with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_uid=997, st_mode=stat.S_IFREG | 0o644)):
                    with self.assertRaisesRegex(ValueError, 'custody'):
                        runner.outer_birth(engine, 'wallet', 'owned-daemon')

    def test_installer_uses_completed_outer_namespace_without_root_cli_fallback(self):
        for fail in (False, True):
            installer = runner.Installer.__new__(runner.Installer)
            installer.uid = 997
            installer.pg_resource = installer.redis_resource = None
            installer.root = Path('/legacy')
            installer.receipts = []
            installer.stopped = Mock()
            installer.stopped.is_set.side_effect = [False, True]
            connection = Mock()
            connection.__enter__ = Mock(return_value=connection)
            connection.__exit__ = Mock(return_value=False)
            connection.getsockopt.return_value = struct.pack('3i', 20, 997, 990)
            connection.recv.side_effect = [b'fresh\n', b'']
            installer.server = Mock()
            installer.server.accept.return_value = (connection, None)
            completed = dict(id='a'*32, engine='sqlite', target='/published/new.db',
                             journal='/published/journal.json', output_sha256='b'*64)
            with self.subTest(fail=fail), patch.object(runner, 'outer_birth', return_value=completed,
                    side_effect=ValueError('unpublished') if fail else None) as birth, \
                 patch.object(runner.subprocess, 'run') as launch, \
                 patch.object(runner.os, 'chown'), patch.object(runner.os, 'chmod'), \
                 patch.object(runner, 'bootstrap_observation'):
                installer.serve()
                birth.assert_called_once_with('sqlite', 'installer')
                launch.assert_not_called()
                if fail:
                    connection.sendall.assert_not_called()
                    self.assertEqual([], installer.receipts)
                else:
                    response = json.loads(connection.sendall.call_args.args[0])
                    self.assertEqual('/published/new.db', response['DSN'])
                    self.assertEqual('/published/journal.json', response['Journal'])
                    self.assertEqual('outer-birth', installer.receipts[0]['operation'])

    def test_legacy_mode_and_selected_daemon_failure_remain_distinct(self):
        with patch.object(runner, 'OUTER_BIRTH', None):
            self.assertIsNone(runner.outer_birth('sqlite', 'installer'))
        adapter = Mock(attempt_id='attempt')
        adapter.verify_daemon.side_effect = ValueError('wrong owned daemon')
        resource = runner.OwnedPostgres.__new__(runner.OwnedPostgres)
        resource.verify = Mock()
        resource.sql = Mock()
        with patch.object(runner, 'OUTER_BIRTH', adapter), patch.object(runner.os, 'geteuid', return_value=0), \
             patch.object(runner.subprocess, 'run') as launch:
            with self.assertRaisesRegex(ValueError, 'wrong owned daemon'):
                resource.birth()
            adapter.assert_not_called()
            resource.sql.assert_not_called()
            launch.assert_not_called()


class OuterControlClientTests(unittest.TestCase):
    def client(self, replies):
        client = runner.OuterBirthControlClient.__new__(runner.OuterBirthControlClient)
        client.attempt_id, client.nonce = 'attempt', 'a' * 64
        client.sequence, client.failed = 0, False
        client.lock = threading.Lock()
        client.connection = Mock()
        client.reader = io.BytesIO(replies)
        return client

    def test_framed_sequence_and_ambiguous_request_never_retries(self):
        client = self.client(b'{"sequence":0,"result":{"id":"synthetic"}}\n')
        self.assertEqual({'id': 'synthetic'}, client('sqlite', 'installer'))
        sent = json.loads(client.connection.sendall.call_args.args[0])
        self.assertEqual({'attempt', 'nonce', 'sequence', 'operation', 'engine', 'purpose'}, set(sent))
        self.assertEqual('birth', sent['operation'])
        with self.assertRaisesRegex(ValueError, 'frame'):
            client('sqlite', 'installer')
        self.assertTrue(client.failed)
        self.assertEqual(2, client.connection.sendall.call_count)
        with self.assertRaisesRegex(ValueError, 'no retry'):
            client('sqlite', 'installer')
        self.assertEqual(2, client.connection.sendall.call_count)
        client.connection.close.assert_called_once()
        for reply in (b'{"sequence":1,"result":{}}\n', b'{"sequence":true,"result":{}}\n',
                      b'{"sequence":0,"result":{},"private":"extra"}\n'):
            with self.subTest(reply=reply):
                client = self.client(reply)
                with self.assertRaises(ValueError):
                    client('sqlite', 'installer')
                self.assertTrue(client.failed)

    def test_daemon_mismatch_closes_transport(self):
        client = self.client(b'{"sequence":0,"result":{"binding":"different"}}\n')
        daemon = Mock()
        daemon.verify.return_value = {'pid': 42, 'startticks': 50}
        with self.assertRaisesRegex(ValueError, 'observations differ'):
            client.verify_daemon('postgres', daemon)
        self.assertTrue(client.failed)
        request = json.loads(client.connection.sendall.call_args.args[0])
        self.assertEqual('verify-daemon', request['operation'])
        self.assertNotIn('pid', request)
        self.assertNotIn('statement', request)


    def test_producer_regression_requires_exact_completed_test_binding(self):
        good = dict(test_sha256='b' * 64, output_sha256='c' * 64,
                    observed_exit=0, regression_complete=True)
        for change in ({}, {'test_sha256': 'd' * 64}, {'observed_exit': 1},
                       {'observed_exit': False}, {'regression_complete': False},
                       {'output_sha256': 'partial'}, {'extra': 'untrusted'}):
            with self.subTest(change=change):
                result = dict(good, **change)
                client = self.client(json.dumps(dict(sequence=0, result=result)).encode() + b'\n')
                if not change:
                    self.assertEqual(good, client.producer_regression('b' * 64))
                else:
                    with self.assertRaises(ValueError):
                        client.producer_regression('b' * 64)
                    self.assertTrue(client.failed)
                request = json.loads(client.connection.sendall.call_args.args[0])
                self.assertEqual(('producer-regression', 'sqlite', ''),
                                 (request['operation'], request['engine'], request['purpose']))
                self.assertNotIn('binary', request)
                self.assertNotIn('command', request)


class OuterDaemonProxyTests(unittest.TestCase):
    def test_proxy_binds_same_socket_and_authenticated_host_record(self):
        for failure in ('', 'inode', 'local-pid', 'uid', 'host-record'):
            with self.subTest(failure=failure):
                proxy = runner.OuterDaemonBinding.__new__(runner.OuterDaemonBinding)
                proxy.engine = 'postgres'
                proxy.socket_dir, proxy.socket_path = Path('/owned/socket'), Path('/owned/socket/.s.PGSQL.5432')
                proxy.value = {'daemon_uid': 102}
                proxy.identity = dict(directory_device=1,directory_inode=2,socket_device=1,socket_file_inode=3)
                directory = SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=102,st_dev=1,st_ino=2)
                endpoint = SimpleNamespace(st_mode=stat.S_IFSOCK|0o777,st_uid=102,st_dev=1,
                                           st_ino=4 if failure=='inode' else 3)
                connection = Mock()
                connection.getsockopt.return_value = struct.pack('3i',1 if failure=='local-pid' else 0,
                                                                 997 if failure=='uid' else 102,102)
                context = Mock();context.__enter__ = Mock(return_value=connection);context.__exit__ = Mock(return_value=False)
                control = Mock()
                import hashlib
                expected = hashlib.sha256(json.dumps(proxy.identity,sort_keys=True,separators=(',',':')).encode()).hexdigest()
                control.request.return_value = {'binding':'wrong' if failure=='host-record' else expected}
                with patch.object(Path,'lstat',side_effect=[directory,endpoint]), \
                     patch.object(runner.socket,'socket',return_value=context),patch.object(runner,'OUTER_BIRTH',control):
                    if failure:
                        with self.assertRaises(ValueError):proxy.verify()
                    else:
                        self.assertEqual(proxy.identity,proxy.verify())
                        control.request.assert_called_once_with('verify-daemon','postgres','')
                    if failure in ('inode','local-pid','uid'):
                        control.request.assert_not_called()

    def test_selected_daemons_never_start_or_stop_legacy_child(self):
        for cls in (runner.OwnedPostgres,runner.CombinedPostgres,runner.OwnedWalletMySQL):
            with self.subTest(cls=cls.__name__):
                daemon = cls.__new__(cls)
                daemon.outer = Mock()
                daemon.process = Mock()
                daemon.outer.verify.return_value = {'same':'owned-resource'}
                self.assertEqual({'same':'owned-resource'},daemon.verify())
                daemon.close()
                daemon.process.assert_not_called()
                self.assertEqual([],daemon.process.mock_calls)
                binding = Mock()
                with patch.object(runner,'OUTER_BIRTH',Mock()),patch.object(runner,'OuterDaemonBinding',return_value=binding), \
                     patch.object(runner.subprocess,'Popen') as launch,patch.object(runner.subprocess,'run') as run:
                    daemon.start()
                    binding.bind.assert_called_once_with(daemon)
                    launch.assert_not_called();run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
