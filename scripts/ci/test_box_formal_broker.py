"""Offline runner adapter tests; no binaries, namespaces or databases execute."""
import copy
import json
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


if __name__ == '__main__':
    unittest.main()
