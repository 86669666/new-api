"""Offline runner adapter tests; no binaries, namespaces or databases execute."""
import copy
from pathlib import Path
import unittest
from unittest.mock import patch

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


if __name__ == '__main__':
    unittest.main()
