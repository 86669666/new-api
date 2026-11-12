"""Offline contracts; real Python children, fixture Git/toolchain/lease/isolation.

No Go/Bun/database/formal inventory, network, git mutation or publisher runs.
The fixture plan substitutes Python children for quality commands deliberately;
passing these tests cannot qualify any candidate SHA or formal scope.
"""
import copy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import quality_execution as execution


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='quality-execution-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.checkout = self.root / 'checkout'
        self.checkout.mkdir()
        for name in ('web/dist', 'relaykit', 'tokenkit'):
            (self.checkout / name).mkdir(parents=True)
        (self.checkout / 'web/dist/index.html').write_text('real fixture assets')
        (self.checkout / 'tracked.txt').write_text('fixture source\n')
        self.evidence = self.root / 'evidence'
        self.evidence.mkdir()
        tool_path = Path(sys.executable).resolve()
        tool = execution.Tool(tool_path, execution.file_digest(tool_path))
        self.runtime = execution.Runtime(
            checkout=self.checkout, evidence_root=self.evidence,
            tools={key: tool for key in ('git', 'go', 'bun', 'python')},
            executor_sha256=execution.file_digest(Path(execution.__file__)),
            contract_sha256=execution.file_digest(Path(execution.__file__).with_name('quality_execution_contract.json')),
            assets_sha256=execution.assets_identity(self.checkout),
            check_lease=Mock(return_value=None), check_isolation=Mock(return_value=None),
            database_environment={'NEWAPI_TEST_PROFILE': 'isolated-ci',
                                  'TEST_MYSQL_DSN': 'root@tcp(127.0.0.1:3306)/newapi_ci_fixture?parseTime=true',
                                  'TEST_POSTGRES_DSN': 'postgres://postgres@127.0.0.1:5432/newapi_ci_fixture?sslmode=disable'})
        self.request = dict(schema='quality-execution-request/v1', repository=execution.REPOSITORY,
                            candidate_sha='a' * 40, candidate_tree='b' * 40,
                            attempt_id='fixture-attempt', invocation='c' * 64)
        data = (self.checkout / 'tracked.txt').read_bytes()
        self.blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest().encode()
        self.head = self.request['candidate_sha']
        self.tree = self.request['candidate_tree']
        self.untracked = b''
        self.index = b'100644 ' + self.blob + b' 0\ttracked.txt\0'
        self.git_patch = patch.object(execution, 'git_read', side_effect=self.fixture_git)
        self.git_patch.start()
        self.addCleanup(self.git_patch.stop)

    def fixture_git(self, runtime, args, env):
        responses = {
            ('rev-parse', '--verify', 'HEAD'): self.head.encode(),
            ('rev-parse', '--verify', 'HEAD^{tree}'): self.tree.encode(),
            ('ls-tree', '-rz', '--full-tree', 'HEAD'): b'100644 blob ' + self.blob + b'\ttracked.txt\0',
            ('ls-files', '--stage', '-z'): self.index,
            ('ls-files', '--others', '--exclude-standard', '-z'): self.untracked,
        }
        return responses[tuple(args)]

    def run_fixture_plan(self, code='print("child passed")', first_only=False, timeout=2):
        commands = execution.COMMANDS[:1] if first_only else execution.COMMANDS
        plan = tuple(execution.Command(c.id, 'python', ('-I', '-B', '-c', code), c.cwd, timeout)
                     for c in commands)
        with patch.object(execution, 'COMMANDS', plan):
            return execution.execute(self.request, self.runtime)

    def test_real_passing_children_never_claim_formal_or_authenticated_success(self):
        result = self.run_fixture_plan()
        self.assertEqual(len(execution.COMMANDS), len(result['commands']))
        self.assertTrue(all(record['status'] == 'passed' and record['process_exit'] == 0
                            for record in result['commands']))
        self.assertEqual(['formal'], result['unexecuted'])
        self.assertEqual('formal_execution_blocked', result['error'])
        self.assertEqual('UNAUTHENTICATED', result['authentication'])
        self.assertEqual(1, result['exit'])
        self.assertFalse(result['cleanup'])
        self.assertEqual(self.request, result['binding'])
        self.assertEqual(set(execution.FORMAL_TIERS), set(result['formal_required_tiers']))
        saved = json.loads((self.evidence / self.request['attempt_id'] / 'execution.json').read_text())
        self.assertEqual(result, saved)
        record = result['commands'][0]
        self.assertEqual(hashlib.sha256(b'child passed\n').hexdigest(), record['stdout_sha256'])
        self.assertGreaterEqual(record['duration_ms'], 0)
        self.assertLessEqual(record['started_at'], record['completed_at'])

    def test_real_failure_is_observed_and_stops_next_command(self):
        result = self.run_fixture_plan('import sys; print("failure"); sys.exit(7)')
        self.assertEqual('command_failed', result['error'])
        self.assertEqual(1, len(result['commands']))
        self.assertEqual(7, result['commands'][0]['process_exit'])
        self.assertEqual('failed', result['commands'][0]['status'])
        self.assertIn('vet-relaykit', result['unexecuted'])
        self.assertNotEqual(0, result['exit'])

    def test_real_timeout_kills_and_reaps_child(self):
        result = self.run_fixture_plan('import time; time.sleep(60)', first_only=True, timeout=0.05)
        record = result['commands'][0]
        self.assertEqual('timeout', record['status'])
        self.assertLess(record['process_exit'], 0)
        self.assertTrue(record['cleanup'])
        self.assertEqual(1, result['exit'])

    def test_real_output_limit_is_failure(self):
        result = execution.run_child([str(self.runtime.tools['python'].path), '-I', '-c',
                                      'import os; os.write(1, b"x" * 100000)'],
                                     self.checkout, {'PATH': '/usr/bin:/bin'}, 2, output_limit=10)
        self.assertEqual('output_limit', result['status'])
        self.assertIsNotNone(result['process_exit'])

    def test_real_background_child_cannot_pass(self):
        # Child detaches neither session nor namespace; launcher must separately
        # enforce cgroups for escaped descendants. This probes process-group cleanup.
        result = execution.run_child([str(self.runtime.tools['python'].path), '-I', '-c',
            'import subprocess, sys; subprocess.Popen([sys.executable,"-I","-c","import time; time.sleep(60)"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)'],
            self.checkout, {'PATH': '/usr/bin:/bin'}, 2)
        self.assertEqual('descendants_remaining', result['status'])
        self.assertEqual(0, result['process_exit'])

    def test_missing_executable_and_missing_tool_dependency(self):
        record = execution.run_child([str(self.root / 'missing')], self.checkout, {}, 1)
        self.assertEqual('launch_failed', record['status'])
        self.assertIsNone(record['process_exit'])
        self.runtime.tools['go'] = execution.Tool(self.root / 'missing', 'd' * 64)
        result = execution.execute(self.request, self.runtime)
        self.assertEqual('missing_dependency', result['error'])
        self.assertEqual([], result['commands'])
        self.assertEqual(list(execution.REQUIRED), result['unexecuted'])

    def test_request_cannot_supply_commands_paths_modules_or_subset(self):
        for key, value in (('argv', ['sh', '-c', 'true']), ('cwd', '/tmp'),
                           ('module', 'evil'), ('commands', ['vet-root']), ('runtime', {})):
            with self.subTest(key=key), patch.object(execution, 'run_child') as child:
                with self.assertRaises(execution.ExecutionError):
                    execution.execute(dict(self.request, **{key: value}), self.runtime)
                child.assert_not_called()

    def test_clean_source_probe_rejects_wrong_sha_tree_dirty_index_and_untracked(self):
        cases = [('head', 'f' * 40, 'source_identity_drift'),
                 ('tree', 'f' * 40, 'source_identity_drift'),
                 ('index', b'', 'dirty_index'), ('untracked', b'unknown\0', 'untracked_source')]
        for field, value, error in cases:
            original = getattr(self, field)
            setattr(self, field, value)
            with self.subTest(field=field), self.assertRaisesRegex(execution.ExecutionError, error):
                execution.source_identity(self.runtime, self.request, {})
            setattr(self, field, original)
        (self.checkout / 'tracked.txt').write_text('changed source')
        with self.assertRaisesRegex(execution.ExecutionError, 'dirty_source'):
            execution.source_identity(self.runtime, self.request, {})

    def test_real_child_source_mutation_rejects_even_with_zero_exit(self):
        result = self.run_fixture_plan('from pathlib import Path; Path("tracked.txt").write_text("drift")')
        self.assertEqual(0, result['commands'][0]['process_exit'])
        self.assertEqual('dirty_source', result['error'])
        self.assertEqual(1, len(result['commands']))
        self.assertEqual(1, result['exit'])

    def test_concurrent_head_move_rejects_before_following_stage(self):
        real_child = execution.run_child
        def run_and_move(*args, **kwargs):
            record = real_child(*args, **kwargs)
            self.head = 'e' * 40
            return record
        with patch.object(execution, 'run_child', side_effect=run_and_move):
            result = self.run_fixture_plan()
        self.assertEqual('source_identity_drift', result['error'])
        self.assertEqual(1, len(result['commands']))

    def test_runtime_pins_and_lock_loss_stop_before_launch(self):
        for runtime, error in ((replace(self.runtime, assets_sha256='0' * 64), 'assets_drift'),
                               (replace(self.runtime, executor_sha256='0' * 64), 'executor_drift'),
                               (replace(self.runtime, contract_sha256='0' * 64), 'contract_drift'),
                               (replace(self.runtime, check_lease=Mock(side_effect=RuntimeError('private'))), 'execution_boundary_failed')):
            with self.subTest(error=error), patch.object(execution, 'run_child') as child:
                result = execution.execute(self.request, runtime)
                self.assertEqual(error, result['error'])
                child.assert_not_called()
                self.assertNotIn('private', json.dumps(result))
        self.runtime.tools['go'] = replace(self.runtime.tools['go'], sha256='0' * 64)
        self.assertEqual('toolchain_drift', execution.execute(self.request, self.runtime)['error'])

    def test_attempt_replay_cannot_write_or_reuse_previous_evidence(self):
        result = self.run_fixture_plan(first_only=True)
        report = self.evidence / self.request['attempt_id'] / 'execution.json'
        original = report.read_bytes()
        with patch.object(execution, 'run_child') as child:
            replay = execution.execute(self.request, self.runtime)
            child.assert_not_called()
        self.assertEqual('replayed_attempt', replay['error'])
        self.assertEqual(original, report.read_bytes())
        self.assertEqual(1, result['exit'])

    def test_invocation_reuse_with_new_attempt_is_rejected(self):
        self.run_fixture_plan(first_only=True)
        self.request['attempt_id'] = 'another-attempt'
        with patch.object(execution, 'run_child') as child:
            replay = execution.execute(self.request, self.runtime)
            child.assert_not_called()
        self.assertEqual('replayed_invocation', replay['error'])
        self.assertEqual(1, replay['exit'])

    def test_empty_or_partial_plan_cannot_turn_green(self):
        with patch.object(execution, 'COMMANDS', ()):
            result = execution.execute(self.request, self.runtime)
        self.assertEqual(list(execution.REQUIRED), result['unexecuted'])
        self.assertEqual(1, result['exit'])
        self.assertFalse(result['cleanup'])

    def test_environment_drops_credentials_and_import_loader_overrides(self):
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'secret-sentinel', 'AWS_SECRET_ACCESS_KEY': 'secret-sentinel',
                                     'PYTHONPATH': '/candidate', 'LD_PRELOAD': '/candidate/evil.so', 'HOME': '/private'}):
            env = execution.child_environment(self.runtime, self.root)
        self.assertNotIn('secret-sentinel', json.dumps(env))
        for key in ('GITHUB_TOKEN', 'AWS_SECRET_ACCESS_KEY', 'PYTHONPATH', 'LD_PRELOAD'):
            self.assertNotIn(key, env)
        record = execution.run_child([str(self.runtime.tools['python'].path), '-I', '-c',
            'import os; assert "GITHUB_TOKEN" not in os.environ; assert "PYTHONPATH" not in os.environ'],
            self.checkout, env, 2)
        self.assertEqual('passed', record['status'])

    def test_cleanup_exception_never_green(self):
        real_killpg = execution.os.killpg
        def kill_then_error(pid, sig):
            try:
                real_killpg(pid, sig)
            except ProcessLookupError:
                pass
            raise PermissionError('fixture cleanup refusal')
        with patch.object(execution.os, 'killpg', side_effect=kill_then_error):
            result = self.run_fixture_plan(first_only=True)
        self.assertEqual('cleanup_failed', result['commands'][0]['status'])
        self.assertFalse(result['commands'][0]['cleanup'])
        self.assertEqual(1, result['exit'])

    def test_evidence_write_failure_never_returns_success(self):
        real_open = Path.open
        def deny_report(path, *args, **kwargs):
            if path.name == 'execution.json':
                raise OSError('fixture evidence failure')
            return real_open(path, *args, **kwargs)
        with patch.object(Path, 'open', deny_report):
            result = self.run_fixture_plan(first_only=True)
        self.assertEqual('evidence_write_failed', result['error'])
        self.assertEqual(1, result['exit'])
        self.assertFalse(result['cleanup'])

    def test_database_missing_configuration_is_not_a_partial_matrix_pass(self):
        self.runtime = replace(self.runtime, database_environment={})
        result = self.run_fixture_plan()
        self.assertEqual('missing_database_environment', result['error'])
        self.assertIn('database', result['unexecuted'])
        self.assertFalse(any(r['id'] == 'database' for r in result['commands']))
        self.assertEqual(1, result['exit'])

    def test_contract_preserves_scope_without_formal_dispatch(self):
        contract = json.loads(Path(execution.__file__).with_name('quality_execution_contract.json').read_text())
        self.assertEqual([command.id for command in execution.COMMANDS], contract['required_commands'])
        self.assertEqual(list(execution.FORMAL_TIERS), contract['formal_required_tiers'])
        self.assertEqual({'backend/formal', 'frontend', 'database/sqlite', 'database/mysql', 'database/postgres'},
                         set(contract['required_scopes']))
        self.assertFalse(any('bootstrap_test_runner.py' in command.args for command in execution.COMMANDS))


class FormalEvidenceTests(unittest.TestCase):
    """Mock runner transport/log records ONLY; no formal child executed."""
    def fixture(self):
        expected = dict(invocation='a' * 64, manifest_sha256='b' * 64,
                        producer_sha256='c' * 64, runner_sha256='d' * 64, tiers={})
        summary = dict(scope='default-full', invocation=expected['invocation'],
                       manifest_sha256=expected['manifest_sha256'], exit=0, unexecuted=[], tiers=[])
        logs = {}
        for tier in execution.FORMAL_TIERS:
            plan = dict(entries=[{'binary': 'test-0', 'cwd': 'fixture', 'run': '.'}],
                        required_leaves=['TestFixture/required'], manifest_sha256='e' * 64)
            expected['tiers'][tier] = plan
            receipt = dict(plan, tier=tier, invocation=expected['invocation'],
                           producer_sha256=expected['producer_sha256'], runner_sha256=expected['runner_sha256'],
                           exit=0, cleanup=True)
            logs[tier] = ('--- PASS: TestFixture/required (0.00s)\nBOOTSTRAP_TIER_RESULT ' + json.dumps(receipt) + '\n').encode()
            summary['tiers'].append(dict(tier=tier, exit=0, receipt=receipt,
                                         log_sha256=hashlib.sha256(logs[tier]).hexdigest(), log='/untrusted/not-read'))
        return summary, expected, logs

    def test_full_fixture_is_structural_observation_never_authenticated_admission(self):
        summary, expected, logs = self.fixture()
        result = execution.inspect_formal_result(summary, expected, 0, logs)
        self.assertTrue(result['structurally_complete'])
        self.assertFalse(result['provenance_authenticated'])
        self.assertEqual('UNAUTHENTICATED', result['authentication'])
        self.assertNotIn('binding', result)
        self.assertNotIn('exit', result)

    def optional_hydra_fixture(self, *, tier='sqlite', mutation=None):
        """Synthetic runner text only; never executes the external Hydra test."""
        summary, expected, logs = self.fixture()
        plan = expected['tiers'][tier]
        entry = dict(binary='test-1', cwd='router',
                     run='^(TestOAuthPublicHydraHTTP|TestOAuthPublicHTTP)$')
        plan['entries'].append(entry)
        start = dict(entry, phase='ordinary')
        end = dict(start, exit=0)
        test = 'TestOAuthPublicHydraHTTP'
        lines = ['BOOTSTRAP_TEST_START ' + json.dumps(start),
                 '=== RUN   ' + test,
                 '    oauth_public_test.go:345: requires isolated real Hydra runtime; local HTTP checks run separately',
                 '--- SKIP: ' + test + ' (0.00s)',
                 'BOOTSTRAP_TEST_END ' + json.dumps(end)]
        if mutation:
            mutation(plan, lines)
        record = next(r for r in summary['tiers'] if r['tier'] == tier)
        record['receipt'].update(entries=plan['entries'], required_leaves=plan['required_leaves'])
        mandatory = dict(binary='test-0', cwd='fixture', run='.', phase='ordinary')
        prefix = ('BOOTSTRAP_TEST_START ' + json.dumps(mandatory) + '\n' +
                  '--- PASS: TestFixture/required (0.00s)\n' +
                  'BOOTSTRAP_TEST_END ' + json.dumps(dict(mandatory, exit=0)) + '\n')
        logs[tier] = (prefix + '\n'.join(lines) +
                      '\nBOOTSTRAP_TIER_RESULT ' + json.dumps(record['receipt']) + '\n').encode()
        record['log_sha256'] = hashlib.sha256(logs[tier]).hexdigest()
        return summary, expected, logs

    def test_exact_optional_hydra_skip_is_unauthenticated_structural_evidence(self):
        summary, expected, logs = self.optional_hydra_fixture()
        result = execution.inspect_formal_result(summary, expected, 0, logs)
        self.assertTrue(result['structurally_complete'])
        self.assertEqual('UNAUTHENTICATED', result['authentication'])
        self.assertFalse(result['provenance_authenticated'])
        self.assertEqual(set(execution.FORMAL_TIERS), set(expected['tiers']))

    def test_original_runner_partition_and_sqlite_receipt_allow_optional_skip(self):
        # Pure partition/receipt functions only; no runner entrypoint or child.
        import bootstrap_test_runner as runner

        entries = [dict(binary='test-' + str(i), cwd=cwd, run='.')
                   for i, cwd in enumerate(('service', 'router', 'controller'))]
        inventory = {'test-0': [*runner.WALLET_TESTS, 'TestServiceLocal'],
                     'test-1': ['TestOAuthPublicHydraHTTP', 'TestOAuthPublicHTTP',
                                'TestSessionRevocationS1Namespace', 'TestSessionRevocationS1RealRedis'],
                     'test-2': ['TestOAuthDerivedTokenOwnerLifecycle', 'TestControllerLocal']}
        partitions = runner.resource_partitions(entries, inventory)
        summary, expected, logs = self.optional_hydra_fixture(
            mutation=lambda p, l: p.update(required_leaves=runner.required_leaves('sqlite')))
        plan = expected['tiers']['sqlite']
        self.assertIn(plan['entries'][-1], partitions['sqlite'])
        metadata = dict(tier='sqlite', invocation=expected['invocation'], entries=plan['entries'],
                        files={'new-api': expected['producer_sha256'], 'runner.py': expected['runner_sha256']})
        receipt = runner.validate_tier_receipt(metadata, plan['manifest_sha256'], logs['sqlite'].decode(), 0)
        self.assertEqual(receipt, summary['tiers'][-1]['receipt'])
        self.assertTrue(execution.inspect_formal_result(summary, expected, 0, logs)['structurally_complete'])

    def mandatory_entry_fixture(self, *, end_mutation=None, dialect=False):
        """Append a frozen mandatory entry to the optional-skip parser fixture."""
        def append_entry(plan, lines):
            entry = dict(binary='test-2', cwd='service' if dialect else 'fixture-other',
                         run='^(TestOAuthDerivedTextRawUsageRejection|TestLocal)$' if dialect else '.')
            plan['entries'].append(entry)
            start = dict(entry, phase='ordinary')
            end = dict(start, exit=0)
            if end_mutation:
                end_mutation(end)
            lines.extend(['BOOTSTRAP_TEST_START ' + json.dumps(start),
                          '--- PASS: TestLocal (0.00s)',
                          'BOOTSTRAP_TEST_END ' + json.dumps(end)])
            if dialect:
                lines.extend([
                    'BOOTSTRAP_TEST_START ' + json.dumps(dict(entry, phase='sqlite-dialect',
                                                              run='^TestOAuthDerivedTextRawUsageRejection$/sqlite')),
                    '--- PASS: TestOAuthDerivedTextRawUsageRejection/sqlite (0.00s)',
                    'BOOTSTRAP_TEST_END ' + json.dumps(dict(entry, phase='sqlite-dialect', exit=0))])
        return self.optional_hydra_fixture(mutation=append_entry)

    def test_review_non_router_failed_exit_rejects(self):
        summary, expected, logs = self.mandatory_entry_fixture(end_mutation=lambda end: end.update(exit=7))
        with self.assertRaises(execution.ExecutionError):
            execution.inspect_formal_result(summary, expected, 0, logs)

    def test_review_non_router_mismatched_end_rejects(self):
        summary, expected, logs = self.mandatory_entry_fixture(end_mutation=lambda end: end.update(binary='test-99'))
        with self.assertRaises(execution.ExecutionError):
            execution.inspect_formal_result(summary, expected, 0, logs)

    def test_genuine_sqlite_dialect_start_override_and_original_end_selector(self):
        summary, expected, logs = self.mandatory_entry_fixture(dialect=True)
        result = execution.inspect_formal_result(summary, expected, 0, logs)
        self.assertTrue(result['structurally_complete'])
        self.assertEqual('UNAUTHENTICATED', result['authentication'])
        self.assertFalse(result['provenance_authenticated'])

    def test_sqlite_producer_pair_is_required_structural_text_only(self):
        # These are log strings, not invocation of the stopped producer test.
        model = dict(binary='test-2', cwd='model', run='.')
        producer = ['BOOTSTRAP_TEST_START ' + json.dumps(dict(model, phase='producer')),
                    'BOOTSTRAP_TEST_END ' + json.dumps(dict(model, phase='producer', exit=0))]

        def add_model(plan, lines):
            plan['entries'].append(model)
            lines.extend(['BOOTSTRAP_TEST_START ' + json.dumps(dict(model, phase='ordinary')),
                          'BOOTSTRAP_TEST_END ' + json.dumps(dict(model, phase='ordinary', exit=0))])

        for mode in ('complete', 'missing', 'failed', 'duplicate'):
            summary, expected, logs = self.optional_hydra_fixture(mutation=add_model)
            prefix = list(producer)
            if mode == 'missing':
                prefix = []
            elif mode == 'failed':
                prefix[-1] = prefix[-1].replace('"exit": 0', '"exit": 7')
            elif mode == 'duplicate':
                prefix += producer
            logs['sqlite'] = ('\n'.join(prefix) + '\n').encode() + logs['sqlite']
            summary['tiers'][-1]['log_sha256'] = hashlib.sha256(logs['sqlite']).hexdigest()
            with self.subTest(mode=mode):
                if mode == 'complete':
                    self.assertTrue(execution.inspect_formal_result(summary, expected, 0, logs)['structurally_complete'])
                else:
                    with self.assertRaises(execution.ExecutionError):
                        execution.inspect_formal_result(summary, expected, 0, logs)

    def test_every_mandatory_pair_requires_complete_consistent_evidence(self):
        for mode in ('bool-exit', 'missing-exit', 'wrong-phase', 'wrong-selector', 'wrong-cwd',
                     'missing-entry', 'missing-dialect', 'dangling-start', 'dangling-end',
                     'duplicate-entry', 'duplicate-dialect', 'unknown-entry', 'unknown-dialect',
                     'dialect-end-override', 'dialect-failure', 'dialect-wrong-binary'):
            summary, expected, logs = self.mandatory_entry_fixture(dialect=True)
            lines = logs['sqlite'].decode().splitlines()
            start = next(i for i, line in enumerate(lines) if line.startswith('BOOTSTRAP_TEST_START ') and 'test-2' in line)
            end = start + 2
            dialect = end + 1
            if mode in ('bool-exit', 'missing-exit', 'wrong-phase', 'wrong-selector', 'wrong-cwd'):
                value = json.loads(lines[end].removeprefix('BOOTSTRAP_TEST_END '))
                if mode == 'missing-exit':
                    value.pop('exit')
                else:
                    key, val = {'bool-exit': ('exit', False), 'wrong-phase': ('phase', 'producer'),
                                'wrong-selector': ('run', '.'), 'wrong-cwd': ('cwd', 'router')}[mode]
                    value[key] = val
                lines[end] = 'BOOTSTRAP_TEST_END ' + json.dumps(value)
            elif mode == 'missing-entry':
                del lines[start:dialect + 3]
            elif mode == 'missing-dialect':
                del lines[dialect:dialect + 3]
            elif mode == 'dangling-start':
                del lines[end]
            elif mode == 'dangling-end':
                del lines[start]
            elif mode in ('duplicate-entry', 'duplicate-dialect'):
                pos = start if mode == 'duplicate-entry' else dialect
                lines[pos:pos] = lines[pos:pos + 3]
            elif mode == 'unknown-entry':
                lines[start] = lines[start].replace('test-2', 'test-99')
            elif mode == 'unknown-dialect':
                lines[dialect] = lines[dialect].replace('TestOAuthDerivedTextRawUsageRejection', 'TestUnknown')
            else:
                value = json.loads(lines[dialect + 2].removeprefix('BOOTSTRAP_TEST_END '))
                if mode == 'dialect-end-override':
                    value['run'] = '^TestOAuthDerivedTextRawUsageRejection$/sqlite'
                elif mode == 'dialect-failure':
                    value['exit'] = 7
                else:
                    value['binary'] = 'test-99'
                lines[dialect + 2] = 'BOOTSTRAP_TEST_END ' + json.dumps(value)
            logs['sqlite'] = ('\n'.join(lines) + '\n').encode()
            summary['tiers'][-1]['log_sha256'] = hashlib.sha256(logs['sqlite']).hexdigest()
            with self.subTest(mode=mode), self.assertRaises(execution.ExecutionError):
                execution.inspect_formal_result(summary, expected, 0, logs)

    def test_optional_skip_cannot_override_inventory_context_or_required_tests(self):
        mutations = {
            'missing-router-inventory': lambda p, l: p['entries'].pop(),
            'missing-all-inventory': lambda p, l: p.update(entries=[]),
            'substituted-inventory': lambda p, l: p['entries'][-1].update(cwd='service'),
            'missing-selected-test': lambda p, l: p['entries'][-1].update(run='^(TestOAuthPublicHTTP)$'),
            'wildcard-selector': lambda p, l: p['entries'][-1].update(run='.'),
            'required-leaf': lambda p, l: p['required_leaves'].append('TestOAuthPublicHydraHTTP'),
            'missing-required-leaf': lambda p, l: p['required_leaves'].append('TestMandatory'),
            'missing-start': lambda p, l: l.pop(0),
            'missing-end': lambda p, l: l.pop(),
            'wrong-phase': lambda p, l: l.__setitem__(0, l[0].replace('ordinary', 'producer')),
            'wrong-binary': lambda p, l: l.__setitem__(0, l[0].replace('test-1', 'test-2')),
            'failed-entry': lambda p, l: l.__setitem__(-1, l[-1].replace('"exit": 0', '"exit": 7')),
            'boolean-exit': lambda p, l: l.__setitem__(-1, l[-1].replace('"exit": 0', '"exit": false')),
            'missing-run': lambda p, l: l.pop(1),
            'missing-reason': lambda p, l: l.pop(2),
            'wrong-reason': lambda p, l: l.__setitem__(2, '    oauth_public_test.go:345: arbitrary skip'),
            'wrong-reason-source': lambda p, l: l.__setitem__(2, l[2].replace('oauth_public_test.go', 'other_test.go')),
            'unknown-skip': lambda p, l: l.insert(4, '--- SKIP: TestUnknown (0.00s)'),
            'lookalike-skip': lambda p, l: l.__setitem__(3, l[3].replace('HydraHTTP', 'HydraHTTPFake')),
            'subtest-skip': lambda p, l: l.__setitem__(3, l[3].replace('HydraHTTP', 'HydraHTTP/child')),
            'mandatory-skip': lambda p, l: l.insert(4, '--- SKIP: TestFixture/required (0.00s)'),
            'mandatory-failure': lambda p, l: l.insert(4, '--- FAIL: TestFixture/required (0.00s)'),
            'optional-failure': lambda p, l: l.__setitem__(3, l[3].replace('SKIP', 'FAIL')),
            'duplicate-skip': lambda p, l: l.insert(4, l[3]),
            'pass-and-skip': lambda p, l: l.insert(4, l[3].replace('SKIP', 'PASS')),
            'nested-entry': lambda p, l: l.insert(1, l[0]),
        }
        for name, mutation in mutations.items():
            summary, expected, logs = self.optional_hydra_fixture(mutation=mutation)
            with self.subTest(name=name), self.assertRaises(execution.ExecutionError):
                execution.inspect_formal_result(summary, expected, 0, logs)
        for tier in execution.FORMAL_TIERS:
            if tier == 'sqlite':
                continue
            summary, expected, logs = self.optional_hydra_fixture(tier=tier)
            with self.subTest(tier=tier), self.assertRaises(execution.ExecutionError):
                execution.inspect_formal_result(summary, expected, 0, logs)

    def test_partial_replayed_failed_and_cleanup_evidence_reject(self):
        mutations = [lambda s: s.update(unexecuted=['sqlite']),
                     lambda s: s['tiers'].pop(),
                     lambda s: s['tiers'].__setitem__(0, copy.deepcopy(s['tiers'][1])),
                     lambda s: s.update(invocation='f' * 64),
                     lambda s: s.update(manifest_sha256='f' * 64),
                     lambda s: s.update(exit=False),
                     lambda s: s['tiers'][0].update(exit=4),
                     lambda s: s['tiers'][0]['receipt'].update(cleanup=False),
                     lambda s: s['tiers'][0]['receipt'].update(entries=[]),
                     lambda s: s['tiers'][0]['receipt'].update(invocation='f' * 64)]
        for index, mutate in enumerate(mutations):
            summary, expected, logs = self.fixture()
            mutate(summary)
            with self.subTest(index=index), self.assertRaises(execution.ExecutionError):
                execution.inspect_formal_result(summary, expected, 0, logs)
        for code in (1, -9, False, None):
            summary, expected, logs = self.fixture()
            with self.subTest(code=code), self.assertRaises(execution.ExecutionError):
                execution.inspect_formal_result(summary, expected, code, logs)

    def test_missing_corrupt_skipped_and_duplicate_log_receipts_reject(self):
        for mode in ('missing-log', 'hash', 'skip', 'missing-receipt', 'duplicate'):
            summary, expected, logs = self.fixture()
            first = summary['tiers'][0]
            name = first['tier']
            if mode == 'missing-log':
                logs.pop(name)
            elif mode == 'hash':
                first['log_sha256'] = '0' * 64
            else:
                if mode == 'skip':
                    logs[name] = logs[name].replace(b'--- PASS:', b'--- SKIP:')
                elif mode == 'missing-receipt':
                    logs[name] = b'--- PASS: TestFixture/required (0.00s)\n'
                else:
                    logs[name] += logs[name]
                first['log_sha256'] = hashlib.sha256(logs[name]).hexdigest()
            with self.subTest(mode=mode), self.assertRaises(execution.ExecutionError):
                execution.inspect_formal_result(summary, expected, 0, logs)


if __name__ == '__main__':
    unittest.main()
