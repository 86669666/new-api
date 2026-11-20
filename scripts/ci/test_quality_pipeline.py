"""A/B integration: real executor children; ALL App/HTTP/formal success is MOCK.

Imports both product modules in this integrated checkout. No sibling imports,
network, credentials, Go/Bun/database/formal inventories, or live publication.
The success control is an independent authenticated-transport fixture, never a
conversion of A's incomplete report into admission. Known A reports may veto it.
"""
import copy
import io
import hashlib
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

import quality_execution as execution
import quality_results as results
import test_quality_execution as execution_fixtures
import test_quality_results as result_fixtures


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.executor = execution_fixtures.ExecutionTests(
            methodName='test_real_failure_is_observed_and_stops_next_command')
        self.executor.setUp()
        self.addCleanup(self.executor.doCleanups)
        self.receipt, self.admission, self.environment = result_fixtures.fixture()
        expected = self.receipt['binding']
        request = self.executor.request
        for key in ('candidate_sha', 'candidate_tree', 'attempt_id', 'invocation'):
            expected[key] = request[key]
            self.receipt['quality'][key] = request[key]
        plan = next(iter(expected['tiers'].values()))
        expected['tiers'] = {tier: copy.deepcopy(plan) for tier in execution.FORMAL_TIERS}
        self.receipt['tiers'] = [dict(tier=tier, exit=0, cleanup=True,
            invocation=expected['invocation'], log_sha256='e' * 64, **plan)
            for tier in expected['tiers']]
        self.receipt['quality']['results']['formal'] = dict(
            required=sorted(expected['tiers']), exit=0, cleanup=True, unexecuted=[],
            commands=[dict(id=tier, exit=0, skipped=False, cleanup=True, log_sha256='e' * 64)
                      for tier in sorted(expected['tiers'])])
        self.admission['expected'] = copy.deepcopy(expected)
        self.admission['quality'] = copy.deepcopy(self.receipt['quality'])
        self.model = result_fixtures.MockReader(self.receipt, self.admission)
        self.model.commit_value['tree']['sha'] = expected['candidate_tree']
        self.http = result_fixtures.MockHTTP(self.model)
        self.calls = []
        self.refresh_mock_receipt()
        opener = patch.object(results.urllib.request, 'build_opener',
                              return_value=SimpleNamespace(open=self.mock_http_open))
        opener.start()
        self.addCleanup(opener.stop)
        self.reader = results.GitHubReader('MOCK-READ-NOT-A-CREDENTIAL')
        transport = results.GitHubStagingHTTP('MOCK-INSTALLATION-NOT-A-CREDENTIAL')
        self.publisher = results.GitHubPublication(self.http.app_get, transport.request)
        self.journal = results.AdmissionJournal(str(self.executor.root / 'pipeline.sqlite'))
        self.now = 200

    def mock_http_open(self, request, timeout):
        """Only HTTP I/O is mocked: real B URL/method/JSON construction runs."""
        parsed = urlsplit(request.full_url)
        self.assertEqual(('https', 'api.github.com'), (parsed.scheme, parsed.netloc))
        self.assertEqual(30, timeout)
        method, path = request.get_method(), parsed.path
        payload = None if request.data is None else json.loads(request.data)
        self.calls.append((method, path, payload))
        prefix = '/repos/' + results.REPOSITORY
        if method == 'POST' or parsed.path == '/installation/repositories':
            value = self.http.installation_request(method,
                path + ('?' + parsed.query if parsed.query else ''), payload)
        else:
            self.assertEqual('GET', method)
            if path == prefix:
                value = self.model.repository()
            elif path == prefix + '/pulls/1':
                value = self.model.pull(1)
            elif path == prefix + '/git/commits/' + self.executor.request['candidate_sha']:
                value = self.model.commit(self.executor.request['candidate_sha'])
            elif path in (prefix + '/check-runs/42', prefix + '/check-runs/43'):
                value = self.model.check(int(path.rsplit('/', 1)[1]))
            elif path == prefix + '/actions/runs/100/attempts/1':
                value = self.model.run(100, 1)
            else:
                self.fail('unexpected endpoint: ' + path)
        return io.BytesIO(json.dumps(value).encode())

    def refresh_mock_receipt(self, report=None):
        # Rebind MOCK transport hashes only. This does not sign anything, and
        # does not copy any A outcome into the independently authored fixture.
        if report is not None:
            self.receipt['quality']['execution_evidence_sha256'] = results.consumer.digest(report)
        self.admission['quality'] = copy.deepcopy(self.receipt['quality'])
        self.admission['receipt_sha256'] = results.consumer.digest(self.receipt)
        self.model.check_value.update(external_id=self.admission['receipt_sha256'],
                                      output={'text': json.dumps(self.receipt)})

    def stage(self, **kwargs):
        return results.stage_publication(self.admission, self.environment, self.reader,
            self.publisher, self.journal, clock=lambda: self.now, **kwargs)

    def collect(self, **kwargs):
        return results.collect_result(self.admission, self.environment, self.reader,
            self.publisher, self.journal, clock=lambda: self.now, **kwargs)

    def test_command_identifiers_align_without_importing_executor_into_publisher(self):
        ids = [command.id for command in execution.COMMANDS]
        self.assertEqual(list(results.BACKEND), ids[:6])
        self.assertEqual(list(results.FRONTEND), ids[6:9])
        self.assertEqual(['database', 'policy-tests', 'consumer-tests'], ids[9:])
        self.assertEqual(list(results.POLICY), ids[10:])
        self.assertEqual(execution.FORMAL_TIERS, results.FORMAL_TIERS)
        contract = json.loads(Path(execution.__file__).with_name('quality_execution_contract.json').read_text())
        self.assertEqual(list(results.FORMAL_TIERS), contract['formal_required_tiers'])
        self.assertEqual(list(results.POLICY), contract['authenticated_policy_tests'])
        self.assertFalse(hasattr(results, 'execution'))

    def test_actual_a_incomplete_report_vetoes_even_mock_authenticated_success(self):
        report = self.executor.run_fixture_plan()
        self.assertEqual(12, len(report['commands']))
        self.assertTrue(all(c['process_exit'] == 0 for c in report['commands']))
        self.assertEqual(['formal'], report['unexecuted'])
        self.assertEqual('UNAUTHENTICATED', report['authentication'])
        self.refresh_mock_receipt(report)
        with self.assertRaisesRegex(ValueError, 'incomplete execution evidence'):
            self.stage(execution_evidence=report)
        self.assertEqual([], self.http.posts)
        self.assertFalse(self.http.green)

    def test_actual_child_failure_reaches_verifier_and_cannot_stage(self):
        report = self.executor.run_fixture_plan('raise SystemExit(7)', first_only=True)
        self.assertEqual(7, report['commands'][0]['process_exit'])
        self.assertEqual('failed', report['commands'][0]['status'])
        self.refresh_mock_receipt(report)
        with self.assertRaisesRegex(ValueError, 'incomplete execution evidence'):
            results.verify(self.admission, self.environment, self.reader,
                           clock=lambda: self.now, execution_evidence=report)
        with self.assertRaises(ValueError):
            self.stage(execution_evidence=report)
        self.assertFalse(self.http.posts)

    def test_actual_report_cannot_replace_receipt_even_with_mock_app_and_matching_hash(self):
        report = self.executor.run_fixture_plan(first_only=True)
        self.model.check_value['output']['text'] = json.dumps(report)
        self.admission['receipt_sha256'] = results.consumer.digest(report)
        self.model.check_value['external_id'] = self.admission['receipt_sha256']
        with self.assertRaises((KeyError, ValueError)):
            self.stage()
        self.assertEqual([], self.http.posts)

    def test_report_wrong_sha_tree_digest_and_missing_metadata_are_not_ignored(self):
        report = self.executor.run_fixture_plan(first_only=True)
        for mutation in ('candidate_sha', 'candidate_tree', 'digest', 'missing', 'auth-label'):
            with self.subTest(mutation=mutation):
                bad = copy.deepcopy(report)
                if mutation in ('candidate_sha', 'candidate_tree'):
                    bad['binding'][mutation] = 'f' * 40
                elif mutation == 'missing':
                    del bad['binding']
                elif mutation == 'auth-label':
                    bad['authentication'] = 'APP-AUTHENTICATED'
                self.refresh_mock_receipt(bad)
                if mutation == 'digest':
                    bad['commands'][0]['stdout_sha256'] = '0' * 64
                with self.assertRaises((KeyError, ValueError)):
                    self.stage(execution_evidence=bad)
                self.assertEqual([], self.http.posts)

    def test_mock_full_formal_inspection_and_separate_app_staging_collection(self):
        # Same full nine-tier plan crosses A's structural inspector and B's
        # authenticated-transport fixture. ALL formal execution/success is MOCK.
        expected = {key: self.admission['expected'][key] for key in
                    ('invocation', 'manifest_sha256', 'producer_sha256', 'runner_sha256', 'tiers')}
        summary = dict(scope='default-full', invocation=expected['invocation'],
                       manifest_sha256=expected['manifest_sha256'], exit=0, unexecuted=[], tiers=[])
        logs = {}
        for tier, plan in expected['tiers'].items():
            receipt = dict(plan, tier=tier, invocation=expected['invocation'], exit=0, cleanup=True,
                           producer_sha256=expected['producer_sha256'], runner_sha256=expected['runner_sha256'])
            logs[tier] = ('--- PASS: fixture-only (0.00s)\nBOOTSTRAP_TIER_RESULT ' + json.dumps(receipt)).encode()
            summary['tiers'].append(dict(tier=tier, exit=0, receipt=receipt,
                                         log_sha256=hashlib.sha256(logs[tier]).hexdigest()))
        observed = execution.inspect_formal_result(summary, expected, 0, logs)
        self.assertFalse(observed['provenance_authenticated'])
        self.assertEqual('UNAUTHENTICATED', observed['authentication'])
        pending = self.stage()
        self.assertEqual('pending', pending['state'])
        self.assertFalse(self.http.green)
        with self.assertRaises(ValueError):
            self.collect()
        self.http.finish_fixture()  # External success MOCK, no product success write.
        self.assertEqual('verified', self.collect()['state'])
        with self.assertRaises(ValueError):
            self.collect()
        self.assertEqual(['POST'], [method for method, _, _ in self.calls if method != 'GET'])
        self.assertEqual('in_progress', self.http.posts[0]['status'])
        self.assertNotIn('conclusion', self.http.posts[0])
        summary['tiers'].pop()
        with self.assertRaises(execution.ExecutionError):
            execution.inspect_formal_result(summary, expected, 0, logs)

    def test_actual_incomplete_report_is_rejected_at_collection_too(self):
        report = self.executor.run_fixture_plan(first_only=True)
        self.refresh_mock_receipt(report)
        self.stage()  # Separate authenticated fixture path, no A report submitted.
        self.http.finish_fixture()
        with self.assertRaisesRegex(ValueError, 'incomplete execution evidence'):
            self.collect(execution_evidence=report)
        # Collection failure must not consume the staged record or write again.
        verified = results.verify(self.admission, self.environment, self.reader, clock=lambda: 200)
        self.assertEqual(43, self.journal.pending(verified))
        self.assertEqual(1, len(self.http.posts))

    def test_expiry_replay_head_drift_and_partial_publication_reject(self):
        self.now = 301
        with self.assertRaises(ValueError):
            self.stage()
        self.assertFalse(self.http.posts)
        self.now = 200
        self.stage()
        with self.assertRaises(sqlite3.IntegrityError):
            self.stage()
        self.http.finish_fixture()
        original = self.model.gate_value['output']['text']
        self.model.gate_value['output']['text'] = '{}'
        with self.assertRaises(ValueError):
            self.collect()
        self.model.gate_value['output']['text'] = original
        self.model.pr['head']['sha'] = 'd' * 40
        with self.assertRaises(ValueError):
            self.collect()
        self.assertEqual(1, len(self.http.posts))
        self.assertEqual(self.executor.request['candidate_sha'], self.http.posts[0]['head_sha'])

    def test_concurrent_head_drift_during_concrete_post_leaves_only_pending(self):
        self.http.before_post = lambda: self.model.pr['head'].update(sha='f' * 40)
        with self.assertRaises(ValueError):
            self.stage()
        self.assertFalse(self.http.green)
        self.assertEqual(1, len(self.http.posts))

    def test_concrete_transport_lost_ack_burns_claim_without_green(self):
        self.http.failure = 'lost-ack'
        with self.assertRaises(OSError):
            self.stage()
        self.assertFalse(self.http.green)
        self.http.failure = None
        with self.assertRaises(sqlite3.IntegrityError):
            self.stage()
        self.assertEqual(1, len(self.http.posts))


if __name__ == '__main__':
    unittest.main()
