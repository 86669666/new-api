"""Offline contract tests. App/API/publisher responses are MOCKS, not admission.

Only test_real_child_failure and the isolated CLI tests execute real tiny Python
children. No test executes Go/Node/database/formal inventories or network writes.
"""
import copy
import json
import io
import os
import re
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
import sqlite3
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

import quality_results as quality


# Real default tier NAMES, synthetic execution records. Keep this fixture
# independent of the admission and verifier's policy constants.
FORMAL_FIXTURE_TIERS = ('postgres', 'postgres-redis', 'wallet-sqlite', 'wallet-mysql',
                        'wallet-postgres', 'lifecycle-sqlite', 'lifecycle-mysql',
                        'lifecycle-postgres', 'sqlite')


def fixture():
    c = quality.consumer
    expected = dict.fromkeys(('candidate_sha', 'candidate_tree', 'execution_sha'), 'a' * 40)
    expected['consumer_sha'] = 'c' * 40
    expected.update(dict.fromkeys(('runner_sha256', 'wrapper_sha256', 'producer_sha256',
        'source_manifest_sha256', 'assets_sha256', 'toolchain_sha256', 'module_sha256',
        'manifest_sha256'), 'b' * 64))
    expected.update(images=c.PINS.copy(), platform='linux/amd64', attempt_id='fixture-attempt',
        admission_id='fixture-admission', invocation='fixture-invocation',
        test_binaries={'test-0': 'c' * 64}, not_before=100, expires_at=300,
        tiers={name: {'entries': [{'binary': 'test-0', 'cwd': 'router', 'run': '.'}],
            'required_leaves': ['fixture-only'], 'manifest_sha256': 'd' * 64}
            for name in FORMAL_FIXTURE_TIERS})
    result = dict(schema=quality.SCHEMA, candidate_sha='a' * 40, candidate_tree='a' * 40,
        execution_sha='a' * 40, attempt_id=expected['attempt_id'], admission_id=expected['admission_id'],
        invocation=expected['invocation'], execution_evidence_sha256='e' * 64,
        pull_number=1, head_repository_id=456, base_sha='b' * 40,
        workflow=dict(path='.github/workflows/box-formal-receipt.yml', ref='refs/heads/main', event='workflow_dispatch',
                      sha='c' * 40, run_id=100, run_attempt=1, workflow_id=101), results={})
    for group, required in [('backend', list(quality.BACKEND)), ('frontend', list(quality.FRONTEND)),
                            ('database', list(quality.DIALECTS)), ('formal', sorted(expected['tiers'])),
                            ('policy', ['policy-tests', 'consumer-tests'])]:
        result['results'][group] = dict(required=required, exit=0, cleanup=True, unexecuted=[],
            commands=[dict(id=name, exit=0, skipped=False, cleanup=True, log_sha256='e' * 64)
                      for name in required])
    result['results']['database']['required_leaves'] = sorted(quality.database_policy.REQUIRED)
    receipt = dict(binding=expected, quality=result, started_at=110, completed_at=190,
        process_exit=0, exit=0, cleanup=True, unexecuted=[], tiers=[dict(tier=name,
        exit=0, cleanup=True, invocation=expected['invocation'], log_sha256='e' * 64,
        **expected['tiers'][name]) for name in FORMAL_FIXTURE_TIERS])
    admission = dict(repository=c.REPOSITORY, repository_id=123, active=True, app_id=c.APP,
        installation_id=c.INSTALLATION, expected=copy.deepcopy(expected), quality=copy.deepcopy(result),
        check_run_id=42, receipt_sha256=c.digest(receipt))
    environment = dict(GITHUB_REPOSITORY=c.REPOSITORY, GITHUB_EVENT_NAME='workflow_dispatch',
        GITHUB_REF='refs/heads/main', BOX_FORMAL_CONSUMER_SHA='c' * 40, GITHUB_WORKFLOW_SHA='c' * 40,
        GITHUB_RUN_ID='100', GITHUB_RUN_ATTEMPT='1',
        GITHUB_WORKFLOW_REF=c.REPOSITORY + '/.github/workflows/box-formal-receipt.yml@refs/heads/main')
    return receipt, admission, environment


class MockReader:
    """Fixture transport only: cannot be used to establish real authentication."""
    def __init__(self, receipt, admission):
        self.receipt = receipt
        self.repo = dict(id=123, full_name=quality.REPOSITORY)
        self.pr = dict(number=1, state='open', merged=False,
            base=dict(repo=self.repo, ref='main', sha='b' * 40),
            head=dict(repo={'id': 456}, sha='a' * 40))
        self.commit_value = dict(sha='a' * 40, tree={'sha': 'a' * 40})
        self.check_value = dict(id=42, name=quality.consumer.CHECK, head_sha='a' * 40,
            app=dict(id=quality.consumer.APP, slug='new-api-box-formal'), status='completed',
            conclusion='success', external_id=admission['receipt_sha256'],
            output={'text': json.dumps(receipt)})
        self.run_value = dict(id=100, run_attempt=1, workflow_id=101, path='.github/workflows/box-formal-receipt.yml',
            event='workflow_dispatch', head_branch='main', head_sha='c' * 40,
            repository=self.repo, head_repository=self.repo, status='in_progress', conclusion=None)
        self.reads = 0
        self.on_pull = lambda _: None

    def repository(self):
        return copy.deepcopy(self.repo)

    def pull(self, number):
        self.reads += 1
        self.on_pull(self)
        return copy.deepcopy(self.pr)

    def commit(self, sha):
        return copy.deepcopy(self.commit_value)

    def check(self, check_id):
        return copy.deepcopy(self.gate_value if check_id == 43 else self.check_value)

    def run(self, run_id, attempt):
        return copy.deepcopy(self.run_value)


class MockHTTP:
    """MOCK authenticated HTTP only; real production transport is not supplied."""
    def __init__(self, reader):
        self.reader = reader
        self.failure = None
        self.before_post = lambda: None
        self.posts = []

    def app_get(self, path):
        if self.failure == 'installation':
            raise ValueError('fixture installation unavailable')
        if path != '/repos/' + quality.REPOSITORY + '/installation':
            raise AssertionError('unexpected App endpoint')
        return dict(id=quality.consumer.INSTALLATION, app_id=quality.consumer.APP,
                    suspended_at=None, permissions={'checks': 'write'})

    def installation_request(self, method, path, payload):
        if method == 'GET' and path == '/installation/repositories?per_page=100':
            return {'repositories': [self.reader.repository()]}
        if method != 'POST' or path != '/repos/' + quality.REPOSITORY + '/check-runs':
            raise AssertionError('unexpected write endpoint')
        if payload['status'] != 'in_progress' or 'conclusion' in payload:
            raise AssertionError('unsafe write')
        self.before_post()
        self.posts.append(copy.deepcopy(payload))
        if self.failure == 'publish':
            raise OSError('fixture POST refused')
        self.reader.gate_value = dict(copy.deepcopy(payload), id=43, conclusion=None,
            app=dict(id=quality.consumer.APP, slug='new-api-box-formal'))
        if self.failure in ('partial', 'lost-ack'):
            raise OSError('fixture uncertain POST acknowledgement')
        return copy.deepcopy(self.reader.gate_value)

    def finish_fixture(self):
        # Models an EXTERNAL existing App publisher, never product code. This
        # synthetic response is not written to GitHub or saved as real admission.
        self.reader.gate_value.update(status='completed', conclusion='success')

    @property
    def green(self):
        gate = getattr(self.reader, 'gate_value', {})
        return gate.get('conclusion') == 'success'


class QualityResultsTests(unittest.TestCase):
    def setUp(self):
        self.receipt, self.admission, self.environment = fixture()
        self.reader = MockReader(self.receipt, self.admission)
        self.http = MockHTTP(self.reader)
        self.publisher = quality.GitHubPublication(self.http.app_get, self.http.installation_request)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.journal = quality.AdmissionJournal(str(Path(self.tmp.name) / 'admissions.sqlite'))

    def verify(self):
        return quality.verify(self.admission, self.environment, self.reader, clock=lambda: 200)

    def publish(self):
        return quality.stage_publication(self.admission, self.environment, self.reader, self.publisher,
                                         self.journal, clock=lambda: 200)

    def resign_fixture(self):
        # This only updates MOCK API data. It is never a real authenticated receipt.
        self.admission['receipt_sha256'] = quality.consumer.digest(self.receipt)
        self.reader.check_value.update(external_id=self.admission['receipt_sha256'],
                                      output={'text': json.dumps(self.receipt)})

    def assert_default_route_rejects(self, route):
        """No execution_evidence argument; agree on all MOCK admission digests.

        For collection prepopulate an exact pending journal/publication fixture
        independently, so rejection cannot pass merely because staging failed.
        """
        self.admission['expected'] = copy.deepcopy(self.receipt['binding'])
        self.admission['quality'] = copy.deepcopy(self.receipt['quality'])
        self.resign_fixture()
        if route == 'collect':
            expected = self.admission['expected']
            request = dict(schema=quality.SCHEMA, name=quality.GATE, repository=quality.REPOSITORY,
                repository_id=self.admission['repository_id'], candidate_sha=expected['candidate_sha'],
                candidate_tree=expected['candidate_tree'], receipt_sha256=self.admission['receipt_sha256'],
                check_run_id=self.admission['check_run_id'], admission_id=expected['admission_id'],
                invocation=expected['invocation'], attempt_id=expected['attempt_id'],
                expires_at=expected['expires_at'], quality=copy.deepcopy(self.admission['quality']))
            self.journal.claim(request)
            self.journal.stage(request, 43)
            self.reader.gate_value = dict(id=43, name=quality.GATE, head_sha=expected['candidate_sha'],
                app=dict(id=quality.consumer.APP, slug='new-api-box-formal'), status='completed',
                conclusion='success', external_id=quality.consumer.digest(request),
                output={'text': json.dumps(request)})
        with self.assertRaises((ValueError, KeyError)):
            if route == 'verify':
                self.verify()
            elif route == 'stage':
                self.publish()
            else:
                quality.collect_result(self.admission, self.environment, self.reader,
                                       self.publisher, self.journal, clock=lambda: 200)
        self.assertEqual([], self.http.posts)
        if route == 'collect':
            self.assertEqual(43, self.journal.pending(request), 'rejected collection must not consume')

    def test_default_routes_reject_consistently_changed_formal_inventory(self):
        for mutation in ('missing', 'substituted', 'extra'):
            for route in ('verify', 'stage', 'collect'):
                with self.subTest(mutation=mutation, route=route):
                    self.setUp()
                    plan = self.receipt['binding']['tiers']
                    if mutation == 'missing':
                        del plan['postgres-redis']
                    elif mutation == 'substituted':
                        plan['unapproved-formal'] = plan.pop('postgres-redis')
                    else:
                        plan['unapproved-formal'] = copy.deepcopy(plan['postgres-redis'])
                    # Receipt, admission, and quality inventory deliberately agree.
                    self.receipt['tiers'] = [dict(tier=name, exit=0, cleanup=True,
                        invocation=self.receipt['binding']['invocation'], log_sha256='e' * 64,
                        **entry) for name, entry in plan.items()]
                    formal = self.receipt['quality']['results']['formal']
                    formal['required'] = sorted(plan)
                    formal['commands'] = [dict(id=name, exit=0, skipped=False, cleanup=True,
                                              log_sha256='e' * 64) for name in sorted(plan)]
                    self.assert_default_route_rejects(route)

    def test_default_routes_require_policy_and_consumer_results(self):
        for command in ('policy-tests', 'consumer-tests'):
            for mutation in ('missing-group', 'missing', 'failed', 'skipped', 'incomplete', 'cleanup'):
                for route in ('verify', 'stage', 'collect'):
                    with self.subTest(command=command, mutation=mutation, route=route):
                        self.setUp()
                        groups = self.receipt['quality']['results']
                        policy = groups['policy']
                        record = next(item for item in policy['commands'] if item['id'] == command)
                        if mutation == 'missing-group':
                            del groups['policy']
                        elif mutation == 'missing':
                            policy['required'].remove(command)
                            policy['commands'].remove(record)
                        elif mutation == 'failed':
                            record['exit'] = 7
                        elif mutation == 'skipped':
                            record['skipped'] = True
                        elif mutation == 'incomplete':
                            policy['unexecuted'] = [command]
                        else:
                            record['cleanup'] = False
                        self.assert_default_route_rejects(route)

    def test_mock_authenticated_success_and_exact_result_return(self):
        pending = self.publish()
        self.assertEqual({'state': 'pending', 'check_run_id': 43, 'candidate_sha': 'a' * 40}, pending)
        self.assertFalse(self.http.green)
        with self.assertRaises(ValueError):
            quality.collect_result(self.admission, self.environment, self.reader, self.publisher,
                                   self.journal, clock=lambda: 200)
        self.http.finish_fixture()
        # Equivalent JSON formatting is allowed; typed values must remain exact.
        self.reader.gate_value['output']['text'] = json.dumps(
            json.loads(self.reader.gate_value['output']['text']), indent=2, sort_keys=True)
        result = quality.collect_result(self.admission, self.environment, self.reader, self.publisher,
                                        self.journal, clock=lambda: 200)
        self.assertEqual('verified', result['state'])
        self.assertEqual('a' * 40, result['result']['candidate_sha'])
        self.assertEqual(self.admission['quality'], result['result']['quality'])
        with self.assertRaises(ValueError):
            quality.collect_result(self.admission, self.environment, self.reader, self.publisher,
                                   self.journal, clock=lambda: 200)
        self.assertEqual(1, len(self.http.posts))

    def test_publication_rejects_equal_values_with_wrong_json_types(self):
        # Python equality aliases False/0, 0.0/0 and 1/True. An App check must
        # echo the exact typed result, even when its external_id is unchanged.
        for field, value in [('exit', False), ('exit', 0.0), ('cleanup', 1)]:
            for route in ('stage', 'collect'):
                with self.subTest(field=field, value=value, route=route):
                    self.setUp()
                    request = self.verify()

                    def substitute(check):
                        output = json.loads(check['output']['text'])
                        output['quality']['results']['backend']['commands'][0][field] = value
                        check['output']['text'] = json.dumps(output)
                        return check

                    if route == 'stage':
                        def response(method, path, payload):
                            check = self.http.installation_request(method, path, payload)
                            return substitute(check) if method == 'POST' else check

                        with patch.object(self.publisher, '_installation_request', side_effect=response):
                            with self.assertRaisesRegex(ValueError, 'substituted quality publication'):
                                self.publish()
                        self.assertFalse(self.http.green)
                        # An ambiguous POST acknowledgement still burns the claim.
                        with self.assertRaises(sqlite3.IntegrityError):
                            self.publish()
                    else:
                        self.publish()
                        self.http.finish_fixture()
                        substitute(self.reader.gate_value)
                        with self.assertRaisesRegex(ValueError, 'substituted quality publication'):
                            quality.collect_result(self.admission, self.environment, self.reader,
                                self.publisher, self.journal, clock=lambda: 200)
                        self.assertEqual(43, self.journal.pending(request))
                    self.assertEqual(1, len(self.http.posts))

    def test_collection_rejects_json_type_drift_on_final_publication_read(self):
        self.publish()
        self.http.finish_fixture()
        request = self.verify()
        read = self.reader.check
        gate_reads = 0

        def response(check_id):
            nonlocal gate_reads
            check = read(check_id)
            if check_id == 43:
                gate_reads += 1
                if gate_reads == 2:
                    check['id'] = 43.0
            return check

        with patch.object(self.reader, 'check', side_effect=response):
            with self.assertRaisesRegex(ValueError, 'publication changed during collection'):
                quality.collect_result(self.admission, self.environment, self.reader,
                    self.publisher, self.journal, clock=lambda: 200)
        self.assertEqual(2, gate_reads)
        self.assertEqual(43, self.journal.pending(request))
        self.assertEqual(1, len(self.http.posts))

    def test_raw_execution_report_cannot_replace_authenticated_receipt(self):
        # A's published interface, represented locally without sibling imports.
        raw = dict(schema='quality-execution-evidence/v1', authentication='UNAUTHENTICATED',
                   binding=dict(schema='quality-execution-request/v1', repository=quality.REPOSITORY,
                       candidate_sha='a' * 40, candidate_tree='a' * 40,
                       attempt_id='fixture-attempt', invocation='f' * 64),
                   provenance={}, started_at=110, completed_at=190, commands=[], required=[],
                   unexecuted=['formal'], blocked=['formal'], exit=1, cleanup=True, error=None)
        self.reader.check_value['output']['text'] = json.dumps(raw)
        self.admission['receipt_sha256'] = quality.consumer.digest(raw)
        self.reader.check_value['external_id'] = self.admission['receipt_sha256']
        with self.assertRaises((KeyError, ValueError)):
            self.publish()
        self.assertFalse(self.http.green)

    def test_each_quality_group_must_be_complete_and_successful(self):
        for group in ('backend', 'formal', 'frontend', 'database', 'policy'):
            for mutation in ('missing', 'partial', 'exit', 'cleanup', 'skip', 'command-fail', 'boolean-exit'):
                with self.subTest(group=group, mutation=mutation):
                    self.setUp()
                    target = self.receipt['quality']['results'][group]
                    if mutation == 'missing':
                        del self.receipt['quality']['results'][group]
                    elif mutation == 'partial':
                        target['commands'].pop()
                    elif mutation == 'exit':
                        target['exit'] = 1
                    elif mutation == 'cleanup':
                        target['cleanup'] = False
                    elif mutation == 'skip':
                        target['commands'][0]['skipped'] = True
                    elif mutation == 'boolean-exit':
                        target['commands'][0]['exit'] = False
                    else:
                        target['commands'][0]['exit'] = 2
                    self.admission['quality'] = copy.deepcopy(self.receipt['quality'])
                    self.resign_fixture()
                    with self.assertRaises((KeyError, ValueError)):
                        self.publish()
                    self.assertFalse(self.http.green)

    def test_authenticated_receipt_and_run_identities_cannot_be_substituted(self):
        cases = [(self.reader.check_value, 'app', {'id': 1, 'slug': 'new-api-box-formal'}),
                 (self.reader.check_value, 'head_sha', 'd' * 40),
                 (self.reader.check_value, 'id', 43),
                 (self.reader.check_value, 'external_id', 'f' * 64),
                 (self.reader.commit_value['tree'], 'sha', 'd' * 40),
                 (self.reader.run_value, 'id', 102),
                 (self.reader.run_value, 'run_attempt', 2),
                 (self.reader.run_value, 'workflow_id', 102),
                 (self.reader.run_value, 'head_sha', 'd' * 40),
                 (self.reader.run_value, 'path', '.github/workflows/untrusted.yml'),
                 (self.reader.run_value, 'event', 'pull_request'),
                 (self.reader.run_value, 'head_branch', 'candidate'),
                 (self.reader.run_value, 'head_repository', {'id': 456}),
                 (self.reader.run_value, 'conclusion', 'failure'),
                 (self.reader.run_value, 'status', 'completed')]
        for target, field, value in cases:
            with self.subTest(field=field, value=value):
                original = target[field]
                target[field] = value
                with self.assertRaises(ValueError):
                    self.publish()
                self.assertFalse(self.http.green)
                target[field] = original

    def test_binding_and_partial_formal_evidence_rejected(self):
        for field in ('candidate_sha', 'candidate_tree', 'execution_sha', 'attempt_id', 'invocation', 'admission_id'):
            with self.subTest(field=field):
                self.setUp()
                self.receipt['quality'][field] = 'f' * 40
                self.admission['quality'] = copy.deepcopy(self.receipt['quality'])
                self.resign_fixture()
                with self.assertRaises(ValueError):
                    self.publish()
        for field, value in [('cleanup', False), ('unexecuted', ['fixture-formal']), ('tiers', [])]:
            with self.subTest(formal=field):
                self.setUp()
                self.receipt[field] = value
                self.resign_fixture()
                with self.assertRaises(ValueError):
                    self.publish()
        self.assertFalse(self.http.green)

    def test_expiry_and_replay_burn_durable_single_use_claim(self):
        self.publish()
        # A second journal connection proves persistence beyond one Python object.
        self.journal = quality.AdmissionJournal(str(Path(self.tmp.name) / 'admissions.sqlite'))
        with self.assertRaises(sqlite3.IntegrityError):
            self.publish()
        self.assertEqual(1, len(self.http.posts))
        self.assertFalse(self.http.green)
        for now in (99, 301):
            self.setUp()
            with self.assertRaises(ValueError):
                quality.stage_publication(self.admission, self.environment, self.reader, self.publisher,
                                          self.journal, clock=lambda: now)
            self.assertFalse(self.http.green)

    def test_head_or_base_change_at_each_reread_and_post_is_never_green(self):
        for side in ('head', 'base'):
            for read in range(1, 7):
                with self.subTest(side=side, read=read):
                    self.setUp()
                    def change(reader):
                        if reader.reads == read:
                            reader.pr[side]['sha'] = 'd' * 40
                    self.reader.on_pull = change
                    with self.assertRaises(ValueError):
                        self.publish()
                    self.assertFalse(self.http.green)
            self.setUp()
            self.http.before_post = lambda: self.reader.pr[side].update(sha='d' * 40)
            with self.assertRaises(ValueError):
                self.publish()
            self.assertFalse(self.http.green)

    def test_partial_publication_and_lost_ack_leave_only_pending_and_cannot_retry(self):
        for failure in ('installation', 'publish', 'partial', 'lost-ack'):
            with self.subTest(failure=failure):
                self.setUp()
                self.http.failure = failure
                with self.assertRaises((ValueError, OSError)):
                    self.publish()
                self.assertFalse(self.http.green)
                if failure != 'installation':
                    self.http.failure = None
                    with self.assertRaises(sqlite3.IntegrityError):
                        self.publish()
                    self.assertFalse(self.http.green)

    def test_collection_rejects_partial_wrong_app_or_changed_head(self):
        for mutation in ('partial', 'app', 'sha', 'head', 'base', 'expiry'):
            with self.subTest(mutation=mutation):
                self.setUp()
                self.publish()
                self.http.finish_fixture()
                if mutation == 'partial':
                    self.reader.gate_value['output']['text'] = '{}'
                elif mutation == 'app':
                    self.reader.gate_value['app']['id'] = 1
                elif mutation == 'sha':
                    self.reader.gate_value['head_sha'] = 'd' * 40
                elif mutation in ('head', 'base'):
                    self.reader.pr[mutation]['sha'] = 'd' * 40
                now = 301 if mutation == 'expiry' else 200
                with self.assertRaises(ValueError):
                    quality.collect_result(self.admission, self.environment, self.reader, self.publisher,
                                           self.journal, clock=lambda: now)
                # There is one prior staged POST, no collector write or new-head success.
                self.assertEqual(1, len(self.http.posts))
                self.assertEqual('a' * 40, self.http.posts[0]['head_sha'])

    def test_real_child_failure_is_rejected_without_publication(self):
        child = subprocess.run([sys.executable, '-I', '-B', '-c', 'raise SystemExit(7)'],
                               env={}, capture_output=True, timeout=5)
        self.assertEqual(7, child.returncode)
        self.receipt['process_exit'] = child.returncode
        self.resign_fixture()
        with self.assertRaises(ValueError):
            self.publish()
        self.assertFalse(self.http.green)

    def test_missing_database_leaves_or_executable_metadata_is_rejected(self):
        self.receipt['quality']['results']['database']['required_leaves'] = []
        self.admission['quality'] = copy.deepcopy(self.receipt['quality'])
        self.resign_fixture()
        with self.assertRaises(ValueError):
            self.publish()
        self.setUp()
        self.receipt['quality']['results']['backend']['commands'][0]['argv'] = ['arbitrary-program']
        self.admission['quality'] = copy.deepcopy(self.receipt['quality'])
        self.resign_fixture()
        with self.assertRaises(ValueError):
            self.publish()
        self.assertFalse(self.http.green)

    def test_durable_claim_allows_only_one_concurrent_caller(self):
        request = self.verify()
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(self.journal.claim, request) for _ in range(2)]
        errors = [future.exception() for future in futures]
        self.assertEqual(1, errors.count(None))
        self.assertEqual(1, sum(isinstance(error, sqlite3.IntegrityError) for error in errors))

    def test_concrete_http_adapter_only_stages_non_green_on_fixed_origin(self):
        transport = quality.GitHubStagingHTTP('FIXTURE-NOT-A-CREDENTIAL')
        payload = dict(name=quality.GATE, head_sha='a' * 40, status='in_progress',
                       external_id='e' * 64, output={'title': 'pending', 'summary': 'pending'})
        with patch.object(quality.urllib.request, 'build_opener') as opener:
            opener.return_value.open.return_value = io.BytesIO(b'{"id":43}')
            self.assertEqual({'id': 43}, transport.request('POST',
                '/repos/' + quality.REPOSITORY + '/check-runs', payload))
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual('https://api.github.com/repos/86669666/new-api/check-runs', request.full_url)
            self.assertEqual('in_progress', json.loads(request.data)['status'])
            for method, path, body in [
                ('PATCH', '/repos/' + quality.REPOSITORY + '/check-runs/43', payload),
                ('POST', '/repos/other/repo/check-runs', payload),
                ('POST', '/repos/' + quality.REPOSITORY + '/check-runs',
                 dict(payload, status='completed', conclusion='success'))]:
                with self.assertRaises(ValueError):
                    transport.request(method, path, body)
            self.assertEqual(1, opener.return_value.open.call_count)
        with self.assertRaises(ValueError):
            quality.consumer.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://evil.invalid')

    def test_get_transport_has_fixed_endpoints_and_rejects_path_injection(self):
        reader = quality.GitHubReader('fixture-only-token')
        with patch.object(quality.consumer, 'api', return_value={}) as api:
            reader.repository()
            reader.pull(1)
            reader.commit('a' * 40)
            reader.check(42)
            reader.run(100, 1)
            self.assertEqual([
                '/repos/86669666/new-api', '/repos/86669666/new-api/pulls/1',
                '/repos/86669666/new-api/git/commits/' + 'a' * 40,
                '/repos/86669666/new-api/check-runs/42',
                '/repos/86669666/new-api/actions/runs/100/attempts/1'],
                [call.args[0] for call in api.call_args_list])
            for method, args in [(reader.pull, ('1/../../x',)), (reader.check, (True,)),
                                 (reader.commit, ('main',)), (reader.run, (100, '../2'))]:
                with self.assertRaises(ValueError):
                    method(*args)
            self.assertEqual(5, api.call_count)

    def test_real_isolated_cli_rejects_candidate_module_injection_and_redacts_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / 'executed'
            (Path(tmp) / 'json.py').write_text(f'open({str(marker)!r}, "w").write("bad")\n')
            env = dict(self.environment, BOX_FORMAL_ADMISSION=json.dumps(self.admission),
                       GITHUB_TOKEN='DO-NOT-LOG-FIXTURE-TOKEN', PYTHONPATH=tmp)
            # Expired fixture: validation fails before any API request.
            child = subprocess.run([sys.executable, '-I', '-B', str(Path(quality.__file__).resolve())],
                env=env, cwd=tmp, capture_output=True, text=True, timeout=5)
            self.assertNotEqual(0, child.returncode)
            self.assertFalse(marker.exists())
            self.assertNotIn('DO-NOT-LOG', child.stdout + child.stderr)
            self.assertEqual('Quality evidence rejected; no publication authorization granted.\n', child.stderr)


class QualityWiringTests(unittest.TestCase):
    """CI wiring contracts: all remote authentication/approvals are OFFLINE MOCKS."""

    def setUp(self):
        self.receipt, self.admission, self.environment = fixture()
        self.admission['quality_check_run_id'] = 43
        self.environment.update(EXPECTED_SHA='a' * 40, BOX_FORMAL_REVIEWER_IDS='[7]',
            QUALITY_RESULTS=json.dumps(dict.fromkeys(('backend', 'frontend', 'database'), 'success')))
        event_dir = tempfile.TemporaryDirectory()
        self.addCleanup(event_dir.cleanup)
        self.event_path = Path(event_dir.name) / 'event.json'
        self.event = dict(action='synchronize', number=1, pull_request=dict(
            number=1, state='open', merged=False, head={'sha': 'a' * 40}, base={'sha': 'b' * 40}))
        self.event_path.write_text(json.dumps(self.event))
        self.environment.update(GITHUB_EVENT_NAME='pull_request', GITHUB_REF='refs/pull/1/merge',
                                GITHUB_EVENT_PATH=str(self.event_path))
        self.reader = MockReader(self.receipt, self.admission)
        self.reader.run_value.update(status='completed', conclusion='success', triggering_actor={'id': 8})
        self.latest = copy.deepcopy(self.reader.run_value)
        self.reviews = [dict(environments=[{'name': 'box-formal-consumer'}],
                             state='approved', user={'id': 7})]
        self.reader.latest_run = lambda run_id: copy.deepcopy(self.latest)
        self.reader.approvals = lambda run_id: copy.deepcopy(self.reviews)
        # Independently authored App response fixture; never stage or publish it.
        expected = self.admission['expected']
        request = dict(schema='box-quality-result/v1', name='Required quality gate',
            repository='86669666/new-api', repository_id=123,
            candidate_sha=expected['candidate_sha'], candidate_tree=expected['candidate_tree'],
            receipt_sha256=self.admission['receipt_sha256'], check_run_id=42,
            admission_id=expected['admission_id'], invocation=expected['invocation'],
            attempt_id=expected['attempt_id'], expires_at=expected['expires_at'],
            quality=copy.deepcopy(self.admission['quality']))
        self.reader.gate_value = dict(id=43, name='Required quality gate', head_sha='a' * 40,
            app=dict(id=5498942, slug='new-api-box-formal'), status='completed', conclusion='success',
            external_id=quality.consumer.digest(request), output={'text': json.dumps(request)})

    def verify(self, now=200):
        return quality.verify_ci_result(self.admission, self.environment, self.reader, clock=lambda: now)

    def test_ci_entry_accepts_only_complete_existing_authenticated_result(self):
        output = io.StringIO()
        original = quality.verify_ci_result
        with patch.dict(os.environ, dict(self.environment, BOX_FORMAL_ADMISSION=json.dumps(self.admission),
                GITHUB_TOKEN='OFFLINE-NOT-A-CREDENTIAL'), clear=True), \
                patch.object(sys, 'argv', ['quality_results.py', 'ci']), \
                patch.object(quality, 'GitHubReader', return_value=self.reader), \
                patch.object(quality, 'verify_ci_result', side_effect=lambda *args: original(
                    *args, clock=lambda: 200)), \
                redirect_stdout(output):
            # Invoke the actual workflow CLI entry, not stage/collect/publisher.
            quality.main()
        self.assertEqual('a' * 40, json.loads(output.getvalue())['candidate_sha'])
        self.assertEqual(42, json.loads(output.getvalue())['check_run_id'])

    def test_ci_rejects_missing_failed_skipped_or_partial_hosted_jobs(self):
        for job in ('backend', 'frontend', 'database'):
            for state in (None, 'failure', 'skipped', 'cancelled', '', 'pending'):
                with self.subTest(job=job, state=state):
                    values = dict.fromkeys(('backend', 'frontend', 'database'), 'success')
                    if state is None:
                        del values[job]
                    else:
                        values[job] = state
                    self.environment['QUALITY_RESULTS'] = json.dumps(values)
                    with self.assertRaises(ValueError):
                        self.verify()

    def test_ci_rejects_wrong_candidate_missing_failed_forged_and_replayed_results(self):
        mutations = ('sha', 'tree', 'missing-check', 'missing-quality', 'failed-receipt',
            'skipped-command', 'missing-tier', 'cleanup', 'gate-failure', 'gate-skip',
            'gate-pending', 'gate-app', 'receipt-app', 'replay-invocation', 'replay-admission',
            'replay-attempt', 'replay-check', 'gate-sha', 'inactive', 'raw-report')
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.setUp()
                if mutation == 'sha':
                    self.environment['EXPECTED_SHA'] = 'd' * 40
                elif mutation == 'tree':
                    self.reader.commit_value['tree']['sha'] = 'd' * 40
                elif mutation == 'missing-check':
                    del self.admission['quality_check_run_id']
                elif mutation == 'missing-quality':
                    del self.receipt['quality']['results']['formal']
                elif mutation == 'failed-receipt':
                    self.receipt['process_exit'] = 7
                elif mutation == 'skipped-command':
                    self.receipt['quality']['results']['policy']['commands'][0]['skipped'] = True
                elif mutation == 'missing-tier':
                    self.receipt['tiers'].pop()
                elif mutation == 'cleanup':
                    self.receipt['cleanup'] = False
                elif mutation.startswith('gate-') and mutation[5:] in ('failure', 'skip'):
                    self.reader.gate_value['conclusion'] = 'skipped' if mutation == 'gate-skip' else 'failure'
                elif mutation == 'gate-pending':
                    self.reader.gate_value.update(status='in_progress', conclusion=None)
                elif mutation in ('gate-app', 'receipt-app'):
                    check = self.reader.gate_value if mutation == 'gate-app' else self.reader.check_value
                    check['app']['id'] = 1
                elif mutation.startswith('replay-') and mutation != 'replay-check':
                    key = {'invocation': 'invocation', 'admission': 'admission_id',
                           'attempt': 'attempt_id'}[mutation[7:]]
                    self.admission['expected'][key] = 'different-attempt'
                elif mutation == 'replay-check':
                    self.admission['quality_check_run_id'] = 44
                elif mutation == 'gate-sha':
                    self.reader.gate_value['head_sha'] = 'd' * 40
                elif mutation == 'inactive':
                    self.admission['active'] = False
                else:
                    self.receipt = dict(schema='quality-execution-evidence/v1', authentication='UNAUTHENTICATED')
                # Even agree on fixture hashes: data cannot replace App origin,
                # successful inventories, or the pre-existing exact gate envelope.
                if 'quality' in self.receipt:
                    self.admission['quality'] = copy.deepcopy(self.receipt['quality'])
                self.reader.check_value['output']['text'] = json.dumps(self.receipt)
                self.admission['receipt_sha256'] = quality.consumer.digest(self.receipt)
                self.reader.check_value['external_id'] = self.admission['receipt_sha256']
                request = json.loads(self.reader.gate_value['output']['text'])
                request.update(receipt_sha256=self.admission['receipt_sha256'],
                               quality=copy.deepcopy(self.admission['quality']))
                self.reader.gate_value.update(external_id=quality.consumer.digest(request),
                                             output={'text': json.dumps(request)})
                with self.assertRaises((ValueError, KeyError)):
                    self.verify()

    def test_ci_rejects_untrusted_workflows_reviewers_reruns_expiry_and_head_drift(self):
        for mutation in ('workflow', 'consumer-sha', 'workflow-failed', 'workflow-skipped',
                         'rerun', 'reviewer', 'self-review', 'no-review', 'rejected-review',
                         'wrong-environment', 'unconfigured-reviewers', 'head', 'base', 'future', 'expired'):
            with self.subTest(mutation=mutation):
                self.setUp()
                if mutation == 'workflow':
                    self.reader.run_value['path'] = '.github/workflows/untrusted.yml'
                elif mutation == 'consumer-sha':
                    self.environment['BOX_FORMAL_CONSUMER_SHA'] = 'd' * 40
                elif mutation.startswith('workflow-'):
                    self.reader.run_value['conclusion'] = mutation[9:]
                elif mutation == 'rerun':
                    self.latest['run_attempt'] = 2
                elif mutation == 'reviewer':
                    self.reviews[0]['user']['id'] = 9
                elif mutation == 'self-review':
                    self.reader.run_value['triggering_actor']['id'] = 7
                    self.latest = copy.deepcopy(self.reader.run_value)
                elif mutation == 'no-review':
                    self.reviews.clear()
                elif mutation == 'rejected-review':
                    self.reviews[0]['state'] = 'rejected'
                elif mutation == 'wrong-environment':
                    self.reviews[0]['environments'][0]['name'] = 'untrusted'
                elif mutation == 'unconfigured-reviewers':
                    self.environment['BOX_FORMAL_REVIEWER_IDS'] = '[]'
                elif mutation in ('head', 'base'):
                    self.reader.pr[mutation]['sha'] = 'd' * 40
                with self.assertRaises(ValueError):
                    self.verify(now={'future': 99, 'expired': 301}.get(mutation, 200))

    def test_ci_rejects_final_read_drift_without_any_publication(self):
        read = self.reader.check
        count = 0

        def drifting_check(check_id):
            nonlocal count
            check = read(check_id)
            if check_id == 43:
                count += 1
                if count == 2:
                    check['conclusion'] = 'failure'
            return check

        self.reader.check = drifting_check
        with self.assertRaisesRegex(ValueError, 'evidence changed'):
            self.verify()

    def test_ci_run_reads_are_fixed_gets_and_compare_identity_not_response_extras(self):
        reader = quality.GitHubReader('OFFLINE-NOT-A-CREDENTIAL')
        with patch.object(quality.consumer, 'api', return_value={}) as api:
            reader.latest_run(100)
            reader.approvals(100)
            self.assertEqual(['/repos/86669666/new-api/actions/runs/100',
                              '/repos/86669666/new-api/actions/runs/100/approvals'],
                             [call.args[0] for call in api.call_args_list])
            for method in (reader.latest_run, reader.approvals):
                for run_id in (True, 0, '100/../../x'):
                    with self.assertRaises(ValueError):
                        method(run_id)
            self.assertEqual(2, api.call_count)
        self.latest['previous_attempt_url'] = None  # Endpoint-specific metadata.
        self.assertEqual('a' * 40, self.verify()['candidate_sha'])

    def test_ci_gate_rejects_duplicate_fields_and_accepts_json_formatting_only(self):
        output = self.reader.gate_value['output']
        value = json.loads(output['text'])
        output['text'] = json.dumps(value, indent=2, sort_keys=True)
        self.assertEqual('a' * 40, self.verify()['candidate_sha'])
        output['text'] = '{"candidate_sha":"forged",' + json.dumps(value)[1:]
        with self.assertRaisesRegex(ValueError, 'duplicate receipt field'):
            self.verify()

    def test_actual_workflow_entry_cannot_emit_sha_after_verifier_failure(self):
        root = Path(quality.__file__).resolve().parents[2]
        workflow = (root / '.github/workflows/ci.yml').read_text()
        gate = workflow.split('  quality-gate:\n', 1)[1]
        self.assertIn('environment: box-formal-consumer', gate)
        self.assertIn('ref: ${{ vars.BOX_FORMAL_READER_SHA }}', gate)
        self.assertIn('BOX_FORMAL_REVIEWER_IDS: ${{ vars.BOX_FORMAL_REVIEWER_IDS }}', gate)
        self.assertIn('github.event.pull_request.head.sha', gate)
        self.assertNotIn('execution route not configured', workflow)
        for name in ('docker-build.yml', 'docker-image-branch.yml', 'electron-build.yml',
                     'release.yml', 'sync-release-to-gitcode.yml'):
            caller = (root / '.github/workflows' / name).read_text().split('  quality:\n', 1)[1]
            caller = re.split(r'^  [a-zA-Z][\w-]*:\n', caller, maxsplit=1, flags=re.MULTILINE)[0]
            self.assertIn('uses: ./.github/workflows/ci.yml', caller)
            self.assertIn('permissions:\n      contents: read\n      checks: read\n      actions: read', caller)
        block = re.search(r'        run: \|\n((?:          .*\n)+)', gate)
        self.assertIsNotNone(block)
        script = textwrap.dedent(block.group(1))
        self.assertEqual('python3 -I -B trusted-quality/scripts/ci/quality_results.py ci',
                         script.splitlines()[0])
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'output'
            calls = Path(tmp) / 'calls'
            env = dict(os.environ, EXPECTED_SHA='a' * 40, GITHUB_OUTPUT=str(output), CALLS=str(calls))
            for code in (0, 7):
                if output.exists():
                    output.unlink()
                # Shell command shim only: the real verifier itself is exercised
                # by test_ci_entry_* with independently authored HTTP fixtures.
                prefix = 'python3() { printf "%s\\n" "$*" > "$CALLS"; return ' + str(code) + '; }\n'
                child = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', prefix + script],
                    env=env, capture_output=True, text=True, timeout=5)
                self.assertEqual(code, child.returncode)
                self.assertEqual('-I -B trusted-quality/scripts/ci/quality_results.py ci\n', calls.read_text())
                self.assertEqual(code == 0, output.exists())

    def test_premerge_contract_open_pr_keeps_strict_binding_and_result_failures(self):
        self.assertEqual('a' * 40, self.verify()['candidate_sha'])
        for mutation in ('event-head', 'event-base', 'event-number', 'live-head', 'live-base',
                         'live-merged', 'hosted-failed', 'app-failed'):
            with self.subTest(mutation=mutation):
                self.setUp()
                if mutation in ('event-head', 'event-base'):
                    self.event['pull_request'][mutation[6:]]['sha'] = 'd' * 40
                elif mutation == 'event-number':
                    self.event['number'] = self.event['pull_request']['number'] = 2
                    self.environment['GITHUB_REF'] = 'refs/pull/2/merge'
                elif mutation in ('live-head', 'live-base'):
                    self.reader.pr[mutation[5:]]['sha'] = 'd' * 40
                elif mutation == 'live-merged':
                    self.reader.pr.update(state='closed', merged=True)
                elif mutation == 'hosted-failed':
                    self.environment['QUALITY_RESULTS'] = json.dumps(
                        dict(backend='failure', frontend='success', database='success'))
                else:
                    self.reader.gate_value['conclusion'] = 'failure'
                self.event_path.write_text(json.dumps(self.event))
                with self.assertRaises(ValueError):
                    self.verify()

    def test_premerge_contract_rejects_unsupported_event_before_api_reads(self):
        for event_name, action, state, merged, ref in (
                ('push', '', 'open', False, 'refs/tags/v1.0.0'),
                ('workflow_dispatch', '', 'open', False, 'refs/heads/main'),
                ('release', '', 'closed', True, 'refs/tags/v1.0.0'),
                ('workflow_call', '', 'open', False, 'refs/heads/main'),
                ('pull_request', 'closed', 'closed', True, 'refs/heads/main'),
                ('pull_request', 'closed', 'closed', False, 'refs/pull/1/merge'),
                ('pull_request', 'synchronize', 'closed', True, 'refs/pull/1/merge'),
                ('pull_request', 'synchronize', 'open', False, 'refs/tags/v1.0.0')):
            with self.subTest(event=event_name, action=action, merged=merged, ref=ref):
                self.setUp()
                self.environment.update(GITHUB_EVENT_NAME=event_name, GITHUB_REF=ref)
                self.event.update(action=action)
                self.event['pull_request'].update(state=state, merged=merged)
                self.event_path.write_text(json.dumps(self.event))
                with patch.object(self.reader, 'repository') as api, \
                        self.assertRaisesRegex(quality.UnsupportedCIEvent, 'only open-PR premerge'):
                    self.verify()
                api.assert_not_called()

    def test_premerge_contract_actual_cli_rejects_without_admission_or_sha_output(self):
        for event_name, action, merged in (('push', '', False), ('workflow_dispatch', '', False),
                                           ('release', '', True), ('pull_request', 'closed', True)):
            with self.subTest(event=event_name):
                self.event.update(action=action)
                self.event['pull_request'].update(state='closed', merged=merged)
                self.event_path.write_text(json.dumps(self.event))
                # Intentionally NO admission/token. Unsupported capability must
                # be diagnosed before missing external configuration or APIs.
                child = subprocess.run([sys.executable, '-I', '-B', quality.__file__, 'ci'],
                    env=dict(GITHUB_EVENT_NAME=event_name, GITHUB_REF='refs/tags/v1.0.0',
                             GITHUB_EVENT_PATH=str(self.event_path)),
                    capture_output=True, text=True, timeout=5)
                self.assertEqual(1, child.returncode)
                self.assertEqual('', child.stdout)
                self.assertEqual('Unsupported CI lifecycle: only open-PR premerge verification is supported; '
                                 'postmerge, tag and publication reuse cannot authorize a SHA.\n', child.stderr)

    def test_premerge_contract_actual_capability_step_and_trigger_declarations(self):
        root = Path(quality.__file__).resolve().parents[2]
        workflow = (root / '.github/workflows/ci.yml').read_text()
        self.assertIn('types: [opened, reopened, synchronize]\n', workflow)
        self.assertNotIn("github.event.action != 'closed'", workflow)
        self.assertIn('no release authorization', workflow)
        gate = workflow.split('  quality-gate:\n', 1)[1]
        self.assertIn('needs: [premerge, backend, frontend, database]', gate)
        self.assertIn('if: always()', gate)
        for name in ('backend', 'frontend', 'database'):
            job = workflow.split('  ' + name + ':\n', 1)[1]
            job = re.split(r'^  [a-zA-Z][\w-]*:\n', job, maxsplit=1, flags=re.MULTILINE)[0]
            self.assertIn('needs: premerge', job)
        premerge = workflow.split('  premerge:\n', 1)[1].split('  backend:\n', 1)[0]
        block = re.search(r'        run: \|\n((?:          .*\n)+)', premerge)
        self.assertIsNotNone(block)
        script = textwrap.dedent(block.group(1))
        for event, action, expected_exit in (('pull_request', 'opened', 0),
                ('pull_request', 'reopened', 0), ('pull_request', 'synchronize', 0),
                ('pull_request', 'closed', 1), ('push', '', 1),
                ('workflow_dispatch', '', 1), ('release', '', 1)):
            with self.subTest(event=event, action=action):
                child = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script],
                    env=dict(EVENT_NAME=event, EVENT_ACTION=action), capture_output=True, text=True, timeout=5)
                self.assertEqual(expected_exit, child.returncode)
                self.assertNotIn('sha=', child.stdout + child.stderr)
                if expected_exit:
                    self.assertIn('publication callers are unsupported', child.stdout)

    def test_premerge_contract_publication_callers_remain_blocked_with_quality_needs(self):
        root = Path(quality.__file__).resolve().parents[2]
        for name in ('docker-build.yml', 'docker-image-branch.yml', 'electron-build.yml',
                     'release.yml', 'sync-release-to-gitcode.yml'):
            with self.subTest(caller=name):
                workflow = (root / '.github/workflows' / name).read_text()
                self.assertIn('postmerge/tag/release\n  # verification remains unsupported', workflow)
                self.assertIn('uses: ./.github/workflows/ci.yml', workflow)
                self.assertIn('needs.quality.outputs.verified_sha', workflow)
                self.assertRegex(workflow, r'needs: \[[^\]\n]*\bquality\b[^\]\n]*\]')
                self.assertNotIn('continue-on-error: true', workflow)


if __name__ == '__main__':
    unittest.main()
