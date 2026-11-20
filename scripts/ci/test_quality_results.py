"""Offline contract tests. App/API/publisher responses are MOCKS, not admission.

Only test_real_child_failure and the isolated CLI tests execute real tiny Python
children. No test executes Go/Node/database/formal inventories or network writes.
"""
import copy
from hashlib import sha256
import json
import io
import os
import re
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, redirect_stdout
import sqlite3
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import Mock, patch

import formal_evidence_publisher
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
                       external_id='e' * 64, output={'title': 'pending', 'summary': 'pending'},
                       started_at='2026-11-19T06:00:00Z')
        with patch.object(quality.urllib.request, 'build_opener') as opener:
            opener.return_value.open.return_value = io.BytesIO(b'{"id":43}')
            self.assertEqual({'id': 43}, transport.request('POST',
                '/repos/' + quality.REPOSITORY + '/check-runs', payload))
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual('https://api.github.com/repos/86669666/new-api/check-runs', request.full_url)
            self.assertEqual('in_progress', json.loads(request.data)['status'])
            self.assertEqual(payload['started_at'], json.loads(request.data)['started_at'])
            for method, path, body in [
                ('PATCH', '/repos/' + quality.REPOSITORY + '/check-runs/43', payload),
                ('POST', '/repos/other/repo/check-runs', payload),
                ('POST', '/repos/' + quality.REPOSITORY + '/check-runs', dict(payload, started_at='tomorrow')),
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


class CIEnvironmentWatch(Mapping):
    """Inert fixture environment; observe indexing, get and os.getenv alike."""

    def __init__(self, values, trace, *, block_admission=False, block_token=False):
        self.values = values
        self.trace = trace
        self.block_admission = block_admission
        self.block_token = block_token

    def __iter__(self):
        return iter(self.values)

    def __len__(self):
        return len(self.values)

    def read(self, operation, key, default=None):
        self.trace.append((operation, key))
        if key in ('GITHUB_TOKEN', 'BOX_FORMAL_EVIDENCE_TOKEN') and self.block_token:
            raise AssertionError('credential accessed before local binding')
        if key == 'BOX_FORMAL_ADMISSION' and self.block_admission:
            raise AssertionError('admission accessed before native validation')
        return self.values[key] if operation == 'index' else self.values.get(key, default)

    def __getitem__(self, key):
        return self.read('index', key)

    def get(self, key, default=None):
        return self.read('get', key, default)


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
        self.event = dict(action='synchronize', number=1,
            repository=dict(id=123, full_name='86669666/new-api'), pull_request=dict(
                number=1, state='open', merged=False,
                head=dict(sha='a' * 40, repo=dict(id=456, full_name='fixture-fork/new-api')),
                base=dict(sha='b' * 40, ref='main', repo=dict(id=123, full_name='86669666/new-api'))))
        self.event_path.write_text(json.dumps(self.event))
        self.environment.update(GITHUB_EVENT_NAME='pull_request', GITHUB_REF='refs/pull/1/merge',
                                GITHUB_EVENT_PATH=str(self.event_path), GITHUB_REPOSITORY_ID='123')
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

    def test_private_evidence_keeps_large_full_receipt_and_enforces_app_binding(self):
        evidence = quality.consumer.evidence
        admission, receipt = copy.deepcopy(self.admission), copy.deepcopy(self.receipt)
        images = {
            'postgres': 'sha256:94bd3af0fdb294cd2c40005951b0b1ad62bd79e058983909628bec4f2b35b313',
            'mysql': 'sha256:5022666e28e408728a872246e5b6478d9177a80e12b881d6f3983568891f1cb0',
        }
        admission['expected']['images'] = images
        receipt['binding']['images'] = images
        with self.assertRaisesRegex(ValueError, 'unapproved images'):
            quality.consumer.validate_receipt(receipt, admission, 200)
        images['mysql'] = self.admission['expected']['images']['mysql']
        with self.assertRaisesRegex(ValueError, 'unapproved images'):
            quality.consumer.validate_receipt(receipt, admission, 200, private=True)
        images['mysql'] = 'sha256:5022666e28e408728a872246e5b6478d9177a80e12b881d6f3983568891f1cb0'
        # Exact transport boundary fixture: keep the real tier inventory and matching full leaf lists.
        leaves = [f'TestPrivateTransportFixture/leaf-{i:05d}' for i in range(2000)]
        admission['expected']['tiers']['sqlite']['required_leaves'] = leaves
        receipt['binding']['tiers']['sqlite']['required_leaves'] = leaves
        next(tier for tier in receipt['tiers'] if tier['tier'] == 'sqlite')['required_leaves'] = leaves
        identity = evidence.identity(admission)
        summary = admission.pop('quality')
        summary['private_fixture_metadata'] = 'private-only-' * 6000
        receipt.pop('quality')
        admission.pop('check_run_id')
        admission.pop('quality_check_run_id')
        admission['receipt_sha256'] = None
        a, b, c = (evidence.canonical(item) for item in (admission, receipt, summary))
        release = dict(identity=identity, consumer_ref='refs/heads/main', admission_sha256=sha256(a).hexdigest(),
                       capture_sha256=sha256(b).hexdigest(), quality_sha256=sha256(c).hexdigest())
        with self.assertRaisesRegex(ValueError, 'protected consumer run'):
            formal_evidence_publisher.seal(a, b, c, dict(release, consumer_ref=None), policy=quality, now=200)
        artifact = formal_evidence_publisher.seal(a, b, c, release, policy=quality, now=200)
        self.assertGreater(len(artifact), 190159)
        reference = evidence.make_reference('d' * 40, artifact, dict(admission, quality=summary))
        config = dict(schema=evidence.CONFIG_SCHEMA, artifact=reference, check_run_id=42, quality_check_run_id=43)
        self.assertLess(len(evidence.canonical(config)), 48 * 1024)
        self.environment.update(BOX_FORMAL_ADMISSION=evidence.canonical(config).decode(),
                                BOX_FORMAL_EVIDENCE_TOKEN='FIXTURE-PRIVATE-READ', GITHUB_TOKEN='FIXTURE-APP-READ')
        def check_identity(binding):
            event = quality.ci_premerge_event(self.environment)
            quality.validate_ci_evidence_reference(event, self.environment, binding)

        with patch.object(quality.consumer, 'read_private_evidence', return_value=artifact) as fetch:
            full, bundle = quality.consumer.configured_evidence(self.environment, 200, check_identity=check_identity)
            fetch.assert_called_once_with('d' * 40, 'FIXTURE-PRIVATE-READ')
        self.assertEqual(bundle[0]['binding']['tiers']['sqlite']['required_leaves'], leaves)
        self.reader.check_value['output']['text'] = evidence.canonical(reference).decode()
        self.reader.check_value['external_id'] = full['receipt_sha256']
        request = quality.verified_request(full, full['receipt_sha256'], full['quality'], bundle)
        self.assertEqual(request['artifact'], reference)
        self.assertNotIn('quality', request)
        self.assertNotIn(b'private-only-', evidence.canonical(request))
        self.assertNotIn(b'private-only-', evidence.canonical(reference))
        self.assertLess(len(evidence.canonical(request)), 65535)
        self.reader.gate_value['name'] = 'Box formal quality result'
        self.reader.gate_value['output']['text'] = evidence.canonical(request).decode()
        self.reader.gate_value['external_id'] = quality.consumer.digest(request)
        result = quality.verify_ci_result(full, self.environment, self.reader, clock=lambda: 200, evidence_bundle=bundle)
        self.assertEqual(result['receipt_sha256'], full['receipt_sha256'])
        self.reader.check_value['output']['text'] = evidence.canonical(dict(reference, commit='e' * 40)).decode()
        with self.assertRaisesRegex(ValueError, 'differs from check output'):
            quality.verify_ci_result(full, self.environment, self.reader, clock=lambda: 200, evidence_bundle=bundle)
        with patch.object(quality.consumer, 'read_private_evidence', return_value=artifact[:-1]) as fetch:
            with self.assertRaisesRegex(ValueError, 'bytes changed'):
                quality.consumer.configured_evidence(self.environment, 200, check_identity=check_identity)
            fetch.reset_mock()
            with self.assertRaisesRegex(ValueError, 'reference expired'):
                quality.consumer.configured_evidence(self.environment, 301, check_identity=check_identity)
            fetch.assert_not_called()

        with patch.object(quality.consumer, 'read_private_evidence') as fetch:
            for key, value in (('pull_number', 2), ('candidate_sha', 'e' * 40),
                               ('base_sha', 'e' * 40), ('repository_id', 999)):
                tampered = copy.deepcopy(config)
                tampered['artifact']['identity'][key] = value
                environment = CIEnvironmentWatch(dict(self.environment, BOX_FORMAL_ADMISSION=
                    evidence.canonical(tampered).decode()), [], block_token=True)
                with self.subTest(field=key), self.assertRaisesRegex(ValueError, 'native CI event'):
                    quality.consumer.configured_evidence(environment, 200, check_identity=check_identity)
            self.environment['QUALITY_RESULTS'] = '{"backend":"failure","frontend":"success","database":"success"}'
            with self.assertRaises(ValueError):
                quality.consumer.configured_evidence(self.environment, 200, check_identity=check_identity)
            fetch.assert_not_called()

        consumer_env = fixture()[2]
        consumer_env.update(BOX_FORMAL_ADMISSION=evidence.canonical(config).decode(),
                            GITHUB_REPOSITORY_ID='123', BOX_FORMAL_EVIDENCE_TOKEN='FIXTURE-PRIVATE-READ')
        with patch.object(quality.consumer, 'read_private_evidence') as fetch:
            for key, value in (('GITHUB_REF', 'refs/heads/other'), ('GITHUB_WORKFLOW_SHA', 'e' * 40),
                               ('GITHUB_EVENT_NAME', 'pull_request'), ('GITHUB_WORKFLOW_REF', 'wrong')):
                environment = CIEnvironmentWatch(dict(consumer_env, **{key: value}), [], block_token=True)
                with self.subTest(field=key), self.assertRaises(ValueError):
                    quality.consumer.configured_evidence(environment, 200)
            fetch.assert_not_called()

    def test_v3_private_seal_binds_release_to_the_original_root_capture(self):
        evidence = quality.consumer.evidence
        admission, receipt = self.admission, self.receipt
        summary = admission.pop('quality')
        receipt.pop('quality')
        for key in ('check_run_id', 'quality_check_run_id', 'receipt_sha256'):
            del admission[key]
        summary['workflow'].update(ref=evidence.CONTROL_REF_V4, workflow_id=quality.FORMAL_WORKFLOW_ID)
        # Preserve the same observed completion, bound to the new exact execution interval.
        admission['expected']['expires_at'] = receipt['binding']['expires_at'] = 10900
        identity = evidence.identity(dict(admission, quality=summary), receipt)
        raw = [evidence.canonical(value) for value in (admission, receipt, summary)]
        release = dict(identity=identity, consumer_ref=evidence.CONTROL_REF_V4,
                       **{k + '_sha256': sha256(v).hexdigest() for k, v in
                          zip(('admission', 'capture', 'quality'), raw)})
        artifact = formal_evidence_publisher.seal(*raw, release, policy=quality, now=1990)
        doc = evidence.decode(artifact)
        self.assertEqual(evidence.ARTIFACT_SCHEMA_V4, doc['schema'])
        reference = evidence.make_reference('d' * 40, artifact, doc['admission'])
        config = dict(schema=evidence.CONFIG_SCHEMA_V4, artifact=reference, check_run_id=42, quality_check_run_id=None)
        self.assertEqual(doc['receipt'], evidence.resolve_configuration(
            config, lambda _: artifact, 1990, lambda _: None)[1][0])
        for now in (189, 1991):
            with self.subTest(now=now), self.assertRaises(ValueError):
                formal_evidence_publisher.seal(*raw, release, policy=quality, now=now)
        with self.assertRaises(ValueError):
            formal_evidence_publisher.seal(*raw, dict(release, identity=dict(identity, release_not_before=191,
                                                    release_expires_at=1991)), policy=quality, now=400)
        rebound = dict(reference, identity=dict(identity, release_not_before=191, release_expires_at=1991))
        with self.assertRaisesRegex(ValueError, 'identity drift'):
            evidence.resolve(rebound, lambda _: artifact, 1991, lambda _: None)
        for schema in (evidence.CONFIG_SCHEMA, 'box-formal-evidence-config/v3'):
            with self.subTest(schema=schema), self.assertRaises(ValueError):
                evidence.resolve_configuration(dict(config, schema=schema), lambda _: artifact, 400, lambda _: None)
        with self.assertRaises(ValueError):
            quality.consumer.configured_evidence({'BOX_FORMAL_ADMISSION': '{"schema":"unknown"}'}, 400)
        for bad in (dict(receipt, completed_at=10901), dict(receipt, started_at=True),
                    dict(receipt, unexecuted=['sqlite'])):
            with self.assertRaises(ValueError):
                quality.consumer.validate_execution_capture(bad, admission)
        for end in (7300, 10899, 10901):
            with self.subTest(end=end):
                resized = dict(receipt['binding'], expires_at=end)
                with self.assertRaisesRegex(ValueError, 'execution interval'):
                    quality.consumer.validate_execution_capture(
                        dict(receipt, binding=resized), dict(admission, expected=resized))
                with self.assertRaisesRegex(ValueError, 'release interval'):
                    evidence.validate_reference(dict(reference, identity=dict(identity, expires_at=end)), 400)
        with self.assertRaisesRegex(ValueError, 'requires its original reader'):
            evidence.uses_release_window(dict(admission, quality={'workflow': {
                'ref': 'refs/heads/codex/formal-quality-r3'}}))

    def test_terminal_proof_binds_both_approvals_hosted_jobs_and_private_artifact(self):
        self.exercise_terminal_proof(quality.consumer.evidence.CONTROL_REF)

    def test_terminal_v3_binds_checks_and_native_approvals_to_root_completion(self):
        self.exercise_terminal_proof(quality.consumer.evidence.CONTROL_REF_V4)

    def test_reuse_requires_historical_c1_and_two_fresh_ordered_approvals(self):
        self.exercise_terminal_proof(quality.consumer.evidence.CONTROL_REF_V4, reuse=True)

    def exercise_terminal_proof(self, control_ref, *, reuse=False):
        evidence = quality.consumer.evidence
        v4 = control_ref == evidence.CONTROL_REF_V4

        def stamp(second):
            return '1970-01-01T00:03:%02dZ' % second  # epoch 180 + second
        for item in (self.admission, self.receipt):
            item['quality']['workflow'].update(ref=control_ref, workflow_id=402689897)
        if v4:
            for item, field in ((self.admission, 'expected'), (self.receipt, 'binding')):
                item[field]['expires_at'] = 10900
        self.admission['receipt_sha256'] = quality.consumer.digest(self.receipt)
        stored = {key: value for key, value in self.admission.items()
                  if key not in ('check_run_id', 'quality_check_run_id')}
        reference = evidence.make_reference('d' * 40, evidence.encode_artifact(stored, self.receipt), stored)
        bundle = (self.receipt, reference)
        self.reader.check_value.update(output={'text': json.dumps(reference)},
                                       external_id=self.admission['receipt_sha256'])
        self.reader.pr['head']['repo']['full_name'] = 'fixture-fork/new-api'
        actor = {'id': 358061300}
        runs = {n: dict(self.latest, id=n, workflow_id=402689897,
                       head_branch=control_ref.removeprefix('refs/heads/'),
                       actor=actor, triggering_actor=actor) for n in (100, 200)}
        approvals = {
            100: [dict(state='approved', user={'id': 3104616}, environments=[
                {'name': 'box-formal-consumer-v2', 'id': 27663161499}])],
            200: [dict(state='approved', user={'id': 3104616}, environments=[
                {'name': 'box-formal-terminal', 'id': 27663161709}])],
        }
        if v4:
            runs[100]['created_at'] = stamp(10)
            runs[200]['created_at'] = stamp(16)
            runs[100]['updated_at'] = stamp(15)
            runs[200]['updated_at'] = stamp(18)
            self.reader.check_value.update(started_at=stamp(11), completed_at=stamp(12))
        self.reader.latest_run = runs.__getitem__
        self.reader.approvals = approvals.__getitem__
        hosted = dict(run_id=300, attempt=1, workflow_blob='e' * 40)
        intent = dict(artifact=reference, receipt_check_id=42, consumer_run=100, hosted=hosted,
                      quality_sha256=quality.consumer.digest(self.receipt['quality']))
        runs[200]['display_title'] = 'Formal terminal ' + quality.consumer.digest(intent)
        self.reader.hosted_workflow_blob = lambda sha: 'e' * 40
        self.reader.run = lambda run_id, attempt: dict(id=300, run_attempt=1, workflow_id=389317795,
            path='.github/workflows/ci.yml', event='pull_request', head_sha='a' * 40, repository=self.reader.repo,
            head_repository={'id': 456}, pull_requests=[self.reader.pr])

        def job(name, sha, *steps):
            return dict(name=name, head_sha=sha, status='completed', conclusion='success',
                        steps=[dict(name=step, status='completed', conclusion='success') for step in steps])

        jobs = {
            100: [job('Verify authenticated box receipt', 'c' * 40, 'Verify complete private evidence')],
            200: [job('Review formal quality evidence', 'c' * 40, 'Verify reviewed execution')],
            300: [
                job('Require supported premerge event', 'a' * 40,
                    'Resolve supported current open PR through read-only API'),
                job('Backend vet, build, and test', 'a' * 40, 'Vet root module', 'Vet relaykit independently',
                    'Vet tokenkit independently', 'Build root module', 'Build relaykit independently',
                    'Build tokenkit independently', 'Policy and consumer regression tests'),
                job('Frontend typecheck and test', 'a' * 40, 'Install dependencies', 'Typecheck', 'Test'),
                job('Required real database contracts', 'a' * 40, 'Required three-database suite (no skips)'),
            ],
        }
        if v4:
            jobs[100][0]['completed_at'] = stamp(15)
            jobs[200][0]['completed_at'] = stamp(18)
        self.reader.jobs = lambda run_id, attempt: jobs[run_id]

        if reuse:
            # The old receipt really expires at 1990. Only the new dispatch review opens at 2000.
            old = reference
            raw = evidence.encode_artifact(stored, self.receipt)
            with patch.object(evidence, 'REUSE_COMMIT', old['commit']), patch.object(
                    evidence, 'REUSE_ARTIFACT_SHA256', old['sha256']):
                reference = evidence.make_reuse_reference(old, 'f' * 40, 101, 2000, 'a' * 32)
                a, b = 101, 201
                hosted = quality.REUSE_HOSTED
                self.reader.hosted_workflow_blob = lambda sha: hosted['workflow_blob']
                old_hosted = self.reader.run(300, 1)
                self.reader.run = lambda run_id, attempt: dict(old_hosted, id=hosted['run_id'])
                jobs[hosted['run_id']] = jobs[300]
                for new, previous, created, done in [(a,100,2000,2005),(b,200,2006,2010)]:
                    runs[new] = dict(runs[previous], id=new, head_sha='f' * 40, status='completed', conclusion='success',
                                     head_branch=evidence.CONTROL_REF_V5.removeprefix('refs/heads/'),
                                     created_at=quality.time.strftime('%Y-%m-%dT%H:%M:%SZ',quality.time.gmtime(created)),
                                     updated_at=quality.time.strftime('%Y-%m-%dT%H:%M:%SZ',quality.time.gmtime(done)))
                    approvals[new] = copy.deepcopy(approvals[previous])
                    jobs[new] = [dict(jobs[previous][0], head_sha='f'*40, completed_at=runs[new]['updated_at'])]
                runs[a]['display_title'] = evidence.reuse_title(old, 'f'*40, reference['nonce'])
                runs[b]['display_title'] = quality.terminal_run_title(reference,evidence.REUSE_CHECK_ID,a,hosted,
                                                                       quality.consumer.digest(self.receipt['quality']))
                self.reader.check_value['id'] = evidence.REUSE_CHECK_ID
                admission, receipt = quality.load_reused_evidence(reference, self.reader, lambda commit: raw)
                def derive_reuse():
                    return quality.verify_terminal_evidence(admission, (receipt, reference), self.reader, b,
                                                            hosted, 'f'*40, 2020, staged_at=2012)
                request = derive_reuse()
                self.assertEqual((quality.TERMINAL_SCHEMA_V5,2000,3800,10900),
                                 tuple(request[k] for k in ('schema','release_not_before','release_expires_at','expires_at')))
                self.assertEqual(self.admission['receipt_sha256'],request['receipt_sha256'])
                self.environment.update(BOX_FORMAL_CONSUMER_SHA='f'*40,GITHUB_RUN_ID=str(hosted['run_id']))
                self.reader.gate_value.update(name=quality.PRIVATE_EVIDENCE_GATE, output={'text':json.dumps(request)},
                                              external_id=quality.consumer.digest(request),started_at='1970-01-01T00:33:32Z',
                                              completed_at='1970-01-01T00:33:35Z')
                self.reader.formal_quality_check = lambda sha: self.reader.gate_value
                def public():
                    return quality.verify_public_terminal(self.environment,self.reader,clock=lambda:2020)
                self.assertEqual(request,public())
                with patch.dict(self.environment,GITHUB_RUN_ID='300'), self.assertRaisesRegex(ValueError,'wrong native hosted gate'):
                    public()
                for obj, change in [(runs[a],{'created_at':'1970-01-01T00:33:21Z'}),
                                    (runs[a],{'run_attempt':2}), (runs[a],{'display_title':'Box formal receipt consumer'}),
                                    (runs[b],{'created_at':runs[a]['created_at']}),
                                    (approvals[a][0],{'state':'rejected'}), (approvals[b][0],{'user':{'id':1}}),
                                    (self.reader.check_value,{'completed_at':'1970-01-01T00:33:21Z'}),
                                    (self.reader.check_value,{'id':42}), (self.reader.check_value,{'conclusion':'neutral'}),
                                    (self.reader.check_value,{'output':{'text':json.dumps(reference)}})]:
                    with self.subTest(change=change), patch.dict(obj,change):
                        for verifier in (derive_reuse,public):
                            with self.assertRaises(ValueError):
                                verifier()
                with self.assertRaises(ValueError):
                    quality.load_reused_evidence(reference, self.reader, lambda commit: raw+b' ')
                env = dict(self.environment,GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_REF=evidence.CONTROL_REF_V5,
                           GITHUB_SHA='f'*40,GITHUB_WORKFLOW_SHA='f'*40,GITHUB_RUN_ID=str(a),GITHUB_RUN_ATTEMPT='1',
                           GITHUB_ACTOR_ID=str(evidence.TRIGGER_ID),GITHUB_TOKEN='public',BOX_FORMAL_EVIDENCE_TOKEN='private',
                           GITHUB_WORKFLOW_REF=quality.REPOSITORY+'/'+evidence.WORKFLOW_PATH+'@'+evidence.CONTROL_REF_V5,
                           BOX_FORMAL_ADMISSION=json.dumps(reference))
                with patch.object(quality,'GitHubReader',return_value=self.reader), patch.object(
                        quality.consumer,'read_private_evidence',return_value=raw) as fetch:
                    with patch.dict(runs[a],status='in_progress',conclusion=None):
                        result = quality.verify_reuse_dispatch(env,terminal=False,clock=lambda:2020)
                        self.assertEqual(result['receipt_sha256'],request['receipt_sha256'])
                    with patch.dict(env,GITHUB_RUN_ID=str(b)), patch.dict(runs[b],status='in_progress',conclusion=None):
                        self.assertEqual(quality.verify_reuse_dispatch(env,terminal=True,clock=lambda:2020),request)
                    fetch.reset_mock()
                    with patch.dict(env,GITHUB_RUN_ID='100'), self.assertRaises(ValueError):
                        quality.verify_reuse_dispatch(env,terminal=False,clock=lambda:2020)
                    fetch.assert_not_called()
            return

        def derive(terminal_run=200, *, active=False):
            return quality.verify_terminal_evidence(self.admission, bundle, self.reader, terminal_run,
                                                     hosted, 'c' * 40, 200, active=active)

        runs[200].update(status='in_progress', conclusion=None)
        self.assertEqual(200, derive(active=True)['terminal_run'])
        with self.assertRaisesRegex(ValueError, 'reviewed workflow did not pass'):
            derive()
        runs[200].update(status='completed', conclusion='success')
        request = derive()
        with self.assertRaisesRegex(ValueError, 'independently reviewed workflow'):
            derive(100)
        self.assertNotIn('quality', request)
        self.reader.gate_value.update(name='Box formal quality result', output={'text': json.dumps(request)},
                                      external_id=quality.consumer.digest(request))
        if v4:
            self.assertEqual((190, 1990, 10900), (request['release_not_before'], request['release_expires_at'],
                                                 request['expires_at']))
            self.reader.gate_value.update(started_at=stamp(19), completed_at=stamp(20))
        self.reader.formal_quality_check = lambda sha: self.reader.check(43)
        self.assertEqual(request, quality.verify_public_terminal(self.environment, self.reader, clock=lambda: 200))
        missing_digest = {key: value for key, value in request.items() if key != 'quality_sha256'}
        original_gate = self.reader.gate_value.copy()
        self.reader.gate_value.update(output={'text': json.dumps(missing_digest)},
                                      external_id=quality.consumer.digest(missing_digest))
        with self.assertRaisesRegex(ValueError, 'independent terminal quality proof'):
            quality.verify_public_terminal(self.environment, self.reader, clock=lambda: 200)
        self.reader.gate_value = original_gate
        for row, key, bad in (
            (runs[100], 'run_attempt', 2), (runs[200], 'triggering_actor', {'id': 3104616}),
            (runs[200], 'display_title', 'Formal terminal ' + 'f' * 64),
            (approvals[200][0], 'user', {'id': 999}), (approvals[100][0], 'state', 'rejected'),
            (jobs[100][0]['steps'][0], 'conclusion', 'skipped'),
            (jobs[300][-1], 'conclusion', 'failure'),
        ):
            old = row[key]
            row[key] = bad
            with self.subTest(field=key, value=bad), self.assertRaises(ValueError):
                quality.verify_public_terminal(self.environment, self.reader, clock=lambda: 200)
            row[key] = old

        if v4:
            # GitHub brackets each approval between native run creation and the protected job completion.
            for row, key, bad in (
                (runs[100], 'created_at', stamp(9)), (runs[100], 'created_at', None),
                (runs[200], 'created_at', stamp(14)), (jobs[100][0], 'completed_at', stamp(11)),
                (runs[200], 'updated_at', stamp(21)), (jobs[200][0], 'completed_at', stamp(21)), (self.reader.gate_value, 'started_at', stamp(17)),
                (self.reader.check_value, 'completed_at', stamp(16)),
            ):
                with self.subTest(field=key, value=bad), patch.dict(row, {key: bad}), self.assertRaises(ValueError):
                    quality.verify_public_terminal(self.environment, self.reader, clock=lambda: 200)
            with self.assertRaisesRegex(ValueError, 'expired'):
                quality.verify_public_terminal(self.environment, self.reader, clock=lambda: 1991)

        http = MockHTTP(self.reader)
        publisher = quality.GitHubPublication(http.app_get, http.installation_request, clock=lambda: 200)
        with tempfile.TemporaryDirectory() as tmp:
            journal = quality.AdmissionJournal(str(Path(tmp) / 'journal.sqlite'))

            def publish():
                return formal_evidence_publisher.publish_terminal(
                    self.admission, bundle, self.reader, publisher, journal, 'OFFLINE-APP',
                    200, hosted, 'c' * 40, policy=quality, clock=lambda: 200)

            real_completion = formal_evidence_publisher.complete_terminal_check

            def complete(check_id, request, token, reader, *, policy, clock):
                self.assertEqual(check_id, journal.pending(request))
                self.assertEqual('in_progress', reader.check(check_id)['status'])
                if v4:
                    def signed_response(update, timeout):
                        self.assertEqual(update.get_method(), 'PATCH')
                        self.assertTrue(update.full_url.endswith('/check-runs/43'))
                        payload = json.loads(update.data)
                        self.assertEqual(stamp(20), payload['completed_at'])
                        self.assertNotIn('started_at', payload)
                        reader.gate_value.update(payload)
                        return io.BytesIO(json.dumps(reader.check(check_id)).encode())
                    with patch.object(formal_evidence_publisher.urllib.request, 'build_opener') as transport:
                        transport.return_value.open.side_effect = signed_response
                        return real_completion(check_id, request, token, reader, policy=policy, clock=clock)
                http.finish_fixture()
                return reader.check(check_id)

            with patch.object(formal_evidence_publisher, 'complete_terminal_check', side_effect=complete) as signer:
                runs[200].update(status='in_progress', conclusion=None)
                with self.assertRaisesRegex(ValueError, 'reviewed workflow did not pass'):
                    publish()
                signer.assert_not_called()
                self.assertEqual([], http.posts)
                runs[200].update(status='completed', conclusion='success')
                self.assertEqual(43, publish())
                signer.assert_called_once()
                with self.assertRaises(sqlite3.IntegrityError):
                    publish()
                self.assertEqual(1, len(http.posts))

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
        self.assertNotIn('environment:', gate)
        self.assertIn('ref: ${{ vars.BOX_FORMAL_READER_SHA }}', gate)
        self.assertNotIn('BOX_FORMAL_ADMISSION', gate)
        self.assertNotIn('secrets.', gate)
        self.assertIn('EXPECTED_SHA: ${{ needs.premerge.outputs.sha }}', gate)
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
        self.assertEqual('python3 -I -B trusted-quality/scripts/ci/quality_results.py public-terminal',
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
                self.assertEqual('-I -B trusted-quality/scripts/ci/quality_results.py public-terminal\n',
                                 calls.read_text())
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
                             GITHUB_REPOSITORY=quality.REPOSITORY, GITHUB_REPOSITORY_ID='123',
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
        self.assertIn('  workflow_dispatch:\n', workflow)
        for name in ('pull_number', 'sha', 'base_sha'):
            self.assertIn('      ' + name + ':\n', workflow.split('  workflow_call:', 1)[0])
        gate = workflow.split('  quality-gate:\n', 1)[1]
        self.assertIn('needs: [premerge, backend, frontend, database]', gate)
        self.assertIn('if: always()', gate)
        for name in ('backend', 'frontend', 'database'):
            job = workflow.split('  ' + name + ':\n', 1)[1]
            job = re.split(r'^  [a-zA-Z][\w-]*:\n', job, maxsplit=1, flags=re.MULTILINE)[0]
            self.assertIn('needs: premerge', job)
            self.assertIn('repository: ${{ needs.premerge.outputs.repository }}', job)
            self.assertIn('ref: ${{ needs.premerge.outputs.sha }}', job)
        premerge = workflow.split('  premerge:\n', 1)[1].split('  backend:\n', 1)[0]
        block = re.search(r'        run: \|\n((?:          .*\n)+)', premerge)
        self.assertIsNotNone(block)
        script = textwrap.dedent(block.group(1))
        self.assertIn('python3 -I -B scripts/ci/quality_results.py premerge', script)
        self.assertIn('persist-credentials: false', premerge)
        # Actual shell + JSON output stage; Python transport is exercised by
        # the real main() fixtures below. This shim is NOT Actions execution.
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'output'
            shim = Path(tmp) / 'python3'
            shim.write_text('#!' + sys.executable + '\nimport sys, os, json\n'
                'if sys.argv[-1] == "premerge":\n'
                ' print(json.dumps(dict(sha="a"*40, repository="fixture-fork/new-api")))\n'
                ' sys.exit(int(os.environ["MOCK_EXIT"]))\n'
                'os.execv(sys.executable, [sys.executable]+sys.argv[1:])\n')
            shim.chmod(0o700)
            for code in (0, 7):
                if output.exists():
                    output.unlink()
                child = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script],
                    env=dict(PATH=tmp + ':/usr/bin:/bin', RUNNER_TEMP=tmp,
                             GITHUB_OUTPUT=str(output), MOCK_EXIT=str(code)),
                    capture_output=True, text=True, timeout=5)
                self.assertEqual(code, child.returncode, child.stderr)
                self.assertEqual(code == 0, output.exists())
                if code == 0:
                    self.assertEqual('sha=' + 'a' * 40 + '\nrepository=fixture-fork/new-api\n', output.read_text())

    def dispatch_fixture(self, *, head_id=456, name='fixture-fork/new-api'):
        """Inert dispatch event, never a synthesized pull_request event."""
        self.event = dict(repository=dict(id=123, full_name=quality.REPOSITORY),
            inputs=dict(pull_number='1', sha='a' * 40, base_sha='b' * 40))
        self.environment.update(GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_REF='refs/heads/reviewed',
            GITHUB_SHA='a' * 40, GITHUB_WORKFLOW_SHA='a' * 40,
            GITHUB_WORKFLOW_REF=quality.REPOSITORY + '/.github/workflows/ci.yml@refs/heads/reviewed')
        self.reader.pr['head']['repo'] = dict(id=head_id, full_name=name)
        self.admission['quality']['head_repository_id'] = head_id
        self.receipt['quality']['head_repository_id'] = head_id
        self.admission['receipt_sha256'] = quality.consumer.digest(self.receipt)
        self.reader.check_value.update(external_id=self.admission['receipt_sha256'],
                                      output={'text': json.dumps(self.receipt)})
        gate = json.loads(self.reader.gate_value['output']['text'])
        gate.update(quality=copy.deepcopy(self.admission['quality']),
                    receipt_sha256=self.admission['receipt_sha256'])
        self.reader.gate_value.update(external_id=quality.consumer.digest(gate),
                                      output={'text': json.dumps(gate)})
        self.event_path.write_text(json.dumps(self.event))

    def test_dispatch_actual_entries_accept_current_same_repo_and_fork(self):
        for head_id, name in ((123, quality.REPOSITORY), (456, 'fixture-fork/new-api')):
            with self.subTest(head_id=head_id):
                self.setUp()
                self.dispatch_fixture(head_id=head_id, name=name)
                trace = []
                watch = CIEnvironmentWatch(dict(self.environment, GITHUB_TOKEN='OFFLINE-NOT-A-CREDENTIAL'),
                                           trace, block_admission=True)
                output = io.StringIO()
                with patch.object(quality.os, 'environ', watch), \
                        patch.object(sys, 'argv', ['quality_results.py', 'premerge']), \
                        patch.object(quality, 'GitHubReader', return_value=self.reader), \
                        patch.object(quality.consumer, 'api', side_effect=AssertionError('no network')), \
                        redirect_stdout(output):
                    quality.main()
                self.assertEqual(dict(sha='a' * 40, repository=name), json.loads(output.getvalue()))
                self.assertFalse(any(key == 'BOX_FORMAL_ADMISSION' for _, key in trace))
                self.reader.reads = 0
                self.observe_ci_input_main('dispatch-' + name, 'VALID')

    def test_dispatch_native_rejections_precede_admission_and_token(self):
        mutations = ('native-repo', 'native-id', 'root-id', 'root-name', 'root-bool-id',
            'missing-input', 'extra-input', 'number-bool', 'number-zero', 'number-leading-zero',
            'sha-type', 'sha-syntax', 'base-type', 'expected-sha', 'workflow-sha', 'ref-sha',
            'tag', 'publication-caller', 'forged-pr', 'duplicate-input')
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.setUp()
                self.dispatch_fixture()
                text = None
                if mutation == 'native-repo':
                    self.environment['GITHUB_REPOSITORY'] = 'untrusted/new-api'
                elif mutation == 'native-id':
                    self.environment['GITHUB_REPOSITORY_ID'] = '0123'
                elif mutation in ('root-id', 'root-bool-id', 'root-name'):
                    self.event['repository']['full_name' if mutation == 'root-name' else 'id'] = (
                        'untrusted/new-api' if mutation == 'root-name' else True if mutation == 'root-bool-id' else 999)
                elif mutation == 'missing-input':
                    del self.event['inputs']['base_sha']
                elif mutation == 'extra-input':
                    self.event['inputs']['head_repository_id'] = '456'
                elif mutation.startswith('number-'):
                    self.event['inputs']['pull_number'] = {'number-bool': True,
                        'number-zero': '0', 'number-leading-zero': '01'}[mutation]
                elif mutation in ('sha-type', 'sha-syntax', 'base-type'):
                    self.event['inputs']['base_sha' if mutation == 'base-type' else 'sha'] = (
                        'not-a-sha' if mutation == 'sha-syntax' else True)
                elif mutation in ('expected-sha', 'workflow-sha', 'ref-sha'):
                    key = {'expected-sha': 'EXPECTED_SHA', 'workflow-sha': 'GITHUB_WORKFLOW_SHA',
                           'ref-sha': 'GITHUB_SHA'}[mutation]
                    self.environment[key] = 'd' * 40
                elif mutation == 'tag':
                    self.environment['GITHUB_REF'] = 'refs/tags/v1'
                elif mutation == 'publication-caller':
                    self.environment['GITHUB_WORKFLOW_REF'] = quality.REPOSITORY + '/.github/workflows/release.yml@refs/heads/reviewed'
                elif mutation == 'forged-pr':
                    self.event['pull_request'] = {}
                else:
                    text = json.dumps(self.event).replace('"pull_number": "1"', '"pull_number": "1", "pull_number": "2"')
                self.observe_ci_input_main(mutation, 'NATIVE', event_text=text)
                # The same native validator fronts hosted preflight, before its
                # token access as well; no admission exists in that operation.
                trace = []
                watch = CIEnvironmentWatch(self.environment, trace, block_admission=True, block_token=True)
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    quality.resolve_ci_candidate(watch)
                self.assertFalse(any(key in ('GITHUB_TOKEN', 'BOX_FORMAL_ADMISSION') for _, key in trace))

    def test_dispatch_admission_binding_rejections_precede_token(self):
        for mutation in ('repository', 'repository-id', 'pull', 'head', 'base', 'attempt'):
            with self.subTest(mutation=mutation):
                self.setUp()
                self.dispatch_fixture()
                if mutation == 'repository':
                    self.admission['repository'] = 'untrusted/new-api'
                elif mutation == 'repository-id':
                    self.admission['repository_id'] = 999
                elif mutation == 'pull':
                    self.admission['quality']['pull_number'] = 2
                elif mutation in ('head', 'base'):
                    self.event['inputs']['sha' if mutation == 'head' else 'base_sha'] = 'd' * 40
                    if mutation == 'head':
                        self.environment.update(EXPECTED_SHA='d' * 40, GITHUB_SHA='d' * 40,
                                                GITHUB_WORKFLOW_SHA='d' * 40)
                else:
                    self.admission['quality']['attempt_id'] = 'replayed-attempt'
                self.observe_ci_input_main(mutation, 'ADMISSION_BINDING')

    def test_dispatch_preflight_rejects_authenticated_pr_drift(self):
        for mutation in ('number', 'closed', 'merged', 'head', 'base', 'target', 'head-repo', 'repo'):
            with self.subTest(mutation=mutation):
                self.setUp()
                self.dispatch_fixture()
                if mutation == 'number':
                    self.reader.pr['number'] = 2
                elif mutation == 'closed':
                    self.reader.pr['state'] = 'closed'
                elif mutation == 'merged':
                    self.reader.pr['merged'] = True
                elif mutation in ('head', 'base'):
                    self.reader.pr[mutation]['sha'] = 'd' * 40
                elif mutation == 'target':
                    self.reader.pr['base']['ref'] = 'untrusted'
                elif mutation == 'head-repo':
                    self.reader.pr['head']['repo']['full_name'] = 'unsafe\noutput=forged'
                else:
                    self.reader.repo['id'] = 999
                with self.assertRaises(ValueError):
                    quality.resolve_ci_candidate(self.environment, self.reader)

    def test_dispatch_final_gate_retains_real_evidence_failure_conditions(self):
        for mutation in ('closed', 'head', 'base', 'head-id', 'missing-app', 'wrong-app',
                         'hosted-failed', 'hosted-skipped', 'replay', 'expiry', 'reviewer', 'final-drift'):
            with self.subTest(mutation=mutation):
                self.setUp()
                self.dispatch_fixture()
                if mutation == 'closed':
                    self.reader.pr.update(state='closed', merged=True)
                elif mutation in ('head', 'base'):
                    self.reader.pr[mutation]['sha'] = 'd' * 40
                elif mutation == 'head-id':
                    self.reader.pr['head']['repo']['id'] = 999
                elif mutation == 'missing-app':
                    self.reader.check_value = {}  # No receipt/check envelope exists.
                elif mutation == 'wrong-app':
                    self.reader.gate_value['app']['id'] = 1
                elif mutation.startswith('hosted-'):
                    self.environment['QUALITY_RESULTS'] = json.dumps(dict(backend=
                        'failure' if mutation == 'hosted-failed' else 'skipped', frontend='success', database='success'))
                elif mutation == 'replay':
                    self.latest['run_attempt'] = 2
                elif mutation == 'reviewer':
                    self.reviews[0]['user']['id'] = 999
                elif mutation == 'final-drift':
                    self.reader.on_pull = lambda reader: reader.pr['head'].update(
                        sha='d' * 40 if reader.reads > 1 else 'a' * 40)
                output = io.StringIO()
                original = quality.verify_ci_result
                with patch.dict(os.environ, dict(self.environment, GITHUB_TOKEN='OFFLINE-NOT-A-CREDENTIAL',
                        BOX_FORMAL_ADMISSION=json.dumps(self.admission)), clear=True), \
                        patch.object(sys, 'argv', ['quality_results.py', 'ci']), \
                        patch.object(quality, 'GitHubReader', return_value=self.reader), \
                        patch.object(quality, 'verify_ci_result', side_effect=lambda *args: original(
                            *args, clock=lambda: 301 if mutation == 'expiry' else 200)), \
                        self.assertRaises((ValueError, KeyError)), redirect_stdout(output):
                    quality.main()
                self.assertEqual('', output.getvalue())

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

    def observe_ci_input_main(self, case, phase, *, event_text=None, admission_text=None, omit_admission=False):
        """Actual main + real verifier; only reader transport and clock are MOCK."""
        self.event_path.write_text(json.dumps(self.event) if event_text is None else event_text)
        trace = []
        values = dict(self.environment, BOX_FORMAL_ADMISSION=json.dumps(self.admission),
                      GITHUB_TOKEN='OFFLINE-NOT-A-CREDENTIAL')
        if admission_text is not None:
            values['BOX_FORMAL_ADMISSION'] = admission_text
        if omit_admission:
            del values['BOX_FORMAL_ADMISSION']
        watch = CIEnvironmentWatch(values, trace, block_admission=phase == 'NATIVE',
                                    block_token=phase != 'VALID')
        output = io.StringIO()
        error = None
        original = quality.verify_ci_result
        methods = ('repository', 'pull', 'check', 'commit', 'run', 'latest_run', 'approvals')
        api = {name: getattr(self.reader, name) for name in methods}

        def construct(token):
            self.assertEqual('OFFLINE-NOT-A-CREDENTIAL', token)
            trace.append(('reader', 'construct'))
            return self.reader

        def read(name, *args):
            trace.append(('api', name))
            return api[name](*args)

        with ExitStack() as stack:
            stack.enter_context(patch.object(quality.os, 'environ', watch))
            stack.enter_context(patch.object(sys, 'argv', ['quality_results.py', 'ci']))
            stack.enter_context(patch.object(quality, 'GitHubReader', side_effect=construct))
            stack.enter_context(patch.object(quality, 'verify_ci_result',
                side_effect=lambda *args: original(*args, clock=lambda: 200)))
            stack.enter_context(patch.object(quality.consumer, 'api',
                side_effect=AssertionError('real network is forbidden in this fixture')))
            for name in methods:
                stack.enter_context(patch.object(self.reader, name,
                    side_effect=lambda *args, method=name: read(method, *args)))
            with redirect_stdout(output):
                try:
                    quality.main()
                except Exception as caught:
                    error = caught
        # No environment values or usable credentials are logged.
        print(json.dumps(dict(case=case, phase=phase, entry='actual main(argv=[quality_results.py,ci])',
            trace=trace, stdout=output.getvalue(), exception=type(error).__name__ if error else None,
            reason=str(error) if error else None,
            proof='OFFLINE MOCK App/API/approval; inert token; no network'), sort_keys=True))
        if phase == 'VALID':
            self.assertIsNone(error)
            self.assertEqual('a' * 40, json.loads(output.getvalue())['candidate_sha'])
            self.assertLess(trace.index(('index', 'BOX_FORMAL_ADMISSION')),
                            trace.index(('index', 'GITHUB_TOKEN')))
            self.assertLess(trace.index(('index', 'GITHUB_TOKEN')), trace.index(('reader', 'construct')))
            self.assertLess(trace.index(('reader', 'construct')), trace.index(('api', 'repository')))
            self.assertEqual(2, trace.count(('api', 'pull')))
        else:
            # Sentinel AssertionError is deliberately NOT an accepted rejection.
            self.assertIsInstance(error, (ValueError, KeyError, TypeError))
            self.assertEqual('', output.getvalue())
            self.assertFalse(any(key == 'GITHUB_TOKEN' or operation in ('reader', 'api')
                                 for operation, key in trace))
            admission_reads = [item for item in trace if item[1] == 'BOX_FORMAL_ADMISSION']
            self.assertEqual(phase == 'ADMISSION_BINDING', bool(admission_reads))
        return error

    def test_ci_input_contract_valid_same_repo_and_fork(self):
        for case, head_id, name, action in (
                ('same-repo', 123, '86669666/new-api', 'opened'),
                ('fork', 456, 'fixture-fork/new-api', 'reopened'),
                ('fork-display-omitted', 456, None, 'synchronize'),
                ('fork-display-renamed-no-local-name-authority', 456, 'another-display/new-api', 'synchronize')):
            with self.subTest(case=case):
                self.setUp()
                self.event['action'] = action
                self.event['pull_request']['head']['repo'] = dict(id=head_id)
                if name is not None:
                    self.event['pull_request']['head']['repo']['full_name'] = name
                self.admission['quality']['head_repository_id'] = head_id
                self.receipt['quality']['head_repository_id'] = head_id
                self.reader.pr['head']['repo'] = dict(id=head_id)
                # Refresh independently authored MOCK object hashes only.
                self.admission['receipt_sha256'] = quality.consumer.digest(self.receipt)
                self.reader.check_value.update(external_id=self.admission['receipt_sha256'],
                                               output={'text': json.dumps(self.receipt)})
                gate = json.loads(self.reader.gate_value['output']['text'])
                gate.update(quality=copy.deepcopy(self.admission['quality']),
                            receipt_sha256=self.admission['receipt_sha256'])
                self.reader.gate_value.update(external_id=quality.consumer.digest(gate),
                                              output={'text': json.dumps(gate)})
                self.environment['GITHUB_SHA'] = 'f' * 40  # Synthetic merge is NOT the PR head.
                self.observe_ci_input_main(case, 'VALID')

    def test_ci_input_contract_native_rejections_precede_admission(self):
        # Partition by mandatory absence, malformed type/shape and ownership
        # contradiction. No Cartesian product or unrelated authenticated tests.
        missing = [
            ('env', 'GITHUB_EVENT_NAME'),
            ('env', 'GITHUB_REPOSITORY'), ('env', 'GITHUB_REPOSITORY_ID'),
            ('env', 'GITHUB_REF'), ('env', 'GITHUB_EVENT_PATH'), ('env', 'EXPECTED_SHA'),
            ('event', 'repository'), ('event', 'repository.id'), ('event', 'repository.full_name'),
            ('event', 'action'), ('event', 'number'), ('event', 'pull_request'),
            ('event', 'pull_request.state'), ('event', 'pull_request.merged'), ('event', 'pull_request.number'),
            ('event', 'pull_request.head'), ('event', 'pull_request.head.repo'),
            ('event', 'pull_request.head.repo.id'), ('event', 'pull_request.head.sha'),
            ('event', 'pull_request.base'), ('event', 'pull_request.base.repo'),
            ('event', 'pull_request.base.repo.id'), ('event', 'pull_request.base.repo.full_name'),
            ('event', 'pull_request.base.ref'), ('event', 'pull_request.base.sha')]
        malformed = [
            ('env', 'GITHUB_REPOSITORY', False),
            ('env', 'GITHUB_REPOSITORY_ID', True), ('env', 'GITHUB_REPOSITORY_ID', 'abc'),
            ('env', 'GITHUB_REF', True), ('env', 'EXPECTED_SHA', True), ('env', 'EXPECTED_SHA', 'bad-sha'),
            ('event', 'repository', []), ('event', 'pull_request', []),
            ('event', 'pull_request.head', []), ('event', 'pull_request.base', []),
            ('event', 'pull_request.head.repo', None), ('event', 'pull_request.base.repo', []),
            ('event', 'repository.id', True), ('event', 'repository.id', '123'), ('event', 'repository.id', 0),
            ('event', 'pull_request.base.repo.id', True), ('event', 'pull_request.head.repo.id', True),
            ('event', 'pull_request.head.repo.id', 456.0), ('event', 'pull_request.head.repo.id', -1),
            ('event', 'number', True),
            ('event', 'pull_request.number', True), ('event', 'pull_request.head.repo.full_name', True),
            ('event', 'pull_request.head.repo.full_name', None),
            ('event', 'pull_request.head.repo.full_name', 'bad/name/shape'),
            ('event', 'pull_request.head.sha', True), ('event', 'pull_request.base.sha', 'bad-sha')]
        drift = [
            ('env', 'GITHUB_REPOSITORY', 'other/project'), ('env', 'GITHUB_REPOSITORY_ID', '999'),
            ('env', 'GITHUB_REF', 'refs/pull/2/merge'), ('env', 'EXPECTED_SHA', 'd' * 40),
            ('event', 'repository.id', 999), ('event', 'repository.full_name', 'other/project'),
            ('event', 'pull_request.base.repo.id', 999),
            ('event', 'pull_request.base.repo.full_name', 'other/project'),
            ('event', 'pull_request.head.repo.full_name', '86669666/new-api'),
            ('event', 'pull_request.head.repo.id', 123), ('event', 'pull_request.number', 2),
            ('event', 'pull_request.base.ref', 'another-branch'),
            ('event', 'pull_request.head.sha', 'd' * 40)]
        cases = [(owner, path, None, True) for owner, path in missing]
        cases += [(owner, path, value, False) for owner, path, value in malformed + drift]
        for index, (owner, path, value, remove) in enumerate(cases):
            case = f'native-{index}:{owner}.{path}:{"missing" if remove else "invalid"}'
            with self.subTest(case=case):
                self.setUp()
                target = self.environment if owner == 'env' else self.event
                parts = path.split('.')
                for part in parts[:-1]:
                    target = target[part]
                if remove:
                    del target[parts[-1]]
                    if path == 'EXPECTED_SHA':
                        self.environment['GITHUB_SHA'] = 'a' * 40  # No fallback, even when equal.
                else:
                    target[parts[-1]] = value
                self.observe_ci_input_main(case, 'NATIVE')
        for case, text in (('event-json-array', '[]'), ('event-json-null', 'null'),
                           ('event-json-malformed', '{'),
                           ('event-json-duplicate', None)):
            with self.subTest(case=case):
                self.setUp()
                if case.endswith('duplicate'):
                    text = '{"number":2,' + json.dumps(self.event)[1:]
                error = self.observe_ci_input_main(case, 'NATIVE', event_text=text)
                if case.endswith('duplicate'):
                    self.assertIn('duplicate receipt field', str(error))

    def test_ci_input_contract_admission_rejections_precede_token(self):
        missing = ['repository', 'repository_id', 'expected', 'quality', 'quality.pull_number',
            'quality.head_repository_id', 'quality.base_sha', 'expected.candidate_sha',
            'expected.candidate_tree', 'expected.execution_sha', 'expected.consumer_sha',
            'quality.candidate_sha', 'quality.candidate_tree', 'quality.execution_sha',
            'expected.admission_id', 'expected.attempt_id', 'expected.invocation',
            'quality.admission_id', 'quality.attempt_id', 'quality.invocation',
            'check_run_id', 'quality_check_run_id']
        invalid = [('repository', 'other/project'), ('repository_id', 999), ('repository_id', True),
            ('repository_id', '123'), ('expected', []), ('quality', []),
            ('quality.pull_number', True), ('quality.pull_number', 2),
            ('quality.head_repository_id', True), ('quality.head_repository_id', 999),
            ('quality.base_sha', 'd' * 40), ('expected.candidate_sha', 'd' * 40),
            ('expected.candidate_tree', 'bad-tree'), ('expected.execution_sha', 'd' * 40),
            ('quality.candidate_sha', 'd' * 40), ('quality.candidate_tree', 'd' * 40),
            ('quality.execution_sha', 'd' * 40), ('expected.consumer_sha', 'd' * 40),
            ('quality.admission_id', 'different'), ('quality.attempt_id', 'different'),
            ('quality.invocation', 'different'), ('check_run_id', True), ('quality_check_run_id', True)]
        cases = [(path, None, True) for path in missing] + [(path, value, False) for path, value in invalid]
        for index, (path, value, remove) in enumerate(cases):
            case = f'admission-{index}:{path}:{"missing" if remove else "invalid"}'
            with self.subTest(case=case):
                self.setUp()
                target = self.admission
                parts = path.split('.')
                for part in parts[:-1]:
                    target = target[part]
                if remove:
                    del target[parts[-1]]
                else:
                    target[parts[-1]] = value
                self.observe_ci_input_main(case, 'ADMISSION_BINDING')
        for case, text, omitted in (
                ('admission-json-array', '[]', False), ('admission-json-null', 'null', False),
                ('admission-json-malformed', '{', False),
                ('admission-json-duplicate', None, False),
                ('admission-env-missing', None, True)):
            with self.subTest(case=case):
                self.setUp()
                if case.endswith('duplicate'):
                    text = '{"repository_id":999,' + json.dumps(self.admission)[1:]
                error = self.observe_ci_input_main(case, 'ADMISSION_BINDING', admission_text=text, omit_admission=omitted)
                if case.endswith('duplicate'):
                    self.assertIn('duplicate receipt field', str(error))
        for case in ('event-base-sha', 'event-head-and-input', 'event-fork-id', 'consistent-native-id'):
            with self.subTest(case=case):
                self.setUp()
                if case == 'event-base-sha':
                    self.event['pull_request']['base']['sha'] = 'd' * 40
                elif case == 'event-head-and-input':
                    self.event['pull_request']['head']['sha'] = 'd' * 40
                    self.environment['EXPECTED_SHA'] = 'd' * 40
                elif case == 'event-fork-id':
                    self.event['pull_request']['head']['repo']['id'] = 999
                else:
                    # No fixed numeric ID is invented: the consistent native
                    # context can only be compared with admission after loading it.
                    self.event['repository']['id'] = 999
                    self.event['pull_request']['base']['repo']['id'] = 999
                    self.environment['GITHUB_REPOSITORY_ID'] = '999'
                self.observe_ci_input_main(case, 'ADMISSION_BINDING')

    def test_ci_input_contract_monitor_covers_index_get_and_getenv(self):
        for operation in ('index', 'get', 'getenv'):
            trace = []
            watch = CIEnvironmentWatch({'GITHUB_TOKEN': 'INERT'}, trace, block_token=True)
            with self.subTest(operation=operation), patch.object(quality.os, 'environ', watch):
                with self.assertRaisesRegex(AssertionError, 'credential accessed'):
                    if operation == 'index':
                        watch['GITHUB_TOKEN']
                    elif operation == 'get':
                        watch.get('GITHUB_TOKEN')
                    else:
                        os.getenv('GITHUB_TOKEN')
            self.assertEqual([('index' if operation == 'index' else 'get', 'GITHUB_TOKEN')], trace)


class StaticDeltaTests(unittest.TestCase):
    def setUp(self):
        self.delta = quality.static_delta
        self.ref = self.delta.make_reference(self.delta.descriptor(), 'a' * 40, 123, 2000, 'b' * 32)

    def test_reference_pins_candidate_and_window(self):
        for now in (2000, 3800):
            self.delta.validate_reference(self.ref, now)
        for now in (1999, 3801, 2000.0):
            with self.subTest(now=now), self.assertRaises(ValueError):
                self.delta.validate_reference(self.ref, now)
        for key, value in [('pull_number', 262), ('candidate_sha', 'c' * 40), ('base_sha', 'd' * 40),
                           ('candidate_tree', 'e' * 40), ('release_expires_at', 3801)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                ref = copy.deepcopy(self.ref)
                ref['identity'][key] = value
                self.delta.validate_reference(ref, 2000)
        with self.assertRaises(ValueError):
            ref = copy.deepcopy(self.ref)
            ref['artifact']['bytes'] = float(ref['artifact']['bytes'])
            self.delta.validate_reference(ref, 2000)

    def test_timed_publisher_uses_static_contract(self):
        result = self.delta.result(self.ref, 456, {'receipt_sha256': 'e' * 64})
        quality.validate_timed_artifact(result, 3800)
        self.assertEqual(result['scope'], 'static-route-delta')
        self.assertEqual(result['baseline']['pull_number'], 262)
        with self.assertRaises(ValueError):
            quality.validate_timed_artifact(result, 3801)
        with self.assertRaises(ValueError):
            self.delta.validate_package(quality, b'unpinned')

    def test_current_subject_requires_both_reviewed_parents(self):
        from unittest.mock import Mock

        delta = self.delta
        repo = {'id': 1423238398, 'full_name': '86669666/new-api'}
        reader = Mock()
        reader.repository.return_value = repo
        reader.pull.return_value = {'number': 261, 'state': 'open', 'merged': False, 'changed_files': 3,
            'head': {'repo': repo, 'ref': delta.BRANCH, 'sha': delta.HEAD},
            'base': {'repo': repo, 'ref': 'main', 'sha': delta.BASE}}
        parents = [{'sha': delta.PRIOR_HEAD}, {'sha': delta.BASE}]
        reader.commit.return_value = {'sha': delta.HEAD, 'tree': {'sha': delta.TREE}, 'parents': parents}
        with patch.object(quality, 'verify_hosted_jobs') as hosted:
            delta.current_subject(quality, reader, self.ref['identity'])
            hosted.assert_called_once_with(reader, delta.HOSTED, self.ref['identity'])
            hosted.reset_mock()
            for invalid in (parents[1:], parents[::-1]):
                reader.commit.return_value['parents'] = invalid
                with self.assertRaises(ValueError):
                    delta.current_subject(quality, reader, self.ref['identity'])
            hosted.assert_not_called()


class UsageDeltaTests(unittest.TestCase):
    def test_usage_reference_scope_timing_and_previous_schema(self):
        usage = quality.usage_delta
        reference = usage.make_reference(usage.descriptor(), 'a' * 40, 123, 2000, 'b' * 32)
        proof = usage.result(reference, 456, {'receipt_sha256': 'c' * 64})
        quality.validate_timed_artifact(proof, 3800)
        self.assertEqual(proof['scope'], 'personal-usage-series-delta')
        self.assertEqual(proof['baseline']['pull_number'], 261)
        for invalid_schema in (quality.TERMINAL_SCHEMA_V7, quality.TERMINAL_SCHEMA_V6):
            with self.subTest(invalid_schema=invalid_schema), self.assertRaises(ValueError):
                quality.validate_timed_artifact(dict(proof, schema=invalid_schema), 3800)
        with self.assertRaises(ValueError):
            quality.validate_timed_artifact(proof, 3801)

    def test_usage_reference_rejects_mutated_candidate_artifact_and_approval_run(self):
        usage = quality.usage_delta
        reference = usage.make_reference(usage.descriptor(), 'a' * 40, 123, 2000, 'b' * 32)
        for field, substitute in [('pull_number', 257), ('candidate_sha', 'd' * 40),
                                  ('candidate_tree', 'e' * 40), ('base_sha', 'f' * 40)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                malformed = copy.deepcopy(reference)
                malformed['identity'][field] = substitute
                usage.validate_reference(malformed, 2000)
        with self.assertRaises(ValueError):
            usage.validate_reference(dict(reference, artifact=dict(reference['artifact'], bytes=16476.0)), 2000)
        with self.assertRaises(ValueError):
            usage.validate_reference(dict(reference, consumer_run=True), 2000)
        with self.assertRaises(ValueError):
            usage.validate_package(quality, b'unpinned')


class InvitationDeltaTests(unittest.TestCase):
    def test_public_invitation_gate_reads_exact_scope_and_both_approvals(self):
        invitation = quality.invitation_delta
        reference = invitation.make_reference(invitation.descriptor(), 'a' * 40, 123, 2000, 'b' * 32)
        baseline = {'receipt_sha256': 'c' * 64}
        result = invitation.result(reference, 456, baseline)
        check = {'id': 789, 'started_at': '1970-01-01T00:42:00Z', 'output': {'text': json.dumps(result)}}
        reader = Mock()
        reader.formal_quality_check.return_value = check
        event = {'number': 257, 'pull_request': {'head': {'sha': invitation.HEAD}}}
        environment = {'GITHUB_EVENT_NAME': 'pull_request', 'GITHUB_RUN_ID': str(invitation.HOSTED['run_id'])}
        with ExitStack() as stack:
            for name in ('validate_ci_evidence_reference', 'validate_gate', 'resolve_ci_candidate'):
                stack.enter_context(patch.object(quality, name))
            stack.enter_context(patch.object(quality, 'ci_premerge_event', return_value=event))
            stack.enter_context(patch.object(quality.consumer.evidence, 'check_times'))
            stack.enter_context(patch.object(invitation, 'historical_baseline', return_value=baseline))
            stack.enter_context(patch.object(invitation, 'current_subject'))
            reviewed = stack.enter_context(patch.object(invitation, 'verify_approvals', return_value=2519))
            self.assertEqual(quality.verify_public_terminal(environment, reader, clock=lambda: 2600), result)
            reviewed.assert_called_once_with(quality, reader, reference, 456, 2600)
            check['output']['text'] = json.dumps(dict(result, scope='personal-usage-series-delta'))
            with self.assertRaisesRegex(ValueError, 'differs from exact scope'):
                quality.verify_public_terminal(environment, reader, clock=lambda: 2600)

    def test_invitation_reference_scope_timing_and_previous_schema(self):
        invitation = quality.invitation_delta
        reference = invitation.make_reference(invitation.descriptor(), 'a' * 40, 123, 2000, 'b' * 32)
        proof = invitation.result(reference, 456, {'receipt_sha256': 'c' * 64})
        quality.validate_timed_artifact(proof, 3800)
        self.assertEqual(proof['scope'], 'organization-invitation-ui-delta')
        self.assertEqual(proof['baseline']['pull_number'], 256)
        for invalid_schema in (quality.TERMINAL_SCHEMA_V8, quality.TERMINAL_SCHEMA_V7):
            with self.subTest(invalid_schema=invalid_schema), self.assertRaises(ValueError):
                quality.validate_timed_artifact(dict(proof, schema=invalid_schema), 3800)
        with self.assertRaises(ValueError):
            quality.validate_timed_artifact(proof, 3801)

    def test_invitation_reference_rejects_mutated_candidate_artifact_and_approval_run(self):
        invitation = quality.invitation_delta
        reference = invitation.make_reference(invitation.descriptor(), 'a' * 40, 123, 2000, 'b' * 32)
        for field, substitute in [('pull_number', 256), ('candidate_sha', 'd' * 40),
                                  ('candidate_tree', 'e' * 40), ('base_sha', 'f' * 40)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                malformed = copy.deepcopy(reference)
                malformed['identity'][field] = substitute
                invitation.validate_reference(malformed, 2000)
        with self.assertRaises(ValueError):
            invitation.validate_reference(dict(reference, artifact=dict(reference['artifact'], bytes=38074.0)), 2000)
        with self.assertRaises(ValueError):
            invitation.validate_reference(dict(reference, consumer_run=True), 2000)
        with self.assertRaises(ValueError):
            invitation.validate_package(quality, b'unpinned')


class OAuthDeltaTests(unittest.TestCase):
    def test_public_oauth_gate_reads_exact_scope_and_both_approvals(self):
        oauth = quality.oauth_delta
        reference = oauth.make_reference(oauth.descriptor(), 'a' * 40, 123, 2000, 'b' * 32)
        baseline = {'receipt_sha256': 'c' * 64}
        result = oauth.result(reference, 456, baseline)
        check = {'id': 789, 'started_at': '1970-01-01T00:42:00Z', 'output': {'text': json.dumps(result)}}
        reader = Mock()
        reader.formal_quality_check.return_value = check
        event = {'number': 254, 'pull_request': {'head': {'sha': oauth.HEAD}}}
        environment = {'GITHUB_EVENT_NAME': 'pull_request', 'GITHUB_RUN_ID': str(oauth.HOSTED['run_id'])}
        with ExitStack() as stack:
            for name in ('validate_ci_evidence_reference', 'validate_gate', 'resolve_ci_candidate'):
                stack.enter_context(patch.object(quality, name))
            stack.enter_context(patch.object(quality, 'ci_premerge_event', return_value=event))
            stack.enter_context(patch.object(quality.consumer.evidence, 'check_times'))
            stack.enter_context(patch.object(oauth, 'historical_baseline', return_value=baseline))
            stack.enter_context(patch.object(oauth, 'current_subject'))
            reviewed = stack.enter_context(patch.object(oauth, 'verify_approvals', return_value=2519))
            self.assertEqual(quality.verify_public_terminal(environment, reader, clock=lambda: 2600), result)
            reviewed.assert_called_once_with(quality, reader, reference, 456, 2600)
            check['output']['text'] = json.dumps(dict(result, scope='personal-usage-series-delta'))
            with self.assertRaisesRegex(ValueError, 'differs from exact scope'):
                quality.verify_public_terminal(environment, reader, clock=lambda: 2600)

    def test_oauth_reference_scope_timing_and_previous_schema(self):
        oauth = quality.oauth_delta
        reference = oauth.make_reference(oauth.descriptor(), 'a' * 40, 123, 2000, 'b' * 32)
        proof = oauth.result(reference, 456, {'receipt_sha256': 'c' * 64})
        quality.validate_timed_artifact(proof, 3800)
        self.assertEqual(proof['scope'], 'oauth-application-revocation-readiness')
        self.assertEqual(proof['baseline']['pull_number'], 257)
        for invalid_schema in (quality.TERMINAL_SCHEMA_V9, quality.TERMINAL_SCHEMA_V8):
            with self.subTest(invalid_schema=invalid_schema), self.assertRaises(ValueError):
                quality.validate_timed_artifact(dict(proof, schema=invalid_schema), 3800)
        with self.assertRaises(ValueError):
            quality.validate_timed_artifact(proof, 3801)

    def test_oauth_reference_rejects_mutated_candidate_artifact_and_approval_run(self):
        oauth = quality.oauth_delta
        reference = oauth.make_reference(oauth.descriptor(), 'a' * 40, 123, 2000, 'b' * 32)
        for field, substitute in [('pull_number', 257), ('candidate_sha', 'd' * 40),
                                  ('candidate_tree', 'e' * 40), ('base_sha', 'f' * 40)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                malformed = copy.deepcopy(reference)
                malformed['identity'][field] = substitute
                oauth.validate_reference(malformed, 2000)
        with self.assertRaises(ValueError):
            oauth.validate_reference(dict(reference, artifact=dict(reference['artifact'], bytes=9983.0)), 2000)
        with self.assertRaises(ValueError):
            oauth.validate_reference(dict(reference, consumer_run=True), 2000)
        with self.assertRaises(ValueError):
            oauth.validate_package(quality, b'unpinned')


class ClientEventsDeltaTests(unittest.TestCase):
    def test_public_client_events_gate_reads_exact_scope_and_both_approvals(self):
        client_events = quality.client_events_delta
        reference = client_events.make_reference(client_events.descriptor(), 'a' * 40, 123, 2000, 'b' * 32)
        baseline = {'receipt_sha256': 'c' * 64}
        result = client_events.result(reference, 456, baseline)
        check = {'id': 789, 'started_at': '1970-01-01T00:42:00Z', 'output': {'text': json.dumps(result)}}
        reader = Mock()
        reader.formal_quality_check.return_value = check
        event = {'number': 260, 'pull_request': {'head': {'sha': client_events.HEAD}}}
        environment = {'GITHUB_EVENT_NAME': 'pull_request', 'GITHUB_RUN_ID': str(client_events.HOSTED['run_id'])}
        with ExitStack() as stack:
            for name in ('validate_ci_evidence_reference', 'validate_gate', 'resolve_ci_candidate'):
                stack.enter_context(patch.object(quality, name))
            stack.enter_context(patch.object(quality, 'ci_premerge_event', return_value=event))
            stack.enter_context(patch.object(quality.consumer.evidence, 'check_times'))
            stack.enter_context(patch.object(client_events, 'historical_baseline', return_value=baseline))
            stack.enter_context(patch.object(client_events, 'current_subject'))
            reviewed = stack.enter_context(patch.object(client_events, 'verify_approvals', return_value=2519))
            self.assertEqual(quality.verify_public_terminal(environment, reader, clock=lambda: 2600), result)
            reviewed.assert_called_once_with(quality, reader, reference, 456, 2600)
            check['output']['text'] = json.dumps(dict(result, scope='personal-usage-series-delta'))
            with self.assertRaisesRegex(ValueError, 'differs from exact scope'):
                quality.verify_public_terminal(environment, reader, clock=lambda: 2600)

    def test_client_events_reference_scope_timing_and_previous_schema(self):
        client_events = quality.client_events_delta
        reference = client_events.make_reference(client_events.descriptor(), 'a' * 40, 123, 2000, 'b' * 32)
        proof = client_events.result(reference, 456, {'receipt_sha256': 'c' * 64})
        quality.validate_timed_artifact(proof, 3800)
        self.assertEqual(proof['scope'], 'anonymous-client-events-intake-and-settings')
        self.assertEqual(proof['baseline']['pull_number'], 254)
        for invalid_schema in (quality.TERMINAL_SCHEMA_V10, quality.TERMINAL_SCHEMA_V9):
            with self.subTest(invalid_schema=invalid_schema), self.assertRaises(ValueError):
                quality.validate_timed_artifact(dict(proof, schema=invalid_schema), 3800)
        with self.assertRaises(ValueError):
            quality.validate_timed_artifact(proof, 3801)

    def test_client_events_reference_rejects_mutated_candidate_artifact_and_approval_run(self):
        client_events = quality.client_events_delta
        reference = client_events.make_reference(client_events.descriptor(), 'a' * 40, 123, 2000, 'b' * 32)
        for field, substitute in [('pull_number', 254), ('candidate_sha', 'd' * 40),
                                  ('candidate_tree', 'e' * 40), ('base_sha', 'f' * 40)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                malformed = copy.deepcopy(reference)
                malformed['identity'][field] = substitute
                client_events.validate_reference(malformed, 2000)
        with self.assertRaises(ValueError):
            client_events.validate_reference(dict(reference, artifact=dict(reference['artifact'], bytes=190015.0)), 2000)
        with self.assertRaises(ValueError):
            client_events.validate_reference(dict(reference, consumer_run=True), 2000)
        with self.assertRaises(ValueError):
            client_events.validate_package(quality, b'unpinned')


if __name__ == '__main__':
    unittest.main()
