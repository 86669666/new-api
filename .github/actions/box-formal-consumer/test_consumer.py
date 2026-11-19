import copy
import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
import consumer
from consumer import APP, INSTALLATION, REPOSITORY, CHECK, PINS, digest, validate_check, validate_receipt, validate_environment


# Fixed policy inventory from the execution contract, independent of admission.
FORMAL_TIERS = ('postgres', 'postgres-redis', 'wallet-sqlite', 'wallet-mysql',
                'wallet-postgres', 'lifecycle-sqlite', 'lifecycle-mysql',
                'lifecycle-postgres', 'sqlite')


def fixture():
    binding = dict.fromkeys(('candidate_sha', 'candidate_tree', 'execution_sha', 'consumer_sha'), 'a' * 40)
    binding.update(dict.fromkeys(('runner_sha256', 'wrapper_sha256', 'producer_sha256',
        'source_manifest_sha256', 'assets_sha256', 'toolchain_sha256', 'module_sha256',
        'manifest_sha256'), 'b' * 64))
    binding.update(images=PINS.copy(), platform='linux/amd64', attempt_id='attempt-1', admission_id='root-1',
        invocation='nonce-1', test_binaries={'test-0': 'c' * 64}, not_before=100, expires_at=300,
        tiers={name: {'entries': [{'binary': 'test-0', 'cwd': 'router', 'run': '.'}],
                      'required_leaves': [], 'manifest_sha256': 'd' * 64}
               for name in FORMAL_TIERS})
    receipt = {'binding': binding, 'started_at': 110, 'completed_at': 190, 'process_exit': 0,
               'exit': 0, 'cleanup': True, 'unexecuted': [], 'tiers': [dict(
                   tier=name, exit=0, cleanup=True, invocation='nonce-1',
                   log_sha256='e' * 64, **binding['tiers'][name]) for name in FORMAL_TIERS]}
    admission = dict(repository=REPOSITORY, repository_id=123, active=True, app_id=APP,
                     installation_id=INSTALLATION, expected=copy.deepcopy(binding),
                     check_run_id=42, receipt_sha256=digest(receipt))
    check = dict(id=42, name=CHECK, head_sha='a' * 40, app={'id': APP, 'slug': 'new-api-box-formal'},
                 status='completed', conclusion='success', external_id=digest(receipt),
                 output={'text': json.dumps(receipt)})
    return receipt, admission, check


class ReceiptTests(unittest.TestCase):
    def test_protected_environment_binding_before_network(self):
        _, admission, _ = fixture()
        environment = dict(GITHUB_REPOSITORY=REPOSITORY, GITHUB_EVENT_NAME='workflow_dispatch',
                           GITHUB_REF='refs/heads/main', BOX_FORMAL_CONSUMER_SHA='a' * 40,
                           GITHUB_WORKFLOW_SHA='a' * 40)
        validate_environment(environment, admission, 200)
        for key, value in [('GITHUB_REF', 'refs/heads/candidate'),
                           ('GITHUB_EVENT_NAME', 'pull_request'),
                           ('BOX_FORMAL_CONSUMER_SHA', 'main'),
                           ('GITHUB_WORKFLOW_SHA', 'f' * 40)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_environment(dict(environment, **{key: value}), admission, 200)
        for key, value in [('active', False), ('check_run_id', 0), ('receipt_sha256', '')]:
            with self.subTest(admission=key), self.assertRaises(ValueError):
                validate_environment(environment, dict(admission, **{key: value}), 200)
        with self.assertRaises(ValueError):
            validate_environment(environment, admission, 301)

    def test_boolean_exit_codes_and_non_integer_times_are_not_process_evidence(self):
        for field, value in [('process_exit', False), ('exit', False), ('started_at', 110.0),
                             ('completed_at', True)]:
            receipt, admission, _ = fixture()
            receipt[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_receipt(receipt, admission, 200)
        receipt, admission, _ = fixture()
        receipt['tiers'][0]['exit'] = False
        with self.assertRaises(ValueError):
            validate_receipt(receipt, admission, 200)
        for check_id in (0, -1, True):
            receipt, admission, check = fixture()
            admission['check_run_id'] = check['id'] = check_id
            with self.subTest(check_id=check_id), self.assertRaises(ValueError):
                validate_check(check, receipt, admission, 200)

    def test_exact_authenticated_receipt(self):
        receipt, admission, check = fixture()
        self.assertEqual(digest(receipt), validate_check(check, receipt, admission, 200))

    def test_missing_partial_failed_and_tampered_receipts(self):
        cases = [('missing', lambda r: r.pop('tiers')),
                 ('partial', lambda r: r.update(tiers=[])),
                 ('duplicate', lambda r: r['tiers'].append(copy.deepcopy(r['tiers'][0]))),
                 ('failed', lambda r: r.update(process_exit=1)),
                 ('unexecuted', lambda r: r.update(unexecuted=['postgres'])),
                 ('cleanup', lambda r: r.update(cleanup=False)),
                 ('tier-failed', lambda r: r['tiers'][0].update(exit=1)),
                 ('leaves', lambda r: r['tiers'][0].update(required_leaves=['wrong'])),
                 ('manifest', lambda r: r['tiers'][0].update(manifest_sha256='f' * 64)),
                 ('tier-replay', lambda r: r['tiers'][0].update(invocation='old'))]
        for label, change in cases:
            with self.subTest(label=label):
                receipt, admission, _ = fixture()
                change(receipt)
                with self.assertRaises((ValueError, KeyError)):
                    validate_receipt(receipt, admission, 200)

    def test_identity_freshness_and_replay(self):
        for key in ('candidate_sha', 'candidate_tree', 'attempt_id', 'runner_sha256', 'producer_sha256',
                    'source_manifest_sha256', 'assets_sha256', 'toolchain_sha256', 'module_sha256'):
            with self.subTest(binding=key):
                receipt, admission, _ = fixture()
                receipt['binding'][key] = 'wrong'
                with self.assertRaises(ValueError):
                    validate_receipt(receipt, admission, 200)
        for now in (99, 301):
            receipt, admission, _ = fixture()
            with self.subTest(now=now), self.assertRaises(ValueError):
                validate_receipt(receipt, admission, now)
        receipt, admission, _ = fixture()
        admission['active'] = False
        with self.assertRaises(ValueError):
            validate_receipt(receipt, admission, 200)

    def test_binding_requires_exact_json_types(self):
        receipt, admission, _ = fixture()
        receipt['binding']['not_before'] = 100.0
        self.assertEqual(receipt['binding'], admission['expected'])  # Python treats 100.0 as 100.
        with self.assertRaises(ValueError):
            validate_receipt(receipt, admission, 200)

    def test_conflicting_duplicate_json_fields_are_rejected(self):
        receipt, admission, check = fixture()
        text = check['output']['text'].replace('"cleanup": true',
                                              '"cleanup": false, "cleanup": true', 1)
        self.assertEqual(receipt, json.loads(text))  # Default JSON parsing hides the conflict.
        check['output']['text'] = text
        with self.assertRaises(ValueError):
            validate_check(check, receipt, admission, 200)

    def test_formal_inventory_cannot_be_reduced_or_extended_by_admission(self):
        for mutation in ('missing', 'substituted', 'extra'):
            with self.subTest(mutation=mutation):
                receipt, admission, _ = fixture()
                plan = receipt['binding']['tiers']
                if mutation == 'missing':
                    del plan['postgres-redis']
                elif mutation == 'substituted':
                    plan['unknown'] = plan.pop('postgres-redis')
                else:
                    plan['unknown'] = copy.deepcopy(plan['postgres-redis'])
                receipt['tiers'] = [dict(tier=name, exit=0, cleanup=True, invocation='nonce-1',
                    log_sha256='e' * 64, **entry) for name, entry in plan.items()]
                admission['expected'] = copy.deepcopy(receipt['binding'])
                with self.assertRaises(ValueError):
                    validate_receipt(receipt, admission, 200)

    def test_main_requires_remote_commit_identity_and_tree(self):
        receipt, admission, check = fixture()
        check['output'] = {'text': json.dumps(receipt)}
        environment = dict(GITHUB_REPOSITORY=REPOSITORY, GITHUB_EVENT_NAME='workflow_dispatch',
            GITHUB_REF='refs/heads/main', BOX_FORMAL_CONSUMER_SHA='a' * 40,
            GITHUB_WORKFLOW_SHA='a' * 40, BOX_FORMAL_ADMISSION=json.dumps(admission),
            GITHUB_TOKEN='fixture-only')
        for sha, tree, accepted in [('a' * 40, 'a' * 40, True),
                                    ('f' * 40, 'a' * 40, False),
                                    ('a' * 40, 'f' * 40, False)]:
            with self.subTest(sha=sha, tree=tree), patch.dict(consumer.os.environ, environment, clear=True), \
                    patch.object(consumer.time, 'time', return_value=200), \
                    patch.object(consumer, 'api', side_effect=[{'id': 123}, check,
                        {'sha': sha, 'tree': {'sha': tree}}]), redirect_stdout(io.StringIO()):
                if accepted:
                    consumer.main()
                else:
                    with self.assertRaises(ValueError):
                        consumer.main()

    def test_wrong_app_check_and_payload(self):
        for field, value in [('app', {'id': 1, 'slug': 'new-api-box-formal'}), ('id', 41),
                             ('head_sha', 'f' * 40), ('conclusion', 'failure'),
                             ('status', 'in_progress'), ('external_id', 'f' * 64)]:
            receipt, admission, check = fixture()
            check[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_check(check, receipt, admission, 200)
        receipt, admission, check = fixture()
        admission['repository'] = 'other/repository'
        with self.assertRaises(ValueError):
            validate_check(check, receipt, admission, 200)


if __name__ == '__main__':
    unittest.main()
