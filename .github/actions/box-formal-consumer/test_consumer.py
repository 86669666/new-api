import copy
import unittest
from consumer import APP, INSTALLATION, REPOSITORY, CHECK, PINS, digest, validate_check, validate_receipt, validate_environment


def fixture():
    binding = dict.fromkeys(('candidate_sha', 'candidate_tree', 'execution_sha', 'consumer_sha'), 'a' * 40)
    binding.update(dict.fromkeys(('runner_sha256', 'wrapper_sha256', 'producer_sha256',
        'source_manifest_sha256', 'assets_sha256', 'toolchain_sha256', 'module_sha256',
        'manifest_sha256'), 'b' * 64))
    binding.update(images=PINS.copy(), platform='linux/amd64', attempt_id='attempt-1', admission_id='root-1',
        invocation='nonce-1', test_binaries={'test-0': 'c' * 64}, not_before=100, expires_at=300,
        tiers={'sqlite': {'entries': [{'binary': 'test-0', 'cwd': 'router', 'run': '.'}],
                         'required_leaves': [], 'manifest_sha256': 'd' * 64}})
    receipt = {'binding': binding, 'started_at': 110, 'completed_at': 190, 'process_exit': 0,
               'exit': 0, 'cleanup': True, 'unexecuted': [], 'tiers': [dict(
                   tier='sqlite', exit=0, cleanup=True, invocation='nonce-1',
                   log_sha256='e' * 64, **binding['tiers']['sqlite'])]}
    admission = dict(repository=REPOSITORY, repository_id=123, active=True, app_id=APP,
                     installation_id=INSTALLATION, expected=copy.deepcopy(binding),
                     check_run_id=42, receipt_sha256=digest(receipt))
    check = dict(id=42, name=CHECK, head_sha='a' * 40, app={'id': APP, 'slug': 'new-api-box-formal'},
                 status='completed', conclusion='success', external_id=digest(receipt))
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
