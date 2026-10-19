import copy
import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest

from database_gate import REQUIRED, validate_environment, validate_events
from release_policy import digest_sources, promotion, quality_results


class ReleasePolicyTests(unittest.TestCase):
    def test_only_newest_stable_promotes(self):
        tags = ['v1.2.0', 'v1.10.0', 'v2.0.0-rc.1', 'relaykit/v9.0.0']
        for tag, expected in [('v1.2.0', False), ('v1.10.0', True), ('v2.0.0-rc.1', False),
                              ('v2.0.0-alpha.1', False), ('v3.0.0', False)]:
            with self.subTest(tag=tag):
                self.assertEqual(expected, promotion(tag, tags))
        self.assertFalse(promotion('v1.10.0', tags + ['v1.11.0']))
        for tag in ('latest', 'nightly', 'v01.2.3', 'v1.2', 'v1.2.3\n', 'v1.2.3;echo bad'):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                promotion(tag, tags)

    def test_publishers_keep_multiple_pending_releases(self):
        root = Path(__file__).resolve().parents[2]
        # Inspect the actual workflow-level settings, not a separate queue model.
        for name in ('docker-build.yml', 'docker-image-branch.yml'):
            workflow = (root / '.github/workflows' / name).read_text()
            block = re.search(r'^concurrency:\n((?:  .+\n)+)', workflow, re.MULTILINE)
            self.assertIsNotNone(block, name)
            config = dict(line.strip().split(': ', 1) for line in block.group(1).splitlines())
            self.assertEqual({'group': 'publish-docker-new-api', 'queue': 'max',
                              'cancel-in-progress': 'false'}, config, name)

    def test_real_preview_prepare_keeps_branch_identity_and_legal_tags(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / '.github/workflows/docker-image-branch.yml').read_text()
        block = re.search(r'        run: \|\n((?:          .*\n)+)', workflow)
        self.assertIsNotNone(block)
        # Only commit lookup is stubbed; ref validation and the workflow's alias CLI run.
        script = ('git() { if [ "$1" = rev-parse ]; then printf "%s\\n" "$TEST_CANDIDATE_SHA"; '
                  'else command git "$@"; fi; }\n' + textwrap.dedent(block.group(1)))
        branches = ['feature/' + 'a' * 52 + '-one', 'feature/' + 'a' * 52 + '-two',
                    'feature/a', 'feature-a', 'A', 'a', '中文分支']
        aliases = []
        for branch in branches:
            runs = []
            for sha, run_id, attempt in [('a' * 40, '100', '1'), ('b' * 40, '9' * 20, '9' * 20)]:
                with self.subTest(branch=branch, run=run_id), tempfile.TemporaryDirectory() as tmp:
                    output = Path(tmp) / 'output'
                    env = dict(os.environ, BRANCH_NAME=branch, GITHUB_OUTPUT=str(output),
                               GITHUB_RUN_ID=run_id, GITHUB_RUN_ATTEMPT=attempt, TEST_CANDIDATE_SHA=sha)
                    subprocess.run(['bash', '-e', '-c', script], cwd=root, env=env,
                                   check=True, capture_output=True, text=True)
                    values = dict(line.split('=', 1) for line in output.read_text().splitlines())
                    for key in ('alias', 'version'):
                        self.assertRegex(values[key], r'^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}$')
                        self.assertTrue(values[key].startswith('preview-'))
                    runs.append(values)
            self.assertNotEqual(runs[0]['sha'], runs[1]['sha'])
            self.assertEqual(runs[0]['alias'], runs[1]['alias'])
            self.assertNotEqual(runs[0]['version'], runs[1]['version'])
            aliases.append(runs[0]['alias'])
        self.assertEqual(len(aliases), len(set(aliases)))

    def test_quality_rejects_every_non_success(self):
        valid = dict.fromkeys(('backend', 'frontend', 'database'), 'success')
        quality_results(valid)
        for key in valid:
            for state in ('failure', 'cancelled', 'skipped', '', 'pending', None):
                with self.subTest(key=key, state=state), self.assertRaises(ValueError):
                    quality_results(dict(valid, **{key: state}))
            missing = dict(valid)
            missing.pop(key)
            with self.assertRaises(ValueError):
                quality_results(missing)

    def test_digest_receipts_cannot_mix_runs_candidates_attempts_or_architectures(self):
        records = [dict(sha='a' * 40, run_id='100', attempt='1', image='calciumion/new-api',
                        arch=arch, digest='sha256:' + char * 64)
                   for arch, char in [('amd64', '1'), ('arm64', '2')]]
        self.assertEqual(['calciumion/new-api@sha256:' + c * 64 for c in ('1', '2')],
                         digest_sources(records[::-1], 'a' * 40, '100', '1'))
        for key, value in [('sha', 'b' * 40), ('run_id', '101'), ('attempt', '2'),
                           ('arch', 'amd64'), ('digest', 'latest-arm64'), ('image', 'wrong/image')]:
            mixed = copy.deepcopy(records)
            mixed[1][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                digest_sources(mixed, 'a' * 40, '100', '1')
        for incomplete in ([], records[:1], records + records[:1]):
            with self.assertRaises(ValueError):
                digest_sources(incomplete, 'a' * 40, '100', '1')


class DatabaseGateTests(unittest.TestCase):
    def test_environment_rejects_missing_or_shared_targets(self):
        valid = {'NEWAPI_TEST_PROFILE': 'isolated-ci',
                 'TEST_MYSQL_DSN': 'root@tcp(127.0.0.1:3306)/newapi_ci_contracts?parseTime=true',
                 'TEST_POSTGRES_DSN': 'postgres://postgres@127.0.0.1:5432/newapi_ci_contracts?sslmode=disable'}
        validate_environment(valid)
        for key in valid:
            env = dict(valid)
            env.pop(key)
            with self.subTest(missing=key), self.assertRaises(ValueError):
                validate_environment(env)
        for host in ('10.10.88.120', 'localhost', 'dev-infra', '192.168.200.1'):
            for key in ('TEST_MYSQL_DSN', 'TEST_POSTGRES_DSN'):
                env = dict(valid)
                env[key] = env[key].replace('127.0.0.1', host)
                with self.subTest(host=host, key=key), self.assertRaises(ValueError):
                    validate_environment(env)
        for key in ('SQL_DSN', 'LOG_SQL_DSN', 'REDIS_CONN_STRING', 'REDIS_URL'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_environment(dict(valid, **{key: 'shared'}))

    def test_database_results_require_real_dialect_execution(self):
        events = [{'Action': 'pass', 'Test': name} for name in sorted(REQUIRED)]
        events += [{'Action': 'pass', 'Package': 'github.com/QuantumNous/new-api/model'}]
        validate_events(events, 0)
        for bad in ([], events[1:], events[:-1], events + [{'Action': 'skip'}],
                    events + [{'Action': 'fail'}]):
            with self.assertRaises(ValueError):
                validate_events(bad, 0)
        with self.assertRaises(ValueError):
            validate_events(events, 1)


if __name__ == '__main__':
    unittest.main()
