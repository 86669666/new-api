"""Eight bounded stdlib fixture groups for the static checker; no HTTP/Go/CI."""

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / 'scripts/openapi/check_route_coverage.py'
SOURCE = (ROOT / 'router/task-router.go').read_text()
INVENTORY = json.loads((ROOT / 'scripts/openapi/route_coverage.json').read_text())
HEADER = SOURCE[:SOURCE.index('func SetTaskRouter')]


class RouteCoverageTests(unittest.TestCase):
    calls = 0

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='issue3-route-fixture-', dir=os.getenv('TMPDIR'))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ['router', 'scripts/openapi', 'docs/openapi']:
            (self.root / name).mkdir(parents=True)

    def check(self, source=SOURCE, inventory=None, paths=None, expected=0, error=''):
        if inventory is None:
            inventory = copy.deepcopy(INVENTORY)
        (self.root / 'router/task-router.go').write_text(source)
        value = inventory if isinstance(inventory, str) else json.dumps(inventory)
        (self.root / 'scripts/openapi/route_coverage.json').write_text(value)
        for name in ['api', 'relay']:
            doc = {'openapi': '3.0.0', 'servers': [], 'paths': paths or {}}
            (self.root / f'docs/openapi/{name}.json').write_text(json.dumps(doc))
        argv = [sys.executable, '-B', str(CHECKER), '--root', str(self.root)]
        result = subprocess.run(argv, cwd=ROOT, text=True, capture_output=True, timeout=10)
        type(self).calls += 1
        print(json.dumps({'fixture_case': self.id(), 'invocation': self.calls, 'argv': argv,
                          'cwd': str(ROOT), 'returncode': result.returncode, 'expected_returncode': expected,
                          'stdout': result.stdout, 'stderr': result.stderr}), flush=True)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        if expected:
            self.assertIn(error, result.stderr)
            self.assertFalse(json.loads(result.stderr)['classification_check_passed'])
            return None
        return json.loads(result.stdout)

    def test_01_current_five_deferred_classifications(self):
        result = self.check()
        self.assertEqual(result['route_count'], 5)
        self.assertEqual(result['counts'], {'documented': 0, 'deferred': 5})
        self.assertFalse(result['complete_documentation'])
        self.assertFalse(result['full_repository_coverage'])

    def test_02_new_registration_requires_classification(self):
        source = SOURCE.rsplit('}', 1)[0] + '\n router.GET("/v1/tasks/health", controller.GetTask)\n}\n'
        self.check(source, expected=1, error='unclassified registrations')
        inventory = copy.deepcopy(INVENTORY)
        entry = copy.deepcopy(inventory['routes'][1])
        entry['path'] = '/v1/tasks/health'
        inventory['routes'].append(entry)
        self.assertEqual(self.check(source, inventory)['route_count'], 6, 'not a hardcoded five-line detector')

    def test_03_removed_source_registration_leaves_stale_entry(self):
        source = '\n'.join(line for line in SOURCE.splitlines() if 'taskSubmitRouter.POST(' not in line)
        self.check(source, expected=1, error="stale classifications: [('POST'")

    def test_04_method_path_and_head_are_independent(self):
        for old, new in [('taskContentRouter.HEAD(', 'taskContentRouter.PUT('),
                         ('/:key/artifacts"', '/:key/outputs"')]:
            with self.subTest(change=new):
                self.check(SOURCE.replace(old, new, 1), expected=1, error='unclassified registrations')
        inventory = copy.deepcopy(INVENTORY)
        inventory['routes'] = [e for e in inventory['routes'] if e['method'] != 'HEAD']
        self.check(inventory=inventory, expected=1, error="('HEAD',")

    def test_05_duplicates_and_wildcard_conflicts(self):
        line = '\t\ttaskReadRouter.GET("/:key", controller.GetTask)'
        for addition, message in [(line, 'duplicate/conflicting registration'),
                                  ('taskReadRouter.GET("/:other/details", controller.GetTask)', 'conflicting wildcard names')]:
            with self.subTest(addition=addition):
                self.check(SOURCE.replace(line, line + '\n' + addition), expected=1, error=message)
        inventory = copy.deepcopy(INVENTORY)
        inventory['routes'].append(copy.deepcopy(inventory['routes'][0]))
        self.check(inventory=inventory, expected=1, error='duplicate classification')
        raw = json.dumps(INVENTORY).replace('"version": 1', '"version": 1, "version": 1', 1)
        self.check(inventory=raw, expected=1, error='duplicate JSON key')

    def test_06_unknown_dynamic_expressions_fail_closed(self):
        cases = [
            (SOURCE.replace('Group("/v1/tasks")', 'Group(prefix)', 1), 'dynamic expression'),
            (SOURCE.replace('GET("/:key",', 'GET("/" + key,', 1), 'dynamic expression'),
            (SOURCE.rsplit('}', 1)[0] + 'registerTasks(router)\n}\n', 'unknown receiver/statement'),
            (SOURCE.replace('taskReadRouter.GET(', 'taskReadRouter.Any(', 1), 'unsupported registration'),
            (SOURCE.replace('controller.GetTask)', 'func() { router.GET("/hidden", handler) })', 1), 'inline registration'),
            (SOURCE + '\nfunc additionalRouter() {}\n', 'unsupported top-level declaration'),
        ]
        for source, message in cases:
            with self.subTest(message=message):
                self.check(source, expected=1, error=message)

    def test_07_group_normalization_and_explicit_parameter_aliases(self):
        source = HEADER + '''func SetTaskRouter(router *gin.Engine) {
            v := router.Group(`/v1//.`)
            tasks := v.Group("/tasks")
            {
                tasks := v.Group("/shadow")
                tasks.GET("/probe", controller.GetTask)
            }
            // router.POST("/ghost", controller.GetTask)
            tasks.GET(
                "/:key/artifacts/:artifact_key/content",
                controller.TaskArtifactContent,
            )
            tasks.HEAD("/:key/artifacts/:artifact_key/content", controller.TaskArtifactContent)
        }
        '''
        inventory = copy.deepcopy(INVENTORY)
        inventory['routes'] = [copy.deepcopy(INVENTORY['routes'][1]), *copy.deepcopy(INVENTORY['routes'][3:])]
        inventory['routes'][0]['path'] = '/v1/shadow/probe'
        result = self.check(source, inventory)
        self.assertEqual([r['path'] for r in result['routes']], [e['path'] for e in inventory['routes']])
        entry = inventory['routes'][1]
        entry.pop('issue')
        entry.pop('reason')
        entry['classification'] = 'documented'
        entry['operation'] = {'document': 'docs/openapi/relay.json',
                              'path': '/v1/tasks/{task_id}/artifacts/{artifact}/content',
                              'parameter_aliases': {'key': 'task_id', 'artifact_key': 'artifact'},
                              'alias_reason': 'Synthetic contract fixture: explicit one-to-one names for the same two path positions.'}
        paths = {entry['operation']['path']: {'get': {'responses': {'200': {'description': 'fixture only'}}}}}
        self.assertEqual(self.check(source, inventory, paths)['counts'], {'documented': 1, 'deferred': 2})
        entry['operation']['alias_reason'] = ''
        self.check(source, inventory, paths, expected=1, error='justification')
        entry['operation']['parameter_aliases'] = {}
        self.check(source, inventory, paths, expected=1, error='without a justified parameter alias')

    def test_08_documented_requires_actual_exact_oas_operation(self):
        inventory = copy.deepcopy(INVENTORY)
        entry = inventory['routes'][-1]
        entry.pop('issue')
        entry.pop('reason')
        entry['classification'] = 'documented'
        path = '/v1/tasks/{key}/artifacts/{artifact_key}/content'
        entry['operation'] = {'document': 'docs/openapi/api.json', 'path': path,
                              'parameter_aliases': {}, 'alias_reason': ''}
        for paths in [{}, {path: {'get': {'responses': {'200': {'description': 'GET only'}}}}}, {path: {'head': {}}}]:
            with self.subTest(paths=paths):
                self.check(inventory=inventory, paths=paths, expected=1, error='missing/unsupported OAS operation: HEAD')


if __name__ == '__main__':
    unittest.main(verbosity=2)
