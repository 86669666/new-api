#!/usr/bin/env python3
"""Deterministic refusal and lifecycle contracts; not real database evidence."""
import collections
import contextlib
import copy
import functools
from pathlib import Path
import io
import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import database_gate as gate
import run_isolated_databases as runner
import released_database_gate as released


class DatabaseGateContracts(unittest.TestCase):
    def test_required_matrix_cannot_be_satisfied_by_another_package_or_skip(self):
        events = [{'Action': 'pass', 'Test': name, 'Package': 'example/model'} for name in gate.REQUIRED]
        events.append({'Action': 'pass', 'Package': 'example/model'})
        gate.validate_events(events, 0)
        for label, candidate, code in [
            ('missing dialect', events[1:], 0),
            ('missing package result', events[:-1], 0),
            ('skip', events + [{'Action': 'skip'}], 0),
            ('nonzero', events, 1),
            ('wrong package', [dict(event, Package='example/controller') if event.get('Test') else event for event in events], 0),
        ]:
            with self.subTest(label=label), self.assertRaises(ValueError):
                gate.validate_events(candidate, code)

    def test_inherited_services_refused_before_docker_or_cleanup(self):
        for key in ('SQL_DSN', 'LOG_SQL_DSN', 'TEST_MYSQL_DSN', 'AUDIT_POSTGRES_DSN',
                    'REDIS_HOST', 'REDIS_URL', 'DATABASE_URL', 'DOCKER_HOST', 'COMPOSE_FILE', 'PGHOST', 'MYSQL_PWD', 'HTTP_PROXY', 'all_proxy', 'NO_PROXY'):
            with self.subTest(key=key), patch.dict(os.environ, {key: 'shared'}, clear=True), patch.object(runner, 'run') as command:
                with self.assertRaises(ValueError):
                    runner.main(['--context', 'owned', '--project', 'newapi-ci-test', '--docker-config', '/absent', '--image-evidence', '/absent', '--relay-evidence', '/absent/receipt'])
                command.assert_not_called()

    def test_exact_socket_and_existing_resources_refuse_before_any_mutation(self):
        base = [json.dumps([{'Endpoints': {'docker': {'Host': runner.SOCKET}}}]),
                json.dumps({'OSType': 'linux', 'Architecture': 'arm64'}), '', '', 'bridge\nhost\nnone\n']
        cases = [
            ('other socket', [json.dumps([{'Endpoints': {'docker': {'Host': 'unix:///var/run/docker.sock'}}}])]),
            ('stopped container', base[:2] + ['owned-elsewhere']),
            ('orphan volume', base[:3] + ['owned-elsewhere']),
            ('orphan network', base[:4] + ['bridge\nhost\nnone\nold_project']),
        ]
        for label, answers in cases:
            with self.subTest(label=label), patch.object(runner, 'run', side_effect=answers) as command:
                with self.assertRaises(ValueError):
                    runner.preflight(['docker'])
                for call in command.call_args_list:
                    self.assertNotIn('up', call.args[0])
                    self.assertNotIn('down', call.args[0])
                    self.assertNotIn('pull', call.args[0])

    def test_missing_image_does_not_trigger_pull_or_cleanup(self):
        answers = [json.dumps([{'Endpoints': {'docker': {'Host': runner.SOCKET}}}]),
                   json.dumps({'OSType': 'linux', 'Architecture': 'arm64'}), '', '', 'bridge\nhost\nnone\n',
                   RuntimeError('image missing')]
        with patch.object(runner, 'run', side_effect=answers) as command:
            with self.assertRaises(RuntimeError):
                runner.preflight(['docker'])
            self.assertEqual(command.call_args.args[0][-3:], ['image', 'inspect', runner.IMAGES['mysql']])

    def test_primary_and_cleanup_failures_are_reported_separately(self):
        spec = {'services': {service: {'image': image, 'pull_policy': 'never', 'platform': 'linux/arm64',
                                     'networks': {'isolated': {}}}
                             for service, image in runner.IMAGES.items()}, 'networks': {'isolated': {'internal': True}}}
        for cleanup_failure in (False, True):
            answers = [json.dumps(spec), RuntimeError('startup failed')]
            answers += [RuntimeError('cleanup failed')] if cleanup_failure else ['', '', '', '']
            with self.subTest(cleanup_failure=cleanup_failure), tempfile.TemporaryDirectory() as config, \
                    patch.dict(os.environ, {}, clear=True), patch.object(runner, 'preflight'), \
                    patch.object(runner, 'run', side_effect=answers), contextlib.redirect_stdout(io.StringIO()) as output:
                status = runner.main(['--context', 'owned', '--project', 'newapi-ci-test', '--docker-config', config, '--image-evidence', '/absent', '--relay-evidence', str(Path(config)/'relay.json')])
                result = json.loads(output.getvalue())
                self.assertEqual(status, 1)
                self.assertIn('startup failed', result['primary_error'])
                if cleanup_failure:
                    self.assertIn('cleanup failed', result['cleanup_error'])
                else:
                    self.assertIsNone(result['cleanup_error'])

    def test_timeout_kills_remaining_descendant_after_leader_exits(self):
        process = unittest.mock.Mock(pid=912345, returncode=-15)
        process.communicate.side_effect = [subprocess.TimeoutExpired('worker', 1), ('', ''), ('', '')]
        with patch.object(runner.subprocess, 'Popen', return_value=process), \
                patch.object(runner.os, 'killpg') as kill, \
                patch.object(runner, 'live_group_members', side_effect=[[912346], []]), \
                patch.object(runner.time, 'sleep'):
            with self.assertRaises(subprocess.TimeoutExpired) as error:
                runner.run(['worker'], timeout=1)
            self.assertIsNone(error.exception.process_cleanup_error)
            self.assertEqual([call.args[1] for call in kill.call_args_list], [runner.signal.SIGTERM, runner.signal.SIGKILL])

    def test_second_cancel_is_coalesced_and_group_cleanup_finishes(self):
        process = unittest.mock.Mock(pid=912345, returncode=None)
        process.communicate.side_effect = [KeyboardInterrupt('first'), KeyboardInterrupt('second'), ('', '')]
        with patch.object(runner.subprocess, 'Popen', return_value=process), \
                patch.object(runner.os, 'killpg') as kill, \
                patch.object(runner, 'live_group_members', return_value=[]), \
                patch.object(runner.signal, 'signal') as handler:
            with self.assertRaises(KeyboardInterrupt) as error:
                runner.run(['worker'])
            self.assertEqual(str(error.exception), 'first')
            self.assertIsNone(error.exception.process_cleanup_error)
            self.assertIn(unittest.mock.call(process.pid, runner.signal.SIGKILL), kill.call_args_list)
            handler.assert_any_call(runner.signal.SIGTERM, runner.signal.SIG_IGN)

    def test_safe_gate_failure_is_visible_without_dsn(self):
        process = unittest.mock.Mock(pid=912345, returncode=1)
        process.communicate.return_value = ('SAFE_GATE_FAILURE mysql missing unique index secret-dsn\n', '')
        with patch.object(runner.subprocess, 'Popen', return_value=process), \
                contextlib.redirect_stderr(io.StringIO()) as output:
            with self.assertRaises(RuntimeError):
                runner.run(['python3', 'database_gate.py'], env={'TEST_MYSQL_DSN':'secret-dsn'}, safe_failure_output=True)
            self.assertIn('SAFE_GATE_FAILURE mysql missing unique index', output.getvalue())
            self.assertNotIn('secret-dsn', output.getvalue())

    def test_arbitrary_docker_failure_remains_private(self):
        process = unittest.mock.Mock(pid=912345, returncode=1)
        process.communicate.return_value = ('private driver details', 'private connection data')
        with patch.object(runner.subprocess, 'Popen', return_value=process), \
                contextlib.redirect_stderr(io.StringIO()) as output:
            with self.assertRaises(RuntimeError) as error:
                runner.run(['docker', 'inspect'])
            self.assertEqual(output.getvalue(), '')
            self.assertNotIn('private', str(error.exception))



class OrganizationIdentityContracts(unittest.TestCase):
    def setUp(self):
        self.old = {'a' * 64: self.volume('a' * 64), 'b' * 64: self.volume('b' * 64)}
        self.new = self.volume('c' * 64)

    @staticmethod
    def volume(name):
        return {'Name': name, 'Driver': 'local', 'Labels': {'com.docker.volume.anonymous': ''},
                'Options': None, 'CreatedAt': '2026-10-21T00:00:00Z', 'Scope': 'local'}

    def test_explicit_baseline_does_not_adopt_extra_volumes(self):
        base = [json.dumps([{'Endpoints': {'docker': {'Host': runner.SOCKET}}}]),
                json.dumps({'OSType': 'linux', 'Architecture': 'arm64'}), '',
                '\n'.join(self.old) + '\nextra-volume\n']
        with patch.object(runner, 'run', side_effect=base), self.assertRaises(ValueError):
            runner.preflight(['docker'], preserve_volumes=self.old)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'baseline.json'
            path.write_text(json.dumps(list(self.old.values())))
            self.assertEqual(runner.preserved_volume_baseline(path), self.old)
            path.write_text(json.dumps([self.new]))
            with self.assertRaises(ValueError):
                runner.preserved_volume_baseline(path)

    def test_historical_mount_refused_before_start(self):
        cid = 'd' * 64
        data = {'Id': cid, 'Config': {'Image': runner.IMAGES['mysql'], 'Labels': {
                    'com.docker.compose.project': 'newapi-ci-test', 'com.docker.compose.service': 'mysql'}},
                'Image': runner.IMAGES['mysql'].split('@')[1],
                'State': {'Running': False, 'StartedAt': '0001-01-01T00:00:00Z'}, 'HostConfig': {},
                'Mounts': [{'Type': 'volume', 'Name': next(iter(self.old)), 'Driver': 'local', 'RW': True,
                            'Destination': '/var/lib/mysql', 'Source': '/a'}]}
        image = {'daemon_image': {'volumes': ['/var/lib/mysql']}}
        with patch.object(runner, 'run', return_value=json.dumps([data])) as command, self.assertRaises(ValueError):
            runner.capture_organization_mounts(['docker'], 'newapi-ci-test', 'mysql', cid, image, self.old, {})
        self.assertEqual(len(command.call_args_list), 1)
        self.assertNotIn('start', repr(command.call_args_list))
        data['Mounts'][0].update(Type='bind', Name='c' * 64)
        with patch.object(runner, 'run', return_value=json.dumps([data])), self.assertRaises(ValueError):
            runner.capture_organization_mounts(['docker'], 'newapi-ci-test', 'mysql', cid, image, self.old, {})

    def test_only_observed_image_anonymous_volume_is_owned(self):
        cid, name = 'd' * 64, self.new['Name']
        data = {'Id': cid, 'Config': {'Image': runner.IMAGES['mysql'], 'Labels': {
                    'com.docker.compose.project': 'newapi-ci-test', 'com.docker.compose.service': 'mysql'}},
                'Image': runner.IMAGES['mysql'].split('@')[1],
                'State': {'Running': False, 'StartedAt': '0001-01-01T00:00:00Z'}, 'HostConfig': {},
                'Mounts': [{'Type': 'volume', 'Name': name, 'Driver': 'local', 'RW': True,
                            'Destination': '/var/lib/mysql', 'Source': '/owned'}]}
        volume = dict(self.new, Mountpoint='/owned')
        owned = {}
        def command(argv, **kwargs):
            if argv[1] == 'inspect':
                return json.dumps([data])
            if argv[1:3] == ['volume', 'inspect']:
                return json.dumps([volume])
            if argv[1:3] == ['ps', '-aq']:
                # Docker's default is a 12-character ID, including stopped containers.
                return (cid if '--no-trunc' in argv else cid[:12]) + '\n'
            self.fail(argv)
        with patch.object(runner, 'run', side_effect=command):
            runner.capture_organization_mounts(['docker'], 'newapi-ci-test', 'mysql', cid,
                                               {'daemon_image': {'volumes': ['/var/lib/mysql']}}, self.old, owned)
        self.assertEqual(owned, {name: self.new})

    def test_cleanup_uses_full_project_ids_after_start_refusal(self):
        from types import SimpleNamespace
        cids = {'mysql': 'd' * 64, 'postgres': 'e' * 64}
        spec = {'services': {engine: {'image': image, 'pull_policy': 'never', 'platform': 'linux/arm64',
                                     'networks': {'isolated': {}}} for engine, image in runner.IMAGES.items()},
                'networks': {'isolated': {'internal': True}}}
        image = {'boot_id': 'boot', 'daemon_image': {'daemon_id': 'daemon'}}
        removed = False
        def command(argv, **kwargs):
            nonlocal removed
            if argv[0] == 'colima':
                return 'boot'
            if 'config' in argv:
                return json.dumps(spec)
            if 'compose' in argv and 'ps' in argv:
                return cids[argv[-1]] + '\n'
            if argv[1:3] == ['volume', 'ls']:
                return '\n'.join(self.old)
            if 'start' in argv:
                raise RuntimeError('test start refused')
            if 'down' in argv:
                self.assertNotIn('--volumes', argv)
                removed = True
            if argv[1:3] == ['ps', '-aq']:
                return '' if removed else '\n'.join(cid if '--no-trunc' in argv else cid[:12] for cid in cids.values())
            return ''
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = root / 'preserved.json'
            baseline.write_text(json.dumps(list(self.old.values())))
            args = SimpleNamespace(image_metadata=root, preserve_volumes=baseline, go=Path('/go'),
                                   image_evidence=root / 'images', relay_evidence=root / 'relay.json', project='newapi-ci-test')
            with patch.dict(os.environ, {}, clear=True), patch.object(runner, 'preflight'), \
                    patch.object(runner, 'verify_live_organization_image', return_value=image), \
                    patch.object(runner, 'organization_daemon_image', return_value=image['daemon_image']), \
                    patch.object(runner, 'capture_organization_mounts', return_value=[]), \
                    patch.object(runner, 'verify_preserved_volumes'), \
                    patch.object(runner, 'cleanup_organization_volumes') as cleanup, \
                    patch.object(runner, 'run', side_effect=command), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(runner.run_organization_identity(args, ['docker']), 1)
                result = json.loads(output.getvalue())
                self.assertIn('test start refused', result['primary_error'])
                self.assertIsNone(result['cleanup_error'])
                self.assertTrue(removed)
                cleanup.assert_called_once_with(['docker'], self.old, {})

    def test_cleanup_never_deletes_history_changed_or_unknown_volumes(self):
        name = self.new['Name']
        for mode in ('owned', 'changed', 'attached', 'unknown'):
            calls = []
            def command(argv, **kwargs):
                calls.append(argv)
                if argv[1:3] == ['volume', 'inspect']:
                    value = self.old.get(argv[3], self.new)
                    if argv[3] == name and mode == 'changed':
                        value = dict(value, CreatedAt='different')
                    return json.dumps([value])
                if argv[1:3] == ['ps', '-aq']:
                    return 'attached\n' if argv[-1] == 'volume=' + name and mode == 'attached' else ''
                if argv[1:3] == ['volume', 'rm']:
                    self.assertEqual(argv[3], name)
                    return name
                if argv[1:3] == ['volume', 'ls']:
                    return '\n'.join([*self.old, *([name] if mode in ('changed', 'attached') else []), *(['unknown'] if mode == 'unknown' else [])])
                self.fail(argv)
            with self.subTest(mode=mode), patch.object(runner, 'run', side_effect=command):
                if mode == 'owned':
                    runner.cleanup_organization_volumes(['docker'], self.old, {name: self.new})
                else:
                    with self.assertRaises(RuntimeError):
                        runner.cleanup_organization_volumes(['docker'], self.old, {name: self.new})
                deleted = [argv[3] for argv in calls if argv[1:3] == ['volume', 'rm']]
                self.assertEqual(deleted, [name] if mode in ('owned', 'unknown') else [])
                self.assertFalse(set(deleted) & self.old.keys())

    def test_exact_http_roots_and_package_cannot_be_skipped_or_substituted(self):
        events = [{'Action': 'pass', 'Package': 'github.com/QuantumNous/new-api/router', 'Test': test}
                  for test in runner.ORGANIZATION_IDENTITY_ROOTS]
        events.append({'Action': 'pass', 'Package': 'github.com/QuantumNous/new-api/router'})
        self.assertEqual(runner.validate_organization_identity_events(events)['roots'], sorted(runner.ORGANIZATION_IDENTITY_ROOTS))
        for candidate in (events[1:], events[:-1], events + [{'Action': 'skip'}], events + [{'Action': 'fail'}],
                          events + [{'Action': 'pass', 'Package': 'github.com/QuantumNous/new-api/router', 'Test': 'UnrelatedRoot'}],
                          [dict(event, Package='github.com/QuantumNous/new-api/model') for event in events]):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                runner.validate_organization_identity_events(candidate)

    def test_task_read_suite_cannot_run_identity_or_an_unbounded_root_set(self):
        package = 'github.com/QuantumNous/new-api/router'
        events = [{'Action': 'pass', 'Package': package, 'Test': 'TestOrganizationTaskReadLifecycle'},
                  {'Action': 'pass', 'Package': package}]
        result = runner.validate_organization_identity_events(events, 'organization-task-read')
        self.assertEqual(result['roots'], ['TestOrganizationTaskReadLifecycle'])
        self.assertEqual(runner.ORGANIZATION_READ_SUITES['organization-task-read'][1], 'g10-organization-task-read')
        for candidate in (events[1:], events[:-1], events + [{'Action': 'skip'}], events + [{'Action': 'fail'}],
                          events + [{'Action': 'pass', 'Package': package, 'Test': 'TestOrganizationLifecycleInvitationIdentity'}]):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                runner.validate_organization_identity_events(candidate, 'organization-task-read')
        with self.assertRaises(ValueError):
            runner.validate_organization_identity_events(events, 'organization-identity')
        with self.assertRaises(ValueError):
            runner.validate_organization_identity_events(events, 'arbitrary')

    def test_invitation_presentation_suite_is_one_closed_http_root(self):
        suite = 'organization-invitation-presentation'
        package = 'github.com/QuantumNous/new-api/router'
        events = [{'Action': 'pass', 'Package': package, 'Test': 'TestOrganizationInvitationPresentation'},
                  {'Action': 'pass', 'Package': package}]
        self.assertEqual(runner.validate_organization_identity_events(events, suite)['roots'], ['TestOrganizationInvitationPresentation'])
        self.assertEqual(runner.ORGANIZATION_READ_SUITES[suite][1], 'g11-organization-invitation-presentation')
        for candidate in (events[1:], events[:-1], events + [{'Action': 'skip'}], events + [{'Action': 'fail'}],
                          events + [{'Action': 'pass', 'Package': package, 'Test': 'TestOrganizationLifecycleInvitationIdentity'}]):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                runner.validate_organization_identity_events(candidate, suite)
        with self.assertRaises(ValueError):
            runner.validate_organization_identity_events(events, 'organization-identity')

    def test_task_batch_suite_is_one_closed_http_root(self):
        suite = 'organization-task-batch'
        package = 'github.com/QuantumNous/new-api/router'
        events = [{'Action': 'pass', 'Package': package, 'Test': 'TestOrganizationTaskBatchRead'},
                  {'Action': 'pass', 'Package': package}]
        self.assertEqual(runner.validate_organization_identity_events(events, suite)['roots'], ['TestOrganizationTaskBatchRead'])
        self.assertEqual(runner.ORGANIZATION_READ_SUITES[suite][1], 'g12-organization-task-batch')
        for candidate in (events[1:], events[:-1], events + [{'Action': 'skip'}], events + [{'Action': 'fail'}],
                          events + [{'Action': 'pass', 'Package': package, 'Test': 'TestOrganizationTaskReadLifecycle'}],
                          [dict(event, Package='github.com/QuantumNous/new-api/model') for event in events]):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                runner.validate_organization_identity_events(candidate, suite)
        with self.assertRaises(ValueError):
            runner.validate_organization_identity_events(events, 'organization-task-read')

    def test_task_export_suite_is_one_closed_http_root(self):
        suite = 'organization-task-export'
        package = 'github.com/QuantumNous/new-api/router'
        events = [{'Action': 'pass', 'Package': package, 'Test': 'TestOrganizationTaskExport'},
                  {'Action': 'pass', 'Package': package}]
        self.assertEqual(runner.validate_organization_identity_events(events, suite)['roots'], ['TestOrganizationTaskExport'])
        self.assertEqual(runner.ORGANIZATION_READ_SUITES[suite][1], 'g13-organization-task-export')
        for candidate in (events[1:], events[:-1], events + [{'Action': 'skip'}], events + [{'Action': 'fail'}],
                          events + [{'Action': 'pass', 'Package': package, 'Test': 'TestOrganizationTaskBatchRead'}],
                          [dict(event, Package='github.com/QuantumNous/new-api/model') for event in events]):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                runner.validate_organization_identity_events(candidate, suite)
        with self.assertRaises(ValueError):
            runner.validate_organization_identity_events(events, 'organization-task-batch')

    def test_task_list_revocation_suite_is_one_closed_http_root(self):
        suite = 'organization-task-list-revocation'
        package = 'github.com/QuantumNous/new-api/router'
        events = [{'Action': 'pass', 'Package': package, 'Test': 'TestOrganizationTaskListRevocation'},
                  {'Action': 'pass', 'Package': package}]
        self.assertEqual(runner.validate_organization_identity_events(events, suite)['roots'], ['TestOrganizationTaskListRevocation'])
        self.assertEqual(runner.ORGANIZATION_READ_SUITES[suite][1], 'g14-organization-task-list-revocation')
        for candidate in (events[1:], events[:-1], events + [{'Action': 'skip'}], events + [{'Action': 'fail'}],
                          events + [{'Action': 'pass', 'Package': package, 'Test': 'TestOrganizationTaskExport'}],
                          [dict(event, Package='github.com/QuantumNous/new-api/model') for event in events]):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                runner.validate_organization_identity_events(candidate, suite)
        with self.assertRaises(ValueError):
            runner.validate_organization_identity_events(events, 'organization-task-export')

    def test_organization_task_funding_isolation_suite_is_closed(self):
        suite = 'organization-task-funding-isolation'
        package = 'github.com/QuantumNous/new-api/router'
        events = [{'Action': 'pass', 'Package': package, 'Test': 'TestOrganizationTaskFundingIsolation'},
                  {'Action': 'pass', 'Package': package}]
        self.assertEqual(runner.validate_organization_identity_events(events, suite)['roots'], ['TestOrganizationTaskFundingIsolation'])
        self.assertEqual(runner.ORGANIZATION_READ_SUITES[suite][1], 'g15-organization-task-funding-isolation')
        for candidate in (events[1:], events[:-1], events + [{'Action': 'skip'}], events + [{'Action': 'fail'}],
                          events + [{'Action': 'pass', 'Package': package, 'Test': 'TestOrganizationTaskListRevocation'}],
                          [dict(event, Package='github.com/QuantumNous/new-api/service') for event in events]):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                runner.validate_organization_identity_events(candidate, suite)
        with self.assertRaises(ValueError):
            runner.validate_organization_identity_events(events, 'organization-task-list-revocation')

    def test_organization_capabilities_suite_is_closed(self):
        suite = 'organization-capabilities'
        package = 'github.com/QuantumNous/new-api/router'
        names = ['TestOrganizationCapabilityProjection', 'TestOrganizationCapabilityProjection/capability_projection',
                 'TestOrganizationAccessHTTP', 'TestOrganizationAccessHTTP/five_operations_roles_and_wire_precision']
        events = [{'Action': 'pass', 'Package': package, 'Test': name} for name in names]
        events.append({'Action': 'pass', 'Package': package})
        self.assertEqual(runner.validate_organization_identity_events(events, suite)['roots'], sorted((names[0], names[2])))
        self.assertEqual(runner.ORGANIZATION_READ_SUITES[suite][1], 'g16-organization-capabilities')
        for candidate in (events[1:], events[:-1], events[:1] + events[2:], events[:3] + events[4:],
                          events + [{'Action': 'skip'}], events + [{'Action': 'fail'}],
                          events + [{'Action': 'pass', 'Package': package, 'Test': 'TestOrganizationAccessHTTP/other'}],
                          [dict(event, Package='github.com/QuantumNous/new-api/service') for event in events]):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                runner.validate_organization_identity_events(candidate, suite)

    def test_live_image_recomputes_bytes_instead_of_trusting_receipt_flags(self):
        import hashlib
        config = {'os': 'linux', 'architecture': 'arm64', 'rootfs': {'type': 'layers', 'diff_ids': ['sha256:layer']},
                  'config': {'Volumes': {'/var/lib/mysql': {}}}}
        config_bytes = json.dumps(config).encode()
        config_digest = 'sha256:' + hashlib.sha256(config_bytes).hexdigest()
        manifest = {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                    'config': {'digest': config_digest, 'size': len(config_bytes)}}
        manifest_bytes = json.dumps(manifest).encode()
        digest = 'sha256:' + hashlib.sha256(manifest_bytes).hexdigest()
        metadata = {'mode': 'metadata', 'verified': True, 'repository': 'library/mysql', 'digest': digest,
                    'platform': {'os': 'linux', 'architecture': 'arm64'}, 'manifest': manifest,
                    'config_digest': config_digest, 'rootfs': config['rootfs']}
        metadata_bytes = json.dumps(metadata).encode()
        daemon = {'descriptor': {'size': len(manifest_bytes)}, 'rootfs': {'Type': 'layers', 'Layers': ['sha256:layer']},
                  'volumes': ['/var/lib/mysql']}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'metadata.json'
            path.write_bytes(metadata_bytes)
            for mutation in ('none', 'manifest', 'config', 'rootfs', 'boot'):
                current = copy.deepcopy(daemon)
                if mutation == 'rootfs': current['rootfs']['Layers'] = ['changed']
                answers = ['boot-1', manifest_bytes + (b' ' if mutation == 'manifest' else b''),
                           config_bytes + (b' ' if mutation == 'config' else b''), 'boot-2' if mutation == 'boot' else 'boot-1']
                with self.subTest(mutation=mutation), \
                        patch.dict(runner.IMAGES, {'mysql': 'docker.io/library/mysql@' + digest}), \
                        patch.dict(runner.ORGANIZATION_METADATA_SHA, {'mysql': hashlib.sha256(metadata_bytes).hexdigest()}), \
                        patch.object(runner, 'organization_daemon_image', return_value=current), \
                        patch.object(runner, 'run', side_effect=answers):
                    if mutation == 'none':
                        proof = runner.verify_live_organization_image(['docker'], 'mysql', path)
                        self.assertEqual(proof['format'], 'live-fixed-organization-image-v1')
                        self.assertEqual(proof['containerd_socket'], '/run/containerd/containerd.sock')
                        self.assertNotIn('accepted', proof)
                    else:
                        with self.assertRaises(runner.RelayIdentityError):
                            runner.verify_live_organization_image(['docker'], 'mysql', path)
            path.write_text(json.dumps({'accepted': True}))
            with self.assertRaises(runner.RelayIdentityError):
                runner.verify_live_organization_image(['docker'], 'mysql', path)

class ReleasedDatabaseContracts(unittest.TestCase):
    def test_release_structure_preserves_columns_indexes_and_uniqueness(self):
        old = [{'table':'tokens', 'columns':[{'name':'key','type':'varchar'}],
                'indexes':[{'name':'idx_tokens_key','columns':['key'],'unique':True,'known':True}]},
               {'table':'audit_logs', 'columns':[{'name':'event_id','type':'varchar'}],
                'indexes':[{'name':'idx_audit_logs_event_id','columns':['event_id'],'unique':True,'known':True}]}]
        current = copy.deepcopy(old)
        current[0]['columns'].append({'name':'allow_user_quota_query','type':'boolean'})
        released.verify_release_schema(old, current)
        for mutation in ('remove_index', 'remove_column', 'unique', 'index_columns', 'unknown_addition'):
            value = copy.deepcopy(current)
            if mutation == 'remove_index': value[1]['indexes'] = []
            elif mutation == 'remove_column': value[1]['columns'] = []
            elif mutation == 'unique': value[1]['indexes'][0]['unique'] = False
            elif mutation == 'index_columns': value[1]['indexes'][0]['columns'] = ['other']
            else: value[1]['columns'].append({'name':'unexpected','type':'text'})
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                released.verify_release_schema(old, value)

    def test_clickhouse_normalizes_only_owned_database_identity(self):
        ddl = "CREATE TABLE `newapi_ci_old`.`logs` (id UInt64) ENGINE = MergeTree ORDER BY id SETTINGS index_granularity = 8192"
        renamed = released.clickhouse_database_identity(ddl, 'newapi_ci_old', 'newapi_ci_restored')
        old = released.normalized_schema([{'table':'logs','ddl':ddl}], 'clickhouse', 'newapi_ci_old')
        current = released.normalized_schema([{'table':'logs','ddl':renamed}], 'clickhouse', 'newapi_ci_restored')
        self.assertEqual(old, current)
        for before, after in [('UInt64','UInt32'), ('ORDER BY id','ORDER BY tuple()'), ('8192','4096'), ('MergeTree','ReplacingMergeTree')]:
            changed = released.normalized_schema([{'table':'logs','ddl':renamed.replace(before,after)}], 'clickhouse','newapi_ci_restored')
            with self.subTest(change=after), self.assertRaises(ValueError):
                released.verify_release_schema(old, changed)
        with self.assertRaises(ValueError):
            released.clickhouse_database_identity(ddl, 'newapi_ci_other', 'newapi_ci_new')

    def test_committed_create_with_failed_client_remains_owned_and_is_reconciled(self):
        with tempfile.TemporaryDirectory() as tmp:
            stores = released.OwnedStores(Path(tmp));stores.containers['mysql'] = 'owned-container'
            databases = set()
            def sql(engine, query, database=None):
                if query.startswith('SELECT count(*)'):
                    return b'1' if 'newapi_ci_partial' in databases else b'0'
                if query.startswith('CREATE DATABASE'):
                    intent = json.loads((Path(tmp)/'database-ownership.json').read_text())[0]
                    self.assertEqual(intent['state'], 'create_pending')
                    self.assertTrue(intent['absent_before_create'])
                    databases.add('newapi_ci_partial')
                    raise RuntimeError('client failed after server CREATE')
                if query.startswith('DROP DATABASE'):
                    databases.remove('newapi_ci_partial');return b''
                self.fail(query)
            stores.sql = sql
            with self.assertRaises(RuntimeError): stores.create('mysql','newapi_ci_partial')
            self.assertEqual(stores.resources[0]['state'], 'create_unknown')
            self.assertFalse(stores.cleanup())
            self.assertFalse(databases)
            self.assertEqual(stores.resources[0]['state'],'absent_after_cleanup')

    def test_existing_database_and_uncertain_existence_never_receive_create_or_drop(self):
        for answer in (b'1', b'', RuntimeError('unavailable')):
            with self.subTest(answer=answer), tempfile.TemporaryDirectory() as tmp:
                stores=released.OwnedStores(Path(tmp));stores.containers['postgres']='owned'
                stores.sql=unittest.mock.Mock(side_effect=[answer])
                with self.assertRaises((ValueError,RuntimeError)):stores.create('postgres','newapi_ci_existing')
                self.assertFalse(stores.resources)
                self.assertFalse(stores.cleanup())
                self.assertEqual(stores.sql.call_count,1)

    def test_repeated_cancel_and_unavailable_reconciliation_preserve_unknown_and_continue(self):
        with tempfile.TemporaryDirectory() as tmp:
            stores=released.OwnedStores(Path(tmp));stores.containers['mysql']='owned'
            stores.resources=[{'engine':'mysql','name':'newapi_ci_'+name,'container':'owned',
                               'absent_before_create':True,'state':'create_unknown'} for name in ('first','second')]
            stores.sql=unittest.mock.Mock(side_effect=[b'1',KeyboardInterrupt('second cancel'),b'0',b'0'])
            with patch.object(released.signal,'signal') as handler:
                errors=stores.cleanup()
            self.assertEqual(stores.sql.call_count,4)
            self.assertEqual(len(errors),1)
            self.assertEqual(stores.resources[1]['state'],'cleanup_unknown')
            self.assertEqual(stores.resources[0]['state'],'absent_after_cleanup')
            handler.assert_any_call(released.signal.SIGTERM,released.signal.SIG_IGN)

    def test_cancelled_fixture_keeps_primary_process_and_database_cleanup_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime=Path(tmp);stores=unittest.mock.Mock(containers={},created=[])
            stores.create.side_effect=lambda engine,name:name
            stores.cleanup.return_value=[{'error':'database state unknown'}]
            error=KeyboardInterrupt('first cancel');error.process_cleanup_error='group still unknown'
            with patch.object(released,'OwnedStores',return_value=stores), \
                 patch.object(released,'COMBINATIONS',(('sqlite','same'),)), \
                 patch.object(released,'run_phase',side_effect=error):
                self.assertFalse(released.run_matrix(runtime,runtime))
            receipt=json.loads((runtime/'database-cleanup.json').read_text())
            self.assertEqual(receipt['primary_error']['error'],'first cancel')
            self.assertEqual(receipt['primary_error']['process_cleanup_error'],'group still unknown')
            self.assertEqual(receipt['errors'],[{'error':'database state unknown'}])
            stores.cleanup.assert_called_once()


    def test_fail_fast_keeps_first_failure_and_finishes_cleanup_with_full_manifests(self):
        for cleanup_failure in (False, True):
            with self.subTest(cleanup_failure=cleanup_failure), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);stores=unittest.mock.Mock(containers={},created=[])
                stores.create.return_value='owned.sqlite'
                if cleanup_failure:stores.cleanup.side_effect=RuntimeError('cleanup failed')
                else:stores.cleanup.return_value=[]
                with patch.object(released,'OwnedStores',return_value=stores), \
                     patch.object(released,'run_phase',side_effect=RuntimeError('first domain failure')) as phase:
                    self.assertFalse(released.run_matrix(root,root,fail_fast=True))
                phase.assert_called_once();stores.cleanup.assert_called_once()
                rows=json.loads((root/'matrix-results.json').read_text())
                required={(r['main'],r['log'],r['phase']) for r in rows if r['phase'] in released.PHASES}
                self.assertEqual(required,{(r['main'],r['log'],r['phase']) for r in released.required_manifest()})
                self.assertFalse(any(r['status']=='pass' for r in rows))
                org=json.loads((root/'organization-migration-results.json').read_text())
                self.assertEqual(len(org),42);self.assertTrue(all(r['status']=='blocked' for r in org))
                receipt=json.loads((root/'database-cleanup.json').read_text())
                self.assertEqual(receipt['primary_error']['error'],'first domain failure')
                self.assertEqual(len(receipt['errors']),int(cleanup_failure))
                if cleanup_failure:self.assertEqual(receipt['errors'][0]['error'],'cleanup failed')

    def test_default_continues_combinations_but_identity_loss_never_does(self):
        for error, expected_calls in ((RuntimeError('domain failure'),7),(runner.RelayIdentityError('identity lost'),1)):
            with self.subTest(error=type(error).__name__),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);stores=unittest.mock.Mock(containers={'mysql':'owned','postgres':'owned','clickhouse':'owned'},created=[])
                stores.create.return_value='owned';stores.cleanup.return_value=[]
                with patch.object(released,'OwnedStores',return_value=stores),patch.object(released,'run_phase',side_effect=error) as phase:
                    self.assertFalse(released.run_matrix(root,root))
                self.assertEqual(phase.call_count,expected_calls)
                stores.cleanup.assert_called_once()
                self.assertEqual(json.loads((root/'database-cleanup.json').read_text())['primary_error']['error'],str(error))

    def test_real_child_domain_failure_exits_normally_after_cleanup_receipt(self):
        # A real bounded child runs the same structured failure path; no database/network access.
        with tempfile.TemporaryDirectory() as tmp:
            script = """import sys,json
from pathlib import Path
from unittest.mock import Mock,patch
import released_database_gate as g
r=Path(sys.argv[1]);s=Mock(containers={},created=[])
s.create.return_value='owned';s.cleanup.return_value=[]
with patch.object(g,'OwnedStores',return_value=s),patch.object(g,'run_phase',side_effect=RuntimeError('child domain failure')):
 result=g.run_matrix(r,r,fail_fast=True)
assert s.cleanup.call_count==1
assert (r/'database-cleanup.json').exists()
sys.exit(0 if result else 7)
"""
            code,out,err=released.execute([__import__('sys').executable,'-B','-c',script,tmp],cwd=Path(released.__file__).parent,timeout=15)
            self.assertEqual(code,7,err.decode());self.assertEqual(out,b'')
            receipt=json.loads((Path(tmp)/'database-cleanup.json').read_text())
            self.assertEqual(receipt['primary_error']['error'],'child domain failure')
            self.assertEqual(receipt['errors'],[])


class OwnedRelayContracts(unittest.TestCase):
    def setUp(self):
     self.cid='a'*64;self.project='newapi-ci-test'
     self.d={'Id':self.cid,'Config':{'Image':runner.IMAGES['mysql'],'Labels':{'com.docker.compose.project':self.project,'com.docker.compose.service':'mysql'}},'Image':runner.IMAGES['mysql'].split('@')[1],'State':{'Running':True,'Health':{'Status':'healthy'}},'HostConfig':{'Privileged':False,'NetworkMode':'owned'},'NetworkSettings':{'Ports':{'3306/tcp':None},'Networks':{'owned':{'NetworkID':'b'*64,'IPAddress':'172.19.0.2','GlobalIPv6Address':''}}}}
     self.n={'Id':'b'*64,'Name':'owned','Driver':'bridge','Internal':True,'Options':{},'Labels':{'com.docker.compose.project':self.project,'com.docker.compose.network':'isolated'},'Containers':{self.cid:{'IPv4Address':'172.19.0.2/16'}},'IPAM':{'Config':[{'Subnet':'172.19.0.0/16','Gateway':'172.19.0.1'}]}}
    def test_owned_null_port_is_not_endpoint(self):
     self.assertEqual(runner.owned_container_identity(self.d,self.n,self.project,'mysql',self.cid)['ip'],'172.19.0.2')
    def test_reject_identity_and_network(self):
     for category in ('owner','id','image','health','privileged','second_network','internal','options','subnet','gateway','protected','network_owner','endpoint'):
      with self.subTest(category=category):
       d,n=copy.deepcopy(self.d),copy.deepcopy(self.n)
       if category=='owner':d['Config']['Labels']['com.docker.compose.project']='other'
       elif category=='id':d['Id']='c'*64
       elif category=='image':d['Image']='sha256:'+'c'*64
       elif category=='health':d['State']['Health']['Status']='starting'
       elif category=='privileged':d['HostConfig']['Privileged']=True
       elif category=='second_network':d['NetworkSettings']['Networks']['other']={}
       elif category=='internal':n['Internal']=False
       elif category=='options':n['Options']={'gateway_mode':'routed'}
       elif category=='subnet':n['IPAM']['Config'][0]['Subnet']='172.20.0.0/16'
       elif category=='gateway':d['NetworkSettings']['Networks']['owned']['IPAddress']='172.19.0.1'
       elif category=='protected':n['IPAM']['Config'][0]['Subnet']='10.10.0.0/16'
       elif category=='network_owner':n['Labels']['com.docker.compose.project']='other'
       elif category=='endpoint':n['Containers'][self.cid]['IPv4Address']='172.19.0.3/16'
       with self.assertRaises(ValueError):runner.owned_container_identity(d,n,self.project,'mysql',self.cid)
    def test_listener(self):
     self.assertTrue(runner.listeners('p123\nn127.0.0.1:40000\n',123,40000))
     for text in ('p124\nn127.0.0.1:40000','p123\nn*:40000','p123\nn127.0.0.1:40001','p123\nn127.0.0.1:40000\nn[::1]:40000',''):
      self.assertFalse(runner.listeners(text,123,40000))

    def test_null_publication_reports_missing_endpoint(self):
        for value in (None, [], {}, [{'HostIp': '0.0.0.0', 'HostPort': '40000'}]):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'no actual literal loopback'):
                runner.published_loopback_port({'NetworkSettings': {'Ports': {'3306/tcp': value}}}, '3306/tcp')

    def test_task_plugin_config_rejects_arbitrary_overrides(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp)
            for values in ({'auths': {}}, {'proxies': {}}, {'cliPluginsExtraDirs': ['/arbitrary']}, {'credsStore': 'helper'}):
                (config / 'config.json').write_text(json.dumps(values))
                with self.subTest(values=values), self.assertRaises(ValueError):
                    runner.docker_command(config, 'owned')
            (config / 'config.json').write_text('{}')
            self.assertEqual(runner.docker_command(config, 'owned'), ['docker', '--config', tmp, '--context', 'owned'])

    def test_fake_receipt_cannot_start_ssh(self):
        with tempfile.TemporaryDirectory() as tmp:
            proof = Path(tmp) / 'proof.json'
            proof.write_text(json.dumps({'accepted': True, 'local_port': 12345, 'pid': 12345}))
            relay = runner.OwnedRelay(['docker'], self.project, 'mysql', self.cid, proof)
            answers = [json.dumps([{'Endpoints': {'docker': {'Host': runner.SOCKET}}}]), 'boot']
            with patch.object(runner, 'run', side_effect=answers), patch.object(runner.subprocess, 'Popen') as start:
                with self.assertRaisesRegex(runner.RelayIdentityError, 'full image mapping'):
                    relay.start()
                start.assert_not_called()

    def test_listener_death_and_wrong_address_abort(self):
        relay = runner.OwnedRelay(['docker'], self.project, 'mysql', self.cid, '/unused')
        relay.port = 40000
        process = unittest.mock.Mock(pid=123)
        relay.process = process
        for state, listener in ((255, ''), (None, 'p123\nn*:40000'), (None, 'p124\nn127.0.0.1:40000')):
            process.poll.return_value = state
            with self.subTest(state=state, listener=listener), patch.object(runner.os, 'getpgid', return_value=123),                     patch.object(runner, 'run', return_value=listener), self.assertRaises(runner.RelayIdentityError):
                relay.check_listener()

    def test_endpoint_change_aborts_without_tracking_replacement(self):
        relay = runner.OwnedRelay(['docker'], self.project, 'mysql', self.cid, '/unused')
        relay.initial = {'ip': '172.19.0.2', 'container_id': self.cid}
        for value in ({'ip': '172.19.0.3', 'container_id': self.cid}, {'ip': '172.19.0.2', 'container_id': 'c'*64}):
            with self.subTest(value=value), patch.object(relay, 'check_listener'), patch.object(relay, 'snapshot', return_value=value):
                with self.assertRaises(runner.RelayIdentityError):
                    relay.check()
                self.assertEqual(relay.initial['ip'], '172.19.0.2')

    def test_relay_failure_terminates_dependent_process(self):
        process = unittest.mock.Mock(pid=123, args=['fixture'])
        process.communicate.side_effect = [subprocess.TimeoutExpired('fixture', 1), ('', '')]
        guard = unittest.mock.Mock(side_effect=[None, None, runner.RelayIdentityError('relay died')])
        with patch.object(runner.subprocess, 'Popen', return_value=process),                 patch.object(runner, 'terminate_group', return_value=None) as cleanup:
            with self.assertRaisesRegex(runner.RelayIdentityError, 'relay died'):
                runner.run(['fixture'], guard=guard)
            cleanup.assert_called_once_with(process)

    def test_repeated_cleanup_and_foreign_listener_are_not_taken_over(self):
        relay = runner.OwnedRelay(['docker'], self.project, 'mysql', self.cid, '/unused')
        process = unittest.mock.Mock(pid=123)
        relay.process, relay.port = process, 40000
        with patch.object(runner, 'terminate_group', return_value=None) as cleanup, patch.object(runner.socket, 'socket') as socket:
            socket.return_value.__enter__.return_value.connect_ex.return_value = 1
            relay.close(); relay.close()
            cleanup.assert_called_once_with(process)
            self.assertIsNone(relay.port)
        relay.port = 40000
        with patch.object(runner.socket, 'socket') as socket, patch.object(runner, 'terminate_group') as cleanup:
            socket.return_value.__enter__.return_value.connect_ex.return_value = 0
            with self.assertRaisesRegex(runner.RelayIdentityError, 'remains open'):
                relay.close()
            cleanup.assert_not_called()

    def test_relay_death_aborts_remaining_matrix_combinations(self):
        with tempfile.TemporaryDirectory() as tmp:
            stores = unittest.mock.Mock(containers={}, created=[])
            stores.create.side_effect = runner.RelayIdentityError('route changed')
            stores.cleanup.return_value = []
            with patch.object(released, 'OwnedStores', return_value=stores),                     patch.object(released, 'COMBINATIONS', (('sqlite', 'same'), ('sqlite', 'same'))):
                self.assertFalse(released.run_matrix(Path(tmp), Path(tmp)))
            stores.create.assert_called_once()
            stores.cleanup.assert_called_once()
            result = json.loads((Path(tmp) / 'matrix-verdict.json').read_text())
            self.assertEqual(result['primary_error']['error_type'], 'RelayIdentityError')


class RelayStartupOwnershipContracts(unittest.TestCase):
    def test_initial_rejection_never_spawns_either_entry(self):
        for module, entry in ((runner, runner.run), (released, released.execute)):
            with self.subTest(entry=entry.__name__), patch.object(module.subprocess, 'Popen') as spawn, \
                    patch.object(module, 'terminate_group') as cleanup:
                error = runner.RelayIdentityError('already invalid')
                with self.assertRaises(runner.RelayIdentityError) as caught:
                    entry(['fixture'], guard=unittest.mock.Mock(side_effect=error))
                self.assertIs(caught.exception, error)
                spawn.assert_not_called(); cleanup.assert_not_called()

    def test_started_failure_and_post_completion_failure_clean_both_entries(self):
        for module, entry in ((runner, runner.run), (released, released.execute)):
            for phase in ('before_io', 'after_completion'):
                with self.subTest(entry=entry.__name__, phase=phase):
                    process = unittest.mock.Mock(pid=123, args=['fixture'], returncode=0)
                    process.communicate.return_value = (b'', b'') if module is released else ('', '')
                    error = runner.RelayIdentityError('route changed')
                    error.process_cleanup_error = 'earlier cleanup unknown'
                    guards = [None, error] if phase == 'before_io' else [None, None, error]
                    with patch.object(module.subprocess, 'Popen', return_value=process) as spawn, \
                            patch.object(module, 'terminate_group', return_value='child cleanup unknown') as cleanup:
                        with self.assertRaises(runner.RelayIdentityError) as caught:
                            kwargs = {'input_bytes': b'owned restore bytes'} if module is released else {}
                            entry(['fixture'], guard=unittest.mock.Mock(side_effect=guards), **kwargs)
                    spawn.assert_called_once(); cleanup.assert_called_once_with(process)
                    self.assertIs(caught.exception, error)
                    self.assertIn('earlier cleanup unknown', error.process_cleanup_error)
                    self.assertIn('child cleanup unknown', error.process_cleanup_error)
                    if phase == 'before_io': process.communicate.assert_not_called()

    def test_restore_stdin_is_sent_once_across_guarded_waits(self):
        process = unittest.mock.Mock(pid=123, args=['restore'], returncode=0)
        process.communicate.side_effect = [subprocess.TimeoutExpired('restore', 1), (b'ok', b'')]
        with patch.object(released.subprocess, 'Popen', return_value=process), \
                patch.object(released, 'terminate_group') as cleanup:
            self.assertEqual(released.execute(['restore'], input_bytes=b'owned restore bytes',
                guard=unittest.mock.Mock()), (0, b'ok', b''))
        self.assertEqual(process.communicate.call_args_list[0].args, (b'owned restore bytes',))
        self.assertEqual(process.communicate.call_args_list[1].args, (None,))
        cleanup.assert_not_called()

    def test_second_failed_starter_is_recorded_and_outer_cleanup_errors_are_preserved(self):
        for outer_failure in (False, True):
            with self.subTest(outer_failure=outer_failure), tempfile.TemporaryDirectory() as tmp, \
                    patch.dict(os.environ, {}, clear=True):
                project = 'newapi-ci-test'
                first = unittest.mock.Mock(receipt={'pid': 123, 'local_port': 40001},
                    initial={'container_id': 'a'*64, 'network_id': 'c'*64, 'ip': '172.19.0.2'},
                    process=unittest.mock.Mock(pid=123), port=40001, boot='boot')
                second = unittest.mock.Mock(receipt={}, initial=None, process=None, port=None, boot='boot')
                first.start.return_value = 40001
                first.close.side_effect = runner.RelayIdentityError('first outer cleanup unknown') if outer_failure else None
                second.close.side_effect = [runner.RelayIdentityError('second self cleanup unknown'),
                    runner.RelayIdentityError('second outer cleanup unknown') if outer_failure else None]
                failure = runner.RelayIdentityError('second listener validation failed')
                failure.process_cleanup_error = 'second self cleanup unknown'

                def fail_after_allocating():
                    before = json.loads((Path(tmp)/'owned-relays.json').read_text())
                    self.assertEqual([r['engine'] for r in before['relays']], ['mysql', 'postgres'])
                    self.assertEqual(before['relays'][1]['state'], 'starting')
                    second.process = unittest.mock.Mock(pid=124)
                    second.port = 40002
                    second.initial = {'container_id': 'b'*64, 'network_id': 'c'*64, 'ip': '172.19.0.3'}
                    try: second.close()
                    except runner.RelayIdentityError: pass
                    raise failure

                second.start.side_effect = fail_after_allocating
                binding = {'docker_config': tmp, 'context': 'owned', 'project': project,
                    'image_evidence': tmp, 'containers': {'mysql': 'a'*64, 'postgres': 'b'*64}}
                answers = [json.dumps([{'Endpoints': {'docker': {'Host': runner.SOCKET}}}])]
                for engine in ('mysql', 'postgres'):
                    answers.append(json.dumps([{'Config': {'Image': runner.IMAGES[engine],
                        'Labels': {'com.docker.compose.project': project, 'com.docker.compose.service': engine}}}]))
                with patch.object(released.OwnedStores, 'call', side_effect=answers), \
                        patch.object(released, 'OwnedRelay', side_effect=[first, second]):
                    with self.assertRaises(runner.RelayIdentityError) as caught:
                        released.OwnedStores(Path(tmp), binding)
                self.assertIs(caught.exception, failure)
                self.assertEqual(str(failure), 'second listener validation failed')
                self.assertIn('second self cleanup unknown', failure.process_cleanup_error)
                self.assertEqual(second.close.call_count, 2); first.close.assert_called_once()
                saved = json.loads((Path(tmp)/'owned-relays.json').read_text())
                self.assertEqual(saved['initialization_error']['error'], str(failure))
                self.assertEqual(saved['initialization_error']['process_cleanup_error'], 'second self cleanup unknown')
                record = saved['relays'][1]
                self.assertEqual((record['pid'], record['local_port'], record['identity']['ip']),
                                 (124, 40002, '172.19.0.3'))
                self.assertEqual(record['state'], 'cleanup_unknown' if outer_failure else 'closed')
                if outer_failure:
                    for message in ('first outer cleanup unknown', 'second outer cleanup unknown'):
                        self.assertIn(message, failure.process_cleanup_error)
                        self.assertIn(message, json.dumps(saved))

    def test_cleanup_unknown_can_be_reconciled_once_and_closed_cleanup_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            stores = released.OwnedStores(Path(tmp))
            relay = unittest.mock.Mock(receipt={'pid': 123, 'local_port': 40001}, initial={},
                process=unittest.mock.Mock(pid=123), port=40001, boot='boot')
            relay.close.side_effect = [runner.RelayIdentityError('unknown'), None]
            stores.relays = [relay]
            stores.relay_records = [{'engine': 'mysql', 'container_id': 'a'*64,
                'state': 'running', 'cleanup_attempts': []}]
            stores.relay_receipt = Path(tmp)/'owned-relays.json'
            self.assertEqual(len(stores.close_relays()), 1)
            self.assertEqual(stores.relay_records[0]['state'], 'cleanup_unknown')
            self.assertEqual(stores.close_relays(), [])
            self.assertEqual(stores.close_relays(), [])
            self.assertEqual(relay.close.call_count, 2)
            saved = json.loads(stores.relay_receipt.read_text())['relays'][0]
            self.assertEqual(saved['state'], 'closed')
            self.assertEqual([a['status'] for a in saved['cleanup_attempts']], ['unknown', 'closed'])
            self.assertEqual(saved['pid'], 123)


class GuardTickContracts(unittest.TestCase):
    """One guard tick shares identical reads; every relay still checks its own route."""
    def setUp(self):
        self.project = 'newapi-ci-tick'
        self.ids = {'mysql': 'a'*64, 'postgres': 'b'*64}
        self.net = 'c'*64
        self.containers = {cid: self.container(cid, engine, ip)
                           for (engine, cid), ip in zip(self.ids.items(), ('172.19.0.2', '172.19.0.3'))}
        self.network = {'Id': self.net, 'Name': 'owned', 'Driver': 'bridge', 'Internal': True, 'Options': {},
            'Labels': {'com.docker.compose.project': self.project, 'com.docker.compose.network': 'isolated'},
            'Containers': {cid: {'IPv4Address': data['NetworkSettings']['Networks']['owned']['IPAddress'] + '/16'}
                           for cid, data in self.containers.items()},
            'IPAM': {'Config': [{'Subnet': '172.19.0.0/16', 'Gateway': '172.19.0.1'}]}}
        self.boots = ['boot-1']
        self.commands = []

    def container(self, cid, engine, ip):
        return {'Id': cid, 'Config': {'Image': runner.IMAGES.get(engine, runner.IMAGES['mysql']), 'Labels': {
            'com.docker.compose.project': self.project, 'com.docker.compose.service': engine}},
            'Image': runner.IMAGES.get(engine, runner.IMAGES['mysql']).split('@')[1],
            'State': {'Running': True, 'Health': {'Status': 'healthy'}},
            'HostConfig': {'Privileged': False, 'NetworkMode': 'owned'},
            'NetworkSettings': {'Ports': {}, 'Networks': {'owned': {'NetworkID': self.net, 'IPAddress': ip, 'GlobalIPv6Address': ''}}}}

    def fake_run(self, command, **kwargs):
        self.commands.append(tuple(command))
        if command[0] == 'colima':
            value = self.boots.pop(0) if len(self.boots) > 1 else self.boots[0]
            if isinstance(value, BaseException):
                raise value
            return value + '\n'
        if command[0] == '/usr/sbin/lsof':
            pid = int(command[command.index('-p') + 1])
            return f'p{pid}\nn127.0.0.1:{40000 + pid}\n'
        if command[-3:-1] == ['network', 'inspect']:
            return json.dumps([self.network])
        if command[-2] == 'inspect':
            return json.dumps([self.containers[command[-1]]])
        raise AssertionError(command)

    def relays(self):
        relays = []
        with patch.object(runner, 'run', side_effect=self.fake_run):
            for pid, (engine, cid) in enumerate(self.ids.items(), start=1):
                relay = runner.OwnedRelay(['docker'], self.project, engine, cid, '/unused')
                relay.process = unittest.mock.Mock(pid=pid)
                relay.process.poll.return_value = None
                relay.port, relay.boot = 40000 + pid, 'boot-1'
                relay.initial = relay.snapshot()
                relays.append(relay)
        self.commands.clear()
        return relays

    def kinds(self):
        names = {'colima': 'boot', '/usr/sbin/lsof': 'lsof'}
        return dict(collections.Counter(names.get(c[0], 'network' if 'network' in c else 'inspect') for c in self.commands))

    def routes(self):
        return patch.object(runner, 'run', side_effect=self.fake_run), patch.object(runner.os, 'getpgid', side_effect=lambda pid: pid)

    def test_one_tick_reads_each_identity_once_and_checks_every_listener(self):
        relays = self.relays()
        run, pgid = self.routes()
        with run, pgid:
            runner.check_relays(relays)
        self.assertEqual(self.kinds(), {'lsof': 4, 'inspect': 2, 'network': 1, 'boot': 1})
        self.assertEqual([c[c.index('-p') + 1] for c in self.commands if c[0] == '/usr/sbin/lsof'], ['1', '2', '1', '2'])
        self.commands.clear()
        relays[1].docker = ['docker', '--context', 'other']
        run, pgid = self.routes()
        with run, pgid:
            runner.check_relays(relays)
        self.assertEqual(self.kinds(), {'lsof': 4, 'inspect': 4, 'network': 2, 'boot': 1})

    def test_guarded_operations_take_a_fresh_sample_every_tick(self):
        relays = self.relays()
        stores = released.OwnedStores(Path('/unused'))
        stores.relays = relays
        process = unittest.mock.Mock(pid=999, args=['fixture'], returncode=0)
        process.communicate.side_effect = [subprocess.TimeoutExpired('fixture', 1), (b'ok', b'')]
        run, pgid = self.routes()
        with run, pgid, patch.object(released.subprocess, 'Popen', return_value=process), \
                patch.object(released, 'terminate_group') as cleanup:
            self.assertEqual(released.execute(['fixture'], guard=stores.check_routes), (0, b'ok', b''))
        cleanup.assert_not_called()
        # Pre-spawn, two wait slices and post-completion: four independent ticks.
        self.assertEqual(self.kinds(), {'lsof': 16, 'inspect': 8, 'network': 4, 'boot': 4})
        self.commands.clear()
        process.communicate.side_effect = [subprocess.TimeoutExpired('fixture', 1), ('ok', '')]
        run, pgid = self.routes()
        with run, pgid:
            runner.guarded_communicate(process, timeout=10, guard=functools.partial(runner.check_relays, relays))
        self.assertEqual(self.kinds(), {'lsof': 12, 'inspect': 6, 'network': 3, 'boot': 3})

    def test_final_sample_bypasses_shared_tick_and_observes_later_relay_change(self):
        relays = self.relays()
        self.boots = ['boot-1', 'boot-2']
        run, pgid = self.routes()
        with run, pgid, self.assertRaises(runner.RelayIdentityError):
            runner.check_relays(relays, fresh=True)
        self.assertEqual(self.kinds(), {'lsof': 4, 'inspect': 6, 'network': 2, 'boot': 2})

    def test_final_guard_failure_after_exit_zero_still_fails_and_settles_child(self):
        for entry, module, result in ((runner.run, runner, ('ok', '')),
                                      (released.execute, released, (b'ok', b''))):
            with self.subTest(entry=entry.__name__):
                process = unittest.mock.Mock(pid=999, args=['fixture'], returncode=0)
                process.communicate.return_value = result
                failure = runner.RelayIdentityError('final identity changed')
                final = unittest.mock.Mock(side_effect=failure)
                with patch.object(module.subprocess, 'Popen', return_value=process), \
                        patch.object(module, 'terminate_group', return_value=None) as cleanup, \
                        self.assertRaises(runner.RelayIdentityError):
                    entry(['fixture'], guard=unittest.mock.Mock(), final_guard=final)
                final.assert_called_once()
                cleanup.assert_called_once_with(process)
                process.communicate.assert_called_once()

    def test_final_guard_cannot_extend_the_child_deadline_or_retry_its_timeout(self):
        for failure_kind in ('deadline', 'timeout'):
            with self.subTest(failure=failure_kind):
                now = [0.0]
                process = unittest.mock.Mock(args=['fixture'], returncode=0)
                process.communicate.return_value = ('ok', '')
                def final():
                    if failure_kind == 'timeout':
                        raise subprocess.TimeoutExpired('final identity read', 1)
                    now[0] = 11.0
                with patch.object(runner.time, 'monotonic', side_effect=lambda: now[0]), \
                        self.assertRaises(subprocess.TimeoutExpired):
                    runner.guarded_communicate(process, timeout=10, guard=unittest.mock.Mock(), final_guard=final)
                process.communicate.assert_called_once()

    def test_failed_identity_read_is_never_memoized(self):
        relay = self.relays()[0]
        tick = {}
        with patch.object(runner, 'run', side_effect=[subprocess.TimeoutExpired('inspect', 5), 'raw']) as read:
            with self.assertRaises(subprocess.TimeoutExpired):
                relay.read(['docker', 'inspect', self.ids['mysql']], tick)
            self.assertEqual(tick, {})
            self.assertEqual(relay.read(['docker', 'inspect', self.ids['mysql']], tick), 'raw')
            self.assertEqual(relay.read(['docker', 'inspect', self.ids['mysql']], tick), 'raw')
            self.assertEqual(read.call_count, 2)

    def test_first_failing_relay_stops_the_tick_with_the_existing_error(self):
        for case, cause, message in (('boot_changed', runner.RelayIdentityError, 'VM boot changed during test'),
                                     ('boot_timeout', subprocess.TimeoutExpired, None),
                                     ('endpoint_changed', runner.RelayIdentityError, 'container/network endpoint changed during test'),
                                     ('recorded_boot_differs', runner.RelayIdentityError, 'VM boot changed during test')):
            with self.subTest(case=case):
                self.setUp()
                relays = self.relays()
                if case == 'boot_changed':
                    self.boots = ['boot-2']
                elif case == 'boot_timeout':
                    self.boots = [subprocess.TimeoutExpired('colima', 5)]
                elif case == 'endpoint_changed':
                    relays[0].initial = dict(relays[0].initial, ip='172.19.0.9')
                else:
                    relays[1].boot = 'boot-0'
                run, pgid = self.routes()
                with run, pgid, self.assertRaisesRegex(runner.RelayIdentityError, 'owned route identity verification failed') as caught:
                    runner.check_relays(relays)
                self.assertIsInstance(caught.exception.__cause__, cause)
                if message:
                    self.assertEqual(str(caught.exception.__cause__), message)
                listeners = [c[c.index('-p') + 1] for c in self.commands if c[0] == '/usr/sbin/lsof']
                self.assertEqual(listeners, ['1', '2', '1', '2'] if case == 'recorded_boot_differs' else ['1', '2', '1'])

    def test_failure_after_spawn_still_cleans_the_guarded_child(self):
        relays = self.relays()
        stores = released.OwnedStores(Path('/unused'))
        stores.relays = relays
        self.boots = ['boot-1', 'boot-2']
        process = unittest.mock.Mock(pid=999, args=['fixture'], returncode=0)
        run, pgid = self.routes()
        with run, pgid, patch.object(released.subprocess, 'Popen', return_value=process) as spawn, \
                patch.object(released, 'terminate_group', return_value='child cleanup unknown') as cleanup, \
                self.assertRaisesRegex(runner.RelayIdentityError, 'owned route identity verification failed') as caught:
            released.execute(['fixture'], guard=stores.check_routes)
        spawn.assert_called_once(); cleanup.assert_called_once_with(process)
        process.communicate.assert_not_called()
        self.assertEqual(caught.exception.process_cleanup_error, 'child cleanup unknown')

    def test_shared_sample_still_rejects_foreign_peers(self):
        relays = self.relays()
        foreign = 'd'*64
        self.containers[foreign] = self.container(foreign, 'redis', '172.19.0.4')
        self.network['Containers'][foreign] = {'IPv4Address': '172.19.0.4/16'}
        run, pgid = self.routes()
        with run, pgid, self.assertRaisesRegex(runner.RelayIdentityError, 'owned route identity verification failed') as caught:
            runner.check_relays(relays)
        self.assertEqual(str(caught.exception.__cause__), 'unexpected network peer')

    def test_cleaning_tick_binds_identity_without_route_probes(self):
        relays = self.relays()
        with tempfile.TemporaryDirectory() as tmp:
            stores = released.OwnedStores(Path(tmp))
            stores.relays = relays
            stores.relay_records = [{'engine': engine, 'container_id': cid, 'state': 'running', 'cleanup_attempts': []}
                                    for engine, cid in self.ids.items()]
            stores.cleaning = True
            run, pgid = self.routes()
            with run, pgid:
                stores.check_routes()
            self.assertEqual(self.kinds(), {'inspect': 6, 'network': 2})
            self.commands.clear()
            stores.cleaning = False
            stores.containers = dict(self.ids)
            stores.resources = [{'engine': 'mysql', 'name': 'newapi_ci_tick', 'container': self.ids['mysql'],
                                 'absent_before_create': True, 'state': 'created'}]
            relays[1].initial = dict(relays[1].initial, ip='172.19.0.9')
            run, pgid = self.routes()
            with run, pgid, patch.object(runner, 'terminate_group', return_value=None), \
                    patch.object(runner.socket, 'socket') as probe, patch.object(released.subprocess, 'Popen') as spawn:
                probe.return_value.__enter__.return_value.connect_ex.return_value = 1
                errors = stores.cleanup()
            spawn.assert_not_called()
            self.assertEqual([e['error'] for e in errors], ['owned database identity changed before cleanup'])
            self.assertEqual(stores.resources[0]['state'], 'cleanup_unknown')
            self.assertEqual([r['state'] for r in stores.relay_records], ['closed', 'closed'])
            self.assertEqual(self.kinds(), {'inspect': 6, 'network': 2})


class ClickHouseAuthContracts(unittest.TestCase):
    canary = "test-only-canary-0123456789<&/:@'\"abcdef"

    def auth(self, root):
        with patch.object(runner.secrets, 'token_urlsafe', return_value=self.canary) as random:
            auth = runner.ClickHouseAuth.create(Path(root).resolve() / 'private')
        random.assert_called_once_with(48)
        self.addCleanup(auth.close)
        return auth

    def driver_fixture(self, tmp, auth):
        stores = released.OwnedStores(Path(tmp).resolve())
        stores.clickhouse_auth = auth
        stores.containers = {'clickhouse': 'a'*64}
        stores.ports = {'clickhouse': 49999}
        relay = unittest.mock.Mock(port=49999)
        stores.relays = [relay]
        stores.relay_records = [{'engine': 'clickhouse', 'container_id': 'a'*64, 'state': 'running'}]
        main = stores.create('sqlite', 'newapi_ci_main')
        with patch.object(stores, 'database_exists', return_value=False), patch.object(stores, 'sql'):
            stores.create('clickhouse', 'newapi_ci_owned')
        env = {'NEWAPI_TEST_PROFILE': 'isolated-ci', 'SQL_DSN': 'local', 'SQLITE_PATH': main,
               'LOG_SQL_DSN': auth.dsn(49999, 'newapi_ci_owned')}
        return stores, env

    def test_private_loader_rejects_missing_empty_permissions_owner_links_and_extra_fields(self):
        for case in ('missing', 'empty', 'mode', 'owner', 'symlink', 'hardlink', 'directory_mode', 'file_directory', 'fifo', 'extra', 'xml_extra', 'wrong_password'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                auth = self.auth(tmp)
                password = auth.directory / 'password'
                xml = auth.directory / 'client.xml'
                if case == 'missing':
                    password.unlink()
                elif case == 'empty':
                    password.write_text('')
                elif case == 'mode':
                    password.chmod(0o644)
                elif case == 'symlink':
                    password.unlink(); password.symlink_to(xml)
                elif case == 'hardlink':
                    os.link(password, Path(tmp) / 'linked')
                elif case == 'file_directory':
                    password.unlink(); password.mkdir()
                elif case == 'fifo':
                    password.unlink(); os.mkfifo(password)
                elif case == 'directory_mode':
                    auth.directory.chmod(0o755)
                elif case == 'extra':
                    (auth.directory / 'unexpected.json').write_text('{}')
                elif case == 'xml_extra':
                    xml.write_bytes(xml.read_bytes().replace(b'</config>', b'<include>foreign</include></config>'))
                elif case == 'wrong_password':
                    xml.write_bytes(runner.ClickHouseAuth.client_xml('wrong-' + self.canary))
                with patch.object(runner.os, 'getuid', return_value=os.getuid()+1) if case == 'owner' else contextlib.nullcontext():
                    with self.assertRaises(ValueError) as error:
                        runner.ClickHouseAuth(auth.directory)
                    self.assertNotIn(self.canary, str(error.exception))
                # Tampering belongs to this synthetic fixture; explicit restoration avoids testing cleanup against a foreign object.
                if case == 'file_directory':
                    password.rmdir(); auth.owned.pop('password')
                if case in ('symlink', 'fifo'):
                    password.unlink()
                    auth.owned.pop('password')
                if case == 'extra':
                    (auth.directory / 'unexpected.json').unlink()
                auth.close()

    def test_xml_url_encoding_and_identity_guard(self):
        from urllib.parse import urlsplit, unquote
        import xml.etree.ElementTree as ET
        with tempfile.TemporaryDirectory() as tmp:
            auth = self.auth(tmp)
            root = ET.fromstring((auth.directory / 'client.xml').read_bytes())
            self.assertEqual({x.tag for x in root}, {'host', 'port', 'user', 'password'})
            self.assertEqual(root.findtext('password'), self.canary)
            dsn = auth.dsn(49999, 'newapi_ci_owned')
            parsed = urlsplit(dsn)
            self.assertEqual((parsed.hostname, parsed.port, unquote(parsed.password)), ('127.0.0.1', 49999, self.canary))
            self.assertNotIn(self.canary, dsn)
            self.assertNotIn(self.canary, auth.redact(self.canary + dsn + root.findtext('password')))
            (auth.directory / 'password').write_text('replacement-' + self.canary)
            (auth.directory / 'client.xml').write_bytes(auth.client_xml('replacement-' + self.canary))
            with self.assertRaises(ValueError):
                auth.dsn(49999, 'newapi_ci_owned')
            auth.close(); auth.close()

    def test_partial_create_cleanup_and_borrowed_loader_never_remove_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / 'partial'
            original = runner.os.open
            def fail_second(path, flags, *args):
                if str(path).endswith('client.xml'):
                    raise OSError('injected write failure')
                return original(path, flags, *args)
            with patch.object(runner.os, 'open', side_effect=fail_second), self.assertRaises(OSError):
                runner.ClickHouseAuth.create(root)
            self.assertFalse(root.exists())
            auth = self.auth(tmp)
            borrowed = runner.ClickHouseAuth(auth.directory); borrowed.close()
            self.assertTrue((auth.directory / 'password').exists())
            # A replaced file is not deleted by the original owner.
            original_path = auth.directory / 'password'
            displaced = Path(tmp) / 'displaced'; original_path.rename(displaced)
            original_path.write_text('foreign')
            with self.assertRaises(RuntimeError): auth.close()
            self.assertEqual(original_path.read_text(), 'foreign')
            original_path.unlink(); displaced.rename(original_path)
            auth.close()

    def spec(self, auth):
        return {'services': {'clickhouse': {'profiles': ['isolated-clickhouse'], 'image': runner.CLICKHOUSE_IMAGE,
            'pull_policy': 'never', 'platform': 'linux/arm64', 'environment': {
                'CLICKHOUSE_PASSWORD_FILE': '/run/newapi-clickhouse/password', 'CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT': '0'},
            'volumes': [{'type': 'bind', 'source': str(auth.directory), 'target': '/run/newapi-clickhouse',
                'read_only': True, 'bind': {'create_host_path': False}}], 'networks': {'isolated': {}},
            'healthcheck': {'test': ['CMD', 'clickhouse-client', '--config-file', runner.CLICKHOUSE_CLIENT, '--query', 'SELECT 1']}}},
            'networks': {'isolated': {'internal': True}}}

    def test_ch_profile_is_separate_and_rejects_unsafe_service_config(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {}, clear=True):
            auth = self.auth(tmp)
            spec = self.spec(auth)
            with patch.object(runner, 'run', return_value=json.dumps(spec)) as command:
                args, env = runner.clickhouse_compose(['docker'], 'newapi-ci-test', auth)
            self.assertIn('isolated-clickhouse', args)
            self.assertNotIn(self.canary, repr((args, env, command.call_args)))
            self.assertEqual(set(runner.IMAGES), {'mysql', 'postgres'})
            # Each default may be absent or explicitly rendered by Compose 5.6.
            for representation in range(8):
                rendered = copy.deepcopy(spec)
                if representation & 1: rendered['services']['clickhouse']['command'] = None
                if representation & 2: rendered['services']['clickhouse']['entrypoint'] = None
                if representation & 4: rendered['networks']['isolated']['ipam'] = {}
                original = copy.deepcopy(rendered)
                with self.subTest(defaults=representation), patch.object(runner, 'run', return_value=json.dumps(rendered)):
                    accepted, _ = runner.clickhouse_compose(['docker'], 'newapi-ci-test', auth)
                self.assertEqual(accepted, args)
                self.assertEqual(rendered, original)
            for field in ('command', 'entrypoint'):
                for value in ([], '', False, 0, {}, ['server'], 'server'):
                    changed = copy.deepcopy(spec)
                    changed['services']['clickhouse'][field] = value
                    with self.subTest(field=field, value=value), patch.object(runner, 'run', return_value=json.dumps(changed)), self.assertRaises(ValueError):
                        runner.clickhouse_compose(['docker'], 'newapi-ci-test', auth)
            for value in (None, [], '', False, 0, {'driver': 'default'}, {'config': []}, {'options': {}}):
                changed = copy.deepcopy(spec); changed['networks']['isolated']['ipam'] = value
                with self.subTest(ipam=value), patch.object(runner, 'run', return_value=json.dumps(changed)), self.assertRaises(ValueError):
                    runner.clickhouse_compose(['docker'], 'newapi-ci-test', auth)
            # No general null/false/empty stripping is permitted for unknown keys.
            for section, field, value in (('service', 'ports', None), ('service', 'privileged', False),
                                          ('service', 'cap_add', []), ('network', 'external', False),
                                          ('network', 'driver_opts', {}), ('network', 'extra', None)):
                changed = copy.deepcopy(spec)
                target = changed['services']['clickhouse'] if section == 'service' else changed['networks']['isolated']
                target[field] = value
                with self.subTest(section=section, field=field), patch.object(runner, 'run', return_value=json.dumps(changed)), self.assertRaises(ValueError):
                    runner.clickhouse_compose(['docker'], 'newapi-ci-test', auth)
            for case in ('extra_service', 'ports', 'privileged', 'network', 'password_env', 'skip_user_setup', 'access_management', 'initdb', 'rw', 'mount', 'argv', 'health', 'profile', 'host_path', 'extra_cap'):
                changed = copy.deepcopy(spec); service = changed['services']['clickhouse']
                if case == 'extra_service': changed['services']['mysql'] = {}
                elif case == 'ports': service['ports'] = [{'published': 9000}]
                elif case == 'privileged': service['privileged'] = True
                elif case == 'network': changed['networks']['isolated']['internal'] = False
                elif case == 'password_env': service['environment']['CLICKHOUSE_PASSWORD'] = self.canary
                elif case == 'skip_user_setup': service['environment']['CLICKHOUSE_SKIP_USER_SETUP'] = '1'
                elif case == 'access_management': service['environment']['CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT'] = '1'
                elif case == 'initdb': service['environment']['CLICKHOUSE_DB'] = 'default'
                elif case == 'rw': service['volumes'][0]['read_only'] = False
                elif case == 'mount': service['volumes'][0]['target'] = '/docker-entrypoint-initdb.d'
                elif case == 'argv': service['command'] = ['--password', self.canary]
                elif case == 'health': service['healthcheck']['test'] = ['CMD', 'clickhouse-client', '--query', 'SELECT 1']
                elif case == 'profile': service['profiles'] = ['isolated-ci']
                elif case == 'host_path': service['volumes'][0]['bind']['create_host_path'] = True
                elif case == 'extra_cap': service['cap_add'] = ['SYS_ADMIN']
                with self.subTest(case=case), patch.object(runner, 'run', return_value=json.dumps(changed)), self.assertRaises(ValueError) as error:
                    runner.clickhouse_compose(['docker'], 'newapi-ci-test', auth)
                self.assertNotIn(self.canary, str(error.exception))
            auth.close()

    def test_driver_failure_and_cancellation_are_redacted_without_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = self.auth(tmp); stores, env = self.driver_fixture(tmp, auth)
            from urllib.parse import quote
            leaked = (self.canary + ' ' + quote(self.canary, safe='') + ' ' + env['LOG_SQL_DSN']).encode()
            for label, dsn in [('correct-but-other-failure', env['LOG_SQL_DSN']),
                               ('absent', 'clickhouse://default@127.0.0.1:49999/newapi_ci_owned'),
                               ('wrong', 'clickhouse://default:wrong-test-secret@127.0.0.1:49999/newapi_ci_owned')]:
                child_env = dict(env, LOG_SQL_DSN=dsn)
                diagnostic = leaked + dsn.encode() + b' wrong-test-secret'
                with self.subTest(label=label), patch.object(released, 'execute', return_value=(1, diagnostic, diagnostic)):
                    code, out, err = stores.run_test(['fixture'], cwd=tmp, env=child_env, timeout=1)
                    self.assertEqual(code, 1)  # A mocked server refusal can never become a passed auth probe.
                    self.assertNotIn(self.canary.encode(), out+err)
                    self.assertNotIn(dsn.encode(), out+err)
                    if label == 'wrong': self.assertNotIn(b'wrong-test-secret', out+err)
            failure = RuntimeError('driver failed: '+self.canary)
            failure.process_cleanup_error = 'cleanup '+self.canary
            with patch.object(released, 'execute', side_effect=failure), self.assertRaises(RuntimeError) as caught:
                stores.run_test(['fixture'], cwd=tmp, env=env, timeout=1)
            self.assertIs(caught.exception, failure)
            self.assertNotIn(self.canary, str(failure)+failure.process_cleanup_error)
            with patch.object(released, 'execute') as execute, self.assertRaises(ValueError):
                stores.run_test(['fixture', env['LOG_SQL_DSN']], cwd=tmp, env=env, timeout=1)
            execute.assert_not_called(); auth.close()

    def test_driver_targets_and_aliases_rejected_before_any_process_or_route_io(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = self.auth(tmp); stores, env = self.driver_fixture(tmp, auth)
            original = env['LOG_SQL_DSN']
            variants = {
                'external': original.replace('127.0.0.1:49999', '203.0.113.10:9000'),
                'protected': original.replace('127.0.0.1:49999', '10.10.88.120:6379'),
                'subnet': original.replace('127.0.0.1:49999', '10.10.88.121:9000'),
                'other_port': original.replace(':49999/', ':49998/'),
                'other_database': original.replace('newapi_ci_owned', 'default'),
                'uncreated_database': original.replace('newapi_ci_owned', 'newapi_ci_unowned'),
                'http': original.replace('clickhouse://', 'http://'),
                'hostname': original.replace('127.0.0.1', 'localhost'),
                'ipv6': original.replace('127.0.0.1', '[::1]'),
                'other_user': original.replace('default:', 'other:'),
                'query': original + '?addr=203.0.113.10:9000',
                'fragment': original + '#target', 'empty': '',
            }
            changed = [(label, dict(env, LOG_SQL_DSN=dsn)) for label, dsn in variants.items()]
            changed += [('alias', dict(env, CLICKHOUSE_DSN=original)),
                        ('redis', dict(env, REDIS_CONN_STRING='redis://10.10.88.120:6379')),
                        ('sql_override', dict(env, SQL_DSN=variants['protected'])),
                        ('audit_override', dict(env, AUDIT_CLICKHOUSE_DSN=variants['other_port'])),
                        ('mysql_alias', dict(env, TEST_MYSQL_DSN=original)),
                        ('sqlite_foreign', dict(env, SQLITE_PATH=str(Path(tmp)/'foreign.db'))),
                        ('sqlite_missing', {k:v for k,v in env.items() if k != 'SQLITE_PATH'}),
                        ('primary_missing', {k:v for k,v in env.items() if k != 'SQL_DSN'}),
                        ('profile_missing', {k:v for k,v in env.items() if k != 'NEWAPI_TEST_PROFILE'})]
            for label, child_env in changed:
                with self.subTest(case=label), patch.object(released.subprocess, 'Popen') as spawn, \
                        patch.object(stores, 'check_routes') as guard, self.assertRaises(ValueError):
                    stores.run_test(['fixture'], cwd=tmp, env=child_env, timeout=1)
                spawn.assert_not_called(); guard.assert_not_called()
            stores.ports['clickhouse'] = 49998
            changed_port = dict(env, LOG_SQL_DSN=original.replace(':49999/', ':49998/'))
            with patch.object(released.subprocess, 'Popen') as spawn, self.assertRaises(ValueError):
                stores.run_test(['fixture'], cwd=tmp, env=changed_port, timeout=1)
            spawn.assert_not_called()
            stores.ports['clickhouse'] = 49999
            for state in ('create_pending', 'create_unknown', 'absent_after_cleanup'):
                stores.resources[0]['state'] = state
                with self.subTest(state=state), patch.object(released.subprocess, 'Popen') as spawn, self.assertRaises(ValueError):
                    stores.run_test(['fixture'], cwd=tmp, env=env, timeout=1)
                spawn.assert_not_called()
            auth.close()

    def test_same_owned_endpoint_all_auth_modes_preserve_real_guard_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = self.auth(tmp); stores, env = self.driver_fixture(tmp, auth)
            for credentials in ('default:'+runner.quote(self.canary, safe=''), 'default', 'default:wrong-test-secret'):
                dsn = 'clickhouse://'+credentials+'@127.0.0.1:49999/newapi_ci_owned'
                child_env = dict(env, LOG_SQL_DSN=dsn, AUDIT_CLICKHOUSE_DSN=dsn)
                process = unittest.mock.Mock(pid=99001, args=['fixture'], returncode=1)
                process.communicate.return_value = (dsn.encode(), dsn.encode())
                stores.relays[0].check.reset_mock()
                with self.subTest(mode=credentials.split(':')[0]), patch.object(released.subprocess, 'Popen', return_value=process) as spawn:
                    code, out, err = stores.run_test(['fixture'], cwd=tmp, env=child_env, timeout=1)
                self.assertEqual(code, 1)
                self.assertEqual(spawn.call_args.kwargs['env'], child_env)
                self.assertGreaterEqual(stores.relays[0].check.call_count, 3)
                self.assertNotIn(dsn.encode(), out+err)
            auth.close()

    def test_probe_secrets_rejected_in_argv_and_scrubbed_from_all_exception_fields(self):
        import traceback
        with tempfile.TemporaryDirectory() as tmp:
            auth = self.auth(tmp); stores, env = self.driver_fixture(tmp, auth)
            for password in (self.canary, 'wrong-test-secret<&/"', None):
                credentials = 'default' + (':'+runner.quote(password, safe='') if password is not None else '')
                dsn = 'clickhouse://'+credentials+'@127.0.0.1:49999/newapi_ci_owned'
                child_env = dict(env, LOG_SQL_DSN=dsn)
                secret = password or self.canary
                forms = (secret, runner.quote(secret, safe=''), runner.escape(secret), json.dumps(secret)[1:-1], dsn)
                for form in forms:
                    with patch.object(released.subprocess, 'Popen') as spawn, self.assertRaises(ValueError):
                        stores.run_test(['fixture', '--password', form], cwd=tmp, env=child_env, timeout=1)
                    spawn.assert_not_called()
                diagnostic = ' '.join(forms)
                for failure in (RuntimeError(diagnostic), subprocess.TimeoutExpired(['fixture', diagnostic], 1),
                                KeyboardInterrupt(diagnostic), subprocess.CalledProcessError(17, ['fixture', diagnostic])):
                    failure.output = diagnostic.encode(); failure.stderr = diagnostic.encode()
                    failure.process_cleanup_error = ['first '+diagnostic, 'second '+diagnostic]
                    failure.__cause__ = OSError(5, diagnostic, diagnostic)
                    failure.__context__ = ValueError(diagnostic)
                    failure.add_note(diagnostic)
                    with patch.object(released, 'execute', side_effect=failure), self.assertRaises(type(failure)) as caught:
                        stores.run_test(['fixture'], cwd=tmp, env=child_env, timeout=1)
                    self.assertIs(caught.exception, failure)
                    self.assertEqual(len(failure.process_cleanup_error), 2)
                    if isinstance(failure, subprocess.TimeoutExpired): self.assertEqual(failure.timeout, 1)
                    if isinstance(failure, subprocess.CalledProcessError): self.assertEqual(failure.returncode, 17)
                    rendered = str(failure)+repr(vars(failure))+repr(failure.args)+''.join(traceback.format_exception(failure))
                    for form in forms: self.assertNotIn(form, rendered)
                # The real timeout branch still kills/reaps and retains cleanup failure diagnostics.
                process = unittest.mock.Mock(pid=99001, args=['fixture'], returncode=None)
                with patch.object(released.subprocess, 'Popen', return_value=process), \
                        patch.object(runner.time, 'monotonic', side_effect=[0, 2]), \
                        patch.object(released, 'terminate_group', return_value=diagnostic) as close, \
                        self.assertRaises(subprocess.TimeoutExpired) as caught:
                    stores.run_test(['fixture'], cwd=tmp, env=child_env, timeout=1)
                close.assert_called_once()
                self.assertEqual(caught.exception.timeout, 1)
                self.assertTrue(caught.exception.process_cleanup_error)
                for form in forms: self.assertNotIn(form, repr(vars(caught.exception))+str(caught.exception))
            auth.close()

    def test_every_ch_sql_and_native_import_uses_restricted_client_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = self.auth(tmp); stores = released.OwnedStores(Path(tmp)); stores.clickhouse_auth = auth; stores.containers = {'clickhouse': 'a'*64}; stores.ports = {'clickhouse': 49999}
            backup = Path(tmp)/'backup'; backup.mkdir()
            (backup/'manifest.json').write_text(json.dumps({'database':'newapi_ci_old','tables':['logs']}))
            (backup/'logs.sql').write_text('CREATE TABLE newapi_ci_old.logs (id UInt64) ENGINE = MergeTree ORDER BY id')
            (backup/'logs.native').write_bytes(b'NativeFixture')
            with patch.object(stores, 'call', return_value=b'') as command:
                stores.sql('clickhouse', 'SELECT 1')
                stores.restore('clickhouse', 'newapi_ci_restored', backup)
            self.assertEqual(command.call_count, 3)
            for call in command.call_args_list:
                args = call.args[0]
                self.assertIn('--config-file', args); self.assertIn(runner.CLICKHOUSE_CLIENT, args)
                self.assertNotIn('--password', args); self.assertNotIn(self.canary, repr(call))
            auth.close()

    def test_absent_auth_and_mixed_profile_refuse_before_docker(self):
        with patch.object(runner, 'run') as command, self.assertRaises(ValueError):
            runner.OwnedRelay(['docker'], 'newapi-ci-test', 'clickhouse', 'a'*64, '/receipt')
        command.assert_not_called()
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {}, clear=True), patch.object(released, 'execute') as execute:
            with self.assertRaises(ValueError):
                released.OwnedStores(Path(tmp), {'containers': {'mysql':'a'*64, 'clickhouse':'b'*64}})
            execute.assert_not_called()

    def test_ch_snapshot_rejects_missing_auth_mount_override_and_extra_peer(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = self.auth(tmp)
            base = OwnedRelayContracts(); base.setUp()
            data, network = copy.deepcopy(base.d), copy.deepcopy(base.n)
            data['Config'].update(Image=runner.CLICKHOUSE_IMAGE, Entrypoint=['/entrypoint.sh'], Cmd=None,
                Env=['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LANG=en_US.UTF-8', 'TZ=UTC',
                     'CLICKHOUSE_CONFIG=/etc/clickhouse-server/config.xml', 'CLICKHOUSE_PASSWORD_FILE=/run/newapi-clickhouse/password',
                     'CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=0'])
            data['Config']['Labels']['com.docker.compose.service']='clickhouse'
            data['Image']=runner.CLICKHOUSE_IMAGE.split('@')[1]
            data['NetworkSettings']['Ports']={'9000/tcp':None}
            data['Mounts']=[{'Destination':'/run/newapi-clickhouse','Type':'bind','Source':str(auth.directory),'RW':False}]
            relay=runner.OwnedRelay(['docker'],base.project,'clickhouse',base.cid,'/receipt',clickhouse_auth=auth)
            with patch.object(runner,'run',side_effect=[json.dumps([data]),json.dumps([network]),json.dumps([data])]):
                self.assertEqual(relay.snapshot()['engine'],'clickhouse')
            for case in ('missing_mount','write_mount','wrong_mount','initdb_mount','password_env','entrypoint','ports','peer'):
                d,n=copy.deepcopy(data),copy.deepcopy(network)
                if case=='missing_mount':d['Mounts']=[]
                elif case=='write_mount':d['Mounts'][0]['RW']=True
                elif case=='wrong_mount':d['Mounts'][0]['Source']='/foreign'
                elif case=='initdb_mount':d['Mounts'].append({'Destination':'/docker-entrypoint-initdb.d'})
                elif case=='password_env':d['Config']['Env'].append('CLICKHOUSE_PASSWORD='+self.canary)
                elif case=='entrypoint':d['Config']['Entrypoint']=['/bin/sh']
                elif case=='ports':d['HostConfig']['PortBindings']={'9000/tcp':[{'HostIp':'0.0.0.0','HostPort':'9000'}]}
                elif case=='peer':n['Containers']['c'*64]={'IPv4Address':'172.19.0.3/16'}
                with self.subTest(case=case), patch.object(runner,'run',side_effect=[json.dumps([d]),json.dumps([n]),json.dumps([d])]), self.assertRaises((ValueError,runner.RelayIdentityError)) as error:
                    relay.snapshot()
                self.assertNotIn(self.canary,str(error.exception))
            auth.close()

    def test_ch_guard_tick_shares_self_inspect_and_keeps_auth_and_sole_peer_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = self.auth(tmp)
            base = OwnedRelayContracts(); base.setUp()
            data, network = copy.deepcopy(base.d), copy.deepcopy(base.n)
            data['Config'].update(Image=runner.CLICKHOUSE_IMAGE, Entrypoint=['/entrypoint.sh'], Cmd=None,
                Env=['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LANG=en_US.UTF-8', 'TZ=UTC',
                     'CLICKHOUSE_CONFIG=/etc/clickhouse-server/config.xml', 'CLICKHOUSE_PASSWORD_FILE=/run/newapi-clickhouse/password',
                     'CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=0'])
            data['Config']['Labels']['com.docker.compose.service']='clickhouse'
            data['Image']=runner.CLICKHOUSE_IMAGE.split('@')[1]
            data['NetworkSettings']['Ports']={'9000/tcp':None}
            data['Mounts']=[{'Destination':'/run/newapi-clickhouse','Type':'bind','Source':str(auth.directory),'RW':False}]
            relay=runner.OwnedRelay(['docker'],base.project,'clickhouse',base.cid,'/receipt',clickhouse_auth=auth)
            with patch.object(runner,'run',side_effect=[json.dumps([data]),json.dumps([network]),json.dumps([data])]):
                relay.initial=relay.snapshot()
            relay.process=unittest.mock.Mock(pid=7); relay.process.poll.return_value=None
            relay.port,relay.boot=40007,'boot-1'
            commands=[]
            def fake(command, **kwargs):
                kind={'colima':'boot','/usr/sbin/lsof':'lsof'}.get(command[0],'network' if 'network' in command else 'inspect')
                commands.append(kind)
                return {'boot':'boot-1\n','lsof':'p7\nn127.0.0.1:40007\n','network':json.dumps([network])}.get(kind,json.dumps([data]))
            with patch.object(runner,'run',side_effect=fake), patch.object(runner.os,'getpgid',side_effect=lambda pid: pid), \
                    patch.object(auth,'validate',wraps=auth.validate) as validate:
                runner.check_relays([relay])
            self.assertEqual(collections.Counter(commands),{'lsof':2,'inspect':1,'network':1,'boot':1})
            validate.assert_called_once()
            network['Containers']['c'*64]={'IPv4Address':'172.19.0.3/16'}
            with patch.object(runner,'run',side_effect=fake), patch.object(runner.os,'getpgid',side_effect=lambda pid: pid), \
                    self.assertRaises(runner.RelayIdentityError) as error:
                runner.check_relays([relay])
            self.assertEqual(str(error.exception.__cause__),'ClickHouse profile must be the only network peer')
            self.assertNotIn(self.canary,str(error.exception))
            auth.close()

    def test_current_boot_ch_mapping_starts_only_native_9000_loopback_relay(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth=self.auth(tmp); receipt=Path(tmp)/'receipt.json'
            required='metadata_hash metadata_object verified fixed_image platform manifest_type config_reference rootfs ready ready_boot host recorded_daemon recorded_context live_boot live_context live_daemon receipt_metadata_hash requested_image'.split()
            proof={'accepted':True,'identity_mode':'containerd-platform-manifest','config_proof':'config_bound_via_verified_manifest',
                'metadata_sha256':'6f7289f17ab9509426e76c1729356bbc0017ddc1dd2e58e74d8ea80c90560509',
                'image':runner.CLICKHOUSE_IMAGE,'socket':runner.SOCKET,'boot_id':'boot',
                'containerd_binding':{'accepted':True,'checks':{key:True for key in required}},
                'fields':{'Descriptor.mediaType':{'actual':'oci'},'RootFS.Layers':{'actual':[{'actual':'layer'}]}}}
            receipt.write_text(json.dumps(proof))
            image={'RepoDigests':[runner.CLICKHOUSE_IMAGE], 'Id':runner.CLICKHOUSE_IMAGE.split('@')[1],
                'Descriptor':{'digest':runner.CLICKHOUSE_IMAGE.split('@')[1],'mediaType':'oci'},
                'Os':'linux','Architecture':'arm64','RootFS':{'Type':'layers','Layers':['layer']}}
            relay=runner.OwnedRelay(['docker'],'newapi-ci-test','clickhouse','a'*64,receipt,clickhouse_auth=auth)
            answers=[json.dumps([{'Endpoints':{'docker':{'Host':runner.SOCKET}}}]),'boot',json.dumps([image]),
                json.dumps({'name':'colima-newapi-a03','status':'Running','sshLocalPort':2222}), 'hostname 127.0.0.1\nport 2222\n','']
            process=unittest.mock.Mock(pid=123);process.poll.return_value=None
            socket=unittest.mock.MagicMock();socket.__enter__.return_value.getsockname.return_value=('127.0.0.1',49999)
            with patch.object(runner,'run',side_effect=answers), patch.object(relay,'snapshot',return_value={'ip':'172.19.0.2'}), \
                 patch.object(relay,'check_listener'), patch.object(relay,'check'), patch.object(runner.socket,'socket',return_value=socket), \
                 patch.object(runner.subprocess,'Popen',return_value=process) as spawn:
                self.assertEqual(relay.start(),49999)
            argv=spawn.call_args.args[0]
            self.assertEqual(argv[argv.index('-L')+1],'127.0.0.1:49999:172.19.0.2:9000')
            self.assertNotIn(self.canary,repr(argv)+json.dumps(relay.receipt))
            # There was no real SSH child; this is a synthetic command/receipt contract only.
            relay.process=None;relay.port=None;auth.close()

    def test_secret_bearing_phase_snapshot_is_never_promoted(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth=self.auth(tmp); root=Path(tmp); evidence=root/'evidence'; evidence.mkdir()
            stores, env = self.driver_fixture(tmp, auth)
            def fixture(command, **kwargs):
                Path(kwargs['env']['A03_RESULT']).write_text(json.dumps({'leak':self.canary}))
                return 0, b'--- PASS: TestReleasedDatabaseGate', b''
            with patch.object(released,'execute',side_effect=fixture), self.assertRaises(RuntimeError):
                released.run_phase(root/'fixture','seed','sqlite','clickhouse',stores,env['SQLITE_PATH'],'newapi_ci_owned',evidence,'canary')
            self.assertFalse((evidence/'canary.snapshot.json').exists())
            self.assertFalse(list(root.glob('phase-result-*')))
            for p in evidence.iterdir(): self.assertNotIn(self.canary,p.read_text())
            auth.close()


class OrganizationMigrationContracts(unittest.TestCase):
    def test_exact_five_table_delta_and_full_structure_required(self):
        old = [{'table':'users','columns':[{'name':'id','type':'integer'}],'indexes':[]}]
        org = [{'table':name,'columns':[{'name':'id','type':'integer'}],
                'indexes':[{'name':'unique_slot','columns':['id'],'unique':True}]} for name in sorted(released.ORGANIZATION_TABLES)]
        current = old + org
        released.verify_release_schema(old,current,current)
        for label, changed in [('missing',current[:-1]),('extra',current+[{'table':'unapproved','columns':[],'indexes':[]}]),
                               ('only four',old+org[:-1])]:
            with self.subTest(label=label), self.assertRaises(ValueError):released.verify_release_schema(old,changed,current)
        for field in ('columns','indexes'):
            changed=copy.deepcopy(current);changed[-1][field][0]['unexpected']='mutation'
            with self.subTest(field=field),self.assertRaises(ValueError):released.verify_release_schema(old,changed,current)
        with self.assertRaises(ValueError):released.verify_release_schema(old,current)  # Independent log DB has no additions.
        changed=copy.deepcopy(current);changed[0]['columns'][0]['type']='text'
        with self.assertRaises(ValueError):released.verify_release_schema(old,changed,current)

    def test_postgres_snapshot_preserves_predicate_definition_and_constraint(self):
        index = {'name':'uk_prefill_name','columns':['name'],'unique':True,'known':True,
                 'primary':False,'primary_known':True,'partial':True,'partial_known':True,
                 'predicate':'(deleted_at IS NULL)','predicate_known':True,'predicate_null':False,
                 'definition':'CREATE UNIQUE INDEX uk_prefill_name ON public.prefill_groups USING btree (name) WHERE (deleted_at IS NULL)',
                 'access_method':'btree','constraint':None}
        original = [{'table':'prefill_groups','columns':[{'name':'name'}],'indexes':[index]}]
        released.verify_release_schema(original,copy.deepcopy(original))
        for field, value in [('predicate','(deleted_at IS NOT NULL)'),('predicate','((deleted_at IS NULL) AND (name <> ''))'),
                             ('definition',index['definition']+' TABLESPACE changed'),('access_method','hash'),
                             ('primary',True),('partial',False),('predicate_known',False),('predicate_null',True),
                             ('constraint',{'kind':'u','deferrable':True})]:
            changed=copy.deepcopy(original);changed[0]['indexes'][0][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):
                released.verify_release_schema(original,changed)

    def test_organization_required_events_bind_every_leaf_and_dialect(self):
        self.assertEqual(sum(len(gate.organization_required_leaves(d)) for d in ('sqlite','mysql','postgres')),65)
        package='github.com/QuantumNous/new-api/model'
        for dialect in ('sqlite','mysql','postgres'):
            events=[{'Action':'pass','Package':package,'Test':f'TestOrganizationLifecycleDatabaseMatrix/{dialect}/{case}'} for case in gate.ORGANIZATION_CASES]
            row_lock_names = []
            if dialect in ('mysql','postgres'):
                row_lock_names = [f'TestOrganizationLifecycleDatabaseMatrix/{dialect}/row_lock_expiry/{subject}'
                                  for subject in ('session','authorization','invitation','transfer')]
                events.extend({'Action':'pass','Package':package,'Test':name} for name in row_lock_names)
            events.append({'Action':'pass','Package':package})
            self.assertEqual(len(gate.validate_organization_events(events,0,dialect)),19 if dialect=='sqlite' else 23)
            for name in row_lock_names:
                for action in ('omitted','skip','fail'):
                    changed=[dict(event) for event in events if event.get('Test') != name]
                    if action!='omitted':changed.append({'Action':action,'Package':package,'Test':name})
                    with self.subTest(dialect=dialect,leaf=name,action=action),self.assertRaises(ValueError):
                        gate.validate_organization_events(changed,0,dialect)
            for unknown in ('clickhouse','unknown','',None):
                with self.subTest(unknown=unknown),self.assertRaises(ValueError):
                    gate.validate_organization_events(events,0,unknown)
            for changed,code in [(events[1:],0),(events[:-1],0),(events,1),
                                 (events+[{'Action':'skip'}],0),
                                 ([dict(e,Package='other/model') for e in events],0),
                                 ([dict(e,Test=e.get('Test','').replace('/'+dialect+'/', '/wrong/')) for e in events],0)]:
                with self.assertRaises(ValueError):gate.validate_organization_events(changed,code,dialect)

        package='github.com/QuantumNous/new-api/controller'
        events=[{'Action':'pass','Package':package,'Test':name} for name in gate.DELETION_REQUIRED]
        events.append({'Action':'pass','Package':package})
        self.assertEqual(len(gate.validate_required_events(events,0,package,gate.DELETION_REQUIRED)),21)
        for changed,code in [(events[1:],0),(events[:-1],0),(events,1),(events+[{'Action':'skip'}],0)]:
            with self.assertRaises(ValueError):gate.validate_required_events(changed,code,package,gate.DELETION_REQUIRED)

    def test_domain_runner_allocates_empty_owned_database_and_never_accepts_partial_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);stores=released.OwnedStores(root)
            stores.containers={'mysql':'a'*64};stores.ports={'mysql':49999}
            with patch.object(stores,'database_exists',return_value=False),patch.object(stores,'sql'), \
                 patch.object(stores,'run_test',return_value=(0,b'',b'')) as execute, \
                 self.assertRaises(ValueError):
                released.run_organization_matrix(root,Path('/go'),stores,root,dialects=('mysql',))
            self.assertEqual(json.loads((root/'organization-verdict.json').read_text())['required_leaf_count'],65)
            record=stores.resources[0]
            self.assertEqual(record['name'],'newapi_ci_organization_mysql')
            self.assertEqual(record['state'],'created');self.assertTrue(record['absent_before_create'])
            env=execute.call_args.kwargs['env']
            self.assertEqual(env['NEWAPI_REQUIRE_DATABASES'],'1')
            self.assertIn('/newapi_ci_organization_mysql?',env['TEST_MYSQL_DSN'])
            self.assertNotIn('TEST_POSTGRES_DSN',env)
            self.assertEqual(execute.call_args.args[0][-1],'^TestOrganizationLifecycleDatabaseMatrix$/^mysql$')


if __name__ == '__main__':
    unittest.main()


POSTGRES_METADATA_GO_TESTS = r"""
func TestPostgresIndexMetadataContract(t *testing.T) {
 table:=postgresTableIdentity{SchemaName:"owned",TableName:"organization_members",TableOID:100}
 base:=postgresIndexColumn{SchemaName:"owned",TableName:"organization_members",TableOID:100,IndexSchema:"owned",IndexName:"idx_org_member_user",IndexOID:200,ColumnCount:3,KeyCount:3,Valid:sql.NullBool{Bool:true,Valid:true},Ready:sql.NullBool{Bool:true,Valid:true},Live:sql.NullBool{Bool:true,Valid:true},Unique:sql.NullBool{Valid:true},Primary:sql.NullBool{Valid:true},Expression:sql.NullBool{Valid:true},Partial:sql.NullBool{Valid:true},Exclusion:sql.NullBool{Valid:true},Immediate:sql.NullBool{Bool:true,Valid:true},NullsNotDistinct:sql.NullBool{Valid:true},DefaultOpclass:sql.NullBool{Bool:true,Valid:true},DefaultCollation:sql.NullBool{Bool:true,Valid:true},DefaultOrder:sql.NullBool{Bool:true,Valid:true},PredicateKnown:sql.NullBool{Bool:true,Valid:true},Definition:"CREATE INDEX idx_org_member_user ON owned.organization_members USING btree (user_id, removed_at, organization_id)",KeyDefinition:"user_id",AccessMethod:"btree"}
 rows:=[]postgresIndexColumn{base,base,base}
 for i,name:=range []string{"user_id","removed_at","organization_id"} { rows[i].Position=i+1;rows[i].AttributeNumber=i+1;rows[i].ColumnName=name }
 indexes,err:=postgresOrderedIndexes(table,rows);require.NoError(t,err);require.Len(t,indexes,1)
 require.Equal(t,[]string{"user_id","removed_at","organization_id"},indexes[0].Columns())
 unique,known:=indexes[0].Unique();require.True(t,known);require.False(t,unique)
 primary,known:=indexes[0].PrimaryKey();require.True(t,known);require.False(t,primary)
 reversed:=append([]postgresIndexColumn(nil),rows...);reversed[0].ColumnName,reversed[2].ColumnName=reversed[2].ColumnName,reversed[0].ColumnName
 wrong,err:=postgresOrderedIndexes(table,reversed);require.NoError(t,err)
 require.NotEqual(t,indexes[0].Columns(),wrong[0].Columns(),"a physically different key order must remain different")
 for _,name:=range []string{"schema","table","table_oid","index_schema","index_name","index_oid","ordinal","missing","expression","attribute","invalid","partial","include","unique","primary"} {
  t.Run(name,func(t *testing.T){
   changed:=append([]postgresIndexColumn(nil),rows...)
   switch name {
   case "schema":changed[1].SchemaName="foreign"
   case "table":changed[1].TableName="foreign"
   case "table_oid":changed[1].TableOID=101
   case "index_schema":changed[1].IndexSchema="foreign"
   case "index_name":changed[1].IndexName="foreign"
   case "index_oid":changed[1].IndexOID=201
   case "ordinal":changed[1].Position=3
   case "missing":changed=changed[:2]
   case "expression":changed[1].Expression.Bool=true
   case "attribute":changed[1].AttributeNumber=0
   case "invalid":changed[1].Valid.Bool=false
   case "partial":changed[1].Partial.Bool=true
   case "include":changed[1].KeyCount=2
   case "unique":changed[1].Unique.Bool=true
   case "primary":changed[1].Primary.Bool=true
   }
   _,err:=postgresOrderedIndexes(table,changed);require.Error(t,err)
  })
 }
 for i:=range rows { rows[i].Unique.Bool=true;rows[i].Primary.Bool=true; rows[i].ConstraintID=sql.NullInt64{Int64:300,Valid:true};rows[i].ConstraintName=sql.NullString{String:"pk",Valid:true};rows[i].ConstraintKind=sql.NullString{String:"p",Valid:true};rows[i].ConstraintDeferrable=sql.NullBool{Valid:true};rows[i].ConstraintDeferred=sql.NullBool{Valid:true};rows[i].ConstraintValidated=sql.NullBool{Bool:true,Valid:true};rows[i].ConstraintDefinition=sql.NullString{String:"PRIMARY KEY (user_id, removed_at, organization_id)",Valid:true} }
 indexes,err=postgresOrderedIndexes(table,rows);require.NoError(t,err)
 unique,known=indexes[0].Unique();require.True(t,known);require.True(t,unique)
 primary,known=indexes[0].PrimaryKey();require.True(t,known);require.True(t,primary)
 // Use an owned SQLite connection as a deliberately incompatible catalog, without a network.
 local,err:=gorm.Open(sqlite.Open(":memory:"),&gorm.Config{Logger:logger.Default.LogMode(logger.Silent)});require.NoError(t,err)
 sqlDB,err:=local.DB();require.NoError(t,err);defer sqlDB.Close()
 pg,err:=gorm.Open(postgres.New(postgres.Config{Conn:sqlDB}),&gorm.Config{DisableAutomaticPing:true,Logger:logger.Default.LogMode(logger.Silent)});require.NoError(t,err)
 _,err=fixtureIndexes(pg,"organization_members");require.Error(t,err,"catalog query errors must not turn into empty successful metadata")
 statement:=pg.Session(&gorm.Session{DryRun:true}).Raw(postgresIndexColumnsSQL,int64(100),"owned","organization_members").Statement
 require.Equal(t,[]any{int64(100),"owned","organization_members"},statement.Vars)
 require.Contains(t,statement.SQL.String(),"t.oid = $1 AND tn.nspname = $2 AND t.relname = $3")
}


func TestPostgresIndexAliasScan(t *testing.T) {
 db,err:=gorm.Open(sqlite.Open(":memory:"),&gorm.Config{Logger:logger.Default.LogMode(logger.Silent)})
 require.NoError(t,err)
 sqlDB,err:=db.DB();require.NoError(t,err);defer sqlDB.Close()
 var version string;require.NoError(t,db.Raw("SELECT sqlite_version()").Scan(&version).Error)
 t.Log("actual SQLite scan fixture version="+version)
 // A02's exact SQL aliases must populate the real generated fixture structs.
 var identities []postgresTableIdentity
 require.NoError(t,db.Raw("SELECT 'owned' AS schema_name, 'organization_members' AS table_name, 100 AS table_oid").Scan(&identities).Error)
 require.Len(t,identities,1)
 t.Run("table_oid",func(t *testing.T){
  assert.Equal(t,int64(100),identities[0].TableOID)
  assert.Equal(t,"owned",identities[0].SchemaName)
  assert.Equal(t,"organization_members",identities[0].TableName)
 })
 t.Run("index_oids",func(t *testing.T){
  var rows []postgresIndexColumn
  require.NoError(t,db.Raw(`SELECT 'owned' AS schema_name, 'organization_members' AS table_name, 100 AS table_oid,
   'owned' AS index_schema, 'idx_org_member_user' AS index_name, 200 AS index_oid,
   1 AS position, 1 AS column_count, 1 AS key_count, 2 AS attribute_number, 'user_id' AS column_name,
   false AS "unique", false AS "primary", true AS valid, true AS ready, true AS live,
   false AS expression, false AS partial, false AS exclusion, true AS immediate, false AS nulls_not_distinct,
 true AS default_opclass, true AS default_collation, true AS default_order, NULL AS predicate, true AS predicate_known,
 'CREATE INDEX idx_org_member_user ON owned.organization_members USING btree (user_id)' AS definition,
 'user_id' AS key_definition, 'btree' AS access_method`).Scan(&rows).Error)
  require.Len(t,rows,1)
  assert.Equal(t,int64(100),rows[0].TableOID)
  assert.Equal(t,int64(200),rows[0].IndexOID)
  indexes,err:=postgresOrderedIndexes(identities[0],rows)
  require.NoError(t,err,"scanned catalog aliases must survive actual ordered metadata validation")
  require.Len(t,indexes,1)
  assert.Equal(t,[]string{"user_id"},indexes[0].Columns())
  unique,known:=indexes[0].Unique();assert.True(t,known);assert.False(t,unique)
  primary,known:=indexes[0].PrimaryKey();assert.True(t,known);assert.False(t,primary)
 })
}

type catalogDiagnosticWriter struct { text string; fail bool }
func (w *catalogDiagnosticWriter) Write(p []byte) (int,error) { if w.fail { return 0,io.ErrShortWrite };w.text+=string(p);return len(p),nil }

func TestPostgresPartialIndexContract(t *testing.T) {
 db,err:=gorm.Open(sqlite.Open(":memory:"),&gorm.Config{Logger:logger.Default.LogMode(logger.Silent)});require.NoError(t,err)
 sqlDB,err:=db.DB();require.NoError(t,err);defer sqlDB.Close()
 // Actual GORM scan populates every new required field, including false and SQL NULL.
 query:=`SELECT 'public' AS schema_name, 'prefill_groups' AS table_name, 100 AS table_oid,
 'public' AS index_schema, 'uk_prefill_name' AS index_name, 200 AS index_oid,
 1 AS position, 1 AS column_count, 1 AS key_count, 2 AS attribute_number, 'name' AS column_name,
 true AS "unique", false AS "primary", true AS valid, true AS ready, true AS live,
 false AS expression, true AS partial, false AS exclusion, true AS immediate,
 false AS nulls_not_distinct, true AS default_opclass, true AS default_collation, true AS default_order,
 '(deleted_at IS NULL)' AS predicate, true AS predicate_known,
 'CREATE UNIQUE INDEX uk_prefill_name ON public.prefill_groups USING btree (name) WHERE (deleted_at IS NULL)' AS definition,
 'name' AS key_definition, 'btree' AS access_method,
 NULL AS constraint_id, NULL AS constraint_name, NULL AS constraint_kind, NULL AS constraint_deferrable,
 NULL AS constraint_deferred, NULL AS constraint_validated, NULL AS constraint_definition`
 var scanned []postgresIndexColumn;require.NoError(t,db.Raw(query).Scan(&scanned).Error);require.Len(t,scanned,1)
 base:=scanned[0];table:=postgresTableIdentity{SchemaName:"public",TableName:"prefill_groups",TableOID:100}
 indexes,err:=postgresOrderedIndexes(table,scanned);require.NoError(t,err);require.Len(t,indexes,1)
 metadata:=indexes[0].(*postgresPhysicalIndex).Metadata
 assert.Equal(t,"(deleted_at IS NULL)",metadata["predicate"]);assert.Equal(t,false,metadata["predicate_null"])
 assert.Equal(t,true,metadata["partial"]);assert.Equal(t,true,metadata["partial_known"]);assert.Equal(t,false,metadata["primary"]);assert.Equal(t,true,metadata["primary_known"])
 assert.Equal(t,base.Definition,metadata["definition"]);assert.Equal(t,"btree",metadata["access_method"])
 encoded,err:=common.Marshal(metadata);require.NoError(t,err);assert.NotContains(t,string(encoded),"OID")
 for _,name:=range []string{"is_not_null","extra_and","other_table","other_index","not_unique","primary","null_predicate","empty_predicate","false_partial","unknown_partial","unknown_predicate","empty_definition","empty_key_definition","unknown_unique","unknown_primary","invalid","not_ready","not_live","expression","include","exclusion","method","opclass","collation","sort","not_immediate","nulls_not_distinct","foreign_schema","foreign_oid","zero_index_oid","duplicate","ordinal","constraint_unknown"} {
  t.Run(name,func(t *testing.T){
   row:=base;identity:=table
   switch name {
   case "is_not_null":row.Predicate.String="(deleted_at IS NOT NULL)"
   case "extra_and":row.Predicate.String="((deleted_at IS NULL) AND (name <> ''::text))"
   case "other_table":row.TableName="organizations";identity.TableName=row.TableName
   case "other_index":row.IndexName="another"
   case "not_unique":row.Unique.Bool=false
   case "primary":row.Primary.Bool=true
   case "null_predicate":row.Predicate.Valid=false
   case "empty_predicate":row.Predicate.String=""
   case "false_partial":row.Partial.Bool=false
   case "unknown_partial":row.Partial.Valid=false
   case "unknown_predicate":row.PredicateKnown.Valid=false
   case "empty_definition":row.Definition=""
   case "empty_key_definition":row.KeyDefinition=""
   case "unknown_unique":row.Unique.Valid=false
   case "unknown_primary":row.Primary.Valid=false
   case "invalid":row.Valid.Bool=false
   case "not_ready":row.Ready.Bool=false
   case "not_live":row.Live.Bool=false
   case "expression":row.Expression.Bool=true
   case "include":row.ColumnCount=2
   case "exclusion":row.Exclusion.Bool=true
   case "method":row.AccessMethod="hash"
   case "opclass":row.DefaultOpclass.Bool=false
   case "collation":row.DefaultCollation.Bool=false
   case "sort":row.DefaultOrder.Bool=false
   case "not_immediate":row.Immediate.Bool=false
   case "nulls_not_distinct":row.NullsNotDistinct.Bool=true
   case "foreign_schema":row.SchemaName="other"
   case "foreign_oid":row.TableOID=101
   case "zero_index_oid":row.IndexOID=0
   case "ordinal":row.Position=2
   case "constraint_unknown":row.ConstraintID=sql.NullInt64{Int64:300,Valid:true}
   }
   rows:=[]postgresIndexColumn{row};if name=="duplicate"{ rows=append(rows,row) }
   // The exact raw record is persisted before the semantic rejection.
   writer:=&catalogDiagnosticWriter{}
   require.NoError(t,writePostgresDiagnostic(writer,map[string]any{"phase":"seed","role":"main","rows":rows}))
   _,err:=postgresOrderedIndexes(identity,rows);require.Error(t,err)
   assert.Contains(t,writer.text,`"phase":"seed"`);assert.Contains(t,writer.text,"uk_prefill_name")
  })
 }
 // Missing/NULL aliases must not collapse into known false through GORM Scan.
 for _,alias:=range []string{"unique","primary","valid","ready","live","expression","partial","exclusion","immediate","nulls_not_distinct","default_opclass","default_collation","default_order","predicate_known"} {
  t.Run("scan_null_"+alias,func(t *testing.T){
   var rows []postgresIndexColumn
   quoted:=alias;if alias=="unique" || alias=="primary" {quoted="\""+alias+"\""}
   nullQuery:=query;replaced:=false
   for _,value:=range []string{"true","false"} {
    target:=value+" AS "+quoted
    for i:=0;i+len(target)<=len(query);i++ { if query[i:i+len(target)]==target {nullQuery=query[:i]+"NULL AS "+quoted+query[i+len(target):];replaced=true;break} }
    if replaced {break}
   }
   require.True(t,replaced)
   require.NoError(t,db.Raw(nullQuery).Scan(&rows).Error);require.Len(t,rows,1)
   require.Equal(t,int64(100),rows[0].TableOID,"all other required metadata remains populated")
   _,err:=postgresOrderedIndexes(table,rows);require.Error(t,err)
  })
 }
 // Scan immediate own unique and primary constraints, never conindid-only FK references.
 for _,kind:=range []string{"u","p"} {
  t.Run("constraint_"+kind,func(t *testing.T){
   row:=base;row.Partial=sql.NullBool{Valid:true};row.Predicate=sql.NullString{}
   var constraint []postgresIndexColumn
   require.NoError(t,db.Raw(`SELECT 300 AS constraint_id, 'own_key' AS constraint_name, ? AS constraint_kind,
 false AS constraint_deferrable, false AS constraint_deferred, true AS constraint_validated,
 'UNIQUE (name)' AS constraint_definition`,kind).Scan(&constraint).Error)
   require.Len(t,constraint,1);c:=constraint[0]
   row.ConstraintID=c.ConstraintID;row.ConstraintName=c.ConstraintName;row.ConstraintKind=c.ConstraintKind;row.ConstraintDeferrable=c.ConstraintDeferrable;row.ConstraintDeferred=c.ConstraintDeferred;row.ConstraintValidated=c.ConstraintValidated;row.ConstraintDefinition=c.ConstraintDefinition
   row.Primary=sql.NullBool{Bool:kind=="p",Valid:true}
   got,err:=postgresOrderedIndexes(table,[]postgresIndexColumn{row});require.NoError(t,err)
   assert.Equal(t,kind,got[0].(*postgresPhysicalIndex).Metadata["constraint"].(map[string]any)["kind"])
   for _,bad:=range []string{"deferrable","deferred","unvalidated","unknown","foreign_key","empty_definition"} {
    changed:=row
    switch bad { case "deferrable":changed.ConstraintDeferrable.Bool=true;case "deferred":changed.ConstraintDeferred.Bool=true;case "unvalidated":changed.ConstraintValidated.Bool=false;case "unknown":changed.ConstraintValidated.Valid=false;case "foreign_key":changed.ConstraintKind.String="f";case "empty_definition":changed.ConstraintDefinition.String="" }
    _,err:=postgresOrderedIndexes(table,[]postgresIndexColumn{changed});assert.Error(t,err,bad)
   }
  })
 }
 assert.Contains(t,postgresIndexColumnsSQL,"con.conrelid = t.oid AND con.contype IN ('p','u')")
 // Physical definition differences survive serialization, even for identical keys.
 changed:=base;changed.Definition+=" TABLESPACE different"
 other,err:=postgresOrderedIndexes(table,[]postgresIndexColumn{changed});require.NoError(t,err)
 assert.NotEqual(t,metadata,other[0].(*postgresPhysicalIndex).Metadata)
 writer:=&catalogDiagnosticWriter{}
 pg,err:=gorm.Open(postgres.New(postgres.Config{Conn:sqlDB}),&gorm.Config{DisableAutomaticPing:true,Logger:logger.Default.LogMode(logger.Silent)});require.NoError(t,err)
 t.Setenv("A03_PHASE","seed")
 _,_,err=collectPostgresIndexes(pg,"prefill_groups",writer);require.Error(t,err)
 assert.Contains(t,writer.text,`"diagnostic_incomplete":true`);assert.Contains(t,writer.text,`"phase":"seed"`);assert.NotContains(t,writer.text,"syntax error")
 require.Error(t,writePostgresDiagnostic(&catalogDiagnosticWriter{fail:true},map[string]any{"phase":"seed"}))
 require.Error(t,writePostgresDiagnostic(writer,map[string]any{"unsupported":make(chan int)}))
 assert.Contains(t,writer.text,"serialization_or_size_limit")
}

"""
