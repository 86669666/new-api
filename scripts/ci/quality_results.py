"""Exact-candidate quality verification in the immutable publisher trust domain.

There is deliberately no credential-loading or write-enabled CLI. A trusted host
injects read and staging capabilities, never module/command names from
an admission or a candidate. Deploy this file, consumer.py, and database_gate.py at one reviewed,
immutable revision, outside the candidate checkout; invoke Python with -I -B.

GitHub's Checks API has no atomic PR-head/replay compare-and-publish operation.
This module can stage only an in-progress check. It never sends success. A
sanctioned existing publisher must finish the exact staged check after its own
complete execution/authentication requirements. Collection independently reads
that App check and the current head again. A lost acknowledgement during staging
can leave only a non-green orphan; it burns the local durable admission claim.
No API claim here promises that a concurrent head change revokes an older SHA's
genuine check. It cannot qualify the new SHA and collection rejects head drift.
"""
import copy
from contextlib import closing
import importlib.util
import json
import os
from pathlib import Path
import re
import sqlite3
import time
import urllib.request
from typing import Protocol

# A fixed sibling in the same immutable deployment, never a candidate-supplied
# import path or module. -I excludes cwd/PYTHONPATH/user site-packages; the
# interpreter and system libraries must also belong to the trusted host.
_CONSUMER = Path(__file__).resolve().parents[2] / '.github/actions/box-formal-consumer/consumer.py'
_spec = importlib.util.spec_from_file_location('_trusted_receipt_consumer', _CONSUMER)
consumer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(consumer)
_DATABASE = Path(__file__).resolve().with_name('database_gate.py')
_database_spec = importlib.util.spec_from_file_location('_trusted_database_policy', _DATABASE)
database_policy = importlib.util.module_from_spec(_database_spec)
_database_spec.loader.exec_module(database_policy)
require = consumer.require
REPOSITORY = consumer.REPOSITORY
GATE = 'Required quality gate'
SCHEMA = 'box-quality-result/v1'
BACKEND = ('vet-root', 'vet-relaykit', 'vet-tokenkit', 'build-root', 'build-relaykit', 'build-tokenkit')
FRONTEND = ('frontend-install', 'frontend-typecheck', 'frontend-test')
DIALECTS = ('sqlite', 'mysql', 'postgres')
POLICY = ('policy-tests', 'consumer-tests')
# Trusted default inventory from bootstrap_test_runner.resource_partitions.
# Do not import the executor into this credential-bearing domain or allow an
# admission to reduce the denominator. Entries/leaves remain exact bindings.
FORMAL_TIERS = ('postgres', 'postgres-redis', 'wallet-sqlite', 'wallet-mysql',
                'wallet-postgres', 'lifecycle-sqlite', 'lifecycle-mysql',
                'lifecycle-postgres', 'sqlite')


class Reader(Protocol):
    """Authenticated read channel owned by the trusted host, not report JSON."""
    def repository(self): ...
    def pull(self, number): ...
    def commit(self, sha): ...
    def check(self, check_id): ...
    def run(self, run_id, attempt): ...


class AdmissionJournal:
    """Durable single-use claims in a trusted host-owned directory, never PR data.

    The host supplies the journal path as configuration. The candidate cannot
    read/write this store. Missing/failed journal storage prevents publication.
    """
    def __init__(self, path):
        self.path = path
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('CREATE TABLE IF NOT EXISTS admissions ('
                       'admission TEXT PRIMARY KEY, invocation TEXT UNIQUE NOT NULL, '
                       'request TEXT NOT NULL, check_id INTEGER, returned INTEGER NOT NULL DEFAULT 0)')

    def claim(self, request):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('INSERT INTO admissions(admission, invocation, request) VALUES (?, ?, ?)',
                       (request['admission_id'], request['invocation'],
                        consumer.canonical(request).decode()))

    def stage(self, request, check_id):
        with closing(sqlite3.connect(self.path)) as db, db:
            changed = db.execute('UPDATE admissions SET check_id=? WHERE admission=? '
                                 'AND request=? AND check_id IS NULL AND returned=0',
                                 (check_id, request['admission_id'], consumer.canonical(request).decode()))
            require(changed.rowcount == 1, 'admission already staged or changed')

    def pending(self, request):
        with closing(sqlite3.connect(self.path)) as db, db:
            row = db.execute('SELECT check_id FROM admissions WHERE admission=? AND request=? '
                             'AND returned=0',
                             (request['admission_id'], consumer.canonical(request).decode())).fetchone()
        require(row is not None and type(row[0]) is int and row[0] > 0, 'no exact pending publication')
        return row[0]

    def consume(self, request, check_id):
        with closing(sqlite3.connect(self.path)) as db, db:
            changed = db.execute('UPDATE admissions SET returned=1 WHERE admission=? AND request=? '
                                 'AND check_id=? AND returned=0',
                                 (request['admission_id'], consumer.canonical(request).decode(), check_id))
            require(changed.rowcount == 1, 'result replay or changed publication')


class GitHubStagingHTTP:
    """Concrete bounded HTTPS adapter for an ALREADY supplied installation token.

    No token minting, file loading, redirect following, generic URL, or success
    operation. The App-authenticated installation metadata reader remains an
    explicit independent capability supplied by the existing sanctioned host.
    """
    def __init__(self, token):
        self._token = token

    def request(self, method, path, payload):
        listing = method == 'GET' and path == '/installation/repositories?per_page=100' and payload is None
        staging = method == 'POST' and path == '/repos/' + REPOSITORY + '/check-runs'
        require(listing or staging, 'HTTP operation outside staging allowlist')
        if staging:
            require(set(payload) == {'name', 'head_sha', 'status', 'external_id', 'output'} and
                    payload['name'] == GATE and payload['status'] == 'in_progress' and
                    re.fullmatch('[0-9a-f]{40}', payload['head_sha']) is not None and
                    re.fullmatch('[0-9a-f]{64}', payload['external_id']) is not None,
                    'only non-green exact-SHA staging is allowed')
        request = urllib.request.Request('https://api.github.com' + path, method=method,
            data=None if payload is None else consumer.canonical(payload), headers={
                'Authorization': 'Bearer ' + self._token, 'Accept': 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json'})
        with urllib.request.build_opener(consumer.NoRedirect).open(request, timeout=30) as response:
            return json.load(response)


class GitHubPublication:
    """Concrete fixed-endpoint NON-GREEN staging over sanctioned HTTP callbacks.

    app_get is the existing App-authenticated read capability for installation
    metadata. installation_request is the existing installation-authenticated
    HTTP capability, limited by the host to the fixed endpoints below. Neither
    callback is selected by request data or loaded from an arbitrary module.
    This class never discovers credentials and never sends a success conclusion.
    """
    def __init__(self, app_get, installation_request):
        self._app_get = app_get
        self._installation_request = installation_request

    def verify_installation(self, repository_id):
        installation = self._app_get('/repos/' + REPOSITORY + '/installation')
        require(installation['id'] == consumer.INSTALLATION and
                installation['app_id'] == consumer.APP and installation['suspended_at'] is None and
                installation['permissions']['checks'] == 'write', 'unverified installed publisher')
        # Verify THIS installation credential has access to THIS repository.
        # The exact repository must appear in this authenticated response. A
        # missing repository (including pagination beyond this page) fails closed.
        accessible = self._installation_request('GET', '/installation/repositories?per_page=100', None)
        require(any(repo['id'] == repository_id and repo['full_name'] == REPOSITORY
                    for repo in accessible['repositories']), 'installation cannot access repository')

    def stage(self, request):
        payload = {'name': GATE, 'head_sha': request['candidate_sha'], 'status': 'in_progress',
                   'external_id': consumer.digest(request), 'output': {
                       'title': 'Awaiting authenticated quality publication',
                       'summary': 'Pending sanctioned publisher completion; this is not a quality success.',
                       'text': consumer.canonical(request).decode()}}
        require(len(payload['output']['text']) <= 65535, 'quality publication exceeds API text limit')
        check = self._installation_request('POST', '/repos/' + REPOSITORY + '/check-runs', payload)
        validate_gate(check, request, completed=False)
        return check['id']


def validate_gate(check, request, *, completed):
    require(type(check['id']) is int and check['id'] > 0, 'invalid quality check ID')
    require(check['app']['id'] == consumer.APP and check['app']['slug'] == 'new-api-box-formal',
            'wrong gate App')
    require(check['name'] == GATE and check['head_sha'] == request['candidate_sha'] and
            check['external_id'] == consumer.digest(request), 'wrong quality publication')
    require(json.loads(check['output']['text']) == request, 'partial or substituted quality publication')
    if completed:
        require(check['status'] == 'completed' and check['conclusion'] == 'success', 'gate is not successful')
    else:
        require(check['status'] == 'in_progress' and check['conclusion'] is None, 'unsafe staging response')


class GitHubReader:
    """Fixed GET-only public GitHub endpoints; no subprocess or credential lookup."""
    def __init__(self, token):
        self._token = token

    def repository(self):
        return consumer.api('/repos/' + REPOSITORY, self._token)

    def pull(self, number):
        require(type(number) is int and number > 0, 'invalid PR number')
        return consumer.api(f'/repos/{REPOSITORY}/pulls/{number}', self._token)

    def commit(self, sha):
        require(isinstance(sha, str) and re.fullmatch('[0-9a-f]{40}', sha), 'invalid commit')
        return consumer.api(f'/repos/{REPOSITORY}/git/commits/{sha}', self._token)

    def check(self, check_id):
        require(type(check_id) is int and check_id > 0, 'invalid check ID')
        return consumer.api(f'/repos/{REPOSITORY}/check-runs/{check_id}', self._token)

    def run(self, run_id, attempt):
        require(type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0,
                'invalid run identity')
        return consumer.api(f'/repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}', self._token)


def validate_quality(receipt, admission):
    """Additional complete-quality contract; existing receipt policy is unchanged."""
    quality = admission['quality']
    require(receipt['quality'] == quality, 'quality admission mismatch')
    require(quality['schema'] == SCHEMA, 'wrong quality schema')
    expected = admission['expected']
    require(quality['candidate_sha'] == expected['candidate_sha'] and
            quality['candidate_tree'] == expected['candidate_tree'], 'quality source mismatch')
    require(quality['execution_sha'] == expected['execution_sha'], 'quality execution mismatch')
    require(quality['admission_id'] == expected['admission_id'] and
            quality['attempt_id'] == expected['attempt_id'] and
            quality['invocation'] == expected['invocation'], 'quality attempt mismatch')
    require(re.fullmatch('[0-9a-f]{64}', quality['execution_evidence_sha256']) is not None,
            'missing execution evidence identity')
    require(type(quality['pull_number']) is int and quality['pull_number'] > 0, 'invalid PR')
    require(type(quality['head_repository_id']) is int and quality['head_repository_id'] > 0,
            'invalid head repository')
    require(re.fullmatch('[0-9a-f]{40}', quality['base_sha']) is not None, 'invalid base')
    require(set(expected['tiers']) == set(FORMAL_TIERS), 'required formal tier inventory changed')
    require(set(quality['results']) == {'backend', 'formal', 'frontend', 'database', 'policy'},
            'incomplete quality coverage')
    inventories = {'backend': list(BACKEND), 'frontend': list(FRONTEND),
                   'database': list(DIALECTS), 'formal': sorted(FORMAL_TIERS), 'policy': list(POLICY)}
    for group, inventory in inventories.items():
        result = quality['results'][group]
        require(result['required'] == inventory, 'quality inventory changed')
        require(result['unexecuted'] == [] and result['cleanup'] is True, 'incomplete quality result')
        require(type(result['exit']) is int and result['exit'] == 0, 'failed quality group')
        require(len(result['commands']) == len(inventory), 'partial quality commands')
        for name, command in zip(inventory, result['commands']):
            require(set(command) == {'id', 'exit', 'skipped', 'cleanup', 'log_sha256'},
                    'unexpected command metadata')
            require(command['id'] == name and type(command['exit']) is int and command['exit'] == 0,
                    'failed or substituted quality command')
            require(command['skipped'] is False and command['cleanup'] is True,
                    'skipped command or cleanup failure')
            require(re.fullmatch('[0-9a-f]{64}', command['log_sha256']) is not None,
                    'missing command evidence')
    require(quality['results']['database']['required_leaves'] == sorted(database_policy.REQUIRED),
            'missing required database leaf inventory')
    # The fixed tier names cannot shrink; operator-owned entry/leaf inventories,
    # test binaries, immutable assets and cleanup remain exact in consumer.
    return quality


def verify_current_head(reader, admission):
    quality = admission['quality']
    pull = reader.pull(quality['pull_number'])
    require(pull['number'] == quality['pull_number'] and pull['state'] == 'open' and
            pull['merged'] is False, 'PR is not an open candidate')
    require(pull['base']['repo']['id'] == admission['repository_id'] and
            pull['base']['repo']['full_name'] == REPOSITORY and pull['base']['ref'] == 'main',
            'wrong PR target')
    require(pull['head']['repo']['id'] == quality['head_repository_id'] and
            pull['head']['sha'] == admission['expected']['candidate_sha'] and
            pull['base']['sha'] == quality['base_sha'], 'PR head or base changed')


def validate_execution_support(report, admission):
    """A supplied raw report can veto, never authenticate, the App evidence.

    The host supplies data, not an executor module/path/callback. Absence leaves
    the existing authenticated-receipt route unchanged; a supplied report must
    match its authenticated content ID and cannot contradict complete execution.
    The current A executor always blocks formal scope, so its reports cannot
    pass this check. No conversion to a receipt or success record occurs here.
    """
    require(report['schema'] == 'quality-execution-evidence/v1' and
            report['authentication'] == 'UNAUTHENTICATED', 'wrong execution evidence schema')
    expected = admission['expected']
    binding = dict(schema='quality-execution-request/v1', repository=REPOSITORY,
                   **{key: expected[key] for key in
                      ('candidate_sha', 'candidate_tree', 'attempt_id', 'invocation')})
    require(report['binding'] == binding, 'execution evidence source or attempt mismatch')
    require(consumer.digest(report) == admission['quality']['execution_evidence_sha256'],
            'execution evidence digest mismatch')
    require(type(report['exit']) is int and report['exit'] == 0 and
            report['cleanup'] is True and report['unexecuted'] == [] and
            report['blocked'] == {} and report['error'] is None, 'incomplete execution evidence')
    commands = [*BACKEND, *FRONTEND, 'database', *POLICY]
    require(report['required'] == commands + ['formal'] and
            sorted(report['formal_required_tiers']) == sorted(FORMAL_TIERS),
            'execution evidence inventory mismatch')
    require([entry['id'] for entry in report['command_inventory']] == commands and
            consumer.digest(report['command_inventory']) == report['command_plan_sha256'],
            'execution command plan mismatch')
    require([entry['id'] for entry in report['commands']] == commands,
            'missing execution command evidence')
    for command in report['commands']:
        require(type(command['process_exit']) is int and command['process_exit'] == 0 and
                command['status'] == 'passed' and command['cleanup'] is True and
                command['process_reaped'] is True, 'failed execution command')
        for stream in ('stdout', 'stderr'):
            require(type(command[stream + '_bytes']) is int and command[stream + '_bytes'] >= 0 and
                    re.fullmatch('[0-9a-f]{64}', command[stream + '_sha256']) is not None,
                    'missing execution output evidence')
    require(type(report['started_at']) is int and type(report['completed_at']) is int and
            expected['not_before'] <= report['started_at'] <= report['completed_at'] <= expected['expires_at'],
            'execution evidence outside admission window')


def verify(admission, environment, reader, *, clock=time.time, execution_evidence=None):
    """Return verified DATA, never an admission token or publication authority."""
    consumer.validate_environment(environment, admission, int(clock()))
    repository = reader.repository()
    require(repository['id'] == admission['repository_id'] and repository['full_name'] == REPOSITORY,
            'repository identity changed')
    verify_current_head(reader, admission)
    check = reader.check(admission['check_run_id'])
    receipt = json.loads(check['output']['text'])
    receipt_hash = consumer.validate_check(check, receipt, admission, int(clock()))
    quality = validate_quality(receipt, admission)
    if execution_evidence is not None:
        validate_execution_support(execution_evidence, admission)
    commit = reader.commit(admission['expected']['candidate_sha'])
    require(commit['sha'] == admission['expected']['candidate_sha'] and
            commit['tree']['sha'] == admission['expected']['candidate_tree'], 'tested tree mismatch')
    workflow = quality['workflow']
    require(workflow['path'] == '.github/workflows/box-formal-receipt.yml'
            and workflow['ref'] == 'refs/heads/main' and workflow['event'] == 'workflow_dispatch'
            and workflow['sha'] == admission['expected']['consumer_sha'], 'untrusted workflow origin')
    for key in ('run_id', 'run_attempt', 'workflow_id'):
        require(type(workflow[key]) is int and workflow[key] > 0, 'invalid workflow identity')
    require(str(workflow['run_id']) == environment['GITHUB_RUN_ID'] and
            str(workflow['run_attempt']) == environment['GITHUB_RUN_ATTEMPT'] and
            environment['GITHUB_WORKFLOW_REF'] == REPOSITORY + '/' + workflow['path'] + '@refs/heads/main',
            'wrong consuming workflow invocation')
    # This is the current protected CONSUMER run, not evidence that Actions ran
    # candidate tests. Complete execution is proved only by the App receipt. The
    # operator finalizes its run binding while the environment is awaiting review.
    run = reader.run(workflow['run_id'], workflow['run_attempt'])
    require(run['id'] == workflow['run_id'] and run['run_attempt'] == workflow['run_attempt'] and
            run['workflow_id'] == workflow['workflow_id'] and run['path'] == workflow['path'] and
            run['event'] == workflow['event'] and run['head_branch'] == 'main' and
            run['head_sha'] == workflow['sha'] and
            run['repository']['id'] == admission['repository_id'] and
            run['repository']['full_name'] == REPOSITORY and
            run['head_repository']['id'] == admission['repository_id'], 'wrong consumer run')
    require(run['status'] == 'in_progress' and run['conclusion'] is None,
            'consumer run is not active')
    verify_current_head(reader, admission)
    consumer.validate_environment(environment, admission, int(clock()))
    return {'schema': SCHEMA, 'name': GATE, 'repository': REPOSITORY,
            'repository_id': admission['repository_id'], 'candidate_sha': admission['expected']['candidate_sha'],
            'candidate_tree': admission['expected']['candidate_tree'], 'receipt_sha256': receipt_hash,
            'check_run_id': admission['check_run_id'], 'admission_id': admission['expected']['admission_id'],
            'invocation': admission['expected']['invocation'], 'attempt_id': admission['expected']['attempt_id'],
            'expires_at': admission['expected']['expires_at'], 'quality': copy.deepcopy(quality)}


def stage_publication(admission, environment, reader, publisher, journal, *, clock=time.time,
                      execution_evidence=None):
    """Stage a non-green check; exceptions burn the admission, never retry writes."""
    admission = copy.deepcopy(admission)
    environment = dict(environment)
    execution_evidence = copy.deepcopy(execution_evidence)
    verified = verify(admission, environment, reader, clock=clock, execution_evidence=execution_evidence)
    publisher.verify_installation(admission['repository_id'])
    journal.claim(verified)
    require(verify(admission, environment, reader, clock=clock, execution_evidence=execution_evidence) == verified,
            'evidence changed after claim')
    check_id = publisher.stage(copy.deepcopy(verified))
    # A concurrent head update or an uncertain POST leaves ONLY a pending check
    # on the old exact SHA; it cannot produce a green current-head result.
    require(verify(admission, environment, reader, clock=clock, execution_evidence=execution_evidence) == verified,
            'evidence changed while staging')
    journal.stage(verified, check_id)
    return {'state': 'pending', 'check_run_id': check_id, 'candidate_sha': verified['candidate_sha']}


def collect_result(admission, environment, reader, publisher, journal, *, clock=time.time,
                   execution_evidence=None):
    """Return only a complete pre-existing App result, once, for the current head.

    There are no network writes here. A failure cannot publish a new green check.
    Existing genuine success belongs to its immutable SHA; it is not a guarantee
    that this PR's head/base will remain unchanged after the final read.
    """
    admission = copy.deepcopy(admission)
    environment = dict(environment)
    execution_evidence = copy.deepcopy(execution_evidence)
    verified = verify(admission, environment, reader, clock=clock, execution_evidence=execution_evidence)
    publisher.verify_installation(admission['repository_id'])
    check_id = journal.pending(verified)
    check = reader.check(check_id)
    require(check['id'] == check_id, 'wrong published check')
    validate_gate(check, verified, completed=True)
    require(verify(admission, environment, reader, clock=clock, execution_evidence=execution_evidence) == verified,
            'evidence changed during collection')
    # Re-read the published object as well: incomplete/changed publication cannot
    # be substituted between receipt verification and final result consumption.
    published = reader.check(check_id)
    require(published == check, 'publication changed during collection')
    verify_current_head(reader, admission)
    consumer.validate_environment(environment, admission, int(clock()))
    journal.consume(verified, check_id)
    return {'state': 'verified', 'check_run_id': check_id, 'result': verified}


def main():
    # This entry point performs reads only, on the protected consumer checkout.
    # Publication is available solely through the trusted host's injected object.
    admission = json.loads(os.environ['BOX_FORMAL_ADMISSION'])
    result = verify(admission, os.environ, GitHubReader(os.environ['GITHUB_TOKEN']))
    print(json.dumps({key: result[key] for key in
                      ('schema', 'candidate_sha', 'candidate_tree', 'check_run_id', 'receipt_sha256')},
                     sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Quality evidence rejected; no publication authorization granted.')
