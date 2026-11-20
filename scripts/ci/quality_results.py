"""Exact-candidate quality verification in the immutable publisher trust domain.

There is deliberately no credential-loading or write-enabled CLI. A trusted host
injects read and staging capabilities, never module/command names from
an admission or a candidate. Deploy this file, consumer.py, and database_gate.py at one reviewed,
immutable revision, outside the candidate checkout; invoke Python with -I -B.
The separate premerge CLI resolves only public checkout coordinates on a hosted
workflow checkout, without admission data or any quality authorization.

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
import sys
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
_release_spec = importlib.util.spec_from_file_location(
    '_trusted_release_policy', Path(__file__).with_name('release_policy.py'))
release_policy = importlib.util.module_from_spec(_release_spec)
_release_spec.loader.exec_module(release_policy)
_delta_spec = importlib.util.spec_from_file_location(
    'newapi_reviewed_formal_delta', Path(__file__).with_name('formal_delta.py'))
delta = importlib.util.module_from_spec(_delta_spec)
_delta_spec.loader.exec_module(delta)
_static_delta_spec = importlib.util.spec_from_file_location(
    'newapi_reviewed_static_delta', Path(__file__).with_name('formal_static_delta.py'))
static_delta = importlib.util.module_from_spec(_static_delta_spec)
_static_delta_spec.loader.exec_module(static_delta)
_usage_delta_spec = importlib.util.spec_from_file_location(
    'newapi_reviewed_usage_delta', Path(__file__).with_name('formal_usage_delta.py'))
usage_delta = importlib.util.module_from_spec(_usage_delta_spec)
_usage_delta_spec.loader.exec_module(usage_delta)
_invitation_delta_spec = importlib.util.spec_from_file_location(
    'newapi_reviewed_invitation_delta', Path(__file__).with_name('formal_invitation_delta.py'))
invitation_delta = importlib.util.module_from_spec(_invitation_delta_spec)
_invitation_delta_spec.loader.exec_module(invitation_delta)
_oauth_delta_spec = importlib.util.spec_from_file_location(
    'newapi_reviewed_oauth_delta', Path(__file__).with_name('formal_oauth_delta.py'))
oauth_delta = importlib.util.module_from_spec(_oauth_delta_spec)
_oauth_delta_spec.loader.exec_module(oauth_delta)
_client_events_delta_spec = importlib.util.spec_from_file_location(
    'newapi_reviewed_client_events_delta', Path(__file__).with_name('formal_client_events_delta.py'))
client_events_delta = importlib.util.module_from_spec(_client_events_delta_spec)
_client_events_delta_spec.loader.exec_module(client_events_delta)
_relay_log_delta_spec = importlib.util.spec_from_file_location(
    'newapi_reviewed_relay_log_delta', Path(__file__).with_name('formal_relay_log_delta.py'))
relay_log_delta = importlib.util.module_from_spec(_relay_log_delta_spec)
_relay_log_delta_spec.loader.exec_module(relay_log_delta)

require = consumer.require
REPOSITORY = consumer.REPOSITORY
GATE = 'Required quality gate'
PRIVATE_EVIDENCE_GATE = 'Box formal quality result'
SCHEMA = 'box-quality-result/v1'
PRIVATE_EVIDENCE_SCHEMA = 'box-quality-result/v2'
TERMINAL_SCHEMA = 'box-quality-terminal/v2'
TERMINAL_SCHEMA_V4 = 'box-quality-terminal/v4'
TERMINAL_SCHEMA_V5 = 'box-quality-terminal/v5'
TERMINAL_SCHEMA_V6 = 'box-quality-terminal/v6'
TERMINAL_SCHEMA_V7 = static_delta.TERMINAL_SCHEMA
TERMINAL_SCHEMA_V8 = usage_delta.TERMINAL_SCHEMA
TERMINAL_SCHEMA_V9 = invitation_delta.TERMINAL_SCHEMA
TERMINAL_SCHEMA_V10 = oauth_delta.TERMINAL_SCHEMA
TERMINAL_SCHEMA_V11 = client_events_delta.TERMINAL_SCHEMA
TERMINAL_SCHEMA_V12 = relay_log_delta.TERMINAL_SCHEMA
TIMED_TERMINAL_SCHEMAS = (TERMINAL_SCHEMA_V4, TERMINAL_SCHEMA_V5, TERMINAL_SCHEMA_V6,
                          TERMINAL_SCHEMA_V7, TERMINAL_SCHEMA_V8, TERMINAL_SCHEMA_V9,
                          TERMINAL_SCHEMA_V10, TERMINAL_SCHEMA_V11, TERMINAL_SCHEMA_V12)
REUSE_HOSTED = {'run_id': 44403089902, 'attempt': 1, 'workflow_blob': 'c123990e4a8c9fd981b721455a8edbc65b62dfc5'}
FORMAL_WORKFLOW_ID = 402689897
CI_WORKFLOW_ID = 389317795
REVIEWER_ID = 3104616
CONSUMER_JOB = ('box-formal-consumer-v2', 27663161499, 'Verify authenticated box receipt',
                'Verify complete private evidence')
TERMINAL_JOB = ('box-formal-terminal', 27663161709, 'Review formal quality evidence', 'Verify reviewed execution')
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
    def latest_run(self, run_id): ...
    def approvals(self, run_id): ...


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
            fields = {'name', 'head_sha', 'status', 'external_id', 'output'}
            require(type(payload) is dict and set(payload) - {'started_at'} == fields and
                    payload['name'] in (GATE, PRIVATE_EVIDENCE_GATE) and payload['status'] == 'in_progress' and
                    re.fullmatch('[0-9a-f]{40}', payload['head_sha']) is not None and
                    re.fullmatch('[0-9a-f]{64}', payload['external_id']) is not None,
                    'only non-green exact-SHA staging is allowed')
            if 'started_at' in payload:
                consumer.evidence.github_time(payload, 'started_at')
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
    def __init__(self, app_get, installation_request, *, clock=time.time):
        self._clock = clock
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
        payload = {'name': request['name'], 'head_sha': request['candidate_sha'], 'status': 'in_progress',
                   'external_id': consumer.digest(request), 'output': {
                       'title': 'Awaiting authenticated quality publication',
                       'summary': 'Pending sanctioned publisher completion; this is not a quality success.',
                       'text': consumer.canonical(request).decode()}}
        if request['schema'] in TIMED_TERMINAL_SCHEMAS:
            now = int(self._clock())
            validate_timed_artifact(request, now)
            payload['started_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now))
        require(len(payload['output']['text']) <= 65535, 'quality publication exceeds API text limit')
        check = self._installation_request('POST', '/repos/' + REPOSITORY + '/check-runs', payload)
        validate_gate(check, request, completed=False)
        return check['id']


def validate_timed_artifact(request, now):
    if request['schema'] == TERMINAL_SCHEMA_V6:
        delta.validate_reference(request['artifact'], now)
    elif request['schema'] == TERMINAL_SCHEMA_V7:
        static_delta.validate_reference(request['artifact'], now)
    elif request['schema'] == TERMINAL_SCHEMA_V8:
        usage_delta.validate_reference(request['artifact'], now)
    elif request['schema'] == TERMINAL_SCHEMA_V9:
        invitation_delta.validate_reference(request['artifact'], now)
    elif request['schema'] == TERMINAL_SCHEMA_V10:
        oauth_delta.validate_reference(request['artifact'], now)
    elif request['schema'] == TERMINAL_SCHEMA_V11:
        client_events_delta.validate_reference(request['artifact'], now)
    elif request['schema'] == TERMINAL_SCHEMA_V12:
        relay_log_delta.validate_reference(request['artifact'], now)
    else:
        consumer.evidence.validate_reference(request['artifact'], now)


def validate_gate(check, request, *, completed):
    require(type(check['id']) is int and check['id'] > 0, 'invalid quality check ID')
    require(check['app']['id'] == consumer.APP and check['app']['slug'] == 'new-api-box-formal',
            'wrong gate App')
    require(check['name'] == request['name'] in (GATE, PRIVATE_EVIDENCE_GATE) and
            check['head_sha'] == request['candidate_sha'] and
            check['external_id'] == consumer.digest(request), 'wrong quality publication')
    # Ordinary equality aliases JSON booleans, integers and floats. Compare
    # canonical data to preserve types; this does not authenticate the source.
    require(consumer.canonical(json.loads(check['output']['text'],
            object_pairs_hook=consumer.unique_json_fields)) == consumer.canonical(request),
            'partial or substituted quality publication')
    if request.get('schema') in TIMED_TERMINAL_SCHEMAS:
        binding = request['artifact']['identity']
        consumer.evidence.check_times(check, binding, binding['release_expires_at'], completed=completed)
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

    def latest_run(self, run_id):
        require(type(run_id) is int and run_id > 0, 'invalid run identity')
        return consumer.api(f'/repos/{REPOSITORY}/actions/runs/{run_id}', self._token)

    def approvals(self, run_id):
        require(type(run_id) is int and run_id > 0, 'invalid run identity')
        return consumer.api(f'/repos/{REPOSITORY}/actions/runs/{run_id}/approvals', self._token)

    def jobs(self, run_id, attempt):
        require(type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0,
                'invalid job query')
        response = consumer.api(
            f'/repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100', self._token)
        require(response['total_count'] == len(response['jobs']), 'incomplete job inventory')
        return response['jobs']

    def hosted_workflow_blob(self, sha):
        require(re.fullmatch('[0-9a-f]{40}', sha) is not None, 'invalid hosted source')
        return consumer.api(f'/repos/{REPOSITORY}/contents/.github/workflows/ci.yml?ref={sha}',
                            self._token)['sha']

    def formal_quality_check(self, sha):
        require(re.fullmatch('[0-9a-f]{40}', sha) is not None, 'invalid quality source')
        response = consumer.api(f'/repos/{REPOSITORY}/commits/{sha}/check-runs?'
                                f'check_name=Box%20formal%20quality%20result&app_id={consumer.APP}',
                                self._token)
        require(response['total_count'] == 1 and len(response['check_runs']) == 1,
                'unique signed formal quality result required')
        return response['check_runs'][0]


def successful_job(jobs, name, sha, steps):
    selected = [job for job in jobs if job['name'] == name]
    require(len(selected) == 1, 'missing or ambiguous required job')
    job = selected[0]
    passed = {step['name'] for step in job['steps']
              if step['status'] == 'completed' and step['conclusion'] == 'success'}
    require(job['head_sha'] == sha and job['status'] == 'completed' and
            job['conclusion'] == 'success' and set(steps) <= passed, 'required job did not pass')
    return job


def verify_reviewed_dispatch(reader, run_id, identity, job, *, active=False, title=None, now=None, after=None, completed_after=None,
                             control_ref=None, exact_start=None):
    evidence = consumer.evidence
    require(type(run_id) is int and run_id > 0, 'invalid dispatch run ID')
    run = reader.latest_run(run_id)
    v4 = 'release_not_before' in identity
    ref = control_ref or (evidence.CONTROL_REF_V4 if v4 else evidence.CONTROL_REF)
    if v4:
        created = evidence.github_time(run, 'created_at')
        require(type(now) is int and identity['release_not_before'] <= created <= now <= identity['release_expires_at']
                and (after is None or after <= created) and (exact_start is None or exact_start == created),
                'reviewed dispatch outside release order')
    require(run['id'] == run_id and run['run_attempt'] == 1 and
            run['workflow_id'] == FORMAL_WORKFLOW_ID and run['path'] == evidence.WORKFLOW_PATH and
            run['event'] == 'workflow_dispatch' and run['head_branch'] == ref.removeprefix('refs/heads/') and
            run['head_sha'] == identity['consumer_sha'] and run['repository']['id'] == identity['repository_id'] and
            run['repository']['full_name'] == REPOSITORY and run['head_repository']['id'] == identity['repository_id'] and
            run['actor']['id'] == run['triggering_actor']['id'] == evidence.TRIGGER_ID, 'wrong protected App dispatch')
    if title is not None:
        require(run['display_title'] == title, 'terminal run reviewed a different admission')
    environment_name, environment_id, job_name, step_name = job
    approvals = [review for review in reader.approvals(run_id) if any(
        env['name'] == environment_name and env['id'] == environment_id for env in review['environments'])]
    require(len(approvals) == 1 and approvals[0]['state'] == 'approved' and
            approvals[0]['user']['id'] == REVIEWER_ID, 'missing independent deployment approval')
    if active:
        require(run['status'] == 'in_progress' and run['conclusion'] is None, 'wrong active terminal run')
    else:
        require(run['status'] == 'completed' and run['conclusion'] == 'success', 'reviewed workflow did not pass')
        protected_job = successful_job(reader.jobs(run_id, 1), job_name, identity['consumer_sha'], (step_name,))
        if v4:
            finished = evidence.github_time(protected_job, 'completed_at')
            updated = evidence.github_time(run, 'updated_at')
            require(created <= finished <= updated <= now and (completed_after is None or completed_after <= finished), 'reviewed run or job outside release window')
            return updated


def verify_hosted_jobs(reader, hosted, identity):
    require(type(hosted) is dict and set(hosted) == {'run_id', 'attempt', 'workflow_blob'},
            'invalid hosted run binding')
    run_id, attempt, blob = hosted['run_id'], hosted['attempt'], hosted['workflow_blob']
    run = reader.run(run_id, attempt)
    require(run['id'] == run_id and run['run_attempt'] == attempt and run['workflow_id'] == CI_WORKFLOW_ID and
            run['path'] == '.github/workflows/ci.yml' and run['event'] == 'pull_request' and
            run['repository']['id'] == identity['repository_id'] and
            run['head_repository']['id'] == identity['head_repository_id'] and
            run['head_sha'] == identity['candidate_sha'], 'wrong hosted premerge run')
    require(any(pull['number'] == identity['pull_number'] and pull['head']['sha'] == identity['candidate_sha'] and
                pull['head']['repo']['id'] == identity['head_repository_id'] and pull['base']['ref'] == 'main' and
                pull['base']['sha'] == identity['base_sha'] and pull['base']['repo']['id'] == identity['repository_id']
                for pull in run['pull_requests']), 'hosted run does not belong to the admitted PR')
    require(re.fullmatch('[0-9a-f]{40}', blob) is not None and
            reader.hosted_workflow_blob(identity['candidate_sha']) == blob, 'unreviewed hosted CI definition')
    verify_hosted_job_steps(reader, hosted, identity['candidate_sha'])


def verify_hosted_job_steps(reader, hosted, candidate_sha):
    jobs = reader.jobs(hosted['run_id'], hosted['attempt'])
    for name, steps in (
        ('Require supported premerge event', ('Resolve supported current open PR through read-only API',)),
        ('Backend vet, build, and test', ('Vet root module', 'Vet relaykit independently', 'Vet tokenkit independently',
            'Build root module', 'Build relaykit independently', 'Build tokenkit independently',
            'Policy and consumer regression tests')),
        ('Frontend typecheck and test', ('Install dependencies', 'Typecheck', 'Test')),
        ('Required real database contracts', ('Required three-database suite (no skips)',)),
    ):
        successful_job(jobs, name, candidate_sha, steps)


def terminal_run_title(reference, receipt_check_id, consumer_run, hosted, quality_sha256):
    intent = dict(artifact=reference, receipt_check_id=receipt_check_id, consumer_run=consumer_run,
                  hosted=hosted, quality_sha256=quality_sha256)
    return 'Formal terminal ' + consumer.digest(intent)


def historical_receipt_check(reader, reference):
    evidence = consumer.evidence
    old = reference['historical']
    check = reader.check(evidence.REUSE_CHECK_ID)
    require(check['id'] == evidence.REUSE_CHECK_ID and check['app']['id'] == consumer.APP and
            check['app']['slug'] == 'new-api-box-formal' and check['name'] == consumer.CHECK and
            check['head_sha'] == old['identity']['candidate_sha'] and check['status'] == 'completed' and
            check['conclusion'] == 'success' and
            evidence.canonical(evidence.decode(check['output']['text'])) == evidence.canonical(old),
            'wrong historical receipt check')
    finished = evidence.github_time(check, 'completed_at')
    evidence.check_times(check, old['identity'], finished)
    return check, finished


def load_reused_evidence(reference, reader, fetch):
    """Load sealed historical bytes using C1's original authenticated completion time."""
    evidence = consumer.evidence
    require(reference['schema'] == evidence.REFERENCE_SCHEMA_V5, 'reuse reference required')
    evidence.validate_reference(reference, reference['identity']['release_not_before'])
    check, finished = historical_receipt_check(reader, reference)
    old = reference['historical']
    admission, receipt = evidence.resolve(old, fetch, finished, lambda binding: require(
        consumer.canonical(binding) == consumer.canonical(old['identity']), 'historical identity changed'))
    admission = dict(admission, check_run_id=evidence.REUSE_CHECK_ID, quality_check_run_id=None)
    consumer.validate_evidence_check(check, admission, finished, (receipt, old))
    validate_quality(receipt, admission)
    return admission, receipt


def verify_reuse_approvals(reader, reference, hosted, quality_sha, now, terminal_run=None, *, active=False):
    evidence = consumer.evidence
    identity = reference['identity']
    require(consumer.canonical(hosted) == consumer.canonical(REUSE_HOSTED), 'original hosted attempt required')
    a = reference['consumer_run']
    title = evidence.reuse_title(reference['historical'], identity['consumer_sha'], reference['nonce'])
    a_done = verify_reviewed_dispatch(reader, a, identity, CONSUMER_JOB, title=title,
                                      active=terminal_run is None and active, now=now,
                                      exact_start=identity['release_not_before'], control_ref=evidence.CONTROL_REF_V5)
    if terminal_run is not None:
        require(terminal_run != a, 'independent terminal dispatch required')
        title = terminal_run_title(reference, evidence.REUSE_CHECK_ID, a, hosted, quality_sha)
        return verify_reviewed_dispatch(reader, terminal_run, identity, TERMINAL_JOB, title=title,
                                        active=active, now=now, after=a_done, control_ref=evidence.CONTROL_REF_V5)


def verify_reused_evidence(admission, bundle, reader, terminal_run, hosted, trusted_sha, now, *, active, staged_at=None):
    evidence = consumer.evidence
    receipt, reference = bundle
    evidence.validate_reference(reference, now)
    old, identity = reference['historical'], reference['identity']
    require(trusted_sha == identity['consumer_sha'] and admission['check_run_id'] == evidence.REUSE_CHECK_ID,
            'wrong reuse consumer or C1')
    historical = {k: v for k, v in admission.items() if k not in ('check_run_id', 'quality_check_run_id')}
    artifact = evidence.encode_artifact(historical, receipt)
    require(evidence.canonical(evidence.make_reference(old['commit'], artifact, historical)) == evidence.canonical(old),
            'historical evidence binding changed')
    c1, finished = historical_receipt_check(reader, reference)
    _, receipt_hash = consumer.validate_evidence_check(c1, admission, finished, (receipt, old))
    quality = validate_quality(receipt, admission)
    verify_current_head(reader, admission)
    b_done = verify_reuse_approvals(reader, reference, hosted, consumer.digest(quality), now, terminal_run, active=active)
    if staged_at is not None:
        require(b_done is not None and b_done <= staged_at <= now, 'C2 staged before terminal completion')
    verify_hosted_jobs(reader, hosted, identity)
    commit = reader.commit(identity['candidate_sha'])
    require(commit['sha'] == identity['candidate_sha'] and commit['tree']['sha'] == identity['candidate_tree'],
            'tested tree changed')
    verify_current_head(reader, admission)
    request = verified_request(admission, receipt_hash, quality, bundle)
    if terminal_run is None:
        return request
    return dict(request, schema=TERMINAL_SCHEMA_V5, consumer_run=reference['consumer_run'],
                terminal_run=terminal_run, hosted=hosted)


def verify_terminal_evidence(admission, bundle, reader, terminal_run, hosted, trusted_sha, now, *, active=False, staged_at=None):
    """Derive a compact result only from the private evidence and genuine run readbacks."""
    receipt, reference = bundle
    if reference['schema'] == consumer.evidence.REFERENCE_SCHEMA_V5:
        return verify_reused_evidence(admission, bundle, reader, terminal_run, hosted, trusted_sha, now,
                                      active=active, staged_at=staged_at)
    identity = reference['identity']
    evidence = consumer.evidence
    evidence.validate_reference(reference, now)
    private_admission = {key: value for key, value in admission.items()
                         if key not in ('check_run_id', 'quality_check_run_id')}
    artifact = evidence.encode_artifact(private_admission, receipt)
    require(evidence.make_reference(reference['commit'], artifact, private_admission) == reference and
            identity['consumer_sha'] == trusted_sha,
            'terminal admission identity changed')
    verify_current_head(reader, admission)
    c1 = reader.check(admission['check_run_id'])
    _, receipt_hash = consumer.validate_evidence_check(c1, admission, now, bundle)
    quality = validate_quality(receipt, admission)
    workflow = quality['workflow']
    v4 = reference['schema'] == evidence.REFERENCE_SCHEMA_V4
    ref = evidence.CONTROL_REF_V4 if v4 else evidence.CONTROL_REF
    require(workflow['run_attempt'] == 1 and workflow['workflow_id'] == FORMAL_WORKFLOW_ID and
            workflow['sha'] == trusted_sha and workflow['path'] == consumer.evidence.WORKFLOW_PATH and
            workflow['ref'] == ref and workflow['event'] == 'workflow_dispatch' and
            workflow['run_id'] != terminal_run, 'wrong independently reviewed workflow bindings')
    c1_done = evidence.github_time(c1, 'completed_at') if v4 else None
    a_done = verify_reviewed_dispatch(reader, workflow['run_id'], identity, CONSUMER_JOB,
                                     now=now, completed_after=c1_done)
    title = terminal_run_title(reference, admission['check_run_id'], workflow['run_id'], hosted,
                               consumer.digest(quality))
    b_done = verify_reviewed_dispatch(reader, terminal_run, identity, TERMINAL_JOB, active=active, title=title,
                                     now=now, after=a_done)
    if v4 and staged_at is not None:
        require(b_done is not None and b_done <= staged_at <= now, 'C2 staged before terminal completion')
    verify_hosted_jobs(reader, hosted, identity)
    commit = reader.commit(identity['candidate_sha'])
    require(commit['sha'] == identity['candidate_sha'] and commit['tree']['sha'] == identity['candidate_tree'],
            'terminal tested tree mismatch')
    verify_current_head(reader, admission)
    schema = TERMINAL_SCHEMA_V4 if reference['schema'] == evidence.REFERENCE_SCHEMA_V4 else TERMINAL_SCHEMA
    return dict(verified_request(admission, receipt_hash, quality, bundle), schema=schema,
                consumer_run=workflow['run_id'], terminal_run=terminal_run, hosted=hosted)


def verify_public_terminal(environment, reader, *, clock=time.time):
    """Verify the App result from the native PR gate using public metadata only."""
    event = ci_premerge_event(environment)
    require(environment['GITHUB_EVENT_NAME'] == 'pull_request', 'native PR event required')
    sha = event['pull_request']['head']['sha']
    check = reader.formal_quality_check(sha)
    result = consumer.evidence.decode(check['output']['text'])
    if isinstance(result, dict) and result.get('schema') == TERMINAL_SCHEMA_V6:
        return delta.verify_public(sys.modules[__name__], environment, reader, clock=clock)
    if isinstance(result, dict) and result.get('schema') == TERMINAL_SCHEMA_V7:
        return static_delta.verify_public(sys.modules[__name__], environment, reader, clock=clock)
    if isinstance(result, dict) and result.get('schema') == TERMINAL_SCHEMA_V8:
        return usage_delta.verify_public(sys.modules[__name__], environment, reader, clock=clock)
    if isinstance(result, dict) and result.get('schema') == TERMINAL_SCHEMA_V9:
        return invitation_delta.verify_public(sys.modules[__name__], environment, reader, clock=clock)
    if isinstance(result, dict) and result.get('schema') == TERMINAL_SCHEMA_V10:
        return oauth_delta.verify_public(sys.modules[__name__], environment, reader, clock=clock)
    if isinstance(result, dict) and result.get('schema') == TERMINAL_SCHEMA_V11:
        return client_events_delta.verify_public(sys.modules[__name__], environment, reader, clock=clock)
    if isinstance(result, dict) and result.get('schema') == TERMINAL_SCHEMA_V12:
        return relay_log_delta.verify_public(sys.modules[__name__], environment, reader, clock=clock)
    fields = {'schema', 'name', 'artifact', 'quality_sha256', 'repository', 'repository_id', 'candidate_sha',
              'candidate_tree', 'receipt_sha256', 'check_run_id', 'admission_id', 'invocation', 'attempt_id',
              'expires_at', 'consumer_run', 'terminal_run', 'hosted'}
    require(type(result) is dict, 'invalid public terminal result')
    v4 = result.get('schema') == TERMINAL_SCHEMA_V4
    reuse = result.get('schema') == TERMINAL_SCHEMA_V5
    release_fields = ('release_not_before', 'release_expires_at') if v4 or reuse else ()
    fields.update(release_fields)
    require(set(result) == fields and result['schema'] in (TERMINAL_SCHEMA, TERMINAL_SCHEMA_V4, TERMINAL_SCHEMA_V5) and
            result['name'] == PRIVATE_EVIDENCE_GATE and result['consumer_run'] != result['terminal_run'] and
            all(type(result[key]) is int and result[key] > 0 for key in ('check_run_id', 'consumer_run', 'terminal_run')) and
            all(type(result[key]) is str and re.fullmatch('[0-9a-f]{64}', result[key]) is not None
                for key in ('receipt_sha256', 'quality_sha256')),
            'independent terminal quality proof required')
    validate_gate(check, result, completed=True)
    reference = result['artifact']
    now = int(clock())
    consumer.evidence.validate_reference(reference, now)
    require(v4 == (reference['schema'] == consumer.evidence.REFERENCE_SCHEMA_V4) and
            reuse == (reference['schema'] == consumer.evidence.REFERENCE_SCHEMA_V5), 'mixed terminal evidence versions')
    identity = reference['identity']
    validate_ci_evidence_reference(event, environment, identity)
    require(all(consumer.canonical(result[key]) == consumer.canonical(identity[key]) for key in
                ('repository', 'repository_id', 'candidate_sha', 'candidate_tree', 'admission_id', 'invocation',
                 'attempt_id', 'expires_at', *release_fields)),
            'terminal result differs from its immutable artifact')
    if reuse:
        require(environment['GITHUB_RUN_ID'] == str(REUSE_HOSTED['run_id']), 'wrong native hosted gate')
        require(result['check_run_id'] == consumer.evidence.REUSE_CHECK_ID and
                result['consumer_run'] == reference['consumer_run'], 'wrong reused check or first approval')
        c1, _ = historical_receipt_check(reader, reference)
        require(c1['external_id'] == result['receipt_sha256'], 'wrong historical receipt hash')
        b_done = verify_reuse_approvals(reader, reference, result['hosted'], result['quality_sha256'],
                                        now, result['terminal_run'])
    else:
        c1 = reader.check(result['check_run_id'])
        require(c1['id'] == result['check_run_id'] and c1['app']['id'] == consumer.APP and
                c1['app']['slug'] == 'new-api-box-formal' and c1['name'] == consumer.CHECK and
                c1['head_sha'] == sha and c1['status'] == 'completed' and c1['conclusion'] == 'success' and
                c1['external_id'] == result['receipt_sha256'] and
                consumer.canonical(consumer.evidence.decode(c1['output']['text'])) == consumer.canonical(reference),
                'published signed receipt does not match terminal proof')
        c1_done = consumer.evidence.check_times(c1, identity, now) if v4 else None
        a_done = verify_reviewed_dispatch(reader, result['consumer_run'], identity, CONSUMER_JOB,
                                         now=now, completed_after=c1_done)
        title = terminal_run_title(reference, result['check_run_id'], result['consumer_run'], result['hosted'],
                                   result['quality_sha256'])
        b_done = verify_reviewed_dispatch(reader, result['terminal_run'], identity, TERMINAL_JOB, title=title,
                                         now=now, after=a_done)
    if v4 or reuse:
        consumer.evidence.check_times(check, identity, now)
        require(b_done <= consumer.evidence.github_time(check, 'started_at'), 'C2 staged before terminal completion')
    verify_hosted_jobs(reader, result['hosted'], identity)
    resolve_ci_candidate(environment, reader)
    commit = reader.commit(sha)
    require(commit['sha'] == sha and commit['tree']['sha'] == identity['candidate_tree'], 'tested tree changed')
    consumer.evidence.validate_reference(reference, int(clock()))
    return result

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


def verify(admission, environment, reader, *, clock=time.time, execution_evidence=None, evidence_bundle=None):
    """Return verified DATA, never an admission token or publication authority."""
    private = evidence_bundle is not None
    consumer.validate_environment(environment, admission, int(clock()), private=private,
                                  receipt=evidence_bundle[0] if private else None)
    repository = reader.repository()
    require(repository['id'] == admission['repository_id'] and repository['full_name'] == REPOSITORY,
            'repository identity changed')
    verify_current_head(reader, admission)
    check = reader.check(admission['check_run_id'])
    receipt, receipt_hash = consumer.validate_evidence_check(check, admission, int(clock()), evidence_bundle)
    quality = validate_quality(receipt, admission)
    if execution_evidence is not None:
        validate_execution_support(execution_evidence, admission)
    commit = reader.commit(admission['expected']['candidate_sha'])
    require(commit['sha'] == admission['expected']['candidate_sha'] and
            commit['tree']['sha'] == admission['expected']['candidate_tree'], 'tested tree mismatch')
    workflow = quality['workflow']
    workflow_ref = environment['GITHUB_REF']
    require(workflow['path'] == consumer.evidence.WORKFLOW_PATH
            and workflow['ref'] == workflow_ref and workflow['event'] == 'workflow_dispatch'
            and workflow['sha'] == admission['expected']['consumer_sha'], 'untrusted workflow origin')
    for key in ('run_id', 'run_attempt', 'workflow_id'):
        require(type(workflow[key]) is int and workflow[key] > 0, 'invalid workflow identity')
    require(str(workflow['run_id']) == environment['GITHUB_RUN_ID'] and
            str(workflow['run_attempt']) == environment['GITHUB_RUN_ATTEMPT'] and
            environment['GITHUB_WORKFLOW_REF'] == REPOSITORY + '/' + workflow['path'] + '@' + workflow_ref,
            'wrong consuming workflow invocation')
    # This is the current protected CONSUMER run, not evidence that Actions ran
    # candidate tests. Complete execution is proved only by the App receipt. The
    # operator finalizes its run binding while the environment is awaiting review.
    run = reader.run(workflow['run_id'], workflow['run_attempt'])
    require(run['id'] == workflow['run_id'] and run['run_attempt'] == workflow['run_attempt'] and
            run['workflow_id'] == workflow['workflow_id'] and run['path'] == workflow['path'] and
            run['event'] == workflow['event'] and run['head_branch'] == workflow_ref.removeprefix('refs/heads/') and
            run['head_sha'] == workflow['sha'] and
            run['repository']['id'] == admission['repository_id'] and
            run['repository']['full_name'] == REPOSITORY and
            run['head_repository']['id'] == admission['repository_id'], 'wrong consumer run')
    require(run['status'] == 'in_progress' and run['conclusion'] is None,
            'consumer run is not active')
    if workflow_ref in (consumer.evidence.CONTROL_REF, consumer.evidence.CONTROL_REF_V4):
        verify_reviewed_dispatch(reader, workflow['run_id'], consumer.evidence.identity(admission, receipt),
                                 CONSUMER_JOB, active=True, now=int(clock()))
    verify_current_head(reader, admission)
    consumer.validate_environment(environment, admission, int(clock()), private=private,
                                  receipt=evidence_bundle[0] if private else None)
    return verified_request(admission, receipt_hash, quality, evidence_bundle)


def verified_request(admission, receipt_hash, quality, evidence_bundle=None):
    """Bind a quality result to the authenticated receipt and its evidence."""
    expected = admission['expected']
    request = {'repository': REPOSITORY, 'repository_id': admission['repository_id'],
               'candidate_sha': expected['candidate_sha'], 'candidate_tree': expected['candidate_tree'],
               'receipt_sha256': receipt_hash, 'check_run_id': admission['check_run_id'],
               'admission_id': expected['admission_id'], 'invocation': expected['invocation'],
               'attempt_id': expected['attempt_id'], 'expires_at': expected['expires_at']}
    if evidence_bundle is None:
        return dict(request, schema=SCHEMA, name=GATE, quality=copy.deepcopy(quality))
    if evidence_bundle[1]['schema'] == consumer.evidence.REFERENCE_SCHEMA_V4:
        request.update(consumer.evidence.release_times(expected, evidence_bundle[0]))
    elif evidence_bundle[1]['schema'] == consumer.evidence.REFERENCE_SCHEMA_V5:
        binding = evidence_bundle[1]['identity']
        request.update(release_not_before=binding['release_not_before'], release_expires_at=binding['release_expires_at'])
    return dict(request, schema=PRIVATE_EVIDENCE_SCHEMA, name=PRIVATE_EVIDENCE_GATE,
                artifact=copy.deepcopy(evidence_bundle[1]), quality_sha256=consumer.digest(quality))


class UnsupportedCIEvent(ValueError):
    """This reader cannot authorize postmerge, tag or publication lifecycles."""


def ci_premerge_event(environment):
    """Check the native event before consulting admission, credentials or APIs.

    A reusable workflow inherits its caller's event; workflow_call itself is not
    an authorization. Dispatch inputs select a PR; they never supply PR metadata.
    """
    kind = environment['GITHUB_EVENT_NAME']
    if kind not in ('pull_request', 'workflow_dispatch') or (
            kind == 'workflow_dispatch' and not environment['GITHUB_REF'].startswith('refs/heads/')):
        raise UnsupportedCIEvent('only open-PR premerge verification is supported')
    require(environment['GITHUB_REPOSITORY'] == REPOSITORY, 'wrong native repository')
    native_id = environment['GITHUB_REPOSITORY_ID']
    require(isinstance(native_id, str) and re.fullmatch('[1-9][0-9]*', native_id) is not None,
            'invalid native repository ID')
    event = json.loads(Path(environment['GITHUB_EVENT_PATH']).read_text(),
                       object_pairs_hook=consumer.unique_json_fields)
    if kind == 'workflow_dispatch':
        if type(event) is not dict or 'pull_request' in event:
            raise UnsupportedCIEvent('only open-PR premerge verification is supported')
        root = event['repository']
        require(type(root) is dict and type(root['id']) is int and root['id'] == int(native_id) and
                root['full_name'] == REPOSITORY, 'dispatch repository ownership mismatch')
        inputs = event['inputs']
        require(type(inputs) is dict and set(inputs) == {'pull_number', 'sha', 'base_sha'},
                'explicit PR, head and base inputs required')
        require(isinstance(inputs['pull_number'], str) and
                re.fullmatch('[1-9][0-9]*', inputs['pull_number']) is not None, 'invalid dispatch PR')
        for key in ('sha', 'base_sha'):
            require(isinstance(inputs[key], str) and re.fullmatch('[0-9a-f]{40}', inputs[key]) is not None,
                    'invalid dispatch source SHA')
        # Dispatch checks attach to the selected workflow ref's commit. Running
        # another ref must not claim to qualify the requested candidate SHA.
        require(environment['EXPECTED_SHA'] == inputs['sha'] == environment['GITHUB_SHA'] ==
                environment['GITHUB_WORKFLOW_SHA'], 'dispatch ref must be the exact candidate')
        require(environment['GITHUB_WORKFLOW_REF'] ==
                REPOSITORY + '/.github/workflows/ci.yml@' + environment['GITHUB_REF'],
                'dispatch must call CI directly, not a publication workflow')
        return event
    require(type(event) is dict and type(event['pull_request']) is dict,
            'invalid PR event structure')
    pull = event['pull_request']
    number = event['number']
    if (event['action'] not in ('opened', 'reopened', 'synchronize') or
            pull['state'] != 'open' or pull['merged'] is not False or
            type(number) is not int or number <= 0 or type(pull['number']) is not int or
            pull['number'] != number or
            environment['GITHUB_REF'] != f'refs/pull/{number}/merge'):
        raise UnsupportedCIEvent('only open-PR premerge verification is supported')
    require(type(pull['head']) is dict and type(pull['base']) is dict,
            'invalid PR source structure')
    root = event['repository']
    base = pull['base']['repo']
    head = pull['head']['repo']
    for repository in (root, base, head):
        require(type(repository) is dict and type(repository['id']) is int and repository['id'] > 0,
                'invalid event repository identity')
    require(root['full_name'] == base['full_name'] == REPOSITORY and
            root['id'] == base['id'] == int(native_id), 'event repository ownership mismatch')
    require(pull['base']['ref'] == 'main', 'wrong event PR target')
    # A fork's display name has no independent admitted local authority. It is
    # optional here; validate its shape when present, and bind its immutable ID
    # below. If it identifies the already-owned target, ID/name must agree.
    if 'full_name' in head:
        name = head['full_name']
        require(isinstance(name, str) and re.fullmatch(r'[^/\s]+/[^/\s]+', name) is not None,
                'invalid head repository display name')
        require((head['id'] == root['id']) == (name == REPOSITORY),
                'head repository conflicts with owned target identity')
    for source in (pull['head'], pull['base']):
        require(isinstance(source['sha'], str) and re.fullmatch('[0-9a-f]{40}', source['sha']) is not None,
                'invalid event source SHA')
    supplied_sha = environment['EXPECTED_SHA']
    require(isinstance(supplied_sha, str) and re.fullmatch('[0-9a-f]{40}', supplied_sha) is not None and
            supplied_sha == pull['head']['sha'], 'wrong CI input SHA')
    return event


def validate_ci_evidence_reference(event, environment, binding):
    release_policy.quality_results(json.loads(environment['QUALITY_RESULTS']))
    native = {'repository': REPOSITORY, 'repository_id': event['repository']['id'],
              'consumer_sha': environment['BOX_FORMAL_CONSUMER_SHA']}
    if environment['GITHUB_EVENT_NAME'] == 'workflow_dispatch':
        inputs = event['inputs']
        native.update(pull_number=int(inputs['pull_number']), candidate_sha=inputs['sha'],
                      base_sha=inputs['base_sha'])
    else:
        pull = event['pull_request']
        native.update(pull_number=event['number'], candidate_sha=pull['head']['sha'],
                      base_sha=pull['base']['sha'], head_repository_id=pull['head']['repo']['id'])
    require(consumer.canonical(native) == consumer.canonical({key: binding.get(key) for key in native}),
            'private evidence does not match native CI event')


def resolve_ci_candidate(environment, reader=None):
    """Resolve public checkout coordinates through GETs, never grant quality.

    Hosted preflight has no admission data. The protected final reader separately
    binds admission and rechecks the current PR and complete App evidence.
    """
    event = ci_premerge_event(environment)
    dispatch = environment['GITHUB_EVENT_NAME'] == 'workflow_dispatch'
    number = int(event['inputs']['pull_number']) if dispatch else event['number']
    head = event['inputs']['sha'] if dispatch else event['pull_request']['head']['sha']
    base = event['inputs']['base_sha'] if dispatch else event['pull_request']['base']['sha']
    if reader is None:
        reader = GitHubReader(environment['GITHUB_TOKEN'])
    repository = reader.repository()
    require(repository['id'] == event['repository']['id'] and repository['full_name'] == REPOSITORY,
            'repository identity changed')
    pull = reader.pull(number)
    require(type(pull['number']) is int and pull['number'] == number and pull['state'] == 'open' and
            pull['merged'] is False, 'PR is not an open candidate')
    require(pull['base']['repo']['id'] == repository['id'] and
            pull['base']['repo']['full_name'] == REPOSITORY and pull['base']['ref'] == 'main' and
            pull['base']['sha'] == base and pull['head']['sha'] == head, 'PR head, base or target changed')
    source = pull['head']['repo']
    require(type(source['id']) is int and source['id'] > 0 and isinstance(source['full_name'], str) and
            re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', source['full_name']) is not None and
            (source['id'] == repository['id']) == (source['full_name'] == REPOSITORY),
            'invalid authenticated head repository')
    if not dispatch:
        require(source['id'] == event['pull_request']['head']['repo']['id'], 'event head repository changed')
    return {'sha': head, 'repository': source['full_name']}


def verify_ci_result(admission, environment, reader=None, *, clock=time.time, evidence_bundle=None):
    """GET-only revalidation of a PRE-EXISTING App quality success for CI.

    Only premerge open-PR current-head/current-base validation is supported.
    Closed/merged, tag and publication reuse cannot authorize any output SHA.
    Unlike verify(), this runs downstream of the protected dispatch. It cannot
    stage/consume a host journal claim or turn a raw report into a result. The
    immutable checkout and all BOX_FORMAL_* values belong to the protected
    box-formal-consumer environment, never workflow inputs or candidate code.
    Re-reading the same immutable check is idempotent, not a new execution or
    attempt; another candidate/admission/run attempt cannot reuse it.
    """
    event = ci_premerge_event(environment)
    release_policy.quality_results(json.loads(environment['QUALITY_RESULTS']))
    require(type(admission) is dict and type(admission['expected']) is dict and
            type(admission['quality']) is dict, 'invalid admission structure')
    expected = admission['expected']
    admitted_quality = admission['quality']
    require(admission['repository'] == REPOSITORY and type(admission['repository_id']) is int and
            admission['repository_id'] > 0 and admission['repository_id'] == event['repository']['id'],
            'admission repository ownership mismatch')
    require(type(admitted_quality['pull_number']) is int and admitted_quality['pull_number'] > 0 and
            type(admitted_quality['head_repository_id']) is int and admitted_quality['head_repository_id'] > 0,
            'invalid admitted PR identity')
    if environment['GITHUB_EVENT_NAME'] == 'workflow_dispatch':
        require(int(event['inputs']['pull_number']) == admitted_quality['pull_number'] and
                event['inputs']['sha'] == expected['candidate_sha'] and
                event['inputs']['base_sha'] == admitted_quality['base_sha'],
                'CI dispatch does not match admitted PR, head or base')
        # A dispatch has no authenticated head repo metadata. Its immutable ID
        # is bound by verify_current_head below, never by caller-supplied input.
    else:
        require(event['number'] == admitted_quality['pull_number'] and
                event['pull_request']['head']['repo']['id'] == admitted_quality['head_repository_id'] and
                event['pull_request']['head']['sha'] == expected['candidate_sha'] and
                event['pull_request']['base']['sha'] == admitted_quality['base_sha'],
                'CI event does not match admitted PR ownership, head or base')
    for key in ('candidate_sha', 'candidate_tree', 'execution_sha'):
        require(isinstance(expected[key], str) and re.fullmatch('[0-9a-f]{40}', expected[key]) is not None and
                admitted_quality[key] == expected[key], 'inconsistent admitted source identity')
    require(expected['execution_sha'] == expected['candidate_sha'], 'build and execution SHA differ')
    for key in ('admission_id', 'attempt_id', 'invocation'):
        require(consumer.canonical(admitted_quality[key]) == consumer.canonical(expected[key]),
                'inconsistent admitted attempt identity')
    trusted = environment['BOX_FORMAL_CONSUMER_SHA']
    require(re.fullmatch('[0-9a-f]{40}', trusted) is not None and
            trusted == expected['consumer_sha'], 'unapproved consumer revision')
    reviewers = json.loads(environment['BOX_FORMAL_REVIEWER_IDS'])
    require(isinstance(reviewers, list) and reviewers and
            all(type(user) is int and user > 0 for user in reviewers) and
            len(set(reviewers)) == len(reviewers), 'trusted reviewer IDs required')
    gate_id = admission['quality_check_run_id']
    require(type(admission['check_run_id']) is int and admission['check_run_id'] > 0 and
            type(gate_id) is int and gate_id > 0 and gate_id != admission['check_run_id'],
            'finalized quality check ID required')
    # The CLI leaves reader unset. All native/admission/input bindings above
    # must finish before even accessing the credential or constructing a client.
    # Trusted offline callers may still inject their existing reader object.
    if reader is None:
        reader = GitHubReader(environment['GITHUB_TOKEN'])
    repository = reader.repository()
    require(repository['id'] == admission['repository_id'] and repository['full_name'] == REPOSITORY,
            'repository identity changed')
    verify_current_head(reader, admission)
    check = reader.check(admission['check_run_id'])
    receipt, receipt_hash = consumer.validate_evidence_check(check, admission, int(clock()), evidence_bundle)
    quality = validate_quality(receipt, admission)
    request = verified_request(admission, receipt_hash, quality, evidence_bundle)
    gate = reader.check(gate_id)
    require(gate['id'] == gate_id, 'wrong quality check ID')
    validate_gate(gate, request, completed=True)
    commit = reader.commit(expected['candidate_sha'])
    require(commit['sha'] == expected['candidate_sha'] and
            commit['tree']['sha'] == expected['candidate_tree'], 'tested tree mismatch')
    workflow = quality['workflow']
    require(workflow['path'] == '.github/workflows/box-formal-receipt.yml' and
            workflow['ref'] == 'refs/heads/main' and workflow['event'] == 'workflow_dispatch' and
            workflow['sha'] == trusted, 'untrusted workflow origin')
    require(all(type(workflow[key]) is int and workflow[key] > 0
                for key in ('run_id', 'run_attempt', 'workflow_id')), 'invalid workflow identity')
    run = reader.run(workflow['run_id'], workflow['run_attempt'])
    require(run['id'] == workflow['run_id'] and run['run_attempt'] == workflow['run_attempt'] and
            run['workflow_id'] == workflow['workflow_id'] and run['path'] == workflow['path'] and
            run['event'] == workflow['event'] and run['head_branch'] == 'main' and
            run['head_sha'] == trusted and run['repository']['id'] == admission['repository_id'] and
            run['repository']['full_name'] == REPOSITORY and
            run['head_repository']['id'] == admission['repository_id'] and
            run['status'] == 'completed' and run['conclusion'] == 'success',
            'consumer workflow did not complete successfully')
    identity_keys = ('id', 'run_attempt', 'workflow_id', 'path', 'event', 'head_branch',
                     'head_sha', 'repository', 'head_repository', 'status', 'conclusion', 'triggering_actor')
    run_identity = consumer.canonical({key: run[key] for key in identity_keys})
    latest = reader.latest_run(workflow['run_id'])
    require(consumer.canonical({key: latest[key] for key in identity_keys}) == run_identity,
            'consumer run replay or rerun')
    approvals = reader.approvals(workflow['run_id'])
    reviews = [review for review in approvals
               if any(env['name'] == 'box-formal-consumer' for env in review['environments'])]
    require(reviews and all(review['state'] == 'approved' and
            type(review['user']['id']) is int and review['user']['id'] in reviewers and
            review['user']['id'] != run['triggering_actor']['id'] for review in reviews),
            'missing or untrusted environment reviewer')
    # Reread both authenticated objects and the latest run, then head and clock.
    # No write or new green publication occurs across this read-only boundary.
    latest = reader.latest_run(workflow['run_id'])
    require(consumer.canonical(reader.check(admission['check_run_id'])) == consumer.canonical(check) and
            consumer.canonical(reader.check(gate_id)) == consumer.canonical(gate) and
            consumer.canonical({key: latest[key] for key in identity_keys}) == run_identity and
            consumer.canonical(reader.approvals(workflow['run_id'])) == consumer.canonical(approvals),
            'quality evidence changed during CI consumption')
    verify_current_head(reader, admission)
    consumer.validate_evidence_check(check, admission, int(clock()), evidence_bundle)
    return request


def stage_publication(admission, environment, reader, publisher, journal, *, clock=time.time,
                      execution_evidence=None, evidence_bundle=None):
    """Stage a non-green check; exceptions burn the admission, never retry writes."""
    require(environment['GITHUB_REF'] not in (consumer.evidence.CONTROL_REF, consumer.evidence.CONTROL_REF_V4),
            'formal control branch requires post-terminal publication')
    admission = copy.deepcopy(admission)
    environment = dict(environment)
    execution_evidence = copy.deepcopy(execution_evidence)
    evidence_bundle = copy.deepcopy(evidence_bundle)
    verified = verify(admission, environment, reader, clock=clock, execution_evidence=execution_evidence,
                      evidence_bundle=evidence_bundle)
    publisher.verify_installation(admission['repository_id'])
    journal.claim(verified)
    require(verify(admission, environment, reader, clock=clock, execution_evidence=execution_evidence,
                      evidence_bundle=evidence_bundle) == verified,
            'evidence changed after claim')
    check_id = publisher.stage(copy.deepcopy(verified))
    # A concurrent head update or an uncertain POST leaves ONLY a pending check
    # on the old exact SHA; it cannot produce a green current-head result.
    require(verify(admission, environment, reader, clock=clock, execution_evidence=execution_evidence,
                      evidence_bundle=evidence_bundle) == verified,
            'evidence changed while staging')
    journal.stage(verified, check_id)
    return {'state': 'pending', 'check_run_id': check_id, 'candidate_sha': verified['candidate_sha']}


def collect_result(admission, environment, reader, publisher, journal, *, clock=time.time,
                   execution_evidence=None, evidence_bundle=None):
    """Return only a complete pre-existing App result, once, for the current head.

    There are no network writes here. A failure cannot publish a new green check.
    Existing genuine success belongs to its immutable SHA; it is not a guarantee
    that this PR's head/base will remain unchanged after the final read.
    """
    admission = copy.deepcopy(admission)
    environment = dict(environment)
    execution_evidence = copy.deepcopy(execution_evidence)
    evidence_bundle = copy.deepcopy(evidence_bundle)
    verified = verify(admission, environment, reader, clock=clock, execution_evidence=execution_evidence,
                      evidence_bundle=evidence_bundle)
    publisher.verify_installation(admission['repository_id'])
    check_id = journal.pending(verified)
    check = reader.check(check_id)
    require(check['id'] == check_id, 'wrong published check')
    validate_gate(check, verified, completed=True)
    require(verify(admission, environment, reader, clock=clock, execution_evidence=execution_evidence,
                      evidence_bundle=evidence_bundle) == verified,
            'evidence changed during collection')
    # Re-read the published object as well: incomplete/changed publication cannot
    # be substituted between receipt verification and final result consumption.
    published = reader.check(check_id)
    require(consumer.canonical(published) == consumer.canonical(check),
            'publication changed during collection')
    verify_current_head(reader, admission)
    consumer.validate_environment(environment, admission, int(clock()), private=evidence_bundle is not None,
                                  receipt=evidence_bundle[0] if evidence_bundle else None)
    journal.consume(verified, check_id)
    return {'state': 'verified', 'check_run_id': check_id, 'result': verified}


def verify_reuse_dispatch(environment, *, terminal, clock=time.time):
    evidence = consumer.evidence
    ref = evidence.CONTROL_REF_V5
    trusted_sha = environment['BOX_FORMAL_CONSUMER_SHA']
    require(environment['GITHUB_EVENT_NAME'] == 'workflow_dispatch' and environment['GITHUB_REF'] == ref and
            environment['GITHUB_REPOSITORY'] == REPOSITORY and
            environment['GITHUB_WORKFLOW_REF'] == REPOSITORY + '/' + evidence.WORKFLOW_PATH + '@' + ref and
            environment['GITHUB_RUN_ATTEMPT'] == '1' and environment['GITHUB_ACTOR_ID'] == str(evidence.TRIGGER_ID) and
            re.fullmatch('[0-9a-f]{40}', trusted_sha) and
            environment['GITHUB_SHA'] == environment['GITHUB_WORKFLOW_SHA'] == trusted_sha,
            'wrong native reuse dispatch')
    reference = evidence.decode(environment['BOX_FORMAL_ADMISSION'])
    now = int(clock())
    evidence.validate_reference(reference, now)
    identity = reference['identity']
    require(reference['schema'] == evidence.REFERENCE_SCHEMA_V5 and identity['consumer_sha'] == trusted_sha and
            environment['GITHUB_REPOSITORY_ID'] == str(identity['repository_id']) and
            identity['repository'] == REPOSITORY, 'reuse context mismatch')
    run_id = int(environment['GITHUB_RUN_ID'])
    a = reference['consumer_run']
    require((run_id != a) if terminal else (run_id == a), 'wrong active review run')
    hosted_fields = [('BOX_FORMAL_HOSTED_RUN_ID','run_id'), ('BOX_FORMAL_HOSTED_RUN_ATTEMPT','attempt'),
                     ('BOX_FORMAL_HOSTED_CI_BLOB','workflow_blob')]
    require(all(environment[key] == str(REUSE_HOSTED[field]) for key,field in hosted_fields if key in environment),
            'original hosted attempt required')
    reader = GitHubReader(environment['GITHUB_TOKEN'])
    if terminal:
        verify_reviewed_dispatch(reader, run_id, identity, TERMINAL_JOB, active=True, now=now, control_ref=ref)
    else:
        verify_reuse_approvals(reader, reference, REUSE_HOSTED, None, now, active=True)

    def fetch(commit):
        token = environment.get('BOX_FORMAL_EVIDENCE_TOKEN')
        require(token and token != environment['GITHUB_TOKEN'], 'private evidence read credential required')
        return consumer.read_private_evidence(commit, token)

    admission, receipt = load_reused_evidence(reference, reader, fetch)
    result = verify_reused_evidence(admission, (receipt, reference), reader, run_id if terminal else None,
                                    REUSE_HOSTED, trusted_sha, int(clock()), active=True)
    evidence.validate_reference(reference, int(clock()))
    return result


def main():
    # Quality reads use the protected consumer checkout; preflight reads only
    # public PR metadata on the hosted workflow checkout, without admission.
    # Publication is available solely through the trusted host's injected object.
    require(sys.argv[1:] in ([], ['ci'], ['premerge'], ['terminal'], ['public-terminal'],
                           ['reuse-consumer'], ['reuse-terminal'], ['delta-consumer'], ['delta-terminal'],
                           ['static-delta-consumer'], ['static-delta-terminal'], ['usage-delta-consumer'], ['usage-delta-terminal'],
                           ['invitation-delta-consumer'], ['invitation-delta-terminal'],
                           ['oauth-delta-consumer'], ['oauth-delta-terminal'],
                           ['client-events-delta-consumer'], ['client-events-delta-terminal'],
                           ['relay-log-delta-consumer'], ['relay-log-delta-terminal']),
            'unknown quality operation')
    if sys.argv[1:] == ['premerge']:
        result = resolve_ci_candidate(os.environ)
        print(json.dumps(result, sort_keys=True))
        return
    if sys.argv[1:] in (['reuse-consumer'], ['reuse-terminal']):
        result = verify_reuse_dispatch(os.environ, terminal=sys.argv[1] == 'reuse-terminal')
    elif sys.argv[1:] in (['delta-consumer'], ['delta-terminal']):
        result = delta.verify_dispatch(sys.modules[__name__], os.environ, terminal=sys.argv[1] == 'delta-terminal')
    elif sys.argv[1:] in (['static-delta-consumer'], ['static-delta-terminal']):
        result = static_delta.verify_dispatch(sys.modules[__name__], os.environ,
                                              terminal=sys.argv[1] == 'static-delta-terminal', clock=time.time)
    elif sys.argv[1:] in (['usage-delta-consumer'], ['usage-delta-terminal']):
        result = usage_delta.verify_dispatch(sys.modules[__name__], os.environ,
                                              terminal=sys.argv[1] == 'usage-delta-terminal', clock=time.time)
    elif sys.argv[1:] in (['invitation-delta-consumer'], ['invitation-delta-terminal']):
        result = invitation_delta.verify_dispatch(sys.modules[__name__], os.environ,
                                                   terminal=sys.argv[1] == 'invitation-delta-terminal', clock=time.time)
    elif sys.argv[1:] in (['oauth-delta-consumer'], ['oauth-delta-terminal']):
        result = oauth_delta.verify_dispatch(sys.modules[__name__], os.environ,
                                              terminal=sys.argv[1] == 'oauth-delta-terminal', clock=time.time)
    elif sys.argv[1:] in (['client-events-delta-consumer'], ['client-events-delta-terminal']):
        result = client_events_delta.verify_dispatch(
            sys.modules[__name__], os.environ, terminal=sys.argv[1] == 'client-events-delta-terminal', clock=time.time)
    elif sys.argv[1:] in (['relay-log-delta-consumer'], ['relay-log-delta-terminal']):
        result = relay_log_delta.verify_dispatch(
            sys.modules[__name__], os.environ, terminal=sys.argv[1] == 'relay-log-delta-terminal', clock=time.time)
    elif sys.argv[1:] == ['terminal']:
        now = int(time.time())
        trusted_sha = consumer.trusted_consumer_context(os.environ, private=True)
        require(os.environ['GITHUB_REF'] == consumer.evidence.CONTROL_REF_V4, 'terminal must use the control branch')
        admission, bundle = consumer.configured_evidence(os.environ, now)
        require(bundle is not None, 'terminal requires complete private evidence')
        hosted = {'run_id': int(os.environ['BOX_FORMAL_HOSTED_RUN_ID']),
                  'attempt': int(os.environ['BOX_FORMAL_HOSTED_RUN_ATTEMPT']),
                  'workflow_blob': os.environ['BOX_FORMAL_HOSTED_CI_BLOB']}
        result = verify_terminal_evidence(admission, bundle, GitHubReader(os.environ['GITHUB_TOKEN']),
                                          int(os.environ['GITHUB_RUN_ID']), hosted, trusted_sha, now, active=True)
    elif sys.argv[1:] == ['public-terminal']:
        ci_premerge_event(os.environ)
        release_policy.quality_results(json.loads(os.environ['QUALITY_RESULTS']))
        result = verify_public_terminal(os.environ, GitHubReader(os.environ['GITHUB_TOKEN']))
    elif sys.argv[1:] == ['ci']:
        event = ci_premerge_event(os.environ)
        admission, bundle = consumer.configured_evidence(
            os.environ, int(time.time()),
            check_identity=lambda binding: validate_ci_evidence_reference(event, os.environ, binding))
        result = (verify_ci_result(admission, os.environ) if bundle is None else
                  verify_ci_result(admission, os.environ, evidence_bundle=bundle))
    else:
        admission, bundle = consumer.configured_evidence(os.environ, int(time.time()))
        result = verify(admission, os.environ, GitHubReader(os.environ['GITHUB_TOKEN']), evidence_bundle=bundle)
    print(json.dumps({key: result[key] for key in
                      ('schema', 'candidate_sha', 'candidate_tree', 'check_run_id', 'receipt_sha256')},
                     sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except UnsupportedCIEvent:
        raise SystemExit('Unsupported CI lifecycle: only open-PR premerge verification is supported; '
                         'postmerge, tag and publication reuse cannot authorize a SHA.')
    except Exception:
        raise SystemExit('Quality evidence rejected; no publication authorization granted.')
