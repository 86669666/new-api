"""Formal evidence reuse for PR #260 anonymous client events."""
from hashlib import sha256
import io
import json
import re
import urllib.request
import zipfile


PR = 260
HEAD = 'f913e9b2a40e246571e50b7ab13109806303ab80'
TREE = '08fc1d1911077597ae4ead158f8267985f11a34f'
BASE = '18941e8f331dc1a4e0a589528da17298d1dbd52a'
PRIOR_HEAD = 'e01549775bb35d0ff8d5ee88da248176fc0d9efd'
BRANCH = 'g4/issue25-anonymous-backend'
CONTROL_REF = 'refs/heads/codex/formal-quality-r11'
REFERENCE_SCHEMA = 'box-formal-client-events-delta-ref/v11'
TERMINAL_SCHEMA = 'box-quality-terminal/v11'
SCOPE = 'anonymous-client-events-intake-and-settings'
C1 = 135232975120
PR254_C2 = 136221211686
PR254_PROOF = '4cbccbbb790724944f7d0dcd5e3e8d48bbe2a3bdecc012ef2a6af00387e1db90'
PR254_A, PR254_B = 44713143478, 44714708983
PR254_NATIVE_JOB = 136222336870
R10 = 'f14b5d2540486964841d2d6d823729a54a3e07e0'
HOSTED = {'run_id': 44729397309, 'attempt': 1,
          'workflow_blob': 'c123990e4a8c9fd981b721455a8edbc65b62dfc5'}
BASELINE = {'pull_number': 254, 'candidate_sha': '8dfbbc5d41de5451ef69b99307b51f507f89ac38',
            'candidate_tree': '430eebb7e33e7e7ec05497c4f607003eae1ee2e2', 'merge_commit': BASE,
            'terminal_check_id': PR254_C2, 'native_run': 44710933114,
            'native_attempt': 2, 'native_job': PR254_NATIVE_JOB}
ARCHIVE = {'commit': 'adf2d04b0b6baba97362a4711f5b3944c2c26672',
           'path': 'formal-audit/pr260-f913e9b2-formal-inputs.zip',
           'bytes': 190015, 'sha256': '7aef6990256ed1c493dd7e2b5ba28f772345bf725ec90bc07a37abb9b48cd355'}
MANIFEST = 'd8a9f04841bf847bb2a155c4736da2fc28e581e626a847f1195e774f98081570'
ORIGINAL_HEAD = 'ecfd52901db9f7738b5aed543ee749727ce47ea1'
FILES = (
    'controller/client_events.go',
    'docs/openapi/api.json',
    'middleware/client_events.go',
    'middleware/client_events_anonymous.go',
    'model/client_event.go',
    'model/client_event_anonymous.go',
    'model/option.go',
    'router/client_events_anonymous_test.go',
    'router/organization_access_test.go',
    'scripts/openapi/check_client.mjs',
    'scripts/openapi/check_contract.py',
    'scripts/openapi/fixtures.json',
    'setting/operation_setting/client_events_setting.go',
    'web/src/features/system-settings/maintenance/__tests__/client-events-settings.test.tsx',
    'web/src/features/system-settings/maintenance/client-events-settings-section.tsx',
    'web/src/i18n/locales/en.json',
    'web/src/i18n/locales/fr.json',
    'web/src/i18n/locales/ja.json',
    'web/src/i18n/locales/ru.json',
    'web/src/i18n/locales/vi.json',
    'web/src/i18n/locales/zh-TW.json',
    'web/src/i18n/locales/zh.json',
)
MEMBERS = {
    'boundaries.executed.go': '244c86bc1b6ae7574cda024211c5f158d1f9870cbac66d6098624d8d62c53529',
    'client-events-default.png': 'be521b2d78a2c2375937b509e93e181f3ff8fb1050161130bd0609ba7b6dc00f',
    'client-events-verified.png': 'ad4c19c2af0bd6d06aaf470a104437c9ca33d72a7b34b4e5def81e87028a579d',
    'openapi.json': '0179af7fa3f1476836b7e90071863a7610d700ab2af48397b2582ee9dea03872',
    'scope.patch': '9ee061f4400c035b1abd0a3144b6bea9a38e3ac08a67c3006ff208d8e25aae4f',
    'validation.json': 'f5a79b6958b650e6842a4fc43d4048877fa392899ec89c4255e0fc7acacbe7c8',
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=True).encode('ascii')


def descriptor():
    return ARCHIVE.copy()


def consumer_intent(artifact, control, nonce):
    if (canonical(artifact) != canonical(ARCHIVE) or not re.fullmatch('[a-f0-9]{40}', control) or
            control == R10 or not re.fullmatch('[a-f0-9]{32}', nonce)):
        raise ValueError('invalid client events delta selection')
    bound = {'artifact': artifact, 'baseline': BASELINE, 'tree': TREE, 'head': HEAD,
             'hosted': HOSTED, 'control': control, 'nonce': nonce}
    return sha256(canonical(bound)).hexdigest()


def make_reference(artifact, control, consumer_run, opened, nonce):
    consumer_intent(artifact, control, nonce)
    if type(consumer_run) is not int or consumer_run <= 0 or type(opened) is not int or opened <= 0:
        raise ValueError('invalid client events delta approval times')
    identity = {'repository': '86669666/new-api', 'repository_id': 1423238398, 'head_repository_id': 1423238398,
                'pull_number': PR, 'base_sha': BASE, 'candidate_sha': HEAD, 'candidate_tree': TREE,
                'consumer_sha': control, 'release_not_before': opened, 'release_expires_at': opened + 1800}
    return {'schema': REFERENCE_SCHEMA, 'artifact': artifact, 'identity': identity, 'consumer_run': consumer_run, 'nonce': nonce}


def validate_reference(reference, now):
    identity = reference['identity']
    expected = make_reference(reference['artifact'], identity['consumer_sha'], reference['consumer_run'],
                              identity['release_not_before'], reference['nonce'])
    if canonical(reference) != canonical(expected) or type(now) is not int or not (
            identity['release_not_before'] <= now <= identity['release_expires_at']):
        raise ValueError('invalid or expired client events delta reference')


def validate_package(policy, raw):
    require = policy.require
    decode = policy.consumer.evidence.decode
    require(type(raw) is bytes and len(raw) == ARCHIVE['bytes'] and sha256(raw).hexdigest() == ARCHIVE['sha256'],
            'wrong immutable client events evidence')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(sorted(archive.namelist()) == sorted((*MEMBERS, 'manifest.json')), 'incorrect client events artifact inventory')
        manifest = archive.read('manifest.json')
        require(sha256(manifest).hexdigest() == MANIFEST and
                {name: sha256(archive.read(name)).hexdigest() for name in MEMBERS} == MEMBERS,
                'unreviewed client events evidence member')
        result = decode(archive.read('validation.json'))
        openapi = decode(archive.read('openapi.json'))
    data = decode(manifest)
    require((data['kind'], data['pull'], data['head'], data['tree'], data['base'], data['prior_head'], data['paths']) ==
            ('pr260-client-events-anonymous/v1', PR, HEAD, TREE, BASE, PRIOR_HEAD, list(FILES)) and
            data['hosted'] == HOSTED and set(data['blobs']) == set(FILES) and data['original_head'] == ORIGINAL_HEAD and
            data['historical_254']['signed_payload_sha256'] == PR254_PROOF and data['members'] == MEMBERS,
            'wrong client events evidence subjects')
    require((result['candidate'], result['tree'], result['review']) == (HEAD, TREE, 'ACCEPT_SCOPED') and
            (result['source']['candidate'], result['source']['tree'], result['source']['blob_count']) == (HEAD, TREE, 2831) and
            result['cleanup'] == {'containers_remaining': 0, 'runtime_tree_removed': True},
            'client events verification or teardown missing')
    versions = {'sqlite': '3.50.4', 'mysql': '8.0.46', 'postgres': '16.15'}
    cases = ['capacity_dedup_concurrency_and_atomic_rollback', 'default_and_strict_legacy_configuration',
             'disable_ordering_and_no_billing_or_sensitive_payload', 'identity_and_sql_cohort_isolation']
    require(set(result['matrix']) == set(versions) and
            all(row['version'] == versions[name] and row['passes'] == cases and row['owned_cleanup'] is True
                for name, row in result['matrix'].items()), 'incomplete client events SQL evidence')
    lifecycle = result['lifecycle']
    require((lifecycle['deadline_http'], lifecycle['deadline_event_writes'], lifecycle['cause'],
             lifecycle['disconnect_event_writes'], lifecycle['subsequent_http'], lifecycle['subsequent_event_writes']) ==
            (503, 0, 'context deadline exceeded', 0, 200, 1) and lifecycle['disconnect_to_gateway_ms'] == 10005 and
            lifecycle['overlay_sha256'] == MEMBERS['boundaries.executed.go'], 'wrong client events lifecycle evidence')
    browser = result['browser']
    require(browser['candidate'] == HEAD and browser['page_errors'] == 0 and
            all(browser[key] is True for key in ('real_login', 'default_disabled', 'save_and_readback', 'reload_persists',
                                                 'cancelled_retention_performs_no_write', 'restored_disabled')) and
            browser['screenshots'] == {name: MEMBERS[name] for name in ('client-events-default.png', 'client-events-verified.png')} and
            openapi['stats']['authenticated_admin'] is True and openapi['stats']['live_http'] is False,
            'client events browser or OpenAPI evidence missing')


def current_subject(policy, reader, identity):
    base = reader.repository()
    pr = reader.pull(PR)
    repo_id = identity['repository_id']
    policy.require(base['id'] == repo_id and base['full_name'] == policy.REPOSITORY and
                   pr['number'] == PR and pr['state'] == 'open' and pr['merged'] is False and pr['changed_files'] == 22 and
                   pr['head']['repo']['id'] == pr['base']['repo']['id'] == repo_id and
                   pr['head']['repo']['full_name'] == pr['base']['repo']['full_name'] == policy.REPOSITORY and
                   pr['head']['sha'] == HEAD and pr['head']['ref'] == BRANCH and
                   pr['base']['sha'] == BASE and pr['base']['ref'] == 'main', 'current client events PR subject changed')
    commit = reader.commit(HEAD)
    policy.require(commit['sha'] == HEAD and commit['tree']['sha'] == TREE and
                   [row['sha'] for row in commit['parents']] == [PRIOR_HEAD, BASE], 'wrong client events candidate tree or parents')
    policy.verify_hosted_jobs(reader, HOSTED, identity)


def historical_baseline(policy, reader, fetch=None):
    previous = policy.oauth_delta
    evidence = policy.consumer.evidence
    proof257 = previous.historical_baseline(policy, reader, fetch)
    check = reader.check(PR254_C2)
    proof = evidence.decode(check['output']['text'])
    policy.require(check['id'] == PR254_C2 and policy.consumer.digest(proof) == PR254_PROOF and
                   (proof['candidate_sha'], proof['candidate_tree'], proof['consumer_run'], proof['terminal_run']) ==
                   (BASELINE['candidate_sha'], BASELINE['candidate_tree'], PR254_A, PR254_B), 'wrong signed PR254 baseline')
    signed = evidence.github_time(check, 'completed_at')
    policy.validate_gate(check, proof, completed=True)
    ref = proof['artifact']
    previous.validate_reference(ref, signed)
    policy.require(ref['identity']['consumer_sha'] == R10 and
                   policy.consumer.canonical(proof) == policy.consumer.canonical(previous.result(ref, PR254_B, proof257)),
                   'signed PR254 evidence differs from reviewed contract')
    done = previous.verify_approvals(policy, reader, ref, PR254_B, signed)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'PR254 signature predates its reviews')
    # GitHub can drop pull_requests on historical Actions runs after source branch deletion.
    # The exact signed v10 proof already bound all four jobs before merge; authenticate
    # the original workflow definition and the observed final GitHub job below.
    original = reader.run(previous.HOSTED['run_id'], previous.HOSTED['attempt'])
    repo_id = ref['identity']['repository_id']
    policy.require(original['id'] == previous.HOSTED['run_id'] and original['run_attempt'] == previous.HOSTED['attempt'] and
                   original['workflow_id'] == policy.CI_WORKFLOW_ID and original['path'] == '.github/workflows/ci.yml' and
                   original['event'] == 'pull_request' and original['head_sha'] == previous.HEAD and
                   original['repository']['id'] == original['head_repository']['id'] == repo_id and
                   reader.hosted_workflow_blob(previous.HEAD) == previous.HOSTED['workflow_blob'],
                   'historical PR254 hosted run or workflow blob changed')
    policy.verify_hosted_job_steps(reader, previous.HOSTED, previous.HEAD)
    if fetch is not None:
        previous.validate_package(policy, fetch(ref['artifact']['commit']))
    pr = reader.pull(254)
    merged = reader.commit(BASE)
    policy.require(pr['number'] == 254 and pr['state'] == 'closed' and pr['merged'] is True and
                   pr['merge_commit_sha'] == BASE and pr['head']['sha'] == BASELINE['candidate_sha'] and
                   pr['base']['ref'] == 'main' and pr['base']['repo']['id'] == repo_id and
                   merged['sha'] == BASE and merged['tree']['sha'] == BASELINE['candidate_tree'] and
                   [row['sha'] for row in merged['parents']] == [previous.BASE, previous.HEAD], 'wrong historical PR254 merge')
    run = reader.run(BASELINE['native_run'], 2)
    policy.require(run['id'] == BASELINE['native_run'] and run['run_attempt'] == 2 and
                   run['head_sha'] == BASELINE['candidate_sha'] and
                   run['repository']['id'] == run['head_repository']['id'] == repo_id and
                   run['path'] == '.github/workflows/ci.yml' and run['event'] == 'pull_request' and run['workflow_id'] == policy.CI_WORKFLOW_ID and
                   run['status'] == 'completed' and run['conclusion'] == 'success', 'historical PR254 native gate did not pass')
    gate = policy.successful_job(reader.jobs(BASELINE['native_run'], 2), policy.GATE, BASELINE['candidate_sha'],
                                 ('Verify hosted jobs and authenticated exact-candidate quality',))
    policy.require(gate['id'] == PR254_NATIVE_JOB and gate['run_id'] == BASELINE['native_run'] and gate['run_attempt'] == 2 and
                   signed <= evidence.github_time(gate, 'started_at') <= evidence.github_time(gate, 'completed_at') <=
                   evidence.github_time(pr, 'merged_at') <= ref['identity']['release_expires_at'],
                   'PR254 native green and merge outside historical publication')
    return proof


def verify_approvals(policy, reader, reference, terminal_run, now, *, active=False):
    binding = reference['identity']
    consumer_run = reference['consumer_run']
    nonce = reference['nonce']
    title = 'Formal delta ' + consumer_intent(reference['artifact'], binding['consumer_sha'], nonce)
    done = policy.verify_reviewed_dispatch(reader, consumer_run, binding, policy.CONSUMER_JOB,
        active=terminal_run is None and active, title=title, now=now, exact_start=binding['release_not_before'],
        control_ref=CONTROL_REF)
    if terminal_run is not None:
        policy.require(type(terminal_run) is int and terminal_run != consumer_run, 'separate client events terminal required')
        title = policy.terminal_run_title(reference, C1, consumer_run, HOSTED, ARCHIVE['sha256'])
        return policy.verify_reviewed_dispatch(reader, terminal_run, binding, policy.TERMINAL_JOB, active=active,
            title=title, now=now, after=done, control_ref=CONTROL_REF)


def result(reference, terminal_run, proof):
    identity = reference['identity']
    return {'schema': TERMINAL_SCHEMA, 'name': 'Box formal quality result', 'artifact': reference,
            'quality_sha256': ARCHIVE['sha256'], 'candidate_sha': HEAD, 'candidate_tree': TREE,
            'repository': identity['repository'], 'repository_id': identity['repository_id'], 'baseline': BASELINE,
            'scope': SCOPE, 'check_run_id': C1, 'receipt_sha256': proof['receipt_sha256'],
            'consumer_run': reference['consumer_run'], 'terminal_run': terminal_run, 'hosted': HOSTED,
            'expires_at': identity['release_expires_at'], 'release_not_before': identity['release_not_before'],
            'release_expires_at': identity['release_expires_at'], 'admission_id': 'pr260-client-events-delta-' + HEAD,
            'invocation': consumer_intent(reference['artifact'], identity['consumer_sha'], reference['nonce'])}


def verify(policy, reference, reader, fetch, terminal_run, now, *, active=False, staged_at=None):
    validate_reference(reference, now)
    policy.require(callable(fetch) and (active or terminal_run is not None), 'both reviewed client events jobs required')
    done = verify_approvals(policy, reader, reference, terminal_run, now, active=active)
    if staged_at is not None:
        policy.require(done is not None and done <= staged_at <= now, 'client events result staged before terminal completion')
    proof = historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    current_subject(policy, reader, reference['identity'])
    request = result(reference, terminal_run, proof)
    if terminal_run is None:
        request['schema'] = 'box-quality-client-events-consumer/v11'
    return request


def prescreen(policy, artifact, reader, fetch):
    policy.require(canonical(artifact) == canonical(ARCHIVE) and callable(fetch), 'wrong client events preflight artifact')
    current_subject(policy, reader, {'repository_id': 1423238398, 'head_repository_id': 1423238398, 'pull_number': PR,
                                    'base_sha': BASE, 'candidate_sha': HEAD})
    historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    return {'candidate_sha': HEAD, 'candidate_tree': TREE, 'baseline': BASELINE, 'hosted': HOSTED, 'artifact': artifact}


def private_fetch(policy, token):
    old_fetch = policy.oauth_delta.private_fetch(policy, token)
    evidence = policy.consumer.evidence

    def fetch(commit):
        if commit != ARCHIVE['commit']:
            return old_fetch(commit)
        path = '/repos/' + evidence.EVIDENCE_REPOSITORY
        repo = policy.consumer.api(path, token)
        policy.require(repo['id'] == evidence.EVIDENCE_REPOSITORY_ID and
                       repo['full_name'] == evidence.EVIDENCE_REPOSITORY and repo['private'] is True,
                       'wrong private client events evidence repository')
        request = urllib.request.Request('https://api.github.com' + path + '/contents/' + ARCHIVE['path'] + '?ref=' + commit,
            method='GET', headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github.raw+json',
                                   'X-GitHub-Api-Version': '2022-11-28'})
        with urllib.request.build_opener(policy.consumer.NoRedirect).open(request, timeout=30) as response:
            return response.read(ARCHIVE['bytes'] + 1)
    return fetch


def verify_dispatch(policy, environment, *, terminal, clock):
    evidence = policy.consumer.evidence
    trusted = environment['BOX_FORMAL_CONSUMER_SHA']
    policy.require(environment['GITHUB_EVENT_NAME'] == 'workflow_dispatch' and environment['GITHUB_REF'] == CONTROL_REF and
                   environment['GITHUB_REPOSITORY'] == policy.REPOSITORY and environment['GITHUB_REPOSITORY_ID'] == '1423238398' and
                   environment['GITHUB_WORKFLOW_REF'] == policy.REPOSITORY + '/' + evidence.WORKFLOW_PATH + '@' + CONTROL_REF and
                   environment['GITHUB_RUN_ATTEMPT'] == '1' and environment['GITHUB_ACTOR_ID'] == str(evidence.TRIGGER_ID) and
                   environment['GITHUB_SHA'] == environment['GITHUB_WORKFLOW_SHA'] == trusted, 'wrong native client events dispatch')
    reference = evidence.decode(environment['BOX_FORMAL_ADMISSION'])
    run = int(environment['GITHUB_RUN_ID'])
    validate_reference(reference, int(clock()))
    policy.require(trusted == reference['identity']['consumer_sha'] and (run != reference['consumer_run']) == terminal,
                   'wrong protected client events run')
    if terminal:
        for field, key in [('BOX_FORMAL_HOSTED_RUN_ID', 'run_id'), ('BOX_FORMAL_HOSTED_RUN_ATTEMPT', 'attempt'),
                           ('BOX_FORMAL_HOSTED_CI_BLOB', 'workflow_blob')]:
            policy.require(environment[field] == str(HOSTED[key]), 'wrong client events hosted run pin')
    token = environment['BOX_FORMAL_EVIDENCE_TOKEN']
    policy.require(token and token != environment['GITHUB_TOKEN'], 'dedicated private evidence reader required')
    checked = verify(policy, reference, policy.GitHubReader(environment['GITHUB_TOKEN']), private_fetch(policy, token),
                     run if terminal else None, int(clock()), active=True)
    validate_reference(reference, int(clock()))
    return checked


def verify_public(policy, environment, reader, *, clock):
    event = policy.ci_premerge_event(environment)
    policy.require(environment['GITHUB_EVENT_NAME'] == 'pull_request' and environment['GITHUB_RUN_ID'] == str(HOSTED['run_id'])
                   and event['number'] == PR and event['pull_request']['head']['sha'] == HEAD, 'wrong native client events gate')
    check = reader.formal_quality_check(HEAD)
    request = policy.consumer.evidence.decode(check['output']['text'])
    now = int(clock())
    reference = request['artifact']
    validate_reference(reference, now)
    policy.validate_ci_evidence_reference(event, environment, reference['identity'])
    policy.validate_gate(check, request, completed=True)
    proof = historical_baseline(policy, reader)
    terminal = request['terminal_run']
    policy.require(type(terminal) is int and check['id'] not in (C1, PR254_C2) and
                   policy.consumer.canonical(request) == policy.consumer.canonical(result(reference, terminal, proof)),
                   'client events result differs from exact scope and subjects')
    done = verify_approvals(policy, reader, reference, terminal, now)
    evidence = policy.consumer.evidence
    evidence.check_times(check, reference['identity'], now)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'client events signature predates second approval')
    current_subject(policy, reader, reference['identity'])
    policy.resolve_ci_candidate(environment, reader)
    validate_reference(reference, int(clock()))
    return request
