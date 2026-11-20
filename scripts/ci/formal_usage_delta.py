"""Formal evidence reuse for PR #256 personal usage series."""
from hashlib import sha256
import io
import json
import re
import urllib.request
import zipfile


PR = 256
HEAD = 'b42fe14873936479e5322ccb58bd79c2b4d9acdc'
TREE = '4a5347ec7407d10c6792d15b15abe39d3481abf2'
BASE = '03ee5a12f8faea62216297a7374a3a206e10b0a5'
PRIOR_HEAD = '67819e0e5303cb10109e636d3164401bc428bc56'
BRANCH = 'codex/t59u-issue16-daily-usage'
CONTROL_REF = 'refs/heads/codex/formal-quality-r8'
REFERENCE_SCHEMA = 'box-formal-usage-delta-ref/v8'
TERMINAL_SCHEMA = 'box-quality-terminal/v8'
SCOPE = 'personal-usage-series-delta'
C1 = 135232975120
PR261_C2 = 135826673126
PR261_PROOF = '69aef804ca1ea76a0e36b69a1501bf1921fbf1968c2ed3cdc15afccff0874d53'
PR261_A, PR261_B = 44596277283, 44596878011
PR261_NATIVE_JOB = 135827489957
R7 = '44a86d23ef85fcfb399111573571c8c4c18afe4a'
HOSTED = {'run_id': 44679225544, 'attempt': 1, 'workflow_blob': 'c123990e4a8c9fd981b721455a8edbc65b62dfc5'}
BASELINE = {'pull_number': 261, 'candidate_sha': '02b7c615e56c41ca0d3abe3b55b09b7e281f4a83',
            'candidate_tree': 'e70bdc1ce19516df0ee7ae6fd16850ac7ae18772', 'merge_commit': BASE,
            'terminal_check_id': PR261_C2, 'native_run': 44593651313, 'native_attempt': 2, 'native_job': PR261_NATIVE_JOB}
ARCHIVE = {'commit': 'f089a7db4b4f814881a58118ccf198c6a32bb8dd',
           'path': 'formal-audit/pr256-b42fe148-personal-usage-evidence.zip',
           'bytes': 16476, 'sha256': '16e96eb2be448a2a53dd62d2bc83d4d5e91e2543e659695c046d1231461f03ce'}
MANIFEST = '80863dacc9cdf61fec4044f87b82d7ea081685e30c7e5145c4571bceb54c9b8f'
PATCH = '77f987d6e2ac960909938260f210fe666734e9d99966967d78e36d25a174c9f6'
TESTED_TREE = 'e8f4ecd6404e1857f2241c294df96307fceec269'
FILES = ('controller/usedata.go', 'controller/usedata_daily_test.go', 'docs/openapi/api.json', 'model/usedata.go',
         'scripts/openapi/check_client.mjs', 'scripts/openapi/check_contract.py', 'scripts/openapi/fixtures.json')
STATIC_EXTRAS = ('scripts/openapi/check_route_coverage.py', 'scripts/openapi/route_coverage.json',
                 'scripts/openapi/test_route_coverage.py')
SQLITE_LEAVES = {'TestPersonalQuotaDaily': 39, 'TestUserQuotaDataSeriesContract': 6, 'TestUserQuotaRangeErrorStatus': 10}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=True).encode('ascii')


def descriptor():
    return ARCHIVE.copy()


def consumer_intent(artifact, control, nonce):
    if (canonical(artifact) != canonical(ARCHIVE) or not re.fullmatch('[a-f0-9]{40}', control) or
            control == R7 or not re.fullmatch('[a-f0-9]{32}', nonce)):
        raise ValueError('invalid usage delta selection')
    bound = {'artifact': artifact, 'baseline': BASELINE, 'tree': TREE, 'head': HEAD,
             'hosted': HOSTED, 'control': control, 'nonce': nonce}
    return sha256(canonical(bound)).hexdigest()


def make_reference(artifact, control, consumer_run, opened, nonce):
    consumer_intent(artifact, control, nonce)
    if type(consumer_run) is not int or consumer_run <= 0 or type(opened) is not int or opened <= 0:
        raise ValueError('invalid usage delta approval times')
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
        raise ValueError('invalid or expired usage delta reference')


def validate_package(policy, raw):
    require = policy.require
    require(type(raw) is bytes and len(raw) == ARCHIVE['bytes'] and sha256(raw).hexdigest() == ARCHIVE['sha256'],
            'wrong immutable usage evidence')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = ('scope.patch', 'identity.json', 'outcome.json', 'go-test.log')
        require(sorted(archive.namelist()) == sorted((*names, 'manifest.json')), 'incorrect usage artifact inventory')
        manifest = archive.read('manifest.json')
        require(sha256(manifest).hexdigest() == MANIFEST, 'unreviewed usage manifest')
        data = policy.consumer.evidence.decode(manifest)
        require((data['schema'], data['pull'], data['head'], data['tree'], data['main'], data['prior_head']) ==
                ('pr256-personal-usage-delta/v1', PR, HEAD, TREE, BASE, PRIOR_HEAD) and
                data['paths'] == list(FILES) and set(data['blobs']) == set(FILES) and
                data['tested_tree'] == TESTED_TREE and data['tested_delta_extras'] == list(STATIC_EXTRAS) and
                data['sqlite_leaf_counts'] == SQLITE_LEAVES and data['members']['scope.patch'] == PATCH,
                'wrong usage evidence subjects')
        require(data['members'] == {name: sha256(archive.read(name)).hexdigest() for name in names},
                'usage evidence member changed')
        outcome = policy.consumer.evidence.decode(archive.read('outcome.json'))
        require(type(outcome['exit_code']) is int and outcome['exit_code'] == 0 and outcome['package_pass'] is True and
                outcome['fail_or_skip'] == [] and outcome['leaf_counts'] == SQLITE_LEAVES and
                outcome['raw_sha256'] == data['members']['go-test.log'], 'usage focused verification not successful')


def current_subject(policy, reader, identity):
    base = reader.repository()
    pr = reader.pull(PR)
    repo_id = identity['repository_id']
    policy.require(base['id'] == repo_id and base['full_name'] == policy.REPOSITORY and
                   pr['number'] == PR and pr['state'] == 'open' and pr['merged'] is False and pr['changed_files'] == 7 and
                   pr['head']['repo']['id'] == pr['base']['repo']['id'] == repo_id and
                   pr['head']['repo']['full_name'] == pr['base']['repo']['full_name'] == policy.REPOSITORY and
                   pr['head']['sha'] == HEAD and pr['head']['ref'] == BRANCH and
                   pr['base']['sha'] == BASE and pr['base']['ref'] == 'main', 'current usage PR subject changed')
    commit = reader.commit(HEAD)
    policy.require(commit['sha'] == HEAD and commit['tree']['sha'] == TREE and
                   [row['sha'] for row in commit['parents']] == [PRIOR_HEAD, BASE], 'wrong usage candidate tree or parents')
    policy.verify_hosted_jobs(reader, HOSTED, identity)


def historical_baseline(policy, reader, fetch=None):
    previous = policy.static_delta
    evidence = policy.consumer.evidence
    proof262 = previous.historical_baseline(policy, reader, fetch)
    check = reader.check(PR261_C2)
    proof = evidence.decode(check['output']['text'])
    policy.require(check['id'] == PR261_C2 and policy.consumer.digest(proof) == PR261_PROOF and
                   (proof['candidate_sha'], proof['candidate_tree'], proof['consumer_run'], proof['terminal_run']) ==
                   (BASELINE['candidate_sha'], BASELINE['candidate_tree'], PR261_A, PR261_B), 'wrong signed PR261 baseline')
    signed = evidence.github_time(check, 'completed_at')
    policy.validate_gate(check, proof, completed=True)
    ref = proof['artifact']
    previous.validate_reference(ref, signed)
    policy.require(ref['identity']['consumer_sha'] == R7 and
                   policy.consumer.canonical(proof) == policy.consumer.canonical(previous.result(ref, PR261_B, proof262)),
                   'signed PR261 evidence differs from reviewed contract')
    done = previous.verify_approvals(policy, reader, ref, PR261_B, signed)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'PR261 signature predates its reviews')
    # GitHub can drop pull_requests on historical Actions runs after source branch deletion.
    # The exact signed v6 proof already bound all four jobs before merge; authenticate
    # the original workflow definition and the observed final GitHub job below.
    original = reader.run(previous.HOSTED['run_id'], previous.HOSTED['attempt'])
    repo_id = ref['identity']['repository_id']
    policy.require(original['id'] == previous.HOSTED['run_id'] and original['run_attempt'] == previous.HOSTED['attempt'] and
                   original['workflow_id'] == policy.CI_WORKFLOW_ID and original['path'] == '.github/workflows/ci.yml' and
                   original['event'] == 'pull_request' and original['head_sha'] == previous.HEAD and
                   original['repository']['id'] == original['head_repository']['id'] == repo_id and
                   reader.hosted_workflow_blob(previous.HEAD) == previous.HOSTED['workflow_blob'],
                   'historical PR261 hosted run or workflow blob changed')
    policy.verify_hosted_job_steps(reader, previous.HOSTED, previous.HEAD)
    if fetch is not None:
        previous.validate_package(policy, fetch(ref['artifact']['commit']))
    pr = reader.pull(261)
    merged = reader.commit(BASE)
    policy.require(pr['number'] == 261 and pr['state'] == 'closed' and pr['merged'] is True and
                   pr['merge_commit_sha'] == BASE and pr['head']['sha'] == BASELINE['candidate_sha'] and
                   pr['base']['ref'] == 'main' and pr['base']['repo']['id'] == repo_id and
                   merged['sha'] == BASE and merged['tree']['sha'] == BASELINE['candidate_tree'] and
                   [row['sha'] for row in merged['parents']] == [previous.BASE, previous.HEAD], 'wrong historical PR261 merge')
    run = reader.run(BASELINE['native_run'], 2)
    policy.require(run['id'] == BASELINE['native_run'] and run['run_attempt'] == 2 and
                   run['head_sha'] == BASELINE['candidate_sha'] and
                   run['repository']['id'] == run['head_repository']['id'] == repo_id and
                   run['path'] == '.github/workflows/ci.yml' and run['event'] == 'pull_request' and run['workflow_id'] == policy.CI_WORKFLOW_ID and
                   run['status'] == 'completed' and run['conclusion'] == 'success', 'historical PR261 native gate did not pass')
    gate = policy.successful_job(reader.jobs(BASELINE['native_run'], 2), policy.GATE, BASELINE['candidate_sha'],
                                 ('Verify hosted jobs and authenticated exact-candidate quality',))
    policy.require(gate['id'] == PR261_NATIVE_JOB and gate['run_id'] == BASELINE['native_run'] and gate['run_attempt'] == 2 and
                   signed <= evidence.github_time(gate, 'started_at') <= evidence.github_time(gate, 'completed_at') <=
                   evidence.github_time(pr, 'merged_at') <= ref['identity']['release_expires_at'],
                   'PR261 native green and merge outside historical publication')
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
        policy.require(type(terminal_run) is int and terminal_run != consumer_run, 'separate usage terminal required')
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
            'release_expires_at': identity['release_expires_at'], 'admission_id': 'pr256-usage-delta-' + HEAD,
            'invocation': consumer_intent(reference['artifact'], identity['consumer_sha'], reference['nonce'])}


def verify(policy, reference, reader, fetch, terminal_run, now, *, active=False, staged_at=None):
    validate_reference(reference, now)
    policy.require(callable(fetch) and (active or terminal_run is not None), 'both reviewed usage jobs required')
    done = verify_approvals(policy, reader, reference, terminal_run, now, active=active)
    if staged_at is not None:
        policy.require(done is not None and done <= staged_at <= now, 'usage result staged before terminal completion')
    proof = historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    current_subject(policy, reader, reference['identity'])
    request = result(reference, terminal_run, proof)
    if terminal_run is None:
        request['schema'] = 'box-quality-usage-consumer/v8'
    return request


def prescreen(policy, artifact, reader, fetch):
    policy.require(canonical(artifact) == canonical(ARCHIVE) and callable(fetch), 'wrong usage preflight artifact')
    current_subject(policy, reader, {'repository_id': 1423238398, 'head_repository_id': 1423238398, 'pull_number': PR,
                                    'base_sha': BASE, 'candidate_sha': HEAD})
    historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    return {'candidate_sha': HEAD, 'candidate_tree': TREE, 'baseline': BASELINE, 'hosted': HOSTED, 'artifact': artifact}


def private_fetch(policy, token):
    old_fetch = policy.static_delta.private_fetch(policy, token)
    evidence = policy.consumer.evidence

    def fetch(commit):
        if commit != ARCHIVE['commit']:
            return old_fetch(commit)
        path = '/repos/' + evidence.EVIDENCE_REPOSITORY
        repo = policy.consumer.api(path, token)
        policy.require(repo['id'] == evidence.EVIDENCE_REPOSITORY_ID and
                       repo['full_name'] == evidence.EVIDENCE_REPOSITORY and repo['private'] is True,
                       'wrong private usage evidence repository')
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
                   environment['GITHUB_SHA'] == environment['GITHUB_WORKFLOW_SHA'] == trusted, 'wrong native usage dispatch')
    reference = evidence.decode(environment['BOX_FORMAL_ADMISSION'])
    run = int(environment['GITHUB_RUN_ID'])
    validate_reference(reference, int(clock()))
    policy.require(trusted == reference['identity']['consumer_sha'] and (run != reference['consumer_run']) == terminal,
                   'wrong protected usage run')
    if terminal:
        for field, key in [('BOX_FORMAL_HOSTED_RUN_ID', 'run_id'), ('BOX_FORMAL_HOSTED_RUN_ATTEMPT', 'attempt'),
                           ('BOX_FORMAL_HOSTED_CI_BLOB', 'workflow_blob')]:
            policy.require(environment[field] == str(HOSTED[key]), 'wrong usage hosted run pin')
    token = environment['BOX_FORMAL_EVIDENCE_TOKEN']
    policy.require(token and token != environment['GITHUB_TOKEN'], 'dedicated private evidence reader required')
    checked = verify(policy, reference, policy.GitHubReader(environment['GITHUB_TOKEN']), private_fetch(policy, token),
                     run if terminal else None, int(clock()), active=True)
    validate_reference(reference, int(clock()))
    return checked


def verify_public(policy, environment, reader, *, clock):
    event = policy.ci_premerge_event(environment)
    policy.require(environment['GITHUB_EVENT_NAME'] == 'pull_request' and environment['GITHUB_RUN_ID'] == str(HOSTED['run_id'])
                   and event['number'] == PR and event['pull_request']['head']['sha'] == HEAD, 'wrong native usage gate')
    check = reader.formal_quality_check(HEAD)
    request = policy.consumer.evidence.decode(check['output']['text'])
    now = int(clock())
    reference = request['artifact']
    validate_reference(reference, now)
    policy.validate_ci_evidence_reference(event, environment, reference['identity'])
    policy.validate_gate(check, request, completed=True)
    proof = historical_baseline(policy, reader)
    terminal = request['terminal_run']
    policy.require(type(terminal) is int and check['id'] not in (C1, PR261_C2) and
                   policy.consumer.canonical(request) == policy.consumer.canonical(result(reference, terminal, proof)),
                   'usage result differs from exact scope and subjects')
    done = verify_approvals(policy, reader, reference, terminal, now)
    evidence = policy.consumer.evidence
    evidence.check_times(check, reference['identity'], now)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'usage signature predates second approval')
    current_subject(policy, reader, reference['identity'])
    policy.resolve_ci_candidate(environment, reader)
    validate_reference(reference, int(clock()))
    return request
