"""Formal evidence reuse for PR #254 OAuth application revocation readiness."""
from hashlib import sha256
import io
import json
import re
import urllib.request
import zipfile


PR = 254
HEAD = '8dfbbc5d41de5451ef69b99307b51f507f89ac38'
TREE = '430eebb7e33e7e7ec05497c4f607003eae1ee2e2'
BASE = 'ce07f5fdc220f9579cb0b53123a3ff611436e269'
PRIOR_HEAD = '0e4874280cf002a653100a20314017e639461907'
BRANCH = 'cursor/oauth-ttl-revoke-readiness-058f'
CONTROL_REF = 'refs/heads/codex/formal-quality-r10'
REFERENCE_SCHEMA = 'box-formal-oauth-delta-ref/v10'
TERMINAL_SCHEMA = 'box-quality-terminal/v10'
SCOPE = 'oauth-application-revocation-readiness'
C1 = 135232975120
PR257_C2 = 136183437537
PR257_PROOF = '3c82fe1045dfcba4022cde24f9f95ac6752a3936efc469075bc3636df8180e7e'
PR257_A, PR257_B = 44702671993, 44703179522
PR257_NATIVE_JOB = 136184298338
R9 = '0287ccaf1a89d0fbf0ac653629c17acd136900de'
HOSTED = {'run_id': 44710933114, 'attempt': 1,
          'workflow_blob': 'c123990e4a8c9fd981b721455a8edbc65b62dfc5'}
BASELINE = {'pull_number': 257, 'candidate_sha': '9eaf75cf963199f0d71612e0a89eceb783fb4f8c',
            'candidate_tree': '050741c77f9fd83c83dc44d2dd2572a31e4c211b', 'merge_commit': BASE,
            'terminal_check_id': PR257_C2, 'native_run': 44686942049,
            'native_attempt': 2, 'native_job': PR257_NATIVE_JOB}
ARCHIVE = {'commit': '7d428fd3d916fae85c3a5b300f07aafe850c0b46',
           'path': 'formal-audit/pr254-8dfbbc5d-formal-inputs.zip',
           'bytes': 9983, 'sha256': '9c1cd61ac3b28d30430653028cf0f85a896b22838b930bdd22557389d736b014'}
MANIFEST = '73970996d008a521a62d599051f3652f4449d0feda58441e7c4e2fa7d14d8be1'
PATCH = '2c472eeced99d40b71c1e3fed49ad8098756d0354ef0331e6989e9ca6b3be835'
VALIDATION = 'a97c4d5912cde2ad5afe37059118762c7e641799c54cc9ae8031fb1680048814'
TESTED_TREE = 'e1393911b625619fa269520a21b522af62df0851'
FILES = (
    'controller/oauth_public_client_test.go',
    'docs/authentication.md',
    'model/oauth_authorized_app.go',
    'model/oauth_cleanup.go',
    'router/oauth_public_test.go',
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=True).encode('ascii')


def descriptor():
    return ARCHIVE.copy()


def consumer_intent(artifact, control, nonce):
    if (canonical(artifact) != canonical(ARCHIVE) or not re.fullmatch('[a-f0-9]{40}', control) or
            control == R9 or not re.fullmatch('[a-f0-9]{32}', nonce)):
        raise ValueError('invalid OAuth delta selection')
    bound = {'artifact': artifact, 'baseline': BASELINE, 'tree': TREE, 'head': HEAD,
             'hosted': HOSTED, 'control': control, 'nonce': nonce}
    return sha256(canonical(bound)).hexdigest()


def make_reference(artifact, control, consumer_run, opened, nonce):
    consumer_intent(artifact, control, nonce)
    if type(consumer_run) is not int or consumer_run <= 0 or type(opened) is not int or opened <= 0:
        raise ValueError('invalid OAuth delta approval times')
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
        raise ValueError('invalid or expired OAuth delta reference')


def validate_package(policy, raw):
    require = policy.require
    decode = policy.consumer.evidence.decode
    require(type(raw) is bytes and len(raw) == ARCHIVE['bytes'] and sha256(raw).hexdigest() == ARCHIVE['sha256'],
            'wrong immutable OAuth evidence')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(sorted(archive.namelist()) == ['manifest.json', 'scope.patch', 'validation.json'],
                'incorrect OAuth artifact inventory')
        manifest = archive.read('manifest.json')
        validation = archive.read('validation.json')
        require(sha256(manifest).hexdigest() == MANIFEST and sha256(archive.read('scope.patch')).hexdigest() == PATCH and
                sha256(validation).hexdigest() == VALIDATION, 'unreviewed OAuth evidence member')
    data = decode(manifest)
    require((data['kind'], data['pull'], data['head'], data['tree'], data['base'], data['prior_head'], data['paths']) ==
            ('pr254-oauth-revoke-delta/v1', PR, HEAD, TREE, BASE, PRIOR_HEAD, list(FILES)) and
            data['hosted'] == HOSTED and set(data['blobs']) == set(FILES) and data['tested_tree'] == TESTED_TREE and
            len(data['base_changes']) == 23 and data['hydra_joint_validation'] == 'held' and
            data['historical_257']['signed_payload_sha256'] == PR257_PROOF and
            data['members'] == {'scope.patch': PATCH, 'validation.json': VALIDATION}, 'wrong OAuth evidence subjects')
    result = decode(validation)
    require(result['candidate']['tree'] == TESTED_TREE and result['go'] == 'go1.26.10 linux/amd64' and
            result['sqlite'] == '3.50.4' and result['cleanup'] == {'ordinary_absent': True, 'formal_absent': True} and
            {key: row['records'] for key, row in result['sqlite_observations'].items()} ==
            {'controller': 8, 'sqlite-revoke': 2, 'sqlite-token': 12}, 'invalid SQLite OAuth verification')
    tests = ['TestOAuthAuthorizedAppRevokeReadiness',
             'TestOAuthAuthorizedAppRevokeReadiness/missing_source_store_refuses_local_revocation']
    require(result['sqlite_observations']['sqlite-revoke']['names'] == tests and
            {'TestOAuthPublicAuthorizationBoundary/access_token_ttl_bound/hydras_default_hour_is_refused',
             'TestOAuthPublicAuthorizationBoundary/access_token_ttl_bound/inclusive_fifteen_minutes_is_accepted'} <=
            set(result['sqlite_observations']['sqlite-token']['names']), 'missing scoped OAuth checks')
    require(set(result['matrix']) == {'mysql', 'postgres'}, 'incomplete real-database OAuth evidence')
    for name, version in [('mysql', '8.0.46'), ('postgres', 'PostgreSQL 15.19 ')]:
        row = result['matrix'][name]
        require(row['engine'] == name and len(row['version']) == 1 and row['version'][0].startswith(version) and
                type(row['process_exit']) is int and row['process_exit'] == 0 and
                row['none_network'] is True and row['cleanup_count_zero'] is True and
                row['owned_container_removed'] is True and row['test_exit_zero'] is True and row['passes'] == tests,
                'real-database OAuth verification did not pass')


def current_subject(policy, reader, identity):
    base = reader.repository()
    pr = reader.pull(PR)
    repo_id = identity['repository_id']
    policy.require(base['id'] == repo_id and base['full_name'] == policy.REPOSITORY and
                   pr['number'] == PR and pr['state'] == 'open' and pr['merged'] is False and pr['changed_files'] == 5 and
                   pr['head']['repo']['id'] == pr['base']['repo']['id'] == repo_id and
                   pr['head']['repo']['full_name'] == pr['base']['repo']['full_name'] == policy.REPOSITORY and
                   pr['head']['sha'] == HEAD and pr['head']['ref'] == BRANCH and
                   pr['base']['sha'] == BASE and pr['base']['ref'] == 'main', 'current OAuth PR subject changed')
    commit = reader.commit(HEAD)
    policy.require(commit['sha'] == HEAD and commit['tree']['sha'] == TREE and
                   [row['sha'] for row in commit['parents']] == [PRIOR_HEAD, BASE], 'wrong OAuth candidate tree or parents')
    policy.verify_hosted_jobs(reader, HOSTED, identity)


def historical_baseline(policy, reader, fetch=None):
    previous = policy.invitation_delta
    evidence = policy.consumer.evidence
    proof256 = previous.historical_baseline(policy, reader, fetch)
    check = reader.check(PR257_C2)
    proof = evidence.decode(check['output']['text'])
    policy.require(check['id'] == PR257_C2 and policy.consumer.digest(proof) == PR257_PROOF and
                   (proof['candidate_sha'], proof['candidate_tree'], proof['consumer_run'], proof['terminal_run']) ==
                   (BASELINE['candidate_sha'], BASELINE['candidate_tree'], PR257_A, PR257_B), 'wrong signed PR257 baseline')
    signed = evidence.github_time(check, 'completed_at')
    policy.validate_gate(check, proof, completed=True)
    ref = proof['artifact']
    previous.validate_reference(ref, signed)
    policy.require(ref['identity']['consumer_sha'] == R9 and
                   policy.consumer.canonical(proof) == policy.consumer.canonical(previous.result(ref, PR257_B, proof256)),
                   'signed PR257 evidence differs from reviewed contract')
    done = previous.verify_approvals(policy, reader, ref, PR257_B, signed)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'PR257 signature predates its reviews')
    # GitHub can drop pull_requests on historical Actions runs after source branch deletion.
    # The exact signed v9 proof already bound all four jobs before merge; authenticate
    # the original workflow definition and the observed final GitHub job below.
    original = reader.run(previous.HOSTED['run_id'], previous.HOSTED['attempt'])
    repo_id = ref['identity']['repository_id']
    policy.require(original['id'] == previous.HOSTED['run_id'] and original['run_attempt'] == previous.HOSTED['attempt'] and
                   original['workflow_id'] == policy.CI_WORKFLOW_ID and original['path'] == '.github/workflows/ci.yml' and
                   original['event'] == 'pull_request' and original['head_sha'] == previous.HEAD and
                   original['repository']['id'] == original['head_repository']['id'] == repo_id and
                   reader.hosted_workflow_blob(previous.HEAD) == previous.HOSTED['workflow_blob'],
                   'historical PR257 hosted run or workflow blob changed')
    policy.verify_hosted_job_steps(reader, previous.HOSTED, previous.HEAD)
    if fetch is not None:
        previous.validate_package(policy, fetch(ref['artifact']['commit']))
    pr = reader.pull(257)
    merged = reader.commit(BASE)
    policy.require(pr['number'] == 257 and pr['state'] == 'closed' and pr['merged'] is True and
                   pr['merge_commit_sha'] == BASE and pr['head']['sha'] == BASELINE['candidate_sha'] and
                   pr['base']['ref'] == 'main' and pr['base']['repo']['id'] == repo_id and
                   merged['sha'] == BASE and merged['tree']['sha'] == BASELINE['candidate_tree'] and
                   [row['sha'] for row in merged['parents']] == [previous.BASE, previous.HEAD], 'wrong historical PR257 merge')
    run = reader.run(BASELINE['native_run'], 2)
    policy.require(run['id'] == BASELINE['native_run'] and run['run_attempt'] == 2 and
                   run['head_sha'] == BASELINE['candidate_sha'] and
                   run['repository']['id'] == run['head_repository']['id'] == repo_id and
                   run['path'] == '.github/workflows/ci.yml' and run['event'] == 'pull_request' and run['workflow_id'] == policy.CI_WORKFLOW_ID and
                   run['status'] == 'completed' and run['conclusion'] == 'success', 'historical PR257 native gate did not pass')
    gate = policy.successful_job(reader.jobs(BASELINE['native_run'], 2), policy.GATE, BASELINE['candidate_sha'],
                                 ('Verify hosted jobs and authenticated exact-candidate quality',))
    policy.require(gate['id'] == PR257_NATIVE_JOB and gate['run_id'] == BASELINE['native_run'] and gate['run_attempt'] == 2 and
                   signed <= evidence.github_time(gate, 'started_at') <= evidence.github_time(gate, 'completed_at') <=
                   evidence.github_time(pr, 'merged_at') <= ref['identity']['release_expires_at'],
                   'PR257 native green and merge outside historical publication')
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
        policy.require(type(terminal_run) is int and terminal_run != consumer_run, 'separate OAuth terminal required')
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
            'release_expires_at': identity['release_expires_at'], 'admission_id': 'pr254-oauth-delta-' + HEAD,
            'invocation': consumer_intent(reference['artifact'], identity['consumer_sha'], reference['nonce'])}


def verify(policy, reference, reader, fetch, terminal_run, now, *, active=False, staged_at=None):
    validate_reference(reference, now)
    policy.require(callable(fetch) and (active or terminal_run is not None), 'both reviewed OAuth jobs required')
    done = verify_approvals(policy, reader, reference, terminal_run, now, active=active)
    if staged_at is not None:
        policy.require(done is not None and done <= staged_at <= now, 'OAuth result staged before terminal completion')
    proof = historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    current_subject(policy, reader, reference['identity'])
    request = result(reference, terminal_run, proof)
    if terminal_run is None:
        request['schema'] = 'box-quality-oauth-consumer/v10'
    return request


def prescreen(policy, artifact, reader, fetch):
    policy.require(canonical(artifact) == canonical(ARCHIVE) and callable(fetch), 'wrong OAuth preflight artifact')
    current_subject(policy, reader, {'repository_id': 1423238398, 'head_repository_id': 1423238398, 'pull_number': PR,
                                    'base_sha': BASE, 'candidate_sha': HEAD})
    historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    return {'candidate_sha': HEAD, 'candidate_tree': TREE, 'baseline': BASELINE, 'hosted': HOSTED, 'artifact': artifact}


def private_fetch(policy, token):
    old_fetch = policy.invitation_delta.private_fetch(policy, token)
    evidence = policy.consumer.evidence

    def fetch(commit):
        if commit != ARCHIVE['commit']:
            return old_fetch(commit)
        path = '/repos/' + evidence.EVIDENCE_REPOSITORY
        repo = policy.consumer.api(path, token)
        policy.require(repo['id'] == evidence.EVIDENCE_REPOSITORY_ID and
                       repo['full_name'] == evidence.EVIDENCE_REPOSITORY and repo['private'] is True,
                       'wrong private OAuth evidence repository')
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
                   environment['GITHUB_SHA'] == environment['GITHUB_WORKFLOW_SHA'] == trusted, 'wrong native OAuth dispatch')
    reference = evidence.decode(environment['BOX_FORMAL_ADMISSION'])
    run = int(environment['GITHUB_RUN_ID'])
    validate_reference(reference, int(clock()))
    policy.require(trusted == reference['identity']['consumer_sha'] and (run != reference['consumer_run']) == terminal,
                   'wrong protected OAuth run')
    if terminal:
        for field, key in [('BOX_FORMAL_HOSTED_RUN_ID', 'run_id'), ('BOX_FORMAL_HOSTED_RUN_ATTEMPT', 'attempt'),
                           ('BOX_FORMAL_HOSTED_CI_BLOB', 'workflow_blob')]:
            policy.require(environment[field] == str(HOSTED[key]), 'wrong OAuth hosted run pin')
    token = environment['BOX_FORMAL_EVIDENCE_TOKEN']
    policy.require(token and token != environment['GITHUB_TOKEN'], 'dedicated private evidence reader required')
    checked = verify(policy, reference, policy.GitHubReader(environment['GITHUB_TOKEN']), private_fetch(policy, token),
                     run if terminal else None, int(clock()), active=True)
    validate_reference(reference, int(clock()))
    return checked


def verify_public(policy, environment, reader, *, clock):
    event = policy.ci_premerge_event(environment)
    policy.require(environment['GITHUB_EVENT_NAME'] == 'pull_request' and environment['GITHUB_RUN_ID'] == str(HOSTED['run_id'])
                   and event['number'] == PR and event['pull_request']['head']['sha'] == HEAD, 'wrong native OAuth gate')
    check = reader.formal_quality_check(HEAD)
    request = policy.consumer.evidence.decode(check['output']['text'])
    now = int(clock())
    reference = request['artifact']
    validate_reference(reference, now)
    policy.validate_ci_evidence_reference(event, environment, reference['identity'])
    policy.validate_gate(check, request, completed=True)
    proof = historical_baseline(policy, reader)
    terminal = request['terminal_run']
    policy.require(type(terminal) is int and check['id'] not in (C1, PR257_C2) and
                   policy.consumer.canonical(request) == policy.consumer.canonical(result(reference, terminal, proof)),
                   'OAuth result differs from exact scope and subjects')
    done = verify_approvals(policy, reader, reference, terminal, now)
    evidence = policy.consumer.evidence
    evidence.check_times(check, reference['identity'], now)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'OAuth signature predates second approval')
    current_subject(policy, reader, reference['identity'])
    policy.resolve_ci_candidate(environment, reader)
    validate_reference(reference, int(clock()))
    return request
