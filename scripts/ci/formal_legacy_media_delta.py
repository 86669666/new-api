"""Formal evidence reuse for PR #270 legacy media compatibility."""
from hashlib import sha256
import io
import json
import re
import urllib.request
import zipfile


PR = 270
HEAD = 'a0d80cecd97c84791af4899c8a9ede0940bde664'
TREE = '0a7eec73666b2eb94a5e4e6012d3370559994296'
BASE = '2d239e958d6275605be553ca23569d85af41b9f0'
BRANCH = 'codex/issue-2-w04-legacy-link-contract'
CONTROL_REF = 'refs/heads/codex/formal-quality-r19'
REFERENCE_SCHEMA = 'box-formal-legacy-media-compatibility-delta-ref/v19'
TERMINAL_SCHEMA = 'box-quality-terminal/v19'
SCOPE = 'legacy-media-compatibility'
C1 = 135232975120
PR269_C2 = 137246861955
PR269_PROOF = 'c07e266279e1c4783ec3a1d4ceb3161b9ca91586d28f197aa8b7f1ad272f30c5'
PR269_A, PR269_B = 45032991237, 45033571110
PR269_NATIVE_JOB = 137247810173
R18 = '0eab58924d13a9282c873863ef45615fca16a97c'
HOSTED = {'attempt': 1, 'run_id': 45037322687, 'workflow_blob': 'c123990e4a8c9fd981b721455a8edbc65b62dfc5'}
BASELINE = {'pull_number': 269, 'candidate_sha': '6f2dd68168e5b4cec34fbaa4912591e15e474177',
            'candidate_tree': '5334b023867f86794e6321aeb24d3ef9fcd8b865', 'merge_commit': BASE,
            'terminal_check_id': PR269_C2, 'native_run': 45004512658,
            'native_attempt': 2, 'native_job': PR269_NATIVE_JOB}
MANIFEST = 'ec70b8e9e228d881d09b1f3869f089a5bf340004787c0e535c8ffda7f48076f3'
ARCHIVE = {'commit': '1cb455bc40fb4a29dd6a70d7b5e5fb88749fd28b', 'path': 'formal-audit/pr270-a0d80cec-formal-inputs.zip', 'bytes': 4097, 'sha256': '2c9b3b87394a8ff79a2a0ec6f35f83f84bf951e5a39126806a8c3c95498b6f6d'}
BLOBS = {'controller/midjourney_test.go': '81516c2b3df311fc83ee80fab915ad13c9ae50e6', 'router/organization_access_test.go': '10d815ed874d57a93ccd85846ddc18f629c98a7e'}
MEMBERS = {'candidate.patch': '85c3d5c8bd24b1e2d572dc2455781b241882b13cf036c512a4e8e448f1218445', 'receipt.json': '4e7f3a77117d51d78e53774e65a02c943b852a56b043897d10bb9527f550c848', 'targeted.jsonl': '697fcdae5d2d891cfd904eff395106e52e07124b97ef6eb41cca5e5382da6cae'}
FILES = tuple(BLOBS)
ARCHIVE_NAME = 'pr270-a0d80cec-formal-inputs.zip'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=True).encode('ascii')


def descriptor():
    return ARCHIVE.copy()


def consumer_intent(artifact, control, nonce):
    if (canonical(artifact) != canonical(ARCHIVE) or not re.fullmatch('[a-f0-9]{40}', control) or
            control == R18 or not re.fullmatch('[a-f0-9]{32}', nonce)):
        raise ValueError('invalid authorization policy reload delta selection')
    bound = {'artifact': artifact, 'baseline': BASELINE, 'tree': TREE, 'head': HEAD,
             'hosted': HOSTED, 'control': control, 'nonce': nonce}
    return sha256(canonical(bound)).hexdigest()


def make_reference(artifact, control, consumer_run, opened, nonce):
    consumer_intent(artifact, control, nonce)
    if type(consumer_run) is not int or consumer_run <= 0 or type(opened) is not int or opened <= 0:
        raise ValueError('invalid authorization policy reload delta approval times')
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
        raise ValueError('invalid or expired authorization policy reload delta reference')


def validate_package(policy, raw):
    require = policy.require
    decode = policy.consumer.evidence.decode
    require(type(raw) is bytes and len(raw) == ARCHIVE['bytes'] and sha256(raw).hexdigest() == ARCHIVE['sha256'],
            'wrong immutable legacy media compatibility archive')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(sorted(archive.namelist()) == sorted((*MEMBERS, 'manifest.json')),
                'incorrect legacy media compatibility inventory')
        manifest = archive.read('manifest.json')
        require(sha256(manifest).hexdigest() == MANIFEST and
                {name: sha256(archive.read(name)).hexdigest() for name in MEMBERS} == MEMBERS,
                'unreviewed legacy media compatibility member')
        data = decode(manifest)
        require(data == dict(kind='pr270-legacy-media-compatibility/v1', pull=PR, head=HEAD, tree=TREE,
                             base=BASE, paths=list(FILES), hosted=HOSTED, blobs=BLOBS,
                             baseline_terminal=PR269_C2, members=MEMBERS),
                'wrong legacy media compatibility evidence subjects')
        receipt = decode(archive.read('receipt.json'))
        require((receipt['baseline'], receipt['candidate_tree'], receipt['patch'], receipt['results'],
                 receipt['reviewer'], receipt['verdict'], receipt['test_roots']) ==
                (BASE, TREE, MEMBERS['candidate.patch'], MEMBERS['targeted.jsonl'], 'gate_review',
                 'ACCEPT_SCOPED', ['TestMidjourneyHistoryPreservesLegacyImageLinks',
                                   'TestOrganizationLegacyCapabilityCompatibility']),
                'wrong legacy media compatibility receipt')
        require(receipt['go'] == '1.26.10 darwin/arm64' and
                receipt['contract'] == 'Legacy Midjourney list projection and archived synthetic V1 GET/HEAD; production code unchanged.',
                'wrong legacy media compatibility contract')
        rows = [decode(line) for line in archive.read('targeted.jsonl').splitlines()]
        outcomes = [row for row in rows if row.get('Action') in ('pass', 'fail', 'skip')]
        require(len(outcomes) == 10 and all(row['Action'] == 'pass' for row in outcomes) and
                {row.get('Package') for row in outcomes} ==
                {'github.com/QuantumNous/new-api/controller', 'github.com/QuantumNous/new-api/router'} and
                {row.get('Test') for row in outcomes if row.get('Test')} ==
                {'TestMidjourneyHistoryPreservesLegacyImageLinks',
                 'TestMidjourneyHistoryPreservesLegacyImageLinks/admin',
                 'TestMidjourneyHistoryPreservesLegacyImageLinks/admin/gateway_link',
                 'TestMidjourneyHistoryPreservesLegacyImageLinks/admin/upstream_link',
                 'TestMidjourneyHistoryPreservesLegacyImageLinks/personal',
                 'TestMidjourneyHistoryPreservesLegacyImageLinks/personal/gateway_link',
                 'TestMidjourneyHistoryPreservesLegacyImageLinks/personal/upstream_link',
                 'TestOrganizationLegacyCapabilityCompatibility'},
                'incomplete legacy media compatibility targeted proof')


def current_subject(policy, reader, identity):
    base = reader.repository()
    pr = reader.pull(PR)
    repo_id = identity['repository_id']
    policy.require(base['id'] == repo_id and base['full_name'] == policy.REPOSITORY and
                   pr['number'] == PR and pr['state'] == 'open' and pr['merged'] is False and pr['draft'] is False and pr['changed_files'] == len(FILES) and
                   pr['head']['repo']['id'] == pr['base']['repo']['id'] == repo_id and
                   pr['head']['repo']['full_name'] == pr['base']['repo']['full_name'] == policy.REPOSITORY and
                   pr['head']['sha'] == HEAD and pr['head']['ref'] == BRANCH and
                   pr['base']['sha'] == BASE and pr['base']['ref'] == 'main', 'current authorization policy reload PR subject changed')
    commit = reader.commit(HEAD)
    policy.require(commit['sha'] == HEAD and commit['tree']['sha'] == TREE and
                   [row['sha'] for row in commit['parents']] == [BASE], 'wrong authorization policy reload candidate tree or parents')
    policy.verify_hosted_jobs(reader, HOSTED, identity)


def historical_baseline(policy, reader, fetch=None):
    previous = policy.authz_policy_reload_delta
    evidence = policy.consumer.evidence
    older = previous.historical_baseline(policy, reader, fetch)
    check = reader.check(PR269_C2)
    proof = evidence.decode(check['output']['text'])
    policy.require(check['id'] == PR269_C2 and policy.consumer.digest(proof) == PR269_PROOF and
                   (proof['candidate_sha'], proof['candidate_tree'], proof['consumer_run'], proof['terminal_run']) ==
                   (BASELINE['candidate_sha'], BASELINE['candidate_tree'], PR269_A, PR269_B),
                   'wrong signed PR269 baseline')
    signed = evidence.github_time(check, 'completed_at')
    policy.validate_gate(check, proof, completed=True)
    ref = proof['artifact']
    previous.validate_reference(ref, signed)
    policy.require(ref['identity']['consumer_sha'] == R18 and
                   policy.consumer.canonical(proof) == policy.consumer.canonical(previous.result(ref, PR269_B, older)),
                   'signed PR269 evidence differs from reviewed contract')
    done = previous.verify_approvals(policy, reader, ref, PR269_B, signed)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'PR269 signature predates its reviews')
    prior_run = reader.run(previous.HOSTED['run_id'], previous.HOSTED['attempt'])
    repo_id = ref['identity']['repository_id']
    policy.require(prior_run['id'] == previous.HOSTED['run_id'] and
                   prior_run['run_attempt'] == previous.HOSTED['attempt'] and
                   prior_run['workflow_id'] == policy.CI_WORKFLOW_ID and prior_run['path'] == '.github/workflows/ci.yml' and
                   prior_run['event'] == 'pull_request' and prior_run['head_sha'] == previous.HEAD and
                   prior_run['repository']['id'] == prior_run['head_repository']['id'] == repo_id and
                   reader.hosted_workflow_blob(previous.HEAD) == previous.HOSTED['workflow_blob'],
                   'historical PR269 hosted run or workflow blob changed')
    policy.verify_hosted_job_steps(reader, previous.HOSTED, previous.HEAD)
    if fetch is not None:
        previous.validate_package(policy, fetch(ref['artifact']['commit']))
    pr = reader.pull(269)
    merged = reader.commit(BASE)
    policy.require(pr['number'] == 269 and pr['state'] == 'closed' and pr['merged'] is True and
                   pr['merge_commit_sha'] == BASE and pr['head']['sha'] == BASELINE['candidate_sha'] and
                   pr['base']['ref'] == 'main' and pr['base']['repo']['id'] == repo_id and
                   merged['sha'] == BASE and merged['tree']['sha'] == BASELINE['candidate_tree'] and
                   [row['sha'] for row in merged['parents']] == [previous.BASE, previous.HEAD], 'wrong historical PR269 merge')
    run = reader.run(BASELINE['native_run'], 2)
    policy.require(run['id'] == BASELINE['native_run'] and run['run_attempt'] == 2 and
                   run['head_sha'] == BASELINE['candidate_sha'] and
                   run['repository']['id'] == run['head_repository']['id'] == repo_id and
                   run['path'] == '.github/workflows/ci.yml' and run['event'] == 'pull_request' and
                   run['workflow_id'] == policy.CI_WORKFLOW_ID and
                   run['status'] == 'completed' and run['conclusion'] == 'success', 'historical PR269 native gate did not pass')
    gate = policy.successful_job(reader.jobs(BASELINE['native_run'], 2), policy.GATE, BASELINE['candidate_sha'],
                                 ('Verify hosted jobs and authenticated exact-candidate quality',))
    policy.require(gate['id'] == PR269_NATIVE_JOB and gate['run_id'] == BASELINE['native_run'] and gate['run_attempt'] == 2 and
                   signed <= evidence.github_time(gate, 'started_at') <= evidence.github_time(gate, 'completed_at') <=
                   evidence.github_time(pr, 'merged_at') <= ref['identity']['release_expires_at'],
                   'PR269 native green and merge outside historical publication')
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
        policy.require(type(terminal_run) is int and terminal_run != consumer_run, 'separate authorization policy reload terminal required')
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
            'release_expires_at': identity['release_expires_at'], 'admission_id': 'pr270-legacy-media-compatibility-' + HEAD,
            'invocation': consumer_intent(reference['artifact'], identity['consumer_sha'], reference['nonce'])}


def verify(policy, reference, reader, fetch, terminal_run, now, *, active=False, staged_at=None):
    validate_reference(reference, now)
    policy.require(callable(fetch) and (active or terminal_run is not None), 'both reviewed authorization policy reload jobs required')
    done = verify_approvals(policy, reader, reference, terminal_run, now, active=active)
    if staged_at is not None:
        policy.require(done is not None and done <= staged_at <= now, 'authorization policy reload result staged before terminal completion')
    proof = historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    current_subject(policy, reader, reference['identity'])
    request = result(reference, terminal_run, proof)
    if terminal_run is None:
        request['schema'] = 'box-quality-legacy-media-consumer/v19'
    return request


def prescreen(policy, artifact, reader, fetch):
    policy.require(canonical(artifact) == canonical(ARCHIVE) and callable(fetch), 'wrong authorization policy reload preflight artifact')
    current_subject(policy, reader, {'repository_id': 1423238398, 'head_repository_id': 1423238398, 'pull_number': PR,
                                    'base_sha': BASE, 'candidate_sha': HEAD})
    historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    return {'candidate_sha': HEAD, 'candidate_tree': TREE, 'baseline': BASELINE, 'hosted': HOSTED, 'artifact': artifact}


def private_fetch(policy, token):
    old_fetch = policy.authz_policy_reload_delta.private_fetch(policy, token)
    evidence = policy.consumer.evidence

    def fetch(commit):
        if commit != ARCHIVE['commit']:
            return old_fetch(commit)
        path = '/repos/' + evidence.EVIDENCE_REPOSITORY
        repo = policy.consumer.api(path, token)
        policy.require(repo['id'] == evidence.EVIDENCE_REPOSITORY_ID and
                       repo['full_name'] == evidence.EVIDENCE_REPOSITORY and repo['private'] is True,
                       'wrong private authorization policy reload evidence repository')
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
                   environment['GITHUB_SHA'] == environment['GITHUB_WORKFLOW_SHA'] == trusted, 'wrong native authorization policy reload dispatch')
    reference = evidence.decode(environment['BOX_FORMAL_ADMISSION'])
    run = int(environment['GITHUB_RUN_ID'])
    validate_reference(reference, int(clock()))
    policy.require(trusted == reference['identity']['consumer_sha'] and (run != reference['consumer_run']) == terminal,
                   'wrong protected authorization policy reload run')
    if terminal:
        for field, key in [('BOX_FORMAL_HOSTED_RUN_ID', 'run_id'), ('BOX_FORMAL_HOSTED_RUN_ATTEMPT', 'attempt'),
                           ('BOX_FORMAL_HOSTED_CI_BLOB', 'workflow_blob')]:
            policy.require(environment[field] == str(HOSTED[key]), 'wrong authorization policy reload hosted run pin')
    token = environment['BOX_FORMAL_EVIDENCE_TOKEN']
    policy.require(token and token != environment['GITHUB_TOKEN'], 'dedicated private evidence reader required')
    checked = verify(policy, reference, policy.GitHubReader(environment['GITHUB_TOKEN']), private_fetch(policy, token),
                     run if terminal else None, int(clock()), active=True)
    validate_reference(reference, int(clock()))
    return checked


def verify_public(policy, environment, reader, *, clock):
    event = policy.ci_premerge_event(environment)
    policy.require(environment['GITHUB_EVENT_NAME'] == 'pull_request' and environment['GITHUB_RUN_ID'] == str(HOSTED['run_id'])
                   and event['number'] == PR and event['pull_request']['head']['sha'] == HEAD, 'wrong native authorization policy reload gate')
    check = reader.formal_quality_check(HEAD)
    request = policy.consumer.evidence.decode(check['output']['text'])
    now = int(clock())
    reference = request['artifact']
    validate_reference(reference, now)
    policy.validate_ci_evidence_reference(event, environment, reference['identity'])
    policy.validate_gate(check, request, completed=True)
    proof = historical_baseline(policy, reader)
    terminal = request['terminal_run']
    policy.require(type(terminal) is int and check['id'] not in (C1, PR269_C2) and
                   policy.consumer.canonical(request) == policy.consumer.canonical(result(reference, terminal, proof)),
                   'authorization policy reload result differs from exact scope and subjects')
    done = verify_approvals(policy, reader, reference, terminal, now)
    evidence = policy.consumer.evidence
    evidence.check_times(check, reference['identity'], now)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'authorization policy reload signature predates second approval')
    current_subject(policy, reader, reference['identity'])
    policy.resolve_ci_candidate(environment, reader)
    validate_reference(reference, int(clock()))
    return request
