"""Formal evidence reuse for PR #274 fixed personal task images."""
from hashlib import sha256
import io
import json
import re
import urllib.request
import zipfile


PR = 274
HEAD = '9aee1f4140fed58a2bbd21d0e4d3fbf325081204'
TREE = 'f26724a21bc44fc13a565822578db9d19b1f439d'
BASE = '37e64c869be90f30a3dee24d52793a59b43a53bf'
BRANCH = 'codex/w04-generic-on-main'
CONTROL_REF = 'refs/heads/codex/formal-quality-r23'
REFERENCE_SCHEMA = 'box-formal-personal-task-image-delta-ref/v23'
TERMINAL_SCHEMA = 'box-quality-terminal/v23'
SCOPE = 'personal-task-image'
C1 = 135232975120
PR273_C2 = 137342669085
PR273_PROOF = '2b5ecba506e8cc7027e8d0f95c671035839c4317b17065c4f193324f0135a40f'
PR273_A, PR273_B = 45065429732, 45065777274
PR273_NATIVE_JOB = 137343082123
R22 = '5661717ae3bb926c329514f52f8525ecbcaf060b'
HOSTED = {'attempt': 1, 'run_id': 45069955933, 'workflow_blob': 'c123990e4a8c9fd981b721455a8edbc65b62dfc5'}
BASELINE = {'pull_number': 273, 'candidate_sha': '80113cb20afa89e422a71b7a00815fb2ecd18b65',
            'candidate_tree': '45ed16435683e44b0c63cf83579e2298ff81e65b', 'merge_commit': BASE, 'terminal_check_id': PR273_C2,
            'native_run': 45060605527, 'native_attempt': 2, 'native_job': PR273_NATIVE_JOB}
MANIFEST = '34440b53f618102a3ce9d925307d7f8d61deaf2cb3b392e2dcd645d53053e199'
ARCHIVE = {'commit': 'b1b7e2d5e4193a1678df9ca185d5ddb2c98dc3f8', 'path': 'formal-audit/pr274-9aee1f41-formal-inputs.zip', 'bytes': 22651, 'sha256': 'f9e7654501b503f6bfc1aa36393f34322b6038e88f00dba975041057d3896379'}
BLOBS = {'controller/personal_media.go': '3f2efff53f5f3a0021ed520b7e4492eda260731c', 'controller/personal_task_image.go': 'b880aa3283266cdb0b8f41eb9ffc4a34bcc9d968', 'controller/task.go': '2a8e8c3958b4a2516e769099eb39ca36dbcc37ec', 'docs/openapi/api.json': '800794fea53a1a6f9e3cc046828e861115837013', 'middleware/access_token_routes.go': '3a83ae950387de6f1f83af50c4b0c704d249515e', 'model/main.go': 'd15b58ff9c6969f90d080019ab5d725b5872b278', 'model/personal_task_image_version.go': '30f0e02e6999c4080de1cd404e2227e0e5b32b61', 'model/task_cas_test.go': '8255a7431e5a758320cfccda181ce0481c4c1922', 'model/user.go': 'c9c94dcd2d8ad56fd22968d66b99d25735d7e946', 'model/user_authentication_test.go': '99f2dab50f06b6298096920555a666db3a7945e7', 'pkg/jsplugin/registry.go': '582e665d27514566de4b9059845d65da9fb25e1b', 'router/api-router.go': 'd0ccedd2edb53954fa1a133f50ee71969a146ff1', 'router/oauth_public_test.go': 'f3ecd104eb97a198ff46997f431e7b0ef394c1e3', 'router/organization_access_test.go': '709c289a1c6d8bcbd2476bf047d790d5124c22ab', 'web/src/features/usage-logs/__tests__/artifacts.test.ts': '7c46e0ad9299b8bb6875d3d44f9b3c882b41933f', 'web/src/features/usage-logs/components/__tests__/image-dialog.test.tsx': '35b14950ba125cfbaf135d5e94b6de04086a31eb', 'web/src/features/usage-logs/components/dialogs/image-dialog.tsx': '1700aae50886e7c8a6ec2276aa6d502f4f190326', 'web/src/features/usage-logs/components/task-artifacts.tsx': '36d65502667ed3470e9cc6a22f4bb5ff3a56c932', 'web/src/features/usage-logs/lib/task-artifacts.ts': 'fc262426b62a5f66b76b00bf96e39d56b6879c0a', 'web/src/features/usage-logs/types.ts': '037adc9a2620e0eaf7df48ebdca2fdf193a2d90b'}
MEMBERS = {'candidate.patch': '4c981f4681b305924ed560778dc559289341dbb62409282644d8a4025ed79379', 'hard-delete.jsonl': '8ca41368011ae15f830f144cef88a9d51947746e38da5eec4fce2cc34436bb45', 'receipt.json': '3bb4d7d5c5b1a1a5edcb552a16f0f101353930f458ac000ce26b0b8876e89ac5', 'route-table.jsonl': 'c2d77f30c0d24b11d2dd0f9fb43a3aa355839917e7a13428c174c6b0242ffe0a', 'router.jsonl': 'a7fd9a6f94ce724a928375dc730b1b0df8096cf7ad66addd39936f6d9b71cbc7', 'sqlite-final.jsonl': 'd1d12c8e36e99488473750108acb620e1723a073d86c5897558381c4508ae11b'}
FILES = tuple(BLOBS)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=True).encode('ascii')


def descriptor():
    return ARCHIVE.copy()


def consumer_intent(artifact, control, nonce):
    if (canonical(artifact) != canonical(ARCHIVE) or not re.fullmatch('[a-f0-9]{40}', control) or
            control == R22 or not re.fullmatch('[a-f0-9]{32}', nonce)):
        raise ValueError('invalid personal task image delta selection')
    bound = {'artifact': artifact, 'baseline': BASELINE, 'tree': TREE, 'head': HEAD,
             'hosted': HOSTED, 'control': control, 'nonce': nonce}
    return sha256(canonical(bound)).hexdigest()


def make_reference(artifact, control, consumer_run, opened, nonce):
    consumer_intent(artifact, control, nonce)
    if type(consumer_run) is not int or consumer_run <= 0 or type(opened) is not int or opened <= 0:
        raise ValueError('invalid personal task image delta approval times')
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
        raise ValueError('invalid or expired personal task image delta reference')


def validate_package(policy, raw):
    require = policy.require
    decode = policy.consumer.evidence.decode
    require(type(raw) is bytes and len(raw) == ARCHIVE['bytes'] and sha256(raw).hexdigest() == ARCHIVE['sha256'],
            'wrong immutable personal task image archive')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(sorted(archive.namelist()) == sorted((*MEMBERS, 'manifest.json')),
                'incorrect personal task image inventory')
        manifest = archive.read('manifest.json')
        require(sha256(manifest).hexdigest() == MANIFEST and
                {name: sha256(archive.read(name)).hexdigest() for name in MEMBERS} == MEMBERS,
                'unreviewed personal task image member')
        data = decode(manifest)
        require(data == dict(kind='pr274-personal-task-image/v1', pull=PR, head=HEAD, tree=TREE,
                             base=BASE, paths=list(FILES), hosted=HOSTED, blobs=BLOBS,
                             baseline_terminal=PR273_C2, members=MEMBERS),
                'wrong personal task image evidence subjects')
        receipt = decode(archive.read('receipt.json'))
        require((receipt['baseline'], receipt['candidate_tree'], receipt['patch'], receipt['reviewer'],
                 receipt['verdict'], receipt['vitest_passed'], receipt['screenshot']['sha256']) ==
                (BASE, TREE, MEMBERS['candidate.patch'], 'gate_review', 'ACCEPT_SCOPED', 23,
                 '7b25305432b95316e3a6cc4e1e7b88d6c4006459d9b11545d1dc47a6aed3d9df'), 'wrong personal task image receipt')
        expected = {'hard-delete.jsonl': 2, 'route-table.jsonl': 2, 'router.jsonl': 6, 'sqlite-final.jsonl': 3}
        require(receipt['target_counts'] == expected, 'wrong scoped test inventory')
        for name, count in expected.items():
            rows = [decode(line) for line in archive.read(name).splitlines()]
            require(len(rows) == count and all(row['Action'] == 'pass' for row in rows),
                    'incomplete scoped personal task image proof')



def current_subject(policy, reader, identity):
    base = reader.repository()
    pr = reader.pull(PR)
    repo_id = identity['repository_id']
    policy.require(base['id'] == repo_id and base['full_name'] == policy.REPOSITORY and
                   pr['number'] == PR and pr['state'] == 'open' and pr['merged'] is False and pr['draft'] is False and pr['changed_files'] == len(FILES) and
                   pr['head']['repo']['id'] == pr['base']['repo']['id'] == repo_id and
                   pr['head']['repo']['full_name'] == pr['base']['repo']['full_name'] == policy.REPOSITORY and
                   pr['head']['sha'] == HEAD and pr['head']['ref'] == BRANCH and
                   pr['base']['sha'] == BASE and pr['base']['ref'] == 'main', 'current personal task image PR subject changed')
    commit = reader.commit(HEAD)
    policy.require(commit['sha'] == HEAD and commit['tree']['sha'] == TREE and
                   [row['sha'] for row in commit['parents']] == [BASE], 'wrong personal task image candidate tree or parents')
    policy.verify_hosted_jobs(reader, HOSTED, identity)


def historical_baseline(policy, reader, fetch=None):
    previous = policy.personal_media_video_delta
    evidence = policy.consumer.evidence
    older = previous.historical_baseline(policy, reader, fetch)
    check = reader.check(PR273_C2)
    proof = evidence.decode(check['output']['text'])
    policy.require(check['id'] == PR273_C2 and policy.consumer.digest(proof) == PR273_PROOF and
                   (proof['candidate_sha'], proof['candidate_tree'], proof['consumer_run'], proof['terminal_run']) ==
                   (BASELINE['candidate_sha'], BASELINE['candidate_tree'], PR273_A, PR273_B),
                   'wrong signed PR273 baseline')
    signed = evidence.github_time(check, 'completed_at')
    policy.validate_gate(check, proof, completed=True)
    ref = proof['artifact']
    previous.validate_reference(ref, signed)
    policy.require(ref['identity']['consumer_sha'] == R22 and
                   policy.consumer.canonical(proof) == policy.consumer.canonical(previous.result(ref, PR273_B, older)),
                   'signed PR273 evidence differs from reviewed contract')
    done = previous.verify_approvals(policy, reader, ref, PR273_B, signed)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'PR273 signature predates its reviews')
    prior_run = reader.run(previous.HOSTED['run_id'], previous.HOSTED['attempt'])
    repo_id = ref['identity']['repository_id']
    policy.require(prior_run['id'] == previous.HOSTED['run_id'] and
                   prior_run['run_attempt'] == previous.HOSTED['attempt'] and
                   prior_run['workflow_id'] == policy.CI_WORKFLOW_ID and prior_run['path'] == '.github/workflows/ci.yml' and
                   prior_run['event'] == 'pull_request' and prior_run['head_sha'] == previous.HEAD and
                   prior_run['repository']['id'] == prior_run['head_repository']['id'] == repo_id and
                   reader.hosted_workflow_blob(previous.HEAD) == previous.HOSTED['workflow_blob'],
                   'historical PR273 hosted run or workflow blob changed')
    policy.verify_hosted_job_steps(reader, previous.HOSTED, previous.HEAD)
    if fetch is not None:
        previous.validate_package(policy, fetch(ref['artifact']['commit']))
    pr = reader.pull(273)
    merged = reader.commit(BASE)
    policy.require(pr['number'] == 273 and pr['state'] == 'closed' and pr['merged'] is True and
                   pr['merge_commit_sha'] == BASE and pr['head']['sha'] == BASELINE['candidate_sha'] and
                   pr['base']['ref'] == 'main' and pr['base']['repo']['id'] == repo_id and
                   merged['sha'] == BASE and merged['tree']['sha'] == BASELINE['candidate_tree'] and
                   [row['sha'] for row in merged['parents']] == [previous.BASE, previous.HEAD], 'wrong historical PR273 merge')
    run = reader.run(BASELINE['native_run'], 2)
    policy.require(run['id'] == BASELINE['native_run'] and run['run_attempt'] == 2 and
                   run['head_sha'] == BASELINE['candidate_sha'] and
                   run['repository']['id'] == run['head_repository']['id'] == repo_id and
                   run['path'] == '.github/workflows/ci.yml' and run['event'] == 'pull_request' and
                   run['workflow_id'] == policy.CI_WORKFLOW_ID and
                   run['status'] == 'completed' and run['conclusion'] == 'success', 'historical PR273 native gate did not pass')
    gate = policy.successful_job(reader.jobs(BASELINE['native_run'], 2), policy.GATE, BASELINE['candidate_sha'],
                                 ('Verify hosted jobs and authenticated exact-candidate quality',))
    policy.require(gate['id'] == PR273_NATIVE_JOB and gate['run_id'] == BASELINE['native_run'] and gate['run_attempt'] == 2 and
                   signed <= evidence.github_time(gate, 'started_at') <= evidence.github_time(gate, 'completed_at') <=
                   evidence.github_time(pr, 'merged_at') <= ref['identity']['release_expires_at'],
                   'PR273 native green and merge outside historical publication')
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
        policy.require(type(terminal_run) is int and terminal_run != consumer_run, 'separate personal task image terminal required')
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
            'release_expires_at': identity['release_expires_at'], 'admission_id': 'pr274-personal-task-image-' + HEAD,
            'invocation': consumer_intent(reference['artifact'], identity['consumer_sha'], reference['nonce'])}


def verify(policy, reference, reader, fetch, terminal_run, now, *, active=False, staged_at=None):
    validate_reference(reference, now)
    policy.require(callable(fetch) and (active or terminal_run is not None), 'both reviewed personal task image jobs required')
    done = verify_approvals(policy, reader, reference, terminal_run, now, active=active)
    if staged_at is not None:
        policy.require(done is not None and done <= staged_at <= now, 'personal task image result staged before terminal completion')
    proof = historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    current_subject(policy, reader, reference['identity'])
    request = result(reference, terminal_run, proof)
    if terminal_run is None:
        request['schema'] = 'box-quality-personal-task-image-consumer/v23'
    return request


def prescreen(policy, artifact, reader, fetch):
    policy.require(canonical(artifact) == canonical(ARCHIVE) and callable(fetch), 'wrong personal task image preflight artifact')
    current_subject(policy, reader, {'repository_id': 1423238398, 'head_repository_id': 1423238398, 'pull_number': PR,
                                    'base_sha': BASE, 'candidate_sha': HEAD})
    historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    return {'candidate_sha': HEAD, 'candidate_tree': TREE, 'baseline': BASELINE, 'hosted': HOSTED, 'artifact': artifact}


def private_fetch(policy, token):
    old_fetch = policy.personal_media_video_delta.private_fetch(policy, token)
    evidence = policy.consumer.evidence

    def fetch(commit):
        if commit != ARCHIVE['commit']:
            return old_fetch(commit)
        path = '/repos/' + evidence.EVIDENCE_REPOSITORY
        repo = policy.consumer.api(path, token)
        policy.require(repo['id'] == evidence.EVIDENCE_REPOSITORY_ID and
                       repo['full_name'] == evidence.EVIDENCE_REPOSITORY and repo['private'] is True,
                       'wrong private personal task image evidence repository')
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
                   environment['GITHUB_SHA'] == environment['GITHUB_WORKFLOW_SHA'] == trusted, 'wrong native personal task image dispatch')
    reference = evidence.decode(environment['BOX_FORMAL_ADMISSION'])
    run = int(environment['GITHUB_RUN_ID'])
    validate_reference(reference, int(clock()))
    policy.require(trusted == reference['identity']['consumer_sha'] and (run != reference['consumer_run']) == terminal,
                   'wrong protected personal task image run')
    if terminal:
        for field, key in [('BOX_FORMAL_HOSTED_RUN_ID', 'run_id'), ('BOX_FORMAL_HOSTED_RUN_ATTEMPT', 'attempt'),
                           ('BOX_FORMAL_HOSTED_CI_BLOB', 'workflow_blob')]:
            policy.require(environment[field] == str(HOSTED[key]), 'wrong personal task image hosted run pin')
    token = environment['BOX_FORMAL_EVIDENCE_TOKEN']
    policy.require(token and token != environment['GITHUB_TOKEN'], 'dedicated private evidence reader required')
    checked = verify(policy, reference, policy.GitHubReader(environment['GITHUB_TOKEN']), private_fetch(policy, token),
                     run if terminal else None, int(clock()), active=True)
    validate_reference(reference, int(clock()))
    return checked


def verify_public(policy, environment, reader, *, clock):
    event = policy.ci_premerge_event(environment)
    policy.require(environment['GITHUB_EVENT_NAME'] == 'pull_request' and environment['GITHUB_RUN_ID'] == str(HOSTED['run_id'])
                   and event['number'] == PR and event['pull_request']['head']['sha'] == HEAD, 'wrong native personal task image gate')
    check = reader.formal_quality_check(HEAD)
    request = policy.consumer.evidence.decode(check['output']['text'])
    now = int(clock())
    reference = request['artifact']
    validate_reference(reference, now)
    policy.validate_ci_evidence_reference(event, environment, reference['identity'])
    policy.validate_gate(check, request, completed=True)
    proof = historical_baseline(policy, reader)
    terminal = request['terminal_run']
    policy.require(type(terminal) is int and check['id'] not in (C1, PR273_C2) and
                   policy.consumer.canonical(request) == policy.consumer.canonical(result(reference, terminal, proof)),
                   'personal task image result differs from exact scope and subjects')
    done = verify_approvals(policy, reader, reference, terminal, now)
    evidence = policy.consumer.evidence
    evidence.check_times(check, reference['identity'], now)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'personal task image signature predates second approval')
    current_subject(policy, reader, reference['identity'])
    policy.resolve_ci_candidate(environment, reader)
    validate_reference(reference, int(clock()))
    return request
