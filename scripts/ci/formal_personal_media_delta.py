"""Formal evidence reuse for PR #271 personal media versions."""
from hashlib import sha256
import io
import json
import re
import urllib.request
import zipfile


PR = 271
HEAD = 'fb783827573c42fa60c80569c9d32af6a7a85831'
TREE = '458fbdc233766c8bef07d6c63e9984cfca47a044'
BASE = '42f5313bb5edad78aa8535ba21f244d7be8c0691'
BRANCH = 'codex/w04-mj-private-versions'
CONTROL_REF = 'refs/heads/codex/formal-quality-r20'
REFERENCE_SCHEMA = 'box-formal-personal-media-versions-delta-ref/v20'
TERMINAL_SCHEMA = 'box-quality-terminal/v20'
SCOPE = 'personal-media-versions'
C1 = 135232975120
PR270_C2 = 137270298256
PR270_PROOF = '54d365a564770dbcc2bda30738139b38057bb898725ffe0ebad94de83a75c61c'
PR270_A, PR270_B = 45041485401, 45042211547
PR270_NATIVE_JOB = 137270637236
R19 = '412067efcde100a3779161fc06d5b2598a6905c5'
HOSTED = {'attempt': 1, 'run_id': 45046129881, 'workflow_blob': 'c123990e4a8c9fd981b721455a8edbc65b62dfc5'}
BASELINE = {'pull_number': 270, 'candidate_sha': 'a0d80cecd97c84791af4899c8a9ede0940bde664',
            'candidate_tree': '0a7eec73666b2eb94a5e4e6012d3370559994296', 'merge_commit': BASE,
            'terminal_check_id': PR270_C2, 'native_run': 45037322687,
            'native_attempt': 2, 'native_job': PR270_NATIVE_JOB}
MANIFEST = 'c42224a51929c64b3efafe41b4ce494f1ac1c331a8dee242ebf126e6b6b2dd2a'
ARCHIVE = {'commit': '86b43f04a0eaa5db98f9eebdc5687f17a217581b', 'path': 'formal-audit/pr271-fb783827-formal-inputs.zip', 'bytes': 25138, 'sha256': '9c2415f15e241300b04a9e3d84debaa0bad11395e276e166b54dc973c3e827ee'}
BLOBS = {'controller/personal_media.go': '5b0b4bf7e97c1109c46a9b677d9b1098a835e59c', 'controller/task.go': 'a40d37c1647f2d491e28fb18b8d667ecd1ed65c6', 'controller/task_generic_test.go': '6b8f95ff12c88c67f43fb4ff42e3dc6c9a9145aa', 'controller/video_proxy.go': '39f83ebea335e3c5ad96cfd837c64152dd5a3e00', 'docs/openapi/api.json': '2d6d879b1d4864f23091963d3dad21a1d1b779dd', 'middleware/access_token_routes.go': '11159488e8a32a099c3da78fefacce2d06cd1e3a', 'model/main.go': '856f7cbcbaaf3582fe62dfc867ab8faee996d744', 'model/midjourney_image_version.go': '573d60c77dbba5612dd18dfc5359f52b57376119', 'model/personal_media.go': '9033d6afd7095a4f788654ed2c6b7df0df1c6113', 'model/task_cas_test.go': 'a3c8ee9bd80bc3e11984bfafb65ea0ecdd959453', 'model/user.go': '3933b8a21d022040519f0f8841b7930334907fb1', 'model/user_authentication_test.go': '514f6072a0ea0e4c91c7817bf595cf7513971c6c', 'router/api-router.go': 'd953636de4671413532b300c4ec6a1bcf1a47beb', 'router/oauth_public_test.go': '49775015313546665d7bf444f70067765fe2396a', 'router/organization_access_test.go': '8835dc31e2b5c9e97fe45ee97646060c449ba8d1', 'web/src/features/usage-logs/__tests__/artifacts.test.ts': '2641b4b14d2883ea5269a91be0e6ae1908c66338', 'web/src/features/usage-logs/components/__tests__/image-dialog.test.tsx': '3c752f2aaca381a1e5939b8e990e78f157283cc6', 'web/src/features/usage-logs/components/columns/drawing-logs-columns.tsx': '91acf5b8c7f02441a97cbacf884fd196de3a1fa3', 'web/src/features/usage-logs/components/dialogs/image-dialog.tsx': '0797cfb9c8fdeda313599f2d08b24a6a55959481', 'web/src/features/usage-logs/lib/task-artifacts.ts': '5f866048e04c80e5b4c9c476478d0c48169fa809'}
MEMBERS = {'candidate.patch': 'aeb1897f8915777509d286cca69d264934f043223cc3f92bc93385244e9eac93', 'final-focused.jsonl': 'a01dc89c6dd40a4b4e6a1016768f91b79a985b83c3825f53227f93fecac54239', 'final-image-format-contract.jsonl': '536a77f3e9fb0759eb43ca1b0f0507e61fe71a2bedde6e0e9b1791983998c19e', 'receipt.json': '1c682e01d589db5eae889d6f5806af6e9c8d4e20f367ebe5e844c30f54f0401f', 'w04-private-focused.jsonl': '8f6c1d228d096c76df3d424fb34b710a3e5dc458e050c8322a80fb44be510120'}
FILES = tuple(BLOBS)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=True).encode('ascii')


def descriptor():
    return ARCHIVE.copy()


def consumer_intent(artifact, control, nonce):
    if (canonical(artifact) != canonical(ARCHIVE) or not re.fullmatch('[a-f0-9]{40}', control) or
            control == R19 or not re.fullmatch('[a-f0-9]{32}', nonce)):
        raise ValueError('invalid personal media version delta selection')
    bound = {'artifact': artifact, 'baseline': BASELINE, 'tree': TREE, 'head': HEAD,
             'hosted': HOSTED, 'control': control, 'nonce': nonce}
    return sha256(canonical(bound)).hexdigest()


def make_reference(artifact, control, consumer_run, opened, nonce):
    consumer_intent(artifact, control, nonce)
    if type(consumer_run) is not int or consumer_run <= 0 or type(opened) is not int or opened <= 0:
        raise ValueError('invalid personal media version delta approval times')
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
        raise ValueError('invalid or expired personal media version delta reference')


def validate_package(policy, raw):
    require = policy.require
    decode = policy.consumer.evidence.decode
    require(type(raw) is bytes and len(raw) == ARCHIVE['bytes'] and sha256(raw).hexdigest() == ARCHIVE['sha256'],
            'wrong immutable personal media version archive')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(sorted(archive.namelist()) == sorted((*MEMBERS, 'manifest.json')),
                'incorrect personal media version inventory')
        manifest = archive.read('manifest.json')
        require(sha256(manifest).hexdigest() == MANIFEST and
                {name: sha256(archive.read(name)).hexdigest() for name in MEMBERS} == MEMBERS,
                'unreviewed personal media version member')
        data = decode(manifest)
        require(data == dict(kind='pr271-personal-media-versions/v1', pull=PR, head=HEAD, tree=TREE,
                             base=BASE, paths=list(FILES), hosted=HOSTED, blobs=BLOBS,
                             baseline_terminal=PR270_C2, members=MEMBERS),
                'wrong personal media version evidence subjects')
        receipt = decode(archive.read('receipt.json'))
        require((receipt['baseline'], receipt['candidate_tree'], receipt['patch'], receipt['reviewer'],
                 receipt['verdict'], receipt['frontend_diff_sha256']) ==
                (BASE, TREE, MEMBERS['candidate.patch'], 'gate_review', 'ACCEPT_SCOPED',
                 '6536d855338f23af784fe3b714932472c2f07596cb3c0d82b47942448d72165e'),
                'wrong personal media version receipt')
        expected = {'final-focused.jsonl': 30, 'final-image-format-contract.jsonl': 8, 'w04-private-focused.jsonl': 47}
        require(receipt['target_counts'] == expected, 'wrong scoped test inventory')
        for name, count in expected.items():
            rows = [decode(line) for line in archive.read(name).splitlines()]
            require(len(rows) == count and all(row['Action'] == 'pass' for row in rows),
                    'incomplete scoped personal media version proof')



def current_subject(policy, reader, identity):
    base = reader.repository()
    pr = reader.pull(PR)
    repo_id = identity['repository_id']
    policy.require(base['id'] == repo_id and base['full_name'] == policy.REPOSITORY and
                   pr['number'] == PR and pr['state'] == 'open' and pr['merged'] is False and pr['draft'] is False and pr['changed_files'] == len(FILES) and
                   pr['head']['repo']['id'] == pr['base']['repo']['id'] == repo_id and
                   pr['head']['repo']['full_name'] == pr['base']['repo']['full_name'] == policy.REPOSITORY and
                   pr['head']['sha'] == HEAD and pr['head']['ref'] == BRANCH and
                   pr['base']['sha'] == BASE and pr['base']['ref'] == 'main', 'current personal media version PR subject changed')
    commit = reader.commit(HEAD)
    policy.require(commit['sha'] == HEAD and commit['tree']['sha'] == TREE and
                   [row['sha'] for row in commit['parents']] == [BASE], 'wrong personal media version candidate tree or parents')
    policy.verify_hosted_jobs(reader, HOSTED, identity)


def historical_baseline(policy, reader, fetch=None):
    previous = policy.legacy_media_delta
    evidence = policy.consumer.evidence
    older = previous.historical_baseline(policy, reader, fetch)
    check = reader.check(PR270_C2)
    proof = evidence.decode(check['output']['text'])
    policy.require(check['id'] == PR270_C2 and policy.consumer.digest(proof) == PR270_PROOF and
                   (proof['candidate_sha'], proof['candidate_tree'], proof['consumer_run'], proof['terminal_run']) ==
                   (BASELINE['candidate_sha'], BASELINE['candidate_tree'], PR270_A, PR270_B),
                   'wrong signed PR270 baseline')
    signed = evidence.github_time(check, 'completed_at')
    policy.validate_gate(check, proof, completed=True)
    ref = proof['artifact']
    previous.validate_reference(ref, signed)
    policy.require(ref['identity']['consumer_sha'] == R19 and
                   policy.consumer.canonical(proof) == policy.consumer.canonical(previous.result(ref, PR270_B, older)),
                   'signed PR270 evidence differs from reviewed contract')
    done = previous.verify_approvals(policy, reader, ref, PR270_B, signed)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'PR270 signature predates its reviews')
    prior_run = reader.run(previous.HOSTED['run_id'], previous.HOSTED['attempt'])
    repo_id = ref['identity']['repository_id']
    policy.require(prior_run['id'] == previous.HOSTED['run_id'] and
                   prior_run['run_attempt'] == previous.HOSTED['attempt'] and
                   prior_run['workflow_id'] == policy.CI_WORKFLOW_ID and prior_run['path'] == '.github/workflows/ci.yml' and
                   prior_run['event'] == 'pull_request' and prior_run['head_sha'] == previous.HEAD and
                   prior_run['repository']['id'] == prior_run['head_repository']['id'] == repo_id and
                   reader.hosted_workflow_blob(previous.HEAD) == previous.HOSTED['workflow_blob'],
                   'historical PR270 hosted run or workflow blob changed')
    policy.verify_hosted_job_steps(reader, previous.HOSTED, previous.HEAD)
    if fetch is not None:
        previous.validate_package(policy, fetch(ref['artifact']['commit']))
    pr = reader.pull(270)
    merged = reader.commit(BASE)
    policy.require(pr['number'] == 270 and pr['state'] == 'closed' and pr['merged'] is True and
                   pr['merge_commit_sha'] == BASE and pr['head']['sha'] == BASELINE['candidate_sha'] and
                   pr['base']['ref'] == 'main' and pr['base']['repo']['id'] == repo_id and
                   merged['sha'] == BASE and merged['tree']['sha'] == BASELINE['candidate_tree'] and
                   [row['sha'] for row in merged['parents']] == [previous.BASE, previous.HEAD], 'wrong historical PR270 merge')
    run = reader.run(BASELINE['native_run'], 2)
    policy.require(run['id'] == BASELINE['native_run'] and run['run_attempt'] == 2 and
                   run['head_sha'] == BASELINE['candidate_sha'] and
                   run['repository']['id'] == run['head_repository']['id'] == repo_id and
                   run['path'] == '.github/workflows/ci.yml' and run['event'] == 'pull_request' and
                   run['workflow_id'] == policy.CI_WORKFLOW_ID and
                   run['status'] == 'completed' and run['conclusion'] == 'success', 'historical PR270 native gate did not pass')
    gate = policy.successful_job(reader.jobs(BASELINE['native_run'], 2), policy.GATE, BASELINE['candidate_sha'],
                                 ('Verify hosted jobs and authenticated exact-candidate quality',))
    policy.require(gate['id'] == PR270_NATIVE_JOB and gate['run_id'] == BASELINE['native_run'] and gate['run_attempt'] == 2 and
                   signed <= evidence.github_time(gate, 'started_at') <= evidence.github_time(gate, 'completed_at') <=
                   evidence.github_time(pr, 'merged_at') <= ref['identity']['release_expires_at'],
                   'PR270 native green and merge outside historical publication')
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
        policy.require(type(terminal_run) is int and terminal_run != consumer_run, 'separate personal media version terminal required')
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
            'release_expires_at': identity['release_expires_at'], 'admission_id': 'pr271-personal-media-versions-' + HEAD,
            'invocation': consumer_intent(reference['artifact'], identity['consumer_sha'], reference['nonce'])}


def verify(policy, reference, reader, fetch, terminal_run, now, *, active=False, staged_at=None):
    validate_reference(reference, now)
    policy.require(callable(fetch) and (active or terminal_run is not None), 'both reviewed personal media version jobs required')
    done = verify_approvals(policy, reader, reference, terminal_run, now, active=active)
    if staged_at is not None:
        policy.require(done is not None and done <= staged_at <= now, 'personal media version result staged before terminal completion')
    proof = historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    current_subject(policy, reader, reference['identity'])
    request = result(reference, terminal_run, proof)
    if terminal_run is None:
        request['schema'] = 'box-quality-personal-media-consumer/v20'
    return request


def prescreen(policy, artifact, reader, fetch):
    policy.require(canonical(artifact) == canonical(ARCHIVE) and callable(fetch), 'wrong personal media version preflight artifact')
    current_subject(policy, reader, {'repository_id': 1423238398, 'head_repository_id': 1423238398, 'pull_number': PR,
                                    'base_sha': BASE, 'candidate_sha': HEAD})
    historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    return {'candidate_sha': HEAD, 'candidate_tree': TREE, 'baseline': BASELINE, 'hosted': HOSTED, 'artifact': artifact}


def private_fetch(policy, token):
    old_fetch = policy.legacy_media_delta.private_fetch(policy, token)
    evidence = policy.consumer.evidence

    def fetch(commit):
        if commit != ARCHIVE['commit']:
            return old_fetch(commit)
        path = '/repos/' + evidence.EVIDENCE_REPOSITORY
        repo = policy.consumer.api(path, token)
        policy.require(repo['id'] == evidence.EVIDENCE_REPOSITORY_ID and
                       repo['full_name'] == evidence.EVIDENCE_REPOSITORY and repo['private'] is True,
                       'wrong private personal media version evidence repository')
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
                   environment['GITHUB_SHA'] == environment['GITHUB_WORKFLOW_SHA'] == trusted, 'wrong native personal media version dispatch')
    reference = evidence.decode(environment['BOX_FORMAL_ADMISSION'])
    run = int(environment['GITHUB_RUN_ID'])
    validate_reference(reference, int(clock()))
    policy.require(trusted == reference['identity']['consumer_sha'] and (run != reference['consumer_run']) == terminal,
                   'wrong protected personal media version run')
    if terminal:
        for field, key in [('BOX_FORMAL_HOSTED_RUN_ID', 'run_id'), ('BOX_FORMAL_HOSTED_RUN_ATTEMPT', 'attempt'),
                           ('BOX_FORMAL_HOSTED_CI_BLOB', 'workflow_blob')]:
            policy.require(environment[field] == str(HOSTED[key]), 'wrong personal media version hosted run pin')
    token = environment['BOX_FORMAL_EVIDENCE_TOKEN']
    policy.require(token and token != environment['GITHUB_TOKEN'], 'dedicated private evidence reader required')
    checked = verify(policy, reference, policy.GitHubReader(environment['GITHUB_TOKEN']), private_fetch(policy, token),
                     run if terminal else None, int(clock()), active=True)
    validate_reference(reference, int(clock()))
    return checked


def verify_public(policy, environment, reader, *, clock):
    event = policy.ci_premerge_event(environment)
    policy.require(environment['GITHUB_EVENT_NAME'] == 'pull_request' and environment['GITHUB_RUN_ID'] == str(HOSTED['run_id'])
                   and event['number'] == PR and event['pull_request']['head']['sha'] == HEAD, 'wrong native personal media version gate')
    check = reader.formal_quality_check(HEAD)
    request = policy.consumer.evidence.decode(check['output']['text'])
    now = int(clock())
    reference = request['artifact']
    validate_reference(reference, now)
    policy.validate_ci_evidence_reference(event, environment, reference['identity'])
    policy.validate_gate(check, request, completed=True)
    proof = historical_baseline(policy, reader)
    terminal = request['terminal_run']
    policy.require(type(terminal) is int and check['id'] not in (C1, PR270_C2) and
                   policy.consumer.canonical(request) == policy.consumer.canonical(result(reference, terminal, proof)),
                   'personal media version result differs from exact scope and subjects')
    done = verify_approvals(policy, reader, reference, terminal, now)
    evidence = policy.consumer.evidence
    evidence.check_times(check, reference['identity'], now)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'personal media version signature predates second approval')
    current_subject(policy, reader, reference['identity'])
    policy.resolve_ci_candidate(environment, reader)
    validate_reference(reference, int(clock()))
    return request
