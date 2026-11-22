"""Formal evidence reuse for PR #273 private legacy video."""
from hashlib import sha256
import io
import json
import re
import urllib.request
import zipfile


PR = 273
HEAD = '80113cb20afa89e422a71b7a00815fb2ecd18b65'
TREE = '45ed16435683e44b0c63cf83579e2298ff81e65b'
BASE = 'c6422f3e2032f468a1b5552b01455edd340fe7b5'
PARENT = 'fb783827573c42fa60c80569c9d32af6a7a85831'
SOURCE_HEAD = '3277f59e41dd96d6053413f9da646b4597923a1d'
SOURCE_PATCH = '0363052f0dbe78f6847325fbb733a42a22f84bdda8913b366e62bdfb45c9ab00'
BRANCH = 'codex/w04-private-legacy-video'
CONTROL_REF = 'refs/heads/codex/formal-quality-r22'
REFERENCE_SCHEMA = 'box-formal-personal-media-video-delta-ref/v22'
TERMINAL_SCHEMA = 'box-quality-terminal/v22'
SCOPE = 'personal-media-video'
C1 = 135232975120
PR272_C2 = 137323663770
PR272_PROOF = '169fea770736214068e56257d4f0f16b03ac504d63040b1bdc25ce2adc31d5ad'
PR272_A, PR272_B = 45057584845, 45058091883
PR272_NATIVE_JOB = 137324257970
R21 = 'ac965d81c336aeabba93250bf926c4d6a161dc84'
HOSTED = {'attempt': 1, 'run_id': 45060605527, 'workflow_blob': 'c123990e4a8c9fd981b721455a8edbc65b62dfc5'}
BASELINE = {'pull_number': 272, 'candidate_sha': '3f1f6350d3514d28794d2d53fc5f5f07582a24b1',
            'candidate_tree': 'e4657f8b542fd438290b6cd2b56d01ada9473574', 'merge_commit': BASE, 'terminal_check_id': PR272_C2,
            'native_run': 45056747057, 'native_attempt': 2, 'native_job': PR272_NATIVE_JOB}
MANIFEST = '7326751115116a5ae0eebbaaaeb0623b78f9e6ad1223c45eadf28114bfe4a31d'
ARCHIVE = {'commit': '4bdbb7484bb2d988f604566e337c66a542f485a9', 'path': 'formal-audit/pr273-80113cb2-formal-inputs.zip', 'bytes': 14964, 'sha256': 'bc8b027624c4ae7d08e4069beba651a7853a65914a37d878f80a39dc8cad3e8f'}
BLOBS = {'controller/personal_media.go': 'cd8793b62ec8697b252f443f7786b6b6b0f7241d', 'controller/task.go': 'ddb1fda871e1605ff51d205c60f52715c75e9d90', 'controller/video_proxy.go': '73c06308c63ffc37811a2ea98a6477c2b89c676c', 'docs/openapi/api.json': '1221a0ca808e5be8fd208b14bddfc8fa13c537e9', 'middleware/access_token_routes.go': '63485f6717b35c3a3309a8c9795d8fa28c142af2', 'middleware/task_media_auth.go': 'aabb2d5ef9f23ea6bda337d5f8f5038e8d56bacc', 'model/personal_media.go': 'ebdbf032d8d57a48fd5155bf65e7d38d5e395413', 'router/api-router.go': '86049e24d29a58897f8917a2ca9c11a3f3646741', 'router/organization_access_test.go': '68b7d83011b59aa0afde6b8998c824a8880bf313', 'service/task_media_ticket.go': '48c7531032c4ae1df6357f20032053df479b6610', 'service/task_media_ticket_test.go': '647b243783e54fa3243695a729091f1ab54ce0f2', 'web/src/features/usage-logs/components/columns/task-logs-columns.tsx': '7d16a2dc6ce866694c50b86c2507b508dc29d4c3', 'web/src/features/usage-logs/components/task-artifacts.tsx': '07629d52e86864fb22e4e903683088713839f6ee', 'web/src/features/usage-logs/lib/task-artifacts.ts': '6a5a69d91658aa3aec1c7e2e4d7ee2cc7eb887d4', 'web/src/features/usage-logs/types.ts': '6e638f55590ed5e2ca2cc2efaf95b3a4f9941a82'}
MEMBERS = {'candidate.patch': 'c2804c2108c9b849777d77cf16bd3f2cc045aa87b360c7ed2b840996354fc50e', 'receipt.json': 'd6f0e5c7509c71d78851dec9a277f785953a03943e48c1597838f6137d0e6da9', 'w04-native-asvs-go.jsonl': 'd1a29129e38f075fdb9bb1238c37bfda3db92d3f96627b1b32ebaa06a15ff14a', 'w04-native-final-go.jsonl': '4dfb71ab82677e93264e981d3764ce7244b0e788410edb66a142fbca90501630'}
FILES = tuple(BLOBS)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=True).encode('ascii')


def descriptor():
    return ARCHIVE.copy()


def consumer_intent(artifact, control, nonce):
    if (canonical(artifact) != canonical(ARCHIVE) or not re.fullmatch('[a-f0-9]{40}', control) or
            control == R21 or not re.fullmatch('[a-f0-9]{32}', nonce)):
        raise ValueError('invalid personal media video delta selection')
    bound = {'artifact': artifact, 'baseline': BASELINE, 'tree': TREE, 'head': HEAD,
             'hosted': HOSTED, 'control': control, 'nonce': nonce}
    return sha256(canonical(bound)).hexdigest()


def make_reference(artifact, control, consumer_run, opened, nonce):
    consumer_intent(artifact, control, nonce)
    if type(consumer_run) is not int or consumer_run <= 0 or type(opened) is not int or opened <= 0:
        raise ValueError('invalid personal media video delta approval times')
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
        raise ValueError('invalid or expired personal media video delta reference')


def validate_package(policy, raw):
    require = policy.require
    decode = policy.consumer.evidence.decode
    require(type(raw) is bytes and len(raw) == ARCHIVE['bytes'] and sha256(raw).hexdigest() == ARCHIVE['sha256'],
            'wrong immutable personal media video archive')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(sorted(archive.namelist()) == sorted((*MEMBERS, 'manifest.json')),
                'incorrect personal media video inventory')
        manifest = archive.read('manifest.json')
        require(sha256(manifest).hexdigest() == MANIFEST and
                {name: sha256(archive.read(name)).hexdigest() for name in MEMBERS} == MEMBERS,
                'unreviewed personal media video member')
        data = decode(manifest)
        require(data == dict(kind='pr273-personal-media-video/v1', pull=PR, head=HEAD, tree=TREE,
                             base=BASE, paths=list(FILES), hosted=HOSTED, blobs=BLOBS,
                             baseline_terminal=PR272_C2, members=MEMBERS),
                'wrong personal media video evidence subjects')
        receipt = decode(archive.read('receipt.json'))
        require((receipt['baseline'], receipt['candidate_tree'], receipt['source_parent'],
                 receipt['source_head'], receipt['source_patch'], receipt['patch'],
                 receipt['reviewer'], receipt['verdict'], receipt['vitest_passed']) ==
                (BASE, TREE, PARENT, SOURCE_HEAD, SOURCE_PATCH, MEMBERS['candidate.patch'],
                 'gate_review', 'ACCEPT_SCOPED', 16), 'wrong private video receipt')
        expected = {'w04-native-asvs-go.jsonl': 3, 'w04-native-final-go.jsonl': 12}
        require(receipt['target_counts'] == expected, 'wrong scoped test inventory')
        for name, count in expected.items():
            rows = [decode(line) for line in archive.read(name).splitlines()]
            require(len(rows) == count and all(row['Action'] == 'pass' for row in rows),
                    'incomplete scoped private video proof')



def current_subject(policy, reader, identity):
    base = reader.repository()
    pr = reader.pull(PR)
    repo_id = identity['repository_id']
    policy.require(base['id'] == repo_id and base['full_name'] == policy.REPOSITORY and
                   pr['number'] == PR and pr['state'] == 'open' and pr['merged'] is False and pr['draft'] is False and pr['changed_files'] == len(FILES) and
                   pr['head']['repo']['id'] == pr['base']['repo']['id'] == repo_id and
                   pr['head']['repo']['full_name'] == pr['base']['repo']['full_name'] == policy.REPOSITORY and
                   pr['head']['sha'] == HEAD and pr['head']['ref'] == BRANCH and
                   pr['base']['sha'] == BASE and pr['base']['ref'] == 'main', 'current personal media video PR subject changed')
    commit = reader.commit(HEAD)
    policy.require(commit['sha'] == HEAD and commit['tree']['sha'] == TREE and
                   [row['sha'] for row in commit['parents']] == [SOURCE_HEAD, BASE], 'wrong personal media video candidate tree or parents')
    policy.verify_hosted_jobs(reader, HOSTED, identity)


def historical_baseline(policy, reader, fetch=None):
    previous = policy.personal_media_share_delta
    evidence = policy.consumer.evidence
    older = previous.historical_baseline(policy, reader, fetch)
    check = reader.check(PR272_C2)
    proof = evidence.decode(check['output']['text'])
    policy.require(check['id'] == PR272_C2 and policy.consumer.digest(proof) == PR272_PROOF and
                   (proof['candidate_sha'], proof['candidate_tree'], proof['consumer_run'], proof['terminal_run']) ==
                   (BASELINE['candidate_sha'], BASELINE['candidate_tree'], PR272_A, PR272_B),
                   'wrong signed PR272 baseline')
    signed = evidence.github_time(check, 'completed_at')
    policy.validate_gate(check, proof, completed=True)
    ref = proof['artifact']
    previous.validate_reference(ref, signed)
    policy.require(ref['identity']['consumer_sha'] == R21 and
                   policy.consumer.canonical(proof) == policy.consumer.canonical(previous.result(ref, PR272_B, older)),
                   'signed PR272 evidence differs from reviewed contract')
    done = previous.verify_approvals(policy, reader, ref, PR272_B, signed)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'PR272 signature predates its reviews')
    prior_run = reader.run(previous.HOSTED['run_id'], previous.HOSTED['attempt'])
    repo_id = ref['identity']['repository_id']
    policy.require(prior_run['id'] == previous.HOSTED['run_id'] and
                   prior_run['run_attempt'] == previous.HOSTED['attempt'] and
                   prior_run['workflow_id'] == policy.CI_WORKFLOW_ID and prior_run['path'] == '.github/workflows/ci.yml' and
                   prior_run['event'] == 'pull_request' and prior_run['head_sha'] == previous.HEAD and
                   prior_run['repository']['id'] == prior_run['head_repository']['id'] == repo_id and
                   reader.hosted_workflow_blob(previous.HEAD) == previous.HOSTED['workflow_blob'],
                   'historical PR272 hosted run or workflow blob changed')
    policy.verify_hosted_job_steps(reader, previous.HOSTED, previous.HEAD)
    if fetch is not None:
        previous.validate_package(policy, fetch(ref['artifact']['commit']))
    pr = reader.pull(272)
    merged = reader.commit(BASE)
    policy.require(pr['number'] == 272 and pr['state'] == 'closed' and pr['merged'] is True and
                   pr['merge_commit_sha'] == BASE and pr['head']['sha'] == BASELINE['candidate_sha'] and
                   pr['base']['ref'] == 'main' and pr['base']['repo']['id'] == repo_id and
                   merged['sha'] == BASE and merged['tree']['sha'] == BASELINE['candidate_tree'] and
                   [row['sha'] for row in merged['parents']] == [previous.BASE, previous.HEAD], 'wrong historical PR272 merge')
    run = reader.run(BASELINE['native_run'], 2)
    policy.require(run['id'] == BASELINE['native_run'] and run['run_attempt'] == 2 and
                   run['head_sha'] == BASELINE['candidate_sha'] and
                   run['repository']['id'] == run['head_repository']['id'] == repo_id and
                   run['path'] == '.github/workflows/ci.yml' and run['event'] == 'pull_request' and
                   run['workflow_id'] == policy.CI_WORKFLOW_ID and
                   run['status'] == 'completed' and run['conclusion'] == 'success', 'historical PR272 native gate did not pass')
    gate = policy.successful_job(reader.jobs(BASELINE['native_run'], 2), policy.GATE, BASELINE['candidate_sha'],
                                 ('Verify hosted jobs and authenticated exact-candidate quality',))
    policy.require(gate['id'] == PR272_NATIVE_JOB and gate['run_id'] == BASELINE['native_run'] and gate['run_attempt'] == 2 and
                   signed <= evidence.github_time(gate, 'started_at') <= evidence.github_time(gate, 'completed_at') <=
                   evidence.github_time(pr, 'merged_at') <= ref['identity']['release_expires_at'],
                   'PR272 native green and merge outside historical publication')
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
        policy.require(type(terminal_run) is int and terminal_run != consumer_run, 'separate personal media video terminal required')
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
            'release_expires_at': identity['release_expires_at'], 'admission_id': 'pr273-personal-media-video-' + HEAD,
            'invocation': consumer_intent(reference['artifact'], identity['consumer_sha'], reference['nonce'])}


def verify(policy, reference, reader, fetch, terminal_run, now, *, active=False, staged_at=None):
    validate_reference(reference, now)
    policy.require(callable(fetch) and (active or terminal_run is not None), 'both reviewed personal media video jobs required')
    done = verify_approvals(policy, reader, reference, terminal_run, now, active=active)
    if staged_at is not None:
        policy.require(done is not None and done <= staged_at <= now, 'personal media video result staged before terminal completion')
    proof = historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    current_subject(policy, reader, reference['identity'])
    request = result(reference, terminal_run, proof)
    if terminal_run is None:
        request['schema'] = 'box-quality-personal-media-video-consumer/v22'
    return request


def prescreen(policy, artifact, reader, fetch):
    policy.require(canonical(artifact) == canonical(ARCHIVE) and callable(fetch), 'wrong personal media video preflight artifact')
    current_subject(policy, reader, {'repository_id': 1423238398, 'head_repository_id': 1423238398, 'pull_number': PR,
                                    'base_sha': BASE, 'candidate_sha': HEAD})
    historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    return {'candidate_sha': HEAD, 'candidate_tree': TREE, 'baseline': BASELINE, 'hosted': HOSTED, 'artifact': artifact}


def private_fetch(policy, token):
    old_fetch = policy.personal_media_share_delta.private_fetch(policy, token)
    evidence = policy.consumer.evidence

    def fetch(commit):
        if commit != ARCHIVE['commit']:
            return old_fetch(commit)
        path = '/repos/' + evidence.EVIDENCE_REPOSITORY
        repo = policy.consumer.api(path, token)
        policy.require(repo['id'] == evidence.EVIDENCE_REPOSITORY_ID and
                       repo['full_name'] == evidence.EVIDENCE_REPOSITORY and repo['private'] is True,
                       'wrong private personal media video evidence repository')
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
                   environment['GITHUB_SHA'] == environment['GITHUB_WORKFLOW_SHA'] == trusted, 'wrong native personal media video dispatch')
    reference = evidence.decode(environment['BOX_FORMAL_ADMISSION'])
    run = int(environment['GITHUB_RUN_ID'])
    validate_reference(reference, int(clock()))
    policy.require(trusted == reference['identity']['consumer_sha'] and (run != reference['consumer_run']) == terminal,
                   'wrong protected personal media video run')
    if terminal:
        for field, key in [('BOX_FORMAL_HOSTED_RUN_ID', 'run_id'), ('BOX_FORMAL_HOSTED_RUN_ATTEMPT', 'attempt'),
                           ('BOX_FORMAL_HOSTED_CI_BLOB', 'workflow_blob')]:
            policy.require(environment[field] == str(HOSTED[key]), 'wrong personal media video hosted run pin')
    token = environment['BOX_FORMAL_EVIDENCE_TOKEN']
    policy.require(token and token != environment['GITHUB_TOKEN'], 'dedicated private evidence reader required')
    checked = verify(policy, reference, policy.GitHubReader(environment['GITHUB_TOKEN']), private_fetch(policy, token),
                     run if terminal else None, int(clock()), active=True)
    validate_reference(reference, int(clock()))
    return checked


def verify_public(policy, environment, reader, *, clock):
    event = policy.ci_premerge_event(environment)
    policy.require(environment['GITHUB_EVENT_NAME'] == 'pull_request' and environment['GITHUB_RUN_ID'] == str(HOSTED['run_id'])
                   and event['number'] == PR and event['pull_request']['head']['sha'] == HEAD, 'wrong native personal media video gate')
    check = reader.formal_quality_check(HEAD)
    request = policy.consumer.evidence.decode(check['output']['text'])
    now = int(clock())
    reference = request['artifact']
    validate_reference(reference, now)
    policy.validate_ci_evidence_reference(event, environment, reference['identity'])
    policy.validate_gate(check, request, completed=True)
    proof = historical_baseline(policy, reader)
    terminal = request['terminal_run']
    policy.require(type(terminal) is int and check['id'] not in (C1, PR272_C2) and
                   policy.consumer.canonical(request) == policy.consumer.canonical(result(reference, terminal, proof)),
                   'personal media video result differs from exact scope and subjects')
    done = verify_approvals(policy, reader, reference, terminal, now)
    evidence = policy.consumer.evidence
    evidence.check_times(check, reference['identity'], now)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'personal media video signature predates second approval')
    current_subject(policy, reader, reference['identity'])
    policy.resolve_ci_candidate(environment, reader)
    validate_reference(reference, int(clock()))
    return request
