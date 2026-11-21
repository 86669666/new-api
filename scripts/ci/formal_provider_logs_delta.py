"""Formal evidence reuse for PR #265 provider stream and custom query logs."""
from hashlib import sha256
import io
import json
import re
import urllib.request
import zipfile


PR = 265
HEAD = '5ab93ccc7199dbbced7f67c3d76232ec7e2c32b6'
TREE = '608826742ff4e1520dc840616cce5216a2277f72'
BASE = 'c84debe09f9e2a56953b3afe990bbb60cb7b9d57'
ROUND_TREES = ('adde380d7c0a358f48a227089110e9caaa912f51',
               '347edbf88402e328bb415c6a4ff0beac3947fca2', TREE)
BRANCH = 'codex/issue-2-provider-log-redaction'
CONTROL_REF = 'refs/heads/codex/formal-quality-r14'
REFERENCE_SCHEMA = 'box-formal-provider-logs-delta-ref/v14'
TERMINAL_SCHEMA = 'box-quality-terminal/v14'
SCOPE = 'provider-stream-query-logs'
C1 = 135232975120
PR264_C2 = 136883649803
PR264_PROOF = '350eb6eb011ce73876a102511aa211a29644a08d40618cd1caf86914dbd122c2'
PR264_A, PR264_B = 44915466272, 44915937063
PR264_NATIVE_JOB = 136884536713
R13 = '4e62c16efbecb92d86d2e1d90f794805e89d5aba'
HOSTED = {'attempt': 1, 'run_id': 44921453144, 'workflow_blob': 'c123990e4a8c9fd981b721455a8edbc65b62dfc5'}
BASELINE = {'pull_number': 264, 'candidate_sha': 'c7247a49f573dd633d82def7f0ee03998879d6a1',
            'candidate_tree': 'd6f5c2c19f3bd881a28a60d75f3ba9f615bfbca0', 'merge_commit': BASE,
            'terminal_check_id': PR264_C2, 'native_run': 44906089368,
            'native_attempt': 2, 'native_job': PR264_NATIVE_JOB}
MANIFEST = '40d2e1658692c2b184e6d046e7a8d253b5276f57ff048c9e73f314a44425ea86'
ARCHIVE = {'bytes': 22047,
 'commit': '5d0636dcdfcbac02d917c21d6ccf8b29973db16a',
 'path': 'formal-audit/pr265-5ab93ccc-formal-inputs.zip',
 'sha256': 'ee8d51b7487eac6012e5e7d05d9903d8470b42bfc59df7d977ce0f6ada77726e'}
BLOBS = {'controller/channel_upstream_update.go': 'e4662a93b0d7152ba96b7384bac349ec132e9b5e',
 'controller/channel_upstream_update_test.go': 'd839988287d3f8c33b07bea5c591dfeedf61c99f',
 'relay/channel/advancedcustom/adaptor.go': '6c43c78ed2d3beb8add08dcf74e94109be4a5c41',
 'relay/channel/advancedcustom/adaptor_test.go': '3af5ee729df46ca75ce36ff1009fce6738116e9d',
 'relay/channel/api_request.go': '8f69b4e2694378b823c2d6dedd085678f05d5395',
 'relay/channel/ollama/stream.go': '5e1e3ba4d5cd105600b8756b3acd9f56125806bb',
 'relay/channel/ollama/stream_test.go': '988fb729697635a2da1f77e486879c3d8d2d2371',
 'relay/channel/openai/chat_via_responses.go': '659f7acb78cadfcb0dc150ac745bf0d844ceed3d',
 'relay/channel/openai/chat_via_responses_test.go': '41d6c79b23f529694a33c5723ab038004850de1c',
 'relay/channel/openai/helper.go': '060c09a5ca19f4b4f764f955cf43e8cc9281966e',
 'relay/channel/openai/image_stream_test.go': '22f16101a7e6789720d5cac68f649716c18552f4',
 'relay/channel/openai/relay-openai.go': 'aee3fb0d162d1c0b178b7b129039fc27094bcfb4',
 'relay/channel/openai/relay_responses.go': '6459a981d5597241ace6e91020aa046657930da0',
 'relay/channel/openai/responses_via_chat.go': '334c39eaae45da4fa6853e181409a0753836482e',
 'relay/common/relay_utils.go': '4dedf35c80fa7753c85809e02ceb2bfb43ae6aa7',
 'relay/common/stream_status.go': 'dae05b5ffced7a4ff8bc9fdd9a618e944edc857c',
 'relay/helper/stream_result.go': '669aee6dafbb4612edc379cf9cc5bfa73b9c4022',
 'relay/helper/stream_scanner.go': '8f285d80d01b1f058df1959593730d96413f143b',
 'relay/helper/stream_scanner_test.go': '7aeea0b423df7751cd2e4ffa2739ff2f4514c43f',
 'service/error.go': '6a362f4e116396a5aa727d3f0d9fd4084abd25b9',
 'service/error_test.go': '905239ec7d57c6b2dd1ae1e833cadbbec97b56a8',
 'service/log_info_generate.go': '55b89eb794ae4bb19e3044f595ac35378201166b'}
MEMBERS = {'candidate.patch': '1e2e09d61b31c55386d1ce63677aa6b944a087c5bbd9abf7a01924fd1bfa3651',
 'targeted-review-retry.json': '4130a9f578187f457a3232e31579299a57c770fa07b17bc03b894485e5c2371e',
 'targeted-review-retry.jsonl': '17b00694713d9179e82b302c9d86720b9e53962c2b6dfae3eae56dee80442b48',
 'targeted-review.json': 'c0e2bac262386372dd7961153e66898683dde5f860a03d5cded09aba5a7fc073',
 'targeted-review.jsonl': 'e7b55c3e963c70e7342217227ade4a3efc98bce07f47a9ba92532016626f55aa',
 'targeted.json': 'e05de5be51bb5f92ff8cf4c1ebf59400aaf883c05064ab9fa1daac84cb6740d4',
 'targeted.jsonl': 'fdcfc0ae1430a31adac6521fc3e10bdc5c593c3b928161e89611ee240a5ce23b',
 'validation.json': 'b4a97766ade208d343c662efe84f2f19e174f1c362698bf8803075af1f87ebe3',
 'verification.json': 'cb5cb88c6aaed6e145d7480a316059b8794b4a6f8c4d0783f7f38db5ca23bed6'}
FILES = tuple(BLOBS)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=True).encode('ascii')


def descriptor():
    return ARCHIVE.copy()


def consumer_intent(artifact, control, nonce):
    if (canonical(artifact) != canonical(ARCHIVE) or not re.fullmatch('[a-f0-9]{40}', control) or
            control == R13 or not re.fullmatch('[a-f0-9]{32}', nonce)):
        raise ValueError('invalid provider log delta selection')
    bound = {'artifact': artifact, 'baseline': BASELINE, 'tree': TREE, 'head': HEAD,
             'hosted': HOSTED, 'control': control, 'nonce': nonce}
    return sha256(canonical(bound)).hexdigest()


def make_reference(artifact, control, consumer_run, opened, nonce):
    consumer_intent(artifact, control, nonce)
    if type(consumer_run) is not int or consumer_run <= 0 or type(opened) is not int or opened <= 0:
        raise ValueError('invalid provider log delta approval times')
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
        raise ValueError('invalid or expired provider log delta reference')


def validate_package(policy, raw):
    require = policy.require
    decode = policy.consumer.evidence.decode
    require(type(raw) is bytes and len(raw) == ARCHIVE['bytes'] and sha256(raw).hexdigest() == ARCHIVE['sha256'],
            'wrong immutable provider log evidence')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(sorted(archive.namelist()) == sorted((*MEMBERS, 'manifest.json')), 'incorrect provider log artifact inventory')
        manifest = archive.read('manifest.json')
        require(sha256(manifest).hexdigest() == MANIFEST and
                {name: sha256(archive.read(name)).hexdigest() for name in MEMBERS} == MEMBERS,
                'unreviewed provider log evidence member')
        result = decode(archive.read('validation.json'))
    data = decode(manifest)
    require((data['kind'], data['pull'], data['head'], data['tree'], data['base'], data['paths']) ==
            ('pr265-provider-stream-query-logs/v1', PR, HEAD, TREE, BASE, list(FILES)) and
            data['hosted'] == HOSTED and data['blobs'] == BLOBS and
            data['baseline_terminal'] == PR264_C2 and data['members'] == MEMBERS, 'wrong provider log evidence subjects')
    require((result['candidate'], result['tree'], result['round_trees'], result['review'], result['runner']) ==
            (HEAD, TREE, list(ROUND_TREES), 'ACCEPT_SCOPED', 'go1.26.10 linux/amd64'),
            'wrong reviewed validation subjects')
    rounds = result['round_leaves']
    leaf = ['github.com/QuantumNous/new-api/relay/channel/openai',
            'TestOpenAIResponsesStreamErrorsKeepProviderDiagnosticsOutOfLogs/chat-backed_provider_failure']
    require([len(items) for items in rounds] == [26, 11, 1] and
            len({tuple(row) for items in rounds for row in items}) == 38 and rounds[2] == [leaf],
            'incomplete provider log regression evidence')
    require(result['excluded'] == {
                'test': leaf[1],
                'status': 'intermediate_fixture_incorrect_status_corrected_and_retested_on_final_tree'},
            'intermediate fixture failure is not credited')


def current_subject(policy, reader, identity):
    base = reader.repository()
    pr = reader.pull(PR)
    repo_id = identity['repository_id']
    policy.require(base['id'] == repo_id and base['full_name'] == policy.REPOSITORY and
                   pr['number'] == PR and pr['state'] == 'open' and pr['merged'] is False and pr['draft'] is False and pr['changed_files'] == len(FILES) and
                   pr['head']['repo']['id'] == pr['base']['repo']['id'] == repo_id and
                   pr['head']['repo']['full_name'] == pr['base']['repo']['full_name'] == policy.REPOSITORY and
                   pr['head']['sha'] == HEAD and pr['head']['ref'] == BRANCH and
                   pr['base']['sha'] == BASE and pr['base']['ref'] == 'main', 'current provider log PR subject changed')
    commit = reader.commit(HEAD)
    policy.require(commit['sha'] == HEAD and commit['tree']['sha'] == TREE and
                   [row['sha'] for row in commit['parents']] == [BASE], 'wrong provider log candidate tree or parents')
    policy.verify_hosted_jobs(reader, HOSTED, identity)


def historical_baseline(policy, reader, fetch=None):
    previous = policy.upstream_errors_delta
    evidence = policy.consumer.evidence
    older = previous.historical_baseline(policy, reader, fetch)
    check = reader.check(PR264_C2)
    proof = evidence.decode(check['output']['text'])
    policy.require(check['id'] == PR264_C2 and policy.consumer.digest(proof) == PR264_PROOF and
                   (proof['candidate_sha'], proof['candidate_tree'], proof['consumer_run'], proof['terminal_run']) ==
                   (BASELINE['candidate_sha'], BASELINE['candidate_tree'], PR264_A, PR264_B),
                   'wrong signed PR264 baseline')
    signed = evidence.github_time(check, 'completed_at')
    policy.validate_gate(check, proof, completed=True)
    ref = proof['artifact']
    previous.validate_reference(ref, signed)
    policy.require(ref['identity']['consumer_sha'] == R13 and
                   policy.consumer.canonical(proof) == policy.consumer.canonical(previous.result(ref, PR264_B, older)),
                   'signed PR264 evidence differs from reviewed contract')
    done = previous.verify_approvals(policy, reader, ref, PR264_B, signed)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'PR264 signature predates its reviews')
    prior_run = reader.run(previous.HOSTED['run_id'], previous.HOSTED['attempt'])
    repo_id = ref['identity']['repository_id']
    policy.require(prior_run['id'] == previous.HOSTED['run_id'] and
                   prior_run['run_attempt'] == previous.HOSTED['attempt'] and
                   prior_run['workflow_id'] == policy.CI_WORKFLOW_ID and prior_run['path'] == '.github/workflows/ci.yml' and
                   prior_run['event'] == 'pull_request' and prior_run['head_sha'] == previous.HEAD and
                   prior_run['repository']['id'] == prior_run['head_repository']['id'] == repo_id and
                   reader.hosted_workflow_blob(previous.HEAD) == previous.HOSTED['workflow_blob'],
                   'historical PR264 hosted run or workflow blob changed')
    policy.verify_hosted_job_steps(reader, previous.HOSTED, previous.HEAD)
    if fetch is not None:
        previous.validate_package(policy, fetch(ref['artifact']['commit']))
    pr = reader.pull(264)
    merged = reader.commit(BASE)
    policy.require(pr['number'] == 264 and pr['state'] == 'closed' and pr['merged'] is True and
                   pr['merge_commit_sha'] == BASE and pr['head']['sha'] == BASELINE['candidate_sha'] and
                   pr['base']['ref'] == 'main' and pr['base']['repo']['id'] == repo_id and
                   merged['sha'] == BASE and merged['tree']['sha'] == BASELINE['candidate_tree'] and
                   [row['sha'] for row in merged['parents']] == [previous.BASE, previous.HEAD], 'wrong historical PR264 merge')
    run = reader.run(BASELINE['native_run'], 2)
    policy.require(run['id'] == BASELINE['native_run'] and run['run_attempt'] == 2 and
                   run['head_sha'] == BASELINE['candidate_sha'] and
                   run['repository']['id'] == run['head_repository']['id'] == repo_id and
                   run['path'] == '.github/workflows/ci.yml' and run['event'] == 'pull_request' and
                   run['workflow_id'] == policy.CI_WORKFLOW_ID and
                   run['status'] == 'completed' and run['conclusion'] == 'success', 'historical PR264 native gate did not pass')
    gate = policy.successful_job(reader.jobs(BASELINE['native_run'], 2), policy.GATE, BASELINE['candidate_sha'],
                                 ('Verify hosted jobs and authenticated exact-candidate quality',))
    policy.require(gate['id'] == PR264_NATIVE_JOB and gate['run_id'] == BASELINE['native_run'] and gate['run_attempt'] == 2 and
                   signed <= evidence.github_time(gate, 'started_at') <= evidence.github_time(gate, 'completed_at') <=
                   evidence.github_time(pr, 'merged_at') <= ref['identity']['release_expires_at'],
                   'PR264 native green and merge outside historical publication')
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
        policy.require(type(terminal_run) is int and terminal_run != consumer_run, 'separate provider log terminal required')
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
            'release_expires_at': identity['release_expires_at'], 'admission_id': 'pr265-provider-logs-delta-' + HEAD,
            'invocation': consumer_intent(reference['artifact'], identity['consumer_sha'], reference['nonce'])}


def verify(policy, reference, reader, fetch, terminal_run, now, *, active=False, staged_at=None):
    validate_reference(reference, now)
    policy.require(callable(fetch) and (active or terminal_run is not None), 'both reviewed provider log jobs required')
    done = verify_approvals(policy, reader, reference, terminal_run, now, active=active)
    if staged_at is not None:
        policy.require(done is not None and done <= staged_at <= now, 'provider log result staged before terminal completion')
    proof = historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    current_subject(policy, reader, reference['identity'])
    request = result(reference, terminal_run, proof)
    if terminal_run is None:
        request['schema'] = 'box-quality-provider-logs-consumer/v14'
    return request


def prescreen(policy, artifact, reader, fetch):
    policy.require(canonical(artifact) == canonical(ARCHIVE) and callable(fetch), 'wrong provider log preflight artifact')
    current_subject(policy, reader, {'repository_id': 1423238398, 'head_repository_id': 1423238398, 'pull_number': PR,
                                    'base_sha': BASE, 'candidate_sha': HEAD})
    historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    return {'candidate_sha': HEAD, 'candidate_tree': TREE, 'baseline': BASELINE, 'hosted': HOSTED, 'artifact': artifact}


def private_fetch(policy, token):
    old_fetch = policy.upstream_errors_delta.private_fetch(policy, token)
    evidence = policy.consumer.evidence

    def fetch(commit):
        if commit != ARCHIVE['commit']:
            return old_fetch(commit)
        path = '/repos/' + evidence.EVIDENCE_REPOSITORY
        repo = policy.consumer.api(path, token)
        policy.require(repo['id'] == evidence.EVIDENCE_REPOSITORY_ID and
                       repo['full_name'] == evidence.EVIDENCE_REPOSITORY and repo['private'] is True,
                       'wrong private provider log evidence repository')
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
                   environment['GITHUB_SHA'] == environment['GITHUB_WORKFLOW_SHA'] == trusted, 'wrong native provider log dispatch')
    reference = evidence.decode(environment['BOX_FORMAL_ADMISSION'])
    run = int(environment['GITHUB_RUN_ID'])
    validate_reference(reference, int(clock()))
    policy.require(trusted == reference['identity']['consumer_sha'] and (run != reference['consumer_run']) == terminal,
                   'wrong protected provider log run')
    if terminal:
        for field, key in [('BOX_FORMAL_HOSTED_RUN_ID', 'run_id'), ('BOX_FORMAL_HOSTED_RUN_ATTEMPT', 'attempt'),
                           ('BOX_FORMAL_HOSTED_CI_BLOB', 'workflow_blob')]:
            policy.require(environment[field] == str(HOSTED[key]), 'wrong provider log hosted run pin')
    token = environment['BOX_FORMAL_EVIDENCE_TOKEN']
    policy.require(token and token != environment['GITHUB_TOKEN'], 'dedicated private evidence reader required')
    checked = verify(policy, reference, policy.GitHubReader(environment['GITHUB_TOKEN']), private_fetch(policy, token),
                     run if terminal else None, int(clock()), active=True)
    validate_reference(reference, int(clock()))
    return checked


def verify_public(policy, environment, reader, *, clock):
    event = policy.ci_premerge_event(environment)
    policy.require(environment['GITHUB_EVENT_NAME'] == 'pull_request' and environment['GITHUB_RUN_ID'] == str(HOSTED['run_id'])
                   and event['number'] == PR and event['pull_request']['head']['sha'] == HEAD, 'wrong native provider log gate')
    check = reader.formal_quality_check(HEAD)
    request = policy.consumer.evidence.decode(check['output']['text'])
    now = int(clock())
    reference = request['artifact']
    validate_reference(reference, now)
    policy.validate_ci_evidence_reference(event, environment, reference['identity'])
    policy.validate_gate(check, request, completed=True)
    proof = historical_baseline(policy, reader)
    terminal = request['terminal_run']
    policy.require(type(terminal) is int and check['id'] not in (C1, PR264_C2) and
                   policy.consumer.canonical(request) == policy.consumer.canonical(result(reference, terminal, proof)),
                   'provider log result differs from exact scope and subjects')
    done = verify_approvals(policy, reader, reference, terminal, now)
    evidence = policy.consumer.evidence
    evidence.check_times(check, reference['identity'], now)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'provider log signature predates second approval')
    current_subject(policy, reader, reference['identity'])
    policy.resolve_ci_candidate(environment, reader)
    validate_reference(reference, int(clock()))
    return request
