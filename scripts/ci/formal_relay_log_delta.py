"""Formal evidence reuse for PR #263 HTTP relay log redaction."""
from hashlib import sha256
import io
import json
import re
import urllib.request
import zipfile


PR = 263
HEAD = 'befcf8944d184b21e5d471ce0114ab6e01c8882a'
TREE = '55369369360d89cf80df362c88f75e967e99f02c'
BASE = '2267c5e373bf620b853f9fd3d0e29c735dcd4616'
REUSED_TREE = '75a396a3992fd8404712bf790428fbae45bd9473'
BRANCH = 'codex/issue-2-relay-url-log-redaction'
CONTROL_REF = 'refs/heads/codex/formal-quality-r12'
REFERENCE_SCHEMA = 'box-formal-relay-log-delta-ref/v12'
TERMINAL_SCHEMA = 'box-quality-terminal/v12'
SCOPE = 'http-relay-log-redaction'
C1 = 135232975120
PR260_C2 = 136295851759
PR260_PROOF = 'd2289d320818594574752a59a7daaf2cbb2dfd506fc4a3569c3b99c07e7a0ddc'
PR260_A, PR260_B = 44736643372, 44737474414
PR260_NATIVE_JOB = 136297107442
R11 = '29f3bea0df85d324fa5c47d87999a0744ececb32'
HOSTED = {'run_id': 44818102346, 'attempt': 1,
          'workflow_blob': 'c123990e4a8c9fd981b721455a8edbc65b62dfc5'}
BASELINE = {'pull_number': 260, 'candidate_sha': 'f913e9b2a40e246571e50b7ab13109806303ab80',
            'candidate_tree': '08fc1d1911077597ae4ead158f8267985f11a34f', 'merge_commit': BASE,
            'terminal_check_id': PR260_C2, 'native_run': 44729397309,
            'native_attempt': 2, 'native_job': PR260_NATIVE_JOB}
MANIFEST = '479d8af395d749a326e93a96fb01e62fbc6d8acb9dc3076557ad36b5ea553ce9'
ARCHIVE = {'bytes': 9477,
 'commit': '9558558c21565b428974ddb154e2dc43ab1bc0df',
 'path': 'formal-audit/pr263-befcf894-formal-inputs-r2.zip',
 'sha256': '021b1ea1cba31c2861f46d1e63f2a60fe061541d9ddca1172a2f03491a82bfca'}
BLOBS = {'relay/channel/api_request.go': '81ed0f02f10dbdbc250babc20b7f9252e5a1568a',
 'relay/channel/api_request_test.go': 'ed2f1e1a02ec72369acd726b0eb10f0001673cbe',
 'relay/common/relay_utils.go': '1ff02f7e1d5b262d5597255d569cabf42afa6984',
 'relay/common/relay_utils_test.go': '332773ec48bbbb80cd2be395f8b19d73f2ade741'}
MEMBERS = {'candidate-r2.patch': '888b65e349efd096e4c7f907ae490b8caf5d737b4a4568c19c42875a4fdfd1d3',
 'candidate-r2.txt': '5b6c862553985836b272b7c613525c8fe167f045364cfa8625da9bb43b298d3f',
 'candidate.txt': '3c009534e76f5f3c5ecabc1c1323c2dd980f20a17a4495985ad64266998937c8',
 'targeted-r2.jsonl': '2484011b0fc36c7d33fb67217448bcfdcde324430c61aec5585f08229477a949',
 'targeted.jsonl': '7fd94bd251876a4bec32d40889143f359e8b78fe8be3d2cb0d06f8b90b4d3221',
 'validation.json': '194c4ef15824c4e9c73d288af13169684dbb172457610c11bda261a905d02296'}
FILES = tuple(BLOBS)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=True).encode('ascii')


def descriptor():
    return ARCHIVE.copy()


def consumer_intent(artifact, control, nonce):
    if (canonical(artifact) != canonical(ARCHIVE) or not re.fullmatch('[a-f0-9]{40}', control) or
            control == R11 or not re.fullmatch('[a-f0-9]{32}', nonce)):
        raise ValueError('invalid relay log delta selection')
    bound = {'artifact': artifact, 'baseline': BASELINE, 'tree': TREE, 'head': HEAD,
             'hosted': HOSTED, 'control': control, 'nonce': nonce}
    return sha256(canonical(bound)).hexdigest()


def make_reference(artifact, control, consumer_run, opened, nonce):
    consumer_intent(artifact, control, nonce)
    if type(consumer_run) is not int or consumer_run <= 0 or type(opened) is not int or opened <= 0:
        raise ValueError('invalid relay log delta approval times')
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
        raise ValueError('invalid or expired relay log delta reference')


def validate_package(policy, raw):
    require = policy.require
    decode = policy.consumer.evidence.decode
    require(type(raw) is bytes and len(raw) == ARCHIVE['bytes'] and sha256(raw).hexdigest() == ARCHIVE['sha256'],
            'wrong immutable relay log evidence')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(sorted(archive.namelist()) == sorted((*MEMBERS, 'manifest.json')), 'incorrect relay log artifact inventory')
        manifest = archive.read('manifest.json')
        require(sha256(manifest).hexdigest() == MANIFEST and
                {name: sha256(archive.read(name)).hexdigest() for name in MEMBERS} == MEMBERS,
                'unreviewed relay log evidence member')
        result = decode(archive.read('validation.json'))
    data = decode(manifest)
    require((data['kind'], data['pull'], data['head'], data['tree'], data['base'], data['paths']) ==
            ('pr263-http-relay-log-redaction/v1', PR, HEAD, TREE, BASE, list(FILES)) and
            data['hosted'] == HOSTED and data['blobs'] == BLOBS and
            data['baseline_terminal'] == PR260_C2 and data['members'] == MEMBERS, 'wrong relay log evidence subjects')
    require((result['candidate'], result['tree'], result['reused_tree'], result['review'], result['runner']) ==
            (HEAD, TREE, REUSED_TREE, 'ACCEPT_SCOPED', 'go1.26.10 linux/amd64') and
            result['isolated_test_dirs'] == 'clean' and result['reused_paths_unchanged'] is True,
            'relay log validation or cleanup missing')
    expected = ['TestDoRequestTransportErrorLogRedaction/' + case
                for case in ('DNS', 'canceled', 'structured_error', 'timeout')]
    reused = {tuple(row) for row in result['reused']}
    require(result['direct'] == expected and len(reused) == len(result['reused']) == 35 and
            {package for package, _ in reused} == {
                'github.com/QuantumNous/new-api/middleware', 'github.com/QuantumNous/new-api/relay/common'},
            'incomplete relay log regression evidence')


def current_subject(policy, reader, identity):
    base = reader.repository()
    pr = reader.pull(PR)
    repo_id = identity['repository_id']
    policy.require(base['id'] == repo_id and base['full_name'] == policy.REPOSITORY and
                   pr['number'] == PR and pr['state'] == 'open' and pr['merged'] is False and pr['draft'] is False and pr['changed_files'] == len(FILES) and
                   pr['head']['repo']['id'] == pr['base']['repo']['id'] == repo_id and
                   pr['head']['repo']['full_name'] == pr['base']['repo']['full_name'] == policy.REPOSITORY and
                   pr['head']['sha'] == HEAD and pr['head']['ref'] == BRANCH and
                   pr['base']['sha'] == BASE and pr['base']['ref'] == 'main', 'current relay log PR subject changed')
    commit = reader.commit(HEAD)
    policy.require(commit['sha'] == HEAD and commit['tree']['sha'] == TREE and
                   [row['sha'] for row in commit['parents']] == [BASE], 'wrong relay log candidate tree or parents')
    policy.verify_hosted_jobs(reader, HOSTED, identity)


def historical_baseline(policy, reader, fetch=None):
    previous = policy.client_events_delta
    evidence = policy.consumer.evidence
    older = previous.historical_baseline(policy, reader, fetch)
    check = reader.check(PR260_C2)
    proof = evidence.decode(check['output']['text'])
    policy.require(check['id'] == PR260_C2 and policy.consumer.digest(proof) == PR260_PROOF and
                   (proof['candidate_sha'], proof['candidate_tree'], proof['consumer_run'], proof['terminal_run']) ==
                   (BASELINE['candidate_sha'], BASELINE['candidate_tree'], PR260_A, PR260_B),
                   'wrong signed PR260 baseline')
    signed = evidence.github_time(check, 'completed_at')
    policy.validate_gate(check, proof, completed=True)
    ref = proof['artifact']
    previous.validate_reference(ref, signed)
    policy.require(ref['identity']['consumer_sha'] == R11 and
                   policy.consumer.canonical(proof) == policy.consumer.canonical(previous.result(ref, PR260_B, older)),
                   'signed PR260 evidence differs from reviewed contract')
    done = previous.verify_approvals(policy, reader, ref, PR260_B, signed)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'PR260 signature predates its reviews')
    prior_run = reader.run(previous.HOSTED['run_id'], previous.HOSTED['attempt'])
    repo_id = ref['identity']['repository_id']
    policy.require(prior_run['id'] == previous.HOSTED['run_id'] and
                   prior_run['run_attempt'] == previous.HOSTED['attempt'] and
                   prior_run['workflow_id'] == policy.CI_WORKFLOW_ID and prior_run['path'] == '.github/workflows/ci.yml' and
                   prior_run['event'] == 'pull_request' and prior_run['head_sha'] == previous.HEAD and
                   prior_run['repository']['id'] == prior_run['head_repository']['id'] == repo_id and
                   reader.hosted_workflow_blob(previous.HEAD) == previous.HOSTED['workflow_blob'],
                   'historical PR260 hosted run or workflow blob changed')
    policy.verify_hosted_job_steps(reader, previous.HOSTED, previous.HEAD)
    if fetch is not None:
        previous.validate_package(policy, fetch(ref['artifact']['commit']))
    pr = reader.pull(260)
    merged = reader.commit(BASE)
    policy.require(pr['number'] == 260 and pr['state'] == 'closed' and pr['merged'] is True and
                   pr['merge_commit_sha'] == BASE and pr['head']['sha'] == BASELINE['candidate_sha'] and
                   pr['base']['ref'] == 'main' and pr['base']['repo']['id'] == repo_id and
                   merged['sha'] == BASE and merged['tree']['sha'] == BASELINE['candidate_tree'] and
                   [row['sha'] for row in merged['parents']] == [previous.BASE, previous.HEAD], 'wrong historical PR260 merge')
    run = reader.run(BASELINE['native_run'], 2)
    policy.require(run['id'] == BASELINE['native_run'] and run['run_attempt'] == 2 and
                   run['head_sha'] == BASELINE['candidate_sha'] and
                   run['repository']['id'] == run['head_repository']['id'] == repo_id and
                   run['path'] == '.github/workflows/ci.yml' and run['event'] == 'pull_request' and
                   run['workflow_id'] == policy.CI_WORKFLOW_ID and
                   run['status'] == 'completed' and run['conclusion'] == 'success', 'historical PR260 native gate did not pass')
    gate = policy.successful_job(reader.jobs(BASELINE['native_run'], 2), policy.GATE, BASELINE['candidate_sha'],
                                 ('Verify hosted jobs and authenticated exact-candidate quality',))
    policy.require(gate['id'] == PR260_NATIVE_JOB and gate['run_id'] == BASELINE['native_run'] and gate['run_attempt'] == 2 and
                   signed <= evidence.github_time(gate, 'started_at') <= evidence.github_time(gate, 'completed_at') <=
                   evidence.github_time(pr, 'merged_at') <= ref['identity']['release_expires_at'],
                   'PR260 native green and merge outside historical publication')
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
        policy.require(type(terminal_run) is int and terminal_run != consumer_run, 'separate relay log terminal required')
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
            'release_expires_at': identity['release_expires_at'], 'admission_id': 'pr263-relay-log-delta-' + HEAD,
            'invocation': consumer_intent(reference['artifact'], identity['consumer_sha'], reference['nonce'])}


def verify(policy, reference, reader, fetch, terminal_run, now, *, active=False, staged_at=None):
    validate_reference(reference, now)
    policy.require(callable(fetch) and (active or terminal_run is not None), 'both reviewed relay log jobs required')
    done = verify_approvals(policy, reader, reference, terminal_run, now, active=active)
    if staged_at is not None:
        policy.require(done is not None and done <= staged_at <= now, 'relay log result staged before terminal completion')
    proof = historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    current_subject(policy, reader, reference['identity'])
    request = result(reference, terminal_run, proof)
    if terminal_run is None:
        request['schema'] = 'box-quality-relay-log-consumer/v12'
    return request


def prescreen(policy, artifact, reader, fetch):
    policy.require(canonical(artifact) == canonical(ARCHIVE) and callable(fetch), 'wrong relay log preflight artifact')
    current_subject(policy, reader, {'repository_id': 1423238398, 'head_repository_id': 1423238398, 'pull_number': PR,
                                    'base_sha': BASE, 'candidate_sha': HEAD})
    historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    return {'candidate_sha': HEAD, 'candidate_tree': TREE, 'baseline': BASELINE, 'hosted': HOSTED, 'artifact': artifact}


def private_fetch(policy, token):
    old_fetch = policy.client_events_delta.private_fetch(policy, token)
    evidence = policy.consumer.evidence

    def fetch(commit):
        if commit != ARCHIVE['commit']:
            return old_fetch(commit)
        path = '/repos/' + evidence.EVIDENCE_REPOSITORY
        repo = policy.consumer.api(path, token)
        policy.require(repo['id'] == evidence.EVIDENCE_REPOSITORY_ID and
                       repo['full_name'] == evidence.EVIDENCE_REPOSITORY and repo['private'] is True,
                       'wrong private relay log evidence repository')
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
                   environment['GITHUB_SHA'] == environment['GITHUB_WORKFLOW_SHA'] == trusted, 'wrong native relay log dispatch')
    reference = evidence.decode(environment['BOX_FORMAL_ADMISSION'])
    run = int(environment['GITHUB_RUN_ID'])
    validate_reference(reference, int(clock()))
    policy.require(trusted == reference['identity']['consumer_sha'] and (run != reference['consumer_run']) == terminal,
                   'wrong protected relay log run')
    if terminal:
        for field, key in [('BOX_FORMAL_HOSTED_RUN_ID', 'run_id'), ('BOX_FORMAL_HOSTED_RUN_ATTEMPT', 'attempt'),
                           ('BOX_FORMAL_HOSTED_CI_BLOB', 'workflow_blob')]:
            policy.require(environment[field] == str(HOSTED[key]), 'wrong relay log hosted run pin')
    token = environment['BOX_FORMAL_EVIDENCE_TOKEN']
    policy.require(token and token != environment['GITHUB_TOKEN'], 'dedicated private evidence reader required')
    checked = verify(policy, reference, policy.GitHubReader(environment['GITHUB_TOKEN']), private_fetch(policy, token),
                     run if terminal else None, int(clock()), active=True)
    validate_reference(reference, int(clock()))
    return checked


def verify_public(policy, environment, reader, *, clock):
    event = policy.ci_premerge_event(environment)
    policy.require(environment['GITHUB_EVENT_NAME'] == 'pull_request' and environment['GITHUB_RUN_ID'] == str(HOSTED['run_id'])
                   and event['number'] == PR and event['pull_request']['head']['sha'] == HEAD, 'wrong native relay log gate')
    check = reader.formal_quality_check(HEAD)
    request = policy.consumer.evidence.decode(check['output']['text'])
    now = int(clock())
    reference = request['artifact']
    validate_reference(reference, now)
    policy.validate_ci_evidence_reference(event, environment, reference['identity'])
    policy.validate_gate(check, request, completed=True)
    proof = historical_baseline(policy, reader)
    terminal = request['terminal_run']
    policy.require(type(terminal) is int and check['id'] not in (C1, PR260_C2) and
                   policy.consumer.canonical(request) == policy.consumer.canonical(result(reference, terminal, proof)),
                   'relay log result differs from exact scope and subjects')
    done = verify_approvals(policy, reader, reference, terminal, now)
    evidence = policy.consumer.evidence
    evidence.check_times(check, reference['identity'], now)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'relay log signature predates second approval')
    current_subject(policy, reader, reference['identity'])
    policy.resolve_ci_candidate(environment, reader)
    validate_reference(reference, int(clock()))
    return request
