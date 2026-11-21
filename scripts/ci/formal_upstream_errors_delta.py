"""Formal evidence reuse for PR #264 shared upstream error logs."""
from hashlib import sha256
import io
import json
import re
import urllib.request
import zipfile


PR = 264
HEAD = 'c7247a49f573dd633d82def7f0ee03998879d6a1'
TREE = 'd6f5c2c19f3bd881a28a60d75f3ba9f615bfbca0'
BASE = 'eec73819fe9fe5270b1cd7923973caea18623019'
ROUND_TREES = ('7b9d4fe680efa69ce01dc2a3c5d17130376f8f52',
               '203db91a48ce624bc7178b7b86a10b155cfd2c32', TREE)
BRANCH = 'codex/issue-2-relay-log-followup'
CONTROL_REF = 'refs/heads/codex/formal-quality-r13'
REFERENCE_SCHEMA = 'box-formal-upstream-errors-delta-ref/v13'
TERMINAL_SCHEMA = 'box-quality-terminal/v13'
SCOPE = 'shared-upstream-error-logs'
C1 = 135232975120
PR263_C2 = 136593039685
PR263_PROOF = '007796703d4e0a6162f3b76bfd11d047acaa2791b64e7aa89c591dc888e85eaa'
PR263_A, PR263_B = 44822367398, 44823222025
PR263_NATIVE_JOB = 136594514874
R12 = 'c2bdbf6e28ca64aa8b625fee2dcb9b2e39e0c6c2'
HOSTED = {'attempt': 1, 'run_id': 44906089368, 'workflow_blob': 'c123990e4a8c9fd981b721455a8edbc65b62dfc5'}
BASELINE = {'pull_number': 263, 'candidate_sha': 'befcf8944d184b21e5d471ce0114ab6e01c8882a',
            'candidate_tree': '55369369360d89cf80df362c88f75e967e99f02c', 'merge_commit': BASE,
            'terminal_check_id': PR263_C2, 'native_run': 44818102346,
            'native_attempt': 2, 'native_job': PR263_NATIVE_JOB}
MANIFEST = '5de0a61dce0a2a8c03b736608892a2c3c5bb4f30d1daa4c39fa6319b08117a7b'
ARCHIVE = {'bytes': 22521,
 'commit': '88c8727870e7c7c920250ebb9253e0d64c630aed',
 'path': 'formal-audit/pr264-c7247a49-formal-inputs.zip',
 'sha256': '8fb70146c301fe93a4fc349f1892a80ffbff72c9971445fca550b6afa3906e01'}
BLOBS = {'controller/channel-test.go': '0d8bb8c1b5cd3263b08a7a8be962a683fa7520fe',
 'controller/relay.go': '52fb103b0a2432030c1b4539559fe2af0e1443f5',
 'relay/channel/advancedcustom/adaptor_test.go': 'c7b2771335e7732d53927de815c7aea9d0285bdc',
 'relay/channel/api_request.go': 'f03fb0be7da7c7e997e4ffd5f4f2a524fcb01f07',
 'relay/channel/api_request_test.go': '1ba83adf871d88c9ba4d992ac30ff3ef486a3327',
 'service/error.go': '012e27a2b06e9fe8a9785d2707424d8f9dff93fb',
 'service/error_test.go': '3a2e56124b9691f19890da3efcab09372417fda7',
 'service/relay_error.go': 'ce748f26692c5a23d624c4c9fb1c0b7997963642',
 'service/request_policy.go': 'ecf9f054941f64fab007b71d7cf32f22f508f5af',
 'service/violation_fee.go': 'ac67019ea1bec5fe04665f446d68fcaed165b657'}
MEMBERS = {'baseline-ws-fixture.jsonl': 'd433dcbbfba6e6420fb834366cda8d335f886da047491e5ed02bddaea13fa228',
 'candidate-r2.json': 'd78da442ad8deb6119e61010894b57c6f1f439b00b1d2f8926f320753dd93f06',
 'candidate-r3.json': '8762d2f87eff097b0227f1c27eaafd1c53a4d05d0bd112bdc4300539735431c9',
 'candidate-r3.patch': 'aa26deb8fa03d2d47110bb54607a01c9ee769c660ddf56a123a8b2b520cd1cb1',
 'candidate.json': '14a39b498a1c13bf29b40b5b1979992450a2247f5d68da96d87f20da2402f532',
 'targeted-r2.jsonl': 'c65ea1a80e4ab2e10bbe14a44363a8458b29ea7f17bd8f404d033669b8e101dd',
 'targeted-r3.jsonl': '7184569aa8da130dbc450dd815cffa15fa77bb6a87b30a149659ad4bd9dfe898',
 'targeted.jsonl': '0bede266fc4ecad3f3ccc56d7268a961887e17f7b26776bceb51a47c5dc1dbbd',
 'validation.json': 'a1c3e754a32e40b3ea59262d385e65aa2812101e940fe92a682225f269d0e373'}
FILES = tuple(BLOBS)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=True).encode('ascii')


def descriptor():
    return ARCHIVE.copy()


def consumer_intent(artifact, control, nonce):
    if (canonical(artifact) != canonical(ARCHIVE) or not re.fullmatch('[a-f0-9]{40}', control) or
            control == R12 or not re.fullmatch('[a-f0-9]{32}', nonce)):
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
            ('pr264-shared-upstream-error-logs/v1', PR, HEAD, TREE, BASE, list(FILES)) and
            data['hosted'] == HOSTED and data['blobs'] == BLOBS and
            data['baseline_terminal'] == PR263_C2 and data['members'] == MEMBERS, 'wrong relay log evidence subjects')
    require((result['candidate'], result['tree'], result['round_trees'], result['review'], result['runner']) ==
            (HEAD, TREE, list(ROUND_TREES), 'ACCEPT_SCOPED', 'go1.26.10 linux/amd64'),
            'wrong reviewed validation subjects')
    rounds = result['round_leaves']
    require([len(items) for items in rounds] == [13, 9, 2] and
            len({tuple(row) for items in rounds for row in items}) == 24 and
            rounds[2] == [['github.com/QuantumNous/new-api/service', 'TestCalcViolationFeeQuotaSaturates'],
                          ['github.com/QuantumNous/new-api/service', 'TestProviderErrorDiagnosticsAreSafeInChannelAndPolicyLogs']],
            'incomplete upstream error regression evidence')
    require(result['excluded'] == {
                'test': 'TestResponsesWebSocketInitialUpstreamRejectionRefundsReservation',
                'status': 'baseline_and_initial_tree_failed_in_fixture_before_assertions'},
            'supplemental fixture failure is not credited')


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
    previous = policy.relay_log_delta
    evidence = policy.consumer.evidence
    older = previous.historical_baseline(policy, reader, fetch)
    check = reader.check(PR263_C2)
    proof = evidence.decode(check['output']['text'])
    policy.require(check['id'] == PR263_C2 and policy.consumer.digest(proof) == PR263_PROOF and
                   (proof['candidate_sha'], proof['candidate_tree'], proof['consumer_run'], proof['terminal_run']) ==
                   (BASELINE['candidate_sha'], BASELINE['candidate_tree'], PR263_A, PR263_B),
                   'wrong signed PR263 baseline')
    signed = evidence.github_time(check, 'completed_at')
    policy.validate_gate(check, proof, completed=True)
    ref = proof['artifact']
    previous.validate_reference(ref, signed)
    policy.require(ref['identity']['consumer_sha'] == R12 and
                   policy.consumer.canonical(proof) == policy.consumer.canonical(previous.result(ref, PR263_B, older)),
                   'signed PR263 evidence differs from reviewed contract')
    done = previous.verify_approvals(policy, reader, ref, PR263_B, signed)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'PR263 signature predates its reviews')
    prior_run = reader.run(previous.HOSTED['run_id'], previous.HOSTED['attempt'])
    repo_id = ref['identity']['repository_id']
    policy.require(prior_run['id'] == previous.HOSTED['run_id'] and
                   prior_run['run_attempt'] == previous.HOSTED['attempt'] and
                   prior_run['workflow_id'] == policy.CI_WORKFLOW_ID and prior_run['path'] == '.github/workflows/ci.yml' and
                   prior_run['event'] == 'pull_request' and prior_run['head_sha'] == previous.HEAD and
                   prior_run['repository']['id'] == prior_run['head_repository']['id'] == repo_id and
                   reader.hosted_workflow_blob(previous.HEAD) == previous.HOSTED['workflow_blob'],
                   'historical PR263 hosted run or workflow blob changed')
    policy.verify_hosted_job_steps(reader, previous.HOSTED, previous.HEAD)
    if fetch is not None:
        previous.validate_package(policy, fetch(ref['artifact']['commit']))
    pr = reader.pull(263)
    merged = reader.commit(BASE)
    policy.require(pr['number'] == 263 and pr['state'] == 'closed' and pr['merged'] is True and
                   pr['merge_commit_sha'] == BASE and pr['head']['sha'] == BASELINE['candidate_sha'] and
                   pr['base']['ref'] == 'main' and pr['base']['repo']['id'] == repo_id and
                   merged['sha'] == BASE and merged['tree']['sha'] == BASELINE['candidate_tree'] and
                   [row['sha'] for row in merged['parents']] == [previous.BASE, previous.HEAD], 'wrong historical PR263 merge')
    run = reader.run(BASELINE['native_run'], 2)
    policy.require(run['id'] == BASELINE['native_run'] and run['run_attempt'] == 2 and
                   run['head_sha'] == BASELINE['candidate_sha'] and
                   run['repository']['id'] == run['head_repository']['id'] == repo_id and
                   run['path'] == '.github/workflows/ci.yml' and run['event'] == 'pull_request' and
                   run['workflow_id'] == policy.CI_WORKFLOW_ID and
                   run['status'] == 'completed' and run['conclusion'] == 'success', 'historical PR263 native gate did not pass')
    gate = policy.successful_job(reader.jobs(BASELINE['native_run'], 2), policy.GATE, BASELINE['candidate_sha'],
                                 ('Verify hosted jobs and authenticated exact-candidate quality',))
    policy.require(gate['id'] == PR263_NATIVE_JOB and gate['run_id'] == BASELINE['native_run'] and gate['run_attempt'] == 2 and
                   signed <= evidence.github_time(gate, 'started_at') <= evidence.github_time(gate, 'completed_at') <=
                   evidence.github_time(pr, 'merged_at') <= ref['identity']['release_expires_at'],
                   'PR263 native green and merge outside historical publication')
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
            'release_expires_at': identity['release_expires_at'], 'admission_id': 'pr264-upstream-errors-delta-' + HEAD,
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
        request['schema'] = 'box-quality-upstream-errors-consumer/v13'
    return request


def prescreen(policy, artifact, reader, fetch):
    policy.require(canonical(artifact) == canonical(ARCHIVE) and callable(fetch), 'wrong relay log preflight artifact')
    current_subject(policy, reader, {'repository_id': 1423238398, 'head_repository_id': 1423238398, 'pull_number': PR,
                                    'base_sha': BASE, 'candidate_sha': HEAD})
    historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    return {'candidate_sha': HEAD, 'candidate_tree': TREE, 'baseline': BASELINE, 'hosted': HOSTED, 'artifact': artifact}


def private_fetch(policy, token):
    old_fetch = policy.relay_log_delta.private_fetch(policy, token)
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
    policy.require(type(terminal) is int and check['id'] not in (C1, PR263_C2) and
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
