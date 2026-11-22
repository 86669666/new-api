"""Formal evidence reuse for PR #268 SQL and legacy Midjourney logs."""
from hashlib import sha256
import io
import json
import re
import urllib.request
import zipfile


PR = 268
HEAD = '953309ce8318900bd7794ae4adfb1f452f8c842d'
TREE = 'b59081afb6a3287f1cb4d656c7aba93532be2042'
BASE = '3559ebd202d767facf190a8eec79f876614c5509'
ROUND_TREES = ('d063e9e1d55500680a79fdde8c4029c686409d3c', TREE)
BRANCH = 'codex/issue-2-sql-and-midjourney-log-redaction'
CONTROL_REF = 'refs/heads/codex/formal-quality-r17'
REFERENCE_SCHEMA = 'box-formal-sql-midjourney-delta-ref/v17'
TERMINAL_SCHEMA = 'box-quality-terminal/v17'
SCOPE = 'sql-midjourney-logs'
C1 = 135232975120
PR267_C2 = 137105049217
PR267_PROOF = '1775fd4f3cde08cae3bc9ea6304f30a4408244ff35cae96adfdd933ad66e7440'
PR267_A, PR267_B = 44987233688, 44987945481
PR267_NATIVE_JOB = 137106005971
R16 = '6dc5e949040cb79402af4dcee2965e05b4dd7391'
HOSTED = {'attempt': 1, 'run_id': 44990744265, 'workflow_blob': 'c123990e4a8c9fd981b721455a8edbc65b62dfc5'}
BASELINE = {'pull_number': 267, 'candidate_sha': 'e4832819ae0178ee82071e685514de2e7cdb260b',
            'candidate_tree': 'c6fbe5a0f728dcabdc6d0a72221b6eaaa57df1e8', 'merge_commit': BASE,
            'terminal_check_id': PR267_C2, 'native_run': 44985894450,
            'native_attempt': 2, 'native_job': PR267_NATIVE_JOB}
MANIFEST = '04800f8083c7701f9584a79529881f38b2ce238bdc52e0b97d697fbd9ab978c9'
ARCHIVE = {'bytes': 17775,
 'commit': '7286a61bcd2dc29112bed10428e7701b3b45727a',
 'path': 'formal-audit/pr268-953309ce-formal-inputs.zip',
 'sha256': '909ea9aa20910b9037cd6509ee795b2f2be84d3b96b7ca58d885d65efd509484'}
BLOBS = {'controller/midjourney.go': '0b9e12be42318a2b1aba9a65fe20b888d764a464',
 'controller/midjourney_test.go': '3aa91c76d6fdaa4222a3b6e4623d4b013c30bf31',
 'model/channel.go': 'be44de5672cec96670e59d46d4a98adc116900b6',
 'model/gorm_logger.go': 'caac48383840a58a34c53bd2d5207abaf6f7cc26',
 'model/gorm_logger_test.go': '8d89a3df83480feb3c64ccced2347ad1a82abe5f',
 'model/log.go': '1ad2c85cc7adcd04512ebb1c493c54be5f822bac',
 'model/user.go': 'c431741f79f12c5a97d772abe02f2ca71dad8443',
 'service/midjourney.go': 'eed18d5b0574655a6da1817f2b69cab3e3999132',
 'service/task_billing.go': '5f629ee7ceaf1484fae1b5ab796dcf23bdb18a46'}
MEMBERS = {'candidate.patch': 'd06ce4675b2d27e81b966e0e63ad61488d6667ce86cb78bddbdf1bfd042ac25f',
 'independent-review.json': 'aa7f908902f21af23bea8d7e3a539c816b4391393ef82002c36a05a022ada8b0',
 'targeted-review.json': '4bfb664045dfbe50d9893cc11cab55d7eafa1244a988b7ceae1dc90ad047046b',
 'targeted-review.jsonl': '4ac1b76a7a4308dff9c1f03270ef92669ee31e42051422b08181a8cc076d42d2',
 'targeted.json': '10cbdba21a8e3cceff123719e4afdce8a3e710f1293b9fd71b0bb6965d8371af',
 'targeted.jsonl': 'a8ea715798589c807220169faac1a059a4be40ff580ea066086b5f8747ad0e61',
 'validation.json': 'b92b31de3fff93162be9b201bca4ff2be65ec5dda10ceab77336ce19ecfac745',
 'verification.json': '38df14e53c097fb5dca737de8450ff0e94968b9de84456dc43bafaf994588673'}
FILES = tuple(BLOBS)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=True).encode('ascii')


def descriptor():
    return ARCHIVE.copy()


def consumer_intent(artifact, control, nonce):
    if (canonical(artifact) != canonical(ARCHIVE) or not re.fullmatch('[a-f0-9]{40}', control) or
            control == R16 or not re.fullmatch('[a-f0-9]{32}', nonce)):
        raise ValueError('invalid SQL and legacy Midjourney log delta selection')
    bound = {'artifact': artifact, 'baseline': BASELINE, 'tree': TREE, 'head': HEAD,
             'hosted': HOSTED, 'control': control, 'nonce': nonce}
    return sha256(canonical(bound)).hexdigest()


def make_reference(artifact, control, consumer_run, opened, nonce):
    consumer_intent(artifact, control, nonce)
    if type(consumer_run) is not int or consumer_run <= 0 or type(opened) is not int or opened <= 0:
        raise ValueError('invalid SQL and legacy Midjourney log delta approval times')
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
        raise ValueError('invalid or expired SQL and legacy Midjourney log delta reference')


def validate_package(policy, raw):
    require = policy.require
    decode = policy.consumer.evidence.decode
    require(type(raw) is bytes and len(raw) == ARCHIVE['bytes'] and sha256(raw).hexdigest() == ARCHIVE['sha256'],
            'wrong immutable SQL and legacy Midjourney log evidence')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(sorted(archive.namelist()) == sorted((*MEMBERS, 'manifest.json')), 'incorrect SQL and legacy Midjourney log artifact inventory')
        manifest = archive.read('manifest.json')
        require(sha256(manifest).hexdigest() == MANIFEST and
                {name: sha256(archive.read(name)).hexdigest() for name in MEMBERS} == MEMBERS,
                'unreviewed SQL and legacy Midjourney log evidence member')
        result = decode(archive.read('validation.json'))
        review = decode(archive.read('independent-review.json'))
    data = decode(manifest)
    require((data['kind'], data['pull'], data['head'], data['tree'], data['base'], data['paths']) ==
            ('pr268-sql-midjourney-logs/v1', PR, HEAD, TREE, BASE, list(FILES)) and
            data['hosted'] == HOSTED and data['blobs'] == BLOBS and
            data['baseline_terminal'] == PR267_C2 and data['members'] == MEMBERS, 'wrong SQL and legacy Midjourney log evidence subjects')
    require((result['candidate'], result['tree'], result['round_trees'], result['review'], result['runner']) ==
            (HEAD, TREE, list(ROUND_TREES), 'ACCEPT_SCOPED', 'go1.26.10 linux/amd64'),
            'wrong reviewed validation subjects')
    rounds = result['round_leaves']
    reused, final = ({tuple(row) for row in items} for items in rounds)
    require([len(items) for items in rounds] == [6, 16] and (len(reused), len(final)) == (6, 16) and
            len(reused | final) == 22 and
            {p for p, _ in reused} == {'github.com/QuantumNous/new-api/controller', 'github.com/QuantumNous/new-api/service'} and
            {p for p, _ in final} == {'github.com/QuantumNous/new-api/model'} and
            result['excluded_failures'] == [[['github.com/QuantumNous/new-api/model',
                'TestGormLoggerEndToEndSanitizedOutput/debug']], []], 'incomplete SQL and legacy Midjourney log regression evidence')
    require((review['base'], review['tree'], review['round_one'], review['verdict'], review['tests_sha256']) ==
            (BASE, TREE, ROUND_TREES[0], 'ACCEPT_SCOPED', MEMBERS['targeted-review.jsonl']),
            'wrong independent review subject')


def current_subject(policy, reader, identity):
    base = reader.repository()
    pr = reader.pull(PR)
    repo_id = identity['repository_id']
    policy.require(base['id'] == repo_id and base['full_name'] == policy.REPOSITORY and
                   pr['number'] == PR and pr['state'] == 'open' and pr['merged'] is False and pr['draft'] is False and pr['changed_files'] == len(FILES) and
                   pr['head']['repo']['id'] == pr['base']['repo']['id'] == repo_id and
                   pr['head']['repo']['full_name'] == pr['base']['repo']['full_name'] == policy.REPOSITORY and
                   pr['head']['sha'] == HEAD and pr['head']['ref'] == BRANCH and
                   pr['base']['sha'] == BASE and pr['base']['ref'] == 'main', 'current SQL and legacy Midjourney log PR subject changed')
    commit = reader.commit(HEAD)
    policy.require(commit['sha'] == HEAD and commit['tree']['sha'] == TREE and
                   [row['sha'] for row in commit['parents']] == [BASE], 'wrong SQL and legacy Midjourney log candidate tree or parents')
    policy.verify_hosted_jobs(reader, HOSTED, identity)


def historical_baseline(policy, reader, fetch=None):
    previous = policy.request_plugin_delta
    evidence = policy.consumer.evidence
    older = previous.historical_baseline(policy, reader, fetch)
    check = reader.check(PR267_C2)
    proof = evidence.decode(check['output']['text'])
    policy.require(check['id'] == PR267_C2 and policy.consumer.digest(proof) == PR267_PROOF and
                   (proof['candidate_sha'], proof['candidate_tree'], proof['consumer_run'], proof['terminal_run']) ==
                   (BASELINE['candidate_sha'], BASELINE['candidate_tree'], PR267_A, PR267_B),
                   'wrong signed PR267 baseline')
    signed = evidence.github_time(check, 'completed_at')
    policy.validate_gate(check, proof, completed=True)
    ref = proof['artifact']
    previous.validate_reference(ref, signed)
    policy.require(ref['identity']['consumer_sha'] == R16 and
                   policy.consumer.canonical(proof) == policy.consumer.canonical(previous.result(ref, PR267_B, older)),
                   'signed PR267 evidence differs from reviewed contract')
    done = previous.verify_approvals(policy, reader, ref, PR267_B, signed)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'PR267 signature predates its reviews')
    prior_run = reader.run(previous.HOSTED['run_id'], previous.HOSTED['attempt'])
    repo_id = ref['identity']['repository_id']
    policy.require(prior_run['id'] == previous.HOSTED['run_id'] and
                   prior_run['run_attempt'] == previous.HOSTED['attempt'] and
                   prior_run['workflow_id'] == policy.CI_WORKFLOW_ID and prior_run['path'] == '.github/workflows/ci.yml' and
                   prior_run['event'] == 'pull_request' and prior_run['head_sha'] == previous.HEAD and
                   prior_run['repository']['id'] == prior_run['head_repository']['id'] == repo_id and
                   reader.hosted_workflow_blob(previous.HEAD) == previous.HOSTED['workflow_blob'],
                   'historical PR267 hosted run or workflow blob changed')
    policy.verify_hosted_job_steps(reader, previous.HOSTED, previous.HEAD)
    if fetch is not None:
        previous.validate_package(policy, fetch(ref['artifact']['commit']))
    pr = reader.pull(267)
    merged = reader.commit(BASE)
    policy.require(pr['number'] == 267 and pr['state'] == 'closed' and pr['merged'] is True and
                   pr['merge_commit_sha'] == BASE and pr['head']['sha'] == BASELINE['candidate_sha'] and
                   pr['base']['ref'] == 'main' and pr['base']['repo']['id'] == repo_id and
                   merged['sha'] == BASE and merged['tree']['sha'] == BASELINE['candidate_tree'] and
                   [row['sha'] for row in merged['parents']] == [previous.BASE, previous.HEAD], 'wrong historical PR267 merge')
    run = reader.run(BASELINE['native_run'], 2)
    policy.require(run['id'] == BASELINE['native_run'] and run['run_attempt'] == 2 and
                   run['head_sha'] == BASELINE['candidate_sha'] and
                   run['repository']['id'] == run['head_repository']['id'] == repo_id and
                   run['path'] == '.github/workflows/ci.yml' and run['event'] == 'pull_request' and
                   run['workflow_id'] == policy.CI_WORKFLOW_ID and
                   run['status'] == 'completed' and run['conclusion'] == 'success', 'historical PR267 native gate did not pass')
    gate = policy.successful_job(reader.jobs(BASELINE['native_run'], 2), policy.GATE, BASELINE['candidate_sha'],
                                 ('Verify hosted jobs and authenticated exact-candidate quality',))
    policy.require(gate['id'] == PR267_NATIVE_JOB and gate['run_id'] == BASELINE['native_run'] and gate['run_attempt'] == 2 and
                   signed <= evidence.github_time(gate, 'started_at') <= evidence.github_time(gate, 'completed_at') <=
                   evidence.github_time(pr, 'merged_at') <= ref['identity']['release_expires_at'],
                   'PR267 native green and merge outside historical publication')
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
        policy.require(type(terminal_run) is int and terminal_run != consumer_run, 'separate SQL and legacy Midjourney log terminal required')
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
            'release_expires_at': identity['release_expires_at'], 'admission_id': 'pr268-sql-midjourney-delta-' + HEAD,
            'invocation': consumer_intent(reference['artifact'], identity['consumer_sha'], reference['nonce'])}


def verify(policy, reference, reader, fetch, terminal_run, now, *, active=False, staged_at=None):
    validate_reference(reference, now)
    policy.require(callable(fetch) and (active or terminal_run is not None), 'both reviewed SQL and legacy Midjourney log jobs required')
    done = verify_approvals(policy, reader, reference, terminal_run, now, active=active)
    if staged_at is not None:
        policy.require(done is not None and done <= staged_at <= now, 'SQL and legacy Midjourney log result staged before terminal completion')
    proof = historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    current_subject(policy, reader, reference['identity'])
    request = result(reference, terminal_run, proof)
    if terminal_run is None:
        request['schema'] = 'box-quality-sql-midjourney-consumer/v17'
    return request


def prescreen(policy, artifact, reader, fetch):
    policy.require(canonical(artifact) == canonical(ARCHIVE) and callable(fetch), 'wrong SQL and legacy Midjourney log preflight artifact')
    current_subject(policy, reader, {'repository_id': 1423238398, 'head_repository_id': 1423238398, 'pull_number': PR,
                                    'base_sha': BASE, 'candidate_sha': HEAD})
    historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    return {'candidate_sha': HEAD, 'candidate_tree': TREE, 'baseline': BASELINE, 'hosted': HOSTED, 'artifact': artifact}


def private_fetch(policy, token):
    old_fetch = policy.request_plugin_delta.private_fetch(policy, token)
    evidence = policy.consumer.evidence

    def fetch(commit):
        if commit != ARCHIVE['commit']:
            return old_fetch(commit)
        path = '/repos/' + evidence.EVIDENCE_REPOSITORY
        repo = policy.consumer.api(path, token)
        policy.require(repo['id'] == evidence.EVIDENCE_REPOSITORY_ID and
                       repo['full_name'] == evidence.EVIDENCE_REPOSITORY and repo['private'] is True,
                       'wrong private SQL and legacy Midjourney log evidence repository')
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
                   environment['GITHUB_SHA'] == environment['GITHUB_WORKFLOW_SHA'] == trusted, 'wrong native SQL and legacy Midjourney log dispatch')
    reference = evidence.decode(environment['BOX_FORMAL_ADMISSION'])
    run = int(environment['GITHUB_RUN_ID'])
    validate_reference(reference, int(clock()))
    policy.require(trusted == reference['identity']['consumer_sha'] and (run != reference['consumer_run']) == terminal,
                   'wrong protected SQL and legacy Midjourney log run')
    if terminal:
        for field, key in [('BOX_FORMAL_HOSTED_RUN_ID', 'run_id'), ('BOX_FORMAL_HOSTED_RUN_ATTEMPT', 'attempt'),
                           ('BOX_FORMAL_HOSTED_CI_BLOB', 'workflow_blob')]:
            policy.require(environment[field] == str(HOSTED[key]), 'wrong SQL and legacy Midjourney log hosted run pin')
    token = environment['BOX_FORMAL_EVIDENCE_TOKEN']
    policy.require(token and token != environment['GITHUB_TOKEN'], 'dedicated private evidence reader required')
    checked = verify(policy, reference, policy.GitHubReader(environment['GITHUB_TOKEN']), private_fetch(policy, token),
                     run if terminal else None, int(clock()), active=True)
    validate_reference(reference, int(clock()))
    return checked


def verify_public(policy, environment, reader, *, clock):
    event = policy.ci_premerge_event(environment)
    policy.require(environment['GITHUB_EVENT_NAME'] == 'pull_request' and environment['GITHUB_RUN_ID'] == str(HOSTED['run_id'])
                   and event['number'] == PR and event['pull_request']['head']['sha'] == HEAD, 'wrong native SQL and legacy Midjourney log gate')
    check = reader.formal_quality_check(HEAD)
    request = policy.consumer.evidence.decode(check['output']['text'])
    now = int(clock())
    reference = request['artifact']
    validate_reference(reference, now)
    policy.validate_ci_evidence_reference(event, environment, reference['identity'])
    policy.validate_gate(check, request, completed=True)
    proof = historical_baseline(policy, reader)
    terminal = request['terminal_run']
    policy.require(type(terminal) is int and check['id'] not in (C1, PR267_C2) and
                   policy.consumer.canonical(request) == policy.consumer.canonical(result(reference, terminal, proof)),
                   'SQL and legacy Midjourney log result differs from exact scope and subjects')
    done = verify_approvals(policy, reader, reference, terminal, now)
    evidence = policy.consumer.evidence
    evidence.check_times(check, reference['identity'], now)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'SQL and legacy Midjourney log signature predates second approval')
    current_subject(policy, reader, reference['identity'])
    policy.resolve_ci_candidate(environment, reader)
    validate_reference(reference, int(clock()))
    return request
