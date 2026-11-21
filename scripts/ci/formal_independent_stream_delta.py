"""Formal evidence reuse for PR #266 independent streams and channel-test logs."""
from hashlib import sha256
import io
import json
import re
import urllib.request
import zipfile


PR = 266
HEAD = 'ce31285d6cd308bcbac29d53fc1f6d5b754cd3c5'
TREE = 'a0e397f8519cb355a845b95dc3efcd26d4cba1ab'
BASE = 'e2ebc2ad768c318d6b96c4ab5d9f0a97cbc148b0'
ROUND_TREES = ('b4ae1a291497c075b55fca1c11ad669f2edc3032', TREE)
BRANCH = 'codex/issue-2-independent-stream-logs'
CONTROL_REF = 'refs/heads/codex/formal-quality-r15'
REFERENCE_SCHEMA = 'box-formal-independent-stream-delta-ref/v15'
TERMINAL_SCHEMA = 'box-quality-terminal/v15'
SCOPE = 'independent-stream-channel-test-logs'
C1 = 135232975120
PR265_C2 = 136908333354
PR265_PROOF = '801d0b8ff47d8175e7260dc84b128c10b2fea5e5b9e7685c5c519973fbf8df5d'
PR265_A, PR265_B = 44923199691, 44923787509
PR265_NATIVE_JOB = 136909354663
R14 = '76446588e9ee161a53ac08ca071849929df0798e'
HOSTED = {'attempt': 1, 'run_id': 44926955541, 'workflow_blob': 'c123990e4a8c9fd981b721455a8edbc65b62dfc5'}
BASELINE = {'pull_number': 265, 'candidate_sha': '5ab93ccc7199dbbced7f67c3d76232ec7e2c32b6',
            'candidate_tree': '608826742ff4e1520dc840616cce5216a2277f72', 'merge_commit': BASE,
            'terminal_check_id': PR265_C2, 'native_run': 44921453144,
            'native_attempt': 2, 'native_job': PR265_NATIVE_JOB}
MANIFEST = 'df66e789f24686f3fa7c620396e4d7e0dbfaf74d862dce9d39f9beac11b5297e'
ARCHIVE = {'bytes': 23944,
 'commit': 'ec76f3d86ae7a4c67d6af822323e43ef6a6360a0',
 'path': 'formal-audit/pr266-ce31285d-formal-inputs.zip',
 'sha256': 'fbee803eb301217dd4a11aca8980e8ecde47d93169d1b34828b43a86eb6d834f'}
BLOBS = {'controller/channel-test.go': 'c95378470a94900794efec43d4b6b0d478743dc6',
 'controller/channel_test_request_test.go': '63e884b7b9234b007b9b0a89cdc2a5430e41a320',
 'relay/channel/aws/dto.go': '020fc06dccdb057762568de9e23f6f08e1d1e97b',
 'relay/channel/aws/relay-aws.go': '98e8886c85140983275420199a6d216e0afee6f9',
 'relay/channel/baidu/relay-baidu.go': 'fcabbbf95f5b28bf1192b6d38a9c58a25b1dd1b9',
 'relay/channel/claude/relay-claude.go': '98d969da401d94eafc1f936984a89ed6aa52efe6',
 'relay/channel/claude/relay_claude_test.go': '7b053cbaaa005c57909d753dc2d2b3bab81db11f',
 'relay/channel/claude/relay_responses.go': '46af473db3f5dddb79efa2826194091d815e461c',
 'relay/channel/cloudflare/relay_cloudflare.go': '2bfb62970db366460aefb9201a9357433a20c26b',
 'relay/channel/cohere/relay-cohere.go': 'fc80244d6e5e5e63d71c86f274b862f4eddf41e8',
 'relay/channel/coze/relay-coze.go': '74c701ccd83055dc7b1328c1f13bbccdd3faf731',
 'relay/channel/coze/relay_coze_test.go': '2db080d1564c87b0ddbf60976d75896ddf3e303b',
 'relay/channel/dify/relay-dify.go': '36ca7ad0c12ddb6c55c35002e1e77d6543d06957',
 'relay/channel/gemini/relay-gemini-native.go': '4524c627cea999047c645fb72be79057e224db7b',
 'relay/channel/gemini/relay-gemini.go': 'a80e8d531f14f8599d4278af3b4d1c99f628d8f7',
 'relay/channel/gemini/relay_gemini_usage_test.go': '77241fc13bbb7ea4b6125f4573d37403c151e73c',
 'relay/channel/gemini/relay_responses.go': '224c7867da29dd4b2e6670cc81555725e084f538',
 'relay/channel/ollama/stream.go': '0ad1e1e39c806d20d6de3220e1dfb9375ab91564',
 'relay/channel/openai/audio.go': '841019ebb5d3fc0e34ad7eefbfb2e2e3fb650c27',
 'relay/channel/openai/relay-openai.go': '060999906112521aa0375a620996084c7e296d38',
 'relay/channel/openai/relay_realtime.go': '70ef76de49cf6964d379ec191ac28b7b5ca8fef3',
 'relay/channel/openai/relay_realtime_test.go': '4f725ec72fc4421c08d676c951b63339187f9f10',
 'relay/channel/palm/relay-palm.go': '9f6a19fab132dde747d9ca363dc4651d3dfeb692',
 'relay/channel/tencent/relay-tencent.go': '49082981945cc2722ff8b891733adb666f254f9e',
 'relay/channel/volcengine/tts.go': '5a12379bea7ce4f502a67d77f0c6833d039f69a2',
 'relay/channel/volcengine/tts_test.go': '3616cc442f528d97ed55acb69ec04762a926fe2a',
 'relay/channel/xai/text.go': '7770c12eac60ab3abb1b1396d0b44f83f3be29fb',
 'relay/channel/xunfei/relay-xunfei.go': 'bdc197304af2cf0cef9e3cfc951c57ee285fad45',
 'relay/channel/zhipu/relay-zhipu.go': 'd187c6d7fea3e019a5a10f03f81bef3d00e64445',
 'relay/common_handler/rerank.go': 'ae13530bd925678c14e5f26cb3666447ae2ed808'}
MEMBERS = {'candidate.patch': '119045fc16f94f66ca7baa108cbaab6533968b03ca7c9af661b4f1647953345e',
 'targeted-review.json': '978d202fa4fbb899e0eba0ada57adbefd1f7f1894370adee1726e0a3b0adba09',
 'targeted-review.jsonl': '70d6b44996b1595b787adff692a332ba5ae2b92a17234c110986b9acd9eb9a81',
 'targeted.json': 'd8978b03a8d1c8155e929cd31731f44649c6e3be74bc54e345377388ba73984c',
 'targeted.jsonl': 'bb7791648e51b5df3891fcb02ef1036c2529d2eefa1e2b9a5853a4fe8e60ab0e',
 'validation.json': '20d6527f309d52f0a58b4b9f710e7dc1ae17512c1cfa7a7f9fec5a6b0432eba0',
 'verification.json': '31044a6bcb4eb7158f08b03063be4c59fafa6fd3e100a866389922135619c7f3'}
FILES = tuple(BLOBS)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=True).encode('ascii')


def descriptor():
    return ARCHIVE.copy()


def consumer_intent(artifact, control, nonce):
    if (canonical(artifact) != canonical(ARCHIVE) or not re.fullmatch('[a-f0-9]{40}', control) or
            control == R14 or not re.fullmatch('[a-f0-9]{32}', nonce)):
        raise ValueError('invalid independent stream log delta selection')
    bound = {'artifact': artifact, 'baseline': BASELINE, 'tree': TREE, 'head': HEAD,
             'hosted': HOSTED, 'control': control, 'nonce': nonce}
    return sha256(canonical(bound)).hexdigest()


def make_reference(artifact, control, consumer_run, opened, nonce):
    consumer_intent(artifact, control, nonce)
    if type(consumer_run) is not int or consumer_run <= 0 or type(opened) is not int or opened <= 0:
        raise ValueError('invalid independent stream log delta approval times')
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
        raise ValueError('invalid or expired independent stream log delta reference')


def validate_package(policy, raw):
    require = policy.require
    decode = policy.consumer.evidence.decode
    require(type(raw) is bytes and len(raw) == ARCHIVE['bytes'] and sha256(raw).hexdigest() == ARCHIVE['sha256'],
            'wrong immutable independent stream log evidence')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(sorted(archive.namelist()) == sorted((*MEMBERS, 'manifest.json')), 'incorrect independent stream log artifact inventory')
        manifest = archive.read('manifest.json')
        require(sha256(manifest).hexdigest() == MANIFEST and
                {name: sha256(archive.read(name)).hexdigest() for name in MEMBERS} == MEMBERS,
                'unreviewed independent stream log evidence member')
        result = decode(archive.read('validation.json'))
    data = decode(manifest)
    require((data['kind'], data['pull'], data['head'], data['tree'], data['base'], data['paths']) ==
            ('pr266-independent-stream-channel-test-logs/v1', PR, HEAD, TREE, BASE, list(FILES)) and
            data['hosted'] == HOSTED and data['blobs'] == BLOBS and
            data['baseline_terminal'] == PR265_C2 and data['members'] == MEMBERS, 'wrong independent stream log evidence subjects')
    require((result['candidate'], result['tree'], result['round_trees'], result['review'], result['runner']) ==
            (HEAD, TREE, list(ROUND_TREES), 'ACCEPT_SCOPED', 'go1.26.10 linux/amd64'),
            'wrong reviewed validation subjects')
    rounds = result['round_leaves']
    corrected = {
        'TestChannelTestResponseLogOmitsProviderContent/JSON',
        'TestClaudeStreamProviderErrorKeepsClientMessageOutOfDiagnostics/converted_Responses',
    }
    require([len(items) for items in rounds] == [11, 6] and
            len({tuple(row) for items in rounds for row in items}) == 17 and
            corrected <= {row[1] for row in rounds[1]} and
            corrected.isdisjoint(row[1] for row in rounds[0]) and
            set(result['excluded']) == corrected, 'incomplete independent stream regression evidence')


def current_subject(policy, reader, identity):
    base = reader.repository()
    pr = reader.pull(PR)
    repo_id = identity['repository_id']
    policy.require(base['id'] == repo_id and base['full_name'] == policy.REPOSITORY and
                   pr['number'] == PR and pr['state'] == 'open' and pr['merged'] is False and pr['draft'] is False and pr['changed_files'] == len(FILES) and
                   pr['head']['repo']['id'] == pr['base']['repo']['id'] == repo_id and
                   pr['head']['repo']['full_name'] == pr['base']['repo']['full_name'] == policy.REPOSITORY and
                   pr['head']['sha'] == HEAD and pr['head']['ref'] == BRANCH and
                   pr['base']['sha'] == BASE and pr['base']['ref'] == 'main', 'current independent stream log PR subject changed')
    commit = reader.commit(HEAD)
    policy.require(commit['sha'] == HEAD and commit['tree']['sha'] == TREE and
                   [row['sha'] for row in commit['parents']] == [BASE], 'wrong independent stream log candidate tree or parents')
    policy.verify_hosted_jobs(reader, HOSTED, identity)


def historical_baseline(policy, reader, fetch=None):
    previous = policy.provider_logs_delta
    evidence = policy.consumer.evidence
    older = previous.historical_baseline(policy, reader, fetch)
    check = reader.check(PR265_C2)
    proof = evidence.decode(check['output']['text'])
    policy.require(check['id'] == PR265_C2 and policy.consumer.digest(proof) == PR265_PROOF and
                   (proof['candidate_sha'], proof['candidate_tree'], proof['consumer_run'], proof['terminal_run']) ==
                   (BASELINE['candidate_sha'], BASELINE['candidate_tree'], PR265_A, PR265_B),
                   'wrong signed PR265 baseline')
    signed = evidence.github_time(check, 'completed_at')
    policy.validate_gate(check, proof, completed=True)
    ref = proof['artifact']
    previous.validate_reference(ref, signed)
    policy.require(ref['identity']['consumer_sha'] == R14 and
                   policy.consumer.canonical(proof) == policy.consumer.canonical(previous.result(ref, PR265_B, older)),
                   'signed PR265 evidence differs from reviewed contract')
    done = previous.verify_approvals(policy, reader, ref, PR265_B, signed)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'PR265 signature predates its reviews')
    prior_run = reader.run(previous.HOSTED['run_id'], previous.HOSTED['attempt'])
    repo_id = ref['identity']['repository_id']
    policy.require(prior_run['id'] == previous.HOSTED['run_id'] and
                   prior_run['run_attempt'] == previous.HOSTED['attempt'] and
                   prior_run['workflow_id'] == policy.CI_WORKFLOW_ID and prior_run['path'] == '.github/workflows/ci.yml' and
                   prior_run['event'] == 'pull_request' and prior_run['head_sha'] == previous.HEAD and
                   prior_run['repository']['id'] == prior_run['head_repository']['id'] == repo_id and
                   reader.hosted_workflow_blob(previous.HEAD) == previous.HOSTED['workflow_blob'],
                   'historical PR265 hosted run or workflow blob changed')
    policy.verify_hosted_job_steps(reader, previous.HOSTED, previous.HEAD)
    if fetch is not None:
        previous.validate_package(policy, fetch(ref['artifact']['commit']))
    pr = reader.pull(265)
    merged = reader.commit(BASE)
    policy.require(pr['number'] == 265 and pr['state'] == 'closed' and pr['merged'] is True and
                   pr['merge_commit_sha'] == BASE and pr['head']['sha'] == BASELINE['candidate_sha'] and
                   pr['base']['ref'] == 'main' and pr['base']['repo']['id'] == repo_id and
                   merged['sha'] == BASE and merged['tree']['sha'] == BASELINE['candidate_tree'] and
                   [row['sha'] for row in merged['parents']] == [previous.BASE, previous.HEAD], 'wrong historical PR265 merge')
    run = reader.run(BASELINE['native_run'], 2)
    policy.require(run['id'] == BASELINE['native_run'] and run['run_attempt'] == 2 and
                   run['head_sha'] == BASELINE['candidate_sha'] and
                   run['repository']['id'] == run['head_repository']['id'] == repo_id and
                   run['path'] == '.github/workflows/ci.yml' and run['event'] == 'pull_request' and
                   run['workflow_id'] == policy.CI_WORKFLOW_ID and
                   run['status'] == 'completed' and run['conclusion'] == 'success', 'historical PR265 native gate did not pass')
    gate = policy.successful_job(reader.jobs(BASELINE['native_run'], 2), policy.GATE, BASELINE['candidate_sha'],
                                 ('Verify hosted jobs and authenticated exact-candidate quality',))
    policy.require(gate['id'] == PR265_NATIVE_JOB and gate['run_id'] == BASELINE['native_run'] and gate['run_attempt'] == 2 and
                   signed <= evidence.github_time(gate, 'started_at') <= evidence.github_time(gate, 'completed_at') <=
                   evidence.github_time(pr, 'merged_at') <= ref['identity']['release_expires_at'],
                   'PR265 native green and merge outside historical publication')
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
        policy.require(type(terminal_run) is int and terminal_run != consumer_run, 'separate independent stream log terminal required')
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
            'release_expires_at': identity['release_expires_at'], 'admission_id': 'pr266-independent-stream-delta-' + HEAD,
            'invocation': consumer_intent(reference['artifact'], identity['consumer_sha'], reference['nonce'])}


def verify(policy, reference, reader, fetch, terminal_run, now, *, active=False, staged_at=None):
    validate_reference(reference, now)
    policy.require(callable(fetch) and (active or terminal_run is not None), 'both reviewed independent stream log jobs required')
    done = verify_approvals(policy, reader, reference, terminal_run, now, active=active)
    if staged_at is not None:
        policy.require(done is not None and done <= staged_at <= now, 'independent stream log result staged before terminal completion')
    proof = historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    current_subject(policy, reader, reference['identity'])
    request = result(reference, terminal_run, proof)
    if terminal_run is None:
        request['schema'] = 'box-quality-independent-stream-consumer/v15'
    return request


def prescreen(policy, artifact, reader, fetch):
    policy.require(canonical(artifact) == canonical(ARCHIVE) and callable(fetch), 'wrong independent stream log preflight artifact')
    current_subject(policy, reader, {'repository_id': 1423238398, 'head_repository_id': 1423238398, 'pull_number': PR,
                                    'base_sha': BASE, 'candidate_sha': HEAD})
    historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    return {'candidate_sha': HEAD, 'candidate_tree': TREE, 'baseline': BASELINE, 'hosted': HOSTED, 'artifact': artifact}


def private_fetch(policy, token):
    old_fetch = policy.provider_logs_delta.private_fetch(policy, token)
    evidence = policy.consumer.evidence

    def fetch(commit):
        if commit != ARCHIVE['commit']:
            return old_fetch(commit)
        path = '/repos/' + evidence.EVIDENCE_REPOSITORY
        repo = policy.consumer.api(path, token)
        policy.require(repo['id'] == evidence.EVIDENCE_REPOSITORY_ID and
                       repo['full_name'] == evidence.EVIDENCE_REPOSITORY and repo['private'] is True,
                       'wrong private independent stream log evidence repository')
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
                   environment['GITHUB_SHA'] == environment['GITHUB_WORKFLOW_SHA'] == trusted, 'wrong native independent stream log dispatch')
    reference = evidence.decode(environment['BOX_FORMAL_ADMISSION'])
    run = int(environment['GITHUB_RUN_ID'])
    validate_reference(reference, int(clock()))
    policy.require(trusted == reference['identity']['consumer_sha'] and (run != reference['consumer_run']) == terminal,
                   'wrong protected independent stream log run')
    if terminal:
        for field, key in [('BOX_FORMAL_HOSTED_RUN_ID', 'run_id'), ('BOX_FORMAL_HOSTED_RUN_ATTEMPT', 'attempt'),
                           ('BOX_FORMAL_HOSTED_CI_BLOB', 'workflow_blob')]:
            policy.require(environment[field] == str(HOSTED[key]), 'wrong independent stream log hosted run pin')
    token = environment['BOX_FORMAL_EVIDENCE_TOKEN']
    policy.require(token and token != environment['GITHUB_TOKEN'], 'dedicated private evidence reader required')
    checked = verify(policy, reference, policy.GitHubReader(environment['GITHUB_TOKEN']), private_fetch(policy, token),
                     run if terminal else None, int(clock()), active=True)
    validate_reference(reference, int(clock()))
    return checked


def verify_public(policy, environment, reader, *, clock):
    event = policy.ci_premerge_event(environment)
    policy.require(environment['GITHUB_EVENT_NAME'] == 'pull_request' and environment['GITHUB_RUN_ID'] == str(HOSTED['run_id'])
                   and event['number'] == PR and event['pull_request']['head']['sha'] == HEAD, 'wrong native independent stream log gate')
    check = reader.formal_quality_check(HEAD)
    request = policy.consumer.evidence.decode(check['output']['text'])
    now = int(clock())
    reference = request['artifact']
    validate_reference(reference, now)
    policy.validate_ci_evidence_reference(event, environment, reference['identity'])
    policy.validate_gate(check, request, completed=True)
    proof = historical_baseline(policy, reader)
    terminal = request['terminal_run']
    policy.require(type(terminal) is int and check['id'] not in (C1, PR265_C2) and
                   policy.consumer.canonical(request) == policy.consumer.canonical(result(reference, terminal, proof)),
                   'independent stream log result differs from exact scope and subjects')
    done = verify_approvals(policy, reader, reference, terminal, now)
    evidence = policy.consumer.evidence
    evidence.check_times(check, reference['identity'], now)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'independent stream log signature predates second approval')
    current_subject(policy, reader, reference['identity'])
    policy.resolve_ci_candidate(environment, reader)
    validate_reference(reference, int(clock()))
    return request
