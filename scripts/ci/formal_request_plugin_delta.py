"""Formal evidence reuse for PR #267 request and task-plugin log redaction."""
from hashlib import sha256
import io
import json
import re
import urllib.request
import zipfile

PR = 267
HEAD = 'e4832819ae0178ee82071e685514de2e7cdb260b'
TREE = 'c6fbe5a0f728dcabdc6d0a72221b6eaaa57df1e8'
BASE = 'ec1656751d533bc0cd996f8f27654d5e95148afe'
ROUND_TREES = ('1098ef8633dc85eeeed4ae3dd382ca2ad09d037c', TREE)
BRANCH = 'codex/issue-2-request-plugin-log-redaction'
CONTROL_REF = 'refs/heads/codex/formal-quality-r16'
REFERENCE_SCHEMA = 'box-formal-request-plugin-delta-ref/v16'
TERMINAL_SCHEMA = 'box-quality-terminal/v16'
SCOPE = 'request-plugin-logs'
C1 = 135232975120
PR266_C2 = 136936945299
PR266_PROOF = '8f7d78a554e46c44ad3b337c28842a5a64500a6e355be43f9a1259d909636906'
PR266_A, PR266_B = 44931992395, 44932931498
PR266_NATIVE_JOB = 136938058889
R15 = '66dc64a488571bc7c64f3a7ca52884070a24ea9a'
HOSTED = {'attempt': 1, 'run_id': 44985894450, 'workflow_blob': 'c123990e4a8c9fd981b721455a8edbc65b62dfc5'}
BASELINE = {'pull_number': 266, 'candidate_sha': 'ce31285d6cd308bcbac29d53fc1f6d5b754cd3c5',
            'candidate_tree': 'a0e397f8519cb355a845b95dc3efcd26d4cba1ab', 'merge_commit': BASE,
            'terminal_check_id': PR266_C2, 'native_run': 44926955541,
            'native_attempt': 2, 'native_job': PR266_NATIVE_JOB}
MANIFEST = '1e5448c4a697fead65ce3d4cd0b4ae50a122e6d75b62321c23994cdc4cf6db5c'
ARCHIVE = {'bytes': 34707,
 'commit': '358c239e40cf92dd640e5a73be621ec28c472600',
 'path': 'formal-audit/pr267-e4832819-formal-inputs.zip',
 'sha256': '3526ed301ff7012b7c447cbbbe54503a309a0f84205509ba269a253a56fa949a'}
BLOBS = {'controller/plugin_protocol_image.go': 'b7481497163cc97f6ed9850f0de7d2cf404d16c4',
 'controller/relay.go': '1fd993d685a66efca63dfd3e4b5036b950e21e38',
 'controller/relay_error_log_test.go': 'f2ccb5d4e599afd6c8416625a03feb6e4ce01bea',
 'controller/task.go': '6eb3d87d5d47fceba9f3baf53f287b8f6c0b1c65',
 'controller/video_proxy.go': 'cfe19021d9ec3dfcf45d79ea116d8f6bb77c65b8',
 'middleware/task_plugin.go': '38456a001f6f5917854bf6c09f1c30c2c716695e',
 'middleware/task_plugin_test.go': '7834834f1f6d177cd94321e767d8958f8b40417a',
 'pkg/jsplugin/engine.go': '0b6ad13a2db2df4b8cde693114f6b197ae50f82e',
 'pkg/jsplugin/engine_test.go': '5fcf93e5699111810a448e8aa8d1bbd01cb2552a',
 'relay/alpha_search_handler.go': '2f06827f2d2b58a7b71b9a0211c0e299ff0f3362',
 'relay/channel/jimeng/sign.go': 'fe4869400224dc69cf774af295b9e3e5149229bf',
 'relay/channel/openai/adaptor.go': '0c6eb8f3f349d27610fb472497b095920bdd70e1',
 'relay/channel/openai/audio_test.go': '0c92d6d01175b7e99bbb8fdee0348875a2a07179',
 'relay/channel/task/jsplugin/adaptor.go': 'c197177c8f0f2e1ea6f8d28c3427f3b8fc87f5f5',
 'relay/claude_handler.go': '7d0242c9bf5474a2e650e994896796d6c7777927',
 'relay/common/override.go': 'a6ec2d03827c8f5428a04ede5fbe8a611fc1749e',
 'relay/common/override_test.go': 'eaf474b7e7deee76acf68eff35eff19b72be6f86',
 'relay/compatible_handler.go': 'a96501fb03018a46b217c25f2951557cdf7c4d40',
 'relay/convert_request_error_test.go': '4cbbe74f31d2a02b4199bc2dfb95bf6a4ae0fd89',
 'relay/embedding_handler.go': 'f9239d451d73030c89e0eb36299e19877c040b2d',
 'relay/gemini_handler.go': 'e31b8edfa876ca2caef1db53bf583efcde72d6ae',
 'relay/image_handler.go': '694c8edbab35a5364f98b227e66a995b7d1b5b0b',
 'relay/mjproxy_handler.go': 'f52a40e30e50dd492431ff82c39cc9b10de12358',
 'relay/rerank_handler.go': '9d06ae05ee001ae0e9301b1233a6e948ae2ecaee',
 'relay/responses_request.go': '3d84af0c20372a5be1c28cafbdd37741016452ee',
 'service/download.go': '30535648a2ddd3499f760667fd4d1d6d22bb35e5',
 'service/error.go': '75eb48067798c31f4a01559f1d832c920b7c7240',
 'service/file_decoder.go': 'd96ae5065d54b855b457e1b7d46723c7a512201e',
 'service/file_service.go': '5049c4cd5144d7bc79072867f9105afa5d18ca47',
 'service/image.go': '0b800c94283b6efe7a8bf3e0e419a21926d7477b',
 'service/midjourney.go': '3285169dbd0013e3cf8ecae5338a5a86f63d3949',
 'service/protected_fetch_client_test.go': '738631adb4378e9d7194f461da59ae26a31ac89a',
 'service/task_polling.go': 'b065b31803fb9cf2427b596d9c020df64bb8595a',
 'service/task_polling_test.go': '4d7a9c7822e9b65770acc496ede6edd9f52d197a'}
MEMBERS = {'candidate.patch': 'b4bf2d998d53cdf0b031311d86b4dd4e1a458f16809cee813e448fcaa9540484',
 'targeted-review.json': '42e85e9efc8c5ecbd6c15ebaf2da97dd67927fc9dd9c77eb9eb3b62bc86053dd',
 'targeted-review.jsonl': '8bc307dea7d47f5567266e3566aa53ab89540b534982d86f37e4626787cf63fe',
 'targeted.json': '518169e9e9f4d455b89b903614a96f920eed9d4eb26441a9006ad99e25b77f85',
 'targeted.jsonl': 'b2c676092738925d4364fcc1186fc031d4bfbcb5c5ee598ce8dc6e13a6ef2c9e',
 'validation.json': 'd5313e2d65483f0b4c967fe717ed2309bad13b62a3da6be22729b933019d29ba',
 'verification.json': '566b2efe909e1a79abab82f67004cc29682e85fcaa39bfc47caa913901d8e102'}
FILES = tuple(BLOBS)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=True).encode('ascii')


def descriptor():
    return ARCHIVE.copy()


def consumer_intent(artifact, control, nonce):
    if (canonical(artifact) != canonical(ARCHIVE) or not re.fullmatch('[a-f0-9]{40}', control) or
            control == R15 or not re.fullmatch('[a-f0-9]{32}', nonce)):
        raise ValueError('invalid request and task-plugin log delta selection')
    bound = {'artifact': artifact, 'baseline': BASELINE, 'tree': TREE, 'head': HEAD,
             'hosted': HOSTED, 'control': control, 'nonce': nonce}
    return sha256(canonical(bound)).hexdigest()


def make_reference(artifact, control, consumer_run, opened, nonce):
    consumer_intent(artifact, control, nonce)
    if type(consumer_run) is not int or consumer_run <= 0 or type(opened) is not int or opened <= 0:
        raise ValueError('invalid request and task-plugin log delta approval times')
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
        raise ValueError('invalid or expired request and task-plugin log delta reference')


def validate_package(policy, raw):
    require = policy.require
    decode = policy.consumer.evidence.decode
    require(type(raw) is bytes and len(raw) == ARCHIVE['bytes'] and sha256(raw).hexdigest() == ARCHIVE['sha256'],
            'wrong immutable request and task-plugin log evidence')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(sorted(archive.namelist()) == sorted((*MEMBERS, 'manifest.json')), 'incorrect request and task-plugin log artifact inventory')
        manifest = archive.read('manifest.json')
        require(sha256(manifest).hexdigest() == MANIFEST and
                {name: sha256(archive.read(name)).hexdigest() for name in MEMBERS} == MEMBERS,
                'unreviewed request and task-plugin log evidence member')
        result = decode(archive.read('validation.json'))
    data = decode(manifest)
    require((data['kind'], data['pull'], data['head'], data['tree'], data['base'], data['paths']) ==
            ('pr267-request-plugin-logs/v1', PR, HEAD, TREE, BASE, list(FILES)) and
            data['hosted'] == HOSTED and data['blobs'] == BLOBS and
            data['baseline_terminal'] == PR266_C2 and data['members'] == MEMBERS, 'wrong request and task-plugin log evidence subjects')
    require((result['candidate'], result['tree'], result['round_trees'], result['review'], result['runner']) ==
            (HEAD, TREE, list(ROUND_TREES), 'ACCEPT_SCOPED', 'go1.26.10 linux/amd64'),
            'wrong reviewed validation subjects')
    rounds = result['round_leaves']
    reused, final = ({tuple(row) for row in items} for items in rounds)
    retested = {tuple(row) for row in result['excluded']}
    require([len(items) for items in rounds] == [36, 20] and (len(reused), len(final)) == (36, 20) and
            len(reused | final) == 56 and len(retested) == 10 and retested <= final and retested.isdisjoint(reused),
            'incomplete request and task-plugin log regression evidence')



def current_subject(policy, reader, identity):
    base = reader.repository()
    pr = reader.pull(PR)
    repo_id = identity['repository_id']
    policy.require(base['id'] == repo_id and base['full_name'] == policy.REPOSITORY and
                   pr['number'] == PR and pr['state'] == 'open' and pr['merged'] is False and pr['draft'] is False and pr['changed_files'] == len(FILES) and
                   pr['head']['repo']['id'] == pr['base']['repo']['id'] == repo_id and
                   pr['head']['repo']['full_name'] == pr['base']['repo']['full_name'] == policy.REPOSITORY and
                   pr['head']['sha'] == HEAD and pr['head']['ref'] == BRANCH and
                   pr['base']['sha'] == BASE and pr['base']['ref'] == 'main', 'current request and task-plugin log PR subject changed')
    commit = reader.commit(HEAD)
    policy.require(commit['sha'] == HEAD and commit['tree']['sha'] == TREE and
                   [row['sha'] for row in commit['parents']] == [BASE], 'wrong request and task-plugin log candidate tree or parents')
    policy.verify_hosted_jobs(reader, HOSTED, identity)


def historical_baseline(policy, reader, fetch=None):
    previous = policy.independent_stream_delta
    evidence = policy.consumer.evidence
    older = previous.historical_baseline(policy, reader, fetch)
    check = reader.check(PR266_C2)
    proof = evidence.decode(check['output']['text'])
    policy.require(check['id'] == PR266_C2 and policy.consumer.digest(proof) == PR266_PROOF and
                   (proof['candidate_sha'], proof['candidate_tree'], proof['consumer_run'], proof['terminal_run']) ==
                   (BASELINE['candidate_sha'], BASELINE['candidate_tree'], PR266_A, PR266_B),
                   'wrong signed PR266 baseline')
    signed = evidence.github_time(check, 'completed_at')
    policy.validate_gate(check, proof, completed=True)
    ref = proof['artifact']
    previous.validate_reference(ref, signed)
    policy.require(ref['identity']['consumer_sha'] == R15 and
                   policy.consumer.canonical(proof) == policy.consumer.canonical(previous.result(ref, PR266_B, older)),
                   'signed PR266 evidence differs from reviewed contract')
    done = previous.verify_approvals(policy, reader, ref, PR266_B, signed)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'PR266 signature predates its reviews')
    prior_run = reader.run(previous.HOSTED['run_id'], previous.HOSTED['attempt'])
    repo_id = ref['identity']['repository_id']
    policy.require(prior_run['id'] == previous.HOSTED['run_id'] and
                   prior_run['run_attempt'] == previous.HOSTED['attempt'] and
                   prior_run['workflow_id'] == policy.CI_WORKFLOW_ID and prior_run['path'] == '.github/workflows/ci.yml' and
                   prior_run['event'] == 'pull_request' and prior_run['head_sha'] == previous.HEAD and
                   prior_run['repository']['id'] == prior_run['head_repository']['id'] == repo_id and
                   reader.hosted_workflow_blob(previous.HEAD) == previous.HOSTED['workflow_blob'],
                   'historical PR266 hosted run or workflow blob changed')
    policy.verify_hosted_job_steps(reader, previous.HOSTED, previous.HEAD)
    if fetch is not None:
        previous.validate_package(policy, fetch(ref['artifact']['commit']))
    pr = reader.pull(266)
    merged = reader.commit(BASE)
    policy.require(pr['number'] == 266 and pr['state'] == 'closed' and pr['merged'] is True and
                   pr['merge_commit_sha'] == BASE and pr['head']['sha'] == BASELINE['candidate_sha'] and
                   pr['base']['ref'] == 'main' and pr['base']['repo']['id'] == repo_id and
                   merged['sha'] == BASE and merged['tree']['sha'] == BASELINE['candidate_tree'] and
                   [row['sha'] for row in merged['parents']] == [previous.BASE, previous.HEAD], 'wrong historical PR266 merge')
    run = reader.run(BASELINE['native_run'], 2)
    policy.require(run['id'] == BASELINE['native_run'] and run['run_attempt'] == 2 and
                   run['head_sha'] == BASELINE['candidate_sha'] and
                   run['repository']['id'] == run['head_repository']['id'] == repo_id and
                   run['path'] == '.github/workflows/ci.yml' and run['event'] == 'pull_request' and
                   run['workflow_id'] == policy.CI_WORKFLOW_ID and
                   run['status'] == 'completed' and run['conclusion'] == 'success', 'historical PR266 native gate did not pass')
    gate = policy.successful_job(reader.jobs(BASELINE['native_run'], 2), policy.GATE, BASELINE['candidate_sha'],
                                 ('Verify hosted jobs and authenticated exact-candidate quality',))
    policy.require(gate['id'] == PR266_NATIVE_JOB and gate['run_id'] == BASELINE['native_run'] and gate['run_attempt'] == 2 and
                   signed <= evidence.github_time(gate, 'started_at') <= evidence.github_time(gate, 'completed_at') <=
                   evidence.github_time(pr, 'merged_at') <= ref['identity']['release_expires_at'],
                   'PR266 native green and merge outside historical publication')
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
        policy.require(type(terminal_run) is int and terminal_run != consumer_run, 'separate request and task-plugin log terminal required')
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
            'release_expires_at': identity['release_expires_at'], 'admission_id': 'pr267-request-plugin-delta-' + HEAD,
            'invocation': consumer_intent(reference['artifact'], identity['consumer_sha'], reference['nonce'])}


def verify(policy, reference, reader, fetch, terminal_run, now, *, active=False, staged_at=None):
    validate_reference(reference, now)
    policy.require(callable(fetch) and (active or terminal_run is not None), 'both reviewed request and task-plugin log jobs required')
    done = verify_approvals(policy, reader, reference, terminal_run, now, active=active)
    if staged_at is not None:
        policy.require(done is not None and done <= staged_at <= now, 'request and task-plugin log result staged before terminal completion')
    proof = historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    current_subject(policy, reader, reference['identity'])
    request = result(reference, terminal_run, proof)
    if terminal_run is None:
        request['schema'] = 'box-quality-request-plugin-consumer/v16'
    return request


def prescreen(policy, artifact, reader, fetch):
    policy.require(canonical(artifact) == canonical(ARCHIVE) and callable(fetch), 'wrong request and task-plugin log preflight artifact')
    current_subject(policy, reader, {'repository_id': 1423238398, 'head_repository_id': 1423238398, 'pull_number': PR,
                                    'base_sha': BASE, 'candidate_sha': HEAD})
    historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    return {'candidate_sha': HEAD, 'candidate_tree': TREE, 'baseline': BASELINE, 'hosted': HOSTED, 'artifact': artifact}


def private_fetch(policy, token):
    old_fetch = policy.independent_stream_delta.private_fetch(policy, token)
    evidence = policy.consumer.evidence

    def fetch(commit):
        if commit != ARCHIVE['commit']:
            return old_fetch(commit)
        path = '/repos/' + evidence.EVIDENCE_REPOSITORY
        repo = policy.consumer.api(path, token)
        policy.require(repo['id'] == evidence.EVIDENCE_REPOSITORY_ID and
                       repo['full_name'] == evidence.EVIDENCE_REPOSITORY and repo['private'] is True,
                       'wrong private request and task-plugin log evidence repository')
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
                   environment['GITHUB_SHA'] == environment['GITHUB_WORKFLOW_SHA'] == trusted, 'wrong native request and task-plugin log dispatch')
    reference = evidence.decode(environment['BOX_FORMAL_ADMISSION'])
    run = int(environment['GITHUB_RUN_ID'])
    validate_reference(reference, int(clock()))
    policy.require(trusted == reference['identity']['consumer_sha'] and (run != reference['consumer_run']) == terminal,
                   'wrong protected request and task-plugin log run')
    if terminal:
        for field, key in [('BOX_FORMAL_HOSTED_RUN_ID', 'run_id'), ('BOX_FORMAL_HOSTED_RUN_ATTEMPT', 'attempt'),
                           ('BOX_FORMAL_HOSTED_CI_BLOB', 'workflow_blob')]:
            policy.require(environment[field] == str(HOSTED[key]), 'wrong request and task-plugin log hosted run pin')
    token = environment['BOX_FORMAL_EVIDENCE_TOKEN']
    policy.require(token and token != environment['GITHUB_TOKEN'], 'dedicated private evidence reader required')
    checked = verify(policy, reference, policy.GitHubReader(environment['GITHUB_TOKEN']), private_fetch(policy, token),
                     run if terminal else None, int(clock()), active=True)
    validate_reference(reference, int(clock()))
    return checked


def verify_public(policy, environment, reader, *, clock):
    event = policy.ci_premerge_event(environment)
    policy.require(environment['GITHUB_EVENT_NAME'] == 'pull_request' and environment['GITHUB_RUN_ID'] == str(HOSTED['run_id'])
                   and event['number'] == PR and event['pull_request']['head']['sha'] == HEAD, 'wrong native request and task-plugin log gate')
    check = reader.formal_quality_check(HEAD)
    request = policy.consumer.evidence.decode(check['output']['text'])
    now = int(clock())
    reference = request['artifact']
    validate_reference(reference, now)
    policy.validate_ci_evidence_reference(event, environment, reference['identity'])
    policy.validate_gate(check, request, completed=True)
    proof = historical_baseline(policy, reader)
    terminal = request['terminal_run']
    policy.require(type(terminal) is int and check['id'] not in (C1, PR266_C2) and
                   policy.consumer.canonical(request) == policy.consumer.canonical(result(reference, terminal, proof)),
                   'request and task-plugin log result differs from exact scope and subjects')
    done = verify_approvals(policy, reader, reference, terminal, now)
    evidence = policy.consumer.evidence
    evidence.check_times(check, reference['identity'], now)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'request and task-plugin log signature predates second approval')
    current_subject(policy, reader, reference['identity'])
    policy.resolve_ci_candidate(environment, reader)
    validate_reference(reference, int(clock()))
    return request
