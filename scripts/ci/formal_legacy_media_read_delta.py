"""Formal evidence reuse for PR #276 legacy media eligibility and revocation reads."""
from hashlib import sha256
import io
import json
import re
import urllib.request
import zipfile


PR = 276
HEAD = '2c1867fcb1a7e6a688879f64b9844a4e81f88a08'
TREE = 'c5f3931c8c8bb5564f9901737405fd1d47837b86'
BASE = '6a5cd941fb1bc0396a8047bce9bf45615cc7cb6c'
BRANCH = 'codex/w04-legacy-media-read'
CONTROL_REF = 'refs/heads/codex/formal-quality-r25'
REFERENCE_SCHEMA = 'box-formal-legacy-media-read-delta-ref/v25'
TERMINAL_SCHEMA = 'box-quality-terminal/v25'
SCOPE = 'legacy-media-read'
C1 = 135232975120
PR275_C2 = 137372189235
PR275_PROOF = '53b17d65bd7814e311824824e23d9cc2dd9a8f092f2db0c079adb60c6b52003d'
PR275_A, PR275_B = 45073447304, 45075238610
PR275_NATIVE_JOB = 137372653671
R24 = '79ac81d44799994e88f9efaa555f525302c39ce0'
HOSTED = {'attempt': 1, 'run_id': 45495408496, 'workflow_blob': 'c123990e4a8c9fd981b721455a8edbc65b62dfc5'}
BASELINE = {'pull_number': 275, 'candidate_sha': '2c516f13a86d3c21207f8ec84ed36a7d04308f50',
            'candidate_tree': 'a931f6cd2b662b35812b353117b100a8094f4821', 'merge_commit': BASE, 'terminal_check_id': PR275_C2,
            'native_run': 45072315027, 'native_attempt': 2, 'native_job': PR275_NATIVE_JOB}
MANIFEST = 'fa4bc5ad22629ee400423673fd24df13f0d52be9c51cd52f93d6419bad1bb1bd'
ARCHIVE = {'commit': '51cf310f8118dad437d6d47bf4c336bf8bd1275e', 'path': 'formal-audit/pr276-2c1867fc-formal-inputs.zip', 'bytes': 16066, 'sha256': '04c941ff8cb8e6c07270c363c63351a5ddf3809716b7e29119f8c71bef07c18b'}
BLOBS = {'controller/task.go': 'fb87028523b99310b72c6536cbf6f4053e44e32b', 'controller/task_generic_test.go': 'f89ba07ba1b2c1633aaa763da4faecf3af116e77', 'model/legacy_media_read.go': '349c825882d9e4bd5d9c20d3a3416f58beb53bc9', 'model/legacy_media_snapshot.go': 'f54e057c5a1d7d40b7026a75b2e413bc4dc316da', 'model/legacy_media_snapshot_test.go': '67fbf43c8b6435f1d8f4f391ecada73bc5901e8d', 'model/main.go': '1f9ff65b0394fbdd6b3077df265c549c6b4f2a86', 'relay/mjproxy_handler.go': '6d6d015329f4b8a373ed4d59807864e571c53ae1', 'router/organization_access_test.go': 'c6719eea00e488608de490692b3e6b7dd3d04c00', 'router/organization_lifecycle_test.go': 'b893f5ab4186011bb31eaeadd450fd903c75e1f8', 'service/legacy_media_read.go': '041171adee0f4fe651e999869f9b87daa950581d'}
MEMBERS = {'candidate.patch': '9c9fadb0f6875b0618ad73db7f9fe143401248bb9819fbf2b1902846b9732556', 'receipt.json': '31116a24af255a752b98da0680f270698bd5e748f6ccdf1fe5248dbe386d7ecd', 'relay-bearer-fixture.go': '448bf7990053eb7faf21f615bdf2c44499e112f04365af59787c9c266ca1d7d6', 'relay-bearer-outcome.txt': '329f97168b1c1f25d9736d1d87e73b171ba96745ef2f43745663cb9c4563c729', 'relay-bearer.json': 'e36f4dacbd1e47af5326653b4ece1ff6fd85362116bf7475c571f7a12766d6ac'}
FILES = tuple(BLOBS)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=True).encode('ascii')


def descriptor():
    return ARCHIVE.copy()


def consumer_intent(artifact, control, nonce):
    if (canonical(artifact) != canonical(ARCHIVE) or not re.fullmatch('[a-f0-9]{40}', control) or
            control == R24 or not re.fullmatch('[a-f0-9]{32}', nonce)):
        raise ValueError('invalid legacy media read delta selection')
    bound = {'artifact': artifact, 'baseline': BASELINE, 'tree': TREE, 'head': HEAD,
             'hosted': HOSTED, 'control': control, 'nonce': nonce}
    return sha256(canonical(bound)).hexdigest()


def make_reference(artifact, control, consumer_run, opened, nonce):
    consumer_intent(artifact, control, nonce)
    if type(consumer_run) is not int or consumer_run <= 0 or type(opened) is not int or opened <= 0:
        raise ValueError('invalid legacy media read delta approval times')
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
        raise ValueError('invalid or expired legacy media read delta reference')


def validate_package(policy, raw):
    require = policy.require
    decode = policy.consumer.evidence.decode
    require(type(raw) is bytes and len(raw) == ARCHIVE['bytes'] and sha256(raw).hexdigest() == ARCHIVE['sha256'],
            'wrong immutable legacy media read archive')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(sorted(archive.namelist()) == sorted((*MEMBERS, 'manifest.json')),
                'incorrect legacy media read inventory')
        manifest = archive.read('manifest.json')
        require(sha256(manifest).hexdigest() == MANIFEST and
                {name: sha256(archive.read(name)).hexdigest() for name in MEMBERS} == MEMBERS,
                'unreviewed legacy media read member')
        data = decode(manifest)
        require(data == dict(kind='pr276-legacy-media-read/v1', pull=PR, head=HEAD, tree=TREE,
                             base=BASE, paths=list(FILES), hosted=HOSTED, blobs=BLOBS,
                             baseline_terminal=PR275_C2, members=MEMBERS),
                'wrong legacy media read evidence subjects')
        receipt = decode(archive.read('receipt.json'))
        require((receipt['baseline'], receipt['candidate_tree'], receipt['patch'], receipt['verdict'], receipt['engines']) ==
                (BASE, TREE, MEMBERS['candidate.patch'], 'ACCEPT_SCOPED', {'mysql': '8.0.46', 'postgres': '15.19', 'sqlite': '3.50.4'}),
                'wrong legacy media read receipt')
        require(receipt['outcomes'] == {'controller-final.jsonl': ['TestTaskArtifactAccessRequiresActiveOwner', 'TestTaskArtifactAccessRejectsAmbiguousHistoricalTaskID', 'compatibility_capability', 'authenticated_read_after_cutover', 'TestDisabledArtifactStorePreservesPluginUpstreamContent'], 'model-sqlite-r2.jsonl': ['shared_deadline'], 'router-affected-r2.jsonl': ['artifacts_and_capabilities_exclude_organization_rows', 'artifact_capability_never_authenticates_organization', 'task_lookup_dispatch_attempt_counter', 'completed_after_remove'], 'router-legacy-r2.jsonl': ['old_mj_and_v1_enforce_the_shared_policy']} and len(receipt['evidence']) == 11,
                'wrong scoped legacy media and database test inventory')
        relay = decode(archive.read('relay-bearer.json'))
        require((relay['pr'], relay['commit'], relay['base'], relay['tree'], relay['status'], relay['oauth_anchor'],
                 relay['origin_requests'], relay['cutover_fixture_only'], relay['teardown'], relay['fixture_sha256'],
                 relay['log_sha256'], relay['manifest_sha256']) ==
                (PR, HEAD, BASE, TREE, 206, True, 1, True, True, MEMBERS['relay-bearer-fixture.go'],
                 '3bc658de924fc722caeb264ad1b840ec69759dcdd665a1fc694725877836a613', '7140c27782c488b8b9dbdf2975d6e7720094f859675c48e6452a5175d33b68f5'),
                'wrong Relay Bearer HTTP proof')
        require(archive.read('relay-bearer-outcome.txt') ==
                b'W04_RELAY_BEARER_HTTP status=206 verified_anchor=true origin_requests=1 correct_live_range=true\n',
                'incomplete Relay Bearer HTTP proof')



def current_subject(policy, reader, identity):
    base = reader.repository()
    pr = reader.pull(PR)
    repo_id = identity['repository_id']
    policy.require(base['id'] == repo_id and base['full_name'] == policy.REPOSITORY and
                   pr['number'] == PR and pr['state'] == 'open' and pr['merged'] is False and pr['draft'] is False and pr['changed_files'] == len(FILES) and
                   pr['head']['repo']['id'] == pr['base']['repo']['id'] == repo_id and
                   pr['head']['repo']['full_name'] == pr['base']['repo']['full_name'] == policy.REPOSITORY and
                   pr['head']['sha'] == HEAD and pr['head']['ref'] == BRANCH and
                   pr['base']['sha'] == BASE and pr['base']['ref'] == 'main', 'current legacy media read PR subject changed')
    commit = reader.commit(HEAD)
    policy.require(commit['sha'] == HEAD and commit['tree']['sha'] == TREE and
                   [row['sha'] for row in commit['parents']] == [BASE], 'wrong legacy media read candidate tree or parents')
    policy.verify_hosted_jobs(reader, HOSTED, identity)


def historical_baseline(policy, reader, fetch=None):
    previous = policy.legacy_media_preparation_delta
    evidence = policy.consumer.evidence
    older = previous.historical_baseline(policy, reader, fetch)
    check = reader.check(PR275_C2)
    proof = evidence.decode(check['output']['text'])
    policy.require(check['id'] == PR275_C2 and policy.consumer.digest(proof) == PR275_PROOF and
                   (proof['candidate_sha'], proof['candidate_tree'], proof['consumer_run'], proof['terminal_run']) ==
                   (BASELINE['candidate_sha'], BASELINE['candidate_tree'], PR275_A, PR275_B),
                   'wrong signed PR275 baseline')
    signed = evidence.github_time(check, 'completed_at')
    policy.validate_gate(check, proof, completed=True)
    ref = proof['artifact']
    previous.validate_reference(ref, signed)
    policy.require(ref['identity']['consumer_sha'] == R24 and
                   policy.consumer.canonical(proof) == policy.consumer.canonical(previous.result(ref, PR275_B, older)),
                   'signed PR275 evidence differs from reviewed contract')
    done = previous.verify_approvals(policy, reader, ref, PR275_B, signed)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'PR275 signature predates its reviews')
    prior_run = reader.run(previous.HOSTED['run_id'], previous.HOSTED['attempt'])
    repo_id = ref['identity']['repository_id']
    policy.require(prior_run['id'] == previous.HOSTED['run_id'] and
                   prior_run['run_attempt'] == previous.HOSTED['attempt'] and
                   prior_run['workflow_id'] == policy.CI_WORKFLOW_ID and prior_run['path'] == '.github/workflows/ci.yml' and
                   prior_run['event'] == 'pull_request' and prior_run['head_sha'] == previous.HEAD and
                   prior_run['repository']['id'] == prior_run['head_repository']['id'] == repo_id and
                   reader.hosted_workflow_blob(previous.HEAD) == previous.HOSTED['workflow_blob'],
                   'historical PR275 hosted run or workflow blob changed')
    policy.verify_hosted_job_steps(reader, previous.HOSTED, previous.HEAD)
    if fetch is not None:
        previous.validate_package(policy, fetch(ref['artifact']['commit']))
    pr = reader.pull(275)
    merged = reader.commit(BASE)
    policy.require(pr['number'] == 275 and pr['state'] == 'closed' and pr['merged'] is True and
                   pr['merge_commit_sha'] == BASE and pr['head']['sha'] == BASELINE['candidate_sha'] and
                   pr['base']['ref'] == 'main' and pr['base']['repo']['id'] == repo_id and
                   merged['sha'] == BASE and merged['tree']['sha'] == BASELINE['candidate_tree'] and
                   [row['sha'] for row in merged['parents']] == [previous.BASE, previous.HEAD], 'wrong historical PR275 merge')
    run = reader.run(BASELINE['native_run'], 2)
    policy.require(run['id'] == BASELINE['native_run'] and run['run_attempt'] == 2 and
                   run['head_sha'] == BASELINE['candidate_sha'] and
                   run['repository']['id'] == run['head_repository']['id'] == repo_id and
                   run['path'] == '.github/workflows/ci.yml' and run['event'] == 'pull_request' and
                   run['workflow_id'] == policy.CI_WORKFLOW_ID and
                   run['status'] == 'completed' and run['conclusion'] == 'success', 'historical PR275 native gate did not pass')
    gate = policy.successful_job(reader.jobs(BASELINE['native_run'], 2), policy.GATE, BASELINE['candidate_sha'],
                                 ('Verify hosted jobs and authenticated exact-candidate quality',))
    policy.require(gate['id'] == PR275_NATIVE_JOB and gate['run_id'] == BASELINE['native_run'] and gate['run_attempt'] == 2 and
                   signed <= evidence.github_time(gate, 'started_at') <= evidence.github_time(gate, 'completed_at') <=
                   evidence.github_time(pr, 'merged_at') <= ref['identity']['release_expires_at'],
                   'PR275 native green and merge outside historical publication')
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
        policy.require(type(terminal_run) is int and terminal_run != consumer_run, 'separate legacy media read terminal required')
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
            'release_expires_at': identity['release_expires_at'], 'admission_id': 'pr276-legacy-media-read-' + HEAD,
            'invocation': consumer_intent(reference['artifact'], identity['consumer_sha'], reference['nonce'])}


def verify(policy, reference, reader, fetch, terminal_run, now, *, active=False, staged_at=None):
    validate_reference(reference, now)
    policy.require(callable(fetch) and (active or terminal_run is not None), 'both reviewed legacy media read jobs required')
    done = verify_approvals(policy, reader, reference, terminal_run, now, active=active)
    if staged_at is not None:
        policy.require(done is not None and done <= staged_at <= now, 'legacy media read result staged before terminal completion')
    proof = historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    current_subject(policy, reader, reference['identity'])
    request = result(reference, terminal_run, proof)
    if terminal_run is None:
        request['schema'] = 'box-quality-legacy-media-read-consumer/v25'
    return request


def prescreen(policy, artifact, reader, fetch):
    policy.require(canonical(artifact) == canonical(ARCHIVE) and callable(fetch), 'wrong legacy media read preflight artifact')
    current_subject(policy, reader, {'repository_id': 1423238398, 'head_repository_id': 1423238398, 'pull_number': PR,
                                    'base_sha': BASE, 'candidate_sha': HEAD})
    historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    return {'candidate_sha': HEAD, 'candidate_tree': TREE, 'baseline': BASELINE, 'hosted': HOSTED, 'artifact': artifact}


def private_fetch(policy, token):
    old_fetch = policy.legacy_media_preparation_delta.private_fetch(policy, token)
    evidence = policy.consumer.evidence

    def fetch(commit):
        if commit != ARCHIVE['commit']:
            return old_fetch(commit)
        path = '/repos/' + evidence.EVIDENCE_REPOSITORY
        repo = policy.consumer.api(path, token)
        policy.require(repo['id'] == evidence.EVIDENCE_REPOSITORY_ID and
                       repo['full_name'] == evidence.EVIDENCE_REPOSITORY and repo['private'] is True,
                       'wrong private legacy media read evidence repository')
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
                   environment['GITHUB_SHA'] == environment['GITHUB_WORKFLOW_SHA'] == trusted, 'wrong native legacy media read dispatch')
    reference = evidence.decode(environment['BOX_FORMAL_ADMISSION'])
    run = int(environment['GITHUB_RUN_ID'])
    validate_reference(reference, int(clock()))
    policy.require(trusted == reference['identity']['consumer_sha'] and (run != reference['consumer_run']) == terminal,
                   'wrong protected legacy media read run')
    if terminal:
        for field, key in [('BOX_FORMAL_HOSTED_RUN_ID', 'run_id'), ('BOX_FORMAL_HOSTED_RUN_ATTEMPT', 'attempt'),
                           ('BOX_FORMAL_HOSTED_CI_BLOB', 'workflow_blob')]:
            policy.require(environment[field] == str(HOSTED[key]), 'wrong legacy media read hosted run pin')
    token = environment['BOX_FORMAL_EVIDENCE_TOKEN']
    policy.require(token and token != environment['GITHUB_TOKEN'], 'dedicated private evidence reader required')
    checked = verify(policy, reference, policy.GitHubReader(environment['GITHUB_TOKEN']), private_fetch(policy, token),
                     run if terminal else None, int(clock()), active=True)
    validate_reference(reference, int(clock()))
    return checked


def verify_public(policy, environment, reader, *, clock):
    event = policy.ci_premerge_event(environment)
    policy.require(environment['GITHUB_EVENT_NAME'] == 'pull_request' and environment['GITHUB_RUN_ID'] == str(HOSTED['run_id'])
                   and event['number'] == PR and event['pull_request']['head']['sha'] == HEAD, 'wrong native legacy media read gate')
    check = reader.formal_quality_check(HEAD)
    request = policy.consumer.evidence.decode(check['output']['text'])
    now = int(clock())
    reference = request['artifact']
    validate_reference(reference, now)
    policy.validate_ci_evidence_reference(event, environment, reference['identity'])
    policy.validate_gate(check, request, completed=True)
    proof = historical_baseline(policy, reader)
    terminal = request['terminal_run']
    policy.require(type(terminal) is int and check['id'] not in (C1, PR275_C2) and
                   policy.consumer.canonical(request) == policy.consumer.canonical(result(reference, terminal, proof)),
                   'legacy media read result differs from exact scope and subjects')
    done = verify_approvals(policy, reader, reference, terminal, now)
    evidence = policy.consumer.evidence
    evidence.check_times(check, reference['identity'], now)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'legacy media read signature predates second approval')
    current_subject(policy, reader, reference['identity'])
    policy.resolve_ci_candidate(environment, reader)
    validate_reference(reference, int(clock()))
    return request
