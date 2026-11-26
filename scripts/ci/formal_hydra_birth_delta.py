"""Formal evidence reuse for PR #255 Hydra birth integration."""
from hashlib import sha256
import io
import json
import re
import urllib.request
import zipfile


PR = 255
HEAD = 'd8df02228774d46a3a360f8b94f66ade3839dd14'
TREE = 'ad683d43b23808a2cd7e24a793e8dba5a6c5240c'
BASE = '838c4a4c623faabd9e42022be8d2d0b8391b742c'
FIXTURE_PARENT = '2fbecfce4f1dc95aaadd0d770475c3341115739a'
BRANCH = 'cursor/oauth-hydra-birth-058f'
CONTROL_REF = 'refs/heads/codex/formal-quality-r27'
REFERENCE_SCHEMA = 'box-formal-hydra-birth-delta-ref/v27'
TERMINAL_SCHEMA = 'box-quality-terminal/v27'
SCOPE = 'hydra-birth'
C1 = 135232975120
PR277_C2 = 139415772844
PR277_PROOF = 'ee77cb912cf07745af2d4ceb89afdb7a0281f9ee3d9bcf0b14cb56df8668bdf2'
PR277_A, PR277_B = 45671837790, 45672499128
PR277_NATIVE_JOB = 139416811406
R26 = '2b71c2c266348a521e44b438c5c8e9309170ac34'
HOSTED = {'attempt': 1, 'run_id': 45708355860, 'workflow_blob': 'c123990e4a8c9fd981b721455a8edbc65b62dfc5'}
NATIVE_MERGE = '286b0b9bee489f9c168b95f565a215cead2eee9a'
BASELINE = {'pull_number': 277, 'candidate_sha': '81cf5f19d7287b8576961982c9c560a844c5cd49', 'candidate_tree': '45012a9a841c166de310bf2bb9f45d9b5c870d73', 'merge_commit': '838c4a4c623faabd9e42022be8d2d0b8391b742c', 'terminal_check_id': 139415772844, 'native_run': 45506805073, 'native_attempt': 2, 'native_job': 139416811406}
MANIFEST = 'ed626e81fccba3584506f6ef3329b2686bcb909f11660266404b3487d7101c74'
ARCHIVE = {'commit': '06c8483ee16be1f691b9fbd6c1282fdf608e20d4', 'path': 'eligibility/pr255-d8df0222-hydra-birth.zip', 'bytes': 22984, 'sha256': '3232150be4c7553c18ea8971f53cc206870fa427faff024ef799c1d5f6c52dc0'}
BLOBS = {'router/oauth_public_test.go': '6737891f92543a14d3bda8116aeabef5a08994a0', 'scripts/ci/bootstrap_test_runner.py': '128fe4fe83808e4ab6633212b3b6de4c6d281724', 'scripts/ci/hydra_birth_security_test.py': 'c9c76377b679cbf9b024f02b2b7ed5e0e0bf032e', 'service/oauth_resource.go': '56cc303057592d7904825e627716663a66e01485'}
MEMBERS = {'candidate.patch': '3c2039f7fb727bab6d7c0af2ff0b6def66299c22c235f5788bef9315a1c5303a', 'hydra-birth-result.json': 'e1c5abb0682f33fb5c1567f72dbd8e93114fe1636fd5be97dd7efd9d04d21627', 'hydra-cookie-probe.log': '889d1e1206ce716269a9b10151b69b02332307615e36ca053005938ec7f312ab', 'issuer-ca-result.json': 'f5f5507bad9cd031dfc27e8a8849c4a16c60eef28ec0cc6279bf3d07748c0aaf', 'receipt.json': 'fb2d6dd78905693aa54a5915551a11c2d5abbea890be62d4289e0b6a6bcb6999'}
FILES = tuple(BLOBS)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=True).encode('ascii')


def descriptor():
    return ARCHIVE.copy()


def consumer_intent(artifact, control, nonce):
    if (canonical(artifact) != canonical(ARCHIVE) or not re.fullmatch('[a-f0-9]{40}', control) or
            control == R26 or not re.fullmatch('[a-f0-9]{32}', nonce)):
        raise ValueError('invalid Hydra birth delta selection')
    bound = {'artifact': artifact, 'baseline': BASELINE, 'tree': TREE, 'head': HEAD,
             'hosted': HOSTED, 'control': control, 'nonce': nonce}
    return sha256(canonical(bound)).hexdigest()


def make_reference(artifact, control, consumer_run, opened, nonce):
    consumer_intent(artifact, control, nonce)
    if type(consumer_run) is not int or consumer_run <= 0 or type(opened) is not int or opened <= 0:
        raise ValueError('invalid Hydra birth delta approval times')
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
        raise ValueError('invalid or expired Hydra birth delta reference')


def validate_package(policy, raw):
    require = policy.require
    decode = policy.consumer.evidence.decode
    require(type(raw) is bytes and len(raw) == ARCHIVE['bytes'] and sha256(raw).hexdigest() == ARCHIVE['sha256'],
            'wrong immutable Hydra birth archive')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(sorted(archive.namelist()) == sorted((*MEMBERS, 'manifest.json')),
                'incorrect Hydra birth inventory')
        manifest = archive.read('manifest.json')
        require(sha256(manifest).hexdigest() == MANIFEST and
                {name: sha256(archive.read(name)).hexdigest() for name in MEMBERS} == MEMBERS,
                'unreviewed Hydra birth member')
        data = decode(manifest)
        require(data == dict(kind='pr255-hydra-birth/v1', pull=PR, head=HEAD, tree=TREE,
                             base=BASE, paths=list(FILES), hosted=HOSTED, blobs=BLOBS,
                             baseline_terminal=PR277_C2, members=MEMBERS),
                'wrong Hydra birth evidence subjects')
        receipt = decode(archive.read('receipt.json'))
        require(receipt == {'baseline': '838c4a4c623faabd9e42022be8d2d0b8391b742c', 'candidate_tree': 'ad683d43b23808a2cd7e24a793e8dba5a6c5240c', 'comparison': {'hydra-birth': 'candidate isolated v26.2.0 runtime result', 'ordinary-sqlite/router': 'candidate targeted TLS result added to historical scope', 'other_historical_scopes': 'baseline signed result retains original identity'}, 'evidence': {'hydra-birth-result.json': 'e1c5abb0682f33fb5c1567f72dbd8e93114fe1636fd5be97dd7efd9d04d21627', 'hydra-cookie-probe.log': '889d1e1206ce716269a9b10151b69b02332307615e36ca053005938ec7f312ab', 'issuer-ca-result.json': 'f5f5507bad9cd031dfc27e8a8849c4a16c60eef28ec0cc6279bf3d07748c0aaf'}, 'head': 'd8df02228774d46a3a360f8b94f66ade3839dd14', 'independent_review': {'identity': 'hydra_review', 'result': 'accepted four-file scope and candidate evidence', 'tracked_blob_count': 2851}, 'patch': '3c2039f7fb727bab6d7c0af2ff0b6def66299c22c235f5788bef9315a1c5303a'}, 'wrong reviewed Hydra birth receipt')
        require(receipt['head'] == HEAD and receipt['baseline'] == BASE and receipt['candidate_tree'] == TREE and
                receipt['patch'] == MEMBERS['candidate.patch'] and
                all(MEMBERS[name] == digest for name, digest in receipt['evidence'].items()),
                'wrong Hydra birth subjects or evidence')



def current_subject(policy, reader, identity):
    base = reader.repository()
    pr = reader.pull(PR)
    repo_id = identity['repository_id']
    policy.require(base['id'] == repo_id and base['full_name'] == policy.REPOSITORY and
                   pr['number'] == PR and pr['state'] == 'open' and pr['merged'] is False and pr['draft'] is False and pr['changed_files'] == len(FILES) and
                   pr['head']['repo']['id'] == pr['base']['repo']['id'] == repo_id and
                   pr['head']['repo']['full_name'] == pr['base']['repo']['full_name'] == policy.REPOSITORY and
                   pr['head']['sha'] == HEAD and pr['head']['ref'] == BRANCH and
                   pr['base']['sha'] == BASE and pr['base']['ref'] == 'main', 'current Hydra birth PR subject changed')
    commit = reader.commit(HEAD)
    policy.require(commit['sha'] == HEAD and commit['tree']['sha'] == TREE and
                   [row['sha'] for row in commit['parents']] == [BASE, FIXTURE_PARENT], 'wrong Hydra birth candidate tree or parents')
    policy.verify_hosted_jobs(reader, HOSTED, identity)


def historical_baseline(policy, reader, fetch=None):
    previous = policy.legacy_owner_revocation_delta
    evidence = policy.consumer.evidence
    older = previous.historical_baseline(policy, reader, fetch)
    check = reader.check(PR277_C2)
    proof = evidence.decode(check['output']['text'])
    policy.require(check['id'] == PR277_C2 and policy.consumer.digest(proof) == PR277_PROOF and
                   (proof['candidate_sha'], proof['candidate_tree'], proof['consumer_run'], proof['terminal_run']) ==
                   (BASELINE['candidate_sha'], BASELINE['candidate_tree'], PR277_A, PR277_B),
                   'wrong signed PR277 baseline')
    signed = evidence.github_time(check, 'completed_at')
    policy.validate_gate(check, proof, completed=True)
    ref = proof['artifact']
    previous.validate_reference(ref, signed)
    policy.require(ref['identity']['consumer_sha'] == R26 and
                   policy.consumer.canonical(proof) == policy.consumer.canonical(previous.result(ref, PR277_B, older)),
                   'signed PR277 evidence differs from reviewed contract')
    done = previous.verify_approvals(policy, reader, ref, PR277_B, signed)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'PR277 signature predates its reviews')
    prior_run = reader.run(previous.HOSTED['run_id'], previous.HOSTED['attempt'])
    repo_id = ref['identity']['repository_id']
    policy.require(prior_run['id'] == previous.HOSTED['run_id'] and
                   prior_run['run_attempt'] == previous.HOSTED['attempt'] and
                   prior_run['workflow_id'] == policy.CI_WORKFLOW_ID and prior_run['path'] == '.github/workflows/ci.yml' and
                   prior_run['event'] == 'pull_request' and prior_run['head_sha'] == previous.HEAD and
                   prior_run['repository']['id'] == prior_run['head_repository']['id'] == repo_id and
                   reader.hosted_workflow_blob(previous.HEAD) == previous.HOSTED['workflow_blob'],
                   'historical PR277 hosted run or workflow blob changed')
    policy.verify_hosted_job_steps(reader, previous.HOSTED, previous.HEAD)
    if fetch is not None:
        previous.validate_package(policy, fetch(ref['artifact']['commit']))
    pr = reader.pull(277)
    merged = reader.commit(BASE)
    policy.require(pr['number'] == 277 and pr['state'] == 'closed' and pr['merged'] is True and
                   pr['merge_commit_sha'] == BASE and pr['head']['sha'] == BASELINE['candidate_sha'] and
                   pr['base']['ref'] == 'main' and pr['base']['repo']['id'] == repo_id and
                   merged['sha'] == BASE and merged['tree']['sha'] == BASELINE['candidate_tree'] and
                   [row['sha'] for row in merged['parents']] == [previous.BASE, previous.HEAD], 'wrong historical PR277 merge')
    run = reader.run(BASELINE['native_run'], 2)
    policy.require(run['id'] == BASELINE['native_run'] and run['run_attempt'] == 2 and
                   run['head_sha'] == BASELINE['candidate_sha'] and
                   run['repository']['id'] == run['head_repository']['id'] == repo_id and
                   run['path'] == '.github/workflows/ci.yml' and run['event'] == 'pull_request' and
                   run['workflow_id'] == policy.CI_WORKFLOW_ID and
                   run['status'] == 'completed' and run['conclusion'] == 'success', 'historical PR277 native gate did not pass')
    gate = policy.successful_job(reader.jobs(BASELINE['native_run'], 2), policy.GATE, BASELINE['candidate_sha'],
                                 ('Verify hosted jobs and authenticated exact-candidate quality',))
    policy.require(gate['id'] == PR277_NATIVE_JOB and gate['run_id'] == BASELINE['native_run'] and gate['run_attempt'] == 2 and
                   signed <= evidence.github_time(gate, 'started_at') <= evidence.github_time(gate, 'completed_at') <=
                   evidence.github_time(pr, 'merged_at') <= ref['identity']['release_expires_at'],
                   'PR277 native green and merge outside historical publication')
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
        policy.require(type(terminal_run) is int and terminal_run != consumer_run, 'separate Hydra birth terminal required')
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
            'release_expires_at': identity['release_expires_at'], 'admission_id': 'pr255-hydra-birth-' + HEAD,
            'invocation': consumer_intent(reference['artifact'], identity['consumer_sha'], reference['nonce'])}


def verify(policy, reference, reader, fetch, terminal_run, now, *, active=False, staged_at=None):
    validate_reference(reference, now)
    policy.require(callable(fetch) and (active or terminal_run is not None), 'both reviewed Hydra birth jobs required')
    done = verify_approvals(policy, reader, reference, terminal_run, now, active=active)
    if staged_at is not None:
        policy.require(done is not None and done <= staged_at <= now, 'Hydra birth result staged before terminal completion')
    proof = historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    current_subject(policy, reader, reference['identity'])
    request = result(reference, terminal_run, proof)
    if terminal_run is None:
        request['schema'] = 'box-quality-hydra-birth-consumer/v27'
    return request


def prescreen(policy, artifact, reader, fetch):
    policy.require(canonical(artifact) == canonical(ARCHIVE) and callable(fetch), 'wrong Hydra birth preflight artifact')
    current_subject(policy, reader, {'repository_id': 1423238398, 'head_repository_id': 1423238398, 'pull_number': PR,
                                    'base_sha': BASE, 'candidate_sha': HEAD})
    historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    return {'candidate_sha': HEAD, 'candidate_tree': TREE, 'baseline': BASELINE, 'hosted': HOSTED, 'artifact': artifact}


def private_fetch(policy, token):
    old_fetch = policy.legacy_owner_revocation_delta.private_fetch(policy, token)
    evidence = policy.consumer.evidence

    def fetch(commit):
        if commit != ARCHIVE['commit']:
            return old_fetch(commit)
        path = '/repos/' + evidence.EVIDENCE_REPOSITORY
        repo = policy.consumer.api(path, token)
        policy.require(repo['id'] == evidence.EVIDENCE_REPOSITORY_ID and
                       repo['full_name'] == evidence.EVIDENCE_REPOSITORY and repo['private'] is True,
                       'wrong private Hydra birth evidence repository')
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
                   environment['GITHUB_SHA'] == environment['GITHUB_WORKFLOW_SHA'] == trusted, 'wrong native Hydra birth dispatch')
    reference = evidence.decode(environment['BOX_FORMAL_ADMISSION'])
    run = int(environment['GITHUB_RUN_ID'])
    validate_reference(reference, int(clock()))
    policy.require(trusted == reference['identity']['consumer_sha'] and (run != reference['consumer_run']) == terminal,
                   'wrong protected Hydra birth run')
    if terminal:
        for field, key in [('BOX_FORMAL_HOSTED_RUN_ID', 'run_id'), ('BOX_FORMAL_HOSTED_RUN_ATTEMPT', 'attempt'),
                           ('BOX_FORMAL_HOSTED_CI_BLOB', 'workflow_blob')]:
            policy.require(environment[field] == str(HOSTED[key]), 'wrong Hydra birth hosted run pin')
    token = environment['BOX_FORMAL_EVIDENCE_TOKEN']
    policy.require(token and token != environment['GITHUB_TOKEN'], 'dedicated private evidence reader required')
    checked = verify(policy, reference, policy.GitHubReader(environment['GITHUB_TOKEN']), private_fetch(policy, token),
                     run if terminal else None, int(clock()), active=True)
    validate_reference(reference, int(clock()))
    return checked


def native_event_with_verified_base(policy, event, environment, reader):
    pull = event['pull_request']
    if pull['base']['sha'] == BASE:
        return event

    # A rerun can carry a stale base in its event payload. The exact merge
    # commit from the original hosted run binds both inputs and the tested tree.
    attempt = environment.get('GITHUB_RUN_ATTEMPT', '')
    policy.require(re.fullmatch('[1-9][0-9]?', attempt) is not None and int(attempt) > 1 and
                   environment.get('GITHUB_SHA') == NATIVE_MERGE and
                   environment['GITHUB_RUN_ID'] == str(HOSTED['run_id']),
                   'wrong native rerun merge identity')
    merge = reader.commit(NATIVE_MERGE)
    policy.require(merge['sha'] == NATIVE_MERGE and merge['tree']['sha'] == TREE and
                   [parent['sha'] for parent in merge['parents']] == [BASE, HEAD],
                   'wrong native rerun merge parents or tree')
    return dict(event, pull_request=dict(pull, base=dict(pull['base'], sha=BASE)))


def verify_public(policy, environment, reader, *, clock):
    policy.reader_stage('r27_native_event')
    event = policy.ci_premerge_event(environment)
    policy.require(environment['GITHUB_EVENT_NAME'] == 'pull_request' and environment['GITHUB_RUN_ID'] == str(HOSTED['run_id'])
                   and event['number'] == PR and event['pull_request']['head']['sha'] == HEAD, 'wrong native Hydra birth gate')
    policy.reader_stage('r27_c2_lookup')
    check = reader.formal_quality_check(HEAD)
    policy.reader_stage('r27_c2_decode')
    request = policy.consumer.evidence.decode(check['output']['text'])
    now = int(clock())
    reference = request['artifact']
    policy.reader_stage('r27_window')
    validate_reference(reference, now)
    policy.reader_stage('r27_native_merge_anchor')
    event = native_event_with_verified_base(policy, event, environment, reader)
    policy.reader_stage('r27_ci_binding')
    policy.validate_ci_evidence_reference(event, environment, reference['identity'])
    policy.reader_stage('r27_c2_authenticity')
    policy.validate_gate(check, request, completed=True)
    policy.reader_stage('r27_history')
    proof = historical_baseline(policy, reader)
    policy.reader_stage('r27_receipt_binding')
    terminal = request['terminal_run']
    policy.require(type(terminal) is int and check['id'] not in (C1, PR277_C2) and
                   policy.consumer.canonical(request) == policy.consumer.canonical(result(reference, terminal, proof)),
                   'Hydra birth result differs from exact scope and subjects')
    policy.reader_stage('r27_approvals')
    done = verify_approvals(policy, reader, reference, terminal, now)
    policy.reader_stage('r27_publication_order')
    evidence = policy.consumer.evidence
    evidence.check_times(check, reference['identity'], now)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'Hydra birth signature predates second approval')
    policy.reader_stage('r27_current_candidate')
    current_subject(policy, reader, reference['identity'])
    policy.reader_stage('r27_premerge_readback')
    policy._resolve_ci_candidate(event, environment, reader)
    policy.reader_stage('r27_final_window')
    validate_reference(reference, int(clock()))
    return request
