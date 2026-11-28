"""Formal evidence reuse for PR #280 organization wallet sync settlement."""
from hashlib import sha256
import io
import json
import re
import urllib.request
import zipfile


PR = 280
HEAD = '03ea9f438f0657c2645da16185d860aa25281f71'
TREE = '2e9ad057fd3c196b897210aa142b0b3e91f4d548'
BASE = '190bd25171eafb5968cd7e2a6bae90663e114b38'
BRANCH = 'codex/issue10-organization-wallet-sync'
CONTROL_REF = 'refs/heads/codex/formal-quality-r30'
REFERENCE_SCHEMA = 'box-formal-organization-wallet-sync-delta-ref/v30'
TERMINAL_SCHEMA = 'box-quality-terminal/v30'
SCOPE = 'organization-wallet-sync'
C1 = 135232975120
PR279_C2 = 140939316610
PR279_PROOF = 'f039e5218e393f5e61b9f99a45c8992f240068a8f6edf6e7ca1b26acb6014f7b'
PR279_A = 46130666659
PR279_B = 46131334371
PR279_NATIVE_JOB = 140939817336
R29 = 'd554448c18c691c78101ad15453defb38d31bf96'
HOSTED = {'attempt': 1, 'run_id': 46135533594, 'workflow_blob': 'c123990e4a8c9fd981b721455a8edbc65b62dfc5'}
NATIVE_MERGE = 'f6e6e44e59330539a9f2f35598551be6b50193a3'
BASELINE = {'pull_number': 279, 'candidate_sha': 'd8d3b53ae01f91830aeb83fc9bb64c39d80042a3', 'candidate_tree': 'fa1502d6fb514941995002b91ed086722c663eb6', 'merge_commit': '190bd25171eafb5968cd7e2a6bae90663e114b38', 'terminal_check_id': 140939316610, 'native_run': 46128531140, 'native_attempt': 2, 'native_job': 140939817336}
MANIFEST = '521d83b8d9cc53281076499c8ffa258216dd7caec854fbc657d776a9c9901cff'
ARCHIVE = {'commit': '2e4afd2e85d80dcbf65d46e57d355d21e505c7ce', 'path': 'preparation/pr280-03ea9f4-organization-wallet-sync-r30.zip', 'bytes': 17011, 'sha256': '31aaf10a1c8d9c55ed00a3a02c363947b821e828c5895b6d203e8c6d9a7a29c1'}
BLOBS = {'controller/organization_wallet_sync.go': 'af4eacb981da81707d22666486c2d9f540739f8a', 'model/main.go': 'c5f8b29bb0d3642f46e173afc7d5db32544c411d', 'model/organization_charge.go': '742d9c4b6cf0f2b60c47ace94c9c1c057ddc2669', 'router/organization_wallet_sync_test.go': '9ebd8e978767dbf47ee7e2737274b4ba5b6e9b7e', 'service/organization_wallet_sync.go': 'e932ac222afd85f75e1ebee80bb144e438ee4ccc'}
MEMBERS = {'build-corrected.log': '4c1f222d55c94fa8122c869d2a59770431cb69037e75967bba082659b47744fb', 'build-germany.sh': '2e03d63f2a23f09e92cb61aa60b8d29bd4b050f1250076aad91bf4240b6fa3d4', 'candidate-files.sha256': '843ae9623a8d1e02ca604730598ed23ddce0d294901ddab15d2c5f89e573bf81', 'candidate.patch': 'ececf1e748ffb617f1d909253cac8a9b27483abf133444fc14750a1110e725b5', 'cleanup.log': 'c26212d263a8bcc283bc08a00aac760b10ceef9999f97c9b48638b2bc3550185', 'migrate-germany.sh': 'f46c311ab87fe466236566327402250825ea0eb608b5c325c3be663a85c6ced0', 'migrate.log': '35d2ee04d7180e48432177e8b92a385f8537f7da6bf2b4e100e38ee26c781e57', 'receipt.json': 'c28a395099ba418062f5a117f6d99b0f2b9edab42dcf4b9bbf2156eaafb719a6', 'run-germany.sh': 'f2522290daa615c995662b930de5c355ab7fcc1d60938b0e07861e5364b4b154', 'test-corrected.log': 'b8b66bcce4dba5911e33c9baa333e6229dcfa66ea6e25349f8796b673971c5e6'}
FILES = tuple(BLOBS)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=True).encode('ascii')


def descriptor():
    return ARCHIVE.copy()


def consumer_intent(artifact, control, nonce):
    if (canonical(artifact) != canonical(ARCHIVE) or not re.fullmatch('[a-f0-9]{40}', control) or
            control == R29 or not re.fullmatch('[a-f0-9]{32}', nonce)):
        raise ValueError('invalid organization wallet sync delta selection')
    bound = {'artifact': artifact, 'baseline': BASELINE, 'tree': TREE, 'head': HEAD,
             'hosted': HOSTED, 'control': control, 'nonce': nonce}
    return sha256(canonical(bound)).hexdigest()


def make_reference(artifact, control, consumer_run, opened, nonce):
    consumer_intent(artifact, control, nonce)
    if type(consumer_run) is not int or consumer_run <= 0 or type(opened) is not int or opened <= 0:
        raise ValueError('invalid organization wallet sync delta approval times')
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
        raise ValueError('invalid or expired organization wallet sync delta reference')


def validate_package(policy, raw):
    require = policy.require
    decode = policy.consumer.evidence.decode
    require(type(raw) is bytes and len(raw) == ARCHIVE['bytes'] and sha256(raw).hexdigest() == ARCHIVE['sha256'],
            'wrong immutable organization wallet sync archive')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(sorted(archive.namelist()) == sorted((*MEMBERS, 'manifest.json')),
                'incorrect organization wallet sync inventory')
        manifest = archive.read('manifest.json')
        require(sha256(manifest).hexdigest() == MANIFEST and
                {name: sha256(archive.read(name)).hexdigest() for name in MEMBERS} == MEMBERS,
                'unreviewed organization wallet sync member')
        data = decode(manifest)
        require(data == dict(kind='pr280-organization-wallet-sync/v1', pull=PR, head=HEAD, tree=TREE,
                             base=BASE, paths=list(FILES), hosted=HOSTED, blobs=BLOBS,
                             baseline_terminal=PR279_C2, members=MEMBERS),
                'wrong organization wallet sync evidence subjects')
        receipt = decode(archive.read('receipt.json'))
        require(receipt == {'baseline': '190bd25171eafb5968cd7e2a6bae90663e114b38', 'baseline_terminal': 140939316610, 'candidate_tree': '2e9ad057fd3c196b897210aa142b0b3e91f4d548', 'cases_per_database': 4, 'evidence': {'build-corrected.log': '4c1f222d55c94fa8122c869d2a59770431cb69037e75967bba082659b47744fb', 'build-germany.sh': '2e03d63f2a23f09e92cb61aa60b8d29bd4b050f1250076aad91bf4240b6fa3d4', 'candidate-files.sha256': '843ae9623a8d1e02ca604730598ed23ddce0d294901ddab15d2c5f89e573bf81', 'cleanup.log': 'c26212d263a8bcc283bc08a00aac760b10ceef9999f97c9b48638b2bc3550185', 'migrate-germany.sh': 'f46c311ab87fe466236566327402250825ea0eb608b5c325c3be663a85c6ced0', 'migrate.log': '35d2ee04d7180e48432177e8b92a385f8537f7da6bf2b4e100e38ee26c781e57', 'run-germany.sh': 'f2522290daa615c995662b930de5c355ab7fcc1d60938b0e07861e5364b4b154', 'test-corrected.log': 'b8b66bcce4dba5911e33c9baa333e6229dcfa66ea6e25349f8796b673971c5e6'}, 'executed_nine_layers': False, 'head': '03ea9f438f0657c2645da16185d860aa25281f71', 'image': 'sha256:cbb4c521e8474dfa0821952892b4a5474684801ec3b8166df8fedd116ad24add', 'independent_review': 'ACCEPT_SCOPED', 'migration_starts': 12, 'patch': 'ececf1e748ffb617f1d909253cac8a9b27483abf133444fc14750a1110e725b5', 'scope': ['organization wallet sync', 'durable payment binding', 'atomic reserve', 'idempotent settlement and refund'], 'tested': ['SQLite 3.50.4', 'PostgreSQL 15.20', 'MySQL 8.0.46'], 'upgrade_release': 'v1.0.0-rc.52'}, 'wrong reviewed candidate receipt')
        require(receipt['head'] == HEAD and receipt['baseline'] == BASE and receipt['candidate_tree'] == TREE and
                receipt['patch'] == MEMBERS['candidate.patch'] and
                all(MEMBERS[name] == digest for name, digest in receipt['evidence'].items()),
                'wrong candidate evidence match')



def current_subject(policy, reader, identity):
    base = reader.repository()
    pr = reader.pull(PR)
    repo_id = identity['repository_id']
    policy.require(base['id'] == repo_id and base['full_name'] == policy.REPOSITORY and
                   pr['number'] == PR and pr['state'] == 'open' and pr['merged'] is False and pr['draft'] is False and pr['changed_files'] == len(FILES) and
                   pr['head']['repo']['id'] == pr['base']['repo']['id'] == repo_id and
                   pr['head']['repo']['full_name'] == pr['base']['repo']['full_name'] == policy.REPOSITORY and
                   pr['head']['sha'] == HEAD and pr['head']['ref'] == BRANCH and
                   pr['base']['sha'] == BASE and pr['base']['ref'] == 'main', 'current organization wallet sync PR subject changed')
    commit = reader.commit(HEAD)
    policy.require(commit['sha'] == HEAD and commit['tree']['sha'] == TREE and
                   [row['sha'] for row in commit['parents']] == [BASE], 'wrong organization wallet sync candidate tree or parents')
    policy.verify_hosted_jobs(reader, HOSTED, identity)


def historical_baseline(policy, reader, fetch=None):
    previous = policy.organization_views_delta
    evidence = policy.consumer.evidence
    older = previous.historical_baseline(policy, reader, fetch)
    check = reader.check(PR279_C2)
    proof = evidence.decode(check['output']['text'])
    policy.require(check['id'] == PR279_C2 and policy.consumer.digest(proof) == PR279_PROOF and
                   (proof['candidate_sha'], proof['candidate_tree'], proof['consumer_run'], proof['terminal_run']) ==
                   (BASELINE['candidate_sha'], BASELINE['candidate_tree'], PR279_A, PR279_B),
                   'wrong signed PR279 baseline')
    signed = evidence.github_time(check, 'completed_at')
    policy.validate_gate(check, proof, completed=True)
    ref = proof['artifact']
    previous.validate_reference(ref, signed)
    policy.require(ref['identity']['consumer_sha'] == R29 and
                   policy.consumer.canonical(proof) == policy.consumer.canonical(previous.result(ref, PR279_B, older)),
                   'signed PR279 evidence differs from reviewed contract')
    done = previous.verify_approvals(policy, reader, ref, PR279_B, signed)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'PR279 signature predates its reviews')
    prior_run = reader.run(previous.HOSTED['run_id'], previous.HOSTED['attempt'])
    repo_id = ref['identity']['repository_id']
    policy.require(prior_run['id'] == previous.HOSTED['run_id'] and
                   prior_run['run_attempt'] == previous.HOSTED['attempt'] and
                   prior_run['workflow_id'] == policy.CI_WORKFLOW_ID and prior_run['path'] == '.github/workflows/ci.yml' and
                   prior_run['event'] == 'pull_request' and prior_run['head_sha'] == previous.HEAD and
                   prior_run['repository']['id'] == prior_run['head_repository']['id'] == repo_id and
                   reader.hosted_workflow_blob(previous.HEAD) == previous.HOSTED['workflow_blob'],
                   'historical PR279 hosted run or workflow blob changed')
    policy.verify_hosted_job_steps(reader, previous.HOSTED, previous.HEAD)
    if fetch is not None:
        previous.validate_package(policy, fetch(ref['artifact']['commit']))
    pr = reader.pull(279)
    merged = reader.commit(BASE)
    policy.require(pr['number'] == 279 and pr['state'] == 'closed' and pr['merged'] is True and
                   pr['merge_commit_sha'] == BASE and pr['head']['sha'] == BASELINE['candidate_sha'] and
                   pr['base']['ref'] == 'main' and pr['base']['repo']['id'] == repo_id and
                   merged['sha'] == BASE and merged['tree']['sha'] == BASELINE['candidate_tree'] and
                   [row['sha'] for row in merged['parents']] == [previous.BASE, previous.HEAD], 'wrong historical PR279 merge')
    run = reader.run(BASELINE['native_run'], BASELINE['native_attempt'])
    policy.require(run['id'] == BASELINE['native_run'] and run['run_attempt'] == BASELINE['native_attempt'] and
                   run['head_sha'] == BASELINE['candidate_sha'] and
                   run['repository']['id'] == run['head_repository']['id'] == repo_id and
                   run['path'] == '.github/workflows/ci.yml' and run['event'] == 'pull_request' and
                   run['workflow_id'] == policy.CI_WORKFLOW_ID and
                   run['status'] == 'completed' and run['conclusion'] == 'success', 'historical PR279 native gate did not pass')
    gate = policy.successful_job(reader.jobs(BASELINE['native_run'], BASELINE['native_attempt']), policy.GATE, BASELINE['candidate_sha'],
                                 ('Verify hosted jobs and authenticated exact-candidate quality',))
    policy.require(gate['id'] == PR279_NATIVE_JOB and gate['run_id'] == BASELINE['native_run'] and gate['run_attempt'] == BASELINE['native_attempt'] and
                   signed <= evidence.github_time(gate, 'started_at') <= evidence.github_time(gate, 'completed_at') <=
                   evidence.github_time(pr, 'merged_at') <= ref['identity']['release_expires_at'],
                   'PR279 native green and merge outside historical publication')
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
        policy.require(type(terminal_run) is int and terminal_run != consumer_run, 'separate organization wallet sync terminal required')
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
            'release_expires_at': identity['release_expires_at'], 'admission_id': 'pr280-organization-wallet-sync-' + HEAD,
            'invocation': consumer_intent(reference['artifact'], identity['consumer_sha'], reference['nonce'])}


def verify(policy, reference, reader, fetch, terminal_run, now, *, active=False, staged_at=None):
    validate_reference(reference, now)
    policy.require(callable(fetch) and (active or terminal_run is not None), 'both reviewed organization wallet sync jobs required')
    done = verify_approvals(policy, reader, reference, terminal_run, now, active=active)
    if staged_at is not None:
        policy.require(done is not None and done <= staged_at <= now, 'organization wallet sync result staged before terminal completion')
    proof = historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    current_subject(policy, reader, reference['identity'])
    request = result(reference, terminal_run, proof)
    if terminal_run is None:
        request['schema'] = 'box-quality-organization-wallet-sync-consumer/v30'
    return request


def prescreen(policy, artifact, reader, fetch):
    policy.require(canonical(artifact) == canonical(ARCHIVE) and callable(fetch), 'wrong organization wallet sync preflight artifact')
    current_subject(policy, reader, {'repository_id': 1423238398, 'head_repository_id': 1423238398, 'pull_number': PR,
                                    'base_sha': BASE, 'candidate_sha': HEAD})
    historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    return {'candidate_sha': HEAD, 'candidate_tree': TREE, 'baseline': BASELINE, 'hosted': HOSTED, 'artifact': artifact}


def private_fetch(policy, token):
    old_fetch = policy.organization_views_delta.private_fetch(policy, token)
    evidence = policy.consumer.evidence

    def fetch(commit):
        if commit != ARCHIVE['commit']:
            return old_fetch(commit)
        path = '/repos/' + evidence.EVIDENCE_REPOSITORY
        repo = policy.consumer.api(path, token)
        policy.require(repo['id'] == evidence.EVIDENCE_REPOSITORY_ID and
                       repo['full_name'] == evidence.EVIDENCE_REPOSITORY and repo['private'] is True,
                       'wrong private organization wallet sync evidence repository')
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
                   environment['GITHUB_SHA'] == environment['GITHUB_WORKFLOW_SHA'] == trusted, 'wrong native organization wallet sync dispatch')
    reference = evidence.decode(environment['BOX_FORMAL_ADMISSION'])
    run = int(environment['GITHUB_RUN_ID'])
    validate_reference(reference, int(clock()))
    policy.require(trusted == reference['identity']['consumer_sha'] and (run != reference['consumer_run']) == terminal,
                   'wrong protected organization wallet sync run')
    if terminal:
        for field, key in [('BOX_FORMAL_HOSTED_RUN_ID', 'run_id'), ('BOX_FORMAL_HOSTED_RUN_ATTEMPT', 'attempt'),
                           ('BOX_FORMAL_HOSTED_CI_BLOB', 'workflow_blob')]:
            policy.require(environment[field] == str(HOSTED[key]), 'wrong organization wallet sync hosted run pin')
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
    policy.reader_stage('r30_native_event')
    event = policy.ci_premerge_event(environment)
    policy.require(environment['GITHUB_EVENT_NAME'] == 'pull_request' and environment['GITHUB_RUN_ID'] == str(HOSTED['run_id'])
                   and event['number'] == PR and event['pull_request']['head']['sha'] == HEAD, 'wrong native organization wallet sync gate')
    policy.reader_stage('r30_c2_lookup')
    check = reader.formal_quality_check(HEAD)
    policy.reader_stage('r30_c2_decode')
    request = policy.consumer.evidence.decode(check['output']['text'])
    now = int(clock())
    reference = request['artifact']
    policy.reader_stage('r30_window')
    validate_reference(reference, now)
    policy.reader_stage('r30_native_merge_anchor')
    event = native_event_with_verified_base(policy, event, environment, reader)
    policy.reader_stage('r30_ci_binding')
    policy.validate_ci_evidence_reference(event, environment, reference['identity'])
    policy.reader_stage('r30_c2_authenticity')
    policy.validate_gate(check, request, completed=True)
    policy.reader_stage('r30_history')
    proof = historical_baseline(policy, reader)
    policy.reader_stage('r30_receipt_binding')
    terminal = request['terminal_run']
    policy.require(type(terminal) is int and check['id'] not in (C1, PR279_C2) and
                   policy.consumer.canonical(request) == policy.consumer.canonical(result(reference, terminal, proof)),
                   'organization wallet sync result differs from exact scope and subjects')
    policy.reader_stage('r30_approvals')
    done = verify_approvals(policy, reader, reference, terminal, now)
    policy.reader_stage('r30_publication_order')
    evidence = policy.consumer.evidence
    evidence.check_times(check, reference['identity'], now)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'organization wallet sync signature predates second approval')
    policy.reader_stage('r30_current_candidate')
    current_subject(policy, reader, reference['identity'])
    policy.reader_stage('r30_premerge_readback')
    policy._resolve_ci_candidate(event, environment, reader)
    policy.reader_stage('r30_final_window')
    validate_reference(reference, int(clock()))
    return request
