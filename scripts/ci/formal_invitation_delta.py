"""Formal evidence reuse for PR #257 organization invitation UI."""
from hashlib import sha256
import io
import json
import re
import urllib.request
import zipfile


PR = 257
HEAD = '9eaf75cf963199f0d71612e0a89eceb783fb4f8c'
TREE = '050741c77f9fd83c83dc44d2dd2572a31e4c211b'
BASE = '064910ccf779caf9ce55723149fa7a8b372761b8'
PRIOR_HEAD = 'a060132ee2172720abfc143205f900ab52238b8d'
BRANCH = 'codex/t60u-issue11-invitation-decline'
CONTROL_REF = 'refs/heads/codex/formal-quality-r9'
REFERENCE_SCHEMA = 'box-formal-invitation-delta-ref/v9'
TERMINAL_SCHEMA = 'box-quality-terminal/v9'
SCOPE = 'organization-invitation-ui-delta'
C1 = 135232975120
PR256_C2 = 136121943994
PR256_PROOF = '7cc84a8db123206a6dbfb69792e6dfe2b0de2e0dfa01faeaa3d803525ff8c7e8'
PR256_A, PR256_B = 44685316327, 44685830312
PR256_NATIVE_JOB = 136122566869
R8 = 'dd1fed694a7450885c0937fe77a34cd9ab56ca6c'
HOSTED = {'run_id': 44686942049, 'attempt': 1,
          'workflow_blob': 'c123990e4a8c9fd981b721455a8edbc65b62dfc5'}
BASELINE = {'pull_number': 256, 'candidate_sha': 'b42fe14873936479e5322ccb58bd79c2b4d9acdc',
            'candidate_tree': '4a5347ec7407d10c6792d15b15abe39d3481abf2', 'merge_commit': BASE,
            'terminal_check_id': PR256_C2, 'native_run': 44679225544,
            'native_attempt': 2, 'native_job': PR256_NATIVE_JOB}
ARCHIVE = {'commit': 'c86fa4c5780252a8f27aed06d3a385da5aea88dc',
           'path': 'formal-audit/pr257-9eaf75cf-formal-inputs.zip',
           'bytes': 38074, 'sha256': '876b4e22eb8914f87b8f046ca9133e95268c3af952751f79d87391ce8f214bb5'}
MANIFEST = '7cd5d10a77d532bc75a1615ad6a836ffe7414f06879c4e62ccb5de953fba404b'
PATCH = 'b76542e11be7ada24955dd18da4f70cff651221d91275655a3c5078148f84a02'
PREPARATION = '9470ade4cb0e91e2432bfac5a7e058472ed9e445de4cf3344d6895a288814186'
SQLITE_TREE = 'f576a219755115f8341347da034cc98159146678'
SQLITE_RECEIPT = '878114b8321bc4520a7aade9af1c25400a119b6cfa72939146ee4947ba2d558c'
INVITATION_PROJECTION = 'd21c29198a6bc2edf03f72b9fe1d534f55065709b4ea98f06765eb99fb53ee40'
FILES = (
    'web/src/features/organizations/__tests__/organization-invitation-slots.test.tsx',
    'web/src/features/organizations/__tests__/organization-invitations.test.tsx',
    'web/src/features/organizations/api.ts',
    'web/src/features/organizations/organization-details-dialog.tsx',
    'web/src/features/organizations/organization-invitation-slots-card.tsx',
    'web/src/features/organizations/organization-invitations-card.tsx',
    'web/src/features/organizations/use-accept-invitation.ts',
    'web/src/features/organizations/use-decline-invitation.ts',
    'web/src/features/organizations/use-revoke-invitation.ts',
    'web/src/i18n/locales/en.json',
    'web/src/i18n/locales/fr.json',
    'web/src/i18n/locales/ja.json',
    'web/src/i18n/locales/ru.json',
    'web/src/i18n/locales/vi.json',
    'web/src/i18n/locales/zh-TW.json',
    'web/src/i18n/locales/zh.json',
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=True).encode('ascii')


def descriptor():
    return ARCHIVE.copy()


def consumer_intent(artifact, control, nonce):
    if (canonical(artifact) != canonical(ARCHIVE) or not re.fullmatch('[a-f0-9]{40}', control) or
            control == R8 or not re.fullmatch('[a-f0-9]{32}', nonce)):
        raise ValueError('invalid invitation delta selection')
    bound = {'artifact': artifact, 'baseline': BASELINE, 'tree': TREE, 'head': HEAD,
             'hosted': HOSTED, 'control': control, 'nonce': nonce}
    return sha256(canonical(bound)).hexdigest()


def make_reference(artifact, control, consumer_run, opened, nonce):
    consumer_intent(artifact, control, nonce)
    if type(consumer_run) is not int or consumer_run <= 0 or type(opened) is not int or opened <= 0:
        raise ValueError('invalid invitation delta approval times')
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
        raise ValueError('invalid or expired invitation delta reference')


def validate_package(policy, raw):
    require = policy.require
    decode = policy.consumer.evidence.decode
    require(type(raw) is bytes and len(raw) == ARCHIVE['bytes'] and sha256(raw).hexdigest() == ARCHIVE['sha256'],
            'wrong immutable invitation evidence')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(sorted(archive.namelist()) == ['manifest.json', 'reviewed-preparation.zip', 'scope.patch'],
                'incorrect invitation artifact inventory')
        manifest = archive.read('manifest.json')
        preparation = archive.read('reviewed-preparation.zip')
        require(sha256(manifest).hexdigest() == MANIFEST and sha256(archive.read('scope.patch')).hexdigest() == PATCH and
                sha256(preparation).hexdigest() == PREPARATION, 'unreviewed invitation evidence member')
    data = decode(manifest)
    require((data['kind'], data['head'], data['tree'], data['main'], data['prior_head'], data['paths']) ==
            ('pr257-bound-inputs-before-human-approval', HEAD, TREE, BASE, PRIOR_HEAD, list(FILES)) and
            (data['hosted_run'], data['attempt'], data['workflow_blob']) ==
            (HOSTED['run_id'], HOSTED['attempt'], HOSTED['workflow_blob']) and
            data['patch_sha256'] == PATCH and data['prior_preparation_sha256'] == PREPARATION and
            data['historical_256']['signed_payload_sha256'] == PR256_PROOF, 'wrong invitation evidence subjects')
    with zipfile.ZipFile(io.BytesIO(preparation)) as archive:
        require(sorted(archive.namelist()) == ['pr257-frontend-review-source.json', 'pr257-preparation.json',
                                              'pr257-sqlite.json', 'pr261-historical-proof.json'],
                'incorrect reviewed invitation preparation inventory')
        prepared = decode(archive.read('pr257-preparation.json'))
        receipt_bytes = archive.read('pr257-sqlite.json')
    changes = prepared['changes']
    condition = prepared['conditional_256']
    projection = condition['organization_invitation_openapi_projection']
    require([change['path'] for change in changes] == list(FILES) and
            all(change['reviewed'] == change['trial'] for change in changes) and
            condition['combined_tree_if_seven_file_patch_is_unchanged'] == TREE and
            projection['sha256'] == INVITATION_PROJECTION and
            (projection['components'], len(projection['paths'])) == (39, 7), 'invitation preparation scope changed')
    receipt = decode(receipt_bytes)
    sqlite = prepared['sqlite']
    require(sha256(receipt_bytes).hexdigest() == sqlite['receipt_sha256'] == SQLITE_RECEIPT and
            receipt['tree'] == prepared['reviewed_sqlite_tree'] == SQLITE_TREE and
            type(receipt['exit']) is int and receipt['exit'] == 0 and
            type(receipt['cleanup_exit']) is int and receipt['cleanup_exit'] == 0 and
            (sqlite['passing_nested_count'], sqlite['passing_root_count'], sqlite['skip_count']) == (43, 2, 0),
            'invitation SQLite evidence did not pass')


def current_subject(policy, reader, identity):
    base = reader.repository()
    pr = reader.pull(PR)
    repo_id = identity['repository_id']
    policy.require(base['id'] == repo_id and base['full_name'] == policy.REPOSITORY and
                   pr['number'] == PR and pr['state'] == 'open' and pr['merged'] is False and pr['changed_files'] == 16 and
                   pr['head']['repo']['id'] == pr['base']['repo']['id'] == repo_id and
                   pr['head']['repo']['full_name'] == pr['base']['repo']['full_name'] == policy.REPOSITORY and
                   pr['head']['sha'] == HEAD and pr['head']['ref'] == BRANCH and
                   pr['base']['sha'] == BASE and pr['base']['ref'] == 'main', 'current invitation PR subject changed')
    commit = reader.commit(HEAD)
    policy.require(commit['sha'] == HEAD and commit['tree']['sha'] == TREE and
                   [row['sha'] for row in commit['parents']] == [PRIOR_HEAD, BASE], 'wrong invitation candidate tree or parents')
    policy.verify_hosted_jobs(reader, HOSTED, identity)


def historical_baseline(policy, reader, fetch=None):
    previous = policy.usage_delta
    evidence = policy.consumer.evidence
    proof261 = previous.historical_baseline(policy, reader, fetch)
    check = reader.check(PR256_C2)
    proof = evidence.decode(check['output']['text'])
    policy.require(check['id'] == PR256_C2 and policy.consumer.digest(proof) == PR256_PROOF and
                   (proof['candidate_sha'], proof['candidate_tree'], proof['consumer_run'], proof['terminal_run']) ==
                   (BASELINE['candidate_sha'], BASELINE['candidate_tree'], PR256_A, PR256_B), 'wrong signed PR256 baseline')
    signed = evidence.github_time(check, 'completed_at')
    policy.validate_gate(check, proof, completed=True)
    ref = proof['artifact']
    previous.validate_reference(ref, signed)
    policy.require(ref['identity']['consumer_sha'] == R8 and
                   policy.consumer.canonical(proof) == policy.consumer.canonical(previous.result(ref, PR256_B, proof261)),
                   'signed PR256 evidence differs from reviewed contract')
    done = previous.verify_approvals(policy, reader, ref, PR256_B, signed)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'PR256 signature predates its reviews')
    # GitHub can drop pull_requests on historical Actions runs after source branch deletion.
    # The exact signed v8 proof already bound all four jobs before merge; authenticate
    # the original workflow definition and the observed final GitHub job below.
    original = reader.run(previous.HOSTED['run_id'], previous.HOSTED['attempt'])
    repo_id = ref['identity']['repository_id']
    policy.require(original['id'] == previous.HOSTED['run_id'] and original['run_attempt'] == previous.HOSTED['attempt'] and
                   original['workflow_id'] == policy.CI_WORKFLOW_ID and original['path'] == '.github/workflows/ci.yml' and
                   original['event'] == 'pull_request' and original['head_sha'] == previous.HEAD and
                   original['repository']['id'] == original['head_repository']['id'] == repo_id and
                   reader.hosted_workflow_blob(previous.HEAD) == previous.HOSTED['workflow_blob'],
                   'historical PR256 hosted run or workflow blob changed')
    policy.verify_hosted_job_steps(reader, previous.HOSTED, previous.HEAD)
    if fetch is not None:
        previous.validate_package(policy, fetch(ref['artifact']['commit']))
    pr = reader.pull(256)
    merged = reader.commit(BASE)
    policy.require(pr['number'] == 256 and pr['state'] == 'closed' and pr['merged'] is True and
                   pr['merge_commit_sha'] == BASE and pr['head']['sha'] == BASELINE['candidate_sha'] and
                   pr['base']['ref'] == 'main' and pr['base']['repo']['id'] == repo_id and
                   merged['sha'] == BASE and merged['tree']['sha'] == BASELINE['candidate_tree'] and
                   [row['sha'] for row in merged['parents']] == [previous.BASE, previous.HEAD], 'wrong historical PR256 merge')
    run = reader.run(BASELINE['native_run'], 2)
    policy.require(run['id'] == BASELINE['native_run'] and run['run_attempt'] == 2 and
                   run['head_sha'] == BASELINE['candidate_sha'] and
                   run['repository']['id'] == run['head_repository']['id'] == repo_id and
                   run['path'] == '.github/workflows/ci.yml' and run['event'] == 'pull_request' and run['workflow_id'] == policy.CI_WORKFLOW_ID and
                   run['status'] == 'completed' and run['conclusion'] == 'success', 'historical PR256 native gate did not pass')
    gate = policy.successful_job(reader.jobs(BASELINE['native_run'], 2), policy.GATE, BASELINE['candidate_sha'],
                                 ('Verify hosted jobs and authenticated exact-candidate quality',))
    policy.require(gate['id'] == PR256_NATIVE_JOB and gate['run_id'] == BASELINE['native_run'] and gate['run_attempt'] == 2 and
                   signed <= evidence.github_time(gate, 'started_at') <= evidence.github_time(gate, 'completed_at') <=
                   evidence.github_time(pr, 'merged_at') <= ref['identity']['release_expires_at'],
                   'PR256 native green and merge outside historical publication')
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
        policy.require(type(terminal_run) is int and terminal_run != consumer_run, 'separate invitation terminal required')
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
            'release_expires_at': identity['release_expires_at'], 'admission_id': 'pr257-invitation-delta-' + HEAD,
            'invocation': consumer_intent(reference['artifact'], identity['consumer_sha'], reference['nonce'])}


def verify(policy, reference, reader, fetch, terminal_run, now, *, active=False, staged_at=None):
    validate_reference(reference, now)
    policy.require(callable(fetch) and (active or terminal_run is not None), 'both reviewed invitation jobs required')
    done = verify_approvals(policy, reader, reference, terminal_run, now, active=active)
    if staged_at is not None:
        policy.require(done is not None and done <= staged_at <= now, 'invitation result staged before terminal completion')
    proof = historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    current_subject(policy, reader, reference['identity'])
    request = result(reference, terminal_run, proof)
    if terminal_run is None:
        request['schema'] = 'box-quality-invitation-consumer/v9'
    return request


def prescreen(policy, artifact, reader, fetch):
    policy.require(canonical(artifact) == canonical(ARCHIVE) and callable(fetch), 'wrong invitation preflight artifact')
    current_subject(policy, reader, {'repository_id': 1423238398, 'head_repository_id': 1423238398, 'pull_number': PR,
                                    'base_sha': BASE, 'candidate_sha': HEAD})
    historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    return {'candidate_sha': HEAD, 'candidate_tree': TREE, 'baseline': BASELINE, 'hosted': HOSTED, 'artifact': artifact}


def private_fetch(policy, token):
    old_fetch = policy.usage_delta.private_fetch(policy, token)
    evidence = policy.consumer.evidence

    def fetch(commit):
        if commit != ARCHIVE['commit']:
            return old_fetch(commit)
        path = '/repos/' + evidence.EVIDENCE_REPOSITORY
        repo = policy.consumer.api(path, token)
        policy.require(repo['id'] == evidence.EVIDENCE_REPOSITORY_ID and
                       repo['full_name'] == evidence.EVIDENCE_REPOSITORY and repo['private'] is True,
                       'wrong private invitation evidence repository')
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
                   environment['GITHUB_SHA'] == environment['GITHUB_WORKFLOW_SHA'] == trusted, 'wrong native invitation dispatch')
    reference = evidence.decode(environment['BOX_FORMAL_ADMISSION'])
    run = int(environment['GITHUB_RUN_ID'])
    validate_reference(reference, int(clock()))
    policy.require(trusted == reference['identity']['consumer_sha'] and (run != reference['consumer_run']) == terminal,
                   'wrong protected invitation run')
    if terminal:
        for field, key in [('BOX_FORMAL_HOSTED_RUN_ID', 'run_id'), ('BOX_FORMAL_HOSTED_RUN_ATTEMPT', 'attempt'),
                           ('BOX_FORMAL_HOSTED_CI_BLOB', 'workflow_blob')]:
            policy.require(environment[field] == str(HOSTED[key]), 'wrong invitation hosted run pin')
    token = environment['BOX_FORMAL_EVIDENCE_TOKEN']
    policy.require(token and token != environment['GITHUB_TOKEN'], 'dedicated private evidence reader required')
    checked = verify(policy, reference, policy.GitHubReader(environment['GITHUB_TOKEN']), private_fetch(policy, token),
                     run if terminal else None, int(clock()), active=True)
    validate_reference(reference, int(clock()))
    return checked


def verify_public(policy, environment, reader, *, clock):
    event = policy.ci_premerge_event(environment)
    policy.require(environment['GITHUB_EVENT_NAME'] == 'pull_request' and environment['GITHUB_RUN_ID'] == str(HOSTED['run_id'])
                   and event['number'] == PR and event['pull_request']['head']['sha'] == HEAD, 'wrong native invitation gate')
    check = reader.formal_quality_check(HEAD)
    request = policy.consumer.evidence.decode(check['output']['text'])
    now = int(clock())
    reference = request['artifact']
    validate_reference(reference, now)
    policy.validate_ci_evidence_reference(event, environment, reference['identity'])
    policy.validate_gate(check, request, completed=True)
    proof = historical_baseline(policy, reader)
    terminal = request['terminal_run']
    policy.require(type(terminal) is int and check['id'] not in (C1, PR256_C2) and
                   policy.consumer.canonical(request) == policy.consumer.canonical(result(reference, terminal, proof)),
                   'invitation result differs from exact scope and subjects')
    done = verify_approvals(policy, reader, reference, terminal, now)
    evidence = policy.consumer.evidence
    evidence.check_times(check, reference['identity'], now)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'invitation signature predates second approval')
    current_subject(policy, reader, reference['identity'])
    policy.resolve_ci_candidate(environment, reader)
    validate_reference(reference, int(clock()))
    return request
