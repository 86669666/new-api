"""Formal evidence reuse for PR #279 organization views and failed top-up display."""
from hashlib import sha256
import io
import json
import re
import urllib.request
import zipfile


PR = 279
HEAD = 'd8d3b53ae01f91830aeb83fc9bb64c39d80042a3'
TREE = 'fa1502d6fb514941995002b91ed086722c663eb6'
BASE = 'fab15930e70802cf82f1db14e9da35acfb43a941'
BRANCH = 'codex/de-tested-organization-views'
CONTROL_REF = 'refs/heads/codex/formal-quality-r29'
REFERENCE_SCHEMA = 'box-formal-organization-views-delta-ref/v29'
TERMINAL_SCHEMA = 'box-quality-terminal/v29'
SCOPE = 'organization-views'
C1 = 135232975120
PR278_C2 = 140568104492
PR278_PROOF = 'cede6ad43a4568f09660f50225a87fae8335d8105396435dc3cf9063cb8a30cc'
PR278_A = 46015727348
PR278_B = 46016323727
PR278_NATIVE_JOB = 140569086998
R28 = '0e073443be68a6e5769d2422ec73078ac6b48820'
HOSTED = {'attempt': 1, 'run_id': 46128531140, 'workflow_blob': 'c123990e4a8c9fd981b721455a8edbc65b62dfc5'}
NATIVE_MERGE = 'cf579b6c2f888ae0ac4b9e3df634da5464a2628e'
BASELINE = {'pull_number': 278, 'candidate_sha': '0f44d06462cfde8cfb5556527eaafa2aa0f7492f', 'candidate_tree': '6cdcbf78e2bbe7c94af9b6bf8d6192c17405071c', 'merge_commit': 'fab15930e70802cf82f1db14e9da35acfb43a941', 'terminal_check_id': 140568104492, 'native_run': 46003710399, 'native_attempt': 2, 'native_job': 140569086998}
MANIFEST = '929e35d8a2a44c41924d161601463c519a6d23f934c02235c36bcf031e7dd78d'
ARCHIVE = {'commit': 'b9e2fe4bf9e80f2123cb3d10e8910d7b2066b1ae', 'path': 'preparation/pr279-d8d3b53-organization-views-r29.zip', 'bytes': 102874, 'sha256': 'adee363e8a93f82e940801cbc97317d71281688eab57209ef2b1aec366a27a2d'}
BLOBS = {'web/src/features/organizations/__tests__/organization-details.test.tsx': '02a26dc957413ae4c7d10b7c4a703e2722e0026c', 'web/src/features/organizations/api.ts': '00c080b0a2837ffe0fa02b06e47939a60b932810', 'web/src/features/organizations/organization-details-dialog.tsx': 'c73f97ea05dde6efad1cc4519662d0ac39e8a0c6', 'web/src/features/organizations/organization-wallet-summary.tsx': 'f5e3e758b0f09eb76780c6a118b8e10af3b33550', 'web/src/features/usage-logs/__tests__/organization-task-scope.test.tsx': '50864f3b610e1d47a76f0c9e0f0dc48b30e6ce5f', 'web/src/features/usage-logs/components/organization-task-scope.tsx': 'ffb033201e869f4fc7ebcacf070c9c76cb6ed14b', 'web/src/features/usage-logs/index.tsx': '4fd6f7a524b3390b325294d78af58ea73bbe0929', 'web/src/features/wallet/lib/__tests__/billing-status.test.ts': '977ccd25ffe0ecdf16ee18cf6346d962f79f345e', 'web/src/features/wallet/lib/billing.ts': '77a4e92c41e32b39339f106b0e0d2453704e14da', 'web/src/features/wallet/types.ts': '9105f191b8e57fd0f025c4c50701884cf6b69486', 'web/src/i18n/locales/en.json': 'b53ad34a6da91bd677a48cba64910e20f3377762', 'web/src/i18n/locales/fr.json': '3a267f7678cc86c14a479f09ac5dc58d39aa765b', 'web/src/i18n/locales/ja.json': '6a13e2c46e46003f42417f80aa98bd0823b344b4', 'web/src/i18n/locales/ru.json': 'b795995efe0b750842a5c3d7af2460891fb727bb', 'web/src/i18n/locales/vi.json': '04b6c0c3ab96f22ab04bc096f6c1149a3327b50e', 'web/src/i18n/locales/zh-TW.json': 'b6c8a194784fe29531f8851df9059346db3f49a7', 'web/src/i18n/locales/zh.json': 'b8c298cd3dea0acc65b5b2048cd06f503b387ead'}
MEMBERS = {'acceptance-docker-build.log': '1fedadee9716420ea2fdb78a3e2cba71989e9e669fa737457c773f4766734f73', 'browser-acceptance.json': 'c30ab2b7aa356d62eb24f5005aa1b46703cbe911754633f6995d2b511e91a38c', 'candidate-files.sha256': 'c81855cb73df0ae17e5e76b0f36929f06c093ecd4280b8b00168d915dcc581df', 'candidate.patch': 'd0e619f91edbbeebb1f10e46c1d8ce32e35e7926adf54fd9bf2ab1fa34c61cc3', 'deploy-scopes.log': '70cd93b723a10ddc372d311c2890bb44536427847c32c6288e62e66abe24c200', 'i18n-sync.log': 'a1ca80b87f32edc9a7ceff972157ae1baa5c399f624b4b94acdc134b675f2cff', 'lint.log': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'organization-task-scope.png': '1a4eb8e348df802f185d8084d9054799362e0f777a7e6da2d7ad52224d02e903', 'organization-wallet.png': '464bc6052280f9fa4dcaa141f91b147a0866a0bdf5171dee6e34f2b82f80ce46', 'personal-orders.png': '381e0f6c724e5031c573bd9ebd9d13689e813cca5c76ba41537943c6c339f21c', 'post-deploy-db.json': 'cbde8098feec70bf98c7c64cc1297eb724905e03abd308471c5d8a85458b8f24', 'receipt.json': '637e2cea5d5caa7e4e253e72f40f8a93b86a1ba19b23fb1ceb83d7ae9b875713', 'scoped-tests.log': 'e7670a9aacc9405faa7964bc3d7d8aaf4104701f2f726107cd427ac129fd75b4', 'typecheck.log': '5b79a0e507fbfe3ee9fe68d86a274c3dec57408303abba3ba342ef01f4551dbe'}
FILES = tuple(BLOBS)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=True).encode('ascii')


def descriptor():
    return ARCHIVE.copy()


def consumer_intent(artifact, control, nonce):
    if (canonical(artifact) != canonical(ARCHIVE) or not re.fullmatch('[a-f0-9]{40}', control) or
            control == R28 or not re.fullmatch('[a-f0-9]{32}', nonce)):
        raise ValueError('invalid organization views delta selection')
    bound = {'artifact': artifact, 'baseline': BASELINE, 'tree': TREE, 'head': HEAD,
             'hosted': HOSTED, 'control': control, 'nonce': nonce}
    return sha256(canonical(bound)).hexdigest()


def make_reference(artifact, control, consumer_run, opened, nonce):
    consumer_intent(artifact, control, nonce)
    if type(consumer_run) is not int or consumer_run <= 0 or type(opened) is not int or opened <= 0:
        raise ValueError('invalid organization views delta approval times')
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
        raise ValueError('invalid or expired organization views delta reference')


def validate_package(policy, raw):
    require = policy.require
    decode = policy.consumer.evidence.decode
    require(type(raw) is bytes and len(raw) == ARCHIVE['bytes'] and sha256(raw).hexdigest() == ARCHIVE['sha256'],
            'wrong immutable organization views archive')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(sorted(archive.namelist()) == sorted((*MEMBERS, 'manifest.json')),
                'incorrect organization views inventory')
        manifest = archive.read('manifest.json')
        require(sha256(manifest).hexdigest() == MANIFEST and
                {name: sha256(archive.read(name)).hexdigest() for name in MEMBERS} == MEMBERS,
                'unreviewed organization views member')
        data = decode(manifest)
        require(data == dict(kind='pr279-organization-views/v1', pull=PR, head=HEAD, tree=TREE,
                             base=BASE, paths=list(FILES), hosted=HOSTED, blobs=BLOBS,
                             baseline_terminal=PR278_C2, members=MEMBERS),
                'wrong organization views evidence subjects')
        receipt = decode(archive.read('receipt.json'))
        require(receipt == {'baseline': 'fab15930e70802cf82f1db14e9da35acfb43a941', 'baseline_terminal': 140568104492, 'build_archive': '7024356343f699c5d7325d0c3e2af935e4e7447fc629c832974779f8d2e97c98', 'candidate_tree': 'fa1502d6fb514941995002b91ed086722c663eb6', 'evidence': {'acceptance-docker-build.log': '1fedadee9716420ea2fdb78a3e2cba71989e9e669fa737457c773f4766734f73', 'browser-acceptance.json': 'c30ab2b7aa356d62eb24f5005aa1b46703cbe911754633f6995d2b511e91a38c', 'candidate-files.sha256': 'c81855cb73df0ae17e5e76b0f36929f06c093ecd4280b8b00168d915dcc581df', 'deploy-scopes.log': '70cd93b723a10ddc372d311c2890bb44536427847c32c6288e62e66abe24c200', 'i18n-sync.log': 'a1ca80b87f32edc9a7ceff972157ae1baa5c399f624b4b94acdc134b675f2cff', 'lint.log': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'organization-task-scope.png': '1a4eb8e348df802f185d8084d9054799362e0f777a7e6da2d7ad52224d02e903', 'organization-wallet.png': '464bc6052280f9fa4dcaa141f91b147a0866a0bdf5171dee6e34f2b82f80ce46', 'personal-orders.png': '381e0f6c724e5031c573bd9ebd9d13689e813cca5c76ba41537943c6c339f21c', 'post-deploy-db.json': 'cbde8098feec70bf98c7c64cc1297eb724905e03abd308471c5d8a85458b8f24', 'scoped-tests.log': 'e7670a9aacc9405faa7964bc3d7d8aaf4104701f2f726107cd427ac129fd75b4', 'typecheck.log': '5b79a0e507fbfe3ee9fe68d86a274c3dec57408303abba3ba342ef01f4551dbe'}, 'executed_nine_layers': False, 'head': 'd8d3b53ae01f91830aeb83fc9bb64c39d80042a3', 'patch': 'd0e619f91edbbeebb1f10e46c1d8ce32e35e7926adf54fd9bf2ab1fa34c61cc3', 'scope': ['organization task scope', 'organization wallet read', 'failed top-up status'], 'tests': 126}, 'wrong reviewed candidate receipt')
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
                   pr['base']['sha'] == BASE and pr['base']['ref'] == 'main', 'current organization views PR subject changed')
    commit = reader.commit(HEAD)
    policy.require(commit['sha'] == HEAD and commit['tree']['sha'] == TREE and
                   [row['sha'] for row in commit['parents']] == [BASE], 'wrong organization views candidate tree or parents')
    policy.verify_hosted_jobs(reader, HOSTED, identity)


def historical_baseline(policy, reader, fetch=None):
    previous = policy.controlled_reconcile_delta
    evidence = policy.consumer.evidence
    older = previous.historical_baseline(policy, reader, fetch)
    check = reader.check(PR278_C2)
    proof = evidence.decode(check['output']['text'])
    policy.require(check['id'] == PR278_C2 and policy.consumer.digest(proof) == PR278_PROOF and
                   (proof['candidate_sha'], proof['candidate_tree'], proof['consumer_run'], proof['terminal_run']) ==
                   (BASELINE['candidate_sha'], BASELINE['candidate_tree'], PR278_A, PR278_B),
                   'wrong signed PR278 baseline')
    signed = evidence.github_time(check, 'completed_at')
    policy.validate_gate(check, proof, completed=True)
    ref = proof['artifact']
    previous.validate_reference(ref, signed)
    policy.require(ref['identity']['consumer_sha'] == R28 and
                   policy.consumer.canonical(proof) == policy.consumer.canonical(previous.result(ref, PR278_B, older)),
                   'signed PR278 evidence differs from reviewed contract')
    done = previous.verify_approvals(policy, reader, ref, PR278_B, signed)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'PR278 signature predates its reviews')
    prior_run = reader.run(previous.HOSTED['run_id'], previous.HOSTED['attempt'])
    repo_id = ref['identity']['repository_id']
    policy.require(prior_run['id'] == previous.HOSTED['run_id'] and
                   prior_run['run_attempt'] == previous.HOSTED['attempt'] and
                   prior_run['workflow_id'] == policy.CI_WORKFLOW_ID and prior_run['path'] == '.github/workflows/ci.yml' and
                   prior_run['event'] == 'pull_request' and prior_run['head_sha'] == previous.HEAD and
                   prior_run['repository']['id'] == prior_run['head_repository']['id'] == repo_id and
                   reader.hosted_workflow_blob(previous.HEAD) == previous.HOSTED['workflow_blob'],
                   'historical PR278 hosted run or workflow blob changed')
    policy.verify_hosted_job_steps(reader, previous.HOSTED, previous.HEAD)
    if fetch is not None:
        previous.validate_package(policy, fetch(ref['artifact']['commit']))
    pr = reader.pull(278)
    merged = reader.commit(BASE)
    policy.require(pr['number'] == 278 and pr['state'] == 'closed' and pr['merged'] is True and
                   pr['merge_commit_sha'] == BASE and pr['head']['sha'] == BASELINE['candidate_sha'] and
                   pr['base']['ref'] == 'main' and pr['base']['repo']['id'] == repo_id and
                   merged['sha'] == BASE and merged['tree']['sha'] == BASELINE['candidate_tree'] and
                   [row['sha'] for row in merged['parents']] == [previous.BASE, previous.HEAD], 'wrong historical PR278 merge')
    run = reader.run(BASELINE['native_run'], BASELINE['native_attempt'])
    policy.require(run['id'] == BASELINE['native_run'] and run['run_attempt'] == BASELINE['native_attempt'] and
                   run['head_sha'] == BASELINE['candidate_sha'] and
                   run['repository']['id'] == run['head_repository']['id'] == repo_id and
                   run['path'] == '.github/workflows/ci.yml' and run['event'] == 'pull_request' and
                   run['workflow_id'] == policy.CI_WORKFLOW_ID and
                   run['status'] == 'completed' and run['conclusion'] == 'success', 'historical PR278 native gate did not pass')
    gate = policy.successful_job(reader.jobs(BASELINE['native_run'], BASELINE['native_attempt']), policy.GATE, BASELINE['candidate_sha'],
                                 ('Verify hosted jobs and authenticated exact-candidate quality',))
    policy.require(gate['id'] == PR278_NATIVE_JOB and gate['run_id'] == BASELINE['native_run'] and gate['run_attempt'] == BASELINE['native_attempt'] and
                   signed <= evidence.github_time(gate, 'started_at') <= evidence.github_time(gate, 'completed_at') <=
                   evidence.github_time(pr, 'merged_at') <= ref['identity']['release_expires_at'],
                   'PR278 native green and merge outside historical publication')
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
        policy.require(type(terminal_run) is int and terminal_run != consumer_run, 'separate organization views terminal required')
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
            'release_expires_at': identity['release_expires_at'], 'admission_id': 'pr279-organization-views-' + HEAD,
            'invocation': consumer_intent(reference['artifact'], identity['consumer_sha'], reference['nonce'])}


def verify(policy, reference, reader, fetch, terminal_run, now, *, active=False, staged_at=None):
    validate_reference(reference, now)
    policy.require(callable(fetch) and (active or terminal_run is not None), 'both reviewed organization views jobs required')
    done = verify_approvals(policy, reader, reference, terminal_run, now, active=active)
    if staged_at is not None:
        policy.require(done is not None and done <= staged_at <= now, 'organization views result staged before terminal completion')
    proof = historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    current_subject(policy, reader, reference['identity'])
    request = result(reference, terminal_run, proof)
    if terminal_run is None:
        request['schema'] = 'box-quality-organization-views-consumer/v29'
    return request


def prescreen(policy, artifact, reader, fetch):
    policy.require(canonical(artifact) == canonical(ARCHIVE) and callable(fetch), 'wrong organization views preflight artifact')
    current_subject(policy, reader, {'repository_id': 1423238398, 'head_repository_id': 1423238398, 'pull_number': PR,
                                    'base_sha': BASE, 'candidate_sha': HEAD})
    historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    return {'candidate_sha': HEAD, 'candidate_tree': TREE, 'baseline': BASELINE, 'hosted': HOSTED, 'artifact': artifact}


def private_fetch(policy, token):
    old_fetch = policy.controlled_reconcile_delta.private_fetch(policy, token)
    evidence = policy.consumer.evidence

    def fetch(commit):
        if commit != ARCHIVE['commit']:
            return old_fetch(commit)
        path = '/repos/' + evidence.EVIDENCE_REPOSITORY
        repo = policy.consumer.api(path, token)
        policy.require(repo['id'] == evidence.EVIDENCE_REPOSITORY_ID and
                       repo['full_name'] == evidence.EVIDENCE_REPOSITORY and repo['private'] is True,
                       'wrong private organization views evidence repository')
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
                   environment['GITHUB_SHA'] == environment['GITHUB_WORKFLOW_SHA'] == trusted, 'wrong native organization views dispatch')
    reference = evidence.decode(environment['BOX_FORMAL_ADMISSION'])
    run = int(environment['GITHUB_RUN_ID'])
    validate_reference(reference, int(clock()))
    policy.require(trusted == reference['identity']['consumer_sha'] and (run != reference['consumer_run']) == terminal,
                   'wrong protected organization views run')
    if terminal:
        for field, key in [('BOX_FORMAL_HOSTED_RUN_ID', 'run_id'), ('BOX_FORMAL_HOSTED_RUN_ATTEMPT', 'attempt'),
                           ('BOX_FORMAL_HOSTED_CI_BLOB', 'workflow_blob')]:
            policy.require(environment[field] == str(HOSTED[key]), 'wrong organization views hosted run pin')
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
    policy.reader_stage('r29_native_event')
    event = policy.ci_premerge_event(environment)
    policy.require(environment['GITHUB_EVENT_NAME'] == 'pull_request' and environment['GITHUB_RUN_ID'] == str(HOSTED['run_id'])
                   and event['number'] == PR and event['pull_request']['head']['sha'] == HEAD, 'wrong native organization views gate')
    policy.reader_stage('r29_c2_lookup')
    check = reader.formal_quality_check(HEAD)
    policy.reader_stage('r29_c2_decode')
    request = policy.consumer.evidence.decode(check['output']['text'])
    now = int(clock())
    reference = request['artifact']
    policy.reader_stage('r29_window')
    validate_reference(reference, now)
    policy.reader_stage('r29_native_merge_anchor')
    event = native_event_with_verified_base(policy, event, environment, reader)
    policy.reader_stage('r29_ci_binding')
    policy.validate_ci_evidence_reference(event, environment, reference['identity'])
    policy.reader_stage('r29_c2_authenticity')
    policy.validate_gate(check, request, completed=True)
    policy.reader_stage('r29_history')
    proof = historical_baseline(policy, reader)
    policy.reader_stage('r29_receipt_binding')
    terminal = request['terminal_run']
    policy.require(type(terminal) is int and check['id'] not in (C1, PR278_C2) and
                   policy.consumer.canonical(request) == policy.consumer.canonical(result(reference, terminal, proof)),
                   'organization views result differs from exact scope and subjects')
    policy.reader_stage('r29_approvals')
    done = verify_approvals(policy, reader, reference, terminal, now)
    policy.reader_stage('r29_publication_order')
    evidence = policy.consumer.evidence
    evidence.check_times(check, reference['identity'], now)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'organization views signature predates second approval')
    policy.reader_stage('r29_current_candidate')
    current_subject(policy, reader, reference['identity'])
    policy.reader_stage('r29_premerge_readback')
    policy._resolve_ci_candidate(event, environment, reader)
    policy.reader_stage('r29_final_window')
    validate_reference(reference, int(clock()))
    return request
