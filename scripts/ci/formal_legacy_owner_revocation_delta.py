"""Formal evidence reuse for PR #277 legacy media owner revocation."""
from hashlib import sha256
import io
import json
import re
import urllib.request
import zipfile


PR = 277
HEAD = '81cf5f19d7287b8576961982c9c560a844c5cd49'
TREE = '45012a9a841c166de310bf2bb9f45d9b5c870d73'
BASE = '0266cff3c385c4066f5bcb5431a2401c9ac48b0b'
BRANCH = 'codex/w04-owner-legacy-revocation'
CONTROL_REF = 'refs/heads/codex/formal-quality-r26'
REFERENCE_SCHEMA = 'box-formal-legacy-owner-revocation-delta-ref/v26'
TERMINAL_SCHEMA = 'box-quality-terminal/v26'
SCOPE = 'legacy-owner-revocation'
C1 = 135232975120
PR276_C2 = 138824957088
PR276_PROOF = 'e30cba3a1d7b2d12ddecf51a1ce006374a02ca72e55aa56250c40d862f6134c2'
PR276_A, PR276_B = 45498261768, 45499375995
PR276_NATIVE_JOB = 138825791734
R25 = '84dc1c5df42a3acfbc1982ee7a376e62aaf199c4'
HOSTED = {'attempt': 1, 'run_id': 45506805073, 'workflow_blob': 'c123990e4a8c9fd981b721455a8edbc65b62dfc5'}
BASELINE = {'pull_number': 276, 'candidate_sha': '2c1867fcb1a7e6a688879f64b9844a4e81f88a08',
            'candidate_tree': 'c5f3931c8c8bb5564f9901737405fd1d47837b86', 'merge_commit': BASE, 'terminal_check_id': PR276_C2,
            'native_run': 45495408496, 'native_attempt': 2, 'native_job': PR276_NATIVE_JOB}
MANIFEST = '1a18c2f29875b9586d2ae427f631710d5f3cb05fc78c817930540de3bb04a516'
ARCHIVE = {'commit': '31e3752d589c62e6af27d0144ca0b1503eaabe5b', 'path': 'formal-audit/pr277-81cf5f19-formal-inputs.zip', 'bytes': 9611, 'sha256': '3fce8e5cca4c313d7082b862a5befce9d4dbd72d7e6470f26cd548736aa62df2'}
BLOBS = {'controller/personal_media.go': 'c2d729b5c87929e3d4c2373287fdd6f04fadf1ea', 'docs/openapi/api.json': '881dd512ca152421aff2a1f9d3c1982e0822db69', 'middleware/access_token_routes.go': '44fd3bd3fcd49d62cdfaa239f150bb4d74f429f5', 'model/legacy_media_snapshot.go': '2dcccf95e60803830211e3896b21dc3eea301f7a', 'model/legacy_media_snapshot_test.go': '6574c904630af902fff8e05bd6f15f68e3cbc01b', 'router/api-router.go': 'c0d929c277da53e7e6db7020450f77f1967d0064', 'router/organization_access_test.go': 'a4aec6e7223b2d791864ae3477660e92bbde1569'}
MEMBERS = {'candidate.patch': '25a933908cfcd5b96e0051d1b983220049f7fda590f921423ff82b5e905f82b6', 'model-sqlite.jsonl': '541aad009ce43fc7d157ac7cd54b006f54c13f783cb4e82de5bebcf852a46fca', 'mysql-targeted.log': '95837461a6919ed0480538403993a8ba499da7aa957fb3d48fc7f1b2e1731e33', 'postgres-targeted.log': 'aac658156fb8defa4c423160ce7442233a7dc5d6e206a3b3836a094987ec23b1', 'receipt.json': 'caa49a6f0f126fcb6f04451b8d49accb7bdf005e4032e4c8316f5888aa1b2941', 'router-targeted.jsonl': '25847b39371af85fc7437c52bc78e5937eb20ef868b02f857bc061bc21f112ec'}
FILES = tuple(BLOBS)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=True).encode('ascii')


def descriptor():
    return ARCHIVE.copy()


def consumer_intent(artifact, control, nonce):
    if (canonical(artifact) != canonical(ARCHIVE) or not re.fullmatch('[a-f0-9]{40}', control) or
            control == R25 or not re.fullmatch('[a-f0-9]{32}', nonce)):
        raise ValueError('invalid legacy owner revocation delta selection')
    bound = {'artifact': artifact, 'baseline': BASELINE, 'tree': TREE, 'head': HEAD,
             'hosted': HOSTED, 'control': control, 'nonce': nonce}
    return sha256(canonical(bound)).hexdigest()


def make_reference(artifact, control, consumer_run, opened, nonce):
    consumer_intent(artifact, control, nonce)
    if type(consumer_run) is not int or consumer_run <= 0 or type(opened) is not int or opened <= 0:
        raise ValueError('invalid legacy owner revocation delta approval times')
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
        raise ValueError('invalid or expired legacy owner revocation delta reference')


def validate_package(policy, raw):
    require = policy.require
    decode = policy.consumer.evidence.decode
    require(type(raw) is bytes and len(raw) == ARCHIVE['bytes'] and sha256(raw).hexdigest() == ARCHIVE['sha256'],
            'wrong immutable legacy owner revocation archive')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(sorted(archive.namelist()) == sorted((*MEMBERS, 'manifest.json')),
                'incorrect legacy owner revocation inventory')
        manifest = archive.read('manifest.json')
        require(sha256(manifest).hexdigest() == MANIFEST and
                {name: sha256(archive.read(name)).hexdigest() for name in MEMBERS} == MEMBERS,
                'unreviewed legacy owner revocation member')
        data = decode(manifest)
        require(data == dict(kind='pr277-legacy-owner-revocation/v1', pull=PR, head=HEAD, tree=TREE,
                             base=BASE, paths=list(FILES), hosted=HOSTED, blobs=BLOBS,
                             baseline_terminal=PR276_C2, members=MEMBERS),
                'wrong legacy owner revocation evidence subjects')
        receipt = decode(archive.read('receipt.json'))
        require(receipt == {'baseline': '0266cff3c385c4066f5bcb5431a2401c9ac48b0b', 'candidate_tree': '45012a9a841c166de310bf2bb9f45d9b5c870d73', 'contract': {'activation': 'No deployment, no clock start, and no changes to existing Relay and public read routes.', 'database': 'Existing schema. Owner transaction retested on three isolated engines.', 'scope': 'Default-off Dashboard owner revocation for prepared MJ and task V1 image-1'}, 'engines': {'mysql': '8.0.46', 'postgres': '16.15', 'sqlite': '3.50.4'}, 'evidence': {'model-sqlite.jsonl': '541aad009ce43fc7d157ac7cd54b006f54c13f783cb4e82de5bebcf852a46fca', 'mysql-targeted.log': '95837461a6919ed0480538403993a8ba499da7aa957fb3d48fc7f1b2e1731e33', 'postgres-targeted.log': 'aac658156fb8defa4c423160ce7442233a7dc5d6e206a3b3836a094987ec23b1', 'router-targeted.jsonl': '25847b39371af85fc7437c52bc78e5937eb20ef868b02f857bc061bc21f112ec'}, 'head': '81cf5f19d7287b8576961982c9c560a844c5cd49', 'http': ['TestPersonalLegacyMediaRevocationDefaultsOff', 'TestAccessTokenRouteRulesCoverEveryDashboardRoute', 'TestPersonalHistoricalMediaReading/old_mj_and_v1_enforce_the_shared_policy'], 'patch': '25a933908cfcd5b96e0051d1b983220049f7fda590f921423ff82b5e905f82b6', 'reviewer': 'gate_review', 'verdict': 'ACCEPT_SCOPED'}, 'wrong reviewed owner revocation receipt')
        require(receipt['head'] == HEAD and receipt['baseline'] == BASE and receipt['candidate_tree'] == TREE and
                receipt['patch'] == MEMBERS['candidate.patch'] and
                all(MEMBERS[name] == digest for name, digest in receipt['evidence'].items()),
                'wrong owner revocation subjects or evidence')



def current_subject(policy, reader, identity):
    base = reader.repository()
    pr = reader.pull(PR)
    repo_id = identity['repository_id']
    policy.require(base['id'] == repo_id and base['full_name'] == policy.REPOSITORY and
                   pr['number'] == PR and pr['state'] == 'open' and pr['merged'] is False and pr['draft'] is False and pr['changed_files'] == len(FILES) and
                   pr['head']['repo']['id'] == pr['base']['repo']['id'] == repo_id and
                   pr['head']['repo']['full_name'] == pr['base']['repo']['full_name'] == policy.REPOSITORY and
                   pr['head']['sha'] == HEAD and pr['head']['ref'] == BRANCH and
                   pr['base']['sha'] == BASE and pr['base']['ref'] == 'main', 'current legacy owner revocation PR subject changed')
    commit = reader.commit(HEAD)
    policy.require(commit['sha'] == HEAD and commit['tree']['sha'] == TREE and
                   [row['sha'] for row in commit['parents']] == [BASE], 'wrong legacy owner revocation candidate tree or parents')
    policy.verify_hosted_jobs(reader, HOSTED, identity)


def historical_baseline(policy, reader, fetch=None):
    previous = policy.legacy_media_read_delta
    evidence = policy.consumer.evidence
    older = previous.historical_baseline(policy, reader, fetch)
    check = reader.check(PR276_C2)
    proof = evidence.decode(check['output']['text'])
    policy.require(check['id'] == PR276_C2 and policy.consumer.digest(proof) == PR276_PROOF and
                   (proof['candidate_sha'], proof['candidate_tree'], proof['consumer_run'], proof['terminal_run']) ==
                   (BASELINE['candidate_sha'], BASELINE['candidate_tree'], PR276_A, PR276_B),
                   'wrong signed PR276 baseline')
    signed = evidence.github_time(check, 'completed_at')
    policy.validate_gate(check, proof, completed=True)
    ref = proof['artifact']
    previous.validate_reference(ref, signed)
    policy.require(ref['identity']['consumer_sha'] == R25 and
                   policy.consumer.canonical(proof) == policy.consumer.canonical(previous.result(ref, PR276_B, older)),
                   'signed PR276 evidence differs from reviewed contract')
    done = previous.verify_approvals(policy, reader, ref, PR276_B, signed)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'PR276 signature predates its reviews')
    prior_run = reader.run(previous.HOSTED['run_id'], previous.HOSTED['attempt'])
    repo_id = ref['identity']['repository_id']
    policy.require(prior_run['id'] == previous.HOSTED['run_id'] and
                   prior_run['run_attempt'] == previous.HOSTED['attempt'] and
                   prior_run['workflow_id'] == policy.CI_WORKFLOW_ID and prior_run['path'] == '.github/workflows/ci.yml' and
                   prior_run['event'] == 'pull_request' and prior_run['head_sha'] == previous.HEAD and
                   prior_run['repository']['id'] == prior_run['head_repository']['id'] == repo_id and
                   reader.hosted_workflow_blob(previous.HEAD) == previous.HOSTED['workflow_blob'],
                   'historical PR276 hosted run or workflow blob changed')
    policy.verify_hosted_job_steps(reader, previous.HOSTED, previous.HEAD)
    if fetch is not None:
        previous.validate_package(policy, fetch(ref['artifact']['commit']))
    pr = reader.pull(276)
    merged = reader.commit(BASE)
    policy.require(pr['number'] == 276 and pr['state'] == 'closed' and pr['merged'] is True and
                   pr['merge_commit_sha'] == BASE and pr['head']['sha'] == BASELINE['candidate_sha'] and
                   pr['base']['ref'] == 'main' and pr['base']['repo']['id'] == repo_id and
                   merged['sha'] == BASE and merged['tree']['sha'] == BASELINE['candidate_tree'] and
                   [row['sha'] for row in merged['parents']] == [previous.BASE, previous.HEAD], 'wrong historical PR276 merge')
    run = reader.run(BASELINE['native_run'], 2)
    policy.require(run['id'] == BASELINE['native_run'] and run['run_attempt'] == 2 and
                   run['head_sha'] == BASELINE['candidate_sha'] and
                   run['repository']['id'] == run['head_repository']['id'] == repo_id and
                   run['path'] == '.github/workflows/ci.yml' and run['event'] == 'pull_request' and
                   run['workflow_id'] == policy.CI_WORKFLOW_ID and
                   run['status'] == 'completed' and run['conclusion'] == 'success', 'historical PR276 native gate did not pass')
    gate = policy.successful_job(reader.jobs(BASELINE['native_run'], 2), policy.GATE, BASELINE['candidate_sha'],
                                 ('Verify hosted jobs and authenticated exact-candidate quality',))
    policy.require(gate['id'] == PR276_NATIVE_JOB and gate['run_id'] == BASELINE['native_run'] and gate['run_attempt'] == 2 and
                   signed <= evidence.github_time(gate, 'started_at') <= evidence.github_time(gate, 'completed_at') <=
                   evidence.github_time(pr, 'merged_at') <= ref['identity']['release_expires_at'],
                   'PR276 native green and merge outside historical publication')
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
        policy.require(type(terminal_run) is int and terminal_run != consumer_run, 'separate legacy owner revocation terminal required')
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
            'release_expires_at': identity['release_expires_at'], 'admission_id': 'pr277-legacy-owner-revocation-' + HEAD,
            'invocation': consumer_intent(reference['artifact'], identity['consumer_sha'], reference['nonce'])}


def verify(policy, reference, reader, fetch, terminal_run, now, *, active=False, staged_at=None):
    validate_reference(reference, now)
    policy.require(callable(fetch) and (active or terminal_run is not None), 'both reviewed legacy owner revocation jobs required')
    done = verify_approvals(policy, reader, reference, terminal_run, now, active=active)
    if staged_at is not None:
        policy.require(done is not None and done <= staged_at <= now, 'legacy owner revocation result staged before terminal completion')
    proof = historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    current_subject(policy, reader, reference['identity'])
    request = result(reference, terminal_run, proof)
    if terminal_run is None:
        request['schema'] = 'box-quality-legacy-owner-revocation-consumer/v26'
    return request


def prescreen(policy, artifact, reader, fetch):
    policy.require(canonical(artifact) == canonical(ARCHIVE) and callable(fetch), 'wrong legacy owner revocation preflight artifact')
    current_subject(policy, reader, {'repository_id': 1423238398, 'head_repository_id': 1423238398, 'pull_number': PR,
                                    'base_sha': BASE, 'candidate_sha': HEAD})
    historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    return {'candidate_sha': HEAD, 'candidate_tree': TREE, 'baseline': BASELINE, 'hosted': HOSTED, 'artifact': artifact}


def private_fetch(policy, token):
    old_fetch = policy.legacy_media_read_delta.private_fetch(policy, token)
    evidence = policy.consumer.evidence

    def fetch(commit):
        if commit != ARCHIVE['commit']:
            return old_fetch(commit)
        path = '/repos/' + evidence.EVIDENCE_REPOSITORY
        repo = policy.consumer.api(path, token)
        policy.require(repo['id'] == evidence.EVIDENCE_REPOSITORY_ID and
                       repo['full_name'] == evidence.EVIDENCE_REPOSITORY and repo['private'] is True,
                       'wrong private legacy owner revocation evidence repository')
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
                   environment['GITHUB_SHA'] == environment['GITHUB_WORKFLOW_SHA'] == trusted, 'wrong native legacy owner revocation dispatch')
    reference = evidence.decode(environment['BOX_FORMAL_ADMISSION'])
    run = int(environment['GITHUB_RUN_ID'])
    validate_reference(reference, int(clock()))
    policy.require(trusted == reference['identity']['consumer_sha'] and (run != reference['consumer_run']) == terminal,
                   'wrong protected legacy owner revocation run')
    if terminal:
        for field, key in [('BOX_FORMAL_HOSTED_RUN_ID', 'run_id'), ('BOX_FORMAL_HOSTED_RUN_ATTEMPT', 'attempt'),
                           ('BOX_FORMAL_HOSTED_CI_BLOB', 'workflow_blob')]:
            policy.require(environment[field] == str(HOSTED[key]), 'wrong legacy owner revocation hosted run pin')
    token = environment['BOX_FORMAL_EVIDENCE_TOKEN']
    policy.require(token and token != environment['GITHUB_TOKEN'], 'dedicated private evidence reader required')
    checked = verify(policy, reference, policy.GitHubReader(environment['GITHUB_TOKEN']), private_fetch(policy, token),
                     run if terminal else None, int(clock()), active=True)
    validate_reference(reference, int(clock()))
    return checked


def verify_public(policy, environment, reader, *, clock):
    event = policy.ci_premerge_event(environment)
    policy.require(environment['GITHUB_EVENT_NAME'] == 'pull_request' and environment['GITHUB_RUN_ID'] == str(HOSTED['run_id'])
                   and event['number'] == PR and event['pull_request']['head']['sha'] == HEAD, 'wrong native legacy owner revocation gate')
    check = reader.formal_quality_check(HEAD)
    request = policy.consumer.evidence.decode(check['output']['text'])
    now = int(clock())
    reference = request['artifact']
    validate_reference(reference, now)
    policy.validate_ci_evidence_reference(event, environment, reference['identity'])
    policy.validate_gate(check, request, completed=True)
    proof = historical_baseline(policy, reader)
    terminal = request['terminal_run']
    policy.require(type(terminal) is int and check['id'] not in (C1, PR276_C2) and
                   policy.consumer.canonical(request) == policy.consumer.canonical(result(reference, terminal, proof)),
                   'legacy owner revocation result differs from exact scope and subjects')
    done = verify_approvals(policy, reader, reference, terminal, now)
    evidence = policy.consumer.evidence
    evidence.check_times(check, reference['identity'], now)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'legacy owner revocation signature predates second approval')
    current_subject(policy, reader, reference['identity'])
    policy.resolve_ci_candidate(environment, reader)
    validate_reference(reference, int(clock()))
    return request
