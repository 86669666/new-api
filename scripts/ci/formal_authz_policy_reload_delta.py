"""Formal evidence reuse for PR #269 authorization policy reload."""
from hashlib import sha256
import io
import json
import re
import urllib.request
import zipfile


PR = 269
HEAD = '6f2dd68168e5b4cec34fbaa4912591e15e474177'
TREE = '5334b023867f86794e6321aeb24d3ef9fcd8b865'
BASE = '8243cc1e1c51ec6923cb6a7c626b07bd95ec5444'
BRANCH = 'codex/issue-2-w05-policy-reload'
CONTROL_REF = 'refs/heads/codex/formal-quality-r18'
REFERENCE_SCHEMA = 'box-formal-authz-policy-reload-delta-ref/v18'
TERMINAL_SCHEMA = 'box-quality-terminal/v18'
SCOPE = 'authz-policy-reload'
C1 = 135232975120
PR268_C2 = 137128784215
PR268_PROOF = 'eaff04b2dd0ce8cd81370823053317a8b4b3266d2b06431ec09fece0b8c6ae4f'
PR268_A, PR268_B = 44994966442, 44995547482
PR268_NATIVE_JOB = 137129889481
R17 = '0bda3ba8ac2772204f52e81c75a987ff2dbada2b'
HOSTED = {'attempt': 1, 'run_id': 45004512658, 'workflow_blob': 'c123990e4a8c9fd981b721455a8edbc65b62dfc5'}
BASELINE = {'pull_number': 268, 'candidate_sha': '953309ce8318900bd7794ae4adfb1f452f8c842d',
            'candidate_tree': 'b59081afb6a3287f1cb4d656c7aba93532be2042', 'merge_commit': BASE,
            'terminal_check_id': PR268_C2, 'native_run': 44990744265,
            'native_attempt': 2, 'native_job': PR268_NATIVE_JOB}
MANIFEST = '6562416f0535e6dfec56fe66ce246934882298ff527f3f55b564d807a6aa3a81'
ARCHIVE = {'bytes': 16209,
 'commit': 'fcedf70e635fbbe1728356e405b5bfa092f072e4',
 'path': 'formal-audit/pr269-6f2dd681-formal-inputs.zip',
 'sha256': '1de0647247ebc026b5a4969253b1899fb4bbde46510340d2a1fc9d7a3672bd0f'}
BLOBS = {'service/authz/authz_test.go': 'e3c11ed7f4d4da8097502c51abaf9981f26165ed'}
MEMBERS = {'build-receipt.json': 'fbd67d5fc2e965789f777dc0bc258775980c335eb52c82755a53d7d303b9fd5b',
 'candidate.patch': '5c5d43224cb5ed7bdd460d93504082b7f5520d7e2d573af172d491c73f45822d',
 'cross_hosts.py': 'ef63c4b9e46f2eb5908c363d69c70ba12260a74cca1903f3f17cfa21890d163f',
 'guest-cleanup': '2179208ad7abc93db9024d0d10bef578696cc56b4771dc3afee36eaef7e311e5',
 'independent-review.json': '6a8a21da6dcc64c408aa6acbf71297cc4f90756baf32c88f68525f8ce322fa7f',
 'mysql/database.log': '418aa1baa2cfc4fac11243331fb32c613c0c7958e41db5162667516d31e31237',
 'mysql/reader.log': 'a5eeded3b40e460b8e64bde1f1e240230061192cef714d6c35b99870907d557c',
 'mysql/receipt.json': '9f6b0b7c7ceea40540d9f762f51192f31f6e5b79fc77170ddbb2c97071a93227',
 'mysql/relay.log': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
 'mysql/revoke.log': 'd864e1314696496b1f303221145b94ec7d6fb86ea37ac53f762cf3d3770dbbc5',
 'mysql/seed.log': 'e4542c8eab935d7a053a87f98b42fe332b8fb8e61b745bdcbf4ee32c3ab6dd35',
 'postgres/database.log': '1e473b2847116c405666908b6fe404f184ae250767eb75a7f0c82646bc6e8e85',
 'postgres/reader.log': '05ef131579cd84e1afc83dd3ff012c209c6ccdf9b8c55188fbb030a301d65b04',
 'postgres/receipt.json': '001a5263ff347d7ee978e8e197c49a964ad69d096f1eb1b63bd168214be0347b',
 'postgres/relay.log': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
 'postgres/revoke.log': '3ab30ff52c7cba407e89de8888c53212eeaac95a68a28750e1bd554bbef5cb7a',
 'postgres/seed.log': 'f4c4ce930f4dcb90d82de1d7a3166c10ff9fdd9cfcf226f01c4ef91d6c059675',
 'targeted.jsonl': 'c23caebea1faf392e6c86436d0387a043b8462142baf944636811d3ae1273cd6',
 'w05_host_qualification_test.go': '43ed2d0755d9e57611df10e1b4f4fcb35864c125bdc9f590c2aafd34d9c7bbd4'}
FILES = tuple(BLOBS)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=True).encode('ascii')


def descriptor():
    return ARCHIVE.copy()


def consumer_intent(artifact, control, nonce):
    if (canonical(artifact) != canonical(ARCHIVE) or not re.fullmatch('[a-f0-9]{40}', control) or
            control == R17 or not re.fullmatch('[a-f0-9]{32}', nonce)):
        raise ValueError('invalid authorization policy reload delta selection')
    bound = {'artifact': artifact, 'baseline': BASELINE, 'tree': TREE, 'head': HEAD,
             'hosted': HOSTED, 'control': control, 'nonce': nonce}
    return sha256(canonical(bound)).hexdigest()


def make_reference(artifact, control, consumer_run, opened, nonce):
    consumer_intent(artifact, control, nonce)
    if type(consumer_run) is not int or consumer_run <= 0 or type(opened) is not int or opened <= 0:
        raise ValueError('invalid authorization policy reload delta approval times')
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
        raise ValueError('invalid or expired authorization policy reload delta reference')


def validate_package(policy, raw):
    require = policy.require
    decode = policy.consumer.evidence.decode
    require(type(raw) is bytes and len(raw) == ARCHIVE['bytes'] and sha256(raw).hexdigest() == ARCHIVE['sha256'],
            'wrong immutable authorization policy reload archive')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(sorted(archive.namelist()) == sorted((*MEMBERS, 'manifest.json')), 'incorrect authorization evidence inventory')
        manifest = archive.read('manifest.json')
        require(sha256(manifest).hexdigest() == MANIFEST and
                {name: sha256(archive.read(name)).hexdigest() for name in MEMBERS} == MEMBERS,
                'unreviewed authorization evidence member')
        data = decode(manifest)
        require(data == dict(kind='pr269-authz-policy-reload/v1', pull=PR, head=HEAD, tree=TREE,
                             base=BASE, paths=list(FILES), hosted=HOSTED, blobs=BLOBS,
                             baseline_terminal=PR268_C2, members=MEMBERS),
                'wrong authorization evidence subjects')
        review = decode(archive.read('independent-review.json'))
        build = decode(archive.read('build-receipt.json'))
        require((review['agent'], review['verdict'], review['base'], review['head'], review['tree'],
                 review['diff_sha256'], review['go_results_sha256'], review['runner_sha256']) ==
                ('gate_review', 'ACCEPT_SCOPED', BASE, HEAD, TREE, MEMBERS['candidate.patch'],
                 MEMBERS['targeted.jsonl'], MEMBERS['cross_hosts.py']), 'wrong independent review subject')
        require((build['commit'], build['tree'], build['fixture_sha256'], build['toolchain'], build['gowork'],
                 build['gotoolchain'], build['cgo_enabled']) ==
                (HEAD, TREE, MEMBERS['w05_host_qualification_test.go'], 'Go 1.26.10', 'off', 'local', 0),
                'wrong cross-host binary source or toolchain')
        require(set(build['binaries']) == {'darwin', 'linux'} and
                all(re.fullmatch('[0-9a-f]{64}', digest) for digest in build['binaries'].values()) and
                len(set(build['binaries'].values())) == 2, 'wrong platform artifact identity')
        records = [decode(line) for line in archive.read('targeted.jsonl').splitlines()]
        outcomes = [row for row in records if row.get('Action') in ('pass', 'fail', 'skip')]
        passed = [row['Test'] for row in outcomes if row.get('Test')]
        require(len(outcomes) == 14 and all(row['Action'] == 'pass' and
                    row['Package'] == 'github.com/QuantumNous/new-api/service/authz' for row in outcomes) and
                len(passed) == len(set(passed)) == 13 and
                'TestReloadPolicyFailsClosedAndRecoversWithRevocation' in passed, 'incomplete targeted authorization proof')
        engines = {'mysql': ('8.0.46', '1142'), 'postgres': ('15.19 (Debian 15.19-1.pgdg12+2)', '42501')}
        require(review['database_receipts'] == {engine: MEMBERS[engine+'/receipt.json'] for engine in engines},
                'unreviewed database receipts')
        for engine, (version, code) in engines.items():
            receipt = decode(archive.read(engine+'/receipt.json'))
            require((receipt['engine'], receipt['server_version'], receipt['server_error'], receipt['policy_poll_seconds'],
                     receipt['private_network'], receipt['writer'], receipt['reader']) ==
                    (engine, version, code, 1, 'none', '10.10.88.120 Linux/amd64 guest', 'local macOS/arm64') and
                    receipt['reader_exit'] == 0 and receipt['no_manual_reader_reload'] is True and
                    receipt['owned_container_removed'] is True, 'incomplete cross-host periodic database proof')
            require(set(receipt['log_sha256']) == {'database.log', 'reader.log', 'relay.log', 'revoke.log', 'seed.log'} and
                    all(MEMBERS[engine+'/'+name] == digest for name, digest in receipt['log_sha256'].items()),
                    'wrong cross-host execution logs')
        require(archive.read('guest-cleanup') == b'owned guest directory removed\n', 'missing fixture cleanup')


def current_subject(policy, reader, identity):
    base = reader.repository()
    pr = reader.pull(PR)
    repo_id = identity['repository_id']
    policy.require(base['id'] == repo_id and base['full_name'] == policy.REPOSITORY and
                   pr['number'] == PR and pr['state'] == 'open' and pr['merged'] is False and pr['draft'] is False and pr['changed_files'] == len(FILES) and
                   pr['head']['repo']['id'] == pr['base']['repo']['id'] == repo_id and
                   pr['head']['repo']['full_name'] == pr['base']['repo']['full_name'] == policy.REPOSITORY and
                   pr['head']['sha'] == HEAD and pr['head']['ref'] == BRANCH and
                   pr['base']['sha'] == BASE and pr['base']['ref'] == 'main', 'current authorization policy reload PR subject changed')
    commit = reader.commit(HEAD)
    policy.require(commit['sha'] == HEAD and commit['tree']['sha'] == TREE and
                   [row['sha'] for row in commit['parents']] == [BASE], 'wrong authorization policy reload candidate tree or parents')
    policy.verify_hosted_jobs(reader, HOSTED, identity)


def historical_baseline(policy, reader, fetch=None):
    previous = policy.sql_midjourney_delta
    evidence = policy.consumer.evidence
    older = previous.historical_baseline(policy, reader, fetch)
    check = reader.check(PR268_C2)
    proof = evidence.decode(check['output']['text'])
    policy.require(check['id'] == PR268_C2 and policy.consumer.digest(proof) == PR268_PROOF and
                   (proof['candidate_sha'], proof['candidate_tree'], proof['consumer_run'], proof['terminal_run']) ==
                   (BASELINE['candidate_sha'], BASELINE['candidate_tree'], PR268_A, PR268_B),
                   'wrong signed PR268 baseline')
    signed = evidence.github_time(check, 'completed_at')
    policy.validate_gate(check, proof, completed=True)
    ref = proof['artifact']
    previous.validate_reference(ref, signed)
    policy.require(ref['identity']['consumer_sha'] == R17 and
                   policy.consumer.canonical(proof) == policy.consumer.canonical(previous.result(ref, PR268_B, older)),
                   'signed PR268 evidence differs from reviewed contract')
    done = previous.verify_approvals(policy, reader, ref, PR268_B, signed)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'PR268 signature predates its reviews')
    prior_run = reader.run(previous.HOSTED['run_id'], previous.HOSTED['attempt'])
    repo_id = ref['identity']['repository_id']
    policy.require(prior_run['id'] == previous.HOSTED['run_id'] and
                   prior_run['run_attempt'] == previous.HOSTED['attempt'] and
                   prior_run['workflow_id'] == policy.CI_WORKFLOW_ID and prior_run['path'] == '.github/workflows/ci.yml' and
                   prior_run['event'] == 'pull_request' and prior_run['head_sha'] == previous.HEAD and
                   prior_run['repository']['id'] == prior_run['head_repository']['id'] == repo_id and
                   reader.hosted_workflow_blob(previous.HEAD) == previous.HOSTED['workflow_blob'],
                   'historical PR268 hosted run or workflow blob changed')
    policy.verify_hosted_job_steps(reader, previous.HOSTED, previous.HEAD)
    if fetch is not None:
        previous.validate_package(policy, fetch(ref['artifact']['commit']))
    pr = reader.pull(268)
    merged = reader.commit(BASE)
    policy.require(pr['number'] == 268 and pr['state'] == 'closed' and pr['merged'] is True and
                   pr['merge_commit_sha'] == BASE and pr['head']['sha'] == BASELINE['candidate_sha'] and
                   pr['base']['ref'] == 'main' and pr['base']['repo']['id'] == repo_id and
                   merged['sha'] == BASE and merged['tree']['sha'] == BASELINE['candidate_tree'] and
                   [row['sha'] for row in merged['parents']] == [previous.BASE, previous.HEAD], 'wrong historical PR268 merge')
    run = reader.run(BASELINE['native_run'], 2)
    policy.require(run['id'] == BASELINE['native_run'] and run['run_attempt'] == 2 and
                   run['head_sha'] == BASELINE['candidate_sha'] and
                   run['repository']['id'] == run['head_repository']['id'] == repo_id and
                   run['path'] == '.github/workflows/ci.yml' and run['event'] == 'pull_request' and
                   run['workflow_id'] == policy.CI_WORKFLOW_ID and
                   run['status'] == 'completed' and run['conclusion'] == 'success', 'historical PR268 native gate did not pass')
    gate = policy.successful_job(reader.jobs(BASELINE['native_run'], 2), policy.GATE, BASELINE['candidate_sha'],
                                 ('Verify hosted jobs and authenticated exact-candidate quality',))
    policy.require(gate['id'] == PR268_NATIVE_JOB and gate['run_id'] == BASELINE['native_run'] and gate['run_attempt'] == 2 and
                   signed <= evidence.github_time(gate, 'started_at') <= evidence.github_time(gate, 'completed_at') <=
                   evidence.github_time(pr, 'merged_at') <= ref['identity']['release_expires_at'],
                   'PR268 native green and merge outside historical publication')
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
        policy.require(type(terminal_run) is int and terminal_run != consumer_run, 'separate authorization policy reload terminal required')
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
            'release_expires_at': identity['release_expires_at'], 'admission_id': 'pr269-authz-policy-reload-' + HEAD,
            'invocation': consumer_intent(reference['artifact'], identity['consumer_sha'], reference['nonce'])}


def verify(policy, reference, reader, fetch, terminal_run, now, *, active=False, staged_at=None):
    validate_reference(reference, now)
    policy.require(callable(fetch) and (active or terminal_run is not None), 'both reviewed authorization policy reload jobs required')
    done = verify_approvals(policy, reader, reference, terminal_run, now, active=active)
    if staged_at is not None:
        policy.require(done is not None and done <= staged_at <= now, 'authorization policy reload result staged before terminal completion')
    proof = historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    current_subject(policy, reader, reference['identity'])
    request = result(reference, terminal_run, proof)
    if terminal_run is None:
        request['schema'] = 'box-quality-authz-policy-reload-consumer/v18'
    return request


def prescreen(policy, artifact, reader, fetch):
    policy.require(canonical(artifact) == canonical(ARCHIVE) and callable(fetch), 'wrong authorization policy reload preflight artifact')
    current_subject(policy, reader, {'repository_id': 1423238398, 'head_repository_id': 1423238398, 'pull_number': PR,
                                    'base_sha': BASE, 'candidate_sha': HEAD})
    historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    return {'candidate_sha': HEAD, 'candidate_tree': TREE, 'baseline': BASELINE, 'hosted': HOSTED, 'artifact': artifact}


def private_fetch(policy, token):
    old_fetch = policy.sql_midjourney_delta.private_fetch(policy, token)
    evidence = policy.consumer.evidence

    def fetch(commit):
        if commit != ARCHIVE['commit']:
            return old_fetch(commit)
        path = '/repos/' + evidence.EVIDENCE_REPOSITORY
        repo = policy.consumer.api(path, token)
        policy.require(repo['id'] == evidence.EVIDENCE_REPOSITORY_ID and
                       repo['full_name'] == evidence.EVIDENCE_REPOSITORY and repo['private'] is True,
                       'wrong private authorization policy reload evidence repository')
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
                   environment['GITHUB_SHA'] == environment['GITHUB_WORKFLOW_SHA'] == trusted, 'wrong native authorization policy reload dispatch')
    reference = evidence.decode(environment['BOX_FORMAL_ADMISSION'])
    run = int(environment['GITHUB_RUN_ID'])
    validate_reference(reference, int(clock()))
    policy.require(trusted == reference['identity']['consumer_sha'] and (run != reference['consumer_run']) == terminal,
                   'wrong protected authorization policy reload run')
    if terminal:
        for field, key in [('BOX_FORMAL_HOSTED_RUN_ID', 'run_id'), ('BOX_FORMAL_HOSTED_RUN_ATTEMPT', 'attempt'),
                           ('BOX_FORMAL_HOSTED_CI_BLOB', 'workflow_blob')]:
            policy.require(environment[field] == str(HOSTED[key]), 'wrong authorization policy reload hosted run pin')
    token = environment['BOX_FORMAL_EVIDENCE_TOKEN']
    policy.require(token and token != environment['GITHUB_TOKEN'], 'dedicated private evidence reader required')
    checked = verify(policy, reference, policy.GitHubReader(environment['GITHUB_TOKEN']), private_fetch(policy, token),
                     run if terminal else None, int(clock()), active=True)
    validate_reference(reference, int(clock()))
    return checked


def verify_public(policy, environment, reader, *, clock):
    event = policy.ci_premerge_event(environment)
    policy.require(environment['GITHUB_EVENT_NAME'] == 'pull_request' and environment['GITHUB_RUN_ID'] == str(HOSTED['run_id'])
                   and event['number'] == PR and event['pull_request']['head']['sha'] == HEAD, 'wrong native authorization policy reload gate')
    check = reader.formal_quality_check(HEAD)
    request = policy.consumer.evidence.decode(check['output']['text'])
    now = int(clock())
    reference = request['artifact']
    validate_reference(reference, now)
    policy.validate_ci_evidence_reference(event, environment, reference['identity'])
    policy.validate_gate(check, request, completed=True)
    proof = historical_baseline(policy, reader)
    terminal = request['terminal_run']
    policy.require(type(terminal) is int and check['id'] not in (C1, PR268_C2) and
                   policy.consumer.canonical(request) == policy.consumer.canonical(result(reference, terminal, proof)),
                   'authorization policy reload result differs from exact scope and subjects')
    done = verify_approvals(policy, reader, reference, terminal, now)
    evidence = policy.consumer.evidence
    evidence.check_times(check, reference['identity'], now)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'authorization policy reload signature predates second approval')
    current_subject(policy, reader, reference['identity'])
    policy.resolve_ci_candidate(environment, reader)
    validate_reference(reference, int(clock()))
    return request
