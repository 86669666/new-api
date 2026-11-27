"""Formal evidence reuse for PR #278 controlled reservation cancellation."""
from hashlib import sha256
import io
import json
import re
import urllib.request
import zipfile


PR = 278
HEAD = '0f44d06462cfde8cfb5556527eaafa2aa0f7492f'
TREE = '6cdcbf78e2bbe7c94af9b6bf8d6192c17405071c'
BASE = 'f1f3a84b3f0982ddab539d361e63039721861f70'
BRANCH = 'codex/29-controlled-reconcile'
CONTROL_REF = 'refs/heads/codex/formal-quality-r28'
REFERENCE_SCHEMA = 'box-formal-controlled-reconcile-delta-ref/v28'
TERMINAL_SCHEMA = 'box-quality-terminal/v28'
SCOPE = 'controlled-reconcile'
C1 = 135232975120
PR255_C2 = 139974456984
PR255_PROOF = '04031e6351e315e43b441c648b10e11166f2c360939bbfb6c044c61b23fed053'
PR255_A = 45836806348
PR255_B = 45837830682
PR255_NATIVE_JOB = 139975816060
R27 = 'a3903a6353d46160dfd334b4e7b5d0561d41b96d'
HOSTED = {'attempt': 1, 'run_id': 46003710399, 'workflow_blob': 'c123990e4a8c9fd981b721455a8edbc65b62dfc5'}
NATIVE_MERGE = 'e8012558c9d0639316215e472af1f1639b82e1a3'
BASELINE = {'pull_number': 255, 'candidate_sha': 'd8df02228774d46a3a360f8b94f66ade3839dd14', 'candidate_tree': 'ad683d43b23808a2cd7e24a793e8dba5a6c5240c', 'merge_commit': 'f1f3a84b3f0982ddab539d361e63039721861f70', 'terminal_check_id': 139974456984, 'native_run': 45708355860, 'native_attempt': 6, 'native_job': 139975816060}
MANIFEST = '828d6251a048a0210b6b4eec1c6a4037bb48a92b9e1f8405d9fe6f7524cd922c'
ARCHIVE = {'commit': '0ca2ae5bfc970786a871ab5365fc142bd000cf49', 'path': 'formal-audit/pr278-0f44d064-controlled-reconcile-r28.zip', 'bytes': 76598, 'sha256': '5575d2bf3073fc32f9da70c97d99d6b4c899af45a0a020c86a8efa5a00208bbc'}
BLOBS = {'controller/oauth_ordinary_token.go': '4c835dec4b51f6d6096276f0796b677745c07911', 'controller/oauth_provider.go': 'b7671eb6f7ac7ec2835f5293ef0d3988710c8c23', 'controller/relay.go': '3f506acd86fa7c385d947b682b17d59ad15d411a', 'controller/token_test.go': 'd96b7301570a6428971bb47876359ca7b6c09a1e', 'docs/openapi/api.json': '73d56b7b9ed1b7b8e331c0958c213ce35dd0c2af', 'main.go': '65541507f38685f443e0c848237391476c4617ee', 'middleware/audit.go': '54db2b302a747bcfb02a62fe6901b71fcb92bcbc', 'middleware/auth_test.go': '80abb12037842e04b9a56b568e621148706b79f3', 'middleware/oauth_resource.go': '75517a4ec9b623dfc80436911737dc733cdc647d', 'model/oauth_derived_billing.go': 'ae443a63431dfdb9666f353a3512d30b9811c00c', 'model/oauth_derived_billing_test.go': 'd3081cf38482139b33e0038ad8e64fc70bf65c6a', 'model/oauth_derived_token.go': 'ab6fb8def6eb31ed7bccce91fbec67d4d2c0e8ab', 'model/oauth_derived_token_bootstrap.go': 'f8d7e99f27502fefcdfb51c94ad87847c5e4d200', 'model/oauth_derived_token_bootstrap_unsupported.go': '923b900fa535ff82563cb9e8c68b8c2ff848542f', 'model/oauth_first_key.go': 'f03a6fa2ec6b3e1bea3710d0985c48a54967a715', 'model/oauth_first_key_install.go': '2ef0e3c11331c379f9d990347bd8b3dcb3121940', 'model/oauth_first_key_mysql.sql': 'd9d6703a0f8d944c16dce1efad154517bb7b6f17', 'model/oauth_first_key_postgres.sql': '4e8fcc7eb0d24e20c6f795f30852df8c9176c3fe', 'model/oauth_grant.go': 'e344e110249d56a84b3971d6ee7f05ae5e79b644', 'model/oauth_issue_attestation.go': '73413a402dd0d1fb9a7363db9f8e969e72a4c236', 'model/oauth_issue_attestation_install.go': '3ad5cd108765e6ae52ffe8068d70ca3058331e32', 'model/oauth_issue_mysql.sql': '106e1cb65ed53b1968e9b9bb331c2954a7959456', 'model/oauth_issue_postgres.sql': 'd2b08be522e2921a6d597ad046db0251b3c7e57e', 'model/oauth_source_install.go': '177ca7cfaca9c01c9072b588323ece3bbf412380', 'model/oauth_source_mysql.sql': 'de4fa8c44fd72c193c192bbb0ad3c824b0aa0ec8', 'model/oauth_source_operations.go': 'bab8949e91438d933cc358b45544684c19f3887c', 'model/oauth_source_operations_test.go': '05563d25e6f912553ac2f0696c6535adc3afeb31', 'model/oauth_source_postgres.sql': 'e351ef2abe43f635dc4685e82ef0d9f1c9985118', 'model/oauth_text_reconcile.go': '312584e06fc7efeeb44215e202bd8030c3ff9fae', 'model/oauth_text_reconcile_cli_linux.go': '932cab5754bba87b74c1e37d05448780a55e85bb', 'model/oauth_text_reconcile_test.go': '70bc23ae295b7f9b7922527a16dcc416f385be79', 'relay/channel/openai/oauth_derived_response_test.go': '37fe9ca137ed35c959eb18d6f61163b70b8b8383', 'relay/channel/openai/relay-openai.go': '2f5915b34eb03bbe05a5b53681060c6421276a41', 'relay/oauth_derived_request.go': '653c3f0412fb3b10367767ea381f0f625aea55e7', 'relay/oauth_derived_response.go': 'd5d3bfc0f1a6e0c4663c6d8085f0b0bd3ce2f099', 'relay/oauth_derived_response_test.go': '27846aa496ec29c6b10f054e89f14d5e0a63e099', 'router/oauth_derived_text_http_test.go': 'e70468f11049506319193cade50ba1a85f4a9972', 'router/oauth_resource_router.go': '48fef48de8b9ba32da12224f794b246b2d48c317', 'router/relay-router.go': 'c73b3edcdc9f6c249479198045d4fc201a150a0e', 'scripts/openapi/check_contract.py': '5cbd574d857cbdb1ef886fa4bf1c29e2e47e9f8e', 'service/auth_token_test.go': 'de1f06aed55bfca48675062e3bbf2e9787b6b9d3', 'service/oauth_derived_billing.go': '5b43256c712e8caef5d573d13279417bf80ede31', 'service/oauth_derived_billing_test.go': 'ed0df7f33b5313ffed6450b0e8f062e35e5fa201', 'service/oauth_derived_transport.go': 'c4c52b55f5ab107f4da53ebb836ddf693afe166d', 'service/oauth_grant.go': '1aa1f12ec3d3a6d16cb8a27661a02d87067f69e7', 'service/oauth_issue_attestation.go': '092950ba25c25f89564c7b03b10902dacde1aa62', 'service/oauth_provider.go': 'e3dc9aeb87b00367fb130f4f272a819c5d70d982', 'service/oauth_provider_test.go': '5912e776d7596cc6727ec171ad8b7118e97ac34e', 'service/oauth_resource.go': 'e157b10a5f9ccd5ddeef3f0b500787af4274b178', 'service/security_verification.go': '0e5f994bfb4871be6973ff14f85dba001fe6e9c0'}
MEMBERS = {'build-r3.log': 'ac13ddafb8844c1a8685fc6be029a5d9a8e8b1b08effc014a35a3671488cce50', 'candidate-files.sha256': '20a2c80989cfa469347494fa918c11a43bbf0617aaba64200e74104c3ba77b63', 'candidate.patch': '790a6504ef5190195ac48f2f19f66c619d571a4c6387d95820a5c19fd895055e', 'other-final.log': '7f978e2d9942fd729da00d6761c4d1dff5d001e1fb91439250bb95535d0bd260', 'pg-final-finish.log': 'ef79a4e072f35b6ba35895b87b14f90bd6dfc5986e7e70e82e7a00680edf4822', 'pg-final-resume.log': '34f5b721bc84bc863e7557ec5ae8a8a3f1936e94e07c673ddda05378435a26d2', 'pg-final.log': 'bef7cb592ca29937206e02c7c8634dd385340275ee3705dbbfde46cb51aa1f47', 'pg-state-digests.log': '49effba4f7060f562cfe49a7103150260f44f38cb0fb6d5332c3435b555d9ced', 'prior-http/candidate-files.complete.sha256': '04a2c037ff2eb8cd7f1984ff7b47b05f01a5ca5568ad943fd8be6fe87ee42eec', 'prior-http/verify-http-r2.log': '6b853e512695e5f20af09859f02e7824ee5e93350f29a0527f1c10179057813e', 'prior-http/verify-http-r3.log': '024cbc4fc2438ec767a8d382474aeb10cb9e77ab258e4bea53c7efd1e26fe544', 'prior-http/verify-wallet.log': '247324a4f7814d72f673fe454d393a2666555142211ac49291552668cc6d4db7', 'receipt.json': '46be13bb9f2707dffa2141ea57325fff23d4fbefc4a2e3f7b90d260d02932d96', 'teardown.log': 'c9336bc653a4310d0f6489bfc96f975ecb9bfb9df23fc39d58696877a9b4eea6'}
FILES = tuple(BLOBS)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=True).encode('ascii')


def descriptor():
    return ARCHIVE.copy()


def consumer_intent(artifact, control, nonce):
    if (canonical(artifact) != canonical(ARCHIVE) or not re.fullmatch('[a-f0-9]{40}', control) or
            control == R27 or not re.fullmatch('[a-f0-9]{32}', nonce)):
        raise ValueError('invalid controlled cancellation delta selection')
    bound = {'artifact': artifact, 'baseline': BASELINE, 'tree': TREE, 'head': HEAD,
             'hosted': HOSTED, 'control': control, 'nonce': nonce}
    return sha256(canonical(bound)).hexdigest()


def make_reference(artifact, control, consumer_run, opened, nonce):
    consumer_intent(artifact, control, nonce)
    if type(consumer_run) is not int or consumer_run <= 0 or type(opened) is not int or opened <= 0:
        raise ValueError('invalid controlled cancellation delta approval times')
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
        raise ValueError('invalid or expired controlled cancellation delta reference')


def validate_package(policy, raw):
    require = policy.require
    decode = policy.consumer.evidence.decode
    require(type(raw) is bytes and len(raw) == ARCHIVE['bytes'] and sha256(raw).hexdigest() == ARCHIVE['sha256'],
            'wrong immutable controlled cancellation archive')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(sorted(archive.namelist()) == sorted((*MEMBERS, 'manifest.json')),
                'incorrect controlled cancellation inventory')
        manifest = archive.read('manifest.json')
        require(sha256(manifest).hexdigest() == MANIFEST and
                {name: sha256(archive.read(name)).hexdigest() for name in MEMBERS} == MEMBERS,
                'unreviewed controlled cancellation member')
        data = decode(manifest)
        require(data == dict(kind='pr278-controlled-reconcile/v1', pull=PR, head=HEAD, tree=TREE,
                             base=BASE, paths=list(FILES), hosted=HOSTED, blobs=BLOBS,
                             baseline_terminal=PR255_C2, members=MEMBERS),
                'wrong controlled cancellation evidence subjects')
        receipt = decode(archive.read('receipt.json'))
        require(receipt == {'baseline': 'f1f3a84b3f0982ddab539d361e63039721861f70', 'candidate_tree': '6cdcbf78e2bbe7c94af9b6bf8d6192c17405071c', 'delta': ['protected derived key prerequisites', 'server-fixed text accounting', 'reserved cancellation: PostgreSQL concurrency, atomic rollback, privilege rejection and same-store restart'], 'evidence': {'build-r3.log': 'ac13ddafb8844c1a8685fc6be029a5d9a8e8b1b08effc014a35a3671488cce50', 'candidate-files.sha256': '20a2c80989cfa469347494fa918c11a43bbf0617aaba64200e74104c3ba77b63', 'other-final.log': '7f978e2d9942fd729da00d6761c4d1dff5d001e1fb91439250bb95535d0bd260', 'pg-final-finish.log': 'ef79a4e072f35b6ba35895b87b14f90bd6dfc5986e7e70e82e7a00680edf4822', 'pg-final-resume.log': '34f5b721bc84bc863e7557ec5ae8a8a3f1936e94e07c673ddda05378435a26d2', 'pg-final.log': 'bef7cb592ca29937206e02c7c8634dd385340275ee3705dbbfde46cb51aa1f47', 'pg-state-digests.log': '49effba4f7060f562cfe49a7103150260f44f38cb0fb6d5332c3435b555d9ced', 'prior-http/candidate-files.complete.sha256': '04a2c037ff2eb8cd7f1984ff7b47b05f01a5ca5568ad943fd8be6fe87ee42eec', 'prior-http/verify-http-r2.log': '6b853e512695e5f20af09859f02e7824ee5e93350f29a0527f1c10179057813e', 'prior-http/verify-http-r3.log': '024cbc4fc2438ec767a8d382474aeb10cb9e77ab258e4bea53c7efd1e26fe544', 'prior-http/verify-wallet.log': '247324a4f7814d72f673fe454d393a2666555142211ac49291552668cc6d4db7', 'teardown.log': 'c9336bc653a4310d0f6489bfc96f975ecb9bfb9df23fc39d58696877a9b4eea6'}, 'head': '0f44d06462cfde8cfb5556527eaafa2aa0f7492f', 'historical': {'credit': 'reuse previously approved baseline coverage at original identity', 'terminal_check': 139974456984}, 'independent_review': {'identity': 'hydra_review', 'result': 'ACCEPT_SCOPED', 'reviewed_source_manifest': '20a2c80989cfa469347494fa918c11a43bbf0617aaba64200e74104c3ba77b63'}, 'patch': '790a6504ef5190195ac48f2f19f66c619d571a4c6387d95820a5c19fd895055e', 'send_claimed': 'read-only; supplier per-request receipt pending'}, 'wrong reviewed candidate receipt')
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
                   pr['base']['sha'] == BASE and pr['base']['ref'] == 'main', 'current controlled cancellation PR subject changed')
    commit = reader.commit(HEAD)
    policy.require(commit['sha'] == HEAD and commit['tree']['sha'] == TREE and
                   [row['sha'] for row in commit['parents']] == [BASE], 'wrong controlled cancellation candidate tree or parents')
    policy.verify_hosted_jobs(reader, HOSTED, identity)


def historical_baseline(policy, reader, fetch=None):
    previous = policy.hydra_birth_delta
    evidence = policy.consumer.evidence
    older = previous.historical_baseline(policy, reader, fetch)
    check = reader.check(PR255_C2)
    proof = evidence.decode(check['output']['text'])
    policy.require(check['id'] == PR255_C2 and policy.consumer.digest(proof) == PR255_PROOF and
                   (proof['candidate_sha'], proof['candidate_tree'], proof['consumer_run'], proof['terminal_run']) ==
                   (BASELINE['candidate_sha'], BASELINE['candidate_tree'], PR255_A, PR255_B),
                   'wrong signed PR255 baseline')
    signed = evidence.github_time(check, 'completed_at')
    policy.validate_gate(check, proof, completed=True)
    ref = proof['artifact']
    previous.validate_reference(ref, signed)
    policy.require(ref['identity']['consumer_sha'] == R27 and
                   policy.consumer.canonical(proof) == policy.consumer.canonical(previous.result(ref, PR255_B, older)),
                   'signed PR255 evidence differs from reviewed contract')
    done = previous.verify_approvals(policy, reader, ref, PR255_B, signed)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'PR255 signature predates its reviews')
    prior_run = reader.run(previous.HOSTED['run_id'], previous.HOSTED['attempt'])
    repo_id = ref['identity']['repository_id']
    policy.require(prior_run['id'] == previous.HOSTED['run_id'] and
                   prior_run['run_attempt'] == previous.HOSTED['attempt'] and
                   prior_run['workflow_id'] == policy.CI_WORKFLOW_ID and prior_run['path'] == '.github/workflows/ci.yml' and
                   prior_run['event'] == 'pull_request' and prior_run['head_sha'] == previous.HEAD and
                   prior_run['repository']['id'] == prior_run['head_repository']['id'] == repo_id and
                   reader.hosted_workflow_blob(previous.HEAD) == previous.HOSTED['workflow_blob'],
                   'historical PR255 hosted run or workflow blob changed')
    policy.verify_hosted_job_steps(reader, previous.HOSTED, previous.HEAD)
    if fetch is not None:
        previous.validate_package(policy, fetch(ref['artifact']['commit']))
    pr = reader.pull(255)
    merged = reader.commit(BASE)
    policy.require(pr['number'] == 255 and pr['state'] == 'closed' and pr['merged'] is True and
                   pr['merge_commit_sha'] == BASE and pr['head']['sha'] == BASELINE['candidate_sha'] and
                   pr['base']['ref'] == 'main' and pr['base']['repo']['id'] == repo_id and
                   merged['sha'] == BASE and merged['tree']['sha'] == BASELINE['candidate_tree'] and
                   [row['sha'] for row in merged['parents']] == [previous.BASE, previous.HEAD], 'wrong historical PR255 merge')
    run = reader.run(BASELINE['native_run'], BASELINE['native_attempt'])
    policy.require(run['id'] == BASELINE['native_run'] and run['run_attempt'] == BASELINE['native_attempt'] and
                   run['head_sha'] == BASELINE['candidate_sha'] and
                   run['repository']['id'] == run['head_repository']['id'] == repo_id and
                   run['path'] == '.github/workflows/ci.yml' and run['event'] == 'pull_request' and
                   run['workflow_id'] == policy.CI_WORKFLOW_ID and
                   run['status'] == 'completed' and run['conclusion'] == 'success', 'historical PR255 native gate did not pass')
    gate = policy.successful_job(reader.jobs(BASELINE['native_run'], BASELINE['native_attempt']), policy.GATE, BASELINE['candidate_sha'],
                                 ('Verify hosted jobs and authenticated exact-candidate quality',))
    policy.require(gate['id'] == PR255_NATIVE_JOB and gate['run_id'] == BASELINE['native_run'] and gate['run_attempt'] == BASELINE['native_attempt'] and
                   signed <= evidence.github_time(gate, 'started_at') <= evidence.github_time(gate, 'completed_at') <=
                   evidence.github_time(pr, 'merged_at') <= ref['identity']['release_expires_at'],
                   'PR255 native green and merge outside historical publication')
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
        policy.require(type(terminal_run) is int and terminal_run != consumer_run, 'separate controlled cancellation terminal required')
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
            'release_expires_at': identity['release_expires_at'], 'admission_id': 'pr278-controlled-reconcile-' + HEAD,
            'invocation': consumer_intent(reference['artifact'], identity['consumer_sha'], reference['nonce'])}


def verify(policy, reference, reader, fetch, terminal_run, now, *, active=False, staged_at=None):
    validate_reference(reference, now)
    policy.require(callable(fetch) and (active or terminal_run is not None), 'both reviewed controlled cancellation jobs required')
    done = verify_approvals(policy, reader, reference, terminal_run, now, active=active)
    if staged_at is not None:
        policy.require(done is not None and done <= staged_at <= now, 'controlled cancellation result staged before terminal completion')
    proof = historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    current_subject(policy, reader, reference['identity'])
    request = result(reference, terminal_run, proof)
    if terminal_run is None:
        request['schema'] = 'box-quality-controlled-reconcile-consumer/v28'
    return request


def prescreen(policy, artifact, reader, fetch):
    policy.require(canonical(artifact) == canonical(ARCHIVE) and callable(fetch), 'wrong controlled cancellation preflight artifact')
    current_subject(policy, reader, {'repository_id': 1423238398, 'head_repository_id': 1423238398, 'pull_number': PR,
                                    'base_sha': BASE, 'candidate_sha': HEAD})
    historical_baseline(policy, reader, fetch)
    validate_package(policy, fetch(ARCHIVE['commit']))
    return {'candidate_sha': HEAD, 'candidate_tree': TREE, 'baseline': BASELINE, 'hosted': HOSTED, 'artifact': artifact}


def private_fetch(policy, token):
    old_fetch = policy.hydra_birth_delta.private_fetch(policy, token)
    evidence = policy.consumer.evidence

    def fetch(commit):
        if commit != ARCHIVE['commit']:
            return old_fetch(commit)
        path = '/repos/' + evidence.EVIDENCE_REPOSITORY
        repo = policy.consumer.api(path, token)
        policy.require(repo['id'] == evidence.EVIDENCE_REPOSITORY_ID and
                       repo['full_name'] == evidence.EVIDENCE_REPOSITORY and repo['private'] is True,
                       'wrong private controlled cancellation evidence repository')
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
                   environment['GITHUB_SHA'] == environment['GITHUB_WORKFLOW_SHA'] == trusted, 'wrong native controlled cancellation dispatch')
    reference = evidence.decode(environment['BOX_FORMAL_ADMISSION'])
    run = int(environment['GITHUB_RUN_ID'])
    validate_reference(reference, int(clock()))
    policy.require(trusted == reference['identity']['consumer_sha'] and (run != reference['consumer_run']) == terminal,
                   'wrong protected controlled cancellation run')
    if terminal:
        for field, key in [('BOX_FORMAL_HOSTED_RUN_ID', 'run_id'), ('BOX_FORMAL_HOSTED_RUN_ATTEMPT', 'attempt'),
                           ('BOX_FORMAL_HOSTED_CI_BLOB', 'workflow_blob')]:
            policy.require(environment[field] == str(HOSTED[key]), 'wrong controlled cancellation hosted run pin')
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
    policy.reader_stage('r28_native_event')
    event = policy.ci_premerge_event(environment)
    policy.require(environment['GITHUB_EVENT_NAME'] == 'pull_request' and environment['GITHUB_RUN_ID'] == str(HOSTED['run_id'])
                   and event['number'] == PR and event['pull_request']['head']['sha'] == HEAD, 'wrong native controlled cancellation gate')
    policy.reader_stage('r28_c2_lookup')
    check = reader.formal_quality_check(HEAD)
    policy.reader_stage('r28_c2_decode')
    request = policy.consumer.evidence.decode(check['output']['text'])
    now = int(clock())
    reference = request['artifact']
    policy.reader_stage('r28_window')
    validate_reference(reference, now)
    policy.reader_stage('r28_native_merge_anchor')
    event = native_event_with_verified_base(policy, event, environment, reader)
    policy.reader_stage('r28_ci_binding')
    policy.validate_ci_evidence_reference(event, environment, reference['identity'])
    policy.reader_stage('r28_c2_authenticity')
    policy.validate_gate(check, request, completed=True)
    policy.reader_stage('r28_history')
    proof = historical_baseline(policy, reader)
    policy.reader_stage('r28_receipt_binding')
    terminal = request['terminal_run']
    policy.require(type(terminal) is int and check['id'] not in (C1, PR255_C2) and
                   policy.consumer.canonical(request) == policy.consumer.canonical(result(reference, terminal, proof)),
                   'controlled cancellation result differs from exact scope and subjects')
    policy.reader_stage('r28_approvals')
    done = verify_approvals(policy, reader, reference, terminal, now)
    policy.reader_stage('r28_publication_order')
    evidence = policy.consumer.evidence
    evidence.check_times(check, reference['identity'], now)
    policy.require(done <= evidence.github_time(check, 'started_at'), 'controlled cancellation signature predates second approval')
    policy.reader_stage('r28_current_candidate')
    current_subject(policy, reader, reference['identity'])
    policy.reader_stage('r28_premerge_readback')
    policy._resolve_ci_candidate(event, environment, reader)
    policy.reader_stage('r28_final_window')
    validate_reference(reference, int(clock()))
    return request
