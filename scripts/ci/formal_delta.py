"""One exact, reviewed test-only descendant of the already merged PR 258."""
from hashlib import sha256
import io
import json
from pathlib import Path
import re
import time
import urllib.request
import zipfile

REPO = '86669666/new-api'
REPO_ID = 1423238398
HEAD = '08c2a376c1a07e97fa2f563cefc900a0725c668e'
TREE = '700459b3f44a5c7d39256e4daf2b2d15d4794e16'
BASE = 'da720e95e6fb26a0f8acb7786fffdb1139f33f88'
OLD_HEAD = '1a4484ed147ffadd9d7bf4f4b1008288a9f360b4'
OLD_TREE = '8b73fe0849542170d45c5b8c256dc1a6c014bd9e'
OLD_BASE = 'f35809d09c7df46b3e98c6a8be656b3c40a5e40b'
OLD_CONTROL = '116aff28541e96b379109980571e222ac54fe050'
C1, OLD_C2 = 135232975120, 135347821719
OLD_A, OLD_B = 44459950392, 44460873572
OLD_GATE = 135348001368
OLD_PROOF = '81b95d7fe8fbdd5655b1271336b59c70260395dc1c6393c46b4b1bccc45f60b4'
HOSTED = dict(run_id=44466603451, attempt=1, workflow_blob='c123990e4a8c9fd981b721455a8edbc65b62dfc5')
CONTROL_REF = 'refs/heads/codex/formal-quality-r6'
REFERENCE_SCHEMA = 'box-formal-delta-ref/v6'
TERMINAL_SCHEMA = 'box-quality-terminal/v6'
ARCHIVE_PATH = 'formal-audit/pr262-08c2a376-specialized-evidence.zip'
ARCHIVE_SIZE = 13333
ARCHIVE_SHA = 'a913f74712e43f960d3c3bbdec4f06bf5c9cc9b35d26e11082da841b9325f53e'
MANIFEST_SHA = '389aaffb59867fc06a1752e949af77e63752752210eb0b405ea7b21fbeefb683'
PATCH_SHA = 'e6ab1a3dbcc628a5f772be00339d5e0b5cb6a61cea9f49a5e3c73921dfe6658b'
FILES = ['controller/access_token_audit_test.go', 'router/organization_creation_policy_test.go',
         'router/organization_lifecycle_test.go', 'router/quota_remaining_display_test.go']
BASELINE = dict(pull_number=258, candidate_sha=OLD_HEAD, candidate_tree=OLD_TREE, merge_commit=BASE,
                receipt_check_id=C1, terminal_check_id=OLD_C2, consumer_run=OLD_A, terminal_run=OLD_B,
                native_run=44403089902, native_attempt=2, native_job=OLD_GATE)
SCOPE = 'test-only-delta'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=True).encode('ascii')


def descriptor():
    value = json.loads(Path(__file__).with_name('delta262.json').read_bytes())
    need(type(value) is dict and set(value) == {'commit','path','bytes','sha256'} and
         type(value['commit']) is str and re.fullmatch('[0-9a-f]{40}',value['commit']) and
         value['path'] == ARCHIVE_PATH and type(value['bytes']) is int and value['bytes'] == ARCHIVE_SIZE and
         value['sha256'] == ARCHIVE_SHA, 'invalid pinned delta artifact')
    return value


def consumer_intent(artifact, control_sha, nonce):
    need(canonical(artifact) == canonical(descriptor()) and type(control_sha) is str and
         re.fullmatch('[0-9a-f]{40}',control_sha) and control_sha != OLD_CONTROL and
         type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce), 'invalid delta selection')
    value = dict(artifact=artifact, candidate_sha=HEAD, candidate_tree=TREE, baseline=BASELINE,
                 hosted=HOSTED, control_sha=control_sha, nonce=nonce)
    return sha256(canonical(value)).hexdigest()


def make_reference(artifact, control_sha, consumer_run, opened, nonce):
    consumer_intent(artifact, control_sha, nonce)
    need(type(consumer_run) is int and consumer_run > 0 and type(opened) is int and opened > 0,
         'invalid delta approval identity')
    identity = dict(repository=REPO, repository_id=REPO_ID, pull_number=262, head_repository_id=REPO_ID,
                    base_sha=BASE, candidate_sha=HEAD, candidate_tree=TREE, consumer_sha=control_sha,
                    release_not_before=opened, release_expires_at=opened+1800)
    return dict(schema=REFERENCE_SCHEMA,artifact=artifact,identity=identity,consumer_run=consumer_run,nonce=nonce)


def validate_reference(reference, now):
    identity = reference['identity']
    expected = make_reference(reference['artifact'],identity['consumer_sha'],reference['consumer_run'],
                              identity['release_not_before'],reference['nonce'])
    need(canonical(reference) == canonical(expected) and type(now) is int and
         identity['release_not_before'] <= now <= identity['release_expires_at'], 'invalid or expired delta reference')


def validate_package(artifact, raw):
    need(canonical(artifact) == canonical(descriptor()) and type(raw) is bytes and len(raw) == ARCHIVE_SIZE and
         sha256(raw).hexdigest() == ARCHIVE_SHA, 'specialized evidence bytes changed')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        data = archive.read('manifest.json')
        need(sha256(data).hexdigest() == MANIFEST_SHA, 'unreviewed delta manifest')
        manifest = json.loads(data)
        patch = manifest['patch']
        need(manifest['schema'] == 'pr262-specialized-evidence-delta/v1' and
             (manifest['repository'],manifest['issue_number'],manifest['pull_number']) == (REPO,259,262) and
             (manifest['head'],manifest['tree'],manifest['base_and_sole_parent']) == (HEAD,TREE,BASE) and
             patch['changed_files'] == FILES and patch['sha256'] == PATCH_SHA and
             sha256(archive.read(patch['member'])).hexdigest() == PATCH_SHA, 'wrong candidate patch or scope')
        rows = manifest['logs']
        members = {'manifest.json','INDEX.md',patch['member'],*(row['projection'] for row in rows)}
        need(len(rows) == 17 and len(members) == len(archive.namelist()) == 20 and
             members == set(archive.namelist()) and all(
                 sha256(archive.read(row['projection'])).hexdigest() == row['projection_sha256'] for row in rows),
             'delta observation inventory changed')
        need(manifest['selected_test_or_leaf_records'] == 25 and manifest['pass_records_including_descendants'] == 61 and
             len(manifest['checkpoint_open_items']) == 5 and len(manifest['nonpass_context']) == 3,
             'specialized observation scope changed')
    return manifest


def current_subject(policy, reader, identity):
    repo = reader.repository()
    pr = reader.pull(262)
    need(repo['id'] == REPO_ID and repo['full_name'] == REPO and pr['number'] == 262 and
         pr['state'] == 'open' and pr['merged'] is False and pr['changed_files'] == 4 and
         pr['head']['repo']['id'] == pr['base']['repo']['id'] == REPO_ID and
         pr['head']['repo']['full_name'] == pr['base']['repo']['full_name'] == REPO and
         pr['head']['sha'] == HEAD and pr['base']['sha'] == BASE and pr['base']['ref'] == 'main',
         'current four-file PR subject changed')
    commit = reader.commit(HEAD)
    need(commit['sha'] == HEAD and commit['tree']['sha'] == TREE and
         [row['sha'] for row in commit['parents']] == [BASE], 'wrong tested delta tree or parent')
    policy.verify_hosted_jobs(reader,HOSTED,identity)


def historical_baseline(policy, reader, fetch=None):
    evidence = policy.consumer.evidence
    check = reader.check(OLD_C2)
    proof = evidence.decode(check['output']['text'])
    need(check['id'] == OLD_C2 and policy.consumer.digest(proof) == OLD_PROOF and
         proof['schema'] == policy.TERMINAL_SCHEMA_V5 and proof['candidate_sha'] == OLD_HEAD and
         proof['candidate_tree'] == OLD_TREE and proof['check_run_id'] == C1 and
         proof['consumer_run'] == OLD_A and proof['terminal_run'] == OLD_B, 'wrong signed historical baseline')
    signed = evidence.github_time(check,'completed_at')
    policy.validate_gate(check,proof,completed=True)
    ref = proof['artifact']
    evidence.validate_reference(ref,signed)
    need(ref['identity']['consumer_sha'] == OLD_CONTROL, 'wrong historical control')
    c1, _ = policy.historical_receipt_check(reader,ref)
    need(c1['external_id'] == proof['receipt_sha256'], 'wrong historical receipt digest')
    b_done = policy.verify_reuse_approvals(reader,ref,proof['hosted'],proof['quality_sha256'],signed,OLD_B)
    need(b_done <= evidence.github_time(check,'started_at'), 'historical check preceded its reviews')
    pr = reader.pull(258)
    merge = reader.commit(BASE)
    source = reader.commit(OLD_HEAD)
    need(pr['number'] == 258 and pr['merged'] is True and pr['state'] == 'closed' and
         pr['merge_commit_sha'] == BASE and pr['head']['sha'] == OLD_HEAD and pr['base']['ref'] == 'main' and
         pr['base']['repo']['id'] == REPO_ID and merge['sha'] == BASE and source['sha'] == OLD_HEAD and
         merge['tree']['sha'] == source['tree']['sha'] == OLD_TREE and
         [p['sha'] for p in merge['parents']] == [OLD_BASE,OLD_HEAD], 'historical merge or tree changed')
    run = reader.run(BASELINE['native_run'],2)
    need(run['id'] == BASELINE['native_run'] and run['run_attempt'] == 2 and run['head_sha'] == OLD_HEAD and
         run['repository']['id'] == REPO_ID and run['event'] == 'pull_request' and
         run['workflow_id'] == policy.CI_WORKFLOW_ID and run['status'] == 'completed' and
         run['conclusion'] == 'success', 'historical native run did not pass')
    gate = policy.successful_job(reader.jobs(BASELINE['native_run'],2),policy.GATE,OLD_HEAD,
                                 ('Verify hosted jobs and authenticated exact-candidate quality',))
    need(gate['id'] == OLD_GATE and gate['run_id'] == BASELINE['native_run'] and gate['run_attempt'] == 2 and
         signed <= evidence.github_time(gate,'started_at') <= evidence.github_time(gate,'completed_at') <=
         evidence.github_time(pr,'merged_at') <= ref['identity']['release_expires_at'], 'wrong historical native gate or merge order')
    if fetch is not None:
        admission, receipt = policy.load_reused_evidence(ref,reader,fetch)
        need(admission['receipt_sha256'] == proof['receipt_sha256'] and
             policy.consumer.digest(receipt['quality']) == proof['quality_sha256'], 'historical private quality differs from signed result')
    return proof


def verify_approvals(policy, reader, reference, terminal_run, now, *, active=False):
    binding = reference['identity']
    a = reference['consumer_run']
    title = 'Formal delta ' + consumer_intent(reference['artifact'],binding['consumer_sha'],reference['nonce'])
    done = policy.verify_reviewed_dispatch(reader,a,binding,policy.CONSUMER_JOB,active=terminal_run is None and active,
                                          title=title,now=now,exact_start=binding['release_not_before'],control_ref=CONTROL_REF)
    if terminal_run is not None:
        need(type(terminal_run) is int and terminal_run > 0 and a != terminal_run, 'separate delta terminal required')
        title = policy.terminal_run_title(reference,C1,a,HOSTED,ARCHIVE_SHA)
        return policy.verify_reviewed_dispatch(reader,terminal_run,binding,policy.TERMINAL_JOB,active=active,
                                              title=title,now=now,after=done,control_ref=CONTROL_REF)


def result(reference, terminal_run, proof):
    identity = reference['identity']
    return dict(schema=TERMINAL_SCHEMA,name='Box formal quality result',artifact=reference,quality_sha256=ARCHIVE_SHA,
                candidate_sha=HEAD,candidate_tree=TREE,repository=REPO,repository_id=REPO_ID,baseline=BASELINE,scope=SCOPE,
                check_run_id=C1,receipt_sha256=proof['receipt_sha256'],consumer_run=reference['consumer_run'],
                terminal_run=terminal_run,hosted=HOSTED,expires_at=identity['release_expires_at'],
                release_not_before=identity['release_not_before'],release_expires_at=identity['release_expires_at'],
                admission_id='pr262-delta-'+HEAD,invocation=consumer_intent(reference['artifact'],identity['consumer_sha'],reference['nonce']))


def verify(policy, reference, reader, fetch, terminal_run, now, *, active=False, staged_at=None):
    validate_reference(reference,now)
    need(callable(fetch) and (active or terminal_run is not None), 'private evidence and both completed reviews required')
    done = verify_approvals(policy,reader,reference,terminal_run,now,active=active)
    if staged_at is not None:
        need(done is not None and done <= staged_at <= now, 'C2 staged before delta terminal completion')
    proof = historical_baseline(policy,reader,fetch)
    validate_package(reference['artifact'],fetch(reference['artifact']['commit']))
    current_subject(policy,reader,reference['identity'])
    request = result(reference,terminal_run,proof)
    if terminal_run is None:
        request['schema'] = 'box-quality-delta-consumer/v6'
    return request


def prescreen(policy, artifact, reader, fetch):
    """Inspect both immutable materials and both candidate subjects before opening A."""
    need(canonical(artifact) == canonical(descriptor()) and callable(fetch), 'wrong preflight artifact')
    current_subject(policy,reader,dict(candidate_sha=HEAD,repository_id=REPO_ID,head_repository_id=REPO_ID,
                                       base_sha=BASE,pull_number=262))
    historical_baseline(policy,reader,fetch)
    validate_package(artifact,fetch(artifact['commit']))
    return dict(candidate_sha=HEAD,candidate_tree=TREE,baseline=BASELINE,hosted=HOSTED,artifact=artifact)


def private_fetch(policy, token):
    """Return a read callback for the two fixed paths in the single private evidence repository."""
    evidence = policy.consumer.evidence
    pin = descriptor()
    need(type(token) is str and token, 'private evidence read credential required')

    def fetch(commit):
        if commit == evidence.REUSE_COMMIT:
            return policy.consumer.read_private_evidence(commit,token)
        need(commit == pin['commit'], 'unknown private delta commit')
        path = '/repos/'+evidence.EVIDENCE_REPOSITORY
        repo = policy.consumer.api(path,token)
        need(repo['id'] == evidence.EVIDENCE_REPOSITORY_ID and repo['full_name'] == evidence.EVIDENCE_REPOSITORY and
             repo['private'] is True, 'wrong private delta repository')
        request = urllib.request.Request('https://api.github.com'+path+'/contents/'+ARCHIVE_PATH+'?ref='+commit,
            method='GET',headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github.raw+json',
                                  'X-GitHub-Api-Version':'2022-11-28'})
        with urllib.request.build_opener(policy.consumer.NoRedirect).open(request,timeout=30) as response:
            return response.read(pin['bytes']+1)
    return fetch


def verify_dispatch(policy, environment, *, terminal, clock=time.time):
    evidence = policy.consumer.evidence
    trusted = environment['BOX_FORMAL_CONSUMER_SHA']
    need(environment['GITHUB_EVENT_NAME'] == 'workflow_dispatch' and environment['GITHUB_REF'] == CONTROL_REF and
         environment['GITHUB_REPOSITORY'] == REPO and environment['GITHUB_REPOSITORY_ID'] == str(REPO_ID) and
         environment['GITHUB_WORKFLOW_REF'] == REPO+'/'+evidence.WORKFLOW_PATH+'@'+CONTROL_REF and
         environment['GITHUB_RUN_ATTEMPT'] == '1' and environment['GITHUB_ACTOR_ID'] == str(evidence.TRIGGER_ID) and
         environment['GITHUB_SHA'] == environment['GITHUB_WORKFLOW_SHA'] == trusted,
         'wrong native delta dispatch')
    ref = evidence.decode(environment['BOX_FORMAL_ADMISSION'])
    now = int(clock())
    validate_reference(ref,now)
    a, run = ref['consumer_run'], int(environment['GITHUB_RUN_ID'])
    need(trusted == ref['identity']['consumer_sha'] and ((run != a) if terminal else (run == a)),
         'wrong current delta review run')
    for field, key in [('BOX_FORMAL_HOSTED_RUN_ID','run_id'),('BOX_FORMAL_HOSTED_RUN_ATTEMPT','attempt'),
                       ('BOX_FORMAL_HOSTED_CI_BLOB','workflow_blob')]:
        need(field not in environment or environment[field] == str(HOSTED[key]), 'wrong requested hosted run')
    reader = policy.GitHubReader(environment['GITHUB_TOKEN'])
    verify_approvals(policy,reader,ref,run if terminal else None,now,active=True)
    token = environment.get('BOX_FORMAL_EVIDENCE_TOKEN')
    need(token and token != environment['GITHUB_TOKEN'], 'dedicated private evidence read credential required')
    output = verify(policy,ref,reader,private_fetch(policy,token),run if terminal else None,int(clock()),active=True)
    validate_reference(ref,int(clock()))
    return output


def verify_public(policy, environment, reader, *, clock=time.time):
    event = policy.ci_premerge_event(environment)
    need(environment['GITHUB_EVENT_NAME'] == 'pull_request' and environment['GITHUB_RUN_ID'] == str(HOSTED['run_id'])
         and event['number'] == 262 and event['pull_request']['head']['sha'] == HEAD, 'wrong native delta quality gate')
    check = reader.formal_quality_check(HEAD)
    request = policy.consumer.evidence.decode(check['output']['text'])
    now = int(clock())
    ref = request['artifact']
    validate_reference(ref,now)
    policy.validate_ci_evidence_reference(event,environment,ref['identity'])
    policy.validate_gate(check,request,completed=True)
    proof = historical_baseline(policy,reader)
    b = request['terminal_run']
    need(type(b) is int and b > 0 and check['id'] not in (C1,OLD_C2) and
         canonical(request) == canonical(result(ref,b,proof)), 'delta result differs from its exact scope and subjects')
    done = verify_approvals(policy,reader,ref,b,now)
    policy.consumer.evidence.check_times(check,ref['identity'],now)
    need(done <= policy.consumer.evidence.github_time(check,'started_at'), 'delta check predates second approval')
    current_subject(policy,reader,ref['identity'])
    policy.resolve_ci_candidate(environment,reader)
    validate_reference(ref,int(clock()))
    return request
