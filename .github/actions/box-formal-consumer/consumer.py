"""Validate an App-authenticated receipt against an operator-controlled admission."""
import hashlib
import importlib.util
import json
import os
import re
import time
import urllib.request
from pathlib import Path

_spec = importlib.util.spec_from_file_location('_formal_evidence', Path(__file__).with_name('evidence.py'))
evidence = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(evidence)


APP = 5498942
INSTALLATION = 175905031
REPOSITORY = '86669666/new-api'
CHECK = 'Box formal verification'
# Fixed contract inventory; an admission may bind details but cannot change it.
FORMAL_TIERS = frozenset(('postgres', 'postgres-redis', 'wallet-sqlite', 'wallet-mysql',
                          'wallet-postgres', 'lifecycle-sqlite', 'lifecycle-mysql',
                          'lifecycle-postgres', 'sqlite'))
PINS = {'postgres': 'sha256:85b1ab67e7c7410b11da3f5b42913fc51b5b46f9cf5f07cc28a98e5f62083c5e',
        'mysql': 'sha256:d78bbb8f2cfdeb362aff7fcbea6b7954bef6429bef26b308f0e65ca5d9410482'}
MIGRATED_PINS = {
    'postgres': 'sha256:94bd3af0fdb294cd2c40005951b0b1ad62bd79e058983909628bec4f2b35b313',
    'mysql': 'sha256:5022666e28e408728a872246e5b6478d9177a80e12b881d6f3983568891f1cb0',
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_receipt(receipt, admission, now, *, private=False):
    expected = admission['expected']
    require(admission['active'] is True, 'inactive admission')
    require(admission['repository'] == REPOSITORY, 'repository mismatch')
    require(admission['app_id'] == APP and admission['installation_id'] == INSTALLATION,
            'publisher mismatch')
    require(canonical(receipt['binding']) == canonical(expected), 'admission binding mismatch')
    for name in ('candidate_sha', 'candidate_tree', 'execution_sha', 'consumer_sha'):
        require(re.fullmatch('[0-9a-f]{40}', expected[name]) is not None, 'invalid git identity')
    for name in ('runner_sha256', 'wrapper_sha256', 'producer_sha256', 'source_manifest_sha256',
                 'assets_sha256', 'toolchain_sha256', 'module_sha256', 'manifest_sha256'):
        require(re.fullmatch('[0-9a-f]{64}', expected[name]) is not None, 'invalid artifact identity')
    require(expected['candidate_sha'] == expected['execution_sha'], 'build and execution SHA differ')
    require(expected['images'] == PINS or (private and expected['images'] == MIGRATED_PINS),
            'unapproved images')
    require(expected['platform'] == 'linux/amd64', 'platform mismatch')
    require(expected['attempt_id'] and expected['admission_id'] and expected['invocation'], 'missing attempt')
    require(expected['test_binaries'] and all(re.fullmatch('[0-9a-f]{64}', v)
            for v in expected['test_binaries'].values()), 'missing test identities')
    require(all(type(value) is int for value in (expected['not_before'], expected['expires_at'],
            receipt['started_at'], receipt['completed_at'], now)), 'invalid receipt times')
    if private and evidence.uses_release_window(admission):
        window = evidence.release_times(expected, receipt)
        require(window['release_not_before'] <= now <= window['release_expires_at'], 'expired formal release')
    else:
        require(expected['not_before'] <= receipt['started_at'] <= receipt['completed_at'] <= now
                <= expected['expires_at'], 'stale or future receipt')
    require(type(receipt['process_exit']) is int and type(receipt['exit']) is int
            and receipt['process_exit'] == 0 and receipt['exit'] == 0
            and receipt['cleanup'] is True and receipt['unexecuted'] == [], 'incomplete execution')
    plan = expected['tiers']
    require(set(plan) == FORMAL_TIERS, 'required formal tier inventory changed')
    require(len(receipt['tiers']) == len(plan), 'missing or duplicate tier')
    seen = set()
    for tier in receipt['tiers']:
        name = tier['tier']
        require(name in plan and name not in seen, 'unexpected or duplicate tier')
        seen.add(name)
        require(type(tier['exit']) is int and tier['exit'] == 0 and tier['cleanup'] is True, 'failed tier')
        require(tier['invocation'] == expected['invocation'], 'replayed tier')
        require(tier['entries'] == plan[name]['entries'] and
                tier['required_leaves'] == plan[name]['required_leaves'], 'partial tier inventory')
        require(tier['manifest_sha256'] == plan[name]['manifest_sha256'], 'tier manifest mismatch')
        require(re.fullmatch('[0-9a-f]{64}', tier['log_sha256']) is not None, 'invalid log hash')
    return digest(receipt)


def validate_execution_capture(receipt, admission):
    """Validate historical root capture data; this does not authorize any publication."""
    require('quality' not in receipt and 'quality' not in admission, 'unannotated root capture required')
    evidence.release_times(admission['expected'], receipt)
    return validate_receipt(receipt, admission, receipt['completed_at'], private=True)


def unique_json_fields(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate receipt field')
        result[key] = value
    return result


def validate_check(check, receipt, admission, now, *, reference=None):
    parsed = evidence.decode(check['output']['text'])
    published = receipt if reference is None else reference
    require(canonical(parsed) == canonical(published), 'receipt differs from check output')
    receipt_hash = validate_receipt(receipt, admission, now, private=reference is not None)
    require(check['app']['id'] == APP and check['app']['slug'] == 'new-api-box-formal', 'wrong App')
    require(type(admission['check_run_id']) is int and admission['check_run_id'] > 0
            and type(check['id']) is int and check['id'] == admission['check_run_id'],
            'wrong check or replay')
    require(check['name'] == CHECK and check['head_sha'] == admission['expected']['execution_sha'],
            'wrong check candidate')
    require(check['status'] == 'completed' and check['conclusion'] == 'success', 'check not successful')
    require(check['external_id'] == receipt_hash == admission['receipt_sha256'], 'receipt hash mismatch')
    if reference is not None and reference['schema'] == evidence.REFERENCE_SCHEMA_V4:
        evidence.validate_reference(reference, now)
        require(canonical(reference['identity']) == canonical(evidence.identity(admission, receipt)),
                'receipt release identity differs from signed reference')
        evidence.check_times(check, reference['identity'], now)
    return receipt_hash


def validate_evidence_check(check, admission, now, bundle=None):
    if bundle is None:
        receipt, reference = evidence.decode(check['output']['text']), None
    else:
        receipt, reference = bundle
    return receipt, validate_check(check, receipt, admission, now, reference=reference)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('API redirect refused')


def api(path, token):
    require(path.startswith('/') and not path.startswith('//'), 'invalid API path')
    request = urllib.request.Request('https://api.github.com' + path,
        method='GET',
        headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
                 'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json'})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
        return json.load(response)


def read_private_evidence(commit, token):
    repository_path = '/repos/' + evidence.EVIDENCE_REPOSITORY
    repo = api(repository_path, token)
    require(repo.get('private') is True and repo.get('id') == evidence.EVIDENCE_REPOSITORY_ID and
            repo.get('full_name') == evidence.EVIDENCE_REPOSITORY, 'untrusted evidence repository')
    require(re.fullmatch('[0-9a-f]{40}', commit) is not None, 'invalid evidence revision')
    request = urllib.request.Request(
        'https://api.github.com' + repository_path + '/contents/' + evidence.EVIDENCE_PATH + '?ref=' + commit,
        headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github.raw+json',
                 'X-GitHub-Api-Version': '2022-11-28'})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
        return response.read(evidence.MAX_ARTIFACT_BYTES + 1)


def configured_evidence(environment, now, *, check_identity=None):
    record = json.loads(environment['BOX_FORMAL_ADMISSION'], object_pairs_hook=unique_json_fields,
                        parse_constant=evidence.reject_constant)
    require(type(record) is dict, 'invalid formal admission')
    require(environment.get('GITHUB_REF') != 'refs/heads/codex/formal-quality-r3',
            'r3 evidence requires its original reader')
    if 'schema' not in record:
        require(environment.get('GITHUB_REF') != evidence.CONTROL_REF_V4, 'v4 protected configuration required')
        return record, None
    require(record['schema'] in (evidence.CONFIG_SCHEMA, evidence.CONFIG_SCHEMA_V4), 'unknown formal configuration')
    if check_identity is None:
        require((environment.get('GITHUB_REF') == evidence.CONTROL_REF_V4) ==
                (record['schema'] == evidence.CONFIG_SCHEMA_V4), 'wrong protected configuration version')
    require(environment.get('GITHUB_REPOSITORY') == REPOSITORY, 'wrong repository')

    def check_consumer_identity(binding):
        trusted = trusted_consumer_context(environment, private=True)
        native_id = environment['GITHUB_REPOSITORY_ID']
        require(re.fullmatch('[1-9][0-9]*', native_id) is not None and
                type(binding['repository_id']) is int and binding['repository_id'] == int(native_id) and
                binding['repository'] == REPOSITORY and binding['consumer_sha'] == trusted and
                environment['GITHUB_WORKFLOW_REF'] == REPOSITORY + '/' + evidence.WORKFLOW_PATH +
                '@' + environment['GITHUB_REF'],
                'private evidence does not match protected consumer context')

    def fetch(commit):
        token = environment.get('BOX_FORMAL_EVIDENCE_TOKEN')
        require(token and token != environment.get('GITHUB_TOKEN'), 'private evidence read credential required')
        return read_private_evidence(commit, token)

    return evidence.resolve_configuration(record, fetch, now, check_identity or check_consumer_identity)


def trusted_consumer_context(environment, *, private=False):
    require(environment['GITHUB_REPOSITORY'] == REPOSITORY, 'wrong repository')
    require(environment['GITHUB_EVENT_NAME'] == 'workflow_dispatch', 'manual admission only')
    refs = ('refs/heads/main', evidence.CONTROL_REF, evidence.CONTROL_REF_V4) if private else ('refs/heads/main',)
    require(environment['GITHUB_REF'] in refs, 'protected consumer ref required')
    trusted = environment['BOX_FORMAL_CONSUMER_SHA']
    require(re.fullmatch('[0-9a-f]{40}', trusted) is not None, 'immutable consumer SHA required')
    require(trusted == environment['GITHUB_WORKFLOW_SHA'], 'unapproved workflow revision')
    if environment['GITHUB_REF'] in (evidence.CONTROL_REF, evidence.CONTROL_REF_V4):
        require(environment['GITHUB_SHA'] == trusted and environment['GITHUB_RUN_ATTEMPT'] == '1' and
                environment['GITHUB_ACTOR_ID'] == str(evidence.TRIGGER_ID), 'wrong native dispatch identity')
    return trusted


def validate_environment(environment, admission, now, *, private=False, receipt=None):
    trusted = trusted_consumer_context(environment, private=private)
    require(trusted == admission['expected']['consumer_sha'], 'unapproved workflow revision')
    require(admission['active'] is True and admission['repository'] == REPOSITORY,
            'inactive or foreign admission')
    require(admission['app_id'] == APP and admission['installation_id'] == INSTALLATION,
            'wrong admitted publisher')
    if private and evidence.uses_release_window(admission):
        window = evidence.release_times(admission['expected'], receipt)
        require(window['release_not_before'] <= now <= window['release_expires_at'], 'expired formal release')
    else:
        require(admission['expected']['not_before'] <= now <= admission['expected']['expires_at'],
                'expired or future admission')
    require(type(admission['check_run_id']) is int and admission['check_run_id'] > 0,
            'published check ID required')
    require(re.fullmatch('[0-9a-f]{64}', admission['receipt_sha256']) is not None,
            'finalized receipt hash required')


def main():
    admission, bundle = configured_evidence(os.environ, int(time.time()))
    validate_environment(os.environ, admission, int(time.time()), private=bundle is not None,
                         receipt=bundle[0] if bundle else None)
    token = os.environ['GITHUB_TOKEN']
    check_id = admission['check_run_id']
    require(type(check_id) is int and check_id > 0, 'invalid check ID')
    repo = api('/repos/' + REPOSITORY, token)
    require(repo['id'] == admission['repository_id'], 'repository ID mismatch')
    check = api('/repos/' + REPOSITORY + '/check-runs/' + str(check_id), token)
    validate_evidence_check(check, admission, int(time.time()), bundle)
    commit = api('/repos/' + REPOSITORY + '/git/commits/' + admission['expected']['execution_sha'], token)
    require(commit['sha'] == admission['expected']['execution_sha'] and
            commit['tree']['sha'] == admission['expected']['candidate_tree'], 'remote commit or tree mismatch')
    print('Authenticated exact-candidate box receipt verified; no integration authorization granted.')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Never print response bodies, credentials, or arbitrary receipt payloads.
        raise SystemExit('Box receipt rejected; inspect sanitized admission and identity evidence.')
