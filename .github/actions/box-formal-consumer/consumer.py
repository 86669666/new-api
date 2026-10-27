"""Validate an App-authenticated receipt against an operator-controlled admission."""
import hashlib
import json
import os
import re
import time
import urllib.request

APP = 5498942
INSTALLATION = 175905031
REPOSITORY = '86669666/new-api'
CHECK = 'Box formal verification'
PINS = {'postgres': 'sha256:85b1ab67e7c7410b11da3f5b42913fc51b5b46f9cf5f07cc28a98e5f62083c5e',
        'mysql': 'sha256:d78bbb8f2cfdeb362aff7fcbea6b7954bef6429bef26b308f0e65ca5d9410482'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_receipt(receipt, admission, now):
    expected = admission['expected']
    require(admission['active'] is True, 'inactive admission')
    require(admission['repository'] == REPOSITORY, 'repository mismatch')
    require(admission['app_id'] == APP and admission['installation_id'] == INSTALLATION,
            'publisher mismatch')
    require(receipt['binding'] == expected, 'admission binding mismatch')
    for name in ('candidate_sha', 'candidate_tree', 'execution_sha', 'consumer_sha'):
        require(re.fullmatch('[0-9a-f]{40}', expected[name]) is not None, 'invalid git identity')
    for name in ('runner_sha256', 'wrapper_sha256', 'producer_sha256', 'source_manifest_sha256',
                 'assets_sha256', 'toolchain_sha256', 'module_sha256', 'manifest_sha256'):
        require(re.fullmatch('[0-9a-f]{64}', expected[name]) is not None, 'invalid artifact identity')
    require(expected['candidate_sha'] == expected['execution_sha'], 'build and execution SHA differ')
    require(expected['images'] == PINS, 'unapproved images')
    require(expected['platform'] == 'linux/amd64', 'platform mismatch')
    require(expected['attempt_id'] and expected['admission_id'] and expected['invocation'], 'missing attempt')
    require(expected['test_binaries'] and all(re.fullmatch('[0-9a-f]{64}', v)
            for v in expected['test_binaries'].values()), 'missing test identities')
    require(expected['not_before'] <= receipt['started_at'] <= receipt['completed_at'] <= now
            <= expected['expires_at'], 'stale or future receipt')
    require(receipt['process_exit'] == 0 and receipt['exit'] == 0
            and receipt['cleanup'] is True and receipt['unexecuted'] == [], 'incomplete execution')
    plan = expected['tiers']
    require(plan and len(receipt['tiers']) == len(plan), 'missing or duplicate tier')
    seen = set()
    for tier in receipt['tiers']:
        name = tier['tier']
        require(name in plan and name not in seen, 'unexpected or duplicate tier')
        seen.add(name)
        require(tier['exit'] == 0 and tier['cleanup'] is True, 'failed tier')
        require(tier['invocation'] == expected['invocation'], 'replayed tier')
        require(tier['entries'] == plan[name]['entries'] and
                tier['required_leaves'] == plan[name]['required_leaves'], 'partial tier inventory')
        require(tier['manifest_sha256'] == plan[name]['manifest_sha256'], 'tier manifest mismatch')
        require(re.fullmatch('[0-9a-f]{64}', tier['log_sha256']) is not None, 'invalid log hash')
    return digest(receipt)


def validate_check(check, receipt, admission, now):
    receipt_hash = validate_receipt(receipt, admission, now)
    require(check['app']['id'] == APP and check['app']['slug'] == 'new-api-box-formal', 'wrong App')
    require(check['id'] == admission['check_run_id'], 'wrong check or replay')
    require(check['name'] == CHECK and check['head_sha'] == admission['expected']['execution_sha'],
            'wrong check candidate')
    require(check['status'] == 'completed' and check['conclusion'] == 'success', 'check not successful')
    require(check['external_id'] == receipt_hash == admission['receipt_sha256'], 'receipt hash mismatch')
    return receipt_hash


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('API redirect refused')


def api(path, token, method='GET', payload=None):
    require(path.startswith('/') and not path.startswith('//'), 'invalid API path')
    request = urllib.request.Request('https://api.github.com' + path,
        data=None if payload is None else canonical(payload), method=method,
        headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
                 'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json'})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
        return json.load(response)


def main():
    admission = json.loads(os.environ['BOX_FORMAL_ADMISSION'])
    require(os.environ['GITHUB_REPOSITORY'] == REPOSITORY, 'wrong repository')
    require(os.environ['GITHUB_WORKFLOW_SHA'] == admission['expected']['consumer_sha'],
            'unapproved workflow revision')
    token = os.environ['GITHUB_TOKEN']
    check_id = admission['check_run_id']
    require(type(check_id) is int and check_id > 0, 'invalid check ID')
    repo = api('/repos/' + REPOSITORY, token)
    require(repo['id'] == admission['repository_id'], 'repository ID mismatch')
    check = api('/repos/' + REPOSITORY + '/check-runs/' + str(check_id), token)
    receipt = json.loads(check['output']['text'])
    validate_check(check, receipt, admission, int(time.time()))
    commit = api('/repos/' + REPOSITORY + '/git/commits/' + admission['expected']['execution_sha'], token)
    require(commit['tree']['sha'] == admission['expected']['candidate_tree'], 'remote tree mismatch')
    print('Authenticated exact-candidate box receipt verified; no integration authorization granted.')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Never print response bodies, credentials, or arbitrary receipt payloads.
        raise SystemExit('Box receipt rejected; inspect sanitized admission and identity evidence.')
