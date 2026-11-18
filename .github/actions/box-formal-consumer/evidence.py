"""Versioned exact-byte references for formal evidence kept in a private repository."""
from datetime import datetime, timezone
from hashlib import sha256
import json
import re

EVIDENCE_REPOSITORY = '86669666/new-api-formal-evidence'
EVIDENCE_REPOSITORY_ID = 1462093892
EVIDENCE_PATH = 'formal-evidence.json'
REFERENCE_SCHEMA = 'box-formal-evidence-ref/v2'
ARTIFACT_SCHEMA = 'box-formal-evidence/v2'
CONFIG_SCHEMA = 'box-formal-evidence-config/v2'
REFERENCE_SCHEMA_V4 = 'box-formal-evidence-ref/v4'
ARTIFACT_SCHEMA_V4 = 'box-formal-evidence/v4'
CONFIG_SCHEMA_V4 = 'box-formal-evidence-config/v4'
EXECUTION_SECONDS = 10_800
RELEASE_SECONDS = 1800
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
WORKFLOW_PATH = '.github/workflows/box-formal-receipt.yml'
CONTROL_REF = 'refs/heads/codex/formal-quality-r2'
CONTROL_REF_V4 = 'refs/heads/codex/formal-quality-r4'
TRIGGER_ID = 358061300


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def unique_fields(pairs):
    fields = {}
    for name, value in pairs:
        require(name not in fields, 'duplicate formal evidence field')
        fields[name] = value
    return fields


def reject_constant(_):
    raise ValueError('invalid formal evidence JSON constant')


def decode(data):
    return json.loads(data, object_pairs_hook=unique_fields, parse_constant=reject_constant)


def uses_release_window(admission):
    ref = admission.get('quality', {}).get('workflow', {}).get('ref')
    require(ref != 'refs/heads/codex/formal-quality-r3', 'r3 evidence requires its original reader')
    return ref == CONTROL_REF_V4


def release_times(expected, receipt):
    start, end = expected['not_before'], expected['expires_at']
    began, done = receipt['started_at'], receipt['completed_at']
    require(all(type(x) is int for x in (start, end, began, done)) and
            end - start == EXECUTION_SECONDS and start <= began <= done <= end,
            'invalid formal execution interval')
    return {'release_not_before': done, 'release_expires_at': done + RELEASE_SECONDS}


def github_time(record, field):
    value = record.get(field)
    require(type(value) is str and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', value),
            'missing or invalid GitHub timestamp: ' + field)
    return int(datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp())


def check_times(check, binding, now, *, completed=True):
    started = github_time(check, 'started_at')
    require(binding['release_not_before'] <= started <= now <= binding['release_expires_at'],
            'signed check outside release window')
    if completed:
        finished = github_time(check, 'completed_at')
        require(started <= finished <= now, 'signed check completion outside release window')
        return finished
    require(check.get('completed_at') is None, 'staged check already completed')
    return started


def identity(admission, receipt=None):
    expected = admission['expected']
    quality = admission['quality']
    binding = {
        'repository': admission['repository'],
        'repository_id': admission['repository_id'],
        'pull_number': quality['pull_number'],
        'head_repository_id': quality['head_repository_id'],
        'consumer_sha': expected['consumer_sha'],
        'base_sha': quality['base_sha'],
        'candidate_sha': expected['candidate_sha'],
        'candidate_tree': expected['candidate_tree'],
        'admission_id': expected['admission_id'],
        'attempt_id': expected['attempt_id'],
        'invocation': expected['invocation'],
        'not_before': expected['not_before'],
        'expires_at': expected['expires_at'],
    }
    if uses_release_window(admission):
        require(type(receipt) is dict, 'v4 identity requires the root execution receipt')
        binding.update(release_times(expected, receipt))
    return binding


def encode_artifact(admission, receipt):
    require('check_run_id' not in admission and 'quality_check_run_id' not in admission,
            'check IDs belong to the protected evidence configuration')
    require(canonical(admission['expected']) == canonical(receipt['binding']) and
            canonical(admission['quality']) == canonical(receipt['quality']),
            'receipt differs from formal evidence admission')
    require(admission.get('receipt_sha256') == sha256(canonical(receipt)).hexdigest(),
            'unbound formal receipt digest')
    schema = ARTIFACT_SCHEMA
    if uses_release_window(admission):
        release_times(admission['expected'], receipt)
        schema = ARTIFACT_SCHEMA_V4
    data = canonical({'schema': schema, 'admission': admission, 'receipt': receipt})
    require(len(data) <= MAX_ARTIFACT_BYTES, 'formal evidence artifact exceeds size limit')
    return data


def make_reference(commit, artifact_bytes, admission):
    v4 = uses_release_window(admission)
    artifact = decode(artifact_bytes)
    require(artifact['schema'] == (ARTIFACT_SCHEMA_V4 if v4 else ARTIFACT_SCHEMA),
            'artifact and admission versions differ')
    if v4:
        require(canonical(artifact['admission']) == canonical(admission) and
                artifact_bytes == encode_artifact(admission, artifact['receipt']),
                'v4 reference requires the finalized canonical artifact')
    binding = identity(admission, artifact['receipt'])
    reference = {'schema': REFERENCE_SCHEMA_V4 if v4 else REFERENCE_SCHEMA, 'commit': commit, 'bytes': len(artifact_bytes),
                 'sha256': sha256(artifact_bytes).hexdigest(), 'identity': binding}
    validate_reference(reference, binding['release_not_before'] if v4 else binding['not_before'])
    return reference


def validate_reference(reference, now):
    require(type(reference) is dict and set(reference) == {'schema', 'commit', 'bytes', 'sha256', 'identity'}
            and reference['schema'] in (REFERENCE_SCHEMA, REFERENCE_SCHEMA_V4), 'invalid formal evidence reference')
    require(type(reference['commit']) is str and type(reference['sha256']) is str and
            re.fullmatch('[0-9a-f]{40}', reference['commit']) is not None and
            re.fullmatch('[0-9a-f]{64}', reference['sha256']) is not None,
            'formal evidence requires an immutable commit and digest')
    require(type(reference['bytes']) is int and 0 < reference['bytes'] <= MAX_ARTIFACT_BYTES,
            'invalid formal evidence size')
    binding = reference['identity']
    require(type(binding) is dict and type(now) is int, 'invalid formal evidence identity or clock')
    start, end = binding['not_before'], binding['expires_at']
    require(type(start) is int and type(end) is int, 'invalid formal execution bounds')
    if reference['schema'] == REFERENCE_SCHEMA_V4:
        opened, expires = binding['release_not_before'], binding['release_expires_at']
        require(type(opened) is int and type(expires) is int and
                end - start == EXECUTION_SECONDS and start <= opened <= end and
                expires == opened + RELEASE_SECONDS, 'invalid formal release interval')
        start, end = opened, expires
    else:
        require('release_not_before' not in binding and 'release_expires_at' not in binding,
                'mixed formal evidence versions')
    require(start <= now <= end, 'formal evidence reference expired')


def resolve(reference, fetch, now, check_identity):
    validate_reference(reference, now)
    check_identity(reference['identity'])
    data = fetch(reference['commit'])
    require(type(data) is bytes and len(data) == reference['bytes'] and
            sha256(data).hexdigest() == reference['sha256'], 'formal evidence bytes changed')
    artifact = decode(data)
    require(type(artifact) is dict and set(artifact) == {'schema', 'admission', 'receipt'} and
            artifact['schema'] == (ARTIFACT_SCHEMA_V4 if reference['schema'] == REFERENCE_SCHEMA_V4 else ARTIFACT_SCHEMA), 'invalid formal evidence artifact')
    admission, receipt = artifact['admission'], artifact['receipt']
    require(canonical(reference['identity']) == canonical(identity(admission, receipt)), 'formal evidence identity drift')
    require(data == encode_artifact(admission, receipt), 'formal evidence bytes are not canonical')
    return admission, receipt


def resolve_configuration(config, fetch, now, check_identity):
    require(set(config) == {'schema', 'artifact', 'check_run_id', 'quality_check_run_id'} and
            config['schema'] in (CONFIG_SCHEMA, CONFIG_SCHEMA_V4) and
            config['artifact']['schema'] == (REFERENCE_SCHEMA_V4 if config['schema'] == CONFIG_SCHEMA_V4 else REFERENCE_SCHEMA), 'invalid protected evidence configuration')
    receipt_id, quality_id = config['check_run_id'], config['quality_check_run_id']
    require(type(receipt_id) is int and receipt_id > 0 and
            (quality_id is None or (type(quality_id) is int and quality_id > 0 and quality_id != receipt_id)),
            'invalid formal evidence check IDs')
    admission, receipt = resolve(config['artifact'], fetch, now, check_identity)
    return dict(admission, check_run_id=receipt_id, quality_check_run_id=quality_id), (receipt, config['artifact'])
