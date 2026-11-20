"""Versioned exact-byte references for formal evidence kept in a private repository."""
from hashlib import sha256
import json
import re

EVIDENCE_REPOSITORY = '86669666/new-api-formal-evidence'
EVIDENCE_REPOSITORY_ID = 1462093892
EVIDENCE_PATH = 'formal-evidence.json'
REFERENCE_SCHEMA = 'box-formal-evidence-ref/v2'
ARTIFACT_SCHEMA = 'box-formal-evidence/v2'
CONFIG_SCHEMA = 'box-formal-evidence-config/v2'
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
WORKFLOW_PATH = '.github/workflows/box-formal-receipt.yml'
CONTROL_REF = 'refs/heads/codex/formal-quality'
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


def identity(admission):
    expected = admission['expected']
    quality = admission['quality']
    return {
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


def encode_artifact(admission, receipt):
    require('check_run_id' not in admission and 'quality_check_run_id' not in admission,
            'check IDs belong to the protected evidence configuration')
    require(canonical(admission['expected']) == canonical(receipt['binding']) and
            canonical(admission['quality']) == canonical(receipt['quality']),
            'receipt differs from formal evidence admission')
    require(admission.get('receipt_sha256') == sha256(canonical(receipt)).hexdigest(),
            'unbound formal receipt digest')
    data = canonical({'schema': ARTIFACT_SCHEMA, 'admission': admission, 'receipt': receipt})
    require(len(data) <= MAX_ARTIFACT_BYTES, 'formal evidence artifact exceeds size limit')
    return data


def make_reference(commit, artifact_bytes, admission):
    reference = {'schema': REFERENCE_SCHEMA, 'commit': commit, 'bytes': len(artifact_bytes),
                 'sha256': sha256(artifact_bytes).hexdigest(), 'identity': identity(admission)}
    validate_reference(reference, reference['identity']['not_before'])
    return reference


def validate_reference(reference, now):
    require(type(reference) is dict and set(reference) == {'schema', 'commit', 'bytes', 'sha256', 'identity'}
            and reference['schema'] == REFERENCE_SCHEMA, 'invalid formal evidence reference')
    require(type(reference['commit']) is str and type(reference['sha256']) is str and
            re.fullmatch('[0-9a-f]{40}', reference['commit']) is not None and
            re.fullmatch('[0-9a-f]{64}', reference['sha256']) is not None,
            'formal evidence requires an immutable commit and digest')
    require(type(reference['bytes']) is int and 0 < reference['bytes'] <= MAX_ARTIFACT_BYTES,
            'invalid formal evidence size')
    binding = reference['identity']
    require(type(binding) is dict and all(type(x) is int for x in
            (now, binding['not_before'], binding['expires_at'])) and
            binding['not_before'] <= now <= binding['expires_at'], 'formal evidence reference expired')


def resolve(reference, fetch, now, check_identity):
    validate_reference(reference, now)
    check_identity(reference['identity'])
    data = fetch(reference['commit'])
    require(type(data) is bytes and len(data) == reference['bytes'] and
            sha256(data).hexdigest() == reference['sha256'], 'formal evidence bytes changed')
    artifact = decode(data)
    require(type(artifact) is dict and set(artifact) == {'schema', 'admission', 'receipt'} and
            artifact['schema'] == ARTIFACT_SCHEMA, 'invalid formal evidence artifact')
    admission, receipt = artifact['admission'], artifact['receipt']
    require(canonical(reference['identity']) == canonical(identity(admission)), 'formal evidence identity drift')
    require(data == encode_artifact(admission, receipt), 'formal evidence bytes are not canonical')
    return admission, receipt


def resolve_configuration(config, fetch, now, check_identity):
    require(set(config) == {'schema', 'artifact', 'check_run_id', 'quality_check_run_id'} and
            config['schema'] == CONFIG_SCHEMA, 'invalid protected evidence configuration')
    receipt_id, quality_id = config['check_run_id'], config['quality_check_run_id']
    require(type(receipt_id) is int and receipt_id > 0 and
            (quality_id is None or (type(quality_id) is int and quality_id > 0 and quality_id != receipt_id)),
            'invalid formal evidence check IDs')
    admission, receipt = resolve(config['artifact'], fetch, now, check_identity)
    return dict(admission, check_run_id=receipt_id, quality_check_run_id=quality_id), (receipt, config['artifact'])
