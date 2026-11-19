"""Seal formal v2 evidence for a separate privileged uploader and App signer.

The trusted host must authenticate the release and finalized capture, then use
its scoped private repository writer. This module never handles credentials or
creates checks. Check IDs are bound by the protected workflow configuration
after GitHub returns them.
"""
from hashlib import sha256
import json
import time
import urllib.request


def seal(admission_bytes, capture_bytes, quality_bytes, release, *, policy, now):
    evidence = policy.consumer.evidence
    for label, raw in (('admission', admission_bytes), ('capture', capture_bytes), ('quality', quality_bytes)):
        evidence.require(type(raw) is bytes and 0 < len(raw) <= evidence.MAX_ARTIFACT_BYTES and
                         sha256(raw).hexdigest() == release.get(label + '_sha256'),
                         'reviewed formal publication input changed')
    admission, receipt, quality = (evidence.decode(raw) for raw in
                                   (admission_bytes, capture_bytes, quality_bytes))
    evidence.require(all(type(value) is dict for value in (admission, receipt, quality)),
                     'formal publication inputs must be objects')
    evidence.require('quality' not in admission and 'quality' not in receipt,
                     'formal capture already has quality evidence')
    workflow = quality.get('workflow')
    evidence.require(type(workflow) is dict and
                     workflow.get('path') == evidence.WORKFLOW_PATH and
                     workflow.get('event') == 'workflow_dispatch' and
                     workflow.get('ref') == release.get('consumer_ref') and
                     workflow['ref'] in ('refs/heads/main', evidence.CONTROL_REF) and
                     workflow.get('sha') == admission['expected']['consumer_sha'] and
                     all(type(workflow.get(key)) is int and workflow[key] > 0 for key in
                         ('run_id', 'run_attempt', 'workflow_id')), 'unbound protected consumer run')
    admission = dict(admission, quality=quality)
    receipt = dict(receipt, quality=quality)
    binding = evidence.identity(admission)
    evidence.require(type(binding['repository_id']) is int and binding['repository_id'] > 0 and
                     evidence.canonical(binding) == evidence.canonical(release.get('identity')),
                     'reviewed formal publication identity changed')
    receipt_digest = policy.consumer.validate_receipt(receipt, admission, now)
    policy.validate_quality(receipt, admission)
    evidence.require(admission.get('receipt_sha256') in (None, receipt_digest),
                     'existing receipt digest conflicts with finalized evidence')
    return evidence.encode_artifact(dict(admission, receipt_sha256=receipt_digest), receipt)


def complete_terminal_check(check_id, request, token, reader, *, policy):
    """Update precisely one already-staged check using a supplied App token."""
    policy.require(type(check_id) is int and check_id > 0 and request['schema'] == policy.TERMINAL_SCHEMA and
                   request['name'] == policy.PRIVATE_EVIDENCE_GATE, 'invalid terminal completion')
    staged = reader.check(check_id)
    policy.require(staged['id'] == check_id, 'wrong staged check ID')
    policy.validate_gate(staged, request, completed=False)
    payload = {'status': 'completed', 'conclusion': 'success', 'output': {
        'title': 'Formal quality verified',
        'summary': 'Complete formal evidence and both independent approvals were verified.',
        'text': policy.consumer.canonical(request).decode(),
    }}
    update = urllib.request.Request(f'https://api.github.com/repos/{policy.REPOSITORY}/check-runs/{check_id}',
        method='PATCH', data=policy.consumer.canonical(payload),
        headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
                 'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json'})
    with urllib.request.build_opener(policy.consumer.NoRedirect).open(update, timeout=30) as response:
        return json.load(response)


def publish_terminal(admission, bundle, reader, publisher, journal, installation_token,
                     terminal_run, hosted, trusted_sha, *, policy, clock=time.time):
    """Complete the new App check only after both protected runs have passed."""
    request = policy.verify_terminal_evidence(admission, bundle, reader, terminal_run, hosted,
                                              trusted_sha, int(clock()))
    publisher.verify_installation(admission['repository_id'])
    journal.claim(request)
    check_id = publisher.stage(request)
    journal.stage(request, check_id)
    policy.require(journal.pending(request) == check_id, 'missing exact pending terminal check')
    policy.require(policy.verify_terminal_evidence(admission, bundle, reader, terminal_run, hosted,
                                                    trusted_sha, int(clock())) == request,
                   'terminal evidence changed before signing')
    published = complete_terminal_check(check_id, request, installation_token, reader, policy=policy)
    policy.require(published['id'] == check_id, 'wrong signed quality check')
    policy.validate_gate(published, request, completed=True)
    current = reader.check(check_id)
    policy.require(policy.consumer.canonical(current) == policy.consumer.canonical(published),
                   'signed quality check changed on readback')
    policy.verify_current_head(reader, admission)
    journal.consume(request, check_id)
    return check_id
