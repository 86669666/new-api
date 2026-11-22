"""Seal versioned formal evidence for a separate privileged uploader and App signer.

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
                     workflow['ref'] in ('refs/heads/main', evidence.CONTROL_REF, evidence.CONTROL_REF_V4) and
                     workflow.get('sha') == admission['expected']['consumer_sha'] and
                     all(type(workflow.get(key)) is int and workflow[key] > 0 for key in
                         ('run_id', 'run_attempt', 'workflow_id')), 'unbound protected consumer run')
    if workflow['ref'] == evidence.CONTROL_REF_V4:
        evidence.require(workflow['run_attempt'] == 1 and workflow['workflow_id'] == policy.FORMAL_WORKFLOW_ID,
                         'unexpected r4 consumer workflow or attempt')
        policy.consumer.validate_execution_capture(receipt, admission)
    admission = dict(admission, quality=quality)
    receipt = dict(receipt, quality=quality)
    binding = evidence.identity(admission, receipt)
    evidence.require(type(binding['repository_id']) is int and binding['repository_id'] > 0 and
                     evidence.canonical(binding) == evidence.canonical(release.get('identity')),
                     'reviewed formal publication identity changed')
    receipt_digest = policy.consumer.validate_receipt(receipt, admission, now, private=True)
    policy.validate_quality(receipt, admission)
    evidence.require(admission.get('receipt_sha256') in (None, receipt_digest),
                     'existing receipt digest conflicts with finalized evidence')
    return evidence.encode_artifact(dict(admission, receipt_sha256=receipt_digest), receipt)


def complete_terminal_check(check_id, request, token, reader, *, policy, clock=time.time):
    """Update precisely one already-staged check using a supplied App token."""
    policy.require(type(check_id) is int and check_id > 0 and
                   request['schema'] in (policy.TERMINAL_SCHEMA, *policy.TIMED_TERMINAL_SCHEMAS) and
                   request['name'] == policy.PRIVATE_EVIDENCE_GATE, 'invalid terminal completion')
    staged = reader.check(check_id)
    policy.require(staged['id'] == check_id, 'wrong staged check ID')
    policy.validate_gate(staged, request, completed=False)
    payload = {'status': 'completed', 'conclusion': 'success', 'output': {
        'title': 'Formal quality verified',
        'summary': 'Complete formal evidence and both independent approvals were verified.',
        'text': policy.consumer.canonical(request).decode(),
    }}
    timed = request['schema'] in policy.TIMED_TERMINAL_SCHEMAS
    if timed:
        now = int(clock())
        reference = request['artifact']
        policy.validate_timed_artifact(request, now)
        policy.consumer.evidence.check_times(staged, reference['identity'], now, completed=False)
        payload['completed_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now))
    update = urllib.request.Request(f'https://api.github.com/repos/{policy.REPOSITORY}/check-runs/{check_id}',
        method='PATCH', data=policy.consumer.canonical(payload),
        headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
                 'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json'})
    with urllib.request.build_opener(policy.consumer.NoRedirect).open(update, timeout=30) as response:
        result = json.load(response)
    if timed:
        policy.require(result.get('completed_at') == payload['completed_at'] and
                       result.get('started_at') == staged['started_at'], 'signed check times changed')
    return result


def publish_terminal(admission, bundle, reader, publisher, journal, installation_token,
                     terminal_run, hosted, trusted_sha, *, policy, clock=time.time):
    """Complete the new App check only after both protected runs have passed."""
    request = policy.verify_terminal_evidence(admission, bundle, reader, terminal_run, hosted,
                                              trusted_sha, int(clock()))
    publisher.verify_installation(admission['repository_id'])
    timed = request['schema'] in (policy.TERMINAL_SCHEMA_V4, policy.TERMINAL_SCHEMA_V5)
    if timed:
        policy.consumer.evidence.validate_reference(bundle[1], int(clock()))
    journal.claim(request)
    check_id = publisher.stage(request)
    journal.stage(request, check_id)
    policy.require(journal.pending(request) == check_id, 'missing exact pending terminal check')
    staged_at = None
    if timed:
        staged = reader.check(check_id)
        policy.require(staged['id'] == check_id, 'staged check changed')
        policy.validate_gate(staged, request, completed=False)
        staged_at = policy.consumer.evidence.check_times(staged, bundle[1]['identity'], int(clock()), completed=False)
    policy.require(policy.verify_terminal_evidence(admission, bundle, reader, terminal_run, hosted,
                                                    trusted_sha, int(clock()), staged_at=staged_at) == request,
                   'terminal evidence changed before signing')
    published = complete_terminal_check(check_id, request, installation_token, reader, policy=policy, clock=clock)
    policy.require(published['id'] == check_id, 'wrong signed quality check')
    policy.validate_gate(published, request, completed=True)
    current = reader.check(check_id)
    policy.require(policy.consumer.canonical(current) == policy.consumer.canonical(published),
                   'signed quality check changed on readback')
    policy.verify_current_head(reader, admission)
    if timed:
        policy.consumer.evidence.validate_reference(bundle[1], int(clock()))
        policy.consumer.evidence.check_times(current, bundle[1]['identity'], int(clock()))
        policy.require(policy.consumer.evidence.github_time(current, 'started_at') == staged_at,
                       'C2 start time changed on completion')
    journal.consume(request, check_id)
    return check_id



def publish_delta(reference, reader, fetch, publication, journal, installation_token, terminal_run,
                  *, policy, clock=time.time):
    for delta in (policy.delta, policy.static_delta, policy.usage_delta,
                  policy.invitation_delta, policy.oauth_delta, policy.client_events_delta, policy.relay_log_delta,
                  policy.upstream_errors_delta, policy.provider_logs_delta,
                  policy.independent_stream_delta, policy.request_plugin_delta, policy.sql_midjourney_delta,
                  policy.authz_policy_reload_delta, policy.legacy_media_delta):
        if reference['schema'] == delta.REFERENCE_SCHEMA:
            break
    else:
        raise ValueError('unknown formal delta reference schema')
    request = delta.verify(policy, reference, reader, fetch, terminal_run, int(clock()))
    publication.verify_installation(request['repository_id'])
    journal.claim(request)
    check_id = publication.stage(request)
    journal.stage(request, check_id)
    policy.require(journal.pending(request) == check_id, 'missing exact pending delta check')
    staged = reader.check(check_id)
    policy.require(staged['id'] == check_id, 'delta check identity changed')
    policy.validate_gate(staged, request, completed=False)
    binding = reference['identity']
    staged_at = policy.consumer.evidence.check_times(staged, binding, int(clock()), completed=False)
    policy.require(delta.verify(policy, reference, reader, fetch, terminal_run, int(clock()),
                                      staged_at=staged_at) == request,
                   'delta evidence changed before signing')
    published = complete_terminal_check(check_id, request, installation_token, reader, policy=policy, clock=clock)
    policy.require(published['id'] == check_id, 'wrong signed delta check')
    policy.validate_gate(published, request, completed=True)
    current = reader.check(check_id)
    policy.require(policy.consumer.canonical(current) == policy.consumer.canonical(published),
                   'signed delta check changed on readback')
    policy.consumer.evidence.check_times(current, binding, int(clock()))
    journal.consume(request, check_id)
    return check_id
