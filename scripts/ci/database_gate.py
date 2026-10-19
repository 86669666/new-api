#!/usr/bin/env python3
"""Run required real-database contracts on explicitly isolated loopback instances."""
import json
import os
import re
import subprocess
import sys
from urllib.parse import urlsplit, unquote


TESTS = ('TestMigrationSchemaStability', 'TestInferencePresetSettingsAndDatabaseRoundTrip')
REQUIRED = {f'{test}/{dialect}' for test in TESTS for dialect in ('sqlite', 'mysql', 'postgres')}


def validate_environment(env):
    if env.get('NEWAPI_TEST_PROFILE') != 'isolated-ci':
        raise ValueError('NEWAPI_TEST_PROFILE=isolated-ci is required')
    mysql = env.get('TEST_MYSQL_DSN', '').strip()
    postgres = env.get('TEST_POSTGRES_DSN', '').strip()
    if not mysql or not postgres:
        raise ValueError('both TEST_MYSQL_DSN and TEST_POSTGRES_DSN are required; refusing partial matrix')
    # Restrict targets to loopback; the CI services or isolated launcher establish ownership.
    match = re.fullmatch(r'[^@]+@tcp\(127\.0\.0\.1:([0-9]+)\)/(newapi_ci_[a-z0-9_]+)(?:\?[^\r\n]*)?', mysql)
    pg = urlsplit(postgres)
    if not match or not 0 < int(match.group(1)) < 65536:
        raise ValueError('MySQL must use a dedicated newapi_ci_* database on literal loopback TCP')
    if (pg.scheme not in ('postgres', 'postgresql') or pg.hostname != '127.0.0.1'
            or not pg.port or not re.fullmatch(r'/newapi_ci_[a-z0-9_]+', pg.path)
            or pg.query not in ('', 'sslmode=disable')):
        raise ValueError('PostgreSQL must use a dedicated newapi_ci_* database on literal loopback TCP')
    # Do not inherit an application's shared service configuration into tests.
    if any(env.get(key) for key in ('SQL_DSN', 'LOG_SQL_DSN', 'REDIS_CONN_STRING', 'REDIS_URL')):
        raise ValueError('application database/Redis environment must be unset for this isolated test profile')


def redact_output(output, env):
    for key, value in env.items():
        if not key.endswith('_DSN') or not value:
            continue
        output = output.replace(value, '[redacted-dsn]')
        if '@tcp(' in value:
            credentials = value.split('@tcp(', 1)[0]
            if ':' in credentials:
                password = credentials.split(':', 1)[1]
                if password:
                    output = output.replace(password, '[redacted-password]')
        else:
            password = urlsplit(value).password
            if password:
                output = output.replace(password, '[redacted-password]').replace(unquote(password), '[redacted-password]')
    return output


def validate_events(events, returncode):
    if returncode:
        raise ValueError('go test failed')
    passed = set()
    package_passed = False
    for event in events:
        if event.get('Action') in ('skip', 'fail'):
            raise ValueError('required database suite skipped or failed')
        if event.get('Action') == 'pass':
            if event.get('Test'):
                if event.get('Package', '').endswith('/model'):
                    passed.add(event['Test'])
            elif event.get('Package', '').endswith('/model'):
                package_passed = True
    if not package_passed or not REQUIRED <= passed:
        raise ValueError('missing required dialect results; refusing empty or partial test success')



ORGANIZATION_CASES = frozenset(('lifecycle', 'authorization', 'history_and_expiry',
    'event_rollback_and_deletion', 'transfer_replacement_rollback', 'read_permissions', 'schema',
    *(f'concurrency/{name}' for name in ('accept_accept', 'revoke_accept', 'disable_accept',
      'remove_transfer', 'cancel_transfer', 'delete_join', 'lock_wait_expiry', 'reissue_accept',
      'platform_disable_accept', 'proof_wait_expiry', 'invitation_wait_expiry', 'transfer_accept_accept'))))


def organization_required_leaves(dialect):
    """One required manifest for validation and the aggregate result denominator."""
    if dialect not in ('sqlite', 'mysql', 'postgres'):
        raise ValueError('unknown organization dialect')
    required = {f'TestOrganizationLifecycleDatabaseMatrix/{dialect}/{case}' for case in ORGANIZATION_CASES}
    if dialect in ('mysql', 'postgres'):
        required.update(f'TestOrganizationLifecycleDatabaseMatrix/{dialect}/row_lock_expiry/{subject}'
                        for subject in ('session', 'authorization', 'invitation', 'transfer'))
    return required


def validate_organization_events(events, returncode, dialect):
    """Require common cases everywhere and actual row-lock expiry cases on server engines."""
    if returncode:
        raise ValueError('organization dialect test failed')
    required = organization_required_leaves(dialect)
    passed = set()
    package_passed = False
    for event in events:
        if event.get('Action') in ('fail', 'skip'):
            raise ValueError('organization suite failed or skipped')
        if event.get('Package') != 'github.com/QuantumNous/new-api/model':
            continue
        if event.get('Action') == 'pass':
            if event.get('Test'):
                passed.add(event['Test'])
            else:
                package_passed = True
    if not package_passed or not required <= passed:
        raise ValueError('missing exact organization dialect leaf results')
    return sorted(required)


DELETION_REQUIRED = frozenset(('TestManageUserDeleteReturnsImmediatelyAndUnknownActionFails',
 'TestManageUserOrganizationMembershipBlocksBothDeleteEntrypoints/hard=false',
 'TestManageUserOrganizationMembershipBlocksBothDeleteEntrypoints/hard=true',
 'TestSecurityAccountDeletionAcceptsEitherFactorAndRevokesSessions/2fa',
 'TestSecurityAccountDeletionAcceptsEitherFactorAndRevokesSessions/oauth',
 'TestSecurityAccountDeletionAcceptsEitherFactorAndRevokesSessions/passkey',
 'TestSecurityAccountDeletionAcceptsEitherFactorAndRevokesSessions/password',
 'TestSecurityAccountDeletionConcurrentRequestsHaveOneWinner',
 'TestSecurityAccountDeletionRechecksTransactionAndConsumesFailedProof/auth_version',
 'TestSecurityAccountDeletionRechecksTransactionAndConsumesFailedProof/revoked_session',
 'TestSecurityAccountDeletionRechecksTransactionAndConsumesFailedProof/root',
 'TestSecurityAccountDeletionRechecksTransactionAndConsumesFailedProof/write_failure',
 'TestSecurityAccountDeletionRejectsOrganizationMemberAndConsumesProof',
 'TestSecurityAccountDeletionRequiresScopedProof/consumed',
 'TestSecurityAccountDeletionRequiresScopedProof/expired',
 'TestSecurityAccountDeletionRequiresScopedProof/factor_added',
 'TestSecurityAccountDeletionRequiresScopedProof/missing',
 'TestSecurityAccountDeletionRequiresScopedProof/other_account',
 'TestSecurityAccountDeletionRequiresScopedProof/other_session',
 'TestSecurityAccountDeletionRequiresScopedProof/password_disabled',
 'TestSecurityAccountDeletionRequiresScopedProof/wrong_scope'))

CONTROLLER_REQUIRED = frozenset(('TestAccessTokenAuditsResultsAndExcludesBrowserSessions',
 'TestAccessTokenCreationChecksGrantBeforeConsumingProof',
 'TestAccessTokenLifecycleAndLateRequests',
 'TestAccessTokenScopeDictionaryIgnoresTheViewersGrants',
 'TestAccessTokenUpdateRenamesFreelyAndChangesGrantOnlyWithProof',
 'TestAcquireLogExportLock',
 'TestAuditIsolationVisibilityAndFailureContracts',
 'TestAuditOtherDatabaseEncoding',
 'TestAuditRoleSnapshotSurvivesActorChanges',
 'TestAuditRoleVisibilityAndPermissions',
 'TestLogExportRules',
 'TestPersonalResourceScopeReadCompatibility',
 'TestPersonalResourceScopeRejectsInvalidIdentity',
 'TestScopedAccessTokenChannelPermissionIntersection',
 'TestScopedAccessTokenTaskArtifactOwnership',
 'TestSecurityAndOperationEventsUseAuditTable'))


def validate_required_events(events, returncode, package, required):
    if returncode or any(event.get('Action') in ('fail','skip') for event in events):
        raise ValueError('required regression failed or skipped')
    passed={event['Test'] for event in events if event.get('Action')=='pass'
            and event.get('Package')==package and event.get('Test')}
    package_passed=any(event.get('Action')=='pass' and event.get('Package')==package
                       and not event.get('Test') for event in events)
    if not package_passed or not set(required)<=passed:
        raise ValueError('missing required regression results')
    return sorted(set(required))

def main():
    validate_environment(os.environ)
    env = dict(os.environ, GOWORK='off', NEWAPI_REQUIRE_DATABASES='1')
    command = ['go', 'test', '-count=1', '-timeout=10m', '-json', './model', '-run', '^(' + '|'.join(TESTS) + ')$']
    # Capture before logging so DSNs/passwords cannot leak from driver errors.
    result = subprocess.run(command, env=env, text=True, capture_output=True, timeout=1200)
    output = result.stdout + result.stderr
    output = redact_output(output, os.environ)
    print(output, end='')
    events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
    validate_events(events, result.returncode)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as error:
        print('Database gate refused: ' + str(error), file=sys.stderr)
        sys.exit(1)
