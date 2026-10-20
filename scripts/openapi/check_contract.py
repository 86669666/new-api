#!/usr/bin/env python3
"""Offline OpenAPI gate. Install requirements.txt in an external venv, then run this file.

Checks OAS 3.0, local references/security, selected source auth declarations and
positive/negative protocol fixtures. This does not prove server/provider runtime
behavior or full route coverage. It never calls the gateway or a provider.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

from jsonschema import RefResolver
from openapi_schema_validator import OAS30Validator
from openapi_spec_validator import OpenAPIV30SpecValidator

ROOT = Path(__file__).resolve().parents[2]
METHODS = {'get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'trace'}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key: ' + key)
        result[key] = value
    return result


def pointer(document, path):
    value = document
    for part in path.removeprefix('#/').split('/'):
        value = value[part.replace('~1', '/').replace('~0', '~')]
    return value


def walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def validate_value(document, schema, value):
    OAS30Validator(schema, resolver=RefResolver.from_schema(document)).validate(value)


def organization_cache_control(value):
    # This is the frozen conservative profile, not a general HTTP parser. Its
    # accepted directives have no quoted values, so comma splitting is safe;
    # any qualified/quoted directive (including a quoted comma) is rejected.
    values = value if isinstance(value, list) else [value]
    if not values or not all(isinstance(item, str) for item in values):
        return False
    directives = set()
    for part in ','.join(values).split(','):
        directive = part.strip(' \t').lower()
        if not re.fullmatch(r'private|no-store|no-cache|must-revalidate|max-age[ \t]*=[ \t]*0', directive):
            return False
        directives.add(directive)
    return {'private', 'no-store'} <= directives


def go_function(source, name):
    match = re.search(r'^func ' + re.escape(name) + r'\(.*?(?=^func |\Z)', source, re.M | re.S)
    assert match, ('missing source function', name)
    return re.sub(r'\s+', ' ', match.group())


def check_conditional_authorization(source_root):
    # Static drift checks on the selected server predicates, not an authorization
    # simulator. Runtime allow/deny tests must still exercise the actual handlers.
    files = {name: (source_root / name).read_text() for name in [
        'middleware/auth.go', 'controller/channel.go', 'controller/task.go',
        'controller/channel_authz.go', 'router/api-router.go',
        'router/channel-router.go', 'relay/helper/valid_request.go',
        'controller/relay.go',
    ]}
    intersection = go_function(files['middleware/auth.go'], 'HasPermission')
    assert 'AccessTokenScopeAllowed(c, service.AccessTokenScopeOf(permission)) && authz.Can(' in intersection, 'source root lacks user/PAT permission intersection'
    ceiling = go_function(files['middleware/auth.go'], 'AccessTokenScopeAllowed')
    assert 'if !c.GetBool("use_access_token") || c.GetBool("access_token_legacy")' in ceiling
    assert 'AccessTokenScopeGranted(c.GetStringSlice("access_token_scopes"), scope)' in ceiling
    predicates = [
        ('AddChannel', '(addChannelRequest.Channel.Type == constant.ChannelTypeTaskPlugin || len(addChannelRequest.Channel.GetSetting().TaskPluginBindings()) > 0) && !middleware.HasPermission(c, authz.TaskPluginBind)'),
        ('UpdateChannel', 'channel.Type == constant.ChannelTypeTaskPlugin && !middleware.HasPermission(c, authz.TaskPluginBind)'),
        ('UpdateChannel', 'settingProvided && !slices.Equal(channel.GetSetting().TaskPluginBindings(), originChannel.GetSetting().TaskPluginBindings()) && !middleware.HasPermission(c, authz.TaskPluginBind)'),
        ('UpdateChannel', 'channelHasSensitiveChanges(&channel, originChannel, requestData) && !middleware.HasPermission(c, authz.ChannelSensitiveWrite)'),
        ('EditTagChannels', '(channelTag.ParamOverride != nil || channelTag.HeaderOverride != nil) && !middleware.HasPermission(c, authz.ChannelSensitiveWrite)'),
        ('CopyChannel', '(origin.Type == constant.ChannelTypeTaskPlugin || len(origin.GetSetting().TaskPluginBindings()) > 0) && !middleware.HasPermission(c, authz.TaskPluginBind)'),
        ('ManageMultiKeys', 'multiKeyActionRequiresSensitiveWrite(request.Action) && !middleware.HasPermission(c, authz.ChannelSensitiveWrite)'),
    ]
    for function, predicate in predicates:
        body = go_function(files['controller/channel.go'], function)
        assert predicate in body, (source_root, function, 'conditional authorization drift')
    assert 'return action == "delete_key" || action == "delete_disabled_keys"' in go_function(files['controller/channel.go'], 'multiKeyActionRequiresSensitiveWrite')
    owner = go_function(files['controller/task.go'], 'getTaskForArtifactRequest')
    assert 'c.GetInt("token_id") == 0 && c.GetInt("role") >= common.RoleAdminUser && middleware.AccessTokenScopeAllowed(c, "log:read")' in owner
    assert 'return model.GetByTaskId(c.GetInt("id"), taskID)' in owner
    dashboard = go_function(files['controller/task.go'], 'GetDashboardTaskArtifacts')
    assert 'if !exists || task == nil { writeTaskArtifactError(c, http.StatusNotFound, "artifact_not_found", "Task or artifact not found") return } writeTaskArtifacts(c, task, true)' in dashboard
    assert 'taskRoute.GET("/:task_id/artifacts", middleware.UserAuth(), controller.GetDashboardTaskArtifacts)' in files['router/api-router.go']
    for method, route, permission, handler in [
        ('Post', '/', 'ChannelSensitiveWrite', 'AddChannel'),
        ('Put', '/', 'ChannelWrite', 'UpdateChannel'),
        ('Put', '/tag', 'ChannelWrite', 'EditTagChannels'),
        ('Post', '/copy/:id', 'ChannelSensitiveWrite', 'CopyChannel'),
        ('Post', '/multi_key/manage', 'ChannelOperate', 'ManageMultiKeys'),
    ]:
        assert f'{{method: http.Method{method}, path: "{route}", permission: authz.{permission}, handler: controller.{handler}}}' in files['router/channel-router.go']
    gemini = go_function(files['relay/helper/valid_request.go'], 'GetAndValidateGeminiRequest')
    assert 'if len(request.Contents) == 0 && len(request.Requests) == 0' in gemini
    assert 'ResponseModalities' not in gemini
    assert re.search(r'case types.RelayFormatClaude:.*?"type":\s+"error",.*?"error":\s+newAPIError.ToClaudeError', files['controller/relay.go'], re.S)
    return {
        'channel_predicates': len(predicates),
        'artifact_owner_and_rejection': 'checked',
        'protocol_source_shapes': ['Claude error', 'Gemini optional generation configuration'],
        'source_sha256': {name: hashlib.sha256(value.encode()).hexdigest() for name, value in files.items()},
        'limitation': 'Static source drift checks only; no server authorization or provider runtime is executed.',
    }


def check_organization_lifecycle(api, relay, fixtures, design_gate):
    contract = api['x-organization-lifecycle-contract']
    routes = contract['routes']
    expected_ids = {f'W{i:02}' for i in range(1, 18)} | {f'Q{i:02}' for i in range(1, 9)} | {'A01', 'A02', 'P01', 'P02', 'P03', 'P04'}
    assert {r['id'] for r in routes} == expected_ids and len(routes) == 31
    samples = {f['contract_id']: f for f in fixtures if f.get('kind') == 's3_operation'}
    assert set(samples) == expected_ids
    schemas = api['components']['schemas']
    assert 'ORG_SELF_INVITE' in schemas['OrganizationLifecycleError400']['properties']['code']['enum']
    assert 'ORG_EMAIL_INVITE_UNSUPPORTED' in schemas['OrganizationLifecycleError400']['properties']['code']['enum']
    request_view = schemas['OrganizationLifecycleRequestView']
    for field in ['from_username', 'target_username']:
        assert request_view['properties'][field]['type'] == 'string'
        assert request_view['properties'][field]['maxLength'] == 20
    assert request_view['oneOf'] == [
        {'properties': {'kind': {'enum': ['invitation']}}, 'required': ['from_username', 'target_username']},
        {'properties': {'kind': {'enum': ['transfer']}},
         'not': {'anyOf': [{'required': ['from_username']}, {'required': ['target_username']}]}},
    ]
    conflict = schemas['OrganizationLifecycleError409']
    assert conflict['properties']['data']['properties'] == {'revision': {'$ref': '#/components/schemas/OrganizationLifecycleID'}}
    assert conflict['properties']['data']['required'] == ['revision']
    assert conflict['properties']['data']['additionalProperties'] is False
    assert conflict['oneOf'] == [
        {'properties': {'code': {'enum': ['ORG_STATE_CHANGED']}}},
        {'properties': {'code': {'enum': [value for value in conflict['properties']['code']['enum'] if value != 'ORG_STATE_CHANGED']}},
         'not': {'required': ['data']}},
    ]
    for path in ['/api/organizations/{org_id}/invitations', '/api/organizations/{org_id}/invitations/{invitation_id}/reissue']:
        operation = api['paths'][path]['post']
        assert 'errors never include the current revision.' not in operation['description']
        assert 'only an authorized stale invite/reissue may include data.revision observed under the existing locks; other conflicts omit it.' in operation['description']
        assert operation['x-organization-invitation-conflicts']['self_invite'] == {'code': 'ORG_SELF_INVITE', 'status': 400, 'retry': 'choose another user'}
    scopes = schemas['OrganizationLifecycleProofResult']['properties']['scope']['enum']
    assert len(scopes) == len(set(scopes)) == 9
    assert 'platform.organization.disable' in scopes
    assert len(contract['schema_map']) == 66
    for route in routes:
        op = api['paths'][route['path']][route['method'].lower()]
        fixture = samples[route['id']]
        assert op['operationId'] == route['operationId'] == fixture['operationId']
        assert op['x-s3-contract-id'] == route['id']
        assert op['x-security-proof-policy'] == route['proof'] == fixture['proof']
        assert op['x-organization-selector-policy'] == route['selector_policy']
        assert op['x-automatic-retry'] is False
        assert str(fixture['status']) in op['responses']
        assert fixture['status'] == (201 if route['id'] == 'W01' else 200)
        validate_value(api, pointer(api, fixture['response_schema']), fixture['response'])
        if route['id'].startswith('P'):
            assert op['security'] == [{'DashboardJWT': []}, {'PersonalAccessToken': []}]
            assert op['x-organization-scope-security'] == [{'DashboardJWT': []}]
            assert op['x-organization-scopes'] == scopes
            if fixture['request'] is not None:
                validate_value(api, op['x-organization-request-schema'], fixture['request'])
                validate_value(api, op['requestBody']['content']['application/json']['schema'], fixture['request'])
        else:
            assert op['security'] == [{'DashboardJWT': []}]
            assert op['tags'] == ['Organizations']
            parameters = op['parameters']
            proof = [p for p in parameters if p.get('name') == 'X-Security-Proof']
            if route['proof'] == 'forbidden':
                assert not proof and 'X-Security-Proof' in op['x-forbidden-request-headers']
            else:
                assert len(proof) == 1 and proof[0]['required'] == (route['proof'] == 'required')
            if route['method'] == 'GET':
                assert 'requestBody' not in op and fixture['request'] is None
            else:
                assert op['requestBody']['required'] is True
                validate_value(api, op['requestBody']['content']['application/json']['schema'], fixture['request'])
            assert 'Idempotency-Key' in op['x-forbidden-request-headers']
        # Include the four shared producer routes: their organization branches
        # have the same header policy, including pre-authentication errors.
        for status in [fixture['status'], *fixture['errors']]:
            response = op['responses'][str(status)]
            if '$ref' in response:
                response = pointer(api, response['$ref'])
            assert response['headers']['Cache-Control']['schema'] == {'$ref': '#/components/schemas/OrganizationCacheControl'}
        for status in fixture['errors']:
            assert str(status) in op['responses']
        assert route['path'] not in relay['paths'], ('phantom relay management route', route['path'])
    assert '/api/user/self/passkey/verify/begin' not in api['paths']
    assert '/api/user/self/passkey/verify/finish' not in api['paths']
    assert 'auth_bundle' in schemas['OrganizationLifecycleProofResult']['required']
    assert 'auth_bundle' not in schemas['SecurityProofData'].get('required', [])
    assert 'refresh_token' not in schemas['OrganizationLifecycleAuthBundle']['properties']
    assert schemas['OrganizationLifecycleBodySelfDisable']['properties']['disabled'] == {'type': 'boolean'}
    assert schemas['OrganizationLifecycleBodyTransferInitiate']['properties']['replace'] == {'type': 'boolean'}
    assert api['x-organization-selection-boundary'] == relay['x-organization-selection-boundary']
    assert api['components']['schemas']['OrganizationCacheControl'] == relay['components']['schemas']['OrganizationCacheControl']
    gate_checked = False
    if design_gate:
        gate_bytes = design_gate.read_bytes()
        effective_sha = '6eef8e4bd07fde5bad1bf42a686461f244abd00b5dc38e58f5e475a2b7a8426d'
        assert hashlib.sha256(gate_bytes).hexdigest() == contract['design_gate_sha256'] == effective_sha, 'Effective v1.1 design gate SHA mismatch'
        gate = json.loads(gate_bytes, object_pairs_hook=unique_object)
        assert gate['contract_id'] == contract['design_contract_id'] == 'newapi-S3-lifecycle-g6-v1.1'
        assert api['x-organization-selection-boundary']['cache_control_contract'] == gate['transport']['cache_control_contract']
        assert {r['id'] for r in gate['routes']} == expected_ids
        for expected, actual in zip(gate['routes'], routes):
            for key in ['id', 'method', 'path', 'proof', 'permission', 'selector_policy', 'success_status', 'error_profile']:
                assert expected[key] == actual[key], (expected['id'], key)
            assert api['paths'][actual['path']][actual['method'].lower()]['x-s3-operation-id'] == expected['operation_id']
        assert contract['transport'] == gate['transport']
        assert contract['proof'] == gate['proof']
        assert contract['mandatory_amendments'] == gate['mandatory_amendments']
        # Compare required/closed typed structures and references recursively.
        # OAS 3.0 uses nullable and singleton enum in place of JSON Schema null/const.
        def compare_schema(expected, actual, location):
            if '$ref' in expected:
                target = contract['schema_map'][expected['$ref'].split('/')[-1]]
                assert actual == {'$ref': '#/components/schemas/' + target}, location
                return
            if 'anyOf' in expected and {'type': 'null'} in expected['anyOf']:
                child = next(x for x in expected['anyOf'] if x != {'type': 'null'})
                if '$ref' in child:
                    child = gate['$defs'][child['$ref'].split('/')[-1]]
                assert actual.get('nullable') is True, location
                actual = dict(actual)
                if 'enum' in actual:
                    actual['enum'] = [x for x in actual['enum'] if x is not None]
                compare_schema(child, actual, location)
                return
            if 'const' in expected:
                assert actual['enum'] == [expected['const']], location
                return
            for key in ['type', 'additionalProperties', 'minimum', 'maximum', 'minLength', 'maxLength', 'maxItems', 'format']:
                if key in expected:
                    assert actual.get(key) == expected[key], (location, key)
            assert set(expected.get('required', [])) == set(actual.get('required', [])), location
            if 'pattern' in expected:
                if 'x-int64-maximum' in expected:
                    # The OAS pattern additionally enforces the gate's decimal int64 cap.
                    assert actual['x-int64-maximum'] == expected['x-int64-maximum']
                    assert re.fullmatch(actual['pattern'], '9223372036854775807')
                    assert not re.fullmatch(actual['pattern'], '9223372036854775808')
                else:
                    assert expected['pattern'] == actual['pattern'], location
            if 'enum' in expected:
                assert actual['enum'] == expected['enum'], location
            if 'properties' in expected:
                assert set(expected['properties']) == set(actual['properties']), location
                for key, value in expected['properties'].items():
                    compare_schema(value, actual['properties'][key], location + '.' + key)
            if 'items' in expected:
                compare_schema(expected['items'], actual['items'], location + '[]')
            for key in ['oneOf', 'allOf', 'anyOf']:
                if key in expected:
                    assert len(expected[key]) == len(actual[key]), location
                    for index, value in enumerate(expected[key]):
                        compare_schema(value, actual[key][index], location + '.' + key + str(index))
        # The current invite input adds one exact username branch. The frozen
        # ID command, proof contexts and every other gate definition stay intact.
        username = {
            'type': 'string', 'minLength': 1, 'maxLength': 20,
            'pattern': r'^[^\u0000-\u001F\u007F-\u009F]+$(?![\s\S])',
            'description': 'Exact existing username, at most 20 Unicode code points. No trimming, case folding, accent folding or Unicode normalization; @ is permitted. This is not an email lookup.',
        }
        invite = schemas['OrganizationLifecycleBodyInvite']
        assert set(invite) == {'description', 'oneOf'} and len(invite['oneOf']) == 2
        username_body = {
            'type': 'object', 'properties': {
                'revision': {'$ref': '#/components/schemas/OrganizationLifecycleID'},
                'role': {'type': 'string', 'enum': ['admin', 'member']},
                'username': username,
            }, 'required': ['revision', 'username', 'role'], 'additionalProperties': False,
        }
        assert invite['oneOf'][1] == username_body
        username_command = {
            'type': 'object', 'properties': {
                'organization_id': {'$ref': '#/components/schemas/OrganizationLifecycleID'},
                'revision': {'$ref': '#/components/schemas/OrganizationLifecycleID'},
                'role': {'type': 'string', 'enum': ['admin']}, 'username': username,
            }, 'required': ['organization_id', 'revision', 'username', 'role'], 'additionalProperties': False,
        }
        assert schemas['OrganizationLifecyclePreviewInviteUsernameCommand'] == username_command
        preview = schemas['OrganizationLifecyclePreviewBody1']
        assert set(preview) == {'oneOf'} and len(preview['oneOf']) == 9
        assert preview['oneOf'][-1] == {
            'type': 'object', 'properties': {
                'action': {'type': 'string', 'enum': ['invite']},
                'command': {'$ref': '#/components/schemas/OrganizationLifecyclePreviewInviteUsernameCommand'},
            }, 'required': ['action', 'command'], 'additionalProperties': False,
        }
        for key, expected in gate['$defs'].items():
            actual = schemas[contract['schema_map'][key]]
            if key == 'Body_invite':
                actual = invite['oneOf'][0]
            elif key == 'PreviewBody_1':
                actual = {'oneOf': preview['oneOf'][:-1]}
            elif key == 'RequestView':
                # Preserve the frozen shared view and strictly check the two
                # invitation-only display fields above; proof schemas stay exact.
                actual = dict(actual)
                actual['properties'] = {name: value for name, value in actual['properties'].items()
                                        if name not in ('from_username', 'target_username')}
                del actual['oneOf']
            compare_schema(expected, actual, key)
        gate_checked = True
    return {'routes': len(routes), 'schemas': len(contract['schema_map']), 'organization_scopes': len(scopes), 'frozen_design_checked': gate_checked, 'design_contract_id': contract['design_contract_id'], 'effective_design_gate_sha256': contract['design_gate_sha256'], 'live_http': False}



def check_organization_task_reads(api):
    task_list = api['paths']['/api/task/self']['get']
    delivery = task_list['x-organization-list-revocation']
    assert delivery['initial_snapshot'] == 'page and total authorized together'
    assert delivery['final_check'] == 'after projection and before first JSON publication'
    assert delivery['current_session_member_enabled'] is True
    assert delivery['organization_wide_roles'] == ['owner', 'admin']
    assert delivery['scope_narrowing_status'] == 404 and delivery['empty_pages_checked'] is True
    assert delivery['requery_tasks_or_total'] is False and delivery['scope_marker_in_response'] is False
    assert delivery['initial_member_promotion'] == 'may publish original own-submission snapshot'
    assert delivery['denial'] == 'no data, items or total'
    assert task_list['x-organization-scope-security'] == [{'DashboardJWT': []}]
    base = '/api/organizations/{org_id}/tasks/{task_row_id}'
    expected = [('GET', base), ('GET', base + '/artifacts'),
                ('GET', base + '/artifacts/{artifact_key}/content'),
                ('HEAD', base + '/artifacts/{artifact_key}/content')]
    contract = api['x-organization-task-read-contract']
    assert contract['routes'] == [{'method': method, 'path': path} for method, path in expected]
    assert contract['task_identity'] == 'organization_id + internal row ID'
    assert contract['list_row_id_field'] == 'task_row_id' and contract['session_only'] is True
    assert contract['anonymous_artifact_access'] is False
    for method, path in expected:
        operation = api['paths'][path][method.lower()]
        assert operation['security'] == [{'DashboardJWT': []}]
        assert operation['x-query-allowlist'] == ['org_id']
        assert operation['x-task-identity'] == contract['task_identity']
        assert operation['x-anonymous-artifact-access'] is False
        assert operation['x-delivery-authorization'] == contract['delivery_authorization']
        assert operation['x-organization-state-mutation'] is False
        assert {'method': method, 'path': path} in api['x-organization-selection-boundary']['positive_selector_allowlist']
        for response in operation['responses'].values():
            assert response['headers']['Cache-Control']['schema'] == {'$ref': '#/components/schemas/OrganizationCacheControl'}
    detail = api['components']['schemas']['OrganizationTaskDetail']
    assert set(detail['properties']) == set(detail['required']) == {
        'task_row_id', 'task_id', 'platform', 'action', 'status', 'progress',
        'created_at', 'submit_time', 'start_time', 'finished_at'}
    assert detail['additionalProperties'] is False
    assert detail['properties']['task_row_id'] == {'$ref': '#/components/schemas/OrganizationLifecycleID'}
    artifacts = api['components']['schemas']['OrganizationTaskArtifacts']
    assert set(artifacts['properties']) == set(artifacts['required']) == {'task_row_id', 'task_id', 'artifacts'}
    assert artifacts['additionalProperties'] is False
    assert artifacts['properties']['artifacts']['items']['additionalProperties'] is False
    batch_path = '/api/organizations/{org_id}/tasks/batch'
    batch_contract = api['x-organization-task-batch-contract']
    assert batch_contract['route'] == {'method': 'GET', 'path': batch_path}
    assert batch_contract['task_identity'] == contract['task_identity']
    assert batch_contract['query_parameter'] == 'task_row_ids'
    assert batch_contract['encoding'] == 'single CSV query value, URL-decoded once'
    assert batch_contract['max_ids'] == 20 and batch_contract['max_decoded_bytes'] == 399
    assert all(batch_contract[key] is True for key in ['unique_ids', 'request_order', 'all_or_nothing', 'session_only'])
    assert batch_contract['unavailable_status'] == 404
    assert batch_contract['projection'] == '#/components/schemas/OrganizationTaskDetail'
    batch = api['paths'][batch_path]
    assert set(batch) == {'get'}
    operation = batch['get']
    assert operation['security'] == [{'DashboardJWT': []}]
    assert operation['x-query-allowlist'] == ['org_id', 'task_row_ids']
    assert operation['x-task-identity'] == contract['task_identity']
    assert operation['x-organization-state-mutation'] is False
    assert operation['x-anonymous-artifact-access'] is False
    assert operation['x-batch-partial-results'] is False
    assert operation['x-batch-order'] == 'request ID order'
    assert operation['x-batch-authorization-recheck'] == batch_contract['publication_recheck']
    assert batch_contract['route'] in api['x-organization-selection-boundary']['positive_selector_allowlist']
    parameter = next(item for item in operation['parameters'] if item.get('name') == 'task_row_ids')
    assert parameter['in'] == 'query' and parameter['required'] is True
    assert parameter['style'] == 'form' and parameter['explode'] is False
    assert parameter['schema'] == {'$ref': '#/components/schemas/OrganizationTaskBatchRowIDs'}
    ids = api['components']['schemas']['OrganizationTaskBatchRowIDs']
    assert ids['type'] == 'array' and ids['minItems'] == 1 and ids['maxItems'] == 20
    assert ids['uniqueItems'] is True and ids['x-decoded-max-bytes'] == 399
    assert ids['items'] == {'$ref': '#/components/schemas/OrganizationLifecycleID'}
    result = api['components']['schemas']['OrganizationTaskBatchResult']['properties']['data']
    assert result['additionalProperties'] is False and result['required'] == ['items']
    assert set(result['properties']) == {'items'}
    assert result['properties']['items'] == {'type': 'array', 'minItems': 1, 'maxItems': 20,
                                            'items': {'$ref': '#/components/schemas/OrganizationTaskDetail'}}
    assert operation['responses']['200']['content']['application/json']['schema'] == {'$ref': '#/components/schemas/OrganizationTaskBatchResult'}
    for response in operation['responses'].values():
        if '$ref' in response:
            response = pointer(api, response['$ref'])
        assert response['headers']['Cache-Control']['schema'] == {'$ref': '#/components/schemas/OrganizationCacheControl'}
    export_contract = api['x-organization-task-export-contract']
    export_path = '/api/organizations/{org_id}/tasks/export'
    assert export_contract['route'] == {'method': 'GET', 'path': export_path}
    assert export_contract['format'] == 'json' and export_contract['filename'] == 'organization-task-states.json'
    attachment = 'attachment; filename="organization-task-states.json"'
    assert export_contract['content_disposition'] == attachment
    assert export_contract['max_ids'] == batch_contract['max_ids']
    assert export_contract['max_decoded_bytes'] == batch_contract['max_decoded_bytes']
    assert export_contract['session_only'] is True and export_contract['all_or_nothing'] is True
    assert export_contract['projection'] == batch_contract['projection']
    assert export_contract['result_schema'] == '#/components/schemas/OrganizationTaskBatchResult'
    assert export_contract['publication_recheck'] == batch_contract['publication_recheck']
    assert export_contract['error_content_disposition'] == 'absent'
    export = api['paths'][export_path]
    assert set(export) == {'get'}
    download = export['get']
    for key in ['security', 'parameters', 'x-query-allowlist', 'x-pat-policy', 'x-forbidden-request-headers',
                'x-request-body-policy', 'x-task-identity', 'x-delivery-authorization',
                'x-batch-authorization-recheck', 'x-batch-order', 'x-batch-partial-results',
                'x-organization-state-mutation', 'x-anonymous-artifact-access']:
        assert download[key] == operation[key], key
    assert download['x-export-format'] == 'json'
    assert download['x-export-serialization'] == export_contract['serialization'] == 'complete in memory before final authorization recheck'
    assert download['x-error-content-disposition'] == 'absent'
    assert export_contract['route'] in api['x-organization-selection-boundary']['positive_selector_allowlist']
    disposition = api['components']['schemas']['OrganizationTaskExportContentDisposition']
    assert disposition == {'type': 'string', 'enum': [attachment]}
    success = download['responses']['200']
    assert success['content'] == operation['responses']['200']['content']
    assert success['headers']['Content-Disposition']['schema'] == {'$ref': '#/components/schemas/OrganizationTaskExportContentDisposition'}
    for status, response in download['responses'].items():
        if status != '200':
            assert response == operation['responses'][status]
        if '$ref' in response:
            response = pointer(api, response['$ref'])
        assert response['headers']['Cache-Control']['schema'] == {'$ref': '#/components/schemas/OrganizationCacheControl'}
        assert ('Content-Disposition' in response['headers']) == (status == '200')
    return {'routes': len(expected), 'batch_routes': 1, 'export_routes': 1, 'list_publication_check': True,
            'anonymous_access': False, 'live_http': False}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=ROOT, help='Explicit business source checkout for combined-candidate checks; defaults to this checkout. No source is copied or modified.')
    parser.add_argument('--claude-wire-fixtures', type=Path, help='Optional JSON array of recorded {status, body} results from local Claude relay/middleware tests; never fetched from a server.')
    parser.add_argument('--design-gate', type=Path, required=True, help='Effective frozen S3 v1.1 contract JSON; its exact SHA and required wire structures are verified offline.')
    args = parser.parse_args()
    source_root = args.source_root.resolve()
    documents = {}
    results = {'specs': {}, 'fixtures': [], 'source_auth_routes_checked': 0, 'source_root': str(source_root)}
    for name in ['api', 'relay']:
        document = json.loads((ROOT / 'docs/openapi' / (name + '.json')).read_text(), object_pairs_hook=unique_object)
        documents[name] = document
        assert document['openapi'] == '3.0.1', name
        # Reject remote references before invoking any resolver: this gate is offline.
        for value in walk(document):
            if '$ref' in value:
                assert value['$ref'].startswith('#/'), value['$ref']
                pointer(document, value['$ref'])
            if 'Cache-Control' in value:
                assert value['Cache-Control'].get('schema', {}).get('enum') != ['private, no-store'], 'Organization Cache-Control is a directive set, not a singleton wire enum'
        OpenAPIV30SpecValidator(document).validate()
        ids = set()
        security = document['components']['securitySchemes']
        requirements = [document.get('security', [])]
        for path, item in document['paths'].items():
            for method, operation in item.items():
                if method not in METHODS:
                    continue
                op_id = operation['operationId']
                assert op_id and op_id not in ids, (name, op_id)
                ids.add(op_id)
                requirements.append(operation.get('security', document.get('security', [])))
                params = item.get('parameters', []) + operation.get('parameters', [])
                for parameter in re.findall(r'\{([^}]+)\}', path):
                    assert any(p.get('in') == 'path' and p.get('name') == parameter and p.get('required') for p in params), (path, parameter)
        for alternatives in requirements:
            for requirement in alternatives:
                for scheme, scopes in requirement.items():
                    assert scheme in security, (name, scheme)
                    if security[scheme]['type'] not in ['oauth2', 'openIdConnect']:
                        assert not scopes, (name, scheme, scopes)
        results['specs'][name] = {'oas': '3.0.1', 'paths': len(document['paths']), 'operations': len(ids), 'valid': True}

    api, relay = documents['api'], documents['relay']
    results['organization_task_reads'] = check_organization_task_reads(api)
    # Bind documented PAT scope/session choices to the checked-in route policy.
    rules = re.findall(r'"([A-Z]+) ([^\"]+)":\s+(accessToken[^,\n]+)', (source_root / 'middleware/access_token_routes.go').read_text())
    for method, gin_path, rule in rules:
        path = re.sub(r':([A-Za-z_]+)', r'{\1}', gin_path)
        operation = api['paths'].get(path, {}).get(method.lower())
        if operation is None or path in ['/api/oauth/state', '/api/pricing']:
            continue
        alternatives = operation['security']
        if rule == 'accessTokenSessionRule':
            assert not any('PersonalAccessToken' in choice for choice in alternatives), (method, path)
            assert any('DashboardJWT' in choice for choice in alternatives), (method, path)
        else:
            assert any('PersonalAccessToken' in choice for choice in alternatives), (method, path)
            scope = re.search(r'"([^"]+)"', rule)
            if scope:
                assert operation['x-pat-scope'] == scope.group(1), (method, path)
        results['source_auth_routes_checked'] += 1
    assert api['paths']['/api/user/login']['post']['security'] == []
    assert api['paths']['/api/user/auth/refresh']['post']['security'] == [{'RefreshCookie': []}]
    assert {} in api['paths']['/api/user/auth/logout']['post']['security']
    assert 'refresh_token' not in api['components']['schemas']['AuthSessionData']['properties']
    assert all('SecurityProof' in item for item in api['paths']['/api/channel/{id}/key']['post']['security'])
    assert api['paths']['/api/channel/{id}/key']['post']['x-pat-scope'] == 'channel:secret_view'
    assert 'ActionSecretView     = "secret_view"' in (source_root / 'service/authz/resources_channel.go').read_text()
    assert '/api/user/token' not in api['paths'] and '/api/verify/status' not in api['paths']
    assert 'const MaxImageN = 128' in (source_root / 'relaykit/dto/openai_image.go').read_text()
    assert relay['components']['schemas']['ImageGenerationRequest']['properties']['n']['maximum'] == 128
    edits = relay['paths']['/v1/images/edits']['post']['requestBody']['content']
    assert set(edits) == {'application/json', 'multipart/form-data'}
    for path in ['/v1/chat/completions', '/v1/completions', '/v1/responses', '/v1/messages']:
        stream = relay['paths'][path]['post']['responses']['200']['content']['text/event-stream']
        assert stream['schema']['type'] == 'string'
        # Parse the documented wire frames; a stream cannot be modeled as one JSON body.
        count = 0
        for frame in stream['example'].strip().split('\n\n'):
            data = '\n'.join(line[5:].lstrip(' ') for line in frame.splitlines() if line.startswith('data:'))
            if data and data != '[DONE]':
                payload = json.loads(data)
                if 'x-event-data-schema' in stream:
                    validate_value(relay, stream['x-event-data-schema'], payload)
                count += 1
        assert count, path
    assert '101' in relay['paths']['/v1/responses']['get']['responses']
    for path in ['/v1/images/generations', '/v1/images/edits']:
        media = relay['paths'][path]['post']['requestBody']['content']['application/json']
        for name, example in media['examples'].items():
            validate_value(relay, media['schema'], example['value'])
            results['fixtures'].append(path + ':' + name)

    fixtures = json.loads((Path(__file__).with_name('fixtures.json')).read_text())
    results['organization_lifecycle'] = check_organization_lifecycle(api, relay, fixtures, args.design_gate)
    for fixture in fixtures:
        if fixture.get('kind') == 's3_operation':
            continue
        document = documents[fixture['document']]
        if fixture.get('kind') == 'cache_control':
            value = fixture['value']
            assert organization_cache_control(value) == fixture['valid'], fixture['name']
            combined = ','.join(value) if isinstance(value, list) else value
            # Validate both actual OAS schemas, in addition to the independent
            # directive check. Missing headers are invalid contract samples.
            for name, cache_document in documents.items():
                schema = pointer(cache_document, fixture['schema'])
                errors = list(OAS30Validator(schema).iter_errors(combined))
                assert bool(errors) != fixture['valid'], (name, fixture['name'], [e.message for e in errors])
            results['fixtures'].append(fixture['name'])
            continue
        if fixture.get('kind') == 'authorization':
            operation = document['paths'][fixture['path']][fixture['method']]
            assert operation['security'] == [{'DashboardJWT': []}, {'PersonalAccessToken': []}], fixture['name']
            if 'policy' in fixture:
                assert operation['x-task-artifact-authorization'] == fixture['policy'], fixture['name']
                assert operation['x-pat-scope'] == fixture['policy']['base_scope'], fixture['name']
            else:
                assert operation['x-pat-scope'] == fixture['base_scope'], fixture['name']
                assert operation['x-user-permission-required'] is True, fixture['name']
                assert operation['x-pat-scope-ceiling-includes-root'] is True, fixture['name']
                conditions = operation['x-pat-conditional-scopes']
                assert {c['id']: c['scopes'] for c in conditions} == fixture['conditions'], fixture['name']
                assert len(conditions) == len(fixture['conditions']), fixture['name']
                assert all(c['when'] and c['user_permissions'] == c['scopes'] for c in conditions), fixture['name']
            results['fixtures'].append(fixture['name'])
            continue
        schema = pointer(document, fixture['schema'])
        errors = list(OAS30Validator(schema, resolver=RefResolver.from_schema(document)).iter_errors(fixture['value']))
        assert bool(errors) != fixture['valid'], (fixture['name'], [e.message for e in errors])
        results['fixtures'].append(fixture['name'])
    results['conditional_authorization_source'] = check_conditional_authorization(source_root)
    if args.claude_wire_fixtures:
        wires = json.loads(args.claude_wire_fixtures.read_text())
        assert wires, 'empty recorded wire fixtures'
        for wire in wires:
            schema = relay['paths']['/v1/messages']['post']['responses'][str(wire['status'])]['content']['application/json']['schema']
            validate_value(relay, schema, wire['body'])
        results['recorded_claude_wire_responses_checked'] = len(wires)
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
