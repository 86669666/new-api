#!/usr/bin/env python3
"""Offline OpenAPI gate. Install requirements.txt in an external venv, then run this file.

Checks OAS 3.0, local references/security, selected source auth declarations and
positive/negative protocol fixtures. This does not prove server/provider runtime
behavior or full route coverage. It never calls the gateway or a provider.
"""
import argparse
import copy
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


def check_native_search(relay):
    operation = relay['paths']['/v1/tools/search']['post']
    assert set(relay['paths']['/v1/tools/search']) == {'post'}
    assert operation['operationId'] == 'searchDeepSeekTools'
    assert operation['security'] == [{'BearerAuth': []}]
    assert operation['x-fixed-model'] == 'deepseek-search'
    assert operation['x-response-max-bytes'] == 16 * 1024 * 1024
    assert operation['x-attempt-timeout-seconds'] == 30
    assert operation['x-automatic-replay-unknown-outcome'] is False
    schemas = relay['components']['schemas']
    request = schemas['DeepSeekSearchRequest']
    assert request['type'] == 'object' and request['required'] == ['query']
    assert request.get('additionalProperties', True) is True
    assert set(request['properties']) == {'query', 'count', 'need_content', 'ori_question', 'localization'}
    assert request['properties']['count'] == {'type': 'integer', 'minimum': 1, 'maximum': 50, 'default': 10}
    assert request['properties']['need_content'] == {'type': 'boolean', 'default': False}
    query = request['properties']['query']
    assert query['type'] == 'string' and query['minLength'] == 1 and query['maxLength'] == 128
    result = schemas['DeepSeekSearchResult']
    assert set(result['required']) == set(result['properties']) == {
        'title', 'url', 'snippet', 'summary', 'content', 'rerank_score', 'authority', 'site_name', 'site_icon', 'date'}
    for field in ('site_name', 'site_icon', 'date'):
        assert result['properties'][field]['nullable'] is True
    assert result['properties']['rerank_score'] == {'type': 'number', 'minimum': 0, 'maximum': 3}
    assert result['properties']['authority'] == {'type': 'integer', 'minimum': -1, 'maximum': 4}
    assert operation['responses']['200']['content'] == {'application/json': {'schema': {'$ref': '#/components/schemas/DeepSeekSearchResponse'}}}
    assert operation['parameters'] == relay['paths']['/v1/chat/completions']['post']['parameters']
    return {'route': '/v1/tools/search', 'native_only': True, 'fixed_model': 'deepseek-search',
            'bounded_complete_response': True, 'provider_io': False}


def check_oauth_userinfo(api, source_root):
    path = '/api/v1/oauth/userinfo'
    assert set(api['paths'][path]) == {'get'}
    operation = api['paths'][path]['get']
    assert operation['operationId'] == 'getOAuthUserInfo'
    assert operation['security'] == [{'OAuthResourceBearer': []}]
    assert operation['x-required-scopes'] == ['profile']
    assert operation['x-optional-disclosure-scope'] == {'email': 'email'}
    assert 'requestBody' not in operation
    assert set(operation['responses']) == {'200', '400', '401', '403', '429', '503'}
    schemas = api['components']['schemas']
    assert schemas['OAuthUserInfo'] == {
        'type': 'object', 'additionalProperties': False,
        'required': ['id', 'username', 'display_name', 'group'],
        'properties': {'id': {'type': 'integer', 'minimum': 1},
                       'username': {'type': 'string'}, 'display_name': {'type': 'string'},
                       'group': {'type': 'string'},
                       'sub': {'type': 'string', 'pattern': r'^[1-9][0-9]*(?![\s\S])', 'description': 'Canonical local user id, present only for the public issuer grant mode; omitted by legacy bridge-only mode.'},
                       'email': {'type': 'string', 'description': 'Present only when the current access token grants the exact email scope.'}},
    }
    for name, code in [('OAuthInvalidToken', 'invalid_token'), ('OAuthInsufficientScope', 'insufficient_scope'),
                       ('OAuthResourceUnavailable', 'temporarily_unavailable')]:
        assert schemas[name] == {'type': 'object', 'additionalProperties': False, 'required': ['error'],
                                 'properties': {'error': {'type': 'string', 'enum': [code]}}}
    assert operation['responses']['200']['content']['application/json']['schema'] == {'$ref': '#/components/schemas/OAuthUserInfo'}
    assert operation['responses']['401']['headers']['WWW-Authenticate']['schema']['enum'] == ['Bearer error="invalid_token"']
    assert operation['responses']['403']['content']['application/json']['schema'] == {'oneOf': [
        {'$ref': '#/components/schemas/OAuthInsufficientScope'},
        api['components']['responses']['OrganizationSelectionUnsupported']['content']['application/json']['schema'],
    ]}
    for status in ('200', '401', '403', '429', '503'):
        assert 'private, no-store' in operation['responses'][status]['headers']['Cache-Control']['description']
    assert 'Hydra does not generate this local binding' in operation['description']
    assert 'status oauth.enabled and client_features.oauth remain false' in operation['description']
    startup = go_function((source_root / 'main.go').read_text(), 'InitResources')
    assert startup.index('service.InitOAuthUserInfoResource()') < startup.index('model.InitDB()')
    routes = (source_root / 'router/oauth_resource_router.go').read_text()
    assert 'OAuthUserInfoAuth(resource)' in routes and 'GlobalAPIRateLimit()' in routes
    assert 'UserAuth(' not in routes and 'AccessTokenAudit(' not in routes
    return {'route': path, 'default_off': True, 'profile_scope': True, 'optional_email': True,
            'independent_credential': True, 'public_issuer_contract': True, 'live_http': False}


def check_oauth_balance(api, source_root):
    path = '/api/v1/oauth/balance'
    assert set(api['paths'][path]) == {'get'}
    operation = api['paths'][path]['get']
    assert operation['operationId'] == 'getOAuthBalance'
    assert operation['security'] == [{'OAuthResourceBearer': []}]
    assert operation['x-required-scopes'] == ['balance:read']
    assert operation['x-query-policy'] == 'forbidden'
    assert operation['x-automatic-retry'] is False and operation['x-default-off'] is True
    assert not operation.get('parameters') and 'requestBody' not in operation
    assert set(operation['responses']) == {'200', '400', '401', '403', '429', '500', '503'}
    schemas = api['components']['schemas']
    result = schemas['OAuthBalanceResult']
    assert result == {'type': 'object', 'additionalProperties': False,
                      'required': ['success', 'message', 'data'],
                      'properties': {'success': {'type': 'boolean', 'enum': [True]},
                                     'message': {'type': 'string', 'enum': ['']},
                                     'data': {'$ref': '#/components/schemas/OAuthBalanceData'}}}
    data = schemas['OAuthBalanceData']
    assert data['additionalProperties'] is False
    assert data['required'] == ['quota', 'used_quota', 'quota_per_unit', 'display_locale']
    assert set(data['properties']) == set(data['required']) | {'display_amount'}
    for name in ['quota', 'used_quota']:
        field = data['properties'][name]
        assert field['type'] == 'integer' and field['minimum'] == -9007199254740991 and field['maximum'] == 9007199254740991
    scale = data['properties']['quota_per_unit']
    assert scale['type'] == 'number' and scale['minimum'] == 0 and scale['exclusiveMinimum'] is True
    assert data['properties']['display_locale'] == {'type': 'string', 'enum': ['en-US']}
    assert data['properties']['display_amount']['type'] == 'string'
    for status, schema in [('200', 'OAuthBalanceResult'), ('400', 'OAuthBalanceInvalidRequest'),
                           ('401', 'OAuthInvalidToken'), ('403', 'OAuthInsufficientScope'), ('503', 'OAuthResourceUnavailable')]:
        assert operation['responses'][status]['content']['application/json']['schema'] == {'$ref': '#/components/schemas/' + schema}
    for status in ['429', '500']:
        assert 'content' not in operation['responses'][status]
    for response in operation['responses'].values():
        assert 'private, no-store' in response['headers']['Cache-Control']['description']
        assert response['headers']['Referrer-Policy']['schema']['enum'] == ['no-referrer']
    assert operation['responses']['403']['headers']['WWW-Authenticate']['schema']['enum'] == ['Bearer error="insufficient_scope", scope="balance:read"']
    supported = schemas['OAuthPublicMetadata']['properties']['scopes_supported']
    assert supported['minItems'] == supported['maxItems'] == 6
    assert supported['items']['enum'] == ['openid', 'profile', 'email', 'offline_access', 'balance:read', 'usage:read']
    routes = (source_root / 'router/oauth_resource_router.go').read_text()
    assert 'OAuthBalanceAuth(resource)' in routes and 'controller.GetOAuthBalance' in routes
    root_routes = (source_root / 'router/main.go').read_text()
    assert root_routes.index('OAuthBalanceBoundary') < root_routes.index('OrganizationSelectionBoundary')
    assert 'OAuthBalancePath' in (source_root / 'middleware/logger.go').read_text()
    return {'route': path, 'success_envelope': True, 'public_grant_only': True,
            'safe_integer_quota': True, 'optional_display_only': True, 'live_http': False}


def check_oauth_usage(api, source_root):
    schemas = api['components']['schemas']
    for kind in ('logs', 'stat'):
        path = '/api/v1/oauth/usage/' + kind
        assert set(api['paths'][path]) == {'get'}
        operation = api['paths'][path]['get']
        assert operation['operationId'] == 'getOAuthUsage' + kind.title()
        assert operation['security'] == [{'OAuthResourceBearer': []}]
        assert operation['x-required-scopes'] == ['usage:read']
        assert operation['x-default-off'] is True and operation['x-automatic-retry'] is False
        assert 'requestBody' not in operation
        assert all(parameter['in'] == 'query' for parameter in operation['parameters'])
        assert not {'org_id', 'token_id', 'user_id', 'access_token'} & {p['name'] for p in operation['parameters']}
        responses = operation['responses']
        assert set(responses) == {'200', '400', '401', '403', '429', '500', '503'}
        assert 'content' not in responses['429'] and 'empty body' in responses['500']['description']
        assert responses['403']['headers']['WWW-Authenticate']['schema']['enum'] == ['Bearer error="insufficient_scope", scope="usage:read"']
        for response in responses.values():
            assert 'private, no-store' in response['headers']['Cache-Control']['description']
            assert response['headers']['Referrer-Policy']['schema']['enum'] == ['no-referrer']
        result = schemas['OAuthUsage' + kind.title() + 'Result']
        assert result['additionalProperties'] is False
        assert result['properties']['data_complete'] == {'type': 'boolean', 'enum': [False]}
        assert result['properties']['quota_per_unit']['exclusiveMinimum'] is True
    for name, fields in (
        ('OAuthUsageLog', {'created_at', 'model_name', 'prompt_tokens', 'completion_tokens', 'quota', 'use_time', 'is_stream', 'group'}),
        ('OAuthUsageBucket', {'ts', 'quota', 'requests', 'tokens'}),
    ):
        schema = schemas[name]
        assert schema['additionalProperties'] is False
        assert set(schema['required']) == set(schema['properties']) == fields
        for field, value in schema['properties'].items():
            if value['type'] == 'integer':
                assert value['maximum'] == 9007199254740991
                assert value['minimum'] == (0 if field in ('created_at', 'ts') else -9007199254740991)
    routes = (source_root / 'router/oauth_resource_router.go').read_text()
    assert 'OAuthUsageAuth(resource)' in routes and 'controller.GetOAuthUsageLogs' in routes and 'controller.GetOAuthUsageStat' in routes
    root_routes = (source_root / 'router/main.go').read_text()
    assert root_routes.index('OAuthUsageBoundary') < root_routes.index('OrganizationSelectionBoundary')
    assert 'OAuthUsagePath' in (source_root / 'middleware/logger.go').read_text()
    return {'routes': 2, 'separate_scope': 'usage:read', 'safe_integers': True,
            'minimal_fields': True, 'source_wiring_checked': True, 'live_http': False}


def check_oauth_provider(api, source_root):
    schemas = api['components']['schemas']
    expected = {
        '/api/oauth/provider/login/preview': ('previewOAuthProviderLogin', 'OAuthProviderPreviewInput', 'OAuthProviderPreview'),
        '/api/oauth/provider/login': ('decideOAuthProviderLogin', 'OAuthProviderLoginDecision', 'OAuthProviderRedirect'),
        '/api/oauth/provider/consent/preview': ('previewOAuthProviderConsent', 'OAuthProviderPreviewInput', 'OAuthProviderPreview'),
        '/api/oauth/provider/consent': ('decideOAuthProviderConsent', 'OAuthProviderConsentDecision', 'OAuthProviderRedirect'),
    }
    for path, (operation_id, request, response) in expected.items():
        assert set(api['paths'][path]) == {'post'}
        operation = api['paths'][path]['post']
        assert operation['operationId'] == operation_id
        assert operation['security'] == [{'DashboardJWT': []}]
        assert operation['x-pat-policy'] == 'session-only'
        assert operation['x-query-policy'] == 'forbidden' and operation['x-request-max-bytes'] == 65536
        assert operation['x-automatic-retry'] is False
        assert operation['requestBody'] == {'required': True, 'content': {'application/json': {'schema': {'$ref': '#/components/schemas/' + request}}}}
        assert operation['responses']['200']['content']['application/json']['schema'] == {'$ref': '#/components/schemas/' + response}
        assert set(operation['responses']) == {'200', '400', '401', '403', '409', '429', '503'}
        for item in operation['responses'].values():
            assert 'private, no-store' in item['headers']['Cache-Control']['description']
        for phrase in ('both current versions', 'at least 24 hours', 'TTL <=30 minutes',
                       'commit before one Admin PUT', 'status oauth.enabled and client_features.oauth remain false'):
            assert phrase in operation['description']
    for name, fields in {
        'OAuthProviderPreviewInput': ['challenge'],
        'OAuthProviderLoginDecision': ['challenge', 'preview_token', 'decision'],
        'OAuthProviderConsentDecision': ['challenge', 'preview_token', 'decision', 'selected_scopes'],
        'OAuthProviderPreview': ['preview_token', 'expires_at', 'phase', 'client_id', 'client_name', 'username', 'requested_scopes', 'allowed_scopes', 'audience'],
        'OAuthProviderRedirect': ['redirect_to'], 'OAuthProviderError': ['error'],
    }.items():
        schema = schemas[name]
        assert schema['type'] == 'object' and schema['additionalProperties'] is False
        assert schema['required'] == fields and set(schema['properties']) == set(fields)
    assert schemas['OAuthProviderLoginDecision']['properties']['decision']['enum'] == ['continue', 'deny']
    consent = schemas['OAuthProviderConsentDecision']
    assert consent['properties']['decision']['enum'] == ['approve', 'deny']
    assert consent['properties']['selected_scopes'] == {
        'type': 'array', 'maxItems': 6, 'uniqueItems': True,
        'items': {'type': 'string', 'enum': ['openid', 'profile', 'email', 'offline_access', 'balance:read', 'usage:read']}}
    assert consent['oneOf'] == [
        {'properties': {'decision': {'enum': ['approve']},
                        'selected_scopes': {'minItems': 1, 'not': {'items': {'enum': ['openid', 'email', 'offline_access', 'balance:read', 'usage:read']}}}}},
        {'properties': {'decision': {'enum': ['deny']}, 'selected_scopes': {'maxItems': 0}}}]
    assert schemas['OAuthProviderError']['properties'] == {'error': {'type': 'string', 'enum': [
        'invalid_request', 'invalid_token', 'access_denied', 'invalid_grant', 'temporarily_unavailable']}}
    routes = (source_root / 'router/oauth_provider_router.go').read_text()
    assert 'OAuthProviderBoundary' in routes and 'OAuthProviderSessionOnly' in routes
    assert 'UserAuth()' in routes and 'CriticalRateLimit()' in routes and 'OAuthResourceNoStore' in routes
    startup = go_function((source_root / 'main.go').read_text(), 'InitResources')
    assert startup.index('service.InitOAuthProviderBridge()') < startup.index('model.InitDB()')
    return {'routes': 4, 'default_off': True, 'real_session_only': True, 'public_issuer_contract': True,
            'live_issuer_executed_by_this_check': False, 'bounded_local_replay_hours': 24, 'required_verified_challenge_minutes': 30}


def check_oauth_revocation(api, source_root):
    operation = api['paths']['/oauth2/revoke']['post']
    assert set(api['paths']['/oauth2/revoke']) == {'post'}
    assert operation['operationId'] == 'revokeOAuthToken'
    assert operation['security'] == [] and operation['x-credential-kind'] == 'public-client-token-possession'
    assert operation['x-default-off'] is True and operation['x-automatic-retry'] is False
    assert operation['x-query-policy'] == 'forbidden-including-force-query'
    assert operation['x-request-max-bytes'] == 8192
    assert operation['requestBody'] == {'required': True, 'content': {
        'application/x-www-form-urlencoded': {'schema': {'$ref': '#/components/schemas/OAuthRevocationRequest'}}}}
    schema = api['components']['schemas']['OAuthRevocationRequest']
    assert schema['type'] == 'object' and schema['additionalProperties'] is False
    assert schema['required'] == ['token', 'client_id']
    assert set(schema['properties']) == {'token', 'client_id', 'token_type_hint'}
    for name, maximum in [('token', 4096), ('client_id', 256), ('token_type_hint', 256)]:
        assert schema['properties'][name]['type'] == 'string'
        assert schema['properties'][name]['maxLength'] == maximum
    assert 'enum' not in schema['properties']['token_type_hint'], 'RFC7009 unknown hints are ignored'
    responses = operation['responses']
    assert set(responses) == {'200', '400', '401', '403', '404', '405', '429', '503'}
    assert 'content' not in responses['200']
    assert responses['429']['content']['application/json']['schema'] == {'$ref': '#/components/schemas/OAuthResourceUnavailable'}
    for status in ('200', '400', '401', '404', '405', '429', '503'):
        assert 'private, no-store' in responses[status]['headers']['Cache-Control']['description']
        assert 'Location' not in responses[status]['headers'] and 'Set-Cookie' not in responses[status]['headers']
    for name, code in [('OAuthRevocationInvalidRequest', 'invalid_request'),
                       ('OAuthRevocationInvalidClient', 'invalid_client'), ('OAuthRevocationNotFound', 'not_found')]:
        assert api['components']['schemas'][name] == {
            'type': 'object', 'additionalProperties': False, 'required': ['error'],
            'properties': {'error': {'type': 'string', 'enum': [code]}}}
    for phrase in ('does not prove actual invalidation', 'mask wrong-client and internal storage failures',
                   'status oauth.enabled and client_features.oauth remain false', 'GetBody=nil'):
        assert phrase in operation['description']
    return {'route': '/oauth2/revoke', 'default_off': True, 'database_changes': False,
            'fixed_issuer_ingress': True, 'actual_issuer_invalidation_proved': False}


def check_oauth_ordinary_token(api, source_root):
    path = api['paths']['/api/v1/oauth/tokens']
    assert set(path) == {'get', 'post'}
    operation = path['post']
    assert operation['operationId'] == 'createOAuthOrdinaryToken'
    assert operation['security'] == [{'OAuthResourceBearer': []}]
    assert operation['x-required-scopes'] == ['tokens:write']
    assert operation['x-default-off'] is True and operation['x-automatic-retry'] is False
    assert operation['x-request-max-bytes'] == 4096
    assert operation['x-query-policy'] == 'forbidden'
    assert path['get']['x-required-scopes'] == ['tokens:read']
    assert 'OAuth revocation does NOT reclaim' in operation['description']
    assert operation['responses']['200']['content']['application/json']['schema'] == {'$ref': '#/components/schemas/OAuthOrdinaryTokenResult'}
    request = api['components']['schemas']['OAuthOrdinaryTokenRequest']
    assert request['additionalProperties'] is False and set(request['properties']) == {'name'}
    validate_value(api, request, {'name': 'personal model key'})
    for invalid in [{}, {'name': ''}, {'name': ' '}, {'name': 'a' * 31}, {'name': 1}, {'name': 'ok', 'group': 'vip'}, {'name': 'ok', 'user_id': 1}]:
        assert list(OAS30Validator(request).iter_errors(invalid)), 'invalid ordinary-key request accepted'
    source = (source_root / 'controller/oauth_ordinary_token.go').read_text()
    assert 'common.ValidateStrictJSONObject(data)' in source and 'len(name) > 30' in source
    assert 'CreateOrdinaryToken(c.Request.Context(), name)' in source
    assert 'controller.CreateOAuthOrdinaryToken(c)' in (source_root / 'router/oauth_resource_router.go').read_text()
    return {'post': True, 'metadata_get_unchanged': True, 'ordinary_lifecycle': True, 'live': False}


def check_oauth_public(api):
    expected = {'/oauth2/auth': ('get', 'authorizeOAuthPublicClient'),
                '/oauth2/token': ('post', 'exchangeOAuthPublicToken'),
                '/.well-known/openid-configuration': ('get', 'getOAuthOpenIDConfiguration'),
                '/.well-known/oauth-authorization-server': ('get', 'getOAuthAuthorizationServerMetadata'),
                '/.well-known/jwks.json': ('get', 'getOAuthPublicJWKS'),
                '/oauth2/error': ('get', 'getOAuthPublicError')}
    for path, (method, operation_id) in expected.items():
        assert set(api['paths'][path]) == {method}
        operation = api['paths'][path][method]
        assert operation['operationId'] == operation_id and operation['security'] == []
        assert operation['x-default-off'] is True and operation['x-automatic-retry'] is False
        assert operation['responses']['403']['content']['application/json']['schema'] == {'$ref': '#/components/schemas/OAuthOrganizationSelectionError'}
    auth = api['paths']['/oauth2/auth']['get']
    assert {'302', '303'} <= set(auth['responses']) and auth['x-query-max-bytes'] == 32768
    assert 'maxLength' not in next(p['schema'] for p in auth['parameters'] if p['name'] == 'redirect_uri')
    token = api['paths']['/oauth2/token']['post']
    assert token['x-request-max-bytes'] == 16384
    assert token['requestBody']['content']['application/x-www-form-urlencoded']['schema'] == {'$ref': '#/components/schemas/OAuthPublicTokenRequest'}
    for name in ['OAuthPublicTokenRequest', 'OAuthPublicTokenResponse', 'OAuthPublicMetadata', 'OAuthPublicJWK', 'OAuthPublicJWKS']:
        assert api['components']['schemas'][name]['additionalProperties'] is False
    assert api['components']['schemas']['OAuthPublicTokenResponse']['properties']['token_type']['enum'] == ['bearer']
    assert api['components']['schemas']['OAuthPublicTokenResponse']['properties']['expires_in']['maximum'] == 900
    return {'routes': 6, 'default_off': True, 'live_issuer': False, 'consumer_acceptance': False}


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


def check_no_available_channel_detail(relay):
    schema = relay['components']['schemas']['RelayError']
    assert schema['type'] == 'object' and schema['required'] == ['message', 'type']
    assert set(schema['properties']) == {'message', 'type', 'param', 'code', 'code_detail', 'group', 'model', 'remaining_display'}
    assert {k: v for k, v in schema['properties']['remaining_display'].items() if k != 'description'} == {'type': 'string', 'minLength': 1}
    assert schema['properties']['message'] == {'type': 'string'}
    assert schema['properties']['type'] == {'type': 'string'}
    assert schema['properties']['param'] == {'nullable': True}
    assert {k: v for k, v in schema['properties']['code'].items() if k != 'description'} == {'nullable': True}
    assert {key: value for key, value in schema['properties']['code_detail'].items() if key != 'description'} == {
        'type': 'string', 'enum': ['no_available_channel'],
    }
    for field in ['group', 'model']:
        assert {key: value for key, value in schema['properties'][field].items() if key != 'description'} == {'type': 'string'}
    assert schema['oneOf'] == [
        {'not': {'required': ['code_detail']}},
        {'required': ['code_detail', 'group', 'model', 'code'], 'properties': {
            'code': {'type': 'string', 'enum': ['model_not_found']},
            'type': {'type': 'string', 'enum': ['new_api_error']},
        }},
    ]
    assert schema['x-no-available-channel-contract'] == {
        'scope': 'HTTP Distribute host OpenAI fallback only; native vendor hooks/fallback and WebSocket unchanged',
        'trigger': 'ChannelSelectError.NoAvailableChannel only; never infer from status, code or message',
        'code_detail': 'no_available_channel',
        'legacy': 'HTTP503, model_not_found, new_api_error and localized message/request-id suffix unchanged',
        'group': 'captured usingGroup; auto stays literal auto, never candidate or last-attempt groups',
        'model': 'original distributor modelRequest.Model; no upstream mapping or plugin/channel diagnostics',
    }
    return {'optional_detail': 'no_available_channel', 'legacy_required_fields': ['message', 'type'], 'scope': 'marked HTTP host OpenAI only'}


def check_personal_log_range_error(api):
    operation = api['paths']['/api/log/self']['get']
    response = operation['responses']['400']
    legacy = api['components']['responses']['OrganizationSelectionBadRequest']
    assert response['headers'] == legacy['headers']
    content = response['content']['application/json']
    assert content['schema'] == {'anyOf': [
        {'$ref': '#/components/schemas/OrganizationSelectionBadRequestError'},
        {'$ref': '#/components/schemas/PersonalLogRangeError'},
    ]}
    for name, example in legacy['content']['application/json']['examples'].items():
        assert content['examples'][name] == example
    assert set(content['examples']) == set(legacy['content']['application/json']['examples']) | {
        'LOG_RANGE_TOO_WIDE_365', 'LOG_RANGE_TOO_WIDE_7',
    }
    assert 'before authentication' in response['description']
    assert 'after personal owner validation and the role check' in response['description']
    assert 'administrators retain' in response['description']
    schema = api['components']['schemas']['PersonalLogRangeError']
    assert {key: value for key, value in schema.items() if key != 'description'} == {
        'type': 'object', 'additionalProperties': False,
        'required': ['success', 'code', 'message', 'message_key', 'message_params'],
        'properties': {
            'success': {'type': 'boolean', 'enum': [False]},
            'code': {'type': 'string', 'enum': ['LOG_RANGE_TOO_WIDE']},
            'message': {'type': 'string'},
            'message_key': {'type': 'string', 'enum': ['The time range cannot exceed {{days}} days']},
            'message_params': {'type': 'object', 'additionalProperties': False,
                               'required': ['days'], 'properties': {'days': {'type': 'integer'}}},
        },
    }
    data_operation = api['paths']['/api/data/self']['get']
    data_response = data_operation['responses']['400']
    assert data_response['headers'] == legacy['headers']
    assert data_response['content'] == response['content']
    assert 'before authentication' in data_response['description']
    assert 'after authentication in GetUserQuotaDates' in data_response['description']
    assert 'all authenticated roles, including administrators and root' in data_response['description']
    assert data_operation['security'] == [{'DashboardJWT': []}, {'PersonalAccessToken': []}]
    assert data_operation['x-pat-scope'] == 'usage:read'
    assert data_operation['parameters'][:2] == [
        {'$ref': '#/components/parameters/PersonalOrganizationHeader'},
        {'$ref': '#/components/parameters/PersonalOrganizationQuery'},
    ]
    for path, item in api['paths'].items():
        if path in ('/api/log/self', '/api/data/self'):
            continue
        assert all(node.get('$ref') != '#/components/schemas/PersonalLogRangeError' for node in walk(item))
    return {'scope': '/api/log/self ordinary-user and /api/data/self all-role range errors only', 'status': 400,
            'code': 'LOG_RANGE_TOO_WIDE', 'selector_400_preserved': True, 'structured_message_preserved': True}


def check_personal_query_errors(api):
    codes = {'/api/log/self': ('LOG_QUERY_FAILED', 'Failed to query logs'),
             '/api/data/self': ('USAGE_QUERY_FAILED', 'Failed to query statistics')}
    for path, (code, message) in codes.items():
        operation = api['paths'][path]['get']
        assert 'guarantee is limited to database query failures' in operation['description']
        response = operation['responses']['500']['content']['application/json']
        assert response['schema'] == {
            'type': 'object', 'additionalProperties': False,
            'required': ['success', 'code', 'message', 'message_key'],
            'properties': {
                'success': {'type': 'boolean', 'enum': [False]},
                'code': {'type': 'string', 'enum': [code]},
                'message': {'type': 'string', 'enum': [message]},
                'message_key': {'type': 'string', 'enum': [message]},
            },
        }
        validate_value(api, response['schema'], response['example'])
    log = api['paths']['/api/log/self']['get']
    assert 'legacy HTTP200 success:false' in log['description']
    media = log['responses']['200']['content']['application/json']
    success, validation = media['schema']['anyOf']
    assert success['properties']['success'] == {'type': 'boolean', 'enum': [True]}
    assert validation['additionalProperties'] is False
    assert validation['required'] == ['success', 'message', 'message_key']
    assert validation['properties']['success'] == {'type': 'boolean', 'enum': [False]}
    messages = ['The search pattern cannot contain consecutive % wildcards',
                'The search pattern can contain at most 2 % wildcards',
                'Fuzzy search keywords must be at least 2 characters long']
    for field in ('message', 'message_key'):
        assert validation['properties'][field] == {'type': 'string', 'enum': messages}
    assert len(media['examples']) == 3
    for example in media['examples'].values():
        validate_value(api, media['schema'], example['value'])
    return {'scope': list(codes), 'database_error_status': 500, 'log_filter_validation_status': 200,
            'no_partial_data': True, 'safe_messages': True, 'live_http': False}


def check_personal_quota_series(api):
    operation = api['paths']['/api/data/self']['get']
    parameters = operation['parameters'][2:]
    assert len(parameters) == 2
    for parameter, name in zip(parameters, ('start_timestamp', 'end_timestamp')):
        assert {key: value for key, value in parameter.items() if key != 'description'} == {
            'name': name, 'in': 'query', 'required': False, 'allowEmptyValue': True,
            'schema': {'type': 'string'},
        }
        assert parameter['description']
    assert 'original parsed end' in operation['description']
    assert 'missing end does not become now' in operation['description']
    assert 'no sorting, zero-fill or day aggregation guarantee' in operation['description']
    assert operation['responses']['200']['headers'] == {}
    assert operation['responses']['200']['content']['application/json']['schema'] == {
        '$ref': '#/components/schemas/PersonalQuotaDataResult'}
    schemas = api['components']['schemas']
    result = schemas['PersonalQuotaDataResult']
    assert {key: value for key, value in result.items() if key != 'description'} == {'allOf': [
        {'$ref': '#/components/schemas/PersonalQuotaDataSuccess'},
    ]}
    success = schemas['PersonalQuotaDataSuccess']
    assert success['type'] == 'object' and 'additionalProperties' not in success
    assert success['required'] == ['success', 'message', 'data', 'granularity', 'quota_per_unit', 'data_complete', 'enable_data_export']
    assert set(success['properties']) == set(success['required'])
    assert success['properties']['success'] == {'type': 'boolean', 'enum': [True]}
    assert success['properties']['message'] == {'type': 'string', 'enum': ['']}
    for name, expected in {
        'granularity': {'type': 'string', 'enum': ['hour']},
        'quota_per_unit': {'type': 'number'},
        'data_complete': {'type': 'boolean', 'enum': [False]},
        'enable_data_export': {'type': 'boolean'},
    }.items():
        assert {key: value for key, value in success['properties'][name].items() if key != 'description'} == expected
    data = success['properties']['data']
    assert {key: value for key, value in data.items() if key != 'description'} == {
        'type': 'array', 'nullable': True, 'items': {'$ref': '#/components/schemas/PersonalQuotaDataPoint'}}
    point = schemas['PersonalQuotaDataPoint']
    assert point['type'] == 'object' and 'additionalProperties' not in point
    assert point['required'] == ['user_id', 'username', 'model_name', 'created_at', 'count', 'quota', 'token_used']
    numeric = {'user_id', 'count', 'quota', 'token_used', 'id', 'token_id', 'channel_id'}
    strings = {'username', 'model_name', 'use_group', 'node_name'}
    assert set(point['properties']) == numeric | strings | {'created_at'}
    for name, field in point['properties'].items():
        expected = {'type': 'integer'} if name in numeric else {'type': 'string'}
        if name == 'created_at':
            expected = {'type': 'integer', 'format': 'int64'}
        assert {key: value for key, value in field.items() if key != 'description'} == expected
    assert 'placeholder' in point['description']
    return {'scope': 'GET /api/data/self existing hourly series', 'query_parameters': [p['name'] for p in parameters],
            'database_error_status': 500, 'empty_array_and_nullable_compatibility': True,
            'collection_disabled_keeps_history': True, 'success_metadata': ['granularity', 'quota_per_unit', 'data_complete', 'enable_data_export'],
            'historical_completeness': False, 'live_http': False}


def check_personal_log_pagination(api):
    operation = api['paths']['/api/log/self']['get']
    assert operation['x-personal-log-pagination'] == {
        'scope': 'GET /api/log/self only; other pagination consumers retain p-only behavior',
        'page_selection': 'first p value whenever parsed URL contains the p key, including bare/empty/invalid/zero/negative/overflow; otherwise first page value',
        'page_fallback': 'existing platform-int parsing preserved: empty/syntax-invalid/zero defaults to 1; negative and overflow behavior unchanged',
        'page_size': 'first page_size value; zero/parse failure falls through first ps then first size then configured ItemsPerPage; nonzero negative values retained; upper cap 100',
        'compatibility': 'pagination parsing introduces no new validation errors or response fields; ownership, filters, sorting, range-limit decisions and authentication unchanged; range-error HTTP status/code documented separately',
    }
    assert operation['security'] == [{'DashboardJWT': []}, {'PersonalAccessToken': []}]
    assert operation['x-pat-scope'] == 'usage:read'
    parameters = operation['parameters']
    assert parameters[:2] == [
        {'$ref': '#/components/parameters/PersonalOrganizationHeader'},
        {'$ref': '#/components/parameters/PersonalOrganizationQuery'},
    ]
    assert [parameter['name'] for parameter in parameters[2:]] == ['p', 'page', 'page_size', 'ps', 'size']
    for parameter in parameters[2:]:
        assert {key: value for key, value in parameter.items() if key != 'description'} == {
            'name': parameter['name'], 'in': 'query', 'required': False,
            'allowEmptyValue': True, 'schema': {'type': 'string'},
        }
        assert parameter['description']
    assert all('x-personal-log-pagination' not in operation
               for path, item in api['paths'].items() if path != '/api/log/self'
               for method, operation in item.items() if method in METHODS)
    return {'page_alias_scope': '/api/log/self', 'canonical_presence_wins': True, 'legacy_fallback_preserved': True}


def check_client_events(api, source_root):
    operation = api['paths']['/api/events']['post']
    schemas = api['components']['schemas']
    assert operation['operationId'] == 'receiveClientEvents'
    assert operation['security'] == [{'ClientEventsBearer': []}]
    assert operation['x-default-enabled'] is False and operation['x-query-policy'] == 'forbidden'
    assert set(operation['responses']) == {'200', '400', '401', '403', '404', '413', '429', '503'}
    assert operation['requestBody']['content']['application/json']['schema'] == {'$ref': '#/components/schemas/ClientEventsInput'}
    assert not any(parameter.get('in') == 'query' for parameter in operation['parameters'])
    body = schemas['ClientEventsInput']
    assert body['required'] == ['client_id', 'channel', 'events'] and body.get('additionalProperties', True) is True
    assert body['properties']['events'] == {'type': 'array', 'minItems': 1, 'maxItems': 10, 'items': {'$ref': '#/components/schemas/ClientEventInput'}}
    event = schemas['ClientEventInput']
    assert event['type'] == 'object' and event.get('additionalProperties', True) is True
    assert set(event['properties']) == {'event_type', 'timestamp', 'data'}
    assert all(set(value) == {'description'} for value in event['properties'].values()), 'invalid known values are skipped, not envelope errors'
    assert schemas['ClientEventsResult']['required'] == ['success', 'count']
    assert schemas['ClientEventsResult']['additionalProperties'] is False
    assert schemas['ClientEventsResult']['properties'] == {'success': {'type': 'boolean', 'enum': [True]}, 'count': {'type': 'integer', 'minimum': 0, 'maximum': 10}}
    error = schemas['ClientEventsError']
    assert error['additionalProperties'] is False and error['required'] == ['success', 'code', 'message', 'message_key']
    assert set(error['properties']) == {'success', 'code', 'message', 'message_key', 'message_params'}
    assert error['properties']['code']['enum'] == ['CLIENT_EVENTS_INVALID', 'CLIENT_EVENTS_UNAUTHORIZED', 'CLIENT_EVENTS_FORBIDDEN', 'CLIENT_EVENTS_DISABLED', 'CLIENT_EVENTS_TOO_LARGE', 'CLIENT_EVENTS_RATE_LIMIT', 'CLIENT_EVENTS_UNAVAILABLE']
    usage = schemas['ClientEventUsageData']
    for field in ('input_tokens', 'output_tokens'):
        assert usage['properties'][field] == {'type': 'integer', 'minimum': 0, 'maximum': 9007199254740991}
    for response in operation['responses'].values():
        assert 'no-store' in response['headers']['Cache-Control']['description']
    assert operation['responses']['429']['headers']['Retry-After']['schema'] == {'type': 'integer', 'minimum': 1}
    router = (source_root / 'router/api-router.go').read_text()
    assert 'events := router.Group("/api", middleware.RouteTag("api"), middleware.ClientEventsBoundary())' in router
    assert 'events.POST("/events", controller.ReceiveClientEvents)' in router
    assert 'events.POST("/events/", controller.ReceiveClientEvents)' in router
    return {'route': 'POST /api/events', 'default_enabled': False, 'durable_count': True, 'event_limit': 10}


def check_client_event_stats(api, source_root):
    schemas = api['components']['schemas']
    for suffix in ('Usage', 'Clients'):
        op = api['paths']['/api/events/' + suffix.lower()]['get']
        assert op['operationId'] == 'getClientEvent' + suffix
        assert op['security'] == [{'DashboardJWT': []}, {'PersonalAccessToken': []}]
        assert op['x-pat-scope'] == 'log:read' and 'requestBody' not in op
        assert {'200','400','401','403','409','422','503'} <= set(op['responses'])
        assert schemas['ClientEvent' + suffix + 'Page']['properties']['data_complete']['enum'] == [False]
    assert schemas['ClientEventUsageGroup']['properties']['input_tokens']['type'] == 'string'
    assert schemas['ClientEventUsageGroup']['properties']['input_tokens']['nullable'] is True
    assert schemas['ClientEventClientsPage']['properties']['groups_additive']['enum'] == [False]
    assert schemas['ClientEventsConfigValue']['additionalProperties'] is False
    assert schemas['ClientEventsConfigOptionWrite']['properties']['value']['type'] == 'string'
    handler = (source_root / 'controller/client_events.go').read_text()
    parser = go_function(handler, 'parseClientEventStatsQuery')
    for phrase in ('len(raw) > 4096', 'query.EndTime-query.StartTime > 31*86400', '(page-1)*size > 2000', 'page > 1'):
        assert phrase in parser, ('client query parser drift', phrase)
    router = (source_root / 'router/api-router.go').read_text()
    for suffix, method in [('usage', 'GetClientEventUsage'), ('clients', 'GetClientEventClients')]:
        assert f'apiRouter.GET("/events/{suffix}", middleware.DisableCache(), middleware.AdminAuth(), middleware.SearchRateLimit(), controller.{method})' in router
    rules = (source_root / 'middleware/access_token_routes.go').read_text()
    for path in ('usage', 'clients'):
        assert re.search(r'"GET /api/events/' + path + r'"\s*:\s*accessTokenScopeRule\("log:read"\)', rules)
    option = (source_root / 'controller/option.go').read_text()
    assert 'model.UpdateClientEventsConfigOption(value)' in option
    config = (source_root / 'setting/operation_setting/client_events_setting.go').read_text()
    assert 'len(fields) != 3' in config
    return {'authenticated_admin': True, 'pat_scope': 'log:read', 'anonymous': False, 'live_http': False}


def check_model_capability_metadata(api, relay):
    schemas = api['components']['schemas']
    facts = ['context_length', 'max_output_tokens', 'vision', 'reasoning', 'tool_use']
    properties = {name: {'type': 'integer', 'format': 'int64', 'minimum': 1, 'maximum': 9007199254740991}
                  if name in facts[:2] else {'type': 'boolean'} for name in facts}
    capabilities = ['vision', 'tools', 'reasoning', 'web_search', 'structured_output']
    modalities = ['text', 'image', 'audio', 'video', 'file']
    for name, values in [('capabilities', capabilities), ('input_modalities', modalities), ('output_modalities', modalities)]:
        properties[name] = {'type': 'array', 'maxItems': 5, 'uniqueItems': True, 'items': {'type': 'string', 'enum': values}}
    properties['display_name'] = {'type': 'string', 'minLength': 1, 'maxLength': 255}
    properties['description'] = {'type': 'string', 'maxLength': 4096}
    facts = list(properties)
    declaration = schemas['ModelCapabilityMetadataDeclaration']
    assert {key: value for key, value in declaration.items() if key != 'description'} == {
        'type': 'object', 'properties': properties, 'minProperties': 1, 'additionalProperties': False,
    }
    mapping = schemas['ModelCapabilityMetadataMap']
    assert {key: value for key, value in mapping.items() if key != 'description'} == {
        'type': 'object', 'maxProperties': 256,
        'additionalProperties': {'$ref': '#/components/schemas/ModelCapabilityMetadataDeclaration'},
    }
    source = schemas['ModelCapabilityMetadataSource']
    assert {key: value for key, value in source.items() if key != 'description'} == {
        'type': 'object', 'properties': {
            'kind': {'type': 'string', 'enum': ['administrator']},
            'version': {'type': 'string', 'pattern': r'^sha256:[0-9a-f]{64}$(?![\s\S])'},
        }, 'required': ['kind', 'version'], 'additionalProperties': False,
    }
    entry = schemas['PricingEntry']
    assert entry['required'] == ['model_name', 'quota_type', 'model_ratio', 'model_price', 'owner_by',
                                 'completion_ratio', 'enable_groups', 'supported_endpoint_types']
    legacy = {'model_name', 'description', 'icon', 'tags', 'owner_by', 'billing_mode', 'billing_expr',
              'pricing_version', 'model_ratio', 'model_price', 'completion_ratio', 'cache_ratio',
              'create_cache_ratio', 'image_ratio', 'audio_ratio', 'audio_completion_ratio', 'vendor_id',
              'quota_type', 'enable_groups', 'supported_endpoint_types', 'billing_usage_schema',
              'billing_usage_examples', 'billing_plugin_variants'}
    assert set(entry['properties']) == legacy | set(facts) | {'metadata_source'}
    for name, schema in properties.items():
        assert entry['properties'][name] == ({'type': 'string'} if name == 'description' else schema)
    assert entry['properties']['metadata_source'] == {'$ref': '#/components/schemas/ModelCapabilityMetadataSource'}
    assert entry['oneOf'] == [
        {'not': {'anyOf': [{'required': [name]} for name in facts if name != 'description'] + [{'required': ['metadata_source']}]}},
        {'required': ['metadata_source'], 'anyOf': [{'required': [name]} for name in facts]},
    ]
    operation = api['paths']['/api/option/']['put']
    branches = operation['requestBody']['content']['application/json']['schema']['oneOf']
    assert branches == [
        {'$ref': '#/components/schemas/ModelCapabilityMetadataOptionWrite'},
        {'type': 'object', 'properties': {
            'key': {'type': 'string', 'not': {'enum': ['ModelCapabilityMetadata', 'ClientEventsConfig']}}, 'value': {},
        }, 'required': ['key', 'value'], 'additionalProperties': True},
        {'$ref': '#/components/schemas/ClientEventsConfigOptionWrite'},
    ]
    write = schemas['ModelCapabilityMetadataOptionWrite']
    assert write['properties']['key'] == {'type': 'string', 'enum': ['ModelCapabilityMetadata']}
    assert {key: value for key, value in write['properties']['value'].items() if key != 'description'} == {
        'type': 'string', 'maxLength': 65536,
    }
    assert set(write['properties']) == {'key', 'value'} and write['required'] == ['key', 'value']
    assert write['type'] == 'object' and write.get('additionalProperties', True) is True
    assert operation['security'] == [{'DashboardJWT': []}, {'PersonalAccessToken': []}]
    assert operation['x-pat-scope'] == 'option:write'
    contract = api['x-model-capability-metadata-contract']
    assert contract['facts'] == facts and contract['bounds'] == {
        'bytes': 65536, 'models': 256, 'model_name_bytes': 255, 'positive_integer_maximum': 9007199254740991,
    }
    assert contract['exclusions'] == ['model retrieve and native Anthropic/Gemini list formats', 'automatic catalog ingestion', 'price/auth/routing/billing changes', 'UI']
    assert 'no linearizable multiwriter' in contract['consistency']
    projection = relay['components']['schemas']['ModelWithCapabilityMetadata']
    assert projection['allOf'][0] == {'$ref': '#/components/schemas/Model'}
    assert projection['allOf'][1]['properties'] == properties | {'metadata_source': {'$ref': '#/components/schemas/ModelCapabilityMetadataSource'}}
    assert relay['components']['schemas']['ModelsResponse']['properties']['data']['items'] == {'$ref': '#/components/schemas/ModelWithCapabilityMetadata'}
    assert set(relay['components']['schemas']['Model']['properties']) == {'id', 'object', 'created', 'owned_by'}
    return {'authority': 'administrator', 'unknown_omitted': True, 'explicit_empty_sets': True,
            'scope': '/api/pricing and visible OpenAI-format /v1/models list'}


def check_token_pricing(api):
    operation = api['paths']['/api/pricing']['get']
    assert operation['security'] == [{}, {'DashboardJWT': []}, {'PersonalAccessToken': []}, {'RelayKey': []}]
    assert operation['x-token-pricing-contract'] == {
        'availability': 'sk only when pricing is enabled and public; dashboard root exception never applies to sk',
        'credential': 'one Authorization value: exact Bearer or bearer, ASCII space, lowercase sk- and nonempty key; no whitespace, controls, comma or dash suffix',
        'principal': 'trusted pricing branch and request-local authenticated token/owner-group snapshot; no credential reparse lookup',
        'group': 'required top-level selection: token group, otherwise owner group; auto remains auto',
        'named': 'current selectable permission and ratio required; revoked or unavailable gives empty collections without fallback',
        'auto': 'permission to select auto required; empty/null/[] inherits global order; nonempty custom filters current permissions before dedup/limit; malformed or revoked yields empty without fallback',
        'projection': 'fresh maps and copied entries; enable_groups intersects candidates; all expands only to candidates; owner-base overrides; prices and units unchanged',
        'cache_control': 'private, no-store on every sk response',
        'legacy': 'anonymous and dashboard response fields and navigation behavior unchanged',
    }
    assert operation['responses']['200']['content']['application/json']['schema'] == {
        'oneOf': [{'$ref': '#/components/schemas/PublicPricingResult'}, {'$ref': '#/components/schemas/TokenPricingResult'}],
    }
    for status in ['200', '401', '403', '500']:
        assert 'private, no-store' in operation['responses'][status]['headers']['Cache-Control']['description']
    schemas = api['components']['schemas']
    public, token = schemas['PublicPricingResult'], schemas['TokenPricingResult']
    fields = ['success', 'data', 'vendors', 'group_ratio', 'usable_group', 'supported_endpoint', 'auto_groups', 'pricing_version']
    assert public['required'] == fields and set(public['properties']) == set(fields)
    assert token['required'] == fields + ['group'] and set(token['properties']) == set(fields + ['group'])
    assert public['additionalProperties'] is False and token['additionalProperties'] is False
    assert token['properties']['group'] == {'type': 'string'}
    assert token['properties']['data'] == {'type': 'array', 'items': {'$ref': '#/components/schemas/TokenPricingEntry'}}
    for field in set(fields) - {'data'}:
        assert public['properties'][field] == token['properties'][field], field
    assert schemas['TokenPricingEntry'] == {
        'allOf': [{'$ref': '#/components/schemas/PricingEntry'}, {'type': 'object', 'properties': {
            'enable_groups': {'type': 'array', 'minItems': 1, 'uniqueItems': True, 'items': {'type': 'string', 'not': {'enum': ['all']}}},
        }}], 'description': 'Only selected permitted candidates; the all sentinel is expanded and never returned.',
    }
    assert schemas['PricingEntry']['additionalProperties'] is False
    for name in ['model_ratio', 'model_price', 'completion_ratio']:
        assert schemas['PricingEntry']['properties'][name] == {'type': 'number', 'format': 'double'}
    return {'optional_public_sk': True, 'required_token_group': True, 'legacy_shape_preserved': True, 'execution_capability': False}


def check_token_usage(api):
    operation = api['paths']['/api/usage/token/']['get']
    assert operation['security'] == [{'RelayKey': []}]
    assert operation['x-token-usage-contract'] == {
        'principal': 'request-local authenticated token and owner-group snapshot; no credential reparse lookup',
        'group': 'nonempty token group, otherwise authenticated owner group; auto remains auto',
        'auto_groups': False, 'pricing': False,
        'quota_privacy': 'user_quota only when AllowUserQuotaQuery', 'cache_control': 'private, no-store',
    }
    for status in ['200', '401', '403', '500']:
        assert operation['responses'][status]['headers']['Cache-Control']['schema'] == {'$ref': '#/components/schemas/OrganizationCacheControl'}
    assert operation['responses']['200']['content']['application/json']['schema'] == {
        'oneOf': [{'$ref': '#/components/schemas/TokenUsageResult'}, {'$ref': '#/components/schemas/ManagementError'}],
    }
    schemas = api['components']['schemas']
    assert schemas['TokenUsageResult'] == {
        'type': 'object', 'properties': {
            'code': {'type': 'boolean', 'enum': [True]}, 'message': {'type': 'string', 'enum': ['ok']},
            'data': {'$ref': '#/components/schemas/TokenUsageData'},
        }, 'required': ['code', 'message', 'data'], 'additionalProperties': False,
    }
    data = schemas['TokenUsageData']
    types = {'object': 'string', 'name': 'string', 'group': 'string', 'total_granted': 'integer',
             'total_used': 'integer', 'total_available': 'integer', 'unlimited_quota': 'boolean',
             'model_limits': 'object', 'model_limits_enabled': 'boolean', 'expires_at': 'integer'}
    assert data['type'] == 'object' and data['additionalProperties'] is False
    assert data['required'] == list(types)
    assert set(data['properties']) == set(types) | {'user_quota'}
    for name, kind in types.items():
        assert data['properties'][name]['type'] == kind
        assert data['properties'][name].get('nullable', False) is False
    assert data['properties']['object']['enum'] == ['token_usage']
    assert data['properties']['model_limits']['additionalProperties'] == {'type': 'boolean'}
    user_quota = data['properties']['user_quota']
    assert user_quota['type'] == 'object' and user_quota['additionalProperties'] is False
    assert user_quota['required'] == ['total_available', 'total_used']
    assert user_quota['properties'] == {name: {'type': 'integer', 'format': 'int64'} for name in user_quota['required']}
    return {'group': 'selected/inherited/auto', 'pricing': False, 'auto_groups': False}



def check_token_usage_series(api):
    schemas = api['components']['schemas']
    for suffix, result, operation_id in [('logs', 'TokenUsageLogsResult', 'getTokenUsageLogs'),
                                         ('stat', 'TokenUsageStatResult', 'getTokenUsageStat')]:
        operation = api['paths']['/api/usage/token/' + suffix]['get']
        assert operation['operationId'] == operation_id
        assert operation['security'] == [{'RelayKey': []}]
        assert operation['x-automatic-retry'] is False
        assert set(operation['responses']) == {'200', '400', '401', '403', '500', '503'}
        assert operation['responses']['200']['content']['application/json']['schema'] == {'$ref': '#/components/schemas/' + result}
        for response in operation['responses'].values():
            assert response['headers']['Cache-Control']['schema'] == {'$ref': '#/components/schemas/OrganizationCacheControl'}
        envelope = schemas[result]
        assert envelope['properties']['data_complete'] == {'type': 'boolean', 'enum': [False]}
        assert set(envelope['required']) == set(envelope['properties'])
        assert envelope['additionalProperties'] is False
        for status in ['401', '403', '500']:
            assert {'$ref': '#/components/schemas/ManagementError'} in operation['responses'][status]['content']['application/json']['schema']['anyOf']
    log = schemas['TokenUsageLog']
    assert set(log['properties']) == set(log['required']) == {'created_at', 'model_name', 'prompt_tokens', 'completion_tokens', 'quota', 'use_time', 'is_stream', 'group'}
    assert log['additionalProperties'] is False
    bucket = schemas['TokenUsageBucket']
    assert set(bucket['properties']) == set(bucket['required']) == {'ts', 'quota', 'requests', 'tokens'}
    assert schemas['TokenUsageStatResult']['properties']['granularity']['enum'] == ['hour', 'day']
    maximum = 9007199254740991
    for schema, fields in [(log, ('created_at', 'prompt_tokens', 'completion_tokens', 'quota', 'use_time')),
                           (bucket, ('quota', 'requests', 'tokens'))]:
        for field in fields:
            assert schema['properties'][field] == {
                'type': 'integer', 'format': 'int64', 'minimum': -maximum, 'maximum': maximum}
    for schema, field in [(bucket, 'ts'), (schemas['TokenUsageLogPage'], 'total')]:
        assert schema['properties'][field] == {
            'type': 'integer', 'format': 'int64', 'minimum': 0, 'maximum': maximum}
    failure = schemas['TokenUsageQueryFailedError']
    assert failure['additionalProperties'] is False
    assert set(failure['required']) == set(failure['properties']) == {'success', 'message', 'code'}
    assert failure['properties']['success'] == {'type': 'boolean', 'enum': [False]}
    assert failure['properties']['code'] == {'type': 'string', 'enum': ['TOKEN_USAGE_QUERY_FAILED']}
    for suffix in ('logs', 'stat'):
        operation = api['paths']['/api/usage/token/' + suffix]['get']
        assert {'$ref': '#/components/schemas/TokenUsageQueryFailedError'} in operation['responses']['500']['content']['application/json']['schema']['anyOf']
        assert 'no partial data' in operation['description']
        assert 'not clamped or rounded' in operation['description']
    return {'api_key_only': True, 'utc_sparse': True, 'data_complete': False,
            'signed_safe_integers': True, 'numeric_failure_without_partial_data': True,
            'legacy_management_errors_preserved': True, 'live_http': False}


def check_organization_limits(api):
    schemas = api['components']['schemas']
    fields = {'max_organizations_created', 'max_organizations_joined'}
    for name in ['OrganizationLimits', 'OrganizationLimitsUpdate']:
        schema = schemas[name]
        assert schema['additionalProperties'] is False
        assert set(schema['required']) == set(schema['properties']) == fields
    for field in fields:
        assert schemas['OrganizationLimits']['properties'][field] == {'type': 'integer', 'minimum': 0, 'maximum': 9007199254740991}
        assert schemas['OrganizationLimitsUpdate']['properties'][field] == {'$ref': '#/components/schemas/OrganizationLimitDecimal'}
    decimal = schemas['OrganizationLimitDecimal']
    assert decimal['type'] == 'string' and decimal['maxLength'] == 16
    for value in ['0', '1', '9007199254740990', '9007199254740991']:
        validate_value(api, decimal, value)
    for value in ['', '00', '+1', '-1', ' 1', '1 ', '1e1', '1\n', '9007199254740992', '9999999999999999', 0, None]:
        assert list(OAS30Validator(decimal).iter_errors(value)), value
    for path, method, operation_id, result, failure in [
        ('/api/organizations/limits', 'get', 'getOrganizationLimits', 'OrganizationLimitsResult', 'OrganizationLimitsUnavailable'),
        ('/api/option/organization_limits', 'put', 'updateOrganizationLimits', 'OrganizationLimitsUpdated', 'OrganizationLimitsUpdateFailed'),
    ]:
        operation = api['paths'][path][method]
        assert set(api['paths'][path]) == {method}
        assert operation['operationId'] == operation_id
        assert operation['security'] == [{'DashboardJWT': []}]
        assert operation['parameters'] == [] and operation['x-query-policy'] == 'forbidden'
        assert operation['x-automatic-retry'] is False
        assert {'X-Organization-Id', 'X-Security-Proof', 'Idempotency-Key'} <= set(operation['x-forbidden-request-headers'])
        assert set(operation['responses']) == {'200', '400', '401', '403', '429', '500', '503'} | ({'413', '415'} if method == 'put' else set())
        for response in operation['responses'].values():
            assert response['headers']['Cache-Control']['schema'] == {'$ref': '#/components/schemas/OrganizationCacheControl'}
        for status, name in [('200', result), ('503', failure)]:
            assert operation['responses'][status]['content']['application/json']['schema'] == {'$ref': '#/components/schemas/' + name}
            assert schemas[name]['additionalProperties'] is False
        assert 'content' not in operation['responses']['429']
        assert operation['responses']['500']['x-empty-body-possible'] is True
        if method == 'put':
            assert operation['x-request-max-bytes'] == 1024
            assert operation['requestBody'] == {'required': True, 'content': {'application/json': {'schema': {'$ref': '#/components/schemas/OrganizationLimitsUpdate'}}}}
        else:
            assert 'requestBody' not in operation
    assert set(schemas['OrganizationLimitsUpdated']['properties']) == set(schemas['OrganizationLimitsUpdated']['required']) == {'success', 'message'}
    assert schemas['OrganizationLimitsUnavailable']['properties']['code']['enum'] == ['ORG_LIMITS_UNAVAILABLE']
    assert schemas['OrganizationLimitsUpdateFailed']['properties']['code']['enum'] == ['ORG_LIMITS_UPDATE_FAILED']
    return {'routes': 2, 'live_session_only': True, 'safeinteger_pair': True, 'automatic_retry': False, 'live_http': False}


def check_organization_create_rate(api):
    operation = api['paths']['/api/organizations']['post']
    rate = operation['x-organization-create-rate-limit']
    assert rate['configuration'] == ['CRITICAL_RATE_LIMIT_ENABLE', 'CRITICAL_RATE_LIMIT', 'CRITICAL_RATE_LIMIT_DURATION']
    assert rate['defaults'] == {'enabled': True, 'requests': 20, 'window_seconds': 1200}
    assert rate['quantity_cap'] is False and rate['idempotency'] is False
    limited = operation['responses']['429']
    assert 'content' not in limited and '$ref' not in limited
    assert limited['headers']['Retry-After']['schema'] == {'type': 'integer', 'minimum': 1}
    assert limited['headers']['Cache-Control']['schema'] == {'$ref': '#/components/schemas/OrganizationCacheControl'}
    assert 'empty body' in operation['responses']['500']['description']
    assert operation['responses']['500']['content']['application/json']['schema'] == {'$ref': '#/components/schemas/OrganizationLifecycleError500'}
    assert 'Idempotency-Key' not in operation['x-forbidden-request-headers']
    assert api['x-organization-create-idempotency']['replay_counts_as_rate_attempt'] is True
    assert operation['x-automatic-retry'] is False
    return {'route': 'POST /api/organizations', 'empty_429': True, 'empty_limiter_500': True,
            'quantity_cap': False, 'idempotency': False, 'live_http': False}


def check_organization_lifecycle(api, relay, fixtures, design_gate):
    check_organization_wallet(api, relay)
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
    assert conflict['properties']['code']['enum'] == [
        'ORG_STATE_CHANGED', 'ORG_NAME_TAKEN', 'ORG_CREATED_LIMIT_REACHED', 'ORG_JOINED_LIMIT_REACHED',
        'ORG_IDEMPOTENCY_CONFLICT', 'ORG_DISABLED', 'ORG_REQUEST_RESOLVED',
        'ORG_ALREADY_MEMBER', 'ORG_INVITATION_EXISTS', 'ORG_WALLET_REQUEST_CONFLICT',
        'ORG_WALLET_ALREADY_REVERSED', 'ORG_WALLET_INSUFFICIENT_AVAILABLE',
        'ORG_WALLET_LIMIT_EXCEEDED', 'ORG_WALLET_NOT_EMPTY',
    ]
    assert contract['name_uniqueness'] == {
        'scope': 'same owner_user_id, dissolved_at = 0',
        'comparison': 'Go strings.EqualFold(strings.TrimSpace(candidate), strings.TrimSpace(existing))',
        'unicode': 'simple case folding only; no normalization, full folding, accent or width removal',
        'disabled_reserves': True, 'dissolved_reserves': False,
        'writers': ['create', 'rename', 'transfer_accept'],
        'conflict': {'status': 409, 'code': 'ORG_NAME_TAKEN', 'data': False},
        'exact_self_rename': 'ORG_STATE_CHANGED',
        'case_only_rename': 'allowed only when no other same-owner non-dissolved name conflicts',
        'history': 'existing duplicates remain unchanged; rename to a conflict-free name is allowed',
        'concurrency': 'formal API transactions serialize on the existing owner User lock; no schema or direct SQL constraint',
    }
    for path, method in [('/api/organizations', 'post'), ('/api/organizations/{org_id}/name', 'patch'),
                         ('/api/organizations/{org_id}/ownership-transfers/{transfer_id}/accept', 'post'),
                         ('/api/organizations/{org_id}/authorization-context', 'post')]:
        assert '409 ORG_NAME_TAKEN without data or conflicting organization details' in api['paths'][path][method]['description']
    assert conflict['properties']['data']['properties'] == {'revision': {'$ref': '#/components/schemas/OrganizationLifecycleID'}}
    assert conflict['properties']['data']['required'] == ['revision']
    assert conflict['properties']['data']['additionalProperties'] is False
    assert 'additionalProperties' not in conflict
    assert conflict['oneOf'] == [
        {'properties': {'code': {'enum': ['ORG_STATE_CHANGED']}}},
        {'properties': {'success': {'type': 'boolean', 'enum': [False]}, 'message': {'type': 'string'},
                        'code': {'enum': ['ORG_NAME_TAKEN', 'ORG_CREATED_LIMIT_REACHED', 'ORG_JOINED_LIMIT_REACHED']}}, 'additionalProperties': False},
        {'properties': {'code': {'enum': [value for value in conflict['properties']['code']['enum']
                                        if value not in ('ORG_STATE_CHANGED', 'ORG_NAME_TAKEN', 'ORG_CREATED_LIMIT_REACHED', 'ORG_JOINED_LIMIT_REACHED')]}},
         'not': {'required': ['data']}},
    ]
    for path in ['/api/organizations/{org_id}/invitations', '/api/organizations/{org_id}/invitations/{invitation_id}/reissue']:
        operation = api['paths'][path]['post']
        assert 'errors never include the current revision.' not in operation['description']
        assert 'only an authorized stale invite/reissue may include data.revision observed under the existing locks; other conflicts omit it.' in operation['description']
        assert operation['x-organization-invitation-conflicts']['self_invite'] == {'code': 'ORG_SELF_INVITE', 'status': 400, 'retry': 'choose another user'}
    scopes = schemas['OrganizationLifecycleProofResult']['properties']['scope']['enum']
    assert len(scopes) == len(set(scopes)) == 11
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
            if route['id'] == 'W01':
                assert 'Idempotency-Key' not in op['x-forbidden-request-headers']
                key = [p for p in parameters if p.get('name') == 'Idempotency-Key']
                assert len(key) == 1 and key[0]['required'] is False
                assert key[0]['schema'] == {'$ref': '#/components/schemas/OrganizationCreateIdempotencyKey'}
                assert op['responses']['200']['content'] == op['responses']['201']['content']
                assert api['x-organization-create-idempotency']['automatic_retry'] is False
                assert api['x-organization-create-idempotency']['replay_status'] == 200
                assert api['x-organization-create-idempotency']['replay_requires_current_authority'] is True
            else:
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
            elif contract['schema_map'][key] in ('OrganizationLifecyclePreviewBody2', 'OrganizationLifecycleVerificationOperation',
                                                  'OrganizationLifecycleProofResult', 'OrganizationLifecycleMethods', 'OrganizationLifecyclePreviewResult'):
                # The wallet branches are checked exactly above; compare the
                # original closed lifecycle structures against the frozen gate.
                actual = copy.deepcopy(actual)
                name = contract['schema_map'][key]
                if name in ('OrganizationLifecyclePreviewBody2', 'OrganizationLifecycleVerificationOperation'):
                    actual['oneOf'] = actual['oneOf'][:-2]
                elif name in ('OrganizationLifecycleProofResult', 'OrganizationLifecycleMethods'):
                    actual['properties']['scope']['enum'] = actual['properties']['scope']['enum'][:-2]
                else:
                    for field in ('amount', 'request_id', 'credit_id', 'reference', 'reason'):
                        del actual['properties']['display']['properties'][field]
                    del actual['oneOf']
            compare_schema(expected, actual, key)
        gate_checked = True
    return {'routes': len(routes), 'schemas': len(contract['schema_map']), 'organization_scopes': len(scopes), 'frozen_design_checked': gate_checked, 'design_contract_id': contract['design_contract_id'], 'effective_design_gate_sha256': contract['design_gate_sha256'], 'live_http': False}



def check_organization_wallet(api, relay):
    schemas = api['components']['schemas']
    contract = api['x-organization-wallet-contract']
    base = '/api/platform/organizations/{org_id}'
    expected = [('GET', '/api/organizations/{org_id}/wallet', 'organization_wallet_balance', 'owner/admin'),
                ('GET', base + '/wallet', 'platform_organization_wallet_balance', 'root'),
                ('POST', base + '/wallet/credits', 'organization_wallet_credit', 'root'),
                ('POST', base + '/wallet/credits/{credit_id}/reverse', 'organization_wallet_reverse', 'root')]
    assert contract['routes'] == [dict(method=m, path=p, operationId=o, permission=r) for m, p, o, r in expected]
    assert contract['tables'] == ['organization_wallets', 'organization_wallet_entries']
    assert contract['consumption_enabled'] is False and contract['personal_funds_fallback'] is False
    assert contract['disabled'] == {'credit': False, 'reverse': True, 'owner_admin_read': True}
    assert contract['dissolved'] == {'write': False, 'owner_admin_read': False, 'platform_root_read': True}
    assert contract['maximum_quota'] == '9007199254740991'
    scopes = ['platform.organization.wallet_credit', 'platform.organization.wallet_reverse']
    assert contract['scopes'] == schemas['OrganizationLifecycleProofResult']['properties']['scope']['enum'][-2:] == scopes
    assert schemas['OrganizationLifecycleMethods']['properties']['scope']['enum'] == schemas['OrganizationLifecycleProofResult']['properties']['scope']['enum']
    for kind, scope in zip(('Credit', 'Reverse'), scopes):
        body = schemas['OrganizationWalletBody' + kind]
        fields = {'revision', 'request_id', 'reason'} | ({'amount', 'reference'} if kind == 'Credit' else set())
        assert set(body['properties']) == set(body['required']) == fields and body['additionalProperties'] is False
        command = schemas['OrganizationWalletCommand' + kind]
        full = fields | {'organization_id'} | ({'credit_id'} if kind == 'Reverse' else set())
        assert set(command['properties']) == set(command['required']) == full and command['additionalProperties'] is False
        context = schemas['OrganizationWalletContext' + kind]
        assert context['properties']['command'] == {'$ref': '#/components/schemas/OrganizationWalletCommand' + kind}
        assert context['properties']['snapshot'] == {
            'type': 'object', 'properties': {'wallet_amount': {'$ref': '#/components/schemas/OrganizationWalletAmount'}},
            'required': ['wallet_amount'], 'additionalProperties': False}
        assert schemas['OrganizationWalletOperation' + kind] == {
            'type': 'object', 'properties': {'scope': {'type': 'string', 'enum': [scope]},
            'context': {'$ref': '#/components/schemas/OrganizationWalletContext' + kind}},
            'required': ['scope', 'context'], 'additionalProperties': False}
        assert schemas['OrganizationLifecycleVerificationOperation']['oneOf'][-2 + ('Credit', 'Reverse').index(kind)] == {
            '$ref': '#/components/schemas/OrganizationWalletOperation' + kind}
        assert schemas['OrganizationLifecyclePreviewBody2']['oneOf'][-2 + ('Credit', 'Reverse').index(kind)] == {
            'type': 'object', 'properties': {'action': {'type': 'string', 'enum': ['wallet_' + kind.lower()]},
            'command': {'$ref': '#/components/schemas/OrganizationWalletCommand' + kind}},
            'required': ['action', 'command'], 'additionalProperties': False}
    assert len(schemas['OrganizationLifecyclePreviewBody2']['oneOf']) == 3
    assert len(schemas['OrganizationLifecycleVerificationOperation']['oneOf']) == 11
    display = schemas['OrganizationLifecyclePreviewResult']['properties']['display']
    assert set(display['properties']) - set(display['required']) == {'amount', 'request_id', 'credit_id', 'reference', 'reason'}
    wallet_display = {
        'amount': {'$ref': '#/components/schemas/OrganizationWalletAmount'},
        'request_id': {'$ref': '#/components/schemas/OrganizationWalletRequestID'},
        'credit_id': {'oneOf': [{'type': 'string', 'enum': ['']}, {'$ref': '#/components/schemas/OrganizationLifecycleID'}]},
        'reference': {'oneOf': [{'type': 'string', 'enum': ['']}, {'$ref': '#/components/schemas/OrganizationWalletText'}]},
        'reason': {'$ref': '#/components/schemas/OrganizationWalletText'},
    }
    assert {field: display['properties'][field] for field in wallet_display} == wallet_display
    previous_scopes = ['organization.self_disable', 'platform.organization.disable', 'organization.dissolve',
                       'organization.change_role', 'organization.remove', 'organization.invite',
                       'organization.reissue', 'organization.transfer_initiate', 'organization.transfer_accept']
    assert schemas['OrganizationLifecyclePreviewResult']['oneOf'] == [
        {'properties': {'operation': {'properties': {'scope': {'enum': previous_scopes}}},
                        'display': {'not': {'anyOf': [{'required': [field]} for field in wallet_display]}}}},
        {'properties': {'operation': {'properties': {'scope': {'enum': scopes}}},
                        'display': {'required': list(wallet_display)}}},
    ]
    for method, path, operation_id, permission in expected:
        operation = api['paths'][path][method.lower()]
        assert operation['operationId'] == operation_id and operation['security'] == [{'DashboardJWT': []}]
        assert operation['x-organization-wallet-permission'] == permission and operation['x-automatic-retry'] is False
        assert {'method': method, 'path': path} in api['x-organization-selection-boundary']['positive_selector_allowlist']
        assert path not in relay['paths']
        if method == 'GET':
            assert 'requestBody' not in operation and operation['x-security-proof-policy'] == 'forbidden'
            expected_permission = ('current active owner/admin membership; disabled organization may be read'
                                   if permission == 'owner/admin' else 'current DB root only; no delegated platform permission')
            assert operation['x-organization-permission'] == expected_permission
            assert operation['responses']['200']['description'] == 'Current authorized organization wallet balance snapshot; reading does not open an account.'
        else:
            assert operation['x-security-proof-policy'] == 'required'
            assert next(p for p in operation['parameters'] if p.get('name') == 'X-Security-Proof')['required'] is True
    return {'routes': 4, 'consumption_enabled': False, 'live_http': False}


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

def check_site_description(api):
    operation = api['paths']['/api/status']['get']
    assert operation['operationId'] == 'getApiStatus' and operation['security'] == []
    assert operation['responses']['200']['content']['application/json']['schema'] == {'$ref': '#/components/schemas/SiteDescriptionResult'}
    assert operation['x-organization-selection'].startswith('personal-only;')
    schemas = api['components']['schemas']
    result = schemas['SiteDescriptionResult']
    assert result == {'type': 'object', 'additionalProperties': False, 'required': ['success', 'message', 'data'],
                      'properties': {'success': {'type': 'boolean', 'enum': [True]}, 'message': {'type': 'string', 'enum': ['']},
                                     'data': {'$ref': '#/components/schemas/SiteDescription'}}}
    description = schemas['SiteDescription']
    fields = {'instance_id': 'SiteInstanceID', 'console_links': 'ConsoleLinks',
              'oauth': 'DesktopOAuthDiscovery', 'client_features': 'ClientFeatureFlags'}
    assert description['type'] == 'object' and 'additionalProperties' not in description
    assert set(description['required']) == set(fields)
    expected_properties = {key: {'$ref': '#/components/schemas/' + value} for key, value in fields.items()}
    expected_properties.update({'enable_data_export': {'type': 'boolean'}, 'quota_per_unit': {'type': 'number'}})
    assert {key: {k: v for k, v in value.items() if k != 'description'}
            for key, value in description['properties'].items()} == expected_properties
    identity = schemas['SiteInstanceID']
    assert identity['type'] == 'string' and identity['pattern'] == r'^(?!00000000-0000-0000-0000-000000000000)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$(?![\s\S])'
    links = schemas['ConsoleLinks']
    routes = {'topup': '/wallet', 'usage_logs': '/usage-logs', 'keys': '/keys', 'pricing': '/pricing'}
    assert links['type'] == 'object' and links['additionalProperties'] is False
    assert set(links['required']) == set(links['properties']) == set(routes)
    for key, route in routes.items():
        link = links['properties'][key]
        assert {k: v for k, v in link.items() if k != 'description'} == {
            'type': 'string', 'nullable': True, 'pattern': r'^https?://[^/?#@\s\\]+(?:/[^?#\s\\]*)?$(?![\s\S])'}
        assert route in link['description']
    for name, flags in [('DesktopOAuthDiscovery', ['enabled']), ('ClientFeatureFlags', ['token_usage_logs', 'oauth', 'model_metadata'])]:
        schema = schemas[name]
        assert {k: v for k, v in schema.items() if k != 'description'} == {
            'type': 'object', 'additionalProperties': False, 'required': flags,
            'properties': {key: {'type': 'boolean', 'enum': [False]} for key in flags}}
        assert schema['description']
    assert all(path in schemas['ClientFeatureFlags']['description'] for path in
               ('/api/log/token', '/api/log/self', '/api/data/self', '/api/pricing'))
    assert 'GitHub/OIDC' in schemas['DesktopOAuthDiscovery']['description']
    return {'anonymous': True, 'additive_fields': list(fields), 'links': routes,
            'future_contracts_enabled': False, 'live_http': False}


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
    results['no_available_channel_detail'] = check_no_available_channel_detail(relay)
    results['oauth_public'] = check_oauth_public(api)
    results['oauth_ordinary_token'] = check_oauth_ordinary_token(api, source_root)
    results['oauth_usage'] = check_oauth_usage(api, source_root)
    results['native_search'] = check_native_search(relay)
    access = api['components']['schemas']['OrganizationAccess']['properties']['capabilities']
    context_access = api['components']['schemas']['RequestAccessContext']['properties']['organization']['properties']['capabilities']
    assert access == context_access, 'Organization capability projections differ between detail and context'
    assert access['type'] == 'object' and access['additionalProperties'] is False
    fields = {'organization_read', 'members_read', 'events_read', 'resource_access',
              'organization_token_issue', 'organization_spend', 'organization_mutation'}
    assert set(access['required']) == set(access['properties']) == fields
    properties = access['properties']
    for name in ('organization_read', 'members_read', 'events_read'):
        assert properties[name] == {'type': 'boolean'}
    for name, expected in [('resource_access', {'type': 'boolean', 'enum': [True]}),
                           ('organization_mutation', {'type': 'boolean'})]:
        assert {key: value for key, value in properties[name].items() if key != 'description'} == expected
        assert properties[name]['description']
    for name in ('organization_token_issue', 'organization_spend'):
        assert properties[name] == {'type': 'boolean', 'enum': [False]}
    assert 'All four unimplemented capabilities are false' not in access['description']
    results['organization_capabilities'] = {'governance_roles': ['owner', 'admin'], 'task_read_channel': True,
                                          'token_issuance': False, 'spending': False, 'advisory_only': True, 'live_http': False}
    results['organization_task_reads'] = check_organization_task_reads(api)
    results['site_description'] = check_site_description(api)
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
    results['token_usage'] = check_token_usage(api)
    results['organization_limits'] = check_organization_limits(api)
    results['organization_create_rate'] = check_organization_create_rate(api)
    results['token_usage_series'] = check_token_usage_series(api)
    results['token_pricing'] = check_token_pricing(api)
    results['client_events'] = check_client_events(api, source_root)
    results['client_event_stats'] = check_client_event_stats(api, source_root)
    results['model_capability_metadata'] = check_model_capability_metadata(api, relay)
    results['personal_log_pagination'] = check_personal_log_pagination(api)
    results['personal_log_range_error'] = check_personal_log_range_error(api)
    results['personal_quota_series'] = check_personal_quota_series(api)
    results['personal_query_errors'] = check_personal_query_errors(api)
    results['oauth_userinfo'] = check_oauth_userinfo(api, source_root)
    results['oauth_balance'] = check_oauth_balance(api, source_root)
    results['oauth_provider'] = check_oauth_provider(api, source_root)
    results['oauth_revocation'] = check_oauth_revocation(api, source_root)
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
