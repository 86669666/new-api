// Generate both real fetch clients outside the checkout, compile them, then
// exercise selected generated requests with a fetch stub (no gateway/provider I/O).
// Install openapi-typescript-codegen@0.29.0 and typescript@5.9.3 in --tool-dir.
// node scripts/openapi/check_client.mjs --tool-dir /absolute/tools --output /absolute/temp
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { adaptOrganizationQuery, organizationQueryOperations } from './adapt_generated_org_query.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const args = process.argv.slice(2);
const toolDir = args[args.indexOf('--tool-dir') + 1];
const output = args[args.indexOf('--output') + 1];
assert(args.includes('--tool-dir') && args.includes('--output') && path.isAbsolute(toolDir) && path.isAbsolute(output), 'Both absolute --tool-dir and --output are required');
assert(!path.resolve(output).startsWith(path.resolve(root) + path.sep) && path.resolve(output) !== path.resolve(root), 'Generated output must remain outside the checkout');
const require = createRequire(path.join(toolDir, 'package.json'));
const codegen = require('openapi-typescript-codegen');
assert.equal(require('openapi-typescript-codegen/package.json').version, '0.29.0');
assert.equal(require('typescript/package.json').version, '5.9.3');
await mkdir(output, { recursive: true });
for (const name of ['api', 'relay']) {
  // Union types preserve the empty-string success message without generating
  // an invalid enum member. Wire schemas and pinned dependencies are unchanged.
  await codegen.generate({ input: path.join(root, 'docs/openapi', name + '.json'), output: path.join(output, 'generated', name), httpClient: 'fetch', useOptions: true, useUnionTypes: true });
}
const organizationService = path.join(output, 'generated/api/services/OrganizationsService.ts');
const rawOrganizationService = await readFile(organizationService, 'utf8');
const adaptedOrganizationService = adaptOrganizationQuery(rawOrganizationService);
assert.equal(adaptOrganizationQuery(rawOrganizationService), adaptedOrganizationService, 'Adaptation must be deterministic');
assert.equal(adaptedOrganizationService.replaceAll('queryOrgId', 'orgId'), rawOrganizationService, 'Only the query variable name may change');
assert.throws(() => adaptOrganizationQuery(adaptedOrganizationService), /Expected unadapted/);
assert.throws(() => adaptOrganizationQuery(rawOrganizationService.replace('public static getOrganizationAccess', 'public static changedOrganizationAccess')), /Expected one getOrganizationAccess/);
assert.throws(() => adaptOrganizationQuery(rawOrganizationService.replace("            path: {\n                'org_id': orgId,", "            path: {\n                'org_id': changedId,")), /Unexpected getOrganizationAccess path\/header shape/);
assert.throws(() => adaptOrganizationQuery(rawOrganizationService.replace('        orgId,\n        xOrganizationId,\n        orgId,', '        orgId,\n        xOrganizationId,\n        changedId,')), /Unexpected getOrganizationAccess query shape/);
await writeFile(path.join(output, 'unadapted-OrganizationsService.ts'), rawOrganizationService);
await writeFile(organizationService, adaptedOrganizationService);
const adaptation = {
  generator: 'openapi-typescript-codegen@0.29.0',
  options: { httpClient: 'fetch', useOptions: true, useUnionTypes: true },
  methods: organizationQueryOperations.map(operation => operation.method),
  change: 'Rename only the optional query variable to queryOrgId; preserve path orgId and both HTTP names org_id.',
  helper: 'scripts/openapi/adapt_generated_org_query.mjs',
  raw_sha256: createHash('sha256').update(rawOrganizationService).digest('hex'),
  adapted_sha256: createHash('sha256').update(adaptedOrganizationService).digest('hex'),
  raw_generation_adapted_before_compile: true,
};
await writeFile(path.join(output, 'generator-adaptation.json'), JSON.stringify(adaptation, null, 2) + '\n');
const apiDocument = JSON.parse(await readFile(path.join(root, 'docs/openapi/api.json'), 'utf8'));
const allFixtures = JSON.parse(await readFile(path.join(root, 'scripts/openapi/fixtures.json'), 'utf8'));
const cacheFixtures = allFixtures.filter(fixture => fixture.kind === 'cache_control');
assert(cacheFixtures.length > 0, 'Cache-Control contract fixtures are required');
for (const name of ['api', 'relay']) {
  const document = JSON.parse(await readFile(path.join(root, 'docs/openapi', name + '.json'), 'utf8'));
  const schema = document.components.schemas.OrganizationCacheControl;
  assert.equal(schema.type, 'string');
  assert.equal(schema.enum, undefined, 'Cache-Control must not be a singleton wire enum');
  // Exercise the actual OAS patterns in ECMAScript too. This is a bounded
  // schema check, not validation performed by the generated fetch client.
  for (const fixture of cacheFixtures) {
    const value = Array.isArray(fixture.value) ? fixture.value.join(',') : fixture.value;
    const valid = typeof value === 'string' && schema.allOf.every(rule => new RegExp(rule.pattern).test(value));
    assert.equal(valid, fixture.valid, `${name}: ${fixture.name}`);
  }
}
await writeFile(path.join(output, 'cache-control-schema-results.json'), JSON.stringify({ fixtures: cacheFixtures.length, documents: ['api', 'relay'], engine: 'ECMAScript RegExp', live_http: false, generated_client_response_validation: false }, null, 2) + '\n');
const lifecycleFixtures = allFixtures.filter(fixture => fixture.kind === 's3_operation');
assert.equal(lifecycleFixtures.length, 31);
const services = await Promise.all((await readdir(path.join(output, 'generated/api/services'))).filter(name => name.endsWith('.ts')).map(async name => ({ name: name.slice(0, -3), source: await readFile(path.join(output, 'generated/api/services', name), 'utf8') })));
const statusServices = services.filter(service => service.source.includes('    public static getApiStatus('));
assert.equal(statusServices.length, 1, 'Exactly one generated anonymous status method is required');
const statusService = statusServices[0].name;
const usageServices = services.filter(service => service.source.includes('    public static getApiUsageTokenCollection('));
assert.equal(usageServices.length, 1, 'Exactly one generated read-only usage method is required');
const usageService = usageServices[0].name;
const pricingServices = services.filter(service => service.source.includes('    public static getApiPricing('));
assert.equal(pricingServices.length, 1, 'Exactly one generated pricing method is required');
const pricingService = pricingServices[0].name;
const logServices = services.filter(service => service.source.includes('    public static getApiLogSelf('));
assert.equal(logServices.length, 1, 'Exactly one generated personal log method is required');
const logService = logServices[0].name;
const dataServices = services.filter(service => service.source.includes('    public static getApiDataSelf('));
assert.equal(dataServices.length, 1, 'Exactly one generated personal dashboard data method is required');
const dataService = dataServices[0].name;
const oauthUserInfoServices = services.filter(service => service.source.includes('    public static getOAuthUserInfo('));
assert.equal(oauthUserInfoServices.length, 1, 'Exactly one generated delegated userinfo method is required');
const oauthUserInfoService = oauthUserInfoServices[0].name;
const oauthProviderOperations = [
  ['previewOAuthProviderLogin', '/api/oauth/provider/login/preview', true],
  ['decideOAuthProviderLogin', '/api/oauth/provider/login', false],
  ['previewOAuthProviderConsent', '/api/oauth/provider/consent/preview', true],
  ['decideOAuthProviderConsent', '/api/oauth/provider/consent', false],
].map(([method, route, preview]) => {
  const matches = services.filter(service => service.source.includes(`    public static ${method}(`));
  assert.equal(matches.length, 1, method);
  return { method, route, preview, service: matches[0].name };
});
const camel = value => value.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());
const invocationMap = lifecycleFixtures.map(fixture => {
  const method = camel(fixture.operationId);
  const matches = services.filter(service => service.source.includes(`    public static ${method}(`));
  assert.equal(matches.length, 1, fixture.operationId);
  const parameters = {};
  for (const placeholder of fixture.path.matchAll(/\{([^}]+)\}/g)) parameters[camel(placeholder[1])] = '9007199254740993';
  if (fixture.request !== null) parameters.requestBody = fixture.request;
  if (fixture.proof !== 'forbidden') parameters.xSecurityProof = 'fixture-proof';
  if (fixture.contract_id === 'P01') parameters.scope = 'organization.self_disable';
  return { contract_id: fixture.contract_id, operationId: fixture.operationId, service: matches[0].name, method, http_method: fixture.method.toUpperCase(), path: fixture.path, request_schema: apiDocument.paths[fixture.path][fixture.method].requestBody?.content['application/json'].schema ?? null, response_schema: fixture.response_schema, arguments: parameters };
});
await writeFile(path.join(output, 'operation-invocation-map.json'), JSON.stringify(invocationMap, null, 2) + '\n');
// Compile actual consumer calls, not only the generated definitions: a valid
// ordinary text request previously failed here with TS2741.
const consumer = path.join(output, 'generated/consumer.ts');
await writeFile(consumer, `import { GeminiService } from './relay';
import { Service, OrganizationsService } from './api';
import type { RequestAccessContext } from './api';
export function compileContractCalls() {
  GeminiService.streamGeminiContent({ model: 'fixture', alt: 'sse', requestBody: { contents: [{ role: 'user', parts: [{ text: 'Hello' }] }] } });
  GeminiService.streamGeminiContent({ model: 'fixture', requestBody: { contents: [{ parts: [{ text: 'Hello' }] }], generationConfig: {} } });
  GeminiService.streamGeminiContent({ model: 'fixture', requestBody: { contents: [{ parts: [{ text: 'Draw a cup' }] }], generationConfig: { responseModalities: ['TEXT', 'IMAGE'] } } });
  Service.getDashboardTaskArtifacts({ taskId: 'fixture-task' });
  OrganizationsService.listAccessibleOrganizations({ orgId: '0', afterId: '0', limit: 20 });
  OrganizationsService.getOrganizationRequestContext({ xOrganizationId: '9007199254740993' });
  OrganizationsService.getOrganizationAccess({ orgId: '9007199254740993', queryOrgId: '9007199254740993' });
  OrganizationsService.listOrganizationMembers({ orgId: '9007199254740993', xOrganizationId: '9007199254740993', limit: 1 });
  OrganizationsService.listOrganizationEvents({ orgId: '9007199254740993', afterId: '0' });
  OrganizationsService.organizationWalletBalance({ orgId: '1' });
  OrganizationsService.platformOrganizationWalletBalance({ orgId: '1' });
  OrganizationsService.organizationWalletCredit({ orgId: '1', xSecurityProof: 'fixture-proof', requestBody: { revision: '1', request_id: '00000000-0000-4000-8000-000000000001', amount: '100', reference: 'ticket-17', reason: 'Manual credit' } });
  OrganizationsService.organizationWalletReverse({ orgId: '1', creditId: '2', xSecurityProof: 'fixture-proof', requestBody: { revision: '1', request_id: '00000000-0000-4000-8000-000000000002', reason: 'Correct credit' } });
  // @ts-expect-error wallet amounts remain decimal strings
  OrganizationsService.organizationWalletCredit({ orgId: '1', xSecurityProof: 'fixture-proof', requestBody: { revision: '1', request_id: 'fixture', amount: 100, reference: 'fixture', reason: 'fixture' } });
  const personal: RequestAccessContext = { actor_user_id: '7', org_id: '0', scope_kind: 'personal', organization: null };
  // @ts-expect-error contents must be an array
  GeminiService.streamGeminiContent({ model: 'fixture', requestBody: { contents: 'invalid' } });
  // @ts-expect-error optional configuration must still be an object
  GeminiService.streamGeminiContent({ model: 'fixture', requestBody: { contents: [], generationConfig: 'invalid' } });
  // @ts-expect-error the body is required
  GeminiService.streamGeminiContent({ model: 'fixture' });
  // @ts-expect-error path IDs remain decimal strings
  OrganizationsService.getOrganizationAccess({ orgId: 9007199254740993 });
  // @ts-expect-error path ID is mandatory
  OrganizationsService.listOrganizationMembers({ afterId: '0' });
  // @ts-expect-error cursor IDs remain decimal strings
  OrganizationsService.listOrganizationEvents({ orgId: '1', afterId: 2 });
  // @ts-expect-error page size is a numeric client argument
  OrganizationsService.listAccessibleOrganizations({ limit: '20' });
  // @ts-expect-error no mutation body on a read operation
  OrganizationsService.getOrganizationAccess({ orgId: '1', requestBody: { name: 'Other' } });
  // @ts-expect-error context has no is_access_grant field
  const unexpected: RequestAccessContext = { ...personal, is_access_grant: false };
}
`);
const typedCalls = [];
let lifecycleTypeNegatives = 0;
for (const operation of invocationMap) {
  const call = `client.${operation.service}.${operation.method}`;
  typedCalls.push(`${call}(${JSON.stringify(operation.arguments)});`);
  if (operation.contract_id.startsWith('W') || operation.contract_id.startsWith('A')) {
    const missingBody = { ...operation.arguments };
    delete missingBody.requestBody;
    typedCalls.push(`// @ts-expect-error lifecycle mutation/preview requires a typed JSON body\n${call}(${JSON.stringify(missingBody)});`);
    lifecycleTypeNegatives++;
  }
  if ('orgId' in operation.arguments) {
    typedCalls.push(`// @ts-expect-error organization IDs must stay decimal strings\n${call}(${JSON.stringify({ ...operation.arguments, orgId: 123 })});`);
    lifecycleTypeNegatives++;
  }
}
const orgVerify = lifecycleFixtures.find(fixture => fixture.contract_id === 'P02').request;
for (const [label, value] of [
  ['scope/context pairing', { ...orgVerify, scope: 'organization.invite' }],
  ['recovery/OAuth/session cannot bypass organization factor verification', { ...orgVerify, method: 'oauth' }],
  ['context is mandatory', { scope: orgVerify.scope, method: 'password', password: 'fixture' }],
  ['opaque hashes cannot replace canonical commands', { ...orgVerify, context: { schema_version: 1, command_hash: 'opaque', snapshot: {} } }],
]) {
  typedCalls.push(`// @ts-expect-error ${label}\nconst invalid${lifecycleTypeNegatives}: client.OrganizationLifecycleOrganizationVerifyRequest = ${JSON.stringify(value)};`);
  lifecycleTypeNegatives++;
}
for (const [label, type, value] of [
  ['disabled=false must be present', 'OrganizationLifecycleBodySelfDisable', { revision: '1', reason: '' }],
  ['replace=false must be present', 'OrganizationLifecycleBodyTransferInitiate', { revision: '1', target_user_id: '2', previous_id: '0', previous_generation: '0' }],
  ['organization proof requires new credentials', 'OrganizationLifecycleProofResult', { proof_token: 'fixture', expires_at: 1900000060, method: 'password', scope: 'organization.self_disable' }],
]) {
  typedCalls.push(`// @ts-expect-error ${label}\nconst invalid${lifecycleTypeNegatives}: client.${type} = ${JSON.stringify(value)};`);
  lifecycleTypeNegatives++;
}
typedCalls.push(`client.Service.postApiVerify({ requestBody: { scope: 'channel.key.read', method: 'password', password: 'fixture', context: { channel_id: 1 } } });`);
typedCalls.push(`const personalProof: client.PersonalSecurityProofData = { proof_token: 'fixture', scope: 'channel.key.read', method: 'password', expires_at: 1900000060 };`);
await writeFile(consumer, await readFile(consumer, 'utf8') + `\nimport * as client from './api';\nexport function compileLifecycleCalls() {\n${typedCalls.join('\n')}\n}\n`);
await writeFile(consumer, await readFile(consumer, 'utf8') + `\nexport async function compileSiteDescription() {\n  const result = await client.${statusService}.getApiStatus({});\n  const identity: string = result.data.instance_id;\n  const topup: string | null = result.data.console_links.topup;\n  const flags: client.ClientFeatureFlags = result.data.client_features;\n  return { identity, topup, flags };\n}\nexport async function compileTokenUsage() {\n  const result = await client.${usageService}.getApiUsageTokenCollection({});\n  if (result.code !== true) return null;\n  const group: string = result.data.group;\n  const quota: number | undefined = result.data.user_quota?.total_available;\n  // @ts-expect-error group remains a string\n  const invalidGroup: client.TokenUsageData['group'] = ['auto'];\n  return { group, quota };\n}\n`);
await writeFile(consumer, await readFile(consumer, 'utf8') + `
export async function compileTokenPricing() {
  const result = await client.${pricingService}.getApiPricing({});
  if (!('group' in result)) return null;
  const group: string = result.group;
  const ratio: number | undefined = result.group_ratio[group];
  const prices: number[] = result.data.map(entry => entry.model_price);
  const contextLength: number | undefined = result.data[0]?.context_length;
  const vision: boolean | undefined = result.data[0]?.vision;
  const declarant: 'administrator' | undefined = result.data[0]?.metadata_source?.kind;
  const declaration: client.ModelCapabilityMetadataDeclaration = { reasoning: false, max_output_tokens: 4096 };
  const option: client.ModelCapabilityMetadataOptionWrite = { key: 'ModelCapabilityMetadata', value: JSON.stringify({ fixture: declaration }) };
  // @ts-expect-error absence, not null, represents an unknown fact
  const unknownVision: client.ModelCapabilityMetadataDeclaration = { vision: null };
  // @ts-expect-error metadata is not supplied as an object through the existing option API
  const objectOption: client.ModelCapabilityMetadataOptionWrite = { key: 'ModelCapabilityMetadata', value: {} };

  // @ts-expect-error selected pricing requires its top-level group
  const missingGroup: client.TokenPricingResult = { success: true, data: [], vendors: [], group_ratio: {}, usable_group: {}, supported_endpoint: {}, auto_groups: [], pricing_version: 'fixture' };
  // @ts-expect-error selection is a string, not candidate array
  const invalidGroup: client.TokenPricingResult['group'] = ['auto'];
  return { group, ratio, prices, contextLength, vision, declarant, option };
}
`);
await writeFile(consumer, await readFile(consumer, 'utf8') + `
export function compilePersonalLogPagination() {
  return client.${logService}.getApiLogSelf({ p: '1', page: '2', pageSize: '1', ps: '3', size: '4' });
}
`);
await writeFile(consumer, await readFile(consumer, 'utf8') + `
export async function compileOAuthUserInfo() {
  const profile = await client.${oauthUserInfoService}.getOAuthUserInfo({});
  const id: number = profile.id;
  const group: string = profile.group;
  const email: string | undefined = profile.email;
  // @ts-expect-error a delegated profile never contains private auth binding fields
  const privateBinding: client.OAuthUserInfo = { id: 1, username: 'fixture', display_name: '', group: 'default', auth_version: 1 };
  // @ts-expect-error unknown email is omitted, not null
  const nullEmail: client.OAuthUserInfo = { id: 1, username: 'fixture', display_name: '', group: 'default', email: null };
  return { id, group, email };
}
`);
await writeFile(consumer, await readFile(consumer, 'utf8') + `
export async function compileOAuthProvider() {
  const preview = await client.${oauthProviderOperations[0].service}.previewOAuthProviderLogin({ requestBody: { challenge: 'fixture' } });
  const token: string = preview.preview_token;
  const expires: number = preview.expires_at;
  const login = await client.${oauthProviderOperations[1].service}.decideOAuthProviderLogin({ requestBody: { challenge: 'fixture', preview_token: token, decision: 'continue' } });
  const consent = await client.${oauthProviderOperations[2].service}.previewOAuthProviderConsent({ requestBody: { challenge: 'fixture' } });
  const resume = await client.${oauthProviderOperations[3].service}.decideOAuthProviderConsent({ requestBody: { challenge: 'fixture', preview_token: consent.preview_token, decision: 'approve', selected_scopes: ['profile'] } });
  // @ts-expect-error local subject is server-owned, never a caller assertion
  const identity: client.OAuthProviderLoginDecision = { challenge: 'fixture', preview_token: token, decision: 'continue', subject: '1' };
  // @ts-expect-error explicit scope selection is an array, never a string
  const scopes: client.OAuthProviderConsentDecision = { challenge: 'fixture', preview_token: token, decision: 'approve', selected_scopes: 'profile' };
  return { expires, login: login.redirect_to, resume: resume.redirect_to };
}
`);
execFileSync(process.execPath, [require.resolve('typescript/bin/tsc'), '--strict', '--target', 'ES2020', '--module', 'commonjs', '--lib', 'ES2020,DOM', '--rootDir', path.join(output, 'generated'), '--outDir', path.join(output, 'compiled'), path.join(output, 'generated/api/index.ts'), path.join(output, 'generated/relay/index.ts'), consumer], { stdio: 'inherit' });
const api = require(path.join(output, 'compiled/api/index.js'));
const relay = require(path.join(output, 'compiled/relay/index.js'));
const calls = [];
let responseStatus = 200;
let responseBody = { success: true, message: '', data: {} };
let responseCacheControl = 'private, no-store';
globalThis.fetch = async (url, init) => {
  // This replaces the transport completely; URLs are never resolved or contacted.
  calls.push({ url, init });
  return new Response(JSON.stringify(responseBody), { status: responseStatus, headers: responseBody === undefined ? {} : { 'Content-Type': 'application/json', 'Cache-Control': responseCacheControl } });
};
api.OpenAPI.BASE = 'https://example.invalid';
relay.OpenAPI.BASE = 'https://example.invalid';
await api.Service.postApiUserLogin({ requestBody: { username: 'example', password: 'fixture-only' } });
assert.equal(calls.at(-1).url, 'https://example.invalid/api/user/login');
assert.deepEqual(JSON.parse(calls.at(-1).init.body), { username: 'example', password: 'fixture-only' });
assert.equal(new Headers(calls.at(-1).init.headers).has('Authorization'), false);
api.OpenAPI.WITH_CREDENTIALS = true;
api.OpenAPI.CREDENTIALS = 'include';
await api.Service.postApiUserAuthRefresh({ xAuthSession: 'fixture-session' });
assert.equal(calls.at(-1).init.credentials, 'include');
assert.equal(new Headers(calls.at(-1).init.headers).get('X-Auth-Session'), 'fixture-session');
assert.equal(calls.at(-1).init.body, undefined);
api.OpenAPI.TOKEN = 'fixture-only';
api.OpenAPI.HEADERS = { 'X-Security-Proof': 'fixture-proof' };
await api.DefaultService.postApiUserAccessTokens({ requestBody: { name: 'Example', scopes: ['profile:read'], expires_at: 0 } });
assert.equal(new Headers(calls.at(-1).init.headers).get('Authorization'), 'Bearer fixture-only');
assert.equal(new Headers(calls.at(-1).init.headers).get('X-Security-Proof'), 'fixture-proof');
relay.OpenAPI.TOKEN = 'fixture-relay-key';
await relay.ImagesService.createImage({ requestBody: { model: 'gpt-image-1', prompt: 'A cup', n: 1 } });
assert.equal(new Headers(calls.at(-1).init.headers).get('Authorization'), 'Bearer fixture-relay-key');
assert.equal(calls.at(-1).url, 'https://example.invalid/v1/images/generations');
await relay.ImagesService.editImage({ requestBody: { model: 'qwen-image-edit-plus', prompt: 'A cup', image: 'https://example.com/source.png', stream: false } });
assert.equal(calls.at(-1).url, 'https://example.invalid/v1/images/edits');
assert.equal(JSON.parse(calls.at(-1).init.body).stream, false);
const textRequest = { contents: [{ role: 'user', parts: [{ text: 'Hello' }] }] };
for (const requestBody of [textRequest, { ...textRequest, generationConfig: {} }, { ...textRequest, generationConfig: { responseModalities: ['TEXT', 'IMAGE'] } }]) {
  await relay.GeminiService.streamGeminiContent({ model: 'fixture-model', alt: 'sse', requestBody });
  assert.equal(calls.at(-1).url, 'https://example.invalid/v1beta/models/fixture-model:streamGenerateContent?alt=sse');
  assert.deepEqual(JSON.parse(calls.at(-1).init.body), requestBody);
}
await api.Service.getDashboardTaskArtifacts({ taskId: 'fixture-task' });
assert.equal(calls.at(-1).url, 'https://example.invalid/api/task/fixture-task/artifacts');
assert.equal(new Headers(calls.at(-1).init.headers).get('Authorization'), 'Bearer fixture-only');
for (const status of [400, 401, 403, 429, 500]) {
  responseStatus = status;
  for (const body of [{ type: 'error', error: { type: 'invalid_request_error', message: 'Fixture rejection' } }, { error: { type: 'invalid_request_error', message: 'Fixture rejection' } }]) {
    responseBody = body;
    await assert.rejects(relay.ClaudeMessagesService.createMessage({ anthropicVersion: '2023-06-01' }), error => {
      assert.equal(error.status, status);
      assert.deepEqual(error.body, body);
      return true;
    });
  }
}
responseStatus = 404;
responseBody = { success: false, message: 'Task or artifact not found', code: 'artifact_not_found' };
await assert.rejects(api.Service.getDashboardTaskArtifacts({ taskId: 'fixture-hidden' }), error => {
  assert.equal(error.status, 404);
  assert.deepEqual(error.body, responseBody);
  assert.equal('data' in error.body, false);
  return true;
});
const inheritedStubbedRequests = calls.length;
api.OpenAPI.HEADERS = undefined;
api.OpenAPI.WITH_CREDENTIALS = false;
const orgId = '9007199254740993';
const organization = { org_id: orgId, name: 'Fixture organization', revision: '1', my_role: 'owner', my_member_revision: '1', capabilities: { organization_read: true, members_read: true, events_read: true, resource_access: true, organization_token_issue: false, organization_spend: false, organization_mutation: true } };
const organizationCalls = [
  ['listAccessibleOrganizations', { orgId: '0', afterId: '0', limit: 20 }, '/api/organizations?org_id=0&after_id=0&limit=20', { items: [organization], limit: 20, next_after_id: null }],
  ['getOrganizationRequestContext', { xOrganizationId: orgId }, '/api/organization-context', { actor_user_id: '7', org_id: orgId, scope_kind: 'organization', organization }],
  ['getOrganizationAccess', { orgId, queryOrgId: orgId }, `/api/organizations/${orgId}?org_id=${orgId}`, organization],
  ['listOrganizationMembers', { orgId, xOrganizationId: orgId, afterId: '0', limit: 1 }, `/api/organizations/${orgId}/members?after_id=0&limit=1`, { items: [], limit: 1, next_after_id: null }],
  ['listOrganizationEvents', { orgId }, `/api/organizations/${orgId}/events?after_id=0&limit=20`, { items: [], limit: 20, next_after_id: null }],
];
for (const [method, parameters, expectedPath, data] of organizationCalls) {
  responseStatus = 200;
  responseBody = { success: true, message: '', data };
  assert.deepEqual(await api.OrganizationsService[method](parameters), responseBody);
  const request = calls.at(-1);
  assert.equal(request.url, api.OpenAPI.BASE + expectedPath);
  assert.equal(request.init.method, 'GET');
  assert.equal(request.init.body, undefined);
  const headers = new Headers(request.init.headers);
  assert.equal(headers.get('Authorization'), 'Bearer fixture-only');
  assert.equal(headers.get('X-Organization-Id'), parameters.xOrganizationId ?? null);
  assert.equal(headers.has('X-Security-Proof'), false);
  assert.equal(headers.has('Idempotency-Key'), false);
  responseStatus = 403;
  responseBody = { success: false, code: 'AUTH_SESSION_REQUIRED', message: 'a dashboard login session is required', message_key: 'a dashboard login session is required' };
  await assert.rejects(api.OrganizationsService[method](parameters), error => {
    assert.equal(error.status, 403);
    assert.deepEqual(error.body, responseBody);
    return true;
  });
}
for (const status of [429, 500]) {
  responseStatus = status;
  responseBody = undefined;
  await assert.rejects(api.OrganizationsService.getOrganizationRequestContext({ orgId: '0' }), error => {
    assert.equal(error.status, status);
    assert.equal(error.body, undefined);
    return true;
  });
}
responseStatus = 200;
responseBody = { success: true, message: '', data: { actor_user_id: '7', org_id: '0', scope_kind: 'personal', organization: null } };
assert.equal((await api.OrganizationsService.getOrganizationRequestContext({ orgId: '0' })).data.organization, null);
assert.equal(calls.at(-1).url, api.OpenAPI.BASE + '/api/organization-context?org_id=0');
assert.equal(new Headers(calls.at(-1).init.headers).has('X-Organization-Id'), false);
// Deliberately unequal values prove that the adapter does not replace the path
// ID with the query ID. Only the real server can prove conflict rejection.
for (const [method, suffix] of [['getOrganizationAccess', ''], ['listOrganizationMembers', '/members'], ['listOrganizationEvents', '/events']]) {
  await api.OrganizationsService[method]({ orgId, queryOrgId: '2' });
  const pagination = suffix ? '&after_id=0&limit=20' : '';
  assert.equal(calls.at(-1).url, api.OpenAPI.BASE + `/api/organizations/${orgId}${suffix}?org_id=2${pagination}`);
}
await Promise.all([
  api.OrganizationsService.getOrganizationRequestContext({ xOrganizationId: '1' }),
  api.OrganizationsService.getOrganizationRequestContext({ xOrganizationId: '2' }),
]);
assert.deepEqual(calls.slice(-2).map(call => new Headers(call.init.headers).get('X-Organization-Id')), ['1', '2']);
const beforeLifecycleRequests = calls.length;
for (let index = 0; index < invocationMap.length; index++) {
  const operation = invocationMap[index];
  const fixture = lifecycleFixtures[index];
  // Existing Passkey middleware emits this conservative superset on both
  // success and error responses. Status/body checks still use a fetch stub.
  responseCacheControl = ['P03', 'P04'].includes(fixture.contract_id)
    ? cacheFixtures.find(sample => sample.name === 'organization Cache-Control: existing Passkey header').value
    : 'private, no-store';
  const invoke = parameters => api[operation.service][operation.method](parameters);
  const start = calls.length;
  responseStatus = fixture.status;
  responseBody = fixture.response;
  assert.deepEqual(await invoke(operation.arguments), fixture.response);
  assert.equal(calls.length, start + 1, 'Generated client must not retry a write');
  const request = calls.at(-1);
  const url = new URL(request.url);
  assert.equal(url.pathname, fixture.path.replace(/\{[^}]+\}/g, '9007199254740993'));
  assert.equal(request.init.method, fixture.method.toUpperCase());
  assert.equal(new Headers(request.init.headers).get('Authorization'), 'Bearer fixture-only');
  assert.equal(new Headers(request.init.headers).get('X-Security-Proof'), operation.arguments.xSecurityProof ?? null);
  assert.equal(new Headers(request.init.headers).has('Idempotency-Key'), false);
  if (fixture.request === null) assert.equal(request.init.body, undefined);
  else {
    assert.deepEqual(JSON.parse(request.init.body), fixture.request);
    assert.equal(new Headers(request.init.headers).get('Content-Type'), 'application/json');
    if ('disabled' in fixture.request) assert.equal(JSON.parse(request.init.body).disabled, false);
    if ('replace' in fixture.request) assert.equal(JSON.parse(request.init.body).replace, false);
  }
  if ('orgId' in operation.arguments) {
    assert.equal(url.searchParams.has('org_id'), false, 'Absent optional query must remain absent');
    await invoke({ ...operation.arguments, queryOrgId: '2' });
    const mismatched = new URL(calls.at(-1).url);
    assert.equal(mismatched.pathname, url.pathname);
    assert.equal(mismatched.searchParams.get('org_id'), '2', 'Query must not replace the path ID');
    await invoke({ ...operation.arguments, xOrganizationId: '9007199254740993' });
    assert.equal(new URL(calls.at(-1).url).searchParams.has('org_id'), false);
    assert.equal(new Headers(calls.at(-1).init.headers).get('X-Organization-Id'), '9007199254740993');
  }
  for (const status of fixture.errors) {
    responseStatus = status;
    responseBody = { success: false, message: 'Fixture rejection', code: apiDocument.components.schemas['OrganizationLifecycleError' + status].properties.code.enum[0] };
    const beforeError = calls.length;
    await assert.rejects(invoke(operation.arguments), error => {
      assert.equal(error.status, status);
      assert.deepEqual(error.body, responseBody);
      return true;
    });
    assert.equal(calls.length, beforeError + 1, 'No retry of error responses');
  }
}
const lifecycleStubbedRequests = calls.length - beforeLifecycleRequests;
// A rejected transport on create must not be retried: the server may have committed.
const savedFetch = globalThis.fetch;
let networkAttempts = 0;
globalThis.fetch = async () => { networkAttempts++; throw new TypeError('Fixture ambiguous network failure'); };
const create = invocationMap.find(operation => operation.contract_id === 'W01');
await assert.rejects(api[create.service][create.method](create.arguments), /Fixture ambiguous network failure/);
assert.equal(networkAttempts, 1);
globalThis.fetch = savedFetch;
await writeFile(path.join(output, 'lifecycle-client-results.json'), JSON.stringify({ operations: invocationMap.length, typed_positive_calls: invocationMap.length + 2, typed_negative_calls: lifecycleTypeNegatives, stubbed_requests: lifecycleStubbedRequests, network_failure_attempts: networkAttempts, live_http: false, server_authorization_verified: false }, null, 2) + '\n');
const imageClient = await readFile(path.join(output, 'generated/relay/services/ImagesService.ts'), 'utf8');

const beforeWalletRequests = calls.length;
// Exact generated wallet transport; this stub is not authorization/runtime proof.
responseStatus = 200;
responseBody = { success: true, message: '', data: { organization_id: '1', opened: false, balance: '0', reserved: '0', available: '0' } };
for (const [method, endpoint] of [['organizationWalletBalance', '/api/organizations/1/wallet'], ['platformOrganizationWalletBalance', '/api/platform/organizations/1/wallet']]) {
  await api.OrganizationsService[method]({ orgId: '1' });
  assert.equal(calls.at(-1).url, api.OpenAPI.BASE + endpoint);
  assert.equal(calls.at(-1).init.method, 'GET');
  assert.equal(calls.at(-1).init.body, undefined);
  assert.equal(new Headers(calls.at(-1).init.headers).has('X-Security-Proof'), false);
}
for (const [method, endpoint, requestBody, extra] of [
  ['organizationWalletCredit', '/api/platform/organizations/1/wallet/credits', { revision: '1', request_id: '00000000-0000-4000-8000-000000000001', amount: '100', reference: 'ticket-17', reason: 'Manual credit' }, {}],
  ['organizationWalletReverse', '/api/platform/organizations/1/wallet/credits/2/reverse', { revision: '1', request_id: '00000000-0000-4000-8000-000000000002', reason: 'Correct credit' }, { creditId: '2' }],
]) {
  responseBody = { success: true, message: '', data: { organization_id: '1', entry_id: '2', amount: '100', balance_after: '100' } };
  await api.OrganizationsService[method]({ orgId: '1', xSecurityProof: 'fixture-proof', requestBody, ...extra });
  assert.equal(calls.at(-1).url, api.OpenAPI.BASE + endpoint);
  assert.equal(calls.at(-1).init.method, 'POST');
  assert.deepEqual(JSON.parse(calls.at(-1).init.body), requestBody);
  assert.equal(new Headers(calls.at(-1).init.headers).get('X-Security-Proof'), 'fixture-proof');
  responseStatus = 409;
  responseBody = { success: false, code: 'ORG_WALLET_REQUEST_CONFLICT', message: 'This wallet request ID was already used with different details.' };
  await assert.rejects(api.OrganizationsService[method]({ orgId: '1', xSecurityProof: 'fixture-proof', requestBody, ...extra }), error => error.status === 409 && error.body.code === 'ORG_WALLET_REQUEST_CONFLICT');
  responseStatus = 200;
}
const walletStubbedRequests = calls.length - beforeWalletRequests;
const beforeUsageRequests = calls.length;
api.OpenAPI.TOKEN = 'sk-generated-usage-fixture';
api.OpenAPI.HEADERS = undefined;
for (const name of ['token usage named group', 'token usage inherited group', 'token usage auto group']) {
  responseBody = allFixtures.find(fixture => fixture.name === name).value;
  const usageResult = await api[usageService].getApiUsageTokenCollection({});
  assert.deepEqual(usageResult, responseBody);
  assert.equal(calls.at(-1).url, api.OpenAPI.BASE + '/api/usage/token/');
  assert.equal(calls.at(-1).init.method, 'GET');
  assert.equal(calls.at(-1).init.body, undefined);
  assert.equal(new Headers(calls.at(-1).init.headers).get('Authorization'), 'Bearer sk-generated-usage-fixture');
  assert.equal(new Headers(calls.at(-1).init.headers).has('X-Security-Proof'), false);
}
responseBody = allFixtures.find(fixture => fixture.name === 'token usage legacy quota failure').value;
assert.deepEqual(await api[usageService].getApiUsageTokenCollection({}), responseBody);
assert.equal('data' in responseBody, false);
responseStatus = 401;
responseBody = { success: false, message: 'Invalid Bearer token' };
await assert.rejects(api[usageService].getApiUsageTokenCollection({}), error => error.status === 401 && error.body.message === 'Invalid Bearer token');
const usageStubbedRequests = calls.length - beforeUsageRequests;
const beforePricingRequests = calls.length;
responseStatus = 200;
api.OpenAPI.TOKEN = 'sk-generated-pricing-fixture';
api.OpenAPI.HEADERS = undefined;
for (const name of ['token pricing named', 'token pricing auto', 'token pricing revoked empty']) {
  responseBody = allFixtures.find(fixture => fixture.name === name).value;
  const pricingResult = await api[pricingService].getApiPricing({});
  assert.deepEqual(pricingResult, responseBody);
  assert.equal(typeof pricingResult.group, 'string');
  assert.equal(calls.at(-1).url, api.OpenAPI.BASE + '/api/pricing');
  assert.equal(calls.at(-1).init.method, 'GET');
  assert.equal(calls.at(-1).init.body, undefined);
  assert.equal(new Headers(calls.at(-1).init.headers).get('Authorization'), 'Bearer sk-generated-pricing-fixture');
  assert.equal(new Headers(calls.at(-1).init.headers).has('X-Security-Proof'), false);
}
responseStatus = 403;
responseBody = { success: false, message: 'a dashboard login session is required' };
await assert.rejects(api[pricingService].getApiPricing({}), error => error.status === 403 && error.body.message === 'a dashboard login session is required');
api.OpenAPI.TOKEN = undefined;
responseStatus = 200;
responseBody = allFixtures.find(fixture => fixture.name === 'public pricing unchanged shape').value;
assert.deepEqual(await api[pricingService].getApiPricing({}), responseBody);
assert.equal(new Headers(calls.at(-1).init.headers).has('Authorization'), false);
assert.equal('group' in responseBody, false);
for (const [name, token] of [
  ['public pricing administrator metadata', undefined],
  ['token pricing administrator metadata', 'sk-generated-pricing-metadata-fixture'],
]) {
  api.OpenAPI.TOKEN = token;
  api.OpenAPI.HEADERS = undefined;
  responseBody = allFixtures.find(fixture => fixture.name === name).value;
  const result = await api[pricingService].getApiPricing({});
  assert.deepEqual(result, responseBody);
  const headers = new Headers(calls.at(-1).init.headers);
  if (token === undefined) {
    assert.equal(headers.has('Authorization'), false);
    assert.equal('group' in result, false);
  } else {
    assert.equal(headers.get('Authorization'), 'Bearer ' + token);
    assert.equal(result.group, 'g1');
  }
  assert.equal(headers.has('X-Security-Proof'), false);
  assert.equal(result.data[0].reasoning, false);
  assert.equal(result.data[0].context_length, 128000);
  assert.equal(result.data[0].metadata_source.kind, 'administrator');
  assert.match(result.data[0].metadata_source.version, /^sha256:[0-9a-f]{64}$/);
  assert.equal(new URL(calls.at(-1).url).pathname, '/api/pricing');
  assert.equal(calls.at(-1).init.method, 'GET');
  assert.equal(calls.at(-1).init.body, undefined);
}
api.OpenAPI.TOKEN = undefined;
api.OpenAPI.HEADERS = undefined;
const pricingStubbedRequests = calls.length - beforePricingRequests;
// Transport only: controller tests, not this replaced fetch response, decide page precedence.
const beforeLogPaginationRequests = calls.length;
api.OpenAPI.TOKEN = 'fixture-log-dashboard';
api.OpenAPI.HEADERS = undefined;
responseStatus = 200;
responseBody = { success: true, message: '', data: { page: 2, page_size: 1, total: 3, items: [{ request_id: 'fixture-2' }] } };
for (const [parameters, expected] of [
  [{ page: '2', pageSize: '1' }, { page: '2', page_size: '1' }],
  [{ p: '2', pageSize: '1' }, { p: '2', page_size: '1' }],
  [{ p: '1', page: '2', pageSize: '1' }, { p: '1', page: '2', page_size: '1' }],
  [{ p: '', page: '2', ps: '1', size: '3' }, { p: '', page: '2', ps: '1', size: '3' }],
]) {
  assert.deepEqual(await api[logService].getApiLogSelf(parameters), responseBody);
  const request = calls.at(-1);
  const url = new URL(request.url);
  assert.equal(url.pathname, '/api/log/self');
  assert.deepEqual(Object.fromEntries(url.searchParams), expected);
  assert.equal(request.init.method, 'GET');
  assert.equal(request.init.body, undefined);
  assert.equal(new Headers(request.init.headers).get('Authorization'), 'Bearer fixture-log-dashboard');
  assert.equal(new Headers(request.init.headers).has('X-Security-Proof'), false);
}
const logPaginationStubbedRequests = calls.length - beforeLogPaginationRequests;
const beforeLogRangeRequests = calls.length;
const successfulLogResponse = responseBody;
const logRangeError = allFixtures.find(fixture => fixture.name === 'personal log range default').value;
responseStatus = 400;
responseBody = logRangeError;
await assert.rejects(api[logService].getApiLogSelf({ p: '1', pageSize: '1' }), error => {
  assert.equal(error.status, 400);
  assert.deepEqual(error.body, logRangeError);
  return true;
});
assert.equal(new URL(calls.at(-1).url).pathname, '/api/log/self');
assert.equal(calls.at(-1).init.method, 'GET');
assert.equal(calls.at(-1).init.body, undefined);
assert.equal(new Headers(calls.at(-1).init.headers).get('Authorization'), 'Bearer fixture-log-dashboard');
assert.equal(new Headers(calls.at(-1).init.headers).has('X-Security-Proof'), false);
const logRangeStubbedRequests = calls.length - beforeLogRangeRequests;
const beforeDataRangeRequests = calls.length;
await assert.rejects(api[dataService].getApiDataSelf({}), error => {
  assert.equal(error.status, 400);
  assert.deepEqual(error.body, logRangeError);
  return true;
});
assert.equal(new URL(calls.at(-1).url).pathname, '/api/data/self');
assert.equal(calls.at(-1).init.method, 'GET');
assert.equal(calls.at(-1).init.body, undefined);
assert.equal(new Headers(calls.at(-1).init.headers).get('Authorization'), 'Bearer fixture-log-dashboard');
assert.equal(new Headers(calls.at(-1).init.headers).has('X-Security-Proof'), false);
const dataRangeStubbedRequests = calls.length - beforeDataRangeRequests;
responseStatus = 200;
responseBody = successfulLogResponse;
api.OpenAPI.TOKEN = undefined;
api.OpenAPI.HEADERS = undefined;
const beforeStatusRequests = calls.length;
api.OpenAPI.TOKEN = undefined;
api.OpenAPI.HEADERS = undefined;
responseStatus = 200;
responseBody = { success: true, message: '', data: { instance_id: '12345678-1234-4234-8234-123456789abc', console_links: { topup: 'http://127.0.0.1:3000/prefix/wallet', usage_logs: null, keys: 'https://console.example/keys', pricing: 'https://console.example/pricing' }, oauth: { enabled: false }, client_features: { token_usage_logs: false, oauth: false, model_metadata: false }, version: 'unchanged' } };
const statusResult = await api[statusService].getApiStatus({});
assert.deepEqual(statusResult, responseBody);
assert.equal(calls.at(-1).url, api.OpenAPI.BASE + '/api/status');
assert.equal(calls.at(-1).init.method, 'GET');
assert.equal(calls.at(-1).init.body, undefined);
assert.equal(new Headers(calls.at(-1).init.headers).has('Authorization'), false);
assert.equal(new Headers(calls.at(-1).init.headers).has('X-Security-Proof'), false);
const statusStubbedRequests = calls.length - beforeStatusRequests;
const beforeOAuthUserInfoRequests = calls.length;
api.OpenAPI.TOKEN = 'fixture-oauth-resource';
api.OpenAPI.HEADERS = undefined;
api.OpenAPI.WITH_CREDENTIALS = false;
for (const profile of [
  { id: 1, username: 'fixture', display_name: 'Display', group: 'default' },
  { id: 1, username: 'fixture', display_name: 'Display', group: 'default', email: 'fixture@example.invalid' },
]) {
  responseStatus = 200;
  responseBody = profile;
  assert.deepEqual(await api[oauthUserInfoService].getOAuthUserInfo({}), profile);
  const request = calls.at(-1);
  assert.equal(request.url, api.OpenAPI.BASE + '/api/v1/oauth/userinfo');
  assert.equal(request.init.method, 'GET');
  assert.equal(request.init.body, undefined);
  assert.equal(new Headers(request.init.headers).get('Authorization'), 'Bearer fixture-oauth-resource');
  assert.equal(new Headers(request.init.headers).has('X-Security-Proof'), false);
}
for (const [status, code] of [[401, 'invalid_token'], [403, 'insufficient_scope'], [503, 'temporarily_unavailable']]) {
  responseStatus = status;
  responseBody = { error: code };
  const before = calls.length;
  await assert.rejects(api[oauthUserInfoService].getOAuthUserInfo({}), error => {
    assert.equal(error.status, status);
    assert.deepEqual(error.body, responseBody);
    return true;
  });
  assert.equal(calls.length, before + 1);
}
api.OpenAPI.TOKEN = undefined;
api.OpenAPI.HEADERS = undefined;
const oauthUserInfoStubbedRequests = calls.length - beforeOAuthUserInfoRequests;
const beforeOAuthProviderRequests = calls.length;
api.OpenAPI.TOKEN = 'fixture-dashboard-session';
api.OpenAPI.HEADERS = undefined;
for (const operation of oauthProviderOperations) {
  const body = operation.preview ? { challenge: 'fixture-challenge' } : {
    challenge: 'fixture-challenge', preview_token: 'p'.repeat(43),
    decision: operation.route.endsWith('/login') ? 'continue' : 'approve',
    ...(operation.route.endsWith('/consent') ? { selected_scopes: ['profile'] } : {}),
  };
  responseStatus = 200;
  responseBody = operation.preview ? {
    preview_token: 'p'.repeat(43), expires_at: 1900000000, phase: operation.route.includes('/login') ? 'login' : 'consent',
    client_id: 'cherry-studio', client_name: 'Fixture', username: 'fixture',
    requested_scopes: ['profile', 'email'], allowed_scopes: ['profile', 'email'], audience: 'newapi-userinfo',
  } : { redirect_to: 'https://issuer.example/oauth2/auth?fixture_verifier=fixture' };
  assert.deepEqual(await api[operation.service][operation.method]({ requestBody: body }), responseBody);
  const request = calls.at(-1);
  assert.equal(request.url, api.OpenAPI.BASE + operation.route);
  assert.equal(request.init.method, 'POST');
  assert.deepEqual(JSON.parse(request.init.body), body);
  const headers = new Headers(request.init.headers);
  assert.equal(headers.get('Authorization'), 'Bearer fixture-dashboard-session');
  assert.equal(headers.get('Content-Type'), 'application/json');
  assert.equal(headers.has('X-Security-Proof'), false);
  responseStatus = 409;
  responseBody = { error: 'invalid_grant' };
  const before = calls.length;
  await assert.rejects(api[operation.service][operation.method]({ requestBody: body }), error => {
    assert.equal(error.status, 409);
    assert.deepEqual(error.body, responseBody);
    return true;
  });
  assert.equal(calls.length, before + 1, 'the client must not retry an ambiguous external decision');
}
api.OpenAPI.TOKEN = undefined;
api.OpenAPI.HEADERS = undefined;
const oauthProviderStubbedRequests = calls.length - beforeOAuthProviderRequests;
console.log(JSON.stringify({ generator: 'openapi-typescript-codegen@0.29.0', compiler: 'typescript@5.9.3', documents: ['api.json', 'relay.json'], compile: 'PASS', adaptation, lifecycle_operations: invocationMap.length, lifecycle_type_negatives: lifecycleTypeNegatives, lifecycle_stubbed_requests: lifecycleStubbedRequests, typed_consumer_positive_calls: 16, typed_consumer_negative_calls: 12, organization_operations: organizationCalls.map(([method]) => method), inherited_stubbed_requests: inheritedStubbedRequests, organization_stubbed_requests: beforeLifecycleRequests - inheritedStubbedRequests, wallet_stubbed_requests: walletStubbedRequests, token_usage_stubbed_requests: usageStubbedRequests, token_usage_typed_group: true, token_pricing_stubbed_requests: pricingStubbedRequests, token_pricing_typed_group: true, personal_log_pagination_stubbed_requests: logPaginationStubbedRequests, personal_log_range_stubbed_requests: logRangeStubbedRequests, personal_data_range_stubbed_requests: dataRangeStubbedRequests, site_description_stubbed_requests: statusStubbedRequests, oauth_userinfo_stubbed_requests: oauthUserInfoStubbedRequests, oauth_provider_stubbed_requests: oauthProviderStubbedRequests, stubbed_requests: calls.length, provider_io: false, live_http_consumer: false, limitations: ['Generator selects the first request media type: image edit JSON is generated; multipart requires an explicit transport adapter.', 'SSE and WebSocket require protocol-aware adapters; this fetch client only verifies HTTP request generation.', 'Configure WITH_CREDENTIALS/CREDENTIALS for refresh cookies; configure TOKEN and HEADERS for bearer/proof or alternate API key headers. Generated clients do not enforce role, PAT scope, proof or server authorization.', 'Error-body checks use replaced fetch responses. Schema acceptance is tested separately; this generator does not validate response schemas at runtime.', 'Raw generation is adapted before compilation. useUnionTypes emits string unions rather than enum objects, including the exact empty success message. The pinned generator still widens boolean enum literals; validate response schemas separately.', 'Organization path/query independence and per-call header isolation are client transport checks only; A03 must verify real server authorization and conflict rejection.'], image_edit_json_generated: imageClient.includes("mediaType: 'application/json'") }, null, 2));
