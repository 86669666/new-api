// openapi-typescript-codegen 0.29.0 maps both path and query org_id to orgId.
// Adapt only organization operations declared by the checked-in API contract.
// A mismatch throws before the caller writes; no wire name or value is changed.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const document = JSON.parse(readFileSync(new URL('../../docs/openapi/api.json', import.meta.url), 'utf8'));
export const organizationQueryOperations = Object.entries(document.paths).flatMap(([url, item]) =>
  Object.values(item).filter(operation => operation.tags?.includes('Organizations') && url.includes('{org_id}') &&
    operation.parameters?.some(parameter => {
      const value = parameter.$ref ? document.components.parameters[parameter.$ref.split('/').at(-1)] : parameter;
      return value.in === 'query' && value.name === 'org_id';
    })).map(operation => ({ method: operation.operationId.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase()), url }))
);

export function adaptOrganizationQuery(source) {
  assert.equal(typeof source, 'string', 'Expected generated TypeScript source');
  assert(source.startsWith('/* generated using openapi-typescript-codegen -- do not edit */'));
  assert(!source.includes('queryOrgId'), 'Expected unadapted organization query parameters');
  for (const { method, url } of organizationQueryOperations) {
    const marker = `    public static ${method}({`;
    assert.equal(source.split(marker).length - 1, 1, `Expected one ${method} method`);
    const start = source.indexOf(marker);
    const next = source.indexOf('    public static ', start + marker.length);
    const end = next < 0 ? source.length : next;
    let block = source.slice(start, end);
    for (const shape of [
      `            url: '${url}',`,
      `        orgId: ${method.startsWith('organization') ? 'OrganizationLifecycleID' : 'string'},`,
      "            path: {\n                'org_id': orgId,",
      "                'X-Organization-Id': xOrganizationId,",
    ]) {
      assert.equal(block.split(shape).length - 1, 1, `Unexpected ${method} path/header shape`);
    }
    // Additional path parameters may occur between the two orgId arguments.
    const argument = '        orgId,\n';
    assert.equal(block.split(argument).length - 1, 2, `Unexpected ${method} query shape`);
    const last = block.lastIndexOf(argument);
    block = block.slice(0, last) + block.slice(last).replace(argument, '        queryOrgId,\n');
    for (const [before, after] of [
      ['        orgId?: string,', '        queryOrgId?: string,'],
      ["            query: {\n                'org_id': orgId,", "            query: {\n                'org_id': queryOrgId,"],
    ]) {
      assert.equal(block.split(before).length - 1, 1, `Unexpected ${method} query shape`);
      block = block.replace(before, after);
    }
    source = source.slice(0, start) + block + source.slice(end);
  }
  return source;
}
