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
    })).map(operation => {
      const parameters = operation.parameters.map(parameter =>
        parameter.$ref ? document.components.parameters[parameter.$ref.split('/').at(-1)] : parameter);
      const paths = parameters.filter(parameter => parameter.in === 'path' && parameter.name === 'org_id');
      assert.equal(paths.length, 1, `Expected one ${operation.operationId} path org_id`);
      assert.equal(paths[0].required, true, `Expected required ${operation.operationId} path org_id`);
      const schema = paths[0].schema;
      const reference = schema.$ref?.match(/^#\/components\/schemas\/([A-Za-z_][A-Za-z0-9_]*)$/);
      assert(!schema.$ref || reference, `Unsupported ${operation.operationId} path schema reference`);
      const pathSchema = reference ? document.components.schemas[reference[1]] : schema;
      assert.equal(pathSchema?.type, 'string', `Expected string ${operation.operationId} path schema`);
      assert.equal(pathSchema.enum, undefined, `Unsupported ${operation.operationId} path enum`);
      return {
        method: operation.operationId.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase()),
        url,
        pathType: reference ? reference[1] : 'string',
      };
    })
);

export function adaptOrganizationQuery(source) {
  assert.equal(typeof source, 'string', 'Expected generated TypeScript source');
  assert(source.startsWith('/* generated using openapi-typescript-codegen -- do not edit */'));
  assert(!source.includes('queryOrgId'), 'Expected unadapted organization query parameters');
  for (const { method, url, pathType } of organizationQueryOperations) {
    const marker = `    public static ${method}({`;
    assert.equal(source.split(marker).length - 1, 1, `Expected one ${method} method`);
    const start = source.indexOf(marker);
    const next = source.indexOf('    public static ', start + marker.length);
    const end = next < 0 ? source.length : next;
    let block = source.slice(start, end);
    for (const shape of [
      `            url: '${url}',`,
      `        orgId: ${pathType},`,
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
    ]) {
      assert.equal(block.split(before).length - 1, 1, `Unexpected ${method} query shape`);
      block = block.replace(before, after);
    }
    // Query entries follow parameter order; org_id need not be the first one.
    const queries = [...block.matchAll(/^            query: \{\n[\s\S]*?^            \},/gm)];
    assert.equal(queries.length, 1, `Unexpected ${method} query shape`);
    const query = queries[0][0];
    const entry = "                'org_id': orgId,";
    assert.equal(query.split(entry).length - 1, 1, `Unexpected ${method} query shape`);
    block = block.replace(query, query.replace(entry, "                'org_id': queryOrgId,"));
    source = source.slice(0, start) + block + source.slice(end);
  }
  return source;
}
