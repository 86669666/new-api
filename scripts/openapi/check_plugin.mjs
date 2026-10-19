// Offline execution of the bundled Alibaba image decoder using documented examples.
// node scripts/openapi/check_plugin.mjs; no hooks that contact providers are called.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const root = new URL('../../', import.meta.url);
const spec = JSON.parse(await readFile(new URL('docs/openapi/relay.json', root), 'utf8'));
const source = await readFile(new URL('plugins/tasks/alibaba/plugin.js', root), 'utf8');
const { protocols } = await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));
// Make accidental network activity a hard failure in this fixture runner.
globalThis.fetch = () => { throw new Error('Network I/O forbidden in contract fixtures'); };
const decode = protocols.openai_image.decodeRequest;
const outcomes = [];
for (const [path, operation] of [['/v1/images/generations', 'generate'], ['/v1/images/edits', 'edit']]) {
  const value = spec.paths[path].post.requestBody.content['application/json'].examples.alibaba.value;
  const result = decode({ model: value.model, operation, body: { kind: 'json', value } });
  assert.equal(result.kind, 'submit');
  assert.equal(result.model, value.model);
  assert.deepEqual(result.requestBody.metadata.input, value.input);
  assert.deepEqual(result.requestBody.metadata.parameters, value.parameters);
  if (operation === 'edit') assert.deepEqual(result.requestBody.images, [value.image]);
  outcomes.push(operation + ': documented JSON example decoded');
}
const multipart = decode({ model: 'qwen-image-edit-plus', operation: 'edit', body: {
  kind: 'multipart', fields: { prompt: ['Make the cup blue'], n: ['2'], stream: ['false'], parameters: ['{"watermark":false}'] },
  files: [{ field: 'image[]', ref: 'fixture-file-1', mimeType: 'image/png' }, { field: 'image[]', ref: 'fixture-file-2', mimeType: 'image/png' }],
} });
assert.equal(multipart.requestBody.n, 2);
assert.equal(multipart.requestBody.images.length, 2);
assert.equal(multipart.requestBody.images[0].__fileRef, 'fixture-file-1');
assert.equal(multipart.requestBody.metadata.parameters.watermark, false);
outcomes.push('edit: repeated multipart image[] decoded');
for (const [name, value, error] of [
  ['nested image alone', { model: 'qwen-image-edit-plus', input: { messages: [{ role: 'user', content: [{ image: 'https://example.com/source.png', text: 'Edit' }] }] } }, /image is required/],
  ['stream unsupported', { prompt: 'Edit', image: 'https://example.com/source.png', stream: true }, /stream is not supported/],
  ['zero count', { prompt: 'Edit', image: 'https://example.com/source.png', n: 0 }, /positive integer/],
  ['fractional count', { prompt: 'Edit', image: 'https://example.com/source.png', n: 1.5 }, /positive integer/],
]) {
  assert.throws(() => decode({ model: 'qwen-image-edit-plus', operation: 'edit', body: { kind: 'json', value } }), error);
  outcomes.push(name + ': rejected');
}
assert.throws(() => decode({ model: 'qwen-image-edit-plus', operation: 'edit', body: { kind: 'multipart', fields: { prompt: ['one', 'two'] }, files: [] } }), /must be provided once/);
outcomes.push('duplicate multipart field: rejected');
console.log(JSON.stringify({ provider_io: false, checks: outcomes }, null, 2));
