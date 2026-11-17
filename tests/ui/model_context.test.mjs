import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const html = readFileSync(new URL('../../internal/admin/console.html', import.meta.url), 'utf8');
const contextFunctions = html.slice(html.indexOf('  function parseContextTokens('), html.indexOf('  // selectedModelIDs'));
const formatFunction = html.slice(html.indexOf('  function formatTokens('), html.indexOf('  // modelsLoaded'));

function setup() {
  const requests = [];
  let syncs = 0;
  const scope = vm.createContext({
    editableCell: options => options,
	  el: (tag,text,className) => ({tag,text,className}),
    api: async (method, path, body) => {
      requests.push({ method, path, body });
      return { ok: true, context_override: body.context_length, context_length: body.context_length || 1000000 };
    },
    syncModelConfig: () => { syncs++; },
  });
  vm.runInContext(contextFunctions + formatFunction, scope);
  return { scope, requests, get syncs() { return syncs; } };
}

test('上下文按十进制显示，与上游 K/M 档位保持一致', () => {
  const { scope } = setup();
  assert.equal(scope.formatTokens(200000), '200K');
  assert.equal(scope.formatTokens(400000), '400K');
  assert.equal(scope.formatTokens(1000000), '1M');
});

test('固定上下文只显示数值，不生成编辑器或保存操作', () => {
  const state=setup();const cell=state.scope.modelContextCell({id:'intern-s2',context_length:262144,context_override:1000000,context_locked:true});
  assert.match(cell.text,/固定/);assert.equal(cell.save,undefined);assert.equal(state.requests.length,0);
});

test('编辑值支持整数、K/M 和清空，拒绝非法或超范围输入', () => {
  const { scope } = setup();
  for (const [value, want] of [['1M', 1000000], ['400k', 400000], ['1.5M', 1500000], ['1000000', 1000000], ['', 0]]) {
    assert.equal(scope.parseContextTokens(value), want);
  }
  for (const value of ['-1', '1.5', '1e6', 'Infinity', '2GB', '100000001', '<script>']) {
    assert.throws(() => scope.parseContextTokens(value));
  }
});

test('保存与恢复默认使用供应商作用域，不把模型别名当作保存键', async () => {
  const state = setup();
  const model = { id: 'deepseek-flash', scope_id: 'qodercn:deepseek-flash', alias: 'my-model', context_length: 1000000, upstream_context_length: 1000000 };
  const options = state.scope.modelContextCell(model);
  assert.equal(options.fallback(), '1M · 自动');
  await options.save('400K');
  assert.equal(state.requests[0].path, '/models/context');
  assert.equal(state.requests[0].body.model, 'qodercn:deepseek-flash');
  assert.equal(model.context_override, 400000);
  assert.equal(model.context_length, 400000);
  await options.save('');
  assert.equal(model.context_override, 0);
  assert.equal(model.context_length, 1000000);
  assert.equal(state.syncs, 2);
});

test('非法输入不发请求，不改变已保存设置', () => {
  const state = setup();
  const model = { id: 'm', scope_id: 'qodercn:m', context_length: 400000, context_override: 400000 };
  const options = state.scope.modelContextCell(model);
  assert.throws(() => options.save('invalid'));
  assert.equal(state.requests.length, 0);
  assert.equal(model.context_override, 400000);
});

test('上游未知时不能把当前手工值当成自动值', () => {
  const { scope } = setup();
  const options = scope.modelContextCell({ id: 'm', context_length: 400000, context_override: 400000, upstream_context_length: 0 });
  assert.equal(options.fallback(), '—');
  assert.equal(options.display(options.saved), '400K · 自定义');
});
