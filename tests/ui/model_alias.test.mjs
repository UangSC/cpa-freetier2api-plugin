import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const html = readFileSync(new URL('../../internal/admin/console.html', import.meta.url), 'utf8');
const aliasFunctions = html.slice(html.indexOf('  var modelAliasSaveVersions'), html.indexOf('  // selectedModelIDs'));
const syncFunctions = html.slice(html.indexOf('  var MODEL_SYNC_DEBOUNCE_MS'), html.indexOf('  // formatTokens'));
const officialID = 'sn-deepseek-v4-1-flash-1017';
const alias = 'DeepSeek-v4.1-flash';

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

function setup(options = {}) {
  const requests = [];
  const banners = [];
  const model = { id: officialID, scope_id: `raccoon:${officialID}`, vendor_id: 'raccoon', alias: 'previous', ...options.model };
  const scope = vm.createContext({
    editableCell: value => value,
    allModels: [model],
    hostPath: path => `host:${path}`,
    banner: (...args) => banners.push(args),
    setTimeout: resolve => setTimeout(resolve, 0),
    syncModelConfig: () => options.sync || Promise.resolve(true),
    api: async (method, path, body) => {
      requests.push({ method, path, body });
      if (path === '/models/alias') {
        if (options.saveError) throw new Error('写盘失败');
        return { ok: true, alias: options.savedAlias ?? body.alias };
      }
      if (path === '/status') return options.status || {
        settings: {}, accounts: [
          { auth_id: 'other-account', vendor_id: 'qodercn' },
          { auth_id: 'raccoon-disabled', vendor_id: 'raccoon', disabled: true },
          { auth_id: 'raccoon-account', vendor_id: 'raccoon' },
        ],
      };
      return options.probe ? options.probe() : { models: [{ id: options.registeredID ?? alias }] };
    },
  });
  vm.runInContext(aliasFunctions, scope);
  return { scope, model, requests, banners };
}

test('别名原样保存，等待同步完成，并只核对目标供应商的注册表', async () => {
  const sync = deferred();
  const state = setup({ sync: sync.promise });
  let finished = false;
  const saving = state.scope.modelIDCell(state.model).save(alias).then(result => { finished = true; return result; });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(finished, false);
  assert.equal(state.requests[0].body.model, `raccoon:${officialID}`);
  assert.equal(state.requests[0].body.alias, alias);
  assert.equal(state.requests.length, 1);
  sync.resolve(true);
  assert.equal((await saving).value, alias);
  assert.equal(state.model.alias, alias);
  const probes = state.requests.filter(request => request.path.startsWith('host:'));
  assert.equal(probes.length, 1);
  assert.match(probes[0].path, /name=raccoon-account$/);
  assert.match(state.banners.at(-1)[1], /已保存并生效/);
});

test('写盘失败保留旧值，同步失败保留已保存值并明确告知尚未生效', async () => {
  const rejected = setup({ saveError: true });
  await assert.rejects(rejected.scope.modelIDCell(rejected.model).save(alias), /写盘失败/);
  assert.equal(rejected.model.alias, 'previous');
  const saved = setup({ sync: Promise.resolve(false) });
  assert.equal((await saved.scope.modelIDCell(saved.model).save(alias)).value, alias);
  assert.equal(saved.requests.length, 1);
  assert.equal(saved.banners.at(-1)[0], 'warn');
  assert.match(saved.banners.at(-1)[1], /已保存.*同步失败/);
});

test('注册表仍是旧值或重载未完成时，不能报告新别名已经生效', async () => {
  for (const options of [
    { registeredID: 'previous' },
    { status: { restart_pending: true, accounts: [{ auth_id: 'a', vendor_id: 'raccoon' }] } },
  ]) {
    const state = setup(options);
    await state.scope.modelIDCell(state.model).save(alias);
    assert.equal(state.banners.at(-1)[0], 'warn');
    assert.match(state.banners.at(-1)[1], /生效核对未通过/);
    assert.ok(state.requests.length < 15, '轮询必须有上限');
  }
});

test('清除别名按渠道标识核对；已禁用模型只确认保存', async () => {
  const state = setup({
    registeredID: `raccoon-${officialID}`,
    status: { settings: { model_name_tag: 'prefix' }, accounts: [{ auth_id: 'a', vendor_id: 'raccoon' }] },
  });
  assert.equal((await state.scope.modelIDCell(state.model).save('')).value, '');
  assert.match(state.banners.at(-1)[1], /已保存并生效/);
  const disabled = setup({ model: { disabled: true } });
  await disabled.scope.modelIDCell(disabled.model).save(alias);
  assert.equal(disabled.banners.at(-1)[0], 'warn');
  assert.match(disabled.banners.at(-1)[1], /模型当前已禁用/);
  assert.equal(disabled.requests.some(request => request.path.startsWith('host:')), false);
});

test('行内编辑器使用服务端回执，避免显示未实际保存的输入值', async () => {
  const state = setup({ savedAlias: 'server.alias', registeredID: 'server.alias' });
  const result = await state.scope.modelIDCell(state.model).save(alias);
  assert.equal(result.value, 'server.alias');
  assert.equal(state.model.alias, 'server.alias');
});

test('同一模型连续改名时，旧核对结果不能覆盖新设置的提示', async () => {
  const oldProbe = deferred();
  let probes = 0;
  const latestAlias = 'latest.alias';
  const state = setup({ probe: () => ++probes === 1 ? oldProbe.promise : { models: [{ id: latestAlias }] } });
  const options = state.scope.modelIDCell(state.model);
  const first = options.save(alias);
  await new Promise(resolve => setImmediate(resolve));
  await options.save(latestAlias);
  assert.match(state.banners.at(-1)[1], /latest\.alias/);
  oldProbe.resolve({ models: [{ id: alias }] });
  await first;
  assert.match(state.banners.at(-1)[1], /latest\.alias/);
});

test('正在重载时新保存的设置等待下一轮重载，失败返回 false', async () => {
  const patches = [];
  const scope = vm.createContext({
    setTimeout, clearTimeout,
    hostPath: path => path,
    loadModels: () => {}, banner: () => {},
    api: async method => {
      if (method === 'GET') return {};
      const pending = deferred();
      patches.push(pending);
      return pending.promise;
    },
  });
  vm.runInContext(syncFunctions + '\nMODEL_SYNC_DEBOUNCE_MS = 0;', scope);
  const first = scope.syncModelConfig();
  await new Promise(resolve => setTimeout(resolve, 10));
  const second = scope.syncModelConfig();
  let secondFinished = false;
  second.then(() => { secondFinished = true; });
  patches[0].resolve({ status: 'ok' });
  assert.equal(await first, true);
  assert.equal(secondFinished, false);
  await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(patches.length, 2);
  patches[1].resolve(null);
  assert.equal(await second, false);
});
