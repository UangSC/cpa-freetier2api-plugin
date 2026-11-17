import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const html = readFileSync(new URL('../../internal/admin/console.html', import.meta.url), 'utf8');
const loginCode = html.slice(html.indexOf('  var loginTimer = null;'), html.indexOf('  // 主「刷新」按钮执行 Token'));
const qwen = { id: 'qwenwork', name: '千问办公', auth_mode: 'oauth', supports_login: true, credential_import: true, credential_import_hint: '从千问办公客户端导出凭证 JSON。' };
const keyVendor = { id: 'key-vendor', name: 'API 渠道', auth_mode: 'apikey', supports_login: false, credential_import: true };

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

function element() {
  return {
    hidden: true, disabled: false, value: '', textContent: '', placeholder: '', style: {}, children: [], handlers: {},
    addEventListener(name, handler) { this.handlers[name] = handler; },
    appendChild(child) { this.children.push(child); child.parentNode = this; },
    removeChild(child) { this.children = this.children.filter(value => value !== child); },
    removeAttribute(name) { delete this[name]; },
    focus() { this.focused = true; },
  };
}

function setup(respond = () => ({ ok: true })) {
  const elements = new Map();
  const requests = [];
  const banners = [];
  const intervals = new Map();
  const storageWrites = [];
  let nextTimer = 0;
  let quotaLoads = 0;
  const get = id => {
    if (!elements.has(id)) elements.set(id, element());
    return elements.get(id);
  };
  const scope = vm.createContext({
    document: { getElementById: get, addEventListener() {} },
    el: () => element(),
    lastStatus: { accounts: [] },
    hostPath: path => `host:${path}`,
    closeVendorMenu() {}, toggleVendorMenu() {},
    banner: (...args) => banners.push(args),
    loadStatus: () => Promise.resolve(),
    loadQuotas: () => { quotaLoads++; return Promise.resolve(); },
    setInterval: callback => { const id = ++nextTimer; intervals.set(id, callback); return id; },
    clearInterval: id => intervals.delete(id),
    setTimeout: () => ++nextTimer, clearTimeout() {},
    localStorage: { setItem: (...args) => storageWrites.push(args) },
    sessionStorage: { setItem: (...args) => storageWrites.push(args) },
    api: (method, path, body) => {
      requests.push({ method, path, body });
      return Promise.resolve(respond(method, path, body));
    },
  });
  vm.runInContext(loginCode, scope);
  return { scope, get, requests, banners, intervals, storageWrites, quotaLoads: () => quotaLoads };
}

const flush = () => new Promise(resolve => setImmediate(resolve));
function click(state, id) { state.get(id).handlers.click(); }

test('OAuth 渠道通过显式粘贴入口提交 JSON，保存后清空凭证', async () => {
  const auth = deferred();
  const state = setup((method, path) => path.startsWith('host:') ? auth.promise : { ok: true });
  state.scope.startVendorAdd(qwen);
  assert.equal(state.get('loginCredentialRow').hidden, false);
  click(state, 'btnPasteCredential');
  assert.equal(state.scope.currentAccountInputMode, 'credential_json');
  assert.equal(state.get('apiKeyHint').textContent, qwen.credential_import_hint);
  const credential = '{"access_token":"test-token"}';
  state.get('inputApiKey').value = credential;
  click(state, 'btnSubmitApiKey');
  await flush();
  const saved = state.requests.find(request => request.path === '/accounts/add');
  assert.equal(saved.body.credential_json, credential);
  assert.equal(saved.body.api_key, undefined);
  assert.equal(state.get('inputApiKey').value, '');
  assert.equal(state.get('apiKeyBox').hidden, true);
  assert.equal(state.scope.currentAccountInputMode, 'api_key');
  assert.deepEqual(state.storageWrites, []);
});

test('支持导入的 API Key 渠道仍默认按 API Key 提交，切模式后才按 JSON 处理', async () => {
  const state = setup();
  state.scope.startVendorAdd(keyVendor);
  const jsonLikeKey = '{"key":"still-an-api-key"}';
  state.get('inputApiKey').value = jsonLikeKey;
  click(state, 'btnSubmitApiKey');
  await flush();
  assert.equal(state.requests[0].body.api_key, jsonLikeKey);
  assert.equal(state.requests[0].body.credential_json, undefined);
  state.scope.startVendorAdd(keyVendor);
  assert.equal(state.get('btnToggleCredentialMode').hidden, false);
  click(state, 'btnToggleCredentialMode');
  assert.equal(state.scope.currentAccountInputMode, 'credential_json');
  state.get('inputApiKey').value = '{"access_token":"test"}';
  click(state, 'btnSubmitApiKey');
  await flush();
  assert.equal(state.requests[1].body.api_key, undefined);
  assert.equal(state.requests[1].body.credential_json, '{"access_token":"test"}');
});

test('无效 JSON 或非对象不会发请求，错误提示不回显令牌内容', () => {
  for (const value of ['{"access_token":"sensitive-value"', 'null', '[]', '"sensitive-value"']) {
    const state = setup();
    state.scope.startCredentialPaste(qwen);
    state.get('inputApiKey').value = value;
    click(state, 'btnSubmitApiKey');
    assert.equal(state.requests.length, 0);
    assert.match(state.banners.at(-1)[1], /凭证 JSON/);
    assert.doesNotMatch(state.banners.at(-1)[1], /sensitive-value/);
    assert.equal(state.get('btnSubmitApiKey').disabled, false);
  }
});

test('切到粘贴或取消后，迟到的授权链接不能恢复旧轮询', async () => {
  const auth = deferred();
  const state = setup(() => auth.promise);
  state.scope.startLogin(qwen);
  click(state, 'btnPasteCredential');
  state.get('inputApiKey').value = '{"access_token":"test"}';
  click(state, 'btnCancelApiKey');
  auth.resolve({ url: 'https://qwenwork.cn/signin', state: 'old-state' });
  await flush();
  assert.equal(state.scope.currentLoginState, '');
  assert.equal(state.scope.currentApiKeyVendor, null);
  assert.equal(state.get('loginUrl').value, '');
  assert.equal(state.get('inputApiKey').value, '');
  assert.equal(state.get('loginBox').hidden, true);
  assert.equal(state.intervals.size, 0);
});

test('切换渠道使旧轮询失效，迟到成功不能干扰新输入或触发额度查询', async () => {
  const poll = deferred();
  const state = setup((method, path) => path.includes('get-auth-status') ? poll.promise : { url: 'https://qwenwork.cn/signin', state: 'old-state' });
  state.scope.startLogin(qwen);
  await flush();
  assert.equal(state.intervals.size, 1);
  [...state.intervals.values()][0]();
  state.scope.startVendorAdd(keyVendor);
  state.get('inputApiKey').value = 'new-input';
  poll.resolve({ status: 'ok' });
  await flush();
  assert.equal(state.intervals.size, 0);
  assert.equal(state.quotaLoads(), 0);
  assert.equal(state.banners.length, 0);
  assert.equal(state.get('inputApiKey').value, 'new-input');
  assert.equal(state.get('apiKeyBox').hidden, false);
});

test('旧保存回执不能清空后来打开的渠道输入，取消清空所有敏感字段', async () => {
  const save = deferred();
  const state = setup(() => save.promise);
  state.scope.startCredentialPaste(qwen);
  state.get('inputApiKey').value = '{"access_token":"old"}';
  click(state, 'btnSubmitApiKey');
  state.scope.startVendorAdd(keyVendor);
  for (const id of ['inputApiKey', 'inputApiLabel', 'loginUrl', 'loginPasteUrl', 'inputSmsPhone', 'inputSmsCode', 'inputSmsLabel']) state.get(id).value = 'new-input';
  save.resolve({ ok: true });
  await flush();
  assert.equal(state.get('inputApiKey').value, 'new-input');
  assert.equal(state.get('apiKeyBox').hidden, false);
  click(state, 'btnCancelApiKey');
  for (const id of ['inputApiKey', 'inputApiLabel', 'loginUrl', 'loginPasteUrl', 'inputSmsPhone', 'inputSmsCode', 'inputSmsLabel']) assert.equal(state.get(id).value, '');
  assert.equal(state.scope.currentAccountInputMode, 'api_key');
  assert.equal(state.scope.currentLoginVendor, null);
});

test('AutoClaw 国际版旧描述仍可从网页登录粘贴凭证，未声明能力的其他渠道不展示', () => {
  const state = setup();
  const legacy = { id: 'autoclawglobal', name: 'AutoClaw 国际版', auth_mode: 'apikey', login_captcha: true };
  state.scope.startVendorAdd(legacy);
  assert.equal(state.get('loginCredentialRow').hidden, false);
  click(state, 'btnPasteCredential');
  assert.equal(state.scope.currentAccountInputMode, 'credential_json');
  assert.match(state.get('apiKeyHint').textContent, /AutoClaw.*自动续期/);
  assert.equal(state.get('btnToggleCredentialMode').hidden, true);
  state.scope.startLogin({ id: 'other', name: '其他渠道', auth_mode: 'oauth', supports_login: true });
  assert.equal(state.get('loginCredentialRow').hidden, true);
});

test('凭证输入关闭自动填充，API Key 遮盖显示', () => {
  const input = html.match(/<input[^>]+id="inputApiKey"[^>]*>/)?.[0];
  assert.match(input, /type="password"/);
  assert.match(input, /autocomplete="off"/);
});

test('只提供凭证导入的 OAuth 渠道直接进入 JSON 模式', () => {
  const state = setup();
  state.scope.startVendorAdd({ ...qwen, supports_login: false });
  assert.equal(state.scope.currentAccountInputMode, 'credential_json');
  assert.equal(state.get('apiKeyBox').hidden, false);
  assert.equal(state.requests.length, 0);
});
