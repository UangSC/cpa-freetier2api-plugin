import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const html = readFileSync(new URL('../../internal/admin/console.html', import.meta.url), 'utf8');
const loginCode = html.slice(html.indexOf('  var loginTimer = null;'), html.indexOf('  // 主「刷新」按钮执行 Token'));
const vendor = {id:'tokenplan', name:'书生 Token Plan', auth_mode:'apikey', supports_login:false, quota_credential_hint:'为当前 Key 绑定墨点', quota_authorization:true};
const flush = () => new Promise(resolve => setImmediate(resolve));

function setup(respond = () => ({ok:true, auth_id:'tokenplan-test.json'}), accounts = []) {
  const elements = new Map();
  const requests = [], messages = [], quotaLoads = [], writes = [];
  const get = id => {
    if (!elements.has(id)) elements.set(id, {
      hidden:true, disabled:false, value:'', textContent:'', style:{}, children:[], handlers:{},
      addEventListener(name, fn) {this.handlers[name] = fn;},
      appendChild(child) {this.children.push(child);},
      removeAttribute(name) {delete this[name];}, focus() {},
    });
    return elements.get(id);
  };
  const scope = vm.createContext({
    document:{getElementById:get, addEventListener(){}}, lastStatus:{accounts}, vendorsById:{tokenplan:vendor},
    accountKey:a => a.auth_id, accountDisplay:a => a.label || a.auth_id,
    closeVendorMenu(){}, toggleVendorMenu(){},
    banner:(...args) => messages.push(args), loadStatus:() => Promise.resolve(),
    loadQuotas:(...args) => {quotaLoads.push(args); return Promise.resolve();},
    setInterval:() => 1, clearInterval(){}, setTimeout:() => 1, clearTimeout(){},
    localStorage:{setItem:(...args) => writes.push(args)}, sessionStorage:{setItem:(...args) => writes.push(args)},
    navigator:{clipboard:{writeText:() => Promise.resolve()}},
    api:(method,path,body) => {requests.push({method,path,body}); return Promise.resolve(respond(path,body));},
  });
  vm.runInContext(loginCode, scope);
  return {scope,get,requests,messages,quotaLoads,writes, click:id => get(id).handlers.click()};
}

test('墨点绑定位于完成授权弹窗内，首页不再常驻账号选择卡片', () => {
  const modal = html.slice(html.indexOf('<div class="modal" id="apiKeyBox"'), html.indexOf('<div id="accounts">'));
  assert.match(modal, /role="dialog"/);
  assert.match(modal, /id="quotaCredentialBox" hidden/);
  assert.match(modal, /id="inputQuotaCredential"[^>]*autocomplete="off"[^>]*-webkit-text-security:disc/);
  assert.doesNotMatch(html, /quotaCredentialAccountSelect|renderQuotaCredentialAccounts|常驻单账号/);
});

test('填写 Key 后生成地址，生成时不保存账号', async () => {
  const state = setup(() => ({ok:true,url:'https://sso.openxlab.org.cn/authentication?draft=one'}));
  state.scope.startVendorAdd(vendor);
  assert.equal(state.get('apiKeyBox').style.display, 'flex');
  assert.equal(state.get('apiKeyTitle').textContent, '完成授权 · 书生 Token Plan');
  assert.equal(state.get('quotaCredentialBox').hidden, false);
  state.click('btnQuotaAuthorizationGenerate'); assert.equal(state.requests.length, 0);
  state.get('inputApiKey').value = 'test-key';
  state.click('btnQuotaAuthorizationGenerate'); await flush();
  assert.equal(state.requests.length, 1);
  assert.equal(state.requests[0].path, '/accounts/quota-auth/start');
  assert.equal(state.requests[0].body.vendor, vendor.id);
  assert.equal(state.requests[0].body.api_key, 'test-key');
  assert.equal(state.requests[0].body.account_id, undefined);
  assert.match(state.get('quotaAuthorizationUrl').value, /draft=one/);
});

test('Key 和回调或多行 cURL 一次保存，成功后清空输入', async () => {
  for (const credential of ['https://discovery.intern-ai.org.cn/token-plan/points#callback?code=test', "curl 'https://discovery.intern-ai.org.cn/api/tokenplan/v1/credits/balance'\n -H 'Authorization: Bearer test-token'"]) {
    const state = setup(); state.scope.startVendorAdd(vendor);
    state.get('inputApiKey').value = 'test-key'; state.get('inputQuotaCredential').value = credential;
    state.click('btnSubmitApiKey'); await flush();
    assert.equal(state.requests.length, 1); assert.equal(state.requests[0].path, '/accounts/add');
    assert.equal(state.requests[0].body.api_key, 'test-key');
    assert.equal(state.requests[0].body.quota_credential, credential);
    assert.equal(state.get('inputApiKey').value, ''); assert.equal(state.get('inputQuotaCredential').value, '');
    assert.equal(state.get('apiKeyBox').hidden, true); assert.deepEqual(state.writes, []);
  }
});

test('墨点授权可选，其他 API Key 供应商不显示余额绑定', async () => {
  const state = setup(); state.scope.startVendorAdd(vendor);
  state.get('inputApiKey').value = 'key-only'; state.click('btnSubmitApiKey'); await flush();
  assert.equal(state.requests[0].body.quota_credential, '');
  state.scope.startVendorAdd({id:'other', name:'其他渠道', auth_mode:'apikey', supports_login:false});
  assert.equal(state.get('quotaCredentialBox').hidden, true);
});

test('已有账号在同一弹窗重新授权，按账号提交且无需重复填写 Key', async () => {
  const account = {auth_id:'existing', vendor_id:vendor.id, label:'测试账号', quota_credential_hint:'hint'};
  const state = setup(path => path.endsWith('/start') ? {ok:true,url:'https://sso.openxlab.org.cn/authentication'} : {ok:true}, [account]);
  state.scope.openQuotaCredential(account); await flush();
  assert.equal(state.get('apiKeyFields').hidden, true);
  assert.equal(state.requests[0].body.account_id, 'existing'); assert.equal(state.requests[0].body.api_key, undefined);
  state.get('inputQuotaCredential').value = 'curl test'; state.click('btnSubmitApiKey'); await flush();
  assert.equal(state.requests[1].path, '/accounts/quota-credential');
  assert.equal(state.requests[1].body.account_id, 'existing'); assert.equal(state.quotaLoads[0][1][0], 'existing');
});

test('取消、换 Key 或换账号会丢弃迟到的授权地址', async () => {
  for (const action of ['cancel','key','account']) {
    let resolve; const pending = new Promise(done => {resolve = done;});
    const state = setup(() => pending); state.scope.startVendorAdd(vendor);
    state.get('inputApiKey').value = 'old-key'; state.scope.generateQuotaAuthorization();
    state.get('inputQuotaCredential').value = 'old-credential';
    if (action === 'cancel') state.click('btnCancelApiKey');
    if (action === 'key') {state.get('inputApiKey').value = 'new-key'; state.get('inputApiKey').handlers.input();}
    if (action === 'account') state.scope.startVendorAdd(vendor);
    resolve({ok:true,url:'https://sso.openxlab.org.cn/authentication?old=one'}); await flush();
    assert.equal(state.get('quotaAuthorizationUrl').value, ''); assert.equal(state.get('inputQuotaCredential').value, '');
    assert.equal(state.get('quotaAuthorizationLink').hidden, true);
  }
});

test('绑定失败保留输入，迟到的保存回执不干扰新表单', async () => {
  const failed = setup(() => ({ok:false,error:'Key 与网页账号不匹配'})); failed.scope.startVendorAdd(vendor);
  failed.get('inputApiKey').value = 'test-key'; failed.get('inputQuotaCredential').value = 'curl test';
  failed.click('btnSubmitApiKey'); await flush();
  assert.equal(failed.get('inputApiKey').value, 'test-key'); assert.equal(failed.get('apiKeyBox').hidden, false);
  let resolve; const state = setup(() => new Promise(done => {resolve = done;}));
  state.scope.startVendorAdd(vendor); state.get('inputApiKey').value = 'old-key'; state.click('btnSubmitApiKey');
  state.scope.startVendorAdd(vendor); state.get('inputApiKey').value = 'new-key'; resolve({ok:true}); await flush();
  assert.equal(state.get('inputApiKey').value, 'new-key');
});

test('停用账号不能生成授权，墨点显示仍保留三位小数', () => {
  const state = setup(); state.scope.openQuotaCredential({auth_id:'disabled', vendor_id:vendor.id, disabled:true});
  assert.equal(state.requests.length, 0); assert.match(state.messages[0][1], /启用/);
  const scope = vm.createContext({});
  vm.runInContext(html.slice(html.indexOf('  function quotaRemainingText('), html.indexOf('  // accountOriginalName')), scope);
  assert.equal(scope.quotaRemainingText({metrics:[{key:'credit_remain',unit:'墨点',value:1234.567}]}), '我的墨点 1,234.567 墨点');
});
