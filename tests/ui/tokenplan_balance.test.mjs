import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const html=readFileSync(new URL('../../internal/admin/console.html',import.meta.url),'utf8');
const helpers=html.slice(html.indexOf('  function quotaRemainingText('),html.indexOf('  // accountOriginalName'));
test('墨点保留三位小数',()=>{
 const scope=vm.createContext({});vm.runInContext(helpers,scope);
 const quota={ok:true,remain:1234,wallet_id:'wallet',fetched_at:'2026-11-17T01:00:00+08:00',metrics:[{key:'credit_remain',unit:'墨点',value:1234.567}]};
 assert.equal(scope.quotaRemainingText(quota),'我的墨点 1,234.567 墨点');
});
test('余额输入不自动填充且遮盖凭证内容',()=>{
 assert.match(html,/id="inputQuotaCredential"[^>]*autocomplete="off"[^>]*-webkit-text-security:disc/);
 assert.match(html,/account_id: accountID/);
 assert.doesNotMatch(html,/btnBindInkBalance|sharedInkBalance/);
});

test('Token Plan 授权模块常驻，不依赖账号行小按钮',()=>{
 assert.match(html,/<div class="card" id="quotaCredentialBox">/);
 assert.match(html,/书生 Token Plan · 墨点授权/);
 assert.match(html,/id="btnQuotaAuthorizationGenerate"/);
 assert.match(html,/id="quotaAuthorizationUrl"/);
 assert.match(html,/lastStatus = status;\s*renderQuotaCredentialAccounts\(status\);/);
});

test('加载账号后可选择并生成可见授权地址，不自动发起绑定',async()=>{
 const elements=new Map();const get=id=>{if(!elements.has(id))elements.set(id,{value:'',hidden:true,disabled:false,textContent:'',children:[],appendChild(e){this.children.push(e)},addEventListener(){}});return elements.get(id)};
 const requests=[];const account={auth_id:'one',vendor_id:'tokenplan',quota_credential_hint:'hint'};
 const scope=vm.createContext({document:{getElementById:get,createElement:()=>({value:'',textContent:''})},lastStatus:{accounts:[account]},accountKey:a=>a.auth_id,accountDisplay:()=> '测试账号',banner(){},loadQuotas(){},navigator:{clipboard:{writeText(){}}},api:(method,path,body)=>{requests.push({path,body});return Promise.resolve({ok:true,url:'https://sso.openxlab.org.cn/authentication?test=1'})}});
 const code=html.slice(html.indexOf('  // ---- 常驻单账号墨点授权入口 ----'),html.indexOf('  function quotaRemainingText('));vm.runInContext(code,scope);
 scope.renderQuotaCredentialAccounts(scope.lastStatus);assert.equal(get('quotaCredentialAccountSelect').value,'one');assert.equal(requests.length,0);
 scope.generateQuotaAuthorization();await new Promise(r=>setImmediate(r));assert.equal(requests[0].path,'/accounts/quota-auth/start');assert.equal(get('quotaAuthorizationLink').hidden,false);assert.match(get('quotaAuthorizationUrl').value,/sso.openxlab/);
});

function setupAccounts(accounts, respond=()=>Promise.resolve({ok:true,url:'https://sso.openxlab.org.cn/authentication?test=1'})) {
 const elements=new Map();
 const get=id=>{if(!elements.has(id))elements.set(id,{value:'',hidden:true,disabled:false,children:[],_text:'',get textContent(){return this._text},set textContent(value){this._text=value;this.children=[]},appendChild(e){this.children.push(e)},addEventListener(){}});return elements.get(id)};
 const requests=[];
 const scope=vm.createContext({document:{getElementById:get,createElement:()=>({value:'',textContent:'',disabled:false})},lastStatus:{accounts},accountKey:a=>a.auth_id,accountDisplay:a=>a.label||a.auth_id,banner(){},loadQuotas(){},navigator:{clipboard:{writeText(){}}},api:(method,path,body)=>{requests.push({path,body});return respond(body)}});
 vm.runInContext(html.slice(html.indexOf('  // ---- 常驻单账号墨点授权入口 ----'),html.indexOf('  function quotaRemainingText(')),scope);
 scope.renderQuotaCredentialAccounts(scope.lastStatus);
 return {scope,get,requests};
}

test('已有停用账号时选择唯一启用账号，停用选项不能发起授权',async()=>{
 const state=setupAccounts([{auth_id:'disabled',vendor_id:'tokenplan',disabled:true,quota_credential_hint:'hint'},{auth_id:'active',vendor_id:'tokenplan',disabled:false,quota_credential_hint:'hint'}]);
 assert.equal(state.get('quotaCredentialAccountSelect').value,'active');
 const disabledOption=state.get('quotaCredentialAccountSelect').children.find(a=>a.value==='disabled');
 assert.equal(disabledOption.disabled,true);assert.match(disabledOption.textContent,/已停用/);
 state.scope.generateQuotaAuthorization();await new Promise(r=>setImmediate(r));assert.equal(state.requests[0].body.account_id,'active');
 state.get('quotaCredentialAccountSelect').value='disabled';state.scope.selectQuotaCredentialAccount();state.scope.generateQuotaAuthorization();
 assert.equal(state.get('btnQuotaAuthorizationGenerate').disabled,true);assert.equal(state.get('quotaAuthorizationUrl').value,'');assert.equal(state.requests.length,1);
});

test('全部停用时说明先启用账号，多账号时由用户明确选择',()=>{
 const state=setupAccounts([{auth_id:'disabled',vendor_id:'tokenplan',disabled:true,quota_credential_hint:'hint'}]);
 assert.equal(state.get('quotaCredentialAccountSelect').disabled,true);assert.match(state.get('quotaCredentialHint').textContent,/启用/);assert.equal(state.get('btnQuotaAuthorizationGenerate').disabled,true);
 const multiple=setupAccounts(['one','two'].map(auth_id=>({auth_id,vendor_id:'tokenplan',quota_credential_hint:'hint'})));
 assert.equal(multiple.get('quotaCredentialAccountSelect').value,'');assert.equal(multiple.get('btnQuotaAuthorizationGenerate').disabled,true);assert.equal(multiple.requests.length,0);
});

test('切换账号后丢弃旧账号的迟到授权地址',async()=>{
 let resolve;const pending=new Promise(done=>{resolve=done});
 const state=setupAccounts(['one','two'].map(auth_id=>({auth_id,vendor_id:'tokenplan',quota_credential_hint:'hint'})),()=>pending);
 state.get('quotaCredentialAccountSelect').value='one';state.scope.selectQuotaCredentialAccount();state.scope.generateQuotaAuthorization();
 state.get('quotaCredentialAccountSelect').value='two';state.scope.selectQuotaCredentialAccount();resolve({ok:true,url:'https://sso.openxlab.org.cn/authentication?old=one'});await new Promise(r=>setImmediate(r));
 assert.equal(state.get('quotaAuthorizationUrl').value,'');assert.equal(state.get('quotaAuthorizationLink').hidden,true);
 state.scope.generateQuotaAuthorization();assert.equal(state.requests[1].body.account_id,'two');
});
