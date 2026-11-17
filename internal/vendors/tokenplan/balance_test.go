package tokenplan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"freetier2api-plugin/internal/core"
	"freetier2api-plugin/internal/hostbridge"
)

type balanceTestHost struct{ dir string }

func (balanceTestHost) ListAuths(context.Context) ([]core.HostAuth, error) { return nil, nil }
func (balanceTestHost) AuthJSON(context.Context, string) ([]byte, bool)    { return nil, false }
func (h balanceTestHost) Settings() core.Settings                          { return core.Settings{StateDir: h.dir} }
func testBalanceToken(exp int64) string {
	claims, _ := json.Marshal(map[string]any{"jti": "user-1", "iss": "OpenXLab", "exp": exp})
	return "header." + base64.RawURLEncoding.EncodeToString(claims) + ".signature"
}

func TestSingleAccountBalanceBindingAndUnboundIsolation(t *testing.T) {
	v := Instances(core.Env{})[0].(*adapter)
	account, _ := v.Parse([]byte(`{"api_key":"sk-testabcd","disabled":false,"note":"keep"}`), "tokenplan-a.json")
	other, _ := v.Parse([]byte(`{"api_key":"sk-other1234"}`), "tokenplan-b.json")
	calls := 0
	hostbridge.Configure(func(_, _ string, payload any) (json.RawMessage, error) {
		calls++
		var req struct {
			Method, URL string
			Headers     http.Header
			Body        []byte
		}
		data, _ := json.Marshal(payload)
		json.Unmarshal(data, &req)
		if req.Method != "GET" || len(req.Body) > 0 {
			t.Fatal("cURL 导入只能发固定 GET")
		}
		body := `{"available_credits":"1234.567"}`
		if strings.Contains(req.URL, "/keys?") {
			body = `{"items":[{"id":"one","masked_key":"sk-...abcd","status":"active"}],"total":1}`
		}
		raw, _ := json.Marshal(map[string]any{"code": 0, "data": json.RawMessage(body)})
		return json.Marshal(map[string]any{"StatusCode": 200, "Body": raw})
	})
	t.Cleanup(func() { hostbridge.Configure(nil) })
	if _, err := v.Quota(context.Background(), other); err == nil || calls != 0 {
		t.Fatal("未绑定账号不得查询余额")
	}
	token := testBalanceToken(time.Now().Add(time.Hour).Unix())
	updated, err := v.PrepareQuotaCredential(context.Background(), account, "curl --url '"+balanceOrigin+balancePath+"' -H 'Authorization: Bearer "+token+"'")
	if err != nil {
		t.Fatal(err)
	}
	bound, err := v.Parse(updated, "tokenplan-a.json")
	if err != nil {
		t.Fatal(err)
	}
	if !v.QuotaCredentialBound(bound) || v.QuotaCredentialBound(other) {
		t.Fatal("绑定不能传播到其他账号")
	}
	quota, err := v.Quota(context.Background(), bound)
	if err != nil || quota.Summary[0].Value != 1234.567 {
		t.Fatalf("余额错误: %v", err)
	}
	var doc map[string]any
	json.Unmarshal(updated, &doc)
	if doc["api_key"] != "sk-testabcd" || doc["note"] != "keep" {
		t.Fatal("绑定不能覆盖原凭证数据")
	}
	if _, ok := core.As[core.CheckinProvider](v); ok {
		t.Fatal("不应增加签到")
	}
}

func TestBalanceValuesAndContextOverrideRemoval(t *testing.T) {
	for _, raw := range []string{`{}`, `{"available_credits":null}`, `{"available_credits":"NaN"}`, `{"available_credits":-1}`} {
		if _, err := balanceValue([]byte(raw)); err == nil {
			t.Fatal("无效余额不能显示为零")
		}
	}
	if value, err := balanceValue([]byte(`{"available_credits":"0.000"}`)); err != nil || value != 0 {
		t.Fatal("合法零余额应正确显示")
	}
	req := &core.ExecuteRequest{Model: "intern-s2", ContextLength: 100000000, Payload: []byte(`{"model":"intern-s2","context_window":1000000,"context_length":1000000,"messages":[]}`)}
	locked, err := lockExecuteRequest(req)
	if err != nil || locked.ContextLength != 262144 || req.ContextLength != 100000000 {
		t.Fatal("执行窗口应固定，且不修改调用方请求")
	}
	body, err := prepareBody(locked.Payload, false)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	json.Unmarshal(body, &fields)
	if fields["context_window"] != nil || fields["context_length"] != nil {
		t.Fatal("不能转发上下文覆盖参数")
	}
}

func TestAuthorizationCallbackIsScopedAndUpdatesOneCredential(t *testing.T) {
	v := Instances(core.Env{})[0].(*adapter)
	cred, _ := v.Parse([]byte(`{"api_key":"sk-testabcd"}`), "tokenplan-a.json")
	start, err := v.StartQuotaAuthorization(context.Background(), cred)
	if err != nil {
		t.Fatal(err)
	}
	authorize, _ := url.Parse(start.URL)
	callback := authorize.Query().Get("redirect") + "?code=mock-code"
	if !strings.HasPrefix(callback, balanceOrigin+"/token-plan/points#freetier2api-balance/") {
		t.Fatal("回调应使用官网允许的 HTTPS 地址")
	}
	token := testBalanceToken(time.Now().Add(time.Hour).Unix())
	hostbridge.Configure(func(_, _ string, payload any) (json.RawMessage, error) {
		var req struct {
			Method, URL string
			Body        []byte
		}
		raw, _ := json.Marshal(payload)
		json.Unmarshal(raw, &req)
		body := `{"code":0,"data":{"available_credits":"10.000"}}`
		if strings.Contains(req.URL, "/users/auth") {
			if req.Method != "POST" {
				t.Fatal("授权码必须通过 POST 交换")
			}
			encoded, _ := json.Marshal(map[string]any{"code": 0, "data": map[string]string{"token": token}})
			body = string(encoded)
		}
		if strings.Contains(req.URL, "/keys?") {
			body = `{"code":0,"data":{"items":[{"id":"a","masked_key":"sk-...abcd","status":"active"}],"total":1}}`
		}
		return json.Marshal(map[string]any{"StatusCode": 200, "Body": []byte(body)})
	})
	t.Cleanup(func() { hostbridge.Configure(nil) })
	updated, err := v.PrepareQuotaCredential(context.Background(), cred, callback)
	if err != nil {
		t.Fatal(err)
	}
	bound, _ := v.Parse(updated, "tokenplan-a.json")
	if !v.QuotaCredentialBound(bound) {
		t.Fatal("回调未绑定到当前凭证")
	}
	if _, err = v.PrepareQuotaCredential(context.Background(), cred, callback); err == nil {
		t.Fatal("同一授权状态不能重复提交")
	}
}
