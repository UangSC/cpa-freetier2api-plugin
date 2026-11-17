package tests

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"freetier2api-plugin/cpasdk/pluginabi"
	"freetier2api-plugin/cpasdk/pluginapi"
	"freetier2api-plugin/internal/hostbridge"
)

func tokenPlanTestJWT() string {
	claims, _ := json.Marshal(map[string]any{"jti": "user-one", "iss": "OpenXLab", "exp": time.Now().Add(time.Hour).Unix()})
	return "header." + base64.RawURLEncoding.EncodeToString(claims) + ".signature"
}

// 完整经过管理接口、供应商校验和宿主保存，检查草稿阶段与提交阶段的边界。
func TestTokenPlanAuthorizationDraftAndAtomicSave(t *testing.T) {
	for _, mode := range []string{"callback", "curl", "key-only", "invalid-curl", "wrong-account", "existing-key"} {
		t.Run(mode, func(t *testing.T) {
			host := installFakeHost(t)
			setupTestPlugin(t)
			if mode == "existing-key" {
				host.addAccount("existing", "tokenplan-existing.json", `{"type":"freetier","vendor":"tokenplan","api_key":"sk-testabcd","note":"keep","disabled":true}`)
			}
			saves := []pluginapi.HostAuthSaveRequest{}
			hostbridge.Configure(func(callbackID, method string, payload any) (json.RawMessage, error) {
				if method == pluginabi.MethodHostAuthSave {
					var save pluginapi.HostAuthSaveRequest
					if err := json.Unmarshal(mustMarshal(payload), &save); err != nil {
						t.Fatal(err)
					}
					saves = append(saves, save)
				}
				return host.call(callbackID, method, payload)
			})
			token := tokenPlanTestJWT()
			host.setUpstream(func(method, address, body string) fakeUpstreamResponse {
				payload := `{"code":0,"data":{"available_credits":"1234.567"}}`
				switch {
				case address == "https://discovery.intern-ai.org.cn/api/user-center/v1/users/auth":
					if method != "POST" || !strings.Contains(body, "test-code") {
						t.Fatal("授权码必须通过固定接口交换")
					}
					payload = string(mustMarshal(map[string]any{"code": 0, "data": map[string]string{"token": token}}))
				case address == "https://discovery.intern-ai.org.cn/api/tokenplan/v1/credits/balance":
					if method != "GET" || body != "" {
						t.Fatal("余额 cURL 不得重放方法或正文")
					}
				case address == "https://discovery.intern-ai.org.cn/api/tokenplan/v1/keys?page=1&page_size=10":
					mask := "sk-...abcd"
					if mode == "wrong-account" {
						mask = "sk-...9999"
					}
					payload = string(mustMarshal(map[string]any{"code": 0, "data": map[string]any{"items": []map[string]string{{"id": "one", "masked_key": mask, "status": "active"}}, "total": 1}}))
				default:
					return fakeUpstreamResponse{Status: 404, Body: `{}`}
				}
				return fakeUpstreamResponse{Status: 200, Body: payload}
			})
			binding := "curl 'https://discovery.intern-ai.org.cn/api/tokenplan/v1/credits/balance' -X POST -H 'Authorization: Bearer " + token + "' --data-raw 'must-not-replay'"
			if mode == "callback" {
				start := managementCallWithBody(t, "POST", "/accounts/quota-auth/start", map[string]string{"vendor": "tokenplan", "api_key": "sk-testabcd"})
				var result struct {
					URL string `json:"url"`
				}
				if start.StatusCode != 200 || json.Unmarshal(start.Body, &result) != nil || result.URL == "" || len(saves) != 0 {
					t.Fatalf("生成授权地址时不应保存账号：%s", start.Body)
				}
				parsed, _ := url.Parse(result.URL)
				binding = parsed.Query().Get("redirect") + "?code=test-code"
				wrong := managementCallWithBody(t, "POST", "/accounts/add", map[string]string{"vendor": "tokenplan", "api_key": "sk-other1234", "quota_credential": binding})
				if wrong.StatusCode != 400 || len(saves) != 0 {
					t.Fatal("草稿回调不能绑定到其他 Key，失败不能写盘")
				}
			}
			if mode == "invalid-curl" {
				binding = strings.Replace(binding, "discovery.intern-ai.org.cn", "example.com", 1)
			}
			if mode == "key-only" {
				binding = ""
			}
			response := managementCallWithBody(t, "POST", "/accounts/add", map[string]string{"vendor": "tokenplan", "api_key": "sk-testabcd", "quota_credential": binding})
			if mode == "invalid-curl" || mode == "wrong-account" {
				if response.StatusCode != 400 || len(saves) != 0 {
					t.Fatalf("无效绑定不能留下账号：status=%d saves=%d", response.StatusCode, len(saves))
				}
				return
			}
			if response.StatusCode != 200 || len(saves) != 1 {
				t.Fatalf("完整授权应一次保存：status=%d saves=%d body=%s", response.StatusCode, len(saves), response.Body)
			}
			var stored map[string]any
			if json.Unmarshal(saves[0].JSON, &stored) != nil || stored["api_key"] != "sk-testabcd" {
				t.Fatal("模型 Key 未保存")
			}
			if mode != "key-only" && (stored["balance_token"] != token || stored["user_id"] != "user-one") {
				t.Fatal("网页授权与 Key 必须保存到同一凭证")
			}
			if mode == "existing-key" && (saves[0].Name != "tokenplan-existing.json" || stored["note"] != "keep" || stored["disabled"] != true) {
				t.Fatal("同一 Key 必须保留原文件及其他设置")
			}
			if strings.Contains(string(response.Body), token) || strings.Contains(string(response.Body), "sk-testabcd") {
				t.Fatal("保存响应不能回显密钥")
			}
		})
	}
}

func TestTokenPlanAuthorizationRejectsInvalidDrafts(t *testing.T) {
	installFakeHost(t)
	setupTestPlugin(t)
	for _, body := range []map[string]string{
		{"vendor": "tokenplan", "api_key": ""},
		{"vendor": "tokenplan", "api_key": "invalid key"},
		{"vendor": "unknown", "api_key": "test"},
		{"account_id": "existing", "vendor": "tokenplan", "api_key": "test"},
	} {
		if response := managementCallWithBody(t, "POST", "/accounts/quota-auth/start", body); response.StatusCode != http.StatusBadRequest {
			t.Fatalf("无效草稿应拒绝：%s", response.Body)
		}
	}
	response := managementCallWithBody(t, "POST", "/accounts/add", map[string]string{"vendor": "opencodezen", "api_key": "test", "quota_credential": "curl test"})
	if response.StatusCode != 400 {
		t.Fatal("其他供应商不能混入余额授权")
	}
}
