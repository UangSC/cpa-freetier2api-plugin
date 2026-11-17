package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"freetier2api-plugin/cpasdk/pluginabi"
	"freetier2api-plugin/cpasdk/pluginapi"
	"freetier2api-plugin/internal/core"
	"freetier2api-plugin/internal/hostbridge"
	"freetier2api-plugin/internal/vendors/codeartsweb"
)

// 从粘贴入口到宿主保存的整条路径：快照里即使是 POST 聊天请求，也只能发身份 GET。
func TestAccountAddCurlVerifiesIdentityWithoutReplayingCapturedRequest(t *testing.T) {
	capture := "curl 'https://devcloud.cn-north-4.huaweicloud.com/chat/codebaseservice/v1/cloudagent/sessions/captured/messages' \\\r\n" +
		" -X POST -H 'cftk: test-token' -H 'User-Agent: test-browser' \\\r\n" +
		" -H 'sec-ch-ua: test-brand' -H 'Authorization: Bearer must-not-forward' \\\r\n" +
		" -b 'webcftk=test-token; session=test-session' --data-raw '{\"content\":\"must-not-replay\"}'"
	for _, scenario := range []struct {
		name       string
		body       accountAddRequest
		identityOK bool
		wantStatus int
		wantHTTP   int
		wantSave   int
	}{
		{"成功保存", accountAddRequest{Vendor: "codeartsweb", CredentialCurl: capture}, true, 200, 1, 1},
		{"会话过期", accountAddRequest{Vendor: "codeartsweb", CredentialCurl: capture}, false, 400, 1, 0},
		{"非原站快照", accountAddRequest{Vendor: "codeartsweb", CredentialCurl: strings.Replace(capture, "devcloud.cn-north-4.huaweicloud.com", "example.com", 1)}, true, 400, 0, 0},
		{"缺少Cookie", accountAddRequest{Vendor: "codeartsweb", CredentialCurl: "curl 'https://devcloud.cn-north-4.huaweicloud.com/chat/home' -H 'cftk: test-token'"}, true, 400, 0, 0},
		{"拒绝附加命令", accountAddRequest{Vendor: "codeartsweb", CredentialCurl: capture + " ; unwanted-command"}, true, 400, 0, 0},
		{"不支持的渠道", accountAddRequest{Vendor: "plain", CredentialCurl: capture}, true, 400, 0, 0},
		{"拒绝混合输入", accountAddRequest{Vendor: "codeartsweb", CredentialCurl: capture, CredentialJSON: "{}"}, true, 400, 0, 0},
		{"拒绝混入APIKey", accountAddRequest{Vendor: "codeartsweb", CredentialCurl: capture, APIKey: "test-key"}, true, 400, 0, 0},
		{"拒绝过长快照", accountAddRequest{Vendor: "codeartsweb", CredentialCurl: "curl " + strings.Repeat("x", 256<<10)}, true, 400, 0, 0},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			deps := newStubDeps(t)
			vendor := codeartsweb.Instances(core.Env{})[0]
			if err := deps.registry.Register(vendor); err != nil {
				t.Fatal(err)
			}
			if err := deps.registry.Register(&fakeVendor{Meta: core.Meta{VendorID: "plain"}}); err != nil {
				t.Fatal(err)
			}
			service := newServiceWithDeps(t, deps)
			descriptors := service.buildVendorsPayload()["vendors"].([]vendorDescriptor)
			if !descriptors[0].CredentialCurlImport || !descriptors[0].CredentialImport || descriptors[0].SupportsLogin || descriptors[1].CredentialCurlImport {
				t.Fatal("供应商的快照导入和授权登录能力应分别声明")
			}
			httpCalls, saveCalls := 0, 0
			var saved pluginapi.HostAuthSaveRequest
			hostbridge.Configure(func(_ string, method string, payload any) (json.RawMessage, error) {
				raw, err := json.Marshal(payload)
				if err != nil {
					return nil, err
				}
				switch method {
				case pluginabi.MethodHostHTTPDo:
					httpCalls++
					var request struct {
						Method, URL string
						Headers     http.Header
						Body        []byte
					}
					if err := json.Unmarshal(raw, &request); err != nil {
						return nil, err
					}
					if request.Method != http.MethodGet || request.URL != "https://devcloud.cn-north-4.huaweicloud.com/chat/rest/me" || len(request.Body) != 0 {
						t.Fatal("导入快照只能通过固定身份接口验证，不能重放 URL、方法或正文")
					}
					if request.Headers.Get("Cookie") != "webcftk=test-token; session=test-session" || request.Headers.Get("cftk") != "test-token" || request.Headers.Get("User-Agent") != "test-browser" || request.Headers.Get("sec-ch-ua") != "test-brand" || request.Headers.Get("Authorization") != "" {
						t.Fatal("浏览器凭证未正确提取或转发了额外认证头")
					}
					status, identity := 401, []byte(`{"error":"expired"}`)
					if scenario.identityOK {
						status, identity = 200, []byte(`{"userId":"verified-user","userName":"Verified User"}`)
					}
					return json.Marshal(map[string]any{"status_code": status, "body": identity, "headers": http.Header{"Content-Type": {"application/json"}}})
				case pluginabi.MethodHostAuthList:
					return json.RawMessage(`[]`), nil
				case pluginabi.MethodHostAuthSave:
					saveCalls++
					return json.RawMessage(`{}`), json.Unmarshal(raw, &saved)
				default:
					return nil, fmt.Errorf("unexpected host method %s", method)
				}
			})
			t.Cleanup(func() { hostbridge.Configure(nil) })
			body, err := json.Marshal(scenario.body)
			if err != nil {
				t.Fatal(err)
			}
			response := service.handleAccountAddRequest(pluginapi.ManagementRequest{Method: http.MethodPost, Body: body})
			if response.StatusCode != scenario.wantStatus || httpCalls != scenario.wantHTTP || saveCalls != scenario.wantSave {
				t.Fatalf("status/http/save = %d/%d/%d, want %d/%d/%d", response.StatusCode, httpCalls, saveCalls, scenario.wantStatus, scenario.wantHTTP, scenario.wantSave)
			}
			if strings.Contains(string(response.Body), "test-session") || strings.Contains(string(response.Body), "must-not-replay") {
				t.Fatal("响应不能回显快照凭证或聊天正文")
			}
			if scenario.wantSave == 0 {
				return
			}
			var credential map[string]any
			if json.Unmarshal(saved.JSON, &credential) != nil || saved.Name != "codeartsweb-verified-user.json" || credential["vendor"] != "codeartsweb" || credential["type"] != "freetier" || credential["user_id"] != "verified-user" || credential["prefix"] != "codeartsweb" || credential["cookie"] != "webcftk=test-token; session=test-session" || credential["cftk"] != "test-token" {
				t.Fatal("必须保存校验后的网页凭证及正确路由归属")
			}
			if credential["curl"] != nil || strings.Contains(string(saved.JSON), "must-not-replay") || strings.Contains(string(saved.JSON), "must-not-forward") {
				t.Fatal("不能保存原始命令、聊天正文或无关认证头")
			}
		})
	}
}
