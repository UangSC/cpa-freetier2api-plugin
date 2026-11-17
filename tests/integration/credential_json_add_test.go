package tests

// credential_json 添加通道：AutoClaw 国际版 token 对凭证（无 api_key 形态）
// 经 /accounts/add 的 credential_json 字段落盘，归属由服务端补齐。

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"freetier2api-plugin/cpasdk/pluginabi"
	"freetier2api-plugin/cpasdk/pluginapi"
	"freetier2api-plugin/internal/hostbridge"
)

func TestAccountAddCredentialJSONAutoClawGlobal(t *testing.T) {
	host := installFakeHost(t)
	var saved pluginapi.HostAuthSaveRequest
	hostbridge.Configure(func(callbackID, method string, payload any) (json.RawMessage, error) {
		if method == pluginabi.MethodHostAuthSave {
			if err := json.Unmarshal(mustMarshal(payload), &saved); err != nil {
				t.Fatalf("解析假宿主凭证写入请求：%v", err)
			}
		}
		return host.call(callbackID, method, payload)
	})
	setupTestPlugin(t)

	credential := map[string]any{
		"accessToken":  "at-test-123",
		"refreshToken": "rt-test-456",
		"region":       "global",
	}
	encoded, _ := json.Marshal(credential)

	response := managementCallWithBody(t, "POST", "/accounts/add", map[string]any{
		"vendor":          "autoclawglobal",
		"credential_json": string(encoded),
		"label":           "intl-test",
	})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("/accounts/add = %d: %s", response.StatusCode, response.Body)
	}
	var payload struct {
		OK      bool   `json:"ok"`
		AuthID  string `json:"auth_id"`
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	if errUnmarshal := json.Unmarshal(response.Body, &payload); errUnmarshal != nil {
		t.Fatalf("decode response: %v (%s)", errUnmarshal, response.Body)
	}
	if !payload.OK {
		t.Fatalf("add failed: %s", response.Body)
	}
	if !strings.HasPrefix(payload.AuthID, "autoclawglobal-") {
		t.Fatalf("auth file name = %q, want autoclawglobal-*", payload.AuthID)
	}
	if saved.Name != payload.AuthID || !json.Valid(saved.JSON) {
		t.Fatalf("凭证应保存至假宿主：name=%q", saved.Name)
	}
	var stored map[string]any
	if err := json.Unmarshal(saved.JSON, &stored); err != nil || stored["vendor"] != "autoclawglobal" || stored["accessToken"] != credential["accessToken"] {
		t.Fatal("假宿主未收到完整且归属正确的凭证")
	}
}

func TestAccountAddCredentialJSONRejectsMalformed(t *testing.T) {
	installFakeHost(t)
	setupTestPlugin(t)

	response := managementCallWithBody(t, "POST", "/accounts/add", map[string]any{
		"vendor":          "autoclawglobal",
		"credential_json": "not-an-object",
	})
	// 通道必须拒绝畸形 JSON（400 参数错误），而不是落盘一个坏文件。
	if response.StatusCode == http.StatusOK {
		var payload struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		_ = json.Unmarshal(response.Body, &payload)
		if payload.OK {
			t.Fatalf("malformed credential_json should not be accepted: %s", response.Body)
		}
		if !strings.Contains(string(response.Body), "JSON") {
			t.Fatalf("unexpected rejection reason: %s", response.Body)
		}
	}
}
