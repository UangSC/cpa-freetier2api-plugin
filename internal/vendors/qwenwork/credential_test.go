package qwenwork

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"freetier2api-plugin/internal/core"
)

const credentialTestExpiry int64 = 2_000_000_000

func credentialTestJWT(t *testing.T, overrides map[string]any) string {
	t.Helper()
	claims := map[string]any{
		"iss": "qwenwork.cn", "sub": "user-1", "user_id": "user-1", "aud": "biz",
		"biz_org_id": "org-1", "biz_team_id": "team-1", "exp": credentialTestExpiry,
	}
	for key, value := range overrides {
		claims[key] = value
	}
	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(data) + "." + base64.RawURLEncoding.EncodeToString([]byte("dummy-signature"))
}

func credentialTestJSON(t *testing.T, raw map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func credentialTestParse(t *testing.T, raw map[string]any) *Credential {
	t.Helper()
	if _, present := raw["token"]; !present {
		raw["token"] = credentialTestJWT(t, nil)
	}
	credential, err := ParseCredential(credentialTestJSON(t, raw))
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func TestCredentialAcceptsDesktopAndPluginJSON(t *testing.T) {
	token := credentialTestJWT(t, nil)
	for _, tc := range []struct {
		name string
		raw  map[string]any
	}{
		{"desktop-auth-v2", map[string]any{
			"token": token, "refreshToken": "synthetic-refresh", "oauthClientId": "desktop-client",
			"loginDeviceId": "desktop-device", "refreshStrategy": "oauth_web_identity",
			"expiresAt": time.Unix(credentialTestExpiry, 0).UTC().Format(time.RFC3339),
			"user":      map[string]any{"id": "user-1", "orgId": "org-1", "teamId": "team-1", "name": "Tester"},
			"endpoints": map[string]any{"protocol": "device-token", "authOrigin": gatewayOrigin, "apiOrigin": gatewayOrigin, "webIdentityApiOrigin": webOrigin},
		}},
		{"plugin-export", map[string]any{
			"type": core.ProviderKey, "vendor": vendorID, "access_token": "Bearer " + token,
			"refresh_token": "synthetic-refresh", "client_id": "desktop-client", "login_device_id": "desktop-device",
			"user_id": "user-1", "org_id": "org-1", "team_id": "team-1", "label": "Tester",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			credential, err := ParseCredential(credentialTestJSON(t, tc.raw))
			if err != nil {
				t.Fatal(err)
			}
			if credential.Token != token || credential.RefreshToken != "synthetic-refresh" || credential.ClientID != "desktop-client" || credential.LoginDeviceID != "desktop-device" {
				t.Fatal("桌面与插件字段未归一化")
			}
			if credential.UserID != "user-1" || credential.OrgID != "org-1" || credential.TeamID != "team-1" || credential.Label != "Tester" {
				t.Fatal("登录身份或展示名未正确读取")
			}
			if credential.ExpiresAt != credentialTestExpiry || credential.AuthOrigin != gatewayOrigin || credential.APIOrigin != gatewayOrigin || credential.WebIdentityOrigin != webOrigin {
				t.Fatal("默认端点或 JWT 到期时间不一致")
			}
		})
	}
}

func TestCredentialRejectsConflictingIdentity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		raw    map[string]any
		claims map[string]any
	}{
		{"flat-user", map[string]any{"user_id": "different"}, nil},
		{"flat-org", map[string]any{"org_id": "different"}, nil},
		{"flat-team", map[string]any{"team_id": "different"}, nil},
		{"nested-user", map[string]any{"user": map[string]any{"id": "different"}}, nil},
		{"flat-and-nested-user", map[string]any{"user_id": "user-1", "user": map[string]any{"id": "different"}}, nil},
		{"flat-and-nested-org", map[string]any{"org_id": "org-1", "user": map[string]any{"orgId": "different"}}, nil},
		{"flat-and-nested-team", map[string]any{"team_id": "team-1", "user": map[string]any{"teamId": "different"}}, nil},
		{"JWT-user-and-sub", map[string]any{}, map[string]any{"sub": "different"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.raw["token"] = credentialTestJWT(t, tc.claims)
			if _, err := ParseCredential(credentialTestJSON(t, tc.raw)); err == nil {
				t.Fatal("矛盾身份必须拒绝，不能只检查优先选中的一个字段")
			}
		})
	}
}

func TestCredentialRejectsForeignProviderDeclarations(t *testing.T) {
	for _, marker := range []string{"vendor", "type", "provider"} {
		t.Run(marker, func(t *testing.T) {
			raw := map[string]any{"token": credentialTestJWT(t, nil), marker: "other-provider"}
			if _, err := ParseCredential(credentialTestJSON(t, raw)); err == nil {
				t.Fatal("明确属于外部供应商的 JSON 不能改写为千问办公凭证")
			}
		})
	}
}

func TestCredentialMatchDoesNotClaimOtherProviders(t *testing.T) {
	v := Instances(core.Env{})[0]
	token := credentialTestJWT(t, nil)
	for _, tc := range []struct {
		name, fileName, provider string
		raw                      map[string]any
		want                     bool
	}{
		{"desktop-token", "desktop.json", "", map[string]any{"token": token}, true},
		{"plugin", "qwenwork-user-1.json", core.ProviderKey, map[string]any{"type": core.ProviderKey, "vendor": vendorID}, true},
		{"foreign-host-provider", "qwenwork-user.json", "codex", map[string]any{"vendor": vendorID, "token": token}, false},
		{"foreign-vendor-with-matching-filename", "qwenwork-user.json", "", map[string]any{"vendor": "qoder", "token": token}, false},
		{"foreign-type", "desktop.json", "", map[string]any{"type": "codex", "token": token}, false},
		{"foreign-provider-field", "desktop.json", "", map[string]any{"provider": "openai", "token": token}, false},
		{"foreign-issuer", "desktop.json", "", map[string]any{"token": credentialTestJWT(t, map[string]any{"iss": "qoder.cn"})}, false},
		{"missing-evidence", "random.json", "", map[string]any{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := v.Match(tc.fileName, tc.provider, tc.raw); got != tc.want {
				t.Fatalf("Match = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCredentialExpiryIsBoundedByJWT(t *testing.T) {
	for _, tc := range []struct {
		name, key string
		value     any
		want      int64
	}{
		{"JWT-only", "", nil, credentialTestExpiry},
		{"numeric-extension", "expires_at", credentialTestExpiry + 3600, credentialTestExpiry},
		{"numeric-shortening", "expires_at", credentialTestExpiry - 3600, credentialTestExpiry - 3600},
		{"RFC3339-extension", "expires_at", time.Unix(credentialTestExpiry+3600, 0).UTC().Format(time.RFC3339), credentialTestExpiry},
		{"desktop-extension", "expiresAt", time.Unix(credentialTestExpiry+3600, 0).UTC().Format(time.RFC3339), credentialTestExpiry},
		{"desktop-shortening", "expiresAt", time.Unix(credentialTestExpiry-3600, 0).UTC().Format(time.RFC3339), credentialTestExpiry - 3600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := map[string]any{}
			if tc.key != "" {
				raw[tc.key] = tc.value
			}
			credential := credentialTestParse(t, raw)
			if credential.ExpiresAt != tc.want {
				t.Fatalf("expiry = %d, want %d", credential.ExpiresAt, tc.want)
			}
		})
	}
}

func TestCredentialAllowsOnlyExactOfficialOrigins(t *testing.T) {
	for _, field := range []string{"authOrigin", "apiOrigin", "webIdentityApiOrigin"} {
		for _, origin := range []string{webOrigin, gatewayOrigin} {
			t.Run(field+"-"+origin, func(t *testing.T) {
				credentialTestParse(t, map[string]any{"endpoints": map[string]any{field: origin}})
			})
		}
		for _, origin := range []string{"http://qwenwork.cn", "https://qwenwork.cn.evil.test", "https://qwenwork.cn/", "https://qwenwork.cn/path", "https://qwenwork.cn?token=synthetic-secret", "https://user@qwenwork.cn", "https://localhost"} {
			t.Run(field+"-reject-"+origin, func(t *testing.T) {
				raw := map[string]any{"token": credentialTestJWT(t, nil), "endpoints": map[string]any{field: origin}}
				_, err := ParseCredential(credentialTestJSON(t, raw))
				if err == nil {
					t.Fatal("非精确官方 origin 必须拒绝")
				}
				if strings.Contains(err.Error(), "synthetic-secret") {
					t.Fatal("端点校验不能回显潜在秘密")
				}
			})
		}
	}
}

func TestCredentialErrorsDoNotEchoInvalidTokens(t *testing.T) {
	for _, data := range [][]byte{nil, []byte("null"), []byte("[]"), []byte("{}"), []byte(`{"token":"synthetic-secret`), []byte(`{"token":"synthetic-secret"}`)} {
		_, err := ParseCredential(data)
		if err == nil {
			t.Fatal("空、非法 JSON 或非法 JWT 必须拒绝")
		}
		if strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatal("错误内容不能包含凭证输入")
		}
	}
	var empty *Credential
	if _, err := empty.StorageJSON(); err == nil {
		t.Fatal("空凭证不能序列化")
	}
}

func TestCredentialStorageClonesRawAndUpdatesTokenAliases(t *testing.T) {
	oldToken := credentialTestJWT(t, nil)
	credential := credentialTestParse(t, map[string]any{
		"token": oldToken, "access_token": oldToken, "accessToken": oldToken, "refreshToken": "old-refresh",
		"expiresAt": time.Unix(credentialTestExpiry, 0).UTC().Format(time.RFC3339),
		"disabled":  true, "proxy_url": "http://proxy.invalid", "note": "keep-note", "updated_at": "2026-11-15T10:00:00Z",
		"custom":    map[string]any{"items": []any{map[string]any{"value": "original"}}},
		"endpoints": map[string]any{"authOrigin": webOrigin},
	})
	before := credentialTestJSON(t, credential.Raw)
	credential.Token = credentialTestJWT(t, map[string]any{"exp": credentialTestExpiry + 7200})
	credential.RefreshToken, credential.ExpiresAt = "new-refresh", credentialTestExpiry+7200
	storage, err := credential.StorageJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, credentialTestJSON(t, credential.Raw)) {
		t.Fatal("序列化修改了正在使用的原始凭证快照")
	}
	var raw map[string]any
	if err := json.Unmarshal(storage, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["type"] != core.ProviderKey || raw["vendor"] != vendorID || raw["token"] != credential.Token || raw["access_token"] != credential.Token || raw["accessToken"] != credential.Token || raw["refreshToken"] != "new-refresh" {
		t.Fatal("凭证归属或桌面令牌别名未同步更新")
	}
	if raw["expiresAt"] != time.Unix(credential.ExpiresAt, 0).UTC().Format(time.RFC3339) || int64(raw["expires_at"].(float64)) != credential.ExpiresAt {
		t.Fatal("两种到期字段必须同步")
	}
	for _, key := range []string{"disabled", "proxy_url", "note", "updated_at", "custom"} {
		if !reflect.DeepEqual(raw[key], credential.Raw[key]) {
			t.Fatalf("序列化丢失用户字段 %s", key)
		}
	}
	mapIn(raw, "custom")["items"].([]any)[0].(map[string]any)["value"] = "changed"
	mapIn(raw, "endpoints")["authOrigin"] = "changed"
	if !bytes.Equal(before, credentialTestJSON(t, credential.Raw)) {
		t.Fatal("导出 JSON 与原始快照存在嵌套引用共享")
	}
}

func TestCredentialMergePreservesLatestUserSettings(t *testing.T) {
	credential := credentialTestParse(t, map[string]any{
		"disabled": false, "proxy_url": "http://old.invalid", "note": "old-note", "updated_at": "2026-11-14T10:00:00Z",
	})
	credential.Token = credentialTestJWT(t, map[string]any{"exp": credentialTestExpiry + 7200})
	credential.ExpiresAt = credentialTestExpiry + 7200
	original := map[string]any{
		"type": core.ProviderKey, "vendor": vendorID, "disabled": true, "proxy_url": "http://new.invalid",
		"note": "new-note", "updated_at": "2026-11-15T10:00:00Z", "prefix": "custom-prefix", "weight": 3,
	}
	merged, err := mergeStorage(credentialTestJSON(t, original), credential)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(merged, &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"disabled", "proxy_url", "note", "updated_at", "prefix"} {
		if !reflect.DeepEqual(got[key], original[key]) {
			t.Fatalf("刷新快照覆盖了原文件中较新的用户字段 %s", key)
		}
	}
	if got["token"] != credential.Token || int64(got["expires_at"].(float64)) != credential.ExpiresAt {
		t.Fatal("保存用户设置时仍须更新登录凭证")
	}
}

func TestCredentialMergePreservesFieldsOutsideAuthSnapshot(t *testing.T) {
	credential := credentialTestParse(t, map[string]any{})
	original := map[string]any{"disabled": true, "proxy_url": "http://proxy.invalid", "note": map[string]any{"value": "retain"}, "modified_at": "2026-11-15T10:00:00Z"}
	merged, err := mergeStorage(credentialTestJSON(t, original), credential)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(merged, &got); err != nil {
		t.Fatal(err)
	}
	for key, value := range original {
		if !reflect.DeepEqual(got[key], value) {
			t.Fatalf("保存丢失原始字段 %s", key)
		}
	}
}

func TestCredentialMergeRejectsInvalidOriginalJSON(t *testing.T) {
	credential := credentialTestParse(t, map[string]any{})
	for _, original := range [][]byte{[]byte("{"), []byte("null"), []byte("[]")} {
		if _, err := mergeStorage(original, credential); err == nil {
			t.Fatal("合并不能把不可解析的原文件当空对象覆盖，避免丢失用户字段")
		}
	}
}
