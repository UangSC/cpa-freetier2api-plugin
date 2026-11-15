package qwenwork

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"freetier2api-plugin/internal/core"
)

const (
	vendorID      = "qwenwork"
	webOrigin     = "https://qwenwork.cn"
	gatewayOrigin = "https://gateway.qwenwork.cn"
)

// Credential 是千问办公的登录快照。续期返回新对象，不修改正在使用的快照。
type Credential struct {
	Token, RefreshToken, UserID, OrgID, TeamID, Label  string
	RefreshStrategy, Protocol, ClientID, LoginDeviceID string
	AuthOrigin, APIOrigin, WebIdentityOrigin           string
	ExpiresAt                                          int64
	Raw                                                map[string]any
}

func stringIn(raw map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := raw[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func mapIn(raw map[string]any, key string) map[string]any {
	value, _ := raw[key].(map[string]any)
	return value
}

func tokenClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("千问办公凭证必须包含有效的登录 JWT")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("千问办公登录 JWT 格式无效")
	}
	var claims map[string]any
	if json.Unmarshal(decoded, &claims) != nil || stringIn(claims, "iss") != "qwenwork.cn" {
		return nil, fmt.Errorf("凭证不属于千问办公国内站")
	}
	return claims, nil
}

// ParseCredential 同时接受解密后的桌面 auth-v2 JSON 与插件导出的凭证 JSON。
// JWT 解析只用于归属与身份一致性检查，服务端请求才验证其签名和有效性。
func ParseCredential(data []byte) (*Credential, error) {
	var raw map[string]any
	if json.Unmarshal(data, &raw) != nil || raw == nil {
		return nil, fmt.Errorf("千问办公凭证必须是 JSON 对象")
	}
	if declared := stringIn(raw, "vendor"); declared != "" && declared != vendorID {
		return nil, fmt.Errorf("凭证供应商不是千问办公")
	}
	for _, key := range []string{"type", "provider"} {
		if declared := stringIn(raw, key); declared != "" && declared != core.ProviderKey {
			return nil, fmt.Errorf("千问办公插件凭证的 type/provider 必须为 freetier")
		}
	}
	token := stringIn(raw, "token", "access_token", "accessToken")
	token = strings.TrimSpace(strings.TrimPrefix(token, "Bearer "))
	if token == "" {
		return nil, fmt.Errorf("千问办公凭证缺少访问令牌")
	}
	claims, err := tokenClaims(token)
	if err != nil {
		return nil, err
	}
	user := mapIn(raw, "user")
	endpoints := mapIn(raw, "endpoints")
	credential := &Credential{
		Token: token, RefreshToken: stringIn(raw, "refresh_token", "refreshToken"),
		UserID:            core.FirstNonEmpty(stringIn(raw, "user_id", "userId"), stringIn(user, "id", "user_id"), stringIn(claims, "user_id", "sub")),
		OrgID:             core.FirstNonEmpty(stringIn(raw, "org_id", "orgId"), stringIn(user, "orgId", "org_id"), stringIn(claims, "biz_org_id")),
		TeamID:            core.FirstNonEmpty(stringIn(raw, "team_id", "teamId"), stringIn(user, "teamId", "team_id"), stringIn(claims, "biz_team_id")),
		Label:             core.FirstNonEmpty(stringIn(raw, "label", "name"), stringIn(user, "name", "nickname", "email")),
		RefreshStrategy:   core.FirstNonEmpty(stringIn(raw, "refresh_strategy", "refreshStrategy"), "oauth_web_identity"),
		Protocol:          core.FirstNonEmpty(stringIn(raw, "protocol"), stringIn(endpoints, "protocol"), "device-token"),
		ClientID:          core.FirstNonEmpty(stringIn(raw, "client_id", "clientId", "oauthClientId"), stringIn(endpoints, "clientId", "client_id")),
		LoginDeviceID:     stringIn(raw, "login_device_id", "loginDeviceId"),
		AuthOrigin:        core.FirstNonEmpty(stringIn(endpoints, "authOrigin", "auth_origin"), gatewayOrigin),
		APIOrigin:         core.FirstNonEmpty(stringIn(endpoints, "apiOrigin", "api_origin"), gatewayOrigin),
		WebIdentityOrigin: core.FirstNonEmpty(stringIn(endpoints, "webIdentityApiOrigin", "web_identity_api_origin"), webOrigin),
		Raw:               raw,
	}
	for _, origin := range []string{credential.AuthOrigin, credential.APIOrigin, credential.WebIdentityOrigin} {
		if origin != webOrigin && origin != gatewayOrigin {
			return nil, fmt.Errorf("仅支持千问办公官方国内站的凭证")
		}
	}
	if credential.UserID == "" {
		return nil, fmt.Errorf("千问办公凭证缺少用户身份")
	}
	if actual := stringIn(claims, "user_id", "sub"); actual != credential.UserID {
		return nil, fmt.Errorf("千问办公凭证的用户身份不一致")
	}
	identities := []struct {
		raw      map[string]any
		keys     []string
		expected string
	}{
		{raw, []string{"user_id", "userId"}, credential.UserID},
		{user, []string{"id", "user_id"}, credential.UserID},
		{claims, []string{"user_id", "sub"}, credential.UserID},
		{raw, []string{"org_id", "orgId"}, credential.OrgID},
		{user, []string{"orgId", "org_id"}, credential.OrgID},
		{raw, []string{"team_id", "teamId"}, credential.TeamID},
		{user, []string{"teamId", "team_id"}, credential.TeamID},
	}
	for _, identity := range identities {
		for _, key := range identity.keys {
			if actual := stringIn(identity.raw, key); actual != "" && actual != identity.expected {
				return nil, fmt.Errorf("千问办公凭证中存在矛盾的用户或企业身份")
			}
		}
	}
	for key, expected := range map[string]string{"user_id": credential.UserID, "biz_org_id": credential.OrgID, "biz_team_id": credential.TeamID} {
		if actual := stringIn(claims, key); actual != "" && expected != actual {
			return nil, fmt.Errorf("千问办公凭证的用户或企业身份不一致")
		}
	}
	credential.ExpiresAt = int64(core.IntFromAny(claims["exp"]))
	if value := stringIn(raw, "expires_at", "expiresAt"); value != "" {
		if parsed, err := time.Parse(time.RFC3339, value); err == nil && (credential.ExpiresAt <= 0 || parsed.Unix() < credential.ExpiresAt) {
			credential.ExpiresAt = parsed.Unix()
		}
	} else if value := core.IntFromAny(raw["expires_at"]); value > 0 && (credential.ExpiresAt <= 0 || int64(value) < credential.ExpiresAt) {
		credential.ExpiresAt = int64(value)
	}
	if credential.Label == "" {
		credential.Label = credential.UserID
	}
	return credential, nil
}

func cloneJSON(raw map[string]any) map[string]any {
	data, _ := json.Marshal(raw)
	var copied map[string]any
	_ = json.Unmarshal(data, &copied)
	if copied == nil {
		copied = make(map[string]any)
	}
	return copied
}

func (credential *Credential) StorageJSON() ([]byte, error) {
	if credential == nil {
		return nil, fmt.Errorf("千问办公凭证为空")
	}
	raw := cloneJSON(credential.Raw)
	raw["type"], raw["vendor"] = core.ProviderKey, vendorID
	raw["token"], raw["refresh_token"] = credential.Token, credential.RefreshToken
	raw["user_id"], raw["org_id"], raw["team_id"] = credential.UserID, credential.OrgID, credential.TeamID
	raw["label"], raw["expires_at"] = credential.Label, credential.ExpiresAt
	raw["refresh_strategy"], raw["protocol"] = credential.RefreshStrategy, credential.Protocol
	raw["client_id"], raw["login_device_id"] = credential.ClientID, credential.LoginDeviceID
	if _, exists := raw["access_token"]; exists {
		raw["access_token"] = credential.Token
	}
	if _, exists := raw["accessToken"]; exists {
		raw["accessToken"] = credential.Token
	}
	if _, exists := raw["refreshToken"]; exists {
		raw["refreshToken"] = credential.RefreshToken
	}
	if _, exists := raw["expiresAt"]; exists {
		raw["expiresAt"] = time.Unix(credential.ExpiresAt, 0).UTC().Format(time.RFC3339)
	}
	endpoints := cloneJSON(mapIn(raw, "endpoints"))
	endpoints["authOrigin"], endpoints["apiOrigin"] = credential.AuthOrigin, credential.APIOrigin
	endpoints["webIdentityApiOrigin"] = credential.WebIdentityOrigin
	raw["endpoints"] = endpoints
	return json.Marshal(raw)
}

func mergeStorage(original []byte, credential *Credential) ([]byte, error) {
	data, err := credential.StorageJSON()
	if err != nil {
		return nil, err
	}
	var existing, updates map[string]any
	if len(original) == 0 {
		return data, nil
	}
	if json.Unmarshal(original, &existing) != nil || existing == nil {
		return nil, fmt.Errorf("原始千问办公凭证不是有效 JSON 对象")
	}
	if declared := stringIn(existing, "vendor"); declared != "" && declared != vendorID {
		return nil, fmt.Errorf("不能将千问办公令牌写入其他供应商的凭证")
	}
	if err := json.Unmarshal(data, &updates); err != nil {
		return nil, err
	}
	// 只更新供应商管理的身份字段，保留宿主在续期期间修改的禁用、代理、备注等设置。
	ownedKeys := []string{"type", "vendor", "token", "access_token", "accessToken", "refresh_token", "refreshToken",
		"expires_at", "expiresAt", "user_id", "org_id", "team_id", "endpoints", "protocol", "client_id", "oauthClientId",
		"refresh_strategy", "refreshStrategy", "login_device_id", "loginDeviceId", "oauthRedirectUri"}
	for _, key := range ownedKeys {
		if value, ok := updates[key]; ok {
			existing[key] = value
		}
	}
	if _, exists := existing["label"]; !exists {
		existing["label"] = credential.Label
	}
	return json.Marshal(existing)
}
