package qwenwork

// 千问办公 PC 2.1.0 当前默认使用 device/selectAccounts + PKCE 轮询。
// native OAuth 的 newLoginEnabled 为 false，不能把新 OAuth 端点当作默认登录入口。
// 授权入口在 gateway.qwenwork.cn；网关将设备授权桥接到网页登录页面。
// qwenwork.cn 的同名 device 路由返回 404，不能把网页登录源当作设备授权源。
// 上游完成账号选择后插件自动轮询取票，凭证由宿主保存，无需劫持 PC 深链。

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"freetier2api-plugin/cpasdk/pluginapi"
	"freetier2api-plugin/internal/core"
	"freetier2api-plugin/internal/hostbridge"
)

const (
	deviceClientID     = "e883ade2-e6e3-4d6d-adf7-f92ceff5fdcb"
	deviceRedirectURI  = "qwenwork-cn://"
	loginTTL           = 5 * time.Minute
	loginPollGap       = 1500 * time.Millisecond
	loginHTTPTimeout   = 30 * time.Second
	loginResponseLimit = 2 * 1024 * 1024
)

type pendingDeviceLogin struct {
	mu                                            sync.Mutex
	nonce, verifier, challenge, machineID         string
	expectedUserID, expectedOrgID, expectedTeamID string
	completed                                     *pluginapi.AuthLoginPollResponse
}

func randomLoginID(uuid bool) (string, error) {
	data := make([]byte, 32)
	if uuid {
		data = data[:16]
	}
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("生成千问登录随机参数失败")
	}
	if !uuid {
		return hex.EncodeToString(data), nil
	}
	data[6], data[8] = (data[6]&15)|64, (data[8]&63)|128
	return fmt.Sprintf("%x-%x-%x-%x-%x", data[:4], data[4:6], data[6:8], data[8:10], data[10:]), nil
}

func (v *adapter) AuthMode() string { return "oauth" }

func (v *adapter) CredentialImportHint() string {
	return "可粘贴千问办公已登录账号的凭证 JSON（桌面 auth-v2 解密导出或本插件导出，包含访问令牌、用户及企业身份；可选刷新令牌）。凭证仅发送给千问办公官方站。"
}

func (v *adapter) LoginStart(_ context.Context, metadata map[string]any) (*pluginapi.AuthLoginStartResponse, error) {
	if v.Env.Logins == nil {
		return nil, fmt.Errorf("千问登录会话服务未初始化")
	}
	verifier, challenge, err := core.NewPKCEPair()
	if err != nil {
		return nil, fmt.Errorf("生成千问登录 PKCE 参数失败")
	}
	state, err := randomLoginID(false)
	if err != nil {
		return nil, err
	}
	nonce, err := randomLoginID(true)
	if err != nil {
		return nil, err
	}
	machineID, err := randomLoginID(true)
	if err != nil {
		return nil, err
	}
	pending := &pendingDeviceLogin{nonce: nonce, verifier: verifier, challenge: challenge, machineID: machineID,
		expectedUserID: stringIn(metadata, "user_id"), expectedOrgID: stringIn(metadata, "org_id"), expectedTeamID: stringIn(metadata, "team_id")}
	query := url.Values{"challenge": {challenge}, "challenge_method": {"S256"}, "nonce": {nonce},
		"machine_id": {machineID}, "client_id": {deviceClientID}, "redirect_uri": {deviceRedirectURI}}
	v.Env.Logins.Register(vendorID, state, loginTTL, loginPollGap, pending)
	return &pluginapi.AuthLoginStartResponse{Provider: core.ProviderKey, URL: gatewayOrigin + "/device/selectAccounts?" + query.Encode(),
		State: state, ExpiresAt: time.Now().Add(loginTTL), Metadata: map[string]any{core.VendorKey: vendorID, "region": "cn"}}, nil
}

func (v *adapter) LoginPoll(ctx context.Context, state string) (*pluginapi.AuthLoginPollResponse, error) {
	if v.Env.Logins == nil {
		return loginFailed("千问登录会话服务未初始化"), nil
	}
	session, pollState := v.Env.Logins.Poll(state)
	if pollState == core.PollMissing || session == nil || session.VendorID != vendorID {
		return loginFailed("登录会话不存在或已过期，请重新登录"), nil
	}
	if pollState == core.PollThrottled {
		return &pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusPending}, nil
	}
	pending, ok := session.Data.(*pendingDeviceLogin)
	if !ok {
		return loginFailed("登录会话无效，请重新登录"), nil
	}
	pending.mu.Lock()
	defer pending.mu.Unlock()
	if pending.completed != nil {
		return pending.completed, nil
	}
	query := url.Values{"nonce": {pending.nonce}, "verifier": {pending.verifier}, "challenge_method": {"S256"}}
	data, _, err := loginRequest(ctx, http.MethodGet, gatewayOrigin+"/api/v1/deviceToken/poll?"+query.Encode(), "", nil, "")
	if err != nil {
		status := loginErrorStatus(err)
		if status == http.StatusNotFound || status == http.StatusTooManyRequests || status >= 500 {
			return &pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusPending, Message: "等待浏览器授权；暂时未取到登录结果"}, nil
		}
		return loginFailed(err.Error()), nil
	}
	if stringIn(data, "nonce") != pending.nonce || stringIn(data, "code_challenge") != pending.challenge || stringIn(data, "code_challenge_method") != "S256" {
		return loginFailed("登录响应与本次 PKCE 会话不匹配，请重新登录"), nil
	}
	token, refresh := stringIn(data, "token", "device_token"), stringIn(data, "refresh_token")
	if token == "" || refresh == "" {
		return loginFailed("千问登录响应缺少令牌，请重新登录"), nil
	}
	profile, _, err := loginRequest(ctx, http.MethodGet, gatewayOrigin+"/api/v1/userinfo", token, nil, "")
	if err != nil {
		return loginFailed("千问登录身份验证未完成，请重新登录"), nil
	}
	identity, err := loginProfileIdentity(profile)
	if err != nil {
		return loginFailed(err.Error()), nil
	}
	if (pending.expectedUserID != "" && pending.expectedUserID != identity.UserID) ||
		(pending.expectedOrgID != "" && pending.expectedOrgID != identity.OrgID) ||
		(pending.expectedTeamID != "" && pending.expectedTeamID != identity.TeamID) {
		return loginFailed("浏览器选择的账号或企业与本次登录目标不一致"), nil
	}
	// 旧设备授权可能返回 opaque 设备票。PC 的 OAuthSessionExchangeClient
	// 通过网页登录会话端点把它换为 JWT；企业账号随后恢复用户在授权页选中的团队。
	token, expiresAt, err := loginWebCredential(ctx, token, data, identity)
	if err != nil {
		return loginFailed(err.Error()), nil
	}
	raw := map[string]any{"type": core.ProviderKey, "vendor": vendorID, "token": token, "refresh_token": refresh,
		"user_id": identity.UserID, "org_id": identity.OrgID, "team_id": identity.TeamID, "label": identity.Label,
		"expires_at": expiresAt, "refresh_strategy": "oauth_web_identity", "protocol": "device-token", "client_id": deviceClientID,
		"login_device_id": pending.machineID, "oauthRedirectUri": deviceRedirectURI,
		"endpoints": map[string]any{"authOrigin": gatewayOrigin, "apiOrigin": gatewayOrigin, "webIdentityApiOrigin": webOrigin}}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return loginFailed("无法生成千问登录凭证"), nil
	}
	credential, err := ParseCredential(encoded)
	if err != nil {
		return loginFailed(err.Error()), nil
	}
	if err := verifyLoginIdentity(ctx, credential, token); err != nil {
		return loginFailed(err.Error()), nil
	}
	storage, err := credential.StorageJSON()
	if err != nil {
		return loginFailed("无法生成千问登录凭证"), nil
	}
	fileName := loginFileName(credential)
	pending.completed = &pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusSuccess, Message: "浏览器授权成功，账号已自动保存",
		Auth: pluginapi.AuthData{Provider: core.ProviderKey, ID: strings.TrimSuffix(fileName, ".json"), FileName: fileName,
			Label: credential.Label, StorageJSON: storage}}
	return pending.completed, nil
}

func loginFailed(message string) *pluginapi.AuthLoginPollResponse {
	return &pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusError, Message: message}
}

// RefreshCredential 返回不可变快照。一次性刷新票据的请求只发送一次：
// 响应不明确或轮换后企业身份恢复失败时，要求重新登录，避免重复使用旧刷新票据。
func RefreshCredential(ctx context.Context, credential *Credential) (*Credential, bool, error) {
	if credential == nil {
		return nil, false, loginFailure(http.StatusUnauthorized, "千问办公凭证为空")
	}
	if credential.ExpiresAt > time.Now().Add(5*time.Minute).Unix() {
		return credential, false, nil
	}
	if credential.RefreshToken == "" {
		return nil, false, loginFailure(http.StatusUnauthorized, "千问登录已过期，缺少刷新令牌，请重新登录")
	}
	if err := validateLoginOrigins(credential); err != nil {
		return nil, false, err
	}
	var data map[string]any
	var err error
	switch credential.Protocol {
	case "", "device-token":
		body := map[string]any{"refresh_token": credential.RefreshToken}
		redirectURI := stringIn(credential.Raw, "oauthRedirectUri", "redirect_uri")
		if credential.ClientID != "" && redirectURI != "" {
			body["client_id"], body["redirect_uri"] = credential.ClientID, redirectURI
		}
		data, _, err = loginRequest(ctx, http.MethodPost, core.FirstNonEmpty(credential.APIOrigin, gatewayOrigin)+"/api/v1/deviceToken/refresh", "", body, "")
	case "native-oauth-iam-business", "native-oauth":
		if credential.ClientID == "" {
			return nil, false, loginFailure(http.StatusUnauthorized, "原 OAuth 客户端标识缺失，请重新登录")
		}
		form := url.Values{"grant_type": {"refresh_token"}, "client_id": {credential.ClientID}, "refresh_token": {credential.RefreshToken}}
		data, _, err = loginRequest(ctx, http.MethodPost, webOrigin+"/auth/oauth/token", "", form.Encode(), "application/x-www-form-urlencoded")
	default:
		return nil, false, loginFailure(http.StatusUnauthorized, "不支持该千问凭证的刷新协议，请重新登录")
	}
	if err != nil {
		return nil, false, loginFailure(http.StatusUnauthorized, "千问刷新结果未确认，请重新登录；不会重复提交旧刷新令牌")
	}
	token, refresh := stringIn(data, "access_token", "device_token", "token"), stringIn(data, "refresh_token")
	expiresAt, err := loginExpiry(data, token)
	if err != nil || token == "" || refresh == "" {
		return nil, false, loginFailure(http.StatusUnauthorized, "千问刷新响应不完整，请重新登录")
	}
	if _, claimsErr := tokenClaims(token); claimsErr != nil {
		token, expiresAt, err = exchangeLoginWebCredential(ctx, token)
		if err != nil {
			return nil, false, loginFailure(http.StatusUnauthorized, "刷新后网页登录凭证交换失败，请重新登录")
		}
	}
	if credential.OrgID != "" || credential.TeamID != "" {
		if credential.OrgID == "" || credential.TeamID == "" {
			return nil, false, loginFailure(http.StatusUnauthorized, "企业身份信息不完整，请重新登录")
		}
		_, responseHeaders, switchErr := loginRequest(ctx, http.MethodPost, core.FirstNonEmpty(credential.WebIdentityOrigin, webOrigin)+"/biz/user/v1/auth/switch-team", token,
			map[string]any{"team_id": credential.TeamID, "user_id": credential.UserID}, "")
		if switchErr != nil {
			return nil, false, loginFailure(http.StatusUnauthorized, "刷新后恢复企业身份失败，请重新登录")
		}
		token, err = loginCookieToken(responseHeaders)
		if err != nil {
			return nil, false, err
		}
		expiresAt, err = loginExpiry(nil, token)
		if err != nil {
			return nil, false, err
		}
	}
	updated := *credential
	updated.Raw = cloneJSON(credential.Raw)
	updated.Token, updated.RefreshToken, updated.ExpiresAt = token, refresh, expiresAt
	if err := verifyLoginIdentity(ctx, &updated, token); err != nil {
		return nil, false, loginFailure(http.StatusUnauthorized, "刷新后的用户或企业身份验证失败，请重新登录")
	}
	storage, err := updated.StorageJSON()
	if err != nil {
		return nil, false, loginFailure(http.StatusUnauthorized, "刷新后的登录凭证无法保存，请重新登录")
	}
	if _, err := ParseCredential(storage); err != nil {
		return nil, false, loginFailure(http.StatusUnauthorized, "刷新后的登录凭证身份不一致，请重新登录")
	}
	return &updated, token != credential.Token || refresh != credential.RefreshToken || expiresAt != credential.ExpiresAt, nil
}

func validateLoginOrigins(credential *Credential) error {
	for _, origin := range []string{credential.AuthOrigin, credential.APIOrigin, credential.WebIdentityOrigin} {
		if origin != "" && origin != webOrigin && origin != gatewayOrigin {
			return loginFailure(http.StatusBadRequest, "仅允许向千问办公官方国内站发送登录凭证")
		}
	}
	return nil
}

type loginIdentity struct{ UserID, OrgID, TeamID, Label string }

func loginProfileIdentity(data map[string]any) (loginIdentity, error) {
	profile := unwrapLoginData(data)
	outer := profile
	if user := mapIn(profile, "user"); user != nil {
		profile = user
	}
	organization := mapIn(profile, "organization")
	if organization == nil {
		organization = mapIn(profile, "biz")
	}
	if organization == nil {
		organization = mapIn(outer, "organization")
	}
	identity := loginIdentity{UserID: stringIn(profile, "id", "user_id", "uid"),
		OrgID:  core.FirstNonEmpty(stringIn(profile, "org_id", "orgId", "organization_id", "organizationId"), stringIn(organization, "org_id", "orgId", "id")),
		TeamID: core.FirstNonEmpty(stringIn(profile, "team_id", "teamId"), stringIn(organization, "team_id", "teamId")),
		Label:  stringIn(profile, "name", "username", "user_name", "email")}
	if identity.UserID == "" || (identity.OrgID == "") != (identity.TeamID == "") {
		return loginIdentity{}, loginFailure(http.StatusUnauthorized, "千问用户或企业身份响应不完整")
	}
	if identity.Label == "" {
		identity.Label = identity.UserID
	}
	return identity, nil
}

func loginFileName(credential *Credential) string {
	// FileNameFor 的 seeds 仅用于 identifier 为空时的兜底；显式把身份摘要
	// 放进文件标识，确保同一用户的不同团队不会覆盖，且不受 64 字符截断影响。
	identity, _ := json.Marshal([]string{credential.UserID, credential.OrgID, credential.TeamID})
	digest := sha256.Sum256(identity)
	label := core.SanitizeFileComponent(credential.UserID)
	if len(label) > 40 {
		label = label[:40]
	}
	return core.FileNameFor(vendorID, label+"-"+hex.EncodeToString(digest[:6]))
}

func loginWebCredential(ctx context.Context, token string, data map[string]any, identity loginIdentity) (string, int64, error) {
	if _, err := tokenClaims(token); err == nil {
		expiry, err := loginExpiry(data, token)
		return token, expiry, err
	}
	jwt, expiry, err := exchangeLoginWebCredential(ctx, token)
	if err != nil {
		return "", 0, err
	}
	if identity.OrgID == "" {
		return jwt, expiry, nil
	}
	_, headers, err := loginRequest(ctx, http.MethodPost, webOrigin+"/biz/user/v1/auth/switch-team", jwt,
		map[string]any{"team_id": identity.TeamID, "user_id": identity.UserID}, "")
	if err != nil {
		return "", 0, err
	}
	jwt, err = loginCookieToken(headers)
	if err != nil {
		return "", 0, err
	}
	expiry, err = loginExpiry(nil, jwt)
	return jwt, expiry, err
}

func exchangeLoginWebCredential(ctx context.Context, deviceToken string) (string, int64, error) {
	// 与 PC OAuthSessionExchangeClient 一致：POST 无正文，以原设备票鉴权，
	// 只接受官方站返回的有明确到期时间的 user/biz 会话 JWT。
	data, _, err := loginRequest(ctx, http.MethodPost, webOrigin+"/auth/oauth/session", deviceToken, nil, "")
	if err != nil {
		return "", 0, err
	}
	token := stringIn(data, "token")
	claims, err := tokenClaims(token)
	if err != nil || (stringIn(claims, "aud") != "user" && stringIn(claims, "aud") != "biz") || stringIn(claims, "sub") == "" {
		return "", 0, loginFailure(http.StatusUnauthorized, "千问网页登录凭证交换响应无效")
	}
	expiry, err := loginExpiry(data, token)
	if err != nil || expiry != int64(core.IntFromAny(claims["exp"])) || (stringIn(claims, "user_id") != "" && stringIn(claims, "user_id") != stringIn(claims, "sub")) {
		return "", 0, loginFailure(http.StatusUnauthorized, "千问网页登录凭证交换响应的身份或有效期不一致")
	}
	return token, expiry, nil
}

func verifyLoginIdentity(ctx context.Context, credential *Credential, token string) error {
	data, _, err := loginRequest(ctx, http.MethodGet, core.FirstNonEmpty(credential.WebIdentityOrigin, webOrigin)+"/biz/user/v1/auth/me", token, nil, "")
	if err != nil {
		return err
	}
	data = unwrapLoginData(data)
	if stringIn(data, "user_id") != credential.UserID {
		return loginFailure(http.StatusUnauthorized, "千问用户身份与登录凭证不一致")
	}
	if credential.OrgID == "" && credential.TeamID == "" {
		if stringIn(data, "identity_kind") != "c_site" {
			return loginFailure(http.StatusUnauthorized, "千问个人身份与登录凭证不一致")
		}
		return nil
	}
	if stringIn(data, "identity_kind") != "biz" || stringIn(mapIn(data, "org"), "id") != credential.OrgID || stringIn(mapIn(data, "team"), "id") != credential.TeamID {
		return loginFailure(http.StatusUnauthorized, "千问企业或团队身份与登录凭证不一致")
	}
	access, _, err := loginRequest(ctx, http.MethodGet, core.FirstNonEmpty(credential.APIOrigin, gatewayOrigin)+"/api/v1/adapter/biz/access-status", token, nil, "")
	if err != nil {
		return err
	}
	access = unwrapLoginData(access)
	canUseCredits, ok := access["can_use_credits"].(bool)
	if stringIn(access, "org_id") != credential.OrgID || stringIn(access, "team_id") != credential.TeamID || stringIn(access, "member_status") != "active" || !ok || !canUseCredits {
		return loginFailure(http.StatusForbidden, "千问企业席位当前不可使用积分或身份不匹配")
	}
	return nil
}

func loginCookieToken(headers http.Header) (string, error) {
	seen := map[string]bool{}
	response := &http.Response{Header: headers}
	for _, cookie := range response.Cookies() {
		if cookie.Name == "token" && cookie.Value != "" && cookie.MaxAge >= 0 && (cookie.Expires.IsZero() || cookie.Expires.After(time.Now())) {
			seen[cookie.Value] = true
		}
	}
	if len(seen) != 1 {
		return "", loginFailure(http.StatusUnauthorized, "千问未返回唯一有效的企业身份令牌，请重新登录")
	}
	for token := range seen {
		return token, nil
	}
	return "", loginFailure(http.StatusUnauthorized, "千问企业身份令牌缺失")
}

func loginExpiry(data map[string]any, token string) (int64, error) {
	if instant := stringIn(data, "expires_at"); instant != "" {
		parsed, err := time.Parse(time.RFC3339, instant)
		if err == nil && parsed.After(time.Now()) {
			return parsed.Unix(), nil
		}
	}
	if seconds := core.IntFromAny(data["expires_in"]); seconds > 0 && seconds <= 365*24*3600 {
		return time.Now().Unix() + int64(seconds), nil
	}
	claims, err := tokenClaims(token)
	if err == nil {
		if expiry := int64(core.IntFromAny(claims["exp"])); expiry > time.Now().Unix() {
			return expiry, nil
		}
	}
	return 0, loginFailure(http.StatusUnauthorized, "千问令牌有效期无效或已过期，请重新登录")
}

func unwrapLoginData(data map[string]any) map[string]any {
	for i := 0; i < 3; i++ {
		inner := mapIn(data, "data")
		if inner == nil {
			break
		}
		data = inner
	}
	return data
}

func loginRequest(ctx context.Context, method, target, token string, body any, contentType string) (map[string]any, http.Header, error) {
	var encoded []byte
	var err error
	if body != nil {
		if value, ok := body.(string); ok {
			encoded = []byte(value)
		} else {
			encoded, err = json.Marshal(body)
			if err != nil {
				return nil, nil, loginFailure(http.StatusBadRequest, "千问登录请求参数无效")
			}
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(encoded))
	if err != nil {
		return nil, nil, loginFailure(http.StatusBadRequest, "千问登录请求地址无效")
	}
	request.Header.Set("Accept", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		if contentType == "" {
			contentType = "application/json"
		}
		request.Header.Set("Content-Type", contentType)
	}
	client := hostbridge.Client(ctx, loginHTTPTimeout)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		status := http.StatusBadGateway
		if failure, ok := core.ToPluginError(err).(*core.PluginError); ok && failure.HTTPStatus > 0 {
			status = failure.HTTPStatus
		}
		return nil, nil, loginFailure(status, fmt.Sprintf("千问登录请求未完成（HTTP %d）", status))
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, loginResponseLimit+1))
	if err != nil || len(data) > loginResponseLimit {
		return nil, nil, loginFailure(http.StatusBadGateway, "千问登录响应读取失败")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, response.Header, loginFailure(response.StatusCode, fmt.Sprintf("千问登录请求被拒绝（HTTP %d）", response.StatusCode))
	}
	var payload map[string]any
	if len(bytes.TrimSpace(data)) == 0 {
		return map[string]any{}, response.Header, nil
	}
	if json.Unmarshal(data, &payload) != nil || payload == nil {
		return nil, response.Header, loginFailure(http.StatusBadGateway, "千问登录响应不是 JSON 对象")
	}
	if code := stringIn(payload, "code"); code != "" && code != "ok" && code != "SUCCESS" && code != "0" {
		return nil, response.Header, loginFailure(http.StatusBadGateway, "千问登录返回业务错误，请重新登录")
	}
	return unwrapLoginData(payload), response.Header, nil
}

func loginFailure(status int, message string) *core.Failure {
	return &core.Failure{Status: status, Kind: core.ClassifyStatus(status), Msg: message}
}
func loginErrorStatus(err error) int {
	if failure, ok := err.(*core.Failure); ok {
		return failure.HTTPStatus()
	}
	return http.StatusBadGateway
}
