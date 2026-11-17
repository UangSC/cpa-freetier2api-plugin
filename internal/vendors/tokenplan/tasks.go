package tokenplan

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"freetier2api-plugin/cpasdk/pluginapi"
	"freetier2api-plugin/internal/core"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const balanceOrigin = "https://discovery.intern-ai.org.cn"
const balancePath = "/api/tokenplan/v1/credits/balance"

type balanceAuth struct {
	Token     string `json:"token,omitempty"`
	UserID    string `json:"user_id"`
	KeyHash   string `json:"key_hash,omitempty"`
	KeyID     string `json:"key_id,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
}

func keyHash(key string) string { sum := sha256.Sum256([]byte(key)); return hex.EncodeToString(sum[:]) }

func parseBalanceAuth(input string) (*balanceAuth, error) {
	input = strings.TrimSpace(input)
	if len(input) == 0 || len(input) > 64<<10 {
		return nil, errors.New("请粘贴墨点余额请求的 cURL 或网页登录令牌")
	}
	token := input
	if strings.HasPrefix(input, "curl") {
		urlMatch := regexp.MustCompile(`https://[^\s'"\\]+`).FindString(input)
		parsed, err := url.Parse(urlMatch)
		if err != nil || parsed.Scheme != "https" || parsed.Host != "discovery.intern-ai.org.cn" || parsed.Path != balancePath {
			return nil, errors.New("cURL 必须来自官方 credits/balance 余额请求")
		}
		match := regexp.MustCompile(`(?i)authorization:\s*Bearer\s+([A-Za-z0-9._-]+)`).FindStringSubmatch(input)
		if len(match) != 2 {
			return nil, errors.New("余额 cURL 缺少网页登录 Authorization 令牌")
		}
		token = match[1]
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("墨点余额需要网页 JWT，模型 API Key 不能代替")
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("网页令牌格式无效")
	}
	var claims struct {
		ID  string `json:"jti"`
		Exp int64  `json:"exp"`
		Iss string `json:"iss"`
	}
	if json.Unmarshal(claimsBytes, &claims) != nil || claims.ID == "" || claims.Iss != "OpenXLab" || strings.ContainsAny(claims.ID, "\r\n; ") || claims.Exp <= time.Now().Unix() {
		return nil, errors.New("墨点网页凭证无效或已过期，请重新复制余额请求")
	}
	return &balanceAuth{Token: token, UserID: claims.ID, ExpiresAt: claims.Exp}, nil
}

func balanceRequest(ctx context.Context, auth *balanceAuth, path string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, balanceOrigin+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	req.Header.Set("Cookie", "uaa-token="+auth.Token+"; ssouid="+auth.UserID)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "zh-CN")
	req.Header.Set("Referer", balanceOrigin+"/token-plan/points")
	response, err := client(ctx, 20*time.Second, false).Do(req)
	if err != nil {
		return nil, errors.New("墨点余额服务暂时无法连接")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, errors.New("读取墨点余额失败")
	}
	if response.StatusCode == 401 || response.StatusCode == 403 {
		return nil, core.NewPluginError("tokenplan_balance_session_expired", "墨点网页登录凭证已过期，请重新粘贴余额 cURL；模型 API Key 不受影响", http.StatusPreconditionFailed)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("墨点服务返回 HTTP %d", response.StatusCode)
	}
	var envelope struct {
		Code int             `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.Code != 0 || len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return nil, errors.New("墨点服务未返回有效账号数据，请检查网页登录凭证")
	}
	return envelope.Data, nil
}

func balanceValue(data []byte) (float64, error) {
	var body map[string]json.RawMessage
	if json.Unmarshal(data, &body) != nil {
		return 0, errors.New("墨点余额响应格式无效")
	}
	raw, ok := body["available_credits"]
	if !ok {
		return 0, errors.New("墨点响应缺少 available_credits")
	}
	var text string
	if json.Unmarshal(raw, &text) != nil {
		text = string(raw)
	}
	value, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return 0, errors.New("墨点余额不是有效的非负数")
	}
	return value, nil
}

type quotaAuthPending struct {
	KeyHash   string
	ExpiresAt time.Time
}

func (v *adapter) QuotaCredentialHint() string {
	return "先打开授权地址完成网页登录，再复制登录后的完整回调链接粘贴；只绑定当前账号。也可粘贴 credits/balance 的 cURL 作为兜底。不绑定则不能查询墨点。"
}

func (v *adapter) QuotaCredentialBound(cred *core.Credential) bool {
	native, err := v.Native(cred)
	return err == nil && native.BalanceToken != "" && native.UserID != "" && native.BalanceKeyHash == keyHash(native.APIKey)
}

func (v *adapter) StartQuotaAuthorization(_ context.Context, cred *core.Credential) (*pluginapi.AuthLoginStartResponse, error) {
	native, err := v.Native(cred)
	if err != nil {
		return nil, err
	}
	state := core.RandomHex(24)
	expires := time.Now().Add(15 * time.Minute)
	v.quotaAuthSessions.Store(state, quotaAuthPending{KeyHash: keyHash(native.APIKey), ExpiresAt: expires})
	redirect := balanceOrigin + "/token-plan/points#freetier2api-balance/" + state
	link := "https://sso.openxlab.org.cn/authentication?clientId=dagw07mkg1bazlxzoy31&source=discovery&lang=zh-CN&redirect=" + url.QueryEscape(redirect)
	return &pluginapi.AuthLoginStartResponse{Provider: core.ProviderKey, URL: link, State: state, ExpiresAt: expires}, nil
}

func (v *adapter) callbackBalanceAuth(ctx context.Context, native *Credential, input string) (*balanceAuth, string, error) {
	callback, err := url.Parse(strings.TrimSpace(input))
	if err != nil || callback.Scheme != "https" || callback.Host != "discovery.intern-ai.org.cn" || callback.Path != "/token-plan/points" || callback.User != nil {
		return nil, "", errors.New("请粘贴授权完成后的官方回调链接")
	}
	parts := strings.SplitN(callback.Fragment, "?", 2)
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "freetier2api-balance/") {
		return nil, "", errors.New("回调缺少绑定状态或授权码")
	}
	state := strings.TrimPrefix(parts[0], "freetier2api-balance/")
	value, ok := v.quotaAuthSessions.Load(state)
	pending, valid := value.(quotaAuthPending)
	if !ok || !valid || time.Now().After(pending.ExpiresAt) || pending.KeyHash != keyHash(native.APIKey) {
		return nil, "", errors.New("绑定会话已过期或账号不匹配，请重新打开授权地址")
	}
	query, err := url.ParseQuery(parts[1])
	if err != nil || query.Get("code") == "" {
		return nil, "", errors.New("回调缺少授权码")
	}
	code := query.Get("code")
	if len(code) > 8192 {
		return nil, "", errors.New("授权码格式无效")
	}
	body, _ := json.Marshal(map[string]string{"code": code})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, balanceOrigin+"/api/user-center/v1/users/auth", strings.NewReader(string(body)))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	response, err := client(ctx, 20*time.Second, false).Do(req)
	if err != nil {
		return nil, "", errors.New("网页登录授权服务暂时无法连接")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, "", errors.New("读取授权响应失败")
	}
	var envelope struct {
		Code int `json:"code"`
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if response.StatusCode != 200 || json.Unmarshal(raw, &envelope) != nil || envelope.Code != 0 || envelope.Data.Token == "" {
		return nil, "", errors.New("授权码无效或已使用，请重新打开授权地址登录")
	}
	auth, err := parseBalanceAuth(envelope.Data.Token)
	return auth, state, err
}

func maskMatchesKey(mask, key string) bool {
	parts := regexp.MustCompile(`\*+|\.{3,}|…`).Split(mask, -1)
	return len(parts) == 2 && len(parts[1]) >= 4 && strings.HasPrefix(key, parts[0]) && strings.HasSuffix(key, parts[1])
}

func (v *adapter) PrepareQuotaCredential(ctx context.Context, cred *core.Credential, input string) ([]byte, error) {
	native, err := v.Native(cred)
	if err != nil {
		return nil, err
	}
	var auth *balanceAuth
	state := ""
	if strings.HasPrefix(strings.TrimSpace(input), "https://") {
		auth, state, err = v.callbackBalanceAuth(ctx, native, input)
	} else {
		auth, err = parseBalanceAuth(input)
	}
	if err != nil {
		return nil, err
	}
	if native.UserID != "" && native.UserID != auth.UserID {
		return nil, errors.New("网页登录账号与此凭证已绑定的账号不同，请为其他账号添加自己的 Key")
	}
	data, err := balanceRequest(ctx, auth, balancePath)
	if err != nil {
		return nil, err
	}
	if _, err = balanceValue(data); err != nil {
		return nil, err
	}
	raw, err := balanceRequest(ctx, auth, "/api/tokenplan/v1/keys?page=1&page_size=10")
	if err != nil {
		return nil, err
	}
	var directory struct {
		Items []struct {
			ID     string `json:"id"`
			Mask   string `json:"masked_key"`
			Status string `json:"status"`
		} `json:"items"`
		Total int `json:"total"`
	}
	if json.Unmarshal(raw, &directory) != nil || directory.Total > len(directory.Items) {
		return nil, errors.New("无法完整核对当前网页账号的 Key")
	}
	matches := 0
	for _, item := range directory.Items {
		if item.ID != "" && item.Status == "active" && maskMatchesKey(item.Mask, native.APIKey) {
			matches++
		}
	}
	if matches != 1 {
		return nil, errors.New("当前 Key 与网页登录账号不匹配或无法唯一确认，请检查账号")
	}
	document := make(map[string]any, len(native.Raw)+3)
	for key, value := range native.Raw {
		document[key] = value
	}
	document["user_id"] = auth.UserID
	document["balance_token"] = auth.Token
	document["balance_key_hash"] = keyHash(native.APIKey)
	updated, err := json.MarshalIndent(document, "", "  ")
	if err == nil && state != "" {
		v.quotaAuthSessions.Delete(state)
	}
	return updated, err
}

func (v *adapter) Quota(ctx context.Context, cred *core.Credential) (*pluginapi.QuotaFetchResponse, error) {
	native, err := v.Native(cred)
	if err != nil {
		return nil, err
	}
	if !v.QuotaCredentialBound(cred) {
		return nil, core.NewPluginError("tokenplan_balance_setup_required", "未绑定墨点，请为此账号单独授权绑定", http.StatusPreconditionRequired)
	}
	auth, err := parseBalanceAuth(native.BalanceToken)
	if err != nil {
		return nil, core.NewPluginError("tokenplan_balance_session_expired", "墨点网页授权已过期，请为此账号重新授权；模型 Key 不受影响", http.StatusPreconditionFailed)
	}
	if auth.UserID != native.UserID {
		return nil, errors.New("墨点授权与当前账号不一致")
	}
	data, err := balanceRequest(ctx, auth, balancePath)
	if err != nil {
		return nil, err
	}
	value, err := balanceValue(data)
	if err != nil {
		return nil, err
	}
	return &pluginapi.QuotaFetchResponse{Subscription: &pluginapi.QuotaSubscription{Plan: "credits", TierName: "我的墨点"}, Summary: []pluginapi.QuotaMetric{{Key: "credit_remain", Label: "我的墨点", Value: value, Unit: "墨点", Format: "number"}}}, nil
}
