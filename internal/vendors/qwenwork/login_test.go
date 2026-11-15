package qwenwork

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"freetier2api-plugin/cpasdk/pluginabi"
	"freetier2api-plugin/cpasdk/pluginapi"
	"freetier2api-plugin/internal/core"
	"freetier2api-plugin/internal/hostbridge"
)

type loginTestSessions struct {
	entries   map[string]*core.LoginSession
	throttled bool
}

func (s *loginTestSessions) Register(vendor, id string, _, _ time.Duration, data any) {
	s.entries[id] = &core.LoginSession{VendorID: vendor, Data: data}
}
func (s *loginTestSessions) Poll(id string) (*core.LoginSession, core.PollState) {
	entry := s.entries[id]
	if entry == nil {
		return nil, core.PollMissing
	}
	if s.throttled {
		return entry, core.PollThrottled
	}
	return entry, core.PollReady
}
func (s *loginTestSessions) Owns(id string) (string, bool) {
	entry := s.entries[id]
	if entry == nil {
		return "", false
	}
	return entry.VendorID, true
}
func (s *loginTestSessions) Delete(id string) { delete(s.entries, id) }

func loginTestAdapter(t *testing.T) (*adapter, *loginTestSessions) {
	t.Helper()
	sessions := &loginTestSessions{entries: map[string]*core.LoginSession{}}
	return Instances(core.Env{Logins: sessions})[0].(*adapter), sessions
}

func loginTestJWT(user, org, team string, expiry int64) string {
	claims := map[string]any{"iss": "qwenwork.cn", "user_id": user, "sub": user, "exp": expiry}
	if org != "" {
		claims["biz_org_id"], claims["biz_team_id"], claims["aud"] = org, team, "biz"
	} else {
		claims["aud"] = "user"
	}
	data, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(data) + "." + base64.RawURLEncoding.EncodeToString([]byte("test-signature-only"))
}

type loginTestResponse struct {
	status  int
	headers http.Header
	payload any
}

func loginTestHost(t *testing.T, handler func(*http.Request) loginTestResponse) {
	t.Helper()
	hostbridge.Configure(func(_ string, method string, payload any) (json.RawMessage, error) {
		if method != pluginabi.MethodHostHTTPDo {
			return nil, fmt.Errorf("unexpected host method %s", method)
		}
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		var request struct {
			Method, URL string
			Headers     http.Header
			Body        []byte
		}
		if err := json.Unmarshal(data, &request); err != nil {
			return nil, err
		}
		req, err := http.NewRequest(request.Method, request.URL, strings.NewReader(string(request.Body)))
		if err != nil {
			return nil, err
		}
		req.Header = request.Headers
		response := handler(req)
		if response.status == 0 {
			response.status = http.StatusOK
		}
		if response.headers == nil {
			response.headers = http.Header{}
		}
		body, err := json.Marshal(response.payload)
		if err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"StatusCode": response.status, "Headers": response.headers, "Body": body})
	})
	t.Cleanup(func() { hostbridge.Configure(nil) })
}

func TestLoginStartUsesDesktopDevicePKCE(t *testing.T) {
	v, sessions := loginTestAdapter(t)
	first, err := v.LoginStart(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := v.LoginStart(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.State == second.State || len(first.State) != 64 {
		t.Fatal("login state must be unique and cryptographically random")
	}
	u, err := url.Parse(first.URL)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	// 匿名验证：gateway 的设备入口 302 到网页登录，web 的同名入口为 404。
	if u.Scheme != "https" || u.Host != "gateway.qwenwork.cn" || u.Path != "/device/selectAccounts" {
		t.Fatalf("unexpected device authorization URL %s", first.URL)
	}
	if query.Get("client_id") != deviceClientID || query.Get("redirect_uri") != deviceRedirectURI || query.Get("challenge_method") != "S256" {
		t.Fatal("device authorization must match enabled PC protocol")
	}
	pending := sessions.entries[first.State].Data.(*pendingDeviceLogin)
	sum := sha256.Sum256([]byte(pending.verifier))
	if query.Get("challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) || query.Get("verifier") != "" || len(query.Get("nonce")) != 36 || len(query.Get("machine_id")) != 36 {
		t.Fatal("PKCE or device parameters invalid")
	}
	if !first.ExpiresAt.After(time.Now()) || first.ExpiresAt.After(time.Now().Add(loginTTL+time.Second)) {
		t.Fatal("invalid login expiry")
	}
	if v.AuthMode() != "oauth" || v.CredentialImportHint() == "" {
		t.Fatal("missing account login/import capability")
	}
}

func TestLoginPollPendingAndThrottle(t *testing.T) {
	v, sessions := loginTestAdapter(t)
	start, err := v.LoginStart(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	loginTestHost(t, func(req *http.Request) loginTestResponse {
		calls++
		if req.URL.Host != "gateway.qwenwork.cn" || req.URL.Path != "/api/v1/deviceToken/poll" {
			t.Fatal("wrong poll endpoint")
		}
		return loginTestResponse{status: 404, payload: map[string]any{}}
	})
	result, err := v.LoginPoll(context.Background(), start.State)
	if err != nil || result.Status != pluginapi.AuthLoginStatusPending {
		t.Fatalf("pending result = %#v, %v", result, err)
	}
	sessions.throttled = true
	result, err = v.LoginPoll(context.Background(), start.State)
	if err != nil || result.Status != pluginapi.AuthLoginStatusPending || calls != 1 {
		t.Fatal("throttled login must not call upstream")
	}
	result, _ = v.LoginPoll(context.Background(), "missing")
	if result.Status != pluginapi.AuthLoginStatusError {
		t.Fatal("unknown state must fail")
	}
}

func TestLoginPollRejectsPKCEBindingMismatch(t *testing.T) {
	v, _ := loginTestAdapter(t)
	start, _ := v.LoginStart(context.Background(), nil)
	loginTestHost(t, func(req *http.Request) loginTestResponse {
		return loginTestResponse{payload: map[string]any{"token": "test", "refresh_token": "test-refresh", "nonce": "wrong", "code_challenge": "wrong", "code_challenge_method": "S256"}}
	})
	result, err := v.LoginPoll(context.Background(), start.State)
	if err != nil || result.Status != pluginapi.AuthLoginStatusError || !strings.Contains(result.Message, "PKCE") {
		t.Fatalf("binding result = %#v, %v", result, err)
	}
}

func loginTestIdentityResponse(req *http.Request, token string, wrongTeam bool) loginTestResponse {
	team := "team-1"
	if wrongTeam {
		team = "other-team"
	}
	switch req.URL.Path {
	case "/api/v1/userinfo":
		return loginTestResponse{payload: map[string]any{"id": "user-1", "username": "Test account", "is_biz": true, "organization_id": "org-1", "organization": map[string]any{"org_id": "org-1", "team_id": "team-1"}}}
	case "/biz/user/v1/auth/me":
		return loginTestResponse{payload: map[string]any{"identity_kind": "biz", "user_id": "user-1", "org": map[string]any{"id": "org-1"}, "team": map[string]any{"id": team}}}
	case "/api/v1/adapter/biz/access-status":
		return loginTestResponse{payload: map[string]any{"data": map[string]any{"org_id": "org-1", "team_id": "team-1", "member_status": "active", "seat_status": "active", "can_use_credits": true}}}
	}
	return loginTestResponse{status: 404, payload: map[string]any{}}
}

func TestLoginPollProducesVerifiedEnterpriseCredential(t *testing.T) {
	v, sessions := loginTestAdapter(t)
	start, _ := v.LoginStart(context.Background(), map[string]any{"user_id": "user-1", "org_id": "org-1", "team_id": "team-1"})
	pending := sessions.entries[start.State].Data.(*pendingDeviceLogin)
	token := loginTestJWT("user-1", "org-1", "team-1", time.Now().Add(time.Hour).Unix())
	pollCalls := 0
	loginTestHost(t, func(req *http.Request) loginTestResponse {
		if req.URL.Path == "/api/v1/deviceToken/poll" {
			pollCalls++
			if req.URL.Query().Get("verifier") != pending.verifier || req.URL.Query().Get("nonce") != pending.nonce {
				t.Fatal("missing poll binding")
			}
			return loginTestResponse{payload: map[string]any{"token": token, "refresh_token": "test-refresh", "nonce": pending.nonce, "code_challenge": pending.challenge, "code_challenge_method": "S256"}}
		}
		if req.Header.Get("Authorization") != "Bearer "+token {
			t.Fatal("missing bearer identity verification")
		}
		return loginTestIdentityResponse(req, token, false)
	})
	result, err := v.LoginPoll(context.Background(), start.State)
	if err != nil || result.Status != pluginapi.AuthLoginStatusSuccess {
		t.Fatalf("login result = %#v, %v", result, err)
	}
	credential, err := ParseCredential(result.Auth.StorageJSON)
	if err != nil {
		t.Fatal(err)
	}
	if credential.UserID != "user-1" || credential.OrgID != "org-1" || credential.TeamID != "team-1" || credential.RefreshToken != "test-refresh" || result.Auth.Provider != core.ProviderKey || !strings.HasPrefix(result.Auth.FileName, "qwenwork-") {
		t.Fatal("incorrect saved enterprise identity")
	}
	if credential.AuthOrigin != gatewayOrigin || credential.APIOrigin != gatewayOrigin || credential.WebIdentityOrigin != webOrigin {
		t.Fatal("device authorization origin and web identity origin must remain separate")
	}
	second, err := v.LoginPoll(context.Background(), start.State)
	if err != nil || second.Status != pluginapi.AuthLoginStatusSuccess || pollCalls != 1 {
		t.Fatal("duplicate success poll must not consume upstream result twice")
	}
}

func TestLoginPollRejectsDifferentEnterprise(t *testing.T) {
	v, sessions := loginTestAdapter(t)
	start, _ := v.LoginStart(context.Background(), nil)
	pending := sessions.entries[start.State].Data.(*pendingDeviceLogin)
	token := loginTestJWT("user-1", "org-1", "team-1", time.Now().Add(time.Hour).Unix())
	loginTestHost(t, func(req *http.Request) loginTestResponse {
		if req.URL.Path == "/api/v1/deviceToken/poll" {
			return loginTestResponse{payload: map[string]any{"token": token, "refresh_token": "test-refresh", "nonce": pending.nonce, "code_challenge": pending.challenge, "code_challenge_method": "S256"}}
		}
		return loginTestIdentityResponse(req, token, true)
	})
	result, err := v.LoginPoll(context.Background(), start.State)
	if err != nil || result.Status != pluginapi.AuthLoginStatusError || len(result.Auth.StorageJSON) != 0 {
		t.Fatal("mismatched team must never be saved")
	}
}

func TestLoginOpaqueDeviceTokenExchangesAndRestoresSelectedTeam(t *testing.T) {
	v, sessions := loginTestAdapter(t)
	start, _ := v.LoginStart(context.Background(), nil)
	pending := sessions.entries[start.State].Data.(*pendingDeviceLogin)
	expiresAt := time.Now().Add(time.Hour).Unix()
	baseToken := loginTestJWT("personal-user", "", "", expiresAt)
	teamToken := loginTestJWT("user-1", "org-1", "team-1", time.Now().Add(time.Hour).Unix())
	exchangeCalls, switchCalls := 0, 0
	loginTestHost(t, func(req *http.Request) loginTestResponse {
		switch req.URL.Path {
		case "/api/v1/deviceToken/poll":
			return loginTestResponse{payload: map[string]any{"token": "opaque-device-ticket", "refresh_token": "device-refresh", "nonce": pending.nonce, "code_challenge": pending.challenge, "code_challenge_method": "S256"}}
		case "/api/v1/userinfo":
			if req.Header.Get("Authorization") != "Bearer opaque-device-ticket" {
				t.Fatal("userinfo must authenticate the device ticket")
			}
			return loginTestIdentityResponse(req, "", false)
		case "/auth/oauth/session":
			exchangeCalls++
			if req.Method != http.MethodPost || req.URL.Host != "qwenwork.cn" || req.Header.Get("Authorization") != "Bearer opaque-device-ticket" {
				t.Fatal("wrong PC web session exchange request")
			}
			return loginTestResponse{payload: map[string]any{"token": baseToken, "expires_at": time.Unix(expiresAt, 0).UTC().Format(time.RFC3339)}}
		case "/biz/user/v1/auth/switch-team":
			switchCalls++
			var body map[string]any
			_ = json.NewDecoder(req.Body).Decode(&body)
			if body["team_id"] != "team-1" || body["user_id"] != "user-1" || req.Header.Get("Authorization") != "Bearer "+baseToken {
				t.Fatal("exchanged personal JWT must restore originally selected company identity")
			}
			return loginTestResponse{headers: http.Header{"Set-Cookie": []string{"token=" + teamToken}}, payload: map[string]any{}}
		default:
			if req.Header.Get("Authorization") != "Bearer "+teamToken {
				t.Fatal("verification must use company JWT")
			}
			return loginTestIdentityResponse(req, teamToken, false)
		}
	})
	result, err := v.LoginPoll(context.Background(), start.State)
	if err != nil || result.Status != pluginapi.AuthLoginStatusSuccess || exchangeCalls != 1 || switchCalls != 1 {
		t.Fatalf("opaque login result = %#v, %v", result, err)
	}
	credential, err := ParseCredential(result.Auth.StorageJSON)
	if err != nil || credential.Token != teamToken || credential.RefreshToken != "device-refresh" || credential.OrgID != "org-1" || strings.Contains(string(result.Auth.StorageJSON), "opaque-device-ticket") {
		t.Fatal("must only save restored company JWT and device refresh ticket")
	}
}

func TestLoginFileNameSeparatesTeamsWithoutTruncatingHash(t *testing.T) {
	first := &Credential{UserID: strings.Repeat("x", 100), OrgID: "org", TeamID: "team-one"}
	second := *first
	second.TeamID = "team-two"
	if loginFileName(first) == loginFileName(&second) || loginFileName(first) != loginFileName(first) {
		t.Fatal("identity file names must be stable and distinct across teams")
	}
}

func TestLoginProfileIdentityAcceptsDesktopUserinfo(t *testing.T) {
	identity, err := loginProfileIdentity(map[string]any{"id": "uid", "organization_id": "org", "organization": map[string]any{"team_id": "team"}, "name": "name"})
	if err != nil || identity.UserID != "uid" || identity.OrgID != "org" || identity.TeamID != "team" {
		t.Fatalf("desktop userinfo identity = %#v, %v", identity, err)
	}
}

func TestRefreshValidCredentialDoesNotCallUpstream(t *testing.T) {
	credential := &Credential{Token: "existing", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	loginTestHost(t, func(req *http.Request) loginTestResponse {
		t.Fatal("valid credential must not rotate token")
		return loginTestResponse{}
	})
	updated, changed, err := RefreshCredential(context.Background(), credential)
	if err != nil || changed || updated != credential {
		t.Fatal("valid credential must retain immutable snapshot")
	}
}

func TestRefreshRestoresExactEnterpriseAndLeavesOriginalUntouched(t *testing.T) {
	oldToken := loginTestJWT("user-1", "org-1", "team-1", time.Now().Add(time.Minute).Unix())
	baseToken := loginTestJWT("personal-user", "", "", time.Now().Add(time.Hour).Unix())
	teamToken := loginTestJWT("user-1", "org-1", "team-1", time.Now().Add(time.Hour).Unix())
	credential := &Credential{Token: oldToken, RefreshToken: "old-refresh", UserID: "user-1", OrgID: "org-1", TeamID: "team-1", ExpiresAt: time.Now().Unix(), Protocol: "device-token", APIOrigin: gatewayOrigin, WebIdentityOrigin: webOrigin, ClientID: deviceClientID, Raw: map[string]any{"oauthRedirectUri": deviceRedirectURI, "note": "keep"}}
	refreshCalls := 0
	loginTestHost(t, func(req *http.Request) loginTestResponse {
		switch req.URL.Path {
		case "/api/v1/deviceToken/refresh":
			refreshCalls++
			var body map[string]any
			if json.NewDecoder(req.Body).Decode(&body) != nil {
				t.Fatal("bad refresh body")
			}
			if body["refresh_token"] != "old-refresh" || body["client_id"] != deviceClientID || body["redirect_uri"] != deviceRedirectURI || req.URL.Host != "gateway.qwenwork.cn" {
				t.Fatal("refresh request does not preserve original OAuth client")
			}
			return loginTestResponse{payload: map[string]any{"device_token": baseToken, "refresh_token": "new-refresh", "expires_in": 3600}}
		case "/biz/user/v1/auth/switch-team":
			var body map[string]any
			_ = json.NewDecoder(req.Body).Decode(&body)
			if req.Header.Get("Authorization") != "Bearer "+baseToken || body["team_id"] != "team-1" || body["user_id"] != "user-1" {
				t.Fatal("team restore must use base token and original identity")
			}
			return loginTestResponse{headers: http.Header{"Set-Cookie": []string{"token=" + teamToken + "; Path=/; Secure; HttpOnly; Max-Age=3600"}}, payload: map[string]any{"ok": true}}
		default:
			if req.Header.Get("Authorization") != "Bearer "+teamToken {
				t.Fatal("identity checks must use restored team token")
			}
			return loginTestIdentityResponse(req, teamToken, false)
		}
	})
	updated, changed, err := RefreshCredential(context.Background(), credential)
	if err != nil || !changed || updated == credential || refreshCalls != 1 {
		t.Fatalf("refresh = %#v, %v, %v", updated, changed, err)
	}
	if updated.Token != teamToken || updated.RefreshToken != "new-refresh" || credential.Token != oldToken || credential.RefreshToken != "old-refresh" || credential.Raw["note"] != "keep" {
		t.Fatal("rotation must return restored snapshot without mutating original")
	}
	updated.Raw["note"] = "changed"
	if credential.Raw["note"] != "keep" {
		t.Fatal("raw maps must not be shared across refresh snapshots")
	}
}

func TestRefreshNativeOAuthIsOnlyForDeclaredProtocol(t *testing.T) {
	token := loginTestJWT("personal-user", "", "", time.Now().Add(time.Hour).Unix())
	credential := &Credential{RefreshToken: "test-refresh", UserID: "personal-user", Protocol: "native-oauth-iam-business", ClientID: "qwenwork-desktop-app", APIOrigin: gatewayOrigin, WebIdentityOrigin: webOrigin}
	loginTestHost(t, func(req *http.Request) loginTestResponse {
		if req.URL.Path == "/auth/oauth/token" {
			body, _ := io.ReadAll(req.Body)
			form, _ := url.ParseQuery(string(body))
			if req.URL.Host != "qwenwork.cn" || req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || form.Get("grant_type") != "refresh_token" || form.Get("client_id") != "qwenwork-desktop-app" {
				t.Fatal("wrong native OAuth request")
			}
			return loginTestResponse{payload: map[string]any{"access_token": token, "refresh_token": "next-refresh", "expires_in": 3600}}
		}
		return loginTestResponse{payload: map[string]any{"identity_kind": "c_site", "user_id": "personal-user"}}
	})
	updated, changed, err := RefreshCredential(context.Background(), credential)
	if err != nil || !changed || updated.Token != token {
		t.Fatalf("native refresh = %#v, %v, %v", updated, changed, err)
	}
}

func TestRefreshFailClosedOnUnknownOrMismatchedIdentity(t *testing.T) {
	for _, name := range []string{"unknown-refresh", "wrong-team"} {
		t.Run(name, func(t *testing.T) {
			baseToken := loginTestJWT("personal-user", "", "", time.Now().Add(time.Hour).Unix())
			teamToken := loginTestJWT("user-1", "org-1", "team-1", time.Now().Add(time.Hour).Unix())
			credential := &Credential{RefreshToken: "do-not-log-me", UserID: "user-1", OrgID: "org-1", TeamID: "team-1", Protocol: "device-token", APIOrigin: gatewayOrigin, WebIdentityOrigin: webOrigin}
			calls := 0
			loginTestHost(t, func(req *http.Request) loginTestResponse {
				if req.URL.Path == "/api/v1/deviceToken/refresh" {
					calls++
					if name == "unknown-refresh" {
						return loginTestResponse{status: 503, payload: map[string]any{"message": "do-not-log-me"}}
					}
					return loginTestResponse{payload: map[string]any{"token": baseToken, "refresh_token": "next-refresh", "expires_in": 3600}}
				}
				if req.URL.Path == "/biz/user/v1/auth/switch-team" {
					return loginTestResponse{headers: http.Header{"Set-Cookie": []string{"token=" + teamToken}}, payload: map[string]any{}}
				}
				return loginTestIdentityResponse(req, teamToken, true)
			})
			updated, changed, err := RefreshCredential(context.Background(), credential)
			if err == nil || updated != nil || changed || calls != 1 || loginErrorStatus(err) != 401 || strings.Contains(err.Error(), "do-not-log-me") {
				t.Fatalf("unsafe refresh result = %#v, %v, %v", updated, changed, err)
			}
		})
	}
}

func TestRefreshRejectsUntrustedOriginAndMissingRefresh(t *testing.T) {
	loginTestHost(t, func(req *http.Request) loginTestResponse {
		t.Fatal("invalid credentials must not be transmitted")
		return loginTestResponse{}
	})
	for _, credential := range []*Credential{nil, {Token: "expired"}, {RefreshToken: "secret", APIOrigin: "https://attacker.invalid"}} {
		if _, _, err := RefreshCredential(context.Background(), credential); err == nil {
			t.Fatal("invalid refresh credential accepted")
		}
	}
}

func TestLoginCookieTokenRejectsAmbiguousOrDeletedCookies(t *testing.T) {
	for _, cookies := range [][]string{{"token=a", "token=b"}, {"token=a; Max-Age=0"}, {"token=a; Expires=Thu, 01 Jan 1970 00:00:00 GMT"}, {"other=a"}} {
		if _, err := loginCookieToken(http.Header{"Set-Cookie": cookies}); err == nil {
			t.Fatalf("unsafe token cookie accepted: %v", cookies)
		}
	}
}
