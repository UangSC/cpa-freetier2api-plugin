package admin

import (
	"freetier2api-plugin/cpasdk/pluginapi"
	"freetier2api-plugin/internal/auth"
	"freetier2api-plugin/internal/core"
	"freetier2api-plugin/internal/hostbridge"
	"net/http"
	"strings"
)

func (s *Service) quotaCredentialAccount(req pluginapi.ManagementRequest, id string) (auth.Account, error) {
	ctx, cancel := hostbridge.ManagementContext(req, requestTimeout)
	defer cancel()
	loaded, _ := s.pool.Load(ctx, hostbridge.RequestCallbackID(req), auth.Options{EnabledRealms: s.deps.Config().EnabledRealms})
	matches := []auth.Account{}
	for _, account := range loaded {
		for _, value := range []string{account.Entry.ID, account.Entry.Name, account.Entry.AuthIndex, account.Credential.FileIDValue()} {
			if strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(value), ".json"), strings.TrimSuffix(strings.TrimSpace(id), ".json")) {
				matches = append(matches, account)
				break
			}
		}
	}
	if strings.TrimSpace(id) == "" || len(matches) != 1 {
		return auth.Account{}, core.NewPluginError("quota_account_invalid", "请选择一个有效账号", http.StatusBadRequest)
	}
	return matches[0], nil
}
func (s *Service) handleQuotaCredential(req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	var input struct {
		AccountID  string `json:"account_id"`
		Credential string `json:"credential_curl"`
	}
	decoded, err := decodeRequestInto(req.Body, input)
	if err != nil {
		return BadJSONRequestResponse()
	}
	account, err := s.quotaCredentialAccount(req, decoded.AccountID)
	if err != nil {
		return JSONResponse(400, map[string]any{"ok": false, "error": err.Error()})
	}
	provider, ok := core.As[core.QuotaCredentialProvider](account.Vendor)
	if !ok {
		return JSONResponse(400, map[string]any{"ok": false, "error": "该平台不支持余额绑定"})
	}
	ctx, cancel := hostbridge.ManagementContext(req, requestTimeout)
	defer cancel()
	updated, err := provider.PrepareQuotaCredential(ctx, account.Credential, decoded.Credential)
	if err != nil {
		return JSONResponse(400, map[string]any{"ok": false, "error": err.Error()})
	}
	name := account.Entry.Name
	if name == "" {
		name = account.Credential.FileIDValue() + ".json"
	}
	if !strings.HasSuffix(name, ".json") {
		name += ".json"
	}
	if err = saveAuthFile(hostbridge.RequestCallbackID(req), name, updated); err != nil {
		return JSONResponse(500, map[string]any{"ok": false, "error": "保存当前账号的墨点授权失败"})
	}
	return JSONResponse(200, map[string]any{"ok": true, "message": "已为当前账号绑定墨点"})
}
func (s *Service) handleQuotaAuthorizationStart(req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	var input struct {
		AccountID string `json:"account_id"`
	}
	decoded, err := decodeRequestInto(req.Body, input)
	if err != nil {
		return BadJSONRequestResponse()
	}
	account, err := s.quotaCredentialAccount(req, decoded.AccountID)
	if err != nil {
		return JSONResponse(400, map[string]any{"ok": false, "error": err.Error()})
	}
	provider, ok := core.As[core.QuotaAuthorizationProvider](account.Vendor)
	if !ok {
		return JSONResponse(400, map[string]any{"ok": false, "error": "该平台不支持网页授权"})
	}
	ctx, cancel := hostbridge.ManagementContext(req, requestTimeout)
	defer cancel()
	result, err := provider.StartQuotaAuthorization(ctx, account.Credential)
	if err != nil {
		return JSONResponse(400, map[string]any{"ok": false, "error": err.Error()})
	}
	return JSONResponse(200, map[string]any{"ok": true, "url": result.URL, "state": result.State})
}
