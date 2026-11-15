package app

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"freetier2api-plugin/cpasdk/pluginabi"
	"freetier2api-plugin/cpasdk/pluginapi"
	"freetier2api-plugin/internal/core"
	"freetier2api-plugin/internal/hostbridge"
	"freetier2api-plugin/internal/logger"
)

const credentialStateSyncTimeout = 5 * time.Second

// syncCredentialStateAfterExecution 仅同步已成功生成后的凭证轮换，不影响模型结果。
// 宿主回调仍使用现有同步 RPC；短 context 控制阶段准入，不能中断已在飞的回调。
// 宿主 save 契约没有版本条件；二次检查可拒绝已观察到的删除/重导入，最终检查到
// save 之间的宿主并发写窗口仍需宿主提供 CAS 后才能完全消除。
func (a *App) syncCredentialStateAfterExecution(ctx context.Context, prepared preparedExecution) {
	observer, okObserver := prepared.vendor.(core.CredentialStateObserver)
	merger, okMerger := prepared.vendor.(core.StorageMerger)
	if !okObserver || !okMerger || prepared.credential == nil || a.registry == nil {
		return
	}
	defer func() {
		if recover() != nil {
			logger.Error("credential state sync interrupted (vendor=%s)", prepared.vendor.ID())
		}
	}()
	if !observer.HasPendingCredentialState(prepared.credential) {
		return
	}
	syncCtx, cancel := context.WithTimeout(ctx, credentialStateSyncTimeout)
	defer cancel()
	if syncCtx.Err() != nil {
		return
	}
	startToken := prepared.credential.TokenValue()
	if startToken == "" {
		return
	}
	entry, latest, latestJSON, ok := a.currentCredentialState(syncCtx, prepared)
	if !ok || latest.TokenValue() != startToken || !sameCredentialStateIdentity(prepared.credential, latest) {
		return
	}
	// 合并前后各检查一次账号，拒绝已经删除或重新导入的账号。
	merged, err := merger.MergeStorageJSON(latestJSON, prepared.credential)
	if err != nil || syncCtx.Err() != nil {
		logger.Info("credential state sync deferred (vendor=%s stage=merge)", prepared.vendor.ID())
		return
	}
	confirmedEntry, confirmed, confirmedJSON, ok := a.currentCredentialState(syncCtx, prepared)
	if !ok || confirmed.TokenValue() != startToken || !sameCredentialStateIdentity(prepared.credential, confirmed) || !sameCredentialStateEntry(entry, confirmedEntry) {
		return
	}
	// 再取最新 JSON 合并：同一令牌下的 prefix/proxy/disabled/label 修改也必须保留。
	merged, err = merger.MergeStorageJSON(confirmedJSON, prepared.credential)
	if err != nil || syncCtx.Err() != nil {
		logger.Info("credential state sync deferred (vendor=%s stage=merge)", prepared.vendor.ID())
		return
	}
	if candidate, ok := a.parseCredentialState(merged, confirmedEntry.Name, prepared.vendor.ID()); !ok || !sameCredentialStateIdentity(prepared.credential, candidate) {
		logger.Info("credential state sync deferred (vendor=%s stage=validate)", prepared.vendor.ID())
		return
	}
	persisted, errSave := hostbridge.SaveAuth(prepared.rpc.HostCallbackID, confirmedEntry.Name, merged)
	if errSave != nil {
		// 保存失败只留阶段，不输出 Cookie、原始 JSON 或可能携带凭证的桥错误。
		logger.Info("credential state sync deferred (vendor=%s stage=save)", prepared.vendor.ID())
		return
	}
	if candidate, ok := a.parseCredentialState(persisted, confirmedEntry.Name, prepared.vendor.ID()); !ok || !sameCredentialStateIdentity(prepared.credential, candidate) {
		logger.Info("credential state sync deferred (vendor=%s stage=confirmation)", prepared.vendor.ID())
		return
	}
	observer.CredentialStatePersisted(prepared.credential, persisted)
}

func credentialStateAuthIndex(entry core.HostAuth) string {
	return core.FirstNonEmpty(entry.AuthIndex, entry.ID, entry.Name)
}

func validCredentialStateName(name string) bool {
	return name != "" && name == strings.TrimSpace(name) && !strings.ContainsAny(name, "/\\") &&
		strings.HasSuffix(strings.ToLower(name), ".json") && name != ".json"
}

func credentialStateReferenceMatches(reference string, entry core.HostAuth) bool {
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return false
	}
	if entry.AuthIndex != "" && reference == entry.AuthIndex {
		return true
	}
	for _, candidate := range []string{entry.ID, entry.Name, core.FileIDFromFileName(entry.Name)} {
		if candidate != "" && strings.EqualFold(reference, candidate) {
			return true
		}
	}
	return false
}

func sameCredentialStateEntry(left, right core.HostAuth) bool {
	return left.Name == right.Name && credentialStateAuthIndex(left) == credentialStateAuthIndex(right)
}

func sameCredentialStateIdentity(executing, candidate *core.Credential) bool {
	if executing == nil || candidate == nil {
		return false
	}
	return executing.UIDValue() == "" || executing.UIDValue() == candidate.UIDValue()
}

func (a *App) parseCredentialState(raw []byte, name, vendorID string) (*core.Credential, bool) {
	credential, ok := a.registry.ParseCredential(raw, name, nil)
	return credential, ok && credential.VendorIDValue() == vendorID
}

func (a *App) currentCredentialState(ctx context.Context, prepared preparedExecution) (core.HostAuth, *core.Credential, []byte, bool) {
	if ctx.Err() != nil {
		return core.HostAuth{}, nil, nil, false
	}
	entries, err := hostbridge.ListAuths(ctx, prepared.rpc.HostCallbackID, a.registry)
	if err != nil || ctx.Err() != nil {
		return core.HostAuth{}, nil, nil, false
	}
	reference := core.FirstNonEmpty(prepared.rpc.AuthID, prepared.credential.FileIDValue())
	fileID := prepared.credential.FileIDValue()
	for _, entry := range entries {
		if entry.RuntimeOnly || !validCredentialStateName(entry.Name) || !credentialStateReferenceMatches(reference, entry) {
			continue
		}
		if fileID != "" && !strings.EqualFold(fileID, core.FileIDFromFileName(entry.Name)) {
			continue
		}
		raw, ok := credentialStateJSON(ctx, prepared.rpc.HostCallbackID, entry)
		if !ok || ctx.Err() != nil {
			return core.HostAuth{}, nil, nil, false
		}
		credential, ok := a.parseCredentialState(raw, entry.Name, prepared.vendor.ID())
		if !ok {
			return core.HostAuth{}, nil, nil, false
		}
		return entry, credential, raw, true
	}
	return core.HostAuth{}, nil, nil, false
}

// 使用宿主原有 get 契约，但不调用会原样记录桥错误的降级包装函数。
func credentialStateJSON(ctx context.Context, callbackID string, entry core.HostAuth) ([]byte, bool) {
	index := credentialStateAuthIndex(entry)
	if index == "" || ctx.Err() != nil {
		return nil, false
	}
	raw, err := hostbridge.CallCtx(hostbridge.WithCallbackID(ctx, callbackID), pluginabi.MethodHostAuthGet,
		pluginapi.HostAuthGetRequest{AuthIndex: index})
	if err != nil || ctx.Err() != nil {
		logger.Info("credential state sync deferred (stage=get)")
		return nil, false
	}
	var response pluginapi.HostAuthGetResponse
	if json.Unmarshal(raw, &response) != nil || len(response.JSON) == 0 {
		return nil, false
	}
	if response.AuthIndex != "" && response.AuthIndex != index {
		return nil, false
	}
	if response.Name != "" && response.Name != entry.Name {
		return nil, false
	}
	return response.JSON, true
}
