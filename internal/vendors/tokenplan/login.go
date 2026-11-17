package tokenplan

import (
	"context"
	"freetier2api-plugin/internal/core"
)

// AuthMode 声明控制台使用完整 API Key 输入，不提供 OAuth 登录流程。
func (v *adapter) AuthMode() string { return "apikey" }

// validateCredential 通过只读模型接口校验 Key；Key 不需要换取或续期。
func validateCredential(ctx context.Context, baseURL string, cred *Credential) (core.NativeRefresh[*Credential], error) {
	_, err := FetchModels(ctx, baseURL, cred.APIKey)
	return core.NativeRefresh[*Credential]{Native: cred, Token: cred.APIKey}, err
}
