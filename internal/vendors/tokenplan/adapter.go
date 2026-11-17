package tokenplan

import (
	"context"
	"strings"
	"sync"

	"freetier2api-plugin/cpasdk/pluginapi"
	"freetier2api-plugin/internal/core"
	"freetier2api-plugin/internal/hostbridge"
)

type adapter struct {
	*core.NativeAdapter[*Credential]
	baseURL           string
	quotaAuthSessions sync.Map
}

func Instances(env core.Env) []core.Vendor {
	inst := &adapter{}
	inst.NativeAdapter = core.NewNativeAdapter(core.NativeSpec[*Credential]{
		Meta: core.Meta{VendorID: VendorID, VendorName: VendorName, VendorRegion: "cn"}, Env: env,
		Extract: func(c *core.Credential) (*Credential, bool) { value, ok := c.Native.(*Credential); return value, ok },
		ParseSeed: func(raw []byte, fileName string) (core.CredentialSeed, *Credential, error) {
			cred, err := ParseCredential(raw)
			if err != nil {
				return core.CredentialSeed{}, nil, err
			}
			return core.CredentialSeed{VendorID: VendorID, Region: "cn", FileID: core.FileIDFromFileName(fileName),
				Label: core.FirstNonEmpty(cred.Label, core.MaskKey(cred.APIKey)), Token: cred.APIKey, AuthMode: "apikey"}, cred, nil
		},
		RefreshNative: func(ctx context.Context, cred *Credential) (core.NativeRefresh[*Credential], error) {
			return validateCredential(ctx, inst.baseURL, cred)
		},
	})
	return []core.Vendor{inst}
}

func (v *adapter) Match(fileName, provider string, raw map[string]any) bool {
	return LooksLikeCredential(raw, fileName, provider)
}
func (v *adapter) Configure(_ core.Settings, settings map[string]string) {
	v.baseURL = strings.TrimSpace(settings["tokenplan_base_url"])
}
func (v *adapter) ConfigFields() []pluginapi.ConfigField {
	return []pluginapi.ConfigField{{Name: "tokenplan_base_url", Type: pluginapi.ConfigFieldTypeString, Description: "Token Plan OpenAI API 基地址，默认 https://discovery-api.intern-ai.org.cn/v1。"}}
}
func (v *adapter) StaticModels(ctx context.Context) ([]pluginapi.ModelInfo, error) {
	cred, ok := core.ProbeNativeCredential(v.Env, VendorID, func(c *core.Credential) (*Credential, bool) { value, ok := c.Native.(*Credential); return value, ok })
	if !ok || cred == nil {
		return nil, nil
	}
	return FetchModels(ctx, v.baseURL, cred.APIKey)
}
func (v *adapter) ModelsForAuth(ctx context.Context, credential *core.Credential) ([]pluginapi.ModelInfo, error) {
	cred, err := v.Native(credential)
	if err != nil {
		return nil, err
	}
	return FetchModels(ctx, v.baseURL, cred.APIKey)
}
func (v *adapter) VetoModelFallback() bool { return true }
func (v *adapter) Execute(ctx context.Context, credential *core.Credential, req *core.ExecuteRequest) (*pluginapi.ExecutorResponse, error) {
	cred, err := v.Native(credential)
	if err != nil {
		return nil, err
	}
	req, err = lockExecuteRequest(req)
	if err != nil {
		return nil, err
	}
	body, err := modelBody(req)
	if err != nil {
		return nil, err
	}
	payload, err := Chat(ctx, v.baseURL, cred.APIKey, body)
	if err != nil {
		return nil, core.ToPluginError(err)
	}
	return &pluginapi.ExecutorResponse{Payload: payload, Headers: map[string][]string{"Content-Type": {core.ContentTypeJSON}}}, nil
}
func (v *adapter) ExecuteStream(ctx context.Context, credential *core.Credential, req *core.ExecuteRequest, sink core.StreamSink) error {
	cred, err := v.Native(credential)
	if err != nil {
		return err
	}
	req, err = lockExecuteRequest(req)
	if err != nil {
		return err
	}
	body, err := modelBody(req)
	if err != nil {
		return err
	}
	response, err := ChatStream(ctx, v.baseURL, cred.APIKey, body)
	if err != nil {
		return core.ToPluginError(err)
	}
	defer response.Body.Close()
	return hostbridge.ForwardRawSSE(response.Body, sink.Emit)
}

var (
	_ core.Vendor                     = (*adapter)(nil)
	_ core.ModelsProvider             = (*adapter)(nil)
	_ core.AuthModeReporter           = (*adapter)(nil)
	_ core.Configurable               = (*adapter)(nil)
	_ core.ConfigFieldsProvider       = (*adapter)(nil)
	_ core.ModelFallbackVeto          = (*adapter)(nil)
	_ core.QuotaProvider              = (*adapter)(nil)
	_ core.QuotaCredentialProvider    = (*adapter)(nil)
	_ core.FixedModelContextProvider  = (*adapter)(nil)
	_ core.QuotaAuthorizationProvider = (*adapter)(nil)
)
