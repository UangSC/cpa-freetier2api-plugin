package codeartsweb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"

	"freetier2api-plugin/cpasdk/pluginapi"
	"freetier2api-plugin/internal/core"
)

// adapter 使用网页会话凭证，与原 CodeArts 的签名凭证分别归属。
type adapter struct {
	*core.NativeAdapter[*Credential]
	client    webClient
	refreshMu sync.Mutex
}

func Instances(env core.Env) []core.Vendor {
	v := &adapter{client: webClient{baseURL: webOrigin}}
	v.NativeAdapter = core.NewNativeAdapter(core.NativeSpec[*Credential]{
		Meta: core.Meta{VendorID: VendorID, VendorName: "CodeArts 网页版", VendorRegion: "cn"}, Env: env,
		Extract: func(cred *core.Credential) (*Credential, bool) {
			native, ok := cred.Native.(*Credential)
			return native, ok && native != nil
		},
		ParseSeed: func(raw []byte, fileName string) (core.CredentialSeed, *Credential, error) {
			native, err := ParseCredential(raw)
			if err != nil {
				return core.CredentialSeed{}, nil, err
			}
			snapshot := native.snapshot()
			label := snapshot.Label
			if label == "" {
				label = core.FirstNonEmpty(snapshot.UserName, snapshot.UserID, "CodeArts 网页账号")
			}
			return core.CredentialSeed{VendorID: VendorID, Region: "cn", Label: label, UID: snapshot.UserID,
				FileID: core.FileIDFromFileName(fileName), Token: cookieFingerprint(snapshot.Cookie), AuthMode: "cookie"}, native, nil
		},
		MergeNative: mergeCredential,
	})
	return []core.Vendor{v}
}

func cookieFingerprint(cookie string) string {
	digest := sha256.Sum256([]byte(cookie))
	return hex.EncodeToString(digest[:])
}

// Refresh 对比宿主上次保存的指纹，捕获聊天或模型响应已轮换的 Cookie。
// 刷新失败时不推进指纹；成功后仍由宿主 MergeStorageJSON 保存，不直接写账号文件。
func (v *adapter) Refresh(ctx context.Context, cred *core.Credential) (*core.Credential, bool, error) {
	v.refreshMu.Lock()
	defer v.refreshMu.Unlock()
	native, err := v.Native(cred)
	if err != nil {
		return nil, false, err
	}
	storedFingerprint := cred.TokenValue()
	before := native.snapshot()
	if err := v.verifyIdentity(ctx, native); err != nil {
		return nil, false, err
	}
	after := native.snapshot()
	currentFingerprint := cookieFingerprint(after.Cookie)
	profileChanged := before.UserID != after.UserID || before.UserName != after.UserName
	if storedFingerprint == currentFingerprint {
		return cred, profileChanged, nil
	}
	changed := cred.ApplyTokenRefresh(currentFingerprint, "", 0)
	return cred, changed || profileChanged, nil
}

func (v *adapter) HasPendingCredentialState(cred *core.Credential) bool {
	native, err := v.Native(cred)
	return err == nil && cookieFingerprint(native.snapshot().Cookie) != cred.TokenValue()
}

// 只确认实际保存的 Cookie；保存期间发生的新轮换仍应保持 pending。
func (v *adapter) CredentialStatePersisted(cred *core.Credential, persistedJSON []byte) {
	v.refreshMu.Lock()
	defer v.refreshMu.Unlock()
	native, err := v.Native(cred)
	if err != nil || cred.VendorIDValue() != VendorID {
		return
	}
	persisted, err := ParseCredential(persistedJSON)
	if err != nil {
		return
	}
	current := native.snapshot()
	saved := persisted.snapshot()
	if current.UserID != "" && current.UserID != saved.UserID {
		return
	}
	cred.ApplyTokenRefresh(cookieFingerprint(saved.Cookie), "", 0)
}

func (v *adapter) Match(fileName, provider string, raw map[string]any) bool {
	if provider != "" && provider != core.ProviderKey {
		return false
	}
	for _, key := range []string{"type", "provider"} {
		if value, _ := raw[key].(string); value != "" && value != core.ProviderKey {
			return false
		}
	}
	if vendor, _ := raw[core.VendorKey].(string); vendor != "" {
		return vendor == VendorID
	}
	return strings.HasPrefix(strings.ToLower(fileName), VendorID+"-")
}

// 网页账号的权限清单以本次身份校验为准。
func (v *adapter) VetoModelFallback() bool { return true }

func (v *adapter) verifyIdentity(ctx context.Context, cred *Credential) error {
	response, err := v.client.json(ctx, cred, "GET", "/chat/rest/me", nil, "")
	if err != nil {
		return err
	}
	identity := unwrapObject(response)
	userID, _ := identity["userId"].(string)
	userName, _ := identity["userName"].(string)
	if userID == "" {
		return expiredSessionError()
	}
	return cred.setIdentity(userID, userName)
}

func mergeCredential(original []byte, native *Credential) ([]byte, error) {
	updated, err := native.StorageJSON()
	if err != nil || len(original) == 0 {
		return updated, err
	}
	var existing, fields map[string]any
	if json.Unmarshal(original, &existing) != nil || existing == nil || json.Unmarshal(updated, &fields) != nil {
		return nil, core.NewPluginError("invalid_credential", "原 CodeArts 网页凭证不是 JSON 对象", 400)
	}
	if vendor, _ := existing[core.VendorKey].(string); vendor != "" && vendor != VendorID {
		return nil, core.NewPluginError("invalid_credential", "CodeArts 网页凭证不能写入其他供应商账号", 400)
	}
	for _, key := range []string{"type", "vendor", "cookie", "cftk", "headers", "user_id", "user_name"} {
		if value, exists := fields[key]; exists {
			existing[key] = value
		}
	}
	if _, exists := existing["label"]; !exists {
		existing["label"] = fields["label"]
	}
	return json.Marshal(existing)
}

func (v *adapter) Execute(ctx context.Context, cred *core.Credential, req *core.ExecuteRequest) (*pluginapi.ExecutorResponse, error) {
	native, err := v.Native(cred)
	if err != nil {
		return nil, err
	}
	if err = v.verifyIdentity(ctx, native); err != nil {
		return nil, err
	}
	result, err := runChat(ctx, v.client, native, req.Model, req.Payload, nil)
	if err != nil {
		return nil, err
	}
	return &pluginapi.ExecutorResponse{Payload: result, Headers: map[string][]string{"Content-Type": {core.ContentTypeJSON}}}, nil
}

func (v *adapter) ExecuteStream(ctx context.Context, cred *core.Credential, req *core.ExecuteRequest, sink core.StreamSink) error {
	native, err := v.Native(cred)
	if err != nil {
		return err
	}
	if err = v.verifyIdentity(ctx, native); err != nil {
		return err
	}
	_, err = runChat(ctx, v.client, native, req.Model, req.Payload, sink.Emit)
	return err
}
