package qwenwork

import (
	"context"
	"strings"
	"sync"

	"freetier2api-plugin/internal/core"
)

type adapter struct {
	*core.NativeAdapter[*Credential]
	credentialMu sync.RWMutex
	modelMu      sync.RWMutex
	modelModes   map[string]string
	modelsByMode map[string]Model
	credits      core.CreditTable
}

func Instances(env core.Env) []core.Vendor {
	v := &adapter{modelModes: make(map[string]string), modelsByMode: make(map[string]Model)}
	v.NativeAdapter = core.NewNativeAdapter(core.NativeSpec[*Credential]{
		Meta: core.Meta{VendorID: vendorID, VendorName: "千问办公", VendorRegion: "cn"}, Env: env,
		Extract: func(credential *core.Credential) (*Credential, bool) {
			native, ok := credential.Native.(*Credential)
			return native, ok
		},
		ParseSeed: func(raw []byte, fileName string) (core.CredentialSeed, *Credential, error) {
			native, err := ParseCredential(raw)
			if err != nil {
				return core.CredentialSeed{}, nil, err
			}
			return core.CredentialSeed{VendorID: vendorID, Region: "cn", Label: native.Label, UID: native.UserID,
				FileID: core.FileIDFromFileName(fileName), Token: native.Token, RefreshToken: native.RefreshToken, ExpiresAt: native.ExpiresAt, AuthMode: "oauth"}, native, nil
		},
		RefreshNative: func(ctx context.Context, credential *Credential) (core.NativeRefresh[*Credential], error) {
			updated, changed, err := RefreshCredential(ctx, credential)
			if err != nil {
				return core.NativeRefresh[*Credential]{}, err
			}
			return core.NativeRefresh[*Credential]{Native: updated, Token: updated.Token, RefreshToken: updated.RefreshToken, ExpiresAt: updated.ExpiresAt, Changed: changed}, nil
		}, MergeNative: mergeStorage,
	})
	return []core.Vendor{v}
}

func (v *adapter) Match(fileName, provider string, raw map[string]any) bool {
	if provider != "" && provider != core.ProviderKey {
		return false
	}
	for _, key := range []string{"type", "provider"} {
		if declared := stringIn(raw, key); declared != "" && declared != core.ProviderKey {
			return false
		}
	}
	if declared := stringIn(raw, "vendor"); declared != "" {
		return declared == vendorID
	}
	if strings.HasPrefix(strings.ToLower(fileName), vendorID+"-") {
		return true
	}
	_, err := tokenClaims(stringIn(raw, "token", "access_token", "accessToken"))
	return err == nil
}

func (v *adapter) Native(credential *core.Credential) (*Credential, error) {
	v.credentialMu.RLock()
	defer v.credentialMu.RUnlock()
	return v.NativeAdapter.Native(credential)
}

func (v *adapter) Refresh(ctx context.Context, credential *core.Credential) (*core.Credential, bool, error) {
	v.credentialMu.Lock()
	defer v.credentialMu.Unlock()
	return v.NativeAdapter.Refresh(ctx, credential)
}

func (v *adapter) MergeStorageJSON(original []byte, credential *core.Credential) ([]byte, error) {
	v.credentialMu.RLock()
	defer v.credentialMu.RUnlock()
	return v.NativeAdapter.MergeStorageJSON(original, credential)
}
