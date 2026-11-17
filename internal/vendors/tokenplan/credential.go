package tokenplan

import (
	"encoding/json"
	"errors"
	"strings"
	"unicode"

	"freetier2api-plugin/internal/core"
)

const VendorID = "tokenplan"
const VendorName = "书生 Token Plan"

func (v *adapter) APIKeyAccountIdentity(apiKey string) string { return "t" + keyHash(apiKey) }

type Credential struct {
	APIKey         string
	Label          string
	UserID         string
	BalanceToken   string
	BalanceKeyHash string
	Raw            map[string]any
}

func ParseCredential(raw []byte) (*Credential, error) {
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil || payload == nil {
		return nil, errors.New("Token Plan 凭证必须是 JSON 对象")
	}
	if kind := strings.TrimSpace(core.GetString(payload, "type")); kind != "" && kind != core.ProviderKey {
		return nil, errors.New("凭证属于其他认证提供方")
	}
	if vendor := strings.TrimSpace(core.GetString(payload, "vendor")); vendor != "" && vendor != VendorID {
		return nil, errors.New("凭证属于其他平台")
	}
	key := core.FirstNonEmpty(core.GetString(payload, "api_key"), core.GetString(payload, "apikey"), core.GetString(payload, "tokenplan_key"))
	key = strings.TrimSpace(key)
	if key == "" || len(key) > 8192 || strings.IndexFunc(key, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return nil, errors.New("请填写 Token Plan 页面创建的完整 API Key")
	}
	return &Credential{APIKey: key, Label: strings.TrimSpace(core.GetString(payload, "label")), UserID: core.GetString(payload, "user_id"), BalanceToken: core.GetString(payload, "balance_token"), BalanceKeyHash: core.GetString(payload, "balance_key_hash"), Raw: payload}, nil
}

func LooksLikeCredential(raw map[string]any, fileName, provider string) bool {
	if kind := strings.TrimSpace(core.GetString(raw, "type")); kind != "" && kind != core.ProviderKey {
		return false
	}
	if provider = strings.TrimSpace(provider); provider != "" && provider != core.ProviderKey && provider != VendorID {
		return false
	}
	if vendor := strings.TrimSpace(core.GetString(raw, "vendor")); vendor != "" {
		return vendor == VendorID
	}
	return strings.EqualFold(strings.TrimSpace(provider), VendorID) ||
		core.FileNameMatchesConvention(fileName, VendorID) || strings.TrimSpace(core.GetString(raw, "tokenplan_key")) != ""
}
