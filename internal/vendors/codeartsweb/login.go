package codeartsweb

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"freetier2api-plugin/internal/core"
)

// 网页账号采用已有会话导入；不把 IDE 的 OAuth 票据冒充为网页 Cookie。
func (v *adapter) AuthMode() string { return "cookie" }

func (v *adapter) CredentialImportHint() string {
	return "登录华为码道网页，在 F12 → Network 中打开模型菜单，找到 agents/detail 请求，右键选择 Copy → Copy as cURL (bash)，将整段文本直接粘贴到这里。保存时自动提取 Cookie、cftk 和浏览器请求头，校验账号并生成凭证 JSON，无需手动转换。也支持已有的网页凭证 JSON；会话过期后请重新复制导入。"
}

func (v *adapter) PrepareCredentialCurlImport(ctx context.Context, text string) ([]byte, error) {
	text = strings.TrimSpace(text)
	if len(text) == 0 || len(text) > maxCredentialBytes {
		return nil, fmt.Errorf("cURL 快照为空或超过 256 KiB，请重新复制请求")
	}
	raw, err := json.Marshal(map[string]string{"curl": text})
	if err != nil {
		return nil, fmt.Errorf("无法解析 cURL 快照")
	}
	return v.PrepareCredentialImport(ctx, raw)
}

func (v *adapter) PrepareCredentialImport(ctx context.Context, raw []byte) ([]byte, error) {
	credential, err := ParseCredential(raw)
	if err != nil {
		return nil, err
	}
	if err := v.verifyIdentity(ctx, credential); err != nil {
		return nil, err
	}
	canonical, err := credential.StorageJSON()
	if err != nil {
		return nil, err
	}
	var fields map[string]any
	if err := json.Unmarshal(canonical, &fields); err != nil {
		return nil, err
	}
	fields["type"], fields["vendor"] = core.ProviderKey, VendorID
	if prefix, _ := fields["prefix"].(string); prefix == "" {
		fields["prefix"] = VendorID
	}
	return json.Marshal(fields)
}
