package codeartsweb

import (
	"context"
	"encoding/json"

	"freetier2api-plugin/internal/core"
)

// 网页账号采用已有会话导入；不把 IDE 的 OAuth 票据冒充为网页 Cookie。
func (v *adapter) AuthMode() string { return "cookie" }

func (v *adapter) CredentialImportHint() string {
	return "导入华为码道网页登录会话 JSON（cookie、cftk、headers），或含 curl 字段的 JSON。headers 保存浏览器 User-Agent 和客户端提示头。保存时会校验身份，默认添加 codeartsweb 模型前缀；会话过期后请重新导入。"
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
