package admin

import (
	"context"
	"testing"

	"freetier2api-plugin/cpasdk/pluginapi"
	"freetier2api-plugin/internal/core"
)

type credentialImportTestVendor struct{ fakeVendor }

func (credentialImportTestVendor) CredentialImportHint() string {
	return "  从已登录客户端导出凭证 JSON  "
}

type apiKeyImportTestVendor struct{ credentialImportTestVendor }

func (apiKeyImportTestVendor) AuthMode() string { return "apikey" }

type oauthImportTestVendor struct{ credentialImportTestVendor }

func (oauthImportTestVendor) LoginStart(context.Context, map[string]any) (*pluginapi.AuthLoginStartResponse, error) {
	return nil, nil
}

func (oauthImportTestVendor) LoginPoll(context.Context, string) (*pluginapi.AuthLoginPollResponse, error) {
	return nil, nil
}

func TestVendorsCredentialImportIsIndependentOfLoginAndAPIKey(t *testing.T) {
	deps := newStubDeps(t)
	base := func(id string) fakeVendor {
		return fakeVendor{Meta: core.Meta{VendorID: id, VendorName: id, VendorRegion: "cn"}}
	}
	for _, vendor := range []core.Vendor{
		&fakeVendor{Meta: core.Meta{VendorID: "plain", VendorName: "plain", VendorRegion: "cn"}},
		&apiKeyImportTestVendor{credentialImportTestVendor{base("api-import")}},
		&oauthImportTestVendor{credentialImportTestVendor{base("oauth-import")}},
	} {
		if err := deps.registry.Register(vendor); err != nil {
			t.Fatal(err)
		}
	}
	rows := newServiceWithDeps(t, deps).buildVendorsPayload()["vendors"].([]vendorDescriptor)
	if len(rows) != 3 {
		t.Fatalf("vendors = %#v", rows)
	}
	if rows[0].CredentialImport || rows[0].CredentialImportHint != "" {
		t.Fatal("未声明导入能力的渠道不应出现导入入口")
	}
	if !rows[1].CredentialImport || rows[1].AuthMode != "apikey" || rows[1].SupportsLogin {
		t.Fatalf("导入能力不应改变 API Key 登录方式: %#v", rows[1])
	}
	if !rows[2].CredentialImport || rows[2].AuthMode != "oauth" || !rows[2].SupportsLogin {
		t.Fatalf("OAuth 登录与导入能力应能同时声明: %#v", rows[2])
	}
	for _, row := range rows[1:] {
		if row.CredentialImportHint != "从已登录客户端导出凭证 JSON" {
			t.Fatalf("导入说明未归一化: %q", row.CredentialImportHint)
		}
	}
}
