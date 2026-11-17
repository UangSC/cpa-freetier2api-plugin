package admin

import (
	"strings"

	"freetier2api-plugin/internal/core"
)

// vendorDescriptor 是供应商的展示描述（供页面下拉与分组用）。
type vendorDescriptor struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Region          string `json:"region"`
	SupportsCheckin bool   `json:"supports_checkin"`
	AuthMode        string `json:"auth_mode"`
	SupportsLogin   bool   `json:"supports_login"`
	// CredentialImport 报告该供应商支持粘贴已有登录凭证 JSON。
	CredentialImport bool `json:"credential_import"`
	// CredentialImportHint 是供应商给用户的凭证获取和导入说明。
	CredentialImportHint string `json:"credential_import_hint,omitempty"`
	// QuotaCredentialHint 为账号授权表单提供可选的余额绑定说明。
	QuotaCredentialHint string `json:"quota_credential_hint,omitempty"`
	QuotaAuthorization  bool   `json:"quota_authorization,omitempty"`
	// SMSLogin 报告该供应商支持「手机号 + 短信验证码」两步登录表单。
	SMSLogin bool `json:"sms_login"`
	// PasteCallback 报告该供应商的登录是否需要（也支持）「粘贴 localhost 回调链接」兜底。
	PasteCallback bool `json:"paste_callback"`
	// CallbackHint 是页面要展示的本机回调地址（仅 PasteCallback 为真时有值）。
	CallbackHint string `json:"callback_hint,omitempty"`
	// LoginCaptcha 报告登录前是否需要页面内的人机验证控件。
	LoginCaptcha bool `json:"login_captcha"`
	// LoginVariants 是同一供应商可选的登录变体（如 AutoClaw 的 Zai / Google）。
	LoginVariants []core.LoginVariant `json:"login_variants,omitempty"`
}

func (s *Service) buildVendorsPayload() map[string]any {
	cfg := s.deps.Config()
	vendors := make([]vendorDescriptor, 0, len(s.registry.Vendors()))
	for _, vendor := range s.registry.Vendors() {
		if !core.RealmEnabled(cfg.EnabledRealms, vendor.Region()) {
			continue
		}
		descriptor := vendorDescriptor{
			ID:              vendor.ID(),
			Name:            vendor.Name(),
			Region:          vendor.Region(),
			SupportsCheckin: core.SupportsCheckin(vendor),
			AuthMode:        vendorAuthMode(vendor),
			SupportsLogin:   vendorSupportsLogin(vendor),
		}
		if _, okSMS := core.As[core.SMSLoginProvider](vendor); okSMS {
			descriptor.SMSLogin = true
		}
		if importer, okImport := core.As[core.CredentialImportProvider](vendor); okImport {
			descriptor.CredentialImport = true
			descriptor.CredentialImportHint = strings.TrimSpace(importer.CredentialImportHint())
		}
		if provider, ok := core.As[core.QuotaCredentialProvider](vendor); ok {
			descriptor.QuotaCredentialHint = strings.TrimSpace(provider.QuotaCredentialHint())
		}
		if _, ok := core.As[core.QuotaAuthorizationProvider](vendor); ok {
			descriptor.QuotaAuthorization = true
		}
		if submitter, okSubmit := core.As[core.CallbackSubmitter](vendor); okSubmit {
			descriptor.PasteCallback = true
			descriptor.CallbackHint = strings.TrimSpace(submitter.LocalCallbackHint())
		}
		if _, okCaptcha := core.As[core.LoginCaptchaProvider](vendor); okCaptcha {
			descriptor.LoginCaptcha = true
		}
		if variants, okVariants := core.As[core.LoginVariantProvider](vendor); okVariants {
			descriptor.LoginVariants = variants.LoginVariants()
		}
		vendors = append(vendors, descriptor)
	}
	return map[string]any{"ok": true, "vendors": vendors}
}

func vendorAuthMode(vendor core.Vendor) string {
	if reporter, okReporter := vendor.(core.AuthModeReporter); okReporter {
		if mode := strings.TrimSpace(reporter.AuthMode()); mode != "" {
			return mode
		}
	}
	return "oauth"
}

func vendorSupportsLogin(vendor core.Vendor) bool {
	if _, okLogin := core.As[core.LoginProvider](vendor); okLogin {
		return true
	}
	// 短信验证码登录也是登录（控制台渲染两步表单而不是授权链接）。
	if _, okSMS := core.As[core.SMSLoginProvider](vendor); okSMS {
		return true
	}
	return false
}
