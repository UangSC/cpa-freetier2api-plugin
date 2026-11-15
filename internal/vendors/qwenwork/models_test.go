package qwenwork

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"freetier2api-plugin/cpasdk/pluginabi"
	"freetier2api-plugin/internal/core"
	"freetier2api-plugin/internal/hostbridge"
)

// 仅保留公开模型清单中三个 qwork 记录的必要字段，不包含真实凭证。
const modelsTestCatalog = `{"qwork":[
 {"key":"flash","enable":true,"max_input_tokens":1000000,"price_factor":0.1,"context_config":{"1M":{"token_count":1000000},"200K":{"token_count":200000},"400K":{"token_count":400000}},"i18n":{"display_name":{"en":"Standard","zh":"标准"},"description":{"zh":"极速全能，秒杀日常任务"}}},
 {"key":"pro","enable":true,"max_input_tokens":1000000,"price_factor":1,"i18n":{"display_name":{"en":"Pro","zh":"高级"}}},
 {"key":"frontier-1","enable":true,"max_input_tokens":1000000,"price_factor":0.4,"context_config":{"1M":{"token_count":1000000},"200k":{"token_count":200000},"400k":{"token_count":400000}},"i18n":{"display_name":{"en":"Qwen4-Max-Preview","zh":"Qwen4-Max 预览版"}}}
]}`

func TestModelsParseOfficialNamesAndMillionTokenWindows(t *testing.T) {
	models, err := parseModels([]byte(modelsTestCatalog))
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 3 {
		t.Fatalf("model count = %d, want 3", len(models))
	}
	for i, expected := range []struct {
		id, mode, name string
		factor         float64
	}{
		{"Standard", "flash", "标准", 0.1},
		{"Pro", "pro", "高级", 1},
		{"Qwen4-Max-Preview", "frontier-1", "Qwen4-Max 预览版", 0.4},
	} {
		if models[i].ID != expected.id || models[i].Mode != expected.mode || models[i].Name != expected.name || models[i].CostFactor != expected.factor {
			t.Fatalf("model %d 未正确保留官方标识、模式与倍率", i)
		}
		if models[i].ContextLength != 1_000_000 {
			t.Fatalf("model %s context = %d, want 1000000", models[i].ID, models[i].ContextLength)
		}
	}
}

func TestModelsContextComesFromAdvertisedTokenCounts(t *testing.T) {
	for _, tc := range []struct {
		name, fields string
		want         int64
	}{
		{"max-input-only", `"max_input_tokens":400000`, 400_000},
		{"context-choice-larger", `"max_input_tokens":200000,"context_config":{"large":{"token_count":1000000}}`, 1_000_000},
		{"max-input-larger", `"max_input_tokens":1000000,"context_config":{"small":{"token_count":200000}}`, 1_000_000},
		{"absent-is-unknown", `"description":"unknown window"`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			models, err := parseModels([]byte(`{"qwork":[{"key":"custom",` + tc.fields + `}]}`))
			if err != nil {
				t.Fatal(err)
			}
			if models[0].ContextLength != tc.want {
				t.Fatalf("context = %d, want %d，不应凭模型名或全局默认补一个 1M", models[0].ContextLength, tc.want)
			}
		})
	}
}

func TestModelsSkipDisabledAndMissingKeys(t *testing.T) {
	models, err := parseModels([]byte(`{"qwork":[
 {"key":"disabled","enable":false,"max_input_tokens":1000000},
 {"key":"","enable":true},
 {"key":"available","max_input_tokens":200000}
]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 1 || models[0].ID != "available" || models[0].Mode != "available" || models[0].ContextLength != 200_000 {
		t.Fatalf("禁用模型或空标识未被过滤: %#v", models)
	}
	for _, data := range []string{`{`, `null`, `[]`, `{}`, `{"qwork":[]}`, `{"qwork":[{"key":"disabled","enable":false}]}`} {
		if _, err := parseModels([]byte(data)); err == nil {
			t.Fatalf("没有有效模型的清单不得伪造默认模型: %s", data)
		}
	}
}

// 模拟 CPA 的 HTTP 回调，不打开网络连接。
func modelsTestHost(t *testing.T, handler func(string) (int, string)) *[]string {
	t.Helper()
	paths := []string{}
	hostbridge.Configure(func(_ string, method string, payload any) (json.RawMessage, error) {
		if method != pluginabi.MethodHostHTTPDo {
			return nil, fmt.Errorf("unexpected host method %s", method)
		}
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		var request struct{ Method, URL string }
		if err := json.Unmarshal(data, &request); err != nil {
			return nil, err
		}
		u, err := url.Parse(request.URL)
		if err != nil {
			return nil, err
		}
		if request.Method != http.MethodGet || u.Scheme != "https" || (u.Host != "qwenwork.cn" && u.Host != "gateway.qwenwork.cn") {
			return nil, fmt.Errorf("unexpected mocked model request")
		}
		paths = append(paths, u.Path)
		status, body := handler(u.Path)
		return json.Marshal(map[string]any{"StatusCode": status, "Headers": http.Header{"Content-Type": {"application/json"}}, "Body": []byte(body)})
	})
	t.Cleanup(func() { hostbridge.Configure(nil) })
	return &paths
}

func TestModelsRegisterNamesModesAndCreditsFromSameCatalog(t *testing.T) {
	paths := modelsTestHost(t, func(path string) (int, string) {
		if path == "/user/info" {
			return http.StatusOK, `{"user_id":"user-1","org_id":"org-1","team_id":"team-1"}`
		}
		if path != "/algo/api/v2/model/list" {
			t.Fatalf("unexpected mocked path %s", path)
		}
		return http.StatusOK, modelsTestCatalog
	})
	v := Instances(core.Env{})[0].(*adapter)
	credential, err := v.Parse(credentialTestJSON(t, map[string]any{"token": credentialTestJWT(t, nil)}), "qwenwork-user-1.json")
	if err != nil {
		t.Fatal(err)
	}
	models, err := v.ModelsForAuth(context.Background(), credential)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*paths, []string{"/user/info", "/algo/api/v2/model/list"}) {
		t.Fatalf("注册模型前必须确认登录凭证，再读清单: %v", *paths)
	}
	if len(models) != 3 {
		t.Fatalf("models = %d, want 3", len(models))
	}
	for _, model := range models {
		if model.ContextLength != 1_000_000 || model.InputTokenLimit != 1_000_000 || core.ModelSupportsImages(model) || !core.ModelSupportsTools(model) {
			t.Fatalf("注册能力与原始模型适配器不一致: %s", model.ID)
		}
	}
	if !reflect.DeepEqual(v.ModelCredits(), map[string]string{"Standard": "0.10X", "Pro": "1.00X", "Qwen4-Max-Preview": "0.40X"}) {
		t.Fatalf("credits = %v", v.ModelCredits())
	}
	native := credential.Native.(*Credential)
	for _, model := range []string{"Qwen4-Max-Preview", "frontier-1"} {
		if mode, err := v.modeFor(context.Background(), native, model); err != nil || mode != "frontier-1" {
			t.Fatalf("对外模型与原始 mode 应映射到同一上游模式: %s", model)
		}
	}
	if len(*paths) != 2 {
		t.Fatal("已有模式映射不应重复查询清单")
	}
}

func TestModelsDoNotQueryCatalogAfterCredentialRejected(t *testing.T) {
	paths := modelsTestHost(t, func(path string) (int, string) {
		if path != "/user/info" {
			t.Fatalf("鉴权失败后仍查询了模型清单: %s", path)
		}
		return http.StatusUnauthorized, `{"code":"unauthorized"}`
	})
	v := Instances(core.Env{})[0].(*adapter)
	credential, err := v.Parse(credentialTestJSON(t, map[string]any{"token": credentialTestJWT(t, nil)}), "qwenwork-user-1.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.ModelsForAuth(context.Background(), credential); err == nil {
		t.Fatal("被上游拒绝的凭证不能注册公共模型清单")
	}
	if len(*paths) != 1 {
		t.Fatalf("mock request count = %d, want 1", len(*paths))
	}
}

func TestModelsDropDisabledModeMappingsWhenCatalogChanges(t *testing.T) {
	current := modelsTestCatalog
	modelsTestHost(t, func(path string) (int, string) {
		if path != "/algo/api/v2/model/list" {
			t.Fatalf("unexpected mocked path %s", path)
		}
		return http.StatusOK, current
	})
	v := Instances(core.Env{})[0].(*adapter)
	credential := credentialTestParse(t, map[string]any{})
	if _, err := v.modelsFor(context.Background(), credential); err != nil {
		t.Fatal(err)
	}
	current = `{"qwork":[{"key":"flash","enable":false,"i18n":{"display_name":{"en":"Standard"}}},{"key":"pro","enable":true,"i18n":{"display_name":{"en":"Pro"}}}]}`
	if _, err := v.modelsFor(context.Background(), credential); err != nil {
		t.Fatal(err)
	}
	if _, err := v.modeFor(context.Background(), credential, "Standard"); err == nil {
		t.Fatal("已禁用模型不能继续命中旧映射")
	} else {
		var failure *core.PluginError
		if !errors.As(err, &failure) || failure.HTTPStatus != http.StatusNotFound {
			t.Fatalf("未知或禁用模型应返回 404: %v", err)
		}
	}
	current = `{"qwork":[{"key":"pro","enable":false,"i18n":{"display_name":{"en":"Pro"}}}]}`
	if _, err := v.modelsFor(context.Background(), credential); err == nil {
		t.Fatal("上游禁用全部模型应明确失败")
	}
	if _, err := v.modeFor(context.Background(), credential, "Pro"); err == nil {
		t.Fatal("成功读取到全部禁用的清单后，不能继续命中缓存模型")
	}
}
