package tokenplan

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"freetier2api-plugin/internal/hostbridge"
)

func TestKnownModelsRetainVerifiedDefaultsWithoutMetadata(t *testing.T) {
	items := []map[string]any{}
	for id := range defaultContextLengths {
		items = append(items, map[string]any{"id": id})
	}
	body, _ := json.Marshal(map[string]any{"object": "list", "data": items})
	models, err := parseModels(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 11 {
		t.Fatal("已验证模型默认值不完整")
	}
	for _, model := range models {
		if model.ContextLength != defaultContextLengths[model.ID] || model.ContextLength <= 0 {
			t.Fatalf("%s 缺少已验证的默认上下文", model.ID)
		}
	}
}

func TestRoutedSchemaContextTakesPrecedenceAndIgnoresImageUnits(t *testing.T) {
	body := []byte(`{"object":"list","data":[{"id":"Atria-Dawn-Preview","context_length":123,"input_modalities":[{"type":"text","supported_inputs":{"max_context_length":{"value":524288,"unit":"token"}}},{"type":"image","supported_inputs":{"max_context_length":{"value":99999999,"unit":"pixel"}}}]},{"id":"future-model"}]}`)
	models, reported, err := parseModelsWithContexts(body)
	if err != nil {
		t.Fatal(err)
	}
	if models[0].ContextLength != 524288 || reported["Atria-Dawn-Preview"] != 524288 {
		t.Fatal("未读取路由返回的真实 token 上限")
	}
	if models[1].ContextLength != 0 {
		t.Fatal("不能为未知模型编造上下文")
	}
}

func TestPublicMetadataCannotEraseDefaultsOrOverrideRoutedContext(t *testing.T) {
	for _, withReported := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "routed"}[withReported], func(t *testing.T) {
			hostbridge.Configure(func(_, _ string, payload any) (json.RawMessage, error) {
				raw, _ := json.Marshal(payload)
				body := `{"object":"list","data":[{"id":"intern-s2"}]}`
				if strings.Contains(string(raw), "/public/models") {
					body = `{"code":0,"data":{"total":1,"models":[{"id":"intern-s2","display_name":"书生-S2","context_length":0}]}}`
				} else if withReported {
					body = `{"object":"list","data":[{"id":"intern-s2","context_length":131072}]}`
				}
				return json.Marshal(map[string]any{"StatusCode": http.StatusOK, "Body": []byte(body)})
			})
			t.Cleanup(func() { hostbridge.Configure(nil) })
			models, err := FetchModels(context.Background(), "", "fake-key")
			if err != nil {
				t.Fatal(err)
			}
			want := int64(262144)
			if len(models) != 1 || models[0].ContextLength != want {
				t.Fatal("外部模型信息不能覆盖插件固定上下文")
			}
		})
	}
}
