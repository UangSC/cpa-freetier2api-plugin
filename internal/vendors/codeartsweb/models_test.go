package codeartsweb

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"freetier2api-plugin/internal/core"
)

func modelFixture(t *testing.T) map[string]any {
	t.Helper()
	var fixture map[string]any
	err := json.Unmarshal([]byte(`{"data":{"gpts":{"models":[{"model_name":"DeepSeek-V4.1-Flash-1017","model_parameters":{"model_id":"deepseek-v4.1-flash-1017","context_window":1048576,"input_length":1044480,"output_context_window":0,"max_tokens":65536}},{"model_name":"disabled","enable":false,"model_parameters":{"model_id":"disabled"}}]}}}`), &fixture)
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestModelParametersKeepInputAndContextSeparate(t *testing.T) {
	models := parseModels(modelFixture(t))
	if len(models) != 1 || models[0].ID != "deepseek-v4.1-flash-1017" {
		t.Fatalf("模型解析错误：%v", models)
	}
	model := models[0]
	if model.ContextWindow != 1048576 || model.Input != 1044480 || model.MaxOutput != 65536 {
		t.Fatalf("不得覆盖上游限制：%+v", model)
	}
}

func TestImportVerifiesIdentityAndAddsRoutingPrefix(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/rest/me" {
			t.Errorf("身份路径错误：%s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"userId":"test-user","userName":"Test User"}`))
	}))
	defer server.Close()
	v := Instances(core.Env{})[0].(*adapter)
	v.client = webClient{baseURL: server.URL, httpClient: server.Client()}
	canonical, err := v.PrepareCredentialImport(context.Background(), []byte(`{"cookie":"sid=test; webcftk=csrf","cftk":"csrf","disabled":false}`))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if json.Unmarshal(canonical, &fields) != nil || fields["prefix"] != VendorID || fields["user_id"] != "test-user" || fields["vendor"] != VendorID {
		t.Fatal("必须保存已验证身份和路由前缀")
	}
	if fields["disabled"] != false {
		t.Fatal("不得丢弃宿主字段")
	}
}

func TestModelsForAuthReportsClientToolBridge(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/chat/rest/me" {
			_, _ = w.Write([]byte(`{"userId":"test-user","userName":"Test User"}`))
			return
		}
		if r.Header.Get("Agent-Type") != "AgentCenter" {
			t.Error("缺少网页模型请求的 Agent-Type")
		}
		_ = json.NewEncoder(w).Encode(modelFixture(t))
	}))
	defer server.Close()
	v := Instances(core.Env{})[0].(*adapter)
	v.client = webClient{baseURL: server.URL, httpClient: server.Client()}
	cred, err := v.Parse([]byte(`{"cookie":"sid=test; webcftk=csrf","cftk":"csrf"}`), "codeartsweb-test.json")
	if err != nil {
		t.Fatal(err)
	}
	models, err := v.ModelsForAuth(context.Background(), cred)
	if err != nil || len(models) != 1 {
		t.Fatalf("模型探测失败：%v", err)
	}
	model := models[0]
	if model.ID != "deepseek-v4.1-flash-1017" || model.InputTokenLimit != 1044480 || model.ContextLength != 1048576 {
		t.Fatalf("元数据错误：%+v", model)
	}
	if !core.ModelSupportsTools(model) || core.ModelSupportsImages(model) {
		t.Fatal("必须报告客户端函数桥接，不能报告未实现的图像能力")
	}
}

func TestCredentialMergePreservesHostSettings(t *testing.T) {
	cred, err := ParseCredential([]byte(`{"cookie":"sid=new; webcftk=new-csrf","cftk":"new-csrf"}`))
	if err != nil {
		t.Fatal(err)
	}
	merged, err := mergeCredential([]byte(`{"vendor":"codeartsweb","cookie":"sid=old","prefix":"custom","disabled":true,"proxy_url":"http://proxy.test","label":"自定义备注"}`), cred)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	_ = json.Unmarshal(merged, &result)
	if result["cookie"] != "sid=new; webcftk=new-csrf" || result["prefix"] != "custom" || result["disabled"] != true || result["label"] != "自定义备注" {
		t.Fatal("Cookie轮换不能覆盖宿主配置")
	}
}
