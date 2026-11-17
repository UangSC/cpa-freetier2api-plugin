package tokenplan

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"freetier2api-plugin/internal/core"
	"freetier2api-plugin/internal/hostbridge"
)

func TestCredentialOwnershipAndHeaderValidation(t *testing.T) {
	for _, raw := range []string{`{"api_key":"bad\r\nInjected: value"}`, `{"vendor":"inkstone","api_key":"key"}`, `{"token":"client-sso"}`, `null`} {
		if _, err := ParseCredential([]byte(raw)); err == nil {
			t.Fatalf("无效凭证被接收: %s", raw)
		}
	}
	if LooksLikeCredential(map[string]any{"api_key": "generic"}, "other.json", "freetier") {
		t.Fatal("不应认领其他平台的通用 API Key")
	}
	if LooksLikeCredential(map[string]any{"vendor": "inkstone"}, "tokenplan-example.json", "freetier") {
		t.Fatal("不应按文件名覆盖明确平台归属")
	}
	if !LooksLikeCredential(map[string]any{"vendor": "tokenplan"}, "renamed.json", "freetier") {
		t.Fatal("明确平台归属应可认领")
	}
	if LooksLikeCredential(map[string]any{"vendor": "tokenplan", "type": "openai"}, "tokenplan-key.json", "freetier") || LooksLikeCredential(map[string]any{"vendor": "tokenplan"}, "tokenplan-key.json", "openai") {
		t.Fatal("不应认领其他认证提供方凭证")
	}
}

func TestModelBodyUsesResolvedModelAlias(t *testing.T) {
	for _, stream := range []bool{false, true} {
		body, err := modelBody(&core.ExecuteRequest{Model: "intern-s2", Payload: []byte(`{"model":"custom-alias","messages":[],"stream":true}`)})
		if err != nil {
			t.Fatal(err)
		}
		body, err = prepareBody(body, stream)
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		json.Unmarshal(body, &payload)
		if payload["model"] != "intern-s2" || payload["stream"] != stream {
			t.Fatal("实际请求应使用宿主解析后的官方模型 ID")
		}
	}
}

func TestHTTPRedirectDoesNotForwardAPIKey(t *testing.T) {
	calls := 0
	hostbridge.Configure(func(_, _ string, _ any) (json.RawMessage, error) {
		calls++
		out, _ := json.Marshal(map[string]any{"StatusCode": 302, "Headers": http.Header{"Location": {"https://other.invalid/v1/models"}}, "Body": []byte("redirect")})
		return out, nil
	})
	t.Cleanup(func() { hostbridge.Configure(nil) })
	_, err := FetchModels(context.Background(), "https://test.invalid/v1", "test-key")
	if err == nil || calls != 1 {
		t.Fatalf("API Key 请求不得自动跳转: calls=%d err=%v", calls, err)
	}
}

func TestChatUsesOfficialKeyProtocolAndPreservesTools(t *testing.T) {
	raw := []byte(`{"model":"intern-s2","messages":[{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"a\"}"}}]},{"role":"tool","tool_call_id":"call_1","content":"test"}],"tools":[{"type":"function","function":{"name":"read_file","parameters":{"type":"object"}}}],"tool_choice":"auto","stream":true,"max_completion_tokens":32,"reasoning_effort":"high"}`)
	response := `{"id":"chat_1","choices":[{"message":{"role":"assistant","content":"OK"}}]}`
	hostbridge.Configure(func(_, method string, payload any) (json.RawMessage, error) {
		if method != "host.http.do" {
			t.Fatalf("错误桥接方法: %s", method)
		}
		encoded, _ := json.Marshal(payload)
		var req struct {
			Method  string      `json:"method"`
			URL     string      `json:"url"`
			Headers http.Header `json:"headers"`
			Body    []byte      `json:"body"`
		}
		if err := json.Unmarshal(encoded, &req); err != nil {
			t.Fatal(err)
		}
		if req.Method != "POST" || req.URL != DefaultBaseURL+"/chat/completions" {
			t.Fatalf("错误端点: %s %s", req.Method, req.URL)
		}
		if req.Headers.Get("Authorization") != "Bearer token-plan-key" {
			t.Fatal("API Key 未正确鉴权")
		}
		for _, key := range []string{"id", "X-Inkstone-Device-ID", "X-Inkstone-Native-Scope", "Cookie"} {
			if req.Headers.Get(key) != "" {
				t.Fatalf("Token Plan 不应携带客户端身份头: %s", key)
			}
		}
		var got, original map[string]json.RawMessage
		json.Unmarshal(req.Body, &got)
		json.Unmarshal(raw, &original)
		for _, key := range []string{"messages", "tools", "tool_choice"} {
			if string(got[key]) != string(original[key]) {
				t.Fatalf("工具或历史消息被修改: %s", key)
			}
		}
		if string(got["stream"]) != "false" || string(got["max_tokens"]) != "32" || got["reasoning_effort"] != nil {
			t.Fatal("请求参数未按官方接口规范化")
		}
		out, _ := json.Marshal(map[string]any{"StatusCode": 200, "Headers": http.Header{"Content-Type": {"application/json"}}, "Body": []byte(response)})
		return out, nil
	})
	t.Cleanup(func() { hostbridge.Configure(nil) })
	got, err := Chat(context.Background(), "", "token-plan-key", raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != response {
		t.Fatalf("模型回复被修改: %s", got)
	}
}

type collectingSink struct{ chunks []string }

func (s *collectingSink) Emit(payload []byte) error {
	s.chunks = append(s.chunks, string(payload))
	return nil
}
func (*collectingSink) Close(string) error { return nil }

func TestStreamForwardsNativeOpenAIToolDeltas(t *testing.T) {
	read := false
	closed := false
	chunk := `{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"a\"}"}}]}}]}`
	hostbridge.Configure(func(_, method string, _ any) (json.RawMessage, error) {
		switch method {
		case "host.http.do_stream":
			return json.RawMessage(`{"status_code":200,"stream_id":"test-stream","headers":{"Content-Type":["text/event-stream"]}}`), nil
		case "host.http.stream_read":
			if read {
				return json.RawMessage(`{"done":true}`), nil
			}
			read = true
			out, _ := json.Marshal(map[string]any{"payload": []byte("data: " + chunk + "\n\ndata: [DONE]\n\n")})
			return out, nil
		case "host.http.stream_close":
			closed = true
			return json.RawMessage(`{}`), nil
		}
		return nil, errors.New("未预期桥接调用")
	})
	t.Cleanup(func() { hostbridge.Configure(nil) })
	v := Instances(core.Env{})[0]
	cred, err := v.Parse([]byte(`{"vendor":"tokenplan","api_key":"test-key"}`), "tokenplan-test.json")
	if err != nil {
		t.Fatal(err)
	}
	sink := &collectingSink{}
	if err := v.ExecuteStream(context.Background(), cred, &core.ExecuteRequest{Payload: []byte(`{"model":"intern-s2","messages":[{"role":"user","content":"test"}]}`)}, sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.chunks) != 1 || sink.chunks[0] != chunk || !closed {
		t.Fatalf("流式工具数据或结束处理错误: %+v closed=%v", sink.chunks, closed)
	}
}

func TestModelsUsesGenerationListAndRejectsMalformedPayload(t *testing.T) {
	models, err := parseModels([]byte(`{"object":"list","data":[{"id":"intern-s2","object":"model"},{"id":"intern-s2"}],"models":[{"name":"intern-decision-4b"}]}`))
	if err != nil || len(models) != 1 || models[0].ID != "intern-s2" {
		t.Fatalf("生成模型与决策模型错误混合: %+v %v", models, err)
	}
	for _, body := range []string{`{"error":{"message":"bad"}}`, `{"object":"list"}`, `[]`, `null`} {
		if _, err := parseModels([]byte(body)); err == nil {
			t.Fatalf("不合法模型目录被接收: %s", body)
		}
	}
	empty, err := parseModels([]byte(`{"object":"list","data":[]}`))
	if err != nil || len(empty) != 0 {
		t.Fatal("合法空目录应保留为空")
	}
}

func TestModelsFetchPreservesAuthFailures(t *testing.T) {
	hostbridge.Configure(func(_, _ string, payload any) (json.RawMessage, error) {
		encoded, _ := json.Marshal(payload)
		if !strings.Contains(string(encoded), "https://test.invalid/v1/models") {
			t.Fatalf("模型查询端点错误: %s", encoded)
		}
		out, _ := json.Marshal(map[string]any{"StatusCode": 401, "Headers": http.Header{}, "Body": []byte(`{"error":{"message":"invalid API key"}}`)})
		return out, nil
	})
	t.Cleanup(func() { hostbridge.Configure(nil) })
	_, err := FetchModels(context.Background(), "https://test.invalid/v1", "fake-key")
	var failure *core.Failure
	if !errors.As(err, &failure) || failure.Status != 401 {
		t.Fatalf("失效 Key 未返回身份错误: %v", err)
	}
}
