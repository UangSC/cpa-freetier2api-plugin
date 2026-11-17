package codeartsweb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"freetier2api-plugin/internal/core"
)

type chatFixture struct {
	client     webClient
	credential *Credential
	created    atomic.Int32
	generated  atomic.Int32
	stopped    atomic.Int32
	body       chan map[string]any
}

func newChatFixture(t *testing.T, frames string, handler func(http.ResponseWriter, *http.Request)) *chatFixture {
	t.Helper()
	fixture := &chatFixture{body: make(chan map[string]any, 1)}
	credential, err := ParseCredential([]byte(`{"cookie":"devclouddevuibjJ_SESSION_ID=fixture-session; devclouddevuibjtcftk=fixture-cftk","cftk":"fixture-cftk"}`))
	if err != nil {
		t.Fatal(err)
	}
	fixture.credential = credential
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/chat/v1/cloudagent/sessions":
			fixture.created.Add(1)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"result":{"session_id":"fixture-session-id"}}`)
		case "/chat/codebaseservice/v1/cloudagent/sessions/fixture-session-id/messages":
			fixture.generated.Add(1)
			var body map[string]any
			if json.NewDecoder(r.Body).Decode(&body) == nil {
				fixture.body <- body
			}
			w.Header().Set("Content-Type", "text/event-stream;charset=UTF-8")
			if handler != nil {
				handler(w, r)
			} else {
				fmt.Fprint(w, frames)
			}
		case "/chat/v1/cloudagent/sessions/fixture-session-id/messages/stop":
			fixture.stopped.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("意外的网页路径：%s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	fixture.client = webClient{baseURL: server.URL, httpClient: server.Client()}
	return fixture
}

func chatRequest(t *testing.T, options map[string]any) []byte {
	t.Helper()
	request := map[string]any{"messages": []any{map[string]any{"role": "user", "content": "只回复 OK"}}}
	for key, value := range options {
		request[key] = value
	}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func parsedCompletion(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func completionChoice(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	return parsedCompletion(t, raw)["choices"].([]any)[0].(map[string]any)
}

func TestWebChatCompleteHistoryAndUsage(t *testing.T) {
	frames := ": keepalive\r\n\r\nevent: tool_call\r\ndata: {\"tool\":\"bash\"}\r\n\r\n" +
		"event: thought\r\ndata: {\"content\":\"思考\"}\r\n\r\n" +
		"event: message\r\ndata: {\n" +
		"data: \"content\":\"你好\"}\r\n\r\n" +
		"event: message\r\ndata: {\"content\":\" OK\"}\r\n\r\n" +
		"event: done\r\ndata: {\"tokens\":{\"input\":10,\"output\":4,\"reasoning\":3,\"total\":19,\"cache\":{\"read\":2}}}\r\n\r\n"
	fixture := newChatFixture(t, frames, nil)
	raw := chatRequest(t, map[string]any{"messages": []any{
		map[string]any{"role": "system", "content": "system-keep"},
		map[string]any{"role": "developer", "content": "developer-keep"},
		map[string]any{"role": "user", "content": "old-user"},
		map[string]any{"role": "assistant", "content": "old-assistant"},
		map[string]any{"role": "user", "content": []any{map[string]any{"type": "text", "text": "latest-user"}}},
	}, "reasoning_effort": "low"})
	result, err := runChat(context.Background(), fixture.client, fixture.credential, "deepseek-v4.1-flash-1017", raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	completion := parsedCompletion(t, result)
	choice := completionChoice(t, result)
	message := choice["message"].(map[string]any)
	if message["content"] != "你好 OK" || message["reasoning_content"] != "思考" || choice["finish_reason"] != "stop" {
		t.Fatalf("回复转换错误：%s", result)
	}
	if completion["model"] != "deepseek-v4.1-flash-1017" {
		t.Fatalf("错误的模型字段：%v", completion["model"])
	}
	usage := completion["usage"].(map[string]any)
	if usage["prompt_tokens"] != float64(12) || usage["completion_tokens"] != float64(7) || usage["total_tokens"] != float64(19) {
		t.Fatalf("统计转换错误：%v", usage)
	}
	body := <-fixture.body
	prompt := body["content"].(string)
	for _, text := range []string{"system-keep", "developer-keep", "old-user", "old-assistant", "latest-user"} {
		if !strings.Contains(prompt, text) {
			t.Fatalf("消息被丢失：%q", text)
		}
	}
	if body["model_id"] != "deepseek-v4.1-flash-1017" || body["reasoning_effort"] != "low" {
		t.Fatalf("上游消息体错误：%v", body)
	}
	if _, exists := body["max_tokens"]; exists {
		t.Fatal("不应向网页伪造 max_tokens 参数")
	}
	if fixture.created.Load() != 1 || fixture.generated.Load() != 1 || fixture.stopped.Load() != 0 {
		t.Fatalf("调用计数错误：建会话 %d、生成 %d、停止 %d", fixture.created.Load(), fixture.generated.Load(), fixture.stopped.Load())
	}
}

func TestWebChatStreamingChunksAndUsage(t *testing.T) {
	fixture := newChatFixture(t, "event: thought\ndata: {\"content\":\"reason\"}\n\nevent: message\ndata: {\"content\":\"reply\"}\n\nevent: done\ndata: {\"tokens\":{\"input\":1,\"output\":2,\"reasoning\":0,\"total\":3}}\n\n", nil)
	chunks := []map[string]any{}
	_, err := runChat(context.Background(), fixture.client, fixture.credential, "demo", chatRequest(t, map[string]any{"stream_options": map[string]any{"include_usage": true}}), func(raw []byte) error {
		if strings.HasPrefix(string(raw), "data:") {
			t.Fatal("sink 应收到裸 JSON")
		}
		chunks = append(chunks, parsedCompletion(t, raw))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 5 {
		t.Fatalf("流分片数量错误：%d", len(chunks))
	}
	if chunks[0]["choices"].([]any)[0].(map[string]any)["delta"].(map[string]any)["role"] != "assistant" {
		t.Fatal("缺少初始 assistant 角色分片")
	}
	if chunks[1]["choices"].([]any)[0].(map[string]any)["delta"].(map[string]any)["reasoning_content"] != "reason" {
		t.Fatal("思考增量没有转换")
	}
	if chunks[3]["choices"].([]any)[0].(map[string]any)["finish_reason"] != "stop" {
		t.Fatal("正常结束缺少 finish_reason")
	}
	if len(chunks[4]["choices"].([]any)) != 0 || chunks[4]["usage"] == nil {
		t.Fatal("usage 应是末尾独立分片")
	}
}

func TestWebChatProxyLimitPreservesUTF8AndStops(t *testing.T) {
	fixture := newChatFixture(t, "event: message\ndata: {\"content\":\"你好abc\"}\n\nevent: done\ndata: {\"tokens\":{\"input\":10,\"output\":10}}\n\n", nil)
	result, err := runChat(context.Background(), fixture.client, fixture.credential, "demo", chatRequest(t, map[string]any{"max_tokens": 5}), nil)
	if err != nil {
		t.Fatal(err)
	}
	completion := parsedCompletion(t, result)
	choice := completionChoice(t, result)
	content := choice["message"].(map[string]any)["content"].(string)
	if content != "你" || !utf8.ValidString(content) || choice["finish_reason"] != "length" {
		t.Fatalf("中文限长错误：%s", result)
	}
	if completion["usage"] != nil {
		t.Fatal("主动截断不能伪造或引用未读取的上游 usage")
	}
	if fixture.stopped.Load() != 1 || fixture.generated.Load() != 1 {
		t.Fatal("主动限长应只停止一次，不能重新生成")
	}
}

func TestWebChatReasoningConsumesProxyBudget(t *testing.T) {
	fixture := newChatFixture(t, "event: thought\ndata: {\"content\":\"abcd\"}\n\nevent: message\ndata: {\"content\":\"XYZ\"}\n\nevent: done\ndata: {}\n\n", nil)
	result, err := runChat(context.Background(), fixture.client, fixture.credential, "demo", chatRequest(t, map[string]any{"max_completion_tokens": 6}), nil)
	if err != nil {
		t.Fatal(err)
	}
	choice := completionChoice(t, result)
	message := choice["message"].(map[string]any)
	if message["reasoning_content"] != "abcd" || message["content"] != "XY" || choice["finish_reason"] != "length" {
		t.Fatalf("思考预算错误：%s", result)
	}
	if fixture.stopped.Load() != 1 {
		t.Fatal("达到思考与正文的合计预算后应停止任务")
	}
}

func TestWebChatReasoningOnlyUTF8Limit(t *testing.T) {
	fixture := newChatFixture(t, "event: thought\ndata: {\"content\":\"思考\"}\n\nevent: message\ndata: {\"content\":\"reply\"}\n\n", nil)
	result, err := runChat(context.Background(), fixture.client, fixture.credential, "demo", chatRequest(t, map[string]any{"max_tokens": 4}), nil)
	if err != nil {
		t.Fatal(err)
	}
	choice := completionChoice(t, result)
	message := choice["message"].(map[string]any)
	if message["reasoning_content"] != "思" || message["content"] != "" || choice["finish_reason"] != "length" {
		t.Fatalf("思考中文截断错误：%s", result)
	}
}

func TestWebChatMissingDoneAndBadEventsNeverRetry(t *testing.T) {
	for name, frames := range map[string]string{
		"missing_done": "event: message\ndata: {\"content\":\"partial\"}\n\n",
		"error_event":  "event: error\ndata: {\"error_code\":\"InferHub.4004\",\"error\":\"private raw text\"}\n\n",
		"invalid_json": "event: message\ndata: not-json\n\n",
		"invalid_utf8": "event: message\ndata: {\"content\":\"\xff\"}\n\n",
		"done_error":   "event: done\ndata: {\"error\":\"failure\"}\n\n",
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newChatFixture(t, frames, nil)
			result, err := runChat(context.Background(), fixture.client, fixture.credential, "demo", chatRequest(t, nil), nil)
			if err == nil || result != nil {
				t.Fatalf("意外成功：%s", result)
			}
			var classified core.UpstreamError
			if !errors.As(err, &classified) || classified.Retryable() {
				t.Fatalf("提交后的失败不可换号重发：%v", err)
			}
			if strings.Contains(err.Error(), "private raw text") {
				t.Fatal("错误不应回显任意服务端文本")
			}
			if fixture.generated.Load() != 1 || fixture.stopped.Load() != 1 {
				t.Fatalf("调用计数异常：%d/%d", fixture.generated.Load(), fixture.stopped.Load())
			}
		})
	}
}

func TestWebChatLongSSELine(t *testing.T) {
	content := strings.Repeat("x", 96<<10)
	encoded, _ := json.Marshal(map[string]any{"content": content})
	fixture := newChatFixture(t, "event: message\ndata: "+string(encoded)+"\n\nevent: done\ndata: {}", nil)
	result, err := runChat(context.Background(), fixture.client, fixture.credential, "demo", chatRequest(t, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if completionChoice(t, result)["message"].(map[string]any)["content"] != content {
		t.Fatal("超过默认 64K 的 SSE 行被丢失")
	}
}

func TestWebChatCancellationStopsExistingSession(t *testing.T) {
	fixture := newChatFixture(t, "", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, ": ready\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := runChat(ctx, fixture.client, fixture.credential, "demo", chatRequest(t, nil), func([]byte) error { cancel(); return nil })
	if err == nil {
		t.Fatal("取消后不应成功")
	}
	if fixture.generated.Load() != 1 || fixture.stopped.Load() != 1 {
		t.Fatalf("取消未停止现有会话：生成 %d、停止 %d", fixture.generated.Load(), fixture.stopped.Load())
	}
}

func TestWebChatGenerationKeepsCredentialFailure(t *testing.T) {
	fixture := newChatFixture(t, "", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	_, err := runChat(context.Background(), fixture.client, fixture.credential, "demo", chatRequest(t, nil), nil)
	var classified core.UpstreamError
	if !errors.As(err, &classified) || classified.HTTPStatus() != http.StatusUnauthorized || classified.Retryable() {
		t.Fatalf("生成阶段的凭证失效不应退化成可重试 502：%v", err)
	}
	if fixture.generated.Load() != 1 {
		t.Fatal("凭证被拒不应再次提交 prompt")
	}
}

func TestWebChatUnsupportedInputBeforeCreatingTask(t *testing.T) {
	for name, options := range map[string]map[string]any{
		"tools":            {"tools": []any{map[string]any{"type": "web_search"}}},
		"image":            {"messages": []any{map[string]any{"role": "user", "content": []any{map[string]any{"type": "image_url", "image_url": map[string]any{"url": "https://example.com/image.png"}}}}}},
		"sampling":         {"temperature": 0.2},
		"invalid_limit":    {"max_tokens": 0},
		"multiple_choices": {"n": 2},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newChatFixture(t, "", nil)
			_, err := runChat(context.Background(), fixture.client, fixture.credential, "demo", chatRequest(t, options), nil)
			var classified core.UpstreamError
			if !errors.As(err, &classified) || classified.HTTPStatus() != http.StatusBadRequest {
				t.Fatalf("应明确报不支持：%v", err)
			}
			if fixture.created.Load() != 0 || fixture.generated.Load() != 0 {
				t.Fatal("无效请求不能创建收费任务")
			}
		})
	}
}
