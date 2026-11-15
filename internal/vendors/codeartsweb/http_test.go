package codeartsweb

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"freetier2api-plugin/internal/core"
	"freetier2api-plugin/internal/hostbridge"
)

func TestWebHTTPUsesCapturedBrowserHeadersAndRotatesCftk(t *testing.T) {
	credential := testCredential(t)
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Origin") != webOrigin || request.Header.Get("Referer") != webOrigin+"/chat/home" || request.Header.Get("Sec-Fetch-Site") != "same-origin" || request.Header.Get("X-Requested-With") != "XMLHttpRequest" {
			t.Error("缺少真实网页上下文头")
		}
		if request.Header.Get("User-Agent") != "browser-agent" || request.Header.Get("Sec-CH-UA") != "test-brand" || request.Header.Get("Authorization") != "" {
			t.Error("客户端标识错误或转发了 CPA 认证头")
		}
		if request.Header.Get("Agent-Type") != "AgentCenter" || request.Header.Get("Accept") != "application/json, text/plain, */*" {
			t.Error("模型查询请求头错误")
		}
		if count.Add(1) == 1 {
			if request.Header.Get("Cftk") != "token+value" {
				t.Error("初始 cftk 不正确")
			}
			http.SetCookie(writer, &http.Cookie{Name: "prefix_cftk", Value: "new-token"})
		} else if request.Header.Get("Cftk") != "new-token" || !strings.Contains(request.Header.Get("Cookie"), "prefix_cftk=new-token") {
			t.Error("未使用轮换后的 cftk 与 Cookie")
		}
		writer.Header().Set("Content-Type", "application/json")
		io.WriteString(writer, `{"gpts":{"models":[]}}`)
	}))
	defer server.Close()
	client := webClient{baseURL: server.URL, httpClient: server.Client()}
	for count := 0; count < 2; count++ {
		if _, err := client.json(context.Background(), credential, http.MethodGet, "/chat/PromptCenterService/v1/agent-center/agents/detail", nil, "AgentCenter"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWebSSEAddsEmptyAuthTokenOnlyToGeneration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, tokenPresent := request.Header["X-Auth-Token"]
		if !tokenPresent || request.Header.Get("X-Auth-Token") != "" || request.Header.Get("Accept") != "text/event-stream" || request.Header.Get("Agent-Type") != "" {
			t.Error("生成头与真实网页不同")
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(writer, "event: done\ndata: {}\n\n")
	}))
	defer server.Close()
	response, err := (webClient{baseURL: server.URL, httpClient: server.Client()}).do(context.Background(), testCredential(t), http.MethodPost, "/chat/codebaseservice/v1/cloudagent/sessions/test/messages", map[string]any{"content": "test"}, "text/event-stream", "")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
}

func TestWebHTTPStopsRedirectBeforeCredentialCanLeaveTarget(t *testing.T) {
	var forwarded atomic.Bool
	foreign := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { forwarded.Store(true) }))
	defer foreign.Close()
	source := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, foreign.URL, http.StatusFound)
	}))
	defer source.Close()
	_, err := (webClient{baseURL: source.URL, httpClient: source.Client()}).json(context.Background(), testCredential(t), http.MethodGet, "/chat/rest/me", nil, "")
	var failure *core.Failure
	if !errors.As(err, &failure) || failure.HTTPStatus() != 401 || failure.Retryable() || forwarded.Load() {
		t.Fatal("登录跳转未安全中止")
	}
}

func TestWebJSONRejectsEmptyInvalidAndOversizedResponses(t *testing.T) {
	for _, body := range []string{"", "<html>login</html>", "null", strings.Repeat(" ", maxJSONResponseBytes+1)} {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { io.WriteString(writer, body) }))
		_, err := (webClient{baseURL: server.URL, httpClient: server.Client()}).json(context.Background(), testCredential(t), http.MethodGet, "/chat/rest/me", nil, "")
		server.Close()
		if err == nil {
			t.Fatal("未拒绝空、无效或过大的 JSON")
		}
		if strings.Contains(err.Error(), "session-value") || strings.Contains(err.Error(), "token+value") || strings.Contains(err.Error(), "<html>") {
			t.Fatal("错误信息泄漏请求或响应内容")
		}
	}
}

func TestWebHTTPRejectsForeignAndTraversingPaths(t *testing.T) {
	for _, relative := range []string{"https://example.com/chat/rest/me", "//example.com/chat/rest/me", "/chat/../auth", "/chat/%2e%2e/auth", "/chat/rest/me#fragment"} {
		if _, err := (webClient{}).do(context.Background(), testCredential(t), http.MethodGet, relative, nil, "application/json", ""); err == nil {
			t.Error("未拒绝越界请求路径")
		}
	}
}

func TestWebHTTPDefaultUsesStreamBridgeWithCallbackContext(t *testing.T) {
	var methods []string
	hostbridge.Configure(func(callbackID, method string, _ any) (json.RawMessage, error) {
		if callbackID != "callback-for-web" {
			t.Error("未保留宿主回调上下文")
		}
		methods = append(methods, method)
		switch method {
		case "host.http.do":
			return json.RawMessage(`{"StatusCode":200,"Headers":{},"Body":"e30="}`), nil
		case "host.http.do_stream":
			return json.RawMessage(`{"status_code":200,"stream_id":"s1","headers":{"Content-Type":["text/event-stream"]}}`), nil
		default:
			return json.RawMessage(`{"done":true}`), nil
		}
	})
	t.Cleanup(func() { hostbridge.Configure(nil) })
	ctx := hostbridge.WithCallbackID(context.Background(), "callback-for-web")
	credential := testCredential(t)
	if _, err := (webClient{}).json(ctx, credential, http.MethodGet, "/chat/rest/me", nil, ""); err != nil {
		t.Fatal(err)
	}
	response, err := (webClient{}).do(ctx, credential, http.MethodPost, "/chat/codebaseservice/v1/cloudagent/sessions/test/messages", map[string]any{"content": "test"}, "text/event-stream", "")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if len(methods) < 2 || methods[0] != "host.http.do" || methods[1] != "host.http.do_stream" {
		t.Fatal("生成请求未使用宿主流式桥", methods)
	}
}
