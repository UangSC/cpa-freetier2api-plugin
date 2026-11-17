package qwenwork

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"freetier2api-plugin/cpasdk/pluginabi"
	"freetier2api-plugin/internal/core"
	"freetier2api-plugin/internal/hostbridge"
)

func chatTestCredential() *Credential {
	return &Credential{Token: "offline.jwt.signature", UserID: "offline-user", OrgID: "offline-org", TeamID: "offline-team", Raw: map[string]any{}}
}

func TestLegacyRuntimeAuthUsesVerifiedRSAAndAES(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	credential := chatTestCredential()
	client, err := newClientContextWithKey(credential, &private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, _ := base64.StdEncoding.DecodeString(client.key)
	key, err := rsa.DecryptPKCS1v15(rand.Reader, private, wrapped)
	if err != nil || len(key) != 16 {
		t.Fatal("运行时认证不是 RSA PKCS#1 v1.5 包装的 AES-128 密钥")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := base64.StdEncoding.DecodeString(client.info)
	plain := make([]byte, len(encoded))
	cipher.NewCBCDecrypter(block, key).CryptBlocks(plain, encoded)
	pad := int(plain[len(plain)-1])
	for _, value := range plain[len(plain)-pad:] {
		if int(value) != pad {
			t.Fatal("运行时认证缺少有效的 PKCS#7 填充")
		}
	}
	var decoded map[string]any
	if err := json.Unmarshal(plain[:len(plain)-pad], &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["uid"] != credential.UserID || decoded["security_oauth_token"] != credential.Token || decoded["organization_id"] != credential.OrgID {
		t.Fatal("认证载荷丢失原始用户、令牌或企业身份")
	}
	if len(decoded) != 3 {
		t.Fatal("认证载荷混入不属于官方运行时格式的字段")
	}
}

func TestLegacySignatureExcludesAlgoPrefixAndQuery(t *testing.T) {
	client, err := newClientContext(chatTestCredential())
	if err != nil {
		t.Fatal(err)
	}
	body := encodeWire([]byte(`{"messages":[{"role":"user","content":"测试"}]}`))
	headers, err := client.headers("/algo/api/v2/model/list?Encode=1", body, "application/json", "", "")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(strings.TrimPrefix(headers.Get("Authorization"), "Bearer COSY."), ".")
	if len(parts) != 2 {
		t.Fatal("COSY 认证格式无效")
	}
	want := md5.Sum([]byte(parts[0] + "\n" + client.key + "\n" + headers.Get("Cosy-Date") + "\n" + body + "\n/api/v2/model/list"))
	if parts[1] != hex.EncodeToString(want[:]) {
		t.Fatal("签名包含了不应参与签名的 /algo 前缀或 query")
	}
	if headers.Get("Cosy-Scene") != "qwork" || headers.Get("Cosy-ClientType") != "6" || headers.Get("Cosy-Business-Product") != "qoder_work" {
		t.Fatal("没有使用当前千问办公 SDK 的协议场景")
	}
	if headers.Get("Cosy-Data-Policy") != "disagree" {
		t.Fatal("缺少用户授权时不能自行声明同意数据策略")
	}
}

func TestLegacyWireMatchesOfficialWASMFixture(t *testing.T) {
	// 该 fixture 是当前 SDK WASM 对虚构载荷的实际输出，独立于 Go 编码实现。
	plain := []byte(`{"text":"中文","items":[1,2]}`)
	const officialWire = "V*lLr%GRKJep$$*tQ)PZB*f*PxCLuxmYKwDxiwBMn*QG"
	if got := encodeWire(plain); got != officialWire {
		t.Fatalf("Go 编码与官方 WASM fixture 不一致: %s", got)
	}
	decoded, err := decodeWire(officialWire)
	if err != nil || !bytes.Equal(decoded, plain) {
		t.Fatal("无法解码官方 WASM fixture")
	}
	if _, err := decodeWire("无效编码"); err == nil {
		t.Fatal("无效编码没有被拒绝")
	}
}

func TestLegacyEnvelopePropagatesNestedHTTPFailure(t *testing.T) {
	_, _, err := unwrapFrame([]byte(`{"headers":{"Content-Type":["application/json"]},"body":"{\"code\":\"503\",\"message\":\"Model catalog unavailable\"}","statusCodeValue":503,"statusCode":"Service Unavailable"}`))
	var failure *core.Failure
	if !errors.As(err, &failure) || failure.HTTPStatus() != 503 {
		t.Fatalf("HTTP 200 中的 503 信封被误判为成功: %v", err)
	}
}

func TestLegacyStreamRejectsPrematureEOF(t *testing.T) {
	stream := "data: {\"statusCodeValue\":200,\"body\":\"{\\\"choices\\\":[{\\\"index\\\":0,\\\"delta\\\":{\\\"content\\\":\\\"partial\\\"}}]}\"}\n\n"
	count := 0
	err := readLegacyStream(context.Background(), io.NopCloser(strings.NewReader(stream)), func(map[string]any) error { count++; return nil })
	if err == nil || count != 1 {
		t.Fatalf("截断推理流必须报错且不得重复内容，count=%d error=%v", count, err)
	}
}

type blockedChatReader struct {
	started chan struct{}
	closed  chan struct{}
	once    sync.Once
	read    sync.Once
}

func (reader *blockedChatReader) Read([]byte) (int, error) {
	reader.read.Do(func() { close(reader.started) })
	<-reader.closed
	return 0, io.EOF
}
func (reader *blockedChatReader) Close() error {
	reader.once.Do(func() { close(reader.closed) })
	return nil
}

func TestLegacyStreamCancellationClosesBlockedRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader := &blockedChatReader{started: make(chan struct{}), closed: make(chan struct{})}
	result := make(chan error, 1)
	go func() { result <- readLegacyStream(ctx, reader, func(map[string]any) error { return nil }) }()
	select {
	case <-reader.started:
	case <-time.After(time.Second):
		t.Fatal("推理流没有开始读取")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("取消请求未传播: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("取消请求后推理流仍阻塞，可能继续消耗额度")
	}
}

func TestLegacyPayloadPreservesClientConversationAndTools(t *testing.T) {
	const input = `{"messages":[{"role":"system","content":"自定义系统消息"},{"role":"user","content":[{"type":"text","text":"查看天气"},{"type":"image_url","image_url":{"url":"data:image/png;base64,ZmFrZQ=="}}]},{"role":"assistant","content":null,"tool_calls":[{"id":"call-1","type":"function","function":{"name":"weather","arguments":"{\"city\":\"厦门\"}"}}]},{"role":"tool","tool_call_id":"call-1","content":"晴"}],"tools":[{"type":"function","function":{"name":"weather","parameters":{"type":"object"}}}],"max_tokens":64,"temperature":0.2,"tool_choice":"auto","enable_thinking":false}`
	request := &core.ExecuteRequest{Model: "Qwen4-Max-Preview", Payload: []byte(input), ContextLength: 400000}
	encoded, _, err := buildLegacyPayload(request, "frontier-1", Model{ID: "Qwen4-Max-Preview", Source: "system", Format: "openai", IsReasoning: false, IsVL: true, ContextLength: 1000000})
	if err != nil {
		t.Fatal(err)
	}
	var source, body map[string]any
	_ = json.Unmarshal([]byte(input), &source)
	_ = json.Unmarshal(encoded, &body)
	for _, key := range []string{"tools"} {
		wanted, _ := json.Marshal(source[key])
		actual, _ := json.Marshal(body[key])
		if !bytes.Equal(wanted, actual) {
			t.Fatalf("客户端 %s 被修改或丢失", key)
		}
	}
	actualMessages := body["messages"].([]any)
	for index, raw := range source["messages"].([]any) {
		wanted := raw.(map[string]any)
		actual := actualMessages[index].(map[string]any)
		for key, value := range wanted {
			encoded, _ := json.Marshal(value)
			got, _ := json.Marshal(actual[key])
			if !bytes.Equal(encoded, got) {
				t.Fatalf("客户端消息 %d 的 %s 字段被改写", index, key)
			}
		}
	}
	if _, ok := actualMessages[1].(map[string]any)["contents"].([]any); !ok {
		t.Fatal("没有提供当前 SDK 的用户 contents 结构")
	}
	if body["business"].(map[string]any)["model_key"] != "frontier-1" || len(body["system"].([]any)) != 1 {
		t.Fatal("实际 SDK 所需的业务模型标识或系统消息缺失")
	}
	parameters := body["parameters"].(map[string]any)
	if parameters["max_tokens"] != float64(64) || parameters["temperature"] != 0.2 || parameters["tool_choice"] != "auto" {
		t.Fatal("客户端生成控制参数没有传递")
	}
	config := body["model_config"].(map[string]any)
	if config["key"] != "frontier-1" || config["max_input_tokens"] != float64(400000) || config["is_reasoning"] != false || config["is_vl"] != true {
		t.Fatal("模型、上下文或推理/图片能力没有正确传递")
	}
}

func TestLegacyPayloadDoesNotInventNonThinkingModelVariant(t *testing.T) {
	_, _, err := buildLegacyPayload(&core.ExecuteRequest{Model: "Qwen4-Max-Preview", Payload: []byte(`{"messages":[{"role":"user","content":"测试"}],"enable_thinking":false}`)},
		"frontier-1", Model{IsReasoning: true})
	var failure *core.PluginError
	if !errors.As(err, &failure) || failure.HTTPStatus != 400 || failure.Code != "unsupported_parameter" {
		t.Fatalf("关闭思考不被支持时应明确拒绝，不能修改模型身份: %v", err)
	}
}

func chatTestStreamHost(t *testing.T, chunks []string, inspect func(http.Header, []byte)) {
	t.Helper()
	position := 0
	hostbridge.Configure(func(_ string, method string, payload any) (json.RawMessage, error) {
		switch method {
		case pluginabi.MethodHostHTTPDoStream:
			data, _ := json.Marshal(payload)
			var request struct {
				Headers http.Header
				Body    []byte
			}
			_ = json.Unmarshal(data, &request)
			inspect(request.Headers, request.Body)
			return json.Marshal(map[string]any{"status_code": 200, "headers": http.Header{"Content-Type": {"text/event-stream"}}, "stream_id": "test-stream"})
		case pluginabi.MethodHostHTTPStreamRead:
			if position >= len(chunks) {
				return json.Marshal(map[string]any{"done": true})
			}
			chunk := chunks[position]
			position++
			return json.Marshal(map[string]any{"payload": []byte(chunk)})
		case pluginabi.MethodHostHTTPStreamClose:
			return json.RawMessage(`{}`), nil
		default:
			return nil, fmt.Errorf("unexpected host method %s", method)
		}
	})
	t.Cleanup(func() { hostbridge.Configure(nil) })
}

func chatTestVendor() (*adapter, *core.Credential) {
	vendor := Instances(core.Env{})[0].(*adapter)
	model := Model{ID: "Qwen4-Max-Preview", Mode: "frontier-1", Source: "system", Format: "openai", ContextLength: 1000000}
	vendor.modelModes[strings.ToLower(model.ID)], vendor.modelsByMode[model.Mode] = model.Mode, model
	native := chatTestCredential()
	return vendor, &core.Credential{VendorID: vendorID, Native: native, Token: native.Token}
}

func TestLegacyExecuteUsesHostBridgeAndAssemblesToolFragments(t *testing.T) {
	vendor, credential := chatTestVendor()
	const first = `{"choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call-1","type":"function","function":{"name":"weather","arguments":"{\"city\":"}}]}}]}`
	const second = `{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"厦门\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`
	chatTestStreamHost(t, []string{"data: " + first + "\n\n", "data: " + second + "\n\n", "data: [DONE]\n\n"}, func(headers http.Header, encoded []byte) {
		if !strings.HasPrefix(headers.Get("Authorization"), "Bearer COSY.") {
			t.Error("推理请求没有经宿主桥携带 COSY 鉴权")
		}
		plain, err := decodeWire(string(encoded))
		if err != nil || !json.Valid(plain) {
			t.Error("宿主桥收到的请求体不是官方编码")
		}
	})
	response, err := vendor.Execute(context.Background(), credential, &core.ExecuteRequest{Model: "Qwen4-Max-Preview", Payload: []byte(`{"messages":[{"role":"user","content":"天气"}]}`)})
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	_ = json.Unmarshal(response.Payload, &body)
	choice := body["choices"].([]any)[0].(map[string]any)
	message := choice["message"].(map[string]any)
	call := message["tool_calls"].([]any)[0].(map[string]any)
	function := call["function"].(map[string]any)
	if function["arguments"] != `{"city":"厦门"}` || function["name"] != "weather" || call["id"] != "call-1" || message["content"] != nil {
		t.Fatal("工具调用分片没有按 OpenAI 语义组装")
	}
	if choice["finish_reason"] != "tool_calls" || body["model"] != "Qwen4-Max-Preview" || body["usage"].(map[string]any)["total_tokens"] != float64(15) {
		t.Fatal("回复收尾、模型名称或 usage 丢失")
	}
}
