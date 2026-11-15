package qwenwork

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"freetier2api-plugin/cpasdk/pluginapi"
	"freetier2api-plugin/internal/core"
	"freetier2api-plugin/internal/hostbridge"
	"freetier2api-plugin/internal/safe"
)

const (
	legacyVersion    = "1.1.75"
	legacyScene      = "qwork"
	legacyInferURL   = gatewayOrigin + "/algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1"
	legacyAlphabet   = "_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!"
	standardAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	maxResponseBytes = 8 * 1024 * 1024
)

// 该公钥与当前官方 SDK 的 generate_runtime_auth_fields 所用公钥相同。
// 加密/签名已通过隔离的官方 WASM 虚构数据验证，不在插件内嵌入该运行时。
const legacyPublicKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA8iMH5c02LilrsERw9t6Pv5Nc
4k6Pz1EaDicBMpdpxKduSZu5OANqUq8er4GM95omAGIOPOh+Nx0spthYA2BqGz+l
6HRkPJ7S236FZz73In/KVuLnwI8JJ2CbuJap8kvheCCZpmAWpb/cPx/3Vr/J6I17
XcW+ML9FoCI6AOvOzwIDAQAB
-----END PUBLIC KEY-----`

type clientContext struct {
	credential *Credential
	info, key  string
	machineID  string
	dataPolicy bool
}

func rsaPublicKey() (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(legacyPublicKey))
	if block == nil {
		return nil, fmt.Errorf("千问办公认证公钥无效")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	public, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("千问办公认证公钥不是 RSA")
	}
	return public, nil
}

func runtimeAuthJSON(credential *Credential) ([]byte, bool, error) {
	if credential == nil || credential.Token == "" || credential.UserID == "" {
		return nil, false, core.NewPluginError("credential_invalid", "千问办公凭证缺少用户或访问令牌", 401)
	}
	data := map[string]any{"uid": credential.UserID, "security_oauth_token": credential.Token}
	if credential.OrgID != "" {
		data["organization_id"] = credential.OrgID
	}
	if tags, ok := credential.Raw["organization_tags"].([]any); ok {
		data["organization_tags"] = tags
	}
	policy, known := credential.Raw["data_policy_agreed"].(bool)
	if known {
		data["data_policy_agreed"] = policy
	}
	encoded, err := json.Marshal(data)
	return encoded, policy, err
}

func newClientContext(credential *Credential) (*clientContext, error) {
	key, err := rsaPublicKey()
	if err != nil {
		return nil, err
	}
	return newClientContextWithKey(credential, key)
}

func newClientContextWithKey(credential *Credential, public *rsa.PublicKey) (*clientContext, error) {
	plain, policy, err := runtimeAuthJSON(credential)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	seed := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, err
	}
	aesKey := []byte(hex.EncodeToString(seed))
	clear(seed)
	defer clear(aesKey)
	wrapped, err := rsa.EncryptPKCS1v15(rand.Reader, public, aesKey)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	padded := make([]byte, len(plain)+pad)
	copy(padded, plain)
	for index := len(plain); index < len(padded); index++ {
		padded[index] = byte(pad)
	}
	defer clear(padded)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, aesKey).CryptBlocks(ciphertext, padded)
	machineID := strings.ReplaceAll(credential.LoginDeviceID, "-", "")
	if decoded, err := hex.DecodeString(machineID); err != nil || len(decoded) != 16 {
		hash := sha256.Sum256([]byte(credential.UserID + ":" + credential.OrgID + ":" + credential.TeamID))
		machineID = hex.EncodeToString(hash[:16])
	}
	return &clientContext{credential: credential, key: base64.StdEncoding.EncodeToString(wrapped),
		info: base64.StdEncoding.EncodeToString(ciphertext), machineID: machineID, dataPolicy: policy}, nil
}

func randomUUID() (string, error) {
	data := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		return "", err
	}
	data[6], data[8] = data[6]&0x0f|0x40, data[8]&0x3f|0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", data[:4], data[4:6], data[6:8], data[8:10], data[10:]), nil
}

func (client *clientContext) headers(path, body, accept, model, source string) (http.Header, error) {
	requestID, err := randomUUID()
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(map[string]string{"version": "v1", "requestId": requestID, "info": client.info, "cosyVersion": legacyVersion, "ideVersion": ""})
	if err != nil {
		return nil, err
	}
	payload64 := base64.StdEncoding.EncodeToString(payload)
	date := strconv.FormatInt(time.Now().Unix(), 10)
	path = strings.TrimPrefix(strings.SplitN(path, "?", 2)[0], "/algo")
	signature := md5.Sum([]byte(payload64 + "\n" + client.key + "\n" + date + "\n" + body + "\n" + path))
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer COSY."+payload64+"."+hex.EncodeToString(signature[:]))
	headers.Set("Accept", accept)
	headers.Set("Content-Type", "application/json")
	headers.Set("Accept-Encoding", "identity")
	headers.Set("Cosy-Version", legacyVersion)
	headers.Set("Cosy-Date", date)
	headers.Set("Cosy-Key", client.key)
	headers.Set("Cosy-User", client.credential.UserID)
	headers.Set("Cosy-MachineId", client.machineID)
	headers.Set("Cosy-MachineToken", client.machineID)
	headers.Set("Cosy-MachineType", "5")
	headers.Set("Cosy-ClientType", "6")
	headers.Set("Cosy-ClientIp", client.machineID)
	headers.Set("Cosy-Business-Product", "qoder_work")
	headers.Set("Cosy-Business-Type", "agent")
	headers.Set("Cosy-Scene", legacyScene)
	headers.Set("Login-Version", "v2")
	headers.Set("Cosy-Data-Policy", "disagree")
	if client.dataPolicy {
		headers.Set("Cosy-Data-Policy", "agree")
	}
	if client.credential.OrgID != "" {
		headers.Set("Cosy-Organization-Id", client.credential.OrgID)
	}
	if model != "" {
		headers.Set("X-Model-Key", model)
		headers.Set("X-Model-Source", core.FirstNonEmpty(source, "system"))
		headers.Set("Cache-Control", "no-cache")
	}
	return headers, nil
}

func encodeWire(plain []byte) string {
	encoded := base64.StdEncoding.EncodeToString(plain)
	part := len(encoded) / 3
	rotated := encoded[len(encoded)-part:] + encoded[part:len(encoded)-part] + encoded[:part]
	result := make([]byte, len(rotated))
	for index := range rotated {
		if rotated[index] == '=' {
			result[index] = '$'
		} else {
			result[index] = legacyAlphabet[strings.IndexByte(standardAlphabet, rotated[index])]
		}
	}
	return string(result)
}

func decodeWire(encoded string) ([]byte, error) {
	mapped := make([]byte, len(encoded))
	for index := range encoded {
		if encoded[index] == '$' {
			mapped[index] = '='
			continue
		}
		position := strings.IndexByte(legacyAlphabet, encoded[index])
		if position < 0 {
			return nil, fmt.Errorf("千问办公返回了无效的编码字符")
		}
		mapped[index] = standardAlphabet[position]
	}
	part := len(mapped) / 3
	base := string(mapped[len(mapped)-part:]) + string(mapped[part:len(mapped)-part]) + string(mapped[:part])
	return base64.StdEncoding.DecodeString(base)
}

func responseBytes(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxResponseBytes {
		return nil, core.NewPluginError("upstream_response_too_large", "千问办公响应超过允许大小", 502)
	}
	return data, nil
}

func qwenJSON(ctx context.Context, method, path string, body any, credential *Credential) ([]byte, error) {
	if credential == nil || credential.Token == "" {
		return nil, core.NewPluginError("credential_invalid", "千问办公凭证为空", 401)
	}
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, webOrigin+path, reader)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+credential.Token)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Client-Source", "web")
	response, err := hostbridge.Client(ctx, 30*time.Second).Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	data, err := responseBytes(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, Classify(response.StatusCode, data)
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(data, &envelope) != nil {
		return nil, core.NewPluginError("upstream_response_invalid", "千问办公响应不是合法 JSON", 502)
	}
	if code, ok := envelope["code"]; ok {
		var value string
		_ = json.Unmarshal(code, &value)
		if value != "" && value != "ok" && value != "SUCCESS" && value != "0" {
			return nil, Classify(http.StatusBadGateway, data)
		}
		if nested, ok := envelope["data"]; ok && string(nested) != "null" {
			return nested, nil
		}
	}
	return data, nil
}

// SignedModelsJSON 使用与推理同源的原始模型目录，保留官方能力与上下文元数据。
func SignedModelsJSON(ctx context.Context, credential *Credential) ([]byte, error) {
	client, err := newClientContext(credential)
	if err != nil {
		return nil, err
	}
	path := "/api/v2/model/list?Encode=1"
	headers, err := client.headers(path, "", "application/json", "", "")
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, gatewayOrigin+"/algo"+path, nil)
	if err != nil {
		return nil, err
	}
	request.Header = headers
	response, err := hostbridge.Client(ctx, 30*time.Second).Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	data, err := responseBytes(response.Body)
	if err != nil {
		return nil, err
	}
	if !json.Valid(data) {
		decoded, err := decodeWire(strings.TrimSpace(string(data)))
		if err != nil || !json.Valid(decoded) {
			return nil, core.NewPluginError("upstream_response_invalid", "千问办公模型目录格式无效", 502)
		}
		data = decoded
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, Classify(response.StatusCode, data)
	}
	return data, nil
}

func latestPrompt(messages []any) string {
	for index := len(messages) - 1; index >= 0; index-- {
		message, _ := messages[index].(map[string]any)
		if message["role"] != "user" {
			continue
		}
		if text, ok := message["content"].(string); ok {
			return text
		}
		blocks, _ := message["content"].([]any)
		var text strings.Builder
		for _, block := range blocks {
			part, _ := block.(map[string]any)
			if part["type"] == "text" {
				if value, ok := part["text"].(string); ok {
					text.WriteString(value)
				}
			}
		}
		return text.String()
	}
	return ""
}

func buildLegacyPayload(request *core.ExecuteRequest, mode string, model Model) ([]byte, string, error) {
	var incoming map[string]any
	if request == nil || json.Unmarshal(request.Payload, &incoming) != nil {
		return nil, "", core.NewPluginError("invalid_request", "请求体必须是 chat-completions JSON", 400)
	}
	messages, ok := incoming["messages"].([]any)
	if !ok || len(messages) == 0 {
		return nil, "", core.NewPluginError("invalid_request", "messages 不能为空", 400)
	}
	if n := core.IntFromAny(incoming["n"]); n > 1 {
		return nil, "", core.NewPluginError("unsupported_parameter", "千问办公目前只支持单个候选回复", 400)
	}
	parameters := make(map[string]any)
	for _, key := range []string{"max_tokens", "max_completion_tokens", "temperature", "top_p", "top_k", "stop", "tool_choice", "parallel_tool_calls", "frequency_penalty", "presence_penalty", "seed", "response_format", "enable_thinking", "reasoning_effort", "reasoning_budget_tokens", "logprobs", "top_logprobs"} {
		if value, exists := incoming[key]; exists {
			parameters[key] = value
		}
	}
	if value, exists := parameters["max_completion_tokens"]; exists {
		if _, exists := parameters["max_tokens"]; !exists {
			parameters["max_tokens"] = value
		}
		delete(parameters, "max_completion_tokens")
	}
	reasoning := model.IsReasoning
	if parameters["enable_thinking"] == false || parameters["reasoning_effort"] == "none" {
		if model.IsReasoning && !model.CanDisableThink {
			return nil, "", core.NewPluginError("unsupported_parameter", "该千问办公模型没有提供关闭思考的能力", 400)
		}
		reasoning = false
	}
	contextLength := model.ContextLength
	if request.ContextLength > 0 {
		contextLength = request.ContextLength
	}
	requestID, err := randomUUID()
	if err != nil {
		return nil, "", err
	}
	sessionID, err := randomUUID()
	if err != nil {
		return nil, "", err
	}
	requestSetID, err := randomUUID()
	if err != nil {
		return nil, "", err
	}
	prompt := latestPrompt(messages)
	modelConfig := map[string]any{"key": mode, "display_name": core.FirstNonEmpty(model.Name, model.ID, mode), "model": "", "format": core.FirstNonEmpty(model.Format, "openai"),
		"is_vl": model.IsVL, "is_reasoning": reasoning, "api_key": "", "url": "", "source": core.FirstNonEmpty(model.Source, "system")}
	if contextLength > 0 {
		modelConfig["max_input_tokens"] = contextLength
	}
	tools, exists := incoming["tools"]
	if !exists {
		tools = []any{}
	}
	var system []any
	for _, raw := range messages {
		message, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if message["role"] == "system" || message["role"] == "developer" {
			if text, ok := message["content"].(string); ok {
				system = append(system, map[string]any{"type": "text", "text": text})
			} else if blocks, ok := message["content"].([]any); ok {
				system = append(system, blocks...)
			}
		}
		if message["role"] == "user" {
			if _, exists := message["contents"]; !exists {
				if text, ok := message["content"].(string); ok {
					message["contents"] = []any{map[string]any{"type": "text", "text": text}}
				} else if blocks, ok := message["content"].([]any); ok {
					message["contents"] = blocks
				}
			}
		}
	}
	if system == nil {
		system = []any{}
	}
	name := []rune(prompt)
	if len(name) > 10 {
		name = name[:10]
	}
	body := map[string]any{
		"request_id": requestID, "request_set_id": requestSetID, "chat_record_id": requestID, "session_id": sessionID,
		"stream": true, "chat_task": "FREE_INPUT", "is_reply": true, "is_retry": false, "source": 1, "version": "3",
		"agent_id": "agent_common", "task_id": "common", "session_type": "qoder_work", "aliyun_user_type": "",
		"chat_context": map[string]any{"text": prompt, "features": []any{}, "extra": map[string]any{"context": []any{},
			"modelConfig": map[string]any{"key": mode, "is_reasoning": reasoning}, "originalContent": prompt}, "chatPrompt": "", "imageUrls": nil},
		"model_config": modelConfig, "system": system, "messages": messages, "tools": tools, "parameters": parameters,
		"business": map[string]any{"product": "qoder_work", "version": legacyVersion, "type": "agent", "id": requestSetID,
			"name": string(name), "begin_at": time.Now().UnixMilli(), "stage": "start", "model_key": mode},
	}
	if value, exists := incoming["metadata"]; exists {
		body["metadata"] = value
	}
	if value, exists := incoming["patches"]; exists {
		body["patches"] = value
	}
	encoded, err := json.Marshal(body)
	return encoded, requestID, err
}

func frameObject(data []byte) (map[string]any, error) {
	var object map[string]any
	if json.Unmarshal(data, &object) == nil && object != nil {
		return object, nil
	}
	decoded, err := decodeWire(strings.TrimSpace(string(data)))
	if err != nil || json.Unmarshal(decoded, &object) != nil || object == nil {
		return nil, core.NewPluginError("upstream_stream_invalid", "千问办公返回了无效的推理分片", 502)
	}
	return object, nil
}

// unwrapFrame 先检查外层 HTTP 状态，避免 HTTP 200 中的错误信封被当成空回复。
func unwrapFrame(data []byte) (map[string]any, bool, error) {
	if strings.TrimSpace(string(data)) == "[DONE]" {
		return nil, true, nil
	}
	object, err := frameObject(data)
	if err != nil {
		return nil, false, err
	}
	for depth := 0; depth < 4; depth++ {
		if raw, exists := object["statusCodeValue"]; exists {
			status := core.IntFromAny(raw)
			if status < 200 || status >= 300 {
				if status < 400 || status > 599 {
					status = 502
				}
				body, _ := object["body"].(string)
				return nil, false, Classify(status, []byte(body))
			}
		}
		if body, ok := object["body"].(string); ok {
			if strings.TrimSpace(body) == "[DONE]" {
				return nil, true, nil
			}
			object, err = frameObject([]byte(body))
			if err != nil {
				return nil, false, err
			}
			continue
		}
		if body, ok := object["body"].(map[string]any); ok {
			object = body
			continue
		}
		if code := stringIn(object, "code"); code != "" && code != "0" && code != "ok" && code != "SUCCESS" {
			status, err := strconv.Atoi(code)
			if err != nil || status < 400 || status > 599 {
				status = 400
			}
			encoded, _ := json.Marshal(object)
			return nil, false, Classify(status, encoded)
		}
		if failure, ok := object["error"].(map[string]any); ok {
			encoded, _ := json.Marshal(failure)
			return nil, false, Classify(http.StatusBadGateway, encoded)
		}
		return object, false, nil
	}
	return nil, false, core.NewPluginError("upstream_stream_invalid", "千问办公推理信封嵌套过深", 502)
}

func readLegacyStream(ctx context.Context, body io.ReadCloser, consume func(map[string]any) error) error {
	stop := make(chan struct{})
	go func() {
		defer safe.Recover("qwenwork stream cancellation")
		select {
		case <-ctx.Done():
			_ = body.Close()
		case <-stop:
		}
	}()
	defer close(stop)
	scanner := hostbridge.NewSSEScanner(body)
	var lines []string
	seen, finished := false, false
	dispatch := func() (bool, error) {
		if len(lines) == 0 {
			return false, nil
		}
		data := strings.Join(lines, "\n")
		lines = nil
		frame, done, err := unwrapFrame([]byte(data))
		if err != nil {
			return false, err
		}
		if done {
			if !seen {
				return false, core.NewPluginError("upstream_stream_empty", "千问办公没有返回推理分片", 502)
			}
			return true, nil
		}
		choices, _ := frame["choices"].([]any)
		_, usage := frame["usage"].(map[string]any)
		if len(choices) == 0 && !usage {
			return false, nil
		}
		if len(choices) > 0 {
			seen = true
		}
		for _, raw := range choices {
			choice, _ := raw.(map[string]any)
			if value, ok := choice["finish_reason"].(string); ok && value != "" {
				finished = true
			}
		}
		return false, consume(frame)
	}
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" {
			if done, err := dispatch(); done || err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			value := strings.TrimPrefix(line, "data:")
			lines = append(lines, strings.TrimPrefix(value, " "))
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if done, err := dispatch(); done || err != nil {
		return err
	}
	if !seen || !finished {
		return core.NewPluginError("upstream_stream_incomplete", "千问办公推理流提前结束", 502)
	}
	return nil
}

func (v *adapter) runRawChat(ctx context.Context, credential *core.Credential, request *core.ExecuteRequest, consume func(map[string]any) error) error {
	if request == nil {
		return core.NewPluginError("invalid_request", "请求不能为空", 400)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	native, err := v.Native(credential)
	if err != nil {
		return err
	}
	mode, err := v.modeFor(ctx, native, request.Model)
	if err != nil {
		return err
	}
	model, ok := v.modelForMode(mode)
	if !ok {
		return core.NewPluginError("model_not_found", "千问办公模型元数据不可用", 404)
	}
	plain, requestID, err := buildLegacyPayload(request, mode, model)
	if err != nil {
		return err
	}
	client, err := newClientContext(native)
	if err != nil {
		return err
	}
	body := encodeWire(plain)
	parsed, _ := url.Parse(legacyInferURL)
	headers, err := client.headers(parsed.Path, body, "text/event-stream", mode, model.Source)
	if err != nil {
		return err
	}
	upstream, err := http.NewRequestWithContext(ctx, http.MethodPost, legacyInferURL, strings.NewReader(body))
	if err != nil {
		return err
	}
	upstream.Header = headers
	response, err := hostbridge.StreamClient(ctx, 0).Do(upstream)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		data, err := responseBytes(response.Body)
		if err != nil {
			return err
		}
		return Classify(response.StatusCode, data)
	}
	if strings.Contains(response.Header.Get("Content-Type"), "application/json") {
		data, err := responseBytes(response.Body)
		if err != nil {
			return err
		}
		if _, _, err := unwrapFrame(data); err != nil {
			return err
		}
		return core.NewPluginError("upstream_stream_invalid", "千问办公没有返回请求的推理流", 502)
	}
	return readLegacyStream(ctx, response.Body, func(frame map[string]any) error {
		frame["model"] = request.Model
		if stringIn(frame, "id") == "" {
			frame["id"] = "chatcmpl-" + requestID
		}
		if stringIn(frame, "object") == "" {
			frame["object"] = "chat.completion.chunk"
		}
		if _, ok := frame["created"]; !ok {
			frame["created"] = time.Now().Unix()
		}
		return consume(frame)
	})
}

func (v *adapter) ExecuteStream(ctx context.Context, credential *core.Credential, request *core.ExecuteRequest, sink core.StreamSink) error {
	return v.runRawChat(ctx, credential, request, func(frame map[string]any) error {
		encoded, err := json.Marshal(frame)
		if err != nil {
			return err
		}
		return sink.Emit(encoded)
	})
}

type accumulatedChoice struct {
	content, reasoning strings.Builder
	finishReason       string
	toolCalls          map[int]map[string]any
	refusal            string
}

func appendToolCalls(choice *accumulatedChoice, values []any) {
	if choice.toolCalls == nil {
		choice.toolCalls = make(map[int]map[string]any)
	}
	for _, value := range values {
		delta, _ := value.(map[string]any)
		index := core.IntFromAny(delta["index"])
		call := choice.toolCalls[index]
		if call == nil {
			call = map[string]any{"type": "function", "function": map[string]any{"name": "", "arguments": ""}}
			choice.toolCalls[index] = call
		}
		if id := stringIn(delta, "id"); id != "" {
			call["id"] = id
		}
		if kind := stringIn(delta, "type"); kind != "" {
			call["type"] = kind
		}
		if incoming, ok := delta["function"].(map[string]any); ok {
			function := call["function"].(map[string]any)
			for _, key := range []string{"name", "arguments"} {
				if fragment, ok := incoming[key].(string); ok {
					prior, _ := function[key].(string)
					function[key] = prior + fragment
				}
			}
		}
	}
}

func (v *adapter) Execute(ctx context.Context, credential *core.Credential, request *core.ExecuteRequest) (*pluginapi.ExecutorResponse, error) {
	choices := make(map[int]*accumulatedChoice)
	var id string
	var created any
	var usage any
	err := v.runRawChat(ctx, credential, request, func(frame map[string]any) error {
		id, created = stringIn(frame, "id"), frame["created"]
		if value, ok := frame["usage"].(map[string]any); ok {
			usage = value
		}
		entries, _ := frame["choices"].([]any)
		for _, entry := range entries {
			raw, _ := entry.(map[string]any)
			index := core.IntFromAny(raw["index"])
			choice := choices[index]
			if choice == nil {
				choice = &accumulatedChoice{}
				choices[index] = choice
			}
			delta, _ := raw["delta"].(map[string]any)
			if text, ok := delta["content"].(string); ok {
				choice.content.WriteString(text)
			}
			if text, ok := delta["reasoning_content"].(string); ok {
				choice.reasoning.WriteString(text)
			}
			if text, ok := delta["refusal"].(string); ok {
				choice.refusal += text
			}
			if values, ok := delta["tool_calls"].([]any); ok {
				appendToolCalls(choice, values)
			}
			if reason, ok := raw["finish_reason"].(string); ok && reason != "" {
				choice.finishReason = reason
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	indices := make([]int, 0, len(choices))
	for index := range choices {
		indices = append(indices, index)
	}
	sort.Ints(indices)
	entries := make([]any, 0, len(indices))
	for _, index := range indices {
		choice := choices[index]
		message := map[string]any{"role": "assistant", "content": choice.content.String()}
		if choice.reasoning.Len() > 0 {
			message["reasoning_content"] = choice.reasoning.String()
		}
		if choice.refusal != "" {
			message["refusal"] = choice.refusal
		}
		if len(choice.toolCalls) > 0 {
			toolIndices := make([]int, 0, len(choice.toolCalls))
			for index := range choice.toolCalls {
				toolIndices = append(toolIndices, index)
			}
			sort.Ints(toolIndices)
			calls := make([]any, 0, len(toolIndices))
			for _, index := range toolIndices {
				calls = append(calls, choice.toolCalls[index])
			}
			message["tool_calls"] = calls
			if choice.content.Len() == 0 {
				message["content"] = nil
			}
		}
		entries = append(entries, map[string]any{"index": index, "message": message, "finish_reason": core.FirstNonEmpty(choice.finishReason, "stop")})
	}
	result := map[string]any{"id": id, "object": "chat.completion", "created": created, "model": request.Model, "choices": entries}
	if usage != nil {
		result["usage"] = usage
	}
	payload, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return &pluginapi.ExecutorResponse{Payload: payload, Headers: map[string][]string{"Content-Type": {core.ContentTypeJSON}}}, nil
}
