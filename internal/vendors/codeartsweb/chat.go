package codeartsweb

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"freetier2api-plugin/internal/core"
)

const (
	maxSSELineBytes      = 4 << 20
	maxSSEFrameBytes     = 8 << 20
	maxReplyBytes        = 16 << 20
	maxProxyOutputBudget = 65536
)

// chatFailure 在 prompt 可能已被接收时禁止宿主换号重发，避免重复计费。
type chatFailure struct {
	code    string
	message string
	status  int
}

func (e *chatFailure) Error() string        { return e.message }
func (e *chatFailure) HTTPStatus() int      { return e.status }
func (e *chatFailure) Retryable() bool      { return false }
func (e *chatFailure) UpstreamKind() string { return e.code }

func newChatFailure(code, message string, status int) error {
	return &chatFailure{code: code, message: message, status: status}
}

type chatMessage struct {
	Role       string          `json:"role"`
	Content    json.RawMessage `json:"content"`
	Name       string          `json:"name,omitempty"`
	ToolCallID string          `json:"tool_call_id,omitempty"`
	ToolCalls  json.RawMessage `json:"tool_calls,omitempty"`
}

type chatInput struct {
	Messages            []chatMessage   `json:"messages"`
	Tools               json.RawMessage `json:"tools"`
	Functions           json.RawMessage `json:"functions"`
	ToolChoice          json.RawMessage `json:"tool_choice"`
	FunctionCall        json.RawMessage `json:"function_call"`
	ParallelToolCalls   *bool           `json:"parallel_tool_calls"`
	toolPolicy          *clientToolPolicy
	N                   *int   `json:"n"`
	MaxTokens           *int64 `json:"max_tokens"`
	MaxCompletionTokens *int64 `json:"max_completion_tokens"`
	ReasoningEffort     string `json:"reasoning_effort"`
	StreamOptions       struct {
		IncludeUsage bool `json:"include_usage"`
	} `json:"stream_options"`
}

type transcriptMessage struct {
	Role       string          `json:"role"`
	Content    string          `json:"content"`
	Name       string          `json:"name,omitempty"`
	ToolCallID string          `json:"tool_call_id,omitempty"`
	ToolCalls  json.RawMessage `json:"tool_calls,omitempty"`
}

// buildChatInput 保留所有角色与历史，网页接口收到的是明确标注角色的文本对话。
// 每次请求建立独立云会话，避免不同客户端共享或串用云端历史。
func buildChatInput(raw []byte) (chatInput, string, int64, error) {
	return buildChatInputWithTools(raw, false)
}

func buildChatInputWithTools(raw []byte, fullTools bool) (chatInput, string, int64, error) {
	var input chatInput
	if err := json.Unmarshal(raw, &input); err != nil {
		return input, "", 0, newChatFailure("invalid_request", "聊天请求必须是合法 JSON。", http.StatusBadRequest)
	}
	if len(input.Messages) == 0 {
		return input, "", 0, newChatFailure("invalid_request", "messages 不能为空。", http.StatusBadRequest)
	}
	if input.N != nil && *input.N != 1 {
		return input, "", 0, newChatFailure("unsupported_parameter", "CodeArts 网页通道每次只生成一个回复，n 必须为 1。", http.StatusBadRequest)
	}
	var err error
	input.toolPolicy, err = prepareClientTools(&input, fullTools)
	if err != nil {
		return input, "", 0, err
	}
	input.ReasoningEffort, err = normalizeWebEffort(input.ReasoningEffort)
	if err != nil {
		return input, "", 0, err
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	for _, name := range []string{"temperature", "top_p", "seed", "stop", "logprobs", "top_logprobs", "frequency_penalty", "presence_penalty"} {
		if value := fields[name]; len(value) > 0 && strings.TrimSpace(string(value)) != "null" {
			return input, "", 0, newChatFailure("unsupported_parameter", "CodeArts 网页接口不提供参数 "+name+"。", http.StatusBadRequest)
		}
	}
	if format := fields["response_format"]; len(format) > 0 && strings.TrimSpace(string(format)) != "null" {
		var value struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(format, &value) != nil || value.Type != "text" {
			return input, "", 0, newChatFailure("unsupported_parameter", "CodeArts 网页通道不提供强制 JSON 或结构化响应格式。", http.StatusBadRequest)
		}
	}
	budget := int64(0)
	for _, limit := range []*int64{input.MaxTokens, input.MaxCompletionTokens} {
		if limit == nil {
			continue
		}
		if *limit <= 0 {
			return input, "", 0, newChatFailure("invalid_request", "输出上限必须是正整数。", http.StatusBadRequest)
		}
		if budget == 0 || *limit < budget {
			budget = *limit
		}
	}
	if budget > maxProxyOutputBudget {
		budget = maxProxyOutputBudget
	}
	transcript := make([]transcriptMessage, 0, len(input.Messages))
	for _, message := range input.Messages {
		switch message.Role {
		case "system", "developer", "user", "assistant", "tool":
		default:
			return input, "", 0, newChatFailure("invalid_request", "不支持的消息角色。", http.StatusBadRequest)
		}
		content, err := messageText(message.Content)
		if err != nil {
			return input, "", 0, err
		}
		if nonEmptyJSON(message.ToolCalls) && !json.Valid(message.ToolCalls) {
			return input, "", 0, newChatFailure("invalid_request", "历史 tool_calls 格式无效。", http.StatusBadRequest)
		}
		transcript = append(transcript, transcriptMessage{Role: message.Role, Content: content, Name: message.Name, ToolCallID: message.ToolCallID, ToolCalls: message.ToolCalls})
	}
	encoded, err := json.Marshal(transcript)
	if err != nil {
		return input, "", 0, newChatFailure("invalid_request", "无法编码对话历史。", http.StatusBadRequest)
	}
	prompt := "请根据以下 JSON 对话历史续写下一条 assistant 回复。role 字段标明消息角色，content 是该角色的消息内容；完整考虑 system、developer 和全部历史。不要复述记录，不要添加角色标签。直接回答最后的请求；不要使用云端工作区或平台内置工具。历史 tool_calls 和 tool 结果均来自客户端，已有结果不能重复执行。\n\n对话历史：\n" + string(encoded) + input.toolPolicy.instructions()
	return input, prompt, budget, nil
}

func nonEmptyJSON(value json.RawMessage) bool {
	text := strings.TrimSpace(string(value))
	return text != "" && text != "null" && text != "[]"
}

func messageText(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text, nil
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) != nil {
		return "", newChatFailure("invalid_request", "消息 content 必须是文本或文本分段。", http.StatusBadRequest)
	}
	texts := make([]string, 0, len(parts))
	for _, part := range parts {
		if part.Type != "text" && part.Type != "input_text" {
			return "", newChatFailure("unsupported_input", "CodeArts 网页通道暂只支持文本输入。", http.StatusBadRequest)
		}
		texts = append(texts, part.Text)
	}
	return strings.Join(texts, "\n"), nil
}

type outputBudget struct {
	left    int64
	enabled bool
}

func (budget *outputBudget) take(value string) (string, bool) {
	if !budget.enabled {
		return value, false
	}
	if budget.left <= 0 {
		return "", true
	}
	if int64(len(value)) < budget.left {
		budget.left -= int64(len(value))
		return value, false
	}
	end := int(budget.left)
	if end > len(value) {
		end = len(value)
	}
	for end > 0 && !utf8.ValidString(value[:end]) {
		end--
	}
	budget.left -= int64(end)
	return value[:end], true
}

type tokenSummary struct {
	Input     *int64 `json:"input"`
	Output    *int64 `json:"output"`
	Reasoning *int64 `json:"reasoning"`
	Total     *int64 `json:"total"`
	Cache     struct {
		Read *int64 `json:"read"`
	} `json:"cache"`
}

func usageFromDone(data map[string]json.RawMessage) map[string]any {
	var tokens tokenSummary
	if raw := data["tokens"]; len(raw) == 0 || json.Unmarshal(raw, &tokens) != nil || tokens.Input == nil || tokens.Output == nil || *tokens.Input < 0 || *tokens.Output < 0 {
		return nil
	}
	prompt, completion := *tokens.Input, *tokens.Output
	usage := map[string]any{}
	if tokens.Cache.Read != nil && *tokens.Cache.Read >= 0 {
		prompt += *tokens.Cache.Read
		usage["prompt_tokens_details"] = map[string]any{"cached_tokens": *tokens.Cache.Read}
	}
	if tokens.Reasoning != nil && *tokens.Reasoning >= 0 {
		completion += *tokens.Reasoning
		usage["completion_tokens_details"] = map[string]any{"reasoning_tokens": *tokens.Reasoning}
	}
	usage["prompt_tokens"], usage["completion_tokens"] = prompt, completion
	if tokens.Total != nil && *tokens.Total >= 0 {
		usage["total_tokens"] = *tokens.Total
	} else {
		usage["total_tokens"] = prompt + completion
	}
	return usage
}

func runChat(ctx context.Context, client webClient, credential *Credential, model string, raw []byte, emit func([]byte) error) (result []byte, err error) {
	input, _, _, err := buildChatInput(raw)
	if err != nil {
		return nil, err
	}
	if input.toolPolicy == nil || !input.toolPolicy.deferred {
		return runChatTurn(ctx, client, credential, model, raw, emit, "", nil, false)
	}
	var buffered [][]byte
	bufferBytes := 0
	var delayed func([]byte) error
	if emit != nil {
		delayed = func(chunk []byte) error {
			bufferBytes += len(chunk)
			if bufferBytes > maxReplyBytes {
				return newChatFailure("response_too_large", "客户端工具选择响应超出读取限制。", http.StatusBadGateway)
			}
			buffered = append(buffered, append([]byte{}, chunk...))
			return nil
		}
	}
	result, err = runChatTurn(ctx, client, credential, model, raw, delayed, "", nil, false)
	var discovery *clientToolDiscovery
	if !errors.As(err, &discovery) {
		if err != nil {
			return nil, err
		}
		for _, chunk := range buffered {
			if err := emit(chunk); err != nil {
				return nil, err
			}
		}
		return result, nil
	}
	var request map[string]json.RawMessage
	_ = json.Unmarshal(raw, &request)
	definitions := make([]json.RawMessage, 0, len(discovery.names))
	for _, name := range discovery.names {
		definitions = append(definitions, input.toolPolicy.byName[name])
	}
	definitionJSON, _ := json.Marshal(definitions)
	if input.toolPolicy.legacy {
		request["functions"] = definitionJSON
	} else {
		request["tools"] = definitionJSON
	}
	request["messages"], _ = json.Marshal([]map[string]any{{"role": "user", "content": "这是你请求的客户端工具完整定义。请依据当前云会话中上一轮的完整对话继续回答；按原请求决定是否调用工具。不要重新执行已有工具结果，不要使用云端工作区或平台内置工具。"}})
	continued, _ := json.Marshal(request)
	return runChatTurn(ctx, client, credential, model, continued, emit, discovery.sessionID, discovery.usage, true)
}

func runChatTurn(ctx context.Context, client webClient, credential *Credential, model string, raw []byte, emit func([]byte) error, cloudSessionID string, previousUsage map[string]any, fullTools bool) (result []byte, err error) {
	input, prompt, limit, err := buildChatInputWithTools(raw, fullTools)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(model) == "" {
		return nil, newChatFailure("invalid_request", "模型 ID 不能为空。", http.StatusBadRequest)
	}
	sessionID := cloudSessionID
	if sessionID == "" {
		created, createErr := client.json(ctx, credential, http.MethodPost, "/chat/v1/cloudagent/sessions", map[string]any{}, "CodeBase")
		if createErr != nil {
			return nil, createErr
		}
		creation, _ := created["result"].(map[string]any)
		sessionID, _ = creation["session_id"].(string)
	}
	if sessionID == "" {
		return nil, newChatFailure("session_create_failed", "CodeArts 没有返回云会话 ID。", http.StatusBadGateway)
	}
	segment := url.PathEscape(sessionID)
	if sessionID == "." || sessionID == ".." {
		return nil, newChatFailure("session_create_failed", "CodeArts 返回的云会话 ID 无效。", http.StatusBadGateway)
	}
	postStarted, completed, stopped, stopAttempted := false, false, false, false
	defer func() {
		if postStarted && !completed && !stopped && !stopAttempted {
			_ = stopChat(ctx, client, credential, segment)
		}
	}()
	body := map[string]any{"content": prompt, "model_id": model, "repos": []any{}}
	if input.ReasoningEffort != "" {
		body["reasoning_effort"] = input.ReasoningEffort
	}
	postStarted = true
	response, err := client.do(ctx, credential, http.MethodPost, "/chat/codebaseservice/v1/cloudagent/sessions/"+segment+"/messages", body, "text/event-stream", "")
	if err != nil {
		var upstream core.UpstreamError
		if errors.As(err, &upstream) {
			return nil, newChatFailure(upstream.UpstreamKind(), err.Error(), upstream.HTTPStatus())
		}
		if ctx.Err() != nil {
			return nil, newChatFailure("client_cancelled", "客户端取消了网页请求，已尝试停止任务。", 499)
		}
		return nil, newChatFailure("generation_unconfirmed", "网页生成请求结果未确认，已尝试停止该任务；不会自动重发提示词。", http.StatusBadGateway)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, newChatFailure("generation_rejected", fmt.Sprintf("CodeArts 网页生成返回 HTTP %d。", response.StatusCode), response.StatusCode)
	}
	if !strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream") {
		return nil, newChatFailure("session_expired", "CodeArts 网页生成未返回 SSE，请重新导入网页登录会话。", http.StatusUnauthorized)
	}
	completionID := "chatcmpl-codeartsweb-" + sessionID
	createdAt := time.Now().Unix()
	publicModel := model
	emitChunk := func(delta map[string]any, finish any, usage map[string]any, emptyChoices bool) error {
		if emit == nil {
			return nil
		}
		choices := []any{}
		if !emptyChoices {
			choices = append(choices, map[string]any{"index": 0, "delta": delta, "finish_reason": finish})
		}
		chunk := map[string]any{"id": completionID, "object": "chat.completion.chunk", "created": createdAt, "model": publicModel, "choices": choices}
		if usage != nil {
			chunk["usage"] = usage
		}
		encoded, marshalErr := json.Marshal(chunk)
		if marshalErr != nil {
			return newChatFailure("response_encode_failed", "无法编码网页回复。", http.StatusBadGateway)
		}
		if emitErr := emit(encoded); emitErr != nil {
			return newChatFailure("client_closed", "客户端已停止读取，已尝试停止网页任务。", 499)
		}
		return nil
	}
	if err := emitChunk(map[string]any{"role": "assistant", "content": ""}, nil, nil, false); err != nil {
		return nil, err
	}
	budget := outputBudget{left: limit, enabled: limit > 0}
	var reply, reasoning strings.Builder
	toolStream := clientToolStream{policy: input.toolPolicy}
	var usage map[string]any
	finish := "stop"
	process := func(event, text string) (bool, error) {
		if event != "message" && event != "thought" && event != "done" && event != "error" {
			return false, nil
		}
		if !utf8.ValidString(text) {
			return false, newChatFailure("invalid_stream", "网页 SSE 包含无效 UTF-8 数据。", http.StatusBadGateway)
		}
		var data map[string]json.RawMessage
		if json.Unmarshal([]byte(text), &data) != nil || data == nil {
			return false, newChatFailure("invalid_stream", "网页 SSE 数据不是有效 JSON 对象。", http.StatusBadGateway)
		}
		if event == "error" {
			var code string
			_ = json.Unmarshal(data["error_code"], &code)
			if code == "" {
				var text string
				_ = json.Unmarshal(data["error"], &text)
				var nested struct {
					Code string `json:"error_code"`
				}
				if json.NewDecoder(strings.NewReader(text)).Decode(&nested) == nil {
					code = nested.Code
				}
			}
			if code != "" && len(code) <= 120 && safeErrorCode(code) {
				return false, newChatFailure("generation_failed", "CodeArts 网页生成失败（"+code+"）。", http.StatusBadGateway)
			}
			return false, newChatFailure("generation_failed", "CodeArts 网页生成返回 error 事件。", http.StatusBadGateway)
		}
		if event == "done" {
			var code string
			_ = json.Unmarshal(data["error_code"], &code)
			if code != "" && code != "0000" && code != "0" {
				return false, newChatFailure("generation_failed", "CodeArts 网页完成事件包含业务错误。", http.StatusBadGateway)
			}
			if failure := strings.TrimSpace(string(data["error"])); failure != "" && failure != "null" && failure != `""` && failure != "false" {
				return false, newChatFailure("generation_failed", "CodeArts 网页完成事件包含错误。", http.StatusBadGateway)
			}
			completed = true
			usage = usageFromDone(data)
			return true, nil
		}
		var messageType string
		_ = json.Unmarshal(data["message_type"], &messageType)
		if messageType == "command" {
			return false, nil
		}
		var content string
		if value, exists := data["content"]; exists {
			if json.Unmarshal(value, &content) != nil {
				return false, newChatFailure("invalid_stream", "网页正文增量必须是文本。", http.StatusBadGateway)
			}
		}
		if content == "" {
			return false, nil
		}
		piece, reached := budget.take(content)
		if reply.Len()+reasoning.Len()+len(piece) > maxReplyBytes {
			return false, newChatFailure("response_too_large", "网页回复超过本地安全读取上限。", http.StatusBadGateway)
		}
		if piece != "" {
			key := "content"
			if event == "thought" {
				reasoning.WriteString(piece)
				key = "reasoning_content"
			} else {
				reply.WriteString(piece)
			}
			if key == "content" && input.toolPolicy != nil {
				piece = toolStream.add(piece)
			}
			if piece != "" {
				if err := emitChunk(map[string]any{key: piece}, nil, nil, false); err != nil {
					return false, err
				}
			}
		}
		if reached {
			finish = "length"
			stopAttempted = true
			if stopErr := stopChat(ctx, client, credential, segment); stopErr != nil {
				return false, newChatFailure("stop_unconfirmed", "已达到本地输出上限，但网页停止结果未确认；不会自动重发。", http.StatusBadGateway)
			}
			stopped = true
			return true, nil
		}
		return false, nil
	}
	if err := readWebSSE(ctx, response.Body, process); err != nil {
		return nil, err
	}
	if !completed && !stopped {
		return nil, newChatFailure("stream_incomplete", "网页生成流意外结束，未收到 done；不会自动重发提示词。", http.StatusBadGateway)
	}
	if completed && strings.TrimSpace(reply.String()) == "" {
		return nil, newChatFailure("empty_response", "CodeArts 网页任务结束但未返回正文或客户端工具调用，请检查输入规模或官网任务状态；不会自动重发。", http.StatusBadGateway)
	}
	content, calls, err := input.toolPolicy.decode(reply.String(), completed && !stopped)
	if err != nil {
		var discovery *clientToolDiscovery
		if errors.As(err, &discovery) {
			discovery.sessionID = sessionID
			discovery.usage = addWebUsage(previousUsage, usage)
		}
		return nil, err
	}
	usage = addWebUsage(previousUsage, usage)
	if input.toolPolicy != nil {
		remaining := content[toolStream.emitted:]
		if remaining != "" {
			if err := emitChunk(map[string]any{"content": remaining}, nil, nil, false); err != nil {
				return nil, err
			}
		}
		if len(calls) > 0 {
			finish = "tool_calls"
			if input.toolPolicy.legacy {
				finish = "function_call"
				if err := emitChunk(map[string]any{"function_call": calls[0].Function}, nil, nil, false); err != nil {
					return nil, err
				}
			} else {
				for index, call := range calls {
					delta := map[string]any{"index": index, "id": call.ID, "type": call.Type, "function": call.Function}
					if err := emitChunk(map[string]any{"tool_calls": []any{delta}}, nil, nil, false); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	if err := emitChunk(map[string]any{}, finish, nil, false); err != nil {
		return nil, err
	}
	if emit != nil && input.StreamOptions.IncludeUsage && usage != nil {
		if err := emitChunk(nil, nil, usage, true); err != nil {
			return nil, err
		}
	}
	message := map[string]any{"role": "assistant", "content": content}
	if len(calls) > 0 {
		if content == "" {
			message["content"] = nil
		}
		if input.toolPolicy.legacy {
			message["function_call"] = calls[0].Function
		} else {
			message["tool_calls"] = calls
		}
	}
	if reasoning.Len() > 0 {
		message["reasoning_content"] = reasoning.String()
	}
	completion := map[string]any{"id": completionID, "object": "chat.completion", "created": createdAt, "model": publicModel,
		"choices": []any{map[string]any{"index": 0, "message": message, "finish_reason": finish}}}
	if usage != nil {
		completion["usage"] = usage
	}
	encoded, err := json.Marshal(completion)
	if err != nil {
		return nil, newChatFailure("response_encode_failed", "无法编码网页回复。", http.StatusBadGateway)
	}
	return encoded, nil
}

func safeErrorCode(value string) bool {
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func stopChat(parent context.Context, client webClient, credential *Credential, sessionSegment string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 3*time.Second)
	defer cancel()
	response, err := client.do(ctx, credential, http.MethodPost, "/chat/v1/cloudagent/sessions/"+sessionSegment+"/messages/stop", nil, "application/json, text/plain, */*", "")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("网页停止返回 HTTP %d", response.StatusCode)
	}
	return nil
}

// readWebSSE 只在完整事件边界解析，避免网络分片切断 UTF-8 或 JSON。
func readWebSSE(ctx context.Context, reader io.Reader, process func(event, data string) (bool, error)) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), maxSSELineBytes)
	event := "message"
	data := []string{}
	frameBytes := 0
	flush := func() (bool, error) {
		if len(data) == 0 {
			event = "message"
			frameBytes = 0
			return false, nil
		}
		stop, err := process(event, strings.Join(data, "\n"))
		event, data, frameBytes = "message", nil, 0
		return stop, err
	}
	for scanner.Scan() {
		if ctx.Err() != nil {
			return newChatFailure("client_cancelled", "客户端取消了网页请求，已尝试停止任务。", 499)
		}
		line := scanner.Text()
		if line == "" {
			stop, err := flush()
			if err != nil {
				return err
			}
			if stop {
				return nil
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "event":
			event = value
		case "data":
			frameBytes += len(value)
			if frameBytes > maxSSEFrameBytes {
				return newChatFailure("stream_frame_too_large", "网页 SSE 单个事件超过读取上限。", http.StatusBadGateway)
			}
			data = append(data, value)
		}
	}
	if ctx.Err() != nil {
		return newChatFailure("client_cancelled", "客户端取消了网页请求，已尝试停止任务。", 499)
	}
	if scanner.Err() != nil {
		return newChatFailure("stream_read_failed", "网页 SSE 读取中断，未确认生成完成；不会自动重发。", http.StatusBadGateway)
	}
	_, err := flush()
	return err
}

// clientToolPolicy 将客户端函数以文本协议交给模型；官网云端工具从不转发。
// 只有完整、带本次随机定界符且通过工具名/选择策略校验的响应才转成 tool_calls。
type clientToolPolicy struct {
	definitions json.RawMessage
	names       map[string]bool
	start, end  string
	required    bool
	selected    string
	parallel    bool
	legacy      bool
	deferred    bool
	byName      map[string]json.RawMessage
}

type clientToolDiscovery struct {
	names     []string
	sessionID string
	usage     map[string]any
}

func (*clientToolDiscovery) Error() string { return "模型请求客户端工具完整定义" }

func addWebUsage(previous, current map[string]any) map[string]any {
	if previous == nil {
		return current
	}
	if current == nil {
		return nil
	}
	result := make(map[string]any)
	for _, key := range []string{"prompt_tokens", "completion_tokens", "total_tokens"} {
		a, _ := previous[key].(int64)
		b, _ := current[key].(int64)
		result[key] = a + b
	}
	for key, field := range map[string]string{"prompt_tokens_details": "cached_tokens", "completion_tokens_details": "reasoning_tokens"} {
		a, _ := previous[key].(map[string]any)
		b, _ := current[key].(map[string]any)
		av, _ := a[field].(int64)
		bv, _ := b[field].(int64)
		if a != nil || b != nil {
			result[key] = map[string]any{field: av + bv}
		}
	}
	return result
}

type clientToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

func normalizeWebEffort(effort string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(effort)) {
	case "", "auto":
		return "", nil
	case "off", "none":
		return "none", nil
	case "minimal":
		return "low", nil
	case "low", "medium", "high", "xhigh", "max":
		return strings.ToLower(strings.TrimSpace(effort)), nil
	default:
		return "", newChatFailure("unsupported_parameter", "CodeArts 网页思考强度支持 none、low、medium、high、xhigh、max。", http.StatusBadRequest)
	}
}

func prepareClientTools(input *chatInput, fullTools bool) (*clientToolPolicy, error) {
	invalid := func(message string) (*clientToolPolicy, error) {
		return nil, newChatFailure("invalid_tools", message, http.StatusBadRequest)
	}
	legacy := nonEmptyJSON(input.Functions)
	if legacy && nonEmptyJSON(input.Tools) {
		return invalid("tools 与旧版 functions 不能同时提供。")
	}
	definitions := input.Tools
	choice := input.ToolChoice
	if legacy {
		definitions, choice = input.Functions, input.FunctionCall
	}
	var items []map[string]json.RawMessage
	if nonEmptyJSON(definitions) && (json.Unmarshal(definitions, &items) != nil || len(items) > 1024) {
		return invalid("客户端工具定义必须是 JSON 数组，最多 1024 个工具。")
	}
	policy := &clientToolPolicy{names: make(map[string]bool), byName: make(map[string]json.RawMessage), parallel: true, legacy: legacy}
	if input.ParallelToolCalls != nil {
		policy.parallel = *input.ParallelToolCalls
	}
	for _, item := range items {
		function := item
		if !legacy {
			var kind string
			if json.Unmarshal(item["type"], &kind) != nil || kind != "function" || json.Unmarshal(item["function"], &function) != nil || function == nil {
				return invalid("CodeArts 网页桥接只支持 function 类型的客户端工具。")
			}
		}
		var name string
		if json.Unmarshal(function["name"], &name) != nil || !validClientToolName(name) || policy.names[name] {
			return invalid("工具名称无效或重复。")
		}
		if raw := function["parameters"]; nonEmptyJSON(raw) {
			var schema map[string]json.RawMessage
			if json.Unmarshal(raw, &schema) != nil || schema == nil {
				return invalid("工具 parameters 必须是 JSON Schema 对象。")
			}
		}
		policy.names[name] = true
		policy.byName[name], _ = json.Marshal(item)
	}
	mode := "auto"
	if nonEmptyJSON(choice) {
		if json.Unmarshal(choice, &mode) != nil {
			var selection struct {
				Type     string `json:"type"`
				Name     string `json:"name"`
				Function struct {
					Name string `json:"name"`
				} `json:"function"`
			}
			if json.Unmarshal(choice, &selection) != nil {
				return invalid("tool_choice 格式无效。")
			}
			if legacy {
				policy.selected = selection.Name
			} else if selection.Type == "function" {
				policy.selected = selection.Function.Name
			}
			if !policy.names[policy.selected] {
				return invalid("tool_choice 指定的工具不在本次定义中。")
			}
			policy.required = true
		} else {
			switch mode {
			case "none":
				return nil, nil
			case "auto":
			case "required":
				policy.required = true
			default:
				return invalid("tool_choice 支持 auto、none、required 或指定 function。")
			}
		}
	}
	if len(policy.names) == 0 {
		if policy.required {
			return invalid("要求调用工具时必须提供工具定义。")
		}
		return nil, nil
	}
	if legacy {
		policy.parallel = false
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, newChatFailure("tool_protocol_failed", "无法建立客户端工具协议。", http.StatusInternalServerError)
	}
	key := hex.EncodeToString(nonce)
	policy.start, policy.end = "<codearts-client-tools-"+key+">", "</codearts-client-tools-"+key+">"
	policy.definitions = definitions
	if len(definitions) > 64<<10 && !fullTools {
		if policy.selected != "" {
			policy.definitions, _ = json.Marshal([]json.RawMessage{policy.byName[policy.selected]})
		} else {
			policy.deferred = true
			index := make([]map[string]string, 0, len(items))
			for _, item := range items {
				function := item
				if !legacy {
					_ = json.Unmarshal(item["function"], &function)
				}
				var name, description string
				_ = json.Unmarshal(function["name"], &name)
				_ = json.Unmarshal(function["description"], &description)
				summary := []rune(strings.SplitN(description, "\n", 2)[0])
				if len(summary) > 120 {
					summary = summary[:120]
				}
				index = append(index, map[string]string{"name": name, "summary": string(summary)})
			}
			policy.definitions, _ = json.Marshal(index)
		}
	}
	return policy, nil
}

func validClientToolName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func (policy *clientToolPolicy) instructions() string {
	if policy == nil {
		return ""
	}
	var text strings.Builder
	if policy.deferred {
		text.WriteString("\n\n客户端工具索引（摘要仅供选择，不足以构造参数；完整定义由客户端保留并按需提供）：\n")
	} else {
		text.WriteString("\n\n客户端函数工具完整定义（工具由客户端执行，不能替换为你的云端内置工具）：\n")
	}
	text.Write(policy.definitions)
	if policy.deferred {
		text.WriteString("\n不需要工具时直接回答用户。需要工具时，必须先请求所需工具的完整定义；不要猜测参数或直接调用工具。输出以下完整定界块后停止，下一轮会提供定义。最多选择16个工具。\n")
		text.WriteString(policy.start + "\n" + `{"describe_tools":["实际工具名"]}` + "\n" + policy.end + "\n")
	} else {
		text.WriteString("\n只有需要客户端工具时才输出如下完整定界块。块内必须是 JSON 对象，calls 为数组，arguments 是符合参数定义的 JSON 对象。不要在思考内容中输出定界块；输出后立即结束，等待下一轮工具结果。定界块之外可以有简短正文。\n")
		text.WriteString(policy.start + "\n" + `{"calls":[{"name":"实际工具名","arguments":{}}]}` + "\n" + policy.end + "\n")
	}
	if policy.required {
		text.WriteString("本轮必须调用至少一个客户端工具。\n")
	} else {
		text.WriteString("不需要工具时直接回答用户，绝不能为了使用工具而读取文件。\n")
	}
	if policy.selected != "" {
		text.WriteString("本轮只能调用客户端工具 " + policy.selected + "。\n")
	}
	if !policy.parallel {
		text.WriteString("本轮最多调用一个客户端工具。\n")
	}
	return text.String()
}

func (policy *clientToolPolicy) decode(text string, complete bool) (string, []clientToolCall, error) {
	if policy == nil {
		return text, nil, nil
	}
	failure := func(message string) (string, []clientToolCall, error) {
		return "", nil, newChatFailure("invalid_tool_response", message, http.StatusBadGateway)
	}
	start := strings.Index(text, policy.start)
	if start < 0 {
		if policy.required {
			return failure("官网未返回所要求的客户端工具调用；不会执行或重发。")
		}
		return text, nil, nil
	}
	if !complete {
		return failure("客户端工具响应因限长而不完整；不会执行残缺参数。")
	}
	after := text[start+len(policy.start):]
	end := strings.Index(after, policy.end)
	if end < 0 {
		return failure("客户端工具响应缺少结束定界符。")
	}
	trailing := after[end+len(policy.end):]
	if strings.Contains(trailing, policy.start) {
		return failure("客户端工具响应包含多个协议块。")
	}
	var envelope struct {
		Describe []string `json:"describe_tools"`
		Calls    []struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"calls"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(after[:end])), &envelope) != nil {
		return failure("客户端工具响应不是有效 JSON。")
	}
	if policy.deferred {
		if len(envelope.Calls) > 0 || len(envelope.Describe) == 0 || len(envelope.Describe) > 16 {
			return failure("模型需要先选择工具并取得完整定义，不能直接猜测参数。")
		}
		seen := make(map[string]bool)
		for _, name := range envelope.Describe {
			if !policy.names[name] || seen[name] {
				return failure("模型请求了未知或重复的工具定义。")
			}
			seen[name] = true
		}
		return "", nil, &clientToolDiscovery{names: envelope.Describe}
	}
	if len(envelope.Describe) > 0 || len(envelope.Calls) == 0 || len(envelope.Calls) > 64 || !policy.parallel && len(envelope.Calls) != 1 {
		return failure("客户端工具响应不是有效调用数组，或违反并行调用限制。")
	}
	calls := make([]clientToolCall, 0, len(envelope.Calls))
	for _, call := range envelope.Calls {
		if !policy.names[call.Name] || policy.selected != "" && policy.selected != call.Name {
			return failure("官网返回了本次未授权的客户端工具名。")
		}
		arguments := call.Arguments
		var encoded string
		if json.Unmarshal(arguments, &encoded) == nil {
			arguments = []byte(encoded)
		}
		var object map[string]json.RawMessage
		if json.Unmarshal(arguments, &object) != nil || object == nil {
			return failure("客户端工具 arguments 必须是完整 JSON 对象。")
		}
		canonical, _ := json.Marshal(object)
		id := make([]byte, 12)
		if _, err := rand.Read(id); err != nil {
			return failure("无法生成客户端工具调用 ID。")
		}
		converted := clientToolCall{ID: "call_" + hex.EncodeToString(id), Type: "function"}
		converted.Function.Name, converted.Function.Arguments = call.Name, string(canonical)
		calls = append(calls, converted)
	}
	return text[:start] + trailing, calls, nil
}

// clientToolStream 只暂存足以识别开定界符的尾部；普通正文仍实时输出。
// 定界块出现后全部暂存，直到完整响应通过校验，避免残缺 JSON 被客户端执行。
type clientToolStream struct {
	policy  *clientToolPolicy
	pending string
	blocked bool
	emitted int
}

func (stream *clientToolStream) add(piece string) string {
	if stream.policy == nil {
		return piece
	}
	stream.pending += piece
	if stream.blocked {
		return ""
	}
	if start := strings.Index(stream.pending, stream.policy.start); start >= 0 {
		result := stream.pending[:start]
		stream.pending = stream.pending[start:]
		stream.blocked = true
		stream.emitted += len(result)
		return result
	}
	end := len(stream.pending) - len(stream.policy.start) + 1
	for end > 0 && !utf8.ValidString(stream.pending[:end]) {
		end--
	}
	if end <= 0 {
		return ""
	}
	result := stream.pending[:end]
	stream.pending = stream.pending[end:]
	stream.emitted += len(result)
	return result
}
