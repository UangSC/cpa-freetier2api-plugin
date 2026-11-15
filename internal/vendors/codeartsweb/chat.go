package codeartsweb

import (
	"bufio"
	"context"
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
	N                   *int            `json:"n"`
	MaxTokens           *int64          `json:"max_tokens"`
	MaxCompletionTokens *int64          `json:"max_completion_tokens"`
	ReasoningEffort     string          `json:"reasoning_effort"`
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
	if nonEmptyJSON(input.Tools) || nonEmptyJSON(input.Functions) {
		return input, "", 0, newChatFailure("unsupported_tools", "CodeArts 网页通道暂不支持客户端函数工具；平台自己的工具事件不会转成客户端 tool_calls。", http.StatusBadRequest)
	}
	if choice := strings.TrimSpace(string(input.ToolChoice)); choice != "" && choice != "null" && choice != `"none"` && choice != `"auto"` {
		return input, "", 0, newChatFailure("unsupported_tools", "CodeArts 网页通道不支持指定客户端工具。", http.StatusBadRequest)
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
	prompt := "请根据以下 JSON 对话历史续写下一条 assistant 回复。role 字段标明消息角色，content 是该角色的消息内容；完整考虑 system、developer 和全部历史。不要复述记录，不要添加角色标签。直接回答最后的请求；这次对话不需要创建或修改工作区文件，不要调用平台内置工具。\n\n对话历史：\n" + string(encoded)
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
	input, prompt, limit, err := buildChatInput(raw)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(model) == "" {
		return nil, newChatFailure("invalid_request", "模型 ID 不能为空。", http.StatusBadRequest)
	}
	created, err := client.json(ctx, credential, http.MethodPost, "/chat/v1/cloudagent/sessions", map[string]any{}, "CodeBase")
	if err != nil {
		return nil, err
	}
	creation, _ := created["result"].(map[string]any)
	sessionID, _ := creation["session_id"].(string)
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
			if err := emitChunk(map[string]any{key: piece}, nil, nil, false); err != nil {
				return false, err
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
	if err := emitChunk(map[string]any{}, finish, nil, false); err != nil {
		return nil, err
	}
	if emit != nil && input.StreamOptions.IncludeUsage && usage != nil {
		if err := emitChunk(nil, nil, usage, true); err != nil {
			return nil, err
		}
	}
	message := map[string]any{"role": "assistant", "content": reply.String()}
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
