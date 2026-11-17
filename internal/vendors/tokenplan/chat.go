package tokenplan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"freetier2api-plugin/internal/core"
	"net/http"
	"sort"
	"strings"
	"time"
)

func lockExecuteRequest(req *core.ExecuteRequest) (*core.ExecuteRequest, error) {
	if req == nil {
		return nil, errors.New("模型请求不能为空")
	}
	model := strings.TrimSpace(req.Model)
	if model == "" {
		var body struct {
			Model string `json:"model"`
		}
		if json.Unmarshal(req.Payload, &body) != nil {
			return nil, errors.New("模型请求格式无效")
		}
		model = body.Model
	}
	window := (&adapter{}).FixedModelContextLength(model)
	if window <= 0 {
		return nil, core.NewPluginError("tokenplan_model_not_pinned", "该模型尚未编入插件固定上下文表", http.StatusBadRequest)
	}
	copy := *req
	copy.Model = model
	copy.ContextLength = window
	return &copy, nil
}

func modelBody(req *core.ExecuteRequest) ([]byte, error) {
	if req == nil {
		return nil, errors.New("模型请求不能为空")
	}
	if strings.TrimSpace(req.Model) == "" {
		return req.Payload, nil
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(req.Payload, &payload); err != nil || payload == nil {
		return nil, errors.New("模型请求必须是 JSON 对象")
	}
	payload["model"], _ = json.Marshal(req.Model)
	return json.Marshal(payload)
}

func prepareBody(raw []byte, stream bool) ([]byte, error) {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(raw, &payload); err != nil || payload == nil {
		return nil, errors.New("模型请求必须是 JSON 对象")
	}
	// 官方 Token Plan 不支持通过请求调整思考强度。
	for _, key := range []string{"thinking", "reasoning", "reasoning_effort", "thinking_budget", "enable_thinking"} {
		delete(payload, key)
	}
	// 上下文不属于上游请求参数；移除客户端或凭证带来的覆盖值。
	for _, key := range []string{"context_length", "context_window", "max_context_length", "input_token_limit", "max_input_tokens"} {
		delete(payload, key)
	}
	if value, ok := payload["max_completion_tokens"]; ok {
		if _, exists := payload["max_tokens"]; !exists {
			payload["max_tokens"] = value
		}
		delete(payload, "max_completion_tokens")
	}
	if stream {
		payload["stream"] = json.RawMessage("true")
	} else {
		payload["stream"] = json.RawMessage("false")
		delete(payload, "stream_options")
	}
	if rawTools, ok := payload["tools"]; ok && len(rawTools) >= 64<<10 {
		payload["tools"] = compactTools(rawTools)
	}
	return json.Marshal(payload)
}

// compactTools 通过共享相同的 Schema 子树减少工具输入 token，不减少工具或参数。
// 只优化较大的工具清单；保持数字精度，并原样保留非函数工具。
func compactTools(raw json.RawMessage) json.RawMessage {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var tools []map[string]any
	if decoder.Decode(&tools) != nil {
		return raw
	}
	for _, tool := range tools {
		if tool["type"] != "function" {
			continue
		}
		function, ok := tool["function"].(map[string]any)
		if !ok {
			continue
		}
		schema, ok := function["parameters"].(map[string]any)
		if !ok {
			continue
		}
		function["parameters"] = compactSchema(schema)
	}
	encoded, err := json.Marshal(tools)
	if err != nil || len(encoded) >= len(raw) {
		return raw
	}
	return encoded
}

type schemaCompactor struct {
	counts   map[string]int
	nodes    map[string]map[string]any
	selected map[string]string
	unsafe   bool
}

func schemaKey(schema map[string]any) string {
	encoded, _ := json.Marshal(schema)
	return string(encoded)
}

// 仅遍历 JSON Schema 的子模式关键字，避免将 examples/default 内的数据改成引用。
func schemaChildren(schema map[string]any, transform func(map[string]any) map[string]any) map[string]any {
	result := make(map[string]any, len(schema))
	for key, value := range schema {
		result[key] = value
		switch key {
		case "properties", "patternProperties", "$defs", "definitions", "dependentSchemas":
			if values, ok := value.(map[string]any); ok {
				updated := make(map[string]any, len(values))
				for name, item := range values {
					if child, ok := item.(map[string]any); ok {
						updated[name] = transform(child)
					} else {
						updated[name] = item
					}
				}
				result[key] = updated
			}
		case "allOf", "anyOf", "oneOf", "prefixItems", "items", "additionalProperties", "additionalItems", "contains", "not", "if", "then", "else", "propertyNames", "unevaluatedProperties", "unevaluatedItems", "contentSchema":
			if child, ok := value.(map[string]any); ok {
				result[key] = transform(child)
			} else if values, ok := value.([]any); ok {
				updated := make([]any, len(values))
				for index, item := range values {
					if child, ok := item.(map[string]any); ok {
						updated[index] = transform(child)
					} else {
						updated[index] = item
					}
				}
				result[key] = updated
			}
		}
	}
	return result
}

func (c *schemaCompactor) count(schema map[string]any, depth int) {
	if depth > 64 {
		c.unsafe = true
		return
	}
	for _, key := range []string{"$id", "$anchor", "$dynamicAnchor", "$dynamicRef", "$recursiveRef", "$recursiveAnchor"} {
		if _, exists := schema[key]; exists {
			c.unsafe = true
			return
		}
	}
	if depth > 0 {
		for _, key := range []string{"$schema", "$defs", "definitions"} {
			if _, exists := schema[key]; exists {
				c.unsafe = true
				return
			}
		}
	}
	_, dialect := schema["$schema"]
	_, defs := schema["$defs"]
	_, legacyDefs := schema["definitions"]
	if !dialect && !defs && !legacyDefs {
		key := schemaKey(schema)
		if len(key) >= 256 {
			c.counts[key]++
			c.nodes[key] = schema
		}
	}
	schemaChildren(schema, func(child map[string]any) map[string]any { c.count(child, depth+1); return child })
}

func (c *schemaCompactor) rewrite(schema map[string]any, skip string) map[string]any {
	key := schemaKey(schema)
	if name, ok := c.selected[key]; ok && key != skip {
		return map[string]any{"$ref": "#/$defs/" + name}
	}
	return schemaChildren(schema, func(child map[string]any) map[string]any { return c.rewrite(child, "") })
}

func compactSchema(schema map[string]any) map[string]any {
	c := &schemaCompactor{counts: map[string]int{}, nodes: map[string]map[string]any{}, selected: map[string]string{}}
	c.count(schema, 0)
	if c.unsafe {
		return schema
	}
	keys := []string{}
	for key, count := range c.counts {
		if count > 1 {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return schema
	}
	sort.Strings(keys)
	existing, exists := schema["$defs"]
	if exists {
		if _, ok := existing.(map[string]any); !ok {
			return schema
		}
	}
	for index, key := range keys {
		name := fmt.Sprintf("freetier_schema_%d", index)
		if defs, ok := existing.(map[string]any); ok {
			if _, collision := defs[name]; collision {
				return schema
			}
		}
		c.selected[key] = name
	}
	result := c.rewrite(schema, "")
	defs, ok := result["$defs"].(map[string]any)
	if !ok {
		defs = map[string]any{}
		result["$defs"] = defs
	}
	for _, key := range keys {
		defs[c.selected[key]] = c.rewrite(c.nodes[key], key)
	}
	if len(schemaKey(result)) >= len(schemaKey(schema)) {
		return schema
	}
	return result
}

func Chat(ctx context.Context, baseURL, apiKey string, raw []byte) ([]byte, error) {
	body, err := prepareBody(raw, false)
	if err != nil {
		return nil, err
	}
	req, err := newRequest(ctx, http.MethodPost, baseURL, "/chat/completions", apiKey, body, false)
	if err != nil {
		return nil, err
	}
	resp, err := client(ctx, 10*time.Minute, false).Do(req)
	if err != nil {
		return nil, &core.Failure{Kind: core.FailureKindTransient, Msg: "Token Plan 请求失败: " + err.Error()}
	}
	defer resp.Body.Close()
	return readResponse(resp, 32<<20)
}

func ChatStream(ctx context.Context, baseURL, apiKey string, raw []byte) (*http.Response, error) {
	body, err := prepareBody(raw, true)
	if err != nil {
		return nil, err
	}
	req, err := newRequest(ctx, http.MethodPost, baseURL, "/chat/completions", apiKey, body, true)
	if err != nil {
		return nil, err
	}
	resp, err := client(ctx, 0, true).Do(req)
	if err != nil {
		return nil, &core.Failure{Kind: core.FailureKindTransient, Msg: "Token Plan 流式请求失败: " + err.Error()}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		_, err = readResponse(resp, 1<<20)
		return nil, err
	}
	if !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		resp.Body.Close()
		return nil, errors.New("Token Plan 没有返回 SSE 流")
	}
	return resp, nil
}
