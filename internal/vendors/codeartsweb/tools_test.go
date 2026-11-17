package codeartsweb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

func testToolOptions() map[string]any {
	return map[string]any{"tools": []any{
		map[string]any{"type": "function", "function": map[string]any{"name": "get_weather", "description": "查询天气", "parameters": map[string]any{"type": "object", "properties": map[string]any{"city": map[string]any{"type": "string"}}, "required": []string{"city"}}}},
		map[string]any{"type": "function", "function": map[string]any{"name": "get_time", "parameters": map[string]any{"type": "object"}}},
	}}
}

func protocolFixture(t *testing.T, calls string, split bool) *chatFixture {
	t.Helper()
	var fixture *chatFixture
	fixture = newChatFixture(t, "", func(w http.ResponseWriter, _ *http.Request) {
		body := <-fixture.body
		prompt := body["content"].(string)
		start := regexp.MustCompile(`<codearts-client-tools-[a-f0-9]+>`).FindString(prompt)
		if start == "" {
			t.Error("缺少客户端工具指令")
			return
		}
		end := "</" + start[1:]
		text := "正在查询。" + start + calls + end + "\n"
		fmt.Fprint(w, "event: tool_call\ndata: {\"tool\":\"bash\",\"params\":{\"command\":\"ignored\"}}\n\n")
		pieces := []string{text}
		if split {
			pieces = nil
			for _, c := range text {
				pieces = append(pieces, string(c))
			}
		}
		for _, piece := range pieces {
			encoded, _ := json.Marshal(map[string]any{"content": piece})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", encoded)
		}
		fmt.Fprint(w, "event: done\ndata: {\"tokens\":{\"input\":5,\"output\":30}}\n\n")
	})
	return fixture
}

func TestWebClientToolsKeepDefinitionsAndHistory(t *testing.T) {
	options := testToolOptions()
	options["messages"] = []any{
		map[string]any{"role": "system", "content": "按工具结果回答"},
		map[string]any{"role": "assistant", "content": nil, "tool_calls": []any{map[string]any{"id": "call_old", "type": "function", "function": map[string]any{"name": "get_weather", "arguments": `{"city":"北京"}`}}}},
		map[string]any{"role": "tool", "tool_call_id": "call_old", "content": "晴天"},
		map[string]any{"role": "user", "content": "现在几点"},
	}
	input, prompt, _, err := buildChatInput(chatRequest(t, options))
	if err != nil || input.toolPolicy == nil {
		t.Fatalf("工具请求不应被拒绝：%v", err)
	}
	for _, wanted := range []string{`"required":["city"]`, `"tool_call_id":"call_old"`, `晴天`, `现在几点`, `客户端执行`} {
		if !strings.Contains(prompt, wanted) {
			t.Errorf("丢失定义或历史 %s", wanted)
		}
	}
}

func TestWebClientToolsStreamAndNonStream(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(fmt.Sprint(streaming), func(t *testing.T) {
			fixture := protocolFixture(t, `{"calls":[{"name":"get_weather","arguments":{"city":"北京"}},{"name":"get_time","arguments":"{}"}]}`, true)
			var chunks []map[string]any
			var emit func([]byte) error
			if streaming {
				emit = func(raw []byte) error { chunks = append(chunks, parsedCompletion(t, raw)); return nil }
			}
			raw, err := runChat(context.Background(), fixture.client, fixture.credential, "demo", chatRequest(t, testToolOptions()), emit)
			if err != nil {
				t.Fatal(err)
			}
			choice := completionChoice(t, raw)
			message := choice["message"].(map[string]any)
			calls := message["tool_calls"].([]any)
			if choice["finish_reason"] != "tool_calls" || len(calls) != 2 {
				t.Fatalf("工具完成形态错误：%s", raw)
			}
			first := calls[0].(map[string]any)
			if first["function"].(map[string]any)["arguments"] != `{"city":"北京"}` {
				t.Fatalf("参数不完整：%v", calls)
			}
			if first["id"] == calls[1].(map[string]any)["id"] {
				t.Fatal("工具 ID 不能重复")
			}
			if streaming {
				var text strings.Builder
				count := 0
				for _, chunk := range chunks {
					for _, c := range chunk["choices"].([]any) {
						delta := c.(map[string]any)["delta"].(map[string]any)
						if value, ok := delta["content"].(string); ok {
							text.WriteString(value)
						}
						if values, ok := delta["tool_calls"].([]any); ok {
							count += len(values)
						}
					}
				}
				if text.String() != message["content"] || count != 2 || strings.Contains(text.String(), "codearts-client-tools") {
					t.Fatalf("流式协议泄漏或丢失：%q %d", text.String(), count)
				}
			}
			if fixture.stopped.Load() != 0 {
				t.Fatal("完成任务不应再次停止")
			}
		})
	}
}

func TestWebClientToolsRejectUnapprovedCalls(t *testing.T) {
	for name, calls := range map[string]string{
		"unknown":   `{"calls":[{"name":"bash","arguments":{}}]}`,
		"malformed": `{"calls":[{"name":"get_weather","arguments":"broken"}]}`,
		"empty":     `{"calls":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			fixture := protocolFixture(t, calls, false)
			_, err := runChat(context.Background(), fixture.client, fixture.credential, "demo", chatRequest(t, testToolOptions()), func(raw []byte) error {
				if strings.Contains(string(raw), `"tool_calls"`) {
					t.Error("无效工具不可下发")
				}
				return nil
			})
			if err == nil {
				t.Fatal("无效工具必须报错")
			}
		})
	}
}

func TestWebClientToolChoiceAndTruncation(t *testing.T) {
	options := testToolOptions()
	options["tool_choice"] = map[string]any{"type": "function", "function": map[string]any{"name": "get_weather"}}
	options["parallel_tool_calls"] = false
	input, _, _, err := buildChatInput(chatRequest(t, options))
	if err != nil {
		t.Fatal(err)
	}
	policy := input.toolPolicy
	for _, text := range []string{"只回答正文", policy.start + `{"calls":[{"name":"get_time","arguments":{}}]}` + policy.end, policy.start + `{"calls":[{"name":"get_weather","arguments":{}},{"name":"get_weather","arguments":{}}]}` + policy.end, policy.start + `{"calls":[]}`} {
		if _, _, err := policy.decode(text, true); err == nil {
			t.Error("策略不匹配必须报错")
		}
	}
	text := policy.start + `{"calls":[{"name":"get_weather","arguments":{}}]}` + policy.end
	if _, _, err := policy.decode(text, false); err == nil {
		t.Fatal("限长不能执行残缺调用")
	}
	if _, calls, err := policy.decode(text, true); err != nil || len(calls) != 1 {
		t.Fatalf("合法单工具失败 %v", err)
	}
}

func TestWebClientToolsNoToolsAndLegacy(t *testing.T) {
	options := testToolOptions()
	options["tool_choice"] = "none"
	input, _, _, err := buildChatInput(chatRequest(t, options))
	if err != nil || input.toolPolicy != nil {
		t.Fatal("none 不应启用工具桥")
	}
	legacy := map[string]any{"functions": []any{map[string]any{"name": "get_weather", "parameters": map[string]any{"type": "object"}}}, "function_call": map[string]any{"name": "get_weather"}}
	fixture := protocolFixture(t, `{"calls":[{"name":"get_weather","arguments":{}}]}`, false)
	raw, err := runChat(context.Background(), fixture.client, fixture.credential, "demo", chatRequest(t, legacy), nil)
	if err != nil {
		t.Fatal(err)
	}
	choice := completionChoice(t, raw)
	if choice["finish_reason"] != "function_call" || choice["message"].(map[string]any)["function_call"] == nil {
		t.Fatalf("旧协议转换失败：%s", raw)
	}
}

func TestWebReasoningOffMapsToOfficialNone(t *testing.T) {
	fixture := newChatFixture(t, "event: message\ndata: {\"content\":\"OK\"}\n\nevent: done\ndata: {}\n\n", nil)
	_, err := runChat(context.Background(), fixture.client, fixture.credential, "demo", chatRequest(t, map[string]any{"reasoning_effort": "off"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if body := <-fixture.body; body["reasoning_effort"] != "none" {
		t.Fatalf("未使用官网值：%v", body)
	}
	_, _, _, err = buildChatInput(chatRequest(t, map[string]any{"reasoning_effort": "unknown"}))
	if err == nil {
		t.Fatal("未知思考档位需在提交前拒绝")
	}
}

func TestWebLargeToolDiscoveryUsesOneCloudSession(t *testing.T) {
	options := testToolOptions()
	tools := options["tools"].([]any)
	tools[1].(map[string]any)["function"].(map[string]any)["description"] = strings.Repeat("完整描述必须保留。", 10000)
	options["tool_choice"] = "required"
	options["stream_options"] = map[string]any{"include_usage": true}
	var fixture *chatFixture
	fixture = newChatFixture(t, "", func(w http.ResponseWriter, _ *http.Request) {
		body := <-fixture.body
		prompt := body["content"].(string)
		start := regexp.MustCompile(`<codearts-client-tools-[a-f0-9]+>`).FindString(prompt)
		end := "</" + start[1:]
		var response string
		if fixture.generated.Load() == 1 {
			if len(prompt) > 10000 || !strings.Contains(prompt, "索引") {
				t.Error("大定义必须按需提供")
			}
			response = start + `{"describe_tools":["get_weather"]}` + end
		} else {
			if !strings.Contains(prompt, `"required":["city"]`) || strings.Contains(prompt, "只回复 OK") {
				t.Error("应提供完整所选 Schema，且不重发原提示词")
			}
			response = start + `{"calls":[{"name":"get_weather","arguments":{"city":"北京"}}]}` + end
		}
		encoded, _ := json.Marshal(map[string]any{"content": response})
		fmt.Fprintf(w, "event: message\ndata: %s\n\nevent: done\ndata: {\"tokens\":{\"input\":10,\"output\":5}}\n\n", encoded)
	})
	var chunks [][]byte
	raw, err := runChat(context.Background(), fixture.client, fixture.credential, "demo", chatRequest(t, options), func(chunk []byte) error { chunks = append(chunks, append([]byte{}, chunk...)); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if fixture.created.Load() != 1 || fixture.generated.Load() != 2 {
		t.Fatal("定义协商应使用同一会话，不重建或重发原提示词")
	}
	result := parsedCompletion(t, raw)
	usage := result["usage"].(map[string]any)
	if usage["prompt_tokens"] != float64(20) || usage["completion_tokens"] != float64(10) {
		t.Fatalf("应汇总两轮实际用量：%v", usage)
	}
	for _, chunk := range chunks {
		if strings.Contains(string(chunk), "describe_tools") {
			t.Fatal("定义协商不应作为客户端工具执行")
		}
	}
	if completionChoice(t, raw)["finish_reason"] != "tool_calls" {
		t.Fatalf("工具完成形态错误：%s", raw)
	}
}

func TestWebLargeToolsPlainAnswerAndEmptyDone(t *testing.T) {
	options := testToolOptions()
	options["tools"].([]any)[0].(map[string]any)["function"].(map[string]any)["description"] = strings.Repeat("长描述", 30000)
	fixture := newChatFixture(t, "event: message\ndata: {\"content\":\"OK\"}\n\nevent: done\ndata: {}\n\n", nil)
	var streamed strings.Builder
	raw, err := runChat(context.Background(), fixture.client, fixture.credential, "demo", chatRequest(t, options), func(chunk []byte) error { streamed.Write(chunk); return nil })
	if err != nil || fixture.generated.Load() != 1 || !strings.Contains(string(raw), `"content":"OK"`) || !strings.Contains(streamed.String(), `"content":"OK"`) {
		t.Fatalf("无工具需求只应请求一轮：%s %v", raw, err)
	}
	empty := newChatFixture(t, "event: done\ndata: {\"tokens\":{\"input\":0,\"output\":0}}\n\n", nil)
	_, err = runChat(context.Background(), empty.client, empty.credential, "demo", chatRequest(t, nil), nil)
	if err == nil {
		t.Fatal("空 done 不得当作成功")
	}
}
