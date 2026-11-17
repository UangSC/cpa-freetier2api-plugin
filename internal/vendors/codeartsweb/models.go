package codeartsweb

import (
	"context"
	"encoding/json"
	"strings"

	"freetier2api-plugin/cpasdk/pluginapi"
	"freetier2api-plugin/internal/core"
)

const modelDetailPath = "/chat/PromptCenterService/v1/agent-center/agents/detail?agent_id=a8bcb36232554267a5142361cc25a393"

type Model struct {
	ID, Name                        string
	ContextWindow, Input, MaxOutput int64
}

func unwrapObject(value map[string]any) map[string]any {
	for index := 0; index < 3; index++ {
		if nested, ok := value["data"].(map[string]any); ok {
			value = nested
			continue
		}
		if nested, ok := value["result"].(map[string]any); ok {
			value = nested
			continue
		}
		break
	}
	return value
}

func parameterInt(value any) int64 {
	switch number := value.(type) {
	case float64:
		if number > 0 && number < 1<<53 {
			return int64(number)
		}
	case json.Number:
		result, _ := number.Int64()
		if result > 0 {
			return result
		}
	}
	return 0
}

func modelString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if text, ok := values[key].(string); ok && strings.TrimSpace(text) != "" {
			return strings.TrimSpace(text)
		}
	}
	return ""
}

func parseModels(response map[string]any) []Model {
	root := unwrapObject(response)
	gpts, _ := root["gpts"].(map[string]any)
	items, _ := gpts["models"].([]any)
	models := make([]Model, 0, len(items))
	for _, raw := range items {
		item, ok := raw.(map[string]any)
		if !ok || item["enable"] == false || item["display_enabled"] == false {
			continue
		}
		parameters, _ := item["model_parameters"].(map[string]any)
		if parameters["enable"] == false || parameters["display_enabled"] == false {
			continue
		}
		id := modelString(parameters, "model_id", "id", "name", "model_name")
		if id == "" {
			id = modelString(item, "model_id", "id", "model_name")
		}
		if id == "" {
			continue
		}
		name := core.FirstNonEmpty(modelString(item, "model_name", "name"), id)
		context := parameterInt(parameters["context_window"])
		if context == 0 {
			context = parameterInt(parameters["input_context_window"])
		}
		input := parameterInt(parameters["input_length"])
		if input == 0 {
			input = parameterInt(parameters["input_context_window"])
		}
		if input == 0 {
			input = context
		}
		output := parameterInt(parameters["output_context_window"])
		if output == 0 {
			output = parameterInt(parameters["max_tokens"])
		}
		models = append(models, Model{ID: id, Name: name, ContextWindow: context, Input: input, MaxOutput: output})
	}
	return models
}

func (v *adapter) StaticModels(ctx context.Context) ([]pluginapi.ModelInfo, error) {
	cred, exists := core.ProbeNativeCredential(v.Env, VendorID, func(credential *core.Credential) (*Credential, bool) {
		native, ok := credential.Native.(*Credential)
		return native, ok && native != nil
	})
	if !exists {
		return nil, nil
	}
	return v.fetchModels(ctx, cred)
}

func (v *adapter) ModelsForAuth(ctx context.Context, cred *core.Credential) ([]pluginapi.ModelInfo, error) {
	native, err := v.Native(cred)
	if err != nil {
		return nil, err
	}
	return v.fetchModels(ctx, native)
}

func (v *adapter) fetchModels(ctx context.Context, cred *Credential) ([]pluginapi.ModelInfo, error) {
	if err := v.verifyIdentity(ctx, cred); err != nil {
		return nil, err
	}
	response, err := v.client.json(ctx, cred, "GET", modelDetailPath, nil, "AgentCenter")
	if err != nil {
		return nil, err
	}
	models := parseModels(response)
	if len(models) == 0 {
		return nil, core.NewPluginError("web_models_unavailable", "CodeArts 网页没有返回可用模型，请检查登录会话", 401)
	}
	result := make([]pluginapi.ModelInfo, 0, len(models))
	for _, model := range models {
		info := core.ModelInfoToPluginAPI(VendorID, core.ModelDescriptor{
			ID: model.ID, Name: model.Name + "（网页）", ContextLength: model.ContextWindow, MaxOutputTokens: model.MaxOutput,
			Description:   "CodeArts 网页智能体通道；支持文本、思考流与客户端函数文本桥接，多轮历史按角色传入；官网云端工具不会交给客户端，输出限长由代理保守执行。",
			SupportsTools: true,
		})
		info.InputTokenLimit = model.Input
		info.SupportedParameters = []string{"stream", "max_tokens", "max_completion_tokens", "reasoning_effort", "tools", "tool_choice", "parallel_tool_calls", "functions", "function_call"}
		result = append(result, info)
	}
	return result, nil
}
