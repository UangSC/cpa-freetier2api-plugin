package tokenplan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"freetier2api-plugin/cpasdk/pluginapi"
	"freetier2api-plugin/internal/core"
	"net/http"
	"strings"
	"time"
)

// 官方模型信息于 2026-11-16 核对；作为插件内置默认值，避免元数据缺失时猜测容量。
var defaultContextLengths = map[string]int64{
	"Agents-A1":                262144,
	"Atria-Dawn":               524288,
	"Atria-Dawn-Preview":       524288,
	"Sage-A1.5":                524288,
	"Sage-A1.5-Taiyi":          524288,
	"Sage-S2.1-Flash":          524288,
	"deepseek-v4.1-flash-1017": 1048576,
	"glm-5.3":                  1048576,
	"intern-s2":                262144,
	"kimi-k3.1-pro":            1048576,
	"qwen3.8-27b":              262144,
}

func (v *adapter) FixedModelContextLength(modelID string) int64 {
	for id, length := range defaultContextLengths {
		if strings.EqualFold(strings.TrimSpace(modelID), id) {
			return length
		}
	}
	return 0
}

func FetchModels(ctx context.Context, baseURL, apiKey string) ([]pluginapi.ModelInfo, error) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, errors.New("查询模型需要 Token Plan API Key")
	}
	req, err := newRequest(ctx, http.MethodGet, baseURL, "/models", apiKey, nil, false)
	if err != nil {
		return nil, err
	}
	resp, err := client(ctx, 30*time.Second, false).Do(req)
	if err != nil {
		return nil, fmt.Errorf("查询 Token Plan 模型失败: %w", err)
	}
	defer resp.Body.Close()
	body, err := readResponse(resp, 4<<20)
	if err != nil {
		return nil, err
	}
	models, _, err := parseModelsWithContexts(body)
	if err != nil {
		return nil, err
	}
	if BaseURL(baseURL) == DefaultBaseURL {
		// 公共目录只补充能力；实际可见模型仍以这把 Key 的 /v1/models 为准。
		if metadata, err := fetchPublicMetadata(ctx); err == nil {
			for i := range models {
				if detail, ok := metadata[models[i].ID]; ok {
					detail.ContextLength = defaultContextLengths[models[i].ID]
					models[i] = core.ModelInfoToPluginAPI("", detail)
				}
			}
		}
	}
	return models, nil
}

func parseModels(body []byte) ([]pluginapi.ModelInfo, error) {
	models, _, err := parseModelsWithContexts(body)
	return models, err
}

func parseModelsWithContexts(body []byte) ([]pluginapi.ModelInfo, map[string]int64, error) {
	var response struct {
		Object string `json:"object"`
		Data   []struct {
			ID              string `json:"id"`
			Object          string `json:"object"`
			ContextLength   int64  `json:"context_length"`
			MaxTokens       int64  `json:"max_output_tokens"`
			InputModalities []struct {
				Type            string `json:"type"`
				SupportedInputs struct {
					MaxContextLength struct {
						Value int64  `json:"value"`
						Unit  string `json:"unit"`
					} `json:"max_context_length"`
				} `json:"supported_inputs"`
			} `json:"input_modalities"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil || response.Object != "list" || response.Data == nil {
		return nil, nil, errors.New("Token Plan 模型目录不是 OpenAI list 格式")
	}
	models := make([]pluginapi.ModelInfo, 0, len(response.Data))
	reported := make(map[string]int64, len(response.Data))
	seen := map[string]bool{}
	for _, entry := range response.Data {
		id := strings.TrimSpace(entry.ID)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		contextLength := int64(0)
		for _, modality := range entry.InputModalities {
			limit := modality.SupportedInputs.MaxContextLength
			if modality.Type == "text" && (limit.Unit == "token" || limit.Unit == "tokens" || limit.Unit == "") && limit.Value > contextLength {
				contextLength = limit.Value
			}
		}
		if contextLength <= 0 {
			contextLength = entry.ContextLength
		}
		if contextLength > 0 {
			reported[id] = contextLength
		}
		contextLength = defaultContextLengths[id]
		models = append(models, core.ModelInfoToPluginAPI("", core.ModelDescriptor{ID: id, Name: id, Description: "Token Plan API Key 可调用模型", ContextLength: contextLength, MaxOutputTokens: entry.MaxTokens}))
	}
	return models, reported, nil
}

func fetchPublicMetadata(ctx context.Context) (map[string]core.ModelDescriptor, error) {
	metadata := map[string]core.ModelDescriptor{}
	for page := 1; page <= 100; page++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://discovery.intern-ai.org.cn/api/tokenplan/v1/public/models?page=%d&page_size=100", page), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := client(ctx, 20*time.Second, false).Do(req)
		if err != nil {
			return nil, err
		}
		body, readErr := readResponse(resp, 4<<20)
		resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		var response struct {
			Code int `json:"code"`
			Data struct {
				Total  int `json:"total"`
				Models []struct {
					ID             string   `json:"id"`
					DisplayName    string   `json:"display_name"`
					ContextLength  int64    `json:"context_length"`
					InputTypes     []string `json:"input_types"`
					Capabilities   []string `json:"capabilities"`
					CapabilitiesEN []string `json:"capabilities_en"`
				} `json:"models"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &response); err != nil || response.Code != 0 {
			return nil, errors.New("Token Plan 公共模型目录格式错误")
		}
		for _, entry := range response.Data.Models {
			detail := core.ModelDescriptor{ID: entry.ID, Name: core.FirstNonEmpty(entry.DisplayName, entry.ID), Description: "Token Plan API Key 可调用模型", ContextLength: entry.ContextLength}
			for _, input := range entry.InputTypes {
				if input == "image" {
					detail.SupportsImages = true
				}
			}
			for _, cap := range append(entry.Capabilities, entry.CapabilitiesEN...) {
				if cap == "工具调用" || strings.EqualFold(cap, "Tool calling") {
					detail.SupportsTools = true
				}
			}
			metadata[entry.ID] = detail
		}
		if page*100 >= response.Data.Total {
			return metadata, nil
		}
	}
	return nil, errors.New("Token Plan 公共模型目录分页超过上限")
}
