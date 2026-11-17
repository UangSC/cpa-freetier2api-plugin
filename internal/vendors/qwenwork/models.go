package qwenwork

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"freetier2api-plugin/cpasdk/pluginapi"
	"freetier2api-plugin/internal/core"
)

type Model struct {
	ID, Mode, Name, Description string
	Source, Format              string
	IsVL, IsReasoning           bool
	CanDisableThink             bool
	ContextLength               int64
	CostFactor                  float64
}

var errNoModels = errors.New("千问办公没有返回可用模型")

func parseModels(data []byte) ([]Model, error) {
	var response struct {
		Qwork []struct {
			Key              string   `json:"key"`
			Enable           *bool    `json:"enable"`
			MaxInputTokens   int64    `json:"max_input_tokens"`
			PriceFactor      float64  `json:"price_factor"`
			Source           string   `json:"source"`
			Format           string   `json:"format"`
			IsVL             bool     `json:"is_vl"`
			IsReasoning      bool     `json:"is_reasoning"`
			SupportsDisabled bool     `json:"supports_disabled"`
			Efforts          []string `json:"efforts"`
			ThinkingConfig   struct {
				SupportsDisabled bool     `json:"supports_disabled"`
				Efforts          []string `json:"efforts"`
			} `json:"thinking_config"`
			ContextConfig map[string]struct {
				TokenCount int64 `json:"token_count"`
			} `json:"context_config"`
			I18n struct {
				DisplayName map[string]string `json:"display_name"`
				Description map[string]string `json:"description"`
			} `json:"i18n"`
		} `json:"qwork"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, fmt.Errorf("千问办公模型清单无效")
	}
	models := make([]Model, 0, len(response.Qwork))
	for _, entry := range response.Qwork {
		if entry.Key == "" || entry.Enable != nil && !*entry.Enable {
			continue
		}
		contextLength := entry.MaxInputTokens
		for _, option := range entry.ContextConfig {
			if option.TokenCount > contextLength {
				contextLength = option.TokenCount
			}
		}
		id := core.FirstNonEmpty(entry.I18n.DisplayName["en"], entry.Key)
		canDisable := entry.SupportsDisabled || entry.ThinkingConfig.SupportsDisabled
		for _, effort := range append(entry.Efforts, entry.ThinkingConfig.Efforts...) {
			if strings.EqualFold(effort, "none") {
				canDisable = true
			}
		}
		models = append(models, Model{ID: id, Mode: entry.Key, Name: core.FirstNonEmpty(entry.I18n.DisplayName["zh"], id),
			Description: entry.I18n.Description["zh"], ContextLength: contextLength, CostFactor: entry.PriceFactor,
			Source: entry.Source, Format: entry.Format, IsVL: entry.IsVL, IsReasoning: entry.IsReasoning, CanDisableThink: canDisable})
	}
	if len(models) == 0 {
		return nil, errNoModels
	}
	return models, nil
}

func (v *adapter) modelsFor(ctx context.Context, credential *Credential) ([]pluginapi.ModelInfo, error) {
	data, err := SignedModelsJSON(ctx, credential)
	if err != nil {
		return nil, err
	}
	models, err := parseModels(data)
	if err != nil {
		if errors.Is(err, errNoModels) {
			v.modelMu.Lock()
			v.modelModes = make(map[string]string)
			v.modelsByMode = make(map[string]Model)
			v.modelMu.Unlock()
			v.credits.Replace(nil)
		}
		return nil, err
	}
	modes := make(map[string]string)
	details := make(map[string]Model)
	for _, model := range models {
		for _, name := range []string{model.ID, model.Mode} {
			key := strings.ToLower(strings.TrimSpace(name))
			if previous, exists := modes[key]; exists && previous != model.Mode {
				return nil, fmt.Errorf("千问办公模型名称存在歧义")
			}
			modes[key] = model.Mode
		}
		details[model.Mode] = model
	}
	v.modelMu.Lock()
	v.modelModes = modes
	v.modelsByMode = details
	v.modelMu.Unlock()
	core.FillCredits(&v.credits, models, func(model Model) string { return model.ID }, func(model Model) string { return core.FormatRate(fmt.Sprintf("%g", model.CostFactor)) })
	return core.ConvertModels(models, func(model Model) (core.ModelDescriptor, bool) {
		return core.ModelDescriptor{ID: model.ID, Name: model.Name, Description: model.Description, ContextLength: model.ContextLength,
			SupportsImages: model.IsVL, SupportsTools: true, CanDisableThinking: !model.IsReasoning || model.CanDisableThink}, true
	}), nil
}

func (v *adapter) modelForMode(mode string) (Model, bool) {
	v.modelMu.RLock()
	defer v.modelMu.RUnlock()
	model, ok := v.modelsByMode[mode]
	return model, ok
}

func (v *adapter) StaticModels(ctx context.Context) ([]pluginapi.ModelInfo, error) {
	native, ok := core.ProbeNativeCredential(v.Env, vendorID, func(credential *core.Credential) (*Credential, bool) {
		native, ok := credential.Native.(*Credential)
		return native, ok
	})
	if !ok {
		return nil, fmt.Errorf("请先添加千问办公账号")
	}
	return v.modelsFor(ctx, native)
}

func (v *adapter) ModelsForAuth(ctx context.Context, credential *core.Credential) ([]pluginapi.ModelInfo, error) {
	native, err := v.Native(credential)
	if err != nil {
		return nil, err
	}
	if _, err := qwenJSON(ctx, "GET", "/user/info", nil, native); err != nil {
		return nil, err
	}
	return v.modelsFor(ctx, native)
}

func (v *adapter) ModelCredits() map[string]string { return v.credits.Snapshot() }

func (v *adapter) modeFor(ctx context.Context, credential *Credential, model string) (string, error) {
	key := strings.ToLower(strings.TrimSpace(model))
	v.modelMu.RLock()
	mode := v.modelModes[key]
	v.modelMu.RUnlock()
	if mode != "" {
		return mode, nil
	}
	if _, err := v.modelsFor(ctx, credential); err != nil {
		return "", err
	}
	v.modelMu.RLock()
	mode = v.modelModes[key]
	v.modelMu.RUnlock()
	if mode == "" {
		return "", core.NewPluginError("model_not_found", "千问办公没有该模型", 404)
	}
	return mode, nil
}
