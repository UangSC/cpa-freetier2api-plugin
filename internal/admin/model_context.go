package admin

import (
	"net/http"
	"strings"

	"freetier2api-plugin/cpasdk/pluginapi"
	"freetier2api-plugin/internal/core"
	"freetier2api-plugin/internal/state"
)

// MaxModelContextLength 限制手工输入的数量级，不代表上游支持该窗口。
const MaxModelContextLength int64 = 100_000_000

func contextScopedKey(vendorID, modelID string) string {
	return strings.ToLower(strings.TrimSpace(vendorID) + ":" + strings.TrimSpace(modelID))
}

// ContextOverride 返回手工覆盖值，0 表示自动跟随上游。
func (c *Catalog) ContextOverride(vendorID, modelID string) int64 {
	if _, fixed := c.fixedContextProvider(vendorID); fixed {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.contexts[contextScopedKey(vendorID, modelID)]
}

// ContextLengthFor 在官方 ID 上查询，避免同名模型和别名串用另一供应商的设置。
func (c *Catalog) ContextLengthFor(vendorID, modelID string) int64 {
	if provider, fixed := c.fixedContextProvider(vendorID); fixed {
		return provider.FixedModelContextLength(modelID)
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if limit := c.contexts[contextScopedKey(vendorID, modelID)]; limit > 0 {
		return limit
	}
	for _, model := range c.cached[vendorID].models {
		if strings.EqualFold(strings.TrimSpace(model.ID), strings.TrimSpace(modelID)) {
			return model.ContextLength
		}
	}
	return 0
}

func (c *Catalog) SetContextLength(vendorID, modelID string, limit int64) {
	if _, fixed := c.fixedContextProvider(vendorID); fixed {
		return
	}
	key := contextScopedKey(vendorID, modelID)
	if c.store == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store.Mutate(func(s *state.State) {
		if s.ModelContexts == nil {
			s.ModelContexts = map[string]int64{}
		}
		if limit == 0 {
			delete(s.ModelContexts, key)
		} else {
			s.ModelContexts[key] = limit
		}
		s.RestartPending = true
	})
	if limit == 0 {
		delete(c.contexts, key)
	} else {
		c.contexts[key] = limit
	}
}

func (c *Catalog) fixedContextProvider(vendorID string) (core.FixedModelContextProvider, bool) {
	if c.registry == nil {
		return nil, false
	}
	vendor, ok := c.registry.ByID(vendorID)
	if !ok {
		return nil, false
	}
	return core.As[core.FixedModelContextProvider](vendor)
}

func (s *Service) modelContextHandler(req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	var body struct {
		Model         string `json:"model"`
		ContextLength *int64 `json:"context_length"`
	}
	decoded, err := decodeRequestInto(req.Body, body)
	if err != nil {
		return BadJSONRequestResponse()
	}
	vendorID, modelID := s.deps.Model().VendorForAliasScope(decoded.Model)
	if vendorID == "" || strings.TrimSpace(modelID) == "" {
		return JSONResponse(http.StatusBadRequest, map[string]any{
			"ok": false, "error": "model 必须是 <vendor>:<官方模型 ID> 形式",
		})
	}
	if _, fixed := s.deps.Model().fixedContextProvider(vendorID); fixed {
		return JSONResponse(http.StatusForbidden, map[string]any{"ok": false, "error": "该平台模型上下文已由插件固定，不允许修改", "context_locked": true})
	}
	if decoded.ContextLength == nil || *decoded.ContextLength < 0 || *decoded.ContextLength > MaxModelContextLength {
		return JSONResponse(http.StatusBadRequest, map[string]any{
			"ok": false, "error": "context_length 必须是 0 到 100000000 之间的整数，0 表示恢复自动值",
		})
	}
	s.deps.Model().SetContextLength(vendorID, modelID, *decoded.ContextLength)
	return JSONResponse(http.StatusOK, map[string]any{
		"ok": true, "context_override": *decoded.ContextLength,
		"context_length": s.deps.Model().ContextLengthFor(vendorID, modelID),
	})
}
