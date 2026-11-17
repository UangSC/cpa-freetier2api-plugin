package hostbridge

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"freetier2api-plugin/cpasdk/pluginabi"
	"freetier2api-plugin/internal/logger"
)

// httpOperation 把本地请求取消传给宿主，不遗弃仍在执行的 CGO 调用。
type httpOperation struct {
	callbackID string
	id         string
	stopCancel func() bool
	cancelOnce sync.Once
}

func beginHTTPOperation(ctx context.Context) (*httpOperation, error) {
	if !httpOperationsEnabled() {
		return nil, nil
	}
	raw, err := CallCtx(ctx, pluginabi.MethodHostHTTPOperationOpen, struct{}{})
	if err != nil {
		// 仅对明确不支持此接口的旧宿主降级；其它错误必须保留。
		message := err.Error()
		if strings.Contains(message, "unsupported host callback") || strings.Contains(message, "unknown_method") ||
			strings.Contains(message, "unknown method: host.http.operation_open") {
			return nil, nil
		}
		return nil, err
	}
	var result struct {
		OperationID string `json:"operation_id"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || strings.TrimSpace(result.OperationID) == "" {
		return nil, fmt.Errorf("host http operation response has no operation id")
	}
	operation := &httpOperation{callbackID: CallbackID(ctx), id: result.OperationID}
	operation.stopCancel = context.AfterFunc(ctx, operation.cancel)
	return operation, nil
}

func (o *httpOperation) cancel() {
	if o == nil {
		return
	}
	o.cancelOnce.Do(func() {
		_, err := Call(o.callbackID, pluginabi.MethodHostHTTPCancel, map[string]string{"operation_id": o.id})
		if err != nil {
			logger.Debug("host http operation cancel failed: %v", err)
		}
	})
}

func (o *httpOperation) stopWatching() {
	if o != nil && o.stopCancel != nil {
		o.stopCancel()
	}
}

func (o *httpOperation) abort() {
	if o != nil {
		o.cancel()
		o.stopWatching()
	}
}
