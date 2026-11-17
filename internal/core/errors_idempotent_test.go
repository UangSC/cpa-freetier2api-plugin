package core

import (
	"errors"
	"fmt"
	"testing"
)

func TestToPluginErrorPreservesExistingStatusAndRetryPolicy(t *testing.T) {
	for _, status := range []int{400, 401, 429, 502} {
		original := NewPluginError("native_error", "已分类的原生接口错误", status)
		original.Retryable = status == 429
		original.RetryAfterSeconds = 7
		for _, input := range []error{original, fmt.Errorf("请求失败: %w", original)} {
			result := ToPluginError(input)
			var mapped *PluginError
			if !errors.As(result, &mapped) || mapped != original || mapped.HTTPStatus != status || mapped.Retryable != original.Retryable || mapped.RetryAfterSeconds != 7 {
				t.Fatal("重复转换丢失了原生错误的身份或重试策略")
			}
		}
	}
}
