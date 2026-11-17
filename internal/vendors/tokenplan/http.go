package tokenplan

import (
	"bytes"
	"context"
	"errors"
	"freetier2api-plugin/internal/core"
	"freetier2api-plugin/internal/hostbridge"
	"io"
	"net/http"
	"strings"
	"time"
)

const DefaultBaseURL = "https://discovery-api.intern-ai.org.cn/v1"

func client(ctx context.Context, timeout time.Duration, stream bool) *http.Client {
	var result *http.Client
	if stream {
		result = hostbridge.StreamClient(ctx, timeout)
	} else {
		result = hostbridge.Client(ctx, timeout)
	}
	result.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return result
}

func BaseURL(override string) string {
	if strings.TrimSpace(override) != "" {
		return strings.TrimRight(strings.TrimSpace(override), "/")
	}
	return DefaultBaseURL
}

func newRequest(ctx context.Context, method, baseURL, path, apiKey string, body []byte, stream bool) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, BaseURL(baseURL)+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	}
	return req, nil
}

func readResponse(resp *http.Response, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, &core.Failure{Kind: core.FailureKindTransient, Msg: "读取 Token Plan 响应失败"}
	}
	if int64(len(body)) > limit {
		return nil, errors.New("Token Plan 响应超过大小上限")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, classify(resp.StatusCode, body)
	}
	return body, nil
}
