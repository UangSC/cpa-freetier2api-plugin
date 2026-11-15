package codeartsweb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"freetier2api-plugin/internal/core"
	"freetier2api-plugin/internal/hostbridge"
)

const maxJSONResponseBytes = 2 << 20

var defaultBrowserHeaders = map[string]string{
	"user-agent":         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36 Edg/157.0.0.0",
	"accept-language":    "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,en-GB;q=0.6",
	"sec-ch-ua":          `"Not-A.Brand";v="99", "Microsoft Edge";v="157", "Chromium";v="157"`,
	"sec-ch-ua-mobile":   "?0",
	"sec-ch-ua-platform": `"Windows"`,
}

// baseURL/httpClient 只供包内测试替换，不接受凭证或客户端传入的目标。
type webClient struct {
	baseURL    string
	httpClient *http.Client
}

func webFailure(kind core.FailureKind, status int, message string, retry bool) error {
	return &core.Failure{Kind: kind, Status: status, Msg: message, RetryableOverride: core.Bool(retry)}
}

func (client webClient) do(ctx context.Context, credential *Credential, method, relative string, body any, accept, agentType string) (*http.Response, error) {
	if credential == nil {
		return nil, webFailure(core.FailureKindCredential, http.StatusUnauthorized, "CodeArts 网页凭证为空，请重新导入", false)
	}
	snapshot := credential.snapshot()
	if !validCookieHeader(snapshot.Cookie) || snapshot.Cftk == "" || !validHeaderValue(snapshot.Cftk) {
		return nil, webFailure(core.FailureKindCredential, http.StatusUnauthorized, "CodeArts 网页会话无效，请重新导入", false)
	}
	parsed, err := url.Parse(relative)
	decoded, decodeErr := url.PathUnescape(parsedPath(parsed))
	if err != nil || decodeErr != nil || parsed == nil || parsed.IsAbs() || parsed.Host != "" || parsed.Fragment != "" || !strings.HasPrefix(path.Clean(decoded), "/chat/") {
		return nil, webFailure(core.FailureKindBadParams, http.StatusBadRequest, "CodeArts 网页请求路径无效", false)
	}
	var encoded []byte
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil || len(encoded) > 16<<20 {
			return nil, webFailure(core.FailureKindBadParams, http.StatusBadRequest, "CodeArts 网页请求体无效或过大", false)
		}
	}
	base := core.FirstNonEmpty(client.baseURL, webOrigin)
	request, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+relative, bytes.NewReader(encoded))
	if err != nil {
		return nil, webFailure(core.FailureKindBadParams, http.StatusBadRequest, "无法创建 CodeArts 网页请求", false)
	}
	for name, value := range defaultBrowserHeaders {
		request.Header.Set(name, value)
	}
	for name, value := range snapshot.Headers {
		if browserHeaderNames[strings.ToLower(name)] && validHeaderValue(value) {
			request.Header.Set(name, value)
		}
	}
	request.Header.Set("Cookie", snapshot.Cookie)
	request.Header.Set("cftk", snapshot.Cftk)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", core.FirstNonEmpty(accept, "application/json, text/plain, */*"))
	request.Header.Set("Origin", webOrigin)
	request.Header.Set("Referer", webOrigin+"/chat/home")
	request.Header.Set("Sec-Fetch-Dest", "empty")
	request.Header.Set("Sec-Fetch-Mode", "cors")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("X-Requested-With", "XMLHttpRequest")
	request.Header.Set("x-codearts-doer-scenario-type", "web")
	request.Header.Set("language", "zh-cn")
	request.Header.Set("X-Language", "zh-cn")
	if agentType != "" {
		if !validHeaderValue(agentType) {
			return nil, webFailure(core.FailureKindBadParams, http.StatusBadRequest, "CodeArts 网页 Agent-Type 无效", false)
		}
		request.Header.Set("Agent-Type", agentType)
	}
	stream := strings.Contains(accept, "text/event-stream")
	if stream {
		request.Header.Set("x-auth-token", "")
	}
	transportClient := client.httpClient
	if transportClient == nil {
		if stream {
			transportClient = hostbridge.StreamClient(ctx, 180*time.Second)
		} else {
			transportClient = hostbridge.Client(ctx, 30*time.Second)
		}
	}
	configured := *transportClient
	configured.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := configured.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// 宿主可能把非 2xx 响应折叠为桥错误，借用公共分类器恢复状态，仍不回显原文。
		var classified *core.PluginError
		if errors.As(core.ToPluginError(err), &classified) && classified.HTTPStatus >= http.StatusBadRequest && classified.HTTPStatus != http.StatusBadGateway {
			status := classified.HTTPStatus
			if status == http.StatusUnauthorized || status == http.StatusForbidden {
				return nil, webFailure(core.FailureKindCredential, http.StatusUnauthorized, "CodeArts 网页登录已失效，请重新导入浏览器会话", false)
			}
			return nil, webFailure(core.ClassifyStatus(status), status, httpFailureMessage(status), false)
		}
		// 不把桥/代理原始错误拼入日志，它可能携带请求头。POST 状态不明确时禁止换号重发。
		return nil, webFailure(core.FailureKindTransient, http.StatusBadGateway, "CodeArts 网页请求未完成，请检查网络或代理", method == http.MethodGet)
	}
	credential.absorbCookies(response.Cookies())
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden || response.StatusCode >= 300 && response.StatusCode < 400 || response.Header.Get("HW-AJAX-REDIRECT") != "" || response.Header.Get("hw-dialog-url") != "" {
		response.Body.Close()
		return nil, webFailure(core.FailureKindCredential, http.StatusUnauthorized, "CodeArts 网页登录已失效，请重新导入浏览器会话", false)
	}
	if response.StatusCode >= http.StatusBadRequest {
		response.Body.Close()
		kind := core.ClassifyStatus(response.StatusCode)
		return nil, webFailure(kind, response.StatusCode, httpFailureMessage(response.StatusCode), false)
	}
	return response, nil
}

func parsedPath(value *url.URL) string {
	if value == nil {
		return ""
	}
	return value.EscapedPath()
}

func httpFailureMessage(status int) string {
	switch status {
	case http.StatusTooManyRequests:
		return "CodeArts 网页请求过于频繁，请稍后再试"
	case http.StatusPaymentRequired:
		return "CodeArts 网页账号额度不足"
	case http.StatusNotFound:
		return "CodeArts 网页接口或会话不存在"
	case http.StatusRequestEntityTooLarge:
		return "CodeArts 网页输入超出服务限制"
	default:
		return "CodeArts 网页接口返回 HTTP " + http.StatusText(status)
	}
}

func (client webClient) json(ctx context.Context, credential *Credential, method, relative string, body any, agentType string) (map[string]any, error) {
	response, err := client.do(ctx, credential, method, relative, body, "application/json, text/plain, */*", agentType)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	encoded, err := io.ReadAll(io.LimitReader(response.Body, maxJSONResponseBytes+1))
	if err != nil || len(encoded) > maxJSONResponseBytes {
		return nil, webFailure(core.FailureKindClient, http.StatusBadGateway, "CodeArts 网页 JSON 响应不完整或超出限制", false)
	}
	if len(bytes.TrimSpace(encoded)) == 0 {
		return nil, webFailure(core.FailureKindCredential, http.StatusUnauthorized, "CodeArts 网页返回空响应，请重新导入登录会话", false)
	}
	var result map[string]any
	if json.Unmarshal(encoded, &result) != nil || result == nil {
		return nil, webFailure(core.FailureKindClient, http.StatusBadGateway, "CodeArts 网页没有返回有效 JSON", false)
	}
	return result, nil
}
