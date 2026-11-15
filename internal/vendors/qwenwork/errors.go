package qwenwork

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"freetier2api-plugin/internal/core"
)

var jwtPattern = regexp.MustCompile(`[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}`)

// Classify 只输出上游错误码与消息，不记录凭证或整份响应。
func Classify(status int, body []byte) *core.Failure {
	var envelope struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Msg     string `json:"msg"`
	}
	_ = json.Unmarshal(body, &envelope)
	message := core.FirstNonEmpty(envelope.Message, envelope.Msg, fmt.Sprintf("千问办公返回 HTTP %d", status))
	if envelope.Code != "" {
		message = envelope.Code + ": " + message
	}
	message = jwtPattern.ReplaceAllString(message, "[凭证已隐藏]")
	kind := core.ClassifyStatus(status)
	if strings.Contains(strings.ToLower(envelope.Code), "quota") || strings.Contains(envelope.Code, "credit") {
		kind = core.FailureKindQuota
	}
	return &core.Failure{Status: status, Msg: core.Truncate(message, 300), Kind: kind}
}
