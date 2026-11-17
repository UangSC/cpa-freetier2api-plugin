package tokenplan

import (
	"freetier2api-plugin/internal/core"
)

func classify(status int, body []byte) *core.Failure {
	// 保留请求追踪编号和服务错误；不会把请求 API Key 拼进错误。
	return &core.Failure{Status: status, Kind: core.ClassifyStatus(status), Msg: core.Truncate(string(body), 400)}
}
