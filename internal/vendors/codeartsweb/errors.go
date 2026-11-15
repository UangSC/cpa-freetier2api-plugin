package codeartsweb

import "freetier2api-plugin/internal/core"

func expiredSessionError() error {
	return &core.Failure{Kind: core.FailureKindCredential, Status: 401,
		Msg: "CodeArts 网页会话失效，请重新导入登录凭证"}
}
