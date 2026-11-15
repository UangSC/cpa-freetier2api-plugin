package codeartsweb

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func testCredential(t *testing.T) *Credential {
	t.Helper()
	credential, err := ParseCredential([]byte(`{"cookie":"analytics=value; prefix_cftk=token%2Bvalue; prefix_J_SESSION_ID=session-value","cftk":"token+value","user_id":"user-1","headers":{"User-Agent":"browser-agent","sec-ch-ua":"test-brand","Authorization":"Bearer must-not-forward"},"prefix":"codeartsweb","disabled":false,"proxy_url":"http://127.0.0.1:1234"}`))
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func TestCredentialImportsBrowserSnapshotAndRetainsHostFields(t *testing.T) {
	credential := testCredential(t)
	snapshot := credential.snapshot()
	if snapshot.Cftk != "token+value" || snapshot.Headers["user-agent"] != "browser-agent" || snapshot.Headers["authorization"] != "" {
		t.Fatal("未正确提取浏览器快照或过滤认证头")
	}
	if err := credential.setIdentity("user-1", "网页账号"); err != nil {
		t.Fatal(err)
	}
	encoded, err := credential.StorageJSON()
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if json.Unmarshal(encoded, &result) != nil {
		t.Fatal("保存结果不是 JSON")
	}
	if result["prefix"] != "codeartsweb" || result["proxy_url"] != "http://127.0.0.1:1234" || result["disabled"] != false {
		t.Fatal("宿主字段丢失")
	}
	if result["type"] != "freetier" || result["vendor"] != VendorID || result["user_name"] != "网页账号" {
		t.Fatal("账号归属未归一")
	}
	if strings.Contains(string(encoded), "must-not-forward") {
		t.Fatal("保存了不允许的认证请求头")
	}
	if err := credential.setIdentity("different-user", "其他账号"); err == nil {
		t.Fatal("未拒绝矛盾账号身份")
	}
}

func TestCredentialRejectsForeignCredentialAndHeaderInjection(t *testing.T) {
	cases := []string{
		`{"access_key_id":"ak","secret_access_key":"sk"}`,
		`{"vendor":"codearts","cookie":"prefix_cftk=t; session=s","cftk":"t"}`,
		`{"type":"other","cookie":"prefix_cftk=t; session=s","cftk":"t"}`,
		`{"origin":"https://example.com","cookie":"prefix_cftk=t; session=s","cftk":"t"}`,
		`{"cookie":"prefix_cftk=t; session=s","cftk":"other"}`,
		`{"cookie":"session=s","cftk":"t\r\nAuthorization: injected"}`,
		`{"cookie":"session=s\r\nHost: injected","cftk":"t"}`,
		`{"cookie":"session=s; invalid-segment","cftk":"t"}`,
		`{"cookie":"prefix_cftk=t; session=s","headers":{"User-Agent":"value\nInjected: yes"}}`,
	}
	for _, data := range cases {
		if _, err := ParseCredential([]byte(data)); err == nil {
			t.Error("应拒绝非法或异站凭证")
		} else if strings.Contains(err.Error(), "session=s") || strings.Contains(err.Error(), "secret_access_key") {
			t.Error("错误信息包含凭证内容")
		}
	}
}

func TestCredentialParsesCurlWithoutExecutingItsContents(t *testing.T) {
	curl := "curl --url '" + webOrigin + "/chat/PromptCenterService/v1/agent-center/agents/detail?agent_id=test' \\\n -H 'cftk: token+value' -H 'User-Agent: browser-agent' -b 'prefix_cftk=token%2Bvalue; session=session-value'"
	encoded, _ := json.Marshal(map[string]any{"curl": curl, "prefix": "codeartsweb"})
	credential, err := ParseCredential(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if credential.snapshot().Cftk != "token+value" || credential.snapshot().Headers["user-agent"] != "browser-agent" {
		t.Fatal("cURL 解析结果不完整")
	}
	stored, err := credential.StorageJSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), "curl --url") {
		t.Fatal("未删除重复的导入命令")
	}
	for _, invalid := range []string{
		strings.Replace(curl, webOrigin, "https://example.com", 1),
		curl + " ; unwanted-command",
		"curl '" + webOrigin + "/chat/home' --unknown 'value'",
		"curl '" + webOrigin + "/chat/home",
	} {
		if _, err := parseCurlHeaders(invalid); err == nil {
			t.Error("未拒绝错误的 cURL 目标或命令参数")
		}
	}
}

func TestCredentialCookieRotationAndExpiration(t *testing.T) {
	credential := testCredential(t)
	credential.absorbCookies([]*http.Cookie{
		{Name: "prefix_cftk", Value: "next%2Btoken", Domain: "devcloud.cn-north-4.huaweicloud.com"},
		{Name: "prefix_J_SESSION_ID", Value: "next-session", Domain: ".huaweicloud.com"},
		{Name: "unrelated", Value: "foreign", Domain: "example.com"},
		{Name: "analytics", Value: "", Expires: time.Now().Add(-time.Hour)},
	})
	snapshot := credential.snapshot()
	if snapshot.Cftk != "next+token" || !strings.Contains(snapshot.Cookie, "prefix_J_SESSION_ID=next-session") || strings.Contains(snapshot.Cookie, "unrelated") || strings.Contains(snapshot.Cookie, "analytics") {
		t.Fatal("Cookie 轮换、异站过滤或过期处理有误")
	}
	stored, err := credential.StorageJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCredential(stored); err != nil {
		t.Fatal("轮换后的凭证无法重新加载", err)
	}
	credential.absorbCookies([]*http.Cookie{{Name: "prefix_cftk", MaxAge: -1}})
	if credential.snapshot().Cftk != "" {
		t.Fatal("上游删除 cftk 后仍然使用旧值")
	}
}

func TestCredentialSnapshotsAreConcurrentAndIndependent(t *testing.T) {
	credential := testCredential(t)
	var group sync.WaitGroup
	for index := 0; index < 20; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for count := 0; count < 20; count++ {
				credential.absorbCookies([]*http.Cookie{{Name: "prefix_cftk", Value: "next-token"}})
				snapshot := credential.snapshot()
				snapshot.Headers["user-agent"] = "must-not-mutate"
				_, _ = credential.StorageJSON()
			}
		}()
	}
	group.Wait()
	if credential.snapshot().Headers["user-agent"] != "browser-agent" {
		t.Fatal("快照修改影响了原凭证")
	}
}
