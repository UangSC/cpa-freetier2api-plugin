package codeartsweb

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"freetier2api-plugin/internal/core"
)

func refreshFixture(t *testing.T, identity string) (*adapter, *core.Credential, *Credential, []byte) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/chat/rest/me" {
			t.Errorf("刷新不应调用其他接口：%s", request.URL.Path)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(identity))
	}))
	t.Cleanup(server.Close)
	v := Instances(core.Env{})[0].(*adapter)
	v.client = webClient{baseURL: server.URL, httpClient: server.Client()}
	stored := []byte(`{"vendor":"codeartsweb","cookie":"sid=old; webcftk=old-csrf","cftk":"old-csrf","user_id":"test-user","user_name":"Test User","prefix":"custom","proxy_url":"http://proxy.test","disabled":true}`)
	credential, err := v.Parse(stored, "codeartsweb-test.json")
	if err != nil {
		t.Fatal(err)
	}
	native, err := v.Native(credential)
	if err != nil {
		t.Fatal(err)
	}
	return v, credential, native, stored
}

func rotateBeforeRefresh(native *Credential) {
	native.absorbCookies([]*http.Cookie{{Name: "sid", Value: "new"}, {Name: "webcftk", Value: "new-csrf"}})
}

func TestRefreshPersistsCookieAlreadyRotatedByAnotherRequest(t *testing.T) {
	v, credential, native, stored := refreshFixture(t, `{"userId":"test-user","userName":"Test User"}`)
	oldFingerprint := credential.TokenValue()
	rotateBeforeRefresh(native)
	if credential.TokenValue() != oldFingerprint {
		t.Fatal("轮换响应不应自行推进宿主保存指纹")
	}
	updated, changed, err := v.Refresh(context.Background(), credential)
	if err != nil || !changed || updated != credential {
		t.Fatalf("身份未改变时也必须报告旧 Cookie 已轮换：changed=%t err=%v", changed, err)
	}
	if credential.TokenValue() != cookieFingerprint(native.snapshot().Cookie) || credential.TokenValue() == oldFingerprint {
		t.Fatal("刷新后没有同步当前 Cookie 指纹")
	}
	merged, err := v.MergeStorageJSON(stored, updated)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if json.Unmarshal(merged, &fields) != nil {
		t.Fatal("合并后的凭证不是 JSON")
	}
	if cookie, _ := fields["cookie"].(string); !strings.Contains(cookie, "sid=new") || fields["cftk"] != "new-csrf" {
		t.Fatal("没有保存已轮换的 Cookie/cftk")
	}
	if fields["prefix"] != "custom" || fields["proxy_url"] != "http://proxy.test" || fields["disabled"] != true {
		t.Fatal("刷新合并覆盖了宿主配置")
	}
	if _, changedAgain, err := v.Refresh(context.Background(), credential); err != nil || changedAgain {
		t.Fatalf("同一 Cookie 不能重复报告变化：changed=%t err=%v", changedAgain, err)
	}
}

func TestRefreshWithoutCookieOrIdentityChangeReturnsFalse(t *testing.T) {
	v, credential, native, _ := refreshFixture(t, `{"userId":"test-user","userName":"Test User"}`)
	oldFingerprint := credential.TokenValue()
	updated, changed, err := v.Refresh(context.Background(), credential)
	if err != nil || changed || updated != credential || credential.TokenValue() != oldFingerprint || oldFingerprint != cookieFingerprint(native.snapshot().Cookie) {
		t.Fatalf("未变化时不应推进指纹或触发保存：changed=%t err=%v", changed, err)
	}
}

func TestRefreshIdentityFailureDoesNotAdvanceCookieFingerprint(t *testing.T) {
	for _, identity := range []string{`{"userId":"other-user","userName":"Other User"}`, `{}`} {
		v, credential, native, _ := refreshFixture(t, identity)
		oldFingerprint := credential.TokenValue()
		rotateBeforeRefresh(native)
		if _, changed, err := v.Refresh(context.Background(), credential); err == nil || changed {
			t.Fatalf("身份失败时必须停止刷新：changed=%t err=%v", changed, err)
		}
		if credential.TokenValue() != oldFingerprint {
			t.Fatal("身份失败仍推进了保存指纹")
		}
	}
}

func TestConcurrentRefreshReportsCookieRotationOnce(t *testing.T) {
	v, credential, native, _ := refreshFixture(t, `{"userId":"test-user","userName":"Test User"}`)
	rotateBeforeRefresh(native)
	var changedCount atomic.Int32
	var group sync.WaitGroup
	for index := 0; index < 8; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			_, changed, err := v.Refresh(context.Background(), credential)
			if err != nil {
				t.Error(err)
			}
			if changed {
				changedCount.Add(1)
			}
		}()
	}
	group.Wait()
	if changedCount.Load() != 1 {
		t.Fatalf("并发刷新应只推进一次相同指纹，实际 %d 次", changedCount.Load())
	}
}
