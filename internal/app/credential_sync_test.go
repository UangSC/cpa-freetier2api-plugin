package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"freetier2api-plugin/cpasdk/pluginabi"
	"freetier2api-plugin/cpasdk/pluginapi"
	"freetier2api-plugin/internal/core"
	"freetier2api-plugin/internal/hostbridge"
	"freetier2api-plugin/internal/logger"
)

const syncTestVendorID = "credential-sync-test"
const syncTestName = syncTestVendorID + "-account.json"
const syncTestRaw = `{"type":"freetier","vendor":"credential-sync-test","token":"old-token","user_id":"same-user","prefix":"custom","proxy_url":"http://old-proxy.test","disabled":true,"label":"用户备注"}`

type syncTestNative struct{ token string }

type syncTestVendor struct{ core.Meta }

func (v *syncTestVendor) Match(name, provider string, raw map[string]any) bool {
	return provider == core.ProviderKey && (raw[core.VendorKey] == v.ID() || strings.HasPrefix(name, v.ID()+"-"))
}

func (v *syncTestVendor) Parse(raw []byte, name string) (*core.Credential, error) {
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil || fields[core.VendorKey] != v.ID() {
		return nil, errors.New("invalid fixture vendor")
	}
	token, _ := fields["token"].(string)
	uid, _ := fields["user_id"].(string)
	return &core.Credential{VendorID: v.ID(), Region: "cn", FileID: core.FileIDFromFileName(name), Token: token, UID: uid, Native: &syncTestNative{token: token}}, nil
}

func (v *syncTestVendor) StaticModels(context.Context) ([]pluginapi.ModelInfo, error) {
	return nil, nil
}
func (v *syncTestVendor) Execute(_ context.Context, cred *core.Credential, _ *core.ExecuteRequest) (*pluginapi.ExecutorResponse, error) {
	cred.Native.(*syncTestNative).token = "new-token"
	return &pluginapi.ExecutorResponse{Payload: []byte(`{"choices":[{"message":{"content":"model-success"}}]}`)}, nil
}
func (v *syncTestVendor) ExecuteStream(_ context.Context, cred *core.Credential, _ *core.ExecuteRequest, sink core.StreamSink) error {
	cred.Native.(*syncTestNative).token = "new-token"
	return sink.Emit([]byte(`{"choices":[{"delta":{"content":"model-success"}}]}`))
}

type syncObserverVendor struct {
	*syncTestVendor
	persistedCalls int
}

func (v *syncObserverVendor) HasPendingCredentialState(cred *core.Credential) bool {
	return cred.Native.(*syncTestNative).token != cred.TokenValue()
}
func (v *syncObserverVendor) CredentialStatePersisted(cred *core.Credential, raw []byte) {
	var fields map[string]any
	_ = json.Unmarshal(raw, &fields)
	token, _ := fields["token"].(string)
	cred.ApplyTokenRefresh(token, "", 0)
	v.persistedCalls++
}
func (v *syncObserverVendor) MergeStorageJSON(raw []byte, cred *core.Credential) ([]byte, error) {
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil {
		return nil, errors.New("invalid fixture json")
	}
	fields["token"] = cred.Native.(*syncTestNative).token
	return json.Marshal(fields)
}

type syncTestHost struct {
	mu                                    sync.Mutex
	latest                                []byte
	exists                                bool
	getError, saveError                   bool
	wrongName, wrongIndex                 bool
	changeOnSecondList                    string
	listCalls, getCalls, saveCalls, calls int
	saved                                 pluginapi.HostAuthSaveRequest
	duringSave                            func()
	closed                                chan struct{}
}

func (h *syncTestHost) call(callbackID, method string, payload any) (json.RawMessage, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls++
	if callbackID != "sync-callback" {
		return nil, fmt.Errorf("callback scope lost")
	}
	switch method {
	case pluginabi.MethodHostAuthList:
		h.listCalls++
		if h.listCalls == 2 {
			switch h.changeOnSecondList {
			case "delete":
				h.exists = false
			case "reimport":
				h.latest = []byte(strings.Replace(syncTestRaw, "old-token", "user-reimport", 1))
			case "settings":
				h.latest = []byte(strings.Replace(strings.Replace(syncTestRaw, "custom", "latest-prefix", 1), "old-proxy", "latest-proxy", 1))
			}
		}
		entries := []core.HostAuth{}
		if h.exists {
			entries = append(entries, core.HostAuth{ID: syncTestName, Name: syncTestName, AuthIndex: "sync-index", Provider: core.ProviderKey})
		}
		return json.Marshal(entries)
	case pluginabi.MethodHostAuthGet:
		h.getCalls++
		if h.getError {
			return nil, errors.New("Cookie: PRIVATE_GET_COOKIE")
		}
		encoded, _ := json.Marshal(payload)
		var req pluginapi.HostAuthGetRequest
		_ = json.Unmarshal(encoded, &req)
		if req.AuthIndex != "sync-index" {
			return nil, errors.New("wrong auth index")
		}
		response := pluginapi.HostAuthGetResponse{AuthIndex: "sync-index", Name: syncTestName}
		if h.exists {
			response.JSON = append(json.RawMessage(nil), h.latest...)
		}
		if h.wrongName {
			response.Name = "other-account.json"
		}
		if h.wrongIndex {
			response.AuthIndex = "other-index"
		}
		return json.Marshal(response)
	case pluginabi.MethodHostAuthSave:
		h.saveCalls++
		encoded, _ := json.Marshal(payload)
		_ = json.Unmarshal(encoded, &h.saved)
		if h.saveError {
			return nil, errors.New("Cookie: PRIVATE_SAVE_COOKIE")
		}
		if !h.exists || h.saved.Name != syncTestName {
			return nil, errors.New("would recreate another account")
		}
		h.latest = append([]byte(nil), h.saved.JSON...)
		if h.duringSave != nil {
			h.duringSave()
		}
		return json.RawMessage(`{"name":"` + syncTestName + `"}`), nil
	case pluginabi.MethodHostStreamEmit:
		return json.RawMessage(`{}`), nil
	case pluginabi.MethodHostStreamClose:
		if h.closed != nil {
			close(h.closed)
			h.closed = nil
		}
		return json.RawMessage(`{}`), nil
	default:
		return nil, fmt.Errorf("unexpected fixture host method %s", method)
	}
}

func newCredentialSyncFixture(t *testing.T, observed bool) (*App, preparedExecution, *syncObserverVendor, *syncTestHost) {
	t.Helper()
	base := &syncTestVendor{Meta: core.Meta{VendorID: syncTestVendorID, VendorName: "测试供应商", VendorRegion: "cn"}}
	observer := &syncObserverVendor{syncTestVendor: base}
	var vendor core.Vendor = base
	if observed {
		vendor = observer
	}
	a, err := New(Options{Factories: []core.VendorFactory{{Instances: func(core.Env) []core.Vendor { return []core.Vendor{vendor} }}}})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := vendor.Parse([]byte(syncTestRaw), syncTestName)
	if err != nil {
		t.Fatal(err)
	}
	prepared := preparedExecution{vendor: vendor, credential: credential, model: "test-model"}
	prepared.rpc.AuthID = syncTestName
	prepared.rpc.HostCallbackID = "sync-callback"
	prepared.rpc.Payload = []byte(`{"model":"test-model","messages":[{"role":"user","content":"test"}]}`)
	host := &syncTestHost{latest: []byte(syncTestRaw), exists: true}
	hostbridge.Configure(host.call)
	t.Cleanup(func() { hostbridge.Configure(nil) })
	return a, prepared, observer, host
}

func TestSuccessfulCredentialStateSyncSavesAndAcknowledgesSnapshot(t *testing.T) {
	a, prepared, observer, host := newCredentialSyncFixture(t, true)
	prepared.credential.Native.(*syncTestNative).token = "new-token"
	a.syncCredentialStateAfterExecution(context.Background(), prepared)
	if host.saveCalls != 1 || observer.persistedCalls != 1 || prepared.credential.TokenValue() != "new-token" {
		t.Fatal("轮换状态未正确保存和确认")
	}
	var fields map[string]any
	_ = json.Unmarshal(host.saved.JSON, &fields)
	if fields["token"] != "new-token" || fields["prefix"] != "custom" || fields["proxy_url"] != "http://old-proxy.test" || fields["disabled"] != true || fields["label"] != "用户备注" {
		t.Fatal("保存轮换时覆盖了最新宿主字段")
	}
}

func TestCredentialStateSyncSkipsUnchangedAndOtherVendors(t *testing.T) {
	for _, observed := range []bool{true, false} {
		a, prepared, observer, host := newCredentialSyncFixture(t, observed)
		if !observed {
			prepared.credential.Native.(*syncTestNative).token = "new-token"
		}
		a.syncCredentialStateAfterExecution(context.Background(), prepared)
		if host.calls != 0 || observer.persistedCalls != 0 {
			t.Fatal("未变化或未参与的供应商不应访问宿主")
		}
	}
}

func TestCredentialStateSyncDoesNotOverwriteReimportOrRecreateDeletedAccount(t *testing.T) {
	for _, change := range []string{"deleted-before", "reimport-before", "delete", "reimport"} {
		t.Run(change, func(t *testing.T) {
			a, prepared, observer, host := newCredentialSyncFixture(t, true)
			prepared.credential.Native.(*syncTestNative).token = "new-token"
			switch change {
			case "deleted-before":
				host.exists = false
			case "reimport-before":
				host.latest = []byte(strings.Replace(syncTestRaw, "old-token", "user-reimport", 1))
			default:
				host.changeOnSecondList = change
			}
			a.syncCredentialStateAfterExecution(context.Background(), prepared)
			if host.saveCalls != 0 || observer.persistedCalls != 0 || prepared.credential.TokenValue() != "old-token" {
				t.Fatal("旧执行状态覆盖新凭证或复活已删除账号")
			}
		})
	}
}

func TestCredentialStateSyncUsesLatestHostSettings(t *testing.T) {
	a, prepared, _, host := newCredentialSyncFixture(t, true)
	prepared.credential.Native.(*syncTestNative).token = "new-token"
	host.changeOnSecondList = "settings"
	a.syncCredentialStateAfterExecution(context.Background(), prepared)
	var fields map[string]any
	_ = json.Unmarshal(host.saved.JSON, &fields)
	if host.saveCalls != 1 || fields["prefix"] != "latest-prefix" || fields["proxy_url"] != "http://latest-proxy.test" || fields["disabled"] != true {
		t.Fatal("没有用最后一次宿主快照保留用户配置")
	}
}

func TestCredentialStateSyncFailureDoesNotAdvanceOrLogSecrets(t *testing.T) {
	oldLevel := logger.CurrentLevel()
	logger.SetLevel("debug")
	t.Cleanup(func() { logger.SetLevel(oldLevel) })
	_, since := logger.Snapshot(0, 1)
	for _, stage := range []string{"get", "save", "wrong-name", "wrong-index"} {
		a, prepared, observer, host := newCredentialSyncFixture(t, true)
		prepared.credential.Native.(*syncTestNative).token = "new-token"
		host.getError = stage == "get"
		host.saveError = stage == "save"
		host.wrongName = stage == "wrong-name"
		host.wrongIndex = stage == "wrong-index"
		a.syncCredentialStateAfterExecution(context.Background(), prepared)
		if observer.persistedCalls != 0 || prepared.credential.TokenValue() != "old-token" {
			t.Fatal("保存失败或账号归属错误仍推进了指纹")
		}
	}
	entries, _ := logger.Snapshot(since, 1000)
	for _, entry := range entries {
		if strings.Contains(entry.Message, "PRIVATE_GET_COOKIE") || strings.Contains(entry.Message, "PRIVATE_SAVE_COOKIE") {
			t.Fatal("凭证同步日志包含敏感桥错误")
		}
	}
}

func TestCredentialStateAcknowledgesSavedSnapshotAndLeavesLaterRotationPending(t *testing.T) {
	a, prepared, observer, host := newCredentialSyncFixture(t, true)
	native := prepared.credential.Native.(*syncTestNative)
	native.token = "new-token"
	host.duringSave = func() { native.token = "later-token" }
	a.syncCredentialStateAfterExecution(context.Background(), prepared)
	if host.saveCalls != 1 || prepared.credential.TokenValue() != "new-token" || !observer.HasPendingCredentialState(prepared.credential) {
		t.Fatal("保存期间的后续轮换被误判为已经保存")
	}
}

func TestSuccessfulExecutionsSyncBeforeStreamCloseAndDoNotFailOnSaveError(t *testing.T) {
	for _, stream := range []bool{false, true} {
		a, prepared, _, host := newCredentialSyncFixture(t, true)
		host.saveError = true
		prepared.rpc.Model = "test-model"
		prepared.rpc.Format = "chat-completions"
		prepared.rpc.StorageJSON = []byte(syncTestRaw)
		if stream {
			prepared.rpc.StreamID = "stream-for-sync"
			host.closed = make(chan struct{})
			closed := host.closed
			encoded, _ := json.Marshal(prepared.rpc)
			if _, err := a.handleExecutorExecuteStream(encoded); err != nil {
				t.Fatal("同步失败不应变成模型错误", err)
			}
			select {
			case <-closed:
			case <-time.After(2 * time.Second):
				t.Fatal("同步失败阻止了流关闭")
			}
		} else {
			encoded, _ := json.Marshal(prepared.rpc)
			response, err := a.handleExecutorExecute(encoded)
			if err != nil || len(response) == 0 {
				t.Fatal("同步失败不应改写模型成功响应", err)
			}
		}
		host.mu.Lock()
		saves := host.saveCalls
		host.mu.Unlock()
		if saves != 1 {
			t.Fatalf("成功执行未触发同步：stream=%t saves=%d", stream, saves)
		}
	}
}
