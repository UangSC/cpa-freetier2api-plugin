package admin

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"freetier2api-plugin/cpasdk/pluginapi"
	"freetier2api-plugin/internal/core"
	"freetier2api-plugin/internal/state"
)

func TestModelAliasSavePersistsExactValueBeforeResponse(t *testing.T) {
	deps := newStubDeps(t)
	dir := t.TempDir()
	deps.store.Configure(dir)
	defer deps.store.Flush()
	if err := deps.registry.Register(&fakeVendor{Meta: core.Meta{VendorID: "raccoon"}}); err != nil {
		t.Fatal(err)
	}
	const model = "sn-deepseek-v4-1-flash-1017"
	deps.manager.CacheStatic("raccoon", []pluginapi.ModelInfo{{ID: model}})
	s := newServiceWithDeps(t, deps)
	for _, alias := range []string{"DeepSeek-v4.1-flash", "deepseek-v4-1-flash", ""} {
		body, _ := json.Marshal(map[string]string{"model": "raccoon:" + model, "alias": alias})
		response := s.modelAliasHandler(pluginapi.ManagementRequest{Body: body})
		if response.StatusCode != http.StatusOK {
			t.Fatalf("save %q: %s", alias, response.Body)
		}
		var result struct {
			Model          string `json:"model"`
			Alias          string `json:"alias"`
			RestartPending bool   `json:"restart_pending"`
		}
		if err := json.Unmarshal(response.Body, &result); err != nil {
			t.Fatal(err)
		}
		if result.Model != "raccoon:"+model || result.Alias != alias || !result.RestartPending {
			t.Fatalf("incorrect save receipt: %+v", result)
		}
		// 新 Store 立即读盘，不能靠原实例缓存或事后 Flush 掩盖未持久化。
		reloaded := state.NewStore()
		reloaded.Configure(dir)
		stored, err := reloaded.Load()
		if err != nil || stored.ModelAliases["raccoon:"+model] != alias {
			t.Fatalf("saved alias lost or rewritten: %+v, %v", stored, err)
		}
		published := deps.manager.ApplyAliases("raccoon", []pluginapi.ModelInfo{{ID: model}})
		want := alias
		if want == "" {
			want = model
		}
		if published[0].ID != want || deps.manager.ResolveOutboundModel("raccoon", want) != model {
			t.Fatalf("published/outbound mapping differs from saved alias: %+v", published)
		}
	}
}

func TestModelAliasWriteFailureKeepsPreviousSetting(t *testing.T) {
	deps := newStubDeps(t)
	dir := t.TempDir()
	deps.store.Configure(dir)
	defer deps.store.Flush()
	if err := deps.registry.Register(&fakeVendor{Meta: core.Meta{VendorID: "raccoon"}}); err != nil {
		t.Fatal(err)
	}
	if err := deps.manager.SetAlias("raccoon", "model", "previous"); err != nil {
		t.Fatal(err)
	}
	// 用同名目录阻止原子写入，兼容 root/Windows，避免依赖只读权限是否生效。
	blocked := filepath.Join(dir, "state.json.tmp")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	response := newServiceWithDeps(t, deps).modelAliasHandler(pluginapi.ManagementRequest{
		Body: []byte(`{"model":"raccoon:model","alias":"new.value"}`),
	})
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("write failure reported as success: %s", response.Body)
	}
	if deps.manager.AliasFor("raccoon", "model") != "previous" || deps.store.Snapshot().ModelAliases["raccoon:model"] != "previous" {
		t.Fatal("failed save changed runtime/state alias")
	}
	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
	deps.store.Flush()
	reloaded := state.NewStore()
	reloaded.Configure(dir)
	stored, err := reloaded.Load()
	if err != nil || stored.ModelAliases["raccoon:model"] != "previous" {
		t.Fatalf("failed save was persisted later: %+v, %v", stored, err)
	}
}
