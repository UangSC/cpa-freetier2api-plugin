package admin

import (
	"net/http"
	"testing"

	"freetier2api-plugin/cpasdk/pluginapi"
	"freetier2api-plugin/internal/core"
	"freetier2api-plugin/internal/state"
)

type fixedContextTestVendor struct{ fakeVendor }

func (*fixedContextTestVendor) FixedModelContextLength(string) int64 { return 262144 }

func TestFixedContextIgnoresPersistedOverridesAndRejectsEditing(t *testing.T) {
	deps := newStubDeps(t)
	defer deps.store.Flush()
	vendor := &fixedContextTestVendor{fakeVendor{core.Meta{VendorID: "tokenplan", VendorName: "Token Plan", VendorRegion: "cn"}}}
	if err := deps.registry.Register(vendor); err != nil {
		t.Fatal(err)
	}
	deps.store.Mutate(func(s *state.State) { s.ModelContexts = map[string]int64{"tokenplan:intern-s2": 1000000} })
	deps.manager.ReloadFromState(deps.store.Snapshot())
	upstream := []pluginapi.ModelInfo{{ID: "intern-s2", ContextLength: 9999999, InputTokenLimit: 9999999}}
	deps.manager.CacheStatic("tokenplan", upstream)
	deps.manager.SetContextLength("tokenplan", "intern-s2", 123)
	if deps.manager.ContextLengthFor("tokenplan", "intern-s2") != 262144 || deps.manager.ContextOverride("tokenplan", "intern-s2") != 0 {
		t.Fatal("插件固定值被外部覆盖")
	}
	registered := deps.manager.ApplyAliases("tokenplan", upstream)
	if registered[0].ContextLength != 262144 || registered[0].InputTokenLimit != 262144 {
		t.Fatal("注册模型没有固定容量")
	}
	service := newServiceWithDeps(t, deps)
	response := service.modelContextHandler(pluginapi.ManagementRequest{Body: []byte(`{"model":"tokenplan:intern-s2","context_length":1048576}`)})
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("不能通过接口修改固定上下文")
	}
}
