package admin

import (
	"net/http"
	"sync"
	"testing"

	"freetier2api-plugin/cpasdk/pluginapi"
	"freetier2api-plugin/internal/core"
)

func TestContextOverrideSurvivesRefreshReloadAndReset(t *testing.T) {
	c := newTestCatalog(t)
	defer c.store.Flush()
	original := []pluginapi.ModelInfo{{ID: "shared", ContextLength: 1_000_000, InputTokenLimit: 1_000_000}}
	c.CacheStatic("workbuddycn", original)
	c.CacheStatic("workbuddyglobal", original)
	c.SetContextLength("workbuddycn", "shared", 400_000)
	c.SetAlias("workbuddycn", "shared", "my-model")
	registered := c.ApplyAliases("workbuddycn", original)
	if registered[0].ID != "my-model" || registered[0].ContextLength != 400_000 || registered[0].InputTokenLimit != 400_000 {
		t.Fatalf("alias registration lost context override: %+v", registered)
	}
	if original[0].ContextLength != 1_000_000 || c.ContextLengthFor("workbuddyglobal", "shared") != 1_000_000 {
		t.Fatal("override changed upstream metadata or another vendor")
	}
	if got := c.ContextLengthFor("WORKBUDDYCN", "SHARED"); got != 400_000 {
		t.Fatalf("case-insensitive override = %d", got)
	}
	// 上游重新探测必须保留用户覆盖，并保留最新自动值供恢复使用。
	c.CacheStatic("workbuddycn", []pluginapi.ModelInfo{{ID: "shared", ContextLength: 2_000_000}})
	c.store.Flush()
	reloaded := NewCatalog(c.store, c.registry)
	reloaded.ReloadFromState(c.store.Snapshot())
	reloaded.CacheStatic("workbuddycn", c.Registered("workbuddycn"))
	if got := reloaded.ContextLengthFor("workbuddycn", "shared"); got != 400_000 {
		t.Fatalf("reload lost override: %d", got)
	}
	reloaded.SetContextLength("workbuddycn", "shared", 0)
	if got := reloaded.ContextLengthFor("workbuddycn", "shared"); got != 2_000_000 {
		t.Fatalf("reset did not restore latest upstream value: %d", got)
	}
	if len(c.store.Snapshot().ModelContexts) != 0 {
		t.Fatal("reset must remove persisted override")
	}
}

func TestContextConcurrentWritesKeepStateAndCatalogConsistent(t *testing.T) {
	c := newTestCatalog(t)
	defer c.store.Flush()
	var workers sync.WaitGroup
	for n := int64(1); n <= 32; n++ {
		workers.Add(1)
		go func(limit int64) {
			defer workers.Done()
			c.SetContextLength("workbuddycn", "shared", limit)
		}(n * 1000)
	}
	workers.Wait()
	if got, want := c.ContextOverride("workbuddycn", "shared"), c.store.Snapshot().ModelContexts["workbuddycn:shared"]; got != want {
		t.Fatalf("runtime context %d differs from persisted context %d", got, want)
	}
}

func TestModelContextHandlerValidationAndReset(t *testing.T) {
	deps := newStubDeps(t)
	defer deps.store.Flush()
	if err := deps.registry.Register(&fakeVendor{Meta: core.Meta{VendorID: "workbuddycn", VendorName: "WB CN", VendorRegion: "cn"}}); err != nil {
		t.Fatal(err)
	}
	deps.manager.CacheStatic("workbuddycn", []pluginapi.ModelInfo{{ID: "shared", ContextLength: 1_000_000}})
	s := newServiceWithDeps(t, deps)
	for _, body := range []string{
		`{"model":"workbuddycn:shared"}`,
		`{"model":"workbuddycn:shared","context_length":null}`,
		`{"model":"workbuddycn:shared","context_length":-1}`,
		`{"model":"workbuddycn:shared","context_length":100000001}`,
		`{"model":"workbuddycn:shared","context_length":1.5}`,
		`{"model":"workbuddycn:shared","context_length":"1M"}`,
		`{"model":"unknown:shared","context_length":1000000}`,
		`{"model":"shared","context_length":1000000}`,
		`{"model":`,
	} {
		response := s.modelContextHandler(pluginapi.ManagementRequest{Body: []byte(body)})
		if response.StatusCode != http.StatusBadRequest {
			t.Errorf("invalid request accepted: %s -> %d", body, response.StatusCode)
		}
	}
	for _, body := range []string{
		`{"model":"workbuddycn:shared","context_length":400000}`,
		`{"model":"workbuddycn:shared","context_length":0}`,
	} {
		response := s.modelContextHandler(pluginapi.ManagementRequest{Body: []byte(body)})
		if response.StatusCode != http.StatusOK {
			t.Fatalf("valid request rejected: %s -> %s", body, response.Body)
		}
	}
	if deps.manager.ContextLengthFor("workbuddycn", "shared") != 1_000_000 {
		t.Fatal("reset failed")
	}
}
