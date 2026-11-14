package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMutateAndSaveFailurePreservesPendingBackgroundChanges(t *testing.T) {
	dir := t.TempDir()
	store := NewStore()
	store.Configure(dir)
	defer store.Flush()
	if _, err := store.Load(); err != nil {
		t.Fatal(err)
	}
	store.Mutate(func(s *State) { s.Tasks["task"] = TaskRecord{Credit: 12} })
	blocked := filepath.Join(dir, "state.json.tmp")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	err := store.MutateAndSave(func(s *State) { s.ModelAliases["vendor:model"] = "failed.alias" })
	if err == nil {
		t.Fatal("failed write must return an error")
	}
	if got := store.Snapshot(); got.Tasks["task"].Credit != 12 || len(got.ModelAliases) != 0 {
		t.Fatalf("rollback lost pending task or retained failed setting: %+v", got)
	}
	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
	store.Flush()
	reloaded := NewStore()
	reloaded.Configure(dir)
	got, err := reloaded.Load()
	if err != nil || got.Tasks["task"].Credit != 12 || len(got.ModelAliases) != 0 {
		t.Fatalf("pending task not saved after recovery: %+v, %v", got, err)
	}
}
