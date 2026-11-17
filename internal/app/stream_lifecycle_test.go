package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"freetier2api-plugin/cpasdk/pluginabi"
)

func TestStoppingRejectsNewStreamsAndCancelsRegisteredStreams(t *testing.T) {
	a := &App{streamCancels: map[uint64]context.CancelFunc{}}
	ctx, _, finish, err := a.BeginPluginStream()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { <-ctx.Done(); finish(); close(done) }()
	a.WaitPluginStreams(time.Second)
	<-done
	if !errors.Is(context.Cause(ctx), errPluginStopping) {
		t.Fatal("shutdown cause was lost")
	}
	if _, _, _, err := a.BeginPluginStream(); err == nil {
		t.Fatal("accepted stream after stop")
	}
}

func TestQuiesceKeepsExistingStreamAlive(t *testing.T) {
	a := &App{streamCancels: map[uint64]context.CancelFunc{}}
	ctx, _, finish, err := a.BeginPluginStream()
	if err != nil {
		t.Fatal(err)
	}
	a.StopStreamAdmission()
	if ctx.Err() != nil {
		t.Fatal("quiesce canceled an active stream")
	}
	if _, _, _, err := a.BeginPluginStream(); err == nil {
		t.Fatal("quiesce accepted a new stream")
	}
	finish()
	a.WaitPluginStreams(time.Second)
}

func TestReconfigureResumesAfterQuiesce(t *testing.T) {
	a, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.StopBackgroundWork(); a.WaitPluginStreams(time.Second) })
	config := []byte(fmt.Sprintf("state_dir: %q\nlog_to_host: false\nlog_to_file: false\nauto_checkin: false\nauto_tasks: false\n", t.TempDir()))
	request, _ := json.Marshal(lifecycleRequest{ConfigYAML: config})
	if _, err := a.HandleMethod(pluginabi.MethodPluginRegister, request); err != nil {
		t.Fatal(err)
	}
	if _, err := a.HandleMethod(pluginabi.MethodPluginQuiesce, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := a.BeginPluginStream(); err == nil {
		t.Fatal("quiesced app accepted streams")
	}
	if _, err := a.HandleMethod(pluginabi.MethodPluginReconfigure, request); err != nil {
		t.Fatal(err)
	}
	if !a.BackgroundRunning() {
		t.Fatal("rollback did not restart background tasks")
	}
	_, _, finish, err := a.BeginPluginStream()
	if err != nil {
		t.Fatalf("rollback did not resume admission: %v", err)
	}
	finish()
}

func TestConcurrentStreamRegistrationAndShutdown(t *testing.T) {
	for iteration := 0; iteration < 20; iteration++ {
		a := &App{streamCancels: map[uint64]context.CancelFunc{}}
		start := make(chan struct{})
		var workers sync.WaitGroup
		for i := 0; i < 20; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				<-start
				_, _, finish, err := a.BeginPluginStream()
				if err == nil {
					finish()
				}
			}()
		}
		close(start)
		a.WaitPluginStreams(time.Second)
		workers.Wait()
		a.streamMu.Lock()
		remaining := len(a.streamCancels)
		a.streamMu.Unlock()
		if remaining != 0 {
			t.Fatalf("remaining streams=%d", remaining)
		}
	}
}
