package hostbridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"freetier2api-plugin/cpasdk/pluginabi"
)

func TestHTTPClientTimeoutCancelsHostOperation(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	var once sync.Once
	Configure(func(callbackID, method string, payload any) (json.RawMessage, error) {
		if callbackID != "request-1" {
			return nil, fmt.Errorf("lost callback id: %q", callbackID)
		}
		switch method {
		case pluginabi.MethodHostHTTPOperationOpen:
			return json.RawMessage(`{"operation_id":"op-1"}`), nil
		case pluginabi.MethodHostHTTPDo:
			request := payload.(rpcHostHTTPRequest)
			if request.OperationID != "op-1" {
				return nil, errors.New("operation id not forwarded")
			}
			close(started)
			<-canceled
			return nil, context.Canceled
		case pluginabi.MethodHostHTTPCancel:
			once.Do(func() { close(canceled) })
			return json.RawMessage(`{}`), nil
		default:
			return nil, fmt.Errorf("unexpected method %s", method)
		}
	}, CallerOptions{HTTPOperations: true})
	t.Cleanup(func() { Configure(nil) })
	parent := WithCallbackID(context.Background(), "request-1")
	request, _ := http.NewRequestWithContext(parent, http.MethodGet, "https://example.invalid/test", nil)
	done := make(chan error, 1)
	go func() { _, err := Client(parent, 30*time.Millisecond).Do(request); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not start")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("timeout must fail the request")
		}
	case <-time.After(time.Second):
		once.Do(func() { close(canceled) })
		<-done
		t.Fatal("local timeout did not cancel the host request")
	}
}

func TestCancelBypassesSaturatedOrdinaryCalls(t *testing.T) {
	for i := 0; i < maxConcurrentCalls; i++ {
		gate <- struct{}{}
	}
	t.Cleanup(func() {
		for i := 0; i < maxConcurrentCalls; i++ {
			<-gate
		}
		Configure(nil)
	})
	Configure(func(_, method string, _ any) (json.RawMessage, error) {
		if method != pluginabi.MethodHostHTTPCancel {
			return nil, errors.New("ordinary call must not enter")
		}
		return json.RawMessage(`{}`), nil
	})
	if _, err := Call("", pluginabi.MethodHostHTTPCancel, nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := CallCtx(ctx, pluginabi.MethodHostHTTPDo, nil); done <- err }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled call kept waiting for a slot")
	}
}

func TestHTTPStreamCancellationUnblocksReadAndClosesOnce(t *testing.T) {
	canceled := make(chan struct{})
	readStarted := make(chan struct{})
	var once sync.Once
	closeCalls := 0
	Configure(func(_, method string, _ any) (json.RawMessage, error) {
		switch method {
		case pluginabi.MethodHostHTTPOperationOpen:
			return json.RawMessage(`{"operation_id":"op-stream"}`), nil
		case pluginabi.MethodHostHTTPDoStream:
			return json.RawMessage(`{"status_code":200,"stream_id":"stream-1"}`), nil
		case pluginabi.MethodHostHTTPStreamRead:
			close(readStarted)
			<-canceled
			return nil, context.Canceled
		case pluginabi.MethodHostHTTPCancel:
			once.Do(func() { close(canceled) })
			return json.RawMessage(`{}`), nil
		case pluginabi.MethodHostHTTPStreamClose:
			closeCalls++
			return json.RawMessage(`{}`), nil
		default:
			return nil, fmt.Errorf("unexpected %s", method)
		}
	}, CallerOptions{HTTPOperations: true})
	t.Cleanup(func() { Configure(nil) })
	ctx, cancel := context.WithCancel(context.Background())
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.invalid/stream", nil)
	response, err := StreamClient(ctx, 0).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := io.ReadAll(response.Body); done <- err }()
	<-readStarted
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("missing cancel error")
		}
	case <-time.After(time.Second):
		t.Fatal("read did not unblock")
	}
	_ = response.Body.Close()
	if closeCalls != 1 {
		t.Fatalf("close calls=%d", closeCalls)
	}
}

func TestOperationFallbackOnlyForUnsupportedHost(t *testing.T) {
	for _, supportedError := range []bool{true, false} {
		Configure(func(_, method string, _ any) (json.RawMessage, error) {
			if method == pluginabi.MethodHostHTTPOperationOpen {
				if supportedError {
					return nil, errors.New("unsupported host callback host.http.operation_open")
				}
				return nil, errors.New("host operation permission rejected")
			}
			return json.RawMessage(`{"StatusCode":200,"Body":"b2s="}`), nil
		}, CallerOptions{HTTPOperations: true})
		request, _ := http.NewRequest(http.MethodGet, "https://example.invalid/legacy", nil)
		response, err := Client(context.Background(), 0).Do(request)
		if supportedError && err != nil {
			t.Fatal(err)
		}
		if !supportedError && err == nil {
			response.Body.Close()
			t.Fatal("must not bypass a failed operation")
		}
		if response != nil {
			response.Body.Close()
		}
	}
	Configure(nil)
}
